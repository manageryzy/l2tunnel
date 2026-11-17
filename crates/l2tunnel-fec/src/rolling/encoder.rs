use super::*;
use crate::field;

struct Job {
    id: RepairId,
    support: Support,
    profile: Option<crate::research::Profile>,
    deadline: Tick,
    cleared: usize,
    source: u32,
    column: usize,
    extent: usize,
    factor: Option<u8>,
    ready: bool,
}
/// Bounded sender state; confirmations are recovery receipts, not native delivery.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EncoderStatus {
    /// Exclusive next allocated source ID.
    pub next_source: u32,
    /// Actual cumulative peer receipt accepted by this owner.
    pub confirmed_prefix: u32,
    /// Retained source vectors, including confirmed fixed-support columns.
    pub retained_sources: usize,
    /// A repair job or immutable output is owned.
    pub pending_repair: bool,
    /// Latched terminal failure, if any.
    pub terminal: Option<Error>,
}
/// Full-byte fixed-window encoder with one resumable repair/output slot.
pub struct Encoder {
    config: Config,
    scope: Scope,
    width: usize,
    vectors: Vec<u8>,
    ids: Vec<Option<u32>>,
    output: Vec<u8>,
    next: u32,
    confirmed: u32,
    next_repair: u64,
    job: Option<Job>,
    last: Tick,
    debt: Option<Tick>,
    terminal: Option<Error>,
    expiry_failure: Option<expiry::Failure>,
    explicit: Option<explicit::Row>,
}
impl Encoder {
    pub(crate) fn requested_storage(config: Config) -> Result<storage::Usage, storage::Error> {
        let width = storage::width(config)?;
        storage::requested::<u8>(mul(config.window, width)?)?
            .join(storage::requested::<Option<u32>>(config.window)?)?
            .join(storage::requested::<u8>(width)?)
    }

    pub(crate) fn storage_usage(&self) -> Result<storage::Usage, storage::Error> {
        let usage = storage::Usage::vector(&self.vectors)?
            .join(storage::Usage::vector(&self.ids)?)?
            .join(storage::Usage::vector(&self.output)?)?;
        match &self.explicit {
            Some(row) => usage.join(row.storage_usage()?),
            None => Ok(usage),
        }
    }
    pub(crate) fn explicit_requested_storage(
        config: Config,
    ) -> Result<storage::Usage, storage::Error> {
        Self::requested_storage(config)?.join(explicit::Row::requested_storage()?)
    }
    pub(crate) fn explicit_memory_bound(config: Config) -> Result<usize, Error> {
        add(Self::memory_bound(config)?, explicit::Row::memory_bound())
    }
    pub(crate) fn new_explicit(config: Config, scope: Scope, now: Tick) -> Result<Self, Error> {
        if Self::explicit_memory_bound(config)? > config.memory_bytes {
            return Err(Error::Capacity);
        }
        let mut owner = Self::new(config, scope, now)?;
        owner.explicit = Some(explicit::Row::new()?);
        Ok(owner)
    }

    /// Conservative payload and metadata reservation before allocating.
    pub fn memory_bound(config: Config) -> Result<usize, Error> {
        let width = config.width()?;
        add(
            add(
                mul(config.window, width)?,
                mul(config.window, std::mem::size_of::<Option<u32>>())?,
            )?,
            add(width, std::mem::size_of::<Self>())?,
        )
    }
    /// Construct all fixed storage; initial source ID is zero and repair ID one.
    pub fn new(config: Config, scope: Scope, now: Tick) -> Result<Self, Error> {
        let bound = Self::memory_bound(config)?;
        if bound > config.memory_bytes {
            return Err(Error::Capacity);
        }
        deadline(now, config.debt_ticks)?;
        deadline(now, config.job_ticks)?;
        let width = config.width()?;
        Ok(Self {
            config,
            scope,
            width,
            vectors: bytes(mul(config.window, width)?)?,
            ids: slots(config.window, None)?,
            output: bytes(width)?,
            next: 0,
            confirmed: 0,
            next_repair: 1,
            job: None,
            last: now,
            debt: None,
            terminal: None,
            expiry_failure: None,
            explicit: None,
        })
    }
    fn time(&mut self, now: Tick) -> Result<(), Error> {
        if self.terminal.is_some() {
            return Err(Error::Terminal);
        }
        if let Err(error) = check_time(
            self.last,
            now,
            &[self.debt, self.job.as_ref().map(|job| job.deadline)],
        ) {
            if error == Error::Expired {
                self.expiry_failure = self
                    .expiry_failure
                    .or_else(|| self.expiry_snapshot().first_expired(now, &[0, 1]));
            }
            self.terminal = Some(error);
            return Err(error);
        }
        self.last = now;
        Ok(())
    }
    fn expires(&mut self, now: Tick, ticks: u64) -> Result<Tick, Error> {
        match deadline(now, ticks) {
            Ok(value) => Ok(value),
            Err(error) => {
                self.terminal = Some(error);
                Err(error)
            }
        }
    }
    /// Admit one exact source. A pending encoding job freezes its support.
    /// This performs at most two fixed-width copies/clears, each <=4098 bytes.
    pub fn admit_source(&mut self, original: &[u8], now: Tick) -> Result<SourceId, Error> {
        self.admit_source_in(original, now, false)
    }
    // The legacy admission owner pins every queued/unsent column before calling
    // this opt-in path. A frozen explicit equation permits later non-overwriting
    // columns; the ordinary rolling and Research admission boundary is unchanged.
    pub(crate) fn admit_source_while_explicit(
        &mut self,
        original: &[u8],
        now: Tick,
    ) -> Result<SourceId, Error> {
        if self.explicit.is_none() {
            return Err(Error::Configuration);
        }
        self.admit_source_in(original, now, true)
    }
    fn admit_source_in(
        &mut self,
        original: &[u8],
        now: Tick,
        explicit_admission: bool,
    ) -> Result<SourceId, Error> {
        if original.is_empty() || original.len() > self.config.max_payload {
            return Err(Error::Length);
        }
        self.time(now)?;
        if self.job.is_some() && !explicit_admission {
            return Err(Error::Busy);
        }
        if self.next == u32::MAX {
            self.terminal = Some(Error::Exhausted);
            return Err(Error::Exhausted);
        }
        if (self.next - self.confirmed) as usize >= self.config.window {
            return Err(Error::Capacity);
        }
        let end = self.next.checked_add(1).ok_or(Error::Exhausted)?;
        let debt = if self.debt.is_none() {
            Some(self.expires(now, self.config.debt_ticks)?)
        } else {
            self.debt
        };
        let index = self.next as usize % self.config.window;
        if let Some(old) = self.ids[index]
            && (old >= self.confirmed
                || old >= end.saturating_sub(self.config.window as u32)
                || self
                    .job
                    .as_ref()
                    .is_some_and(|job| (job.support.start..job.support.end).contains(&old)))
        {
            return Err(Error::Capacity);
        }
        let vector = &mut self.vectors[index * self.width..(index + 1) * self.width];
        vector.fill(0);
        vector[..2].copy_from_slice(&(original.len() as u16).to_be_bytes());
        vector[2..2 + original.len()].copy_from_slice(original);
        let id = SourceId(self.next);
        self.ids[index] = Some(self.next);
        self.next = end;
        self.debt = debt;
        Ok(id)
    }
    /// Borrow an exact original retained source for systematic transmission.
    pub fn source(&self, id: SourceId) -> Option<&[u8]> {
        if self.terminal.is_some() {
            return None;
        }
        let index = id.0 as usize % self.config.window;
        if self.ids[index] != Some(id.0) {
            return None;
        }
        let vector = &self.vectors[index * self.width..(index + 1) * self.width];
        let length = usize::from(u16::from_be_bytes([vector[0], vector[1]]));
        Some(&vector[2..2 + length])
    }
    /// Apply a cumulative authenticated receipt; reordered older receipts are no-ops.
    pub fn confirm_prefix(&mut self, prefix: u32, now: Tick) -> Result<(), Error> {
        if prefix > self.next {
            return Err(Error::Identity);
        }
        self.time(now)?;
        self.confirmed = self.confirmed.max(prefix);
        if self.confirmed == self.next {
            self.debt = None;
        }
        Ok(())
    }
    /// Begin the next owned regular/tail equation. A failed call consumes no ID.
    pub fn begin_repair(&mut self, tail: bool, now: Tick) -> Result<RepairId, Error> {
        if self.explicit.is_some() {
            return Err(Error::Configuration);
        }
        self.time(now)?;
        if self.job.is_some() {
            return Err(Error::Busy);
        }
        if self.confirmed == self.next {
            return Err(Error::Identity);
        }
        if self.next_repair == u64::MAX {
            self.terminal = Some(Error::Exhausted);
            return Err(Error::Exhausted);
        }
        let id = RepairId(self.next_repair);
        let support = self.config.support(self.next, id, tail)?;
        self.start_repair(id, support, None, now)
    }
    // Only the research owner may admit a canonical alternative equation. Its
    // negotiated profile is immutable for the entire job; public rolling APIs
    // continue deriving compact local/global support themselves.
    pub(crate) fn begin_equation(
        &mut self,
        support: Support,
        profile: crate::research::Profile,
        now: Tick,
    ) -> Result<RepairId, Error> {
        if self.explicit.is_some() {
            return Err(Error::Configuration);
        }
        profile.validate()?;
        if support.end == 0
            || support.end != self.next
            || support.start > support.end
            || support.end - support.start > self.config.window as u32
        {
            return Err(Error::Identity);
        }
        u32::try_from(self.next_repair).map_err(|_| Error::Exhausted)?;
        self.time(now)?;
        if self.job.is_some() {
            return Err(Error::Busy);
        }
        let id = RepairId(self.next_repair);
        self.start_repair(id, support, Some(profile), now)
    }
    // Freeze a canonical sparse equation without requiring its newest source to
    // be the newest admitted source. Queued owners must preserve referenced ring
    // columns until this call; all actual source identities are checked here.
    pub(crate) fn begin_explicit(
        &mut self,
        terms: &[explicit::Term],
        feedback: bool,
        queued: Tick,
        now: Tick,
        cap: Tick,
    ) -> Result<RepairId, Error> {
        if self.explicit.is_none() {
            return Err(Error::Configuration);
        }
        let support = explicit::support(terms, feedback, self.config.window)?;
        if support.end > self.next {
            return Err(Error::Identity);
        }
        self.time(now)?;
        if queued > now {
            self.terminal = Some(Error::TimeRegression);
            return Err(Error::TimeRegression);
        }
        let end = self.expires(queued, self.config.job_ticks)?.min(cap);
        if now >= end {
            self.expiry_failure.get_or_insert(expiry::Failure {
                observed: now,
                selected: expiry::Deadline::new(
                    expiry::Kind::EncoderJob,
                    end,
                    Some(expiry::Identity::Repair {
                        id: RepairId(self.next_repair),
                        support: Some((support.start, support.end)),
                    }),
                ),
            });
            self.terminal = Some(Error::Expired);
            return Err(Error::Expired);
        }
        if self.job.is_some() {
            return Err(Error::Busy);
        }
        if self.next_repair == u64::MAX {
            self.terminal = Some(Error::Exhausted);
            return Err(Error::Exhausted);
        }
        for term in terms {
            if self.source(term.source).is_none() {
                return Err(Error::Identity);
            }
        }
        self.explicit
            .as_mut()
            .ok_or(Error::Configuration)?
            .load(terms);
        let id = RepairId(self.next_repair);
        self.install_repair(id, support, None, end)
    }
    fn start_repair(
        &mut self,
        id: RepairId,
        support: Support,
        profile: Option<crate::research::Profile>,
        now: Tick,
    ) -> Result<RepairId, Error> {
        let deadline = self.expires(now, self.config.job_ticks)?;
        self.install_repair(id, support, profile, deadline)
    }
    fn install_repair(
        &mut self,
        id: RepairId,
        support: Support,
        profile: Option<crate::research::Profile>,
        deadline: Tick,
    ) -> Result<RepairId, Error> {
        self.job = Some(Job {
            id,
            support,
            profile,
            deadline,
            cleared: 0,
            source: support.start,
            column: 0,
            extent: 2,
            factor: None,
            ready: false,
        });
        Ok(id)
    }
    /// Advance bounded clearing/coefficient/GF work; pending output remains immutable.
    pub fn step(&mut self, now: Tick, mut budget: WorkBudget) -> Result<WorkUsed, Error> {
        budget.validate()?;
        self.time(now)?;
        let before = budget;
        let Some(job) = &mut self.job else {
            return Ok(WorkUsed::default());
        };
        while !job.ready && spend(&mut budget.metadata) {
            if job.cleared < self.width {
                if !spend(&mut budget.copies) {
                    break;
                }
                self.output[job.cleared] = 0;
                job.cleared += 1;
                continue;
            }
            if job.source == job.support.end {
                job.ready = true;
                break;
            }
            let index = job.source as usize % self.config.window;
            if self.ids[index] != Some(job.source) {
                self.terminal = Some(Error::Identity);
                return Err(Error::Identity);
            }
            let factor = match job.factor {
                Some(value) => value,
                None => {
                    // Research evaluation is bounded by its validated tap limit:
                    // one metadata visit performs at most sixteen single-block
                    // maintained SHA-256 evaluations, with no heap allocation.
                    let value = if let Some(row) = &self.explicit {
                        row.coefficient(job.source)
                    } else {
                        match job.profile {
                            Some(profile) => profile.coefficient(
                                u32::try_from(job.id.0).map_err(|_| Error::Exhausted)?,
                                job.source,
                            )?,
                            None => field::compact_coefficient(job.support.seed, job.source),
                        }
                    };
                    // Include every selected original, even a zero coefficient
                    // in a contiguous policy. Explicit rows contain only nonzero
                    // terms, so their intervening gap IDs are outside support.
                    if self.explicit.is_none() || value != 0 {
                        let start = index * self.width;
                        let original = usize::from(u16::from_be_bytes([
                            self.vectors[start],
                            self.vectors[start + 1],
                        ]));
                        job.extent = job.extent.max(2 + original);
                    }
                    job.factor = Some(value);
                    value
                }
            };
            if factor == 0 {
                job.source += 1;
                job.factor = None;
                continue;
            }
            if !spend(&mut budget.field) {
                break;
            }
            self.output[job.column] ^=
                field::multiply(factor, self.vectors[index * self.width + job.column]);
            job.column += 1;
            if job.column == self.width {
                job.column = 0;
                job.source += 1;
                job.factor = None;
            }
        }
        Ok(used(before, budget))
    }
    /// Inspect one immutable complete repair; polling consumes no ID or output.
    pub fn pending_repair(&self) -> Option<Repair<'_>> {
        let job = self.job.as_ref()?;
        (job.ready && self.terminal.is_none()).then_some(Repair {
            scope: self.scope,
            id: job.id,
            support: job.support,
            bytes: &self.output[..job.extent],
        })
    }
    /// Copy and consume the exact pending equation after external output reservation.
    /// An undersized output leaves both its bytes and this owner unchanged.
    pub fn take_repair(
        &mut self,
        output: &mut [u8],
        now: Tick,
    ) -> Result<(RepairId, Support, usize), Error> {
        self.time(now)?;
        let job = self
            .job
            .as_ref()
            .filter(|job| job.ready)
            .ok_or(Error::Busy)?;
        if output.len() < job.extent {
            return Err(Error::OutputTooSmall);
        }
        let value = (job.id, job.support, job.extent);
        output[..job.extent].copy_from_slice(&self.output[..job.extent]);
        self.next_repair += 1;
        self.job = None;
        Ok(value)
    }
    /// Confirm complete external ownership of the borrowed pending repair without copying.
    /// Call only after its entire immutable descriptor/vector has been handed off.
    pub fn confirm_repair(&mut self, id: RepairId, now: Tick) -> Result<(), Error> {
        self.time(now)?;
        let job = self
            .job
            .as_ref()
            .filter(|job| job.ready)
            .ok_or(Error::Busy)?;
        if job.id != id {
            return Err(Error::Identity);
        }
        self.next_repair += 1;
        self.job = None;
        Ok(())
    }
    /// Original earliest owned deadline; no timer is renewed by polling.
    pub fn deadline(&self) -> Option<Tick> {
        self.debt
            .into_iter()
            .chain(self.job.as_ref().map(|job| job.deadline))
            .min()
    }
    /// Read original lifetimes without checking time or changing authority.
    pub fn expiry_snapshot(&self) -> expiry::Snapshot {
        use expiry::{Deadline, Identity, Kind};
        expiry::Snapshot {
            scope: self.scope,
            last_successful: self.last,
            terminal: self.terminal,
            failure: self.expiry_failure,
            candidates: [
                self.debt.map(|at| {
                    Deadline::new(
                        Kind::EncoderDebt,
                        at,
                        Some(Identity::Sources {
                            first: self.confirmed,
                            end: self.next,
                        }),
                    )
                }),
                self.job.as_ref().map(|job| {
                    Deadline::new(
                        Kind::EncoderJob,
                        job.deadline,
                        Some(Identity::Repair {
                            id: job.id,
                            support: Some((job.support.start, job.support.end)),
                        }),
                    )
                }),
                None,
                None,
                None,
                None,
            ],
        }
    }
    /// Bounded diagnostic snapshot.
    pub fn status(&self) -> EncoderStatus {
        EncoderStatus {
            next_source: self.next,
            confirmed_prefix: self.confirmed,
            retained_sources: (self.next as usize).min(self.config.window),
            pending_repair: self.job.is_some(),
            terminal: self.terminal,
        }
    }
}

#[cfg(test)]
mod equation_tests;
