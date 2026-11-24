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
#[derive(Clone, Copy, PartialEq)]
enum Admission {
    Idle,
    Explicit,
    ScannedGlobal,
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
    // Only the continuously sliding scheduler tracks the original cap of each
    // admitted source. Standalone/cohort owners retain their existing policy.
    source_deadlines: Vec<Tick>,
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
            .join(storage::Usage::vector(&self.output)?)?
            .join(storage::Usage::vector(&self.source_deadlines)?)?;
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
            source_deadlines: Vec::new(),
            terminal: None,
            expiry_failure: None,
            explicit: None,
        })
    }
    pub(crate) fn sliding_requested_storage(
        config: Config,
    ) -> Result<storage::Usage, storage::Error> {
        Self::requested_storage(config)?.join(storage::requested::<Tick>(config.window)?)
    }
    pub(crate) fn sliding_memory_bound(config: Config) -> Result<usize, Error> {
        add(
            Self::memory_bound(config)?,
            mul(config.window, std::mem::size_of::<Tick>())?,
        )
    }
    pub(crate) fn targeted_memory_bound(config: Config) -> Result<usize, Error> {
        add(
            Self::sliding_memory_bound(config)?,
            mul(config.window, std::mem::size_of::<Tick>())?,
        )
    }
    pub(crate) fn new_targeted(config: Config, scope: Scope, now: Tick) -> Result<Self, Error> {
        if Self::targeted_memory_bound(config)? > config.memory_bytes {
            return Err(Error::Capacity);
        }
        let mut owner = Self::new(config, scope, now)?;
        owner.source_deadlines = slots(mul(2, config.window)?, Tick(u64::MAX))?;
        Ok(owner)
    }
    pub(crate) fn new_sliding(config: Config, scope: Scope, now: Tick) -> Result<Self, Error> {
        if Self::sliding_memory_bound(config)? > config.memory_bytes {
            return Err(Error::Capacity);
        }
        let mut owner = Self::new(config, scope, now)?;
        owner.source_deadlines = slots(config.window, Tick(0))?;
        Ok(owner)
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
        self.admit_source_in(original, now, now, Admission::Idle)
    }
    pub(crate) fn admit_source_created(
        &mut self,
        original: &[u8],
        created: Tick,
        now: Tick,
    ) -> Result<SourceId, Error> {
        self.admit_source_in(original, created, now, Admission::Idle)
    }
    pub(super) fn computing_full_global(&self) -> bool {
        self.job.as_ref().is_some_and(|job| {
            !job.ready
                && !job.support.tail
                && job.profile.is_none()
                && self.explicit.is_none()
                && self.config.local_window < self.config.window
                && job.support.end >= self.config.window as u32
                && ((job.id.0 & 0x7fff) as u16).is_multiple_of(self.config.global_every)
        })
    }
    // Queued originals move from separate custody into a ring vector. The
    // reservation covers its complete clear, encoded length and actual bytes.
    pub(super) fn admit_queued_source(
        &mut self,
        original: &[u8],
        created: Tick,
        now: Tick,
        during_global: bool,
        budget: &mut WorkBudget,
    ) -> Result<Option<SourceId>, Error> {
        let cost = add(self.width, add(2, original.len())?)?;
        let Some(remaining) = budget.copies.checked_sub(cost) else {
            return Ok(None);
        };
        let admission = if during_global {
            if !self.computing_full_global() {
                return Err(Error::Busy);
            }
            Admission::ScannedGlobal
        } else {
            Admission::Idle
        };
        let id = self.admit_source_in(original, created, now, admission)?;
        budget.copies = remaining;
        Ok(Some(id))
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
        self.admit_source_in(original, now, now, Admission::Explicit)
    }
    fn admit_source_in(
        &mut self,
        original: &[u8],
        created: Tick,
        now: Tick,
        admission: Admission,
    ) -> Result<SourceId, Error> {
        if original.is_empty() || original.len() > self.config.max_payload {
            return Err(Error::Length);
        }
        self.time(now)?;
        if self.job.is_some() && admission == Admission::Idle {
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
        let index = self.next as usize % self.config.window;
        if let Some(old) = self.ids[index]
            && (old >= self.confirmed
                || old >= end.saturating_sub(self.config.window as u32)
                || self.job.as_ref().is_some_and(|job| {
                    // A partial column is still referenced. Only complete
                    // contributions before the cursor survive reuse in output.
                    (job.support.start..job.support.end).contains(&old)
                        && (admission != Admission::ScannedGlobal || old >= job.source)
                }))
        {
            return Err(Error::Capacity);
        }
        if self.debt.is_none() || !self.source_deadlines.is_empty() {
            let expires = self.expires(created, self.config.debt_ticks)?;
            if self.source_deadlines.len() > self.config.window {
                let mut node = index + self.config.window;
                self.source_deadlines[node] = expires;
                while node > 1 {
                    node /= 2;
                    self.source_deadlines[node] =
                        self.source_deadlines[node * 2].min(self.source_deadlines[node * 2 + 1]);
                }
                self.debt = Some(self.debt.map_or(expires, |old| old.min(expires)));
            } else if let Some(slot) = self.source_deadlines.get_mut(index) {
                *slot = expires;
            }
            self.debt.get_or_insert(expires);
        }
        let vector = &mut self.vectors[index * self.width..(index + 1) * self.width];
        vector.fill(0);
        vector[..2].copy_from_slice(&(original.len() as u16).to_be_bytes());
        vector[2..2 + original.len()].copy_from_slice(original);
        let id = SourceId(self.next);
        self.ids[index] = Some(self.next);
        self.next = end;
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
        if prefix <= self.confirmed {
            return Ok(());
        }
        self.confirmed = prefix;
        if prefix == self.next {
            self.debt = None;
        } else if self.source_deadlines.len() > self.config.window {
            // Packing can admit an older frame from another channel later. Query
            // only the live ring interval, excluding old acknowledged leaves.
            let window = self.config.window;
            let start = prefix as usize % window;
            let count = (self.next - prefix) as usize;
            let end = start + count;
            let mut at = self.min_source_deadline(start, end.min(window));
            if end > window {
                at = at.min(self.min_source_deadline(0, end - window));
            }
            self.debt = Some(at);
        } else if let Some(&original) = self
            .source_deadlines
            .get(prefix as usize % self.config.window)
        {
            self.debt = Some(original);
        }
        Ok(())
    }
    fn min_source_deadline(&self, begin: usize, end: usize) -> Tick {
        let mut left = begin + self.config.window;
        let mut right = end + self.config.window;
        let mut at = Tick(u64::MAX);
        while left < right {
            if left % 2 == 1 {
                at = at.min(self.source_deadlines[left]);
                left += 1;
            }
            if right % 2 == 1 {
                right -= 1;
                at = at.min(self.source_deadlines[right]);
            }
            left /= 2;
            right /= 2;
        }
        at
    }
    pub(super) fn next_regular(&self, confirmed: u32) -> Result<(RepairId, Support), Error> {
        if self.next_repair == u64::MAX {
            return Err(Error::Exhausted);
        }
        let id = RepairId(self.next_repair);
        Ok((
            id,
            self.config
                .confirmed_prefix_support(self.next, id, false, confirmed)?,
        ))
    }
    // An already frozen equation keeps the current serial until its physical receipt.
    pub(super) fn following_regular(
        &self,
        queued: u32,
        end: u32,
        confirmed: u32,
    ) -> Result<(RepairId, Support), Error> {
        let serial = self
            .next_repair
            .checked_add(u64::from(self.job.is_some()))
            .and_then(|v| v.checked_add(u64::from(queued)))
            .filter(|v| *v < u64::MAX)
            .ok_or(Error::Exhausted)?;
        let id = RepairId(serial);
        Ok((
            id,
            self.config
                .confirmed_prefix_support(end, id, false, confirmed)?,
        ))
    }
    pub(super) fn begin_earned_regular(
        &mut self,
        id: RepairId,
        support: Support,
        confirmed: u32,
        cap: Tick,
        now: Tick,
    ) -> Result<RepairId, Error> {
        self.time(now)?;
        if self.job.is_some() {
            return Err(Error::Busy);
        }
        if self.explicit.is_some()
            || id.0 != self.next_repair
            || self.confirmed == self.next
            || support.end > self.next
            || support.start < self.next.saturating_sub(self.config.window as u32)
            || support
                != self.config.confirmed_prefix_support(
                    support.end,
                    id,
                    false,
                    confirmed.min(support.start),
                )?
        {
            return Err(Error::Identity);
        }
        if now >= cap {
            return Err(Error::Expired);
        }
        self.install_repair(id, support, None, cap)
    }
    /// Begin the next owned regular/tail equation. A failed call consumes no ID.
    pub fn begin_repair(&mut self, tail: bool, now: Tick) -> Result<RepairId, Error> {
        self.begin_repair_with_prefix(tail, 0, now)
    }
    pub(super) fn begin_repair_with_prefix(
        &mut self,
        tail: bool,
        confirmed: u32,
        now: Tick,
    ) -> Result<RepairId, Error> {
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
        let support = self
            .config
            .confirmed_prefix_support(self.next, id, tail, confirmed)?;
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
                if budget.copies == 0 {
                    break;
                }
                // The outer visit already paid for one byte. Batch only the
                // same visits that the scalar loop could finish this call.
                let count = (self.width - job.cleared)
                    .min(budget.copies)
                    .min(budget.metadata + 1);
                let end = job.cleared + count;
                self.output[job.cleared..end].fill(0);
                budget.copies -= count;
                budget.metadata -= count - 1;
                job.cleared = end;
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
            // Admission stores a validated length and canonical zero suffix.
            // A zero suffix contributes nothing to any encoded equation.
            let start = index * self.width;
            let extent = 2 + usize::from(u16::from_be_bytes([
                self.vectors[start],
                self.vectors[start + 1],
            ]));
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
                        job.extent = job.extent.max(extent);
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
            if budget.field == 0 {
                break;
            }
            // Stay inside this validated source and retain the original field
            // and metadata charge, including a later unsuccessful visit.
            let count = (extent - job.column)
                .min(budget.field)
                .min(budget.metadata + 1);
            let end = job.column + count;
            gf_batch::xor_scaled::<false>(
                &mut self.output[job.column..end],
                &self.vectors[start + job.column..start + end],
                factor,
            );
            budget.field -= count;
            budget.metadata -= count - 1;
            job.column = end;
            if job.column == extent {
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
    /// Original debt deadline of the oldest unconfirmed source; with
    /// per-source tracking it moves as receipts advance.
    pub(crate) fn debt(&self) -> Option<Tick> {
        self.debt
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
            decoder_job: None,
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
mod batch_work_tests;
#[cfg(test)]
mod equation_tests;
