use super::*;
use crate::field;

struct Job {
    id: RepairId,
    support: Support,
    deadline: Tick,
    cleared: usize,
    source: u32,
    column: usize,
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
}
impl Encoder {
    pub(super) fn requested_storage(config: Config) -> Result<storage::Usage, storage::Error> {
        let width = storage::width(config)?;
        storage::requested::<u8>(mul(config.window, width)?)?
            .join(storage::requested::<Option<u32>>(config.window)?)?
            .join(storage::requested::<u8>(width)?)
    }

    pub(super) fn storage_usage(&self) -> Result<storage::Usage, storage::Error> {
        storage::Usage::vector(&self.vectors)?
            .join(storage::Usage::vector(&self.ids)?)?
            .join(storage::Usage::vector(&self.output)?)
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
        if original.is_empty() || original.len() > self.config.max_payload {
            return Err(Error::Length);
        }
        self.time(now)?;
        if self.job.is_some() {
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
            && (old >= self.confirmed || old >= end.saturating_sub(self.config.window as u32))
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
        let deadline = self.expires(now, self.config.job_ticks)?;
        self.job = Some(Job {
            id,
            support,
            deadline,
            cleared: 0,
            source: support.start,
            column: 0,
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
                    let value = field::compact_coefficient(job.support.seed, job.source);
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
            bytes: &self.output,
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
        if output.len() < self.width {
            return Err(Error::OutputTooSmall);
        }
        let value = (job.id, job.support, self.width);
        output[..self.width].copy_from_slice(&self.output);
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
