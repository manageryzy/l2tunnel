use super::gf_batch::xor_scaled;
use super::*;
use crate::field;

#[cfg(test)]
mod expiry_detail_tests;
mod lifetimes;
mod transaction;
use transaction::{Cell, Pool, Ticket};

#[derive(Clone, Copy, Default)]
struct Header {
    prefix: u32,
    observed: u32,
    rank: usize,
    // Exclusive upper bound for occupied row slots in this transaction.
    row_end: usize,
    known_count: usize,
    evicted_before: u32,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Descriptor {
    id: RepairId,
    support: Support,
    profile: Option<crate::research::Profile>,
    confirmed: u32,
}
#[derive(Clone, Copy)]
enum Input {
    Source(u32),
    Repair(Descriptor),
}
impl Input {
    fn expiry_identity(self) -> expiry::Identity {
        match self {
            Self::Source(id) => expiry::Identity::Sources {
                first: id,
                end: id + 1,
            },
            Self::Repair(d) => expiry::Identity::Repair {
                id: d.id,
                support: Some((d.support.start, d.support.end)),
            },
        }
    }
    fn end(self) -> u32 {
        match self {
            Self::Source(id) => id + 1,
            Self::Repair(d) => d.support.end,
        }
    }
    fn start(self) -> u32 {
        match self {
            Self::Source(id) => id,
            Self::Repair(d) => d.support.start,
        }
    }
    fn coefficient(self, id: u32) -> Result<u8, Error> {
        match self {
            Self::Source(_) => Ok(1),
            Self::Repair(d) => match d.profile {
                Some(profile) => {
                    profile.coefficient(u32::try_from(d.id.0).map_err(|_| Error::Exhausted)?, id)
                }
                None => Ok(field::compact_coefficient(d.support.seed, id)),
            },
        }
    }
}
#[derive(Clone, Copy)]
#[cfg_attr(test, derive(Debug, Eq, PartialEq))]
enum Phase {
    CopyRow {
        row: usize,
        from: usize,
        to: usize,
        index: usize,
    },
    Clear(usize),
    Load(usize),
    Support(u32),
    Known {
        source: u32,
        factor: u8,
        column: usize,
        extent: usize,
    },
    Reduce(u32),
    Eliminate {
        row: usize,
        factor: u8,
        index: usize,
        next: u32,
    },
    Pivot(u32),
    Invert {
        pivot: u32,
        result: u8,
        base: u8,
        exponent: u8,
    },
    Square {
        pivot: u32,
        result: u8,
        base: u8,
        exponent: u8,
    },
    Zero(usize),
    Normalize {
        pivot: u32,
        factor: u8,
        index: usize,
    },
    Others {
        pivot: u32,
        row: usize,
    },
    OtherEliminate {
        pivot: u32,
        row: usize,
        factor: u8,
        index: usize,
    },
    FindSlot {
        pivot: u32,
        row: usize,
    },
    Insert {
        pivot: u32,
        row: usize,
        index: usize,
    },
    CandidateCount {
        pivot: u32,
        index: usize,
        count: usize,
    },
    Scan {
        row: usize,
    },
    Validate {
        row: Option<usize>,
        id: u32,
        index: usize,
        length: usize,
    },
    Store {
        row: Option<usize>,
        id: u32,
        index: usize,
    },
    Advance,
    Evict(u32),
    History(usize),
    Commit,
}
impl Phase {
    fn expiry_cursor(self) -> expiry::DecoderPhase {
        use expiry::DecoderPhase as Cursor;
        match self {
            Self::CopyRow {
                row,
                from,
                to,
                index,
            } => Cursor::CopyRow {
                row,
                from,
                to,
                index,
            },
            Self::Clear(index) => Cursor::Clear(index),
            Self::Load(index) => Cursor::Load(index),
            Self::Support(source) => Cursor::Support(source),
            Self::Known { source, column, .. } => Cursor::Known { source, column },
            Self::Reduce(source) => Cursor::Reduce(source),
            Self::Eliminate {
                row, index, next, ..
            } => Cursor::Eliminate { row, index, next },
            Self::Pivot(source) => Cursor::Pivot(source),
            Self::Invert {
                pivot, exponent, ..
            } => Cursor::Invert { pivot, exponent },
            Self::Square {
                pivot, exponent, ..
            } => Cursor::Square { pivot, exponent },
            Self::Zero(index) => Cursor::Zero(index),
            Self::Normalize { pivot, index, .. } => Cursor::Normalize { pivot, index },
            Self::Others { pivot, row } => Cursor::Others { pivot, row },
            Self::OtherEliminate {
                pivot, row, index, ..
            } => Cursor::OtherEliminate { pivot, row, index },
            Self::CandidateCount { pivot, index, .. } => Cursor::CandidateCount { pivot, index },
            // Scan visits one versioned row count, without a coefficient cursor.
            Self::Scan { row } => Cursor::Scan { row, index: 0 },
            Self::FindSlot { pivot, row } => Cursor::FindSlot { pivot, row },
            Self::Insert { pivot, row, index } => Cursor::Insert { pivot, row, index },
            Self::Validate { row, id, index, .. } => Cursor::Validate {
                row,
                source: id,
                index,
            },
            Self::Store { row, id, index } => Cursor::Store {
                row,
                source: id,
                index,
            },
            Self::Advance => Cursor::Advance,
            Self::Evict(source) => Cursor::Evict(source),
            Self::History(index) => Cursor::History(index),
            Self::Commit => Cursor::Commit,
        }
    }
}
struct Job {
    ticket: Ticket,
    resume: Option<Phase>,
    // Only authenticated originals with no unresolved equation may bypass
    // candidate algebra. The existing input vector retains exact length/padding.
    systematic: bool,
    // Exact coefficient count from CandidateCount, retained until row insertion.
    candidate_nonzero: usize,
    input: Input,
    phase: Phase,
    // Injected original arrival and successful decoder admission. These are
    // diagnostic facts only; every deadline still uses the original inputs.
    received: Tick,
    admitted: Tick,
    deadline: Tick,
    debt: Option<Tick>,
    recovered: usize,
}
/// Initial packet staging result; Staged is not yet committed recovery receipt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Begin {
    /// One bounded input job is now owned.
    Staged,
    /// Exact retained source/repair duplicate; no work job allocated.
    Duplicate,
    /// Outside retained history or no remaining useful support.
    Stale,
}
/// Result of one bounded service call.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DecodeStep {
    /// No staged input exists.
    Idle(WorkUsed),
    /// Original job is retained for another budgeted call.
    Pending(WorkUsed),
    /// Exact state was committed atomically; prefix is not native delivery.
    Accepted {
        /// Actual work consumed.
        work: WorkUsed,
        /// Number of newly decoded original sources.
        recovered: usize,
        /// Contiguous exact decoded prefix.
        prefix: u32,
    },
    /// Innovative row exceeded finite storage; prior live state is unchanged.
    Capacity(WorkUsed),
}
/// Bounded recovery and ownership observations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DecoderStatus {
    /// Greatest committed authenticated source end, including equations.
    pub observed_end: u32,
    /// Contiguous published receipt prefix; decoded future columns may be retained.
    pub decoded_prefix: u32,
    /// Contiguous upper recovery-consumer handoff prefix, not native delivery.
    pub handoff_prefix: u32,
    /// Historical and future known source vectors retained in the bounded ring.
    pub known_sources: usize,
    /// Independent unresolved rows.
    pub rank: usize,
    /// A bounded candidate/shadow job is owned.
    pub pending_job: bool,
    /// Oldest accepted repair-ID history floor.
    pub repair_floor: u64,
    /// Latched terminal failure.
    pub terminal: Option<Error>,
}
#[derive(Clone, Copy)]
struct Row {
    version: Cell<()>,
    nonzero: [usize; 2],
    // Physical writes to each bank, including partially prepared/aborted versions.
    // A cleared bit proves that its coefficient block is zero in that bank.
    blocks: [u64; 2],
}
impl Row {
    fn new() -> Self {
        Self {
            version: Cell::new(),
            nonzero: [0; 2],
            blocks: [0; 2],
        }
    }
    fn selected(&self, pool: &Pool, active: Option<Ticket>) -> Result<Option<usize>, Error> {
        self.version.selected(pool, active)
    }
    fn prepare(
        &mut self,
        pool: &mut Pool,
        active: Ticket,
    ) -> Result<(usize, Option<usize>), Error> {
        self.version.prepare(pool, active)
    }
}
/// Resumable atomic rolling decoder retaining nearly 2W known columns.
pub struct Decoder {
    config: Config,
    scope: Scope,
    width: usize,
    live: Header,
    shadow: Header,
    data: [Vec<u8>; 2],
    known: Vec<Cell<Option<u32>>>,
    pivots: Vec<Cell<Option<u32>>>,
    map: Vec<Cell<Option<usize>>>,
    // The coefficient count follows the same two-version transaction decision
    // as its row bytes. A failed candidate cannot publish a shadow count.
    rows: Vec<Row>,
    decisions: Pool,
    active: Option<Ticket>,
    // Immutable while referenced by committed identities. Candidate recovery may
    // stage only into vacant slots; publication is the identity-bank commit.
    known_data: Vec<u8>,
    input: Vec<u8>,
    candidate: Vec<u8>,
    candidate_blocks: u64,
    history: Vec<u8>,
    history_meta: Vec<Option<Descriptor>>,
    history_floor: u64,
    highest_repair: u64,
    job: Option<Job>,
    handoff: u32,
    last: Tick,
    debt: Option<Tick>,
    delivery: Option<Tick>,
    terminal: Option<Error>,
    expiry_failure: Option<expiry::Failure>,
    explicit: Option<explicit::DecoderState>,
    sliding: Option<lifetimes::Sliding>,
}
// The outer step already paid the first metadata visit. A coefficient chunk
// stops before the row end; the following transition keeps its separate visit.
fn metadata_chunk(remaining: usize, budget: &WorkBudget) -> Result<usize, Error> {
    Ok(remaining.min(add(budget.metadata, 1)?))
}

// step() already charged the first metadata visit. Each copied/cleared byte
// still consumes one copy and one metadata unit; batching removes dispatch only.
// The end-of-phase transition remains a separate, unchanged metadata visit.
fn copy_chunk(remaining: usize, budget: &WorkBudget) -> Result<usize, Error> {
    Ok(remaining.min(budget.copies).min(add(budget.metadata, 1)?))
}
fn charge_copy_chunk(count: usize, budget: &mut WorkBudget) {
    // The caller has a nonempty phase and nonzero copy budget. copy_chunk also
    // bounds count by the remaining metadata plus the visit already charged.
    budget.copies -= count;
    budget.metadata -= count - 1;
}

// The caller preserves the original first field debit before identity lookup;
// step() already charged its metadata visit. Additional bytes consume both
// domains without another phase dispatch or crossing this source/row extent.
fn field_chunk(remaining: usize, budget: &WorkBudget) -> Result<usize, Error> {
    Ok(remaining
        .min(add(budget.field, 1)?)
        .min(add(budget.metadata, 1)?))
}
fn charge_field_chunk(count: usize, budget: &mut WorkBudget) {
    budget.field -= count - 1;
    budget.metadata -= count - 1;
}

// One machine word covers the whole circular coefficient array, independent
// of the absolute source IDs. Payload bytes always stay in the work range.
fn coefficient_block_bytes(window: usize) -> usize {
    window.div_ceil(u64::BITS as usize).max(128)
}

fn coefficient_run(
    index: usize,
    end: usize,
    window: usize,
    blocks: u64,
) -> Result<std::ops::Range<usize>, Error> {
    if index > end || window > end {
        return Err(Error::Identity);
    }
    let width = coefficient_block_bytes(window);
    if window <= width || index >= window {
        return Ok(index..end);
    }
    let block = index / width;
    let remaining = blocks >> block;
    if remaining == 0 {
        return Ok(window..end);
    }
    let skip = remaining.trailing_zeros() as usize;
    let active = (remaining >> skip).trailing_ones() as usize;
    let start = if skip == 0 {
        index
    } else {
        ((block + skip) * width).min(window)
    };
    let stop = ((block + skip + active) * width).min(window);
    Ok(start..if stop == window { end } else { stop })
}

enum Action {
    Continue,
    Paused,
    Accepted,
    Capacity,
}
impl Decoder {
    pub(crate) fn requested_storage(config: Config) -> Result<storage::Usage, storage::Error> {
        let width = storage::width(config)?;
        let row_bytes = mul(config.max_rows, add(config.window, width)?)?;
        let cells = add(mul(3, config.window)?, mul(2, config.max_rows)?)?;
        storage::requested::<u8>(row_bytes)?
            .join(storage::requested::<u8>(row_bytes)?)?
            .join(storage::requested::<Cell<Option<u32>>>(mul(
                2,
                config.window,
            )?)?)?
            .join(storage::requested::<Cell<Option<u32>>>(config.max_rows)?)?
            .join(storage::requested::<Cell<Option<usize>>>(config.window)?)?
            .join(storage::requested::<Row>(config.max_rows)?)?
            .join(Pool::requested_storage(cells)?)?
            .join(storage::requested::<u8>(mul(
                mul(2, config.window)?,
                width,
            )?)?)?
            .join(storage::requested::<u8>(width)?)?
            .join(storage::requested::<u8>(add(config.window, width)?)?)?
            .join(storage::requested::<u8>(mul(
                config.repair_history,
                width,
            )?)?)?
            .join(storage::requested::<Option<Descriptor>>(
                config.repair_history,
            )?)
    }

    pub(crate) fn storage_usage(&self) -> Result<storage::Usage, storage::Error> {
        let usage = storage::Usage::vector(&self.data[0])?
            .join(storage::Usage::vector(&self.data[1])?)?
            .join(storage::Usage::vector(&self.known)?)?
            .join(storage::Usage::vector(&self.pivots)?)?
            .join(storage::Usage::vector(&self.map)?)?
            .join(storage::Usage::vector(&self.rows)?)?
            .join(self.decisions.storage_usage()?)?
            .join(storage::Usage::vector(&self.known_data)?)?
            .join(storage::Usage::vector(&self.input)?)?
            .join(storage::Usage::vector(&self.candidate)?)?
            .join(storage::Usage::vector(&self.history)?)?
            .join(storage::Usage::vector(&self.history_meta)?)?;
        let usage = match &self.sliding {
            Some(sliding) => usage.join(sliding.usage()?)?,
            None => usage,
        };
        match &self.explicit {
            Some(state) => usage.join(state.storage_usage()?),
            None => Ok(usage),
        }
    }
    pub(crate) fn explicit_requested_storage(
        config: Config,
    ) -> Result<storage::Usage, storage::Error> {
        Self::requested_storage(config)?.join(explicit::DecoderState::requested_storage(
            config.repair_history,
        )?)
    }
    pub(crate) fn explicit_memory_bound(config: Config) -> Result<usize, Error> {
        add(
            Self::memory_bound(config)?,
            explicit::DecoderState::memory_bound(config.repair_history)?,
        )
    }
    pub(crate) fn sliding_requested_storage(
        config: Config,
    ) -> Result<storage::Usage, storage::Error> {
        Self::requested_storage(config)?.join(lifetimes::Sliding::requested(config)?)
    }
    pub(crate) fn sliding_memory_bound(config: Config) -> Result<usize, Error> {
        add(
            Self::memory_bound(config)?,
            lifetimes::Sliding::bytes(config)?,
        )
    }
    pub(crate) fn new_sliding(config: Config, scope: Scope, now: Tick) -> Result<Self, Error> {
        if Self::sliding_memory_bound(config)? > config.memory_bytes {
            return Err(Error::Capacity);
        }
        let mut owner = Self::new(config, scope, now)?;
        owner.sliding = Some(lifetimes::Sliding::new(config)?);
        Ok(owner)
    }

    pub(crate) fn new_explicit(config: Config, scope: Scope, now: Tick) -> Result<Self, Error> {
        if Self::explicit_memory_bound(config)? > config.memory_bytes {
            return Err(Error::Capacity);
        }
        let mut owner = Self::new(config, scope, now)?;
        owner.explicit = Some(explicit::DecoderState::new(config.repair_history)?);
        Ok(owner)
    }

    /// Fixed equation versions, metadata decisions and history, checked before allocation.
    pub fn memory_bound(c: Config) -> Result<usize, Error> {
        let width = c.width()?;
        let rows = mul(c.max_rows, add(c.window, width)?)?;
        let cells = add(mul(3, c.window)?, mul(2, c.max_rows)?)?;
        let metadata = add(
            add(
                mul(
                    add(mul(2, c.window)?, c.max_rows)?,
                    std::mem::size_of::<Cell<Option<u32>>>(),
                )?,
                mul(c.window, std::mem::size_of::<Cell<Option<usize>>>())?,
            )?,
            add(
                mul(c.max_rows, std::mem::size_of::<Row>())?,
                Pool::memory_bound(cells)?,
            )?,
        )?;
        add(
            add(mul(2, rows)?, metadata)?,
            add(
                mul(
                    c.repair_history,
                    add(width, std::mem::size_of::<Option<Descriptor>>())?,
                )?,
                add(
                    mul(2 * c.window, width)?,
                    add(add(width, c.window + width)?, std::mem::size_of::<Self>())?,
                )?,
            )?,
        )
    }
    /// Construct every bounded bank/scratch/history allocation before packet ingress.
    pub fn new(config: Config, scope: Scope, now: Tick) -> Result<Self, Error> {
        if Self::memory_bound(config)? > config.memory_bytes {
            return Err(Error::Capacity);
        }
        for ticks in [config.job_ticks, config.debt_ticks, config.handoff_ticks] {
            deadline(now, ticks)?;
        }
        let width = config.width()?;
        Ok(Self {
            config,
            scope,
            width,
            live: Header::default(),
            shadow: Header::default(),
            data: [
                bytes(mul(config.max_rows, add(config.window, width)?)?)?,
                bytes(mul(config.max_rows, add(config.window, width)?)?)?,
            ],
            known: slots(2 * config.window, Cell::new())?,
            pivots: slots(config.max_rows, Cell::new())?,
            map: slots(config.window, Cell::new())?,
            rows: slots(config.max_rows, Row::new())?,
            decisions: Pool::new(add(mul(3, config.window)?, mul(2, config.max_rows)?)?)?,
            active: None,
            known_data: bytes(mul(2 * config.window, width)?)?,
            input: bytes(width)?,
            candidate: bytes(config.window + width)?,
            candidate_blocks: 0,
            history: bytes(mul(config.repair_history, width)?)?,
            history_meta: slots(config.repair_history, None)?,
            history_floor: 1,
            highest_repair: 0,
            job: None,
            handoff: 0,
            last: now,
            debt: None,
            delivery: None,
            terminal: None,
            expiry_failure: None,
            explicit: None,
            sliding: None,
        })
    }
    fn time(&mut self, now: Tick) -> Result<(), Error> {
        if self.terminal.is_some() {
            return Err(Error::Terminal);
        }
        if let Err(error) = check_time(
            self.last,
            now,
            &[
                self.debt,
                self.delivery,
                self.job.as_ref().map(|job| job.deadline),
            ],
        ) {
            if error == Error::Expired {
                self.expiry_failure = self
                    .expiry_failure
                    .or_else(|| self.expiry_snapshot().first_expired(now, &[0, 1, 2]));
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
            Err(error) => self.fail(error),
        }
    }
    fn fail<T>(&mut self, error: Error) -> Result<T, Error> {
        self.terminal = Some(error);
        Err(error)
    }
    fn input_deadlines(
        &mut self,
        input: Input,
        received: Tick,
        observed: Tick,
        cap: Tick,
    ) -> Result<(Tick, Option<Tick>), Error> {
        if received > observed {
            return self.fail(Error::TimeRegression);
        }
        let job_end = self.expires(received, self.config.job_ticks)?.min(cap);
        let debt_end = self.expires(received, self.config.debt_ticks)?.min(cap);
        let debt = match self.debt {
            Some(value) => Some(value.min(debt_end)),
            None if input.end() > self.live.prefix => Some(debt_end),
            None => None,
        };
        if observed >= job_end || debt.is_some_and(|end| observed >= end) {
            let at = if observed >= job_end {
                job_end
            } else {
                debt.unwrap_or(job_end)
            };
            self.expiry_failure.get_or_insert(expiry::Failure {
                observed,
                selected: expiry::Deadline::new(
                    if observed >= job_end {
                        expiry::Kind::DecoderJob
                    } else {
                        expiry::Kind::DecoderDebt
                    },
                    at,
                    Some(input.expiry_identity()),
                ),
            });
            return self.fail(Error::Expired);
        }
        // Sliding windows retain the original cap only for newly evidenced IDs.
        // Existing IDs already have their own cap. A job still observes both.
        Ok((
            job_end,
            if self.sliding.is_some() {
                Some(debt_end)
            } else {
                debt
            },
        ))
    }
    fn stage(
        &mut self,
        input: Input,
        job_end: Tick,
        debt: Option<Tick>,
        received: Tick,
        admitted: Tick,
    ) -> Result<Begin, Error> {
        let ticket = self.decisions.begin()?;
        self.active = Some(ticket);
        self.shadow = self.live;
        self.shadow.observed = self.shadow.observed.max(input.end());
        // Every committed equation ends at or before the exclusive observed end.
        // A newer original cannot eliminate a coefficient in any retained row.
        let systematic =
            matches!(input, Input::Source(id) if self.live.rank == 0 || id >= self.live.observed);
        let phase = if let Input::Source(id) = input
            && systematic
        {
            Phase::Validate {
                row: None,
                id,
                index: 0,
                length: 0,
            }
        } else {
            Phase::Clear(0)
        };
        self.job = Some(Job {
            ticket,
            resume: None,
            systematic,
            candidate_nonzero: 0,
            input,
            phase,
            received,
            admitted,
            deadline: job_end,
            debt,
            recovered: 0,
        });
        Ok(Begin::Staged)
    }
    /// Stage an exact authenticated original. Only the bounded input copy occurs here.
    /// Parser errors and Busy leave live recovery state unchanged.
    pub fn begin_source(
        &mut self,
        scope: Scope,
        id: SourceId,
        original: &[u8],
        now: Tick,
    ) -> Result<Begin, Error> {
        self.begin_source_at(scope, id, original, now, now)
    }
    /// Preserve original authenticated input age while observing current time.
    pub fn begin_source_at(
        &mut self,
        scope: Scope,
        id: SourceId,
        original: &[u8],
        received: Tick,
        observed: Tick,
    ) -> Result<Begin, Error> {
        self.begin_source_until(scope, id, original, received, observed, Tick(u64::MAX))
    }
    /// Clamp original job/debt age to the caller's retained operation/session cap.
    pub fn begin_source_until(
        &mut self,
        scope: Scope,
        id: SourceId,
        original: &[u8],
        received: Tick,
        now: Tick,
        original_deadline: Tick,
    ) -> Result<Begin, Error> {
        self.source_input(scope, id, original, received, now, original_deadline, true)?
            .ok_or(Error::Busy)
    }

    /// Classify committed sources before optionally staging fresh decoder work.
    /// The candidate store can write only outside the committed retention horizon.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn source_input(
        &mut self,
        scope: Scope,
        id: SourceId,
        original: &[u8],
        received: Tick,
        now: Tick,
        original_deadline: Tick,
        stage_new: bool,
    ) -> Result<Option<Begin>, Error> {
        if scope != self.scope {
            return Err(Error::Scope);
        }
        if id.0 == u32::MAX {
            return Err(Error::Identity);
        }
        if original.is_empty() || original.len() > self.config.max_payload {
            return Err(Error::Length);
        }
        self.time(now)?;
        if received > now {
            return self.fail(Error::TimeRegression);
        }
        if now >= original_deadline {
            self.expiry_failure.get_or_insert(expiry::Failure {
                observed: now,
                selected: expiry::Deadline::new(
                    expiry::Kind::IncomingCap,
                    original_deadline,
                    Some(expiry::Identity::Sources {
                        first: id.0,
                        end: id.0 + 1,
                    }),
                ),
            });
            return self.fail(Error::Expired);
        }
        if stage_new && self.job.is_some() {
            return Err(Error::Busy);
        }
        let floor = self.live.prefix.saturating_sub(self.config.window as u32);
        if id.0 < floor {
            return Ok(Some(Begin::Stale));
        }
        if u64::from(id.0) >= u64::from(self.live.prefix) + self.config.window as u64 {
            // An earlier queued source can advance the window before a new
            // input takes its ordinary FIFO turn.
            return if stage_new {
                Err(Error::Identity)
            } else {
                Ok(None)
            };
        }
        let slot = id.0 as usize % (2 * self.config.window);
        if self.known[slot].get(&self.decisions, None)? == Some(id.0) {
            let data = &self.known_data[slot * self.width..(slot + 1) * self.width];
            let len = usize::from(u16::from_be_bytes([data[0], data[1]]));
            return if len == original.len() && data[2..2 + len] == *original {
                Ok(Some(Begin::Duplicate))
            } else {
                self.fail(Error::Conflict)
            };
        }
        if !stage_new {
            return Ok(None);
        }
        if id.0 < self.live.prefix {
            return self.fail(Error::Identity);
        }
        let input = Input::Source(id.0);
        let (job_end, debt) = self.input_deadlines(input, received, now, original_deadline)?;
        self.input[..2].copy_from_slice(&(original.len() as u16).to_be_bytes());
        self.input[2..2 + original.len()].copy_from_slice(original);
        self.input[2 + original.len()..].fill(0);
        self.stage(input, job_end, debt, received, now).map(Some)
    }
    /// Stage a complete authenticated equation; useful end<=prefix+W is checked first.
    pub fn begin_repair(&mut self, repair: Repair<'_>, now: Tick) -> Result<Begin, Error> {
        self.begin_repair_at(repair, now, now)
    }
    /// Preserve original repair arrival while observing current decoder time.
    pub fn begin_repair_at(
        &mut self,
        repair: Repair<'_>,
        received: Tick,
        observed: Tick,
    ) -> Result<Begin, Error> {
        self.begin_repair_until(repair, received, observed, Tick(u64::MAX))
    }
    /// Stage the same equation under original age and caller cap, without renewal.
    pub fn begin_repair_until(
        &mut self,
        repair: Repair<'_>,
        received: Tick,
        now: Tick,
        original_deadline: Tick,
    ) -> Result<Begin, Error> {
        if self.explicit.is_some() {
            return Err(Error::Configuration);
        }
        if repair.scope != self.scope {
            return Err(Error::Scope);
        }
        repair.validate_extent(self.width)?;
        if repair.id.0 == u64::MAX
            || self
                .config
                .support(repair.support.end, repair.id, repair.support.tail)?
                != repair.support
        {
            return Err(Error::Identity);
        }
        self.stage_repair(repair, None, 0, received, now, original_deadline)
    }
    // Structural and canonical profile validation belongs to the research owner.
    // This entry point still enforces the real decoder's complete finite horizon,
    // retained history, exact duplicate identity and original deadline rules.
    pub(crate) fn begin_equation_until(
        &mut self,
        repair: Repair<'_>,
        profile: crate::research::Profile,
        confirmed: u32,
        received: Tick,
        now: Tick,
        original_deadline: Tick,
    ) -> Result<Begin, Error> {
        if self.explicit.is_some() {
            return Err(Error::Configuration);
        }
        profile.validate()?;
        if repair.scope != self.scope {
            return Err(Error::Scope);
        }
        repair.validate_extent(self.width)?;
        if repair.id.0 == 0
            || u32::try_from(repair.id.0).is_err()
            || repair.support.end == 0
            || repair.support.start > repair.support.end
            || confirmed > repair.support.end
            || repair.support.end - repair.support.start > self.config.window as u32
        {
            return Err(Error::Identity);
        }
        self.stage_repair(
            repair,
            Some(profile),
            confirmed,
            received,
            now,
            original_deadline,
        )
    }
    // An explicit-only owner shares the exact same transactional GF solver.
    // Canonical terms are copied only for a newly staged job; duplicates compare
    // the complete retained coefficient row, without a digest or allocation.
    pub(crate) fn begin_explicit_until(
        &mut self,
        repair: Repair<'_>,
        terms: &[explicit::Term],
        received: Tick,
        now: Tick,
        cap: Tick,
    ) -> Result<Begin, Error> {
        if self.explicit.is_none() {
            return Err(Error::Configuration);
        }
        if repair.scope != self.scope {
            return Err(Error::Scope);
        }
        repair.validate_extent(self.width)?;
        if repair.id.0 == 0 || repair.id.0 == u64::MAX || repair.support.seed > 1 {
            return Err(Error::Identity);
        }
        let support = explicit::support(terms, repair.support.seed == 1, self.config.window)?;
        if support != repair.support {
            return Err(Error::Identity);
        }
        let begin = self.stage_repair(repair, None, 0, received, now, cap)?;
        let state = self.explicit.as_mut().ok_or(Error::Configuration)?;
        match begin {
            Begin::Staged => state.input.load(terms),
            Begin::Duplicate => {
                let slot = (repair.id.0 % self.config.repair_history as u64) as usize;
                if !state.matches(slot, terms) {
                    return self.fail(Error::Conflict);
                }
            }
            Begin::Stale => {}
        }
        Ok(begin)
    }
    fn stage_repair(
        &mut self,
        repair: Repair<'_>,
        profile: Option<crate::research::Profile>,
        confirmed: u32,
        received: Tick,
        now: Tick,
        original_deadline: Tick,
    ) -> Result<Begin, Error> {
        self.time(now)?;
        if received > now {
            return self.fail(Error::TimeRegression);
        }
        if now >= original_deadline {
            self.expiry_failure.get_or_insert(expiry::Failure {
                observed: now,
                selected: expiry::Deadline::new(
                    expiry::Kind::IncomingCap,
                    original_deadline,
                    Some(expiry::Identity::Repair {
                        id: repair.id,
                        support: Some((repair.support.start, repair.support.end)),
                    }),
                ),
            });
            return self.fail(Error::Expired);
        }
        if self.job.is_some() {
            return Err(Error::Busy);
        }
        if repair.id.0 < self.history_floor {
            return Ok(Begin::Stale);
        }
        let descriptor = Descriptor {
            id: repair.id,
            support: repair.support,
            profile,
            confirmed,
        };
        let slot = (repair.id.0 % self.config.repair_history as u64) as usize;
        if let Some(old) = self.history_meta[slot]
            && old.id == repair.id
        {
            let retained = &self.history[slot * self.width..(slot + 1) * self.width];
            return if old == descriptor
                && retained[..repair.bytes.len()] == *repair.bytes
                && retained[repair.bytes.len()..].iter().all(|byte| *byte == 0)
            {
                Ok(Begin::Duplicate)
            } else {
                self.fail(Error::Conflict)
            };
        }
        if repair.support.end <= self.live.prefix
            || repair.support.start < self.live.prefix.saturating_sub(self.config.window as u32)
        {
            return Ok(Begin::Stale);
        }
        if u64::from(repair.support.end) > u64::from(self.live.prefix) + self.config.window as u64 {
            return Err(Error::Identity);
        }
        let input = Input::Repair(descriptor);
        let (job_end, debt) = self.input_deadlines(input, received, now, original_deadline)?;
        // One bounded clear and prefix copy restore the same logical equation
        // used by the solver and duplicate history, without another allocation.
        self.input[..repair.bytes.len()].copy_from_slice(repair.bytes);
        self.input[repair.bytes.len()..].fill(0);
        self.stage(input, job_end, debt, received, now)
    }
    fn row_start(&self, row: usize) -> usize {
        row * (self.config.window + self.width)
    }
    fn known_at(&self, slot: usize) -> Result<Option<u32>, Error> {
        self.known[slot].get(&self.decisions, self.active)
    }
    fn live_known(&self, slot: usize) -> Result<Option<u32>, Error> {
        self.known[slot].get(&self.decisions, None)
    }
    fn pivot_at(&self, row: usize) -> Result<Option<u32>, Error> {
        self.pivots[row].get(&self.decisions, self.active)
    }
    fn map_at(&self, column: usize) -> Result<Option<usize>, Error> {
        self.map[column].get(&self.decisions, self.active)
    }
    fn set_known(&mut self, slot: usize, value: Option<u32>) -> Result<(), Error> {
        self.known[slot].set(
            &mut self.decisions,
            self.active.ok_or(Error::Identity)?,
            value,
        )
    }
    fn set_pivot(&mut self, row: usize, value: Option<u32>) -> Result<(), Error> {
        self.pivots[row].set(
            &mut self.decisions,
            self.active.ok_or(Error::Identity)?,
            value,
        )?;
        if value.is_some() {
            self.shadow.row_end = self.shadow.row_end.max(row + 1);
        } else if row + 1 == self.shadow.row_end {
            // Earlier vacant slots can remain in the bound until the last
            // live pivot clears. No occupied row may be skipped.
            self.shadow.row_end = row;
        }
        Ok(())
    }
    fn set_map(&mut self, column: usize, value: Option<usize>) -> Result<(), Error> {
        self.map[column].set(
            &mut self.decisions,
            self.active.ok_or(Error::Identity)?,
            value,
        )
    }
    fn known(&self, id: u32) -> Result<Option<usize>, Error> {
        let slot = id as usize % (2 * self.config.window);
        Ok((self.known_at(slot)? == Some(id)).then_some(slot * self.width))
    }
    fn row_bank(&self, row: usize, active: Option<Ticket>) -> Result<usize, Error> {
        self.rows[row]
            .selected(&self.decisions, active)?
            .ok_or(Error::Identity)
    }
    fn row_byte(&self, row: usize, index: usize) -> Result<u8, Error> {
        let bank = self.row_bank(row, self.active)?;
        Ok(self.data[bank][self.row_start(row) + index])
    }
    fn zero_coefficient_run(&self, id: u32, budget: &WorkBudget) -> Result<usize, Error> {
        let w = self.config.window;
        let remaining = self
            .shadow
            .observed
            .checked_sub(id)
            .ok_or(Error::Identity)?;
        let remaining = usize::try_from(remaining).map_err(|_| Error::Exhausted)?;
        let column = id as usize % w;
        // Do not cross the circular-column boundary, source-ID limit, first
        // nonzero coefficient or this turn's original metadata allowance.
        let bytes = metadata_chunk(remaining.min(w - column), budget)?;
        let coefficients = self
            .candidate
            .get(column..add(column, bytes)?)
            .ok_or(Error::Identity)?;
        Ok(coefficients
            .iter()
            .position(|value| *value != 0)
            .unwrap_or(bytes))
    }
    fn prepare_row(
        &mut self,
        job: &mut Job,
        row: usize,
        copy_old: bool,
        next: Phase,
    ) -> Result<(), Error> {
        let (to, from) = self.rows[row].prepare(&mut self.decisions, job.ticket)?;
        if copy_old && let Some(from) = from {
            self.rows[row].blocks[to] |= self.rows[row].blocks[from];
            job.resume = Some(next);
            job.phase = Phase::CopyRow {
                row,
                from,
                to,
                index: 0,
            };
        } else {
            if !copy_old {
                self.rows[row].blocks[to] |= self.candidate_blocks;
            }
            job.phase = next;
        }
        Ok(())
    }
    // The working row bank cannot change within one bounded phase visit.
    // Known-data writes stay private until the transaction publishes their ID.
    fn payload_storage(
        &mut self,
        row: Option<usize>,
        systematic: bool,
    ) -> Result<(&[u8], &mut [u8]), Error> {
        let payload = match row {
            Some(row) => {
                let bank = self.row_bank(row, self.active)?;
                let start = self.row_start(row) + self.config.window;
                &self.data[bank][start..start + self.width]
            }
            None if systematic => &self.input,
            None => &self.candidate[self.config.window..],
        };
        Ok((payload, &mut self.known_data))
    }
    fn advance(
        &mut self,
        job: &mut Job,
        budget: &mut WorkBudget,
        now: Tick,
    ) -> Result<Action, Error> {
        let w = self.config.window;
        let width = self.width;
        match job.phase {
            Phase::CopyRow {
                row,
                from,
                to,
                index,
            } => {
                let stride = add(w, width)?;
                if index == stride {
                    let target = self.rows.get_mut(row).ok_or(Error::Identity)?;
                    let nonzero = *target.nonzero.get(from).ok_or(Error::Identity)?;
                    *target.nonzero.get_mut(to).ok_or(Error::Identity)? = nonzero;
                    target.blocks[to] = target.blocks[from];
                    job.phase = job.resume.take().ok_or(Error::Identity)?;
                } else {
                    if budget.copies == 0 {
                        return Ok(Action::Paused);
                    }
                    let blocks = *self
                        .rows
                        .get(row)
                        .and_then(|r| r.blocks.get(to))
                        .ok_or(Error::Identity)?;
                    let run = coefficient_run(index, stride, w, blocks)?;
                    let index = run.start;
                    let remaining = run.len();
                    let count = copy_chunk(remaining, budget)?;
                    let start = add(mul(row, stride)?, index)?;
                    let end = add(start, count)?;
                    // Cell::prepare chooses the other version of this same row.
                    // Borrow the two actual banks separately; no temporary row,
                    // overlapping copy or committed-bank mutation is permitted.
                    let [first, second] = &mut self.data;
                    let (source, destination) = match (from, to) {
                        (0, 1) => (first, second),
                        (1, 0) => (second, first),
                        _ => return Err(Error::Identity),
                    };
                    let source = source.get(start..end).ok_or(Error::Identity)?;
                    let destination = destination.get_mut(start..end).ok_or(Error::Identity)?;
                    destination.copy_from_slice(source);
                    charge_copy_chunk(count, budget);
                    job.phase = Phase::CopyRow {
                        row,
                        from,
                        to,
                        index: add(index, count)?,
                    };
                }
            }
            Phase::Clear(i) => {
                let run = coefficient_run(i, self.candidate.len(), w, self.candidate_blocks)?;
                let i = run.start;
                if i == self.candidate.len() {
                    self.candidate_blocks = 0;
                    job.phase = Phase::Load(0);
                } else {
                    if budget.copies == 0 {
                        return Ok(Action::Paused);
                    }
                    let remaining = run.len();
                    let count = copy_chunk(remaining, budget)?;
                    let end = add(i, count)?;
                    self.candidate
                        .get_mut(i..end)
                        .ok_or(Error::Identity)?
                        .fill(0);
                    charge_copy_chunk(count, budget);
                    job.phase = Phase::Clear(end);
                }
            }
            Phase::Load(i) => {
                if i == width {
                    job.phase = Phase::Support(job.input.start());
                } else {
                    if budget.copies == 0 {
                        return Ok(Action::Paused);
                    }
                    let remaining = width.checked_sub(i).ok_or(Error::Identity)?;
                    let count = copy_chunk(remaining, budget)?;
                    let end = add(i, count)?;
                    let source = self.input.get(i..end).ok_or(Error::Identity)?;
                    let destination = self
                        .candidate
                        .get_mut(add(w, i)?..add(w, end)?)
                        .ok_or(Error::Identity)?;
                    destination.copy_from_slice(source);
                    charge_copy_chunk(count, budget);
                    job.phase = Phase::Load(end);
                }
            }
            Phase::Support(id) => {
                if id == job.input.end() {
                    job.phase = Phase::Reduce(job.input.start().max(self.live.prefix));
                } else {
                    // A research metadata visit includes at most sixteen
                    // single-block SHA-256 evaluations, bounded by Profile.
                    let factor = if matches!(job.input, Input::Repair(_)) {
                        match &self.explicit {
                            Some(state) => state.input.coefficient(id),
                            None => job.input.coefficient(id)?,
                        }
                    } else {
                        job.input.coefficient(id)?
                    };
                    if factor == 0 {
                        job.phase = Phase::Support(id + 1);
                    } else if let Some(start) = self.known(id)? {
                        // Known vectors were length/padding validated before
                        // publication. Their suffix is algebraic zero, so it
                        // requires neither GF work nor per-byte metadata visits.
                        let prefix = self
                            .known_data
                            .get(start..add(start, 2)?)
                            .ok_or(Error::Identity)?;
                        let extent =
                            add(2, usize::from(u16::from_be_bytes([prefix[0], prefix[1]])))?;
                        if !(3..=width).contains(&extent) {
                            return Err(Error::Identity);
                        }
                        job.phase = Phase::Known {
                            source: id,
                            factor,
                            column: 0,
                            extent,
                        };
                    } else {
                        if id < self.live.prefix {
                            return Err(Error::Identity);
                        }
                        self.candidate[id as usize % w] = factor;
                        self.candidate_blocks |=
                            1u64 << ((id as usize % w) / coefficient_block_bytes(w));
                        job.phase = Phase::Support(id + 1);
                    }
                }
            }
            Phase::Known {
                source,
                factor,
                column,
                extent,
            } => {
                if column == extent {
                    job.phase = Phase::Support(source + 1);
                } else {
                    if !spend(&mut budget.field) {
                        return Ok(Action::Paused);
                    }
                    let start = self.known(source)?.ok_or(Error::Identity)?;
                    let remaining = extent.checked_sub(column).ok_or(Error::Identity)?;
                    let count = field_chunk(remaining, budget)?;
                    let end = add(column, count)?;
                    let known = self
                        .known_data
                        .get(add(start, column)?..add(start, end)?)
                        .ok_or(Error::Identity)?;
                    let candidate = self
                        .candidate
                        .get_mut(add(w, column)?..add(w, end)?)
                        .ok_or(Error::Identity)?;
                    xor_scaled::<false>(candidate, known, factor);
                    charge_field_chunk(count, budget);
                    job.phase = Phase::Known {
                        source,
                        factor,
                        column: end,
                        extent,
                    };
                }
            }
            Phase::Reduce(id) => {
                // A retained row has no term below its pivot. Elimination can
                // introduce later terms only inside the observed source horizon.
                if id >= self.shadow.observed {
                    job.phase = Phase::Pivot(job.input.start().max(self.live.prefix));
                } else {
                    let factor = self.candidate[id as usize % w];
                    if factor == 0 {
                        let count = self.zero_coefficient_run(id, budget)?;
                        budget.metadata -= count - 1;
                        job.phase = Phase::Reduce(
                            id.checked_add(u32::try_from(count).map_err(|_| Error::Exhausted)?)
                                .ok_or(Error::Exhausted)?,
                        );
                        return Ok(Action::Continue);
                    }
                    if let Some(row) = self.map_at(id as usize % w)? {
                        if self.pivot_at(row)? != Some(id) {
                            return Err(Error::Identity);
                        }
                        job.phase = Phase::Eliminate {
                            row,
                            factor,
                            index: 0,
                            next: id + 1,
                        };
                        return Ok(Action::Continue);
                    }
                    job.phase = Phase::Reduce(id + 1);
                }
            }
            Phase::Eliminate {
                row,
                factor,
                index,
                next,
            } => {
                if index == w + width {
                    job.phase = Phase::Reduce(next);
                } else {
                    if !spend(&mut budget.field) {
                        return Ok(Action::Paused);
                    }
                    let bank = self.row_bank(row, self.active)?;
                    let blocks = self.rows[row].blocks[bank];
                    self.candidate_blocks |= blocks;
                    let run = coefficient_run(index, w + width, w, blocks)?;
                    let index = run.start;
                    // No transaction decision changes within this row chunk.
                    let stride = add(w, width)?;
                    let remaining = run.len();
                    let count = field_chunk(remaining, budget)?;
                    let end = add(index, count)?;
                    let start = mul(row, stride)?;
                    let equation = self.data[bank]
                        .get(add(start, index)?..add(start, end)?)
                        .ok_or(Error::Identity)?;
                    let candidate = self.candidate.get_mut(index..end).ok_or(Error::Identity)?;
                    xor_scaled::<false>(candidate, equation, factor);
                    charge_field_chunk(count, budget);
                    job.phase = Phase::Eliminate {
                        row,
                        factor,
                        index: end,
                        next,
                    };
                }
            }
            Phase::Pivot(id) => {
                if id >= self.shadow.observed {
                    job.phase = Phase::Zero(0);
                } else {
                    let value = self.candidate[id as usize % w];
                    if value == 0 {
                        let count = self.zero_coefficient_run(id, budget)?;
                        budget.metadata -= count - 1;
                        job.phase = Phase::Pivot(
                            id.checked_add(u32::try_from(count).map_err(|_| Error::Exhausted)?)
                                .ok_or(Error::Exhausted)?,
                        );
                    } else {
                        job.phase = Phase::Invert {
                            pivot: id,
                            result: 1,
                            base: value,
                            exponent: 254,
                        };
                    }
                }
            }
            Phase::Invert {
                pivot,
                mut result,
                base,
                exponent,
            } => {
                if exponent == 0 {
                    job.phase = Phase::Normalize {
                        pivot,
                        factor: result,
                        index: 0,
                    };
                } else {
                    if exponent & 1 != 0 {
                        if !spend(&mut budget.field) {
                            return Ok(Action::Paused);
                        }
                        result = field::multiply(result, base);
                    }
                    job.phase = Phase::Square {
                        pivot,
                        result,
                        base,
                        exponent,
                    };
                }
            }
            Phase::Square {
                pivot,
                result,
                base,
                exponent,
            } => {
                if !spend(&mut budget.field) {
                    return Ok(Action::Paused);
                }
                job.phase = Phase::Invert {
                    pivot,
                    result,
                    base: field::multiply(base, base),
                    exponent: exponent >> 1,
                };
            }
            Phase::Zero(i) => {
                if i == width {
                    job.phase = Phase::Advance;
                } else {
                    if !spend(&mut budget.copies) {
                        return Ok(Action::Paused);
                    }
                    let count = metadata_chunk(width - i, budget)?.min(1 + budget.copies);
                    let end = i + count;
                    if self.candidate[w + i..w + end].iter().any(|&byte| byte != 0) {
                        return Err(Error::Inconsistent);
                    }
                    budget.copies -= count - 1;
                    budget.metadata -= count - 1;
                    job.phase = Phase::Zero(end);
                }
            }
            Phase::Normalize {
                pivot,
                factor,
                index,
            } => {
                let run = coefficient_run(index, w + width, w, self.candidate_blocks)?;
                let index = run.start;
                if index == w + width {
                    job.phase = Phase::Others { pivot, row: 0 };
                } else {
                    if !spend(&mut budget.field) {
                        return Ok(Action::Paused);
                    }
                    let remaining = run.len();
                    let count = field_chunk(remaining, budget)?;
                    let end = add(index, count)?;
                    let candidate = self.candidate.get_mut(index..end).ok_or(Error::Identity)?;
                    if factor != 1 {
                        let products = &gf_batch::MULTIPLICATION_ROWS[usize::from(factor)];
                        for value in candidate {
                            *value = products[usize::from(*value)];
                        }
                    }
                    charge_field_chunk(count, budget);
                    job.phase = Phase::Normalize {
                        pivot,
                        factor,
                        index: end,
                    };
                }
            }
            Phase::Others { pivot, row } => {
                if row >= self.shadow.row_end {
                    job.phase = Phase::CandidateCount {
                        pivot,
                        index: 0,
                        count: 0,
                    };
                } else if self.pivot_at(row)?.is_none() {
                    job.phase = Phase::Others {
                        pivot,
                        row: row + 1,
                    };
                } else {
                    let factor = self.row_byte(row, pivot as usize % w)?;
                    if factor == 0 {
                        job.phase = Phase::Others {
                            pivot,
                            row: row + 1,
                        };
                    } else {
                        self.prepare_row(
                            job,
                            row,
                            true,
                            Phase::OtherEliminate {
                                pivot,
                                row,
                                factor,
                                index: 0,
                            },
                        )?;
                    }
                }
            }
            Phase::OtherEliminate {
                pivot,
                row,
                factor,
                index,
            } => {
                let run = coefficient_run(index, w + width, w, self.candidate_blocks)?;
                let index = run.start;
                if index == w + width {
                    job.phase = Phase::Others {
                        pivot,
                        row: row + 1,
                    };
                } else {
                    if !spend(&mut budget.field) {
                        return Ok(Action::Paused);
                    }
                    // prepare_row already selected this transaction's writable
                    // bank. Resolve it after the original first field debit;
                    // no decision or source row changes within this chunk.
                    let bank = self.row_bank(row, self.active)?;
                    self.rows[row].blocks[bank] |= self.candidate_blocks;
                    let stride = add(w, width)?;
                    let remaining = run.len();
                    let count = field_chunk(remaining, budget)?;
                    let end = add(index, count)?;
                    let start = mul(row, stride)?;
                    let nonzero = self.rows[row].nonzero[bank];
                    let candidate = self.candidate.get(index..end).ok_or(Error::Identity)?;
                    let equation = self.data[bank]
                        .get_mut(add(start, index)?..add(start, end)?)
                        .ok_or(Error::Identity)?;
                    let coefficients = w.saturating_sub(index).min(count);
                    let (coefficient_row, payload_row) = equation.split_at_mut(coefficients);
                    let (coefficient_input, payload_input) = candidate.split_at(coefficients);
                    let (removed, added) =
                        xor_scaled::<true>(coefficient_row, coefficient_input, factor);
                    xor_scaled::<false>(payload_row, payload_input, factor);
                    let nonzero = nonzero.checked_sub(removed).ok_or(Error::Identity)?;
                    let nonzero = add(nonzero, added)?;
                    if nonzero > w {
                        return Err(Error::Identity);
                    }
                    self.rows[row].nonzero[bank] = nonzero;
                    charge_field_chunk(count, budget);
                    job.phase = Phase::OtherEliminate {
                        pivot,
                        row,
                        factor,
                        index: end,
                    };
                }
            }
            Phase::CandidateCount {
                pivot,
                index,
                count,
            } => {
                let run = coefficient_run(index, w, w, self.candidate_blocks)?;
                let index = run.start;
                if index == w {
                    job.candidate_nonzero = count;
                    if count == 1 {
                        job.phase = Phase::Validate {
                            row: None,
                            id: pivot,
                            index: 0,
                            length: 0,
                        };
                    } else {
                        job.phase = Phase::FindSlot { pivot, row: 0 };
                    }
                } else {
                    let remaining = run.len();
                    let bytes = metadata_chunk(remaining, budget)?;
                    let end = add(index, bytes)?;
                    let coefficients = self.candidate.get(index..end).ok_or(Error::Identity)?;
                    let count = add(
                        count,
                        coefficients.iter().filter(|value| **value != 0).count(),
                    )?;
                    budget.metadata -= bytes - 1;
                    job.phase = Phase::CandidateCount {
                        pivot,
                        index: end,
                        count,
                    };
                }
            }
            Phase::FindSlot { pivot, row } => {
                if row == self.config.max_rows {
                    return Ok(Action::Capacity);
                }
                if self.pivot_at(row)?.is_none() {
                    self.prepare_row(
                        job,
                        row,
                        false,
                        Phase::Insert {
                            pivot,
                            row,
                            index: 0,
                        },
                    )?;
                } else {
                    job.phase = Phase::FindSlot {
                        pivot,
                        row: row + 1,
                    };
                }
            }
            Phase::Insert { pivot, row, index } => {
                if index == w + width {
                    let bank = self.row_bank(row, self.active)?;
                    self.rows[row].nonzero[bank] = job.candidate_nonzero;
                    self.rows[row].blocks[bank] = self.candidate_blocks;
                    self.set_pivot(row, Some(pivot))?;
                    self.set_map(pivot as usize % w, Some(row))?;
                    self.shadow.rank += 1;
                    job.phase = Phase::Scan { row: 0 };
                } else {
                    if !spend(&mut budget.copies) {
                        return Ok(Action::Paused);
                    }
                    let bank = self.row_bank(row, self.active)?;
                    let run = coefficient_run(index, w + width, w, self.rows[row].blocks[bank])?;
                    let index = run.start;
                    // The first copy and metadata visit are already charged.
                    // Preserve the separate end visit that publishes the pivot.
                    let stride = add(w, width)?;
                    let remaining = run.len();
                    let count = remaining
                        .min(add(budget.copies, 1)?)
                        .min(add(budget.metadata, 1)?);
                    let end = add(index, count)?;
                    let start = mul(row, stride)?;
                    let candidate = self.candidate.get(index..end).ok_or(Error::Identity)?;
                    self.data[bank]
                        .get_mut(add(start, index)?..add(start, end)?)
                        .ok_or(Error::Identity)?
                        .copy_from_slice(candidate);
                    budget.copies -= count - 1;
                    budget.metadata -= count - 1;
                    job.phase = Phase::Insert {
                        pivot,
                        row,
                        index: end,
                    };
                }
            }
            Phase::Scan { row } => {
                if row >= self.shadow.row_end {
                    job.phase = Phase::Advance;
                } else if let Some(pivot) = self.pivot_at(row)? {
                    // Insert publishes the complete count; CopyRow transfers it
                    // with the selected bank, and OtherEliminate updates it with
                    // each coefficient chunk. The transaction selects both bytes
                    // and count together, including after a rollback/reuse.
                    // This is one row visit paid by step, not w coefficient work.
                    let bank = self.row_bank(row, self.active)?;
                    let count = self.rows[row].nonzero[bank];
                    if count > w {
                        return Err(Error::Identity);
                    }
                    job.phase = if count == 1 {
                        Phase::Validate {
                            row: Some(row),
                            id: pivot,
                            index: 0,
                            length: 0,
                        }
                    } else {
                        Phase::Scan { row: row + 1 }
                    };
                } else {
                    job.phase = Phase::Scan { row: row + 1 };
                }
            }
            Phase::Validate {
                row,
                id,
                index,
                length,
            } => {
                if index == 0 {
                    let (payload, _) = self.payload_storage(row, job.systematic)?;
                    let length = usize::from(u16::from_be_bytes([payload[0], payload[1]]));
                    if length == 0 || length > self.config.max_payload {
                        return Err(Error::Length);
                    }
                    job.phase = Phase::Validate {
                        row,
                        id,
                        // Only the padding has a required value. Store charges
                        // the complete vector when it copies the original.
                        index: length + 2,
                        length,
                    };
                } else if index == width {
                    let slot = id as usize % (2 * w);
                    if let Some(old) = self.known_at(slot)?
                        && old >= self.shadow.prefix.saturating_sub(w as u32)
                    {
                        return Err(Error::Identity);
                    }
                    // Payload staging may touch only a slot unreachable through
                    // committed metadata. The authenticated horizon guarantees this
                    // for new identities even if candidate prefix advancement evicts
                    // additional shadow identities before commit.
                    if self
                        .live_known(slot)?
                        .is_some_and(|old| old >= self.live.prefix.saturating_sub(w as u32))
                    {
                        return Err(Error::Identity);
                    }
                    job.phase = Phase::Store { row, id, index: 0 };
                } else {
                    if !spend(&mut budget.copies) {
                        return Ok(Action::Paused);
                    }
                    let count = metadata_chunk(width - index, budget)?.min(1 + budget.copies);
                    let end = index + count;
                    let (payload, _) = self.payload_storage(row, job.systematic)?;
                    if payload[index..end].iter().any(|byte| *byte != 0) {
                        return Err(Error::Length);
                    }
                    budget.copies -= count - 1;
                    budget.metadata -= count - 1;
                    job.phase = Phase::Validate {
                        row,
                        id,
                        index: index + count,
                        length,
                    };
                }
            }
            Phase::Store { row, id, index } => {
                let slot = id as usize % (2 * w);
                if index == width {
                    if self.known_at(slot)?.is_none() {
                        self.shadow.known_count += 1;
                    }
                    self.set_known(slot, Some(id))?;
                    job.recovered += 1;
                    if let Some(row) = row {
                        self.set_pivot(row, None)?;
                        self.set_map(id as usize % w, None)?;
                        self.shadow.rank -= 1;
                        if self.shadow.rank == 0 {
                            self.shadow.row_end = 0;
                        }
                        job.phase = Phase::Scan { row: row + 1 };
                    } else if job.systematic {
                        // No committed row depends on this original. Shared
                        // prefix, eviction and publication still run.
                        job.phase = Phase::Advance;
                    } else {
                        job.phase = Phase::Scan { row: 0 };
                    }
                } else {
                    if !spend(&mut budget.copies) {
                        return Ok(Action::Paused);
                    }
                    // The slot remains invisible until its staged identity commits.
                    let target = slot * width + index;
                    let count = metadata_chunk(width - index, budget)?.min(1 + budget.copies);
                    let (payload, known) = self.payload_storage(row, job.systematic)?;
                    known[target..target + count].copy_from_slice(&payload[index..index + count]);
                    budget.copies -= count - 1;
                    budget.metadata -= count - 1;
                    job.phase = Phase::Store {
                        row,
                        id,
                        index: index + count,
                    };
                }
            }
            Phase::Advance => {
                let id = self.shadow.prefix;
                if ((id - self.handoff) as usize) < self.config.handoff_sources
                    && self.known_at(id as usize % (2 * w))? == Some(id)
                {
                    self.shadow.prefix = id.checked_add(1).ok_or(Error::Exhausted)?;
                } else {
                    job.phase = Phase::Evict(self.live.evicted_before);
                }
            }
            Phase::Evict(id) => {
                let floor = self.shadow.prefix.saturating_sub(w as u32);
                if id == floor {
                    self.shadow.evicted_before = floor;
                    job.phase = Phase::History(0);
                } else {
                    let slot = id as usize % (2 * w);
                    if self.known_at(slot)? == Some(id) {
                        self.set_known(slot, None)?;
                        self.shadow.known_count -= 1;
                    }
                    job.phase = Phase::Evict(id.checked_add(1).ok_or(Error::Exhausted)?);
                }
            }
            Phase::History(i) => {
                if let Input::Repair(d) = job.input {
                    let term_bytes = self.explicit.as_ref().map_or(0, |state| state.input.len());
                    if i == width + term_bytes {
                        job.phase = Phase::Commit;
                    } else {
                        if !spend(&mut budget.copies) {
                            return Ok(Action::Paused);
                        }
                        let slot = (d.id.0 % self.config.repair_history as u64) as usize;
                        if i < width {
                            let count = metadata_chunk(width - i, budget)?.min(1 + budget.copies);
                            let start = slot * width + i;
                            self.history[start..start + count]
                                .copy_from_slice(&self.input[i..i + count]);
                            budget.copies -= count - 1;
                            budget.metadata -= count - 1;
                            job.phase = Phase::History(i + count);
                        } else if let Some(state) = &mut self.explicit {
                            state.copy_history_byte(slot, i - width);
                            job.phase = Phase::History(i + 1);
                        }
                    }
                } else {
                    job.phase = Phase::Commit;
                }
            }
            Phase::Commit => {
                let observed_at = (self.shadow.observed > self.live.observed)
                    .then_some(job.debt)
                    .flatten();
                let published_at = self.publication_deadline(self.shadow.prefix, now)?;
                let delivery = if self.shadow.prefix > self.handoff {
                    Some(match self.delivery {
                        Some(value) => value,
                        None => self.expires(now, self.config.handoff_ticks)?,
                    })
                } else {
                    None
                };
                if let Input::Repair(d) = job.input {
                    let slot = (d.id.0 % self.config.repair_history as u64) as usize;
                    self.history_meta[slot] = Some(d);
                    if let Some(state) = &mut self.explicit {
                        state.commit(slot);
                    }
                    self.highest_repair = self.highest_repair.max(d.id.0);
                    self.history_floor = self
                        .highest_repair
                        .saturating_sub(self.config.repair_history as u64 - 1)
                        .max(1);
                }
                self.decisions.commit(job.ticket)?;
                self.active = None;
                self.live = self.shadow;
                self.debt = if self.live.prefix < self.live.observed {
                    job.debt
                } else {
                    None
                };
                self.delivery = delivery;
                self.refresh_sliding(observed_at, published_at);
                return Ok(Action::Accepted);
            }
        }
        Ok(Action::Continue)
    }
    fn publication_deadline(&mut self, new_prefix: u32, now: Tick) -> Result<Option<Tick>, Error> {
        if self.sliding.is_some() && new_prefix > self.live.prefix {
            return self.expires(now, self.config.handoff_ticks).map(Some);
        }
        Ok(None)
    }

    fn refresh_sliding(&mut self, observed_at: Option<Tick>, published_at: Option<Tick>) {
        if let Some(sliding) = &mut self.sliding {
            (self.debt, self.delivery) =
                sliding.refresh(self.live, self.handoff, observed_at, published_at);
        }
    }

    /// Advance only within supplied copy, field and metadata budgets.
    /// Upper handoff can continue during a job; publication obeys its separate bound.
    pub fn step(&mut self, now: Tick, mut budget: WorkBudget) -> Result<DecodeStep, Error> {
        budget.validate()?;
        self.time(now)?;
        let before = budget;
        let Some(mut job) = self.job.take() else {
            let old = self.live.prefix;
            while budget.metadata > 0
                && ((self.live.prefix - self.handoff) as usize) < self.config.handoff_sources
            {
                if self.live_known(self.live.prefix as usize % (2 * self.config.window))?
                    != Some(self.live.prefix)
                {
                    break;
                }
                let delivery = match self.delivery {
                    Some(value) => value,
                    None => self.expires(now, self.config.handoff_ticks)?,
                };
                self.live.prefix = self.live.prefix.checked_add(1).ok_or(Error::Exhausted)?;
                self.delivery = Some(delivery);
                budget.metadata -= 1;
            }
            if self.live.prefix == self.live.observed {
                self.debt = None;
            }
            if old < self.live.prefix && self.sliding.is_some() {
                let published_at = self.expires(now, self.config.handoff_ticks)?;
                self.refresh_sliding(None, Some(published_at));
            }
            return if old == self.live.prefix {
                Ok(DecodeStep::Idle(used(before, budget)))
            } else {
                Ok(DecodeStep::Accepted {
                    work: used(before, budget),
                    recovered: 0,
                    prefix: self.live.prefix,
                })
            };
        };
        while spend(&mut budget.metadata) {
            match self.advance(&mut job, &mut budget, now) {
                Ok(Action::Continue) => {}
                Ok(Action::Paused) => break,
                Ok(Action::Accepted) => {
                    return Ok(DecodeStep::Accepted {
                        work: used(before, budget),
                        recovered: job.recovered,
                        prefix: self.live.prefix,
                    });
                }
                Ok(Action::Capacity) => {
                    self.active = None;
                    self.decisions.release(job.ticket)?;
                    return Ok(DecodeStep::Capacity(used(before, budget)));
                }
                Err(error) => {
                    self.job = Some(job);
                    return self.fail(error);
                }
            }
        }
        self.job = Some(job);
        Ok(DecodeStep::Pending(used(before, budget)))
    }
    /// Borrow the next contiguous exact original awaiting the upper recovery consumer.
    pub fn pending_source(&self) -> Option<(SourceId, &[u8])> {
        if self.terminal.is_some() || self.handoff >= self.live.prefix {
            return None;
        }
        let slot = self.handoff as usize % (2 * self.config.window);
        if self.live_known(slot).ok()? != Some(self.handoff) {
            return None;
        }
        let vector = &self.known_data[slot * self.width..(slot + 1) * self.width];
        let length = usize::from(u16::from_be_bytes([vector[0], vector[1]]));
        Some((SourceId(self.handoff), &vector[2..2 + length]))
    }
    /// Borrow an exact committed original at or beyond the upper handoff prefix.
    /// Candidate/shadow writes are never exposed, and this does not acknowledge
    /// recovery, advance a prefix or grant native-delivery authority.
    pub fn decoded_source(&self, id: SourceId) -> Result<Option<&[u8]>, Error> {
        if self.terminal.is_some() {
            return Err(Error::Terminal);
        }
        if id.0 < self.handoff {
            return Ok(None);
        }
        let slot = id.0 as usize % (2 * self.config.window);
        if self.live_known(slot)? != Some(id.0) {
            return Ok(None);
        }
        let vector = &self.known_data[slot * self.width..(slot + 1) * self.width];
        let length = usize::from(u16::from_be_bytes([vector[0], vector[1]]));
        let end = 2usize.checked_add(length).ok_or(Error::Length)?;
        if length > self.config.max_payload || end > vector.len() {
            return Err(Error::Length);
        }
        Ok(Some(&vector[2..end]))
    }
    /// Confirm actual upper-owner acceptance, not TAP/TUN delivery or peer receipt.
    pub fn confirm_handoff(&mut self, id: SourceId, now: Tick) -> Result<(), Error> {
        self.time(now)?;
        if id.0 != self.handoff || self.pending_source().is_none() {
            return Err(Error::Identity);
        }
        let old_prefix = self.live.prefix;
        self.handoff = self.handoff.checked_add(1).ok_or(Error::Exhausted)?;
        // A pending job owns a snapshot of prefix metadata; only its separate
        // handoff watermark may change until the bank is atomically committed.
        if self.job.is_none()
            && self.live_known(self.live.prefix as usize % (2 * self.config.window))?
                == Some(self.live.prefix)
        {
            self.live.prefix = self.live.prefix.checked_add(1).ok_or(Error::Exhausted)?;
        }
        if self.live.prefix == self.live.observed {
            self.debt = None;
        }
        if self.handoff == self.live.prefix
            && self.live_known(self.live.prefix as usize % (2 * self.config.window))?
                != Some(self.live.prefix)
        {
            self.delivery = None;
        }
        let published_at = if self.sliding.is_some() && self.live.prefix > old_prefix {
            Some(self.expires(now, self.config.handoff_ticks)?)
        } else {
            None
        };
        self.refresh_sliding(None, published_at);
        Ok(())
    }
    /// Earliest retained original ordered handoff deadline.
    pub const fn handoff_deadline(&self) -> Option<Tick> {
        self.delivery
    }
    /// Earliest original job, unresolved debt or upper handoff deadline.
    pub fn deadline(&self) -> Option<Tick> {
        self.debt
            .into_iter()
            .chain(self.delivery)
            .chain(self.job.as_ref().map(|job| job.deadline))
            .min()
    }
    // Every retained ID below the contiguous prefix is known. Subtract that
    // history from the committed count instead of scanning future columns.
    // The actual eviction watermark can lag prefix advancement during handoff.
    pub(crate) fn feedback_state(&self) -> Result<(u32, u32, u32), Error> {
        let live = self.live;
        let history = live
            .prefix
            .checked_sub(live.evicted_before)
            .ok_or(Error::Identity)?;
        let history = usize::try_from(history).map_err(|_| Error::Identity)?;
        let future = live
            .known_count
            .checked_sub(history)
            .ok_or(Error::Identity)?;
        let future = u32::try_from(future).map_err(|_| Error::Identity)?;
        let extent = live
            .observed
            .checked_sub(live.prefix)
            .ok_or(Error::Identity)?;
        let unknown = extent.checked_sub(future).ok_or(Error::Identity)?;
        let rank = u32::try_from(live.rank).map_err(|_| Error::Identity)?;
        Ok((live.prefix, live.observed, unknown.saturating_sub(rank)))
    }
    /// Read original lifetimes without examining payloads or advancing time.
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
                        Kind::DecoderDebt,
                        at,
                        Some(Identity::Sources {
                            first: self.live.prefix,
                            end: self.live.observed,
                        }),
                    )
                }),
                self.delivery.map(|at| {
                    Deadline::new(
                        Kind::DecoderHandoff,
                        at,
                        Some(Identity::Sources {
                            first: self.handoff,
                            end: self.live.prefix,
                        }),
                    )
                }),
                self.job.as_ref().map(|job| {
                    Deadline::new(
                        Kind::DecoderJob,
                        job.deadline,
                        Some(job.input.expiry_identity()),
                    )
                }),
                None,
                None,
                None,
            ],
            decoder_job: self.job.as_ref().map(|job| expiry::DecoderJob {
                identity: job.input.expiry_identity(),
                received: job.received,
                admitted: job.admitted,
                deadline: job.deadline,
                phase: job.phase.expiry_cursor(),
            }),
        }
    }
    /// Constant-size ownership snapshot without allocating or scanning payloads.
    pub fn status(&self) -> DecoderStatus {
        DecoderStatus {
            observed_end: self.live.observed,
            decoded_prefix: self.live.prefix,
            handoff_prefix: self.handoff,
            known_sources: self.live.known_count,
            rank: self.live.rank,
            pending_job: self.job.is_some(),
            repair_floor: self.history_floor,
            terminal: self.terminal,
        }
    }
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod sparse_work_tests;

#[cfg(test)]
mod systematic_work_tests;

#[cfg(test)]
mod decoded_source_tests;

#[cfg(test)]
mod feedback_tests;

#[cfg(test)]
mod equation_tests;

#[cfg(test)]
mod copy_batch_tests;

#[cfg(test)]
mod field_batch_tests;
