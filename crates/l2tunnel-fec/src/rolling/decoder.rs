use super::*;
use crate::field;

mod transaction;
use transaction::{Cell, Pool, Ticket};

#[derive(Clone, Copy, Default)]
struct Header {
    prefix: u32,
    observed: u32,
    rank: usize,
    known_count: usize,
    evicted_before: u32,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Descriptor {
    id: RepairId,
    support: Support,
}
#[derive(Clone, Copy)]
enum Input {
    Source(u32),
    Repair(Descriptor),
}
impl Input {
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
    fn coefficient(self, id: u32) -> u8 {
        match self {
            Self::Source(_) => 1,
            Self::Repair(d) => field::compact_coefficient(d.support.seed, id),
        }
    }
}
#[derive(Clone, Copy)]
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
        index: usize,
        count: usize,
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
struct Job {
    ticket: Ticket,
    resume: Option<Phase>,
    input: Input,
    phase: Phase,
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
    rows: Vec<Cell<()>>,
    decisions: Pool,
    active: Option<Ticket>,
    // Immutable while referenced by committed identities. Candidate recovery may
    // stage only into vacant slots; publication is the identity-bank commit.
    known_data: Vec<u8>,
    input: Vec<u8>,
    candidate: Vec<u8>,
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
}
enum Action {
    Continue,
    Paused,
    Accepted,
    Capacity,
}
impl Decoder {
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
                mul(c.max_rows, std::mem::size_of::<Cell<()>>())?,
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
            rows: slots(config.max_rows, Cell::new())?,
            decisions: Pool::new(add(mul(3, config.window)?, mul(2, config.max_rows)?)?)?,
            active: None,
            known_data: bytes(mul(2 * config.window, width)?)?,
            input: bytes(width)?,
            candidate: bytes(config.window + width)?,
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
    fn stage(&mut self, input: Input, now: Tick) -> Result<Begin, Error> {
        let job_end = self.expires(now, self.config.job_ticks)?;
        let debt = match self.debt {
            Some(value) => Some(value),
            None if input.end() > self.live.prefix => {
                Some(self.expires(now, self.config.debt_ticks)?)
            }
            None => None,
        };
        let ticket = self.decisions.begin()?;
        self.active = Some(ticket);
        self.shadow = self.live;
        self.shadow.observed = self.shadow.observed.max(input.end());
        self.job = Some(Job {
            ticket,
            resume: None,
            input,
            phase: Phase::Clear(0),
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
        if self.job.is_some() {
            return Err(Error::Busy);
        }
        let floor = self.live.prefix.saturating_sub(self.config.window as u32);
        if id.0 < floor {
            return Ok(Begin::Stale);
        }
        if u64::from(id.0) >= u64::from(self.live.prefix) + self.config.window as u64 {
            return Err(Error::Identity);
        }
        let slot = id.0 as usize % (2 * self.config.window);
        if self.known[slot].get(&self.decisions, None)? == Some(id.0) {
            let data = &self.known_data[slot * self.width..(slot + 1) * self.width];
            let len = usize::from(u16::from_be_bytes([data[0], data[1]]));
            return if len == original.len() && data[2..2 + len] == *original {
                Ok(Begin::Duplicate)
            } else {
                self.fail(Error::Conflict)
            };
        }
        if id.0 < self.live.prefix {
            return self.fail(Error::Identity);
        }
        self.expires(now, self.config.job_ticks)?;
        self.expires(now, self.config.debt_ticks)?;
        self.input.fill(0);
        self.input[..2].copy_from_slice(&(original.len() as u16).to_be_bytes());
        self.input[2..2 + original.len()].copy_from_slice(original);
        self.stage(Input::Source(id.0), now)
    }
    /// Stage a complete authenticated equation; useful end<=prefix+W is checked first.
    pub fn begin_repair(&mut self, repair: Repair<'_>, now: Tick) -> Result<Begin, Error> {
        if repair.scope != self.scope {
            return Err(Error::Scope);
        }
        if repair.bytes.len() != self.width {
            return Err(Error::Length);
        }
        if repair.id.0 == u64::MAX
            || self
                .config
                .support(repair.support.end, repair.id, repair.support.tail)?
                != repair.support
        {
            return Err(Error::Identity);
        }
        self.time(now)?;
        if self.job.is_some() {
            return Err(Error::Busy);
        }
        if repair.id.0 < self.history_floor {
            return Ok(Begin::Stale);
        }
        let descriptor = Descriptor {
            id: repair.id,
            support: repair.support,
        };
        let slot = (repair.id.0 % self.config.repair_history as u64) as usize;
        if let Some(old) = self.history_meta[slot]
            && old.id == repair.id
        {
            return if old == descriptor
                && self.history[slot * self.width..(slot + 1) * self.width] == *repair.bytes
            {
                Ok(Begin::Duplicate)
            } else {
                self.fail(Error::Conflict)
            };
        }
        if repair.support.end <= self.live.prefix {
            return Ok(Begin::Stale);
        }
        if u64::from(repair.support.end) > u64::from(self.live.prefix) + self.config.window as u64 {
            return Err(Error::Identity);
        }
        self.expires(now, self.config.job_ticks)?;
        self.expires(now, self.config.debt_ticks)?;
        self.input.copy_from_slice(repair.bytes);
        self.stage(Input::Repair(descriptor), now)
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
        )
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
    fn set_row_byte(&mut self, row: usize, index: usize, value: u8) -> Result<(), Error> {
        let bank = self.row_bank(row, self.active)?;
        let at = self.row_start(row) + index;
        self.data[bank][at] = value;
        Ok(())
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
            job.resume = Some(next);
            job.phase = Phase::CopyRow {
                row,
                from,
                to,
                index: 0,
            };
        } else {
            job.phase = next;
        }
        Ok(())
    }
    fn payload_byte(&self, row: Option<usize>, index: usize) -> Result<u8, Error> {
        match row {
            Some(row) => self.row_byte(row, self.config.window + index),
            None => Ok(self.candidate[self.config.window + index]),
        }
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
                if index == w + width {
                    job.phase = job.resume.take().ok_or(Error::Identity)?;
                } else {
                    if !spend(&mut budget.copies) {
                        return Ok(Action::Paused);
                    }
                    let at = self.row_start(row) + index;
                    self.data[to][at] = self.data[from][at];
                    job.phase = Phase::CopyRow {
                        row,
                        from,
                        to,
                        index: index + 1,
                    };
                }
            }
            Phase::Clear(i) => {
                if i == self.candidate.len() {
                    job.phase = Phase::Load(0);
                } else {
                    if !spend(&mut budget.copies) {
                        return Ok(Action::Paused);
                    }
                    self.candidate[i] = 0;
                    job.phase = Phase::Clear(i + 1);
                }
            }
            Phase::Load(i) => {
                if i == width {
                    job.phase = Phase::Support(job.input.start());
                } else {
                    if !spend(&mut budget.copies) {
                        return Ok(Action::Paused);
                    }
                    self.candidate[w + i] = self.input[i];
                    job.phase = Phase::Load(i + 1);
                }
            }
            Phase::Support(id) => {
                if id == job.input.end() {
                    job.phase = Phase::Reduce(self.live.prefix);
                } else {
                    let factor = job.input.coefficient(id);
                    if factor == 0 {
                        job.phase = Phase::Support(id + 1);
                    } else if self.known(id)?.is_some() {
                        job.phase = Phase::Known {
                            source: id,
                            factor,
                            column: 0,
                        };
                    } else {
                        if id < self.live.prefix {
                            return Err(Error::Identity);
                        }
                        self.candidate[id as usize % w] = factor;
                        job.phase = Phase::Support(id + 1);
                    }
                }
            }
            Phase::Known {
                source,
                factor,
                column,
            } => {
                if column == width {
                    job.phase = Phase::Support(source + 1);
                } else {
                    if !spend(&mut budget.field) {
                        return Ok(Action::Paused);
                    }
                    let start = self.known(source)?.ok_or(Error::Identity)?;
                    self.candidate[w + column] ^=
                        field::multiply(factor, self.known_data[start + column]);
                    job.phase = Phase::Known {
                        source,
                        factor,
                        column: column + 1,
                    };
                }
            }
            Phase::Reduce(id) => {
                if u64::from(id) >= u64::from(self.live.prefix) + w as u64 || id == u32::MAX {
                    job.phase = Phase::Pivot(self.live.prefix);
                } else {
                    let factor = self.candidate[id as usize % w];
                    if factor != 0
                        && let Some(row) = self.map_at(id as usize % w)?
                    {
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
                    self.candidate[index] ^= field::multiply(factor, self.row_byte(row, index)?);
                    job.phase = Phase::Eliminate {
                        row,
                        factor,
                        index: index + 1,
                        next,
                    };
                }
            }
            Phase::Pivot(id) => {
                if u64::from(id) >= u64::from(self.live.prefix) + w as u64 || id == u32::MAX {
                    job.phase = Phase::Zero(0);
                } else {
                    let value = self.candidate[id as usize % w];
                    if value == 0 {
                        job.phase = Phase::Pivot(id + 1);
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
                    if self.candidate[w + i] != 0 {
                        return Err(Error::Inconsistent);
                    }
                    job.phase = Phase::Zero(i + 1);
                }
            }
            Phase::Normalize {
                pivot,
                factor,
                index,
            } => {
                if index == w + width {
                    job.phase = Phase::Others { pivot, row: 0 };
                } else {
                    if !spend(&mut budget.field) {
                        return Ok(Action::Paused);
                    }
                    self.candidate[index] = field::multiply(factor, self.candidate[index]);
                    job.phase = Phase::Normalize {
                        pivot,
                        factor,
                        index: index + 1,
                    };
                }
            }
            Phase::Others { pivot, row } => {
                if row == self.config.max_rows {
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
                if index == w + width {
                    job.phase = Phase::Others {
                        pivot,
                        row: row + 1,
                    };
                } else {
                    if !spend(&mut budget.field) {
                        return Ok(Action::Paused);
                    }
                    let value =
                        self.row_byte(row, index)? ^ field::multiply(factor, self.candidate[index]);
                    self.set_row_byte(row, index, value)?;
                    job.phase = Phase::OtherEliminate {
                        pivot,
                        row,
                        factor,
                        index: index + 1,
                    };
                }
            }
            Phase::CandidateCount {
                pivot,
                index,
                count,
            } => {
                if index == w {
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
                    job.phase = Phase::CandidateCount {
                        pivot,
                        index: index + 1,
                        count: count + usize::from(self.candidate[index] != 0),
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
                    self.set_pivot(row, Some(pivot))?;
                    self.set_map(pivot as usize % w, Some(row))?;
                    self.shadow.rank += 1;
                    job.phase = Phase::Scan {
                        row: 0,
                        index: 0,
                        count: 0,
                    };
                } else {
                    if !spend(&mut budget.copies) {
                        return Ok(Action::Paused);
                    }
                    self.set_row_byte(row, index, self.candidate[index])?;
                    job.phase = Phase::Insert {
                        pivot,
                        row,
                        index: index + 1,
                    };
                }
            }
            Phase::Scan { row, index, count } => {
                if row == self.config.max_rows {
                    job.phase = Phase::Advance;
                } else if self.pivot_at(row)?.is_none() {
                    job.phase = Phase::Scan {
                        row: row + 1,
                        index: 0,
                        count: 0,
                    };
                } else if index == w {
                    if count == 1 {
                        job.phase = Phase::Validate {
                            row: Some(row),
                            id: self.pivot_at(row)?.ok_or(Error::Identity)?,
                            index: 0,
                            length: 0,
                        };
                    } else {
                        job.phase = Phase::Scan {
                            row: row + 1,
                            index: 0,
                            count: 0,
                        };
                    }
                } else {
                    let byte = self.row_byte(row, index)?;
                    job.phase = Phase::Scan {
                        row,
                        index: index + 1,
                        count: count + usize::from(byte != 0),
                    };
                }
            }
            Phase::Validate {
                row,
                id,
                index,
                length,
            } => {
                if index == 0 {
                    let length = usize::from(u16::from_be_bytes([
                        self.payload_byte(row, 0)?,
                        self.payload_byte(row, 1)?,
                    ]));
                    if length == 0 || length > self.config.max_payload {
                        return Err(Error::Length);
                    }
                    job.phase = Phase::Validate {
                        row,
                        id,
                        index: 2,
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
                    if index >= length + 2 && self.payload_byte(row, index)? != 0 {
                        return Err(Error::Length);
                    }
                    job.phase = Phase::Validate {
                        row,
                        id,
                        index: index + 1,
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
                        job.phase = Phase::Scan {
                            row: row + 1,
                            index: 0,
                            count: 0,
                        };
                    } else {
                        job.phase = Phase::Scan {
                            row: 0,
                            index: 0,
                            count: 0,
                        };
                    }
                } else {
                    if !spend(&mut budget.copies) {
                        return Ok(Action::Paused);
                    }
                    let value = self.payload_byte(row, index)?;
                    // Both identity banks proved this slot unreferenced. Partial
                    // payload writes are invisible until the identity bank commits.
                    self.known_data[slot * width + index] = value;
                    job.phase = Phase::Store {
                        row,
                        id,
                        index: index + 1,
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
                    if i == width {
                        job.phase = Phase::Commit;
                    } else {
                        if !spend(&mut budget.copies) {
                            return Ok(Action::Paused);
                        }
                        let slot = (d.id.0 % self.config.repair_history as u64) as usize;
                        self.history[slot * width + i] = self.input[i];
                        job.phase = Phase::History(i + 1);
                    }
                } else {
                    job.phase = Phase::Commit;
                }
            }
            Phase::Commit => {
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
                return Ok(Action::Accepted);
            }
        }
        Ok(Action::Continue)
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
    /// Confirm actual upper-owner acceptance, not TAP/TUN delivery or peer receipt.
    pub fn confirm_handoff(&mut self, id: SourceId, now: Tick) -> Result<(), Error> {
        self.time(now)?;
        if id.0 != self.handoff || self.pending_source().is_none() {
            return Err(Error::Identity);
        }
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
        Ok(())
    }
    /// Earliest original job, unresolved debt or upper handoff deadline.
    pub fn deadline(&self) -> Option<Tick> {
        self.debt
            .into_iter()
            .chain(self.delivery)
            .chain(self.job.as_ref().map(|job| job.deadline))
            .min()
    }
    // Scheduler scans only committed columns while it freezes new decoder work.
    // No payload or sender ledger is exposed, and each lookup is constant work.
    pub(super) fn committed_known(&self, id: SourceId) -> bool {
        self.live_known(id.0 as usize % (2 * self.config.window))
            .ok()
            .flatten()
            == Some(id.0)
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
