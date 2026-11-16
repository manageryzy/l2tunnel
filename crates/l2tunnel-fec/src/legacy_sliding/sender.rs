use super::*;

/// Local custody identity, including the exact physical source attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OutputId {
    /// One first-send or retry attempt; retries retain the source wire identity.
    Source {
        /// Original source identity.
        source: SourceId,
        /// One-based physical attempt.
        attempt: u32,
    },
    /// One complete real-byte repair.
    Repair(RepairId),
}
/// Immutable packet awaiting complete caller-confirmed carrier custody.
#[derive(Clone, Copy, Debug)]
pub enum Output<'a> {
    /// A first systematic source or exact original retry.
    Source {
        /// Authenticated domain.
        scope: Scope,
        /// Nonwrapping original identity.
        id: SourceId,
        /// Local attempt identity; this does not alter the original wire bytes.
        attempt: u32,
        /// Exact retained payload including meaningful zero tails.
        original: &'a [u8],
    },
    /// A frozen sparse equation and actual coded payload.
    Repair(Repair<'a>),
}
impl Output<'_> {
    /// Identity required for this exact physical completion.
    pub fn id(self) -> OutputId {
        match self {
            Self::Source { id, attempt, .. } => OutputId::Source {
                source: id,
                attempt,
            },
            Self::Repair(repair) => OutputId::Repair(repair.equation.id),
        }
    }
    /// Actual protocol bytes before caller-supplied carrier/authentication overhead.
    pub fn encoded_len(self) -> usize {
        wire::HEADER_BYTES
            + match self {
                Self::Source { original, .. } => original.len(),
                Self::Repair(repair) => 5 * repair.terms.len() + repair.equation.bytes.len(),
            }
    }
    /// Charge every actual source, retry, coefficient and repair-payload byte.
    pub fn charge(self, overhead: usize) -> Result<usize, Error> {
        self.encoded_len()
            .checked_add(overhead)
            .ok_or(Error::Exhausted)
    }
}
/// Replay disposition of an authenticated complete feedback snapshot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FeedbackDisposition {
    /// Receipt retirement and any causally eligible repair batch were committed.
    Applied,
    /// Latest identity and entire body match; no new repair or timer change.
    Duplicate,
    /// An older snapshot supplied monotonic selective/cumulative receipt evidence.
    /// Its body does not replace the latest identity fingerprint.
    Reordered,
}
/// Finite sender ownership and scheduling facts, separate from native delivery.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SenderStatus {
    /// Actual source storage and contiguous confirmed prefix.
    pub encoder: rolling::EncoderStatus,
    /// Exclusive prefix with a complete first physical transmission.
    pub sent_sources: u32,
    /// Number of original sources lacking an authenticated receipt.
    pub pending_sources: usize,
    /// Exact original payload bytes lacking a receipt.
    pub pending_bytes: usize,
    /// Scheduled repair rows, including one encoding or waiting for custody.
    pub queued_repairs: usize,
    /// Generated periodic repairs; feedback repairs do not advance this counter.
    pub periodic_repairs: u64,
    /// Interleaved numerator credit from completed first transmissions only.
    pub repair_credit: u32,
    /// Sources admitted in the current FEC timer generation.
    pub fec_count: u32,
    /// An immutable complete packet is ready.
    pub output_ready: bool,
    /// Latest committed feedback identity.
    pub feedback: Option<FeedbackId>,
    /// Original terminal error, if any.
    pub terminal: Option<Error>,
}
#[derive(Clone, Copy)]
struct Flight {
    id: SourceId,
    size: usize,
    expires: Tick,
    sent_at: Option<Tick>,
    rtt: u64,
    retry_at: Option<Tick>,
    retry_order: u64,
    repair_until: Tick,
    queued: usize,
    attempts: u32,
    early: bool,
    acknowledged: bool,
}
#[derive(Clone, Copy)]
struct Job {
    terms: usize,
    queued: Tick,
    due: Tick,
    expires: Tick,
    order: u64,
    feedback: bool,
}
#[derive(Clone, Copy)]
enum Pending {
    Source { id: SourceId, attempt: u32 },
    Repair { slot: usize, id: RepairId },
}
#[derive(Clone, Copy)]
struct Receipt {
    id: FeedbackId,
    prefix: Option<u32>,
    count: usize,
}

/// Bounded legacy sliding/hybrid scheduler over actual retained source bytes.
///
/// Metadata admission is atomic and bounded by 255 flights, 1024 repair slots
/// and 65,025 coefficient entries per generated batch. Coefficient generation
/// is caller-injected, not a new PRNG or a substitution of compact coefficients.
/// GF/copy work inside an active equation uses the supplied WorkBudget. There is
/// no clock, socket, packet packer, loss oracle or unbounded application queue.
pub struct Sender {
    config: Config,
    scope: Scope,
    encoder: rolling::Encoder,
    flights: Vec<Option<Flight>>,
    jobs: Vec<Option<Job>>,
    terms: Vec<Term>,
    coefficients: Vec<u8>,
    candidates: Vec<SourceId>,
    receipt_ids: Vec<SourceId>,
    pending: Option<Pending>,
    prepared: Option<Tick>,
    output_end: Option<Tick>,
    debt_end: Option<Tick>,
    queue_end: Option<Tick>,
    fec_due: Option<Tick>,
    fec_count: u32,
    credit: u32,
    periodic: u64,
    sent: u32,
    pending_sources: usize,
    pending_bytes: usize,
    queued: usize,
    highest_feedback: u32,
    receipt: Option<Receipt>,
    order: u64,
    last: Tick,
    terminal: Option<Error>,
}

fn allocated<T: Clone>(count: usize, initial: T) -> Result<Vec<T>, Error> {
    let mut value = Vec::new();
    value
        .try_reserve_exact(count)
        .map_err(|_| Error::Allocation)?;
    value.resize(count, initial);
    Ok(value)
}
fn add_tick(at: Tick, ticks: u64) -> Result<Tick, Error> {
    at.0.checked_add(ticks).map(Tick).ok_or(Error::Exhausted)
}

impl Sender {
    /// Exact requested heap layout for pre-admission inventory.
    pub(crate) fn requested_storage(
        config: Config,
    ) -> Result<rolling::storage::Usage, rolling::storage::Error> {
        config.validate()?;
        let count = config
            .repair_queue
            .checked_mul(usize::from(config.long_window))
            .ok_or(Error::Exhausted)?;
        let mut usage = rolling::Encoder::explicit_requested_storage(config.recovery)?;
        usage = storage::join(
            usage,
            storage::requested::<Option<Flight>>(config.recovery.window)?,
        )?;
        usage = storage::join(
            usage,
            storage::requested::<Option<Job>>(config.repair_queue)?,
        )?;
        usage = storage::join(usage, storage::requested::<Term>(count)?)?;
        usage = storage::join(
            usage,
            storage::requested::<u8>(usize::from(config.long_window))?,
        )?;
        usage = storage::join(
            usage,
            storage::requested::<SourceId>(usize::from(config.long_window))?,
        )?;
        storage::join(
            usage,
            storage::requested::<SourceId>(usize::from(config.feedback_batch))?,
        )
    }
    /// Observe all actual nested capacities; inline owner and allocator metadata are excluded.
    pub fn storage_usage(&self) -> Result<rolling::storage::Usage, rolling::storage::Error> {
        let mut usage = self.encoder.storage_usage()?;
        usage = storage::join(usage, storage::vector(&self.flights)?)?;
        usage = storage::join(usage, storage::vector(&self.jobs)?)?;
        usage = storage::join(usage, storage::vector(&self.terms)?)?;
        usage = storage::join(usage, storage::vector(&self.coefficients)?)?;
        usage = storage::join(usage, storage::vector(&self.candidates)?)?;
        storage::join(usage, storage::vector(&self.receipt_ids)?)
    }
    /// Conservative fixed owner bound including its inline header.
    pub fn memory_bound(config: Config) -> Result<usize, Error> {
        let usage = Self::requested_storage(config).map_err(|error| match error {
            rolling::storage::Error::Recovery(value) => value,
            _ => Error::Capacity,
        })?;
        usage
            .capacity_bytes
            .checked_add(std::mem::size_of::<Self>())
            .ok_or(Error::Exhausted)
    }
    /// Admit exact requested and observed capacities before accepting any payload.
    pub fn new_reserved(
        config: Config,
        scope: Scope,
        now: Tick,
        limits: rolling::storage::Limits,
    ) -> Result<Self, rolling::storage::Error> {
        let plan = storage::Plan::for_sender(config)?;
        plan.admit(limits, now)?;
        let value = Self::new(config, scope, now)?;
        plan.verify(value.storage_usage()?, limits)?;
        Ok(value)
    }
    /// Allocate the complete fixed source/flight/repair storage up front.
    pub fn new(config: Config, scope: Scope, now: Tick) -> Result<Self, Error> {
        config.validate()?;
        if Self::memory_bound(config)? > config.memory_bytes {
            return Err(Error::Capacity);
        }
        let width = usize::from(config.long_window);
        let count = config
            .repair_queue
            .checked_mul(width)
            .ok_or(Error::Exhausted)?;
        Ok(Self {
            encoder: rolling::Encoder::new_explicit(config.recovery, scope, now)?,
            flights: allocated(config.recovery.window, None)?,
            jobs: allocated(config.repair_queue, None)?,
            terms: allocated(
                count,
                Term {
                    source: SourceId(0),
                    coefficient: 0,
                },
            )?,
            coefficients: allocated(width, 0)?,
            candidates: allocated(width, SourceId(0))?,
            receipt_ids: allocated(usize::from(config.feedback_batch), SourceId(0))?,
            config,
            scope,
            pending: None,
            prepared: None,
            output_end: None,
            debt_end: None,
            queue_end: None,
            fec_due: None,
            fec_count: 0,
            credit: 0,
            periodic: 0,
            sent: 0,
            pending_sources: 0,
            pending_bytes: 0,
            queued: 0,
            highest_feedback: 0,
            receipt: None,
            order: 0,
            last: now,
            terminal: None,
        })
    }
    fn fail<T>(&mut self, error: Error) -> Result<T, Error> {
        self.terminal = Some(error);
        Err(error)
    }
    fn time(&mut self, now: Tick) -> Result<(), Error> {
        if self.terminal.is_some() {
            return Err(Error::Terminal);
        }
        if now < self.last {
            return self.fail(Error::TimeRegression);
        }
        if [self.output_end, self.debt_end, self.queue_end]
            .into_iter()
            .flatten()
            .any(|end| now >= end)
        {
            return self.fail(Error::Expired);
        }
        if let Err(error) = self.encoder.step(now, WorkBudget::default()) {
            return self.fail(error);
        }
        self.last = now;
        Ok(())
    }
    fn next_order(&mut self) -> Result<u64, Error> {
        self.order = self.order.checked_add(1).ok_or(Error::Exhausted)?;
        Ok(self.order)
    }
    fn flight(&self, id: SourceId) -> Option<&Flight> {
        self.flights[id.0 as usize % self.flights.len()]
            .as_ref()
            .filter(|flight| flight.id == id)
    }
    fn flight_mut(&mut self, id: SourceId) -> Option<&mut Flight> {
        let at = id.0 as usize % self.flights.len();
        self.flights[at].as_mut().filter(|flight| flight.id == id)
    }
    fn row(&self, slot: usize, count: usize) -> &[Term] {
        let start = slot * usize::from(self.config.long_window);
        &self.terms[start..start + count]
    }
    fn periodic_count(&self, count: u32, credit: u32) -> usize {
        if count == 0 {
            return 0;
        }
        if self.config.interleave_repairs {
            (credit / u32::from(self.config.repair_every)).max(1) as usize
        } else {
            (count * u32::from(self.config.repairs_per_group))
                .div_ceil(u32::from(self.config.repair_every)) as usize
        }
    }
    fn reserved_periodic_count(&self) -> usize {
        let unearned = u32::from(matches!(
            self.pending,
            Some(Pending::Source { attempt: 1, .. })
        )) * u32::from(self.config.repairs_per_group);
        self.periodic_count(self.fec_count, self.credit + unearned)
    }
    fn due_service(&self, now: Tick) -> bool {
        self.fec_due.is_some_and(|due| now >= due)
            || self.jobs.iter().flatten().any(|job| now >= job.due)
            || self
                .flights
                .iter()
                .flatten()
                .any(|flight| !flight.acknowledged && flight.retry_at.is_some_and(|due| now >= due))
    }
    /// Admit one exact original. A ready timer, repair or retry is serviced first.
    /// Original output/debt deadlines include time already spent upstream.
    pub fn admit_source(
        &mut self,
        original: &[u8],
        created_at: Tick,
        now: Tick,
    ) -> Result<SourceId, Error> {
        if original.is_empty() || original.len() > self.config.recovery.max_payload {
            return Err(Error::Length);
        }
        if created_at > now {
            return Err(Error::TimeRegression);
        }
        self.time(now)?;
        if self.pending.is_some() || self.due_service(now) {
            return Err(Error::Busy);
        }
        let output_end = add_tick(created_at, self.config.recovery.job_ticks)?;
        let debt = add_tick(created_at, self.config.recovery.debt_ticks)?;
        if now >= output_end || now >= debt {
            return Err(Error::Expired);
        }
        let reserve = self.periodic_count(
            self.fec_count + 1,
            self.credit + u32::from(self.config.repairs_per_group),
        );
        if self.jobs.len() - self.queued < reserve {
            return Err(Error::Capacity);
        }
        let next = self.encoder.status().next_source;
        let retained_floor = next
            .saturating_add(1)
            .saturating_sub(self.config.recovery.window as u32);
        for (slot, job) in self.jobs.iter().enumerate() {
            if let Some(job) = job
                && self
                    .row(slot, job.terms)
                    .first()
                    .is_some_and(|term| term.source.0 < retained_floor)
            {
                return Err(Error::Capacity);
            }
        }
        let fec_due = if self.fec_count == 0 {
            Some(add_tick(now, self.config.fec_wait_ticks)?)
        } else {
            self.fec_due
        };
        let id = self.encoder.admit_source(original, now)?;
        let at = id.0 as usize % self.flights.len();
        self.flights[at] = Some(Flight {
            id,
            size: original.len(),
            expires: debt,
            sent_at: None,
            rtt: 0,
            retry_at: None,
            retry_order: 0,
            repair_until: Tick(0),
            queued: 0,
            attempts: 0,
            early: false,
            acknowledged: false,
        });
        self.pending_sources += 1;
        self.pending_bytes += original.len();
        self.fec_count += 1;
        self.fec_due = fec_due;
        self.debt_end = Some(self.debt_end.map_or(debt, |old| old.min(debt)));
        self.pending = Some(Pending::Source { id, attempt: 1 });
        self.prepared = Some(now);
        self.output_end = Some(output_end);
        Ok(id)
    }
    // Prepare every row in currently inactive slots before publishing any row.
    // Invalid coefficient input leaves the visible queue and flight counters intact.
    fn queue_batch<C: CoefficientSource + ?Sized>(
        &mut self,
        count: usize,
        feedback_count: Option<usize>,
        now: Tick,
        random: &mut C,
    ) -> Result<(), Error> {
        if count == 0 {
            return Ok(());
        }
        if count > 255 || self.jobs.len() - self.queued < count {
            return Err(Error::Capacity);
        }
        let mut chosen = [0_usize; 255];
        let mut found = 0;
        for (slot, job) in self.jobs.iter().enumerate() {
            if job.is_none() {
                chosen[found] = slot;
                found += 1;
                if found == count {
                    break;
                }
            }
        }
        let mut staged = [None; 255];
        let periodic_end = self
            .periodic
            .checked_add(count as u64)
            .ok_or(Error::Exhausted)?;
        let order_end = self
            .order
            .checked_add(count as u64)
            .ok_or(Error::Exhausted)?;
        let source_end = self.encoder.status().next_source;
        for row in 0..count {
            let slot = chosen[row];
            let serial = self.periodic + row as u64 + 1;
            let width = if let Some(candidates) = feedback_count {
                candidates
            } else {
                let long = self.config.mode == Mode::Sliding
                    || serial.is_multiple_of(u64::from(self.config.long_every));
                usize::from(if long {
                    self.config.long_window
                } else {
                    self.config.short_window
                })
                .min(source_end as usize)
            };
            if width == 0 {
                return Err(Error::Identity);
            }
            random.fill(&mut self.coefficients[..width])?;
            if self.coefficients[..width].contains(&0) {
                return Err(Error::Identity);
            }
            let start = slot * usize::from(self.config.long_window);
            let mut expires = add_tick(now, self.config.recovery.job_ticks)?;
            for offset in 0..width {
                let source = if feedback_count.is_some() {
                    self.candidates[offset]
                } else {
                    SourceId(source_end - width as u32 + offset as u32)
                };
                if self.encoder.source(source).is_none() {
                    return Err(Error::Identity);
                }
                let flight = self.flight(source).ok_or(Error::Identity)?;
                if !flight.acknowledged {
                    expires = expires.min(flight.expires);
                }
                self.terms[start + offset] = Term {
                    source,
                    coefficient: self.coefficients[offset],
                };
            }
            let spacing = if feedback_count.is_some() {
                0
            } else {
                self.config
                    .repair_spacing_ticks
                    .checked_mul(row as u64 + 1)
                    .ok_or(Error::Exhausted)?
            };
            staged[row] = Some(Job {
                terms: width,
                queued: now,
                due: add_tick(now, spacing)?,
                expires,
                order: self.order + row as u64 + 1,
                feedback: feedback_count.is_some(),
            });
        }
        for row in 0..count {
            let slot = chosen[row];
            let job = staged[row].ok_or(Error::Identity)?;
            for offset in 0..job.terms {
                let source =
                    self.terms[slot * usize::from(self.config.long_window) + offset].source;
                if let Some(flight) = self.flight_mut(source)
                    && !flight.acknowledged
                {
                    flight.queued += 1;
                }
            }
            self.jobs[slot] = Some(job);
            self.queue_end = Some(
                self.queue_end
                    .map_or(job.expires, |old| old.min(job.expires)),
            );
        }
        self.queued += count;
        self.order = order_end;
        if feedback_count.is_none() {
            self.periodic = periodic_end;
        }
        Ok(())
    }
    fn flush_code<C: CoefficientSource + ?Sized>(
        &mut self,
        now: Tick,
        random: &mut C,
    ) -> Result<(), Error> {
        if self.fec_count == 0 {
            return Ok(());
        }
        let count = self.periodic_count(self.fec_count, self.credit);
        self.queue_batch(count, None, now, random)?;
        if self.config.interleave_repairs {
            self.credit = self
                .credit
                .saturating_sub(count as u32 * u32::from(self.config.repair_every));
        }
        self.fec_count = 0;
        self.fec_due = None;
        Ok(())
    }
    /// Service one selected timer/output, then bounded actual-byte equation work.
    /// Scheduling scans at most 255 flights and 1024 queued rows; a flush creates
    /// at most 65,025 coefficient entries atomically. WorkUsed reports encoder work.
    pub fn step<C: CoefficientSource + ?Sized>(
        &mut self,
        now: Tick,
        budget: WorkBudget,
        random: &mut C,
    ) -> Result<WorkUsed, Error> {
        if [budget.field, budget.copies, budget.metadata]
            .into_iter()
            .any(|n| n > rolling::MAX_STEP_WORK)
        {
            return Err(Error::WorkLimit);
        }
        self.time(now)?;
        if self.pending.is_none() && budget.metadata != 0 {
            if self.fec_due.is_some_and(|due| now >= due)
                && let Err(error) = self.flush_code(now, random)
            {
                return self.fail(error);
            }
            let repair = self
                .jobs
                .iter()
                .enumerate()
                .filter_map(|(slot, job)| job.map(|job| (job.due, job.order, slot)))
                .filter(|(due, _, _)| *due <= now)
                .min();
            let retry = self
                .flights
                .iter()
                .flatten()
                .filter(|flight| !flight.acknowledged)
                .filter_map(|flight| {
                    flight
                        .retry_at
                        .map(|due| (due, flight.retry_order, flight.id))
                })
                .filter(|(due, _, _)| *due <= now)
                .min();
            if let Some((_, _, slot)) =
                repair.filter(|r| retry.is_none_or(|t| (r.0, r.1) <= (t.0, t.1)))
            {
                let job = self.jobs[slot].ok_or(Error::Identity)?;
                let start = slot * usize::from(self.config.long_window);
                let id = self
                    .encoder
                    .begin_explicit(
                        &self.terms[start..start + job.terms],
                        job.feedback,
                        job.queued,
                        now,
                        job.expires,
                    )
                    .or_else(|error| self.fail(error))?;
                self.pending = Some(Pending::Repair { slot, id });
                self.prepared = Some(now);
                self.output_end = Some(job.expires);
            } else if let Some((_, _, id)) = retry {
                let flight = *self.flight(id).ok_or(Error::Identity)?;
                if flight.attempts >= self.config.max_attempts {
                    return self.fail(Error::Exhausted);
                }
                self.pending = Some(Pending::Source {
                    id,
                    attempt: flight.attempts + 1,
                });
                self.prepared = Some(now);
                self.output_end =
                    Some(add_tick(now, self.config.recovery.job_ticks)?.min(flight.expires));
            }
        }
        self.encoder
            .step(now, budget)
            .or_else(|error| self.fail(error))
    }
    /// Borrow one complete immutable record; polling cannot change timers or credit.
    pub fn pending_output(&self) -> Option<Output<'_>> {
        if self.terminal.is_some() {
            return None;
        }
        match self.pending? {
            Pending::Source { id, attempt } => Some(Output::Source {
                scope: self.scope,
                id,
                attempt,
                original: self.encoder.source(id)?,
            }),
            Pending::Repair { slot, .. } => {
                let job = self.jobs[slot]?;
                Some(Output::Repair(Repair {
                    equation: self.encoder.pending_repair()?,
                    terms: self.row(slot, job.terms),
                    feedback_triggered: job.feedback,
                }))
            }
        }
    }
    /// Exact current record length for shared MUX/carrier output reservation.
    pub fn pending_wire_len(&self) -> Option<usize> {
        self.pending_output().map(Output::encoded_len)
    }
    /// Encode without consuming output. Capacity errors preserve caller bytes.
    pub fn encode_pending(&self, output: &mut [u8]) -> Result<usize, Error> {
        match self.pending_output().ok_or(Error::Busy)? {
            Output::Source {
                scope,
                id,
                original,
                ..
            } => wire::encode_source(self.config, scope, id, original, output),
            Output::Repair(repair) => wire::encode_repair(self.config, repair, output),
        }
    }
    fn rto(&self, rtt: u64) -> Result<u64, Error> {
        let value = (u128::from(rtt) * u128::from(self.config.rto_factor_numerator))
            .div_ceil(u128::from(self.config.rto_factor_denominator));
        let value = u64::try_from(value).map_err(|_| Error::Exhausted)?;
        Ok(value.max(self.config.rto_min_ticks))
    }
    /// Confirm exact complete physical custody, retaining the measured path RTT
    /// and serialization finish separately from the receipt-observation tick.
    /// First-source credit is earned once; retries retain constant per-path RTO.
    pub fn confirm_output<C: CoefficientSource + ?Sized>(
        &mut self,
        id: OutputId,
        finished: Tick,
        now: Tick,
        rtt_ticks: u64,
        random: &mut C,
    ) -> Result<(), Error> {
        if self.pending_output().ok_or(Error::Busy)?.id() != id {
            return Err(Error::Identity);
        }
        if self.prepared.is_none_or(|prepared| finished < prepared) || finished > now {
            return self.fail(Error::TimeRegression);
        }
        self.time(now)?;
        match self.pending.ok_or(Error::Busy)? {
            Pending::Source { id, attempt } => {
                let flight = *self.flight(id).ok_or(Error::Identity)?;
                if !flight.acknowledged {
                    let interval = self.rto(rtt_ticks).or_else(|error| self.fail(error))?;
                    let retry = add_tick(finished, interval).or_else(|error| self.fail(error))?;
                    let order = self.next_order().or_else(|error| self.fail(error))?;
                    let value = self.flight_mut(id).ok_or(Error::Identity)?;
                    value.sent_at = Some(finished);
                    value.rtt = rtt_ticks;
                    value.attempts = attempt;
                    value.retry_at = Some(retry);
                    value.retry_order = order;
                }
                self.pending = None;
                self.prepared = None;
                self.output_end = None;
                if attempt == 1 {
                    self.sent = id.0.checked_add(1).ok_or(Error::Exhausted)?;
                    if self.config.interleave_repairs {
                        self.credit += u32::from(self.config.repairs_per_group);
                    }
                    let ready = if self.config.interleave_repairs {
                        self.credit >= u32::from(self.config.repair_every)
                    } else {
                        self.fec_count >= u32::from(self.config.repair_every)
                    };
                    if (ready || self.fec_due.is_some_and(|due| now >= due))
                        && let Err(error) = self.flush_code(now, random)
                    {
                        return self.fail(error);
                    }
                }
            }
            Pending::Repair { slot, id } => {
                let job = self.jobs[slot].ok_or(Error::Identity)?;
                let arrival = add_tick(finished, rtt_ticks).or_else(|error| self.fail(error))?;
                let expected = add_tick(arrival, self.config.feedback_wait_ticks)
                    .or_else(|error| self.fail(error))?;
                self.encoder
                    .confirm_repair(id, now)
                    .or_else(|error| self.fail(error))?;
                for offset in 0..job.terms {
                    let source =
                        self.terms[slot * usize::from(self.config.long_window) + offset].source;
                    let Some(flight) = self
                        .flight(source)
                        .copied()
                        .filter(|flight| !flight.acknowledged)
                    else {
                        continue;
                    };
                    let change =
                        job.feedback && flight.retry_at.is_some_and(|retry| expected >= retry);
                    let rearm = if change {
                        Some(
                            add_tick(expected, self.config.rto_min_ticks)
                                .or_else(|error| self.fail(error))?,
                        )
                    } else {
                        None
                    };
                    let order = if change {
                        Some(self.next_order().or_else(|error| self.fail(error))?)
                    } else {
                        None
                    };
                    let value = self.flight_mut(source).ok_or(Error::Identity)?;
                    value.queued = value.queued.checked_sub(1).ok_or(Error::Identity)?;
                    value.repair_until = value.repair_until.max(expected);
                    if let Some(order) = order {
                        value.retry_at = rearm;
                        value.retry_order = order;
                    }
                }
                self.jobs[slot] = None;
                self.queued -= 1;
                self.queue_end = self.jobs.iter().flatten().map(|job| job.expires).min();
                self.pending = None;
                self.prepared = None;
                self.output_end = None;
            }
        }
        Ok(())
    }
    fn acknowledged_by(feedback: Feedback<'_>, source: SourceId) -> bool {
        feedback.prefix.is_some_and(|prefix| source.0 < prefix)
            || feedback.ids.binary_search(&source).is_ok()
    }
    /// Apply authenticated exact/cumulative receipts and causally eligible early
    /// feedback repairs. A batch of M eligible holes generates M independent rows
    /// over those same M holes. Capacity/invalid coefficient errors commit no ACK,
    /// early marker or queue row, so the caller may retry the complete feedback.
    /// Reordered snapshots merge monotonic receipt evidence; their older IDs do
    /// not erase the newest fingerprint. External authenticated replay checks
    /// must bind an older identity to its original bytes. Existing queued/early
    /// guards bound repeat repair scheduling even after reordered receipt copies.
    pub fn receive_feedback<C: CoefficientSource + ?Sized>(
        &mut self,
        feedback: Feedback<'_>,
        now: Tick,
        random: &mut C,
    ) -> Result<FeedbackDisposition, Error> {
        feedback.validate(self.config)?;
        if feedback.scope != self.scope {
            return Err(Error::Scope);
        }
        if feedback.prefix.is_some_and(|prefix| prefix > self.sent)
            || feedback.ids.iter().any(|id| id.0 >= self.sent)
        {
            return Err(Error::Identity);
        }
        self.time(now)?;
        let reordered = self.receipt.is_some_and(|old| feedback.id < old.id);
        if let Some(old) = self.receipt
            && feedback.id == old.id
        {
            return if feedback.prefix == old.prefix
                && feedback.ids == &self.receipt_ids[..old.count]
            {
                Ok(FeedbackDisposition::Duplicate)
            } else {
                Err(Error::Conflict)
            };
        }
        let highest = self
            .highest_feedback
            .max(feedback.prefix.unwrap_or(0))
            .max(feedback.ids.last().map_or(0, |id| id.0 + 1));
        let mut count = 0;
        let mut largest = 0;
        if self.config.feedback_repair {
            for source in self.encoder.status().confirmed_prefix..self.encoder.status().next_source
            {
                let id = SourceId(source);
                if source + 1 >= highest || count == usize::from(self.config.long_window) {
                    break;
                }
                let Some(flight) = self.flight(id).copied() else {
                    return Err(Error::Identity);
                };
                if flight.acknowledged
                    || Self::acknowledged_by(feedback, id)
                    || flight.attempts != 1
                    || flight.early
                    || flight.queued != 0
                {
                    continue;
                }
                let eligible = add_tick(flight.sent_at.ok_or(Error::Identity)?, flight.rtt)?
                    .max(flight.repair_until);
                if now < eligible {
                    continue;
                }
                let size = largest.max(flight.size);
                if size + 4 * (count + 1) > self.config.feedback_payload_budget {
                    continue;
                }
                self.candidates[count] = id;
                count += 1;
                largest = size;
            }
        }
        let reserve = self.reserved_periodic_count();
        if self.jobs.len() - self.queued < count + reserve {
            return Err(Error::Capacity);
        }
        self.queue_batch(count, Some(count), now, random)?;
        for offset in 0..count {
            let source = self.candidates[offset];
            self.flight_mut(source).ok_or(Error::Identity)?.early = true;
        }
        for at in 0..self.flights.len() {
            let Some(flight) = self.flights[at].as_mut() else {
                continue;
            };
            if !flight.acknowledged && Self::acknowledged_by(feedback, flight.id) {
                flight.acknowledged = true;
                flight.retry_at = None;
                self.pending_sources -= 1;
                self.pending_bytes -= flight.size;
            }
        }
        let mut prefix = self.encoder.status().confirmed_prefix;
        while prefix < self.encoder.status().next_source
            && self
                .flight(SourceId(prefix))
                .is_some_and(|flight| flight.acknowledged)
        {
            prefix += 1;
        }
        self.encoder
            .confirm_prefix(prefix, now)
            .or_else(|error| self.fail(error))?;
        if self.pending_sources == 0 {
            self.debt_end = None;
        }
        self.highest_feedback = highest;
        if !reordered {
            self.receipt_ids[..feedback.ids.len()].copy_from_slice(feedback.ids);
            self.receipt = Some(Receipt {
                id: feedback.id,
                prefix: feedback.prefix,
                count: feedback.ids.len(),
            });
        }
        Ok(if reordered {
            FeedbackDisposition::Reordered
        } else {
            FeedbackDisposition::Applied
        })
    }
    /// Earliest immutable expiry; service due times are not expiry renewals.
    pub fn deadline(&self) -> Option<Tick> {
        self.encoder
            .deadline()
            .into_iter()
            .chain(self.output_end)
            .chain(self.debt_end)
            .chain(self.queue_end)
            .min()
    }
    /// Earliest timer or hard expiry for caller-owned event scheduling.
    pub fn next_wakeup(&self) -> Option<Tick> {
        self.deadline()
            .into_iter()
            .chain(self.fec_due)
            .chain(self.jobs.iter().flatten().map(|job| job.due))
            .chain(
                self.flights
                    .iter()
                    .flatten()
                    .filter(|flight| !flight.acknowledged)
                    .filter_map(|flight| flight.retry_at),
            )
            .min()
    }
    /// True only after all admitted originals are acknowledged, every partial
    /// FEC group is flushed and every queued/output packet leaves this owner.
    /// Retained coding history is reusable and is not outstanding delivery debt.
    pub fn is_drained(&self) -> bool {
        self.terminal.is_none()
            && self.pending_sources == 0
            && self.queued == 0
            && self.fec_count == 0
            && self.pending.is_none()
    }
    /// Bounded allocation-free diagnostic snapshot.
    pub fn status(&self) -> SenderStatus {
        SenderStatus {
            encoder: self.encoder.status(),
            sent_sources: self.sent,
            pending_sources: self.pending_sources,
            pending_bytes: self.pending_bytes,
            queued_repairs: self.queued,
            periodic_repairs: self.periodic,
            repair_credit: self.credit,
            fec_count: self.fec_count,
            output_ready: self.pending_output().is_some(),
            feedback: self.receipt.map(|receipt| receipt.id),
            terminal: self.terminal,
        }
    }
}

#[cfg(test)]
#[path = "sender_tests.rs"]
mod tests;
