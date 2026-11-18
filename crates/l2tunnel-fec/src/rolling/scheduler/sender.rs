use super::*;

/// Nonreused identity of the exact current source/repair output.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OutputId {
    /// Systematic original source identity.
    Source(SourceId),
    /// Complete repair identity, independent of the source namespace.
    Repair(RepairId),
}
/// Borrowed immutable output; encode it with the structural codec before handoff.
#[derive(Clone, Copy, Debug)]
pub enum Output<'a> {
    /// One actual admitted source, before the sender earns repair credit.
    Source {
        /// Complete authenticated outer domain.
        scope: Scope,
        /// Exact original identity.
        id: SourceId,
        /// Actual original bytes, including meaningful zero tails.
        original: &'a [u8],
    },
    /// One completely computed actual-byte equation.
    Repair(Repair<'a>),
}
impl Output<'_> {
    /// Identity required to confirm exactly this complete external handoff.
    pub fn id(self) -> OutputId {
        match self {
            Self::Source { id, .. } => OutputId::Source(id),
            Self::Repair(value) => OutputId::Repair(value.id),
        }
    }
}
/// One local physical-copy ordinal; source wire identity remains unchanged.
/// This is not peer authority or evidence that any carrier accepted bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SourceCopy {
    source: SourceId,
    ordinal: u8,
    total: u8,
    prepared_at: Tick,
}
impl SourceCopy {
    /// The one original recovery source shared by every physical copy.
    pub const fn source(self) -> SourceId {
        self.source
    }
    /// One-based physical ordinal, unchanged through local backpressure.
    pub const fn ordinal(self) -> u8 {
        self.ordinal
    }
    /// Exact selected physical count, from one through four.
    pub const fn total(self) -> u8 {
        self.total
    }
    /// Earliest caller time at which this exact ordinal became available.
    pub const fn prepared_at(self) -> Tick {
        self.prepared_at
    }
}

/// Bounded handling of an authenticated identified cumulative receipt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FeedbackDisposition {
    /// A fresh identity updated actual receipt/deficit state.
    Applied,
    /// Same retained identity and complete body; no state/timer change.
    Duplicate,
    /// Older identity or regressed prefix; no receipt/deficit/timer change.
    Stale,
}
/// Current scheduling facts; these are not carrier or native-delivery measurements.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SenderStatus {
    /// Actual bounded encoder ownership.
    pub encoder: EncoderStatus,
    /// Exclusive identity after all accepted originals, including queued custody.
    pub next_source: u32,
    /// Originals in custody and awaiting physical scheduling outside the encoder.
    pub queued_fresh: usize,
    /// Largest observed custody queue depth.
    pub peak_queued_fresh: usize,
    /// Fixed preallocated custody queue capacity.
    pub fresh_queue_limit: usize,
    /// Exclusive source prefix fully handed off by this scheduler's caller.
    pub sent_sources: u32,
    /// Residual exact numerator units, always below the denominator.
    pub repair_credit: u32,
    /// Regular earned repairs waiting for service, at most two for targeted service.
    pub regular_due: u32,
    /// Unfinished repairs in the current bounded tail burst, including its output.
    pub tail_remaining: u32,
    /// Next idle-tail service trigger; it is not an expiry deadline.
    pub tail_due: Option<Tick>,
    /// Complete immutable output is ready for caller ownership transfer.
    pub output_ready: bool,
    /// Latest applied actual receipt identity.
    pub feedback: Option<FeedbackId>,
    /// Original wrapper failure, if any.
    pub terminal: Option<Error>,
}
/// Unique local physical-handoff witness for a retained-original retransmission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RetryToken {
    id: SourceId,
    serial: u64,
    prepared: Tick,
}
#[derive(Clone, Copy)]
enum Pending {
    Source(SourceId),
    Retry {
        id: SourceId,
        full_credit: Option<bool>,
    },
    Repair {
        id: RepairId,
        tail: bool,
    },
}
/// One pure sender: a real encoder, exact repair credit and one immutable output.
pub struct Sender {
    policy: Policy,
    scope: Scope,
    encoder: Encoder,
    retry_queue: targeted::Queues,
    fresh: fresh::Queue,
    // Fresh wire bytes minus twice recovery wire bytes under contention.
    balance: i64,
    competing: bool,
    last_named: bool,
    last_probe: bool,
    mux_age_micros: u64,
    full_credit: bool,
    requested_prefix: u32,
    retry_serial: u64,
    retry_token: Option<RetryToken>,
    pending: Option<Pending>,
    output_end: Option<Tick>,
    source_copy: Option<SourceCopy>,
    sent: u32,
    credit: u32,
    regular_due: u32,
    tail_remaining: u32,
    tail_due: Option<Tick>,
    feedback: Option<Feedback>,
    last: Tick,
    terminal: Option<Error>,
    expiry_failure: Option<expiry::Failure>,
}
impl Sender {
    /// Admit the complete exact heap layout before constructing the same encoder.
    /// Existing conservative policy/config caps and all original time checks remain.
    pub fn new_reserved(
        policy: Policy,
        scope: Scope,
        now: Tick,
        limits: storage::Limits,
    ) -> Result<Self, storage::Error> {
        let plan = storage::Plan::for_sender(policy)?;
        plan.admit(limits, now)?;
        let value = Self::new(policy, scope, now)?;
        plan.verify(value.storage_usage()?, limits)?;
        Ok(value)
    }

    /// Observe actual retained nested capacities, excluding the inline owner header.
    /// This observation is also available for the unchanged compatibility constructor.
    pub fn storage_usage(&self) -> Result<storage::Usage, storage::Error> {
        self.encoder
            .storage_usage()?
            .join(self.retry_queue.usage()?)?
            .join(self.fresh.usage()?)
    }

    /// Conservative total retained reservation, excluding caller buffers/allocator overhead.
    pub fn memory_bound(policy: Policy) -> Result<usize, Error> {
        policy.validate()?;
        add(
            add(
                if policy.source_wire.is_targeted() {
                    Encoder::targeted_memory_bound(policy.recovery)?
                } else {
                    Encoder::sliding_memory_bound(policy.recovery)?
                },
                add(
                    targeted::Queues::bytes(policy)?,
                    fresh::Queue::bytes(policy)?,
                )?,
            )?,
            std::mem::size_of::<Self>(),
        )
    }
    /// Construct all encoder payload storage before accepting originals.
    pub fn new(policy: Policy, scope: Scope, now: Tick) -> Result<Self, Error> {
        if Self::memory_bound(policy)? > policy.memory_bytes {
            return Err(Error::Capacity);
        }
        deadline(now, policy.tail_ticks)?;
        Ok(Self {
            encoder: if policy.source_wire.is_targeted() {
                Encoder::new_targeted(policy.recovery, scope, now)?
            } else {
                Encoder::new_sliding(policy.recovery, scope, now)?
            },
            retry_queue: targeted::Queues::new(policy)?,
            fresh: fresh::Queue::new(policy)?,
            balance: 0,
            competing: false,
            last_named: false,
            last_probe: false,
            mux_age_micros: 0,
            full_credit: false,
            requested_prefix: 0,
            retry_serial: 0,
            retry_token: None,
            policy,
            scope,
            pending: None,
            output_end: None,
            source_copy: None,
            sent: 0,
            credit: 0,
            regular_due: 0,
            tail_remaining: 0,
            tail_due: None,
            feedback: None,
            last: now,
            terminal: None,
            expiry_failure: None,
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
        if let Err(error) = check_time(
            self.last,
            now,
            &[self.output_end, self.fresh.earliest().map(|e| Tick(e.due))],
        ) {
            if error == Error::Expired {
                self.expiry_failure = self
                    .expiry_failure
                    .or_else(|| self.expiry_snapshot().first_expired(now, &[3, 4]));
            }
            return self.fail(error);
        }
        if let Err(error) = self.encoder.step(now, WorkBudget::default()) {
            return self.fail(error);
        }
        self.last = now;
        Ok(())
    }
    fn later(&mut self, now: Tick, ticks: u64) -> Result<Tick, Error> {
        deadline(now, ticks).or_else(|error| self.fail(error))
    }
    /// Take bounded custody of one source. Repair credit starts at physical confirmation.
    pub fn admit_source(&mut self, original: &[u8], now: Tick) -> Result<SourceId, Error> {
        self.admit_source_with_copies(original, now, 1)
    }
    /// Admit one actual source and a bounded physical-copy group. No additional
    /// source, debt or repair credit is created for subsequent copies.
    pub fn admit_source_with_copies(
        &mut self,
        original: &[u8],
        now: Tick,
        copies: u8,
    ) -> Result<SourceId, Error> {
        self.admit_source_with_copies_at(original, now, now, copies)
    }
    /// Preserve the packing creation time through targeted custody, selection and receipt.
    pub fn admit_source_with_copies_at(
        &mut self,
        original: &[u8],
        created: Tick,
        now: Tick,
        copies: u8,
    ) -> Result<SourceId, Error> {
        if !(1..=4).contains(&copies) {
            return Err(Error::Configuration);
        }
        self.time(now)?;
        let targeted = self.policy.source_wire.is_targeted();
        let created = if targeted { created } else { now };
        let busy =
            self.pending.is_some() || self.regular_due != 0 || self.retry_queue.has_retries();
        if !targeted && busy {
            return Err(Error::Busy);
        }
        if original.is_empty() || original.len() > self.policy.recovery.max_payload {
            return Err(Error::Length);
        }
        if created > now {
            return self.fail(Error::TimeRegression);
        }
        let end = self.later(created, self.policy.recovery.job_ticks)?;
        if targeted {
            let due = end.min(self.later(created, self.policy.recovery.debt_ticks)?);
            let state = self.encoder.status();
            let id = state
                .next_source
                .checked_add(self.fresh.len as u32)
                .ok_or(Error::Exhausted)?;
            if id == u32::MAX {
                return self.fail(Error::Exhausted);
            }
            if now >= due {
                self.expiry_failure = Some(expiry::Failure {
                    observed: now,
                    selected: expiry::Deadline::new(
                        expiry::Kind::IncomingCap,
                        due,
                        Some(expiry::Identity::Sources {
                            first: id,
                            end: id + 1,
                        }),
                    ),
                });
                return self.fail(Error::Expired);
            }
            if (id - state.confirmed_prefix) as usize >= self.policy.recovery.window {
                return Err(Error::Capacity);
            }
            if busy || self.fresh.len > 0 || self.tail_due.is_some_and(|v| now >= v) {
                self.fresh.push(
                    fresh::Entry {
                        id,
                        created: created.0,
                        due: due.0,
                        copies,
                        len: original.len(),
                    },
                    original,
                )?;
                return Ok(SourceId(id));
            }
            self.competing = false;
            self.balance = 0;
        }
        let id = self.encoder.admit_source_created(original, created, now)?;
        self.install_source(id, copies, now, end);
        Ok(id)
    }
    fn install_source(&mut self, id: SourceId, copies: u8, now: Tick, end: Tick) {
        self.tail_remaining = 0;
        if !self.policy.source_wire.is_targeted() {
            self.tail_due = None;
        }
        self.pending = Some(Pending::Source(id));
        self.source_copy = Some(SourceCopy {
            source: id,
            ordinal: 1,
            total: copies,
            prepared_at: now,
        });
        self.output_end = Some(end);
    }
    fn select_fresh(&mut self, now: Tick) -> Result<(), Error> {
        let (e, original) = self.fresh.front().ok_or(Error::Busy)?;
        let id = self
            .encoder
            .admit_source_created(original, Tick(e.created), now)?;
        self.fresh.pop();
        self.install_source(
            id,
            e.copies,
            now,
            deadline(Tick(e.created), self.policy.recovery.job_ticks)?,
        );
        Ok(())
    }
    /// Advance at most one bounded repair job. All-zero work cannot start a job.
    pub fn step(&mut self, now: Tick, budget: WorkBudget) -> Result<WorkUsed, Error> {
        self.step_with_regular_filter(now, budget, |_, _| Ok(false))
    }
    /// An opt-in targeted sender may displace an earned regular opportunity with
    /// already accepted retry bytes. A displaced opportunity starts no equation
    /// and consumes no repair serial, output reservation or source custody.
    pub fn step_with_regular_filter(
        &mut self,
        now: Tick,
        mut budget: WorkBudget,
        mut displace: impl FnMut(RepairId, Support) -> Result<bool, Error>,
    ) -> Result<WorkUsed, Error> {
        budget.validate()?;
        self.time(now)?;
        let before = budget;
        if self.pending.is_none() && spend(&mut budget.metadata) {
            let state = self.encoder.status();
            let targeted = self.policy.source_wire.is_targeted();
            let outstanding = state.confirmed_prefix != state.next_source;
            if !outstanding {
                self.regular_due = 0;
                self.tail_remaining = 0;
                self.tail_due = None;
            }
            let named = self.retry_queue.has_retries();
            let regular = self.regular_due != 0 && outstanding;
            let probe = targeted && outstanding && self.tail_due.is_some_and(|v| now >= v);
            let recovery = named || regular || probe;
            self.competing = self.fresh.len > 0 && recovery;
            if !self.competing {
                self.balance = 0;
            }
            if self.fresh.len > 0 && (!recovery || (self.balance <= 0 && self.regular_due < 2)) {
                self.select_fresh(now)?;
                return Ok(used(before, budget));
            }
            // The oldest unconfirmed source gets an independent timed probe even
            // during continuous admissions and repeated newer named requests.
            if probe && !(self.last_probe && (named || regular)) {
                self.last_probe = true;
                self.queue_retry(SourceId(state.confirmed_prefix), None, now)?;
                return Ok(used(before, budget));
            }
            self.last_probe = false;
            if !(regular && self.last_named)
                && let Some((id, full_credit)) = self
                    .retry_queue
                    .next_retry(state.confirmed_prefix, &mut budget)
            {
                self.last_named = true;
                self.queue_retry(id, Some(full_credit), now)?;
                return Ok(used(before, budget));
            }
            if outstanding {
                if !targeted
                    && self.regular_due == 0
                    && self.tail_remaining == 0
                    && self.tail_due.is_some_and(|due| now >= due)
                {
                    self.tail_remaining = self.feedback.map_or(1, |f| f.deficit.max(1));
                }
                let tail = self.regular_due == 0;
                if !tail || self.tail_remaining != 0 {
                    self.last_named = false;
                    if !tail && self.policy.source_wire.is_targeted() {
                        let (id, support) = self.encoder.next_regular()?;
                        if displace(id, support)? {
                            self.regular_due -= 1;
                            return Ok(used(before, budget));
                        }
                    }
                    let end = self.later(now, self.policy.recovery.job_ticks)?;
                    let id = self.encoder.begin_repair(tail, now)?;
                    if !tail {
                        self.regular_due -= 1;
                    }
                    self.pending = Some(Pending::Repair { id, tail });
                    self.output_end = Some(end);
                }
            }
        }
        if matches!(self.pending, Some(Pending::Repair { .. })) {
            let consumed = self.encoder.step(now, budget)?;
            budget = remaining(budget, consumed);
        }
        Ok(used(before, budget))
    }
    fn queue_retry(
        &mut self,
        id: SourceId,
        full_credit: Option<bool>,
        now: Tick,
    ) -> Result<(), Error> {
        if self.encoder.source(id).is_none() {
            return Err(Error::Identity);
        }
        self.output_end = Some(self.later(now, self.policy.recovery.job_ticks)?);
        self.retry_serial = self.retry_serial.checked_add(1).ok_or(Error::Exhausted)?;
        self.retry_token = Some(RetryToken {
            id,
            serial: self.retry_serial,
            prepared: now,
        });
        self.pending = Some(Pending::Retry { id, full_credit });
        Ok(())
    }
    /// Read the immutable witness for one exact retry, retained across local backpressure.
    pub fn pending_retry_token(&self) -> Option<RetryToken> {
        self.retry_token
    }
    /// Consume this retry once after the actual complete physical handoff.
    pub fn confirm_retry(
        &mut self,
        token: RetryToken,
        accepted: Tick,
        observed: Tick,
    ) -> Result<(), Error> {
        let bytes = self.pending_wire_len()?.unwrap_or_default();
        self.confirm_retry_charged(token, accepted, observed, bytes)
    }
    /// Confirm the exact retry with the actual enclosing carrier byte cost.
    pub fn confirm_retry_charged(
        &mut self,
        token: RetryToken,
        accepted: Tick,
        observed: Tick,
        wire_bytes: usize,
    ) -> Result<(), Error> {
        if self.retry_token != Some(token) {
            return Err(Error::Identity);
        }
        if token.prepared > accepted || accepted > observed {
            return self.fail(Error::TimeRegression);
        }
        self.time(observed)?;
        self.finish_output(OutputId::Source(token.id), observed, accepted, wire_bytes)
    }
    /// Only a named retry earns shared repair credit at complete physical acceptance.
    pub fn pending_requested_retry(&self) -> bool {
        self.pending_requested_credit().is_some()
    }
    /// Tier bound to the request that scheduled this retained original.
    /// None denotes an ordinary output or a quiet probe.
    pub fn pending_requested_credit(&self) -> Option<bool> {
        match self.pending {
            Some(Pending::Retry { full_credit, .. }) => full_credit,
            _ => None,
        }
    }
    /// Age of the oldest local unadmitted frame when processing authenticated feedback.
    pub fn observe_mux_wait_micros(&mut self, age: u64) {
        self.mux_age_micros = age;
    }
    /// At least one received request awaits inspection under the next work budget.
    pub fn requested_retry_waiting(&self) -> bool {
        self.retry_queue.has_retries()
    }
    fn idle_ticks(&self) -> u64 {
        if self.policy.source_wire.is_targeted() {
            targeted::PROBE
        } else {
            self.policy.tail_ticks
        }
    }
    fn observe_prefix_progress(&mut self, prefix: u32, now: Tick) -> Result<(), Error> {
        let previous = self
            .requested_prefix
            .max(self.feedback.map_or(0, |f| f.prefix));
        if self.policy.source_wire.is_targeted() && prefix > previous {
            self.tail_due = if prefix < self.sent {
                Some(self.later(now, targeted::PROBE)?)
            } else {
                None
            };
        }
        Ok(())
    }
    /// Borrow the exact current immutable complete output. Polling changes nothing.
    pub fn pending_output(&self) -> Option<Output<'_>> {
        if self.terminal.is_some() {
            return None;
        }
        match self.pending? {
            Pending::Source(id) | Pending::Retry { id, .. } => Some(Output::Source {
                scope: self.scope,
                id,
                original: self.encoder.source(id)?,
            }),
            Pending::Repair { .. } => self.encoder.pending_repair().map(Output::Repair),
        }
    }
    /// Encode the immutable pending output into caller-reserved storage, without consuming it.
    /// Structural wire errors and undersized output leave the caller bytes unchanged.
    pub fn encode_pending(&self, output: &mut [u8]) -> Result<usize, Error> {
        match self.pending_output().ok_or(Error::Busy)? {
            Output::Source {
                scope,
                id,
                original,
            } => wire::encode_source_with(
                self.policy.recovery,
                self.policy.source_wire,
                scope,
                id,
                original,
                output,
            ),
            Output::Repair(repair) => wire::encode_repair_with(
                self.policy.recovery,
                self.policy.source_wire,
                repair,
                output,
            ),
        }
    }
    /// Exact length `encode_pending` would write for the current immutable output.
    /// Polling changes nothing; charge this before reserving carrier allowance.
    pub fn pending_wire_len(&self) -> Result<Option<usize>, Error> {
        match self.pending_output() {
            None => Ok(None),
            Some(Output::Source { original, .. }) => wire::source_len(
                self.policy.recovery,
                self.policy.source_wire,
                original.len(),
            )
            .map(Some),
            Some(Output::Repair(repair)) => repair
                .bytes
                .len()
                .checked_add(wire::HEADER_BYTES)
                .map(Some)
                .ok_or(Error::Length),
        }
    }
    /// Observe the exact current systematic-copy ordinal without changing time.
    pub fn pending_source_copy(&self) -> Option<SourceCopy> {
        if self.terminal.is_some() {
            return None;
        }
        self.source_copy
    }
    /// Confirm an ordinary one-copy source or repair. Explicit repeated-source
    /// groups require their ordinal-bearing witness and cannot use this method.
    pub fn confirm_output(&mut self, id: OutputId, now: Tick) -> Result<(), Error> {
        let bytes = self.pending_wire_len()?.unwrap_or_default();
        self.confirm_output_charged(id, now, bytes)
    }
    /// Confirm one complete ordinary output with its enclosing carrier byte cost.
    pub fn confirm_output_charged(
        &mut self,
        id: OutputId,
        now: Tick,
        wire_bytes: usize,
    ) -> Result<(), Error> {
        if self.retry_token.is_some() || self.source_copy.is_some_and(|copy| copy.total != 1) {
            return Err(Error::Identity);
        }
        self.time(now)?;
        self.finish_output(id, now, now, wire_bytes)
    }
    /// Consume exactly one caller-observed whole systematic-copy acceptance.
    /// A repeated ordinal is rejected before clock, counters or retirement change.
    /// The original group deadline remains fixed from initial source admission.
    pub fn confirm_source_copy(
        &mut self,
        observed: Tick,
        accepted: Tick,
        copy: SourceCopy,
    ) -> Result<(), Error> {
        let bytes = self.pending_wire_len()?.unwrap_or_default();
        self.confirm_source_copy_charged(observed, accepted, copy, bytes)
    }
    /// Confirm one physical original ordinal with its enclosing carrier byte cost.
    pub fn confirm_source_copy_charged(
        &mut self,
        observed: Tick,
        accepted: Tick,
        copy: SourceCopy,
        wire_bytes: usize,
    ) -> Result<(), Error> {
        if self.source_copy != Some(copy)
            || !matches!(self.pending, Some(Pending::Source(id)) if id == copy.source)
        {
            return Err(Error::Identity);
        }
        // Physical ownership has already happened. Retire this local witness
        // even when its timing subsequently makes this scheduler terminal.
        self.source_copy = None;
        if accepted < copy.prepared_at || accepted > observed {
            return self.fail(Error::TimeRegression);
        }
        self.time(observed)?;
        if copy.ordinal < copy.total {
            self.sent = copy.source.0.checked_add(1).ok_or(Error::Exhausted)?;
            self.source_copy = Some(SourceCopy {
                ordinal: copy.ordinal + 1,
                prepared_at: observed,
                ..copy
            });
            self.charge(true, wire_bytes);
            return Ok(());
        }
        self.finish_output(
            OutputId::Source(copy.source),
            observed,
            accepted,
            wire_bytes,
        )
    }
    fn charge(&mut self, fresh: bool, wire_bytes: usize) {
        if !self.competing {
            return;
        }
        let cap = 4 * (self.policy.recovery.max_payload + wire::HEADER_BYTES) as i64;
        let cost = i64::try_from(wire_bytes).unwrap_or(i64::MAX);
        self.balance = if fresh {
            self.balance.saturating_add(cost)
        } else {
            self.balance.saturating_sub(cost.saturating_mul(2))
        }
        .clamp(-cap, cap);
    }
    fn finish_output(
        &mut self,
        id: OutputId,
        now: Tick,
        accepted: Tick,
        wire_bytes: usize,
    ) -> Result<(), Error> {
        let output = self.pending_output().ok_or(Error::Busy)?;
        if output.id() != id {
            return Err(Error::Identity);
        }
        let pending = self.pending.ok_or(Error::Busy)?;
        match pending {
            Pending::Source(source) => {
                let tail_due =
                    deadline(accepted, self.idle_ticks()).or_else(|error| self.fail(error))?;
                self.sent = source.0.checked_add(1).ok_or(Error::Exhausted)?;
                let earned = self.credit + self.policy.repair_numerator;
                self.regular_due += earned / self.policy.repair_denominator;
                self.credit = earned % self.policy.repair_denominator;
                if self.policy.source_wire.is_targeted() {
                    self.tail_due.get_or_insert(tail_due);
                } else {
                    self.tail_due = Some(tail_due);
                }
                self.source_copy = None;
                // A peer may have acknowledged the first actual copy already.
                // Remaining physical copies pinned the exact encoder payload;
                // applying the retained real prefix now cannot invent receipt.
                if self.feedback.is_some() || self.requested_prefix != 0 {
                    let prefix = self
                        .feedback
                        .map_or(0, |f| f.prefix)
                        .max(self.requested_prefix);
                    self.encoder.confirm_prefix(prefix, now)?;
                    if prefix == self.encoder.status().next_source {
                        self.regular_due = 0;
                        self.tail_remaining = 0;
                        self.tail_due = None;
                    }
                }
            }
            Pending::Retry { id, full_credit } => {
                self.retry_token = None;
                let prefix = self
                    .requested_prefix
                    .max(self.feedback.map_or(0, |f| f.prefix));
                if full_credit.is_none() && id.0 >= prefix {
                    self.tail_due = Some(self.later(accepted, targeted::PROBE)?);
                }
                self.encoder
                    .confirm_prefix(prefix.max(self.encoder.status().confirmed_prefix), now)?;
                if self.encoder.status().confirmed_prefix == self.sent {
                    self.tail_due = None;
                }
            }
            Pending::Repair { id, tail } => {
                let needs_timer = tail
                    && self.tail_remaining <= 1
                    && self.encoder.status().confirmed_prefix != self.encoder.status().next_source;
                let next = if needs_timer {
                    Some(self.later(now, self.policy.tail_ticks)?)
                } else {
                    self.tail_due
                };
                self.encoder.confirm_repair(id, now)?;
                if tail {
                    self.tail_remaining = self.tail_remaining.saturating_sub(1);
                    self.tail_due = next;
                }
            }
        }
        self.charge(matches!(pending, Pending::Source(_)), wire_bytes);
        self.pending = None;
        self.output_end = None;
        Ok(())
    }
    /// Apply only caller-authenticated feedback bound to this complete forward scope.
    pub fn receive_feedback(
        &mut self,
        feedback: Feedback,
        now: Tick,
    ) -> Result<FeedbackDisposition, Error> {
        feedback.validate(self.policy.recovery)?;
        if feedback.scope != self.scope {
            return Err(Error::Scope);
        }
        self.time(now)?;
        if feedback.observed_end > self.sent {
            return Err(Error::Identity);
        }
        if let Some(previous) = self.feedback {
            if feedback.id < previous.id {
                return Ok(FeedbackDisposition::Stale);
            }
            if feedback.id == previous.id {
                return if feedback == previous {
                    Ok(FeedbackDisposition::Duplicate)
                } else {
                    Err(Error::Conflict)
                };
            }
        }
        if feedback.prefix < self.encoder.status().confirmed_prefix
            || self
                .feedback
                .is_some_and(|old| feedback.prefix < old.prefix)
        {
            return Ok(FeedbackDisposition::Stale);
        }
        if self
            .feedback
            .is_some_and(|old| feedback.observed_end < old.observed_end)
        {
            return Err(Error::Identity);
        }
        let released = self
            .source_copy
            .map_or(feedback.prefix, |copy| feedback.prefix.min(copy.source.0));
        let released = self.pin_retry(released);
        self.encoder.confirm_prefix(released, now)?;
        self.observe_prefix_progress(feedback.prefix, now)?;
        self.feedback = Some(feedback);
        if released == self.encoder.status().next_source {
            self.regular_due = 0;
            self.tail_remaining = 0;
            self.tail_due = None;
        }
        Ok(FeedbackDisposition::Applied)
    }
    fn pin_retry(&self, prefix: u32) -> u32 {
        match self.pending {
            Some(Pending::Retry { id, .. }) => prefix.min(id.0),
            _ => prefix,
        }
    }
    /// Admit authenticated, observed source requests while retaining older unconfirmed bytes.
    pub fn receive_request(
        &mut self,
        request: GapRequest,
        now: Tick,
    ) -> Result<FeedbackDisposition, Error> {
        if !self.policy.source_wire.is_targeted() {
            return Err(Error::Format);
        }
        request.validate(self.policy.recovery)?;
        if request.scope != self.scope {
            return Err(Error::Scope);
        }
        let last = request.start + (31 - request.mask.leading_zeros());
        if last >= self.sent {
            return Err(Error::Identity);
        }
        self.time(now)?;
        self.observe_prefix_progress(request.prefix, now)?;
        self.requested_prefix = self.requested_prefix.max(request.prefix);
        let mut release = self
            .requested_prefix
            .max(self.encoder.status().confirmed_prefix);
        if let Some(copy) = self.source_copy {
            release = release.min(copy.source.0);
        }
        self.encoder.confirm_prefix(self.pin_retry(release), now)?;
        let base = self
            .encoder
            .status()
            .confirmed_prefix
            .max(self.requested_prefix);
        let mut mask = request.mask;
        while mask != 0 {
            let id = request.start + mask.trailing_zeros();
            if id >= base {
                let full_credit = match self.mux_age_micros {
                    0..=5_000 => false,
                    15_000.. => true,
                    _ => self.full_credit,
                };
                if self
                    .retry_queue
                    .enqueue_retry(id, request.id.0, full_credit)
                {
                    self.full_credit = full_credit;
                }
            }
            mask &= mask - 1;
        }
        Ok(FeedbackDisposition::Applied)
    }
    /// Parse structurally, then apply under the same mandatory caller authentication boundary.
    pub fn receive_feedback_wire(
        &mut self,
        bytes: &[u8],
        now: Tick,
    ) -> Result<FeedbackDisposition, Error> {
        if bytes.get(5) == Some(&5) {
            return self
                .receive_request(GapRequest::decode_full(self.policy.recovery, bytes)?, now);
        }
        self.receive_feedback(decode_feedback(self.policy.recovery, bytes)?, now)
    }
    /// Read original outer and nested lifetimes without advancing service.
    pub fn expiry_snapshot(&self) -> expiry::Snapshot {
        use expiry::{Deadline, Identity, Kind};
        let mut snapshot = self.encoder.expiry_snapshot();
        let identity = self.pending.map(|pending| match pending {
            Pending::Source(id) | Pending::Retry { id, .. } => Identity::Sources {
                first: id.0,
                end: id.0 + 1,
            },
            Pending::Repair { id, .. } => Identity::Repair { id, support: None },
        });
        snapshot.candidates[3] = self
            .output_end
            .map(|at| Deadline::new(Kind::DataOutput, at, identity));
        snapshot.candidates[4] = self.fresh.earliest().map(|e| {
            Deadline::new(
                Kind::DataOutput,
                Tick(e.due),
                Some(Identity::Sources {
                    first: e.id,
                    end: e.id + 1,
                }),
            )
        });
        snapshot.last_successful = self.last;
        snapshot.terminal = self.terminal.or(snapshot.terminal);
        snapshot.failure = self.expiry_failure.or(snapshot.failure);
        snapshot
    }
    /// Earliest original hard expiry; service triggers do not renew it.
    pub fn deadline(&self) -> Option<Tick> {
        self.encoder
            .deadline()
            .into_iter()
            .chain(self.output_end)
            .chain(self.fresh.earliest().map(|e| Tick(e.due)))
            .min()
    }
    /// Earliest hard expiry or idle-tail trigger. Immediate output/work is visible in status.
    pub fn wake_at(&self) -> Option<Tick> {
        self.deadline().into_iter().chain(self.tail_due).min()
    }
    /// Constant-size scheduling snapshot, without advancing state.
    pub fn status(&self) -> SenderStatus {
        SenderStatus {
            encoder: self.encoder.status(),
            next_source: self.encoder.status().next_source + self.fresh.len as u32,
            queued_fresh: self.fresh.len,
            peak_queued_fresh: self.fresh.peak,
            fresh_queue_limit: self.fresh.limit(),
            sent_sources: self.sent,
            repair_credit: self.credit,
            regular_due: self.regular_due,
            tail_remaining: self.tail_remaining,
            tail_due: self.tail_due,
            output_ready: self.pending_output().is_some(),
            feedback: self.feedback.map(|f| f.id),
            terminal: self.terminal,
        }
    }
}

#[cfg(test)]
#[path = "sender_copy_tests.rs"]
mod copy_tests;
