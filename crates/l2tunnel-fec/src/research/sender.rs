use super::*;

/// Nonreused identity of one complete immutable output.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OutputId {
    /// One systematic source.
    Source(SourceId),
    /// One charged repair, independent of the source namespace.
    Repair(RepairId),
}

/// Immutable output borrowed until the caller confirms complete carrier custody.
#[derive(Clone, Copy, Debug)]
pub enum Output<'a> {
    /// Exact original bytes; a successful handoff earns 26/125 repair credit.
    Source {
        /// Authenticated enclosing domain.
        scope: Scope,
        /// Absolute nonwrapping source identity.
        id: SourceId,
        /// Exact original including meaningful trailing zero bytes.
        original: &'a [u8],
    },
    /// Actual encoded payload and the frozen sender-confirmed prefix.
    Repair(Repair<'a>),
}
impl Output<'_> {
    /// Identity required to confirm this exact complete output.
    pub fn id(self) -> OutputId {
        match self {
            Self::Source { id, .. } => OutputId::Source(id),
            Self::Repair(repair) => OutputId::Repair(repair.equation.id),
        }
    }
    /// Exact structural record bytes, before enclosing authentication/carrier overhead.
    pub fn encoded_len(self) -> usize {
        wire::HEADER_BYTES
            + match self {
                Self::Source { original, .. } => original.len(),
                Self::Repair(repair) => repair.equation.bytes.len(),
            }
    }
    /// Charge all actual record bytes plus caller-selected enclosing overhead.
    /// Every source, recursive repair and fallback repair uses this same boundary.
    pub fn charge(self, overhead: usize) -> Result<usize, Error> {
        self.encoded_len()
            .checked_add(overhead)
            .ok_or(Error::Exhausted)
    }
}

/// Treatment of one caller-authenticated cumulative receipt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FeedbackDisposition {
    /// A fresh nonregressing receipt was accepted.
    Applied,
    /// The latest identity and entire body match; no state changed.
    Duplicate,
    /// An older identity or prefix cannot change retention or scheduling.
    Stale,
}

/// Bounded sender observations; none establish native delivery.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SenderStatus {
    /// Actual source/equation storage and cumulative receipt.
    pub encoder: rolling::EncoderStatus,
    /// Exclusive prefix whose systematic records reached caller-confirmed custody.
    pub sent_sources: u32,
    /// Residual numerator units, always smaller than 125.
    pub repair_credit: u32,
    /// Repair records whose complete custody was confirmed.
    pub sent_repairs: u32,
    /// An earned repair owns the only output slot, including unfinished GF work.
    pub repair_pending: bool,
    /// The immutable complete output is available.
    pub output_ready: bool,
    /// Latest accepted feedback identity.
    pub feedback: Option<FeedbackId>,
    /// Original wrapper failure, if any.
    pub terminal: Option<Error>,
}

#[derive(Clone, Copy)]
enum Pending {
    Source(SourceId),
    Repair { id: RepairId, confirmed: u32 },
}

/// Causal 26/125 sender with one immutable output and a bounded real-byte encoder.
///
/// The caller supplies original creation time, monotonic service time and actual
/// whole-record output completions. No idle repair, tail repair, retransmission,
/// receiver-rank inference, timer-driven credit or additional payload queue exists.
/// An earned repair is frozen immediately after its source handoff and prevents
/// admission of the next source until its own complete handoff. Authentication,
/// delayed network delivery, pacing and shared MUX admission belong to the caller.
pub struct Sender {
    config: Config,
    scope: Scope,
    encoder: rolling::Encoder,
    pending: Option<Pending>,
    output_end: Option<Tick>,
    available_at: Option<Tick>,
    debt_end: Option<Tick>,
    sent: u32,
    repairs: u32,
    credit: u32,
    feedback: Option<Feedback>,
    feedback_at: Option<Tick>,
    last_source_accepted: Option<Tick>,
    last: Tick,
    terminal: Option<Error>,
}
impl Sender {
    /// Admit and verify the actual nested encoder heap capacities before use.
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

    /// Actual retained nested capacities, excluding this owner's inline header.
    pub fn storage_usage(&self) -> Result<rolling::storage::Usage, rolling::storage::Error> {
        self.encoder.storage_usage()
    }

    /// Conservative total reservation, excluding caller buffers and allocator metadata.
    pub fn memory_bound(config: Config) -> Result<usize, Error> {
        config.validate()?;
        rolling::Encoder::memory_bound(config.recovery)?
            .checked_add(std::mem::size_of::<Self>())
            .ok_or(Error::Exhausted)
    }

    /// Reserve all fixed encoder storage before admitting original payloads.
    pub fn new(config: Config, scope: Scope, now: Tick) -> Result<Self, Error> {
        if Self::memory_bound(config)? > config.memory_bytes {
            return Err(Error::Capacity);
        }
        Ok(Self {
            encoder: rolling::Encoder::new(config.recovery, scope, now)?,
            config,
            scope,
            pending: None,
            output_end: None,
            available_at: None,
            debt_end: None,
            sent: 0,
            repairs: 0,
            credit: 0,
            feedback: None,
            feedback_at: None,
            last_source_accepted: None,
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
        if [self.output_end, self.debt_end]
            .into_iter()
            .flatten()
            .any(|end| now >= end)
        {
            return self.fail(Error::Expired);
        }
        if let Err(error) = self.encoder.step(now, WorkBudget::default()) {
            return self.fail(error);
        }
        self.notice_availability(now);
        self.last = now;
        Ok(())
    }

    fn notice_availability(&mut self, now: Tick) {
        if self.available_at.is_none()
            && matches!(self.pending, Some(Pending::Repair { .. }))
            && self.encoder.pending_repair().is_some()
        {
            self.available_at = Some(now);
        }
    }

    /// Admit an original into the only output slot without earning repair credit.
    ///
    /// Both deadlines start at `created_at`, including time spent upstream. The
    /// conservative earliest unresolved-debt deadline survives later admissions,
    /// partial prefix feedback, polling and output backpressure. Prospective
    /// already-expired input is rejected before source storage is changed.
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
        if self.pending.is_some() {
            return Err(Error::Busy);
        }
        let output_end = created_at
            .0
            .checked_add(self.config.recovery.job_ticks)
            .map(Tick)
            .ok_or(Error::Exhausted)?;
        let debt_end = created_at
            .0
            .checked_add(self.config.recovery.debt_ticks)
            .map(Tick)
            .ok_or(Error::Exhausted)?;
        if now >= output_end || now >= debt_end {
            return Err(Error::Expired);
        }
        let id = self.encoder.admit_source(original, now)?;
        self.pending = Some(Pending::Source(id));
        self.available_at = Some(now);
        self.output_end = Some(output_end);
        self.debt_end = Some(self.debt_end.map_or(debt_end, |old| old.min(debt_end)));
        Ok(id)
    }

    /// Advance bounded encoding work. Zero work changes no output or repair credit.
    pub fn step(&mut self, now: Tick, budget: WorkBudget) -> Result<WorkUsed, Error> {
        self.time(now)?;
        match self.encoder.step(now, budget) {
            Ok(used) => {
                self.notice_availability(now);
                Ok(used)
            }
            Err(error @ Error::WorkLimit) => Err(error),
            Err(error) => self.fail(error),
        }
    }

    /// Borrow the current complete output; repeated polling changes nothing.
    pub fn pending_output(&self) -> Option<Output<'_>> {
        if self.terminal.is_some() {
            return None;
        }
        match self.pending? {
            Pending::Source(id) => Some(Output::Source {
                scope: self.scope,
                id,
                original: self.encoder.source(id)?,
            }),
            Pending::Repair { confirmed, .. } => self.encoder.pending_repair().map(|equation| {
                Output::Repair(Repair {
                    equation,
                    confirmed,
                })
            }),
        }
    }

    /// Exact record bytes currently available for output reservation and MUX charging.
    pub fn pending_wire_len(&self) -> Option<usize> {
        self.pending_output().map(Output::encoded_len)
    }

    /// Serialize into caller storage without consuming output or earning credit.
    /// All validation and capacity failures preserve caller bytes and pending state.
    pub fn encode_pending(&self, output: &mut [u8]) -> Result<usize, Error> {
        match self.pending_output().ok_or(Error::Busy)? {
            Output::Source {
                scope,
                id,
                original,
            } => wire::encode_source(self.config, scope, id, original, output),
            Output::Repair(repair) => wire::encode_repair(self.config, repair, output),
        }
    }

    /// Confirm exactly one complete output after actual external carrier custody.
    ///
    /// A systematic handoff earns exactly 26 numerator units. Every earned repair
    /// is frozen immediately, before any subsequently arriving prefix feedback,
    /// and retains the original source's deadline. The cumulative prefix cannot
    /// cancel an earned or pending repair. A failed support admission terminates
    /// this owner explicitly rather than shortening the reference equation.
    pub fn confirm_output(&mut self, id: OutputId, now: Tick) -> Result<(), Error> {
        self.confirm_output_at(id, now, now)
    }

    /// Preserve actual physical acceptance separately from callback observation.
    ///
    /// Repair support may only use feedback causally available at acceptance.
    /// Acceptance cannot precede this exact source/repair's actual availability.
    /// If later feedback was already applied, no historical prefix is invented:
    /// this owner becomes terminal, retires the physical output exactly once and
    /// retains its real sent count. The caller must order actual completions
    /// before subsequently arriving feedback. Neither timestamp rewinds a clock
    /// or renews the original source/debt cap.
    pub fn confirm_output_at(
        &mut self,
        id: OutputId,
        accepted: Tick,
        now: Tick,
    ) -> Result<(), Error> {
        let actual = self.pending_output().ok_or(Error::Busy)?.id();
        if actual != id {
            return Err(Error::Identity);
        }
        let freezes_repair = matches!(id, OutputId::Source(_)) && self.credit + 26 >= 125;
        let causal = self.available_at.is_some_and(|at| at <= accepted)
            && accepted <= now
            && (!freezes_repair || self.feedback_at.is_none_or(|at| at <= accepted));
        if matches!(id, OutputId::Source(_)) {
            self.last_source_accepted = Some(accepted);
        }
        let result = if causal {
            self.confirm_current(id, now)
        } else {
            Err(Error::TimeRegression)
        };
        if let Err(error) = result {
            // Whole physical ownership is irreversible even if subsequent
            // causal/time/expiry validation cannot continue this algorithm.
            match id {
                OutputId::Source(source) => {
                    self.sent = source.0.checked_add(1).ok_or(Error::Exhausted)?
                }
                OutputId::Repair(repair) => {
                    self.repairs = u32::try_from(repair.0).map_err(|_| Error::Exhausted)?
                }
            }
            self.pending = None;
            self.available_at = None;
            self.output_end = None;
            self.terminal.get_or_insert(error);
            return Err(error);
        }
        Ok(())
    }

    fn confirm_current(&mut self, id: OutputId, now: Tick) -> Result<(), Error> {
        let actual = self.pending_output().ok_or(Error::Busy)?.id();
        if actual != id {
            return Err(Error::Identity);
        }
        self.time(now)?;
        match self.pending.ok_or(Error::Busy)? {
            Pending::Source(source) => {
                self.sent = source.0.checked_add(1).ok_or(Error::Exhausted)?;
                let earned = self.credit + 26;
                self.credit = earned % 125;
                if earned >= 125 {
                    let serial = self
                        .repairs
                        .checked_add(1)
                        .ok_or(Error::Exhausted)
                        .or_else(|error| self.fail(error))?;
                    let confirmed = self.encoder.status().confirmed_prefix;
                    let support = self
                        .config
                        .profile
                        .support(self.sent, confirmed, serial)
                        .or_else(|error| self.fail(error))?;
                    let repair = self
                        .encoder
                        .begin_equation(support, self.config.profile, now)
                        .or_else(|error| self.fail(error))?;
                    if repair != RepairId(u64::from(serial)) {
                        return self.fail(Error::Identity);
                    }
                    self.pending = Some(Pending::Repair {
                        id: repair,
                        confirmed,
                    });
                    self.available_at = None;
                    self.notice_availability(now);
                } else {
                    self.pending = None;
                    self.available_at = None;
                    self.output_end = None;
                }
            }
            Pending::Repair { id, .. } => {
                self.encoder
                    .confirm_repair(id, now)
                    .or_else(|error| self.fail(error))?;
                self.repairs = self
                    .repairs
                    .checked_add(1)
                    .ok_or(Error::Exhausted)
                    .or_else(|error| self.fail(error))?;
                self.pending = None;
                self.available_at = None;
                self.output_end = None;
            }
        }
        Ok(())
    }

    /// Apply only an authenticated receipt delivered for this exact forward scope.
    ///
    /// Feedback conveys a cumulative prefix, never rank or guessed loss. The
    /// caller must supply real causal arrival times. Older snapshots cannot
    /// rewrite history, and no snapshot may observe an unsent systematic source.
    pub fn receive_feedback(
        &mut self,
        feedback: Feedback,
        now: Tick,
    ) -> Result<FeedbackDisposition, Error> {
        self.receive_feedback_at(feedback, now, now)
    }

    /// Preserve the original authenticated arrival while advancing service time.
    /// A fresh snapshot older than an already completed source cannot rewrite
    /// its frozen support. The caller must merge those genuine events first.
    pub fn receive_feedback_at(
        &mut self,
        feedback: Feedback,
        received: Tick,
        now: Tick,
    ) -> Result<FeedbackDisposition, Error> {
        if received > now {
            return Err(Error::TimeRegression);
        }
        feedback.validate(self.config)?;
        if feedback.scope != self.scope {
            return Err(Error::Scope);
        }
        if feedback.observed_end > self.sent {
            return Err(Error::Identity);
        }
        self.time(now)?;
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
            if feedback.prefix < previous.prefix {
                return Ok(FeedbackDisposition::Stale);
            }
            if feedback.observed_end < previous.observed_end {
                return Err(Error::Identity);
            }
        }
        if self.last_source_accepted.is_some_and(|at| received < at) {
            return self.fail(Error::TimeRegression);
        }
        self.encoder
            .confirm_prefix(feedback.prefix, now)
            .or_else(|error| self.fail(error))?;
        self.feedback = Some(feedback);
        self.feedback_at = Some(received);
        if feedback.prefix == self.encoder.status().next_source {
            self.debt_end = None;
        }
        Ok(FeedbackDisposition::Applied)
    }

    /// Parse one receipt under the same mandatory external authentication boundary.
    pub fn receive_feedback_wire(
        &mut self,
        bytes: &[u8],
        now: Tick,
    ) -> Result<FeedbackDisposition, Error> {
        self.receive_feedback_wire_at(bytes, now, now)
    }
    /// Parse exactly one authenticated receipt with its unchanged arrival time.
    pub fn receive_feedback_wire_at(
        &mut self,
        bytes: &[u8],
        received: Tick,
        now: Tick,
    ) -> Result<FeedbackDisposition, Error> {
        match wire::inspect(self.config, bytes)? {
            wire::View::Feedback(feedback) => self.receive_feedback_at(feedback, received, now),
            _ => Err(Error::Format),
        }
    }

    /// Earliest original hard deadline; output polling and partial feedback never renew it.
    pub fn deadline(&self) -> Option<Tick> {
        self.encoder
            .deadline()
            .into_iter()
            .chain(self.output_end)
            .chain(self.debt_end)
            .min()
    }

    /// Allocation-free observation of actual sender ownership.
    pub fn status(&self) -> SenderStatus {
        SenderStatus {
            encoder: self.encoder.status(),
            sent_sources: self.sent,
            repair_credit: self.credit,
            sent_repairs: self.repairs,
            repair_pending: matches!(self.pending, Some(Pending::Repair { .. })),
            output_ready: self.pending_output().is_some(),
            feedback: self.feedback.map(|feedback| feedback.id),
            terminal: self.terminal,
        }
    }
}

#[cfg(test)]
#[path = "sender_tests.rs"]
mod tests;
