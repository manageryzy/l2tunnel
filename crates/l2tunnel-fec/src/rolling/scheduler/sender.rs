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
    /// Exclusive source prefix fully handed off by this scheduler's caller.
    pub sent_sources: u32,
    /// Residual exact numerator units, always below the denominator.
    pub repair_credit: u32,
    /// Regular earned repairs waiting for service, at most one.
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
#[derive(Clone, Copy)]
enum Pending {
    Source(SourceId),
    Repair { id: RepairId, tail: bool },
}
/// One pure sender: a real encoder, exact repair credit and one immutable output.
pub struct Sender {
    policy: Policy,
    scope: Scope,
    encoder: Encoder,
    pending: Option<Pending>,
    output_end: Option<Tick>,
    sent: u32,
    credit: u32,
    regular_due: u32,
    tail_remaining: u32,
    tail_due: Option<Tick>,
    feedback: Option<Feedback>,
    last: Tick,
    terminal: Option<Error>,
}
impl Sender {
    /// Conservative total retained reservation, excluding caller buffers/allocator overhead.
    pub fn memory_bound(policy: Policy) -> Result<usize, Error> {
        policy.validate()?;
        add(
            Encoder::memory_bound(policy.recovery)?,
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
            encoder: Encoder::new(policy.recovery, scope, now)?,
            policy,
            scope,
            pending: None,
            output_end: None,
            sent: 0,
            credit: 0,
            regular_due: 0,
            tail_remaining: 0,
            tail_due: None,
            feedback: None,
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
        if let Err(error) = check_time(self.last, now, &[self.output_end]) {
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
    /// Admit one source into the only output slot; no repair credit is earned yet.
    /// Performs only the primitive's bounded source copy; no wire buffer is allocated.
    pub fn admit_source(&mut self, original: &[u8], now: Tick) -> Result<SourceId, Error> {
        self.time(now)?;
        if self.pending.is_some()
            || self.regular_due != 0
            || self.tail_remaining != 0
            || self.tail_due.is_some_and(|due| now >= due)
        {
            return Err(Error::Busy);
        }
        let end = self.later(now, self.policy.recovery.job_ticks)?;
        let id = self.encoder.admit_source(original, now)?;
        self.pending = Some(Pending::Source(id));
        self.output_end = Some(end);
        Ok(id)
    }
    /// Advance at most one bounded repair job. All-zero work cannot start a job.
    pub fn step(&mut self, now: Tick, mut budget: WorkBudget) -> Result<WorkUsed, Error> {
        budget.validate()?;
        self.time(now)?;
        let before = budget;
        if self.pending.is_none() && spend(&mut budget.metadata) {
            let state = self.encoder.status();
            if state.confirmed_prefix == state.next_source {
                self.regular_due = 0;
                self.tail_remaining = 0;
                self.tail_due = None;
            } else {
                if self.regular_due == 0
                    && self.tail_remaining == 0
                    && self.tail_due.is_some_and(|due| now >= due)
                {
                    self.tail_remaining = self.feedback.map_or(1, |f| f.deficit.max(1));
                }
                let tail = self.regular_due == 0;
                if !tail || self.tail_remaining != 0 {
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
    /// Borrow the exact current immutable complete output. Polling changes nothing.
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
            } => wire::encode_source(self.policy.recovery, scope, id, original, output),
            Output::Repair(repair) => wire::encode_repair(self.policy.recovery, repair, output),
        }
    }
    /// Confirm complete caller handoff of this identity, earning source credit or retiring repair.
    /// WouldBlock must leave this uncalled; repeated polls do not move any timer.
    pub fn confirm_output(&mut self, id: OutputId, now: Tick) -> Result<(), Error> {
        self.time(now)?;
        let output = self.pending_output().ok_or(Error::Busy)?;
        if output.id() != id {
            return Err(Error::Identity);
        }
        match self.pending.ok_or(Error::Busy)? {
            Pending::Source(source) => {
                let tail_due = self.later(now, self.policy.tail_ticks)?;
                self.sent = source.0 + 1;
                let earned = self.credit + self.policy.repair_numerator;
                self.regular_due += earned / self.policy.repair_denominator;
                self.credit = earned % self.policy.repair_denominator;
                self.tail_due = Some(tail_due);
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
        if feedback.prefix < self.encoder.status().confirmed_prefix {
            return Ok(FeedbackDisposition::Stale);
        }
        if self
            .feedback
            .is_some_and(|old| feedback.observed_end < old.observed_end)
        {
            return Err(Error::Identity);
        }
        self.encoder.confirm_prefix(feedback.prefix, now)?;
        self.feedback = Some(feedback);
        if feedback.prefix == self.encoder.status().next_source {
            self.regular_due = 0;
            self.tail_remaining = 0;
            self.tail_due = None;
        }
        Ok(FeedbackDisposition::Applied)
    }
    /// Parse structurally, then apply under the same mandatory caller authentication boundary.
    pub fn receive_feedback_wire(
        &mut self,
        bytes: &[u8],
        now: Tick,
    ) -> Result<FeedbackDisposition, Error> {
        self.receive_feedback(decode_feedback(self.policy.recovery, bytes)?, now)
    }
    /// Earliest original hard expiry; service triggers do not renew it.
    pub fn deadline(&self) -> Option<Tick> {
        self.encoder
            .deadline()
            .into_iter()
            .chain(self.output_end)
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
