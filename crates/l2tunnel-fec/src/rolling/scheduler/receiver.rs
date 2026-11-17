use super::*;

/// One bounded receive-service result; work includes decoding and feedback construction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReceiverStep {
    /// Actual combined work, at most the caller's budget in every component.
    pub work: WorkUsed,
    /// Underlying atomic decoder result, including explicit equation-capacity rejection.
    pub decode: DecodeStep,
    /// One immutable structural receipt is ready for reverse caller handoff.
    pub feedback_ready: bool,
}
/// Current receiver ownership; no native delivery is inferred.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReceiverStatus {
    /// Actual committed decoder state.
    pub decoder: DecoderStatus,
    /// One immutable committed snapshot is undergoing bounded serialization.
    pub feedback_building: bool,
    /// One immutable receipt is waiting for caller handoff.
    pub feedback_ready: bool,
    /// Unreported receive events, saturated at the configured threshold.
    pub feedback_events: u32,
    /// Original first-event feedback trigger; later events do not postpone it.
    pub feedback_due: Option<Tick>,
    /// Original wrapper failure, if any.
    pub terminal: Option<Error>,
}
struct Scan {
    value: Feedback,
    copied: usize,
}
/// One pure receiver with an actual decoder and one bounded identified feedback output.
pub struct Receiver {
    policy: Policy,
    scope: Scope,
    decoder: Decoder,
    events: u32,
    due: Option<Tick>,
    scan: Option<Scan>,
    feedback: Option<Feedback>,
    wire: [u8; FEEDBACK_BYTES],
    output_end: Option<Tick>,
    next_feedback: u64,
    last: Tick,
    terminal: Option<Error>,
    expiry_failure: Option<expiry::Failure>,
}
impl Receiver {
    /// Admit every exact decoder bank, decision pool and scratch allocation first.
    /// Existing conservative policy/config caps and all original time checks remain.
    pub fn new_reserved(
        policy: Policy,
        scope: Scope,
        now: Tick,
        limits: storage::Limits,
    ) -> Result<Self, storage::Error> {
        let plan = storage::Plan::for_receiver(policy)?;
        plan.admit(limits, now)?;
        let value = Self::new(policy, scope, now)?;
        plan.verify(value.storage_usage()?, limits)?;
        Ok(value)
    }

    /// Observe every actual retained nested capacity, excluding the inline header.
    /// The same observation works with the unchanged compatibility constructor.
    pub fn storage_usage(&self) -> Result<storage::Usage, storage::Error> {
        self.decoder.storage_usage()
    }

    /// Conservative total reservation, excluding caller buffers/allocator overhead.
    pub fn memory_bound(policy: Policy) -> Result<usize, Error> {
        policy.validate()?;
        add(
            Decoder::memory_bound(policy.recovery)?,
            std::mem::size_of::<Self>(),
        )
    }
    /// Allocate all decoder storage before accepting peer packets.
    pub fn new(policy: Policy, scope: Scope, now: Tick) -> Result<Self, Error> {
        if Self::memory_bound(policy)? > policy.memory_bytes {
            return Err(Error::Capacity);
        }
        deadline(now, policy.feedback_ticks)?;
        Ok(Self {
            decoder: Decoder::new(policy.recovery, scope, now)?,
            policy,
            scope,
            events: 0,
            due: None,
            scan: None,
            feedback: None,
            wire: [0; FEEDBACK_BYTES],
            output_end: None,
            next_feedback: 1,
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
        if let Err(error) = check_time(self.last, now, &[self.output_end]) {
            if error == Error::Expired {
                self.expiry_failure = self
                    .expiry_failure
                    .or_else(|| self.expiry_snapshot().first_expired(now, &[3]));
            }
            return self.fail(error);
        }
        if let Err(error) = self.decoder.step(now, WorkBudget::default()) {
            return self.fail(error);
        }
        self.last = now;
        Ok(())
    }
    fn notice(&mut self, now: Tick) -> Result<(), Error> {
        if self.due.is_none() {
            self.due = Some(deadline(now, self.policy.feedback_ticks).or_else(|e| self.fail(e))?);
        }
        self.events = (self.events + 1).min(self.policy.feedback_packets);
        Ok(())
    }
    /// Stage one complete caller-authenticated source/repair record through the existing codec.
    /// No input queue is hidden: an actual pending decode job returns Busy unchanged.
    /// An immutable feedback snapshot does not prevent new decode admission.
    pub fn receive_wire(&mut self, bytes: &[u8], now: Tick) -> Result<Begin, Error> {
        self.receive_wire_at(bytes, now, now)
    }
    /// Stage already authenticated bytes without renewing their original age.
    pub fn receive_wire_at(
        &mut self,
        bytes: &[u8],
        received: Tick,
        observed: Tick,
    ) -> Result<Begin, Error> {
        self.receive_wire_until(bytes, received, observed, Tick(u64::MAX))
    }
    /// Preserve original arrival and the existing caller operation/session cap.
    pub fn receive_wire_until(
        &mut self,
        bytes: &[u8],
        received: Tick,
        now: Tick,
        original_deadline: Tick,
    ) -> Result<Begin, Error> {
        self.time(now)?;
        let view = wire::inspect_with(self.policy.recovery, self.policy.source_wire, bytes)?;
        self.receive_view_until(view, received, now, original_deadline)
    }

    /// Admit a typed selected data body through the same decoder and original cap.
    pub fn receive_view_until(
        &mut self,
        view: wire::View<'_>,
        received: Tick,
        now: Tick,
        original_deadline: Tick,
    ) -> Result<Begin, Error> {
        self.time(now)?;
        let result = match view {
            wire::View::Source {
                scope,
                id,
                original,
            } => self.decoder.begin_source_until(
                scope,
                id,
                original,
                received,
                now,
                original_deadline,
            )?,
            wire::View::Repair(value) => {
                self.decoder
                    .begin_repair_until(value, received, now, original_deadline)?
            }
        };
        if result != Begin::Staged {
            self.notice(now)?;
        }
        Ok(result)
    }
    /// Advance actual decode and feedback work under shared per-component caps.
    /// All-zero work validates original time bounds but starts/advances no job.
    pub fn step(&mut self, now: Tick, mut budget: WorkBudget) -> Result<ReceiverStep, Error> {
        budget.validate()?;
        self.time(now)?;
        let before = budget;
        let old_prefix = self.decoder.status().decoded_prefix;
        let decode = self.decoder.step(now, budget)?;
        let consumed = match decode {
            DecodeStep::Idle(work)
            | DecodeStep::Pending(work)
            | DecodeStep::Capacity(work)
            | DecodeStep::Accepted { work, .. } => work,
        };
        budget = remaining(budget, consumed);
        if matches!(
            decode,
            DecodeStep::Accepted { .. } | DecodeStep::Capacity(_)
        ) || old_prefix != self.decoder.status().decoded_prefix
        {
            self.notice(now)?;
        }
        if self.scan.is_none()
            && self.feedback.is_none()
            && !self.decoder.status().pending_job
            && (self.events >= self.policy.feedback_packets
                || self.due.is_some_and(|due| now >= due))
            && spend(&mut budget.metadata)
        {
            if self.next_feedback == u64::MAX {
                return self.fail(Error::Exhausted);
            }
            let end = deadline(now, self.policy.recovery.job_ticks).or_else(|e| self.fail(e))?;
            let (prefix, observed_end, deficit) = self.decoder.feedback_state()?;
            self.scan = Some(Scan {
                value: Feedback {
                    scope: self.scope,
                    id: FeedbackId(self.next_feedback),
                    prefix,
                    observed_end,
                    deficit,
                },
                copied: 0,
            });
            self.events = 0;
            self.due = None;
            self.output_end = Some(end);
        }
        while self.scan.is_some() && spend(&mut budget.metadata) {
            let scan = self.scan.as_mut().ok_or(Error::Busy)?;
            let value = scan.value;
            if scan.copied < FEEDBACK_BYTES {
                if !spend(&mut budget.copies) {
                    break;
                }
                self.wire[scan.copied] = value.byte(scan.copied);
                scan.copied += 1;
            } else {
                self.feedback = Some(value);
                self.scan = None;
            }
        }
        Ok(ReceiverStep {
            work: used(before, budget),
            decode,
            feedback_ready: self.feedback.is_some(),
        })
    }
    /// Borrow actual decoded bytes awaiting upper recovery handoff, not native delivery.
    pub fn pending_source(&self) -> Option<(SourceId, &[u8])> {
        if self.terminal.is_some() {
            None
        } else {
            self.decoder.pending_source()
        }
    }
    /// Original ordered-handoff cohort cap of the actual nested decoder.
    pub fn handoff_deadline(&self) -> Option<Tick> {
        self.decoder.handoff_deadline()
    }
    /// Original cap of an actual ready immutable feedback output, if present.
    pub fn feedback_deadline(&self) -> Option<Tick> {
        self.feedback.and(self.output_end)
    }
    /// Borrow a committed original without recovery/native receipt authority.
    /// Decoder candidate/shadow storage and retired handoffs remain hidden.
    pub fn decoded_source(&self, id: SourceId) -> Result<Option<&[u8]>, Error> {
        if self.terminal.is_some() {
            return Err(Error::Terminal);
        }
        self.decoder.decoded_source(id)
    }
    /// Confirm an exact upper handoff without changing an existing feedback snapshot.
    pub fn confirm_handoff(&mut self, id: SourceId, now: Tick) -> Result<(), Error> {
        self.time(now)?;
        let before = self.decoder.status().decoded_prefix;
        self.decoder.confirm_handoff(id, now)?;
        if self.decoder.status().decoded_prefix != before {
            self.notice(now)?;
        }
        Ok(())
    }
    /// Inspect one immutable complete feedback descriptor; polls never consume an identity.
    pub fn pending_feedback(&self) -> Option<Feedback> {
        if self.terminal.is_some() {
            None
        } else {
            self.feedback
        }
    }
    /// Borrow the exact immutable structural wire bytes, without granting authentication.
    pub fn pending_feedback_wire(&self) -> Option<&[u8]> {
        self.pending_feedback().map(|_| self.wire.as_slice())
    }
    /// Confirm complete reverse carrier ownership. Loss afterward requires a fresh receipt event.
    pub fn confirm_feedback(&mut self, id: FeedbackId, now: Tick) -> Result<(), Error> {
        self.time(now)?;
        if self.feedback.ok_or(Error::Busy)?.id != id {
            return Err(Error::Identity);
        }
        self.feedback = None;
        self.output_end = None;
        self.next_feedback += 1;
        Ok(())
    }
    /// Read original outer and nested lifetimes without advancing service.
    pub fn expiry_snapshot(&self) -> expiry::Snapshot {
        use expiry::{Deadline, Identity, Kind};
        let mut snapshot = self.decoder.expiry_snapshot();
        let identity = self
            .feedback
            .map(|f| f.id.0)
            .or_else(|| self.scan.as_ref().map(|scan| scan.value.id.0))
            .map(Identity::Feedback);
        snapshot.candidates[3] = self
            .output_end
            .map(|at| Deadline::new(Kind::FeedbackOutput, at, identity));
        snapshot.last_successful = self.last;
        snapshot.terminal = self.terminal.or(snapshot.terminal);
        snapshot.failure = self.expiry_failure.or(snapshot.failure);
        snapshot
    }
    /// Earliest original decode/debt/handoff or feedback-output expiry.
    pub fn deadline(&self) -> Option<Tick> {
        self.decoder
            .deadline()
            .into_iter()
            .chain(self.output_end)
            .min()
    }
    /// Earliest hard expiry or first-event trigger; ready work remains explicit in status.
    pub fn wake_at(&self) -> Option<Tick> {
        self.deadline().into_iter().chain(self.due).min()
    }
    /// Constant-size current ownership snapshot, without a scan or new measurement.
    pub fn status(&self) -> ReceiverStatus {
        ReceiverStatus {
            decoder: self.decoder.status(),
            feedback_building: self.scan.is_some(),
            feedback_ready: self.pending_feedback().is_some(),
            feedback_events: self.events,
            feedback_due: self.due,
            terminal: self.terminal,
        }
    }
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod feedback_tests;
