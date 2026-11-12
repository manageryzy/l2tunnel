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
    /// A bounded known-column scan/serialization job freezes new decode admission.
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
    prefix: u32,
    end: u32,
    rank: usize,
    cursor: u32,
    known: u32,
    value: Option<Feedback>,
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
}
impl Receiver {
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
    /// No input queue is hidden: a decode/feedback-scan job returns Busy unchanged.
    pub fn receive_wire(&mut self, bytes: &[u8], now: Tick) -> Result<Begin, Error> {
        self.time(now)?;
        if self.scan.is_some() {
            return Err(Error::Busy);
        }
        let result = match wire::inspect(self.policy.recovery, bytes)? {
            wire::View::Source {
                scope,
                id,
                original,
            } => self.decoder.begin_source(scope, id, original, now)?,
            wire::View::Repair(value) => self.decoder.begin_repair(value, now)?,
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
            let status = self.decoder.status();
            self.scan = Some(Scan {
                prefix: status.decoded_prefix,
                end: status.observed_end,
                rank: status.rank,
                cursor: status.decoded_prefix,
                known: 0,
                value: None,
                copied: 0,
            });
            self.events = 0;
            self.due = None;
            self.output_end = Some(end);
        }
        while self.scan.is_some() && spend(&mut budget.metadata) {
            let scan = self.scan.as_mut().ok_or(Error::Busy)?;
            if scan.cursor < scan.end {
                if self.decoder.committed_known(SourceId(scan.cursor)) {
                    scan.known += 1;
                }
                scan.cursor += 1;
                continue;
            }
            let value = *scan.value.get_or_insert_with(|| Feedback {
                scope: self.scope,
                id: FeedbackId(self.next_feedback),
                prefix: scan.prefix,
                observed_end: scan.end,
                deficit: (scan.end - scan.prefix - scan.known).saturating_sub(scan.rank as u32),
            });
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
    /// Confirm an exact upper handoff. A feedback scan freezes its committed snapshot.
    pub fn confirm_handoff(&mut self, id: SourceId, now: Tick) -> Result<(), Error> {
        self.time(now)?;
        if self.scan.is_some() {
            return Err(Error::Busy);
        }
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
