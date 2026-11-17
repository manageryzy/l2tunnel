use super::*;

/// One bounded decoder service result and feedback-custody observation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReceiverStep {
    /// Decoder result; Capacity leaves the committed algebra unchanged.
    pub decode: DecodeStep,
    /// Combined work including a possible constant-size feedback snapshot.
    pub work: WorkUsed,
    /// One immutable receipt is waiting for reverse ownership confirmation.
    pub feedback_ready: bool,
}
/// Committed receive state and bounded feedback ownership.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReceiverStatus {
    /// Existing committed decoder state; no candidate rows escape.
    pub decoder: rolling::DecoderStatus,
    /// Snapshot currently owned by this receiver.
    pub feedback: Option<Feedback>,
    /// First qualifying packet event waiting for feedback capacity.
    pub feedback_event: Option<Tick>,
    /// Terminal wrapper error, if any.
    pub terminal: Option<Error>,
}
#[derive(Clone, Copy)]
struct InputTiming {
    received: Tick,
    feedback_end: Tick,
}
/// Real received-byte decoder with packet-triggered cumulative prefix feedback.
pub struct Receiver {
    config: Config,
    scope: Scope,
    decoder: rolling::Decoder,
    feedback: Option<Feedback>,
    output_end: Option<Tick>,
    event: Option<Tick>,
    event_end: Option<Tick>,
    staged: Option<InputTiming>,
    retained_cap: Option<Tick>,
    next_report_at: Option<Tick>,
    next_feedback: u64,
    last: Tick,
    terminal: Option<Error>,
    expiry_failure: Option<rolling::expiry::Failure>,
}
impl Receiver {
    #[cfg(test)]
    pub(super) fn config_for_test(&self) -> Config {
        self.config
    }
    /// Conservative complete owner size; caller buffers and allocator metadata are excluded.
    pub fn memory_bound(config: Config) -> Result<usize, Error> {
        config.validate()?;
        add(
            rolling::Decoder::memory_bound(config.recovery)?,
            std::mem::size_of::<Self>(),
        )
    }
    /// Construct every decoder bank and history before processing any packet.
    pub fn new(config: Config, scope: Scope, now: Tick) -> Result<Self, Error> {
        if Self::memory_bound(config)? > config.memory_bytes {
            return Err(Error::Capacity);
        }
        deadline(now, config.feedback_ticks)?;
        Ok(Self {
            config,
            scope,
            decoder: rolling::Decoder::new(config.recovery, scope, now)?,
            feedback: None,
            output_end: None,
            event: None,
            event_end: None,
            staged: None,
            retained_cap: None,
            next_report_at: None,
            next_feedback: 1,
            last: now,
            terminal: None,
            expiry_failure: None,
        })
    }
    /// Pre-admit all actual nested heap capacities before constructing this owner.
    pub fn new_reserved(
        config: Config,
        scope: Scope,
        now: Tick,
        limits: storage::Limits,
    ) -> Result<Self, storage::Error> {
        let plan = storage::Plan::for_receiver(config)?;
        plan.admit(limits, now)?;
        let value = Self::new(config, scope, now)?;
        plan.verify(value.storage_usage()?, limits)?;
        Ok(value)
    }
    /// Actual retained vector capacities, including idle decoder buffers.
    pub fn storage_usage(&self) -> Result<storage::Usage, storage::Error> {
        self.decoder.storage_usage()
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
            &[self.output_end, self.event_end, self.retained_cap],
        ) {
            if error == Error::Expired {
                self.expiry_failure = self
                    .expiry_failure
                    .or_else(|| self.expiry_snapshot().first_expired(now, &[3, 4, 5]));
            }
            return self.fail(error);
        }
        if let Err(error) = self.decoder.step(now, WorkBudget::default()) {
            return self.fail(error);
        }
        self.last = now;
        Ok(())
    }
    fn decoder_result<T>(&mut self, result: Result<T, Error>) -> Result<T, Error> {
        match result {
            Err(error) if self.decoder.status().terminal.is_some() => self.fail(error),
            other => other,
        }
    }
    fn notice(&mut self, timing: InputTiming, now: Tick) {
        if self.next_report_at.is_none_or(|due| now >= due) {
            if self.event.is_none() {
                self.event = Some(timing.received);
                self.event_end = Some(timing.feedback_end);
            } else if let Some(end) = self.event_end {
                self.event_end = Some(end.min(timing.feedback_end));
            }
        }
    }
    fn release_idle_cap(&mut self) {
        let state = self.decoder.status();
        if !state.pending_job
            && state.handoff_prefix == state.observed_end
            && self.feedback.is_none()
            && self.event.is_none()
            && self.staged.is_none()
        {
            self.retained_cap = None;
        }
    }
    /// Admit one complete authenticated record with no hidden ingress queue.
    pub fn receive_wire(&mut self, bytes: &[u8], now: Tick) -> Result<Begin, Error> {
        self.receive_wire_at(bytes, now, now, Tick(u64::MAX))
    }
    /// Preserve original authenticated arrival and a caller operation/session cap.
    /// Busy never owns the caller's bytes; retry with the same original times.
    /// Feedback inherits the original arrival plus job age, clamped to `cap`.
    /// The earliest finite admitted cap conservatively bounds all owned recovery,
    /// upper handoff, feedback and event state until every observed source is
    /// handed off and all jobs/events/feedback are discharged. Only then may a
    /// later independent operation supply a new cap. Idle time does not renew it.
    pub fn receive_wire_at(
        &mut self,
        bytes: &[u8],
        received: Tick,
        now: Tick,
        cap: Tick,
    ) -> Result<Begin, Error> {
        let view = wire::inspect(self.config, bytes)?;
        self.receive_view_at(view, received, now, cap)
    }

    /// Admit a typed selected body while retaining the same causal input and cap.
    pub fn receive_view_at(
        &mut self,
        view: wire::View<'_>,
        received: Tick,
        now: Tick,
        cap: Tick,
    ) -> Result<Begin, Error> {
        match view {
            wire::View::Source { original, .. } => {
                wire::source_len(self.config, original.len())?;
            }
            wire::View::Repair(value) => value.validate(self.config)?,
            wire::View::Feedback(_) => return Err(Error::Format),
        }
        let incoming = match view {
            wire::View::Source { scope, .. } => scope,
            wire::View::Repair(value) => value.equation.scope,
            wire::View::Feedback(_) => return Err(Error::Format),
        };
        if incoming != self.scope {
            return Err(Error::Scope);
        }
        self.time(now)?;
        let outcome = match view {
            wire::View::Source {
                scope,
                id,
                original,
            } => self
                .decoder
                .begin_source_until(scope, id, original, received, now, cap),
            wire::View::Repair(value) => self.decoder.begin_equation_until(
                value.equation,
                self.config.profile,
                value.confirmed,
                received,
                now,
                cap,
            ),
            wire::View::Feedback(_) => return Err(Error::Format),
        };
        let outcome = self.decoder_result(outcome)?;
        let feedback_end = deadline(received, self.config.recovery.job_ticks)
            .map(|end| end.min(cap))
            .or_else(|error| self.fail(error))?;
        if now >= feedback_end {
            self.expiry_failure.get_or_insert(rolling::expiry::Failure {
                observed: now,
                selected: rolling::expiry::Deadline::new(
                    rolling::expiry::Kind::FeedbackEvent,
                    feedback_end,
                    None,
                ),
            });
            return self.fail(Error::Expired);
        }
        if cap != Tick(u64::MAX) {
            self.retained_cap = Some(self.retained_cap.map_or(cap, |old| old.min(cap)));
        }
        let timing = InputTiming {
            received,
            feedback_end,
        };
        if outcome == Begin::Staged {
            self.staged = Some(timing);
        } else {
            self.notice(timing, now);
        }
        self.release_idle_cap();
        Ok(outcome)
    }
    /// Advance existing bounded GF work and, if affordable, freeze a committed receipt.
    pub fn step(&mut self, now: Tick, budget: WorkBudget) -> Result<ReceiverStep, Error> {
        self.time(now)?;
        let result = self.decoder.step(now, budget);
        let decode = self.decoder_result(result)?;
        let mut work = match decode {
            DecodeStep::Idle(w)
            | DecodeStep::Pending(w)
            | DecodeStep::Capacity(w)
            | DecodeStep::Accepted { work: w, .. } => w,
        };
        if matches!(decode, DecodeStep::Accepted { .. }) {
            if let Some(timing) = self.staged.take() {
                self.notice(timing, now);
            }
        } else if matches!(decode, DecodeStep::Capacity(_)) {
            self.staged = None;
        }
        if self.feedback.is_none()
            && !self.decoder.status().pending_job
            && work.metadata < budget.metadata
            && let Some(end) = self.event_end
        {
            if self.next_feedback == u64::MAX {
                return self.fail(Error::Exhausted);
            }
            let (prefix, observed_end, _) = self
                .decoder
                .feedback_state()
                .or_else(|error| self.fail(error))?;
            let due =
                deadline(now, self.config.feedback_ticks).or_else(|error| self.fail(error))?;
            self.feedback = Some(Feedback {
                scope: self.scope,
                id: FeedbackId(self.next_feedback),
                prefix,
                observed_end,
            });
            self.output_end = Some(end);
            self.next_report_at = Some(due);
            self.event = None;
            self.event_end = None;
            work.metadata += 1;
        }
        self.release_idle_cap();
        Ok(ReceiverStep {
            decode,
            work,
            feedback_ready: self.feedback.is_some(),
        })
    }
    /// Exact contiguous original bytes waiting for upper recovery handoff.
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
    /// Borrow one actual committed source for bounded record preview without consuming handoff.
    pub fn decoded_source(&self, id: SourceId) -> Result<Option<&[u8]>, Error> {
        if self.terminal.is_some() {
            return Err(Error::Terminal);
        }
        self.decoder.decoded_source(id)
    }
    /// Confirm only the current contiguous recovery handoff; no native receipt is implied.
    pub fn confirm_handoff(&mut self, id: SourceId, now: Tick) -> Result<(), Error> {
        self.time(now)?;
        let result = self.decoder.confirm_handoff(id, now);
        self.decoder_result(result)?;
        self.release_idle_cap();
        Ok(())
    }
    /// Borrow immutable cumulative feedback without consuming its identity.
    pub fn pending_feedback(&self) -> Option<Feedback> {
        if self.terminal.is_some() {
            None
        } else {
            self.feedback
        }
    }
    /// Serialize at most eighty bytes to caller storage; an error changes neither owner nor output.
    pub fn encode_feedback(&self, output: &mut [u8]) -> Result<usize, Error> {
        wire::encode_feedback(
            self.config,
            self.pending_feedback().ok_or(Error::Busy)?,
            output,
        )
    }
    /// Confirm complete reverse carrier ownership. A lost packet requires a later packet event.
    pub fn confirm_feedback(&mut self, id: FeedbackId, now: Tick) -> Result<(), Error> {
        self.time(now)?;
        if self.feedback.ok_or(Error::Busy)?.id != id {
            return Err(Error::Identity);
        }
        self.feedback = None;
        self.output_end = None;
        self.next_feedback += 1;
        self.release_idle_cap();
        Ok(())
    }
    /// Read original outer and nested lifetimes without advancing service.
    pub fn expiry_snapshot(&self) -> rolling::expiry::Snapshot {
        use rolling::expiry::{Deadline, Identity, Kind};
        let mut snapshot = self.decoder.expiry_snapshot();
        let identity = self.feedback.map(|f| Identity::Feedback(f.id.0));
        snapshot.candidates[3] = self
            .output_end
            .map(|at| Deadline::new(Kind::FeedbackOutput, at, identity));
        snapshot.candidates[4] = self
            .event_end
            .map(|at| Deadline::new(Kind::FeedbackEvent, at, None));
        snapshot.candidates[5] = self
            .retained_cap
            .map(|at| Deadline::new(Kind::RetainedInput, at, None));
        snapshot.last_successful = self.last;
        snapshot.terminal = self.terminal.or(snapshot.terminal);
        snapshot.failure = self.expiry_failure.or(snapshot.failure);
        snapshot
    }
    /// Earliest original decoder, feedback output, or deferred-event expiry.
    pub fn deadline(&self) -> Option<Tick> {
        self.decoder
            .deadline()
            .into_iter()
            .chain(self.output_end)
            .chain(self.event_end)
            .chain(self.retained_cap)
            .min()
    }
    /// Current committed state; it never reveals a speculative equation transaction.
    pub fn status(&self) -> ReceiverStatus {
        ReceiverStatus {
            decoder: self.decoder.status(),
            feedback: self.pending_feedback(),
            feedback_event: self.event,
            terminal: self.terminal,
        }
    }
}

#[cfg(test)]
#[path = "receiver_tests.rs"]
mod tests;
