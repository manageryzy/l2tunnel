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
    /// Decoder abandonment counters (abandoned, dropped repairs and rows,
    /// late originals).
    pub abandon: rolling::AbandonStatus,
    /// Abandoned sources by the trigger that fired.
    pub abandoned_by: AbandonReasons,
    /// Oldest current hole and how long it has been missing, in ticks.
    pub hole: Option<(SourceId, u64)>,
    /// Repairs covering the current hole since it became the oldest.
    pub covering_repairs: u64,
    /// Receipts repeated after input went quiet.
    pub receipt_repeats: u64,
}
/// Abandonment trigger counts (`docs/modules/research-recursive.md`).
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct AbandonReasons {
    /// No repair the sender can still send includes the hole.
    pub definite: u64,
    /// The deficit cannot close within `abandon_ticks` at the measured rate.
    pub projected: u64,
    /// The hole was missing for `abandon_ticks`.
    pub cap: u64,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Trigger {
    Definite,
    Projected,
    Cap,
}
/// The oldest missing source and its evidence.
#[derive(Clone, Copy)]
struct Hole {
    id: u32,
    // First time any source of this cohort was seen missing. Every source
    // below `cohort_end` was already observed missing then, so a later hole
    // in the cohort is at least this old (a conservative age).
    since: Tick,
    cohort_end: u32,
    // Covering-repair rate window, restarted for each new oldest hole.
    rate_since: Tick,
    covering: u64,
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
    hole: Option<Hole>,
    // Greatest received recursive span start, only for a recursive profile
    // with taps and no fresh slots: no later repair includes a lower source.
    recursive_floor: Option<u32>,
    abandoned_by: AbandonReasons,
    // Receipt repeat after input goes quiet (owner decision 2026-11-24): a
    // lost final receipt would otherwise leave a window-blocked sender with no
    // packet to trigger another one.
    repeat_at: Option<Tick>,
    trailing_at: Option<Tick>,
    repeat_step: u8,
    receipt_repeats: u64,
    last_receipt: Option<(u32, u32)>,
}
/// Repeats after the last receipt while input stays quiet. Intervals double
/// from 4x `feedback_ticks` up to 64x: about 0.4 s in all at the plans' 1 ms,
/// and all nine receipts lost at 15% loss has probability about 4e-8.
const RECEIPT_REPEATS: u8 = 8;
const MAX_REPEAT_SHIFT: u8 = 4;
impl Receiver {
    #[cfg(test)]
    pub(super) fn config_for_test(&self) -> Config {
        self.config
    }
    /// Conservative complete owner size; caller buffers and allocator metadata are excluded.
    pub fn memory_bound(config: Config) -> Result<usize, Error> {
        config.validate()?;
        add(
            rolling::Decoder::sliding_memory_bound(config.recovery)?,
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
            // Per-source debt (`lifetimes::Sliding`); see the research design's
            // hole-abandonment section.
            decoder: rolling::Decoder::new_sliding(config.recovery, scope, now)?,
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
            hole: None,
            recursive_floor: None,
            abandoned_by: AbandonReasons::default(),
            repeat_at: None,
            trailing_at: None,
            repeat_step: 0,
            receipt_repeats: 0,
            last_receipt: None,
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
        } else if self
            .decoder
            .feedback_state()
            .is_ok_and(|(prefix, end, _)| self.last_receipt != Some((prefix, end)))
        {
            // Rate-limited new information: report it at the window's end
            // instead of dropping it, or the last change in a window (such as
            // an abandonment) would wait for the next input. Duplicates still
            // generate nothing.
            self.trailing_at = self.next_report_at;
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
        // Fresh input restarts the receipt-repeat sequence.
        self.repeat_step = 0;
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
        if let wire::View::Repair(value) = view {
            let support = value.equation.support;
            if outcome == Begin::Staged
                && let Some(hole) = &mut self.hole
                && support.start <= hole.id
                && hole.id < support.end
            {
                hole.covering += 1;
            }
            if matches!(
                self.config.profile,
                Profile::Recursive { taps, fresh_interval: 0, .. } if taps != 0
            ) {
                self.recursive_floor = Some(
                    self.recursive_floor
                        .map_or(support.start, |old| old.max(support.start)),
                );
            }
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
        work.metadata += self.abandon_holes(now, budget.metadata.saturating_sub(work.metadata))?;
        let trailing = self.trailing_at.is_some_and(|at| now >= at);
        let repeat = self.repeat_at.is_some_and(|at| now >= at);
        if self.feedback.is_none() && self.event.is_none() && (trailing || repeat) {
            let end = deadline(now, self.config.recovery.job_ticks)
                .map(|end| self.retained_cap.map_or(end, |cap| end.min(cap)))
                .or_else(|error| self.fail(error))?;
            self.event = Some(now);
            self.event_end = Some(end);
            if !trailing {
                self.repeat_at = None;
                self.repeat_step = self.repeat_step.saturating_add(1);
                self.receipt_repeats += 1;
            }
        }
        if self.event.is_some() {
            self.trailing_at = None;
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
            // A receipt with new information (for example after an
            // abandonment) restarts the repeat sequence.
            if self.last_receipt != Some((prefix, observed_end)) {
                self.repeat_step = 0;
                self.last_receipt = Some((prefix, observed_end));
            }
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
    /// Refresh the oldest-hole record from committed decoder state.
    fn track_hole(&mut self, now: Tick) -> Result<(), Error> {
        let current = self.decoder.hole().or_else(|error| self.fail(error))?;
        self.hole = match (current, self.hole) {
            (None, _) => None,
            (Some(id), Some(hole)) if hole.id == id => Some(hole),
            (Some(id), previous) => {
                let (since, cohort_end) = match previous {
                    Some(hole) if id < hole.cohort_end => (hole.since, hole.cohort_end),
                    _ => (now, self.decoder.status().observed_end),
                };
                Some(Hole {
                    id,
                    since,
                    cohort_end,
                    rate_since: now,
                    covering: 0,
                })
            }
        };
        Ok(())
    }

    /// First abandonment trigger that holds for the current hole.
    fn trigger(&self, now: Tick) -> Result<Option<Trigger>, Error> {
        let limit = self.config.abandon_ticks;
        let Some(hole) = self.hole else {
            return Ok(None);
        };
        if limit == 0 {
            return Ok(None);
        }
        if self.recursive_floor.is_some_and(|start| start > hole.id) {
            return Ok(Some(Trigger::Definite));
        }
        let age = now.0.saturating_sub(hole.since.0);
        if age >= limit {
            return Ok(Some(Trigger::Cap));
        }
        let elapsed = now.0.saturating_sub(hole.rate_since.0);
        if hole.covering > 0 && elapsed > 0 {
            // age + deficit / rate >= limit, with rate = covering / elapsed.
            let (_, _, deficit) = self.decoder.feedback_state()?;
            let covering = u128::from(hole.covering);
            if u128::from(age) * covering + u128::from(deficit) * u128::from(elapsed)
                >= u128::from(limit) * covering
            {
                return Ok(Some(Trigger::Projected));
            }
        }
        Ok(None)
    }

    /// Abandon oldest holes while a trigger holds, at most one per metadata
    /// unit. Each abandonment is one bounded decoder transaction (at most `W`
    /// slot visits) and schedules a receipt so the sender learns the new prefix.
    fn abandon_holes(&mut self, now: Tick, budget: usize) -> Result<usize, Error> {
        if self.config.abandon_ticks == 0 || self.decoder.status().pending_job {
            return Ok(0);
        }
        self.track_hole(now)?;
        let mut used = 0;
        while used < budget {
            let Some(trigger) = self.trigger(now).or_else(|error| self.fail(error))? else {
                break;
            };
            match self.decoder.abandon_prefix(now) {
                Ok(Some(_)) => {}
                Ok(None) | Err(Error::Busy) => break,
                Err(error) => return self.fail(error),
            }
            match trigger {
                Trigger::Definite => self.abandoned_by.definite += 1,
                Trigger::Projected => self.abandoned_by.projected += 1,
                Trigger::Cap => self.abandoned_by.cap += 1,
            }
            used += 1;
            self.track_hole(now)?;
        }
        if used > 0 {
            let feedback_end = deadline(now, self.config.recovery.job_ticks)
                .map(|end| self.retained_cap.map_or(end, |cap| end.min(cap)))
                .or_else(|error| self.fail(error))?;
            self.notice(
                InputTiming {
                    received: now,
                    feedback_end,
                },
                now,
            );
        }
        Ok(used)
    }

    /// Soft service time at which the current hole reaches `abandon_ticks`.
    /// Not an expiry: reaching it only abandons the hole.
    pub fn abandon_wake(&self) -> Option<Tick> {
        if self.config.abandon_ticks == 0 {
            return None;
        }
        let hole = self.hole?;
        Some(Tick(hole.since.0.saturating_add(self.config.abandon_ticks)))
    }

    /// Whether a step at `now` would abandon a hole.
    pub fn abandon_due(&self, now: Tick) -> bool {
        !self.decoder.status().pending_job && self.trigger(now).ok().flatten().is_some()
    }

    /// Soft service times that are not expiries: hole abandonment, a
    /// rate-limited receipt and the next receipt repeat.
    pub fn service_wake(&self) -> Option<Tick> {
        self.abandon_wake()
            .into_iter()
            .chain(self.trailing_at)
            .chain(self.repeat_at)
            .min()
    }

    /// Whether a step at `now` would abandon a hole or repeat a receipt.
    pub fn service_due(&self, now: Tick) -> bool {
        self.abandon_due(now)
            || (self.feedback.is_none()
                && self.event.is_none()
                && self
                    .trailing_at
                    .into_iter()
                    .chain(self.repeat_at)
                    .any(|at| now >= at))
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
        self.repeat_at = if self.repeat_step < RECEIPT_REPEATS {
            let ticks = self
                .config
                .feedback_ticks
                .checked_mul(4 << self.repeat_step.min(MAX_REPEAT_SHIFT))
                .ok_or(Error::Exhausted)
                .or_else(|error| self.fail(error))?;
            Some(deadline(now, ticks).or_else(|error| self.fail(error))?)
        } else {
            None
        };
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
            abandon: self.decoder.abandon_status(),
            abandoned_by: self.abandoned_by,
            hole: self
                .hole
                .map(|hole| (SourceId(hole.id), self.last.0.saturating_sub(hole.since.0))),
            covering_repairs: self.hole.map_or(0, |hole| hole.covering),
            receipt_repeats: self.receipt_repeats,
        }
    }
}

#[cfg(test)]
#[path = "receiver_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "abandon_tests.rs"]
mod abandon_tests;
