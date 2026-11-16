use super::*;

#[derive(Clone, Copy)]
struct Timing {
    received: Tick,
    end: Tick,
}
#[derive(Clone, Copy)]
struct Receipt {
    id: SourceId,
    timing: Timing,
}
#[derive(Clone, Copy)]
struct Scan {
    next: u32,
    end: u32,
    timing: Timing,
}
#[derive(Clone, Copy)]
struct Snapshot {
    id: FeedbackId,
    prefix: Option<u32>,
    count: usize,
    end: Tick,
}

/// One bounded decoder service result and reverse-output custody observation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReceiverStep {
    /// Existing GF decoder result; only accepted banks expose source bytes.
    pub decode: DecodeStep,
    /// Metered GF work and per-source committed receipt scan visits.
    /// A snapshot also costs one metadata visit; its <=255-ID copy is atomic.
    pub work: WorkUsed,
    /// An immutable feedback snapshot awaits actual reverse output confirmation.
    pub feedback_ready: bool,
}
/// Receiver state without borrowing speculative matrices or exposing sender data.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReceiverStatus {
    /// Existing committed recovery and delivery state.
    pub decoder: rolling::DecoderStatus,
    /// True contiguous known prefix, independent of upper handoff capacity.
    pub receipt_prefix: u32,
    /// Selective receipt events not yet frozen into output.
    pub pending_receipts: usize,
    /// One committed-known scan must finish before accepting another input.
    pub scanning: bool,
    /// Immutable reverse output identity.
    pub feedback: Option<FeedbackId>,
    /// Latched wrapper failure.
    pub terminal: Option<Error>,
}

/// Bounded real-byte receiver with Python-style selective/cumulative feedback.
/// Duplicate systematics re-ack; duplicate/dependent repairs schedule no feedback.
pub struct Receiver {
    config: Config,
    scope: Scope,
    decoder: rolling::Decoder,
    // Committed known sources can span 2W (at most 510 IDs) while upper
    // handoff is blocked; the forward admission window remains W.
    seen: Vec<Option<SourceId>>,
    receipts: Vec<Option<Receipt>>,
    output_ids: Vec<SourceId>,
    count: usize,
    prefix: u32,
    staged: Option<Timing>,
    scan: Option<Scan>,
    snapshot: Option<Snapshot>,
    next_feedback: u64,
    retained_cap: Option<Tick>,
    last: Tick,
    terminal: Option<Error>,
}
impl Receiver {
    /// Conservative complete owner size, excluding caller buffers and allocator metadata.
    pub fn memory_bound(config: Config) -> Result<usize, Error> {
        config.validate()?;
        let extra = config.recovery.window
            * (2 * std::mem::size_of::<Option<SourceId>>()
                + std::mem::size_of::<Option<Receipt>>())
            + usize::from(config.feedback_batch) * std::mem::size_of::<SourceId>();
        add(
            add(
                rolling::Decoder::explicit_memory_bound(config.recovery)?,
                extra,
            )?,
            std::mem::size_of::<Self>(),
        )
    }
    pub(super) fn requested_storage(config: Config) -> Result<storage::Usage, storage::Error> {
        let mut value = rolling::Decoder::explicit_requested_storage(config.recovery)?;
        value = storage::join(
            value,
            storage::requested::<Option<SourceId>>(2 * config.recovery.window)?,
        )?;
        value = storage::join(
            value,
            storage::requested::<Option<Receipt>>(config.recovery.window)?,
        )?;
        storage::join(
            value,
            storage::requested::<SourceId>(usize::from(config.feedback_batch))?,
        )
    }
    /// Construct every matrix, history and feedback buffer before accepting input.
    pub fn new(config: Config, scope: Scope, now: Tick) -> Result<Self, Error> {
        if Self::memory_bound(config)? > config.memory_bytes {
            return Err(Error::Capacity);
        }
        deadline(now, config.recovery.job_ticks)?;
        deadline(now, config.feedback_wait_ticks)?;
        Ok(Self {
            config,
            scope,
            decoder: rolling::Decoder::new_explicit(config.recovery, scope, now)?,
            seen: slots(2 * config.recovery.window, None)?,
            receipts: slots(config.recovery.window, None)?,
            output_ids: slots(usize::from(config.feedback_batch), SourceId(0))?,
            count: 0,
            prefix: 0,
            staged: None,
            scan: None,
            snapshot: None,
            next_feedback: 1,
            retained_cap: None,
            last: now,
            terminal: None,
        })
    }
    /// Admit exact nested heap capacity before constructing the owner.
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
    /// Actual retained heap capacities including all idle buffers.
    pub fn storage_usage(&self) -> Result<storage::Usage, storage::Error> {
        let value = storage::join(self.decoder.storage_usage()?, storage::vector(&self.seen)?)?;
        let value = storage::join(value, storage::vector(&self.receipts)?)?;
        storage::join(value, storage::vector(&self.output_ids)?)
    }
    fn fail<T>(&mut self, error: Error) -> Result<T, Error> {
        self.terminal = Some(error);
        Err(error)
    }
    fn time(&mut self, now: Tick) -> Result<(), Error> {
        if self.terminal.is_some() {
            return Err(Error::Terminal);
        }
        if let Err(error) = check_time(self.last, now, &[self.deadline()]) {
            return self.fail(error);
        }
        if let Err(error) = self.decoder.step(now, WorkBudget::default()) {
            return self.fail(error);
        }
        self.last = now;
        Ok(())
    }
    fn result<T>(&mut self, result: Result<T, Error>) -> Result<T, Error> {
        match result {
            Err(error) if self.decoder.status().terminal.is_some() => self.fail(error),
            other => other,
        }
    }
    fn notice(&mut self, id: SourceId, timing: Timing) -> Result<(), Error> {
        if let Some(old) = self.receipts.iter_mut().flatten().find(|old| old.id == id) {
            old.timing.received = old.timing.received.min(timing.received);
            old.timing.end = old.timing.end.min(timing.end);
            return Ok(());
        }
        let slot = self
            .receipts
            .iter_mut()
            .find(|slot| slot.is_none())
            .ok_or(Error::Capacity)?;
        *slot = Some(Receipt { id, timing });
        self.count += 1;
        Ok(())
    }
    fn release_cap(&mut self) {
        let state = self.decoder.status();
        if state.handoff_prefix == state.observed_end
            && !state.pending_job
            && self.staged.is_none()
            && self.scan.is_none()
            && self.count == 0
            && self.snapshot.is_none()
        {
            self.retained_cap = None;
        }
    }
    /// Admit a complete authenticated record with its current arrival timestamp.
    pub fn receive_wire(&mut self, bytes: &[u8], now: Tick) -> Result<Begin, Error> {
        self.receive_wire_at(bytes, now, now, Tick(u64::MAX))
    }
    /// Preserve original arrival and operation cap across Busy retries. No hidden
    /// ingress queue exists. Packet/feedback/upper-handoff expiry never renews.
    pub fn receive_wire_at(
        &mut self,
        bytes: &[u8],
        received: Tick,
        now: Tick,
        cap: Tick,
    ) -> Result<Begin, Error> {
        let mut terms = [Term {
            source: SourceId(0),
            coefficient: 1,
        }; 255];
        let mut ids = [SourceId(0); 255];
        let view = wire::inspect(self.config, bytes, &mut terms, &mut ids)?;
        let incoming = match view {
            wire::View::Source { scope, .. } => scope,
            wire::View::Repair(value) => value.equation.scope,
            wire::View::Feedback(_) => return Err(Error::Format),
        };
        if incoming != self.scope {
            return Err(Error::Scope);
        }
        self.time(now)?;
        if self.scan.is_some() {
            return Err(Error::Busy);
        }
        if received > now {
            return Err(Error::TimeRegression);
        }
        let end = deadline(received, self.config.recovery.job_ticks)?.min(cap);
        if now >= end {
            return self.fail(Error::Expired);
        }
        let source = if let wire::View::Source { id, .. } = view {
            Some(id)
        } else {
            None
        };
        // A duplicate systematic still owes a receipt; reserve a metadata slot
        // before admitting it so a full feedback queue never loses that event.
        if source.is_some_and(|id| {
            self.count == self.receipts.len()
                && !self.receipts.iter().flatten().any(|old| old.id == id)
        }) {
            return Err(Error::Capacity);
        }
        let result = match view {
            wire::View::Source {
                scope,
                id,
                original,
            } => self
                .decoder
                .begin_source_until(scope, id, original, received, now, cap),
            wire::View::Repair(value) => {
                self.decoder
                    .begin_explicit_until(value.equation, value.terms, received, now, cap)
            }
            wire::View::Feedback(_) => return Err(Error::Format),
        };
        let outcome = self.result(result)?;
        if cap != Tick(u64::MAX) {
            self.retained_cap = Some(self.retained_cap.map_or(cap, |old| old.min(cap)));
        }
        let timing = Timing { received, end };
        if outcome == Begin::Staged {
            self.staged = Some(timing);
        } else if let Some(id) = source {
            // Stale originals below upper handoff are already known; stale
            // equations do not provide evidence for an additional receipt.
            if outcome == Begin::Duplicate || id.0 < self.decoder.status().handoff_prefix {
                self.notice(
                    id,
                    Timing {
                        received: now,
                        ..timing
                    },
                )?;
            }
        }
        self.release_cap();
        Ok(outcome)
    }
    fn freeze(&mut self, now: Tick) -> Result<bool, Error> {
        if self.snapshot.is_some() || self.count == 0 {
            return Ok(false);
        }
        let first = self
            .receipts
            .iter()
            .flatten()
            .map(|r| r.timing.received)
            .min()
            .ok_or(Error::Identity)?;
        if self.count < self.config.feedback_limit()?
            && now < deadline(first, self.config.feedback_wait_ticks)?
        {
            return Ok(false);
        }
        if self.next_feedback == u64::MAX {
            return self.fail(Error::Exhausted);
        }
        let prefix = self.config.cumulative_feedback.then_some(self.prefix);
        let mut count = 0;
        let mut end = Tick(u64::MAX);
        // Each pass selects the lowest pending ID; at most 255*255 metadata
        // comparisons and 255 ID copies. This bounded snapshot is atomic.
        for _ in 0..self.config.feedback_limit()? {
            let Some((at, item)) = self
                .receipts
                .iter()
                .enumerate()
                .filter_map(|(at, item)| item.map(|item| (at, item)))
                .min_by_key(|(_, item)| item.id)
            else {
                break;
            };
            self.receipts[at] = None;
            self.count -= 1;
            end = end.min(item.timing.end);
            if prefix.is_none_or(|prefix| item.id.0 >= prefix) {
                self.output_ids[count] = item.id;
                count += 1;
            }
        }
        // A cumulative snapshot also discharges older already-known events.
        if let Some(prefix) = prefix {
            for item in &mut self.receipts {
                if item.is_some_and(|item| item.id.0 < prefix)
                    && let Some(item) = item.take()
                {
                    end = end.min(item.timing.end);
                    self.count -= 1;
                }
            }
        }
        self.snapshot = Some(Snapshot {
            id: FeedbackId(self.next_feedback),
            prefix,
            count,
            end,
        });
        Ok(true)
    }
    /// Advance existing budgeted GF work, scan committed known originals and
    /// freeze at most one feedback output. Budget-one calls make progress.
    pub fn step(&mut self, now: Tick, budget: WorkBudget) -> Result<ReceiverStep, Error> {
        self.time(now)?;
        let result = self.decoder.step(now, budget);
        let decode = self.result(result)?;
        let mut work = match decode {
            DecodeStep::Idle(w)
            | DecodeStep::Pending(w)
            | DecodeStep::Capacity(w)
            | DecodeStep::Accepted { work: w, .. } => w,
        };
        if matches!(decode, DecodeStep::Accepted { .. }) {
            if let Some(timing) = self.staged.take() {
                let state = self.decoder.status();
                self.prefix = self.prefix.max(state.handoff_prefix);
                self.scan = Some(Scan {
                    next: state.handoff_prefix,
                    end: state.observed_end,
                    timing: Timing {
                        received: now,
                        ..timing
                    },
                });
            }
        } else if matches!(decode, DecodeStep::Capacity(_)) {
            self.staged = None;
        }
        while work.metadata < budget.metadata {
            let Some(scan) = self.scan else {
                break;
            };
            if scan.next == scan.end {
                self.scan = None;
                break;
            }
            let id = SourceId(scan.next);
            let known = self.decoder.decoded_source(id)?.is_some();
            let at = id.0 as usize % self.seen.len();
            if known && self.seen[at] != Some(id) {
                if self.count == self.receipts.len() {
                    break;
                }
                self.notice(id, scan.timing)?;
                self.seen[at] = Some(id);
            }
            if known && self.prefix == id.0 {
                self.prefix += 1;
            }
            self.scan = Some(Scan {
                next: scan.next + 1,
                ..scan
            });
            work.metadata += 1;
        }
        if self.scan.is_some_and(|scan| scan.next == scan.end) {
            self.scan = None;
        }
        if work.metadata < budget.metadata && self.freeze(now)? {
            work.metadata += 1;
        }
        self.release_cap();
        Ok(ReceiverStep {
            decode,
            work,
            feedback_ready: self.snapshot.is_some(),
        })
    }
    /// Next exact original awaiting recovery-consumer custody, never native proof.
    /// Finish the committed-known scan before handing off its backing bytes.
    pub fn pending_source(&self) -> Option<(SourceId, &[u8])> {
        if self.terminal.is_some() || self.scan.is_some() {
            None
        } else {
            self.decoder.pending_source()
        }
    }
    /// Confirm only the next contiguous original after its receipt scan completes.
    pub fn confirm_handoff(&mut self, id: SourceId, now: Tick) -> Result<(), Error> {
        self.time(now)?;
        if self.scan.is_some() {
            return Err(Error::Busy);
        }
        let result = self.decoder.confirm_handoff(id, now);
        self.result(result)?;
        self.release_cap();
        Ok(())
    }
    /// Borrow one immutable reverse output; retries keep its identity and bytes.
    pub fn pending_feedback(&self) -> Option<Feedback<'_>> {
        if self.terminal.is_some() {
            return None;
        }
        self.snapshot.map(|value| Feedback {
            scope: self.scope,
            id: value.id,
            prefix: value.prefix,
            ids: &self.output_ids[..value.count],
        })
    }
    /// Serialize the complete feedback charged to the caller's reverse budget.
    pub fn encode_feedback(&self, output: &mut [u8]) -> Result<usize, Error> {
        wire::encode_feedback(
            self.config,
            self.pending_feedback().ok_or(Error::Busy)?,
            output,
        )
    }
    /// Release a snapshot only after actual reverse carrier ownership. Lost final
    /// feedback is regenerated by a later duplicate systematic, as in Python.
    pub fn confirm_feedback(&mut self, id: FeedbackId, now: Tick) -> Result<(), Error> {
        self.time(now)?;
        if self.snapshot.ok_or(Error::Busy)?.id != id {
            return Err(Error::Identity);
        }
        self.snapshot = None;
        self.next_feedback += 1;
        self.release_cap();
        Ok(())
    }
    /// Earliest original decoder, admitted operation or owned receipt deadline.
    pub fn deadline(&self) -> Option<Tick> {
        self.decoder
            .deadline()
            .into_iter()
            .chain(self.retained_cap)
            .chain(self.snapshot.map(|value| value.end))
            .chain(self.staged.map(|value| value.end))
            .chain(self.scan.map(|value| value.timing.end))
            .chain(self.receipts.iter().flatten().map(|value| value.timing.end))
            .min()
    }
    /// Next batching timer or hard deadline; invoke step immediately for pending work.
    pub fn next_wakeup(&self) -> Option<Tick> {
        self.deadline()
            .into_iter()
            .chain(self.receipts.iter().flatten().filter_map(|value| {
                deadline(value.timing.received, self.config.feedback_wait_ticks).ok()
            }))
            .min()
    }
    /// All admitted source, decode and reverse-output custody is discharged.
    /// This is a local recovery boundary, not native application delivery proof.
    pub fn is_drained(&self) -> bool {
        let state = self.decoder.status();
        self.terminal.is_none()
            && state.handoff_prefix == state.observed_end
            && !state.pending_job
            && self.staged.is_none()
            && self.scan.is_none()
            && self.snapshot.is_none()
            && self.count == 0
    }
    /// Committed recovery, feedback custody and terminal status.
    pub fn status(&self) -> ReceiverStatus {
        ReceiverStatus {
            decoder: self.decoder.status(),
            receipt_prefix: self.prefix,
            pending_receipts: self.count,
            scanning: self.scan.is_some(),
            feedback: self.snapshot.map(|value| value.id),
            terminal: self.terminal,
        }
    }
}

#[cfg(test)]
#[path = "receiver_tests.rs"]
mod receiver_tests;
