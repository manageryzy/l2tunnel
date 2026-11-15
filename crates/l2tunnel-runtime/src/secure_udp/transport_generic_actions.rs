//! Physical action adapter for the actual leased State in the sole I/O owner.
//!
//! No clock, protocol phase, crypto number or native completion is synthesized.

use super::generic::{PendingRequest, Runtime, TransactionReply};
use super::*;
use l2tunnel::swift_configuration::Configuration as C;

pub(super) struct ActionWork {
    pub(super) action: transactions::Action,
    pub(super) applied: bool,
    admitted: Option<NativeBoundary>,
}

/// Stack-only snapshot taken before borrowing an Entry in the same sole-owner turn.
/// Counts come only from the actual Peer and are not physical completion facts.
pub(super) struct NativeFence {
    origin: NativeOrigin,
    channels: usize,
    counts: [u64; swift::MAX_CHANNELS],
}

pub(super) fn check_native_fence(
    fence: Option<&NativeFence>,
    origin: NativeOrigin,
    identity: records::NativeIdentity,
) -> io::Result<()> {
    if let Some(fence) = fence {
        let channel = identity.channel.index();
        if fence.origin != origin
            || channel >= fence.channels
            || identity.record.0 >= fence.counts[channel]
        {
            return Err(protocol(
                "native record exceeds actual exclusive peer fence",
            ));
        }
    }
    Ok(())
}

impl Driver {
    pub(super) fn can_admit_native(&self) -> io::Result<bool> {
        if self.common.is_some() {
            return self.can_admit_common_native();
        }
        let admitted = match &self.owner {
            owner::DataOwner::Legacy(legacy) => legacy.coordinator.admission_allowed(),
            owner::DataOwner::Generic(state) => state.can_admit_data(),
            owner::DataOwner::Common(_) => return Err(protocol("common owner lost selection")),
        };
        Ok(admitted
            && self
                .owner
                .engine(core::Epoch(self.source_scope.epoch.0))?
                .has_room())
    }

    pub(super) fn transaction_receive_scope(
        &self,
        scope: Scope,
    ) -> io::Result<Option<transaction::ReadDisposition>> {
        let owner::DataOwner::Generic(state) = &self.owner else {
            return Ok(None);
        };
        let Some(reader) = state.peer().reader(core::Epoch(scope.epoch.0)) else {
            return Ok(None);
        };
        if transaction_scope(core::Epoch(scope.epoch.0), reader.config)? != scope {
            return Err(protocol(
                "generic scope differs from actual epoch configuration",
            ));
        }
        let engine = state.engine(core::Epoch(scope.epoch.0))?;
        let config = self
            .generic
            .as_ref()
            .ok_or_else(|| protocol("generic owner lacks runtime contract"))?
            .contract
            .resolve(*reader.config)?;
        if engine.send_config() != config.send.records
            || engine.receive_config() != config.receive.records
            || !self.scope_registered(scope)
        {
            return Err(protocol("generic reader, Bank or security scope differs"));
        }
        Ok(Some(reader.disposition))
    }

    pub(super) fn transaction_epochs(&self) -> [Option<core::Epoch>; 2] {
        let owner::DataOwner::Generic(state) = &self.owner else {
            return [None, None];
        };
        let first = state.peer().active_epoch();
        let second = state.peer().operation().map(|operation| {
            if operation.origin().epoch == first {
                operation.ticket().epoch
            } else {
                operation.origin().epoch
            }
        });
        let mut result = [None, None];
        for candidate in [Some(first), second].into_iter().flatten() {
            if result.contains(&Some(candidate)) {
                continue;
            }
            if state.peer().reader(candidate).is_some()
                && state.engine(candidate).is_ok()
                && let Some(slot) = result.iter_mut().find(|slot| slot.is_none())
            {
                *slot = Some(candidate);
            }
        }
        result
    }

    pub(super) fn transaction_native_fence(&self) -> io::Result<Option<NativeFence>> {
        let owner::DataOwner::Generic(state) = &self.owner else {
            return Ok(None);
        };
        let Some(operation) = state.peer().operation() else {
            return Ok(None);
        };
        let Some(fence) = state.peer().peer_fence() else {
            return Ok(None);
        };
        let scope = original_scope(operation);
        if self.feedback_scope != scope {
            return Ok(None);
        }
        let origin = NativeOrigin::new(&self.info, scope, records::Direction::Receive);
        let width = state
            .engine(operation.origin().epoch)?
            .receive_config()
            .channels;
        if fence.counts().len() != width {
            return Err(protocol(
                "actual peer fence width differs from old receive engine",
            ));
        }
        let mut counts = [0; swift::MAX_CHANNELS];
        counts[..width].copy_from_slice(fence.counts());
        Ok(Some(NativeFence {
            origin,
            channels: width,
            counts,
        }))
    }

    /// Freeze the actual queued request's cap exactly once, before allocation.
    pub(super) fn request_transaction(
        &mut self,
        now: u64,
        configuration: C,
        reply: TransactionReply,
    ) -> io::Result<()> {
        let Some(runtime) = self.generic.as_mut() else {
            let _ = reply.send(Err(SwitchError::Invalid));
            return Err(protocol("generic request on legacy runtime"));
        };
        if self.info.role != security::Role::Initiator {
            let _ = reply.send(Err(SwitchError::NotCoordinator));
            return Ok(());
        }
        let owner::DataOwner::Generic(state) = &self.owner else {
            let _ = reply.send(Err(SwitchError::Invalid));
            return Err(protocol("generic runtime lacks actual State"));
        };
        if self.terminal.is_some() || now >= self.lease {
            let _ = reply.send(Err(SwitchError::Closed));
            return Ok(());
        }
        if runtime.request.is_some()
            || runtime.action.is_some()
            || runtime.outcome.is_some()
            || !state.can_admit_data()
            || self.target.is_some()
        {
            let _ = reply.send(Err(SwitchError::Busy));
            return Ok(());
        }
        if runtime.contract.resolve(configuration).is_err() {
            let _ = reply.send(Err(SwitchError::Invalid));
            return Ok(());
        }
        let at = u64::try_from(duration(now).as_millis()).map_err(invalid)?;
        let lease = u64::try_from(duration(self.lease).as_millis()).map_err(invalid)?;
        let cap = at
            .checked_add(runtime.contract.settings().max_operation_ms)
            .ok_or_else(exhausted)?
            .min(lease);
        if cap <= at {
            let _ = reply.send(Err(SwitchError::Closed));
            return Ok(());
        }
        runtime.request = Some(PendingRequest {
            configuration,
            cap: transaction::Tick(cap),
            reply,
        });
        runtime.observation_dirty = true;
        Ok(())
    }

    /// Allocation is admitted only through the original loop's injected clock.
    pub(super) fn admit_transaction(
        &mut self,
        mut sample: impl FnMut() -> io::Result<Duration>,
    ) -> io::Result<()> {
        let runtime = self
            .generic
            .as_mut()
            .ok_or_else(|| protocol("generic admission on legacy runtime"))?;
        let owner::DataOwner::Generic(state) = &mut self.owner else {
            return Err(protocol("generic admission lacks State"));
        };
        if let Some(outcome) = runtime.outcome {
            let operation = outcome_operation(outcome);
            match state.peer().operation() {
                None => return Ok(()),
                Some(actual) if actual == operation => {}
                Some(_) => return Err(protocol("held outcome overlaps another actual admission")),
            }
            if operation.identity().role != mg::Role::Server {
                return Ok(());
            }
            let now = sample()?;
            let at = transaction::Tick(u64::try_from(now.as_millis()).map_err(invalid)?);
            let Some(view) =
                self.control
                    .preview_transaction(state.peer(), now, operation.expires())?
            else {
                return Ok(());
            };
            if view.preparation().is_some() {
                return Err(protocol("held outcome cannot prepare another target"));
            }
            let envelope = control::Envelope::decode(
                view.envelope(),
                control::Limits {
                    max_frame_bytes: 65_536,
                    max_management_bytes: 65_536 - control::HEADER_BYTES,
                    max_feedback_bytes: 1,
                },
            )
            .map_err(protocol)?;
            let control::Body::Management(command) = envelope.body else {
                return Err(protocol("held outcome retry is not management"));
            };
            let frame = mg::Frame::decode(command, mg::Limits::default()).map_err(protocol)?;
            let authority = state
                .peer()
                .cached_retry_authority(at)
                .map_err(protocol)?
                .ok_or_else(|| protocol("held outcome lost actual cached retry authority"))?;
            let exact = state.peer().phase() == transaction::Phase::Idle
                && authority.operation() == operation
                && envelope.binding.scope == operation.origin()
                && matches!(
                    authority.reply_kind(),
                    mg::MessageKind::Retire | mg::MessageKind::Reject
                )
                && authority.request().header.same_request(frame.header)
                && authority.request().body == frame.body;
            if !exact {
                return Err(protocol(
                    "held outcome input differs from exact cached final request",
                ));
            }
            state.dispatch(&mut self.control, &mut sample)?;
            return Ok(());
        }
        if state.peer().operation().is_none()
            && let Some(request) = runtime.request.as_ref()
        {
            let first = sample()?;
            let at = transaction::Tick(u64::try_from(first.as_millis()).map_err(invalid)?);
            if at >= request.cap {
                if let Some(request) = runtime.request.take() {
                    let _ = request.reply.send(Err(SwitchError::Rejected));
                }
            } else {
                let mut sampled = first;
                let mut first = Some(first);
                match state.propose(
                    &mut self.control,
                    request.configuration,
                    request.cap,
                    || {
                        let next = if let Some(first) = first.take() {
                            first
                        } else {
                            sample()?
                        };
                        sampled = next;
                        Ok(next)
                    },
                ) {
                    Ok(_) => {}
                    Err(error)
                        if error.kind() == io::ErrorKind::InvalidInput
                            && state.peer().operation().is_none() =>
                    {
                        if let Some(request) = runtime.request.take() {
                            let expired = sampled.as_millis() >= u128::from(request.cap.0);
                            let _ = request.reply.send(Err(if expired {
                                SwitchError::Rejected
                            } else {
                                SwitchError::Invalid
                            }));
                        }
                    }
                    Err(error) => return Err(error),
                }
            }
        }
        state.dispatch(&mut self.control, &mut sample)?;
        Ok(())
    }

    /// Service and physical work only; this method never prepares a new Bank.
    pub(super) fn progress_transaction(&mut self, now: u64) -> io::Result<()> {
        if !self.check_expiry(now)? {
            return Ok(());
        }
        let mut runtime = self
            .generic
            .take()
            .ok_or_else(|| protocol("generic progress on legacy runtime"))?;
        let result = self.progress_transaction_inner(&mut runtime, now);
        self.generic = Some(runtime);
        result?;
        self.bucket.refill(now)?;
        if now >= self.ingress.refill {
            self.ingress.left = self.config.work.receive_packets;
            self.ingress.refill = add(now, self.config.work.receive_interval)?;
        }
        Ok(())
    }

    fn progress_transaction_inner(&mut self, runtime: &mut Runtime, now: u64) -> io::Result<()> {
        self.validate_known_transaction_fence()?;
        self.service_transaction_state(now)?;
        if runtime.action.is_none() {
            runtime.action = self
                .transaction_state_mut()?
                .take_action()
                .map(|action| ActionWork {
                    action,
                    applied: false,
                    admitted: None,
                });
        }
        if let Some(mut work) = runtime.action.take() {
            let completed = self.progress_transaction_action(runtime, &mut work, now);
            match completed {
                Ok(true) => {}
                Ok(false) => runtime.action = Some(work),
                Err(error) => {
                    runtime.action = Some(work);
                    return Err(error);
                }
            }
        }
        if self.terminal.is_none() {
            self.service_transaction_state(now)?;
        }
        self.validate_known_transaction_fence()?;
        if let Some(outcome) = self.transaction_state_mut()?.take_outcome() {
            if runtime.outcome.is_some() {
                return Err(protocol(
                    "another actual transaction outcome still owns custody",
                ));
            }
            let operation = outcome_operation(outcome);
            if let Some(request) = runtime.request.as_ref()
                && (operation.expires() != request.cap
                    || operation.ticket().digest
                        != transaction::configuration_digest(&request.configuration)
                            .map_err(protocol)?)
            {
                return Err(protocol(
                    "transaction outcome differs from actual queued request",
                ));
            }
            runtime.outcome = Some(outcome);
        }
        if let Some(outcome) = runtime.outcome {
            let operation = outcome_operation(outcome);
            let at = transaction::Tick(u64::try_from(duration(now).as_millis()).map_err(invalid)?);
            if at >= operation.expires() {
                self.terminal = Some(StopReason::PolicyTimeout);
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "original outcome custody cap",
                ));
            }
            match self.transaction_state()?.peer().operation() {
                Some(actual) if actual == operation => {}
                Some(_) => return Err(protocol("held outcome overlaps another actual operation")),
                None => {
                    if runtime.completion.is_none()
                        && let Some(request) = runtime.request.take()
                    {
                        let result = match outcome {
                            transactions::Outcome::Retired { .. } => {
                                let epoch = self.transaction_state()?.epoch();
                                if epoch != operation.ticket().epoch {
                                    return Err(protocol(
                                        "retired outcome differs from actual promoted Bank",
                                    ));
                                }
                                Ok(epoch)
                            }
                            transactions::Outcome::Aborted { .. } => Err(SwitchError::Rejected),
                        };
                        runtime.completion = Some((request.reply, result));
                    } else if runtime.completion.is_none() {
                        runtime.outcome = None;
                    }
                }
            }
        }
        Ok(())
    }

    pub(super) fn report_transaction_completion(
        &mut self,
        mut sample: impl FnMut() -> io::Result<u64>,
        observe: impl FnOnce(&Self, u64) -> io::Result<()>,
    ) -> io::Result<bool> {
        if self.common.is_some() {
            return self.report_common_completion(sample, observe);
        }
        if self
            .generic
            .as_ref()
            .is_none_or(|runtime| runtime.completion.is_none())
        {
            return Ok(false);
        }
        let now = sample()?;
        if !self.check_expiry(now)? {
            return Ok(false);
        }
        observe(self, now)?;
        if !self.check_expiry(sample()?)? {
            return Ok(false);
        }
        let runtime = self
            .generic
            .as_mut()
            .ok_or_else(|| protocol("completion lost generic owner"))?;
        let (reply, result) = runtime
            .completion
            .take()
            .ok_or_else(|| protocol("observed completion lost reply"))?;
        runtime.outcome = None;
        let _ = reply.send(result);
        Ok(true)
    }

    fn progress_transaction_action(
        &mut self,
        runtime: &mut Runtime,
        work: &mut ActionWork,
        now: u64,
    ) -> io::Result<bool> {
        let operation = work.action.operation();
        let old = original_scope(operation);
        let interrupted = self
            .transaction_state()?
            .interruption(&work.action)
            .is_some();
        if interrupted
            && matches!(
                work.action.event(),
                transaction::Event::Stage { .. } | transaction::Event::Drain { .. }
            )
        {
            if matches!(work.action.event(), transaction::Event::Stage { .. }) && work.applied {
                let target = self
                    .target
                    .ok_or_else(|| protocol("applied Stage lost target reader"))?;
                if self.records.active_data() != old {
                    return Err(protocol("cancelled Stage was already promoted"));
                }
                self.records.cancel_staged_data(target).map_err(protocol)?;
                self.target = None;
                self.transaction_origin = None;
                self.retired_send = None;
            }
            let owner::DataOwner::Generic(state) = &mut self.owner else {
                return Err(protocol("generic action lacks State"));
            };
            return Ok(state.complete_action(
                &mut self.control,
                &mut work.action,
                transactions::Completion::Cancelled,
                duration(now),
            )? == transactions::Progress::Advanced);
        }
        match work.action.event() {
            transaction::Event::Stage { ticket, config } => {
                if !work.applied {
                    if self.target.is_some()
                        || self.retired_send.is_some()
                        || self.retired_receive.is_some()
                        || self.records.active_data() != old
                        || self.source_scope != old
                        || self.feedback_scope != old
                    {
                        return Err(protocol(
                            "Stage does not start from the actual sole old generation",
                        ));
                    }
                    runtime.contract.resolve(*config)?;
                    let target = transaction_scope(ticket.epoch, config)?;
                    if target.configuration.0 != ticket.digest.0 {
                        return Err(protocol("Stage digest differs from actual configuration"));
                    }
                    let admitted = NativeBoundary::capture(
                        self.owner.engine(operation.origin().epoch)?,
                        NativeOrigin::new(&self.info, old, records::Direction::Send),
                        records::Direction::Send,
                    )?;
                    self.records.stage_data(target).map_err(protocol)?;
                    self.target = Some(target);
                    self.transaction_origin = Some(old);
                    self.retired_send = Some(admitted);
                    work.admitted = Some(admitted);
                    work.applied = true;
                }
                let admitted = work
                    .admitted
                    .ok_or_else(|| protocol("applied Stage lost original admitted boundary"))?;
                let fence = boundary_fence(admitted)?;
                let owner::DataOwner::Generic(state) = &mut self.owner else {
                    return Err(protocol("generic Stage lacks State"));
                };
                Ok(state.complete_action(
                    &mut self.control,
                    &mut work.action,
                    transactions::Completion::Staged { admitted: &fence },
                    duration(now),
                )? == transactions::Progress::Advanced)
            }
            transaction::Event::Drain { local, peer } => {
                if !work.applied {
                    self.validate_known_transaction_fence()?;
                    let engine = self.owner.engine(operation.origin().epoch)?;
                    if !engine.send_drained()
                        || !engine.receive_drained()
                        || !self.native.is_empty()
                    {
                        return Ok(false);
                    }
                    let admitted = self
                        .retired_send
                        .ok_or_else(|| protocol("Drain lost frozen admitted boundary"))?;
                    let sent = NativeBoundary::capture(
                        engine,
                        NativeOrigin::new(&self.info, old, records::Direction::Send),
                        records::Direction::Send,
                    )?;
                    let extracted = NativeBoundary::capture(
                        engine,
                        NativeOrigin::new(&self.info, old, records::Direction::Receive),
                        records::Direction::Receive,
                    )?;
                    if sent != admitted || boundary_fence(sent)? != *local {
                        return Err(protocol("Drain changed its original admitted send fence"));
                    }
                    if boundary_fence(extracted)? != *peer {
                        return Ok(false);
                    }
                    if !self.written.matches_extracted(engine, extracted.origin)
                        || self.written.boundary() != extracted
                    {
                        return Err(protocol(
                            "Drain lacks independent exact native extraction/physical fences",
                        ));
                    }
                    if self.retired_receive.is_some_and(|prior| prior != extracted) {
                        return Err(protocol("Drain replaced retained physical receive witness"));
                    }
                    self.retired_receive = Some(extracted);
                    work.applied = true;
                }
                let sent = boundary_fence(
                    self.retired_send
                        .ok_or_else(|| protocol("Drain lost local witness"))?,
                )?;
                let delivered = boundary_fence(
                    self.retired_receive
                        .ok_or_else(|| protocol("Drain lost physical receive witness"))?,
                )?;
                let owner::DataOwner::Generic(state) = &mut self.owner else {
                    return Err(protocol("generic Drain lacks State"));
                };
                Ok(state.complete_action(
                    &mut self.control,
                    &mut work.action,
                    transactions::Completion::Drained {
                        sent: &sent,
                        delivered: &delivered,
                    },
                    duration(now),
                )? == transactions::Progress::Advanced)
            }
            transaction::Event::Committed(ticket) => {
                if !work.applied {
                    if !self.transaction_barrier_ready(old)? {
                        return Ok(false);
                    }
                    let value = *self.transaction_state()?.peer().active_config();
                    let config = runtime.contract.resolve(value)?;
                    let target = transaction_scope(ticket.epoch, &value)?;
                    if self.target != Some(target)
                        || self.records.active_data() != old
                        || self.source_scope != old
                        || self.feedback_scope != old
                    {
                        return Err(protocol(
                            "Commit differs from actual staged physical scopes",
                        ));
                    }
                    let written = NativeWritten::new(
                        NativeOrigin::new(&self.info, target, records::Direction::Receive),
                        config.receive.records.channels,
                    )?;
                    self.bucket.refill(now)?;
                    self.records.activate_data(target).map_err(protocol)?;
                    self.source_scope = target;
                    self.feedback_scope = target;
                    self.send = config.send;
                    self.receive = config.receive;
                    self.config = config;
                    self.bucket.rate = config.send.bytes_per_second;
                    self.written = written;
                    work.applied = true;
                }
                self.complete_transaction_applied(work, now)
            }
            transaction::Event::Retired(epoch) => {
                if !work.applied {
                    if *epoch != operation.origin().epoch {
                        return Err(protocol("Retired event has another old epoch"));
                    }
                    if !self.transaction_barrier_ready(old)? {
                        return Ok(false);
                    }
                    if self.records.active_data() == old {
                        return Err(protocol("Retire attempted before physical promotion"));
                    }
                    self.records.retire_data(old).map_err(protocol)?;
                    work.applied = true;
                }
                let completed = self.complete_transaction_applied(work, now)?;
                if completed {
                    self.target = None;
                    self.transaction_origin = None;
                    self.retired_send = None;
                    self.retired_receive = None;
                }
                Ok(completed)
            }
            transaction::Event::Aborted(_) => {
                if !work.applied {
                    if self.records.active_data() != old
                        || self.source_scope != old
                        || self.feedback_scope != old
                    {
                        return Err(protocol(
                            "Aborted transaction cannot roll back promoted scopes",
                        ));
                    }
                    if let Some(target) = self.target {
                        self.records.cancel_staged_data(target).map_err(protocol)?;
                    }
                    work.applied = true;
                }
                let completed = self.complete_transaction_applied(work, now)?;
                if completed {
                    self.target = None;
                    self.transaction_origin = None;
                    self.retired_send = None;
                    self.retired_receive = None;
                }
                Ok(completed)
            }
            transaction::Event::Uncertain(_) => {
                work.applied = true;
                self.complete_transaction_applied(work, now)
            }
            transaction::Event::Failed => {
                work.applied = true;
                let completed = self.complete_transaction_applied(work, now)?;
                self.terminal = Some(StopReason::PolicyTimeout);
                if let Some(request) = runtime.request.take() {
                    let _ = request.reply.send(Err(SwitchError::Closed));
                }
                Ok(completed)
            }
        }
    }

    fn complete_transaction_applied(
        &mut self,
        work: &mut ActionWork,
        now: u64,
    ) -> io::Result<bool> {
        let owner::DataOwner::Generic(state) = &mut self.owner else {
            return Err(protocol("generic completion lacks State"));
        };
        Ok(state.complete_action(
            &mut self.control,
            &mut work.action,
            transactions::Completion::Applied,
            duration(now),
        )? == transactions::Progress::Advanced)
    }

    /// Old duplicate processing may retain a conservative ready hint. A genuine
    /// terminal pop clears it; any newly extracted old packet is protocol excess.
    fn transaction_barrier_ready(&mut self, old: Scope) -> io::Result<bool> {
        if self.feedback_scope == old && !self.native.is_empty() {
            return Ok(false);
        }
        if self.feedback_scope != old
            && self
                .native
                .front()
                .is_some_and(|packet| packet.metadata().origin.scope == old)
        {
            return Err(protocol("promoted native FIFO still contains old origin"));
        }
        let admitted = self
            .retired_send
            .ok_or_else(|| protocol("physical barrier lost old send witness"))?;
        let extracted = self
            .retired_receive
            .ok_or_else(|| protocol("physical barrier lost old receive witness"))?;
        if !admitted.canonical_for(
            NativeOrigin::new(&self.info, old, records::Direction::Send),
            records::Direction::Send,
        ) || !extracted.canonical_for(
            NativeOrigin::new(&self.info, old, records::Direction::Receive),
            records::Direction::Receive,
        ) {
            return Err(protocol("physical barrier retained another native origin"));
        }
        let epoch = core::Epoch(old.epoch.0);
        if !self.owner.engine(epoch)?.receive_drained()
            && self
                .owner
                .entry(epoch)?
                .pop_identified()
                .map_err(native_record_error)?
                .is_some()
        {
            return Err(protocol(
                "draining epoch extracted native data after completed fence",
            ));
        }
        let engine = self.owner.engine(epoch)?;
        if !engine.send_drained() || !engine.receive_drained() {
            return Ok(false);
        }
        if NativeBoundary::capture(engine, admitted.origin, records::Direction::Send)? != admitted
            || NativeBoundary::capture(engine, extracted.origin, records::Direction::Receive)?
                != extracted
        {
            return Err(protocol("old engine moved beyond completed native barrier"));
        }
        if self.written.origin == extracted.origin && self.written.boundary() != extracted {
            return Err(protocol("physical write witness moved after old barrier"));
        }
        Ok(true)
    }

    /// Reject already extracted or physically completed excess as soon as a
    /// formerly unknown authenticated peer fence becomes available, before writes.
    fn validate_known_transaction_fence(&self) -> io::Result<()> {
        let state = self.transaction_state()?;
        let Some(operation) = state.peer().operation() else {
            return Ok(());
        };
        let Some(peer) = state.peer().peer_fence() else {
            return Ok(());
        };
        let old = original_scope(operation);
        let engine = state.engine(operation.origin().epoch)?;
        let extracted = NativeBoundary::capture(
            engine,
            NativeOrigin::new(&self.info, old, records::Direction::Receive),
            records::Direction::Receive,
        )?;
        let written = if self.written.origin == extracted.origin {
            self.written.boundary()
        } else {
            self.retired_receive
                .ok_or_else(|| protocol("known old peer fence lost physical witness"))?
        };
        if peer.counts().len() != extracted.channels
            || !written.canonical_for(extracted.origin, records::Direction::Receive)
            || written.channels != extracted.channels
        {
            return Err(protocol(
                "known peer fence has another native direction or width",
            ));
        }
        for (channel, limit) in peer.counts().iter().enumerate() {
            if extracted.counts[channel] > *limit || written.counts[channel] > *limit {
                return Err(protocol(
                    "native extraction or physical write exceeds newly known peer fence",
                ));
            }
        }
        if let Some(front) = self.native.front() {
            let metadata = front.metadata();
            if metadata.origin == extracted.origin {
                let channel = metadata.identity.channel.index();
                if channel >= peer.counts().len()
                    || metadata.identity.record.0 >= peer.counts()[channel]
                {
                    return Err(protocol(
                        "queued native record exceeds newly known peer fence",
                    ));
                }
            }
        }
        Ok(())
    }

    fn service_transaction_state(&mut self, now: u64) -> io::Result<()> {
        let owner::DataOwner::Generic(state) = &mut self.owner else {
            return Err(protocol("generic service lacks actual State"));
        };
        state.service(&mut self.control, duration(now))?;
        Ok(())
    }
    fn transaction_state(&self) -> io::Result<&transactions::State> {
        match &self.owner {
            owner::DataOwner::Generic(state) => Ok(state),
            _ => Err(protocol("generic operation lacks actual State")),
        }
    }
    fn transaction_state_mut(&mut self) -> io::Result<&mut transactions::State> {
        match &mut self.owner {
            owner::DataOwner::Generic(state) => Ok(state),
            _ => Err(protocol("generic operation lacks actual State")),
        }
    }
}

fn original_scope(operation: transaction::Operation) -> Scope {
    Scope {
        epoch: security::Epoch(operation.origin().epoch.0),
        configuration: security::ConfigDigest(operation.origin().digest.0),
    }
}
fn transaction_scope(epoch: core::Epoch, value: &C) -> io::Result<Scope> {
    Ok(Scope {
        epoch: security::Epoch(epoch.0),
        configuration: security::ConfigDigest(
            transaction::configuration_digest(value)
                .map_err(protocol)?
                .0,
        ),
    })
}
fn boundary_fence(boundary: NativeBoundary) -> io::Result<transaction::Fence> {
    if !(1..=swift::MAX_CHANNELS).contains(&boundary.channels) {
        return Err(protocol("native boundary width"));
    }
    transaction::Fence::new(&boundary.counts[..boundary.channels]).map_err(protocol)
}

fn outcome_operation(outcome: transactions::Outcome) -> transaction::Operation {
    match outcome {
        transactions::Outcome::Retired { operation, .. }
        | transactions::Outcome::Aborted { operation, .. } => operation,
    }
}
