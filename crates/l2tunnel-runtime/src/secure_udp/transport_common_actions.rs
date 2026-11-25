//! Physical Common adapter of the same leased TransactionState implementation.
//! Counts become a barrier only with stopped ingress and real full-generation drain.
use super::*;
use l2tunnel::{record_configuration::Configuration as C, record_engine as engine};

#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) struct Boundary {
    origin: NativeOrigin,
    width: usize,
    counts: [u64; 256],
}
impl Boundary {
    fn capture(engine: &engine::Engine, origin: NativeOrigin, send: bool) -> io::Result<Self> {
        let view = engine.native_counts().map_err(protocol)?;
        if view.context.epoch != origin.scope.epoch.0
            || view.context.session != u128::from_be_bytes(origin.binding.session.0)
            || view.digest.0 != origin.scope.configuration.0
        {
            return Err(protocol("common boundary origin"));
        }
        let source = if send { view.admitted } else { view.committed };
        if source.is_empty() || source.len() > 256 {
            return Err(protocol("common boundary width"));
        }
        let mut counts = [0; 256];
        counts[..source.len()].copy_from_slice(source);
        Ok(Self {
            origin,
            width: source.len(),
            counts,
        })
    }
    fn fence(self) -> io::Result<transaction::Fence> {
        transaction::Fence::new(&self.counts[..self.width]).map_err(protocol)
    }
}
pub(super) struct ActionWork {
    pub(super) action: transactions::CommonAction,
    pub(super) applied: bool,
    admitted: Option<Boundary>,
}
pub(super) fn outcome_deadline(outcome: transactions::Outcome) -> Duration {
    Duration::from_millis(outcome_operation(outcome).expires().0)
}
type StateObservation = (
    core::Epoch,
    transaction::Phase,
    Option<transaction::Operation>,
    Scope,
);

impl Driver {
    pub(super) fn can_admit_native(&self) -> io::Result<bool> {
        self.can_admit_common_native()
    }

    pub(super) fn transaction_observation(&self) -> io::Result<Option<StateObservation>> {
        let state = self.common_state()?;
        Ok(Some((
            state.epoch(),
            state.peer().phase(),
            state.peer().operation(),
            self.feedback_scope,
        )))
    }

    pub(super) fn report_transaction_completion(
        &mut self,
        sample: impl FnMut() -> io::Result<u64>,
        observe: impl FnOnce(&Self, u64) -> io::Result<()>,
    ) -> io::Result<bool> {
        self.report_common_completion(sample, observe)
    }

    /// Freeze the actual queued request's cap exactly once, before allocation.
    pub(super) fn request_common(
        &mut self,
        now: u64,
        configuration: C,
        reply: common::TransactionReply,
    ) -> io::Result<()> {
        let Some(runtime) = self.common.as_deref_mut() else {
            let _ = reply.send(Err(SwitchError::Invalid));
            return Err(protocol("generic request on legacy runtime"));
        };
        if runtime
            .reuse_controller()
            .is_some_and(super::common_reuse::Controller::active)
        {
            let _ = reply.send(Err(SwitchError::Busy));
            return Ok(());
        }
        if runtime.contract.proxy_binding().is_some() {
            // The initial proxy composition has no generation-handoff contract.
            let _ = reply.send(Err(SwitchError::Invalid));
            return Ok(());
        }
        if self.info.role != security::Role::Initiator {
            let _ = reply.send(Err(SwitchError::NotCoordinator));
            return Ok(());
        }
        let owner::DataOwner::Common(state) = &self.owner;
        if self.terminal.is_some() || now >= self.lease {
            let _ = reply.send(Err(SwitchError::Closed));
            return Ok(());
        }
        if runtime.path.unavailable
            || runtime.request.is_some()
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
        if state.current() == &configuration {
            let _ = reply.send(Ok(state.epoch()));
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
        runtime.request = Some(common::PendingRequest {
            configuration,
            cap: transaction::Tick(cap),
            reply,
        });
        runtime.observation_dirty = true;
        Ok(())
    }

    /// Allocation is admitted only through the original loop's injected clock.
    pub(super) fn admit_common(
        &mut self,
        mut sample: impl FnMut() -> io::Result<Duration>,
    ) -> io::Result<()> {
        let runtime = self
            .common
            .as_deref_mut()
            .ok_or_else(|| protocol("generic admission on legacy runtime"))?;
        let owner::DataOwner::Common(state) = &mut self.owner;
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
            } else if let Some(gate) = self.device_mtu.as_deref_mut()
                && let readiness = gate.ready_for(&request.configuration)
                && readiness != super::device_mtu::Readiness::Ready
            {
                // Lower the device MTU before proposing a smaller size; a
                // failed lowering refuses the switch.
                if readiness == super::device_mtu::Readiness::Failed
                    && let Some(request) = runtime.request.take()
                {
                    let _ = request.reply.send(Err(SwitchError::DeviceMtu));
                }
            } else if !runtime.path.unavailable {
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
        let device_mtu = &mut self.device_mtu;
        state.dispatch_preparations(
            &mut self.control,
            runtime.contract.proxy_binding().is_none()
                && !runtime
                    .reuse_controller()
                    .is_some_and(super::common_reuse::Controller::active),
            // The follower lowers its device MTU before acknowledging a
            // smaller target; a failed lowering proceeds (decision 8 drops
            // and counts leftover oversized packets).
            |target| {
                device_mtu
                    .as_deref_mut()
                    .is_none_or(|gate| gate.ready_for(target) != super::device_mtu::Readiness::Wait)
            },
            &mut sample,
        )?;
        Ok(())
    }

    /// Service and physical work only; this method never prepares a new Bank.
    pub(super) fn progress_common(&mut self, now: u64) -> io::Result<()> {
        if !self.check_expiry(now)? {
            return Ok(());
        }
        self.service_due_acks(now)?;
        self.retry_common_feedback(now)?;
        self.retry_common_connection_input(now)?;
        let mut runtime = self
            .common
            .take()
            .ok_or_else(|| protocol("generic progress on legacy runtime"))?;
        let result = self.progress_common_inner(&mut runtime, now);
        self.common = Some(runtime);
        result?;
        self.bucket.refill(now)?;
        if now >= self.ingress.refill {
            self.ingress.left = self.config.work.receive_packets;
            self.ingress.refill = add(now, self.config.work.receive_interval)?;
        }
        Ok(())
    }

    fn progress_common_inner(&mut self, runtime: &mut common::Runtime, now: u64) -> io::Result<()> {
        #[cfg(unix)]
        self.observe_proxy_retirement(runtime)?;
        self.progress_connection_reuse(runtime, now)?;
        self.validate_common_fence()?;
        self.service_common_state(now)?;
        if runtime.action.is_none() {
            runtime.action = self
                .common_state_mut()?
                .take_action()
                .map(|action| ActionWork {
                    action,
                    applied: false,
                    admitted: None,
                });
        }
        if let Some(mut work) = runtime.action.take() {
            let completed = self.progress_common_action(runtime, &mut work, now);
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
            self.service_common_state(now)?;
        }
        self.validate_common_fence()?;
        if let Some(outcome) = self.common_state_mut()?.take_outcome() {
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
            match self.common_state()?.peer().operation() {
                Some(actual) if actual == operation => {}
                Some(_) => return Err(protocol("held outcome overlaps another actual operation")),
                None => {
                    if runtime.completion.is_none()
                        && let Some(request) = runtime.request.take()
                    {
                        let result = match outcome {
                            transactions::Outcome::Retired { .. } => {
                                let epoch = self.common_state()?.epoch();
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

    pub(super) fn report_common_completion(
        &mut self,
        mut sample: impl FnMut() -> io::Result<u64>,
        observe: impl FnOnce(&Self, u64) -> io::Result<()>,
    ) -> io::Result<bool> {
        if self
            .common
            .as_deref()
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
            .common
            .as_deref_mut()
            .ok_or_else(|| protocol("completion lost generic owner"))?;
        let (reply, result) = runtime
            .completion
            .take()
            .ok_or_else(|| protocol("observed completion lost reply"))?;
        runtime.outcome = None;
        let _ = reply.send(result);
        Ok(true)
    }

    fn progress_common_action(
        &mut self,
        runtime: &mut common::Runtime,
        work: &mut ActionWork,
        now: u64,
    ) -> io::Result<bool> {
        let operation = work.action.operation();
        let old = original_scope(operation);
        if self.common_state()?.interruption(&work.action).is_some()
            && matches!(
                work.action.event(),
                transaction::Event::Stage { .. } | transaction::Event::Drain { .. }
            )
        {
            if work.applied && matches!(work.action.event(), transaction::Event::Stage { .. }) {
                let target = self
                    .target
                    .ok_or_else(|| protocol("cancelled common Stage lost target"))?;
                self.records.cancel_staged_data(target).map_err(protocol)?;
                self.target = None;
                self.transaction_origin = None;
                runtime.sent = None;
                runtime.delivered = None;
            }
            let owner::DataOwner::Common(state) = &mut self.owner;
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
                        || runtime.sent.is_some()
                        || runtime.delivered.is_some()
                        || self.records.active_data() != old
                        || self.source_scope != old
                        || self.feedback_scope != old
                    {
                        return Err(protocol("common Stage original scopes"));
                    }
                    runtime.contract.resolve(*config)?;
                    if runtime.pending_feedback.is_some()
                        || runtime.pending_ingress.is_some()
                        || runtime
                            .connection_input
                            .as_ref()
                            .is_some_and(|input| !input.is_empty())
                    {
                        return Ok(false);
                    }
                    // Queued originals predate the stopped-ingress barrier. They
                    // must reach their real codecs before its admitted fence.
                    if !self
                        .common_state()?
                        .engine(operation.origin().epoch)?
                        .ingress_empty()
                    {
                        return Ok(false);
                    }
                    if self
                        .common_state()?
                        .engine(operation.origin().epoch)?
                        .queue_usage()
                        .packets
                        != 0
                    {
                        return Ok(false);
                    }
                    let admitted = Boundary::capture(
                        self.common_state()?.engine(operation.origin().epoch)?,
                        NativeOrigin::new(&self.info, old, records::Direction::Send),
                        true,
                    )?;
                    let target = common_scope(ticket.epoch, config)?;
                    self.records.stage_data(target).map_err(protocol)?;
                    self.target = Some(target);
                    self.transaction_origin = Some(old);
                    runtime.sent = Some(admitted);
                    work.admitted = Some(admitted);
                    work.applied = true;
                }
                let fence = work
                    .admitted
                    .ok_or_else(|| protocol("common Stage lost fence"))?
                    .fence()?;
                let owner::DataOwner::Common(state) = &mut self.owner;
                Ok(state.complete_action(
                    &mut self.control,
                    &mut work.action,
                    transactions::Completion::Staged { admitted: &fence },
                    duration(now),
                )? == transactions::Progress::Advanced)
            }
            transaction::Event::Drain { local, peer } => {
                if !work.applied {
                    self.validate_common_fence()?;
                    let engine = self.common_state()?.engine(operation.origin().epoch)?;
                    if !self.control.native_receipts_drained(envelope_scope(old))?
                        || !engine.drained().map_err(protocol)?
                        || !self.native.is_empty()
                        || runtime.sealed.is_some()
                        || runtime.unsealed.is_some()
                        || runtime.raw_control.is_some()
                        || runtime.pending_feedback.is_some()
                        || runtime.pending_ingress.is_some()
                        || runtime
                            .connection_input
                            .as_ref()
                            .is_some_and(|input| !input.is_empty())
                    {
                        return Ok(false);
                    }
                    let sent = Boundary::capture(
                        engine,
                        NativeOrigin::new(&self.info, old, records::Direction::Send),
                        true,
                    )?;
                    let delivered = Boundary::capture(
                        engine,
                        NativeOrigin::new(&self.info, old, records::Direction::Receive),
                        false,
                    )?;
                    let counts = engine.native_counts().map_err(protocol)?;
                    if counts.prepared != counts.committed {
                        return Err(protocol("common physical custody differs from extraction"));
                    }
                    if runtime.sent != Some(sent) || sent.fence()? != *local {
                        return Err(protocol("common local barrier moved"));
                    }
                    if delivered.fence()? != *peer {
                        return Ok(false);
                    }
                    runtime.delivered = Some(delivered);
                    work.applied = true;
                }
                let sent = runtime
                    .sent
                    .ok_or_else(|| protocol("common send witness missing"))?
                    .fence()?;
                let delivered = runtime
                    .delivered
                    .ok_or_else(|| protocol("common physical witness missing"))?
                    .fence()?;
                let owner::DataOwner::Common(state) = &mut self.owner;
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
                    if !self.common_barrier_ready(runtime, old)? {
                        return Ok(false);
                    }
                    let value = *self.common_state()?.peer().active_config();
                    runtime.contract.resolve(value)?;
                    let target = common_scope(ticket.epoch, &value)?;
                    if self.target != Some(target)
                        || self.records.active_data() != old
                        || self.source_scope != old
                        || self.feedback_scope != old
                    {
                        return Err(protocol("common Commit physical scopes"));
                    }
                    self.bucket.refill(now)?;
                    self.records.activate_data(target).map_err(protocol)?;
                    self.source_scope = target;
                    self.feedback_scope = target;
                    let local = value
                        .descriptor()
                        .local(common_contract::mg_role(self.info.role));
                    self.bucket.rate = local.send().common().bytes_per_second();
                    if let Some(serializer) = runtime.serializer.as_mut() {
                        serializer.observe(now, self.bucket.rate)?;
                    }
                    self.bucket.burst = local.send().common().burst_bytes();
                    self.bucket.tokens = self.bucket.tokens.min(self.bucket.burst as u128 * SCALE);
                    self.config.path_mtu = value.descriptor().path_mtu();
                    work.applied = true;
                }
                self.complete_common_applied(work, now)
            }
            transaction::Event::Retired(epoch) => {
                if !work.applied {
                    if *epoch != operation.origin().epoch {
                        return Err(protocol("common Retired old epoch"));
                    }
                    if !self.common_barrier_ready(runtime, old)? {
                        return Ok(false);
                    }
                    if self.records.active_data() == old {
                        return Err(protocol("common Retire before physical promotion"));
                    }
                    self.records.retire_data(old).map_err(protocol)?;
                    work.applied = true;
                }
                let done = self.complete_common_applied(work, now)?;
                if done {
                    self.target = None;
                    self.transaction_origin = None;
                    runtime.sent = None;
                    runtime.delivered = None;
                }
                Ok(done)
            }
            transaction::Event::Aborted(_) => {
                if !work.applied {
                    if self.records.active_data() != old
                        || self.source_scope != old
                        || self.feedback_scope != old
                    {
                        return Err(protocol("common abort after promotion"));
                    }
                    if let Some(target) = self.target {
                        self.records.cancel_staged_data(target).map_err(protocol)?;
                    }
                    work.applied = true;
                }
                let done = self.complete_common_applied(work, now)?;
                if done {
                    self.target = None;
                    self.transaction_origin = None;
                    runtime.sent = None;
                    runtime.delivered = None;
                }
                Ok(done)
            }
            transaction::Event::Uncertain(_) => {
                work.applied = true;
                self.complete_common_applied(work, now)
            }
            transaction::Event::Failed => {
                work.applied = true;
                let done = self.complete_common_applied(work, now)?;
                self.terminal = Some(StopReason::PolicyTimeout);
                if let Some(request) = runtime.request.take() {
                    let _ = request.reply.send(Err(SwitchError::Closed));
                }
                Ok(done)
            }
        }
    }
    fn complete_common_applied(&mut self, work: &mut ActionWork, now: u64) -> io::Result<bool> {
        let owner::DataOwner::Common(state) = &mut self.owner;
        Ok(state.complete_action(
            &mut self.control,
            &mut work.action,
            transactions::Completion::Applied,
            duration(now),
        )? == transactions::Progress::Advanced)
    }
    fn common_barrier_ready(&self, runtime: &common::Runtime, old: Scope) -> io::Result<bool> {
        if !self.native.is_empty()
            || runtime.sealed.is_some()
            || runtime.unsealed.is_some()
            || runtime.raw_control.is_some()
            || runtime.pending_feedback.is_some()
            || runtime.pending_ingress.is_some()
            || runtime
                .connection_input
                .as_ref()
                .is_some_and(|input| !input.is_empty())
        {
            return Ok(false);
        }
        let engine = self.common_state()?.engine(core::Epoch(old.epoch.0))?;
        if !self.control.native_receipts_drained(envelope_scope(old))?
            || !engine.drained().map_err(protocol)?
        {
            return Ok(false);
        }
        let sent = Boundary::capture(
            engine,
            NativeOrigin::new(&self.info, old, records::Direction::Send),
            true,
        )?;
        let delivered = Boundary::capture(
            engine,
            NativeOrigin::new(&self.info, old, records::Direction::Receive),
            false,
        )?;
        if runtime.sent != Some(sent) || runtime.delivered != Some(delivered) {
            return Err(protocol("common completed barrier moved"));
        }
        Ok(true)
    }
    pub(super) fn validate_common_fence(&self) -> io::Result<()> {
        let state = self.common_state()?;
        let (Some(operation), Some(peer)) = (state.peer().operation(), state.peer().peer_fence())
        else {
            return Ok(());
        };
        if state.peer().reader(operation.origin().epoch).is_none() {
            return Ok(());
        }
        let engine = state.engine(operation.origin().epoch)?;
        let counts = engine.native_counts().map_err(protocol)?;
        if counts.prepared.len() != peer.counts().len()
            || counts.committed.len() != peer.counts().len()
        {
            return Err(protocol("common peer fence width"));
        }
        // These are only excess checks while ingress is live. Equality is used
        // exclusively in Drain after the complete real generation is drained.
        if counts
            .prepared
            .iter()
            .zip(peer.counts())
            .any(|(actual, limit)| actual > limit)
            || counts
                .committed
                .iter()
                .zip(peer.counts())
                .any(|(actual, limit)| actual > limit)
        {
            return Err(protocol("common physical native exceeds peer fence"));
        }
        Ok(())
    }
    fn service_common_state(&mut self, now: u64) -> io::Result<()> {
        let owner::DataOwner::Common(state) = &mut self.owner;
        state.service(&mut self.control, duration(now))?;
        Ok(())
    }
    pub(super) fn common_state(&self) -> io::Result<&transactions::CommonState> {
        match &self.owner {
            owner::DataOwner::Common(state) => Ok(state),
        }
    }
    pub(super) fn common_state_mut(&mut self) -> io::Result<&mut transactions::CommonState> {
        match &mut self.owner {
            owner::DataOwner::Common(state) => Ok(state),
        }
    }
}
fn original_scope(operation: transaction::Operation) -> Scope {
    record_scope(operation.origin())
}
pub(super) fn record_scope(origin: control::Scope) -> Scope {
    Scope {
        epoch: security::Epoch(origin.epoch.0),
        configuration: security::ConfigDigest(origin.digest.0),
    }
}
pub(super) fn common_scope(epoch: core::Epoch, value: &C) -> io::Result<Scope> {
    Ok(Scope {
        epoch: security::Epoch(epoch.0),
        // The concrete canonical encoder validates the same complete value and
        // domain using bounded stack storage; no per-record Vec is needed.
        configuration: security::ConfigDigest(value.digest().map_err(protocol)?.0),
    })
}
fn outcome_operation(outcome: transactions::Outcome) -> transaction::Operation {
    match outcome {
        transactions::Outcome::Retired { operation, .. }
        | transactions::Outcome::Aborted { operation, .. } => operation,
    }
}
