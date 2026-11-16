//! Selected same-generation reuse on the existing sole Common/Control owner.
use super::*;
/// Actual local same-owner retirement phase, separate from global completion.
pub use l2tunnel::record_engine::connection_reuse::ConnectionReusePhase;
use l2tunnel::{
    connection_records::retirement::command::{Command as Wire, Kind},
    record_engine::connection_reuse::ConnectionReuse,
};
use l2tunnel_packet::FlowKey;

/// Explicit selected-controller admission or local terminal outcome.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConnectionReuseError {
    /// Actual profile/current owner does not install this supported reuse path.
    Unsupported,
    /// Original bounded admission or another operation currently owns the slot.
    Busy,
    /// The actual request receiver ended before it accepted this request.
    Closed,
    /// Owner, key, lifetime or local retained binding failed admission.
    Invalid,
    /// The original local cap expired before request acceptance.
    Expired,
    /// Accepted work may have affected the peer; completion is not known locally.
    OutcomeUnknown,
    /// The actual current owner or authenticated protocol invariant failed.
    Protocol,
}
/// Concrete local completion after crossed fences and activation confirmation.
/// This does not assert simultaneous peer completion or native application use.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConnectionReuseOutcome {
    /// Actual unchanged independent owner index.
    pub owner: u16,
    /// Retired route incarnation of that same owner.
    pub old_incarnation: u64,
    /// Checked next route incarnation installed on the retained owner.
    pub next_incarnation: u64,
    /// Nonwrapping selected-operation attempt within this session.
    pub attempt: u64,
    /// Original data epoch, unchanged by this reuse operation.
    pub epoch: core::Epoch,
    /// Full original complete configuration, unchanged by slot reuse.
    pub configuration: core::ConfigDigest,
}
/// Read-only actual local controller state, retaining original operation scope.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConnectionReuseSnapshot {
    /// Full retained operation with local role and original local cap.
    pub operation: transaction::Operation,
    /// Actual selected independent owner index.
    pub owner: u16,
    /// Exact retired native flow claim.
    pub old_key: FlowKey,
    /// Exact closed-installed next flow claim.
    pub next_key: FlowKey,
    /// Route incarnation before the operation.
    pub old_incarnation: u64,
    /// Checked proposed/installed next incarnation, not itself proof of success.
    pub next_incarnation: u64,
    /// Actual local semantic phase or latched failure.
    pub phase: ConnectionReusePhase,
    /// Original local expiry in this Driver's injected microsecond domain.
    pub original_deadline_micros: u64,
}
pub(super) struct Request {
    owner: u16,
    old_key: FlowKey,
    next_key: FlowKey,
    deadline: Instant,
}
pub(super) type Reply = oneshot::Sender<Result<ConnectionReuseOutcome, ConnectionReuseError>>;
pub(super) const HISTORY: usize = 32;
/// Exact bounded retired identity; exhaustion refuses before another STOP.
#[derive(Clone, Copy)]
pub(super) struct Tombstone {
    operation: transaction::Operation,
    old_key: FlowKey,
    reply: Wire,
}
/// One explicitly selected reservation; no payload is allocated for other profiles.
pub(super) struct Installed {
    reuse: Option<Controller>,
    reuse_attempt: u64,
    reuse_history: [Option<Tombstone>; HISTORY],
    reuse_history_len: usize,
}
impl Installed {
    pub(super) fn capacity_bytes() -> io::Result<usize> {
        std::alloc::Layout::array::<Self>(1)
            .map(|layout| layout.size())
            .map_err(io::Error::other)
    }
    pub(super) fn new() -> Self {
        Self {
            reuse: None,
            reuse_attempt: 0,
            reuse_history: [None; HISTORY],
            reuse_history_len: 0,
        }
    }
    pub(super) fn controller(&self) -> Option<&Controller> {
        self.reuse.as_ref()
    }
}
pub(super) struct Controller {
    state: ConnectionReuse,
    output: Option<(control_owner::Token, Wire, bool)>,
    replay: Option<Wire>,
    reply: Option<Reply>,
    deadline: u64,
    epoch: core::Epoch,
    digest: core::ConfigDigest,
    cached: bool,
    failed: bool,
}
impl Drop for Controller {
    fn drop(&mut self) {
        if let Some(reply) = self.reply.take() {
            let _ = reply.send(Err(ConnectionReuseError::OutcomeUnknown));
        }
    }
}
impl Controller {
    pub(super) fn active(&self) -> bool {
        !self.state.completed()
            || self.output.is_some()
            || self.replay.is_some()
            || self.reply.is_some()
    }
    pub(super) fn deadline(&self) -> u64 {
        self.deadline
    }
    pub(super) fn snapshot(&self) -> ConnectionReuseSnapshot {
        ConnectionReuseSnapshot {
            operation: self.state.operation(),
            owner: self.state.owner(),
            old_key: self.state.old_key(),
            next_key: self.state.next_key(),
            old_incarnation: self.state.old_incarnation(),
            next_incarnation: self.state.next_incarnation(),
            phase: if self.failed {
                ConnectionReusePhase::Failed
            } else {
                self.state.phase()
            },
            original_deadline_micros: self.deadline,
        }
    }
}
impl common::CommonControlHandle {
    /// The original local caller cap includes channel wait and is never renewed.
    pub async fn reuse_until(
        &self,
        owner: u16,
        old_key: FlowKey,
        next_key: FlowKey,
        original_deadline: Instant,
    ) -> Result<ConnectionReuseOutcome, ConnectionReuseError> {
        if Instant::now() >= original_deadline {
            return Err(ConnectionReuseError::Expired);
        }
        let (tx, rx) = oneshot::channel();
        self.0
            .try_send(common::Command::Reuse(
                Request {
                    owner,
                    old_key,
                    next_key,
                    deadline: original_deadline,
                },
                tx,
            ))
            .map_err(|e| match e {
                mpsc::error::TrySendError::Full(_) => ConnectionReuseError::Busy,
                mpsc::error::TrySendError::Closed(_) => ConnectionReuseError::Closed,
            })?;
        rx.await
            .unwrap_or(Err(ConnectionReuseError::OutcomeUnknown))
    }
}
fn tick(now: u64) -> transaction::Tick {
    transaction::Tick(now / 1000)
}
fn identity(info: &member::Info) -> transaction::Identity {
    let role = if info.role == security::Role::Initiator {
        mg::Role::Client
    } else {
        mg::Role::Server
    };
    transaction::Identity {
        session: mg::SessionId(info.binding.session.0),
        role,
        local: mg::EndpointId(if role == mg::Role::Client { 1 } else { 2 }),
        remote: mg::EndpointId(if role == mg::Role::Client { 2 } else { 1 }),
        lane: mg::LaneId(LANE),
    }
}
fn scope(scope: Scope) -> control::Scope {
    control::Scope {
        epoch: core::Epoch(scope.epoch.0),
        digest: core::ConfigDigest(scope.configuration.0),
    }
}
impl Driver {
    pub(super) fn request_connection_reuse(
        &mut self,
        now: u64,
        request: Request,
        reply: Reply,
    ) -> io::Result<()> {
        let validate = (|| {
            let runtime = self
                .common
                .as_deref()
                .ok_or(ConnectionReuseError::Unsupported)?;
            if !runtime.contract.connection_reuse() || self.info.role != security::Role::Initiator {
                return Err(ConnectionReuseError::Unsupported);
            }
            let installed = runtime
                .reuse_owner
                .as_ref()
                .ok_or(ConnectionReuseError::Unsupported)?;
            if installed.reuse_history_len >= HISTORY
                || installed.reuse.as_ref().is_some_and(Controller::active)
                || runtime.request.is_some()
                || runtime.action.is_some()
                || self
                    .common_state()
                    .map_err(|_| ConnectionReuseError::Protocol)?
                    .peer()
                    .operation()
                    .is_some()
            {
                return Err(ConnectionReuseError::Busy);
            }
            let cap = clock(self.origin, request.deadline)
                .map_err(|_| ConnectionReuseError::Invalid)?
                .min(self.lease);
            if cap <= now {
                return Err(ConnectionReuseError::Expired);
            }
            let maximum = runtime.contract.settings().max_operation_ms;
            if cap.saturating_sub(now) > maximum.saturating_mul(1000) {
                return Err(ConnectionReuseError::Invalid);
            }
            let epoch = core::Epoch(self.source_scope.epoch.0);
            let incarnation = self
                .common_state()
                .map_err(|_| ConnectionReuseError::Protocol)?
                .engine(epoch)
                .map_err(|_| ConnectionReuseError::Protocol)?
                .connection_route_incarnation(request.owner)
                .map_err(|_| ConnectionReuseError::Unsupported)?;
            if self
                .common_state()
                .map_err(|_| ConnectionReuseError::Protocol)?
                .engine(epoch)
                .map_err(|_| ConnectionReuseError::Protocol)?
                .connection_owner_key(request.owner)
                .map_err(|_| ConnectionReuseError::Invalid)?
                != Some(request.old_key)
                || self
                    .common_state()
                    .map_err(|_| ConnectionReuseError::Protocol)?
                    .engine(epoch)
                    .map_err(|_| ConnectionReuseError::Protocol)?
                    .connection_claims_key(request.next_key)
            {
                return Err(ConnectionReuseError::Invalid);
            }
            let attempt = installed
                .reuse_attempt
                .checked_add(1)
                .ok_or(ConnectionReuseError::Protocol)?;
            let command = Wire::begin(
                identity(&self.info),
                scope(self.source_scope),
                attempt,
                request.owner,
                incarnation,
                request.old_key,
                request.next_key,
                tick(now),
                tick(cap),
                tick(self.lease),
                maximum,
            )
            .map_err(|_| ConnectionReuseError::Invalid)?;
            let state = ConnectionReuse::from_local(command, tick(now), tick(self.lease), maximum)
                .map_err(|_| ConnectionReuseError::Invalid)?;
            let cap = state
                .operation()
                .expires()
                .0
                .checked_mul(1000)
                .ok_or(ConnectionReuseError::Invalid)?;
            Ok((state, cap, attempt, epoch))
        })();
        match validate {
            Ok((state, cap, attempt, epoch)) => {
                let digest = core::ConfigDigest(self.source_scope.configuration.0);
                let runtime = self
                    .common
                    .as_deref_mut()
                    .ok_or_else(|| protocol("reuse runtime absent"))?;
                let installed = runtime
                    .reuse_owner
                    .as_mut()
                    .ok_or_else(|| protocol("reuse reservation absent"))?;
                installed.reuse_attempt = attempt;
                installed.reuse = Some(Controller {
                    state,
                    output: None,
                    replay: None,
                    reply: Some(reply),
                    deadline: cap,
                    epoch,
                    digest,
                    cached: false,
                    failed: false,
                });
                runtime.observation_dirty = true;
                Ok(())
            }
            Err(error) => {
                let _ = reply.send(Err(error));
                Ok(())
            }
        }
    }
    pub(super) fn admit_connection_reuse(
        &self,
        now: u64,
        envelope: control::Envelope<'_>,
    ) -> io::Result<Wire> {
        let runtime = self
            .common
            .as_deref()
            .ok_or_else(|| protocol("reuse on another backend"))?;
        if !runtime.contract.connection_reuse() {
            return Err(invalid("slot reuse not authenticated by selected profile"));
        }
        let installed = runtime
            .reuse_owner
            .as_ref()
            .ok_or_else(|| protocol("reuse reservation absent"))?;
        let attempt =
            Wire::attempt_hint(envelope).ok_or_else(|| protocol("short reuse command"))?;
        let retained = installed
            .reuse
            .as_ref()
            .filter(|c| c.state.operation().ticket().attempt == attempt)
            .map(|c| c.state.operation())
            .or_else(|| {
                installed
                    .reuse_history
                    .iter()
                    .flatten()
                    .find(|c| c.operation.ticket().attempt == attempt)
                    .map(|c| c.operation)
            });
        Wire::admit(
            envelope,
            mg::Ingress::AuthenticatedManagement {
                session: mg::SessionId(self.info.binding.session.0),
                lane: mg::LaneId(LANE),
                sender: if self.info.role == security::Role::Initiator {
                    mg::Role::Server
                } else {
                    mg::Role::Client
                },
            },
            identity(&self.info),
            retained.map_or(scope(self.source_scope), |operation| operation.origin()),
            tick(now),
            tick(self.lease),
            runtime.contract.settings().max_operation_ms,
            retained,
        )
        .map_err(protocol)
    }
    pub(super) fn receive_connection_reuse(&mut self, now: u64, command: Wire) -> io::Result<()> {
        let mut runtime = self
            .common
            .take()
            .ok_or_else(|| protocol("reuse runtime absent"))?;
        let result = (|| {
            let runtime = &mut *runtime;
            let installed = runtime
                .reuse_owner
                .as_mut()
                .ok_or_else(|| protocol("reuse reservation absent"))?;
            if let Some(state) = installed.reuse.as_mut() {
                if state.state.operation().ticket().attempt == command.operation().ticket().attempt
                {
                    // Expired completed retries are acknowledged by the retained Control
                    // owner but never gain a new semantic output lifetime.
                    if state.state.completed() && now >= state.deadline {
                        return Ok(());
                    }
                    let duplicate = command.kind() as u8 <= state.state.peer_stage() as u8;
                    state.state.receive(command).map_err(protocol)?;
                    if duplicate && state.output.is_none() && state.state.outgoing().is_none() {
                        state.replay = state.state.last_confirmed();
                    }
                    runtime.observation_dirty = true;
                    return Ok(());
                }
                if state.active() {
                    return Err(protocol("conflicting live reuse operation"));
                }
            }
            if let Some(retired) = installed.reuse_history.iter().flatten().find(|entry| {
                entry.operation.ticket().attempt == command.operation().ticket().attempt
            }) {
                // A later attempt or epoch cannot reopen an exact completed
                // operation. The cached terminal response remains tombstoned;
                // only the current live controller may retransmit before its cap.
                if retired.reply.operation() != retired.operation {
                    return Err(protocol("reuse tombstone identity changed"));
                }
                return Ok(());
            }
            if installed.reuse_history_len >= HISTORY
                || command.kind() != Kind::Stop
                || self.info.role != security::Role::Responder
                || command.operation().ticket().attempt <= installed.reuse_attempt
                || runtime.request.is_some()
                || runtime.action.is_some()
                || self.common_state()?.peer().operation().is_some()
            {
                return Err(protocol("stale/conflicting reuse STOP"));
            }
            let maximum = runtime.contract.settings().max_operation_ms;
            let state =
                ConnectionReuse::from_peer_stop(command, tick(now), tick(self.lease), maximum)
                    .map_err(protocol)?;
            let deadline = state
                .operation()
                .expires()
                .0
                .checked_mul(1000)
                .ok_or_else(exhausted)?;
            installed.reuse_attempt = command.operation().ticket().attempt;
            installed.reuse = Some(Controller {
                state,
                output: None,
                replay: None,
                reply: None,
                deadline,
                epoch: core::Epoch(self.source_scope.epoch.0),
                digest: core::ConfigDigest(self.source_scope.configuration.0),
                cached: false,
                failed: false,
            });
            runtime.observation_dirty = true;
            Ok(())
        })();
        self.common = Some(runtime);
        result
    }
    pub(super) fn progress_connection_reuse(
        &mut self,
        runtime: &mut common::Runtime,
        now: u64,
    ) -> io::Result<()> {
        let Some(installed) = runtime.reuse_owner.as_mut() else {
            return Ok(());
        };
        let Some(mut controller) = installed.reuse.take() else {
            return Ok(());
        };
        let result = (|| {
            if !controller.active() {
                return Ok(());
            }
            if now >= controller.deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "original connection reuse cap",
                ));
            }
            if let Some((token, command, semantic)) = controller.output
                && self.control.confirmed(token, duration(now))?
            {
                self.control.retire(token, duration(now))?;
                if semantic {
                    controller
                        .state
                        .outgoing_confirmed(command)
                        .map_err(protocol)?;
                }
                controller.output = None;
            }
            // This is a concrete external-custody guard, not an injected boolean.
            // All original retained input remains serviceable until this is true.
            let external = runtime.sealed.is_none()
                && runtime.unsealed.is_none()
                && runtime.raw_control.is_none()
                && runtime.pending_feedback.is_none()
                && runtime.pending_ingress.is_none()
                && runtime
                    .connection_input
                    .as_ref()
                    .is_none_or(common_connections::Input::is_empty)
                && self.native.is_empty();
            if external {
                match self
                    .common_state_mut()?
                    .entry(controller.epoch)?
                    .progress_connection_reuse(
                        &mut controller.state,
                        l2tunnel::record_engine::Tick(now),
                    ) {
                    Ok(()) => {}
                    Err(l2tunnel::record_bank::Error::Engine(
                        l2tunnel::record_engine::Error::Connections(
                            l2tunnel::connection_records::Error::RetirementBusy,
                        ),
                    )) => {}
                    Err(error) => return Err(protocol(error)),
                }
            }
            if controller.output.is_none()
                && let Some((command, semantic)) = controller
                    .state
                    .outgoing()
                    .map(|c| (c, true))
                    .or_else(|| controller.replay.map(|c| (c, false)))
            {
                let mut bytes = [0; l2tunnel::connection_records::retirement::command::MAX_BYTES];
                let length = command.encode(&mut bytes).map_err(protocol)?;
                if let Some(token) = self.control.submit(
                    scope(self.source_scope),
                    control::Body::ProfileControl {
                        tag: control::ProfileTag::SlotReuseV1,
                        bytes: &bytes[..length],
                    },
                    duration(now),
                    duration(controller.deadline),
                    false,
                )? {
                    controller.output = Some((token, command, semantic));
                    if !semantic {
                        controller.replay = None;
                    }
                }
            }
            if controller.state.completed()
                && controller.output.is_none()
                && controller.replay.is_none()
            {
                if !controller.cached {
                    let index = installed.reuse_history_len;
                    let target = installed
                        .reuse_history
                        .get_mut(index)
                        .ok_or_else(|| protocol("reuse tombstone capacity"))?;
                    *target = Some(Tombstone {
                        operation: controller.state.operation(),
                        old_key: controller.state.old_key(),
                        reply: controller
                            .state
                            .last_confirmed()
                            .ok_or_else(|| protocol("reuse missing confirmed terminal response"))?,
                    });
                    installed.reuse_history_len = installed
                        .reuse_history_len
                        .checked_add(1)
                        .ok_or_else(exhausted)?;
                    controller.cached = true;
                }
                if let Some(reply) = controller.reply.take() {
                    let _ = reply.send(Ok(ConnectionReuseOutcome {
                        owner: controller.state.owner(),
                        old_incarnation: controller.state.old_incarnation(),
                        next_incarnation: controller.state.next_incarnation(),
                        attempt: controller.state.operation().ticket().attempt,
                        epoch: controller.epoch,
                        configuration: controller.digest,
                    }));
                }
            }
            runtime.observation_dirty = true;
            Ok(())
        })();
        if result.is_err() {
            controller.failed = true;
            if let Some(reply) = controller.reply.take() {
                let _ = reply.send(Err(ConnectionReuseError::OutcomeUnknown));
            }
        }
        installed.reuse = Some(controller);
        result
    }
}

impl Driver {
    pub(super) fn reject_retired_connection_native(
        &self,
        epoch: core::Epoch,
        bytes: &[u8],
    ) -> io::Result<bool> {
        let Some(runtime) = &self.common else {
            return Ok(false);
        };
        let Some(installed) = runtime.reuse_owner.as_ref() else {
            return Ok(false);
        };
        if installed.reuse_history_len == 0 {
            return Ok(false);
        }
        let engine = self.common_state()?.engine(epoch)?;
        let policy = engine
            .configuration()
            .descriptor()
            .direction(common_contract::mg_role(self.info.role))
            .common()
            .pipeline();
        let class = l2tunnel_packet::classify(runtime.contract.native_layer(), bytes, policy.parse)
            .map_err(protocol)?;
        Ok(installed
            .reuse_history
            .iter()
            .flatten()
            .any(|entry| entry.old_key == class.key)
            && !engine.connection_claims_key(class.key))
    }
}
