//! Private composition prerequisite; selected control provenance is not installed.
use super::*;
use crate::connection_records::{self as records, retirement};
use l2tunnel_management::transaction;

/// Original actual Pipeline registration plus its collection-owned operation.
pub(crate) struct ConnectionRetirement {
    token: retirement::Retirement,
    key: pipeline::FlowKey,
    binding: pipeline::Binding,
    installed: Option<retirement::Installed>,
}
impl Engine {
    fn connection_retirement_internal_empty(&self) -> bool {
        self.pipeline.usage().packets == 0
            && self.ingress_empty()
            && self.pending.is_none()
            && self.fragments.as_ref().is_none_or(fragment::State::drained)
            && matches!(&self.owner, Owner::Connections(owner)
                if !owner.has_output() && owner.pending_deadline().is_none())
    }
    /// The runtime must stop new admission and retain its actual external I/O proof.
    /// An actual Operation binds this hook; this call does not authenticate its peer.
    pub(crate) fn begin_connection_retirement(
        &mut self,
        now: Tick,
        index: u16,
        key: pipeline::FlowKey,
        operation: transaction::Operation,
    ) -> Result<ConnectionRetirement, Error> {
        self.advance(now)?;
        if !self.connection_retirement_internal_empty() {
            return Err(Error::Connections(records::Error::RetirementBusy));
        }
        let binding = self
            .pipeline
            .flow(&key)
            .ok_or(Error::Connections(records::Error::Binding))?
            .binding;
        if binding.channel != index {
            return Err(Error::Connections(records::Error::Binding));
        }
        let scope = retirement::Scope::from_operation(
            owner::recovery_context(self.context),
            self.digest,
            operation,
        )
        .map_err(Error::Connections)?;
        let Owner::Connections(owner) = &mut self.owner else {
            return Err(Error::Unsupported(Capability::FlowReuse));
        };
        let id = owner.collection.owner(index).map_err(Error::Connections)?;
        let token = owner
            .collection
            .begin_retirement(id, key, scope, duration(now))
            .map_err(Error::Connections)?;
        Ok(ConnectionRetirement {
            token,
            key,
            binding,
            installed: None,
        })
    }
    /// Internal custody is necessary; external held/deferred records remain runtime-owned.
    pub(crate) fn connection_retirement_fence(
        &self,
        now: Tick,
        token: &ConnectionRetirement,
    ) -> Result<retirement::Fence, Error> {
        self.healthy()?;
        if !self.connection_retirement_internal_empty() {
            return Err(Error::Connections(records::Error::RetirementBusy));
        }
        let Owner::Connections(owner) = &self.owner else {
            return Err(Error::Unsupported(Capability::FlowReuse));
        };
        owner
            .collection
            .retirement_fence(duration(now), &token.token)
            .map_err(Error::Connections)
    }
    /// Only authenticated selected-control ingress may supply this exact peer fence.
    pub(crate) fn accept_connection_retirement_fence_at(
        &mut self,
        received: Tick,
        observed: Tick,
        token: &ConnectionRetirement,
        peer: retirement::Fence,
    ) -> Result<(), Error> {
        self.advance(observed)?;
        let Owner::Connections(owner) = &mut self.owner else {
            return Err(Error::Unsupported(Capability::FlowReuse));
        };
        owner
            .collection
            .accept_retirement_fence_at(duration(received), duration(observed), &token.token, peer)
            .map_err(Error::Connections)
    }
    /// Retire the exact local Pipeline registration and passive ACK history together.
    /// The caller additionally proves external carrier/native/deferred custody absent.
    pub(crate) fn install_connection_reuse(
        &mut self,
        now: Tick,
        token: &mut ConnectionRetirement,
    ) -> Result<retirement::Installed, Error> {
        self.advance(now)?;
        if !self.connection_retirement_internal_empty() {
            return Err(Error::Connections(records::Error::RetirementBusy));
        }
        let expected = match &self.owner {
            Owner::Connections(owner) => owner
                .collection
                .preflight_reuse(duration(now), &token.token)
                .map_err(Error::Connections)?,
            _ => return Err(Error::Unsupported(Capability::FlowReuse)),
        };
        if let Some(installed) = token.installed {
            if installed != expected || self.pipeline.flow(&token.key).is_some() {
                return Err(Error::Invariant);
            }
            return Ok(installed);
        }
        if self.pipeline.flow(&token.key).map(|flow| flow.binding) != Some(token.binding) {
            return Err(Error::Connections(records::Error::Binding));
        }
        let actual = if let Some(ingress) = &mut self.ingress {
            ingress
                .retire_drained(&mut self.pipeline, &token.key)
                .map_err(Error::Ingress)?
        } else {
            self.pipeline
                .retire_drained(&token.key)
                .map_err(Error::Pipeline)?
        };
        if actual != token.binding {
            return self.fail(Error::Invariant);
        }
        let Owner::Connections(owner) = &mut self.owner else {
            return self.fail(Error::Invariant);
        };
        // No collection mutation occurred after the complete preflight above.
        let installed = match owner.collection.install_reuse(duration(now), &token.token) {
            Ok(installed) if installed == expected => installed,
            _ => return self.fail(Error::Invariant),
        };
        token.installed = Some(installed);
        Ok(installed)
    }
    /// Does not authorize external resume until genuine peer installation is confirmed.
    pub(crate) fn activate_connection_reuse_after_confirmation(
        &mut self,
        now: Tick,
        token: &ConnectionRetirement,
        peer: retirement::Installed,
    ) -> Result<(), Error> {
        self.advance(now)?;
        if token.installed.is_none()
            || !self.connection_retirement_internal_empty()
            || self.pipeline.flow(&token.key).is_some()
        {
            return Err(Error::Connections(records::Error::RetirementBusy));
        }
        let Owner::Connections(owner) = &mut self.owner else {
            return Err(Error::Unsupported(Capability::FlowReuse));
        };
        owner
            .collection
            .activate_reuse_after_confirmation(duration(now), &token.token, peer)
            .map_err(Error::Connections)
    }
}

/// Installed selected-control progress, without any second data/recovery owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConnectionReusePhase {
    /// Original admission is being stopped under the original operation cap.
    Stopping,
    /// Actual old source, feedback, native and crossed-fence debt remains live.
    Draining,
    /// The next key/incarnation is installed while fresh admission stays closed.
    Installed,
    /// Matching peer installation is known and activation is being confirmed.
    Activating,
    /// Concrete local semantic prerequisites completed; external output may remain.
    Completed,
    /// The actual runtime latched failure; this does not imply rollback.
    Failed,
}
/// One immutable same-generation operation and its actual issuing owner witness.
pub struct ConnectionReuse {
    local: retirement::command::Command,
    token: Option<ConnectionRetirement>,
    peer_stopped: Option<u64>,
    peer_fence: Option<retirement::command::Command>,
    local_fence: Option<retirement::Fence>,
    peer_installed: Option<retirement::command::Command>,
    peer_stage: retirement::command::Kind,
    outgoing: Option<retirement::command::Command>,
    complete: bool,
    next_bound: bool,
    activated: bool,
    last_sent: Option<retirement::command::Kind>,
    last_confirmed: Option<retirement::command::Command>,
}
impl ConnectionReuse {
    /// Start from an opaque local request or genuinely attested peer STOP.
    fn new(
        command: retirement::command::Command,
        now: l2tunnel_management::transaction::Tick,
        session: l2tunnel_management::transaction::Tick,
        maximum_ms: u64,
        remote: bool,
    ) -> Result<Self, Error> {
        use retirement::command::Kind;
        if command.kind() != Kind::Stop {
            return Err(Error::Connections(records::Error::RetirementConflict));
        }
        let local = if remote {
            command
                .mirrored(now, session, maximum_ms)
                .map_err(Error::Connections)?
        } else {
            command
        };
        if (local.operation().identity().role == Role::Server) != remote {
            return Err(Error::Connections(records::Error::RetirementConflict));
        }
        Ok(Self {
            local,
            token: None,
            peer_stopped: remote.then_some(command.admitted()),
            peer_fence: None,
            local_fence: None,
            peer_installed: None,
            peer_stage: Kind::Stop,
            outgoing: None,
            complete: false,
            next_bound: false,
            activated: false,
            last_sent: None,
            last_confirmed: None,
        })
    }
    /// Begin from an opaque local proposal; the actual Engine still owns all checks.
    pub fn from_local(
        command: retirement::command::Command,
        now: transaction::Tick,
        session: transaction::Tick,
        maximum_ms: u64,
    ) -> Result<Self, Error> {
        Self::new(command, now, session, maximum_ms, false)
    }
    /// Begin only from an attested opaque peer STOP with its frozen local cap.
    pub fn from_peer_stop(
        command: retirement::command::Command,
        now: transaction::Tick,
        session: transaction::Tick,
        maximum_ms: u64,
    ) -> Result<Self, Error> {
        Self::new(command, now, session, maximum_ms, true)
    }
    fn queue(&mut self, kind: retirement::command::Kind, admitted: u64, written: u64) {
        if self.outgoing.is_none() && self.last_sent.is_none_or(|old| (old as u8) < kind as u8) {
            self.outgoing = Some(self.local.phase(kind, admitted, written));
        }
    }
    /// Full original operation, including local role and unchanged local cap.
    pub fn operation(&self) -> transaction::Operation {
        self.local.operation()
    }
    /// Actual independent owner index retained by this operation.
    pub fn owner(&self) -> u16 {
        self.local.owner()
    }
    /// Exact original native flow claim.
    pub fn old_key(&self) -> pipeline::FlowKey {
        self.local.old_key()
    }
    /// Exact proposed next flow claim, installed while admission is closed.
    pub fn next_key(&self) -> pipeline::FlowKey {
        self.local.next_key()
    }
    /// Original route incarnation of the unchanged endpoint owner.
    pub fn old_incarnation(&self) -> u64 {
        self.local.incarnation()
    }
    /// Checked next incarnation, independent of source/native counters.
    pub fn next_incarnation(&self) -> u64 {
        self.local.next_incarnation()
    }
    /// Whether local semantic prerequisites completed, not external/global release.
    pub fn completed(&self) -> bool {
        self.complete
    }
    /// Exact immutable pending semantic command; no receipt is minted.
    pub fn outgoing(&self) -> Option<retirement::command::Command> {
        self.outgoing
    }
    /// Exact last transport-confirmed semantic response, bounded to this operation.
    pub fn last_confirmed(&self) -> Option<retirement::command::Command> {
        self.last_confirmed
    }
    /// Actual observed peer phase; this is not a caller-constructible fence.
    pub fn peer_stage(&self) -> retirement::command::Kind {
        self.peer_stage
    }
    /// Actual local semantic phase, without inferring simultaneous peer state.
    pub fn phase(&self) -> ConnectionReusePhase {
        use retirement::command::Kind;
        if self.complete {
            ConnectionReusePhase::Completed
        } else if self.next_bound {
            if self.peer_stage as u8 >= Kind::Activate as u8 {
                ConnectionReusePhase::Activating
            } else {
                ConnectionReusePhase::Installed
            }
        } else if self.token.is_some() {
            ConnectionReusePhase::Draining
        } else {
            ConnectionReusePhase::Stopping
        }
    }
    /// Retire only a real transport-confirmed exact semantic output.
    pub fn outgoing_confirmed(
        &mut self,
        command: retirement::command::Command,
    ) -> Result<(), Error> {
        if self.outgoing != Some(command) {
            return Err(Error::Connections(records::Error::RetirementConflict));
        }
        if command.kind() == retirement::command::Kind::DoneAck {
            self.complete = true;
        }
        self.last_sent = Some(command.kind());
        self.last_confirmed = Some(command);
        self.outgoing = None;
        Ok(())
    }
    /// Store an exact authenticated progress observation, never caller-made fences.
    pub fn receive(&mut self, command: retirement::command::Command) -> Result<(), Error> {
        use retirement::command::Kind;
        if !self.local.matches(command) {
            return Err(Error::Connections(records::Error::RetirementConflict));
        }
        let client = self.operation().identity().role == Role::Client;
        match command.kind() {
            Kind::Stop if !client => {
                if self.peer_stopped.is_some_and(|v| v != command.admitted()) {
                    return Err(Error::Connections(records::Error::RetirementConflict));
                }
                self.peer_stopped = Some(command.admitted());
            }
            Kind::Stopped if client => {
                if self.peer_stopped.is_some_and(|v| v != command.admitted()) {
                    return Err(Error::Connections(records::Error::RetirementConflict));
                }
                self.peer_stopped = Some(command.admitted());
            }
            Kind::Fence => {
                if self.peer_fence.is_some_and(|v| v != command) {
                    return Err(Error::Connections(records::Error::RetirementConflict));
                }
                self.peer_fence = Some(command);
            }
            Kind::Installed => {
                if self.peer_installed.is_some_and(|v| v != command) {
                    return Err(Error::Connections(records::Error::RetirementConflict));
                }
                self.peer_installed = Some(command);
            }
            Kind::Activate if !client => {}
            Kind::Activated if client => {}
            Kind::Done if !client => {}
            Kind::DoneAck
                if client
                    && self.activated
                    && self.next_bound
                    && (self
                        .last_sent
                        .is_some_and(|kind| kind as u8 >= Kind::Done as u8)
                        || self
                            .outgoing
                            .is_some_and(|pending| pending.kind() == Kind::Done)) =>
            {
                self.complete = true;
            }
            _ => return Err(Error::Connections(records::Error::RetirementConflict)),
        }
        // Old exact retries never regress the semantic state or original cap.
        if command.kind() as u8 > self.peer_stage as u8 {
            self.peer_stage = command.kind();
        }
        Ok(())
    }
    /// Existing endpoints, queued input and external physical/native custody must
    /// remain live while this returns Busy; it creates no output/crypto authority.
    pub fn progress(&mut self, engine: &mut Engine, now: Tick) -> Result<(), Error> {
        use retirement::command::Kind;
        if self.complete {
            return Ok(());
        }
        if duration(now) >= Duration::from_millis(self.operation().expires().0) {
            return Err(Error::Connections(records::Error::RetirementExpired));
        }
        if self.token.is_none() {
            let token = engine.begin_connection_retirement(
                now,
                self.owner(),
                self.old_key(),
                self.operation(),
            )?;
            self.token = Some(token);
        }
        let token = self.token.as_ref().ok_or(Error::Invariant)?;
        let (admitted, written) = if self.activated {
            let fence = self.local_fence.ok_or(Error::Invariant)?;
            (fence.admitted(), fence.written())
        } else {
            engine.connection_retirement_counts(token)?
        };
        let client = self.operation().identity().role == Role::Client;
        if self.peer_stopped.is_none() {
            self.queue(if client { Kind::Stop } else { Kind::Stopped }, admitted, 0);
            return Ok(());
        }
        if !client && self.peer_stage == Kind::Stop && self.outgoing.is_none() {
            self.queue(Kind::Stopped, admitted, 0);
            return Ok(());
        }
        if written != self.peer_stopped.ok_or(Error::Invariant)? {
            return Ok(());
        }
        if self.local_fence.is_none() {
            self.local_fence = Some(engine.connection_retirement_fence(now, token)?);
        }
        if self.peer_fence.is_none() {
            self.queue(Kind::Fence, admitted, written);
            return Ok(());
        }
        if self
            .last_sent
            .is_none_or(|kind| (kind as u8) < Kind::Fence as u8)
        {
            self.queue(Kind::Fence, admitted, written);
            return Ok(());
        }
        let peer = self.peer_fence.ok_or(Error::Invariant)?;
        if !self.activated {
            engine.accept_connection_retirement_fence_at(
                now,
                now,
                token,
                peer.fence().map_err(Error::Connections)?,
            )?;
        }
        if !self.next_bound {
            if self.outgoing.is_some() {
                return Ok(());
            }
            let next_key = self.next_key();
            let token = self.token.as_mut().ok_or(Error::Invariant)?;
            engine.install_connection_reuse_named(now, token, next_key)?;
            self.next_bound = true;
            self.queue(Kind::Installed, admitted, written);
            return Ok(());
        }
        let Some(peer) = self.peer_installed else {
            return Ok(());
        };
        if client
            && (self.peer_stage as u8) >= Kind::Installed as u8
            && (self.peer_stage as u8) < Kind::Activated as u8
        {
            if !self.activated {
                engine.activate_connection_reuse_after_confirmation(
                    now,
                    self.token.as_ref().ok_or(Error::Invariant)?,
                    peer.installed().map_err(Error::Connections)?,
                )?;
                self.activated = true;
            }
            self.queue(Kind::Activate, admitted, written);
        } else if !client && (self.peer_stage as u8) >= Kind::Activate as u8 {
            if !self.activated {
                engine.activate_connection_reuse_after_confirmation(
                    now,
                    self.token.as_ref().ok_or(Error::Invariant)?,
                    peer.installed().map_err(Error::Connections)?,
                )?;
                self.activated = true;
            }
            self.queue(
                if self.peer_stage == Kind::Done {
                    Kind::DoneAck
                } else {
                    Kind::Activated
                },
                admitted,
                written,
            );
        } else if client && self.peer_stage == Kind::Activated && self.outgoing.is_none() {
            self.queue(Kind::Done, admitted, written);
        }
        Ok(())
    }
}
impl Engine {
    /// Observe the actual current claim of the selected independent owner.
    pub fn connection_owner_key(&self, index: u16) -> Result<Option<pipeline::FlowKey>, Error> {
        let Owner::Connections(owner) = &self.owner else {
            return Err(Error::Unsupported(Capability::FlowReuse));
        };
        let id = owner.collection.owner(index).map_err(Error::Connections)?;
        owner.collection.owner_key(id).map_err(Error::Connections)
    }
    /// Inspect actual current claims without learning or admitting a native packet.
    pub fn connection_claims_key(&self, key: pipeline::FlowKey) -> bool {
        matches!(&self.owner,Owner::Connections(owner) if owner.collection.claims_key(key))
    }
    /// Observe the actual current per-slot route incarnation.
    pub fn connection_route_incarnation(&self, index: u16) -> Result<u64, Error> {
        let Owner::Connections(owner) = &self.owner else {
            return Err(Error::Unsupported(Capability::FlowReuse));
        };
        let id = owner.collection.owner(index).map_err(Error::Connections)?;
        owner
            .collection
            .route_incarnation(id)
            .map_err(Error::Connections)
    }
    fn connection_retirement_counts(
        &self,
        token: &ConnectionRetirement,
    ) -> Result<(u64, u64), Error> {
        let Owner::Connections(owner) = &self.owner else {
            return Err(Error::Unsupported(Capability::FlowReuse));
        };
        owner
            .collection
            .retirement_counts(&token.token)
            .map_err(Error::Connections)
    }
    fn install_connection_reuse_named(
        &mut self,
        now: Tick,
        token: &mut ConnectionRetirement,
        next: pipeline::FlowKey,
    ) -> Result<(), Error> {
        if self.pipeline.flow(&next).is_some() {
            return Err(Error::Connections(records::Error::Binding));
        }
        let weight = self
            .pipeline
            .flow(&token.key)
            .ok_or(Error::Connections(records::Error::Binding))?
            .weight;
        self.install_connection_reuse(now, token)?;
        if self
            .pipeline
            .learn(next, token.binding.channel, weight, duration(now))
            .is_err()
        {
            // The old binding is already retired; partial install is terminal.
            return self.fail(Error::Invariant);
        }
        let Owner::Connections(owner) = &mut self.owner else {
            return self.fail(Error::Invariant);
        };
        if owner
            .collection
            .install_reuse_named(duration(now), &token.token, next)
            .is_err()
        {
            return self.fail(Error::Invariant);
        }
        Ok(())
    }
}
