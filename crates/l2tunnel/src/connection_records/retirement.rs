//! Private drain/fence prerequisite. Only selected authenticated control may drive it.
use super::*;
use l2tunnel_core::ConfigDigest;
use l2tunnel_management::{Role, transaction};
use l2tunnel_recovery::EndpointRole;

/// Immutable original operation binding; construction does not authenticate input.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Scope {
    context: RecoveryContext,
    digest: ConfigDigest,
    attempt: u64,
    target_epoch: u64,
    target_digest: ConfigDigest,
    local: u32,
    remote: u32,
    lane: u32,
    expires: Duration,
}
impl Scope {
    /// Borrow only a real retained management operation, never route metadata.
    pub(crate) fn from_operation(
        context: RecoveryContext,
        digest: ConfigDigest,
        operation: transaction::Operation,
    ) -> Result<Self, Error> {
        let identity = operation.identity();
        let origin = operation.origin();
        let ticket = operation.ticket();
        let role = match identity.role {
            Role::Client => EndpointRole::Initiator,
            Role::Server => EndpointRole::Responder,
        };
        if context.session != u128::from_be_bytes(identity.session.0)
            || context.role != role
            || context.epoch != origin.epoch.0
            || digest != origin.digest
            || ticket.attempt == 0
        {
            return Err(Error::RetirementConflict);
        }
        Ok(Self {
            context,
            digest,
            attempt: ticket.attempt,
            target_epoch: ticket.epoch.0,
            target_digest: ticket.digest,
            local: identity.local.0,
            remote: identity.remote.0,
            lane: identity.lane.0,
            expires: Duration::from_millis(operation.expires().0),
        })
    }
    fn peer_of(self, other: Self) -> bool {
        self.context.session == other.context.session
            && self.context.epoch == other.context.epoch
            && self.context.role != other.context.role
            && self.digest == other.digest
            && self.attempt == other.attempt
            && self.target_epoch == other.target_epoch
            && self.target_digest == other.target_digest
            && self.local == other.remote
            && self.remote == other.local
            && self.lane == other.lane
    }
}

/// Move-only local witness; it grants neither peer authentication nor external drain.
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct Retirement {
    instance: u64,
    owner: OwnerId,
    incarnation: u64,
    serial: u64,
}
/// Observation to be transported only by an authenticated management operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Fence {
    scope: Scope,
    owner: OwnerId,
    incarnation: u64,
    key: crate::packet::FlowKey,
    admitted: u64,
    written: u64,
}
/// Observation that the old route was fenced and the next route remains closed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Installed {
    fence: Fence,
    next_incarnation: u64,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct State {
    scope: Scope,
    key: crate::packet::FlowKey,
    original_incarnation: u64,
    serial: u64,
    peer: Option<Fence>,
    installed: bool,
    last: Duration,
}
impl State {
    pub(super) fn deadline(&self) -> Duration {
        self.scope.expires
    }
    pub(super) fn installed(&self) -> bool {
        self.installed
    }
    pub(super) fn check_time(&self, now: Duration) -> Result<(), Error> {
        if now < self.last {
            return Err(Error::Time);
        }
        if now >= self.scope.expires {
            return Err(Error::RetirementExpired);
        }
        Ok(())
    }
}
fn local_drained(slot: &Slot) -> bool {
    slot.native_failure.is_none()
        && slot.raw_failure.is_none()
        && slot.native.is_none()
        && slot.raw_send.is_none()
        && slot.raw_receive.is_none()
        && slot.endpoint.drained()
}

impl Collection {
    /// Exact current route identity; immutable requested configuration is unchanged.
    pub fn route_incarnation(&self, id: OwnerId) -> Result<u64, Error> {
        Ok(self.slot(id)?.incarnation)
    }
    /// This observation does not authorize a flow or bypass Pipeline admission.
    pub fn admission_open(&self, id: OwnerId) -> Result<bool, Error> {
        Ok(self.slot(id)?.retirement.is_none())
    }
    fn retirement_state(&self, token: &Retirement) -> Result<State, Error> {
        if token.instance != self.instance {
            return Err(Error::Token);
        }
        let state = self.slot(token.owner)?.retirement.ok_or(Error::Token)?;
        if state.original_incarnation != token.incarnation || state.serial != token.serial {
            return Err(Error::Token);
        }
        Ok(state)
    }
    /// Stop new local admission. All original I/O and native custody stays serviceable.
    pub(crate) fn begin_retirement(
        &mut self,
        id: OwnerId,
        key: crate::packet::FlowKey,
        scope: Scope,
        now: Duration,
    ) -> Result<Retirement, Error> {
        if scope.context != self.context {
            return Err(Error::RetirementConflict);
        }
        let slot = self.slot(id)?;
        if let Some(state) = slot.retirement {
            state.check_time(now)?;
            if state.scope != scope || state.key != key {
                return Err(Error::RetirementConflict);
            }
            return Ok(Retirement {
                instance: self.instance,
                owner: id,
                incarnation: state.original_incarnation,
                serial: state.serial,
            });
        }
        if slot.claim != Some(key) {
            return Err(Error::Binding);
        }
        if now >= scope.expires {
            return Err(Error::RetirementExpired);
        }
        if scope.attempt <= slot.highest_retirement_attempt {
            return Err(Error::RetirementConflict);
        }
        let serial = slot
            .retirement_serial
            .checked_add(1)
            .ok_or(Error::Arithmetic)?;
        slot.incarnation.checked_add(1).ok_or(Error::Arithmetic)?;
        let incarnation = slot.incarnation;
        let state = State {
            scope,
            key,
            original_incarnation: incarnation,
            serial,
            peer: None,
            installed: false,
            last: now,
        };
        let slot = self.slot_mut(id)?;
        slot.retirement = Some(state);
        slot.retirement_serial = serial;
        slot.highest_retirement_attempt = scope.attempt;
        Ok(Retirement {
            instance: self.instance,
            owner: id,
            incarnation,
            serial,
        })
    }
    /// Actual monotonic whole-native totals; this observation is not a fence.
    pub(crate) fn retirement_counts(&self, token: &Retirement) -> Result<(u64, u64), Error> {
        self.retirement_state(token)?;
        let slot = self.slot(token.owner)?;
        Ok((slot.admitted_native, slot.written_native))
    }
    /// Reserve the exact next flow while the actual slot remains admission-closed.
    pub(crate) fn install_reuse_named(
        &mut self,
        now: Duration,
        token: &Retirement,
        next: crate::packet::FlowKey,
    ) -> Result<Installed, Error> {
        let state = self.retirement_state(token)?;
        if state.key == next {
            return Err(Error::RetirementConflict);
        }
        for (index, slot) in self.slots.iter().enumerate() {
            if index != usize::from(token.owner.index()) && slot.claim == Some(next) {
                return Err(Error::Binding);
            }
        }
        let installed = self.install_reuse(now, token)?;
        self.slot_mut(token.owner)?.claim = Some(next);
        Ok(installed)
    }
    /// Snapshot actual whole-native counters only after this owner's actual drain.
    pub(crate) fn retirement_fence(
        &self,
        now: Duration,
        token: &Retirement,
    ) -> Result<Fence, Error> {
        let state = self.retirement_state(token)?;
        state.check_time(now)?;
        let slot = self.slot(token.owner)?;
        if !local_drained(slot) {
            return Err(Error::RetirementBusy);
        }
        Ok(Fence {
            scope: state.scope,
            owner: token.owner,
            incarnation: state.original_incarnation,
            key: state.key,
            admitted: slot.admitted_native,
            written: slot.written_native,
        })
    }
    /// Caller must authenticate/replay-check the fence under this exact operation.
    /// Retry pressure retains the original input arrival and operation cap externally.
    pub(crate) fn accept_retirement_fence_at(
        &mut self,
        received: Duration,
        observed: Duration,
        token: &Retirement,
        peer: Fence,
    ) -> Result<(), Error> {
        let mut state = self.retirement_state(token)?;
        state.check_time(observed)?;
        if received > observed || received >= state.scope.expires {
            return Err(Error::Time);
        }
        if !state.scope.peer_of(peer.scope)
            || peer.owner != token.owner
            || peer.incarnation != state.original_incarnation
            || peer.key != state.key
        {
            return Err(Error::RetirementConflict);
        }
        if state.peer.is_some_and(|actual| actual != peer) {
            return Err(Error::RetirementConflict);
        }
        let local = self.retirement_fence(observed, token)?;
        if local.admitted != peer.written || local.written != peer.admitted {
            return Err(Error::RetirementBusy);
        }
        state.peer = Some(peer);
        state.last = observed;
        self.slot_mut(token.owner)?.retirement = Some(state);
        Ok(())
    }
    /// Preflight for the Engine's atomic Pipeline/history retirement before install.
    pub(crate) fn preflight_reuse(
        &self,
        now: Duration,
        token: &Retirement,
    ) -> Result<Installed, Error> {
        let state = self.retirement_state(token)?;
        state.check_time(now)?;
        let local = self.retirement_fence(now, token)?;
        let peer = state.peer.ok_or(Error::RetirementBusy)?;
        if local.admitted != peer.written || local.written != peer.admitted {
            return Err(Error::RetirementBusy);
        }
        let next_incarnation = state
            .original_incarnation
            .checked_add(1)
            .ok_or(Error::Arithmetic)?;
        if self.slot(token.owner)?.incarnation
            != if state.installed {
                next_incarnation
            } else {
                state.original_incarnation
            }
        {
            return Err(Error::Invariant);
        }
        Ok(Installed {
            fence: local,
            next_incarnation,
        })
    }
    /// Caller must first retire the same Pipeline binding/history and external custody.
    /// No endpoint, source, codec, raw serial or native counter is reset or replaced.
    pub(crate) fn install_reuse(
        &mut self,
        now: Duration,
        token: &Retirement,
    ) -> Result<Installed, Error> {
        let installed = self.preflight_reuse(now, token)?;
        let slot = self.slot_mut(token.owner)?;
        let state = slot.retirement.as_mut().ok_or(Error::Invariant)?;
        state.installed = true;
        state.last = now;
        slot.incarnation = installed.next_incarnation;
        slot.claim = None;
        Ok(installed)
    }
    /// Only a matching authenticated peer installation confirmation reopens admission.
    pub(crate) fn activate_reuse_after_confirmation(
        &mut self,
        now: Duration,
        token: &Retirement,
        peer: Installed,
    ) -> Result<(), Error> {
        let state = self.retirement_state(token)?;
        state.check_time(now)?;
        let installed = self.preflight_reuse(now, token)?;
        if !state.installed
            || !installed.fence.scope.peer_of(peer.fence.scope)
            || installed.fence.owner != peer.fence.owner
            || installed.fence.incarnation != peer.fence.incarnation
            || installed.fence.key != peer.fence.key
            || installed.next_incarnation != peer.next_incarnation
            || installed.fence.admitted != peer.fence.written
            || installed.fence.written != peer.fence.admitted
        {
            return Err(Error::RetirementConflict);
        }
        self.slot_mut(token.owner)?.retirement = None;
        Ok(())
    }
}

#[cfg(test)]
#[path = "retirement_tests.rs"]
mod tests;

/// Strict selected-control grammar and authenticated admission boundary.
pub mod command;

impl Fence {
    pub(crate) fn admitted(self) -> u64 {
        self.admitted
    }
    pub(crate) fn written(self) -> u64 {
        self.written
    }
}

impl Collection {
    pub(crate) fn owner_key(&self, id: OwnerId) -> Result<Option<crate::packet::FlowKey>, Error> {
        Ok(self.slot(id)?.claim)
    }
    pub(crate) fn claims_key(&self, key: crate::packet::FlowKey) -> bool {
        self.slots.iter().any(|slot| slot.claim == Some(key))
    }
}
