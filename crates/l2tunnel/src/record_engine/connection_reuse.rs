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
