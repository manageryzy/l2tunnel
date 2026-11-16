//! Explicit common-v2 facade on the existing Records scope/cover owner.
use super::{
    Class, Error, Opened as RecordOpened, Owners, ROUTE_BYTES, Records, Scope,
    Sealed as RecordSealed,
    framing::{Format, Route},
};
use crate::{
    cover,
    handshake::{self, Time},
    security::{self, refresh as sec},
};
pub use sec::{
    Activation, ActivationOutcome, KeyEpoch, Prepared, Request, RequestOutcome, Started,
};

/// Actual covered output with explicit fresh-key provenance.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Sealed {
    /// Existing actual packet number/generation and complete cover length.
    pub record: RecordSealed,
    /// Actual key epoch used.
    pub key_epoch: KeyEpoch,
    /// Actual continuing sender base.
    pub ratchet_base: security::PacketNumber,
}
/// Authenticated covered input; copying does not grant lifecycle authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Opened {
    /// Existing exact authenticated scope/number and plaintext length.
    pub record: RecordOpened,
    /// Actual receiving fresh-key context.
    pub key_epoch: KeyEpoch,
    /// Actual authenticated ratchet base.
    pub ratchet_base: security::PacketNumber,
}
pub(super) fn class(value: Class) -> sec::Class {
    match value {
        Class::User => sec::Class::Data,
        Class::Control => sec::Class::Management,
    }
}
impl Records {
    /// Consume only a real confirmed selected initial Noise owner. Membership
    /// admission is a separate required controller gate, not inferred from this type.
    #[allow(clippy::too_many_arguments)]
    pub fn new_refreshable(
        initial: handshake::refresh::ConfirmedInitial,
        lane: security::LaneId,
        limits: security::Limits,
        protection: security::Protection,
        cover: cover::Config,
        control: Scope,
        data: Scope,
        now: Time,
        session_expires: Time,
    ) -> Result<Self, Error> {
        Format::Refreshable.capacity(cover, limits, protection, limits.max_body_bytes)?;
        let handshake_bytes = 168usize;
        if handshake_bytes > cover.limits().max_protected_bytes
            || handshake_bytes
                .checked_add(cover.overhead(cover::Phase::Handshake, handshake_bytes)?)
                .ok_or(Error::TooLarge)?
                > cover.limits().max_packet_bytes
        {
            return Err(Error::TooLarge);
        }
        let mut owners = Vec::new();
        owners
            .try_reserve_exact(1)
            .map_err(|_| Error::Refresh(sec::Error::Allocation))?;
        if owners.capacity() != 1 {
            return Err(sec::Error::Configuration.into());
        }
        owners.push(initial.install(
            lane,
            limits,
            protection,
            control.epoch,
            control.configuration,
            now,
            session_expires,
        )?);
        Ok(Self {
            cover,
            limits,
            protection,
            control,
            data,
            additional: None,
            owners: Owners::Refreshable(owners),
        })
    }
    fn refreshed(&self) -> Result<&sec::Owners, Error> {
        match &self.owners {
            Owners::Refreshable(owners) => Ok(&owners[0]),
            Owners::Legacy { .. } | Owners::Compact(_) => Err(sec::Error::Mode.into()),
        }
    }
    fn refreshed_mut(&mut self) -> Result<&mut sec::Owners, Error> {
        match &mut self.owners {
            Owners::Refreshable(owners) => Ok(&mut owners[0]),
            Owners::Legacy { .. } | Owners::Compact(_) => Err(sec::Error::Mode.into()),
        }
    }
    /// Actual local crypto selector; never a setter or an authentication proof.
    pub fn key_epoch(&self) -> Result<KeyEpoch, Error> {
        Ok(self.refreshed()?.key_epoch())
    }
    /// Observe bounded old/prepared key overlap independently of data scopes.
    pub fn additional_key_epoch(&self) -> Result<Option<KeyEpoch>, Error> {
        Ok(self.refreshed()?.additional_epoch())
    }
    /// Mint the unique global initiator's local refresh request/admission.
    pub fn begin_refresh(&mut self, now: Time, original_deadline: Time) -> Result<Started, Error> {
        Ok(self
            .refreshed_mut()?
            .begin_refresh(sec::Tick(now.0), sec::Tick(original_deadline.0))?)
    }
    /// Consume an actual fresh Noise proof into the exact pending key context.
    pub fn prepare_refresh(
        &mut self,
        material: handshake::refresh::AuthenticatedRefresh,
        now: Time,
    ) -> Result<Prepared, Error> {
        Ok(material.prepare_into(self.refreshed_mut()?, now)?)
    }
    /// Switch both send keys at their actual continuing counters.
    pub fn activate_refresh(
        &mut self,
        prepared: &Prepared,
        now: Time,
    ) -> Result<Activation, Error> {
        Ok(self
            .refreshed_mut()?
            .activate_refresh(prepared, sec::Tick(now.0))?)
    }
    /// Drop exact old keys after real peer activation and original overlap.
    pub fn retire_refresh(&mut self, target: KeyEpoch, now: Time) -> Result<(), Error> {
        Ok(self
            .refreshed_mut()?
            .retire_refresh(target, sec::Tick(now.0))?)
    }
    /// Cancel only the exact unactivated target. Its selector and used PNs stay burned.
    pub fn abort_refresh(&mut self, target: KeyEpoch, now: Time) -> Result<(), Error> {
        Ok(self
            .refreshed_mut()?
            .abort_refresh(target, sec::Tick(now.0))?)
    }

    fn covered(
        &self,
        outer: cover::PacketMeta,
        route: [u8; ROUTE_BYTES],
        raw: sec::Sealed,
        workspace: &mut [u8],
        output: &mut [u8],
    ) -> Result<Sealed, Error> {
        Ok(Sealed {
            record: self.finish_cover(outer, route, raw.record, workspace, output)?,
            key_epoch: raw.key_epoch,
            ratchet_base: raw.ratchet_base,
        })
    }
    /// Timed selected emission; the ordinary un-timed API cannot bypass key expiry.
    pub fn seal_at(
        &mut self,
        now: Time,
        class: Class,
        outer: cover::PacketMeta,
        body: &[u8],
        workspace: &mut [u8],
        output: &mut [u8],
    ) -> Result<Sealed, Error> {
        self.refreshed_mut()?.check_time(sec::Tick(now.0))?;
        let scope = match class {
            Class::User => self.data,
            Class::Control => self.control,
        };
        self.seal_v2_scope(now, class, scope, outer, body, workspace, output)
    }
    /// Preserve explicit source/feedback data-scope routing across key refresh.
    pub fn seal_user_in_at(
        &mut self,
        now: Time,
        scope: Scope,
        outer: cover::PacketMeta,
        body: &[u8],
        workspace: &mut [u8],
        output: &mut [u8],
    ) -> Result<Sealed, Error> {
        self.refreshed_mut()?.check_time(sec::Tick(now.0))?;
        if self.registered_scope(Class::User, scope.epoch)? != scope {
            return Err(Error::Scope);
        }
        self.seal_v2_scope(now, Class::User, scope, outer, body, workspace, output)
    }
    #[allow(clippy::too_many_arguments)]
    fn seal_v2_scope(
        &mut self,
        now: Time,
        class_id: Class,
        scope: Scope,
        outer: cover::PacketMeta,
        body: &[u8],
        workspace: &mut [u8],
        output: &mut [u8],
    ) -> Result<Sealed, Error> {
        let capacity = self.preflight(outer, body.len(), workspace, output)?;
        let route = Route::new(class_id, scope);
        let raw = self.refreshed_mut()?.seal(
            sec::Tick(now.0),
            class(class_id),
            route.metadata(),
            body,
            &mut workspace[ROUTE_BYTES..capacity.seal_workspace_bytes],
        )?;
        self.covered(outer, route.bytes, raw, workspace, output)
    }
    /// Timed actual authentication with continuing shared replay across key slots.
    pub fn open_at(
        &mut self,
        now: Time,
        packet: &[u8],
        workspace: &mut [u8],
        plaintext: &mut [u8],
    ) -> Result<Opened, Error> {
        self.refreshed_mut()?.check_time(sec::Tick(now.0))?;
        let incoming = self.incoming(packet, workspace, plaintext)?;
        let route = incoming.route;
        let opened = self.refreshed_mut()?.open(
            sec::Tick(now.0),
            class(route.class),
            route.metadata(),
            incoming.protected,
            workspace,
        )?;
        plaintext[..opened.record.bytes].copy_from_slice(&workspace[..opened.record.bytes]);
        Ok(Opened {
            record: RecordOpened {
                class: route.class,
                scope: route.scope,
                number: opened.record.number,
                generation: opened.record.generation,
                bytes: opened.record.bytes,
                feedback: false,
                authenticated: true,
            },
            key_epoch: opened.key_epoch,
            ratchet_base: opened.ratchet_base,
        })
    }
    fn maintenance_route(&self) -> [u8; ROUTE_BYTES] {
        let mut route = Route::new(Class::Control, self.control).bytes;
        route[0] = 4;
        route
    }
    /// Protect the fixed immutable admitted request on the current old keys.
    pub fn seal_refresh_request(
        &mut self,
        request: &Request,
        now: Time,
        outer: cover::PacketMeta,
        workspace: &mut [u8],
        output: &mut [u8],
    ) -> Result<RecordSealed, Error> {
        self.refreshed_mut()?.check_time(sec::Tick(now.0))?;
        let capacity = self.preflight(outer, 72, workspace, output)?;
        let raw = self.refreshed_mut()?.seal_request(
            request,
            sec::Tick(now.0),
            &mut workspace[ROUTE_BYTES..capacity.seal_workspace_bytes],
        )?;
        Ok(self
            .covered(outer, self.maintenance_route(), raw, workspace, output)?
            .record)
    }
    fn maintenance_input<'a>(&self, packet: &'a [u8], workspace: &[u8]) -> Result<&'a [u8], Error> {
        let decoded = self.cover.decode(packet)?;
        if decoded.phase != cover::Phase::Established {
            return Err(Error::Phase);
        }
        if decoded.protected.get(..ROUTE_BYTES) != Some(self.maintenance_route().as_slice()) {
            return Err(Error::Scope);
        }
        let raw = decoded
            .protected
            .get(ROUTE_BYTES..)
            .ok_or(Error::Malformed)?;
        let body = raw
            .len()
            .checked_sub(sec::PREFIX_BYTES + self.protection.tag_bytes())
            .ok_or(Error::Malformed)?;
        let capacity = self.capacity(body)?;
        if workspace.len() < capacity.open_workspace_bytes {
            return Err(Error::OutputTooSmall);
        }
        Ok(raw)
    }
    /// Mint remote authority only inside actual old-key authentication/admission.
    pub fn open_refresh_request(
        &mut self,
        packet: &[u8],
        now: Time,
        original_deadline: Time,
        workspace: &mut [u8],
    ) -> Result<RequestOutcome, Error> {
        self.refreshed_mut()?.check_time(sec::Tick(now.0))?;
        let raw = self.maintenance_input(packet, workspace)?;
        Ok(self.refreshed_mut()?.open_request(
            sec::Tick(now.0),
            sec::Tick(original_deadline.0),
            raw,
            workspace,
        )?)
    }
    /// Emit both actual bases under the new Management key.
    pub fn seal_refresh_activation(
        &mut self,
        now: Time,
        outer: cover::PacketMeta,
        workspace: &mut [u8],
        output: &mut [u8],
    ) -> Result<RecordSealed, Error> {
        self.refreshed_mut()?.check_time(sec::Tick(now.0))?;
        let capacity = self.preflight(outer, 88, workspace, output)?;
        let raw = self.refreshed_mut()?.seal_activation(
            sec::Tick(now.0),
            &mut workspace[ROUTE_BYTES..capacity.seal_workspace_bytes],
        )?;
        Ok(self
            .covered(outer, self.maintenance_route(), raw, workspace, output)?
            .record)
    }
    /// Record peer activation only after actual matching new-key authentication.
    pub fn open_refresh_activation(
        &mut self,
        packet: &[u8],
        now: Time,
        workspace: &mut [u8],
    ) -> Result<ActivationOutcome, Error> {
        self.refreshed_mut()?.check_time(sec::Tick(now.0))?;
        let raw = self.maintenance_input(packet, workspace)?;
        Ok(self
            .refreshed_mut()?
            .open_activation(sec::Tick(now.0), raw, workspace)?)
    }
}
