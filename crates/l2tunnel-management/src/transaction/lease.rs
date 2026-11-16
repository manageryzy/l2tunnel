//! Explicit bounded operations for the selected streamed control contract.
//!
//! Legacy peers retain their existing phase timers and wire bytes. Leased peers
//! additionally own one immutable operation through terminal reply custody.
//! All times are caller-injected milliseconds; no clock or carrier is owned here.

use super::{
    Configuration, Effects, Error, Frame, Header, Identity, Ingress, Message, MessageKind, Peer,
    Phase, RequestId, Role, Tick, Ticket, add, configuration_limits, opposite, reply_to,
};
use crate::{messages, session_control};
use l2tunnel_core::Epoch;

/// Explicit immutable limits of the negotiated leased transaction contract.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LeaseSettings {
    /// Original authenticated session expiry in the same injected millisecond domain.
    pub session_expires: Tick,
    /// Largest admitted operation lifetime, without renewal at a phase transition.
    pub max_operation_ms: u64,
    /// Actual negotiated Transaction stream ARQ epoch, not a data epoch.
    pub transaction_epoch: u64,
}

/// Disjoint semantic identity within the same authenticated management session.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OperationKind {
    /// Existing whole-generation configuration transaction.
    ModeSwitch,
    /// Explicit same-generation independent-owner retirement grammar v1.
    SlotReuseV1,
}

/// Opaque original operation identity, retained even after local retirement.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Operation {
    identity: Identity,
    kind: OperationKind,
    ticket: Ticket,
    origin: session_control::Scope,
    expires: Tick,
}
impl Operation {
    /// Exact operation grammar; a slot command cannot alias a mode transaction.
    pub const fn kind(self) -> OperationKind {
        self.kind
    }
    /// Construct a bounded selected-control identity, without authenticating input.
    /// Only an actual authenticated command gateway may use peer-supplied values.
    #[allow(clippy::too_many_arguments)]
    pub fn slot_reuse(
        identity: Identity,
        origin: crate::session_control::Scope,
        attempt: u64,
        target: l2tunnel_core::ConfigDigest,
        now: Tick,
        expires: Tick,
        session_expires: Tick,
        maximum_ms: u64,
    ) -> Result<Self, Error> {
        if identity.session.0 == [0; 16]
            || origin.epoch.0 == 0
            || attempt == 0
            || maximum_ms == 0
            || expires <= now
            || expires > session_expires
            || expires
                .0
                .checked_sub(now.0)
                .is_none_or(|remaining| remaining > maximum_ms)
        {
            return Err(Error::LeaseExpired);
        }
        Ok(Self {
            identity,
            kind: OperationKind::SlotReuseV1,
            ticket: Ticket {
                attempt,
                epoch: origin.epoch,
                digest: target,
            },
            origin,
            expires,
        })
    }

    /// Counterpart identity of this exact selected operation, with unchanged cap.
    /// This is not peer authentication or a peer installation receipt.
    pub fn mirror_slot_reuse(self) -> Result<Self, Error> {
        if self.kind != OperationKind::SlotReuseV1 {
            return Err(Error::LeaseRequired);
        }
        let id = self.identity;
        Ok(Self {
            identity: Identity {
                role: opposite(id.role),
                local: id.remote,
                remote: id.local,
                ..id
            },
            ..self
        })
    }
    /// Full authenticated session, role, lane and logical endpoints.
    pub fn identity(self) -> Identity {
        self.identity
    }
    /// Exact target proposal, independent of its originating configuration.
    pub fn ticket(self) -> Ticket {
        self.ticket
    }
    /// Original data epoch and digest; never substituted with the target digest.
    pub fn origin(self) -> session_control::Scope {
        self.origin
    }
    /// Immutable original expiry, including staging, drain and final custody.
    pub fn expires(self) -> Tick {
        self.expires
    }
}

/// Opaque context for one currently owned immutable outgoing logical message.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OutboundContext {
    operation: Operation,
    request: RequestId,
    kind: MessageKind,
    final_reply: bool,
}
impl OutboundContext {
    /// Original authenticated data origin, including its full configuration digest.
    pub fn origin(self) -> session_control::Scope {
        self.operation.origin
    }
    /// Original operation expiry; wrapping and transport waits cannot extend it.
    pub fn expires(self) -> Tick {
        self.operation.expires
    }
    /// Immutable logical outgoing request identity, distinct from packet numbers.
    pub fn request(self) -> RequestId {
        self.request
    }
    /// Exact outgoing management grammar kind.
    pub fn kind(self) -> MessageKind {
        self.kind
    }
    /// A follower's terminal cached RETIRE or REJECT reply requires confirmation.
    pub fn is_final_reply(self) -> bool {
        self.final_reply
    }
}

/// Borrowed authority for only the actual current cached request and reply.
///
/// A witness cannot survive mutation of its peer or mint an arbitrary old-scope
/// message. Fresh outer/nested replay checks and exact verified origin remain
/// mandatory; this is not authority for user data, feedback or ProfileControl.
pub struct CachedRetryAuthority<'a> {
    operation: Operation,
    request: Frame<'a>,
    reply: &'a Message,
}
impl CachedRetryAuthority<'_> {
    /// Original immutable operation whose cache still owns this reply.
    pub fn operation(&self) -> Operation {
        self.operation
    }
    /// Exact retained incoming logical request, excluding no payload bytes.
    pub fn request(&self) -> Frame<'_> {
        self.request
    }
    /// Actual immutable reply identity, not a caller-supplied request number.
    pub fn reply_request(&self) -> RequestId {
        self.reply.request
    }
    /// Actual cached reply kind.
    pub fn reply_kind(&self) -> MessageKind {
        self.reply.kind
    }
}

struct FinalIncoming {
    header: Header,
    body: Vec<u8>,
}
pub(super) struct State {
    settings: LeaseSettings,
    operation: Option<Operation>,
    candidate: Option<Tick>,
    final_incoming: Option<FinalIncoming>,
    expired: bool,
}

fn validate_lease(
    identity: Identity,
    epoch: Epoch,
    lease: LeaseSettings,
    now: Tick,
) -> Result<(), Error> {
    if lease.session_expires <= now
        || lease.max_operation_ms == 0
        || lease.transaction_epoch == 0
        || identity.session.0 == [0; 16]
        || epoch.0 == 0
    {
        return Err(Error::Configuration("invalid operation lease"));
    }
    Ok(())
}

impl<C: Configuration> Peer<C> {
    /// Select the additive leased contract without changing any legacy wire bytes.
    pub fn new_leased(
        identity: Identity,
        epoch: Epoch,
        initial: C,
        supported: &[C],
        settings: super::Settings,
        lease: LeaseSettings,
        now: Tick,
    ) -> Result<Self, Error> {
        validate_lease(identity, epoch, lease, now)?;
        let peer = Self::new(identity, epoch, initial, supported, settings, now)?;
        Ok(peer.with_lease(lease))
    }

    /// Require immutable operation leases and explicit global-sender fence widths.
    /// The selected configuration encodes both global widths; no wire field or
    /// default migration is inferred from selecting this constructor.
    pub fn new_leased_directional(
        identity: Identity,
        epoch: Epoch,
        initial: C,
        supported: &[C],
        settings: super::Settings,
        lease: LeaseSettings,
        now: Tick,
    ) -> Result<Self, Error> {
        validate_lease(identity, epoch, lease, now)?;
        let peer = Self::new_directional(identity, epoch, initial, supported, settings, now)?;
        Ok(peer.with_lease(lease))
    }

    fn with_lease(mut self, lease: LeaseSettings) -> Self {
        self.lease = Some(State {
            settings: lease,
            operation: None,
            candidate: None,
            final_incoming: None,
            expired: false,
        });
        self.deadline = self.clamp_lease(self.deadline);
        self.next_retry = self.clamp_lease(self.next_retry);
        self
    }

    /// Whether this peer explicitly requires original operation leases.
    pub fn is_leased(&self) -> bool {
        self.lease.is_some()
    }
    /// Current immutable operation, including locally idle final custody.
    pub fn operation(&self) -> Option<Operation> {
        self.lease.as_ref().and_then(|lease| lease.operation)
    }

    /// Earliest relevant injected wake; failed peers have no resumable work.
    pub fn next_deadline(&self) -> Option<Tick> {
        if self.phase == Phase::Failed {
            return None;
        }
        let operation = self.operation();
        let session = self
            .lease
            .as_ref()
            .map(|lease| lease.settings.session_expires);
        let phase = (!matches!(self.phase, Phase::Idle | Phase::Failed)).then_some(self.deadline);
        let retry = (phase.is_some() && (self.outstanding.is_some() || self.cached.is_some()))
            .then_some(self.next_retry);
        session
            .into_iter()
            .chain(operation.map(|operation| operation.expires))
            .chain(phase)
            .chain(retry)
            .min()
    }

    /// Begin one bounded local proposal; another unresolved operation is busy.
    pub fn propose_until(
        &mut self,
        config: C,
        now: Tick,
        expires: Tick,
    ) -> Result<Effects<C>, Error> {
        self.observe_lease(now)?;
        self.readonly_time(now)?;
        if !self.is_leased() {
            return Err(Error::LeaseRequired);
        }
        if self.operation().is_some() || self.phase != Phase::Idle {
            return Err(Error::Busy);
        }
        self.validate_new_cap(now, expires)?;
        self.advance(now)?;
        if let Some(lease) = self.lease.as_mut() {
            lease.candidate = Some(expires);
        }
        let result = self.propose_inner(config);
        if let Some(lease) = self.lease.as_mut() {
            lease.candidate = None;
        }
        result
    }

    /// Validate an explicit original cap before admitting or mutating peer input.
    /// A valid first PREPARE, or REJECT after a lost PREPARE, starts the operation.
    pub fn receive_until(
        &mut self,
        verified: Ingress,
        bytes: &[u8],
        now: Tick,
        expires: Tick,
    ) -> Result<Effects<C>, Error> {
        self.observe_lease(now)?;
        self.validate_receive_until(verified, bytes, now, expires)?;
        let starting = self.operation().is_none();
        if starting && let Some(lease) = self.lease.as_mut() {
            lease.candidate = Some(expires);
        }
        let result = self.receive(verified, bytes, now);
        if let Some(lease) = self.lease.as_mut() {
            lease.candidate = None;
        }
        result
    }

    /// Read-only cap and binding preflight for an atomic outer stream gate.
    /// Expiry is reported without changing replay, counters, phase or injected time.
    pub fn validate_receive_until(
        &self,
        verified: Ingress,
        bytes: &[u8],
        now: Tick,
        expires: Tick,
    ) -> Result<(), Error> {
        self.validate_receive_cap(now, expires)?;
        let frame = self.verified_frame(verified, bytes)?;
        self.validate_operation_frame(frame)
    }

    pub(super) fn validate_receive_cap(&self, now: Tick, expires: Tick) -> Result<(), Error> {
        self.readonly_time(now)?;
        if !self.is_leased() {
            return Err(Error::LeaseRequired);
        }
        if let Some(operation) = self.operation() {
            if expires != operation.expires {
                return Err(Error::LeaseConflict);
            }
        } else {
            self.validate_new_cap(now, expires)?;
        }
        Ok(())
    }

    /// Read-only exact origin authority before an outer stream sequence commits.
    /// True permits only an exact retained cached request or exact terminal
    /// incoming reply still awaiting its acceptance proof under the old origin.
    /// False identifies ordinary current-operation or valid first-command input.
    pub fn validate_control_origin(
        &self,
        verified: Ingress,
        bytes: &[u8],
        claimed: session_control::Scope,
        now: Tick,
    ) -> Result<bool, Error> {
        self.readonly_time(now)?;
        if !self.is_leased() {
            return Err(Error::LeaseRequired);
        }
        let frame = self.verified_frame(verified, bytes)?;
        self.validate_operation_frame(frame)?;
        let origin = self
            .operation()
            .map_or_else(|| self.current_origin(), |operation| operation.origin);
        if claimed != origin || frame.header.source_epoch != origin.epoch {
            return Err(Error::Custody);
        }
        if self.retained_final_incoming(frame) {
            return Ok(true);
        }
        let Some(authority) = self.cached_retry_authority(now)? else {
            return Ok(false);
        };
        Ok(authority.request.header.same_request(frame.header)
            && authority.request.body == frame.body)
    }

    /// Borrow the current exact request/reply witness while its original lease lives.
    pub fn cached_retry_authority(
        &self,
        now: Tick,
    ) -> Result<Option<CachedRetryAuthority<'_>>, Error> {
        self.readonly_time(now)?;
        if !self.is_leased() {
            return Err(Error::LeaseRequired);
        }
        let Some(operation) = self.operation() else {
            return Ok(None);
        };
        let Some(cached) = self.cached.as_ref() else {
            return Ok(None);
        };
        let request = self
            .gate
            .requests
            .iter()
            .find(|request| request.header.request == cached.for_request)
            .ok_or(Error::Custody)?;
        if request.header.ticket != operation.ticket
            || request.header.source_epoch != operation.origin.epoch
            || cached.message.ticket != operation.ticket
            || cached.message.source != operation.origin.epoch
        {
            return Err(Error::Custody);
        }
        Ok(Some(CachedRetryAuthority {
            operation,
            request: Frame {
                header: request.header,
                body: &request.body,
            },
            reply: &cached.message,
        }))
    }

    /// Recover the original scope and cap of an actual currently owned logical output.
    /// Packet and lane fields retain their established retry equality semantics.
    pub fn outbound_context(&self, emitted: &[u8]) -> Result<OutboundContext, Error> {
        self.readonly_time(self.now)?;
        let operation = self.operation().ok_or(Error::LeaseRequired)?;
        let frame =
            Frame::decode(emitted, configuration_limits::<C>()?).map_err(Error::Admission)?;
        if frame.header.packet.0 == 0 || frame.header.packet.0 >= self.next_packet {
            return Err(Error::Custody);
        }
        let command = self
            .outstanding
            .as_ref()
            .filter(|message| self.matches_outgoing(frame, message));
        let cached = self
            .cached
            .as_ref()
            .map(|cached| &cached.message)
            .filter(|message| self.matches_outgoing(frame, message));
        let (message, final_reply) = if let Some(message) = command {
            (message, false)
        } else if let Some(message) = cached {
            (message, is_final(message.kind))
        } else {
            return Err(Error::Custody);
        };
        if message.source != operation.origin.epoch || message.ticket != operation.ticket {
            return Err(Error::Custody);
        }
        Ok(OutboundContext {
            operation,
            request: message.request,
            kind: message.kind,
            final_reply,
        })
    }

    /// Release coordinator terminal custody only after the exact incoming final
    /// L2SC message was accepted and its whole-message receipt was retained.
    /// Invalid proof, body or context preflight does not advance peer time; the
    /// borrowed proof remains available for a correct exact retry.
    pub fn complete_accepted(
        &mut self,
        proof: &messages::Accepted<'_>,
        envelope: &[u8],
        now: Tick,
    ) -> Result<(), Error> {
        self.observe_lease(now)?;
        self.readonly_time(now)?;
        if self.identity.role != Role::Client || self.phase != Phase::Idle {
            return Err(Error::Custody);
        }
        let frame = self.custody_envelope(
            proof.ticket(),
            proof.observed_at(),
            envelope,
            now,
            opposite(self.identity.role),
        )?;
        if !self.retained_final_incoming(frame) {
            return Err(Error::Custody);
        }
        let request = frame.header.request;
        self.advance(now)?;
        self.gate.retire_through(request);
        self.release_operation();
        Ok(())
    }

    /// Release a follower's final cache only after exact whole-message acceptance
    /// and all its outgoing fragment source receipts were actually confirmed.
    /// Invalid proof, body or context preflight leaves peer time and cache
    /// unchanged; the original borrowed proof can be checked again.
    pub fn complete_confirmed(
        &mut self,
        proof: &messages::Confirmed<'_>,
        envelope: &[u8],
        now: Tick,
    ) -> Result<(), Error> {
        self.observe_lease(now)?;
        self.readonly_time(now)?;
        if self.identity.role != Role::Server || self.phase != Phase::Idle {
            return Err(Error::Custody);
        }
        let frame = self.custody_envelope(
            proof.ticket(),
            proof.observed_at(),
            envelope,
            now,
            self.identity.role,
        )?;
        let cached = self.cached.as_ref().ok_or(Error::Custody)?;
        if !is_final(cached.message.kind) || !self.matches_outgoing(frame, &cached.message) {
            return Err(Error::Custody);
        }
        let request = cached.for_request;
        self.advance(now)?;
        self.gate.retire_through(request);
        self.release_operation();
        Ok(())
    }

    pub(super) fn observe_lease(&mut self, now: Tick) -> Result<(), Error> {
        let Some(lease) = self.lease.as_mut() else {
            return Ok(());
        };
        if lease.expired {
            return Err(Error::LeaseExpired);
        }
        if now < self.now {
            return Err(Error::Clock);
        }
        if now >= lease.settings.session_expires
            || lease
                .operation
                .is_some_and(|operation| now >= operation.expires)
        {
            lease.expired = true;
            self.phase = Phase::Failed;
            return Err(Error::LeaseExpired);
        }
        if self.phase == Phase::Failed {
            return Err(Error::Failed);
        }
        Ok(())
    }
    pub(super) fn clamp_lease(&self, at: Tick) -> Tick {
        self.lease.as_ref().map_or(at, |lease| {
            at.min(lease.settings.session_expires)
                .min(lease.operation.map_or(at, |operation| operation.expires))
        })
    }
    pub(super) fn begin_operation(&mut self, ticket: Ticket) -> Result<(), Error> {
        let origin = self.current_origin();
        let Some(lease) = self.lease.as_mut() else {
            return Ok(());
        };
        if lease.operation.is_some() {
            return Err(Error::Busy);
        }
        let expires = lease.candidate.ok_or(Error::LeaseRequired)?;
        lease.operation = Some(Operation {
            identity: self.identity,
            kind: OperationKind::ModeSwitch,
            ticket,
            origin,
            expires,
        });
        lease.final_incoming = None;
        Ok(())
    }
    pub(super) fn complete_local_abort(&mut self) {
        if self.lease.is_some() {
            self.release_operation();
        }
    }
    pub(super) fn capture_final_incoming(&mut self, frame: Frame<'_>) -> Result<(), Error> {
        let Some(lease) = self.lease.as_mut() else {
            return Ok(());
        };
        let operation = lease.operation.ok_or(Error::LeaseRequired)?;
        if !is_final(frame.header.kind)
            || frame.header.ticket != operation.ticket
            || frame.header.source_epoch != operation.origin.epoch
            || frame.body.len() != 8
        {
            return Err(Error::Custody);
        }
        lease.final_incoming = Some(FinalIncoming {
            header: frame.header,
            body: frame.body.to_vec(),
        });
        Ok(())
    }
    pub(super) fn final_request_is_held(&self, request: RequestId) -> bool {
        self.lease
            .as_ref()
            .and_then(|lease| lease.final_incoming.as_ref())
            .is_some_and(|incoming| incoming.header.request == request)
    }
    pub(super) fn leased_receive_preflight(
        &self,
        verified: Ingress,
        bytes: &[u8],
    ) -> Result<(), Error> {
        let Some(lease) = self.lease.as_ref() else {
            return Ok(());
        };
        if lease.operation.is_none() && lease.candidate.is_none() {
            return Err(Error::LeaseRequired);
        }
        self.validate_operation_frame(self.verified_frame(verified, bytes)?)
    }

    pub(super) fn readonly_time(&self, now: Tick) -> Result<(), Error> {
        if let Some(lease) = self.lease.as_ref()
            && (lease.expired
                || now >= lease.settings.session_expires
                || lease
                    .operation
                    .is_some_and(|operation| now >= operation.expires))
        {
            return Err(Error::LeaseExpired);
        }
        if now < self.now {
            return Err(Error::Clock);
        }
        if self.phase == Phase::Failed {
            return Err(Error::Failed);
        }
        add(now, self.settings.reconcile_timeout_ms)?;
        Ok(())
    }
    pub(super) fn validate_new_cap(&self, now: Tick, expires: Tick) -> Result<(), Error> {
        let lease = self.lease.as_ref().ok_or(Error::LeaseRequired)?;
        if expires <= now
            || expires > lease.settings.session_expires
            || expires.0 - now.0 > lease.settings.max_operation_ms
        {
            return Err(Error::Configuration("invalid operation lease"));
        }
        Ok(())
    }
    pub(super) fn current_origin(&self) -> session_control::Scope {
        let active = self.guard.active();
        session_control::Scope {
            epoch: active.epoch,
            digest: active.digest,
        }
    }
    pub(super) fn verified_frame<'a>(
        &self,
        verified: Ingress,
        bytes: &'a [u8],
    ) -> Result<Frame<'a>, Error> {
        let Ingress::AuthenticatedManagement {
            session,
            lane,
            sender,
        } = verified
        else {
            return Err(Error::Admission(crate::Error::UntrustedOrigin));
        };
        if session != self.identity.session
            || lane != self.identity.lane
            || sender != opposite(self.identity.role)
        {
            return Err(Error::Admission(crate::Error::BindingMismatch));
        }
        let frame = Frame::decode(bytes, configuration_limits::<C>()?).map_err(Error::Admission)?;
        let header = frame.header;
        if header.session != session
            || header.lane != lane
            || header.sender != sender
            || header.source != self.identity.remote
            || header.destination != self.identity.local
        {
            return Err(Error::Admission(crate::Error::BindingMismatch));
        }
        Ok(frame)
    }
    fn validate_operation_frame(&self, frame: Frame<'_>) -> Result<(), Error> {
        self.operation_frame(frame).map(|_| ())
    }

    pub(super) fn operation_frame(
        &self,
        frame: Frame<'_>,
    ) -> Result<Option<(C, super::Fence)>, Error> {
        if self
            .gate
            .retired_through
            .is_some_and(|floor| frame.header.request <= floor)
        {
            return Err(Error::Admission(crate::Error::RequestRetired));
        }
        if let Some(operation) = self.operation() {
            if frame.header.ticket != operation.ticket
                || frame.header.source_epoch != operation.origin.epoch
            {
                return Err(Error::LeaseConflict);
            }
            let cached = self.cached.as_ref().and_then(|cached| {
                self.gate
                    .requests
                    .iter()
                    .find(|request| request.header.request == cached.for_request)
            });
            if let Some(cached) = cached
                && frame.header.request == cached.header.request
                && (!cached.header.same_request(frame.header) || cached.body != frame.body)
            {
                return Err(Error::Custody);
            }
            if self.phase == Phase::Idle {
                let exact = if self.identity.role == Role::Server {
                    cached.is_some_and(|cached| {
                        cached.header.same_request(frame.header) && cached.body == frame.body
                    })
                } else {
                    self.retained_final_incoming(frame)
                };
                if !exact {
                    return Err(Error::Custody);
                }
            }
            return Ok(None);
        }
        if self.identity.role != Role::Server || self.phase != Phase::Idle {
            return Err(Error::LeaseRequired);
        }
        let header = frame.header;
        if header.source_epoch != self.active_epoch()
            || header.ticket.attempt <= self.last_attempt
            || header.ticket.epoch.0
                != self
                    .active_epoch()
                    .0
                    .checked_add(1)
                    .ok_or(Error::Exhausted)?
            || header.request.0 <= self.last_command
            || reply_to(frame.body)? != 0
        {
            return Err(Error::Unexpected);
        }
        match header.kind {
            MessageKind::Prepare => self.first_prepare(frame, Error::Malformed).map(Some),
            MessageKind::Reject if frame.body.len() == 8 => Ok(None),
            _ => Err(Error::Unexpected),
        }
    }
    fn matches_outgoing(&self, frame: Frame<'_>, message: &Message) -> bool {
        let header = frame.header;
        header.session == self.identity.session
            && header.lane == self.identity.lane
            && header.sender == self.identity.role
            && header.source == self.identity.local
            && header.destination == self.identity.remote
            && header.kind == message.kind
            && header.request == message.request
            && header.source_epoch == message.source
            && header.ticket == message.ticket
            && frame.body == message.body
    }
    fn retained_final_incoming(&self, frame: Frame<'_>) -> bool {
        if self.identity.role != Role::Client {
            return false;
        }
        let Some(incoming) = self
            .lease
            .as_ref()
            .and_then(|lease| lease.final_incoming.as_ref())
        else {
            return false;
        };
        if !incoming.header.same_request(frame.header) || incoming.body != frame.body {
            return false;
        }
        self.gate.requests.iter().any(|request| {
            request.header.same_request(incoming.header) && request.body == incoming.body
        })
    }
    fn custody_envelope<'a>(
        &self,
        ticket: messages::Ticket,
        observed: std::time::Duration,
        bytes: &'a [u8],
        now: Tick,
        sender: Role,
    ) -> Result<Frame<'a>, Error> {
        let lease = self.lease.as_ref().ok_or(Error::LeaseRequired)?;
        let operation = lease.operation.ok_or(Error::Custody)?;
        let binding = ticket.binding();
        if u64::try_from(observed.as_millis()).ok() != Some(now.0)
            || ticket.length() != bytes.len()
            || binding.session != self.identity.session
            || binding.lane != self.identity.lane
            || binding.local_role != self.identity.role
            || binding.control_epoch != lease.settings.transaction_epoch
            || ring::digest::digest(&ring::digest::SHA256, bytes).as_ref() != &ticket.digest()[..]
        {
            return Err(Error::Custody);
        }
        let envelope = session_control::Envelope::decode(
            bytes,
            session_control::Limits {
                max_frame_bytes: 65_536,
                max_management_bytes: 65_536 - session_control::HEADER_BYTES,
                max_feedback_bytes: 1,
            },
        )
        .map_err(|_| Error::Custody)?;
        let actual = envelope.binding;
        if actual.session != self.identity.session
            || actual.lane != self.identity.lane
            || actual.sender != sender
            || actual.scope != operation.origin
            || actual.packet.0 == 0
        {
            return Err(Error::Custody);
        }
        let session_control::Body::Management(management) = envelope.body else {
            return Err(Error::Custody);
        };
        let frame =
            Frame::decode(management, configuration_limits::<C>()?).map_err(|_| Error::Custody)?;
        let header = frame.header;
        let (source, destination) = if sender == self.identity.role {
            (self.identity.local, self.identity.remote)
        } else {
            (self.identity.remote, self.identity.local)
        };
        if header.session != self.identity.session
            || header.lane != self.identity.lane
            || header.sender != sender
            || header.source != source
            || header.destination != destination
            || header.source_epoch != operation.origin.epoch
            || header.ticket != operation.ticket
            || !is_final(header.kind)
            || header.packet.0 == 0
        {
            return Err(Error::Custody);
        }
        Ok(frame)
    }
    fn release_operation(&mut self) {
        self.cached = None;
        self.incoming = None;
        if let Some(lease) = self.lease.as_mut() {
            lease.operation = None;
            lease.candidate = None;
            lease.final_incoming = None;
        }
    }
}

fn is_final(kind: MessageKind) -> bool {
    matches!(kind, MessageKind::Retire | MessageKind::Reject)
}

#[cfg(test)]
mod tests;
