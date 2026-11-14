//! Explicit bridge to real leased transactions and borrowed whole-message proofs.

use super::*;
use l2tunnel_management::transaction as tx;

/// Capacity pressure is distinct from a completed custody transfer.
#[derive(Debug, Eq, PartialEq)]
pub(crate) enum Attempt<T> {
    Blocked,
    Complete(T),
}

/// No second semantic dispatch is permitted while retained effects occupy the slot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DispatchProgress {
    Idle,
    Blocked,
    Dispatched,
}

/// Borrowed actual complete Transaction bytes; not acceptance or storage authority.
pub(crate) struct PendingTransaction<'a, C: tx::Configuration> {
    incoming: Incoming,
    delivery: messages::Delivery<'a>,
    preparation: Option<tx::Preparation<C>>,
}

impl<C: tx::Configuration> PendingTransaction<'_, C> {
    pub(crate) fn incoming(&self) -> Incoming {
        self.incoming
    }
    pub(crate) fn envelope(&self) -> &[u8] {
        self.delivery.bytes()
    }
    pub(crate) fn deadline(&self) -> Duration {
        self.delivery.deadline()
    }
    pub(crate) fn preparation(&self) -> Option<&tx::Preparation<C>> {
        self.preparation.as_ref()
    }
    /// Release the message borrow before actual target allocation and revalidation.
    pub(crate) fn into_preparation(self) -> Option<tx::Preparation<C>> {
        self.preparation
    }
}

/// Exact incoming bytes remain disjoint from reusable Control/Liveness scratch.
pub(crate) struct PendingEffect<C: tx::Configuration> {
    incoming: Incoming,
    envelope: Vec<u8>,
    operation: tx::Operation,
    effects: tx::Effects<C>,
}

impl<C: tx::Configuration> PendingEffect<C> {
    #[cfg(test)]
    pub(crate) fn incoming(&self) -> Incoming {
        self.incoming
    }
    #[cfg(test)]
    pub(crate) fn envelope(&self) -> &[u8] {
        &self.envelope
    }
    #[cfg(test)]
    pub(crate) fn operation(&self) -> tx::Operation {
        self.operation
    }
    #[cfg(test)]
    pub(crate) fn effects(&self) -> &tx::Effects<C> {
        &self.effects
    }
    #[cfg(test)]
    pub(crate) fn take_outbound(&mut self) -> Option<Vec<u8>> {
        self.effects.outbound.take()
    }
    pub(crate) fn into_parts(self) -> (Incoming, Vec<u8>, tx::Operation, tx::Effects<C>) {
        (self.incoming, self.envelope, self.operation, self.effects)
    }
}

/// One unadmitted candidate owned by this exact selected Control backend.
#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) struct Reservation {
    binding: delivery::Binding,
    operation: tx::Operation,
    context: tx::OutboundContext,
    submission: messages::SubmissionId,
    deadline: Duration,
    length: usize,
    digest: [u8; 32],
}

impl Reservation {
    pub(super) fn deadline(&self) -> Duration {
        self.deadline
    }
}

/// First exact logical envelope; Peer retries never replace its bytes or deadline.
pub(crate) struct FrozenOutput {
    reservation: Reservation,
    envelope: Vec<u8>,
    token: Option<Token>,
    cancelled: bool,
}

impl FrozenOutput {
    pub(crate) fn envelope(&self) -> &[u8] {
        &self.envelope
    }
    pub(crate) fn command(&self) -> &[u8] {
        &self.envelope[sc::HEADER_BYTES..]
    }
    pub(crate) fn operation(&self) -> tx::Operation {
        self.reservation.operation
    }
    pub(crate) fn context(&self) -> tx::OutboundContext {
        self.reservation.context
    }
    pub(crate) fn submission(&self) -> messages::SubmissionId {
        self.reservation.submission
    }
    pub(crate) fn deadline(&self) -> Duration {
        self.reservation.deadline
    }
    pub(crate) fn token(&self) -> Option<Token> {
        self.token
    }

    /// The caller still owns its ledger; this only checks actual Peer authority.
    pub(crate) fn logical_matches<C: tx::Configuration>(
        &self,
        peer: &tx::Peer<C>,
        command: &[u8],
    ) -> io::Result<bool> {
        if self.cancelled {
            return Err(invalid("cancelled frozen transaction output"));
        }
        let context = peer.outbound_context(command).map_err(protocol)?;
        let prior = management(self.command())?;
        let next = management(command)?;
        Ok(peer.operation() == Some(self.operation())
            && context == self.context()
            && prior.header.same_request(next.header)
            && prior.body == next.body)
    }
}

impl Owner {
    /// Explicit selection; old constructors, grammars and sequences are unchanged.
    #[cfg(test)]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new_leased(
        base: delivery::Settings,
        selected: Settings,
        binding: delivery::Binding,
        control_scope: sc::Scope,
        data_scope: sc::Scope,
        now: Duration,
        expires: Duration,
    ) -> io::Result<Self> {
        Self::new(
            base,
            Some(selected),
            binding,
            control_scope,
            data_scope,
            now,
            expires,
        )?
        .into_leased(control_scope, data_scope)
    }

    #[cfg(test)] // Preserve the preceding private runtime backing as a compatibility regression seam.
    #[allow(clippy::too_many_arguments)] // Existing contexts plus explicit actual ARQ backing limits.
    pub(crate) fn new_leased_reserved_arq(
        base: delivery::Settings,
        selected: Settings,
        binding: delivery::Binding,
        control_scope: sc::Scope,
        data_scope: sc::Scope,
        now: Duration,
        expires: Duration,
        limits: [recovery::storage::Limits; 3],
    ) -> io::Result<Self> {
        Self::construct(
            base,
            Some(selected),
            binding,
            control_scope,
            data_scope,
            now,
            expires,
            Storage::ReservedArq(limits),
        )?
        .into_leased(control_scope, data_scope)
    }

    #[allow(clippy::too_many_arguments)] // Existing contexts plus complete actual message heaps.
    #[cfg(test)] // Preserve the prior private constructor while production consumes its checked Plan.
    pub(crate) fn new_leased_reserved_messages(
        base: delivery::Settings,
        selected: Settings,
        binding: delivery::Binding,
        control_scope: sc::Scope,
        data_scope: sc::Scope,
        now: Duration,
        expires: Duration,
        limits: [messages::storage::Limits; 3],
    ) -> io::Result<Self> {
        let wrapper = wrapper_storage::Plan::new(selected, base)?;
        Self::new_leased_reserved_messages_with_wrapper_plan(
            base,
            selected,
            binding,
            control_scope,
            data_scope,
            now,
            expires,
            limits,
            wrapper,
            wrapper_storage::Limits {
                capacity_bytes: wrapper.capacity_bytes(),
            },
        )
    }

    #[allow(clippy::too_many_arguments)] // Exact original contexts and independently bounded wrapper backing.
    pub(crate) fn new_leased_reserved_messages_with_wrapper_plan(
        base: delivery::Settings,
        selected: Settings,
        binding: delivery::Binding,
        control_scope: sc::Scope,
        data_scope: sc::Scope,
        now: Duration,
        expires: Duration,
        limits: [messages::storage::Limits; 3],
        wrapper: wrapper_storage::Plan,
        wrapper_limit: wrapper_storage::Limits,
    ) -> io::Result<Self> {
        Self::construct(
            base,
            Some(selected),
            binding,
            control_scope,
            data_scope,
            now,
            expires,
            Storage::ReservedMessages {
                messages: limits,
                wrapper: &wrapper,
                wrapper_limit,
            },
        )?
        .into_leased(control_scope, data_scope)
    }

    fn into_leased(mut self, control_scope: sc::Scope, data_scope: sc::Scope) -> io::Result<Self> {
        let Backend::Streamed(streamed) = &mut self.backend else {
            return Err(invalid("leased Control requires streamed owners"));
        };
        streamed.gate = streams::gate::Gate::new_transaction_bound(streams::gate::GateSettings {
            binding: sc::PeerBinding {
                session: self.binding.session,
                remote_role: opposite(self.binding.local_role),
                control_lane: self.binding.lane,
                data_lanes: [Some(self.binding.lane), None],
            },
            control: control_scope,
            active: policy(data_scope),
            limits: envelope_limits(streamed.envelope.len())?,
        })
        .map_err(invalid)?;
        streamed.leased = true;
        Ok(self)
    }

    pub(crate) fn transaction_binding(&self) -> io::Result<delivery::Binding> {
        self.leased()?;
        streams::delivery_binding(self.binding, streams::Stream::Transaction).map_err(invalid)
    }

    /// Preview actual pending bytes without observing time or consuming custody.
    /// The caller retains the original operation cap and must revalidate on dispatch.
    pub(crate) fn preview_transaction<C: tx::Configuration>(
        &self,
        peer: &tx::Peer<C>,
        now: Duration,
        cap: tx::Tick,
    ) -> io::Result<Option<PendingTransaction<'_, C>>> {
        let streamed = self.leased()?;
        if self.failed {
            return Err(protocol("control proof callback failed"));
        }
        if now < self.now {
            return Err(protocol("control time moved backwards"));
        }
        if now >= self.expires {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "original control session expiry",
            ));
        }
        if streamed
            .reservation
            .as_ref()
            .is_some_and(|entry| now >= entry.deadline())
        {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "original frozen control message deadline",
            ));
        }
        for owner in &streamed.owners {
            owner.check_time(now).map_err(protocol)?;
        }
        let i = index(streams::Stream::Transaction);
        if streamed.held[i].is_some() {
            return Ok(None);
        }
        let Some(delivery) = streamed.owners[i].pending() else {
            return Ok(None);
        };
        let preparation = streamed
            .gate
            .preview_transaction(
                peer,
                authenticated_remote(self.binding),
                streams::Stream::Transaction,
                delivery.bytes(),
                tick(now)?,
                cap,
            )
            .map_err(protocol)?;
        Ok(Some(PendingTransaction {
            incoming: Incoming {
                token: Token {
                    binding: self.binding,
                    kind: TokenKind::Streamed {
                        stream: streams::Stream::Transaction,
                        ticket: delivery.ticket(),
                    },
                },
                bytes: delivery.bytes().len(),
                stream: Some(streams::Stream::Transaction),
            },
            delivery,
            preparation,
        }))
    }

    /// Reserve bytes/effect custody before joint Gate and actual Peer admission.
    pub(crate) fn dispatch_transaction<C: tx::Configuration>(
        &mut self,
        peer: &mut tx::Peer<C>,
        now: Duration,
        cap: tx::Tick,
        effect: &mut Option<PendingEffect<C>>,
    ) -> io::Result<DispatchProgress> {
        self.leased()?;
        self.observe(now)?;
        if effect.is_some() {
            return Ok(DispatchProgress::Blocked);
        }
        let tick = tick(now)?;
        let binding = self.binding;
        let streamed = self.leased_mut()?;
        let i = index(streams::Stream::Transaction);
        if streamed.held[i].is_some() {
            return Ok(DispatchProgress::Blocked);
        }
        let Some(delivery) = streamed.owners[i].pending() else {
            return Ok(DispatchProgress::Idle);
        };
        let envelope = sc::Envelope::decode(
            delivery.bytes(),
            envelope_limits(streamed.settings.streams[i].max_message_bytes)?,
        )
        .map_err(protocol)?;
        if incoming_stream(envelope.body, true)? != streams::Stream::Transaction {
            return Err(protocol("nontransaction message in Transaction owner"));
        }
        let scope = envelope.binding.scope;
        let incoming = Incoming {
            token: Token {
                binding,
                kind: TokenKind::Streamed {
                    stream: streams::Stream::Transaction,
                    ticket: delivery.ticket(),
                },
            },
            bytes: delivery.bytes().len(),
            stream: Some(streams::Stream::Transaction),
        };
        let deadline = delivery.deadline();
        let exact = copied(delivery.bytes())?;
        let effects = streamed
            .gate
            .receive_transaction(
                peer,
                authenticated_remote(binding),
                streams::Stream::Transaction,
                &exact,
                tick,
                cap,
            )
            .map_err(protocol)?;
        let Some(operation) = peer.operation() else {
            self.failed = true;
            return Err(protocol("successful leased dispatch lost its operation"));
        };
        *effect = Some(PendingEffect {
            incoming,
            envelope: exact,
            operation,
            effects,
        });
        streamed.held[i] = Some(Held {
            incoming,
            scope,
            deadline,
            dispatched: true,
            leased: true,
        });
        Ok(DispatchProgress::Dispatched)
    }

    /// Borrow proof only after the real owner retained its acceptance receipt.
    pub(crate) fn with_accepted<R>(
        &mut self,
        incoming: Incoming,
        now: Duration,
        finish: impl for<'p> FnOnce(&messages::Accepted<'p>) -> io::Result<R>,
    ) -> io::Result<Attempt<R>> {
        self.check_token(incoming.token)?;
        self.leased()?;
        self.observe(now)?;
        let streamed = self.leased_mut()?;
        let i = index(streams::Stream::Transaction);
        let held = streamed.held[i]
            .filter(|held| held.incoming == incoming && held.leased && held.dispatched)
            .ok_or_else(|| invalid("unknown dispatched leased incoming ticket"))?;
        let TokenKind::Streamed { stream, ticket } = held.incoming.token.kind else {
            return Err(invalid("leased incoming contains legacy custody"));
        };
        if stream != streams::Stream::Transaction {
            return Err(invalid("leased acceptance requires Transaction custody"));
        }
        let result = match streamed.owners[i].accept_with_receipt(ticket, now) {
            Ok(proof) => finish(&proof),
            Err(messages::Error::Backpressure) => return Ok(Attempt::Blocked),
            Err(error) => return Err(protocol(error)),
        };
        match result {
            Ok(value) => {
                streamed.held[i] = None;
                Ok(Attempt::Complete(value))
            }
            Err(error) => {
                self.failed = true;
                Err(error)
            }
        }
    }

    /// Source ACKs or bool observations cannot manufacture this borrowed proof.
    pub(crate) fn with_confirmed<R>(
        &mut self,
        token: Token,
        now: Duration,
        finish: impl for<'p> FnOnce(&messages::Confirmed<'p>) -> io::Result<R>,
    ) -> io::Result<Attempt<R>> {
        self.check_token(token)?;
        self.leased()?;
        self.observe(now)?;
        let streamed = self.leased_mut()?;
        let TokenKind::Streamed { stream, ticket } = token.kind else {
            return Err(invalid("leased confirmation contains legacy custody"));
        };
        if stream != streams::Stream::Transaction {
            return Err(invalid("leased confirmation requires Transaction custody"));
        }
        let i = index(stream);
        let position = streamed.outgoing[i]
            .iter()
            .position(|entry| entry.token == token)
            .ok_or_else(|| invalid("unknown leased outgoing ticket"))?;
        let result = match streamed.owners[i]
            .confirmation(ticket, now)
            .map_err(protocol)?
        {
            Some(proof) => finish(&proof),
            None => return Ok(Attempt::Blocked),
        };
        match result {
            Ok(value) => {
                streamed.outgoing[i][position].confirmed = true;
                Ok(Attempt::Complete(value))
            }
            Err(error) => {
                self.failed = true;
                Err(error)
            }
        }
    }

    /// Freeze one actual Peer-owned logical output before its first admission.
    pub(crate) fn freeze_transaction<C: tx::Configuration>(
        &mut self,
        peer: &tx::Peer<C>,
        command: &[u8],
        now: Duration,
    ) -> io::Result<FrozenOutput> {
        self.leased()?;
        self.observe(now)?;
        let context = peer.outbound_context(command).map_err(protocol)?;
        let operation = peer
            .operation()
            .ok_or_else(|| invalid("Peer has no owned operation"))?;
        check_identity(self.binding, operation)?;
        if context.origin() != operation.origin() || context.expires() != operation.expires() {
            return Err(protocol("Peer output context changed original authority"));
        }
        let expires = self.expires;
        let binding = self.binding;
        let streamed = self.leased_mut()?;
        if streamed.reservation.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "Transaction output is reserved",
            ));
        }
        let i = index(streams::Stream::Transaction);
        let operation_cap = Duration::from_millis(context.expires().0);
        let deadline = now
            .checked_add(streamed.settings.streams[i].message_lifetime)
            .ok_or_else(exhausted)?
            .min(operation_cap)
            .min(expires);
        if deadline <= now {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "original transaction cap expired",
            ));
        }
        streamed.next[i].checked_add(1).ok_or_else(exhausted)?;
        let submission = messages::SubmissionId(streamed.next[i]);
        let envelope = sc::Envelope {
            binding: envelope_binding(binding, submission.0, context.origin()),
            body: sc::Body::Management(command),
        };
        let limits = envelope_limits(streamed.settings.streams[i].max_message_bytes)?;
        let length = envelope.encoded_len(limits).map_err(protocol)?;
        let mut bytes = Vec::new();
        bytes.try_reserve_exact(length).map_err(invalid)?;
        bytes.resize(length, 0);
        envelope.encode(&mut bytes, limits).map_err(protocol)?;
        let reservation = Reservation {
            binding,
            operation,
            context,
            submission,
            deadline,
            length,
            digest: digest(&bytes),
        };
        streamed.reservation = Some(reservation);
        Ok(FrozenOutput {
            reservation,
            envelope: bytes,
            token: None,
            cancelled: false,
        })
    }

    /// Admission pressure retains the exact candidate ID, bytes and deadline.
    pub(crate) fn submit_frozen(
        &mut self,
        output: &mut FrozenOutput,
        now: Duration,
    ) -> io::Result<Attempt<Token>> {
        self.leased()?;
        self.observe(now)?;
        if output.cancelled || output.reservation.binding != self.binding {
            return Err(invalid("frozen output belongs to another Control owner"));
        }
        if let Some(token) = output.token {
            let streamed = self.leased()?;
            if streamed.outgoing[index(streams::Stream::Transaction)]
                .iter()
                .any(|entry| entry.token == token)
            {
                return Ok(Attempt::Complete(token));
            }
            return Err(invalid("frozen output has already retired"));
        }
        let binding = self.binding;
        let streamed = self.leased_mut()?;
        validate_reservation(streamed, output)?;
        let i = index(streams::Stream::Transaction);
        if streamed.outgoing[i].len() >= streamed.settings.streams[i].max_outbound_messages {
            return Ok(Attempt::Blocked);
        }
        let next = streamed.next[i].checked_add(1).ok_or_else(exhausted)?;
        match streamed.owners[i].submit(
            output.submission(),
            output.envelope(),
            now,
            output.deadline(),
        ) {
            Ok(ticket) => {
                let token = Token {
                    binding,
                    kind: TokenKind::Streamed {
                        stream: streams::Stream::Transaction,
                        ticket,
                    },
                };
                streamed.outgoing[i].push(Outgoing {
                    token,
                    scope: output.context().origin(),
                    deadline: output.deadline(),
                    auto_retire: false,
                    confirmed: false,
                });
                streamed.next[i] = next;
                streamed.reservation = None;
                output.token = Some(token);
                Ok(Attempt::Complete(token))
            }
            Err(messages::Error::Backpressure) => Ok(Attempt::Blocked),
            Err(error) => Err(protocol(error)),
        }
    }

    /// Release only an unadmitted command superseded by its actual leased Peer.
    pub(crate) fn cancel_frozen<C: tx::Configuration>(
        &mut self,
        peer: &tx::Peer<C>,
        output: &mut FrozenOutput,
        now: Duration,
    ) -> io::Result<()> {
        self.observe(now)?;
        if output.token.is_some() || peer.operation() != Some(output.operation()) {
            return Err(invalid(
                "frozen output cannot be cancelled under another operation",
            ));
        }
        check_identity(self.binding, output.operation())?;
        match peer.outbound_context(output.command()) {
            Err(tx::Error::Custody) => {}
            Ok(_) => return Err(invalid("actual Peer still owns the frozen command")),
            Err(error) => return Err(protocol(error)),
        }
        let streamed = self.leased_mut()?;
        validate_reservation(streamed, output)?;
        streamed.reservation = None;
        output.cancelled = true;
        Ok(())
    }

    /// Data authority can retire while exact leased final-message custody remains.
    pub(crate) fn retire_leased_draining<C: tx::Configuration>(
        &mut self,
        peer: &tx::Peer<C>,
        scope: sc::Scope,
        now: Duration,
    ) -> io::Result<()> {
        self.leased()?;
        self.observe(now)?;
        if !peer.is_leased() || peer.reader(scope.epoch).is_some() {
            return Err(invalid("actual Peer still retains the old reader"));
        }
        if let Some(operation) = peer.operation() {
            check_identity(self.binding, operation)?;
        }
        let streamed = self.leased_mut()?;
        if streamed.active.epoch != peer.active_epoch()
            || streamed.active.digest
                != tx::configuration_digest(peer.active_config()).map_err(protocol)?
        {
            return Err(invalid("Control active scope does not match actual Peer"));
        }
        streamed.gate.retire_draining(scope).map_err(protocol)?;
        streamed.draining = None;
        Ok(())
    }

    fn leased(&self) -> io::Result<&Streamed> {
        match &self.backend {
            Backend::Streamed(streamed) if streamed.leased => Ok(streamed),
            _ => Err(invalid(
                "leased transaction Control contract was not selected",
            )),
        }
    }
    fn leased_mut(&mut self) -> io::Result<&mut Streamed> {
        match &mut self.backend {
            Backend::Streamed(streamed) if streamed.leased => Ok(streamed),
            _ => Err(invalid(
                "leased transaction Control contract was not selected",
            )),
        }
    }
}

pub(super) fn incoming_stream(body: sc::Body<'_>, leased: bool) -> io::Result<streams::Stream> {
    match body {
        sc::Body::Management(_) if leased => Ok(streams::Stream::Transaction),
        sc::Body::ProfileControl { .. } if leased => Err(protocol(
            "SwiftPolicyV1 is not the leased Management contract",
        )),
        _ => outgoing_stream(body),
    }
}

fn tick(now: Duration) -> io::Result<tx::Tick> {
    u64::try_from(now.as_millis())
        .map(tx::Tick)
        .map_err(invalid)
}
fn copied(bytes: &[u8]) -> io::Result<Vec<u8>> {
    let mut result = Vec::new();
    result.try_reserve_exact(bytes.len()).map_err(invalid)?;
    result.extend_from_slice(bytes);
    Ok(result)
}
fn digest(bytes: &[u8]) -> [u8; 32] {
    let mut result = [0; 32];
    result.copy_from_slice(ring::digest::digest(&ring::digest::SHA256, bytes).as_ref());
    result
}
fn management(bytes: &[u8]) -> io::Result<mg::Frame<'_>> {
    mg::Frame::decode(bytes, mg::Limits::default()).map_err(protocol)
}
fn authenticated_remote(binding: delivery::Binding) -> mg::Ingress {
    mg::Ingress::AuthenticatedManagement {
        session: binding.session,
        lane: binding.lane,
        sender: opposite(binding.local_role),
    }
}
fn check_identity(binding: delivery::Binding, operation: tx::Operation) -> io::Result<()> {
    let identity = operation.identity();
    if identity.session != binding.session
        || identity.lane != binding.lane
        || identity.role != binding.local_role
    {
        return Err(invalid(
            "actual leased Peer binding differs from Control owner",
        ));
    }
    Ok(())
}
fn validate_reservation(streamed: &Streamed, output: &FrozenOutput) -> io::Result<()> {
    let i = index(streams::Stream::Transaction);
    if output.cancelled
        || streamed.reservation != Some(output.reservation)
        || streamed.next[i] != output.submission().0
        || output.envelope.len() != output.reservation.length
        || digest(&output.envelope) != output.reservation.digest
    {
        return Err(invalid("frozen Transaction reservation changed"));
    }
    Ok(())
}
