//! Explicit control-backend ownership without a socket or cryptographic owner.
//!
//! The caller authenticates Control records before ingress and dispatches exact
//! presented envelopes before accepting them. Streamed completion means whole
//! message custody, never an applied policy or a generic mode transaction.

use l2tunnel_management::{
    self as mg, control_streams as streams, delivery, messages, session_control as sc,
};
use l2tunnel_recovery as recovery;
use std::{io, time::Duration};

#[path = "control_leased.rs"]
mod leased;
#[path = "control_wrapper_storage.rs"]
pub(crate) mod wrapper_storage;
#[cfg(test)]
pub(crate) use leased::PendingEffect;
pub(crate) use leased::{Attempt, DispatchProgress, FrozenOutput};

/// Explicit per-stream storage/recovery bounds under one shared service budget.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Settings {
    /// Transaction, Liveness and DataFeedback settings in that fixed order.
    pub streams: [messages::Settings; 3],
}

impl Settings {
    /// Exact existing streamed packet layout, without constructing an owner.
    pub(crate) fn max_packet_bytes(self, base: delivery::Settings) -> io::Result<usize> {
        raw_packet_bytes(base)?
            .checked_add(streams::HEADER_BYTES)
            .ok_or_else(|| invalid("wrapper size overflow"))
    }

    /// Persistent wrapper heap only; message heaps and bridge copies are separate.
    #[cfg(test)] // Compatibility view; production consumes the exact typed wrapper Plan.
    pub(crate) fn wrapper_capacity_bytes(self, base: delivery::Settings) -> io::Result<usize> {
        Ok(wrapper_storage::Plan::new(self, base)?.capacity_bytes())
    }

    /// Pure complete message plans under the actual independently bound streams.
    pub(crate) fn message_storage_plans(
        self,
        binding: delivery::Binding,
        now: Duration,
        expires: Duration,
    ) -> io::Result<[messages::storage::Plan; 3]> {
        let make = |index: usize| {
            messages::storage::Plan::for_owner(
                self.streams[index],
                streams::delivery_binding(binding, streams::Stream::ALL[index]).map_err(invalid)?,
                now,
                expires,
            )
            .map_err(invalid)
        };
        Ok([make(0)?, make(1)?, make(2)?])
    }

    /// Validate actual owners, exact wrapper overhead and complete path geometry.
    /// Message lifetimes may exceed the session; each owner clamps its expiry.
    pub fn validate(
        self,
        base: delivery::Settings,
        path_mtu: usize,
        lifetime: Duration,
    ) -> io::Result<()> {
        streams::Limits {
            max_packet_bytes: base
                .recovery
                .max_source_bytes
                .checked_add(recovery::DATA_HEADER_BYTES)
                .ok_or_else(|| invalid("control packet size overflow"))?,
        }
        .validate()
        .map_err(invalid)?;
        let expected = delivery::Settings {
            wire_overhead: base
                .wire_overhead
                .checked_add(streams::HEADER_BYTES)
                .ok_or_else(|| invalid("stream wrapper overhead overflow"))?,
            ..base
        };
        let binding = delivery::Binding {
            session: mg::SessionId([1; 16]),
            lane: mg::LaneId(0),
            local_role: mg::Role::Client,
            control_epoch: 1,
        };
        for (stream, settings) in streams::Stream::ALL.into_iter().zip(self.streams) {
            if settings.delivery != expected || settings.path_mtu != path_mtu {
                return Err(invalid(
                    "stream settings must preserve base service bounds and exact wrapper geometry",
                ));
            }
            envelope_limits(settings.max_message_bytes)?;
            let chunk = base
                .recovery
                .max_source_bytes
                .checked_sub(1 + l2tunnel_codec::FRAGMENT_HEADER_BYTES)
                .filter(|chunk| *chunk > 0)
                .ok_or_else(|| invalid("control fragment has no payload capacity"))?;
            if settings.max_message_bytes.div_ceil(chunk) > usize::from(settings.max_fragments) {
                return Err(invalid(
                    "fragment bound cannot carry the declared whole-message ceiling",
                ));
            }
            settings
                .validate(
                    streams::delivery_binding(binding, stream).map_err(invalid)?,
                    Duration::ZERO,
                    lifetime,
                )
                .map_err(invalid)?;
        }
        Ok(())
    }
}

/// Opaque ownership of an admitted original source or complete message.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Token {
    binding: delivery::Binding,
    kind: TokenKind,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TokenKind {
    Legacy(u64),
    Streamed {
        stream: streams::Stream,
        ticket: messages::Ticket,
    },
}

/// One exact envelope presented once for the caller's semantic dispatcher.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Incoming {
    pub token: Token,
    pub bytes: usize,
    pub stream: Option<streams::Stream>,
}

struct Legacy {
    service: delivery::Service,
    next: u64,
    envelope: Vec<u8>,
    limits: sc::Limits,
}

struct Outgoing {
    token: Token,
    scope: sc::Scope,
    deadline: Duration,
    auto_retire: bool,
    confirmed: bool,
}

#[derive(Clone, Copy)]
struct Held {
    incoming: Incoming,
    scope: sc::Scope,
    deadline: Duration,
    dispatched: bool,
    leased: bool,
}

struct Streamed {
    leased: bool,
    reservation: Option<leased::Reservation>,
    owners: [messages::Owner; 3],
    gate: streams::gate::Gate,
    settings: Settings,
    next: [u64; 3],
    outgoing: [Vec<Outgoing>; 3],
    held: [Option<Held>; 3],
    control_scope: sc::Scope,
    active: sc::Scope,
    draining: Option<sc::Scope>,
    envelope: Vec<u8>,
    raw: Vec<u8>,
    poll_cursor: usize,
    receive_cursor: usize,
    auto_cursor: usize,
    quota: delivery::Settings,
    refill: Duration,
    packets_left: u32,
    bytes_left: usize,
}

fn raw_packet_bytes(base: delivery::Settings) -> io::Result<usize> {
    base.recovery
        .max_source_bytes
        .checked_add(recovery::DATA_HEADER_BYTES)
        .ok_or_else(|| invalid("control packet size overflow"))
}

fn wrapper_layout(outgoing: [usize; 3], envelope: usize, raw: usize) -> io::Result<usize> {
    let mut total = std::mem::size_of::<Streamed>();
    for count in outgoing {
        let bytes = std::alloc::Layout::array::<Outgoing>(count)
            .map_err(invalid)?
            .size();
        total = total
            .checked_add(bytes)
            .ok_or_else(|| invalid("control wrapper layout overflow"))?;
    }
    for size in [envelope, raw] {
        let bytes = std::alloc::Layout::array::<u8>(size)
            .map_err(invalid)?
            .size();
        total = total
            .checked_add(bytes)
            .ok_or_else(|| invalid("control wrapper layout overflow"))?;
    }
    Ok(total)
}

#[derive(Clone, Copy)]
enum Storage<'a> {
    Legacy,
    #[cfg(test)]
    ReservedArq([recovery::storage::Limits; 3]),
    ReservedMessages {
        messages: [messages::storage::Limits; 3],
        wrapper: &'a wrapper_storage::Plan,
        wrapper_limit: wrapper_storage::Limits,
    },
}

enum Backend {
    Legacy(Box<Legacy>),
    Streamed(wrapper_storage::StreamedStorage),
}

/// Selected bounded control transport; all actual I/O remains with its caller.
pub(crate) struct Owner {
    backend: Backend,
    binding: delivery::Binding,
    expires: Duration,
    now: Duration,
    max_packet: usize,
    failed: bool,
}

/// Unpublished actual owners; errors release every earlier completed stream.
/// This guard is temporary construction state, not part of the retained owner.
#[derive(Default)]
struct StreamConstruction {
    owners: [Option<(streams::Stream, messages::Owner)>; 3],
    #[cfg(test)]
    observer: Option<Box<dyn FnMut(StreamConstructionDrop)>>,
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum StreamConstructionDrop {
    Before(streams::Stream, Option<recovery::storage::Usage>),
    After(streams::Stream),
}

impl StreamConstruction {
    fn collect<L: Copy>(
        mut self,
        settings: Settings,
        binding: delivery::Binding,
        limits: Option<[L; 3]>,
        mut factory: impl FnMut(
            streams::Stream,
            messages::Settings,
            delivery::Binding,
            Option<L>,
        ) -> io::Result<messages::Owner>,
    ) -> io::Result<[messages::Owner; 3]> {
        for (index, (stream, settings)) in streams::Stream::ALL
            .into_iter()
            .zip(settings.streams)
            .enumerate()
        {
            let binding = streams::delivery_binding(binding, stream).map_err(invalid)?;
            self.owners[index] = Some((
                stream,
                factory(
                    stream,
                    settings,
                    binding,
                    limits.map(|limits| limits[index]),
                )?,
            ));
        }
        self.finish()
    }

    fn from_owners(
        owners: [messages::Owner; 3],
        _allocation: &mut wrapper_storage::Allocation,
    ) -> Self {
        let [transaction, liveness, feedback] = owners;
        Self {
            owners: [
                Some((streams::Stream::Transaction, transaction)),
                Some((streams::Stream::Liveness, liveness)),
                Some((streams::Stream::DataFeedback, feedback)),
            ],
            #[cfg(test)]
            observer: _allocation.owner_observer.take(),
        }
    }

    fn finish(mut self) -> io::Result<[messages::Owner; 3]> {
        let [
            Some((_, transaction)),
            Some((_, liveness)),
            Some((_, feedback)),
        ] = std::mem::take(&mut self.owners)
        else {
            return Err(invalid("control stream count"));
        };
        Ok([transaction, liveness, feedback])
    }
}

impl Drop for StreamConstruction {
    fn drop(&mut self) {
        for owner in &mut self.owners {
            if let Some((_stream, owner)) = owner.take() {
                #[cfg(test)]
                if let Some(observer) = &mut self.observer {
                    observer(StreamConstructionDrop::Before(
                        _stream,
                        owner.arq_storage_usage(),
                    ));
                }
                drop(owner);
                #[cfg(test)]
                if let Some(observer) = &mut self.observer {
                    observer(StreamConstructionDrop::After(_stream));
                }
            }
        }
    }
}

fn construct_stream_owners(
    settings: Settings,
    binding: delivery::Binding,
    limits: Option<[recovery::storage::Limits; 3]>,
    factory: impl FnMut(
        streams::Stream,
        messages::Settings,
        delivery::Binding,
        Option<recovery::storage::Limits>,
    ) -> io::Result<messages::Owner>,
) -> io::Result<[messages::Owner; 3]> {
    StreamConstruction::default().collect(settings, binding, limits, factory)
}

impl Owner {
    #[allow(clippy::too_many_arguments)] // The frozen boundary names each independent context.
    pub(crate) fn new(
        base: delivery::Settings,
        selected: Option<Settings>,
        binding: delivery::Binding,
        control_scope: sc::Scope,
        data_scope: sc::Scope,
        now: Duration,
        expires: Duration,
    ) -> io::Result<Self> {
        Self::construct(
            base,
            selected,
            binding,
            control_scope,
            data_scope,
            now,
            expires,
            Storage::Legacy,
        )
    }

    /// Actual three-stream ARQ subset for compatibility and complete-owner regressions.
    #[cfg(test)]
    pub(crate) fn arq_storage_usage(&self) -> Option<[recovery::storage::Usage; 3]> {
        let Backend::Streamed(streamed) = &self.backend else {
            return None;
        };
        Some([
            streamed.owners[0].arq_storage_usage()?,
            streamed.owners[1].arq_storage_usage()?,
            streamed.owners[2].arq_storage_usage()?,
        ])
    }

    /// Actual complete message heaps, including their ARQ/reassembly subpools once.
    pub(crate) fn message_storage_usage(&self) -> Option<[messages::storage::Usage; 3]> {
        let Backend::Streamed(streamed) = &self.backend else {
            return None;
        };
        Some([
            streamed.owners[0].storage_usage()?,
            streamed.owners[1].storage_usage()?,
            streamed.owners[2].storage_usage()?,
        ])
    }

    pub(crate) fn wrapper_capacity_bytes(&self) -> io::Result<usize> {
        let Backend::Streamed(streamed) = &self.backend else {
            return Err(invalid("wrapper storage requires streamed control"));
        };
        wrapper_layout(
            streamed.outgoing.each_ref().map(|values| values.capacity()),
            streamed.envelope.capacity(),
            streamed.raw.capacity(),
        )
    }

    /// Actual fallibly provisioned wrapper backing, separate from message heaps.
    pub(crate) fn wrapper_storage_usage(&self) -> io::Result<Option<wrapper_storage::Usage>> {
        match &self.backend {
            Backend::Legacy(_) => Ok(None),
            Backend::Streamed(streamed) => streamed.usage(),
        }
    }

    #[allow(clippy::too_many_arguments)] // Existing contexts plus explicit per-stream backing limits.
    fn construct(
        base: delivery::Settings,
        selected: Option<Settings>,
        binding: delivery::Binding,
        control_scope: sc::Scope,
        data_scope: sc::Scope,
        now: Duration,
        expires: Duration,
        storage: Storage<'_>,
    ) -> io::Result<Self> {
        Self::construct_with_wrapper_allocation(
            base,
            selected,
            binding,
            control_scope,
            data_scope,
            now,
            expires,
            storage,
            &mut wrapper_storage::Allocation::default(),
        )
    }

    #[allow(clippy::too_many_arguments)] // Existing construction plus one local reservation context.
    fn construct_with_wrapper_allocation(
        base: delivery::Settings,
        selected: Option<Settings>,
        binding: delivery::Binding,
        control_scope: sc::Scope,
        data_scope: sc::Scope,
        now: Duration,
        expires: Duration,
        storage: Storage<'_>,
        allocation: &mut wrapper_storage::Allocation,
    ) -> io::Result<Self> {
        if selected.is_none() && !matches!(storage, Storage::Legacy) {
            return Err(invalid("reserved control requires explicit streams"));
        }
        let raw = raw_packet_bytes(base)?;
        let (backend, max_packet) = if let Some(settings) = selected {
            Self::construct_streamed(
                base,
                settings,
                binding,
                control_scope,
                data_scope,
                now,
                expires,
                raw,
                storage,
                allocation,
            )?
        } else {
            let limits = sc::Limits {
                max_frame_bytes: base.recovery.max_source_bytes,
                max_management_bytes: mg::HEADER_LEN,
                max_feedback_bytes: 1,
            };
            limits.validate().map_err(invalid)?;
            (
                Backend::Legacy(Box::new(Legacy {
                    service: delivery::Service::new(base, binding, now, expires)
                        .map_err(invalid)?,
                    next: 1,
                    envelope: vec![0; base.recovery.max_source_bytes],
                    limits,
                })),
                raw,
            )
        };
        Ok(Self {
            backend,
            binding,
            expires,
            now,
            max_packet,
            failed: false,
        })
    }

    #[allow(clippy::too_many_arguments)] // Selected synchronous provisioning stays off the legacy constructor stack.
    fn construct_streamed(
        base: delivery::Settings,
        settings: Settings,
        binding: delivery::Binding,
        control_scope: sc::Scope,
        data_scope: sc::Scope,
        now: Duration,
        expires: Duration,
        raw: usize,
        storage: Storage<'_>,
        allocation: &mut wrapper_storage::Allocation,
    ) -> io::Result<(Backend, usize)> {
        let lifetime = expires
            .checked_sub(now)
            .ok_or_else(|| invalid("control already expired"))?;
        settings.validate(base, settings.streams[0].path_mtu, lifetime)?;
        if let Storage::ReservedMessages {
            wrapper,
            wrapper_limit,
            ..
        } = storage
        {
            wrapper.check(&settings, &base, wrapper_limit)?;
        }
        let maximum = settings
            .streams
            .iter()
            .map(|settings| settings.max_message_bytes)
            .max()
            .ok_or_else(|| invalid("missing control streams"))?;
        let make_gate = || {
            streams::gate::Gate::new(streams::gate::GateSettings {
                binding: sc::PeerBinding {
                    session: binding.session,
                    remote_role: opposite(binding.local_role),
                    control_lane: binding.lane,
                    data_lanes: [Some(binding.lane), None],
                },
                control: control_scope,
                active: policy(data_scope),
                limits: envelope_limits(maximum)?,
            })
            .map_err(invalid)
        };
        let reserved_gate = if matches!(storage, Storage::ReservedMessages { .. }) {
            Some(make_gate()?)
        } else {
            None
        };
        #[cfg(test)]
        if let Storage::ReservedArq(limits) = storage {
            // Preflight all three pool limits before allocating the first stream.
            for (settings, limit) in settings.streams.into_iter().zip(limits) {
                let plan = recovery::storage::Plan::for_arq(settings.delivery.recovery)
                    .map_err(invalid)?;
                if plan.capacity_bytes() > limit.capacity_bytes {
                    return Err(invalid("control ARQ storage limit"));
                }
            }
        }
        let owners = if let Storage::ReservedMessages {
            messages: limits, ..
        } = storage
        {
            let plans = settings.message_storage_plans(binding, now, expires)?;
            for (plan, limit) in plans.iter().zip(limits) {
                if plan.capacity_bytes() > limit.capacity_bytes {
                    return Err(invalid("control complete message storage limit"));
                }
            }
            StreamConstruction::default().collect(
                settings,
                binding,
                Some(limits),
                |_, settings, stream_binding, limit| {
                    messages::Owner::new_reserved(
                        settings,
                        stream_binding,
                        now,
                        expires,
                        limit.ok_or_else(|| invalid("missing complete message limit"))?,
                    )
                    .map_err(invalid)
                },
            )?
        } else {
            #[cfg(not(test))]
            let arq_limits = None;
            #[cfg(test)]
            let arq_limits = match storage {
                Storage::ReservedArq(limits) => Some(limits),
                _ => None,
            };
            construct_stream_owners(
                settings,
                binding,
                arq_limits,
                |_, settings, stream_binding, limit| match limit {
                    Some(limit) => messages::Owner::new_reserved_arq(
                        settings,
                        stream_binding,
                        now,
                        expires,
                        limit,
                    )
                    .map_err(invalid),
                    None => messages::Owner::new(settings, stream_binding, now, expires)
                        .map_err(invalid),
                },
            )?
        };
        let gate = match reserved_gate {
            Some(gate) => gate,
            None => make_gate()?,
        };
        let size = settings.max_packet_bytes(base)?;
        let owners = StreamConstruction::from_owners(owners, allocation);
        let build = move |outgoing, envelope, raw| {
            Ok(Streamed {
                leased: false,
                reservation: None,
                owners: owners.finish()?,
                gate,
                settings,
                next: [1; 3],
                outgoing,
                held: [None; 3],
                control_scope,
                active: data_scope,
                draining: None,
                envelope,
                raw,
                poll_cursor: 0,
                receive_cursor: 0,
                auto_cursor: 0,
                quota: base,
                refill: now,
                packets_left: 0,
                bytes_left: 0,
            })
        };
        let streamed = match storage {
            Storage::ReservedMessages {
                wrapper,
                wrapper_limit,
                ..
            } => wrapper.provision(wrapper_limit, allocation, build)?,
            _ => wrapper_storage::StreamedStorage::Legacy(Box::new(build(
                std::array::from_fn(|i| {
                    Vec::with_capacity(settings.streams[i].max_outbound_messages)
                }),
                vec![0; maximum],
                vec![0; raw],
            )?)),
        };
        Ok((Backend::Streamed(streamed), size))
    }

    pub(crate) fn max_packet_bytes(&self) -> usize {
        self.max_packet
    }

    /// Reserve one immutable envelope only when the actual source/message owner accepts it.
    /// A refused admission consumes no envelope or submission identity.
    /// Streamed custody receives its own immutable expiry bounded by the caller's
    /// original operation cap; this does not replace that operation's deadline.
    pub(crate) fn submit(
        &mut self,
        scope: sc::Scope,
        body: sc::Body<'_>,
        now: Duration,
        original_deadline: Duration,
        auto_retire: bool,
    ) -> io::Result<Option<Token>> {
        self.observe(now)?;
        match &mut self.backend {
            Backend::Legacy(legacy) => {
                let next = legacy.next.checked_add(1).ok_or_else(exhausted)?;
                let envelope = sc::Envelope {
                    binding: envelope_binding(self.binding, legacy.next, scope),
                    body,
                };
                let length = envelope
                    .encode(&mut legacy.envelope, legacy.limits)
                    .map_err(protocol)?;
                match legacy.service.submit(&legacy.envelope[..length], now) {
                    Ok(source) => {
                        legacy.next = next;
                        Ok(Some(Token {
                            binding: self.binding,
                            kind: TokenKind::Legacy(source),
                        }))
                    }
                    Err(delivery::Error::Recovery(recovery::RecoveryError::Capacity(
                        recovery::BufferSide::Send,
                    ))) => Ok(None),
                    Err(error) => Err(protocol(error)),
                }
            }
            Backend::Streamed(streamed) => {
                let streamed = &mut **streamed;
                let stream = outgoing_stream(body)?;
                if streamed.leased && stream == streams::Stream::Transaction {
                    return Err(invalid("leased Management requires frozen Peer output"));
                }
                let i = index(stream);
                if auto_retire && stream != streams::Stream::Liveness {
                    return Err(invalid("profile tokens require explicit completion"));
                }
                if (stream == streams::Stream::Liveness && scope != streamed.control_scope)
                    || (stream == streams::Stream::Transaction
                        && scope != streamed.active
                        && Some(scope) != streamed.draining)
                {
                    return Err(invalid("outgoing control origin is not registered"));
                }
                let next = streamed.next[i].checked_add(1).ok_or_else(exhausted)?;
                let deadline = now
                    .checked_add(streamed.settings.streams[i].message_lifetime)
                    .ok_or_else(exhausted)?
                    .min(original_deadline)
                    .min(self.expires);
                let envelope = sc::Envelope {
                    binding: envelope_binding(self.binding, streamed.next[i], scope),
                    body,
                };
                let length = envelope
                    .encode(
                        &mut streamed.envelope,
                        envelope_limits(streamed.settings.streams[i].max_message_bytes)?,
                    )
                    .map_err(protocol)?;
                match streamed.owners[i].submit(
                    messages::SubmissionId(streamed.next[i]),
                    &streamed.envelope[..length],
                    now,
                    deadline,
                ) {
                    Ok(ticket) => {
                        let token = Token {
                            binding: self.binding,
                            kind: TokenKind::Streamed { stream, ticket },
                        };
                        streamed.outgoing[i].push(Outgoing {
                            token,
                            scope,
                            deadline,
                            auto_retire,
                            confirmed: false,
                        });
                        streamed.next[i] = next;
                        Ok(Some(token))
                    }
                    Err(messages::Error::Backpressure) => Ok(None),
                    Err(error) => Err(protocol(error)),
                }
            }
        }
    }

    pub(crate) fn confirmed(&mut self, token: Token, now: Duration) -> io::Result<bool> {
        self.check_token(token)?;
        self.observe(now)?;
        match (&mut self.backend, token.kind) {
            (Backend::Legacy(legacy), TokenKind::Legacy(source)) => legacy
                .service
                .source_confirmed(source, now)
                .map_err(protocol),
            (Backend::Streamed(streamed), TokenKind::Streamed { stream, ticket }) => streamed
                .owners[index(stream)]
            .confirmed(ticket, now)
            .map_err(protocol),
            _ => Err(invalid("control token belongs to another backend")),
        }
    }

    pub(crate) fn retire(&mut self, token: Token, now: Duration) -> io::Result<()> {
        self.check_token(token)?;
        self.observe(now)?;
        match (&mut self.backend, token.kind) {
            (Backend::Legacy(_), TokenKind::Legacy(_)) => Ok(()),
            (Backend::Streamed(streamed), TokenKind::Streamed { stream, ticket }) => {
                let streamed = &mut **streamed;
                let i = index(stream);
                streamed.owners[i].retire(ticket, now).map_err(protocol)?;
                streamed.outgoing[i].retain(|entry| entry.token != token);
                Ok(())
            }
            _ => Err(invalid("control token belongs to another backend")),
        }
    }

    pub(crate) fn receive(
        &mut self,
        verified: mg::Ingress,
        bytes: &[u8],
        now: Duration,
    ) -> io::Result<()> {
        verify(self.binding, verified)?;
        self.observe(now)?;
        match &mut self.backend {
            Backend::Legacy(legacy) => legacy
                .service
                .receive(verified, bytes, now)
                .map_err(protocol),
            Backend::Streamed(streamed) => {
                let frame = streams::Frame::decode(
                    bytes,
                    streams::Limits {
                        max_packet_bytes: self.max_packet - streams::HEADER_BYTES,
                    },
                )
                .map_err(protocol)?;
                streamed.owners[index(frame.stream)]
                    .receive(verified, frame.packet, now)
                    .map_err(protocol)
            }
        }
    }

    /// Copy and present a held envelope once; semantic dispatch remains external.
    #[cfg(test)]
    pub(crate) fn next(
        &mut self,
        now: Duration,
        output: &mut [u8],
    ) -> io::Result<Option<Incoming>> {
        self.next_with_deferred_scope(now, output, None)
    }

    /// Retain a pending command for the actual staged target until its reader
    /// activates. Deferral grants no scope authority and does not block Liveness.
    pub(crate) fn next_with_deferred_scope(
        &mut self,
        now: Duration,
        output: &mut [u8],
        deferred: Option<sc::Scope>,
    ) -> io::Result<Option<Incoming>> {
        self.observe(now)?;
        match &mut self.backend {
            Backend::Legacy(legacy) => Ok(legacy
                .service
                .deliver(output, now)
                .map_err(protocol)?
                .map(|(source, bytes)| Incoming {
                    token: Token {
                        binding: self.binding,
                        kind: TokenKind::Legacy(source),
                    },
                    bytes,
                    stream: None,
                })),
            Backend::Streamed(streamed) => {
                for offset in 0..3 {
                    let i = (streamed.receive_cursor + offset) % 3;
                    if streamed.held[i].is_some() {
                        continue;
                    }
                    let Some(delivery) = streamed.owners[i].pending() else {
                        continue;
                    };
                    let stream = streams::Stream::ALL[i];
                    let envelope = sc::Envelope::decode(
                        delivery.bytes(),
                        envelope_limits(streamed.settings.streams[i].max_message_bytes)?,
                    )
                    .map_err(protocol)?;
                    if leased::incoming_stream(envelope.body, streamed.leased)? != stream {
                        return Err(protocol("control body was substituted across streams"));
                    }
                    if streamed.leased && stream == streams::Stream::Transaction {
                        continue;
                    }
                    let scope = envelope.binding.scope;
                    if stream == streams::Stream::Transaction && deferred == Some(scope) {
                        continue;
                    }
                    let bytes = delivery.bytes().len();
                    let ticket = delivery.ticket();
                    let deadline = delivery.deadline();
                    let target = output
                        .get_mut(..bytes)
                        .ok_or_else(|| invalid("control completion output is too small"))?;
                    target.copy_from_slice(delivery.bytes());
                    streamed
                        .gate
                        .admit(
                            mg::Ingress::AuthenticatedManagement {
                                session: self.binding.session,
                                lane: self.binding.lane,
                                sender: opposite(self.binding.local_role),
                            },
                            stream,
                            target,
                        )
                        .map_err(protocol)?;
                    let incoming = Incoming {
                        token: Token {
                            binding: self.binding,
                            kind: TokenKind::Streamed { stream, ticket },
                        },
                        bytes,
                        stream: Some(stream),
                    };
                    streamed.held[i] = Some(Held {
                        incoming,
                        scope,
                        deadline,
                        dispatched: false,
                        leased: false,
                    });
                    streamed.receive_cursor = (i + 1) % 3;
                    return Ok(Some(incoming));
                }
                Ok(None)
            }
        }
    }

    /// Observe complete unpresented messages without advancing work or the gate.
    /// A staged-origin command remains ineligible; this is a scheduling hint,
    /// never authentication, semantic acceptance or a reason to extend expiry.
    pub(crate) fn ready_for_dispatch(&self, deferred: Option<sc::Scope>) -> io::Result<bool> {
        let Backend::Streamed(streamed) = &self.backend else {
            return Ok(false);
        };
        for (i, stream) in streams::Stream::ALL.into_iter().enumerate() {
            if streamed.held[i].is_some() {
                continue;
            }
            let Some(delivery) = streamed.owners[i].pending() else {
                continue;
            };
            let envelope = sc::Envelope::decode(
                delivery.bytes(),
                envelope_limits(streamed.settings.streams[i].max_message_bytes)?,
            )
            .map_err(protocol)?;
            if leased::incoming_stream(envelope.body, streamed.leased)? != stream {
                return Err(protocol("control body was substituted across streams"));
            }
            if stream != streams::Stream::Transaction || deferred != Some(envelope.binding.scope) {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Observe only work serviced by the nontransaction dispatcher. Transaction
    /// bytes remain exclusively with the leased State, including blocked or
    /// malformed candidates. This hint changes no gate, cursor, time or custody.
    pub(crate) fn ready_nontransaction(&self) -> io::Result<bool> {
        let Backend::Streamed(streamed) = &self.backend else {
            return Ok(false);
        };
        for stream in [streams::Stream::Liveness, streams::Stream::DataFeedback] {
            let i = index(stream);
            if streamed.held[i].is_some() {
                continue;
            }
            let Some(delivery) = streamed.owners[i].pending() else {
                continue;
            };
            let envelope = sc::Envelope::decode(
                delivery.bytes(),
                envelope_limits(streamed.settings.streams[i].max_message_bytes)?,
            )
            .map_err(protocol)?;
            if leased::incoming_stream(envelope.body, streamed.leased)? != stream {
                return Err(protocol("control body was substituted across streams"));
            }
            return Ok(true);
        }
        Ok(false)
    }

    /// Mark successful semantic dispatch and retain receipt admission across pressure.
    pub(crate) fn accepted(&mut self, incoming: Incoming, now: Duration) -> io::Result<()> {
        self.check_token(incoming.token)?;
        self.observe(now)?;
        match (&mut self.backend, incoming.token.kind) {
            (Backend::Legacy(_), TokenKind::Legacy(_)) => Ok(()),
            (Backend::Streamed(streamed), TokenKind::Streamed { stream, ticket }) => {
                let streamed = &mut **streamed;
                let i = index(stream);
                let held = streamed.held[i]
                    .as_mut()
                    .filter(|held| held.incoming == incoming)
                    .ok_or_else(|| invalid("unknown presented control message"))?;
                if held.leased {
                    return Err(invalid(
                        "leased custody requires a borrowed acceptance callback",
                    ));
                }
                held.dispatched = true;
                match streamed.owners[i].accept(ticket, now) {
                    Ok(()) => {
                        streamed.held[i] = None;
                        Ok(())
                    }
                    Err(messages::Error::Backpressure) => Ok(()),
                    Err(error) => Err(protocol(error)),
                }
            }
            _ => Err(invalid("control token belongs to another backend")),
        }
    }

    /// Emit one attempt inside the original shared control interval and wire allowance.
    pub(crate) fn poll(
        &mut self,
        now: Duration,
        allowance: usize,
        output: &mut [u8],
    ) -> io::Result<Option<delivery::Emission>> {
        self.observe(now)?;
        if output.len() < self.max_packet {
            return Err(invalid("control packet output is too small"));
        }
        match &mut self.backend {
            Backend::Legacy(legacy) => legacy
                .service
                .poll(now, allowance, output)
                .map_err(protocol),
            Backend::Streamed(streamed) => {
                let streamed = &mut **streamed;
                if now >= streamed.refill {
                    streamed.refill = now
                        .checked_add(streamed.quota.interval)
                        .ok_or_else(exhausted)?
                        .min(self.expires);
                    streamed.packets_left = streamed.quota.packets_per_interval;
                    streamed.bytes_left = streamed.quota.bytes_per_interval;
                }
                let available = allowance.min(streamed.bytes_left);
                if streamed.packets_left == 0 {
                    return Ok(None);
                }
                for offset in 0..3 {
                    let i = (streamed.poll_cursor + offset) % 3;
                    if let Some(emission) = streamed.owners[i]
                        .poll(now, available, &mut streamed.raw)
                        .map_err(protocol)?
                    {
                        let stream = streams::Stream::ALL[i];
                        let bytes = streams::Frame {
                            stream,
                            packet: &streamed.raw[..emission.bytes],
                        }
                        .encode(
                            output,
                            streams::Limits {
                                max_packet_bytes: streamed.raw.len(),
                            },
                        )
                        .map_err(protocol)?;
                        streamed.packets_left -= 1;
                        streamed.bytes_left -= emission.wire_bytes;
                        streamed.poll_cursor = (i + 1) % 3;
                        return Ok(Some(delivery::Emission {
                            bytes,
                            wire_bytes: emission.wire_bytes,
                        }));
                    }
                }
                Ok(None)
            }
        }
    }

    pub(crate) fn deadline(&self) -> Duration {
        match &self.backend {
            Backend::Legacy(legacy) => legacy.service.deadline(),
            Backend::Streamed(streamed) => {
                let absolute = streamed
                    .owners
                    .iter()
                    .map(messages::Owner::expiry)
                    .chain(
                        streamed
                            .reservation
                            .as_ref()
                            .map(leased::Reservation::deadline),
                    )
                    .min()
                    .unwrap_or(self.expires);
                if streamed.packets_left == 0 {
                    let due = streamed
                        .owners
                        .iter()
                        .map(messages::Owner::deadline)
                        .min()
                        .unwrap_or(self.expires);
                    return absolute.min(due.max(streamed.refill));
                }
                // A small ACK may fit even when the maximum source reservation
                // does not. Filter each owner's actual reservation separately;
                // increasing this outer allowance remains a separate trigger.
                let due = streamed
                    .owners
                    .iter()
                    .map(|owner| owner.deadline_with_allowance(streamed.bytes_left))
                    .min()
                    .unwrap_or(self.expires);
                let refill = if streamed.bytes_left < streamed.quota.bytes_per_interval {
                    streamed.refill
                } else {
                    self.expires
                };
                absolute.min(due).min(refill)
            }
        }
    }

    /// Earliest immutable session/message/assembly expiry, independent of any
    /// emission eligibility or outer allowance refill.
    pub(crate) fn expiry(&self) -> Duration {
        match &self.backend {
            Backend::Legacy(_) => self.expires,
            Backend::Streamed(streamed) => streamed
                .owners
                .iter()
                .map(messages::Owner::expiry)
                .chain(
                    streamed
                        .reservation
                        .as_ref()
                        .map(leased::Reservation::deadline),
                )
                .chain([self.expires])
                .min()
                .unwrap_or(self.expires),
        }
    }

    pub(crate) fn retained(&self) -> recovery::Retained {
        match &self.backend {
            Backend::Legacy(legacy) => legacy.service.retained(),
            Backend::Streamed(streamed) => {
                streamed
                    .owners
                    .iter()
                    .fold(recovery::Retained::default(), |mut sum, owner| {
                        let retained = owner.retained().recovery;
                        sum.send_records = sum.send_records.saturating_add(retained.send_records);
                        sum.send_bytes = sum.send_bytes.saturating_add(retained.send_bytes);
                        sum.receive_records =
                            sum.receive_records.saturating_add(retained.receive_records);
                        sum.receive_bytes =
                            sum.receive_bytes.saturating_add(retained.receive_bytes);
                        sum
                    })
            }
        }
    }

    #[cfg(test)]
    pub(crate) fn drained(&self) -> bool {
        match &self.backend {
            Backend::Legacy(legacy) => legacy.service.drained(),
            Backend::Streamed(streamed) => {
                streamed.held.iter().all(Option::is_none)
                    && streamed.owners.iter().all(|owner| {
                        let retained = owner.retained();
                        retained.outbound_messages == 0
                            && retained.held_bytes == 0
                            && retained.incomplete_messages == 0
                            && retained.recovery == recovery::Retained::default()
                    })
            }
        }
    }

    /// Transaction presentation/receipt custody only; unrelated liveness is separate.
    pub(crate) fn has_dispatched(&self) -> bool {
        match &self.backend {
            Backend::Legacy(_) => false,
            Backend::Streamed(streamed) => {
                streamed.held[index(streams::Stream::Transaction)].is_some()
            }
        }
    }

    pub(crate) fn pending_deadline(&self) -> Option<Duration> {
        match &self.backend {
            Backend::Legacy(_) => None,
            Backend::Streamed(streamed) => {
                let i = index(streams::Stream::Transaction);
                streamed.outgoing[i]
                    .iter()
                    .filter(|entry| !streamed.leased || !entry.confirmed)
                    .map(|entry| entry.deadline)
                    .chain(streamed.held[i].map(|held| held.deadline))
                    .chain(
                        streamed
                            .reservation
                            .as_ref()
                            .map(leased::Reservation::deadline),
                    )
                    .min()
            }
        }
    }

    pub(crate) fn advance_scope(&mut self, scope: sc::Scope) -> io::Result<()> {
        if let Backend::Streamed(streamed) = &mut self.backend {
            let streamed = &mut **streamed;
            if scope == streamed.active {
                return Ok(());
            }
            streamed
                .gate
                .advance_scope(policy(scope))
                .map_err(protocol)?;
            streamed.draining = Some(streamed.active);
            streamed.active = scope;
        }
        Ok(())
    }

    pub(crate) fn retire_draining(&mut self, scope: sc::Scope) -> io::Result<()> {
        if let Backend::Streamed(streamed) = &mut self.backend {
            let streamed = &mut **streamed;
            let i = index(streams::Stream::Transaction);
            let pending_old = if let Some(delivery) = streamed.owners[i].pending() {
                sc::Envelope::decode(
                    delivery.bytes(),
                    envelope_limits(streamed.settings.streams[i].max_message_bytes)?,
                )
                .map_err(protocol)?
                .binding
                .scope
                    == scope
            } else {
                false
            };
            if streamed.outgoing[i]
                .iter()
                .any(|entry| entry.scope == scope)
                || streamed.held[i].is_some_and(|held| held.scope == scope)
                || pending_old
            {
                return Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "old control scope still owns custody",
                ));
            }
            streamed.gate.retire_draining(scope).map_err(protocol)?;
            streamed.draining = None;
        }
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn legacy_next_sequence(&self) -> Option<u64> {
        match &self.backend {
            Backend::Legacy(legacy) => Some(legacy.next),
            Backend::Streamed(_) => None,
        }
    }

    #[cfg(test)]
    pub(crate) fn legacy_mut(&mut self) -> Option<&mut delivery::Service> {
        match &mut self.backend {
            Backend::Legacy(legacy) => Some(&mut legacy.service),
            Backend::Streamed(_) => None,
        }
    }

    fn check_token(&self, token: Token) -> io::Result<()> {
        if token.binding != self.binding {
            return Err(invalid("control token belongs to another session"));
        }
        Ok(())
    }

    fn observe(&mut self, now: Duration) -> io::Result<()> {
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
        if let Backend::Streamed(streamed) = &mut self.backend {
            let streamed = &mut **streamed;
            if streamed
                .reservation
                .as_ref()
                .is_some_and(|reservation| now >= reservation.deadline())
            {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "original frozen control message deadline",
                ));
            }
            for i in 0..3 {
                streamed.owners[i].tick(now).map_err(protocol)?;
                if let Some(held) = streamed.held[i].filter(|held| held.dispatched && !held.leased)
                    && let TokenKind::Streamed { ticket, .. } = held.incoming.token.kind
                {
                    match streamed.owners[i].accept(ticket, now) {
                        Ok(()) => streamed.held[i] = None,
                        Err(messages::Error::Backpressure) => {}
                        Err(error) => return Err(protocol(error)),
                    }
                }
            }
            // Only Liveness permits automatic retirement. Inspect one rotating
            // entry, so confirmed() cannot multiply work_per_call by the entire
            // bounded retry ledger. Manual entries do not starve later entries.
            let i = index(streams::Stream::Liveness);
            if !streamed.outgoing[i].is_empty() {
                let position = streamed.auto_cursor % streamed.outgoing[i].len();
                let entry = &streamed.outgoing[i][position];
                let TokenKind::Streamed { ticket, .. } = entry.token.kind else {
                    return Err(protocol("streamed custody contains a legacy token"));
                };
                if entry.auto_retire
                    && streamed.owners[i]
                        .confirmed(ticket, now)
                        .map_err(protocol)?
                {
                    streamed.owners[i].retire(ticket, now).map_err(protocol)?;
                    streamed.outgoing[i].remove(position);
                    streamed.auto_cursor = position;
                } else {
                    streamed.auto_cursor = position + 1;
                }
            }
        }
        self.now = now;
        Ok(())
    }
}

fn policy(scope: sc::Scope) -> streams::gate::DataPolicy {
    streams::gate::DataPolicy {
        scope,
        recovery: None,
        receipts: sc::ReceiptPolicy::Cumulative,
    }
}
fn index(stream: streams::Stream) -> usize {
    stream as usize - 1
}
fn opposite(role: mg::Role) -> mg::Role {
    match role {
        mg::Role::Client => mg::Role::Server,
        mg::Role::Server => mg::Role::Client,
    }
}
fn outgoing_stream(body: sc::Body<'_>) -> io::Result<streams::Stream> {
    match body {
        sc::Body::Ping { .. } | sc::Body::Pong { .. } => Ok(streams::Stream::Liveness),
        sc::Body::ProfileControl {
            tag: sc::ProfileTag::SwiftPolicyV1,
            ..
        } => Ok(streams::Stream::Transaction),
        _ => Err(protocol(
            "selected Swift control backend does not dispatch this body",
        )),
    }
}
fn envelope_binding(binding: delivery::Binding, packet: u64, scope: sc::Scope) -> sc::Binding {
    sc::Binding {
        session: binding.session,
        lane: binding.lane,
        sender: binding.local_role,
        packet: mg::PacketNumber(packet),
        scope,
    }
}
fn envelope_limits(maximum: usize) -> io::Result<sc::Limits> {
    let limits = sc::Limits {
        max_frame_bytes: maximum,
        max_management_bytes: maximum
            .checked_sub(sc::HEADER_BYTES)
            .ok_or_else(|| invalid("control envelope ceiling"))?,
        max_feedback_bytes: 1,
    };
    limits.validate().map_err(invalid)?;
    Ok(limits)
}
fn verify(binding: delivery::Binding, verified: mg::Ingress) -> io::Result<()> {
    match verified {
        mg::Ingress::AuthenticatedManagement {
            session,
            lane,
            sender,
        } if session == binding.session
            && lane == binding.lane
            && sender == opposite(binding.local_role) =>
        {
            Ok(())
        }
        _ => Err(protocol("control ingress lacks full authenticated binding")),
    }
}
fn invalid(error: impl std::fmt::Display) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, error.to_string())
}
fn protocol(error: impl std::fmt::Display) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error.to_string())
}
fn exhausted() -> io::Error {
    invalid("control sequence or time arithmetic exhausted")
}

#[cfg(test)]
#[path = "control_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "control_leased_tests.rs"]
mod leased_tests;

#[cfg(test)]
#[path = "control_storage_tests.rs"]
mod storage_tests;
