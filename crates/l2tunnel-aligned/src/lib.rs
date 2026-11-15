//! Bounded aligned Python symbols composed with the existing reliable FEC engine.
//!
//! All ingress recovery packets require prior carrier integrity/replay validation.
//! Enqueue accepts only frames already admitted by the common MUX/QoS policy.
//! This crate opens no device/socket and supplies no authentication or congestion
//! controller. Explicit unpacked independent-short delivery observes retained
//! sources while preserving the original ordered recovery and native gap state.

use l2tunnel_codec::{
    aligned_envelope as envelope, aligned_receiver as receiver, aligned_sender as sender,
};
use l2tunnel_core::{ConfigDigest, Epoch};
use l2tunnel_recovery::{BufferSide, EndpointRole, RecoveryContext, RecoveryError};
use l2tunnel_reliable::{OutboundBudget, Reliable, ReliableConfig};
use std::{fmt, time::Duration};

/// Explicit timed packed-source composition over the same reliable owner.
pub mod packed;
/// Complete fallible backing for actual directional codec/recovery owners.
pub mod storage;

pub use l2tunnel_codec::aligned_receiver::{
    ChannelId, Delivery, Prepared, RecordIdentity, UnitWitness,
};

/// Explicit authenticated native interpretation; never inferred from packet bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativePolicy {
    /// Ethernet eligibility checks select header compression or exact raw fallback.
    EthernetHeaders,
    /// Native IP is always an exact kind-2 raw body, including fragmented packets.
    RawIp,
}

/// Complete immutable policy, including exact external wire charges.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Config {
    /// Authenticated native-layer/body-selection policy.
    pub native_policy: NativePolicy,
    /// Body, ordering, replay, storage and native-delivery limits.
    pub receiver: receiver::Limits,
    /// Existing Cauchy/ARQ engine, without an alternate implementation here.
    pub recovery: ReliableConfig,
    /// Maximum complete recovery packet before carrier protection/underlay overhead.
    pub max_recovery_packet_bytes: usize,
}
impl Config {
    /// Validate all cross-module geometry, storage and configured lifetime bounds.
    pub fn validate(self) -> Result<(), Error> {
        let held = self
            .recovery
            .arq
            .receive_records
            .checked_add(self.recovery.max_restored_packets)
            .ok_or(Error::Configuration)?;
        self.validate_geometry(
            envelope::HEADER_BYTES + self.receiver.body.symbol_bytes,
            held,
        )
    }
    fn validate_geometry(self, original: usize, minimum_source_window: usize) -> Result<(), Error> {
        self.receiver
            .memory_bound_bytes()
            .map_err(Error::Receiver)?;
        sender_config(self)
            .memory_bound_bytes()
            .map_err(Error::Sender)?;
        if self.native_policy == NativePolicy::RawIp
            && (self.receiver.body.elide_payload_length
                || self.receiver.body.predictive
                || self.receiver.body.timestamp_pair_dictionary)
        {
            return Err(Error::Configuration);
        }
        let largest_body = (self.receiver.body.max_frame_bytes + 29).clamp(69, 65535);
        let fragments = largest_body.div_ceil(self.receiver.body.symbol_bytes - 8);
        if self.receiver.first_source.0 != 0
            || self.receiver.source_window < minimum_source_window
            || self.receiver.max_fragments_per_record < fragments
            || self.recovery.arq.max_source_bytes != original
            || self.recovery.arq.max_retries > 256
            || self.max_recovery_packet_bytes > 65_507
            || Duration::from_millis(self.receiver.lifetime_ticks) <= self.recovery_horizon()?
        {
            return Err(Error::Configuration);
        }
        let maximum = self
            .recovery
            .maximum_packet_bytes()
            .map_err(Error::Recovery)?;
        if maximum > self.max_recovery_packet_bytes {
            return Err(Error::Configuration);
        }
        Ok(())
    }
    /// Maximum configured retry timer sum plus partial-block flush duration.
    /// External send/device backpressure has no bounded delivery guarantee.
    pub fn recovery_horizon(self) -> Result<Duration, Error> {
        if self.recovery.arq.max_retries > 256 {
            return Err(Error::Configuration);
        }
        let mut sum = self.recovery.flush_after;
        let mut rto = self.recovery.arq.initial_rto;
        for _ in 0..=self.recovery.arq.max_retries {
            sum = sum.checked_add(rto).ok_or(Error::Configuration)?;
            rto = rto
                .checked_mul(2)
                .unwrap_or(Duration::MAX)
                .min(self.recovery.arq.maximum_rto);
        }
        Ok(sum)
    }
    /// Canonical version/domain-separated SHA-256 of every policy/bound field.
    /// This digest must be authenticated by the embedding session negotiation.
    pub fn digest(self) -> Result<ConfigDigest, Error> {
        self.validate()?;
        let mut bytes = Vec::with_capacity(640);
        bytes.extend_from_slice(b"l2tunnel/aligned-envelope-v1/reliable-v1/config-v1\0");
        self.append_fields(&mut bytes);
        Ok(config_hash(&bytes))
    }
    fn append_fields(self, bytes: &mut Vec<u8>) {
        bytes.push(match self.native_policy {
            NativePolicy::EthernetHeaders => 1,
            NativePolicy::RawIp => 2,
        });
        let limits = self.receiver;
        let body = limits.body;
        for value in [
            body.max_frame_bytes,
            body.symbol_bytes,
            body.independent_short_frame_bytes,
        ] {
            number(bytes, value as u64);
        }
        bytes.extend_from_slice(&[
            u8::from(body.elide_payload_length),
            u8::from(body.predictive),
            u8::from(body.timestamp_pair_dictionary),
        ]);
        for value in [
            u64::from(limits.channels),
            limits.first_record.0,
            limits.first_source.0,
            u64::from(limits.record_window),
            limits.source_window as u64,
            limits.lookahead_records as u64,
            limits.lookahead_bytes as u64,
            limits.lookahead_fragments as u64,
            limits.max_fragments_per_record as u64,
            limits.lifetime_ticks,
        ] {
            number(bytes, value);
        }
        let recovery = self.recovery;
        let arq = recovery.arq;
        for value in [
            arq.max_source_bytes,
            arq.send_bytes,
            arq.receive_bytes,
            arq.send_records,
            arq.receive_records,
        ] {
            number(bytes, value as u64);
        }
        for value in [arq.initial_rto, arq.maximum_rto, arq.ack_delay] {
            duration(bytes, value);
        }
        number(bytes, u64::from(arq.max_retries));
        let fec = recovery.fec;
        for value in [
            fec.block.max_sources as u64,
            fec.block.max_source_bytes as u64,
            fec.block.max_packet_bytes as u64,
            fec.block.max_work_per_symbol,
            fec.max_generations as u64,
            fec.max_symbols_per_generation as u64,
            fec.max_reserved_bytes as u64,
            fec.max_lifetime_ticks,
            fec.generation_window,
            recovery.repair_symbols as u64,
        ] {
            number(bytes, value);
        }
        duration(bytes, recovery.flush_after);
        for value in [
            recovery.max_restored_packets,
            recovery.max_restored_bytes,
            recovery.outer_overhead_bytes,
            self.max_recovery_packet_bytes,
        ] {
            number(bytes, value as u64);
        }
    }
    /// Configured full application emission ceiling including external overhead.
    pub fn maximum_charged_bytes(self) -> Result<usize, Error> {
        self.validate()?;
        self.max_recovery_packet_bytes
            .checked_add(self.recovery.outer_overhead_bytes)
            .ok_or(Error::Configuration)
    }
}

/// Explicit ownership, configuration and terminal protocol failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// Contradictory or excessive local limits.
    Configuration,
    /// The single frame stage is occupied; no new frame was admitted.
    Busy,
    /// Time moved backwards or exceeds the injected millisecond domain.
    Time,
    /// An immutable receiver handoff expired under backpressure.
    Expired,
    /// Recovered/source allocator identity disagrees with its envelope.
    Identity,
    /// Received body violates the authenticated raw-IP versus header policy.
    Policy,
    /// Sender body/fragment staging failure.
    Sender(sender::Error),
    /// Timed packed sender ownership or first-unit clock failure.
    PackedSender(l2tunnel_codec::packed_sender::Error),
    /// Invalid enclosing identity encoding.
    Envelope(envelope::Error),
    /// Packed container scope, unit/record identity or canonical format failure.
    PackedEnvelope(l2tunnel_codec::packed_envelope::Error),
    /// Receiver admission/native ownership failure.
    Receiver(receiver::Error),
    /// Authoritative recovery failure or retryable resource pressure.
    Recovery(l2tunnel_reliable::Error),
}
impl Error {
    /// Whether the caller may retain the exact input and retry after draining.
    pub fn is_backpressure(self) -> bool {
        matches!(
            self,
            Self::Busy
                | Self::Recovery(
                    l2tunnel_reliable::Error::RestoredCapacity
                        | l2tunnel_reliable::Error::Arq(RecoveryError::Capacity(_))
                )
        )
    }
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "aligned endpoint: {self:?}")
    }
}
impl std::error::Error for Error {}

/// Bounded pipeline ownership snapshot, not peer native-delivery acknowledgement.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Status {
    /// A local admitted frame still has symbols not copied into recovery.
    pub staged_frame: bool,
    /// Present only for the explicit packed profile, with distinct unit ownership.
    pub packing: Option<l2tunnel_codec::packed_sender::Status>,
    /// Ordered recovered source waiting for receiver storage.
    pub retained_handoff: bool,
    /// Receiver record/native ownership counters.
    pub receiver: receiver::Status,
    /// Existing reliable engine retention counters.
    pub recovery: l2tunnel_reliable::Storage,
    /// Sticky terminal failure, if any.
    pub failure: Option<Error>,
}

/// Pure exclusive owner of codec/recovery/native handoffs for both directions.
pub struct Endpoint {
    config: Config,
    receive_config: Config,
    receive_scope: receiver::Scope,
    send_scope: receiver::Scope,
    sender: packed::SenderOwner,
    packing: Option<packed::Options>,
    receive_packing: Option<packed::Options>,
    // Ordered packed-source framing is independent of out-of-order short-unit
    // proofs. Only actual ordered recovery handoff advances this cursor.
    receive_unit: Option<receiver::SourceId>,
    packed_symbols: Vec<u8>,
    recovery: Reliable,
    receiver: receiver::Receiver,
    send_buffer: Vec<u8>,
    receive_buffer: Vec<u8>,
    handoff: Option<(u64, usize, Duration)>,
    now: Duration,
    failure: Option<Error>,
    usage: Option<storage::Usage>,
}
impl Endpoint {
    /// Reserve complete actual same-policy duplex backing without fallback.
    pub fn new_reserved(
        config: Config,
        context: RecoveryContext,
        limits: storage::Limits,
    ) -> Result<Self, storage::Error> {
        Self::new_duplex_reserved(config, config, context, limits)
    }
    /// Reserve all actual independently configured direction owners and workspaces.
    pub fn new_duplex_reserved(
        send: Config,
        receive: Config,
        context: RecoveryContext,
        limits: storage::Limits,
    ) -> Result<Self, storage::Error> {
        let plan = storage::Plan::for_duplex(send, receive)?;
        Self::new_reserved_profile(plan, context, limits)
    }
    /// Actual complete retained heap; an allocating endpoint returns None.
    pub fn storage_usage(&self) -> Option<storage::Usage> {
        self.usage
    }
    fn new_reserved_profile(
        plan: storage::Plan,
        context: RecoveryContext,
        limits: storage::Limits,
    ) -> Result<Self, storage::Error> {
        if context.session == 0 {
            return Err(storage::Error::Endpoint(Error::Configuration));
        }
        let mut allocation = storage::Allocation::new(&plan, limits)?;
        Self::assemble_reserved(plan, context, limits, &mut allocation)
    }
    fn assemble_reserved(
        plan: storage::Plan,
        context: RecoveryContext,
        limits: storage::Limits,
        allocation: &mut storage::Allocation,
    ) -> Result<Self, storage::Error> {
        use l2tunnel_codec::aligned_storage as codec;
        let config = plan.send_config();
        let receive_config = plan.receive_config();
        let send_direction = match context.role {
            EndpointRole::Initiator => receiver::Direction::InitiatorToResponder,
            EndpointRole::Responder => receiver::Direction::ResponderToInitiator,
        };
        let receive_direction = match context.role {
            EndpointRole::Initiator => receiver::Direction::ResponderToInitiator,
            EndpointRole::Responder => receiver::Direction::InitiatorToResponder,
        };
        let send_scope = receiver::Scope {
            session: context.session.to_be_bytes(),
            epoch: Epoch(context.epoch),
            direction: send_direction,
        };
        let receive_scope = receiver::Scope {
            direction: receive_direction,
            ..send_scope
        };
        let mut construction = storage::Construction::default();
        #[cfg(test)]
        {
            construction.trace = allocation.trace.clone();
        }
        let (sender, sender_usage) = if let Some(packed) = plan.send_packed() {
            let mut cell = allocation.vec(1)?;
            let sender = l2tunnel_codec::packed_sender::Sender::new_reserved(
                send_scope,
                packed.sender(),
                codec::Limits {
                    capacity_bytes: plan.sender,
                },
            )
            .map_err(storage::Error::Codec)?;
            let usage = sender.storage_usage().ok_or(storage::Error::Invariant)?;
            cell.push(sender);
            (packed::SenderOwner::Packed(cell), usage)
        } else {
            let mut cell = allocation.vec(1)?;
            let sender = sender::Sender::new_reserved(
                send_scope,
                sender_config(config),
                codec::Limits {
                    capacity_bytes: plan.sender,
                },
            )
            .map_err(storage::Error::Codec)?;
            let usage = sender.storage_usage().ok_or(storage::Error::Invariant)?;
            cell.push(sender);
            (packed::SenderOwner::Aligned(cell), usage)
        };
        construction.sender = Some(sender);
        let packing = plan.send_packed().map(|p| p.options());
        let receive_packing = plan.receive_packed().map(|p| p.options());
        let symbols = receive_packing.map_or(0, |p| {
            usize::from(p.max_units) * receive_config.receiver.body.symbol_bytes
        });
        construction.packed_symbols = allocation.bytes(symbols)?;
        construction.recovery = Some(
            Reliable::new_duplex_reserved(
                config.recovery,
                receive_config.recovery,
                context,
                l2tunnel_reliable::storage::Limits {
                    capacity_bytes: plan.reliable_plan().capacity_bytes(),
                },
            )
            .map_err(storage::Error::Reliable)?,
        );
        construction.receiver = Some(
            receiver::Receiver::new_reserved(
                receive_scope,
                receive_config.receiver,
                codec::Limits {
                    capacity_bytes: plan.receiver.capacity_bytes(),
                },
            )
            .map_err(storage::Error::Codec)?,
        );
        construction.send_buffer = allocation.bytes(config.recovery.arq.max_source_bytes)?;
        construction.receive_buffer =
            allocation.bytes(receive_config.recovery.arq.max_source_bytes)?;
        let recovery_usage = construction
            .recovery
            .as_ref()
            .and_then(Reliable::storage_usage)
            .ok_or(storage::Error::Invariant)?;
        let receiver_usage = construction
            .receiver
            .as_ref()
            .and_then(receiver::Receiver::storage_usage)
            .ok_or(storage::Error::Invariant)?;
        let (wrapper, wrapper_allocations) = allocation.actual();
        let capacity_bytes = storage::sum(&[
            wrapper,
            sender_usage.capacity_bytes,
            recovery_usage.capacity_bytes,
            receiver_usage.capacity_bytes,
        ])?;
        let allocations = storage::sum(&[
            wrapper_allocations,
            sender_usage.allocations,
            recovery_usage.allocations,
            receiver_usage.allocations,
        ])?;
        if wrapper != plan.wrapper || capacity_bytes != plan.capacity_bytes() {
            return Err(storage::Error::Invariant);
        }
        let sender = construction
            .sender
            .take()
            .ok_or(storage::Error::Invariant)?;
        let recovery = construction
            .recovery
            .take()
            .ok_or(storage::Error::Invariant)?;
        let receiver = construction
            .receiver
            .take()
            .ok_or(storage::Error::Invariant)?;
        let packed_symbols = std::mem::take(&mut construction.packed_symbols);
        let send_buffer = std::mem::take(&mut construction.send_buffer);
        let receive_buffer = std::mem::take(&mut construction.receive_buffer);
        construction.transferred(capacity_bytes);
        Ok(Self {
            config,
            receive_config,
            receive_scope,
            send_scope,
            sender,
            packing,
            receive_packing,
            receive_unit: Some(receive_config.receiver.first_source),
            packed_symbols,
            recovery,
            receiver,
            send_buffer,
            receive_buffer,
            handoff: None,
            now: Duration::ZERO,
            failure: None,
            usage: Some(storage::Usage {
                limit_bytes: limits.capacity_bytes,
                capacity_bytes,
                allocations,
            }),
        })
    }
    /// Construct opposite direction domains from the authenticated local role.
    pub fn new(config: Config, context: RecoveryContext) -> Result<Self, Error> {
        Self::new_profile(config, context, None)
    }
    /// Construct one actual owner from complete independent data-direction policies.
    pub fn new_duplex(
        send: Config,
        receive: Config,
        context: RecoveryContext,
    ) -> Result<Self, Error> {
        Self::new_duplex_profile(send, receive, context, None, None)
    }
    fn new_profile(
        config: Config,
        context: RecoveryContext,
        packing: Option<packed::Options>,
    ) -> Result<Self, Error> {
        Self::new_duplex_profile(config, config, context, packing, packing)
    }
    fn new_duplex_profile(
        config: Config,
        receive_config: Config,
        context: RecoveryContext,
        packing: Option<packed::Options>,
        receive_packing: Option<packed::Options>,
    ) -> Result<Self, Error> {
        match packing {
            Some(p) => p.config(config).validate()?,
            None => config.validate()?,
        }
        match receive_packing {
            Some(p) => p.config(receive_config).validate()?,
            None => receive_config.validate()?,
        }
        if context.session == 0 {
            return Err(Error::Configuration);
        }
        let send_direction = match context.role {
            EndpointRole::Initiator => receiver::Direction::InitiatorToResponder,
            EndpointRole::Responder => receiver::Direction::ResponderToInitiator,
        };
        let receive_direction = match context.role {
            EndpointRole::Initiator => receiver::Direction::ResponderToInitiator,
            EndpointRole::Responder => receiver::Direction::InitiatorToResponder,
        };
        let send_scope = receiver::Scope {
            session: context.session.to_be_bytes(),
            epoch: Epoch(context.epoch),
            direction: send_direction,
        };
        let receive_scope = receiver::Scope {
            direction: receive_direction,
            ..send_scope
        };
        Ok(Self {
            config,
            receive_config,
            receive_scope,
            send_scope,
            sender: match packing {
                Some(p) => packed::SenderOwner::Packed(vec![
                    l2tunnel_codec::packed_sender::Sender::new(
                        send_scope,
                        p.config(config).sender(),
                    )
                    .map_err(Error::PackedSender)?,
                ]),
                None => packed::SenderOwner::Aligned(vec![
                    sender::Sender::new(send_scope, sender_config(config))
                        .map_err(Error::Sender)?,
                ]),
            },
            packing,
            receive_packing,
            receive_unit: Some(receive_config.receiver.first_source),
            packed_symbols: vec![
                0;
                receive_packing.map_or(0, |p| usize::from(p.max_units)
                    * receive_config.receiver.body.symbol_bytes)
            ],
            recovery: Reliable::new_duplex(config.recovery, receive_config.recovery, context)
                .map_err(Error::Recovery)?,
            receiver: receiver::Receiver::new(receive_scope, receive_config.receiver)
                .map_err(Error::Receiver)?,
            send_buffer: vec![0; config.recovery.arq.max_source_bytes],
            receive_buffer: vec![0; receive_config.recovery.arq.max_source_bytes],
            handoff: None,
            now: Duration::ZERO,
            failure: None,
            usage: None,
        })
    }
    /// Retain one already-MUX-admitted native frame; success is not peer delivery.
    /// A busy/invalid enqueue consumes neither codec context nor source identity.
    pub fn enqueue_admitted(
        &mut self,
        channel: ChannelId,
        frame: &[u8],
        now: Duration,
    ) -> Result<(), Error> {
        self.enqueue_identified(channel, frame, now).map(|_| ())
    }
    /// Return the transactional sender-owned native-body identity. It excludes
    /// any separate context record and exists before packed polling consumes units.
    pub fn enqueue_identified(
        &mut self,
        channel: ChannelId,
        frame: &[u8],
        now: Duration,
    ) -> Result<RecordIdentity, Error> {
        if let Some(options) = self.packing {
            if let Some(error) = self.failure {
                return Err(error);
            }
            packed::micros(now)?
                .checked_add(options.hold_micros)
                .ok_or(Error::PackedSender(
                    l2tunnel_codec::packed_sender::Error::Packing(
                        l2tunnel_codec::packed::Error::ClockExhausted,
                    ),
                ))?;
        }
        self.advance(now)?;
        let staged = self
            .sender
            .stage(self.config.native_policy, channel, frame, now);
        let identity = if self.sender.packing().is_some_and(|s| s.failure.is_some()) {
            self.terminal_result(staged)?
        } else {
            staged?
        };
        if self.packing.is_some() {
            self.submit_packed()?;
        } else {
            self.pump_send()?;
        }
        Ok(identity)
    }
    /// Borrow exact original record units from a locally generated source or
    /// systematic emission. Repairs contain no original unit. These are structural
    /// witnesses only: the runtime must await actual carrier send and match each
    /// identity to its own native admission before confirming every fragment.
    /// The caller reserves one slot for aligned or max_units slots for packed.
    pub fn outgoing_units(
        &mut self,
        packet: &[u8],
        output: &mut [UnitWitness],
    ) -> Result<usize, Error> {
        self.recovery
            .inspect_output(packet)
            .map_err(Error::Recovery)?;
        let role = match self.send_scope.direction {
            receiver::Direction::InitiatorToResponder => EndpointRole::Initiator,
            receiver::Direction::ResponderToInitiator => EndpointRole::Responder,
        };
        let view = l2tunnel_reliable::inspect_structural(
            packet,
            role,
            self.config.max_recovery_packet_bytes,
            self.config.recovery.arq.max_source_bytes,
            self.config.recovery.fec.block,
        )
        .map_err(Error::Recovery)?;
        let Some((source, bytes)) = view.source else {
            return Ok(0);
        };
        if let Some(options) = self.packing {
            let packed = l2tunnel_codec::packed_envelope::decode(
                options.config(self.config).envelope(),
                self.send_scope,
                bytes,
            )
            .map_err(Error::PackedEnvelope)?;
            if packed.identity().source.0 != source.0 {
                return Err(Error::Identity);
            }
            if output.len() < packed.len() {
                return Err(Error::Configuration);
            }
            for (index, unit) in packed.units().map_err(Error::PackedEnvelope)?.enumerate() {
                let symbol = &mut self.send_buffer[..self.config.receiver.body.symbol_bytes];
                symbol.fill(0);
                symbol[..unit.bytes.len()].copy_from_slice(unit.bytes);
                output[index] = receiver::unit_witness(unit.identity, symbol, self.config.receiver)
                    .map_err(Error::Receiver)?;
            }
            Ok(packed.len())
        } else {
            if output.is_empty() {
                return Err(Error::Configuration);
            }
            let aligned = envelope::decode(
                self.send_scope,
                self.config.receiver.body.symbol_bytes,
                self.config.receiver.channels,
                bytes,
            )
            .map_err(Error::Envelope)?;
            if aligned.identity.source.0 != source.0 {
                return Err(Error::Identity);
            }
            output[0] =
                receiver::unit_witness(aligned.identity, aligned.symbol, self.config.receiver)
                    .map_err(Error::Receiver)?;
            Ok(1)
        }
    }
    /// Explicit raw-IP enqueue; reject a session bound to Ethernet header policy.
    pub fn enqueue_admitted_raw(
        &mut self,
        channel: ChannelId,
        frame: &[u8],
        now: Duration,
    ) -> Result<(), Error> {
        if self.config.native_policy != NativePolicy::RawIp {
            return Err(Error::Configuration);
        }
        self.enqueue_admitted(channel, frame, now)
    }
    /// Emit at most one source/repair/retry under the caller's shared wire budget.
    /// The caller retains returned bytes until its carrier accepts them.
    pub fn poll_data(
        &mut self,
        now: Duration,
        output: &mut [u8],
        budget: &mut OutboundBudget,
    ) -> Result<Option<usize>, Error> {
        self.advance(now)?;
        self.pump_send()?;
        let result = self
            .recovery
            .poll_data(now, output, budget)
            .map_err(Error::Recovery);
        self.recovery_result(result)
    }
    /// Emit only feedback, using the same common budget as all data emissions.
    pub fn poll_feedback(
        &mut self,
        now: Duration,
        output: &mut [u8],
        budget: &mut OutboundBudget,
    ) -> Result<Option<usize>, Error> {
        self.advance(now)?;
        let result = self
            .recovery
            .poll_feedback(now, output, budget)
            .map_err(Error::Recovery);
        self.recovery_result(result)
    }
    /// Admit complete recovery bytes only after carrier integrity/replay checks.
    /// Retryable pressure leaves ownership of the exact input with the caller.
    pub fn receive_authenticated(&mut self, packet: &[u8], now: Duration) -> Result<(), Error> {
        self.advance(now)?;
        let result = self.recovery.receive(packet, now).map_err(Error::Recovery);
        self.recovery_result(result)?;
        self.pump_receive()
    }
    /// Bounded receiver work selected by the caller's common channel scheduler.
    pub fn prepare(
        &mut self,
        channel: ChannelId,
        now: Duration,
        max_records: usize,
    ) -> Result<Prepared, Error> {
        self.advance(now)?;
        self.pump_receive()?;
        let result = self
            .receiver
            .prepare(channel, ticks(now)?, max_records)
            .map_err(Error::Receiver);
        self.terminal_result(result)
    }
    /// Immutable native bytes; never hiddenly retired by polling or WouldBlock.
    pub fn pending(&self) -> Option<Delivery<'_>> {
        if self.failure.is_some() {
            None
        } else {
            self.receiver.pending()
        }
    }
    /// Original expiry of pending native custody, excluding recovery/packing work.
    pub fn pending_deadline(&self) -> Option<Duration> {
        if self.failure.is_some() {
            None
        } else {
            self.receiver
                .pending_deadline()
                .map(|tick| Duration::from_millis(tick.0))
        }
    }
    /// Commit only after complete native-device acceptance, checking expiry first.
    pub fn commit_delivery(&mut self, now: Duration) -> Result<(), Error> {
        self.advance(now)?;
        let result = self
            .receiver
            .commit_delivery(ticks(now)?)
            .map_err(Error::Receiver);
        self.terminal_result(result)?;
        self.pump_receive()
    }
    /// Service injected receiver/handoff time while idle; recovery needs polls too.
    pub fn tick(&mut self, now: Duration) -> Result<(), Error> {
        self.advance(now)?;
        if self.packing.is_some() {
            self.pump_send()?;
        }
        self.pump_receive()
    }
    /// Actual next recovery ACK deadline, excluding data and native work.
    pub fn feedback_deadline(&self) -> Option<Duration> {
        if self.failure.is_some() {
            None
        } else {
            self.recovery.feedback_deadline()
        }
    }

    /// Next recovery, receiver or retained-handoff deadline; poll it even while idle.
    pub fn deadline(&self) -> Option<Duration> {
        if self.failure.is_some() {
            return None;
        }
        self.recovery
            .deadline()
            .into_iter()
            .chain(self.handoff.map(|(_, _, deadline)| deadline))
            .chain(
                self.sender
                    .packing()
                    .and_then(|s| s.packing.deadline_micros)
                    .map(Duration::from_micros),
            )
            .chain(
                self.receiver
                    .deadline()
                    .map(|tick| Duration::from_millis(tick.0)),
            )
            .min()
    }
    /// True only after all local staging, recovery and native record ownership drains.
    pub fn drained(&self) -> bool {
        let status = self.receiver.status();
        self.failure.is_none()
            && !self.sender.is_pending()
            && self.recovery.drained()
            && self.handoff.is_none()
            && status.retained_records == 0
            && status.retained_sources == 0
            && status.pending_bytes.is_none()
    }
    /// Exact maximum complete recovery output, excluding configured carrier overhead.
    pub fn max_packet_bytes(&self) -> usize {
        self.recovery.max_packet_bytes()
    }
    /// Exact local recovery emission ceiling before external overhead.
    pub fn send_max_packet_bytes(&self) -> usize {
        self.recovery.send_max_packet_bytes()
    }
    /// Exact peer recovery packet ceiling used by authenticated ingress.
    pub fn receive_max_packet_bytes(&self) -> usize {
        self.recovery.receive_max_packet_bytes()
    }
    /// Existing engine's classification for routing data/feedback after authentication.
    pub fn inspect_peer(&self, packet: &[u8]) -> Result<l2tunnel_reliable::RecordKind, Error> {
        self.recovery.inspect_peer(packet).map_err(Error::Recovery)
    }
    /// Existing engine's classification of an emitted local record.
    pub fn inspect_output(&self, packet: &[u8]) -> Result<l2tunnel_reliable::RecordKind, Error> {
        self.recovery
            .inspect_output(packet)
            .map_err(Error::Recovery)
    }
    /// Actual reliable FEC/ARQ emission and restoration counters.
    pub fn statistics(&self) -> l2tunnel_reliable::Statistics {
        self.recovery.statistics()
    }
    /// Actual ARQ timeout and source ownership counters.
    pub fn arq_statistics(&self) -> l2tunnel_recovery::Statistics {
        self.recovery.arq_statistics()
    }
    /// Snapshot of retained local state without releasing any ownership.
    pub fn status(&self) -> Status {
        Status {
            staged_frame: self.sender.staged_frame(),
            packing: self.sender.packing(),
            retained_handoff: self.handoff.is_some(),
            receiver: self.receiver.status(),
            recovery: self.recovery.storage(),
            failure: self.failure,
        }
    }
    fn advance(&mut self, now: Duration) -> Result<(), Error> {
        if let Some(error) = self.failure {
            return Err(error);
        }
        if now < self.now {
            return Err(Error::Time);
        }
        if self.packing.is_some() && packed::micros(now).is_err() {
            return if self.drained() {
                Err(Error::Time)
            } else {
                self.fail(Error::Time)
            };
        }
        let tick = ticks(now)?;
        self.now = now;
        if self.handoff.is_some_and(|(_, _, deadline)| now >= deadline) {
            return self.fail(Error::Expired);
        }
        let result = self.receiver.tick(tick).map_err(Error::Receiver);
        self.terminal_result(result)
    }
    fn pump_send(&mut self) -> Result<(), Error> {
        if let packed::SenderOwner::Packed(sender) = &mut self.sender {
            let result = sender[0]
                .poll(packed::micros(self.now)?)
                .map_err(Error::PackedSender);
            self.terminal_result(result)?;
            return self.submit_packed();
        }
        for _ in 0..self.config.recovery.arq.send_records {
            if !self.sender.is_pending() {
                break;
            }
            let result = self.recovery.next_source_id().map_err(Error::Recovery);
            let id = self.terminal_result(result)?;
            let length = self
                .sender
                .write_pending(receiver::SourceId(id), &mut self.send_buffer)?;
            match self.recovery.submit(&self.send_buffer[..length], self.now) {
                Ok(actual) if actual == id => self.sender.commit_source()?,
                Ok(_) => return self.fail(Error::Identity),
                Err(l2tunnel_reliable::Error::Arq(
                    RecoveryError::Capacity(BufferSide::Send) | RecoveryError::SequenceWindow,
                )) => break,
                Err(error) => return self.fail(Error::Recovery(error)),
            }
        }
        Ok(())
    }
    fn submit_packed(&mut self) -> Result<(), Error> {
        if !self.sender.packing().is_some_and(|s| s.packing.sealed) {
            return Ok(());
        }
        let result = self.recovery.next_source_id().map_err(Error::Recovery);
        let id = self.terminal_result(result)?;
        let result = self
            .sender
            .write_pending(receiver::SourceId(id), &mut self.send_buffer);
        let length = self.terminal_result(result)?;
        match self.recovery.submit(&self.send_buffer[..length], self.now) {
            Ok(actual) if actual == id => {
                let result = self.sender.commit_source();
                self.terminal_result(result)
            }
            Ok(_) => self.fail(Error::Identity),
            Err(l2tunnel_reliable::Error::Arq(
                RecoveryError::Capacity(BufferSide::Send) | RecoveryError::SequenceWindow,
            )) => Ok(()),
            Err(error) => self.fail(Error::Recovery(error)),
        }
    }
    fn pump_receive(&mut self) -> Result<(), Error> {
        self.preview_receive()?;
        for _ in 0..self.receive_config.recovery.arq.receive_records {
            if self.handoff.is_none() {
                let result = self
                    .recovery
                    .poll_delivered(&mut self.receive_buffer)
                    .map_err(Error::Recovery);
                let Some((id, length)) = self.recovery_result(result)? else {
                    break;
                };
                let deadline = self
                    .now
                    .checked_add(Duration::from_millis(
                        self.receive_config.receiver.lifetime_ticks,
                    ))
                    .ok_or(Error::Time)?;
                self.handoff = Some((id, length, deadline));
            }
            let Some((id, length, _)) = self.handoff else {
                break;
            };
            if let Some(options) = self.receive_packing {
                match self.admit_packed(options, id, length) {
                    Ok(()) => {
                        self.handoff = None;
                        continue;
                    }
                    Err(Error::Receiver(
                        receiver::Error::Capacity | receiver::Error::RecordWindow,
                    )) => break,
                    Err(error) => return self.fail(error),
                }
            }
            let view = match envelope::decode(
                self.receive_scope,
                self.receive_config.receiver.body.symbol_bytes,
                self.receive_config.receiver.channels,
                &self.receive_buffer[..length],
            ) {
                Ok(view) => view,
                Err(error) => return self.fail(Error::Envelope(error)),
            };
            if view.identity.source.0 != id {
                return self.fail(Error::Identity);
            }
            if self.receive_config.native_policy == NativePolicy::RawIp {
                let symbol = view.symbol;
                let raw = symbol[3] == 2;
                let fragment = symbol[3] == 4 && (symbol[6..8] != [0, 0] || symbol[8] == 2);
                if !raw && !fragment {
                    return self.fail(Error::Policy);
                }
            }
            match self
                .receiver
                .admit_authenticated(view.identity, view.symbol, ticks(self.now)?)
            {
                Ok(receiver::Admission::Accepted) => self.handoff = None,
                Ok(receiver::Admission::Duplicate | receiver::Admission::StaleSource)
                    if self
                        .receive_config
                        .receiver
                        .body
                        .independent_short_frame_bytes
                        != 0 =>
                {
                    // The same real source may already have been observed
                    // before ordered recovery reached it. Receiver tombstones
                    // retain conflict evidence until contiguous retirement.
                    self.handoff = None;
                }
                Ok(_) => return self.fail(Error::Identity),
                Err(receiver::Error::Capacity | receiver::Error::RecordWindow) => break,
                Err(error) => return self.fail(Error::Receiver(error)),
            }
        }
        Ok(())
    }

    fn preview_receive(&mut self) -> Result<(), Error> {
        if self
            .receive_config
            .receiver
            .body
            .independent_short_frame_bytes
            == 0
        {
            return Ok(());
        }
        if let Some(options) = self.receive_packing {
            return self.preview_packed(options);
        }
        let now = ticks(self.now)?;
        let result = (|| {
            for (id, payload) in self.recovery.received_sources().map_err(Error::Recovery)? {
                let view = envelope::decode(
                    self.receive_scope,
                    self.receive_config.receiver.body.symbol_bytes,
                    self.receive_config.receiver.channels,
                    payload,
                )
                .map_err(Error::Envelope)?;
                if view.identity.source.0 != id {
                    return Err(Error::Identity);
                }
                if self.receive_config.native_policy == NativePolicy::RawIp {
                    let symbol = view.symbol;
                    let raw = symbol[3] == 2;
                    let fragment = symbol[3] == 4 && (symbol[6..8] != [0, 0] || symbol[8] == 2);
                    if !raw && !fragment {
                        return Err(Error::Policy);
                    }
                }
                match self
                    .receiver
                    .admit_authenticated(view.identity, view.symbol, now)
                {
                    Ok(
                        receiver::Admission::Accepted
                        | receiver::Admission::Duplicate
                        | receiver::Admission::StaleSource,
                    ) => {}
                    // Actual ARQ ownership is retained for ordered retry. No
                    // source or native completion is fabricated on pressure.
                    Err(receiver::Error::Capacity | receiver::Error::RecordWindow) => break,
                    Ok(_) => return Err(Error::Identity),
                    Err(error) => return Err(Error::Receiver(error)),
                }
            }
            Ok(())
        })();
        self.terminal_result(result)
    }
    fn admit_packed(
        &mut self,
        options: packed::Options,
        id: u64,
        length: usize,
    ) -> Result<(), Error> {
        let mut inputs: [receiver::AuthenticatedSymbol<'_>; 255] =
            std::array::from_fn(|_| receiver::AuthenticatedSymbol {
                identity: receiver::SymbolIdentity {
                    scope: self.receive_scope,
                    source: receiver::SourceId(0),
                    record: receiver::RecordId(0),
                },
                bytes: &[],
            });
        let (first, count) = packed_inputs(
            options,
            self.receive_config,
            self.receive_scope,
            id,
            &self.receive_buffer[..length],
            &mut self.packed_symbols,
            &mut inputs,
        )?;
        if Some(first) != self.receive_unit {
            return Err(Error::Identity);
        }
        // The envelope parser already checked every unit's full-width ID.
        // None is the exact exhausted next ID, never wrapping back to zero.
        let next = first.0.checked_add(count as u64).map(receiver::SourceId);
        let preview = self
            .receive_config
            .receiver
            .body
            .independent_short_frame_bytes
            != 0;
        let count = if preview {
            // Previewed units can already belong to the actual contiguous
            // admission prefix, including its exhausted u64 endpoint. The
            // independent ordered-source cursor still validates this immutable
            // recovery-owned envelope's complete unit range.
            let floor = self.receiver.status().source_floor;
            let mut retained = 0;
            for index in 0..count {
                if floor.is_some_and(|floor| inputs[index].identity.source.0 >= floor.0) {
                    inputs[retained] = receiver::AuthenticatedSymbol {
                        identity: inputs[index].identity,
                        bytes: inputs[index].bytes,
                    };
                    retained += 1;
                }
            }
            retained
        } else {
            count
        };
        if count == 0 {
            self.receive_unit = next;
            return Ok(());
        }
        let mut outcomes = [receiver::Admission::Accepted; 255];
        let admitted = self
            .receiver
            .admit_validated_batch_authenticated_into(
                &inputs[..count],
                ticks(self.now)?,
                &mut outcomes[..count],
            )
            .map_err(Error::Receiver)?;
        if admitted != count
            || outcomes[..count].iter().any(|a| {
                !(matches!(a, receiver::Admission::Accepted)
                    || preview
                        && matches!(
                            a,
                            receiver::Admission::Duplicate | receiver::Admission::StaleSource
                        ))
            })
        {
            return Err(Error::Identity);
        }
        self.receive_unit = next;
        Ok(())
    }
    fn preview_packed(&mut self, options: packed::Options) -> Result<(), Error> {
        let now = ticks(self.now)?;
        let result = (|| {
            for (id, payload) in self.recovery.received_sources().map_err(Error::Recovery)? {
                let mut inputs: [receiver::AuthenticatedSymbol<'_>; 255] =
                    std::array::from_fn(|_| receiver::AuthenticatedSymbol {
                        identity: receiver::SymbolIdentity {
                            scope: self.receive_scope,
                            source: receiver::SourceId(0),
                            record: receiver::RecordId(0),
                        },
                        bytes: &[],
                    });
                let (_, count) = packed_inputs(
                    options,
                    self.receive_config,
                    self.receive_scope,
                    id,
                    payload,
                    &mut self.packed_symbols,
                    &mut inputs,
                )?;
                let mut selected = 0;
                // Validate all units before one atomic eligible-ledger admission.
                // Ordinary context-dependent frames remain recovery-owned.
                for index in 0..count {
                    let eligible = self
                        .receiver
                        .is_independent_short(inputs[index].identity, inputs[index].bytes)
                        .map_err(Error::Receiver)?;
                    if eligible
                        && self
                            .receiver
                            .status()
                            .source_floor
                            .is_some_and(|floor| inputs[index].identity.source.0 > floor.0)
                    {
                        inputs[selected] = receiver::AuthenticatedSymbol {
                            identity: inputs[index].identity,
                            bytes: inputs[index].bytes,
                        };
                        selected += 1;
                    }
                }
                if selected == 0 {
                    continue;
                }
                let mut outcomes = [receiver::Admission::Accepted; 255];
                match self.receiver.admit_batch_authenticated_into(
                    &inputs[..selected],
                    now,
                    &mut outcomes[..selected],
                ) {
                    Ok(admitted)
                        if admitted == selected
                            && outcomes[..selected].iter().all(|a| {
                                matches!(
                                    a,
                                    receiver::Admission::Accepted
                                        | receiver::Admission::Duplicate
                                        | receiver::Admission::StaleSource
                                )
                            }) => {}
                    Err(receiver::Error::Capacity | receiver::Error::RecordWindow) => break,
                    Ok(_) => return Err(Error::Identity),
                    Err(error) => return Err(Error::Receiver(error)),
                }
            }
            Ok(())
        })();
        self.terminal_result(result)
    }
    fn recovery_result<T>(&mut self, result: Result<T, Error>) -> Result<T, Error> {
        match result {
            Err(error)
                if error.is_backpressure()
                    || matches!(
                        error,
                        Error::Recovery(l2tunnel_reliable::Error::OutputTooSmall { .. })
                    ) =>
            {
                Err(error)
            }
            other => self.terminal_result(other),
        }
    }
    fn terminal_result<T>(&mut self, result: Result<T, Error>) -> Result<T, Error> {
        result.or_else(|error| self.fail(error))
    }
    fn fail<T>(&mut self, error: Error) -> Result<T, Error> {
        self.failure = Some(error);
        Err(error)
    }
}

// Reuse the exact ordinary packed parser and retained padded symbol slab for
// ordered admission and short preview. No payload queue or codec is duplicated.
#[allow(clippy::too_many_arguments)] // Explicit existing owners and borrowed caller scratch.
fn packed_inputs<'a>(
    options: packed::Options,
    config: Config,
    scope: receiver::Scope,
    source: u64,
    packet: &[u8],
    scratch: &'a mut [u8],
    output: &mut [receiver::AuthenticatedSymbol<'a>; 255],
) -> Result<(receiver::SourceId, usize), Error> {
    let view =
        l2tunnel_codec::packed_envelope::decode(options.config(config).envelope(), scope, packet)
            .map_err(Error::PackedEnvelope)?;
    if view.identity().source.0 != source {
        return Err(Error::Identity);
    }
    let first = view.identity().first_unit;
    let units = view.units().map_err(Error::PackedEnvelope)?;
    let count = units.len();
    let width = config.receiver.body.symbol_bytes;
    let mut received = 0;
    for (unit, symbol) in units.zip(scratch.chunks_exact_mut(width)) {
        symbol.fill(0);
        symbol[..unit.bytes.len()].copy_from_slice(unit.bytes);
        if config.native_policy == NativePolicy::RawIp {
            let raw = symbol[3] == 2;
            let fragment = symbol[3] == 4 && (symbol[6..8] != [0, 0] || symbol[8] == 2);
            if !raw && !fragment {
                return Err(Error::Policy);
            }
        }
        output[received] = receiver::AuthenticatedSymbol {
            identity: unit.identity,
            bytes: symbol,
        };
        received += 1;
    }
    if received != count {
        return Err(Error::Identity);
    }
    Ok((first, count))
}

fn sender_config(config: Config) -> sender::Config {
    sender::Config {
        body: config.receiver.body,
        channels: config.receiver.channels,
        first_record: config.receiver.first_record,
    }
}
fn ticks(now: Duration) -> Result<receiver::Tick, Error> {
    Ok(receiver::Tick(
        u64::try_from(now.as_millis()).map_err(|_| Error::Time)?,
    ))
}
fn config_hash(bytes: &[u8]) -> ConfigDigest {
    let hash = ring::digest::digest(&ring::digest::SHA256, bytes);
    let mut result = [0; 32];
    result.copy_from_slice(hash.as_ref());
    ConfigDigest(result)
}
fn number(output: &mut Vec<u8>, value: u64) {
    output.extend_from_slice(&value.to_be_bytes());
}
fn duration(output: &mut Vec<u8>, value: Duration) {
    number(output, value.as_secs());
    number(output, u64::from(value.subsec_nanos()));
}

#[cfg(test)]
mod directional_tests;
#[cfg(test)]
mod packed_early_tests;
#[cfg(test)]
mod packed_tests;
#[cfg(test)]
mod tests;
