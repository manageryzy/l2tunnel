//! Fixed native MUX and Python-aligned symbols over authenticated UDP or genuine QUIC.
//! Cauchy recovery remains globally source ordered; early-short gap bypass and hot
//! reload are unsupported. Existing frame/fragment runtime profiles are unchanged.

use super::{Compression, Duplex, RuntimeConfig, invalid, packet_valid, quic, udp};
use crate::datagram::{DatagramParts, DatagramReceive, DatagramSend};
use l2tunnel_aligned::{self as protocol, NativePolicy};
use l2tunnel_auth::SessionConfig;
use l2tunnel_codec::{aligned_body, aligned_receiver};
use l2tunnel_core::ConfigDigest;
use l2tunnel_device::{PacketDevice, PacketLayer};
use l2tunnel_pipeline::{self as pipeline, Pipeline, PipelineConfig};
use l2tunnel_recovery::{EndpointRole, RecoveryContext};
use std::{io, net::SocketAddr, time::Duration};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    sync::{mpsc, watch},
    task::JoinSet,
    time::{Instant, MissedTickBehavior, interval},
};
use udp::{DatagramPolicy, Lane};
#[path = "aligned_delivery.rs"]
mod delivery;
#[path = "aligned_owner.rs"]
mod owner;
use owner::Endpoint;
pub(super) use owner::Selection;

/// Immutable native scheduling and actual aligned/Cauchy policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Config {
    /// Required canonical native flight budgets, independent of local queues.
    pub delivery: crate::managed::DeliveryConfig,
    /// Complete bounded symbol/recovery/native interpretation.
    pub protocol: protocol::Config,
    /// Existing common MUX and explicit TAP or transparent-TUN QoS policy.
    pub pipeline: PipelineConfig,
}
impl Config {
    /// Derive exact envelope/source budgets from an explicitly Cauchy UDP transport.
    pub fn for_udp(
        runtime: RuntimeConfig,
        transport: udp::Config,
        channels: u16,
        delivery: crate::managed::DeliveryConfig,
    ) -> io::Result<Self> {
        udp::transport_session_config(runtime, transport)?;
        Self::from_policy(runtime, transport.policy()?, channels, delivery)
    }
    /// Derive exact budgets from an explicitly Cauchy genuine QUIC transport.
    pub fn for_quic(
        runtime: RuntimeConfig,
        transport: quic::Config,
        channels: u16,
        delivery: crate::managed::DeliveryConfig,
    ) -> io::Result<Self> {
        quic::transport_session_config(runtime, transport)?;
        Self::from_policy(runtime, transport.policy()?, channels, delivery)
    }
    fn from_policy(
        runtime: RuntimeConfig,
        policy: DatagramPolicy,
        channels: u16,
        delivery: crate::managed::DeliveryConfig,
    ) -> io::Result<Self> {
        let value = Self::derive(runtime, policy, channels, 48, delivery)?;
        value.validate(runtime, policy)?;
        Ok(value)
    }
    pub(super) fn derive(
        runtime: RuntimeConfig,
        policy: DatagramPolicy,
        channels: u16,
        envelope_bytes: usize,
        delivery: crate::managed::DeliveryConfig,
    ) -> io::Result<Self> {
        runtime.validate()?;
        delivery.validate(runtime)?;
        let recovery = policy
            .reliable
            .ok_or_else(|| invalid("aligned runtime requires Cauchy recovery"))?;
        let symbol_bytes = recovery
            .arq
            .max_source_bytes
            .checked_sub(envelope_bytes)
            .ok_or_else(|| invalid("aligned envelope MTU"))?;
        let fragments = (runtime.max_packet + 29).clamp(69, 65535).div_ceil(
            symbol_bytes
                .checked_sub(8)
                .filter(|n| *n != 0)
                .ok_or_else(|| invalid("aligned fragment geometry"))?,
        );
        let queue_bytes = runtime
            .queue_packets
            .checked_mul(runtime.max_packet)
            .ok_or_else(|| invalid("aligned native queue overflow"))?;
        let records = delivery
            .forward
            .max_records
            .max(delivery.reverse.max_records);
        // Encoded lookahead has its own finite pure-codec geometry. It is not
        // the flight grant or the local MUX queue. Lower-layer pressure retains
        // original ownership when this bank is full.
        let lookahead = records
            .min(2048)
            .checked_mul(2)
            .ok_or_else(|| invalid("aligned record count overflow"))?
            .min(1_048_576 / fragments);
        let body_bytes = delivery
            .forward
            .max_inflight_bytes
            .max(delivery.reverse.max_inflight_bytes)
            .checked_add(
                (records as u64)
                    .checked_mul(98)
                    .ok_or_else(|| invalid("aligned body overhead overflow"))?,
            )
            .and_then(|n| usize::try_from(n).ok())
            .ok_or_else(|| invalid("aligned body allocation overflow"))?;
        let value = Self {
            delivery,
            protocol: protocol::Config {
                native_policy: match runtime.layer {
                    PacketLayer::Ethernet => NativePolicy::EthernetHeaders,
                    PacketLayer::Ip => NativePolicy::RawIp,
                },
                receiver: aligned_receiver::Limits {
                    body: aligned_body::Config {
                        max_frame_bytes: runtime.max_packet,
                        symbol_bytes,
                        elide_payload_length: runtime.layer == PacketLayer::Ethernet,
                        predictive: runtime.layer == PacketLayer::Ethernet,
                        timestamp_pair_dictionary: runtime.layer == PacketLayer::Ethernet,
                        independent_short_frame_bytes: 128.min(symbol_bytes.saturating_sub(6)),
                    },
                    channels,
                    first_record: aligned_receiver::RecordId(0),
                    first_source: aligned_receiver::SourceId(0),
                    record_window: 32767,
                    source_window: recovery.arq.receive_records + recovery.max_restored_packets,
                    lookahead_records: lookahead,
                    lookahead_bytes: body_bytes,
                    lookahead_fragments: lookahead
                        .checked_mul(fragments)
                        .ok_or_else(|| invalid("aligned fragment count overflow"))?,
                    max_fragments_per_record: fragments,
                    lifetime_ticks: u64::try_from(policy.reassembly_timeout.as_millis())
                        .map_err(|_| invalid("aligned lifetime overflow"))?,
                },
                recovery,
                max_recovery_packet_bytes: policy.payload_bytes,
            },
            pipeline: PipelineConfig {
                profile: match runtime.layer {
                    PacketLayer::Ethernet => pipeline::Profile::TapSystem,
                    PacketLayer::Ip => pipeline::Profile::TunDrr(pipeline::TunQosConfig {
                        base_quantum_bytes: u32::try_from(runtime.max_packet)
                            .map_err(|_| invalid("aligned DRR quantum"))?,
                        max_weight: 1,
                        per_flow: pipeline::QueueLimits {
                            bytes: queue_bytes,
                            packets: runtime.queue_packets,
                        },
                    }),
                },
                flows: pipeline::FlowTableConfig {
                    capacity: 1024,
                    channels,
                    mapping: pipeline::Mapping::Crc32,
                    idle_timeout: Duration::from_secs(60),
                },
                parse: pipeline::ParseLimits {
                    max_packet_bytes: runtime.max_packet,
                    ..pipeline::ParseLimits::default()
                },
                queue: pipeline::QueueLimits {
                    bytes: queue_bytes,
                    packets: runtime.queue_packets,
                },
            },
        };
        Ok(value)
    }
    fn validate(self, runtime: RuntimeConfig, policy: DatagramPolicy) -> io::Result<()> {
        runtime.validate()?;
        self.protocol.validate().map_err(io::Error::other)?;
        self.validate_runtime(runtime, policy)
    }
    pub(super) fn validate_runtime(
        self,
        runtime: RuntimeConfig,
        policy: DatagramPolicy,
    ) -> io::Result<()> {
        self.delivery.validate(runtime)?;
        delivery::validate(self)?;
        runtime.validate()?;
        let native = match runtime.layer {
            PacketLayer::Ethernet => NativePolicy::EthernetHeaders,
            PacketLayer::Ip => NativePolicy::RawIp,
        };
        let profile_matches = matches!(
            (runtime.layer, self.pipeline.profile),
            (PacketLayer::Ethernet, pipeline::Profile::TapSystem)
                | (PacketLayer::Ip, pipeline::Profile::TunDrr(_))
        );
        if runtime.compression != Compression::None
            || runtime.max_packet > 65532
            || self.protocol.native_policy != native
            || !profile_matches
            || self.protocol.recovery
                != policy
                    .reliable
                    .ok_or_else(|| invalid("aligned requires Cauchy"))?
            || self.protocol.recovery.outer_overhead_bytes != 0
            || self.protocol.max_recovery_packet_bytes != policy.payload_bytes
            || self.protocol.receiver.body.max_frame_bytes != runtime.max_packet
            || self.protocol.receiver.channels != self.pipeline.flows.channels
            || self.pipeline.flows.mapping != pipeline::Mapping::Crc32
            || self.pipeline.parse.max_packet_bytes != runtime.max_packet
            || self.pipeline.queue.packets > runtime.queue_packets
            || self.pipeline.queue.bytes
                > runtime
                    .queue_packets
                    .checked_mul(runtime.max_packet)
                    .ok_or_else(|| invalid("aligned queue overflow"))?
        {
            return Err(invalid(
                "aligned native policy, queue, format or geometry mismatch",
            ));
        }
        Pipeline::new(self.pipeline).map_err(io::Error::other)?;
        Ok(())
    }
}
fn bind(base: SessionConfig, config: Config) -> io::Result<SessionConfig> {
    bind_delivery(
        bind_policy(
            base,
            config.protocol.digest().map_err(io::Error::other)?,
            config.pipeline,
            b"l2tunnel/aligned-runtime/v2/common-mux-crc32/native-identity-credit-v2\0",
        ),
        config.delivery,
    )
}
pub(super) fn bind_delivery(
    base: SessionConfig,
    delivery: crate::managed::DeliveryConfig,
) -> io::Result<SessionConfig> {
    let mut hash = ring::digest::Context::new(&ring::digest::SHA256);
    hash.update(b"l2tunnel/aligned-packed/delivery-policy-v2\0");
    hash.update(&base.digest.0);
    hash.update(&delivery.canonical()?);
    let digest = ConfigDigest(
        hash.finish()
            .as_ref()
            .try_into()
            .map_err(|_| invalid("aligned delivery digest"))?,
    );
    Ok(SessionConfig {
        layer: base.layer,
        digest,
    })
}
pub(super) fn bind_policy(
    base: SessionConfig,
    protocol_digest: ConfigDigest,
    policy: PipelineConfig,
    domain: &[u8],
) -> SessionConfig {
    let mut hash = ring::digest::Context::new(&ring::digest::SHA256);
    hash.update(domain);
    hash.update(&base.digest.0);
    hash.update(&protocol_digest.0);
    match policy.profile {
        pipeline::Profile::TapSystem => hash.update(&[0]),
        pipeline::Profile::TunDrr(qos) => {
            hash.update(&[1]);
            for number in [
                qos.base_quantum_bytes as u64,
                qos.max_weight as u64,
                qos.per_flow.bytes as u64,
                qos.per_flow.packets as u64,
            ] {
                hash.update(&number.to_be_bytes());
            }
        }
    }
    for number in [
        policy.flows.capacity as u64,
        u64::from(policy.flows.channels),
        policy.flows.idle_timeout.as_secs(),
        u64::from(policy.flows.idle_timeout.subsec_nanos()),
        policy.parse.max_packet_bytes as u64,
        u64::from(policy.parse.max_vlan_tags),
        u64::from(policy.parse.max_ipv6_extensions),
        policy.parse.max_ipv6_extension_bytes as u64,
        policy.queue.bytes as u64,
        policy.queue.packets as u64,
    ] {
        hash.update(&number.to_be_bytes());
    }
    let mut digest = [0; 32];
    digest.copy_from_slice(hash.finish().as_ref());
    SessionConfig {
        layer: base.layer,
        digest: ConfigDigest(digest),
    }
}
/// Canonical aligned policy before applying the selected physical UDP lane.
pub fn udp_base_session_config(
    runtime: RuntimeConfig,
    transport: udp::Config,
    config: Config,
) -> io::Result<SessionConfig> {
    config.validate(runtime, transport.policy()?)?;
    bind(udp::transport_session_config(runtime, transport)?, config)
}
/// Exact retained TLS member-authentication binding for this aligned UDP lane.
pub fn udp_session_config(
    runtime: RuntimeConfig,
    transport: udp::Config,
    config: Config,
    lane: Lane,
) -> io::Result<SessionConfig> {
    let carrier = udp_carrier_config(
        runtime,
        transport,
        config,
        lane,
        SocketAddr::from(([127, 0, 0, 1], 1)),
    )?;
    l2tunnel_udp::session_config(carrier.base, carrier.profile).map_err(io::Error::other)
}
/// Construct the actual fixed-endpoint carrier with aligned authentication binding.
pub fn udp_carrier_config(
    runtime: RuntimeConfig,
    transport: udp::Config,
    config: Config,
    lane: Lane,
    peer: SocketAddr,
) -> io::Result<l2tunnel_udp::Config> {
    let mut carrier = udp::transport_carrier_config(runtime, transport, lane, peer)?;
    carrier.base = udp_base_session_config(runtime, transport, config)?;
    Ok(carrier)
}
/// Canonical aligned native binding passed to the genuine QUIC endpoint.
pub fn quic_base_session_config(
    runtime: RuntimeConfig,
    transport: quic::Config,
    config: Config,
) -> io::Result<SessionConfig> {
    config.validate(runtime, transport.policy()?)?;
    bind(quic::transport_session_config(runtime, transport)?, config)
}
/// Exact expected member-authentication binding after QUIC profile application.
pub fn quic_session_config(
    runtime: RuntimeConfig,
    transport: quic::Config,
    config: Config,
    lane: Lane,
) -> io::Result<SessionConfig> {
    l2tunnel_quic::session_config(
        quic_base_session_config(runtime, transport, config)?,
        quic::carrier_profile(transport, lane)?,
    )
    .map_err(io::Error::other)
}
/// Actual retained full or paired-half UDP carriers bound to aligned native policy.
pub struct UdpLink(udp::Link);
impl UdpLink {
    /// Validate one full-duplex authenticated carrier before native admission.
    pub fn full(
        carrier: l2tunnel_udp::Carrier,
        runtime: RuntimeConfig,
        transport: udp::Config,
        config: Config,
    ) -> io::Result<Self> {
        Ok(Self(udp::Link::full_bound(
            carrier,
            runtime,
            transport,
            udp_base_session_config(runtime, transport, config)?,
        )?))
    }
}
/// Prove two distinct client UDP lanes with their existing retained pair protocol.
pub async fn udp_client_pair(
    first: l2tunnel_udp::Carrier,
    second: l2tunnel_udp::Carrier,
    runtime: RuntimeConfig,
    transport: udp::Config,
    config: Config,
) -> io::Result<UdpLink> {
    Ok(UdpLink(
        udp::pair_bound(
            first,
            second,
            runtime,
            transport,
            udp_base_session_config(runtime, transport, config)?,
            true,
        )
        .await?,
    ))
}
/// Verify two distinct server UDP lanes before any native device read.
pub async fn udp_server_pair(
    first: l2tunnel_udp::Carrier,
    second: l2tunnel_udp::Carrier,
    runtime: RuntimeConfig,
    transport: udp::Config,
    config: Config,
) -> io::Result<UdpLink> {
    Ok(UdpLink(
        udp::pair_bound(
            first,
            second,
            runtime,
            transport,
            udp_base_session_config(runtime, transport, config)?,
            false,
        )
        .await?,
    ))
}
/// Actual retained full or paired-half genuine QUIC connections with aligned binding.
pub struct QuicLink(quic::Link);
impl QuicLink {
    /// Validate one full-duplex genuine QUIC connection before native admission.
    pub fn full(
        connection: l2tunnel_quic::AuthenticatedConnection,
        runtime: RuntimeConfig,
        transport: quic::Config,
        config: Config,
    ) -> io::Result<Self> {
        Ok(Self(quic::Link::full_bound(
            connection,
            runtime,
            transport,
            quic_base_session_config(runtime, transport, config)?,
        )?))
    }
}
/// Prove the client's two actual independently authenticated QUIC lanes.
pub async fn quic_client_pair(
    first: l2tunnel_quic::AuthenticatedConnection,
    second: l2tunnel_quic::AuthenticatedConnection,
    runtime: RuntimeConfig,
    transport: quic::Config,
    config: Config,
) -> io::Result<QuicLink> {
    Ok(QuicLink(
        quic::pair_bound(
            first,
            second,
            runtime,
            transport,
            quic_base_session_config(runtime, transport, config)?,
            true,
        )
        .await?,
    ))
}
/// Verify the server's two actual independently authenticated QUIC lanes.
pub async fn quic_server_pair(
    first: l2tunnel_quic::AuthenticatedConnection,
    second: l2tunnel_quic::AuthenticatedConnection,
    runtime: RuntimeConfig,
    transport: quic::Config,
    config: Config,
) -> io::Result<QuicLink> {
    Ok(QuicLink(
        quic::pair_bound(
            first,
            second,
            runtime,
            transport,
            quic_base_session_config(runtime, transport, config)?,
            false,
        )
        .await?,
    ))
}
/// Run fixed aligned native forwarding on actual protected UDP, retaining TLS control.
pub async fn run_udp<D: PacketDevice<Error = io::Error>>(
    device: D,
    link: UdpLink,
    runtime: RuntimeConfig,
    transport: udp::Config,
    config: Config,
) -> io::Result<()> {
    let (parts, initiator) = link
        .0
        .into_bound_parts(udp_base_session_config(runtime, transport, config)?)?;
    run_parts(
        device,
        parts,
        initiator,
        runtime,
        transport.policy()?,
        Selection::Aligned(config),
    )
    .await
}
/// Run fixed aligned native forwarding on actual standalone QUIC; no TCP socket is added.
pub async fn run_quic<D: PacketDevice<Error = io::Error>>(
    device: D,
    link: QuicLink,
    runtime: RuntimeConfig,
    transport: quic::Config,
    config: Config,
) -> io::Result<()> {
    let (parts, initiator) = link
        .0
        .into_bound_parts(quic_base_session_config(runtime, transport, config)?)?;
    run_parts(
        device,
        parts,
        initiator,
        runtime,
        transport.policy()?,
        Selection::Aligned(config),
    )
    .await
}
struct State {
    endpoint: Endpoint,
    outbound: Option<mpsc::Sender<delivery::Outbound>>,
    feedback: watch::Sender<udp::Feedback>,
    native_feedback: mpsc::Sender<protocol::RecordIdentity>,
    receives: bool,
    flight: Option<delivery::Flight>,
    incoming: l2tunnel_flow_control::delivery_window::Config,
    next_channel: u16,
}
impl State {
    fn check_retention(&self, runtime: RuntimeConfig) -> io::Result<()> {
        let retained = self.endpoint.status().receiver;
        if retained.native_records > self.incoming.max_records
            || retained.pending_bytes.is_some_and(|bytes| {
                bytes as u64 > self.incoming.max_inflight_bytes || bytes > runtime.max_packet
            })
        {
            return Err(invalid("aligned peer exceeded native delivery capacity"));
        }
        Ok(())
    }
    fn control(
        &mut self,
        event: udp::NativeControlEvent,
        actual: Duration,
        now: Duration,
    ) -> io::Result<()> {
        match event {
            udp::NativeControlEvent::Ack(bytes) => {
                if self
                    .endpoint
                    .inspect_peer(&bytes)
                    .map_err(io::Error::other)?
                    != l2tunnel_reliable::RecordKind::Feedback
                {
                    return Err(invalid("aligned data on control path"));
                }
                self.endpoint
                    .receive_authenticated(&bytes, now)
                    .map_err(io::Error::other)
            }
            udp::NativeControlEvent::Delivered { channel, record } => self
                .flight
                .as_mut()
                .ok_or_else(|| invalid("aligned native receipt on receive-only lane"))?
                .delivered(
                    protocol::RecordIdentity {
                        channel: protocol::ChannelId(channel),
                        record: aligned_receiver::RecordId(record),
                    },
                    actual,
                    now,
                ),
        }
    }
}
pub(super) async fn run_parts<D, C, S, R>(
    device: D,
    parts: Vec<DatagramParts<C, S, R>>,
    initiator: bool,
    runtime: RuntimeConfig,
    policy: DatagramPolicy,
    selection: Selection,
) -> io::Result<()>
where
    D: PacketDevice<Error = io::Error>,
    C: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    S: DatagramSend,
    R: DatagramReceive,
{
    run_parts_observed(device, parts, initiator, runtime, policy, selection, None).await
}
#[derive(Clone, Copy, Debug, Default)]
pub(super) struct ActorStatus {
    pub flight: [Option<l2tunnel_flow_control::delivery_window::Status>; 2],
}
pub(super) async fn run_parts_observed<D, C, S, R>(
    mut device: D,
    parts: Vec<DatagramParts<C, S, R>>,
    initiator: bool,
    runtime: RuntimeConfig,
    mut policy: DatagramPolicy,
    selection: Selection,
    observer: Option<watch::Sender<ActorStatus>>,
) -> io::Result<()>
where
    D: PacketDevice<Error = io::Error>,
    C: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    S: DatagramSend,
    R: DatagramReceive,
{
    selection.validate(runtime, policy)?;
    let config = selection.base();
    if device.layer() != runtime.layer {
        return Err(invalid(
            "aligned native device layer differs from authentication",
        ));
    }
    policy.control_magic = selection.control_magic();
    let mut pipeline = Pipeline::new(config.pipeline).map_err(io::Error::other)?;
    let (control_tx, mut control_rx) = mpsc::channel(8);
    let (data_tx, mut data_rx) = mpsc::channel(policy.arq.receive_records * parts.len());
    let started = Instant::now();
    let budget = udp::SharedBudget::from_policy(policy, started);
    let mut tasks = JoinSet::new();
    let mut states = Vec::new();
    let sent_capacity = runtime.queue_packets;
    let (sent_tx, mut sent_rx) = mpsc::channel(sent_capacity);
    let role = if initiator {
        crate::managed::Role::Client
    } else {
        crate::managed::Role::Server
    };
    for (index, part) in parts.into_iter().enumerate() {
        let sends = policy.duplex == Duplex::Full || (index == 0) == initiator;
        let receives = policy.duplex == Duplex::Full || !sends;
        let context = RecoveryContext {
            session: u128::from_be_bytes(part.session),
            epoch: 1,
            role: if initiator {
                EndpointRole::Initiator
            } else {
                EndpointRole::Responder
            },
        };
        let (reader, writer) = tokio::io::split(part.control);
        let (feedback, changes) = watch::channel(udp::Feedback::default());
        tasks.spawn(udp::read_native_control_bound_timed(
            reader,
            index,
            control_tx.clone(),
            policy.control_timeout,
            56,
            policy.control_magic,
        ));
        let (native_feedback, native_changes) = mpsc::channel(runtime.queue_packets);
        tasks.spawn(delivery::write_control(
            writer,
            changes,
            native_changes,
            policy,
            budget.clone(),
        ));
        if receives {
            tasks.spawn(udp::read_datagrams(
                part.receiver,
                policy.payload_bytes,
                index,
                data_tx.clone(),
            ));
        }
        let outbound = if sends {
            let (tx, rx) = mpsc::channel(1);
            tasks.spawn(delivery::write_datagrams(
                part.sender,
                rx,
                index,
                sent_tx.clone(),
            ));
            Some(tx)
        } else {
            None
        };
        states.push(State {
            endpoint: selection.endpoint(context)?,
            outbound,
            feedback,
            receives,
            native_feedback,
            incoming: config.delivery.incoming(role),
            flight: sends
                .then(|| {
                    delivery::Flight::new(
                        config.delivery.outgoing(role),
                        usize::from(config.pipeline.flows.channels),
                        config.protocol.receiver.max_fragments_per_record,
                    )
                })
                .transpose()?,
            next_channel: 0,
        });
    }
    drop(control_tx);
    drop(data_tx);
    drop(sent_tx);
    let mut ticker = interval(runtime.poll_interval);
    ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
    let mut packet = vec![0; l2tunnel_device::READ_BUFFER_BYTES];
    let mut encoded = vec![0; policy.payload_bytes];
    let mut units = vec![
        protocol::UnitWitness {
            identity: protocol::RecordIdentity {
                channel: protocol::ChannelId(0),
                record: aligned_receiver::RecordId(0)
            },
            index: 0,
            count: 1,
        };
        selection.unit_limit()
    ];
    let mut ingress: Option<Vec<u8>> = None;
    let mut selected: Option<pipeline::Packet> = None;
    let mut idle_cursor = None;
    let result = async {
    loop {
        let packing_wake = states.iter().filter_map(|state| state.endpoint.packing_wake()).min();
        tokio::select! {
            _=async { match packing_wake {
                Some(deadline) => tokio::time::sleep_until(started + deadline).await,
                None => std::future::pending().await,
            }}=>{},
            Some(result)=tasks.join_next()=>return match result { Ok(Err(error))=>Err(error), Err(error)=>Err(io::Error::other(error)), Ok(Ok(()))=>Err(invalid("aligned carrier task ended")) },
            Some((lane,event,actual))=control_rx.recv()=>states[lane].control(event,delivery::since(started, actual)?,started.elapsed())?,
            Some(sent)=sent_rx.recv()=>states[sent.lane].flight.as_mut().ok_or_else(||invalid("aligned send callback on receive-only lane"))?.sent(&sent.units,delivery::since(started, sent.at)?,started.elapsed())?,
            Some((lane,bytes))=data_rx.recv()=>{
                let state=&mut states[lane];
                if !state.receives || state.endpoint.inspect_peer(&bytes).map_err(io::Error::other)? == l2tunnel_reliable::RecordKind::Feedback { return Err(invalid("aligned datagram role or kind")); }
                state.endpoint.receive_authenticated(&bytes,started.elapsed()).map_err(io::Error::other)?;
                state.check_retention(runtime)?;
            },
            _=ticker.tick()=>{},
        }
        // At most one static channel capacity is drained per actor turn; a
        // concurrently producing writer cannot create an unbounded drain loop.
        for _ in 0..sent_capacity {
            let Ok(sent) = sent_rx.try_recv() else { break };
            states[sent.lane].flight.as_mut().ok_or_else(|| invalid("aligned unexpected send callback"))?
                .sent(&sent.units, delivery::since(started, sent.at)?, started.elapsed())?;
        }
        for state in &mut states {
            if let Some(flight) = &mut state.flight { flight.tick(started.elapsed())?; }
        }
        retire_registration(&mut pipeline, selected.as_ref(), &mut idle_cursor, started.elapsed())?;
        // Only the explicit packed profile batches native ingress with common
        // MUX admission. Fresh time per operation prevents a slow burst from
        // admitting later units against an expired first-unit packing deadline.
        for _ in 0..selection.burst_limit() {
            let mut progress = ingress_step(&mut device, &mut pipeline, &mut ingress,
                &mut packet, runtime, config, started.elapsed())?;
            let mut staged = false;
            for state in states.iter_mut().filter(|state| state.outbound.is_some()) {
                staged |= state.endpoint.status().staged_frame;
                state.endpoint.tick(started.elapsed()).map_err(io::Error::other)?;
                state.check_retention(runtime)?;
                progress |= admit_native(state, &mut pipeline, &mut selected, started.elapsed())?;
            }
            if !progress && !staged { break; }
        }
        let now = started.elapsed();
        for state in &mut states {
            let now = if selection.burst_limit() == 0 { now } else { started.elapsed() };
            state.endpoint.tick(now).map_err(io::Error::other)?;
            state.check_retention(runtime)?;
            if state.receives {
                for _ in 0..usize::from(config.pipeline.flows.channels) {
                    let channel = protocol::ChannelId(state.next_channel as u8);
                    state.next_channel = (state.next_channel + 1) % config.pipeline.flows.channels;
                    let now = if selection.burst_limit() == 0 { now } else { started.elapsed() };
                    state
                        .endpoint
                        .prepare(channel, now, 4)
                        .map_err(io::Error::other)?;
                    let Some(frame) = state.endpoint.pending() else {
                        continue;
                    };
                    if frame.bytes.len() > runtime.max_packet
                        || !packet_valid(runtime.layer, frame.bytes)
                    {
                        return Err(invalid("invalid aligned native packet"));
                    }
                    let key = pipeline
                        .classify(frame.bytes)
                        .map_err(io::Error::other)?
                        .key;
                    match pipeline.learn(key, u16::from(frame.channel.0), 1, now) {
                        Ok(_) => {},
                        Err(error) if flow_capacity(&error) => break,
                        Err(error) => return Err(io::Error::other(error)),
                    }
                    let identity = protocol::RecordIdentity { channel: frame.channel, record: frame.record };
                    // Reserve exact receipt ownership before the irreversible
                    // native write. A full control queue retains the same frame.
                    let receipt = match state.native_feedback.try_reserve() {
                        Ok(permit) => permit,
                        Err(mpsc::error::TrySendError::Full(_)) => break,
                        Err(mpsc::error::TrySendError::Closed(_)) => return Err(invalid("aligned native feedback writer closed")),
                    };
                    match device.transmit(frame.bytes) {
                        Ok(()) => {
                            state
                                .endpoint
                                .commit_delivery(if selection.burst_limit() == 0 { now } else { started.elapsed() })
                                .map_err(io::Error::other)?;
                            receipt.send(identity);
                        }
                        Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                        Err(error) => return Err(error),
                    }
                    state.check_retention(runtime)?;
                }
            }
            if state.outbound.is_some() {
                if selection.burst_limit() == 0 {
                    admit_native(state, &mut pipeline, &mut selected, now)?;
                }
                let outbound = state.outbound.as_ref().ok_or_else(|| invalid("missing aligned sender"))?;
                let now = if selection.burst_limit() == 0 { now } else { started.elapsed() };
                match outbound.try_reserve() {
                    Ok(permit) => {
                        if let Some(length) =
                            budget.poll_with(false, now, &mut encoded, |output, allowance| {
                                state
                                    .endpoint
                                    .poll_data(now, output, allowance)
                                    .map_err(io::Error::other)
                            })?
                        {
                            let count = state.endpoint.outgoing_units(&encoded[..length], &mut units).map_err(io::Error::other)?;
                            permit.send(delivery::Outbound { bytes: encoded[..length].to_vec(), units: units[..count].to_vec() });
                        }
                    }
                    Err(mpsc::error::TrySendError::Full(_)) => {}
                    Err(mpsc::error::TrySendError::Closed(_)) => {
                        return Err(invalid("aligned datagram writer closed"));
                    }
                }
            }
            let now = if selection.burst_limit() == 0 { now } else { started.elapsed() };
            if let Some(length) =
                budget.poll_with(true, now, &mut encoded, |output, allowance| {
                    state
                        .endpoint
                        .poll_feedback(now, output, allowance)
                        .map_err(io::Error::other)
                })?
            {
                state
                    .feedback
                    .send_modify(|feedback| feedback.ack = Some(encoded[..length].to_vec()));
            }
        }
        if selection.burst_limit() == 0 {
            ingress_step(&mut device, &mut pipeline, &mut ingress, &mut packet, runtime, config, now)?;
        }
        if let Some(observer) = &observer {
            let mut status = ActorStatus::default();
            for (index, state) in states.iter().enumerate() {
                status.flight[index] = state.flight.as_ref().map(|flight| flight.controller.status(delivery::micros(started.elapsed())?).map_err(io::Error::other)).transpose()?;
            }
            observer.send_replace(status);
        }
    }
    }.await;
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    result
}

fn admit_native(
    state: &mut State,
    pipeline: &mut Pipeline,
    selected: &mut Option<pipeline::Packet>,
    now: Duration,
) -> io::Result<bool> {
    if state.endpoint.status().staged_frame {
        return Ok(false);
    }
    if selected.is_none() {
        *selected = pipeline.dequeue().map_err(io::Error::other)?;
    }
    let Some(item) = selected.take() else {
        return Ok(false);
    };
    let flight = state
        .flight
        .as_mut()
        .ok_or_else(|| invalid("aligned missing native flight owner"))?;
    if !flight.preview(item.payload.len(), now)? {
        *selected = Some(item);
        return Ok(false);
    }
    let channel = u8::try_from(item.metadata.binding.channel)
        .map_err(|_| invalid("aligned channel range"))?;
    match state
        .endpoint
        .enqueue_identified(protocol::ChannelId(channel), &item.payload, now)
    {
        Ok(identity) => {
            flight.admit(identity, item.payload.len(), now)?;
            Ok(true)
        }
        Err(protocol::Error::Busy) => {
            *selected = Some(item);
            Ok(false)
        }
        Err(error) => Err(io::Error::other(error)),
    }
}

fn flow_capacity(error: &pipeline::PipelineError) -> bool {
    matches!(
        error,
        pipeline::PipelineError::Flow(l2tunnel_packet::FlowError::Capacity)
    )
}

fn retire_registration(
    pipeline: &mut Pipeline,
    selected: Option<&pipeline::Packet>,
    cursor: &mut Option<pipeline::FlowKey>,
    now: Duration,
) -> io::Result<()> {
    // Selected packets retain a local Binding until admission. Thereafter the
    // aligned/packed endpoints, recovery and native handoff own only channel and
    // bytes, never FlowId. Fixed CRC mapping (validated at startup) preserves that
    // channel on relearn; retirement cannot alter their contexts or delivery debt.
    // This proves registration dependencies drained, not delivery of owned bytes.
    let scan = pipeline
        .idle_step(
            now,
            *cursor,
            16,
            selected.map(|packet| packet.metadata.classification.key),
        )
        .map_err(io::Error::other)?;
    *cursor = scan.after;
    if let Some((key, _)) = scan.candidate {
        pipeline
            .retire_idle_drained(&key, now)
            .map_err(io::Error::other)?;
    }
    Ok(())
}
fn ingress_step<D: PacketDevice<Error = io::Error>>(
    device: &mut D,
    pipeline: &mut Pipeline,
    ingress: &mut Option<Vec<u8>>,
    packet: &mut [u8],
    runtime: RuntimeConfig,
    config: Config,
    now: Duration,
) -> io::Result<bool> {
    let mut progress = false;
    if ingress.is_none()
        && pipeline.usage().packets < config.pipeline.queue.packets
        && let Some(length) = device.receive(packet)?
    {
        if length > runtime.max_packet || !packet_valid(runtime.layer, &packet[..length]) {
            return Err(invalid("device supplied invalid aligned packet"));
        }
        *ingress = Some(packet[..length].to_vec());
        progress = true;
    }
    if let Some(bytes) = ingress.take() {
        match pipeline.enqueue(bytes, now) {
            Ok(_) => progress = true,
            Err(error)
                if matches!(error.kind, pipeline::PipelineError::Budget(_))
                    || flow_capacity(&error.kind) =>
            {
                *ingress = Some(error.payload)
            }
            Err(error) => return Err(io::Error::other(error)),
        }
    }
    Ok(progress)
}

#[cfg(test)]
#[path = "aligned_tests.rs"]
mod tests;
