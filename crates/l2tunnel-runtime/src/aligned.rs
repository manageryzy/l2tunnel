//! Fixed native MUX and Python-aligned symbols over authenticated UDP or genuine QUIC.
//! Cauchy recovery remains globally source ordered; early-short gap bypass and hot
//! reload are unsupported. Existing frame/fragment runtime profiles are unchanged.

use super::{Compression, Duplex, RuntimeConfig, invalid, packet_valid, quic, udp};
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
use udp::{DatagramParts, DatagramPolicy, DatagramReceive, DatagramSend, Lane};
#[path = "aligned_owner.rs"]
mod owner;
use owner::Endpoint;
pub(super) use owner::Selection;

/// Immutable native scheduling and actual aligned/Cauchy policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Config {
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
    ) -> io::Result<Self> {
        udp::base_session_config(runtime, transport)?;
        Self::from_policy(runtime, transport.policy()?, channels)
    }
    /// Derive exact budgets from an explicitly Cauchy genuine QUIC transport.
    pub fn for_quic(
        runtime: RuntimeConfig,
        transport: quic::Config,
        channels: u16,
    ) -> io::Result<Self> {
        quic::base_session_config(runtime, transport)?;
        Self::from_policy(runtime, transport.policy()?, channels)
    }
    fn from_policy(
        runtime: RuntimeConfig,
        policy: DatagramPolicy,
        channels: u16,
    ) -> io::Result<Self> {
        let value = Self::derive(runtime, policy, channels, 48)?;
        value.validate(runtime, policy)?;
        Ok(value)
    }
    pub(super) fn derive(
        runtime: RuntimeConfig,
        policy: DatagramPolicy,
        channels: u16,
        envelope_bytes: usize,
    ) -> io::Result<Self> {
        runtime.validate()?;
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
        let value = Self {
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
                    lookahead_records: runtime
                        .queue_packets
                        .checked_mul(2)
                        .ok_or_else(|| invalid("aligned record count overflow"))?,
                    lookahead_bytes: runtime
                        .queue_packets
                        .checked_mul(runtime.max_packet + 98)
                        .ok_or_else(|| invalid("aligned body queue overflow"))?,
                    lookahead_fragments: runtime
                        .queue_packets
                        .checked_mul(2)
                        .and_then(|n| n.checked_mul(fragments))
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
            || self.protocol.receiver.lookahead_records < 2 * runtime.queue_packets
            || self.protocol.receiver.lookahead_bytes
                < runtime.queue_packets * (runtime.max_packet + 98)
            || self.protocol.receiver.lookahead_fragments
                < 2 * runtime.queue_packets * self.protocol.receiver.max_fragments_per_record
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
    Ok(bind_policy(
        base,
        config.protocol.digest().map_err(io::Error::other)?,
        config.pipeline,
        b"l2tunnel/aligned-runtime/v1/common-mux-crc32/control-v1\0",
    ))
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
    bind(udp::base_session_config(runtime, transport)?, config)
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
    let mut carrier = udp::carrier_config(runtime, transport, lane, peer)?;
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
    bind(quic::base_session_config(runtime, transport)?, config)
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
    outbound: Option<mpsc::Sender<Vec<u8>>>,
    feedback: watch::Sender<udp::Feedback>,
    receives: bool,
    admitted: u64,
    delivered: u64,
    peer_delivered: u64,
    next_channel: u16,
}
impl State {
    fn check_retention(&self, runtime: RuntimeConfig) -> io::Result<()> {
        if self.endpoint.status().receiver.native_records > runtime.queue_packets {
            return Err(invalid("aligned peer exceeded native delivery window"));
        }
        Ok(())
    }
    fn control(&mut self, event: udp::ControlEvent, now: Duration) -> io::Result<()> {
        match event {
            udp::ControlEvent::Ack(bytes) => {
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
            udp::ControlEvent::Credit(value) => {
                if value < self.peer_delivered || value > self.admitted {
                    return Err(invalid("aligned native credit beyond admission"));
                }
                self.peer_delivered = value;
                Ok(())
            }
        }
    }
}
pub(super) async fn run_parts<D, C, S, R>(
    mut device: D,
    parts: Vec<DatagramParts<C, S, R>>,
    initiator: bool,
    runtime: RuntimeConfig,
    mut policy: DatagramPolicy,
    selection: Selection,
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
        tasks.spawn(udp::read_control_bound(
            reader,
            index,
            control_tx.clone(),
            policy.control_timeout,
            56,
            policy.control_magic,
        ));
        tasks.spawn(udp::write_control_bound(
            writer,
            changes,
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
            tasks.spawn(udp::write_datagrams(part.sender, rx));
            Some(tx)
        } else {
            None
        };
        states.push(State {
            endpoint: selection.endpoint(context)?,
            outbound,
            feedback,
            receives,
            admitted: 0,
            delivered: 0,
            peer_delivered: 0,
            next_channel: 0,
        });
    }
    drop(control_tx);
    drop(data_tx);
    let mut ticker = interval(runtime.poll_interval);
    ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
    let mut packet = vec![0; l2tunnel_device::READ_BUFFER_BYTES];
    let mut encoded = vec![0; policy.payload_bytes];
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
            Some((lane,event))=control_rx.recv()=>states[lane].control(event,started.elapsed())?,
            Some((lane,bytes))=data_rx.recv()=>{
                let state=&mut states[lane];
                if !state.receives || state.endpoint.inspect_peer(&bytes).map_err(io::Error::other)? == l2tunnel_reliable::RecordKind::Feedback { return Err(invalid("aligned datagram role or kind")); }
                state.endpoint.receive_authenticated(&bytes,started.elapsed()).map_err(io::Error::other)?;
                state.check_retention(runtime)?;
            },
            _=ticker.tick()=>{},
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
                progress |= admit_native(state, &mut pipeline, &mut selected, runtime, started.elapsed())?;
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
                    match device.transmit(frame.bytes) {
                        Ok(()) => {
                            state
                                .endpoint
                                .commit_delivery(if selection.burst_limit() == 0 { now } else { started.elapsed() })
                                .map_err(io::Error::other)?;
                            state.delivered = state
                                .delivered
                                .checked_add(1)
                                .ok_or_else(|| invalid("aligned native counter exhausted"))?;
                            state
                                .feedback
                                .send_modify(|feedback| feedback.credit = state.delivered);
                        }
                        Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                        Err(error) => return Err(error),
                    }
                    state.check_retention(runtime)?;
                }
            }
            if state.outbound.is_some() {
                if selection.burst_limit() == 0 {
                    admit_native(state, &mut pipeline, &mut selected, runtime, now)?;
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
                            permit.send(encoded[..length].to_vec());
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
    runtime: RuntimeConfig,
    now: Duration,
) -> io::Result<bool> {
    if state.endpoint.status().staged_frame
        || state.admitted - state.peer_delivered >= runtime.queue_packets as u64
    {
        return Ok(false);
    }
    if selected.is_none() {
        *selected = pipeline.dequeue().map_err(io::Error::other)?;
    }
    let Some(item) = selected.take() else {
        return Ok(false);
    };
    let next = state
        .admitted
        .checked_add(1)
        .ok_or_else(|| invalid("aligned admission exhausted"))?;
    let channel = u8::try_from(item.metadata.binding.channel)
        .map_err(|_| invalid("aligned channel range"))?;
    match state
        .endpoint
        .enqueue_admitted(protocol::ChannelId(channel), &item.payload, now)
    {
        Ok(()) => {
            state.admitted = next;
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
