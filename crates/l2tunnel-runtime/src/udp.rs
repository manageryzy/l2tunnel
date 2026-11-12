//! Fixed-mode native packets over authenticated UDP with bounded selective repeat.
//! TLS remains the authenticated liveness, recovery-feedback and delivery-credit path.
use super::{Compression, Duplex, RuntimeConfig, invalid, packet_valid};
use l2tunnel_auth::SessionConfig;
use l2tunnel_codec::{
    FRAGMENT_HEADER_BYTES, FragmentConfig, FragmentContext, Fragmenter, MessageId, Reassembler,
    ReassemblyConfig, ReassemblyStatus, SessionId,
};
use l2tunnel_core::{ConfigDigest, Epoch};
use l2tunnel_datagram::{DatagramConfig, KeyContext};
use l2tunnel_device::PacketDevice;
use l2tunnel_fec as fec;
use l2tunnel_recovery::{
    ACK_PACKET_BYTES, ArqConfig, BufferSide, DATA_HEADER_BYTES, EndpointRole, PacketView,
    RecoveryContext, RecoveryEngine, RecoveryError, SelectiveRepeat, inspect_packet,
};
use l2tunnel_reliable::{self as reliable, OutboundBudget, RecordKind, Reliable, ReliableConfig};
use l2tunnel_udp::{
    self as carrier, Carrier, Control, CoverProfile, Direction, KeyGeneration, LaneId, Profile,
    Protection, Traffic, UdpReceiver, UdpSender,
};
use ring::rand::{SecureRandom, SystemRandom};
use std::collections::VecDeque;
use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{mpsc, watch};
use tokio::task::JoinSet;
use tokio::time::{Instant, MissedTickBehavior, interval, timeout};

/// Negotiated ordered recovery; FEC repairs preserve original ARQ/native identities.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecoveryMode {
    /// Existing ordered selective repeat, without coding overhead.
    SelectiveRepeat,
    /// Real systematic/Cauchy block recovery with selective-repeat fallback.
    Cauchy {
        /// Maximum sources in one block, 1..=16 and no larger than either ARQ window.
        sources: usize,
        /// Repairs per full block, 1..=16; partial blocks round the ratio upward.
        repairs: usize,
        /// Positive partial-block age shorter than the initial ARQ RTO.
        flush_after: Duration,
    },
}
/// Finite protocol-record admission allowance, shared by all lanes and control.
/// This fixed pacing policy does not implement congestion control or kernel wire metering.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WireBudget {
    /// Refill period; unused allowance does not accumulate beyond one interval.
    pub interval: Duration,
    /// Maximum emitted UDP records and TLS control frames admitted per interval.
    pub packets: usize,
    /// Maximum charged bytes, including each path's explicit framing allowance.
    pub wire_bytes: usize,
}
/// Fixed resource and authenticated packet policy for an entire link.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Config {
    /// One bidirectional carrier or two independent directional carriers.
    pub duplex: Duplex,
    /// Explicit custom cover; not OpenVPN or QUIC interoperability.
    pub cover: CoverProfile,
    /// Required datagram confidentiality/integrity protection.
    pub protection: Protection,
    /// Complete outer IP packet budget.
    pub path_mtu: usize,
    /// IP/UDP and any additional underlay encapsulation bytes.
    pub outer_overhead_bytes: usize,
    /// Bounded ordered selective-repeat window and retry policy.
    pub arq: ArqConfig,
    /// Fixed recovery mode; switching requires a new authenticated session.
    pub recovery: RecoveryMode,
    /// Common admission allowance including a bounded internal control reservation.
    pub wire_budget: WireBudget,
    /// Bootstrap, control idle and individual socket operation bound.
    pub control_timeout: Duration,
    /// Maximum periodic TLS heartbeat spacing when its writer is available.
    pub heartbeat_interval: Duration,
    /// Maximum lifetime of an incomplete native packet; expiry closes the link.
    pub reassembly_timeout: Duration,
}
impl Config {
    /// Construct finite defaults for a bare IPv4/IPv6 UDP underlay.
    pub fn new(
        duplex: Duplex,
        cover: CoverProfile,
        protection: Protection,
        path_mtu: usize,
        ipv6: bool,
    ) -> io::Result<Self> {
        let mut value = Self {
            duplex,
            cover,
            protection,
            path_mtu,
            outer_overhead_bytes: if ipv6 { 48 } else { 28 },
            arq: ArqConfig::default(),
            recovery: RecoveryMode::SelectiveRepeat,
            wire_budget: WireBudget {
                interval: Duration::from_millis(1),
                packets: 128,
                wire_bytes: 128 * path_mtu.clamp(256, 65_535),
            },
            control_timeout: Duration::from_secs(120),
            heartbeat_interval: Duration::from_secs(1),
            reassembly_timeout: Duration::from_secs(60),
        };
        let maximum = value
            .payload_budget()?
            .checked_sub(DATA_HEADER_BYTES)
            .ok_or_else(|| invalid("UDP MTU cannot hold recovery header"))?;
        value.arq.max_source_bytes = maximum;
        value.arq.send_bytes = maximum * 64;
        value.arq.receive_bytes = maximum * 64;
        value.validate()?;
        Ok(value)
    }
    /// Select recovery and recompute its MTU-limited fragment/source byte budgets.
    /// Other ARQ timing/window settings are retained and validated.
    pub fn with_recovery(mut self, recovery: RecoveryMode) -> io::Result<Self> {
        self.recovery = recovery;
        let overhead = match recovery {
            RecoveryMode::SelectiveRepeat => DATA_HEADER_BYTES,
            RecoveryMode::Cauchy {
                sources, repairs, ..
            } => {
                if !(1..=16).contains(&sources) || !(1..=16).contains(&repairs) {
                    return Err(invalid("Cauchy dimensions outside bounded runtime profile"));
                }
                reliable::ENVELOPE_BYTES + fec::HEADER_BYTES + sources + 2 + DATA_HEADER_BYTES
            }
        };
        self.arq.max_source_bytes = self
            .payload_budget()?
            .checked_sub(overhead)
            .ok_or_else(|| invalid("UDP MTU cannot hold recovery envelope"))?;
        if matches!(recovery, RecoveryMode::Cauchy { .. }) {
            self.arq.max_source_bytes = self
                .arq
                .max_source_bytes
                .min(fec::MAX_SOURCE_BYTES - DATA_HEADER_BYTES);
        }
        self.arq.send_bytes = self
            .arq
            .max_source_bytes
            .checked_mul(self.arq.send_records)
            .ok_or_else(|| invalid("send byte budget overflow"))?;
        self.arq.receive_bytes = self
            .arq
            .max_source_bytes
            .checked_mul(self.arq.receive_records)
            .ok_or_else(|| invalid("receive byte budget overflow"))?;
        self.validate()?;
        Ok(self)
    }
    pub(super) fn reliable(self) -> io::Result<Option<ReliableConfig>> {
        reliable_config(self.arq, self.recovery, self.payload_budget()?)
    }
    fn feedback_bytes(self) -> usize {
        ACK_PACKET_BYTES
            + if self.recovery == RecoveryMode::SelectiveRepeat {
                0
            } else {
                reliable::ENVELOPE_BYTES
            }
    }
    fn control_overhead(self) -> usize {
        // Accounting allowance: application header + two TLS records and two
        // IP/TCP packets with maximum TCP options. Kernel wire behavior is separate.
        8 + 2 * 22 + 2 * (self.outer_overhead_bytes + 12 + 40)
    }
    fn control_reservation(self) -> OutboundBudget {
        let packets = 3 * if self.duplex == Duplex::Full { 1 } else { 2 };
        OutboundBudget {
            packets,
            wire_bytes: packets * (self.control_overhead() + self.feedback_bytes()),
        }
    }
    fn payload_budget(self) -> io::Result<usize> {
        let overhead = DatagramConfig {
            context: KeyContext {
                session: l2tunnel_datagram::SessionId([0; 16]),
                direction: Direction::ClientToServer,
                lane: LaneId(0),
                generation: KeyGeneration(0),
            },
            cover: self.cover,
            protection: self.protection,
            path_mtu: self.path_mtu,
            outer_overhead_bytes: self.outer_overhead_bytes,
            max_payload_bytes: 1,
            max_packets_per_key: 1,
            max_payload_bytes_per_key: 1,
        }
        .wire_overhead();
        self.path_mtu
            .checked_sub(self.outer_overhead_bytes)
            .and_then(|n| n.checked_sub(overhead))
            .filter(|n| *n <= usize::from(u16::MAX))
            .ok_or_else(|| invalid("UDP MTU/header budget"))
    }
    fn validate(self) -> io::Result<()> {
        let payload_budget = self.payload_budget()?;
        if !(256..=65_535).contains(&self.path_mtu)
            || self.outer_overhead_bytes < 28
            || self.arq.max_source_bytes <= FRAGMENT_HEADER_BYTES
            || self
                .arq
                .max_source_bytes
                .checked_add(DATA_HEADER_BYTES)
                .is_none_or(|n| n > payload_budget)
            || self.arq.send_bytes > self.arq.max_source_bytes.saturating_mul(64)
            || self.arq.receive_bytes > self.arq.max_source_bytes.saturating_mul(64)
            || self.control_timeout.is_zero()
            || self.control_timeout > Duration::from_secs(120)
            || self.heartbeat_interval.is_zero()
            || self.heartbeat_interval > self.control_timeout / 3
            || self.reassembly_timeout.is_zero()
            || self.reassembly_timeout > Duration::from_secs(120)
            || self.arq.maximum_rto > Duration::from_secs(30)
            || self.arq.max_retries > 64
        {
            return Err(invalid("invalid bounded UDP runtime configuration"));
        }
        for duration in [
            self.control_timeout,
            self.heartbeat_interval,
            self.reassembly_timeout,
            self.arq.initial_rto,
            self.arq.maximum_rto,
            self.arq.ack_delay,
        ] {
            duration_nanos(duration)?;
        }
        let reserve = self.control_reservation();
        if self.wire_budget.interval.is_zero()
            || self.wire_budget.interval > self.control_timeout / 8
            || self.wire_budget.interval > Duration::from_secs(1)
            || self.wire_budget.packets <= reserve.packets
            || self.wire_budget.packets > 65_536
            || self.wire_budget.wire_bytes < reserve.wire_bytes + self.path_mtu
            || self.wire_budget.wire_bytes > 256 * 1024 * 1024
        {
            return Err(invalid(
                "invalid shared wire allowance or control reservation",
            ));
        }
        self.reliable()?;
        SelectiveRepeat::new(
            self.arq,
            RecoveryContext {
                session: 0,
                epoch: 1,
                role: EndpointRole::Initiator,
            },
        )
        .map_err(io::Error::other)?;
        Ok(())
    }
}
pub(super) fn reliable_config(
    arq: ArqConfig,
    recovery: RecoveryMode,
    payload_budget: usize,
) -> io::Result<Option<ReliableConfig>> {
    let RecoveryMode::Cauchy {
        sources,
        repairs,
        flush_after,
    } = recovery
    else {
        return Ok(None);
    };
    if !(1..=16).contains(&sources) || !(1..=16).contains(&repairs) {
        return Err(invalid("Cauchy dimensions outside bounded runtime profile"));
    }
    let source_bytes = DATA_HEADER_BYTES
        .checked_add(arq.max_source_bytes)
        .filter(|n| *n <= fec::MAX_SOURCE_BYTES)
        .ok_or_else(|| invalid("coded source ceiling"))?;
    let width = source_bytes + 2;
    let symbols = sources + repairs;
    let generations = arq
        .receive_records
        .div_ceil(sources)
        .saturating_add(1)
        .min(64);
    let reservation = (sources * 3 + symbols) * (sources + width) * generations;
    let restored = arq
        .send_records
        .checked_add(sources)
        .filter(|n| *n <= reliable::MAX_RESTORED_PACKETS)
        .ok_or_else(|| invalid("restored count ceiling"))?;
    let value = ReliableConfig {
        arq,
        fec: fec::DecoderConfig {
            block: fec::BlockConfig {
                max_sources: sources,
                max_source_bytes: source_bytes,
                max_packet_bytes: fec::HEADER_BYTES + sources + width,
                max_work_per_symbol: ((sources * 2 + 1) * (sources + width) + 16) as u64,
            },
            max_generations: generations,
            max_symbols_per_generation: symbols,
            max_reserved_bytes: reservation,
            max_lifetime_ticks: ticks(arq.initial_rto)?.max(1),
            generation_window: 128,
        },
        repair_symbols: repairs,
        flush_after,
        max_restored_packets: restored,
        max_restored_bytes: restored * source_bytes,
        outer_overhead_bytes: 0,
    };
    let endpoint = Reliable::new(
        value,
        RecoveryContext {
            session: 0,
            epoch: 1,
            role: EndpointRole::Initiator,
        },
    )
    .map_err(io::Error::other)?;
    if endpoint.max_packet_bytes() > payload_budget {
        return Err(invalid(
            "coded packet exceeds protected UDP payload ceiling",
        ));
    }
    Ok(Some(value))
}

fn duration_nanos(value: Duration) -> io::Result<u64> {
    u64::try_from(value.as_nanos()).map_err(|_| invalid("duration exceeds canonical bound"))
}
/// Explicit physical lane selection; Full permits First only.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Lane {
    /// Full carrier, or client-to-server bulk lane 0 in half mode.
    First,
    /// Server-to-client bulk lane 1, permitted only in half mode.
    Second,
}
fn profile(config: Config, lane: Lane) -> io::Result<Profile> {
    config.validate()?;
    let traffic = match (config.duplex, lane) {
        (Duplex::Full, Lane::First) => Traffic::FullDuplex,
        (Duplex::Half, Lane::First) => Traffic::HalfDuplex {
            sender: Direction::ClientToServer,
        },
        (Duplex::Half, Lane::Second) => Traffic::HalfDuplex {
            sender: Direction::ServerToClient,
        },
        _ => return Err(invalid("full UDP has no second lane")),
    };
    let value = Profile {
        traffic,
        cover: config.cover,
        protection: config.protection,
        lane: LaneId(if lane == Lane::First { 0 } else { 1 }),
        generation: KeyGeneration(0),
        path_mtu: config.path_mtu,
        outer_overhead_bytes: config.outer_overhead_bytes,
        max_payload_bytes: config.payload_budget()?,
        max_packets_per_key: l2tunnel_datagram::MAX_PACKETS_PER_KEY,
        max_payload_bytes_per_key: l2tunnel_datagram::MAX_PAYLOAD_BYTES_PER_KEY,
    };
    value.canonical().map_err(io::Error::other)?;
    Ok(value)
}
/// Canonical initial packet/recovery/queue binding before adding the physical UDP lane.
pub fn base_session_config(runtime: RuntimeConfig, config: Config) -> io::Result<SessionConfig> {
    runtime.validate()?;
    config.validate()?;
    let mut hash = ring::digest::Context::new(&ring::digest::SHA256);
    hash.update(b"l2tunnel/udp-runtime/v2/frame-v1/fragment-v1/arq-v1/reliable-v1\0");
    hash.update(&[
        match runtime.layer {
            l2tunnel_device::PacketLayer::Ethernet => 1,
            l2tunnel_device::PacketLayer::Ip => 2,
        },
        match runtime.compression {
            Compression::None => 0,
            Compression::Lz4IfSmaller => 1,
        },
    ]);
    hash.update(
        &profile(config, Lane::First)?
            .canonical()
            .map_err(io::Error::other)?,
    );
    for number in [
        runtime.max_packet,
        runtime.queue_packets,
        config.arq.max_source_bytes,
        config.arq.send_bytes,
        config.arq.receive_bytes,
        config.arq.send_records,
        config.arq.receive_records,
    ] {
        hash.update(
            &u64::try_from(number)
                .map_err(|_| invalid("configuration integer overflow"))?
                .to_be_bytes(),
        );
    }
    for duration in [
        runtime.poll_interval,
        config.arq.initial_rto,
        config.arq.maximum_rto,
        config.arq.ack_delay,
        config.control_timeout,
        config.heartbeat_interval,
        config.reassembly_timeout,
    ] {
        hash.update(&duration_nanos(duration)?.to_be_bytes());
    }
    hash.update(&config.arq.max_retries.to_be_bytes());
    hash.update(&duration_nanos(config.wire_budget.interval)?.to_be_bytes());
    for number in [config.wire_budget.packets, config.wire_budget.wire_bytes] {
        hash.update(&(number as u64).to_be_bytes());
    }
    if let Some(reliable) = config.reliable()? {
        hash.update(&[1]);
        for number in [
            reliable.fec.block.max_sources,
            reliable.fec.block.max_source_bytes,
            reliable.fec.block.max_packet_bytes,
            reliable.fec.max_generations,
            reliable.fec.max_symbols_per_generation,
            reliable.fec.max_reserved_bytes,
            reliable.repair_symbols,
            reliable.max_restored_packets,
            reliable.max_restored_bytes,
            reliable.outer_overhead_bytes,
        ] {
            hash.update(&(number as u64).to_be_bytes());
        }
        for number in [
            reliable.fec.block.max_work_per_symbol,
            reliable.fec.max_lifetime_ticks,
            reliable.fec.generation_window,
            duration_nanos(reliable.flush_after)?,
        ] {
            hash.update(&number.to_be_bytes());
        }
    } else {
        hash.update(&[0]);
    }
    Ok(SessionConfig {
        layer: runtime.layer,
        digest: ConfigDigest(
            hash.finish()
                .as_ref()
                .try_into()
                .map_err(|_| invalid("digest length"))?,
        ),
    })
}
/// Exact TLS member-authentication binding for the selected lane.
pub fn session_config(
    runtime: RuntimeConfig,
    config: Config,
    lane: Lane,
) -> io::Result<SessionConfig> {
    carrier::session_config(
        base_session_config(runtime, config)?,
        profile(config, lane)?,
    )
    .map_err(io::Error::other)
}
/// Construct the matching fixed-endpoint UDP bootstrap configuration.
pub fn carrier_config(
    runtime: RuntimeConfig,
    config: Config,
    lane: Lane,
    peer: SocketAddr,
) -> io::Result<carrier::Config> {
    if peer.is_ipv6() && config.outer_overhead_bytes < 48 {
        return Err(invalid("IPv6 UDP needs complete outer headers"));
    }
    Ok(carrier::Config {
        base: base_session_config(runtime, config)?,
        profile: profile(config, lane)?,
        peer,
        timeout: config.control_timeout,
    })
}
/// Private shared datagram pump configuration; carrier adapters validate its binding.
#[derive(Clone, Copy)]
pub(super) struct DatagramPolicy {
    pub duplex: Duplex,
    pub arq: ArqConfig,
    pub reliable: Option<ReliableConfig>,
    pub payload_bytes: usize,
    pub data_overhead: usize,
    pub control_overhead: usize,
    pub control_magic: [u8; 4],
    pub wire_budget: WireBudget,
    pub control_timeout: Duration,
    pub heartbeat_interval: Duration,
    pub reassembly_timeout: Duration,
}
impl DatagramPolicy {
    fn feedback_bytes(self) -> usize {
        ACK_PACKET_BYTES
            + if self.reliable.is_some() {
                reliable::ENVELOPE_BYTES
            } else {
                0
            }
    }
    fn control_reservation(self) -> OutboundBudget {
        let packets = 3 * if self.duplex == Duplex::Full { 1 } else { 2 };
        OutboundBudget {
            packets,
            wire_bytes: packets * (self.control_overhead + self.feedback_bytes()),
        }
    }
}
impl Config {
    pub(super) fn policy(self) -> io::Result<DatagramPolicy> {
        Ok(DatagramPolicy {
            duplex: self.duplex,
            arq: self.arq,
            reliable: self.reliable()?,
            payload_bytes: self.payload_budget()?,
            data_overhead: self.path_mtu - self.payload_budget()?,
            control_overhead: self.control_overhead(),
            control_magic: *b"L2UC",
            wire_budget: self.wire_budget,
            control_timeout: self.control_timeout,
            heartbeat_interval: self.heartbeat_interval,
            reassembly_timeout: self.reassembly_timeout,
        })
    }
}
pub(super) trait DatagramSend: Send + 'static {
    fn send(&mut self, bytes: &[u8]) -> impl std::future::Future<Output = io::Result<()>> + Send;
}
pub(super) trait DatagramReceive: Send + 'static {
    fn receive(
        &mut self,
        output: &mut [u8],
    ) -> impl std::future::Future<Output = io::Result<Option<usize>>> + Send;
}
impl DatagramSend for UdpSender {
    async fn send(&mut self, bytes: &[u8]) -> io::Result<()> {
        UdpSender::send(self, bytes)
            .await
            .map(|_| ())
            .map_err(io::Error::other)
    }
}
impl DatagramReceive for UdpReceiver {
    async fn receive(&mut self, output: &mut [u8]) -> io::Result<Option<usize>> {
        match UdpReceiver::receive(self, output).await {
            Ok(carrier::ReceiveEvent::Packet(packet)) => Ok(Some(packet.payload_len)),
            Ok(carrier::ReceiveEvent::Discarded(_)) | Err(carrier::Error::Timeout) => Ok(None),
            Err(error) => Err(io::Error::other(error)),
        }
    }
}
pub(super) struct DatagramParts<C, S, R> {
    pub session: [u8; 16],
    pub control: C,
    pub sender: S,
    pub receiver: R,
}
struct Parts {
    control: Control,
    sender: UdpSender,
    receiver: UdpReceiver,
}
fn checked_parts_bound(
    value: Carrier,
    runtime: RuntimeConfig,
    config: Config,
    lane: Lane,
    base: SessionConfig,
) -> io::Result<Parts> {
    runtime.validate()?;
    if base.layer != runtime.layer {
        return Err(invalid("aligned base native layer mismatch"));
    }
    let (control, sender, receiver) = value.into_parts();
    if control.info().config
        != carrier::session_config(base, profile(config, lane)?).map_err(io::Error::other)?
    {
        return Err(invalid(
            "UDP carrier authentication does not bind runtime/lane",
        ));
    }
    Ok(Parts {
        control,
        sender,
        receiver,
    })
}
pub(super) type BoundParts = (Vec<DatagramParts<Control, UdpSender, UdpReceiver>>, bool);
/// Owned authenticated full or paired-half link; construction performs no device reads.
pub struct Link {
    parts: Vec<Parts>,
    binding: SessionConfig,
    initiator: bool,
}
impl Link {
    /// Validate and retain one full-duplex authenticated UDP carrier.
    pub fn full(value: Carrier, runtime: RuntimeConfig, config: Config) -> io::Result<Self> {
        Self::full_bound(
            value,
            runtime,
            config,
            base_session_config(runtime, config)?,
        )
    }
    pub(super) fn full_bound(
        value: Carrier,
        runtime: RuntimeConfig,
        config: Config,
        base: SessionConfig,
    ) -> io::Result<Self> {
        if config.duplex != Duplex::Full {
            return Err(invalid("full constructor requires full UDP"));
        }
        let parts = checked_parts_bound(value, runtime, config, Lane::First, base)?;
        let initiator = parts.control.info().peer_member.is_none();
        Ok(Self {
            parts: vec![parts],
            binding: base,
            initiator,
        })
    }
    pub(super) fn into_bound_parts(self, expected: SessionConfig) -> io::Result<BoundParts> {
        if self.binding != expected {
            return Err(invalid("aligned runtime binding mismatch"));
        }
        Ok((
            self.parts
                .into_iter()
                .map(|p| DatagramParts {
                    session: p.control.info().session_id,
                    control: p.control,
                    sender: p.sender,
                    receiver: p.receiver,
                })
                .collect(),
            self.initiator,
        ))
    }
}
const PAIR_PREFIX: &[u8; 16] = b"L2U-PAIR-V1\0\0\0\0\0";
async fn pair(
    first: Carrier,
    second: Carrier,
    runtime: RuntimeConfig,
    config: Config,
    initiator: bool,
) -> io::Result<Link> {
    pair_bound(
        first,
        second,
        runtime,
        config,
        base_session_config(runtime, config)?,
        initiator,
    )
    .await
}
pub(super) async fn pair_bound(
    first: Carrier,
    second: Carrier,
    runtime: RuntimeConfig,
    config: Config,
    base: SessionConfig,
    initiator: bool,
) -> io::Result<Link> {
    if config.duplex != Duplex::Half {
        return Err(invalid("pair constructor requires half UDP"));
    }
    let mut first = checked_parts_bound(first, runtime, config, Lane::First, base)?;
    let mut second = checked_parts_bound(second, runtime, config, Lane::Second, base)?;
    let a = first.control.info();
    let b = second.control.info();
    if a.peer_member.is_none() != initiator
        || b.peer_member.is_none() != initiator
        || a.member != b.member
        || a.server != b.server
        || a.session_id == b.session_id
    {
        return Err(invalid("UDP pair identity, role or session mismatch"));
    }
    timeout(config.control_timeout, async {
        let mut challenge = [0; 48];
        if initiator {
            first.control.read_exact(&mut challenge).await?;
            if &challenge[..16] != PAIR_PREFIX {
                return Err(invalid("UDP pair challenge"));
            }
            second.control.write_all(&challenge).await?;
            second.control.flush().await?;
            for control in [&mut first.control, &mut second.control] {
                let mut accepted = [0; 48];
                control.read_exact(&mut accepted).await?;
                if accepted != challenge {
                    return Err(invalid("UDP pair acceptance"));
                }
            }
        } else {
            challenge[..16].copy_from_slice(PAIR_PREFIX);
            SystemRandom::new()
                .fill(&mut challenge[16..])
                .map_err(|_| invalid("UDP pairing randomness"))?;
            first.control.write_all(&challenge).await?;
            first.control.flush().await?;
            let mut echoed = [0; 48];
            second.control.read_exact(&mut echoed).await?;
            if echoed != challenge {
                return Err(invalid("UDP pair proof"));
            }
            for control in [&mut first.control, &mut second.control] {
                control.write_all(&challenge).await?;
                control.flush().await?;
            }
        }
        Ok(())
    })
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "UDP pair timeout"))??;
    Ok(Link {
        parts: vec![first, second],
        binding: base,
        initiator,
    })
}
/// Prove a client's two independently authenticated, directionally fixed UDP lanes.
pub async fn client_pair(
    first: Carrier,
    second: Carrier,
    runtime: RuntimeConfig,
    config: Config,
) -> io::Result<Link> {
    pair(first, second, runtime, config, true).await
}
/// Verify a listener's two independently authenticated, directionally fixed UDP lanes.
pub async fn server_pair(
    first: Carrier,
    second: Carrier,
    runtime: RuntimeConfig,
    config: Config,
) -> io::Result<Link> {
    pair(first, second, runtime, config, false).await
}

pub(super) enum Engine {
    Arq {
        context: RecoveryContext,
        endpoint: Box<SelectiveRepeat>,
    },
    Cauchy(Box<Reliable>),
}
impl Engine {
    #[cfg(test)]
    fn new(config: Config, context: RecoveryContext) -> io::Result<Self> {
        Self::from_policy(config.policy()?, context)
    }
    pub(super) fn from_policy(
        config: DatagramPolicy,
        context: RecoveryContext,
    ) -> io::Result<Self> {
        if let Some(reliable) = config.reliable {
            Ok(Self::Cauchy(Box::new(
                Reliable::new(reliable, context).map_err(io::Error::other)?,
            )))
        } else {
            Ok(Self::Arq {
                context,
                endpoint: Box::new(
                    SelectiveRepeat::new(config.arq, context).map_err(io::Error::other)?,
                ),
            })
        }
    }
    pub(super) fn inspect(&self, packet: &[u8], maximum: usize) -> io::Result<RecordKind> {
        match self {
            Self::Arq { context, .. } => Ok(
                match inspect_packet(packet, *context, maximum).map_err(io::Error::other)? {
                    PacketView::Data { .. } => RecordKind::Source,
                    PacketView::Ack { .. } => RecordKind::Feedback,
                },
            ),
            Self::Cauchy(endpoint) => endpoint.inspect_peer(packet).map_err(io::Error::other),
        }
    }
    pub(super) fn submit(&mut self, bytes: &[u8], now: Duration) -> io::Result<u64> {
        match self {
            Self::Arq { endpoint, .. } => endpoint.submit(bytes, now).map_err(io::Error::other),
            Self::Cauchy(endpoint) => endpoint.submit(bytes, now).map_err(io::Error::other),
        }
    }
    pub(super) fn receive(&mut self, bytes: &[u8], now: Duration) -> io::Result<()> {
        match self {
            Self::Arq { endpoint, .. } => endpoint.receive(bytes, now).map_err(io::Error::other),
            Self::Cauchy(endpoint) => endpoint.receive(bytes, now).map_err(io::Error::other),
        }
    }
    pub(super) fn delivered(&mut self, output: &mut [u8]) -> io::Result<Option<(u64, usize)>> {
        match self {
            Self::Arq { endpoint, .. } => endpoint.poll_delivered(output).map_err(io::Error::other),
            Self::Cauchy(endpoint) => endpoint.poll_delivered(output).map_err(io::Error::other),
        }
    }
    pub(super) fn poll(
        &mut self,
        feedback: bool,
        now: Duration,
        output: &mut [u8],
        budget: &mut OutboundBudget,
    ) -> io::Result<Option<usize>> {
        match self {
            Self::Cauchy(endpoint) => if feedback {
                endpoint.poll_feedback(now, output, budget)
            } else {
                endpoint.poll_data(now, output, budget)
            }
            .map_err(io::Error::other),
            Self::Arq { endpoint, .. } => {
                let required = if feedback {
                    ACK_PACKET_BYTES
                } else {
                    endpoint.max_packet_bytes()
                };
                if budget.packets == 0 || budget.wire_bytes < required {
                    return Ok(None);
                }
                let length = if feedback {
                    endpoint.poll_feedback(now, output)
                } else {
                    endpoint.poll_source(now, output)
                }
                .map_err(io::Error::other)?;
                if let Some(length) = length {
                    budget.packets -= 1;
                    budget.wire_bytes -= length;
                }
                Ok(length)
            }
        }
    }
}
pub(super) fn pressure(error: &io::Error, side: BufferSide) -> bool {
    let Some(inner) = error.get_ref() else {
        return false;
    };
    if let Some(error) = inner.downcast_ref::<RecoveryError>() {
        return matches!(error, RecoveryError::SequenceWindow)
            || matches!(error, RecoveryError::Capacity(found) if *found == side);
    }
    if let Some(error) = inner.downcast_ref::<reliable::Error>() {
        return (side == BufferSide::Receive && *error == reliable::Error::RestoredCapacity)
            || matches!(error, reliable::Error::Arq(RecoveryError::SequenceWindow))
            || matches!(error, reliable::Error::Arq(RecoveryError::Capacity(found)) if *found == side);
    }
    false
}
#[derive(Clone, Copy)]
struct Ledger {
    limits: WireBudget,
    remaining: OutboundBudget,
    reservation: OutboundBudget,
    reserved: OutboundBudget,
    next: Duration,
}
impl Ledger {
    fn new(config: DatagramPolicy) -> Self {
        let total = OutboundBudget {
            packets: config.wire_budget.packets,
            wire_bytes: config.wire_budget.wire_bytes,
        };
        Self {
            limits: config.wire_budget,
            remaining: total,
            reservation: config.control_reservation(),
            reserved: config.control_reservation(),
            next: config.wire_budget.interval,
        }
    }
    fn refresh(&mut self, now: Duration) -> io::Result<()> {
        if now >= self.next {
            self.remaining = OutboundBudget {
                packets: self.limits.packets,
                wire_bytes: self.limits.wire_bytes,
            };
            self.reserved = self.reservation;
            self.next = now
                .checked_add(self.limits.interval)
                .ok_or_else(|| invalid("wire interval exhausted"))?;
        }
        Ok(())
    }
    fn available(&self, control: bool) -> OutboundBudget {
        if control {
            self.remaining
        } else {
            OutboundBudget {
                packets: self.remaining.packets.saturating_sub(self.reserved.packets),
                wire_bytes: self
                    .remaining
                    .wire_bytes
                    .saturating_sub(self.reserved.wire_bytes),
            }
        }
    }
    fn debit(&mut self, control: bool, bytes: usize) -> io::Result<()> {
        let available = self.available(control);
        if available.packets == 0 || available.wire_bytes < bytes {
            return Err(invalid("wire allowance overdraw"));
        }
        self.remaining.packets -= 1;
        self.remaining.wire_bytes -= bytes;
        if control {
            self.reserved.packets = self.reserved.packets.saturating_sub(1);
            self.reserved.wire_bytes = self.reserved.wire_bytes.saturating_sub(bytes);
        }
        Ok(())
    }
}
#[derive(Clone)]
pub(super) struct SharedBudget {
    ledger: Arc<Mutex<Ledger>>,
    started: Instant,
    data_overhead: usize,
    control_overhead: usize,
}
impl SharedBudget {
    #[cfg(test)]
    fn new(config: Config, started: Instant) -> Self {
        // Legacy tests supply validated Config. Preserve their construction API.
        let control_overhead = config.control_overhead();
        let data_overhead = config
            .path_mtu
            .saturating_sub(config.payload_budget().unwrap_or(0));
        let policy = DatagramPolicy {
            duplex: config.duplex,
            arq: config.arq,
            reliable: None,
            payload_bytes: 0,
            data_overhead,
            control_overhead,
            control_magic: *b"L2UC",
            wire_budget: config.wire_budget,
            control_timeout: config.control_timeout,
            heartbeat_interval: config.heartbeat_interval,
            reassembly_timeout: config.reassembly_timeout,
        };
        let mut ledger = Ledger::new(policy);
        ledger.reservation = config.control_reservation();
        ledger.reserved = ledger.reservation;
        Self {
            ledger: Arc::new(Mutex::new(ledger)),
            started,
            data_overhead,
            control_overhead,
        }
    }
    pub(super) fn from_policy(config: DatagramPolicy, started: Instant) -> Self {
        Self {
            ledger: Arc::new(Mutex::new(Ledger::new(config))),
            started,
            data_overhead: config.data_overhead,
            control_overhead: config.control_overhead,
        }
    }
    fn poll(
        &self,
        control: bool,
        now: Duration,
        endpoint: &mut Engine,
        output: &mut [u8],
    ) -> io::Result<Option<usize>> {
        self.poll_with(control, now, output, |output, allowance| {
            endpoint.poll(control, now, output, allowance)
        })
    }
    pub(super) fn poll_with<F>(
        &self,
        control: bool,
        now: Duration,
        output: &mut [u8],
        poll: F,
    ) -> io::Result<Option<usize>>
    where
        F: FnOnce(&mut [u8], &mut OutboundBudget) -> io::Result<Option<usize>>,
    {
        let mut ledger = self
            .ledger
            .lock()
            .map_err(|_| invalid("wire ledger poisoned"))?;
        ledger.refresh(now)?;
        let overhead = if control {
            self.control_overhead
        } else {
            self.data_overhead
        };
        let available = ledger.available(control);
        let mut allowance = OutboundBudget {
            packets: available.packets,
            wire_bytes: available.wire_bytes.saturating_sub(overhead),
        };
        let before = allowance;
        let result = poll(output, &mut allowance)?;
        if let Some(length) = result {
            if before.packets.checked_sub(allowance.packets) != Some(1)
                || before.wire_bytes.checked_sub(allowance.wire_bytes) != Some(length)
            {
                return Err(invalid("recovery emission allowance mismatch"));
            }
            ledger.debit(control, length + overhead)?;
        } else if before != allowance {
            return Err(invalid("recovery charged a missing emission"));
        }
        Ok(result)
    }
    async fn control(&self, body_bytes: usize) -> io::Result<()> {
        let charge = self
            .control_overhead
            .checked_add(body_bytes)
            .ok_or_else(|| invalid("control allowance overflow"))?;
        loop {
            let deadline = {
                let mut ledger = self
                    .ledger
                    .lock()
                    .map_err(|_| invalid("wire ledger poisoned"))?;
                ledger.refresh(self.started.elapsed())?;
                let available = ledger.available(true);
                if available.packets != 0 && available.wire_bytes >= charge {
                    ledger.debit(true, charge)?;
                    return Ok(());
                }
                ledger.next
            };
            tokio::time::sleep_until(self.started + deadline).await;
        }
    }
}
#[derive(Clone, Default)]
pub(super) struct Feedback {
    pub ack: Option<Vec<u8>>,
    pub credit: u64,
}
pub(super) enum ControlEvent {
    Ack(Vec<u8>),
    Credit(u64),
}
pub(super) async fn read_control_bound(
    mut reader: impl AsyncRead + Unpin,
    lane: usize,
    events: mpsc::Sender<(usize, ControlEvent)>,
    duration: Duration,
    feedback_bytes: usize,
    magic: [u8; 4],
) -> io::Result<()> {
    loop {
        let event = timeout(duration, async {
            let mut header = [0; 8];
            reader.read_exact(&mut header).await?;
            if header[..4] != magic || header[4] != 1 {
                return Err(invalid("UDP control header"));
            }
            let length = usize::from(u16::from_be_bytes([header[6], header[7]]));
            match (header[5], length) {
                (1, 0) => Ok(None),
                (2, length) if length == feedback_bytes => {
                    let mut bytes = vec![0; feedback_bytes];
                    reader.read_exact(&mut bytes).await?;
                    Ok(Some(ControlEvent::Ack(bytes)))
                }
                (3, 8) => {
                    let mut bytes = [0; 8];
                    reader.read_exact(&mut bytes).await?;
                    Ok(Some(ControlEvent::Credit(u64::from_be_bytes(bytes))))
                }
                _ => Err(invalid("UDP control kind or length")),
            }
        })
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "UDP control read deadline"))??;
        if let Some(event) = event {
            events
                .send((lane, event))
                .await
                .map_err(|_| invalid("UDP control consumer closed"))?;
        }
    }
}
async fn write_control_frame_bound(
    writer: &mut (impl AsyncWrite + Unpin),
    kind: u8,
    body: &[u8],
    magic: [u8; 4],
) -> io::Result<()> {
    let length = u16::try_from(body.len()).map_err(|_| invalid("UDP control length"))?;
    let mut header = *b"L2UC\x01\0\0\0";
    header[..4].copy_from_slice(&magic);
    header[5] = kind;
    header[6..].copy_from_slice(&length.to_be_bytes());
    writer.write_all(&header).await?;
    writer.write_all(body).await?;
    writer.flush().await
}
pub(super) async fn write_control_bound(
    mut writer: impl AsyncWrite + Unpin,
    mut changes: watch::Receiver<Feedback>,
    config: DatagramPolicy,
    budget: SharedBudget,
) -> io::Result<()> {
    let mut heartbeat = interval(config.heartbeat_interval);
    heartbeat.set_missed_tick_behavior(MissedTickBehavior::Skip);
    let mut previous = Feedback::default();
    loop {
        tokio::select! {
            changed = changes.changed() => changed.map_err(|_| invalid("UDP feedback owner closed"))?,
            _ = heartbeat.tick() => {},
        }
        let latest = changes.borrow_and_update().clone();
        timeout(config.control_timeout, async {
            if latest.ack != previous.ack
                && let Some(ack) = &latest.ack
            {
                write_control_frame_bound(&mut writer, 2, ack, config.control_magic).await?;
            }
            if latest.credit != previous.credit {
                budget.control(8).await?;
                write_control_frame_bound(
                    &mut writer,
                    3,
                    &latest.credit.to_be_bytes(),
                    config.control_magic,
                )
                .await?;
            }
            budget.control(0).await?;
            write_control_frame_bound(&mut writer, 1, &[], config.control_magic).await
        })
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "UDP control writer deadline"))??;
        previous = latest;
    }
}
#[cfg(test)]
async fn read_control(
    reader: impl AsyncRead + Unpin,
    lane: usize,
    events: mpsc::Sender<(usize, ControlEvent)>,
    duration: Duration,
    feedback_bytes: usize,
) -> io::Result<()> {
    read_control_bound(reader, lane, events, duration, feedback_bytes, *b"L2UC").await
}
#[cfg(test)]
async fn write_control_frame(
    writer: &mut (impl AsyncWrite + Unpin),
    kind: u8,
    body: &[u8],
) -> io::Result<()> {
    write_control_frame_bound(writer, kind, body, *b"L2UC").await
}
#[cfg(test)]
async fn write_control(
    writer: impl AsyncWrite + Unpin,
    changes: watch::Receiver<Feedback>,
    config: Config,
    budget: SharedBudget,
) -> io::Result<()> {
    write_control_bound(writer, changes, config.policy()?, budget).await
}
pub(super) async fn read_datagrams(
    mut receiver: impl DatagramReceive,
    maximum: usize,
    lane: usize,
    events: mpsc::Sender<(usize, Vec<u8>)>,
) -> io::Result<()> {
    let mut buffer = vec![0; maximum];
    loop {
        match receiver.receive(&mut buffer).await? {
            Some(length) if length <= buffer.len() => events
                .send((lane, buffer[..length].to_vec()))
                .await
                .map_err(|_| invalid("datagram consumer closed"))?,
            Some(_) => return Err(invalid("datagram adapter exceeded buffer")),
            None => tokio::task::yield_now().await,
        }
    }
}
pub(super) async fn write_datagrams(
    mut sender: impl DatagramSend,
    mut packets: mpsc::Receiver<Vec<u8>>,
) -> io::Result<()> {
    while let Some(bytes) = packets.recv().await {
        sender.send(&bytes).await?;
    }
    Err(invalid("datagram producer closed"))
}
struct State {
    engine: Engine,
    fragmenter: Fragmenter,
    reassembly: Reassembler,
    fragments: VecDeque<Vec<u8>>,
    native: VecDeque<Vec<u8>>,
    outbound: Option<mpsc::Sender<Vec<u8>>>,
    feedback: watch::Sender<Feedback>,
    receives: bool,
    admitted: u64,
    received: u64,
    delivered: u64,
    peer_delivered: u64,
}
impl State {
    fn control(
        &mut self,
        event: ControlEvent,
        now: Duration,
        config: DatagramPolicy,
    ) -> io::Result<()> {
        match event {
            ControlEvent::Ack(bytes) => {
                if self.engine.inspect(&bytes, config.arq.max_source_bytes)? != RecordKind::Feedback
                {
                    return Err(invalid("non-feedback on UDP control path"));
                }
                self.engine.receive(&bytes, now)?;
            }
            ControlEvent::Credit(value) => {
                if value < self.peer_delivered || value > self.admitted {
                    return Err(invalid(
                        "UDP native delivery credit exceeds admitted frames or regresses",
                    ));
                }
                self.peer_delivered = value;
            }
        }
        Ok(())
    }
    fn data(&mut self, bytes: &[u8], now: Duration, config: DatagramPolicy) -> io::Result<()> {
        if !self.receives
            || self.engine.inspect(bytes, config.arq.max_source_bytes)? == RecordKind::Feedback
        {
            return Err(invalid("non-data or disabled UDP receive lane"));
        }
        match self.engine.receive(bytes, now) {
            Ok(()) => Ok(()),
            Err(error) if pressure(&error, BufferSide::Receive) => Ok(()),
            Err(error) => Err(error),
        }
    }
}
fn ticks(now: Duration) -> io::Result<u64> {
    u64::try_from(now.as_millis()).map_err(|_| invalid("runtime clock exhausted"))
}
fn increment(value: &mut u64) -> io::Result<()> {
    *value = value
        .checked_add(1)
        .ok_or_else(|| invalid("UDP runtime counter exhausted"))?;
    Ok(())
}
/// Run fixed-mode reliable native packets, retaining authenticated TLS control.
/// Hot reload is unsupported: create a new authenticated session for a new profile.
/// EOF, malformed authenticated input, retry/credit/reassembly failure are explicit errors.
pub async fn run<D: PacketDevice<Error = io::Error>>(
    device: D,
    link: Link,
    runtime: RuntimeConfig,
    config: Config,
) -> io::Result<()> {
    if link.binding != base_session_config(runtime, config)? || device.layer() != runtime.layer {
        return Err(invalid(
            "UDP runtime/device differs from authenticated configuration",
        ));
    }
    let parts = link
        .parts
        .into_iter()
        .map(|p| DatagramParts {
            session: p.control.info().session_id,
            control: p.control,
            sender: p.sender,
            receiver: p.receiver,
        })
        .collect();
    run_datagrams(device, parts, link.initiator, runtime, config.policy()?).await
}
pub(super) async fn run_datagrams<D, C, S, R>(
    mut device: D,
    parts: Vec<DatagramParts<C, S, R>>,
    initiator: bool,
    runtime: RuntimeConfig,
    config: DatagramPolicy,
) -> io::Result<()>
where
    D: PacketDevice<Error = io::Error>,
    C: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    S: DatagramSend,
    R: DatagramReceive,
{
    let codec = runtime.codec()?;
    let maximum = codec.max_encoded_len();
    let chunk = config.arq.max_source_bytes - FRAGMENT_HEADER_BYTES;
    let max_fragments =
        u16::try_from(maximum.div_ceil(chunk)).map_err(|_| invalid("UDP fragment count"))?;
    let (control_tx, mut control_rx) = mpsc::channel(8);
    let (data_tx, mut data_rx) = mpsc::channel(config.arq.receive_records * parts.len());
    let started = Instant::now();
    let budget = SharedBudget::from_policy(config, started);
    let mut tasks = JoinSet::new();
    let mut states = Vec::new();
    for (index, parts) in parts.into_iter().enumerate() {
        let session = parts.session;
        let context = RecoveryContext {
            session: u128::from_be_bytes(session),
            epoch: 1,
            role: if initiator {
                EndpointRole::Initiator
            } else {
                EndpointRole::Responder
            },
        };
        let fragment_context = FragmentContext {
            session: SessionId(u64::from_be_bytes(
                session[..8]
                    .try_into()
                    .map_err(|_| invalid("session length"))?,
            )),
            epoch: Epoch(1),
        };
        let sends = config.duplex == Duplex::Full || (index == 0) == initiator;
        let receives = config.duplex == Duplex::Full || !sends;
        let (reader, writer) = tokio::io::split(parts.control);
        let (feedback, changes) = watch::channel(Feedback::default());
        tasks.spawn(read_control_bound(
            reader,
            index,
            control_tx.clone(),
            config.control_timeout,
            config.feedback_bytes(),
            config.control_magic,
        ));
        tasks.spawn(write_control_bound(writer, changes, config, budget.clone()));
        if receives {
            tasks.spawn(read_datagrams(
                parts.receiver,
                config.payload_bytes,
                index,
                data_tx.clone(),
            ));
        }
        let outbound = if sends {
            let (tx, rx) = mpsc::channel(1);
            tasks.spawn(write_datagrams(parts.sender, rx));
            Some(tx)
        } else {
            None
        };
        states.push(State {
            engine: Engine::from_policy(config, context)?,
            fragmenter: Fragmenter::new(
                fragment_context,
                FragmentConfig {
                    path_mtu: config.arq.max_source_bytes,
                    outer_overhead_bytes: 0,
                    max_message_bytes: maximum,
                    max_fragments,
                },
                MessageId(0),
            )
            .map_err(io::Error::other)?,
            reassembly: Reassembler::new(
                fragment_context,
                ReassemblyConfig {
                    max_message_bytes: maximum,
                    max_messages: 1,
                    max_fragment_payload_bytes: u16::try_from(chunk)
                        .map_err(|_| invalid("fragment payload bound"))?,
                    max_fragments_per_message: max_fragments,
                    max_total_fragments: usize::from(max_fragments),
                    max_reserved_bytes: maximum,
                    max_lifetime_ticks: ticks(config.reassembly_timeout)?.max(1),
                    replay_window: 64,
                },
            )
            .map_err(io::Error::other)?,
            fragments: VecDeque::new(),
            native: VecDeque::new(),
            outbound,
            feedback,
            receives,
            admitted: 0,
            received: 0,
            delivered: 0,
            peer_delivered: 0,
        });
    }
    drop(control_tx);
    drop(data_tx);
    let mut ticker = interval(runtime.poll_interval);
    ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
    // Native adapters require a full maximum-plus-one sentinel to detect truncation.
    let mut packet = vec![0; l2tunnel_device::READ_BUFFER_BYTES];
    let mut source = vec![0; config.arq.max_source_bytes];
    let mut record = vec![0; maximum];
    let mut encoded = vec![0; config.payload_bytes];
    loop {
        tokio::select! {
            Some(result) = tasks.join_next() => return match result {
                Ok(Err(error)) => Err(error),
                Err(error) => Err(io::Error::other(error)),
                Ok(Ok(())) => Err(invalid("UDP task ended unexpectedly")),
            },
            Some((lane, event)) = control_rx.recv() => states[lane].control(event, started.elapsed(), config)?,
            Some((lane, bytes)) = data_rx.recv() => states[lane].data(&bytes, started.elapsed(), config)?,
            _ = ticker.tick() => {},
        }
        let now = started.elapsed();
        for state in &mut states {
            if !state
                .reassembly
                .expire(ticks(now)?)
                .map_err(io::Error::other)?
                .is_empty()
            {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "UDP native packet reassembly expired",
                ));
            }
            while let Some(bytes) = state.native.front() {
                match device.transmit(bytes) {
                    Ok(()) => {
                        state.native.pop_front();
                        increment(&mut state.delivered)?;
                        state
                            .feedback
                            .send_modify(|feedback| feedback.credit = state.delivered);
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                    Err(error) => return Err(error),
                }
            }
            while state.native.len() < runtime.queue_packets {
                let Some((_, length)) = state.engine.delivered(&mut source)? else {
                    break;
                };
                if let ReassemblyStatus::Complete { message, length } = state
                    .reassembly
                    .accept(&source[..length], ticks(now)?, &mut record)
                    .map_err(io::Error::other)?
                {
                    if message.0 != state.received
                        || state.received - state.delivered >= runtime.queue_packets as u64
                        || (runtime.compression == Compression::None && record.get(4) != Some(&0))
                    {
                        return Err(invalid(
                            "UDP native sequence, delivery window or codec mismatch",
                        ));
                    }
                    let native = codec
                        .decode_vec(&record[..length])
                        .map_err(io::Error::other)?;
                    if !packet_valid(runtime.layer, &native) {
                        return Err(invalid("invalid UDP native packet"));
                    }
                    state.native.push_back(native);
                    increment(&mut state.received)?;
                }
            }
            if let Some(outbound) = &state.outbound {
                if state.fragments.is_empty()
                    && state.admitted - state.peer_delivered < runtime.queue_packets as u64
                    && let Some(length) = device.receive(&mut packet)?
                {
                    if length > runtime.max_packet
                        || !packet_valid(runtime.layer, &packet[..length])
                    {
                        return Err(invalid("device supplied invalid UDP native packet"));
                    }
                    let bytes = codec
                        .encode_vec(&packet[..length])
                        .map_err(io::Error::other)?;
                    state.fragments = state
                        .fragmenter
                        .fragment(&bytes)
                        .map_err(io::Error::other)?
                        .fragments
                        .into();
                    increment(&mut state.admitted)?;
                }
                while let Some(bytes) = state.fragments.front() {
                    match state.engine.submit(bytes, now) {
                        Ok(_) => {
                            state.fragments.pop_front();
                        }
                        Err(error) if pressure(&error, BufferSide::Send) => break,
                        Err(error) => return Err(error),
                    }
                }
                match outbound.try_reserve() {
                    Ok(permit) => {
                        if let Some(length) =
                            budget.poll(false, now, &mut state.engine, &mut encoded)?
                        {
                            permit.send(encoded[..length].to_vec());
                        }
                    }
                    Err(mpsc::error::TrySendError::Full(_)) => {}
                    Err(mpsc::error::TrySendError::Closed(_)) => {
                        return Err(invalid("UDP writer closed"));
                    }
                }
            }
            if let Some(length) = budget.poll(true, now, &mut state.engine, &mut encoded)? {
                state
                    .feedback
                    .send_modify(|feedback| feedback.ack = Some(encoded[..length].to_vec()));
            }
        }
    }
}

#[cfg(test)]
#[path = "udp_tests.rs"]
mod tests;
