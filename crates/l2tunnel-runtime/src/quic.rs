//! Fixed native packet runtime over genuine UDP-only QUIC, independent of custom covers.
//! The bounded recovery/device pump is shared with UDP; QUIC owns outer congestion control.
use super::udp::{self, DatagramParts, DatagramPolicy, DatagramReceive, DatagramSend};
pub use super::udp::{Lane, RecoveryMode, WireBudget};
use super::{Compression, Duplex, RuntimeConfig, invalid};
use l2tunnel_auth::{Direction, SessionConfig, SessionInfo};
use l2tunnel_core::ConfigDigest;
use l2tunnel_device::PacketDevice;
use l2tunnel_quic::{
    self as carrier, AuthenticatedConnection, Control, DatagramReceiver, DatagramSender, Profile,
    Traffic,
};
use l2tunnel_recovery::{
    ArqConfig, DATA_HEADER_BYTES, EndpointRole, RecoveryContext, SelectiveRepeat,
};
use ring::rand::{SecureRandom, SystemRandom};
use std::io;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::timeout;

/// Fixed authenticated genuine QUIC runtime configuration; hot reload is unsupported.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Config {
    /// One full carrier or two independently authenticated directional carriers.
    pub duplex: Duplex,
    /// Required opaque configured ALPN, exactly 16 nonzero-as-a-whole bytes.
    pub application_id: [u8; 16],
    /// Complete IP packet ceiling; QUIC needs >=1228 IPv4 / >=1248 IPv6.
    pub path_mtu: usize,
    /// Complete underlay IP/UDP and optional extra encapsulation allowance.
    pub outer_overhead_bytes: usize,
    /// Bounded ordered application recovery policy.
    pub arq: ArqConfig,
    /// Existing selective repeat or real Cauchy with ARQ fallback.
    pub recovery: RecoveryMode,
    /// One finite allowance shared by both lanes, data, repairs and control.
    pub wire_budget: WireBudget,
    /// Handshake pairing, idle control and individual operation deadline.
    pub control_timeout: Duration,
    /// Bounded control heartbeat spacing when writable.
    pub heartbeat_interval: Duration,
    /// Maximum incomplete native packet lifetime.
    pub reassembly_timeout: Duration,
    /// Carrier queue byte allowance expressed in maximum record units.
    pub queued_datagrams: usize,
    /// Reliable control send/receive byte window.
    pub control_window_bytes: usize,
}
impl Config {
    /// Construct finite defaults without opening sockets or devices.
    pub fn new(
        duplex: Duplex,
        application_id: [u8; 16],
        path_mtu: usize,
        ipv6: bool,
    ) -> io::Result<Self> {
        let value = Self {
            duplex,
            application_id,
            path_mtu,
            outer_overhead_bytes: if ipv6 { 48 } else { 28 },
            arq: ArqConfig::default(),
            recovery: RecoveryMode::SelectiveRepeat,
            wire_budget: WireBudget {
                interval: Duration::from_millis(1),
                packets: 128,
                wire_bytes: 128 * path_mtu.clamp(1228, 65535),
            },
            control_timeout: Duration::from_secs(120),
            heartbeat_interval: Duration::from_secs(1),
            reassembly_timeout: Duration::from_secs(60),
            queued_datagrams: 32,
            control_window_bytes: 65536,
        };
        value.with_recovery(RecoveryMode::SelectiveRepeat)
    }
    /// Select existing recovery and recompute the exact MTU-limited source allowance.
    pub fn with_recovery(mut self, recovery: RecoveryMode) -> io::Result<Self> {
        self.recovery = recovery;
        let overhead = match recovery {
            RecoveryMode::SelectiveRepeat => DATA_HEADER_BYTES,
            RecoveryMode::Cauchy {
                sources, repairs, ..
            } => {
                if !(1..=16).contains(&sources) || !(1..=16).contains(&repairs) {
                    return Err(invalid("QUIC Cauchy dimensions"));
                }
                l2tunnel_reliable::ENVELOPE_BYTES
                    + l2tunnel_fec::HEADER_BYTES
                    + sources
                    + 2
                    + DATA_HEADER_BYTES
            }
        };
        self.arq.max_source_bytes = self
            .payload_bytes()?
            .checked_sub(overhead)
            .ok_or_else(|| invalid("QUIC recovery MTU"))?;
        if matches!(recovery, RecoveryMode::Cauchy { .. }) {
            self.arq.max_source_bytes = self
                .arq
                .max_source_bytes
                .min(l2tunnel_fec::MAX_SOURCE_BYTES - DATA_HEADER_BYTES);
        }
        self.arq.send_bytes = self
            .arq
            .max_source_bytes
            .checked_mul(self.arq.send_records)
            .ok_or_else(|| invalid("QUIC send capacity overflow"))?;
        self.arq.receive_bytes = self
            .arq
            .max_source_bytes
            .checked_mul(self.arq.receive_records)
            .ok_or_else(|| invalid("QUIC receive capacity overflow"))?;
        self.validate()?;
        Ok(self)
    }
    fn payload_bytes(self) -> io::Result<usize> {
        if self.path_mtu > 65535 || self.outer_overhead_bytes < 28 {
            return Err(invalid("QUIC path MTU or underlay allowance"));
        }
        self.path_mtu
            .checked_sub(self.outer_overhead_bytes)
            .filter(|n| *n >= 1200)
            .and_then(|n| n.checked_sub(128 + 48))
            .ok_or_else(|| invalid("QUIC needs 1200-byte UDP payload minimum"))
    }
    pub(super) fn policy(self) -> io::Result<DatagramPolicy> {
        Ok(DatagramPolicy {
            duplex: self.duplex,
            arq: self.arq,
            reliable: udp::reliable_config(self.arq, self.recovery, self.payload_bytes()?)?,
            payload_bytes: self.payload_bytes()?,
            data_overhead: self.path_mtu - self.payload_bytes()?,
            control_overhead: 8 + 2 * (self.outer_overhead_bytes + 128),
            control_magic: *b"L2QF",
            wire_budget: self.wire_budget,
            control_timeout: self.control_timeout,
            heartbeat_interval: self.heartbeat_interval,
            reassembly_timeout: self.reassembly_timeout,
        })
    }
    /// Validate exact finite carrier, recovery, timer and common admission budgets.
    pub fn validate(self) -> io::Result<()> {
        let payload = self.payload_bytes()?;
        if self.arq.max_source_bytes <= l2tunnel_codec::FRAGMENT_HEADER_BYTES
            || self
                .arq
                .max_source_bytes
                .checked_add(DATA_HEADER_BYTES)
                .is_none_or(|n| n > payload)
            || self.arq.send_bytes > self.arq.max_source_bytes.saturating_mul(64)
            || self.arq.receive_bytes > self.arq.max_source_bytes.saturating_mul(64)
            || self.arq.maximum_rto > Duration::from_secs(30)
            || self.arq.max_retries > 64
            || self.control_timeout.is_zero()
            || self.control_timeout > Duration::from_secs(120)
            || self.heartbeat_interval.is_zero()
            || self.heartbeat_interval > self.control_timeout / 3
            || self.reassembly_timeout.is_zero()
            || self.reassembly_timeout > Duration::from_secs(120)
        {
            return Err(invalid("QUIC bounded recovery or timer configuration"));
        }
        SelectiveRepeat::new(
            self.arq,
            RecoveryContext {
                session: 0,
                epoch: 1,
                role: EndpointRole::Initiator,
            },
        )
        .map_err(io::Error::other)?;
        self.profile_unchecked(Lane::First)?
            .validate()
            .map_err(io::Error::other)?;
        let policy = self.policy()?;
        let count = 3 * if self.duplex == Duplex::Full { 1 } else { 2 };
        let ack = l2tunnel_recovery::ACK_PACKET_BYTES
            + if policy.reliable.is_some() {
                l2tunnel_reliable::ENVELOPE_BYTES
            } else {
                0
            };
        let reserve = count * (policy.control_overhead + ack);
        if self.wire_budget.interval.is_zero()
            || self.wire_budget.interval > self.control_timeout / 8
            || self.wire_budget.interval > Duration::from_secs(1)
            || self.wire_budget.packets <= count
            || self.wire_budget.packets > 65536
            || self.wire_budget.wire_bytes < reserve + self.path_mtu
            || self.wire_budget.wire_bytes > 256 * 1024 * 1024
        {
            return Err(invalid("QUIC shared wire allowance or control reservation"));
        }
        Ok(())
    }
    fn profile_unchecked(self, lane: Lane) -> io::Result<Profile> {
        let traffic = match (self.duplex, lane) {
            (Duplex::Full, Lane::First) => Traffic::FullDuplex,
            (Duplex::Half, Lane::First) => Traffic::HalfDuplex {
                sender: Direction::ClientToServer,
            },
            (Duplex::Half, Lane::Second) => Traffic::HalfDuplex {
                sender: Direction::ServerToClient,
            },
            _ => return Err(invalid("full QUIC has no second lane")),
        };
        Ok(Profile {
            application_id: self.application_id,
            traffic,
            lane: if lane == Lane::First { 0 } else { 1 },
            max_datagram_bytes: self.payload_bytes()?,
            queued_datagrams: self.queued_datagrams,
            control_window_bytes: self.control_window_bytes,
            udp_payload_ceiling: u16::try_from(self.path_mtu - self.outer_overhead_bytes)
                .map_err(|_| invalid("QUIC UDP ceiling"))?,
            idle_timeout: self.control_timeout,
            io_timeout: self.control_timeout,
        })
    }
}
/// Exact profile supplied to the genuine QUIC endpoint's TLS constructors.
pub fn carrier_profile(config: Config, lane: Lane) -> io::Result<Profile> {
    config.validate()?;
    config.profile_unchecked(lane)
}
/// Canonical native/recovery binding passed to the genuine QUIC endpoint before authentication.
pub(crate) fn transport_session_config(
    runtime: RuntimeConfig,
    config: Config,
) -> io::Result<SessionConfig> {
    runtime.validate()?;
    config.validate()?;
    let mut hash = ring::digest::Context::new(&ring::digest::SHA256);
    hash.update(b"l2tunnel/quic-runtime/v1/frame-v1/fragment-v1/arq-v1/reliable-v1\0");
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
    let profile = carrier::session_config(
        SessionConfig {
            layer: runtime.layer,
            digest: ConfigDigest([0; 32]),
        },
        carrier_profile(config, Lane::First)?,
    )
    .map_err(io::Error::other)?;
    hash.update(&profile.digest.0);
    for number in [
        runtime.max_packet,
        runtime.queue_packets,
        config.path_mtu,
        config.outer_overhead_bytes,
        config.arq.max_source_bytes,
        config.arq.send_bytes,
        config.arq.receive_bytes,
        config.arq.send_records,
        config.arq.receive_records,
        config.wire_budget.packets,
        config.wire_budget.wire_bytes,
    ] {
        hash.update(
            &u64::try_from(number)
                .map_err(|_| invalid("QUIC config integer overflow"))?
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
        config.wire_budget.interval,
    ] {
        hash.update(
            &u64::try_from(duration.as_nanos())
                .map_err(|_| invalid("QUIC config duration overflow"))?
                .to_be_bytes(),
        );
    }
    hash.update(&config.arq.max_retries.to_be_bytes());
    if let RecoveryMode::Cauchy {
        sources,
        repairs,
        flush_after,
    } = config.recovery
    {
        hash.update(&[1]);
        hash.update(&(sources as u64).to_be_bytes());
        hash.update(&(repairs as u64).to_be_bytes());
        hash.update(
            &u64::try_from(flush_after.as_nanos())
                .map_err(|_| invalid("QUIC FEC duration overflow"))?
                .to_be_bytes(),
        );
    } else {
        hash.update(&[0]);
    }
    let mut digest = [0; 32];
    digest.copy_from_slice(hash.finish().as_ref());
    Ok(SessionConfig {
        layer: runtime.layer,
        digest: ConfigDigest(digest),
    })
}
/// Bind mandatory native-byte delivery policy independently of recovery/local queues.
pub fn base_session_config(
    runtime: RuntimeConfig,
    config: Config,
    delivery: crate::managed::DeliveryConfig,
) -> io::Result<SessionConfig> {
    let transport = transport_session_config(runtime, config)?;
    crate::packet_delivery::validate(runtime, delivery, config.arq.max_source_bytes)?;
    let mut hash = ring::digest::Context::new(&ring::digest::SHA256);
    hash.update(b"l2tunnel/quic-runtime/v2/delivery-window-v1\0");
    hash.update(&transport.digest.0);
    hash.update(&delivery.canonical()?);
    Ok(SessionConfig {
        layer: transport.layer,
        digest: ConfigDigest(
            hash.finish()
                .as_ref()
                .try_into()
                .map_err(|_| invalid("delivery digest length"))?,
        ),
    })
}
/// Final expected auth binding; the endpoint applies this profile to the supplied base once.
pub fn session_config(
    runtime: RuntimeConfig,
    config: Config,
    lane: Lane,
    delivery: crate::managed::DeliveryConfig,
) -> io::Result<SessionConfig> {
    carrier::session_config(
        base_session_config(runtime, config, delivery)?,
        carrier_profile(config, lane)?,
    )
    .map_err(io::Error::other)
}
struct Parts {
    info: SessionInfo,
    control: Control,
    sender: DatagramSender,
    receiver: DatagramReceiver,
}
#[cfg(test)]
fn checked_parts(
    value: AuthenticatedConnection,
    runtime: RuntimeConfig,
    config: Config,
    lane: Lane,
    delivery: crate::managed::DeliveryConfig,
) -> io::Result<Parts> {
    checked_parts_bound(
        value,
        runtime,
        config,
        lane,
        base_session_config(runtime, config, delivery)?,
    )
}
fn checked_parts_bound(
    value: AuthenticatedConnection,
    runtime: RuntimeConfig,
    config: Config,
    lane: Lane,
    base: SessionConfig,
) -> io::Result<Parts> {
    runtime.validate()?;
    if base.layer != runtime.layer {
        return Err(invalid("aligned base native layer mismatch"));
    }
    let info = *value.info();
    if info.config
        != carrier::session_config(base, carrier_profile(config, lane)?)
            .map_err(io::Error::other)?
    {
        return Err(invalid("QUIC authenticated runtime/lane mismatch"));
    }
    let (control, sender, receiver) = value.into_parts();
    Ok(Parts {
        info,
        control,
        sender,
        receiver,
    })
}
pub(super) type BoundParts = (
    Vec<DatagramParts<Control, DatagramSender, DatagramReceiver>>,
    bool,
);
/// Validated full or paired-half QUIC link; construction never reads a native device.
pub struct Link {
    parts: Vec<Parts>,
    binding: SessionConfig,
    initiator: bool,
}
impl Link {
    /// Retain one actual full-duplex genuine QUIC authenticated connection.
    pub fn full(
        value: AuthenticatedConnection,
        runtime: RuntimeConfig,
        config: Config,
        delivery: crate::managed::DeliveryConfig,
    ) -> io::Result<Self> {
        Self::full_bound(
            value,
            runtime,
            config,
            base_session_config(runtime, config, delivery)?,
        )
    }
    pub(super) fn full_bound(
        value: AuthenticatedConnection,
        runtime: RuntimeConfig,
        config: Config,
        base: SessionConfig,
    ) -> io::Result<Self> {
        if config.duplex != Duplex::Full {
            return Err(invalid("full constructor requires full QUIC"));
        }
        let parts = checked_parts_bound(value, runtime, config, Lane::First, base)?;
        let initiator = parts.info.peer_member.is_none();
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
                    session: p.info.session_id,
                    control: p.control,
                    sender: p.sender,
                    receiver: p.receiver,
                })
                .collect(),
            self.initiator,
        ))
    }
}
const PAIR_PREFIX: &[u8; 16] = b"L2Q-PAIR-V1\0\0\0\0\0";
async fn pair(
    first: AuthenticatedConnection,
    second: AuthenticatedConnection,
    runtime: RuntimeConfig,
    config: Config,
    initiator: bool,
    delivery: crate::managed::DeliveryConfig,
) -> io::Result<Link> {
    pair_bound(
        first,
        second,
        runtime,
        config,
        base_session_config(runtime, config, delivery)?,
        initiator,
    )
    .await
}
pub(super) async fn pair_bound(
    first: AuthenticatedConnection,
    second: AuthenticatedConnection,
    runtime: RuntimeConfig,
    config: Config,
    base: SessionConfig,
    initiator: bool,
) -> io::Result<Link> {
    if config.duplex != Duplex::Half {
        return Err(invalid("pair constructor requires half QUIC"));
    }
    let mut first = checked_parts_bound(first, runtime, config, Lane::First, base)?;
    let mut second = checked_parts_bound(second, runtime, config, Lane::Second, base)?;
    let a = first.info;
    let b = second.info;
    if a.peer_member.is_none() != initiator
        || b.peer_member.is_none() != initiator
        || a.member != b.member
        || a.server != b.server
        || a.session_id == b.session_id
    {
        return Err(invalid("QUIC pair identity, role or session mismatch"));
    }
    timeout(config.control_timeout, async {
        let mut challenge = [0; 48];
        if initiator {
            first.control.read_exact(&mut challenge).await?;
            if &challenge[..16] != PAIR_PREFIX {
                return Err(invalid("QUIC pair challenge"));
            }
            second.control.write_all(&challenge).await?;
            second.control.flush().await?;
            for control in [&mut first.control, &mut second.control] {
                let mut accepted = [0; 48];
                control.read_exact(&mut accepted).await?;
                if accepted != challenge {
                    return Err(invalid("QUIC pair acceptance"));
                }
            }
        } else {
            challenge[..16].copy_from_slice(PAIR_PREFIX);
            SystemRandom::new()
                .fill(&mut challenge[16..])
                .map_err(|_| invalid("QUIC pairing randomness"))?;
            first.control.write_all(&challenge).await?;
            first.control.flush().await?;
            let mut echoed = [0; 48];
            second.control.read_exact(&mut echoed).await?;
            if echoed != challenge {
                return Err(invalid("QUIC pair proof"));
            }
            for control in [&mut first.control, &mut second.control] {
                control.write_all(&challenge).await?;
                control.flush().await?;
            }
        }
        Ok(())
    })
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "QUIC pairing deadline"))??;
    Ok(Link {
        parts: vec![first, second],
        binding: base,
        initiator,
    })
}
/// Prove a client's two separately authenticated directional QUIC connections.
pub async fn client_pair(
    first: AuthenticatedConnection,
    second: AuthenticatedConnection,
    runtime: RuntimeConfig,
    config: Config,
    delivery: crate::managed::DeliveryConfig,
) -> io::Result<Link> {
    pair(first, second, runtime, config, true, delivery).await
}
/// Verify a server's two separately authenticated directional QUIC connections.
pub async fn server_pair(
    first: AuthenticatedConnection,
    second: AuthenticatedConnection,
    runtime: RuntimeConfig,
    config: Config,
    delivery: crate::managed::DeliveryConfig,
) -> io::Result<Link> {
    pair(first, second, runtime, config, false, delivery).await
}
impl DatagramSend for DatagramSender {
    async fn send(&mut self, bytes: &[u8]) -> io::Result<()> {
        DatagramSender::send(self, bytes)
            .await
            .map(|_| ())
            .map_err(io::Error::other)
    }
}
impl DatagramReceive for DatagramReceiver {
    async fn receive(&mut self, output: &mut [u8]) -> io::Result<Option<usize>> {
        match DatagramReceiver::receive(self, output).await {
            Ok(carrier::Received::Packet { len, .. }) => Ok(Some(len)),
            Ok(carrier::Received::Discarded) | Err(carrier::Error::TimedOut) => Ok(None),
            Err(error) => Err(io::Error::other(error)),
        }
    }
}
/// Run fixed-mode native forwarding with mandatory bounded control liveness.
/// EOF, malformed input, retry exhaustion and expired reassembly are errors; hot reload is unsupported.
pub async fn run<D: PacketDevice<Error = io::Error>>(
    device: D,
    link: Link,
    runtime: RuntimeConfig,
    config: Config,
    delivery: crate::managed::DeliveryConfig,
) -> io::Result<()> {
    run_observed(device, link, runtime, config, None, delivery).await
}
/// Run with bounded read-only observations of local, recovery and delivery domains.
pub async fn run_observed<D: PacketDevice<Error = io::Error>>(
    device: D,
    link: Link,
    runtime: RuntimeConfig,
    config: Config,
    observer: Option<crate::udp::Reporter>,
    delivery: crate::managed::DeliveryConfig,
) -> io::Result<()> {
    if link.binding != base_session_config(runtime, config, delivery)?
        || device.layer() != runtime.layer
    {
        return Err(invalid("QUIC runtime/device differs from authentication"));
    }
    let parts = link
        .parts
        .into_iter()
        .map(|p| DatagramParts {
            session: p.info.session_id,
            control: p.control,
            sender: p.sender,
            receiver: p.receiver,
        })
        .collect();
    let mut policy = config.policy()?;
    policy.control_magic = *b"L2Q2";
    udp::run_datagrams(
        device,
        parts,
        link.initiator,
        runtime,
        policy,
        observer,
        delivery,
    )
    .await
}
#[cfg(test)]
#[path = "quic_tests.rs"]
mod tests;
