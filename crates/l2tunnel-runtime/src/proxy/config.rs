use super::*;
use std::net::{IpAddr, SocketAddr};

/// One canonical network prefix; host bits must be zero.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct IpPrefix {
    address: IpAddr,
    bits: u8,
}
impl IpPrefix {
    /// Reject excessive lengths and noncanonical host bits before policy admission.
    pub fn new(address: IpAddr, bits: u8) -> io::Result<Self> {
        let value = Self { address, bits };
        if bits > if address.is_ipv4() { 32 } else { 128 } || !value.canonical() {
            return Err(invalid("noncanonical proxy prefix"));
        }
        Ok(value)
    }
    /// Canonical prefix address.
    pub fn address(self) -> IpAddr {
        self.address
    }
    /// Prefix bit count.
    pub fn bits(self) -> u8 {
        self.bits
    }
    fn number(address: IpAddr) -> u128 {
        match address {
            IpAddr::V4(ip) => u128::from(u32::from(ip)),
            IpAddr::V6(ip) => u128::from(ip),
        }
    }
    fn mask(self) -> u128 {
        let width = if self.address.is_ipv4() { 32 } else { 128 };
        if self.bits == 0 {
            0
        } else {
            u128::MAX << (width - self.bits)
        }
    }
    fn canonical(self) -> bool {
        Self::number(self.address) & !self.mask() == 0
    }
    fn contains(self, address: IpAddr) -> bool {
        address.is_ipv4() == self.address.is_ipv4()
            && Self::number(address) & self.mask() == Self::number(self.address)
    }
}
/// Inclusive original destination-port interval.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct PortRange {
    /// Nonzero first port.
    pub first: u16,
    /// Last port, at least first.
    pub last: u16,
}
/// Explicit original source/destination ownership permission.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct RouteRule {
    /// Allowed original source network.
    pub source: IpPrefix,
    /// Allowed original destination network.
    pub destination: IpPrefix,
    /// Allowed original destination ports.
    pub ports: PortRange,
}
/// Bounded canonical allowlist; this authorizes proxying, not transparent routing.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RoutePolicy {
    rules: Vec<RouteRule>,
}
impl RoutePolicy {
    /// Sort/deduplicate at most 256 rules; empty denies every new proxy flow.
    pub fn new(mut rules: Vec<RouteRule>) -> io::Result<Self> {
        if rules.len() > 256
            || rules.iter().any(|r| {
                r.source.address.is_ipv4() != r.destination.address.is_ipv4()
                    || r.ports.first == 0
                    || r.ports.first > r.ports.last
            })
        {
            return Err(invalid("invalid bounded proxy routes"));
        }
        rules.sort_unstable();
        rules.dedup();
        rules.shrink_to_fit();
        Ok(Self { rules })
    }
    /// Exact canonical rules bound by authentication.
    pub fn rules(&self) -> &[RouteRule] {
        &self.rules
    }
    /// Permission for the original oriented tuple, checked independently at both peers.
    pub fn permits(&self, source: SocketAddr, destination: SocketAddr) -> bool {
        self.rules.iter().any(|r| {
            r.source.contains(source.ip())
                && r.destination.contains(destination.ip())
                && (r.ports.first..=r.ports.last).contains(&destination.port())
        })
    }
}
/// Maintained native stack policy; ephemeral seeds and original tuples are runtime-owned.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativePolicy {
    /// Complete native IP ceiling.
    pub mtu: usize,
    /// Per-leg maintained send-ring capacity.
    pub send_bytes: usize,
    /// Per-leg maintained receive-ring capacity.
    pub receive_bytes: usize,
    /// Each native ingress/egress ring's packet count.
    pub packet_slots: usize,
    /// Maintained delayed-ACK hint in milliseconds.
    pub ack_delay_millis: u64,
    /// Maintained native keepalive interval.
    pub keepalive_millis: u64,
    /// Maintained native idle timeout.
    pub idle_timeout_millis: u64,
    /// Explicit close behavior; defaults preserve maintained TCP.
    pub time_wait_reset_policy: proxy::TimeWaitResetPolicy,
}
/// Fixed original-byte relay policy and lifetime owner caps.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RelayPolicy {
    /// Lifetime allocated proxy owners, including refusals and tombstones.
    pub max_flows: usize,
    /// Lifetime transparent tuple/address decisions.
    pub max_policies: usize,
    /// Largest original byte segment in a relay record.
    pub max_record_bytes: usize,
    /// Hard original-byte/record ceiling per flow.
    pub maximum: Window,
    /// Fixed buffer-backed future target per flow.
    pub initial: Window,
    /// Absolute Open/Ready/Commit reservation timeout.
    pub admission_timeout: Duration,
}
/// One common user-record scheduler per direction, including proxy control records.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MuxPolicy {
    /// Common CRC32-affinity channel count in 1..=256.
    pub channels: u16,
    /// Lifetime flow bindings; no live or silent idle eviction.
    pub max_flow_bindings: usize,
    /// Complete framed bytes retained by the common arbiter.
    pub queue_bytes: usize,
    /// Common packet count, including one-byte/control records.
    pub queue_records: usize,
    /// Shared-arbiter bytes per flow.
    pub per_flow_bytes: usize,
    /// Shared-arbiter records per flow.
    pub per_flow_records: usize,
    /// Base byte quantum for existing DRR.
    pub quantum_bytes: u32,
    /// Explicit untrusted-DSCP multipliers; every value is in 1..=16.
    pub dscp_weights: [u16; 64],
}
/// Distinct transparent delivery reservation and native scheduler storage.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeliveryPolicy {
    /// Original transparent IP bytes admitted but not yet written remotely.
    pub transparent_bytes: usize,
    /// Original transparent IP packet reservation.
    pub transparent_packets: usize,
    /// Complete native packets retained by the common native arbiter.
    pub native_queue_bytes: usize,
    /// Complete native packet slots, including proxy SYN/ACK/FIN packets.
    pub native_queue_packets: usize,
}
/// Absolute service deadlines; shutdown is never renewed by later phases.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Timeouts {
    /// Mutual Start/Ready on every retained direction.
    pub startup: Duration,
    /// Maximum interval without authenticated peer liveness.
    pub control_idle: Duration,
    /// One bound from first local/validated peer Quiesce through all TLS joins.
    pub shutdown: Duration,
}
/// Complete immutable profile; client is the sole proxy originator.
#[derive(Clone, Debug)]
pub struct Config {
    /// TUN-only native limits; compression must be None.
    pub runtime: RuntimeConfig,
    /// One full or two separately authenticated directional bulk lanes.
    pub duplex: Duplex,
    /// Maintained TCP ring/timer policy.
    pub native: NativePolicy,
    /// Original-byte credit and owner limits.
    pub relay: RelayPolicy,
    /// Common user admission/QoS.
    pub mux: MuxPolicy,
    /// Native delivery and receive-storage limits.
    pub delivery: DeliveryPolicy,
    /// Exact source/destination ownership allowlist.
    pub routes: RoutePolicy,
    /// Startup, liveness and entire shutdown bounds.
    pub timeouts: Timeouts,
    /// At most this many maintained owners advanced by each Table::poll call.
    /// Other metadata scans visit the separately bounded maximum of 64 owners.
    pub flow_poll_work: usize,
    /// Maintained TCP work steps per visited owner.
    pub stack_poll_work: usize,
    /// Per-physical-direction control send/decode service budget per second.
    /// Buffered arrivals are backpressured, never granted extra processing slots.
    pub control_rate: usize,
}
/// Conservative explicit storage bound, excluding maintained TLS/allocator overhead.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MemoryBound {
    /// Configured payload/scratch/ring reservation.
    pub payload_bytes: usize,
    /// Finite queue/table metadata entries.
    pub metadata_slots: usize,
    /// Actual selected Common Bridge metadata owner, including its bounded unit
    /// receipt bitmap. This is separate from payload credit and counted once;
    /// Arc bookkeeping, TLS and allocator overhead remain outside this extent.
    pub common_bridge_metadata_bytes: usize,
}
impl Config {
    /// Conservative finite initial policy; no route is implicitly authorized.
    pub fn new(runtime: RuntimeConfig, duplex: Duplex, routes: RoutePolicy) -> io::Result<Self> {
        let max = runtime
            .max_packet
            .checked_add(128)
            .ok_or_else(|| invalid("proxy size overflow"))?;
        let bytes = max
            .checked_mul(runtime.queue_packets)
            .ok_or_else(|| invalid("proxy queue overflow"))?;
        let value = Self {
            runtime,
            duplex,
            routes,
            native: NativePolicy {
                mtu: runtime.max_packet,
                send_bytes: 65536,
                receive_bytes: 65536,
                packet_slots: 16,
                ack_delay_millis: 10,
                keepalive_millis: 1000,
                idle_timeout_millis: 30000,
                time_wait_reset_policy: proxy::TimeWaitResetPolicy::Maintained,
            },
            relay: RelayPolicy {
                max_flows: 16,
                max_policies: 1024,
                max_record_bytes: runtime.max_packet.min(4096),
                maximum: Window {
                    bytes: 65536,
                    records: 64,
                },
                initial: Window {
                    bytes: 16384,
                    records: 16,
                },
                admission_timeout: Duration::from_secs(10),
            },
            mux: MuxPolicy {
                channels: 16,
                max_flow_bindings: 4096,
                queue_bytes: bytes,
                queue_records: runtime.queue_packets,
                per_flow_bytes: bytes,
                per_flow_records: runtime.queue_packets,
                quantum_bytes: 1600,
                dscp_weights: [1; 64],
            },
            delivery: DeliveryPolicy {
                transparent_bytes: runtime
                    .max_packet
                    .checked_mul(runtime.queue_packets)
                    .ok_or_else(|| invalid("proxy native overflow"))?,
                transparent_packets: runtime.queue_packets,
                native_queue_bytes: bytes,
                native_queue_packets: runtime.queue_packets,
            },
            timeouts: Timeouts {
                startup: Duration::from_secs(10),
                control_idle: Duration::from_secs(30),
                shutdown: Duration::from_secs(120),
            },
            flow_poll_work: 16,
            stack_poll_work: 16,
            control_rate: 256,
        };
        value.validate()?;
        Ok(value)
    }
    pub(super) fn table(&self, logical: [u8; 16], originator: bool, seed: u64) -> session::Config {
        session::Config {
            session: logical,
            epoch: 1,
            role: if originator {
                session::Role::Originator
            } else {
                session::Role::Acceptor
            },
            max_flows: self.relay.max_flows,
            max_policies: self.relay.max_policies,
            native: proxy::TcpIpConfig {
                local: ([10, 0, 0, 1], 1).into(),
                peer: ([10, 0, 0, 2], 2).into(),
                mtu: self.native.mtu,
                send_bytes: self.native.send_bytes,
                receive_bytes: self.native.receive_bytes,
                packet_slots: self.native.packet_slots,
                random_seed: seed,
                ack_delay_millis: self.native.ack_delay_millis,
                keepalive_millis: self.native.keepalive_millis,
                idle_timeout_millis: self.native.idle_timeout_millis,
            },
            max_record_bytes: self.relay.max_record_bytes,
            maximum: self.relay.maximum,
            initial: self.relay.initial,
            admission_timeout_ms: self.relay.admission_timeout.as_millis() as u64,
            time_wait_reset_policy: self.native.time_wait_reset_policy,
        }
    }
    pub(super) fn parse(&self) -> l2tunnel_packet::ParseLimits {
        l2tunnel_packet::ParseLimits {
            max_packet_bytes: self.runtime.max_packet,
            ..Default::default()
        }
    }
    pub(super) fn classify(&self, bytes: &[u8]) -> io::Result<Classification> {
        l2tunnel_packet::classify(PacketLayer::Ip, bytes, self.parse()).map_err(io::Error::other)
    }
    pub(super) fn max_user(&self) -> io::Result<usize> {
        self.runtime
            .max_packet
            .max(
                self.relay
                    .max_record_bytes
                    .checked_add(56)
                    .ok_or_else(|| invalid("proxy record overflow"))?,
            )
            .max(142)
            .checked_add(24)
            .ok_or_else(|| invalid("proxy envelope overflow"))
    }
    /// Reject excessive or unsupported policy before native reads or large allocation.
    pub fn validate(&self) -> io::Result<MemoryBound> {
        self.runtime.validate()?;
        if self.max_user()? > super::super::wire::MAX_PAYLOAD {
            return Err(invalid("proxy record ceiling"));
        }
        // Supported local service reservations, never renewed deadlines or a
        // bound on transport buffering/RTT, native work or user-data drainage.
        // Start/Ready reserve two slots. In normal operation each direction
        // owns at most one Credit, Ping and Pong; four send/receive service
        // edges reserve 3 slots each for heartbeat, plus two actor polls.
        // Shutdown adds the four-slot coalescing wait to all four service
        // edges for those three normal controls and Quiesce/Barrier/latest
        // Credit/Ack (4 + 4 * 7 slots), plus four actor polls. This conservative
        // supported-minimum policy does not assume overlap of those waits.
        let slot = super::transport::control_interval(self.control_rate)?;
        let minimum = |slots, polls| {
            slot.checked_mul(slots)
                .and_then(|d| {
                    self.runtime
                        .poll_interval
                        .checked_mul(polls)
                        .and_then(|scheduling| d.checked_add(scheduling))
                })
                .ok_or_else(|| invalid("proxy control pacing feasibility overflow"))
        };
        if self.timeouts.startup < minimum(2, 0)?
            || self.timeouts.control_idle < minimum(12, 2)?
            || self.timeouts.shutdown < minimum(32, 4)?
        {
            return Err(invalid(
                "proxy deadlines cannot service configured control rate",
            ));
        }
        let durations = [
            self.timeouts.startup,
            self.timeouts.control_idle,
            self.timeouts.shutdown,
            self.relay.admission_timeout,
        ];
        if self.runtime.layer != PacketLayer::Ip
            || self.runtime.compression != Compression::None
            || self.native.mtu != self.runtime.max_packet
            || self.native.mtu < 1280
            || durations.iter().any(|d| {
                *d < Duration::from_millis(10)
                    || *d > Duration::from_secs(120)
                    || d.subsec_nanos() % 1_000_000 != 0
            })
            || !(1..=64).contains(&self.flow_poll_work)
            || !(1..=1024).contains(&self.stack_poll_work)
            || !(16..=1024).contains(&self.control_rate)
            || !(1..=256).contains(&self.mux.channels)
            || !(self.relay.max_flows..=4096).contains(&self.mux.max_flow_bindings)
            || self.mux.dscp_weights.iter().any(|w| !(1..=16).contains(w))
            || self.mux.quantum_bytes == 0
            || self.mux.queue_records == 0
            || self.mux.queue_records > 1024
            || self.mux.per_flow_records == 0
            || self.mux.per_flow_records > self.mux.queue_records
            || self.mux.per_flow_bytes > self.mux.queue_bytes
            || self.mux.per_flow_bytes < self.max_user()? + super::record::FRAME_OVERHEAD
            || self.delivery.transparent_packets == 0
            || self.delivery.transparent_packets > 1024
            || self.delivery.transparent_bytes < self.runtime.max_packet
            || self.delivery.native_queue_packets < self.delivery.transparent_packets
            || self.delivery.native_queue_packets > 2048
            || self.delivery.native_queue_bytes < self.delivery.transparent_bytes
            || self.delivery.native_queue_bytes < self.runtime.max_packet
            || self.max_user()? > super::super::wire::MAX_PAYLOAD
        {
            return Err(invalid("invalid bounded proxy runtime policy"));
        }
        self.table([1; 16], true, 1)
            .validate()
            .map_err(io::Error::other)?;
        let n = &self.native;
        let r = &self.relay;
        let bound = n
            .send_bytes
            .checked_add(n.receive_bytes)
            .and_then(|v| v.checked_add(r.maximum.bytes as usize))
            .and_then(|v| v.checked_add(r.max_record_bytes + 56))
            .and_then(|v| v.checked_add((2 * n.packet_slots + 1) * n.mtu))
            .and_then(|v| v.checked_mul(r.max_flows))
            .and_then(|v| v.checked_add(self.mux.queue_bytes.checked_mul(2)?))
            .and_then(|v| v.checked_add(self.delivery.native_queue_bytes))
            .and_then(|v| v.checked_add(self.delivery.transparent_bytes))
            .and_then(|v| {
                v.checked_add(
                    (self.runtime.queue_packets + 8)
                        * (self.max_user().ok()? + super::record::FRAME_OVERHEAD),
                )
            })
            .and_then(|v| v.checked_add(65536 + 4 * self.runtime.max_packet))
            .filter(|v| *v <= 268_435_456)
            .ok_or_else(|| invalid("proxy aggregate memory bound"))?;
        Ok(MemoryBound {
            payload_bytes: bound,
            common_bridge_metadata_bytes: {
                #[cfg(unix)]
                {
                    super::common_bridge::Bridge::metadata_bytes()
                }
                #[cfg(not(unix))]
                {
                    0
                }
            },
            metadata_slots: self.mux.max_flow_bindings * 4
                + self.mux.queue_records * 4
                + self.relay.max_policies
                + self.relay.max_flows * 8
                + self.delivery.native_queue_packets * 2,
        })
    }
}
/// Exact immutable profile for both authenticated roles and every retained lane.
pub fn session_config(config: &Config) -> io::Result<SessionConfig> {
    config.validate()?;
    let mut h = ring::digest::Context::new(&ring::digest::SHA256);
    h.update(b"l2tunnel/tun-tcp-proxy-runtime/v2/common-record-union/fixed-credit/local-system-random-u64-v1\0");
    h.update(&[
        1,
        u8::from(config.duplex == Duplex::Half),
        u8::from(
            config.native.time_wait_reset_policy == proxy::TimeWaitResetPolicy::IgnoreInTimeWait,
        ),
    ]);
    let n = &config.native;
    let r = &config.relay;
    let m = &config.mux;
    let d = &config.delivery;
    for value in [
        config.runtime.max_packet as u64,
        config.runtime.queue_packets as u64,
        config
            .runtime
            .poll_interval
            .as_nanos()
            .try_into()
            .map_err(io::Error::other)?,
        n.mtu as u64,
        n.send_bytes as u64,
        n.receive_bytes as u64,
        n.packet_slots as u64,
        n.ack_delay_millis,
        n.keepalive_millis,
        n.idle_timeout_millis,
        r.max_flows as u64,
        r.max_policies as u64,
        r.max_record_bytes as u64,
        r.maximum.bytes,
        r.maximum.records,
        r.initial.bytes,
        r.initial.records,
        r.admission_timeout.as_millis() as u64,
        m.channels as u64,
        m.max_flow_bindings as u64,
        m.queue_bytes as u64,
        m.queue_records as u64,
        m.per_flow_bytes as u64,
        m.per_flow_records as u64,
        m.quantum_bytes as u64,
        d.transparent_bytes as u64,
        d.transparent_packets as u64,
        d.native_queue_bytes as u64,
        d.native_queue_packets as u64,
        config.timeouts.startup.as_millis() as u64,
        config.timeouts.control_idle.as_millis() as u64,
        config.timeouts.shutdown.as_millis() as u64,
        config.flow_poll_work as u64,
        config.stack_poll_work as u64,
        config.control_rate as u64,
        config.routes.rules.len() as u64,
    ] {
        h.update(&value.to_be_bytes());
    }
    for weight in m.dscp_weights {
        h.update(&weight.to_be_bytes());
    }
    for rule in &config.routes.rules {
        for prefix in [rule.source, rule.destination] {
            h.update(&[u8::from(prefix.address.is_ipv6()), prefix.bits]);
            h.update(&IpPrefix::number(prefix.address).to_be_bytes());
        }
        h.update(&rule.ports.first.to_be_bytes());
        h.update(&rule.ports.last.to_be_bytes());
    }
    let mut bytes = [0; 32];
    bytes.copy_from_slice(h.finish().as_ref());
    Ok(SessionConfig {
        layer: PacketLayer::Ip,
        digest: ConfigDigest(bytes),
    })
}
