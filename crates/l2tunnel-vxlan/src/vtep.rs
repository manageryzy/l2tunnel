//! Pure, bounded VXLAN VTEP switching, FDB learning, BUM accounting and
//! path-MTU policy (`docs/overlay-and-carriers.md`, `docs/modules/vxlan.md`).
//!
//! No sockets, Tokio, clocks or OS handles live here: time is injected as
//! monotonic microseconds (`now_micros: u64`), and peer transport endpoints
//! are represented by typed `PeerId` values owned by the runtime adapter.

use crate::{Error, HEADER_LEN, MAX_FRAME, Vni, decode};
use std::collections::{BTreeMap, BTreeSet};

/// Outer IPv4 header length without options.
pub const IPV4_HEADER_BYTES: usize = 20;
/// Outer IPv6 base header length.
pub const IPV6_HEADER_BYTES: usize = 40;
/// Outer UDP header length.
pub const UDP_HEADER_BYTES: usize = 8;
/// Minimum Ethernet header length (dst MAC + src MAC + EtherType).
pub const ETHERNET_HEADER_BYTES: usize = 14;
/// 802.1Q VLAN tag length in bytes.
pub const VLAN_TAG_BYTES: usize = 4;
/// RFC 7348 standard VXLAN UDP destination port.
pub const STANDARD_VXLAN_PORT: u16 = 4789;
/// EtherType for IEEE 802.1Q VLAN-tagged frames.
pub const ETHERTYPE_VLAN_8021Q: u16 = 0x8100;
/// EtherType for IEEE 802.1ad QinQ service tags.
pub const ETHERTYPE_QINQ: u16 = 0x88a8;
/// Upper bound on peer allowlist entries per domain.
pub const MAX_PEERS_PER_DOMAIN: usize = 256;
/// Upper bound on total FDB entries across all domains.
pub const MAX_TOTAL_FDB_ENTRIES: usize = 65_536;
/// Upper bound on configured domains in one VTEP instance.
pub const MAX_DOMAINS: usize = 4096;

/// Explicitly distinct VXLAN operating modes (`VX-01`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VxlanMode {
    /// Carry nested VXLAN UDP packets opaquely as ordinary user IP/Ethernet bytes.
    PassThrough,
    /// Terminate VXLAN on an explicit Ethernet VTEP boundary.
    Vtep,
}

/// Logical attachment layer verified against [`VxlanMode`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AttachmentLayer {
    /// L3 IP packet device (TUN).
    Ip,
    /// L2 Ethernet frame device (TAP / VTEP).
    Ethernet,
}

/// Capabilities exposed by a validated VXLAN mode and layer pair (`VX-01`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VxlanCapabilities {
    /// Selected operating mode.
    pub mode: VxlanMode,
    /// Attachment layer.
    pub layer: AttachmentLayer,
    /// Whether this attachment performs VTEP encapsulation/decapsulation.
    pub vtep_termination: bool,
    /// Whether nested VXLAN packets pass through opaquely.
    pub nested_passthrough: bool,
}

/// Validate outer UDP checksum semantics for RFC 7348 VXLAN (`VX-03`).
///
/// - Over IPv4, checksum `0` (RFC 7348 §5 default) and nonzero valid checksums
///   are both permitted.
/// - Over IPv6 (RFC 8200 / RFC 6935), checksum `0` is rejected unless
///   `allow_ipv6_zero_checksum` is explicitly enabled by operator policy.
pub const fn validate_outer_udp_checksum(
    outer_ipv6: bool,
    udp_checksum: u16,
    allow_ipv6_zero_checksum: bool,
) -> Result<(), VtepError> {
    if outer_ipv6 && udp_checksum == 0 && !allow_ipv6_zero_checksum {
        return Err(VtepError::InvalidConfig);
    }
    Ok(())
}

/// Validate that `mode` and `layer` form an unambiguous, supported combination.
///
/// VTEP termination requires an Ethernet layer and never turns an L3 TUN device
/// into Ethernet. Pass-through is valid on both IP (TUN) and Ethernet (TAP).
pub fn validate_mode(
    mode: VxlanMode,
    layer: AttachmentLayer,
    recursive_vxlan_requested: bool,
) -> Result<VxlanCapabilities, VtepError> {
    if recursive_vxlan_requested {
        return Err(VtepError::RecursiveEncapsulation);
    }
    match (mode, layer) {
        (VxlanMode::Vtep, AttachmentLayer::Ip) => Err(VtepError::IncompatibleLayer),
        (VxlanMode::Vtep, AttachmentLayer::Ethernet) => Ok(VxlanCapabilities {
            mode,
            layer,
            vtep_termination: true,
            nested_passthrough: false,
        }),
        (VxlanMode::PassThrough, _) => Ok(VxlanCapabilities {
            mode,
            layer,
            vtep_termination: false,
            nested_passthrough: true,
        }),
    }
}

/// Typed bridge domain identifier.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct DomainId(pub u32);

/// Typed authorized remote VTEP peer identifier.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct PeerId(pub u32);

/// IEEE 802 48-bit MAC address.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Mac(pub [u8; 6]);

impl Mac {
    /// Broadcast MAC `ff:ff:ff:ff:ff:ff`.
    pub const BROADCAST: Self = Self([0xff; 6]);
    /// All-zero MAC `00:00:00:00:00:00`.
    pub const ZERO: Self = Self([0x00; 6]);

    /// Whether the I/G (multicast/broadcast) bit is set.
    pub const fn is_multicast(self) -> bool {
        (self.0[0] & 0x01) != 0
    }

    /// Whether the address is broadcast.
    pub const fn is_broadcast(self) -> bool {
        matches!(self.0, [0xff, 0xff, 0xff, 0xff, 0xff, 0xff])
    }

    /// Whether the address is all zeros.
    pub const fn is_zero(self) -> bool {
        matches!(self.0, [0, 0, 0, 0, 0, 0])
    }

    /// Extract the destination MAC from a complete Ethernet frame.
    pub fn ethernet_dst(frame: &[u8]) -> Result<Self, VtepError> {
        let slice = frame.get(0..6).ok_or(VtepError::Codec(Error::Truncated))?;
        let mut bytes = [0u8; 6];
        bytes.copy_from_slice(slice);
        Ok(Self(bytes))
    }

    /// Extract the source MAC from a complete Ethernet frame.
    pub fn ethernet_src(frame: &[u8]) -> Result<Self, VtepError> {
        let slice = frame.get(6..12).ok_or(VtepError::Codec(Error::Truncated))?;
        let mut bytes = [0u8; 6];
        bytes.copy_from_slice(slice);
        Ok(Self(bytes))
    }
}

/// Explicit per-domain VLAN admission policy (`VX-04`).
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum VlanPolicy {
    /// Admit only untagged frames (reject 802.1Q and QinQ EtherTypes).
    UntaggedOnly,
    /// Admit untagged frames (if `allow_untagged`) plus listed 802.1Q VLAN IDs (`1..=4094`).
    Allowed {
        /// Whether untagged frames are admitted.
        allow_untagged: bool,
        /// Explicit set of permitted 12-bit 802.1Q VLAN IDs (`1..=4094`).
        vlans: BTreeSet<u16>,
    },
    /// Admit untagged and any valid 802.1Q tagged frame, preserving full bytes.
    PreserveAll,
}

impl VlanPolicy {
    /// Validate policy bounds (VLAN IDs in `1..=4094`, bounded set size).
    pub fn validate(&self) -> Result<(), VtepError> {
        if let Self::Allowed { vlans, .. } = self {
            if vlans.len() > 4094 {
                return Err(VtepError::InvalidConfig);
            }
            if vlans.iter().any(|&vid| vid == 0 || vid > 4094) {
                return Err(VtepError::InvalidVlan);
            }
        }
        Ok(())
    }

    /// Inspect an Ethernet frame's outer VLAN context without mutating bytes.
    pub fn admit(&self, frame: &[u8]) -> Result<Option<u16>, VtepError> {
        let ethertype_bytes = frame
            .get(12..14)
            .ok_or(VtepError::Codec(Error::Truncated))?;
        let ethertype = u16::from_be_bytes([ethertype_bytes[0], ethertype_bytes[1]]);
        let vlan = if ethertype == ETHERTYPE_VLAN_8021Q {
            let tag = frame
                .get(14..18)
                .ok_or(VtepError::Codec(Error::Truncated))?;
            let vid = u16::from_be_bytes([tag[0], tag[1]]) & 0x0fff;
            // Priority-tagged (VID 0) counts as untagged for domain isolation;
            // 4095 is reserved by IEEE 802.1Q.
            if vid == 4095 {
                return Err(VtepError::InvalidVlan);
            }
            (vid != 0).then_some(vid)
        } else if ethertype == ETHERTYPE_QINQ {
            if frame.len() < ETHERNET_HEADER_BYTES + VLAN_TAG_BYTES {
                return Err(VtepError::Codec(Error::Truncated));
            }
            return match self {
                Self::PreserveAll => {
                    let tag = frame
                        .get(14..16)
                        .ok_or(VtepError::Codec(Error::Truncated))?;
                    let vid = u16::from_be_bytes([tag[0], tag[1]]) & 0x0fff;
                    if vid == 4095 {
                        return Err(VtepError::InvalidVlan);
                    }
                    Ok((vid != 0).then_some(vid))
                }
                Self::UntaggedOnly | Self::Allowed { .. } => Err(VtepError::VlanNotAllowed),
            };
        } else {
            None
        };

        match (self, vlan) {
            (Self::UntaggedOnly, None) | (Self::PreserveAll, _) => Ok(vlan),
            (Self::UntaggedOnly, Some(_)) => Err(VtepError::VlanNotAllowed),
            (
                Self::Allowed {
                    allow_untagged: true,
                    ..
                },
                None,
            ) => Ok(None),
            (
                Self::Allowed {
                    allow_untagged: false,
                    ..
                },
                None,
            ) => Err(VtepError::VlanNotAllowed),
            (Self::Allowed { vlans, .. }, Some(vid)) if vlans.contains(&vid) => Ok(Some(vid)),
            (Self::Allowed { .. }, Some(_)) => Err(VtepError::VlanNotAllowed),
        }
    }
}

/// Policy for unicast frames whose destination MAC is not in the FDB (`VX-04`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UnknownUnicastPolicy {
    /// Replicate to all other authorized peers in the domain (charged as BUM).
    Flood,
    /// Drop unknown unicast frames rather than flooding.
    Drop,
}

/// Path-MTU and encapsulation overhead calculation without IP fragmentation (`VX-07`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OverheadBudget {
    /// Underlay link MTU (outer IP packet limit, e.g. 1500 or 9000 for jumbo).
    pub underlay_mtu: usize,
    /// Whether the outer VXLAN transport uses IPv6 (`40 B`) instead of IPv4 (`20 B`).
    pub outer_ipv6: bool,
    /// Additional outer tunnel/record overhead bytes when carried inside l2tunnel.
    pub tunnel_overhead_bytes: usize,
    /// Total outer encapsulation overhead in bytes (IP + UDP + VXLAN + tunnel).
    pub outer_overhead_bytes: usize,
    /// Maximum complete inner Ethernet frame length (including 14 B header + any VLAN tag).
    pub max_inner_frame_bytes: usize,
    /// Maximum untagged inner L3 IP MTU (`max_inner_frame_bytes - 14`).
    pub max_inner_l3_mtu: usize,
    /// Maximum 802.1Q-tagged inner L3 IP MTU (`max_inner_frame_bytes - 18`).
    pub max_inner_vlan_l3_mtu: usize,
}

impl OverheadBudget {
    /// Compute the exact non-fragmented inner Ethernet frame and L3 MTU bounds.
    pub fn compute(
        underlay_mtu: usize,
        outer_ipv6: bool,
        tunnel_overhead_bytes: usize,
    ) -> Result<Self, VtepError> {
        let ip = if outer_ipv6 {
            IPV6_HEADER_BYTES
        } else {
            IPV4_HEADER_BYTES
        };
        let outer_overhead_bytes = ip
            .checked_add(UDP_HEADER_BYTES)
            .and_then(|v| v.checked_add(HEADER_LEN))
            .and_then(|v| v.checked_add(tunnel_overhead_bytes))
            .ok_or(VtepError::InvalidConfig)?;
        let max_inner_frame_bytes = underlay_mtu
            .checked_sub(outer_overhead_bytes)
            .ok_or(VtepError::PathMtuTooSmall)?
            .min(MAX_FRAME);
        if max_inner_frame_bytes < ETHERNET_HEADER_BYTES {
            return Err(VtepError::PathMtuTooSmall);
        }
        let max_inner_l3_mtu = max_inner_frame_bytes - ETHERNET_HEADER_BYTES;
        let max_inner_vlan_l3_mtu =
            max_inner_frame_bytes.saturating_sub(ETHERNET_HEADER_BYTES + VLAN_TAG_BYTES);
        Ok(Self {
            underlay_mtu,
            outer_ipv6,
            tunnel_overhead_bytes,
            outer_overhead_bytes,
            max_inner_frame_bytes,
            max_inner_l3_mtu,
            max_inner_vlan_l3_mtu,
        })
    }

    /// Check that `frame_len` fits without outer IP fragmentation.
    pub fn check_frame(self, frame_len: usize) -> Result<(), VtepError> {
        if frame_len < ETHERNET_HEADER_BYTES {
            return Err(VtepError::Codec(Error::Truncated));
        }
        if frame_len > self.max_inner_frame_bytes {
            return Err(VtepError::PathMtuExceeded {
                frame_bytes: frame_len,
                max_frame_bytes: self.max_inner_frame_bytes,
            });
        }
        Ok(())
    }
}

/// Per-domain FDB sizing, aging and MAC-move limits (`VX-04`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FdbConfig {
    /// Maximum entries in this domain (1..=65536).
    pub max_entries: usize,
    /// Dynamic entry inactivity lifetime in microseconds (`> 0`).
    pub aging_ttl_micros: u64,
    /// Sliding window for counting MAC moves in microseconds (`> 0`).
    pub move_window_micros: u64,
    /// Maximum allowed peer changes per MAC within `move_window_micros` (`>= 1`).
    pub max_moves_per_window: u32,
}

impl FdbConfig {
    /// Validate finite bounds.
    pub fn validate(self) -> Result<(), VtepError> {
        if self.max_entries == 0
            || self.max_entries > MAX_TOTAL_FDB_ENTRIES
            || self.aging_ttl_micros == 0
            || self.move_window_micros == 0
            || self.max_moves_per_window == 0
        {
            return Err(VtepError::InvalidConfig);
        }
        Ok(())
    }
}

/// Per-domain BUM replication byte/packet budget and per-peer quota (`VX-05`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BumPolicy {
    /// Sustained aggregate replicated bytes per second (`> 0`).
    pub bytes_per_sec: u64,
    /// Maximum replicated-byte burst capacity (`>= 1518`).
    pub burst_bytes: u64,
    /// Sustained aggregate replicated packets per second (`> 0`).
    pub packets_per_sec: u64,
    /// Maximum replicated-packet burst capacity (`>= 1`).
    pub burst_packets: u64,
    /// Maximum replicated copies emitted for a single BUM frame (`1..=MAX_PEERS_PER_DOMAIN`).
    pub max_replicas_per_frame: usize,
    /// Maximum replicas per peer within one second window (`>= 1`).
    pub per_peer_packets_per_sec: u64,
}

impl BumPolicy {
    /// Validate finite non-zero BUM limits.
    pub fn validate(self) -> Result<(), VtepError> {
        if self.bytes_per_sec == 0
            || self.burst_bytes < ETHERNET_HEADER_BYTES as u64
            || self.packets_per_sec == 0
            || self.burst_packets == 0
            || self.max_replicas_per_frame == 0
            || self.max_replicas_per_frame > MAX_PEERS_PER_DOMAIN
            || self.per_peer_packets_per_sec == 0
        {
            return Err(VtepError::InvalidConfig);
        }
        Ok(())
    }
}

/// Complete immutable configuration for one VTEP bridge domain.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DomainConfig {
    /// Unique bridge domain ID.
    pub domain: DomainId,
    /// Authorized 24-bit VXLAN Network Identifier.
    pub vni: Vni,
    /// Explicit VLAN policy for this domain.
    pub vlan: VlanPolicy,
    /// Policy for unknown unicast destinations.
    pub unknown_unicast: UnknownUnicastPolicy,
    /// Bounded FDB configuration.
    pub fdb: FdbConfig,
    /// Bounded BUM replication policy.
    pub bum: BumPolicy,
    /// Path-MTU and encapsulation budget (no outer IP fragmentation).
    pub mtu: OverheadBudget,
    /// Whether to reject decapsulated frames that themselves look like nested VXLAN UDP
    /// on `STANDARD_VXLAN_PORT` (loop/recursive-encapsulation guard).
    pub reject_recursive_vxlan: bool,
}

impl DomainConfig {
    /// Validate all nested bounds.
    pub fn validate(&self) -> Result<(), VtepError> {
        self.vlan.validate()?;
        self.fdb.validate()?;
        self.bum.validate()?;
        if self.mtu.max_inner_frame_bytes < ETHERNET_HEADER_BYTES {
            return Err(VtepError::PathMtuTooSmall);
        }
        Ok(())
    }
}

/// Structured error returned by the pure VTEP engine.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VtepError {
    /// Underlying VXLAN header codec error.
    Codec(Error),
    /// Invalid configuration or zero/out-of-range limit.
    InvalidConfig,
    /// VTEP mode cannot attach to an L3 IP device.
    IncompatibleLayer,
    /// Recursive VXLAN decapsulation or self-loop configuration refused.
    RecursiveEncapsulation,
    /// Underlay MTU is too small to carry a minimum Ethernet frame.
    PathMtuTooSmall,
    /// Frame exceeds the non-fragmented VXLAN path MTU.
    PathMtuExceeded {
        /// Actual inner Ethernet frame length.
        frame_bytes: usize,
        /// Configured maximum inner Ethernet frame length.
        max_frame_bytes: usize,
    },
    /// Domain or peer table capacity exceeded.
    Capacity,
    /// Conflicting VNI/domain or duplicate loop-forming endpoint assignment.
    Conflict,
    /// Unknown domain ID.
    UnknownDomain,
    /// Peer is not in the domain's allowlist (spoofed or unauthorized ingress).
    UnauthorizedPeer,
    /// VNI has no authorized domain mapping.
    UnauthorizedVni,
    /// Invalid 802.1Q VLAN ID (e.g. 0 in allowed set or 4095 reserved).
    InvalidVlan,
    /// Frame's VLAN tag is disallowed by domain policy.
    VlanNotAllowed,
    /// Invalid source MAC (multicast/broadcast/zero) for learning.
    InvalidSourceMac,
    /// Static FDB entry cannot be overwritten by dynamic learning or capacity full of static entries.
    StaticPrecedence,
    /// Loop-forming configuration detected (e.g. peer attached twice or duplicate binding).
    LoopConfiguration,
}

impl From<Error> for VtepError {
    fn from(value: Error) -> Self {
        Self::Codec(value)
    }
}

/// Saturating per-domain and aggregate VTEP counters.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct VtepStats {
    /// Accepted ingress frames delivered to the tunnel/bridge.
    pub ingress_accepted: u64,
    /// Accepted ingress Ethernet bytes.
    pub ingress_bytes: u64,
    /// Ingress datagrams rejected because the peer was not allowlisted for the VNI/domain.
    pub dropped_unauthorized_peer: u64,
    /// Ingress datagrams rejected because the VNI was not configured.
    pub dropped_unauthorized_vni: u64,
    /// Ingress datagrams rejected for malformed/truncated VXLAN headers.
    pub dropped_malformed: u64,
    /// Ingress or egress frames rejected for violating domain VLAN policy.
    pub dropped_vlan: u64,
    /// Ingress or egress frames rejected for exceeding VXLAN path MTU.
    pub dropped_path_mtu: u64,
    /// Ingress frames dropped because recursive nested VXLAN was detected.
    pub dropped_recursive_vxlan: u64,
    /// Dynamic FDB entries inserted or refreshed.
    pub fdb_learned: u64,
    /// Dynamic FDB entries evicted due to capacity.
    pub fdb_evicted: u64,
    /// Dynamic FDB entries expired by aging.
    pub fdb_aged: u64,
    /// Dynamic FDB moves suppressed by the MAC-move rate limiter.
    pub fdb_move_suppressed: u64,
    /// Dynamic FDB updates ignored because a static entry owns the key.
    pub fdb_static_protected: u64,
    /// Known unicast frames forwarded to one peer.
    pub egress_unicast: u64,
    /// Unknown unicast frames dropped by [`UnknownUnicastPolicy::Drop`].
    pub egress_unknown_unicast_dropped: u64,
    /// BUM frames replicated (count of original frames).
    pub egress_bum_frames: u64,
    /// Total replicated BUM copies emitted.
    pub egress_bum_replicas: u64,
    /// Total aggregate wire bytes charged across all BUM replicas (VXLAN header + frame).
    pub egress_bum_charged_bytes: u64,
    /// BUM frames dropped because the domain byte/packet budget was exhausted.
    pub egress_bum_budget_drops: u64,
    /// BUM replicas skipped because a peer's per-peer quota was exhausted.
    pub egress_bum_peer_quota_drops: u64,
    /// Frames suppressed by split-horizon (destination equals ingress peer).
    pub egress_split_horizon_drops: u64,
}

/// Key for one FDB record: bridge domain, optional 802.1Q VLAN, and MAC address.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct FdbKey {
    /// Bridge domain.
    pub domain: DomainId,
    /// Optional 802.1Q VLAN context (`None` for untagged).
    pub vlan: Option<u16>,
    /// Source MAC address.
    pub mac: Mac,
}

/// One FDB entry stored inside a domain.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FdbEntry {
    /// Peer owning this MAC.
    pub peer: PeerId,
    /// Whether this entry was statically configured (never aged or dynamically overwritten).
    pub is_static: bool,
    /// Last observation timestamp in monotonic microseconds.
    pub last_seen_micros: u64,
    /// Window start for MAC-move rate limiting.
    pub move_window_start_micros: u64,
    /// Number of peer changes observed in the current move window.
    pub moves_in_window: u32,
}

/// Result of admitting and validating one ingress VXLAN datagram.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IngressDecision<'a> {
    /// Target bridge domain.
    pub domain: DomainId,
    /// Validated VNI.
    pub vni: Vni,
    /// Admitted VLAN context (if tagged).
    pub vlan: Option<u16>,
    /// Source MAC extracted from the inner frame.
    pub src_mac: Mac,
    /// Destination MAC extracted from the inner frame.
    pub dst_mac: Mac,
    /// Borrowed complete inner Ethernet bytes (never mutated).
    pub ethernet: &'a [u8],
}

/// Provenance of a frame entering egress selection, used for split-horizon.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EgressSource {
    /// Frame arrived from the local tunnel/host bridge (not from any VXLAN peer).
    Local,
    /// Frame arrived from VXLAN peer `PeerId` (split-horizon forbids returning to it).
    RemotePeer(PeerId),
}

/// Computed egress forwarding plan for one Ethernet frame.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EgressPlan {
    /// VNI to stamp on outgoing VXLAN headers.
    pub vni: Vni,
    /// Ordered list of target peers (empty if dropped/filtered).
    pub targets: Vec<PeerId>,
    /// Whether this frame was treated as BUM (broadcast, multicast, or flooded unknown unicast).
    pub is_bum: bool,
    /// Aggregate wire bytes charged to the domain BUM budget (0 for known unicast).
    pub bum_charged_bytes: u64,
}

struct BumBucket {
    policy: BumPolicy,
    byte_tokens: u64,
    packet_tokens: u64,
    last_refill_micros: u64,
    peer_window_start_micros: u64,
    peer_counts: BTreeMap<PeerId, u64>,
}

impl BumBucket {
    fn new(policy: BumPolicy) -> Self {
        Self {
            policy,
            byte_tokens: policy.burst_bytes,
            packet_tokens: policy.burst_packets,
            last_refill_micros: 0,
            peer_window_start_micros: 0,
            peer_counts: BTreeMap::new(),
        }
    }

    fn refill(&mut self, now_micros: u64) {
        if now_micros > self.last_refill_micros {
            let elapsed = now_micros - self.last_refill_micros;
            let add_bytes = u64::try_from(
                u128::from(elapsed) * u128::from(self.policy.bytes_per_sec) / 1_000_000,
            )
            .unwrap_or(u64::MAX);
            let add_pkts = u64::try_from(
                u128::from(elapsed) * u128::from(self.policy.packets_per_sec) / 1_000_000,
            )
            .unwrap_or(u64::MAX);
            self.byte_tokens = self
                .byte_tokens
                .saturating_add(add_bytes)
                .min(self.policy.burst_bytes);
            self.packet_tokens = self
                .packet_tokens
                .saturating_add(add_pkts)
                .min(self.policy.burst_packets);
            self.last_refill_micros = now_micros;
        }
        if now_micros.saturating_sub(self.peer_window_start_micros) >= 1_000_000 {
            self.peer_counts.clear();
            self.peer_window_start_micros = now_micros;
        }
    }

    fn allow_peer(&mut self, peer: PeerId) -> bool {
        let count = self.peer_counts.entry(peer).or_insert(0);
        if *count >= self.policy.per_peer_packets_per_sec {
            return false;
        }
        *count = count.saturating_add(1);
        true
    }

    fn try_charge(&mut self, replicas: usize, per_replica_wire_bytes: usize) -> Option<u64> {
        let replicas_u64 = u64::try_from(replicas).ok()?;
        let total_bytes = replicas_u64.checked_mul(u64::try_from(per_replica_wire_bytes).ok()?)?;
        if self.packet_tokens < replicas_u64 || self.byte_tokens < total_bytes {
            return None;
        }
        self.packet_tokens -= replicas_u64;
        self.byte_tokens -= total_bytes;
        Some(total_bytes)
    }
}

struct DomainState {
    config: DomainConfig,
    peers: BTreeSet<PeerId>,
    fdb: BTreeMap<FdbKey, FdbEntry>,
    bum: BumBucket,
}

/// Pure, bounded multi-domain VXLAN VTEP engine (`MOD-VX-06`, `VX-01..VX-07`).
pub struct Vtep {
    domains: BTreeMap<DomainId, DomainState>,
    vni_to_domain: BTreeMap<Vni, DomainId>,
    max_total_fdb: usize,
    stats: VtepStats,
}

impl Vtep {
    /// Create a VTEP engine with an explicit global FDB cap (`1..=65536`).
    pub fn new(max_total_fdb: usize) -> Result<Self, VtepError> {
        if max_total_fdb == 0 || max_total_fdb > MAX_TOTAL_FDB_ENTRIES {
            return Err(VtepError::InvalidConfig);
        }
        Ok(Self {
            domains: BTreeMap::new(),
            vni_to_domain: BTreeMap::new(),
            max_total_fdb,
            stats: VtepStats::default(),
        })
    }

    /// Register a new bridge domain and bind its VNI.
    pub fn add_domain(&mut self, config: DomainConfig) -> Result<(), VtepError> {
        config.validate()?;
        if self.domains.len() >= MAX_DOMAINS {
            return Err(VtepError::Capacity);
        }
        if self.domains.contains_key(&config.domain) || self.vni_to_domain.contains_key(&config.vni)
        {
            return Err(VtepError::Conflict);
        }
        let domain = config.domain;
        let vni = config.vni;
        let bum = BumBucket::new(config.bum);
        self.domains.insert(
            domain,
            DomainState {
                config,
                peers: BTreeSet::new(),
                fdb: BTreeMap::new(),
                bum,
            },
        );
        self.vni_to_domain.insert(vni, domain);
        Ok(())
    }

    /// Update a domain's path-MTU budget (e.g. after a path-MTU change).
    pub fn update_domain_mtu(
        &mut self,
        domain: DomainId,
        mtu: OverheadBudget,
    ) -> Result<(), VtepError> {
        if mtu.max_inner_frame_bytes < ETHERNET_HEADER_BYTES {
            return Err(VtepError::PathMtuTooSmall);
        }
        let state = self
            .domains
            .get_mut(&domain)
            .ok_or(VtepError::UnknownDomain)?;
        state.config.mtu = mtu;
        Ok(())
    }

    /// Authorize a remote peer on `domain`.
    ///
    /// Rejects duplicate attachment of the same peer across two domains sharing a
    /// bridge loop or exceeding [`MAX_PEERS_PER_DOMAIN`].
    pub fn authorize_peer(&mut self, domain: DomainId, peer: PeerId) -> Result<(), VtepError> {
        let state = self
            .domains
            .get_mut(&domain)
            .ok_or(VtepError::UnknownDomain)?;
        if state.peers.contains(&peer) {
            return Ok(());
        }
        if state.peers.len() >= MAX_PEERS_PER_DOMAIN {
            return Err(VtepError::Capacity);
        }
        state.peers.insert(peer);
        Ok(())
    }

    /// Reject loop-forming peer topologies where the same local/remote socket pair
    /// or self-loop endpoint is configured.
    pub fn validate_no_endpoint_loop(
        local_bind: std::net::SocketAddr,
        peers: &[(PeerId, std::net::SocketAddr)],
    ) -> Result<(), VtepError> {
        let mut seen = BTreeSet::new();
        for &(_peer, addr) in peers {
            if addr == local_bind {
                return Err(VtepError::LoopConfiguration);
            }
            if !seen.insert(addr) {
                return Err(VtepError::LoopConfiguration);
            }
        }
        Ok(())
    }

    /// Remove a peer from `domain` and purge all dynamic FDB entries pointing to it.
    /// Static entries are left intact so operator intent is preserved.
    pub fn remove_peer(&mut self, domain: DomainId, peer: PeerId) -> Result<usize, VtepError> {
        let state = self
            .domains
            .get_mut(&domain)
            .ok_or(VtepError::UnknownDomain)?;
        state.peers.remove(&peer);
        let before = state.fdb.len();
        state
            .fdb
            .retain(|_, entry| entry.is_static || entry.peer != peer);
        Ok(before.saturating_sub(state.fdb.len()))
    }

    /// Install a static FDB entry that takes precedence over dynamic learning.
    pub fn insert_static_fdb(
        &mut self,
        domain: DomainId,
        vlan: Option<u16>,
        mac: Mac,
        peer: PeerId,
    ) -> Result<(), VtepError> {
        if mac.is_multicast() || mac.is_zero() {
            return Err(VtepError::InvalidSourceMac);
        }
        let total = self.total_fdb_entries();
        let state = self
            .domains
            .get_mut(&domain)
            .ok_or(VtepError::UnknownDomain)?;
        if !state.peers.contains(&peer) {
            return Err(VtepError::UnauthorizedPeer);
        }
        if let Some(vid) = vlan
            && (vid == 0 || vid > 4094)
        {
            return Err(VtepError::InvalidVlan);
        }
        let key = FdbKey { domain, vlan, mac };
        if !state.fdb.contains_key(&key)
            && (state.fdb.len() >= state.config.fdb.max_entries || total >= self.max_total_fdb)
        {
            if !evict_oldest_dynamic(&mut state.fdb) {
                return Err(VtepError::StaticPrecedence);
            }
            self.stats.fdb_evicted = self.stats.fdb_evicted.saturating_add(1);
        }
        state.fdb.insert(
            key,
            FdbEntry {
                peer,
                is_static: true,
                last_seen_micros: 0,
                move_window_start_micros: 0,
                moves_in_window: 0,
            },
        );
        Ok(())
    }

    /// Remove a static or dynamic FDB entry explicitly.
    pub fn remove_fdb(&mut self, key: FdbKey) -> Option<FdbEntry> {
        self.domains
            .get_mut(&key.domain)
            .and_then(|state| state.fdb.remove(&key))
    }

    /// Look up an FDB entry without modifying aging state.
    pub fn lookup_fdb(&self, key: FdbKey) -> Option<FdbEntry> {
        self.domains
            .get(&key.domain)
            .and_then(|state| state.fdb.get(&key).copied())
    }

    /// Expire all dynamic FDB entries older than each domain's `aging_ttl_micros`.
    pub fn age_fdb(&mut self, now_micros: u64) -> usize {
        let mut aged = 0usize;
        for state in self.domains.values_mut() {
            let ttl = state.config.fdb.aging_ttl_micros;
            let before = state.fdb.len();
            state.fdb.retain(|_, entry| {
                entry.is_static || now_micros.saturating_sub(entry.last_seen_micros) < ttl
            });
            aged = aged.saturating_add(before.saturating_sub(state.fdb.len()));
        }
        self.stats.fdb_aged = self.stats.fdb_aged.saturating_add(aged as u64);
        aged
    }

    /// Current total FDB entries across all domains.
    pub fn total_fdb_entries(&self) -> usize {
        self.domains.values().map(|d| d.fdb.len()).sum()
    }

    /// Current FDB entry count for one domain.
    pub fn domain_fdb_entries(&self, domain: DomainId) -> usize {
        self.domains.get(&domain).map_or(0, |d| d.fdb.len())
    }

    /// Current saturating statistics snapshot.
    pub fn stats(&self) -> VtepStats {
        self.stats
    }

    /// Admit, validate, and learn from one raw VXLAN UDP datagram from `peer`.
    ///
    /// Unauthorized peers, unauthorized VNIs, disallowed VLANs, oversized frames,
    /// and recursive VXLAN frames are all rejected **before** any FDB learning.
    /// Management-looking inner Ethernet frames remain ordinary user bytes.
    pub fn ingress<'a>(
        &mut self,
        peer: PeerId,
        datagram: &'a [u8],
        now_micros: u64,
    ) -> Result<IngressDecision<'a>, VtepError> {
        let packet = match decode(datagram, MAX_FRAME) {
            Ok(packet) => packet,
            Err(err) => {
                self.stats.dropped_malformed = self.stats.dropped_malformed.saturating_add(1);
                return Err(VtepError::Codec(err));
            }
        };
        let Some(&domain) = self.vni_to_domain.get(&packet.vni) else {
            self.stats.dropped_unauthorized_vni =
                self.stats.dropped_unauthorized_vni.saturating_add(1);
            return Err(VtepError::UnauthorizedVni);
        };
        let total_fdb = self.total_fdb_entries();
        let state = self
            .domains
            .get_mut(&domain)
            .ok_or(VtepError::UnknownDomain)?;
        if !state.peers.contains(&peer) {
            self.stats.dropped_unauthorized_peer =
                self.stats.dropped_unauthorized_peer.saturating_add(1);
            return Err(VtepError::UnauthorizedPeer);
        }
        if let Err(err) = state.config.mtu.check_frame(packet.ethernet.len()) {
            self.stats.dropped_path_mtu = self.stats.dropped_path_mtu.saturating_add(1);
            return Err(err);
        }
        let vlan = match state.config.vlan.admit(packet.ethernet) {
            Ok(vlan) => vlan,
            Err(err) => {
                self.stats.dropped_vlan = self.stats.dropped_vlan.saturating_add(1);
                return Err(err);
            }
        };
        if state.config.reject_recursive_vxlan && looks_like_nested_vxlan(packet.ethernet) {
            self.stats.dropped_recursive_vxlan =
                self.stats.dropped_recursive_vxlan.saturating_add(1);
            return Err(VtepError::RecursiveEncapsulation);
        }

        let dst_mac = Mac::ethernet_dst(packet.ethernet)?;
        let src_mac = Mac::ethernet_src(packet.ethernet)?;

        // Expire stale entries in this domain before checking capacity.
        let ttl = state.config.fdb.aging_ttl_micros;
        let before = state.fdb.len();
        state.fdb.retain(|_, entry| {
            entry.is_static || now_micros.saturating_sub(entry.last_seen_micros) < ttl
        });
        let aged = before.saturating_sub(state.fdb.len());
        self.stats.fdb_aged = self.stats.fdb_aged.saturating_add(aged as u64);

        // Learn source MAC only if unicast and non-zero.
        if !src_mac.is_multicast() && !src_mac.is_zero() {
            let key = FdbKey {
                domain,
                vlan,
                mac: src_mac,
            };
            if let Some(existing) = state.fdb.get_mut(&key) {
                if existing.is_static {
                    self.stats.fdb_static_protected =
                        self.stats.fdb_static_protected.saturating_add(1);
                } else if existing.peer == peer {
                    existing.last_seen_micros = now_micros;
                    self.stats.fdb_learned = self.stats.fdb_learned.saturating_add(1);
                } else {
                    // MAC move: enforce per-window rate limit.
                    if now_micros.saturating_sub(existing.move_window_start_micros)
                        >= state.config.fdb.move_window_micros
                    {
                        existing.move_window_start_micros = now_micros;
                        existing.moves_in_window = 0;
                    }
                    if existing.moves_in_window >= state.config.fdb.max_moves_per_window {
                        self.stats.fdb_move_suppressed =
                            self.stats.fdb_move_suppressed.saturating_add(1);
                    } else {
                        existing.peer = peer;
                        existing.last_seen_micros = now_micros;
                        existing.moves_in_window = existing.moves_in_window.saturating_add(1);
                        self.stats.fdb_learned = self.stats.fdb_learned.saturating_add(1);
                    }
                }
            } else {
                let effective_total = total_fdb.saturating_sub(aged);
                let mut has_room = state.fdb.len() < state.config.fdb.max_entries
                    && effective_total < self.max_total_fdb;
                if !has_room && evict_oldest_dynamic(&mut state.fdb) {
                    self.stats.fdb_evicted = self.stats.fdb_evicted.saturating_add(1);
                    has_room = true;
                }
                if has_room {
                    state.fdb.insert(
                        key,
                        FdbEntry {
                            peer,
                            is_static: false,
                            last_seen_micros: now_micros,
                            move_window_start_micros: now_micros,
                            moves_in_window: 0,
                        },
                    );
                    self.stats.fdb_learned = self.stats.fdb_learned.saturating_add(1);
                } else {
                    self.stats.fdb_static_protected =
                        self.stats.fdb_static_protected.saturating_add(1);
                }
            }
        }

        self.stats.ingress_accepted = self.stats.ingress_accepted.saturating_add(1);
        self.stats.ingress_bytes = self
            .stats
            .ingress_bytes
            .saturating_add(packet.ethernet.len() as u64);
        Ok(IngressDecision {
            domain,
            vni: packet.vni,
            vlan,
            src_mac,
            dst_mac,
            ethernet: packet.ethernet,
        })
    }

    /// Resolve egress target peers for an Ethernet frame in `domain`.
    ///
    /// Enforces path MTU, VLAN policy, split-horizon (never returns to
    /// `EgressSource::RemotePeer(p)`), unknown-unicast policy, per-domain BUM
    /// byte/packet token buckets, and per-peer BUM quotas.
    pub fn egress(
        &mut self,
        domain: DomainId,
        source: EgressSource,
        ethernet: &[u8],
        now_micros: u64,
    ) -> Result<EgressPlan, VtepError> {
        let state = self
            .domains
            .get_mut(&domain)
            .ok_or(VtepError::UnknownDomain)?;
        let vni = state.config.vni;
        if let Err(err) = state.config.mtu.check_frame(ethernet.len()) {
            self.stats.dropped_path_mtu = self.stats.dropped_path_mtu.saturating_add(1);
            return Err(err);
        }
        let vlan = match state.config.vlan.admit(ethernet) {
            Ok(vlan) => vlan,
            Err(err) => {
                self.stats.dropped_vlan = self.stats.dropped_vlan.saturating_add(1);
                return Err(err);
            }
        };
        let dst = Mac::ethernet_dst(ethernet)?;

        // Expire stale FDB entries before lookup.
        let ttl = state.config.fdb.aging_ttl_micros;
        let before = state.fdb.len();
        state.fdb.retain(|_, entry| {
            entry.is_static || now_micros.saturating_sub(entry.last_seen_micros) < ttl
        });
        let aged = before.saturating_sub(state.fdb.len());
        self.stats.fdb_aged = self.stats.fdb_aged.saturating_add(aged as u64);

        // Known unicast path.
        if !dst.is_multicast() {
            let key = FdbKey {
                domain,
                vlan,
                mac: dst,
            };
            if let Some(entry) = state.fdb.get(&key).copied()
                && state.peers.contains(&entry.peer)
            {
                if source == EgressSource::RemotePeer(entry.peer) {
                    self.stats.egress_split_horizon_drops =
                        self.stats.egress_split_horizon_drops.saturating_add(1);
                    return Ok(EgressPlan {
                        vni,
                        targets: Vec::new(),
                        is_bum: false,
                        bum_charged_bytes: 0,
                    });
                }
                self.stats.egress_unicast = self.stats.egress_unicast.saturating_add(1);
                return Ok(EgressPlan {
                    vni,
                    targets: vec![entry.peer],
                    is_bum: false,
                    bum_charged_bytes: 0,
                });
            }
            if state.config.unknown_unicast == UnknownUnicastPolicy::Drop {
                self.stats.egress_unknown_unicast_dropped =
                    self.stats.egress_unknown_unicast_dropped.saturating_add(1);
                return Ok(EgressPlan {
                    vni,
                    targets: Vec::new(),
                    is_bum: false,
                    bum_charged_bytes: 0,
                });
            }
        }

        // BUM path (broadcast, multicast, or flooded unknown unicast).
        state.bum.refill(now_micros);
        let mut candidates = Vec::new();
        for &peer in &state.peers {
            if source == EgressSource::RemotePeer(peer) {
                self.stats.egress_split_horizon_drops =
                    self.stats.egress_split_horizon_drops.saturating_add(1);
                continue;
            }
            if candidates.len() >= state.config.bum.max_replicas_per_frame {
                break;
            }
            if !state.bum.allow_peer(peer) {
                self.stats.egress_bum_peer_quota_drops =
                    self.stats.egress_bum_peer_quota_drops.saturating_add(1);
                continue;
            }
            candidates.push(peer);
        }
        if candidates.is_empty() {
            return Ok(EgressPlan {
                vni,
                targets: Vec::new(),
                is_bum: true,
                bum_charged_bytes: 0,
            });
        }
        let wire_per_replica = ethernet.len().saturating_add(HEADER_LEN);
        let Some(charged) = state.bum.try_charge(candidates.len(), wire_per_replica) else {
            self.stats.egress_bum_budget_drops =
                self.stats.egress_bum_budget_drops.saturating_add(1);
            return Ok(EgressPlan {
                vni,
                targets: Vec::new(),
                is_bum: true,
                bum_charged_bytes: 0,
            });
        };
        self.stats.egress_bum_frames = self.stats.egress_bum_frames.saturating_add(1);
        self.stats.egress_bum_replicas = self
            .stats
            .egress_bum_replicas
            .saturating_add(candidates.len() as u64);
        self.stats.egress_bum_charged_bytes =
            self.stats.egress_bum_charged_bytes.saturating_add(charged);
        Ok(EgressPlan {
            vni,
            targets: candidates,
            is_bum: true,
            bum_charged_bytes: charged,
        })
    }
}

fn evict_oldest_dynamic(fdb: &mut BTreeMap<FdbKey, FdbEntry>) -> bool {
    let oldest = fdb
        .iter()
        .filter(|(_, entry)| !entry.is_static)
        .min_by_key(|(key, entry)| (entry.last_seen_micros, **key))
        .map(|(key, _)| *key);
    if let Some(key) = oldest {
        fdb.remove(&key);
        true
    } else {
        false
    }
}

/// Detect whether an inner Ethernet frame carries IPv4/IPv6 UDP to port 4789
/// with a base VXLAN header, so a VTEP configured to refuse recursive VXLAN
/// never decapsulates nested VXLAN loops.
fn looks_like_nested_vxlan(frame: &[u8]) -> bool {
    let Some(et_bytes) = frame.get(12..14) else {
        return false;
    };
    let mut offset = 14usize;
    let mut ethertype = u16::from_be_bytes([et_bytes[0], et_bytes[1]]);
    if ethertype == ETHERTYPE_VLAN_8021Q {
        let Some(inner_et) = frame.get(16..18) else {
            return false;
        };
        ethertype = u16::from_be_bytes([inner_et[0], inner_et[1]]);
        offset = 18;
    }
    match ethertype {
        0x0800 => {
            let Some(ip) = frame.get(offset..) else {
                return false;
            };
            if ip.len() < 20 || (ip[0] >> 4) != 4 {
                return false;
            }
            let ihl = usize::from(ip[0] & 0x0f) * 4;
            if ihl < 20 || ip.len() < ihl + UDP_HEADER_BYTES + HEADER_LEN || ip[9] != 17 {
                return false;
            }
            let udp = &ip[ihl..];
            let dst_port = u16::from_be_bytes([udp[2], udp[3]]);
            dst_port == STANDARD_VXLAN_PORT
                && udp.get(UDP_HEADER_BYTES..UDP_HEADER_BYTES + 4) == Some(&[8, 0, 0, 0])
        }
        0x86dd => {
            let Some(ip) = frame.get(offset..) else {
                return false;
            };
            if ip.len() < 40 + UDP_HEADER_BYTES + HEADER_LEN || (ip[0] >> 4) != 6 || ip[6] != 17 {
                return false;
            }
            let udp = &ip[40..];
            let dst_port = u16::from_be_bytes([udp[2], udp[3]]);
            dst_port == STANDARD_VXLAN_PORT
                && udp.get(UDP_HEADER_BYTES..UDP_HEADER_BYTES + 4) == Some(&[8, 0, 0, 0])
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encode;

    fn frame(dst: Mac, src: Mac, vlan: Option<u16>, ethertype: u16, payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&dst.0);
        out.extend_from_slice(&src.0);
        if let Some(vid) = vlan {
            out.extend_from_slice(&ETHERTYPE_VLAN_8021Q.to_be_bytes());
            out.extend_from_slice(&vid.to_be_bytes());
        }
        out.extend_from_slice(&ethertype.to_be_bytes());
        out.extend_from_slice(payload);
        out
    }

    fn vxlan_datagram(vni: Vni, eth: &[u8]) -> Result<Vec<u8>, VtepError> {
        let mut buf = vec![0u8; HEADER_LEN + eth.len()];
        let n = encode(vni, eth, &mut buf)?;
        buf.truncate(n);
        Ok(buf)
    }

    #[test]
    fn outer_udp_checksum_policy_enforces_ipv4_and_ipv6_semantics() {
        assert_eq!(validate_outer_udp_checksum(false, 0, false), Ok(()));
        assert_eq!(validate_outer_udp_checksum(false, 0x1234, false), Ok(()));
        assert_eq!(validate_outer_udp_checksum(true, 0xabcd, false), Ok(()));
        assert_eq!(
            validate_outer_udp_checksum(true, 0, false),
            Err(VtepError::InvalidConfig)
        );
        assert_eq!(validate_outer_udp_checksum(true, 0, true), Ok(()));
    }

    fn sample_domain(
        domain: u32,
        vni_raw: u32,
        vlan: VlanPolicy,
    ) -> Result<DomainConfig, VtepError> {
        Ok(DomainConfig {
            domain: DomainId(domain),
            vni: Vni::new(vni_raw)?,
            vlan,
            unknown_unicast: UnknownUnicastPolicy::Flood,
            fdb: FdbConfig {
                max_entries: 4,
                aging_ttl_micros: 10_000_000,
                move_window_micros: 1_000_000,
                max_moves_per_window: 2,
            },
            bum: BumPolicy {
                bytes_per_sec: 10_000,
                burst_bytes: 5_000,
                packets_per_sec: 10,
                burst_packets: 6,
                max_replicas_per_frame: 8,
                per_peer_packets_per_sec: 4,
            },
            mtu: OverheadBudget::compute(1500, false, 0)?,
            reject_recursive_vxlan: true,
        })
    }

    #[test]
    fn mode_validation_separates_passthrough_vtep_and_rejects_tun_vtep_or_recursion()
    -> Result<(), VtepError> {
        assert_eq!(
            validate_mode(VxlanMode::Vtep, AttachmentLayer::Ip, false),
            Err(VtepError::IncompatibleLayer)
        );
        assert_eq!(
            validate_mode(VxlanMode::Vtep, AttachmentLayer::Ethernet, true),
            Err(VtepError::RecursiveEncapsulation)
        );
        let vtep_caps = validate_mode(VxlanMode::Vtep, AttachmentLayer::Ethernet, false)?;
        assert!(vtep_caps.vtep_termination && !vtep_caps.nested_passthrough);
        let tun_pt = validate_mode(VxlanMode::PassThrough, AttachmentLayer::Ip, false)?;
        assert!(!tun_pt.vtep_termination && tun_pt.nested_passthrough);
        let tap_pt = validate_mode(VxlanMode::PassThrough, AttachmentLayer::Ethernet, false)?;
        assert!(!tap_pt.vtep_termination && tap_pt.nested_passthrough);
        Ok(())
    }

    #[test]
    fn vni_domain_vlan_and_peer_isolation_reject_spoofed_ingress_before_fdb_learning()
    -> Result<(), VtepError> {
        let mut allowed = BTreeSet::new();
        allowed.insert(100);
        let mut vtep = Vtep::new(64)?;
        vtep.add_domain(sample_domain(
            1,
            1001,
            VlanPolicy::Allowed {
                allow_untagged: false,
                vlans: allowed,
            },
        )?)?;
        vtep.add_domain(sample_domain(2, 1002, VlanPolicy::UntaggedOnly)?)?;
        vtep.authorize_peer(DomainId(1), PeerId(10))?;
        vtep.authorize_peer(DomainId(2), PeerId(20))?;

        let src = Mac([0x02, 0, 0, 0, 0, 1]);
        let dst = Mac([0x02, 0, 0, 0, 0, 2]);
        let eth_vlan100 = frame(dst, src, Some(100), 0x0800, &[0x45; 46]);
        let eth_vlan200 = frame(dst, src, Some(200), 0x0800, &[0x45; 46]);

        // Spoofed peer (PeerId 20 is only authorized on domain 2, not domain 1).
        let pkt = vxlan_datagram(Vni::new(1001)?, &eth_vlan100)?;
        assert_eq!(
            vtep.ingress(PeerId(20), &pkt, 1_000),
            Err(VtepError::UnauthorizedPeer)
        );
        assert_eq!(vtep.total_fdb_entries(), 0);

        // Unauthorized VNI.
        let bad_vni = vxlan_datagram(Vni::new(9999)?, &eth_vlan100)?;
        assert_eq!(
            vtep.ingress(PeerId(10), &bad_vni, 1_000),
            Err(VtepError::UnauthorizedVni)
        );

        // Disallowed VLAN 200 on domain 1.
        let bad_vlan = vxlan_datagram(Vni::new(1001)?, &eth_vlan200)?;
        assert_eq!(
            vtep.ingress(PeerId(10), &bad_vlan, 1_000),
            Err(VtepError::VlanNotAllowed)
        );
        assert_eq!(vtep.total_fdb_entries(), 0);

        // Authorized peer + VNI + VLAN 100 succeeds and learns only in domain 1 / VLAN 100.
        let decision = vtep.ingress(PeerId(10), &pkt, 1_000)?;
        assert_eq!(decision.domain, DomainId(1));
        assert_eq!(decision.vlan, Some(100));
        assert_eq!(decision.ethernet, eth_vlan100.as_slice());
        assert_eq!(vtep.domain_fdb_entries(DomainId(1)), 1);
        assert_eq!(vtep.domain_fdb_entries(DomainId(2)), 0);
        Ok(())
    }

    #[test]
    fn fdb_aging_mac_moves_static_precedence_eviction_and_peer_removal() -> Result<(), VtepError> {
        let mut vtep = Vtep::new(16)?;
        let mut cfg = sample_domain(1, 500, VlanPolicy::UntaggedOnly)?;
        cfg.fdb.max_entries = 2;
        cfg.fdb.aging_ttl_micros = 5_000_000;
        cfg.fdb.move_window_micros = 1_000_000;
        cfg.fdb.max_moves_per_window = 1;
        vtep.add_domain(cfg)?;
        for p in [1, 2, 3] {
            vtep.authorize_peer(DomainId(1), PeerId(p))?;
        }

        let static_mac = Mac([0x02, 0, 0, 0, 0, 0xaa]);
        let dyn_a = Mac([0x02, 0, 0, 0, 0, 0x01]);
        let dyn_b = Mac([0x02, 0, 0, 0, 0, 0x02]);
        vtep.insert_static_fdb(DomainId(1), None, static_mac, PeerId(1))?;

        // Dynamic traffic with static MAC from another peer must NOT overwrite static entry.
        let spoof_static = vxlan_datagram(
            Vni::new(500)?,
            &frame(Mac::BROADCAST, static_mac, None, 0x0806, &[0; 28]),
        )?;
        let _ = vtep.ingress(PeerId(2), &spoof_static, 100)?;
        assert_eq!(
            vtep.lookup_fdb(FdbKey {
                domain: DomainId(1),
                vlan: None,
                mac: static_mac,
            })
            .map(|e| (e.peer, e.is_static)),
            Some((PeerId(1), true))
        );
        assert_eq!(vtep.stats().fdb_static_protected, 1);

        // Learn dyn_a on peer 1, then move once to peer 2 (allowed), second move in window suppressed.
        let f_a = vxlan_datagram(
            Vni::new(500)?,
            &frame(Mac::BROADCAST, dyn_a, None, 0x0800, &[0; 46]),
        )?;
        let _ = vtep.ingress(PeerId(1), &f_a, 100_000)?;
        let _ = vtep.ingress(PeerId(2), &f_a, 200_000)?;
        assert_eq!(
            vtep.lookup_fdb(FdbKey {
                domain: DomainId(1),
                vlan: None,
                mac: dyn_a,
            })
            .map(|e| e.peer),
            Some(PeerId(2))
        );
        let _ = vtep.ingress(PeerId(3), &f_a, 300_000)?;
        assert_eq!(
            vtep.lookup_fdb(FdbKey {
                domain: DomainId(1),
                vlan: None,
                mac: dyn_a,
            })
            .map(|e| e.peer),
            Some(PeerId(2))
        );
        assert_eq!(vtep.stats().fdb_move_suppressed, 1);

        // Domain cap is 2 (static_mac + dyn_a). Learning dyn_b evicts dyn_a (oldest dynamic), never static_mac.
        let f_b = vxlan_datagram(
            Vni::new(500)?,
            &frame(Mac::BROADCAST, dyn_b, None, 0x0800, &[0; 46]),
        )?;
        let _ = vtep.ingress(PeerId(3), &f_b, 400_000)?;
        assert!(
            vtep.lookup_fdb(FdbKey {
                domain: DomainId(1),
                vlan: None,
                mac: static_mac,
            })
            .is_some()
        );
        assert!(
            vtep.lookup_fdb(FdbKey {
                domain: DomainId(1),
                vlan: None,
                mac: dyn_a,
            })
            .is_none()
        );
        assert_eq!(vtep.stats().fdb_evicted, 1);

        // Peer removal purges peer 3's dynamic entry while leaving static entry untouched.
        assert_eq!(vtep.remove_peer(DomainId(1), PeerId(3))?, 1);
        assert_eq!(vtep.domain_fdb_entries(DomainId(1)), 1);

        // Re-learn dyn_a on peer 2 and verify aging expires it after TTL while static survives.
        let _ = vtep.ingress(PeerId(2), &f_a, 1_000_000)?;
        assert_eq!(vtep.domain_fdb_entries(DomainId(1)), 2);
        assert_eq!(vtep.age_fdb(7_000_000), 1);
        assert_eq!(vtep.domain_fdb_entries(DomainId(1)), 1);
        Ok(())
    }

    #[test]
    fn bum_accounting_split_horizon_unknown_unicast_and_loop_rejection() -> Result<(), VtepError> {
        let mut vtep = Vtep::new(32)?;
        let mut cfg = sample_domain(1, 777, VlanPolicy::UntaggedOnly)?;
        cfg.bum = BumPolicy {
            bytes_per_sec: 1_000,
            burst_bytes: 500,
            packets_per_sec: 10,
            burst_packets: 10,
            max_replicas_per_frame: 4,
            per_peer_packets_per_sec: 2,
        };
        vtep.add_domain(cfg)?;
        for p in [1, 2, 3] {
            vtep.authorize_peer(DomainId(1), PeerId(p))?;
        }

        // Loop configuration check rejects self-bind and duplicate peers.
        let bind = "127.0.0.1:4789"
            .parse()
            .map_err(|_| VtepError::InvalidConfig)?;
        let peer_a = "127.0.0.2:4789"
            .parse()
            .map_err(|_| VtepError::InvalidConfig)?;
        assert_eq!(
            Vtep::validate_no_endpoint_loop(bind, &[(PeerId(1), bind)]),
            Err(VtepError::LoopConfiguration)
        );
        assert_eq!(
            Vtep::validate_no_endpoint_loop(bind, &[(PeerId(1), peer_a), (PeerId(2), peer_a)]),
            Err(VtepError::LoopConfiguration)
        );

        // Split-horizon: broadcast arriving from Peer 1 replicates ONLY to Peers 2 and 3.
        let bcast = frame(
            Mac::BROADCAST,
            Mac([0x02, 0, 0, 0, 0, 1]),
            None,
            0x0806,
            &[0; 100],
        );
        let plan = vtep.egress(DomainId(1), EgressSource::RemotePeer(PeerId(1)), &bcast, 0)?;
        assert_eq!(plan.targets, vec![PeerId(2), PeerId(3)]);
        assert!(plan.is_bum);
        assert_eq!(
            plan.bum_charged_bytes,
            2 * (bcast.len() + HEADER_LEN) as u64
        );
        assert_eq!(vtep.stats().egress_split_horizon_drops, 1);

        // Second broadcast exhausts burst_bytes (500 B: 244 already spent, 244 more fits = 488),
        // third broadcast is dropped by BUM byte budget!
        let plan2 = vtep.egress(DomainId(1), EgressSource::RemotePeer(PeerId(1)), &bcast, 0)?;
        assert_eq!(plan2.targets.len(), 2);
        let plan3 = vtep.egress(DomainId(1), EgressSource::RemotePeer(PeerId(1)), &bcast, 0)?;
        assert!(plan3.targets.is_empty());
        assert_eq!(vtep.stats().egress_bum_peer_quota_drops, 2);

        // Domain with UnknownUnicastPolicy::Drop never floods unknown unicast.
        let mut drop_cfg = sample_domain(2, 778, VlanPolicy::UntaggedOnly)?;
        drop_cfg.unknown_unicast = UnknownUnicastPolicy::Drop;
        vtep.add_domain(drop_cfg)?;
        vtep.authorize_peer(DomainId(2), PeerId(1))?;
        let unknown = frame(
            Mac([0x02, 0, 0, 0, 0, 0x99]),
            Mac([0x02, 0, 0, 0, 0, 0x01]),
            None,
            0x0800,
            &[0; 46],
        );
        let dropped = vtep.egress(DomainId(2), EgressSource::Local, &unknown, 0)?;
        assert!(dropped.targets.is_empty());
        assert_eq!(vtep.stats().egress_unknown_unicast_dropped, 1);
        Ok(())
    }

    #[test]
    fn mtu_budget_jumbo_and_management_looking_inner_frames_are_handled_explicitly()
    -> Result<(), VtepError> {
        let v4 = OverheadBudget::compute(1500, false, 0)?;
        assert_eq!(v4.outer_overhead_bytes, 36);
        assert_eq!(v4.max_inner_frame_bytes, 1464);
        assert_eq!(v4.max_inner_l3_mtu, 1450);
        assert_eq!(v4.max_inner_vlan_l3_mtu, 1446);

        let v6_tunneled = OverheadBudget::compute(1500, true, 57)?;
        assert_eq!(v6_tunneled.outer_overhead_bytes, 40 + 8 + 8 + 57);
        assert_eq!(v6_tunneled.max_inner_frame_bytes, 1500 - 113);

        let jumbo = OverheadBudget::compute(9000, false, 0)?;
        assert_eq!(jumbo.max_inner_frame_bytes, 8964);
        jumbo.check_frame(8964)?;
        assert!(matches!(
            jumbo.check_frame(8965),
            Err(VtepError::PathMtuExceeded { .. })
        ));

        // Management-looking inner frame (EtherType 0x88b5 + L2SC/L2MG bytes) stays pure user data.
        let mut vtep = Vtep::new(16)?;
        vtep.add_domain(sample_domain(1, 42, VlanPolicy::PreserveAll)?)?;
        vtep.authorize_peer(DomainId(1), PeerId(1))?;
        let mgmt_looking = frame(
            Mac([0x02, 0, 0, 0, 0, 2]),
            Mac([0x02, 0, 0, 0, 0, 1]),
            None,
            0x88b5,
            b"L2MG\x01\x00\x00\x00L2SCforged-control-bytes",
        );
        let pkt = vxlan_datagram(Vni::new(42)?, &mgmt_looking)?;
        let admitted = vtep.ingress(PeerId(1), &pkt, 100)?;
        assert_eq!(admitted.ethernet, mgmt_looking.as_slice());

        // Path-MTU reduction dynamically rejects previously valid larger frames.
        vtep.update_domain_mtu(DomainId(1), OverheadBudget::compute(1280, true, 0)?)?;
        let large = frame(
            Mac([0x02, 0, 0, 0, 0, 2]),
            Mac([0x02, 0, 0, 0, 0, 1]),
            None,
            0x0800,
            &[0x45; 1300],
        );
        let large_pkt = vxlan_datagram(Vni::new(42)?, &large)?;
        assert!(matches!(
            vtep.ingress(PeerId(1), &large_pkt, 200),
            Err(VtepError::PathMtuExceeded { .. })
        ));

        // Recursive nested VXLAN on UDP/4789 is rejected when reject_recursive_vxlan is enabled.
        let mut inner_ip_udp_vxlan = vec![0u8; 20 + 8 + 8 + 14];
        inner_ip_udp_vxlan[0] = 0x45;
        inner_ip_udp_vxlan[9] = 17;
        inner_ip_udp_vxlan[22..24].copy_from_slice(&STANDARD_VXLAN_PORT.to_be_bytes());
        inner_ip_udp_vxlan[28..32].copy_from_slice(&[8, 0, 0, 0]);
        let recursive_eth = frame(
            Mac([0x02, 0, 0, 0, 0, 2]),
            Mac([0x02, 0, 0, 0, 0, 1]),
            None,
            0x0800,
            &inner_ip_udp_vxlan,
        );
        let recursive_pkt = vxlan_datagram(Vni::new(42)?, &recursive_eth)?;
        assert_eq!(
            vtep.ingress(PeerId(1), &recursive_pkt, 300),
            Err(VtepError::RecursiveEncapsulation)
        );
        assert_eq!(vtep.stats().dropped_recursive_vxlan, 1);
        Ok(())
    }
}
