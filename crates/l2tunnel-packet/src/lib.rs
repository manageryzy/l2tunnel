//! Bounded structural packet classification and connection affinity.
//!
//! No checksums, TCP windows, packet bytes or operating-system state are changed.
//! Unsupported protocols retain explicit opaque keys; a classification is not
//! authentication, checksum verification, reassembly or a forwarding permission.
//!
//! ```
//! use l2tunnel_packet::{classify, FlowTable, FlowTableConfig, Mapping, PacketLayer, ParseLimits};
//! use std::time::Duration;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let frame = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0x88, 0xb5];
//! let packet = classify(PacketLayer::Ethernet, &frame, ParseLimits::default())?;
//! let mut flows = FlowTable::new(FlowTableConfig {
//!     capacity: 1024, channels: 16, mapping: Mapping::Crc32,
//!     idle_timeout: Duration::from_secs(60),
//! })?;
//! let binding = flows.assign(packet.key, Duration::ZERO)?;
//! assert!(binding.channel < 16);
//! // Admit the original frame through the common MUX using this binding.
//! # Ok(())
//! # }
//! ```

mod flow;
mod parse;

/// Actual fallible fixed-capacity flow-table backing.
pub mod storage;

pub use flow::{Binding, FlowError, FlowId, FlowTable, FlowTableConfig, PreparedAssignment};
pub use l2tunnel_core::Mapping;
pub use l2tunnel_device::PacketLayer;
pub use parse::classify;

/// Maximum retained VLAN headers, independent of packet size.
pub const MAX_VLAN_TAGS: usize = 4;

/// Hard bound on extension-header walking.
pub const MAX_IPV6_EXTENSIONS: u8 = 16;

/// Hard bound on bytes inspected as IPv6 extension headers.
pub const MAX_IPV6_EXTENSION_BYTES: usize = 4096;

/// Configured structural parsing limits; unsupported depth retains opaque traffic.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ParseLimits {
    /// Maximum captured packet bytes, including Ethernet headers and padding.
    pub max_packet_bytes: usize,
    /// Maximum inspected VLAN tags, from zero through four.
    pub max_vlan_tags: u8,
    /// Maximum inspected IPv6 extension headers, from zero through sixteen.
    pub max_ipv6_extensions: u8,
    /// Maximum inspected IPv6 extension bytes, from zero through 4096.
    pub max_ipv6_extension_bytes: usize,
}

impl Default for ParseLimits {
    fn default() -> Self {
        Self {
            max_packet_bytes: 65_605,
            max_vlan_tags: 4,
            max_ipv6_extensions: 8,
            max_ipv6_extension_bytes: 256,
        }
    }
}

/// Supported header that failed structural validation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Header {
    /// Link-layer header.
    Ethernet,
    /// VLAN header.
    Vlan,
    /// ARP address header.
    Arp,
    /// IPv4 header or declared packet.
    Ipv4,
    /// IPv6 header or declared packet.
    Ipv6,
    /// IPv6 extension header.
    Ipv6Extension,
    /// TCP header.
    Tcp,
    /// UDP header.
    Udp,
}

/// Structural failure; unsupported valid headers instead produce opaque metadata.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ParseError {
    /// A configured limit exceeds its hard bound or permits no packet.
    InvalidLimits,
    /// The captured packet exceeds the configured byte bound.
    PacketTooLarge,
    /// A required header or declared length is absent from captured bytes.
    Truncated(Header),
    /// A supported header contains an impossible length or version.
    Malformed(Header),
    /// A TUN packet starts with neither IPv4 nor IPv6.
    UnknownIpVersion,
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "packet classification failed: {self:?}")
    }
}

impl std::error::Error for ParseError {}

/// Why further classification stopped while retaining the packet.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OpaqueReason {
    /// An EtherType has no decoder in this module.
    EtherType(u16),
    /// IEEE 802.3 length/LLC traffic is preserved without LLC decoding.
    Llc,
    /// Further VLAN tags exceed the configured inspection bound.
    VlanDepth,
    /// ARP uses an address family other than Ethernet/IPv4.
    ArpAddressFormat,
    /// The IP protocol or next header has no transport decoder.
    IpProtocol(u8),
    /// IPv6 explicitly declares no next header.
    NoNextHeader,
    /// Further IPv6 headers exceed the configured count or byte bound.
    ExtensionLimit,
    /// Zero IPv6 payload length plus hop-by-hop signals a potential jumbogram.
    Ipv6JumbogramUnsupported,
}

/// Structural packet classification, independent of scheduling privilege.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PacketKind {
    /// Explicit local ordered proxy record; never produced by native parsing.
    ProxyRecord,
    /// Complete unfragmented TCP header.
    Tcp,
    /// Complete unfragmented UDP header.
    Udp,
    /// Ethernet/IPv4 ARP.
    Arp,
    /// Fragment (including conservative IPv6 atomic-fragment classification).
    Fragment,
    /// Forward unchanged using the returned coarser key.
    Opaque(OpaqueReason),
}

/// Observed VLAN tag; priority is excluded from flow identity.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct VlanTag {
    /// Tag protocol identifier (for example 0x8100 or 0x88a8).
    pub tpid: u16,
    /// Original tag control information, including VID, PCP and DEI.
    pub tci: u16,
}

/// Observed Ethernet header and bounded outer-to-inner VLAN tags.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EthernetMetadata {
    /// Source MAC address.
    pub source: [u8; 6],
    /// Destination MAC address.
    pub destination: [u8; 6],
    /// EtherType or length after the inspected VLAN prefix.
    pub ether_type: u16,
    /// Parsed outer-to-inner VLAN tags; only the prefix `vlan_count` is meaningful.
    pub vlans: [VlanTag; MAX_VLAN_TAGS],
    /// Number of parsed VLAN tags.
    pub vlan_count: u8,
    /// Bytes of inspected Ethernet and VLAN headers.
    pub header_bytes: usize,
}

/// Fixed-size IP address, with family retained in equality and encoding.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum Address {
    /// Four IPv4 network-order bytes.
    V4([u8; 4]),
    /// Sixteen IPv6 network-order bytes.
    V6([u8; 16]),
}

/// Complete IP address/port endpoint, sorted as one unit for bidirectional keys.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Endpoint {
    /// Endpoint IP address.
    pub address: Address,
    /// Host-order transport port.
    pub port: u16,
}

/// Fragment metadata; no reassembly or transport port inference is performed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FragmentMetadata {
    /// IPv4 identification or IPv6 fragment identification.
    pub id: u32,
    /// Fragment offset in bytes.
    pub offset_bytes: u32,
    /// Whether more fragments follow.
    pub more: bool,
    /// IPv6 fragment with zero offset and no more-fragments bit.
    pub atomic: bool,
}

/// Observed IP metadata. Length is absent for an unsupported jumbo candidate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IpMetadata {
    /// Original source IP.
    pub source: Address,
    /// Original destination IP.
    pub destination: Address,
    /// Transport protocol, uninspected next header, or fragment next header.
    pub protocol: u8,
    /// Six-bit differentiated-services value, not a trusted priority grant.
    pub dscp: u8,
    /// Two-bit original ECN field.
    pub ecn: u8,
    /// Declared complete IP packet bytes, excluding Ethernet padding.
    pub packet_bytes: Option<usize>,
    /// Inspected base/header-option/extension bytes, excluding transport header.
    pub header_bytes: usize,
    /// Present for an IPv4 fragment or any IPv6 fragment header.
    pub fragment: Option<FragmentMetadata>,
}

/// Complete transport metadata; absent for every fragment and opaque suffix.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransportMetadata {
    /// Source port.
    pub source_port: u16,
    /// Destination port.
    pub destination_port: u16,
    /// TCP data offset or UDP's eight-byte header.
    pub header_bytes: usize,
    /// Data bytes after the transport header (UDP excludes any IP suffix).
    pub payload_bytes: usize,
    /// Original TCP flags, including NS; absent for UDP.
    pub tcp_flags: Option<u16>,
    /// Original unscaled TCP advertised window; never rewritten.
    pub tcp_window: Option<u16>,
}

/// Observed variable-length ARP header.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ArpMetadata {
    /// Hardware address family.
    pub hardware_type: u16,
    /// Protocol address family.
    pub protocol_type: u16,
    /// Hardware address bytes per endpoint.
    pub hardware_bytes: u8,
    /// Protocol address bytes per endpoint.
    pub protocol_bytes: u8,
    /// ARP operation; unknown operations are preserved.
    pub operation: u16,
    /// Complete declared ARP bytes, excluding Ethernet padding.
    pub packet_bytes: usize,
}

/// Fixed-size classification result; packet bytes remain with the caller.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Classification {
    /// Canonical identity, suitable for bounded flow-table lookup.
    pub key: FlowKey,
    /// Parsed class or explicit opaque reason.
    pub kind: PacketKind,
    /// Original captured packet length, including any padding.
    pub observed_bytes: usize,
    /// Link metadata for TAP, absent for TUN.
    pub ethernet: Option<EthernetMetadata>,
    /// IP metadata when the base header could be read.
    pub ip: Option<IpMetadata>,
    /// Complete unfragmented TCP/UDP metadata.
    pub transport: Option<TransportMetadata>,
    /// ARP metadata, including unsupported address formats.
    pub arp: Option<ArpMetadata>,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Ord, PartialOrd, Hash)]
struct Domain {
    count: u8,
    tags: [(u16, u16); MAX_VLAN_TAGS],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
enum Tuple {
    ProxyRecords,
    Transport(u8, Endpoint, Endpoint),
    Ip(u8, Address, Address),
    Fragment(u8, u32, Address, Address),
    Arp([u8; 4], [u8; 4]),
    Ethernet(u16, [u8; 6], [u8; 6]),
}

/// Canonical fixed-size flow identity. Use one table per tenant/session/epoch.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct FlowKey {
    domain: Domain,
    tuple: Tuple,
}

/// Fixed-buffer versioned flow-key encoding; unused storage is not serialized.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KeyBytes {
    bytes: [u8; 96],
    length: usize,
}

impl KeyBytes {
    /// Return exactly the encoded prefix without allocating.
    pub fn as_slice(&self) -> &[u8] {
        &self.bytes[..self.length]
    }

    fn push(&mut self, bytes: &[u8]) {
        // All callers encode fixed types; their maximum combined size is 62.
        let end = self.length + bytes.len();
        self.bytes[self.length..end].copy_from_slice(bytes);
        self.length = end;
    }

    fn address(&mut self, address: Address) {
        match address {
            Address::V4(value) => {
                self.push(&[4]);
                self.push(&value);
            }
            Address::V6(value) => {
                self.push(&[6]);
                self.push(&value);
            }
        }
    }
}

impl FlowKey {
    /// One ordered proxy-record namespace, distinct from every native packet key.
    /// The caller must already arbitrate the original TCP flows before this lane.
    pub fn proxy_records() -> Self {
        Self {
            domain: Domain::default(),
            tuple: Tuple::ProxyRecords,
        }
    }

    /// Encode `L2FK`, version 1, VLAN count/pairs and the canonical tuple.
    ///
    /// Tuple tags are 1=transport, 2=IP, 3=fragment, 4=ARP, 5=Ethernet,
    /// 6=explicit ordered proxy records.
    /// Integers are big-endian; IP addresses carry a one-byte family marker.
    pub fn canonical_bytes(&self) -> KeyBytes {
        let mut output = KeyBytes {
            bytes: [0; 96],
            length: 0,
        };
        output.push(b"L2FK\x01");
        output.push(&[self.domain.count]);
        for (tpid, vid) in self.domain.tags.iter().take(usize::from(self.domain.count)) {
            output.push(&tpid.to_be_bytes());
            output.push(&vid.to_be_bytes());
        }
        match self.tuple {
            Tuple::ProxyRecords => output.push(&[6]),
            Tuple::Transport(protocol, low, high) => {
                output.push(&[1, protocol]);
                output.address(low.address);
                output.push(&low.port.to_be_bytes());
                output.address(high.address);
                output.push(&high.port.to_be_bytes());
            }
            Tuple::Ip(protocol, low, high) => {
                output.push(&[2, protocol]);
                output.address(low);
                output.address(high);
            }
            Tuple::Fragment(protocol, id, low, high) => {
                output.push(&[3, protocol]);
                output.push(&id.to_be_bytes());
                output.address(low);
                output.address(high);
            }
            Tuple::Arp(low, high) => {
                output.push(&[4]);
                output.push(&low);
                output.push(&high);
            }
            Tuple::Ethernet(ether_type, low, high) => {
                output.push(&[5]);
                output.push(&ether_type.to_be_bytes());
                output.push(&low);
                output.push(&high);
            }
        }
        output
    }

    /// Exact Python CRC input for untagged IPv4/TCP; all other keys return `None`.
    pub fn python_tcp_bytes(&self) -> Option<[u8; 13]> {
        if self.domain.count != 0 {
            return None;
        }
        let Tuple::Transport(6, low, high) = self.tuple else {
            return None;
        };
        let (Address::V4(low_ip), Address::V4(high_ip)) = (low.address, high.address) else {
            return None;
        };
        let mut bytes = [0; 13];
        bytes[0] = 6;
        bytes[1..5].copy_from_slice(&low_ip);
        bytes[5..7].copy_from_slice(&low.port.to_be_bytes());
        bytes[7..11].copy_from_slice(&high_ip);
        bytes[11..13].copy_from_slice(&high.port.to_be_bytes());
        Some(bytes)
    }

    /// Stable IEEE CRC32 affinity hash, never an integrity or authentication check.
    pub fn crc32(&self) -> u32 {
        match self.python_tcp_bytes() {
            Some(bytes) => crc32(&bytes),
            None => crc32(self.canonical_bytes().as_slice()),
        }
    }
}

fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = !0u32;
    for &byte in bytes {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            crc = (crc >> 1) ^ (0xedb8_8320 & (0u32.wrapping_sub(crc & 1)));
        }
    }
    !crc
}

fn ordered<T: Ord>(left: T, right: T) -> (T, T) {
    if left <= right {
        (left, right)
    } else {
        (right, left)
    }
}

#[cfg(test)]
mod tests;
