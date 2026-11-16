//! Conservative evidence over the maintained classifier and smoltcp wire checks.
use l2tunnel_packet::{Address, Classification, FlowKey, PacketKind};
use smoltcp::wire::{IpAddress, Ipv4Packet, Ipv6Packet, TcpOption, TcpPacket};

// Four VLANs, direct IPv6 and the maximum TCP header; unsupported layouts bypass.
const MAX_SAFE_ACK_BYTES: usize = 14 + 4 * l2tunnel_packet::MAX_VLAN_TAGS + 40 + 60;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct Key {
    pub(super) flow: FlowKey,
    source: Address,
    source_port: u16,
}
#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) struct Signature {
    bytes: [u8; MAX_SAFE_ACK_BYTES],
    length: usize,
}
#[derive(Clone, Copy)]
pub(super) struct Ack {
    pub(super) key: Key,
    pub(super) acknowledged: u32,
    pub(super) signature: Option<Signature>,
}

pub(super) fn inspect(bytes: &[u8], class: Classification, maximum: usize) -> Option<Ack> {
    let ip = class.ip?;
    let transport = class.transport?;
    if class.kind != PacketKind::Tcp
        || ip.fragment.is_some()
        || transport.payload_bytes != 0
        || transport.tcp_flags != Some(0x10)
        || bytes.len() > maximum
        || bytes.len() > MAX_SAFE_ACK_BYTES
    {
        return None;
    }
    let link = class.ethernet.map_or(0, |ethernet| ethernet.header_bytes);
    let declared = ip.packet_bytes?;
    if link.checked_add(declared)? != bytes.len() {
        return None;
    }
    let native = bytes.get(link..)?;
    let (source, destination, ipv4) = match native.first()? >> 4 {
        4 => {
            if ip.header_bytes != 20 {
                return None;
            }
            let packet = Ipv4Packet::new_checked(native).ok()?;
            if !packet.verify_checksum() {
                return None;
            }
            (
                IpAddress::Ipv4(packet.src_addr()),
                IpAddress::Ipv4(packet.dst_addr()),
                true,
            )
        }
        6 => {
            if ip.header_bytes != 40 {
                return None;
            }
            let packet = Ipv6Packet::new_checked(native).ok()?;
            if packet.payload_len() == 0 {
                return None;
            }
            (
                IpAddress::Ipv6(packet.src_addr()),
                IpAddress::Ipv6(packet.dst_addr()),
                false,
            )
        }
        _ => return None,
    };
    let tcp_bytes = native.get(ip.header_bytes..)?;
    let tcp = TcpPacket::new_checked(tcp_bytes).ok()?;
    if !tcp.verify_checksum(&source, &destination) {
        return None;
    }
    let key = Key {
        flow: class.key,
        source: ip.source,
        source_port: transport.source_port,
    };
    let mut ack = Ack {
        key,
        acknowledged: tcp.ack_number().0 as u32,
        signature: None,
    };
    let tcp_at = link.checked_add(ip.header_bytes)?;
    let mut signature = Signature {
        bytes: [0; MAX_SAFE_ACK_BYTES],
        length: bytes.len(),
    };
    signature.bytes[..bytes.len()].copy_from_slice(bytes);
    // Never erase or rewrite original packet fields; this copy is equality evidence.
    if ipv4 {
        signature.bytes[link + 4..link + 6].fill(0);
        signature.bytes[link + 10..link + 12].fill(0);
    }
    signature.bytes[tcp_at + 8..tcp_at + 12].fill(0);
    signature.bytes[tcp_at + 16..tcp_at + 18].fill(0);
    if ip.ecn != 0 || tcp_bytes[12] & 0x0f != 0 {
        return Some(ack);
    }
    let mut timestamp = false;
    let mut options = tcp.options();
    let mut offset = tcp_at + 20;
    while !options.is_empty() {
        let Ok((rest, option)) = TcpOption::parse(options) else {
            return Some(ack);
        };
        match option {
            TcpOption::EndOfList => {
                if rest.iter().any(|byte| *byte != 0) {
                    return Some(ack);
                }
                break;
            }
            TcpOption::NoOperation => {}
            TcpOption::TimeStamp { .. } if !timestamp => {
                timestamp = true;
                signature.bytes[offset + 2..offset + 10].fill(0);
            }
            _ => return Some(ack),
        }
        offset += options.len() - rest.len();
        options = rest;
    }
    ack.signature = Some(signature);
    Some(ack)
}
