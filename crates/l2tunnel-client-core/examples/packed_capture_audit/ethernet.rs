//! Conservative complete-frame witnesses, separate from native admission.
use super::Result;
use l2tunnel_packet::{OpaqueReason, PacketKind, PacketLayer, ParseLimits, classify};

pub(super) fn complete(frame: &[u8]) -> Result<bool> {
    let packet = classify(
        PacketLayer::Ethernet,
        frame,
        ParseLimits {
            max_packet_bytes: 1600,
            max_vlan_tags: 4,
            max_ipv6_extensions: 8,
            max_ipv6_extension_bytes: 256,
        },
    )?;
    if let PacketKind::Opaque(reason) = packet.kind
        && !matches!(
            reason,
            OpaqueReason::IpProtocol(_) | OpaqueReason::NoNextHeader
        )
    {
        return Ok(false);
    }
    let native_bytes = if packet.kind == PacketKind::Arp {
        packet.arp.map(|arp| arp.packet_bytes)
    } else {
        packet.ip.and_then(|ip| ip.packet_bytes)
    };
    let Some(native_bytes) = native_bytes else {
        return Ok(false);
    };
    let ethernet = packet.ethernet.ok_or("Ethernet metadata missing")?;
    let end = ethernet
        .header_bytes
        .checked_add(native_bytes)
        .ok_or("Ethernet declared extent overflow")?;
    // Keep every original octet. Other suffixes remain valid raw records but
    // supply no complete-packet witness; never infer or strip an Ethernet FCS.
    Ok(frame.len() == end || (end < 60 && frame.len() == 60))
}
