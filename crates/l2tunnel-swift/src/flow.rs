//! Stateless classification of native packets into ordering channels.
//!
//! Packets of one transport connection always map to the same channel, so a
//! loss delays only the connections sharing that channel. Classification is a
//! local sender choice: the receiver never needs to repeat it, and a packet
//! this parser does not understand simply uses channel zero.

const ETHERTYPE_IPV4: u16 = 0x0800;
const ETHERTYPE_IPV6: u16 = 0x86DD;
const ETHERTYPE_VLAN: u16 = 0x8100;
const TCP: u8 = 6;
const UDP: u8 = 17;

fn mix(hash: u64, bytes: &[u8]) -> u64 {
    bytes.iter().fold(hash, |hash, byte| {
        (hash ^ u64::from(*byte)).wrapping_mul(0x0000_0100_0000_01B3)
    })
}

fn ports(hash: u64, protocol: u8, transport: Option<&[u8]>) -> u64 {
    match transport {
        Some(header) if matches!(protocol, TCP | UDP) && header.len() >= 4 => {
            mix(hash, &header[..4])
        }
        _ => hash,
    }
}

fn ip(packet: &[u8]) -> Option<u64> {
    let hash = 0xCBF2_9CE4_8422_2325;
    match packet.first()? >> 4 {
        4 => {
            let header = usize::from(packet[0] & 0x0F) * 4;
            if header < 20 || packet.len() < header {
                return None;
            }
            let protocol = packet[9];
            let hash = mix(mix(hash, &packet[12..20]), &[protocol]);
            // Later fragments carry no ports; keep every fragment together.
            let fragmented = u16::from_be_bytes([packet[6], packet[7]]) & 0x3FFF != 0;
            Some(if fragmented {
                hash
            } else {
                ports(hash, protocol, packet.get(header..))
            })
        }
        6 => {
            let addresses = packet.get(8..40)?;
            let next = packet[6];
            let hash = mix(mix(hash, addresses), &[next]);
            Some(ports(hash, next, packet.get(40..)))
        }
        _ => None,
    }
}

/// Channel in `0..channels` for a raw IP packet. `channels` of zero or one
/// always yields zero.
pub fn classify_ip(packet: &[u8], channels: usize) -> usize {
    if channels <= 1 {
        return 0;
    }
    ip(packet).map_or(0, |hash| ((hash >> 32 ^ hash) % channels as u64) as usize)
}

/// Channel in `0..channels` for an Ethernet frame, looking through one VLAN tag.
pub fn classify_ethernet(frame: &[u8], channels: usize) -> usize {
    let mut offset = 12;
    let ethertype = |offset: usize| {
        frame
            .get(offset..offset + 2)
            .map(|bytes| u16::from_be_bytes([bytes[0], bytes[1]]))
    };
    let mut kind = ethertype(offset);
    if kind == Some(ETHERTYPE_VLAN) {
        offset += 4;
        kind = ethertype(offset);
    }
    match (kind, frame.get(offset + 2..)) {
        (Some(ETHERTYPE_IPV4 | ETHERTYPE_IPV6), Some(packet)) => classify_ip(packet, channels),
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tcp(source: u16, destination: u16, last: u8) -> Vec<u8> {
        let mut packet = vec![0u8; 40];
        packet[0] = 0x45;
        packet[9] = TCP;
        packet[12..16].copy_from_slice(&[198, 18, 0, 1]);
        packet[16..20].copy_from_slice(&[198, 18, 0, last]);
        packet[20..22].copy_from_slice(&source.to_be_bytes());
        packet[22..24].copy_from_slice(&destination.to_be_bytes());
        packet
    }
    fn frame(packet: &[u8], vlan: bool) -> Vec<u8> {
        let mut frame = vec![0u8; 12];
        if vlan {
            frame.extend_from_slice(&[0x81, 0x00, 0x00, 0x07]);
        }
        frame.extend_from_slice(&[0x08, 0x00]);
        frame.extend_from_slice(packet);
        frame
    }

    #[test]
    fn a_connection_keeps_its_channel_and_connections_spread() {
        let mut used = std::collections::BTreeSet::new();
        for port in 40_000..40_256u16 {
            let packet = tcp(port, 24_500, 2);
            let channel = classify_ip(&packet, 16);
            assert!(channel < 16);
            // Payload, sequence numbers and the frame around it do not matter.
            let mut later = packet.clone();
            later[24..40].fill(0xEE);
            later[2..6].fill(0x11);
            assert_eq!(classify_ip(&later, 16), channel);
            assert_eq!(classify_ethernet(&frame(&packet, false), 16), channel);
            assert_eq!(classify_ethernet(&frame(&packet, true), 16), channel);
            used.insert(channel);
        }
        assert_eq!(used.len(), 16, "256 connections left a channel unused");
        assert_ne!(
            (0..64)
                .map(|port| classify_ip(&tcp(port, 1, 2), 16))
                .collect::<Vec<_>>(),
            (0..64)
                .map(|port| classify_ip(&tcp(port, 1, 3), 16))
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn fragments_ipv6_and_unknown_input_are_handled_without_panicking() {
        let whole = tcp(7, 9, 2);
        let mut first = whole.clone();
        first[6] = 0x20; // more fragments
        let mut later = whole.clone();
        later[7] = 0xB9; // fragment offset
        later[20..24].fill(0x55);
        assert_eq!(classify_ip(&first, 16), classify_ip(&later, 16));
        let mut v6 = vec![0u8; 60];
        v6[0] = 0x60;
        v6[6] = UDP;
        v6[8..40].fill(3);
        v6[40..44].copy_from_slice(&[0, 53, 200, 1]);
        let channel = classify_ip(&v6, 16);
        let mut other = v6.clone();
        other[43] = 2;
        assert!(channel < 16);
        assert_eq!(classify_ip(&v6[..40], 16), classify_ip(&v6[..41], 16));
        let _ = classify_ip(&other, 16);
        for bad in [
            &[][..],
            &[0x45][..],
            &[0x4F; 30][..],
            &[0x60; 39][..],
            &[0x10; 64][..],
        ] {
            assert_eq!(classify_ip(bad, 16), 0);
            assert_eq!(classify_ethernet(bad, 16), 0);
        }
        // ARP and short frames use channel zero; one channel is always zero.
        let mut arp = vec![0u8; 42];
        arp[12..14].copy_from_slice(&[0x08, 0x06]);
        assert_eq!(classify_ethernet(&arp, 16), 0);
        assert_eq!(classify_ethernet(&frame(&whole, false)[..13], 16), 0);
        assert_eq!(classify_ip(&whole, 1), 0);
        assert_eq!(classify_ip(&whole, 0), 0);
    }
}
