use l2tunnel_packet::{PacketLayer, ParseLimits, classify};
use l2tunnel_pipeline::ack_coalescing::is_complete_pure_tcp_ack;

pub(super) fn eligible(bytes: &[u8]) -> bool {
    // Direct IPv4/IPv6 and at most a complete 60-byte TCP header.
    if !(40..=100).contains(&bytes.len()) {
        return false;
    }
    let Ok(class) = classify(PacketLayer::Ip, bytes, ParseLimits::default()) else {
        return false;
    };
    if !is_complete_pure_tcp_ack(bytes, class, 100) {
        return false;
    }
    let Some(tcp) = class.ip.and_then(|ip| bytes.get(ip.header_bytes..)) else {
        return false;
    };
    // The maintained predicate proves framing and checksums. Restrict early handoff
    // further to recognized ACK option layouts; all other packets retain ordering.
    tcp[12] & 15 == 0 && supported_options(&tcp[20..])
}

fn supported_options(mut options: &[u8]) -> bool {
    let mut timestamp = false;
    let mut sack = false;
    while let Some((&kind, rest)) = options.split_first() {
        if kind == 0 {
            return rest.iter().all(|&byte| byte == 0);
        }
        if kind == 1 {
            options = rest;
            continue;
        }
        let Some(&len) = rest.first() else {
            return false;
        };
        let len = usize::from(len);
        if len > options.len() {
            return false;
        }
        match (kind, len) {
            (8, 10) if !timestamp => timestamp = true,
            (5, 10 | 18 | 26 | 34) if !sack => sack = true,
            _ => return false,
        }
        options = &options[len..];
    }
    true
}
