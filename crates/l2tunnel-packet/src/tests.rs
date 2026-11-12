use super::*;
use std::time::Duration;

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn tcp(source: u16, destination: u16, payload: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0; 20];
    bytes[..2].copy_from_slice(&source.to_be_bytes());
    bytes[2..4].copy_from_slice(&destination.to_be_bytes());
    bytes[12] = 0x50;
    bytes[13] = 0x12;
    bytes[14..16].copy_from_slice(&4096u16.to_be_bytes());
    bytes.extend_from_slice(payload);
    bytes
}

fn udp(source: u16, destination: u16, payload: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0; 8];
    bytes[..2].copy_from_slice(&source.to_be_bytes());
    bytes[2..4].copy_from_slice(&destination.to_be_bytes());
    bytes[4..6].copy_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
    bytes.extend_from_slice(payload);
    bytes
}

fn v4(source: [u8; 4], destination: [u8; 4], protocol: u8, payload: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0; 20];
    bytes[0] = 0x45;
    bytes[1] = (46 << 2) | 3;
    bytes[2..4].copy_from_slice(&((20 + payload.len()) as u16).to_be_bytes());
    bytes[4..6].copy_from_slice(&0x1234u16.to_be_bytes());
    bytes[8] = 64;
    bytes[9] = protocol;
    bytes[12..16].copy_from_slice(&source);
    bytes[16..20].copy_from_slice(&destination);
    bytes.extend_from_slice(payload);
    bytes
}

fn v6(next: u8, payload: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0; 40];
    bytes[0] = 0x6b;
    bytes[1] = 0xb0;
    bytes[4..6].copy_from_slice(&(payload.len() as u16).to_be_bytes());
    bytes[6] = next;
    bytes[7] = 64;
    bytes[8..24].copy_from_slice(&[1; 16]);
    bytes[24..40].copy_from_slice(&[2; 16]);
    bytes.extend_from_slice(payload);
    bytes
}

fn ethernet(ether_type: u16, payload: &[u8], tags: &[(u16, u16)]) -> Vec<u8> {
    let mut bytes = vec![0; 12];
    bytes[..6].copy_from_slice(&[1; 6]);
    bytes[6..12].copy_from_slice(&[2; 6]);
    for &(tpid, tci) in tags {
        bytes.extend_from_slice(&tpid.to_be_bytes());
        bytes.extend_from_slice(&tci.to_be_bytes());
    }
    bytes.extend_from_slice(&ether_type.to_be_bytes());
    bytes.extend_from_slice(payload);
    bytes
}

fn parse_ip(bytes: &[u8]) -> Result<Classification, ParseError> {
    classify(PacketLayer::Ip, bytes, ParseLimits::default())
}

fn key(port: u16) -> FlowKey {
    FlowKey {
        domain: Domain::default(),
        tuple: Tuple::Transport(
            6,
            Endpoint {
                address: Address::V4([10, 0, 0, 1]),
                port,
            },
            Endpoint {
                address: Address::V4([10, 0, 0, 2]),
                port: 443,
            },
        ),
    }
}

fn table_config(mapping: Mapping, capacity: usize) -> FlowTableConfig {
    FlowTableConfig {
        mapping,
        capacity,
        channels: 3,
        idle_timeout: Duration::from_secs(5),
    }
}

#[test]
fn ipv4_tcp_reverse_padding_and_observation_fields() -> TestResult {
    let ip = v4(
        [10, 0, 0, 1],
        [10, 0, 0, 2],
        6,
        &tcp(12345, 443, b"arbitrary\x00\xff"),
    );
    let reverse = v4(
        [10, 0, 0, 2],
        [10, 0, 0, 1],
        6,
        &tcp(443, 12345, b"different"),
    );
    let original = ip.clone();
    let tun = parse_ip(&ip)?;
    let mut tap_bytes = ethernet(0x0800, &ip, &[]);
    tap_bytes.extend_from_slice(&[0xab; 12]);
    let tap = classify(PacketLayer::Ethernet, &tap_bytes, ParseLimits::default())?;
    assert_eq!(tun.key, tap.key);
    assert_eq!(tun.key, parse_ip(&reverse)?.key);
    assert_eq!(tap.observed_bytes, ip.len() + 26);
    assert_eq!(
        tap.ip.map(|meta| (meta.dscp, meta.ecn, meta.packet_bytes)),
        Some((46, 3, Some(ip.len())))
    );
    assert_eq!(
        tun.transport
            .map(|meta| (meta.tcp_flags, meta.tcp_window, meta.payload_bytes)),
        Some((Some(0x12), Some(4096), 11))
    );
    assert_eq!(ip, original);
    Ok(())
}

#[test]
fn every_supported_frame_prefix_is_rejected_when_truncated() -> TestResult {
    let mut arp = vec![0; 28];
    arp[..8].copy_from_slice(&[0, 1, 8, 0, 6, 4, 0, 1]);
    let cases = [
        ethernet(0x0800, &v4([1; 4], [2; 4], 6, &tcp(1, 2, b"abc")), &[]),
        ethernet(
            0x0800,
            &v4([1; 4], [2; 4], 17, &udp(1, 2, b"abc")),
            &[(0x88a8, 1), (0x8100, 2)],
        ),
        ethernet(0x86dd, &v6(6, &tcp(1, 2, b"abc")), &[]),
        ethernet(0x0806, &arp, &[]),
    ];
    for frame in cases {
        classify(PacketLayer::Ethernet, &frame, ParseLimits::default())?;
        for end in 0..frame.len() {
            assert!(
                classify(PacketLayer::Ethernet, &frame[..end], ParseLimits::default()).is_err(),
                "accepted prefix {end}/{}",
                frame.len()
            );
        }
    }
    Ok(())
}

#[test]
fn ipv4_and_transport_lengths_do_not_use_ethernet_padding() -> TestResult {
    let mut ip = v4([1; 4], [2; 4], 6, &tcp(1, 2, b""));
    ip[0] = 0x44;
    assert_eq!(parse_ip(&ip), Err(ParseError::Malformed(Header::Ipv4)));
    ip[0] = 0x4f;
    assert_eq!(parse_ip(&ip), Err(ParseError::Malformed(Header::Ipv4)));
    ip[0] = 0x45;
    ip[2..4].copy_from_slice(&19u16.to_be_bytes());
    assert_eq!(parse_ip(&ip), Err(ParseError::Malformed(Header::Ipv4)));
    ip[2..4].copy_from_slice(&40u16.to_be_bytes());
    ip[32] = 0x40;
    assert_eq!(parse_ip(&ip), Err(ParseError::Malformed(Header::Tcp)));
    ip[32] = 0xf0;
    let mut frame = ethernet(0x0800, &ip, &[]);
    frame.extend_from_slice(&[0; 60]);
    assert_eq!(
        classify(PacketLayer::Ethernet, &frame, ParseLimits::default()),
        Err(ParseError::Malformed(Header::Tcp))
    );
    let mut ip = v4([1; 4], [2; 4], 17, &udp(1, 2, b""));
    for size in [0u16, 7, 9, 65535] {
        ip[24..26].copy_from_slice(&size.to_be_bytes());
        assert_eq!(parse_ip(&ip), Err(ParseError::Malformed(Header::Udp)));
    }
    // IP and TCP options are structurally bounded and retained, not interpreted.
    let mut segment = tcp(1, 2, b"abc");
    segment.splice(20..20, [1; 4]);
    segment[12] = 0x60;
    let mut ip = v4([1; 4], [2; 4], 6, &segment);
    ip.splice(20..20, [1; 4]);
    ip[0] = 0x46;
    let length = ip.len() as u16;
    ip[2..4].copy_from_slice(&length.to_be_bytes());
    let result = parse_ip(&ip)?;
    assert_eq!(result.ip.map(|meta| meta.header_bytes), Some(24));
    assert_eq!(
        result
            .transport
            .map(|meta| (meta.header_bytes, meta.payload_bytes)),
        Some((24, 3))
    );
    Ok(())
}

#[test]
fn vlan_stack_limits_priority_identity_and_unknown_ethernet_survive() -> TestResult {
    let ip = v4([1; 4], [2; 4], 6, &tcp(1, 2, b""));
    let tags = [(0x88a8, 7), (0x8100, 8), (0x8100, 9), (0x8100, 10)];
    let frame = ethernet(0x0800, &ip, &tags);
    let result = classify(PacketLayer::Ethernet, &frame, ParseLimits::default())?;
    assert_eq!(result.kind, PacketKind::Tcp);
    assert_eq!(result.ethernet.map(|meta| meta.vlan_count), Some(4));
    assert_eq!(result.key.canonical_bytes().as_slice().len(), 38);
    let mut priority = frame.clone();
    priority[14] |= 0xf0;
    assert_eq!(
        result.key,
        classify(PacketLayer::Ethernet, &priority, ParseLimits::default())?.key
    );
    priority[15] ^= 1;
    assert_ne!(
        result.key,
        classify(PacketLayer::Ethernet, &priority, ParseLimits::default())?.key
    );
    let limited = ParseLimits {
        max_vlan_tags: 3,
        ..ParseLimits::default()
    };
    assert_eq!(
        classify(PacketLayer::Ethernet, &frame, limited)?.kind,
        PacketKind::Opaque(OpaqueReason::VlanDepth)
    );
    let five = ethernet(0x0800, &ip, &[(0x8100, 1); 5]);
    assert_eq!(
        classify(PacketLayer::Ethernet, &five, ParseLimits::default())?.kind,
        PacketKind::Opaque(OpaqueReason::VlanDepth)
    );
    for size in 14..18 {
        assert_eq!(
            classify(
                PacketLayer::Ethernet,
                &frame[..size],
                ParseLimits::default()
            ),
            Err(ParseError::Truncated(Header::Vlan))
        );
    }
    let unknown = ethernet(0x88b5, b"opaque\xff", &[]);
    assert_eq!(
        classify(PacketLayer::Ethernet, &unknown, ParseLimits::default())?.kind,
        PacketKind::Opaque(OpaqueReason::EtherType(0x88b5))
    );
    let llc = ethernet(3, b"\xaa\xaa\x03padding", &[]);
    assert_eq!(
        classify(PacketLayer::Ethernet, &llc, ParseLimits::default())?.kind,
        PacketKind::Opaque(OpaqueReason::Llc)
    );
    assert_eq!(
        classify(PacketLayer::Ethernet, &llc[..16], ParseLimits::default()),
        Err(ParseError::Truncated(Header::Ethernet))
    );
    let longer_llc = ethernet(8, b"\xaa\xaa\x03hello", &[]);
    assert_eq!(
        classify(PacketLayer::Ethernet, &llc, ParseLimits::default())?.key,
        classify(PacketLayer::Ethernet, &longer_llc, ParseLimits::default())?.key
    );
    Ok(())
}

#[test]
fn arp_request_reply_and_unusual_address_formats() -> TestResult {
    let mut arp = [0; 28];
    arp[..8].copy_from_slice(&[0, 1, 8, 0, 6, 4, 0, 1]);
    arp[14..18].copy_from_slice(&[10, 0, 0, 1]);
    arp[24..28].copy_from_slice(&[10, 0, 0, 2]);
    let request = classify(
        PacketLayer::Ethernet,
        &ethernet(0x0806, &arp, &[]),
        ParseLimits::default(),
    )?;
    arp[7] = 2;
    arp[14..18].copy_from_slice(&[10, 0, 0, 2]);
    arp[24..28].copy_from_slice(&[10, 0, 0, 1]);
    let mut reply = ethernet(0x0806, &arp, &[]);
    reply[..12].fill(0xff);
    let response = classify(PacketLayer::Ethernet, &reply, ParseLimits::default())?;
    assert_eq!(request.kind, PacketKind::Arp);
    assert_eq!(request.key, response.key);
    let unusual = ethernet(0x0806, &[0, 7, 0, 9, 1, 2, 0, 1, 1, 2, 3, 4, 5, 6], &[]);
    assert_eq!(
        classify(PacketLayer::Ethernet, &unusual, ParseLimits::default())?.kind,
        PacketKind::Opaque(OpaqueReason::ArpAddressFormat)
    );
    let mut malicious = unusual;
    malicious[18] = 255;
    malicious[19] = 255;
    assert_eq!(
        classify(PacketLayer::Ethernet, &malicious, ParseLimits::default()),
        Err(ParseError::Truncated(Header::Arp))
    );
    Ok(())
}

#[test]
fn ipv4_fragments_share_directional_datagram_affinity_without_ports() -> TestResult {
    let mut first = v4([1; 4], [2; 4], 6, &[0xff; 8]);
    first[6..8].copy_from_slice(&0x2000u16.to_be_bytes());
    let mut later = first.clone();
    later[6..8].copy_from_slice(&1u16.to_be_bytes());
    later[20..].fill(0);
    let a = parse_ip(&first)?;
    let b = parse_ip(&later)?;
    assert_eq!(a.kind, PacketKind::Fragment);
    assert_eq!(a.key, b.key);
    assert!(a.transport.is_none() && b.transport.is_none());
    assert_eq!(
        b.ip.and_then(|meta| meta.fragment)
            .map(|fragment| fragment.offset_bytes),
        Some(8)
    );
    later[4] ^= 1;
    assert_ne!(a.key, parse_ip(&later)?.key);
    later[4] ^= 1;
    later[12..16].fill(2);
    later[16..20].fill(1);
    assert_ne!(a.key, parse_ip(&later)?.key);
    Ok(())
}

#[test]
fn ipv6_udp_and_bounded_extension_chain() -> TestResult {
    let segment = udp(53, 49152, b"payload");
    let mut chain = vec![
        43, 0, 0, 0, 0, 0, 0, 0, 60, 0, 0, 0, 0, 0, 0, 0, 51, 0, 0, 0, 0, 0, 0, 0, 17, 1, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0,
    ];
    chain.extend_from_slice(&segment);
    let bytes = v6(0, &chain);
    let result = parse_ip(&bytes)?;
    assert_eq!(result.kind, PacketKind::Udp);
    assert_eq!(
        result.ip.map(|ip| (ip.header_bytes, ip.dscp, ip.ecn)),
        Some((76, 46, 3))
    );
    assert_eq!(
        result.transport.map(|transport| transport.payload_bytes),
        Some(7)
    );
    let mut reverse = v6(17, &udp(49152, 53, b"reverse"));
    reverse[8..24].fill(2);
    reverse[24..40].fill(1);
    assert_eq!(result.key, parse_ip(&reverse)?.key);
    for limits in [
        ParseLimits {
            max_ipv6_extensions: 3,
            ..ParseLimits::default()
        },
        ParseLimits {
            max_ipv6_extension_bytes: 35,
            ..ParseLimits::default()
        },
        ParseLimits {
            max_ipv6_extensions: 0,
            ..ParseLimits::default()
        },
    ] {
        let limited = classify(PacketLayer::Ip, &bytes, limits)?;
        assert_eq!(
            limited.kind,
            PacketKind::Opaque(OpaqueReason::ExtensionLimit)
        );
        assert!(limited.transport.is_none());
    }
    for end in 0..bytes.len() {
        assert!(parse_ip(&bytes[..end]).is_err());
    }
    Ok(())
}

#[test]
fn ipv6_extension_truncation_and_unknown_headers_are_distinct() -> TestResult {
    for next in [0, 43, 44, 51, 60] {
        for size in 1..8 {
            let mut suffix = vec![0; size];
            if size > 1 && next == 51 {
                suffix[1] = 1;
            }
            assert!(parse_ip(&v6(next, &suffix)).is_err());
        }
    }
    let invalid_ah = v6(51, &[6, 0, 0, 0, 0, 0, 0, 0]);
    assert_eq!(
        parse_ip(&invalid_ah),
        Err(ParseError::Malformed(Header::Ipv6Extension))
    );
    let oversized_header = v6(60, &[6, 5, 0, 0, 0, 0, 0, 0]);
    assert_eq!(
        parse_ip(&oversized_header),
        Err(ParseError::Truncated(Header::Ipv6Extension))
    );
    for protocol in [50, 135, 253] {
        assert_eq!(
            parse_ip(&v6(protocol, b"opaque"))?.kind,
            PacketKind::Opaque(OpaqueReason::IpProtocol(protocol))
        );
    }
    assert_eq!(
        parse_ip(&v6(59, b""))?.kind,
        PacketKind::Opaque(OpaqueReason::NoNextHeader)
    );
    let mut jumbo = v6(0, &[17, 0, 0xc2, 4, 0, 1, 0, 0]);
    jumbo[4..6].fill(0);
    let result = parse_ip(&jumbo)?;
    assert_eq!(
        result.kind,
        PacketKind::Opaque(OpaqueReason::Ipv6JumbogramUnsupported)
    );
    assert_eq!(result.ip.and_then(|ip| ip.packet_bytes), None);
    assert!(result.transport.is_none());
    Ok(())
}

#[test]
fn ipv6_fragments_including_atomic_never_read_ports() -> TestResult {
    let mut fragment = vec![60, 0, 0, 1, 0x12, 0x34, 0x56, 0x78];
    fragment.extend_from_slice(&[0xee; 8]);
    let first = parse_ip(&v6(44, &fragment))?;
    fragment[2..4].copy_from_slice(&8u16.to_be_bytes());
    let later = parse_ip(&v6(44, &fragment))?;
    assert_eq!(first.key, later.key);
    assert_eq!(first.kind, PacketKind::Fragment);
    assert!(first.transport.is_none());
    fragment[2..4].fill(0);
    let atomic = parse_ip(&v6(44, &fragment[..8]))?;
    assert_eq!(atomic.key, first.key);
    assert_eq!(
        atomic
            .ip
            .and_then(|ip| ip.fragment)
            .map(|fragment| fragment.atomic),
        Some(true)
    );
    assert!(atomic.transport.is_none());
    Ok(())
}

#[test]
fn limits_ip_versions_and_opaque_protocols() -> TestResult {
    let packet = v4([1; 4], [2; 4], 1, b"ICMP");
    assert_eq!(
        parse_ip(&packet)?.kind,
        PacketKind::Opaque(OpaqueReason::IpProtocol(1))
    );
    for limits in [
        ParseLimits {
            max_packet_bytes: 0,
            ..ParseLimits::default()
        },
        ParseLimits {
            max_vlan_tags: 5,
            ..ParseLimits::default()
        },
        ParseLimits {
            max_ipv6_extensions: 17,
            ..ParseLimits::default()
        },
        ParseLimits {
            max_ipv6_extension_bytes: 4097,
            ..ParseLimits::default()
        },
    ] {
        assert_eq!(
            classify(PacketLayer::Ip, &packet, limits),
            Err(ParseError::InvalidLimits)
        );
    }
    assert_eq!(
        classify(
            PacketLayer::Ip,
            &packet,
            ParseLimits {
                max_packet_bytes: packet.len() - 1,
                ..ParseLimits::default()
            }
        ),
        Err(ParseError::PacketTooLarge)
    );
    assert_eq!(parse_ip(&[0x10]), Err(ParseError::UnknownIpVersion));
    let mut mismatch = ethernet(0x86dd, &[0; 40], &[]);
    mismatch[14] = 0x45;
    assert_eq!(
        classify(PacketLayer::Ethernet, &mismatch, ParseLimits::default()),
        Err(ParseError::Malformed(Header::Ipv6))
    );
    Ok(())
}

#[test]
fn bounded_header_mutations_and_extension_hard_limit() -> TestResult {
    let mut extensions = Vec::new();
    for index in 0..16 {
        extensions.extend_from_slice(&[if index == 15 { 6 } else { 60 }, 0, 0, 0, 0, 0, 0, 0]);
    }
    extensions.extend_from_slice(&tcp(1, 2, b"nonzero"));
    let packet = v6(60, &extensions);
    let maximum = ParseLimits {
        max_ipv6_extensions: 16,
        ..ParseLimits::default()
    };
    assert_eq!(
        classify(PacketLayer::Ip, &packet, maximum)?.kind,
        PacketKind::Tcp
    );
    assert_eq!(
        parse_ip(&packet)?.kind,
        PacketKind::Opaque(OpaqueReason::ExtensionLimit)
    );
    let one_byte = ParseLimits {
        max_ipv6_extension_bytes: 1,
        ..ParseLimits::default()
    };
    assert_eq!(
        classify(PacketLayer::Ip, &v6(60, &[0]), one_byte)?.kind,
        PacketKind::Opaque(OpaqueReason::ExtensionLimit)
    );
    // A finite byte-mutation corpus checks all branches and length nibbles. It
    // is not a substitute for the separately tracked ongoing fuzzing gate.
    let baseline = ethernet(0x86dd, &packet, &[(0x88a8, 1), (0x8100, 2)]);
    for offset in 0..baseline.len() {
        for value in 0..=255 {
            let mut changed = baseline.clone();
            changed[offset] = value;
            if let Ok(classification) = classify(PacketLayer::Ethernet, &changed, maximum) {
                assert_eq!(classification.observed_bytes, changed.len());
                assert!(classification.key.canonical_bytes().as_slice().len() <= 62);
                if classification.kind == PacketKind::Fragment {
                    assert!(classification.transport.is_none());
                }
            }
        }
    }
    Ok(())
}

#[test]
fn actual_python_mapping_golden_bytes_hashes_channels_and_reversal() -> TestResult {
    // Executed simulator DuplexMux._channel, with zlib.crc32 input captured.
    let vectors = [
        (
            [10, 0, 0, 1],
            12345,
            [10, 0, 0, 2],
            443,
            [6, 10, 0, 0, 1, 0x30, 0x39, 10, 0, 0, 2, 1, 0xbb],
            0x0d5c_7acc,
            [0, 2, 12, 204],
        ),
        (
            [192, 0, 2, 9],
            65535,
            [192, 0, 2, 9],
            1,
            [6, 192, 0, 2, 9, 0, 1, 192, 0, 2, 9, 255, 255],
            0xfb02_d3d2,
            [0, 2, 2, 210],
        ),
        (
            [255; 4],
            0,
            [0; 4],
            65535,
            [6, 0, 0, 0, 0, 255, 255, 255, 255, 255, 255, 0, 0],
            0x55d1_8bd5,
            [0, 1, 5, 213],
        ),
        (
            [10, 8, 0, 9],
            80,
            [10, 8, 0, 1],
            49152,
            [6, 10, 8, 0, 1, 192, 0, 10, 8, 0, 9, 0, 80],
            0x67e9_c1d3,
            [0, 2, 3, 211],
        ),
    ];
    for (source, sport, destination, dport, bytes, hash, channels) in vectors {
        let a = parse_ip(&v4(source, destination, 6, &tcp(sport, dport, b"")))?.key;
        let b = parse_ip(&v4(destination, source, 6, &tcp(dport, sport, b"")))?.key;
        assert_eq!(a, b);
        assert_eq!(a.python_tcp_bytes(), Some(bytes));
        assert_eq!(a.crc32(), hash);
        for (count, expected) in [1, 3, 16, 256].into_iter().zip(channels) {
            let mut table = FlowTable::new(FlowTableConfig {
                channels: count,
                ..table_config(Mapping::Crc32, 8)
            })?;
            assert_eq!(table.assign(a, Duration::ZERO)?.channel, expected);
            assert_eq!(
                table.assign(a, Duration::ZERO)?,
                table.assign(b, Duration::ZERO)?
            );
            assert_eq!(table.len(), 1);
        }
    }
    assert_eq!(crc32(b"123456789"), 0xcbf4_3926);
    Ok(())
}

#[test]
fn canonical_encoding_distinguishes_family_protocol_domain_and_endpoint_pairing() -> TestResult {
    let v4_tcp = parse_ip(&v4([1; 4], [2; 4], 6, &tcp(1, 2, b"")))?.key;
    let v4_udp = parse_ip(&v4([1; 4], [2; 4], 17, &udp(1, 2, b"")))?.key;
    let v6_tcp = parse_ip(&v6(6, &tcp(1, 2, b"")))?.key;
    let swapped_ports = parse_ip(&v4([1; 4], [2; 4], 6, &tcp(2, 1, b"")))?.key;
    let tagged = classify(
        PacketLayer::Ethernet,
        &ethernet(
            0x0800,
            &v4([1; 4], [2; 4], 6, &tcp(1, 2, b"")),
            &[(0x8100, 1)],
        ),
        ParseLimits::default(),
    )?
    .key;
    for other in [v4_udp, v6_tcp, swapped_ports, tagged] {
        assert_ne!(v4_tcp, other);
        assert_ne!(
            v4_tcp.canonical_bytes().as_slice(),
            other.canonical_bytes().as_slice()
        );
    }
    for other in [v4_udp, v6_tcp, tagged] {
        assert_eq!(other.python_tcp_bytes(), None);
    }
    let longest = classify(
        PacketLayer::Ethernet,
        &ethernet(0x86dd, &v6(6, &tcp(1, 2, b"")), &[(0x8100, 1); 4]),
        ParseLimits::default(),
    )?
    .key;
    assert_eq!(longest.canonical_bytes().as_slice().len(), 62);
    Ok(())
}

#[test]
fn round_robin_learned_affinity_and_simultaneous_open_conflicts() -> TestResult {
    let mut a = FlowTable::new(table_config(Mapping::ConnectionRoundRobin, 8))?;
    let mut b = FlowTable::new(table_config(Mapping::ConnectionRoundRobin, 8))?;
    let first = a.assign(key(1), Duration::ZERO)?;
    assert_eq!((first.id, first.channel), (FlowId(1), 0));
    assert_eq!(a.assign(key(1), Duration::ZERO)?, first);
    assert_eq!(b.learn(key(1), first.channel, Duration::ZERO)?.channel, 0);
    assert_eq!(b.assign(key(1), Duration::ZERO)?.channel, 0);
    // Learned identities do not consume the local RR cursor, as in Python.
    assert_eq!(b.assign(key(2), Duration::ZERO)?.channel, 0);
    assert_eq!(a.assign(key(2), Duration::ZERO)?.channel, 1);
    assert_eq!(
        a.learn(key(2), 0, Duration::ZERO),
        Err(FlowError::BindingConflict {
            expected: 1,
            received: 0
        })
    );
    assert_eq!(
        b.learn(key(2), 1, Duration::ZERO),
        Err(FlowError::BindingConflict {
            expected: 0,
            received: 1
        })
    );
    assert_eq!(a.assign(key(3), Duration::ZERO)?.channel, 2);
    assert_eq!(a.assign(key(4), Duration::ZERO)?.channel, 0);
    assert_eq!(
        a.learn(key(5), 3, Duration::ZERO),
        Err(FlowError::InvalidChannel)
    );
    assert_eq!(a.len(), 4);
    Ok(())
}

#[test]
fn capacity_idle_retirement_and_time_are_explicit() -> TestResult {
    let mut table = FlowTable::new(table_config(Mapping::ConnectionRoundRobin, 1))?;
    let first = table.assign(key(1), Duration::from_secs(1))?;
    assert_eq!(
        table.assign(key(2), Duration::from_secs(100)),
        Err(FlowError::Capacity)
    );
    assert_eq!(table.lookup(&key(1)), Some(first));
    assert_eq!(table.oldest_idle(Duration::from_secs(5))?, None);
    assert_eq!(
        table.retire_idle(&key(1), Duration::from_secs(5)),
        Err(FlowError::NotIdle)
    );
    // A packet at the deadline refreshes the entry instead of automatic eviction.
    assert_eq!(table.assign(key(1), Duration::from_secs(6))?, first);
    assert_eq!(
        table.assign(key(1), Duration::from_secs(5)),
        Err(FlowError::TimeRegression)
    );
    assert_eq!(
        table.oldest_idle(Duration::from_secs(5)),
        Err(FlowError::TimeRegression)
    );
    assert_eq!(
        table.retire_idle(&key(1), Duration::from_secs(5)),
        Err(FlowError::TimeRegression)
    );
    assert_eq!(
        table.oldest_idle(Duration::from_secs(11))?,
        Some((key(1), first))
    );
    assert_eq!(table.retire_idle(&key(1), Duration::from_secs(11))?, first);
    assert_eq!(
        table.retire_idle(&key(1), Duration::from_secs(11)),
        Err(FlowError::UnknownFlow)
    );
    let second = table.assign(key(1), Duration::from_secs(11))?;
    assert_eq!((second.id, second.channel), (FlowId(2), 1));
    assert_eq!(table.remove_drained(&key(1)), Some(second));
    assert_eq!(table.remove_drained(&key(1)), None);
    assert!(table.is_empty());
    Ok(())
}

#[test]
fn table_invalid_config_and_crc_channel_conflicts() -> TestResult {
    for config in [
        FlowTableConfig {
            capacity: 0,
            ..table_config(Mapping::Crc32, 1)
        },
        FlowTableConfig {
            capacity: 65537,
            ..table_config(Mapping::Crc32, 1)
        },
        FlowTableConfig {
            channels: 0,
            ..table_config(Mapping::Crc32, 1)
        },
        FlowTableConfig {
            channels: 257,
            ..table_config(Mapping::Crc32, 1)
        },
        FlowTableConfig {
            idle_timeout: Duration::ZERO,
            ..table_config(Mapping::Crc32, 1)
        },
    ] {
        assert!(matches!(
            FlowTable::new(config),
            Err(FlowError::InvalidConfig)
        ));
    }
    let mut table = FlowTable::new(table_config(Mapping::Crc32, 1))?;
    let expected = (key(1).crc32() % 3) as u16;
    let wrong = (expected + 1) % 3;
    assert_eq!(
        table.learn(key(1), wrong, Duration::ZERO),
        Err(FlowError::BindingConflict {
            expected,
            received: wrong
        })
    );
    assert!(table.is_empty());
    assert_eq!(
        table.learn(key(1), expected, Duration::ZERO)?.channel,
        expected
    );
    assert_eq!(
        table.learn(key(2), (key(2).crc32() % 3) as u16, Duration::ZERO),
        Err(FlowError::Capacity)
    );
    Ok(())
}
