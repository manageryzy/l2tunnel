use super::*;
use aligned_body::{BodyKind, Decoded, Decoder, Padding};

fn frame(protocol: u16, body: &[u8], tags: usize) -> Vec<u8> {
    let mut bytes = vec![2, 0, 0, 0, 0, 2, 2, 0, 0, 0, 0, 1];
    for index in 0..tags {
        let tpid: u16 = [0x8100, 0x88a8, 0x9100][index % 3];
        bytes.extend_from_slice(&tpid.to_be_bytes());
        bytes.extend_from_slice(&(0xa001 + index as u16).to_be_bytes());
    }
    bytes.extend_from_slice(&protocol.to_be_bytes());
    bytes.extend_from_slice(body);
    bytes
}

fn udp4(payload: &[u8]) -> Vec<u8> {
    let mut bytes = ip(1);
    bytes.truncate(28);
    bytes.extend_from_slice(payload);
    let length = bytes.len() as u16;
    bytes[2..4].copy_from_slice(&length.to_be_bytes());
    bytes[24..26].copy_from_slice(&(length - 20).to_be_bytes());
    bytes
}

fn ipv6(next: u8, payload: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0; 40];
    bytes[0] = 0x60;
    bytes[4..6].copy_from_slice(&(payload.len() as u16).to_be_bytes());
    bytes[6] = next;
    bytes[7] = 64;
    bytes[8] = 0x20;
    bytes[9] = 1;
    bytes[23] = 1;
    bytes[24] = 0x20;
    bytes[25] = 1;
    bytes[39] = 2;
    bytes.extend_from_slice(payload);
    bytes
}

fn udp6(payload: &[u8]) -> Vec<u8> {
    let mut udp = vec![0; 8];
    udp[..2].copy_from_slice(&1000u16.to_be_bytes());
    udp[2..4].copy_from_slice(&1001u16.to_be_bytes());
    udp[4..6].copy_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
    udp.extend_from_slice(payload);
    ipv6(17, &udp)
}

fn arp() -> Vec<u8> {
    let mut bytes = vec![0; 28];
    bytes[..2].copy_from_slice(&1u16.to_be_bytes());
    bytes[2..4].copy_from_slice(&0x0800u16.to_be_bytes());
    bytes[4] = 6;
    bytes[5] = 4;
    bytes[6..8].copy_from_slice(&1u16.to_be_bytes());
    bytes[8..14].copy_from_slice(&[2, 0, 0, 0, 0, 1]);
    bytes[14..18].copy_from_slice(&[192, 0, 2, 1]);
    bytes[24..28].copy_from_slice(&[192, 0, 2, 2]);
    bytes
}

fn unit(
    derived: &Fixture,
    channel: u8,
    record: u64,
    bytes: &[u8],
    ordinary: bool,
) -> Result<Vec<u8>> {
    let policy = derived.packed.protocol.base.receiver.body;
    let mut encoder = aligned_body::Encoder::new(policy)?;
    let mut encoded = vec![0; encoder.max_encoded_len()];
    let written = if ordinary {
        encoder.encode(bytes, &mut encoded)?
    } else {
        encoder.encode_raw(bytes, &mut encoded)?
    };
    assert_eq!(written.context_len, 0);
    let body = &encoded[..written.body_len];
    let mut restored = vec![0; 1600];
    let mut decoder = Decoder::new(policy)?;
    let Decoded::Frame {
        written,
        kind: BodyKind::Raw,
        ..
    } = decoder.decode_body(body, Padding::Exact, &mut restored)?
    else {
        return Err("fixture did not produce an actual raw body".into());
    };
    assert_eq!(&restored[..written], bytes);
    let mut result = vec![channel];
    result.extend_from_slice(&(record as u16).to_be_bytes());
    result.extend_from_slice(body);
    Ok(result)
}

fn inspect_frames(bytes: &[u8]) -> Result<Value> {
    let mut value = settings();
    value["layer"] = json!("tap");
    let (config, derived) = configure(&value)?;
    let payload = source(
        &derived,
        0,
        0,
        0,
        &[
            unit(&derived, 0, 0, bytes, false)?,
            unit(&derived, 1, 1, bytes, false)?,
        ],
        &[0, 1],
    )?;
    let packets = recovery_packets(&derived, 0, &[payload])?;
    audit::inspect(&config, &derived, &seal(&config, &derived, 0, &packets)?)
}

fn qualifies(bytes: &[u8], expected: usize) -> Result<()> {
    let result = inspect_frames(bytes)?;
    let row = &result["directions"][0];
    assert_eq!(row["sources"], 1);
    assert_eq!(row["multi_unit_sources"], 1);
    assert_eq!(row["complete_packet_aggregation_sources"], expected);
    assert_eq!(row["duplicate_sources"], 1);
    Ok(())
}

#[test]
fn production_small_udp_frames_use_ordinary_raw_encoding_in_both_duplex_modes() -> Result<()> {
    for cover in ["quic-like", "openvpn-like"] {
        for duplex in ["half", "full"] {
            let mut value = settings();
            value["layer"] = json!("tap");
            value["cover"] = json!(cover);
            value["duplex"] = json!(duplex);
            let (config, derived) = configure(&value)?;
            let mut input = Vec::new();
            for direction in 0..2 {
                let prefix = [b'L', b'2', b'B', b'1', direction, 0];
                let digest = ring::digest::digest(&ring::digest::SHA256, &prefix);
                let mut payload = prefix.to_vec();
                payload.extend_from_slice(digest.as_ref());
                payload.extend_from_slice(&digest.as_ref()[..26]);
                assert_eq!(payload.len(), 64);
                let a = frame(0x0800, &udp4(&payload), 0);
                let b = frame(0x86dd, &udp6(&payload), 0);
                assert_eq!((a.len(), b.len()), (106, 126));
                let packed = source(
                    &derived,
                    direction,
                    0,
                    0,
                    &[
                        unit(&derived, 0, 0, &a, true)?,
                        unit(&derived, 1, 1, &b, true)?,
                    ],
                    &[0, 1],
                )?;
                let packets = recovery_packets(&derived, direction, &[packed])?;
                input.extend(seal(&config, &derived, direction, &packets)?);
            }
            let result = audit::inspect(&config, &derived, &input)?;
            assert_eq!(result["scope"], "structural-only");
            for direction in 0..2 {
                let row = &result["directions"][direction];
                assert_eq!(row["sources"], 1);
                assert_eq!(row["complete_packet_aggregation_sources"], 1);
                assert_eq!(row["duplicate_sources"], 1);
            }
        }
    }
    Ok(())
}

#[test]
fn vlan_ip_and_arp_preserve_exact_or_minimum_padded_frames() -> Result<()> {
    for tags in 0..=4 {
        for (protocol, packet) in [(0x0800, udp4(&[3; 64])), (0x86dd, udp6(&[4; 64]))] {
            qualifies(&frame(protocol, &packet, tags), 1)?;
        }
        let mut packet = arp();
        // An unrecognized operation is still a complete standard address format.
        packet[6..8].copy_from_slice(&u16::MAX.to_be_bytes());
        let exact = frame(0x0806, &packet, tags);
        assert_eq!(exact.len(), 42 + tags * 4);
        qualifies(&exact, 1)?;
        let mut padded = exact;
        padded.resize(60, 0xa5);
        qualifies(&padded, 1)?;
    }
    for exact in [frame(0x0800, &ip(2), 0), frame(0x86dd, &ipv6(59, &[]), 0)] {
        assert!(exact.len() < 60);
        qualifies(&exact, 1)?;
        let mut padded = exact;
        padded.resize(60, 0x9b);
        qualifies(&padded, 1)?;
    }
    Ok(())
}

#[test]
fn options_extensions_and_native_fragments_count_whole_packets_only() -> Result<()> {
    let mut options = udp4(&[5; 8]);
    options.splice(20..20, [1, 1, 1, 1]);
    options[0] = 0x46;
    let length = options.len() as u16;
    options[2..4].copy_from_slice(&length.to_be_bytes());
    qualifies(&frame(0x0800, &options, 1), 1)?;
    let ordinary6 = udp6(&[6; 8]);
    let mut extension = vec![17, 0, 0, 0, 0, 0, 0, 0];
    extension.extend_from_slice(&ordinary6[40..]);
    qualifies(&frame(0x86dd, &ipv6(60, &extension), 2), 1)?;
    for bits in [0x2000u16, 1] {
        let mut fragment = udp4(&[7; 8]);
        fragment[6..8].copy_from_slice(&bits.to_be_bytes());
        qualifies(&frame(0x0800, &fragment, 0), 1)?;
    }
    for bits in [0u16, 1, 8] {
        let mut fragment = vec![17, 0, 0, 0, 1, 2, 3, 4];
        fragment[2..4].copy_from_slice(&bits.to_be_bytes());
        fragment.extend_from_slice(&[8; 8]);
        qualifies(&frame(0x86dd, &ipv6(44, &fragment), 0), 1)?;
    }
    let mut unknown_transport = ip(1);
    unknown_transport[9] = 253;
    qualifies(&frame(0x0800, &unknown_transport, 0), 1)?;
    Ok(())
}

#[test]
fn opaque_link_formats_and_bounded_inspection_exhaustion_supply_no_witness() -> Result<()> {
    qualifies(&frame(0x88b5, &udp4(&[9; 8]), 0), 0)?;
    qualifies(&frame(36, &ip(1), 0), 0)?;
    qualifies(&frame(0x0800, &ip(1), 5), 0)?;
    let mut unsupported_arp = arp();
    unsupported_arp[1] = 2;
    qualifies(&frame(0x0806, &unsupported_arp, 0), 0)?;
    qualifies(&frame(0x86dd, &ipv6(0, &[]), 0), 0)?;
    let mut extensions = Vec::new();
    for index in 0..9 {
        extensions.extend_from_slice(&[if index == 8 { 59 } else { 60 }, 0, 0, 0, 0, 0, 0, 0]);
    }
    qualifies(&frame(0x86dd, &ipv6(60, &extensions), 0), 0)?;
    let mut oversized_extension = vec![0; 264];
    oversized_extension[0] = 59;
    oversized_extension[1] = 32;
    qualifies(&frame(0x86dd, &ipv6(60, &oversized_extension), 0), 0)?;
    Ok(())
}

#[test]
fn arbitrary_suffix_and_fcs_lookalike_never_become_inferred_packet_bytes() -> Result<()> {
    for size in [43, 59, 61] {
        let mut bytes = frame(0x0806, &arp(), 0);
        bytes.resize(size, 0xa5);
        qualifies(&bytes, 0)?;
    }
    for (protocol, body) in [(0x0800, udp4(&[1; 64])), (0x86dd, udp6(&[2; 64]))] {
        for extra in [1, 4] {
            let mut bytes = frame(protocol, &body, 0);
            bytes.extend(std::iter::repeat_n(0x7b, extra));
            qualifies(&bytes, 0)?;
        }
    }
    Ok(())
}

#[test]
fn malformed_supported_ethernet_structure_fails_the_entire_audit() -> Result<()> {
    let mut malformed = vec![
        Vec::new(),
        vec![0; 13],
        frame(0x8100, &[], 0),
        frame(0x0806, &[0; 7], 0),
        frame(0x0800, &[0; 19], 0),
        frame(0x86dd, &[0; 39], 0),
        frame(100, &[0; 99], 0),
    ];
    let mut packet = ip(1);
    packet[0] = 0x65;
    malformed.push(frame(0x0800, &packet, 0));
    packet = ip(1);
    packet[0] = 0x44;
    malformed.push(frame(0x0800, &packet, 0));
    packet = ip(1);
    packet[3] = 37;
    malformed.push(frame(0x0800, &packet, 0));
    packet = ip(1);
    packet[25] = 7;
    malformed.push(frame(0x0800, &packet, 0));
    malformed.push(frame(0x86dd, &ipv6(60, &[59, 1, 0, 0, 0, 0, 0, 0]), 0));
    for bytes in malformed {
        assert!(
            inspect_frames(&bytes).is_err(),
            "accepted malformed frame {bytes:02x?}"
        );
    }
    Ok(())
}

#[test]
fn duplicate_native_identity_and_codec_fragments_cannot_manufacture_aggregation() -> Result<()> {
    let mut value = settings();
    value["layer"] = json!("tap");
    let (config, derived) = configure(&value)?;
    let bytes = frame(0x0800, &ip(1), 0);
    let a = unit(&derived, 0, 0, &bytes, false)?;
    let mut context = vec![0; 72];
    context[0] = 1;
    context[2] = 1;
    context[5] = 66;
    let fragment = vec![2, 0, 2, 4, 0, 4, 0, 0, 2, 0, 1, 9];
    for (units, records, expected) in [
        (vec![a.clone(), a.clone()], vec![0, 0], 0),
        (vec![context, fragment], vec![1, 2], 0),
        (vec![a, unit(&derived, 1, 0, &bytes, false)?], vec![0, 0], 1),
    ] {
        let payload = source(&derived, 0, 0, 0, &units, &records)?;
        let packets = recovery_packets(&derived, 0, &[payload])?;
        let result = audit::inspect(&config, &derived, &seal(&config, &derived, 0, &packets)?)?;
        assert_eq!(
            result["directions"][0]["complete_packet_aggregation_sources"],
            expected
        );
        assert_eq!(result["directions"][0]["sources"], 1);
        assert_eq!(result["directions"][0]["duplicate_sources"], 1);
    }
    Ok(())
}
