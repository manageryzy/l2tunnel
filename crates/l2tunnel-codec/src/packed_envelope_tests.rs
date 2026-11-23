#![allow(clippy::unwrap_used)]
use super::*;
use crate::aligned_receiver::Direction;
use l2tunnel_core::Epoch;

fn config() -> Config {
    Config {
        symbol_bytes: 1460,
        channels: 4,
        max_units: 16,
    }
}
fn identity() -> Identity {
    Identity {
        scope: Scope {
            session: [11; 16],
            epoch: Epoch(7),
            direction: Direction::InitiatorToResponder,
        },
        source: SourceId(1234),
        first_unit: SourceId(9876),
    }
}
fn unit(channel: u8, serial: u16, payload: &[u8]) -> Vec<u8> {
    let mut result = vec![channel];
    result.extend(serial.to_be_bytes());
    result.push(2);
    result.extend((payload.len() as u16).to_be_bytes());
    result.extend(payload);
    result
}
fn container(units: &[Vec<u8>]) -> Vec<u8> {
    let mut bytes = vec![255, units.len() as u8];
    for unit in units {
        bytes.extend((unit.len() as u16).to_be_bytes());
        bytes.extend(unit);
    }
    bytes
}

fn ack_config() -> AckLz4Config {
    AckLz4Config {
        packed: config(),
        max_source_bytes: 1460,
        max_ack_bytes: 128,
    }
}

#[cfg(feature = "lz4")]
fn ack_source(packets: &[Vec<u8>]) -> Vec<u8> {
    let ident = identity();
    let records: Vec<_> = (0..packets.len())
        .map(|i| RecordId(3463 + i as u64))
        .collect();
    let units: Vec<_> = packets
        .iter()
        .zip(&records)
        .map(|(p, r)| unit(0, r.0 as u16, p))
        .collect();
    let payload = if units.len() == 1 {
        units[0].clone()
    } else {
        container(&units)
    };
    let mut plain = vec![0; 1460];
    let n = encode_compact(config(), ident, &records, &payload, &mut plain).unwrap();
    plain.truncate(n);
    plain
}

#[cfg(feature = "lz4")]
fn test_ack() -> Vec<u8> {
    let mut b = vec![0; 64];
    b[0] = 0x45;
    b[2..4].copy_from_slice(&64u16.to_be_bytes());
    b[6] = 0x40;
    b[8] = 64;
    b[9] = 6;
    b[12..20].copy_from_slice(&[10, 0, 0, 2, 10, 0, 0, 1]);
    b[20..24].copy_from_slice(&[0, 80, 1, 2]);
    b[32] = 0xb0;
    b[33] = 0x10;
    b[40..52].copy_from_slice(&[1, 1, 8, 10, 0, 0, 0, 12, 0, 0, 0, 9]);
    b[52..64].copy_from_slice(&[1, 1, 5, 10, 0, 0, 1, 0, 0, 1, 0, 0]);
    b
}

#[cfg(feature = "lz4")]
#[test]
fn ack_lz4_exact_packed_bytes_and_independent_sources() {
    let cfg = ack_config();
    let id = identity();
    let mut table = AckLz4Table::new().unwrap();
    assert_eq!((table.allocations(), table.capacity_bytes()), (1, 8192));
    let mut work = vec![0x55; cfg.encode_scratch_len().unwrap()];
    let mut packets = vec![test_ack(); 8];
    packets[1][33] |= 0xc0;
    let a = ack_source(&packets);
    packets[3][26] = 123;
    let b = ack_source(&packets);
    let mut frames = Vec::new();
    for plain in [&a, &b] {
        let n = cfg
            .try_encode(id.scope, id.source, plain, &mut work, &mut table)
            .unwrap()
            .unwrap();
        assert!(n < plain.len());
        assert_eq!(
            &work[..3],
            &[0, (plain.len() >> 8) as u8, plain.len() as u8]
        );
        frames.push(work[..n].to_vec());
        assert!(decode_compact(config(), id.scope, id.source, &work[..n]).is_err());
    }
    // Restore B before A and with no other source available. The final zero bytes matter.
    for (wire, plain) in frames.iter().zip([&a, &b]).rev() {
        let mut result = vec![0xa5; 1460];
        assert_eq!(
            cfg.decode(id.scope, id.source, wire, &mut result).unwrap(),
            Some(plain.len())
        );
        assert_eq!(&result[..plain.len()], &plain[..]);
        assert!(result[plain.len()..].iter().all(|&b| b == 0xa5));
        assert_eq!(&plain[plain.len() - 2..], &[0, 0]);
        assert_eq!(
            cfg.decode(id.scope, id.source, plain, &mut []).unwrap(),
            None
        );
    }
}

#[cfg(feature = "lz4")]
#[test]
fn ack_lz4_rejects_non_ack_units_and_malformed_or_oversized_blocks() {
    let cfg = ack_config();
    let id = identity();
    let mut table = AckLz4Table::new().unwrap();
    let mut work = vec![0; cfg.encode_scratch_len().unwrap()];
    for (off, value) in [
        (0, 0x65),
        (6, 0x60),
        (7, 1),
        (9, 17),
        (3, 65),
        (32, 0x90),
        (33, 0x12),
        (33, 0x14),
        (33, 0x11),
        (33, 0x18),
        (55, 9),
    ] {
        let mut bad = test_ack();
        bad[off] = value;
        let plain = ack_source(&[test_ack(), bad]);
        assert_eq!(
            cfg.try_encode(id.scope, id.source, &plain, &mut work, &mut table)
                .unwrap(),
            None
        );
        // An authenticated peer cannot relabel this mixed source as a compressed ACK block.
        let mut forged = vec![0, (plain.len() >> 8) as u8, plain.len() as u8];
        forged.extend(lz4_flex::block::compress(&plain));
        assert!(forged.len() < plain.len());
        assert!(cfg.decode(id.scope, id.source, &forged, &mut work).is_err());
    }
    let raw = ack_source(&[test_ack(), test_ack()]);
    let n = cfg
        .try_encode(id.scope, id.source, &raw, &mut work, &mut table)
        .unwrap()
        .unwrap();
    let valid = work[..n].to_vec();
    assert!(matches!(
        cfg.try_encode(id.scope, id.source, &raw, &mut [0; 8], &mut table),
        Err(Error::OutputTooSmall { .. })
    ));
    assert_eq!(
        cfg.decode(id.scope, id.source, &valid, &mut [0; 8]),
        Err(Error::OutputTooSmall { needed: raw.len() })
    );
    let mut undersized = valid.clone();
    undersized[1..3].copy_from_slice(&((raw.len() - 1) as u16).to_be_bytes());
    let mut longer = valid.clone();
    longer[1..3].copy_from_slice(&((raw.len() + 1) as u16).to_be_bytes());
    let mut padded = valid.clone();
    padded.push(0);
    for bytes in [
        &[][..],
        &[0],
        &[0, 0, 99],
        &[0, 0, 4, 0],
        &[0, 0xff, 0xff, 0],
        &valid[..n - 1],
        &undersized,
        &longer,
        &padded,
    ] {
        assert!(cfg.decode(id.scope, id.source, bytes, &mut work).is_err());
    }
    let small = AckLz4Config {
        max_source_bytes: raw.len() - 1,
        ..cfg
    };
    assert!(
        small
            .decode(id.scope, id.source, &valid, &mut work)
            .is_err()
    );
    assert!(
        small
            .try_encode(id.scope, id.source, &raw, &mut work, &mut table)
            .is_err()
    );
    let mut invalid = raw.clone();
    invalid[1] = 9;
    assert!(
        cfg.try_encode(id.scope, id.source, &invalid, &mut work, &mut table)
            .is_err()
    );
    let mut fragment = vec![0, 0, 1, 4, 0, 8, 0, 0];
    fragment.extend([0; 8]);
    let mut envelope = [0; 64];
    let n = encode_compact(config(), id, &[RecordId(1)], &fragment, &mut envelope).unwrap();
    assert_eq!(
        cfg.try_encode(id.scope, id.source, &envelope[..n], &mut work, &mut table)
            .unwrap(),
        None
    );
}

#[cfg(feature = "lz4")]
#[test]
fn ack_lz4_incompressible_plain_and_all_nonzero_unit_counts_are_unambiguous() {
    let cfg = ack_config();
    let id = identity();
    let mut table = AckLz4Table::new().unwrap();
    let mut work = vec![0; cfg.encode_scratch_len().unwrap()];
    let mut ip: Vec<_> = (0u8..40)
        .map(|i| i.wrapping_mul(71).wrapping_add(57))
        .collect();
    ip[0] = 0x45;
    ip[2..4].copy_from_slice(&40u16.to_be_bytes());
    ip[6..8].copy_from_slice(&[0x40, 0]);
    ip[9] = 6;
    ip[32] = 0x50;
    ip[33] = 0x10;
    assert!(crate::tcp_header::pure_ipv4_ack(&ip));
    let plain = ack_source(&[ip]);
    assert_eq!(
        cfg.try_encode(id.scope, id.source, &plain, &mut work, &mut table)
            .unwrap(),
        None
    );
    let wide = Config {
        symbol_bytes: 8192,
        channels: 4,
        max_units: 255,
    };
    let records: Vec<_> = (0..255).map(RecordId).collect();
    let raw: Vec<_> = records.iter().map(|r| unit(1, r.0 as u16, &[42])).collect();
    let mut source = vec![0; wide.max_source_bytes().unwrap()];
    let n = encode_compact(wide, id, &records, &container(&raw), &mut source).unwrap();
    assert_eq!(source[0], 255);
    assert_eq!(
        decode_compact(wide, id.scope, id.source, &source[..n])
            .unwrap()
            .units()
            .unwrap()
            .len(),
        255
    );
    assert_eq!(
        AckLz4Config {
            packed: wide,
            max_source_bytes: n,
            ..cfg
        }
        .decode(id.scope, id.source, &source[..n], &mut [])
        .unwrap(),
        None
    );
    source[0] = 0;
    assert!(decode_compact(wide, id.scope, id.source, &source[..n]).is_err());
}

#[cfg(not(feature = "lz4"))]
#[test]
fn ack_lz4_provider_absent_is_explicit_and_preserves_plain_source() {
    let cfg = ack_config();
    let id = identity();
    assert!(matches!(
        AckLz4Table::new(),
        Err(Error::CompressionUnavailable)
    ));
    assert_eq!(cfg.encode_scratch_len(), Err(Error::CompressionUnavailable));
    assert_eq!(
        cfg.decode(id.scope, id.source, &[0, 0, 20, 0], &mut []),
        Err(Error::CompressionUnavailable)
    );
    assert_eq!(
        cfg.decode(
            id.scope,
            id.source,
            &[1, 1, 0, 0, 0, 0, 0, 2, 0, 1, 42],
            &mut []
        ),
        Ok(None)
    );
}
fn source(identity: Identity, records: &[RecordId], payload: &[u8]) -> Vec<u8> {
    let mut output = vec![0xaa; config().max_source_bytes().unwrap()];
    let length = encode(config(), identity, records, payload, &mut output).unwrap();
    assert!(output[length..].iter().all(|byte| *byte == 0xaa));
    output.truncate(length);
    output
}

#[test]
fn compact_source_keeps_full_identities_and_bounded_canonical_record_lists() {
    for record in [0, 127, 128, 65536, u64::MAX] {
        let identity = identity();
        let payload = unit(0, record as u16, b"opaque\0\0");
        let mut output = vec![0xa5; config().max_source_bytes().unwrap()];
        let length = encode_compact(
            config(),
            identity,
            &[RecordId(record)],
            &payload,
            &mut output,
        )
        .unwrap();
        let view =
            decode_compact(config(), identity.scope, identity.source, &output[..length]).unwrap();
        assert_eq!(view.identity(), identity);
        assert_eq!(view.payload(), payload);
        let parsed = view.units().unwrap().next().unwrap();
        assert_eq!(parsed.identity.record, RecordId(record));
        assert_eq!(parsed.identity.source, identity.first_unit);
        assert!(length < HEADER_BYTES + 8 + payload.len());
        assert!(output[length..].iter().all(|byte| *byte == 0xa5));
        for end in 0..length {
            assert!(
                decode_compact(config(), identity.scope, identity.source, &output[..end]).is_err()
            );
        }
        let mut short = vec![0xa5; length - 1];
        assert_eq!(
            encode_compact(
                config(),
                identity,
                &[RecordId(record)],
                &payload,
                &mut short
            ),
            Err(Error::OutputTooSmall { needed: length })
        );
        assert!(short.iter().all(|byte| *byte == 0xa5));
    }
    let identity = identity();
    let payload = container(&[unit(0, 65535, b"one"), unit(1, 0, b"two")]);
    let mut output = vec![0; config().max_source_bytes().unwrap()];
    let length = encode_compact(
        config(),
        identity,
        &[RecordId(u64::MAX), RecordId(65536)],
        &payload,
        &mut output,
    )
    .unwrap();
    let view =
        decode_compact(config(), identity.scope, identity.source, &output[..length]).unwrap();
    assert_eq!(
        view.units()
            .unwrap()
            .map(|unit| unit.identity.record.0)
            .collect::<Vec<_>>(),
        [u64::MAX, 65536]
    );
    // Unknown flags and nonminimal scalar encodings have no alternate interpretation.
    output[1] = 2;
    assert!(decode_compact(config(), identity.scope, identity.source, &output[..length]).is_err());
    assert!(decode_compact(config(), identity.scope, identity.source, &[1, 1, 0x80, 0]).is_err());
}

#[test]
fn exact_header_and_distinct_source_unit_record_spaces_round_trip() {
    for direction in [
        Direction::InitiatorToResponder,
        Direction::ResponderToInitiator,
    ] {
        let mut identity = identity();
        identity.scope.direction = direction;
        let units = [
            unit(0, 65535, b"first"),
            unit(1, 0, b"second"),
            unit(0, 0, b"third"),
        ];
        let records = [RecordId(65535), RecordId(131072), RecordId(65536)];
        let payload = container(&units);
        let bytes = source(identity, &records, &payload);
        assert_eq!(&bytes[..5], b"L2PK\x01");
        assert_eq!(bytes[6], 3);
        assert_eq!(&bytes[8..10], &1460_u16.to_be_bytes());
        assert_eq!(&bytes[36..44], &1234_u64.to_be_bytes());
        assert_eq!(&bytes[44..52], &9876_u64.to_be_bytes());
        assert_eq!(bytes.len(), 56 + 8 * 3 + payload.len());
        let view = decode(config(), identity.scope, &bytes).unwrap();
        assert_eq!(view.identity(), identity);
        assert_eq!(view.len(), 3);
        assert!(!view.is_empty());
        assert_eq!(view.payload(), payload);
        let mut iter = view.units().unwrap();
        assert_eq!(iter.len(), 3);
        for index in 0..3 {
            let value = iter.next().unwrap();
            assert_eq!(value.bytes, units[index]);
            assert_eq!(value.identity.source, SourceId(9876 + index as u64));
            assert_eq!(value.identity.record, records[index]);
            assert_eq!(value.identity.scope, identity.scope);
            assert_ne!(value.identity.source, identity.source);
        }
        assert!(iter.next().is_none());
        assert!(iter.next().is_none());
        assert_eq!(iter.len(), 0);
    }
}

#[test]
fn single_fragment_and_last_nonwrapping_id_remain_exact() {
    let mut identity = identity();
    identity.source = SourceId(u64::MAX);
    identity.first_unit = SourceId(u64::MAX);
    let mut fragment = vec![2, 0xff, 0xff, 4];
    fragment.extend(1500_u16.to_be_bytes());
    fragment.extend(1452_u16.to_be_bytes());
    fragment.extend([73; 48]);
    let bytes = source(identity, &[RecordId(u64::MAX)], &fragment);
    let view = decode(config(), identity.scope, &bytes).unwrap();
    let value = view.units().unwrap().next().unwrap();
    assert_eq!(value.bytes, fragment);
    assert_eq!(value.identity.source, SourceId(u64::MAX));
    assert_eq!(value.identity.record, RecordId(u64::MAX));
    let payload = container(&[unit(0, 0, b"a"), unit(1, 1, b"b")]);
    let mut output = [0xa5; 200];
    assert_eq!(
        encode(
            config(),
            identity,
            &[RecordId(0), RecordId(1)],
            &payload,
            &mut output
        ),
        Err(Error::Exhausted)
    );
    assert_eq!(output, [0xa5; 200]);
}

#[test]
fn every_truncation_scope_length_identity_and_reserved_byte_is_checked() {
    let identity = identity();
    let payload = container(&[unit(0, 10, b"hello"), unit(1, 20, b"world")]);
    let bytes = source(identity, &[RecordId(10), RecordId(20)], &payload);
    for length in 0..bytes.len() {
        assert!(
            decode(config(), identity.scope, &bytes[..length]).is_err(),
            "length {length}"
        );
    }
    for offset in [0, 4, 5, 7, 8, 10, 12, 28, 52, 53, 54, 55] {
        let mut changed = bytes.clone();
        changed[offset] ^= 0x80;
        assert!(
            decode(config(), identity.scope, &changed).is_err(),
            "offset {offset}"
        );
    }
    for count in [0, 1, 3, 17, 255] {
        let mut changed = bytes.clone();
        changed[6] = count;
        assert!(decode(config(), identity.scope, &changed).is_err());
    }
    for offset in [HEADER_BYTES + 7, HEADER_BYTES + 15] {
        let mut changed = bytes.clone();
        changed[offset] ^= 1;
        assert!(matches!(
            decode(config(), identity.scope, &changed),
            Err(Error::Identity)
        ));
    }
    let mut changed = bytes.clone();
    changed[44..52].copy_from_slice(&u64::MAX.to_be_bytes());
    assert!(matches!(
        decode(config(), identity.scope, &changed),
        Err(Error::Exhausted)
    ));
    let mut wrong = identity.scope;
    wrong.epoch.0 += 1;
    assert!(matches!(decode(config(), wrong, &bytes), Err(Error::Scope)));
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(decode(config(), identity.scope, &trailing).is_err());
    // Even when the declared payload length includes the zero, canonical
    // envelopes do not accept coding padding as meaningful container bytes.
    trailing[10..12].copy_from_slice(&((payload.len() + 1) as u16).to_be_bytes());
    assert!(decode(config(), identity.scope, &trailing).is_err());
}

#[test]
fn encoding_validation_is_atomic_for_all_bounds_and_inner_errors() {
    let identity = identity();
    let payload = unit(0, 0, b"native opaque bytes");
    let needed = HEADER_BYTES + 8 + payload.len();
    for length in 0..needed {
        let mut output = vec![0x99; length];
        assert_eq!(
            encode(config(), identity, &[RecordId(0)], &payload, &mut output),
            Err(Error::OutputTooSmall { needed })
        );
        assert_eq!(output, vec![0x99; length]);
    }
    for cfg in [
        Config {
            channels: 0,
            ..config()
        },
        Config {
            channels: 256,
            ..config()
        },
        Config {
            max_units: 0,
            ..config()
        },
        Config {
            symbol_bytes: 65535,
            ..config()
        },
        Config {
            symbol_bytes: 8,
            ..config()
        },
    ] {
        assert!(cfg.max_source_bytes().is_err());
    }
    let mut output = [0xbb; 2048];
    for (records, bytes) in [
        (vec![], payload.clone()),
        (vec![RecordId(1)], payload.clone()),
        (vec![RecordId(0)], unit(4, 0, b"bad channel")),
        (vec![RecordId(0)], vec![255, 0, 0, 5]),
        (vec![RecordId(0), RecordId(0)], payload),
        (
            vec![RecordId(0), RecordId(0)],
            container(&[unit(0, 0, b"ok"), vec![1, 0, 0, 3, 0]]),
        ),
    ] {
        assert!(encode(config(), identity, &records, &bytes, &mut output).is_err());
        assert_eq!(output, [0xbb; 2048]);
    }
}
