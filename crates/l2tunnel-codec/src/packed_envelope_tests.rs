#![allow(clippy::unwrap_used)]
use super::*;

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
fn source(identity: Identity, records: &[RecordId], payload: &[u8]) -> Vec<u8> {
    let mut output = vec![0xaa; config().max_source_bytes().unwrap()];
    let length = encode(config(), identity, records, payload, &mut output).unwrap();
    assert!(output[length..].iter().all(|byte| *byte == 0xaa));
    output.truncate(length);
    output
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
