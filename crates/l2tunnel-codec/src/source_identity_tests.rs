use super::*;
use crate::{
    aligned_envelope,
    aligned_receiver::{RecordId, SymbolIdentity},
    packed_envelope,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn identity(direction: Direction) -> Identity {
    Identity {
        scope: Scope {
            session: [
                0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
                0x1e, 0x1f,
            ],
            epoch: Epoch(0x2021_2223_2425_2627),
            direction,
        },
        source: SourceId(0x3031_3233_3435_3637),
    }
}
fn packed_config() -> packed_envelope::Config {
    packed_envelope::Config {
        symbol_bytes: 32,
        channels: 3,
        max_units: 2,
    }
}
const RECORD: RecordId = RecordId(0x4041_4243_4445_fffe);
const SYMBOL: [u8; 12] = [2, 0xff, 0xfe, 2, 0, 3, 0xa1, 0, 0, 0, 0, 0];
const PAYLOAD: [u8; 24] = [
    255, 2, 0, 9, 2, 0xff, 0xfe, 2, 0, 3, 0xa1, 0, 0, 0, 9, 0, 0, 0, 2, 0, 3, 0xa2, 0, 0,
];

#[test]
fn legacy_identity_layouts_remain_byte_exact_and_borrowed() -> TestResult {
    for (direction, code) in [
        (Direction::InitiatorToResponder, 0),
        (Direction::ResponderToInitiator, 1),
    ] {
        let id = identity(direction);
        let aligned_id = SymbolIdentity {
            scope: id.scope,
            source: id.source,
            record: RECORD,
        };
        let mut aligned = [0xa5; 61];
        let length = aligned_envelope::encode(aligned_id, &SYMBOL, &mut aligned)?;
        let mut expected = vec![
            b'L', b'2', b'A', b'S', 1, code, 0, 12, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
            0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25,
            0x26, 0x27, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x40, 0x41, 0x42, 0x43,
            0x44, 0x45, 0xff, 0xfe,
        ];
        expected.extend_from_slice(&SYMBOL);
        assert_eq!(&aligned[..length], expected);
        assert_eq!(aligned[length], 0xa5);
        let view = aligned_envelope::decode(id.scope, SYMBOL.len(), 3, &aligned[..length])?;
        assert_eq!(view.identity, aligned_id);
        assert_eq!(view.symbol, SYMBOL);
        assert_eq!(view.symbol.as_ptr(), aligned[48..].as_ptr());
        let header = decode(Layout::Aligned, id.scope, &aligned[..length])?;
        assert_eq!(header.identity, id);
        assert_eq!(header.tail.as_ptr(), aligned[40..].as_ptr());

        let packed_id = packed_envelope::Identity {
            scope: id.scope,
            source: id.source,
            first_unit: SourceId(0x5051_5253_5455_5657),
        };
        let records = [RECORD, RecordId(0x4041_4243_4446_0000)];
        let mut packed = [0xa5; 97];
        let length =
            packed_envelope::encode(packed_config(), packed_id, &records, &PAYLOAD, &mut packed)?;
        let mut expected = vec![
            b'L', b'2', b'P', b'K', 1, code, 2, 0, 0, 32, 0, 24, 0x10, 0x11, 0x12, 0x13, 0x14,
            0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22,
            0x23, 0x24, 0x25, 0x26, 0x27, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x50,
            0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0, 0, 0, 0, 0x40, 0x41, 0x42, 0x43, 0x44,
            0x45, 0xff, 0xfe, 0x40, 0x41, 0x42, 0x43, 0x44, 0x46, 0, 0,
        ];
        expected.extend_from_slice(&PAYLOAD);
        assert_eq!(&packed[..length], expected);
        assert_eq!(packed[length], 0xa5);
        let view = packed_envelope::decode(packed_config(), id.scope, &packed[..length])?;
        assert_eq!(view.identity(), packed_id);
        assert_eq!(view.payload(), PAYLOAD);
        assert_eq!(view.payload().as_ptr(), packed[72..].as_ptr());
        let units: Vec<_> = view.units()?.collect();
        assert_eq!(units.len(), 2);
        assert_eq!(units[0].bytes, &PAYLOAD[4..13]);
        assert_eq!(units[1].bytes, &PAYLOAD[15..]);
        for (index, unit) in units.iter().enumerate() {
            assert_eq!(unit.identity.scope, id.scope);
            assert_eq!(unit.identity.record, records[index]);
            assert_eq!(
                unit.identity.source.0,
                packed_id.first_unit.0 + index as u64
            );
            assert_ne!(unit.identity.source, packed_id.source);
        }
        let header = decode(Layout::Packed, id.scope, &packed[..length])?;
        assert_eq!(header.identity, id);
        assert_eq!(header.tail.as_ptr(), packed[44..].as_ptr());
    }
    Ok(())
}

#[test]
fn shared_identity_preserves_short_output_and_parser_refusals() -> TestResult {
    let id = identity(Direction::InitiatorToResponder);
    let aligned_id = SymbolIdentity {
        scope: id.scope,
        source: id.source,
        record: RECORD,
    };
    let mut short = [0xa5; 59];
    assert_eq!(
        aligned_envelope::encode(aligned_id, &SYMBOL, &mut short),
        Err(aligned_envelope::Error::OutputTooSmall { needed: 60 })
    );
    assert_eq!(short, [0xa5; 59]);
    let packed_id = packed_envelope::Identity {
        scope: id.scope,
        source: id.source,
        first_unit: SourceId(u64::MAX - 1),
    };
    let records = [RECORD, RecordId(0x4041_4243_4446_0000)];
    let mut short = [0xa5; 95];
    assert_eq!(
        packed_envelope::encode(packed_config(), packed_id, &records, &PAYLOAD, &mut short),
        Err(packed_envelope::Error::OutputTooSmall { needed: 96 })
    );
    assert_eq!(short, [0xa5; 95]);

    let mut aligned = [0; 60];
    aligned_envelope::encode(aligned_id, &SYMBOL, &mut aligned)?;
    let mut packed = [0; 96];
    packed_envelope::encode(packed_config(), packed_id, &records, &PAYLOAD, &mut packed)?;
    aligned[5] = 2;
    packed[5] = 2;
    assert_eq!(
        aligned_envelope::decode(id.scope, SYMBOL.len(), 3, &aligned),
        Err(aligned_envelope::Error::Malformed)
    );
    assert!(matches!(
        packed_envelope::decode(packed_config(), id.scope, &packed),
        Err(packed_envelope::Error::Malformed)
    ));
    aligned[5] = 0;
    packed[5] = 0;
    aligned[8] ^= 1;
    packed[12] ^= 1;
    assert_eq!(
        aligned_envelope::decode(id.scope, SYMBOL.len(), 3, &aligned),
        Err(aligned_envelope::Error::Scope)
    );
    assert!(matches!(
        packed_envelope::decode(packed_config(), id.scope, &packed),
        Err(packed_envelope::Error::Scope)
    ));
    Ok(())
}
