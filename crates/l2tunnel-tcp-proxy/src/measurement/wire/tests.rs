use super::*;
type TestError = Box<dyn std::error::Error>;
type TestResult = Result<(), TestError>;
type Fixture = (Record, Vec<u8>);

fn header(direction: Direction) -> Header {
    Header {
        scope: Scope {
            session: [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
            epoch: 0x0102_0304_0506_0708,
            flow: 0x1112_1314_1516_1718,
        },
        direction,
        serial: 0x2122_2324_2526_2728,
    }
}
fn demand() -> Demand {
    Demand {
        produced: Window {
            bytes: 0x0102_0304_0506_0708,
            records: 0x0001_0203,
        },
        observed_grant: Window {
            bytes: 0x0102_0304_0506_0708,
            records: 0x0004_0506,
        },
        native_unread_bytes: 0x0102_0304,
        pending_data_bytes: 0x1122,
        byte_blocked: true,
        record_blocked: false,
    }
}
fn fixtures() -> Result<Vec<Fixture>, TestError> {
    [
        (
            Record {
                header: header(Direction::OriginatorToAcceptor),
                body: Body::Demand(demand()),
            },
            include_str!("fixtures/demand.hex"),
        ),
        (
            Record {
                header: header(Direction::AcceptorToOriginator),
                body: Body::EchoRequest {
                    nonce: 0x8182_8384_8586_8788,
                },
            },
            include_str!("fixtures/echo-request.hex"),
        ),
        (
            Record {
                header: header(Direction::OriginatorToAcceptor),
                body: Body::EchoReply {
                    nonce: 0x8182_8384_8586_8788,
                },
            },
            include_str!("fixtures/echo-reply.hex"),
        ),
    ]
    .into_iter()
    .map(|(record, hex)| {
        let bytes = hex
            .split_ascii_whitespace()
            .map(|word| u8::from_str_radix(word, 16))
            .collect::<Result<Vec<_>, _>>()?;
        Ok((record, bytes))
    })
    .collect()
}

#[test]
fn independent_canonical_fixtures_match_both_directions_and_all_kinds() -> TestResult {
    for (record, bytes) in fixtures()? {
        assert_eq!(decode(&bytes)?, record);
        let mut output = [0xa7; MAX_RECORD_BYTES + 9];
        let length = encode(record, &mut output[3..])?;
        assert_eq!(length, bytes.len());
        assert_eq!(&output[3..3 + length], bytes);
        assert_eq!(&output[..3], [0xa7; 3]);
        assert!(output[3 + length..].iter().all(|byte| *byte == 0xa7));
        for (direction, octet) in [
            (Direction::OriginatorToAcceptor, 1),
            (Direction::AcceptorToOriginator, 2),
        ] {
            let mut expected = bytes.clone();
            expected[6] = octet;
            let directional = Record {
                header: Header {
                    direction,
                    ..record.header
                },
                ..record
            };
            let mut encoded = [0; MAX_RECORD_BYTES];
            let length = encode(directional, &mut encoded)?;
            assert_eq!(&encoded[..length], expected);
            assert_eq!(decode(&expected)?, directional);
        }
    }
    Ok(())
}

#[test]
fn every_truncation_and_bounded_excess_length_rejects_before_body_reads() -> TestResult {
    for (_, bytes) in fixtures()? {
        for length in 0..bytes.len() {
            assert_eq!(decode(&bytes[..length]), Err(DecodeError::Length));
        }
        for length in bytes.len() + 1..=MAX_RECORD_BYTES + 8 {
            let mut extra = bytes.clone();
            extra.resize(length, 0);
            assert_eq!(decode(&extra), Err(DecodeError::Length));
        }
        let mut huge = [0; MAX_RECORD_BYTES * 4];
        huge[..bytes.len()].copy_from_slice(&bytes);
        assert_eq!(decode(&huge), Err(DecodeError::Length));
    }
    Ok(())
}

#[test]
fn unknown_discriminants_reserved_bytes_and_all_flag_bits_reject() -> TestResult {
    for (_, bytes) in fixtures()? {
        for (offset, expected) in [
            (4, DecodeError::Version),
            (5, DecodeError::Kind),
            (6, DecodeError::Direction),
        ] {
            for value in 0..=u8::MAX {
                let valid = match offset {
                    4 => value == VERSION,
                    5 => (1..=3).contains(&value),
                    _ => (1..=2).contains(&value),
                };
                if !valid {
                    let mut changed = bytes.clone();
                    changed[offset] = value;
                    assert_eq!(decode(&changed), Err(expected));
                }
            }
        }
        for offset in 0..4 {
            let mut changed = bytes.clone();
            changed[offset] ^= 0x80;
            assert_eq!(decode(&changed), Err(DecodeError::Magic));
        }
        for bit in 0..8 {
            let mut changed = bytes.clone();
            changed[7] = 1 << bit;
            assert_eq!(decode(&changed), Err(DecodeError::Reserved));
        }
        if bytes.len() == DEMAND_BYTES {
            for offset in 97..104 {
                for bit in 0..8 {
                    let mut changed = bytes.clone();
                    changed[offset] = 1 << bit;
                    assert_eq!(decode(&changed), Err(DecodeError::Reserved));
                }
            }
            for bit in 2..8 {
                let mut changed = bytes.clone();
                changed[96] |= 1 << bit;
                assert_eq!(decode(&changed), Err(DecodeError::Reserved));
            }
            for kind in [2, 3] {
                let mut changed = bytes.clone();
                changed[5] = kind;
                assert_eq!(decode(&changed), Err(DecodeError::Length));
            }
        } else {
            let mut changed = bytes.clone();
            changed[5] = 1;
            assert_eq!(decode(&changed), Err(DecodeError::Length));
        }
    }
    Ok(())
}

#[test]
fn zero_identity_and_nonce_reject_in_both_apis_without_changing_output() -> TestResult {
    for (record, bytes) in fixtures()? {
        for (start, end) in [(8, 24), (24, 32), (32, 40), (40, 48)] {
            let mut changed = bytes.clone();
            changed[start..end].fill(0);
            assert_eq!(
                decode(&changed),
                Err(DecodeError::Invalid(InvalidField::Identity))
            );
        }
        let mut variants = [record; 4];
        variants[0].header.scope.session = [0; 16];
        variants[1].header.scope.epoch = 0;
        variants[2].header.scope.flow = 0;
        variants[3].header.serial = 0;
        for invalid in variants {
            unchanged_on_invalid(invalid, InvalidField::Identity);
        }
        if bytes.len() == ECHO_BYTES {
            let mut changed = bytes;
            changed[48..56].fill(0);
            assert_eq!(
                decode(&changed),
                Err(DecodeError::Invalid(InvalidField::Nonce))
            );
            let body = match record.body {
                Body::EchoRequest { .. } => Body::EchoRequest { nonce: 0 },
                _ => Body::EchoReply { nonce: 0 },
            };
            unchanged_on_invalid(Record { body, ..record }, InvalidField::Nonce);
        }
    }
    Ok(())
}

fn unchanged_on_invalid(record: Record, expected: InvalidField) {
    for capacity in 0..=MAX_RECORD_BYTES + 8 {
        let mut output = [0xd3; MAX_RECORD_BYTES + 10];
        assert_eq!(
            encode(record, &mut output[1..1 + capacity]),
            Err(EncodeError::Invalid(expected))
        );
        assert_eq!(output, [0xd3; MAX_RECORD_BYTES + 10]);
    }
}

#[test]
fn late_counter_and_flag_failures_leave_even_full_output_unchanged() -> TestResult {
    let valid = Demand {
        produced: Window {
            bytes: 9,
            records: 3,
        },
        observed_grant: Window {
            bytes: 9,
            records: 3,
        },
        native_unread_bytes: 1,
        pending_data_bytes: 0,
        byte_blocked: false,
        record_blocked: false,
    };
    let mut invalids = [valid; 6];
    invalids[0].produced.bytes = u64::MAX;
    invalids[1].produced.records = u64::MAX;
    invalids[2].native_unread_bytes = 0;
    invalids[2].byte_blocked = true;
    invalids[3].native_unread_bytes = 0;
    invalids[3].record_blocked = true;
    invalids[4].observed_grant.bytes = 10;
    invalids[4].byte_blocked = true;
    invalids[5].observed_grant.records = 4;
    invalids[5].record_blocked = true;
    for (index, invalid) in invalids.into_iter().enumerate() {
        let expected = if index < 2 {
            InvalidField::CounterOrder
        } else {
            InvalidField::BlockedFlags
        };
        unchanged_on_invalid(
            Record {
                header: header(Direction::OriginatorToAcceptor),
                body: Body::Demand(invalid),
            },
            expected,
        );
        // Build malformed bytes by editing a valid record, independently of the
        // encoder's own intrinsic rejection, including the last flags field.
        let mut bytes = [0; DEMAND_BYTES];
        encode(
            Record {
                header: header(Direction::OriginatorToAcceptor),
                body: Body::Demand(valid),
            },
            &mut bytes,
        )?;
        for (at, value) in [
            (48, invalid.produced.bytes),
            (56, invalid.produced.records),
            (64, invalid.observed_grant.bytes),
            (72, invalid.observed_grant.records),
            (80, invalid.native_unread_bytes),
        ] {
            bytes[at..at + 8].copy_from_slice(&value.to_be_bytes());
        }
        bytes[96] = u8::from(invalid.byte_blocked) | (u8::from(invalid.record_blocked) << 1);
        assert_eq!(decode(&bytes), Err(DecodeError::Invalid(expected)));
    }
    Ok(())
}

#[test]
fn every_small_capacity_fails_atomically_and_exact_capacity_succeeds() -> TestResult {
    for (record, bytes) in fixtures()? {
        for capacity in 0..bytes.len() {
            let mut output = [0xe5; MAX_RECORD_BYTES + 2];
            assert_eq!(
                encode(record, &mut output[1..1 + capacity]),
                Err(EncodeError::OutputTooSmall {
                    needed: bytes.len()
                })
            );
            assert_eq!(output, [0xe5; MAX_RECORD_BYTES + 2]);
        }
        let mut output = [0xe5; MAX_RECORD_BYTES + 2];
        assert_eq!(
            encode(record, &mut output[1..1 + bytes.len()])?,
            bytes.len()
        );
        assert_eq!(&output[1..1 + bytes.len()], bytes);
        assert_eq!(output[0], 0xe5);
        assert!(output[1 + bytes.len()..].iter().all(|byte| *byte == 0xe5));
    }
    Ok(())
}

#[test]
fn zero_and_maximum_counters_roundtrip_without_inventing_owner_limits() -> TestResult {
    let maximum = Demand {
        produced: Window {
            bytes: u64::MAX,
            records: u64::MAX,
        },
        observed_grant: Window {
            bytes: u64::MAX,
            records: u64::MAX,
        },
        native_unread_bytes: u64::MAX,
        pending_data_bytes: u64::MAX,
        byte_blocked: true,
        record_blocked: true,
    };
    let full_header = Header {
        scope: Scope {
            session: [u8::MAX; 16],
            epoch: u64::MAX,
            flow: u64::MAX,
        },
        direction: Direction::AcceptorToOriginator,
        serial: u64::MAX,
    };
    for body in [
        Body::Demand(Demand::default()),
        Body::Demand(maximum),
        Body::EchoRequest { nonce: 1 },
        Body::EchoReply { nonce: u64::MAX },
    ] {
        let record = Record {
            header: full_header,
            body,
        };
        let mut bytes = [0; MAX_RECORD_BYTES];
        let length = encode(record, &mut bytes)?;
        assert_eq!(decode(&bytes[..length])?, record);
        // Repeated parsing intentionally has no replay/freshness authority.
        assert_eq!(decode(&bytes[..length])?, record);
    }
    for byte_blocked in [false, true] {
        for record_blocked in [false, true] {
            let record = Record {
                header: full_header,
                body: Body::Demand(Demand {
                    byte_blocked,
                    record_blocked,
                    ..maximum
                }),
            };
            let mut bytes = [0; DEMAND_BYTES];
            encode(record, &mut bytes)?;
            assert_eq!(decode(&bytes)?, record);
        }
    }
    Ok(())
}
