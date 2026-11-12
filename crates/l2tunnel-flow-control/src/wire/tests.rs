use super::*;
use crate::{Capacity, Received, ReceiverCredits, SenderCredits};

type Result = std::result::Result<(), Box<dyn std::error::Error>>;
fn scope() -> Scope {
    Scope {
        session: 0x000102030405060708090a0b0c0d0e0f,
        epoch: 17,
        direction: Direction::Forward,
    }
}
fn pass(message: Message) -> std::result::Result<Message, Error> {
    decode(&encode(message)?)
}

#[test]
fn independent_literal_network_order_golden() -> Result {
    // Literal wire bytes, independently laid out as network-order integers.
    let hex = concat!(
        "4c43010200000000",
        "000102030405060708090a0b0c0d0e0f",
        "0000000000000011",
        "0000000000000012",
        "0000000000000013",
        "0000000000000014",
        "0000000000000015",
        "0000000000000016"
    );
    let golden = (0..hex.len())
        .step_by(2)
        .map(|offset| u8::from_str_radix(&hex[offset..offset + 2], 16))
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let message = Message::Grant(Grant {
        scope: scope(),
        flow: FlowId(18),
        flow_limit: Credit {
            bytes: 19,
            records: 20,
        },
        session_limit: Credit {
            bytes: 21,
            records: 22,
        },
    });
    assert_eq!(encode(message)?.as_slice(), golden);
    assert_eq!(decode(&golden)?, message);
    Ok(())
}

#[test]
fn all_variants_reject_noncanonical_lengths_tags_and_reserved_body() -> Result {
    for direction in [Direction::Forward, Direction::Reverse] {
        let scope = Scope {
            direction,
            ..scope()
        };
        let flow = FlowId(2);
        let offset = FinalOffset {
            scope,
            flow,
            admitted: Credit {
                bytes: 9,
                records: 2,
            },
        };
        for message in [
            Message::Open { scope, flow },
            Message::Grant(Grant {
                scope,
                flow,
                flow_limit: offset.admitted,
                session_limit: offset.admitted,
            }),
            Message::Record(Record {
                scope,
                flow,
                id: RecordId(1),
                byte_start: 5,
                byte_len: 4,
            }),
            Message::Release(Release {
                scope,
                flow,
                consumed: offset.admitted,
            }),
            Message::Final {
                offset,
                mode: RetirementMode::Drained,
            },
            Message::FinalAck {
                offset,
                mode: RetirementMode::Abandon,
            },
        ] {
            let bytes = encode(message)?;
            assert_eq!(decode(&bytes)?, message);
            assert_eq!(message.scope(), scope);
            assert_eq!(message.flow(), flow);
            for end in 0..WIRE_LEN {
                assert_eq!(decode(&bytes[..end]), Err(Error::Length));
            }
            assert_eq!(
                decode(&[bytes.as_slice(), &[0]].concat()),
                Err(Error::Length)
            );
            for (index, value) in [
                (0, 0),
                (2, 2),
                (3, 0),
                (3, 7),
                (4, 2),
                (5, 2),
                (6, 1),
                (7, 1),
            ] {
                let mut bad = bytes;
                bad[index] = value;
                assert!(decode(&bad).is_err());
            }
            if !matches!(message, Message::Grant(_)) {
                let mut bad = bytes;
                bad[71] = 1;
                assert_eq!(decode(&bad), Err(Error::Reserved));
            }
        }
    }
    Ok(())
}

#[test]
fn overflowing_ranges_and_contradictory_credit_are_rejected() {
    let scope = scope();
    let flow = FlowId(1);
    for (id, byte_start, byte_len) in [(u64::MAX, 0, 0), (0, u64::MAX, 1)] {
        assert_eq!(
            encode(Message::Record(Record {
                scope,
                flow,
                id: RecordId(id),
                byte_start,
                byte_len
            })),
            Err(Error::Offset)
        );
    }
    let invalid = Credit {
        bytes: 1,
        records: 0,
    };
    assert_eq!(
        encode(Message::Release(Release {
            scope,
            flow,
            consumed: invalid
        })),
        Err(Error::Offset)
    );
    assert_eq!(
        encode(Message::Grant(Grant {
            scope,
            flow,
            flow_limit: Credit {
                bytes: 2,
                records: 1
            },
            session_limit: Credit {
                bytes: 1,
                records: 1
            }
        })),
        Err(Error::Offset)
    );
}

#[test]
fn actual_ledgers_exchange_serialized_tokens_and_retire() -> Result {
    let scope = scope();
    let flow = FlowId(1);
    let capacity = Capacity {
        credit: Credit {
            bytes: 7,
            records: 1,
        },
        max_flows: 1,
    };
    let mut sender = SenderCredits::new(scope, capacity)?;
    let mut receiver = ReceiverCredits::new(scope, capacity)?;
    sender.open_flow(flow)?;
    let Message::Open { flow, .. } = pass(Message::Open { scope, flow })? else {
        return Err("unexpected open".into());
    };
    receiver.open_flow(flow)?;
    let Message::Grant(grant) = pass(Message::Grant(receiver.grant(flow, capacity.credit)?))?
    else {
        return Err("unexpected grant".into());
    };
    sender.apply_grant(grant)?;
    let source = sender.admit(flow, 7)?;
    assert!(sender.admit(flow, 1).is_err());
    let Message::Record(record) = pass(Message::Record(source))? else {
        return Err("unexpected data".into());
    };
    assert_eq!(receiver.receive(record)?, Received::New);
    assert_eq!(receiver.receive(record)?, Received::Duplicate);
    let Message::Release(release) = pass(Message::Release(receiver.release_next(flow)?))? else {
        return Err("unexpected release".into());
    };
    sender.apply_release(release)?;
    sender.apply_release(release)?;
    let offset = sender.retire(flow, RetirementMode::Drained)?;
    let Message::Final { offset, mode } = pass(Message::Final {
        offset,
        mode: RetirementMode::Drained,
    })?
    else {
        return Err("unexpected final".into());
    };
    receiver.retire(offset, mode)?;
    assert_eq!(
        pass(Message::FinalAck { offset, mode })?,
        Message::FinalAck { offset, mode }
    );
    assert!(sender.apply_grant(grant).is_err());
    assert!(receiver.receive(record).is_err());
    Ok(())
}
