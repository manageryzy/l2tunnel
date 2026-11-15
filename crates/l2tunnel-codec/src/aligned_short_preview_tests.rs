use super::*;
type TestResult = Result<(), Box<dyn std::error::Error>>;

fn limits() -> Limits {
    Limits {
        body: aligned_body::Config {
            max_frame_bytes: 256,
            symbol_bytes: 64,
            elide_payload_length: false,
            predictive: false,
            timestamp_pair_dictionary: false,
            independent_short_frame_bytes: 8,
        },
        channels: 2,
        first_record: RecordId(0),
        first_source: SourceId(0),
        record_window: 8,
        source_window: 8,
        lookahead_records: 4,
        lookahead_bytes: 1024,
        lookahead_fragments: 16,
        max_fragments_per_record: 8,
        lifetime_ticks: 100,
    }
}
fn raw(identity: SymbolIdentity, frame: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0; 64];
    bytes[1..3].copy_from_slice(&(identity.record.0 as u16).to_be_bytes());
    bytes[3] = 2;
    bytes[4..6].copy_from_slice(&(frame.len() as u16).to_be_bytes());
    bytes[6..6 + frame.len()].copy_from_slice(frame);
    bytes
}

#[test]
fn short_preview_uses_actual_scope_parser_and_generic_limit_without_admission() -> TestResult {
    let scope = Scope {
        session: [7; 16],
        epoch: Epoch(3),
        direction: Direction::InitiatorToResponder,
    };
    let identity = SymbolIdentity {
        scope,
        source: SourceId(7),
        record: RecordId(u64::MAX),
    };
    let config = limits();
    let plan = crate::aligned_storage::ReceiverPlan::for_limits(config)?;
    for reserved in [false, true] {
        let receiver = if reserved {
            Receiver::new_reserved(
                scope,
                config,
                crate::aligned_storage::Limits {
                    capacity_bytes: plan.capacity_bytes(),
                },
            )?
        } else {
            Receiver::new(scope, config)?
        };
        let before = receiver.status();
        assert!(receiver.is_independent_short(identity, &raw(identity, b"12345678"))?);
        assert!(!receiver.is_independent_short(identity, &raw(identity, b"123456789"))?);
        let mut fragment = vec![0; 64];
        fragment[1..3].copy_from_slice(&u16::MAX.to_be_bytes());
        fragment[3] = 4;
        fragment[4..6].copy_from_slice(&100u16.to_be_bytes());
        assert!(!receiver.is_independent_short(identity, &fragment)?);
        let mut malformed = raw(identity, b"tiny");
        malformed[63] = 1;
        assert_eq!(
            receiver.is_independent_short(identity, &malformed),
            Err(Error::Malformed)
        );
        let mut foreign = identity;
        foreign.scope.epoch = Epoch(4);
        assert_eq!(
            receiver.is_independent_short(foreign, &raw(identity, b"tiny")),
            Err(Error::Scope)
        );
        assert_eq!(receiver.status(), before);
    }
    let mut disabled = config;
    disabled.body.independent_short_frame_bytes = 0;
    assert!(
        !Receiver::new(scope, disabled)?.is_independent_short(identity, &raw(identity, b"tiny"))?
    );
    Ok(())
}
