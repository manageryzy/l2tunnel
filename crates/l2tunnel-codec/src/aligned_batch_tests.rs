use super::*;
type TestResult = Result<(), Box<dyn std::error::Error>>;
type EncodedUnits = Vec<(u64, Vec<u8>)>;

fn scope() -> Scope {
    Scope {
        session: [7; 16],
        epoch: Epoch(2),
        direction: Direction::InitiatorToResponder,
    }
}
fn limits() -> Limits {
    Limits {
        body: aligned_body::Config {
            max_frame_bytes: 1600,
            symbol_bytes: 64,
            elide_payload_length: false,
            predictive: false,
            timestamp_pair_dictionary: false,
            independent_short_frame_bytes: 0,
        },
        channels: 2,
        first_record: RecordId(0),
        first_source: SourceId(0),
        record_window: 8,
        source_window: 16,
        lookahead_records: 8,
        lookahead_bytes: 4096,
        lookahead_fragments: 64,
        max_fragments_per_record: 64,
        lifetime_ticks: 100,
    }
}
fn symbol(channel: u8, record: u64, value: u8) -> Vec<u8> {
    let mut bytes = vec![0; 64];
    bytes[0] = channel;
    bytes[1..3].copy_from_slice(&(record as u16).to_be_bytes());
    bytes[3] = 2;
    bytes[4..6].copy_from_slice(&10_u16.to_be_bytes());
    bytes[6..16].fill(value);
    bytes
}
fn unit(source: u64, record: u64, bytes: &[u8]) -> AuthenticatedSymbol<'_> {
    AuthenticatedSymbol {
        identity: SymbolIdentity {
            scope: scope(),
            source: SourceId(source),
            record: RecordId(record),
        },
        bytes,
    }
}
fn admit(
    receiver: &mut Receiver,
    value: &AuthenticatedSymbol<'_>,
    now: Tick,
) -> Result<Admission, Error> {
    receiver.admit_authenticated(value.identity, value.bytes, now)
}
fn deliver(receiver: &mut Receiver, channel: u8, value: u8, now: Tick) -> TestResult {
    assert_eq!(
        receiver.prepare(ChannelId(channel), now, 8)?,
        Prepared::Ready
    );
    assert_eq!(
        receiver.pending().ok_or("missing native bytes")?.bytes,
        [value; 10]
    );
    receiver.commit_delivery(now)?;
    Ok(())
}

#[test]
fn batch_matches_sequential_admission_and_native_ownership() -> TestResult {
    let (a, b, c) = (symbol(0, 0, 1), symbol(1, 0, 2), symbol(0, 1, 3));
    let units = [unit(1, 0, &b), unit(0, 0, &a), unit(2, 1, &c)];
    let mut batch = Receiver::new(scope(), limits())?;
    let mut sequential = Receiver::new(scope(), limits())?;
    let expected = units
        .iter()
        .map(|u| admit(&mut sequential, u, Tick(1)))
        .collect::<Result<Vec<_>, _>>()?;
    assert_eq!(batch.admit_batch_authenticated(&units, Tick(1))?, expected);
    assert_eq!(batch.status(), sequential.status());
    for receiver in [&mut batch, &mut sequential] {
        deliver(receiver, 0, 1, Tick(2))?;
        deliver(receiver, 1, 2, Tick(2))?;
        deliver(receiver, 0, 3, Tick(2))?;
    }
    assert_eq!(batch.status(), sequential.status());
    assert_eq!(
        batch.admit_batch_authenticated(&units, Tick(3))?,
        vec![Admission::StaleSource; 3]
    );
    Ok(())
}

#[test]
fn late_failure_restores_cleared_source_proofs_and_pending_native() -> TestResult {
    let (a, b, c) = (symbol(0, 0, 1), symbol(1, 0, 2), symbol(0, 1, 3));
    let mut receiver = Receiver::new(scope(), limits())?;
    admit(&mut receiver, &unit(1, 0, &b), Tick(1))?;
    assert_eq!(receiver.prepare(ChannelId(1), Tick(2), 1)?, Prepared::Ready);
    let saved = receiver.status();
    // Unit 0 would clear both its proof and the already retained source 1 proof.
    let wrong = [unit(0, 0, &a), unit(2, 7, &c)];
    assert_eq!(
        receiver.admit_batch_authenticated(&wrong, Tick(9)),
        Err(Error::Malformed)
    );
    assert_eq!(receiver.status(), saved);
    assert_eq!(
        receiver.pending().ok_or("lost native handoff")?.bytes,
        [2; 10]
    );
    // Failed time 9 did not become an accepted timestamp or erase proof 1.
    assert_eq!(
        admit(&mut receiver, &unit(1, 0, &b), Tick(3))?,
        Admission::Duplicate
    );
    let mut conflict = b.clone();
    conflict[6] ^= 1;
    assert_eq!(
        receiver.admit_batch_authenticated(&[unit(0, 0, &a), unit(1, 0, &conflict)], Tick(3)),
        Ok(vec![Admission::Accepted, Admission::StaleSource])
    );
    // Once contiguous sources advance, stale-source handling is deliberately the
    // ordinary API's behavior; packed source replay belongs to the outer owner.
    receiver.commit_delivery(Tick(3))?;
    deliver(&mut receiver, 0, 1, Tick(3))?;
    Ok(())
}

#[test]
fn capacity_window_scope_and_conflict_errors_rollback_every_earlier_unit() -> TestResult {
    let a = symbol(0, 0, 1);
    let b = symbol(0, 1, 2);
    let far = symbol(0, 9, 3);
    for (bytes, record, expected) in [(&b, 1, Error::Capacity), (&far, 9, Error::RecordWindow)] {
        let mut policy = limits();
        policy.lookahead_records = 0;
        let mut receiver = Receiver::new(scope(), policy)?;
        let saved = receiver.status();
        assert_eq!(
            receiver.admit_batch_authenticated(&[unit(0, 0, &a), unit(1, record, bytes)], Tick(1)),
            Err(expected)
        );
        assert_eq!(receiver.status(), saved);
        assert_eq!(
            admit(&mut receiver, &unit(0, 0, &a), Tick(1))?,
            Admission::Accepted
        );
    }
    let mut receiver = Receiver::new(scope(), limits())?;
    let saved = receiver.status();
    let mut wrong = unit(1, 1, &b);
    wrong.identity.scope.epoch = Epoch(99);
    assert_eq!(
        receiver.admit_batch_authenticated(&[unit(0, 0, &a), wrong], Tick(1)),
        Err(Error::Scope)
    );
    assert_eq!(receiver.status(), saved);
    let mut changed = b.clone();
    changed[6] ^= 1;
    assert_eq!(
        receiver.admit_batch_authenticated(&[unit(1, 1, &b), unit(1, 1, &changed)], Tick(1)),
        Err(Error::Conflict)
    );
    assert_eq!(receiver.status(), saved);
    Ok(())
}

#[test]
fn final_fragment_validation_is_transactional() -> TestResult {
    let mut body = vec![4; 103];
    body[0] = 2;
    body[1..3].copy_from_slice(&100_u16.to_be_bytes());
    let fragment = |offset: usize, input: &[u8]| {
        let mut bytes = vec![0; 64];
        bytes[3] = 4;
        bytes[4..6].copy_from_slice(&103_u16.to_be_bytes());
        bytes[6..8].copy_from_slice(&(offset as u16).to_be_bytes());
        let size = (103 - offset).min(56);
        bytes[8..8 + size].copy_from_slice(&input[offset..offset + size]);
        bytes
    };
    let (first, last) = (fragment(0, &body), fragment(56, &body));
    let mut bad_body = body.clone();
    bad_body[1..3].copy_from_slice(&99_u16.to_be_bytes());
    let bad_first = fragment(0, &bad_body);
    let mut receiver = Receiver::new(scope(), limits())?;
    let saved = receiver.status();
    assert_eq!(
        receiver.admit_batch_authenticated(&[unit(0, 0, &bad_first), unit(1, 0, &last)], Tick(1)),
        Err(Error::Malformed)
    );
    assert_eq!(receiver.status(), saved);
    assert_eq!(
        receiver.admit_batch_authenticated(&[unit(0, 0, &first), unit(1, 0, &last)], Tick(1))?,
        vec![Admission::Accepted; 2]
    );
    assert_eq!(receiver.prepare(ChannelId(0), Tick(2), 1)?, Prepared::Ready);
    assert_eq!(
        receiver.pending().ok_or("missing assembled frame")?.bytes,
        [4; 100]
    );
    receiver.commit_delivery(Tick(2))?;
    Ok(())
}

#[test]
fn batch_bounds_time_and_existing_expiry_remain_explicit() -> TestResult {
    let a = symbol(0, 0, 1);
    let mut receiver = Receiver::new(scope(), limits())?;
    assert_eq!(
        receiver.admit_batch_authenticated(&[], Tick(0)),
        Err(Error::Configuration)
    );
    let oversized: Vec<_> = (0..256).map(|_| unit(0, 0, &a)).collect();
    assert_eq!(
        receiver.admit_batch_authenticated(&oversized, Tick(0)),
        Err(Error::Configuration)
    );
    let mut maximum = Receiver::new(scope(), limits())?;
    let permitted: Vec<_> = (0..255).map(|_| unit(0, 0, &a)).collect();
    let outcomes = maximum.admit_batch_authenticated(&permitted, Tick(1))?;
    assert_eq!(outcomes.len(), 255);
    assert_eq!(outcomes[0], Admission::Accepted);
    assert!(
        outcomes[1..]
            .iter()
            .all(|outcome| *outcome == Admission::StaleSource)
    );
    let mut final_policy = limits();
    final_policy.first_source = SourceId(u64::MAX);
    let mut final_source = Receiver::new(scope(), final_policy)?;
    let saved = final_source.status();
    assert_eq!(
        final_source
            .admit_batch_authenticated(&[unit(u64::MAX, 0, &a), unit(u64::MAX, 0, &a)], Tick(1),),
        Err(Error::Exhausted)
    );
    assert_eq!(final_source.status(), saved);
    final_source.admit_batch_authenticated(&[unit(u64::MAX, 0, &a)], Tick(1))?;
    assert_eq!(final_source.status().source_floor, None);
    assert_eq!(
        receiver.admit_batch_authenticated(&[unit(0, 0, &a)], Tick(u64::MAX)),
        Err(Error::Time)
    );
    assert_eq!(receiver.status().source_floor, Some(SourceId(0)));
    receiver.admit_batch_authenticated(&[unit(0, 0, &a)], Tick(2))?;
    assert_eq!(
        receiver.admit_batch_authenticated(&[unit(1, 0, &a)], Tick(1)),
        Err(Error::Time)
    );
    assert_eq!(
        receiver.admit_batch_authenticated(&[unit(1, 0, &a)], Tick(102)),
        Err(Error::Expired)
    );
    assert_eq!(receiver.status().failure, Some(Error::Expired));
    assert_eq!(
        receiver.admit_batch_authenticated(&[unit(1, 0, &a)], Tick(103)),
        Err(Error::Expired)
    );
    let mut large = limits();
    large.body.symbol_bytes = 3000;
    large.source_window = 65536;
    assert!(large.memory_bound_bytes().is_ok());
    assert_eq!(large.batch_memory_bound_bytes(), Err(Error::Configuration));
    assert!(limits().batch_memory_bound_bytes()? > limits().memory_bound_bytes()?);
    Ok(())
}

fn fixture_frame() -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let value = include_str!("../tests/data/aligned-sender-goldens.tsv")
        .lines()
        .find(|line| !line.starts_with('#'))
        .and_then(|line| line.split('\t').nth(6))
        .ok_or("missing actual Python frame")?;
    (0..value.len())
        .step_by(2)
        .map(|i| Ok(u8::from_str_radix(&value[i..i + 2], 16)?))
        .collect()
}
fn encoded_units(policy: Limits, frame: &[u8]) -> Result<EncodedUnits, Box<dyn std::error::Error>> {
    let mut sender = crate::aligned_sender::Sender::new(
        scope(),
        crate::aligned_sender::Config {
            body: policy.body,
            channels: policy.channels,
            first_record: policy.first_record,
        },
    )?;
    sender.stage(ChannelId(0), frame)?;
    let mut result = Vec::new();
    while sender.is_pending() {
        let pending = sender.pending_unit()?;
        let mut bytes = pending.bytes.to_vec();
        bytes.resize(policy.body.symbol_bytes, 0);
        result.push((pending.record.0, bytes));
        sender.commit_unit()?;
    }
    Ok(result)
}

#[test]
fn semantic_batch_failure_keeps_live_context_pending_bytes_and_original_time() -> TestResult {
    let mut policy = limits();
    policy.body.symbol_bytes = 256;
    let frame = fixture_frame()?;
    let values = encoded_units(policy, &frame)?;
    assert_eq!(values.len(), 2); // Real context then context-dependent frame.
    let mut earlier = symbol(1, 0, 9);
    earlier.resize(256, 0);
    let mut receiver = Receiver::new(scope(), policy)?;
    admit(&mut receiver, &unit(0, 0, &earlier), Tick(1))?;
    assert_eq!(receiver.prepare(ChannelId(1), Tick(1), 1)?, Prepared::Ready);
    let saved = receiver.status();
    let mut bad = vec![0; 256];
    bad[1..3].copy_from_slice(&(values[1].0 as u16).to_be_bytes());
    bad[3] = 6; // Structural implicit-body parse succeeds; delta decoding must fail.
    bad[4..10].fill(255);
    assert!(matches!(
        receiver.admit_validated_batch_authenticated(
            &[
                unit(1, values[0].0, &values[0].1),
                unit(2, values[1].0, &bad)
            ],
            Tick(9)
        ),
        Err(Error::Body(_))
    ));
    assert_eq!(receiver.status(), saved);
    assert_eq!(receiver.pending().ok_or("lost pending")?.bytes, [9; 10]);
    assert!(!receiver.channels[0].decoder.has_context());
    let inputs = values
        .iter()
        .enumerate()
        .map(|(i, (record, bytes))| unit(i as u64 + 1, *record, bytes))
        .collect::<Vec<_>>();
    assert_eq!(
        receiver.admit_validated_batch_authenticated(&inputs, Tick(2))?,
        vec![Admission::Accepted; 2]
    );
    // Successful preflight still did not apply contexts or native acceptance.
    assert!(!receiver.channels[0].decoder.has_context());
    assert_eq!(receiver.expected(ChannelId(0))?, Some(RecordId(0)));
    assert_eq!(receiver.pending().ok_or("lost pending")?.bytes, [9; 10]);
    receiver.commit_delivery(Tick(2))?;
    assert_eq!(receiver.prepare(ChannelId(0), Tick(2), 8)?, Prepared::Ready);
    assert_eq!(
        receiver
            .pending()
            .ok_or("missing reconstructed frame")?
            .bytes,
        frame
    );
    receiver.commit_delivery(Tick(2))?;
    assert!(receiver.channels[0].decoder.has_context());
    Ok(())
}

#[test]
fn semantic_fragment_tail_is_reserved_then_validated_without_early_native_commit() -> TestResult {
    let mut policy = limits();
    policy.body.symbol_bytes = 48;
    let frame = fixture_frame()?;
    let values = encoded_units(policy, &frame)?;
    assert!(values.len() >= 3);
    let mut receiver = Receiver::new(scope(), policy)?;
    for (i, (record, bytes)) in values.iter().enumerate() {
        let saved_expected = receiver.expected(ChannelId(0))?;
        receiver.admit_validated_batch_authenticated(&[unit(i as u64, *record, bytes)], Tick(1))?;
        assert_eq!(receiver.expected(ChannelId(0))?, saved_expected);
        assert!(receiver.pending().is_none());
        assert!(!receiver.channels[0].decoder.has_context());
    }
    assert_eq!(receiver.prepare(ChannelId(0), Tick(2), 8)?, Prepared::Ready);
    assert_eq!(
        receiver.pending().ok_or("missing fragment frame")?.bytes,
        frame
    );
    receiver.commit_delivery(Tick(2))?;
    assert_eq!(receiver.status().retained_records, 0);
    Ok(())
}

#[test]
fn semantic_complete_gap_rejects_without_weakening_ordinary_or_early_raw_api() -> TestResult {
    let future = symbol(0, 1, 3);
    let head = symbol(0, 0, 2);
    let mut receiver = Receiver::new(scope(), limits())?;
    let saved = receiver.status();
    assert_eq!(
        receiver.admit_validated_batch_authenticated(&[unit(0, 1, &future)], Tick(1)),
        Err(Error::UnresolvedContext)
    );
    assert_eq!(receiver.status(), saved);
    assert_eq!(
        receiver.admit_batch_authenticated(&[unit(0, 1, &future)], Tick(1))?,
        vec![Admission::Accepted]
    );
    // A later source resolving the head validates both complete records privately.
    receiver.admit_validated_batch_authenticated(&[unit(1, 0, &head)], Tick(2))?;
    deliver(&mut receiver, 0, 2, Tick(2))?;
    deliver(&mut receiver, 0, 3, Tick(2))?;
    let mut early = limits();
    early.body.independent_short_frame_bytes = 10;
    let mut receiver = Receiver::new(scope(), early)?;
    receiver.admit_validated_batch_authenticated(&[unit(0, 1, &future)], Tick(1))?;
    assert_eq!(receiver.status().early_tombstones, 0);
    assert_eq!(receiver.prepare(ChannelId(0), Tick(1), 1)?, Prepared::Ready);
    assert!(receiver.pending().ok_or("missing early raw")?.early);
    receiver.commit_delivery(Tick(1))?;
    receiver.admit_validated_batch_authenticated(&[unit(1, 0, &head)], Tick(2))?;
    deliver(&mut receiver, 0, 2, Tick(2))?;
    receiver.prepare(ChannelId(0), Tick(2), 2)?;
    assert_eq!(receiver.status().retained_records, 0);
    Ok(())
}

#[test]
fn semantic_preflight_bounds_failure_and_exhaustion_do_not_allocate_new_authority() -> TestResult {
    let a = symbol(0, 0, 1);
    let mut receiver = Receiver::new(scope(), limits())?;
    assert_eq!(
        receiver.admit_validated_batch_authenticated(&[], Tick(0)),
        Err(Error::Configuration)
    );
    let too_many = (0..256).map(|_| unit(0, 0, &a)).collect::<Vec<_>>();
    assert_eq!(
        receiver.admit_validated_batch_authenticated(&too_many, Tick(0)),
        Err(Error::Configuration)
    );
    assert_eq!(
        receiver.admit_validated_batch_authenticated(&[unit(0, 0, &a)], Tick(u64::MAX)),
        Err(Error::Time)
    );
    receiver.admit_validated_batch_authenticated(&[unit(0, 0, &a)], Tick(2))?;
    let saved = receiver.status();
    assert_eq!(
        receiver.admit_validated_batch_authenticated(&[unit(0, 0, &a)], Tick(1)),
        Err(Error::Time)
    );
    assert_eq!(receiver.status(), saved);
    assert_eq!(
        receiver.admit_validated_batch_authenticated(&[unit(0, 0, &a)], Tick(102)),
        Err(Error::Expired)
    );
    assert_eq!(receiver.status().failure, Some(Error::Expired));
    let mut policy = limits();
    policy.first_record = RecordId(u64::MAX);
    policy.first_source = SourceId(u64::MAX);
    let final_bytes = symbol(0, u64::MAX, 5);
    let mut final_receiver = Receiver::new(scope(), policy)?;
    final_receiver
        .admit_validated_batch_authenticated(&[unit(u64::MAX, u64::MAX, &final_bytes)], Tick(1))?;
    assert_eq!(final_receiver.status().source_floor, None);
    assert_eq!(
        final_receiver.expected(ChannelId(0))?,
        Some(RecordId(u64::MAX))
    );
    deliver(&mut final_receiver, 0, 5, Tick(2))?;
    assert_eq!(final_receiver.expected(ChannelId(0))?, None);
    let mut large = limits();
    large.body.symbol_bytes = 3000;
    large.source_window = 65536;
    let mut receiver = Receiver::new(scope(), large)?;
    assert_eq!(
        receiver.admit_validated_batch_authenticated(&[unit(0, 0, &a)], Tick(0)),
        Err(Error::Configuration)
    );
    Ok(())
}
