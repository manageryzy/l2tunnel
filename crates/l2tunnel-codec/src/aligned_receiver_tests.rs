use super::*;
type TestError = Box<dyn std::error::Error + Send + Sync>;
type TestResult = Result<(), TestError>;
fn scope() -> Scope {
    Scope {
        session: [9; 16],
        epoch: Epoch(3),
        direction: Direction::InitiatorToResponder,
    }
}
fn limits() -> Limits {
    Limits {
        body: aligned_body::Config {
            max_frame_bytes: 65535,
            symbol_bytes: 1460,
            elide_payload_length: true,
            predictive: true,
            timestamp_pair_dictionary: true,
            independent_short_frame_bytes: 0,
        },
        channels: 2,
        first_record: RecordId(0),
        first_source: SourceId(0),
        record_window: 32767,
        source_window: 128,
        lookahead_records: 64,
        lookahead_bytes: 1_048_576,
        lookahead_fragments: 1024,
        max_fragments_per_record: 1024,
        lifetime_ticks: 10_000,
    }
}
fn identity(source: u64, record: u64) -> SymbolIdentity {
    SymbolIdentity {
        scope: scope(),
        source: SourceId(source),
        record: RecordId(record),
    }
}
fn raw(symbol: usize, channel: u8, record: u64, frame: &[u8]) -> Vec<u8> {
    let mut bytes = vec![channel];
    bytes.extend_from_slice(&(record as u16).to_be_bytes());
    bytes.push(2);
    bytes.extend_from_slice(&(frame.len() as u16).to_be_bytes());
    bytes.extend_from_slice(frame);
    bytes.resize(symbol, 0);
    bytes
}
fn hex(text: &str) -> Result<Vec<u8>, TestError> {
    if !text.len().is_multiple_of(2) {
        return Err("odd fixture hex".into());
    }
    text.as_bytes()
        .chunks(2)
        .map(|bytes| Ok(u8::from_str_radix(std::str::from_utf8(bytes)?, 16)?))
        .collect()
}
fn drain(
    receiver: &mut Receiver,
    channel: ChannelId,
    now: Tick,
) -> Result<Vec<(u8, u64, Vec<u8>)>, TestError> {
    let mut deliveries = Vec::new();
    for _ in 0..256 {
        match receiver.prepare(channel, now, 1)? {
            Prepared::Ready => {
                let output = receiver.pending().ok_or("missing prepared bytes")?;
                deliveries.push((output.channel.0, output.record.0, output.bytes.to_vec()));
                receiver.commit_delivery(now)?;
            }
            Prepared::Idle => return Ok(deliveries),
            Prepared::Progress => {}
        }
    }
    Err("bounded drain did not terminate".into())
}
#[test]
fn actual_python_reorder_fragment_short_wrap_and_duplicate_traces_match() -> TestResult {
    let mut receiver = Receiver::new(scope(), limits())?;
    let mut rows = 0;
    for line in include_str!("../tests/data/aligned-receiver-goldens.tsv")
        .lines()
        .filter(|line| !line.starts_with('#'))
    {
        let f: Vec<_> = line.split('\t').collect();
        if f.len() != 12 {
            return Err("fixture columns".into());
        }
        let step: usize = f[1].parse()?;
        let symbol: usize = f[2].parse()?;
        if step == 0 {
            let mut config = limits();
            config.body.symbol_bytes = symbol;
            config.body.independent_short_frame_bytes = f[3].parse()?;
            config.first_record = RecordId(f[4].parse()?);
            receiver = Receiver::new(scope(), config)?;
        }
        let bytes = hex(f[7])?;
        let now = Tick(step as u64 + 1);
        receiver.admit_authenticated(identity(f[5].parse()?, f[6].parse()?), &bytes, now)?;
        let actual = drain(&mut receiver, ChannelId(bytes[0]), now)?;
        let mut expected = Vec::new();
        for event in f[8].split(';').filter(|s| !s.is_empty()) {
            let parts: Vec<_> = event.split(':').collect();
            if let Some(frame) = parts[2].strip_prefix('=') {
                expected.push((
                    parts[0].parse::<u8>()?,
                    parts[1].parse::<u64>()?,
                    hex(frame)?,
                ));
            }
        }
        assert_eq!(actual, expected, "{} step{} native events", f[0], step);
        assert_eq!(
            receiver.expected(ChannelId(0))?,
            Some(RecordId(f[9].parse()?)),
            "{} step{} channel0",
            f[0],
            step
        );
        assert_eq!(
            receiver.expected(ChannelId(1))?,
            Some(RecordId(f[10].parse()?)),
            "{} step{} channel1",
            f[0],
            step
        );
        let mut tombstones: Vec<_> = receiver
            .records
            .iter()
            .flatten()
            .filter(|r| r.early_delivered)
            .map(|r| format!("{}:{}", r.channel.0, r.id.0))
            .collect();
        tombstones.sort();
        assert_eq!(
            tombstones.join(";"),
            f[11],
            "{} step{} tombstones",
            f[0],
            step
        );
        rows += 1;
    }
    assert_eq!(rows, 51);
    Ok(())
}
#[test]
fn lookahead_saturation_preserves_head_reservation_and_immutable_pending_native() -> TestResult {
    let mut config = limits();
    config.lookahead_records = 1;
    config.lookahead_bytes = 8;
    config.lookahead_fragments = 0;
    let mut receiver = Receiver::new(scope(), config)?;
    receiver.admit_authenticated(identity(1, 1), &raw(1460, 0, 1, b"later"), Tick(1))?;
    let before = receiver.status();
    assert_eq!(
        receiver.admit_authenticated(identity(2, 2), &raw(1460, 0, 2, b"third"), Tick(2)),
        Err(Error::Capacity)
    );
    assert_eq!(receiver.status(), before);
    receiver.admit_authenticated(
        identity(0, 0),
        &raw(1460, 0, 0, b"head consumes only its progress reserve"),
        Tick(2),
    )?;
    assert_eq!(receiver.prepare(ChannelId(0), Tick(3), 1)?, Prepared::Ready);
    let pending = receiver.pending().ok_or("pending")?.bytes.to_vec();
    assert_eq!(receiver.expected(ChannelId(0))?, Some(RecordId(0)));
    for time in 4..20 {
        assert_eq!(
            receiver.prepare(ChannelId(1), Tick(time), 1)?,
            Prepared::Ready
        );
        assert_eq!(receiver.pending().ok_or("held pending")?.bytes, pending);
    }
    receiver.commit_delivery(Tick(20))?;
    receiver.admit_authenticated(identity(2, 2), &raw(1460, 0, 2, b"third"), Tick(21))?;
    assert_eq!(
        drain(&mut receiver, ChannelId(0), Tick(21))?,
        vec![(0, 1, b"later".to_vec()), (0, 2, b"third".to_vec())]
    );
    assert_eq!(receiver.status().retained_records, 0);
    Ok(())
}
#[test]
fn source_holes_are_not_evicted_and_retired_records_cannot_replay_with_new_sources() -> TestResult {
    let mut config = limits();
    config.source_window = 4;
    let mut receiver = Receiver::new(scope(), config)?;
    let later = raw(1460, 0, 1, b"later");
    let head = raw(1460, 0, 0, b"head");
    receiver.admit_authenticated(identity(3, 1), &later, Tick(1))?;
    let before = receiver.status();
    assert_eq!(
        receiver.admit_authenticated(identity(4, 1), &later, Tick(2)),
        Err(Error::SourceWindow)
    );
    assert_eq!(receiver.status(), before);
    receiver.admit_authenticated(identity(0, 0), &head, Tick(2))?;
    assert_eq!(
        receiver.admit_authenticated(identity(2, 1), &later, Tick(3))?,
        Admission::Duplicate
    );
    assert_eq!(
        receiver.admit_authenticated(identity(1, 0), &head, Tick(4))?,
        Admission::Duplicate
    );
    assert_eq!(receiver.status().source_floor, Some(SourceId(4)));
    assert_eq!(receiver.status().retained_sources, 0);
    assert_eq!(drain(&mut receiver, ChannelId(0), Tick(4))?.len(), 2);
    assert_eq!(
        receiver.admit_authenticated(identity(4, 0), &head, Tick(5))?,
        Admission::StaleRecord
    );
    assert_eq!(
        receiver.admit_authenticated(identity(0, 0), &head, Tick(6))?,
        Admission::StaleSource
    );
    assert!(drain(&mut receiver, ChannelId(0), Tick(6))?.is_empty());
    Ok(())
}
fn fragments(symbol: usize, record: u64, body: &[u8]) -> Vec<Vec<u8>> {
    let capacity = symbol - 8;
    body.chunks(capacity)
        .enumerate()
        .map(|(index, piece)| {
            let mut bytes = vec![0];
            bytes.extend_from_slice(&(record as u16).to_be_bytes());
            bytes.push(4);
            bytes.extend_from_slice(&(body.len() as u16).to_be_bytes());
            bytes.extend_from_slice(&((index * capacity) as u16).to_be_bytes());
            bytes.extend_from_slice(piece);
            bytes.resize(symbol, 0);
            bytes
        })
        .collect()
}
#[test]
fn fragments_reserve_whole_body_and_reject_conflicts_padding_and_bad_final_length_transactionally()
-> TestResult {
    let mut config = limits();
    config.body.symbol_bytes = 72;
    config.max_fragments_per_record = 2;
    let mut receiver = Receiver::new(scope(), config)?;
    let mut body = vec![2, 0, 100];
    body.extend(0..100);
    let parts = fragments(72, 0, &body);
    receiver.admit_authenticated(identity(1, 0), &parts[0], Tick(1))?;
    assert_eq!(receiver.status().record_bytes, 103);
    assert_eq!(receiver.status().fragment_slots, 2);
    let before = receiver.status();
    let mut conflict = parts[0].clone();
    conflict[10] ^= 1;
    assert_eq!(
        receiver.admit_authenticated(identity(1, 0), &conflict, Tick(2)),
        Err(Error::Conflict)
    );
    assert_eq!(
        receiver.admit_authenticated(identity(2, 0), &conflict, Tick(2)),
        Err(Error::Conflict)
    );
    let mut padding = parts[1].clone();
    padding[71] = 1;
    assert_eq!(
        receiver.admit_authenticated(identity(0, 0), &padding, Tick(2)),
        Err(Error::Malformed)
    );
    assert_eq!(receiver.status(), before);
    receiver.admit_authenticated(identity(0, 0), &parts[1], Tick(3))?;
    assert_eq!(
        drain(&mut receiver, ChannelId(0), Tick(3))?,
        vec![(0, 0, (0..100).collect())]
    );
    let mut malformed = body.clone();
    malformed.push(0);
    let bad = fragments(72, 1, &malformed);
    receiver.admit_authenticated(identity(2, 1), &bad[0], Tick(4))?;
    let before = receiver.status();
    assert_eq!(
        receiver.admit_authenticated(identity(3, 1), &bad[1], Tick(5)),
        Err(Error::Malformed)
    );
    assert_eq!(receiver.status(), before);
    assert_eq!(receiver.prepare(ChannelId(0), Tick(5), 5)?, Prepared::Idle);
    Ok(())
}
#[test]
fn independent_short_tombstone_retains_body_gap_and_conflict_proof_until_contiguous_retirement()
-> TestResult {
    let mut config = limits();
    config.body.independent_short_frame_bytes = 128;
    let mut receiver = Receiver::new(scope(), config)?;
    let short = raw(1460, 0, 1, b"generic independent bytes");
    receiver.admit_authenticated(identity(1, 1), &short, Tick(1))?;
    assert_eq!(receiver.prepare(ChannelId(0), Tick(2), 1)?, Prepared::Ready);
    assert!(receiver.pending().ok_or("early")?.early);
    receiver.commit_delivery(Tick(2))?;
    assert_eq!(receiver.expected(ChannelId(0))?, Some(RecordId(0)));
    assert_eq!(receiver.status().early_tombstones, 1);
    let before = receiver.status();
    let changed = raw(1460, 0, 1, b"different independent bytes");
    assert_eq!(
        receiver.admit_authenticated(identity(2, 1), &changed, Tick(3)),
        Err(Error::Conflict)
    );
    assert_eq!(receiver.status(), before);
    assert_eq!(
        receiver.admit_authenticated(identity(2, 1), &short, Tick(3))?,
        Admission::Duplicate
    );
    assert_eq!(receiver.prepare(ChannelId(0), Tick(4), 8)?, Prepared::Idle);
    receiver.admit_authenticated(identity(0, 0), &raw(1460, 0, 0, b"earlier"), Tick(5))?;
    assert_eq!(
        drain(&mut receiver, ChannelId(0), Tick(5))?,
        vec![(0, 0, b"earlier".to_vec())]
    );
    assert_eq!(receiver.expected(ChannelId(0))?, Some(RecordId(2)));
    assert_eq!(receiver.status().early_tombstones, 0);
    Ok(())
}
#[test]
fn absolute_identity_scope_window_wrap_and_exhaustion_are_checked_before_interpretation()
-> TestResult {
    let mut config = limits();
    config.first_record = RecordId(65536);
    config.body.independent_short_frame_bytes = 128;
    let mut receiver = Receiver::new(scope(), config)?;
    let old = raw(1460, 0, 0, b"same low16 bits");
    assert_eq!(
        receiver.admit_authenticated(identity(0, 0), &old, Tick(1))?,
        Admission::StaleRecord
    );
    assert_eq!(receiver.prepare(ChannelId(0), Tick(1), 4)?, Prepared::Idle);
    let mut wrong = identity(1, 65536);
    wrong.scope.epoch = Epoch(2);
    let before = receiver.status();
    assert_eq!(
        receiver.admit_authenticated(wrong, &old, Tick(u64::MAX)),
        Err(Error::Scope)
    );
    assert_eq!(receiver.status(), before);
    wrong = identity(1, 65536);
    wrong.scope.direction = Direction::ResponderToInitiator;
    assert_eq!(
        receiver.admit_authenticated(wrong, &old, Tick(2)),
        Err(Error::Scope)
    );
    assert_eq!(
        receiver.admit_authenticated(identity(1, 65537), &old, Tick(2)),
        Err(Error::Malformed)
    );
    assert_eq!(
        receiver.admit_authenticated(
            identity(1, 65536 + 32768),
            &raw(1460, 0, 65536 + 32768, b"too far"),
            Tick(2)
        ),
        Err(Error::RecordWindow)
    );
    receiver.admit_authenticated(identity(1, 65536), &old, Tick(2))?;
    assert_eq!(
        drain(&mut receiver, ChannelId(0), Tick(2))?,
        vec![(0, 65536, b"same low16 bits".to_vec())]
    );
    config.first_record = RecordId(u64::MAX);
    config.first_source = SourceId(u64::MAX);
    let mut receiver = Receiver::new(scope(), config)?;
    receiver.admit_authenticated(
        identity(u64::MAX, u64::MAX),
        &raw(1460, 0, u64::MAX, b"last"),
        Tick(1),
    )?;
    assert_eq!(drain(&mut receiver, ChannelId(0), Tick(1))?.len(), 1);
    assert_eq!(receiver.expected(ChannelId(0))?, None);
    assert_eq!(receiver.status().source_floor, None);
    assert_eq!(
        receiver.admit_authenticated(identity(0, 0), &old, Tick(2)),
        Err(Error::Exhausted)
    );
    Ok(())
}
#[test]
fn held_output_tombstone_source_hole_and_fragment_deadlines_are_terminal_and_not_renewed()
-> TestResult {
    let mut config = limits();
    config.lifetime_ticks = 10;
    config.body.independent_short_frame_bytes = 128;
    for variant in 0..4 {
        let mut receiver = Receiver::new(scope(), config)?;
        let record = if variant == 2 { 0 } else { 1 };
        if variant == 2 {
            receiver.channels[0].expected = Some(RecordId(1));
        }
        let bytes = raw(1460, 0, record, b"deadline");
        receiver.admit_authenticated(identity(1, record), &bytes, Tick(1))?;
        if variant < 2 {
            receiver.prepare(ChannelId(0), Tick(2), 1)?;
            if variant == 1 {
                receiver.commit_delivery(Tick(2))?;
            }
        }
        receiver.admit_authenticated(identity(1, record), &bytes, Tick(10))?;
        assert_eq!(receiver.tick(Tick(9)), Err(Error::Time));
        let expected = receiver.expected(ChannelId(0))?;
        let error = if variant == 0 {
            receiver.commit_delivery(Tick(11))
        } else {
            receiver.tick(Tick(11))
        };
        assert_eq!(error, Err(Error::Expired));
        assert_eq!(receiver.status().failure, Some(Error::Expired));
        assert!(receiver.pending().is_none());
        assert_eq!(receiver.expected(ChannelId(0))?, expected);
        assert_eq!(
            receiver.prepare(ChannelId(0), Tick(12), 10),
            Err(Error::Expired)
        );
    }
    let mut config = limits();
    config.body.symbol_bytes = 72;
    config.lifetime_ticks = 10;
    let mut receiver = Receiver::new(scope(), config)?;
    let mut body = vec![2, 0, 100];
    body.extend(0..100);
    receiver.admit_authenticated(identity(0, 0), &fragments(72, 0, &body)[0], Tick(1))?;
    assert_eq!(receiver.tick(Tick(11)), Err(Error::Expired));
    Ok(())
}
#[test]
fn malformed_semantics_wait_for_context_then_fail_closed_without_native_delivery() -> TestResult {
    let mut receiver = Receiver::new(scope(), limits())?;
    let mut symbol = vec![0, 0, 0, 6];
    symbol.resize(1460, 0);
    receiver.admit_authenticated(identity(0, 0), &symbol, Tick(1))?;
    assert!(matches!(
        receiver.prepare(ChannelId(0), Tick(2), 1),
        Err(Error::Body(_))
    ));
    assert!(receiver.pending().is_none());
    assert_eq!(receiver.expected(ChannelId(0))?, Some(RecordId(0)));
    assert!(matches!(receiver.tick(Tick(3)), Err(Error::Body(_))));
    Ok(())
}
#[test]
fn invalid_bounds_malformed_inputs_and_clock_overflow_never_consume_replay_or_capacity()
-> TestResult {
    for config in [
        Limits {
            source_window: 0,
            ..limits()
        },
        Limits {
            record_window: 0,
            ..limits()
        },
        Limits {
            channels: 0,
            ..limits()
        },
        Limits {
            lookahead_records: 4097,
            ..limits()
        },
        Limits {
            max_fragments_per_record: 0,
            ..limits()
        },
        Limits {
            lifetime_ticks: 0,
            ..limits()
        },
    ] {
        assert!(Receiver::new(scope(), config).is_err());
    }
    let mut receiver = Receiver::new(scope(), limits())?;
    let before = receiver.status();
    let valid = raw(1460, 0, 0, b"x");
    for length in 0..valid.len() {
        assert_eq!(
            receiver.admit_authenticated(identity(0, 0), &valid[..length], Tick(1)),
            Err(Error::Malformed)
        );
        assert_eq!(receiver.status(), before);
    }
    assert_eq!(
        receiver.admit_authenticated(identity(0, 0), &valid, Tick(u64::MAX)),
        Err(Error::Time)
    );
    assert_eq!(receiver.status(), before);
    let mut unknown = valid.clone();
    unknown[3] = 8;
    assert_eq!(
        receiver.admit_authenticated(identity(0, 0), &unknown, Tick(1)),
        Err(Error::Malformed)
    );
    let mut padding = valid.clone();
    padding[1459] = 1;
    assert_eq!(
        receiver.admit_authenticated(identity(0, 0), &padding, Tick(1)),
        Err(Error::Malformed)
    );
    assert_eq!(receiver.status(), before);
    assert_eq!(receiver.commit_delivery(Tick(1)), Err(Error::NoPending));
    assert!(limits().memory_bound_bytes()? < 256 * 1024 * 1024);
    Ok(())
}

#[test]
fn compressed_header_context_is_committed_only_after_native_acceptance() -> TestResult {
    let rows: Vec<Vec<&str>> = include_str!("../tests/data/aligned-body-goldens.tsv")
        .lines()
        .filter(|line| line.starts_with("pair_64_0\t"))
        .map(|line| line.split('\t').collect())
        .collect();
    if rows.len() != 2 {
        return Err("compressed context fixture".into());
    }
    let first_context = hex(rows[0][8])?;
    let first_body = hex(rows[0][9])?;
    let second_body = hex(rows[1][9])?;
    let second_frame = hex(rows[1][7])?;
    let mut receiver = Receiver::new(scope(), limits())?;
    for (id, body) in [(0, &first_context), (1, &first_body), (2, &second_body)] {
        let mut symbol = vec![0];
        symbol.extend_from_slice(&(id as u16).to_be_bytes());
        symbol.extend_from_slice(body);
        symbol.resize(1460, 0);
        receiver.admit_authenticated(identity(id, id), &symbol, Tick(1))?;
    }
    assert_eq!(receiver.prepare(ChannelId(0), Tick(2), 8)?, Prepared::Ready);
    receiver.commit_delivery(Tick(2))?;
    assert_eq!(receiver.prepare(ChannelId(0), Tick(3), 8)?, Prepared::Ready);
    assert_eq!(
        receiver.pending().ok_or("second output")?.bytes,
        second_frame
    );
    let mut probe = Decoder::new(limits().body)?;
    let mut bytes = vec![0; 65535];
    probe.copy_context_from(&receiver.channels[0].decoder);
    probe.decode_body(&second_body, Padding::Exact, &mut bytes)?;
    assert_eq!(&bytes[..second_frame.len()], second_frame);
    for now in 4..12 {
        receiver.prepare(ChannelId(1), Tick(now), 8)?;
        assert_eq!(
            receiver.pending().ok_or("held context frame")?.bytes,
            second_frame
        );
    }
    receiver.commit_delivery(Tick(12))?;
    probe.copy_context_from(&receiver.channels[0].decoder);
    probe.decode_body(&second_body, Padding::Exact, &mut bytes)?;
    assert_ne!(&bytes[..second_frame.len()], second_frame);
    assert_eq!(receiver.expected(ChannelId(0))?, Some(RecordId(3)));
    Ok(())
}
