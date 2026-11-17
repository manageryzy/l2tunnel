use super::*;
#[path = "packed_sender_copy_tests.rs"]
mod copies;
use crate::{aligned_body, aligned_receiver as receiver};
use l2tunnel_core::Epoch;
type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
fn buffer_snapshot_distinguishes_timer_hold_sealed_source_and_staged_frame() -> TestResult {
    let mut sender = Sender::new(scope(), config(64))?;
    sender.stage_raw(ChannelId(0), b"first", 0)?;
    let held = sender.buffer_snapshot();
    assert_eq!(held.stage.stage.items, 0);
    assert_eq!(held.packing.source.items, 1);
    assert_eq!(held.packing.source.bytes, 11);
    assert_eq!(held.packing.source.byte_capacity, 64);
    assert_eq!(held.packing.units, 1);
    assert_eq!(held.packing.unit_capacity, 4);
    assert_eq!(held.packing.sealed, None);
    sender.poll(500)?;
    let sealed = sender.buffer_snapshot();
    assert_eq!(sealed.packing.source, held.packing.source);
    assert_eq!(sealed.packing.sealed, Some(packed::SealReason::Timer));
    sender.stage_raw(ChannelId(1), b"next", 500)?;
    let staged = sender.buffer_snapshot();
    assert_eq!(staged.stage.stage.items, 1);
    assert_eq!(staged.packing, sealed.packing);
    assert_eq!(
        sender.stage_raw(ChannelId(0), b"refused", 500),
        Err(Error::Busy)
    );
    assert_eq!(sender.buffer_snapshot(), staged);
    sender.commit_source()?;
    assert_eq!(sender.buffer_snapshot().packing.source.items, 0);
    assert_eq!(sender.buffer_snapshot().stage.stage.items, 1);
    sender.poll(500)?;
    assert_eq!(sender.buffer_snapshot().stage.stage.items, 0);
    assert_eq!(sender.buffer_snapshot().packing.source.bytes, 10);
    Ok(())
}

#[test]
fn clock_exhaustion_rejects_fresh_ownership_and_is_terminal_for_an_owned_frame() -> TestResult {
    let config = config(64);
    let error = Error::Packing(packed::Error::ClockExhausted);
    let mut sender = Sender::new(scope(), config)?;
    let saved = sender.status();
    assert_eq!(
        sender.stage_raw(ChannelId(0), b"fresh", u64::MAX),
        Err(error)
    );
    assert_eq!(sender.status(), saved);
    // Rejection did not advance time or consume the frame's record identity.
    sender.stage_raw(ChannelId(0), b"valid", 1)?;
    sender.flush(1)?;
    let first = copy_to_test_owner(&mut sender, config, 0)?;
    let view = envelope::decode(config.envelope(), scope(), &first)?;
    assert_eq!(
        view.units()?.next().ok_or("missing unit")?.identity.record,
        RecordId(0)
    );

    let mut sender = Sender::new(scope(), config)?;
    sender.stage_raw(ChannelId(0), b"earlier", 1)?;
    sender.flush(1)?;
    sender.stage_raw(ChannelId(1), b"owned", 2)?;
    assert!(sender.status().staged_frame);
    copy_to_test_owner(&mut sender, config, 0)?;
    assert_eq!(sender.poll(u64::MAX), Err(error));
    let failed = sender.status();
    assert_eq!(failed.failure, Some(error));
    assert!(failed.staged_frame);
    assert!(!sender.is_idle());
    assert_eq!(sender.poll(u64::MAX), Err(error));
    assert_eq!(sender.flush(u64::MAX), Err(error));
    assert_eq!(sender.commit_source(), Err(error));
    assert_eq!(sender.status(), failed);
    Ok(())
}
fn scope() -> Scope {
    Scope {
        session: [3; 16],
        epoch: Epoch(7),
        direction: receiver::Direction::InitiatorToResponder,
    }
}
fn config(symbol: usize) -> Config {
    Config {
        sender: aligned::Config {
            body: aligned_body::Config {
                max_frame_bytes: 4096,
                symbol_bytes: symbol,
                elide_payload_length: true,
                predictive: true,
                timestamp_pair_dictionary: true,
                independent_short_frame_bytes: 0,
            },
            channels: 2,
            first_record: RecordId(0),
        },
        packing: packed::Config {
            symbol_bytes: symbol,
            hold_micros: 500,
        },
        max_units: 4,
        first_unit: SourceId(0),
        work_limit: 4,
    }
}
// This bounded test-owned source buffer substitutes only for the local copy
// boundary. These codec tests do not claim an ARQ/FEC execution or peer receipt.
fn copy_to_test_owner(sender: &mut Sender, config: Config, source: u64) -> Result<Vec<u8>, Error> {
    let mut copied = vec![
        0;
        config
            .envelope()
            .max_source_bytes()
            .map_err(Error::Envelope)?
    ];
    let length = sender.write_pending(SourceId(source), &mut copied)?;
    copied.truncate(length);
    sender.commit_source()?;
    Ok(copied)
}
fn receive(
    config: Config,
    receiver: &mut receiver::Receiver,
    source: u64,
    bytes: &[u8],
) -> TestResult {
    let view = envelope::decode(config.envelope(), scope(), bytes)?;
    assert_eq!(view.identity().source, SourceId(source));
    assert_eq!(
        view.identity().first_unit,
        receiver.status().source_floor.ok_or("exhausted receiver")?
    );
    let units = view
        .units()?
        .map(|unit| {
            let mut bytes = unit.bytes.to_vec();
            bytes.resize(config.packing.symbol_bytes, 0);
            (unit.identity, bytes)
        })
        .collect::<Vec<_>>();
    let inputs = units
        .iter()
        .map(|(identity, bytes)| receiver::AuthenticatedSymbol {
            identity: *identity,
            bytes,
        })
        .collect::<Vec<_>>();
    assert!(
        receiver
            .admit_batch_authenticated(&inputs, receiver::Tick(1))?
            .iter()
            .all(|result| *result == receiver::Admission::Accepted)
    );
    Ok(())
}
fn receiver(config: Config) -> Result<receiver::Receiver, receiver::Error> {
    receiver::Receiver::new(
        scope(),
        receiver::Limits {
            body: config.sender.body,
            channels: 2,
            first_record: config.sender.first_record,
            first_source: config.first_unit,
            record_window: 64,
            source_window: 128,
            lookahead_records: 64,
            lookahead_bytes: 262144,
            lookahead_fragments: 4096,
            max_fragments_per_record: 1024,
            lifetime_ticks: 10000,
        },
    )
}
fn hex(input: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    (0..input.len())
        .step_by(2)
        .map(|i| Ok(u8::from_str_radix(&input[i..i + 2], 16)?))
        .collect()
}

#[test]
fn timer_and_recovery_pressure_retain_exact_source_and_one_pending_frame() -> TestResult {
    let config = config(64);
    let mut sender = Sender::new(scope(), config)?;
    sender.stage_raw(ChannelId(0), &[1, 2, 0, 0], 100)?;
    sender.stage_raw(ChannelId(1), &[3, 4, 0, 0], 200)?;
    assert_eq!(sender.deadline_micros(), Some(600));
    let mut out = vec![0xa5; config.envelope().max_source_bytes()?];
    assert_eq!(
        sender.write_pending(SourceId(9), &mut out),
        Err(Error::NoPending)
    );
    assert!(out.iter().all(|byte| *byte == 0xa5));
    sender.poll(599)?;
    assert!(!sender.status().packing.sealed);
    sender.poll(600)?;
    let length = sender.write_pending(SourceId(9), &mut out)?;
    let original = out.clone();
    sender.stage_raw(ChannelId(0), b"later", 601)?;
    assert!(sender.status().staged_frame);
    assert_eq!(
        sender.stage_raw(ChannelId(1), b"busy", 601),
        Err(Error::Busy)
    );
    assert_eq!(sender.status().next_unit, Some(SourceId(2)));
    sender.poll(900)?;
    assert_eq!(sender.deadline_micros(), Some(600));
    assert_eq!(sender.write_pending(SourceId(9), &mut out)?, length);
    assert_eq!(out, original);
    let mut short = [0xa5; 12];
    assert!(matches!(
        sender.write_pending(SourceId(9), &mut short),
        Err(Error::Envelope(envelope::Error::OutputTooSmall { .. }))
    ));
    assert_eq!(short, [0xa5; 12]);
    let stored = copy_to_test_owner(&mut sender, config, 9)?;
    assert_eq!(&stored, out.get(..length).ok_or("prefix")?);
    sender.poll(901)?;
    assert_eq!(sender.status().first_unit, Some(SourceId(2)));
    assert_eq!(sender.deadline_micros(), Some(1401));
    assert_eq!(
        sender.poll(900),
        Err(Error::Packing(packed::Error::ClockRegression))
    );
    sender.flush(902)?;
    copy_to_test_owner(&mut sender, config, 10)?;
    assert!(sender.is_idle());
    Ok(())
}

#[test]
fn negotiated_unit_limit_seals_before_accepting_another_frame() -> TestResult {
    let mut config = config(128);
    config.max_units = 2;
    let mut sender = Sender::new(scope(), config)?;
    sender.stage_raw(ChannelId(0), b"one", 0)?;
    sender.stage_raw(ChannelId(1), b"two", 1)?;
    assert_eq!(sender.status().packing.units, 2);
    assert!(sender.status().packing.sealed);
    sender.stage_raw(ChannelId(0), b"three", 2)?;
    assert!(sender.status().staged_frame);
    let first = copy_to_test_owner(&mut sender, config, 99)?;
    let view = envelope::decode(config.envelope(), scope(), &first)?;
    assert_eq!(view.len(), 2);
    assert_eq!(view.identity().first_unit, SourceId(0));
    sender.flush(3)?;
    let second = copy_to_test_owner(&mut sender, config, 100)?;
    let view = envelope::decode(config.envelope(), scope(), &second)?;
    assert_eq!(view.len(), 1);
    assert_eq!(view.identity().first_unit, SourceId(2));
    assert!(sender.is_idle());
    Ok(())
}

#[test]
fn context_fragments_wrap_and_raw_zero_tails_round_trip_through_envelopes() -> TestResult {
    let mut config = config(48);
    config.sender.first_record = RecordId(65535);
    config.work_limit = 1;
    let fixture = include_str!("../tests/data/aligned-sender-goldens.tsv");
    let frame = hex(fixture
        .lines()
        .find(|line| line.starts_with("symbol128\t0\t"))
        .ok_or("fixture")?
        .split('\t')
        .nth(6)
        .ok_or("frame")?)?;
    let mut sender = Sender::new(scope(), config)?;
    let mut receiver = receiver(config)?;
    sender.stage(ChannelId(1), &frame, 0)?;
    let mut source = 100u64;
    let mut units = 0u64;
    for now in 1..256 {
        sender.flush(now)?;
        if sender.status().packing.sealed {
            let bytes = copy_to_test_owner(&mut sender, config, source)?;
            units += envelope::decode(config.envelope(), scope(), &bytes)?.len() as u64;
            receive(config, &mut receiver, source, &bytes)?;
            source += 1;
        }
        if sender.is_idle() {
            break;
        }
    }
    assert!(sender.is_idle());
    assert!(units >= 3);
    assert_eq!(sender.status().next_unit, Some(SourceId(units)));
    for _ in 0..8 {
        if receiver.prepare(ChannelId(1), receiver::Tick(1), 1)? == receiver::Prepared::Ready {
            break;
        }
    }
    assert_eq!(receiver.pending().ok_or("native frame")?.bytes, frame);
    receiver.commit_delivery(receiver::Tick(1))?;
    assert_eq!(receiver.expected(ChannelId(1))?, Some(RecordId(65537)));
    sender.stage_raw(ChannelId(0), &[7, 8, 0, 0, 0, 0], 300)?;
    sender.flush(301)?;
    let bytes = copy_to_test_owner(&mut sender, config, source)?;
    receive(config, &mut receiver, source, &bytes)?;
    assert_eq!(
        receiver.prepare(ChannelId(0), receiver::Tick(1), 1)?,
        receiver::Prepared::Ready
    );
    assert_eq!(
        receiver.pending().ok_or("raw zero tail")?.bytes,
        [7, 8, 0, 0, 0, 0]
    );
    Ok(())
}

#[test]
fn exhausted_units_never_wrap_or_discard_partial_frame_ownership() -> TestResult {
    let mut config = config(32);
    config.first_unit = SourceId(u64::MAX);
    let mut sender = Sender::new(scope(), config)?;
    sender.stage_raw(ChannelId(0), b"last", 0)?;
    sender.flush(1)?;
    let bytes = copy_to_test_owner(&mut sender, config, u64::MAX)?;
    assert_eq!(
        envelope::decode(config.envelope(), scope(), &bytes)?
            .identity()
            .first_unit,
        SourceId(u64::MAX)
    );
    assert_eq!(
        sender.stage_raw(ChannelId(0), b"again", 2),
        Err(Error::Exhausted)
    );
    assert!(sender.is_idle());
    let mut fragmented = Sender::new(scope(), config)?;
    fragmented.stage_raw(ChannelId(0), &[4; 100], 0)?;
    assert!(fragmented.status().staged_frame);
    copy_to_test_owner(&mut fragmented, config, 0)?;
    assert_eq!(fragmented.poll(1), Err(Error::Exhausted));
    assert_eq!(fragmented.status().failure, Some(Error::Exhausted));
    assert!(fragmented.status().staged_frame);
    assert!(!fragmented.is_idle());
    assert_eq!(fragmented.flush(2), Err(Error::Exhausted));
    Ok(())
}

#[test]
fn invalid_geometry_work_and_count_are_rejected_before_allocation() {
    let original = config(64);
    for changed in [
        Config {
            max_units: 0,
            ..original
        },
        Config {
            work_limit: 0,
            ..original
        },
        Config {
            work_limit: 256,
            ..original
        },
        Config {
            packing: packed::Config {
                symbol_bytes: 65,
                ..original.packing
            },
            ..original
        },
        Config {
            sender: aligned::Config {
                channels: 256,
                ..original.sender
            },
            ..original
        },
    ] {
        assert!(changed.memory_bound_bytes().is_err());
        assert!(Sender::new(scope(), changed).is_err());
    }
}
