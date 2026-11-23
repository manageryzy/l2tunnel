use super::*;
use crate::{aligned_envelope as envelope, aligned_sender as sender, aligned_storage as heap};

#[path = "aligned_receiver/fixed_anchor_tests.rs"]
mod fixed_anchor;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
fn scope() -> Scope {
    Scope {
        session: [11; 16],
        epoch: Epoch(7),
        direction: Direction::InitiatorToResponder,
    }
}
fn limits(symbol_bytes: usize) -> Limits {
    Limits {
        body: aligned_body::Config {
            max_frame_bytes: 4096,
            symbol_bytes,
            elide_payload_length: true,
            predictive: true,
            timestamp_pair_dictionary: true,
            independent_short_frame_bytes: 0,
        },
        channels: 2,
        first_record: RecordId(0),
        first_source: SourceId(0),
        record_window: 16,
        source_window: 16,
        lookahead_records: 8,
        lookahead_bytes: 8192,
        lookahead_fragments: 64,
        max_fragments_per_record: 64,
        lifetime_ticks: 100,
    }
}
fn receiver(limits: Limits, reserved: bool) -> TestResult<Receiver> {
    let mut value = if reserved {
        let plan = heap::ReceiverPlan::for_limits(limits)?;
        Receiver::new_reserved(
            scope(),
            limits,
            heap::Limits {
                capacity_bytes: plan.capacity_bytes(),
            },
        )?
    } else {
        Receiver::new(scope(), limits)?
    };
    value.validate_compact_units_selection()?;
    value.enable_compact_units()?;
    Ok(value)
}
fn sender(limits: Limits) -> TestResult<sender::Sender> {
    Ok(sender::Sender::new(
        scope(),
        sender::Config {
            body: limits.body,
            channels: limits.channels,
            first_record: limits.first_record,
        },
    )?)
}
fn units(
    sender: &mut sender::Sender,
    limits: Limits,
    next: &mut u64,
) -> TestResult<Vec<(SymbolIdentity, Vec<u8>)>> {
    let mut units = Vec::new();
    while sender.is_pending() {
        let mut output = vec![0xa5; 10 + limits.body.symbol_bytes];
        let length = sender.write_pending_compact(&mut output)?;
        let view = envelope::decode_compact(
            scope(),
            SourceId(*next),
            limits.body.symbol_bytes,
            limits.channels,
            &output[..length],
        )?;
        units.push((view.identity, view.symbol.to_vec()));
        sender.commit_source()?;
        *next += 1;
    }
    Ok(units)
}
fn vector(trace: &str, case: &str) -> TestResult<Vec<u8>> {
    let fields = include_str!("../tests/data/aligned-body-goldens.tsv")
        .lines()
        .filter(|line| !line.starts_with('#'))
        .map(|line| line.split('\t').collect::<Vec<_>>())
        .find(|fields| fields[0] == trace && fields[1] == case)
        .ok_or("missing preserved native vector")?;
    (0..fields[7].len())
        .step_by(2)
        .map(|at| Ok(u8::from_str_radix(&fields[7][at..at + 2], 16)?))
        .collect()
}
fn deliver(receiver: &mut Receiver, channel: ChannelId, now: Tick) -> TestResult<Vec<u8>> {
    for _ in 0..4 {
        match receiver.prepare(channel, now, 1)? {
            Prepared::Ready => {
                let native = receiver.pending().ok_or("missing native")?.bytes.to_vec();
                receiver.commit_delivery(now)?;
                return Ok(native);
            }
            Prepared::Progress => {}
            Prepared::Idle => return Err("unexpected native gap".into()),
        }
    }
    Err("bounded native drain exhausted".into())
}

#[test]
fn compact_exact_fragment_units_reorder_without_losing_zero_tail_or_storage() -> TestResult {
    let limits = limits(16);
    let mut sender = sender(limits)?;
    let mut frame = vec![0; 25];
    frame[..3].copy_from_slice(&[1, 2, 3]);
    sender.stage_raw(ChannelId(1), &frame)?;
    let units = units(&mut sender, limits, &mut 0)?;
    assert_eq!(
        units.iter().map(|(_, unit)| unit.len()).collect::<Vec<_>>(),
        [16, 16, 16, 12]
    );
    for (index, (identity, bytes)) in units.iter().enumerate() {
        let witness = unit_witness_compact(*identity, bytes, limits)?;
        assert_eq!((witness.index, witness.count), (index, 4));
        assert_eq!(witness.identity.channel, ChannelId(1));
        for end in 0..bytes.len() {
            assert!(unit_witness_compact(*identity, &bytes[..end], limits).is_err());
        }
    }
    for reserved in [false, true] {
        let mut receiver = receiver(limits, reserved)?;
        let usage = receiver.storage_usage();
        let (identity, last) = &units[3];
        assert_eq!(
            receiver.admit_authenticated(*identity, last, Tick(1))?,
            Admission::Accepted
        );
        assert_eq!(receiver.prepare(ChannelId(1), Tick(1), 1)?, Prepared::Idle);
        for (identity, bytes) in &units[..3] {
            receiver.admit_authenticated(*identity, bytes, Tick(2))?;
        }
        assert_eq!(receiver.prepare(ChannelId(1), Tick(2), 1)?, Prepared::Ready);
        assert_eq!(receiver.pending().ok_or("native")?.bytes, frame);
        assert_eq!(
            receiver.admit_authenticated(*identity, last, Tick(3))?,
            Admission::StaleSource
        );
        assert_eq!(receiver.pending().ok_or("held native")?.bytes, frame);
        receiver.commit_delivery(Tick(3))?;
        assert_eq!(receiver.storage_usage(), usage);
        assert_eq!(receiver.enable_compact_units(), Err(Error::Configuration));
    }
    Ok(())
}

#[test]
fn compact_predictive_exact_length_rejects_missing_zero_with_atomic_rollback() -> TestResult {
    let limits = limits(1460);
    let first = vector("mask_0", "0")?;
    let second = vector("mask_0", "1")?;
    let mut sender = sender(limits)?;
    let mut next = 0;
    sender.stage(ChannelId(0), &first)?;
    let initial = units(&mut sender, limits, &mut next)?;
    sender.stage(ChannelId(0), &second)?;
    let mut predicted = units(&mut sender, limits, &mut next)?;
    assert_eq!(predicted.len(), 1);
    let (identity, bytes) = &mut predicted[0];
    assert_eq!(bytes[3] & 7, 7);
    *bytes.last_mut().ok_or("predictive payload")? = 0;
    // This byte is real payload, not generated padding. The context knows that
    // the full payload is required even when its final value is zero.
    for reserved in [false, true] {
        let mut receiver = receiver(limits, reserved)?;
        let usage = receiver.storage_usage();
        for (identity, bytes) in &initial {
            receiver.admit_authenticated(*identity, bytes, Tick(1))?;
        }
        assert_eq!(deliver(&mut receiver, ChannelId(0), Tick(1))?, first);
        let before = receiver.status();
        let truncated = [AuthenticatedSymbol {
            identity: *identity,
            bytes: &bytes[..bytes.len() - 1],
        }];
        assert!(matches!(
            receiver.admit_validated_batch_authenticated(&truncated, Tick(2)),
            Err(Error::Body(_))
        ));
        assert_eq!(receiver.status(), before);
        let valid = [AuthenticatedSymbol {
            identity: *identity,
            bytes,
        }];
        assert_eq!(
            receiver.admit_validated_batch_authenticated(&valid, Tick(2))?,
            [Admission::Accepted]
        );
        let native = deliver(&mut receiver, ChannelId(0), Tick(2))?;
        assert_eq!(native.len(), second.len());
        assert_eq!(native.last(), Some(&0));
        assert_eq!(receiver.storage_usage(), usage);
    }
    Ok(())
}

#[test]
fn compact_four_byte_predictive_unit_decodes_without_padding() -> TestResult {
    let limits = limits(1460);
    let mut sender = sender(limits)?;
    let mut receiver = receiver(limits, true)?;
    let mut next = 0;
    for case in ["0", "1"] {
        let native = vector("pair_0_0", case)?;
        sender.stage(ChannelId(0), &native)?;
        let units = units(&mut sender, limits, &mut next)?;
        if case == "1" {
            assert_eq!(units.len(), 1);
            assert_eq!(units[0].1.len(), 4);
        }
        for (identity, bytes) in &units {
            receiver.admit_authenticated(*identity, bytes, Tick(1))?;
        }
        assert_eq!(deliver(&mut receiver, ChannelId(0), Tick(1))?, native);
    }
    Ok(())
}

#[test]
fn compact_same_tick_admission_and_duplicate_never_renew_original_expiry() -> TestResult {
    for reserved in [false, true] {
        let mut receiver = receiver(limits(64), reserved)?;
        let identity = SymbolIdentity {
            scope: scope(),
            source: SourceId(1),
            record: RecordId(1),
        };
        let bytes = [0, 0, 1, 2, 0, 3, 9, 0, 0];
        receiver.tick(Tick(1))?;
        receiver.admit_authenticated(identity, &bytes, Tick(1))?;
        assert_eq!(receiver.deadline(), Some(Tick(101)));
        for _ in 0..32 {
            assert_eq!(
                receiver.admit_authenticated(identity, &bytes, Tick(1))?,
                Admission::Duplicate
            );
        }
        receiver.tick(Tick(100))?;
        assert_eq!(
            receiver.admit_authenticated(identity, &bytes, Tick(100))?,
            Admission::Duplicate
        );
        assert_eq!(receiver.deadline(), Some(Tick(101)));
        assert_eq!(receiver.tick(Tick(101)), Err(Error::Expired));
        assert_eq!(
            receiver.tick(Tick(100)),
            Err(Error::Expired),
            "sticky expiry precedes memoization and regression"
        );
    }
    Ok(())
}

#[test]
fn compact_failed_batches_restore_expiry_check_clock_with_retained_ledger() -> TestResult {
    for reserved in [false, true] {
        let mut receiver = receiver(limits(64), reserved)?;
        let identity = |source, record| SymbolIdentity {
            scope: scope(),
            source: SourceId(source),
            record: RecordId(record),
        };
        let first = [0, 0, 1, 2, 0, 3, 9, 0, 0];
        let next = [0, 0, 2, 2, 0, 3, 8, 0, 0];
        let conflict = [0, 0, 2, 2, 0, 3, 7, 0, 0];
        receiver.admit_authenticated(identity(1, 1), &first, Tick(1))?;
        let before = receiver.status();
        let bad = [
            AuthenticatedSymbol {
                identity: identity(2, 2),
                bytes: &next,
            },
            AuthenticatedSymbol {
                identity: identity(2, 2),
                bytes: &conflict,
            },
        ];
        assert_eq!(
            receiver.admit_batch_authenticated(&bad, Tick(50)),
            Err(Error::Conflict)
        );
        assert_eq!(receiver.status(), before);
        assert_eq!(receiver.last_time, Some(Tick(1)));
        let unresolved = [AuthenticatedSymbol {
            identity: identity(2, 2),
            bytes: &next,
        }];
        assert_eq!(
            receiver.admit_validated_batch_authenticated(&unresolved, Tick(50)),
            Err(Error::UnresolvedContext)
        );
        assert_eq!(receiver.status(), before);
        assert_eq!(receiver.last_time, Some(Tick(1)));
        assert_eq!(receiver.tick(Tick(0)), Err(Error::Time));
        receiver.tick(Tick(2))?;
        assert_eq!(receiver.deadline(), Some(Tick(101)));
        assert_eq!(receiver.tick(Tick(101)), Err(Error::Expired));
    }
    Ok(())
}
