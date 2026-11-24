//! Exact reference, replay, transaction, and storage boundaries on real IP headers.
use super::*;

fn selected(limits: Limits, reserved: bool, compact: bool) -> TestResult<Receiver> {
    let mut rx = if reserved {
        let plan = heap::ReceiverPlan::for_fixed_anchor_ip_limits(limits)?;
        let previous =
            heap::ReceiverPlan::for_ip_limits_with_early_replay(limits)?.capacity_bytes();
        assert_eq!(
            plan.capacity_bytes() - previous,
            Receiver::fixed_anchor_history_bytes(limits)?
        );
        let capacity_bytes = plan.capacity_bytes();
        assert!(matches!(
            Receiver::new_reserved_ip_with_fixed_anchors(
                scope(),
                limits,
                heap::Limits {
                    capacity_bytes: capacity_bytes - 1
                }
            ),
            Err(heap::Error::Limit { .. })
        ));
        let rx = Receiver::new_reserved_ip_with_fixed_anchors(
            scope(),
            limits,
            heap::Limits { capacity_bytes },
        )?;
        assert_eq!(
            rx.storage_usage()
                .ok_or("missing reservation")?
                .capacity_bytes,
            capacity_bytes
        );
        rx
    } else {
        Receiver::new_ip_with_fixed_anchors(scope(), limits)?
    };
    if compact {
        rx.enable_compact_units()?;
    }
    Ok(rx)
}

fn identity(source: u64, record: u64) -> SymbolIdentity {
    SymbolIdentity {
        scope: scope(),
        source: SourceId(source),
        record: RecordId(record),
    }
}

fn unit(channel: u8, record: u64, body: &[u8], padded: bool) -> Vec<u8> {
    let mut bytes = vec![channel];
    bytes.extend_from_slice(&(record as u16).to_be_bytes());
    bytes.extend_from_slice(body);
    if padded {
        bytes.resize(128, 0);
    }
    bytes
}

fn add(
    rx: &mut Receiver,
    source: u64,
    channel: u8,
    record: u64,
    body: &[u8],
) -> Result<Admission, Error> {
    rx.admit_authenticated(
        identity(source, record),
        &unit(channel, record, body, !rx.compact_units),
        Tick(1),
    )
}

fn prepare(rx: &mut Receiver) -> Result<Prepared, Error> {
    rx.prepare_with_independent_packets(
        ChannelId(0),
        Tick(1),
        1,
        |_| false,
        |_, _| EarlyDecision::Allow,
    )
}
fn take(rx: &mut Receiver, record: u64, frame: &[u8], early: bool) -> TestResult {
    for _ in 0..16 {
        if prepare(rx)? != Prepared::Progress {
            break;
        }
    }
    let output = rx.pending().ok_or("missing physical output")?;
    assert_eq!(
        (output.record, output.bytes, output.early),
        (RecordId(record), frame, early)
    );
    assert_eq!(prepare(rx)?, Prepared::Ready);
    rx.commit_delivery(Tick(1))?;
    Ok(())
}
fn fixture() -> TestResult<(Vec<u8>, Vec<u8>)> {
    // Same native IPv4 packet independently asserted in tcp_header::ip_tests.
    let hex = "45000037ffff4000400626bf0a0000010a00000201bb1388fffffffe000000098018ffff5c5b00000101080affffffff000000070102f0";
    let frame = (0..hex.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&hex[at..at + 2], 16))
        .collect::<Result<Vec<_>, _>>()?;
    let mut output = [0; 256];
    crate::tcp_header::IpHeaderEncoder::new(4096)?.encode(&frame, &mut output)?;
    let length = 3 + usize::from(u16::from_be_bytes([output[1], output[2]]));
    assert_eq!(output[0], 8);
    Ok((frame, output[..length].to_vec()))
}

#[test]
fn fixed_anchor_crosses_gaps_and_retires_once_using_live_and_archived_contexts() -> TestResult {
    let (frame, context) = fixture()?;
    for reserved in [false, true] {
        for compact in [false, true] {
            let mut rx = selected(limits(128), reserved, compact)?;
            let usage = rx.storage_usage();
            let delta = |distance| [11, distance, 9, 0, 3, 0, 1, 2, 0xf0];
            add(&mut rx, 0, 0, 3, &delta(2))?;
            add(&mut rx, 1, 1, 1, &context)?;
            assert_eq!(prepare(&mut rx)?, Prepared::Idle);
            add(&mut rx, 2, 0, 1, &context)?;
            assert_eq!(prepare(&mut rx)?, Prepared::Progress); // One charged context decode.
            take(&mut rx, 3, &frame, true)?;
            assert_eq!(add(&mut rx, 3, 0, 3, &delta(2))?, Admission::Duplicate);
            assert_eq!(prepare(&mut rx)?, Prepared::Idle);
            add(&mut rx, 4, 0, 0, &[2, 0, 1, 55])?;
            take(&mut rx, 0, &[55], false)?;
            assert_eq!(prepare(&mut rx)?, Prepared::Progress); // Retires context 1.
            add(&mut rx, 5, 0, 4, &delta(3))?;
            take(&mut rx, 4, &frame, true)?;
            add(&mut rx, 6, 0, 2, &[2, 0, 1, 22])?;
            take(&mut rx, 2, &[22], false)?;
            assert_eq!(prepare(&mut rx)?, Prepared::Progress);
            assert_eq!(prepare(&mut rx)?, Prepared::Progress);
            assert_eq!(prepare(&mut rx)?, Prepared::Idle);
            assert_eq!(rx.expected(ChannelId(0))?, Some(RecordId(5)));
            assert_eq!(rx.status().early_tombstones, 0);
            // A newer context changes the source TCP port. Record 9 still names
            // context 1 at the maximum distance, even after context 5 retired.
            let mut newer = context.clone();
            newer[3 + 20] ^= 1;
            add(&mut rx, 7, 0, 5, &newer)?;
            assert_eq!(prepare(&mut rx)?, Prepared::Progress);
            add(&mut rx, 8, 0, 9, &delta(8))?;
            take(&mut rx, 9, &frame, true)?;
            assert_eq!(rx.storage_usage(), usage);
        }
    }
    Ok(())
}

#[test]
fn fixed_anchor_grammar_journal_and_old_hole_deadline_are_strict() -> TestResult {
    let (_, context) = fixture()?;
    let delta = [11, 2, 9, 0, 3, 0, 1, 2, 0xf0];
    for reserved in [false, true] {
        let mut rx = selected(limits(128), reserved, true)?;
        for invalid in [
            &delta[..],
            &[11, 0, 9, 0, 0, 0],
            &[11, 9, 9, 0, 0, 0],
            &[11, 1, 11],
            &[11, 1, 2, 0, 1, 1],
            &[9, 0, 0, 0],
            &[10, 0, 1, 0, 8, 0],
        ] {
            assert_eq!(add(&mut rx, 0, 0, 0, invalid), Err(Error::Malformed));
        }
        let context_unit = unit(0, 0, &context, false);
        let future = unit(0, 2, &delta, false);
        let symbols = [
            AuthenticatedSymbol {
                identity: identity(0, 0),
                bytes: &context_unit,
            },
            AuthenticatedSymbol {
                identity: identity(1, 2),
                bytes: &future,
            },
        ];
        assert_eq!(
            rx.admit_validated_batch_authenticated(&symbols, Tick(1)),
            Err(Error::UnresolvedContext)
        );
        assert_eq!(rx.expected(ChannelId(0))?, Some(RecordId(0)));
        assert_eq!(rx.status().retained_records, 0);
        add(&mut rx, 0, 0, 2, &delta)?;
        assert_eq!(prepare(&mut rx)?, Prepared::Idle); // Aborted context cannot leak.
        add(&mut rx, 1, 0, 0, &context)?;
        let (frame, _) = fixture()?;
        take(&mut rx, 2, &frame, true)?;
        assert_eq!(rx.deadline(), Some(Tick(101)));
        assert_eq!(rx.tick(Tick(101)), Err(Error::Expired));
        let mut previous = Receiver::new_ip_with_early_replay(scope(), limits(128))?;
        previous.enable_compact_units()?;
        assert_eq!(add(&mut previous, 0, 0, 2, &delta), Err(Error::Malformed));
    }
    Ok(())
}

#[test]
fn fixed_anchor_real_sender_recovers_fragmented_context_and_explicit_or_elided_native() -> TestResult
{
    let (frame, _) = fixture()?;
    for symbol in [9, 16] {
        let mut limits = limits(symbol);
        limits.source_window = 128;
        limits.lookahead_fragments = 128;
        let mut sender = sender::Sender::new_ip(
            scope(),
            sender::Config {
                body: limits.body,
                channels: limits.channels,
                first_record: RecordId(1),
            },
        )?;
        let (_, observed) = sender.stage_fixed_anchor_headers_observed(ChannelId(0), &frame)?;
        let units = units(&mut sender, limits, &mut 0)?;
        let (anchors, native): (Vec<_>, Vec<_>) =
            units.iter().partition(|(id, _)| id.record == RecordId(1));
        assert!(anchors.len() > 1);
        if symbol == 9 {
            assert!(native.len() > 1);
            assert_eq!(observed.kind, aligned_body::BodyKind::Delta);
        } else {
            assert_eq!(native.len(), 1);
            assert_eq!(observed.kind, aligned_body::BodyKind::Elided);
        }
        for reserved in [false, true] {
            for compact in [false, true] {
                let mut rx = selected(limits, reserved, compact)?;
                let accept =
                    |rx: &mut Receiver, (id, bytes): &(SymbolIdentity, Vec<u8>)| -> TestResult {
                        let mut bytes = bytes.clone();
                        if !compact {
                            bytes.resize(symbol, 0);
                        }
                        assert_eq!(
                            rx.admit_authenticated(*id, &bytes, Tick(1))?,
                            Admission::Accepted
                        );
                        Ok(())
                    };
                for row in native.iter().rev().chain(anchors[1..].iter().rev()) {
                    accept(&mut rx, row)?;
                }
                assert_eq!(prepare(&mut rx)?, Prepared::Idle);
                accept(&mut rx, anchors[0])?;
                take(&mut rx, 2, &frame, true)?;
                assert_eq!(prepare(&mut rx)?, Prepared::Idle);
            }
        }
    }
    Ok(())
}

/// RRP-08: after the recovery owner abandons a source, a channel head skips
/// the record lost with it, a delta whose anchor was lost is discarded rather
/// than failing the receiver, and later records deliver. Without a declared
/// loss the same gap only waits.
#[test]
fn declared_loss_skips_lost_heads_and_discards_orphaned_deltas() -> TestResult {
    let (frame, context) = fixture()?;
    let delta = |distance| [11, distance, 9, 0, 3, 0, 1, 2, 0xf0];
    for reserved in [false, true] {
        for compact in [false, true] {
            let mut rx = selected(limits(128), reserved, compact)?;
            let usage = rx.storage_usage();
            add(&mut rx, 0, 0, 0, &[2, 0, 1, 55])?;
            take(&mut rx, 0, &[55], false)?;
            // Source 1 carried context record 1 and is never admitted.
            add(&mut rx, 2, 0, 2, &delta(1))?;
            assert_eq!(prepare(&mut rx)?, Prepared::Idle);
            assert_eq!(rx.expected(ChannelId(0))?, Some(RecordId(1)));
            assert_eq!(rx.status().source_floor, Some(SourceId(1)));
            // A declared loss below an already-admitted unit is a no-op for
            // the floor but still enables loss handling.
            rx.abandon_sources(SourceId(1), Tick(1))?;
            assert_eq!(rx.status().loss, LossStatus::default());
            rx.abandon_sources(SourceId(2), Tick(1))?;
            assert_eq!(rx.status().source_floor, Some(SourceId(3)));
            assert_eq!(prepare(&mut rx)?, Prepared::Idle);
            assert_eq!(rx.expected(ChannelId(0))?, Some(RecordId(3)));
            assert_eq!(
                rx.status().loss,
                LossStatus {
                    abandoned_units: 1,
                    dropped_records: 1,
                    skipped_records: 1,
                }
            );
            assert_eq!(rx.status().failure, None);
            // A fresh anchor and its delta deliver normally afterwards.
            add(&mut rx, 3, 0, 3, &context)?;
            add(&mut rx, 4, 0, 4, &delta(1))?;
            assert_eq!(prepare(&mut rx)?, Prepared::Progress);
            take(&mut rx, 4, &frame, false)?;
            assert_eq!(rx.status().retained_records, 0);
            assert_eq!(rx.storage_usage(), usage);
        }
    }
    Ok(())
}

/// RRP-08: a later fragment of a record whose first fragment went with an
/// abandoned source is stale, keeps its unit proof and never fails the
/// receiver. A batch that fails after such a drop restores the loss counters.
#[test]
fn declared_loss_makes_orphaned_fragments_stale_and_rolls_back_counters() -> TestResult {
    let tail = |record: u64| {
        let mut body = vec![4];
        body.extend_from_slice(&200_u16.to_be_bytes());
        body.extend_from_slice(&120_u16.to_be_bytes());
        body.extend_from_slice(&[7; 80]);
        unit(0, record, &body, true)
    };
    for reserved in [false, true] {
        let mut rx = selected(limits(128), reserved, false)?;
        add(&mut rx, 0, 0, 0, &[2, 0, 1, 55])?;
        take(&mut rx, 0, &[55], false)?;
        // Without a declared loss an orphaned tail is ordinary custody.
        let mut strict = selected(limits(128), reserved, false)?;
        strict.admit_authenticated(identity(1, 1), &tail(1), Tick(1))?;
        assert_eq!(strict.status().retained_records, 1);
        // Source 1 carried record 1's first fragment and was abandoned.
        rx.abandon_sources(SourceId(2), Tick(1))?;
        let before = rx.status();
        let stale = tail(1);
        let bad = unit(0, 3, &[0xee], true);
        let mut outcomes = [Admission::Duplicate; 2];
        assert!(
            rx.admit_batch_authenticated_into(
                &[
                    AuthenticatedSymbol {
                        identity: identity(2, 1),
                        bytes: &stale,
                    },
                    AuthenticatedSymbol {
                        identity: identity(3, 3),
                        bytes: &bad,
                    },
                ],
                Tick(1),
                &mut outcomes,
            )
            .is_err()
        );
        assert_eq!(rx.status(), before);
        assert_eq!(
            rx.admit_authenticated(identity(2, 1), &stale, Tick(1))?,
            Admission::StaleRecord
        );
        let status = rx.status();
        assert_eq!(
            (status.source_floor, status.retained_records, status.failure),
            (Some(SourceId(3)), 0, None)
        );
        assert_eq!(status.loss.dropped_records, before.loss.dropped_records + 1);
        add(&mut rx, 3, 0, 2, &[2, 0, 1, 22])?;
        take(&mut rx, 2, &[22], false)?;
    }
    Ok(())
}
