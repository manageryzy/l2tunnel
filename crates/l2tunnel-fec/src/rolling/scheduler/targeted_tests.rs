//! Real charged wire handoffs under selective loss, with an old missing source.
use super::*;

fn setup() -> (Policy, Scope, WorkBudget) {
    (
        Policy {
            recovery: Config {
                window: 256,
                local_window: 128,
                global_every: 16,
                max_payload: 8,
                max_rows: 4,
                repair_history: 32,
                handoff_sources: 256,
                job_ticks: 500_000,
                debt_ticks: 2_000_000,
                handoff_ticks: 1_000_000,
                memory_bytes: 64 << 20,
            },
            repair_numerator: 0,
            repair_denominator: 1,
            tail_ticks: 140_000,
            feedback_ticks: 1_000,
            feedback_packets: 64,
            memory_bytes: 64 << 20,
            source_wire: wire::SourceWire::TargetedExact,
        },
        Scope {
            session: [3; 16],
            epoch: 4,
            stream: 1,
            direction: 0,
        },
        WorkBudget {
            field: 65_536,
            copies: 65_536,
            metadata: 65_536,
        },
    )
}
fn admit_source(s: &mut Sender, id: u32, now: Tick) -> Result<(), Error> {
    let bytes = id.to_be_bytes();
    assert_eq!(s.admit_source(&bytes, now)?, SourceId(id));
    s.confirm_output(OutputId::Source(SourceId(id)), now)
}
fn inject(r: &mut Receiver, id: u32, now: Tick, w: WorkBudget) -> Result<(), Error> {
    let data = id.to_be_bytes();
    let (_, scope, _) = setup();
    r.receive_view_until(
        wire::View::Source {
            scope,
            id: SourceId(id),
            original: &data,
        },
        now,
        now,
        Tick(u64::MAX),
    )?;
    for _ in 0..100 {
        r.step(now, w)?;
        if !r.status().decoder.pending_job {
            return Ok(());
        }
    }
    Err(Error::WorkLimit)
}
fn drain_receipts(
    r: &mut Receiver,
    s: &mut Sender,
    now: Tick,
    w: WorkBudget,
    drop_old: bool,
) -> Result<Vec<GapRequest>, Error> {
    let mut seen = Vec::new();
    let (p, scope, _) = setup();
    for _ in 0..16 {
        r.step(now, w)?;
        let Some(f) = r.pending_feedback() else {
            break;
        };
        if let Some(request) = r.pending_request() {
            let mut wire = [0; wire::compact::MAXIMUM_FEEDBACK_BYTES];
            let n = r.encode_compact_request(request, &mut wire)?;
            let wire::compact::View::Gap(actual) =
                wire::compact::inspect(p.recovery, scope, &wire[..n])?
            else {
                return Err(Error::Identity);
            };
            assert_eq!(actual, request);
            assert_eq!(
                GapRequest::decode_full(p.recovery, r.pending_feedback_wire().ok_or(Error::Busy)?)?,
                request
            );
            seen.push(request);
            if !drop_old || request.start != 0 {
                s.receive_request(actual, now)?;
                // An identical physical replay cannot multiply pending or later sends.
                s.receive_request(actual, now)?;
            }
        } else {
            s.receive_feedback_wire(r.pending_feedback_wire().ok_or(Error::Busy)?, now)?;
        }
        r.confirm_feedback(f.id, now)?;
    }
    Ok(seen)
}
#[test]
fn targeted_retries_only_named_old_and_distant_sources_without_prefix_jump()
-> Result<(), Box<dyn std::error::Error>> {
    let (p, scope, w) = setup();
    let mut s = Sender::new_reserved(
        p,
        scope,
        Tick(0),
        storage::Limits {
            capacity_bytes: storage::Plan::for_sender(p)?.capacity_bytes(),
        },
    )?;
    let mut r = Receiver::new_reserved(
        p,
        scope,
        Tick(0),
        storage::Limits {
            capacity_bytes: storage::Plan::for_receiver(p)?.capacity_bytes(),
        },
    )?;
    for id in 0..201 {
        admit_source(&mut s, id, Tick(0))?;
        if id != 0 && id != 150 {
            inject(&mut r, id, Tick(0), w)?;
        }
    }
    assert!(drain_receipts(&mut r, &mut s, Tick(1_999), w, true)?.is_empty());
    let named = drain_receipts(&mut r, &mut s, Tick(2_000), w, true)?;
    assert_eq!(
        named
            .iter()
            .map(|r| (r.prefix, r.start, r.mask))
            .collect::<Vec<_>>(),
        [(0, 0, 1), (0, 150, 1)]
    );
    s.step(Tick(2_001), w)?;
    assert!(s.pending_requested_retry());
    let mut packet = [0; wire::HEADER_BYTES + 16];
    let n = s.encode_pending(&mut packet)?;
    let wire::View::Source { id, original, .. } =
        wire::inspect_with(p.recovery, p.source_wire, &packet[..n])?
    else {
        return Err(Error::Format.into());
    };
    assert_eq!(id, SourceId(150));
    assert_eq!(original, 150u32.to_be_bytes());
    // Drop the first requested retry even after complete sender ownership transfer.
    let first_retry = s.pending_retry_token().ok_or(Error::Busy)?;
    assert_eq!(
        s.confirm_output(OutputId::Source(id), Tick(2_001)),
        Err(Error::Identity)
    );
    s.confirm_retry(first_retry, Tick(2_001), Tick(2_001))?;
    assert_eq!(s.status().sent_sources, 201);
    assert_eq!(s.status().encoder.confirmed_prefix, 0);
    assert!(drain_receipts(&mut r, &mut s, Tick(81_999), w, true)?.is_empty());
    assert_eq!(
        drain_receipts(&mut r, &mut s, Tick(82_000), w, true)?.len(),
        2
    );
    s.step(Tick(82_001), w)?;
    inject(&mut r, 150, Tick(82_001), w)?;
    assert_eq!(
        s.confirm_retry(first_retry, Tick(82_001), Tick(82_001)),
        Err(Error::Identity)
    );
    s.confirm_retry(
        s.pending_retry_token().ok_or(Error::Busy)?,
        Tick(82_001),
        Tick(82_001),
    )?;
    assert_eq!(
        r.decoded_source(SourceId(150))?,
        Some(&150u32.to_be_bytes()[..])
    );
    assert_eq!(r.status().decoder.decoded_prefix, 0);
    assert!(!s.requested_retry_waiting());
    s.step(Tick(139_999), w)?;
    assert!(s.pending_output().is_none());
    s.step(Tick(140_000), w)?;
    assert!(!s.pending_requested_retry());
    assert_eq!(
        s.pending_output().map(|p| p.id()),
        Some(OutputId::Source(SourceId(0)))
    );
    inject(&mut r, 0, Tick(140_000), w)?;
    s.confirm_retry(
        s.pending_retry_token().ok_or(Error::Busy)?,
        Tick(140_000),
        Tick(140_000),
    )?;
    for id in 0..201 {
        assert_eq!(
            r.pending_source(),
            Some((SourceId(id), &id.to_be_bytes()[..]))
        );
        r.confirm_handoff(SourceId(id), Tick(140_000))?;
    }
    drain_receipts(&mut r, &mut s, Tick(141_000), w, false)?;
    assert_eq!(s.status().encoder.confirmed_prefix, 201);
    assert_eq!(s.status().sent_sources, 201);
    Ok(())
}

#[test]
fn repeated_requests_share_a_blocked_native_output_and_retry_after_an_actual_loss()
-> Result<(), Error> {
    let (policy, scope, work) = setup();
    let mut s = Sender::new(policy, scope, Tick(0))?;
    admit_source(&mut s, 0, Tick(0))?;
    let request = |serial| GapRequest {
        scope,
        id: FeedbackId(serial),
        prefix: 0,
        start: 0,
        mask: 1,
    };
    let mut now = Tick(100);
    let receipt = Feedback {
        scope,
        id: FeedbackId(1),
        prefix: 0,
        observed_end: 1,
        deficit: 1,
    };
    s.receive_feedback(receipt, now)?;
    assert!(!s.requested_retry_waiting());
    s.receive_request(request(2), now)?;
    s.receive_request(request(3), now)?;
    s.step(now, work)?;
    let original = s.pending_retry_token().ok_or(Error::Busy)?;
    s.receive_request(request(4), now)?;
    s.receive_request(request(3), now)?;
    assert_eq!(s.pending_retry_token(), Some(original));
    assert!(!s.requested_retry_waiting());
    s.confirm_retry(original, now, now)?;
    // The carrier drops that physically handed copy. A newer request must
    // still select exactly the same source under a fresh physical witness.
    now = Tick(80_100);
    s.receive_request(request(5), now)?;
    s.step(now, work)?;
    let retry = s.pending_retry_token().ok_or(Error::Busy)?;
    assert_ne!(original, retry);
    s.confirm_retry(retry, now, now)?;
    s.receive_feedback(
        Feedback {
            id: FeedbackId(6),
            prefix: 1,
            deficit: 0,
            ..receipt
        },
        now,
    )?;
    s.receive_request(request(7), now)?;
    assert_eq!(s.status().encoder.confirmed_prefix, 1);
    assert_eq!(
        s.request_counts(),
        RequestCounts {
            first: 1,
            repeated: 3,
            coalesced_queued: 1,
            coalesced_prepared: 1,
            duplicate_or_older: 1,
            confirmed: 1,
        }
    );
    Ok(())
}

#[test]
fn targeted_request_strict_bounds_and_direction_precede_custody_changes() -> Result<(), Error> {
    let (p, scope, _) = setup();
    let mut s = Sender::new(p, scope, Tick(0))?;
    admit_source(&mut s, 0, Tick(0))?;
    let request = GapRequest {
        scope,
        id: FeedbackId(1),
        start: 0,
        prefix: 0,
        mask: 1,
    };
    for bad in [
        GapRequest { mask: 0, ..request },
        GapRequest { mask: 2, ..request },
        GapRequest {
            mask: 511,
            ..request
        },
        GapRequest {
            start: u32::MAX - 1,
            mask: 5,
            prefix: u32::MAX - 1,
            ..request
        },
        GapRequest {
            start: 1,
            ..request
        },
        GapRequest {
            prefix: 1,
            ..request
        },
        GapRequest {
            id: FeedbackId(0),
            ..request
        },
        GapRequest {
            scope: Scope {
                direction: 1,
                ..scope
            },
            ..request
        },
    ] {
        assert!(s.receive_request(bad, Tick(0)).is_err());
        assert!(!s.requested_retry_waiting());
        assert_eq!(s.status().encoder.confirmed_prefix, 0);
    }
    let mut bytes = [0x88; 26];
    let n = wire::compact::encode_gap(p.recovery, request, &mut bytes)?;
    for len in 0..n {
        assert!(wire::compact::inspect(p.recovery, scope, &bytes[..len]).is_err());
    }
    assert!(wire::compact::inspect(p.recovery, scope, &bytes[..n + 1]).is_err());
    let mut old = Sender::new(
        Policy {
            source_wire: wire::SourceWire::Exact,
            ..p
        },
        scope,
        Tick(0),
    )?;
    assert_eq!(old.receive_request(request, Tick(0)), Err(Error::Format));
    Ok(())
}

#[test]
fn targeted_fresh_and_old_share_eight_ids_per_interval() -> Result<(), Error> {
    let (p, scope, w) = setup();
    let mut r = Receiver::new(p, scope, Tick(0))?;
    let mut s = Sender::new(p, scope, Tick(0))?;
    for i in 0..=32 {
        admit_source(&mut s, i, Tick(0))?;
    }
    inject(&mut r, 32, Tick(0), w)?;
    assert!(drain_receipts(&mut r, &mut s, Tick(1_999), w, true)?.is_empty());
    let first = drain_receipts(&mut r, &mut s, Tick(2_000), w, true)?;
    assert_eq!(first.len(), 1);
    assert_eq!((first[0].start, first[0].mask), (0, 255));
    // Older requests mature during an interval when no work was granted.
    r.step(Tick(82_000), WorkBudget::default())?;
    let second = drain_receipts(&mut r, &mut s, Tick(82_000), w, true)?;
    assert_eq!(second.len(), 1);
    assert_eq!((second[0].start, second[0].mask), (0, 0x0f0f));
    assert!(drain_receipts(&mut r, &mut s, Tick(83_999), w, true)?.is_empty());
    Ok(())
}

#[test]
fn targeted_fairness_charges_physical_bytes_and_keeps_retries_live() -> Result<(), Error> {
    let (policy, scope, work) = setup();
    let now = Tick(1);
    let mut s = Sender::new(policy, scope, now)?;
    for id in 0..8 {
        admit_source(&mut s, id, now)?;
    }
    s.receive_request(
        GapRequest {
            scope,
            id: FeedbackId(1),
            prefix: 0,
            start: 0,
            mask: 255,
        },
        now,
    )?;
    for id in 8u32..16 {
        assert_eq!(s.admit_source(&id.to_be_bytes(), now)?, SourceId(id));
    }
    assert_eq!(s.admit_source(b"full", now), Err(Error::Busy));
    assert_eq!(
        (
            s.status().encoder.next_source,
            s.status().next_source,
            s.status().peak_queued_fresh
        ),
        (8, 16, 8)
    );
    assert_eq!(
        s.receive_request(
            GapRequest {
                scope,
                id: FeedbackId(2),
                prefix: 0,
                start: 8,
                mask: 1
            },
            now
        ),
        Err(Error::Identity)
    );

    // The first original costs 210 actual bytes, so four 30-byte retries
    // may run before fresh has used its two-to-one share. Polling and stale
    // confirmations cannot consume credit.
    s.step(now, work)?;
    let copy = s.pending_source_copy().ok_or(Error::Busy)?;
    assert_eq!(copy.source(), SourceId(8));
    s.confirm_source_copy_charged(now, now, copy, 210)?;
    assert_eq!(
        s.confirm_source_copy_charged(now, now, copy, 210),
        Err(Error::Identity)
    );
    for id in 0..4 {
        s.step(now, work)?;
        let token = s.pending_retry_token().ok_or(Error::Busy)?;
        assert_eq!(
            s.pending_output().ok_or(Error::Busy)?.id(),
            OutputId::Source(SourceId(id))
        );
        s.confirm_retry_charged(token, now, now, 30)?;
    }
    s.step(now, work)?;
    assert_eq!(
        s.pending_source_copy().ok_or(Error::Busy)?.source(),
        SourceId(9)
    );
    Ok(())
}

#[test]
fn targeted_queued_originals_preserve_global_repair_across_ring_wrap() -> Result<(), Error> {
    let (mut policy, scope, work) = setup();
    policy.recovery.window = 4;
    policy.recovery.local_window = 2;
    policy.recovery.handoff_sources = 4;
    policy.recovery.global_every = 1;
    policy.repair_numerator = 1;
    policy.repair_denominator = 4;
    let now = Tick(1);
    let mut expected = Vec::new();
    for buffer in [false, true] {
        let mut s = Sender::new(policy, scope, now)?;
        for id in 0..4 {
            admit_source(&mut s, id, now)?;
        }
        s.receive_feedback(
            Feedback {
                scope,
                id: FeedbackId(1),
                prefix: 2,
                observed_end: 4,
                deficit: 0,
            },
            now,
        )?;
        s.step(
            now,
            WorkBudget {
                metadata: 1,
                ..Default::default()
            },
        )?;
        assert!(s.status().encoder.pending_repair);
        assert!(s.pending_output().is_none());
        if buffer {
            assert_eq!(s.admit_source(b"later", now)?, SourceId(4));
            assert_eq!(s.admit_source(b"newer", now)?, SourceId(5));
            assert_eq!(s.admit_source(b"over", now), Err(Error::Capacity));
        }
        s.step(now, work)?;
        let Output::Repair(row) = s.pending_output().ok_or(Error::Busy)? else {
            return Err(Error::Identity);
        };
        assert_eq!((row.support.start, row.support.end), (0, 4));
        if buffer {
            assert_eq!(row.bytes, expected);
        } else {
            expected.extend_from_slice(row.bytes);
        }
        s.confirm_output(OutputId::Repair(row.id), now)?;
        if buffer {
            s.step(now, work)?;
            let Output::Source { id, original, .. } = s.pending_output().ok_or(Error::Busy)? else {
                return Err(Error::Identity);
            };
            assert_eq!((id, original), (SourceId(4), b"later".as_slice()));
        }
    }
    Ok(())
}

#[test]
fn targeted_creation_deadlines_survive_reordering_and_queue_service() -> Result<(), Error> {
    let (policy, scope, work) = setup();
    let now = Tick(100);
    let mut s = Sender::new(policy, scope, now)?;
    s.admit_source(b"first", now)?;
    s.admit_source_with_copies_at(b"older", Tick(60), now, 1)?;
    s.admit_source_with_copies_at(b"oldest", Tick(20), now, 1)?;
    assert_eq!(s.deadline(), Some(Tick(20 + policy.recovery.job_ticks)));
    for id in 0..3 {
        if id > 0 {
            s.step(now, work)?;
        }
        s.confirm_output(OutputId::Source(SourceId(id)), now)?;
    }
    for prefix in 0..3 {
        if prefix > 0 {
            s.receive_feedback(
                Feedback {
                    scope,
                    id: FeedbackId(u64::from(prefix)),
                    prefix,
                    observed_end: 3,
                    deficit: 0,
                },
                now,
            )?;
        }
        assert_eq!(s.deadline(), Some(Tick(20 + policy.recovery.debt_ticks)));
    }
    let mut held = Sender::new(policy, scope, now)?;
    held.admit_source(b"held", now)?;
    held.admit_source_with_copies_at(b"older", Tick(20), now, 1)?;
    let expired = Tick(20 + policy.recovery.job_ticks);
    assert_eq!(held.step(expired, work), Err(Error::Expired));
    let selected = held.expiry_snapshot().failure.ok_or(Error::Busy)?.selected;
    assert_eq!(selected.at, expired);
    assert_eq!(
        selected.identity,
        Some(expiry::Identity::Sources { first: 1, end: 2 })
    );
    Ok(())
}

#[test]
fn targeted_oldest_probe_only_rearms_on_observed_prefix_progress() -> Result<(), Error> {
    let (policy, scope, work) = setup();
    let mut s = Sender::new(policy, scope, Tick(0))?;
    for id in 0..3 {
        admit_source(&mut s, id, Tick(0))?;
    }
    let receipt = Feedback {
        scope,
        id: FeedbackId(1),
        prefix: 1,
        observed_end: 3,
        deficit: 0,
    };
    let advanced = Tick(100_000);
    s.receive_feedback(receipt, advanced)?;
    let due = deadline(advanced, targeted::PROBE)?;
    assert_eq!(s.status().tail_due, Some(due));
    s.receive_feedback(
        Feedback {
            id: FeedbackId(2),
            ..receipt
        },
        Tick(110_000),
    )?;
    s.receive_request(
        GapRequest {
            scope,
            id: FeedbackId(3),
            prefix: 1,
            start: 2,
            mask: 1,
        },
        Tick(120_000),
    )?;
    s.step(Tick(120_000), work)?;
    let token = s.pending_retry_token().ok_or(Error::Busy)?;
    s.confirm_retry(token, Tick(120_000), Tick(120_000))?;
    admit_source(&mut s, 3, Tick(135_000))?;
    assert_eq!(s.status().tail_due, Some(due));
    s.step(due, work)?;
    assert!(s.pending_retry_token().is_some());
    assert!(!s.pending_requested_retry());
    assert_eq!(
        s.pending_output().ok_or(Error::Busy)?.id(),
        OutputId::Source(SourceId(1))
    );
    Ok(())
}

#[test]
fn targeted_contended_regular_debt_is_bounded_and_all_classes_advance() -> Result<(), Error> {
    let (mut policy, scope, work) = setup();
    policy.repair_numerator = 1;
    let mut s = Sender::new(policy, scope, Tick(0))?;
    admit_source(&mut s, 0, Tick(0))?;
    for id in 1u32..9 {
        assert_eq!(s.admit_source(&id.to_be_bytes(), Tick(0))?, SourceId(id));
    }
    let now = Tick(targeted::PROBE);
    let (mut fresh, mut named, mut regular, mut oldest) = (0, 0, 0, 0);
    for serial in 1..=40 {
        s.receive_request(
            GapRequest {
                scope,
                id: FeedbackId(serial),
                prefix: 0,
                start: 0,
                mask: 1,
            },
            now,
        )?;
        s.step(now, work)?;
        if let Some(token) = s.pending_retry_token() {
            if s.pending_requested_retry() {
                named += 1;
            } else {
                oldest += 1;
            }
            s.confirm_retry_charged(token, now, now, 120)?;
        } else {
            let id = s.pending_output().ok_or(Error::Busy)?.id();
            match id {
                OutputId::Source(_) => fresh += 1,
                OutputId::Repair(_) => regular += 1,
            }
            s.confirm_output_charged(id, now, 120)?;
        }
        assert!(s.status().regular_due <= 2);
        if fresh == 8 && regular == 9 {
            break;
        }
    }
    assert_eq!((fresh, regular, oldest), (8, 9, 1));
    assert!(named >= 4);
    assert_eq!(s.status().encoder.confirmed_prefix, 0);
    Ok(())
}
