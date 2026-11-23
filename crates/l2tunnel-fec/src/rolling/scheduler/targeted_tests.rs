//! Real charged wire handoffs under selective loss, with an old missing source.
use super::*;

mod confirmed_prefix;

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
fn held_original_preserves_mature_gap_and_frozen_feedback_across_duplicate_release()
-> Result<(), Error> {
    let (policy, scope, work) = setup();
    let mut r = Receiver::new(policy, scope, Tick(0))?;
    inject(&mut r, 2, Tick(0), work)?;
    r.hold_queued_source(SourceId(0))?;
    r.hold_queued_source(SourceId(0))?;
    assert_eq!(
        r.hold_queued_source(SourceId(policy.recovery.window as u32)),
        Err(Error::Identity)
    );
    r.release_queued_source(SourceId(policy.recovery.window as u32));
    r.step(Tick(2_000), work)?;
    let other = r.pending_request().ok_or(Error::Busy)?;
    assert_eq!((other.start, other.mask), (1, 1));
    r.release_queued_source(SourceId(0));
    r.confirm_feedback(other.id, Tick(2_000))?;
    r.step(Tick(5_000), work)?;
    assert!(r.pending_request().is_none());
    if let Some(ordinary) = r.pending_feedback() {
        r.confirm_feedback(ordinary.id, Tick(5_000))?;
    }
    // Drop the second local occurrence without admitting it to the decoder.
    // Its original 2 ms deadline already matured and no new timer is needed.
    r.release_queued_source(SourceId(0));
    r.step(Tick(5_000), work)?;
    let due = r.pending_request().ok_or(Error::Busy)?;
    assert_eq!((due.start, due.mask, due.scope), (0, 1, scope));
    let mut before = [0; wire::compact::MAXIMUM_FEEDBACK_BYTES];
    let len = r.encode_compact_request(due, &mut before)?;
    r.hold_queued_source(SourceId(0))?;
    let mut after = [0; wire::compact::MAXIMUM_FEEDBACK_BYTES];
    assert_eq!(r.encode_compact_request(due, &mut after)?, len);
    assert_eq!(after, before);
    r.confirm_feedback(due.id, Tick(5_000))?;
    r.release_queued_source(SourceId(0));
    r.step(Tick(8_000), work)?;
    assert!(r.pending_request().is_none());
    assert_eq!(r.status().decoder.decoded_prefix, 0);
    Ok(())
}

#[test]
fn late_fifo_release_after_wrap_never_releases_a_new_generation() -> Result<(), Error> {
    let (mut policy, scope, w) = setup();
    policy.recovery.window = 4;
    policy.recovery.local_window = 2;
    policy.recovery.handoff_sources = 4;
    let mut r = Receiver::new(policy, scope, Tick(0))?;
    r.hold_queued_source(SourceId(0))?;
    for id in 0..4 {
        inject(&mut r, id, Tick(0), w)?;
        r.confirm_handoff(SourceId(id), Tick(0))?;
    }
    assert!(!r.tracks_queued_source(SourceId(0)));
    r.hold_queued_source(SourceId(4))?;
    r.release_queued_source(SourceId(0));
    inject(&mut r, 6, Tick(0), w)?;
    r.step(Tick(2_000), w)?;
    let request = r.pending_request().ok_or(Error::Busy)?;
    assert_eq!((request.prefix, request.start, request.mask), (4, 5, 1));
    r.confirm_feedback(request.id, Tick(2_000))?;
    r.release_queued_source(SourceId(4));
    r.step(Tick(4_000), w)?;
    assert_eq!(r.pending_request().ok_or(Error::Busy)?.start, 4);
    Ok(())
}

#[test]
fn a_queued_original_withdraws_only_the_unsealed_distant_span() -> Result<(), Error> {
    let (policy, scope, work) = setup();
    let mut r = Receiver::new(policy, scope, Tick(0))?;
    for id in (1..=36).filter(|&id| id != 35) {
        inject(&mut r, id, Tick(0), work)?;
    }
    r.step(Tick(2_000), work)?;
    let frozen = r.pending_request().ok_or(Error::Busy)?;
    assert_eq!((frozen.start, frozen.mask), (0, 1));
    r.hold_queued_source(SourceId(35))?;
    assert_eq!(r.pending_request(), Some(frozen));
    r.confirm_feedback(frozen.id, Tick(2_000))?;
    r.step(Tick(2_100), work)?;
    assert!(r.pending_request().is_none());
    if let Some(ordinary) = r.pending_feedback() {
        r.confirm_feedback(ordinary.id, Tick(2_100))?;
    }
    r.release_queued_source(SourceId(35));
    r.step(Tick(4_000), work)?;
    let next = r.pending_request().ok_or(Error::Busy)?;
    assert_eq!((next.start, next.mask), (35, 1));
    Ok(())
}

#[test]
fn a_repair_retires_only_solved_names_from_an_unpublished_distant_span() -> Result<(), Error> {
    let (mut policy, scope, work) = setup();
    policy.recovery.local_window = 2;
    let mut receiver = Receiver::new(policy, scope, Tick(0))?;
    let mut encoder = Encoder::new(policy.recovery, scope, Tick(0))?;
    for id in 0_u32..=38 {
        if id <= 35 {
            encoder.admit_source(&id.to_be_bytes(), Tick(0))?;
        }
        if ![0, 35, 37].contains(&id) {
            inject(&mut receiver, id, Tick(0), work)?;
        }
    }
    receiver.step(Tick(2_000), work)?;
    let frozen = receiver.pending_request().ok_or(Error::Busy)?;
    assert_eq!((frozen.start, frozen.mask), (0, 1));
    encoder.begin_repair(false, Tick(2_001))?;
    encoder.step(Tick(2_001), work)?;
    let row = encoder.pending_repair().ok_or(Error::WorkLimit)?;
    assert_eq!((row.support.start, row.support.end), (34, 36));
    receiver.receive_view_until(
        wire::View::Repair(row),
        Tick(2_001),
        Tick(2_001),
        Tick(u64::MAX),
    )?;
    receiver.step(Tick(2_001), work)?;
    assert_eq!(
        receiver.decoded_source(SourceId(35))?,
        Some(35_u32.to_be_bytes().as_slice())
    );
    assert_eq!(receiver.pending_request(), Some(frozen));
    receiver.confirm_feedback(frozen.id, Tick(2_001))?;
    let one_lookup = WorkBudget {
        field: 0,
        copies: 0,
        metadata: 1,
    };
    let partial = receiver.step(Tick(2_002), one_lookup)?;
    assert!(partial.work.metadata <= 1);
    assert!(receiver.pending_request().is_none());
    receiver.step(Tick(2_002), work)?;
    let next = receiver.pending_request().ok_or(Error::Busy)?;
    assert_eq!((next.prefix, next.start, next.mask), (0, 37, 1));
    Ok(())
}

#[test]
fn a_queued_higher_source_can_name_a_hole_while_a_repair_is_running() -> Result<(), Error> {
    let (policy, scope, work) = setup();
    let mut receiver = Receiver::new(policy, scope, Tick(0))?;
    let mut encoder = Encoder::new(policy.recovery, scope, Tick(0))?;
    for id in 0_u32..3 {
        encoder.admit_source(&id.to_be_bytes(), Tick(0))?;
        if id != 1 {
            inject(&mut receiver, id, Tick(0), work)?;
        }
    }
    encoder.begin_repair(false, Tick(0))?;
    encoder.step(Tick(0), work)?;
    let row = encoder.pending_repair().ok_or(Error::WorkLimit)?;
    receiver.receive_view_until(wire::View::Repair(row), Tick(0), Tick(0), Tick(u64::MAX))?;
    receiver.hold_queued_source(SourceId(3))?;
    receiver.hold_queued_source(SourceId(5))?;
    let no_field = WorkBudget { field: 0, ..work };
    receiver.step(Tick(0), no_field)?;
    receiver.step(Tick(1_999), no_field)?;
    assert!(receiver.pending_request().is_none());
    let step = receiver.step(Tick(2_000), no_field)?;
    assert_eq!(step.work.field, 0);
    assert!(receiver.status().decoder.pending_job);
    let request = receiver.pending_request().ok_or(Error::Busy)?;
    assert_eq!(
        (request.prefix, request.start, request.mask),
        (1, 1, 0b1001)
    );
    // The higher authenticated FIFO inputs changed only the named request.
    // Source 4 is absent; the current equation stops before that source.
    assert_eq!(receiver.status().decoder.observed_end, 3);
    assert_eq!(receiver.status().decoder.decoded_prefix, 1);
    receiver.confirm_feedback(request.id, Tick(2_000))?;
    receiver.step(Tick(2_001), work)?;
    assert_eq!(
        receiver.decoded_source(SourceId(1))?,
        Some(1_u32.to_be_bytes().as_slice())
    );
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
fn full_global_accepts_only_scanned_reuse_and_recovers_old_gap_after_overtake() -> Result<(), Error>
{
    let (mut policy, scope, work) = setup();
    policy.recovery.window = 8;
    policy.recovery.local_window = 2;
    policy.recovery.handoff_sources = 8;
    policy.recovery.global_every = 1;
    policy.repair_numerator = 1;
    policy.repair_denominator = 8;
    let now = Tick(1);
    let mut s = Sender::new(policy, scope, now)?;
    let mut r = Receiver::new(policy, scope, now)?;
    let mut serial = Encoder::new(policy.recovery, scope, now)?;
    for id in 0u32..8 {
        admit_source(&mut s, id, now)?;
        serial.admit_source(&id.to_be_bytes(), now)?;
        if id < 6 {
            inject(&mut r, id, now, work)?;
            r.confirm_handoff(SourceId(id), now)?;
        }
    }
    serial.begin_repair(false, now)?;
    serial.step(now, work)?;
    let expected = serial.pending_repair().ok_or(Error::Busy)?;
    s.receive_feedback(
        Feedback {
            scope,
            id: FeedbackId(1),
            prefix: 6,
            observed_end: 8,
            deficit: 2,
        },
        now,
    )?;
    s.step(
        now,
        WorkBudget {
            metadata: 1,
            ..WorkBudget::default()
        },
    )?;
    let frozen_end = s.expiry_snapshot().candidates[1];
    assert!(frozen_end.is_some());
    s.admit_source_with_copies(&8u32.to_be_bytes(), now, 2)?;
    s.admit_source(&9u32.to_be_bytes(), now)?;

    // Even a confirmed source stays pinned through its last field byte.
    let small = |field| WorkBudget { field, ..work };
    let width = policy.recovery.width()?;
    let transfer = width + 2 + 8u32.to_be_bytes().len();
    assert_eq!(s.step(now, small(1))?.copies, width);
    assert!(s.pending_output().is_none());
    // Finishing the first old column makes reuse safe. The next source
    // nevertheless stays untouched without its complete copy allowance.
    for (field, copies) in [(5, 0), (1, transfer - 1)] {
        let used = s.step(
            now,
            WorkBudget {
                field,
                copies,
                ..work
            },
        )?;
        assert_eq!(used.copies, 0);
        assert_eq!(s.status().queued_fresh, 2);
        assert_eq!(s.status().encoder.next_source, 8);
        assert!(s.pending_output().is_none());
    }
    assert_eq!(
        s.step(
            now,
            WorkBudget {
                field: 1,
                copies: transfer,
                ..work
            }
        )?
        .copies,
        transfer
    );
    let first = s.pending_source_copy().ok_or(Error::Busy)?;
    assert_eq!(
        (first.source(), first.ordinal(), first.total()),
        (SourceId(8), 1, 2)
    );
    assert!(s.computing_full_global());
    assert_eq!(s.expiry_snapshot().candidates[1], frozen_end);
    assert_eq!(
        s.confirm_output(OutputId::Repair(expected.id), now),
        Err(Error::Identity)
    );
    s.step(now, small(1))?;
    assert_eq!(s.pending_source_copy(), Some(first));
    inject(&mut r, 8, now, work)?;
    s.confirm_source_copy_charged(now, now, first, 80)?;
    let second = s.pending_source_copy().ok_or(Error::Busy)?;
    assert_eq!(second.ordinal(), 2);
    assert_eq!(
        s.confirm_source_copy_charged(now, now, first, 80),
        Err(Error::Identity)
    );
    s.confirm_source_copy_charged(now, now, second, 80)?;
    s.receive_request(
        GapRequest {
            scope,
            id: FeedbackId(2),
            prefix: 6,
            start: 7,
            mask: 1,
        },
        now,
    )?;
    s.step(now, small(2))?;
    let token = s.pending_retry_token().ok_or(Error::Busy)?;
    let Output::Source { id, original, .. } = s.pending_output().ok_or(Error::Busy)? else {
        return Err(Error::Identity);
    };
    assert_eq!(id, SourceId(7));
    assert_eq!(original, &7u32.to_be_bytes());
    // Finishing the equation behind a refused physical retry cannot replace it.
    s.step(now, work)?;
    assert!(!s.computing_full_global());
    assert_eq!(s.pending_retry_token(), Some(token));
    assert_eq!(
        s.pending_output().map(Output::id),
        Some(OutputId::Source(id))
    );
    inject(&mut r, 7, now, work)?;
    s.confirm_retry_charged(token, now, now, 72)?;
    let Output::Repair(actual) = s.pending_output().ok_or(Error::Busy)? else {
        return Err(Error::Identity);
    };
    assert_eq!(
        (actual.id, actual.support, actual.bytes),
        (expected.id, expected.support, expected.bytes)
    );
    r.receive_view_until(wire::View::Repair(actual), now, now, Tick(u64::MAX))?;
    r.step(now, work)?;
    s.confirm_output(OutputId::Repair(expected.id), now)?;
    for id in 6u32..=8 {
        assert_eq!(
            r.pending_source(),
            Some((SourceId(id), id.to_be_bytes().as_slice()))
        );
        r.confirm_handoff(SourceId(id), now)?;
    }
    assert_eq!(r.status().decoder.decoded_prefix, 9);
    Ok(())
}

#[test]
fn blocked_interleaved_source_retains_original_global_job_cap() -> Result<(), Error> {
    let (mut policy, scope, work) = setup();
    policy.recovery.window = 4;
    policy.recovery.local_window = 2;
    policy.recovery.global_every = 1;
    policy.recovery.handoff_sources = 4;
    policy.recovery.job_ticks = 40;
    policy.repair_numerator = 1;
    policy.repair_denominator = 4;
    let mut s = Sender::new(policy, scope, Tick(0))?;
    for id in 0..4 {
        admit_source(&mut s, id, Tick(0))?;
    }
    s.receive_feedback(
        Feedback {
            scope,
            id: FeedbackId(1),
            prefix: 2,
            observed_end: 4,
            deficit: 0,
        },
        Tick(1),
    )?;
    s.step(
        Tick(5),
        WorkBudget {
            metadata: 1,
            ..WorkBudget::default()
        },
    )?;
    let job = s.expiry_snapshot().candidates[1].ok_or(Error::Busy)?;
    s.admit_source(b"later", Tick(10))?;
    s.step(Tick(10), WorkBudget { field: 6, ..work })?;
    assert_eq!(
        s.pending_output().map(Output::id),
        Some(OutputId::Source(SourceId(4)))
    );
    assert_eq!(s.deadline(), Some(Tick(45)));
    assert_eq!(s.step(Tick(45), work), Err(Error::Expired));
    assert_eq!(
        s.expiry_snapshot().failure.ok_or(Error::Busy)?.selected,
        job
    );
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
                OutputId::Near8(_) => return Err(Error::Identity),
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

/// A real missing oldest source remains recoverable after multi-copy fresh
/// handoffs accumulate repair debt across the global support's ring wrap.
#[test]
fn full_global_bounded_debt_keeps_oldest_probe_and_pays_all_earned_equations() -> Result<(), Error>
{
    old_hole_bounded_global(false)?;
    old_hole_bounded_global(true)
}
fn old_hole_bounded_global(earned: bool) -> Result<(), Error> {
    const LOST: u32 = 55;
    const TOTAL: u32 = 148;
    let (mut p, scope, full) = setup();
    p.recovery.window = 64;
    p.recovery.local_window = 16;
    p.recovery.handoff_sources = 64;
    p.repair_numerator = 41;
    p.repair_denominator = 200;
    let mut s = Sender::new(p, scope, Tick(0))?;
    if earned {
        s.enable_earned_regular()?;
    }
    let mut r = Receiver::new(p, scope, Tick(0))?;
    let tiny = WorkBudget { field: 2, ..full };
    let mut now = Tick(0);
    let (mut offered, mut delivered, mut confirmed) = (0u32, 0u32, 0u32);
    let (mut regular, mut final_originals, mut extra_copies) = (0u32, 0u32, 0u32);
    let (mut peak_due, mut slow_grants, mut dropped_named, mut restored) = (0, 0, false, false);
    let mut requested = false;
    for _ in 0..100_000 {
        while offered < TOTAL {
            let data = offered.to_be_bytes();
            match s.admit_source_with_copies_at(&data, now, now, 4) {
                Ok(id) => {
                    assert_eq!(id, SourceId(offered));
                    offered += 1;
                }
                Err(Error::Capacity | Error::Busy) => break,
                Err(e) => return Err(e),
            }
        }
        if extra_copies >= 32 && !requested {
            assert_eq!((confirmed, delivered), (LOST, LOST));
            s.receive_request(
                GapRequest {
                    scope,
                    id: FeedbackId(50_000),
                    prefix: LOST,
                    start: LOST,
                    mask: 1,
                },
                now,
            )?;
            requested = true;
        }
        let before = s.status();
        let running_global = s.computing_full_global();
        let budget = if running_global {
            tiny
        } else {
            WorkBudget { field: 32, ..full }
        };
        let used = s.step(now, budget)?;
        let after = s.status();
        peak_due = peak_due.max(after.regular_due);
        assert!(after.regular_due <= 16);
        if running_global
            && before.regular_due >= 2
            && after.encoder.next_source > before.encoder.next_source
        {
            assert!(used.field > 0 && used.copies > 0 && used.metadata > 0);
            extra_copies += u32::from(s.pending_source_copy().ok_or(Error::Busy)?.total());
            assert!(extra_copies <= 64);
        }
        if running_global
            && before.regular_due >= 2
            && before.queued_fresh > 0
            && s.pending_output().is_none()
        {
            slow_grants += 1;
        }
        if let Some(token) = s.pending_retry_token() {
            let Output::Source { id, original, .. } = s.pending_output().ok_or(Error::Busy)? else {
                return Err(Error::Identity);
            };
            assert_eq!((id.0, original), (LOST, LOST.to_be_bytes().as_slice()));
            if s.pending_requested_retry() {
                assert!(requested && !dropped_named);
                dropped_named = true;
                s.confirm_retry(token, now, now)?;
                now = s.status().tail_due.ok_or(Error::Busy)?;
            } else {
                assert!(dropped_named && !restored);
                inject(&mut r, id.0, now, full)?;
                s.confirm_retry(token, now, now)?;
                restored = true;
            }
        } else if let Some(copy) = s.pending_source_copy() {
            let id = copy.source().0;
            if copy.ordinal() == 1 && id != LOST {
                inject(&mut r, id, now, full)?;
            }
            s.confirm_source_copy_charged(now, now, copy, 60)?;
            if copy.ordinal() == copy.total() {
                final_originals += 1;
            }
        } else if let Some(Output::Repair(row)) = s.pending_output() {
            // Drop all equations. The only route for LOST is its retained original.
            regular += 1;
            assert_eq!(row.id.0, u64::from(regular));
            if earned {
                assert_eq!(row.support.end, (regular * 200).div_ceil(41));
            }
            s.confirm_output(OutputId::Repair(row.id), now)?;
        }
        while let Some((id, bytes)) = r.pending_source() {
            assert_eq!(
                (id.0, bytes),
                (delivered, delivered.to_be_bytes().as_slice())
            );
            r.confirm_handoff(id, now)?;
            delivered += 1;
        }
        // Send a delayed complete cumulative ACK, keeping recovery outstanding
        // until the owed opportunities have seen the normal post-job scheduler.
        let ack = if final_originals == TOTAL && regular == TOTAL * 41 / 200 {
            delivered
        } else {
            delivered.min(s.status().sent_sources.saturating_sub(8))
        };
        if ack > confirmed {
            s.receive_feedback(
                Feedback {
                    scope,
                    id: FeedbackId(60_000 + u64::from(ack)),
                    prefix: ack,
                    observed_end: ack,
                    deficit: 0,
                },
                now,
            )?;
            confirmed = ack;
        }
        if confirmed == TOTAL {
            break;
        }
    }
    assert!(requested && dropped_named && restored);
    assert_eq!(extra_copies, 64);
    assert!(peak_due > 2 && slow_grants > 0);
    assert_eq!(
        (offered, final_originals, delivered, confirmed),
        (TOTAL, TOTAL, TOTAL, TOTAL)
    );
    assert_eq!(
        (regular, s.status().regular_due, s.status().repair_credit),
        (TOTAL * 41 / 200, 0, TOTAL * 41 % 200)
    );
    assert_eq!(s.status().encoder.confirmed_prefix, TOTAL);
    assert!(s.pending_output().is_none());
    Ok(())
}

#[test]
fn physical_last_copy_prices_once_and_later_credit_cannot_displace_it() -> Result<(), Error> {
    let (mut p, scope, work) = setup();
    p.repair_numerator = 1;
    let mut s = Sender::new(p, scope, Tick(0))?;
    s.enable_earned_regular()?;
    s.admit_source_with_copies(&[1, 2, 3, 4, 0, 0], Tick(1), 3)?;
    let mut attempts = Vec::new();
    for ordinal in 1..=3 {
        let copy = s.pending_source_copy().ok_or(Error::Busy)?;
        assert_eq!(ordinal, copy.ordinal());
        assert_eq!(s.pending_source_copy(), Some(copy));
        let at = Tick(u64::from(ordinal));
        s.confirm_source_copy_priced(at, at, copy, 64, |id, support| {
            attempts.push((id, support));
            Ok(false)
        })?;
        assert_eq!(attempts.len(), usize::from(ordinal == 3));
        assert_eq!(
            s.confirm_source_copy_priced(at, at, copy, 64, |_, _| Err(Error::Conflict)),
            Err(Error::Identity)
        );
    }
    assert_eq!(s.deadline(), Some(Tick(3 + p.recovery.job_ticks)));
    let request = GapRequest {
        scope,
        id: FeedbackId(1),
        prefix: 0,
        start: 0,
        mask: 1,
    };
    s.receive_request(request, Tick(4))?;
    s.step(Tick(4), work)?;
    let token = s.pending_retry_token().ok_or(Error::Busy)?;
    s.confirm_retry_charged(token, Tick(4), Tick(4), 512)?;
    s.step_with_regular_filter(Tick(5), work, |_, _| Err(Error::Conflict))?;
    let Some(Output::Repair(r)) = s.pending_output() else {
        return Err(Error::Busy);
    };
    assert_eq!(attempts, [(r.id, r.support)]);
    let frozen = r.bytes.to_vec();
    s.receive_feedback(
        Feedback {
            scope,
            id: FeedbackId(2),
            prefix: 1,
            observed_end: 1,
            deficit: 0,
        },
        Tick(6),
    )?;
    assert_eq!(s.deadline(), Some(Tick(3 + p.recovery.job_ticks)));
    let Some(Output::Repair(r)) = s.pending_output() else {
        return Err(Error::Busy);
    };
    assert_eq!(r.bytes, frozen);
    s.confirm_output(OutputId::Repair(r.id), Tick(6))?;
    assert_eq!(s.deadline(), None);
    Ok(())
}

#[test]
fn unstarted_earned_job_keeps_original_cap_or_clears_on_full_confirmation() -> Result<(), Error> {
    let (mut p, scope, work) = setup();
    p.repair_numerator = 1;
    for acknowledge in [false, true] {
        let mut s = Sender::new(p, scope, Tick(0))?;
        s.enable_earned_regular()?;
        s.admit_source(&[7], Tick(10))?;
        s.confirm_output(OutputId::Source(SourceId(0)), Tick(11))?;
        let cap = Tick(11 + p.recovery.job_ticks);
        assert_eq!(s.deadline(), Some(cap));
        if acknowledge {
            s.receive_feedback(
                Feedback {
                    scope,
                    id: FeedbackId(1),
                    prefix: 1,
                    observed_end: 1,
                    deficit: 0,
                },
                Tick(12),
            )?;
            assert_eq!(s.status().regular_due, 0);
            assert_eq!(s.deadline(), None);
            s.admit_source(&[8], cap)?;
            s.confirm_output(OutputId::Source(SourceId(1)), cap)?;
            s.step(cap, work)?;
            let Some(Output::Repair(r)) = s.pending_output() else {
                return Err(Error::Busy);
            };
            assert_eq!((r.id, r.support.end), (RepairId(1), 2));
        } else {
            assert_eq!(s.step(cap, work), Err(Error::Expired));
            let failed = s.expiry_snapshot().failure.ok_or(Error::Identity)?;
            assert_eq!(
                (failed.selected.at, failed.selected.identity),
                (
                    cap,
                    Some(expiry::Identity::Repair {
                        id: RepairId(1),
                        support: Some((0, 1))
                    })
                )
            );
        }
    }
    Ok(())
}

#[test]
fn queued_global_keeps_older_columns_than_the_earlier_local_across_repeated_wraps()
-> Result<(), Error> {
    let (mut p, scope, full) = setup();
    p.recovery.window = 8;
    p.recovery.local_window = 2;
    p.recovery.global_every = 2;
    p.recovery.handoff_sources = 8;
    p.repair_numerator = 1;
    p.repair_denominator = 1;
    let at = Tick(0);
    let mut s = Sender::new(p, scope, at)?;
    s.enable_earned_regular()?;
    let (mut offered, mut sent, mut repair_count, mut two_due) = (0u32, 0u32, 0u32, false);
    fn bytes(i: u32) -> [u8; 4] {
        (i.wrapping_mul(0x12345) + 7).to_be_bytes()
    }
    for _ in 0..16000 {
        while offered < 96 {
            match s.admit_source(&bytes(offered), at) {
                Ok(id) => {
                    assert_eq!(id.0, offered);
                    offered += 1;
                }
                Err(Error::Busy | Error::Capacity) => break,
                Err(e) => return Err(e),
            }
        }
        s.step(at, WorkBudget { field: 3, ..full })?;
        if let Some(c) = s.pending_source_copy() {
            assert_eq!(c.source().0, sent);
            s.confirm_source_copy_charged(at, at, c, 56)?;
            sent += 1;
            if sent > 2 {
                s.receive_feedback(
                    Feedback {
                        scope,
                        id: FeedbackId(u64::from(sent)),
                        prefix: sent - 2,
                        observed_end: sent - 2,
                        deficit: 0,
                    },
                    at,
                )?;
            }
        } else if let Some(Output::Repair(r)) = s.pending_output() {
            repair_count += 1;
            let end = repair_count;
            let start = end.saturating_sub(if end.is_multiple_of(2) { 8 } else { 2 });
            assert_eq!(
                (r.id.0, r.support.start, r.support.end),
                (u64::from(end), start, end)
            );
            let mut expected = [0u8; 6];
            for id in start..end {
                let coefficient =
                    crate::field::compact_coefficient(end.wrapping_mul(2654435761), id);
                for (out, byte) in expected.iter_mut().zip([0, 4].into_iter().chain(bytes(id))) {
                    *out ^= crate::field::multiply(byte, coefficient);
                }
            }
            assert_eq!(r.bytes, expected);
            s.confirm_output(OutputId::Repair(r.id), at)?;
        }
        two_due |= s.status().regular_due >= 2;
        if sent == 96 && repair_count == sent {
            break;
        }
    }
    assert_eq!((sent, repair_count, two_due), (96, 96, true));
    Ok(())
}
