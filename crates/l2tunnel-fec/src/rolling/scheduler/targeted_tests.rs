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
