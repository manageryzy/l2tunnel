use super::*;

fn config() -> Config {
    Config {
        window: 256,
        local_window: 128,
        global_every: 2,
        max_payload: 8,
        max_rows: 16,
        repair_history: 32,
        handoff_sources: 256,
        job_ticks: 100,
        debt_ticks: 1000,
        handoff_ticks: 500,
        memory_bytes: 1 << 20,
    }
}
fn scope() -> Scope {
    Scope {
        session: [7; 16],
        epoch: 0,
        stream: 0,
        direction: 0,
    }
}
fn budget(n: usize) -> WorkBudget {
    WorkBudget {
        copies: n,
        field: n,
        metadata: n,
    }
}
fn finish(d: &mut Decoder, units: usize) -> Result<WorkUsed, Error> {
    let mut total = WorkUsed::default();
    loop {
        let before = d.status();
        let result = d.step(Tick(0), budget(units))?;
        let w = match result {
            DecodeStep::Idle(w)
            | DecodeStep::Pending(w)
            | DecodeStep::Capacity(w)
            | DecodeStep::Accepted { work: w, .. } => w,
        };
        assert!(w.copies <= units && w.field <= units && w.metadata <= units);
        total.copies += w.copies;
        total.field += w.field;
        total.metadata += w.metadata;
        if !matches!(result, DecodeStep::Pending(_)) {
            return Ok(total);
        }
        let after = d.status();
        assert_eq!(before.decoded_prefix, after.decoded_prefix);
        assert_eq!(before.known_sources, after.known_sources);
        assert_eq!(before.observed_end, after.observed_end);
    }
}
#[test]
fn vacant_systematic_has_bounded_copies_and_atomic_one_unit_publication() -> Result<(), Error> {
    let c = config();
    let mut d = Decoder::new(c, scope(), Tick(0))?;
    d.begin_source(scope(), SourceId(0), &[4, 5], Tick(0))?;
    let work = finish(&mut d, 1)?;
    // Candidate clearing and validation/storage are bounded by W + payload,
    // independent of both complete known-vector and equation banks.
    assert!(work.copies < c.window + 5 * c.width()?);
    assert_eq!(d.pending_source(), Some((SourceId(0), &[4, 5][..])));
    assert_eq!(
        d.begin_source(scope(), SourceId(0), &[4, 5], Tick(0))?,
        Begin::Duplicate
    );
    Ok(())
}
#[test]
fn vacant_staging_expiry_does_not_publish_or_renew_deadline() -> Result<(), Error> {
    let c = config();
    let mut d = Decoder::new(c, scope(), Tick(0))?;
    d.begin_source(scope(), SourceId(0), &[4, 5], Tick(0))?;
    for _ in 0..900 {
        if !matches!(d.step(Tick(0), budget(1))?, DecodeStep::Pending(_)) {
            break;
        }
    }
    assert_eq!(d.status().decoded_prefix, 0);
    assert!(d.pending_source().is_none());
    assert!(d.step(Tick(100), budget(1)).is_err());
    assert_eq!(d.status().decoded_prefix, 0);
    assert!(d.pending_source().is_none());
    assert_eq!(d.step(Tick(0), budget(1)), Err(Error::Terminal));
    Ok(())
}
#[test]
fn global_repair_uses_all_vacant_staged_history_past_local128() -> Result<(), Error> {
    let c = config();
    let mut e = Encoder::new(c, scope(), Tick(0))?;
    let mut d = Decoder::new(c, scope(), Tick(0))?;
    for i in 0..200_u32 {
        let payload = i.to_be_bytes();
        let id = e.admit_source(&payload, Tick(0))?;
        if i != 0 {
            d.begin_source(scope(), id, &payload, Tick(0))?;
            finish(&mut d, 4096)?;
        }
    }
    assert_eq!(d.status().known_sources, 199);
    assert_eq!(d.status().decoded_prefix, 0);
    e.begin_repair(true, Tick(0))?;
    while e.pending_repair().is_none() {
        e.step(Tick(0), budget(4096))?;
    }
    let repair = e.pending_repair().ok_or(Error::Identity)?;
    assert_eq!(repair.support.start, 0);
    assert_eq!(repair.support.end, 200);
    d.begin_repair(repair, Tick(0))?;
    finish(&mut d, 4096)?;
    for i in 0..200_u32 {
        assert_eq!(
            d.pending_source(),
            Some((SourceId(i), i.to_be_bytes().as_slice()))
        );
        d.confirm_handoff(SourceId(i), Tick(0))?;
    }
    assert_eq!(d.status().decoded_prefix, 200);
    Ok(())
}

#[test]
fn shared_known_ring_preserves_rank_positive_commit_and_staged_failure_atomicity()
-> Result<(), Error> {
    for expire in [false, true] {
        let c = config();
        let mut e = Encoder::new(c, scope(), Tick(0))?;
        let mut d = Decoder::new(c, scope(), Tick(0))?;
        e.admit_source(&[11, 12], Tick(0))?;
        e.admit_source(&[21, 22], Tick(0))?;
        e.admit_source(&[31, 32], Tick(0))?;
        d.begin_source(scope(), SourceId(0), &[11, 12], Tick(0))?;
        finish(&mut d, 1)?;
        d.confirm_handoff(SourceId(0), Tick(0))?;
        let retained = d.known_data[..c.width()?].to_vec();
        e.begin_repair(true, Tick(0))?;
        while e.pending_repair().is_none() {
            e.step(Tick(0), budget(4096))?;
        }
        d.begin_repair(e.pending_repair().ok_or(Error::Identity)?, Tick(0))?;
        let repair_work = finish(&mut d, 4096)?;
        assert!(repair_work.copies < 2 * c.max_rows * (c.window + c.width()?));
        assert_eq!(d.status().rank, 1);
        assert_eq!(d.live.data.len(), c.max_rows * (c.window + c.width()?));
        assert_eq!(d.known_data.len(), 2 * c.window * c.width()?);
        let committed_rows = d.live.data.clone();
        let committed_known = d.live.known.clone();
        let committed = d.status();
        d.begin_source(scope(), SourceId(1), &[21, 22], Tick(0))?;
        assert!(matches!(
            d.job.as_ref().ok_or(Error::Identity)?.phase,
            Phase::CopyData(0)
        ));
        // Stop after a complete payload has been written into the shared ring,
        // while its candidate identity is still unpublished.
        while d.job.as_ref().ok_or(Error::Identity)?.recovered == 0 {
            assert!(matches!(
                d.step(Tick(0), budget(1))?,
                DecodeStep::Pending(_)
            ));
        }
        assert_eq!(&d.known_data[..c.width()?], retained);
        assert_eq!(d.live.data, committed_rows);
        assert_eq!(d.live.known, committed_known);
        assert_eq!(d.status().decoded_prefix, committed.decoded_prefix);
        assert_eq!(d.status().rank, committed.rank);
        assert!(d.pending_source().is_none());
        if expire {
            assert!(d.step(Tick(100), budget(1)).is_err());
            assert_eq!(&d.known_data[..c.width()?], retained);
            assert_eq!(d.live.data, committed_rows);
            assert_eq!(d.live.known, committed_known);
            assert_eq!(d.status().known_sources, 1);
            assert_eq!(d.step(Tick(100), budget(4096)), Err(Error::Terminal));
        } else {
            finish(&mut d, 1)?;
            assert_eq!(d.pending_source(), Some((SourceId(1), &[21, 22][..])));
            d.confirm_handoff(SourceId(1), Tick(0))?;
            assert_eq!(d.pending_source(), Some((SourceId(2), &[31, 32][..])));
            assert_eq!(d.status().rank, 0);
        }
    }
    Ok(())
}
