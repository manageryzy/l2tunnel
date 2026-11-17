use super::*;

fn committed_rows(d: &Decoder) -> Result<Vec<u8>, Error> {
    let mut bytes = Vec::new();
    for row in 0..d.config.max_rows {
        let selected = d.rows[row].selected(&d.decisions, None)?;
        for column in 0..d.config.window + d.width {
            bytes.push(selected.map_or(0, |bank| d.data[bank][d.row_start(row) + column]));
        }
    }
    Ok(bytes)
}
fn committed_known(d: &Decoder) -> Result<Vec<Option<u32>>, Error> {
    d.known
        .iter()
        .map(|cell| cell.get(&d.decisions, None))
        .collect()
}
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
    // Hold actual partially stored unpublished bytes instead of relying on
    // a dense-algebra iteration count that a systematic fast path removes.
    for _ in 0..100_000 {
        if matches!(
            d.job.as_ref().ok_or(Error::Identity)?.phase,
            Phase::Store { index: 1.., .. }
        ) {
            break;
        }
        assert!(matches!(
            d.step(Tick(0), budget(1))?,
            DecodeStep::Pending(_)
        ));
    }
    assert!(matches!(
        d.job.as_ref().ok_or(Error::Identity)?.phase,
        Phase::Store { index: 1.., .. }
    ));
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
        assert_eq!(d.data[0].len(), c.max_rows * (c.window + c.width()?));
        assert_eq!(d.known_data.len(), 2 * c.window * c.width()?);
        let committed_equations = committed_rows(&d)?;
        let committed_identities = committed_known(&d)?;
        let committed = d.status();
        d.begin_source(scope(), SourceId(1), &[21, 22], Tick(0))?;
        assert!(matches!(
            d.job.as_ref().ok_or(Error::Identity)?.phase,
            Phase::Clear(0)
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
        assert_eq!(committed_rows(&d)?, committed_equations);
        assert_eq!(committed_known(&d)?, committed_identities);
        assert_eq!(d.status().decoded_prefix, committed.decoded_prefix);
        assert_eq!(d.status().rank, committed.rank);
        assert!(d.pending_source().is_none());
        if expire {
            assert!(d.step(Tick(100), budget(1)).is_err());
            assert_eq!(&d.known_data[..c.width()?], retained);
            assert_eq!(committed_rows(&d)?, committed_equations);
            assert_eq!(committed_known(&d)?, committed_identities);
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

fn repair_copy(e: &mut Encoder, c: Config) -> Result<(RepairId, Support, Vec<u8>), Error> {
    e.begin_repair(true, Tick(0))?;
    while e.pending_repair().is_none() {
        e.step(Tick(0), budget(4096))?;
    }
    let mut wire = vec![0; c.width()?];
    let (id, support, length) = e.take_repair(&mut wire, Tick(0))?;
    assert!(length <= wire.len());
    wire.truncate(length);
    Ok((id, support, wire))
}
fn stage_repair(d: &mut Decoder, packet: &(RepairId, Support, Vec<u8>)) -> Result<(), Error> {
    assert_eq!(
        d.begin_repair(
            Repair {
                scope: scope(),
                id: packet.0,
                support: packet.1,
                bytes: &packet.2,
            },
            Tick(0)
        )?,
        Begin::Staged
    );
    Ok(())
}

#[test]
fn capacity_abort_preserves_exact_committed_rows_and_allows_retry_and_reuse() -> Result<(), Error> {
    let c = Config {
        max_rows: 1,
        ..config()
    };
    let mut e = Encoder::new(c, scope(), Tick(0))?;
    let mut d = Decoder::new(c, scope(), Tick(0))?;
    for bytes in [&[11, 12][..], &[21, 22], &[31, 32]] {
        e.admit_source(bytes, Tick(0))?;
    }
    let first = repair_copy(&mut e, c)?;
    let second = repair_copy(&mut e, c)?;
    stage_repair(&mut d, &first)?;
    finish(&mut d, 1)?;
    assert_eq!(d.status().rank, 1);
    let rows = committed_rows(&d)?;
    let known = committed_known(&d)?;
    let before = d.status();
    // A second independent equation needs another row. Even elimination of the
    // original row before discovering Capacity must remain unpublished.
    for _ in 0..32 {
        stage_repair(&mut d, &second)?;
        let outcome = loop {
            let step = d.step(Tick(0), budget(1))?;
            if !matches!(step, DecodeStep::Pending(_)) {
                break step;
            }
            assert_eq!(committed_rows(&d)?, rows);
            assert_eq!(committed_known(&d)?, known);
        };
        assert!(matches!(outcome, DecodeStep::Capacity(_)));
        assert!(!d.status().pending_job);
        assert!(d.active.is_none());
        assert_eq!(committed_rows(&d)?, rows);
        assert_eq!(committed_known(&d)?, known);
        assert_eq!(d.status(), before);
    }
    // Supplying the existing row's pivot (source0) would first reduce it to
    // another unresolved equation, which also needs a second row. Supply the
    // nonpivot source2 instead: this stores exact known bytes without needing
    // another unresolved row, then the rejected equation can solve source0/1.
    d.begin_source(scope(), SourceId(2), &[31, 32], Tick(0))?;
    finish(&mut d, 1)?;
    assert_eq!(d.status().known_sources, 1);
    assert_eq!(d.status().rank, 1);
    assert_eq!(d.live_known(2)?, Some(2));
    assert_eq!(&d.known_data[2 * d.width + 2..2 * d.width + 4], &[31, 32]);
    // The previously rejected repair has not been added to duplicate history.
    stage_repair(&mut d, &second)?;
    finish(&mut d, 1)?;
    for (id, bytes) in [(0, &[11, 12][..]), (1, &[21, 22]), (2, &[31, 32])] {
        assert_eq!(d.pending_source(), Some((SourceId(id), bytes)));
        d.confirm_handoff(SourceId(id), Tick(0))?;
    }
    assert_eq!(d.status().rank, 0);
    assert_eq!(d.status().decoded_prefix, 3);
    Ok(())
}

#[test]
fn partial_first_row_copy_expiry_never_publishes_or_renews_job() -> Result<(), Error> {
    let c = config();
    let mut e = Encoder::new(c, scope(), Tick(0))?;
    let mut d = Decoder::new(c, scope(), Tick(0))?;
    for bytes in [&[11, 12][..], &[21, 22], &[31, 32]] {
        e.admit_source(bytes, Tick(0))?;
    }
    let packet = repair_copy(&mut e, c)?;
    stage_repair(&mut d, &packet)?;
    finish(&mut d, 4096)?;
    let rows = committed_rows(&d)?;
    let known = committed_known(&d)?;
    let before = d.status();
    d.begin_source(scope(), SourceId(1), &[21, 22], Tick(0))?;
    for _ in 0..100_000 {
        if matches!(
            d.job.as_ref().ok_or(Error::Identity)?.phase,
            Phase::CopyRow { index: 1.., .. }
        ) {
            break;
        }
        assert!(matches!(
            d.step(Tick(0), budget(1))?,
            DecodeStep::Pending(_)
        ));
    }
    assert!(matches!(
        d.job.as_ref().ok_or(Error::Identity)?.phase,
        Phase::CopyRow { index: 1.., .. }
    ));
    assert_eq!(committed_rows(&d)?, rows);
    assert_eq!(committed_known(&d)?, known);
    assert!(d.step(Tick(c.job_ticks), budget(1)).is_err());
    assert_eq!(committed_rows(&d)?, rows);
    assert_eq!(committed_known(&d)?, known);
    assert_eq!(d.status().rank, before.rank);
    assert_eq!(d.status().decoded_prefix, before.decoded_prefix);
    assert_eq!(d.step(Tick(0), budget(4096)), Err(Error::Terminal));
    Ok(())
}

#[test]
fn repeated_commit_eviction_wrap_keeps_exact_history_with_delayed_handoff() -> Result<(), Error> {
    let c = Config {
        window: 8,
        local_window: 3,
        max_rows: 4,
        handoff_sources: 1,
        ..config()
    };
    let mut d = Decoder::new(c, scope(), Tick(0))?;
    for batch in 0..16_u32 {
        let first = 4 * batch;
        // Out-of-order originals commit before the blocked contiguous handoff
        // moves the prefix. The next transaction must evict that delayed span.
        for offset in (0..4).rev() {
            let id = first + offset;
            let bytes = id.to_be_bytes();
            d.begin_source(scope(), SourceId(id), &bytes, Tick(0))?;
            finish(&mut d, if id % 2 == 0 { 1 } else { 17 })?;
            assert!(d.status().known_sources <= 2 * c.window);
        }
        for id in first..first + 4 {
            assert_eq!(
                d.pending_source(),
                Some((SourceId(id), &id.to_be_bytes()[..]))
            );
            d.confirm_handoff(SourceId(id), Tick(0))?;
        }
        assert_eq!(d.status().decoded_prefix, first + 4);
        assert_eq!(d.status().rank, 0);
        assert!(!d.status().pending_job);
        if first >= 16 {
            assert_eq!(
                d.begin_source(
                    scope(),
                    SourceId(first - 16),
                    &(first - 16).to_be_bytes(),
                    Tick(0)
                )?,
                Begin::Stale
            );
        }
    }
    Ok(())
}
