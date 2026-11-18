//! Capacity-independent transaction snapshots, measured through actual owner work.
use super::*;
fn large() -> Config {
    Config {
        window: 8192,
        local_window: 128,
        global_every: 16,
        max_payload: 1460,
        max_rows: 2048,
        repair_history: 64,
        handoff_sources: 8192,
        job_ticks: 100,
        debt_ticks: 1000,
        handoff_ticks: 500,
        memory_bytes: 128 * 1024 * 1024,
    }
}
fn scope() -> Scope {
    Scope {
        session: [23; 16],
        epoch: 1,
        stream: 7,
        direction: 0,
    }
}
fn finish(decoder: &mut Decoder) -> Result<WorkUsed, Error> {
    let mut total = WorkUsed::default();
    for _ in 0..10000 {
        let before = decoder.status();
        let outcome = decoder.step(
            Tick(0),
            WorkBudget {
                copies: MAX_STEP_WORK,
                field: MAX_STEP_WORK,
                metadata: MAX_STEP_WORK,
            },
        )?;
        let work = match outcome {
            DecodeStep::Idle(work)
            | DecodeStep::Pending(work)
            | DecodeStep::Capacity(work)
            | DecodeStep::Accepted { work, .. } => work,
        };
        assert!(
            work.copies <= MAX_STEP_WORK
                && work.field <= MAX_STEP_WORK
                && work.metadata <= MAX_STEP_WORK
        );
        total.copies += work.copies;
        total.field += work.field;
        total.metadata += work.metadata;
        if matches!(outcome, DecodeStep::Accepted { .. }) {
            return Ok(total);
        }
        assert!(
            matches!(outcome, DecodeStep::Pending(_)),
            "must actually commit the staged job"
        );
        let after = decoder.status();
        assert_eq!(before.decoded_prefix, after.decoded_prefix);
        assert_eq!(before.rank, after.rank);
        assert_eq!(before.known_sources, after.known_sources);
    }
    Err(Error::Capacity)
}
#[test]
fn sparse_large_clean_original_does_not_snapshot_all_window_metadata() -> Result<(), Error> {
    let c = large();
    let mut decoder = Decoder::new(c, scope(), Tick(0))?;
    assert_eq!(
        decoder.begin_source(scope(), SourceId(0), &[11, 12], Tick(0))?,
        Begin::Staged
    );
    let work = finish(&mut decoder)?;
    let bound = 2 * c.width()? + 32;
    eprintln!(
        "sparse_clean_work copies={} field={} metadata={} metadata_bound={bound} memory={}",
        work.copies,
        work.field,
        work.metadata,
        Decoder::memory_bound(c)?
    );
    assert_eq!(decoder.pending_source(), Some((SourceId(0), &[11, 12][..])));
    assert_eq!(decoder.status().known_sources, 1);
    assert_eq!(decoder.status().rank, 0);
    // A rank-zero original validates/stores its exact vector and publishes its
    // identity. Empty candidate/row algebra must not scale with W or max_rows.
    assert_eq!(work.field, 0);
    assert!(work.copies <= 2 * c.width()?);
    assert!(
        work.metadata <= bound,
        "clean original visited configured empty algebra capacity"
    );
    Ok(())
}
#[test]
fn sparse_large_rank_one_original_copies_only_touched_rows() -> Result<(), Error> {
    let c = large();
    let mut encoder = Encoder::new(c, scope(), Tick(0))?;
    let mut decoder = Decoder::new(c, scope(), Tick(0))?;
    for bytes in [&[11, 12][..], &[21, 22], &[31, 32]] {
        encoder.admit_source(bytes, Tick(0))?;
    }
    decoder.begin_source(scope(), SourceId(0), &[11, 12], Tick(0))?;
    finish(&mut decoder)?;
    decoder.confirm_handoff(SourceId(0), Tick(0))?;
    encoder.begin_repair(true, Tick(0))?;
    for _ in 0..10000 {
        if encoder.pending_repair().is_some() {
            break;
        }
        encoder.step(
            Tick(0),
            WorkBudget {
                copies: MAX_STEP_WORK,
                field: MAX_STEP_WORK,
                metadata: MAX_STEP_WORK,
            },
        )?;
    }
    decoder.begin_repair(encoder.pending_repair().ok_or(Error::Identity)?, Tick(0))?;
    finish(&mut decoder)?;
    assert_eq!(
        decoder.status().rank,
        1,
        "must retain a genuine unresolved equation"
    );
    decoder.begin_source(scope(), SourceId(1), &[21, 22], Tick(0))?;
    let work = finish(&mut decoder)?;
    let bound = 5 * (c.window + c.width()?) + 10 * c.width()?;
    eprintln!(
        "sparse_rank1_work copies={} field={} metadata={} copy_bound={bound} full_bank_bytes={} memory={}",
        work.copies,
        work.field,
        work.metadata,
        c.max_rows * (c.window + c.width()?),
        Decoder::memory_bound(c)?
    );
    assert_eq!(decoder.pending_source(), Some((SourceId(1), &[21, 22][..])));
    decoder.confirm_handoff(SourceId(1), Tick(0))?;
    assert_eq!(decoder.pending_source(), Some((SourceId(2), &[31, 32][..])));
    assert_eq!(decoder.status().rank, 0);
    // One dirty existing row, candidate and actual known payload work are allowed;
    // copying max_rows rows when only one exists is not.
    assert!(
        work.copies <= bound,
        "rank-one original cloned the configured equation bank"
    );
    Ok(())
}

#[test]
fn local_repair_with_an_older_equation_costs_the_same_in_a_larger_row_bank() -> Result<(), Error> {
    fn trial(rows: usize) -> Result<WorkUsed, Error> {
        let c = Config {
            max_rows: rows,
            max_payload: 16,
            ..large()
        };
        let mut e = Encoder::new(c, scope(), Tick(0))?;
        let mut d = Decoder::new(c, scope(), Tick(0))?;
        let original = |id: u32| [id as u8, 0x42, 0];
        let budget = WorkBudget {
            field: MAX_STEP_WORK,
            copies: MAX_STEP_WORK,
            metadata: MAX_STEP_WORK,
        };
        let mut work = WorkUsed::default();
        for id in 0..130 {
            e.admit_source(&original(id), Tick(0))?;
            if ![0, 1, 120].contains(&id) {
                d.begin_source(scope(), SourceId(id), &original(id), Tick(0))?;
                finish(&mut d)?;
            }
            if matches!(id, 1 | 129) {
                e.begin_repair(false, Tick(0))?;
                while e.pending_repair().is_none() {
                    e.step(Tick(0), budget)?;
                }
                let equation = e.pending_repair().ok_or(Error::Identity)?;
                let repair_id = equation.id;
                d.begin_repair(equation, Tick(0))?;
                work = finish(&mut d)?;
                e.confirm_repair(repair_id, Tick(0))?;
                assert_eq!(d.status().rank, 1);
                assert_eq!(d.status().decoded_prefix, 0);
            }
        }
        assert_eq!(
            d.decoded_source(SourceId(120))?,
            Some(original(120).as_slice())
        );
        d.begin_source(scope(), SourceId(0), &original(0), Tick(0))?;
        finish(&mut d)?;
        for id in 0..130 {
            assert_eq!(
                d.pending_source(),
                Some((SourceId(id), original(id).as_slice()))
            );
            d.confirm_handoff(SourceId(id), Tick(0))?;
        }
        assert_eq!(d.status().rank, 0);
        Ok(work)
    }
    assert_eq!(trial(2)?, trial(2048)?);
    Ok(())
}
