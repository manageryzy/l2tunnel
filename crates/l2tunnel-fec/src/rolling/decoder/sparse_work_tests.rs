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

#[test]
fn wrapped_local_algebra_reuses_aborted_bank_and_recovers_older_global_gap() -> Result<(), Error> {
    let c = Config {
        window: 384,
        local_window: 128,
        handoff_sources: 384,
        max_rows: 2,
        max_payload: 31,
        ..large()
    };
    let now = Tick(0);
    let mut encoder = Encoder::new(c, scope(), now)?;
    let mut decoder = Decoder::new(c, scope(), now)?;
    let limited = WorkBudget {
        field: 11,
        copies: 7,
        metadata: 17,
    };
    let originals = |id: u32| [id as u8, (id >> 8) as u8, 0x80, 0];
    let missing = [190, 378, 383, 389, 401, 439];
    for id in 0..458 {
        encoder.admit_source(&originals(id), now)?;
        if !missing.contains(&id) {
            decoder.begin_source(scope(), SourceId(id), &originals(id), now)?;
            finish(&mut decoder)?;
        }
        if id < missing[0] {
            decoder.confirm_handoff(SourceId(id), now)?;
            encoder.confirm_prefix(id + 1, now)?;
        }
    }
    let verify_mask = |d: &Decoder| {
        let width = coefficient_block_bytes(c.window);
        let valid = |data: &[u8], mask: u64| {
            data[..c.window]
                .iter()
                .enumerate()
                .all(|(i, byte)| mask & (1u64 << (i / width)) != 0 || *byte == 0)
        };
        assert!(valid(&d.candidate, d.candidate_blocks));
        for (row, state) in d.rows.iter().enumerate() {
            for (bank, mask) in state.blocks.into_iter().enumerate() {
                assert!(valid(&d.data[bank][d.row_start(row)..], mask));
            }
        }
    };
    for (i, global) in [true, false, false].into_iter().enumerate() {
        let id = encoder.begin_repair(global, now)?;
        while encoder.pending_repair().is_none() {
            encoder.step(now, limited)?;
        }
        let repair = encoder.pending_repair().ok_or(Error::Identity)?;
        if !global {
            assert!(repair.support.start > missing[0]);
            assert!(repair.support.start < c.window as u32 && repair.support.end > c.window as u32);
        }
        decoder.begin_repair(repair, now)?;
        let committed = decoder.status();
        loop {
            let result = decoder.step(now, limited)?;
            verify_mask(&decoder);
            if let DecodeStep::Pending(work) = result {
                assert!(
                    work.field <= limited.field
                        && work.copies <= limited.copies
                        && work.metadata <= limited.metadata
                );
                assert_eq!(decoder.status().rank, committed.rank);
                assert_eq!(decoder.status().decoded_prefix, committed.decoded_prefix);
            } else {
                if i == 2 {
                    assert!(matches!(result, DecodeStep::Capacity(_)));
                    assert_eq!(decoder.status().rank, 2);
                } else {
                    assert!(matches!(result, DecodeStep::Accepted { .. }));
                    assert_eq!(decoder.status().rank, i + 1);
                }
                break;
            }
        }
        encoder.confirm_repair(id, now)?;
    }
    // Deliver enough local originals to unlock both retained equations. Source
    // 190 occurs only in the older global equation and is never retransmitted.
    for id in [378, 383, 389, 401, 439] {
        if decoder.decoded_source(SourceId(id))?.is_some() {
            continue;
        }
        decoder.begin_source(scope(), SourceId(id), &originals(id), now)?;
        loop {
            let result = decoder.step(now, limited)?;
            verify_mask(&decoder);
            match result {
                DecodeStep::Accepted { .. } => break,
                DecodeStep::Pending(_) => {}
                DecodeStep::Capacity(_) => break,
                _ => return Err(Error::Identity),
            }
        }
    }
    assert_eq!(decoder.status().rank, 0);
    for id in missing[0]..458 {
        assert_eq!(
            decoder.pending_source(),
            Some((SourceId(id), originals(id).as_slice()))
        );
        decoder.confirm_handoff(SourceId(id), now)?;
    }
    Ok(())
}
