use super::*;

fn fresh(max_rows: usize) -> Result<Decoder, Error> {
    let config = Config {
        window: 16,
        local_window: 2,
        global_every: 2,
        max_payload: 8,
        max_rows,
        repair_history: 8,
        handoff_sources: 8,
        job_ticks: 20,
        debt_ticks: 50,
        handoff_ticks: 100,
        memory_bytes: 1 << 20,
    };
    let scope = Scope {
        session: [3; 16],
        epoch: 3,
        stream: 0,
        direction: 0,
    };
    Decoder::new_sliding(config, scope, Tick(0))
}
fn budget(n: usize) -> WorkBudget {
    WorkBudget {
        copies: n,
        metadata: n,
        field: n,
    }
}
fn payload(id: u32) -> [u8; 3] {
    [id as u8 + 1, 0, 0xc3]
}
fn source(d: &mut Decoder, id: u32) -> Result<(), Error> {
    assert_eq!(
        d.begin_source(d.scope, SourceId(id), &payload(id), Tick(0))?,
        Begin::Staged
    );
    assert!(matches!(
        d.step(Tick(0), budget(8192))?,
        DecodeStep::Accepted { .. }
    ));
    Ok(())
}

#[test]
fn older_repair_rejects_an_unequal_systematic_before_it_can_be_published() -> Result<(), Error> {
    let mut d = fresh(4)?;
    for id in 0..7 {
        source(&mut d, id)?;
    }
    repair(&mut d, 2, 8, Tick(10))?;
    let wrong = [0xf0, 0, 0xc3];
    assert!(!d.commit_independent_source(
        SourceId(7),
        &wrong,
        Tick(0),
        Tick(0),
        Tick(12),
        &mut budget(100)
    )?);
    assert_eq!(d.decoded_source(SourceId(7))?, None);
    d.step(Tick(1), budget(8192))?;
    assert_eq!(d.decoded_source(SourceId(7))?, Some(payload(7).as_slice()));
    assert_eq!(
        d.begin_source(d.scope, SourceId(7), &wrong, Tick(1)),
        Err(Error::Conflict)
    );
    Ok(())
}
fn repair(d: &mut Decoder, serial: u64, end: u32, cap: Tick) -> Result<(), Error> {
    let id = RepairId(serial);
    let support = d.config.support(end, id, false)?;
    let mut bytes = [0; 10];
    for i in support.start..support.end {
        let factor = field::compact_coefficient(support.seed, i);
        let p = payload(i);
        for (dst, value) in bytes.iter_mut().zip([0, 3, p[0], p[1], p[2]]) {
            *dst ^= field::multiply(factor, value);
        }
    }
    let r = Repair {
        scope: d.scope,
        id,
        support,
        bytes: &bytes,
    };
    assert_eq!(
        d.begin_repair_until(r, Tick(0), Tick(0), cap)?,
        Begin::Staged
    );
    Ok(())
}

#[test]
fn disjoint_source_commits_atomic_bytes_during_wide_repair_and_preserves_old_gap()
-> Result<(), Error> {
    let mut d = fresh(4)?;
    for id in [0, 1, 3, 4, 5] {
        source(&mut d, id)?;
    }
    repair(&mut d, 2, 6, Tick(12))?;
    for _ in 0..64 {
        if d.job
            .as_ref()
            .is_some_and(|j| matches!(j.phase, Phase::Known { .. }))
        {
            break;
        }
        assert!(matches!(
            d.step(Tick(0), budget(1))?,
            DecodeStep::Pending(_)
        ));
    }
    assert!(
        d.job
            .as_ref()
            .is_some_and(|j| matches!(j.phase, Phase::Known { .. }))
    );
    let predecessor = d.expiry_snapshot().decoder_job;
    assert_eq!(d.independent_source_floor(), Some(6));
    assert!(!d.commit_independent_source(
        SourceId(2),
        &payload(2),
        Tick(0),
        Tick(1),
        Tick(10),
        &mut budget(100)
    )?);
    assert!(!d.commit_independent_source(
        SourceId(7),
        &payload(7),
        Tick(0),
        Tick(1),
        Tick(10),
        &mut budget(9)
    )?);
    assert_eq!(d.decoded_source(SourceId(7))?, None);
    let mut work = budget(100);
    assert!(d.commit_independent_source(
        SourceId(7),
        &payload(7),
        Tick(0),
        Tick(1),
        Tick(10),
        &mut work
    )?);
    assert_eq!(work.field, 100);
    assert_eq!(work.copies, 90);
    assert_eq!(d.decoded_source(SourceId(7))?, Some(payload(7).as_slice()));
    assert_eq!(d.expiry_snapshot().decoder_job, predecessor);
    assert_eq!(d.feedback_state()?.0, 2);
    assert_eq!(d.deadline(), Some(Tick(10)));
    assert!(matches!(
        d.step(Tick(2), budget(8192))?,
        DecodeStep::Accepted { recovered: 1, .. }
    ));
    assert_eq!(d.feedback_state()?.0, 6);
    assert_eq!(d.decoded_source(SourceId(2))?, Some(payload(2).as_slice()));
    assert_eq!(d.decoded_source(SourceId(7))?, Some(payload(7).as_slice()));
    assert_eq!(d.deadline(), Some(Tick(10)));
    assert_eq!(
        d.begin_source(d.scope, SourceId(7), &payload(7), Tick(3))?,
        Begin::Duplicate
    );
    assert_eq!(
        d.begin_source(d.scope, SourceId(7), &[0xff], Tick(3)),
        Err(Error::Conflict)
    );
    Ok(())
}

#[test]
fn disjoint_commit_survives_basis_capacity_rollback_and_respects_pending_expiry()
-> Result<(), Error> {
    let mut d = fresh(1)?;
    source(&mut d, 5)?;
    repair(&mut d, 2, 4, Tick(20))?;
    assert!(matches!(
        d.step(Tick(0), budget(8192))?,
        DecodeStep::Accepted { recovered: 0, .. }
    ));
    assert_eq!(d.status().rank, 1);
    repair(&mut d, 4, 6, Tick(11))?;
    assert!(d.commit_independent_source(
        SourceId(7),
        &payload(7),
        Tick(0),
        Tick(0),
        Tick(12),
        &mut budget(100)
    )?);
    assert!(matches!(
        d.step(Tick(0), budget(8192))?,
        DecodeStep::Capacity(_)
    ));
    assert_eq!(d.status().rank, 1);
    assert_eq!(d.status().known_sources, 2);
    assert_eq!(d.decoded_source(SourceId(7))?, Some(payload(7).as_slice()));
    repair(&mut d, 4, 6, Tick(7))?;
    assert_eq!(
        d.commit_independent_source(
            SourceId(8),
            &payload(8),
            Tick(6),
            Tick(7),
            Tick(100),
            &mut budget(100)
        ),
        Err(Error::Expired)
    );
    assert_eq!(d.status().known_sources, 2);
    assert_eq!(
        d.expiry_snapshot().failure.map(|x| x.selected.kind),
        Some(expiry::Kind::DecoderJob)
    );
    Ok(())
}

#[test]
fn reordered_disjoint_sources_preserve_the_wide_rows_original_work_horizon() -> Result<(), Error> {
    let mut d = fresh(4)?;
    let mut serial = fresh(4)?;
    for decoder in [&mut d, &mut serial] {
        for id in [0, 1, 3, 4, 5] {
            source(decoder, id)?;
        }
        repair(decoder, 2, 6, Tick(20))?;
    }
    for (id, cap) in [(8, 14), (6, 9), (7, 10)] {
        assert_eq!(d.independent_source_floor(), Some(6));
        assert!(d.commit_independent_source(
            SourceId(id),
            &payload(id),
            Tick(0),
            Tick(1),
            Tick(cap),
            &mut budget(100)
        )?);
        assert_eq!(d.shadow.observed, 6);
        assert_eq!(d.status().observed_end, 9);
        assert_eq!(d.status().decoded_prefix, 2);
        assert_eq!(d.deadline(), Some(Tick(14)));
    }
    let before = d.status();
    assert!(!d.commit_independent_source(
        SourceId(7),
        &payload(7),
        Tick(0),
        Tick(1),
        Tick(10),
        &mut budget(100)
    )?);
    assert_eq!(d.status(), before);
    let original_step = serial.step(Tick(2), budget(8192))?;
    assert_eq!(d.step(Tick(2), budget(8192))?, original_step);
    assert_eq!((d.status().observed_end, d.status().known_sources), (9, 9));
    assert_eq!(
        d.step(Tick(2), budget(8192))?,
        DecodeStep::Accepted {
            work: WorkUsed {
                field: 0,
                copies: 0,
                metadata: 2
            },
            recovered: 0,
            prefix: 8,
        }
    );
    // A second wide row supplies an active transaction for the conflict check.
    // Use a separate receiver so the final conflict cannot alter the oracle.
    let mut conflict = fresh(4)?;
    source(&mut conflict, 5)?;
    repair(&mut conflict, 2, 6, Tick(20))?;
    assert!(conflict.commit_independent_source(
        SourceId(7),
        &payload(7),
        Tick(0),
        Tick(1),
        Tick(14),
        &mut budget(100)
    )?);
    assert_eq!(
        conflict.commit_independent_source(
            SourceId(7),
            &[7, 8],
            Tick(0),
            Tick(1),
            Tick(14),
            &mut budget(100)
        ),
        Err(Error::Conflict)
    );
    assert_eq!(conflict.status().known_sources, 2);
    Ok(())
}
