//! Received originals without encoder state; work must depend on vector width.
use super::*;
fn config(window: usize, rows: usize) -> Config {
    Config {
        window,
        local_window: window.min(128),
        global_every: 16,
        max_payload: 64,
        max_rows: rows,
        repair_history: 4,
        handoff_sources: 1,
        job_ticks: 100,
        debt_ticks: 1000,
        handoff_ticks: 500,
        memory_bytes: 128 * 1024 * 1024,
    }
}
fn scope() -> Scope {
    Scope {
        session: [31; 16],
        epoch: 1,
        stream: 8,
        direction: 0,
    }
}
fn budget(units: usize) -> WorkBudget {
    WorkBudget {
        copies: units,
        field: units,
        metadata: units,
    }
}
fn finish(d: &mut Decoder, now: Tick, units: usize) -> Result<WorkUsed, Error> {
    let mut total = WorkUsed::default();
    for _ in 0..100_000 {
        let before = d.status();
        let result = d.step(now, budget(units))?;
        let work = match result {
            DecodeStep::Pending(w) | DecodeStep::Accepted { work: w, .. } => w,
            _ => return Err(Error::Identity),
        };
        assert!(work.copies <= units && work.field <= units && work.metadata <= units);
        total.copies += work.copies;
        total.field += work.field;
        total.metadata += work.metadata;
        if matches!(result, DecodeStep::Accepted { .. }) {
            return Ok(total);
        }
        let after = d.status();
        assert_eq!(after.decoded_prefix, before.decoded_prefix);
        assert_eq!(after.known_sources, before.known_sources);
        assert_eq!(after.rank, before.rank);
    }
    Err(Error::Capacity)
}

#[test]
fn systematic_original_work_is_independent_of_window_and_row_capacity() -> Result<(), Error> {
    let payload: Vec<u8> = (0..64)
        .map(|i| if i % 3 == 0 { 0 } else { i ^ 0xab })
        .collect();
    let mut results = Vec::new();
    for (window, rows) in [(128, 1), (8192, 1), (8192, 2048)] {
        let c = config(window, rows);
        let mut d = Decoder::new(c, scope(), Tick(0))?;
        assert_eq!(
            d.begin_source(scope(), SourceId(0), &payload, Tick(0))?,
            Begin::Staged
        );
        let work = finish(&mut d, Tick(0), MAX_STEP_WORK)?;
        assert_eq!(d.pending_source(), Some((SourceId(0), payload.as_slice())));
        assert_eq!(d.status().rank, 0);
        assert_eq!(d.status().known_sources, 1);
        eprintln!(
            "systematic_work window={window} rows={rows} copies={} field={} metadata={} memory={}",
            work.copies,
            work.field,
            work.metadata,
            Decoder::memory_bound(c)?
        );
        results.push(work);
    }
    // All exact received bytes were committed before any cost assertion. These
    // bounds use vector width alone, not configured coefficient/row capacity.
    for work in &results {
        assert_eq!(
            work.field, 0,
            "rank-zero original must not do GF normalization"
        );
        assert!(work.copies <= 2 * 66);
        assert!(work.metadata <= 2 * 66 + 32);
    }
    assert_eq!(results[0], results[1]);
    assert_eq!(results[1], results[2]);
    Ok(())
}

#[test]
fn systematic_tiny_budget_preserves_exact_lengths_zero_tails_and_ring_history() -> Result<(), Error>
{
    let mut d = Decoder::new(config(8, 8), scope(), Tick(0))?;
    for id in 0..40_u32 {
        let length = match id % 3 {
            0 => 1,
            1 => 7,
            _ => 64,
        };
        let mut payload = vec![id as u8; length];
        payload[length - 1] = 0;
        assert_eq!(
            d.begin_source(scope(), SourceId(id), &payload, Tick(0))?,
            Begin::Staged
        );
        finish(&mut d, Tick(0), 1)?;
        assert_eq!(d.pending_source(), Some((SourceId(id), payload.as_slice())));
        assert_eq!(
            d.begin_source(scope(), SourceId(id), &payload, Tick(0))?,
            Begin::Duplicate
        );
        d.confirm_handoff(SourceId(id), Tick(0))?;
        assert_eq!(d.status().decoded_prefix, id + 1);
        assert!(d.status().known_sources <= 16);
        if id >= 16 {
            assert_eq!(
                d.begin_source(scope(), SourceId(id - 16), &[1], Tick(0))?,
                Begin::Stale
            );
        }
    }
    Ok(())
}

#[test]
fn systematic_partial_store_preserves_original_expiry_and_unpublished_state() -> Result<(), Error> {
    let c = config(128, 16);
    let mut d = Decoder::new(c, scope(), Tick(0))?;
    d.begin_source(scope(), SourceId(0), &[5, 0], Tick(5))?;
    assert_eq!(d.deadline(), Some(Tick(105)));
    for _ in 0..100_000 {
        if matches!(
            d.job.as_ref().ok_or(Error::Identity)?.phase,
            Phase::Store { index: 1.., .. }
        ) {
            break;
        }
        assert!(matches!(
            d.step(Tick(104), budget(1))?,
            DecodeStep::Pending(_)
        ));
    }
    assert!(matches!(
        d.job.as_ref().ok_or(Error::Identity)?.phase,
        Phase::Store { index: 1.., .. }
    ));
    assert_eq!(d.deadline(), Some(Tick(105)));
    assert_eq!(d.status().known_sources, 0);
    assert_eq!(d.status().decoded_prefix, 0);
    assert!(d.pending_source().is_none());
    assert!(d.step(Tick(105), budget(MAX_STEP_WORK)).is_err());
    assert_eq!(d.status().known_sources, 0);
    assert_eq!(d.status().decoded_prefix, 0);
    assert!(d.pending_source().is_none());
    assert_eq!(d.step(Tick(105), budget(1)), Err(Error::Terminal));
    Ok(())
}

#[test]
fn systematic_reuses_length_padding_validation_and_conflict_rejection() -> Result<(), Error> {
    for corruption in 0..3 {
        let mut d = Decoder::new(config(128, 16), scope(), Tick(0))?;
        d.begin_source(scope(), SourceId(0), &[5, 0], Tick(0))?;
        // Defensive internal witness: even a corrupted staged vector cannot
        // bypass the common length/padding validator before known publication.
        match corruption {
            0 => d.input[..2].copy_from_slice(&0_u16.to_be_bytes()),
            1 => d.input[..2].copy_from_slice(&65_u16.to_be_bytes()),
            _ => d.input[65] = 1,
        }
        assert_eq!(d.step(Tick(0), budget(MAX_STEP_WORK)), Err(Error::Length));
        assert_eq!(d.status().known_sources, 0);
        assert!(d.pending_source().is_none());
    }
    let mut d = Decoder::new(config(128, 16), scope(), Tick(0))?;
    d.begin_source(scope(), SourceId(0), &[5, 0], Tick(0))?;
    finish(&mut d, Tick(0), 1)?;
    assert_eq!(
        d.begin_source(scope(), SourceId(0), &[5], Tick(0)),
        Err(Error::Conflict)
    );
    Ok(())
}

#[test]
fn systematic_handoff_pressure_and_pending_job_do_not_publish_or_renew_delivery()
-> Result<(), Error> {
    let mut d = Decoder::new(config(8, 8), scope(), Tick(0))?;
    for id in [1, 0] {
        d.begin_source(scope(), SourceId(id), &[id as u8, 0], Tick(0))?;
        finish(&mut d, Tick(0), 1)?;
    }
    assert_eq!(d.status().decoded_prefix, 1);
    assert_eq!(d.pending_source(), Some((SourceId(0), &[0, 0][..])));
    assert_eq!(d.deadline(), Some(Tick(500)));
    d.begin_source(scope(), SourceId(2), &[2, 0], Tick(10))?;
    d.confirm_handoff(SourceId(0), Tick(20))?;
    assert_eq!(d.status().handoff_prefix, 1);
    assert_eq!(
        d.status().decoded_prefix,
        1,
        "pending transaction keeps committed prefix frozen"
    );
    assert_eq!(
        d.deadline(),
        Some(Tick(110)),
        "original job deadline is not renewed"
    );
    finish(&mut d, Tick(20), 1)?;
    assert_eq!(d.status().decoded_prefix, 2);
    assert_eq!(d.pending_source(), Some((SourceId(1), &[1, 0][..])));
    assert_eq!(
        d.deadline(),
        Some(Tick(500)),
        "original delivery deadline survives publication"
    );
    d.confirm_handoff(SourceId(1), Tick(30))?;
    assert_eq!(d.pending_source(), Some((SourceId(2), &[2, 0][..])));
    assert_eq!(d.deadline(), Some(Tick(500)));
    Ok(())
}

#[test]
fn genuine_equation_to_zero_rank_then_fast_original_repair_and_ring_reuse() -> Result<(), Error> {
    // Independent maintained-Python received equations, also pinned by the
    // rolling byte-parity corpus. No Encoder or sender payload ledger is used.
    const E3_R16: [u8; 10] = [0, 69, 111, 193, 0, 0, 0, 0, 0, 0];
    const E5_T3: [u8; 10] = [0, 132, 202, 159, 239, 0, 0, 0, 0, 0];
    let c = Config {
        window: 4,
        local_window: 2,
        global_every: 2,
        max_payload: 8,
        max_rows: 4,
        repair_history: 32,
        ..config(4, 4)
    };
    let mut d = Decoder::new(c, scope(), Tick(0))?;
    d.begin_source(scope(), SourceId(0), &[1, 2, 0], Tick(0))?;
    finish(&mut d, Tick(0), 1)?;
    d.confirm_handoff(SourceId(0), Tick(0))?;
    assert_eq!(
        d.begin_repair(
            Repair {
                scope: scope(),
                id: RepairId(16),
                support: c.support(3, RepairId(16), false)?,
                bytes: &E3_R16
            },
            Tick(0)
        )?,
        Begin::Staged
    );
    finish(&mut d, Tick(0), 1)?;
    assert_eq!(
        d.status().rank,
        1,
        "must actually retain an unresolved equation"
    );
    assert!(d.pending_source().is_none());
    // The retained equation has support ending at 3. A new original at that
    // boundary is independent even while that older equation remains live.
    d.begin_source(scope(), SourceId(3), &[0x91, 0, 0x72, 0], Tick(0))?;
    let work = finish(&mut d, Tick(0), MAX_STEP_WORK)?;
    assert_eq!(d.status().rank, 1);
    assert!(d.pending_source().is_none());
    d.begin_source(scope(), SourceId(1), &[0, 0, 0, 0], Tick(0))?;
    finish(&mut d, Tick(0), 1)?;
    for (id, bytes) in [(1, &[0, 0, 0, 0][..]), (2, &[255][..])] {
        assert_eq!(d.pending_source(), Some((SourceId(id), bytes)));
        d.confirm_handoff(SourceId(id), Tick(0))?;
    }
    assert_eq!(d.status().rank, 0);
    for pivot in &d.pivots {
        assert_eq!(pivot.get(&d.decisions, None)?, None);
    }
    for mapping in &d.map {
        assert_eq!(mapping.get(&d.decisions, None)?, None);
    }
    assert_eq!(
        d.pending_source(),
        Some((SourceId(3), &[0x91, 0, 0x72, 0][..]))
    );
    d.confirm_handoff(SourceId(3), Tick(0))?;
    d.begin_source(scope(), SourceId(5), &[6], Tick(0))?;
    finish(&mut d, Tick(0), 1)?;
    assert!(d.pending_source().is_none(), "source4 is genuinely missing");
    assert_eq!(
        d.begin_repair(
            Repair {
                scope: scope(),
                id: RepairId(3),
                support: c.support(5, RepairId(3), true)?,
                bytes: &E5_T3
            },
            Tick(0)
        )?,
        Begin::Staged
    );
    finish(&mut d, Tick(0), 1)?;
    for (id, bytes) in [(4, &[4, 5][..]), (5, &[6][..])] {
        assert_eq!(d.pending_source(), Some((SourceId(id), bytes)));
        d.confirm_handoff(SourceId(id), Tick(0))?;
    }
    for id in 6..32_u32 {
        let bytes = id.to_be_bytes();
        d.begin_source(scope(), SourceId(id), &bytes, Tick(0))?;
        finish(&mut d, Tick(0), 1)?;
        assert_eq!(d.pending_source(), Some((SourceId(id), bytes.as_slice())));
        d.confirm_handoff(SourceId(id), Tick(0))?;
        assert_eq!(d.status().rank, 0);
    }
    assert_eq!(
        d.begin_source(scope(), SourceId(0), &[1, 2, 0], Tick(0))?,
        Begin::Stale
    );
    // Assert costs only after every exact byte/repair/history transition above.
    assert_eq!(work.field, 0);
    assert!(work.copies <= 2 * c.width()?);
    assert!(work.metadata <= 2 * c.width()? + 32);
    Ok(())
}
