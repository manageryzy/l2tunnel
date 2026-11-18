use super::*;

fn config() -> Config {
    Config {
        window: 4,
        local_window: 2,
        global_every: 2,
        max_payload: 8,
        max_rows: 4,
        repair_history: 8,
        handoff_sources: 4,
        job_ticks: 100,
        debt_ticks: 1_000,
        handoff_ticks: 500,
        memory_bytes: 1 << 20,
    }
}
fn scope() -> Scope {
    Scope {
        session: [0x67; 16],
        epoch: 3,
        stream: 11,
        direction: 1,
    }
}
fn budget(units: usize) -> WorkBudget {
    WorkBudget {
        field: units,
        copies: units,
        metadata: units,
    }
}
// Existing maintained-Python E4_R1 received equation; no encoder payload ledger.
const E4_R1: [u8; 10] = [0, 201, 97, 0, 250, 0, 0, 0, 0, 0];
fn repair() -> Result<Repair<'static>, Error> {
    Ok(Repair {
        scope: scope(),
        id: RepairId(1),
        support: config().support(4, RepairId(1), false)?,
        bytes: &E4_R1,
    })
}

#[test]
fn decoder_expiry_details_keep_original_arrival_admission_and_actual_gf_cursor() -> Result<(), Error>
{
    let mut d = Decoder::new(config(), scope(), Tick(0))?;
    let storage = d.storage_usage();
    assert_eq!(
        d.begin_repair_until(repair()?, Tick(5), Tick(30), Tick(60))?,
        Begin::Staged
    );
    for _ in 0..1_000 {
        if matches!(
            d.job.as_ref().ok_or(Error::Identity)?.phase,
            Phase::Normalize { index: 0, .. }
        ) {
            break;
        }
        assert!(matches!(
            d.step(Tick(30), budget(1))?,
            DecodeStep::Pending(_)
        ));
    }
    assert!(matches!(
        d.job.as_ref().ok_or(Error::Identity)?.phase,
        Phase::Normalize { index: 0, .. }
    ));
    assert_eq!(
        d.step(Tick(59), budget(2))?,
        DecodeStep::Pending(WorkUsed {
            field: 2,
            copies: 0,
            metadata: 2
        })
    );
    let retained = d.expiry_snapshot().decoder_job.ok_or(Error::Identity)?;
    assert_eq!(
        (retained.received, retained.admitted, retained.deadline),
        (Tick(5), Tick(30), Tick(60))
    );
    assert_eq!(retained.admitted.0 - retained.received.0, 25);
    assert!(matches!(
        retained.phase,
        expiry::DecoderPhase::Normalize { index: 2, .. }
    ));
    assert_eq!(d.step(Tick(60), budget(MAX_STEP_WORK)), Err(Error::Expired));
    let failed = d.expiry_snapshot();
    let failure = failed.failure.ok_or(Error::Identity)?;
    assert_eq!(failure.observed, Tick(60));
    assert_eq!(failure.selected.kind, expiry::Kind::DecoderJob);
    assert_eq!(failure.selected.identity, Some(retained.identity));
    assert_eq!(failure.selected.at, retained.deadline);
    assert_eq!(failed.decoder_job, Some(retained));
    assert_eq!(failure.observed.0 - retained.admitted.0, 30);
    // A later terminal call cannot refresh either tick, advance the cursor or
    // rewrite the exact first failure. These intervals do not measure CPU work.
    assert_eq!(
        d.step(Tick(61), budget(MAX_STEP_WORK)),
        Err(Error::Terminal)
    );
    assert_eq!(d.expiry_snapshot(), failed);
    assert_eq!(d.storage_usage(), storage);
    Ok(())
}

#[test]
fn decoder_expiry_before_admission_has_no_fabricated_job_or_cursor() -> Result<(), Error> {
    let mut d = Decoder::new(config(), scope(), Tick(0))?;
    assert_eq!(
        d.begin_repair_until(repair()?, Tick(5), Tick(106), Tick(200)),
        Err(Error::Expired)
    );
    let failed = d.expiry_snapshot();
    assert_eq!(failed.decoder_job, None);
    let failure = failed.failure.ok_or(Error::Identity)?;
    assert_eq!(failure.selected.kind, expiry::Kind::DecoderJob);
    assert_eq!(
        (failure.selected.at, failure.observed),
        (Tick(105), Tick(106))
    );
    assert_eq!(
        failure.selected.identity,
        Some(expiry::Identity::Repair {
            id: RepairId(1),
            support: Some((2, 4))
        })
    );
    assert_eq!(d.step(Tick(107), budget(1)), Err(Error::Terminal));
    assert_eq!(d.expiry_snapshot(), failed);
    let e = Encoder::new(config(), scope(), Tick(0))?;
    assert_eq!(e.expiry_snapshot().decoder_job, None);
    Ok(())
}

#[test]
fn decoder_expiry_details_reset_on_new_admission_and_do_not_relabel_another_input_failure()
-> Result<(), Error> {
    let mut d = Decoder::new(config(), scope(), Tick(0))?;
    assert_eq!(
        d.begin_source_until(
            scope(),
            SourceId(0),
            &[1, 2, 0],
            Tick(5),
            Tick(10),
            Tick(90)
        )?,
        Begin::Staged
    );
    assert!(matches!(
        d.step(Tick(10), budget(MAX_STEP_WORK))?,
        DecodeStep::Accepted { .. }
    ));
    assert_eq!(d.expiry_snapshot().decoder_job, None);
    assert_eq!(
        d.begin_source_until(scope(), SourceId(1), &[7, 0], Tick(11), Tick(20), Tick(80))?,
        Begin::Staged
    );
    let retained = d.expiry_snapshot().decoder_job.ok_or(Error::Identity)?;
    assert_eq!(
        (retained.received, retained.admitted, retained.deadline),
        (Tick(11), Tick(20), Tick(80))
    );
    assert_eq!(
        retained.identity,
        expiry::Identity::Sources { first: 1, end: 2 }
    );
    assert_eq!(
        d.begin_source_until(scope(), SourceId(2), &[8], Tick(12), Tick(21), Tick(81)),
        Err(Error::Busy)
    );
    assert_eq!(d.expiry_snapshot().decoder_job, Some(retained));
    // The original caller-cap check precedes Busy. Its different attempted input
    // must stay distinguishable from the already retained decoder candidate.
    assert_eq!(
        d.begin_source_until(scope(), SourceId(3), &[9], Tick(13), Tick(22), Tick(22)),
        Err(Error::Expired)
    );
    let failed = d.expiry_snapshot();
    let failure = failed.failure.ok_or(Error::Identity)?;
    assert_eq!(failure.selected.kind, expiry::Kind::IncomingCap);
    assert_eq!(
        failure.selected.identity,
        Some(expiry::Identity::Sources { first: 3, end: 4 })
    );
    assert_eq!(failed.decoder_job, Some(retained));
    assert_eq!(d.step(Tick(23), budget(1)), Err(Error::Terminal));
    assert_eq!(d.expiry_snapshot(), failed);
    Ok(())
}
