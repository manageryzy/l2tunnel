use super::*;

fn budget(field: usize, copies: usize, metadata: usize) -> WorkBudget {
    WorkBudget {
        field,
        copies,
        metadata,
    }
}

#[test]
fn encoder_batches_preserve_exact_work_cursors_equation_and_original_expiry()
-> Result<(), Box<dyn std::error::Error>> {
    let config = Config {
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
    };
    let scope = Scope {
        session: [0x67; 16],
        epoch: 3,
        stream: 11,
        direction: 1,
    };
    let make = || -> Result<Encoder, Error> {
        let mut owner = Encoder::new(config, scope, Tick(0))?;
        for original in [&[1, 2, 0][..], &[0, 0, 0, 0], &[255]] {
            owner.admit_source(original, Tick(0))?;
        }
        owner.next_repair = 2;
        owner.begin_repair(false, Tick(0))?;
        Ok(owner)
    };
    let mut owner = make()?;
    let usage = owner.storage_usage()?;
    // Includes zero allowance, a failed visit after copying and partial GF work.
    // Source extents are 5, 6 and 3 bytes, including their length prefixes.
    // Implicit zero suffixes neither modify the equation nor consume GF work.
    for (allowance, expected, cleared, source, column) in [
        (budget(0, 0, 0), budget(0, 0, 0), 0, 0, 0),
        (budget(4, 3, 4), budget(0, 3, 4), 3, 0, 0),
        (budget(4, 0, 7), budget(0, 0, 1), 3, 0, 0),
        (budget(4, 64, 2), budget(0, 2, 2), 5, 0, 0),
        (budget(4, 64, 64), budget(4, 5, 10), 10, 0, 4),
        (budget(64, 64, 2), budget(2, 0, 2), 10, 1, 1),
        (budget(5, 64, 64), budget(5, 0, 6), 10, 2, 0),
        (budget(64, 64, 64), budget(3, 0, 4), 10, 3, 0),
    ] {
        assert_eq!(owner.step(Tick(0), allowance)?, expected);
        let job = owner.job.as_ref().ok_or(Error::Identity)?;
        assert_eq!(
            (job.cleared, job.source, job.column),
            (cleared, source, column)
        );
        assert_eq!(job.deadline, Tick(100));
        assert_eq!(owner.storage_usage()?, usage);
    }
    let repair = owner.pending_repair().ok_or(Error::WorkLimit)?;
    // Existing independently generated Python E3_R2 vector; omitted tail is zero.
    assert_eq!(repair.bytes, &[0, 198, 17, 161, 0, 0]);
    assert_eq!(&owner.output[repair.bytes.len()..], &[0; 4]);
    assert_eq!(
        owner.step(Tick(1), budget(64, 64, 64))?,
        WorkUsed::default()
    );
    let mut expired = make()?;
    assert_eq!(
        expired.step(Tick(100), budget(64, 64, 64)),
        Err(Error::Expired)
    );
    assert_eq!(
        expired
            .expiry_snapshot()
            .failure
            .ok_or(Error::Identity)?
            .selected
            .at,
        Tick(100)
    );
    Ok(())
}
