use super::*;
use crate::research::Profile;

type TestResult = Result<(), Box<dyn std::error::Error>>;

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
        session: [19; 16],
        epoch: 2,
        stream: 7,
        direction: 0,
    }
}
fn profile() -> Profile {
    Profile::Accumulator {
        lanes: 2,
        window: 4,
    }
}
fn budget() -> WorkBudget {
    WorkBudget {
        field: 1,
        copies: 1,
        metadata: 1,
    }
}
fn finish(decoder: &mut Decoder, now: Tick) -> Result<(), Error> {
    for _ in 0..10_000 {
        let step = decoder.step(now, budget())?;
        let work = match step {
            DecodeStep::Idle(work)
            | DecodeStep::Pending(work)
            | DecodeStep::Capacity(work)
            | DecodeStep::Accepted { work, .. } => work,
        };
        assert!(work.field <= 1 && work.copies <= 1 && work.metadata <= 1);
        match step {
            DecodeStep::Accepted { .. } => return Ok(()),
            DecodeStep::Pending(_) => {}
            _ => return Err(Error::Identity),
        }
    }
    Err(Error::WorkLimit)
}

const ORIGINALS: [&[u8]; 4] = [&[0, 5, 255], &[11, 0, 128, 0], &[1], &[2, 7, 3]];

fn encoded() -> Result<Encoder, Error> {
    let mut encoder = Encoder::new(config(), scope(), Tick(0))?;
    for bytes in ORIGINALS {
        encoder.admit_source(bytes, Tick(0))?;
    }
    // Retained acknowledged sources are still valid equation columns.
    encoder.confirm_prefix(4, Tick(0))?;
    encoder.begin_equation(profile().support(4, 0, 1)?, profile(), Tick(0))?;
    for _ in 0..1_000 {
        let work = encoder.step(Tick(0), budget())?;
        assert!(work.field <= 1 && work.copies <= 1 && work.metadata <= 1);
        if encoder.pending_repair().is_some() {
            return Ok(encoder);
        }
    }
    Err(Error::WorkLimit)
}

#[test]
fn research_equation_recovers_retained_payload_and_binds_replay_profile() -> TestResult {
    let encoder = encoded()?;
    let repair = encoder.pending_repair().ok_or(Error::Busy)?;
    let mut decoder = Decoder::new(config(), scope(), Tick(0))?;
    for id in [0, 2, 3] {
        assert_eq!(
            decoder.begin_source(scope(), SourceId(id), ORIGINALS[id as usize], Tick(0))?,
            Begin::Staged
        );
        finish(&mut decoder, Tick(0))?;
    }
    assert_eq!(
        decoder.begin_equation_until(repair, profile(), 0, Tick(0), Tick(0), Tick(90))?,
        Begin::Staged
    );
    finish(&mut decoder, Tick(0))?;
    for (id, bytes) in ORIGINALS.iter().enumerate() {
        assert_eq!(
            decoder.pending_source(),
            Some((SourceId(id as u32), *bytes))
        );
        decoder.confirm_handoff(SourceId(id as u32), Tick(0))?;
    }
    assert_eq!(
        decoder.begin_equation_until(repair, profile(), 0, Tick(0), Tick(0), Tick(90))?,
        Begin::Duplicate
    );
    let changed = Profile::Accumulator {
        lanes: 3,
        window: 4,
    };
    assert_eq!(
        decoder.begin_equation_until(repair, changed, 0, Tick(0), Tick(0), Tick(90)),
        Err(Error::Conflict)
    );
    assert_eq!(decoder.status().terminal, Some(Error::Conflict));
    Ok(())
}

#[test]
fn research_equation_preserves_queued_arrival_cap_and_atomic_expiry() -> TestResult {
    let encoder = encoded()?;
    let repair = encoder.pending_repair().ok_or(Error::Busy)?;
    let mut decoder = Decoder::new(config(), scope(), Tick(0))?;
    let before = decoder.status();
    assert_eq!(
        decoder.begin_equation_until(repair, profile(), 0, Tick(3), Tick(10), Tick(50))?,
        Begin::Staged
    );
    assert_eq!(decoder.deadline(), Some(Tick(50)));
    assert!(matches!(
        decoder.step(Tick(49), budget())?,
        DecodeStep::Pending(_)
    ));
    assert_eq!(decoder.step(Tick(50), budget()), Err(Error::Expired));
    assert_eq!(decoder.status().decoded_prefix, before.decoded_prefix);
    assert_eq!(decoder.status().rank, before.rank);
    assert_eq!(decoder.status().observed_end, before.observed_end);
    Ok(())
}

#[test]
fn research_equation_checks_horizon_without_relaxing_public_compact_api() -> TestResult {
    let encoder = encoded()?;
    let repair = encoder.pending_repair().ok_or(Error::Busy)?;
    let mut decoder = Decoder::new(config(), scope(), Tick(0))?;
    let before = decoder.status();
    assert_eq!(decoder.begin_repair(repair, Tick(0)), Err(Error::Identity));
    let oversized = Repair {
        support: Support {
            end: 5,
            ..repair.support
        },
        ..repair
    };
    assert_eq!(
        decoder.begin_equation_until(oversized, profile(), 0, Tick(0), Tick(0), Tick(90)),
        Err(Error::Identity)
    );
    let backwards = Repair {
        support: Support {
            start: 5,
            ..repair.support
        },
        ..repair
    };
    assert_eq!(
        decoder.begin_equation_until(backwards, profile(), 0, Tick(0), Tick(0), Tick(90)),
        Err(Error::Identity)
    );
    let wrong_scope = Repair {
        scope: Scope {
            epoch: 3,
            ..scope()
        },
        ..repair
    };
    assert_eq!(
        decoder.begin_equation_until(wrong_scope, profile(), 0, Tick(0), Tick(0), Tick(90)),
        Err(Error::Scope)
    );
    assert_eq!(decoder.status(), before);
    Ok(())
}
