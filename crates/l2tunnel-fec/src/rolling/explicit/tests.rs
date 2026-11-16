use super::*;

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn config() -> Config {
    Config {
        window: 512,
        local_window: 128,
        global_every: 16,
        max_payload: 7,
        max_rows: 4,
        repair_history: 2,
        handoff_sources: 512,
        job_ticks: 100,
        debt_ticks: 1000,
        handoff_ticks: 500,
        memory_bytes: 1 << 24,
    }
}
fn scope() -> Scope {
    Scope {
        session: [0x4c; 16],
        epoch: 3,
        stream: 5,
        direction: 1,
    }
}
fn budget(n: usize) -> WorkBudget {
    WorkBudget {
        field: n,
        copies: n,
        metadata: n,
    }
}
fn payload(id: u32) -> [u8; 4] {
    [id as u8, 0, (id >> 8) as u8, 251]
}
fn finish(decoder: &mut Decoder, cap: usize) -> Result<(), Error> {
    for _ in 0..100_000 {
        let result = decoder.step(Tick(0), budget(cap))?;
        let work = match result {
            DecodeStep::Idle(w)
            | DecodeStep::Pending(w)
            | DecodeStep::Capacity(w)
            | DecodeStep::Accepted { work: w, .. } => w,
        };
        assert!(work.field <= cap && work.copies <= cap && work.metadata <= cap);
        match result {
            DecodeStep::Accepted { .. } => return Ok(()),
            DecodeStep::Pending(_) => {}
            _ => return Err(Error::Identity),
        }
    }
    Err(Error::WorkLimit)
}

#[test]
fn explicit_sparse_old_source_recovery_and_exact_coefficient_replay() -> TestResult {
    let mut encoder = Encoder::new_explicit(config(), scope(), Tick(0))?;
    let mut decoder = Decoder::new_explicit(config(), scope(), Tick(0))?;
    for id in 0..310 {
        encoder.admit_source(&payload(id), Tick(0))?;
        if id != 1 {
            assert_eq!(
                decoder.begin_source(scope(), SourceId(id), &payload(id), Tick(0))?,
                Begin::Staged
            );
            finish(&mut decoder, 65_536)?;
        }
    }
    let terms = [
        Term {
            source: SourceId(1),
            coefficient: 3,
        },
        Term {
            source: SourceId(300),
            coefficient: 211,
        },
    ];
    // This is a sparse old-source feedback equation: extent300, two terms,
    // and lastsource300 older than the current exclusive source prefix310.
    encoder.begin_explicit(&terms, true, Tick(0), Tick(0), Tick(90))?;
    for _ in 0..10_000 {
        let work = encoder.step(Tick(0), budget(1))?;
        assert!(work.field <= 1 && work.copies <= 1 && work.metadata <= 1);
        if encoder.pending_repair().is_some() {
            break;
        }
    }
    let repair = encoder.pending_repair().ok_or(Error::WorkLimit)?;
    assert_eq!(
        repair.support,
        Support {
            start: 1,
            end: 301,
            seed: 1,
            tail: false
        }
    );
    assert_eq!(
        decoder.begin_explicit_until(repair, &terms, Tick(0), Tick(0), Tick(90))?,
        Begin::Staged
    );
    finish(&mut decoder, 1)?;
    for id in 0..310 {
        assert_eq!(
            decoder.pending_source(),
            Some((SourceId(id), payload(id).as_slice()))
        );
        decoder.confirm_handoff(SourceId(id), Tick(0))?;
    }
    assert_eq!(
        decoder.begin_explicit_until(repair, &terms, Tick(0), Tick(0), Tick(90))?,
        Begin::Duplicate
    );
    let mut changed = terms;
    changed[1].coefficient ^= 1;
    assert_eq!(
        decoder.begin_explicit_until(repair, &changed, Tick(0), Tick(0), Tick(90)),
        Err(Error::Conflict)
    );
    Ok(())
}

#[test]
fn explicit_constructor_storage_and_admission_failures_preserve_default_heap() -> TestResult {
    let c = config();
    let base_encoder = Encoder::requested_storage(c)?;
    let encoder = Encoder::new_explicit(c, scope(), Tick(0))?;
    let usage = encoder.storage_usage()?;
    assert_eq!(usage, Encoder::explicit_requested_storage(c)?);
    assert_eq!(
        usage.capacity_bytes - base_encoder.capacity_bytes,
        ROW_BYTES
    );
    assert_eq!(usage.allocations - base_encoder.allocations, 1);
    assert_eq!(
        Encoder::new(c, scope(), Tick(0))?.storage_usage()?,
        base_encoder
    );
    let base_decoder = Decoder::requested_storage(c)?;
    let decoder = Decoder::new_explicit(c, scope(), Tick(0))?;
    let usage = decoder.storage_usage()?;
    assert_eq!(usage, Decoder::explicit_requested_storage(c)?);
    assert_eq!(
        usage.capacity_bytes - base_decoder.capacity_bytes,
        DecoderState::memory_bound(c.repair_history)?
    );
    assert_eq!(usage.allocations - base_decoder.allocations, 3);
    assert_eq!(
        Decoder::new(c, scope(), Tick(0))?.storage_usage()?,
        base_decoder
    );
    let mut short = c;
    short.memory_bytes = Encoder::explicit_memory_bound(c)? - 1;
    assert!(matches!(
        Encoder::new_explicit(short, scope(), Tick(0)),
        Err(Error::Capacity)
    ));
    short.memory_bytes = Decoder::explicit_memory_bound(c)? - 1;
    assert!(matches!(
        Decoder::new_explicit(short, scope(), Tick(0)),
        Err(Error::Capacity)
    ));

    let mut encoder = encoder;
    encoder.admit_source(&payload(0), Tick(0))?;
    let before = encoder.status();
    for terms in [
        vec![],
        vec![Term {
            source: SourceId(0),
            coefficient: 0,
        }],
        vec![
            Term {
                source: SourceId(0),
                coefficient: 1
            };
            2
        ],
        vec![
            Term {
                source: SourceId(0),
                coefficient: 1
            };
            MAX_TERMS + 1
        ],
        vec![Term {
            source: SourceId(1),
            coefficient: 1,
        }],
    ] {
        assert!(
            encoder
                .begin_explicit(&terms, false, Tick(0), Tick(0), Tick(90))
                .is_err()
        );
        assert_eq!(encoder.status(), before);
    }
    assert_eq!(
        encoder.begin_repair(false, Tick(0)),
        Err(Error::Configuration)
    );
    assert!(matches!(
        support(
            &[
                Term {
                    source: SourceId(0),
                    coefficient: 1
                },
                Term {
                    source: SourceId(512),
                    coefficient: 2
                }
            ],
            false,
            c.window
        ),
        Err(Error::Capacity)
    ));
    Ok(())
}

#[test]
fn explicit_original_queued_deadline_and_atomic_decoder_expiry() -> TestResult {
    let c = config();
    let terms = [Term {
        source: SourceId(0),
        coefficient: 7,
    }];
    let mut encoder = Encoder::new_explicit(c, scope(), Tick(0))?;
    encoder.admit_source(&payload(0), Tick(0))?;
    encoder.begin_explicit(&terms, false, Tick(1), Tick(20), Tick(30))?;
    assert_eq!(encoder.deadline(), Some(Tick(30)));
    encoder.step(Tick(20), budget(65_536))?;
    let repair = encoder.pending_repair().ok_or(Error::WorkLimit)?;
    let mut decoder = Decoder::new_explicit(c, scope(), Tick(0))?;
    let before = decoder.status();
    decoder.begin_explicit_until(repair, &terms, Tick(1), Tick(20), Tick(30))?;
    assert_eq!(decoder.deadline(), Some(Tick(30)));
    assert!(matches!(
        decoder.step(Tick(29), budget(1))?,
        DecodeStep::Pending(_)
    ));
    assert_eq!(decoder.step(Tick(30), budget(1)), Err(Error::Expired));
    assert_eq!(decoder.status().decoded_prefix, before.decoded_prefix);
    assert_eq!(decoder.status().rank, before.rank);
    assert_eq!(decoder.status().observed_end, before.observed_end);
    assert_eq!(encoder.step(Tick(30), budget(1)), Err(Error::Expired));
    Ok(())
}
