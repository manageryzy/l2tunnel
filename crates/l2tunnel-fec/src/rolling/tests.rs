use super::*;

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
        session: [0x67; 16],
        epoch: 3,
        stream: 11,
        direction: 1,
    }
}

const ORIGINALS: [&[u8]; 8] = [
    &[1, 2, 0],
    &[0, 0, 0, 0],
    &[255],
    &[0x91, 0, 0x72, 0],
    &[4, 5],
    &[6],
    &[7, 8, 0],
    &[0; 8],
];

// Literal received equations generated with maintained Python PRODUCT/coefficient,
// polynomial 0x11d. These are u16-length enclosing vectors, not legacy compact
// wire bytes, and the decoder never borrows an encoder or sender payload ledger.
const E3_R1: [u8; 10] = [0, 70, 239, 0, 0, 0, 0, 0, 0, 0];
const E3_R2: [u8; 10] = [0, 198, 17, 161, 0, 0, 0, 0, 0, 0];
const E3_R16: [u8; 10] = [0, 69, 111, 193, 0, 0, 0, 0, 0, 0];
const E4_R1: [u8; 10] = [0, 201, 97, 0, 250, 0, 0, 0, 0, 0];
const E4_R2: [u8; 10] = [0, 221, 245, 161, 154, 0, 0, 0, 0, 0];
const E4_R3: [u8; 10] = [0, 49, 141, 0, 239, 0, 0, 0, 0, 0];
const E4_R4: [u8; 10] = [0, 193, 69, 163, 222, 0, 0, 0, 0, 0];
const E5_T3: [u8; 10] = [0, 132, 202, 159, 239, 0, 0, 0, 0, 0];
const E1_R1: [u8; 10] = [0, 32, 235, 203, 0, 0, 0, 0, 0, 0];

fn budget(units: usize) -> WorkBudget {
    WorkBudget {
        field: units,
        copies: units,
        metadata: units,
    }
}

fn work(result: DecodeStep) -> WorkUsed {
    match result {
        DecodeStep::Idle(value)
        | DecodeStep::Pending(value)
        | DecodeStep::Capacity(value)
        | DecodeStep::Accepted { work: value, .. } => value,
    }
}

fn finish(decoder: &mut Decoder, now: Tick, cap: WorkBudget) -> Result<DecodeStep, Error> {
    let original = decoder.status();
    for _ in 0..100_000 {
        let result = decoder.step(now, cap)?;
        let used = work(result);
        assert!(used.field <= cap.field);
        assert!(used.copies <= cap.copies);
        assert!(used.metadata <= cap.metadata);
        if matches!(result, DecodeStep::Pending(_)) {
            let status = decoder.status();
            assert_eq!(status.decoded_prefix, original.decoded_prefix);
            assert_eq!(status.observed_end, original.observed_end);
            assert_eq!(status.rank, original.rank);
            assert_eq!(status.known_sources, original.known_sources);
        } else {
            return Ok(result);
        }
    }
    Err(Error::WorkLimit)
}

fn repair<'a>(
    config: Config,
    end: u32,
    id: u64,
    tail: bool,
    bytes: &'a [u8],
) -> Result<Repair<'a>, Error> {
    Ok(Repair {
        scope: scope(),
        id: RepairId(id),
        support: config.support(end, RepairId(id), tail)?,
        bytes,
    })
}

fn source(decoder: &mut Decoder, id: usize) -> TestResult {
    assert_eq!(
        decoder.begin_source(scope(), SourceId(id as u32), ORIGINALS[id], Tick(0))?,
        Begin::Staged
    );
    assert!(matches!(
        finish(decoder, Tick(0), budget(65_536))?,
        DecodeStep::Accepted { .. }
    ));
    Ok(())
}

fn drain(decoder: &mut Decoder, ids: std::ops::Range<usize>) -> TestResult {
    for id in ids {
        assert_eq!(
            decoder.pending_source(),
            Some((SourceId(id as u32), ORIGINALS[id]))
        );
        decoder.confirm_handoff(SourceId(id as u32), Tick(0))?;
    }
    assert_eq!(decoder.pending_source(), None);
    Ok(())
}

#[test]
fn independent_python_length_vector_recovers_every_single_loss() -> TestResult {
    for missing in 0..3 {
        let mut decoder = Decoder::new(config(), scope(), Tick(0))?;
        for id in 0..3 {
            if id != missing {
                source(&mut decoder, id)?;
            }
        }
        assert_eq!(
            decoder.begin_repair(repair(config(), 3, 16, false, &E3_R16)?, Tick(0))?,
            Begin::Staged
        );
        assert!(matches!(
            finish(&mut decoder, Tick(0), budget(65_536))?,
            DecodeStep::Accepted { prefix: 3, .. }
        ));
        drain(&mut decoder, 0..3)?;
        assert_eq!(decoder.status().rank, 0);
    }
    Ok(())
}

#[test]
fn actual_four_source_loss_recovers_with_varied_local_global_support() -> TestResult {
    for units in [1, 3, 17, 65_536] {
        let mut decoder = Decoder::new(config(), scope(), Tick(0))?;
        for (id, bytes) in [(1, &E4_R1), (2, &E4_R2), (3, &E4_R3), (4, &E4_R4)] {
            assert_eq!(
                decoder.begin_repair(repair(config(), 4, id, false, bytes)?, Tick(0))?,
                Begin::Staged
            );
            assert!(matches!(
                finish(&mut decoder, Tick(0), budget(units))?,
                DecodeStep::Accepted { .. }
            ));
        }
        assert_eq!(decoder.status().decoded_prefix, 4);
        assert_eq!(decoder.status().rank, 0);
        drain(&mut decoder, 0..4)?;
    }
    Ok(())
}

#[test]
fn historical_confirmed_and_future_columns_coexist_across_nearly_two_windows() -> TestResult {
    let mut decoder = Decoder::new(config(), scope(), Tick(0))?;
    for id in 0..3 {
        source(&mut decoder, id)?;
    }
    drain(&mut decoder, 0..3)?;
    for id in 4..7 {
        source(&mut decoder, id)?;
    }
    assert_eq!(decoder.status().decoded_prefix, 3);
    assert_eq!(decoder.status().known_sources, 6);
    assert_eq!(
        decoder.begin_repair(repair(config(), 5, 3, true, &E5_T3)?, Tick(0))?,
        Begin::Staged
    );
    assert!(matches!(
        finish(&mut decoder, Tick(0), budget(3))?,
        DecodeStep::Accepted {
            prefix: 7,
            recovered: 1,
            ..
        }
    ));
    drain(&mut decoder, 3..7)?;
    assert!(decoder.status().known_sources <= 2 * config().window);
    assert_eq!(
        decoder.begin_source(scope(), SourceId(0), ORIGINALS[0], Tick(0))?,
        Begin::Stale
    );
    Ok(())
}

#[test]
fn dependent_equations_have_independent_identity_history_without_invented_rank() -> TestResult {
    let mut decoder = Decoder::new(config(), scope(), Tick(0))?;
    for id in [16, 32_784] {
        assert_eq!(
            decoder.begin_repair(repair(config(), 3, id, false, &E3_R16)?, Tick(0))?,
            Begin::Staged
        );
        assert!(matches!(
            finish(&mut decoder, Tick(0), budget(17))?,
            DecodeStep::Accepted {
                recovered: 0,
                prefix: 0,
                ..
            }
        ));
        assert_eq!(decoder.status().rank, 1);
    }
    assert_eq!(
        decoder.begin_repair(repair(config(), 3, 32_784, false, &E3_R16)?, Tick(0))?,
        Begin::Duplicate
    );
    assert_eq!(
        decoder.begin_repair(repair(config(), 3, 16, false, &E3_R16)?, Tick(0))?,
        Begin::Stale
    );
    source(&mut decoder, 0)?;
    source(&mut decoder, 1)?;
    drain(&mut decoder, 0..3)?;
    Ok(())
}

#[test]
fn algebraic_inconsistency_latches_without_publishing_shadow_state() -> TestResult {
    let mut decoder = Decoder::new(config(), scope(), Tick(0))?;
    decoder.begin_repair(repair(config(), 3, 16, false, &E3_R16)?, Tick(0))?;
    finish(&mut decoder, Tick(0), budget(65_536))?;
    let before = decoder.status();
    let mut corrupt = E3_R16;
    corrupt[9] = 1;
    decoder.begin_repair(repair(config(), 3, 32_784, false, &corrupt)?, Tick(0))?;
    assert_eq!(
        finish(&mut decoder, Tick(0), budget(3)),
        Err(Error::Inconsistent)
    );
    assert_eq!(decoder.status().rank, before.rank);
    assert_eq!(decoder.status().decoded_prefix, before.decoded_prefix);
    assert_eq!(decoder.status().known_sources, before.known_sources);
    assert_eq!(decoder.status().terminal, Some(Error::Inconsistent));
    assert_eq!(decoder.step(Tick(0), budget(65_536)), Err(Error::Terminal));
    Ok(())
}

#[test]
fn zero_coefficients_are_dependent_and_nonzero_payload_is_inconsistent() -> TestResult {
    for (payload, result) in [([0; 10], None), ([1; 10], Some(Error::Inconsistent))] {
        let mut decoder = Decoder::new(config(), scope(), Tick(0))?;
        decoder.begin_repair(repair(config(), 1, 83, false, &payload)?, Tick(0))?;
        let outcome = finish(&mut decoder, Tick(0), budget(1));
        if let Some(error) = result {
            assert_eq!(outcome, Err(error));
        } else {
            assert!(matches!(
                outcome?,
                DecodeStep::Accepted {
                    recovered: 0,
                    prefix: 0,
                    ..
                }
            ));
            assert_eq!(decoder.status().rank, 0);
            assert_eq!(decoder.status().observed_end, 1);
        }
    }
    Ok(())
}

#[test]
fn exact_duplicate_and_conflicting_repair_id_are_distinct() -> TestResult {
    let mut decoder = Decoder::new(config(), scope(), Tick(0))?;
    decoder.begin_repair(repair(config(), 3, 1, false, &E3_R1)?, Tick(0))?;
    finish(&mut decoder, Tick(0), budget(65_536))?;
    let before = decoder.status();
    assert_eq!(
        decoder.begin_repair(repair(config(), 3, 1, false, &E3_R1)?, Tick(0))?,
        Begin::Duplicate
    );
    assert_eq!(decoder.status(), before);
    let mut conflict = E3_R1;
    conflict[2] ^= 1;
    assert_eq!(
        decoder.begin_repair(repair(config(), 3, 1, false, &conflict)?, Tick(0)),
        Err(Error::Conflict)
    );
    assert_eq!(decoder.status().terminal, Some(Error::Conflict));
    Ok(())
}

#[test]
fn exact_source_duplicate_preserves_zero_tails_and_conflict_is_terminal() -> TestResult {
    let mut decoder = Decoder::new(config(), scope(), Tick(0))?;
    source(&mut decoder, 0)?;
    assert_eq!(
        decoder.begin_source(scope(), SourceId(0), &[1, 2, 0], Tick(0))?,
        Begin::Duplicate
    );
    assert_eq!(
        decoder.begin_source(scope(), SourceId(0), &[1, 2], Tick(0)),
        Err(Error::Conflict)
    );
    assert_eq!(decoder.status().decoded_prefix, 1);
    assert_eq!(decoder.pending_source(), None);
    Ok(())
}

#[test]
fn rank_capacity_is_atomic_and_needed_systematic_input_can_progress() -> TestResult {
    let c = Config {
        max_rows: 1,
        ..config()
    };
    let mut decoder = Decoder::new(c, scope(), Tick(0))?;
    decoder.begin_repair(repair(c, 4, 1, false, &E4_R1)?, Tick(0))?;
    finish(&mut decoder, Tick(0), budget(17))?;
    let before = decoder.status();
    decoder.begin_repair(repair(c, 4, 2, false, &E4_R2)?, Tick(0))?;
    assert!(matches!(
        finish(&mut decoder, Tick(0), budget(3))?,
        DecodeStep::Capacity(_)
    ));
    assert_eq!(decoder.status(), before);
    source(&mut decoder, 2)?;
    assert_eq!(decoder.status().rank, 0);
    source(&mut decoder, 0)?;
    source(&mut decoder, 1)?;
    drain(&mut decoder, 0..4)?;
    Ok(())
}

#[test]
fn upper_handoff_remains_usable_during_owned_shadow_job() -> TestResult {
    let c = Config {
        handoff_sources: 1,
        ..config()
    };
    let mut decoder = Decoder::new(c, scope(), Tick(0))?;
    source(&mut decoder, 0)?;
    decoder.begin_source(scope(), SourceId(1), ORIGINALS[1], Tick(0))?;
    assert!(matches!(
        decoder.step(Tick(0), budget(1))?,
        DecodeStep::Pending(_)
    ));
    assert_eq!(decoder.status().decoded_prefix, 1);
    assert_eq!(decoder.pending_source(), Some((SourceId(0), ORIGINALS[0])));
    decoder.confirm_handoff(SourceId(0), Tick(0))?;
    assert!(decoder.status().pending_job);
    assert!(matches!(
        finish(&mut decoder, Tick(0), budget(1))?,
        DecodeStep::Accepted { prefix: 2, .. }
    ));
    drain(&mut decoder, 1..2)?;
    Ok(())
}

#[test]
fn single_slot_handoff_drains_batch_recovery_without_new_peer_input() -> TestResult {
    let c = Config {
        handoff_sources: 1,
        ..config()
    };
    let mut decoder = Decoder::new(c, scope(), Tick(0))?;
    for id in 1..4 {
        source(&mut decoder, id)?;
    }
    decoder.begin_repair(repair(c, 4, 2, false, &E4_R2)?, Tick(0))?;
    assert!(matches!(
        finish(&mut decoder, Tick(0), budget(3))?,
        DecodeStep::Accepted { .. }
    ));
    assert_eq!(decoder.status().rank, 0);
    let original_deadline = decoder.deadline();
    for (id, expected) in ORIGINALS.iter().enumerate().take(4) {
        for _ in 0..10_000 {
            if decoder.pending_source().is_some() {
                break;
            }
            let used = work(decoder.step(Tick(10 + id as u64), budget(1))?);
            assert!(used.field <= 1 && used.copies <= 1 && used.metadata <= 1);
        }
        assert_eq!(
            decoder.pending_source(),
            Some((SourceId(id as u32), *expected))
        );
        assert!(decoder.status().decoded_prefix - decoder.status().handoff_prefix <= 1);
        assert_eq!(decoder.deadline(), original_deadline);
        decoder.confirm_handoff(SourceId(id as u32), Tick(10 + id as u64))?;
    }
    assert_eq!(decoder.pending_source(), None);
    assert_eq!(decoder.status().decoded_prefix, 4);
    assert_eq!(decoder.status().handoff_prefix, 4);
    assert_eq!(decoder.deadline(), None);
    Ok(())
}

#[test]
fn malformed_recovered_lengths_and_padding_are_never_exposed() -> TestResult {
    // Coefficient(regular seed 1, source 0) = 235, generated in Python.
    let malformed = [
        [0; 10],                             // Empty original.
        [0, 224, 0, 0, 0, 0, 0, 0, 0, 0],    // Length nine, negotiated maximum eight.
        [0, 235, 46, 0, 0, 0, 0, 0, 0, 235], // Length one, nonzero padding.
    ];
    for bytes in malformed {
        let mut decoder = Decoder::new(config(), scope(), Tick(0))?;
        decoder.begin_repair(repair(config(), 1, 1, false, &bytes)?, Tick(0))?;
        assert_eq!(finish(&mut decoder, Tick(0), budget(3)), Err(Error::Length));
        assert_eq!(decoder.status().decoded_prefix, 0);
        assert_eq!(decoder.pending_source(), None);
    }
    Ok(())
}

#[test]
fn zero_budget_busy_and_parser_failures_preserve_owned_job() -> TestResult {
    let mut decoder = Decoder::new(config(), scope(), Tick(0))?;
    decoder.begin_repair(repair(config(), 1, 1, false, &E1_R1)?, Tick(0))?;
    let before = decoder.status();
    assert_eq!(
        decoder.step(Tick(0), WorkBudget::default())?,
        DecodeStep::Pending(WorkUsed::default())
    );
    assert_eq!(decoder.status(), before);
    assert_eq!(
        decoder.begin_source(scope(), SourceId(1), ORIGINALS[1], Tick(0)),
        Err(Error::Busy)
    );
    let mut wrong_scope = scope();
    wrong_scope.epoch += 1;
    assert_eq!(
        decoder.begin_source(wrong_scope, SourceId(0), ORIGINALS[0], Tick(0)),
        Err(Error::Scope)
    );
    assert_eq!(
        decoder.step(Tick(0), budget(MAX_STEP_WORK + 1)),
        Err(Error::WorkLimit)
    );
    assert_eq!(decoder.status(), before);
    assert!(matches!(
        finish(&mut decoder, Tick(0), budget(1))?,
        DecodeStep::Accepted { prefix: 1, .. }
    ));
    drain(&mut decoder, 0..1)?;
    Ok(())
}

#[test]
fn shape_support_scope_and_future_horizon_are_checked_before_work() -> TestResult {
    let mut decoder = Decoder::new(config(), scope(), Tick(0))?;
    let before = decoder.status();
    assert_eq!(
        decoder.begin_source(scope(), SourceId(4), ORIGINALS[0], Tick(0)),
        Err(Error::Identity)
    );
    assert_eq!(
        decoder.begin_source(scope(), SourceId(u32::MAX), ORIGINALS[0], Tick(0)),
        Err(Error::Identity)
    );
    assert_eq!(
        decoder.begin_source(scope(), SourceId(0), &[], Tick(0)),
        Err(Error::Length)
    );
    assert_eq!(
        decoder.begin_source(scope(), SourceId(0), &[0; 9], Tick(0)),
        Err(Error::Length)
    );
    assert_eq!(
        decoder.begin_repair(repair(config(), 5, 2, false, &E4_R2)?, Tick(0)),
        Err(Error::Identity)
    );
    assert_eq!(
        decoder.begin_repair(repair(config(), 3, 2, false, &E3_R2[..9])?, Tick(0)),
        Err(Error::Length)
    );
    let mut bad = repair(config(), 3, 2, false, &E3_R2)?;
    bad.support.start = 1;
    assert_eq!(decoder.begin_repair(bad, Tick(0)), Err(Error::Identity));
    bad = repair(config(), 3, 2, false, &E3_R2)?;
    bad.support.seed ^= 1;
    assert_eq!(decoder.begin_repair(bad, Tick(0)), Err(Error::Identity));
    bad = repair(config(), 3, 2, false, &E3_R2)?;
    bad.scope.direction ^= 1;
    assert_eq!(decoder.begin_repair(bad, Tick(0)), Err(Error::Scope));
    assert_eq!(decoder.status(), before);
    source(&mut decoder, 0)?;
    assert_eq!(
        decoder.begin_repair(repair(config(), 1, 1, false, &E1_R1)?, Tick(0))?,
        Begin::Stale
    );
    Ok(())
}

#[test]
fn original_gap_and_job_deadlines_are_not_renewed() -> TestResult {
    let c = Config {
        job_ticks: 10,
        debt_ticks: 100,
        ..config()
    };
    let mut decoder = Decoder::new(c, scope(), Tick(0))?;
    decoder.begin_source(scope(), SourceId(2), ORIGINALS[2], Tick(1))?;
    assert_eq!(decoder.deadline(), Some(Tick(11)));
    finish(&mut decoder, Tick(1), budget(65_536))?;
    assert_eq!(decoder.deadline(), Some(Tick(101)));
    assert_eq!(
        decoder.begin_source(scope(), SourceId(2), ORIGINALS[2], Tick(50))?,
        Begin::Duplicate
    );
    decoder.begin_source(scope(), SourceId(3), ORIGINALS[3], Tick(70))?;
    finish(&mut decoder, Tick(70), budget(65_536))?;
    assert_eq!(decoder.deadline(), Some(Tick(101)));
    assert_eq!(decoder.step(Tick(101), budget(65_536)), Err(Error::Expired));
    assert_eq!(decoder.status().decoded_prefix, 0);

    let mut decoder = Decoder::new(c, scope(), Tick(0))?;
    decoder.begin_repair(repair(c, 1, 1, false, &E1_R1)?, Tick(0))?;
    decoder.step(Tick(9), WorkBudget::default())?;
    assert_eq!(decoder.deadline(), Some(Tick(10)));
    assert_eq!(decoder.step(Tick(10), budget(65_536)), Err(Error::Expired));
    assert_eq!(decoder.status().decoded_prefix, 0);
    Ok(())
}

#[test]
fn handoff_deadline_and_time_regression_are_terminal() -> TestResult {
    let mut decoder = Decoder::new(config(), scope(), Tick(0))?;
    source(&mut decoder, 0)?;
    assert_eq!(decoder.deadline(), Some(Tick(500)));
    assert_eq!(
        decoder.begin_source(scope(), SourceId(0), ORIGINALS[0], Tick(499))?,
        Begin::Duplicate
    );
    assert_eq!(decoder.deadline(), Some(Tick(500)));
    assert_eq!(
        decoder.confirm_handoff(SourceId(0), Tick(500)),
        Err(Error::Expired)
    );
    assert_eq!(decoder.pending_source(), None);
    let mut decoder = Decoder::new(config(), scope(), Tick(10))?;
    assert_eq!(
        decoder.step(Tick(9), WorkBudget::default()),
        Err(Error::TimeRegression)
    );
    assert_eq!(decoder.step(Tick(10), budget(1)), Err(Error::Terminal));
    let mut encoder = Encoder::new(config(), scope(), Tick(10))?;
    assert_eq!(
        encoder.admit_source(ORIGINALS[0], Tick(9)),
        Err(Error::TimeRegression)
    );
    assert_eq!(
        encoder.admit_source(ORIGINALS[0], Tick(10)),
        Err(Error::Terminal)
    );
    Ok(())
}

#[test]
fn sender_matches_independent_python_equation_and_retains_confirmed_columns() -> TestResult {
    let mut encoder = Encoder::new(config(), scope(), Tick(0))?;
    for (id, original) in ORIGINALS.iter().enumerate().take(5) {
        if id > 0 {
            encoder.confirm_prefix(id as u32, Tick(0))?;
        }
        assert_eq!(
            encoder.admit_source(original, Tick(0))?,
            SourceId(id as u32)
        );
    }
    assert_eq!(encoder.source(SourceId(0)), None);
    assert_eq!(encoder.source(SourceId(1)), Some(ORIGINALS[1]));
    assert_eq!(encoder.begin_repair(true, Tick(0))?, RepairId(1));
    assert_eq!(
        encoder.admit_source(ORIGINALS[5], Tick(0)),
        Err(Error::Busy)
    );
    for _ in 0..1_000 {
        let used = encoder.step(Tick(0), budget(1))?;
        assert!(used.field <= 1 && used.copies <= 1 && used.metadata <= 1);
        if encoder.pending_repair().is_some() {
            break;
        }
    }
    assert!(encoder.pending_repair().is_some());
    let pending = encoder.pending_repair().ok_or(Error::Busy)?;
    assert_eq!(pending.support.start, 1);
    assert_eq!(pending.support.end, 5);
    // Tail id 1 has the regular-id-1 seed but global support.
    let expected = [0, 154, 159, 79, 250, 0, 0, 0, 0, 0];
    assert_eq!(pending.bytes, expected);
    let mut short = [0xa5; 9];
    assert_eq!(
        encoder.take_repair(&mut short, Tick(0)),
        Err(Error::OutputTooSmall)
    );
    assert_eq!(short, [0xa5; 9]);
    assert_eq!(encoder.pending_repair().ok_or(Error::Busy)?.bytes, expected);
    let mut output = [0xa5; 12];
    assert_eq!(
        encoder.take_repair(&mut output, Tick(0))?,
        (RepairId(1), config().support(5, RepairId(1), true)?, 10)
    );
    assert_eq!(&output[..10], expected);
    assert_eq!(&output[10..], &[0xa5; 2]);
    assert!(encoder.pending_repair().is_none());
    assert_eq!(encoder.begin_repair(false, Tick(0))?, RepairId(2));
    Ok(())
}

#[test]
fn sender_pressure_and_original_deadlines_preserve_pending_identity() -> TestResult {
    let mut encoder = Encoder::new(config(), scope(), Tick(0))?;
    for original in ORIGINALS.iter().take(4) {
        encoder.admit_source(original, Tick(0))?;
    }
    assert_eq!(
        encoder.admit_source(ORIGINALS[4], Tick(0)),
        Err(Error::Capacity)
    );
    assert_eq!(encoder.confirm_prefix(5, Tick(0)), Err(Error::Identity));
    encoder.confirm_prefix(1, Tick(1))?;
    encoder.confirm_prefix(0, Tick(2))?;
    assert_eq!(encoder.status().confirmed_prefix, 1);
    assert_eq!(encoder.admit_source(ORIGINALS[4], Tick(2))?, SourceId(4));
    assert_eq!(encoder.deadline(), Some(Tick(1_000)));
    assert_eq!(encoder.begin_repair(false, Tick(3))?, RepairId(1));
    assert_eq!(encoder.deadline(), Some(Tick(103)));
    let before = encoder.status();
    assert_eq!(
        encoder.step(Tick(99), WorkBudget::default())?,
        WorkUsed::default()
    );
    assert_eq!(encoder.status(), before);
    assert_eq!(encoder.step(Tick(103), budget(65_536)), Err(Error::Expired));
    assert_eq!(encoder.status().terminal, Some(Error::Expired));
    assert_eq!(
        encoder.take_repair(&mut [0; 10], Tick(104)),
        Err(Error::Terminal)
    );
    Ok(())
}

#[test]
fn support_matches_saved_python_serial_wrap_and_tail_oracles() -> TestResult {
    let c = Config {
        window: 8192,
        local_window: 128,
        global_every: 16,
        ..config()
    };
    for (end, id, tail, start, seed) in [
        (3, 1, false, 0, 2_654_435_761),
        (9000, 15, false, 8872, 1_161_830_751),
        (9000, 16, false, 808, 3_816_266_512),
        (9000, 17, true, 808, 2_175_734_977),
        (32771, 32768, false, 24579, 0),
        (32771, 32769, false, 32643, 2_654_435_761),
        (32771, 32769, true, 24579, 1_527_773_617),
    ] {
        assert_eq!(
            c.support(end, RepairId(id), tail)?,
            Support {
                start,
                end,
                seed,
                tail
            }
        );
    }
    assert_eq!(crate::MAX_SOURCES, 256);
    Ok(())
}

#[test]
fn invalid_configuration_reservation_and_work_fail_before_ingress() -> TestResult {
    for c in [
        Config {
            window: 0,
            ..config()
        },
        Config {
            window: MAX_WINDOW + 1,
            ..config()
        },
        Config {
            local_window: 5,
            ..config()
        },
        Config {
            global_every: 0,
            ..config()
        },
        Config {
            max_payload: MAX_PAYLOAD + 1,
            ..config()
        },
        Config {
            max_rows: 5,
            ..config()
        },
        Config {
            repair_history: 16_385,
            ..config()
        },
        Config {
            handoff_sources: 0,
            ..config()
        },
        Config {
            handoff_sources: 5,
            ..config()
        },
        Config {
            job_ticks: 1_001,
            ..config()
        },
    ] {
        assert_eq!(c.validate(), Err(Error::Configuration));
        assert!(matches!(
            Encoder::new(c, scope(), Tick(0)),
            Err(Error::Configuration)
        ));
        assert!(matches!(
            Decoder::new(c, scope(), Tick(0)),
            Err(Error::Configuration)
        ));
    }
    let c = Config {
        memory_bytes: 1,
        ..config()
    };
    assert!(matches!(
        Encoder::new(c, scope(), Tick(0)),
        Err(Error::Capacity)
    ));
    assert!(matches!(
        Decoder::new(c, scope(), Tick(0)),
        Err(Error::Capacity)
    ));
    assert!(matches!(
        Encoder::new(config(), scope(), Tick(u64::MAX)),
        Err(Error::Exhausted)
    ));
    assert!(matches!(
        Decoder::new(config(), scope(), Tick(u64::MAX)),
        Err(Error::Exhausted)
    ));
    let mut encoder = Encoder::new(config(), scope(), Tick(0))?;
    assert_eq!(
        encoder.step(Tick(0), budget(MAX_STEP_WORK + 1)),
        Err(Error::WorkLimit)
    );
    assert_eq!(encoder.status().terminal, None);
    Ok(())
}

#[test]
fn maximum_length_all_zero_original_has_its_exact_nonempty_length() -> TestResult {
    let c = Config {
        window: 1,
        local_window: 1,
        max_rows: 1,
        handoff_sources: 1,
        ..config()
    };
    let mut decoder = Decoder::new(c, scope(), Tick(0))?;
    // Python PRODUCT[235][8] = 11; payload zeroes do not erase original length.
    let equation = [0, 11, 0, 0, 0, 0, 0, 0, 0, 0];
    decoder.begin_repair(repair(c, 1, 1, false, &equation)?, Tick(0))?;
    assert!(matches!(
        finish(&mut decoder, Tick(0), budget(1))?,
        DecodeStep::Accepted { prefix: 1, .. }
    ));
    assert_eq!(decoder.pending_source(), Some((SourceId(0), &[0; 8][..])));
    decoder.confirm_handoff(SourceId(0), Tick(0))?;
    assert_eq!(decoder.pending_source(), None);
    Ok(())
}

#[test]
fn pending_job_handoff_does_not_renew_already_recovered_batch_deadline() -> TestResult {
    let c = Config {
        handoff_sources: 1,
        job_ticks: 200,
        ..config()
    };
    let mut decoder = Decoder::new(c, scope(), Tick(0))?;
    for id in 1..4 {
        source(&mut decoder, id)?;
    }
    decoder.begin_repair(repair(c, 4, 2, false, &E4_R2)?, Tick(0))?;
    finish(&mut decoder, Tick(0), budget(65_536))?;
    assert_eq!(decoder.status().decoded_prefix, 1);
    assert_eq!(decoder.deadline(), Some(Tick(500)));
    // No new information: an independent, fully known equation owns a shadow
    // job while the oldest output is handed off. Remaining exact batch members
    // must retain their existing upper-owner deadline across that interleaving.
    decoder.begin_repair(repair(c, 4, 4, false, &E4_R4)?, Tick(100))?;
    decoder.step(Tick(100), budget(1))?;
    decoder.confirm_handoff(SourceId(0), Tick(100))?;
    finish(&mut decoder, Tick(100), budget(65_536))?;
    assert_eq!(decoder.pending_source(), Some((SourceId(1), ORIGINALS[1])));
    assert_eq!(decoder.deadline(), Some(Tick(500)));
    Ok(())
}
