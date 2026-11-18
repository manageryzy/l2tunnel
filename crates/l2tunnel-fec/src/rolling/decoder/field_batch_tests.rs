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
fn budget(field: usize, copies: usize, metadata: usize) -> WorkBudget {
    WorkBudget {
        field,
        copies,
        metadata,
    }
}
fn full() -> WorkBudget {
    budget(MAX_STEP_WORK, MAX_STEP_WORK, MAX_STEP_WORK)
}

// Independent maintained-Python vectors already pinned in rolling/tests.rs.
// No sender state or regenerated expected GF bytes are used by these fixtures.
const E4_R1: [u8; 10] = [0, 201, 97, 0, 250, 0, 0, 0, 0, 0];
const E4_R2: [u8; 10] = [0, 221, 245, 161, 154, 0, 0, 0, 0, 0];
const ORIGINALS: [&[u8]; 4] = [&[1, 2, 0], &[0, 0, 0, 0], &[255], &[0x91, 0, 0x72, 0]];

// These five arms are the original bytewise implementation. Unchanged phases
// and transaction publication still use the production owner.
fn bytewise_advance(
    d: &mut Decoder,
    job: &mut Job,
    budget: &mut WorkBudget,
    now: Tick,
) -> Result<Action, Error> {
    let w = d.config.window;
    let width = d.width;
    match job.phase {
        Phase::Known {
            source,
            factor,
            column,
        } => {
            if column == width {
                job.phase = Phase::Support(source + 1);
            } else {
                if !spend(&mut budget.field) {
                    return Ok(Action::Paused);
                }
                let start = d.known(source)?.ok_or(Error::Identity)?;
                d.candidate[w + column] ^= field::multiply(factor, d.known_data[start + column]);
                job.phase = Phase::Known {
                    source,
                    factor,
                    column: column + 1,
                };
            }
        }
        Phase::Eliminate {
            row,
            factor,
            index,
            next,
        } => {
            if index == w + width {
                job.phase = Phase::Reduce(next);
            } else {
                if !spend(&mut budget.field) {
                    return Ok(Action::Paused);
                }
                d.candidate[index] ^= field::multiply(factor, d.row_byte(row, index)?);
                job.phase = Phase::Eliminate {
                    row,
                    factor,
                    index: index + 1,
                    next,
                };
            }
        }
        Phase::Normalize {
            pivot,
            factor,
            index,
        } => {
            if index == w + width {
                job.phase = Phase::Others { pivot, row: 0 };
            } else {
                if !spend(&mut budget.field) {
                    return Ok(Action::Paused);
                }
                d.candidate[index] = field::multiply(factor, d.candidate[index]);
                job.phase = Phase::Normalize {
                    pivot,
                    factor,
                    index: index + 1,
                };
            }
        }
        Phase::CandidateCount {
            pivot,
            index,
            count,
        } => {
            if index == w {
                if count == 1 {
                    job.phase = Phase::Validate {
                        row: None,
                        id: pivot,
                        index: 0,
                        length: 0,
                    };
                } else {
                    job.phase = Phase::FindSlot { pivot, row: 0 };
                }
            } else {
                job.phase = Phase::CandidateCount {
                    pivot,
                    index: index + 1,
                    count: count + usize::from(d.candidate[index] != 0),
                };
            }
        }
        Phase::Scan { row, index, count } => {
            if row == d.config.max_rows {
                job.phase = Phase::Advance;
            } else if d.pivot_at(row)?.is_none() {
                job.phase = Phase::Scan {
                    row: row + 1,
                    index: 0,
                    count: 0,
                };
            } else if index == w {
                if count == 1 {
                    job.phase = Phase::Validate {
                        row: Some(row),
                        id: d.pivot_at(row)?.ok_or(Error::Identity)?,
                        index: 0,
                        length: 0,
                    };
                } else {
                    job.phase = Phase::Scan {
                        row: row + 1,
                        index: 0,
                        count: 0,
                    };
                }
            } else {
                let byte = d.row_byte(row, index)?;
                job.phase = Phase::Scan {
                    row,
                    index: index + 1,
                    count: count + usize::from(byte != 0),
                };
            }
        }
        _ => return d.advance(job, budget, now),
    }
    Ok(Action::Continue)
}

// Keep the actual step's metadata visit, failure and Capacity rollback order.
fn bytewise_step(d: &mut Decoder, now: Tick, mut budget: WorkBudget) -> Result<DecodeStep, Error> {
    if d.job.is_none() {
        return d.step(now, budget);
    }
    budget.validate()?;
    d.time(now)?;
    let before = budget;
    let mut job = d.job.take().ok_or(Error::Identity)?;
    while spend(&mut budget.metadata) {
        match bytewise_advance(d, &mut job, &mut budget, now) {
            Ok(Action::Continue) => {}
            Ok(Action::Paused) => break,
            Ok(Action::Accepted) => {
                return Ok(DecodeStep::Accepted {
                    work: used(before, budget),
                    recovered: job.recovered,
                    prefix: d.live.prefix,
                });
            }
            Ok(Action::Capacity) => {
                d.active = None;
                d.decisions.release(job.ticket)?;
                return Ok(DecodeStep::Capacity(used(before, budget)));
            }
            Err(error) => {
                d.job = Some(job);
                return d.fail(error);
            }
        }
    }
    d.job = Some(job);
    Ok(DecodeStep::Pending(used(before, budget)))
}

fn header(value: &Header) -> (u32, u32, usize, usize, u32) {
    (
        value.prefix,
        value.observed,
        value.rank,
        value.known_count,
        value.evicted_before,
    )
}
fn assert_same(a: &Decoder, b: &Decoder) -> Result<(), Error> {
    assert_eq!(a.status(), b.status());
    assert_eq!(a.pending_source(), b.pending_source());
    assert_eq!(a.data, b.data);
    assert_eq!(a.candidate, b.candidate);
    assert_eq!(a.input, b.input);
    assert_eq!(a.known_data, b.known_data);
    assert_eq!(a.history, b.history);
    assert_eq!(a.history_meta, b.history_meta);
    assert_eq!(a.active, b.active);
    assert_eq!(
        a.job.as_ref().map(|j| j.phase),
        b.job.as_ref().map(|j| j.phase)
    );
    assert_eq!(
        a.job
            .as_ref()
            .map(|j| (j.resume, j.deadline, j.debt, j.recovered)),
        b.job
            .as_ref()
            .map(|j| (j.resume, j.deadline, j.debt, j.recovered))
    );
    for (x, y) in a.known.iter().zip(&b.known) {
        assert_eq!(
            x.get(&a.decisions, a.active)?,
            y.get(&b.decisions, b.active)?
        );
        assert_eq!(x.get(&a.decisions, None)?, y.get(&b.decisions, None)?);
    }
    assert_eq!(a.storage_usage(), b.storage_usage());
    assert_eq!(a.expiry_snapshot(), b.expiry_snapshot());
    assert_eq!(header(&a.live), header(&b.live));
    assert_eq!(header(&a.shadow), header(&b.shadow));
    assert_eq!(
        (a.highest_repair, a.history_floor),
        (b.highest_repair, b.history_floor)
    );
    for (x, y) in a.pivots.iter().zip(&b.pivots) {
        assert_eq!(
            x.get(&a.decisions, a.active)?,
            y.get(&b.decisions, b.active)?
        );
        assert_eq!(x.get(&a.decisions, None)?, y.get(&b.decisions, None)?);
    }
    for (x, y) in a.map.iter().zip(&b.map) {
        assert_eq!(
            x.get(&a.decisions, a.active)?,
            y.get(&b.decisions, b.active)?
        );
        assert_eq!(x.get(&a.decisions, None)?, y.get(&b.decisions, None)?);
    }
    for (x, y) in a.rows.iter().zip(&b.rows) {
        assert_eq!(
            x.selected(&a.decisions, a.active)?,
            y.selected(&b.decisions, b.active)?
        );
        assert_eq!(
            x.selected(&a.decisions, None)?,
            y.selected(&b.decisions, None)?
        );
    }
    Ok(())
}

fn stage(d: &mut Decoder, id: u64, bytes: &[u8]) -> Result<(), Error> {
    assert_eq!(
        d.begin_repair(
            Repair {
                scope: scope(),
                id: RepairId(id),
                support: d.config.support(4, RepairId(id), false)?,
                bytes,
            },
            Tick(0)
        )?,
        Begin::Staged
    );
    Ok(())
}
fn finish(d: &mut Decoder) -> Result<(), Error> {
    for _ in 0..1_000 {
        match d.step(Tick(0), full())? {
            DecodeStep::Accepted { .. } => return Ok(()),
            DecodeStep::Pending(_) => {}
            _ => return Err(Error::Identity),
        }
    }
    Err(Error::WorkLimit)
}
fn finish_pair(a: &mut Decoder, b: &mut Decoder) -> Result<DecodeStep, Error> {
    let quotas = [
        budget(0, 0, 0),
        budget(0, 9, 2),
        budget(9, 0, 3),
        budget(1, 1, 1),
        budget(3, 5, 9),
        budget(8, 2, 1),
        full(),
    ];
    for turn in 0..10_000 {
        let quota = quotas[turn % quotas.len()];
        let actual = a.step(Tick(0), quota)?;
        assert_eq!(actual, bytewise_step(b, Tick(0), quota)?);
        assert_same(a, b)?;
        if !matches!(actual, DecodeStep::Pending(_)) {
            return Ok(actual);
        }
    }
    Err(Error::WorkLimit)
}
fn committed_rows(d: &Decoder) -> Result<Vec<u8>, Error> {
    let mut result = Vec::new();
    for row in 0..d.config.max_rows {
        if let Some(bank) = d.rows[row].selected(&d.decisions, None)? {
            let start = d.row_start(row);
            result.extend_from_slice(&d.data[bank][start..start + d.config.window + d.width]);
        }
    }
    Ok(result)
}

#[test]
fn field_batch_python_vectors_match_every_step_and_repeated_capacity_rollback() -> Result<(), Error>
{
    let c = Config {
        max_rows: 1,
        ..config()
    };
    let mut a = Decoder::new(c, scope(), Tick(0))?;
    let mut b = Decoder::new(c, scope(), Tick(0))?;
    let storage = a.storage_usage();
    for d in [&mut a, &mut b] {
        stage(d, 1, &E4_R1)?;
    }
    assert!(matches!(
        finish_pair(&mut a, &mut b)?,
        DecodeStep::Accepted { .. }
    ));
    assert_eq!(a.status().rank, 1);
    let before = a.status();
    let committed = committed_rows(&a)?;
    // The existing finite rank-capacity scenario, now differential at every
    // small/zero/asymmetric work boundary and across repeated bank reuse.
    for _ in 0..3 {
        for d in [&mut a, &mut b] {
            stage(d, 2, &E4_R2)?;
        }
        assert!(matches!(
            finish_pair(&mut a, &mut b)?,
            DecodeStep::Capacity(_)
        ));
        assert_eq!(a.status(), before);
        assert_eq!(committed_rows(&a)?, committed);
    }
    for id in [2, 0] {
        for d in [&mut a, &mut b] {
            assert_eq!(
                d.begin_source(scope(), SourceId(id as u32), ORIGINALS[id], Tick(0))?,
                Begin::Staged
            );
        }
        assert!(matches!(
            finish_pair(&mut a, &mut b)?,
            DecodeStep::Accepted { .. }
        ));
        if id == 2 {
            assert_eq!(a.status().rank, 0);
        }
    }
    // Retrying the previously refused equation now exercises Known on actual
    // historical/future originals and recovers the remaining missing source 1.
    // It is not stale: the committed prefix is still below support.end.
    for d in [&mut a, &mut b] {
        stage(d, 2, &E4_R2)?;
    }
    assert!(matches!(
        finish_pair(&mut a, &mut b)?,
        DecodeStep::Accepted { .. }
    ));
    for (index, bytes) in ORIGINALS.into_iter().enumerate() {
        let id = SourceId(u32::try_from(index).map_err(|_| Error::Exhausted)?);
        for d in [&mut a, &mut b] {
            assert_eq!(d.pending_source(), Some((id, bytes)));
            d.confirm_handoff(id, Tick(0))?;
        }
        assert_same(&a, &b)?;
    }
    assert_eq!(a.storage_usage(), storage);
    assert_eq!(a.status().decoded_prefix, 4);
    Ok(())
}

fn phase_kind(phase: Phase) -> u8 {
    match phase {
        Phase::Known { .. } => 1,
        Phase::Eliminate { .. } => 2,
        Phase::Normalize { .. } => 3,
        Phase::CandidateCount { .. } => 4,
        Phase::Scan { .. } => 5,
        _ => 0,
    }
}
fn phase_owner(phase: Phase, bank: usize) -> Result<Decoder, Error> {
    let mut d = Decoder::new(config(), scope(), Tick(0))?;
    d.begin_source(scope(), SourceId(0), ORIGINALS[0], Tick(0))?;
    finish(&mut d)?;
    stage(&mut d, 1, &E4_R1)?;
    finish(&mut d)?;
    assert_eq!(d.status().rank, 1);
    stage(&mut d, 2, &E4_R2)?;
    // Exercise both a committed selected bank and a real transaction's prepared
    // alternate version. The phase runner never publishes this synthetic prefix.
    if bank == 1 {
        let ticket = d.active.ok_or(Error::Identity)?;
        let (to, from) = d.rows[0].prepare(&mut d.decisions, ticket)?;
        let from = from.ok_or(Error::Identity)?;
        let original = d.data[from].clone();
        d.data[to].copy_from_slice(&original);
    }
    assert_eq!(d.row_bank(0, d.active)?, bank);
    d.candidate.fill(0xa5);
    d.job.as_mut().ok_or(Error::Identity)?.phase = phase;
    Ok(d)
}
fn phase_prefix(
    d: &mut Decoder,
    mut quota: WorkBudget,
    reference: bool,
) -> Result<WorkUsed, Error> {
    let before = quota;
    let mut job = d.job.take().ok_or(Error::Identity)?;
    let kind = phase_kind(job.phase);
    while phase_kind(job.phase) == kind && spend(&mut quota.metadata) {
        let result = if reference {
            bytewise_advance(d, &mut job, &mut quota, Tick(0))?
        } else {
            d.advance(&mut job, &mut quota, Tick(0))?
        };
        if matches!(result, Action::Paused) {
            break;
        }
    }
    d.job = Some(job);
    Ok(used(before, quota))
}

#[test]
fn field_batch_tiny_budgets_and_exact_end_visits_match_both_selected_banks() -> Result<(), Error> {
    let width = config().width()?;
    let stride = config().window + width;
    for bank in [0, 1] {
        for index in [0, 1, stride - 1, stride] {
            for quota in [
                budget(0, 0, 0),
                budget(0, 8, 1),
                budget(8, 8, 0),
                budget(1, 0, 8),
                budget(8, 0, 1),
                budget(3, 0, 5),
                full(),
            ] {
                for phase in [
                    Phase::Known {
                        source: 0,
                        factor: 235,
                        column: if index == stride - 1 {
                            width - 1
                        } else {
                            index.min(width)
                        },
                    },
                    Phase::Eliminate {
                        row: 0,
                        factor: 113,
                        index,
                        next: 3,
                    },
                    Phase::Normalize {
                        pivot: 0,
                        factor: 235,
                        index,
                    },
                ] {
                    let mut a = phase_owner(phase, bank)?;
                    let mut b = phase_owner(phase, bank)?;
                    assert_eq!(
                        phase_prefix(&mut a, quota, false)?,
                        phase_prefix(&mut b, quota, true)?
                    );
                    assert_same(&a, &b)?;
                }
            }
        }
    }
    Ok(())
}

#[test]
fn field_batch_partial_normalize_keeps_original_expiry_and_committed_state() -> Result<(), Error> {
    let mut a = Decoder::new(config(), scope(), Tick(0))?;
    let mut b = Decoder::new(config(), scope(), Tick(0))?;
    for d in [&mut a, &mut b] {
        stage(d, 1, &E4_R1)?;
    }
    for _ in 0..1_000 {
        if matches!(
            a.job.as_ref().ok_or(Error::Identity)?.phase,
            Phase::Normalize { index: 0, .. }
        ) {
            break;
        }
        let quota = budget(1, 1, 1);
        assert_eq!(
            a.step(Tick(0), quota)?,
            bytewise_step(&mut b, Tick(0), quota)?
        );
        assert_same(&a, &b)?;
    }
    assert!(matches!(
        a.job.as_ref().ok_or(Error::Identity)?.phase,
        Phase::Normalize { index: 0, .. }
    ));
    let committed = committed_rows(&a)?;
    let quota = budget(2, 0, 2);
    assert_eq!(
        a.step(Tick(99), quota)?,
        bytewise_step(&mut b, Tick(99), quota)?
    );
    assert!(matches!(
        a.job.as_ref().ok_or(Error::Identity)?.phase,
        Phase::Normalize { index: 2, .. }
    ));
    assert_same(&a, &b)?;
    assert_eq!(a.job.as_ref().ok_or(Error::Identity)?.deadline, Tick(100));
    assert_eq!(committed_rows(&a)?, committed);
    assert_eq!(a.step(Tick(100), full()), Err(Error::Expired));
    assert_eq!(
        bytewise_step(&mut b, Tick(100), full()),
        Err(Error::Expired)
    );
    assert_same(&a, &b)?;
    assert_eq!(committed_rows(&a)?, committed);
    assert_eq!(a.step(Tick(100), full()), Err(Error::Terminal));
    Ok(())
}

#[test]
fn field_batch_missing_identity_preserves_first_field_debit_and_pause_order() -> Result<(), Error> {
    for phase in [
        Phase::Known {
            source: 1,
            factor: 235,
            column: 0,
        },
        Phase::Eliminate {
            row: 0,
            factor: 235,
            index: 0,
            next: 1,
        },
    ] {
        for field in [0, 1, 8] {
            let mut a = Decoder::new(config(), scope(), Tick(0))?;
            let mut b = Decoder::new(config(), scope(), Tick(0))?;
            for d in [&mut a, &mut b] {
                d.begin_source(scope(), SourceId(0), ORIGINALS[0], Tick(0))?;
                d.job.as_mut().ok_or(Error::Identity)?.phase = phase;
            }
            let mut ja = a.job.take().ok_or(Error::Identity)?;
            let mut jb = b.job.take().ok_or(Error::Identity)?;
            // Metadata is already charged by the outer step before this call.
            let mut qa = budget(field, 8, 7);
            let mut qb = qa;
            let ra = a.advance(&mut ja, &mut qa, Tick(0));
            let rb = bytewise_advance(&mut b, &mut jb, &mut qb, Tick(0));
            if field == 0 {
                assert!(matches!(ra, Ok(Action::Paused)));
            } else {
                assert!(matches!(ra, Err(Error::Identity)));
            }
            assert_eq!(
                ra.map(|value| std::mem::discriminant(&value)),
                rb.map(|value| std::mem::discriminant(&value))
            );
            assert_eq!(qa, qb);
            assert_eq!(qa.field, field.saturating_sub(1));
            assert_eq!(qa.metadata, 7);
            a.job = Some(ja);
            b.job = Some(jb);
            assert_same(&a, &b)?;
        }
    }
    Ok(())
}

#[test]
fn scan_batch_tiny_budgets_and_row_transition_visits_match_selected_banks() -> Result<(), Error> {
    let w = config().window;
    for bank in [0, 1] {
        for index in [0, 1, w - 1, w] {
            for count in [0, 1, 3] {
                for metadata in [0, 1, 2, w - index, w - index + 1, MAX_STEP_WORK] {
                    for phase in [
                        Phase::CandidateCount {
                            pivot: 0,
                            index,
                            count,
                        },
                        Phase::Scan {
                            row: 0,
                            index,
                            count,
                        },
                    ] {
                        let mut a = phase_owner(phase, bank)?;
                        let mut b = phase_owner(phase, bank)?;
                        // Count sparse coefficients, including zero runs, without
                        // confusing this synthetic phase prefix with publication.
                        for d in [&mut a, &mut b] {
                            d.candidate[..w].copy_from_slice(&[0, 7, 0, 0x91]);
                        }
                        let quota = budget(0, 0, metadata);
                        assert_eq!(
                            phase_prefix(&mut a, quota, false)?,
                            phase_prefix(&mut b, quota, true)?
                        );
                        assert_same(&a, &b)?;
                    }
                }
            }
        }
    }
    Ok(())
}

#[test]
fn scan_batch_does_not_cross_row_or_end_transition_in_one_visit() -> Result<(), Error> {
    let w = config().window;
    for phase in [
        Phase::CandidateCount {
            pivot: 0,
            index: w - 1,
            count: 0,
        },
        Phase::Scan {
            row: 0,
            index: w - 1,
            count: 0,
        },
    ] {
        let mut d = phase_owner(phase, 1)?;
        let mut job = d.job.take().ok_or(Error::Identity)?;
        let mut quota = budget(0, 0, 9);
        assert!(matches!(
            d.advance(&mut job, &mut quota, Tick(0))?,
            Action::Continue
        ));
        assert_eq!(quota.metadata, 9); // The outer step paid this one byte already.
        assert!(
            matches!(job.phase, Phase::CandidateCount { index, .. } | Phase::Scan { index, .. } if index == w)
        );
        // A separate metadata visit owns the transition and its validation.
        assert!(spend(&mut quota.metadata));
        assert!(matches!(
            d.advance(&mut job, &mut quota, Tick(0))?,
            Action::Continue
        ));
        assert_eq!(quota.metadata, 8);
    }
    Ok(())
}

#[test]
fn scan_batch_partial_real_transaction_preserves_original_expiry_and_live_rows() -> Result<(), Error>
{
    let mut a = Decoder::new(config(), scope(), Tick(0))?;
    let mut b = Decoder::new(config(), scope(), Tick(0))?;
    for d in [&mut a, &mut b] {
        stage(d, 1, &E4_R1)?;
    }
    for _ in 0..1_000 {
        if matches!(
            a.job.as_ref().ok_or(Error::Identity)?.phase,
            Phase::Scan {
                row: 0,
                index: 0,
                ..
            }
        ) {
            break;
        }
        let quota = budget(1, 1, 1);
        assert_eq!(
            a.step(Tick(0), quota)?,
            bytewise_step(&mut b, Tick(0), quota)?
        );
        assert_same(&a, &b)?;
    }
    assert!(matches!(
        a.job.as_ref().ok_or(Error::Identity)?.phase,
        Phase::Scan {
            row: 0,
            index: 0,
            ..
        }
    ));
    let committed = committed_rows(&a)?;
    let quota = budget(0, 0, 2);
    assert_eq!(
        a.step(Tick(99), quota)?,
        bytewise_step(&mut b, Tick(99), quota)?
    );
    assert!(matches!(
        a.job.as_ref().ok_or(Error::Identity)?.phase,
        Phase::Scan {
            row: 0,
            index: 2,
            ..
        }
    ));
    assert_eq!(a.job.as_ref().ok_or(Error::Identity)?.deadline, Tick(100));
    assert_same(&a, &b)?;
    assert_eq!(committed_rows(&a)?, committed);
    assert_eq!(a.step(Tick(100), full()), Err(Error::Expired));
    assert_eq!(
        bytewise_step(&mut b, Tick(100), full()),
        Err(Error::Expired)
    );
    assert_same(&a, &b)?;
    assert_eq!(committed_rows(&a)?, committed);
    assert_eq!(a.step(Tick(100), full()), Err(Error::Terminal));
    Ok(())
}

#[test]
fn scan_batch_missing_bank_preserves_first_validation_and_metadata_debit() -> Result<(), Error> {
    for metadata in [0, 1, 8] {
        let phase = Phase::Scan {
            row: 0,
            index: 0,
            count: usize::MAX,
        };
        let mut a = Decoder::new(config(), scope(), Tick(0))?;
        let mut b = Decoder::new(config(), scope(), Tick(0))?;
        for d in [&mut a, &mut b] {
            d.begin_source(scope(), SourceId(0), ORIGINALS[0], Tick(0))?;
            // An actual staged pivot with no selected equation bank must fail
            // identity before even an invalid private counter could overflow.
            d.set_pivot(0, Some(0))?;
            d.job.as_mut().ok_or(Error::Identity)?.phase = phase;
        }
        if metadata == 0 {
            assert_eq!(
                a.step(Tick(0), budget(0, 0, 0))?,
                bytewise_step(&mut b, Tick(0), budget(0, 0, 0))?
            );
        } else {
            let mut ja = a.job.take().ok_or(Error::Identity)?;
            let mut jb = b.job.take().ok_or(Error::Identity)?;
            let mut qa = budget(0, 0, metadata - 1);
            let mut qb = qa;
            assert!(matches!(
                a.advance(&mut ja, &mut qa, Tick(0)),
                Err(Error::Identity)
            ));
            assert!(matches!(
                bytewise_advance(&mut b, &mut jb, &mut qb, Tick(0)),
                Err(Error::Identity)
            ));
            assert_eq!(qa, qb);
            assert_eq!(qa.metadata, metadata - 1);
            a.job = Some(ja);
            b.job = Some(jb);
        }
        assert_same(&a, &b)?;
    }
    Ok(())
}

#[test]
fn scan_batch_checked_private_extent_and_count_fail_without_partial_cursor() -> Result<(), Error> {
    for phase in [
        Phase::CandidateCount {
            pivot: 0,
            index: config().window + 1,
            count: 0,
        },
        Phase::CandidateCount {
            pivot: 0,
            index: 0,
            count: usize::MAX,
        },
    ] {
        let mut d = phase_owner(phase, 0)?;
        let mut job = d.job.take().ok_or(Error::Identity)?;
        let mut quota = budget(0, 0, 3);
        let expected = if matches!(
            phase,
            Phase::CandidateCount {
                count: usize::MAX,
                ..
            }
        ) {
            Error::Exhausted
        } else {
            Error::Identity
        };
        assert!(
            matches!(d.advance(&mut job, &mut quota, Tick(0)), Err(error) if error == expected)
        );
        assert_eq!(job.phase, phase);
        assert_eq!(quota, budget(0, 0, 3));
    }
    Ok(())
}
