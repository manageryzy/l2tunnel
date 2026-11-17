use super::*;

fn config() -> Config {
    Config {
        window: 16,
        local_window: 8,
        global_every: 2,
        max_payload: 16,
        max_rows: 4,
        repair_history: 8,
        handoff_sources: 16,
        job_ticks: 100,
        debt_ticks: 1000,
        handoff_ticks: 500,
        memory_bytes: 1 << 20,
    }
}
fn scope() -> Scope {
    Scope {
        session: [7; 16],
        epoch: 0,
        stream: 0,
        direction: 0,
    }
}
fn budget(n: usize) -> WorkBudget {
    WorkBudget {
        field: n,
        copies: n,
        metadata: n,
    }
}

// The oracle is intentionally limited to the three changed phases. Every other
// phase, including GF operations and atomic publication, uses the actual owner.
fn bytewise_advance(
    d: &mut Decoder,
    job: &mut Job,
    budget: &mut WorkBudget,
    now: Tick,
) -> Result<Action, Error> {
    let w = d.config.window;
    let width = d.width;
    match job.phase {
        Phase::CopyRow {
            row,
            from,
            to,
            index,
        } => {
            if index == w + width {
                job.phase = job.resume.take().ok_or(Error::Identity)?;
            } else {
                if !spend(&mut budget.copies) {
                    return Ok(Action::Paused);
                }
                let at = d.row_start(row) + index;
                d.data[to][at] = d.data[from][at];
                job.phase = Phase::CopyRow {
                    row,
                    from,
                    to,
                    index: index + 1,
                };
            }
        }
        Phase::Clear(i) => {
            if i == d.candidate.len() {
                job.phase = Phase::Load(0);
            } else {
                if !spend(&mut budget.copies) {
                    return Ok(Action::Paused);
                }
                d.candidate[i] = 0;
                job.phase = Phase::Clear(i + 1);
            }
        }
        Phase::Load(i) => {
            if i == width {
                job.phase = Phase::Support(job.input.start());
            } else {
                if !spend(&mut budget.copies) {
                    return Ok(Action::Paused);
                }
                d.candidate[w + i] = d.input[i];
                job.phase = Phase::Load(i + 1);
            }
        }
        _ => return d.advance(job, budget, now),
    }
    Ok(Action::Continue)
}

// Reuse the current owner for idle work. The staged-job loop differs from step()
// only at the three-phase oracle call, retaining its exact metadata visit order.
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
    Ok(())
}
fn finish_pair(a: &mut Decoder, b: &mut Decoder) -> Result<DecodeStep, Error> {
    let budgets = [
        budget(0),
        WorkBudget {
            field: 0,
            copies: 64,
            metadata: 0,
        },
        WorkBudget {
            field: 64,
            copies: 0,
            metadata: 9,
        },
        WorkBudget {
            field: 0,
            copies: 9,
            metadata: 2,
        },
        WorkBudget {
            field: 2,
            copies: 3,
            metadata: 64,
        },
        budget(1),
        budget(7),
        budget(MAX_STEP_WORK),
    ];
    for index in 0..10_000 {
        let quota = budgets[index % budgets.len()];
        let actual = a.step(Tick(0), quota)?;
        assert_eq!(actual, bytewise_step(b, Tick(0), quota)?);
        assert_same(a, b)?;
        if !matches!(actual, DecodeStep::Pending(_)) {
            return Ok(actual);
        }
    }
    Err(Error::WorkLimit)
}
fn repair(e: &mut Encoder, c: Config) -> Result<(RepairId, Support, Vec<u8>), Error> {
    e.begin_repair(true, Tick(0))?;
    for _ in 0..10_000 {
        if e.pending_repair().is_some() {
            let mut bytes = vec![0; c.width()?];
            let (id, support, len) = e.take_repair(&mut bytes, Tick(0))?;
            bytes.truncate(len);
            return Ok((id, support, bytes));
        }
        e.step(Tick(0), budget(MAX_STEP_WORK))?;
    }
    Err(Error::WorkLimit)
}
fn stage(d: &mut Decoder, packet: &(RepairId, Support, Vec<u8>)) -> Result<(), Error> {
    assert_eq!(
        d.begin_repair(
            Repair {
                scope: scope(),
                id: packet.0,
                support: packet.1,
                bytes: &packet.2
            },
            Tick(0),
        )?,
        Begin::Staged
    );
    Ok(())
}
fn committed_rows(d: &Decoder) -> Result<Vec<u8>, Error> {
    let mut bytes = Vec::new();
    for row in 0..d.config.max_rows {
        let selected = d.rows[row].selected(&d.decisions, None)?;
        for column in 0..d.config.window + d.width {
            bytes.push(selected.map_or(0, |bank| d.data[bank][d.row_start(row) + column]));
        }
    }
    Ok(bytes)
}

#[test]
fn copy_batch_matches_bytewise_work_state_recovery_and_capacity_rollback() -> Result<(), Error> {
    let c = Config {
        max_rows: 1,
        ..config()
    };
    let payloads = [&[11, 12, 0, 0][..], &[21, 22, 23, 0, 0], &[31, 0]];
    let mut encoder = Encoder::new(c, scope(), Tick(0))?;
    let mut actual = Decoder::new(c, scope(), Tick(0))?;
    let mut reference = Decoder::new(c, scope(), Tick(0))?;
    let storage = actual.storage_usage();
    for bytes in payloads {
        encoder.admit_source(bytes, Tick(0))?;
    }
    let first = repair(&mut encoder, c)?;
    let second = repair(&mut encoder, c)?;
    for d in [&mut actual, &mut reference] {
        stage(d, &first)?;
    }
    assert!(matches!(
        finish_pair(&mut actual, &mut reference)?,
        DecodeStep::Accepted { .. }
    ));
    assert_eq!(actual.status().rank, 1);
    let committed = committed_rows(&actual)?;
    let before = actual.status();
    // A rejected independent row must remain uncommitted, including bank reuse
    // across repeated attempts. The oracle uses the same finite decision pool.
    for _ in 0..3 {
        for d in [&mut actual, &mut reference] {
            stage(d, &second)?;
        }
        assert!(matches!(
            finish_pair(&mut actual, &mut reference)?,
            DecodeStep::Capacity(_)
        ));
        assert_eq!(committed_rows(&actual)?, committed);
        assert_eq!(actual.status(), before);
    }
    // A nonpivot original lets the rejected repair recover both missing sources.
    // Their mixed lengths and meaningful trailing zeros must survive unchanged.
    for d in [&mut actual, &mut reference] {
        assert_eq!(
            d.begin_source(scope(), SourceId(2), payloads[2], Tick(0))?,
            Begin::Staged
        );
    }
    assert!(matches!(
        finish_pair(&mut actual, &mut reference)?,
        DecodeStep::Accepted { .. }
    ));
    for d in [&mut actual, &mut reference] {
        stage(d, &second)?;
    }
    assert!(matches!(
        finish_pair(&mut actual, &mut reference)?,
        DecodeStep::Accepted { .. }
    ));
    for (index, bytes) in payloads.into_iter().enumerate() {
        let id = SourceId(u32::try_from(index).map_err(|_| Error::Exhausted)?);
        assert_eq!(actual.pending_source(), Some((id, bytes)));
        assert_eq!(reference.pending_source(), Some((id, bytes)));
        actual.confirm_handoff(id, Tick(0))?;
        reference.confirm_handoff(id, Tick(0))?;
        assert_same(&actual, &reference)?;
    }
    assert_eq!(actual.status().rank, 0);
    assert_eq!(actual.status().decoded_prefix, 3);
    assert_eq!(actual.storage_usage(), storage);
    Ok(())
}

fn in_copy_phase(phase: Phase) -> bool {
    matches!(
        phase,
        Phase::CopyRow { .. } | Phase::Clear(_) | Phase::Load(_)
    )
}
fn phase_prefix(
    d: &mut Decoder,
    mut budget: WorkBudget,
    reference: bool,
) -> Result<WorkUsed, Error> {
    let before = budget;
    let mut job = d.job.take().ok_or(Error::Identity)?;
    while in_copy_phase(job.phase) && spend(&mut budget.metadata) {
        let action = if reference {
            bytewise_advance(d, &mut job, &mut budget, Tick(0))?
        } else {
            d.advance(&mut job, &mut budget, Tick(0))?
        };
        if matches!(action, Action::Paused) {
            break;
        }
    }
    d.job = Some(job);
    Ok(used(before, budget))
}
fn phase_owner(phase: Phase) -> Result<Decoder, Error> {
    let mut d = Decoder::new(config(), scope(), Tick(0))?;
    d.begin_source(scope(), SourceId(0), &[11, 0, 0], Tick(0))?;
    d.candidate.fill(0xa5);
    for (bank, data) in d.data.iter_mut().enumerate() {
        for (index, byte) in data.iter_mut().enumerate() {
            *byte = (index as u8).wrapping_add(if bank == 0 { 17 } else { 91 });
        }
    }
    let job = d.job.as_mut().ok_or(Error::Identity)?;
    job.phase = phase;
    job.resume = Some(Phase::Support(0));
    Ok(d)
}

#[test]
fn copy_batch_zero_budgets_and_phase_end_visits_match_both_bank_directions() -> Result<(), Error> {
    let width = config().width()?;
    let stride = config().window + width;
    for (from, to) in [(0, 1), (1, 0)] {
        for index in [0, 1, stride - 1, stride] {
            for quota in [
                budget(0),
                WorkBudget {
                    field: 0,
                    copies: 0,
                    metadata: 1,
                },
                WorkBudget {
                    field: 0,
                    copies: 5,
                    metadata: 0,
                },
                WorkBudget {
                    field: 0,
                    copies: 1,
                    metadata: 8,
                },
                WorkBudget {
                    field: 0,
                    copies: 8,
                    metadata: 1,
                },
                budget(3),
                budget(MAX_STEP_WORK),
            ] {
                for phase in [
                    Phase::CopyRow {
                        row: config().max_rows - 1,
                        from,
                        to,
                        index,
                    },
                    Phase::Clear(index),
                    Phase::Load(index.min(width)),
                ] {
                    let mut actual = phase_owner(phase)?;
                    let mut reference = phase_owner(phase)?;
                    assert_eq!(
                        phase_prefix(&mut actual, quota, false)?,
                        phase_prefix(&mut reference, quota, true)?
                    );
                    assert_same(&actual, &reference)?;
                }
            }
        }
    }
    Ok(())
}

#[test]
fn copy_batch_partial_row_expiry_preserves_committed_state_and_original_cap() -> Result<(), Error> {
    let c = config();
    let mut encoder = Encoder::new(c, scope(), Tick(0))?;
    let mut d = Decoder::new(c, scope(), Tick(0))?;
    for bytes in [&[11, 12][..], &[21, 22], &[31, 32]] {
        encoder.admit_source(bytes, Tick(0))?;
    }
    let packet = repair(&mut encoder, c)?;
    stage(&mut d, &packet)?;
    for _ in 0..10_000 {
        if !matches!(
            d.step(Tick(0), budget(MAX_STEP_WORK))?,
            DecodeStep::Pending(_)
        ) {
            break;
        }
    }
    assert_eq!(d.status().rank, 1);
    let rows = committed_rows(&d)?;
    let known: Vec<_> = d
        .known
        .iter()
        .map(|cell| cell.get(&d.decisions, None))
        .collect::<Result<_, _>>()?;
    let before = d.status();
    d.begin_source(scope(), SourceId(1), &[21, 22], Tick(0))?;
    for _ in 0..10_000 {
        if matches!(
            d.job.as_ref().ok_or(Error::Identity)?.phase,
            Phase::CopyRow { index: 0, .. }
        ) {
            break;
        }
        assert!(matches!(
            d.step(Tick(0), budget(1))?,
            DecodeStep::Pending(_)
        ));
    }
    let job = d.job.as_ref().ok_or(Error::Identity)?;
    assert!(matches!(job.phase, Phase::CopyRow { index: 0, .. }));
    let deadline = job.deadline;
    let result = d.step(
        Tick(0),
        WorkBudget {
            field: 0,
            copies: 7,
            metadata: 4,
        },
    )?;
    assert_eq!(
        result,
        DecodeStep::Pending(WorkUsed {
            field: 0,
            copies: 4,
            metadata: 4
        })
    );
    assert!(matches!(
        d.job.as_ref().ok_or(Error::Identity)?.phase,
        Phase::CopyRow { index: 4, .. }
    ));
    assert_eq!(d.job.as_ref().ok_or(Error::Identity)?.deadline, deadline);
    assert_eq!(committed_rows(&d)?, rows);
    assert_eq!(d.step(deadline, budget(MAX_STEP_WORK)), Err(Error::Expired));
    assert_eq!(committed_rows(&d)?, rows);
    assert_eq!(
        d.known
            .iter()
            .map(|cell| cell.get(&d.decisions, None))
            .collect::<Result<Vec<_>, _>>()?,
        known
    );
    assert_eq!(d.status().rank, before.rank);
    assert_eq!(d.status().decoded_prefix, before.decoded_prefix);
    assert_eq!(d.step(deadline, budget(1)), Err(Error::Terminal));
    Ok(())
}

#[test]
fn copy_batch_rejects_invalid_row_bank_or_extent_without_writing() -> Result<(), Error> {
    for phase in [
        Phase::CopyRow {
            row: 0,
            from: 0,
            to: 0,
            index: 0,
        },
        Phase::CopyRow {
            row: 0,
            from: 2,
            to: 1,
            index: 0,
        },
        Phase::CopyRow {
            row: config().max_rows,
            from: 0,
            to: 1,
            index: 0,
        },
        Phase::CopyRow {
            row: 0,
            from: 0,
            to: 1,
            index: config().window + config().width()? + 1,
        },
    ] {
        let mut d = phase_owner(phase)?;
        let before = d.data.clone();
        let mut job = d.job.take().ok_or(Error::Identity)?;
        let mut available = budget(7);
        assert!(matches!(
            d.advance(&mut job, &mut available, Tick(0)),
            Err(Error::Identity)
        ));
        assert_eq!(d.data, before);
        assert_eq!(available, budget(7));
    }
    Ok(())
}
