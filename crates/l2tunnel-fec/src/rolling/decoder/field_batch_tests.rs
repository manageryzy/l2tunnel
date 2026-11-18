use super::*;
use crate::rolling::gf_batch::{MULTIPLICATION_ROWS, nonzero_bytes};

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

fn check_scaled(factor: u8, input: &[u8], before: &[u8]) {
    let expected: Vec<_> = before
        .iter()
        .zip(input)
        .map(|(old, value)| *old ^ field::multiply(factor, *value))
        .collect();
    let mut counted = before.to_vec();
    let (removed, added) = xor_scaled::<true>(&mut counted, input, factor);
    assert_eq!(counted, expected);
    let old_count = before.iter().filter(|value| **value != 0).count();
    let new_count = expected.iter().filter(|value| **value != 0).count();
    assert!(removed <= old_count);
    assert_eq!(old_count - removed + added, new_count);
    let mut payload = before.to_vec();
    assert_eq!(xor_scaled::<false>(&mut payload, input, factor), (0, 0));
    assert_eq!(payload, expected);
}

#[test]
fn measured_gf_rows_match_all_factors_and_byte_products() {
    for factor in 0..=u8::MAX {
        for value in 0..=u8::MAX {
            assert_eq!(
                MULTIPLICATION_ROWS[usize::from(factor)][usize::from(value)],
                field::multiply(factor, value)
            );
        }
        let all: Vec<_> = (0..=u8::MAX).collect();
        let before: Vec<_> = all.iter().map(|value| value.wrapping_mul(19)).collect();
        check_scaled(factor, &all, &before);
        check_scaled(factor, &[0; 256], &before);
        let mixed: Vec<_> = all
            .iter()
            .enumerate()
            .map(|(index, value)| if index % 32 < 16 { 0 } else { *value })
            .collect();
        check_scaled(factor, &mixed, &before);
    }
}

#[test]
fn measured_gf_chunks_preserve_zero_mixed_dense_boundaries_and_counts() {
    for length in [
        0, 1, 7, 8, 9, 15, 16, 17, 31, 32, 33, 63, 64, 65, 257, 1290, 8192,
    ] {
        for factor in [0, 1, 2, 129, 255] {
            for offset in [0, 1, 7] {
                let before: Vec<_> = (0..length + offset)
                    .map(|index| (index as u8).wrapping_mul(37))
                    .collect();
                for density in 0..3 {
                    let input: Vec<_> = (0..length + offset)
                        .map(|index| match density {
                            0 => 0,
                            1 if index % 32 < 24 => 0,
                            _ => ((index % 255) + 1) as u8,
                        })
                        .collect();
                    check_scaled(factor, &input[offset..], &before[offset..]);
                }
            }
        }
    }
    // Adjacent zero/high-bit bytes must not borrow/carry into another byte's
    // nonzero count, including the factor-one whole-word XOR path.
    for pair in 0..=u16::MAX {
        let bytes = pair.to_ne_bytes();
        let word = [
            bytes[0], bytes[1], bytes[0], bytes[1], bytes[0], bytes[1], bytes[0], bytes[1],
        ];
        assert_eq!(
            nonzero_bytes(u64::from_ne_bytes(word)),
            word.iter().filter(|value| **value != 0).count()
        );
    }
}

// These arms retain the independent bytewise algebra and its work debits.
// Scan deliberately recounts all coefficients without reading the cache, then
// charges the new one-row visit. Known still multiplies the complete validated
// vector, including its zero suffix, but charges only the effective extent.
// These intentionally reduced costs are separate from byte-exact algebra; all
// other phase debits and transaction publication remain unchanged.
fn bytewise_advance(
    d: &mut Decoder,
    job: &mut Job,
    budget: &mut WorkBudget,
    now: Tick,
) -> Result<Action, Error> {
    let w = d.config.window;
    let width = d.width;
    match job.phase {
        Phase::Reduce(id) => {
            if id >= d.shadow.observed {
                job.phase = Phase::Pivot(job.input.start().max(d.live.prefix));
            } else {
                let factor = d.candidate[id as usize % w];
                if factor != 0
                    && let Some(row) = d.map_at(id as usize % w)?
                {
                    if d.pivot_at(row)? != Some(id) {
                        return Err(Error::Identity);
                    }
                    job.phase = Phase::Eliminate {
                        row,
                        factor,
                        index: 0,
                        next: id + 1,
                    };
                    return Ok(Action::Continue);
                }
                job.phase = Phase::Reduce(id + 1);
            }
        }
        Phase::Pivot(id) => {
            if id >= d.shadow.observed {
                job.phase = Phase::Zero(0);
            } else {
                let value = d.candidate[id as usize % w];
                if value == 0 {
                    job.phase = Phase::Pivot(id + 1);
                } else {
                    job.phase = Phase::Invert {
                        pivot: id,
                        result: 1,
                        base: value,
                        exponent: 254,
                    };
                }
            }
        }
        Phase::Known {
            source,
            factor,
            column,
            extent,
        } => {
            if column == extent {
                // Independent full-width algebra: a bad extent or nonzero
                // suffix would make this oracle differ from the optimized row.
                let start = d.known(source)?.ok_or(Error::Identity)?;
                for tail in extent..width {
                    d.candidate[w + tail] ^= field::multiply(factor, d.known_data[start + tail]);
                }
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
                    extent,
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
        Phase::OtherEliminate {
            pivot,
            row,
            factor,
            index,
        } => {
            if index == w + width {
                job.phase = Phase::Others {
                    pivot,
                    row: row + 1,
                };
            } else {
                if !spend(&mut budget.field) {
                    return Ok(Action::Paused);
                }
                let old = d.row_byte(row, index)?;
                let value = old ^ field::multiply(factor, d.candidate[index]);
                let bank = d.row_bank(row, d.active)?;
                let at = d.row_start(row) + index;
                d.data[bank][at] = value;
                if index < w {
                    d.rows[row].nonzero[bank] = d.rows[row].nonzero[bank]
                        .checked_sub(usize::from(old != 0))
                        .ok_or(Error::Identity)?
                        + usize::from(value != 0);
                }
                job.phase = Phase::OtherEliminate {
                    pivot,
                    row,
                    factor,
                    index: index + 1,
                };
            }
        }
        Phase::Insert { pivot, row, index } => {
            if index == w + width {
                let bank = d.row_bank(row, d.active)?;
                d.rows[row].nonzero[bank] = job.candidate_nonzero;
                d.set_pivot(row, Some(pivot))?;
                d.set_map(pivot as usize % w, Some(row))?;
                d.shadow.rank += 1;
                job.phase = Phase::Scan { row: 0 };
            } else {
                if !spend(&mut budget.copies) {
                    return Ok(Action::Paused);
                }
                let value = d.candidate[index];
                let bank = d.row_bank(row, d.active)?;
                let at = d.row_start(row) + index;
                d.data[bank][at] = value;
                job.phase = Phase::Insert {
                    pivot,
                    row,
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
                job.candidate_nonzero = count;
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
        Phase::Scan { row } => {
            if row >= d.shadow.row_end {
                job.phase = Phase::Advance;
            } else if let Some(pivot) = d.pivot_at(row)? {
                let mut count = 0;
                for index in 0..w {
                    count += usize::from(d.row_byte(row, index)? != 0);
                }
                job.phase = if count == 1 {
                    Phase::Validate {
                        row: Some(row),
                        id: pivot,
                        index: 0,
                        length: 0,
                    }
                } else {
                    Phase::Scan { row: row + 1 }
                };
            } else {
                job.phase = Phase::Scan { row: row + 1 };
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
fn assert_row_counts(d: &Decoder) -> Result<(), Error> {
    for row in 0..d.config.max_rows {
        for active in [None, d.active] {
            if d.pivots[row].get(&d.decisions, active)?.is_none() {
                continue;
            }
            // Deliberately malformed private-state fixtures separately verify
            // the missing-bank error. There is no row to recount in that case.
            let Some(bank) = d.rows[row].selected(&d.decisions, active)? else {
                continue;
            };
            let partial = d.job.as_ref().is_some_and(|job| match job.phase {
                Phase::CopyRow {
                    row: copying, to, ..
                } => copying == row && to == bank,
                Phase::Insert { row: inserting, .. } => {
                    inserting == row && d.row_bank(row, d.active).ok() == Some(bank)
                }
                _ => false,
            });
            if !partial {
                let start = d.row_start(row);
                let actual = d.data[bank][start..start + d.config.window]
                    .iter()
                    .filter(|value| **value != 0)
                    .count();
                assert_eq!(d.rows[row].nonzero[bank], actual);
            }
        }
    }
    Ok(())
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
        a.job.as_ref().map(|job| job.candidate_nonzero),
        b.job.as_ref().map(|job| job.candidate_nonzero)
    );
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
        assert_eq!(x.nonzero, y.nonzero);
        assert_eq!(
            x.selected(&a.decisions, a.active)?,
            y.selected(&b.decisions, b.active)?
        );
        assert_eq!(
            x.selected(&a.decisions, None)?,
            y.selected(&b.decisions, None)?
        );
    }
    assert_row_counts(a)?;
    assert_row_counts(b)?;
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

#[test]
fn row_counts_large_window_preserve_global_recovery_against_full_coefficient_census()
-> Result<(), Error> {
    let c = Config {
        window: 8192,
        handoff_sources: 8192,
        memory_bytes: 64 << 20,
        ..config()
    };
    let mut a = Decoder::new(c, scope(), Tick(0))?;
    let mut b = Decoder::new(c, scope(), Tick(0))?;
    let storage = a.storage_usage();
    assert_eq!(storage, Decoder::requested_storage(c));
    for d in [&mut a, &mut b] {
        stage(d, 2, &E4_R2)?;
    }
    assert!(matches!(
        finish_pair(&mut a, &mut b)?,
        DecodeStep::Accepted { .. }
    ));
    for d in [&mut a, &mut b] {
        stage(d, 1, &E4_R1)?;
    }
    assert!(matches!(
        finish_pair(&mut a, &mut b)?,
        DecodeStep::Accepted { .. }
    ));
    for id in [0, 2] {
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
    }
    assert_eq!(a.status().decoded_prefix, 4);
    for (id, original) in ORIGINALS.into_iter().enumerate() {
        assert_eq!(a.pending_source(), Some((SourceId(id as u32), original)));
        a.confirm_handoff(SourceId(id as u32), Tick(0))?;
        b.confirm_handoff(SourceId(id as u32), Tick(0))?;
        assert_same(&a, &b)?;
    }
    assert_eq!(a.storage_usage(), storage);
    Ok(())
}

fn phase_kind(phase: Phase) -> u8 {
    match phase {
        Phase::Known { .. } => 1,
        Phase::Eliminate { .. } => 2,
        Phase::Normalize { .. } => 3,
        Phase::CandidateCount { .. } => 4,
        Phase::Scan { .. } => 5,
        Phase::OtherEliminate { .. } => 6,
        Phase::Insert { .. } => 7,
        Phase::Reduce(_) => 8,
        Phase::Pivot(_) => 9,
        _ => 0,
    }
}

#[test]
fn zero_runs_match_scalar_at_ring_wrap_source_limit_and_first_nonzero() -> Result<(), Error> {
    for start in [0, 1, 3, u32::MAX - 3] {
        for coefficients in [[0, 0, 0, 0], [0, 0, 7, 0]] {
            for phase in [Phase::Reduce(start), Phase::Pivot(start)] {
                for metadata in [0, 1, 2, 3, 4, 9, MAX_STEP_WORK] {
                    let mut a = phase_owner(phase, 0)?;
                    let mut b = phase_owner(phase, 0)?;
                    for d in [&mut a, &mut b] {
                        d.live.prefix = start;
                        d.shadow.prefix = start;
                        d.candidate[..4].copy_from_slice(&coefficients);
                        let ticket = d.active.ok_or(Error::Identity)?;
                        for column in &mut d.map {
                            column.set(&mut d.decisions, ticket, None)?;
                        }
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
    Ok(())
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
        d.rows[0].nonzero[to] = d.rows[0].nonzero[from];
    }
    assert_eq!(d.row_bank(0, d.active)?, bank);
    d.candidate.fill(0xa5);
    if let Phase::Insert { row, index, .. } = phase {
        let start = d.row_start(row);
        d.data[bank][start..start + index].copy_from_slice(&d.candidate[..index]);
    }
    let job = d.job.as_mut().ok_or(Error::Identity)?;
    job.candidate_nonzero = d.config.window;
    job.phase = phase;
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
                            ORIGINALS[0].len() + 1
                        } else {
                            index.min(ORIGINALS[0].len() + 2)
                        },
                        extent: ORIGINALS[0].len() + 2,
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
                    Phase::OtherEliminate {
                        pivot: 0,
                        row: 0,
                        factor: 113,
                        index,
                    },
                    Phase::Insert {
                        pivot: 0,
                        row: 0,
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
            extent: ORIGINALS[1].len() + 2,
        },
        Phase::Eliminate {
            row: 0,
            factor: 235,
            index: 0,
            next: 1,
        },
        Phase::OtherEliminate {
            pivot: 0,
            row: 0,
            factor: 235,
            index: 0,
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
fn row_insert_batch_missing_bank_preserves_first_copy_debit() -> Result<(), Error> {
    for copies in [0, 1, 8] {
        let phase = Phase::Insert {
            pivot: 0,
            row: 0,
            index: 0,
        };
        let mut a = Decoder::new(config(), scope(), Tick(0))?;
        let mut b = Decoder::new(config(), scope(), Tick(0))?;
        for d in [&mut a, &mut b] {
            d.begin_source(scope(), SourceId(0), ORIGINALS[0], Tick(0))?;
            d.job.as_mut().ok_or(Error::Identity)?.phase = phase;
        }
        let mut ja = a.job.take().ok_or(Error::Identity)?;
        let mut jb = b.job.take().ok_or(Error::Identity)?;
        let mut qa = budget(8, copies, 7);
        let mut qb = qa;
        let ra = a.advance(&mut ja, &mut qa, Tick(0));
        let rb = bytewise_advance(&mut b, &mut jb, &mut qb, Tick(0));
        if copies == 0 {
            assert!(matches!(ra, Ok(Action::Paused)));
        } else {
            assert!(matches!(ra, Err(Error::Identity)));
        }
        assert_eq!(
            ra.map(|value| std::mem::discriminant(&value)),
            rb.map(|value| std::mem::discriminant(&value))
        );
        assert_eq!(qa, qb);
        assert_eq!(qa.copies, copies.saturating_sub(1));
        assert_eq!(qa.metadata, 7);
        a.job = Some(ja);
        b.job = Some(jb);
        assert_same(&a, &b)?;
    }
    Ok(())
}

#[test]
fn other_eliminate_batch_partial_transaction_keeps_original_expiry_and_live_row()
-> Result<(), Error> {
    let mut a = Decoder::new(config(), scope(), Tick(0))?;
    let mut b = Decoder::new(config(), scope(), Tick(0))?;
    for d in [&mut a, &mut b] {
        stage(d, 2, &E4_R2)?;
    }
    assert!(matches!(
        finish_pair(&mut a, &mut b)?,
        DecodeStep::Accepted { .. }
    ));
    let committed = committed_rows(&a)?;
    for d in [&mut a, &mut b] {
        stage(d, 1, &E4_R1)?;
    }
    for _ in 0..10_000 {
        if matches!(
            a.job.as_ref().ok_or(Error::Identity)?.phase,
            Phase::OtherEliminate { index: 0, .. }
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
    let Phase::OtherEliminate { row, index: 0, .. } = a.job.as_ref().ok_or(Error::Identity)?.phase
    else {
        return Err(Error::Identity);
    };
    // The actual repair copied the committed row before reaching this phase.
    assert_ne!(
        a.rows[row].selected(&a.decisions, a.active)?,
        a.rows[row].selected(&a.decisions, None)?
    );
    let quota = budget(2, 0, 2);
    assert_eq!(
        a.step(Tick(99), quota)?,
        bytewise_step(&mut b, Tick(99), quota)?
    );
    assert!(matches!(
        a.job.as_ref().ok_or(Error::Identity)?.phase,
        Phase::OtherEliminate { index: 2, .. }
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
    Ok(())
}

#[test]
fn candidate_count_tiny_budgets_and_transition_visits_match_scalar() -> Result<(), Error> {
    let w = config().window;
    for bank in [0, 1] {
        for index in [0, 1, w - 1, w] {
            for count in [0, 1, 3] {
                for metadata in [0, 1, 2, w - index, w - index + 1, MAX_STEP_WORK] {
                    let phase = Phase::CandidateCount {
                        pivot: 0,
                        index,
                        count,
                    };
                    let mut a = phase_owner(phase, bank)?;
                    let mut b = phase_owner(phase, bank)?;
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
    Ok(())
}

#[test]
fn candidate_count_keeps_separate_end_transition_visit() -> Result<(), Error> {
    let w = config().window;
    let phase = Phase::CandidateCount {
        pivot: 0,
        index: w - 1,
        count: 0,
    };
    let mut d = phase_owner(phase, 1)?;
    let mut job = d.job.take().ok_or(Error::Identity)?;
    let mut quota = budget(0, 0, 9);
    assert!(matches!(
        d.advance(&mut job, &mut quota, Tick(0))?,
        Action::Continue
    ));
    assert_eq!(quota.metadata, 9); // The outer step already paid this byte.
    assert!(matches!(job.phase, Phase::CandidateCount { index, .. } if index == w));
    assert!(spend(&mut quota.metadata));
    assert!(matches!(
        d.advance(&mut job, &mut quota, Tick(0))?,
        Action::Continue
    ));
    assert_eq!(quota.metadata, 8);
    Ok(())
}

#[test]
fn cached_scan_single_visit_matches_full_census_in_both_transaction_banks() -> Result<(), Error> {
    for bank in [0, 1] {
        for count in [0, 1, 2, config().window] {
            let mut a = phase_owner(Phase::Scan { row: 0 }, bank)?;
            let mut b = phase_owner(Phase::Scan { row: 0 }, bank)?;
            for d in [&mut a, &mut b] {
                // Private row fixtures must initialize the complete authoritative
                // pair. The independent oracle reads only the coefficient bytes.
                let at = d.row_start(0);
                d.data[bank][at..at + d.config.window].fill(0);
                d.data[bank][at..at + count].fill(1);
                d.rows[0].nonzero[bank] = count;
            }
            for quota in [budget(0, 0, 0), budget(0, 0, 1)] {
                assert_eq!(
                    a.step(Tick(0), quota)?,
                    bytewise_step(&mut b, Tick(0), quota)?
                );
                assert_same(&a, &b)?;
            }
            let phase = a.job.as_ref().ok_or(Error::Identity)?.phase;
            if count == 1 {
                assert!(matches!(
                    phase,
                    Phase::Validate {
                        row: Some(0),
                        index: 0,
                        ..
                    }
                ));
            } else {
                assert_eq!(phase, Phase::Scan { row: 1 });
            }
        }
    }
    Ok(())
}

#[test]
fn cached_scan_transaction_keeps_original_expiry_and_committed_rows() -> Result<(), Error> {
    let mut a = Decoder::new(config(), scope(), Tick(0))?;
    let mut b = Decoder::new(config(), scope(), Tick(0))?;
    for d in [&mut a, &mut b] {
        stage(d, 1, &E4_R1)?;
    }
    for _ in 0..1_000 {
        if matches!(
            a.job.as_ref().ok_or(Error::Identity)?.phase,
            Phase::Scan { row: 0 }
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
    assert_eq!(
        a.job.as_ref().ok_or(Error::Identity)?.phase,
        Phase::Scan { row: 0 }
    );
    let committed = committed_rows(&a)?;
    let quota = budget(0, 0, 1);
    assert_eq!(
        a.step(Tick(99), quota)?,
        bytewise_step(&mut b, Tick(99), quota)?
    );
    assert_eq!(
        a.job.as_ref().ok_or(Error::Identity)?.phase,
        Phase::Scan { row: 1 }
    );
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
fn cached_scan_missing_bank_keeps_validation_and_metadata_debit() -> Result<(), Error> {
    for metadata in [0, 1, 8] {
        let phase = Phase::Scan { row: 0 };
        let mut a = Decoder::new(config(), scope(), Tick(0))?;
        let mut b = Decoder::new(config(), scope(), Tick(0))?;
        for d in [&mut a, &mut b] {
            d.begin_source(scope(), SourceId(0), ORIGINALS[0], Tick(0))?;
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
fn cached_scan_rejects_impossible_count_without_advancing_the_row() -> Result<(), Error> {
    let mut d = phase_owner(Phase::Scan { row: 0 }, 1)?;
    let bank = d.row_bank(0, d.active)?;
    d.rows[0].nonzero[bank] = d.config.window + 1;
    assert_eq!(d.step(Tick(0), budget(0, 0, 1)), Err(Error::Identity));
    assert_eq!(
        d.job.as_ref().ok_or(Error::Identity)?.phase,
        Phase::Scan { row: 0 }
    );
    Ok(())
}

#[test]
fn cached_scan_8192_columns_2048_rows_charge_visits_within_original_turn_budget()
-> Result<(), Error> {
    let c = Config {
        window: 8192,
        max_rows: 2048,
        handoff_sources: 8192,
        memory_bytes: 64 << 20,
        ..config()
    };
    let mut d = Decoder::new(c, scope(), Tick(0))?;
    let storage = d.storage_usage();
    stage(&mut d, 1, &E4_R1)?;
    let ticket = d.active.ok_or(Error::Identity)?;
    for row in 0..c.max_rows {
        let (bank, old) = d.rows[row].prepare(&mut d.decisions, ticket)?;
        assert!(old.is_none());
        let start = d.row_start(row);
        d.data[bank][start + row] = 1;
        d.data[bank][start + row + 1] = 1;
        d.rows[row].nonzero[bank] = 2;
        d.set_pivot(row, Some(row as u32))?;
        d.set_map(row, Some(row))?;
    }
    d.shadow.rank = c.max_rows;
    d.job.as_mut().ok_or(Error::Identity)?.phase = Phase::Scan { row: 0 };
    assert_row_counts(&d)?;
    let started = std::time::Instant::now();
    let actual = d.step(Tick(99), budget(0, 0, c.max_rows + 1))?;
    let elapsed = started.elapsed();
    assert_eq!(
        actual,
        DecodeStep::Pending(WorkUsed {
            field: 0,
            copies: 0,
            metadata: 2049
        })
    );
    assert_eq!(d.job.as_ref().ok_or(Error::Identity)?.phase, Phase::Advance);
    assert_eq!(d.job.as_ref().ok_or(Error::Identity)?.deadline, Tick(100));
    assert_eq!(d.storage_usage(), storage);
    let former_metadata = c.max_rows * (c.window + 1) + 1;
    assert_eq!(former_metadata, 16_779_265);
    assert_eq!(former_metadata.div_ceil(MAX_STEP_WORK), 257);
    assert!(c.max_rows + 1 < MAX_STEP_WORK);
    eprintln!(
        "cached Scan 8192 columns/2048 occupied rows: metadata=2049 former_metadata={former_metadata} local_step_wall_ns={}",
        elapsed.as_nanos()
    );
    // The fast census did not publish its private rows or renew the job cap.
    assert_eq!(d.status().rank, 0);
    assert_eq!(d.step(Tick(100), full()), Err(Error::Expired));
    assert_eq!(d.status().rank, 0);
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

#[test]
fn known_validated_extent_matches_full_width_algebra_and_skips_only_zero_suffix()
-> Result<(), Error> {
    let c = Config {
        max_payload: 1288,
        ..config()
    };
    for length in [1, 3, 64, c.max_payload] {
        for pattern in [0, 1, 2] {
            let mut original = vec![0; length];
            for (index, byte) in original.iter_mut().enumerate() {
                *byte = match pattern {
                    0 => 0,
                    1 => {
                        if index % 3 == 0 {
                            0xa5
                        } else {
                            0
                        }
                    }
                    _ => 1 + (index % 255) as u8,
                };
            }
            // A meaningful zero tail stays inside the original encoded length.
            original[length - 1] = 0;
            let mut d = Decoder::new(c, scope(), Tick(0))?;
            assert_eq!(
                d.begin_source(scope(), SourceId(0), &original, Tick(0))?,
                Begin::Staged
            );
            finish(&mut d)?;
            let storage = d.storage_usage();
            let support = c.support(4, RepairId(2), false)?;
            let mut repair = vec![0; c.width()?];
            for (id, bytes) in [&original[..], ORIGINALS[1], ORIGINALS[2], ORIGINALS[3]]
                .into_iter()
                .enumerate()
            {
                let mut vector = vec![0; c.width()?];
                vector[..2].copy_from_slice(&(bytes.len() as u16).to_be_bytes());
                vector[2..2 + bytes.len()].copy_from_slice(bytes);
                let factor = field::compact_coefficient(support.seed, id as u32);
                for (out, value) in repair.iter_mut().zip(vector) {
                    *out ^= field::multiply(factor, value);
                }
            }
            stage(&mut d, 2, &repair)?;
            // Real Support resolves the committed known vector and its validated
            // prefix. No direct phase or known-byte mutation constructs the extent.
            assert!(matches!(
                d.step(Tick(0), budget(0, MAX_STEP_WORK, MAX_STEP_WORK))?,
                DecodeStep::Pending(_)
            ));
            assert!(
                matches!(
                    d.job.as_ref().ok_or(Error::Identity)?.phase,
                    Phase::Known {
                        source: 0,
                        column: 0,
                        ..
                    }
                ),
                "actual phase {:?}",
                d.job.as_ref().map(|job| job.phase)
            );
            let Phase::Known {
                source: 0,
                factor,
                column: 0,
                extent,
            } = d.job.as_ref().ok_or(Error::Identity)?.phase
            else {
                return Err(Error::Identity);
            };
            assert_eq!(extent, length + 2);
            let start = d.known(0)?.ok_or(Error::Identity)?;
            let mut expected = d.candidate.clone();
            for column in 0..d.width {
                expected[c.window + column] ^=
                    field::multiply(factor, d.known_data[start + column]);
            }
            assert_eq!(
                phase_prefix(&mut d, budget(0, 0, 0), false)?,
                WorkUsed::default()
            );
            let used = phase_prefix(&mut d, full(), false)?;
            assert_eq!(
                used,
                WorkUsed {
                    field: extent,
                    copies: 0,
                    metadata: extent + 1
                }
            );
            assert_eq!(d.candidate, expected);
            assert_eq!(
                d.job.as_ref().ok_or(Error::Identity)?.phase,
                Phase::Support(1)
            );
            assert_eq!(d.job.as_ref().ok_or(Error::Identity)?.deadline, Tick(100));
            assert_eq!(d.storage_usage(), storage);
        }
    }
    Ok(())
}
