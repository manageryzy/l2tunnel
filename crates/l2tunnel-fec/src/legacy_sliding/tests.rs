#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use super::*;

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn scope() -> Scope {
    Scope {
        session: [0x51; 16],
        epoch: 4,
        stream: 3,
        direction: 1,
    }
}
fn config() -> Config {
    Config {
        recovery: rolling::Config {
            window: 16,
            local_window: 4,
            global_every: 16,
            max_payload: 11,
            max_rows: 8,
            repair_history: 16,
            handoff_sources: 1,
            job_ticks: 10_000,
            debt_ticks: 100_000,
            handoff_ticks: 10_000,
            memory_bytes: 16 * 1024 * 1024,
        },
        mode: Mode::Sliding,
        long_window: 5,
        short_window: 2,
        long_every: 3,
        repair_every: 3,
        repairs_per_group: 2,
        interleave_repairs: false,
        feedback_repair: false,
        cumulative_feedback: false,
        feedback_batch: 8,
        fec_wait_ticks: 5000,
        repair_spacing_ticks: 0,
        feedback_wait_ticks: 200,
        rto_min_ticks: 1000,
        rto_factor_numerator: 5,
        rto_factor_denominator: 2,
        repair_queue: 16,
        max_attempts: 8,
        feedback_payload_budget: 1412,
        max_record_bytes: 2048,
        memory_bytes: 16 * 1024 * 1024,
    }
}
fn budget(value: usize) -> WorkBudget {
    WorkBudget {
        field: value,
        copies: value,
        metadata: value,
    }
}
fn payload(source: u32) -> Vec<u8> {
    let mut body: Vec<_> = (0..1 + source % 11)
        .map(|offset| (source * 37 + offset * 53) as u8)
        .collect();
    if source.is_multiple_of(3) {
        *body.last_mut().unwrap() = 0;
    }
    body
}
fn hex(value: &str) -> Result<Vec<u8>, std::num::ParseIntError> {
    (0..value.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&value[at..at + 2], 16))
        .collect()
}
fn source_wire(config: Config, source: u32) -> Vec<u8> {
    let mut bytes = vec![0; config.max_record_bytes];
    let length = wire::encode_source(
        config,
        scope(),
        SourceId(source),
        &payload(source),
        &mut bytes,
    )
    .unwrap();
    bytes.truncate(length);
    bytes
}
fn finish(receiver: &mut Receiver, now: Tick) -> Result<(), Error> {
    for _ in 0..10_000 {
        let result = receiver.step(now, budget(64))?;
        assert!(result.work.field <= 64 && result.work.copies <= 64 && result.work.metadata <= 64);
        if matches!(result.decode, DecodeStep::Capacity(_)) {
            return Err(Error::Capacity);
        }
        let status = receiver.status();
        if !status.decoder.pending_job && !status.scanning {
            return Ok(());
        }
    }
    Err(Error::WorkLimit)
}
fn repair_wire(config: Config, terms: &[Term], feedback: bool) -> Result<Vec<u8>, Error> {
    let mut encoder = rolling::Encoder::new_explicit(config.recovery, scope(), Tick(0))?;
    for source in 0..=terms.last().ok_or(Error::Identity)?.source.0 {
        encoder.admit_source(&payload(source), Tick(0))?;
    }
    encoder.begin_explicit(terms, feedback, Tick(0), Tick(0), Tick(9999))?;
    for _ in 0..10_000 {
        encoder.step(Tick(0), budget(64))?;
        if let Some(equation) = encoder.pending_repair() {
            let repair = Repair {
                equation,
                terms,
                feedback_triggered: feedback,
            };
            let mut bytes = vec![0; repair.charge(0)?];
            wire::encode_repair(config, repair, &mut bytes)?;
            return Ok(bytes);
        }
    }
    Err(Error::WorkLimit)
}

#[test]
fn legacy_actual_python_payload_vectors_recover_missing_original_without_sender() -> TestResult {
    let mut checked = 0;
    for line in include_str!("../../tests/fixtures/legacy-sliding-policy.txt").lines() {
        let fields: Vec<_> = line.split_ascii_whitespace().collect();
        if fields.first() != Some(&"q") {
            continue;
        }
        let ids: Vec<u32> = fields[5]
            .split(',')
            .map(str::parse)
            .collect::<Result<_, _>>()?;
        let coefficients = hex(fields[6])?;
        let terms: Vec<_> = ids
            .iter()
            .zip(&coefficients)
            .map(|(&id, &coefficient)| Term {
                source: SourceId(id),
                coefficient,
            })
            .collect();
        let c = Config {
            mode: if fields[1] == "hybrid" {
                Mode::Hybrid
            } else {
                Mode::Sliding
            },
            ..config()
        };
        let packet = repair_wire(c, &terms, fields[4] == "1")?;
        let actual = &packet[wire::HEADER_BYTES + 5 * terms.len()..];
        let extent = 2 + ids
            .iter()
            .map(|id| payload(*id).len())
            .max()
            .ok_or(Error::Identity)?;
        assert_eq!(actual.len(), extent);
        let mut expanded = actual.to_vec();
        expanded.resize(c.recovery.width()?, 0);
        assert_eq!(expanded, hex(fields[7])?, "{line}");
        // The encoder is already dropped; the receiver gets only actual records.
        let plan = storage::Plan::for_receiver(c)?;
        let mut receiver = Receiver::new_reserved(
            c,
            scope(),
            Tick(0),
            storage::Limits {
                capacity_bytes: plan.capacity_bytes(),
            },
        )?;
        let usage = receiver.storage_usage()?;
        let missing = ids[0];
        let end = ids.last().copied().ok_or(Error::Identity)? + 1;
        for source in (0..end).rev().filter(|source| *source != missing) {
            assert_eq!(
                receiver.receive_wire(&source_wire(c, source), Tick(0))?,
                Begin::Staged
            );
            finish(&mut receiver, Tick(0))?;
        }
        assert_eq!(receiver.receive_wire(&packet, Tick(0))?, Begin::Staged);
        finish(&mut receiver, Tick(0))?;
        assert_eq!(receiver.status().receipt_prefix, end, "{line}");
        for source in 0..end {
            assert_eq!(
                receiver.pending_source(),
                Some((SourceId(source), payload(source).as_slice())),
                "{line}"
            );
            receiver.confirm_handoff(SourceId(source), Tick(0))?;
        }
        finish(&mut receiver, Tick(200))?;
        let feedback = receiver.pending_feedback().ok_or(Error::Identity)?;
        assert_eq!(feedback.ids.len(), end as usize);
        receiver.confirm_feedback(feedback.id, Tick(200))?;
        assert_eq!(receiver.receive_wire(&packet, Tick(201))?, Begin::Duplicate);
        finish(&mut receiver, Tick(401))?;
        assert!(
            receiver.pending_feedback().is_none(),
            "duplicate repair re-acked: {line}"
        );
        assert_eq!(receiver.storage_usage()?, usage);
        checked += 1;
    }
    assert_eq!(checked, 16);
    Ok(())
}

#[test]
fn legacy_selective_cumulative_feedback_retains_reverse_custody_and_reacks_source() -> TestResult {
    for cumulative in [false, true] {
        let c = Config {
            cumulative_feedback: cumulative,
            feedback_batch: 2,
            feedback_wait_ticks: 20,
            ..config()
        };
        let mut receiver = Receiver::new(c, scope(), Tick(0))?;
        for source in [0, 2] {
            receiver.receive_wire(&source_wire(c, source), Tick(0))?;
            finish(&mut receiver, Tick(0))?;
        }
        let old = receiver.pending_feedback().ok_or(Error::Identity)?;
        assert_eq!(old.prefix, cumulative.then_some(1));
        assert_eq!(
            old.ids,
            if cumulative {
                &[SourceId(2)][..]
            } else {
                &[SourceId(0), SourceId(2)][..]
            }
        );
        let old_id = old.id;
        let charge = old.charge(17)?;
        let mut old_bytes = vec![0; charge - 17];
        assert_eq!(receiver.encode_feedback(&mut old_bytes)?, old_bytes.len());
        receiver.receive_wire(&source_wire(c, 1), Tick(1))?;
        finish(&mut receiver, Tick(1))?;
        assert_eq!(receiver.status().receipt_prefix, 3);
        assert_eq!(receiver.status().decoder.decoded_prefix, 1);
        let mut again = vec![0; old_bytes.len()];
        receiver.encode_feedback(&mut again)?;
        assert_eq!(
            again, old_bytes,
            "held reverse bytes changed after later receipt"
        );
        assert_eq!(
            receiver.pending_feedback().ok_or(Error::Identity)?.id,
            old_id
        );
        assert_eq!(
            receiver.confirm_feedback(FeedbackId(old_id.0 + 99), Tick(1)),
            Err(Error::Identity)
        );
        receiver.confirm_feedback(old_id, Tick(1))?;
        finish(&mut receiver, Tick(21))?;
        let next = receiver.pending_feedback().ok_or(Error::Identity)?;
        assert_eq!(next.id, FeedbackId(old_id.0 + 1));
        assert_eq!(next.prefix, cumulative.then_some(3));
        assert_eq!(
            next.ids,
            if cumulative {
                &[][..]
            } else {
                &[SourceId(1)][..]
            }
        );
        receiver.confirm_feedback(next.id, Tick(21))?;
        assert_eq!(
            receiver.receive_wire(&source_wire(c, 2), Tick(22))?,
            Begin::Duplicate
        );
        finish(&mut receiver, Tick(42))?;
        let duplicate = receiver.pending_feedback().ok_or(Error::Identity)?;
        assert_eq!(duplicate.id, FeedbackId(old_id.0 + 2));
        assert_eq!(duplicate.prefix, cumulative.then_some(3));
        assert_eq!(
            duplicate.ids,
            if cumulative {
                &[][..]
            } else {
                &[SourceId(2)][..]
            }
        );
        receiver.confirm_feedback(duplicate.id, Tick(42))?;
        for source in 0..3 {
            assert_eq!(
                receiver.pending_source(),
                Some((SourceId(source), payload(source).as_slice()))
            );
            receiver.confirm_handoff(SourceId(source), Tick(42))?;
        }
    }
    Ok(())
}

#[test]
fn legacy_feedback_capacity_backpressure_preserves_original_and_snapshot() -> TestResult {
    let mut c = config();
    c.long_window = 1;
    c.short_window = 1;
    c.feedback_batch = 1;
    c.recovery.window = 1;
    c.recovery.local_window = 1;
    c.recovery.max_rows = 1;
    let mut receiver = Receiver::new(c, scope(), Tick(0))?;
    for source in 0..2 {
        receiver.receive_wire(&source_wire(c, source), Tick(u64::from(source)))?;
        finish(&mut receiver, Tick(u64::from(source)))?;
        receiver.confirm_handoff(SourceId(source), Tick(u64::from(source)))?;
    }
    assert_eq!(
        receiver.pending_feedback().ok_or(Error::Identity)?.ids,
        &[SourceId(0)]
    );
    let before = receiver.status();
    let packet = source_wire(c, 2);
    assert_eq!(
        receiver.receive_wire(&packet, Tick(2)),
        Err(Error::Capacity)
    );
    assert_eq!(receiver.status(), before);
    receiver.confirm_feedback(FeedbackId(1), Tick(2))?;
    finish(&mut receiver, Tick(2))?;
    assert_eq!(
        receiver.pending_feedback().ok_or(Error::Identity)?.ids,
        &[SourceId(1)]
    );
    receiver.confirm_feedback(FeedbackId(2), Tick(2))?;
    assert_eq!(
        receiver.receive_wire_at(&packet, Tick(2), Tick(3), Tick(100))?,
        Begin::Staged
    );
    finish(&mut receiver, Tick(3))?;
    assert_eq!(
        receiver.pending_source(),
        Some((SourceId(2), payload(2).as_slice()))
    );
    Ok(())
}

#[test]
fn legacy_wire_failures_scope_and_original_expiry_preserve_committed_state() -> TestResult {
    let c = config();
    let terms = [
        Term {
            source: SourceId(0),
            coefficient: 43,
        },
        Term {
            source: SourceId(1),
            coefficient: 195,
        },
    ];
    let packet = repair_wire(c, &terms, false)?;
    let mut terms_scratch = [terms[0]; 255];
    let mut ids = [SourceId(0); 255];
    for length in 0..wire::HEADER_BYTES + 5 * terms.len() + 3 {
        assert!(wire::inspect(c, &packet[..length], &mut terms_scratch, &mut ids).is_err());
    }
    for offset in [4, 67, wire::HEADER_BYTES + 4] {
        let mut changed = packet.clone();
        changed[offset] = if offset == wire::HEADER_BYTES + 4 {
            0
        } else {
            0xff
        };
        assert!(wire::inspect(c, &changed, &mut terms_scratch, &mut ids).is_err());
    }
    let plan = storage::Plan::for_receiver(c)?;
    assert!(matches!(
        Receiver::new_reserved(
            c,
            scope(),
            Tick(0),
            storage::Limits {
                capacity_bytes: plan.capacity_bytes() - 1
            }
        ),
        Err(storage::Error::Capacity)
    ));
    let mut receiver = Receiver::new(c, scope(), Tick(0))?;
    let before = receiver.status();
    let mut wrong_scope = packet.clone();
    wrong_scope[8] ^= 1;
    assert_eq!(
        receiver.receive_wire(&wrong_scope, Tick(10_001)),
        Err(Error::Scope)
    );
    assert_eq!(receiver.status(), before);
    receiver.receive_wire_at(&packet, Tick(0), Tick(5), Tick(6))?;
    assert_eq!(receiver.deadline(), Some(Tick(6)));
    assert_eq!(receiver.step(Tick(6), budget(1)), Err(Error::Expired));
    assert_eq!(receiver.status().decoder.rank, before.decoder.rank);
    assert_eq!(
        receiver.status().decoder.decoded_prefix,
        before.decoder.decoded_prefix
    );
    assert_eq!(
        receiver.status().decoder.observed_end,
        before.decoder.observed_end
    );
    Ok(())
}

#[test]
fn legacy_actual_python_periodic_schedule_and_acknowledged_history() -> TestResult {
    struct CapturedCoefficients {
        rows: Vec<Vec<u8>>,
        next: usize,
    }
    impl CoefficientSource for CapturedCoefficients {
        fn fill(&mut self, coefficients: &mut [u8]) -> Result<(), Error> {
            let row = self.rows.get(self.next).ok_or(Error::Identity)?;
            if row.len() != coefficients.len() {
                return Err(Error::Identity);
            }
            coefficients.copy_from_slice(row);
            self.next += 1;
            Ok(())
        }
    }
    let records: Vec<Vec<_>> = include_str!("../../tests/fixtures/legacy-sliding-policy.txt")
        .lines()
        .map(|line| line.split_ascii_whitespace().collect())
        .collect();
    let mut checked = 0;
    for case in ["ceil", "hybrid", "interleave"] {
        let profile = records
            .iter()
            .find(|row| row.first() == Some(&"p") && row[1] == case)
            .ok_or(Error::Identity)?;
        let mut c = config();
        c.mode = if profile[2] == "hybrid" {
            Mode::Hybrid
        } else {
            Mode::Sliding
        };
        c.repair_every = profile[3].parse()?;
        c.repairs_per_group = profile[4].parse()?;
        c.interleave_repairs = profile[5] == "1";
        c.short_window = profile[6].parse()?;
        c.long_window = profile[7].parse()?;
        c.long_every = profile[8].parse()?;
        c.fec_wait_ticks = profile[9].parse()?;
        c.repair_spacing_ticks = profile[10].parse()?;
        c.rto_min_ticks = profile[11].parse()?;
        c.feedback_wait_ticks = profile[12].parse()?;
        c.recovery.job_ticks = 2_000_000;
        c.recovery.debt_ticks = 10_000_000;
        c.recovery.handoff_ticks = 2_000_000;
        let mut coefficients = CapturedCoefficients {
            rows: records
                .iter()
                .filter(|row| row.first() == Some(&"q") && row[1] == case)
                .map(|row| hex(row[6]))
                .collect::<Result<_, _>>()?,
            next: 0,
        };
        let mut sender = Sender::new(c, scope(), Tick(0))?;
        let storage = sender.storage_usage()?;
        for row in records.iter().filter(|row| row.get(1) == Some(&case)) {
            match row[0] {
                "a" => {
                    let now = Tick(row[2].parse()?);
                    let source = SourceId(row[3].parse()?);
                    if case == "ceil" && source == SourceId(4) {
                        assert_eq!(
                            sender.receive_feedback(
                                Feedback {
                                    scope: scope(),
                                    id: FeedbackId(1),
                                    prefix: None,
                                    ids: &[SourceId(0), SourceId(1), SourceId(2), SourceId(3)],
                                },
                                now,
                                &mut coefficients,
                            )?,
                            FeedbackDisposition::Applied,
                        );
                        assert_eq!(sender.status().pending_sources, 0);
                    }
                    let original = hex(row[4])?;
                    assert_eq!(sender.admit_source(&original, now, now)?, source);
                    let output = sender.pending_output().ok_or(Error::Identity)?;
                    assert!(
                        matches!(output, Output::Source { id, attempt: 1, original: bytes, .. }
                        if id == source && bytes == original)
                    );
                    // Immediate custody aligns Python admission credit with this
                    // library's physical first-send credit. Packer delay is separate.
                    sender.confirm_output(output.id(), now, now, 2000, &mut coefficients)?;
                }
                "q" => {
                    let now = Tick(row[2].parse()?);
                    let serial: u64 = row[3].parse()?;
                    for _ in 0..10_000 {
                        sender.step(now, budget(64), &mut coefficients)?;
                        if sender.pending_output().is_some() {
                            break;
                        }
                    }
                    let output = sender.pending_output().ok_or(Error::WorkLimit)?;
                    let Output::Repair(repair) = output else {
                        return Err(Error::Identity.into());
                    };
                    let ids: Vec<u32> = row[5]
                        .split(',')
                        .map(str::parse)
                        .collect::<Result<_, _>>()?;
                    let values = hex(row[6])?;
                    let terms: Vec<_> = ids
                        .iter()
                        .zip(values)
                        .map(|(&id, coefficient)| Term {
                            source: SourceId(id),
                            coefficient,
                        })
                        .collect();
                    assert_eq!(repair.equation.id, RepairId(serial), "{case} at {}", now.0);
                    assert!(!repair.feedback_triggered);
                    assert_eq!(repair.terms, terms, "{case} repair {serial}");
                    let extent = 2 + ids
                        .iter()
                        .map(|id| payload(*id).len())
                        .max()
                        .ok_or(Error::Identity)?;
                    assert_eq!(repair.equation.bytes.len(), extent);
                    let mut expanded = repair.equation.bytes.to_vec();
                    expanded.resize(c.recovery.width()?, 0);
                    assert_eq!(expanded, hex(row[7])?, "{case} repair {serial}");
                    let generated = records
                        .iter()
                        .filter(|other| {
                            other.first() == Some(&"q") && other[1] == case && other[2] == row[2]
                        })
                        .map(|other| other[3].parse::<u64>())
                        .collect::<Result<Vec<_>, _>>()?
                        .into_iter()
                        .max()
                        .ok_or(Error::Identity)?;
                    assert_eq!(sender.status().periodic_repairs, generated);
                    sender.confirm_output(output.id(), now, now, 2000, &mut coefficients)?;
                    checked += 1;
                }
                "z" => {
                    let status = sender.status();
                    assert_eq!(
                        status.fec_count,
                        row[4].parse::<u32>()?,
                        "{case} {}",
                        row[2]
                    );
                    assert_eq!(
                        status.repair_credit,
                        row[5].parse::<u32>()?,
                        "{case} {}",
                        row[2]
                    );
                    assert_eq!(
                        status.periodic_repairs,
                        row[7].parse::<u64>()?,
                        "{case} {}",
                        row[2]
                    );
                    assert_eq!(status.queued_repairs, 0);
                    assert!(!status.output_ready);
                }
                _ => {}
            }
        }
        assert_eq!(coefficients.next, coefficients.rows.len());
        assert_eq!(sender.storage_usage()?, storage);
    }
    assert_eq!(checked, 13);
    Ok(())
}

#[test]
fn previous_full_width_legacy_wire_version_is_refused() -> TestResult {
    let c = config();
    let mut bytes = source_wire(c, 0);
    bytes[4] = 1;
    let mut terms = [Term {
        source: SourceId(0),
        coefficient: 1,
    }; 255];
    let mut ids = [SourceId(0); 255];
    assert!(matches!(
        wire::inspect(c, &bytes, &mut terms, &mut ids),
        Err(Error::Format)
    ));
    Ok(())
}
