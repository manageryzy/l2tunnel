use super::*;

type TestResult = Result<(), Box<dyn std::error::Error>>;

struct Coefficients(u8);
impl CoefficientSource for Coefficients {
    fn fill(&mut self, bytes: &mut [u8]) -> Result<(), Error> {
        for byte in bytes {
            self.0 = self.0.wrapping_add(1).max(1);
            *byte = self.0;
        }
        Ok(())
    }
}
fn config() -> Config {
    Config {
        recovery: rolling::Config {
            window: 16,
            local_window: 2,
            global_every: 16,
            max_payload: 11,
            max_rows: 16,
            repair_history: 32,
            handoff_sources: 16,
            job_ticks: 20_000,
            debt_ticks: 100_000,
            handoff_ticks: 50_000,
            memory_bytes: 1 << 20,
        },
        mode: Mode::Hybrid,
        long_window: 5,
        short_window: 1,
        long_every: 10,
        repair_every: 5,
        repairs_per_group: 1,
        interleave_repairs: false,
        feedback_repair: true,
        cumulative_feedback: false,
        feedback_batch: 16,
        fec_wait_ticks: 10_000,
        repair_spacing_ticks: 6000,
        feedback_wait_ticks: 200,
        rto_min_ticks: 1000,
        rto_factor_numerator: 5,
        rto_factor_denominator: 2,
        repair_queue: 16,
        max_attempts: 16,
        feedback_payload_budget: 512,
        max_record_bytes: 512,
        memory_bytes: 1 << 20,
    }
}
fn scope() -> Scope {
    Scope {
        session: [0x28; 16],
        epoch: 3,
        stream: 4,
        direction: 1,
    }
}
fn source(
    sender: &mut Sender,
    id: u32,
    now: u64,
    rtt: u64,
    random: &mut Coefficients,
) -> Result<(), Error> {
    assert_eq!(
        sender.admit_source(&[id as u8, 0], Tick(now), Tick(now))?,
        SourceId(id)
    );
    sender.confirm_output(
        OutputId::Source {
            source: SourceId(id),
            attempt: 1,
        },
        Tick(now),
        Tick(now),
        rtt,
        random,
    )
}
fn finish(sender: &mut Sender, now: u64, random: &mut Coefficients) -> Result<(), Error> {
    for _ in 0..100_000 {
        if sender.pending_output().is_some() {
            return Ok(());
        }
        let used = sender.step(
            Tick(now),
            WorkBudget {
                field: 1,
                copies: 1,
                metadata: 1,
            },
            random,
        )?;
        assert!(used.field <= 1 && used.copies <= 1 && used.metadata <= 1);
    }
    Err(Error::WorkLimit)
}

#[test]
fn feedback_m_holes_emits_m_frozen_rows_and_rearms_only_feedback_repair() -> TestResult {
    let mut sender = Sender::new(config(), scope(), Tick(0))?;
    let mut random = Coefficients(0);
    for id in 0..5 {
        source(
            &mut sender,
            id,
            (u64::from(id) + 1) * 100,
            2000,
            &mut random,
        )?;
    }
    assert_eq!(sender.status().queued_repairs, 1);
    assert_eq!(
        sender.flight(SourceId(1)).ok_or(Error::Identity)?.retry_at,
        Some(Tick(5200))
    );
    let ids = [SourceId(0), SourceId(2), SourceId(4)];
    let receipt = Feedback {
        scope: scope(),
        id: FeedbackId(1),
        prefix: None,
        ids: &ids,
    };
    assert_eq!(
        sender.receive_feedback(receipt, Tick(4000), &mut random)?,
        FeedbackDisposition::Applied
    );
    assert_eq!(sender.status().queued_repairs, 3);
    assert_eq!(sender.status().pending_sources, 2);
    for (finished, expected) in [(4100, 7300), (4200, 7300)] {
        finish(&mut sender, finished - 100, &mut random)?;
        let Some(Output::Repair(repair)) = sender.pending_output() else {
            return Err(Error::Identity.into());
        };
        assert!(repair.feedback_triggered);
        assert_eq!(
            repair
                .terms
                .iter()
                .map(|term| term.source)
                .collect::<Vec<_>>(),
            [SourceId(1), SourceId(3)]
        );
        let id = OutputId::Repair(repair.equation.id);
        let mut encoded = [0; 95];
        let count = sender.encode_pending(&mut encoded)?;
        assert_eq!(count, wire::HEADER_BYTES + 10 + 4);
        assert_eq!(sender.pending_wire_len(), Some(count));
        assert_eq!(
            sender.receive_feedback(receipt, Tick(finished), &mut random)?,
            FeedbackDisposition::Duplicate
        );
        let mut repeated = [0; 95];
        sender.encode_pending(&mut repeated)?;
        assert_eq!(encoded, repeated);
        sender.confirm_output(id, Tick(finished), Tick(finished), 2000, &mut random)?;
        for id in [SourceId(1), SourceId(3)] {
            assert_eq!(
                sender.flight(id).ok_or(Error::Identity)?.retry_at,
                Some(Tick(expected))
            );
            assert!(sender.flight(id).ok_or(Error::Identity)?.early);
        }
    }
    finish(&mut sender, 6500, &mut random)?;
    let id = sender.pending_output().ok_or(Error::Busy)?.id();
    sender.confirm_output(id, Tick(6500), Tick(6500), 2000, &mut random)?;
    // The second equation's expected receipt (6400) precedes the already
    // rearmed 7300 retry, so it must not renew that timer. Service is observed
    // 100 ticks late; the actual 7400 completion still sets RTO to 12400.
    for id in [SourceId(1), SourceId(3)] {
        finish(&mut sender, 7400, &mut random)?;
        assert_eq!(
            sender.pending_output().ok_or(Error::Busy)?.id(),
            OutputId::Source {
                source: id,
                attempt: 2
            }
        );
        sender.confirm_output(
            OutputId::Source {
                source: id,
                attempt: 2,
            },
            Tick(7400),
            Tick(7400),
            2000,
            &mut random,
        )?;
        assert_eq!(
            sender.flight(id).ok_or(Error::Identity)?.retry_at,
            Some(Tick(12_400))
        );
    }
    Ok(())
}

#[test]
fn queued_periodic_repair_never_suppresses_constant_rto_retry_or_attempt_cap() -> TestResult {
    let mut config = config();
    config.repair_every = 1;
    config.repair_spacing_ticks = 100;
    config.rto_min_ticks = 1;
    config.max_attempts = 2;
    let mut sender = Sender::new(config, scope(), Tick(0))?;
    let mut random = Coefficients(0);
    source(&mut sender, 0, 0, 10, &mut random)?;
    assert_eq!(sender.flight(SourceId(0)).ok_or(Error::Identity)?.queued, 1);
    finish(&mut sender, 25, &mut random)?;
    let output = sender.pending_output().ok_or(Error::Busy)?;
    assert_eq!(
        output.id(),
        OutputId::Source {
            source: SourceId(0),
            attempt: 2
        }
    );
    assert_eq!(output.charge(28)?, wire::HEADER_BYTES + 2 + 28);
    let current_id = output.id();
    assert_eq!(
        sender.confirm_output(
            OutputId::Source {
                source: SourceId(0),
                attempt: 1
            },
            Tick(26),
            Tick(26),
            10,
            &mut random
        ),
        Err(Error::Identity)
    );
    sender.confirm_output(current_id, Tick(26), Tick(26), 10, &mut random)?;
    assert_eq!(
        sender.flight(SourceId(0)).ok_or(Error::Identity)?.retry_at,
        Some(Tick(51))
    );
    assert_eq!(
        sender.step(
            Tick(51),
            WorkBudget {
                metadata: 1,
                ..WorkBudget::default()
            },
            &mut random
        ),
        Err(Error::Exhausted)
    );
    assert_eq!(sender.status().terminal, Some(Error::Exhausted));
    Ok(())
}

#[test]
fn first_admission_timer_and_completion_credit_survive_local_output_backpressure() -> TestResult {
    let mut config = config();
    config.interleave_repairs = true;
    config.repair_every = 8;
    config.repairs_per_group = 3;
    config.fec_wait_ticks = 10;
    config.repair_spacing_ticks = 1;
    let mut sender = Sender::new(config, scope(), Tick(0))?;
    let mut random = Coefficients(0);
    sender.admit_source(&[7, 0], Tick(0), Tick(0))?;
    assert_eq!(sender.status().repair_credit, 0);
    assert_eq!(sender.next_wakeup(), Some(Tick(10)));
    sender.step(Tick(12), WorkBudget::default(), &mut random)?;
    assert_eq!(sender.status().queued_repairs, 0);
    assert_eq!(sender.fec_due, Some(Tick(10)));
    sender.confirm_output(
        OutputId::Source {
            source: SourceId(0),
            attempt: 1,
        },
        Tick(12),
        Tick(12),
        2000,
        &mut random,
    )?;
    assert_eq!(sender.status().queued_repairs, 1);
    assert_eq!(sender.status().repair_credit, 0);
    assert_eq!(sender.status().fec_count, 0);
    assert_eq!(sender.next_wakeup(), Some(Tick(13)));
    finish(&mut sender, 13, &mut random)?;
    let id = sender.pending_output().ok_or(Error::Busy)?.id();
    sender.confirm_output(id, Tick(13), Tick(13), 2000, &mut random)?;
    for (id, time) in [(1, 14), (2, 15), (3, 16)] {
        source(&mut sender, id, time, 2000, &mut random)?;
    }
    assert_eq!(sender.status().repair_credit, 1);
    assert_eq!(sender.status().queued_repairs, 1);
    Ok(())
}

#[test]
fn acknowledged_history_stays_pinned_until_every_spaced_frozen_equation_sends() -> TestResult {
    let mut config = config();
    config.recovery.window = 4;
    config.recovery.max_rows = 4;
    config.recovery.handoff_sources = 4;
    config.mode = Mode::Sliding;
    config.long_window = 4;
    config.repair_every = 1;
    config.cumulative_feedback = true;
    config.repair_spacing_ticks = 100;
    let mut sender = Sender::new(config, scope(), Tick(0))?;
    let mut random = Coefficients(0);
    for id in 0..4 {
        source(&mut sender, id, u64::from(id), 2000, &mut random)?;
    }
    sender.receive_feedback(
        Feedback {
            scope: scope(),
            id: FeedbackId(1),
            prefix: Some(4),
            ids: &[],
        },
        Tick(4),
        &mut random,
    )?;
    assert_eq!(sender.status().pending_sources, 0);
    assert_eq!(
        sender.admit_source(&[4, 0], Tick(4), Tick(4)),
        Err(Error::Capacity)
    );
    for time in 100..104 {
        finish(&mut sender, time, &mut random)?;
        let Some(Output::Repair(repair)) = sender.pending_output() else {
            return Err(Error::Identity.into());
        };
        assert_eq!(
            repair.terms.first().ok_or(Error::Identity)?.source,
            SourceId(0)
        );
        let id = OutputId::Repair(repair.equation.id);
        sender.confirm_output(id, Tick(time), Tick(time), 2000, &mut random)?;
    }
    assert_eq!(
        sender.admit_source(&[4, 0], Tick(104), Tick(104))?,
        SourceId(4)
    );
    Ok(())
}

#[test]
fn invalid_coefficients_fail_closed_after_physical_source_without_losing_completion() -> TestResult
{
    struct Invalid;
    impl CoefficientSource for Invalid {
        fn fill(&mut self, bytes: &mut [u8]) -> Result<(), Error> {
            bytes.fill(0);
            Ok(())
        }
    }
    let mut config = config();
    config.repair_every = 1;
    let mut sender = Sender::new(config, scope(), Tick(0))?;
    sender.admit_source(&[1], Tick(0), Tick(0))?;
    assert_eq!(
        sender.confirm_output(
            OutputId::Source {
                source: SourceId(0),
                attempt: 1
            },
            Tick(1),
            Tick(1),
            20,
            &mut Invalid
        ),
        Err(Error::Identity)
    );
    assert_eq!(sender.status().sent_sources, 1);
    assert_eq!(sender.status().queued_repairs, 0);
    assert_eq!(sender.status().terminal, Some(Error::Identity));
    assert_eq!(
        sender.flight(SourceId(0)).ok_or(Error::Identity)?.attempts,
        1
    );
    Ok(())
}

#[test]
fn reordered_selective_receipts_merge_without_replacing_the_latest_fingerprint() -> TestResult {
    let mut config = config();
    config.feedback_repair = false;
    let mut sender = Sender::new(config, scope(), Tick(0))?;
    let mut random = Coefficients(0);
    for id in 0..3 {
        source(&mut sender, id, u64::from(id), 2000, &mut random)?;
    }
    let later_ids = [SourceId(2)];
    let later = Feedback {
        scope: scope(),
        id: FeedbackId(2),
        prefix: None,
        ids: &later_ids,
    };
    assert_eq!(
        sender.receive_feedback(later, Tick(3), &mut random)?,
        FeedbackDisposition::Applied
    );
    let earlier_ids = [SourceId(0)];
    let earlier = Feedback {
        scope: scope(),
        id: FeedbackId(1),
        prefix: None,
        ids: &earlier_ids,
    };
    assert_eq!(
        sender.receive_feedback(earlier, Tick(4), &mut random)?,
        FeedbackDisposition::Reordered
    );
    assert_eq!(sender.status().encoder.confirmed_prefix, 1);
    assert_eq!(sender.status().pending_sources, 1);
    assert_eq!(sender.status().feedback, Some(FeedbackId(2)));
    assert_eq!(
        sender.receive_feedback(later, Tick(5), &mut random)?,
        FeedbackDisposition::Duplicate
    );
    assert_eq!(
        sender.receive_feedback(earlier, Tick(6), &mut random)?,
        FeedbackDisposition::Reordered
    );
    assert_eq!(sender.status().pending_sources, 1);
    let last_ids = [SourceId(1)];
    let last = Feedback {
        scope: scope(),
        id: FeedbackId(3),
        prefix: None,
        ids: &last_ids,
    };
    sender.receive_feedback(last, Tick(7), &mut random)?;
    assert_eq!(sender.status().encoder.confirmed_prefix, 3);
    assert_eq!(sender.status().pending_sources, 0);
    Ok(())
}

#[test]
fn original_creation_and_queued_job_expiry_survive_backpressure_and_acknowledgment() -> TestResult {
    let mut config = config();
    config.recovery.job_ticks = 100;
    config.recovery.debt_ticks = 1000;
    config.recovery.handoff_ticks = 500;
    let mut random = Coefficients(0);
    let mut sender = Sender::new(config, scope(), Tick(10))?;
    sender.admit_source(&[1], Tick(0), Tick(10))?;
    assert_eq!(sender.deadline(), Some(Tick(100)));
    sender.step(Tick(99), WorkBudget::default(), &mut random)?;
    assert_eq!(sender.deadline(), Some(Tick(100)));
    assert_eq!(
        sender.step(Tick(100), WorkBudget::default(), &mut random),
        Err(Error::Expired)
    );
    assert_eq!(sender.status().terminal, Some(Error::Expired));

    config.repair_every = 1;
    config.repair_spacing_ticks = 200;
    let mut sender = Sender::new(config, scope(), Tick(0))?;
    source(&mut sender, 0, 0, 20, &mut random)?;
    let ids = [SourceId(0)];
    sender.receive_feedback(
        Feedback {
            scope: scope(),
            id: FeedbackId(1),
            prefix: None,
            ids: &ids,
        },
        Tick(1),
        &mut random,
    )?;
    assert_eq!(sender.status().pending_sources, 0);
    assert_eq!(sender.status().queued_repairs, 1);
    assert_eq!(sender.deadline(), Some(Tick(100)));
    sender.step(Tick(99), WorkBudget::default(), &mut random)?;
    assert_eq!(
        sender.step(Tick(100), WorkBudget::default(), &mut random),
        Err(Error::Expired)
    );

    let mut sender = Sender::new(config, scope(), Tick(200))?;
    assert_eq!(
        sender.admit_source(&[1], Tick(0), Tick(200)),
        Err(Error::Expired)
    );
    assert_eq!(sender.status().encoder.next_source, 0);
    assert_eq!(sender.status().terminal, None);
    assert_eq!(
        sender.admit_source(&[1], Tick(200), Tick(200))?,
        SourceId(0)
    );
    Ok(())
}

#[test]
fn invalid_feedback_batch_coefficients_do_not_commit_receipts_or_early_guards() -> TestResult {
    struct Invalid;
    impl CoefficientSource for Invalid {
        fn fill(&mut self, coefficients: &mut [u8]) -> Result<(), Error> {
            coefficients.fill(0);
            Ok(())
        }
    }
    let mut sender = Sender::new(config(), scope(), Tick(0))?;
    let mut random = Coefficients(0);
    for id in 0..5 {
        source(
            &mut sender,
            id,
            (u64::from(id) + 1) * 100,
            2000,
            &mut random,
        )?;
    }
    let ids = [SourceId(0), SourceId(2), SourceId(4)];
    let feedback = Feedback {
        scope: scope(),
        id: FeedbackId(1),
        prefix: None,
        ids: &ids,
    };
    let before = sender.status();
    assert_eq!(
        sender.receive_feedback(feedback, Tick(4000), &mut Invalid),
        Err(Error::Identity)
    );
    assert_eq!(sender.status(), before);
    for id in [SourceId(1), SourceId(3)] {
        let flight = sender.flight(id).ok_or(Error::Identity)?;
        assert!(!flight.early);
        assert_eq!(flight.queued, 0);
    }
    assert_eq!(
        sender.receive_feedback(feedback, Tick(4000), &mut random)?,
        FeedbackDisposition::Applied
    );
    assert_eq!(sender.status().pending_sources, 2);
    assert_eq!(sender.status().queued_repairs, 3);
    Ok(())
}
