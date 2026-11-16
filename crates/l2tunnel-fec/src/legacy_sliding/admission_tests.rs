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
            job_ticks: 1000,
            debt_ticks: 10000,
            handoff_ticks: 5000,
            memory_bytes: 1 << 20,
        },
        mode: Mode::Sliding,
        long_window: 5,
        short_window: 2,
        long_every: 3,
        repair_every: 5,
        repairs_per_group: 2,
        interleave_repairs: true,
        feedback_repair: true,
        cumulative_feedback: false,
        feedback_batch: 16,
        fec_wait_ticks: 10,
        repair_spacing_ticks: 1,
        feedback_wait_ticks: 2,
        rto_min_ticks: 100,
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
        session: [0x73; 16],
        epoch: 3,
        stream: 4,
        direction: 1,
    }
}
fn ids(sender: &Sender, slot: usize) -> Vec<SourceId> {
    sender.jobs[slot]
        .map(|job| {
            sender
                .row(slot, job.terms)
                .iter()
                .map(|term| term.source)
                .collect()
        })
        .unwrap_or_default()
}
fn complete(sender: &mut Sender, now: u64, random: &mut Coefficients) -> Result<(), Error> {
    let id = sender.pending_output().ok_or(Error::Busy)?.id();
    sender.confirm_output(id, Tick(now), Tick(now), 100, random)
}

#[test]
fn admission_credit_and_timer_freeze_support_while_original_output_is_held() -> TestResult {
    let config = config();
    let plan = storage::Plan::for_sender_admission(config)?;
    assert!(
        Sender::new_reserved_admission(
            config,
            scope(),
            Tick(0),
            storage::Limits {
                capacity_bytes: plan.capacity_bytes() - 1
            }
        )
        .is_err()
    );
    let mut sender = Sender::new_reserved_admission(
        config,
        scope(),
        Tick(0),
        storage::Limits {
            capacity_bytes: plan.capacity_bytes(),
        },
    )?;
    let usage = sender.storage_usage()?;
    assert_eq!(usage.capacity_bytes, plan.capacity_bytes());
    assert_eq!(usage.allocations, plan.allocations());
    let mut random = Coefficients(0);
    sender.admit_source_with_coefficients(&[1, 0], Tick(0), Tick(0), &mut random)?;
    let original_id = sender.pending_output().ok_or(Error::Busy)?.id();
    let mut original = [0u8; 512];
    let length = sender.encode_pending(&mut original)?;
    assert_eq!(sender.status().repair_credit, 2);
    for id in 1..3 {
        assert_eq!(
            sender.admit_source_with_coefficients(
                &[id as u8, 0],
                Tick(id),
                Tick(id),
                &mut random
            )?,
            SourceId(id as u32)
        );
    }
    assert_eq!(
        (
            sender.status().periodic_repairs,
            sender.status().repair_credit
        ),
        (1, 1)
    );
    assert_eq!(ids(&sender, 0), [SourceId(0), SourceId(1), SourceId(2)]);
    sender.admit_source_with_coefficients(&[3, 0], Tick(3), Tick(3), &mut random)?;
    assert_eq!(sender.fec_due, Some(Tick(13)));
    sender.step(
        Tick(13),
        WorkBudget {
            field: 0,
            copies: 0,
            metadata: 1,
        },
        &mut random,
    )?;
    assert_eq!(sender.fec_due, None);
    assert_eq!(
        (
            sender.status().periodic_repairs,
            sender.status().repair_credit
        ),
        (2, 0)
    );
    assert_eq!(
        ids(&sender, 1),
        [SourceId(0), SourceId(1), SourceId(2), SourceId(3)]
    );
    // The first frozen equation is not widened by later admission or timer work.
    assert_eq!(ids(&sender, 0), [SourceId(0), SourceId(1), SourceId(2)]);
    sender.admit_source_with_coefficients(&[4, 0], Tick(14), Tick(14), &mut random)?;
    let mut repeated = [0u8; 512];
    assert_eq!(sender.encode_pending(&mut repeated)?, length);
    assert_eq!(original, repeated);
    assert_eq!(sender.status().unsent_sources, 5);
    assert_eq!(
        sender.pending_output().ok_or(Error::Busy)?.id(),
        original_id
    );
    sender.confirm_output(original_id, Tick(15), Tick(16), 100, &mut random)?;
    assert_eq!(
        (
            sender.status().repair_credit,
            sender.status().periodic_repairs
        ),
        (2, 2)
    );
    assert_eq!(sender.fec_due, Some(Tick(24)));
    assert_eq!(
        sender.flight(SourceId(0)).ok_or(Error::Identity)?.retry_at,
        Some(Tick(265))
    );
    assert_eq!(sender.storage_usage()?, usage);
    assert_eq!(sender.status().unsent_sources, 4);
    assert_eq!(
        sender.confirm_output(original_id, Tick(15), Tick(16), 100, &mut random),
        Err(Error::Busy)
    );
    assert_eq!(sender.status().repair_credit, 2);
    Ok(())
}

#[test]
fn invalid_admission_coefficients_preserve_original_source_and_frozen_queue() -> TestResult {
    struct Invalid;
    impl CoefficientSource for Invalid {
        fn fill(&mut self, bytes: &mut [u8]) -> Result<(), Error> {
            bytes.fill(0);
            Ok(())
        }
    }
    let mut config = config();
    config.interleave_repairs = false;
    config.repair_every = 2;
    config.repairs_per_group = 1;
    let mut sender = Sender::new_admission(config, scope(), Tick(0))?;
    let mut random = Coefficients(0);
    sender.admit_source_with_coefficients(&[1], Tick(0), Tick(0), &mut random)?;
    let id = sender.pending_output().ok_or(Error::Busy)?.id();
    let status = sender.status();
    assert_eq!(
        sender.admit_source_with_coefficients(&[2], Tick(1), Tick(1), &mut Invalid),
        Err(Error::Identity)
    );
    assert_eq!(sender.status(), status);
    assert_eq!(sender.pending_output().ok_or(Error::Busy)?.id(), id);
    assert_eq!(sender.encoder.source(SourceId(0)), Some([1].as_slice()));
    assert_eq!(
        sender.admit_source_with_coefficients(&[2], Tick(1), Tick(1), &mut random)?,
        SourceId(1)
    );
    assert_eq!(sender.status().queued_repairs, 1);
    Ok(())
}

#[test]
fn frozen_repair_accepts_later_admission_without_authorizing_unsent_feedback() -> TestResult {
    let mut config = config();
    config.interleave_repairs = false;
    config.repair_every = 2;
    config.repairs_per_group = 1;
    config.repair_spacing_ticks = 0;
    let mut sender = Sender::new_admission(config, scope(), Tick(0))?;
    let mut random = Coefficients(0);
    for id in 0..2 {
        sender.admit_source_with_coefficients(&[id as u8, 0], Tick(id), Tick(id), &mut random)?;
        if id == 0 {
            complete(&mut sender, id, &mut random)?;
        }
    }
    sender.step(
        Tick(2),
        WorkBudget {
            field: 1,
            copies: 1,
            metadata: 1,
        },
        &mut random,
    )?;
    assert!(matches!(
        sender.pending_output(),
        Some(Output::Source {
            id: SourceId(1),
            ..
        })
    ));
    complete(&mut sender, 2, &mut random)?;
    for _ in 0..128 {
        sender.step(
            Tick(3),
            WorkBudget {
                field: 1,
                copies: 1,
                metadata: 1,
            },
            &mut random,
        )?;
        if matches!(sender.pending_output(), Some(Output::Repair(_))) {
            break;
        }
    }
    let repair = sender.pending_output().ok_or(Error::Busy)?;
    assert!(matches!(repair, Output::Repair(_)));
    let repair_id = repair.id();
    let mut before = [0u8; 512];
    let length = sender.encode_pending(&mut before)?;
    sender.admit_source_with_coefficients(&[9, 0], Tick(4), Tick(4), &mut random)?;
    let unseen = [SourceId(2)];
    let feedback = Feedback {
        scope: scope(),
        id: FeedbackId(1),
        prefix: None,
        ids: &unseen,
    };
    assert_eq!(
        sender.receive_feedback(feedback, Tick(4), &mut random),
        Err(Error::Identity)
    );
    let received = [SourceId(0)];
    assert_eq!(
        sender.receive_feedback(
            Feedback {
                ids: &received,
                ..feedback
            },
            Tick(4),
            &mut random
        )?,
        FeedbackDisposition::Applied
    );
    let mut after = [0u8; 512];
    assert_eq!(sender.encode_pending(&mut after)?, length);
    assert_eq!(before, after);
    sender.confirm_output(repair_id, Tick(5), Tick(5), 100, &mut random)?;
    assert_eq!(
        sender.receive_feedback(
            Feedback {
                id: FeedbackId(2),
                ..feedback
            },
            Tick(5),
            &mut random
        ),
        Err(Error::Identity)
    );
    assert_eq!(sender.status().unsent_sources, 1);
    assert_eq!(sender.status().pending_sources, 2);
    Ok(())
}
