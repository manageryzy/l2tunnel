use super::*;

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn config(profile: Profile) -> Config {
    Config {
        recovery: rolling::Config {
            window: 64,
            local_window: 4,
            global_every: 16,
            max_payload: 8,
            max_rows: 64,
            repair_history: 32,
            handoff_sources: 64,
            job_ticks: 100,
            debt_ticks: 1000,
            handoff_ticks: 500,
            memory_bytes: 1 << 20,
        },
        profile,
        feedback_ticks: 5,
        memory_bytes: 1 << 20,
    }
}

fn accumulator() -> Config {
    config(Profile::Accumulator {
        lanes: 3,
        window: 4,
    })
}

fn scope() -> Scope {
    Scope {
        session: [0x57; 16],
        epoch: 1,
        stream: 2,
        direction: 0,
    }
}

fn finish(sender: &mut Sender, now: Tick, units: usize) -> Result<(), Error> {
    let budget = WorkBudget {
        field: units,
        copies: units,
        metadata: units,
    };
    for _ in 0..100_000 {
        if sender.pending_output().is_some() {
            return Ok(());
        }
        let used = sender.step(now, budget)?;
        assert!(used.field <= budget.field);
        assert!(used.copies <= budget.copies);
        assert!(used.metadata <= budget.metadata);
    }
    Err(Error::WorkLimit)
}

fn feedback(id: u64, prefix: u32, observed_end: u32) -> Feedback {
    Feedback {
        scope: scope(),
        id: FeedbackId(id),
        prefix,
        observed_end,
    }
}

#[test]
fn credit_requires_complete_custody_and_feedback_cannot_cancel_a_frozen_repair() -> TestResult {
    let mut sender = Sender::new(accumulator(), scope(), Tick(0))?;
    for id in 0..5 {
        assert_eq!(
            sender.admit_source(&[id as u8, 0], Tick(0), Tick(0))?,
            SourceId(id)
        );
        assert_eq!(sender.status().repair_credit, id * 26);
        let output = sender.pending_output().ok_or(Error::Busy)?;
        assert_eq!(output.encoded_len(), wire::HEADER_BYTES + 2);
        assert_eq!(output.charge(28)?, wire::HEADER_BYTES + 30);
        assert_eq!(output.charge(usize::MAX), Err(Error::Exhausted));
        assert_eq!(
            sender.confirm_output(OutputId::Source(SourceId(id + 1)), Tick(0)),
            Err(Error::Identity)
        );
        let mut small = [0xa7; 1];
        assert_eq!(
            sender.encode_pending(&mut small),
            Err(Error::OutputTooSmall)
        );
        assert_eq!(small, [0xa7]);
        assert_eq!(sender.status().sent_sources, id);
        sender.confirm_output(OutputId::Source(SourceId(id)), Tick(0))?;
    }
    assert_eq!(sender.status().repair_credit, 5);
    assert!(sender.status().repair_pending);
    assert_eq!(
        sender.admit_source(&[9], Tick(0), Tick(0)),
        Err(Error::Busy)
    );
    assert_eq!(
        sender.step(Tick(0), WorkBudget::default())?,
        WorkUsed::default()
    );
    assert!(sender.pending_output().is_none());
    assert_eq!(
        sender.receive_feedback(feedback(1, 5, 5), Tick(0))?,
        FeedbackDisposition::Applied
    );
    finish(&mut sender, Tick(0), 1)?;
    let Some(Output::Repair(repair)) = sender.pending_output() else {
        return Err(Error::Identity.into());
    };
    assert_eq!(repair.confirmed, 0);
    assert_eq!(repair.equation.support.start, 1);
    assert_eq!(repair.equation.support.end, 5);
    assert_eq!(sender.pending_wire_len(), Some(wire::HEADER_BYTES + 4));
    let mut before = [0; 90];
    sender.encode_pending(&mut before)?;
    assert_eq!(
        sender.receive_feedback(feedback(1, 5, 5), Tick(1))?,
        FeedbackDisposition::Duplicate
    );
    finish(&mut sender, Tick(1), 1)?;
    let mut after = [0; 90];
    sender.encode_pending(&mut after)?;
    assert_eq!(before, after);
    sender.confirm_output(OutputId::Repair(RepairId(1)), Tick(1))?;
    assert_eq!(sender.status().sent_repairs, 1);
    sender.step(
        Tick(900),
        WorkBudget {
            field: 65536,
            copies: 65536,
            metadata: 65536,
        },
    )?;
    assert!(sender.pending_output().is_none());
    assert_eq!(sender.deadline(), None);
    Ok(())
}

#[test]
fn exact_26_per_125_schedule_keeps_fallback_slots_and_retained_recursive_history() -> TestResult {
    let config = config(Profile::Recursive {
        taps: 2,
        width: 2,
        reset: 4,
        fresh_interval: 4,
    });
    let mut sender = Sender::new(config, scope(), Tick(0))?;
    let mut fallbacks = 0;
    for source in 0..125_u32 {
        let payload = [source as u8, (source >> 8) as u8, 0];
        sender.admit_source(&payload, Tick(0), Tick(0))?;
        sender.confirm_output(OutputId::Source(SourceId(source)), Tick(0))?;
        // Authenticated receipt after scheduling must not rewrite the frozen
        // support, and confirmed recursive history remains retained by Encoder.
        sender.receive_feedback(
            feedback(u64::from(source) + 1, source + 1, source + 1),
            Tick(0),
        )?;
        if sender.status().repair_pending {
            finish(&mut sender, Tick(0), 17)?;
            let Some(Output::Repair(repair)) = sender.pending_output() else {
                return Err(Error::Identity.into());
            };
            let serial = u32::try_from(repair.equation.id.0)?;
            assert_eq!(repair.equation.support.end, (serial * 125).div_ceil(26));
            assert_eq!(repair.confirmed, source);
            assert_eq!(
                repair.equation.support,
                config.profile.support(source + 1, source, serial)?
            );
            repair.validate(config)?;
            fallbacks += u32::from(config.profile.mode(serial)? == RepairMode::Fallback);
            sender.confirm_output(OutputId::Repair(repair.equation.id), Tick(0))?;
        }
        assert_eq!(sender.status().sent_repairs, (source + 1) * 26 / 125);
    }
    assert_eq!(sender.status().sent_repairs, 26);
    assert_eq!(sender.status().repair_credit, 0);
    assert_eq!(fallbacks, 6);
    assert_eq!(sender.status().encoder.retained_sources, 64);
    Ok(())
}

#[test]
fn original_creation_deadlines_survive_backpressure_work_and_partial_feedback() -> TestResult {
    let mut sender = Sender::new(accumulator(), scope(), Tick(10))?;
    assert_eq!(
        sender.admit_source(&[1], Tick(11), Tick(10)),
        Err(Error::TimeRegression)
    );
    sender.admit_source(&[1, 0], Tick(0), Tick(10))?;
    assert_eq!(sender.deadline(), Some(Tick(100)));
    sender.step(Tick(99), WorkBudget::default())?;
    assert_eq!(
        sender.confirm_output(OutputId::Source(SourceId(0)), Tick(100)),
        Err(Error::Expired)
    );
    assert_eq!(sender.status().terminal, Some(Error::Expired));

    let mut sender = Sender::new(accumulator(), scope(), Tick(10))?;
    sender.admit_source(&[1], Tick(0), Tick(10))?;
    sender.confirm_output(OutputId::Source(SourceId(0)), Tick(10))?;
    sender.admit_source(&[2], Tick(10), Tick(20))?;
    sender.confirm_output(OutputId::Source(SourceId(1)), Tick(20))?;
    sender.receive_feedback(feedback(1, 1, 2), Tick(900))?;
    assert_eq!(sender.deadline(), Some(Tick(1000)));
    assert_eq!(
        sender.step(Tick(1000), WorkBudget::default()),
        Err(Error::Expired)
    );

    let mut sender = Sender::new(accumulator(), scope(), Tick(0))?;
    for source in 0..5 {
        sender.admit_source(&[source as u8], Tick(0), Tick(90))?;
        sender.confirm_output(OutputId::Source(SourceId(source)), Tick(90))?;
    }
    assert_eq!(sender.deadline(), Some(Tick(100)));
    assert_eq!(
        sender.step(Tick(100), WorkBudget::default()),
        Err(Error::Expired)
    );
    Ok(())
}

#[test]
fn feedback_bounds_duplicates_reordering_and_conflicts_do_not_invent_receipt() -> TestResult {
    let mut sender = Sender::new(accumulator(), scope(), Tick(0))?;
    sender.admit_source(&[1], Tick(0), Tick(0))?;
    assert_eq!(
        sender.receive_feedback(feedback(1, 1, 1), Tick(0)),
        Err(Error::Identity)
    );
    sender.confirm_output(OutputId::Source(SourceId(0)), Tick(0))?;
    sender.admit_source(&[2], Tick(0), Tick(0))?;
    sender.confirm_output(OutputId::Source(SourceId(1)), Tick(0))?;
    assert_eq!(
        sender.receive_feedback(feedback(2, 1, 2), Tick(0))?,
        FeedbackDisposition::Applied
    );
    let deadline = sender.deadline();
    assert_eq!(
        sender.receive_feedback(feedback(2, 1, 2), Tick(1))?,
        FeedbackDisposition::Duplicate
    );
    assert_eq!(
        sender.receive_feedback(feedback(2, 2, 2), Tick(2)),
        Err(Error::Conflict)
    );
    assert_eq!(
        sender.receive_feedback(feedback(1, 2, 2), Tick(3))?,
        FeedbackDisposition::Stale
    );
    assert_eq!(
        sender.receive_feedback(feedback(3, 0, 2), Tick(4))?,
        FeedbackDisposition::Stale
    );
    assert_eq!(
        sender.receive_feedback(feedback(3, 1, 1), Tick(5)),
        Err(Error::Identity)
    );
    assert_eq!(sender.status().encoder.confirmed_prefix, 1);
    assert_eq!(sender.deadline(), deadline);
    let mut wrong_scope = feedback(3, 2, 2);
    wrong_scope.scope.epoch += 1;
    assert_eq!(
        sender.receive_feedback(wrong_scope, Tick(5)),
        Err(Error::Scope)
    );
    assert_eq!(
        sender.receive_feedback(feedback(3, 2, 2), Tick(6))?,
        FeedbackDisposition::Applied
    );
    assert_eq!(sender.deadline(), None);
    Ok(())
}

#[test]
fn missing_feedback_backpressures_instead_of_truncating_global_support() -> TestResult {
    let mut config = accumulator();
    config.recovery.window = 8;
    config.recovery.max_rows = 8;
    config.recovery.handoff_sources = 8;
    let mut sender = Sender::new(config, scope(), Tick(0))?;
    for source in 0..8 {
        sender.admit_source(&[source as u8], Tick(0), Tick(0))?;
        sender.confirm_output(OutputId::Source(SourceId(source)), Tick(0))?;
        if sender.status().repair_pending {
            finish(&mut sender, Tick(0), 65536)?;
            let id = sender.pending_output().ok_or(Error::Busy)?.id();
            sender.confirm_output(id, Tick(0))?;
        }
    }
    assert_eq!(
        sender.admit_source(&[8], Tick(0), Tick(0)),
        Err(Error::Capacity)
    );
    assert_eq!(sender.status().sent_sources, 8);
    assert_eq!(sender.status().encoder.confirmed_prefix, 0);
    assert_eq!(sender.status().terminal, None);
    Ok(())
}

#[test]
fn actual_feedback_arrival_orders_repair_prefix_without_clock_rewind_or_renewed_cap() -> TestResult
{
    let setup = || -> Result<(Sender, Feedback), Error> {
        let config = accumulator();
        let mut sender = Sender::new(config, scope(), Tick(0))?;
        let mut receiver = super::super::Receiver::new(config, scope(), Tick(0))?;
        for id in 0..4 {
            sender.admit_source(&[id as u8, 0], Tick(id), Tick(id))?;
            let mut wire = [0; 128];
            let length = sender.encode_pending(&mut wire)?;
            sender.confirm_output(OutputId::Source(SourceId(id as u32)), Tick(id))?;
            if id == 0 {
                receiver.receive_wire(&wire[..length], Tick(1))?;
                receiver.step(
                    Tick(1),
                    WorkBudget {
                        field: 1024,
                        copies: 1024,
                        metadata: 1024,
                    },
                )?;
            }
        }
        let feedback = receiver.pending_feedback().ok_or(Error::Busy)?;
        assert_eq!(feedback.prefix, 1);
        sender.admit_source(&[4, 0], Tick(10), Tick(10))?;
        Ok((sender, feedback))
    };
    for (early, equal_tick) in [(true, false), (false, false), (true, true), (false, true)] {
        let (mut sender, feedback) = setup()?;
        let original_cap = sender.deadline();
        if early {
            sender.receive_feedback_at(
                feedback,
                Tick(if equal_tick { 12 } else { 11 }),
                Tick(15),
            )?;
        }
        sender.confirm_output_at(OutputId::Source(SourceId(4)), Tick(12), Tick(15))?;
        if !early {
            sender.receive_feedback_at(
                feedback,
                Tick(if equal_tick { 12 } else { 13 }),
                Tick(15),
            )?;
        }
        finish(&mut sender, Tick(15), 1024)?;
        let Output::Repair(repair) = sender.pending_output().ok_or(Error::Busy)? else {
            return Err("real earned repair missing".into());
        };
        assert_eq!(repair.confirmed, if early { 1 } else { 0 });
        assert_eq!(sender.status().sent_sources, 5);
        assert_eq!(sender.deadline(), original_cap);
        assert_eq!(
            sender.step(Tick(14), WorkBudget::default()),
            Err(Error::TimeRegression)
        );
    }
    let (mut sender, feedback) = setup()?;
    sender.receive_feedback_at(feedback, Tick(11), Tick(15))?;
    let cap = sender.deadline().ok_or(Error::Expired)?;
    assert_eq!(
        sender.confirm_output_at(OutputId::Source(SourceId(4)), Tick(12), cap),
        Err(Error::Expired)
    );
    assert_eq!(sender.status().sent_sources, 5);
    assert!(sender.pending_output().is_none());
    assert!(
        sender
            .confirm_output_at(OutputId::Source(SourceId(4)), Tick(12), cap)
            .is_err()
    );
    let mut unsent = Sender::new(accumulator(), scope(), Tick(0))?;
    unsent.admit_source(&[0, 0], Tick(0), Tick(0))?;
    assert_eq!(
        unsent.receive_feedback_at(feedback, Tick(1), Tick(1)),
        Err(Error::Identity)
    );
    assert_eq!(unsent.status().sent_sources, 0);
    Ok(())
}
