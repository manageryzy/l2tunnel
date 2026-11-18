//! Actual encoder/receiver outputs, including feedback during physical copies.
use super::*;
type TestResult = Result<(), Box<dyn std::error::Error>>;
fn policy() -> Policy {
    Policy {
        recovery: Config {
            window: 4,
            local_window: 2,
            global_every: 2,
            max_payload: 8,
            max_rows: 4,
            repair_history: 8,
            handoff_sources: 2,
            job_ticks: 100,
            debt_ticks: 1000,
            handoff_ticks: 500,
            memory_bytes: 1 << 20,
        },
        repair_numerator: 1,
        repair_denominator: 1,
        tail_ticks: 10,
        feedback_ticks: 2,
        feedback_packets: 1,
        memory_bytes: 1 << 20,
        source_wire: wire::SourceWire::Exact,
    }
}
fn scope() -> Scope {
    Scope {
        session: [7; 16],
        epoch: 2,
        stream: 11,
        direction: 0,
    }
}
fn work() -> WorkBudget {
    WorkBudget {
        field: 65536,
        copies: 65536,
        metadata: 65536,
    }
}
fn wire(sender: &Sender) -> Result<Vec<u8>, Error> {
    let mut bytes = vec![0; 128];
    let length = sender.encode_pending(&mut bytes)?;
    bytes.truncate(length);
    Ok(bytes)
}

#[test]
fn actual_source_copies_keep_one_identity_payload_credit_and_exact_legacy_wire() -> TestResult {
    let policy = policy();
    for copies in 1..=4 {
        let plan = storage::Plan::for_sender(policy)?;
        let mut sender = Sender::new_reserved(
            policy,
            scope(),
            Tick(0),
            storage::Limits {
                capacity_bytes: plan.capacity_bytes(),
            },
        )?;
        let usage = sender.storage_usage()?;
        let mut legacy = Sender::new(policy, scope(), Tick(0))?;
        let before = sender.status();
        assert_eq!(
            sender.admit_source_with_copies(b"x\0\0", Tick(5), 0),
            Err(Error::Configuration)
        );
        assert_eq!(
            sender.admit_source_with_copies(b"x\0\0", Tick(5), 5),
            Err(Error::Configuration)
        );
        assert_eq!(sender.status(), before);
        assert_eq!(
            sender.admit_source_with_copies(b"x\0\0", Tick(5), copies)?,
            SourceId(0)
        );
        legacy.admit_source(b"x\0\0", Tick(5))?;
        let original = wire(&legacy)?;
        assert_eq!(wire(&sender)?, original);
        let end = sender.deadline();
        let mut previous = None;
        for ordinal in 1..=copies {
            let copy = sender.pending_source_copy().ok_or("missing actual copy")?;
            assert_eq!(copy.source(), SourceId(0));
            assert_eq!(copy.ordinal(), ordinal);
            assert_eq!(copy.total(), copies);
            assert_eq!(wire(&sender)?, original);
            assert_eq!(sender.deadline(), end);
            if copies > 1 {
                assert_eq!(
                    sender.confirm_output(OutputId::Source(SourceId(0)), Tick(6)),
                    Err(Error::Identity)
                );
            }
            if let Some(stale) = previous {
                let state = sender.status();
                assert_eq!(
                    sender.confirm_source_copy(Tick(0), Tick(0), stale),
                    Err(Error::Identity)
                );
                assert_eq!(sender.status(), state);
            }
            sender.confirm_source_copy(
                Tick(5 + u64::from(ordinal)),
                Tick(5 + u64::from(ordinal)),
                copy,
            )?;
            if ordinal < copies {
                assert_eq!(sender.status().regular_due, 0);
                assert_eq!(sender.status().encoder.confirmed_prefix, 0);
            }
            previous = Some(copy);
        }
        assert!(sender.pending_output().is_none());
        assert_eq!(sender.status().encoder.next_source, 1);
        assert_eq!(sender.status().sent_sources, 1);
        assert_eq!(sender.status().regular_due, 1);
        assert_eq!(sender.status().repair_credit, 0);
        assert_eq!(sender.storage_usage()?, usage);
        let old = previous.ok_or("last copy")?;
        let state = sender.status();
        assert_eq!(
            sender.confirm_source_copy(Tick(0), Tick(0), old),
            Err(Error::Identity)
        );
        assert_eq!(sender.status(), state);
    }
    Ok(())
}

#[test]
fn actual_peer_feedback_after_first_copy_pins_payload_and_keeps_latest_prefix() -> TestResult {
    let policy = policy();
    let mut sender = Sender::new(policy, scope(), Tick(0))?;
    let mut peer = Receiver::new(policy, scope(), Tick(0))?;
    sender.admit_source_with_copies(b"a\0b\0", Tick(0), 3)?;
    let bytes = wire(&sender)?;
    let first = sender.pending_source_copy().ok_or("first copy")?;
    sender.confirm_source_copy(Tick(1), Tick(1), first)?;
    peer.receive_wire(&bytes, Tick(2))?;
    for _ in 0..64 {
        peer.step(Tick(2), work())?;
        if peer.pending_feedback().is_some() {
            break;
        }
    }
    assert_eq!(
        peer.pending_source(),
        Some((SourceId(0), b"a\0b\0".as_slice()))
    );
    let feedback = peer.pending_feedback().ok_or("actual peer receipt")?;
    assert_eq!(feedback.prefix, 1);
    assert_eq!(feedback.observed_end, 1);
    sender.receive_feedback_wire(
        peer.pending_feedback_wire().ok_or("feedback bytes")?,
        Tick(3),
    )?;
    assert_eq!(sender.status().encoder.confirmed_prefix, 0);
    assert_eq!(wire(&sender)?, bytes);
    // A later-identified but regressed prefix cannot erase the authenticated
    // receipt retained while the exact copy payload is pinned.
    let stale = Feedback {
        id: FeedbackId(feedback.id.0 + 1),
        prefix: 0,
        deficit: 1,
        ..feedback
    };
    assert_eq!(
        sender.receive_feedback(stale, Tick(4))?,
        FeedbackDisposition::Stale
    );
    let latest = Feedback {
        id: FeedbackId(feedback.id.0 + 2),
        ..feedback
    };
    assert_eq!(
        sender.receive_feedback(latest, Tick(4))?,
        FeedbackDisposition::Applied
    );
    for now in [Tick(5), Tick(6)] {
        let copy = sender.pending_source_copy().ok_or("retained copy")?;
        assert_eq!(wire(&sender)?, bytes);
        sender.confirm_source_copy(now, now, copy)?;
    }
    assert_eq!(sender.status().feedback, Some(latest.id));
    assert_eq!(sender.status().encoder.confirmed_prefix, 1);
    assert_eq!(sender.status().encoder.next_source, 1);
    assert_eq!(sender.status().regular_due, 0);
    assert_eq!(sender.status().tail_due, None);
    assert!(sender.pending_output().is_none());
    peer.confirm_handoff(SourceId(0), Tick(6))?;
    assert!(peer.pending_source().is_none());
    Ok(())
}

#[test]
fn original_group_cap_and_acceptance_bounds_survive_held_and_last_copy() -> TestResult {
    let mut policy = policy();
    policy.recovery.job_ticks = 20;
    let mut sender = Sender::new(policy, scope(), Tick(0))?;
    sender.admit_source_with_copies(b"z", Tick(0), 3)?;
    let original = wire(&sender)?;
    let end = sender.deadline();
    let first = sender.pending_source_copy().ok_or("first")?;
    sender.confirm_source_copy(Tick(10), Tick(2), first)?;
    assert_eq!(sender.deadline(), end);
    let second = sender.pending_source_copy().ok_or("second")?;
    sender.step(Tick(19), WorkBudget::default())?;
    assert_eq!(sender.pending_source_copy(), Some(second));
    assert_eq!(wire(&sender)?, original);
    sender.confirm_source_copy(Tick(19), Tick(12), second)?;
    assert_eq!(sender.deadline(), end);
    let last = sender.pending_source_copy().ok_or("last")?;
    assert_eq!(
        sender.confirm_source_copy(Tick(20), Tick(19), last),
        Err(Error::Expired)
    );
    assert!(sender.pending_source_copy().is_none());
    assert_eq!(sender.status().terminal, Some(Error::Expired));
    assert_eq!(
        sender.confirm_source_copy(Tick(1), Tick(1), last),
        Err(Error::Identity)
    );
    for accepted in [Tick(4), Tick(7)] {
        let mut bad = Sender::new(policy, scope(), Tick(0))?;
        bad.admit_source_with_copies(b"z", Tick(5), 2)?;
        let copy = bad.pending_source_copy().ok_or("bad-time copy")?;
        assert_eq!(
            bad.confirm_source_copy(Tick(6), accepted, copy),
            Err(Error::TimeRegression)
        );
        assert_eq!(bad.status().terminal, Some(Error::TimeRegression));
        assert!(bad.pending_source_copy().is_none());
    }
    Ok(())
}

#[test]
fn fresh_source_preempts_only_unmaterialized_tail_and_keeps_physical_copies() -> TestResult {
    let mut policy = policy();
    policy.repair_numerator = 0;
    let mut sender = Sender::new(policy, scope(), Tick(0))?;
    let mut peer = Receiver::new(policy, scope(), Tick(0))?;
    for at in 0..3 {
        let id = sender.admit_source(b"x\0", Tick(at))?;
        let bytes = wire(&sender)?;
        sender.confirm_output(OutputId::Source(id), Tick(at))?;
        if at == 2 {
            peer.receive_wire(&bytes, Tick(3))?;
        }
    }
    for _ in 0..64 {
        peer.step(Tick(3), work())?;
        if peer.pending_feedback().is_some() {
            break;
        }
    }
    let feedback = peer.pending_feedback().ok_or("actual sparse receipt")?;
    assert_eq!(
        (feedback.prefix, feedback.observed_end, feedback.deficit),
        (0, 3, 2)
    );
    sender.receive_feedback(feedback, Tick(3))?;
    let original_debt = sender.expiry_snapshot().candidates[0].map(|value| value.at);
    let usage = sender.storage_usage()?;
    sender.step(
        Tick(12),
        WorkBudget {
            field: 0,
            copies: 0,
            metadata: 1,
        },
    )?;
    assert!(sender.status().encoder.pending_repair);
    assert!(sender.pending_output().is_none());
    assert_eq!(sender.admit_source(b"next", Tick(12)), Err(Error::Busy));
    sender.step(Tick(12), work())?;
    let repair = sender.pending_output().ok_or("computed tail")?.id();
    let immutable = wire(&sender)?;
    assert_eq!(sender.admit_source(b"next", Tick(12)), Err(Error::Busy));
    assert_eq!(wire(&sender)?, immutable);
    sender.confirm_output(repair, Tick(13))?;
    assert_eq!(sender.status().tail_remaining, 1);
    assert_eq!(sender.status().tail_due, Some(Tick(12)));
    let source = sender.admit_source_with_copies(b"next\0", Tick(14), 3)?;
    assert_eq!(source, SourceId(3));
    assert_eq!(sender.status().tail_remaining, 0);
    assert_eq!(sender.status().tail_due, None);
    assert_eq!(
        sender.expiry_snapshot().candidates[0].map(|value| value.at),
        original_debt
    );
    let original_cap = sender.deadline();
    let bytes = wire(&sender)?;
    for at in 15..=17 {
        let copy = sender.pending_source_copy().ok_or("actual copy witness")?;
        assert_eq!(sender.admit_source(b"blocked", Tick(at)), Err(Error::Busy));
        assert_eq!(wire(&sender)?, bytes);
        assert_eq!(sender.deadline(), original_cap);
        sender.confirm_source_copy(Tick(at), Tick(at), copy)?;
        if at < 17 {
            assert_eq!(sender.status().tail_due, None);
        }
    }
    assert_eq!(sender.status().tail_due, Some(Tick(27)));
    assert_eq!(
        sender.expiry_snapshot().candidates[0].map(|value| value.at),
        original_debt
    );
    assert_eq!(sender.storage_usage()?, usage);
    Ok(())
}

#[test]
fn overdue_idle_tail_yields_to_source_but_earned_regular_repair_does_not() -> TestResult {
    for regular in [0, 1] {
        let mut policy = policy();
        policy.repair_numerator = regular;
        let mut sender = Sender::new(policy, scope(), Tick(0))?;
        let first = sender.admit_source(b"first", Tick(0))?;
        sender.confirm_output(OutputId::Source(first), Tick(0))?;
        assert_eq!(sender.status().tail_due, Some(Tick(10)));
        if regular == 1 {
            assert_eq!(sender.admit_source(b"next", Tick(10)), Err(Error::Busy));
            assert_eq!(sender.status().regular_due, 1);
            sender.step(Tick(10), work())?;
            let output = sender.pending_output().ok_or("earned regular repair")?;
            assert!(matches!(output, Output::Repair(repair) if !repair.support.tail));
            sender.confirm_output(output.id(), Tick(10))?;
        }
        assert_eq!(sender.admit_source(b"next", Tick(11))?, SourceId(1));
        assert_eq!(sender.status().tail_due, None);
        sender.confirm_output(OutputId::Source(SourceId(1)), Tick(12))?;
        assert_eq!(sender.status().tail_due, Some(Tick(22)));
    }
    Ok(())
}

#[test]
fn refused_source_preserves_tail_recovery_and_silent_peer_drain() -> TestResult {
    let mut policy = policy();
    policy.repair_numerator = 0;
    policy.recovery.window = 1;
    policy.recovery.local_window = 1;
    policy.recovery.max_rows = 1;
    policy.recovery.handoff_sources = 1;
    let mut sender = Sender::new(policy, scope(), Tick(0))?;
    let mut peer = Receiver::new(policy, scope(), Tick(0))?;
    let first = sender.admit_source(b"lost\0", Tick(0))?;
    sender.confirm_output(OutputId::Source(first), Tick(0))?;
    let original = sender.status();
    assert_eq!(
        sender.admit_source(b"invalid length", Tick(10)),
        Err(Error::Length)
    );
    assert_eq!(sender.status().tail_due, original.tail_due);
    assert_eq!(sender.admit_source(b"full", Tick(10)), Err(Error::Capacity));
    assert_eq!(sender.status().tail_due, original.tail_due);
    assert_eq!(sender.status().tail_remaining, original.tail_remaining);
    sender.step(Tick(10), work())?;
    let output = sender.pending_output().ok_or("required tail repair")?;
    assert!(matches!(output, Output::Repair(repair) if repair.support.tail));
    let id = output.id();
    let bytes = wire(&sender)?;
    sender.confirm_output(id, Tick(11))?;
    assert_eq!(sender.status().tail_due, Some(Tick(21)));
    peer.receive_wire(&bytes, Tick(12))?;
    for _ in 0..64 {
        peer.step(Tick(12), work())?;
        if peer.pending_feedback().is_some() {
            break;
        }
    }
    assert_eq!(
        peer.pending_source(),
        Some((SourceId(0), b"lost\0".as_slice()))
    );
    sender.receive_feedback_wire(
        peer.pending_feedback_wire()
            .ok_or("repaired cumulative receipt")?,
        Tick(13),
    )?;
    assert_eq!(sender.status().encoder.confirmed_prefix, 1);
    assert_eq!(sender.status().tail_remaining, 0);
    assert_eq!(sender.status().tail_due, None);
    assert_eq!(sender.deadline(), None);
    sender.step(Tick(2000), work())?;
    assert!(sender.pending_output().is_none());
    Ok(())
}
