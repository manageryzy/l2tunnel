use super::*;
use crate::rolling::{Scope, SourceId, WorkBudget, wire};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn policy() -> scheduler::Policy {
    scheduler::Policy {
        recovery: Config {
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
        },
        repair_numerator: 0,
        repair_denominator: 1,
        tail_ticks: 20,
        feedback_ticks: 2,
        feedback_packets: 1,
        memory_bytes: 1 << 20,
        source_wire: wire::SourceWire::Padded,
    }
}

fn scope() -> Scope {
    Scope {
        session: [0x73; 16],
        epoch: 3,
        stream: 7,
        direction: 1,
    }
}

#[test]
fn exact_plans_observe_all_real_buffers_and_refuse_one_short() -> TestResult {
    let policy = policy();
    let sender = Plan::for_sender(policy)?;
    let receiver = Plan::for_receiver(policy)?;
    assert_eq!(sender.policy(), policy);
    assert_eq!(receiver.policy(), policy);
    assert_eq!(sender.allocations(), 3);
    assert_eq!(receiver.allocations(), 13);
    for plan in [sender, receiver] {
        let limits = Limits {
            capacity_bytes: plan.capacity_bytes() - 1,
        };
        assert_eq!(plan.admit(limits, Tick(0)), Err(Error::Capacity));
        match plan.kind {
            Kind::Sender => assert!(matches!(
                scheduler::Sender::new_reserved(policy, scope(), Tick(0), limits),
                Err(Error::Capacity)
            )),
            Kind::Receiver => assert!(matches!(
                scheduler::Receiver::new_reserved(policy, scope(), Tick(0), limits),
                Err(Error::Capacity)
            )),
        }
        for extra in 0..=1 {
            let limits = Limits {
                capacity_bytes: plan.capacity_bytes() + extra,
            };
            let usage = match plan.kind {
                Kind::Sender => scheduler::Sender::new_reserved(policy, scope(), Tick(0), limits)?
                    .storage_usage()?,
                Kind::Receiver => {
                    scheduler::Receiver::new_reserved(policy, scope(), Tick(0), limits)?
                        .storage_usage()?
                }
            };
            assert_eq!(usage, plan.usage);
        }
    }
    // Observations inspect the existing owners, including the unchanged constructors.
    assert_eq!(
        scheduler::Sender::new(policy, scope(), Tick(0))?.storage_usage()?,
        sender.usage
    );
    assert_eq!(
        scheduler::Receiver::new(policy, scope(), Tick(0))?.storage_usage()?,
        receiver.usage
    );
    Ok(())
}

#[test]
fn complete_preflight_preserves_legacy_guards_and_rejects_deadline_overflow() -> TestResult {
    let mut value = policy();
    value.recovery.memory_bytes = 1;
    assert_eq!(
        Plan::for_sender(value),
        Err(Error::Recovery(super::super::Error::Capacity))
    );
    assert_eq!(
        Plan::for_receiver(value),
        Err(Error::Recovery(super::super::Error::Capacity))
    );
    value = policy();
    value.memory_bytes = 1;
    assert_eq!(
        Plan::for_sender(value),
        Err(Error::Recovery(super::super::Error::Capacity))
    );
    assert_eq!(
        Plan::for_receiver(value),
        Err(Error::Recovery(super::super::Error::Capacity))
    );
    value = policy();
    value.recovery.window = 0;
    assert_eq!(
        Plan::for_sender(value),
        Err(Error::Recovery(super::super::Error::Configuration))
    );
    assert_eq!(
        Plan::for_receiver(value),
        Err(Error::Recovery(super::super::Error::Configuration))
    );
    for plan in [Plan::for_sender(policy())?, Plan::for_receiver(policy())?] {
        assert_eq!(
            plan.admit(Limits { capacity_bytes: 0 }, Tick(u64::MAX)),
            Err(Error::Recovery(super::super::Error::Exhausted))
        );
        assert_eq!(
            plan.verify(
                Usage {
                    allocations: plan.allocations() + 1,
                    ..plan.usage
                },
                Limits {
                    capacity_bytes: plan.capacity_bytes()
                }
            ),
            Err(Error::Layout)
        );
    }
    Ok(())
}

#[test]
fn actual_systematic_feedback_and_recycling_keep_observed_layouts() -> TestResult {
    let policy = policy();
    let tx_plan = Plan::for_sender(policy)?;
    let rx_plan = Plan::for_receiver(policy)?;
    let mut sender = scheduler::Sender::new_reserved(
        policy,
        scope(),
        Tick(0),
        Limits {
            capacity_bytes: tx_plan.capacity_bytes(),
        },
    )?;
    let mut receiver = scheduler::Receiver::new_reserved(
        policy,
        scope(),
        Tick(0),
        Limits {
            capacity_bytes: rx_plan.capacity_bytes(),
        },
    )?;
    let mut packet = [0; 74];
    let work = WorkBudget {
        field: 65_536,
        copies: 65_536,
        metadata: 65_536,
    };
    for index in 0..12_u32 {
        let now = Tick(u64::from(index));
        let original = [index as u8, 0, 0x91, 0];
        let source = sender.admit_source(&original, now)?;
        assert_eq!(source, SourceId(index));
        let id = sender.pending_output().ok_or("missing real output")?.id();
        let length = sender.encode_pending(&mut packet)?;
        receiver.receive_wire(&packet[..length], now)?;
        sender.confirm_output(id, now)?;
        for _ in 0..100 {
            receiver.step(now, work)?;
            if receiver.pending_feedback().is_some() {
                break;
            }
        }
        assert_eq!(
            receiver.pending_source(),
            Some((source, original.as_slice()))
        );
        let feedback = receiver.pending_feedback().ok_or("missing real feedback")?;
        sender.receive_feedback(feedback, now)?;
        receiver.confirm_feedback(feedback.id, now)?;
        receiver.confirm_handoff(source, now)?;
        assert_eq!(sender.storage_usage()?, tx_plan.usage);
        assert_eq!(receiver.storage_usage()?, rx_plan.usage);
    }
    assert_eq!(sender.status().sent_sources, 12);
    assert_eq!(receiver.status().decoder.decoded_prefix, 12);
    Ok(())
}
