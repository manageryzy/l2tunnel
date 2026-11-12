use super::*;
use crate::{Capacity, CreditError, Direction, LimitDomain, ReceiverCredits, Scope, SenderCredits};

fn credit(bytes: u64, records: u64) -> Credit {
    Credit { bytes, records }
}

fn config() -> TargetConfig {
    TargetConfig {
        initial: credit(100, 10),
        minimum: credit(10, 1),
        session_cap: credit(1_600, 160),
        per_flow_cap: credit(1_600, 160),
        policy_cap: credit(1_600, 160),
        queue_allowance_bytes: 10,
        queue_delay_target_micros: 100,
        many_flow_step: credit(20, 2),
        few_flow_threshold: 4,
        max_flows: 16,
        bootstrap_rtt_micros: 1_000,
        recovery_rtts: 2,
    }
}

fn measured(in_flight: Credit) -> Feedback {
    Feedback {
        rtt_micros: Some(1_000),
        delivery_bytes_per_second: Some(1_000_000_000),
        in_flight,
        ..Feedback::default()
    }
}

#[test]
fn few_flows_double_only_once_per_rtt_without_catch_up() -> Result<(), TargetError> {
    for flows in [
        vec![FlowId(1)],
        vec![FlowId(1), FlowId(2), FlowId(3), FlowId(4)],
    ] {
        let mut controller = TargetController::new(config(), Micros(0))?;
        assert_eq!(
            controller
                .update(Micros(0), measured(credit(100, 10)), &flows)?
                .total(),
            credit(100, 10)
        );
        assert_eq!(
            controller
                .update(Micros(999), measured(credit(100, 10)), &flows)?
                .total(),
            credit(100, 10)
        );
        let doubled = controller.update(Micros(1_000), measured(credit(100, 10)), &flows)?;
        assert_eq!(doubled.total(), credit(200, 20));
        assert_eq!(doubled.state(), TargetState::Probing);
        assert_eq!(
            controller
                .update(Micros(1_000), measured(credit(200, 20)), &flows)?
                .total(),
            credit(200, 20)
        );
        assert_eq!(
            controller
                .update(Micros(100_000), measured(credit(200, 20)), &flows)?
                .total(),
            credit(400, 40)
        );
    }
    Ok(())
}

#[test]
fn effective_grant_exhaustion_qualifies_growth_without_bypassing_other_gates()
-> Result<(), TargetError> {
    let mut controller = TargetController::new(config(), Micros(0))?;
    let flows = [FlowId(1)];
    let exhausted = Feedback {
        sender_credit_exhausted: true,
        ..measured(credit(10, 1))
    };
    assert_eq!(
        controller.update(Micros(0), exhausted, &flows)?.total(),
        credit(100, 10)
    );
    assert_eq!(
        controller.update(Micros(999), exhausted, &flows)?.total(),
        credit(100, 10)
    );
    assert_eq!(
        controller.update(Micros(1000), exhausted, &flows)?.total(),
        credit(200, 20)
    );
    assert_eq!(
        controller.update(Micros(1000), exhausted, &flows)?.total(),
        credit(200, 20)
    );
    for missing in [
        Feedback {
            rtt_micros: None,
            ..exhausted
        },
        Feedback {
            delivery_bytes_per_second: None,
            ..exhausted
        },
    ] {
        assert_eq!(
            controller.update(Micros(2000), missing, &flows)?.total(),
            credit(200, 20)
        );
    }
    let pressure = Feedback {
        receiver_pressure: true,
        ..exhausted
    };
    assert_eq!(
        controller.update(Micros(3000), pressure, &flows)?.total(),
        credit(100, 10)
    );
    assert_eq!(
        controller.update(Micros(4000), exhausted, &[])?.total(),
        Credit::default()
    );
    assert_eq!(
        controller.update(Micros(5000), exhausted, &flows)?.total(),
        credit(100, 10)
    );
    Ok(())
}

#[test]
fn five_flows_use_aggregate_additive_growth_and_equal_shares() -> Result<(), TargetError> {
    let flows = [FlowId(5), FlowId(1), FlowId(3), FlowId(2), FlowId(4)];
    let mut controller = TargetController::new(config(), Micros(0))?;
    controller.update(Micros(0), measured(credit(100, 10)), &flows)?;
    let plan = controller.update(Micros(1_000), measured(credit(100, 10)), &flows)?;
    assert_eq!(plan.total(), credit(120, 12));
    assert_eq!(
        plan.flows()
            .iter()
            .map(|flow| flow.credit.bytes)
            .sum::<u64>(),
        120
    );
    assert_eq!(
        plan.flows()
            .iter()
            .map(|flow| flow.credit.records)
            .sum::<u64>(),
        12
    );
    assert!(plan.flows().iter().all(|flow| flow.credit.bytes == 24));
    assert!(
        plan.flows()
            .iter()
            .all(|flow| (2..=3).contains(&flow.credit.records))
    );
    assert!(
        plan.flows()
            .windows(2)
            .all(|pair| pair[0].flow < pair[1].flow)
    );
    Ok(())
}

#[test]
fn scarce_record_remainders_rotate_without_creating_budget() -> Result<(), TargetError> {
    let mut settings = config();
    settings.initial = credit(100, 3);
    let mut controller = TargetController::new(settings, Micros(0))?;
    let flows = [FlowId(1), FlowId(2), FlowId(3), FlowId(4), FlowId(5)];
    let mut shares = [0; 5];
    for round in 0..5 {
        let now = Micros(round * 1_000);
        let plan = controller.update(now, measured(Credit::default()), &flows)?;
        assert_eq!(plan.total(), credit(100, 3));
        assert_eq!(
            plan.flows()
                .iter()
                .map(|flow| flow.credit.records)
                .sum::<u64>(),
            3
        );
        for (index, flow) in plan.flows().iter().enumerate() {
            shares[index] += flow.credit.records;
        }
        assert_eq!(
            controller
                .update(now, measured(Credit::default()), &flows)?
                .flows(),
            plan.flows()
        );
    }
    assert_eq!(shares, [3, 3, 3, 3, 3]);
    Ok(())
}

#[test]
fn bdp_memory_per_flow_and_policy_caps_all_apply() -> Result<(), TargetError> {
    let mut settings = config();
    settings.session_cap = credit(1_000, 100);
    settings.per_flow_cap = credit(150, 15);
    settings.policy_cap = credit(700, 70);
    let mut controller = TargetController::new(settings, Micros(0))?;
    let feedback = Feedback {
        delivery_bytes_per_second: Some(100_000),
        ..measured(credit(1_000, 100))
    };
    controller.update(Micros(0), feedback, &[FlowId(1)])?;
    assert_eq!(
        controller
            .update(Micros(1_000), feedback, &[FlowId(1)])?
            .total(),
        credit(110, 15)
    );
    controller.restart(Micros(2_000))?;
    let flows = [FlowId(1), FlowId(2), FlowId(3), FlowId(4), FlowId(5)];
    for round in 2..50 {
        let plan =
            controller.update(Micros(round * 1_000), measured(credit(1_600, 160)), &flows)?;
        assert!(plan.total().fits(settings.policy_cap));
        assert!(plan.total().fits(settings.session_cap));
        assert!(
            plan.flows()
                .iter()
                .all(|flow| flow.credit.fits(settings.per_flow_cap))
        );
    }
    assert_eq!(
        controller
            .update(Micros(50_000), measured(credit(1_600, 160)), &flows)?
            .total(),
        credit(700, 70)
    );
    Ok(())
}

#[test]
fn pressure_reduces_once_per_rtt_and_requires_quiet_recovery() -> Result<(), TargetError> {
    let mut controller = TargetController::new(config(), Micros(0))?;
    let flows = [FlowId(1)];
    controller.update(Micros(0), measured(credit(100, 10)), &flows)?;
    let pressured = Feedback {
        ecn: true,
        ..measured(credit(100, 10))
    };
    let reduced = controller.update(Micros(1), pressured, &flows)?;
    assert_eq!(reduced.total(), credit(50, 5));
    assert_eq!(reduced.state(), TargetState::Backpressure);
    assert_eq!(
        controller.update(Micros(2), pressured, &flows)?.total(),
        credit(50, 5)
    );
    assert_eq!(
        controller.update(Micros(1_001), pressured, &flows)?.total(),
        credit(25, 2)
    );
    assert_eq!(
        controller
            .update(Micros(2_000), measured(credit(100, 10)), &flows)?
            .state(),
        TargetState::Recovering
    );
    assert_eq!(
        controller
            .update(Micros(3_001), measured(credit(100, 10)), &flows)?
            .total(),
        credit(50, 4)
    );
    Ok(())
}

#[test]
fn queue_delay_requires_persistence_and_missing_estimates_cannot_grow() -> Result<(), TargetError> {
    let mut controller = TargetController::new(config(), Micros(0))?;
    let flows = [FlowId(1)];
    let delayed = Feedback {
        queue_delay_micros: 101,
        ..measured(credit(100, 10))
    };
    assert_eq!(
        controller.update(Micros(0), delayed, &flows)?.total(),
        credit(100, 10)
    );
    assert_eq!(
        controller.update(Micros(999), delayed, &flows)?.total(),
        credit(100, 10)
    );
    assert_eq!(
        controller.update(Micros(1_000), delayed, &flows)?.total(),
        credit(50, 5)
    );
    controller.restart(Micros(2_000))?;
    let unmeasured = Feedback {
        in_flight: credit(1_600, 160),
        ..Feedback::default()
    };
    controller.update(Micros(2_000), unmeasured, &flows)?;
    assert_eq!(
        controller
            .update(Micros(100_000), unmeasured, &flows)?
            .total(),
        credit(100, 10)
    );
    assert_eq!(
        controller
            .update(Micros(101_000), measured(Credit::default()), &[])?
            .total(),
        Credit::default()
    );
    // Idle time does not earn a catch-up growth step when demand returns.
    assert_eq!(
        controller
            .update(Micros(1_000_000), measured(credit(100, 10)), &flows)?
            .total(),
        credit(100, 10)
    );
    Ok(())
}

#[test]
fn invalid_observations_and_time_regression_do_not_mutate_policy() -> Result<(), TargetError> {
    let mut controller = TargetController::new(config(), Micros(10))?;
    let feedback = measured(credit(100, 10));
    controller.update(Micros(10), feedback, &[FlowId(1)])?;
    let baseline = controller.clone();
    assert_eq!(
        controller.update(Micros(9), feedback, &[FlowId(1)]),
        Err(TargetError::NonMonotonicTime)
    );
    assert_eq!(
        controller.update(Micros(1_000), feedback, &[FlowId(1), FlowId(1)]),
        Err(TargetError::DuplicateFlow)
    );
    assert_eq!(
        controller.update(
            Micros(1_000),
            Feedback {
                rtt_micros: Some(0),
                ..feedback
            },
            &[FlowId(1)]
        ),
        Err(TargetError::InvalidFeedback)
    );
    assert_eq!(
        controller.update(
            Micros(1_000),
            Feedback {
                rtt_micros: Some(u64::MAX),
                ..feedback
            },
            &[FlowId(1)]
        ),
        Err(TargetError::Overflow)
    );
    assert_eq!(controller.last_update, baseline.last_update);
    assert_eq!(controller.current, baseline.current);
    assert_eq!(
        controller
            .update(Micros(1_010), feedback, &[FlowId(1)])?
            .total(),
        credit(200, 20)
    );
    Ok(())
}

#[test]
fn caps_use_wide_arithmetic_and_configuration_bounds_work() -> Result<(), TargetError> {
    let mut settings = config();
    settings.session_cap = credit(u64::MAX, u64::MAX);
    settings.policy_cap = settings.session_cap;
    settings.per_flow_cap = settings.session_cap;
    let mut controller = TargetController::new(settings, Micros(0))?;
    let feedback = Feedback {
        rtt_micros: Some(u64::MAX / 2),
        delivery_bytes_per_second: Some(u64::MAX),
        in_flight: settings.session_cap,
        ..Feedback::default()
    };
    controller.update(Micros(0), feedback, &[FlowId(1), FlowId(2)])?;
    assert_eq!(
        controller
            .update(Micros(u64::MAX / 2), feedback, &[FlowId(1), FlowId(2)])?
            .total(),
        credit(200, 20)
    );
    settings.few_flow_threshold = 5;
    assert!(matches!(
        TargetController::new(settings, Micros(0)),
        Err(TargetError::InvalidConfig)
    ));
    let mut controller = TargetController::new(config(), Micros(0))?;
    let too_many: Vec<_> = (0..17).map(FlowId).collect();
    assert_eq!(
        controller.update(Micros(0), measured(credit(100, 10)), &too_many),
        Err(TargetError::TooManyFlows)
    );
    Ok(())
}

#[test]
fn pressure_never_revokes_grants_and_record_overshoot_cannot_deadlock_bytes()
-> Result<(), Box<dyn std::error::Error>> {
    let scope = Scope {
        session: 1,
        epoch: 1,
        direction: Direction::Forward,
    };
    let capacity = Capacity {
        credit: credit(1_600, 160),
        max_flows: 1,
    };
    let mut receiver = ReceiverCredits::new(scope, capacity)?;
    let mut sender = SenderCredits::new(scope, capacity)?;
    let flow = FlowId(1);
    receiver.open_flow(flow)?;
    sender.open_flow(flow)?;
    let mut controller = TargetController::new(config(), Micros(0))?;
    let initial = controller.update(Micros(0), measured(credit(100, 10)), &[flow])?;
    let granted = receiver.grant_to_target(flow, initial.flows()[0].credit, initial.total())?;
    sender.apply_grant(granted)?;
    let record = sender.admit(flow, 100)?;
    let reduced = controller.update(
        Micros(1),
        Feedback {
            receiver_pressure: true,
            ..measured(credit(100, 1))
        },
        &[flow],
    )?;
    assert_eq!(reduced.total(), credit(50, 5));
    assert_eq!(
        receiver.grant_to_target(flow, reduced.flows()[0].credit, reduced.total())?,
        granted
    );
    assert_eq!(receiver.reserved(), credit(100, 10));
    receiver.receive(record)?;
    sender.apply_release(receiver.release_next(flow)?)?;
    assert_eq!(receiver.reserved(), credit(0, 9));
    // Unrevocable record promises exceed the new count target. Byte replenishment
    // must still let the peer consume those promises without count inflation.
    let replenished = receiver.grant_to_target(flow, reduced.flows()[0].credit, reduced.total())?;
    assert_eq!(replenished.flow_limit, credit(150, 10));
    assert_eq!(receiver.reserved(), credit(50, 9));
    sender.apply_grant(replenished)?;
    sender.admit(flow, 50)?;
    Ok(())
}

#[test]
fn sender_exhaustion_replenishes_after_release_without_growth_or_new_arrival()
-> Result<(), Box<dyn std::error::Error>> {
    let scope = Scope {
        session: 2,
        epoch: 1,
        direction: Direction::Forward,
    };
    let mut settings = config();
    settings.initial = credit(100, 1);
    let capacity = Capacity {
        credit: settings.session_cap,
        max_flows: 1,
    };
    let mut receiver = ReceiverCredits::new(scope, capacity)?;
    let mut sender = SenderCredits::new(scope, capacity)?;
    let flow = FlowId(1);
    receiver.open_flow(flow)?;
    sender.open_flow(flow)?;
    let mut controller = TargetController::new(settings, Micros(0))?;
    let plan = controller.update(Micros(0), measured(credit(100, 1)), &[flow])?;
    sender.apply_grant(receiver.grant_to_target(flow, plan.flows()[0].credit, plan.total())?)?;
    let record = sender.admit(flow, 100)?;
    assert_eq!(
        sender.admit(flow, 1),
        Err(CreditError::SenderExhausted(LimitDomain::Flow))
    );
    receiver.receive(record)?;
    sender.apply_release(receiver.release_next(flow)?)?;
    let plan = controller.update(
        Micros(1),
        Feedback {
            sender_credit_exhausted: true,
            ..measured(Credit::default())
        },
        &[flow],
    )?;
    assert_eq!(plan.total(), credit(100, 1));
    assert_eq!(plan.state(), TargetState::Steady);
    sender.apply_grant(receiver.grant_to_target(flow, plan.flows()[0].credit, plan.total())?)?;
    sender.admit(flow, 100)?;
    Ok(())
}
