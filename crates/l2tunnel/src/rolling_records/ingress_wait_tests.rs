//! Actual ingress and decoder owners; no fabricated Busy or deadline renewal.
use super::*;
use crate::record_engine::EmissionKind;
use crate::rolling_records::waits::ingress::Outcome;

fn queued_observed<P: RecoveryPolicy>(config: Config<P>, enabled: bool) -> TestResult<Endpoint<P>> {
    let mut ingress = IngressLimits {
        slots: 3,
        capacity_bytes: usize::MAX,
    };
    ingress.capacity_bytes = ingress.required_capacity(config.forward.maximum_packet_bytes()?)?;
    let plain = storage::Plan::for_endpoint_with_options(
        config,
        context(Role::Server),
        17,
        Tick(0),
        CopyPolicies::ONE,
        Some(ingress),
    )?;
    let plan = if enabled {
        plain.with_wait_diagnostics()?
    } else {
        plain
    };
    if enabled {
        assert_eq!(
            plan.capacity_bytes() - plain.capacity_bytes(),
            std::mem::size_of::<waits::Snapshot>()
        );
        assert!(matches!(
            Endpoint::new_reserved(
                plan,
                storage::Limits {
                    capacity_bytes: plain.capacity_bytes()
                }
            ),
            Err(Error::Capacity { .. })
        ));
    }
    let mut owner = Endpoint::new_reserved(
        plan,
        storage::Limits {
            capacity_bytes: plan.capacity_bytes(),
        },
    )?;
    assert_eq!(
        owner
            .storage_usage()
            .ok_or("actual planned usage")?
            .capacity_bytes,
        plan.capacity_bytes()
    );
    assert_eq!(owner.waits.capacity(), usize::from(enabled));
    owner.enable_compact_wire(85)?;
    Ok(owner)
}
fn selected_sender<P: RecoveryPolicy>(config: Config<P>) -> TestResult<Endpoint<P>> {
    let mut sender = observed(config, Role::Client)?;
    sender.enable_compact_wire(53)?;
    Ok(sender)
}
fn source<P: RecoveryPolicy>(
    sender: &mut Endpoint<P>,
    at: u64,
    value: u8,
) -> TestResult<(PreparedOutput, Vec<u8>)> {
    sender
        .enqueue_admitted_identified(Tick(at), 0, &packet(true, value, 48))?
        .ok_or("actual native source")?;
    sender.flush(Tick(at))?;
    let out = output(sender, Tick(at))?;
    sender.confirm_output(Tick(at), out.0)?;
    Ok(out)
}
fn data_wait<P: RecoveryPolicy>(config: Config<P>, duplicate: bool) -> TestResult {
    let mut sender = selected_sender(config)?;
    let first = source(&mut sender, 1, 1)?;
    let second = if duplicate {
        first.clone()
    } else {
        source(&mut sender, 2, 2)?
    };
    let mut owner = queued_observed(config, true)?;
    let original_usage = owner.storage_usage();
    for (at, pn, value) in [(1, 71, &first), (2, 72, &second)] {
        owner.accept_authenticated_until(
            Tick(at),
            Tick(at),
            Tick(900_000),
            Some(pn),
            value.0.kind,
            &value.1,
        )?;
    }
    let empty = owner
        .wait_snapshot(Tick(2))
        .ok_or("observed")?
        .ingress_admission
        .ok_or("ingress")?;
    assert_eq!(empty.refusals, 0); // Queue residence alone is not a refusal.
    owner.step(
        Tick(10),
        rolling::WorkBudget {
            field: 1,
            copies: 1,
            metadata: 1,
        },
    )?;
    let blocker = P::receive_expiry(&owner.incoming)
        .decoder_job
        .ok_or("actual partial decoder job")?;
    assert_eq!(
        owner.ingress_status().ok_or("queue")?.oldest_records_number,
        Some(72)
    );
    owner.step(Tick(11), rolling::WorkBudget::default())?;
    owner.step(Tick(12), rolling::WorkBudget::default())?;
    let waiting = owner
        .wait_snapshot(Tick(12))
        .ok_or("observed")?
        .ingress_admission
        .ok_or("ingress")?;
    let pending = waiting.pending.ok_or("actual head Busy")?;
    assert_eq!(pending.serial, 2);
    assert_eq!(pending.input.records_number, Some(72));
    assert_eq!(pending.input.received, Tick(2));
    assert_eq!(pending.input.deadline, Tick(900_000));
    assert_eq!(pending.since, Tick(11));
    assert_eq!(pending.last_refusal, Tick(12));
    assert_eq!(pending.first_blocker, Some(blocker));
    assert_eq!(waiting.completions, [1, 0, 0]);
    assert_eq!(waiting.without_refusal, [1, 0, 0]);
    for _ in 0..64 {
        if owner.ingress_status().ok_or("queue")?.packets == 0 {
            break;
        }
        owner.step(Tick(20), work())?;
    }
    assert_eq!(owner.ingress_status().ok_or("drained queue")?.packets, 0);
    let full = owner.wait_snapshot(Tick(20)).ok_or("observed")?;
    let done = full.ingress_admission.ok_or("ingress")?;
    let resolved = done.last_resolved.ok_or("same head completed")?;
    let outcome = if duplicate {
        Outcome::Duplicate
    } else {
        Outcome::Staged
    };
    assert_eq!(resolved.outcome, Some(outcome));
    assert_eq!(resolved.pending.input, pending.input);
    assert_eq!(resolved.pending.serial, pending.serial);
    assert_eq!(resolved.pending.since, Tick(11));
    assert_eq!(done.populations[outcome.index()].elapsed_us, 9);
    assert_eq!(done.populations[outcome.index()].episodes, 1);
    assert_eq!(done.next_head, 3);
    if duplicate {
        assert!(resolved.admitted_job.is_none());
    } else {
        let admitted = resolved.admitted_job.ok_or("actual new job")?;
        assert_ne!(admitted.identity, blocker.identity);
        assert_eq!(admitted.received, rolling::Tick(2));
        assert_eq!(admitted.admitted, rolling::Tick(20));
        assert_eq!(admitted.deadline, rolling::Tick(900_000));
    }
    assert!(!full.identity_mismatch && !full.clock_regression && !full.overflow);
    assert_eq!(owner.storage_usage(), original_usage);
    Ok(())
}
#[test]
fn actual_rolling_research_ingress_busy_tracks_same_head_and_distinct_completion() -> TestResult {
    let config = config(true, rolling::wire::SourceWire::Exact);
    for duplicate in [false, true] {
        data_wait(config, duplicate)?;
        data_wait(research_config(config), duplicate)?;
    }
    Ok(())
}
#[test]
fn actual_stale_repair_completion_is_not_new_decoder_admission() -> TestResult {
    let mut config = config(true, rolling::wire::SourceWire::Exact);
    config.forward.scheduler.repair_numerator = 1;
    config.forward.scheduler.repair_denominator = 1;
    let mut sender = selected_sender(config)?;
    let first = source(&mut sender, 1, 1)?;
    for _ in 0..64 {
        sender.step(Tick(2), work())?;
    }
    let repair = output(&mut sender, Tick(2))?;
    assert_eq!(repair.0.kind, EmissionKind::Repair);
    let mut owner = queued_observed(config, true)?;
    for (at, pn, value) in [(1, 71, &first), (2, 72, &repair)] {
        owner.accept_authenticated_until(
            Tick(at),
            Tick(at),
            Tick(900_000),
            Some(pn),
            value.0.kind,
            &value.1,
        )?;
    }
    owner.step(
        Tick(10),
        rolling::WorkBudget {
            field: 1,
            copies: 1,
            metadata: 1,
        },
    )?;
    owner.step(Tick(11), rolling::WorkBudget::default())?;
    assert!(
        owner
            .wait_snapshot(Tick(11))
            .ok_or("snapshot")?
            .ingress_admission
            .ok_or("ingress")?
            .pending
            .is_some()
    );
    for _ in 0..64 {
        if owner.ingress_status().ok_or("queue")?.packets == 0 {
            break;
        }
        owner.step(Tick(20), work())?;
    }
    assert_eq!(owner.ingress_status().ok_or("queue")?.packets, 0);
    let done = owner
        .wait_snapshot(Tick(20))
        .ok_or("snapshot")?
        .ingress_admission
        .ok_or("ingress")?;
    let resolved = done.last_resolved.ok_or("stale repair")?;
    assert_eq!(resolved.outcome, Some(Outcome::Stale));
    assert!(resolved.admitted_job.is_none());
    assert_eq!(done.populations[2].episodes, 1);
    assert_eq!(done.populations[2].elapsed_us, 9);
    Ok(())
}
#[test]
fn actual_ingress_expiry_and_stale_sample_do_not_fabricate_progress() -> TestResult {
    let config = config(true, rolling::wire::SourceWire::Exact);
    let mut sender = selected_sender(config)?;
    let first = source(&mut sender, 1, 1)?;
    let mut owner = queued_observed(config, true)?;
    owner.accept_authenticated_until(
        Tick(1),
        Tick(1),
        Tick(1000),
        Some(71),
        first.0.kind,
        &first.1,
    )?;
    owner.accept_authenticated_until(
        Tick(2),
        Tick(2),
        Tick(15),
        Some(72),
        first.0.kind,
        &first.1,
    )?;
    owner.step(
        Tick(10),
        rolling::WorkBudget {
            field: 1,
            copies: 1,
            metadata: 1,
        },
    )?;
    owner.step(Tick(11), rolling::WorkBudget::default())?;
    let original = owner.wait_snapshot(Tick(11)).ok_or("snapshot")?;
    let stale = original
        .censor(Tick(12), Terminal::MetricStop)
        .ingress_admission
        .ok_or("ingress")?;
    assert!(stale.terminal_unavailable && stale.pending.is_some());
    assert_eq!(stale.populations[3].episodes, 0);
    assert_eq!(stale.terminal_at, None);
    assert_eq!(owner.tick(Tick(15)), Err(Error::Expired));
    let failed = owner.wait_snapshot(Tick(100)).ok_or("failed snapshot")?;
    assert_eq!(failed.terminal, Some((Tick(15), Terminal::OwnerFailure)));
    let failed = failed.ingress_admission.ok_or("ingress")?;
    assert_eq!(failed.terminal_at, Some(Tick(15)));
    assert_eq!(failed.populations[3].episodes, 1);
    assert_eq!(failed.populations[3].elapsed_us, 4);
    assert_eq!(
        failed.last_resolved.ok_or("censored identity")?.outcome,
        None
    );
    assert_eq!(failed.completions, [1, 0, 0]);
    let disabled = queued_observed(config, false)?;
    assert!(disabled.wait_snapshot(Tick(0)).is_none());
    assert!(
        observed(config, Role::Server)?
            .wait_snapshot(Tick(0))
            .ok_or("snapshot")?
            .ingress_admission
            .is_none()
    );
    Ok(())
}
