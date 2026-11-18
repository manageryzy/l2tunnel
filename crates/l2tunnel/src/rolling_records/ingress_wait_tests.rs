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
    let blocker = P::receive_expiry(&owner.incoming)
        .decoder_job
        .ok_or("actual partial decoder job")?;
    owner.step(
        Tick(10),
        rolling::WorkBudget {
            field: 1,
            copies: 1,
            metadata: 1,
        },
    )?;

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
    assert_eq!(pending.serial, 1);
    assert_eq!(pending.input.records_number, Some(72));
    assert_eq!(pending.input.received, Tick(2));
    assert_eq!(pending.input.deadline, Tick(900_000));
    assert_eq!(pending.since, Tick(10));
    assert_eq!(pending.last_refusal, Tick(10));
    assert_eq!(waiting.refusals, 1);
    assert_eq!(pending.first_blocker, Some(blocker));
    assert_eq!(waiting.completions, [0, 0, 0]);
    assert_eq!(waiting.without_refusal, [0, 0, 0]);
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
    assert_eq!(resolved.pending.since, Tick(10));
    assert_eq!(done.populations[outcome.index()].elapsed_us, 10);
    assert_eq!(done.populations[outcome.index()].episodes, 1);
    assert_eq!(done.next_head, 2);
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
fn actual_ingress_residence_includes_wait_before_first_busy_and_censored_tail() -> TestResult {
    let config = config(true, rolling::wire::SourceWire::Exact);
    let mut sender = selected_sender(config)?;
    let first = source(&mut sender, 1, 1)?;
    let second = source(&mut sender, 2, 2)?;
    let mut owner = queued_observed(config, true)?;
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
    owner.step(
        Tick(3),
        rolling::WorkBudget {
            field: 1,
            copies: 1,
            metadata: 1,
        },
    )?;
    let sample = owner.wait_snapshot(Tick(100_002)).ok_or("snapshot")?;
    let censored = sample.censor(Tick(100_002), Terminal::MetricStop);
    let held = censored.ingress_admission.ok_or("ingress")?.residence;
    let ages = held.retained_ages.ok_or("actual queued data")?;
    assert_eq!(ages.count, 1);
    assert_eq!(ages.maximum_us, 100_000);
    assert_eq!(ages.at_least_100ms, 1);
    assert_eq!(held.retained_at, Some(Tick(100_002)));
    assert_eq!(held.all.count, 1); // Censoring never fabricates successful removal.
    for _ in 0..64 {
        if owner.ingress_status().ok_or("queue")?.packets == 0 {
            break;
        }
        owner.step(Tick(110_002), work())?;
    }
    assert_eq!(owner.ingress_status().ok_or("queue")?.packets, 0);
    let snapshot = owner.wait_snapshot(Tick(110_002)).ok_or("snapshot")?;
    let residence = snapshot.ingress_admission.ok_or("ingress")?.residence;
    assert_eq!(residence.all.count, 2);
    assert_eq!(residence.immediate.count, 1);
    assert_eq!(residence.queued.count, 1);
    assert_eq!(residence.queued.maximum_us, 110_000);
    assert_eq!(residence.queued.at_least_100ms, 1);
    assert_eq!(residence.all.p99_upper_us(), Some(131_071));
    assert_eq!(residence.retained_ages.ok_or("empty fresh queue")?.count, 0);
    assert!(!snapshot.overflow && !snapshot.clock_regression);
    Ok(())
}

#[test]
fn actual_direct_ingress_residence_keeps_original_receive_age() -> TestResult {
    let config = config(true, rolling::wire::SourceWire::Exact);
    let mut sender = selected_sender(config)?;
    let first = source(&mut sender, 1, 1)?;
    let mut owner = queued_observed(config, true)?;
    owner.accept_authenticated_until(
        Tick(1),
        Tick(100_001),
        Tick(900_000),
        Some(71),
        first.0.kind,
        &first.1,
    )?;
    assert_eq!(owner.ingress_status().ok_or("queue")?.packets, 0);
    let snapshot = owner.wait_snapshot(Tick(100_001)).ok_or("snapshot")?;
    let residence = snapshot.ingress_admission.ok_or("ingress")?.residence;
    assert_eq!(residence.all.count, 1);
    assert_eq!(residence.immediate.count, 1);
    assert_eq!(residence.immediate.sum_us, 100_000);
    assert_eq!(residence.immediate.at_least_100ms, 1);
    assert_eq!(residence.queued.count, 0);
    assert!(!snapshot.overflow && !snapshot.clock_regression);
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
    assert_eq!(done.populations[2].elapsed_us, 10);
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
    assert_eq!(failed.populations[3].elapsed_us, 5);
    assert_eq!(
        failed.last_resolved.ok_or("censored identity")?.outcome,
        None
    );
    assert_eq!(failed.completions, [0, 0, 0]);
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

fn queued_work_stops_at_native_capacity<P: RecoveryPolicy>(config: Config<P>) -> TestResult {
    let mut sender = selected_sender(config)?;
    let first = source(&mut sender, 1, 1)?;
    let second = source(&mut sender, 2, 2)?;
    let mut owner = queued_observed(config, true)?;
    let usage = owner.storage_usage();
    assert!(!owner.work_pending());
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
    assert!(owner.work_pending());
    let job = P::receive_expiry(&owner.incoming)
        .decoder_job
        .ok_or("real partial job")?;
    owner.step(
        Tick(10),
        rolling::WorkBudget {
            field: 1,
            copies: 1,
            metadata: 1,
        },
    )?;

    assert!(owner.work_pending());
    owner.step(Tick(11), rolling::WorkBudget::default())?;
    let refused = owner
        .wait_snapshot(Tick(11))
        .ok_or("snapshot")?
        .ingress_admission
        .ok_or("ingress")?
        .pending
        .ok_or("real Busy head")?;
    assert_eq!(refused.first_blocker, Some(job));
    assert_eq!(refused.input.records_number, Some(72));
    assert_eq!(refused.input.received, Tick(2));
    assert_eq!(refused.input.deadline, Tick(900_000));
    // Complete computation without consuming the already decoded native head.
    // The second decoded source must then wait for actual record capacity,
    // rather than requesting endless cooperative computation turns.
    for _ in 0..64 {
        owner.step(Tick(20), work())?;
    }
    assert_eq!(owner.ingress_status().ok_or("ingress")?.packets, 0);
    assert!(P::receive_expiry(&owner.incoming).decoder_job.is_none());
    let snapshot = owner.wait_snapshot(Tick(20)).ok_or("snapshot")?;
    let held = snapshot.sites[Site::DecodedHandoff.index()]
        .pending
        .ok_or("native capacity")?;
    assert_eq!(held.operation.id, 1);
    assert!(!owner.work_pending());
    let completed = snapshot
        .ingress_admission
        .ok_or("ingress")?
        .last_resolved
        .ok_or("same Busy head completed")?;
    assert_eq!(completed.pending.input, refused.input);
    assert_eq!(completed.outcome, Some(Outcome::Staged));
    let mut native = [0; 1024];
    let mut committed = false;
    for _ in 0..8 {
        if let NativePreparation::Ready(prepared) =
            owner.prepare_native(Tick(30), 16, Tick(10_000), &mut native)?
        {
            owner.commit_native(Tick(30), prepared.token())?;
            committed = true;
            break;
        }
    }
    assert!(committed);
    for _ in 0..16 {
        owner.step(Tick(31), work())?;
    }
    let after = owner.wait_snapshot(Tick(31)).ok_or("released")?;
    let handoff = after.sites[Site::DecodedHandoff.index()];
    assert!(handoff.pending.is_none());
    assert_eq!(
        handoff
            .last_resolved
            .ok_or("same source advanced")?
            .operation,
        held.operation
    );
    assert_eq!(owner.storage_usage(), usage);
    Ok(())
}

#[test]
fn queued_rolling_and_research_work_does_not_spin_on_native_handoff_pressure() -> TestResult {
    let mut config = config(true, rolling::wire::SourceWire::Exact);
    for direction in [&mut config.forward, &mut config.reverse] {
        direction.receiver.lookahead_records = 0;
        direction.receiver.body.independent_short_frame_bytes = 0;
        direction.packing.sender.body = direction.receiver.body;
    }
    queued_work_stops_at_native_capacity(config)?;
    queued_work_stops_at_native_capacity(research_config(config))
}
