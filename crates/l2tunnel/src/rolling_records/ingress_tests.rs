//! Real reserved decoder input custody; no socket/native-platform qualification.
use super::*;

fn queued(config: Config, slots: usize) -> TestResult<(Endpoint, storage::Usage)> {
    let maximum = config.forward.maximum_packet_bytes()?;
    let mut ingress = IngressLimits {
        slots,
        capacity_bytes: usize::MAX,
    };
    ingress.capacity_bytes = ingress.required_capacity(maximum)?;
    let short = IngressLimits {
        capacity_bytes: ingress.capacity_bytes - 1,
        ..ingress
    };
    assert!(matches!(
        short.required_capacity(maximum),
        Err(Error::Ingress(crate::native_storage::Error::Limit { .. }))
    ));
    let old = storage::Plan::for_endpoint(config, context(Role::Server), 17, Tick(0))?;
    let plan = storage::Plan::for_endpoint_with_options(
        config,
        context(Role::Server),
        17,
        Tick(0),
        CopyPolicies::ONE,
        Some(ingress),
    )?;
    assert_eq!(
        plan.capacity_bytes(),
        old.capacity_bytes() + ingress.capacity_bytes
    );
    let endpoint = Endpoint::new_reserved(
        plan,
        storage::Limits {
            capacity_bytes: plan.capacity_bytes(),
        },
    )?;
    let usage = endpoint
        .storage_usage()
        .ok_or("actual queue/decoder heap")?;
    assert_eq!(usage.capacity_bytes, plan.capacity_bytes());
    Ok((endpoint, usage))
}

#[test]
fn busy_decoder_requests_only_holes_outside_authenticated_fifo_custody() -> TestResult {
    let mut config = short_config(0, rolling::wire::SourceWire::TargetedExact);
    config.forward.scheduler.repair_numerator = 0;
    config.forward.scheduler.feedback_packets = 64;
    let mut sender = endpoint(config, Role::Client)?;
    sender.enable_queue_aware_repair_budget(1500)?;
    let mut serial = 1;
    let mut packets = Vec::new();
    for source in 0u32..4 {
        sender
            .enqueue_admitted_identified(Tick(0), 0, &packet(true, source as u8, 80))?
            .ok_or("admitted frame")?;
        sender.flush(Tick(0))?;
        sender.step(Tick(0), work())?;
        let (prepared, data) =
            emit(&mut sender, Tick(0), &mut serial, true)?.ok_or("systematic source")?;
        assert_eq!(
            prepared.id,
            OutputId::Data(scheduler::OutputId::Source(rolling::SourceId(source)))
        );
        packets.push(data);
    }
    let (mut receiver, _) = queued(config, 1)?;
    receiver.accept_authenticated(Tick(0), packets[3].kind, &packets[3].bytes)?;
    receiver.accept_authenticated(Tick(1), packets[0].kind, &packets[0].bytes)?;
    assert_eq!(
        receiver.accept_authenticated(Tick(1), packets[1].kind, &packets[1].bytes),
        Err(Error::Busy)
    );
    let queued = receiver.ingress_status().ok_or("queue")?;
    assert_eq!(queued.packets, 1);
    assert_eq!(queued.full_refusals, [1, 0, 0]);
    // Observe the real receiver between the decoder grant and its next FIFO
    // handoff. The arrived original cannot advance the authenticated prefix.
    receiver.incoming.step(rolling::Tick(1), work())?;
    receiver.incoming.step(rolling::Tick(2_001), work())?;
    let requested = receiver
        .incoming
        .pending_request()
        .ok_or("actual gap request")?;
    assert_eq!(
        (requested.start, requested.mask, requested.prefix),
        (1, 3, 0)
    );
    assert_eq!(
        receiver.ingress_status().ok_or("held source")?.deadline,
        queued.deadline
    );
    receiver
        .incoming
        .confirm_feedback(requested.id, rolling::Tick(2_001))?;
    receiver.step(Tick(2_002), work())?;
    assert_eq!(
        receiver.ingress_status().ok_or("released source")?.packets,
        0
    );
    assert_eq!(receiver.receiver_status().decoder.decoded_prefix, 1);
    Ok(())
}

#[test]
fn actual_queue_retains_busy_input_exact_bytes_and_original_age_until_decoder_ownership()
-> TestResult {
    let config = short_config(64, rolling::wire::SourceWire::Exact);
    let (old_wire, short_wire, old_id, short_id, old, short) = originals(config)?;
    let (mut receiver, usage) = queued(config, 1)?;
    receiver.accept_authenticated_until(
        Tick(6),
        Tick(6),
        Tick(9_000_000),
        Some(71),
        short_wire.kind,
        &short_wire.bytes,
    )?;
    receiver.accept_authenticated_until(
        Tick(7),
        Tick(7),
        Tick(8_000_000),
        Some(72),
        old_wire.kind,
        &old_wire.bytes,
    )?;
    let full = receiver.ingress_status().ok_or("actual ingress")?;
    assert!(receiver.receiver_status().decoder.pending_job);
    assert_eq!(full.packets, 1);
    assert_eq!(full.bytes, old_wire.bytes.len());
    assert_eq!(full.oldest_received, Some(Tick(7)));
    assert_eq!(full.oldest_records_number, Some(72));
    assert_eq!(full.deadline, Some(Tick(1_000_007)));
    assert!(!receiver.drained());
    assert_eq!(
        receiver.accept_authenticated_until(
            Tick(7),
            Tick(7),
            Tick(8_000_000),
            Some(73),
            short_wire.kind,
            &short_wire.bytes
        ),
        Err(Error::Busy)
    );
    assert_eq!(
        receiver.ingress_status(),
        Some(IngressStatus {
            full_refusals: [1, 0, 0],
            ..full
        })
    );
    let one = receiver.step(
        Tick(9),
        rolling::WorkBudget {
            field: 1,
            copies: 1,
            metadata: 1,
        },
    )?;
    assert!(
        one.receive.work.field <= 1
            && one.receive.work.copies <= 1
            && one.receive.work.metadata <= 1
    );
    let held = receiver.ingress_status().ok_or("retained input")?;
    assert_eq!(held.packets, 1);
    assert_eq!(held.bytes, old_wire.bytes.len());
    assert_eq!(held.oldest_received, Some(Tick(7)));
    assert_eq!(held.oldest_records_number, Some(72));
    assert!(receiver.receiver_status().decoder.pending_job);
    service_until(&mut receiver, Tick(9), |owner| {
        owner
            .ingress_status()
            .is_some_and(|state| state.packets == 0)
            && owner.receiver_status().decoder.handoff_prefix == 2
    })?;
    let mut output = [0; 1024];
    for (identity, bytes) in [(old_id, old), (short_id, short)] {
        let native = ready(&mut receiver, Tick(9), &mut output)?;
        assert_eq!(native.identity(), identity);
        assert_eq!(&output[..native.bytes()], bytes);
        receiver.commit_native(Tick(9), native.token())?;
    }
    assert_eq!(receiver.statistics().committed, 2);
    assert_eq!(receiver.storage_usage(), Some(usage));
    assert_eq!(
        receiver
            .ingress_status()
            .ok_or("empty actual ingress")?
            .bytes,
        0
    );
    Ok(())
}

#[test]
fn targeted_committed_copy_crosses_full_input_queue_without_displacing_fresh_work() -> TestResult {
    let mut config = short_config(0, rolling::wire::SourceWire::TargetedExact);
    config.forward.scheduler.repair_numerator = 0;
    let (old_wire, short_wire, old_id, short_id, old, short) = originals(config)?;
    for conflict in [false, true] {
        let (mut receiver, _) = queued(config, 1)?;
        receiver.accept_authenticated(Tick(1), old_wire.kind, &old_wire.bytes)?;
        service_until(&mut receiver, Tick(1), |owner| {
            owner.receiver_status().decoder.handoff_prefix == 1
        })?;
        receiver.accept_authenticated(Tick(2), short_wire.kind, &short_wire.bytes)?;
        receiver.accept_authenticated(Tick(2), short_wire.kind, &short_wire.bytes)?;
        let full = receiver.ingress_status().ok_or("actual queue")?;
        assert_eq!(full.packets, 1);
        assert!(receiver.receiver_status().decoder.pending_job);
        let events = receiver.receiver_status().feedback_events;
        let mut bytes = old_wire.bytes.clone();
        if conflict {
            *bytes.last_mut().ok_or("nonempty original")? ^= 1;
            assert_eq!(
                receiver.accept_authenticated(Tick(2), old_wire.kind, &bytes),
                Err(Error::Rolling(rolling::Error::Conflict))
            );
            assert!(receiver.failure().is_some());
            continue;
        }
        receiver.accept_authenticated(Tick(2), old_wire.kind, &bytes)?;
        assert_eq!(receiver.ingress_status(), Some(full));
        assert_eq!(receiver.receiver_status().feedback_events, events + 1);
        service_until(&mut receiver, Tick(2), |owner| {
            owner
                .ingress_status()
                .is_some_and(|queue| queue.packets == 0)
                && owner.receiver_status().decoder.handoff_prefix == 2
        })?;
        let mut output = [0; 1024];
        for (identity, expected) in [(old_id, &old), (short_id, &short)] {
            let native = ready(&mut receiver, Tick(2), &mut output)?;
            assert_eq!(native.identity(), identity);
            assert_eq!(&output[..native.bytes()], expected.as_slice());
            receiver.commit_native(Tick(2), native.token())?;
        }
        assert_eq!(receiver.statistics().committed, 2);
    }
    Ok(())
}

#[test]
fn queued_targeted_burst_shares_one_grant_and_yields_for_feedback_and_native() -> TestResult {
    for feedback_packets in [2, 64] {
        let mut config = short_config(0, rolling::wire::SourceWire::TargetedExact);
        config.forward.scheduler.repair_numerator = 0;
        config.forward.scheduler.feedback_packets = feedback_packets;
        let (old, later, _, _, _, _) = originals(config)?;
        let (mut receiver, _) = queued(config, 12)?;
        // The entire out-of-order train arrives before its first copy commits.
        for _ in 0..10 {
            receiver.accept_authenticated(Tick(1), later.kind, &later.bytes)?;
        }
        receiver.step(Tick(1), work())?;
        let before = receiver.ingress_status().ok_or("actual queue")?.packets;
        let step = receiver.step_queued(Tick(1), work())?;
        let after = receiver.ingress_status().ok_or("actual queue")?.packets;
        assert!(step.receive.work.field <= work().field);
        assert!(step.receive.work.copies <= work().copies);
        assert!(step.receive.work.metadata <= work().metadata);
        if feedback_packets == 2 {
            assert!(step.receive.feedback_ready);
            assert_eq!(before - after, 1);
        } else {
            assert!(!step.receive.feedback_ready);
            assert!(step.native_progress);
            assert_eq!(before - after, 1);
            let next = receiver.step_queued(Tick(1), work())?;
            assert!(!next.native_progress && !next.source_handed && !next.receive.feedback_ready);
            assert_eq!(
                after - receiver.ingress_status().ok_or("actual queue")?.packets,
                config.forward.packing.work_limit
            );
            let unit = rolling::WorkBudget {
                field: 0,
                copies: 0,
                metadata: 1,
            };
            let constrained = receiver.step_queued(Tick(1), unit)?;
            assert_eq!(constrained.receive.work.field, 0);
            assert_eq!(constrained.receive.work.copies, 0);
            assert!(constrained.receive.work.metadata <= 1);
        }
        receiver.accept_authenticated(Tick(1), old.kind, &old.bytes)?;
        let mut handed = 0;
        for _ in 0..20 {
            let prior = receiver.receiver_status().decoder.handoff_prefix;
            let step = receiver.step_queued(Tick(1), work())?;
            let new = receiver.receiver_status().decoder.handoff_prefix;
            assert_eq!(new - prior, u32::from(step.source_handed));
            handed += u32::from(step.source_handed);
            if new == 2 {
                break;
            }
        }
        assert_eq!(handed, 2);
    }
    Ok(())
}

#[test]
fn queued_and_started_input_preserve_original_caller_cap_without_timer_renewal() -> TestResult {
    let config = short_config(64, rolling::wire::SourceWire::Exact);
    let (_, wire, _, _, _, _) = originals(config)?;
    for start in [false, true] {
        let (mut receiver, usage) = queued(config, 1)?;
        if !start {
            receiver.accept_authenticated_until(
                Tick(5),
                Tick(5),
                Tick(1000),
                Some(90),
                wire.kind,
                &wire.bytes,
            )?;
        }
        receiver.accept_authenticated_until(
            Tick(6),
            Tick(6),
            Tick(11),
            Some(91),
            wire.kind,
            &wire.bytes,
        )?;
        assert_eq!(receiver.deadline(), Some(Tick(11)));
        if start {
            receiver.step(
                Tick(9),
                rolling::WorkBudget {
                    field: 1,
                    copies: 1,
                    metadata: 1,
                },
            )?;
            assert_eq!(receiver.ingress_status().ok_or("actual input")?.packets, 0);
            assert!(receiver.receiver_status().decoder.pending_job);
            assert_eq!(receiver.deadline(), Some(Tick(11)));
        }
        assert!(receiver.tick(Tick(11)).is_err());
        assert!(receiver.failure().is_some());
        assert!(receiver.tick(Tick(10)).is_err());
        assert!(!receiver.drained());
        assert_eq!(receiver.storage_usage(), Some(usage));
    }
    Ok(())
}
