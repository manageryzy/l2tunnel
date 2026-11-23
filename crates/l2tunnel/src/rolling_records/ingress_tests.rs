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

fn targeted_sources() -> TestResult<(Config, Vec<Datagram>)> {
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
    Ok((config, packets))
}
#[test]
fn coalesced_targeted_source_preserves_custody_and_makes_room_for_the_next_original() -> TestResult
{
    let (config, packets) = targeted_sources()?;
    let (mut receiver, usage) = queued(config, 2)?;
    let receive = |receiver: &mut Endpoint, at, pn, index: usize, cap| {
        let wire = &packets[index];
        receiver.accept_authenticated_until(
            Tick(at),
            Tick(at),
            Tick(cap),
            Some(pn),
            wire.kind,
            &wire.bytes,
        )
    };
    receive(&mut receiver, 0, 10, 3, 8000)?;
    receive(&mut receiver, 1, 11, 0, 7000)?;
    let before = receiver.ingress_status().ok_or("retained source")?;
    receive(&mut receiver, 2, 12, 0, 9000)?;
    assert_eq!(
        receiver.ingress_status(),
        Some(IngressStatus {
            coalesced_sources: 1,
            ..before
        })
    );
    receive(&mut receiver, 3, 13, 1, 8000)?;
    let full = receiver.ingress_status().ok_or("two distinct originals")?;
    assert_eq!(full.packets, 2);
    assert_eq!(full.oldest_records_number, Some(11));
    assert_eq!(full.oldest_received, Some(Tick(1)));
    assert_eq!(full.deadline, Some(Tick(7000)));
    receive(&mut receiver, 4, 14, 1, 9500)?;
    assert_eq!(
        receiver.ingress_status(),
        Some(IngressStatus {
            coalesced_sources: 2,
            ..full
        })
    );
    assert_eq!(receive(&mut receiver, 4, 15, 2, 9500), Err(Error::Busy));
    assert_eq!(receiver.storage_usage(), Some(usage));
    service_until(&mut receiver, Tick(5), |owner| {
        owner.ingress_status().is_some_and(|q| q.packets == 0)
    })?;
    receive(&mut receiver, 6, 16, 2, 9500)?;
    service_until(&mut receiver, Tick(7), |owner| {
        owner.receiver_status().decoder.decoded_prefix == 4
    })?;
    Ok(())
}

#[test]
fn full_targeted_fifo_stages_its_old_head_when_decoder_is_idle() -> TestResult {
    let (config, packets) = targeted_sources()?;
    let (mut receiver, usage) = queued(config, 2)?;
    let accept = |receiver: &mut Endpoint, source: usize, t, pn, cap| {
        receiver.accept_authenticated_until(
            Tick(t),
            Tick(t),
            Tick(cap),
            Some(pn),
            packets[source].kind,
            &packets[source].bytes,
        )
    };
    accept(&mut receiver, 3, 0, 100, 9_000)?;
    accept(&mut receiver, 3, 1, 101, 9_000)?;
    accept(&mut receiver, 0, 2, 102, 7_000)?;
    // The active source finishes; its retained duplicate comes off the front
    // without installing another decode job. Source 0 still has FIFO custody.
    receiver.step(Tick(3), work())?;
    assert!(!receiver.receiver_status().decoder.pending_job);
    assert_eq!(
        receiver
            .ingress_status()
            .ok_or("retained original")?
            .oldest_records_number,
        Some(102)
    );
    accept(&mut receiver, 1, 4, 103, 8_000)?;
    assert_eq!(receiver.ingress_status().ok_or("full queue")?.packets, 2);
    accept(&mut receiver, 2, 5, 104, 8_500)?;
    let after = receiver.ingress_status().ok_or("targeted queue")?;
    assert_eq!((after.packets, after.full_refusals), (2, [0; 3]));
    assert_eq!(after.oldest_records_number, Some(103));
    assert_eq!(after.deadline, Some(Tick(8_000)));
    assert!(receiver.receiver_status().decoder.pending_job);
    let job = receiver
        .incoming
        .expiry_snapshot()
        .decoder_job
        .ok_or("old head")?;
    assert_eq!(
        job.identity,
        rolling::expiry::Identity::Sources { first: 0, end: 1 }
    );
    assert_eq!(job.received, rolling::Tick(2));
    assert_eq!(job.deadline, rolling::Tick(7_000));
    service_until(&mut receiver, Tick(6), |r| {
        r.receiver_status().decoder.decoded_prefix == 4
    })?;
    assert_eq!(receiver.storage_usage(), Some(usage));
    Ok(())
}
#[test]
fn queued_copy_with_older_arrival_or_tighter_cap_keeps_its_own_custody() -> TestResult {
    let (config, packets) = targeted_sources()?;
    for (earlier_arrival, tighter_cap) in [(1, 10_000), (4, 8_000)] {
        let (mut receiver, _) = queued(config, 2)?;
        let active = &packets[3];
        receiver.accept_authenticated(Tick(0), active.kind, &active.bytes)?;
        let wire = &packets[0];
        receiver.accept_authenticated_until(
            Tick(3),
            Tick(3),
            Tick(9_000),
            Some(17),
            wire.kind,
            &wire.bytes,
        )?;
        receiver.accept_authenticated_until(
            Tick(earlier_arrival),
            Tick(4),
            Tick(tighter_cap),
            Some(18),
            wire.kind,
            &wire.bytes,
        )?;
        let full = receiver.ingress_status().ok_or("queued copies")?;
        assert_eq!((full.packets, full.coalesced_sources), (2, 0));
        assert_eq!(full.oldest_records_number, Some(17));
        assert_eq!(full.oldest_received, Some(Tick(3)));
        assert_eq!(full.deadline, Some(Tick(9_000.min(tighter_cap))));
    }
    Ok(())
}
#[test]
fn conflicting_authenticated_copy_of_queued_source_fails_before_publication() -> TestResult {
    let (config, mut packets) = targeted_sources()?;
    let (mut receiver, _) = queued(config, 1)?;
    for index in [3, 0] {
        let wire = &packets[index];
        receiver.accept_authenticated(Tick(0), wire.kind, &wire.bytes)?;
    }
    let old = receiver.ingress_status().ok_or("retained original")?;
    let wire = &mut packets[0];
    *wire.bytes.last_mut().ok_or("source payload")? ^= 1;
    assert_eq!(
        receiver.accept_authenticated(Tick(1), wire.kind, &wire.bytes),
        Err(Error::Rolling(rolling::Error::Conflict))
    );
    assert_eq!(receiver.ingress_status(), Some(old));
    assert_eq!(receiver.receiver_status().decoder.decoded_prefix, 0);
    Ok(())
}
#[test]
fn busy_decoder_requests_only_holes_outside_authenticated_fifo_custody() -> TestResult {
    let (config, packets) = targeted_sources()?;
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
fn coalesced_targeted_burst_retains_feedback_and_native_progress() -> TestResult {
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
        let burst = receiver.ingress_status().ok_or("out-of-order burst")?;
        assert_eq!((burst.packets, burst.coalesced_sources), (1, 8));
        receiver.step(Tick(1), work())?;
        let step = receiver.step_queued(Tick(1), work())?;
        assert_eq!(receiver.ingress_status().ok_or("actual queue")?.packets, 0);
        assert!(step.receive.work.field <= work().field);
        assert!(step.receive.work.copies <= work().copies);
        assert!(step.receive.work.metadata <= work().metadata);
        if feedback_packets == 2 {
            assert!(step.receive.feedback_ready);
        } else {
            assert!(!step.receive.feedback_ready);
            assert!(step.native_progress);
            let next = receiver.step_queued(Tick(1), work())?;
            assert!(!next.native_progress && !next.source_handed && !next.receive.feedback_ready);
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
fn full_targeted_fifo_services_additional_distinct_inputs_with_the_remaining_grant() -> TestResult {
    let (config, packets) = targeted_sources()?;
    let (mut ordinary, _) = queued(config, 3)?;
    let (mut batched, _) = queued(config, 3)?;
    for receiver in [&mut ordinary, &mut batched] {
        for wire in &packets {
            receiver.accept_authenticated(Tick(0), wire.kind, &wire.bytes)?;
        }
        assert_eq!(receiver.ingress_status().ok_or("full FIFO")?.packets, 3);
    }
    let reference = ordinary.step(Tick(1), work())?;
    let grant = batched.step_queued(Tick(1), work())?;
    assert!(reference.source_handed && grant.source_handed);
    assert_eq!(batched.receiver_status().decoder.handoff_prefix, 1);
    assert!(grant.receive.work.field <= work().field);
    assert!(grant.receive.work.copies <= work().copies);
    assert!(grant.receive.work.metadata <= work().metadata);
    assert!(
        batched.ingress_status().ok_or("batched")?.packets
            < ordinary.ingress_status().ok_or("ordinary")?.packets
    );
    service_until(&mut batched, Tick(2), |owner| {
        owner.receiver_status().decoder.handoff_prefix == 4
    })?;
    Ok(())
}

fn compact_fixture(
    config: Config,
    receiver: &Endpoint,
    count: u8,
    frame_bytes: usize,
) -> TestResult<(Vec<Datagram>, Vec<Vec<u8>>)> {
    let mut sender = endpoint(config, Role::Client)?;
    sender.enable_compact_wire(53)?;
    sender.enable_queue_aware_repair_budget(1500)?;
    let mut serial = 1;
    let mut originals = Vec::new();
    let mut packets = Vec::new();
    for n in 0..count {
        sender
            .enqueue_admitted_identified(Tick(0), 0, &packet(true, n, frame_bytes))?
            .ok_or("native admission")?;
        sender.flush(Tick(0))?;
        sender.step(Tick(0), work())?;
        let (_, wire) = emit(&mut sender, Tick(0), &mut serial, true)?.ok_or("source")?;
        let recovery::View::Source { id, original, .. } =
            receiver.inspect_data(&wire.bytes, false)?
        else {
            return Err("source expected".into());
        };
        assert_eq!(id.0, u32::from(n));
        originals.push(original.to_vec());
        packets.push(wire);
    }
    Ok((packets, originals))
}

fn compact_repair(
    config: Config,
    receiver: &Endpoint,
    originals: &[Vec<u8>],
    serial: u64,
    end: u32,
) -> TestResult<Datagram> {
    let recovery = config.forward.scheduler.recovery;
    let rid = rolling::RepairId(serial);
    let support = recovery.support(end, rid, false)?;
    let mut rhs = vec![0; recovery.width()?];
    for id in support.start..support.end {
        let bytes = &originals[id as usize];
        let factor = crate::fec::field::compact_coefficient(support.seed, id);
        for (dst, &byte) in rhs
            .iter_mut()
            .zip((bytes.len() as u16).to_be_bytes().iter().chain(bytes))
        {
            *dst ^= crate::fec::field::multiply(factor, byte);
        }
    }
    let mut wire = vec![0; rhs.len() + 32];
    let size = rolling::wire::compact::encode_data(
        scheduler::Output::Repair(rolling::Repair {
            scope: receiver.peer_rolling_scope(),
            id: rid,
            support,
            bytes: &rhs,
        }),
        &mut wire,
    )?;
    wire.truncate(size);
    Ok(Datagram {
        kind: record_engine::EmissionKind::Repair,
        bytes: wire,
    })
}

#[test]
fn compact_disjoint_source_frees_a_full_ingress_slot_before_wide_repair_commits() -> TestResult {
    let mut config = short_config(0, rolling::wire::SourceWire::TargetedExact);
    config.forward.scheduler.recovery.local_window = 1;
    config.forward.scheduler.repair_numerator = 0;
    let (mut receiver, usage) = queued(config, 1)?;
    receiver.enable_compact_wire(85)?;
    let (packets, originals) = compact_fixture(config, &receiver, 4, 80)?;
    for n in [0, 2] {
        receiver.accept_authenticated(Tick(0), packets[n].kind, &packets[n].bytes)?;
        service_until(&mut receiver, Tick(0), |r| {
            r.receiver_status().decoder.observed_end == n as u32 + 1
        })?;
    }
    let row = compact_repair(config, &receiver, &originals, 2, 3)?;
    receiver.accept_authenticated(Tick(0), row.kind, &row.bytes)?;
    receiver.accept_authenticated_until(
        Tick(0),
        Tick(0),
        Tick(5000),
        Some(88),
        packets[3].kind,
        &packets[3].bytes,
    )?;
    assert_eq!(receiver.ingress_status().ok_or("queued")?.packets, 1);
    let grant = rolling::WorkBudget {
        field: 0,
        copies: 4096,
        metadata: 4096,
    };
    let result = receiver.step_queued(Tick(1), grant)?;
    assert!(
        result.receive.work.copies <= grant.copies
            && result.receive.work.metadata <= grant.metadata
    );
    assert_eq!(result.receive.work.field, 0);
    assert_eq!(receiver.ingress_status().ok_or("freed")?.packets, 0);
    assert!(receiver.receiver_status().decoder.pending_job);
    assert_eq!(receiver.receiver_status().decoder.decoded_prefix, 1);
    assert_eq!(
        receiver.incoming.decoded_source(rolling::SourceId(3))?,
        Some(originals[3].as_slice())
    );
    assert_eq!(receiver.storage_usage(), Some(usage));
    service_until(&mut receiver, Tick(2), |r| {
        r.receiver_status().decoder.decoded_prefix == 4
    })?;
    Ok(())
}

#[test]
fn fresh_systematic_at_fifo_head_can_deliver_in_the_same_receive_turn() -> TestResult {
    let mut config = short_config(128, rolling::wire::SourceWire::TargetedExact);
    config.forward.scheduler.repair_numerator = 0;
    config.forward.scheduler.feedback_packets = 1024;
    config.forward.packing.work_limit = 32;
    let (mut rx, usage) = queued(config, 2)?;
    rx.enable_compact_wire(85)?;
    let (sources, _) = compact_fixture(config, &rx, 8, 40)?;
    let now = Tick(0);
    for i in [1, 7] {
        rx.accept_authenticated(now, sources[i].kind, &sources[i].bytes)?;
    }
    assert_eq!(rx.ingress_status().ok_or("ingress")?.packets, 1);
    let grant = work();
    let step = rx.step(now, grant)?;
    assert!(
        step.receive.work.copies <= grant.copies && step.receive.work.metadata <= grant.metadata
    );
    assert_eq!(step.receive.work.field, 0);
    assert_eq!(rx.receiver_status().decoder.decoded_prefix, 0);
    assert_eq!(rx.receiver_status().decoder.known_sources, 2);
    let mut output = [0; 1024];
    for i in [1, 7] {
        let prepared = ready(&mut rx, now, &mut output)?;
        assert_eq!(
            prepared.identity().record.0,
            config.forward.receiver.first_record.0 + u64::from(i)
        );
        assert_eq!(&output[..prepared.bytes()], packet(true, i, 40));
        rx.commit_native(now, prepared.token())?;
    }
    assert_eq!(rx.storage_usage(), Some(usage));
    Ok(())
}

#[test]
fn distinct_outer_sources_cannot_publish_conflicting_bytes_for_one_packed_unit() -> TestResult {
    let mut config = short_config(128, rolling::wire::SourceWire::TargetedExact);
    config.forward.scheduler.repair_numerator = 0;
    config.forward.scheduler.feedback_packets = 1024;
    config.forward.packing.work_limit = 32;
    let (mut template, _) = queued(config, 2)?;
    template.enable_compact_wire(85)?;
    let (sources, originals) = compact_fixture(config, &template, 2, 80)?;
    let mut alias = originals[1].clone();
    let frame = packet(true, 1, 80);
    let at = alias
        .windows(frame.len())
        .position(|bytes| bytes == frame)
        .ok_or("native body")?;
    alias[at + 40] ^= 1;
    let mut wire = vec![0; alias.len() + 16];
    let len = rolling::wire::compact::encode_data(
        scheduler::Output::Source {
            scope: template.peer_rolling_scope(),
            id: rolling::SourceId(7),
            original: &alias,
        },
        &mut wire,
    )?;
    let now = Tick(0);
    for serial in [false, true] {
        let (mut rx, _) = queued(config, 2)?;
        rx.enable_compact_wire(85)?;
        rx.accept_authenticated(now, sources[1].kind, &sources[1].bytes)?;
        if serial {
            let first = rx.step(now, work())?;
            assert!(first.native_progress);
            assert!(!rx.receiver_status().decoder.pending_job);
        }
        rx.accept_authenticated(now, sources[1].kind, &wire[..len])?;
        assert_eq!(
            rx.step(now, work()),
            Err(Error::Receiver(receiver::Error::Conflict))
        );
        assert_eq!(rx.statistics().committed, 0);
    }
    Ok(())
}

#[test]
fn fresh_fifo_continuation_yields_to_ready_feedback() -> TestResult {
    let mut config = short_config(128, rolling::wire::SourceWire::TargetedExact);
    config.forward.scheduler.repair_numerator = 0;
    config.forward.scheduler.feedback_packets = 1;
    let (mut rx, _) = queued(config, 2)?;
    rx.enable_compact_wire(85)?;
    let (sources, _) = compact_fixture(config, &rx, 3, 40)?;
    for src in &sources[1..] {
        rx.accept_authenticated(Tick(0), src.kind, &src.bytes)?;
    }
    let step = rx.step(Tick(0), work())?;
    assert!(step.receive.feedback_ready);
    let decoder = rx.receiver_status().decoder;
    assert_eq!(decoder.known_sources, 1);
    assert!(decoder.pending_job);
    Ok(())
}

#[test]
fn compact_disjoint_fifo_preserves_each_observed_repair_frontier() -> TestResult {
    let mut config = short_config(0, rolling::wire::SourceWire::TargetedExact);
    config.forward.scheduler.repair_numerator = 0;
    let (mut receiver, usage) = queued(config, 8)?;
    receiver.enable_compact_wire(85)?;
    let (src, originals) = compact_fixture(config, &receiver, 10, 80)?;
    for n in [0, 2] {
        receiver.accept_authenticated(Tick(0), src[n].kind, &src[n].bytes)?;
        service_until(&mut receiver, Tick(0), |r| {
            r.receiver_status().decoder.observed_end == n as u32 + 1
        })?;
    }
    let local = compact_repair(config, &receiver, &originals, 1, 3)?;
    receiver.accept_authenticated(Tick(0), local.kind, &local.bytes)?;
    let global = compact_repair(config, &receiver, &originals, 2, 5)?;
    let local2 = compact_repair(config, &receiver, &originals, 3, 7)?;
    let future = compact_repair(config, &receiver, &originals, 4, 9)?;
    // Origins 4 and 6 first witness the ranges up to 5 and 7. Their arrivals
    // establish the caps. Source 3 lies in the older queued global support.
    // The global ending at 9 first witnesses a new range and must stay ahead of 9.
    for (i, packet) in [
        &src[4], &global, &src[3], &src[6], &local2, &src[7], &future, &src[9],
    ]
    .into_iter()
    .enumerate()
    {
        let time = Tick(i as u64 + 1);
        receiver.accept_authenticated_until(
            time,
            time,
            Tick(80 + i as u64),
            Some(100 + i as u64),
            packet.kind,
            &packet.bytes,
        )?;
    }
    assert_eq!(receiver.ingress_status().ok_or("full")?.packets, 8);
    for _ in 0..4 {
        let grant = rolling::WorkBudget {
            field: 0,
            copies: 8192,
            metadata: 8192,
        };
        let step = receiver.step_queued(Tick(9), grant)?;
        assert_eq!(step.receive.work.field, 0);
        assert!(
            step.receive.work.copies <= grant.copies
                && step.receive.work.metadata <= grant.metadata
        );
    }
    for n in [4, 6, 7] {
        assert_eq!(
            receiver.incoming.decoded_source(rolling::SourceId(n))?,
            Some(originals[n as usize].as_slice())
        );
    }
    for n in [1, 3, 9] {
        assert_eq!(
            receiver.incoming.decoded_source(rolling::SourceId(n))?,
            None
        );
    }
    assert_eq!(receiver.receiver_status().decoder.observed_end, 8);
    assert_eq!(receiver.receiver_status().decoder.decoded_prefix, 1);
    assert_eq!(receiver.ingress_status().ok_or("retained")?.packets, 5);
    assert_eq!(
        receiver.ingress_status().ok_or("retained")?.deadline,
        Some(Tick(81))
    );
    assert_eq!(receiver.storage_usage(), Some(usage));
    let mut native = [0; 1024];
    let mut delivered = [false; 10];
    for _ in 0..64 {
        receiver.step_queued(Tick(10), work())?;
        if let NativePreparation::Ready(prepared) =
            receiver.prepare_native(Tick(10), 32, Tick(50), &mut native)?
        {
            let id = native[40];
            assert_eq!(&native[..prepared.bytes()], packet(true, id, 80));
            assert!(!std::mem::replace(&mut delivered[id as usize], true));
            receiver.commit_native(Tick(10), prepared.token())?;
        }
        if delivered.iter().all(|&ok| ok) {
            break;
        }
    }
    assert!(delivered.into_iter().all(|ok| ok));
    assert_eq!(receiver.receiver_status().decoder.decoded_prefix, 10);
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
