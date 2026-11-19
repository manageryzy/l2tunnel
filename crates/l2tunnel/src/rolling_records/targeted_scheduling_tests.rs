use super::*;

#[test]
fn sealed_targeted_source_uses_only_the_residual_grant_at_a_freed_fifo_slot() -> TestResult {
    for continuation in [false, true] {
        for (missing_byte, metadata) in [(false, 2), (true, 2), (false, 1)] {
            let enough = !missing_byte && metadata == 2;
            let mut cfg = config(true, rolling::wire::SourceWire::TargetedExact);
            cfg.forward.scheduler.repair_numerator = 0;
            let mut endpoint = endpoint(cfg, Role::Client)?;
            endpoint.enable_compact_wire(41)?;
            endpoint.enable_queue_aware_repair_budget(1500)?;
            let created = Tick(17);
            let now = Tick(29);
            let at = rolling_tick(now);
            let limit = endpoint.sender_status().fresh_queue_limit;
            let first = endpoint
                .sender
                .admit_source(b"first", rolling_tick(created))?;
            for _ in 0..limit {
                endpoint
                    .sender
                    .admit_source(b"queued", rolling_tick(created))?;
            }
            endpoint
                .enqueue_admitted_identified(created, 0, &packet(true, 7, 64))?
                .ok_or("stage")?;
            endpoint.flush(created)?;
            assert_eq!(endpoint.sender_status().queued_fresh, limit);
            let id = endpoint.sender_status().next_source;
            let mut expected = [0; 512];
            let n = endpoint.packing.write_pending_compact(&mut expected)?;
            endpoint
                .sender
                .confirm_output(scheduler::OutputId::Source(first), at)?;
            endpoint.tick(now)?;
            let select = cfg.forward.scheduler.recovery.width()? + 2 + b"queued".len();
            let grant = rolling::WorkBudget {
                copies: select + n - usize::from(missing_byte),
                metadata,
                ..work()
            };
            let used = if continuation {
                endpoint.continue_targeted_send(now, grant)?
            } else {
                endpoint.step(now, grant)?.send
            };
            assert_eq!(
                endpoint.sender_status().queued_fresh,
                limit - usize::from(!enough)
            );
            assert_eq!(endpoint.packing.has_pending_source(), !enough);
            assert_eq!(used.copies, select + if enough { n } else { 0 });
            assert_eq!(used.metadata, 1 + usize::from(enough));
            let selected = endpoint
                .sender
                .pending_output()
                .ok_or("physical original")?
                .id();
            assert_eq!(
                selected,
                scheduler::OutputId::Source(rolling::SourceId(first.0 + 1))
            );
            // The same physical owner cannot admit or charge the sealed source twice.
            assert_eq!(
                endpoint.continue_targeted_send(now, grant)?,
                rolling::WorkUsed::default()
            );
            if !enough {
                endpoint.step(now, work())?;
            }
            for next in first.0 + 1..id {
                assert_eq!(
                    endpoint
                        .sender
                        .pending_output()
                        .ok_or("queued output")?
                        .id(),
                    scheduler::OutputId::Source(rolling::SourceId(next))
                );
                endpoint
                    .sender
                    .confirm_output(scheduler::OutputId::Source(rolling::SourceId(next)), at)?;
                endpoint.step(now, work())?;
            }
            let Some(scheduler::Output::Source {
                id: actual,
                original,
                ..
            }) = endpoint.sender.pending_output()
            else {
                return Err("sealed source missing".into());
            };
            assert_eq!((actual.0, original), (id, &expected[..n]));
            let deadline =
                endpoint.sender.expiry_snapshot().candidates[3].ok_or("output deadline")?;
            assert_eq!(
                deadline.at.0,
                created.0 + cfg.forward.scheduler.recovery.job_ticks
            );
        }
    }
    Ok(())
}

#[test]
fn targeted_physical_continuation_charges_exact_fifo_transfer_once() -> TestResult {
    let mut cfg = config(true, rolling::wire::SourceWire::TargetedExact);
    cfg.forward.scheduler.repair_numerator = 0;
    let mut endpoint = endpoint(cfg, Role::Client)?;
    let now = Tick(0);
    let at = rolling_tick(now);
    let first = endpoint.sender.admit_source(b"first", at)?;
    let second = endpoint.sender.admit_source(b"second", at)?;
    let third = endpoint.sender.admit_source(b"x", at)?;
    endpoint
        .sender
        .confirm_output(scheduler::OutputId::Source(first), at)?;
    let width = cfg.forward.scheduler.recovery.width()?;
    let cost = width + 2 + b"second".len();
    let grant = |copies| rolling::WorkBudget { copies, ..work() };
    for copies in [0, cost - 1] {
        assert_eq!(
            endpoint.continue_targeted_send(now, grant(copies))?.copies,
            0
        );
        assert_eq!(endpoint.sender_status().queued_fresh, 2);
        assert!(endpoint.sender.pending_output().is_none());
    }
    assert_eq!(
        endpoint.continue_targeted_send(now, grant(cost))?.copies,
        cost
    );
    assert_eq!(endpoint.sender_status().queued_fresh, 1);
    assert_eq!(
        endpoint.sender.pending_output().map(scheduler::Output::id),
        Some(scheduler::OutputId::Source(second))
    );
    assert_eq!(
        endpoint.continue_targeted_send(now, grant(cost))?,
        rolling::WorkUsed::default()
    );
    endpoint
        .sender
        .confirm_output(scheduler::OutputId::Source(second), at)?;
    assert_eq!(endpoint.step(now, grant(width + 3))?.send.copies, width + 3);
    assert_eq!(
        endpoint.sender.pending_output().map(scheduler::Output::id),
        Some(scheduler::OutputId::Source(third))
    );
    Ok(())
}

#[test]
fn continuation_shares_one_copy_grant_between_global_clear_and_wrapped_source() -> TestResult {
    let mut cfg = config(true, rolling::wire::SourceWire::TargetedExact);
    let policy = &mut cfg.forward.scheduler;
    policy.recovery.global_every = 1;
    policy.repair_numerator = 1;
    policy.repair_denominator = policy.recovery.window as u32;
    let width = policy.recovery.width()?;
    let window = policy.recovery.window as u32;
    let mut endpoint = endpoint(cfg, Role::Client)?;
    let now = Tick(0);
    let at = rolling_tick(now);
    let scope = endpoint.sender.expiry_snapshot().scope;
    for id in 0..window {
        let original = endpoint.sender.admit_source(&id.to_be_bytes(), at)?;
        endpoint
            .sender
            .confirm_output(scheduler::OutputId::Source(original), at)?;
    }
    endpoint.sender.receive_feedback(
        scheduler::Feedback {
            scope,
            id: scheduler::FeedbackId(1),
            prefix: window / 2,
            observed_end: window,
            deficit: 0,
        },
        at,
    )?;
    endpoint.step(
        now,
        rolling::WorkBudget {
            metadata: 1,
            ..Default::default()
        },
    )?;
    assert!(endpoint.sender.computing_full_global());
    let fresh = endpoint.sender.admit_source(&window.to_be_bytes(), at)?;
    let transfer = width + 2 + window.to_be_bytes().len();
    let grant = |copies, field| rolling::WorkBudget {
        copies,
        field,
        ..work()
    };
    let used = endpoint.continue_targeted_send(now, grant(width + transfer - 1, 6))?;
    assert_eq!((used.copies, used.field), (width, 6));
    assert_eq!(endpoint.sender_status().queued_fresh, 1);
    assert!(endpoint.sender.pending_output().is_none());
    let used = endpoint.continue_targeted_send(now, grant(transfer, 1))?;
    assert_eq!((used.copies, used.field), (transfer, 1));
    assert_eq!(
        endpoint.sender.pending_output().map(scheduler::Output::id),
        Some(scheduler::OutputId::Source(fresh))
    );
    // A repeated poll advances only the pending equation. The unchanged
    // physical original consumes no second transfer allowance.
    assert_eq!(
        endpoint
            .continue_targeted_send(now, grant(transfer, 1))?
            .copies,
        0
    );
    endpoint
        .sender
        .confirm_output(scheduler::OutputId::Source(fresh), at)?;
    endpoint.continue_targeted_send(now, work())?;
    assert_eq!(
        endpoint.sender.pending_output().map(scheduler::Output::id),
        Some(scheduler::OutputId::Repair(rolling::RepairId(1)))
    );
    Ok(())
}

#[test]
fn packed_fragment_tails_reconstruct_after_loss_without_blocking_another_channel() -> TestResult {
    let mut config = short_config(0, rolling::wire::SourceWire::TargetedExact);
    config.forward.scheduler.repair_numerator = 0;
    let mut sender = endpoint(config, Role::Client)?;
    let mut receiver = make_receiver(config, true)?;
    sender.enable_compact_wire(41)?;
    receiver.enable_compact_wire(73)?;
    sender.enable_queue_aware_repair_budget(1500)?;
    receiver.enable_queue_aware_repair_budget(1500)?;
    let frames = [packet(true, 11, 230), packet(true, 13, 235)];
    let mut ids = Vec::new();
    let mut wire = Vec::new();
    let mut serial = 1;
    for (i, frame) in frames.iter().enumerate() {
        let now = Tick(10 + i as u64);
        ids.push(
            sender
                .enqueue_admitted_identified(now, i as u16, frame)?
                .ok_or("admission")?,
        );
        sender.step(now, work())?;
        let (prepared, sent) = emit(&mut sender, now, &mut serial, true)?.ok_or("full fragment")?;
        assert_eq!(
            prepared.id,
            OutputId::Data(scheduler::OutputId::Source(rolling::SourceId(i as u32)))
        );
        wire.push(sent);
        sender.step(now, work())?;
    }
    let now = Tick(520);
    sender.step(now, work())?;
    let (prepared, tails) = emit(&mut sender, now, &mut serial, true)?.ok_or("matched tails")?;
    assert_eq!(
        prepared.id,
        OutputId::Data(scheduler::OutputId::Source(rolling::SourceId(2)))
    );
    for datagram in [&wire[1], &tails] {
        receiver.accept_authenticated(now, datagram.kind, &datagram.bytes)?;
        settle(&mut receiver, now)?;
    }
    let mut out = [0; 1024];
    let second = ready(&mut receiver, now, &mut out)?;
    assert_eq!(second.identity(), ids[1]);
    assert_eq!(&out[..second.bytes()], &frames[1]);
    receiver.commit_native(now, second.token())?;
    assert_eq!(receiver.receiver_status().decoder.handoff_prefix, 0);
    let later = Tick(2600);
    let mut feedback_serial = 1;
    let requests = feedback(&mut receiver, &mut sender, later, &mut feedback_serial)?;
    assert_eq!(
        requests
            .iter()
            .map(|r| (r.start, r.mask))
            .collect::<Vec<_>>(),
        [(0, 1)]
    );
    sender.step(later, work())?;
    let (_, retry) = emit(&mut sender, later, &mut serial, true)?.ok_or("named oldest head")?;
    assert_eq!(retry.bytes, wire[0].bytes);
    receiver.accept_authenticated(later, retry.kind, &retry.bytes)?;
    settle(&mut receiver, later)?;
    let first = ready(&mut receiver, later, &mut out)?;
    assert_eq!(first.identity(), ids[0]);
    assert_eq!(&out[..first.bytes()], &frames[0]);
    receiver.commit_native(later, first.token())?;
    settle(&mut receiver, later)?;
    assert_eq!(receiver.receiver_status().decoder.handoff_prefix, 3);
    feedback(&mut receiver, &mut sender, Tick(3600), &mut feedback_serial)?;
    assert_eq!(
        sender
            .repair_budget_status()
            .ok_or("budget")?
            .unconfirmed_sources,
        0
    );
    Ok(())
}

#[test]
fn targeted_full_lookahead_preserves_other_channel_delivery_before_old_gap_closes() -> TestResult {
    let mut config = short_config(0, rolling::wire::SourceWire::TargetedExact);
    config.forward.scheduler.repair_numerator = 0;
    config.forward.receiver.lookahead_records = 1;
    let mut sender = endpoint(config, Role::Client)?;
    let mut receiver = make_receiver(config, true)?;
    sender.enable_compact_wire(41)?;
    receiver.enable_compact_wire(73)?;
    sender.enable_queue_aware_repair_budget(1500)?;
    receiver.enable_queue_aware_repair_budget(1500)?;
    let now = Tick(1);
    let mut serial = 1;
    let mut frames = Vec::new();
    let mut wires = Vec::new();
    for (i, channel) in [1, 0, 0, 1].into_iter().enumerate() {
        let bytes = packet(true, i as u8, 64);
        let id = sender
            .enqueue_admitted_identified(now, channel, &bytes)?
            .ok_or("admit")?;
        frames.push((id, bytes));
        if i != 1 {
            sender.flush(now)?;
            sender.step(now, work())?;
            let (_, wire) = emit(&mut sender, now, &mut serial, true)?.ok_or("packed source")?;
            wires.push(wire);
        }
    }
    let mut out = [0; 1024];
    for (index, expected_frames) in [(2, &[][..]), (1, &[1, 2][..]), (0, &[0, 3][..])] {
        let wire = &wires[index];
        receiver.accept_authenticated(now, wire.kind, &wire.bytes)?;
        for &frame in expected_frames {
            settle(&mut receiver, now)?;
            let delivery = ready(&mut receiver, now, &mut out)?;
            assert_eq!(delivery.identity(), frames[frame].0);
            assert_eq!(&out[..delivery.bytes()], &frames[frame].1);
            receiver.commit_native(now, delivery.token())?;
        }
        settle(&mut receiver, now)?;
        if index != 0 {
            assert_eq!(receiver.receiver_status().decoder.handoff_prefix, 0);
        }
    }
    assert_eq!(receiver.receiver_status().decoder.handoff_prefix, 3);
    assert_eq!(receiver.statistics().committed, 4);
    Ok(())
}

#[test]
fn targeted_full_lookahead_preserves_packed_channel_heads_and_later_exact_handoff() -> TestResult {
    let mut config = short_config(0, rolling::wire::SourceWire::TargetedExact);
    config.forward.scheduler.repair_numerator = 0;
    config.forward.receiver.lookahead_records = 1;
    let mut sender = endpoint(config, Role::Client)?;
    let mut receiver = make_receiver(config, true)?;
    sender.enable_compact_wire(41)?;
    receiver.enable_compact_wire(73)?;
    sender.enable_queue_aware_repair_budget(1500)?;
    receiver.enable_queue_aware_repair_budget(1500)?;

    let now = Tick(5);
    let frames = [
        packet(true, 1, 64),
        packet(true, 2, 64),
        packet(true, 3, 64),
    ];
    let mut identities = Vec::new();
    let mut wires = Vec::new();
    let mut serial = 1;
    for (index, frame) in frames.iter().enumerate() {
        identities.push(
            sender
                .enqueue_admitted_identified(now, 0, frame)?
                .ok_or("admit")?,
        );
        if index != 0 {
            sender.flush(now)?;
            sender.step(now, work())?;
            let (prepared, wire) =
                emit(&mut sender, now, &mut serial, true)?.ok_or("packed source")?;
            assert_eq!(
                prepared.id,
                OutputId::Data(scheduler::OutputId::Source(rolling::SourceId(
                    wires.len() as u32
                )))
            );
            wires.push(wire);
        }
    }
    // Lose the two-unit oldest source. Its successor holds the only shared
    // lookahead record while the channel's separately reserved head is empty.
    receiver.accept_authenticated(now, wires[1].kind, &wires[1].bytes)?;
    settle(&mut receiver, now)?;
    assert_eq!(receiver.record_status().retained_records, 1);
    assert_eq!(receiver.receiver_status().decoder.handoff_prefix, 0);
    let later = Tick(2_010);
    let mut feedback_serial = 1;
    let requests = feedback(&mut receiver, &mut sender, later, &mut feedback_serial)?;
    assert_eq!(
        requests
            .iter()
            .map(|r| (r.start, r.mask))
            .collect::<Vec<_>>(),
        [(0, 1)]
    );
    sender.step(later, work())?;
    let (_, retry) = emit(&mut sender, later, &mut serial, true)?.ok_or("named retry")?;
    assert_eq!(retry.bytes, wires[0].bytes);
    receiver.accept_authenticated(later, retry.kind, &retry.bytes)?;
    let mut head_accepted = false;
    for _ in 0..128 {
        let step = receiver.step(later, work())?;
        head_accepted |= step.native_progress;
        if head_accepted {
            break;
        }
    }
    assert!(head_accepted);
    assert_eq!(receiver.receiver_status().decoder.handoff_prefix, 0);
    assert_eq!(receiver.record_status().retained_records, 2);
    // Duplicate arrival and repeated scheduling must never deliver the head twice.
    receiver.accept_authenticated(later, retry.kind, &retry.bytes)?;
    let mut out = [0; 1024];
    for (identity, frame) in identities.iter().zip(frames) {
        settle(&mut receiver, later)?;
        let ready = ready(&mut receiver, later, &mut out)?;
        assert_eq!(&ready.identity(), identity);
        assert_eq!(&out[..ready.bytes()], frame);
        receiver.commit_native(later, ready.token())?;
    }
    settle(&mut receiver, later)?;
    assert_eq!(receiver.receiver_status().decoder.handoff_prefix, 2);
    assert_eq!(receiver.statistics().committed, 3);
    assert_eq!(receiver.record_status().retained_records, 0);
    feedback(
        &mut receiver,
        &mut sender,
        Tick(later.0 + 1000),
        &mut feedback_serial,
    )?;
    assert_eq!(
        sender
            .repair_budget_status()
            .ok_or("repair budget")?
            .unconfirmed_sources,
        0
    );
    Ok(())
}

fn settle(endpoint: &mut Endpoint, now: Tick) -> TestResult {
    for _ in 0..128 {
        endpoint.step(now, work())?;
        if !endpoint.work_pending() {
            break;
        }
    }
    Ok(())
}

fn feedback(
    receiver: &mut Endpoint,
    sender: &mut Endpoint,
    now: Tick,
    serial: &mut u64,
) -> TestResult<Vec<scheduler::GapRequest>> {
    let mut requests = Vec::new();
    for _ in 0..16 {
        receiver.step(now, work())?;
        let request = receiver.incoming.pending_request();
        let Some((_, wire)) = emit(receiver, now, serial, false)? else {
            break;
        };
        sender.accept_authenticated(now, wire.kind, &wire.bytes)?;
        requests.extend(request);
    }
    Ok(requests)
}

#[test]
fn targeted_fresh_channel_is_served_during_named_retries_and_oldest_loss_repeats() -> TestResult {
    const FRESH: u32 = 9;
    let mut config = short_config(0, rolling::wire::SourceWire::TargetedExact);
    config.forward.scheduler.repair_numerator = 0;
    config.forward.receiver.lookahead_records = 16;
    config.forward.scheduler.recovery.handoff_sources = 16;
    let mut sender = endpoint(config, Role::Client)?;
    let mut receiver = make_receiver(config, true)?;
    sender.enable_compact_wire(41)?;
    receiver.enable_compact_wire(73)?;
    sender.enable_queue_aware_repair_budget(1500)?;
    receiver.enable_queue_aware_repair_budget(1500)?;

    let mut frames = Vec::new();
    let mut originals = Vec::new();
    let mut data_serial = 1;
    let mut feedback_serial = 1;
    for index in 0..FRESH {
        let frame = packet(true, 0x10 + index as u8, 140);
        let identity = sender
            .enqueue_admitted_identified(Tick(0), 0, &frame)?
            .ok_or("channel A admission")?;
        sender.flush(Tick(0))?;
        sender.step(Tick(0), work())?;
        let (prepared, wire) = emit(&mut sender, Tick(0), &mut data_serial, true)?
            .ok_or("original channel A source")?;
        assert_eq!(
            prepared.id,
            OutputId::Data(scheduler::OutputId::Source(rolling::SourceId(index)))
        );
        frames.push((identity, frame));
        originals.push(wire.bytes);
        if index == FRESH - 1 {
            receiver.accept_authenticated(Tick(0), wire.kind, &originals[index as usize])?;
        }
    }
    settle(&mut receiver, Tick(0))?;
    assert!(feedback(&mut receiver, &mut sender, Tick(0), &mut feedback_serial)?.is_empty());
    let now = Tick(2_100);
    sender.observe_mux_wait_micros(20_000);
    let gaps = feedback(&mut receiver, &mut sender, now, &mut feedback_serial)?;
    assert_eq!(gaps.len(), 1);
    assert_eq!((gaps[0].prefix, gaps[0].start, gaps[0].mask), (0, 0, 0xff));

    // A has a named retry ready for the carrier when B first becomes runnable.
    sender.step(now, work())?;
    assert!(sender.sender.pending_requested_retry());
    let fresh = packet(true, 0xf1, 140);
    let fresh_id = sender
        .enqueue_admitted_identified(now, 1, &fresh)?
        .ok_or("fresh channel B admission during A recovery")?;
    sender.flush(now)?;
    let mut output = [0; 1024];
    let mut retried = [false; 8];
    let mut fresh_delivered = false;
    for _ in 0..=retried.len() {
        sender.step(now, work())?;
        let (prepared, wire) = emit(&mut sender, now, &mut data_serial, true)?
            .ok_or("expected new source or named retry")?;
        let OutputId::Data(scheduler::OutputId::Source(rolling::SourceId(id))) = prepared.id else {
            return Err("unexpected output during named recovery".into());
        };
        if id == FRESH {
            let retries_before_fresh = retried.iter().filter(|v| **v).count();
            assert!(
                (1..=4).contains(&retries_before_fresh),
                "fresh source waited for {retries_before_fresh} retries"
            );
            assert!(!fresh_delivered);
            for _ in 0..2 {
                receiver.accept_authenticated(now, wire.kind, &wire.bytes)?;
                settle(&mut receiver, now)?;
            }
            let native = ready(&mut receiver, now, &mut output)?;
            assert_eq!(native.identity(), fresh_id);
            assert_eq!(&output[..native.bytes()], fresh);
            receiver.commit_native(now, native.token())?;
            assert_eq!(receiver.receiver_status().decoder.handoff_prefix, 0);
            fresh_delivered = true;
        } else {
            let seen = retried
                .get_mut(id as usize)
                .ok_or("unsolicited retransmission")?;
            assert!(!*seen);
            *seen = true;
            assert_eq!(wire.bytes, originals[id as usize]);
            if id != 0 {
                receiver.accept_authenticated(now, wire.kind, &wire.bytes)?;
                settle(&mut receiver, now)?;
            }
        }
    }
    assert!(fresh_delivered && retried.into_iter().all(|done| done));
    assert_eq!(receiver.statistics().committed, 1);

    // Only retry zero was lost. Its aging timer must generate a new request.
    feedback(&mut receiver, &mut sender, now, &mut feedback_serial)?;
    let later = Tick(now.0 + 80_000);
    let repeat = feedback(&mut receiver, &mut sender, later, &mut feedback_serial)?;
    assert_eq!(repeat.len(), 1);
    assert_eq!(
        (repeat[0].prefix, repeat[0].start, repeat[0].mask),
        (0, 0, 1)
    );
    assert!(repeat[0].id.0 > gaps[0].id.0);
    sender.step(later, work())?;
    let (_, retry) = emit(&mut sender, later, &mut data_serial, true)?.ok_or("aged retry")?;
    assert_eq!(retry.bytes, originals[0]);
    receiver.accept_authenticated(later, retry.kind, &retry.bytes)?;
    for (identity, frame) in frames {
        settle(&mut receiver, later)?;
        let native = ready(&mut receiver, later, &mut output)?;
        assert_eq!(native.identity(), identity);
        assert_eq!(&output[..native.bytes()], frame);
        receiver.commit_native(later, native.token())?;
    }
    settle(&mut receiver, later)?;
    assert_eq!(receiver.receiver_status().decoder.handoff_prefix, FRESH + 1);
    assert_eq!(receiver.statistics().committed, u64::from(FRESH + 1));
    assert_eq!(
        receiver.prepare_native(later, 16, Tick(9_000_000), &mut output)?,
        NativePreparation::Idle
    );
    feedback(
        &mut receiver,
        &mut sender,
        Tick(later.0 + 1000),
        &mut feedback_serial,
    )?;
    assert_eq!(
        sender
            .repair_budget_status()
            .ok_or("repair budget")?
            .unconfirmed_sources,
        0
    );
    Ok(())
}
