use super::*;

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
