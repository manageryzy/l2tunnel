use super::*;

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
