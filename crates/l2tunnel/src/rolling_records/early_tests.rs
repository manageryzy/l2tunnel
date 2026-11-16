use super::*;

fn short_config(limit: usize, wire: rolling::wire::SourceWire) -> Config {
    let mut config = config(true, wire);
    for direction in [&mut config.forward, &mut config.reverse] {
        direction.receiver.body.independent_short_frame_bytes = limit;
        direction.packing.sender.body = direction.receiver.body;
    }
    config.native_stall_micros = 10_000_000;
    config
}

type Originals = (
    Datagram,
    Datagram,
    receiver::RecordIdentity,
    receiver::RecordIdentity,
    Vec<u8>,
    Vec<u8>,
);

fn originals(config: Config) -> TestResult<Originals> {
    let mut sender = endpoint(config, Role::Client)?;
    let old = packet(true, 0x39, 80);
    let short = packet(true, 0x71, 48);
    let old_id = sender
        .enqueue_admitted_identified(Tick(0), 0, &old)?
        .ok_or("old admission")?;
    sender.flush(Tick(0))?;
    sender.step(Tick(0), work())?;
    let mut number = 1u64 << 50;
    let (first, old_wire) = emit(&mut sender, Tick(0), &mut number, true)?.ok_or("old source")?;
    assert_eq!(
        first.id,
        OutputId::Data(scheduler::OutputId::Source(rolling::SourceId(0)))
    );
    let short_id = sender
        .enqueue_admitted_identified(Tick(0), 0, &short)?
        .ok_or("short admission")?;
    sender.flush(Tick(0))?;
    sender.step(Tick(0), work())?;
    let (second, short_wire) =
        emit(&mut sender, Tick(0), &mut number, true)?.ok_or("short source")?;
    assert_eq!(
        second.id,
        OutputId::Data(scheduler::OutputId::Source(rolling::SourceId(1)))
    );
    Ok((old_wire, short_wire, old_id, short_id, old, short))
}

fn make_receiver(config: Config, reserved: bool) -> TestResult<Endpoint> {
    if reserved {
        let plan = storage::Plan::for_endpoint(config, context(Role::Server), 17, Tick(0))?;
        Ok(Endpoint::new_reserved(
            plan,
            storage::Limits {
                capacity_bytes: plan.capacity_bytes(),
            },
        )?)
    } else {
        endpoint(config, Role::Server)
    }
}

fn service_until(
    endpoint: &mut Endpoint,
    now: Tick,
    done: impl Fn(&Endpoint) -> bool,
) -> TestResult {
    let budget = rolling::WorkBudget {
        field: 1,
        copies: 1,
        metadata: 1,
    };
    for _ in 0..20_000 {
        let step = endpoint.step(now, budget)?;
        assert!(step.send.field <= 1 && step.send.copies <= 1 && step.send.metadata <= 1);
        assert!(
            step.receive.work.field <= 1
                && step.receive.work.copies <= 1
                && step.receive.work.metadata <= 1
        );
        if done(endpoint) {
            return Ok(());
        }
    }
    Err("bounded work did not finish".into())
}

fn ready(endpoint: &mut Endpoint, now: Tick, output: &mut [u8]) -> TestResult<PreparedNative> {
    for _ in 0..8 {
        match endpoint.prepare_native(now, 16, Tick(9_000_000), output)? {
            NativePreparation::Ready(prepared) => return Ok(prepared),
            NativePreparation::Idle | NativePreparation::Progress => {}
            NativePreparation::AlreadyPending(_) => return Err("unexpected existing native".into()),
        }
    }
    Err("actual native not ready".into())
}

#[test]
fn rolling_short_crosses_real_gap_with_work_one_and_later_ordered_deduplication() -> TestResult {
    for wire in [
        rolling::wire::SourceWire::Padded,
        rolling::wire::SourceWire::Exact,
    ] {
        for reserved in [false, true] {
            let config = short_config(64, wire);
            let (old_wire, short_wire, old_id, short_id, old, short) = originals(config)?;
            let mut receiver = make_receiver(config, reserved)?;
            receiver.accept_authenticated(Tick(6), short_wire.kind, &short_wire.bytes)?;
            let zero = receiver.step(Tick(6), rolling::WorkBudget::default())?;
            assert_eq!(zero.receive.work, rolling::WorkBudget::default());
            assert_eq!(receiver.record_status().retained_records, 0);
            service_until(&mut receiver, Tick(6), |owner| {
                owner.record_status().retained_records != 0
            })?;
            assert_eq!(receiver.receiver_status().decoder.handoff_prefix, 0);
            assert_eq!(receiver.receiver_status().decoder.decoded_prefix, 0);
            let mut output = [0; 1024];
            let early = ready(&mut receiver, Tick(6), &mut output)?;
            assert_eq!(early.identity(), short_id);
            assert!(early.early());
            assert_eq!(&output[..early.bytes()], &short);
            let mut held = [0xa5; 1024];
            assert_eq!(
                receiver.prepare_native(Tick(7), 1, Tick(8_000_000), &mut held)?,
                NativePreparation::AlreadyPending(early)
            );
            assert_eq!(held, [0xa5; 1024]);
            assert_eq!(early.deadline(), Tick(5_000_006));
            receiver.commit_native(Tick(7), early.token())?;
            assert_eq!(receiver.record_status().early_tombstones, 1);

            receiver.accept_authenticated(Tick(8), old_wire.kind, &old_wire.bytes)?;
            service_until(&mut receiver, Tick(8), |owner| {
                owner.receiver_status().decoder.handoff_prefix == 2
            })?;
            let original = ready(&mut receiver, Tick(8), &mut output)?;
            assert_eq!(original.identity(), old_id);
            assert!(!original.early());
            assert_eq!(&output[..original.bytes()], &old);
            receiver.commit_native(Tick(8), original.token())?;
            // Physical commit retires that original only. Give each actual
            // receive channel one bounded turn at the same tick so the now-head
            // early tombstone is retired without another native delivery.
            let mut retired = false;
            for _ in 0..config.forward.receiver.channels {
                match receiver.prepare_native(Tick(8), 1, Tick(9_000_000), &mut held)? {
                    NativePreparation::Progress => {
                        assert!(!retired);
                        retired = true;
                    }
                    NativePreparation::Idle => {}
                    _ => return Err("tombstone cleanup produced another native".into()),
                }
                assert_eq!(held, [0xa5; 1024]);
            }
            assert!(retired);
            assert_eq!(receiver.record_status().early_tombstones, 0);
            receiver.accept_authenticated(Tick(9), short_wire.kind, &short_wire.bytes)?;
            for _ in 0..4 {
                assert_eq!(
                    receiver.prepare_native(Tick(9), 16, Tick(9_000_000), &mut output)?,
                    NativePreparation::Idle
                );
            }
            assert_eq!(receiver.statistics().committed, 2);
            assert_eq!(receiver.failure(), None);

            let disabled = short_config(0, wire);
            let mut ordinary = make_receiver(disabled, reserved)?;
            ordinary.accept_authenticated(Tick(6), short_wire.kind, &short_wire.bytes)?;
            service_until(&mut ordinary, Tick(6), |owner| !owner.work_pending())?;
            assert_eq!(ordinary.record_status().retained_records, 0);
            assert_eq!(ordinary.receiver_status().decoder.handoff_prefix, 0);
        }
    }
    Ok(())
}

#[test]
fn rolling_early_native_keeps_original_record_expiry_while_recovery_continues() -> TestResult {
    let config = short_config(64, rolling::wire::SourceWire::Exact);
    let (old, short, _, short_id, _, bytes) = originals(config)?;
    let mut receiver = make_receiver(config, true)?;
    receiver.accept_authenticated(Tick(6), short.kind, &short.bytes)?;
    service_until(&mut receiver, Tick(6), |owner| {
        owner.record_status().retained_records != 0
    })?;
    let mut output = [0; 1024];
    let pending = ready(&mut receiver, Tick(6), &mut output)?;
    assert_eq!(pending.identity(), short_id);
    assert_eq!(&output[..pending.bytes()], &bytes);
    assert_eq!(pending.deadline(), Tick(5_000_006));
    receiver.accept_authenticated(Tick(7), old.kind, &old.bytes)?;
    service_until(&mut receiver, Tick(7), |owner| {
        owner.receiver_status().decoder.handoff_prefix == 2 && !owner.work_pending()
    })?;
    let mut number = 99;
    for _ in 0..4 {
        if emit(&mut receiver, Tick(7), &mut number, false)?.is_none() {
            break;
        }
    }
    let mut held = [0xa5; 1024];
    assert_eq!(
        receiver.prepare_native(Tick(5_000_005), 1, Tick(9_000_000), &mut held)?,
        NativePreparation::AlreadyPending(pending)
    );
    assert_eq!(held, [0xa5; 1024]);
    assert_eq!(
        receiver.commit_native(Tick(5_000_006), pending.token()),
        Err(Error::Expired)
    );
    assert_eq!(receiver.statistics().committed, 1);
    assert_eq!(receiver.pending_native(), None);
    assert!(!receiver.drained());
    Ok(())
}

#[test]
fn rolling_late_earlier_source_rescans_after_retained_later_preview_with_work_one() -> TestResult {
    let config = short_config(64, rolling::wire::SourceWire::Exact);
    let frames = [
        packet(true, 0x31, 80),
        packet(true, 0x52, 48),
        packet(true, 0x73, 44),
    ];
    let mut sender = endpoint(config, Role::Client)?;
    let mut packets = Vec::new();
    let mut identities = Vec::new();
    let mut number = 1u64 << 51;
    for (index, frame) in frames.iter().enumerate() {
        identities.push(
            sender
                .enqueue_admitted_identified(Tick(0), 0, frame)?
                .ok_or("actual source admission")?,
        );
        sender.flush(Tick(0))?;
        let mut systematic = None;
        for _ in 0..32 {
            sender.step(Tick(0), work())?;
            if let Some((prepared, packet)) = emit(&mut sender, Tick(0), &mut number, true)? {
                match prepared.id {
                    OutputId::Data(scheduler::OutputId::Source(id)) => {
                        assert_eq!(id, rolling::SourceId(index as u32));
                        systematic = Some(packet);
                        break;
                    }
                    OutputId::Data(scheduler::OutputId::Repair(_)) => {}
                    _ => return Err("unexpected sender feedback".into()),
                }
            }
        }
        packets.push(systematic.ok_or("actual systematic output")?);
    }

    let mut receiver = make_receiver(config, true)?;
    receiver.accept_authenticated(Tick(6), packets[2].kind, &packets[2].bytes)?;
    service_until(&mut receiver, Tick(6), |owner| {
        !owner.receiver_status().decoder.pending_job
    })?;
    assert_eq!(receiver.receiver_status().decoder.observed_end, 3);
    assert_eq!(receiver.record_status().retained_records, 0);
    let budget = rolling::WorkBudget {
        field: 1,
        copies: 1,
        metadata: 1,
    };
    let mut copying = false;
    for _ in 0..8 {
        let step = receiver.step(Tick(6), budget)?;
        assert!(
            step.receive.work.field <= 1
                && step.receive.work.copies <= 1
                && step.receive.work.metadata <= 1
        );
        assert_eq!(receiver.record_status().retained_records, 0);
        if step.receive.work.copies == 1 {
            // No decode or feedback work is owned. This is the first real slab
            // byte of source2, reached only after scanning absent sources0/1.
            assert!(!receiver.receiver_status().decoder.pending_job);
            assert!(!receiver.receiver_status().feedback_building);
            copying = true;
            break;
        }
    }
    assert!(copying);

    // Earlier source1 becomes committed while source2's partial preview owns
    // the slab. Its availability must survive until that preview finishes.
    receiver.accept_authenticated(Tick(6), packets[1].kind, &packets[1].bytes)?;
    service_until(&mut receiver, Tick(6), |owner| {
        !owner.receiver_status().decoder.pending_job
    })?;
    assert_eq!(receiver.record_status().retained_records, 0);
    service_until(&mut receiver, Tick(6), |owner| {
        owner.record_status().retained_records == 2
    })?;
    assert_eq!(receiver.receiver_status().decoder.handoff_prefix, 0);
    assert_eq!(receiver.receiver_status().decoder.decoded_prefix, 0);
    let mut output = [0; 1024];
    for index in [1, 2] {
        let native = ready(&mut receiver, Tick(6), &mut output)?;
        assert!(native.early());
        assert_eq!(native.identity(), identities[index]);
        assert_eq!(&output[..native.bytes()], &frames[index]);
        receiver.commit_native(Tick(6), native.token())?;
    }
    service_until(&mut receiver, Tick(6), |owner| !owner.work_pending())?;
    assert_eq!(receiver.record_status().early_tombstones, 2);
    assert_eq!(receiver.statistics().committed, 2);
    assert_eq!(receiver.receiver_status().decoder.handoff_prefix, 0);
    assert_eq!(receiver.failure(), None);
    Ok(())
}

#[test]
fn preview_reports_native_progress_only_after_actual_short_admission() -> TestResult {
    let config = short_config(64, rolling::wire::SourceWire::Exact);
    let (_, short_wire, _, short_id, _, short) = originals(config)?;
    let mut receiver = make_receiver(config, true)?;
    receiver.accept_authenticated(Tick(6), short_wire.kind, &short_wire.bytes)?;
    let zero = receiver.step(Tick(6), rolling::WorkBudget::default())?;
    assert!(!zero.source_handed && !zero.native_progress);
    let budget = rolling::WorkBudget {
        field: 1,
        copies: 1,
        metadata: 1,
    };
    let mut reported = false;
    let mut partial_turns = 0;
    for _ in 0..20_000 {
        let step = receiver.step(Tick(6), budget)?;
        assert!(!step.source_handed);
        assert!(
            step.receive.work.field <= 1
                && step.receive.work.copies <= 1
                && step.receive.work.metadata <= 1
        );
        if step.native_progress {
            assert!(receiver.record_status().retained_records > 0);
            reported = true;
            break;
        }
        assert_eq!(receiver.record_status().retained_records, 0);
        partial_turns += 1;
    }
    assert!(reported && partial_turns > 1);
    assert_eq!(receiver.receiver_status().decoder.handoff_prefix, 0);
    let mut output = [0; 1024];
    let native = ready(&mut receiver, Tick(6), &mut output)?;
    assert!(native.early());
    assert_eq!(native.identity(), short_id);
    assert_eq!(&output[..native.bytes()], short);
    for _ in 0..64 {
        let step = receiver.step(Tick(6), budget)?;
        assert!(!step.source_handed && !step.native_progress);
    }
    receiver.commit_native(Tick(6), native.token())?;
    assert_eq!(receiver.statistics().committed, 1);
    Ok(())
}

#[path = "ingress_tests.rs"]
mod ingress;
