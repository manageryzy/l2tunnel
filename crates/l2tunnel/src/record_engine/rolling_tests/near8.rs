use super::*;
use rolling::wire::SourceWire;

const IP_OVERHEAD: usize = 49;

fn selected(wire: SourceWire, role: Role) -> TestResult<Engine> {
    let base = fixture(true, SourceWire::Exact)?;
    let descriptor = base.descriptor();
    let configuration::Profile::Rolling { mut config, stream } = *descriptor.profile() else {
        return Err("expected rolling configuration".into());
    };
    config.geometry.forward_overhead_bytes = IP_OVERHEAD;
    config.forward.scheduler.source_wire = wire;
    config.forward.scheduler.repair_numerator = 41;
    config.forward.scheduler.repair_denominator = 200;
    config.reverse.scheduler.source_wire = SourceWire::TargetedExact;
    let selected = configuration::Configuration::new(
        base.envelope(),
        configuration::Descriptor::new(
            descriptor.path_mtu(),
            descriptor.duplex(),
            *descriptor.direction(Role::Client).common(),
            *descriptor.direction(Role::Server).common(),
            configuration::Profile::RollingCopies {
                config,
                stream,
                copies: rolling_records::CopyPolicies::ONE,
            },
        )?,
    )?;
    let plan = storage::Plan::for_engine(
        selected,
        context(role),
        config.geometry,
        NativeLimits {
            stall_micros: 50_000,
        },
    )?;
    let mut engine = Engine::new_reserved(
        plan,
        storage::Limits {
            capacity_bytes: plan.capacity_bytes(),
        },
    )?;
    if wire.is_near8() {
        assert_eq!(engine.tick(Tick(0)), Err(Error::Configuration));
    }
    engine.enable_compact_wire(73)?;
    Ok(engine)
}

#[test]
fn negotiated_forward_near8_delivers_a_lost_source_before_feedback() -> TestResult {
    let mut sender = selected(SourceWire::TargetedNear8, Role::Client)?;
    let mut receiver = selected(SourceWire::TargetedNear8, Role::Server)?;
    let mut old = selected(SourceWire::TargetedExact, Role::Server)?;
    assert!(sender.uses_near8_sender());
    assert!(!receiver.uses_near8_sender());

    let mut frames = Vec::new();
    let mut delivered = 0;
    let mut accepted = 0;
    let mut number = 0;
    let mut largest = 0;
    let mut lost = 0;
    let mut regular = 0;
    let mut near = 0;
    sender.observe_near8_capacity(Tick(0), 0, 0)?;
    for index in 0..16_u8 {
        // Two real native records in each of four low-utilization 100 ms intervals
        // both fund the second group and activate the local capacity gate.
        let start = if index < 8 {
            u64::from(index / 2) * 100_000 + u64::from(index % 2) * 15_000 + 1000
        } else {
            400_000 + u64::from(index - 8) * 2000
        };
        let mut frame = packet(true, 3333, 95 + usize::from(index % 4), index + 1);
        *frame.last_mut().ok_or("native payload")? = 0;
        sender.enqueue_borrowed(Tick(start), &frame)?;
        sender
            .admit_borrowed(Tick(start))?
            .ok_or("native admission")?;
        frames.push(frame);
        let now = Tick(start + 750);
        sender.observe_near8_capacity(now, accepted, 0)?;
        for _ in 0..16 {
            sender.step(now, work())?;
            let mut buf = [0; 1500];
            let mut budget = OutboundBudget {
                packets: 1,
                wire_bytes: 1500,
            };
            if let Some(emission) =
                sender.poll(now, number, true, &mut buf, &mut budget, &mut witnesses())?
            {
                number += 1;
                let body = &mut buf[..emission.bytes];
                let extent = sender
                    .inspect_output_extent(body, emission.kind, false)?
                    .recovery
                    .ok_or("recovery extent")?;
                let token = sender.pending_carrier_output().ok_or("carrier output")?;
                sender.confirm_carrier_output(now, token)?;
                assert_eq!(emission.wire_bytes, IP_OVERHEAD + body.len());
                assert_eq!(budget.wire_bytes, 1500 - emission.wire_bytes);
                accepted += emission.wire_bytes as u64;
                sender.observe_near8_capacity(now, accepted, 0)?;
                match body[0] {
                    1 => {
                        if body[1] >= 8 {
                            largest = largest.max(extent.payload_bytes);
                        }
                        if body[1] == 15 {
                            lost += 1;
                            continue;
                        }
                    }
                    2 => regular += 1,
                    rolling::near8::TAG => {
                        assert_eq!(delivered, 15);
                        assert_eq!(&body[..2], &[6, 16]);
                        assert_eq!(
                            (extent.header_bytes, extent.payload_bytes),
                            (2, largest + 2)
                        );
                        assert_eq!(emission.wire_bytes, IP_OVERHEAD + 2 + 2 + largest);
                        assert_eq!(receiver.inspect_peer(body)?, EmissionKind::Repair);
                        let format =
                            Error::Rolling(rolling_records::Error::Rolling(rolling::Error::Format));
                        assert_eq!(sender.inspect_peer(body), Err(format));
                        assert_eq!(old.inspect_peer(body), Err(format));
                        assert_eq!(
                            old.accept_authenticated(
                                now,
                                emission.security_number,
                                EmissionKind::Repair,
                                body
                            ),
                            Err(format)
                        );
                        assert_eq!(old.statistics().committed, 0);
                        near = emission.wire_bytes as u64;
                    }
                    tag => return Err(format!("unexpected forward tag {tag}").into()),
                }
                receiver.accept_authenticated(
                    now,
                    emission.security_number,
                    emission.kind,
                    body,
                )?;
            }
            receiver.step(now, work())?;
            let mut native = [0; 1024];
            if let NativePreparation::Ready(value) =
                receiver.prepare_native(now, 128, Tick(now.0 + 50_000), &mut native)?
            {
                assert_eq!(&native[..value.bytes()], frames[delivered]);
                receiver.commit_native(now, value.token())?;
                delivered += 1;
            }
        }
    }
    // The reverse owner was never polled; its cumulative and named feedback
    // could not have triggered either delivery or a retransmission.
    let budget = sender.rolling_repair_budget().ok_or("budget status")?;
    let status = budget.near8.ok_or("near8 status")?;
    assert_eq!((lost, delivered, regular), (1, 16, 3));
    assert_eq!((status.sent_rows, status.sent_ip_bytes), (1, near));
    assert!(near > IP_OVERHEAD as u64);
    assert_eq!(
        (
            budget.unconfirmed_sources,
            budget.requested_retry_wire_bytes
        ),
        (16, 0)
    );
    Ok(())
}
