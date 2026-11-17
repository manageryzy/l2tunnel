use super::super::tests::{Family, Link, context, fixture, geometry, packet};
use super::*;
type Result = std::result::Result<(), Box<dyn std::error::Error>>;

fn policy(maximum: usize, records: usize) -> window::Config {
    window::Config {
        target_bandwidth_bps: 100_000_000,
        bootstrap_rtt_micros: 10_000,
        min_rtt_micros: 1,
        max_rtt_micros: 120_000,
        headroom_percent: 100,
        minimum_bytes: maximum as u64,
        max_inflight_bytes: (maximum * records) as u64,
        max_records: records,
        max_packet_bytes: maximum as u64,
        metadata_limit_bytes: 1 << 20,
        sample_ttl_micros: 100_000,
        flush_timeout_micros: 2_000_000,
    }
}
fn configuration(
    family: Family,
) -> std::result::Result<configuration::Configuration, Box<dyn std::error::Error>> {
    let old = fixture(family, false)?;
    let descriptor = old.descriptor();
    let common = |role| {
        let view = descriptor.direction(role);
        let old = view.common();
        configuration::CommonDirection::new(
            old.traffic(),
            old.pipeline(),
            old.bytes_per_second(),
            old.burst_bytes(),
            configuration::NativeWindow::Delivery(policy(view.max_native(), 1)),
        )
    };
    Ok(configuration::Configuration::new(
        old.envelope(),
        configuration::Descriptor::new(
            descriptor.path_mtu(),
            descriptor.duplex(),
            common(Role::Client)?,
            common(Role::Server)?,
            *descriptor.profile(),
        )?,
    )?)
}
fn engine(
    c: configuration::Configuration,
    role: Role,
) -> std::result::Result<Engine, Box<dyn std::error::Error>> {
    let plan = storage::Plan::for_engine(
        c,
        context(role),
        geometry(),
        NativeLimits {
            stall_micros: 500_000,
        },
    )?;
    let mut engine = Engine::new_reserved(
        plan,
        storage::Limits {
            capacity_bytes: plan.capacity_bytes(),
        },
    )?;
    engine.enable_compact_wire(if role == Role::Client { 17 } else { 73 })?;
    Ok(engine)
}

#[test]
fn actual_compact_native_window_waits_for_device_receipt_not_recovery_ack() -> Result {
    for family in [Family::Aligned, Family::Packed] {
        for role in [Role::Client, Role::Server] {
            let c = configuration(family)?;
            let peer = if role == Role::Client {
                Role::Server
            } else {
                Role::Client
            };
            let mut a = engine(c, role)?;
            let mut b = engine(c, peer)?;
            let usage = a.storage_usage().ok_or("reserved")?;
            assert!(usage.native_window_bytes > 0);
            assert_eq!(
                usage.capacity_bytes,
                usage.fixed_bytes
                    + usage.pipeline_bytes
                    + usage.record_bytes
                    + usage.ingress_bytes
                    + usage.fragment_bytes
                    + usage.native_window_bytes
            );
            let first = packet(false, 1001, 300, 5);
            let second = packet(false, 1002, 100, 7);
            a.enqueue_borrowed(Tick(0), &first)?;
            let second_metadata = a.enqueue_borrowed(Tick(0), &second)?;
            assert!(a.admit_borrowed(Tick(0))?.is_some());
            let mut refusal = None;
            assert!(
                a.admit_borrowed_diagnosed(Tick(0), |value| refusal = Some(value))?
                    .is_none()
            );
            let refusal = refusal.ok_or("actual native-window refusal")?;
            assert_eq!(
                refusal.reason,
                super::super::AdmissionBlock::NativeDeliveryWindow
            );
            assert_eq!(refusal.bytes, second.len());
            assert_eq!(refusal.flow, second_metadata.binding.id);
            assert_eq!(refusal.channel, second_metadata.binding.channel);
            assert_eq!(refusal.timing, second_metadata.timing);
            let mut forward = Link::new(&c, role)?;
            let mut reverse = Link::new(&c, peer)?;
            let mut clock = 1;
            let mut output = vec![0; b.native_max];
            let mut written = false;
            for step in 0..100 {
                clock = clock.max(step * 1000);
                forward.transfer(&mut a, &mut b, true, &mut clock)?;
                reverse.transfer(&mut b, &mut a, false, &mut clock)?;
                assert!(a.admit_borrowed(Tick(clock))?.is_none());
                for _ in 0..6 {
                    if let NativePreparation::Ready(pending) =
                        b.prepare_native(Tick(clock), 8, Tick(clock + 500_000), &mut output)?
                    {
                        assert_eq!(&output[..pending.bytes()], first);
                        // Decoding and recovery ACKs still do not release native debt.
                        assert_eq!(
                            a.native_window_status(Tick(clock))?
                                .ok_or("window")?
                                .outstanding
                                .records,
                            1
                        );
                        assert!(b.pending_native_delivery().is_none());
                        b.commit_native(Tick(clock), pending.token())?;
                        let receipt = b.pending_native_delivery().ok_or("real device receipt")?;
                        assert_eq!(receipt.bytes(), first.len());
                        assert_eq!(receipt.deadline(), pending.deadline());
                        assert_eq!(
                            b.prepare_native(Tick(clock), 8, Tick(u64::MAX), &mut output)?,
                            NativePreparation::Idle
                        );
                        a.accept_native_delivery(Tick(clock), Tick(clock), receipt.identity())?;
                        a.accept_native_delivery(Tick(clock), Tick(clock), receipt.identity())?;
                        b.native_delivery_queued(receipt)?;
                        let status = a.native_window_status(Tick(clock))?.ok_or("window")?;
                        assert_eq!(status.delivered.bytes, first.len() as u64);
                        assert_eq!(status.flushed_total.records, 1);
                        assert_eq!(status.outstanding.records, 0);
                        let mut refused = false;
                        assert!(
                            a.admit_borrowed_diagnosed(Tick(clock), |_| refused = true)?
                                .is_some()
                        );
                        assert!(!refused);
                        assert_eq!(a.storage_usage(), Some(usage));
                        written = true;
                        break;
                    }
                }
                if written {
                    break;
                }
            }
            assert!(written);
        }
    }
    Ok(())
}

#[test]
fn native_delivery_before_physical_callback_keeps_original_flush_deadline() -> Result {
    let c = configuration(Family::Aligned)?;
    let mut state = State::new(Plan::new(&c, Role::Client, 1)?.ok_or("window plan")?)?;
    let id = receiver::RecordIdentity {
        channel: receiver::ChannelId(0),
        record: receiver::RecordId(7),
    };
    state.admitted(Tick(10), ProfileIdentity::Aligned(id), 100)?;
    state.delivered(Tick(20), Tick(20), id)?;
    let status = state.status(Tick(20))?.ok_or("window")?;
    assert_eq!(status.delivered.records, 1);
    assert_eq!(status.flushed_total.records, 0);
    assert_eq!(status.retained_records, 1);
    assert!(!state.preview(Tick(20), 100)?);
    assert_eq!(status.next_flush_deadline, Some(Micros(2_000_010)));
    state.capture(&[receiver::UnitWitness {
        identity: id,
        index: 0,
        count: 2,
    }])?;
    state.confirm(Tick(30), Tick(15))?;
    assert_eq!(
        state
            .status(Tick(30))?
            .ok_or("window")?
            .flushed_total
            .records,
        0
    );
    state.capture(&[receiver::UnitWitness {
        identity: id,
        index: 1,
        count: 2,
    }])?;
    state.confirm(Tick(40), Tick(16))?;
    let status = state.status(Tick(40))?.ok_or("window")?;
    assert_eq!(status.flushed_total.records, 1);
    assert_eq!(status.retained_records, 0);
    assert!(status.sample.is_none());
    assert!(state.preview(Tick(40), 100)?);
    state.admitted(
        Tick(50),
        ProfileIdentity::Aligned(receiver::RecordIdentity {
            record: receiver::RecordId(9),
            ..id
        }),
        100,
    )?;
    assert_eq!(
        state.tick(Tick(2_000_050)),
        Err(Error::NativeWindow(window::Error::FlushExpired))
    );
    Ok(())
}

#[test]
fn native_delivery_plan_refuses_unwitnessed_profile_and_undersized_metadata() -> Result {
    assert!(matches!(
        storage::Plan::for_engine(
            configuration(Family::Swift)?,
            context(Role::Client),
            geometry(),
            NativeLimits { stall_micros: 1 }
        ),
        Err(storage::Error::Engine(Error::Unsupported(
            Capability::NativeWindow
        )))
    ));
    let c = configuration(Family::Aligned)?;
    let plan = Plan::new(&c, Role::Client, 1)?.ok_or("window")?;
    let heap = plan.heap_bytes();
    let mut selected = plan.send.ok_or("sender")?;
    selected.metadata_limit_bytes = selected.metadata_bytes()?;
    assert!(heap > selected.metadata_limit_bytes);
    // The exact planned layout is a separate charge from the controller itself.
    let common = c.descriptor().direction(Role::Client).common();
    let changed = configuration::CommonDirection::new(
        common.traffic(),
        common.pipeline(),
        common.bytes_per_second(),
        common.burst_bytes(),
        configuration::NativeWindow::Delivery(selected),
    )?;
    let c = configuration::Configuration::new(
        c.envelope(),
        configuration::Descriptor::new(
            c.descriptor().path_mtu(),
            c.descriptor().duplex(),
            changed,
            *c.descriptor().direction(Role::Server).common(),
            *c.descriptor().profile(),
        )?,
    )?;
    assert!(matches!(
        Plan::new(&c, Role::Client, 1),
        Err(Error::NativeWindow(window::Error::Configuration))
    ));
    Ok(())
}

#[test]
fn native_window_identity_churn_reuses_bounded_slots_without_duplicate_credit() -> Result {
    let c = configuration(Family::Aligned)?;
    let mut state = State::new(Plan::new(&c, Role::Client, 1)?.ok_or("window plan")?)?;
    let usage = state.usage();
    for index in 0..1100 {
        let now = index * 10;
        let id = receiver::RecordIdentity {
            channel: receiver::ChannelId((index % 2) as u8),
            record: receiver::RecordId(index + 7),
        };
        assert!(state.preview(Tick(now), 100)?);
        state.admitted(Tick(now), ProfileIdentity::Aligned(id), 100)?;
        let unknown = receiver::RecordIdentity {
            record: receiver::RecordId(index + 10_000),
            ..id
        };
        assert!(matches!(
            state.delivered(Tick(now), Tick(now), unknown),
            Err(Error::NativeWindow(window::Error::Feedback))
        ));
        state.capture(&[receiver::UnitWitness {
            identity: id,
            index: 0,
            count: 1,
        }])?;
        state.confirm(Tick(now + 2), Tick(now + 1))?;
        state.delivered(Tick(now + 3), Tick(now + 3), id)?;
        state.delivered(Tick(now + 4), Tick(now + 4), id)?;
        let status = state.status(Tick(now + 4))?.ok_or("native owner")?;
        assert_eq!(status.retained_records, 0);
        assert_eq!(status.delivered.records, index + 1);
        assert_eq!(status.delivered.bytes, (index + 1) * 100);
        assert_eq!(state.usage(), usage);
    }
    Ok(())
}
