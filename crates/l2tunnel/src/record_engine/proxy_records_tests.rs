use super::super::tests::{Family, context, fixture, geometry};
use super::super::*;
use configuration::{CommonDirection, Descriptor, Profile};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn configuration(
    channels: u16,
    repair: usize,
    native: usize,
) -> TestResult<configuration::Configuration> {
    let original = fixture(Family::Aligned, true)?;
    let Profile::Aligned {
        mut forward,
        mut reverse,
    } = *original.descriptor().profile()
    else {
        return Err("aligned fixture".into());
    };
    for config in [&mut forward, &mut reverse] {
        config.receiver.channels = channels;
        config.receiver.body.max_frame_bytes = native;
        config.recovery.repair_symbols = repair;
    }
    let common = |role| -> TestResult<CommonDirection> {
        let old = original.descriptor().direction(role).common();
        let mut traffic = old.traffic();
        traffic.tcp = TcpControl::SplitTcpProxy;
        let mut pipeline = old.pipeline();
        pipeline.flows.channels = channels;
        // Exercise the parse bypass even with learned native reverse affinity.
        pipeline.flows.mapping = pipeline::Mapping::ConnectionRoundRobinLearned;
        pipeline.parse.max_packet_bytes = native;
        pipeline.queue.packets = 2;
        if let pipeline::Profile::TunDrr(ref mut tun) = pipeline.profile {
            tun.per_flow.packets = 2;
        }
        Ok(CommonDirection::new(
            traffic,
            pipeline,
            old.bytes_per_second(),
            old.burst_bytes(),
            old.native_window(),
        )?)
    };
    Ok(configuration::Configuration::new(
        original.envelope(),
        Descriptor::new(
            1500,
            l2tunnel_core::Duplex::Full,
            common(Role::Client)?,
            common(Role::Server)?,
            Profile::Aligned { forward, reverse },
        )?,
    )?)
}

fn reserved(config: configuration::Configuration, role: Role) -> TestResult<Engine> {
    let plan = storage::Plan::for_engine(
        config,
        context(role),
        geometry(),
        NativeLimits {
            stall_micros: 10_000,
        },
    )?;
    Ok(Engine::new_reserved(
        plan,
        storage::Limits {
            capacity_bytes: plan.capacity_bytes(),
        },
    )?)
}

#[test]
fn explicit_proxy_records_retain_actual_queue_timing_and_reject_native_admission() -> TestResult {
    let config = configuration(1, 0, 96)?;
    let mut engine = reserved(config, Role::Client)?;
    assert!(engine.proxy_records());
    let bytes = b"LTPW opaque bytes, never an IP packet";
    assert_eq!(
        engine.enqueue_borrowed(Tick(0), bytes),
        Err(Error::Unsupported(Capability::TcpProxy))
    );
    assert_eq!(
        engine.ingest_borrowed_at(Tick(0), Tick(0), bytes, Tick(100)),
        Err(Error::Unsupported(Capability::TcpProxy))
    );
    let metadata = engine.enqueue_proxy_borrowed(Tick(1), Tick(2), bytes, Tick(100))?;
    assert_eq!(
        metadata.classification.kind,
        l2tunnel_packet::PacketKind::ProxyRecord
    );
    assert_eq!(
        metadata.classification.key,
        l2tunnel_packet::FlowKey::proxy_records()
    );
    assert!(metadata.classification.ip.is_none());
    assert_eq!(metadata.timing.received, Duration::from_micros(1));
    assert_eq!(
        metadata.timing.original_deadline,
        Some(Duration::from_micros(100))
    );
    engine.enqueue_proxy_borrowed(Tick(3), Tick(3), b"second", Tick(100))?;
    let usage = engine.queue_usage();
    assert!(
        engine
            .enqueue_proxy_borrowed(Tick(4), Tick(4), b"third", Tick(100))
            .is_err()
    );
    assert_eq!(engine.queue_usage(), usage);
    assert_eq!(engine.admit_borrowed(Tick(100)), Err(Error::Expired));
    assert_eq!(engine.queue_usage(), usage);
    assert_eq!(engine.failure(), Some(Error::Expired));
    Ok(())
}

#[test]
fn proxy_profile_refuses_unordered_fec_and_unselected_paths() -> TestResult {
    for config in [configuration(2, 0, 96)?, configuration(1, 1, 96)?] {
        assert!(matches!(
            Engine::new_functional(
                config,
                context(Role::Client),
                geometry(),
                NativeLimits {
                    stall_micros: 10_000
                }
            ),
            Err(Error::Unsupported(Capability::TcpProxy))
        ));
    }
    let mut fragmented = reserved(configuration(1, 0, 123)?, Role::Client)?;
    assert!(fragmented.proxy_records());
    fragmented.enqueue_proxy_borrowed(Tick(0), Tick(0), &[7; 123], Tick(100_000))?;
    assert!(fragmented.admit_borrowed(Tick(1))?.is_some());
    let mut native = reserved(fixture(Family::Aligned, true)?, Role::Client)?;
    assert_eq!(
        native.enqueue_proxy_borrowed(Tick(0), Tick(0), b"opaque", Tick(100)),
        Err(Error::Unsupported(Capability::TcpProxy))
    );
    let mut engine = reserved(configuration(1, 0, 96)?, Role::Client)?;
    assert!(
        engine
            .enqueue_proxy_borrowed(Tick(0), Tick(1), &[], Tick(10))
            .is_err()
    );
    assert!(
        engine
            .enqueue_proxy_borrowed(Tick(0), Tick(2), &[0; 97], Tick(10))
            .is_err()
    );
    assert_eq!(
        engine.enqueue_proxy_borrowed(Tick(0), Tick(10), b"late", Tick(10)),
        Err(Error::Pipeline(pipeline::PipelineError::Timing))
    );
    assert_eq!(engine.queue_usage(), pipeline::QueueUsage::default());
    Ok(())
}

#[test]
fn opaque_proxy_body_has_exact_admission_witness_and_retained_physical_custody() -> TestResult {
    let config = configuration(1, 0, 96)?;
    let mut sender = reserved(config, Role::Client)?;
    let mut recipient = reserved(config, Role::Server)?;
    let bytes = b"LTPW\0\xff arbitrary proxy record with no native headers";
    sender.enqueue_proxy_borrowed(Tick(0), Tick(1), bytes, Tick(100_000))?;
    let admitted = sender
        .admit_borrowed(Tick(2))?
        .ok_or("actual ARQ admission")?;
    let ProfileIdentity::Aligned(identity) = admitted.permit else {
        return Err("aligned identity".into());
    };
    let mut output = [0; 1500];
    let mut witnesses = [receiver::UnitWitness {
        identity,
        index: usize::MAX,
        count: usize::MAX,
    }];
    let mut budget = OutboundBudget {
        packets: 1,
        wire_bytes: 1500,
    };
    let emitted = sender
        .poll(Tick(3), 9, true, &mut output, &mut budget, &mut witnesses)?
        .ok_or("actual source")?;
    assert_eq!(emitted.kind, EmissionKind::Source(SourceForm::DirectArq));
    assert_eq!(emitted.witnesses, 1);
    assert_eq!(
        witnesses[0],
        receiver::UnitWitness {
            identity,
            index: 0,
            count: 1
        }
    );
    let physical = sender
        .pending_carrier_output()
        .ok_or("real retained token")?;
    assert_eq!(physical.emission(), emitted);
    let mut blocked_budget = OutboundBudget {
        packets: 1,
        wire_bytes: 1500,
    };
    let mut untouched = [0xa5; 1500];
    assert_eq!(
        sender.poll(
            Tick(4),
            10,
            true,
            &mut untouched,
            &mut blocked_budget,
            &mut witnesses
        )?,
        Some(emitted)
    );
    assert_eq!(untouched, [0xa5; 1500]);
    assert_eq!(
        blocked_budget,
        OutboundBudget {
            packets: 1,
            wire_bytes: 1500
        }
    );
    assert_eq!(sender.pending_carrier_output().as_ref(), Some(&physical));
    sender.confirm_carrier_output(Tick(5), physical)?;
    assert!(sender.pending_carrier_output().is_none());
    recipient.accept_authenticated(
        Tick(6),
        emitted.security_number,
        emitted.kind,
        &mut output[..emitted.bytes],
    )?;
    let mut restored = [0; 96];
    let pending = loop {
        match recipient.prepare_native(Tick(7), 8, Tick(100_000), &mut restored)? {
            NativePreparation::Ready(pending) => break pending,
            NativePreparation::Progress => continue,
            _ => return Err("missing recovered opaque record".into()),
        }
    };
    assert_eq!(&restored[..pending.bytes()], bytes);
    assert_eq!(pending.identity(), ProfileIdentity::Aligned(identity));
    assert_eq!(
        recipient.prepare_native(Tick(8), 8, Tick(200_000), &mut [0; 96])?,
        NativePreparation::AlreadyPending(pending)
    );
    recipient.commit_native(Tick(9), pending.token())?;
    assert!(recipient.pending_native().is_none());
    Ok(())
}
