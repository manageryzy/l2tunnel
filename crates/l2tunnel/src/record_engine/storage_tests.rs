use super::tests::{Family, Link, context, fixture, geometry, identity_channel, packet};
use super::*;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn native_limits() -> NativeLimits {
    NativeLimits {
        stall_micros: 50_000,
    }
}

fn build(configuration: configuration::Configuration, role: Role) -> TestResult<Engine> {
    let plan =
        storage::Plan::for_engine(configuration, context(role), geometry(), native_limits())?;
    Ok(Engine::new_reserved(
        plan,
        storage::Limits {
            capacity_bytes: plan.capacity_bytes(),
        },
    )?)
}

fn next(clock: &mut u64) -> Tick {
    let value = Tick(*clock);
    *clock += 1;
    value
}

fn peer(role: Role) -> Role {
    if role == Role::Client {
        Role::Server
    } else {
        Role::Client
    }
}

fn record_heap(configuration: &configuration::Configuration, role: Role) -> TestResult<usize> {
    let local = configuration.descriptor().local(role);
    Ok(match (local.send().profile(), local.receive().profile()) {
        (
            configuration::DirectionProfile::Swift(send),
            configuration::DirectionProfile::Swift(receive),
        ) => swift::storage::Plan::for_engine(*send, *receive)?.capacity_bytes(),
        (
            configuration::DirectionProfile::Aligned(send),
            configuration::DirectionProfile::Aligned(receive),
        ) => aligned::storage::Plan::for_duplex(*send, *receive)?.capacity_bytes(),
        (
            configuration::DirectionProfile::Packed(send),
            configuration::DirectionProfile::Packed(receive),
        ) => aligned::storage::Plan::for_packed_duplex(*send, *receive)?.capacity_bytes(),
        _ => return Err("fixture family mismatch".into()),
    })
}

fn with_forward_policy(
    configuration: configuration::Configuration,
    tcp: TcpControl,
    window: configuration::NativeWindow,
) -> TestResult<configuration::Configuration> {
    let descriptor = configuration.descriptor();
    let common = descriptor.direction(Role::Client).common();
    let mut traffic = common.traffic();
    traffic.tcp = tcp;
    let forward = configuration::CommonDirection::new(
        traffic,
        common.pipeline(),
        common.bytes_per_second(),
        common.burst_bytes(),
        window,
    )?;
    Ok(configuration::Configuration::new(
        configuration.envelope(),
        configuration::Descriptor::new(
            descriptor.path_mtu(),
            descriptor.duplex(),
            forward,
            *descriptor.direction(Role::Server).common(),
            *descriptor.profile(),
        )?,
    )?)
}

#[test]
fn complete_actual_plans_observe_nested_capacity_once_and_refuse_owned_output() -> TestResult {
    for family in [Family::Swift, Family::Aligned, Family::Packed] {
        for raw in [false, true] {
            let configuration = fixture(family, raw)?;
            for role in [Role::Client, Role::Server] {
                let plan = storage::Plan::for_engine(
                    configuration,
                    context(role),
                    geometry(),
                    native_limits(),
                )?;
                assert_eq!(plan.configuration(), &configuration);
                assert_eq!(plan.context(), context(role));
                assert_eq!(plan.geometry(), geometry());
                assert_eq!(plan.native_limits(), native_limits());
                let expected_pipeline = pipeline::storage::Plan::for_pipeline(
                    configuration
                        .descriptor()
                        .local(role)
                        .send()
                        .common()
                        .pipeline(),
                )?
                .capacity_bytes();
                let expected_record = record_heap(&configuration, role)?;
                assert_eq!(plan.heap_bytes(), expected_pipeline + expected_record);
                assert_eq!(
                    plan.capacity_bytes(),
                    std::mem::size_of::<Engine>() + plan.heap_bytes()
                );
                assert!(matches!(Engine::new_reserved(plan,
                    storage::Limits { capacity_bytes: plan.capacity_bytes() - 1 }),
                    Err(storage::Error::Limit { required, limit })
                        if required == plan.capacity_bytes() && limit + 1 == required));
                let mut engine = build(configuration, role)?;
                let usage = engine.storage_usage().ok_or("actual complete usage")?;
                let pipeline = engine.pipeline.storage_usage().ok_or("actual Pipeline")?;
                let (record_bytes, record_allocations) =
                    engine.owner.storage_heap().ok_or("actual record owner")?;
                assert_eq!(usage.fixed_bytes, std::mem::size_of::<Engine>());
                assert_eq!(usage.pipeline_bytes, expected_pipeline);
                assert_eq!(usage.pipeline_bytes, pipeline.capacity_bytes);
                assert_eq!(usage.record_bytes, expected_record);
                assert_eq!(usage.record_bytes, record_bytes);
                assert_eq!(
                    usage.capacity_bytes,
                    usage.fixed_bytes + usage.pipeline_bytes + usage.record_bytes
                );
                assert_eq!(usage.allocations, pipeline.allocations + record_allocations);
                assert_eq!(usage.capacity_bytes, plan.capacity_bytes());
                assert_eq!(usage.limit_bytes, plan.capacity_bytes());
                assert_eq!(engine.qualification(), Qualification::Reserved);
                let bytes = packet(raw, 1001, 100, 0x43);
                let metadata = engine.enqueue_borrowed(Tick(0), &bytes)?;
                let queue = engine.queue_usage();
                let before = engine.statistics();
                assert_eq!(engine.admit_one(Tick(0)), Err(Error::OwnedOutput));
                assert_eq!(engine.queue_usage(), queue);
                assert_eq!(engine.statistics(), before);
                assert_eq!(engine.failure(), None);
                assert_eq!(engine.storage_usage(), Some(usage));
                let actual = engine
                    .admit_borrowed(Tick(0))?
                    .ok_or("actual codec admission")?;
                assert_eq!(actual.metadata, metadata);
                assert_eq!(identity_channel(actual.permit), metadata.binding.channel);
                assert_eq!(engine.queue_usage(), pipeline::QueueUsage::default());
                assert_eq!(engine.statistics().admitted, 1);
            }
        }
        for (tcp, capability) in [
            (TcpControl::TunnelCredits, Capability::TunnelCredits),
            (TcpControl::SplitTcpProxy, Capability::TcpProxy),
        ] {
            let configuration = with_forward_policy(
                fixture(family, true)?,
                tcp,
                configuration::NativeWindow::Disabled,
            )?;
            assert!(
                matches!(storage::Plan::for_engine(configuration, context(Role::Client), geometry(), native_limits()),
                Err(storage::Error::Engine(Error::Unsupported(actual))) if actual == capability)
            );
        }
        let configuration = with_forward_policy(
            fixture(family, true)?,
            TcpControl::System,
            configuration::NativeWindow::Delivery(l2tunnel_flow_control::delivery_window::Config {
                target_bandwidth_bps: 4_000_000,
                bootstrap_rtt_micros: 70_000,
                min_rtt_micros: 100,
                max_rtt_micros: 200_000,
                headroom_percent: 125,
                minimum_bytes: 1024,
                max_inflight_bytes: 100_000,
                max_records: 17,
                max_packet_bytes: 1024,
                metadata_limit_bytes: 10_000,
                sample_ttl_micros: 4_000_000,
                flush_timeout_micros: 20_000,
            }),
        )?;
        assert!(matches!(
            storage::Plan::for_engine(
                configuration,
                context(Role::Client),
                geometry(),
                native_limits()
            ),
            Err(storage::Error::Engine(Error::Unsupported(
                Capability::NativeWindow
            )))
        ));
    }
    Ok(())
}

fn first_port(
    configuration: &configuration::Configuration,
    raw: bool,
    role: Role,
) -> TestResult<u16> {
    let configuration::DirectionProfile::Swift(config) =
        configuration.descriptor().direction(role).profile()
    else {
        return Ok(1001);
    };
    (1000..1064)
        .find(|port| {
            let bytes = packet(raw, *port, 100, 7);
            let implicit = if raw {
                swift::flow::classify_ip(&bytes, config.channels)
            } else {
                swift::flow::classify_ethernet(&bytes, config.channels)
            };
            implicit != 0
        })
        .ok_or_else(|| "bounded selected-channel fixture".into())
}

fn actual_pair(
    configuration: configuration::Configuration,
    raw: bool,
    role: Role,
    pressure: bool,
) -> TestResult {
    let mut sender = build(configuration, role)?;
    let mut receiver = build(configuration, peer(role))?;
    let sender_usage = sender.storage_usage();
    let receiver_usage = receiver.storage_usage();
    let native_max = configuration.descriptor().direction(role).max_native();
    let port = first_port(&configuration, raw, role)?;
    let mut originals = Vec::new();
    for (port, length, value) in [
        (port, if pressure { native_max } else { 100 }, 7),
        (port + 1, if raw { 40 } else { 54 }, 8),
        (port, 120, 9),
    ] {
        let bytes = packet(raw, port, length, value);
        let metadata = sender.enqueue_borrowed(Tick(0), &bytes)?;
        originals.push((bytes, metadata));
    }
    assert_eq!(
        originals
            .iter()
            .map(|(_, metadata)| metadata.binding.channel)
            .collect::<Vec<_>>(),
        [0, 1, 0]
    );
    let mut clock = 0;
    let mut accepted: Vec<(ProfileIdentity, Vec<u8>)> = Vec::new();
    if pressure {
        let admitted = sender
            .admit_borrowed(next(&mut clock))?
            .ok_or("first actual admission")?;
        assert_eq!(admitted.metadata, originals[0].1);
        accepted.push((admitted.permit, originals[0].0.clone()));
        let queue = sender.queue_usage();
        for _ in 0..3 {
            assert!(sender.admit_borrowed(next(&mut clock))?.is_none());
            assert_eq!(sender.queue_usage(), queue);
            assert_eq!(sender.statistics().admitted, 1);
            assert_eq!(sender.failure(), None);
            assert_eq!(sender.storage_usage(), sender_usage);
        }
    }
    let mut data = Link::new(&configuration, role)?;
    let mut feedback = Link::new(&configuration, peer(role))?;
    let mut native = vec![0; native_max];
    let mut delivered = Vec::new();
    let mut done = false;
    for step in 0..64 {
        clock = clock.max(step * 10_000);
        for _ in 0..8 {
            let Some(admitted) = sender.admit_borrowed(next(&mut clock))? else {
                break;
            };
            assert_eq!(
                identity_channel(admitted.permit),
                admitted.metadata.binding.channel
            );
            let original = originals
                .iter()
                .find(|(_, metadata)| *metadata == admitted.metadata)
                .ok_or("actual original metadata")?;
            assert!(
                !accepted
                    .iter()
                    .any(|(identity, _)| *identity == admitted.permit)
            );
            accepted.push((admitted.permit, original.0.clone()));
        }
        data.transfer(&mut sender, &mut receiver, true, &mut clock)?;
        for _ in 0..16 {
            let now = next(&mut clock);
            let cap = Tick(now.0 + 10_000);
            let NativePreparation::Ready(prepared) =
                receiver.prepare_native(now, 8, cap, &mut native)?
            else {
                continue;
            };
            let actual = &native[..prepared.bytes()];
            assert!(
                accepted
                    .iter()
                    .any(|(identity, bytes)| *identity == prepared.identity() && bytes == actual)
            );
            assert!(!delivered.contains(&prepared.identity()));
            assert!(prepared.deadline() > now && prepared.deadline() <= cap);
            assert_eq!(receiver.pending_native(), Some(prepared));
            let mut other = [0xa7; 17];
            assert_eq!(
                receiver.prepare_native(next(&mut clock), 0, Tick(u64::MAX), &mut other)?,
                NativePreparation::AlreadyPending(prepared)
            );
            assert_eq!(other, [0xa7; 17]);
            receiver.commit_native(next(&mut clock), prepared.token())?;
            let committed = receiver.statistics().committed;
            assert_eq!(
                receiver.commit_native(next(&mut clock), prepared.token()),
                Err(Error::Token)
            );
            assert_eq!(receiver.statistics().committed, committed);
            delivered.push(prepared.identity());
        }
        // The peer has no queued user data: its actual feedback stays serviceable
        // with data disabled, under the same once-only full-wire allowance.
        feedback.transfer(&mut receiver, &mut sender, false, &mut clock)?;
        assert_eq!(sender.storage_usage(), sender_usage);
        assert_eq!(receiver.storage_usage(), receiver_usage);
        if accepted.len() == originals.len()
            && delivered.len() == originals.len()
            && sender.drained()?
            && receiver.drained()?
        {
            done = true;
            break;
        }
    }
    assert!(
        done,
        "reserved actual pair exceeded its finite injected-time bound"
    );
    assert_eq!(sender.statistics().admitted, 3);
    assert_eq!(receiver.statistics().prepared, 3);
    assert_eq!(receiver.statistics().committed, 3);
    assert!(sender.statistics().emitted > 0);
    assert!(receiver.statistics().emitted > 0);
    assert_eq!(sender.failure(), None);
    assert_eq!(receiver.failure(), None);
    Ok(())
}

#[test]
fn actual_reserved_families_deliver_tap_tun_in_both_unequal_directions_with_feedback() -> TestResult
{
    for family in [Family::Swift, Family::Aligned, Family::Packed] {
        for raw in [false, true] {
            for role in [Role::Client, Role::Server] {
                actual_pair(fixture(family, raw)?, raw, role, false)?;
            }
        }
    }
    Ok(())
}

#[test]
fn actual_reserved_full_or_busy_keeps_queue_until_the_same_head_can_retry() -> TestResult {
    for family in [Family::Swift, Family::Aligned, Family::Packed] {
        let original = fixture(family, true)?;
        let descriptor = original.descriptor();
        let mut profile = *descriptor.profile();
        if let configuration::Profile::Swift { forward, .. } = &mut profile {
            forward.codec.queue_bytes = forward.codec.max_packet + swift::FRAME_PREFIX;
        }
        let common = descriptor.direction(Role::Client).common();
        let mut pipeline = common.pipeline();
        if let pipeline::Profile::TunDrr(policy) = &mut pipeline.profile {
            policy.base_quantum_bytes = 2048;
        }
        let forward = configuration::CommonDirection::new(
            common.traffic(),
            pipeline,
            common.bytes_per_second(),
            common.burst_bytes(),
            common.native_window(),
        )?;
        let configuration = configuration::Configuration::new(
            original.envelope(),
            configuration::Descriptor::new(
                descriptor.path_mtu(),
                descriptor.duplex(),
                forward,
                *descriptor.direction(Role::Server).common(),
                profile,
            )?,
        )?;
        actual_pair(configuration, true, Role::Client, true)?;
    }
    Ok(())
}

struct DifferentialLink {
    number: u64,
    overhead: usize,
    first: Vec<u8>,
    second: Vec<u8>,
    first_witnesses: Vec<receiver::UnitWitness>,
    second_witnesses: Vec<receiver::UnitWitness>,
    emitted: usize,
    feedback: usize,
}

impl DifferentialLink {
    fn new(engine: &Engine, role: Role) -> Self {
        let witness = receiver::UnitWitness {
            identity: receiver::RecordIdentity {
                channel: receiver::ChannelId(0),
                record: receiver::RecordId(0),
            },
            index: 0,
            count: 1,
        };
        Self {
            number: if role == Role::Client {
                (1u64 << 48) + 0x12345
            } else {
                (1u64 << 56) + 0x34567
            },
            overhead: engine.overhead,
            first: vec![0; engine.send_max],
            second: vec![0; engine.send_max],
            first_witnesses: vec![witness; engine.witnesses],
            second_witnesses: vec![witness; engine.witnesses],
            emitted: 0,
            feedback: 0,
        }
    }

    fn transfer(
        &mut self,
        senders: (&mut Engine, &mut Engine),
        receivers: (&mut Engine, &mut Engine),
        allow_data: bool,
        clock: &mut u64,
    ) -> TestResult {
        for _ in 0..16 {
            let now = next(clock);
            let before = OutboundBudget {
                packets: 1,
                wire_bytes: self.first.len() + self.overhead,
            };
            let mut first_budget = before;
            let mut second_budget = before;
            let first = senders.0.poll(
                now,
                self.number,
                allow_data,
                &mut self.first,
                &mut first_budget,
                &mut self.first_witnesses,
            )?;
            let second = senders.1.poll(
                now,
                self.number,
                allow_data,
                &mut self.second,
                &mut second_budget,
                &mut self.second_witnesses,
            )?;
            assert_eq!(first, second);
            assert_eq!(first_budget, second_budget);
            let Some(emission) = first else {
                assert_eq!(first_budget, before);
                return Ok(());
            };
            assert!(self.number > u64::from(u32::MAX));
            assert_eq!(emission.security_number, self.number);
            assert_eq!(emission.wire_bytes, emission.bytes + self.overhead);
            assert_eq!(first_budget.packets, 0);
            assert_eq!(
                first_budget.wire_bytes,
                before.wire_bytes - emission.wire_bytes
            );
            assert_eq!(
                &self.first[..emission.bytes],
                &self.second[..emission.bytes]
            );
            assert_eq!(
                &self.first_witnesses[..emission.witnesses],
                &self.second_witnesses[..emission.witnesses]
            );
            if !allow_data {
                assert_eq!(emission.kind, EmissionKind::Feedback);
            }
            if emission.kind == EmissionKind::Feedback {
                self.feedback += 1;
            }
            let now = next(clock);
            for sender in [&mut *senders.0, &mut *senders.1] {
                if let Some(token) = sender.pending_carrier_output() {
                    assert_eq!(token.emission(), emission);
                    sender.confirm_carrier_output(now, token)?;
                }
            }
            // These paired pure owners receive the same caller-authenticated
            // plaintext. Security and physical socket custody remain external.
            receivers.0.accept_authenticated(
                now,
                self.number,
                emission.kind,
                &mut self.first[..emission.bytes],
            )?;
            receivers.1.accept_authenticated(
                now,
                self.number,
                emission.kind,
                &mut self.second[..emission.bytes],
            )?;
            self.number = self.number.checked_add(1).ok_or("security number")?;
            self.emitted += 1;
        }
        Ok(())
    }
}

fn differential(configuration: configuration::Configuration, raw: bool) -> TestResult {
    let mut legacy_sender = Engine::new_functional(
        configuration,
        context(Role::Client),
        geometry(),
        native_limits(),
    )?;
    let mut legacy_receiver = Engine::new_functional(
        configuration,
        context(Role::Server),
        geometry(),
        native_limits(),
    )?;
    let mut sender = build(configuration, Role::Client)?;
    let mut receiver = build(configuration, Role::Server)?;
    assert_eq!(legacy_sender.storage_usage(), None);
    let sender_usage = sender.storage_usage();
    let receiver_usage = receiver.storage_usage();
    let port = first_port(&configuration, raw, Role::Client)?;
    let mut originals = Vec::new();
    for (port, length, value) in [(port, 100, 0x37), (port + 1, 500, 0x83), (port, 120, 0x49)] {
        let bytes = packet(raw, port, length, value);
        let metadata = sender.enqueue_borrowed(Tick(0), &bytes)?;
        assert_eq!(metadata, legacy_sender.enqueue(Tick(0), bytes.clone())?);
        originals.push((bytes, metadata));
    }
    let mut data = DifferentialLink::new(&sender, Role::Client);
    let mut feedback = DifferentialLink::new(&receiver, Role::Server);
    let mut first_native = vec![0; receiver.native_max];
    let mut second_native = vec![0; receiver.native_max];
    let mut accepted = Vec::new();
    let mut delivered = Vec::new();
    let mut clock = 0;
    let mut done = false;
    for step in 0..64 {
        clock = clock.max(step * 10_000);
        for _ in 0..8 {
            let now = next(&mut clock);
            let first = legacy_sender.admit_one(now)?;
            let second = sender.admit_borrowed(now)?;
            match (first, second) {
                (Some(first), Some(second)) => {
                    assert_eq!(first.permit, second.permit);
                    assert_eq!(first.packet.metadata, second.metadata);
                    assert_eq!(
                        identity_channel(second.permit),
                        second.metadata.binding.channel
                    );
                    assert!(originals.contains(&(first.packet.payload.clone(), second.metadata)));
                    accepted.push((first.permit, first.packet.payload));
                }
                (None, None) => break,
                _ => return Err("functional/reserved admission divergence".into()),
            }
        }
        data.transfer(
            (&mut legacy_sender, &mut sender),
            (&mut legacy_receiver, &mut receiver),
            true,
            &mut clock,
        )?;
        for _ in 0..16 {
            let now = next(&mut clock);
            let cap = Tick(now.0 + 10_000);
            let first = legacy_receiver.prepare_native(now, 8, cap, &mut first_native)?;
            let second = receiver.prepare_native(now, 8, cap, &mut second_native)?;
            assert_eq!(first, second);
            if let NativePreparation::Ready(prepared) = first {
                assert_eq!(
                    &first_native[..prepared.bytes()],
                    &second_native[..prepared.bytes()]
                );
                assert!(
                    accepted
                        .iter()
                        .any(|(identity, bytes)| *identity == prepared.identity()
                            && bytes == &second_native[..prepared.bytes()])
                );
                assert!(!delivered.contains(&prepared.identity()));
                let now = next(&mut clock);
                legacy_receiver.commit_native(now, prepared.token())?;
                let actual = receiver
                    .pending_native()
                    .ok_or("actual reserved pending token")?;
                receiver.commit_native(now, actual.token())?;
                delivered.push(prepared.identity());
            }
        }
        feedback.transfer(
            (&mut legacy_receiver, &mut receiver),
            (&mut legacy_sender, &mut sender),
            false,
            &mut clock,
        )?;
        assert_eq!(sender.statistics(), legacy_sender.statistics());
        assert_eq!(receiver.statistics(), legacy_receiver.statistics());
        assert_eq!(sender.queue_usage(), legacy_sender.queue_usage());
        assert_eq!(sender.storage_usage(), sender_usage);
        assert_eq!(receiver.storage_usage(), receiver_usage);
        if accepted.len() == originals.len()
            && delivered.len() == originals.len()
            && sender.drained()?
            && receiver.drained()?
            && legacy_sender.drained()?
            && legacy_receiver.drained()?
        {
            done = true;
            break;
        }
    }
    assert!(
        done,
        "functional/reserved differential exceeded its finite injected-time bound"
    );
    assert!(data.emitted > 0);
    assert!(feedback.feedback > 0);
    assert_eq!(delivered.len(), 3);
    Ok(())
}

#[test]
fn actual_reserved_and_functional_families_keep_full64_bytes_ids_witnesses_and_wire_budgets()
-> TestResult {
    for family in [Family::Swift, Family::Aligned, Family::Packed] {
        for raw in [false, true] {
            differential(fixture(family, raw)?, raw)?;
        }
    }
    Ok(())
}
