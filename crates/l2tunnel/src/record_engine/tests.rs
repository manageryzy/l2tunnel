use super::*;
use l2tunnel_codec::aligned_body;
use l2tunnel_core::{Duplex, traffic};
use l2tunnel_fec as fec;
use l2tunnel_recovery::ArqConfig;
use l2tunnel_reliable::ReliableConfig;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Family {
    Swift,
    Aligned,
    Packed,
}

fn swift_policy(reverse: bool, raw: bool) -> swift::records::Config {
    swift::records::Config {
        channels: if reverse { 2 } else { 3 },
        layer: if raw {
            swift::records::Layer::Ip
        } else {
            swift::records::Layer::Ethernet
        },
        max_native: 1024,
        codec: swift::Config {
            datagram_bytes: if reverse { 320 } else { 256 },
            window: if reverse { 7 } else { 5 },
            repair_numerator: 1,
            repair_denominator: 2,
            flow_sources: 16,
            queue_bytes: if reverse { 49152 } else { 32768 },
            max_packet: 1025,
            flush_micros: if reverse { 201 } else { 101 },
            feedback_micros: if reverse { 701 } else { 503 },
            tail_micros: 5000,
            min_rto_micros: 20000,
            max_rto_micros: 100000,
        },
    }
}

fn aligned_policy(reverse: bool, raw: bool, packed: bool) -> aligned::Config {
    let symbol = if reverse { 256 } else { 128 };
    let units = if reverse { 4 } else { 3 };
    let original = if packed {
        56 + 8 * units + symbol
    } else {
        48 + symbol
    };
    let source = 44 + original;
    let count = if reverse { 2 } else { 3 };
    let fec_packet = 56 + count + 2 + source;
    let fragments = 65535usize.div_ceil(symbol - 8);
    aligned::Config {
        native_policy: if raw {
            aligned::NativePolicy::RawIp
        } else {
            aligned::NativePolicy::EthernetHeaders
        },
        receiver: receiver::Limits {
            body: aligned_body::Config {
                max_frame_bytes: if reverse { 1152 } else { 1024 },
                symbol_bytes: symbol,
                elide_payload_length: !raw,
                predictive: !raw,
                timestamp_pair_dictionary: !raw,
                independent_short_frame_bytes: 0,
            },
            channels: if reverse { 2 } else { 3 },
            first_record: receiver::RecordId(if reverse { 19 } else { 7 }),
            first_source: receiver::SourceId(0),
            record_window: 32,
            source_window: 32,
            lookahead_records: 8,
            lookahead_bytes: if packed { units * 65535 } else { 8192 },
            lookahead_fragments: if packed { units * fragments } else { 8192 },
            max_fragments_per_record: fragments,
            lifetime_ticks: 5000,
        },
        recovery: ReliableConfig {
            arq: ArqConfig {
                max_source_bytes: original,
                send_bytes: 8 * original,
                receive_bytes: 8 * original,
                send_records: 8,
                receive_records: 8,
                initial_rto: Duration::from_millis(if reverse { 150 } else { 100 }),
                maximum_rto: Duration::from_millis(400),
                ack_delay: Duration::from_millis(if reverse { 7 } else { 1 }),
                max_retries: 2,
            },
            fec: fec::DecoderConfig {
                block: fec::BlockConfig {
                    max_sources: count,
                    max_source_bytes: source,
                    max_packet_bytes: fec_packet,
                    max_work_per_symbol: 1_000_000,
                },
                max_generations: 4,
                max_symbols_per_generation: 5,
                max_reserved_bytes: 1_000_000,
                max_lifetime_ticks: 50,
                generation_window: 32,
            },
            repair_symbols: 1,
            flush_after: Duration::from_millis(if reverse { 9 } else { 5 }),
            max_restored_packets: 16,
            max_restored_bytes: 16 * source,
            outer_overhead_bytes: if reverse { 73 } else { 17 },
        },
        // A loose validated ceiling is preserved; it is not the minimum output buffer.
        max_recovery_packet_bytes: 8 + fec_packet + if reverse { 9 } else { 7 },
    }
}

fn common(
    reverse: bool,
    raw: bool,
    channels: u16,
    native: usize,
) -> TestResult<configuration::CommonDirection> {
    let policy = if raw {
        traffic::TrafficPolicy {
            layer: traffic::NetworkLayer::Tun,
            tcp: TcpControl::System,
            qos: traffic::Qos::WeightedDeficit,
        }
    } else {
        traffic::TrafficPolicy::tap()
    };
    Ok(configuration::CommonDirection::new(
        policy,
        pipeline::PipelineConfig {
            profile: if raw {
                pipeline::Profile::TunDrr(pipeline::TunQosConfig {
                    base_quantum_bytes: 64,
                    max_weight: 4,
                    per_flow: pipeline::QueueLimits {
                        bytes: 8192,
                        packets: 16,
                    },
                })
            } else {
                pipeline::Profile::TapSystem
            },
            flows: pipeline::FlowTableConfig {
                capacity: 8,
                channels,
                mapping: pipeline::Mapping::ConnectionRoundRobin,
                idle_timeout: Duration::from_secs(5),
            },
            parse: pipeline::ParseLimits {
                max_packet_bytes: native,
                ..pipeline::ParseLimits::default()
            },
            queue: pipeline::QueueLimits {
                bytes: 32768,
                packets: 32,
            },
        },
        if reverse { 1_000_002 } else { 2_000_001 },
        if reverse { 8195 } else { 8193 },
        configuration::NativeWindow::Disabled,
    )?)
}

pub(super) fn fixture(family: Family, raw: bool) -> TestResult<configuration::Configuration> {
    let profile = match family {
        Family::Swift => configuration::Profile::Swift {
            forward: swift_policy(false, raw),
            reverse: swift_policy(true, raw),
        },
        Family::Aligned => configuration::Profile::Aligned {
            forward: aligned_policy(false, raw, false),
            reverse: aligned_policy(true, raw, false),
        },
        Family::Packed => configuration::Profile::Packed {
            forward: aligned::packed::Config {
                base: aligned_policy(false, raw, true),
                hold_micros: 201,
                max_units: 3,
                work_limit: 2,
            },
            reverse: aligned::packed::Config {
                base: aligned_policy(true, raw, true),
                hold_micros: 701,
                max_units: 4,
                work_limit: 3,
            },
        },
    };
    let native = if family == Family::Swift { 1024 } else { 1152 };
    Ok(configuration::Configuration::new(
        configuration::EnvelopeDigest::new([0x39; 32]),
        configuration::Descriptor::new(
            1500,
            Duplex::Full,
            common(false, raw, 3, 1024)?,
            common(true, raw, 2, native)?,
            profile,
        )?,
    )?)
}

pub(super) fn context(role: Role) -> Context {
    Context {
        session: 0x1234_5678_9012_3456,
        epoch: 7,
        role,
    }
}
pub(super) fn geometry() -> Geometry {
    Geometry {
        forward_overhead_bytes: 17,
        reverse_overhead_bytes: 73,
    }
}
fn next(clock: &mut u64) -> Tick {
    let now = Tick(*clock);
    *clock += 1;
    now
}
pub(super) fn identity_channel(identity: ProfileIdentity) -> u16 {
    match identity {
        ProfileIdentity::Swift(identity) => identity.channel.index() as u16,
        ProfileIdentity::Aligned(identity)
        | ProfileIdentity::Packed(identity)
        | ProfileIdentity::Rolling(identity) => u16::from(identity.channel.0),
    }
}

pub(super) fn packet(raw: bool, port: u16, native_length: usize, value: u8) -> Vec<u8> {
    let length = native_length - if raw { 0 } else { 14 };
    let mut bytes = vec![value; length];
    bytes[..40].fill(0);
    bytes[0] = 0x45;
    bytes[2..4].copy_from_slice(&(length as u16).to_be_bytes());
    bytes[4..6].copy_from_slice(&u16::from(value).to_be_bytes());
    bytes[8] = 64;
    bytes[9] = 6;
    bytes[12..16].copy_from_slice(&[10, 0, 0, 1]);
    bytes[16..20].copy_from_slice(&[10, 0, 0, 2]);
    bytes[20..22].copy_from_slice(&port.to_be_bytes());
    bytes[22..24].copy_from_slice(&443_u16.to_be_bytes());
    bytes[24..28].copy_from_slice(&u32::from(value).to_be_bytes());
    bytes[32] = 0x50;
    bytes[33] = 0x10;
    if raw {
        bytes
    } else {
        let mut frame = vec![1; 6];
        frame.extend_from_slice(&[2; 6]);
        frame.extend_from_slice(&[8, 0]);
        frame.extend(bytes);
        frame
    }
}

pub(super) struct Link {
    number: u64,
    overhead: usize,
    channels: u16,
    output: Vec<u8>,
    witnesses: Vec<receiver::UnitWitness>,
    units: Vec<receiver::RecordIdentity>,
    emissions: u64,
    sources: usize,
    feedback: usize,
    swift: bool,
}
impl Link {
    pub(super) fn new(configuration: &configuration::Configuration, role: Role) -> Self {
        let direction = configuration.descriptor().direction(role);
        let (maximum, witnesses, swift) = match direction.profile() {
            configuration::DirectionProfile::Swift(config) => {
                (config.codec.datagram_bytes, 0, true)
            }
            configuration::DirectionProfile::Aligned(config) => {
                (config.max_recovery_packet_bytes, 1, false)
            }
            configuration::DirectionProfile::Packed(config) => (
                config.base.max_recovery_packet_bytes,
                usize::from(config.max_units),
                false,
            ),
            configuration::DirectionProfile::Rolling { config, .. } => (
                configuration.descriptor().path_mtu(),
                usize::from(config.packing.max_units),
                false,
            ),
        };
        Self {
            number: if role == Role::Client {
                (1_u64 << 48) + 0x12345
            } else {
                (1_u64 << 56) + 0x34567
            },
            overhead: if role == Role::Client { 17 } else { 73 },
            channels: direction.channels(),
            output: vec![0; maximum],
            witnesses: vec![
                receiver::UnitWitness {
                    identity: receiver::RecordIdentity {
                        channel: receiver::ChannelId(0),
                        record: receiver::RecordId(0)
                    },
                    index: 0,
                    count: 1
                };
                witnesses
            ],
            units: Vec::new(),
            emissions: 0,
            sources: 0,
            feedback: 0,
            swift,
        }
    }

    pub(super) fn transfer(
        &mut self,
        sender: &mut Engine,
        receiver: &mut Engine,
        allow_data: bool,
        clock: &mut u64,
    ) -> TestResult {
        for _ in 0..16 {
            let before = OutboundBudget {
                packets: 1,
                wire_bytes: self.output.len() + self.overhead,
            };
            let mut budget = before;
            let sent_at = next(clock);
            let Some(emission) = sender.poll(
                sent_at,
                self.number,
                allow_data,
                &mut self.output,
                &mut budget,
                &mut self.witnesses,
            )?
            else {
                assert_eq!(budget, before);
                return Ok(());
            };
            assert_eq!(emission.security_number, self.number);
            assert!(emission.security_number > u64::from(u32::MAX));
            assert_eq!(emission.wire_bytes, emission.bytes + self.overhead);
            assert_eq!(
                budget,
                OutboundBudget {
                    packets: 0,
                    wire_bytes: before.wire_bytes - emission.wire_bytes
                }
            );
            if !allow_data {
                assert_eq!(emission.kind, EmissionKind::Feedback);
            }
            match emission.kind {
                EmissionKind::Source(form) => {
                    self.sources += 1;
                    assert_eq!(form == SourceForm::Swift, self.swift);
                    assert_eq!(emission.witnesses == 0, self.swift);
                }
                EmissionKind::Repair => assert_eq!(emission.witnesses, 0),
                EmissionKind::Feedback => {
                    self.feedback += 1;
                    assert_eq!(emission.witnesses, 0);
                }
            }
            for unit in &self.witnesses[..emission.witnesses] {
                assert!(u16::from(unit.identity.channel.0) < self.channels);
                assert!(unit.count > 0 && unit.index < unit.count);
                self.units.push(unit.identity);
            }
            let mut body = self.output[..emission.bytes].to_vec();
            // This link observes whole carrier ownership before peer delivery.
            if let Some(token) = sender.pending_carrier_output() {
                assert_eq!(token.emission(), emission);
                sender.confirm_carrier_output(sent_at, token)?;
            }
            // This finite plaintext link assumes the caller's authentication boundary.
            receiver.accept_authenticated(
                next(clock),
                emission.security_number,
                emission.kind,
                &mut body,
            )?;
            self.emissions += 1;
            self.number = self.number.checked_add(1).ok_or("security counter")?;
        }
        Ok(())
    }
}

fn record_admission(
    admitted: pipeline::Admitted<ProfileIdentity>,
    originals: &[(Vec<u8>, pipeline::PacketMetadata)],
    accepted: &mut Vec<(ProfileIdentity, Vec<u8>)>,
) {
    assert!(
        originals
            .iter()
            .any(|(bytes, metadata)| admitted.packet.payload == *bytes
                && admitted.packet.metadata == *metadata)
    );
    assert_eq!(
        identity_channel(admitted.permit),
        admitted.packet.metadata.binding.channel
    );
    assert!(
        !accepted
            .iter()
            .any(|(identity, _)| *identity == admitted.permit)
    );
    accepted.push((admitted.permit, admitted.packet.payload));
}

fn roundtrip(
    configuration: configuration::Configuration,
    raw: bool,
    role: Role,
    pressure: bool,
) -> TestResult {
    let peer = if role == Role::Client {
        Role::Server
    } else {
        Role::Client
    };
    let limits = NativeLimits {
        stall_micros: 50_000,
    };
    let mut sender = Engine::new_functional(configuration, context(role), geometry(), limits)?;
    let mut receiver = Engine::new_functional(configuration, context(peer), geometry(), limits)?;
    assert_eq!(sender.configuration(), &configuration);
    assert_eq!(receiver.configuration(), &configuration);
    assert_eq!(sender.qualification(), Qualification::Functional);
    assert_eq!(
        configuration
            .descriptor()
            .direction(Role::Client)
            .channels(),
        3
    );
    assert_eq!(
        configuration
            .descriptor()
            .direction(Role::Server)
            .channels(),
        2
    );
    assert_eq!(
        configuration
            .descriptor()
            .direction(Role::Client)
            .common()
            .bytes_per_second(),
        2_000_001
    );
    assert_eq!(
        configuration
            .descriptor()
            .direction(Role::Server)
            .common()
            .bytes_per_second(),
        1_000_002
    );
    let native_max = configuration.descriptor().direction(role).max_native();
    let first_port = if let configuration::DirectionProfile::Swift(config) =
        configuration.descriptor().direction(role).profile()
    {
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
            .ok_or("bounded explicit-channel fixture")?
    } else {
        1001
    };
    let mut originals = Vec::new();
    for (port, length, value) in [
        (first_port, if pressure { native_max } else { 100 }, 7),
        (first_port + 1, if raw { 40 } else { 54 }, 8),
        (first_port, 120, 9),
    ] {
        let bytes = packet(raw, port, length, value);
        let metadata = sender.enqueue(Tick(0), bytes.clone())?;
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
    let mut accepted = Vec::new();
    if pressure {
        record_admission(
            sender
                .admit_one(next(&mut clock))?
                .ok_or("first admission")?,
            &originals,
            &mut accepted,
        );
        let before = sender.queue_usage();
        for _ in 0..3 {
            let native_before = sender.native_counts()?.admitted.to_vec();
            assert!(sender.admit_one(next(&mut clock))?.is_none());
            assert_eq!(sender.native_counts()?.admitted, native_before);
            assert_eq!(sender.queue_usage(), before);
            assert_eq!(sender.statistics().admitted, 1);
            assert_eq!(sender.failure(), None);
        }
    }
    let mut data = Link::new(&configuration, role);
    let mut feedback = Link::new(&configuration, peer);
    let mut native = vec![0; native_max];
    let mut delivered = Vec::new();
    let mut done = false;
    for step in 0..64 {
        clock = clock.max(step * 10_000);
        for _ in 0..8 {
            let Some(admitted) = sender.admit_one(next(&mut clock))? else {
                break;
            };
            record_admission(admitted, &originals, &mut accepted);
        }
        data.transfer(&mut sender, &mut receiver, true, &mut clock)?;
        for _ in 0..16 {
            let prepared_at = next(&mut clock);
            let original_cap = Tick(prepared_at.0 + 10_000);
            let before_prepared = receiver.native_counts()?.prepared.to_vec();
            let NativePreparation::Ready(prepared) =
                receiver.prepare_native(prepared_at, 8, original_cap, &mut native)?
            else {
                assert_eq!(receiver.native_counts()?.prepared, before_prepared);
                continue;
            };
            assert_eq!(
                receiver.native_counts()?.prepared.iter().sum::<u64>(),
                delivered.len() as u64 + 1
            );
            assert_eq!(
                receiver.native_counts()?.committed.iter().sum::<u64>(),
                delivered.len() as u64
            );
            let bytes = native[..prepared.bytes()].to_vec();
            assert!(
                accepted
                    .iter()
                    .any(|(identity, original)| *identity == prepared.identity()
                        && *original == bytes)
            );
            assert!(!delivered.contains(&prepared.identity()));
            assert_eq!(prepared.deadline(), original_cap);
            assert_eq!(receiver.pending_native(), Some(prepared));
            let counts_before_retry = receiver.native_counts()?.prepared.to_vec();
            let mut other_output = [0xa5; 17];
            assert_eq!(
                receiver.prepare_native(next(&mut clock), 0, Tick(u64::MAX), &mut other_output)?,
                NativePreparation::AlreadyPending(prepared)
            );
            assert_eq!(other_output, [0xa5; 17]);
            assert_eq!(receiver.native_counts()?.prepared, counts_before_retry);
            assert_eq!(&native[..prepared.bytes()], bytes);
            receiver.commit_native(next(&mut clock), prepared.token())?;
            let committed = receiver.statistics().committed;
            assert_eq!(
                receiver.commit_native(next(&mut clock), prepared.token()),
                Err(Error::Token)
            );
            assert_eq!(receiver.statistics().committed, committed);
            assert_eq!(receiver.failure(), None);
            delivered.push(prepared.identity());
        }
        feedback.transfer(&mut receiver, &mut sender, false, &mut clock)?;
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
        "actual profile roundtrip exceeded its finite injected-time work bound"
    );
    assert_eq!(accepted.len(), originals.len());
    assert!(data.sources > 0 && feedback.feedback > 0);
    assert_eq!(sender.statistics().admitted, 3);
    let width = usize::from(configuration.descriptor().direction(role).channels());
    let mut expected = vec![0; width];
    expected[0] = 2;
    expected[1] = 1;
    let sent_counts = sender.native_counts()?;
    let received_counts = receiver.native_counts()?;
    assert_eq!(sent_counts.context, context(role));
    assert_eq!(received_counts.context, context(peer));
    assert_eq!(sent_counts.digest, received_counts.digest);
    assert_eq!(sent_counts.admitted, expected);
    assert_eq!(received_counts.prepared, expected);
    assert_eq!(received_counts.committed, expected);
    assert!(sent_counts.prepared.iter().all(|count| *count == 0));
    assert!(sent_counts.committed.iter().all(|count| *count == 0));
    assert!(received_counts.admitted.iter().all(|count| *count == 0));
    assert_eq!(
        (
            receiver.statistics().prepared,
            receiver.statistics().committed
        ),
        (3, 3)
    );
    assert_eq!(sender.statistics().emitted, data.emissions);
    assert_eq!(receiver.statistics().emitted, feedback.emissions);
    for (identity, _) in accepted {
        match identity {
            ProfileIdentity::Swift(_) => assert!(data.units.is_empty()),
            ProfileIdentity::Aligned(identity)
            | ProfileIdentity::Packed(identity)
            | ProfileIdentity::Rolling(identity) => {
                assert!(data.units.contains(&identity))
            }
        }
    }
    Ok(())
}

#[test]
fn actual_swift_queue_roundtrips_tap_and_tun_in_both_asymmetric_directions() -> TestResult {
    for raw in [false, true] {
        for role in [Role::Client, Role::Server] {
            roundtrip(fixture(Family::Swift, raw)?, raw, role, false)?;
        }
    }
    Ok(())
}
#[test]
fn actual_aligned_queue_roundtrips_tap_and_tun_in_both_asymmetric_directions() -> TestResult {
    for raw in [false, true] {
        for role in [Role::Client, Role::Server] {
            roundtrip(fixture(Family::Aligned, raw)?, raw, role, false)?;
        }
    }
    Ok(())
}
#[test]
fn actual_packed_queue_roundtrips_tap_and_tun_in_both_asymmetric_directions() -> TestResult {
    for raw in [false, true] {
        for role in [Role::Client, Role::Server] {
            roundtrip(fixture(Family::Packed, raw)?, raw, role, false)?;
        }
    }
    Ok(())
}

#[test]
fn explicit_arq_only_configuration_roundtrips_actual_aligned_and_packed_native_custody()
-> TestResult {
    for family in [Family::Aligned, Family::Packed] {
        for raw in [false, true] {
            let old = fixture(family, raw)?;
            let descriptor = old.descriptor();
            let mut profile = *descriptor.profile();
            let policies = match &mut profile {
                configuration::Profile::Aligned { forward, reverse } => [forward, reverse],
                configuration::Profile::Packed { forward, reverse } => {
                    [&mut forward.base, &mut reverse.base]
                }
                _ => return Err("aligned-family fixture".into()),
            };
            for policy in policies {
                policy.recovery.repair_symbols = 0;
                policy.max_recovery_packet_bytes = policy.recovery.maximum_packet_bytes()?;
            }
            let selected = configuration::Configuration::new(
                old.envelope(),
                configuration::Descriptor::new(
                    descriptor.path_mtu(),
                    descriptor.duplex(),
                    *descriptor.direction(Role::Client).common(),
                    *descriptor.direction(Role::Server).common(),
                    profile,
                )?,
            )?;
            let mut bytes = vec![0; configuration::CONFIGURATION_BYTES];
            selected.encode_into(&mut bytes)?;
            let selected = configuration::Configuration::decode(&bytes)?;
            assert_ne!(selected, old);
            for role in [Role::Client, Role::Server] {
                roundtrip(selected, raw, role, false)?;
            }
        }
    }
    Ok(())
}

#[test]
fn actual_full_or_busy_preserves_common_head_until_recovery_allows_exact_retry() -> TestResult {
    for family in [Family::Swift, Family::Aligned, Family::Packed] {
        let original = fixture(family, true)?;
        let descriptor = original.descriptor();
        let mut profile = *descriptor.profile();
        if let configuration::Profile::Swift { forward, .. } = &mut profile {
            forward.codec.queue_bytes = forward.codec.max_packet + swift::FRAME_PREFIX;
        }
        let mut pipeline = descriptor.direction(Role::Client).common().pipeline();
        if let pipeline::Profile::TunDrr(policy) = &mut pipeline.profile {
            policy.base_quantum_bytes = 2048;
        }
        let common = descriptor.direction(Role::Client).common();
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
        roundtrip(configuration, true, Role::Client, true)?;
    }
    Ok(())
}

#[test]
fn actual_held_native_original_cap_expires_without_a_completion_or_renewal() -> TestResult {
    for family in [Family::Swift, Family::Aligned, Family::Packed] {
        let configuration = fixture(family, true)?;
        let limits = NativeLimits {
            stall_micros: 50_000,
        };
        let mut sender =
            Engine::new_functional(configuration, context(Role::Client), geometry(), limits)?;
        let mut receiver =
            Engine::new_functional(configuration, context(Role::Server), geometry(), limits)?;
        sender.enqueue(Tick(0), packet(true, 1001, 100, 7))?;
        sender.admit_one(Tick(0))?.ok_or("admission")?;
        let mut link = Link::new(&configuration, Role::Client);
        let mut output = vec![0; 1024];
        let mut clock = 0;
        let mut held = None;
        'prepare: for step in 0..32 {
            clock = clock.max(step * 10_000);
            link.transfer(&mut sender, &mut receiver, true, &mut clock)?;
            for _ in 0..8 {
                let now = next(&mut clock);
                if let NativePreparation::Ready(prepared) =
                    receiver.prepare_native(now, 8, Tick(now.0 + 7), &mut output)?
                {
                    held = Some(prepared);
                    break 'prepare;
                }
            }
        }
        let held = held.ok_or("bounded actual native preparation")?;
        let retained = output.clone();
        assert_eq!(
            receiver.prepare_native(next(&mut clock), 0, Tick(u64::MAX), &mut output)?,
            NativePreparation::AlreadyPending(held)
        );
        assert_eq!(output, retained);
        assert_eq!(receiver.tick(held.deadline()), Err(Error::Expired));
        assert_eq!(receiver.failure(), Some(Error::Expired));
        assert_eq!(
            (
                receiver.statistics().prepared,
                receiver.statistics().committed
            ),
            (1, 0)
        );
        assert_eq!(receiver.drained(), Err(Error::Expired));
        assert_eq!(
            receiver.prepare_native(held.deadline(), 8, Tick(u64::MAX), &mut output),
            Err(Error::Expired)
        );
        assert_eq!(output, retained);
    }
    Ok(())
}

#[test]
fn loose_recovery_ceiling_preserves_configuration_and_uses_actual_public_output_minimum()
-> TestResult {
    for family in [Family::Aligned, Family::Packed] {
        let original = fixture(family, true)?;
        let descriptor = original.descriptor();
        let mut profile = *descriptor.profile();
        match &mut profile {
            configuration::Profile::Aligned { forward, reverse } => {
                forward.max_recovery_packet_bytes = 60_000;
                reverse.max_recovery_packet_bytes = 60_000;
            }
            configuration::Profile::Packed { forward, reverse } => {
                forward.base.max_recovery_packet_bytes = 60_000;
                reverse.base.max_recovery_packet_bytes = 60_000;
            }
            configuration::Profile::Swift { .. } | configuration::Profile::Rolling { .. } => {
                return Err("aligned-family fixture".into());
            }
        }
        let configuration = configuration::Configuration::new(
            original.envelope(),
            configuration::Descriptor::new(
                descriptor.path_mtu(),
                descriptor.duplex(),
                *descriptor.direction(Role::Client).common(),
                *descriptor.direction(Role::Server).common(),
                profile,
            )?,
        )?;
        for role in [Role::Client, Role::Server] {
            let direction = configuration.descriptor().direction(role);
            let (recovery, cap) = match direction.profile() {
                configuration::DirectionProfile::Aligned(config) => {
                    (config.recovery, config.max_recovery_packet_bytes)
                }
                configuration::DirectionProfile::Packed(config) => {
                    (config.base.recovery, config.base.max_recovery_packet_bytes)
                }
                configuration::DirectionProfile::Swift(_)
                | configuration::DirectionProfile::Rolling { .. } => {
                    return Err("aligned-family direction".into());
                }
            };
            let actual = recovery.maximum_packet_bytes()?;
            assert_eq!(cap, 60_000);
            assert!(actual < cap);
            assert!(
                actual + recovery.outer_overhead_bytes <= configuration.descriptor().path_mtu()
            );
            assert!(actual + recovery.outer_overhead_bytes <= direction.common().burst_bytes());
            let mut engine = Engine::new_functional(
                configuration,
                context(role),
                geometry(),
                NativeLimits {
                    stall_micros: 50_000,
                },
            )?;
            assert_eq!(engine.configuration(), &configuration);
            let mut link = Link::new(&configuration, role);
            let before = OutboundBudget {
                packets: 1,
                wire_bytes: actual + recovery.outer_overhead_bytes,
            };
            let mut budget = before;
            assert_eq!(
                engine.poll(
                    Tick(0),
                    link.number,
                    true,
                    &mut vec![0; actual - 1],
                    &mut budget,
                    &mut link.witnesses
                ),
                Err(Error::Output { required: actual })
            );
            assert_eq!(budget, before);
            let mut output = vec![0; actual];
            assert_eq!(
                engine.poll(
                    Tick(0),
                    link.number,
                    true,
                    &mut output,
                    &mut budget,
                    &mut link.witnesses
                )?,
                None
            );
            assert_eq!(budget, before);
            engine.enqueue(Tick(1), packet(true, 1001, 100, 7))?;
            engine
                .admit_one(Tick(1))?
                .ok_or("actual profile admission")?;
            let mut emitted = false;
            for step in 1..=4 {
                let mut budget = before;
                if let Some(emission) = engine.poll(
                    Tick(step * 10_000),
                    link.number,
                    true,
                    &mut output,
                    &mut budget,
                    &mut link.witnesses,
                )? {
                    assert!(matches!(emission.kind, EmissionKind::Source(_)));
                    assert!(emission.bytes <= actual);
                    assert_eq!(
                        emission.wire_bytes,
                        emission.bytes + recovery.outer_overhead_bytes
                    );
                    assert_eq!(
                        budget,
                        OutboundBudget {
                            packets: 0,
                            wire_bytes: before.wire_bytes - emission.wire_bytes
                        }
                    );
                    emitted = true;
                    break;
                }
                assert_eq!(budget, before);
            }
            assert!(
                emitted,
                "actual maximum-sized caller buffer must permit emission"
            );
            assert_eq!(engine.configuration(), &configuration);
        }
    }
    Ok(())
}

#[test]
fn prepared_aligned_native_cap_is_original_record_expiry_not_a_recovery_service_timer() -> TestResult
{
    for family in [Family::Aligned, Family::Packed] {
        let configuration = fixture(family, true)?;
        let limits = NativeLimits {
            stall_micros: 50_000,
        };
        let mut sender =
            Engine::new_functional(configuration, context(Role::Client), geometry(), limits)?;
        let mut receiver =
            Engine::new_functional(configuration, context(Role::Server), geometry(), limits)?;
        let native = packet(true, 1001, 100, 7);
        sender.enqueue(Tick(0), native.clone())?;
        sender.admit_one(Tick(0))?.ok_or("actual admission")?;
        let mut forward = Link::new(&configuration, Role::Client);
        let mut arrival = None;
        for step in 0..8 {
            let now = Tick(step * 10_000);
            let mut budget = OutboundBudget {
                packets: 1,
                wire_bytes: forward.output.len() + forward.overhead,
            };
            if let Some(emission) = sender.poll(
                now,
                forward.number,
                true,
                &mut forward.output,
                &mut budget,
                &mut forward.witnesses,
            )? {
                assert!(matches!(emission.kind, EmissionKind::Source(_)));
                let token = sender
                    .pending_carrier_output()
                    .ok_or("actual carrier source token")?;
                assert_eq!(token.emission(), emission);
                sender.confirm_carrier_output(now, token)?;
                let received_at = Tick(now.0 + 10);
                let mut body = forward.output[..emission.bytes].to_vec();
                receiver.accept_authenticated(
                    received_at,
                    emission.security_number,
                    emission.kind,
                    &mut body,
                )?;
                arrival = Some(received_at);
                break;
            }
        }
        let arrival = arrival.ok_or("bounded original-source arrival")?;
        let lifetime = match configuration.descriptor().direction(Role::Client).profile() {
            configuration::DirectionProfile::Aligned(config) => config.receiver.lifetime_ticks,
            configuration::DirectionProfile::Packed(config) => config.base.receiver.lifetime_ticks,
            configuration::DirectionProfile::Swift(_)
            | configuration::DirectionProfile::Rolling { .. } => {
                return Err("aligned-family lifetime".into());
            }
        };
        // Receiver record age starts in its injected millisecond domain at admission.
        let record_expiry = Tick((arrival.0 / 1000 + lifetime) * 1000);
        receiver.enqueue(Tick(arrival.0 + 1), packet(true, 2001, 100, 9))?;
        receiver
            .admit_one(Tick(arrival.0 + 2))?
            .ok_or("reverse source admission")?;
        let mut reverse = Link::new(&configuration, Role::Server);
        let mut retry_armed = false;
        let mut outgoing_empty = false;
        let mut last_poll = arrival;
        'poll: for step in 1..=8 {
            let now = Tick(arrival.0 + step * 10_000);
            for _ in 0..4 {
                let mut budget = OutboundBudget {
                    packets: 1,
                    wire_bytes: reverse.output.len() + reverse.overhead,
                };
                match receiver.poll(
                    now,
                    reverse.number,
                    true,
                    &mut reverse.output,
                    &mut budget,
                    &mut reverse.witnesses,
                )? {
                    Some(emission) => {
                        let token = receiver
                            .pending_carrier_output()
                            .ok_or("actual reverse carrier token")?;
                        assert_eq!(token.emission(), emission);
                        receiver.confirm_carrier_output(now, token)?;
                        retry_armed |= matches!(emission.kind, EmissionKind::Source(_));
                        reverse.number += 1;
                        // Drop the real reverse source deliberately, leaving its ARQ retry due.
                    }
                    None if retry_armed => {
                        outgoing_empty = true;
                        last_poll = now;
                        break 'poll;
                    }
                    None => break,
                }
            }
        }
        assert!(retry_armed && outgoing_empty);
        let recovery_due = receiver
            .deadline()?
            .ok_or("real unacknowledged-source retry")?;
        assert!(recovery_due > last_poll && recovery_due < record_expiry);
        let near_expiry = Tick(record_expiry.0 - 2000);
        assert!(recovery_due < near_expiry);
        let external_cap = Tick(record_expiry.0 + 1_000_000);
        assert!(near_expiry.0 + limits.stall_micros > record_expiry.0);
        let mut output = vec![0; 1024];
        let NativePreparation::Ready(prepared) =
            receiver.prepare_native(near_expiry, 8, external_cap, &mut output)?
        else {
            return Err("actual retained record must prepare before its original expiry".into());
        };
        assert_eq!(&output[..prepared.bytes()], native);
        assert_eq!(prepared.deadline(), record_expiry);
        assert_eq!(receiver.deadline()?, Some(recovery_due));
        let retained = output.clone();
        assert_eq!(
            receiver.prepare_native(Tick(near_expiry.0 + 1), 0, Tick(u64::MAX), &mut output)?,
            NativePreparation::AlreadyPending(prepared)
        );
        assert_eq!(output, retained);
        receiver.commit_native(Tick(near_expiry.0 + 2), prepared.token())?;
        assert_eq!(receiver.statistics().committed, 1);
        assert!(!receiver.drained()?);
    }
    Ok(())
}
