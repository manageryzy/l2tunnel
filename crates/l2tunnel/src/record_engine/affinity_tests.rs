//! Actual Packed owners and maintained flow keys; the link assumes caller authentication.
use super::*;
use crate::record_engine::tests::{Family, Link, context, fixture, geometry, packet};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
type Delivered = (Vec<Vec<u8>>, Vec<Vec<u8>>);

fn selected(equal: bool, learned: bool) -> TestResult<configuration::Configuration> {
    let original = fixture(Family::Packed, false)?;
    let descriptor = original.descriptor();
    let configuration::Profile::Packed {
        forward,
        mut reverse,
    } = *descriptor.profile()
    else {
        return Err("actual Packed fixture missing".into());
    };
    if equal {
        reverse.base.receiver.channels = forward.base.receiver.channels;
    }
    let common = |role, width| -> TestResult<configuration::CommonDirection> {
        let old = descriptor.direction(role).common();
        let mut policy = old.pipeline();
        policy.flows.channels = width;
        policy.flows.mapping = if learned {
            pipeline::Mapping::ConnectionRoundRobinLearned
        } else {
            pipeline::Mapping::ConnectionRoundRobin
        };
        Ok(configuration::CommonDirection::new(
            old.traffic(),
            policy,
            old.bytes_per_second(),
            old.burst_bytes(),
            old.native_window(),
        )?)
    };
    Ok(configuration::Configuration::new(
        original.envelope(),
        configuration::Descriptor::new(
            descriptor.path_mtu(),
            descriptor.duplex(),
            common(Role::Client, forward.base.receiver.channels)?,
            common(Role::Server, reverse.base.receiver.channels)?,
            configuration::Profile::Packed { forward, reverse },
        )?,
    )?)
}

fn build(configuration: configuration::Configuration, role: Role) -> TestResult<Engine> {
    let plan = storage::Plan::for_engine(
        configuration,
        context(role),
        geometry(),
        NativeLimits {
            stall_micros: 50_000,
        },
    )?;
    Ok(Engine::new_reserved(
        plan,
        storage::Limits {
            capacity_bytes: plan.capacity_bytes(),
        },
    )?)
}

fn checksum(bytes: &[u8]) -> u16 {
    let mut sum = 0_u32;
    for pair in bytes.chunks(2) {
        sum += u32::from(u16::from_be_bytes([pair[0], *pair.get(1).unwrap_or(&0)]));
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn frame(port: u16, length: usize, value: u8, reverse: bool) -> Vec<u8> {
    let mut bytes = packet(false, port, length, value);
    if reverse {
        for index in 0..6 {
            bytes.swap(index, index + 6);
        }
        for index in 0..4 {
            bytes.swap(26 + index, 30 + index);
        }
        for index in 0..2 {
            bytes.swap(34 + index, 36 + index);
        }
    }
    bytes[24..26].fill(0);
    bytes[50..52].fill(0);
    let ip = checksum(&bytes[14..34]);
    bytes[24..26].copy_from_slice(&ip.to_be_bytes());
    let mut pseudo = bytes[26..34].to_vec();
    pseudo.extend_from_slice(&[0, 6]);
    pseudo.extend_from_slice(&((bytes.len() - 34) as u16).to_be_bytes());
    pseudo.extend_from_slice(&bytes[34..]);
    let tcp = checksum(&pseudo);
    bytes[50..52].copy_from_slice(&tcp.to_be_bytes());
    assert_eq!(checksum(&bytes[14..34]), 0);
    let end = pseudo.len();
    pseudo[end - (bytes.len() - 34)..].copy_from_slice(&bytes[34..]);
    assert_eq!(checksum(&pseudo), 0);
    bytes
}

fn next(clock: &mut u64) -> Tick {
    let at = Tick(*clock);
    *clock += 1;
    at
}

fn collect(owner: &mut Engine, clock: &mut u64, received: &mut Vec<Vec<u8>>) -> TestResult {
    for _ in 0..8 {
        let mut output = [0; 1152];
        let now = next(clock);
        match owner.prepare_native(now, 1, Tick(now.0 + 50_000), &mut output)? {
            NativePreparation::Ready(prepared) => {
                let bytes = output[..prepared.bytes()].to_vec();
                if prepared.bytes() == 1100 {
                    assert_eq!(native_counts::identity_channel(prepared.identity()), 1);
                    let parse = owner
                        .configuration
                        .descriptor()
                        .local(owner.context.role)
                        .receive()
                        .common()
                        .pipeline()
                        .parse;
                    let key =
                        l2tunnel_packet::classify(pipeline::PacketLayer::Ethernet, &bytes, parse)?
                            .key;
                    let learned = owner
                        .pipeline
                        .flow(&key)
                        .ok_or("decoded affinity was not learned")?;
                    assert_eq!(learned.binding.channel, 1);
                    let counts = owner.statistics();
                    let mut unchanged = [0x5a; 1152];
                    let at = next(clock);
                    assert_eq!(
                        owner.prepare_native(at, 1, Tick(at.0 + 100_000), &mut unchanged)?,
                        NativePreparation::AlreadyPending(prepared)
                    );
                    assert!(unchanged.iter().all(|byte| *byte == 0x5a));
                    assert_eq!(owner.pipeline.flow(&key), Some(learned));
                    assert_eq!(owner.statistics(), counts);
                    assert_eq!(
                        owner.retire_affinity_idle(next(clock), None, 1),
                        Err(Error::Pipeline(pipeline::PipelineError::Busy))
                    );
                    assert_eq!(owner.pending_native(), Some(prepared));
                }
                received.push(bytes);
                // The pure caller observes one whole native handoff; no device
                // syscall or peer delivery guarantee is claimed by this link.
                owner.commit_native(next(clock), prepared.token())?;
            }
            NativePreparation::Idle | NativePreparation::Progress => {}
            NativePreparation::AlreadyPending(_) => {
                return Err("unexpected external native custody".into());
            }
        }
    }
    Ok(())
}

fn exchange(
    a: &mut Engine,
    b: &mut Engine,
    ab: &mut Link,
    ba: &mut Link,
    clock: &mut u64,
) -> TestResult<Delivered> {
    let mut at_a = Vec::new();
    let mut at_b = Vec::new();
    for _ in 0..1000 {
        a.admit_borrowed(next(clock))?;
        b.admit_borrowed(next(clock))?;
        ab.transfer(a, b, true, clock)?;
        ba.transfer(b, a, true, clock)?;
        collect(a, clock, &mut at_a)?;
        collect(b, clock, &mut at_b)?;
        if a.drained()? && b.drained()? {
            return Ok((at_a, at_b));
        }
        *clock += 1000;
    }
    Err("actual Packed/native/recovery ownership did not drain".into())
}

fn retire(owner: &mut Engine, now: Tick) -> TestResult<usize> {
    let mut after = None;
    let mut count = 0;
    for _ in 0..16 {
        let scan = owner.retire_affinity_idle(now, after, 1)?;
        assert!(scan.examined <= 1);
        if let Some((key, _)) = scan.candidate {
            count += 1;
            assert_eq!(owner.pipeline.flow(&key), None);
        }
        after = scan.after;
        if after.is_none() {
            return Ok(count);
        }
    }
    Err("bounded retirement cursor did not finish".into())
}

#[test]
fn decoded_channel_learns_reverse_without_advancing_local_rr_and_retires_only_after_real_drain()
-> TestResult {
    assert!(selected(false, false).is_ok());
    assert!(selected(false, true).is_err());
    let config = selected(true, true)?;
    let mut encoded = [0; configuration::CONFIGURATION_BYTES];
    config.encode_into(&mut encoded)?;
    assert_eq!(configuration::Configuration::decode(&encoded)?, config);
    assert_ne!(config.digest()?, selected(true, false)?.digest()?);
    let mut client = build(config, Role::Client)?;
    let mut server = build(config, Role::Server)?;
    let client_usage = client.storage_usage();
    let server_usage = server.storage_usage();
    let mut ab = Link::new(&config, Role::Client)?;
    let mut ba = Link::new(&config, Role::Server)?;
    let mut clock = 1;
    let first = frame(10_001, 100, 7, false);
    let target = frame(10_002, 1100, 8, false);
    let one = server.enqueue_borrowed(next(&mut clock), &first)?;
    let two = server.enqueue_borrowed(next(&mut clock), &target)?;
    assert_eq!((one.binding.channel, two.binding.channel), (0, 1));
    // Incoming target is larger than the local outbound parser's1024-byte cap.
    // The actual receive policy permits1152 bytes and must govern learning.
    assert!(target.len() > config.descriptor().direction(Role::Client).max_native());
    let (mut to_client, to_server) =
        exchange(&mut client, &mut server, &mut ab, &mut ba, &mut clock)?;
    to_client.sort();
    let mut original = vec![first, target];
    original.sort();
    assert_eq!(to_client, original);
    assert!(to_server.is_empty());
    let reply = frame(10_002, 100, 9, true);
    let unrelated = frame(10_003, 100, 10, false);
    let reverse = client.enqueue_borrowed(next(&mut clock), &reply)?;
    let local = client.enqueue_borrowed(next(&mut clock), &unrelated)?;
    assert_eq!(reverse.binding.channel, 1);
    assert_eq!(
        local.binding.channel, 0,
        "learning must not consume local RR assignments"
    );
    let (to_client, mut to_server) =
        exchange(&mut client, &mut server, &mut ab, &mut ba, &mut clock)?;
    assert!(to_client.is_empty());
    to_server.sort();
    let mut expected = vec![reply, unrelated];
    expected.sort();
    assert_eq!(to_server, expected);
    assert_eq!(client.storage_usage(), client_usage);
    assert_eq!(server.storage_usage(), server_usage);
    assert!(client.drained()? && server.drained()?);
    assert!(
        client
            .retire_affinity_idle(next(&mut clock), None, 1)?
            .candidate
            .is_none()
    );
    let idle = Tick(clock + 5_000_000);
    assert_eq!(retire(&mut client, idle)?, 3);
    assert_eq!(retire(&mut server, idle)?, 3);
    assert_eq!(client.pipeline.registered_flows(), 0);
    assert_eq!(server.pipeline.registered_flows(), 0);
    clock = idle.0 + 1;
    // Local simultaneous assignment has no production arbitration yet. Both
    // actual senders assign the same new flow differently; decoded conflict
    // must be visible without overwriting the queued local binding or custody.
    let queued = frame(10_004, 100, 11, true);
    let incoming = frame(10_004, 100, 12, false);
    let local = client.enqueue_borrowed(next(&mut clock), &queued)?;
    let peer = server.enqueue_borrowed(next(&mut clock), &incoming)?;
    assert_eq!((local.binding.channel, peer.binding.channel), (1, 2));
    let before = client.statistics();
    let original = client
        .pipeline
        .flow(&local.classification.key)
        .ok_or("local queued flow missing")?;
    let mut conflict = None;
    for _ in 0..100 {
        server.admit_borrowed(next(&mut clock))?;
        ba.transfer(&mut server, &mut client, true, &mut clock)?;
        let mut output = [0; 1152];
        let at = next(&mut clock);
        match client.prepare_native(at, 1, Tick(at.0 + 50_000), &mut output) {
            Err(error) => {
                conflict = Some(error);
                break;
            }
            Ok(NativePreparation::Idle | NativePreparation::Progress) => {}
            Ok(_) => return Err("conflicting decoded frame gained native custody".into()),
        }
        clock += 1000;
    }
    let error = Error::Pipeline(pipeline::PipelineError::Flow(
        l2tunnel_packet::FlowError::BindingConflict {
            expected: 1,
            received: 2,
        },
    ));
    assert_eq!(conflict, Some(error));
    assert_eq!(client.tick(next(&mut clock)), Err(error));
    assert_eq!(client.pending_native(), None);
    assert_eq!(client.statistics(), before);
    assert_eq!(
        client.pipeline.flow(&local.classification.key),
        Some(original)
    );
    assert_eq!(client.queue_usage().packets, 1);
    assert_eq!(client.storage_usage(), client_usage);
    Ok(())
}
