use super::*;
use crate::record_configuration as configuration;
use l2tunnel_aligned as aligned;
use l2tunnel_codec::{aligned_body, aligned_receiver as receiver};
use l2tunnel_core::{Duplex, traffic};
use l2tunnel_management::Role;
use l2tunnel_pipeline as pipeline;
use l2tunnel_recovery::ArqConfig;
use l2tunnel_reliable::{OutboundBudget, ReliableConfig};
use l2tunnel_swift as swift;
use std::time::Duration;

pub(super) type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Family {
    Swift,
    Aligned,
    Packed,
}
pub(super) const FAMILIES: [Family; 3] = [Family::Swift, Family::Aligned, Family::Packed];

fn aligned_config(reverse: bool, packed: bool) -> aligned::Config {
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
        native_policy: aligned::NativePolicy::EthernetHeaders,
        receiver: receiver::Limits {
            body: aligned_body::Config {
                max_frame_bytes: 1024,
                symbol_bytes: symbol,
                elide_payload_length: true,
                predictive: true,
                timestamp_pair_dictionary: true,
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
            fec: l2tunnel_fec::DecoderConfig {
                block: l2tunnel_fec::BlockConfig {
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
        max_recovery_packet_bytes: 8 + fec_packet + if reverse { 9 } else { 7 },
    }
}
fn swift_config(reverse: bool) -> swift::records::Config {
    swift::records::Config {
        channels: if reverse { 2 } else { 3 },
        layer: swift::records::Layer::Ethernet,
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
fn common(reverse: bool) -> TestResult<configuration::CommonDirection> {
    Ok(configuration::CommonDirection::new(
        traffic::TrafficPolicy::tap(),
        pipeline::PipelineConfig {
            profile: pipeline::Profile::TapSystem,
            flows: pipeline::FlowTableConfig {
                capacity: 8,
                channels: if reverse { 2 } else { 3 },
                mapping: pipeline::Mapping::ConnectionRoundRobin,
                idle_timeout: Duration::from_secs(5),
            },
            parse: pipeline::ParseLimits {
                max_packet_bytes: 1024,
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
pub(super) fn config(family: Family) -> TestResult<configuration::Configuration> {
    let profile = match family {
        Family::Swift => configuration::Profile::Swift {
            forward: swift_config(false),
            reverse: swift_config(true),
        },
        Family::Aligned => configuration::Profile::Aligned {
            forward: aligned_config(false, false),
            reverse: aligned_config(true, false),
        },
        Family::Packed => configuration::Profile::Packed {
            forward: aligned::packed::Config {
                base: aligned_config(false, true),
                hold_micros: 201,
                max_units: 3,
                work_limit: 2,
            },
            reverse: aligned::packed::Config {
                base: aligned_config(true, true),
                hold_micros: 701,
                max_units: 4,
                work_limit: 3,
            },
        },
    };
    Ok(configuration::Configuration::new(
        configuration::EnvelopeDigest::new([0x39; 32]),
        configuration::Descriptor::new(1500, Duplex::Full, common(false)?, common(true)?, profile)?,
    )?)
}
pub(super) fn plan(family: Family, role: Role, epoch: u64) -> TestResult<engine::storage::Plan> {
    Ok(engine::storage::Plan::for_engine(
        config(family)?,
        engine::Context {
            session: 0x1234_5678_9012_3456,
            epoch,
            role,
        },
        engine::Geometry {
            forward_overhead_bytes: 17,
            reverse_overhead_bytes: 73,
        },
        engine::NativeLimits {
            stall_micros: 50_000,
        },
    )?)
}
pub(super) fn bank(initial: engine::storage::Plan, spare: usize) -> TestResult<Bank> {
    let inventory = storage::Plan::for_bank(initial, 137)?;
    Ok(Bank::new(
        inventory,
        storage::Limits {
            capacity_bytes: inventory
                .capacity_bytes()
                .checked_add(spare)
                .ok_or("test allowance")?,
        },
    )?)
}
pub(super) fn packet(value: u8) -> Vec<u8> {
    let mut bytes = vec![value; 80];
    bytes[..6].fill(1);
    bytes[6..12].fill(2);
    bytes[12..14].copy_from_slice(&0x88b5u16.to_be_bytes());
    bytes
}

#[test]
fn every_real_family_transition_publishes_the_exact_virgin_and_preserves_current_queue()
-> TestResult {
    for source in FAMILIES {
        for target in FAMILIES {
            if source == target {
                continue;
            }
            let first = plan(source, Role::Client, 7)?;
            let next = plan(target, Role::Client, 8)?;
            let mut bank = bank(first, next.heap_bytes())?;
            let current = bank.initial();
            let bytes = packet(0x43);
            let metadata = bank
                .entry(current)?
                .enqueue_borrowed(engine::Tick(0), &bytes)?;
            let original = bank.engine(current)? as *const engine::Engine;
            let old_statistics = bank.engine(current)?.statistics();
            let old_queue = bank.engine(current)?.queue_usage();
            let mut prepared = bank.prepare(next)?;
            let virgin = bank.prepared_engine(&prepared)? as *const engine::Engine;
            assert_eq!(
                bank.prepared_engine(&prepared)?.statistics(),
                engine::Statistics::default()
            );
            assert_eq!(
                bank.prepared_engine(&prepared)?.configuration(),
                next.configuration()
            );
            assert!(matches!(bank.entry(prepared.id), Err(Error::Stale)));
            assert!(matches!(bank.prepare(next), Err(Error::Slots)));
            let published = bank.publish(&mut prepared)?;
            assert_eq!(bank.engine(published)? as *const engine::Engine, virgin);
            assert_eq!(bank.publish(&mut prepared), Err(Error::Stale));
            assert_eq!(bank.cancel(&mut prepared), Err(Error::Stale));
            assert_eq!(bank.engine(current)? as *const engine::Engine, original);
            assert_eq!(bank.engine(current)?.statistics(), old_statistics);
            assert_eq!(bank.engine(current)?.queue_usage(), old_queue);
            assert_eq!(bank.retire(current), Err(Error::NotDrained));
            let mut refusals = 0;
            let admitted = bank
                .entry(current)?
                .admit_borrowed_diagnosed(engine::Tick(0), |_| refusals += 1)?
                .ok_or("actual old admission")?;
            assert_eq!(refusals, 0);
            assert_eq!(admitted.metadata, metadata);
            let encoding = admitted.permit.encoding;
            assert_eq!(encoding.original_native_bytes, bytes.len());
            assert_eq!(encoding.context_bytes, 0);
            match source {
                Family::Swift => {
                    assert_eq!(encoding.encoded_body_bytes, bytes.len() + 1);
                    assert_eq!(encoding.framing_bytes, 2);
                    assert_eq!(encoding.net_gain_bytes(), -3);
                }
                Family::Aligned | Family::Packed => {
                    assert_eq!(encoding.encoded_body_bytes, bytes.len() + 3);
                    assert_eq!(encoding.framing_bytes, 3);
                    assert_eq!(encoding.net_gain_bytes(), -6);
                }
            }
            assert!(
                bank.entry(current)?
                    .admit_borrowed_diagnosed(engine::Tick(0), |_| refusals += 1)?
                    .is_none()
            );
            assert_eq!(refusals, 0, "an empty Pipeline is not backpressure");
            let usage = bank.usage();
            let mut snapshots = 0;
            bank.entry(current)?.visit_codec_buffers(|_| snapshots += 1);
            assert!(snapshots > 0);
            assert_eq!(bank.usage(), usage);
            assert_eq!(bank.engine(current)?.statistics().admitted, 1);
            // Teardown releases this deliberately undrained old owner, without a clean-retire claim.
        }
    }
    Ok(())
}

#[test]
fn foreign_consumed_and_recycled_guards_refuse_without_accessing_an_engine() -> TestResult {
    let first = plan(Family::Swift, Role::Client, 7)?;
    let next = plan(Family::Aligned, Role::Client, 8)?;
    let mut a = bank(first, next.heap_bytes())?;
    let mut b = bank(first, next.heap_bytes())?;
    let mut prepared = a.prepare(next)?;
    let old_id = prepared.id;
    let before = (b.usage(), b.engine(b.initial())?.statistics());
    assert!(matches!(b.prepared_engine(&prepared), Err(Error::Stale)));
    assert_eq!(b.publish(&mut prepared), Err(Error::Stale));
    assert_eq!(b.cancel(&mut prepared), Err(Error::Stale));
    assert!(matches!(b.entry(a.initial()), Err(Error::Stale)));
    assert_eq!((b.usage(), b.engine(b.initial())?.statistics()), before);
    a.cancel(&mut prepared)?;
    assert_eq!(a.cancel(&mut prepared), Err(Error::Stale));
    let mut replacement = a.prepare(next)?;
    assert_eq!(replacement.id.slot, old_id.slot);
    assert_ne!(replacement.id.generation, old_id.generation);
    assert!(matches!(a.engine(old_id), Err(Error::Stale)));
    let id = a.publish(&mut replacement)?;
    a.retire(id)?;
    assert!(matches!(a.entry(id), Err(Error::Stale)));
    let charged = {
        let _abandoned = a.prepare(next)?;
        a.usage()
    };
    assert_eq!(a.usage(), charged);
    assert!(matches!(a.prepare(next), Err(Error::Slots)));
    Ok(())
}

fn transfer(
    sender: &mut Bank,
    from: GenerationId,
    receivers: &mut [(&mut Bank, GenerationId)],
    now: engine::Tick,
    number: &mut u64,
) -> TestResult<bool> {
    let mut output = [0u8; 1500];
    let mut witnesses = [receiver::UnitWitness {
        identity: receiver::RecordIdentity {
            channel: receiver::ChannelId(0),
            record: receiver::RecordId(0),
        },
        index: 0,
        count: 1,
    }; 4];
    let mut budget = OutboundBudget {
        packets: 1,
        wire_bytes: 1500,
    };
    let Some(emission) =
        sender
            .entry(from)?
            .poll(now, *number, true, &mut output, &mut budget, &mut witnesses)?
    else {
        return Ok(false);
    };
    assert_eq!(emission.security_number, *number);
    if let Some(token) = sender.entry(from)?.pending_carrier_output() {
        assert_eq!(token.emission(), emission);
        sender.entry(from)?.confirm_carrier_output(now, token)?;
    }
    *number = number.checked_add(1).ok_or("test number exhausted")?;
    for (receiver, id) in receivers {
        let mut plaintext = output[..emission.bytes].to_vec();
        // The pure fixture supplies trusted plaintext; no outer authentication is claimed.
        receiver.entry(*id)?.accept_authenticated(
            now,
            emission.security_number,
            emission.kind,
            &mut plaintext,
        )?;
    }
    Ok(true)
}

#[test]
fn actual_pending_native_lease_keeps_custody_and_rejects_foreign_and_recycled_tokens() -> TestResult
{
    use crate::native_storage as native;
    let sender_plan = plan(Family::Swift, Role::Client, 7)?;
    let receiver_plan = plan(Family::Swift, Role::Server, 7)?;
    let mut sender = bank(sender_plan, 0)?;
    let mut receiver = bank(receiver_plan, 0)?;
    let mut foreign = bank(receiver_plan, 0)?;
    let source = sender.initial();
    let destination = receiver.initial();
    let other = foreign.initial();
    let bytes = packet(0x93);
    sender
        .entry(source)?
        .enqueue_borrowed(engine::Tick(0), &bytes)?;
    sender
        .entry(source)?
        .admit_borrowed(engine::Tick(0))?
        .ok_or("actual source admission")?;
    let native_plan = native::Plan::<PreparedNative>::for_queue(native::Config {
        packets: 2,
        bytes: 2048,
        max_native: 1024,
    })?;
    let native_capacity = native_plan.capacity_bytes();
    let mut native = native::Queue::new_reserved(
        native_plan,
        native::Limits {
            capacity_bytes: native_capacity,
        },
    )?;
    let mut number = (1u64 << 48) + 0x12345;
    let mut foreign_output = [0u8; 1024];
    let mut ready = None;
    let mut other_ready = None;
    let mut prepared_at = 0;
    let mut native_pointer = None;
    for step in 0..64u64 {
        let now = engine::Tick(step * 1000);
        transfer(
            &mut sender,
            source,
            &mut [(&mut receiver, destination), (&mut foreign, other)],
            now,
            &mut number,
        )?;
        if ready.is_none() {
            let mut lease = native.acquire().ok_or("actual preallocated free slot")?;
            let result = {
                let output = lease.output()?;
                let result = receiver.entry(destination)?.prepare_native(
                    now,
                    32,
                    engine::Tick(10_000_000),
                    output,
                )?;
                if let NativePreparation::Ready(packet) = result {
                    assert_eq!(&output[..packet.bytes()], bytes);
                    native_pointer = Some(output.as_ptr());
                }
                result
            };
            match result {
                NativePreparation::Ready(packet) => {
                    assert_eq!(packet.generation(), destination);
                    lease.publish(packet, now.0, packet.bytes())?;
                    ready = Some(packet);
                    prepared_at = now.0;
                }
                NativePreparation::Idle | NativePreparation::Progress => {}
                NativePreparation::AlreadyPending(_) => {
                    return Err("unexpected initial pending slot".into());
                }
            }
        }
        if other_ready.is_none() {
            match foreign.entry(other)?.prepare_native(
                now,
                32,
                engine::Tick(10_000_000),
                &mut foreign_output,
            )? {
                NativePreparation::Ready(packet) => other_ready = Some(packet),
                NativePreparation::Idle | NativePreparation::Progress => {}
                NativePreparation::AlreadyPending(_) => {
                    return Err("unexpected foreign initial pending slot".into());
                }
            }
        }
        if ready.is_some() && other_ready.is_some() {
            break;
        }
    }
    let ready = ready.ok_or("bounded actual native preparation")?;
    let other_ready = other_ready.ok_or("bounded actual foreign native preparation")?;
    assert_eq!(ready.deadline(), engine::Tick(prepared_at + 50_000));
    assert_eq!(
        receiver
            .engine(destination)?
            .pending_native()
            .map(|packet| packet.token()),
        foreign
            .engine(other)?
            .pending_native()
            .map(|packet| packet.token())
    );
    assert_ne!(ready.token(), other_ready.token());
    let other_before = foreign.engine(other)?.statistics();
    // Even identical actual inner tokens cannot cross the Bank ownership boundary.
    assert_eq!(
        foreign
            .entry(other)?
            .commit_native(engine::Tick(0), ready.token()),
        Err(Error::Stale)
    );
    assert_eq!(foreign.engine(other)?.statistics(), other_before);
    assert_eq!(foreign.engine(other)?.failure(), None);
    assert_eq!(receiver.retire(destination), Err(Error::NotDrained));
    let mut untouched = [0xa5; 1024];
    assert_eq!(
        receiver.entry(destination)?.prepare_native(
            engine::Tick(prepared_at + 1),
            32,
            engine::Tick(20_000_000),
            &mut untouched
        )?,
        NativePreparation::AlreadyPending(ready)
    );
    assert_eq!(untouched, [0xa5; 1024]);
    assert_eq!(native.len(), 1);
    assert_eq!(
        native.front().ok_or("real pending FIFO")?.since(),
        prepared_at
    );
    assert_eq!(
        native.front().ok_or("real pending FIFO")?.metadata(),
        &ready
    );
    assert_eq!(
        Some(native.front().ok_or("same leased buffer")?.bytes().as_ptr()),
        native_pointer
    );
    assert_eq!(receiver.engine(destination)?.statistics().committed, 0);
    assert_eq!(
        foreign.entry(other)?.tick(other_ready.deadline()),
        Err(Error::Engine(engine::Error::Expired))
    );
    assert_eq!(
        foreign.retire(other),
        Err(Error::Engine(engine::Error::Expired))
    );
    assert_eq!(foreign.engine(other)?.statistics().committed, 0);
    // A complete trusted sink observation is explicit; no real-device qualification is claimed.
    let whole_sink = native
        .front()
        .ok_or("whole pending packet")?
        .bytes()
        .to_vec();
    assert_eq!(whole_sink, bytes);
    receiver
        .entry(destination)?
        .commit_native(engine::Tick(prepared_at + 1), ready.token())?;
    native.complete_front()?;
    assert!(native.is_empty());
    assert_eq!(receiver.engine(destination)?.statistics().committed, 1);
    assert_eq!(
        receiver
            .entry(destination)?
            .commit_native(engine::Tick(prepared_at + 1), ready.token()),
        Err(Error::Engine(engine::Error::Token))
    );
    let mut reverse = (1u64 << 56) + 0x34567;
    let mut drained = false;
    for step in 0..512u64 {
        let now = engine::Tick(prepared_at + 2 + step * 1000);
        transfer(
            &mut receiver,
            destination,
            &mut [(&mut sender, source)],
            now,
            &mut reverse,
        )?;
        transfer(
            &mut sender,
            source,
            &mut [(&mut receiver, destination)],
            now,
            &mut number,
        )?;
        // Feedback can mark the actual receive owner ready. Service it until
        // it observes no additional native body before claiming full drain.
        for (bank, id) in [(&mut sender, source), (&mut receiver, destination)] {
            assert!(matches!(
                bank.entry(id)?.prepare_native(
                    now,
                    32,
                    engine::Tick(10_000_000),
                    &mut foreign_output,
                )?,
                NativePreparation::Idle | NativePreparation::Progress
            ));
        }
        if receiver.engine(destination)?.drained()? && sender.engine(source)?.drained()? {
            drained = true;
            break;
        }
    }
    assert!(drained);
    receiver.retire(destination)?;
    let mut replacement = receiver.prepare(receiver_plan)?;
    let recycled = receiver.publish(&mut replacement)?;
    assert_eq!(recycled.slot, destination.slot);
    assert_ne!(recycled.generation, destination.generation);
    let before = receiver.engine(recycled)?.statistics();
    assert_eq!(
        receiver
            .entry(recycled)?
            .commit_native(engine::Tick(0), ready.token()),
        Err(Error::Stale)
    );
    assert_eq!(receiver.engine(recycled)?.statistics(), before);
    assert_eq!(receiver.engine(recycled)?.failure(), None);
    assert!(matches!(receiver.entry(destination), Err(Error::Stale)));
    Ok(())
}
