//! Actual independent owners exchange wire bytes; no sender source ledger is read.
#[path = "early_tests.rs"]
mod early;
use super::*;
use crate::{
    codec::{aligned_body, aligned_sender, packed},
    management::Role,
};
use std::collections::VecDeque;
type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn direction(reverse: bool, raw: bool, wire: rolling::wire::SourceWire) -> DirectionConfig {
    let symbol_bytes = if reverse { 224 } else { 192 };
    let channels = if reverse { 2 } else { 3 };
    let body = aligned_body::Config {
        max_frame_bytes: 1024,
        symbol_bytes,
        elide_payload_length: !raw,
        predictive: !raw,
        timestamp_pair_dictionary: !raw,
        independent_short_frame_bytes: 64,
    };
    let first_record = receiver::RecordId(if reverse { 19 } else { 7 });
    let first_source = receiver::SourceId(if reverse { 91 } else { 13 });
    DirectionConfig {
        native_policy: if raw {
            NativePolicy::RawIp
        } else {
            NativePolicy::EthernetHeaders
        },
        receiver: receiver::Limits {
            body,
            channels,
            first_record,
            first_source,
            record_window: 32,
            source_window: 32,
            lookahead_records: 4,
            lookahead_bytes: 4 * 65535,
            lookahead_fragments: 64,
            max_fragments_per_record: 8,
            lifetime_ticks: 5_000_000,
        },
        packing: packed_sender::Config {
            sender: aligned_sender::Config {
                body,
                channels,
                first_record,
            },
            packing: packed::Config {
                symbol_bytes,
                hold_micros: if reverse { 701 } else { 503 },
            },
            max_units: 4,
            first_unit: first_source,
            work_limit: 4,
        },
        codec_stage_micros: 1_000_000,
        scheduler: scheduler::Policy {
            recovery: rolling::Config {
                window: 16,
                local_window: 4,
                global_every: 2,
                max_payload: 512,
                max_rows: 16,
                repair_history: 64,
                handoff_sources: 2,
                job_ticks: 1_000_000,
                debt_ticks: 10_000_000,
                handoff_ticks: 2_000_000,
                memory_bytes: 16 << 20,
            },
            repair_numerator: 1,
            repair_denominator: 2,
            tail_ticks: 1000,
            feedback_ticks: 100,
            feedback_packets: 2,
            memory_bytes: 16 << 20,
            source_wire: wire,
        },
    }
}
fn config(raw: bool, wire: rolling::wire::SourceWire) -> Config {
    Config {
        forward: direction(false, raw, wire),
        reverse: direction(true, raw, wire),
        geometry: Geometry {
            forward_overhead_bytes: 41,
            reverse_overhead_bytes: 73,
        },
        native_stall_micros: 10_000,
    }
}
fn context(role: Role) -> Context {
    Context {
        session: 0x102030405060708091a2b3c4d5e6f789,
        epoch: 7,
        role,
    }
}
fn endpoint(config: Config, role: Role) -> TestResult<Endpoint> {
    Ok(Endpoint::new(config, context(role), 17, Tick(0))?)
}
fn work() -> rolling::WorkBudget {
    rolling::WorkBudget {
        field: 65536,
        copies: 65536,
        metadata: 65536,
    }
}
fn packet(raw: bool, value: u8, length: usize) -> Vec<u8> {
    let ip_length = length - if raw { 0 } else { 14 };
    let mut bytes = vec![value; ip_length];
    bytes[..40].fill(0);
    bytes[0] = 0x45;
    bytes[2..4].copy_from_slice(&(ip_length as u16).to_be_bytes());
    bytes[8] = 64;
    bytes[9] = 6;
    bytes[12..16].copy_from_slice(&[10, 0, 0, 1]);
    bytes[16..20].copy_from_slice(&[10, 0, 0, 2]);
    bytes[20..22].copy_from_slice(&1000u16.to_be_bytes());
    bytes[22..24].copy_from_slice(&443u16.to_be_bytes());
    bytes[32] = 0x50;
    bytes[33] = 0x10;
    bytes[ip_length - 4..].fill(0);
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
fn witness() -> receiver::UnitWitness {
    receiver::UnitWitness {
        identity: receiver::RecordIdentity {
            channel: receiver::ChannelId(0),
            record: receiver::RecordId(0),
        },
        index: 0,
        count: 1,
    }
}
#[derive(Clone)]
struct Datagram {
    kind: record_engine::EmissionKind,
    bytes: Vec<u8>,
}
fn emit(
    endpoint: &mut Endpoint,
    now: Tick,
    number: &mut u64,
    allow_data: bool,
) -> TestResult<Option<(PreparedOutput, Datagram)>> {
    let mut output = [0u8; rolling::wire::MAX_RECORD_BYTES];
    let mut witnesses = [witness(); 4];
    let mut budget = OutboundBudget {
        packets: 1,
        wire_bytes: 10_000,
    };
    let Some(prepared) = endpoint.prepare_output(
        now,
        *number,
        allow_data,
        &mut output,
        &mut budget,
        &mut witnesses,
    )?
    else {
        return Ok(None);
    };
    assert_eq!(prepared.security_number, *number);
    assert_eq!(budget.packets, 0);
    assert_eq!(budget.wire_bytes, 10_000 - prepared.wire_bytes);
    assert_eq!(prepared.wire_bytes, prepared.bytes + endpoint.overhead);
    let datagram = Datagram {
        kind: prepared.kind,
        bytes: output[..prepared.bytes].to_vec(),
    };
    endpoint.confirm_output(now, prepared)?;
    *number = number
        .checked_add(1)
        .ok_or("test security number exhaustion")?;
    Ok(Some((prepared, datagram)))
}
fn receive(endpoint: &mut Endpoint, now: Tick, queue: &mut VecDeque<Datagram>) -> TestResult {
    if let Some(front) = queue.front() {
        match endpoint.accept_authenticated(now, front.kind, &front.bytes) {
            Ok(()) => {
                queue.pop_front();
            }
            Err(error) if error.is_backpressure() => {}
            Err(error) => return Err(error.into()),
        }
    }
    assert!(queue.len() <= 128);
    Ok(())
}

#[test]
fn actual_compact_rolling_recovers_both_directions_with_loss_and_original_zero_tails() -> TestResult
{
    for wire in [
        rolling::wire::SourceWire::Padded,
        rolling::wire::SourceWire::Exact,
    ] {
        for raw in [false, true] {
            let config = config(raw, wire);
            let mut client = endpoint(config, Role::Client)?;
            let mut server = endpoint(config, Role::Server)?;
            let forward = packet(raw, 0x39, 700);
            let reverse = packet(raw, 0x73, 389);
            let forward_id = client
                .enqueue_admitted_identified(Tick(0), 2, &forward)?
                .ok_or("forward admission")?;
            let reverse_id = server
                .enqueue_admitted_identified(Tick(0), 1, &reverse)?
                .ok_or("reverse admission")?;
            client.flush(Tick(0))?;
            server.flush(Tick(0))?;
            let mut to_server = VecDeque::new();
            let mut to_client = VecDeque::new();
            let mut numbers = [(1u64 << 48) + 0x12345, (1u64 << 56) + 0x34567];
            let mut dropped_source = false;
            let mut dropped_feedback = false;
            let mut repairs = 0;
            let mut delivered = [false; 2];
            for step in 0..5000u64 {
                let now = Tick(step * 10);
                client.step(now, work())?;
                server.step(now, work())?;
                if let Some((prepared, datagram)) = emit(&mut client, now, &mut numbers[0], true)? {
                    if matches!(
                        prepared.id,
                        OutputId::Data(scheduler::OutputId::Source(rolling::SourceId(0)))
                    ) && !dropped_source
                    {
                        dropped_source = true;
                    } else {
                        to_server.push_back(datagram);
                    }
                    if prepared.kind == record_engine::EmissionKind::Repair {
                        repairs += 1;
                    }
                }
                if let Some((prepared, datagram)) = emit(&mut server, now, &mut numbers[1], true)? {
                    if prepared.kind == record_engine::EmissionKind::Feedback && !dropped_feedback {
                        dropped_feedback = true;
                    } else {
                        to_client.push_back(datagram);
                    }
                }
                receive(&mut server, now, &mut to_server)?;
                receive(&mut client, now, &mut to_client)?;
                for (index, endpoint, expected, identity) in [
                    (0, &mut server, &forward, forward_id),
                    (1, &mut client, &reverse, reverse_id),
                ] {
                    let mut output = [0u8; 1024];
                    if let NativePreparation::Ready(prepared) =
                        endpoint.prepare_native(now, 32, Tick(1_000_000), &mut output)?
                    {
                        assert!(!delivered[index]);
                        assert_eq!(prepared.identity(), identity);
                        assert_eq!(&output[..prepared.bytes()], expected);
                        assert_eq!(endpoint.statistics().committed, 0);
                        endpoint.commit_native(now, prepared.token())?;
                        delivered[index] = true;
                    }
                }
                if delivered == [true, true]
                    && to_client.is_empty()
                    && to_server.is_empty()
                    && client.drained()
                    && server.drained()
                {
                    break;
                }
            }
            assert_eq!(delivered, [true, true]);
            assert!(dropped_source && dropped_feedback && repairs > 0);
            assert!(client.drained() && server.drained());
            assert_eq!(client.statistics().committed, 1);
            assert_eq!(server.statistics().committed, 1);
        }
    }
    Ok(())
}

#[test]
fn exact_output_budget_retry_retains_real_owner_and_full_security_number() -> TestResult {
    let config = config(true, rolling::wire::SourceWire::Exact);
    let mut endpoint = endpoint(config, Role::Client)?;
    let original = packet(true, 0x91, 64);
    endpoint
        .enqueue_admitted_identified(Tick(0), 0, &original)?
        .ok_or("admission")?;
    endpoint.flush(Tick(0))?;
    endpoint.step(Tick(0), work())?;
    let length = endpoint
        .sender
        .pending_wire_len()?
        .ok_or("systematic output")?;
    let mut output = [0xa5; rolling::wire::MAX_RECORD_BYTES];
    let mut witnesses = [witness(); 4];
    let mut budget = OutboundBudget {
        packets: 1,
        wire_bytes: length + 40,
    };
    let status = endpoint.sender_status();
    assert_eq!(
        endpoint.prepare_output(
            Tick(0),
            u64::MAX - 17,
            true,
            &mut output,
            &mut budget,
            &mut witnesses
        )?,
        None
    );
    assert_eq!(output, [0xa5; rolling::wire::MAX_RECORD_BYTES]);
    assert_eq!(endpoint.sender_status(), status);
    budget.wire_bytes += 1;
    let prepared = endpoint
        .prepare_output(
            Tick(0),
            u64::MAX - 17,
            true,
            &mut output,
            &mut budget,
            &mut witnesses,
        )?
        .ok_or("exact retry")?;
    assert_eq!(prepared.security_number, u64::MAX - 17);
    assert_eq!(output[4], 2);
    assert_eq!(&output[66..70], b"L2PK");
    assert_eq!(
        prepared.bytes,
        66 + usize::from(u16::from_be_bytes([output[64], output[65]]))
    );
    let saved = output;
    let charged = budget.wire_bytes;
    assert_eq!(
        endpoint.prepare_output(Tick(1), 7, false, &mut output, &mut budget, &mut witnesses)?,
        Some(prepared)
    );
    assert_eq!(output, saved);
    assert_eq!(budget.wire_bytes, charged);
    let mut foreign = Endpoint::new(config, context(Role::Client), 17, Tick(0))?;
    foreign
        .enqueue_admitted_identified(Tick(0), 0, &original)?
        .ok_or("foreign admission")?;
    foreign.flush(Tick(0))?;
    foreign.step(Tick(0), work())?;
    let mut foreign_output = [0; rolling::wire::MAX_RECORD_BYTES];
    let mut foreign_budget = OutboundBudget {
        packets: 1,
        wire_bytes: prepared.wire_bytes,
    };
    let foreign_prepared = foreign
        .prepare_output(
            Tick(0),
            prepared.security_number,
            true,
            &mut foreign_output,
            &mut foreign_budget,
            &mut witnesses,
        )?
        .ok_or("foreign actual output")?;
    assert_eq!(
        &foreign_output[..foreign_prepared.bytes],
        &saved[..prepared.bytes]
    );
    assert_eq!(foreign_prepared.id, prepared.id);
    assert_ne!(foreign_prepared, prepared);
    let foreign_status = foreign.sender_status();
    assert_eq!(
        foreign.confirm_output(Tick(u64::MAX), prepared),
        Err(Error::Token)
    );
    assert_eq!(foreign.sender_status(), foreign_status);
    assert_eq!(foreign.failure(), None);
    assert_eq!(
        endpoint.confirm_output(Tick(u64::MAX), foreign_prepared),
        Err(Error::Token)
    );
    assert_eq!(endpoint.failure(), None);
    let mut stale = prepared;
    stale.security_number -= 1;
    assert_eq!(
        endpoint.confirm_output(Tick(u64::MAX), stale),
        Err(Error::Token)
    );
    assert_eq!(endpoint.failure(), None);
    endpoint.confirm_output(Tick(1), prepared)?;
    assert_eq!(
        endpoint.confirm_output(Tick(1), prepared),
        Err(Error::Token)
    );
    assert_eq!(endpoint.statistics().handed, 1);
    Ok(())
}

#[test]
fn complete_policy_and_stream_binding_preserve_independent_fields_and_width_limits() -> TestResult {
    let config = config(true, rolling::wire::SourceWire::Exact);
    let digest = config.digest()?;
    let mut changed = config;
    changed.reverse.scheduler.recovery.global_every += 1;
    assert_ne!(digest, changed.digest()?);
    changed = config;
    changed.reverse.codec_stage_micros += 1;
    assert_ne!(digest, changed.digest()?);
    changed = config;
    changed.reverse.receiver.lifetime_ticks += 1;
    assert_ne!(digest, changed.digest()?);
    assert_ne!(config.binding_digest(17)?, config.binding_digest(18)?);
    assert_eq!(
        endpoint(config, Role::Server)?.binding_digest(),
        config.binding_digest(17)?
    );
    changed = config;
    changed.forward.packing.sender.channels = 256;
    changed.forward.receiver.channels = 256;
    assert!(changed.validate().is_err());
    changed = config;
    changed.forward.packing.first_unit.0 += 1;
    assert_eq!(changed.validate(), Err(Error::Configuration));
    changed = config;
    changed.reverse.packing.sender.body.symbol_bytes += 1;
    assert!(changed.validate().is_err());
    Ok(())
}

#[test]
fn actual_reserved_pipeline_handoff_retains_busy_head_and_original_native_expiry() -> TestResult {
    use crate::pipeline;
    use std::time::Duration;
    let config = config(true, rolling::wire::SourceWire::Exact);
    let mut client = endpoint(config, Role::Client)?;
    let mut server = endpoint(config, Role::Server)?;
    let queue = pipeline::QueueLimits {
        bytes: 4096,
        packets: 4,
    };
    let policy = pipeline::PipelineConfig {
        profile: pipeline::Profile::TunDrr(pipeline::TunQosConfig {
            base_quantum_bytes: 1024,
            max_weight: 1,
            per_flow: queue,
        }),
        flows: pipeline::FlowTableConfig {
            capacity: 4,
            channels: 3,
            mapping: pipeline::Mapping::ConnectionRoundRobin,
            idle_timeout: Duration::from_secs(1),
        },
        parse: pipeline::ParseLimits {
            max_packet_bytes: 1024,
            ..pipeline::ParseLimits::default()
        },
        queue,
    };
    let plan = pipeline::storage::Plan::for_pipeline(policy)?;
    let limit = pipeline::storage::Limits {
        capacity_bytes: plan.capacity_bytes(),
    };
    let mut pipeline = pipeline::Pipeline::new_reserved(policy, limit)?;
    let usage = pipeline.storage_usage();
    let first = packet(true, 0x33, 1000);
    let second = packet(true, 0x77, 900);
    pipeline.enqueue_borrowed(&first, Duration::ZERO)?;
    pipeline.enqueue_borrowed(&second, Duration::ZERO)?;
    let admitted = client
        .admit_from_pipeline(Tick(0), &mut pipeline)?
        .ok_or("actual borrowed admission")?;
    assert_eq!(client.statistics().admitted, 1);
    let waiting = pipeline.usage();
    assert!(client.packing.status().staged_frame);
    assert!(
        client
            .enqueue_admitted_identified(Tick(0), admitted.metadata.binding.channel, &second)?
            .is_none()
    );
    assert!(
        client
            .admit_from_pipeline(Tick(0), &mut pipeline)?
            .is_none()
    );
    assert_eq!(pipeline.usage(), waiting);
    assert_eq!(client.statistics().admitted, 1);
    assert_eq!(pipeline.storage_usage(), usage);
    let mut number = (1u64 << 48) + 9;
    let mut reverse = (1u64 << 56) + 11;
    let mut forward = VecDeque::new();
    let mut backward = VecDeque::new();
    let mut prepared_native = None;
    for step in 0..5000u64 {
        let now = Tick(step * 10);
        client.step(now, work())?;
        server.step(now, work())?;
        if let Some((_, datagram)) = emit(&mut client, now, &mut number, true)? {
            forward.push_back(datagram);
        }
        // Reverse rolling feedback remains available with all reverse user data disabled.
        if let Some((prepared, datagram)) = emit(&mut server, now, &mut reverse, false)? {
            assert_eq!(prepared.kind, record_engine::EmissionKind::Feedback);
            backward.push_back(datagram);
        }
        receive(&mut server, now, &mut forward)?;
        receive(&mut client, now, &mut backward)?;
        let mut output = [0u8; 1024];
        if let NativePreparation::Ready(prepared) =
            server.prepare_native(now, 32, Tick(1_000_000), &mut output)?
        {
            assert_eq!(&output[..prepared.bytes()], first);
            assert_eq!(prepared.identity(), admitted.permit);
            prepared_native = Some((now, prepared));
            break;
        }
    }
    let (now, prepared) = prepared_native.ok_or("bounded actual native prepare")?;
    let mut untouched = [0xa5; 1024];
    assert_eq!(
        server.prepare_native(Tick(now.0 + 1), 32, Tick(9_000_000), &mut untouched)?,
        NativePreparation::AlreadyPending(prepared)
    );
    assert_eq!(untouched, [0xa5; 1024]);
    assert_eq!(server.statistics().committed, 0);
    assert_eq!(
        server.commit_native(prepared.deadline(), prepared.token()),
        Err(Error::Expired)
    );
    assert_eq!(server.statistics().committed, 1);
    assert_eq!(server.pending_native(), None);
    assert_eq!(
        server.commit_native(now, prepared.token()),
        Err(Error::Token)
    );
    assert_eq!(server.statistics().committed, 1);
    assert_eq!(pipeline.usage(), waiting);
    assert_eq!(pipeline.storage_usage(), usage);
    Ok(())
}

#[path = "copy_tests.rs"]
mod copies;

#[path = "framing_tests.rs"]
mod framing;
