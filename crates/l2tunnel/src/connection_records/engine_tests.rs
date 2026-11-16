//! Actual shared-Pipeline consumer; authentication and physical receipts are injected.
use super::*;
use crate::codec::aligned_receiver as receiver;
use crate::{record_configuration as c, record_engine as engine};
use l2tunnel_core::{Duplex, traffic};
use l2tunnel_management::Role;
use l2tunnel_pipeline as pipeline;

fn tick(millis: u64) -> engine::Tick {
    engine::Tick(millis * 1000)
}

fn common() -> TestResult<c::CommonDirection> {
    Ok(c::CommonDirection::new(
        traffic::TrafficPolicy {
            layer: traffic::NetworkLayer::Tun,
            tcp: traffic::TcpControl::System,
            qos: traffic::Qos::WeightedDeficit,
        },
        pipeline::PipelineConfig {
            profile: pipeline::Profile::TunDrr(pipeline::TunQosConfig {
                base_quantum_bytes: 512,
                max_weight: 4,
                per_flow: pipeline::QueueLimits {
                    bytes: 8192,
                    packets: 16,
                },
            }),
            flows: pipeline::FlowTableConfig {
                capacity: 32,
                channels: 16,
                mapping: pipeline::Mapping::ConnectionRoundRobinLearned,
                idle_timeout: ms(5000),
            },
            parse: pipeline::ParseLimits {
                max_packet_bytes: 512,
                ..pipeline::ParseLimits::default()
            },
            queue: pipeline::QueueLimits {
                bytes: 32768,
                packets: 32,
            },
        },
        1_000_000,
        8192,
        c::NativeWindow::Disabled,
    )?)
}

fn engine_pair() -> TestResult<(engine::Engine, engine::Engine, c::Configuration)> {
    let (cfg, _) = selected()?;
    let value = c::Configuration::new(
        c::EnvelopeDigest::new([0x68; 32]),
        c::Descriptor::new(
            1500,
            Duplex::Full,
            common()?,
            common()?,
            c::Profile::PerConnectionCompact {
                forward: Direction {
                    compact: cfg.send,
                    owners: cfg.owners,
                    incarnation: cfg.incarnation,
                    unreliable: cfg.send_unreliable,
                },
                reverse: Direction {
                    compact: cfg.receive,
                    owners: cfg.owners,
                    incarnation: cfg.incarnation,
                    unreliable: cfg.receive_unreliable,
                },
            },
        )?,
    )?;
    let construct = |role| -> TestResult<engine::Engine> {
        let plan = engine::storage::Plan::for_engine(
            value,
            engine::Context {
                session: 0x1020,
                epoch: 7,
                role,
            },
            engine::Geometry {
                forward_overhead_bytes: 28,
                reverse_overhead_bytes: 28,
            },
            engine::NativeLimits {
                stall_micros: 1_000_000,
            },
        )?;
        let built = engine::Engine::new_reserved(
            plan,
            engine::storage::Limits {
                capacity_bytes: plan.capacity_bytes(),
            },
        )?;
        assert_eq!(
            built
                .storage_usage()
                .ok_or("actual Engine backing")?
                .capacity_bytes,
            plan.capacity_bytes()
        );
        Ok(built)
    };
    Ok((construct(Role::Client)?, construct(Role::Server)?, value))
}

fn tcp(port: u16) -> TestResult<Vec<u8>> {
    let mut bytes = ack(port);
    bytes.resize(100, 0x71);
    bytes[2..4].copy_from_slice(&100u16.to_be_bytes());
    bytes[33] = 0x18;
    fix_checksums(&mut bytes)?;
    Ok(bytes)
}
fn fix_checksums(bytes: &mut [u8]) -> TestResult {
    bytes[10..12].fill(0);
    bytes[36..38].fill(0);
    let ip = checksum(&bytes[..20]);
    bytes[10..12].copy_from_slice(&ip.to_be_bytes());
    let length = u16::try_from(
        bytes
            .len()
            .checked_sub(20)
            .ok_or("actual test TCP length")?,
    )?;
    let mut pseudo = bytes[12..20].to_vec();
    pseudo.extend_from_slice(&[0, 6]);
    pseudo.extend_from_slice(&length.to_be_bytes());
    pseudo.extend_from_slice(&bytes[20..]);
    let tcp = checksum(&pseudo);
    bytes[36..38].copy_from_slice(&tcp.to_be_bytes());
    Ok(())
}
fn reverse_ack(port: u16) -> TestResult<Vec<u8>> {
    let mut bytes = ack(port);
    bytes[12..16].copy_from_slice(&[192, 0, 2, 2]);
    bytes[16..20].copy_from_slice(&[192, 0, 2, 1]);
    bytes[20..22].copy_from_slice(&443u16.to_be_bytes());
    bytes[22..24].copy_from_slice(&port.to_be_bytes());
    fix_checksums(&mut bytes)?;
    Ok(bytes)
}

#[test]
fn actual_shared_pipeline_keeps_independent_loss_and_raw_ack_physical_custody_distinct()
-> TestResult {
    let (mut a, mut b, value) = engine_pair()?;
    let mut canonical = [0; c::CONFIGURATION_BYTES];
    value.encode_into(&mut canonical)?;
    assert_eq!(canonical[5], 8);
    assert_eq!(c::Configuration::decode(&canonical)?, value);
    let mut unsupported = canonical;
    unsupported[5] = 9;
    assert_eq!(
        c::Configuration::decode(&unsupported),
        Err(c::Error::Prefix)
    );
    let mut invalid = canonical;
    invalid[320 + DIRECTION_BYTES] = 1;
    assert!(c::Configuration::decode(&invalid).is_err());
    let first = tcp(41000)?;
    let second = tcp(41001)?;
    a.ingest_borrowed_at(tick(0), tick(0), &first, tick(1000))?;
    let first_admission = a
        .admit_borrowed(tick(0))?
        .ok_or("actual first owner admission")?;
    let engine::ProfileIdentity::Connection(first_identity) = first_admission.permit else {
        return Err("recovered first identity".into());
    };
    assert_eq!(first_identity.owner.index(), 0);
    let mut wire = vec![0; 2048];
    let mut witnesses = [receiver::UnitWitness {
        identity: receiver::RecordIdentity {
            channel: receiver::ChannelId(0),
            record: receiver::RecordId(0),
        },
        index: 0,
        count: 1,
    }; 1];
    let mut budget = OutboundBudget {
        packets: 8,
        wire_bytes: 8192,
    };
    let lost = a
        .poll(
            tick(1),
            u64::MAX - 8,
            true,
            &mut wire,
            &mut budget,
            &mut witnesses,
        )?
        .ok_or("actual first source")?;
    assert_eq!(witnesses[0].identity.channel.0, 0);
    let held = a
        .pending_carrier_output()
        .ok_or("actual held physical token")?;
    a.ingest_borrowed_at(tick(1), tick(1), &second, tick(1000))?;
    let next = a
        .admit_borrowed(tick(1))?
        .ok_or("independent admission while original output held")?;
    let engine::ProfileIdentity::Connection(next) = next.permit else {
        return Err("second recovered identity".into());
    };
    assert_eq!(next.owner.index(), 1);
    let debit = budget;
    let mut unchanged = vec![0xa5; 2048];
    assert_eq!(
        a.poll(
            tick(2),
            u64::MAX - 7,
            true,
            &mut unchanged,
            &mut budget,
            &mut witnesses
        )?,
        Some(lost)
    );
    assert!(unchanged.iter().all(|byte| *byte == 0xa5));
    assert_eq!(budget, debit);
    a.confirm_carrier_output_at(tick(3), tick(3), held)?;
    // The first accepted source is deliberately lost. The second real owner
    // progresses before any first-owner retry or recovery feedback is delivered.
    let emitted = a
        .poll(
            tick(4),
            u64::MAX - 6,
            true,
            &mut wire,
            &mut budget,
            &mut witnesses,
        )?
        .ok_or("second independent physical source")?;
    assert_eq!(witnesses[0].identity.channel.0, 1);
    let source = a
        .pending_carrier_output()
        .ok_or("second actual source token")?;
    let mut packet = wire[..emitted.bytes].to_vec();
    a.confirm_carrier_output_at(tick(4), tick(4), source)?;
    b.accept_authenticated_at(
        tick(4),
        tick(4),
        emitted.security_number,
        emitted.kind,
        &mut packet,
    )?;
    let mut native = vec![0; 512];
    let mut ready = None;
    for _ in 0..32 {
        if let engine::NativePreparation::Ready(prepared) =
            b.prepare_native(tick(5), 1, tick(1000), &mut native)?
        {
            ready = Some(prepared);
            break;
        }
    }
    let ready = ready.ok_or("second owner native despite lost first source")?;
    assert_eq!(&native[..ready.bytes()], second.as_slice());
    assert!(
        matches!(ready.identity(), engine::ProfileIdentity::Connection(identity) if identity.owner.index() == 1)
    );
    b.commit_native(tick(5), ready.token())?;
    let ack = reverse_ack(41001)?;
    let metadata = b.ingest_borrowed_at(tick(6), tick(6), &ack, tick(1000))?;
    let engine::IngressAdmission::Forwarded(metadata) = metadata else {
        return Err("raw ACK entered actual Pipeline".into());
    };
    assert_eq!(metadata.binding.channel, 1);
    let admitted = b
        .admit_borrowed(tick(6))?
        .ok_or("same flow raw ACK admission")?;
    assert!(
        matches!(admitted.permit, engine::ProfileIdentity::UnreliableNative(identity) if identity.owner.index() == 1)
    );
    assert!(b.native_counts()?.admitted.iter().all(|count| *count == 0));
    let raw = b
        .poll(
            tick(6),
            u64::MAX - 5,
            true,
            &mut wire,
            &mut budget,
            &mut witnesses,
        )?
        .ok_or("actual source-free ACK output")?;
    assert_eq!(raw.kind, engine::EmissionKind::UnreliableNative);
    assert_eq!(raw.wire_bytes, ack.len() + route::HEADER_BYTES + 28);
    assert_eq!(raw.witnesses, 0);
    let token = b
        .pending_carrier_output()
        .ok_or("raw actual physical witness")?;
    let mut packet = wire[..raw.bytes].to_vec();
    b.confirm_carrier_output_at(tick(7), tick(7), token)?;
    a.accept_authenticated_until(
        tick(7),
        tick(7),
        tick(1000),
        raw.security_number,
        raw.kind,
        &mut packet,
    )?;
    let mut raw_ready = None;
    for _ in 0..32 {
        if let engine::NativePreparation::Ready(prepared) =
            a.prepare_native(tick(8), 1, tick(1000), &mut native)?
        {
            raw_ready = Some(prepared);
            break;
        }
    }
    let raw_ready = raw_ready.ok_or("actual ACK native write custody")?;
    assert_eq!(&native[..raw_ready.bytes()], ack.as_slice());
    assert!(matches!(
        raw_ready.identity(),
        engine::ProfileIdentity::UnreliableNative(_)
    ));
    a.commit_native(tick(8), raw_ready.token())?;
    assert_eq!(
        a.commit_native(tick(8), raw_ready.token()),
        Err(engine::Error::Token)
    );
    assert!(a.native_counts()?.prepared.iter().all(|count| *count == 0));
    assert!(a.native_counts()?.committed.iter().all(|count| *count == 0));
    let facts = a
        .connection_snapshot()
        .ok_or("actual installed cohort status")?;
    assert_eq!(facts.owners, 16);
    assert!(!facts.flow_reuse);
    assert_eq!(facts.unreliable.received, 1);
    assert_eq!(facts.unreliable.native_written, 1);
    assert!(!a.drained()?);
    assert_eq!(
        b.connection_snapshot()
            .ok_or("actual sender raw counters")?
            .unreliable
            .physical_accepted,
        1
    );
    Ok(())
}
