//! Actual common owners and actual leased intents; no physical barrier claim.
use super::*;
use l2tunnel::record_configuration as configuration;
use l2tunnel_aligned as aligned;
use l2tunnel_codec::{aligned_body, aligned_receiver as receiver};
use l2tunnel_core::{Duplex, traffic};
use l2tunnel_management::{EndpointId, LaneId, SessionId};
use l2tunnel_pipeline as pipeline;
use l2tunnel_recovery::ArqConfig;
use l2tunnel_reliable::ReliableConfig;
use l2tunnel_swift as swift;
use std::time::Duration;

pub(in crate::secure_udp::transport) type Result<T = ()> =
    std::result::Result<T, Box<dyn std::error::Error>>;
pub(in crate::secure_udp::transport) const EXTERNAL: usize = 137;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::secure_udp::transport) enum Profile {
    Swift,
    Aligned,
    Packed,
}

fn swift_config(reverse: bool) -> swift::records::Config {
    swift::records::Config {
        channels: if reverse { 2 } else { 3 },
        layer: swift::records::Layer::Ethernet,
        max_native: 1024,
        codec: swift::Config {
            datagram_bytes: if reverse { 320 } else { 256 },
            window: 2,
            repair_numerator: 0,
            repair_denominator: 1,
            flow_sources: 8,
            queue_bytes: 8192,
            max_packet: 1025,
            flush_micros: 0,
            feedback_micros: 50,
            tail_micros: 5000,
            min_rto_micros: 20000,
            max_rto_micros: 100000,
        },
    }
}
fn aligned_config(reverse: bool, packed: bool) -> aligned::Config {
    let symbol = if reverse { 256 } else { 128 };
    let units = if reverse { 4 } else { 3 };
    let original = if packed {
        56 + 8 * units + symbol
    } else {
        48 + symbol
    };
    let source = 44 + original;
    let count = 2;
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
            record_window: 4,
            source_window: 32,
            lookahead_records: 4,
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
                initial_rto: Duration::from_millis(100),
                maximum_rto: Duration::from_millis(400),
                ack_delay: Duration::ZERO,
                max_retries: 4,
            },
            fec: l2tunnel_fec::DecoderConfig {
                block: l2tunnel_fec::BlockConfig {
                    max_sources: count,
                    max_source_bytes: source,
                    max_packet_bytes: fec_packet,
                    max_work_per_symbol: 1_000_000,
                },
                max_generations: 2,
                max_symbols_per_generation: 4,
                max_reserved_bytes: 1_000_000,
                max_lifetime_ticks: 50,
                generation_window: 32,
            },
            repair_symbols: 1,
            flush_after: Duration::from_millis(5),
            max_restored_packets: 16,
            max_restored_bytes: 16 * source,
            outer_overhead_bytes: if reverse { 73 } else { 17 },
        },
        max_recovery_packet_bytes: 8 + fec_packet + 7,
    }
}
fn common(reverse: bool) -> Result<configuration::CommonDirection> {
    Ok(configuration::CommonDirection::new(
        traffic::TrafficPolicy::tap(),
        pipeline::PipelineConfig {
            profile: pipeline::Profile::TapSystem,
            flows: pipeline::FlowTableConfig {
                capacity: 4,
                channels: if reverse { 2 } else { 3 },
                mapping: pipeline::Mapping::ConnectionRoundRobin,
                idle_timeout: Duration::from_secs(5),
            },
            parse: pipeline::ParseLimits {
                max_packet_bytes: 1024,
                ..pipeline::ParseLimits::default()
            },
            queue: pipeline::QueueLimits {
                bytes: 8192,
                packets: 8,
            },
        },
        if reverse { 1_000_002 } else { 2_000_001 },
        if reverse { 8195 } else { 8193 },
        configuration::NativeWindow::Disabled,
    )?)
}
pub(in crate::secure_udp::transport) fn configuration(profile: Profile) -> Result<C> {
    let profile = match profile {
        Profile::Swift => configuration::Profile::Swift {
            forward: swift_config(false),
            reverse: swift_config(true),
        },
        Profile::Aligned => configuration::Profile::Aligned {
            forward: aligned_config(false, false),
            reverse: aligned_config(true, false),
        },
        Profile::Packed => configuration::Profile::Packed {
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
    Ok(C::new(
        configuration::EnvelopeDigest::new([0x39; 32]),
        configuration::Descriptor::new(1500, Duplex::Full, common(false)?, common(true)?, profile)?,
    )?)
}
pub(in crate::secure_udp::transport) fn values() -> Result<[C; 3]> {
    Ok([
        configuration(Profile::Swift)?,
        configuration(Profile::Aligned)?,
        configuration(Profile::Packed)?,
    ])
}
pub(in crate::secure_udp::transport) fn identity(role: Role) -> tx::Identity {
    tx::Identity {
        session: SessionId([0x62; 16]),
        role,
        lane: LaneId(7),
        local: EndpointId(if role == Role::Client { 1 } else { 2 }),
        remote: EndpointId(if role == Role::Client { 2 } else { 1 }),
    }
}
pub(in crate::secure_udp::transport) fn geometry() -> records::Geometry {
    records::Geometry {
        forward_overhead_bytes: 17,
        reverse_overhead_bytes: 73,
    }
}
pub(in crate::secure_udp::transport) fn native() -> records::NativeLimits {
    records::NativeLimits {
        stall_micros: 50_000,
    }
}
pub(in crate::secure_udp::transport) fn initial_plan(role: Role) -> Result<records::storage::Plan> {
    Ok(plan(
        values()?[0],
        identity(role),
        Epoch(10),
        geometry(),
        native(),
    )?)
}
pub(in crate::secure_udp::transport) fn bank(role: Role) -> Result<Bank> {
    let maximum = values()?
        .into_iter()
        .try_fold(0, |maximum, value| -> Result<usize> {
            Ok(maximum
                .max(plan(value, identity(role), Epoch(11), geometry(), native())?.heap_bytes()))
        })?;
    let initial = storage::storage::Plan::for_bank(initial_plan(role)?, EXTERNAL)?;
    let limit = initial
        .capacity_bytes()
        .checked_add(maximum)
        .ok_or("fixture budget overflow")?;
    Ok(Bank::new(
        identity(role),
        Epoch(10),
        values()?[0],
        geometry(),
        native(),
        storage::storage::Limits {
            capacity_bytes: limit,
        },
        EXTERNAL,
    )?)
}
pub(in crate::secure_udp::transport) fn peer(role: Role, supported: &[C]) -> Result<tx::Peer<C>> {
    Ok(tx::Peer::new_leased_directional(
        identity(role),
        Epoch(10),
        supported[0],
        supported,
        tx::Settings {
            retry_ms: 10,
            phase_timeout_ms: 500,
            reconcile_timeout_ms: 1000,
        },
        tx::LeaseSettings {
            session_expires: tx::Tick(10_000),
            max_operation_ms: 5000,
            transaction_epoch: 4,
        },
        tx::Tick(0),
    )?)
}

#[test]
fn real_common_budget_refusal_preserves_current_queue_and_readonly_peer_intent() -> Result {
    let values = values()?;
    let initial = storage::storage::Plan::for_bank(initial_plan(Role::Client)?, EXTERNAL)?;
    let target = plan(
        values[1],
        identity(Role::Client),
        Epoch(11),
        geometry(),
        native(),
    )?;
    let mut bank = Bank::new(
        identity(Role::Client),
        Epoch(10),
        values[0],
        geometry(),
        native(),
        storage::storage::Limits {
            capacity_bytes: initial.capacity_bytes() + target.heap_bytes() - 1,
        },
        EXTERNAL,
    )?;
    let peer = peer(Role::Client, &values)?;
    let mut packet = [0x43; 80];
    packet[12..14].copy_from_slice(&0x88b5u16.to_be_bytes());
    bank.entry(Epoch(10))?
        .enqueue_borrowed(records::Tick(0), &packet)?;
    let before = (
        bank.usage(),
        bank.engine(Epoch(10))?.statistics(),
        bank.engine(Epoch(10))?.queue_usage(),
        bank.next_serial,
    );
    let pointer = bank.engine(Epoch(10))? as *const records::Engine;
    let intent = peer.preview_propose_until(&values[1], tx::Tick(1), tx::Tick(5000))?;
    let error = bank
        .prepare(intent)
        .err()
        .ok_or("one-short target unexpectedly allocated")?;
    assert!(matches!(
        error
            .get_ref()
            .and_then(|e| e.downcast_ref::<storage::Error>()),
        Some(storage::Error::Limit { .. })
    ));
    assert_eq!(
        (
            bank.usage(),
            bank.engine(Epoch(10))?.statistics(),
            bank.engine(Epoch(10))?.queue_usage(),
            bank.next_serial
        ),
        before
    );
    assert_eq!(bank.engine(Epoch(10))? as *const records::Engine, pointer);
    assert!(!bank.contains_epoch(Epoch(11)));
    assert!(peer.operation().is_none());
    assert_eq!(peer.phase(), tx::Phase::Idle);
    Ok(())
}

#[test]
fn actual_common_preparation_is_foreign_safe_and_publishes_the_same_engine() -> Result {
    let values = values()?;
    let mut a = bank(Role::Client)?;
    let mut b = bank(Role::Client)?;
    let mut peer = peer(Role::Client, &values)?;
    let intent = peer.preview_propose_until(&values[1], tx::Tick(1), tx::Tick(5000))?;
    let mut prepared = a.prepare(intent)?;
    let pointer = a.storage.prepared_engine(&prepared.storage)? as *const records::Engine;
    assert!(!a.contains_epoch(Epoch(11)));
    let before = b.usage();
    assert!(b.cancel(&mut prepared).is_err());
    assert_eq!(b.usage(), before);
    assert!(!prepared.consumed);
    let effects = peer.propose_until(values[1], tx::Tick(1), tx::Tick(5000))?;
    assert!(matches!(effects.event, Some(tx::Event::Stage { .. })));
    let operation = peer.operation().ok_or("missing real operation")?;
    a.stage(&mut prepared, operation)?;
    assert_eq!(a.engine(Epoch(11))? as *const records::Engine, pointer);
    assert_eq!(a.engine(Epoch(11))?.configuration(), &values[1]);
    assert_eq!(a.current(), &values[0]);
    assert_eq!(a.epoch(), Epoch(10));
    assert!(a.cancel(&mut prepared).is_err());
    // This is the actual storage publication guard, not a physical drain proof.
    assert_eq!(peer.phase(), tx::Phase::Staging);
    Ok(())
}

#[test]
fn complete_envelope_mismatch_refuses_before_any_common_reservation() -> Result {
    let values = values()?;
    let target = C::new(
        configuration::EnvelopeDigest::new([0x3a; 32]),
        *values[1].descriptor(),
    )?;
    let peer = peer(Role::Client, &[values[0], target])?;
    let mut bank = bank(Role::Client)?;
    let before = (bank.usage(), bank.next_serial);
    let intent = peer.preview_propose_until(&target, tx::Tick(1), tx::Tick(5000))?;
    assert!(bank.prepare(intent).is_err());
    assert_eq!((bank.usage(), bank.next_serial), before);
    assert!(bank.reservation.is_none());
    assert!(peer.operation().is_none());
    Ok(())
}
