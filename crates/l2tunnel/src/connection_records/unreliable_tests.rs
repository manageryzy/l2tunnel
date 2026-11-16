//! Actual fixed payload custody; authentication and whole writes are caller-injected.
use super::*;
use crate::packet::{Classification, PacketLayer, ParseLimits, classify};
use l2tunnel_recovery::EndpointRole;

fn checksum(bytes: &[u8]) -> u16 {
    let mut sum = 0u32;
    for pair in bytes.chunks(2) {
        sum += u32::from(u16::from_be_bytes([pair[0], *pair.get(1).unwrap_or(&0)]));
    }
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}
fn ack(port: u16) -> Vec<u8> {
    let mut bytes = vec![0; 40];
    bytes[0] = 0x45;
    bytes[2..4].copy_from_slice(&40u16.to_be_bytes());
    bytes[8] = 64;
    bytes[9] = 6;
    bytes[12..16].copy_from_slice(&[192, 0, 2, 1]);
    bytes[16..20].copy_from_slice(&[192, 0, 2, 2]);
    bytes[20..22].copy_from_slice(&port.to_be_bytes());
    bytes[22..24].copy_from_slice(&443u16.to_be_bytes());
    bytes[31] = 7;
    bytes[32] = 0x50;
    bytes[33] = 0x10;
    bytes[34..36].copy_from_slice(&1024u16.to_be_bytes());
    let ip_sum = checksum(&bytes[..20]);
    bytes[10..12].copy_from_slice(&ip_sum.to_be_bytes());
    let mut pseudo = bytes[12..20].to_vec();
    pseudo.extend_from_slice(&[0, 6, 0, 20]);
    pseudo.extend_from_slice(&bytes[20..]);
    let tcp_sum = checksum(&pseudo);
    bytes[36..38].copy_from_slice(&tcp_sum.to_be_bytes());
    bytes
}
fn metadata(bytes: &[u8]) -> TestResult<Classification> {
    Ok(classify(PacketLayer::Ip, bytes, ParseLimits::default())?)
}
fn selected() -> TestResult<(Config, storage::Plan)> {
    let mut cfg = config(16)?;
    cfg.send_unreliable = Some(UnreliableConfig {
        max_bytes: 128,
        hold_micros: 10_000,
    });
    cfg.receive_unreliable = Some(UnreliableConfig {
        max_bytes: 96,
        hold_micros: 10_000,
    });
    let plan = storage::Plan::for_collection(cfg)?;
    Ok((cfg, plan))
}

#[test]
fn raw_ack_original_caps_once_debit_and_physical_retirement_never_create_recovery_debt()
-> TestResult {
    let (cfg, plan) = selected()?;
    let mut peer_cfg = cfg;
    peer_cfg.send_unreliable = cfg.receive_unreliable;
    peer_cfg.receive_unreliable = cfg.send_unreliable;
    let peer_plan = storage::Plan::for_collection(peer_cfg)?;
    let mut a = Collection::new_reserved(
        plan,
        context(EndpointRole::Initiator),
        storage::Limits {
            capacity_bytes: plan.capacity_bytes(),
        },
    )?;
    let mut b = Collection::new_reserved(
        peer_plan,
        context(EndpointRole::Responder),
        storage::Limits {
            capacity_bytes: peer_plan.capacity_bytes(),
        },
    )?;
    let id = a.owner(0)?;
    let bytes = ack(40000);
    let class = metadata(&bytes)?;
    assert!(a.unreliable_eligible(class, &bytes));
    let identity = a
        .offer_unreliable(id, ms(0), ms(0), ms(8), class, &bytes)?
        .ok_or("actual raw ACK admission")?;
    assert!(a.slot(id)?.endpoint.drained());
    assert!(!a.drained());
    assert_eq!(
        a.offer_unreliable(id, ms(1), ms(1), ms(100), class, &bytes)?,
        None
    );
    let mut wire = vec![0; plan.send_max_packet_bytes()];
    let mut budget = OutboundBudget {
        packets: 1,
        wire_bytes: 1000,
    };
    let token = a
        .poll_unreliable(id, ms(1), &mut wire, &mut budget)?
        .ok_or("actual raw carrier custody")?;
    assert_eq!(token.identity(), identity);
    assert_eq!(token.deadline(), ms(8));
    assert_eq!(token.wire_bytes(), bytes.len() + route::HEADER_BYTES + 28);
    assert_eq!(
        budget,
        OutboundBudget {
            packets: 0,
            wire_bytes: 1000 - token.wire_bytes()
        }
    );
    let exact = wire[..token.bytes()].to_vec();
    let held_budget = budget;
    let mut untouched = vec![0xa5; wire.len()];
    assert!(
        a.poll_unreliable(id, ms(2), &mut untouched, &mut budget)?
            .is_none()
    );
    assert!(untouched.iter().all(|b| *b == 0xa5));
    assert_eq!(budget, held_budget);
    assert_eq!(a.pending_unreliable_output(id)?.as_ref(), Some(&token));
    let foreign = a
        .pending_unreliable_output(id)?
        .ok_or("same retained raw witness")?;
    assert_eq!(
        b.confirm_unreliable_output_at(ms(2), ms(2), foreign),
        Err(Error::Token)
    );
    b.accept_classified_authenticated_at(ms(3), ms(3), ms(7), &exact, class)?;
    let native = b
        .prepare_unreliable_native(id, ms(5))?
        .ok_or("actual raw native custody")?;
    let pending = b
        .pending_unreliable_native(id)?
        .ok_or("actual immutable ACK bytes")?;
    assert_eq!(pending.bytes, bytes.as_slice());
    assert_eq!(pending.deadline, ms(7));
    let repeat = b
        .prepare_unreliable_native(id, ms(6))?
        .ok_or("same native witness")?;
    assert_eq!(native, repeat);
    assert_eq!(
        b.pending_unreliable_native(id)?
            .ok_or("original native cap")?
            .deadline,
        ms(7)
    );
    // Acceptance preceded its cap; observing it later does not invent lateness.
    b.commit_unreliable_native_at(ms(9), ms(6), native)?;
    assert_eq!(
        b.commit_unreliable_native_at(ms(9), ms(6), repeat),
        Err(Error::Token)
    );
    let duplicate = a
        .pending_unreliable_output(id)?
        .ok_or("original physical witness")?;
    a.confirm_unreliable_output_at(ms(20), ms(2), token)?;
    assert_eq!(
        a.confirm_unreliable_output_at(ms(20), ms(2), duplicate),
        Err(Error::Token)
    );
    assert_eq!(a.unreliable_statistics().physical_accepted, 1);
    assert_eq!(a.unreliable_statistics().late_physical_accepted, 0);
    assert_eq!(b.unreliable_statistics().native_written, 1);
    assert!(a.slot(id)?.endpoint.drained() && b.slot(id)?.endpoint.drained());
    assert!(a.drained() && b.drained());
    // A genuine accepted datagram may be lost without ever creating peer debt.
    let other = a.owner(1)?;
    let second = ack(40001);
    let second_class = metadata(&second)?;
    a.offer_unreliable(other, ms(20), ms(20), ms(25), second_class, &second)?
        .ok_or("second raw ACK")?;
    let mut budget = OutboundBudget {
        packets: 1,
        wire_bytes: 1000,
    };
    let token = a
        .poll_unreliable(other, ms(21), &mut wire, &mut budget)?
        .ok_or("raw output later lost")?;
    a.confirm_unreliable_output_at(ms(30), ms(22), token)?;
    assert!(a.drained());
    let late = a.owner(2)?;
    let third = ack(40002);
    let third_class = metadata(&third)?;
    a.offer_unreliable(late, ms(30), ms(30), ms(35), third_class, &third)?
        .ok_or("actual late output admission")?;
    let mut budget = OutboundBudget {
        packets: 1,
        wire_bytes: 1000,
    };
    let token = a
        .poll_unreliable(late, ms(31), &mut wire, &mut budget)?
        .ok_or("late raw output")?;
    assert_eq!(
        a.confirm_unreliable_output_at(ms(40), ms(36), token),
        Err(Error::UnreliableExpired)
    );
    assert_eq!(a.unreliable_statistics().physical_accepted, 3);
    assert_eq!(a.unreliable_statistics().late_physical_accepted, 1);
    assert!(a.pending_unreliable_output(late)?.is_none());
    assert!(!a.drained());
    Ok(())
}

#[test]
fn flow_claims_raw_busy_and_complete_directional_policy_are_failure_atomic() -> TestResult {
    let (cfg, plan) = selected()?;
    let mut a = Collection::new_reserved(
        plan,
        context(EndpointRole::Initiator),
        storage::Limits {
            capacity_bytes: plan.capacity_bytes(),
        },
    )?;
    let id = a.owner(0)?;
    let other = a.owner(1)?;
    let bytes = ack(40000);
    let class = metadata(&bytes)?;
    a.offer_unreliable(id, ms(0), ms(0), ms(8), class, &bytes)?
        .ok_or("actual claim")?;
    let before = a.unreliable_statistics();
    assert_eq!(
        a.offer_recovered(other, class.key, ms(0), &frame(1)),
        Err(Error::Binding)
    );
    let different = ack(40001);
    let different_class = metadata(&different)?;
    assert_eq!(
        a.offer_unreliable(id, ms(1), ms(1), ms(100), different_class, &different),
        Err(Error::Binding)
    );
    assert_eq!(a.unreliable_statistics(), before);
    assert!(a.slot(id)?.endpoint.drained() && a.slot(other)?.endpoint.drained());
    let mut wire = vec![0; plan.send_max_packet_bytes()];
    let mut budget = OutboundBudget {
        packets: 1,
        wire_bytes: 1000,
    };
    let token = a
        .poll_unreliable(id, ms(1), &mut wire, &mut budget)?
        .ok_or("held exact ACK")?;
    let original = wire[..token.bytes()].to_vec();
    assert_eq!(&original[route::HEADER_BYTES..], bytes.as_slice());
    a.confirm_unreliable_output_at(ms(2), ms(2), token)?;
    // Downstream delay cannot restart the selected hold interval.
    a.offer_unreliable(id, ms(2), ms(6), ms(100), class, &bytes)?
        .ok_or("delayed same-flow admission")?;
    let mut budget = OutboundBudget {
        packets: 1,
        wire_bytes: 1000,
    };
    let delayed = a
        .poll_unreliable(id, ms(6), &mut wire, &mut budget)?
        .ok_or("original ingress cap")?;
    assert_eq!(delayed.deadline(), ms(12));
    let mut peer_cfg = cfg;
    peer_cfg.send_unreliable = cfg.receive_unreliable;
    peer_cfg.receive_unreliable = cfg.send_unreliable;
    let peer_plan = storage::Plan::for_collection(peer_cfg)?;
    let mut peer = Collection::new_reserved(
        peer_plan,
        context(EndpointRole::Responder),
        storage::Limits {
            capacity_bytes: peer_plan.capacity_bytes(),
        },
    )?;
    peer.accept_classified_authenticated_at(ms(3), ms(3), ms(8), &original, class)?;
    let first = peer
        .prepare_unreliable_native(id, ms(4))?
        .ok_or("held actual receive slot")?;
    let held_stats = peer.unreliable_statistics();
    assert_eq!(
        peer.accept_classified_authenticated_at(ms(4), ms(5), ms(8), &original, class),
        Err(Error::UnreliableBusy)
    );
    assert!(Error::UnreliableBusy.is_backpressure());
    assert_eq!(peer.unreliable_statistics(), held_stats);
    assert_eq!(
        peer.pending_unreliable_native(id)?
            .ok_or("unchanged held receive")?
            .deadline,
        ms(8)
    );
    peer.commit_unreliable_native_at(ms(6), ms(6), first)?;
    // Retry retains its own original arrival/cap; no renewed cap at observation.
    assert_eq!(
        peer.accept_classified_authenticated_at(ms(4), ms(8), ms(8), &original, class),
        Err(Error::UnreliableExpired)
    );
    assert_eq!(peer.unreliable_statistics().received, held_stats.received);
    assert!(peer.pending_unreliable_native(id)?.is_none());
    let direction = Direction {
        compact: cfg.send,
        owners: cfg.owners,
        incarnation: cfg.incarnation,
        unreliable: cfg.send_unreliable,
    };
    let mut encoded = [0; DIRECTION_BYTES];
    direction.encode_into(&mut encoded)?;
    assert_eq!(DIRECTION_BYTES, 277);
    assert_eq!(Direction::decode(&encoded)?, direction);
    let mut invalid = encoded;
    invalid[aligned::COMPACT_CONFIG_BYTES + 11] = 0;
    assert_eq!(Direction::decode(&invalid), Err(Error::Configuration));
    let mut invalid = encoded;
    invalid[aligned::COMPACT_CONFIG_BYTES] = 2;
    assert_eq!(Direction::decode(&invalid), Err(Error::Configuration));
    let usage = a.storage_usage();
    assert_eq!(usage.capacity_bytes, plan.capacity_bytes());
    assert_eq!(a.raw_send.capacity(), usize::from(cfg.owners) * 128);
    assert_eq!(a.raw_receive.capacity(), usize::from(cfg.owners) * 96);
    Ok(())
}

#[path = "engine_tests.rs"]
mod engine;
