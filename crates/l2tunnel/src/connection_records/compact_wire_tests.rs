//! Actual selected route owners; caller authentication and physical writes are injected.
use super::tests::{TestResult, collect, config, construct, context, frame, ms};
use super::*;
use crate::packet::{PacketLayer, ParseLimits, classify};
use l2tunnel_core::{ConfigDigest, Epoch};
use l2tunnel_management::{self as mg, session_control as sc, transaction as tx};
use l2tunnel_recovery::EndpointRole;

fn budget() -> OutboundBudget {
    OutboundBudget {
        packets: 1,
        wire_bytes: 100_000,
    }
}
fn body(port: u16) -> TestResult<(Vec<u8>, crate::packet::FlowKey)> {
    let mut bytes = frame(0x31);
    bytes[20..22].copy_from_slice(&port.to_be_bytes());
    bytes[22..24].copy_from_slice(&443u16.to_be_bytes());
    bytes[24..26].copy_from_slice(&80u16.to_be_bytes());
    bytes[26..28].fill(0);
    let key = classify(PacketLayer::Ip, &bytes, ParseLimits::default())?.key;
    Ok((bytes, key))
}
fn feedback(from: &mut Collection, to: &mut Collection, id: OwnerId, now: Duration) -> TestResult {
    let mut bytes = vec![0; from.plan.send_max_packet_bytes()];
    let mut allowance = budget();
    if let Some(token) = from.poll_feedback(id, now, &mut bytes, &mut allowance)? {
        let length = token.bytes();
        let (header, inner) = route::decode_compact(&bytes[..length])?;
        assert_eq!(header.class, route::Class::Feedback);
        assert_eq!(length - inner.len(), 10);
        assert_eq!(token.wire_bytes(), length + 40);
        assert_eq!(allowance.wire_bytes, 100_000 - token.wire_bytes());
        from.confirm_output_at(now, now, token)?;
        to.accept_authenticated_at(now, now, &bytes[..length])?;
    }
    Ok(())
}

#[test]
fn compact_route_arms_are_exact_full_width_and_never_fallback() -> TestResult {
    for class in [
        route::Class::Source,
        route::Class::Feedback,
        route::Class::UnreliableNative,
    ] {
        let header = route::Header {
            owner: OwnerId(255),
            incarnation: u64::MAX,
            class,
            unreliable_serial: if class == route::Class::UnreliableNative {
                u64::MAX
            } else {
                0
            },
        };
        let length = if class == route::Class::UnreliableNative {
            18
        } else {
            10
        };
        assert_eq!(header.compact_bytes(), length);
        let mut bytes = vec![0xa5; length + 1];
        header.encode_compact(&mut bytes[..length])?;
        assert_eq!(route::decode_compact(&bytes)?, (header, &bytes[length..]));
        assert_eq!(&bytes[2..10], &u64::MAX.to_be_bytes());
        for end in 0..=length {
            assert!(route::decode_compact(&bytes[..end]).is_err());
        }
        assert!(route::decode(&bytes).is_err());
        let mut invalid = bytes.clone();
        invalid[2..10].fill(0);
        assert_eq!(route::decode_compact(&invalid), Err(route::Error::Identity));
        let mut output = vec![0x55; length];
        assert_eq!(
            route::Header {
                incarnation: 0,
                ..header
            }
            .encode_compact(&mut output),
            Err(route::Error::Identity)
        );
        assert!(output.iter().all(|byte| *byte == 0x55));
    }
    Ok(())
}

#[test]
fn compact_collection_loss_independent_progress_strong_feedback_and_reuse_keep_one_owner()
-> TestResult {
    let cfg = config(2)?;
    let mut a = construct(cfg, EndpointRole::Initiator)?;
    let mut b = construct(cfg, EndpointRole::Responder)?;
    a.enable_compact_wire(40)?;
    b.enable_compact_wire(40)?;
    let usage = a.storage_usage();
    let zero = a.owner(0)?;
    let one = a.owner(1)?;
    let (first, key) = body(40000)?;
    let (second, other_key) = body(40001)?;
    let original = a
        .offer_recovered(zero, key, ms(0), &first)?
        .ok_or("first admission")?;
    a.offer_recovered(one, other_key, ms(0), &second)?
        .ok_or("independent admission")?;
    let mut bytes = vec![0; a.plan.send_max_packet_bytes()];
    let mut allowance = budget();
    let lost = a
        .poll_data(zero, ms(0), &mut bytes, &mut allowance)?
        .ok_or("original source")?;
    let stale = bytes[..lost.bytes()].to_vec();
    let (header, inner) = a.decode_route(&stale)?;
    assert_eq!(header.incarnation, cfg.incarnation);
    assert_eq!(stale.len() - inner.len(), 10);
    assert_eq!(lost.wire_bytes(), stale.len() + 28);
    assert_eq!(allowance.wire_bytes, 100_000 - lost.wire_bytes());
    let mut wrong = stale.clone();
    wrong[2..10].copy_from_slice(&(cfg.incarnation ^ (1 << 63)).to_be_bytes());
    assert_eq!(
        b.accept_authenticated_at(ms(0), ms(0), &wrong),
        Err(Error::Incarnation)
    );
    let mut wrong = stale.clone();
    wrong[0] = 2;
    assert_eq!(
        b.accept_authenticated_at(ms(0), ms(0), &wrong),
        Err(Error::Class)
    );
    let mut held = vec![0x55; bytes.len()];
    let before = allowance;
    assert!(
        a.poll_data(zero, ms(0), &mut held, &mut allowance)?
            .is_none()
    );
    assert_eq!(allowance, before);
    assert!(held.iter().all(|byte| *byte == 0x55));
    let independent = a
        .poll_data(one, ms(0), &mut bytes, &mut budget())?
        .ok_or("other owner progresses")?;
    let length = independent.bytes();
    a.confirm_output_at(ms(0), ms(0), independent)?;
    b.accept_authenticated_at(ms(0), ms(0), &bytes[..length])?;
    let mut delivered = [Vec::new(), Vec::new()];
    collect(&mut b, one, ms(0), &mut delivered[1])?;
    assert_eq!(delivered[1], [second]);
    assert!(b.pending_native(zero)?.is_none());
    a.confirm_output_at(ms(10), ms(7), lost)?;
    let mut retried = false;
    for tick in 20..=1900 {
        let now = ms(tick);
        for id in [zero, one] {
            if let Some(token) = a.poll_data(id, now, &mut bytes, &mut budget())? {
                let length = token.bytes();
                retried |= id == zero;
                assert_eq!(token.wire_bytes(), length + 28);
                a.confirm_output_at(now, now, token)?;
                b.accept_authenticated_at(now, now, &bytes[..length])?;
            }
            collect(&mut b, id, now, &mut delivered[usize::from(id.index())])?;
            feedback(&mut b, &mut a, id, now)?;
        }
        if a.drained() && b.drained() {
            break;
        }
    }
    assert!(retried && a.drained() && b.drained());
    assert_eq!(delivered[0], [first]);
    b.bind_received_owner(zero, key)?;
    let digest = ConfigDigest([0x39; 32]);
    let operation = tx::Operation::slot_reuse(
        tx::Identity {
            session: mg::SessionId(context(EndpointRole::Initiator).session.to_be_bytes()),
            role: mg::Role::Client,
            local: mg::EndpointId(1),
            remote: mg::EndpointId(2),
            lane: mg::LaneId(3),
        },
        sc::Scope {
            epoch: Epoch(7),
            digest,
        },
        1,
        ConfigDigest([0x42; 32]),
        tx::Tick(2000),
        tx::Tick(3000),
        tx::Tick(4000),
        1000,
    )?;
    let ta = a.begin_retirement(
        zero,
        key,
        retirement::Scope::from_operation(context(EndpointRole::Initiator), digest, operation)?,
        ms(2000),
    )?;
    let tb = b.begin_retirement(
        zero,
        key,
        retirement::Scope::from_operation(
            context(EndpointRole::Responder),
            digest,
            operation.mirror_slot_reuse()?,
        )?,
        ms(2000),
    )?;
    let fa = a.retirement_fence(ms(2000), &ta)?;
    let fb = b.retirement_fence(ms(2000), &tb)?;
    a.accept_retirement_fence_at(ms(2000), ms(2000), &ta, fb)?;
    b.accept_retirement_fence_at(ms(2000), ms(2000), &tb, fa)?;
    let ia = a.install_reuse(ms(2000), &ta)?;
    let ib = b.install_reuse(ms(2000), &tb)?;
    a.activate_reuse_after_confirmation(ms(2000), &ta, ib)?;
    b.activate_reuse_after_confirmation(ms(2000), &tb, ia)?;
    assert_eq!(
        b.accept_authenticated_at(ms(2000), ms(2000), &stale),
        Err(Error::Incarnation)
    );
    let (next, next_key) = body(41000)?;
    let admitted = a
        .offer_recovered(zero, next_key, ms(2000), &next)?
        .ok_or("reused selected owner")?;
    assert_eq!(admitted.incarnation, cfg.incarnation + 1);
    assert!(admitted.record.record.0 > original.record.record.0);
    let token = a
        .poll_data(zero, ms(2000), &mut bytes, &mut budget())?
        .ok_or("selected source after reuse")?;
    let length = token.bytes();
    let (header, inner) = a.decode_route(&bytes[..length])?;
    assert_eq!(length - inner.len(), 10);
    let (observed_route, extent) = a.inspect_output_extent(&bytes[..length])?;
    assert_eq!(observed_route, header);
    let extent = extent.ok_or("actual recovered route extent")?;
    assert_eq!(
        extent.recovery.bytes + observed_route.compact_bytes(),
        length
    );
    assert!(extent.codec.is_some());
    assert_eq!(header.incarnation, cfg.incarnation + 1);
    assert_eq!(token.wire_bytes(), length + 28);
    a.confirm_output_at(ms(2000), ms(2000), token)?;
    b.accept_authenticated_at(ms(2000), ms(2000), &bytes[..length])?;
    let mut restored = Vec::new();
    collect(&mut b, zero, ms(2000), &mut restored)?;
    assert_eq!(restored, [next]);
    assert_eq!(a.storage_usage(), usage);
    assert!(a.compact_wire && b.compact_wire);
    Ok(())
}

#[test]
fn compact_collection_selection_refusal_is_atomic_across_previously_polled_owners() -> TestResult {
    let mut owner = construct(config(2)?, EndpointRole::Initiator)?;
    let zero = owner.owner(0)?;
    let one = owner.owner(1)?;
    let mut bytes = vec![0; owner.plan.send_max_packet_bytes()];
    assert!(
        owner
            .poll_data(one, ms(1), &mut bytes, &mut budget())?
            .is_none()
    );
    assert!(owner.enable_compact_wire(40).is_err());
    assert!(!owner.compact_wire);
    owner.enqueue(zero, ms(1), &frame(0x41))?;
    let token = owner
        .poll_data(zero, ms(1), &mut bytes, &mut budget())?
        .ok_or("legacy source after refused selection")?;
    let (_, inner) = route::decode(&bytes[..token.bytes()])?;
    assert_eq!(token.bytes() - inner.len(), 24);
    assert_eq!(inner[12], 2);
    assert!(route::decode_compact(&bytes[..token.bytes()]).is_err());
    Ok(())
}

fn ack() -> Vec<u8> {
    fn checksum(bytes: &[u8]) -> u16 {
        let mut sum = bytes
            .chunks(2)
            .map(|pair| u32::from(u16::from_be_bytes([pair[0], *pair.get(1).unwrap_or(&0)])))
            .sum::<u32>();
        while sum > 0xffff {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        !(sum as u16)
    }
    let mut bytes = vec![0; 40];
    bytes[0] = 0x45;
    bytes[2..4].copy_from_slice(&40u16.to_be_bytes());
    bytes[8] = 64;
    bytes[9] = 6;
    bytes[12..16].copy_from_slice(&[192, 0, 2, 1]);
    bytes[16..20].copy_from_slice(&[192, 0, 2, 2]);
    bytes[20..22].copy_from_slice(&40000u16.to_be_bytes());
    bytes[22..24].copy_from_slice(&443u16.to_be_bytes());
    bytes[31] = 7;
    bytes[32] = 0x50;
    bytes[33] = 0x10;
    bytes[34..36].copy_from_slice(&1024u16.to_be_bytes());
    let ip = checksum(&bytes[..20]);
    bytes[10..12].copy_from_slice(&ip.to_be_bytes());
    let mut pseudo = bytes[12..20].to_vec();
    pseudo.extend_from_slice(&[0, 6, 0, 20]);
    pseudo.extend_from_slice(&bytes[20..]);
    let tcp = checksum(&pseudo);
    bytes[36..38].copy_from_slice(&tcp.to_be_bytes());
    bytes
}

#[test]
fn compact_source_free_route_preserves_full_serial_once_cost_and_native_custody() -> TestResult {
    let mut cfg = config(1)?;
    cfg.send_unreliable = Some(UnreliableConfig {
        max_bytes: 128,
        hold_micros: 10_000,
    });
    cfg.receive_unreliable = cfg.send_unreliable;
    let mut a = construct(cfg, EndpointRole::Initiator)?;
    let mut b = construct(cfg, EndpointRole::Responder)?;
    a.enable_compact_wire(40)?;
    b.enable_compact_wire(40)?;
    let id = a.owner(0)?;
    let frame = ack();
    let class = classify(PacketLayer::Ip, &frame, ParseLimits::default())?;
    let original = a
        .offer_unreliable(id, ms(0), ms(0), ms(8), class, &frame)?
        .ok_or("raw ACK admission")?;
    let mut bytes = vec![0; a.plan.send_max_packet_bytes()];
    let mut allowance = budget();
    let token = a
        .poll_unreliable(id, ms(1), &mut bytes, &mut allowance)?
        .ok_or("raw output")?;
    let (header, payload) = a.decode_route(&bytes[..token.bytes()])?;
    assert_eq!(token.bytes() - payload.len(), 18);
    assert_eq!(header.unreliable_serial, original.serial);
    assert_eq!(payload, frame);
    let (observed_route, extent) = a.inspect_output_extent(&bytes[..token.bytes()])?;
    assert_eq!(observed_route, header);
    assert_eq!(extent, None);
    assert_eq!(token.wire_bytes(), 18 + frame.len() + 28);
    assert_eq!(allowance.wire_bytes, 100_000 - token.wire_bytes());
    assert!(a.slot(id)?.endpoint.drained());
    assert!(
        a.poll_unreliable(id, ms(2), &mut bytes, &mut allowance)?
            .is_none()
    );
    b.accept_classified_authenticated_at(ms(3), ms(3), ms(7), &bytes[..token.bytes()], class)?;
    let native = b
        .prepare_unreliable_native(id, ms(4))?
        .ok_or("actual ACK native")?;
    assert_eq!(
        b.pending_unreliable_native(id)?
            .ok_or("actual ACK bytes")?
            .bytes,
        frame
    );
    b.commit_unreliable_native_at(ms(5), ms(5), native)?;
    a.confirm_unreliable_output_at(ms(5), ms(2), token)?;
    assert!(a.drained() && b.drained());
    assert!(a.slot(id)?.endpoint.drained() && b.slot(id)?.endpoint.drained());
    Ok(())
}
