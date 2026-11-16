//! Real endpoint custody; management authentication is injected only into private scopes.
use super::super::tests::{TestResult, collect, config, construct, context, frame, ms};
use super::*;
use crate::packet::{PacketLayer, ParseLimits, classify};

fn scope(role: EndpointRole, attempt: u64, expires: Duration) -> Scope {
    let (local, remote) = match role {
        EndpointRole::Initiator => (1, 2),
        EndpointRole::Responder => (2, 1),
    };
    Scope {
        context: context(role),
        digest: ConfigDigest([0x39; 32]),
        attempt,
        target_epoch: 8,
        target_digest: ConfigDigest([0x42; 32]),
        local,
        remote,
        lane: 3,
        expires,
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
fn raw_ack() -> Vec<u8> {
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
fn budget() -> OutboundBudget {
    OutboundBudget {
        packets: 1,
        wire_bytes: 100_000,
    }
}
fn feedback(from: &mut Collection, to: &mut Collection, id: OwnerId, now: Duration) -> TestResult {
    let mut bytes = vec![0; from.plan.send_max_packet_bytes()];
    if let Some(token) = from.poll_feedback(id, now, &mut bytes, &mut budget())? {
        let length = token.bytes();
        from.confirm_output_at(now, now, token)?;
        to.accept_authenticated_at(now, now, &bytes[..length])?;
    }
    Ok(())
}

#[test]
fn reuse_keeps_actual_owner_state_and_requires_crossed_drain_before_new_incarnation() -> TestResult
{
    let cfg = config(2)?;
    let mut a = construct(cfg, EndpointRole::Initiator)?;
    let mut b = construct(cfg, EndpointRole::Responder)?;
    let usage = a.storage_usage();
    let id = a.owner(0)?;
    let (old_bytes, old_key) = body(40000)?;
    let original = a
        .offer_recovered(id, old_key, ms(0), &old_bytes)?
        .ok_or("old actual admission")?;
    let mut wire = vec![0; a.plan.send_max_packet_bytes()];
    let token = a
        .poll_data(id, ms(0), &mut wire, &mut budget())?
        .ok_or("old physical output")?;
    let stale_output = a.pending_data_output(id)?.ok_or("old output witness")?;
    let old_wire = wire[..token.bytes()].to_vec();
    a.confirm_output_at(ms(0), ms(0), token)?;
    b.accept_authenticated_at(ms(0), ms(0), &old_wire)?;
    let mut held = None;
    for _ in 0..8 {
        match b.prepare_native(id, ms(1), 1)? {
            NativePreparation::Progress => {}
            NativePreparation::Ready(token) => {
                held = Some(token);
                break;
            }
            _ => return Err("actual old native body missing".into()),
        }
    }
    let held = held.ok_or("bounded old native preparation")?;
    let stale_native = match b.prepare_native(id, ms(1), 1)? {
        NativePreparation::AlreadyPending(token) => token,
        _ => return Err("original native custody not retained".into()),
    };
    assert_eq!(b.pending_native(id)?.ok_or("old body")?.bytes, old_bytes);
    b.bind_received_owner(id, old_key)?;
    let ta = a.begin_retirement(
        id,
        old_key,
        scope(EndpointRole::Initiator, 1, ms(200)),
        ms(1),
    )?;
    let tb = b.begin_retirement(
        id,
        old_key,
        scope(EndpointRole::Responder, 1, ms(199)),
        ms(1),
    )?;
    assert_eq!(a.offer_recovered(id, old_key, ms(1), &old_bytes)?, None);
    assert_eq!(a.retirement_fence(ms(1), &ta), Err(Error::RetirementBusy));
    assert_eq!(b.retirement_fence(ms(1), &tb), Err(Error::RetirementBusy));
    b.commit_native(ms(1), held)?;
    let mut delivered = Vec::new();
    // Service all three original 5 ms feedback emissions, including retained repeats.
    for step in 2..=20 {
        let now = ms(step);
        // The actual sender must finish its bounded codec staging even when
        // every emitted source has already reached the peer.
        if let Some(token) = a.poll_data(id, now, &mut wire, &mut budget())? {
            let length = token.bytes();
            a.confirm_output_at(now, now, token)?;
            b.accept_authenticated_at(now, now, &wire[..length])?;
        }
        collect(&mut b, id, now, &mut delivered)?;
        feedback(&mut b, &mut a, id, now)?;
        feedback(&mut a, &mut b, id, now)?;
        if local_drained(a.slot(id)?) && local_drained(b.slot(id)?) {
            break;
        }
    }
    assert!(delivered.is_empty());
    let (independent, independent_key) = body(40001)?;
    let other = a.owner(1)?;
    assert!(
        a.offer_recovered(other, independent_key, ms(20), &independent)?
            .is_some()
    );
    assert!(!a.drained());
    let independent_status = a.slot(other)?.endpoint.status();
    assert_eq!(independent_status.recovery.arq.send_records, 1);
    let fa = a.retirement_fence(ms(20), &ta).map_err(|error| {
        format!(
            "initiator old fence: {error:?}; endpoint={:?}",
            a.slots[0].endpoint.status()
        )
    })?;
    let fb = b.retirement_fence(ms(20), &tb).map_err(|error| {
        format!(
            "responder old fence: {error:?}; endpoint={:?}",
            b.slots[0].endpoint.status()
        )
    })?;
    assert_eq!(
        (fa.admitted, fa.written, fb.admitted, fb.written),
        (1, 0, 0, 1)
    );
    assert!(!b.drained(), "retirement control still owns an obligation");
    a.accept_retirement_fence_at(ms(20), ms(20), &ta, fb)
        .map_err(|error| {
            format!("a.accept_retirement_fence_at(ms(20), ms(20), &ta, fb): {error:?}")
        })?;
    b.accept_retirement_fence_at(ms(20), ms(20), &tb, fa)
        .map_err(|error| {
            format!("b.accept_retirement_fence_at(ms(20), ms(20), &tb, fa): {error:?}")
        })?;
    let ia = a
        .install_reuse(ms(20), &ta)
        .map_err(|error| format!("a.install_reuse(ms(20), &ta): {error:?}"))?;
    let ib = b
        .install_reuse(ms(20), &tb)
        .map_err(|error| format!("b.install_reuse(ms(20), &tb): {error:?}"))?;
    assert!(!a.admission_open(id)? && !b.admission_open(id)?);
    assert_eq!(a.route_incarnation(id)?, cfg.incarnation + 1);
    assert_eq!(a.route_incarnation(other)?, cfg.incarnation);
    assert_eq!(
        b.accept_authenticated_at(ms(20), ms(20), &old_wire),
        Err(Error::Incarnation)
    );
    let mut premature = old_wire.clone();
    premature[8..16].copy_from_slice(&(cfg.incarnation + 1).to_be_bytes());
    assert_eq!(
        b.accept_authenticated_at(ms(20), ms(20), &premature),
        Err(Error::Retiring)
    );
    assert!(b.pending_native(id)?.is_none());
    assert_eq!(
        a.confirm_output_at(ms(20), ms(20), stale_output),
        Err(Error::Token)
    );
    assert_eq!(b.commit_native(ms(20), stale_native), Err(Error::Token));
    let mut conflicting_install = ib;
    conflicting_install.next_incarnation += 1;
    assert_eq!(
        a.activate_reuse_after_confirmation(ms(20), &ta, conflicting_install),
        Err(Error::RetirementConflict)
    );
    assert!(!a.admission_open(id)?);
    a.activate_reuse_after_confirmation(ms(20), &ta, ib)
        .map_err(|error| {
            format!("a.activate_reuse_after_confirmation(ms(20), &ta, ib): {error:?}")
        })?;
    b.activate_reuse_after_confirmation(ms(20), &tb, ia)
        .map_err(|error| {
            format!("b.activate_reuse_after_confirmation(ms(20), &tb, ia): {error:?}")
        })?;
    let (new_bytes, new_key) = body(40100)?;
    let next = a
        .offer_recovered(id, new_key, ms(20), &new_bytes)?
        .ok_or("new flow on same actual endpoint")?;
    assert_eq!(
        a.begin_retirement(
            id,
            new_key,
            scope(EndpointRole::Initiator, 1, ms(200)),
            ms(20)
        ),
        Err(Error::RetirementConflict)
    );
    assert!(a.admission_open(id)?);
    assert_eq!(next.incarnation, cfg.incarnation + 1);
    assert!(next.record.record.0 > original.record.record.0);
    let mut output = Vec::new();
    for step in 21..=40 {
        let now = ms(step);
        if let Some(token) = a.poll_data(id, now, &mut wire, &mut budget())? {
            let length = token.bytes();
            assert_eq!(
                route::decode(&wire[..length])?.0.incarnation,
                cfg.incarnation + 1
            );
            a.confirm_output_at(now, now, token)?;
            b.accept_authenticated_at(now, now, &wire[..length])?;
        }
        collect(&mut b, id, now, &mut output)?;
        feedback(&mut b, &mut a, id, now)?;
        if local_drained(a.slot(id)?) && local_drained(b.slot(id)?) {
            break;
        }
    }
    assert_eq!(output, vec![new_bytes]);
    assert_eq!(a.storage_usage(), usage);
    assert_eq!(a.slot(other)?.endpoint.status(), independent_status);
    assert!(!a.slot(other)?.endpoint.drained());
    Ok(())
}

#[test]
fn retirement_conflicts_caps_and_foreign_tokens_never_reset_or_reopen_a_route() -> TestResult {
    let mut cfg = config(1)?;
    cfg.send_unreliable = Some(UnreliableConfig {
        max_bytes: 128,
        hold_micros: 10_000,
    });
    cfg.receive_unreliable = cfg.send_unreliable;
    let mut a = construct(cfg, EndpointRole::Initiator)?;
    let mut b = construct(cfg, EndpointRole::Responder)?;
    let id = a.owner(0)?;
    let ack = raw_ack();
    let class = classify(PacketLayer::Ip, &ack, ParseLimits::default())?;
    let key = class.key;
    // Lost source-free ACKs do not become reliable delivery debt.
    a.bind_received_owner(id, key)?;
    b.bind_received_owner(id, key)?;
    let sa = scope(EndpointRole::Initiator, 1, ms(5));
    let sb = scope(EndpointRole::Responder, 1, ms(6));
    a.offer_unreliable(id, ms(0), ms(0), ms(4), class, &ack)?
        .ok_or("actual old ACK admission")?;
    let mut wire = vec![0; a.plan.send_max_packet_bytes()];
    let raw = a
        .poll_unreliable(id, ms(0), &mut wire, &mut budget())?
        .ok_or("held old ACK output")?;
    assert_eq!(raw.deadline(), ms(4));
    let ta = a.begin_retirement(id, key, sa, ms(0))?;
    assert_eq!(a.retirement_fence(ms(0), &ta), Err(Error::RetirementBusy));
    assert_eq!(a.expiry_deadline(), Some(ms(4)));
    // Actual whole acceptance releases local custody; the ACK is then lost.
    a.confirm_unreliable_output_at(ms(1), ms(1), raw)?;
    assert_eq!(a.unreliable_statistics().physical_accepted, 1);
    assert_eq!(b.unreliable_statistics().received, 0);
    let duplicate = a.begin_retirement(id, key, sa, ms(4))?;
    assert_eq!(ta, duplicate);
    assert_eq!(a.expiry_deadline(), Some(ms(5)));
    let tb = b.begin_retirement(id, key, sb, ms(0))?;
    assert_eq!(a.retirement_fence(ms(0), &tb), Err(Error::Token));
    let fa = a.retirement_fence(ms(4), &ta)?;
    let fb = b.retirement_fence(ms(4), &tb)?;
    let mut wrong = fb;
    wrong.scope.digest.0[0] ^= 1;
    assert_eq!(
        a.accept_retirement_fence_at(ms(3), ms(4), &ta, wrong),
        Err(Error::RetirementConflict)
    );
    assert_eq!(a.preflight_reuse(ms(4), &ta), Err(Error::RetirementBusy));
    wrong = fb;
    wrong.written = 1;
    assert_eq!(
        a.accept_retirement_fence_at(ms(3), ms(4), &ta, wrong),
        Err(Error::RetirementBusy)
    );
    a.accept_retirement_fence_at(ms(3), ms(4), &ta, fb)?;
    b.accept_retirement_fence_at(ms(3), ms(4), &tb, fa)?;
    let ia = a.install_reuse(ms(4), &ta)?;
    let ib = b.install_reuse(ms(4), &tb)?;
    assert_eq!(
        a.activate_reuse_after_confirmation(ms(5), &ta, ib),
        Err(Error::RetirementExpired)
    );
    assert!(!a.admission_open(id)?);
    assert_eq!(
        a.slot(id)?
            .retirement
            .ok_or("retained expired operation")?
            .scope
            .expires,
        ms(5)
    );
    assert_eq!(a.route_incarnation(id)?, cfg.incarnation + 1);
    assert_eq!(b.preflight_reuse(ms(6), &tb), Err(Error::RetirementExpired));
    assert_eq!(ia.next_incarnation, ib.next_incarnation);
    assert_eq!(a.slot(id)?.admitted_native, 0);
    assert_eq!(a.slot(id)?.written_native, 0);
    Ok(())
}
