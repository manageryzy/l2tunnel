//! Actual leased Peer preparation without staging, admission or timer mutation.

use super::*;
use crate::transaction::tests::directional::Policy;
use crate::transaction::{
    Effects, Event, Fence, LeaseSettings, Operation, Settings, configuration_digest,
};
use crate::{EndpointId, Frame, Header, LaneId, PacketNumber, RequestId, Role, SessionId};
use l2tunnel_core::Epoch;

type Result<T = ()> = std::result::Result<T, Error>;
const CAP: Tick = Tick(1_000);

fn identity(role: Role) -> Identity {
    Identity {
        session: SessionId([0x61; 16]),
        role,
        local: EndpointId(if role == Role::Client { 1 } else { 2 }),
        remote: EndpointId(if role == Role::Client { 2 } else { 1 }),
        lane: LaneId(7),
    }
}
fn ingress(role: Role) -> Ingress {
    Ingress::AuthenticatedManagement {
        session: identity(role).session,
        lane: LaneId(7),
        sender: role,
    }
}
fn pair() -> Result<(Peer<Policy>, Peer<Policy>)> {
    let initial = Policy::new(2, 3);
    let target = Policy::new(4, 1);
    let make = |role| {
        Peer::new_leased_directional(
            identity(role),
            Epoch(10),
            initial.clone(),
            &[initial.clone(), target.clone()],
            Settings {
                retry_ms: 10,
                phase_timeout_ms: 100,
                reconcile_timeout_ms: 200,
            },
            LeaseSettings {
                session_expires: Tick(10_000),
                max_operation_ms: 2_000,
                transaction_epoch: 4,
            },
            Tick(0),
        )
    };
    Ok((make(Role::Client)?, make(Role::Server)?))
}
fn wire(effects: Effects<Policy>) -> Result<Vec<u8>> {
    effects.outbound.ok_or(Error::Unexpected)
}
fn encoded(header: Header, body: &[u8]) -> Result<Vec<u8>> {
    let mut output = vec![0; crate::HEADER_LEN + body.len()];
    Frame { header, body }
        .encode(&mut output, super::super::limits())
        .map_err(Error::Admission)?;
    Ok(output)
}
fn rewrite(bytes: &[u8], update: impl FnOnce(&mut Header, &mut Vec<u8>)) -> Result<Vec<u8>> {
    let frame = Frame::decode(bytes, super::super::limits()).map_err(Error::Admission)?;
    let mut header = frame.header;
    let mut body = frame.body.to_vec();
    update(&mut header, &mut body);
    encoded(header, &body)
}
fn prepare(client: &mut Peer<Policy>) -> Result<Vec<u8>> {
    client.propose_until(Policy::new(4, 1), Tick(1), CAP)?;
    wire(client.staged(Fence::new(&[3, 5])?, Tick(2))?)
}
#[derive(Debug, Eq, PartialEq)]
struct Snapshot {
    phase: Phase,
    active: Policy,
    guard: (l2tunnel_session::Phase, l2tunnel_session::Ticket),
    operation: Option<Operation>,
    now: Tick,
    attempt: u64,
    command: u64,
    request: u64,
    packet: u64,
    deadline: Tick,
    retry: Tick,
    supported: Vec<l2tunnel_core::ConfigDigest>,
    replay: (Option<PacketNumber>, u128),
    floor: Option<RequestId>,
    retained: usize,
    requests: Vec<(Header, Vec<u8>)>,
    cached: Option<(RequestId, MessageKind, Vec<u8>)>,
}
fn snapshot(peer: &Peer<Policy>) -> Snapshot {
    Snapshot {
        phase: peer.phase,
        active: peer.active.clone(),
        guard: (peer.guard.phase(), peer.guard.active()),
        operation: peer.operation(),
        now: peer.now,
        attempt: peer.last_attempt,
        command: peer.last_command,
        request: peer.next_request,
        packet: peer.next_packet,
        deadline: peer.deadline,
        retry: peer.next_retry,
        supported: peer.supported.clone(),
        replay: (peer.gate.replay.highest, peer.gate.replay.seen),
        floor: peer.gate.retired_through,
        retained: peer.gate.retained_bytes,
        requests: peer
            .gate
            .requests
            .iter()
            .map(|r| (r.header, r.body.clone()))
            .collect(),
        cached: peer
            .cached
            .as_ref()
            .map(|c| (c.for_request, c.message.kind, c.message.body.clone())),
    }
}

#[test]
fn repeated_local_preview_then_actual_asymmetric_stage_preserves_ids_and_original_scope() -> Result
{
    let (mut client, _) = pair()?;
    let before = snapshot(&client);
    let target = Policy::new(4, 1);
    for at in [Tick(1), Tick(50), Tick(99)] {
        let intent = client.preview_propose_until(&target, at, CAP)?;
        assert_eq!(intent.identity(), identity(Role::Client));
        assert_eq!(intent.ticket().attempt, 1);
        assert_eq!(intent.ticket().epoch, Epoch(11));
        assert_eq!(intent.ticket().digest, configuration_digest(&target)?);
        assert_eq!(
            intent.origin(),
            session_control::Scope {
                epoch: Epoch(10),
                digest: configuration_digest(&Policy::new(2, 3))?
            }
        );
        assert_eq!(intent.config(), &target);
        assert_eq!(intent.expires(), CAP);
        assert_eq!(snapshot(&client), before);
    }
    let intended = client.preview_propose_until(&target, Tick(1), CAP)?;
    let event = client.propose_until(target, Tick(1), CAP)?.event;
    assert!(
        matches!(event,Some(Event::Stage {ticket,config}) if ticket==intended.ticket() && config==*intended.config())
    );
    let frame = wire(client.staged(Fence::new(&[3, 5])?, Tick(2))?)?;
    let frame = Frame::decode(&frame, super::super::limits()).map_err(Error::Admission)?;
    assert_eq!(frame.header.request, RequestId(1));
    assert_eq!(frame.header.packet, PacketNumber(1));
    Ok(())
}

#[test]
fn remote_preview_matches_real_first_stage_and_retries_never_prepare_twice() -> Result {
    let (mut client, mut server) = pair()?;
    let bytes = prepare(&mut client)?;
    let before = snapshot(&server);
    for at in [Tick(3), Tick(99)] {
        let intent = server
            .preview_receive_until(ingress(Role::Client), &bytes, at, CAP)?
            .ok_or(Error::Unexpected)?;
        assert_eq!(intent.identity(), identity(Role::Server));
        assert_eq!(intent.config(), &Policy::new(4, 1));
        assert_eq!(intent.expires(), CAP);
        assert_eq!(intent.origin().epoch, Epoch(10));
        assert_eq!(snapshot(&server), before);
    }
    let intent = server
        .preview_receive_until(ingress(Role::Client), &bytes, Tick(3), CAP)?
        .ok_or(Error::Unexpected)?;
    let event = server
        .receive_until(ingress(Role::Client), &bytes, Tick(3), CAP)?
        .event;
    assert!(
        matches!(event,Some(Event::Stage {ticket,config}) if ticket==intent.ticket() && config==*intent.config())
    );
    let original = snapshot(&server);
    assert!(matches!(
        server.preview_receive_until(ingress(Role::Client), &bytes, Tick(4), CAP),
        Err(Error::Admission(crate::Error::PacketReplay))
    ));
    let repeated = rewrite(&bytes, |h, _| h.packet = PacketNumber(2))?;
    assert!(
        server
            .preview_receive_until(ingress(Role::Client), &repeated, Tick(4), CAP)?
            .is_none()
    );
    assert_eq!(snapshot(&server), original);
    assert!(
        server
            .receive_until(ingress(Role::Client), &repeated, Tick(4), CAP)?
            .event
            .is_none()
    );
    let ready = wire(server.staged(Fence::new(&[7, 11, 13])?, Tick(5))?)?;
    let repeated = rewrite(&bytes, |h, _| h.packet = PacketNumber(3))?;
    let before = snapshot(&server);
    assert!(
        server
            .preview_receive_until(ingress(Role::Client), &repeated, Tick(6), CAP)?
            .is_none()
    );
    assert_eq!(snapshot(&server), before);
    let cached = wire(server.receive_until(ingress(Role::Client), &repeated, Tick(6), CAP)?)?;
    let a = Frame::decode(&ready, super::super::limits()).map_err(Error::Admission)?;
    let b = Frame::decode(&cached, super::super::limits()).map_err(Error::Admission)?;
    assert!(a.header.same_request(b.header));
    assert_eq!(a.body, b.body);
    Ok(())
}

#[test]
fn new_prepare_request_during_operation_and_conflicting_retry_are_atomic_refusals() -> Result {
    let (mut client, mut server) = pair()?;
    let bytes = prepare(&mut client)?;
    server.receive_until(ingress(Role::Client), &bytes, Tick(3), CAP)?;
    let before = snapshot(&server);
    let changed = rewrite(&bytes, |h, b| {
        h.packet = PacketNumber(2);
        if let Some(last) = b.last_mut() {
            *last ^= 1;
        }
    })?;
    assert!(matches!(
        server.preview_receive_until(ingress(Role::Client), &changed, Tick(4), CAP),
        Err(Error::Admission(crate::Error::RequestConflict))
    ));
    let fresh = rewrite(&bytes, |h, _| {
        h.packet = PacketNumber(2);
        h.request = RequestId(2);
    })?;
    assert!(matches!(
        server.preview_receive_until(ingress(Role::Client), &fresh, Tick(4), CAP),
        Err(Error::Unexpected)
    ));
    assert_eq!(snapshot(&server), before);
    let retry = rewrite(&bytes, |h, _| h.packet = PacketNumber(2))?;
    assert!(
        server
            .preview_receive_until(ingress(Role::Client), &retry, Tick(4), CAP)?
            .is_none()
    );
    server.receive_until(ingress(Role::Client), &retry, Tick(4), CAP)?;
    Ok(())
}

#[test]
fn invalid_caps_catalog_bindings_and_directional_fences_do_not_mutate_or_burn_attempts() -> Result {
    let (mut client, server) = pair()?;
    let before = snapshot(&client);
    for invalid in [Policy::new(0, 1), Policy::new(257, 1), Policy::new(4, 2)] {
        assert!(
            client
                .preview_propose_until(&invalid, Tick(1), CAP)
                .is_err()
        );
        assert_eq!(snapshot(&client), before);
    }
    for cap in [Tick(1), Tick(2_002), Tick(10_001)] {
        assert!(
            client
                .preview_propose_until(&Policy::new(4, 1), Tick(1), cap)
                .is_err()
        );
        assert_eq!(snapshot(&client), before);
    }
    assert!(matches!(
        server.preview_propose_until(&Policy::new(4, 1), Tick(1), CAP),
        Err(Error::NotCoordinator)
    ));
    let bytes = prepare(&mut client)?;
    let before = snapshot(&server);
    let wrong_width = rewrite(&bytes, |_, b| {
        b.truncate(8 + Policy::ENCODED_LEN);
        b.extend_from_slice(&3u16.to_be_bytes());
        b.extend_from_slice(&[0; 24]);
    })?;
    let wrong_digest = rewrite(&bytes, |h, _| h.ticket.digest.0[0] ^= 1)?;
    let wrong_canonical = rewrite(&bytes, |_, b| b[8] = 2)?;
    for invalid in [&wrong_width, &wrong_digest, &wrong_canonical] {
        assert!(
            server
                .preview_receive_until(ingress(Role::Client), invalid, Tick(3), CAP)
                .is_err()
        );
        assert_eq!(snapshot(&server), before);
    }
    for verified in [
        Ingress::UserTraffic,
        Ingress::Unauthenticated,
        ingress(Role::Server),
        Ingress::AuthenticatedManagement {
            session: SessionId([0x62; 16]),
            lane: LaneId(7),
            sender: Role::Client,
        },
        Ingress::AuthenticatedManagement {
            session: identity(Role::Client).session,
            lane: LaneId(8),
            sender: Role::Client,
        },
    ] {
        assert!(
            server
                .preview_receive_until(verified, &bytes, Tick(3), CAP)
                .is_err()
        );
        assert_eq!(snapshot(&server), before);
    }
    assert!(
        server
            .preview_receive_until(ingress(Role::Client), &bytes, Tick(3), CAP)?
            .is_some()
    );
    Ok(())
}

#[test]
fn actual_full_request_or_byte_ledger_refuses_preview_and_preserves_new_packet() -> Result {
    for byte_bound in [false, true] {
        let (mut client, mut server) = pair()?;
        let bytes = prepare(&mut client)?;
        // Populate the real gate through its real admit API; no synthetic replay state.
        if byte_bound {
            server.gate.limits.max_retained_bytes = bytes.len() - 1;
        } else {
            let filler = rewrite(&bytes, |h, _| {
                h.request = RequestId(9);
                h.packet = PacketNumber(9);
            })?;
            server.gate.limits.max_requests = 1;
            server
                .gate
                .admit(ingress(Role::Client), &filler)
                .map_err(Error::Admission)?;
        }
        let before = snapshot(&server);
        assert!(matches!(
            server.preview_receive_until(ingress(Role::Client), &bytes, Tick(3), CAP),
            Err(Error::Admission(crate::Error::Capacity))
        ));
        assert_eq!(snapshot(&server), before);
        if byte_bound {
            server.gate.limits.max_retained_bytes = 16_384;
        } else {
            server.gate.limits.max_requests = 4;
        }
        assert!(
            server
                .preview_receive_until(ingress(Role::Client), &bytes, Tick(3), CAP)?
                .is_some()
        );
        assert!(matches!(
            server
                .receive_until(ingress(Role::Client), &bytes, Tick(3), CAP)?
                .event,
            Some(Event::Stage { .. })
        ));
    }
    Ok(())
}

#[test]
fn original_expiry_and_backward_time_are_readonly_then_actual_observation_is_terminal() -> Result {
    let (mut client, mut server) = pair()?;
    let bytes = prepare(&mut client)?;
    server.receive_until(ingress(Role::Client), &bytes, Tick(3), CAP)?;
    let repeated = rewrite(&bytes, |h, _| h.packet = PacketNumber(2))?;
    let before = snapshot(&server);
    for now in [CAP, Tick(1_001)] {
        assert!(matches!(
            server.preview_receive_until(ingress(Role::Client), &repeated, now, CAP),
            Err(Error::LeaseExpired)
        ));
        assert_eq!(snapshot(&server), before);
    }
    assert!(matches!(
        server.preview_receive_until(ingress(Role::Client), &repeated, Tick(2), CAP),
        Err(Error::Clock)
    ));
    assert!(matches!(
        server.preview_receive_until(ingress(Role::Client), &repeated, Tick(4), Tick(999)),
        Err(Error::LeaseConflict)
    ));
    assert_eq!(snapshot(&server), before);
    assert!(
        server
            .preview_receive_until(ingress(Role::Client), &repeated, Tick(999), CAP)?
            .is_none()
    );
    assert!(matches!(server.poll(CAP), Err(Error::LeaseExpired)));
    assert_eq!(server.phase(), Phase::Failed);
    assert_eq!(server.phase_deadline(), None);
    Ok(())
}

#[test]
fn first_reject_after_lost_prepare_has_no_preparation_but_starts_real_operation() -> Result {
    let (mut client, mut server) = pair()?;
    let _lost = prepare(&mut client)?;
    let reject = wire(client.poll(Tick(102))?)?;
    let before = snapshot(&server);
    assert!(
        server
            .preview_receive_until(ingress(Role::Client), &reject, Tick(103), CAP)?
            .is_none()
    );
    assert_eq!(snapshot(&server), before);
    assert!(matches!(
        server
            .receive_until(ingress(Role::Client), &reject, Tick(103), CAP)?
            .event,
        Some(Event::Aborted(1))
    ));
    assert_eq!(server.phase(), Phase::Idle);
    assert!(server.operation().is_some());
    assert_eq!(server.phase_deadline(), None);
    Ok(())
}

#[test]
fn phase_deadline_is_original_phase_cap_not_due_retry_and_does_not_spin_or_renew() -> Result {
    let (mut client, _) = pair()?;
    assert_eq!(client.phase_deadline(), None);
    prepare(&mut client)?;
    assert_eq!(client.next_deadline(), Some(Tick(12)));
    assert_eq!(client.phase_deadline(), Some(Tick(102)));
    let before = snapshot(&client);
    for _ in 0..8 {
        assert_eq!(client.phase_deadline(), Some(Tick(102)));
    }
    assert_eq!(snapshot(&client), before);
    let retry = client.poll(Tick(12))?;
    assert!(retry.outbound.is_some());
    assert_eq!(client.phase_deadline(), Some(Tick(102)));
    assert_eq!(client.next_deadline(), Some(Tick(22)));
    client.poll(Tick(102))?;
    assert_eq!(client.phase(), Phase::Aborting);
    assert_eq!(client.phase_deadline(), Some(Tick(202)));
    Ok(())
}

#[test]
fn preview_requires_explicit_lease_and_counter_overflow_never_changes_state() -> Result {
    let (initial, target) = (Policy::new(2, 3), Policy::new(4, 1));
    let legacy = Peer::new_directional(
        identity(Role::Client),
        Epoch(10),
        initial.clone(),
        &[initial.clone(), target.clone()],
        Settings::default(),
        Tick(0),
    )?;
    assert!(matches!(
        legacy.preview_propose_until(&target, Tick(1), CAP),
        Err(Error::LeaseRequired)
    ));
    assert!(matches!(
        legacy.preview_receive_until(ingress(Role::Server), &[], Tick(1), CAP),
        Err(Error::LeaseRequired)
    ));
    let (mut client, _) = pair()?;
    client.last_attempt = u64::MAX;
    let before = snapshot(&client);
    assert!(matches!(
        client.preview_propose_until(&target, Tick(1), CAP),
        Err(Error::Exhausted)
    ));
    assert_eq!(snapshot(&client), before);
    Ok(())
}
