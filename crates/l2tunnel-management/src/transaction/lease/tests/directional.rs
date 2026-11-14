//! Asymmetric global-sender fences preserve immutable leases and exact retries.

use super::*;
use crate::transaction::tests::directional::Policy;
use crate::transaction::{Configuration, Effects, Operation};

fn directional_pair(
    initial: Policy,
    target: Policy,
    directional: bool,
) -> Result<(Peer<Policy>, Peer<Policy>)> {
    let catalog = [initial.clone(), target];
    let make = |role| {
        if directional {
            Peer::new_leased_directional(
                identity(role),
                Epoch(1),
                initial.clone(),
                &catalog,
                settings(),
                lease(),
                Tick(0),
            )
        } else {
            Peer::new_leased(
                identity(role),
                Epoch(1),
                initial.clone(),
                &catalog,
                settings(),
                lease(),
                Tick(0),
            )
        }
    };
    Ok((make(Role::Client)?, make(Role::Server)?))
}
fn flight(effects: Effects<Policy>) -> Result<Vec<u8>> {
    effects.outbound.ok_or(Error::Unexpected)
}
fn local_fences() -> Result<(Fence, Fence)> {
    Ok((Fence::new(&[3, 5])?, Fence::new(&[7, 11, 13])?))
}
#[derive(Debug, Eq, PartialEq)]
struct Snapshot {
    phase: Phase,
    epoch: Epoch,
    active: Policy,
    operation: Option<Operation>,
    requests: usize,
    replies: usize,
    now: Tick,
    attempt: u64,
    request: u64,
    packet: u64,
    deadline: Tick,
    retry: Tick,
}
fn snapshot(peer: &Peer<Policy>) -> Snapshot {
    Snapshot {
        phase: peer.phase(),
        epoch: peer.active_epoch(),
        active: peer.active_config().clone(),
        operation: peer.operation(),
        requests: peer.retained_requests(),
        replies: peer.retained_replies(),
        now: peer.now,
        attempt: peer.last_attempt,
        request: peer.next_request,
        packet: peer.next_packet,
        deadline: peer.deadline,
        retry: peer.next_retry,
    }
}
fn fields(original: &[u8], skip: usize, replacement: &[u8]) -> Result<Vec<u8>> {
    let frame = Frame::decode(original, Limits::default()).map_err(Error::Admission)?;
    let mut body = frame.body.get(..skip).ok_or(Error::Malformed)?.to_vec();
    body.extend_from_slice(replacement);
    encoded(frame.header, &body)
}
fn counts(count: u16) -> Vec<u8> {
    let mut bytes = count.to_be_bytes().to_vec();
    for _ in 0..count {
        bytes.extend_from_slice(&0u64.to_be_bytes());
    }
    bytes
}
fn assert_original(peer: &Peer<Policy>, initial: &Policy, target: &Policy) -> Result {
    let operation = peer.operation().ok_or(Error::Unexpected)?;
    assert_eq!(operation.identity(), identity(operation.identity().role));
    assert_eq!(operation.expires(), EXPIRES);
    assert_eq!(operation.origin().epoch, Epoch(1));
    assert_eq!(operation.origin().digest, configuration_digest(initial)?);
    assert_eq!(operation.ticket().epoch, Epoch(2));
    assert_eq!(operation.ticket().digest, configuration_digest(target)?);
    assert!(
        peer.next_deadline()
            .is_some_and(|deadline| deadline <= EXPIRES)
    );
    Ok(())
}
fn begin_asymmetric(
    client: &mut Peer<Policy>,
    server: &mut Peer<Policy>,
    target: Policy,
    local: &Fence,
    remote: &Fence,
) -> Result<[Vec<u8>; 2]> {
    let started = client.propose_until(target.clone(), Tick(0), EXPIRES)?;
    assert!(matches!(started.event, Some(Event::Stage { config, .. }) if config == target));
    let prepare = flight(client.staged(local.clone(), Tick(1))?)?;
    server.validate_receive_until(ingress(Role::Client), &prepare, Tick(2), EXPIRES)?;
    let staged = server.receive_until(ingress(Role::Client), &prepare, Tick(2), EXPIRES)?;
    assert!(matches!(staged.event, Some(Event::Stage { config, .. }) if config == target));
    let ready = server.staged(remote.clone(), Tick(3))?;
    assert_eq!(
        ready.event,
        Some(Event::Drain {
            local: remote.clone(),
            peer: local.clone()
        })
    );
    let ready = flight(ready)?;
    assert_eq!(
        client
            .receive_until(ingress(Role::Server), &ready, Tick(4), EXPIRES)?
            .event,
        Some(Event::Drain {
            local: local.clone(),
            peer: remote.clone()
        })
    );
    Ok([prepare, ready])
}
fn finish_asymmetric(
    client: &mut Peer<Policy>,
    server: &mut Peer<Policy>,
    local: &Fence,
    remote: &Fence,
) -> Result<[Vec<u8>; 2]> {
    let barrier = flight(client.confirm_drained(local, remote, Tick(5))?)?;
    assert!(
        server
            .receive_until(ingress(Role::Client), &barrier, Tick(6), EXPIRES)?
            .outbound
            .is_none()
    );
    let barrier_ack = flight(server.confirm_drained(remote, local, Tick(7))?)?;
    let commit =
        flight(client.receive_until(ingress(Role::Server), &barrier_ack, Tick(8), EXPIRES)?)?;
    let committed = server.receive_until(ingress(Role::Client), &commit, Tick(9), EXPIRES)?;
    assert!(matches!(committed.event, Some(Event::Committed(_))));
    let retire = flight(client.receive_until(
        ingress(Role::Server),
        &flight(committed)?,
        Tick(10),
        EXPIRES,
    )?)?;
    let retired = server.receive_until(ingress(Role::Client), &retire, Tick(11), EXPIRES)?;
    assert_eq!(retired.event, Some(Event::Retired(Epoch(1))));
    let reply = flight(retired)?;
    assert_eq!(
        client
            .receive_until(ingress(Role::Server), &reply, Tick(12), EXPIRES)?
            .event,
        Some(Event::Retired(Epoch(1)))
    );
    Ok([retire, reply])
}

#[test]
fn leased_asymmetric_full_exchange_retains_original_origin_and_final_custody() -> Result {
    let initial = Policy::new(2, 3);
    let target = Policy::new(4, 1);
    let (mut client, mut server) = directional_pair(initial.clone(), target.clone(), true)?;
    let (local, remote) = local_fences()?;
    begin_asymmetric(&mut client, &mut server, target.clone(), &local, &remote)?;
    for peer in [&client, &server] {
        assert_original(peer, &initial, &target)?;
    }
    finish_asymmetric(&mut client, &mut server, &local, &remote)?;
    for peer in [&client, &server] {
        assert_original(peer, &initial, &target)?;
        assert_eq!(peer.active_config(), &target);
        assert_eq!(peer.sender_channels(Role::Client), 4);
        assert_eq!(peer.sender_channels(Role::Server), 1);
        assert_eq!(peer.phase(), Phase::Idle);
        // A lifecycle event alone does not release whole-message custody.
        assert!(!peer.can_admit_data());
        assert!(peer.reader(Epoch(1)).is_none());
    }
    assert!(client.cached_retry_authority(Tick(12))?.is_none());
    let cached = server
        .cached_retry_authority(Tick(12))?
        .ok_or(Error::Unexpected)?;
    assert_eq!(
        cached.operation().origin().digest,
        configuration_digest(&initial)?
    );
    assert_eq!(cached.request().header.kind, MessageKind::Retire);
    assert_eq!(cached.reply_kind(), MessageKind::Retire);
    assert_eq!(
        client.propose_until(initial, Tick(13), EXPIRES),
        Err(Error::Busy)
    );
    Ok(())
}

#[test]
fn leased_legacy_constructor_ignores_overridden_sender_widths() -> Result {
    let initial = Policy::new(0, 257);
    let target = Policy::new(257, 0);
    let (mut client, mut server) = directional_pair(initial.clone(), target.clone(), false)?;
    let local = Fence::new(&[3, 5])?;
    let remote = Fence::new(&[7, 11])?;
    begin_asymmetric(&mut client, &mut server, target.clone(), &local, &remote)?;
    finish_asymmetric(&mut client, &mut server, &local, &remote)?;
    for peer in [&client, &server] {
        assert_eq!(peer.sender_channels(Role::Client), 2);
        assert_eq!(peer.sender_channels(Role::Server), 2);
        assert_original(peer, &initial, &target)?;
    }
    Ok(())
}

#[test]
fn first_directional_prepare_preflight_rejects_wrong_width_without_mutation() -> Result {
    let initial = Policy::new(2, 3);
    let target = Policy::new(4, 1);
    let (mut client, mut server) = directional_pair(initial.clone(), target, true)?;
    client.propose_until(Policy::new(4, 1), Tick(0), EXPIRES)?;
    let prepare = flight(client.staged(local_fences()?.0, Tick(0))?)?;
    for count in [0, 1, 3, 4, 257] {
        let wrong = fields(&prepare, 8 + Policy::ENCODED_LEN, &counts(count))?;
        let before = snapshot(&server);
        assert_eq!(
            server.validate_receive_until(ingress(Role::Client), &wrong, Tick(20), EXPIRES),
            Err(Error::Malformed)
        );
        assert_eq!(snapshot(&server), before);
        assert_eq!(
            server.receive_until(ingress(Role::Client), &wrong, Tick(20), EXPIRES),
            Err(Error::Malformed)
        );
        assert_eq!(snapshot(&server), before);
    }
    let old = crate::session_control::Scope {
        epoch: Epoch(1),
        digest: configuration_digest(&initial)?,
    };
    assert_eq!(
        server.validate_control_origin(ingress(Role::Client), &prepare, old, Tick(20)),
        Ok(false)
    );
    assert_eq!(server.now, Tick(0));
    // The same unconsumed packet still starts the operation at the original time.
    assert!(matches!(
        server
            .receive_until(ingress(Role::Client), &prepare, Tick(0), EXPIRES)?
            .event,
        Some(Event::Stage { .. })
    ));
    let ready = flight(server.staged(local_fences()?.1, Tick(1))?)?;
    let frame = Frame::decode(&ready, Limits::default()).map_err(Error::Admission)?;
    assert_eq!(frame.header.request.0, 1);
    assert_eq!(frame.header.packet.0, 1);
    Ok(())
}

#[test]
fn first_directional_target_digest_cap_and_binding_checks_are_atomic() -> Result {
    let initial = Policy::new(2, 3);
    let target = Policy::new(4, 1);
    let alternate = Policy::new(5, 1);
    let (mut client, _) = directional_pair(initial.clone(), target.clone(), true)?;
    let mut server = Peer::new_leased_directional(
        identity(Role::Server),
        Epoch(1),
        initial.clone(),
        &[initial.clone(), target.clone(), alternate.clone()],
        settings(),
        lease(),
        Tick(0),
    )?;
    client.propose_until(target.clone(), Tick(0), EXPIRES)?;
    let prepare = flight(client.staged(local_fences()?.0, Tick(0))?)?;
    let frame = Frame::decode(&prepare, Limits::default()).map_err(Error::Admission)?;
    let mut canonical = vec![0; Policy::ENCODED_LEN];
    alternate.encode_into(&mut canonical)?;
    canonical.extend_from_slice(&frame.body[8 + Policy::ENCODED_LEN..]);
    let wrong_digest = fields(&prepare, 8, &canonical)?;
    let before = snapshot(&server);
    assert_eq!(
        server.validate_receive_until(ingress(Role::Client), &wrong_digest, Tick(20), EXPIRES),
        Err(Error::Unexpected)
    );
    assert_eq!(
        server.receive_until(ingress(Role::Client), &wrong_digest, Tick(20), EXPIRES),
        Err(Error::Unexpected)
    );
    assert_eq!(snapshot(&server), before);
    for invalid in [
        Policy::new(0, 1),
        Policy::new(257, 1),
        Policy::new(4, 0),
        Policy::new(4, 257),
    ] {
        let mut body = frame.body.to_vec();
        invalid.encode_into(&mut body[8..8 + Policy::ENCODED_LEN])?;
        let wrong = encoded(
            Header {
                ticket: l2tunnel_session::Ticket {
                    digest: configuration_digest(&invalid)?,
                    ..frame.header.ticket
                },
                ..frame.header
            },
            &body,
        )?;
        assert!(matches!(
            server.validate_receive_until(ingress(Role::Client), &wrong, Tick(20), EXPIRES),
            Err(Error::Configuration(_))
        ));
        assert!(matches!(
            server.receive_until(ingress(Role::Client), &wrong, Tick(20), EXPIRES),
            Err(Error::Configuration(_))
        ));
        assert_eq!(snapshot(&server), before);
    }
    let wrong_ingress = Ingress::AuthenticatedManagement {
        sender: Role::Server,
        session: identity(Role::Client).session,
        lane: identity(Role::Client).lane,
    };
    assert!(matches!(
        server.validate_receive_until(wrong_ingress, &prepare, Tick(20), EXPIRES),
        Err(Error::Admission(crate::Error::BindingMismatch))
    ));
    assert_eq!(snapshot(&server), before);
    server.receive_until(ingress(Role::Client), &prepare, Tick(0), EXPIRES)?;
    let admitted = snapshot(&server);
    for cap in [Tick(999), Tick(1_001)] {
        assert_eq!(
            server.validate_receive_until(
                ingress(Role::Client),
                &fresh(&prepare, 2)?,
                Tick(20),
                cap
            ),
            Err(Error::LeaseConflict)
        );
        assert_eq!(
            server.receive_until(ingress(Role::Client), &fresh(&prepare, 2)?, Tick(20), cap),
            Err(Error::LeaseConflict)
        );
        assert_eq!(snapshot(&server), admitted);
    }
    assert_eq!(
        server.receive_until(
            ingress(Role::Client),
            &fresh(&prepare, 2)?,
            Tick(1),
            EXPIRES
        )?,
        Effects::default()
    );
    Ok(())
}

#[test]
fn actual_retries_keep_old_directional_facts_across_prepare_commit_and_retire() -> Result {
    let initial = Policy::new(2, 3);
    let target = Policy::new(4, 1);
    let (mut client, mut server) = directional_pair(initial.clone(), target.clone(), true)?;
    let (local, remote) = local_fences()?;
    client.propose_until(target.clone(), Tick(0), EXPIRES)?;
    let prepare = flight(client.staged(local.clone(), Tick(0))?)?;
    server.receive_until(ingress(Role::Client), &prepare, Tick(0), EXPIRES)?;
    let lost_ready = flight(server.staged(remote.clone(), Tick(0))?)?;
    let original = Frame::decode(&prepare, Limits::default()).map_err(Error::Admission)?;
    let mut altered_fence = original.body.to_vec();
    let last = altered_fence.last_mut().ok_or(Error::Malformed)?;
    *last ^= 1;
    let changed = encoded(
        Header {
            packet: PacketNumber(2),
            ..original.header
        },
        &altered_fence,
    )?;
    let before = snapshot(&server);
    let old_origin = server.operation().ok_or(Error::Unexpected)?.origin();
    assert_eq!(
        server.validate_receive_until(ingress(Role::Client), &changed, Tick(1), EXPIRES),
        Err(Error::Custody)
    );
    assert_eq!(
        server.validate_control_origin(ingress(Role::Client), &changed, old_origin, Tick(1)),
        Err(Error::Custody)
    );
    assert_eq!(snapshot(&server), before);
    let repeated_prepare = flight(client.poll(Tick(10))?)?;
    let old_prepare = Frame::decode(&prepare, Limits::default()).map_err(Error::Admission)?;
    let new_prepare =
        Frame::decode(&repeated_prepare, Limits::default()).map_err(Error::Admission)?;
    assert!(old_prepare.header.same_request(new_prepare.header));
    assert_eq!(old_prepare.body, new_prepare.body);
    assert!(new_prepare.header.packet > old_prepare.header.packet);
    let cached =
        server.receive_until(ingress(Role::Client), &repeated_prepare, Tick(10), EXPIRES)?;
    assert!(cached.event.is_none());
    let recovered_ready = flight(cached)?;
    assert_eq!(
        client
            .receive_until(ingress(Role::Server), &recovered_ready, Tick(10), EXPIRES)?
            .event,
        Some(Event::Drain {
            local: local.clone(),
            peer: remote.clone()
        })
    );
    assert!(matches!(
        client.receive_until(ingress(Role::Server), &lost_ready, Tick(10), EXPIRES),
        Err(Error::Admission(crate::Error::RequestRetired))
    ));
    let barrier = flight(client.confirm_drained(&local, &remote, Tick(10))?)?;
    server.receive_until(ingress(Role::Client), &barrier, Tick(10), EXPIRES)?;
    let repeated_barrier = flight(client.poll(Tick(20))?)?;
    assert_eq!(
        server.receive_until(ingress(Role::Client), &repeated_barrier, Tick(20), EXPIRES)?,
        Effects::default()
    );
    let barrier_ack = flight(server.confirm_drained(&remote, &local, Tick(20))?)?;
    let commit =
        flight(client.receive_until(ingress(Role::Server), &barrier_ack, Tick(20), EXPIRES)?)?;
    let committed = server.receive_until(ingress(Role::Client), &commit, Tick(20), EXPIRES)?;
    assert!(matches!(committed.event, Some(Event::Committed(_))));
    let lost_commit_ack = flight(committed)?;
    let repeated_commit = flight(client.poll(Tick(30))?)?;
    let committed_again =
        server.receive_until(ingress(Role::Client), &repeated_commit, Tick(30), EXPIRES)?;
    assert!(committed_again.event.is_none());
    let retire = flight(client.receive_until(
        ingress(Role::Server),
        &flight(committed_again)?,
        Tick(30),
        EXPIRES,
    )?)?;
    assert!(matches!(
        client.receive_until(ingress(Role::Server), &lost_commit_ack, Tick(30), EXPIRES),
        Err(Error::Admission(crate::Error::RequestRetired))
    ));
    let retired = server.receive_until(ingress(Role::Client), &retire, Tick(30), EXPIRES)?;
    assert_eq!(retired.event, Some(Event::Retired(Epoch(1))));
    let lost_retire_ack = flight(retired)?;
    assert_eq!(server.sender_channels(Role::Client), 4);
    assert_eq!(server.sender_channels(Role::Server), 1);
    let repeated_retire = flight(client.poll(Tick(40))?)?;
    let retired_again =
        server.receive_until(ingress(Role::Client), &repeated_retire, Tick(40), EXPIRES)?;
    assert!(retired_again.event.is_none());
    let final_ack = flight(retired_again)?;
    assert_eq!(
        client
            .receive_until(ingress(Role::Server), &final_ack, Tick(40), EXPIRES)?
            .event,
        Some(Event::Retired(Epoch(1)))
    );
    assert_eq!(
        client.receive_until(ingress(Role::Server), &lost_retire_ack, Tick(40), EXPIRES)?,
        Effects::default()
    );
    for peer in [&client, &server] {
        assert_original(peer, &initial, &target)?;
    }
    Ok(())
}

#[test]
fn final_cached_retry_checks_exact_old_origin_body_binding_and_original_expiry() -> Result {
    let initial = Policy::new(2, 3);
    let target = Policy::new(4, 1);
    let (mut client, mut server) = directional_pair(initial.clone(), target.clone(), true)?;
    let (local, remote) = local_fences()?;
    begin_asymmetric(&mut client, &mut server, target.clone(), &local, &remote)?;
    let [retire, reply] = finish_asymmetric(&mut client, &mut server, &local, &remote)?;
    let old = server.operation().ok_or(Error::Unexpected)?.origin();
    let late = fresh(&retire, 100)?;
    let before = snapshot(&server);
    assert_eq!(
        server.validate_control_origin(ingress(Role::Client), &late, old, Tick(999)),
        Ok(true)
    );
    assert_eq!(
        server.validate_receive_until(ingress(Role::Client), &late, Tick(999), EXPIRES),
        Ok(())
    );
    assert_eq!(snapshot(&server), before);
    let wrong_scope = crate::session_control::Scope {
        epoch: Epoch(2),
        digest: configuration_digest(&target)?,
    };
    assert_eq!(
        server.validate_control_origin(ingress(Role::Client), &late, wrong_scope, Tick(999)),
        Err(Error::Custody)
    );
    let frame = Frame::decode(&late, Limits::default()).map_err(Error::Admission)?;
    let mut body = frame.body.to_vec();
    body[7] = 1;
    let changed = encoded(frame.header, &body)?;
    assert_eq!(
        server.validate_receive_until(ingress(Role::Client), &changed, Tick(999), EXPIRES),
        Err(Error::Custody)
    );
    assert_eq!(
        server.validate_control_origin(ingress(Role::Client), &changed, old, Tick(999)),
        Err(Error::Custody)
    );
    for wrong in [
        Header {
            request: crate::RequestId(99),
            ..frame.header
        },
        Header {
            kind: MessageKind::Commit,
            ..frame.header
        },
    ] {
        assert_eq!(
            server.validate_receive_until(
                ingress(Role::Client),
                &encoded(wrong, frame.body)?,
                Tick(999),
                EXPIRES
            ),
            Err(Error::Custody)
        );
    }
    let wrong_ingress = Ingress::AuthenticatedManagement {
        session: SessionId([0x32; 16]),
        lane: identity(Role::Client).lane,
        sender: Role::Client,
    };
    assert!(matches!(
        server.validate_control_origin(wrong_ingress, &late, old, Tick(999)),
        Err(Error::Admission(crate::Error::BindingMismatch))
    ));
    assert_eq!(snapshot(&server), before);
    let cached = server
        .cached_retry_authority(Tick(999))?
        .ok_or(Error::Unexpected)?;
    assert!(cached.request().header.same_request(frame.header));
    assert_eq!(cached.request().body, frame.body);
    assert_eq!(cached.operation().origin(), old);
    let context = server.outbound_context(&reply)?;
    assert_eq!(context.origin(), old);
    assert_eq!(context.expires(), EXPIRES);
    assert!(context.is_final_reply());
    // Exact final incoming authority is retained independently at the client.
    assert_eq!(
        client.validate_control_origin(ingress(Role::Server), &fresh(&reply, 100)?, old, Tick(999)),
        Ok(true)
    );
    for at in [EXPIRES, Tick(1_001)] {
        assert!(matches!(
            server.cached_retry_authority(at),
            Err(Error::LeaseExpired)
        ));
        assert_eq!(
            server.validate_receive_until(ingress(Role::Client), &late, at, EXPIRES),
            Err(Error::LeaseExpired)
        );
        assert_eq!(snapshot(&server), before);
    }
    let cached_reply = server.receive_until(ingress(Role::Client), &late, Tick(999), EXPIRES)?;
    assert!(cached_reply.event.is_none());
    assert!(cached_reply.outbound.is_some());
    assert_eq!(
        server.operation().ok_or(Error::Unexpected)?.expires(),
        EXPIRES
    );
    assert_eq!(server.poll(EXPIRES), Err(Error::LeaseExpired));
    assert_eq!(server.phase(), Phase::Failed);
    assert_eq!(server.next_deadline(), None);
    assert_eq!(server.poll(Tick(1_001)), Err(Error::LeaseExpired));
    Ok(())
}

#[test]
fn leased_directional_local_invalid_policy_and_constructor_checks_do_not_burn_ids() -> Result {
    let initial = Policy::new(2, 3);
    let target = Policy::new(4, 1);
    let (mut client, _) = directional_pair(initial.clone(), target.clone(), true)?;
    for invalid in [
        Policy::new(0, 3),
        Policy::new(257, 3),
        Policy::new(2, 0),
        Policy::new(2, 257),
    ] {
        assert!(matches!(
            Peer::new_leased_directional(
                identity(Role::Server),
                Epoch(1),
                initial.clone(),
                &[initial.clone(), invalid.clone()],
                settings(),
                lease(),
                Tick(0)
            ),
            Err(Error::Configuration(_))
        ));
        let before = snapshot(&client);
        assert!(matches!(
            client.propose_until(invalid, Tick(0), EXPIRES),
            Err(Error::Configuration(_))
        ));
        assert_eq!(snapshot(&client), before);
    }
    client.propose_until(target, Tick(0), EXPIRES)?;
    let prepare = flight(client.staged(local_fences()?.0, Tick(0))?)?;
    let header = Frame::decode(&prepare, Limits::default())
        .map_err(Error::Admission)?
        .header;
    assert_eq!(header.ticket.attempt, 1);
    assert_eq!(header.request.0, 1);
    assert_eq!(header.packet.0, 1);
    for directional in [false, true] {
        let zero_session = Identity {
            session: SessionId([0; 16]),
            ..identity(Role::Server)
        };
        let construct = |who, epoch| {
            if directional {
                Peer::new_leased_directional(
                    who,
                    epoch,
                    initial.clone(),
                    std::slice::from_ref(&initial),
                    settings(),
                    lease(),
                    Tick(0),
                )
            } else {
                Peer::new_leased(
                    who,
                    epoch,
                    initial.clone(),
                    std::slice::from_ref(&initial),
                    settings(),
                    lease(),
                    Tick(0),
                )
            }
        };
        assert!(matches!(
            construct(zero_session, Epoch(1)),
            Err(Error::Configuration("invalid operation lease"))
        ));
        assert!(matches!(
            construct(identity(Role::Server), Epoch(0)),
            Err(Error::Configuration("invalid operation lease"))
        ));
    }
    Ok(())
}

#[test]
fn missing_asymmetric_prepare_still_allows_exact_eight_byte_first_reject() -> Result {
    let initial = Policy::new(2, 3);
    let target = Policy::new(4, 1);
    let (mut client, mut server) = directional_pair(initial.clone(), target.clone(), true)?;
    let expires = Tick(3_000);
    client.propose_until(target, Tick(0), expires)?;
    let lost = flight(client.staged(local_fences()?.0, Tick(0))?)?;
    let reject = flight(client.poll(Tick(1_000))?)?;
    let frame = Frame::decode(&reject, Limits::default()).map_err(Error::Admission)?;
    assert_eq!(frame.header.kind, MessageKind::Reject);
    assert_eq!(frame.body, &0u64.to_be_bytes());
    let before = snapshot(&server);
    server.validate_receive_until(ingress(Role::Client), &reject, Tick(1_000), expires)?;
    assert_eq!(snapshot(&server), before);
    let rejected = server.receive_until(ingress(Role::Client), &reject, Tick(1_000), expires)?;
    assert_eq!(rejected.event, Some(Event::Aborted(1)));
    let reply = flight(rejected)?;
    assert_eq!(
        client
            .receive_until(ingress(Role::Server), &reply, Tick(1_001), expires)?
            .event,
        Some(Event::Aborted(1))
    );
    for peer in [&client, &server] {
        assert_eq!(peer.active_config(), &initial);
        assert_eq!(peer.sender_channels(Role::Client), 2);
        assert_eq!(peer.sender_channels(Role::Server), 3);
        let operation = peer.operation().ok_or(Error::Unexpected)?;
        assert_eq!(operation.expires(), expires);
        assert_eq!(operation.origin().digest, configuration_digest(&initial)?);
        assert!(!peer.can_admit_data());
    }
    assert!(matches!(
        server.validate_receive_until(
            ingress(Role::Client),
            &fresh(&lost, 100)?,
            Tick(1_002),
            expires
        ),
        Err(Error::Admission(crate::Error::RequestRetired))
    ));
    Ok(())
}
