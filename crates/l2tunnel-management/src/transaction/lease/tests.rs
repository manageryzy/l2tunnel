//! Genuine two-peer regression cases for the explicitly leased transaction contract.

use crate::transaction::{
    Error, Event, Fence, Identity, LeaseSettings, Peer, Phase, ReadDisposition, Settings, Tick,
    configuration_digest,
};
use crate::{
    EndpointId, Frame, Header, Ingress, LaneId, Limits, MessageKind, PacketNumber, Role, SessionId,
};
use l2tunnel_core::{Delivery, Epoch, Mapping, ModeConfig, RecordLayout};

type Result<T = ()> = std::result::Result<T, Error>;

const EXPIRES: Tick = Tick(1_000);

fn policies() -> (ModeConfig, ModeConfig) {
    let initial = ModeConfig {
        channels: 2,
        ..ModeConfig::default()
    };
    let next = ModeConfig {
        channels: 3,
        mapping: Mapping::Crc32,
        records: RecordLayout::Packed,
        delivery: Delivery::IndependentShort,
        ..initial.clone()
    };
    (initial, next)
}

fn identity(role: Role) -> Identity {
    Identity {
        session: SessionId([0x31; 16]),
        role,
        local: EndpointId(if role == Role::Client { 11 } else { 22 }),
        remote: EndpointId(if role == Role::Client { 22 } else { 11 }),
        lane: LaneId(7),
    }
}

fn ingress(sender: Role) -> Ingress {
    Ingress::AuthenticatedManagement {
        session: identity(sender).session,
        lane: identity(sender).lane,
        sender,
    }
}

fn lease() -> LeaseSettings {
    LeaseSettings {
        session_expires: Tick(10_000),
        max_operation_ms: 5_000,
        transaction_epoch: 1,
    }
}

fn settings() -> Settings {
    Settings {
        retry_ms: 10,
        phase_timeout_ms: 1_000,
        reconcile_timeout_ms: 2_000,
    }
}

fn endpoint(role: Role) -> Result<Peer> {
    let (initial, next) = policies();
    Peer::new_leased(
        identity(role),
        Epoch(1),
        initial.clone(),
        &[initial, next],
        settings(),
        lease(),
        Tick(0),
    )
}

fn pair() -> Result<(Peer, Peer)> {
    Ok((endpoint(Role::Client)?, endpoint(Role::Server)?))
}

fn wire(effects: crate::transaction::Effects) -> Result<Vec<u8>> {
    effects.outbound.ok_or(Error::Unexpected)
}

fn fences() -> Result<(Fence, Fence)> {
    Ok((Fence::new(&[3, 5])?, Fence::new(&[9, 7])?))
}

fn begin(client: &mut Peer, server: &mut Peer, now: Tick) -> Result<(Fence, Fence)> {
    let (_, next) = policies();
    let (local, remote) = fences()?;
    assert!(matches!(
        client.propose_until(next, now, EXPIRES)?.event,
        Some(Event::Stage { .. })
    ));
    let prepare = wire(client.staged(local.clone(), now)?)?;
    assert!(matches!(
        server
            .receive_until(ingress(Role::Client), &prepare, now, EXPIRES)?
            .event,
        Some(Event::Stage { .. })
    ));
    let ready = wire(server.staged(remote.clone(), now)?)?;
    assert!(matches!(
        client
            .receive_until(ingress(Role::Server), &ready, now, EXPIRES)?
            .event,
        Some(Event::Drain { .. })
    ));
    Ok((local, remote))
}

fn commit_ready(client: &mut Peer, server: &mut Peer, now: Tick) -> Result<Vec<u8>> {
    let (local, remote) = begin(client, server, now)?;
    let barrier = wire(client.confirm_drained(&local, &remote, now)?)?;
    assert!(
        server
            .receive_until(ingress(Role::Client), &barrier, now, EXPIRES)?
            .outbound
            .is_none()
    );
    let acknowledged = wire(server.confirm_drained(&remote, &local, now)?)?;
    wire(client.receive_until(ingress(Role::Server), &acknowledged, now, EXPIRES)?)
}

fn retire_ready(client: &mut Peer, server: &mut Peer, now: Tick) -> Result<Vec<u8>> {
    let commit = commit_ready(client, server, now)?;
    let acknowledged = server.receive_until(ingress(Role::Client), &commit, now, EXPIRES)?;
    assert!(matches!(acknowledged.event, Some(Event::Committed(_))));
    let retire = client.receive_until(ingress(Role::Server), &wire(acknowledged)?, now, EXPIRES)?;
    assert!(matches!(retire.event, Some(Event::Committed(_))));
    wire(retire)
}

fn encoded(header: Header, body: &[u8]) -> Result<Vec<u8>> {
    let mut bytes = vec![0; crate::HEADER_LEN + body.len()];
    Frame { header, body }
        .encode(&mut bytes, Limits::default())
        .map_err(Error::Admission)?;
    Ok(bytes)
}

fn fresh(bytes: &[u8], packet: u64) -> Result<Vec<u8>> {
    let frame = Frame::decode(bytes, Limits::default()).map_err(Error::Admission)?;
    encoded(
        Header {
            packet: PacketNumber(packet),
            ..frame.header
        },
        frame.body,
    )
}

fn observation(peer: &Peer) -> (Phase, Epoch, usize, usize, Option<Tick>) {
    (
        peer.phase(),
        peer.active_epoch(),
        peer.retained_requests(),
        peer.retained_replies(),
        peer.operation().map(|operation| operation.expires()),
    )
}

fn assert_operation(peer: &Peer, expires: Tick) -> Result {
    let operation = peer.operation().ok_or(Error::Unexpected)?;
    assert_eq!(operation.expires(), expires);
    assert_eq!(operation.identity(), identity(operation.identity().role));
    assert_eq!(operation.origin().epoch, Epoch(1));
    assert_eq!(
        operation.origin().digest,
        configuration_digest(&policies().0)?
    );
    assert_eq!(operation.ticket().epoch, Epoch(2));
    assert_eq!(
        operation.ticket().digest,
        configuration_digest(&policies().1)?
    );
    assert_ne!(operation.origin().digest, operation.ticket().digest);
    assert!(
        peer.next_deadline()
            .is_some_and(|deadline| deadline <= expires)
    );
    Ok(())
}

#[test]
fn leased_contract_requires_explicit_caps_without_consuming_initial_ids() -> Result {
    let (mut client, mut server) = pair()?;
    let (_, next) = policies();
    assert!(client.is_leased());
    assert_eq!(
        client.propose(next.clone(), Tick(0)),
        Err(Error::LeaseRequired)
    );
    assert!(client.operation().is_none());
    for expires in [Tick(0), Tick(5_001), Tick(10_001)] {
        assert!(matches!(
            client.propose_until(next.clone(), Tick(0), expires),
            Err(Error::Configuration(_))
        ));
        assert!(client.operation().is_none());
        assert_eq!(client.phase(), Phase::Idle);
        assert_eq!(client.retained_requests(), 0);
    }
    let started = client.propose_until(next, Tick(0), EXPIRES)?;
    let Some(Event::Stage { ticket, .. }) = started.event else {
        return Err(Error::Unexpected);
    };
    assert_eq!(ticket.attempt, 1);
    let prepare = wire(client.staged(fences()?.0, Tick(0))?)?;
    let frame = Frame::decode(&prepare, Limits::default()).map_err(Error::Admission)?;
    assert_eq!(frame.header.request.0, 1);
    assert_eq!(frame.header.packet.0, 1);
    assert_eq!(
        server.receive(ingress(Role::Client), &prepare, Tick(0)),
        Err(Error::LeaseRequired)
    );
    assert!(server.operation().is_none());
    assert_eq!(server.retained_requests(), 0);
    for expires in [Tick(0), Tick(5_001), Tick(10_001)] {
        let before = observation(&server);
        assert!(matches!(
            server.validate_receive_until(ingress(Role::Client), &prepare, Tick(0), expires),
            Err(Error::Configuration(_))
        ));
        assert_eq!(observation(&server), before);
        assert!(matches!(
            server.receive_until(ingress(Role::Client), &prepare, Tick(0), expires),
            Err(Error::Configuration(_))
        ));
        assert_eq!(observation(&server), before);
    }
    assert!(matches!(
        server
            .receive_until(ingress(Role::Client), &prepare, Tick(0), EXPIRES)?
            .event,
        Some(Event::Stage { .. })
    ));
    Ok(())
}

#[test]
fn staging_and_drain_check_original_expiry_without_an_intervening_poll() -> Result {
    for at in [Tick(999), Tick(1_000), Tick(1_001)] {
        let mut client = endpoint(Role::Client)?;
        client.propose_until(policies().1, Tick(0), EXPIRES)?;
        let result = client.staged(fences()?.0, at);
        if at < EXPIRES {
            assert!(result?.outbound.is_some());
            assert_eq!(client.phase(), Phase::AwaitReady);
        } else {
            assert_eq!(result, Err(Error::LeaseExpired));
            assert_eq!(client.phase(), Phase::Failed);
            assert!(client.reader(Epoch(1)).is_none());
            assert!(!client.can_admit_data());
        }
        let (mut client, mut server) = pair()?;
        let (local, remote) = begin(&mut client, &mut server, Tick(0))?;
        let result = client.confirm_drained(&local, &remote, at);
        if at < EXPIRES {
            assert!(result?.outbound.is_some());
            assert_eq!(client.phase(), Phase::AwaitBarrier);
        } else {
            assert_eq!(result, Err(Error::LeaseExpired));
            assert_eq!(client.phase(), Phase::Failed);
            assert_eq!(client.active_epoch(), Epoch(1));
            assert_eq!(server.active_epoch(), Epoch(1));
        }
    }
    Ok(())
}

#[test]
fn late_commit_and_retire_cannot_apply_before_the_expiry_poll() -> Result {
    for at in [Tick(999), Tick(1_000), Tick(1_001)] {
        let (mut client, mut server) = pair()?;
        let commit = commit_ready(&mut client, &mut server, Tick(0))?;
        assert_eq!(server.active_epoch(), Epoch(1));
        let result = server.receive_until(ingress(Role::Client), &commit, at, EXPIRES);
        if at < EXPIRES {
            assert!(matches!(result?.event, Some(Event::Committed(_))));
            assert_eq!(server.active_epoch(), Epoch(2));
        } else {
            assert_eq!(result, Err(Error::LeaseExpired));
            assert_eq!(server.phase(), Phase::Failed);
            assert_eq!(server.active_epoch(), Epoch(1));
        }
        let (mut client, mut server) = pair()?;
        let retire = retire_ready(&mut client, &mut server, Tick(0))?;
        assert_eq!(client.active_epoch(), Epoch(2));
        assert_eq!(server.active_epoch(), Epoch(2));
        let result = server.receive_until(ingress(Role::Client), &retire, at, EXPIRES);
        if at < EXPIRES {
            assert_eq!(result?.event, Some(Event::Retired(Epoch(1))));
        } else {
            assert_eq!(result, Err(Error::LeaseExpired));
            assert_eq!(server.phase(), Phase::Failed);
            assert_eq!(server.active_epoch(), Epoch(2));
            assert_eq!(client.active_epoch(), Epoch(2));
            assert!(server.reader(Epoch(1)).is_none());
        }
    }
    Ok(())
}

#[test]
fn phase_progress_and_fresh_packet_retries_never_extend_the_operation() -> Result {
    let (mut client, mut server) = pair()?;
    let (local, remote) = fences()?;
    let event = client.propose_until(policies().1, Tick(0), EXPIRES)?.event;
    assert!(matches!(event, Some(Event::Stage { .. })));
    assert_operation(&client, EXPIRES)?;
    let prepare = wire(client.staged(local.clone(), Tick(100))?)?;
    assert_operation(&client, EXPIRES)?;
    let staged = server.receive_until(ingress(Role::Client), &prepare, Tick(200), EXPIRES)?;
    assert!(matches!(staged.event, Some(Event::Stage { .. })));
    assert_operation(&server, EXPIRES)?;
    let retried_prepare = wire(client.poll(Tick(210))?)?;
    let duplicate =
        server.receive_until(ingress(Role::Client), &retried_prepare, Tick(210), EXPIRES)?;
    assert_eq!(duplicate, crate::transaction::Effects::default());
    let ready = wire(server.staged(remote.clone(), Tick(300))?)?;
    assert!(matches!(
        client
            .receive_until(ingress(Role::Server), &ready, Tick(400), EXPIRES)?
            .event,
        Some(Event::Drain { .. })
    ));
    assert_operation(&client, EXPIRES)?;
    let barrier = wire(client.confirm_drained(&local, &remote, Tick(500))?)?;
    server.receive_until(ingress(Role::Client), &barrier, Tick(600), EXPIRES)?;
    let barrier_ack = wire(server.confirm_drained(&remote, &local, Tick(700))?)?;
    let commit =
        wire(client.receive_until(ingress(Role::Server), &barrier_ack, Tick(800), EXPIRES)?)?;
    assert_eq!(
        client
            .reader(Epoch(2))
            .ok_or(Error::Unexpected)?
            .disposition,
        ReadDisposition::Staged
    );
    let committed = server.receive_until(ingress(Role::Client), &commit, Tick(850), EXPIRES)?;
    assert!(matches!(committed.event, Some(Event::Committed(_))));
    let duplicate_commit = fresh(&commit, 100)?;
    let repeated =
        server.receive_until(ingress(Role::Client), &duplicate_commit, Tick(860), EXPIRES)?;
    assert!(repeated.event.is_none());
    assert!(repeated.outbound.is_some());
    assert_operation(&server, EXPIRES)?;
    let committed =
        client.receive_until(ingress(Role::Server), &wire(committed)?, Tick(900), EXPIRES)?;
    assert!(matches!(committed.event, Some(Event::Committed(_))));
    let retire = wire(committed)?;
    let retired = server.receive_until(ingress(Role::Client), &retire, Tick(950), EXPIRES)?;
    assert_eq!(retired.event, Some(Event::Retired(Epoch(1))));
    let duplicate_retire = fresh(&retire, 101)?;
    let repeated =
        server.receive_until(ingress(Role::Client), &duplicate_retire, Tick(960), EXPIRES)?;
    assert!(repeated.event.is_none());
    assert!(repeated.outbound.is_some());
    let retired =
        client.receive_until(ingress(Role::Server), &wire(retired)?, Tick(970), EXPIRES)?;
    assert_eq!(retired.event, Some(Event::Retired(Epoch(1))));
    for peer in [&client, &server] {
        assert_eq!(peer.phase(), Phase::Idle);
        assert_eq!(peer.active_epoch(), Epoch(2));
        assert!(peer.reader(Epoch(1)).is_none());
        assert!(
            !peer.can_admit_data(),
            "semantic RETIRE is not final message custody"
        );
        assert_operation(peer, EXPIRES)?;
        assert!(peer.retained_requests() <= 1);
        assert!(peer.retained_replies() <= 1);
    }
    Ok(())
}

#[test]
fn readonly_preflight_and_conflicting_deadline_reject_without_consuming_arrival() -> Result {
    let (mut client, mut server) = pair()?;
    let (local, remote) = fences()?;
    client.propose_until(policies().1, Tick(0), EXPIRES)?;
    let prepare = wire(client.staged(local, Tick(0))?)?;
    server.receive_until(ingress(Role::Client), &prepare, Tick(0), EXPIRES)?;
    let before = observation(&server);
    let retried = fresh(&prepare, 2)?;
    for expires in [Tick(999), Tick(1_001)] {
        assert_eq!(
            server.validate_receive_until(ingress(Role::Client), &retried, Tick(1), expires),
            Err(Error::LeaseConflict)
        );
        assert_eq!(observation(&server), before);
        assert_eq!(
            server.receive_until(ingress(Role::Client), &retried, Tick(1), expires),
            Err(Error::LeaseConflict)
        );
        assert_eq!(observation(&server), before);
    }
    assert_eq!(
        server.validate_receive_until(ingress(Role::Client), &retried, Tick(999), EXPIRES),
        Ok(())
    );
    assert_eq!(observation(&server), before);
    for at in [EXPIRES, Tick(1_001)] {
        assert_eq!(
            server.validate_receive_until(ingress(Role::Client), &retried, at, EXPIRES),
            Err(Error::LeaseExpired)
        );
        assert_eq!(observation(&server), before);
    }
    // Read-only future-time checks did not advance either gate or clock.
    assert_eq!(
        server.receive_until(ingress(Role::Client), &retried, Tick(1), EXPIRES)?,
        crate::transaction::Effects::default()
    );
    let ready = wire(server.staged(remote, Tick(2))?)?;
    let frame = Frame::decode(&ready, Limits::default()).map_err(Error::Admission)?;
    assert_eq!(frame.header.request.0, 1);
    assert_eq!(frame.header.packet.0, 1);
    assert_eq!(frame.body[..8], 1u64.to_be_bytes());
    Ok(())
}

#[test]
fn first_reject_after_missing_prepare_retains_the_same_bounded_origin() -> Result {
    let (mut client, mut server) = pair()?;
    let expires = Tick(3_000);
    client.propose_until(policies().1, Tick(0), expires)?;
    let lost_prepare = wire(client.staged(fences()?.0, Tick(0))?)?;
    let reject = wire(client.poll(Tick(1_000))?)?;
    assert_eq!(client.phase(), Phase::Aborting);
    assert_eq!(
        Frame::decode(&reject, Limits::default())
            .map_err(Error::Admission)?
            .header
            .kind,
        MessageKind::Reject
    );
    assert!(server.operation().is_none());
    let accepted = server.receive_until(ingress(Role::Client), &reject, Tick(1_000), expires)?;
    assert_eq!(accepted.event, Some(Event::Aborted(1)));
    assert_eq!(server.active_epoch(), Epoch(1));
    assert_operation(&server, expires)?;
    let context =
        server.outbound_context(accepted.outbound.as_deref().ok_or(Error::Unexpected)?)?;
    assert_eq!(
        context.origin(),
        server.operation().ok_or(Error::Unexpected)?.origin()
    );
    assert_eq!(context.expires(), expires);
    assert_eq!(context.kind(), MessageKind::Reject);
    assert!(context.is_final_reply());
    let retried = fresh(&reject, 100)?;
    let repeated = server.receive_until(ingress(Role::Client), &retried, Tick(1_010), expires)?;
    assert!(repeated.event.is_none());
    assert!(repeated.outbound.is_some());
    let completed = client.receive_until(
        ingress(Role::Server),
        &wire(accepted)?,
        Tick(1_020),
        expires,
    )?;
    assert_eq!(completed.event, Some(Event::Aborted(1)));
    assert!(matches!(
        server.receive_until(
            ingress(Role::Client),
            &fresh(&lost_prepare, 101)?,
            Tick(1_030),
            expires
        ),
        Err(Error::Admission(crate::Error::RequestRetired))
    ));
    assert_operation(&client, expires)?;
    assert_operation(&server, expires)?;
    assert!(!client.can_admit_data());
    assert!(!server.can_admit_data());
    Ok(())
}

#[test]
fn retired_origin_authority_matches_only_the_actual_cached_logical_request() -> Result {
    let (mut client, mut server) = pair()?;
    let retire = retire_ready(&mut client, &mut server, Tick(0))?;
    let retired = server.receive_until(ingress(Role::Client), &retire, Tick(0), EXPIRES)?;
    assert_eq!(retired.event, Some(Event::Retired(Epoch(1))));
    let reply = wire(retired)?;
    let original = server.operation().ok_or(Error::Unexpected)?.origin();
    let request = Frame::decode(&retire, Limits::default()).map_err(Error::Admission)?;
    let reply_frame = Frame::decode(&reply, Limits::default()).map_err(Error::Admission)?;
    let context = server.outbound_context(&reply)?;
    assert_eq!(context.origin(), original);
    assert_eq!(context.expires(), EXPIRES);
    assert_eq!(context.request(), reply_frame.header.request);
    assert_eq!(context.kind(), MessageKind::Retire);
    assert!(context.is_final_reply());
    assert_ne!(context.origin().digest, reply_frame.header.ticket.digest);
    let authority = server
        .cached_retry_authority(Tick(1))?
        .ok_or(Error::Unexpected)?;
    assert_eq!(authority.operation().origin(), original);
    assert_eq!(authority.operation().expires(), EXPIRES);
    assert_eq!(authority.request(), request);
    assert_eq!(authority.reply_request(), reply_frame.header.request);
    assert_eq!(authority.reply_kind(), MessageKind::Retire);

    let retried = fresh(&retire, 100)?;
    let before = observation(&server);
    assert_eq!(
        server.validate_control_origin(ingress(Role::Client), &retried, original, Tick(1)),
        Ok(true)
    );
    assert_eq!(
        server.validate_receive_until(ingress(Role::Client), &retried, Tick(1), EXPIRES),
        Ok(())
    );
    assert_eq!(observation(&server), before);
    for changed in [
        crate::session_control::Scope {
            digest: request.header.ticket.digest,
            ..original
        },
        crate::session_control::Scope {
            epoch: Epoch(2),
            ..original
        },
        crate::session_control::Scope {
            epoch: Epoch(2),
            digest: request.header.ticket.digest,
        },
    ] {
        assert!(
            server
                .validate_control_origin(ingress(Role::Client), &retried, changed, Tick(1))
                .is_err()
        );
        assert_eq!(observation(&server), before);
    }
    let mut changed_session = identity(Role::Client).session;
    changed_session.0[15] ^= 1;
    for verified in [
        Ingress::UserTraffic,
        Ingress::Unauthenticated,
        Ingress::AuthenticatedManagement {
            session: changed_session,
            lane: LaneId(7),
            sender: Role::Client,
        },
        Ingress::AuthenticatedManagement {
            session: identity(Role::Client).session,
            lane: LaneId(8),
            sender: Role::Client,
        },
        Ingress::AuthenticatedManagement {
            session: identity(Role::Client).session,
            lane: LaneId(7),
            sender: Role::Server,
        },
    ] {
        assert!(
            server
                .validate_control_origin(verified, &retried, original, Tick(1))
                .is_err()
        );
        assert!(
            server
                .validate_receive_until(verified, &retried, Tick(1), EXPIRES)
                .is_err()
        );
        assert_eq!(observation(&server), before);
    }
    for field in 0..12 {
        let mut header = Header {
            packet: PacketNumber(100),
            ..request.header
        };
        let mut body = request.body.to_vec();
        match field {
            0 => header.session.0[15] ^= 1,
            1 => header.lane = LaneId(8),
            2 => header.sender = Role::Server,
            3 => header.source = EndpointId(99),
            4 => header.destination = EndpointId(99),
            5 => header.request.0 += 1,
            6 => header.kind = MessageKind::Commit,
            7 => header.source_epoch = Epoch(2),
            8 => header.ticket.attempt += 1,
            9 => header.ticket.digest.0[31] ^= 1,
            10 => header.ticket.epoch = Epoch(3),
            _ => body[7] ^= 1,
        }
        let changed = encoded(header, &body)?;
        assert!(
            server
                .validate_control_origin(ingress(Role::Client), &changed, original, Tick(1))
                .is_err(),
            "altered cached request field {field} gained origin authority"
        );
        assert!(
            server
                .validate_receive_until(ingress(Role::Client), &changed, Tick(1), EXPIRES)
                .is_err()
        );
        assert_eq!(observation(&server), before);
    }
    let repeated = server.receive_until(ingress(Role::Client), &retried, Tick(1), EXPIRES)?;
    assert!(repeated.event.is_none());
    let repeated = wire(repeated)?;
    let repeated = Frame::decode(&repeated, Limits::default()).map_err(Error::Admission)?;
    assert_eq!(repeated.header.request, reply_frame.header.request);
    assert_eq!(repeated.body, reply_frame.body);
    assert_ne!(repeated.header.packet, reply_frame.header.packet);
    assert_eq!(server.active_epoch(), Epoch(2));
    assert!(server.reader(Epoch(1)).is_none());
    assert_eq!(server.retained_requests(), 1);
    assert_eq!(server.retained_replies(), 1);
    assert_operation(&server, EXPIRES)?;
    for packet in 101..=356 {
        let retried = fresh(&retire, packet)?;
        let repeated = server.receive_until(ingress(Role::Client), &retried, Tick(2), EXPIRES)?;
        assert!(repeated.event.is_none());
        let repeated = wire(repeated)?;
        let repeated = Frame::decode(&repeated, Limits::default()).map_err(Error::Admission)?;
        assert_eq!(repeated.header.request, reply_frame.header.request);
        assert_eq!(repeated.body, reply_frame.body);
        assert_eq!(server.retained_requests(), 1);
        assert_eq!(server.retained_replies(), 1);
        assert_operation(&server, EXPIRES)?;
    }
    Ok(())
}

#[test]
fn final_idle_cache_expires_at_the_original_bound_without_custody_or_rollback() -> Result {
    for at in [Tick(999), Tick(1_000), Tick(1_001)] {
        let (mut client, mut server) = pair()?;
        let retire = retire_ready(&mut client, &mut server, Tick(0))?;
        let reply =
            wire(server.receive_until(ingress(Role::Client), &retire, Tick(0), EXPIRES)?)?;
        assert_eq!(
            client
                .receive_until(ingress(Role::Server), &reply, Tick(0), EXPIRES)?
                .event,
            Some(Event::Retired(Epoch(1)))
        );
        assert!(!client.can_admit_data());
        assert!(!server.can_admit_data());
        let before = observation(&server);
        if at < EXPIRES {
            assert!(server.cached_retry_authority(at)?.is_some());
            assert_eq!(observation(&server), before);
            assert_eq!(server.poll(at)?, crate::transaction::Effects::default());
            assert_eq!(server.phase(), Phase::Idle);
            assert_operation(&server, EXPIRES)?;
        } else {
            assert_eq!(
                server.cached_retry_authority(at).err(),
                Some(Error::LeaseExpired)
            );
            assert_eq!(observation(&server), before);
            assert_eq!(server.poll(at), Err(Error::LeaseExpired));
            assert_eq!(server.outbound_context(&reply), Err(Error::LeaseExpired));
            assert_eq!(server.phase(), Phase::Failed);
            assert_eq!(server.active_epoch(), Epoch(2));
            assert!(server.reader(Epoch(1)).is_none());
            assert!(server.reader(Epoch(2)).is_none());
            assert!(server.operation().is_some());
            assert_eq!(server.retained_requests(), 1);
            assert_eq!(server.retained_replies(), 1);
            assert_eq!(
                server.receive_until(ingress(Role::Client), &fresh(&retire, 100)?, at, EXPIRES),
                Err(Error::LeaseExpired)
            );
            assert_eq!(server.poll(at), Err(Error::LeaseExpired));
            assert!(!server.can_admit_data());
        }
    }
    Ok(())
}

#[test]
fn invalid_lease_settings_and_backward_time_do_not_create_another_operation() -> Result {
    let (initial, next) = policies();
    for invalid in [
        LeaseSettings {
            session_expires: Tick(0),
            ..lease()
        },
        LeaseSettings {
            max_operation_ms: 0,
            ..lease()
        },
        LeaseSettings {
            transaction_epoch: 0,
            ..lease()
        },
    ] {
        assert!(matches!(
            Peer::new_leased(
                identity(Role::Client),
                Epoch(1),
                initial.clone(),
                &[initial.clone(), next.clone()],
                settings(),
                invalid,
                Tick(0)
            ),
            Err(Error::Configuration(_))
        ));
    }
    let mut client = endpoint(Role::Client)?;
    client.propose_until(next.clone(), Tick(5), EXPIRES)?;
    let before = observation(&client);
    assert_eq!(
        client.propose_until(next, Tick(6), Tick(900)),
        Err(Error::Busy)
    );
    assert_eq!(observation(&client), before);
    assert_eq!(client.poll(Tick(4)), Err(Error::Clock));
    assert_eq!(observation(&client), before);
    assert_operation(&client, EXPIRES)?;
    Ok(())
}

#[test]
fn session_cap_is_inclusive_for_admission_and_checked_time_overflow_has_no_peer() -> Result {
    let (initial, next) = policies();
    let mut client = Peer::new_leased(
        identity(Role::Client),
        Epoch(1),
        initial.clone(),
        &[initial.clone(), next.clone()],
        settings(),
        LeaseSettings {
            session_expires: EXPIRES,
            ..lease()
        },
        Tick(0),
    )?;
    assert!(matches!(
        client.propose_until(next.clone(), Tick(0), Tick(1_001)),
        Err(Error::Configuration(_))
    ));
    assert!(client.operation().is_none());
    assert!(matches!(
        client.propose_until(next.clone(), Tick(0), EXPIRES)?.event,
        Some(Event::Stage { .. })
    ));
    assert_operation(&client, EXPIRES)?;
    assert_eq!(
        client.staged(fences()?.0, EXPIRES),
        Err(Error::LeaseExpired)
    );
    assert_eq!(client.phase(), Phase::Failed);
    assert!(matches!(
        Peer::new_leased(
            identity(Role::Client),
            Epoch(1),
            initial.clone(),
            &[initial, next],
            settings(),
            LeaseSettings {
                session_expires: Tick(u64::MAX),
                ..lease()
            },
            Tick(u64::MAX - 1_000)
        ),
        Err(Error::Clock)
    ));
    Ok(())
}

#[test]
fn final_incoming_reply_retries_remain_idempotent_until_actual_acceptance_custody() -> Result {
    for kind in [MessageKind::Retire, MessageKind::Reject] {
        let (mut client, mut server) = pair()?;
        let (reply, now, expires, expected) = if kind == MessageKind::Retire {
            let retire = retire_ready(&mut client, &mut server, Tick(0))?;
            (
                wire(server.receive_until(ingress(Role::Client), &retire, Tick(0), EXPIRES)?)?,
                Tick(0),
                EXPIRES,
                Event::Retired(Epoch(1)),
            )
        } else {
            let expires = Tick(3_000);
            client.propose_until(policies().1, Tick(0), expires)?;
            let _lost_prepare = wire(client.staged(fences()?.0, Tick(0))?)?;
            let reject = wire(client.poll(Tick(1_000))?)?;
            (
                wire(server.receive_until(
                    ingress(Role::Client),
                    &reject,
                    Tick(1_000),
                    expires,
                )?)?,
                Tick(1_000),
                expires,
                Event::Aborted(1),
            )
        };
        let result = client.receive_until(ingress(Role::Server), &reply, now, expires)?;
        assert_eq!(result.event, Some(expected));
        assert_eq!(client.phase(), Phase::Idle);
        assert_eq!(client.retained_requests(), 1);
        assert!(!client.can_admit_data());
        let original = client.operation().ok_or(Error::Unexpected)?;
        let retried = fresh(&reply, 100)?;
        let before = observation(&client);
        assert_eq!(
            client.validate_control_origin(ingress(Role::Server), &retried, original.origin(), now),
            Ok(true)
        );
        assert_eq!(
            client.validate_receive_until(ingress(Role::Server), &retried, now, expires),
            Ok(())
        );
        assert_eq!(observation(&client), before);
        assert_eq!(
            client.receive_until(ingress(Role::Server), &retried, now, expires)?,
            crate::transaction::Effects::default()
        );
        assert_eq!(client.retained_requests(), 1);
        assert_eq!(client.operation(), Some(original));
        let frame = Frame::decode(&reply, Limits::default()).map_err(Error::Admission)?;
        let mut changed_body = frame.body.to_vec();
        changed_body[7] ^= 1;
        let changed = encoded(
            Header {
                packet: PacketNumber(101),
                ..frame.header
            },
            &changed_body,
        )?;
        let before = observation(&client);
        assert!(
            client
                .validate_control_origin(ingress(Role::Server), &changed, original.origin(), now)
                .is_err()
        );
        assert!(
            client
                .validate_receive_until(ingress(Role::Server), &changed, now, expires)
                .is_err()
        );
        assert_eq!(observation(&client), before);
        assert_eq!(client.poll(expires), Err(Error::LeaseExpired));
        assert_eq!(client.phase(), Phase::Failed);
    }
    Ok(())
}

#[test]
fn a_never_emitted_staging_abort_releases_only_its_local_custody() -> Result {
    let mut client = endpoint(Role::Client)?;
    let expires = Tick(3_000);
    client.propose_until(policies().1, Tick(0), expires)?;
    assert!(client.poll(Tick(999))?.event.is_none());
    let aborted = client.poll(Tick(1_000))?;
    assert_eq!(aborted.event, Some(Event::Aborted(1)));
    assert!(aborted.outbound.is_none());
    assert_eq!(client.phase(), Phase::Idle);
    assert!(client.operation().is_none());
    assert!(client.can_admit_data());
    assert_eq!(client.active_epoch(), Epoch(1));
    assert_eq!(client.retained_requests(), 0);
    assert_eq!(client.retained_replies(), 0);
    assert!(client.cached_retry_authority(Tick(1_000))?.is_none());
    let staged = client.propose_until(policies().1, Tick(1_001), expires)?;
    let Some(Event::Stage { ticket, .. }) = staged.event else {
        return Err(Error::Unexpected);
    };
    assert_eq!(ticket.attempt, 2);
    let prepare = wire(client.staged(fences()?.0, Tick(1_001))?)?;
    let frame = Frame::decode(&prepare, Limits::default()).map_err(Error::Admission)?;
    assert_eq!(frame.header.request.0, 1);
    assert_eq!(frame.header.packet.0, 1);
    Ok(())
}

#[test]
fn uncertain_commit_reconciliation_cannot_renew_the_original_cap_or_roll_back() -> Result {
    let (initial, next) = policies();
    let make = |role| {
        Peer::new_leased(
            identity(role),
            Epoch(1),
            initial.clone(),
            &[initial.clone(), next.clone()],
            Settings {
                phase_timeout_ms: 100,
                ..settings()
            },
            lease(),
            Tick(0),
        )
    };
    let mut client = make(Role::Client)?;
    let mut server = make(Role::Server)?;
    let expires = Tick(500);
    let (local, remote) = fences()?;
    client.propose_until(next, Tick(0), expires)?;
    let prepare = wire(client.staged(local.clone(), Tick(0))?)?;
    server.receive_until(ingress(Role::Client), &prepare, Tick(0), expires)?;
    let ready = wire(server.staged(remote.clone(), Tick(0))?)?;
    client.receive_until(ingress(Role::Server), &ready, Tick(0), expires)?;
    let barrier = wire(client.confirm_drained(&local, &remote, Tick(0))?)?;
    server.receive_until(ingress(Role::Client), &barrier, Tick(0), expires)?;
    let barrier_ack = wire(server.confirm_drained(&remote, &local, Tick(0))?)?;
    let commit =
        wire(client.receive_until(ingress(Role::Server), &barrier_ack, Tick(0), expires)?)?;
    let withheld_ack = server.receive_until(ingress(Role::Client), &commit, Tick(0), expires)?;
    assert!(matches!(withheld_ack.event, Some(Event::Committed(_))));
    assert_eq!(server.active_epoch(), Epoch(2));
    assert_eq!(client.active_epoch(), Epoch(1));
    let uncertain = client.poll(Tick(100))?;
    assert!(matches!(uncertain.event, Some(Event::Uncertain(_))));
    assert!(uncertain.outbound.is_some());
    assert_eq!(client.phase(), Phase::Uncertain);
    assert_operation(&client, expires)?;
    let final_retry = client.poll(Tick(499))?;
    assert!(final_retry.event.is_none());
    assert!(final_retry.outbound.is_some());
    assert_operation(&client, expires)?;
    let before = observation(&client);
    let ack = wire(withheld_ack)?;
    assert_eq!(
        client.validate_receive_until(ingress(Role::Server), &ack, expires, expires),
        Err(Error::LeaseExpired)
    );
    assert_eq!(observation(&client), before);
    assert_eq!(
        client.receive_until(ingress(Role::Server), &ack, expires, expires),
        Err(Error::LeaseExpired)
    );
    assert_eq!(client.phase(), Phase::Failed);
    assert_eq!(client.active_epoch(), Epoch(1));
    assert_eq!(server.active_epoch(), Epoch(2));
    assert!(client.reader(Epoch(1)).is_none());
    assert!(client.reader(Epoch(2)).is_none());
    assert!(!client.can_admit_data());
    Ok(())
}

mod directional;
