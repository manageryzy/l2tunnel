//! Joint preview uses the real encoded envelopes and leaves both gates uncommitted.

use super::*;

fn preview(
    endpoint: &Endpoint,
    bytes: &[u8],
    now: tx::Tick,
    expires: tx::Tick,
) -> std::result::Result<Option<tx::Preparation<ModeConfig>>, TransactionError> {
    endpoint.gate.preview_transaction(
        &endpoint.peer,
        verified(opposite(endpoint.role)),
        Stream::Transaction,
        bytes,
        now,
        expires,
    )
}

#[test]
fn joint_preview_matches_stage_and_does_not_consume_envelope_or_inner_identity() -> Result {
    let mut client = Endpoint::new(Role::Client)?;
    let mut server = Endpoint::new(Role::Server)?;
    let (initial, next) = modes();
    let old = origin(10, &initial)?;
    client.peer.propose_until(next.clone(), NOW, EXPIRY)?;
    let command = wire(client.peer.staged(tx::Fence::new(&[3, 5])?, NOW)?)?;
    let bytes = server.wrap(old, &command)?;
    let before = observe(&server);
    for at in [NOW, tx::Tick(90)] {
        let intent = preview(&server, &bytes, at, EXPIRY)?.ok_or("missing staging intent")?;
        assert_eq!(intent.config(), &next);
        assert_eq!(intent.origin(), old);
        assert_eq!(intent.identity(), identity(Role::Server));
        assert_eq!(intent.expires(), EXPIRY);
        assert_eq!(observe(&server), before);
    }
    let intent = preview(&server, &bytes, NOW, EXPIRY)?.ok_or("missing staging intent")?;
    let effects = server.gate.receive_transaction(
        &mut server.peer,
        verified(Role::Client),
        Stream::Transaction,
        &bytes,
        NOW,
        EXPIRY,
    )?;
    assert!(
        matches!(effects.event,Some(tx::Event::Stage {ticket,config}) if ticket==intent.ticket() && config==*intent.config())
    );
    assert_eq!(
        server.gate.highest_packet(Stream::Transaction),
        Some(PacketNumber(1))
    );
    assert!(matches!(
        preview(&server, &bytes, NOW, EXPIRY),
        Err(TransactionError::Gate(Error::Legacy(
            crate::Error::PacketReplay
        )))
    ));
    let retry = rewrite(&command, |h, _| h.packet = PacketNumber(2))?;
    let retry = server.wrap(old, &retry)?;
    let before = observe(&server);
    assert!(preview(&server, &retry, NOW, EXPIRY)?.is_none());
    assert_eq!(observe(&server), before);
    let effects = server.gate.receive_transaction(
        &mut server.peer,
        verified(Role::Client),
        Stream::Transaction,
        &retry,
        NOW,
        EXPIRY,
    )?;
    assert!(effects.event.is_none());
    Ok(())
}

#[test]
fn wrong_joint_origin_stream_grammar_sequence_and_cap_leave_valid_first_prepare_admissible()
-> Result {
    let mut client = Endpoint::new(Role::Client)?;
    let mut server = Endpoint::new(Role::Server)?;
    let (initial, next) = modes();
    let old = origin(10, &initial)?;
    client.peer.propose_until(next, NOW, EXPIRY)?;
    let command = wire(client.peer.staged(tx::Fence::new(&[3, 5])?, NOW)?)?;
    let good = server.wrap(old, &command)?;
    let wrong_scope = Scope {
        digest: ConfigDigest([0x11; 32]),
        ..old
    };
    let invalid = [
        envelope(Role::Client, 1, wrong_scope, Body::Management(&command))?,
        envelope(Role::Client, 2, old, Body::Management(&command))?,
        envelope(
            Role::Client,
            1,
            old,
            Body::ProfileControl {
                tag: ProfileTag::SwiftPolicyV1,
                bytes: &[1],
            },
        )?,
    ];
    let before = observe(&server);
    for bytes in &invalid {
        assert!(preview(&server, bytes, NOW, EXPIRY).is_err());
        assert_eq!(observe(&server), before);
    }
    for stream in [Stream::Liveness, Stream::DataFeedback] {
        assert!(
            server
                .gate
                .preview_transaction(
                    &server.peer,
                    verified(Role::Client),
                    stream,
                    &good,
                    NOW,
                    EXPIRY
                )
                .is_err()
        );
        assert_eq!(observe(&server), before);
    }
    for verified in [
        Ingress::UserTraffic,
        verified(Role::Server),
        Ingress::AuthenticatedManagement {
            session: SessionId([0x44; 16]),
            lane: LANE,
            sender: Role::Client,
        },
    ] {
        assert!(
            server
                .gate
                .preview_transaction(
                    &server.peer,
                    verified,
                    Stream::Transaction,
                    &good,
                    NOW,
                    EXPIRY
                )
                .is_err()
        );
        assert_eq!(observe(&server), before);
    }
    assert!(preview(&server, &good, NOW, NOW).is_err());
    assert_eq!(observe(&server), before);
    assert!(preview(&server, &good, NOW, EXPIRY)?.is_some());
    server.gate.receive_transaction(
        &mut server.peer,
        verified(Role::Client),
        Stream::Transaction,
        &good,
        NOW,
        EXPIRY,
    )?;
    Ok(())
}

#[test]
fn retained_terminal_old_origin_preview_is_narrow_and_expires_without_reopening_user_scope()
-> Result {
    let mut client = Endpoint::new(Role::Client)?;
    let mut server = Endpoint::new(Role::Server)?;
    let (initial, next) = modes();
    let old = origin(10, &initial)?;
    let target = origin(11, &next)?;
    client.peer.propose_until(next, NOW, EXPIRY)?;
    let local = tx::Fence::new(&[3, 5])?;
    let remote = tx::Fence::new(&[7, 11])?;
    let prepare = wire(client.peer.staged(local.clone(), NOW)?)?;
    server.receive(old, &prepare, NOW)?;
    let ready = wire(server.peer.staged(remote.clone(), NOW)?)?;
    client.receive(old, &ready, NOW)?;
    let barrier = wire(client.peer.confirm_drained(&local, &remote, NOW)?)?;
    server.receive(old, &barrier, NOW)?;
    let barrier_ack = wire(server.peer.confirm_drained(&remote, &local, NOW)?)?;
    let commit = wire(client.receive(old, &barrier_ack, NOW)?)?;
    let commit_ack = wire(server.receive(old, &commit, NOW)?)?;
    let retire = wire(client.receive(old, &commit_ack, NOW)?)?;
    let retire_ack = wire(server.receive(old, &retire, NOW)?)?;
    client.receive(old, &retire_ack, NOW)?;
    for endpoint in [&mut client, &mut server] {
        endpoint.gate.advance_scope(policy(target))?;
        endpoint.gate.retire_draining(old)?;
    }
    let retry = rewrite(&retire, |h, _| h.packet = PacketNumber(100))?;
    let bytes = server.wrap(old, &retry)?;
    let before = observe(&server);
    assert!(preview(&server, &bytes, tx::Tick(999), EXPIRY)?.is_none());
    assert_eq!(observe(&server), before);
    assert_eq!(server.gate.active.scope, target);
    assert!(server.gate.draining.is_none());
    let changed = rewrite(&retry, |_, b| {
        if let Some(last) = b.last_mut() {
            *last ^= 1;
        }
    })?;
    let changed = server.wrap(old, &changed)?;
    assert!(preview(&server, &changed, NOW, EXPIRY).is_err());
    assert_eq!(observe(&server), before);
    for at in [EXPIRY, tx::Tick(1_001)] {
        assert!(matches!(
            preview(&server, &bytes, at, EXPIRY),
            Err(TransactionError::Transaction(tx::Error::LeaseExpired))
        ));
        assert_eq!(observe(&server), before);
    }
    let effects = server.gate.receive_transaction(
        &mut server.peer,
        verified(Role::Client),
        Stream::Transaction,
        &bytes,
        tx::Tick(999),
        EXPIRY,
    )?;
    assert!(effects.event.is_none());
    // A fresh final reply at the coordinator uses its exact unaccepted incoming witness.
    let reply = wire(effects)?;
    let reply = client.wrap(old, &reply)?;
    let before = observe(&client);
    assert!(preview(&client, &reply, tx::Tick(999), EXPIRY)?.is_none());
    assert_eq!(observe(&client), before);
    Ok(())
}
