//! Actual reserved Engines and opaque selected commands; crypto is caller-injected.
use super::*;
use crate::connection_records::retirement::command::{Command, Kind, MAX_BYTES};
use crate::record_engine::connection_reuse::ConnectionReuse;
use l2tunnel_management::{self as mg, session_control as sc, transaction as tx};

fn identity(role: mg::Role) -> tx::Identity {
    tx::Identity {
        session: mg::SessionId(0x1020_u128.to_be_bytes()),
        role,
        local: mg::EndpointId(if role == mg::Role::Client { 1 } else { 2 }),
        remote: mg::EndpointId(if role == mg::Role::Client { 2 } else { 1 }),
        lane: mg::LaneId(3),
    }
}
fn scope(value: c::Configuration) -> TestResult<sc::Scope> {
    Ok(sc::Scope {
        epoch: l2tunnel_core::Epoch(7),
        digest: value.digest()?,
    })
}
fn attested(
    command: Command,
    local: mg::Role,
    now: u64,
    retained: Option<tx::Operation>,
) -> TestResult<Command> {
    let mut body = [0; MAX_BYTES];
    let length = command.encode(&mut body)?;
    let remote = if local == mg::Role::Client {
        mg::Role::Server
    } else {
        mg::Role::Client
    };
    let envelope = sc::Envelope {
        binding: sc::Binding {
            session: identity(local).session,
            lane: mg::LaneId(3),
            sender: remote,
            packet: mg::PacketNumber(1),
            scope: command.operation().origin(),
        },
        body: sc::Body::ProfileControl {
            tag: sc::ProfileTag::SlotReuseV1,
            bytes: &body[..length],
        },
    };
    // Exercise the maintained outer envelope parser too. This remains an injected
    // authentication boundary, not a TLS/Noise or replay-integration claim.
    let limits = sc::Limits {
        max_frame_bytes: 512,
        max_management_bytes: 112,
        max_feedback_bytes: 64,
    };
    let mut encoded = [0; 512];
    let length = envelope.encode(&mut encoded, limits)?;
    let envelope = sc::Envelope::decode(&encoded[..length], limits)?;
    Ok(Command::admit(
        envelope,
        mg::Ingress::AuthenticatedManagement {
            session: identity(local).session,
            lane: mg::LaneId(3),
            sender: remote,
        },
        identity(local),
        command.operation().origin(),
        tx::Tick(now),
        tx::Tick(10_000),
        2000,
        retained,
    )?)
}
fn output(
    from: &mut engine::Engine,
    to: &mut engine::Engine,
    now: u64,
    number: &mut u64,
) -> TestResult<Option<(engine::Emission, Vec<u8>)>> {
    let mut bytes = vec![0; 2048];
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
        wire_bytes: 100_000,
    };
    *number = number.checked_add(1).ok_or("test packet number")?;
    let Some(emitted) = from.poll(
        tick(now),
        *number,
        true,
        &mut bytes,
        &mut budget,
        &mut witnesses,
    )?
    else {
        return Ok(None);
    };
    let token = from
        .pending_carrier_output()
        .ok_or("actual output custody")?;
    from.confirm_carrier_output_at(tick(now), tick(now), token)?;
    bytes.truncate(emitted.bytes);
    let original = bytes.clone();
    to.accept_authenticated_until(
        tick(now),
        tick(now),
        tick(5000),
        emitted.security_number,
        emitted.kind,
        &mut bytes,
    )?;
    Ok(Some((emitted, original)))
}
fn native(owner: &mut engine::Engine, now: u64) -> TestResult<Vec<Vec<u8>>> {
    let mut result = Vec::new();
    let mut bytes = [0; 512];
    for _ in 0..32 {
        match owner.prepare_native(tick(now), 1, tick(5000), &mut bytes)? {
            engine::NativePreparation::Idle => break,
            engine::NativePreparation::Progress => {}
            engine::NativePreparation::Ready(p) | engine::NativePreparation::AlreadyPending(p) => {
                result.push(bytes[..p.bytes()].to_vec());
                owner.commit_native(tick(now), p.token())?;
            }
        }
    }
    Ok(result)
}

#[test]
fn opaque_reuse_commands_retain_relative_clock_cap_and_exact_keys() -> TestResult {
    let (_, _, value) = engine_pair()?;
    let old = metadata(&tcp(41000)?)?.key;
    let next = metadata(&tcp(41001)?)?.key;
    for key in [old, next] {
        let bytes = key.canonical_bytes();
        assert_eq!(
            pipeline::FlowKey::from_canonical_bytes(bytes.as_slice())?,
            key
        );
        let mut bad = bytes.as_slice().to_vec();
        bad.push(0);
        assert!(pipeline::FlowKey::from_canonical_bytes(&bad).is_err());
    }
    let first = Command::begin(
        identity(mg::Role::Client),
        scope(value)?,
        1,
        0,
        selected()?.0.incarnation,
        old,
        next,
        tx::Tick(10),
        tx::Tick(210),
        tx::Tick(10_000),
        2000,
    )?;
    let peer = attested(first, mg::Role::Server, 900, None)?;
    assert_eq!(peer.operation().expires(), tx::Tick(1100));
    let local = ConnectionReuse::from_peer_stop(peer, tx::Tick(900), tx::Tick(10_000), 2000)?;
    let repeated = attested(first, mg::Role::Server, 950, Some(local.operation()))?;
    assert_eq!(repeated.operation().expires(), tx::Tick(1100));
    assert_eq!(repeated.old_key(), old);
    assert_eq!(repeated.next_key(), next);
    let mut bytes = [0xa5; MAX_BYTES];
    let mut short = [0xa5; 16];
    assert!(first.encode(&mut short).is_err());
    assert_eq!(short, [0xa5; 16]);
    let length = first.encode(&mut bytes)?;
    assert_eq!(&bytes[..6], b"L2CR\x01\x01");
    assert_eq!(&bytes[72..80], &200_u64.to_be_bytes());
    assert!(length <= MAX_BYTES);
    bytes[79] ^= 1; // Immutable lifetime changed without its target commitment.
    let envelope = sc::Envelope {
        binding: sc::Binding {
            session: identity(mg::Role::Server).session,
            lane: mg::LaneId(3),
            sender: mg::Role::Client,
            packet: mg::PacketNumber(1),
            scope: scope(value)?,
        },
        body: sc::Body::ProfileControl {
            tag: sc::ProfileTag::SlotReuseV1,
            bytes: &bytes[..length],
        },
    };
    assert!(
        Command::admit(
            envelope,
            mg::Ingress::AuthenticatedManagement {
                session: identity(mg::Role::Server).session,
                lane: mg::LaneId(3),
                sender: mg::Role::Client,
            },
            identity(mg::Role::Server),
            scope(value)?,
            tx::Tick(900),
            tx::Tick(10_000),
            2000,
            None
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn actual_engines_reuse_one_owner_after_crossed_drain_and_keep_new_native_identity() -> TestResult {
    let (mut a, mut b, value) = engine_pair()?;
    let old_bytes = tcp(41000)?;
    let old_key = metadata(&old_bytes)?.key;
    let next_bytes = tcp(41100)?;
    let next_key = metadata(&next_bytes)?.key;
    let before_a = a.storage_usage();
    let before_b = b.storage_usage();
    a.ingest_borrowed_at(tick(0), tick(0), &old_bytes, tick(5000))?;
    let old = a
        .admit_borrowed(tick(0))?
        .ok_or("old actual Pipeline admission")?;
    let engine::ProfileIdentity::Connection(old) = old.permit else {
        return Err("old recovered owner".into());
    };
    let mut number = 1;
    let (old_emission, old_wire) =
        output(&mut a, &mut b, 1, &mut number)?.ok_or("old real source")?;
    assert_eq!(native(&mut b, 2)?, vec![old_bytes]);
    for now in 3..=25 {
        output(&mut a, &mut b, now, &mut number)?;
        output(&mut b, &mut a, now, &mut number)?;
        assert!(native(&mut a, now)?.is_empty());
        assert!(native(&mut b, now)?.is_empty());
    }
    assert_eq!(a.connection_owner_key(0)?, Some(old_key));
    assert_eq!(b.connection_owner_key(0)?, Some(old_key));
    let original_incarnation = a.connection_route_incarnation(0)?;
    let command = Command::begin(
        identity(mg::Role::Client),
        scope(value)?,
        1,
        0,
        original_incarnation,
        old_key,
        next_key,
        tx::Tick(30),
        tx::Tick(500),
        tx::Tick(10_000),
        2000,
    )?;
    let mut local = ConnectionReuse::from_local(command, tx::Tick(30), tx::Tick(10_000), 2000)?;
    let mut remote: Option<ConnectionReuse> = None;
    let mut saw_done_ack_before_local_ack = false;
    for now in 30..=100 {
        local.progress(&mut a, tick(now))?;
        if let Some(command) = local.outgoing() {
            let received = attested(
                command,
                mg::Role::Server,
                now,
                remote.as_ref().map(ConnectionReuse::operation),
            )?;
            if let Some(remote) = &mut remote {
                remote.receive(received)?;
            } else {
                remote = Some(ConnectionReuse::from_peer_stop(
                    received,
                    tx::Tick(now),
                    tx::Tick(10_000),
                    2000,
                )?);
            }
            // Genuine semantic reply may precede observation of the transport ACK.
            if command.kind() != Kind::Done {
                local.outgoing_confirmed(command)?;
            }
        }
        let remote = remote
            .as_mut()
            .ok_or("attested STOP creates real responder")?;
        remote.progress(&mut b, tick(now))?;
        if let Some(command) = remote.outgoing() {
            let received = attested(command, mg::Role::Client, now, Some(local.operation()))?;
            local.receive(received)?;
            remote.outgoing_confirmed(command)?;
            if command.kind() == Kind::DoneAck {
                let retained = local
                    .outgoing()
                    .ok_or("Done still owns transport custody")?;
                assert_eq!(retained.kind(), Kind::Done);
                saw_done_ack_before_local_ack = local.completed();
                local.outgoing_confirmed(retained)?;
            }
        }
        output(&mut a, &mut b, now, &mut number)?;
        output(&mut b, &mut a, now, &mut number)?;
        if local.completed() && remote.completed() {
            break;
        }
    }
    assert!(local.completed() && remote.as_ref().is_some_and(ConnectionReuse::completed));
    assert!(saw_done_ack_before_local_ack);
    assert_eq!(a.connection_route_incarnation(0)?, original_incarnation + 1);
    assert_eq!(b.connection_route_incarnation(0)?, original_incarnation + 1);
    assert_eq!(a.connection_owner_key(0)?, Some(next_key));
    let mut stale = old_wire;
    assert!(matches!(
        b.accept_authenticated_at(
            tick(101),
            tick(101),
            number + 1,
            old_emission.kind,
            &mut stale
        ),
        Err(engine::Error::Connections(Error::Incarnation))
    ));
    assert_eq!(
        b.failure(),
        None,
        "stale route cannot poison the new incarnation"
    );
    a.ingest_borrowed_at(tick(101), tick(101), &next_bytes, tick(5000))?;
    let next = a
        .admit_borrowed(tick(101))?
        .ok_or("new binding on same real owner")?;
    let engine::ProfileIdentity::Connection(next) = next.permit else {
        return Err("new recovered owner".into());
    };
    assert_eq!(next.owner, old.owner);
    assert_eq!(next.incarnation, original_incarnation + 1);
    assert!(next.record.record.0 > old.record.record.0);
    let mut delivered = Vec::new();
    for now in 102..=130 {
        output(&mut a, &mut b, now, &mut number)?;
        output(&mut b, &mut a, now, &mut number)?;
        delivered.extend(native(&mut b, now)?);
    }
    assert_eq!(delivered, vec![next_bytes]);
    assert_eq!(a.storage_usage(), before_a);
    assert_eq!(b.storage_usage(), before_b);
    assert_eq!(a.native_counts()?.admitted[0], 2);
    assert_eq!(b.native_counts()?.committed[0], 2);
    Ok(())
}
