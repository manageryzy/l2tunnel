use super::*;
use crate::session_control::{Binding, ProfileTag};
use crate::{EndpointId, Frame, Header, LaneId, MessageKind, Role, SessionId};
use l2tunnel_core::{ConfigDigest, Delivery, Epoch, Mapping, ModeConfig, RecordLayout};

type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

const SESSION: SessionId = SessionId([0x43; 16]);
const LANE: LaneId = LaneId(7);
const NOW: tx::Tick = tx::Tick(1);
const EXPIRY: tx::Tick = tx::Tick(1_000);
const ENVELOPE_LIMITS: Limits = Limits {
    max_frame_bytes: 2_048,
    max_management_bytes: 1_024,
    max_feedback_bytes: 128,
};

fn opposite(role: Role) -> Role {
    match role {
        Role::Client => Role::Server,
        Role::Server => Role::Client,
    }
}

fn identity(role: Role) -> tx::Identity {
    tx::Identity {
        session: SESSION,
        role,
        local: EndpointId(if role == Role::Client { 1 } else { 2 }),
        remote: EndpointId(if role == Role::Client { 2 } else { 1 }),
        lane: LANE,
    }
}

fn verified(sender: Role) -> Ingress {
    Ingress::AuthenticatedManagement {
        session: SESSION,
        lane: LANE,
        sender,
    }
}

fn modes() -> (ModeConfig, ModeConfig) {
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

fn origin(epoch: u64, config: &ModeConfig) -> Result<Scope> {
    Ok(Scope {
        epoch: Epoch(epoch),
        digest: tx::configuration_digest(config)?,
    })
}

fn settings(role: Role, scope: Scope) -> GateSettings {
    GateSettings {
        binding: PeerBinding {
            session: SESSION,
            remote_role: opposite(role),
            control_lane: LANE,
            data_lanes: [Some(LANE), None],
        },
        control: Scope {
            epoch: Epoch(1),
            digest: ConfigDigest([0x91; 32]),
        },
        active: policy(scope),
        limits: ENVELOPE_LIMITS,
    }
}

fn policy(scope: Scope) -> DataPolicy {
    DataPolicy {
        scope,
        recovery: None,
        receipts: ReceiptPolicy::Cumulative,
    }
}

fn peer(role: Role, leased: bool) -> Result<tx::Peer> {
    let (initial, next) = modes();
    let supported = [initial.clone(), next];
    let timing = tx::Settings {
        retry_ms: 10,
        phase_timeout_ms: 100,
        reconcile_timeout_ms: 200,
    };
    Ok(if leased {
        tx::Peer::new_leased(
            identity(role),
            Epoch(10),
            initial,
            &supported,
            timing,
            tx::LeaseSettings {
                session_expires: tx::Tick(10_000),
                max_operation_ms: 2_000,
                transaction_epoch: 4,
            },
            tx::Tick(0),
        )?
    } else {
        tx::Peer::new(
            identity(role),
            Epoch(10),
            initial,
            &supported,
            timing,
            tx::Tick(0),
        )?
    })
}

fn envelope(sender: Role, packet: u64, scope: Scope, body: Body<'_>) -> Result<Vec<u8>> {
    let envelope = Envelope {
        binding: Binding {
            session: SESSION,
            lane: LANE,
            sender,
            packet: PacketNumber(packet),
            scope,
        },
        body,
    };
    let mut bytes = vec![0; envelope.encoded_len(ENVELOPE_LIMITS)?];
    envelope.encode(&mut bytes, ENVELOPE_LIMITS)?;
    Ok(bytes)
}

fn rewrite(command: &[u8], update: impl FnOnce(&mut Header, &mut Vec<u8>)) -> Result<Vec<u8>> {
    let frame = Frame::decode(command, crate::Limits::default())?;
    let mut header = frame.header;
    let mut body = frame.body.to_vec();
    update(&mut header, &mut body);
    let mut bytes = vec![0; crate::HEADER_LEN + body.len()];
    Frame {
        header,
        body: &body,
    }
    .encode(&mut bytes, crate::Limits::default())?;
    Ok(bytes)
}

fn wire(effects: tx::Effects) -> Result<Vec<u8>> {
    effects
        .outbound
        .ok_or_else(|| "missing transaction emission".into())
}

struct Endpoint {
    peer: tx::Peer,
    gate: Gate,
    role: Role,
}

impl Endpoint {
    fn new(role: Role) -> Result<Self> {
        let (initial, _) = modes();
        Ok(Self {
            peer: peer(role, true)?,
            gate: Gate::new_transaction_bound(settings(role, origin(10, &initial)?))?,
            role,
        })
    }

    fn next_packet(&self) -> u64 {
        self.gate
            .highest_packet(Stream::Transaction)
            .map_or(1, |packet| packet.0 + 1)
    }

    fn wrap(&self, scope: Scope, command: &[u8]) -> Result<Vec<u8>> {
        envelope(
            opposite(self.role),
            self.next_packet(),
            scope,
            Body::Management(command),
        )
    }

    fn receive(&mut self, scope: Scope, command: &[u8], now: tx::Tick) -> Result<tx::Effects> {
        let bytes = self.wrap(scope, command)?;
        Ok(self.gate.receive_transaction(
            &mut self.peer,
            verified(opposite(self.role)),
            Stream::Transaction,
            &bytes,
            now,
            EXPIRY,
        )?)
    }
}

#[derive(Debug, Eq, PartialEq)]
struct Observation {
    sequences: [Option<PacketNumber>; 3],
    active: DataPolicy,
    draining: Option<DataPolicy>,
    phase: tx::Phase,
    epoch: Epoch,
    config: ModeConfig,
    requests: usize,
    replies: usize,
    operation: Option<(Scope, tx::Tick)>,
    readers: [Option<(ModeConfig, tx::ReadDisposition)>; 2],
}

fn observe(endpoint: &Endpoint) -> Observation {
    Observation {
        sequences: Stream::ALL.map(|stream| endpoint.gate.highest_packet(stream)),
        active: endpoint.gate.active,
        draining: endpoint.gate.draining,
        phase: endpoint.peer.phase(),
        epoch: endpoint.peer.active_epoch(),
        config: endpoint.peer.active_config().clone(),
        requests: endpoint.peer.retained_requests(),
        replies: endpoint.peer.retained_replies(),
        operation: endpoint
            .peer
            .operation()
            .map(|operation| (operation.origin(), operation.expires())),
        readers: [Epoch(10), Epoch(11)].map(|epoch| {
            endpoint
                .peer
                .reader(epoch)
                .map(|reader| (reader.config.clone(), reader.disposition))
        }),
    }
}

fn refuse(
    endpoint: &mut Endpoint,
    ingress: Ingress,
    stream: Stream,
    bytes: &[u8],
    now: tx::Tick,
    expires: tx::Tick,
) -> Result<TransactionError> {
    let before = observe(endpoint);
    let error = endpoint
        .gate
        .receive_transaction(&mut endpoint.peer, ingress, stream, bytes, now, expires)
        .err();
    assert_eq!(observe(endpoint), before);
    error.ok_or_else(|| "unexpected transaction admission".into())
}

#[derive(Default)]
struct Events {
    stage: [u32; 2],
    commit: [u32; 2],
    retire: [u32; 2],
}

impl Events {
    fn record(&mut self, index: usize, effects: &tx::Effects) {
        match effects.event {
            Some(tx::Event::Stage { .. }) => self.stage[index] += 1,
            Some(tx::Event::Committed(_)) => self.commit[index] += 1,
            Some(tx::Event::Retired(_)) => self.retire[index] += 1,
            _ => {}
        }
    }
}

struct Pair {
    client: Endpoint,
    server: Endpoint,
    old: Scope,
    target: Scope,
    events: Events,
}

impl Pair {
    fn new() -> Result<Self> {
        let (initial, next) = modes();
        Ok(Self {
            client: Endpoint::new(Role::Client)?,
            server: Endpoint::new(Role::Server)?,
            old: origin(10, &initial)?,
            target: origin(11, &next)?,
            events: Events::default(),
        })
    }

    fn prepare(&mut self) -> Result<Vec<u8>> {
        let (_, next) = modes();
        let effects = self.client.peer.propose_until(next, tx::Tick(0), EXPIRY)?;
        self.events.record(0, &effects);
        wire(self.client.peer.staged(tx::Fence::new(&[3, 4])?, NOW)?)
    }

    // Reach an actual staged coordinator and committed follower. The returned
    // COMMIT_ACK still has the original data scope, never the target scope.
    fn committed_follower(&mut self) -> Result<Vec<u8>> {
        let local = tx::Fence::new(&[3, 4])?;
        let remote = tx::Fence::new(&[8, 9])?;
        let prepare = self.prepare()?;
        let effects = self.server.receive(self.old, &prepare, NOW)?;
        self.events.record(1, &effects);
        let ready = wire(self.server.peer.staged(remote.clone(), NOW)?)?;
        self.client.receive(self.old, &ready, NOW)?;
        let barrier = wire(self.client.peer.confirm_drained(&local, &remote, NOW)?)?;
        let effects = self.server.receive(self.old, &barrier, NOW)?;
        assert!(effects.outbound.is_none() && effects.event.is_none());
        let barrier_ack = wire(self.server.peer.confirm_drained(&remote, &local, NOW)?)?;
        let commit = wire(self.client.receive(self.old, &barrier_ack, NOW)?)?;
        let effects = self.server.receive(self.old, &commit, NOW)?;
        self.events.record(1, &effects);
        self.server.gate.advance_scope(policy(self.target))?;
        wire(effects)
    }

    // Deliberately lose the final reply after the follower removes its old reader.
    fn retired_follower(&mut self) -> Result<Vec<u8>> {
        let commit_ack = self.committed_follower()?;
        let effects = self.client.receive(self.old, &commit_ack, NOW)?;
        self.events.record(0, &effects);
        self.client.gate.advance_scope(policy(self.target))?;
        let retire = wire(effects)?;
        let effects = self.server.receive(self.old, &retire, NOW)?;
        self.events.record(1, &effects);
        self.server.gate.retire_draining(self.old)?;
        assert_eq!(self.server.peer.phase(), tx::Phase::Idle);
        assert!(self.server.peer.reader(self.old.epoch).is_none());
        let reply = wire(effects)?;
        assert_eq!(self.client.peer.phase(), tx::Phase::AwaitRetireAck);
        Ok(reply)
    }
}

#[test]
fn management_requires_both_explicit_bound_contracts_and_cannot_use_plain_admit() -> Result {
    let mut pair = Pair::new()?;
    let prepare = pair.prepare()?;
    let bytes = pair.server.wrap(pair.old, &prepare)?;
    let before = observe(&pair.server);
    assert_eq!(
        pair.server
            .gate
            .admit(verified(Role::Client), Stream::Transaction, &bytes)
            .err(),
        Some(Error::Kind)
    );
    assert_eq!(observe(&pair.server), before);

    for (bound_gate, leased_peer) in [(false, true), (true, false), (false, false)] {
        let gate = if bound_gate {
            Gate::new_transaction_bound(settings(Role::Server, pair.old))?
        } else {
            Gate::new(settings(Role::Server, pair.old))?
        };
        let mut endpoint = Endpoint {
            gate,
            peer: peer(Role::Server, leased_peer)?,
            role: Role::Server,
        };
        assert_eq!(
            refuse(
                &mut endpoint,
                verified(Role::Client),
                Stream::Transaction,
                &bytes,
                NOW,
                EXPIRY,
            )?,
            TransactionError::Contract
        );
    }
    let effects = pair.server.receive(pair.old, &prepare, NOW)?;
    assert!(matches!(effects.event, Some(tx::Event::Stage { .. })));
    Ok(())
}

#[test]
fn new_operation_caps_and_immutable_expiry_refuse_before_either_owner_advances() -> Result {
    let mut pair = Pair::new()?;
    let prepare = pair.prepare()?;
    let bytes = pair.server.wrap(pair.old, &prepare)?;
    for expires in [
        NOW,
        tx::Tick(0),
        tx::Tick(2_002),
        tx::Tick(10_001),
        tx::Tick(u64::MAX),
    ] {
        refuse(
            &mut pair.server,
            verified(Role::Client),
            Stream::Transaction,
            &bytes,
            NOW,
            expires,
        )?;
    }
    let effects = pair.server.receive(pair.old, &prepare, NOW)?;
    assert!(matches!(effects.event, Some(tx::Event::Stage { .. })));
    assert_eq!(observe(&pair.server).operation, Some((pair.old, EXPIRY)));

    let retry = wire(pair.client.peer.poll(tx::Tick(11))?)?;
    let retry_bytes = pair.server.wrap(pair.old, &retry)?;
    assert_eq!(
        refuse(
            &mut pair.server,
            verified(Role::Client),
            Stream::Transaction,
            &retry_bytes,
            tx::Tick(11),
            tx::Tick(EXPIRY.0 + 1),
        )?,
        TransactionError::Transaction(tx::Error::LeaseConflict)
    );
    // The same fresh inner and outer numbers remain available after refusal.
    assert_eq!(
        pair.server.receive(pair.old, &retry, tx::Tick(11))?,
        tx::Effects::default()
    );
    assert_eq!(observe(&pair.server).operation, Some((pair.old, EXPIRY)));
    Ok(())
}

#[test]
fn full_authenticated_binding_precedes_parse_and_endpoints_precede_peer_mutation() -> Result {
    let mut pair = Pair::new()?;
    let prepare = pair.prepare()?;
    let bytes = pair.server.wrap(pair.old, &prepare)?;
    let mut other_session = SESSION;
    other_session.0[15] ^= 1;
    for ingress in [
        Ingress::UserTraffic,
        Ingress::Unauthenticated,
        Ingress::AuthenticatedManagement {
            session: other_session,
            lane: LANE,
            sender: Role::Client,
        },
        Ingress::AuthenticatedManagement {
            session: SESSION,
            lane: LaneId(LANE.0 + 1),
            sender: Role::Client,
        },
        verified(Role::Server),
    ] {
        for input in [&[][..], bytes.as_slice()] {
            let error = refuse(
                &mut pair.server,
                ingress,
                Stream::Transaction,
                input,
                tx::Tick(20),
                EXPIRY,
            )?;
            assert!(matches!(
                error,
                TransactionError::Gate(
                    Error::Binding | Error::Legacy(crate::Error::UntrustedOrigin)
                )
            ));
        }
    }
    for at in [6, 15, 31] {
        let mut malformed = bytes.clone();
        malformed[at] ^= 1;
        refuse(
            &mut pair.server,
            verified(Role::Client),
            Stream::Transaction,
            &malformed,
            tx::Tick(20),
            EXPIRY,
        )?;
    }
    for local in [false, true] {
        let changed = rewrite(&prepare, |header, _| {
            if local {
                header.destination.0 += 1;
            } else {
                header.source.0 += 1;
            }
        })?;
        let changed = pair.server.wrap(pair.old, &changed)?;
        assert!(matches!(
            refuse(
                &mut pair.server,
                verified(Role::Client),
                Stream::Transaction,
                &changed,
                tx::Tick(20),
                EXPIRY,
            )?,
            TransactionError::Transaction(_)
        ));
    }
    // Failed preflights at t=20 must not advance the opaque peer clock either.
    pair.server.receive(pair.old, &prepare, NOW)?;
    Ok(())
}

#[test]
fn target_digest_and_actual_staged_reader_never_authorize_target_origin_management() -> Result {
    let mut pair = Pair::new()?;
    let ack = pair.committed_follower()?;
    assert_eq!(pair.client.peer.phase(), tx::Phase::AwaitCommitAck);
    let reader = pair
        .client
        .peer
        .reader(pair.target.epoch)
        .ok_or("missing staged reader")?;
    assert_eq!(reader.disposition, tx::ReadDisposition::Staged);
    assert_eq!(reader.config, &modes().1);
    assert_eq!(observe(&pair.client).operation, Some((pair.old, EXPIRY)));

    let wrong_digest = Scope {
        digest: pair.target.digest,
        ..pair.old
    };
    let bytes = pair.client.wrap(wrong_digest, &ack)?;
    refuse(
        &mut pair.client,
        verified(Role::Server),
        Stream::Transaction,
        &bytes,
        tx::Tick(20),
        EXPIRY,
    )?;
    let target_ack = rewrite(&ack, |header, _| header.source_epoch = pair.target.epoch)?;
    let bytes = pair.client.wrap(pair.target, &target_ack)?;
    refuse(
        &mut pair.client,
        verified(Role::Server),
        Stream::Transaction,
        &bytes,
        tx::Tick(20),
        EXPIRY,
    )?;
    let effects = pair.client.receive(pair.old, &ack, NOW)?;
    assert!(matches!(effects.event, Some(tx::Event::Committed(_))));
    assert_eq!(pair.client.peer.active_epoch(), pair.target.epoch);
    Ok(())
}

#[test]
fn retired_origin_admits_only_exact_real_cached_command_without_repeating_effects() -> Result {
    let mut pair = Pair::new()?;
    let lost_reply = pair.retired_follower()?;
    let retry = wire(pair.client.peer.poll(tx::Tick(11))?)?;
    let before = Frame::decode(&lost_reply, crate::Limits::default())?;
    let retry_frame = Frame::decode(&retry, crate::Limits::default())?;
    assert_eq!(retry_frame.header.kind, MessageKind::Retire);
    assert_eq!(observe(&pair.server).operation, Some((pair.old, EXPIRY)));

    for change in 0..7 {
        let changed = rewrite(&retry, |header, body| match change {
            0 => header.request.0 += 1,
            1 => header.kind = MessageKind::Commit,
            2 => header.ticket.attempt += 1,
            3 => header.ticket.epoch.0 += 1,
            4 => header.ticket.digest.0[31] ^= 1,
            5 => body[7] ^= 1,
            _ => body.push(0),
        })?;
        let bytes = pair.server.wrap(pair.old, &changed)?;
        refuse(
            &mut pair.server,
            verified(Role::Client),
            Stream::Transaction,
            &bytes,
            tx::Tick(20),
            EXPIRY,
        )?;
    }
    let wrong_origin = Scope {
        digest: pair.target.digest,
        ..pair.old
    };
    let bytes = pair.server.wrap(wrong_origin, &retry)?;
    refuse(
        &mut pair.server,
        verified(Role::Client),
        Stream::Transaction,
        &bytes,
        tx::Tick(20),
        EXPIRY,
    )?;
    let bytes = pair.server.wrap(pair.old, &retry)?;
    let state = observe(&pair.server);
    assert_eq!(
        pair.server
            .gate
            .admit(verified(Role::Client), Stream::Transaction, &bytes)
            .err(),
        Some(Error::Kind)
    );
    assert_eq!(observe(&pair.server), state);

    let effects = pair.server.receive(pair.old, &retry, tx::Tick(11))?;
    assert!(effects.event.is_none());
    let reply = wire(effects)?;
    let after = Frame::decode(&reply, crate::Limits::default())?;
    assert_eq!(after.header.kind, before.header.kind);
    assert_eq!(after.header.request, before.header.request);
    assert_eq!(after.header.ticket, before.header.ticket);
    assert_eq!(after.body, before.body);
    assert_ne!(after.header.packet, before.header.packet);
    assert!(pair.server.peer.reader(pair.old.epoch).is_none());

    let effects = pair.client.receive(pair.old, &reply, tx::Tick(11))?;
    pair.events.record(0, &effects);
    pair.client.gate.retire_draining(pair.old)?;
    assert_eq!(pair.events.stage, [1, 1]);
    assert_eq!(pair.events.commit, [1, 1]);
    assert_eq!(pair.events.retire, [1, 1]);
    assert_eq!(
        pair.client.peer.active_config(),
        pair.server.peer.active_config()
    );
    assert_eq!(pair.client.peer.phase(), tx::Phase::Idle);
    assert_eq!(pair.server.peer.phase(), tx::Phase::Idle);
    assert!(pair.client.peer.reader(pair.old.epoch).is_none());
    Ok(())
}

#[test]
fn retired_origin_keeps_only_the_exact_unaccepted_terminal_incoming_reply() -> Result {
    let mut pair = Pair::new()?;
    let final_reply = pair.retired_follower()?;
    // This actual coordinator retry was emitted before the delayed final reply
    // arrived. Its eventual follower response may arrive after local retirement.
    let delayed_request = wire(pair.client.peer.poll(tx::Tick(11))?)?;
    let effects = pair.client.receive(pair.old, &final_reply, tx::Tick(11))?;
    pair.events.record(0, &effects);
    pair.client.gate.retire_draining(pair.old)?;
    assert_eq!(pair.client.peer.phase(), tx::Phase::Idle);
    assert_eq!(pair.client.peer.retained_replies(), 0);
    assert!(pair.client.peer.reader(pair.old.epoch).is_none());
    assert!(pair.client.gate.draining.is_none());
    assert_eq!(observe(&pair.client).operation, Some((pair.old, EXPIRY)));

    let effects = pair
        .server
        .receive(pair.old, &delayed_request, tx::Tick(11))?;
    assert!(effects.event.is_none());
    let retry_reply = wire(effects)?;
    let first = Frame::decode(&final_reply, crate::Limits::default())?;
    let retry = Frame::decode(&retry_reply, crate::Limits::default())?;
    assert_eq!(retry.header.kind, MessageKind::Retire);
    assert_eq!(retry.header.request, first.header.request);
    assert_eq!(retry.header.ticket, first.header.ticket);
    assert_eq!(retry.body, first.body);
    assert_ne!(retry.header.packet, first.header.packet);

    for change in 0..5 {
        let changed = rewrite(&retry_reply, |header, body| match change {
            0 => header.request.0 += 1,
            1 => header.kind = MessageKind::CommitAck,
            2 => header.ticket.attempt += 1,
            3 => body[7] ^= 1,
            _ => body.push(0),
        })?;
        let bytes = pair.client.wrap(pair.old, &changed)?;
        refuse(
            &mut pair.client,
            verified(Role::Server),
            Stream::Transaction,
            &bytes,
            tx::Tick(20),
            EXPIRY,
        )?;
    }
    let bytes = pair.client.wrap(
        Scope {
            digest: pair.target.digest,
            ..pair.old
        },
        &retry_reply,
    )?;
    refuse(
        &mut pair.client,
        verified(Role::Server),
        Stream::Transaction,
        &bytes,
        tx::Tick(20),
        EXPIRY,
    )?;
    let bytes = pair.client.wrap(pair.old, &retry_reply)?;
    for now in [EXPIRY, tx::Tick(EXPIRY.0 + 1)] {
        assert_eq!(
            refuse(
                &mut pair.client,
                verified(Role::Server),
                Stream::Transaction,
                &bytes,
                now,
                EXPIRY,
            )?,
            TransactionError::Transaction(tx::Error::LeaseExpired)
        );
    }
    let before = observe(&pair.client);
    assert_eq!(
        pair.client
            .gate
            .admit(verified(Role::Server), Stream::Transaction, &bytes)
            .err(),
        Some(Error::Kind)
    );
    assert_eq!(observe(&pair.client), before);
    let effects = pair.client.receive(pair.old, &retry_reply, tx::Tick(11))?;
    assert_eq!(effects, tx::Effects::default());
    assert_eq!(observe(&pair.client).operation, Some((pair.old, EXPIRY)));
    assert_eq!(pair.events.stage, [1, 1]);
    assert_eq!(pair.events.commit, [1, 1]);
    assert_eq!(pair.events.retire, [1, 1]);
    assert_eq!(
        pair.client.gate.highest_packet(Stream::Transaction),
        Some(PacketNumber(5))
    );
    Ok(())
}

#[test]
fn active_draining_and_retired_origins_cannot_bypass_original_operation_expiry() -> Result {
    for stage in 0..3 {
        let mut pair = Pair::new()?;
        let retry = if stage == 0 {
            let prepare = pair.prepare()?;
            pair.server.receive(pair.old, &prepare, NOW)?;
            pair.server.peer.staged(tx::Fence::new(&[8, 9])?, NOW)?;
            wire(pair.client.peer.poll(tx::Tick(11))?)?
        } else if stage == 1 {
            pair.committed_follower()?;
            // The original COMMIT is still outstanding at the coordinator.
            wire(pair.client.peer.poll(tx::Tick(11))?)?
        } else {
            pair.retired_follower()?;
            wire(pair.client.peer.poll(tx::Tick(11))?)?
        };
        let bytes = pair.server.wrap(pair.old, &retry)?;
        let before = observe(&pair.server);
        assert_eq!(
            pair.server
                .gate
                .admit(verified(Role::Client), Stream::Transaction, &bytes)
                .err(),
            Some(Error::Kind)
        );
        assert_eq!(observe(&pair.server), before);
        for now in [EXPIRY, tx::Tick(EXPIRY.0 + 1)] {
            assert_eq!(
                refuse(
                    &mut pair.server,
                    verified(Role::Client),
                    Stream::Transaction,
                    &bytes,
                    now,
                    EXPIRY,
                )?,
                TransactionError::Transaction(tx::Error::LeaseExpired)
            );
        }
        assert_eq!(
            refuse(
                &mut pair.server,
                verified(Role::Client),
                Stream::Transaction,
                &bytes,
                tx::Tick(11),
                tx::Tick(EXPIRY.0 + 1),
            )?,
            TransactionError::Transaction(tx::Error::LeaseConflict)
        );
        assert_eq!(observe(&pair.server).operation, Some((pair.old, EXPIRY)));
        // Read-only expiry refusals did not mutate Peer.now or consume numbers.
        let effects = pair.server.receive(pair.old, &retry, tx::Tick(11))?;
        assert!(effects.event.is_none());
        assert!(effects.outbound.is_some());
    }
    Ok(())
}

#[test]
fn wrong_stream_and_non_management_refuse_without_consuming_other_streams() -> Result {
    let mut pair = Pair::new()?;
    let prepare = pair.prepare()?;
    let bytes = pair.server.wrap(pair.old, &prepare)?;
    for stream in [Stream::Liveness, Stream::DataFeedback] {
        assert_eq!(
            refuse(
                &mut pair.server,
                verified(Role::Client),
                stream,
                &bytes,
                NOW,
                EXPIRY,
            )?,
            TransactionError::Gate(Error::Kind)
        );
    }
    for body in [
        Body::Ping { nonce: 1 },
        Body::Pong { nonce: 1 },
        Body::ProfileControl {
            tag: ProfileTag::SwiftPolicyV1,
            bytes: &[1],
        },
        Body::NativeReceipt {
            lane: LANE,
            receipt: NativeReceipt::Cumulative { records: 1 },
        },
    ] {
        let bytes = envelope(Role::Client, 1, pair.old, body)?;
        assert_eq!(
            refuse(
                &mut pair.server,
                verified(Role::Client),
                Stream::Transaction,
                &bytes,
                NOW,
                EXPIRY,
            )?,
            TransactionError::Gate(Error::Kind)
        );
    }
    let ping = envelope(
        Role::Client,
        1,
        pair.server.gate.settings.control,
        Body::Ping { nonce: 1 },
    )?;
    pair.server
        .gate
        .admit(verified(Role::Client), Stream::Liveness, &ping)?;
    let receipt = envelope(
        Role::Client,
        1,
        pair.old,
        Body::NativeReceipt {
            lane: LANE,
            receipt: NativeReceipt::Cumulative { records: 1 },
        },
    )?;
    pair.server
        .gate
        .admit(verified(Role::Client), Stream::DataFeedback, &receipt)?;
    pair.server.receive(pair.old, &prepare, NOW)?;
    assert_eq!(
        Stream::ALL.map(|stream| pair.server.gate.highest_packet(stream)),
        [Some(PacketNumber(1)); 3]
    );
    Ok(())
}

#[test]
fn semantic_peer_failure_is_terminal_without_outer_sequence_commit_or_rollback_claim() -> Result {
    let mut pair = Pair::new()?;
    let prepare = pair.prepare()?;
    pair.server.receive(pair.old, &prepare, NOW)?;
    let before = observe(&pair.server);
    assert_eq!(before.phase, tx::Phase::FollowerStaging);
    // Fresh command identities and the exact operation ticket pass admission,
    // but a BARRIER before actual follower staging violates the existing FSM.
    let invalid = rewrite(&prepare, |header, body| {
        header.kind = MessageKind::Barrier;
        header.packet.0 += 1;
        header.request.0 += 1;
        body.truncate(8);
    })?;
    let bytes = pair.server.wrap(pair.old, &invalid)?;
    let error = pair
        .server
        .gate
        .receive_transaction(
            &mut pair.server.peer,
            verified(Role::Client),
            Stream::Transaction,
            &bytes,
            NOW,
            EXPIRY,
        )
        .err();
    assert_eq!(
        error,
        Some(TransactionError::Transaction(tx::Error::Unexpected))
    );
    assert_eq!(pair.server.peer.phase(), tx::Phase::Failed);
    assert_eq!(
        pair.server.gate.highest_packet(Stream::Transaction),
        before.sequences[0]
    );
    assert_eq!(pair.server.peer.active_epoch(), pair.old.epoch);
    assert!(pair.server.peer.reader(pair.old.epoch).is_none());
    // The transaction's internal admission owner may already retain the frame;
    // this path is terminal, not an atomic rollback or an alternate-path retry.
    assert!(pair.server.peer.retained_requests() > before.requests);
    Ok(())
}

#[test]
fn joint_sequence_gaps_and_replay_refuse_before_the_transaction_owner_changes() -> Result {
    let mut pair = Pair::new()?;
    let prepare = pair.prepare()?;
    for packet in [2, u64::MAX] {
        let bytes = envelope(Role::Client, packet, pair.old, Body::Management(&prepare))?;
        assert_eq!(
            refuse(
                &mut pair.server,
                verified(Role::Client),
                Stream::Transaction,
                &bytes,
                tx::Tick(20),
                EXPIRY,
            )?,
            TransactionError::Gate(Error::Sequence)
        );
    }
    let bytes = pair.server.wrap(pair.old, &prepare)?;
    pair.server.receive(pair.old, &prepare, NOW)?;
    assert_eq!(
        refuse(
            &mut pair.server,
            verified(Role::Client),
            Stream::Transaction,
            &bytes,
            tx::Tick(20),
            EXPIRY,
        )?,
        TransactionError::Gate(Error::Legacy(crate::Error::PacketReplay))
    );
    let retry = wire(pair.client.peer.poll(tx::Tick(11))?)?;
    assert_eq!(
        pair.server.receive(pair.old, &retry, tx::Tick(11))?,
        tx::Effects::default()
    );
    assert_eq!(
        pair.server.gate.highest_packet(Stream::Transaction),
        Some(PacketNumber(2))
    );
    Ok(())
}
