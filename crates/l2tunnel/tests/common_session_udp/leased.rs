//! Full generic transaction custody, not a native data-profile switch fixture.
use super::*;
use std::collections::VecDeque;

const TRANSACTION: usize = Stream::Transaction as usize - 1;
const FRAME_BOUNDS: mg::Limits = mg::Limits {
    max_frame_bytes: 4096,
    max_requests: 4,
    max_retained_bytes: 16_384,
};

fn initial_deadline() -> tx::Tick {
    tx::Tick(ESTABLISHED_AT / 1000 + 5000)
}

fn tick(now: Duration) -> tx::Tick {
    tx::Tick(now.as_millis() as u64)
}

fn leased_peer(role: mg::Role) -> Result<tx::Peer<ModeConfig>> {
    let binding = streams::delivery_binding(
        mg::delivery::Binding {
            session: identity(role).session,
            lane: mg::LaneId(0),
            local_role: role,
            control_epoch: 1,
        },
        Stream::Transaction,
    )?;
    leased_peer_in(identity(role), binding.control_epoch)
}

fn leased_peer_in(identity: tx::Identity, transaction_epoch: u64) -> Result<tx::Peer<ModeConfig>> {
    let initial = ModeConfig::default();
    let next = ModeConfig {
        mapping: Mapping::Crc32,
        ..initial.clone()
    };
    Ok(tx::Peer::new_leased(
        identity,
        Epoch(10),
        initial.clone(),
        &[initial, next],
        tx::Settings {
            retry_ms: 20,
            phase_timeout_ms: 2000,
            reconcile_timeout_ms: 4000,
        },
        tx::LeaseSettings {
            session_expires: tx::Tick(10_000),
            max_operation_ms: 5000,
            transaction_epoch,
        },
        tx::Tick(ESTABLISHED_AT / 1000),
    )?)
}

fn replay_follower(
    commands: &[Vec<u8>],
    identity: tx::Identity,
    transaction_epoch: u64,
) -> Result<tx::Peer<ModeConfig>> {
    // These are pure negative custody vectors. Rebind the actual transcript to
    // another trusted local identity without claiming a second authenticated UDP
    // session; an existing real message proof must not complete that peer.
    let mut peer = leased_peer_in(identity, transaction_epoch)?;
    for command in commands {
        let frame = mg::Frame::decode(command, FRAME_BOUNDS)?;
        let header = mg::Header {
            session: identity.session,
            lane: identity.lane,
            ..frame.header
        };
        let mut bytes = vec![0; command.len()];
        mg::Frame {
            header,
            body: frame.body,
        }
        .encode(&mut bytes, FRAME_BOUNDS)?;
        let effects = peer.receive_until(
            mg::Ingress::AuthenticatedManagement {
                session: identity.session,
                lane: identity.lane,
                sender: mg::Role::Client,
            },
            &bytes,
            tx::Tick(ESTABLISHED_AT / 1000),
            initial_deadline(),
        )?;
        if matches!(effects.event, Some(tx::Event::Stage { .. })) {
            let staged = peer.staged(
                local_fence(mg::Role::Server)?,
                tx::Tick(ESTABLISHED_AT / 1000),
            )?;
            let Some(tx::Event::Drain {
                local,
                peer: remote,
            }) = staged.event
            else {
                return Err("missing replay drain".into());
            };
            peer.confirm_drained(&local, &remote, tx::Tick(ESTABLISHED_AT / 1000))?;
        }
    }
    assert_eq!(peer.phase(), tx::Phase::Idle);
    assert!(!peer.can_admit_data());
    Ok(peer)
}

fn local_fence(role: mg::Role) -> Result<tx::Fence> {
    let counts: Vec<_> = (0..16)
        .map(|channel| {
            if role == mg::Role::Client {
                channel + 1
            } else {
                2 * channel + 3
            }
        })
        .collect();
    Ok(tx::Fence::new(&counts)?)
}

struct Outgoing {
    header: mg::Header,
    body: Vec<u8>,
    envelope: Vec<u8>,
    id: SubmissionId,
    ticket: Option<Ticket>,
    deadline: tx::Tick,
    final_reply: bool,
    retired: bool,
}

struct Incoming {
    ticket: Ticket,
    bytes: Vec<u8>,
    final_reply: bool,
}

struct LeasedEndpoint {
    base: StreamEndpoint,
    peer: tx::Peer<ModeConfig>,
    outgoing: Vec<Outgoing>,
    incoming: Option<Incoming>,
    events: [usize; 3],
    next_envelope: u64,
    cached_retries: usize,
    proofs: usize,
    blocked_submissions: usize,
    received: Vec<Vec<u8>>,
    blocked_snapshot: Option<(SubmissionId, Vec<u8>, tx::Tick)>,
    blocked_acceptances: usize,
    retired_sources: Vec<Vec<u8>>,
}

impl LeasedEndpoint {
    fn new(mut base: StreamEndpoint) -> Result<Self> {
        base.gate = gate::Gate::new_transaction_bound(gate_settings(base.role)?)?;
        Ok(Self {
            peer: leased_peer(base.role)?,
            base,
            outgoing: Vec::new(),
            incoming: None,
            events: [0; 3],
            next_envelope: 1,
            cached_retries: 0,
            proofs: 0,
            blocked_submissions: 0,
            received: Vec::new(),
            blocked_snapshot: None,
            blocked_acceptances: 0,
            retired_sources: Vec::new(),
        })
    }

    fn retain_outbound(&mut self, bytes: Vec<u8>, force_fresh: bool) -> Result {
        let context = self.peer.outbound_context(&bytes)?;
        assert_eq!(context.origin(), scope()?);
        assert_eq!(context.expires(), initial_deadline());
        let frame = mg::Frame::decode(&bytes, FRAME_BOUNDS)?;
        // Whole-message ARQ already retries an immutable transmission. A second
        // Peer emission of that logical reply reuses its first retained envelope;
        // it does not create a second complete message or reset its deadline.
        if !force_fresh
            && self.outgoing.iter().any(|old| {
                !old.retired && old.header.same_request(frame.header) && old.body == frame.body
            })
        {
            return Ok(());
        }
        assert!(
            self.outgoing.len() < 8,
            "fixture exceeded bounded operation output slots"
        );
        let binding = control::Binding {
            session: identity(self.base.role).session,
            lane: mg::LaneId(0),
            sender: self.base.role,
            packet: mg::PacketNumber(self.next_envelope),
            scope: context.origin(),
        };
        let envelope = control::Envelope {
            binding,
            body: control::Body::Management(&bytes),
        };
        let mut encoded = vec![0; envelope.encoded_len(ENVELOPE_LIMITS)?];
        envelope.encode(&mut encoded, ENVELOPE_LIMITS)?;
        self.outgoing.push(Outgoing {
            header: frame.header,
            body: frame.body.to_vec(),
            envelope: encoded,
            id: SubmissionId(self.next_envelope),
            ticket: None,
            deadline: context.expires(),
            final_reply: context.is_final_reply(),
            retired: false,
        });
        self.next_envelope += 1;
        Ok(())
    }

    fn effects(&mut self, first: tx::Effects<ModeConfig>, now: Duration) -> Result {
        let mut effects = VecDeque::from([first]);
        while let Some(effect) = effects.pop_front() {
            if let Some(bytes) = effect.outbound {
                self.retain_outbound(bytes, false)?;
            }
            if let Some(event) = effect.event {
                match event {
                    tx::Event::Stage { .. } => {
                        self.events[0] += 1;
                        effects
                            .push_back(self.peer.staged(local_fence(self.base.role)?, tick(now))?);
                    }
                    tx::Event::Drain { local, peer } => {
                        assert_eq!(local, local_fence(self.base.role)?);
                        let remote = if self.base.role == mg::Role::Client {
                            mg::Role::Server
                        } else {
                            mg::Role::Client
                        };
                        assert_eq!(peer, local_fence(remote)?);
                        // Trusted injected facts in this protocol fixture; no
                        // native packet/device drain claim is made here.
                        effects.push_back(self.peer.confirm_drained(&local, &peer, tick(now))?);
                    }
                    tx::Event::Committed(_) => {
                        self.events[1] += 1;
                        let next = control::Scope {
                            epoch: self.peer.active_epoch(),
                            digest: tx::configuration_digest(self.peer.active_config())?,
                        };
                        self.base.gate.advance_scope(gate::DataPolicy {
                            scope: next,
                            recovery: None,
                            receipts: control::ReceiptPolicy::Cumulative,
                        })?;
                    }
                    tx::Event::Retired(epoch) => {
                        self.events[2] += 1;
                        assert_eq!(epoch, Epoch(10));
                        self.base.gate.retire_draining(scope()?)?;
                        assert!(self.peer.reader(epoch).is_none());
                        assert!(
                            !self.peer.can_admit_data(),
                            "Idle is not final reply custody"
                        );
                    }
                    other => return Err(format!("unexpected fixture event: {other:?}").into()),
                }
            }
        }
        Ok(())
    }

    fn submit_pending(&mut self, now: Duration) -> Result {
        for outgoing in &mut self.outgoing {
            if outgoing.ticket.is_some() {
                continue;
            }
            match self.base.owners[TRANSACTION].submit(
                outgoing.id,
                &outgoing.envelope,
                now,
                Duration::from_millis(outgoing.deadline.0),
            ) {
                Ok(ticket) => {
                    if let Some((id, bytes, deadline)) = self.blocked_snapshot.take() {
                        assert_eq!(
                            (outgoing.id, &outgoing.envelope, outgoing.deadline),
                            (id, &bytes, deadline)
                        );
                    }
                    outgoing.ticket = Some(ticket);
                }
                Err(messages::Error::Backpressure) => {
                    self.blocked_submissions += 1;
                    if let Some((id, bytes, deadline)) = &self.blocked_snapshot {
                        assert_eq!(
                            (outgoing.id, &outgoing.envelope, outgoing.deadline),
                            (*id, bytes, *deadline)
                        );
                    } else {
                        self.blocked_snapshot =
                            Some((outgoing.id, outgoing.envelope.clone(), outgoing.deadline));
                    }
                    break;
                }
                Err(error) => return Err(error.into()),
            }
        }
        Ok(())
    }

    fn dispatch(&mut self, now: Duration) -> Result {
        if self.incoming.is_none() {
            let Some(held) = self.base.owners[TRANSACTION].pending() else {
                return Ok(());
            };
            let ticket = held.ticket();
            let bytes = held.bytes().to_vec();
            let parsed = control::Envelope::decode(&bytes, ENVELOPE_LIMITS)?;
            let control::Body::Management(command) = parsed.body else {
                return Err("unexpected non-management body".into());
            };
            let frame = mg::Frame::decode(command, FRAME_BOUNDS)?;
            let is_cached = self
                .peer
                .cached_retry_authority(tick(now))?
                .is_some_and(|authority| authority.request().header.same_request(frame.header));
            let sender = if self.base.role == mg::Role::Client {
                mg::Role::Server
            } else {
                mg::Role::Client
            };
            let expiry = self
                .peer
                .operation()
                .map_or(initial_deadline(), |operation| operation.expires());
            let effects = self.base.gate.receive_transaction(
                &mut self.peer,
                mg::Ingress::AuthenticatedManagement {
                    session: identity(sender).session,
                    lane: mg::LaneId(0),
                    sender,
                },
                Stream::Transaction,
                &bytes,
                tick(now),
                expiry,
            )?;
            if self.base.role == mg::Role::Server {
                assert!(self.received.len() < 8);
                self.received.push(command.to_vec());
            }
            if is_cached {
                assert_eq!(frame.header.kind, mg::MessageKind::Retire);
                assert!(effects.event.is_none());
                self.cached_retries += 1;
            }
            let final_reply = self.base.role == mg::Role::Client
                && matches!(
                    frame.header.kind,
                    mg::MessageKind::Retire | mg::MessageKind::Reject
                );
            self.effects(effects, now)?;
            self.incoming = Some(Incoming {
                ticket,
                bytes,
                final_reply,
            });
        }
        let Some(incoming) = &self.incoming else {
            return Ok(());
        };
        match self.base.owners[TRANSACTION].accept_with_receipt(incoming.ticket, now) {
            Ok(proof) => {
                if incoming.final_reply {
                    let original = self.peer.operation();
                    let mut altered = incoming.bytes.clone();
                    altered[0] ^= 1;
                    assert_eq!(
                        self.peer.complete_accepted(&proof, &altered, tick(now)),
                        Err(tx::Error::Custody)
                    );
                    assert_eq!(
                        self.peer.complete_accepted(
                            &proof,
                            &incoming.bytes,
                            tx::Tick(tick(now).0 + 1)
                        ),
                        Err(tx::Error::Custody)
                    );
                    assert_eq!(self.peer.operation(), original);
                    self.peer
                        .complete_accepted(&proof, &incoming.bytes, tick(now))?;
                    assert_eq!(
                        self.peer
                            .complete_accepted(&proof, &incoming.bytes, tick(now)),
                        Err(tx::Error::Custody)
                    );
                    self.proofs += 1;
                } else if self.peer.phase() == tx::Phase::Idle && self.peer.operation().is_some() {
                    assert_eq!(
                        self.peer
                            .complete_accepted(&proof, &incoming.bytes, tick(now)),
                        Err(tx::Error::Custody)
                    );
                }
                self.incoming = None;
            }
            Err(messages::Error::Backpressure) => {
                self.blocked_acceptances += 1;
                let held = self.base.owners[TRANSACTION]
                    .pending()
                    .ok_or("lost held custody")?;
                assert_eq!(held.ticket(), incoming.ticket);
                assert_eq!(held.bytes(), incoming.bytes);
            }
            Err(error) => return Err(error.into()),
        }
        Ok(())
    }

    fn confirmations(&mut self, now: Duration) -> Result {
        for outgoing in &mut self.outgoing {
            if outgoing.retired {
                continue;
            }
            let Some(ticket) = outgoing.ticket else {
                continue;
            };
            if outgoing.final_reply {
                let Some(proof) = self.base.owners[TRANSACTION].confirmation(ticket, now)? else {
                    continue;
                };
                assert_eq!(self.peer.phase(), tx::Phase::Idle);
                assert!(!self.peer.can_admit_data());
                let original = self.peer.operation();
                let mut altered = outgoing.envelope.clone();
                altered[0] ^= 1;
                assert_eq!(
                    self.peer.complete_confirmed(&proof, &altered, tick(now)),
                    Err(tx::Error::Custody)
                );
                assert_eq!(
                    self.peer.complete_confirmed(
                        &proof,
                        &outgoing.envelope,
                        tx::Tick(tick(now).0 + 1)
                    ),
                    Err(tx::Error::Custody)
                );
                assert_eq!(self.peer.operation(), original);
                let mut other_session = identity(mg::Role::Server);
                other_session.session.0[15] ^= 1;
                let mut other_lane = identity(mg::Role::Server);
                other_lane.lane = mg::LaneId(7);
                for (binding, epoch) in [
                    (identity(mg::Role::Server), 5),
                    (other_session, 4),
                    (other_lane, 4),
                ] {
                    let mut other = replay_follower(&self.received, binding, epoch)?;
                    let before = other.operation();
                    assert_eq!(
                        other.complete_confirmed(&proof, &outgoing.envelope, tick(now)),
                        Err(tx::Error::Custody)
                    );
                    assert_eq!(other.operation(), before);
                    assert!(!other.can_admit_data());
                }
                self.peer
                    .complete_confirmed(&proof, &outgoing.envelope, tick(now))?;
                assert_eq!(
                    self.peer
                        .complete_confirmed(&proof, &outgoing.envelope, tick(now)),
                    Err(tx::Error::Custody)
                );
                self.proofs += 1;
            } else if !self.base.owners[TRANSACTION].confirmed(ticket, now)? {
                continue;
            }
            if self.base.role == mg::Role::Server
                && !outgoing.final_reply
                && self.blocked_submissions == 0
            {
                // Retain three confirmed entries until the real final reply hits
                // its metadata limit, then retry its exact original submission.
                continue;
            }
            self.base.owners[TRANSACTION].retire(ticket, now)?;
            outgoing.retired = true;
        }
        Ok(())
    }
}

fn pump_leased(endpoints: &mut [LeasedEndpoint; 2], now: Duration, withhold_reply: bool) -> Result {
    for side in 0..2 {
        let (left, right) = endpoints.split_at_mut(1);
        let (source, target) = if side == 0 {
            (&mut left[0], &mut right[0])
        } else {
            (&mut right[0], &mut left[0])
        };
        let mut allowance = 4096;
        for stream in Stream::ALL {
            let mut packet = [0; 300];
            while let Some(emission) =
                source
                    .base
                    .owner(stream)
                    .poll(now, allowance, &mut packet)?
            {
                let blocked_data = side == 1
                    && withhold_reply
                    && stream == Stream::Transaction
                    && matches!(
                        l2tunnel::recovery::inspect_packet(
                            &packet[..emission.bytes],
                            l2tunnel::recovery::RecoveryContext {
                                session: u128::from_be_bytes(identity(mg::Role::Client).session.0),
                                epoch: 4,
                                role: l2tunnel::recovery::EndpointRole::Initiator,
                            },
                            256
                        )?,
                        l2tunnel::recovery::PacketView::Data { .. }
                    );
                if side == 1 && source.events[2] == 1 && stream == Stream::Transaction {
                    let view = l2tunnel::recovery::inspect_packet(
                        &packet[..emission.bytes],
                        l2tunnel::recovery::RecoveryContext {
                            session: u128::from_be_bytes(identity(mg::Role::Client).session.0),
                            epoch: 4,
                            role: l2tunnel::recovery::EndpointRole::Initiator,
                        },
                        256,
                    )?;
                    if matches!(view, l2tunnel::recovery::PacketView::Data { .. })
                        && !source
                            .retired_sources
                            .iter()
                            .any(|old| old == &packet[..emission.bytes])
                    {
                        assert!(source.retired_sources.len() < 8);
                        source
                            .retired_sources
                            .push(packet[..emission.bytes].to_vec());
                    }
                }
                let cost = transfer_stream(
                    &mut source.base,
                    &mut target.base,
                    stream,
                    &packet[..emission.bytes],
                    now,
                    blocked_data,
                )?;
                assert_eq!(cost, emission.wire_bytes);
                allowance -= cost;
            }
        }
    }
    Ok(())
}

#[test]
fn leased_retire_retry_survives_scope_retirement_and_final_reply_loss_on_both_covers() -> Result {
    for appearance in [cover::Appearance::QuicLike, cover::Appearance::MediaLike] {
        let covers = covers(appearance)?;
        let sockets = sockets()?;
        let (roots, confirmations) = authenticated_roots(&sockets, covers)?;
        let [left_socket, right_socket] = sockets;
        let [left_root, right_root] = roots;
        let [left_confirmation, right_confirmation] = confirmations;
        let mut endpoints = [
            LeasedEndpoint::new(StreamEndpoint::new(
                left_socket,
                left_root,
                left_confirmation,
                covers[0],
                mg::Role::Client,
            )?)?,
            LeasedEndpoint::new(StreamEndpoint::new_with_message_limit(
                right_socket,
                right_root,
                right_confirmation,
                covers[1],
                mg::Role::Server,
                3,
            )?)?,
        ];
        let mut now = Duration::from_micros(ESTABLISHED_AT);
        let next = ModeConfig {
            mapping: Mapping::Crc32,
            ..ModeConfig::default()
        };
        let proposal = endpoints[0]
            .peer
            .propose_until(next, tick(now), initial_deadline())?;
        endpoints[0].effects(proposal, now)?;
        let mut round = 0u64;
        let mut ping = None;
        let mut pong = None;
        let mut received_pong = false;
        let mut retries = 0;
        let mut retry_at = Duration::ZERO;
        let mut final_blocked = false;
        let mut finished = false;
        for _ in 0..4000 {
            for endpoint in &mut endpoints {
                endpoint.submit_pending(now)?;
                endpoint.confirmations(now)?;
            }
            if endpoints[1].events[2] == 1 && !final_blocked {
                final_blocked = true;
            }
            if final_blocked && round < 130 && ping.is_none() {
                let bytes = envelope(
                    mg::Role::Client,
                    round + 1,
                    control::Body::Ping { nonce: round + 1 },
                )?;
                ping = Some(endpoints[0].base.owner(Stream::Liveness).submit(
                    SubmissionId(round + 1),
                    &bytes,
                    now,
                    Duration::from_millis(initial_deadline().0),
                )?);
            }
            let withhold_reply = final_blocked && endpoints[1].blocked_acceptances == 0;
            pump_leased(&mut endpoints, now, withhold_reply)?;
            for endpoint in &mut endpoints {
                endpoint.dispatch(now)?;
            }
            if let Some((ticket, bytes)) = admit_pending(&mut endpoints[1].base, Stream::Liveness)?
            {
                assert!(
                    matches!(control::Envelope::decode(&bytes, ENVELOPE_LIMITS)?.body,
                    control::Body::Ping { nonce } if nonce == round + 1)
                );
                endpoints[1]
                    .base
                    .owner(Stream::Liveness)
                    .accept(ticket, now)?;
                let bytes = envelope(
                    mg::Role::Server,
                    round + 1,
                    control::Body::Pong { nonce: round + 1 },
                )?;
                pong = Some(endpoints[1].base.owner(Stream::Liveness).submit(
                    SubmissionId(round + 1),
                    &bytes,
                    now,
                    Duration::from_millis(initial_deadline().0),
                )?);
            }
            if let Some((ticket, bytes)) = admit_pending(&mut endpoints[0].base, Stream::Liveness)?
            {
                assert!(
                    matches!(control::Envelope::decode(&bytes, ENVELOPE_LIMITS)?.body,
                    control::Body::Pong { nonce } if nonce == round + 1)
                );
                endpoints[0]
                    .base
                    .owner(Stream::Liveness)
                    .accept(ticket, now)?;
                received_pong = true;
            }
            if let (Some(left), Some(right)) = (ping, pong)
                && received_pong
                && endpoints[0]
                    .base
                    .owner(Stream::Liveness)
                    .confirmed(left, now)?
                && endpoints[1]
                    .base
                    .owner(Stream::Liveness)
                    .confirmed(right, now)?
            {
                endpoints[0]
                    .base
                    .owner(Stream::Liveness)
                    .retire(left, now)?;
                endpoints[1]
                    .base
                    .owner(Stream::Liveness)
                    .retire(right, now)?;
                ping = None;
                pong = None;
                received_pong = false;
                round += 1;
            }
            if round == 130 && retries < 3 && now >= retry_at {
                assert_eq!(endpoints[1].peer.phase(), tx::Phase::Idle);
                assert!(!endpoints[1].peer.can_admit_data());
                assert_eq!(
                    endpoints[1]
                        .peer
                        .operation()
                        .ok_or("missing final lease")?
                        .expires(),
                    initial_deadline()
                );
                let retry = endpoints[0]
                    .peer
                    .poll(tick(now))?
                    .outbound
                    .ok_or("missing RETIRE retry")?;
                let frame = mg::Frame::decode(&retry, FRAME_BOUNDS)?;
                assert_eq!(frame.header.kind, mg::MessageKind::Retire);
                let first = endpoints[0]
                    .outgoing
                    .iter()
                    .find(|out| out.header.kind == mg::MessageKind::Retire)
                    .ok_or("missing first RETIRE")?;
                assert!(first.header.same_request(frame.header));
                assert_ne!(first.header.packet, frame.header.packet);
                endpoints[0].retain_outbound(retry, true)?;
                retries += 1;
                retry_at = now + Duration::from_millis(20);
            }
            if retries == 3
                && endpoints.iter().all(|endpoint| {
                    endpoint.peer.operation().is_none()
                        && endpoint.proofs == 1
                        && endpoint.outgoing.iter().all(|out| out.retired)
                        && endpoint.base.owners.iter().all(|owner| {
                            owner.retained().outbound_messages == 0
                                && owner.retained().recovery.send_records == 0
                        })
                })
            {
                finished = true;
                break;
            }
            now += Duration::from_millis(1);
        }
        assert!(
            finished,
            "final receipt custody did not settle under the original cap"
        );
        assert_eq!(round, 130);
        assert_eq!(endpoints[1].cached_retries, 3);
        assert!(endpoints[1].blocked_submissions > 0);
        assert!(endpoints[1].blocked_acceptances > 0);
        assert!(endpoints[1].blocked_snapshot.is_none());
        let final_reply = &endpoints[1]
            .outgoing
            .iter()
            .find(|outgoing| outgoing.final_reply)
            .ok_or("missing retained final reply")?
            .envelope;
        assert!(endpoints[1].retired_sources.iter().any(|packet| {
            packet
                .windows(final_reply.len())
                .any(|bytes| bytes == final_reply)
        }));
        // After both real completion proofs, late copies of the original ARQ
        // sources must terminate below message dispatch. They are resealed with
        // fresh common Control nonces, not assigned fresh envelope/source IDs.
        now += Duration::from_millis(1);
        let mut allowance = 4096;
        let mut highest_source = 0;
        for packet in endpoints[1].retired_sources.clone() {
            let l2tunnel::recovery::PacketView::Data { source, .. } =
                l2tunnel::recovery::inspect_packet(
                    &packet,
                    l2tunnel::recovery::RecoveryContext {
                        session: u128::from_be_bytes(identity(mg::Role::Client).session.0),
                        epoch: 4,
                        role: l2tunnel::recovery::EndpointRole::Initiator,
                    },
                    256,
                )?
            else {
                return Err("captured non-source packet".into());
            };
            highest_source = highest_source.max(source.0);
            let (left, right) = endpoints.split_at_mut(1);
            let cost = transfer_stream(
                &mut right[0].base,
                &mut left[0].base,
                Stream::Transaction,
                &packet,
                now,
                false,
            )?;
            assert!(cost <= allowance);
            allowance -= cost;
            assert!(left[0].base.owner(Stream::Transaction).pending().is_none());
        }
        let (left, right) = endpoints.split_at_mut(1);
        let mut ack = [0; 300];
        let emission = left[0]
            .base
            .owner(Stream::Transaction)
            .poll(now, 4096, &mut ack)?
            .ok_or("missing delayed-source duplicate ACK")?;
        assert!(matches!(
            l2tunnel::recovery::inspect_packet(
                &ack[..emission.bytes],
                l2tunnel::recovery::RecoveryContext {
                    session: u128::from_be_bytes(identity(mg::Role::Client).session.0),
                    epoch: 4,
                    role: l2tunnel::recovery::EndpointRole::Responder,
                },
                256
            )?,
            l2tunnel::recovery::PacketView::Ack { prefix, .. } if prefix > highest_source
        ));
        let cost = transfer_stream(
            &mut left[0].base,
            &mut right[0].base,
            Stream::Transaction,
            &ack[..emission.bytes],
            now,
            false,
        )?;
        assert_eq!(cost, emission.wire_bytes);
        assert!(cost <= 4096);
        for _ in 0..4 {
            pump_leased(&mut endpoints, now, false)?;
            for endpoint in &mut endpoints {
                endpoint.dispatch(now)?;
            }
            now += Duration::from_millis(1);
        }
        for endpoint in &endpoints {
            assert_eq!(endpoint.events, [1, 1, 1]);
            assert_eq!(endpoint.peer.active_epoch(), Epoch(11));
            assert!(endpoint.peer.reader(Epoch(10)).is_none());
            assert!(endpoint.peer.can_admit_data());
            assert!(endpoint.base.owners.iter().all(|owner| {
                owner.retained().outbound_messages == 0
                    && owner.retained().recovery.send_records == 0
            }));
            assert_eq!(
                (
                    endpoint.base.socket.local_addr()?,
                    endpoint.base.socket.peer_addr()?
                ),
                endpoint.base.original
            );
            assert!(endpoint.base.records.next_number(record::Class::Control).0 > 128);
            assert!(endpoint.base.largest_generation > 0);
            assert_eq!(
                endpoint.base.gate.highest_packet(Stream::Liveness),
                Some(mg::PacketNumber(130))
            );
        }
        assert_eq!(
            endpoints[0].base.gate.highest_packet(Stream::Transaction),
            Some(mg::PacketNumber(4))
        );
        assert_eq!(
            endpoints[1].base.gate.highest_packet(Stream::Transaction),
            Some(mg::PacketNumber(7))
        );
    }
    Ok(())
}
