//! Explicit draft control streams over one existing authenticated UDP owner.
use super::*;
use l2tunnel::core::{Epoch, Mapping, ModeConfig};
use mg::{
    control_streams::{self as streams, Stream, gate},
    messages::{self, SubmissionId, Ticket},
    session_control as control, transaction as tx,
};

const CONTROL_SCOPE: control::Scope = control::Scope {
    epoch: Epoch(1),
    digest: l2tunnel::core::ConfigDigest([4; 32]),
};
const FRAME_LIMITS: streams::Limits = streams::Limits {
    max_packet_bytes: 300,
};
const ENVELOPE_LIMITS: control::Limits = control::Limits {
    max_frame_bytes: 4096,
    max_management_bytes: 4016,
    max_feedback_bytes: 256,
};

fn scope() -> Result<control::Scope> {
    Ok(control::Scope {
        epoch: Epoch(10),
        digest: tx::configuration_digest(&ModeConfig::default())?,
    })
}

fn make_gate(local_role: mg::Role) -> Result<gate::Gate> {
    Ok(gate::Gate::new(gate::GateSettings {
        binding: control::PeerBinding {
            session: mg::SessionId([31; 16]),
            remote_role: if local_role == mg::Role::Client {
                mg::Role::Server
            } else {
                mg::Role::Client
            },
            control_lane: mg::LaneId(0),
            data_lanes: [Some(mg::LaneId(0)), None],
        },
        control: CONTROL_SCOPE,
        active: gate::DataPolicy {
            scope: scope()?,
            recovery: None,
            receipts: control::ReceiptPolicy::Cumulative,
        },
        limits: ENVELOPE_LIMITS,
    })?)
}

fn identity(role: mg::Role) -> tx::Identity {
    tx::Identity {
        session: mg::SessionId([31; 16]),
        role,
        local: mg::EndpointId(if role == mg::Role::Client { 11 } else { 22 }),
        remote: mg::EndpointId(if role == mg::Role::Client { 22 } else { 11 }),
        lane: mg::LaneId(0),
    }
}

fn peer(role: mg::Role) -> Result<tx::Peer<ModeConfig>> {
    let initial = ModeConfig::default();
    let next = ModeConfig {
        mapping: Mapping::Crc32,
        ..initial.clone()
    };
    Ok(tx::Peer::new(
        identity(role),
        Epoch(10),
        initial.clone(),
        &[initial, next],
        tx::Settings {
            retry_ms: 20,
            phase_timeout_ms: 2000,
            reconcile_timeout_ms: 4000,
        },
        tx::Tick(0),
    )?)
}

fn envelope(sender: mg::Role, packet: u64, body: control::Body<'_>) -> Result<Vec<u8>> {
    let envelope = control::Envelope {
        binding: control::Binding {
            session: identity(sender).session,
            lane: mg::LaneId(0),
            sender,
            packet: mg::PacketNumber(packet),
            scope: if matches!(
                body,
                control::Body::Ping { .. } | control::Body::Pong { .. }
            ) {
                CONTROL_SCOPE
            } else {
                scope()?
            },
        },
        body,
    };
    let mut bytes = vec![0; envelope.encoded_len(ENVELOPE_LIMITS)?];
    envelope.encode(&mut bytes, ENVELOPE_LIMITS)?;
    Ok(bytes)
}

struct StreamEndpoint {
    socket: UdpSocket,
    original: (SocketAddr, SocketAddr),
    role: mg::Role,
    records: record::Records,
    owners: Vec<messages::Owner>,
    gate: gate::Gate,
    outer: u32,
    largest_generation: u64,
    _confirmation: hs::ConfirmationCache,
}

impl StreamEndpoint {
    fn new(
        socket: UdpSocket,
        root: security::SessionRoot,
        confirmation: hs::ConfirmationCache,
        cover: cover::Config,
        role: mg::Role,
    ) -> Result<Self> {
        let records = record::Records::new(
            root,
            security::LaneId(0),
            security::Limits {
                max_body_bytes: 1024,
                packets_per_key: 8,
                max_body_bytes_per_key: 1 << 20,
            },
            security::Protection::ChaCha20Poly1305,
            cover,
            record::Scope {
                epoch: security::Epoch(1),
                configuration: security::ConfigDigest(CONTROL_SCOPE.digest.0),
            },
            record::Scope {
                epoch: security::Epoch(10),
                configuration: security::ConfigDigest(scope()?.digest.0),
            },
        )?;
        let wire_overhead = records
            .capacity(FRAME_LIMITS.max_packet_bytes + streams::HEADER_BYTES)?
            .packet_bytes
            - FRAME_LIMITS.max_packet_bytes
            + 28;
        let binding = mg::delivery::Binding {
            session: identity(role).session,
            lane: mg::LaneId(0),
            local_role: role,
            control_epoch: 1,
        };
        let settings = messages::Settings {
            delivery: mg::delivery::Settings {
                recovery: l2tunnel::recovery::ArqConfig {
                    max_source_bytes: 256,
                    send_bytes: 1024,
                    receive_bytes: 1024,
                    send_records: 4,
                    receive_records: 4,
                    initial_rto: Duration::from_millis(10),
                    maximum_rto: Duration::from_millis(100),
                    ack_delay: Duration::ZERO,
                    max_retries: 32,
                },
                interval: Duration::from_millis(1),
                packets_per_interval: 16,
                bytes_per_interval: 16_384,
                wire_overhead,
            },
            path_mtu: 1500,
            max_message_bytes: 4096,
            max_outbound_messages: 4,
            max_outbound_bytes: 65_536,
            max_fragments: 128,
            max_reassembly_bytes: 32_768,
            max_incomplete_messages: 4,
            message_lifetime: Duration::from_secs(5),
            work_per_call: 4,
        };
        let owners = Stream::ALL
            .into_iter()
            .map(|stream| {
                messages::Owner::new(
                    settings,
                    streams::delivery_binding(binding, stream)?,
                    Duration::from_micros(ESTABLISHED_AT),
                    Duration::from_secs(10),
                )
                .map_err(Box::<dyn Error>::from)
            })
            .collect::<Result<Vec<_>>>()?;
        let gate = make_gate(role)?;
        Ok(Self {
            original: (socket.local_addr()?, socket.peer_addr()?),
            socket,
            role,
            records,
            owners,
            gate,
            outer: 0,
            largest_generation: 0,
            _confirmation: confirmation,
        })
    }

    fn owner(&mut self, stream: Stream) -> &mut messages::Owner {
        &mut self.owners[stream as usize - 1]
    }
}

fn transfer_stream(
    source: &mut StreamEndpoint,
    target: &mut StreamEndpoint,
    stream: Stream,
    packet: &[u8],
    now: Duration,
    drop_transaction: bool,
) -> Result<usize> {
    let mut body = [0; 1024];
    let bytes = streams::Frame { stream, packet }.encode(&mut body, FRAME_LIMITS)?;
    let mut workspace = [0; 2048];
    let mut wire = [0; 2048];
    // Every ARQ retry gets a fresh common Control nonce; streams create no
    // cryptographic owner and never reset that counter or its replay window.
    let sealed = source.records.seal(
        record::Class::Control,
        cover::PacketMeta {
            phase: cover::Phase::Established,
            packet_number: cover::PacketNumber(source.outer),
            media_timestamp: cover::MediaTimestamp(source.outer.wrapping_mul(960)),
        },
        &body[..bytes],
        &mut workspace,
        &mut wire,
    )?;
    source.outer += 1;
    if drop_transaction && stream == Stream::Transaction {
        return Ok(sealed.bytes + 28);
    }
    assert_eq!(source.socket.send(&wire[..sealed.bytes])?, sealed.bytes);
    let mut incoming = [0; 2048];
    let bytes = target.socket.recv(&mut incoming)?;
    let mut plain = [0; 2048];
    let opened = target
        .records
        .open(&incoming[..bytes], &mut workspace, &mut plain)?;
    assert_eq!(opened.class, record::Class::Control);
    assert_eq!(opened.scope, target.records.control_scope());
    target.largest_generation = target.largest_generation.max(opened.generation.0);
    let decoded = streams::Frame::decode(&plain[..opened.bytes], FRAME_LIMITS)?;
    assert_eq!(decoded.stream, stream);
    target.owner(decoded.stream).receive(
        mg::Ingress::AuthenticatedManagement {
            session: identity(source.role).session,
            lane: mg::LaneId(0),
            sender: source.role,
        },
        decoded.packet,
        now,
    )?;
    Ok(sealed.bytes + 28)
}

fn pump(endpoints: &mut [StreamEndpoint; 2], now: Duration, blocked: bool) -> Result {
    for side in 0..2 {
        let (left, right) = endpoints.split_at_mut(1);
        let (source, target) = if side == 0 {
            (&mut left[0], &mut right[0])
        } else {
            (&mut right[0], &mut left[0])
        };
        // A single allowance is debited across all logical streams, including
        // intentionally lost emissions; independent owners do not multiply it.
        let mut allowance = 4096;
        for stream in Stream::ALL {
            let mut packet = [0; 300];
            while let Some(emission) = source.owner(stream).poll(now, allowance, &mut packet)? {
                let cost = transfer_stream(
                    source,
                    target,
                    stream,
                    &packet[..emission.bytes],
                    now,
                    blocked,
                )?;
                assert_eq!(cost, emission.wire_bytes);
                assert!(cost <= allowance);
                allowance -= cost;
            }
        }
    }
    Ok(())
}

fn admit_pending(
    endpoint: &mut StreamEndpoint,
    stream: Stream,
) -> Result<Option<(Ticket, Vec<u8>)>> {
    let Some(delivery) = endpoint.owner(stream).pending() else {
        return Ok(None);
    };
    let ticket = delivery.ticket();
    let bytes = delivery.bytes().to_vec();
    let sender = if endpoint.role == mg::Role::Client {
        mg::Role::Server
    } else {
        mg::Role::Client
    };
    endpoint.gate.admit(
        mg::Ingress::AuthenticatedManagement {
            session: identity(sender).session,
            lane: mg::LaneId(0),
            sender,
        },
        stream,
        &bytes,
    )?;
    Ok(Some((ticket, bytes)))
}

#[test]
fn blocked_transaction_cannot_age_out_after_130_authenticated_ping_pongs() -> Result {
    for appearance in [cover::Appearance::QuicLike, cover::Appearance::MediaLike] {
        let covers = covers(appearance)?;
        let sockets = sockets()?;
        let (roots, confirmations) = authenticated_roots(&sockets, covers)?;
        let [left_socket, right_socket] = sockets;
        let [left_root, right_root] = roots;
        let [left_confirmation, right_confirmation] = confirmations;
        let mut endpoints = [
            StreamEndpoint::new(
                left_socket,
                left_root,
                left_confirmation,
                covers[0],
                mg::Role::Client,
            )?,
            StreamEndpoint::new(
                right_socket,
                right_root,
                right_confirmation,
                covers[1],
                mg::Role::Server,
            )?,
        ];
        let mut coordinator = peer(mg::Role::Client)?;
        let mut follower = peer(mg::Role::Server)?;
        let next = ModeConfig {
            mapping: Mapping::Crc32,
            ..ModeConfig::default()
        };
        assert!(matches!(
            coordinator.propose(next, tx::Tick(0))?.event,
            Some(tx::Event::Stage { .. })
        ));
        let management = coordinator
            .staged(tx::Fence::new(&[0; 16])?, tx::Tick(0))?
            .outbound
            .ok_or("missing genuine PREPARE")?;
        let prepare = envelope(mg::Role::Client, 1, control::Body::Management(&management))?;
        assert_eq!(prepare.len(), 354);
        let mut now = Duration::from_micros(ESTABLISHED_AT);
        let original_deadline = now + Duration::from_secs(5);
        let transaction = endpoints[0].owner(Stream::Transaction).submit(
            SubmissionId(1),
            &prepare,
            now,
            original_deadline,
        )?;
        let mut round = 0u64;
        let mut ping: Option<Ticket> = None;
        let mut pong: Option<Ticket> = None;
        let mut received_pong = false;
        let mut admitted = false;
        let mut finished = false;
        for _ in 0..4000 {
            if round < 130 && ping.is_none() {
                let bytes = envelope(
                    mg::Role::Client,
                    round + 1,
                    control::Body::Ping { nonce: round + 1 },
                )?;
                ping = Some(endpoints[0].owner(Stream::Liveness).submit(
                    SubmissionId(round + 1),
                    &bytes,
                    now,
                    original_deadline,
                )?);
            }
            pump(&mut endpoints, now, round < 130)?;
            if let Some((ticket, bytes)) = admit_pending(&mut endpoints[1], Stream::Liveness)? {
                assert!(
                    matches!(control::Envelope::decode(&bytes, ENVELOPE_LIMITS)?.body,
                    control::Body::Ping { nonce } if nonce == round + 1)
                );
                endpoints[1].owner(Stream::Liveness).accept(ticket, now)?;
                let bytes = envelope(
                    mg::Role::Server,
                    round + 1,
                    control::Body::Pong { nonce: round + 1 },
                )?;
                assert!(pong.is_none());
                pong = Some(endpoints[1].owner(Stream::Liveness).submit(
                    SubmissionId(round + 1),
                    &bytes,
                    now,
                    original_deadline,
                )?);
            }
            if let Some((ticket, bytes)) = admit_pending(&mut endpoints[0], Stream::Liveness)? {
                assert!(
                    matches!(control::Envelope::decode(&bytes, ENVELOPE_LIMITS)?.body,
                    control::Body::Pong { nonce } if nonce == round + 1)
                );
                endpoints[0].owner(Stream::Liveness).accept(ticket, now)?;
                received_pong = true;
            }
            if let (Some(left), Some(right)) = (ping, pong)
                && received_pong
                && endpoints[0].owner(Stream::Liveness).confirmed(left, now)?
                && endpoints[1].owner(Stream::Liveness).confirmed(right, now)?
            {
                endpoints[0].owner(Stream::Liveness).retire(left, now)?;
                endpoints[1].owner(Stream::Liveness).retire(right, now)?;
                ping = None;
                pong = None;
                received_pong = false;
                round += 1;
            }
            if round < 130 {
                assert!(endpoints[1].owner(Stream::Transaction).pending().is_none());
                assert!(
                    !endpoints[0]
                        .owner(Stream::Transaction)
                        .confirmed(transaction, now)?
                );
            } else if let Some((ticket, bytes)) =
                admit_pending(&mut endpoints[1], Stream::Transaction)?
            {
                assert_eq!(bytes, prepare);
                assert!(!admitted);
                let parsed = control::Envelope::decode(&bytes, ENVELOPE_LIMITS)?;
                let control::Body::Management(command) = parsed.body else {
                    return Err("wrong transaction body".into());
                };
                let outcome = follower.receive(
                    mg::Ingress::AuthenticatedManagement {
                        session: identity(mg::Role::Client).session,
                        lane: mg::LaneId(0),
                        sender: mg::Role::Client,
                    },
                    command,
                    tx::Tick(now.as_millis() as u64),
                )?;
                assert!(matches!(outcome.event, Some(tx::Event::Stage { .. })));
                assert_eq!(follower.active_epoch(), Epoch(10));
                endpoints[1]
                    .owner(Stream::Transaction)
                    .accept(ticket, now)?;
                admitted = true;
            }
            if admitted
                && endpoints[0]
                    .owner(Stream::Transaction)
                    .confirmed(transaction, now)?
            {
                endpoints[0]
                    .owner(Stream::Transaction)
                    .retire(transaction, now)?;
                finished = true;
                break;
            }
            now += Duration::from_millis(1);
        }
        assert_eq!(round, 130);
        assert!(admitted);
        assert!(
            finished,
            "whole-message acceptance never reached the original sender"
        );
        for endpoint in &endpoints {
            assert_eq!(
                (endpoint.socket.local_addr()?, endpoint.socket.peer_addr()?),
                endpoint.original
            );
            assert!(endpoint.records.next_number(record::Class::Control).0 > 128);
            assert!(endpoint.largest_generation > 0);
        }
        assert_eq!(follower.active_epoch(), Epoch(10));
    }
    Ok(())
}
