//! Original-socket integration fixture, not a native device or client-service test.
use l2tunnel::{
    cover, handshake as hs, management as mg, secure_record as record, security, swift,
};
use std::{
    error::Error,
    net::{SocketAddr, UdpSocket},
    time::Duration,
};
use zeroize::Zeroizing;

type Result<T = ()> = std::result::Result<T, Box<dyn Error>>;
const ESTABLISHED_AT: u64 = 12_000;

struct TestEntropy(u8);
impl hs::Entropy for TestEntropy {
    fn fill(&mut self, destination: &mut [u8; 32]) -> std::result::Result<(), hs::EntropyError> {
        // Reproducible fixture entropy only; never a runtime entropy provider.
        destination.fill(self.0);
        self.0 = self.0.wrapping_add(1);
        Ok(())
    }
}

fn covers(appearance: cover::Appearance) -> Result<[cover::Config; 2]> {
    let make = |local, peer, local_ssrc, peer_ssrc| {
        cover::Config::new(
            appearance,
            cover::ConnectionIds {
                local: cover::ConnectionId([local; 8]),
                peer: cover::ConnectionId([peer; 8]),
            },
            cover::MediaConfig {
                local_ssrc: cover::Ssrc(local_ssrc),
                peer_ssrc: cover::Ssrc(peer_ssrc),
                payload_type: 96,
            },
            cover::Limits {
                max_packet_bytes: 1472,
                max_protected_bytes: 1400,
            },
        )
    };
    Ok([make(1, 2, 101, 202)?, make(2, 1, 202, 101)?])
}

fn sockets() -> Result<[UdpSocket; 2]> {
    let sockets = [
        UdpSocket::bind("127.0.0.1:0")?,
        UdpSocket::bind("127.0.0.1:0")?,
    ];
    for side in 0..2 {
        sockets[side].connect(sockets[1 - side].local_addr()?)?;
        sockets[side].set_read_timeout(Some(Duration::from_secs(2)))?;
    }
    Ok(sockets)
}

fn authenticated_roots(
    sockets: &[UdpSocket; 2],
    covers: [cover::Config; 2],
) -> Result<([security::SessionRoot; 2], [hs::ConfirmationCache; 2])> {
    let secrets = [
        hs::LocalSecret::new(Zeroizing::new([11; 32])),
        hs::LocalSecret::new(Zeroizing::new([22; 32])),
    ];
    let peers = [secrets[1].public_key(), secrets[0].public_key()];
    let binding = hs::Binding {
        session: security::SessionId([31; 16]),
        configuration: [41; 32],
        carrier: [if covers[0].appearance() == cover::Appearance::QuicLike {
            51
        } else {
            52
        }; 32],
        outer: [61; 32],
        member: [71; 32],
    };
    let [initiator, responder] = secrets;
    let make = |role, local, peer, seed| {
        hs::Handshake::new(
            hs::Config {
                role,
                profile: hs::Profile::Ik,
                binding,
                deadline: hs::Time(1_000_000),
            },
            local,
            peer,
            None,
            hs::Time(0),
            &mut TestEntropy(seed),
        )
    };
    let mut handshakes = [
        make(security::Role::Initiator, initiator, peers[0], 81)?,
        make(security::Role::Responder, responder, peers[1], 82)?,
    ];
    for (round, side) in [0, 1, 0, 1].into_iter().enumerate() {
        let now = hs::Time((round as u64 + 1) * 1000);
        let mut original = [0; hs::MAX_FLIGHT_BYTES];
        let flight = handshakes[side].write(now, &mut original)?;
        // Script loss of the first emission of every flight. Retry the exact
        // cached bytes before handing off roots; no duplicate encryption occurs.
        let mut retried = [0; hs::MAX_FLIGHT_BYTES];
        let retry = handshakes[side].retransmit(hs::Time(now.0 + 1), flight.kind, &mut retried)?;
        assert_eq!(&original[..flight.bytes], &retried[..retry.bytes]);
        let mut body = vec![match flight.kind {
            hs::FlightKind::Initiation => 1,
            hs::FlightKind::Response => 2,
            hs::FlightKind::Confirmation => 3,
        }];
        body.extend_from_slice(&retried[..retry.bytes]);
        let mut wire = [0; 1472];
        let length = covers[side].encode(
            cover::PacketMeta {
                phase: cover::Phase::Handshake,
                packet_number: cover::PacketNumber(round as u32),
                media_timestamp: cover::MediaTimestamp(round as u32 * 960),
            },
            &body,
            &mut wire,
        )?;
        if round == 2 {
            continue;
        } // Lose the initiator's final confirmation.
        assert_eq!(sockets[side].send(&wire[..length])?, length);
        let mut received = [0; 1472];
        let received = sockets[1 - side]
            .recv(&mut received)
            .map(|length| received[..length].to_vec())?;
        let decoded = covers[1 - side].decode(&received)?;
        assert_eq!(decoded.phase, cover::Phase::Handshake);
        let kind = match decoded.protected.first() {
            Some(1) => hs::FlightKind::Initiation,
            Some(2) => hs::FlightKind::Response,
            Some(3) => hs::FlightKind::Confirmation,
            _ => return Err("bad fixture flight".into()),
        };
        assert_eq!(
            handshakes[1 - side].read(hs::Time(now.0 + 2), kind, &decoded.protected[1..])?,
            hs::ReadOutcome::Accepted
        );
        assert_eq!(
            handshakes[1 - side].read(hs::Time(now.0 + 3), kind, &decoded.protected[1..])?,
            hs::ReadOutcome::Duplicate
        );
    }
    assert!(handshakes[0].is_complete());
    assert!(!handshakes[1].is_complete());
    let [left, mut right] = handshakes;
    let hs::Established {
        root: left_root,
        confirmation: mut left_confirmation,
    } = left.finish_with_confirmation(hs::Time(10_000))?;
    // The root is already released. Retained ciphertext completes the peer
    // on the same socket without recreating a handshake or touching a nonce.
    let mut confirmation = [0; hs::MAX_FLIGHT_BYTES];
    let flight = left_confirmation.retransmit(hs::Time(11_000), &mut confirmation)?;
    let mut body = vec![3];
    body.extend_from_slice(&confirmation[..flight.bytes]);
    let mut wire = [0; 1472];
    let length = covers[0].encode(
        cover::PacketMeta {
            phase: cover::Phase::Handshake,
            packet_number: cover::PacketNumber(4),
            media_timestamp: cover::MediaTimestamp(3840),
        },
        &body,
        &mut wire,
    )?;
    sockets[0].send(&wire[..length])?;
    let length = sockets[1].recv(&mut wire)?;
    let decoded = covers[1].decode(&wire[..length])?;
    right.read(
        hs::Time(11_001),
        hs::FlightKind::Confirmation,
        &decoded.protected[1..],
    )?;
    assert!(right.is_complete());
    let hs::Established {
        root: right_root,
        confirmation: right_confirmation,
    } = right.finish_with_confirmation(hs::Time(ESTABLISHED_AT))?;
    Ok((
        [left_root, right_root],
        [left_confirmation, right_confirmation],
    ))
}

fn swift_policy() -> swift::Config {
    swift::Config {
        datagram_bytes: 512,
        window: 8,
        repair_numerator: 0,
        repair_denominator: 1000,
        flow_sources: 64,
        queue_bytes: 64 * 1024,
        max_packet: 700,
        flush_micros: 0,
        feedback_micros: 100,
        tail_micros: 1000,
        min_rto_micros: 1000,
        max_rto_micros: 10_000,
    }
}

struct Endpoint {
    socket: UdpSocket,
    original: (SocketAddr, SocketAddr),
    records: record::Records,
    control: mg::delivery::Service,
    sender: swift::Sender,
    receiver: swift::Receiver,
    packets: Vec<Vec<u8>>,
    commands: Vec<Vec<u8>>,
    outer: u32,
    dropped_user: bool,
    dropped_control: bool,
    largest_generation: u64,
    _confirmation: hs::ConfirmationCache,
}
impl Endpoint {
    fn new(
        socket: UdpSocket,
        root: security::SessionRoot,
        confirmation: hs::ConfirmationCache,
        cover: cover::Config,
        role: mg::Role,
    ) -> Result<Self> {
        let original = (socket.local_addr()?, socket.peer_addr()?);
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
                configuration: security::ConfigDigest([4; 32]),
            },
            record::Scope {
                epoch: security::Epoch(10),
                configuration: security::ConfigDigest([5; 32]),
            },
        )?;
        let source_packet_bytes = 128 + l2tunnel::recovery::DATA_HEADER_BYTES;
        let wire_overhead =
            records.capacity(source_packet_bytes)?.packet_bytes - source_packet_bytes + 28;
        let control = mg::delivery::Service::new(
            mg::delivery::Settings {
                recovery: l2tunnel::recovery::ArqConfig {
                    max_source_bytes: 128,
                    send_bytes: 512,
                    receive_bytes: 512,
                    send_records: 4,
                    receive_records: 4,
                    initial_rto: Duration::from_millis(1),
                    maximum_rto: Duration::from_millis(4),
                    ack_delay: Duration::ZERO,
                    max_retries: 8,
                },
                interval: Duration::from_millis(1),
                packets_per_interval: 8,
                bytes_per_interval: 8192,
                wire_overhead,
            },
            mg::delivery::Binding {
                session: mg::SessionId([31; 16]),
                lane: mg::LaneId(0),
                local_role: role,
                control_epoch: 1,
            },
            Duration::from_micros(ESTABLISHED_AT),
            Duration::from_secs(1),
        )?;
        Ok(Self {
            socket,
            original,
            records,
            control,
            sender: swift::Sender::new(swift_policy())?,
            receiver: swift::Receiver::new(swift_policy())?,
            packets: Vec::new(),
            commands: Vec::new(),
            outer: 0,
            dropped_user: false,
            dropped_control: false,
            largest_generation: 0,
            _confirmation: confirmation,
        })
    }
}

fn transfer(
    source: &mut Endpoint,
    target: &mut Endpoint,
    class: record::Class,
    body: &[u8],
    now: u64,
    sender: mg::Role,
) -> Result<usize> {
    let mut workspace = [0; 2048];
    let mut packet = [0; 2048];
    let sealed = source.records.seal(
        class,
        cover::PacketMeta {
            phase: cover::Phase::Established,
            packet_number: cover::PacketNumber(source.outer),
            media_timestamp: cover::MediaTimestamp(source.outer.wrapping_mul(960)),
        },
        body,
        &mut workspace,
        &mut packet,
    )?;
    source.outer += 1;
    let dropped = match class {
        record::Class::User
            if !source.dropped_user && body[0] & swift::KIND_MASK == swift::KIND_SOURCE =>
        {
            source.dropped_user = true;
            true
        }
        record::Class::Control if !source.dropped_control => {
            source.dropped_control = true;
            true
        }
        _ => false,
    };
    if dropped {
        return Ok(sealed.bytes + 28);
    }
    assert_eq!(source.socket.send(&packet[..sealed.bytes])?, sealed.bytes);
    let mut received = [0; 2048];
    let length = target.socket.recv(&mut received)?;
    let mut plaintext = [0; 2048];
    let opened = target
        .records
        .open(&received[..length], &mut workspace, &mut plaintext)?;
    assert_eq!(opened.class, class);
    target.largest_generation = target.largest_generation.max(opened.generation.0);
    match opened.class {
        record::Class::Control => {
            assert_eq!(opened.scope, target.records.control_scope());
            target.control.receive(
                mg::Ingress::AuthenticatedManagement {
                    session: mg::SessionId([31; 16]),
                    lane: mg::LaneId(0),
                    sender,
                },
                &plaintext[..opened.bytes],
                Duration::from_micros(now),
            )?;
        }
        record::Class::User if plaintext[0] & swift::KIND_MASK == swift::KIND_FEEDBACK => {
            target.sender.on_feedback(now, &plaintext[..opened.bytes])?
        }
        record::Class::User => target
            .receiver
            .on_datagram(opened.number.0, &plaintext[..opened.bytes])?,
    }
    Ok(sealed.bytes + 28)
}

#[test]
fn noise_swift_and_reliable_control_share_the_original_udp_pair() -> Result {
    for appearance in [cover::Appearance::QuicLike, cover::Appearance::MediaLike] {
        let covers = covers(appearance)?;
        let sockets = sockets()?;
        let (roots, confirmations) = authenticated_roots(&sockets, covers)?;
        let [left_socket, right_socket] = sockets;
        let [left_root, right_root] = roots;
        let [left_confirmation, right_confirmation] = confirmations;
        let mut endpoints = [
            Endpoint::new(
                left_socket,
                left_root,
                left_confirmation,
                covers[0],
                mg::Role::Client,
            )?,
            Endpoint::new(
                right_socket,
                right_root,
                right_confirmation,
                covers[1],
                mg::Role::Server,
            )?,
        ];
        let expected: Vec<Vec<u8>> = (0..32u8)
            .map(|id| {
                let mut bytes: Vec<u8> = (0..598)
                    .map(|offset| id.wrapping_add(offset as u8))
                    .collect();
                bytes.extend_from_slice(&[0, 0]);
                bytes
            })
            .collect();
        for endpoint in &mut endpoints {
            for bytes in &expected {
                assert!(endpoint.sender.push_packet(ESTABLISHED_AT, bytes)?);
            }
            endpoint.control.submit(
                b"control before data staging\0\0",
                Duration::from_micros(ESTABLISHED_AT),
            )?;
        }
        let mut staged = false;
        for now in (ESTABLISHED_AT..ESTABLISHED_AT + 100_000).step_by(500) {
            if now == ESTABLISHED_AT + 2000 {
                let next = record::Scope {
                    epoch: security::Epoch(11),
                    configuration: security::ConfigDigest([6; 32]),
                };
                for endpoint in &mut endpoints {
                    endpoint.control.submit(
                        b"fixed control across local reader change\0\0",
                        Duration::from_micros(now),
                    )?;
                    let before = endpoint.records.next_number(record::Class::User);
                    endpoint.records.stage_data(next)?;
                    endpoint.records.activate_data(next)?;
                    assert_eq!(endpoint.records.next_number(record::Class::User), before);
                }
                staged = true;
            }
            for side in 0..2 {
                let (left, right) = endpoints.split_at_mut(1);
                let (source, target, role) = if side == 0 {
                    (&mut left[0], &mut right[0], mg::Role::Client)
                } else {
                    (&mut right[0], &mut left[0], mg::Role::Server)
                };
                let mut budget = 8192usize;
                let mut body = [0; 1024];
                while let Some(emission) =
                    source
                        .control
                        .poll(Duration::from_micros(now), budget, &mut body)?
                {
                    let cost = transfer(
                        source,
                        target,
                        record::Class::Control,
                        &body[..emission.bytes],
                        now,
                        role,
                    )?;
                    assert_eq!(cost, emission.wire_bytes);
                    budget -= cost;
                }
                let mut body = Vec::new();
                let feedback_reservation = source
                    .records
                    .capacity(swift::FEEDBACK_HEADER + 2 * swift::MAX_REQUESTS)?
                    .packet_bytes
                    + 28;
                while budget
                    >= source
                        .records
                        .capacity(swift_policy().datagram_bytes)?
                        .packet_bytes
                        + 28
                        + feedback_reservation
                {
                    let number = source.records.next_number(record::Class::User);
                    if !source.sender.poll(now, number.0, &mut body)? {
                        break;
                    }
                    budget -= transfer(source, target, record::Class::User, &body, now, role)?;
                }
                if source.receiver.feedback(now, &mut body) {
                    let cost = source.records.capacity(body.len())?.packet_bytes + 28;
                    assert!(
                        cost <= budget,
                        "fixture failed to reserve user feedback budget"
                    );
                    transfer(source, target, record::Class::User, &body, now, role)?;
                }
            }
            for endpoint in &mut endpoints {
                let mut packet = Vec::new();
                while endpoint.receiver.pop_packet(&mut packet)? {
                    endpoint.packets.push(packet.clone());
                }
                let mut command = [0; 128];
                while let Some((_, length)) = endpoint
                    .control
                    .deliver(&mut command, Duration::from_micros(now))?
                {
                    endpoint.commands.push(command[..length].to_vec());
                }
            }
            if staged
                && endpoints.iter().all(|endpoint| {
                    endpoint.packets.len() == expected.len()
                        && endpoint.sender.unconfirmed() == 0
                        && endpoint.commands.len() == 2
                        && endpoint.control.drained()
                })
            {
                break;
            }
        }
        for endpoint in &endpoints {
            assert_eq!(endpoint.packets, expected);
            assert_eq!(
                endpoint.commands,
                [
                    b"control before data staging\0\0".to_vec(),
                    b"fixed control across local reader change\0\0".to_vec()
                ]
            );
            assert!(endpoint.control.drained());
            assert_eq!(endpoint.sender.unconfirmed(), 0);
            assert!(endpoint.sender.stats().retransmits > 0);
            assert!(endpoint.largest_generation > 1);
            assert!(endpoint.dropped_user && endpoint.dropped_control);
            assert_eq!(
                (endpoint.socket.local_addr()?, endpoint.socket.peer_addr()?),
                endpoint.original
            );
        }
    }
    Ok(())
}
