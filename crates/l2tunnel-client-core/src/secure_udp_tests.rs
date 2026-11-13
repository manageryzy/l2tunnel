//! Real shared-factory authentication and original-socket data/control fixtures.
use super::*;
use l2tunnel::{management as mg, secure_record as record, swift};
use std::{collections::BTreeMap, error::Error, net::SocketAddr};
use tokio::time::{sleep, timeout};
use zeroize::Zeroizing;

type Result<T = ()> = std::result::Result<T, Box<dyn Error + Send + Sync>>;
const TURN_WIRE_BYTES: usize = 4096;
const IP_UDP_BYTES: usize = 28;

async fn sockets() -> Result<[UdpSocket; 2]> {
    let sockets = [
        UdpSocket::bind("127.0.0.1:0").await?,
        UdpSocket::bind("127.0.0.1:0").await?,
    ];
    sockets[0].connect(sockets[1].local_addr()?).await?;
    sockets[1].connect(sockets[0].local_addr()?).await?;
    Ok(sockets)
}

fn identities(profile: hs::Profile) -> ([establish::Identity; 2], establish::Peers) {
    // Public fixture credentials; each real Noise exchange still obtains fresh
    // ephemeral entropy through the maintained runtime entropy provider.
    let initiator = hs::LocalSecret::new(Zeroizing::new([11; 32]));
    let responder = hs::LocalSecret::new(Zeroizing::new([22; 32]));
    let peers = establish::Peers {
        initiator: initiator.public_key(),
        responder: responder.public_key(),
    };
    let psk = || (profile == hs::Profile::IkPsk2).then(|| hs::Psk::new(Zeroizing::new([99; 32])));
    (
        [
            establish::Identity {
                local: initiator,
                peer: peers.responder,
                psk: psk(),
            },
            establish::Identity {
                local: responder,
                peer: peers.initiator,
                psk: psk(),
            },
        ],
        peers,
    )
}

fn member_key() -> Result<identity::IdentityKey> {
    let encoded = Zeroizing::new(l2tunnel_auth::MemberKey::generate_pkcs8()?);
    Ok(identity::IdentityKey::from_pkcs8(&encoded)?)
}

fn settings(
    appearance: cover::Appearance,
    profile: hs::Profile,
    path: gate::Path,
    member: identity::MemberPublicKey,
) -> Result<Settings> {
    let cover = Cover {
        appearance,
        initiator_connection: cover::ConnectionId([1; 8]),
        responder_connection: cover::ConnectionId([2; 8]),
        initiator_ssrc: cover::Ssrc(101),
        responder_ssrc: cover::Ssrc(202),
        payload_type: 96,
        max_packet_bytes: 1472,
        max_protected_bytes: 1400,
    };
    let mut gate = gate::Config::new(path, [3; 32], 7)?;
    gate.path_mtu = 1500;
    gate.outer_overhead = cover.bootstrap_overhead(false)?;
    gate.interval = Duration::from_millis(1);
    gate.initial_rto = Duration::from_millis(2);
    gate.maximum_rto = Duration::from_millis(20);
    gate.gate_attempts = 64;
    gate.handshake_timeout = Duration::from_secs(1);
    gate.cookie_ttl = Duration::from_millis(500);
    gate.arq.initial_rto = Duration::from_millis(2);
    gate.arq.maximum_rto = Duration::from_millis(20);
    gate.arq.ack_delay = Duration::ZERO;
    Ok(Settings {
        gate,
        cover,
        profile,
        application: ConfigDigest([17; 32]),
        outer: [23; 32],
        member,
        membership: Membership {
            retry_interval: Duration::from_millis(2),
            max_attempts: 64,
            receive_interval: Duration::from_millis(1),
            receive_packets_per_interval: 64,
        },
        bootstrap_receive_packets_per_interval: 128,
    })
}

fn outer(number: u32, phase: cover::Phase) -> cover::PacketMeta {
    cover::PacketMeta {
        phase,
        packet_number: cover::PacketNumber(number),
        media_timestamp: cover::MediaTimestamp(number.wrapping_mul(960)),
    }
}

fn advance(number: &mut u32) -> Result {
    *number = number
        .checked_add(1)
        .ok_or("fixture outer counter exhausted")?;
    Ok(())
}

fn tail_output(
    bootstrap: &mut establish::BootstrapTail,
    joining: &mut member::JoiningTail,
    cover: cover::Config,
    next: &mut u32,
    now: Instant,
    allowance: &mut usize,
    packets: &mut Vec<Vec<u8>>,
) -> Result {
    let mut output = [0; 1472];
    if *allowance >= bootstrap.max_packet_bytes() + IP_UDP_BYTES
        && let Some(bytes) =
            bootstrap.poll(now, outer(*next, cover::Phase::Handshake), &mut output)?
    {
        advance(next)?;
        *allowance -= bytes + IP_UDP_BYTES;
        packets.push(output[..bytes].to_vec());
    }
    // JoiningTail has no key or reader; cover capacity bounds its exact cached
    // acceptance before an attempt is consumed by poll.
    if *allowance >= cover.limits().max_packet_bytes + IP_UDP_BYTES
        && let Some(bytes) =
            joining.poll(now, outer(*next, cover::Phase::Established), &mut output)?
    {
        advance(next)?;
        *allowance -= bytes + IP_UDP_BYTES;
        packets.push(output[..bytes].to_vec());
    }
    Ok(())
}

async fn early_tail_turn(parts: &mut member::Parts) -> Result<usize> {
    let mut allowance = TURN_WIRE_BYTES;
    let mut packets = Vec::new();
    tail_output(
        &mut parts.bootstrap,
        &mut parts.joining,
        parts.cover,
        &mut parts.next_outer,
        Instant::now(),
        &mut allowance,
        &mut packets,
    )?;
    for packet in packets {
        assert_eq!(parts.socket.send(&packet).await?, packet.len());
    }
    let mut input = [0; 1473];
    for _ in 0..32 {
        let length = match parts.socket.try_recv(&mut input) {
            Ok(length) => length,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
            Err(error) => return Err(error.into()),
        };
        let decoded = parts.cover.decode(&input[..length])?;
        if !parts.bootstrap.receive(decoded, Instant::now())? {
            parts.joining.receive(decoded, Instant::now())?;
        }
    }
    Ok(TURN_WIRE_BYTES - allowance)
}

fn observe(
    session: &Session,
    requested: Settings,
    peers: establish::Peers,
    role: security::Role,
    original: (SocketAddr, SocketAddr),
) -> Result {
    assert_eq!(session.requested(), requested);
    let effective = session.effective();
    assert_eq!(
        effective.binding.configuration,
        requested.configuration(peers)?.0
    );
    assert_eq!(effective.cover.appearance(), requested.cover.appearance);
    assert_eq!(effective.profile, requested.profile);
    let info = session.info();
    assert_eq!(info.member, requested.member);
    assert_eq!(info.peers, peers);
    assert_eq!(info.role, role);
    assert_eq!((info.local_addr, info.peer_addr), original);
    assert_ne!(info.binding.session.0, [0; 16]);
    assert_ne!(info.binding.transcript, [0; 32]);
    assert_eq!(info.authenticated.session, info.binding.session);
    assert_eq!(
        info.authenticated.configuration,
        effective.binding.configuration
    );
    assert_eq!(info.authenticated.carrier, effective.binding.carrier);
    assert_ne!(info.authenticated.outer, requested.outer);
    assert!(info.statistics.noise_flights >= 2);
    Ok(())
}

async fn authenticate(
    appearance: cover::Appearance,
    profile: hs::Profile,
) -> Result<([member::Parts; 2], Settings)> {
    let [client_socket, server_socket] = sockets().await?;
    let originals = [
        (client_socket.local_addr()?, client_socket.peer_addr()?),
        (server_socket.local_addr()?, server_socket.peer_addr()?),
    ];
    let member = member_key()?;
    let settings = settings(
        appearance,
        profile,
        gate::Path {
            client: originals[0].0,
            server: originals[1].0,
        },
        member.public_key(),
    )?;
    let ([client_identity, server_identity], peers) = identities(profile);
    let origin = Instant::now();
    let deadline = origin + Duration::from_secs(2);
    // These fixed secrets are fixture inputs, not provisioning recommendations.
    let mut server = Server::new(
        settings,
        peers,
        gate::Secret::new([41; 32]),
        gate::Secret::new([42; 32]),
        origin,
    )?;
    let mut client_entropy = establish::RuntimeEntropy::new();
    let mut server_entropy = establish::RuntimeEntropy::new();
    let client = connect(
        client_socket,
        settings,
        client_identity,
        &member,
        gate::Secret::new([41; 32]),
        deadline,
        &mut client_entropy,
    );
    let accepted = server.accept(
        server_socket,
        server_identity,
        deadline,
        &mut server_entropy,
    );
    tokio::pin!(client, accepted);
    let (early_side, early) = tokio::select! {
        biased;
        result = &mut accepted => (1, result?),
        result = &mut client => (0, result?),
    };
    let role = if early_side == 0 {
        security::Role::Initiator
    } else {
        security::Role::Responder
    };
    observe(&early, settings, peers, role, originals[early_side])?;
    let mut early = early.into_parts();
    assert_eq!(early.deadline, deadline);
    // The incomplete factory future is deliberately not polled for this short
    // interval. The completed side must retain sole-reader final-tail custody.
    for _ in 0..4 {
        early_tail_turn(&mut early).await?;
        sleep(Duration::from_millis(1)).await;
    }
    let late = loop {
        tokio::select! {
            result = &mut client, if early_side == 1 => break result?,
            result = &mut accepted, if early_side == 0 => break result?,
            _ = sleep(Duration::from_millis(1)) => { early_tail_turn(&mut early).await?; }
            _ = tokio::time::sleep_until(deadline) => return Err("factory fixture exceeded original deadline".into()),
        }
    };
    let late_role = if early_side == 0 {
        security::Role::Responder
    } else {
        security::Role::Initiator
    };
    observe(&late, settings, peers, late_role, originals[1 - early_side])?;
    let late = late.into_parts();
    assert_eq!(late.deadline, deadline);
    assert_eq!(early.info.binding, late.info.binding);
    assert_eq!(early.root.binding(), early.info.binding);
    assert_eq!(late.root.binding(), late.info.binding);
    Ok((
        if early_side == 0 {
            [early, late]
        } else {
            [late, early]
        },
        settings,
    ))
}

fn swift_config() -> swift::records::Config {
    swift::records::Config {
        codec: swift::Config {
            datagram_bytes: 512,
            window: 8,
            repair_numerator: 0,
            repair_denominator: 1000,
            flow_sources: 128,
            queue_bytes: 64 * 1024,
            max_packet: 701,
            flush_micros: 0,
            feedback_micros: 100,
            tail_micros: 1_000,
            min_rto_micros: 1_000,
            max_rto_micros: 10_000,
        },
        channels: 4,
        layer: swift::records::Layer::Ip,
        max_native: 700,
    }
}

struct Endpoint {
    socket: UdpSocket,
    original: (SocketAddr, SocketAddr),
    cover: cover::Config,
    bootstrap: establish::BootstrapTail,
    joining: member::JoiningTail,
    outer: u32,
    role: mg::Role,
    session: mg::SessionId,
    records: record::Records,
    swift: swift::records::Engine,
    control: mg::delivery::Service,
    packets: Vec<Vec<u8>>,
    commands: Vec<Vec<u8>>,
    dropped_user: bool,
    dropped_control: bool,
    duplicated: bool,
    replay_rejections: u64,
    largest_generation: u64,
    control_charge: u64,
    charged: u64,
    physical: u64,
}

impl Endpoint {
    fn new(parts: member::Parts, configuration: security::ConfigDigest) -> Result<Self> {
        let member::Parts {
            socket,
            root,
            cover,
            bootstrap,
            joining,
            next_outer,
            deadline: _,
            info,
        } = parts;
        let original = (socket.local_addr()?, socket.peer_addr()?);
        let role = if info.role == security::Role::Initiator {
            mg::Role::Client
        } else {
            mg::Role::Server
        };
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
                configuration,
            },
            record::Scope {
                epoch: security::Epoch(10),
                configuration,
            },
        )?;
        let max_source = 128 + l2tunnel::recovery::DATA_HEADER_BYTES;
        let wire_overhead = records.capacity(max_source)?.packet_bytes + IP_UDP_BYTES - max_source;
        let session = mg::SessionId(info.binding.session.0);
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
                    max_retries: 16,
                },
                interval: Duration::from_millis(1),
                packets_per_interval: 8,
                bytes_per_interval: TURN_WIRE_BYTES,
                wire_overhead,
            },
            mg::delivery::Binding {
                session,
                lane: mg::LaneId(0),
                local_role: role,
                control_epoch: 1,
            },
            Duration::ZERO,
            Duration::from_secs(1),
        )?;
        Ok(Self {
            socket,
            original,
            cover,
            bootstrap,
            joining,
            outer: next_outer,
            role,
            session,
            records,
            swift: swift::records::Engine::new(swift_config())?,
            control,
            packets: Vec::new(),
            commands: Vec::new(),
            dropped_user: false,
            dropped_control: false,
            duplicated: false,
            replay_rejections: 0,
            largest_generation: 0,
            control_charge: 0,
            charged: 0,
            physical: 0,
        })
    }

    fn queue(
        &mut self,
        class: record::Class,
        body: &[u8],
        allowance: &mut usize,
        output: &mut Vec<Vec<u8>>,
    ) -> Result<usize> {
        let cost = self.records.capacity(body.len())?.packet_bytes + IP_UDP_BYTES;
        assert!(cost <= *allowance);
        let mut workspace = [0; 2048];
        let mut packet = [0; 1472];
        let sealed = self.records.seal(
            class,
            outer(self.outer, cover::Phase::Established),
            body,
            &mut workspace,
            &mut packet,
        )?;
        advance(&mut self.outer)?;
        assert_eq!(cost, sealed.bytes + IP_UDP_BYTES);
        *allowance -= cost;
        let drop = match class {
            record::Class::User
                if !self.dropped_user && body[0] & swift::KIND_MASK == swift::KIND_SOURCE =>
            {
                self.dropped_user = true;
                true
            }
            record::Class::Control if !self.dropped_control => {
                self.dropped_control = true;
                true
            }
            _ => false,
        };
        if !drop {
            output.push(packet[..sealed.bytes].to_vec());
            if class == record::Class::User && !self.duplicated && *allowance >= cost {
                // An actual second send of identical ciphertext is separately
                // charged; protection numbers are not reserved again.
                *allowance -= cost;
                output.push(packet[..sealed.bytes].to_vec());
                self.duplicated = true;
            }
        }
        Ok(cost)
    }

    async fn send_turn(&mut self, now: u64) -> Result {
        let mut allowance = TURN_WIRE_BYTES;
        let mut packets = Vec::new();
        tail_output(
            &mut self.bootstrap,
            &mut self.joining,
            self.cover,
            &mut self.outer,
            Instant::now(),
            &mut allowance,
            &mut packets,
        )?;
        let mut control = [0; 256];
        while let Some(emission) =
            self.control
                .poll(Duration::from_micros(now), allowance, &mut control)?
        {
            let cost = self.queue(
                record::Class::Control,
                &control[..emission.bytes],
                &mut allowance,
                &mut packets,
            )?;
            assert_eq!(cost, emission.wire_bytes);
            self.control_charge += cost as u64;
        }
        let maximum = self
            .records
            .capacity(swift_config().codec.datagram_bytes)?
            .packet_bytes
            + IP_UDP_BYTES;
        while allowance >= maximum {
            let number = self.records.next_number(record::Class::User);
            let Some(body) = self
                .swift
                .poll(now, swift::records::RecordNumber(number.0), true)?
            else {
                break;
            };
            let body = body.to_vec();
            self.queue(record::Class::User, &body, &mut allowance, &mut packets)?;
        }
        assert!(packets.len() <= 64);
        let charged = TURN_WIRE_BYTES - allowance;
        let physical: usize = packets
            .iter()
            .map(|packet| packet.len() + IP_UDP_BYTES)
            .sum();
        assert!(physical <= charged && charged <= TURN_WIRE_BYTES);
        self.charged += charged as u64;
        self.physical += physical as u64;
        // Reordering occurs within this already charged bounded handoff turn.
        for packet in packets.into_iter().rev() {
            assert_eq!(self.socket.send(&packet).await?, packet.len());
        }
        Ok(())
    }

    fn receive_turn(&mut self, now: u64) -> Result {
        let mut packet = [0; 1473];
        for _ in 0..64 {
            let length = match self.socket.try_recv(&mut packet) {
                Ok(length) => length,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                Err(error) => return Err(error.into()),
            };
            let decoded = self.cover.decode(&packet[..length])?;
            if self.bootstrap.receive(decoded, Instant::now())?
                || self.joining.receive(decoded, Instant::now())?
            {
                continue;
            }
            if decoded.phase != cover::Phase::Established {
                continue;
            }
            let mut workspace = [0; 2048];
            let mut plain = [0; 1024];
            let opened = match self
                .records
                .open(&packet[..length], &mut workspace, &mut plain)
            {
                Ok(opened) => opened,
                Err(record::Error::Security(security::Error::Replay)) => {
                    self.replay_rejections += 1;
                    continue;
                }
                Err(error) => return Err(error.into()),
            };
            self.largest_generation = self.largest_generation.max(opened.generation.0);
            match opened.class {
                record::Class::Control => {
                    assert_eq!(opened.scope, self.records.control_scope());
                    let sender = if self.role == mg::Role::Client {
                        mg::Role::Server
                    } else {
                        mg::Role::Client
                    };
                    self.control.receive(
                        mg::Ingress::AuthenticatedManagement {
                            session: self.session,
                            lane: mg::LaneId(0),
                            sender,
                        },
                        &plain[..opened.bytes],
                        Duration::from_micros(now),
                    )?;
                }
                record::Class::User => self.swift.accept(
                    now,
                    swift::records::RecordNumber(opened.number.0),
                    &mut plain[..opened.bytes],
                )?,
            }
        }
        while let Some(packet) = self.swift.pop()? {
            self.packets.push(packet.to_vec());
        }
        let mut command = [0; 128];
        while let Some((_, bytes)) = self
            .control
            .deliver(&mut command, Duration::from_micros(now))?
        {
            self.commands.push(command[..bytes].to_vec());
        }
        Ok(())
    }
}

fn checksum(bytes: &[u8]) -> [u8; 2] {
    let mut sum = 0_u32;
    for pair in bytes.chunks(2) {
        sum += u32::from(pair[0]) << 8 | u32::from(*pair.get(1).unwrap_or(&0));
        sum = (sum & 0xffff) + (sum >> 16);
    }
    let sum = (sum & 0xffff) + (sum >> 16);
    (!(sum as u16)).to_be_bytes()
}

fn native_packets(side: u8) -> Vec<Vec<u8>> {
    (0..32_u32)
        .map(|id| {
            let counter = id / 4;
            let port = 40_000 + u16::from(side) * 1_000 + (id % 4) as u16;
            let mut bytes = vec![side.wrapping_add(id as u8); 600];
            bytes[..40].fill(0);
            bytes[0] = 0x45;
            bytes[2..4].copy_from_slice(&600_u16.to_be_bytes());
            bytes[4..6].copy_from_slice(&(counter as u16).to_be_bytes());
            bytes[6] = 0x40;
            bytes[8] = 64;
            bytes[9] = 6;
            bytes[12..20].copy_from_slice(&[198, 18, 0, 1, 198, 18, 0, 2]);
            bytes[20..22].copy_from_slice(&port.to_be_bytes());
            bytes[22..24].copy_from_slice(&24_500_u16.to_be_bytes());
            bytes[24..28].copy_from_slice(&(counter * 560).to_be_bytes());
            bytes[28..32].copy_from_slice(&5_u32.to_be_bytes());
            bytes[32] = 0x50;
            bytes[33] = 0x10;
            bytes[34..36].copy_from_slice(&1024_u16.to_be_bytes());
            bytes[40..44].copy_from_slice(&counter.to_be_bytes());
            bytes[598..].fill(0);
            let ip = checksum(&bytes[..20]);
            bytes[10..12].copy_from_slice(&ip);
            let mut pseudo = bytes[12..20].to_vec();
            pseudo.extend_from_slice(&[0, 6, 2, 68]); // 580-byte TCP segment.
            pseudo.extend_from_slice(&bytes[20..]);
            let tcp = checksum(&pseudo);
            bytes[36..38].copy_from_slice(&tcp);
            bytes
        })
        .chain([vec![0], vec![0; 600], vec![0xff, side, 0, 1, 0, 0]])
        .collect()
}

fn counts(packets: &[Vec<u8>]) -> BTreeMap<Vec<u8>, usize> {
    let mut counts = BTreeMap::new();
    for packet in packets {
        *counts.entry(packet.clone()).or_insert(0) += 1;
    }
    counts
}

#[tokio::test]
async fn real_factories_members_swift_and_control_keep_the_original_udp_pair() -> Result {
    for appearance in [cover::Appearance::QuicLike, cover::Appearance::MediaLike] {
        for profile in [hs::Profile::Ik, hs::Profile::IkPsk2] {
            let ([left, right], settings) = authenticate(appearance, profile).await?;
            let configuration = settings.configuration(left.info.peers)?;
            let mut endpoints = [
                Endpoint::new(left, configuration)?,
                Endpoint::new(right, configuration)?,
            ];
            let expected = [native_packets(0), native_packets(1)];
            for (side, endpoint) in endpoints.iter_mut().enumerate() {
                let channels: std::collections::BTreeSet<_> = expected[side]
                    .iter()
                    .map(|packet| swift::flow::classify_ip(packet, 4))
                    .collect();
                assert!(
                    channels.len() > 1,
                    "fixture did not exercise independent channels"
                );
                for bytes in &expected[side] {
                    assert_eq!(
                        endpoint.swift.offer(0, bytes)?,
                        swift::records::Admission::Accepted
                    );
                }
                endpoint.control.submit(
                    b"actual member; control before scope change\0\0",
                    Duration::ZERO,
                )?;
            }
            let mut changed = false;
            for tick in 0..500_u64 {
                let now = tick * 1_000;
                if tick == 5 {
                    for endpoint in &mut endpoints {
                        let before = endpoint.records.next_number(record::Class::User);
                        let control = endpoint.records.control_scope();
                        let next = record::Scope {
                            epoch: security::Epoch(11),
                            configuration: security::ConfigDigest([31; 32]),
                        };
                        endpoint.records.stage_data(next)?;
                        endpoint.records.activate_data(next)?;
                        assert_eq!(endpoint.records.next_number(record::Class::User), before);
                        assert_eq!(endpoint.records.control_scope(), control);
                        endpoint.control.submit(
                            b"fixed management across local scope change\0\0",
                            Duration::from_micros(now),
                        )?;
                    }
                    changed = true;
                }
                for endpoint in &mut endpoints {
                    endpoint.send_turn(now).await?;
                }
                sleep(Duration::from_millis(1)).await;
                for endpoint in &mut endpoints {
                    endpoint.receive_turn(now)?;
                }
                if changed
                    && endpoints.iter().enumerate().all(|(side, endpoint)| {
                        endpoint.packets.len() == expected[1 - side].len()
                            && endpoint.commands.len() == 2
                            && endpoint.swift.send_drained()
                            && endpoint.control.drained()
                    })
                {
                    break;
                }
            }
            for (side, endpoint) in endpoints.iter().enumerate() {
                assert_eq!(counts(&endpoint.packets), counts(&expected[1 - side]));
                assert_eq!(
                    endpoint.commands,
                    [
                        b"actual member; control before scope change\0\0".to_vec(),
                        b"fixed management across local scope change\0\0".to_vec()
                    ]
                );
                assert!(endpoint.swift.send_drained() && endpoint.control.drained());
                assert!(endpoint.swift.stats().sender.retransmits > 0);
                assert!(endpoint.swift.stats().header_bytes_saved > 0);
                let mut next = [0_u32; 4];
                for packet in &endpoint.packets {
                    if packet.len() == 600 && packet[0] == 0x45 {
                        let port = u16::from_be_bytes([packet[20], packet[21]]);
                        let flow = usize::from(port - 40_000 - (1 - side) as u16 * 1_000);
                        let counter = u32::from_be_bytes(packet[40..44].try_into()?);
                        assert_eq!(counter, next[flow]);
                        next[flow] += 1;
                    }
                }
                assert_eq!(next, [8; 4]);
                assert!(endpoint.largest_generation > 1);
                assert!(endpoint.dropped_user && endpoint.dropped_control && endpoint.duplicated);
                assert!(endpoint.replay_rejections > 0);
                assert!(endpoint.charged > endpoint.physical);
                assert_eq!(
                    endpoint.control_charge,
                    endpoint.control.statistics().emitted_wire_bytes
                );
                assert_eq!(
                    (endpoint.socket.local_addr()?, endpoint.socket.peer_addr()?),
                    endpoint.original
                );
            }
        }
    }
    Ok(())
}

#[tokio::test]
async fn mismatched_local_member_is_rejected_before_a_network_packet() -> Result {
    for appearance in [cover::Appearance::QuicLike, cover::Appearance::MediaLike] {
        let [client, server] = sockets().await?;
        let expected = member_key()?;
        let supplied = member_key()?;
        let settings = settings(
            appearance,
            hs::Profile::Ik,
            gate::Path {
                client: client.local_addr()?,
                server: server.local_addr()?,
            },
            expected.public_key(),
        )?;
        let ([identity, _], _) = identities(hs::Profile::Ik);
        let mut entropy = establish::RuntimeEntropy::new();
        let result = connect(
            client,
            settings,
            identity,
            &supplied,
            gate::Secret::new([41; 32]),
            Instant::now() + Duration::from_millis(100),
            &mut entropy,
        )
        .await;
        assert!(matches!(result, Err(error) if error.kind() == io::ErrorKind::PermissionDenied));
        assert!(
            timeout(Duration::from_millis(10), server.recv(&mut [0; 1500]))
                .await
                .is_err()
        );
    }
    Ok(())
}

#[tokio::test]
async fn wrong_configured_noise_pin_cannot_release_a_factory_session() -> Result {
    for appearance in [cover::Appearance::QuicLike, cover::Appearance::MediaLike] {
        let [client, responder] = sockets().await?;
        let member = member_key()?;
        let settings = settings(
            appearance,
            hs::Profile::Ik,
            gate::Path {
                client: client.local_addr()?,
                server: responder.local_addr()?,
            },
            member.public_key(),
        )?;
        let ([mut client_identity, server_identity], peers) = identities(hs::Profile::Ik);
        client_identity.peer = hs::LocalSecret::new(Zeroizing::new([33; 32])).public_key();
        let now = Instant::now();
        let deadline = now + Duration::from_millis(80);
        let mut server = Server::new(
            settings,
            peers,
            gate::Secret::new([41; 32]),
            gate::Secret::new([42; 32]),
            now,
        )?;
        let mut client_entropy = establish::RuntimeEntropy::new();
        let mut server_entropy = establish::RuntimeEntropy::new();
        let (client, server) = tokio::join!(
            connect(
                client,
                settings,
                client_identity,
                &member,
                gate::Secret::new([41; 32]),
                deadline,
                &mut client_entropy
            ),
            server.accept(responder, server_identity, deadline, &mut server_entropy)
        );
        assert!(client.is_err() && server.is_err());
    }
    Ok(())
}
