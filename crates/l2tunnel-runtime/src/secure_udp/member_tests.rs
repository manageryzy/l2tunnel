use super::*;
use l2tunnel_handshake as hs;
use l2tunnel_udp_control as gate;
use std::cell::Cell;

type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

struct Entropy(u8);
impl hs::Entropy for Entropy {
    fn fill(&mut self, output: &mut [u8; 32]) -> std::result::Result<(), hs::EntropyError> {
        output.fill(self.0);
        self.0 = self.0.wrapping_add(1);
        Ok(())
    }
}

fn member(other: bool) -> Result<identity::IdentityKey> {
    // Published RFC8032 test vectors; never actual provisioning material.
    let seed = if other {
        "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb"
    } else {
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
    };
    let public = if other {
        "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c"
    } else {
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
    };
    let text = format!("3051020101300506032b657004220420{seed}812100{public}");
    let encoded = text
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| Ok(u8::from_str_radix(std::str::from_utf8(pair)?, 16)?))
        .collect::<Result<Vec<u8>>>()?;
    Ok(identity::IdentityKey::from_pkcs8(&encoded)?)
}

fn appearance(appearance: cover::Appearance, local: u8, peer: u8) -> Result<cover::Config> {
    Ok(cover::Config::new(
        appearance,
        cover::ConnectionIds {
            local: cover::ConnectionId([local; 8]),
            peer: cover::ConnectionId([peer; 8]),
        },
        cover::MediaConfig {
            local_ssrc: cover::Ssrc(u32::from(local)),
            peer_ssrc: cover::Ssrc(u32::from(peer)),
            payload_type: 96,
        },
        cover::Limits {
            max_packet_bytes: 1200,
            max_protected_bytes: 512,
        },
    )?)
}

async fn pair(
    appearance_kind: cover::Appearance,
) -> Result<(establish::Established, establish::Established)> {
    pair_with_bootstrap_retry_limit(appearance_kind, 8).await
}

async fn pair_with_bootstrap_retry_limit(
    appearance_kind: cover::Appearance,
    bootstrap_retries: u16,
) -> Result<(establish::Established, establish::Established)> {
    let client = UdpSocket::bind("127.0.0.1:0").await?;
    let server = UdpSocket::bind("127.0.0.1:0").await?;
    let path = gate::Path {
        client: client.local_addr()?,
        server: server.local_addr()?,
    };
    client.connect(path.server).await?;
    server.connect(path.client).await?;
    let mut gate = gate::Config::new(path, [30; 32], 1)?;
    gate.outer_overhead = 28
        + 1
        + if appearance_kind == cover::Appearance::QuicLike {
            30
        } else {
            14
        };
    gate.arq.max_source_bytes = 100;
    gate.arq.send_bytes = 3200;
    gate.arq.receive_bytes = 3200;
    gate.arq.initial_rto = Duration::from_millis(10);
    gate.arq.maximum_rto = Duration::from_millis(100);
    gate.arq.ack_delay = Duration::from_millis(1);
    gate.arq.max_retries = bootstrap_retries;
    gate.cookie_ttl = Duration::from_millis(500);
    gate.handshake_timeout = Duration::from_secs(1);
    gate.initial_rto = Duration::from_millis(10);
    gate.maximum_rto = Duration::from_millis(100);
    gate.gate_attempts = 32;
    let local = hs::LocalSecret::new(Zeroizing::new([11; 32]));
    let remote = hs::LocalSecret::new(Zeroizing::new([22; 32]));
    let peers = establish::Peers {
        initiator: local.public_key(),
        responder: remote.public_key(),
    };
    let binding = establish::Binding {
        configuration: [3; 32],
        carrier: [4; 32],
        outer: [5; 32],
        member: [6; 32],
    };
    let client_config = establish::Config {
        gate,
        cover: appearance(appearance_kind, 1, 2)?,
        profile: hs::Profile::Ik,
        binding,
        receive_packets_per_interval: 64,
    };
    let server_config = establish::Config {
        cover: appearance(appearance_kind, 2, 1)?,
        ..client_config
    };
    let now = Instant::now();
    let deadline = now + Duration::from_secs(1);
    let mut admission = establish::ServerAdmission::new(
        server_config,
        peers,
        gate::Secret::new([7; 32]),
        gate::Secret::new([8; 32]),
        now,
    )?;
    let mut client_entropy = Entropy(40);
    let mut server_entropy = Entropy(60);
    let (client, server) = tokio::try_join!(
        establish::connect(
            client,
            client_config,
            establish::Identity {
                local,
                peer: peers.responder,
                psk: None
            },
            gate::Secret::new([7; 32]),
            deadline,
            &mut client_entropy
        ),
        establish::accept(
            server,
            establish::Identity {
                local: remote,
                peer: peers.initiator,
                psk: None
            },
            &mut admission,
            deadline,
            &mut server_entropy
        )
    )?;
    assert_eq!(client.binding, server.binding);
    assert_eq!(client.deadline, deadline);
    assert_eq!(server.deadline, deadline);
    Ok((client, server))
}

fn settings(established: &establish::Established) -> Settings {
    Settings {
        context: identity::Context {
            session: established.binding.session,
            transcript: established.binding.transcript,
            configuration: established.authenticated.configuration,
            carrier: established.authenticated.carrier,
            outer: established.authenticated.outer,
            initiator_noise: identity::NoisePublicKey(established.peers.initiator.0),
            responder_noise: identity::NoisePublicKey(established.peers.responder.0),
        },
        retry_interval: Duration::from_millis(10),
        max_attempts: 32,
        receive_interval: Duration::from_millis(5),
        receive_packets_per_interval: 8,
    }
}

#[tokio::test]
async fn actual_member_admission_keeps_original_socket_and_joining_owners() -> Result {
    for appearance in [cover::Appearance::QuicLike, cover::Appearance::MediaLike] {
        let (client, server) = pair(appearance).await?;
        let client_addr = client.socket.local_addr()?;
        let server_addr = server.socket.local_addr()?;
        let deadline = client.deadline;
        let client_settings = settings(&client);
        let server_settings = settings(&server);
        let member = member(false)?;
        let members = identity::Allowlist::new(&[member.public_key()])?;
        let (client, server) = tokio::try_join!(
            connect(client, &member, client_settings),
            accept(server, members, server_settings)
        )?;
        assert_eq!(client.info().member, member.public_key());
        assert_eq!(client.info().binding, server.info().binding);
        assert_eq!(client.info().role, security::Role::Initiator);
        assert_eq!(server.info().role, security::Role::Responder);
        assert_eq!(client.info().local_addr, client_addr);
        assert_eq!(client.info().peer_addr, server_addr);
        let mut client = client.into_parts();
        let mut server = server.into_parts();
        assert_eq!(client.deadline, deadline);
        assert_eq!(server.deadline, deadline);
        assert_eq!(client.socket.local_addr()?, client_addr);
        assert_eq!(server.socket.local_addr()?, server_addr);
        assert_eq!(
            client
                .root
                .sender(
                    security::Purpose::Joining,
                    security::LaneId(0),
                    JOINING_LIMITS,
                    security::Protection::ChaCha20Poly1305
                )
                .err(),
            Some(security::Error::DomainInUse)
        );
        assert_eq!(
            server
                .root
                .receiver(
                    security::Purpose::Joining,
                    security::LaneId(0),
                    JOINING_LIMITS,
                    security::Protection::ChaCha20Poly1305
                )
                .err(),
            Some(security::Error::DomainInUse)
        );
        let mut sender = client.root.sender(
            security::Purpose::Data,
            security::LaneId(0),
            JOINING_LIMITS,
            security::Protection::ChaCha20Poly1305,
        )?;
        let mut receiver = server.root.receiver(
            security::Purpose::Data,
            security::LaneId(0),
            JOINING_LIMITS,
            security::Protection::ChaCha20Poly1305,
        )?;
        let mut wire = [0; 256];
        let sealed = sender.seal(
            joining_metadata(client_settings.context),
            &[0, 1, 0, 255],
            &mut wire,
        )?;
        let mut plain = [0; 256];
        let opened = receiver.open(
            joining_metadata(server_settings.context),
            &wire[..sealed.bytes],
            &mut plain,
        )?;
        assert_eq!(&plain[..opened.bytes], &[0, 1, 0, 255]);
    }
    Ok(())
}

#[tokio::test]
async fn wrong_member_and_wrong_local_binding_never_release_roots() -> Result {
    let (client, server) = pair(cover::Appearance::QuicLike).await?;
    let client_settings = settings(&client);
    let server_settings = settings(&server);
    let members = identity::Allowlist::new(&[member(true)?.public_key()])?;
    let client_member = member(false)?;
    let (client, server) = tokio::join!(
        connect(client, &client_member, client_settings),
        accept(server, members, server_settings)
    );
    assert!(client.is_err());
    assert_eq!(
        server.err().map(|error| error.kind()),
        Some(io::ErrorKind::PermissionDenied)
    );
    let (client, server) = pair(cover::Appearance::MediaLike).await?;
    let valid = settings(&client);
    assert!(validate(&client, valid, security::Role::Initiator).is_ok());
    for field in 0..15 {
        let mut wrong = valid;
        match field {
            0 => wrong.context.session.0[0] ^= 1,
            1 => wrong.context.transcript[0] ^= 1,
            2 => wrong.context.initiator_noise.0[0] ^= 1,
            3 => wrong.context.responder_noise.0[0] ^= 1,
            4 => wrong.max_attempts = 0,
            5 => wrong.max_attempts = 1025,
            6 => wrong.receive_packets_per_interval = 0,
            7 => wrong.receive_interval = Duration::ZERO,
            8 => wrong.receive_packets_per_interval = 1025,
            9 => wrong.retry_interval = Duration::ZERO,
            10 => wrong.retry_interval = Duration::from_secs(2),
            11 => wrong.receive_interval = Duration::from_secs(2),
            12 => wrong.context.configuration[0] ^= 1,
            13 => wrong.context.carrier[0] ^= 1,
            _ => wrong.context.outer[0] ^= 1,
        }
        assert_eq!(
            validate(&client, wrong, security::Role::Initiator)
                .err()
                .map(|error| error.kind()),
            Some(io::ErrorKind::InvalidInput)
        );
    }
    assert_eq!(
        validate(&client, valid, security::Role::Responder)
            .err()
            .map(|error| error.kind()),
        Some(io::ErrorKind::InvalidInput)
    );
    drop(server);
    Ok(())
}

#[tokio::test]
async fn transient_socket_errors_recover_without_releasing_unauthenticated_roots() -> Result {
    let (client, server) = pair(cover::Appearance::QuicLike).await?;
    let client_settings = settings(&client);
    let server_settings = settings(&server);
    let original_deadline = client.deadline;
    let member = member(false)?;
    let members = identity::Allowlist::new(&[member.public_key()])?;
    let recovering = SEND_PATH_ERRORS.scope(
        Cell::new(1),
        RECEIVE_PATH_ERRORS.scope(Cell::new(2), connect(client, &member, client_settings)),
    );
    let (client, server) = tokio::try_join!(recovering, accept(server, members, server_settings))?;
    assert_eq!(client.info().member, member.public_key());
    assert_eq!(client.info().binding, server.info().binding);
    assert_eq!(client.into_parts().deadline, original_deadline);
    assert_eq!(server.into_parts().deadline, original_deadline);
    Ok(())
}

#[tokio::test]
async fn persistent_socket_errors_consume_bounded_work_until_original_deadline() -> Result {
    // Keep this finite bootstrap retry allowance longer than the original
    // one-second deadline, so the deadline is the first applicable bound.
    let (client, server) =
        pair_with_bootstrap_retry_limit(cover::Appearance::MediaLike, 32).await?;
    let original_deadline = client.deadline;
    let mut policy = settings(&client);
    policy.max_attempts = 1024;
    policy.receive_packets_per_interval = 1;
    let member = member(false)?;
    // After real establishment, inject local socket results while advancing only
    // Tokio's runtime clock. No packet, retry or receive error can renew expiry.
    tokio::time::pause();
    let origin = Instant::now();
    let allowance = original_deadline.duration_since(origin).as_nanos()
        / policy.receive_interval.as_nanos()
        + 1;
    let (result, sends, receives) = SEND_PATH_ERRORS
        .scope(
            Cell::new(u32::MAX),
            RECEIVE_PATH_ERRORS.scope(Cell::new(u32::MAX), async {
                let result = connect(client, &member, policy).await;
                (
                    result,
                    u32::MAX - SEND_PATH_ERRORS.with(Cell::get),
                    u32::MAX - RECEIVE_PATH_ERRORS.with(Cell::get),
                )
            }),
        )
        .await;
    assert_eq!(
        result.err().map(|error| error.kind()),
        Some(io::ErrorKind::TimedOut)
    );
    // Pinned Tokio 1.53.1: time/source.rs::deadline_to_tick rounds the deadline
    // up, while runtime/time/mod.rs::park_internal subtracts the floored current
    // tick and advances paused time by that whole-ms duration. The current
    // fractional phase plus deadline rounding is strictly less than two ms.
    // This is virtual timer quantization, never renewal of the absolute expiry.
    let completed = Instant::now();
    assert!(completed >= original_deadline);
    let overshoot = completed.duration_since(original_deadline);
    let timer_quantization_bound = Duration::from_millis(2);
    assert!(
        overshoot < timer_quantization_bound,
        "paused Tokio 1.53.1 overshoot {overshoot:?}, bound {timer_quantization_bound:?}; \
         original deadline {original_deadline:?}, completed {completed:?}"
    );
    eprintln!(
        "persistent member deadline virtual overshoot: {overshoot:?} (< {timer_quantization_bound:?})"
    );
    assert!(sends > 1 && sends < policy.max_attempts);
    assert!(receives > 1 && u128::from(receives) <= allowance);
    drop(server);
    Ok(())
}

#[tokio::test]
async fn pending_bootstrap_retry_exhaustion_remains_terminal_during_path_loss() -> Result {
    let (client, server) = pair_with_bootstrap_retry_limit(cover::Appearance::MediaLike, 8).await?;
    assert!(
        !client.tail.drained(),
        "retain the actual final-flight debt"
    );
    let original_deadline = client.deadline;
    let mut policy = settings(&client);
    policy.max_attempts = 1024;
    policy.receive_packets_per_interval = 1;
    let member = member(false)?;
    tokio::time::pause();
    let result = SEND_PATH_ERRORS
        .scope(
            Cell::new(u32::MAX),
            RECEIVE_PATH_ERRORS.scope(Cell::new(u32::MAX), connect(client, &member, policy)),
        )
        .await;
    let error = result
        .err()
        .ok_or("terminal bootstrap debt released a root")?;
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    assert!(
        matches!(
            error
                .get_ref()
                .and_then(|cause| cause.downcast_ref::<establish::Error>()),
            Some(establish::Error::Gate(gate::Error::Recovery(
                l2tunnel_recovery::RecoveryError::RetryExhausted { .. }
            )))
        ),
        "unexpected terminal cause: {error:?}"
    );
    assert!(Instant::now() < original_deadline);
    drop(server);
    Ok(())
}

#[tokio::test]
async fn dropped_final_acceptance_completes_from_ciphertext_only_tail() -> Result {
    for appearance_kind in [cover::Appearance::QuicLike, cover::Appearance::MediaLike] {
        let (client, server) = pair(appearance_kind).await?;
        let client_settings = settings(&client);
        let server_settings = settings(&server);
        let member = member(false)?;
        let members = identity::Allowlist::new(&[member.public_key()])?;
        let client_done = Cell::new(false);
        let client_future = async {
            let authenticated = connect(client, &member, client_settings).await?;
            client_done.set(true);
            Ok::<_, io::Error>(authenticated.into_parts())
        };
        let server_future = async {
            let authenticated = DROP_FIRST_ACCEPTANCE
                .scope(Cell::new(true), accept(server, members, server_settings))
                .await?;
            assert!(
                !client_done.get(),
                "client cannot release before authenticating acceptance"
            );
            let mut parts = authenticated.into_parts();
            let expected = *parts
                .joining
                .cache
                .as_ref()
                .ok_or_else(|| invalid("missing final acceptance cache"))?
                .accepted;
            let mut input = [0; 1201];
            let mut output = [0; 1200];
            loop {
                let now = Instant::now();
                before(now, parts.deadline)?;
                if let Some(length) = parts
                    .bootstrap
                    .poll(
                        now,
                        metadata(parts.next_outer, cover::Phase::Handshake),
                        &mut output,
                    )
                    .map_err(bootstrap_error)?
                {
                    advance(&mut parts.next_outer)?;
                    handoff(parts.deadline, send(&parts.socket, &output[..length])).await?;
                }
                if let Some(length) = parts.joining.poll(
                    Instant::now(),
                    metadata(parts.next_outer, cover::Phase::Established),
                    &mut output,
                )? {
                    // Local output targets the peer ID, so inspect with its complementary cover.
                    let peer_cover = appearance(appearance_kind, 1, 2)
                        .map_err(|_| invalid("test appearance"))?;
                    assert_eq!(
                        peer_cover
                            .decode(&output[..length])
                            .map_err(cover_error)?
                            .protected,
                        expected
                    );
                    advance(&mut parts.next_outer)?;
                    handoff(parts.deadline, send(&parts.socket, &output[..length])).await?;
                    return Ok::<_, io::Error>(parts);
                }
                let now = Instant::now();
                let mut wake = parts
                    .bootstrap
                    .deadline()
                    .unwrap_or(parts.deadline)
                    .min(parts.joining.deadline().unwrap_or(parts.deadline))
                    .min(parts.deadline);
                if wake <= now {
                    wake = now + Duration::from_millis(1);
                }
                tokio::select! {
                    _ = sleep_until(wake) => {}
                    received = parts.socket.recv(&mut input) => {
                        let now = Instant::now();
                        before(now, parts.deadline)?;
                        let length = received?;
                        let decoded = match parts.cover.decode(&input[..length]) { Ok(decoded) => decoded, Err(_) => continue };
                        if !parts.bootstrap.receive(decoded, now).map_err(bootstrap_error)? {
                            parts.joining.receive(decoded, now)?;
                        }
                    }
                }
            }
        };
        let (client, server) = tokio::try_join!(client_future, server_future)?;
        assert_eq!(client.root.binding(), server.root.binding());
        assert!(client_done.get());
    }
    Ok(())
}

#[tokio::test]
async fn silent_peer_retries_exact_ciphertext_and_cancellation_closes_socket() -> Result {
    let (client, server) = pair(cover::Appearance::QuicLike).await?;
    let mut policy = settings(&client);
    policy.max_attempts = 3;
    let member = member(false)?;
    let client_future = connect(client, &member, policy);
    let observer = async {
        let mut input = [0; 1201];
        let mut proofs: Vec<Vec<u8>> = Vec::new();
        let mut packets = Vec::new();
        while proofs.len() < 3 {
            let length = handoff(server.deadline, server.socket.recv(&mut input)).await?;
            let decoded = match server.cover.decode(&input[..length]) {
                Ok(decoded) => decoded,
                Err(_) => continue,
            };
            if decoded.phase == cover::Phase::Established
                && decoded.protected.first() == Some(&ROUTE)
            {
                proofs.push(decoded.protected.to_vec());
                packets.push(input[..length].to_vec());
            }
        }
        assert_eq!(proofs[0], proofs[1]);
        assert_eq!(proofs[1], proofs[2]);
        assert_ne!(packets[0], packets[1]);
        Ok::<_, io::Error>(())
    };
    let (client, observed) = tokio::join!(client_future, observer);
    observed?;
    assert_eq!(
        client.err().map(|error| error.kind()),
        Some(io::ErrorKind::TimedOut)
    );
    let (client, _server) = pair(cover::Appearance::MediaLike).await?;
    let address = client.socket.local_addr()?;
    let policy = settings(&client);
    {
        let future = connect(client, &member, policy);
        tokio::pin!(future);
        tokio::select! {
            _ = sleep_until(Instant::now() + Duration::from_millis(5)) => {}
            _ = &mut future => return Err(invalid("silent member unexpectedly completed").into()),
        }
    }
    let rebound = UdpSocket::bind(address).await?;
    assert_eq!(rebound.local_addr()?, address);
    Ok(())
}

#[tokio::test]
async fn authenticated_acceptance_for_another_member_is_not_readiness() -> Result {
    let (client, mut server) = pair(cover::Appearance::QuicLike).await?;
    let policy = settings(&client);
    let key = member(false)?;
    let wrong = member(true)?.public_key();
    let client_future = connect(client, &key, policy);
    let malicious_peer = async {
        let mut sender = server
            .root
            .sender(
                security::Purpose::Joining,
                security::LaneId(0),
                JOINING_LIMITS,
                security::Protection::ChaCha20Poly1305,
            )
            .map_err(security_error)?;
        let mut body = [0; ACCEPT_BYTES];
        body[..2].copy_from_slice(&[1, 2]);
        body[2..].copy_from_slice(&wrong.0);
        let mut protected = [0; ACCEPT_WIRE];
        seal(&mut sender, policy.context, &body, &mut protected)?;
        let mut output = [0; 1200];
        let length = server
            .cover
            .encode(
                metadata(server.next_outer, cover::Phase::Established),
                &protected,
                &mut output,
            )
            .map_err(cover_error)?;
        handoff(server.deadline, send(&server.socket, &output[..length])).await
    };
    let (client, peer) = tokio::join!(client_future, malicious_peer);
    peer?;
    assert_eq!(
        client.err().map(|error| error.kind()),
        Some(io::ErrorKind::PermissionDenied)
    );
    Ok(())
}

#[tokio::test]
async fn receive_quota_preserves_retry_progress_under_unauthenticated_flood() -> Result {
    let (client, server) = pair(cover::Appearance::MediaLike).await?;
    let mut policy = settings(&client);
    policy.max_attempts = 2;
    policy.receive_packets_per_interval = 1;
    policy.receive_interval = Duration::from_millis(20);
    let key = member(false)?;
    let done = Cell::new(false);
    let client_future = async {
        let result = connect(client, &key, policy).await;
        done.set(true);
        result
    };
    let flood = async {
        let end = Instant::now() + Duration::from_millis(200);
        let mut sent = 0usize;
        while !done.get() && Instant::now() < end {
            if server.socket.send(&[0x80, 0]).await.is_err() {
                break;
            }
            sent += 1;
            if sent.is_multiple_of(64) {
                tokio::task::yield_now().await;
            }
        }
        sent
    };
    let started = Instant::now();
    let (client, sent) = tokio::join!(client_future, flood);
    assert!(sent > 1);
    assert_eq!(
        client.err().map(|error| error.kind()),
        Some(io::ErrorKind::TimedOut)
    );
    assert!(Instant::now().duration_since(started) < Duration::from_millis(500));
    Ok(())
}

fn decoded(body: &[u8]) -> cover::Decoded<'_> {
    cover::Decoded {
        phase: cover::Phase::Established,
        sequence: cover::OuterSequence::Quic(cover::PacketNumber(1)),
        media_timestamp: None,
        protected: body,
    }
}

#[test]
fn tail_retries_are_exact_interval_bounded_and_do_not_renew_or_keep_keys() -> Result {
    let cover = appearance(cover::Appearance::QuicLike, 2, 1)?;
    let now = Instant::now();
    let policy = Settings {
        context: identity::Context {
            session: security::SessionId([1; 16]),
            transcript: [2; 32],
            configuration: [3; 32],
            carrier: [4; 32],
            outer: [5; 32],
            initiator_noise: identity::NoisePublicKey([6; 32]),
            responder_noise: identity::NoisePublicKey([7; 32]),
        },
        retry_interval: Duration::from_millis(10),
        max_attempts: 3,
        receive_interval: Duration::from_millis(5),
        receive_packets_per_interval: 2,
    };
    let mut proof = [11; PROOF_WIRE];
    proof[0] = ROUTE;
    let mut accepted = [12; ACCEPT_WIRE];
    accepted[0] = ROUTE;
    let end = now + Duration::from_millis(100);
    let mut tail = JoiningTail::server(cover, policy, end, now, proof, accepted);
    let mut wrong = proof;
    wrong[5] ^= 1;
    assert!(tail.receive(decoded(&wrong), now)?);
    assert_eq!(tail.deadline(), Some(end));
    assert!(tail.receive(decoded(&proof), now)?);
    let due = now + Duration::from_millis(10);
    assert_eq!(tail.deadline(), Some(due));
    tail.receive(decoded(&proof), now + Duration::from_millis(5))?;
    assert_eq!(
        tail.deadline(),
        Some(due),
        "duplicates cannot postpone a scheduled retry"
    );
    assert_eq!(
        tail.poll(due, metadata(20, cover::Phase::Established), &mut [0; 1])
            .err()
            .map(|error| error.kind()),
        Some(io::ErrorKind::InvalidInput)
    );
    assert_eq!(tail.attempts, 1);
    let mut output = [0; 256];
    let length = tail
        .poll(due, metadata(21, cover::Phase::Established), &mut output)?
        .ok_or_else(|| invalid("retry not emitted"))?;
    let peer_cover = appearance(cover::Appearance::QuicLike, 1, 2)?;
    assert_eq!(peer_cover.decode(&output[..length])?.protected, accepted);
    tail.receive(decoded(&proof), due + Duration::from_millis(1))?;
    assert_eq!(tail.deadline(), Some(due + Duration::from_millis(10)));
    assert!(
        tail.poll(
            due + Duration::from_millis(10),
            metadata(22, cover::Phase::Established),
            &mut output
        )?
        .is_some()
    );
    assert!(tail.cache.is_none());
    assert_eq!(tail.deadline(), None);
    assert!(
        tail.poll(end, metadata(23, cover::Phase::Established), &mut output)?
            .is_none()
    );
    let mut expired = JoiningTail::server(cover, policy, end, now, proof, accepted);
    expired.receive(decoded(&proof), end - Duration::from_millis(1))?;
    assert!(
        expired
            .poll(end, metadata(24, cover::Phase::Established), &mut output)?
            .is_none()
    );
    assert!(expired.cache.is_none());
    for kind in [cover::Appearance::QuicLike, cover::Appearance::MediaLike] {
        let cover = appearance(kind, 2, 1)?;
        let peer_cover = appearance(kind, 1, 2)?;
        let mut exact = JoiningTail::server(cover, policy, end, now, proof, accepted);
        let required = exact.max_packet_bytes();
        assert_eq!(
            required,
            ACCEPT_WIRE + cover.overhead(cover::Phase::Established, ACCEPT_WIRE)?
        );
        assert!(required < cover.limits().max_packet_bytes);
        exact.receive(decoded(&proof), now)?;
        let mut output = vec![0x55; required];
        assert!(
            exact
                .poll(
                    due,
                    metadata(25, cover::Phase::Established),
                    &mut output[..required - 1]
                )
                .is_err()
        );
        assert_eq!(output, vec![0x55; required]);
        assert_eq!(exact.attempts, 1);
        assert_eq!(
            exact.poll(due, metadata(25, cover::Phase::Established), &mut output)?,
            Some(required)
        );
        assert_eq!(peer_cover.decode(&output)?.protected, accepted);
        exact.receive(decoded(&proof), end - Duration::from_millis(1))?;
        assert_eq!(
            exact.poll(end, metadata(26, cover::Phase::Established), &mut [])?,
            None
        );
        assert_eq!(exact.deadline(), None, "expiry needs no output capacity");
    }
    let mut number = u32::MAX;
    assert_eq!(
        advance(&mut number).err().map(|error| error.kind()),
        Some(io::ErrorKind::InvalidInput)
    );
    assert_eq!(number, u32::MAX);
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn blocked_or_ready_after_expiry_handoff_cannot_report_success() -> Result {
    let deadline = Instant::now() + Duration::from_millis(10);
    let blocked = handoff(deadline, std::future::pending::<io::Result<()>>()).await;
    assert_eq!(
        blocked.err().map(|error| error.kind()),
        Some(io::ErrorKind::TimedOut)
    );
    let deadline = Instant::now() + Duration::from_millis(10);
    let late = handoff(deadline, async {
        tokio::time::advance(Duration::from_millis(10)).await;
        Ok(())
    })
    .await;
    assert_eq!(
        late.err().map(|error| error.kind()),
        Some(io::ErrorKind::TimedOut)
    );
    Ok(())
}
