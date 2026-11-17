//! Actual managed initial authentication and retained joining custody only.
use super::*;
use l2tunnel::handshake as hs;
use l2tunnel_udp_control as gate;
use std::{cell::Cell, future::poll_fn, task::Poll};

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
    // Published RFC8032 vectors, never deployment credentials.
    let (seed, public) = if other {
        (
            "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
            "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
        )
    } else {
        (
            "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        )
    };
    let text = format!("3051020101300506032b657004220420{seed}812100{public}");
    let bytes = text
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| Ok(u8::from_str_radix(std::str::from_utf8(pair)?, 16)?))
        .collect::<Result<Vec<u8>>>()?;
    Ok(identity::IdentityKey::from_pkcs8(&bytes)?)
}
fn appearance(kind: cover::Appearance, local: u8, peer: u8) -> Result<cover::Config> {
    Ok(cover::Config::new(
        kind,
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
fn selection(key_micros: u64) -> Result<hs::refresh::Selection> {
    Ok(hs::refresh::Selection::new(hs::refresh::SelectionSpec {
        lane: security::LaneId(3),
        limits: security::Limits {
            max_body_bytes: 256,
            packets_per_key: security::MAX_PACKETS_PER_KEY,
            max_body_bytes_per_key: security::MAX_BODY_BYTES_PER_KEY,
        },
        protection: security::Protection::ChaCha20Poly1305,
        control_epoch: security::Epoch(4),
        control_digest: security::ConfigDigest([19; 32]),
        envelope_digest: security::ConfigDigest([20; 32]),
        exchange_micros: 1_000_000,
        key_micros,
        overlap_micros: 1_000,
        max_flight_copies: 8,
    })?)
}

async fn pair(
    kind: cover::Appearance,
    profile: hs::Profile,
    selected: hs::refresh::Selection,
) -> Result<(
    establish::refresh::Established,
    establish::refresh::Established,
)> {
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
        + if kind == cover::Appearance::QuicLike {
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
    gate.cookie_ttl = Duration::from_secs(2);
    gate.handshake_timeout = Duration::from_secs(2);
    gate.initial_rto = Duration::from_millis(10);
    gate.maximum_rto = Duration::from_millis(100);
    gate.gate_attempts = 32;
    let client_key = hs::LocalSecret::new(Zeroizing::new([11; 32]));
    let server_key = hs::LocalSecret::new(Zeroizing::new([22; 32]));
    let peers = establish::Peers {
        initiator: client_key.public_key(),
        responder: server_key.public_key(),
    };
    // The complete control digest is deliberately distinct from H0; no recursive hash.
    let binding = establish::Binding {
        configuration: [3; 32],
        carrier: [4; 32],
        outer: [5; 32],
        member: [6; 32],
    };
    let client_config = establish::Config {
        gate,
        cover: appearance(kind, 1, 2)?,
        profile,
        binding,
        receive_packets_per_interval: 64,
    };
    let server_config = establish::Config {
        cover: appearance(kind, 2, 1)?,
        ..client_config
    };
    let now = Instant::now();
    let deadline = now + Duration::from_secs(2);
    let mut admission = establish::refresh::ServerAdmission::new(
        server_config,
        selected,
        peers,
        gate::Secret::new([7; 32]),
        gate::Secret::new([8; 32]),
        now,
    )?;
    let psk = || (profile == hs::Profile::IkPsk2).then(|| hs::Psk::new(Zeroizing::new([9; 32])));
    let mut client_entropy = Entropy(40);
    let mut server_entropy = Entropy(60);
    let (client, server) = tokio::try_join!(
        establish::refresh::connect(
            client,
            client_config,
            selected,
            establish::Identity {
                local: client_key,
                peer: peers.responder,
                psk: psk()
            },
            gate::Secret::new([7; 32]),
            deadline,
            &mut client_entropy
        ),
        establish::refresh::accept(
            server,
            establish::Identity {
                local: server_key,
                peer: peers.initiator,
                psk: psk()
            },
            &mut admission,
            deadline,
            &mut server_entropy
        ),
    )?;
    assert_eq!(client.binding(), server.binding());
    assert_eq!(client.authenticated(), server.authenticated());
    assert_eq!(client.deadline(), deadline);
    assert_eq!(server.deadline(), deadline);
    assert_eq!(client.local_addr()?, path.client);
    assert_eq!(server.local_addr()?, path.server);
    Ok((client, server))
}

fn settings(established: &establish::refresh::Established) -> Settings {
    let binding = established.binding();
    let authenticated = established.authenticated();
    let peers = established.peers();
    Settings {
        context: identity::Context {
            session: binding.session,
            transcript: binding.transcript,
            configuration: authenticated.configuration,
            carrier: authenticated.carrier,
            outer: authenticated.outer,
            initiator_noise: identity::NoisePublicKey(peers.initiator.0),
            responder_noise: identity::NoisePublicKey(peers.responder.0),
        },
        retry_interval: Duration::from_millis(10),
        max_attempts: 32,
        receive_interval: Duration::from_millis(5),
        receive_packets_per_interval: 8,
    }
}
#[tokio::test]
async fn actual_selected_member_handoff_retains_initial_authority_on_original_socket() -> Result {
    for kind in [cover::Appearance::QuicLike, cover::Appearance::MediaLike] {
        for profile in [hs::Profile::Ik, hs::Profile::IkPsk2] {
            let selected = selection(5_000_000)?;
            let (client, server) = pair(kind, profile, selected).await?;
            let client_origin = client.clock_origin();
            let server_origin = server.clock_origin();
            let client_addr = client.local_addr()?;
            let server_addr = server.local_addr()?;
            let original_deadline = client.deadline();
            let client_settings = settings(&client);
            let server_settings = settings(&server);
            let member = member(false)?;
            let members = identity::Allowlist::new(&[member.public_key()])?;
            let (client, server) = tokio::try_join!(
                refresh::connect(client, &member, client_settings),
                refresh::accept(server, members, server_settings),
            )?;
            assert_eq!(client.info().member, member.public_key());
            assert_eq!(client.info().binding, server.info().binding);
            assert_eq!(client.info().local_addr, client_addr);
            assert_eq!(server.info().local_addr, server_addr);
            let client = client.into_parts();
            let server = server.into_parts();
            assert_eq!(client.clock_origin(), client_origin);
            assert_eq!(server.clock_origin(), server_origin);
            assert_eq!(client.deadline, original_deadline);
            assert_eq!(server.deadline, original_deadline);
            assert_eq!(client.initial.selection(), selected);
            assert_eq!(server.initial.selection(), selected);
            assert_eq!(client.initial.pins(), server.initial.pins());
            assert_eq!(client.initial.role(), security::Role::Initiator);
            assert_eq!(server.initial.role(), security::Role::Responder);
            assert_eq!(client.socket.local_addr()?, client_addr);
            assert_eq!(server.socket.local_addr()?, server_addr);
        }
    }
    Ok(())
}

#[tokio::test]
async fn selected_member_denial_and_context_mismatch_do_not_release_authority() -> Result {
    let (client, server) = pair(
        cover::Appearance::QuicLike,
        hs::Profile::Ik,
        selection(5_000_000)?,
    )
    .await?;
    let mut client_settings = settings(&client);
    client_settings.context.configuration[0] ^= 1;
    let member = member(false)?;
    let mut observations = Vec::new();
    let result = refresh::connect_observed(client, &member, client_settings, &mut |row| {
        observations.push(row)
    })
    .await;
    assert_eq!(
        result.err().ok_or("mismatched H0 accepted")?.kind(),
        io::ErrorKind::InvalidInput
    );
    assert_eq!(
        observations.last().and_then(|row| row.reason),
        Some(Reason::Configuration)
    );
    drop(server);

    let (client, server) = pair(
        cover::Appearance::MediaLike,
        hs::Profile::IkPsk2,
        selection(5_000_000)?,
    )
    .await?;
    let client_settings = settings(&client);
    let server_settings = settings(&server);
    let members = identity::Allowlist::new(&[self::member(true)?.public_key()])?;
    let mut observations = Vec::new();
    let mut observer = |row| observations.push(row);
    let result = tokio::try_join!(
        refresh::connect(client, &member, client_settings),
        refresh::accept_observed(server, members, server_settings, &mut observer),
    );
    assert_eq!(
        result.err().ok_or("unlisted member accepted")?.kind(),
        io::ErrorKind::PermissionDenied
    );
    assert_eq!(
        observations.last().and_then(|row| row.reason),
        Some(Reason::Authentication)
    );
    Ok(())
}

#[tokio::test]
async fn managed_joining_wakes_at_retained_key_cap_without_renewing_outer_deadline() -> Result {
    let (client, server) = pair(
        cover::Appearance::QuicLike,
        hs::Profile::Ik,
        selection(100_000)?,
    )
    .await?;
    let original_deadline = server.deadline();
    let settings = settings(&server);
    let member = member(false)?;
    let members = identity::Allowlist::new(&[member.public_key()])?;
    tokio::time::pause();
    let mut observations = Vec::new();
    let mut observer = |row| observations.push(row);
    let mut future = Box::pin(refresh::accept_observed(
        server,
        members,
        settings,
        &mut observer,
    ));
    let pending = poll_fn(|cx| Poll::Ready(future.as_mut().poll(cx).is_pending())).await;
    assert!(
        pending,
        "silent peer must retain actual managed Joining custody"
    );
    tokio::time::advance(Duration::from_micros(100_000)).await;
    let result = future.await;
    assert_eq!(
        result
            .err()
            .ok_or("expired managed Joining released authority")?
            .kind(),
        io::ErrorKind::TimedOut
    );
    assert!(Instant::now() < original_deadline);
    assert_eq!(
        observations.last().and_then(|row| row.reason),
        Some(Reason::OriginalDeadline)
    );
    drop(client);
    Ok(())
}

#[tokio::test]
async fn selected_dropped_acceptance_retries_original_ciphertext_after_key_owner_retirement()
-> Result {
    for kind in [cover::Appearance::QuicLike, cover::Appearance::MediaLike] {
        let (client, server) = pair(kind, hs::Profile::Ik, selection(5_000_000)?).await?;
        let client_settings = settings(&client);
        let server_settings = settings(&server);
        let member = member(false)?;
        let members = identity::Allowlist::new(&[member.public_key()])?;
        let client_done = Cell::new(false);
        let client_future = async {
            let authenticated = refresh::connect(client, &member, client_settings).await?;
            client_done.set(true);
            Ok::<_, io::Error>(authenticated.into_parts())
        };
        let server_future = async {
            let authenticated = DROP_FIRST_ACCEPTANCE
                .scope(
                    Cell::new(true),
                    refresh::accept(server, members, server_settings),
                )
                .await?;
            assert!(
                !client_done.get(),
                "actual acceptance must precede client authority release"
            );
            let mut parts = authenticated.into_parts();
            let expected = *parts
                .joining
                .cache
                .as_ref()
                .ok_or_else(|| invalid("missing ciphertext tail"))?
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
                    assert_eq!(
                        timeout_at(parts.deadline, parts.socket.send(&output[..length]))
                            .await
                            .map_err(|_| timed_out("test bootstrap send cap"))??,
                        length
                    );
                }
                if let Some(length) = parts.joining.poll(
                    Instant::now(),
                    metadata(parts.next_outer, cover::Phase::Established),
                    &mut output,
                )? {
                    let peer = appearance(kind, 1, 2).map_err(|_| invalid("test cover"))?;
                    assert_eq!(
                        peer.decode(&output[..length])
                            .map_err(cover_error)?
                            .protected,
                        expected
                    );
                    advance(&mut parts.next_outer)?;
                    assert_eq!(
                        timeout_at(parts.deadline, parts.socket.send(&output[..length]))
                            .await
                            .map_err(|_| timed_out("test acceptance send cap"))??,
                        length
                    );
                    return Ok::<_, io::Error>(parts);
                }
                let wake = parts
                    .bootstrap
                    .deadline()
                    .unwrap_or(parts.deadline)
                    .min(parts.joining.deadline().unwrap_or(parts.deadline))
                    .min(parts.deadline);
                tokio::select! {
                    _ = sleep_until(wake) => {},
                    received = parts.socket.recv(&mut input) => {
                        let length = received?;
                        let decoded = parts.cover.decode(&input[..length]).map_err(cover_error)?;
                        if !parts.bootstrap.receive(decoded, Instant::now()).map_err(bootstrap_error)? {
                            assert!(parts.joining.receive(decoded, Instant::now())?);
                        }
                    }
                }
            }
        };
        let (client, server) = tokio::try_join!(client_future, server_future)?;
        assert!(client_done.get());
        assert_eq!(client.info.binding, server.info.binding);
        assert_eq!(server.joining.attempts, 2);
        assert_eq!(server.initial.binding(), server.info.binding);
        assert_eq!(client.initial.binding(), client.info.binding);
    }
    Ok(())
}
