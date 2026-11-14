//! Actual factory authentication of the explicitly selected streamed profile.
use super::*;
use crate::secure_udp::{self, member};
use std::error::Error;
use tokio::{net::UdpSocket, time::Instant};

type Result<T = ()> = std::result::Result<T, Box<dyn Error + Send + Sync>>;

async fn sockets() -> Result<[UdpSocket; 2]> {
    let sockets = [
        UdpSocket::bind("127.0.0.1:0").await?,
        UdpSocket::bind("127.0.0.1:0").await?,
    ];
    sockets[0].connect(sockets[1].local_addr()?).await?;
    sockets[1].connect(sockets[0].local_addr()?).await?;
    Ok(sockets)
}

fn identities() -> [establish::Identity; 2] {
    let client = hs::LocalSecret::new(Zeroizing::new([11; 32]));
    let server = hs::LocalSecret::new(Zeroizing::new([22; 32]));
    let client_public = client.public_key();
    let server_public = server.public_key();
    [
        establish::Identity {
            local: client,
            peer: server_public,
            psk: None,
        },
        establish::Identity {
            local: server,
            peer: client_public,
            psk: None,
        },
    ]
}

fn member_key() -> Result<identity::IdentityKey> {
    let encoded = Zeroizing::new(l2tunnel_auth::MemberKey::generate_pkcs8()?);
    Ok(identity::IdentityKey::from_pkcs8(&encoded)?)
}

fn selected_profile(
    appearance: l2tunnel_cover::Appearance,
    sockets: &[UdpSocket; 2],
    member: identity::MemberPublicKey,
) -> Result<(Profile, establish::Peers)> {
    let (base, peers) = fixture(
        l2tunnel_udp_control::Path {
            client: sockets[0].local_addr()?,
            server: sockets[1].local_addr()?,
        },
        appearance,
        member,
    )?;
    let mut initiator = base.initiator;
    let mut responder = base.responder;
    enable_streams(&mut initiator)?;
    enable_streams(&mut responder)?;
    Ok((
        Profile::new(
            base.connection,
            base.session_with_seed(),
            initiator,
            responder,
        )?,
        peers,
    ))
}

fn outer(parts: &member::Parts, phase: l2tunnel_cover::Phase) -> l2tunnel_cover::PacketMeta {
    l2tunnel_cover::PacketMeta {
        phase,
        packet_number: l2tunnel_cover::PacketNumber(parts.next_outer),
        media_timestamp: l2tunnel_cover::MediaTimestamp(parts.next_outer.wrapping_mul(960)),
    }
}

async fn service_early(parts: &mut member::Parts) -> Result {
    let mut output = vec![0; parts.cover.limits().max_packet_bytes];
    let metadata = outer(parts, l2tunnel_cover::Phase::Handshake);
    if let Some(length) = parts
        .bootstrap
        .poll(Instant::now(), metadata, &mut output)?
    {
        parts.next_outer = parts.next_outer.checked_add(1).ok_or("outer exhaustion")?;
        assert_eq!(parts.socket.send(&output[..length]).await?, length);
    }
    let metadata = outer(parts, l2tunnel_cover::Phase::Established);
    if let Some(length) = parts.joining.poll(Instant::now(), metadata, &mut output)? {
        parts.next_outer = parts.next_outer.checked_add(1).ok_or("outer exhaustion")?;
        assert_eq!(parts.socket.send(&output[..length]).await?, length);
    }
    let maximum = parts.cover.limits().max_packet_bytes;
    let mut input = vec![0; maximum + 1];
    for _ in 0..32 {
        let length = match parts.socket.try_recv(&mut input) {
            Ok(length) => length,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
            Err(error) => return Err(error.into()),
        };
        assert!(length <= maximum);
        let decoded = parts.cover.decode(&input[..length])?;
        if !parts.bootstrap.receive(decoded, Instant::now())? {
            assert!(parts.joining.receive(decoded, Instant::now())?);
        }
    }
    Ok(())
}

#[tokio::test]
async fn real_factories_authenticate_selected_stream_contract_on_both_original_pairs() -> Result {
    authenticate_profiles(false).await
}

#[tokio::test]
async fn real_factories_authenticate_complete_generic_catalog_and_distinct_user_digest() -> Result {
    authenticate_profiles(true).await
}

async fn authenticate_profiles(generic: bool) -> Result {
    for appearance in [
        l2tunnel_cover::Appearance::QuicLike,
        l2tunnel_cover::Appearance::MediaLike,
    ] {
        let sockets = sockets().await?;
        let originals = [
            (sockets[0].local_addr()?, sockets[0].peer_addr()?),
            (sockets[1].local_addr()?, sockets[1].peer_addr()?),
        ];
        let member = member_key()?;
        let (profile, peers) = selected_profile(appearance, &sockets, member.public_key())?;
        let transaction = if generic {
            use crate::secure_udp::transaction_profile::{
                Parameters, Profile as TransactionProfile,
            };
            use l2tunnel::swift_configuration::{Catalog, Descriptor};
            let mut initiator = profile.runtime(security::Role::Initiator);
            let mut responder = profile.runtime(security::Role::Responder);
            initiator.send.records.channels = 2;
            initiator.receive.records.channels = 3;
            initiator.send.bytes_per_second += 1;
            initiator.receive.records.codec.window += 1;
            responder.send = initiator.receive;
            responder.receive = initiator.send;
            let initial = Descriptor::new(initiator.path_mtu, initiator.send, initiator.receive)?;
            let mut forward = initiator.send;
            let mut reverse = initiator.receive;
            forward.records.channels = 4;
            reverse.records.channels = 1;
            let target = Descriptor::new(initiator.path_mtu, forward, reverse)?;
            Some(TransactionProfile::new(
                profile.connection(),
                profile.session_with_seed(),
                peers,
                initiator,
                responder,
                Catalog::new(initial, &[initial, target])?,
                Parameters {
                    protocol: l2tunnel_management::transaction::Settings::default(),
                    max_operation_ms: 5000,
                    retained_bytes: 256 << 20,
                },
            )?)
        } else {
            None
        };
        let requested = transaction
            .as_ref()
            .map_or(profile.settings(), |value| value.settings());
        let expected = match &transaction {
            Some(value) => value.configuration()?,
            None => profile.configuration(peers)?,
        };
        if let Some(value) = &transaction {
            assert_ne!(value.data_digest().0, expected.0);
            assert_eq!(
                value.data_digest(),
                l2tunnel_management::transaction::configuration_digest(&value.initial())?
            );
        }
        let [client_socket, server_socket] = sockets;
        let [client_identity, server_identity] = identities();
        let origin = Instant::now();
        let deadline = origin + Duration::from_secs(2);
        let mut server = secure_udp::Server::new(
            requested,
            peers,
            l2tunnel_udp_control::Secret::new([41; 32]),
            l2tunnel_udp_control::Secret::new([42; 32]),
            origin,
        )?;
        let mut client_entropy = establish::RuntimeEntropy::new();
        let mut server_entropy = establish::RuntimeEntropy::new();
        let client = secure_udp::connect(
            client_socket,
            requested,
            client_identity,
            &member,
            l2tunnel_udp_control::Secret::new([41; 32]),
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
        let (side, early) = tokio::select! {
            result = &mut client => (0, result?),
            result = &mut accepted => (1, result?),
            _ = tokio::time::sleep_until(deadline) => return Err("factory deadline".into()),
        };
        assert_eq!(early.requested(), requested);
        assert_eq!(early.info().authenticated.configuration, expected.0);
        let mut early = early.into_parts();
        let late = loop {
            tokio::select! {
                result = &mut client, if side == 1 => break result?,
                result = &mut accepted, if side == 0 => break result?,
                _ = tokio::time::sleep(Duration::from_millis(1)) => service_early(&mut early).await?,
                _ = tokio::time::sleep_until(deadline) => return Err("factory tail deadline".into()),
            }
        };
        assert_eq!(late.requested(), requested);
        assert_eq!(late.info().authenticated.configuration, expected.0);
        let late = late.into_parts();
        let parts = if side == 0 {
            [early, late]
        } else {
            [late, early]
        };
        assert_eq!(parts[0].info.binding, parts[1].info.binding);
        for (side, parts) in parts.into_iter().enumerate() {
            let role = if side == 0 {
                security::Role::Initiator
            } else {
                security::Role::Responder
            };
            assert_eq!(parts.info.role, role);
            assert_eq!(parts.info.peers, peers);
            assert_eq!(parts.info.authenticated.configuration, expected.0);
            assert_eq!(
                parts.info.authenticated.session,
                parts.root.binding().session
            );
            assert_eq!(parts.root.binding(), parts.info.binding);
            assert_eq!(
                (parts.socket.local_addr()?, parts.socket.peer_addr()?),
                originals[side]
            );
            assert_eq!(parts.deadline, deadline);
            let runtime = match &transaction {
                Some(value) => value.runtime_for(value.initial(), role)?,
                None => profile.runtime(role),
            };
            assert!(runtime.streams.is_some());
        }
    }
    Ok(())
}

#[tokio::test]
async fn mismatched_stream_selection_or_bounds_cannot_release_factory_authentication() -> Result {
    for appearance in [
        l2tunnel_cover::Appearance::QuicLike,
        l2tunnel_cover::Appearance::MediaLike,
    ] {
        for mismatch in 0..2 {
            let sockets = sockets().await?;
            let member = member_key()?;
            let (selected, peers) = selected_profile(appearance, &sockets, member.public_key())?;
            let mut a = selected.initiator;
            let mut b = selected.responder;
            for runtime in [&mut a, &mut b] {
                if mismatch == 0 {
                    runtime.streams = None;
                } else {
                    runtime.streams.as_mut().ok_or("missing streams")?.streams[0].work_per_call +=
                        1;
                }
            }
            let other = Profile::new(selected.connection, selected.session_with_seed(), a, b)?;
            assert_ne!(selected.configuration(peers)?, other.configuration(peers)?);
            let [client_socket, server_socket] = sockets;
            let [client_identity, server_identity] = identities();
            let origin = Instant::now();
            let deadline = origin + Duration::from_millis(250);
            let mut server = secure_udp::Server::new(
                other.settings(),
                peers,
                l2tunnel_udp_control::Secret::new([41; 32]),
                l2tunnel_udp_control::Secret::new([42; 32]),
                origin,
            )?;
            let mut client_entropy = establish::RuntimeEntropy::new();
            let mut server_entropy = establish::RuntimeEntropy::new();
            let (client, accepted) = tokio::join!(
                secure_udp::connect(
                    client_socket,
                    selected.settings(),
                    client_identity,
                    &member,
                    l2tunnel_udp_control::Secret::new([41; 32]),
                    deadline,
                    &mut client_entropy,
                ),
                server.accept(
                    server_socket,
                    server_identity,
                    deadline,
                    &mut server_entropy
                ),
            );
            assert!(
                client.is_err(),
                "client released mismatched contract {mismatch}"
            );
            assert!(
                accepted.is_err(),
                "server released mismatched contract {mismatch}"
            );
        }
    }
    Ok(())
}
