use super::*;
use tokio::net::TcpListener;

type TestError = Box<dyn std::error::Error + Send + Sync>;
type TestResult = Result<(), TestError>;

#[path = "sni_tests.rs"]
mod sni;
#[path = "udp_tests.rs"]
mod udp;

fn fixture() -> Result<(ClientTls, ServerTls), TestError> {
    let certified = rcgen::generate_simple_self_signed(vec!["tunnel.test".to_owned()])?;
    let chain = vec![certified.cert.der().to_vec()];
    Ok((
        ClientTls::from_der_roots(&chain)?,
        ServerTls::from_der(&chain, &certified.signing_key.serialize_der())?,
    ))
}

fn member() -> Result<MemberKey, Error> {
    MemberKey::from_pkcs8(&MemberKey::generate_pkcs8()?)
}

fn config(layer: PacketLayer) -> SessionConfig {
    SessionConfig {
        layer,
        digest: ConfigDigest([0xab; 32]),
    }
}

async fn authenticated_pair(
    layer: PacketLayer,
) -> Result<(AuthenticatedConnection, AuthenticatedConnection), TestError> {
    let (client_tls, server_tls) = fixture()?;
    let key = member()?;
    let members = MemberAllowlist::new(&[key.public_key()])?;
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let server_task = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.map_err(Error::Io)?;
        server_accept(
            tcp,
            &server_tls,
            &members,
            config(layer),
            Duration::from_secs(5),
        )
        .await
    });
    let tcp = TcpStream::connect(address).await?;
    let original_local = tcp.local_addr()?;
    let mut client = client_connect(
        tcp,
        &client_tls,
        "tunnel.test",
        &key,
        config(layer),
        Duration::from_secs(5),
    )
    .await?;
    let mut server = server_task.await??;
    assert_eq!(client.local_addr()?, original_local);
    assert_eq!(client.peer_addr()?, address);
    assert_eq!(server.peer_addr()?, original_local);
    assert_eq!(client.info().session_id, server.info().session_id);
    assert_eq!(client.info().member, server.info().member);
    assert_eq!(client.info().server, server.info().server);
    assert_eq!(client.info().config, server.info().config);
    assert_eq!(client.info().peer_member, None);
    assert_eq!(server.info().peer_member, Some(key.public_key()));
    assert_eq!(
        client.stream.get_ref().1.protocol_version(),
        Some(rustls::ProtocolVersion::TLSv1_3)
    );
    match &server.stream {
        TlsStream::Server(stream) => assert_eq!(stream.get_ref().1.server_name(), None),
        TlsStream::Client(_) => return Err("expected accepted server stream".into()),
    }
    client.write_all(b"client frame\x00\xff").await?;
    client.flush().await?;
    let mut received = [0; 14];
    server.read_exact(&mut received).await?;
    assert_eq!(&received, b"client frame\x00\xff");
    server.write_all(b"server frame").await?;
    server.flush().await?;
    let mut received = [0; 12];
    client.read_exact(&mut received).await?;
    assert_eq!(&received, b"server frame");
    Ok((client, server))
}

#[tokio::test]
async fn real_tls_tap_and_tun_keep_socket_verify_identity_and_exchange_data() -> TestResult {
    for layer in [PacketLayer::Ethernet, PacketLayer::Ip] {
        authenticated_pair(layer).await?;
    }
    Ok(())
}

#[tokio::test]
async fn exported_keys_match_and_separate_purpose_direction_and_lane() -> TestResult {
    let (client, server) = authenticated_pair(PacketLayer::Ip).await?;
    let baseline = client.export_key(KeyPurpose::Management, Direction::ClientToServer, 1)?;
    let remote = server.export_key(KeyPurpose::Management, Direction::ClientToServer, 1)?;
    assert!(baseline.expose_bytes() == remote.expose_bytes());
    for (purpose, direction, lane) in [
        (KeyPurpose::LaneJoin, Direction::ClientToServer, 1),
        (KeyPurpose::Data, Direction::ClientToServer, 1),
        (KeyPurpose::Management, Direction::ServerToClient, 1),
        (KeyPurpose::Management, Direction::ClientToServer, 2),
    ] {
        let separated = client.export_key(purpose, direction, lane)?;
        assert!(baseline.expose_bytes() != separated.expose_bytes());
    }
    Ok(())
}

#[tokio::test]
async fn wrong_certificate_root_and_name_fail_real_tls() -> TestResult {
    for wrong_root in [false, true] {
        let (mut client_tls, server_tls) = fixture()?;
        if wrong_root {
            client_tls = fixture()?.0;
        }
        let key = member()?;
        let members = MemberAllowlist::new(&[key.public_key()])?;
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let server_task = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.map_err(Error::Io)?;
            server_accept(
                tcp,
                &server_tls,
                &members,
                config(PacketLayer::Ip),
                Duration::from_secs(2),
            )
            .await
        });
        let tcp = TcpStream::connect(address).await?;
        let name = if wrong_root {
            "tunnel.test"
        } else {
            "wrong.test"
        };
        assert!(
            client_connect(
                tcp,
                &client_tls,
                name,
                &key,
                config(PacketLayer::Ip),
                Duration::from_secs(2)
            )
            .await
            .is_err()
        );
        assert!(server_task.await?.is_err());
    }
    Ok(())
}

#[tokio::test]
async fn member_and_configuration_mismatches_do_not_release_streams() -> TestResult {
    for variant in 0..3 {
        let (client_tls, server_tls) = fixture()?;
        let key = member()?;
        let allowed_key = if variant == 0 {
            member()?.public_key()
        } else {
            key.public_key()
        };
        let members = MemberAllowlist::new(&[allowed_key])?;
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let server_task = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.map_err(Error::Io)?;
            server_accept(
                tcp,
                &server_tls,
                &members,
                config(PacketLayer::Ip),
                Duration::from_secs(2),
            )
            .await
        });
        let mut expected = config(PacketLayer::Ip);
        if variant == 1 {
            expected.layer = PacketLayer::Ethernet;
        }
        if variant == 2 {
            expected.digest = ConfigDigest([0; 32]);
        }
        let tcp = TcpStream::connect(address).await?;
        let client = client_connect(
            tcp,
            &client_tls,
            "tunnel.test",
            &key,
            expected,
            Duration::from_secs(2),
        )
        .await;
        assert!(client.is_err());
        let server = server_task.await?;
        if variant == 0 {
            assert!(matches!(server, Err(Error::MemberDenied)));
        } else {
            assert!(server.is_err());
        }
    }
    Ok(())
}

async fn raw_client(tcp: TcpStream, tls: &ClientTls) -> Result<TlsStream<TcpStream>, TestError> {
    let name = ServerName::try_from("tunnel.test")?;
    Ok(TlsConnector::from(tls.0.clone())
        .connect(name, tcp)
        .await?
        .into())
}

#[tokio::test]
async fn malformed_oversized_and_out_of_state_frames_fail_without_waiting_for_body() -> TestResult {
    for variant in 0..4 {
        let (client_tls, server_tls) = fixture()?;
        let key = member()?;
        let members = MemberAllowlist::new(&[key.public_key()])?;
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let server_task = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.map_err(Error::Io)?;
            server_accept(
                tcp,
                &server_tls,
                &members,
                config(PacketLayer::Ip),
                Duration::from_secs(2),
            )
            .await
        });
        let mut stream = raw_client(TcpStream::connect(address).await?, &client_tls).await?;
        read_frame::<CHALLENGE_LEN>(&mut stream, CHALLENGE).await?;
        let mut header = *b"L2AU\x01\x02\x00\xa1";
        match variant {
            0 => header[0] = 0,
            1 => header[4] = 2,
            2 => header[5] = READY,
            _ => {
                header[6] = 255;
                header[7] = 255;
            }
        }
        stream.write_all(&header).await?;
        stream.flush().await?;
        assert!(matches!(server_task.await?, Err(Error::Protocol(_))));
    }
    Ok(())
}

#[tokio::test]
async fn total_timeout_applies_during_tls_and_application_handshake() -> TestResult {
    for complete_tls in [false, true] {
        let (client_tls, server_tls) = fixture()?;
        let key = member()?;
        let members = MemberAllowlist::new(&[key.public_key()])?;
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let server_task = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.map_err(Error::Io)?;
            server_accept(
                tcp,
                &server_tls,
                &members,
                config(PacketLayer::Ip),
                Duration::from_millis(100),
            )
            .await
        });
        let tcp = TcpStream::connect(address).await?;
        if complete_tls {
            let mut held_stream = raw_client(tcp, &client_tls).await?;
            read_frame::<CHALLENGE_LEN>(&mut held_stream, CHALLENGE).await?;
            assert!(matches!(server_task.await?, Err(Error::TimedOut)));
            drop(held_stream);
        } else {
            assert!(matches!(server_task.await?, Err(Error::TimedOut)));
            drop(tcp);
        }
    }
    Ok(())
}

#[tokio::test]
async fn captured_member_proof_cannot_replay_on_another_tls_connection() -> TestResult {
    let (client_tls, server_tls) = fixture()?;
    let key = member()?;
    let members = MemberAllowlist::new(&[key.public_key()])?;
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let tls = server_tls.clone();
    let allowed = members.clone();
    let first_server = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.map_err(Error::Io)?;
        let result = server_accept(
            tcp,
            &tls,
            &allowed,
            config(PacketLayer::Ip),
            Duration::from_secs(3),
        )
        .await;
        Ok::<_, Error>((listener, result))
    });
    let mut first = raw_client(TcpStream::connect(address).await?, &client_tls).await?;
    let challenge = read_frame::<CHALLENGE_LEN>(&mut first, CHALLENGE).await?;
    let mut proof = [0; PROOF_LEN];
    random_fill(&mut proof[..32])?;
    proof[32..64].copy_from_slice(&key.public_key().0);
    write_config(&mut proof[64..97], config(PacketLayer::Ip));
    let first_transcript = transcript(&first, &challenge, &proof[..PROOF_PREFIX_LEN])?;
    proof[PROOF_PREFIX_LEN..].copy_from_slice(&key.0.sign(&first_transcript)?);
    write_frame(&mut first, PROOF, &proof).await?;
    let accepted = read_frame::<48>(&mut first, ACCEPT).await?;
    write_frame(&mut first, FINISH, &accepted[16..]).await?;
    read_frame::<32>(&mut first, READY).await?;
    let (listener, first_result) = first_server.await??;
    first_result?;
    let second_server = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.map_err(Error::Io)?;
        server_accept(
            tcp,
            &server_tls,
            &members,
            config(PacketLayer::Ip),
            Duration::from_secs(3),
        )
        .await
    });
    let mut second = raw_client(TcpStream::connect(address).await?, &client_tls).await?;
    let second_challenge = read_frame::<CHALLENGE_LEN>(&mut second, CHALLENGE).await?;
    let replay_transcript = transcript(&second, &challenge, &proof[..PROOF_PREFIX_LEN])?;
    assert!(
        l2tunnel_identity::verify_signature(
            key.public_key(),
            &replay_transcript,
            &proof[PROOF_PREFIX_LEN..],
        )
        .is_err()
    );
    assert_ne!(second_challenge[..48], challenge[..48]);
    write_frame(&mut second, PROOF, &proof).await?;
    assert!(matches!(second_server.await?, Err(Error::InvalidProof)));
    Ok(())
}

#[tokio::test]
async fn valid_identity_with_corrupt_proof_or_lying_config_is_rejected() -> TestResult {
    for wrong_config in [false, true] {
        let (client_tls, server_tls) = fixture()?;
        let key = member()?;
        let members = MemberAllowlist::new(&[key.public_key()])?;
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let server_task = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.map_err(Error::Io)?;
            server_accept(
                tcp,
                &server_tls,
                &members,
                config(PacketLayer::Ip),
                Duration::from_secs(2),
            )
            .await
        });
        let mut stream = raw_client(TcpStream::connect(address).await?, &client_tls).await?;
        read_frame::<CHALLENGE_LEN>(&mut stream, CHALLENGE).await?;
        let mut proof = [0; PROOF_LEN];
        proof[32..64].copy_from_slice(&key.public_key().0);
        write_config(
            &mut proof[64..97],
            config(if wrong_config {
                PacketLayer::Ethernet
            } else {
                PacketLayer::Ip
            }),
        );
        write_frame(&mut stream, PROOF, &proof).await?;
        let result = server_task.await?;
        if wrong_config {
            assert!(matches!(result, Err(Error::BindingMismatch)));
        } else {
            assert!(matches!(result, Err(Error::InvalidProof)));
        }
    }
    Ok(())
}

#[test]
fn local_configuration_is_bounded_and_tls_defaults_are_restricted() -> TestResult {
    let (client_tls, server_tls) = fixture()?;
    assert!(!client_tls.0.enable_sni);
    assert!(!client_tls.0.enable_early_data);
    assert_eq!(server_tls.config.max_early_data_size, 0);
    assert_eq!(server_tls.config.send_tls13_tickets, 0);
    assert!(ClientTls::from_der_roots(&[]).is_err());
    assert!(ClientTls::from_der_roots(&[vec![0; 65_537]]).is_err());
    assert!(ServerTls::from_der(&[], &[]).is_err());
    assert!(MemberKey::from_pkcs8(&[]).is_err());
    assert!(MemberAllowlist::new(&[]).is_err());
    assert!(MemberAllowlist::new(&vec![MemberPublicKey([0; 32]); 1_025]).is_err());
    assert!(validate_timeout(Duration::ZERO).is_err());
    assert!(validate_timeout(Duration::from_secs(121)).is_err());
    Ok(())
}

#[tokio::test]
async fn caller_verified_exchange_separates_domain_exporter_certificate_config_and_roles()
-> TestResult {
    for mismatch in 0..6 {
        let key = member()?;
        let members = MemberAllowlist::new(&[key.public_key()])?;
        let server = CallerVerifiedChannel::new_after_verification(
            ChannelTransport::QuicTls,
            ServerIdentity([4; 32]),
            [5; 32],
        );
        let client = CallerVerifiedChannel::new_after_verification(
            if mismatch == 1 {
                ChannelTransport::TcpTls
            } else {
                ChannelTransport::QuicTls
            },
            ServerIdentity([if mismatch == 3 { 6 } else { 4 }; 32]),
            [if mismatch == 2 { 6 } else { 5 }; 32],
        );
        let cfg = config(PacketLayer::Ip);
        let mut client_cfg = cfg;
        if mismatch == 4 {
            client_cfg.digest.0[0] ^= 1;
        }
        if mismatch == 5 {
            client_cfg.layer = PacketLayer::Ethernet;
        }
        let (mut a, mut b) = tokio::io::duplex(1024);
        let deadline = Duration::from_millis(100);
        let (a_result, b_result) = tokio::join!(
            client_authenticate_channel(&mut a, &key, client_cfg, &client, deadline),
            server_authenticate_channel(&mut b, &members, cfg, &server, deadline),
        );
        if mismatch == 0 {
            assert_eq!(a_result?.session_id, b_result?.session_id);
        } else {
            assert!(a_result.is_err());
            assert!(b_result.is_err());
        }
    }
    let key = member()?;
    let binding = CallerVerifiedChannel::new_after_verification(
        ChannelTransport::QuicTls,
        ServerIdentity([4; 32]),
        [5; 32],
    );
    let (mut a, mut b) = tokio::io::duplex(1024);
    let deadline = Duration::from_millis(20);
    let (a_result, b_result) = tokio::join!(
        client_authenticate_channel(&mut a, &key, config(PacketLayer::Ip), &binding, deadline),
        client_authenticate_channel(&mut b, &key, config(PacketLayer::Ip), &binding, deadline),
    );
    assert!(matches!(a_result, Err(Error::TimedOut)));
    assert!(matches!(b_result, Err(Error::TimedOut)));
    Ok(())
}

#[tokio::test]
async fn generic_io_uses_actual_verified_tls_and_retains_exporter_and_stream() -> TestResult {
    for wrong_name in [false, true] {
        let (client_tls, server_tls) = fixture()?;
        let key = member()?;
        let members = MemberAllowlist::new(&[key.public_key()])?;
        let (a, b) = tokio::io::duplex(1024);
        let cfg = config(PacketLayer::Ip);
        let (a, b) = tokio::join!(
            client_connect_io(
                a,
                &client_tls,
                if wrong_name {
                    "wrong.test"
                } else {
                    "tunnel.test"
                },
                &key,
                cfg,
                Duration::from_secs(2)
            ),
            server_accept_io(b, &server_tls, &members, cfg, Duration::from_secs(2)),
        );
        if wrong_name {
            assert!(a.is_err());
            assert!(b.is_err());
            continue;
        }
        let mut a = a?;
        let mut b = b?;
        assert_eq!(a.info().session_id, b.info().session_id);
        assert_eq!(
            a.export_key(KeyPurpose::Data, Direction::ClientToServer, 0)?
                .expose_bytes(),
            b.export_key(KeyPurpose::Data, Direction::ClientToServer, 0)?
                .expose_bytes()
        );
        a.write_all(b"same TLS").await?;
        let mut bytes = [0; 8];
        b.read_exact(&mut bytes).await?;
        assert_eq!(&bytes, b"same TLS");
        let (stream, _) = a.into_parts();
        assert_eq!(
            stream.get_ref().1.protocol_version(),
            Some(rustls::ProtocolVersion::TLSv1_3)
        );
    }
    Ok(())
}

#[tokio::test]
async fn explicit_tls_profile_verifies_identity_rejects_domain_mismatch_and_separates_keys()
-> TestResult {
    for mismatch in 0..6 {
        let (mut client_tls, server_tls) = fixture()?;
        let key = member()?;
        let allowed = if mismatch == 4 {
            member()?.public_key()
        } else {
            key.public_key()
        };
        let members = MemberAllowlist::new(&[allowed])?;
        if mismatch == 2 {
            client_tls = fixture()?.0;
        }
        let cfg = config(PacketLayer::Ip);
        let mut client_cfg = cfg;
        if mismatch == 5 {
            client_cfg.digest.0[0] ^= 1;
        }
        let (a, b) = tokio::io::duplex(4096);
        let (a, b) = tokio::join!(
            client_connect_profile_io(
                a,
                &client_tls,
                if mismatch == 3 {
                    "wrong.test"
                } else {
                    "tunnel.test"
                },
                &key,
                client_cfg,
                TlsIoProfile::OpenVpnLikeTls,
                Duration::from_secs(2)
            ),
            server_accept_profile_io(
                b,
                &server_tls,
                &members,
                cfg,
                if mismatch == 1 {
                    TlsIoProfile::TcpTls
                } else {
                    TlsIoProfile::OpenVpnLikeTls
                },
                Duration::from_secs(2)
            ),
        );
        if mismatch != 0 {
            assert!(a.is_err() && b.is_err());
            continue;
        }
        let mut a = a?;
        let mut b = b?;
        assert_eq!(a.profile(), TlsIoProfile::OpenVpnLikeTls);
        assert_eq!(b.profile(), a.profile());
        match &b.stream {
            TlsStream::Server(stream) => assert_eq!(stream.get_ref().1.server_name(), None),
            TlsStream::Client(_) => return Err("expected server TLS".into()),
        }
        let key = a.export_key(KeyPurpose::Data, Direction::ClientToServer, 7)?;
        assert_eq!(
            key.expose_bytes(),
            b.export_key(KeyPurpose::Data, Direction::ClientToServer, 7)?
                .expose_bytes()
        );
        // Same TLS session and identical public context must still separate all old/new labels.
        let new = export(
            &a.stream,
            TlsIoProfile::OpenVpnLikeTls.key_label(KeyPurpose::Data),
            Some(b"fixed-context"),
        )?;
        let old = export(
            &a.stream,
            TlsIoProfile::TcpTls.key_label(KeyPurpose::Data),
            Some(b"fixed-context"),
        )?;
        assert_ne!(new, old);
        for purpose in [KeyPurpose::LaneJoin, KeyPurpose::Management] {
            assert_ne!(
                key.expose_bytes(),
                a.export_key(purpose, Direction::ClientToServer, 7)?
                    .expose_bytes()
            );
        }
        a.write_all(b"verified profile bytes").await?;
        let mut bytes = [0; 22];
        b.read_exact(&mut bytes).await?;
        assert_eq!(&bytes, b"verified profile bytes");
    }
    assert_eq!(
        ChannelTransport::TcpTls.exporter_label(),
        b"EXPORTER-l2tunnel-member-proof-v1"
    );
    assert_eq!(
        ChannelTransport::TcpTls.transcript_domain(),
        b"l2tunnel/member-auth/v1\0"
    );
    assert_eq!(
        ChannelTransport::QuicTls.exporter_label(),
        b"EXPORTER-l2tunnel-quic-member-proof-v1"
    );
    assert_ne!(
        ChannelTransport::OpenVpnLikeTls.exporter_label(),
        ChannelTransport::QuicTls.exporter_label()
    );
    Ok(())
}

#[tokio::test]
async fn explicit_tls_profile_timeout_and_cancellation_drop_original_io() -> TestResult {
    let (client_tls, _) = fixture()?;
    let key = member()?;
    let (io, _peer) = tokio::io::duplex(4096);
    assert!(matches!(
        client_connect_profile_io(
            io,
            &client_tls,
            "tunnel.test",
            &key,
            config(PacketLayer::Ip),
            TlsIoProfile::OpenVpnLikeTls,
            Duration::from_millis(20)
        )
        .await,
        Err(Error::TimedOut)
    ));
    let (io, mut peer) = tokio::io::duplex(4096);
    let pending = tokio::spawn(async move {
        client_connect_profile_io(
            io,
            &client_tls,
            "tunnel.test",
            &key,
            config(PacketLayer::Ip),
            TlsIoProfile::OpenVpnLikeTls,
            Duration::from_secs(2),
        )
        .await
    });
    let mut hello = [0; 4096];
    assert!(timeout(Duration::from_secs(1), peer.read(&mut hello)).await?? > 0);
    pending.abort();
    assert!(pending.await.is_err_and(|error| error.is_cancelled()));
    assert_eq!(
        timeout(Duration::from_secs(1), peer.read(&mut hello)).await??,
        0
    );
    Ok(())
}
