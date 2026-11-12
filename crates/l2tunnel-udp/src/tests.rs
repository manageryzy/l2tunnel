use super::*;
use l2tunnel_auth::{
    ClientTls, MemberAllowlist, MemberKey, ServerTls, client_connect, server_accept,
};
use tokio::net::{TcpListener, TcpStream};
type TestError = Box<dyn std::error::Error + Send + Sync>;
type TestResult = Result<(), TestError>;

fn profile() -> Profile {
    Profile {
        traffic: Traffic::FullDuplex,
        cover: CoverProfile::QuicLike,
        protection: Protection::ChaCha20Poly1305,
        lane: LaneId(7),
        generation: KeyGeneration(3),
        path_mtu: 1500,
        outer_overhead_bytes: 28,
        max_payload_bytes: 256,
        max_packets_per_key: 1000,
        max_payload_bytes_per_key: 1_000_000,
    }
}
fn base() -> SessionConfig {
    SessionConfig {
        layer: PacketLayer::Ethernet,
        digest: ConfigDigest([21; 32]),
    }
}
async fn auth_pair(
    profile: Profile,
) -> Result<(AuthenticatedConnection, AuthenticatedConnection), TestError> {
    let cert = rcgen::generate_simple_self_signed(vec!["udp.test".to_owned()])?;
    let chain = vec![cert.cert.der().to_vec()];
    let client_tls = ClientTls::from_der_roots(&chain)?;
    let server_tls = ServerTls::from_der(&chain, &cert.signing_key.serialize_der())?;
    let key = MemberKey::from_pkcs8(&MemberKey::generate_pkcs8()?)?;
    let members = MemberAllowlist::new(&[key.public_key()])?;
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let client = TcpStream::connect(listener.local_addr()?).await?;
    client.set_nodelay(true)?;
    let (server, _) = listener.accept().await?;
    server.set_nodelay(true)?;
    Ok(tokio::try_join!(
        client_connect(
            client,
            &client_tls,
            "udp.test",
            &key,
            session_config(base(), profile)?,
            Duration::from_secs(3)
        ),
        server_accept(
            server,
            &server_tls,
            &members,
            session_config(base(), profile)?,
            Duration::from_secs(3)
        ),
    )?)
}
async fn carriers(profile: Profile, duration: Duration) -> Result<(Carrier, Carrier), TestError> {
    let (client, server) = auth_pair(profile).await?;
    let client_tcp = client.local_addr()?;
    let server_tcp = server.local_addr()?;
    let a = UdpSocket::bind("127.0.0.1:0").await?;
    let b = UdpSocket::bind("127.0.0.1:0").await?;
    let client_config = Config {
        base: base(),
        profile,
        peer: b.local_addr()?,
        timeout: duration,
    };
    let server_config = Config {
        peer: a.local_addr()?,
        ..client_config
    };
    let (client, server) = tokio::try_join!(
        establish(client, a, client_config),
        establish(server, b, server_config)
    )?;
    assert_eq!(client.control.local_addr()?, client_tcp);
    assert_eq!(server.control.local_addr()?, server_tcp);
    Ok((client, server))
}
fn delivered(event: ReceiveEvent) -> Result<OpenedPacket, TestError> {
    if let ReceiveEvent::Packet(packet) = event {
        Ok(packet)
    } else {
        Err("expected authenticated packet".into())
    }
}
async fn heartbeat(client: &mut Control, server: &mut Control) -> TestResult {
    client.write_all(b"C").await?;
    client.flush().await?;
    assert_eq!(server.read_u8().await?, b'C');
    server.write_all(b"S").await?;
    server.flush().await?;
    assert_eq!(client.read_u8().await?, b'S');
    Ok(())
}

#[tokio::test]
async fn real_tls_udp_matrix_covers_protection_and_half_full_directions() -> TestResult {
    for cover in [CoverProfile::OpenVpnLike, CoverProfile::QuicLike] {
        for protection in [Protection::ChaCha20Poly1305, Protection::HmacSha256] {
            for traffic in [
                Traffic::FullDuplex,
                Traffic::HalfDuplex {
                    sender: Direction::ClientToServer,
                },
                Traffic::HalfDuplex {
                    sender: Direction::ServerToClient,
                },
            ] {
                let profile = Profile {
                    cover,
                    protection,
                    traffic,
                    ..profile()
                };
                let (a, b) = carriers(profile, Duration::from_secs(3)).await?;
                let (mut ac, mut tx_a, mut rx_a) = a.into_parts();
                let (mut bc, mut tx_b, mut rx_b) = b.into_parts();
                assert_eq!(ac.info().session_id, bc.info().session_id);
                heartbeat(&mut ac, &mut bc).await?;
                let mut output = vec![0; profile.max_payload_bytes];
                if profile.permits(Direction::ClientToServer) {
                    for number in 0..3 {
                        let payload = vec![number as u8 + 1; 173];
                        assert_eq!(tx_a.send(&payload).await?.packet.0, number);
                        let opened = delivered(rx_b.receive(&mut output).await?)?;
                        assert_eq!(opened.packet.0, number);
                        assert_eq!(&output[..opened.payload_len], payload);
                    }
                } else {
                    assert!(matches!(
                        tx_a.send(b"disabled").await,
                        Err(Error::DirectionDisabled)
                    ));
                    assert!(matches!(
                        rx_b.receive(&mut output).await,
                        Err(Error::DirectionDisabled)
                    ));
                }
                if profile.permits(Direction::ServerToClient) {
                    assert_eq!(
                        tx_b.send(b"reverse control-shaped user bytes L2MC")
                            .await?
                            .packet
                            .0,
                        0
                    );
                    let opened = delivered(rx_a.receive(&mut output).await?)?;
                    assert_eq!(
                        &output[..opened.payload_len],
                        b"reverse control-shaped user bytes L2MC"
                    );
                } else {
                    assert!(matches!(
                        tx_b.send(b"disabled").await,
                        Err(Error::DirectionDisabled)
                    ));
                    assert!(matches!(
                        rx_a.receive(&mut output).await,
                        Err(Error::DirectionDisabled)
                    ));
                }
                heartbeat(&mut ac, &mut bc).await?;
            }
        }
    }
    Ok(())
}

#[tokio::test]
async fn spoof_replay_integrity_context_and_oversize_preserve_receive_state() -> TestResult {
    for protection in [Protection::ChaCha20Poly1305, Protection::HmacSha256] {
        let profile = Profile {
            protection,
            ..profile()
        };
        let (a, b) = carriers(profile, Duration::from_secs(3)).await?;
        let (_ac, mut tx, _ar) = a.into_parts();
        let (_bc, _bt, mut rx) = b.into_parts();
        let mut output = vec![0x5a; profile.max_payload_bytes];
        let payload = vec![0xa4; profile.max_payload_bytes];
        tx.send(&payload).await?;
        let mut wire = vec![0; rx.maximum + 1];
        let (length, _) = rx.socket.recv_from(&mut wire).await?;
        wire.truncate(length);
        let foreign = UdpSocket::bind("127.0.0.1:0").await?;
        foreign.send_to(&wire, rx.local_addr()?).await?;
        assert_eq!(
            rx.receive(&mut output).await?,
            ReceiveEvent::Discarded(DiscardReason::WrongPeer)
        );
        assert_eq!(output, vec![0x5a; profile.max_payload_bytes]);
        let mut oversized = wire.clone();
        oversized.extend_from_slice(&[0; 500]);
        tx.socket.send_to(&oversized, tx.peer_addr()).await?;
        assert_eq!(
            rx.receive(&mut output).await?,
            ReceiveEvent::Discarded(DiscardReason::Oversized)
        );
        for offset in [9 + 5, 9 + 8, 9 + 24, 9 + 28, wire.len() - 1] {
            let mut bad = wire.clone();
            bad[offset] ^= 1;
            tx.socket.send_to(&bad, tx.peer_addr()).await?;
            assert!(matches!(
                rx.receive(&mut output).await?,
                ReceiveEvent::Discarded(DiscardReason::Protection(_))
            ));
            assert_eq!(rx.usage(), Usage::default());
            assert_eq!(output, vec![0x5a; profile.max_payload_bytes]);
        }
        tx.socket.send_to(&wire, tx.peer_addr()).await?;
        assert_eq!(delivered(rx.receive(&mut output).await?)?.packet.0, 0);
        assert_eq!(output, payload);
        tx.socket.send_to(&wire, tx.peer_addr()).await?;
        assert_eq!(
            rx.receive(&mut output).await?,
            ReceiveEvent::Discarded(DiscardReason::Protection(datagram::Error::Replay))
        );
        assert_eq!(rx.usage().packets, 1);
    }
    Ok(())
}

#[tokio::test]
async fn small_output_and_receive_cancellation_preserve_queued_packet() -> TestResult {
    let (a, b) = carriers(profile(), Duration::from_secs(3)).await?;
    let (_ac, mut tx, _ar) = a.into_parts();
    let (_bc, _bt, mut rx) = b.into_parts();
    let mut output = vec![0x5a; 256];
    assert!(
        timeout(Duration::from_millis(10), rx.receive(&mut output))
            .await
            .is_err()
    );
    assert_eq!(rx.usage(), Usage::default());
    tx.send(b"retry after cancelled receive").await?;
    assert!(matches!(
        rx.receive(&mut output[..1]).await,
        Err(Error::Datagram(datagram::Error::OutputTooSmall))
    ));
    let opened = delivered(rx.receive(&mut output).await?)?;
    assert_eq!(opened.packet.0, 0);
    assert_eq!(
        &output[..opened.payload_len],
        b"retry after cancelled receive"
    );
    Ok(())
}

#[tokio::test]
async fn control_drop_observed_eof_and_idle_expiry_close_udp() -> TestResult {
    let (a, b) = carriers(profile(), Duration::from_secs(3)).await?;
    let (_ac, _at, _ar) = a.into_parts();
    let (bc, _bt, mut rx) = b.into_parts();
    let task = tokio::spawn(async move { rx.receive(&mut vec![0; 256]).await });
    tokio::task::yield_now().await;
    drop(bc);
    assert!(matches!(
        timeout(Duration::from_millis(200), task).await??,
        Err(Error::ControlClosed)
    ));
    let (a, b) = carriers(profile(), Duration::from_secs(3)).await?;
    let (mut ac, mut tx, _ar) = a.into_parts();
    let (mut bc, _bt, mut rx) = b.into_parts();
    ac.shutdown().await?;
    assert!(bc.read_u8().await.is_err());
    assert!(matches!(
        tx.send(b"closed").await,
        Err(Error::ControlClosed)
    ));
    assert!(matches!(
        rx.receive(&mut vec![0; 256]).await,
        Err(Error::ControlClosed)
    ));
    let (a, _b) = carriers(profile(), Duration::from_millis(40)).await?;
    let (_ac, mut tx, _ar) = a.into_parts();
    tokio::time::sleep(Duration::from_millis(60)).await;
    assert!(matches!(
        tx.send(b"expired").await,
        Err(Error::ControlExpired)
    ));
    assert_eq!(tx.usage(), Usage::default());
    assert!(matches!(
        tx.send(b"closed permanently").await,
        Err(Error::ControlClosed)
    ));
    Ok(())
}

#[tokio::test]
async fn heartbeat_renews_lease_without_extending_receive_deadline() -> TestResult {
    let (a, b) = carriers(profile(), Duration::from_millis(100)).await?;
    let (mut ac, mut tx, _ar) = a.into_parts();
    let (mut bc, _bt, mut rx) = b.into_parts();
    let mut output = vec![0x5a; 256];
    let (received, heartbeats) = tokio::join!(rx.receive(&mut output), async {
        tokio::time::sleep(Duration::from_millis(35)).await;
        heartbeat(&mut ac, &mut bc).await?;
        tokio::time::sleep(Duration::from_millis(35)).await;
        heartbeat(&mut ac, &mut bc).await
    });
    heartbeats?;
    assert!(matches!(received, Err(Error::Timeout)));
    assert_eq!(rx.usage(), Usage::default());
    assert_eq!(output, vec![0x5a; 256]);
    tx.send(b"still live after operation timeout").await?;
    delivered(rx.receive(&mut output).await?)?;
    Ok(())
}

#[tokio::test]
async fn exact_key_budgets_and_forged_budget_overrun_are_separate() -> TestResult {
    let limited = Profile {
        max_packets_per_key: 1,
        ..profile()
    };
    let (a, b) = carriers(limited, Duration::from_secs(3)).await?;
    let (_ac, mut tx, _ar) = a.into_parts();
    let (_bc, _bt, mut rx) = b.into_parts();
    tx.send(b"one").await?;
    delivered(rx.receive(&mut vec![0; 256]).await?)?;
    assert!(matches!(
        tx.send(b"two").await,
        Err(Error::Datagram(datagram::Error::KeyUsageExhausted))
    ));
    assert!(matches!(
        rx.receive(&mut vec![0; 256]).await,
        Err(Error::Datagram(datagram::Error::KeyUsageExhausted))
    ));
    let limited = Profile {
        max_payload_bytes_per_key: 300,
        ..profile()
    };
    let (a, b) = carriers(limited, Duration::from_secs(3)).await?;
    let (_ac, mut tx, _ar) = a.into_parts();
    let (_bc, _bt, mut rx) = b.into_parts();
    tx.send(&[1; 200]).await?;
    delivered(rx.receive(&mut vec![0; 256]).await?)?;
    tx.send(&[2; 50]).await?;
    let mut wire = vec![0; 1000];
    let (length, _) = rx.socket.recv_from(&mut wire).await?;
    wire.truncate(length);
    let mut forged = wire.clone();
    forged.resize(rx.maximum, 0);
    forged[9 + 40..9 + 42].copy_from_slice(&256_u16.to_be_bytes());
    tx.socket.send_to(&forged, tx.peer_addr()).await?;
    let mut output = vec![0x5a; 256];
    assert_eq!(
        rx.receive(&mut output).await?,
        ReceiveEvent::Discarded(DiscardReason::Protection(
            datagram::Error::KeyUsageExhausted
        ))
    );
    assert_eq!(rx.usage().payload_bytes, 200);
    assert_eq!(output, vec![0x5a; 256]);
    tx.socket.send_to(&wire, tx.peer_addr()).await?;
    delivered(rx.receive(&mut output).await?)?;
    assert_eq!(rx.usage().payload_bytes, 250);
    Ok(())
}

#[tokio::test]
async fn tls_bootstrap_rejects_wrong_header_digest_and_total_timeout() -> TestResult {
    let profile = profile();
    for case in 0..4 {
        let (client, mut server) = auth_pair(profile).await?;
        let socket = UdpSocket::bind("127.0.0.1:0").await?;
        let peer = UdpSocket::bind("127.0.0.1:0").await?;
        let config = Config {
            base: base(),
            profile,
            peer: peer.local_addr()?,
            timeout: Duration::from_millis(100),
        };
        if case == 0 {
            let wrong = Config {
                profile: Profile {
                    lane: LaneId(99),
                    ..profile
                },
                ..config
            };
            assert!(matches!(
                establish(client, socket, wrong).await,
                Err(Error::Configuration(_))
            ));
        } else {
            let task = tokio::spawn(establish(client, socket, config));
            let mut offer = [0; BOOTSTRAP_BYTES];
            server.read_exact(&mut offer).await?;
            assert_eq!(&offer[..8], &[b'L', b'2', b'U', b'D', 1, 1, 0, 56]);
            if case == 1 {
                server
                    .write_all(&[b'L', b'2', b'U', b'D', 1, 2, 255, 255])
                    .await?;
                server.flush().await?;
                assert!(matches!(task.await?, Err(Error::Bootstrap)));
            } else if case == 2 {
                offer[5] = 2;
                offer[32] ^= 1;
                server.write_all(&offer).await?;
                server.flush().await?;
                assert!(matches!(task.await?, Err(Error::Bootstrap)));
            } else {
                assert!(matches!(task.await?, Err(Error::Timeout)));
            }
        }
    }
    Ok(())
}

#[test]
fn canonical_profile_binds_every_dimension_and_rejects_invalid_budgets() -> TestResult {
    let initial = profile();
    let bytes = initial.canonical()?;
    assert_eq!(bytes.len(), 40);
    assert_eq!(&bytes[..12], &[1, 1, 2, 1, 0, 0, 0, 7, 0, 0, 0, 3]);
    assert_eq!(&bytes[12..24], &[0, 0, 5, 220, 0, 0, 0, 28, 0, 0, 1, 0]);
    let digest = session_config(base(), initial)?.digest;
    for other in [
        Profile {
            traffic: Traffic::HalfDuplex {
                sender: Direction::ClientToServer,
            },
            ..initial
        },
        Profile {
            cover: CoverProfile::OpenVpnLike,
            ..initial
        },
        Profile {
            protection: Protection::HmacSha256,
            ..initial
        },
        Profile {
            lane: LaneId(8),
            ..initial
        },
        Profile {
            generation: KeyGeneration(4),
            ..initial
        },
        Profile {
            path_mtu: 1400,
            ..initial
        },
        Profile {
            outer_overhead_bytes: 48,
            ..initial
        },
        Profile {
            max_payload_bytes: 250,
            ..initial
        },
        Profile {
            max_packets_per_key: 999,
            ..initial
        },
        Profile {
            max_payload_bytes_per_key: 999_999,
            ..initial
        },
    ] {
        assert_ne!(session_config(base(), other)?.digest, digest);
    }
    assert_ne!(
        session_config(
            SessionConfig {
                layer: PacketLayer::Ip,
                ..base()
            },
            initial
        )?
        .digest,
        digest
    );
    assert_ne!(
        session_config(
            SessionConfig {
                digest: ConfigDigest([0; 32]),
                ..base()
            },
            initial
        )?
        .digest,
        digest
    );
    for bad in [
        Profile {
            path_mtu: 20,
            ..initial
        },
        Profile {
            outer_overhead_bytes: 0,
            ..initial
        },
        Profile {
            max_payload_bytes: 0,
            ..initial
        },
        Profile {
            max_payload_bytes: usize::MAX,
            ..initial
        },
        Profile {
            max_packets_per_key: 0,
            ..initial
        },
        Profile {
            max_packets_per_key: u64::MAX,
            ..initial
        },
        Profile {
            max_payload_bytes_per_key: 255,
            ..initial
        },
        Profile {
            max_payload_bytes_per_key: u64::MAX,
            ..initial
        },
    ] {
        assert!(bad.canonical().is_err());
    }
    Ok(())
}

#[tokio::test]
async fn endpoint_validation_rejects_invalid_family_and_non_unicast_addresses() -> TestResult {
    for peer in [
        "127.0.0.1:0",
        "0.0.0.0:1234",
        "224.0.0.1:1234",
        "255.255.255.255:1234",
        "[::1]:1234",
    ] {
        let (client, _server) = auth_pair(profile()).await?;
        let socket = UdpSocket::bind("127.0.0.1:0").await?;
        assert!(matches!(
            establish(
                client,
                socket,
                Config {
                    base: base(),
                    profile: profile(),
                    peer: peer.parse()?,
                    timeout: Duration::from_secs(1)
                }
            )
            .await,
            Err(Error::Configuration(_))
        ));
    }
    let (client, _server) = auth_pair(profile()).await?;
    let socket = UdpSocket::bind("0.0.0.0:0").await?;
    assert!(matches!(
        establish(
            client,
            socket,
            Config {
                base: base(),
                profile: profile(),
                peer: "127.0.0.1:1234".parse()?,
                timeout: Duration::from_secs(1)
            }
        )
        .await,
        Err(Error::Configuration(_))
    ));
    Ok(())
}

#[tokio::test]
async fn queued_late_tls_progress_cannot_revive_expired_udp_keys() -> TestResult {
    let (a, b) = carriers(profile(), Duration::from_millis(40)).await?;
    let (mut ac, _at, _ar) = a.into_parts();
    let (mut bc, mut bt, _br) = b.into_parts();
    ac.write_all(b"queued but unserviced control heartbeat")
        .await?;
    ac.flush().await?;
    tokio::time::sleep(Duration::from_millis(60)).await;
    assert_eq!(
        bc.read_u8().await.err().map(|error| error.kind()),
        Some(io::ErrorKind::TimedOut)
    );
    assert!(matches!(
        bt.send(b"must remain closed").await,
        Err(Error::ControlClosed)
    ));
    assert_eq!(bt.usage(), Usage::default());
    Ok(())
}

#[tokio::test]
async fn injected_cancelled_socket_work_does_not_rewind_real_session_nonce() -> TestResult {
    let (a, b) = carriers(profile(), Duration::from_secs(3)).await?;
    let (_ac, mut tx, _ar) = a.into_parts();
    let (_bc, _bt, mut rx) = b.into_parts();
    // Inject pending socket work after the exact production cryptographic reservation.
    let sealed = tx
        .sealer
        .as_mut()
        .ok_or("missing send key")?
        .seal_into(b"cancelled", &mut tx.buffer)?;
    assert_eq!(sealed.packet.0, 0);
    assert!(
        timeout(
            Duration::from_millis(10),
            bounded_io(
                std::future::pending::<io::Result<usize>>(),
                &tx.liveness,
                tx.duration
            )
        )
        .await
        .is_err()
    );
    assert_eq!(tx.usage().packets, 1);
    assert_eq!(tx.send(b"next actual UDP packet").await?.packet.0, 1);
    let mut output = vec![0; 256];
    assert_eq!(delivered(rx.receive(&mut output).await?)?.packet.0, 1);
    assert_eq!(tx.usage().packets, 2);
    Ok(())
}

#[tokio::test]
async fn real_udp_reordering_is_exposed_without_reliable_stream_claims() -> TestResult {
    let (a, b) = carriers(profile(), Duration::from_secs(3)).await?;
    let (_ac, mut tx, _ar) = a.into_parts();
    let (_bc, _bt, mut rx) = b.into_parts();
    let mut captured = Vec::new();
    for value in [11, 22] {
        tx.send(&[value; 50]).await?;
        let mut bytes = vec![0; rx.maximum + 1];
        let (count, _) = rx.socket.recv_from(&mut bytes).await?;
        bytes.truncate(count);
        captured.push(bytes);
    }
    let mut output = vec![0; 256];
    for index in [1, 0] {
        tx.socket.send_to(&captured[index], tx.peer_addr()).await?;
        let packet = delivered(rx.receive(&mut output).await?)?;
        assert_eq!(packet.packet.0, index as u64);
        assert_eq!(
            &output[..packet.payload_len],
            &[if index == 0 { 11 } else { 22 }; 50]
        );
    }
    assert_eq!(rx.usage().packets, 2);
    Ok(())
}
