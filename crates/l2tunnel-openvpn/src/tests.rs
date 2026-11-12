use super::*;
use l2tunnel_auth::{ClientTls, MemberAllowlist, MemberKey, ServerTls, SessionConfig};
use l2tunnel_core::ConfigDigest;
use l2tunnel_device::PacketLayer;
use l2tunnel_udp_control::{Path, Secret};
use std::time::Duration;
use tokio::{
    net::UdpSocket,
    time::{sleep, timeout},
};
type TestError = Box<dyn std::error::Error + Send + Sync>;
type TestResult = Result<(), TestError>;

async fn pair(
    protection: Protection,
    change: impl FnOnce(&mut Config),
) -> Result<(Carrier, Carrier, Config), TestError> {
    let a = UdpSocket::bind("127.0.0.1:0").await?;
    let b = UdpSocket::bind("127.0.0.1:0").await?;
    let mut config = Config::new(
        Path {
            client: a.local_addr()?,
            server: b.local_addr()?,
        },
        SessionConfig {
            layer: PacketLayer::Ip,
            digest: ConfigDigest([7; 32]),
        },
        protection,
    )?;
    change(&mut config);
    let cert = rcgen::generate_simple_self_signed(vec!["standalone.test".to_owned()])?;
    let chain = vec![cert.cert.der().to_vec()];
    let client_tls = ClientTls::from_der_roots(&chain)?;
    let server_tls = ServerTls::from_der(&chain, &cert.signing_key.serialize_der())?;
    let member = MemberKey::from_pkcs8(&MemberKey::generate_pkcs8()?)?;
    let members = MemberAllowlist::new(&[member.public_key()])?;
    let (a, b) = timeout(Duration::from_secs(5), async {
        tokio::join!(
            client_connect(
                a,
                config,
                ClientCredentials {
                    tls: &client_tls,
                    server_name: "standalone.test",
                    member: &member,
                    admission: Secret::new([9; 32])
                }
            ),
            server_accept(
                b,
                config,
                ServerCredentials {
                    tls: &server_tls,
                    members: &members,
                    admission: Secret::new([9; 32]),
                    cookie: Secret::new([8; 32])
                }
            ),
        )
    })
    .await?;
    Ok((a?, b?, config))
}

#[tokio::test]
async fn full_runtime_uses_real_tls_and_exact_bidirectional_packets_then_drains_close() -> TestResult
{
    for protection in [Protection::ChaCha20Poly1305, Protection::HmacSha256] {
        let (a, b, config) = pair(protection, |_| {}).await?;
        assert_eq!(a.info().session_id, b.info().session_id);
        let (ac, at, mut ar) = a.split();
        let (bc, bt, mut br) = b.split();
        assert!(matches!(
            at.send(&vec![0; config.arq.max_source_bytes + 1]).await,
            Err(Error::PacketTooLarge)
        ));
        assert!(matches!(at.send(&[]).await, Err(Error::PacketTooLarge)));
        assert_eq!(ac.status()?.admitted_packets, 0);
        let (forward, reverse) = (vec![0xa7; 900], vec![0x3d; 777]);
        at.send(&forward).await?;
        bt.send(&reverse).await?;
        let mut buffer = vec![0; 2000];
        assert_eq!(
            timeout(Duration::from_secs(2), br.receive(&mut buffer)).await??,
            forward.len()
        );
        assert_eq!(&buffer[..forward.len()], &forward);
        assert_eq!(
            timeout(Duration::from_secs(2), ar.receive(&mut buffer)).await??,
            reverse.len()
        );
        assert_eq!(&buffer[..reverse.len()], &reverse);
        let (a, b) = tokio::join!(ac.close(), bc.close());
        assert_eq!(a?.status.terminal, Some(Terminal::Clean));
        assert_eq!(b?.status.terminal, Some(Terminal::Clean));
    }
    Ok(())
}

#[tokio::test]
async fn held_small_output_preserves_packet_slot_and_close_reports_incomplete() -> TestResult {
    let (a, b, _) = pair(Protection::ChaCha20Poly1305, |cfg| {
        cfg.close_timeout = Duration::from_millis(150);
        cfg.packet_slots = 1;
    })
    .await?;
    let (ac, at, _ar) = a.split();
    let (bc, _bt, mut br) = b.split();
    at.send(b"exact retained bytes").await?;
    assert!(matches!(
        timeout(Duration::from_secs(1), br.receive(&mut [0; 1])).await?,
        Err(Error::OutputTooSmall)
    ));
    let (a, b) = tokio::join!(ac.close(), bc.close());
    assert!(
        matches!(a, Err(Error::IncompleteClose)),
        "client close: {a:?}"
    );
    assert!(
        matches!(b, Err(Error::IncompleteClose)),
        "server close: {b:?}"
    );
    Ok(())
}

#[tokio::test]
async fn authenticated_lease_outlives_bootstrap_while_actual_tls_heartbeats_progress() -> TestResult
{
    let (a, b, cfg) = pair(Protection::ChaCha20Poly1305, |cfg| {
        cfg.bootstrap.handshake_timeout = Duration::from_millis(500);
        cfg.bootstrap.cookie_ttl = Duration::from_millis(100);
        cfg.bootstrap.initial_rto = Duration::from_millis(10);
        cfg.bootstrap.maximum_rto = Duration::from_millis(50);
        cfg.authentication_timeout = Duration::from_millis(400);
        cfg.bootstrap.arq.initial_rto = Duration::from_millis(20);
        cfg.bootstrap.arq.maximum_rto = Duration::from_millis(100);
        cfg.authenticated_lease = Duration::from_secs(2);
        cfg.inactivity_timeout = Duration::from_millis(300);
        cfg.heartbeat_interval = Duration::from_millis(30);
    })
    .await?;
    let (ac, at, _ar) = a.split();
    let (bc, _bt, mut br) = b.split();
    sleep(cfg.bootstrap.handshake_timeout + Duration::from_millis(100)).await;
    at.send(b"after bootstrap expiry").await?;
    let mut bytes = [0; 64];
    let n = timeout(Duration::from_secs(1), br.receive(&mut bytes)).await??;
    assert_eq!(&bytes[..n], b"after bootstrap expiry");
    assert!(ac.status()?.tls_messages > 2 && bc.status()?.tls_messages > 2);
    let (a, b) = tokio::join!(ac.close(), bc.close());
    a?;
    b?;
    Ok(())
}

#[tokio::test]
async fn half_lane_allows_reverse_feedback_but_rejects_reverse_user_packets() -> TestResult {
    let (a, b, _) = pair(Protection::HmacSha256, |cfg| {
        cfg.profile.traffic = Traffic::HalfDuplex {
            sender: l2tunnel_datagram::Direction::ClientToServer,
        };
    })
    .await?;
    let (ac, at, _ar) = a.split();
    let (bc, bt, mut br) = b.split();
    assert!(matches!(
        bt.send(b"forbidden reverse user bytes").await,
        Err(Error::DirectionDisabled)
    ));
    for index in 0..80_u8 {
        let packet = vec![index; 700];
        at.send(&packet).await?;
        let mut output = vec![0; 1000];
        let n = timeout(Duration::from_secs(1), br.receive(&mut output)).await??;
        assert_eq!(&output[..n], &packet);
    }
    let (a, b) = tokio::join!(ac.close(), bc.close());
    a?;
    b?;
    Ok(())
}

#[tokio::test]
async fn blocked_application_keeps_reverse_and_tls_control_progress_with_small_common_budget()
-> TestResult {
    let (a, b, _) = pair(Protection::ChaCha20Poly1305, |cfg| {
        cfg.packet_slots = 1;
        cfg.arq.send_records = 4;
        cfg.arq.receive_records = 4;
        cfg.arq.send_bytes = cfg.arq.max_source_bytes * 4;
        cfg.arq.receive_bytes = cfg.arq.max_source_bytes * 4;
        cfg.arq.ack_delay = Duration::ZERO;
        cfg.heartbeat_interval = Duration::from_millis(20);
        cfg.inactivity_timeout = Duration::from_millis(300);
        cfg.wire_budget.packets = 4;
        cfg.wire_budget.ip_bytes = 4 * cfg.bootstrap.path_mtu;
        cfg.wire_budget.reserved_control_packets = 2;
        cfg.wire_budget.reserved_control_bytes = 2 * cfg.bootstrap.path_mtu;
        cfg.wire_budget.maximum_control_packets = 3;
    })
    .await?;
    let (ac, at, mut ar) = a.split();
    let (bc, bt, mut br) = b.split();
    let producer = tokio::spawn(async move {
        for n in 0..20_u8 {
            at.send(&vec![n; 900]).await?;
        }
        Ok::<_, Error>(())
    });
    sleep(Duration::from_millis(100)).await;
    assert!(!producer.is_finished());
    bt.send(b"reverse progresses while consumer is blocked")
        .await?;
    let mut buffer = [0; 1200];
    let n = timeout(Duration::from_secs(1), ar.receive(&mut buffer)).await??;
    assert_eq!(
        &buffer[..n],
        b"reverse progresses while consumer is blocked"
    );
    assert!(ac.status()?.tls_messages > 0 && bc.status()?.tls_messages > 0);
    for n in 0..20_u8 {
        let count = timeout(Duration::from_secs(2), br.receive(&mut buffer)).await??;
        assert_eq!(&buffer[..count], vec![n; 900]);
    }
    producer.await??;
    let (a, b) = tokio::join!(ac.close(), bc.close());
    a?;
    b?;
    Ok(())
}

#[tokio::test]
async fn actual_absolute_lease_expires_even_with_fresh_tls_heartbeats() -> TestResult {
    let (a, b, _) = pair(Protection::ChaCha20Poly1305, |cfg| {
        cfg.authenticated_lease = Duration::from_millis(250);
        cfg.inactivity_timeout = Duration::from_millis(150);
        cfg.heartbeat_interval = Duration::from_millis(20);
    })
    .await?;
    let (ac, at, _ar) = a.split();
    let (bc, _bt, _br) = b.split();
    sleep(Duration::from_millis(350)).await;
    assert_eq!(ac.status()?.terminal, Some(Terminal::Timeout));
    assert_eq!(bc.status()?.terminal, Some(Terminal::Timeout));
    assert!(ac.status()?.tls_messages > 2);
    assert!(matches!(at.send(b"expired").await, Err(Error::Timeout)));
    Ok(())
}

#[tokio::test]
async fn small_output_retry_delivers_same_packet_and_owner_drop_revokes_handles() -> TestResult {
    let (a, b, _) = pair(Protection::HmacSha256, |_| {}).await?;
    let (ac, at, _ar) = a.split();
    let (_bc, _bt, mut br) = b.split();
    at.send(b"held exact packet").await?;
    assert!(matches!(
        br.receive(&mut [0; 1]).await,
        Err(Error::OutputTooSmall)
    ));
    let mut bytes = [0; 32];
    let n = br.receive(&mut bytes).await?;
    assert_eq!(&bytes[..n], b"held exact packet");
    drop(ac);
    assert!(matches!(
        at.send(b"after owner drop").await,
        Err(Error::Closed)
    ));
    Ok(())
}

#[tokio::test]
async fn actual_runtime_recovers_independent_packets_under_bounded_path_impairments() -> TestResult
{
    let (a, b, _) = pair(Protection::ChaCha20Poly1305, |cfg| {
        assert!(
            crate::test_wire::install(cfg.bootstrap.path.client, crate::test_wire::Mode::Impaired)
                .is_ok()
        );
        assert!(
            crate::test_wire::install(cfg.bootstrap.path.server, crate::test_wire::Mode::Impaired)
                .is_ok()
        );
        cfg.inactivity_timeout = Duration::from_secs(5);
        cfg.heartbeat_interval = Duration::from_millis(200);
    })
    .await?;
    let (ac, at, mut ar) = a.split();
    let (bc, bt, mut br) = b.split();
    timeout(Duration::from_secs(10), async {
        tokio::try_join!(
            async {
                for n in 0..64_u8 {
                    at.send(&vec![n; 900]).await?;
                }
                Ok::<_, Error>(())
            },
            async {
                for n in 0..48_u8 {
                    bt.send(&vec![n ^ 0x75; 700]).await?;
                }
                Ok::<_, Error>(())
            },
            async {
                let mut bytes = [0; 1200];
                for n in 0..64_u8 {
                    let size = br.receive(&mut bytes).await?;
                    assert_eq!(&bytes[..size], vec![n; 900]);
                }
                Ok::<_, Error>(())
            },
            async {
                let mut bytes = [0; 1200];
                for n in 0..48_u8 {
                    let size = ar.receive(&mut bytes).await?;
                    assert_eq!(&bytes[..size], vec![n ^ 0x75; 700]);
                }
                Ok::<_, Error>(())
            },
        )
    })
    .await??;
    assert!(ac.status()?.discarded_datagrams > 0 && bc.status()?.discarded_datagrams > 0);
    let (a, b) = tokio::join!(ac.close(), bc.close());
    a?;
    b?;
    Ok(())
}

#[tokio::test]
async fn valid_data_and_replayed_outer_control_do_not_renew_tls_inactivity() -> TestResult {
    let (a, b, _) = pair(Protection::HmacSha256, |cfg| {
        let mode = crate::test_wire::Mode::ReplayTlsAfter(Duration::from_millis(150));
        assert!(crate::test_wire::install(cfg.bootstrap.path.client, mode).is_ok());
        assert!(crate::test_wire::install(cfg.bootstrap.path.server, mode).is_ok());
        cfg.inactivity_timeout = Duration::from_millis(300);
        cfg.heartbeat_interval = Duration::from_millis(30);
    })
    .await?;
    let (ac, at, _ar) = a.split();
    let (bc, _bt, mut br) = b.split();
    sleep(Duration::from_millis(200)).await;
    let before = bc.status()?;
    for n in 0..8_u8 {
        at.send(&[n; 32]).await?;
        let mut bytes = [0; 32];
        assert_eq!(
            timeout(Duration::from_millis(100), br.receive(&mut bytes)).await??,
            32
        );
        sleep(Duration::from_millis(10)).await;
    }
    let after = bc.status()?;
    assert_eq!(after.tls_messages, before.tls_messages);
    assert!(after.delivered_packets > before.delivered_packets);
    sleep(Duration::from_millis(300)).await;
    assert_eq!(ac.status()?.terminal, Some(Terminal::Timeout));
    assert_eq!(bc.status()?.terminal, Some(Terminal::Timeout));
    assert!(ac.status()?.discarded_datagrams > 0 && bc.status()?.discarded_datagrams > 0);
    Ok(())
}

#[tokio::test]
async fn real_runtime_rejects_admission_certificate_and_member_failures() -> TestResult {
    for failure in 0..3 {
        let a = UdpSocket::bind("127.0.0.1:0").await?;
        let b = UdpSocket::bind("127.0.0.1:0").await?;
        let local = [a.local_addr()?, b.local_addr()?];
        let mut config = Config::new(
            Path {
                client: local[0],
                server: local[1],
            },
            SessionConfig {
                layer: PacketLayer::Ip,
                digest: ConfigDigest([3; 32]),
            },
            Protection::ChaCha20Poly1305,
        )?;
        config.bootstrap.cookie_ttl = Duration::from_millis(100);
        config.bootstrap.handshake_timeout = Duration::from_millis(500);
        config.authentication_timeout = Duration::from_millis(400);
        config.bootstrap.initial_rto = Duration::from_millis(10);
        config.bootstrap.maximum_rto = Duration::from_millis(50);
        let cert = rcgen::generate_simple_self_signed(vec!["negative.test".to_owned()])?;
        let chain = vec![cert.cert.der().to_vec()];
        let client_tls = ClientTls::from_der_roots(&chain)?;
        let server_tls = ServerTls::from_der(&chain, &cert.signing_key.serialize_der())?;
        let member = MemberKey::from_pkcs8(&MemberKey::generate_pkcs8()?)?;
        let other = MemberKey::from_pkcs8(&MemberKey::generate_pkcs8()?)?;
        let members = MemberAllowlist::new(&[if failure == 2 {
            other.public_key()
        } else {
            member.public_key()
        }])?;
        let (client, server) = timeout(Duration::from_secs(2), async {
            tokio::join!(
                client_connect(
                    a,
                    config,
                    ClientCredentials {
                        tls: &client_tls,
                        server_name: if failure == 1 {
                            "wrong.test"
                        } else {
                            "negative.test"
                        },
                        member: &member,
                        admission: Secret::new([if failure == 0 { 8 } else { 9 }; 32])
                    }
                ),
                server_accept(
                    b,
                    config,
                    ServerCredentials {
                        tls: &server_tls,
                        members: &members,
                        admission: Secret::new([9; 32]),
                        cookie: Secret::new([7; 32])
                    }
                ),
            )
        })
        .await?;
        assert!(client.is_err() && server.is_err());
        // Failed factories own their spawned driver aborts, rather than leaving the tuple open.
        tokio::task::yield_now().await;
        let _released_client = UdpSocket::bind(local[0]).await?;
        let _released_server = UdpSocket::bind(local[1]).await?;
    }
    Ok(())
}

#[tokio::test]
async fn cancelling_after_cookie_admission_releases_the_single_socket_owner() -> TestResult {
    let a = UdpSocket::bind("127.0.0.1:0").await?;
    let b = UdpSocket::bind("127.0.0.1:0").await?;
    let local = a.local_addr()?;
    let config = Config::new(
        Path {
            client: local,
            server: b.local_addr()?,
        },
        SessionConfig {
            layer: PacketLayer::Ip,
            digest: ConfigDigest([2; 32]),
        },
        Protection::ChaCha20Poly1305,
    )?;
    let cert = rcgen::generate_simple_self_signed(vec!["cancel.test".to_owned()])?;
    let client_tls = ClientTls::from_der_roots(&[cert.cert.der().to_vec()])?;
    let member = MemberKey::from_pkcs8(&MemberKey::generate_pkcs8()?)?;
    let (cancelled, gate) = tokio::join!(
        timeout(
            Duration::from_millis(100),
            client_connect(
                a,
                config,
                ClientCredentials {
                    tls: &client_tls,
                    server_name: "cancel.test",
                    member: &member,
                    admission: Secret::new([9; 32])
                }
            )
        ),
        async {
            let start = tokio::time::Instant::now();
            let mut gate = l2tunnel_udp_control::ServerGate::new(
                config.gate_config()?,
                Secret::new([9; 32]),
                Secret::new([8; 32]),
                Duration::ZERO,
            )?;
            let mut bytes = [0; 1500];
            loop {
                let (length, peer) =
                    timeout(Duration::from_secs(1), b.recv_from(&mut bytes)).await??;
                match gate.receive(peer, &bytes[..length], [3; 16], start.elapsed())? {
                    l2tunnel_udp_control::GateEvent::Retry(reply) => {
                        b.send_to(&reply, peer).await?;
                    }
                    l2tunnel_udp_control::GateEvent::Accepted(_) => return Ok::<_, TestError>(()),
                    _ => {}
                }
            }
        }
    );
    assert!(cancelled.is_err());
    gate?;
    tokio::task::yield_now().await;
    let _released = UdpSocket::bind(local).await?;
    Ok(())
}

#[tokio::test]
async fn key_exhaustion_revokes_packet_handles_without_implicit_rekey() -> TestResult {
    let (a, b, _) = pair(Protection::ChaCha20Poly1305, |cfg| {
        cfg.profile.max_packets_per_key = 1
    })
    .await?;
    let (ac, at, _ar) = a.split();
    let (bc, _bt, _br) = b.split();
    let admission = at.send(b"one finite key use").await;
    assert!(matches!(admission, Ok(()) | Err(Error::Closed)));
    timeout(Duration::from_secs(1), async {
        while ac.status()?.terminal.is_none() {
            sleep(Duration::from_millis(5)).await;
        }
        Ok::<_, Error>(())
    })
    .await??;
    assert_eq!(ac.status()?.terminal, Some(Terminal::Failed));
    assert_eq!(ac.status()?.admitted_packets, 1);
    assert!(matches!(
        at.send(b"no silent key reset").await,
        Err(Error::Closed)
    ));
    drop((ac, bc));
    Ok(())
}

#[tokio::test]
async fn asymmetric_final_ack_loss_and_repeated_final_retries_keep_original_control_alive()
-> TestResult {
    for losses in [1, 3] {
        let (a, b, cfg) = pair(Protection::ChaCha20Poly1305, |cfg| {
            cfg.bootstrap.arq.initial_rto = Duration::from_millis(20);
            cfg.bootstrap.arq.maximum_rto = Duration::from_millis(80);
            cfg.bootstrap.arq.ack_delay = Duration::from_millis(8);
            assert!(
                test_wire::install(
                    cfg.bootstrap.path.server,
                    test_wire::Mode::DropCloseAcks(losses)
                )
                .is_ok()
            );
        })
        .await?;
        let (ac, at, _ar) = a.split();
        let (bc, _bt, mut br) = b.split();
        at.send(b"drained before final TLS close").await?;
        assert_eq!(br.receive(&mut [0; 128]).await?, 30);
        let (a, b) = tokio::try_join!(ac.close(), bc.close())?;
        assert_eq!(a.status.terminal, Some(Terminal::Clean));
        assert_eq!(b.status.terminal, Some(Terminal::Clean));
        assert_eq!(test_wire::dropped(cfg.bootstrap.path.server)?, losses);
    }
    Ok(())
}

#[tokio::test]
async fn endless_final_ack_loss_cannot_extend_absolute_close_deadline() -> TestResult {
    for default_profile in [false, true] {
        let (a, b, cfg) = pair(Protection::ChaCha20Poly1305, |cfg| {
            if !default_profile {
                cfg.bootstrap.arq.initial_rto = Duration::from_millis(10);
                cfg.bootstrap.arq.maximum_rto = Duration::from_millis(30);
                cfg.bootstrap.arq.ack_delay = Duration::from_millis(8);
                cfg.bootstrap.arq.max_retries = 100;
                cfg.close_timeout = Duration::from_millis(160);
            }
            assert!(
                test_wire::install(
                    cfg.bootstrap.path.server,
                    test_wire::Mode::DropCloseAcks(usize::MAX)
                )
                .is_ok()
            );
        })
        .await?;
        let (ac, _at, _ar) = a.split();
        let (bc, _bt, _br) = b.split();
        let started = tokio::time::Instant::now();
        let (a, b) = tokio::join!(ac.close(), bc.close());
        assert!(matches!(a, Err(Error::IncompleteClose)));
        assert!(matches!(b, Err(Error::IncompleteClose)));
        assert!(started.elapsed() >= cfg.close_timeout);
        assert!(started.elapsed() < Duration::from_secs(if default_profile { 6 } else { 1 }));
        assert!(test_wire::dropped(cfg.bootstrap.path.server)? > 1);
    }
    Ok(())
}
