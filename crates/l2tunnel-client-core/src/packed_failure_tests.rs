use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::net::UdpSocket;

#[test]
fn options_and_exact_geometry_fail_before_socket_work() -> TestResult {
    let config = connection(PacketLayer::Ethernet, Duplex::Full);
    let (a, _) = endpoints(Duplex::Full)?;
    let original = settings();
    let (profile, records) = udp_config(config, a, original)?;
    let binding = runtime::udp_base_session_config(config.runtime(), profile, records)?;
    assert_ne!(
        binding,
        l2tunnel_runtime::udp::base_session_config(
            config.runtime(),
            profile,
            crate::delivery_tests::policy()
        )?
    );
    let (_, aligned) = crate::aligned::udp_config(
        config,
        a,
        crate::aligned::Settings {
            channels: 4,
            delivery: crate::delivery_tests::policy(),
        },
    )?;
    assert_ne!(
        binding,
        l2tunnel_runtime::aligned::udp_base_session_config(config.runtime(), profile, aligned)?
    );
    for index in 0..4 {
        let mut changed = original;
        match index {
            0 => changed.channels = 2,
            1 => changed.packing.hold_micros = 500,
            2 => changed.packing.max_units = 3,
            _ => changed.packing.work_limit = 8,
        }
        let (_, records) = udp_config(config, a, changed)?;
        assert_ne!(
            binding,
            runtime::udp_base_session_config(config.runtime(), profile, records)?
        );
    }
    for index in 0..9 {
        let mut bad = original;
        match index {
            0 => bad.channels = 0,
            1 => bad.channels = 256,
            2 => bad.packing.hold_micros = 0,
            3 => bad.packing.hold_micros = 1001,
            4 => bad.packing.max_units = 0,
            5 => bad.packing.max_units = 255, // Envelope cannot fit this real MTU.
            6 => bad.packing.work_limit = 0,
            7 => bad.packing.work_limit = 256,
            _ => bad.channels = u16::MAX,
        }
        assert!(udp_config(config, a, bad).is_err());
        assert!(quic_config(config, as_quic(a), bad).is_err());
    }
    assert!(
        udp_config(
            ConnectionConfig {
                compression: Compression::Lz4IfSmaller,
                ..config
            },
            a,
            original
        )
        .is_err()
    );
    assert!(
        udp_config(
            config,
            udp::Settings {
                recovery: udp::RecoveryMode::SelectiveRepeat,
                ..a
            },
            original
        )
        .is_err()
    );
    assert!(udp_config(config, udp::Settings { path_mtu: 575, ..a }, original).is_err());
    Ok(())
}

#[tokio::test]
async fn actual_udp_and_quic_reject_every_packing_policy_mismatch_and_wrong_identity() -> TestResult
{
    let unrelated = credentials()?;
    let credentials = credentials()?;
    let config = connection(PacketLayer::Ip, Duplex::Full);
    let client = ClientTls::from_der_roots(&credentials.chain)?;
    let server = ServerTls::from_der(&credentials.chain, &credentials.key)?;
    for case in 0..8 {
        let mut other = settings();
        match case {
            0 => other.channels = 2,
            1 => other.packing.hold_micros = 500,
            2 => other.packing.max_units = 3,
            3 => other.packing.work_limit = 8,
            6 => other.delivery.forward.target_bandwidth_bps += 1,
            7 => other.delivery.reverse.target_bandwidth_bps += 1,
            _ => {}
        }
        let name = if case == 4 {
            "wrong-name.test"
        } else {
            "packed-client.test"
        };
        let members = if case == 5 {
            &unrelated.members
        } else {
            &credentials.members
        };
        let (a, b) = endpoints(Duplex::Full)?;
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let (first, second) = timeout(Duration::from_secs(5), async {
            tokio::join!(
                connect_udp(
                    address,
                    &client,
                    name,
                    &credentials.member,
                    config,
                    a,
                    settings()
                ),
                accept_udp(&listener, &server, members, config, b, other),
            )
        })
        .await?;
        assert!(first.is_err(), "UDP client accepted case {case}");
        assert!(second.is_err(), "UDP server accepted case {case}");
        let (a, b) = endpoints(Duplex::Full)?;
        let listener = QuicListener::bind(
            &credentials.chain,
            &credentials.key,
            config,
            as_quic(b),
            other,
        )?;
        let (first, second) = timeout(Duration::from_secs(5), async {
            tokio::join!(
                connect_quic(
                    &credentials.chain,
                    name,
                    &credentials.member,
                    config,
                    as_quic(a),
                    settings()
                ),
                listener.accept(members),
            )
        })
        .await?;
        assert!(first.is_err(), "QUIC client accepted case {case}");
        assert!(second.is_err(), "QUIC server accepted case {case}");
    }
    Ok(())
}

#[test]
fn base_frame_delivery_is_versioned_and_aligned_v2_bindings_stay_fixed() -> TestResult {
    let config = connection(PacketLayer::Ethernet, Duplex::Full);
    let (a, _) = endpoints(Duplex::Full)?;
    let profile = udp::runtime_config(config, a)?;
    let (quic, aligned_quic) = crate::aligned::quic_config(
        config,
        as_quic(a),
        crate::aligned::Settings {
            channels: 4,
            delivery: crate::delivery_tests::policy(),
        },
    )?;
    let (_, aligned_udp) = crate::aligned::udp_config(
        config,
        a,
        crate::aligned::Settings {
            channels: 4,
            delivery: crate::delivery_tests::policy(),
        },
    )?;
    let actual = [
        l2tunnel_runtime::udp::base_session_config(
            config.runtime(),
            profile,
            crate::delivery_tests::policy(),
        )?
        .digest
        .0,
        l2tunnel_runtime::aligned::udp_base_session_config(config.runtime(), profile, aligned_udp)?
            .digest
            .0,
        l2tunnel_runtime::quic::base_session_config(
            config.runtime(),
            quic,
            crate::delivery_tests::policy(),
        )?
        .digest
        .0,
        l2tunnel_runtime::aligned::quic_base_session_config(config.runtime(), quic, aligned_quic)?
            .digest
            .0,
    ];
    // Entries0/2 independently wrap the frozen old transport digests with the
    // explicit base delivery policy (Python hashlib recipe retained in work).
    // Entries1/3 preserve the existing aligned v2 identities byte-for-byte.
    assert_eq!(
        actual,
        [
            [
                18, 166, 245, 219, 57, 242, 10, 253, 95, 137, 176, 73, 89, 106, 114, 213, 111, 165,
                104, 43, 27, 76, 36, 109, 253, 147, 177, 221, 229, 57, 229, 29
            ],
            [
                129, 73, 123, 2, 98, 145, 23, 184, 185, 239, 215, 132, 202, 116, 193, 228, 27, 98,
                237, 27, 91, 228, 207, 255, 20, 211, 174, 149, 104, 194, 18, 132
            ],
            [
                103, 105, 69, 20, 55, 135, 205, 55, 114, 193, 70, 80, 198, 173, 221, 187, 108, 221,
                85, 156, 218, 221, 97, 188, 99, 255, 221, 83, 219, 52, 155, 216
            ],
            [
                105, 252, 241, 205, 161, 123, 76, 93, 218, 18, 176, 82, 233, 196, 183, 216, 47,
                125, 240, 159, 91, 181, 129, 252, 165, 225, 255, 254, 26, 135, 101, 67
            ],
        ]
    );
    Ok(())
}

struct Counted(Arc<AtomicUsize>);
impl Drop for Counted {
    fn drop(&mut self) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}
#[tokio::test]
async fn expired_setup_never_polls_and_ready_after_expiry_drops_the_returned_owner() -> TestResult {
    let polled = AtomicUsize::new(0);
    let result = finish_before(Instant::now(), async {
        polled.fetch_add(1, Ordering::SeqCst);
        Ok(())
    })
    .await;
    assert!(matches!(result, Err(e) if e.kind() == io::ErrorKind::TimedOut));
    assert_eq!(polled.load(Ordering::SeqCst), 0);
    let drops = Arc::new(AtomicUsize::new(0));
    let end = Instant::now() + Duration::from_millis(1);
    let result = finish_before(end, async {
        let until = std::time::Instant::now() + Duration::from_millis(3);
        while std::time::Instant::now() < until {
            std::hint::spin_loop();
        }
        Ok(Counted(drops.clone()))
    })
    .await;
    assert!(matches!(result, Err(e) if e.kind() == io::ErrorKind::TimedOut));
    assert_eq!(drops.load(Ordering::SeqCst), 1);
    let end = Instant::now() + Duration::from_millis(1);
    let result = finish_before(end, async {
        let until = std::time::Instant::now() + Duration::from_millis(3);
        while std::time::Instant::now() < until {
            std::hint::spin_loop();
        }
        Err::<(), _>(io::Error::other(
            "inner failure returned after original setup deadline",
        ))
    })
    .await;
    assert!(matches!(result, Err(e) if e.kind() == io::ErrorKind::TimedOut));
    Ok(())
}

async fn tuples_available(settings: udp::Settings, stage: &str) -> io::Result<()> {
    // This existing cleanup observation bound never extends setup. Last-owner
    // abandonment now owns driver teardown rather than waiting for Quinn's
    // variable 3-PTO drain. Keep the same five-second allowance as the failed
    // aggregate; a rerun or wider observer is not an ownership fix.
    let started = Instant::now();
    timeout(Duration::from_secs(5), async {
        loop {
            let first = UdpSocket::bind(settings.forward.local).await;
            let second = match settings.reverse {
                Some(value) => Some(UdpSocket::bind(value.local).await),
                None => None,
            };
            if first.is_ok() && second.as_ref().is_none_or(Result::is_ok) {
                eprintln!(
                    "{stage}: exact UDP tuples released after {:?}",
                    started.elapsed()
                );
                return Ok::<_, io::Error>(());
            }
            drop((first, second));
            sleep(Duration::from_millis(2)).await;
        }
    })
    .await
    .map_err(|error| {
        io::Error::other(format!(
            "{stage}: attempt sockets still bound at {:?}/{:?}: {error}",
            settings.forward.local,
            settings.reverse.map(|v| v.local)
        ))
    })?
}

#[tokio::test]
async fn factory_expiry_releases_attempt_sockets_but_accept_preserves_listener_owners() -> TestResult
{
    let credentials = credentials()?;
    let client = ClientTls::from_der_roots(&credentials.chain)?;
    let server = ServerTls::from_der(&credentials.chain, &credentials.key)?;
    let mut config = connection(PacketLayer::Ip, Duplex::Half);
    config.handshake_timeout = Duration::from_millis(100);
    let (a, b) = endpoints(Duplex::Half)?;
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let result = connect_udp(
        listener.local_addr()?,
        &client,
        "packed-client.test",
        &credentials.member,
        config,
        a,
        settings(),
    )
    .await;
    assert!(matches!(result, Err(e) if e.kind() == io::ErrorKind::TimedOut));
    tuples_available(a, "UDP connect expiry").await?;
    // Consume the abandoned TCP attempt, then the next accept has no new peer.
    drop(listener.accept().await?);
    let result = accept_udp(
        &listener,
        &server,
        &credentials.members,
        config,
        b,
        settings(),
    )
    .await;
    assert!(matches!(result, Err(e) if e.kind() == io::ErrorKind::TimedOut));
    tuples_available(b, "UDP accept expiry").await?;
    let probe = tokio::net::TcpStream::connect(listener.local_addr()?).await?;
    drop(listener.accept().await?);
    drop(probe);
    let (a, b) = endpoints(Duplex::Half)?;
    let result = connect_quic(
        &credentials.chain,
        "packed-client.test",
        &credentials.member,
        config,
        as_quic(a),
        settings(),
    )
    .await;
    assert!(matches!(result, Err(e) if e.kind() == io::ErrorKind::TimedOut));
    tuples_available(a, "QUIC connect expiry").await?;
    let listener = QuicListener::bind(
        &credentials.chain,
        &credentials.key,
        config,
        as_quic(b),
        settings(),
    )?;
    assert!(listener.accept(&credentials.members).await.is_err());
    assert!(UdpSocket::bind(b.forward.local).await.is_err());
    assert!(
        UdpSocket::bind(b.reverse.ok_or("missing reverse")?.local)
            .await
            .is_err()
    );
    drop(listener);
    tuples_available(b, "QUIC listener drop").await?;
    Ok(())
}

#[tokio::test]
async fn caller_cancellation_releases_the_original_attempt_sockets() -> TestResult {
    let credentials = credentials()?;
    let client = ClientTls::from_der_roots(&credentials.chain)?;
    let config = connection(PacketLayer::Ip, Duplex::Half);
    for genuine_quic in [false, true] {
        let (a, _) = endpoints(Duplex::Half)?;
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let mut attempt = Box::pin(async {
            if genuine_quic {
                connect_quic(
                    &credentials.chain,
                    "packed-client.test",
                    &credentials.member,
                    config,
                    as_quic(a),
                    settings(),
                )
                .await
                .map(|_| ())
            } else {
                connect_udp(
                    address,
                    &client,
                    "packed-client.test",
                    &credentials.member,
                    config,
                    a,
                    settings(),
                )
                .await
                .map(|_| ())
            }
        });
        // Wait for both exact physical bindings, not an assumed scheduling delay.
        tokio::select! {
            result = &mut attempt => return Err(format!("attempt completed before cancellation: {result:?}").into()),
            result = timeout(Duration::from_secs(1), async {
                loop {
                    let first = UdpSocket::bind(a.forward.local).await;
                    let second = UdpSocket::bind(a.reverse.ok_or("missing reverse")?.local).await;
                    if matches!(first.as_ref(), Err(e) if e.kind()==io::ErrorKind::AddrInUse)
                        && matches!(second.as_ref(), Err(e) if e.kind()==io::ErrorKind::AddrInUse) {
                        return Ok::<_, TestError>(());
                    }
                    drop((first, second));
                    sleep(Duration::from_millis(2)).await;
                }
            }) => result??,
        }
        drop(attempt);
        tuples_available(
            a,
            if genuine_quic {
                "QUIC caller cancellation"
            } else {
                "UDP caller cancellation"
            },
        )
        .await?;
    }
    Ok(())
}

#[tokio::test]
async fn missing_second_udp_lane_drops_the_authenticated_first_lane_at_original_deadline()
-> TestResult {
    let credentials = credentials()?;
    let client = ClientTls::from_der_roots(&credentials.chain)?;
    let server = ServerTls::from_der(&credentials.chain, &credentials.key)?;
    let config = ConnectionConfig {
        handshake_timeout: Duration::from_millis(500),
        ..connection(PacketLayer::Ip, Duplex::Half)
    };
    let (a, b) = endpoints(Duplex::Half)?;
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let mut attempt = Box::pin(connect_udp(
        listener.local_addr()?,
        &client,
        "packed-client.test",
        &credentials.member,
        config,
        a,
        settings(),
    ));
    let (profile, records) = udp_config(config, b, settings())?;
    let first_and_incomplete_second = async {
        let socket = UdpSocket::bind(b.forward.local).await?;
        let (stream, _) = listener.accept().await?;
        let stream = l2tunnel_auth::server_accept(
            stream,
            &server,
            &credentials.members,
            runtime::udp_session_config(
                config.runtime(),
                profile,
                records,
                l2tunnel_runtime::udp::Lane::First,
            )?,
            config.handshake_timeout,
        )
        .await?;
        let first = l2tunnel_udp::establish(
            stream,
            socket,
            runtime::udp_carrier_config(
                config.runtime(),
                profile,
                records,
                l2tunnel_runtime::udp::Lane::First,
                b.forward.peer,
            )?,
        )
        .await?;
        // The first lane really authenticated. Accept TCP for the second lane,
        // but never complete its TLS/member handshake or produce a pair proof.
        let (incomplete, _) = listener.accept().await?;
        Ok::<_, TestError>((first, incomplete))
    };
    let peer = tokio::select! {
        result = &mut attempt => return Err(format!("first lane did not establish: {}", result.is_ok()).into()),
        result = first_and_incomplete_second => result?,
    };
    assert!(UdpSocket::bind(a.forward.local).await.is_err());
    assert!(
        UdpSocket::bind(a.reverse.ok_or("missing reverse")?.local)
            .await
            .is_err()
    );
    let result = attempt.await;
    assert!(matches!(result, Err(e) if e.kind() == io::ErrorKind::TimedOut));
    tuples_available(a, "UDP missing second lane").await?;
    drop(peer);
    Ok(())
}

#[tokio::test]
async fn missing_second_quic_lane_drops_the_authenticated_first_lane_at_original_deadline()
-> TestResult {
    let credentials = credentials()?;
    let config = ConnectionConfig {
        handshake_timeout: Duration::from_millis(500),
        ..connection(PacketLayer::Ip, Duplex::Half)
    };
    let (a, b) = endpoints(Duplex::Half)?;
    let (profile, records) = quic_config(config, as_quic(b), settings())?;
    let tls = l2tunnel_quic::ServerConfig::from_der(
        &credentials.chain,
        &credentials.key,
        l2tunnel_runtime::quic::carrier_profile(profile, l2tunnel_runtime::quic::Lane::First)?,
        l2tunnel_quic::EndpointLimits {
            max_connections: 1,
            pending_connections: 4,
            handshake_timeout: config.handshake_timeout,
        },
    )?;
    // Only the actual first server endpoint exists; the reverse peer never binds.
    let listener = l2tunnel_quic::ServerEndpoint::bind(b.forward.local, &tls)?;
    let mut attempt = Box::pin(connect_quic(
        &credentials.chain,
        "packed-client.test",
        &credentials.member,
        config,
        as_quic(a),
        settings(),
    ));
    let first = tokio::select! {
        result = &mut attempt => return Err(format!("first QUIC lane did not establish: {}", result.is_ok()).into()),
        result = listener.accept(&credentials.members, runtime::quic_base_session_config(config.runtime(), profile, records)?) => result?,
    };
    assert!(UdpSocket::bind(a.forward.local).await.is_err());
    assert!(
        UdpSocket::bind(a.reverse.ok_or("missing reverse")?.local)
            .await
            .is_err()
    );
    let result = attempt.await;
    assert!(matches!(result, Err(e) if e.kind() == io::ErrorKind::TimedOut));
    tuples_available(a, "QUIC missing second lane").await?;
    drop((first, listener));
    Ok(())
}
