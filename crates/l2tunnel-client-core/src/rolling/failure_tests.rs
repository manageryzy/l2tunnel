use super::*;
#[tokio::test]
async fn rolling_actual_policy_mismatch_name_and_member_fail_before_session() -> TestResult {
    let c = credentials()?;
    let stranger = credentials()?;
    let client = ClientTls::from_der_roots(&c.chain)?;
    let server = ServerTls::from_der(&c.chain, &c.key)?;
    for duplex in [Duplex::Full, Duplex::Half] {
        for case in 0..3 {
            let config = ConnectionConfig {
                handshake_timeout: Duration::from_millis(500),
                ..connection(PacketLayer::Ip, duplex)
            };
            let settings = settings()?;
            let mut other = serde_json::to_value(&settings)?;
            if case == 0 {
                other["scheduling"]["tail_millis"] = 21.into();
            }
            let other = Settings::from_json(&serde_json::to_vec(&other)?)?;
            let name = if case == 1 {
                "wrong-name.test"
            } else {
                "rolling-client.test"
            };
            let allow = if case == 2 {
                &stranger.members
            } else {
                &c.members
            };
            let (a, b) = endpoints(duplex)?;
            let listener = TcpListener::bind("127.0.0.1:0").await?;
            let (one, two) = tokio::join!(
                connect_udp(
                    listener.local_addr()?,
                    &client,
                    name,
                    &c.member,
                    config,
                    a,
                    &settings
                ),
                accept_udp(&listener, &server, allow, config, b, &other)
            );
            assert!(
                one.is_err() && two.is_err(),
                "UDP accepted mismatch case{case} {duplex:?}"
            );
            let (a, b) = endpoints(duplex)?;
            let listener = QuicListener::bind(&c.chain, &c.key, config, as_quic(b), &other)?;
            let (one, two) = tokio::join!(
                connect_quic(&c.chain, name, &c.member, config, as_quic(a), &settings),
                listener.accept(allow)
            );
            assert!(
                one.is_err() && two.is_err(),
                "QUIC accepted mismatch case{case} {duplex:?}"
            );
        }
    }
    Ok(())
}
#[tokio::test]
async fn rolling_cancelled_accept_preserves_listener_and_drop_is_not_clean_close() -> TestResult {
    let c = credentials()?;
    let client = ClientTls::from_der_roots(&c.chain)?;
    let server = ServerTls::from_der(&c.chain, &c.key)?;
    let settings = settings()?;
    for duplex in [Duplex::Full, Duplex::Half] {
        let config = connection(PacketLayer::Ip, duplex);
        let (a, b) = endpoints(duplex)?;
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        assert!(
            timeout(
                Duration::from_millis(10),
                accept_udp(&listener, &server, &c.members, config, b, &settings)
            )
            .await
            .is_err()
        );
        let (one, two) = tokio::try_join!(
            connect_udp(
                listener.local_addr()?,
                &client,
                "rolling-client.test",
                &c.member,
                config,
                a,
                &settings
            ),
            accept_udp(&listener, &server, &c.members, config, b, &settings)
        )?;
        let observed = one.observer();
        drop(one);
        assert_eq!(observed.snapshot().phase, Phase::Cancelled);
        assert!(!observed.snapshot().clean_drain);
        drop(two);
        // The listener remains an owner after setup cancellation and actual Session cancellation.
        assert!(listener.local_addr()?.port() != 0);
        let (a, b) = endpoints(duplex)?;
        let listener = QuicListener::bind(&c.chain, &c.key, config, as_quic(b), &settings)?;
        assert!(
            timeout(Duration::from_millis(10), listener.accept(&c.members))
                .await
                .is_err()
        );
        let (one, two) = tokio::try_join!(
            connect_quic(
                &c.chain,
                "rolling-client.test",
                &c.member,
                config,
                as_quic(a),
                &settings
            ),
            listener.accept(&c.members)
        )?;
        let observed = one.observer();
        let error = one
            .run(Device {
                native: Native::default(),
                layer: PacketLayer::Ethernet,
            })
            .await
            .err()
            .ok_or("wrong device accepted")?;
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        let status = observed.snapshot();
        assert_eq!(status.phase, Phase::Failed);
        assert_eq!(status.failure.as_deref(), Some("InvalidInput"));
        drop(two);
    }
    Ok(())
}
#[tokio::test]
async fn rolling_original_accept_timeout_is_not_renewed_for_half_mode() -> TestResult {
    let c = credentials()?;
    let server = ServerTls::from_der(&c.chain, &c.key)?;
    let settings = settings()?;
    for duplex in [Duplex::Full, Duplex::Half] {
        let config = ConnectionConfig {
            handshake_timeout: Duration::from_millis(30),
            ..connection(PacketLayer::Ip, duplex)
        };
        let (_, b) = endpoints(duplex)?;
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let result = timeout(
            Duration::from_millis(250),
            accept_udp(&listener, &server, &c.members, config, b, &settings),
        )
        .await?;
        assert_eq!(
            result.err().ok_or("missing timeout")?.kind(),
            io::ErrorKind::TimedOut
        );
        let listener = QuicListener::bind(&c.chain, &c.key, config, as_quic(b), &settings)?;
        let result = timeout(Duration::from_millis(250), listener.accept(&c.members)).await?;
        assert_eq!(
            result.err().ok_or("missing QUIC timeout")?.kind(),
            io::ErrorKind::TimedOut
        );
    }
    Ok(())
}

#[tokio::test]
async fn rolling_half_first_lane_auth_does_not_renew_setup_or_leak_attempt_sockets() -> TestResult {
    let c = credentials()?;
    let client = ClientTls::from_der_roots(&c.chain)?;
    let server = ServerTls::from_der(&c.chain, &c.key)?;
    let settings = settings()?;
    let config = ConnectionConfig {
        handshake_timeout: Duration::from_millis(200),
        ..connection(PacketLayer::Ip, Duplex::Half)
    };
    let (a, b) = endpoints(Duplex::Half)?;
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let (profile, records) = udp_config(config, b, &settings)?;
    let started = Instant::now();
    let mut attempt = Box::pin(connect_udp(
        listener.local_addr()?,
        &client,
        "rolling-client.test",
        &c.member,
        config,
        a,
        &settings,
    ));
    let peer = async {
        let socket = tokio::net::UdpSocket::bind(b.forward.local).await?;
        let (stream, _) = listener.accept().await?;
        stream.set_nodelay(true)?;
        sleep(Duration::from_millis(100)).await;
        let stream = l2tunnel_auth::server_accept(
            stream,
            &server,
            &c.members,
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
        let (unfinished, _) = listener.accept().await?;
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>((first, unfinished))
    };
    let retained = tokio::select! {result=&mut attempt=>return Err(format!("first lane did not complete authentication: {:?}",result.err()).into()),result=peer=>result?};
    let result = attempt.await;
    assert_eq!(
        result.err().ok_or("missing timeout")?.kind(),
        io::ErrorKind::TimedOut
    );
    assert!(started.elapsed() < Duration::from_millis(275));
    for endpoint in [a.forward.local, a.reverse.ok_or("reverse")?.local] {
        let _socket = tokio::net::UdpSocket::bind(endpoint).await?;
    }
    drop(retained);
    Ok(())
}
#[tokio::test]
async fn rolling_actual_connect_cancellation_releases_both_lane_socket_owners() -> TestResult {
    let c = credentials()?;
    let client = ClientTls::from_der_roots(&c.chain)?;
    let settings = settings()?;
    let config = connection(PacketLayer::Ip, Duplex::Half);
    for quic in [false, true] {
        let (a, _) = endpoints(Duplex::Half)?;
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let mut attempt = Box::pin(async {
            if quic {
                connect_quic(
                    &c.chain,
                    "rolling-client.test",
                    &c.member,
                    config,
                    as_quic(a),
                    &settings,
                )
                .await
            } else {
                connect_udp(
                    address,
                    &client,
                    "rolling-client.test",
                    &c.member,
                    config,
                    a,
                    &settings,
                )
                .await
            }
        });
        tokio::select! {
            result=&mut attempt=>return Err(format!("attempt finished before socket ownership witness: {}",result.is_ok()).into()),
            result=timeout(Duration::from_secs(1),async {loop {
                let one=tokio::net::UdpSocket::bind(a.forward.local).await;let two=tokio::net::UdpSocket::bind(a.reverse.ok_or("reverse")?.local).await;
                if matches!(one.as_ref(),Err(e) if e.kind()==io::ErrorKind::AddrInUse) && matches!(two.as_ref(),Err(e) if e.kind()==io::ErrorKind::AddrInUse) {return Ok::<_,Box<dyn std::error::Error+Send+Sync>>(());}
                drop((one,two));sleep(Duration::from_millis(1)).await;
            }})=>result??,
        }
        drop(attempt);
        timeout(Duration::from_secs(1), async {
            loop {
                let one = tokio::net::UdpSocket::bind(a.forward.local).await;
                let two = tokio::net::UdpSocket::bind(a.reverse.ok_or("reverse")?.local).await;
                if one.is_ok() && two.is_ok() {
                    return Ok::<_, Box<dyn std::error::Error + Send + Sync>>(());
                }
                drop((one, two));
                sleep(Duration::from_millis(1)).await;
            }
        })
        .await??;
    }
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn rolling_half_quic_first_lane_auth_keeps_original_pair_deadline() -> TestResult {
    use std::{future::Future, task::Poll};

    // Real QUIC I/O must not race a100ms CPU/scheduler allowance. Both Quinn's
    // TokioRuntime and the client use this injected clock. Keep it from idle
    // auto-advance, and bound actual socket/crypto progress independently.
    async fn wall_bound<F: Future>(
        operation: F,
        deadline: std::time::Instant,
    ) -> io::Result<F::Output> {
        tokio::pin!(operation);
        std::future::poll_fn(|cx| {
            if std::time::Instant::now() >= deadline {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "real QUIC fixture wall watchdog exhausted",
                )));
            }
            match operation.as_mut().poll(cx) {
                Poll::Ready(value) => Poll::Ready(Ok(value)),
                Poll::Pending => {
                    cx.waker().wake_by_ref();
                    Poll::Pending
                }
            }
        })
        .await
    }

    let c = credentials()?;
    let settings = settings()?;
    let config = ConnectionConfig {
        handshake_timeout: Duration::from_millis(200),
        ..connection(PacketLayer::Ip, Duplex::Half)
    };
    let (mut a, b) = endpoints(Duplex::Half)?;
    let (profile, records) = quic_config(config, as_quic(b), &settings)?;
    let base = runtime::quic_base_session_config(config.runtime(), profile, records)?;
    let tls = l2tunnel_quic::ServerConfig::from_der(
        &c.chain,
        &c.key,
        l2tunnel_runtime::quic::carrier_profile(profile, l2tunnel_runtime::quic::Lane::First)?,
        l2tunnel_quic::EndpointLimits {
            max_connections: 1,
            pending_connections: 4,
            handshake_timeout: config.handshake_timeout,
        },
    )?;
    let listener = l2tunnel_quic::ServerEndpoint::bind(b.forward.local, &tls)?;
    let reverse = b.reverse.ok_or("server reverse")?;
    // Receive the second lane's genuine Initial without answering it. This
    // witnesses completed client first-lane authentication and avoids an ICMP
    // refusal substituting for the intended incomplete second handshake.
    let blackhole = tokio::net::UdpSocket::bind(reverse.local).await?;
    let mut clock = tokio::task::JoinSet::new();
    clock.spawn(async {
        loop {
            tokio::task::yield_now().await;
        }
    });
    let wall_deadline = std::time::Instant::now() + Duration::from_secs(3);
    let started = Instant::now();
    let mut attempt = Box::pin(connect_quic(
        &c.chain,
        "rolling-client.test",
        &c.member,
        config,
        as_quic(a),
        &settings,
    ));
    // Socket reservations cannot be passed through the public factory. Retry
    // only an actual local bind collision returned by its first synchronous
    // poll, before any Pending/authentication progress. Logical time and both
    // original watchdogs are unchanged; no completed/partial session is retried.
    for retry in 0..4 {
        assert_eq!(Instant::now(), started);
        let initial = std::future::poll_fn(|cx| Poll::Ready(attempt.as_mut().poll(cx))).await;
        let early_error = match &initial {
            Poll::Ready(Err(error)) => Some(error),
            _ => None,
        };
        if retry < 3 && early_error.is_some_and(|error| udp_startup_addr_in_use(error)) {
            drop(attempt);
            let (fresh, _) = endpoints(Duplex::Half)?;
            a.forward.local = fresh.forward.local;
            a.reverse.as_mut().ok_or("client reverse")?.local =
                fresh.reverse.ok_or("fresh reverse")?.local;
            attempt = Box::pin(connect_quic(
                &c.chain,
                "rolling-client.test",
                &c.member,
                config,
                as_quic(a),
                &settings,
            ));
            continue;
        }
        assert!(
            initial.is_pending(),
            "setup ended before the first peer accept: {early_error:?}"
        );
        break;
    }
    let client_reverse = a.reverse.ok_or("client reverse")?;
    tokio::time::advance(Duration::from_millis(100)).await;
    let retained = wall_bound(
        async {
            tokio::select! {
                result=&mut attempt=>Err(io::Error::other(format!("first QUIC lane failed before original pair wait: {:?}",result.err()))),
                result=listener.accept(&c.members,base)=>result.map_err(io::Error::other),
            }
        },
        wall_deadline,
    )
    .await??;
    let mut packet = [0; 1500];
    let (length, peer) = wall_bound(
        async {
            tokio::select! {
                result=&mut attempt=>Err(io::Error::other(format!("setup ended before second Initial: {:?}",result.err()))),
                result=blackhole.recv_from(&mut packet)=>result,
            }
        },
        wall_deadline,
    )
    .await??;
    assert_eq!(peer, client_reverse.local);
    assert!(length >= 1200, "missing full QUIC Initial datagram");
    assert_eq!(packet[0] & 0xf0, 0xc0); // QUIC v1 long-header Initial.
    assert_eq!(&packet[1..5], &1u32.to_be_bytes());
    assert_eq!(started.elapsed(), Duration::from_millis(100));
    for endpoint in [a.forward.local, client_reverse.local] {
        assert_eq!(
            tokio::net::UdpSocket::bind(endpoint)
                .await
                .err()
                .map(|e| e.kind()),
            Some(io::ErrorKind::AddrInUse)
        );
    }
    tokio::time::advance(Duration::from_millis(99)).await;
    let early = std::future::poll_fn(|cx| Poll::Ready(attempt.as_mut().poll(cx))).await;
    assert!(early.is_pending(), "original setup ended before200ms");
    tokio::time::advance(Duration::from_millis(1)).await;
    let expired = std::future::poll_fn(|cx| Poll::Ready(attempt.as_mut().poll(cx))).await;
    let Poll::Ready(result) = expired else {
        return Err("original200ms setup bound was renewed after first authentication".into());
    };
    assert_eq!(
        result.err().ok_or("missing QUIC pair timeout")?.kind(),
        io::ErrorKind::TimedOut
    );
    assert_eq!(started.elapsed(), config.handshake_timeout);
    drop(attempt);
    wall_bound(
        async {
            loop {
                let one = tokio::net::UdpSocket::bind(a.forward.local).await;
                let two = tokio::net::UdpSocket::bind(client_reverse.local).await;
                if one.is_ok() && two.is_ok() {
                    return;
                }
                drop((one, two));
                tokio::task::yield_now().await;
            }
        },
        wall_deadline,
    )
    .await?;
    drop((retained, listener, blackhole, clock));
    Ok(())
}
