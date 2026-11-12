//! Real client entry points, canonical bindings and nonblocking native endpoints.
include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/test_udp_bind.rs"));
use super::*;
use l2tunnel_core::Duplex;
use l2tunnel_device::{PacketDevice, PacketLayer};
use std::{
    collections::VecDeque,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::{
    task::JoinSet,
    time::{sleep, timeout},
};
type TestError = Box<dyn std::error::Error + Send + Sync>;
type TestResult = Result<(), TestError>;
fn connection(layer: PacketLayer, duplex: Duplex) -> ConnectionConfig {
    ConnectionConfig {
        layer,
        duplex,
        max_packet: 1600,
        compression: Compression::None,
        handshake_timeout: Duration::from_secs(3),
    }
}
fn recovery() -> udp::RecoveryMode {
    udp::RecoveryMode::Cauchy {
        sources: 4,
        repairs: 2,
        flush_after: Duration::from_millis(5),
    }
}
fn reverse(value: udp::Endpoints) -> udp::Endpoints {
    udp::Endpoints {
        local: value.peer,
        peer: value.local,
    }
}
fn endpoints(duplex: Duplex) -> io::Result<(udp::Settings, udp::Settings)> {
    // Keep every reservation alive while choosing ports; only then hand them to the clients.
    let sockets = (0..4)
        .map(|_| crate::test_ports::reserve(false))
        .collect::<io::Result<Vec<_>>>()?;
    let first = udp::Endpoints {
        local: sockets[0].local_addr()?,
        peer: sockets[1].local_addr()?,
    };
    let second = (duplex == Duplex::Half)
        .then(|| {
            Ok::<_, io::Error>(udp::Endpoints {
                local: sockets[2].local_addr()?,
                peer: sockets[3].local_addr()?,
            })
        })
        .transpose()?;
    let a = udp::Settings {
        forward: first,
        reverse: second,
        cover: udp::CoverProfile::QuicLike,
        protection: udp::Protection::ChaCha20Poly1305,
        path_mtu: 1500,
        recovery: recovery(),
    };
    Ok((
        a,
        udp::Settings {
            forward: reverse(first),
            reverse: second.map(reverse),
            ..a
        },
    ))
}
fn as_quic(value: udp::Settings) -> quic::Settings {
    quic::Settings {
        forward: value.forward,
        reverse: value.reverse,
        application_id: *b"client-align-001",
        path_mtu: value.path_mtu,
        recovery: value.recovery,
    }
}
type PacketQueues = (VecDeque<Vec<u8>>, Vec<Vec<u8>>);
#[derive(Clone, Default)]
struct Native {
    state: Arc<Mutex<PacketQueues>>,
}
impl Native {
    fn access<T>(&self, f: impl FnOnce(&mut PacketQueues) -> T) -> io::Result<T> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| io::Error::other("test device lock"))?;
        Ok(f(&mut state))
    }
}
struct Device {
    native: Native,
    layer: PacketLayer,
}
impl PacketDevice for Device {
    type Error = io::Error;
    fn layer(&self) -> PacketLayer {
        self.layer
    }
    fn receive(&mut self, output: &mut [u8]) -> io::Result<Option<usize>> {
        if output.len() < l2tunnel_device::READ_BUFFER_BYTES {
            return Err(io::Error::other("missing sentinel"));
        }
        self.native.access(|state| {
            state.0.pop_front().map(|packet| {
                output[..packet.len()].copy_from_slice(&packet);
                packet.len()
            })
        })
    }
    fn transmit(&mut self, bytes: &[u8]) -> io::Result<()> {
        self.native.access(|state| state.1.push(bytes.to_vec()))
    }
}
fn frame(layer: PacketLayer, value: u8) -> Vec<u8> {
    let mut bytes = vec![value; 1600];
    if layer == PacketLayer::Ethernet {
        bytes[12..14].copy_from_slice(&0x88b5u16.to_be_bytes());
    } else {
        bytes[..28].fill(0);
        bytes[0] = 0x45;
        bytes[2..4].copy_from_slice(&1600u16.to_be_bytes());
        bytes[8] = 64;
        bytes[9] = 17;
        bytes[12..16].copy_from_slice(&[10, 0, 0, value]);
        bytes[16..20].copy_from_slice(&[10, 1, 0, value]);
        bytes[20..22].copy_from_slice(&4000u16.to_be_bytes());
        bytes[22..24].copy_from_slice(&5000u16.to_be_bytes());
        bytes[24..26].copy_from_slice(&1580u16.to_be_bytes());
    }
    bytes
}
struct Credentials {
    chain: Vec<Vec<u8>>,
    key: Vec<u8>,
    member: MemberKey,
    members: MemberAllowlist,
}
fn credentials() -> Result<Credentials, TestError> {
    let cert = rcgen::generate_simple_self_signed(vec!["aligned-client.test".into()])?;
    let member = MemberKey::from_pkcs8(&MemberKey::generate_pkcs8()?)?;
    let members = MemberAllowlist::new(&[member.public_key()])?;
    Ok(Credentials {
        chain: vec![cert.cert.der().to_vec()],
        key: cert.signing_key.serialize_der(),
        member,
        members,
    })
}
async fn wait_delivery(
    a: &Native,
    b: &Native,
    first: &[u8],
    second: &[u8],
    tasks: &mut JoinSet<io::Result<()>>,
) -> TestResult {
    timeout(Duration::from_secs(5),async {
        loop {
            if a.access(|state|state.1.clone())?==vec![second.to_vec()] && b.access(|state|state.1.clone())?==vec![first.to_vec()] {return Ok::<_,TestError>(());}
            tokio::select! {
                result=tasks.join_next()=>return Err(format!("runtime exited before exact delivery: {result:?}").into()),
                _=sleep(Duration::from_millis(2))=>{}
            }
        }
    }).await??;
    // Tests end by explicit cancellation, never claim a graceful native drain.
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    Ok(())
}
#[tokio::test]
async fn aligned_udp_clients_forward_both_layers_and_duplex_modes() -> TestResult {
    let credentials = credentials()?;
    let client = ClientTls::from_der_roots(&credentials.chain)?;
    let server = ServerTls::from_der(&credentials.chain, &credentials.key)?;
    for layer in [PacketLayer::Ethernet, PacketLayer::Ip] {
        for duplex in [Duplex::Full, Duplex::Half] {
            let config = connection(layer, duplex);
            let settings = Settings {
                channels: 4,
                delivery: crate::delivery_tests::policy(),
            };
            let ((a_link, transport, records), (b_link, _, _)) = retry_udp_startup!(8, {
                let (a, b) = endpoints(duplex)?;
                let listener = TcpListener::bind("127.0.0.1:0").await?;
                let links = timeout(Duration::from_secs(8), async {
                    tokio::try_join!(
                        connect_udp(
                            listener.local_addr()?,
                            &client,
                            "aligned-client.test",
                            &credentials.member,
                            config,
                            a,
                            settings
                        ),
                        accept_udp(
                            &listener,
                            &server,
                            &credentials.members,
                            config,
                            b,
                            settings
                        )
                    )
                })
                .await??;
                Ok(links)
            })?;
            let first = frame(layer, 1);
            let second = frame(layer, 2);
            let an = Native::default();
            let bn = Native::default();
            an.access(|state| state.0.push_back(first.clone()))?;
            bn.access(|state| state.0.push_back(second.clone()))?;
            let mut tasks = JoinSet::new();
            tasks.spawn(runtime::run_udp(
                Device {
                    native: an.clone(),
                    layer,
                },
                a_link,
                config.runtime(),
                transport,
                records,
            ));
            tasks.spawn(runtime::run_udp(
                Device {
                    native: bn.clone(),
                    layer,
                },
                b_link,
                config.runtime(),
                transport,
                records,
            ));
            wait_delivery(&an, &bn, &first, &second, &mut tasks).await?;
        }
    }
    Ok(())
}
#[tokio::test]
async fn aligned_quic_clients_forward_both_layers_and_duplex_modes() -> TestResult {
    let credentials = credentials()?;
    for layer in [PacketLayer::Ethernet, PacketLayer::Ip] {
        for duplex in [Duplex::Full, Duplex::Half] {
            let config = connection(layer, duplex);
            let settings = Settings {
                channels: 4,
                delivery: crate::delivery_tests::policy(),
            };
            let ((a_link, transport, records), (b_link, _, _)) = retry_udp_startup!(8, {
                let (a, b) = endpoints(duplex)?;
                let listener = QuicListener::bind(
                    &credentials.chain,
                    &credentials.key,
                    config,
                    as_quic(b),
                    settings,
                )?;
                let links = timeout(Duration::from_secs(8), async {
                    tokio::try_join!(
                        connect_quic(
                            &credentials.chain,
                            "aligned-client.test",
                            &credentials.member,
                            config,
                            as_quic(a),
                            settings
                        ),
                        listener.accept(&credentials.members)
                    )
                })
                .await??;
                Ok(links)
            })?;
            let first = frame(layer, 1);
            let second = frame(layer, 2);
            let an = Native::default();
            let bn = Native::default();
            an.access(|state| state.0.push_back(first.clone()))?;
            bn.access(|state| state.0.push_back(second.clone()))?;
            let mut tasks = JoinSet::new();
            tasks.spawn(runtime::run_quic(
                Device {
                    native: an.clone(),
                    layer,
                },
                a_link,
                config.runtime(),
                transport,
                records,
            ));
            tasks.spawn(runtime::run_quic(
                Device {
                    native: bn.clone(),
                    layer,
                },
                b_link,
                config.runtime(),
                transport,
                records,
            ));
            wait_delivery(&an, &bn, &first, &second, &mut tasks).await?;
        }
    }
    Ok(())
}
#[test]
fn aligned_limits_and_binding_are_explicit() -> TestResult {
    let config = connection(PacketLayer::Ethernet, Duplex::Full);
    let (a, _) = endpoints(Duplex::Full)?;
    let settings = Settings {
        channels: 4,
        delivery: crate::delivery_tests::policy(),
    };
    let (transport, records) = udp_config(config, a, settings)?;
    let binding = runtime::udp_base_session_config(config.runtime(), transport, records)?;
    assert_ne!(
        binding,
        l2tunnel_runtime::udp::base_session_config(
            config.runtime(),
            transport,
            crate::delivery_tests::policy()
        )?
    );
    let (_, changed) = udp_config(
        config,
        a,
        Settings {
            channels: 2,
            delivery: crate::delivery_tests::policy(),
        },
    )?;
    assert_ne!(
        binding,
        runtime::udp_base_session_config(config.runtime(), transport, changed)?
    );
    for channels in [0, 257, u16::MAX] {
        assert!(
            udp_config(
                config,
                a,
                Settings {
                    channels,
                    delivery: crate::delivery_tests::policy()
                }
            )
            .is_err()
        );
    }
    assert!(
        udp_config(
            ConnectionConfig {
                compression: Compression::Lz4IfSmaller,
                ..config
            },
            a,
            settings
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
            settings
        )
        .is_err()
    );
    assert!(udp_config(config, udp::Settings { path_mtu: 575, ..a }, settings).is_err());
    Settings {
        channels: 256,
        delivery: crate::delivery_tests::policy(),
    }
    .validate(config, recovery())?;
    let (quic, records) = quic_config(config, as_quic(a), settings)?;
    assert_ne!(
        runtime::quic_base_session_config(config.runtime(), quic, records)?,
        l2tunnel_runtime::quic::base_session_config(
            config.runtime(),
            quic,
            crate::delivery_tests::policy()
        )?
    );
    Ok(())
}
#[tokio::test]
async fn mismatched_aligned_channels_fail_authentication() -> TestResult {
    let credentials = credentials()?;
    let config = connection(PacketLayer::Ethernet, Duplex::Full);
    let client = ClientTls::from_der_roots(&credentials.chain)?;
    let server = ServerTls::from_der(&credentials.chain, &credentials.key)?;
    let (first, second) = retry_udp_startup!(5, {
        let (a, b) = endpoints(Duplex::Full)?;
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let results = timeout(Duration::from_secs(5), async {
            tokio::join!(
                connect_udp(
                    address,
                    &client,
                    "aligned-client.test",
                    &credentials.member,
                    config,
                    a,
                    Settings {
                        channels: 4,
                        delivery: crate::delivery_tests::policy()
                    }
                ),
                accept_udp(
                    &listener,
                    &server,
                    &credentials.members,
                    config,
                    b,
                    Settings {
                        channels: 2,
                        delivery: crate::delivery_tests::policy()
                    }
                )
            )
        });
        // Resolve local address before the joined operations so both paths must actually fail.
        let (first, second) = results.await?;
        if first
            .as_ref()
            .err()
            .is_some_and(|e| udp_startup_addr_in_use(e))
            || second
                .as_ref()
                .err()
                .is_some_and(|e| udp_startup_addr_in_use(e))
        {
            return Err(
                io::Error::new(io::ErrorKind::AddrInUse, "test startup bind collision").into(),
            );
        }
        Ok((first, second))
    })?;
    assert!(first.is_err());
    assert!(second.is_err());
    let (first, second) = retry_udp_startup!(5, {
        let (a, b) = endpoints(Duplex::Full)?;
        let listener = QuicListener::bind(
            &credentials.chain,
            &credentials.key,
            config,
            as_quic(b),
            Settings {
                channels: 2,
                delivery: crate::delivery_tests::policy(),
            },
        )?;
        let (first, second) = timeout(Duration::from_secs(5), async {
            tokio::join!(
                connect_quic(
                    &credentials.chain,
                    "aligned-client.test",
                    &credentials.member,
                    config,
                    as_quic(a),
                    Settings {
                        channels: 4,
                        delivery: crate::delivery_tests::policy()
                    }
                ),
                listener.accept(&credentials.members)
            )
        })
        .await?;
        if first
            .as_ref()
            .err()
            .is_some_and(|e| udp_startup_addr_in_use(e))
            || second
                .as_ref()
                .err()
                .is_some_and(|e| udp_startup_addr_in_use(e))
        {
            return Err(
                io::Error::new(io::ErrorKind::AddrInUse, "test startup bind collision").into(),
            );
        }
        Ok((first, second))
    })?;
    assert!(first.is_err());
    assert!(second.is_err());
    Ok(())
}
#[tokio::test]
async fn base_frame_client_helpers_bind_delivery_for_full_and_half() -> TestResult {
    let credentials = credentials()?;
    let client = ClientTls::from_der_roots(&credentials.chain)?;
    let server = ServerTls::from_der(&credentials.chain, &credentials.key)?;
    for duplex in [Duplex::Full, Duplex::Half] {
        let config = connection(PacketLayer::Ethernet, duplex);
        retry_udp_startup!(8, {
            let (a, b) = endpoints(duplex)?;
            let listener = TcpListener::bind("127.0.0.1:0").await?;
            timeout(Duration::from_secs(8), async {
                tokio::try_join!(
                    udp::connect(
                        listener.local_addr()?,
                        &client,
                        "aligned-client.test",
                        &credentials.member,
                        config,
                        a,
                        crate::delivery_tests::policy(),
                    ),
                    udp::accept(
                        &listener,
                        &server,
                        &credentials.members,
                        config,
                        b,
                        crate::delivery_tests::policy()
                    )
                )
            })
            .await??;
            Ok(())
        })?;
        retry_udp_startup!(8, {
            let (a, b) = endpoints(duplex)?;
            let listener = quic::Listener::bind(
                &credentials.chain,
                &credentials.key,
                config,
                as_quic(b),
                crate::delivery_tests::policy(),
            )?;
            timeout(Duration::from_secs(8), async {
                tokio::try_join!(
                    quic::connect(
                        &credentials.chain,
                        "aligned-client.test",
                        &credentials.member,
                        config,
                        as_quic(a),
                        crate::delivery_tests::policy(),
                    ),
                    listener.accept(&credentials.members)
                )
            })
            .await??;
            Ok(())
        })?;
    }
    assert!(
        quic::finish_pair(
            tokio::time::Instant::now(),
            std::future::pending::<io::Result<()>>()
        )
        .await
        .is_err()
    );
    Ok(())
}

#[tokio::test]
async fn udp_startup_retry_is_bounded_and_only_retries_bind_collisions() -> TestResult {
    let attempts = std::cell::Cell::new(0);
    let value = retry_udp_startup!(1, {
        attempts.set(attempts.get() + 1);
        if attempts.get() == 1 {
            return Err(io::Error::new(io::ErrorKind::AddrInUse, "injected pre-start bind").into());
        }
        Ok(7)
    })?;
    assert_eq!(value, 7);
    assert_eq!(attempts.get(), 2);
    for (kind, expected) in [
        (io::ErrorKind::AddrInUse, 4),
        (io::ErrorKind::PermissionDenied, 1),
    ] {
        attempts.set(0);
        let result: Result<(), TestError> = retry_udp_startup!(1, {
            attempts.set(attempts.get() + 1);
            Err(io::Error::new(kind, "injected startup error").into())
        });
        assert!(result.is_err());
        assert_eq!(attempts.get(), expected);
    }
    Ok(())
}

#[tokio::test]
async fn udp_startup_classifies_actual_wrapped_quic_bind_without_retrying_auth() -> TestResult {
    let credentials = credentials()?;
    let held = crate::test_ports::reserve(false)?;
    let held_address = held.local_addr()?;
    let (mut a, _) = endpoints(Duplex::Full)?;
    a.forward.local = held_address;
    let config = connection(PacketLayer::Ip, Duplex::Full);
    let transport = as_quic(a);
    let error = match quic::connect(
        &credentials.chain,
        "aligned-client.test",
        &credentials.member,
        config,
        transport,
        crate::delivery_tests::policy(),
    )
    .await
    {
        Err(error) => error,
        Ok(_) => return Err(io::Error::other("occupied client endpoint accepted").into()),
    };
    // This is the real factory wrapper from the formerly unrecognized failure.
    assert_eq!(error.kind(), io::ErrorKind::Other);
    assert!(
        udp_startup_addr_in_use(&error),
        "actual bind error: {error:?}"
    );
    assert!(std::net::UdpSocket::bind(held_address).is_err());
    drop(held);
    let _released = std::net::UdpSocket::bind(held_address)?;
    for error in [
        l2tunnel_quic::Error::Authentication(l2tunnel_auth::Error::BindingMismatch),
        l2tunnel_quic::Error::Protocol("rejected"),
        l2tunnel_quic::Error::TimedOut,
        l2tunnel_quic::Error::Io(io::Error::new(io::ErrorKind::PermissionDenied, "denied")),
    ] {
        assert!(!udp_startup_addr_in_use(&io::Error::other(error)));
    }
    Ok(())
}

#[tokio::test]
async fn udp_startup_retries_cannot_renew_original_deadline() {
    let attempts = std::cell::Cell::new(0);
    let result: Result<(), TestError> = async {
        retry_udp_startup!(1, {
            attempts.set(attempts.get() + 1);
            sleep(Duration::from_millis(300)).await;
            Err::<(), _>(io::Error::new(io::ErrorKind::AddrInUse, "injected bind collision").into())
        })?;
        Ok(())
    }
    .await;
    assert!(result.as_ref().err().is_some_and(|error| {
        error
            .downcast_ref::<tokio::time::error::Elapsed>()
            .is_some()
    }));
    assert_eq!(attempts.get(), 4);
}

#[tokio::test(start_paused = true)]
async fn base_half_quic_first_lane_auth_keeps_original_pair_deadline() -> TestResult {
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
    let config = ConnectionConfig {
        handshake_timeout: Duration::from_millis(200),
        ..connection(PacketLayer::Ip, Duplex::Half)
    };
    let (a, b) = endpoints(Duplex::Half)?;
    let profile = quic::runtime_config(config, as_quic(b))?;
    let base = l2tunnel_runtime::quic::base_session_config(
        config.runtime(),
        profile,
        crate::delivery_tests::policy(),
    )?;
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
    let client_reverse = a.reverse.ok_or("client reverse")?;
    let mut clock = tokio::task::JoinSet::new();
    clock.spawn(async {
        loop {
            tokio::task::yield_now().await;
        }
    });
    let wall_deadline = std::time::Instant::now() + Duration::from_secs(3);
    let started = tokio::time::Instant::now();
    let mut attempt = Box::pin(quic::connect(
        &c.chain,
        "aligned-client.test",
        &c.member,
        config,
        as_quic(a),
        crate::delivery_tests::policy(),
    ));
    // Start the original allowance before delaying the peer's first accept.
    let initial = std::future::poll_fn(|cx| Poll::Ready(attempt.as_mut().poll(cx))).await;
    assert!(
        initial.is_pending(),
        "setup ended before the first peer accept"
    );
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

#[tokio::test]
async fn base_frame_policy_mismatch_reaches_authentication_and_rejects_both_peers() -> TestResult {
    let credentials = credentials()?;
    let config = connection(PacketLayer::Ethernet, Duplex::Full);
    let client = ClientTls::from_der_roots(&credentials.chain)?;
    let server = ServerTls::from_der(&credentials.chain, &credentials.key)?;
    let client_delivery = crate::delivery_tests::policy();
    let mut server_delivery = client_delivery;
    server_delivery.reverse.target_bandwidth_bps += 1;
    for genuine in [false, true] {
        let (first, second) = retry_udp_startup!(5, {
            let (a, b) = endpoints(Duplex::Full)?;
            let (first, second) = if genuine {
                let listener = quic::Listener::bind(
                    &credentials.chain,
                    &credentials.key,
                    config,
                    as_quic(b),
                    server_delivery,
                )?;
                timeout(Duration::from_secs(5), async {
                    tokio::join!(
                        async {
                            quic::connect(
                                &credentials.chain,
                                "aligned-client.test",
                                &credentials.member,
                                config,
                                as_quic(a),
                                client_delivery,
                            )
                            .await
                            .map(|_| ())
                        },
                        async { listener.accept(&credentials.members).await.map(|_| ()) },
                    )
                })
                .await?
            } else {
                let listener = TcpListener::bind("127.0.0.1:0").await?;
                timeout(Duration::from_secs(5), async {
                    tokio::join!(
                        async {
                            udp::connect(
                                listener.local_addr()?,
                                &client,
                                "aligned-client.test",
                                &credentials.member,
                                config,
                                a,
                                client_delivery,
                            )
                            .await
                            .map(|_| ())
                        },
                        async {
                            udp::accept(
                                &listener,
                                &server,
                                &credentials.members,
                                config,
                                b,
                                server_delivery,
                            )
                            .await
                            .map(|_| ())
                        },
                    )
                })
                .await?
            };
            if [&first, &second].iter().any(|result| {
                result
                    .as_ref()
                    .err()
                    .is_some_and(|error| udp_startup_addr_in_use(error))
            }) {
                return Err(io::Error::new(
                    io::ErrorKind::AddrInUse,
                    "test startup bind collision",
                )
                .into());
            }
            Ok((first, second))
        })?;
        assert!(first.is_err() && second.is_err());
        let errors = [first, second];
        assert!(
            errors
                .iter()
                .any(|result| result.as_ref().err().is_some_and(|error| {
                    let cause = error.get_ref();
                    cause.is_some_and(|cause| {
                        matches!(
                            cause.downcast_ref::<l2tunnel_auth::Error>(),
                            Some(l2tunnel_auth::Error::BindingMismatch)
                        ) || matches!(
                            cause.downcast_ref::<l2tunnel_quic::Error>(),
                            Some(l2tunnel_quic::Error::Authentication(
                                l2tunnel_auth::Error::BindingMismatch
                            ))
                        )
                    })
                })),
            "must witness actual authenticated policy mismatch, not only two failures; genuine={genuine} errors={errors:?}"
        );
    }
    Ok(())
}
