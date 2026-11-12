//! Real original-loopback handshake deadline regressions; no privileged lab.
use super::*;
use tokio::time::{Instant, sleep, timeout};
// Serialize these real-time fixtures so their own TLS/crypto work does not
// consume each other's deliberately short phase budgets. Original deadlines
// and the default concurrent workspace test runner remain unchanged.
static NETWORK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

type Failure = Box<dyn std::error::Error + Send + Sync>;
type Result<T = ()> = std::result::Result<T, Failure>;
struct Credentials {
    client: ClientTls,
    server: ServerTls,
    member: MemberKey,
    allow: MemberAllowlist,
}
fn credentials() -> Result<Credentials> {
    let cert = rcgen::generate_simple_self_signed(vec!["base-deadline.test".into()])?;
    let chain = vec![cert.cert.der().to_vec()];
    let member = MemberKey::from_pkcs8(&MemberKey::generate_pkcs8()?)?;
    Ok(Credentials {
        client: ClientTls::from_der_roots(&chain)?,
        server: ServerTls::from_der(&chain, &cert.signing_key.serialize_der())?,
        allow: MemberAllowlist::new(&[member.public_key()])?,
        member,
    })
}
fn config(duplex: Duplex, limit: Duration) -> ConnectionConfig {
    ConnectionConfig {
        layer: PacketLayer::Ip,
        duplex,
        max_packet: 1600,
        compression: Compression::None,
        handshake_timeout: limit,
    }
}
#[tokio::test]
async fn original_one_second_budget_includes_both_authentications_and_pairing() -> Result {
    let _network = NETWORK.lock().await;
    let c = credentials()?;
    let cfg = config(Duplex::Half, Duration::from_millis(1000));
    let binding = cfg.session()?;
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let peer = async {
        let (first, _) = timeout(Duration::from_secs(2), listener.accept()).await??;
        sleep(Duration::from_millis(400)).await;
        let first =
            auth::server_accept(first, &c.server, &c.allow, binding, Duration::from_secs(3))
                .await?;
        let (second, _) = timeout(Duration::from_secs(2), listener.accept()).await??;
        sleep(Duration::from_millis(400)).await;
        let second =
            auth::server_accept(second, &c.server, &c.allow, binding, Duration::from_secs(3))
                .await?;
        sleep(Duration::from_millis(500)).await;
        let result = l2tunnel_runtime::server_pair(first, second).await;
        Ok::<_, Failure>(result)
    };
    let client = async {
        let started = Instant::now();
        let result = connect(address, &c.client, "base-deadline.test", &c.member, cfg).await;
        (started.elapsed(), result)
    };
    let ((elapsed, result), _peer) =
        timeout(Duration::from_secs(4), async { tokio::join!(client, peer) }).await?;
    assert!(
        result.is_err(),
        "late half admission succeeded after original1000ms: {elapsed:?}"
    );
    assert_eq!(
        result.err().map(|e| e.kind()),
        Some(io::ErrorKind::TimedOut)
    );
    assert!(
        elapsed < Duration::from_millis(1250),
        "original deadline was reset: {elapsed:?}"
    );
    Ok(())
}

async fn closed<S: tokio::io::AsyncRead + Unpin>(stream: &mut S) -> Result {
    use tokio::io::AsyncReadExt;
    timeout(Duration::from_millis(800), async {
        let mut bytes = [0; 4096];
        for _ in 0..32 {
            match stream.read(&mut bytes).await {
                Ok(0) => return Ok::<_, Failure>(()),
                Ok(_) => {}
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::UnexpectedEof
                            | io::ErrorKind::ConnectionReset
                            | io::ErrorKind::ConnectionAborted
                            | io::ErrorKind::BrokenPipe
                    ) =>
                {
                    return Ok(());
                }
                Err(e) => return Err(e.into()),
            }
        }
        Err("original socket did not reach bounded EOF".into())
    })
    .await??;
    Ok(())
}
fn timely(result: io::Result<Link>, elapsed: Duration, budget: Duration) {
    assert_eq!(
        result.err().map(|e| e.kind()),
        Some(io::ErrorKind::TimedOut)
    );
    // Scheduling tolerance is only a test-observation guard. No late success
    // is accepted, and the actual absolute protocol deadline remains unchanged.
    assert!(
        elapsed < budget + Duration::from_millis(180),
        "deadline restarted: {elapsed:?}"
    );
}
#[tokio::test]
async fn loopback_full_half_tap_tun_and_compression_still_authenticate() -> Result {
    let _network = NETWORK.lock().await;
    let c = credentials()?;
    for duplex in [Duplex::Full, Duplex::Half] {
        for layer in [PacketLayer::Ethernet, PacketLayer::Ip] {
            for compression in [Compression::None, Compression::Lz4IfSmaller] {
                let cfg = ConnectionConfig {
                    layer,
                    compression,
                    ..config(duplex, Duration::from_secs(2))
                };
                let listener = TcpListener::bind("127.0.0.1:0").await?;
                let address = listener.local_addr()?;
                let (client, server) = tokio::join!(
                    connect(address, &c.client, "base-deadline.test", &c.member, cfg),
                    accept(&listener, &c.server, &c.allow, cfg)
                );
                drop((client?, server?));
            }
        }
    }
    Ok(())
}
#[tokio::test]
async fn first_accept_times_out_but_original_listener_remains_usable() -> Result {
    let _network = NETWORK.lock().await;
    let c = credentials()?;
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let started = Instant::now();
    let cfg = config(Duplex::Full, Duration::from_millis(60));
    let result = timeout(
        Duration::from_millis(600),
        accept(&listener, &c.server, &c.allow, cfg),
    )
    .await?;
    timely(result, started.elapsed(), cfg.handshake_timeout);
    assert_eq!(listener.local_addr()?, address);
    let cfg = config(Duplex::Full, Duration::from_secs(2));
    let (client, server) = tokio::join!(
        connect(address, &c.client, "base-deadline.test", &c.member, cfg),
        accept(&listener, &c.server, &c.allow, cfg)
    );
    drop((client?, server?));
    Ok(())
}
#[tokio::test]
async fn client_second_tls_uses_remaining_budget_and_closes_both_original_sockets() -> Result {
    let _network = NETWORK.lock().await;
    let c = credentials()?;
    let cfg = config(Duplex::Half, Duration::from_millis(400));
    let binding = cfg.session()?;
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let peer = async {
        let (stream, _) = timeout(Duration::from_secs(2), listener.accept()).await??;
        sleep(Duration::from_millis(240)).await;
        let mut first =
            auth::server_accept(stream, &c.server, &c.allow, binding, Duration::from_secs(2))
                .await?;
        let (mut second, _) = timeout(Duration::from_secs(2), listener.accept()).await??;
        tokio::try_join!(closed(&mut first), closed(&mut second))?;
        Ok::<_, Failure>(())
    };
    let client = async {
        let started = Instant::now();
        let result = connect(address, &c.client, "base-deadline.test", &c.member, cfg).await;
        timely(result, started.elapsed(), cfg.handshake_timeout);
        Ok::<_, Failure>(())
    };
    tokio::try_join!(peer, client)?;
    Ok(())
}
#[tokio::test]
async fn server_first_wait_and_second_tls_share_budget_and_release_accepted_sockets() -> Result {
    let _network = NETWORK.lock().await;
    let c = credentials()?;
    let cfg = config(Duplex::Half, Duration::from_millis(400));
    let binding = cfg.session()?;
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let peer = async {
        sleep(Duration::from_millis(180)).await;
        let mut first = auth::client_connect(
            TcpStream::connect(address).await?,
            &c.client,
            "base-deadline.test",
            &c.member,
            binding,
            Duration::from_secs(2),
        )
        .await?;
        sleep(Duration::from_millis(100)).await;
        let mut second = TcpStream::connect(address).await?;
        tokio::try_join!(closed(&mut first), closed(&mut second))?;
        Ok::<_, Failure>(())
    };
    let server = async {
        let started = Instant::now();
        let result = accept(&listener, &c.server, &c.allow, cfg).await;
        timely(result, started.elapsed(), cfg.handshake_timeout);
        Ok::<_, Failure>(())
    };
    tokio::try_join!(peer, server)?;
    Ok(())
}
#[tokio::test]
async fn client_pair_wait_cannot_restart_deadline_and_closes_both_authenticated_lanes() -> Result {
    let _network = NETWORK.lock().await;
    let c = credentials()?;
    let cfg = config(Duplex::Half, Duration::from_millis(400));
    let binding = cfg.session()?;
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let peer = async {
        let (stream, _) = timeout(Duration::from_secs(2), listener.accept()).await??;
        let mut first =
            auth::server_accept(stream, &c.server, &c.allow, binding, Duration::from_secs(2))
                .await?;
        let (second, _) = timeout(Duration::from_secs(2), listener.accept()).await??;
        sleep(Duration::from_millis(180)).await;
        let mut second =
            auth::server_accept(second, &c.server, &c.allow, binding, Duration::from_secs(2))
                .await?;
        tokio::try_join!(closed(&mut first), closed(&mut second))?;
        Ok::<_, Failure>(())
    };
    let client = async {
        let started = Instant::now();
        let result = connect(address, &c.client, "base-deadline.test", &c.member, cfg).await;
        timely(result, started.elapsed(), cfg.handshake_timeout);
        Ok::<_, Failure>(())
    };
    tokio::try_join!(peer, client)?;
    Ok(())
}
#[tokio::test]
async fn server_pair_wait_cannot_restart_deadline_and_closes_both_authenticated_lanes() -> Result {
    let _network = NETWORK.lock().await;
    let c = credentials()?;
    let cfg = config(Duplex::Half, Duration::from_millis(400));
    let binding = cfg.session()?;
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let peer = async {
        let mut first = auth::client_connect(
            TcpStream::connect(address).await?,
            &c.client,
            "base-deadline.test",
            &c.member,
            binding,
            Duration::from_secs(2),
        )
        .await?;
        sleep(Duration::from_millis(140)).await;
        let mut second = auth::client_connect(
            TcpStream::connect(address).await?,
            &c.client,
            "base-deadline.test",
            &c.member,
            binding,
            Duration::from_secs(2),
        )
        .await?;
        tokio::try_join!(closed(&mut first), closed(&mut second))?;
        Ok::<_, Failure>(())
    };
    let server = async {
        let started = Instant::now();
        let result = accept(&listener, &c.server, &c.allow, cfg).await;
        timely(result, started.elapsed(), cfg.handshake_timeout);
        Ok::<_, Failure>(())
    };
    tokio::try_join!(peer, server)?;
    Ok(())
}
#[tokio::test]
async fn malformed_second_tls_fails_early_and_closes_already_authenticated_lane() -> Result {
    let _network = NETWORK.lock().await;
    use tokio::io::AsyncWriteExt;
    let c = credentials()?;
    let cfg = config(Duplex::Half, Duration::from_secs(2));
    let binding = cfg.session()?;
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let peer = async {
        let mut first = auth::client_connect(
            TcpStream::connect(address).await?,
            &c.client,
            "base-deadline.test",
            &c.member,
            binding,
            Duration::from_secs(2),
        )
        .await?;
        let mut second = TcpStream::connect(address).await?;
        second.write_all(b"not valid TLS").await?;
        second.shutdown().await?;
        tokio::try_join!(closed(&mut first), closed(&mut second))?;
        Ok::<_, Failure>(())
    };
    let server = async {
        let started = Instant::now();
        let result = accept(&listener, &c.server, &c.allow, cfg).await;
        let e = result.err().ok_or("accepted malformed TLS")?;
        assert_ne!(e.kind(), io::ErrorKind::TimedOut);
        assert!(started.elapsed() < Duration::from_secs(1));
        Ok::<_, Failure>(())
    };
    tokio::try_join!(peer, server)?;
    Ok(())
}
#[tokio::test]
async fn accept_cancellation_drops_first_socket_and_preserves_listener() -> Result {
    let _network = NETWORK.lock().await;
    use std::future::poll_fn;
    let c = credentials()?;
    let cfg = config(Duplex::Half, Duration::from_secs(2));
    let binding = cfg.session()?;
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let io = TcpStream::connect(address).await?;
    let mut server = Box::pin(accept(&listener, &c.server, &c.allow, cfg));
    let mut client = Box::pin(auth::client_connect(
        io,
        &c.client,
        "base-deadline.test",
        &c.member,
        binding,
        Duration::from_secs(2),
    ));
    let mut first = timeout(
        Duration::from_secs(1),
        poll_fn(|cx| {
            assert!(server.as_mut().poll(cx).is_pending());
            client.as_mut().poll(cx)
        }),
    )
    .await??;
    drop(server);
    closed(&mut first).await?;
    drop(first);
    drop(client);
    let cfg = config(Duplex::Full, Duration::from_secs(2));
    let (a, b) = tokio::join!(
        connect(address, &c.client, "base-deadline.test", &c.member, cfg),
        accept(&listener, &c.server, &c.allow, cfg)
    );
    drop((a?, b?));
    Ok(())
}
#[tokio::test]
async fn invalid_configuration_does_not_accept_or_connect_any_socket() -> Result {
    let _network = NETWORK.lock().await;
    let c = credentials()?;
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    for duration in [Duration::ZERO, Duration::from_secs(121)] {
        let cfg = config(Duplex::Full, duration);
        assert_eq!(
            connect(address, &c.client, "base-deadline.test", &c.member, cfg)
                .await
                .err()
                .map(|e| e.kind()),
            Some(io::ErrorKind::InvalidInput)
        );
        assert_eq!(
            accept(&listener, &c.server, &c.allow, cfg)
                .await
                .err()
                .map(|e| e.kind()),
            Some(io::ErrorKind::InvalidInput)
        );
    }
    assert!(
        timeout(Duration::from_millis(30), listener.accept())
            .await
            .is_err()
    );
    let io = TcpStream::connect(address).await?;
    let cfg = config(Duplex::Full, Duration::from_secs(1));
    let mut wrong = cfg.session()?;
    wrong.layer = PacketLayer::Ethernet;
    assert_eq!(
        accept_session(&listener, &c.server, &c.allow, cfg, wrong)
            .await
            .err()
            .map(|e| e.kind()),
        Some(io::ErrorKind::InvalidInput)
    );
    let (queued, _) = timeout(Duration::from_millis(100), listener.accept()).await??;
    assert_eq!(queued.peer_addr()?, io.local_addr()?);
    Ok(())
}
#[tokio::test]
async fn expired_deadline_never_polls_input_and_late_ready_owner_is_dropped() -> Result {
    let _network = NETWORK.lock().await;
    use std::{
        pin::Pin,
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
        task::{Context, Poll},
    };
    use tokio::io::{AsyncRead, AsyncReadExt, ReadBuf};
    struct LateIo(Arc<AtomicUsize>);
    impl AsyncRead for LateIo {
        fn poll_read(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            out: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            self.0.fetch_add(1, Ordering::Relaxed);
            std::thread::sleep(Duration::from_millis(25));
            out.put_slice(b"x");
            Poll::Ready(Ok(()))
        }
    }
    struct Owner(Arc<AtomicUsize>);
    impl Drop for Owner {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }
    let reads = Arc::new(AtomicUsize::new(0));
    let drops = Arc::new(AtomicUsize::new(0));
    let mut input = LateIo(reads.clone());
    let expired = HandshakeDeadline(Instant::now() - Duration::from_millis(1));
    let result = expired
        .within(async {
            let mut b = [0];
            input.read_exact(&mut b).await?;
            Ok(Owner(drops.clone()))
        })
        .await;
    assert_eq!(
        result.err().map(|e| e.kind()),
        Some(io::ErrorKind::TimedOut)
    );
    assert_eq!(reads.load(Ordering::Relaxed), 0);
    let end = HandshakeDeadline::start(Duration::from_millis(10))?;
    let result = end
        .within(async {
            let mut b = [0];
            input.read_exact(&mut b).await?;
            Ok(Owner(drops.clone()))
        })
        .await;
    assert_eq!(
        result.err().map(|e| e.kind()),
        Some(io::ErrorKind::TimedOut)
    );
    assert_eq!(reads.load(Ordering::Relaxed), 1);
    assert_eq!(drops.load(Ordering::Relaxed), 1);
    Ok(())
}
