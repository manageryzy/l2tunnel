//! Boundary regressions for explicitly bound base-native UDP/QUIC delivery.
use super::*;
use l2tunnel_runtime::managed::DeliveryConfig;
use tokio::time::timeout;
type Failure = Box<dyn std::error::Error + Send + Sync>;
type Result<T = ()> = std::result::Result<T, Failure>;
fn config() -> ConnectionConfig {
    ConnectionConfig {
        layer: PacketLayer::Ip,
        duplex: Duplex::Full,
        max_packet: 1600,
        compression: Compression::None,
        handshake_timeout: Duration::from_secs(2),
    }
}
fn settings(local: SocketAddr, peer: SocketAddr) -> quic::Settings {
    quic::Settings {
        forward: udp::Endpoints { local, peer },
        reverse: None,
        application_id: *b"base-delivery-28",
        path_mtu: 1280,
        recovery: udp::RecoveryMode::SelectiveRepeat,
    }
}
fn invalid_delivery() -> DeliveryConfig {
    let mut delivery = delivery_tests::policy();
    delivery.forward.target_bandwidth_bps = 0;
    delivery
}
#[tokio::test]
async fn invalid_base_quic_delivery_precedes_bad_certificates_and_occupied_socket() -> Result {
    let held = crate::test_ports::reserve(false)?;
    let peer = crate::test_ports::reserve(false)?;
    let settings = settings(held.local_addr()?, peer.local_addr()?);
    let cfg = config();
    let profile = quic::runtime_config(cfg, settings)?;
    let expected =
        l2tunnel_runtime::quic::base_session_config(cfg.runtime(), profile, invalid_delivery())
            .err()
            .ok_or("invalid delivery unexpectedly accepted")?;
    let actual = quic::Listener::bind(&[], &[], cfg, settings, invalid_delivery())
        .err()
        .ok_or("invalid delivery unexpectedly bound")?;
    assert_eq!(actual.kind(), expected.kind());
    assert_eq!(actual.to_string(), expected.to_string());
    // The malformed certificate and occupied bind are independent adverse
    // witnesses: a valid delivery policy must proceed far enough to reject them.
    let credentials = quic::Listener::bind(&[], &[], cfg, settings, delivery_tests::policy())
        .err()
        .ok_or("empty credentials unexpectedly accepted")?;
    assert_ne!(actual.to_string(), credentials.to_string());
    Ok(())
}
#[tokio::test]
async fn derived_quic_listener_public_base_accept_rejects_without_waiting_for_peer() -> Result {
    let local = crate::test_ports::reserve(false)?;
    let peer = crate::test_ports::reserve(false)?;
    let settings = settings(local.local_addr()?, peer.local_addr()?);
    drop(local);
    let cert = rcgen::generate_simple_self_signed(vec!["base-delivery.test".into()])?;
    let member = MemberKey::from_pkcs8(&MemberKey::generate_pkcs8()?)?;
    let allow = MemberAllowlist::new(&[member.public_key()])?;
    let cfg = config();
    // bind_base is the existing private path used by derived records. There is
    // intentionally no QUIC peer; an incorrect public accept would wait for I/O.
    let listener = quic::Listener::bind_base(
        &[cert.cert.der().to_vec()],
        &cert.signing_key.serialize_der(),
        cfg,
        settings,
        cfg.session()?,
    )?;
    for _ in 0..2 {
        let result = timeout(Duration::from_millis(100), listener.accept(&allow)).await?;
        let error = result
            .err()
            .ok_or("derived listener accepted base records")?;
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert!(error.to_string().contains("derived QUIC listener"));
    }
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn base_udp_and_quic_idle_accepts_share_the_original_entry_deadline() -> Result {
    use std::{future::Future, pin::Pin, task::Poll};
    let cert = rcgen::generate_simple_self_signed(vec!["base-delivery.test".into()])?;
    let chain = vec![cert.cert.der().to_vec()];
    let key = cert.signing_key.serialize_der();
    let tls = ServerTls::from_der(&chain, &key)?;
    let member = MemberKey::from_pkcs8(&MemberKey::generate_pkcs8()?)?;
    let allow = MemberAllowlist::new(&[member.public_key()])?;
    let mut clock = tokio::task::JoinSet::new();
    clock.spawn(async {
        loop {
            tokio::task::yield_now().await;
        }
    });
    for genuine in [false, true] {
        let local = crate::test_ports::reserve(false)?;
        let peer = crate::test_ports::reserve(false)?;
        let settings = settings(local.local_addr()?, peer.local_addr()?);
        drop(local);
        let cfg = ConnectionConfig {
            handshake_timeout: Duration::from_millis(200),
            ..config()
        };
        let udp_listener = TcpListener::bind("127.0.0.1:0").await?;
        let quic_listener = if genuine {
            Some(quic::Listener::bind(
                &chain,
                &key,
                cfg,
                settings,
                delivery_tests::policy(),
            )?)
        } else {
            None
        };
        let transport = udp::Settings {
            forward: settings.forward,
            reverse: None,
            cover: udp::CoverProfile::OpenVpnLike,
            protection: udp::Protection::ChaCha20Poly1305,
            path_mtu: 1280,
            recovery: udp::RecoveryMode::SelectiveRepeat,
        };
        let started = tokio::time::Instant::now();
        let mut attempt: Pin<Box<dyn Future<Output = io::Result<()>>>> =
            if let Some(listener) = &quic_listener {
                Box::pin(async { listener.accept(&allow).await.map(|_| ()) })
            } else {
                Box::pin(async {
                    udp::accept(
                        &udp_listener,
                        &tls,
                        &allow,
                        cfg,
                        transport,
                        delivery_tests::policy(),
                    )
                    .await
                    .map(|_| ())
                })
            };
        let first = std::future::poll_fn(|cx| Poll::Ready(attempt.as_mut().poll(cx))).await;
        assert!(first.is_pending(), "idle accept unexpectedly completed");
        tokio::time::advance(Duration::from_millis(199)).await;
        let early = std::future::poll_fn(|cx| Poll::Ready(attempt.as_mut().poll(cx))).await;
        assert!(early.is_pending(), "original entry deadline ended early");
        tokio::time::advance(Duration::from_millis(1)).await;
        let expired = std::future::poll_fn(|cx| Poll::Ready(attempt.as_mut().poll(cx))).await;
        let Poll::Ready(result) = expired else {
            return Err("idle accept renewed original deadline".into());
        };
        assert_eq!(
            result
                .err()
                .ok_or("idle accept unexpectedly succeeded")?
                .kind(),
            io::ErrorKind::TimedOut
        );
        assert_eq!(started.elapsed(), cfg.handshake_timeout);
        drop(attempt);
    }
    drop(clock);
    Ok(())
}
