use super::*;
#[tokio::test]
async fn setup_deadline_rejects_ready_success_before_and_after_poll() -> io::Result<()> {
    let expired = Instant::now();
    assert_eq!(
        within(expired, async { Ok(()) })
            .await
            .err()
            .map(|e| e.kind()),
        Some(io::ErrorKind::TimedOut)
    );
    let expires = Instant::now() + Duration::from_millis(1);
    let result = within(expires, async {
        std::thread::sleep(Duration::from_millis(2));
        Ok(())
    })
    .await;
    assert_eq!(
        result.err().map(|e| e.kind()),
        Some(io::ErrorKind::TimedOut)
    );
    Ok(())
}

use crate::udp::Endpoints;
use l2tunnel_core::Duplex;
use l2tunnel_device::PacketLayer;
use std::{collections::VecDeque, net::SocketAddr};
use tokio::time::{sleep, timeout};
type TestError = Box<dyn std::error::Error + Send + Sync>;
type TestResult = Result<(), TestError>;
fn bundle(seed: u8) -> io::Result<KeyBundle> {
    let mut b = [seed; 64];
    b[32..].fill(seed + 1);
    KeyBundle::from_bytes(b)
}
fn config(duplex: Duplex) -> ConnectionConfig {
    ConnectionConfig {
        layer: PacketLayer::Ip,
        duplex,
        max_packet: 1600,
        compression: crate::Compression::Lz4IfSmaller,
        handshake_timeout: Duration::from_secs(3),
    }
}
async fn endpoints(
    ipv6: bool,
    duplex: Duplex,
) -> io::Result<(
    super::super::Settings,
    super::super::Settings,
    Vec<SocketAddr>,
)> {
    let host = if ipv6 { "[::1]:0" } else { "127.0.0.1:0" };
    let mut sockets = Vec::new();
    for _ in 0..if duplex == Duplex::Half { 4 } else { 2 } {
        sockets.push(UdpSocket::bind(host).await?);
    }
    let addresses = sockets
        .iter()
        .map(UdpSocket::local_addr)
        .collect::<io::Result<Vec<_>>>()?;
    let a = super::super::Settings {
        forward: Endpoints {
            local: addresses[0],
            peer: addresses[1],
        },
        reverse: (duplex == Duplex::Half).then(|| Endpoints {
            local: addresses[2],
            peer: addresses[3],
        }),
        protection: if ipv6 {
            carrier::Protection::HmacSha256
        } else {
            carrier::Protection::ChaCha20Poly1305
        },
        path_mtu: if ipv6 { 1280 } else { 1200 },
        authenticated_lease: Duration::from_secs(3600),
    };
    let b = super::super::Settings {
        forward: Endpoints {
            local: a.forward.peer,
            peer: a.forward.local,
        },
        reverse: a.reverse.map(|r| Endpoints {
            local: r.peer,
            peer: r.local,
        }),
        ..a
    };
    Ok((a, b, addresses))
}
struct Credentials {
    client: ClientTls,
    server: ServerTls,
    member: MemberKey,
    members: MemberAllowlist,
}
fn credentials() -> Result<Credentials, TestError> {
    let certificate =
        rcgen::generate_simple_self_signed(vec!["standalone-client.test".to_owned()])?;
    let chain = vec![certificate.cert.der().to_vec()];
    let member = MemberKey::from_pkcs8(&MemberKey::generate_pkcs8()?)?;
    Ok(Credentials {
        client: ClientTls::from_der_roots(&chain)?,
        server: ServerTls::from_der(&chain, &certificate.signing_key.serialize_der())?,
        members: MemberAllowlist::new(&[member.public_key()])?,
        member,
    })
}
async fn rebind(addresses: Vec<SocketAddr>) -> io::Result<()> {
    timeout(Duration::from_secs(1), async {
        loop {
            let mut sockets = Vec::new();
            let mut okay = true;
            for a in &addresses {
                match UdpSocket::bind(a).await {
                    Ok(v) => sockets.push(v),
                    Err(_) => {
                        okay = false;
                        break;
                    }
                }
            }
            if okay {
                return Ok(());
            }
            drop(sockets);
            sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .map_err(|_| invalid("owned UDP socket leaked"))?
}

#[derive(Default)]
struct Native {
    outgoing: VecDeque<Vec<u8>>,
    received: Vec<Vec<u8>>,
    reads: usize,
    blocked: bool,
    fail: bool,
}
#[derive(Clone)]
struct Device {
    layer: PacketLayer,
    state: Arc<Mutex<Native>>,
}
impl Device {
    fn new(layer: PacketLayer) -> Self {
        Self {
            layer,
            state: Arc::new(Mutex::new(Native::default())),
        }
    }
    fn change<T>(&self, f: impl FnOnce(&mut Native) -> T) -> io::Result<T> {
        let mut state = self.state.lock().map_err(|_| invalid("test mutex"))?;
        Ok(f(&mut state))
    }
}
impl PacketDevice for Device {
    type Error = io::Error;
    fn layer(&self) -> PacketLayer {
        self.layer
    }
    fn receive(&mut self, out: &mut [u8]) -> io::Result<Option<usize>> {
        self.change(|s| {
            s.outgoing.pop_front().map(|p| {
                out[..p.len()].copy_from_slice(&p);
                s.reads += 1;
                p.len()
            })
        })
    }
    fn transmit(&mut self, p: &[u8]) -> io::Result<()> {
        self.change(|s| {
            if s.fail {
                Err(io::Error::from_raw_os_error(1))
            } else if s.blocked {
                Err(io::ErrorKind::WouldBlock.into())
            } else {
                s.received.push(p.to_vec());
                Ok(())
            }
        })?
    }
}
fn packet(layer: PacketLayer, seed: u8) -> Vec<u8> {
    let mut p = vec![seed; 1500];
    match layer {
        PacketLayer::Ip => {
            p[0] = 0x45;
            p[2..4].copy_from_slice(&1500u16.to_be_bytes());
        }
        PacketLayer::Ethernet => p[12..14].copy_from_slice(&0x88b5u16.to_be_bytes()),
    };
    p
}
async fn sessions(
    c: ConnectionConfig,
    ipv6: bool,
    drain_timeout: Duration,
) -> Result<(Session, Session, Vec<SocketAddr>), TestError> {
    let (a, b, addresses) = endpoints(ipv6, c.duplex).await?;
    let credentials = credentials()?;
    let (a, b) = tokio::try_join!(
        connect(
            &credentials.client,
            "standalone-client.test",
            &credentials.member,
            bundle(1)?,
            c,
            Settings {
                transport: a,
                drain_timeout
            }
        ),
        accept(
            &credentials.server,
            &credentials.members,
            bundle(1)?,
            bundle(4)?,
            c,
            Settings {
                transport: b,
                drain_timeout
            }
        ),
    )?;
    Ok((a, b, addresses))
}
async fn received(d: &Device, n: usize) -> io::Result<()> {
    timeout(Duration::from_secs(4), async {
        while d.change(|s| s.received.len())? < n {
            sleep(Duration::from_millis(2)).await;
        }
        Ok(())
    })
    .await
    .map_err(|_| invalid("test delivery timeout"))?
}
#[tokio::test]
async fn genuine_eight_profiles_transfer_and_confirm_native_then_carrier() -> TestResult {
    for duplex in [Duplex::Full, Duplex::Half] {
        for layer in [PacketLayer::Ip, PacketLayer::Ethernet] {
            for compression in [crate::Compression::None, crate::Compression::Lz4IfSmaller] {
                let c = ConnectionConfig {
                    layer,
                    compression,
                    ..config(duplex)
                };
                let (a, b, addresses) = sessions(
                    c,
                    compression == crate::Compression::None,
                    Duration::from_secs(5),
                )
                .await?;
                assert_eq!(a.binding(), b.binding());
                let da = Device::new(layer);
                let db = Device::new(layer);
                let pa = packet(layer, 17);
                let pb = packet(layer, 31);
                da.change(|s| s.outgoing.push_back(pa.clone()))?;
                db.change(|s| s.outgoing.push_back(pb.clone()))?;
                let (ha, ra) = a.into_run(da.clone())?;
                let (hb, rb) = b.into_run(db.clone())?;
                let mut ja = tokio::spawn(ra);
                let mut jb = tokio::spawn(rb);
                received(&da, 1).await?;
                received(&db, 1).await?;
                assert_eq!(da.change(|s| s.received.clone())?, vec![pb]);
                assert_eq!(db.change(|s| s.received.clone())?, vec![pa]);
                assert_eq!(ha.request_drain()?, Acceptance::Accepted);
                assert_eq!(ha.request_drain()?, Acceptance::AlreadyAccepted);
                assert!(ha.snapshot()?.terminal.is_none());
                // The server finishes from peer stop only: no fabricated local acceptance.
                let mut a_done = false;
                let mut b_done = false;
                let joined = timeout(Duration::from_secs(6), async {
                    let a = (&mut ja).await;
                    a_done = true;
                    let b = (&mut jb).await;
                    b_done = true;
                    Ok::<_, TestError>((a??, b??))
                })
                .await;
                let (a, b) = match joined {
                    Ok(result) => result?,
                    Err(_) => {
                        let evidence = format!(
                            "native matrix join timeout: {duplex:?}/{layer:?}/{compression:?}; left={:?}; right={:?}; joins=({a_done},{b_done})",
                            ha.snapshot()?,
                            hb.snapshot()?
                        );
                        ja.abort();
                        jb.abort();
                        if !a_done {
                            let _ = ja.await;
                        }
                        if !b_done {
                            let _ = jb.await;
                        }
                        rebind(addresses).await?;
                        return Err(evidence.into());
                    }
                };
                assert_eq!(a.local, b.peer);
                assert_eq!(a.peer, b.local);
                assert_eq!(a.local.packets, 1);
                assert!(matches!(
                    ha.snapshot()?.terminal,
                    Some(Terminal::Closed { .. })
                ));
                assert!(!hb.snapshot()?.drain_accepted);
                assert!(matches!(
                    hb.snapshot()?.terminal,
                    Some(Terminal::Closed { .. })
                ));
                assert_eq!(
                    ha.request_drain().err().map(|e| e.kind()),
                    Some(io::ErrorKind::BrokenPipe)
                );
                rebind(addresses).await?;
            }
        }
    }
    Ok(())
}
#[tokio::test]
async fn unpolled_and_pending_runner_cancellation_releases_original_sockets() -> TestResult {
    for poll in [false, true] {
        let (a, b, addresses) =
            sessions(config(Duplex::Half), false, Duration::from_secs(5)).await?;
        let (handle, run) = a.into_run(Device::new(PacketLayer::Ip))?;
        if poll {
            let job = tokio::spawn(run);
            sleep(Duration::from_millis(5)).await;
            job.abort();
            assert!(job.await.is_err());
        } else {
            drop(run);
        }
        assert_eq!(handle.snapshot()?.terminal, Some(Terminal::Cancelled));
        assert!(handle.request_drain().is_err());
        drop(b);
        rebind(addresses).await?;
    }
    Ok(())
}
#[tokio::test]
async fn actual_native_failure_preserves_errno_and_retained_progress() -> TestResult {
    let (a, b, addresses) = sessions(config(Duplex::Full), false, Duration::from_secs(5)).await?;
    let da = Device::new(PacketLayer::Ip);
    let db = Device::new(PacketLayer::Ip);
    da.change(|s| s.outgoing.push_back(packet(PacketLayer::Ip, 5)))?;
    db.change(|s| s.fail = true)?;
    let (_ha, ra) = a.into_run(da)?;
    let (hb, rb) = b.into_run(db)?;
    let ja = tokio::spawn(ra);
    let result = timeout(Duration::from_secs(3), rb)
        .await?
        .err()
        .ok_or("native write unexpectedly succeeded")?;
    assert_eq!(result.reason.raw_os_error(), Some(1));
    let Some(Terminal::Failed { error, progress }) = hb.snapshot()?.terminal else {
        return Err("missing actual failure".into());
    };
    assert_eq!(error.raw_os_error, Some(1));
    assert_eq!(progress.pending_native_packets, 1);
    assert_eq!(progress.native_confirmed, 0);
    ja.abort();
    let _ = ja.await;
    rebind(addresses).await?;
    Ok(())
}
#[tokio::test]
async fn blocked_native_retains_request_and_reverse_progress_until_original_deadline() -> TestResult
{
    let (a, b, addresses) =
        sessions(config(Duplex::Half), false, Duration::from_millis(200)).await?;
    let da = Device::new(PacketLayer::Ip);
    let db = Device::new(PacketLayer::Ip);
    da.change(|s| s.outgoing.push_back(packet(PacketLayer::Ip, 5)))?;
    db.change(|s| {
        s.outgoing.push_back(packet(PacketLayer::Ip, 7));
        s.blocked = true;
    })?;
    let (ha, ra) = a.into_run(da.clone())?;
    let (hb, rb) = b.into_run(db.clone())?;
    let ja = tokio::spawn(ra);
    let jb = tokio::spawn(rb);
    received(&da, 1).await?;
    assert_eq!(db.change(|s| s.received.len())?, 0);
    ha.request_drain()?;
    hb.request_drain()?;
    sleep(Duration::from_millis(20)).await;
    assert!(ha.snapshot()?.terminal.is_none());
    assert!(hb.snapshot()?.terminal.is_none());
    assert!(timeout(Duration::from_secs(1), ja).await??.is_err());
    assert!(timeout(Duration::from_secs(1), jb).await??.is_err());
    assert!(matches!(
        ha.snapshot()?.terminal,
        Some(Terminal::Failed { .. })
    ));
    assert!(matches!(
        hb.snapshot()?.terminal,
        Some(Terminal::Failed { .. })
    ));
    rebind(addresses).await?;
    Ok(())
}
#[tokio::test]
async fn accepted_before_first_poll_keeps_original_timestamp() -> TestResult {
    let (a, b, addresses) = sessions(config(Duplex::Full), false, Duration::from_millis(1)).await?;
    let (ha, ra) = a.into_run(Device::new(PacketLayer::Ip))?;
    ha.request_drain()?;
    sleep(Duration::from_millis(5)).await;
    assert_eq!(ha.request_drain()?, Acceptance::AlreadyAccepted);
    let error = ra
        .await
        .err()
        .ok_or("expired request unexpectedly succeeded")?;
    assert_eq!(error.reason.kind(), io::ErrorKind::TimedOut);
    assert!(matches!(
        ha.snapshot()?.terminal,
        Some(Terminal::Failed { .. })
    ));
    drop(b);
    rebind(addresses).await?;
    Ok(())
}
#[test]
fn bounded_diagnostics_preserve_utf8_errno_and_strict_schema() -> TestResult {
    let e = Failure::from_error(&io::Error::other("界".repeat(600)));
    assert!(e.diagnostic.len() <= 512);
    assert_eq!(e.diagnostic.len() % 3, 0);
    let mut v = serde_json::to_value(e)?;
    v["diagnostic"] = serde_json::Value::String("a".repeat(513));
    assert!(serde_json::from_value::<Failure>(v).is_err());
    let e = Failure::from_error(&io::Error::from_raw_os_error(1));
    assert_eq!(e.raw_os_error, Some(1));
    Ok(())
}
#[tokio::test]
async fn factory_profile_identity_admission_certificate_and_lane_failures_are_bounded() -> TestResult
{
    for mutation in 0..5 {
        let c = credentials()?;
        let cfg = ConnectionConfig {
            handshake_timeout: Duration::from_millis(250),
            ..config(Duplex::Half)
        };
        let (a, b, addresses) = endpoints(false, cfg.duplex).await?;
        let a = Settings {
            transport: a,
            drain_timeout: Duration::from_secs(5),
        };
        let mut b = Settings {
            transport: b,
            drain_timeout: Duration::from_secs(5),
        };
        let stranger = MemberKey::from_pkcs8(&MemberKey::generate_pkcs8()?)?;
        let forbidden = MemberAllowlist::new(&[stranger.public_key()])?;
        if mutation == 0 {
            b.drain_timeout = Duration::from_secs(4);
        }
        if mutation == 4 {
            b.transport
                .reverse
                .as_mut()
                .ok_or("reverse")?
                .peer
                .set_port(1);
        }
        let start = Instant::now();
        let (left, right) = tokio::join!(
            connect(
                &c.client,
                if mutation == 3 {
                    "wrong.test"
                } else {
                    "standalone-client.test"
                },
                &c.member,
                bundle(1)?,
                cfg,
                a
            ),
            accept(
                &c.server,
                if mutation == 2 {
                    &forbidden
                } else {
                    &c.members
                },
                bundle(if mutation == 1 { 7 } else { 1 })?,
                bundle(4)?,
                cfg,
                b
            ),
        );
        assert!(left.is_err() && right.is_err(), "mutation {mutation}");
        assert!(start.elapsed() < Duration::from_millis(800));
        rebind(addresses).await?;
    }
    Ok(())
}
#[tokio::test]
async fn native_prebind_cookie_and_factory_cancellation_release_ownership() -> TestResult {
    let c = credentials()?;
    let cfg = config(Duplex::Half);
    let (a, b, addresses) = endpoints(false, cfg.duplex).await?;
    let a = Settings {
        transport: a,
        drain_timeout: Duration::from_secs(5),
    };
    let b = Settings {
        transport: b,
        drain_timeout: Duration::from_secs(5),
    };
    assert!(
        accept(&c.server, &c.members, bundle(1)?, bundle(1)?, cfg, b)
            .await
            .is_err()
    );
    let occupied = UdpSocket::bind(a.transport.reverse.ok_or("reverse")?.local).await?;
    assert!(
        connect(
            &c.client,
            "standalone-client.test",
            &c.member,
            bundle(1)?,
            cfg,
            a
        )
        .await
        .is_err()
    );
    drop(UdpSocket::bind(a.transport.forward.local).await?);
    drop(occupied);
    // Merely creating an unpolled factory does not bind a socket.
    drop(connect(
        &c.client,
        "standalone-client.test",
        &c.member,
        bundle(1)?,
        cfg,
        a,
    ));
    rebind(addresses.clone()).await?;
    let task = tokio::spawn(async move {
        connect(
            &c.client,
            "standalone-client.test",
            &c.member,
            bundle(1)?,
            cfg,
            a,
        )
        .await
    });
    sleep(Duration::from_millis(20)).await;
    task.abort();
    assert!(task.await.is_err());
    rebind(addresses).await?;
    Ok(())
}
#[tokio::test]
async fn dropping_all_handles_does_not_cancel_the_retained_runner() -> TestResult {
    let (a, b, addresses) = sessions(config(Duplex::Full), false, Duration::from_secs(5)).await?;
    let (ha, ra) = a.into_run(Device::new(PacketLayer::Ip))?;
    let (hb, rb) = b.into_run(Device::new(PacketLayer::Ip))?;
    drop(ha);
    let ja = tokio::spawn(ra);
    let jb = tokio::spawn(rb);
    sleep(Duration::from_millis(20)).await;
    assert!(!ja.is_finished());
    hb.request_drain()?;
    timeout(Duration::from_secs(6), async {
        ja.await??;
        jb.await??;
        Ok::<_, TestError>(())
    })
    .await??;
    rebind(addresses).await?;
    Ok(())
}
#[tokio::test]
async fn legacy_digest_is_pinned_and_native_timeout_has_a_distinct_domain() -> TestResult {
    let a = super::super::Settings {
        forward: Endpoints {
            local: "127.0.0.1:24000".parse()?,
            peer: "127.0.0.1:24001".parse()?,
        },
        reverse: None,
        protection: carrier::Protection::ChaCha20Poly1305,
        path_mtu: 1200,
        authenticated_lease: Duration::from_secs(3600),
    };
    let c = config(Duplex::Full);
    let old = super::super::profiles(c, a, true)?;
    let digest = old.first.session_config()?.digest.0;
    assert_eq!(
        digest,
        [
            14, 225, 54, 163, 142, 29, 83, 176, 76, 128, 12, 38, 6, 77, 183, 131, 137, 48, 66, 74,
            220, 167, 123, 213, 108, 144, 235, 45, 194, 179, 27, 153
        ]
    );
    for timeout in [
        Duration::ZERO,
        Duration::from_nanos(1_000_001),
        Duration::from_secs(121),
    ] {
        assert!(
            runtime_config(
                c,
                Settings {
                    transport: a,
                    drain_timeout: timeout
                }
            )
            .is_err()
        );
    }
    let first = profiles(
        c,
        Settings {
            transport: a,
            drain_timeout: Duration::from_secs(5),
        },
        true,
    )?;
    let second = profiles(
        c,
        Settings {
            transport: a,
            drain_timeout: Duration::from_secs(4),
        },
        true,
    )?;
    assert_ne!(old.first.session_config()?, first.first.session_config()?);
    assert_ne!(
        first.first.session_config()?,
        second.first.session_config()?
    );
    Ok(())
}
#[cfg(unix)]
#[tokio::test]
async fn actual_private_socket_acceptance_terminal_and_five_second_local_only_grace() -> TestResult
{
    use crate::local as api;
    use std::os::unix::fs::DirBuilderExt;
    struct Directory(std::path::PathBuf);
    impl Drop for Directory {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    let directory = Directory(
        std::env::temp_dir().join(format!("l2t-native-drain-client-{}", std::process::id())),
    );
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&directory.0)?;
    let path = directory.0.join("api.sock");
    let server = api::Server::bind(&path)?;
    let (a, b, addresses) = sessions(config(Duplex::Half), false, Duration::from_secs(5)).await?;
    let da = Device::new(PacketLayer::Ip);
    let db = Device::new(PacketLayer::Ip);
    da.change(|s| s.outgoing.push_back(packet(PacketLayer::Ip, 17)))?;
    db.change(|s| s.blocked = true)?;
    let (ha, ra) = a.into_run(da.clone())?;
    // Record the genuine native future's completion at its source, not after
    // waiting for the remote runner or a later status poll. The original
    // completion owner and actual result remain unchanged.
    let (finished, observed) = tokio::sync::oneshot::channel();
    let Run { future, completion } = ra;
    let ra = Run {
        future: Box::pin(async move {
            let result = future.await;
            let _ = finished.send(Instant::now());
            result
        }),
        completion,
    };
    let (hb, rb) = b.into_run(db.clone())?;
    let mut ja = tokio::spawn(serve(
        ra,
        ha.clone(),
        crate::Compression::Lz4IfSmaller,
        Some(server),
        Duration::ZERO,
        Duration::from_secs(5),
    ));
    let mut jb = tokio::spawn(rb);
    timeout(Duration::from_secs(1), async {
        while da.change(|s| s.reads)? == 0 {
            sleep(Duration::from_millis(1)).await;
        }
        Ok::<_, io::Error>(())
    })
    .await??;
    let request = |action| api::Request {
        version: api::VERSION,
        action,
    };
    let first = api::request(&path, &request(api::Action::DrainOpenVpn {})).await?;
    assert!(first.ok);
    assert_eq!(first.code, "accepted");
    let state = first
        .state
        .and_then(|s| s.openvpn_drain)
        .ok_or("native state")?;
    assert!(state.drain_accepted && state.terminal.is_none());
    assert_eq!(
        api::request(&path, &request(api::Action::DrainOpenVpn {}))
            .await?
            .code,
        "already_accepted"
    );
    assert_eq!(
        api::request(&path, &request(api::Action::DrainProxy {}))
            .await?
            .code,
        "unsupported"
    );
    assert_eq!(
        api::request(
            &path,
            &request(api::Action::SwitchCompression {
                compression: api::Compression::Off
            })
        )
        .await?
        .code,
        "unsupported"
    );
    db.change(|s| s.blocked = false)?;
    // One existing six-second network bound covers both actual completions.
    let network_deadline = Instant::now() + Duration::from_secs(6);
    let terminal_recorded = tokio::time::timeout_at(network_deadline, observed)
        .await
        .map_err(|e| {
            format!(
                "local network completion: {e}; local={:?}; peer={:?}",
                ha.snapshot(),
                hb.snapshot()
            )
        })??;
    let status = api::request(&path, &request(api::Action::Status {})).await?;
    assert!(matches!(
        status
            .state
            .and_then(|s| s.openvpn_drain)
            .and_then(|s| s.terminal),
        Some(Terminal::Closed { .. })
    ));
    let closed = api::request(&path, &request(api::Action::DrainOpenVpn {})).await?;
    assert!(!closed.ok);
    assert_eq!(closed.code, "closed");
    tokio::time::timeout_at(network_deadline, &mut jb)
        .await
        .map_err(|e| {
            format!(
                "peer network completion: {e}; local={:?}; peer={:?}",
                ha.snapshot(),
                hb.snapshot()
            )
        })???;
    // Network owners are gone during local grace; all original UDP tuples can rebind.
    rebind(addresses).await?;
    assert!(!ja.is_finished());
    tokio::time::timeout_at(terminal_recorded + Duration::from_secs(6), &mut ja)
        .await
        .map_err(|e| {
            format!(
                "local-only grace completion after {:?}: {e}; local={:?}",
                terminal_recorded.elapsed(),
                ha.snapshot()
            )
        })???;
    assert!(terminal_recorded.elapsed() >= Duration::from_secs(5));
    assert!(!path.exists());
    Ok(())
}
#[cfg(unix)]
#[tokio::test]
async fn frontend_actual_failure_returns_errno_and_no_false_success_or_network_grace() -> TestResult
{
    let (a, b, addresses) = sessions(config(Duplex::Full), false, Duration::from_secs(5)).await?;
    let da = Device::new(PacketLayer::Ip);
    let db = Device::new(PacketLayer::Ip);
    da.change(|s| s.outgoing.push_back(packet(PacketLayer::Ip, 5)))?;
    db.change(|s| s.fail = true)?;
    let (_ha, ra) = a.into_run(da)?;
    let (hb, rb) = b.into_run(db)?;
    let ja = tokio::spawn(ra);
    let error = timeout(
        Duration::from_secs(2),
        serve(
            rb,
            hb.clone(),
            crate::Compression::None,
            None,
            Duration::ZERO,
            Duration::from_secs(5),
        ),
    )
    .await?
    .err()
    .ok_or("frontend failure falsely succeeded")?;
    assert_eq!(error.raw_os_error(), Some(1));
    assert!(matches!(
        hb.snapshot()?.terminal,
        Some(Terminal::Failed { .. })
    ));
    ja.abort();
    let _ = ja.await;
    rebind(addresses).await?;
    Ok(())
}
#[tokio::test]
async fn wrong_native_layer_fails_before_device_reads_and_releases_session() -> TestResult {
    let (a, b, addresses) = sessions(config(Duplex::Full), false, Duration::from_secs(5)).await?;
    let device = Device::new(PacketLayer::Ethernet);
    assert!(a.into_run(device.clone()).is_err());
    assert_eq!(device.change(|s| s.reads)?, 0);
    drop(b);
    rebind(addresses).await?;
    Ok(())
}
