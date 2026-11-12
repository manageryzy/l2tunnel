use super::*;
use std::{
    collections::VecDeque,
    sync::{Arc, Mutex},
};
use tokio::time::{sleep, timeout};
type Failure = Box<dyn std::error::Error + Send + Sync>;
type TestResult = Result<(), Failure>;
fn connection(duplex: Duplex) -> ConnectionConfig {
    ConnectionConfig {
        layer: PacketLayer::Ip,
        duplex,
        max_packet: 1600,
        compression: Compression::None,
        handshake_timeout: Duration::from_secs(3),
    }
}
fn settings() -> io::Result<Settings> {
    Ok(Settings::new(RoutePolicy::new(Vec::new())?))
}
struct Credentials {
    client: ClientTls,
    server: ServerTls,
    member: MemberKey,
    allow: MemberAllowlist,
}
fn credentials() -> Result<Credentials, Failure> {
    let cert = rcgen::generate_simple_self_signed(vec!["proxy-client.test".into()])?;
    let chain = vec![cert.cert.der().to_vec()];
    let member = MemberKey::from_pkcs8(&MemberKey::generate_pkcs8()?)?;
    Ok(Credentials {
        client: ClientTls::from_der_roots(&chain)?,
        server: ServerTls::from_der(&chain, &cert.signing_key.serialize_der())?,
        allow: MemberAllowlist::new(&[member.public_key()])?,
        member,
    })
}

#[test]
fn required_policy_fields_and_authoritative_defaults() -> io::Result<()> {
    let settings = Settings::from_json(
        br#"{"version":1,"channels":16,"time_wait_reset":"maintained","routes":[]}"#,
    )?;
    assert_eq!(settings, Settings::new(RoutePolicy::new(Vec::new())?));
    assert!(Settings::from_json(br#"{"version":1,"routes":[]}"#).is_err());
    Ok(())
}

#[test]
fn strict_policy_rejects_unknown_missing_duplicate_and_excessive_fields() -> TestResult {
    let base = serde_json::json!({"version":1,"channels":16,"time_wait_reset":"maintained","routes":[{"source":"10.0.0.0/24","destination":"10.1.0.0/24","ports":{"first":443,"last":443}}]});
    for (field, value) in [
        ("version", serde_json::json!(2)),
        ("channels", serde_json::json!(0)),
        ("channels", serde_json::json!(257)),
        ("time_wait_reset", serde_json::json!("automatic")),
        ("unknown", serde_json::json!(true)),
    ] {
        let mut changed = base.clone();
        changed[field] = value;
        assert!(Settings::from_json(&serde_json::to_vec(&changed)?).is_err());
    }
    for text in [
        "10.0.0.1/24",
        "10.0.0.0/33",
        "10.0.0.0",
        "10.0.0.0/24 ",
        "localhost/24",
        "[::]/0",
        "::%1/0",
        "::/129",
    ] {
        let mut changed = base.clone();
        changed["routes"][0]["source"] = serde_json::json!(text);
        assert!(Settings::from_json(&serde_json::to_vec(&changed)?).is_err());
    }
    for (key, value) in [("first", 0), ("last", 442), ("last", 65536)] {
        let mut changed = base.clone();
        changed["routes"][0]["ports"][key] = serde_json::json!(value);
        assert!(Settings::from_json(&serde_json::to_vec(&changed)?).is_err());
    }
    let mut mixed = base.clone();
    mixed["routes"][0]["destination"] = serde_json::json!("fd00::/64");
    assert!(Settings::from_json(&serde_json::to_vec(&mixed)?).is_err());
    let mut unknown = base.clone();
    unknown["routes"][0]["ports"]["extra"] = serde_json::json!(0);
    assert!(Settings::from_json(&serde_json::to_vec(&unknown)?).is_err());
    let repeated = vec![base["routes"][0].clone(); 257];
    let mut large = base.clone();
    large["routes"] = serde_json::json!(repeated);
    assert!(Settings::from_json(&serde_json::to_vec(&large)?).is_err());
    large["routes"] = serde_json::json!(vec![base["routes"][0].clone(); 256]);
    assert_eq!(
        Settings::from_json(&serde_json::to_vec(&large)?)?
            .routes
            .rules()
            .len(),
        1
    );
    assert!(Settings::from_json(&vec![b' '; MAX_POLICY_BYTES + 1]).is_err());
    assert!(Settings::from_json(br#"{"version":1,"version":1,"channels":16,"time_wait_reset":"maintained","routes":[]}"#).is_err());
    Ok(())
}
#[test]
fn canonical_fixed_binding_and_incompatible_profiles() -> TestResult {
    let a=Settings::from_json(br#"{"version":1,"channels":4,"time_wait_reset":"maintained","routes":[{"source":"fd00::/64","destination":"fd01::/64","ports":{"first":1,"last":443}},{"source":"10.0.0.0/24","destination":"10.1.0.0/24","ports":{"first":443,"last":443}}]}"#)?;
    let mut b = a.clone();
    let mut rules = b.routes.rules().to_vec();
    rules.reverse();
    rules.push(rules[0]);
    b.routes = RoutePolicy::new(rules)?;
    let base = connection(Duplex::Half);
    let binding = runtime::session_config(&runtime_config(base, &a)?)?;
    assert_eq!(
        binding,
        runtime::session_config(&runtime_config(base, &b)?)?
    );
    assert_ne!(binding, base.session()?);
    for changed in [
        ConnectionConfig {
            layer: PacketLayer::Ethernet,
            ..base
        },
        ConnectionConfig {
            compression: Compression::Lz4IfSmaller,
            ..base
        },
        ConnectionConfig {
            handshake_timeout: Duration::ZERO,
            ..base
        },
        ConnectionConfig {
            handshake_timeout: Duration::from_secs(121),
            ..base
        },
        ConnectionConfig {
            max_packet: 1279,
            ..base
        },
    ] {
        assert!(runtime_config(changed, &a).is_err());
    }
    b.channels = 5;
    assert_ne!(
        binding,
        runtime::session_config(&runtime_config(base, &b)?)?
    );
    b = a.clone();
    b.time_wait_reset_policy = TimeWaitResetPolicy::IgnoreInTimeWait;
    assert_ne!(
        binding,
        runtime::session_config(&runtime_config(base, &b)?)?
    );
    b.channels = 257;
    assert!(runtime_config(base, &b).is_err());
    for target in [
        "0.0.0.0:1",
        "127.0.0.1:0",
        "224.0.0.1:42",
        "255.255.255.255:42",
        "[::]:1",
        "[ff00::1]:42",
    ] {
        assert!(remote(target.parse()?).is_err());
    }
    Ok(())
}

#[test]
fn maximum_mixed_ipv6_literal_has_canonical_policy_identity() -> TestResult {
    let text = "2001:db8:ffff:ffff:ffff:ffff:192.168.255.255/128";
    assert_eq!(text.len(), 48);
    // The maximum textual IPv6 address has six four-digit hex groups.
    let longest = "2001:ffff:ffff:ffff:ffff:ffff:192.168.255.255/128";
    assert_eq!(longest.len(), 49);
    let policy = serde_json::json!({"version":1,"channels":16,"time_wait_reset":"maintained","routes":[{"source":longest,"destination":longest,"ports":{"first":443,"last":443}}]});
    let settings = Settings::from_json(&serde_json::to_vec(&policy)?)?;
    let address: IpAddr = longest.split_once('/').ok_or("CIDR")?.0.parse()?;
    let canonical = format!("{address}/128");
    let mut other = policy;
    other["routes"][0]["source"] = serde_json::json!(canonical);
    other["routes"][0]["destination"] = serde_json::json!(canonical);
    let normalized = Settings::from_json(&serde_json::to_vec(&other)?)?;
    assert_eq!(settings, normalized);
    let cfg = connection(Duplex::Full);
    assert_eq!(
        runtime::session_config(&runtime_config(cfg, &settings)?)?,
        runtime::session_config(&runtime_config(cfg, &normalized)?)?
    );
    assert!(prefix(&format!("{}0", longest)).is_err());
    Ok(())
}
#[derive(Default)]
struct Queues {
    outgoing: VecDeque<Vec<u8>>,
    received: Vec<Vec<u8>>,
    reads: usize,
    blocked: bool,
}
#[derive(Clone, Default)]
struct Device(Arc<Mutex<Queues>>);
impl Device {
    fn change<T>(&self, f: impl FnOnce(&mut Queues) -> T) -> io::Result<T> {
        let mut state = self.0.lock().map_err(|_| io::Error::other("test lock"))?;
        Ok(f(&mut state))
    }
}

#[cfg(unix)]
mod local_control {
    use super::*;
    use crate::local::{self, Action, ProxySnapshot, ProxyTerminal, Request, VERSION};
    use std::os::unix::fs::DirBuilderExt;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(0);
    struct Directory(PathBuf);
    impl Directory {
        fn new() -> io::Result<Self> {
            let path = std::env::temp_dir().join(format!(
                "l2t-proxy-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::DirBuilder::new().mode(0o700).create(&path)?;
            Ok(Self(path))
        }
        fn socket(&self) -> PathBuf {
            self.0.join("api.sock")
        }
    }
    impl Drop for Directory {
        fn drop(&mut self) {
            let _cleanup = std::fs::remove_dir_all(&self.0);
        }
    }
    async fn query(path: &Path, action: Action) -> io::Result<local::Response> {
        timeout(
            Duration::from_millis(500),
            local::request(
                path,
                &Request {
                    version: VERSION,
                    action,
                },
            ),
        )
        .await
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::TimedOut,
                "local acceptance blocked on network drain",
            )
        })?
    }
    fn snapshot(response: local::Response) -> io::Result<ProxySnapshot> {
        response
            .state
            .and_then(|s| s.proxy)
            .ok_or_else(|| io::Error::other("proxy status missing"))
    }
    async fn sessions(
        duplex: Duplex,
        shutdown: Option<Duration>,
    ) -> Result<(Session, Session), Failure> {
        let c = credentials()?;
        let cfg = connection(duplex);
        let policy = settings()?;
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        if shutdown.is_none() {
            return Ok(tokio::try_join!(
                connect(
                    listener.local_addr()?,
                    &c.client,
                    "proxy-client.test",
                    &c.member,
                    cfg,
                    &policy
                ),
                accept(&listener, &c.server, &c.allow, cfg, &policy)
            )?);
        }
        // Test-only authenticated short deadline: the typed public factory keeps its production default.
        let mut config = runtime_config(cfg, &policy)?;
        if let Some(value) = shutdown {
            config.timeouts.shutdown = value;
            // Preserve the original 100ms network deadline with an explicit
            // authenticated pacing policy: 32 slots at 512/s + 4ms polling
            // reserves 66.5ms; the default 256/s needs 129ms and is invalid.
            config.control_rate = 512;
        }
        let binding = runtime::session_config(&config)?;
        let mut lanes = Vec::new();
        for _ in 0..if duplex == Duplex::Full { 1 } else { 2 } {
            let client = TcpStream::connect(listener.local_addr()?).await?;
            let (server, _) = listener.accept().await?;
            lanes.push(tokio::try_join!(
                auth::client_connect(
                    client,
                    &c.client,
                    "proxy-client.test",
                    &c.member,
                    binding,
                    Duration::from_secs(3)
                ),
                auth::server_accept(server, &c.server, &c.allow, binding, Duration::from_secs(3))
            )?);
        }
        let (a, b) = lanes.remove(0);
        let (a, b) = if duplex == Duplex::Full {
            (
                runtime::Link::full(a, &config)?,
                runtime::Link::full(b, &config)?,
            )
        } else {
            let (a2, b2) = lanes.remove(0);
            tokio::try_join!(
                runtime::client_pair(a, a2, &config),
                runtime::server_pair(b, b2, &config)
            )?
        };
        Ok((
            Session {
                link: a,
                config: config.clone(),
            },
            Session { link: b, config },
        ))
    }
    async fn admitted(handle: &Handle) -> TestResult {
        timeout(Duration::from_secs(3), async {
            while handle
                .status()
                .is_none_or(|s| s.transparent_admitted_packets != 1)
            {
                sleep(Duration::from_millis(1)).await;
            }
        })
        .await?;
        Ok(())
    }
    async fn terminal(path: &Path) -> Result<ProxyTerminal, Failure> {
        Ok(timeout(Duration::from_secs(3), async {
            loop {
                if let Some(outcome) = snapshot(query(path, Action::Status {}).await?)?.terminal {
                    return Ok::<_, io::Error>(outcome);
                }
                sleep(Duration::from_millis(1)).await;
            }
        })
        .await??)
    }
    #[tokio::test]
    async fn actual_socket_accepts_promptly_and_reports_only_actual_run_closure() -> TestResult {
        for duplex in [Duplex::Full, Duplex::Half] {
            let (a, b) = sessions(duplex, None).await?;
            let digest = runtime::session_config(a.config())?.digest.0;
            let directory = Directory::new()?;
            let path = directory.socket();
            let server = local::Server::bind(&path)?;
            let da = Device::default();
            let db = Device::default();
            da.change(|s| s.outgoing.push_back(packet(1)))?;
            db.change(|s| s.blocked = true)?;
            let (ha, ca) = control_channel();
            let (_hb, cb) = control_channel();
            let ta = tokio::spawn(crate::cli::serve_proxy_for_test(
                a.run(da, ca),
                ha.clone(),
                digest,
                Some(server),
                Duration::from_millis(200),
            ));
            let tb = tokio::spawn(b.run(db.clone(), cb));
            admitted(&ha).await?;
            let accepted = query(&path, Action::DrainProxy {}).await?;
            assert!(accepted.ok);
            assert_eq!(accepted.code, "accepted");
            assert!(snapshot(accepted)?.terminal.is_none());
            assert!(!ta.is_finished());
            for _ in 0..3 {
                let repeated = query(&path, Action::DrainProxy {}).await?;
                assert_eq!(repeated.code, "already_accepted");
                assert!(snapshot(repeated)?.terminal.is_none());
            }
            assert!(
                query(
                    &path,
                    Action::SwitchCompression {
                        compression: local::Compression::Lz4
                    }
                )
                .await?
                .code
                    == "unsupported"
            );
            db.change(|s| s.blocked = false)?;
            let ProxyTerminal::Closed { report } = terminal(&path).await? else {
                return Err("successful run reported failure".into());
            };
            assert_eq!(report.local_transparent_packets, 1);
            assert_eq!(
                report.tls_lanes_closed,
                if duplex == Duplex::Full { 1 } else { 2 }
            );
            assert_eq!(query(&path, Action::DrainProxy {}).await?.code, "closed");
            assert!(path.exists()); // Only the finite local grace remains.
            let actual = timeout(Duration::from_secs(2), ta).await???;
            let peer = timeout(Duration::from_secs(2), tb).await???;
            assert_eq!(actual.peer_user_records, peer.local_user_records);
            assert_eq!(db.change(|s| s.received.clone())?, vec![packet(1)]);
            assert!(!path.exists());
        }
        Ok(())
    }
    #[test]
    fn original_100ms_deadline_requires_explicit_compatible_pacing() -> TestResult {
        let mut config = runtime_config(connection(Duplex::Half), &settings()?)?;
        config.timeouts.shutdown = Duration::from_millis(100);
        assert_eq!(config.control_rate, 256);
        let failure = config
            .validate()
            .err()
            .ok_or("invalid short policy accepted")?;
        assert_eq!(failure.kind(), io::ErrorKind::InvalidData);
        assert_eq!(
            failure.to_string(),
            "proxy deadlines cannot service configured control rate"
        );
        config.control_rate = 512;
        config.validate()?;
        assert_eq!(config.timeouts.shutdown, Duration::from_millis(100));
        Ok(())
    }
    #[tokio::test]
    async fn repeated_local_requests_do_not_renew_actual_network_deadline_or_fake_success()
    -> TestResult {
        let (a, b) = sessions(Duplex::Half, Some(Duration::from_millis(100))).await?;
        let digest = runtime::session_config(a.config())?.digest.0;
        let directory = Directory::new()?;
        let path = directory.socket();
        let server = local::Server::bind(&path)?;
        let da = Device::default();
        let db = Device::default();
        da.change(|s| s.outgoing.push_back(packet(1)))?;
        db.change(|s| s.blocked = true)?;
        let (ha, ca) = control_channel();
        let (_hb, cb) = control_channel();
        let ta = tokio::spawn(crate::cli::serve_proxy_for_test(
            a.run(da, ca),
            ha.clone(),
            digest,
            Some(server),
            Duration::from_millis(200),
        ));
        let tb = tokio::spawn(b.run(db.clone(), cb));
        admitted(&ha).await?;
        let began = Instant::now();
        assert_eq!(query(&path, Action::DrainProxy {}).await?.code, "accepted");
        loop {
            let response = query(&path, Action::DrainProxy {}).await?;
            if snapshot(response)?.terminal.is_some() {
                break;
            }
            assert!(
                began.elapsed() < Duration::from_millis(500),
                "retries renewed network drain"
            );
            sleep(Duration::from_millis(10)).await;
        }
        assert!(matches!(
            terminal(&path).await?,
            ProxyTerminal::Failed { .. }
        ));
        assert!(began.elapsed() >= Duration::from_millis(90));
        assert_eq!(db.change(|s| s.received.len())?, 0);
        let error = timeout(Duration::from_secs(2), ta)
            .await??
            .err()
            .ok_or("false clean result")?;
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert!(timeout(Duration::from_secs(2), tb).await??.is_err());
        assert!(!path.exists());
        Ok(())
    }
}
impl PacketDevice for Device {
    type Error = io::Error;
    fn layer(&self) -> PacketLayer {
        PacketLayer::Ip
    }
    fn receive(&mut self, out: &mut [u8]) -> io::Result<Option<usize>> {
        if out.len() < l2tunnel_device::READ_BUFFER_BYTES {
            return Err(invalid("sentinel missing"));
        }
        self.change(|s| {
            s.reads += 1;
            s.outgoing.pop_front().map(|p| {
                out[..p.len()].copy_from_slice(&p);
                p.len()
            })
        })
    }
    fn transmit(&mut self, p: &[u8]) -> io::Result<()> {
        self.change(|s| {
            if s.blocked {
                Err(io::ErrorKind::WouldBlock.into())
            } else {
                s.received.push(p.to_vec());
                Ok(())
            }
        })?
    }
}
fn packet(value: u8) -> Vec<u8> {
    let mut p = vec![value; 1600];
    p[..40].fill(0);
    p[0] = 0x60;
    p[4..6].copy_from_slice(&1560_u16.to_be_bytes());
    p[6] = 253;
    p[7] = 64;
    p[8] = 0xfd;
    p[23] = 1;
    p[24] = 0xfd;
    p[39] = 2;
    p
}
#[tokio::test]
async fn actual_client_factories_full_half_forward_and_drain_original_sessions() -> TestResult {
    for duplex in [Duplex::Full, Duplex::Half] {
        let c = credentials()?;
        let cfg = connection(duplex);
        let settings = settings()?;
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let (a, b) = tokio::try_join!(
            connect(
                listener.local_addr()?,
                &c.client,
                "proxy-client.test",
                &c.member,
                cfg,
                &settings
            ),
            accept(&listener, &c.server, &c.allow, cfg, &settings)
        )?;
        assert_eq!(a.config().duplex, duplex);
        assert_eq!(
            runtime::session_config(a.config())?,
            runtime::session_config(b.config())?
        );
        let da = Device::default();
        let db = Device::default();
        da.change(|s| s.outgoing.push_back(packet(1)))?;
        db.change(|s| s.outgoing.push_back(packet(2)))?;
        let (ha, ca) = control_channel();
        let (hb, cb) = control_channel();
        let ta = tokio::spawn(a.run(da.clone(), ca));
        let tb = tokio::spawn(b.run(db.clone(), cb));
        timeout(Duration::from_secs(3), async {
            while da.change(|s| s.received.len())? != 1 || db.change(|s| s.received.len())? != 1 {
                if ta.is_finished() || tb.is_finished() {
                    return Err(format!(
                        "prequeued native delivery stopped: client={:?}, server={:?}",
                        ha.status(),
                        hb.status()
                    )
                    .into());
                }
                sleep(Duration::from_millis(1)).await;
            }
            Ok::<_, Failure>(())
        })
        .await??;
        assert_eq!(da.change(|s| s.received.clone())?, vec![packet(2)]);
        assert_eq!(db.change(|s| s.received.clone())?, vec![packet(1)]);
        let waiter = ha.request_drain()?;
        let result = timeout(Duration::from_secs(3), waiter.wait()).await??;
        assert_eq!(result, ta.await??);
        let peer = tb.await??;
        assert_eq!(peer.local_user_records, result.peer_user_records);
        assert_eq!(peer.native_confirmed_packets, 1);
        assert_eq!(hb.status().map(|s| s.phase), Some(Phase::Closed));
    }
    Ok(())
}
#[tokio::test]
async fn factories_reject_server_member_and_exact_profile_mismatch() -> TestResult {
    for case in 0..4 {
        let c = credentials()?;
        let other = credentials()?;
        let cfg = connection(Duplex::Full);
        let mut client_policy = settings()?;
        let server_policy = settings()?;
        if case == 3 {
            client_policy.channels = 7;
        }
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let (a, b) = tokio::join!(
            connect(
                listener.local_addr()?,
                if case == 0 { &other.client } else { &c.client },
                if case == 1 {
                    "wrong.test"
                } else {
                    "proxy-client.test"
                },
                if case == 2 { &other.member } else { &c.member },
                cfg,
                &client_policy
            ),
            accept(&listener, &c.server, &c.allow, cfg, &server_policy)
        );
        assert!(a.is_err());
        assert!(b.is_err());
    }
    Ok(())
}
#[tokio::test]
async fn first_accept_and_spent_deadlines_cannot_restart() -> TestResult {
    let c = credentials()?;
    let mut cfg = connection(Duplex::Half);
    cfg.handshake_timeout = Duration::from_millis(30);
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let result = accept(&listener, &c.server, &c.allow, cfg, &settings()?).await;
    assert_eq!(
        result.err().map(|e| e.kind()),
        Some(io::ErrorKind::TimedOut)
    );
    assert!(
        within(Instant::now() - Duration::from_millis(1), async { Ok(()) })
            .await
            .is_err()
    );
    Ok(())
}
#[tokio::test]
async fn second_lane_uses_remaining_original_client_deadline() -> TestResult {
    let c = credentials()?;
    let mut cfg = connection(Duplex::Half);
    cfg.handshake_timeout = Duration::from_millis(700);
    let policy = settings()?;
    let binding = runtime::session_config(&runtime_config(cfg, &policy)?)?;
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let peer = async {
        let (stream, _) = listener.accept().await?;
        sleep(Duration::from_millis(450)).await;
        let first =
            auth::server_accept(stream, &c.server, &c.allow, binding, Duration::from_secs(2))
                .await?;
        let (second, _) = listener.accept().await?;
        sleep(Duration::from_millis(500)).await;
        drop((first, second));
        Ok::<_, Failure>(())
    };
    let client = async {
        let start = Instant::now();
        let result = connect(
            address,
            &c.client,
            "proxy-client.test",
            &c.member,
            cfg,
            &policy,
        )
        .await;
        assert_eq!(
            result.err().map(|e| e.kind()),
            Some(io::ErrorKind::TimedOut)
        );
        assert!(start.elapsed() < Duration::from_millis(950));
        Ok::<_, Failure>(())
    };
    tokio::try_join!(peer, client)?;
    Ok(())
}
#[tokio::test]
async fn independently_valid_members_cannot_form_one_half_pair() -> TestResult {
    let c = credentials()?;
    let second = MemberKey::from_pkcs8(&MemberKey::generate_pkcs8()?)?;
    let allow = MemberAllowlist::new(&[c.member.public_key(), second.public_key()])?;
    let cfg = connection(Duplex::Half);
    let policy = settings()?;
    let binding = runtime::session_config(&runtime_config(cfg, &policy)?)?;
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let peer = async {
        let first = auth::client_connect(
            TcpStream::connect(address).await?,
            &c.client,
            "proxy-client.test",
            &c.member,
            binding,
            Duration::from_secs(2),
        )
        .await?;
        let second = auth::client_connect(
            TcpStream::connect(address).await?,
            &c.client,
            "proxy-client.test",
            &second,
            binding,
            Duration::from_secs(2),
        )
        .await?;
        sleep(Duration::from_millis(20)).await;
        drop((first, second));
        Ok::<_, Failure>(())
    };
    let server = async {
        assert!(
            accept(&listener, &c.server, &allow, cfg, &policy)
                .await
                .is_err()
        );
        Ok::<_, Failure>(())
    };
    tokio::try_join!(peer, server)?;
    Ok(())
}

#[tokio::test]
async fn server_first_wait_and_second_lane_share_original_deadline() -> TestResult {
    let c = credentials()?;
    let mut cfg = connection(Duplex::Half);
    cfg.handshake_timeout = Duration::from_millis(700);
    let policy = settings()?;
    let binding = runtime::session_config(&runtime_config(cfg, &policy)?)?;
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let peer = async {
        sleep(Duration::from_millis(450)).await;
        let first = auth::client_connect(
            TcpStream::connect(address).await?,
            &c.client,
            "proxy-client.test",
            &c.member,
            binding,
            Duration::from_secs(2),
        )
        .await?;
        sleep(Duration::from_millis(500)).await;
        drop(first);
        Ok::<_, Failure>(())
    };
    let server = async {
        let start = Instant::now();
        let result = accept(&listener, &c.server, &c.allow, cfg, &policy).await;
        assert_eq!(
            result.err().map(|e| e.kind()),
            Some(io::ErrorKind::TimedOut)
        );
        assert!(start.elapsed() < Duration::from_millis(950));
        Ok::<_, Failure>(())
    };
    tokio::try_join!(peer, server)?;
    Ok(())
}

#[tokio::test]
async fn typed_session_controller_loss_is_abnormal() -> TestResult {
    let c = credentials()?;
    let cfg = connection(Duplex::Full);
    let policy = settings()?;
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let (a, _peer) = tokio::try_join!(
        connect(
            listener.local_addr()?,
            &c.client,
            "proxy-client.test",
            &c.member,
            cfg,
            &policy
        ),
        accept(&listener, &c.server, &c.allow, cfg, &policy)
    )?;
    let device = Device::default();
    let (handle, control) = control_channel();
    drop(handle);
    let result = a.run(device.clone(), control).await;
    assert_eq!(
        result.err().map(|e| e.kind()),
        Some(io::ErrorKind::BrokenPipe)
    );
    assert_eq!(device.change(|s| s.reads)?, 0);
    Ok(())
}
