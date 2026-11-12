use super::*;
use crate::{Compression, PacketLayer};
use std::time::Duration;
use std::{
    collections::VecDeque,
    sync::{Arc, Mutex},
};
use tokio::time::Instant;
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
    Settings::from_json(&serde_json::to_vec(&policy_json())?)
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
                "l2t-measured-proxy-{}-{}",
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
            config.fixed.timeouts.shutdown = value;
            // Preserve the original 100ms network deadline with an explicit
            // authenticated pacing policy: 32 slots at 512/s + 4ms polling
            // reserves 66.5ms; the default 256/s needs 129ms and is invalid.
            config.fixed.control_rate = 512;
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
                .is_none_or(|s| s.runtime.transparent_admitted_packets != 1)
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
            let ta = tokio::spawn(crate::cli::serve_measured_for_test(
                a.run(da, ca),
                ha.clone(),
                duplex,
                digest,
                Some(server),
                Duration::from_millis(200),
            ));
            let tb = tokio::spawn(b.run(db.clone(), cb));
            admitted(&ha).await?;
            let observed = snapshot(query(&path, Action::Status {}).await?)?
                .measured
                .ok_or("measured status missing")?;
            assert_eq!(
                observed.capabilities.effective,
                Some(Profile::MeasuredRelayV1)
            );
            assert_eq!(
                observed.capabilities.effective_carrier,
                Some(Carrier::TcpTls)
            );
            assert!(!observed.capabilities.native_window_qualified);
            assert!(observed.aggregate.is_some());
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
        config.fixed.timeouts.shutdown = Duration::from_millis(100);
        assert_eq!(config.fixed.control_rate, 256);
        let failure = config
            .validate()
            .err()
            .ok_or("invalid short policy accepted")?;
        assert_eq!(failure.kind(), io::ErrorKind::InvalidData);
        assert_eq!(
            failure.to_string(),
            "proxy deadlines cannot service configured control rate"
        );
        config.fixed.control_rate = 512;
        config.validate()?;
        assert_eq!(config.fixed.timeouts.shutdown, Duration::from_millis(100));
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
        let ta = tokio::spawn(crate::cli::serve_measured_for_test(
            a.run(da, ca),
            ha.clone(),
            Duplex::Half,
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
        assert_eq!(a.config().fixed.duplex, duplex);
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
        assert_eq!(
            hb.status().map(|s| s.runtime.phase),
            Some(l2tunnel_runtime::proxy::Phase::Closed)
        );
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
            client_policy.fixed.channels = 7;
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
        proxy::within(Instant::now() - Duration::from_millis(1), async { Ok(()) })
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

fn policy_json() -> serde_json::Value {
    serde_json::json!({
        "version":1,"profile":"measured-relay-v1",
        "fixed":{"version":1,"channels":16,"time_wait_reset":"maintained","routes":[]},
        "allocation":{"target":{
            "initial":{"bytes":32768,"records":32},"minimum":{"bytes":2048,"records":1},
            "session_cap":{"bytes":1048576,"records":1024},"per_flow_cap":{"bytes":65536,"records":64},
            "policy_cap":{"bytes":1048576,"records":1024},"queue_allowance_bytes":65536,
            "queue_delay_target_micros":5000,"many_flow_step":{"bytes":2048,"records":1},
            "few_flow_threshold":4,"max_flows":16,"bootstrap_rtt_micros":1000,"recovery_rtts":2
        },"minimum_per_flow":{"bytes":2048,"records":1}},
        "ownership":{"pending_ttl_micros":20000,"probe_interval_micros":10000,"probe_timeout_micros":30000,
            "handoff_timeout_micros":50000,"emission_interval_micros":10000,"max_records_per_interval":8},
        "observation":{"report_interval_micros":10000,"sample_ttl_micros":40000,"demand_idle_micros":20000,
            "rate_interval_micros":10000,"rate_bins":4},
        "service":{"report_work_per_turn":4,"admission_work_per_turn":4,"callback_work_per_turn":4,
            "plan_interval_micros":10000,"status_interval_micros":20000}
    })
}

#[test]
fn strict_measured_policy_requires_and_bounds_every_nested_field() -> TestResult {
    fn visit(
        value: &serde_json::Value,
        root: &serde_json::Value,
        path: &mut Vec<String>,
    ) -> TestResult {
        if let Some(object) = value.as_object() {
            for key in object.keys() {
                let mut changed = root.clone();
                let mut parent = &mut changed;
                for part in path.iter() {
                    parent = &mut parent[part];
                }
                parent.as_object_mut().ok_or("object")?.remove(key);
                assert!(
                    Settings::from_json(&serde_json::to_vec(&changed)?).is_err(),
                    "missing {path:?}/{key}"
                );
            }
            let original = serde_json::to_string(value)?;
            let first = object.iter().next().ok_or("empty object")?;
            let duplicate = format!(
                "{{{}:{},{}",
                serde_json::to_string(first.0)?,
                serde_json::to_string(first.1)?,
                &original[1..]
            );
            let unknown = format!("{{\"unexpected\":0,{}", &original[1..]);
            for replacement in [duplicate, unknown] {
                let text = serde_json::to_string(root)?.replacen(&original, &replacement, 1);
                assert!(
                    Settings::from_json(text.as_bytes()).is_err(),
                    "accepted duplicate/unknown at {path:?}"
                );
            }
            for (key, child) in object {
                path.push(key.clone());
                visit(child, root, path)?;
                path.pop();
            }
        } else if value.is_number() {
            for bad in [
                serde_json::json!(-1),
                serde_json::json!(1.5),
                serde_json::json!("18446744073709551616"),
            ] {
                let mut changed = root.clone();
                let mut slot = &mut changed;
                for part in path.iter() {
                    slot = &mut slot[part];
                }
                *slot = bad;
                assert!(
                    Settings::from_json(&serde_json::to_vec(&changed)?).is_err(),
                    "numeric {path:?}"
                );
            }
        }
        Ok(())
    }
    let root = policy_json();
    visit(&root, &root, &mut Vec::new())?;
    let mut bytes = serde_json::to_vec(&root)?;
    bytes.resize(MAX_POLICY_BYTES, b' ');
    Settings::from_json(&bytes)?;
    bytes.push(b' ');
    assert!(Settings::from_json(&bytes).is_err());
    let mut routes = root;
    routes["fixed"]["routes"] = serde_json::json!(vec![
        serde_json::json!({"source":"10.0.0.0/24","destination":"10.1.0.0/24","ports":{"first":443,"last":443}});
        257
    ]);
    assert!(Settings::from_json(&serde_json::to_vec(&routes)?).is_err());
    Ok(())
}

#[test]
fn every_numeric_measured_policy_field_is_validated_or_authenticated() -> TestResult {
    fn visit(
        value: &serde_json::Value,
        root: &serde_json::Value,
        path: &mut Vec<String>,
        binding: auth::SessionConfig,
    ) -> TestResult {
        if let Some(object) = value.as_object() {
            for (key, child) in object {
                path.push(key.clone());
                visit(child, root, path, binding)?;
                path.pop();
            }
        } else if let Some(number) = value.as_u64() {
            let mut changed = root.clone();
            let mut slot = &mut changed;
            for part in path.iter() {
                slot = &mut slot[part];
            }
            *slot = serde_json::json!(number + 1);
            if let Ok(settings) = Settings::from_json(&serde_json::to_vec(&changed)?)
                && let Ok(config) = runtime_config(connection(Duplex::Full), &settings)
            {
                assert_ne!(
                    binding,
                    runtime::session_config(&config)?,
                    "unbound {path:?}"
                );
            }
        }
        Ok(())
    }
    let root = policy_json();
    let binding =
        runtime::session_config(&runtime_config(connection(Duplex::Full), &settings()?)?)?;
    visit(&root, &root, &mut Vec::new(), binding)
}
