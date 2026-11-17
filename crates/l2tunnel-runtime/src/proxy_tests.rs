use super::*;
use l2tunnel_auth::{
    ClientTls, MemberAllowlist, MemberKey, ServerTls, client_connect, server_accept,
};
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::{Instant, sleep, timeout};
type Failure = Box<dyn std::error::Error + Send + Sync>;
type TestResult = Result<(), Failure>;

fn config(duplex: Duplex) -> io::Result<Config> {
    Config::new(
        RuntimeConfig {
            layer: PacketLayer::Ip,
            max_packet: 1600,
            compression: Compression::None,
            queue_packets: 4,
            poll_interval: Duration::from_millis(1),
        },
        duplex,
        RoutePolicy::new(Vec::new())?,
    )
}
async fn links(config: &Config) -> Result<(Link, Link), Failure> {
    let mut lanes = authenticated(session_config(config)?, config.duplex).await?;
    let (c, s) = lanes.remove(0);
    if config.duplex == Duplex::Full {
        Ok((Link::full(c, config)?, Link::full(s, config)?))
    } else {
        let (c2, s2) = lanes.remove(0);
        Ok(tokio::try_join!(
            client_pair(c, c2, config),
            server_pair(s, s2, config)
        )?)
    }
}
async fn authenticated(
    binding: SessionConfig,
    duplex: Duplex,
) -> Result<Vec<(AuthenticatedConnection, AuthenticatedConnection)>, Failure> {
    let cert = rcgen::generate_simple_self_signed(vec!["proxy.test".into()])?;
    let chain = vec![cert.cert.der().to_vec()];
    let client_tls = ClientTls::from_der_roots(&chain)?;
    let server_tls = ServerTls::from_der(&chain, &cert.signing_key.serialize_der())?;
    let member = MemberKey::from_pkcs8(&MemberKey::generate_pkcs8()?)?;
    let allow = MemberAllowlist::new(&[member.public_key()])?;
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let mut lanes = Vec::new();
    for _ in 0..if duplex == Duplex::Half { 2 } else { 1 } {
        let client = TcpStream::connect(listener.local_addr()?).await?;
        client.set_nodelay(true)?;
        let (server, _) = listener.accept().await?;
        server.set_nodelay(true)?;
        lanes.push(tokio::try_join!(
            client_connect(
                client,
                &client_tls,
                "proxy.test",
                &member,
                binding,
                Duration::from_secs(3)
            ),
            server_accept(server, &server_tls, &allow, binding, Duration::from_secs(3))
        )?);
    }
    Ok(lanes)
}
#[derive(Default)]
struct Native {
    outgoing: VecDeque<Vec<u8>>,
    received: Vec<Vec<u8>>,
    blocked: bool,
    reads: usize,
}
#[derive(Clone, Default)]
struct Device(Arc<Mutex<Native>>);
impl Device {
    fn change<T>(&self, f: impl FnOnce(&mut Native) -> T) -> io::Result<T> {
        let mut state = self.0.lock().map_err(|_| invalid("test device lock"))?;
        Ok(f(&mut state))
    }
}
impl PacketDevice for Device {
    type Error = io::Error;
    fn layer(&self) -> PacketLayer {
        PacketLayer::Ip
    }
    fn receive(&mut self, output: &mut [u8]) -> io::Result<Option<usize>> {
        if output.len() < l2tunnel_device::READ_BUFFER_BYTES {
            return Err(invalid("native sentinel required"));
        }
        self.change(|s| {
            s.reads += 1;
            s.outgoing.pop_front().map(|p| {
                let n = p.len();
                output[..n].copy_from_slice(&p);
                n
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
    let mut b = vec![value; 100];
    b[0] = 0x60;
    b[1..4].fill(0);
    b[4..6].copy_from_slice(&60_u16.to_be_bytes());
    b[6] = 253;
    b[7] = 64;
    b[8..40].fill(0);
    b[8] = 0xfd;
    b[23] = 1;
    b[24] = 0xfd;
    b[39] = 2;
    b
}
async fn wait_forwarding(handle: &Handle) -> TestResult {
    timeout(Duration::from_secs(3), async {
        loop {
            if handle
                .status()
                .is_some_and(|s| s.phase == Phase::Forwarding)
            {
                return Ok::<_, Failure>(());
            }
            sleep(Duration::from_millis(1)).await;
        }
    })
    .await?
}
async fn received(device: &Device, n: usize) -> TestResult {
    timeout(Duration::from_secs(3), async {
        while device.change(|s| s.received.len())? < n {
            sleep(Duration::from_millis(1)).await;
        }
        Ok::<_, Failure>(())
    })
    .await?
}

#[test]
fn canonical_routes_and_checked_config() -> io::Result<()> {
    let prefix = IpPrefix::new("10.0.0.0".parse().map_err(io::Error::other)?, 24)?;
    assert!(IpPrefix::new("10.0.0.1".parse().map_err(io::Error::other)?, 24).is_err());
    let rules = RoutePolicy::new(vec![RouteRule {
        source: prefix,
        destination: prefix,
        ports: PortRange {
            first: 1,
            last: 65535,
        },
    }])?;
    let runtime = RuntimeConfig {
        layer: PacketLayer::Ip,
        max_packet: 1600,
        compression: Compression::None,
        queue_packets: 4,
        poll_interval: Duration::from_millis(1),
    };
    let mut config = Config::new(runtime, Duplex::Full, rules)?;
    let digest = session_config(&config)?;
    config.native.time_wait_reset_policy = proxy::TimeWaitResetPolicy::IgnoreInTimeWait;
    assert_ne!(digest, session_config(&config)?);
    config.relay.max_record_bytes = usize::MAX;
    assert!(config.validate().is_err());
    Ok(())
}

#[tokio::test]
async fn real_tls_both_duplex_transparent_and_exact_close() -> TestResult {
    for duplex in [Duplex::Full, Duplex::Half] {
        let cfg = config(duplex)?;
        let (a, b) = links(&cfg).await?;
        let da = Device::default();
        let db = Device::default();
        let (ha, ca) = control_channel();
        let (hb, cb) = control_channel();
        let ra = tokio::spawn(run(da.clone(), a, cfg.clone(), ca));
        let rb = tokio::spawn(run(db.clone(), b, cfg, cb));
        wait_forwarding(&ha).await?;
        wait_forwarding(&hb).await?;
        da.change(|s| s.outgoing.extend([packet(1), packet(2)]))?;
        db.change(|s| s.outgoing.push_back(packet(3)))?;
        received(&da, 1).await?;
        received(&db, 2).await?;
        let wa = ha.request_drain()?;
        let wb = hb.request_drain()?;
        let (a, b) = timeout(Duration::from_secs(3), async {
            Ok::<_, Failure>((wa.wait().await?, wb.wait().await?))
        })
        .await??;
        assert_eq!(a.local_user_records, b.peer_user_records);
        assert_eq!(b.native_confirmed_packets, 2);
        assert_eq!(
            a.tls_lanes_closed,
            if duplex == Duplex::Half { 2 } else { 1 }
        );
        assert_eq!(ra.await??, a);
        assert_eq!(rb.await??, b);
        assert_eq!(
            db.change(|s| s.received.clone())?,
            vec![packet(1), packet(2)]
        );
    }
    Ok(())
}

#[tokio::test]
async fn asymmetric_native_pressure_and_peer_only_drain_are_bounded() -> TestResult {
    for duplex in [Duplex::Full, Duplex::Half] {
        let mut cfg = config(duplex)?;
        cfg.timeouts.shutdown = Duration::from_millis(180);
        let (a, b) = links(&cfg).await?;
        let da = Device::default();
        let db = Device::default();
        db.change(|s| s.blocked = true)?;
        let (ha, ca) = control_channel();
        let (hb, cb) = control_channel();
        let ra = tokio::spawn(run(da.clone(), a, cfg.clone(), ca));
        let rb = tokio::spawn(run(db.clone(), b, cfg, cb));
        wait_forwarding(&ha).await?;
        wait_forwarding(&hb).await?;
        da.change(|s| s.outgoing.push_back(packet(7)))?;
        timeout(Duration::from_secs(2), async {
            while ha
                .status()
                .is_none_or(|s| s.transparent_admitted_packets == 0)
            {
                sleep(Duration::from_millis(1)).await;
            }
        })
        .await?;
        let started = Instant::now();
        let waiter = ha.request_drain()?;
        assert!(
            timeout(Duration::from_secs(2), waiter.wait())
                .await?
                .is_err()
        );
        assert!(started.elapsed() < Duration::from_secs(1));
        assert!(ra.await?.is_err());
        assert!(timeout(Duration::from_secs(2), rb).await??.is_err());
        assert_eq!(db.change(|s| s.received.len())?, 0);
    }
    Ok(())
}

#[tokio::test]
async fn blocked_native_releases_credit_after_own_barrier() -> TestResult {
    for duplex in [Duplex::Full, Duplex::Half] {
        let cfg = config(duplex)?;
        let (a, b) = links(&cfg).await?;
        let da = Device::default();
        let db = Device::default();
        db.change(|s| s.blocked = true)?;
        let (ha, ca) = control_channel();
        let (hb, cb) = control_channel();
        let ra = tokio::spawn(run(da.clone(), a, cfg.clone(), ca));
        let rb = tokio::spawn(run(db.clone(), b, cfg, cb));
        wait_forwarding(&ha).await?;
        wait_forwarding(&hb).await?;
        da.change(|s| s.outgoing.push_back(packet(9)))?;
        timeout(Duration::from_secs(2), async {
            while ha
                .status()
                .is_none_or(|s| s.transparent_admitted_packets == 0)
            {
                sleep(Duration::from_millis(1)).await;
            }
        })
        .await?;
        let waiter = ha.request_drain()?;
        sleep(Duration::from_millis(40)).await;
        assert_eq!(db.change(|s| s.received.len())?, 0);
        db.change(|s| s.blocked = false)?;
        let report = timeout(Duration::from_secs(3), waiter.wait()).await??;
        assert_eq!(report.local_transparent_packets, 1);
        assert_eq!(ra.await??, report);
        assert_eq!(rb.await??.native_confirmed_packets, 1);
    }
    Ok(())
}

struct HostState {
    engine: l2tunnel_raw_tcp::TcpEngine,
    start: Instant,
    blocked: bool,
}
#[derive(Clone)]
struct Host(Arc<Mutex<HostState>>);
impl Host {
    fn change<T>(&self, f: impl FnOnce(&mut HostState) -> io::Result<T>) -> io::Result<T> {
        let mut state = self.0.lock().map_err(|_| invalid("host lock"))?;
        f(&mut state)
    }
    fn new(ipv6: bool, server: bool) -> io::Result<Self> {
        let (local, peer): (std::net::SocketAddr, std::net::SocketAddr) = if ipv6 {
            (
                "[fd00:112::1]:32001".parse().map_err(io::Error::other)?,
                "[fd00:112::2]:443".parse().map_err(io::Error::other)?,
            )
        } else {
            (
                ([10, 112, 0, 1], 32001).into(),
                ([10, 112, 0, 2], 443).into(),
            )
        };
        let config = proxy::TcpIpConfig {
            local: if server { peer } else { local },
            peer: if server { local } else { peer },
            mtu: 1600,
            send_bytes: 4096,
            receive_bytes: 4096,
            packet_slots: 8,
            random_seed: if server { 59 } else { 37 },
            ack_delay_millis: 0,
            keepalive_millis: 1000,
            idle_timeout_millis: 30000,
        };
        let mut engine = l2tunnel_raw_tcp::TcpEngine::new_ip(
            config,
            if server {
                proxy::Role::Server
            } else {
                proxy::Role::Client
            },
            Millis(0),
        )
        .map_err(io::Error::other)?;
        engine
            .set_time_wait_reset_policy(proxy::TimeWaitResetPolicy::IgnoreInTimeWait)
            .map_err(io::Error::other)?;
        Ok(Self(Arc::new(Mutex::new(HostState {
            engine,
            start: Instant::now(),
            blocked: false,
        }))))
    }
}
impl PacketDevice for Host {
    type Error = io::Error;
    fn layer(&self) -> PacketLayer {
        PacketLayer::Ip
    }
    fn receive(&mut self, out: &mut [u8]) -> io::Result<Option<usize>> {
        if out.len() < l2tunnel_device::READ_BUFFER_BYTES {
            return Err(invalid("host sentinel"));
        }
        self.change(|s| {
            s.engine
                .poll(
                    Millis(
                        s.start
                            .elapsed()
                            .as_millis()
                            .try_into()
                            .map_err(io::Error::other)?,
                    ),
                    16,
                )
                .map_err(io::Error::other)?;
            Ok(s.engine.pop_packet().map(|p| {
                out[..p.len()].copy_from_slice(&p);
                p.len()
            }))
        })
    }
    fn transmit(&mut self, p: &[u8]) -> io::Result<()> {
        self.change(|s| {
            if s.blocked {
                return Err(io::ErrorKind::WouldBlock.into());
            }
            s.engine.ingest(p).map_err(|e| {
                if e == l2tunnel_raw_tcp::Error::QueueFull {
                    io::ErrorKind::WouldBlock.into()
                } else {
                    io::Error::other(e)
                }
            })
        })
    }
}
async fn proxy_stream_case(duplex: Duplex, ipv6: bool, allow: bool, reverse: bool) -> TestResult {
    let mut cfg = config(duplex)?;
    let prefix = if ipv6 {
        IpPrefix::new("fd00:112::".parse()?, 64)?
    } else {
        IpPrefix::new("10.112.0.0".parse()?, 24)?
    };
    cfg.routes = RoutePolicy::new(vec![RouteRule {
        source: prefix,
        destination: prefix,
        ports: PortRange {
            first: 443,
            last: 443,
        },
    }])?;
    cfg.native.time_wait_reset_policy = proxy::TimeWaitResetPolicy::IgnoreInTimeWait;
    if !allow {
        cfg.routes = RoutePolicy::new(Vec::new())?;
    }
    cfg.relay.max_record_bytes = 512;
    cfg.relay.maximum = Window {
        bytes: 2048,
        records: 8,
    };
    cfg.relay.initial = Window {
        bytes: 1024,
        records: 4,
    };
    cfg.native.send_bytes = 4096;
    cfg.native.receive_bytes = 4096;
    let (a, b) = links(&cfg).await?;
    let da = Host::new(ipv6, reverse)?;
    let db = Host::new(ipv6, !reverse)?;
    let (ha, ca) = control_channel();
    let (hb, cb) = control_channel();
    let ra = tokio::spawn(run(da.clone(), a, cfg.clone(), ca));
    let rb = tokio::spawn(run(db.clone(), b, cfg, cb));
    wait_forwarding(&ha).await?;
    wait_forwarding(&hb).await?;
    let input_a: Vec<_> = (0..7001).map(|i| (i % 251) as u8).collect();
    let input_b: Vec<_> = (0..4099).map(|i| (i % 239) as u8).collect();
    let mut sent = [0; 2];
    let mut got = [Vec::new(), Vec::new()];
    let mut closed = [false; 2];
    let mut eof = [false; 2];
    timeout(Duration::from_secs(15), async {
        loop {
            for (i, host) in [&da, &db].into_iter().enumerate() {
                let input = if i == 0 { &input_a } else { &input_b };
                host.change(|s| {
                    if sent[i] < input.len() {
                        match s.engine.write(&input[sent[i]..]) {
                            Ok(n) => sent[i] += n,
                            Err(l2tunnel_raw_tcp::Error::NotConnected) => {}
                            Err(e) => return Err(io::Error::other(e)),
                        }
                    }
                    if sent[i] == input.len() && !closed[i] {
                        s.engine.close();
                        closed[i] = true;
                    }
                    let mut out = [0; 777];
                    match s.engine.read(&mut out).map_err(io::Error::other)? {
                        l2tunnel_raw_tcp::ReadOutcome::Data(n) => {
                            got[i].extend_from_slice(&out[..n])
                        }
                        l2tunnel_raw_tcp::ReadOutcome::Eof => eof[i] = true,
                        l2tunnel_raw_tcp::ReadOutcome::Pending => {}
                    }
                    Ok(())
                })?;
            }
            if eof == [true, true] {
                return Ok::<_, Failure>(());
            }
            if ha.status().is_some_and(|s| s.phase == Phase::Failed)
                || hb.status().is_some_and(|s| s.phase == Phase::Failed)
            {
                return Err(
                    format!("runtime failed: {:?} / {:?}", ha.status(), hb.status()).into(),
                );
            }
            sleep(Duration::from_millis(1)).await;
        }
    })
    .await??;
    assert_eq!(got[0], input_b);
    assert_eq!(got[1], input_a);
    let expected = usize::from(allow && !reverse);
    assert_eq!(ha.status().map(|s| s.flows), Some(expected));
    assert_eq!(hb.status().map(|s| s.flows), Some(expected));
    let waiter = ha.request_drain()?;
    let report = timeout(Duration::from_secs(15), waiter.wait()).await??;
    assert_eq!(report.clean_flows, expected);
    assert_eq!(report.stopped_flows, 0);
    assert_eq!(ra.await??, report);
    assert_eq!(rb.await??.clean_flows, expected);
    Ok(())
}
#[tokio::test]
async fn actual_ipv4_ipv6_tcp_endpoints_full_and_half_preserve_streams_and_fin() -> TestResult {
    tokio::try_join!(
        proxy_stream_case(Duplex::Full, false, true, false),
        proxy_stream_case(Duplex::Full, true, true, false),
        proxy_stream_case(Duplex::Half, false, true, false),
        proxy_stream_case(Duplex::Half, true, true, false)
    )?;
    Ok(())
}

async fn measured_links(
    cfg: &measured::Config,
) -> Result<(measured::Link, measured::Link), Failure> {
    let mut lanes = authenticated(measured::session_config(cfg)?, cfg.fixed.duplex).await?;
    let (a, b) = lanes.remove(0);
    if cfg.fixed.duplex == Duplex::Full {
        Ok((measured::Link::full(a, cfg)?, measured::Link::full(b, cfg)?))
    } else {
        let (a2, b2) = lanes.remove(0);
        Ok(tokio::try_join!(
            measured::client_pair(a, a2, cfg),
            measured::server_pair(b, b2, cfg)
        )?)
    }
}

async fn measured_stream_case(duplex: Duplex, ipv6: bool, slow_status: bool) -> TestResult {
    let mut cfg = measured::config_tests::config()?;
    cfg.fixed.duplex = duplex;
    let prefix = if ipv6 {
        IpPrefix::new("fd00:112::".parse()?, 64)?
    } else {
        IpPrefix::new("10.112.0.0".parse()?, 24)?
    };
    cfg.fixed.routes = RoutePolicy::new(vec![RouteRule {
        source: prefix,
        destination: prefix,
        ports: PortRange {
            first: 443,
            last: 443,
        },
    }])?;
    // This fixture intentionally selects the same explicit TIME-WAIT policy as
    // the existing fixed stream fixture; the public default remains Maintained.
    cfg.fixed.native.time_wait_reset_policy = proxy::TimeWaitResetPolicy::IgnoreInTimeWait;
    cfg.measured.ownership.handoff_timeout_micros = 500_000;
    cfg.measured.ownership.probe_timeout_micros = 300_000;
    cfg.measured.observation.sample_ttl_micros = 400_000;
    if slow_status {
        cfg.service.status_interval_micros = 500_000;
    }
    let (a, b) = measured_links(&cfg).await?;
    assert_eq!(a.role(), session::Role::Originator);
    assert_eq!(b.role(), session::Role::Acceptor);
    assert_eq!(a.logical_session(), b.logical_session());
    let da = Host::new(ipv6, false)?;
    let db = Host::new(ipv6, true)?;
    let (ha, ca) = measured::control_channel();
    let (hb, cb) = measured::control_channel();
    let ra = tokio::spawn(measured::run(da.clone(), a, cfg.clone(), ca));
    let rb = tokio::spawn(measured::run(db.clone(), b, cfg, cb));
    let input_a: Vec<_> = (0..7001).map(|i| (i % 251) as u8).collect();
    let input_b: Vec<_> = (0..4099).map(|i| (i % 239) as u8).collect();
    let mut sent = [0; 2];
    let mut got = [Vec::new(), Vec::new()];
    let mut closed = [false; 2];
    let mut eof = [false; 2];
    let mut saw_rate = [false; 2];
    let mut saw_echo = [false; 2];
    timeout(Duration::from_secs(5), async {
        loop {
            for (i, host) in [&da, &db].into_iter().enumerate() {
                let input = if i == 0 { &input_a } else { &input_b };
                host.change(|s| {
                    if sent[i] < input.len() {
                        let end = (sent[i] + 128).min(input.len());
                        match s.engine.write(&input[sent[i]..end]) {
                            Ok(n) => sent[i] += n,
                            Err(l2tunnel_raw_tcp::Error::NotConnected) => {}
                            Err(e) => return Err(io::Error::other(e)),
                        }
                    }
                    // Native EOF does not order the separate measurement records
                    // or their coalesced public snapshots. Keep this measurement
                    // workload active until both real observations arrive, within
                    // the same original transfer deadline; then exercise FIN/drain.
                    if sent[i] == input.len()
                        && !closed[i]
                        && saw_rate == [true; 2]
                        && saw_echo == [true; 2]
                    {
                        s.engine.close();
                        closed[i] = true;
                    }
                    let mut out = [0; 777];
                    match s.engine.read(&mut out).map_err(io::Error::other)? {
                        l2tunnel_raw_tcp::ReadOutcome::Data(n) => {
                            got[i].extend_from_slice(&out[..n])
                        }
                        l2tunnel_raw_tcp::ReadOutcome::Eof => eof[i] = true,
                        l2tunnel_raw_tcp::ReadOutcome::Pending => {}
                    }
                    Ok(())
                })?;
            }
            for (i, handle) in [&ha, &hb].into_iter().enumerate() {
                if let Some(status) = handle.status() {
                    if status.runtime.phase == Phase::Failed {
                        return Err(format!("measured runtime failed: {status:?}").into());
                    }
                    saw_rate[i] |= status.measurement.observations.ack_rate.is_some();
                    saw_echo[i] |= status.measurement.observations.service_latency.is_some();
                }
            }
            if eof == [true, true] {
                break;
            }
            sleep(Duration::from_millis(2)).await;
        }
        Ok::<_, Failure>(())
    })
    .await
    .map_err(|e| {
        format!(
            "measured stream timeout {duplex:?}/{ipv6}: {e}: {:?}/{:?}",
            ha.status(),
            hb.status()
        )
    })??;
    assert_eq!(got[0], input_b);
    assert_eq!(got[1], input_a);
    assert_eq!(saw_rate, [true; 2]);
    assert_eq!(
        saw_echo,
        [true; 2],
        "coalesced echo snapshot {duplex:?}/{ipv6}: {:?}/{:?}",
        ha.status(),
        hb.status()
    );
    for handle in [&ha, &hb] {
        let s = handle.status().ok_or("measured snapshot")?;
        assert_eq!(s.runtime.flows, 1);
        assert!(s.measurement.applied.is_some());
        assert!(s.measurement.admitted_by_kind.into_iter().all(|n| n > 0));
        assert!(s.measurement.admitted_framed_bytes > 0);
    }
    // Preserve the maintained TIME-WAIT timer; application EOF alone is not a
    // clean native-leg proof. Match the existing fixed fixture's finite bound.
    let report = timeout(Duration::from_secs(15), ha.request_drain()?.wait())
        .await
        .map_err(|e| {
            format!(
                "measured drain timeout {duplex:?}/{ipv6}: {e}: {:?}/{:?}",
                ha.status(),
                hb.status()
            )
        })??;
    assert_eq!(ra.await??, report);
    assert_eq!(rb.await??.clean_flows, 1);
    assert_eq!(report.clean_flows, 1);
    for handle in [&ha, &hb] {
        let s = handle.status().ok_or("terminal measured snapshot")?;
        assert_eq!(s.runtime.phase, Phase::Closed);
        assert_eq!(
            (s.measurement.queued, s.measurement.awaiting_callback),
            (0, 0)
        );
        assert_eq!(s.measurement.flows.len(), 1);
    }
    Ok(())
}
#[tokio::test]
async fn measured_actual_tcp_both_roles_full_half_ipv4_ipv6_and_full_flush_drain() -> TestResult {
    tokio::try_join!(
        measured_stream_case(Duplex::Full, false, false),
        measured_stream_case(Duplex::Full, true, false),
        measured_stream_case(Duplex::Half, false, false),
        measured_stream_case(Duplex::Half, true, false)
    )?;
    Ok(())
}

#[tokio::test]
async fn measured_short_stream_observes_coalesced_status_before_fin() -> TestResult {
    measured_stream_case(Duplex::Full, false, true).await
}

#[tokio::test]
async fn measured_rejects_fixed_profile_and_drops_no_device_input_on_binding_mismatch() -> TestResult
{
    let cfg = measured::config_tests::config()?;
    let (a, _) = authenticated(session_config(&cfg.fixed)?, Duplex::Full)
        .await?
        .remove(0);
    assert!(measured::Link::full(a, &cfg).is_err());
    let (a, _) = measured_links(&cfg).await?;
    let mut changed = cfg.clone();
    changed.service.status_interval_micros += 1;
    let device = Device::default();
    let (_handle, control) = measured::control_channel();
    assert!(
        measured::run(device.clone(), a, changed, control)
            .await
            .is_err()
    );
    assert_eq!(device.change(|s| s.reads)?, 0);
    Ok(())
}

#[tokio::test]
async fn measured_original_startup_wake_precedes_long_native_poll_interval() -> TestResult {
    let mut cfg = measured::config_tests::config()?;
    cfg.fixed.runtime.poll_interval = Duration::from_millis(100);
    cfg.fixed.timeouts.startup = Duration::from_millis(10);
    cfg.measured.ownership.pending_ttl_micros = 1_000_000;
    cfg.measured.ownership.probe_interval_micros = 100_000;
    cfg.measured.ownership.probe_timeout_micros = 1_000_000;
    cfg.measured.ownership.handoff_timeout_micros = 2_000_000;
    cfg.measured.ownership.emission_interval_micros = 100_000;
    cfg.measured.observation.report_interval_micros = 400_000;
    cfg.measured.observation.sample_ttl_micros = 1_000_000;
    cfg.measured.observation.demand_idle_micros = 800_000;
    cfg.measured.observation.rate_interval_micros = 100_000;
    cfg.service.plan_interval_micros = 100_000;
    cfg.service.status_interval_micros = 100_000;
    let (a, _held_peer) = measured_links(&cfg).await?;
    tokio::time::pause();
    let device = Device::default();
    let (handle, control) = measured::control_channel();
    let task = tokio::spawn(measured::run(device.clone(), a, cfg, control));
    for _ in 0..4 {
        if handle.status().is_some() {
            break;
        }
        tokio::time::advance(Duration::from_millis(1)).await;
    }
    if handle.status().is_none() && task.is_finished() {
        return Err(format!("early measured startup: {:?}", task.await?).into());
    }
    assert!(handle.status().is_some());
    tokio::time::advance(Duration::from_millis(10)).await;
    let failure = timeout(Duration::from_millis(1), task)
        .await??
        .err()
        .ok_or("startup incorrectly completed")?;
    assert_eq!(failure.kind(), io::ErrorKind::TimedOut);
    assert_eq!(device.change(|s| s.reads)?, 0);
    assert_eq!(
        handle.status().map(|s| s.runtime.phase),
        Some(Phase::Failed)
    );
    Ok(())
}

#[tokio::test]
async fn measured_asymmetric_native_backpressure_preserves_credit_and_peer_only_drain() -> TestResult
{
    for duplex in [Duplex::Full, Duplex::Half] {
        let mut cfg = measured::config_tests::config()?;
        cfg.fixed.duplex = duplex;
        let (a, b) = measured_links(&cfg).await?;
        let da = Device::default();
        let db = Device::default();
        db.change(|s| s.blocked = true)?;
        da.change(|s| s.outgoing.push_back(packet(71)))?;
        let (ha, ca) = measured::control_channel();
        let (hb, cb) = measured::control_channel();
        let ra = tokio::spawn(measured::run(da, a, cfg.clone(), ca));
        let rb = tokio::spawn(measured::run(db.clone(), b, cfg, cb));
        timeout(Duration::from_secs(3), async {
            loop {
                if hb
                    .status()
                    .is_some_and(|s| s.measurement.pressure.receiver_pressure)
                {
                    break;
                }
                sleep(Duration::from_millis(1)).await;
            }
        })
        .await?;
        assert!(db.change(|s| s.received.is_empty())?);
        assert_eq!(
            hb.status()
                .ok_or("status")?
                .runtime
                .native_confirmed_packets,
            0
        );
        let waiter = ha.request_drain()?;
        sleep(Duration::from_millis(20)).await;
        assert!(!ra.is_finished() && !rb.is_finished());
        assert_ne!(hb.status().ok_or("status")?.runtime.phase, Phase::Closed);
        db.change(|s| s.blocked = false)?;
        let report = timeout(Duration::from_secs(3), waiter.wait()).await??;
        assert_eq!(ra.await??, report);
        assert_eq!(rb.await??.native_confirmed_packets, 1);
        assert_eq!(db.change(|s| s.received.clone())?, vec![packet(71)]);
    }
    Ok(())
}
#[test]
fn controls_and_user_envelopes_reject_noncanonical_lengths() -> TestResult {
    use wire::{ControlFrame as F, Credit, Fence, Start};
    let start = Start {
        digest: [3; 32],
        session: [7; 16],
        originator: true,
        duplex: Duplex::Half,
        lane: 1,
    };
    let f = Fence {
        records: 9,
        transparent: Credit {
            bytes: 100,
            packets: 1,
        },
        flows: 3,
    };
    for frame in [
        F::Start(start),
        F::Ready(start),
        F::Credit(f.transparent),
        F::Ping(9),
        F::Pong(9),
        F::Quiesce,
        F::Barrier(f),
        F::Ack(f),
    ] {
        let encoded = frame.encode();
        assert_eq!(F::decode(&encoded)?, frame);
        for n in 0..encoded.len() {
            assert!(F::decode(&encoded[..n]).is_err());
        }
        let mut extended = encoded.clone();
        extended.push(0);
        assert!(F::decode(&extended).is_err());
        let mut bad = encoded;
        bad[9] = 1;
        assert!(F::decode(&bad).is_err());
    }
    let cfg = config(Duplex::Full)?;
    let frame = wire::user(0, 1, b"test")?;
    for n in 0..frame.len() {
        assert!(wire::decode_user(&frame[..n], &cfg).is_err());
    }
    let mut bad = frame;
    bad[5] = 0;
    assert!(wire::decode_user(&bad, &cfg).is_err());
    Ok(())
}

#[tokio::test]
async fn route_denied_and_reverse_originated_tcp_remain_transparent() -> TestResult {
    tokio::try_join!(
        proxy_stream_case(Duplex::Full, false, false, false),
        proxy_stream_case(Duplex::Half, true, true, true)
    )?;
    Ok(())
}

async fn manual_frame(
    peer: &mut Link,
    _sequence: u64,
    kind: super::record::Kind,
    body: &[u8],
) -> io::Result<()> {
    use tokio::io::AsyncWriteExt;
    let bytes = super::record::encode(kind, body)?;
    peer.inner.writer.write_u32(bytes.len() as u32).await?;
    peer.inner.writer.write_all(&bytes).await?;
    peer.inner.writer.flush().await
}
async fn manual_start(peer: &mut Link, cfg: &Config, bad_role: bool) -> io::Result<()> {
    let start = wire::Start {
        digest: peer.binding.digest.0,
        session: peer.logical,
        originator: bad_role,
        duplex: cfg.duplex,
        lane: 0,
    };
    manual_frame(
        peer,
        0,
        super::record::Kind::Control,
        &wire::ControlFrame::Start(start).encode(),
    )
    .await?;
    manual_frame(
        peer,
        1,
        super::record::Kind::Control,
        &wire::ControlFrame::Ready(start).encode(),
    )
    .await
}
#[tokio::test]
async fn authenticated_bad_role_duplicate_start_and_unearned_credit_fail_closed() -> TestResult {
    for case in 0..5 {
        let cfg = config(Duplex::Full)?;
        let (local, mut peer) = links(&cfg).await?;
        let device = Device::default();
        let (handle, control) = control_channel();
        let task = tokio::spawn(run(device.clone(), local, cfg.clone(), control));
        manual_start(&mut peer, &cfg, case == 0).await?;
        if case != 0 {
            wait_forwarding(&handle).await?;
            let kind = super::record::Kind::Control;
            match case {
                1 => manual_start(&mut peer, &cfg, false).await?,
                2 => {
                    manual_frame(
                        &mut peer,
                        2,
                        kind,
                        &wire::ControlFrame::Credit(wire::Credit {
                            bytes: 1,
                            packets: 1,
                        })
                        .encode(),
                    )
                    .await?
                }
                3 => {
                    let mut body = wire::ControlFrame::Ping(1).encode();
                    body[9] = 1;
                    manual_frame(&mut peer, 2, kind, &body).await?;
                }
                _ => {
                    let body = wire::user(cfg.mux.channels, 0, b"bad")?;
                    manual_frame(&mut peer, 2, super::record::Kind::Data, &body).await?;
                }
            }
        }
        assert!(timeout(Duration::from_secs(2), task).await??.is_err());
        assert_eq!(device.change(|s| s.received.len())?, 0);
        if case == 0 {
            assert_eq!(device.change(|s| s.reads)?, 0);
        }
    }
    Ok(())
}

#[tokio::test]
async fn startup_timeout_profile_mismatch_and_controller_drop_are_terminal() -> TestResult {
    let mut cfg = config(Duplex::Full)?;
    cfg.timeouts.startup = Duration::from_millis(30);
    let (local, _peer) = links(&cfg).await?;
    let device = Device::default();
    let (_handle, control) = control_channel();
    let result = timeout(
        Duration::from_secs(1),
        run(device.clone(), local, cfg.clone(), control),
    )
    .await?;
    assert_eq!(
        result.err().map(|e| e.kind()),
        Some(io::ErrorKind::TimedOut)
    );
    assert_eq!(device.change(|s| s.reads)?, 0);
    let (local, _peer) = links(&cfg).await?;
    let (_handle, control) = control_channel();
    let mut other = cfg.clone();
    other.mux.channels += 1;
    assert!(run(device.clone(), local, other, control).await.is_err());
    assert_eq!(device.change(|s| s.reads)?, 0);
    let (local, _peer) = links(&cfg).await?;
    let (handle, control) = control_channel();
    drop(handle);
    assert_eq!(
        run(device, local, cfg, control)
            .await
            .err()
            .map(|e| e.kind()),
        Some(io::ErrorKind::BrokenPipe)
    );
    Ok(())
}

#[test]
fn common_user_arbiter_has_channel_fifo_and_shared_saturation() -> TestResult {
    use arbiter::{Arbiter, Owner};
    let mut cfg = config(Duplex::Full)?;
    cfg.mux.channels = 1;
    cfg.mux.queue_records = 2;
    cfg.mux.per_flow_records = 2;
    let mut arbiter = Arbiter::new(&cfg, false)?;
    let a = cfg.classify(&packet(1))?.key;
    let mut other = packet(2);
    other[23] = 3;
    let b = cfg.classify(&other)?.key;
    arbiter
        .push(a, 1, vec![1; 48], Owner::Proxy(1), Duration::ZERO)
        .map_err(|e| e.error)?;
    arbiter
        .push(b, 16, vec![2; 48], Owner::Transparent(24), Duration::ZERO)
        .map_err(|e| e.error)?;
    let before = arbiter.usage();
    assert_eq!(before, (106, 2)); // Two 48-byte bodies, each with a 5-byte boundary.
    let rejected = arbiter
        .push(b, 16, vec![3; 48], Owner::Transparent(24), Duration::ZERO)
        .err()
        .ok_or("unbounded shared queue")?;
    assert!(rejected.pressure);
    assert_eq!(arbiter.usage(), before);
    assert!(
        arbiter
            .pop(|owner, _| matches!(owner, Owner::Transparent(_)))?
            .is_none()
    );
    assert_eq!(
        arbiter.pop(|_, _| true)?.map(|p| p.owner),
        Some(Owner::Proxy(1))
    );
    assert_eq!(
        arbiter.pop(|_, _| true)?.map(|p| p.owner),
        Some(Owner::Transparent(24))
    );
    assert_eq!(arbiter.usage(), (0, 0));
    Ok(())
}

#[tokio::test]
async fn infeasible_pre_start_drain_is_rejected_before_device_io() -> TestResult {
    for duplex in [Duplex::Full, Duplex::Half] {
        let mut cfg = config(duplex)?;
        let (local, _peer) = links(&cfg).await?;
        cfg.timeouts.shutdown = Duration::from_millis(30);
        let device = Device::default();
        device.change(|s| s.outgoing.push_back(packet(3)))?;
        let (handle, control) = control_channel();
        let waiter = handle.request_drain()?;
        let failure = run(device.clone(), local, cfg, control)
            .await
            .err()
            .ok_or("infeasible drain config accepted")?;
        assert_eq!(failure.kind(), io::ErrorKind::InvalidData);
        assert_eq!(
            failure.to_string(),
            "proxy deadlines cannot service configured control rate"
        );
        assert!(waiter.wait().await.is_err());
        assert_eq!(device.change(|s| s.reads)?, 0);
        assert_eq!(device.change(|s| s.outgoing.len())?, 1);
    }
    Ok(())
}

#[path = "proxy_control_pacing_tests.rs"]
mod control_pacing_cases;
