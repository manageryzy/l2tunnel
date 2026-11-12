//! Genuine UDP-only QUIC runtime, independent native devices and an owned UDP relay.
use super::*;
use l2tunnel_auth::{MemberAllowlist, MemberKey};
use l2tunnel_device::PacketLayer;
use l2tunnel_quic::{ClientConfig, ClientEndpoint, EndpointLimits, ServerConfig, ServerEndpoint};
use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use tokio::net::UdpSocket;
use tokio::task::JoinSet;
use tokio::time::Instant;
type TestError = Box<dyn std::error::Error + Send + Sync>;
type TestResult = Result<(), TestError>;
fn runtime(layer: PacketLayer) -> RuntimeConfig {
    RuntimeConfig {
        layer,
        max_packet: 4000,
        compression: Compression::None,
        queue_packets: 2,
        poll_interval: Duration::from_millis(1),
    }
}
fn config(duplex: Duplex, recovery: RecoveryMode) -> io::Result<Config> {
    let mut config =
        Config::new(duplex, *b"runtime-quic-001", 1400, false)?.with_recovery(recovery)?;
    config.arq.initial_rto = Duration::from_millis(100);
    config.arq.maximum_rto = Duration::from_millis(400);
    config.arq.ack_delay = Duration::from_millis(1);
    config.arq.max_retries = 20;
    config.control_timeout = Duration::from_secs(3);
    config.heartbeat_interval = Duration::from_millis(20);
    config.reassembly_timeout = Duration::from_secs(3);
    config.validate()?;
    Ok(config)
}
#[derive(Default)]
struct Native {
    outgoing: VecDeque<Vec<u8>>,
    delivered: Vec<Vec<u8>>,
    admitted: usize,
    blocked: bool,
}
#[derive(Clone)]
struct Device {
    layer: PacketLayer,
    native: Arc<Mutex<Native>>,
}
impl Device {
    fn new(layer: PacketLayer) -> Self {
        Self {
            layer,
            native: Arc::new(Mutex::new(Native::default())),
        }
    }
    fn change<T>(&self, f: impl FnOnce(&mut Native) -> T) -> io::Result<T> {
        let mut guard = self
            .native
            .lock()
            .map_err(|_| invalid("test device lock"))?;
        Ok(f(&mut guard))
    }
}
impl PacketDevice for Device {
    type Error = io::Error;
    fn layer(&self) -> PacketLayer {
        self.layer
    }
    fn receive(&mut self, out: &mut [u8]) -> io::Result<Option<usize>> {
        if out.len() < l2tunnel_device::READ_BUFFER_BYTES {
            return Err(invalid("native sentinel required"));
        }
        self.change(|n| {
            n.outgoing.pop_front().map(|p| {
                out[..p.len()].copy_from_slice(&p);
                n.admitted += 1;
                p.len()
            })
        })
    }
    fn transmit(&mut self, packet: &[u8]) -> io::Result<()> {
        self.change(|n| {
            if n.blocked {
                return Err(io::ErrorKind::WouldBlock.into());
            }
            n.delivered.push(packet.to_vec());
            Ok(())
        })?
    }
}
fn packet(layer: PacketLayer, value: u8, len: usize) -> Vec<u8> {
    let mut bytes: Vec<_> = (0..len)
        .map(|i| (i.wrapping_mul(17) as u8) ^ value)
        .collect();
    if layer == PacketLayer::Ip {
        bytes[0] = 0x45;
        bytes[2..4].copy_from_slice(&(len as u16).to_be_bytes());
    } else {
        bytes[12..14].copy_from_slice(&0x88b5u16.to_be_bytes());
    }
    bytes
}
#[derive(Default)]
struct RelayState {
    impaired: AtomicBool,
    blackhole: AtomicBool,
    dropped: AtomicUsize,
    reordered: AtomicUsize,
    largest: AtomicUsize,
}
struct Relays {
    state: Arc<RelayState>,
    tasks: JoinSet<io::Result<()>>,
}
impl Relays {
    fn new() -> Self {
        Self {
            state: Arc::new(RelayState::default()),
            tasks: JoinSet::new(),
        }
    }
    async fn add(&mut self, server: SocketAddr) -> io::Result<SocketAddr> {
        let socket = UdpSocket::bind("127.0.0.1:0").await?;
        let address = socket.local_addr()?;
        let state = self.state.clone();
        self.tasks.spawn(async move {
            let mut client = None;
            let mut buffer = vec![0; 65536];
            let mut counter = 0usize;
            let mut held: Option<(Vec<u8>, SocketAddr)> = None;
            loop {
                let (count, from) = socket.recv_from(&mut buffer).await?;
                state.largest.fetch_max(count, Ordering::Relaxed);
                let target = if from == server {
                    match client {
                        Some(address) => address,
                        None => continue,
                    }
                } else {
                    client = Some(from);
                    server
                };
                if state.blackhole.load(Ordering::Relaxed) {
                    state.dropped.fetch_add(1, Ordering::Relaxed);
                    continue;
                }
                counter = counter.wrapping_add(1);
                if state.impaired.load(Ordering::Relaxed) {
                    if counter.is_multiple_of(7) {
                        state.dropped.fetch_add(1, Ordering::Relaxed);
                        continue;
                    }
                    if held.is_none() && counter.is_multiple_of(11) {
                        held = Some((buffer[..count].to_vec(), target));
                        continue;
                    }
                }
                socket.send_to(&buffer[..count], target).await?;
                if let Some((bytes, peer)) = held.take() {
                    socket.send_to(&bytes, peer).await?;
                    state.reordered.fetch_add(1, Ordering::Relaxed);
                }
            }
        });
        Ok(address)
    }
}
async fn authenticated(
    runtime: RuntimeConfig,
    config: Config,
    relays: &mut Relays,
) -> Result<Vec<(AuthenticatedConnection, AuthenticatedConnection)>, TestError> {
    let cert = rcgen::generate_simple_self_signed(vec!["quic.test".to_owned()])?;
    let chain = vec![cert.cert.der().to_vec()];
    let key_der = cert.signing_key.serialize_der();
    let member = MemberKey::from_pkcs8(&MemberKey::generate_pkcs8()?)?;
    let members = MemberAllowlist::new(&[member.public_key()])?;
    let mut result = Vec::new();
    for lane in if config.duplex == Duplex::Full {
        vec![Lane::First]
    } else {
        vec![Lane::First, Lane::Second]
    } {
        let profile = carrier_profile(config, lane)?;
        let limits = EndpointLimits::default();
        let client = ClientEndpoint::bind(
            "127.0.0.1:0".parse()?,
            &ClientConfig::from_der_roots(&chain, profile, limits)?,
        )?;
        let server = ServerEndpoint::bind(
            "127.0.0.1:0".parse()?,
            &ServerConfig::from_der(&chain, &key_der, profile, limits)?,
        )?;
        let relay = relays.add(server.local_addr()?).await?;
        let base = base_session_config(runtime, config)?;
        let (a, b) = tokio::join!(
            client.connect(relay, "quic.test", &member, base),
            server.accept(&members, base)
        );
        result.push((a?, b?));
    }
    Ok(result)
}
async fn links(runtime: RuntimeConfig, config: Config) -> Result<(Link, Link, Relays), TestError> {
    let mut relays = Relays::new();
    let mut values = authenticated(runtime, config, &mut relays).await?;
    if config.duplex == Duplex::Full {
        let (a, b) = values.pop().ok_or("missing pair")?;
        Ok((
            Link::full(a, runtime, config)?,
            Link::full(b, runtime, config)?,
            relays,
        ))
    } else {
        let (a2, b2) = values.pop().ok_or("missing second")?;
        let (a1, b1) = values.pop().ok_or("missing first")?;
        let (a, b) = tokio::join!(
            client_pair(a1, a2, runtime, config),
            server_pair(b1, b2, runtime, config)
        );
        Ok((a?, b?, relays))
    }
}
async fn wait_delivery(
    tasks: &mut JoinSet<io::Result<()>>,
    a: &Device,
    b: &Device,
    count: usize,
) -> TestResult {
    let end = Instant::now() + Duration::from_secs(8);
    loop {
        if a.change(|n| n.delivered.len())? == count && b.change(|n| n.delivered.len())? == count {
            return Ok(());
        }
        tokio::select! {
            Some(result)=tasks.join_next()=>return Err(format!("runtime ended: {result:?}").into()),
            _=tokio::time::sleep(Duration::from_millis(2))=>{},
        }
        if Instant::now() >= end {
            return Err("native delivery deadline".into());
        }
    }
}

#[tokio::test]
async fn all_native_profiles_real_udp_loss_reorder_fragmentation_and_backpressure() -> TestResult {
    for duplex in [Duplex::Full, Duplex::Half] {
        for layer in [PacketLayer::Ethernet, PacketLayer::Ip] {
            for compression in [Compression::None, Compression::Lz4IfSmaller] {
                for recovery in [
                    RecoveryMode::SelectiveRepeat,
                    RecoveryMode::Cauchy {
                        sources: 4,
                        repairs: 2,
                        flush_after: Duration::from_millis(2),
                    },
                ] {
                    let mut runtime = runtime(layer);
                    runtime.compression = compression;
                    let config = config(duplex, recovery)?;
                    let (a, b, relays) = links(runtime, config).await?;
                    let a_device = Device::new(layer);
                    let b_device = Device::new(layer);
                    let forward: Vec<_> = (0..10)
                        .map(|i| packet(layer, i, 1300 + i as usize * 233))
                        .collect();
                    let reverse: Vec<_> = (0..10)
                        .map(|i| packet(layer, i + 100, 1400 + i as usize * 211))
                        .collect();
                    a_device.change(|n| n.outgoing = forward.clone().into())?;
                    b_device.change(|n| {
                        n.outgoing = reverse.clone().into();
                        n.blocked = true;
                    })?;
                    relays.state.impaired.store(true, Ordering::Relaxed);
                    let mut tasks = JoinSet::new();
                    tasks.spawn(run(a_device.clone(), a, runtime, config));
                    tasks.spawn(run(b_device.clone(), b, runtime, config));
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    assert!(b_device.change(|n| n.delivered.is_empty())?);
                    assert!(a_device.change(|n| n.admitted)? <= runtime.queue_packets);
                    b_device.change(|n| n.blocked = false)?;
                    wait_delivery(&mut tasks, &a_device, &b_device, 10).await?;
                    assert_eq!(b_device.change(|n| n.delivered.clone())?, forward);
                    assert_eq!(a_device.change(|n| n.delivered.clone())?, reverse);
                    assert!(relays.state.dropped.load(Ordering::Relaxed) > 0);
                    assert!(relays.state.reordered.load(Ordering::Relaxed) > 0);
                    assert!(
                        relays.state.largest.load(Ordering::Relaxed)
                            <= config.path_mtu - config.outer_overhead_bytes
                    );
                    tasks.abort_all();
                    while tasks.join_next().await.is_some() {}
                }
            }
        }
    }
    Ok(())
}

#[tokio::test]
async fn link_binding_role_lane_and_device_config_fail_before_admission() -> TestResult {
    let runtime = runtime(PacketLayer::Ip);
    let full = config(Duplex::Full, RecoveryMode::SelectiveRepeat)?;
    let mut relays = Relays::new();
    let (a, _b) = authenticated(runtime, full, &mut relays)
        .await?
        .pop()
        .ok_or("missing full")?;
    let mut mismatch = runtime;
    mismatch.max_packet -= 1;
    assert!(Link::full(a, mismatch, full).is_err());
    let half = config(Duplex::Half, RecoveryMode::SelectiveRepeat)?;
    let mut pair = authenticated(runtime, half, &mut relays).await?;
    let (a2, b2) = pair.pop().ok_or("second")?;
    let (a1, b1) = pair.pop().ok_or("first")?;
    assert!(client_pair(a2, a1, runtime, half).await.is_err());
    assert!(client_pair(b1, b2, runtime, half).await.is_err());
    let (a, _b, _relays) = links(runtime, full).await?;
    let device = Device::new(PacketLayer::Ethernet);
    device.change(|n| n.outgoing.push_back(packet(PacketLayer::Ethernet, 1, 100)))?;
    assert!(run(device.clone(), a, runtime, full).await.is_err());
    assert_eq!(device.change(|n| n.admitted)?, 0);
    Ok(())
}

#[test]
fn mtu_and_all_policy_fields_are_authentication_bound() -> TestResult {
    assert!(Config::new(Duplex::Full, [1; 16], 1227, false).is_err());
    assert!(Config::new(Duplex::Full, [1; 16], 1247, true).is_err());
    assert!(Config::new(Duplex::Full, [0; 16], 1500, false).is_err());
    Config::new(Duplex::Half, [1; 16], 1228, false)?;
    Config::new(Duplex::Half, [1; 16], 1248, true)?;
    let cfg = config(Duplex::Half, RecoveryMode::SelectiveRepeat)?;
    let rt = runtime(PacketLayer::Ip);
    let base = base_session_config(rt, cfg)?;
    for field in 0..9 {
        let mut c = cfg;
        match field {
            0 => c.application_id[0] ^= 1,
            1 => c.queued_datagrams += 1,
            2 => c.control_window_bytes += 1,
            3 => c.arq.max_retries += 1,
            4 => c.wire_budget.packets += 1,
            5 => c.wire_budget.wire_bytes += 1,
            6 => c.heartbeat_interval += Duration::from_nanos(1),
            7 => c.reassembly_timeout += Duration::from_nanos(1),
            8 => {
                c = c.with_recovery(RecoveryMode::Cauchy {
                    sources: 2,
                    repairs: 1,
                    flush_after: Duration::from_millis(2),
                })?
            }
            _ => return Err("test field".into()),
        };
        assert_ne!(base, base_session_config(rt, c)?);
    }
    assert_ne!(
        session_config(rt, cfg, Lane::First)?,
        session_config(rt, cfg, Lane::Second)?
    );
    Ok(())
}

#[tokio::test]
async fn malformed_control_data_native_size_and_control_closure_fail_explicitly() -> TestResult {
    for failure in 0..4 {
        let rt = runtime(PacketLayer::Ip);
        let cfg = config(Duplex::Full, RecoveryMode::SelectiveRepeat)?;
        let mut relays = Relays::new();
        let (a, b) = authenticated(rt, cfg, &mut relays)
            .await?
            .pop()
            .ok_or("pair")?;
        let mut attacker = checked_parts(a, rt, cfg, Lane::First)?;
        let victim = Link::full(b, rt, cfg)?;
        let device = Device::new(PacketLayer::Ip);
        if failure == 2 {
            device.change(|n| {
                n.outgoing
                    .push_back(packet(PacketLayer::Ip, 1, rt.max_packet + 1))
            })?;
        }
        let mut tasks = JoinSet::new();
        tasks.spawn(run(device, victim, rt, cfg));
        match failure {
            0 => attacker.control.write_all(b"BAD!\x01\x01\0\0").await?,
            1 => {
                attacker.sender.send(b"bad recovery record").await?;
            }
            2 => {}
            3 => drop(attacker),
            _ => return Err("failure test".into()),
        }
        let result = timeout(Duration::from_secs(2), tasks.join_next())
            .await?
            .ok_or("missing task")??;
        assert!(result.is_err());
    }
    Ok(())
}

#[tokio::test]
async fn common_budget_keeps_control_live_under_native_block_and_blackhole_terminates() -> TestResult
{
    let rt = runtime(PacketLayer::Ip);
    let mut cfg = config(
        Duplex::Half,
        RecoveryMode::Cauchy {
            sources: 2,
            repairs: 1,
            flush_after: Duration::from_millis(2),
        },
    )?;
    cfg.wire_budget = WireBudget {
        interval: Duration::from_millis(5),
        packets: 8,
        wire_bytes: 6000,
    };
    cfg.validate()?;
    let (a, b, relays) = links(rt, cfg).await?;
    let ad = Device::new(rt.layer);
    let bd = Device::new(rt.layer);
    ad.change(|n| n.outgoing = (0..6).map(|i| packet(rt.layer, i, 3000)).collect())?;
    bd.change(|n| {
        n.blocked = true;
        n.outgoing = (0..6).map(|i| packet(rt.layer, i + 100, 3000)).collect();
    })?;
    let mut tasks = JoinSet::new();
    tasks.spawn(run(ad.clone(), a, rt, cfg));
    tasks.spawn(run(bd.clone(), b, rt, cfg));
    tokio::time::sleep(Duration::from_millis(150)).await;
    assert!(tasks.try_join_next().is_none());
    assert!(ad.change(|n| n.admitted)? <= rt.queue_packets);
    bd.change(|n| n.blocked = false)?;
    wait_delivery(&mut tasks, &ad, &bd, 6).await?;
    relays.state.blackhole.store(true, Ordering::Relaxed);
    ad.change(|n| n.outgoing.push_back(packet(rt.layer, 55, 3000)))?;
    let result = timeout(Duration::from_secs(5), tasks.join_next())
        .await?
        .ok_or("missing termination")??;
    assert!(result.is_err());
    Ok(())
}
