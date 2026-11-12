//! Genuine authenticated carrier tests for the timed packed selection.
use super::*;
use crate::{Compression, Duplex};
use l2tunnel_device::PacketLayer;
use std::time::Duration;
use tokio::{task::JoinSet, time::interval};
fn options() -> Options {
    Options {
        hold_micros: 1000,
        max_units: 4,
        work_limit: 16,
    }
}
use l2tunnel_auth::{
    ClientTls, MemberAllowlist, MemberKey, ServerTls, client_connect, server_accept,
};
use l2tunnel_datagram::{CoverProfile, Protection};
use l2tunnel_quic::{ClientConfig, ClientEndpoint, EndpointLimits, ServerConfig, ServerEndpoint};
use std::{
    collections::VecDeque,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
};
use tokio::{
    net::{TcpListener, TcpStream, UdpSocket},
    time::{sleep, timeout},
};
type TestError = Box<dyn std::error::Error + Send + Sync>;
type TestResult = Result<(), TestError>;
fn runtime(layer: PacketLayer) -> RuntimeConfig {
    RuntimeConfig {
        layer,
        max_packet: 4000,
        compression: Compression::None,
        queue_packets: 8,
        poll_interval: Duration::from_millis(1),
    }
}
fn udp_transport(
    duplex: Duplex,
    cover: CoverProfile,
    protection: Protection,
) -> io::Result<udp::Config> {
    let mut config = udp::Config::new(duplex, cover, protection, 576, false)?.with_recovery(
        udp::RecoveryMode::Cauchy {
            sources: 3,
            repairs: 2,
            flush_after: Duration::from_millis(2),
        },
    )?;
    config.arq.initial_rto = Duration::from_millis(100);
    config.arq.maximum_rto = Duration::from_millis(200);
    config.arq.max_retries = 8;
    config.control_timeout = Duration::from_secs(3);
    config.heartbeat_interval = Duration::from_millis(20);
    config.reassembly_timeout = Duration::from_secs(5);
    Ok(config)
}
fn quic_transport(duplex: Duplex) -> io::Result<quic::Config> {
    let mut config = quic::Config::new(duplex, *b"aligned-test-001", 1400, false)?.with_recovery(
        udp::RecoveryMode::Cauchy {
            sources: 3,
            repairs: 2,
            flush_after: Duration::from_millis(2),
        },
    )?;
    config.arq.initial_rto = Duration::from_millis(100);
    config.arq.maximum_rto = Duration::from_millis(200);
    config.arq.max_retries = 8;
    config.control_timeout = Duration::from_secs(3);
    config.heartbeat_interval = Duration::from_millis(20);
    config.reassembly_timeout = Duration::from_secs(5);
    Ok(config)
}
#[derive(Default)]
struct Native {
    outgoing: VecDeque<Vec<u8>>,
    delivered: Vec<Vec<u8>>,
    admitted: usize,
    blocked: bool,
    writes: usize,
}
#[derive(Clone)]
struct Device {
    layer: PacketLayer,
    state: Arc<Mutex<Native>>,
    service_delay: Duration,
}
impl Device {
    fn new(layer: PacketLayer) -> Self {
        Self {
            layer,
            state: Arc::new(Mutex::new(Native::default())),
            service_delay: Duration::ZERO,
        }
    }
    fn change<T>(&self, f: impl FnOnce(&mut Native) -> T) -> io::Result<T> {
        let mut state = self.state.lock().map_err(|_| invalid("test device lock"))?;
        Ok(f(&mut state))
    }
}
impl PacketDevice for Device {
    type Error = io::Error;
    fn layer(&self) -> PacketLayer {
        self.layer
    }
    fn receive(&mut self, output: &mut [u8]) -> io::Result<Option<usize>> {
        if output.len() < l2tunnel_device::READ_BUFFER_BYTES {
            return Err(invalid("native sentinel required"));
        }
        // Finite test-only CPU service simulates a long burst without a second
        // packet or timer driving the actor; production adapters remain nonblocking.
        let until = std::time::Instant::now() + self.service_delay;
        while std::time::Instant::now() < until {
            std::hint::spin_loop();
        }
        self.change(|state| {
            state.outgoing.pop_front().map(|packet| {
                output[..packet.len()].copy_from_slice(&packet);
                state.admitted += 1;
                packet.len()
            })
        })
    }
    fn transmit(&mut self, bytes: &[u8]) -> io::Result<()> {
        self.change(|state| {
            state.writes += 1;
            if state.blocked {
                Err(io::ErrorKind::WouldBlock.into())
            } else {
                state.delivered.push(bytes.to_vec());
                Ok(())
            }
        })?
    }
}

#[path = "packed_timing_tests.rs"]
mod timing;
fn packet(layer: PacketLayer, value: u8, length: usize) -> Vec<u8> {
    let mut bytes = vec![value; length];
    if layer == PacketLayer::Ethernet {
        bytes[12..14].copy_from_slice(&0x88b5u16.to_be_bytes());
    } else {
        bytes[..28].fill(0);
        bytes[0] = 0x45;
        bytes[2..4].copy_from_slice(&(length as u16).to_be_bytes());
        bytes[8] = 64;
        bytes[9] = 17;
        bytes[12..16].copy_from_slice(&[10, 0, 0, value.max(1)]);
        bytes[16..20].copy_from_slice(&[10, 0, 1, 1]);
        bytes[20..22].copy_from_slice(&(4000 + u16::from(value)).to_be_bytes());
        bytes[22..24].copy_from_slice(&5000u16.to_be_bytes());
        bytes[24..26].copy_from_slice(&((length - 20) as u16).to_be_bytes());
    }
    bytes
}
fn frames(layer: PacketLayer) -> Result<Vec<Vec<u8>>, TestError> {
    let mut frames = Vec::new();
    if layer == PacketLayer::Ethernet {
        for line in include_str!("../../l2tunnel-codec/tests/data/aligned-sender-goldens.tsv")
            .lines()
            .filter(|line| line.starts_with("symbol128\t0\t") || line.starts_with("symbol128\t1\t"))
        {
            let text = line.split('\t').nth(6).ok_or("golden native")?;
            frames.push(
                (0..text.len())
                    .step_by(2)
                    .map(|offset| u8::from_str_radix(&text[offset..offset + 2], 16))
                    .collect::<Result<Vec<_>, _>>()?,
            );
        }
    }
    for value in 1..9 {
        frames.push(packet(
            layer,
            value,
            if value == 8 {
                3500
            } else {
                64 + usize::from(value) * 17
            },
        ));
    }
    for value in 10..22 {
        let mut bytes = packet(layer, value, 64);
        bytes[60..].fill(0);
        frames.push(bytes);
    }
    Ok(frames)
}
#[derive(Default)]
struct Observations {
    dropped: AtomicUsize,
    reordered: AtomicUsize,
    largest: AtomicUsize,
    packed_sources: AtomicUsize,
    packed_max_units: AtomicUsize,
    packed_context: AtomicUsize,
    packed_predictive: AtomicUsize,
}
struct Relays {
    tasks: JoinSet<io::Result<()>>,
    observations: Arc<Observations>,
}
impl Relays {
    fn new() -> Self {
        Self {
            tasks: JoinSet::new(),
            observations: Arc::new(Observations::default()),
        }
    }
    async fn add(
        &mut self,
        server: SocketAddr,
        client: Option<SocketAddr>,
        impair: bool,
    ) -> io::Result<SocketAddr> {
        let socket = UdpSocket::bind("127.0.0.1:0").await?;
        let address = socket.local_addr()?;
        let observations = self.observations.clone();
        self.tasks.spawn(async move {
            let mut client=client;let mut input=vec![0;65536];let mut count=0usize;let mut held:Option<(Vec<u8>,SocketAddr)>=None;let mut timer=interval(Duration::from_millis(5));
            loop {tokio::select! {
                result=socket.recv_from(&mut input)=>{
                    let (length,source)=result?;observations.largest.fetch_max(length,Ordering::Relaxed);
                    let destination=if source==server { if let Some(client)=client {client}else{continue} } else {client=Some(source);server};
                    // Structural observation of cleartext integrity-mode sources.
                    // Actual carrier authentication remains at the receiving endpoint.
                    observe_packed(&input[..length], &observations);
                    count+=1;
                    if impair&&count.is_multiple_of(7) {observations.dropped.fetch_add(1,Ordering::Relaxed);continue;}
                    if impair&&count.is_multiple_of(5)&&held.is_none() {held=Some((input[..length].to_vec(),destination));continue;}
                    socket.send_to(&input[..length],destination).await?;
                    if let Some((bytes,to))=held.take() {socket.send_to(&bytes,to).await?;observations.reordered.fetch_add(1,Ordering::Relaxed);}
                },
                _=timer.tick()=>if let Some((bytes,to))=held.take() {socket.send_to(&bytes,to).await?;observations.reordered.fetch_add(1,Ordering::Relaxed);},
            }}
        });
        Ok(address)
    }
}
async fn udp_links(
    rt: RuntimeConfig,
    transport: udp::Config,
    config: Config,
    impair: bool,
) -> Result<(UdpLink, UdpLink, Relays), TestError> {
    udp_links_bound(rt, transport, config, impair, false).await
}
async fn udp_links_bound(
    rt: RuntimeConfig,
    transport: udp::Config,
    config: Config,
    impair: bool,
    ordinary: bool,
) -> Result<(UdpLink, UdpLink, Relays), TestError> {
    let cert = rcgen::generate_simple_self_signed(vec!["aligned.test".to_owned()])?;
    let chain = vec![cert.cert.der().to_vec()];
    let client_tls = ClientTls::from_der_roots(&chain)?;
    let server_tls = ServerTls::from_der(&chain, &cert.signing_key.serialize_der())?;
    let member = MemberKey::from_pkcs8(&MemberKey::generate_pkcs8()?)?;
    let members = MemberAllowlist::new(&[member.public_key()])?;
    let mut relays = Relays::new();
    let mut pairs = Vec::new();
    for lane in if transport.duplex == Duplex::Full {
        vec![Lane::First]
    } else {
        vec![Lane::First, Lane::Second]
    } {
        let a = UdpSocket::bind("127.0.0.1:0").await?;
        let b = UdpSocket::bind("127.0.0.1:0").await?;
        let peer = relays
            .add(b.local_addr()?, Some(a.local_addr()?), impair)
            .await?;
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let a_tcp = TcpStream::connect(listener.local_addr()?).await?;
        let (b_tcp, _) = listener.accept().await?;
        a_tcp.set_nodelay(true)?;
        b_tcp.set_nodelay(true)?;
        let legacy = aligned::Config::for_udp(rt, transport, 4)?;
        let binding = if ordinary {
            aligned::udp_session_config(rt, transport, legacy, lane)?
        } else {
            udp_session_config(rt, transport, config, lane)?
        };
        let carrier_config = |peer| {
            if ordinary {
                aligned::udp_carrier_config(rt, transport, legacy, lane, peer)
            } else {
                udp_carrier_config(rt, transport, config, lane, peer)
            }
        };
        let (a_tls, b_tls) = tokio::try_join!(
            client_connect(
                a_tcp,
                &client_tls,
                "aligned.test",
                &member,
                binding,
                Duration::from_secs(3)
            ),
            server_accept(
                b_tcp,
                &server_tls,
                &members,
                binding,
                Duration::from_secs(3)
            )
        )?;
        let (a, b) = tokio::try_join!(
            l2tunnel_udp::establish(a_tls, a, carrier_config(peer)?),
            l2tunnel_udp::establish(b_tls, b, carrier_config(peer)?)
        )?;
        pairs.push((a, b));
    }
    let (a, b) = if transport.duplex == Duplex::Full {
        let (a, b) = pairs.pop().ok_or("first")?;
        (
            UdpLink::full(a, rt, transport, config)?,
            UdpLink::full(b, rt, transport, config)?,
        )
    } else {
        let (a2, b2) = pairs.pop().ok_or("second")?;
        let (a1, b1) = pairs.pop().ok_or("first")?;
        tokio::try_join!(
            udp_client_pair(a1, a2, rt, transport, config),
            udp_server_pair(b1, b2, rt, transport, config)
        )?
    };
    Ok((a, b, relays))
}
async fn quic_links(
    rt: RuntimeConfig,
    transport: quic::Config,
    config: Config,
) -> Result<(QuicLink, QuicLink, Relays), TestError> {
    let cert = rcgen::generate_simple_self_signed(vec!["aligned.test".to_owned()])?;
    let chain = vec![cert.cert.der().to_vec()];
    let key = cert.signing_key.serialize_der();
    let member = MemberKey::from_pkcs8(&MemberKey::generate_pkcs8()?)?;
    let members = MemberAllowlist::new(&[member.public_key()])?;
    let mut relays = Relays::new();
    let mut pairs = Vec::new();
    for lane in if transport.duplex == Duplex::Full {
        vec![Lane::First]
    } else {
        vec![Lane::First, Lane::Second]
    } {
        let profile = quic::carrier_profile(transport, lane)?;
        let client = ClientEndpoint::bind(
            "127.0.0.1:0".parse()?,
            &ClientConfig::from_der_roots(&chain, profile, EndpointLimits::default())?,
        )?;
        let server = ServerEndpoint::bind(
            "127.0.0.1:0".parse()?,
            &ServerConfig::from_der(&chain, &key, profile, EndpointLimits::default())?,
        )?;
        let peer = relays.add(server.local_addr()?, None, true).await?;
        let base = quic_base_session_config(rt, transport, config)?;
        let (a, b) = tokio::try_join!(
            client.connect(peer, "aligned.test", &member, base),
            server.accept(&members, base)
        )?;
        pairs.push((a, b));
    }
    let (a, b) = if transport.duplex == Duplex::Full {
        let (a, b) = pairs.pop().ok_or("first")?;
        (
            QuicLink::full(a, rt, transport, config)?,
            QuicLink::full(b, rt, transport, config)?,
        )
    } else {
        let (a2, b2) = pairs.pop().ok_or("second")?;
        let (a1, b1) = pairs.pop().ok_or("first")?;
        tokio::try_join!(
            quic_client_pair(a1, a2, rt, transport, config),
            quic_server_pair(b1, b2, rt, transport, config)
        )?
    };
    Ok((a, b, relays))
}
async fn wait_delivery(
    tasks: &mut JoinSet<io::Result<()>>,
    a: &Device,
    b: &Device,
    count: usize,
) -> TestResult {
    timeout(Duration::from_secs(8),async {
        loop {
            if a.change(|state|state.delivered.len())?==count&&b.change(|state|state.delivered.len())?==count{return Ok(());}
            tokio::select! {Some(result)=tasks.join_next()=>return Err(io::Error::other(format!("aligned runtime ended: {result:?}"))),_=sleep(Duration::from_millis(2))=>{}}
        }
    }).await??;
    Ok(())
}
async fn exercise(
    a: &Device,
    b: &Device,
    tasks: &mut JoinSet<io::Result<()>>,
    input: &[Vec<u8>],
) -> TestResult {
    a.change(|state| state.outgoing.extend(input.iter().cloned()))?;
    b.change(|state| {
        state.blocked = true;
        state.outgoing.extend(input.iter().cloned());
    })?;
    sleep(Duration::from_millis(70)).await;
    assert!(b.change(|state| state.delivered.is_empty())?);
    assert!(
        a.change(|state| state.admitted)? <= 17,
        "peer native credit and common queue must bound reads"
    );
    b.change(|state| state.blocked = false)?;
    wait_delivery(tasks, a, b, input.len()).await?;
    let mut expected = input.to_vec();
    expected.sort();
    for device in [a, b] {
        let mut actual = device.change(|state| state.delivered.clone())?;
        actual.sort();
        assert_eq!(actual, expected);
    }
    Ok(())
}
#[tokio::test]
async fn actual_udp_packed_tap_tun_full_half_covers_and_suites_with_loss_and_backpressure()
-> TestResult {
    for duplex in [Duplex::Full, Duplex::Half] {
        for layer in [PacketLayer::Ethernet, PacketLayer::Ip] {
            for cover in [CoverProfile::OpenVpnLike, CoverProfile::QuicLike] {
                for protection in [Protection::ChaCha20Poly1305, Protection::HmacSha256] {
                    let rt = runtime(layer);
                    let transport = udp_transport(duplex, cover, protection)?;
                    let config = Config::for_udp(rt, transport, 4, options())?;
                    let (a_link, b_link, relays) = udp_links(rt, transport, config, true).await?;
                    let a = Device::new(layer);
                    let b = Device::new(layer);
                    let mut tasks = JoinSet::new();
                    tasks.spawn(run_udp(a.clone(), a_link, rt, transport, config));
                    tasks.spawn(run_udp(b.clone(), b_link, rt, transport, config));
                    exercise(&a, &b, &mut tasks, &frames(layer)?).await?;
                    assert!(relays.observations.dropped.load(Ordering::Relaxed) > 0);
                    assert!(relays.observations.reordered.load(Ordering::Relaxed) > 0);
                    assert!(
                        relays.observations.largest.load(Ordering::Relaxed) + 28
                            <= transport.path_mtu
                    );
                    if protection == Protection::HmacSha256 {
                        assert!(relays.observations.packed_sources.load(Ordering::Relaxed) > 0);
                        assert!(
                            relays.observations.packed_max_units.load(Ordering::Relaxed) > 1,
                            "actual multi-unit sources required"
                        );
                    }
                    if layer == PacketLayer::Ethernet && protection == Protection::HmacSha256 {
                        assert!(relays.observations.packed_context.load(Ordering::Relaxed) > 0);
                        assert!(
                            relays
                                .observations
                                .packed_predictive
                                .load(Ordering::Relaxed)
                                > 0
                        );
                    }
                    tasks.abort_all();
                    while tasks.join_next().await.is_some() {}
                }
            }
        }
    }
    Ok(())
}
#[tokio::test]
async fn actual_quic_packed_tap_tun_full_half_without_tcp_with_loss_and_backpressure() -> TestResult
{
    for duplex in [Duplex::Full, Duplex::Half] {
        for layer in [PacketLayer::Ethernet, PacketLayer::Ip] {
            let rt = runtime(layer);
            let transport = quic_transport(duplex)?;
            let config = Config::for_quic(rt, transport, 4, options())?;
            let (a_link, b_link, relays) = quic_links(rt, transport, config).await?;
            let a = Device::new(layer);
            let b = Device::new(layer);
            let mut tasks = JoinSet::new();
            tasks.spawn(run_quic(a.clone(), a_link, rt, transport, config));
            tasks.spawn(run_quic(b.clone(), b_link, rt, transport, config));
            exercise(&a, &b, &mut tasks, &frames(layer)?).await?;
            assert!(relays.observations.dropped.load(Ordering::Relaxed) > 0);
            tasks.abort_all();
            while tasks.join_next().await.is_some() {}
        }
    }
    Ok(())
}

fn observe_packed(packet: &[u8], seen: &Observations) {
    use l2tunnel_codec::{
        aligned_receiver::{Direction, Scope},
        packed_envelope as env,
    };
    for (offset, magic) in packet.windows(5).enumerate() {
        if magic != b"L2PK\x01" || packet.len() < offset + 56 {
            continue;
        }
        let bytes = &packet[offset..];
        let count = usize::from(bytes[6]);
        let length = 56 + 8 * count + usize::from(u16::from_be_bytes([bytes[10], bytes[11]]));
        if length > bytes.len() {
            continue;
        }
        let Ok(session) = bytes[12..28].try_into() else {
            continue;
        };
        let Ok(epoch) = bytes[28..36].try_into() else {
            continue;
        };
        let scope = Scope {
            session,
            epoch: l2tunnel_core::Epoch(u64::from_be_bytes(epoch)),
            direction: match bytes[5] {
                0 => Direction::InitiatorToResponder,
                1 => Direction::ResponderToInitiator,
                _ => continue,
            },
        };
        let config = env::Config {
            symbol_bytes: usize::from(u16::from_be_bytes([bytes[8], bytes[9]])),
            channels: 4,
            max_units: 4,
        };
        let Ok(view) = env::decode(config, scope, &bytes[..length]) else {
            continue;
        };
        seen.packed_sources.fetch_add(1, Ordering::Relaxed);
        seen.packed_max_units
            .fetch_max(view.len(), Ordering::Relaxed);
        if let Ok(units) = view.units() {
            for unit in units {
                let kind = unit.bytes[3];
                if kind == 0 {
                    seen.packed_context.fetch_add(1, Ordering::Relaxed);
                }
                if kind == 6 || kind & 7 == 5 || kind & 7 == 7 {
                    seen.packed_predictive.fetch_add(1, Ordering::Relaxed);
                }
            }
        }
    }
}

#[test]
fn exact_geometry_domain_and_complete_batch_reservations_are_checked() -> TestResult {
    let rt = runtime(PacketLayer::Ethernet);
    let transport = udp_transport(
        Duplex::Full,
        CoverProfile::OpenVpnLike,
        Protection::HmacSha256,
    )?;
    let config = Config::for_udp(rt, transport, 4, options())?;
    let binding = udp_base_session_config(rt, transport, config)?;
    let ordinary = aligned::Config::for_udp(rt, transport, 4)?;
    assert_ne!(
        binding,
        aligned::udp_base_session_config(rt, transport, ordinary)?
    );
    assert_eq!(
        config.protocol.envelope().max_source_bytes()?,
        transport.arq.max_source_bytes
    );
    for changed in [
        Options {
            hold_micros: 999,
            ..options()
        },
        Options {
            max_units: 3,
            ..options()
        },
        Options {
            work_limit: 15,
            ..options()
        },
    ] {
        assert_ne!(
            binding,
            udp_base_session_config(rt, transport, Config::for_udp(rt, transport, 4, changed)?)?
        );
    }
    for invalid in [
        Options {
            hold_micros: 0,
            ..options()
        },
        Options {
            hold_micros: 1001,
            ..options()
        },
        Options {
            max_units: 0,
            ..options()
        },
        Options {
            max_units: 255,
            ..options()
        },
        Options {
            work_limit: 0,
            ..options()
        },
        Options {
            work_limit: 256,
            ..options()
        },
    ] {
        assert!(Config::for_udp(rt, transport, 4, invalid).is_err());
    }
    for channels in [0, 256] {
        assert!(Config::for_udp(rt, transport, channels, options()).is_err());
    }
    let mut bad = config;
    bad.protocol.base.receiver.lookahead_records = usize::from(options().max_units) - 1;
    assert!(udp_base_session_config(rt, transport, bad).is_err());
    bad = config;
    bad.protocol.base.receiver.lookahead_fragments = 1;
    assert!(udp_base_session_config(rt, transport, bad).is_err());
    bad = config;
    bad.pipeline.flows.mapping = l2tunnel_pipeline::Mapping::ConnectionRoundRobin;
    assert!(udp_base_session_config(rt, transport, bad).is_err());
    assert!(
        Config::for_udp(
            rt,
            transport.with_recovery(udp::RecoveryMode::SelectiveRepeat)?,
            4,
            options()
        )
        .is_err()
    );
    let mut wrong = rt;
    wrong.compression = Compression::Lz4IfSmaller;
    assert!(Config::for_udp(wrong, transport, 4, options()).is_err());
    Ok(())
}

#[tokio::test]
async fn genuine_ordinary_udp_carriers_cannot_be_relabelled_as_packed() -> TestResult {
    for duplex in [Duplex::Full, Duplex::Half] {
        let rt = runtime(PacketLayer::Ip);
        let transport = udp_transport(duplex, CoverProfile::OpenVpnLike, Protection::HmacSha256)?;
        let config = Config::for_udp(rt, transport, 4, options())?;
        assert!(
            udp_links_bound(rt, transport, config, false, true)
                .await
                .is_err()
        );
    }
    Ok(())
}

#[tokio::test]
async fn long_native_burst_resamples_time_instead_of_renewing_first_unit_deadline() -> TestResult {
    let rt = runtime(PacketLayer::Ip);
    let transport = udp_transport(
        Duplex::Full,
        CoverProfile::OpenVpnLike,
        Protection::HmacSha256,
    )?;
    let config = Config::for_udp(rt, transport, 4, options())?;
    let (a_link, b_link, relays) = udp_links(rt, transport, config, false).await?;
    let mut a = Device::new(rt.layer);
    a.service_delay = Duration::from_millis(2); // Exceeds the original 1 ms hold.
    let b = Device::new(rt.layer);
    let input: Vec<_> = (1..=6).map(|seed| packet(rt.layer, seed, 64)).collect();
    a.change(|s| s.outgoing.extend(input.iter().cloned()))?;
    let mut tasks = JoinSet::new();
    tasks.spawn(run_udp(a.clone(), a_link, rt, transport, config));
    tasks.spawn(run_udp(b.clone(), b_link, rt, transport, config));
    timeout(Duration::from_secs(2),async {
        while b.change(|s|s.delivered.len())? !=input.len() {
            tokio::select! {Some(result)=tasks.join_next()=>return Err(io::Error::other(format!("slow packed actor ended: {result:?}"))),_=sleep(Duration::from_millis(1))=>{}}
        }
        Ok::<_,io::Error>(())
    }).await??;
    assert!(relays.observations.packed_sources.load(Ordering::Relaxed) >= input.len());
    assert_eq!(
        relays.observations.packed_max_units.load(Ordering::Relaxed),
        1
    );
    let mut actual = b.change(|s| s.delivered.clone())?;
    actual.sort();
    let mut expected = input;
    expected.sort();
    assert_eq!(actual, expected);
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    Ok(())
}

#[tokio::test]
async fn wrong_bound_runtime_is_rejected_before_any_device_read_and_control_eof_stops_peer()
-> TestResult {
    let rt = runtime(PacketLayer::Ip);
    let transport = udp_transport(
        Duplex::Full,
        CoverProfile::OpenVpnLike,
        Protection::HmacSha256,
    )?;
    let config = Config::for_udp(rt, transport, 4, options())?;
    let (a, b, _relays) = udp_links(rt, transport, config, false).await?;
    let device = Device::new(rt.layer);
    device.change(|state| state.outgoing.push_back(packet(rt.layer, 1, 100)))?;
    let mut changed = config;
    changed.protocol.base.receiver.record_window -= 1;
    assert!(
        run_udp(device.clone(), a, rt, transport, changed)
            .await
            .is_err()
    );
    assert_eq!(device.change(|state| state.admitted)?, 0);
    assert!(
        timeout(
            Duration::from_secs(2),
            run_udp(Device::new(rt.layer), b, rt, transport, config)
        )
        .await?
        .is_err()
    );
    Ok(())
}

#[tokio::test]
async fn native_wouldblock_expires_without_fabricating_delivery_credit() -> TestResult {
    let rt = runtime(PacketLayer::Ip);
    let mut transport = udp_transport(
        Duplex::Full,
        CoverProfile::OpenVpnLike,
        Protection::HmacSha256,
    )?;
    transport.arq.initial_rto = Duration::from_millis(100);
    transport.arq.maximum_rto = Duration::from_millis(100);
    transport.arq.max_retries = 0;
    transport.reassembly_timeout = Duration::from_millis(200);
    let config = Config::for_udp(rt, transport, 4, options())?;
    let (a_link, b_link, _relays) = udp_links(rt, transport, config, false).await?;
    let a = Device::new(rt.layer);
    let b = Device::new(rt.layer);
    a.change(|state| state.outgoing.push_back(packet(rt.layer, 1, 100)))?;
    b.change(|state| state.blocked = true)?;
    let a_task = tokio::spawn(run_udp(a, a_link, rt, transport, config));
    let result = timeout(
        Duration::from_secs(2),
        run_udp(b.clone(), b_link, rt, transport, config),
    )
    .await?;
    assert!(
        result
            .err()
            .ok_or("expected expiry")?
            .to_string()
            .contains("Expired")
    );
    assert!(b.change(|state| state.delivered.is_empty())?);
    a_task.abort();
    let _ = a_task.await;
    Ok(())
}

#[tokio::test]
async fn packed_retirement_churn_keeps_recovery_and_native_held_bytes() -> TestResult {
    for duplex in [Duplex::Full, Duplex::Half] {
        let mut rt = runtime(PacketLayer::Ip);
        rt.queue_packets = 2;
        let transport = udp_transport(duplex, CoverProfile::QuicLike, Protection::HmacSha256)?;
        let mut config = Config::for_udp(rt, transport, 4, options())?;
        config.pipeline.flows.capacity = 4;
        config.pipeline.flows.idle_timeout = Duration::from_millis(10);
        let (a_link, b_link, relays) = udp_links(rt, transport, config, true).await?;
        let a = Device::new(rt.layer);
        let b = Device::new(rt.layer);
        let mut tasks = JoinSet::new();
        tasks.spawn(run_udp(a.clone(), a_link, rt, transport, config));
        tasks.spawn(run_udp(b.clone(), b_link, rt, transport, config));
        let input = (1..17)
            .map(|n| packet(rt.layer, n, 100 + usize::from(n)))
            .collect::<Vec<_>>();
        let reverse = (21..37)
            .map(|n| packet(rt.layer, n, 100 + usize::from(n)))
            .collect::<Vec<_>>();
        a.change(|state| state.outgoing.extend(input.iter().cloned()))?;
        b.change(|state| {
            state.blocked = true;
            state.outgoing.extend(reverse.iter().cloned());
        })?;
        sleep(Duration::from_millis(70)).await;
        assert!(b.change(|state| state.delivered.is_empty())?);
        b.change(|state| state.blocked = false)?;
        wait_delivery(&mut tasks, &a, &b, input.len()).await?;
        for (device, mut expected) in [(&a, reverse), (&b, input)] {
            let mut actual = device.change(|state| state.delivered.clone())?;
            expected.sort();
            actual.sort();
            assert_eq!(actual, expected);
        }
        assert!(relays.observations.dropped.load(Ordering::Relaxed) > 0);
        assert!(relays.observations.reordered.load(Ordering::Relaxed) > 0);
        tasks.abort_all();
        while tasks.join_next().await.is_some() {}
    }
    Ok(())
}
