//! Actual authenticated carriers and independent native endpoints for the aligned pump.
use super::*;
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
        queue_packets: 2,
        poll_interval: Duration::from_millis(1),
    }
}
fn delivery(runtime: RuntimeConfig) -> crate::managed::DeliveryConfig {
    let policy = l2tunnel_flow_control::delivery_window::Config {
        target_bandwidth_bps: 80_000_000,
        bootstrap_rtt_micros: 70_000,
        min_rtt_micros: 2_000,
        max_rtt_micros: 2_000_000,
        headroom_percent: 125,
        minimum_bytes: runtime.max_packet as u64,
        max_inflight_bytes: 4 * 1024 * 1024,
        max_records: runtime.queue_packets,
        max_packet_bytes: runtime.max_packet as u64,
        metadata_limit_bytes: 2 * 1024 * 1024,
        sample_ttl_micros: 1_000_000,
        flush_timeout_micros: 10_000_000,
    };
    crate::managed::DeliveryConfig {
        forward: policy,
        reverse: policy,
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
}
impl Device {
    fn new(layer: PacketLayer) -> Self {
        Self {
            layer,
            state: Arc::new(Mutex::new(Native::default())),
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
    Ok(frames)
}
#[derive(Default)]
struct Observations {
    dropped: AtomicUsize,
    reordered: AtomicUsize,
    largest: AtomicUsize,
    aligned_context: AtomicUsize,
    aligned_predictive: AtomicUsize,
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
                    // Read-only cleartext evidence is available only in integrity mode.
                    if let Some(offset)=input[..length].windows(5).position(|bytes|bytes==b"L2AS\x01") && length>=offset+52 {
                        let kind=input[offset+51];
                        if kind==0 {observations.aligned_context.fetch_add(1,Ordering::Relaxed);}
                        if kind==6 || kind&7==5 || kind&7==7 {observations.aligned_predictive.fetch_add(1,Ordering::Relaxed);}
                    }
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
        let binding = udp_session_config(rt, transport, config, lane)?;
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
            l2tunnel_udp::establish(
                a_tls,
                a,
                udp_carrier_config(rt, transport, config, lane, peer)?
            ),
            l2tunnel_udp::establish(
                b_tls,
                b,
                udp_carrier_config(rt, transport, config, lane, peer)?
            )
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
    timeout(Duration::from_secs(2), async {
        loop {
            if b.change(|state| state.writes > 0)? { return Ok::<_, io::Error>(()); }
            tokio::select! {
                Some(result) = tasks.join_next() => return Err(io::Error::other(format!("runtime ended before actual native pressure: {result:?}"))),
                _ = sleep(Duration::from_millis(1)) => {},
            }
        }
    }).await??;
    assert!(b.change(|state| state.delivered.is_empty())?);
    assert!(
        a.change(|state| state.admitted)? <= 2 * runtime(a.layer).queue_packets + 2,
        "configured flight records plus local queue, ingress and selected packet bound reads"
    );
    b.change(|state| state.blocked = false)?;
    wait_delivery(tasks, a, b, input.len()).await?;
    let mut expected = input.to_vec();
    expected.sort();
    for device in [a, b] {
        let mut actual = device.change(|state| state.delivered.clone())?;
        actual.sort();
        assert_eq!(actual, expected);
        // Classification uses the same parser as the actor. Global channel
        // interleaving is allowed, but one flow must keep its original order.
        let actual_order = device.change(|state| state.delivered.clone())?;
        let rt = runtime(device.layer);
        let transport = udp_transport(
            Duplex::Full,
            CoverProfile::OpenVpnLike,
            Protection::HmacSha256,
        )?;
        let classifier = Pipeline::new(Config::for_udp(rt, transport, 4, delivery(rt))?.pipeline)?;
        for frame in input {
            let key = classifier.classify(frame)?.key;
            let wanted: Vec<_> = input
                .iter()
                .filter(|p| classifier.classify(p).is_ok_and(|p| p.key == key))
                .collect();
            let observed: Vec<_> = actual_order
                .iter()
                .filter(|p| classifier.classify(p).is_ok_and(|p| p.key == key))
                .collect();
            assert_eq!(observed, wanted, "one native flow reordered");
        }
    }
    Ok(())
}
#[tokio::test]
async fn actual_udp_aligned_tap_tun_full_half_covers_and_suites_with_loss_and_backpressure()
-> TestResult {
    for duplex in [Duplex::Full, Duplex::Half] {
        for layer in [PacketLayer::Ethernet, PacketLayer::Ip] {
            for cover in [CoverProfile::OpenVpnLike, CoverProfile::QuicLike] {
                for protection in [Protection::ChaCha20Poly1305, Protection::HmacSha256] {
                    let rt = runtime(layer);
                    let transport = udp_transport(duplex, cover, protection)?;
                    let config = Config::for_udp(rt, transport, 4, delivery(rt))?;
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
                    if layer == PacketLayer::Ethernet && protection == Protection::HmacSha256 {
                        assert!(relays.observations.aligned_context.load(Ordering::Relaxed) > 0);
                        assert!(
                            relays
                                .observations
                                .aligned_predictive
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
async fn actual_quic_aligned_tap_tun_full_half_without_tcp_with_loss_and_backpressure() -> TestResult
{
    for duplex in [Duplex::Full, Duplex::Half] {
        for layer in [PacketLayer::Ethernet, PacketLayer::Ip] {
            let rt = runtime(layer);
            let transport = quic_transport(duplex)?;
            let config = Config::for_quic(rt, transport, 4, delivery(rt))?;
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
#[test]
fn configuration_rejects_unimplemented_or_inconsistent_policies_and_binds_every_profile()
-> TestResult {
    let rt = runtime(PacketLayer::Ethernet);
    let transport = udp_transport(
        Duplex::Full,
        CoverProfile::OpenVpnLike,
        Protection::HmacSha256,
    )?;
    let config = Config::for_udp(rt, transport, 4, delivery(rt))?;
    let base = udp_base_session_config(rt, transport, config)?;
    // The required v2 byte/identity policy must reject this historical v1 digest.
    assert_ne!(
        base.digest.0,
        [
            161, 123, 239, 214, 7, 22, 246, 234, 53, 233, 88, 139, 15, 167, 254, 188, 105, 58, 234,
            141, 21, 208, 14, 39, 175, 96, 80, 17, 225, 66, 168, 100
        ]
    );
    assert_ne!(base, udp::base_session_config(rt, transport)?);
    let mut changed = config;
    changed.protocol.receiver.body.predictive = false;
    changed.protocol.receiver.body.timestamp_pair_dictionary = false;
    assert_ne!(base, udp_base_session_config(rt, transport, changed)?);
    changed = config;
    changed.pipeline.flows.mapping = pipeline::Mapping::ConnectionRoundRobin;
    assert!(udp_base_session_config(rt, transport, changed).is_err());
    changed = config;
    changed.protocol.native_policy = NativePolicy::RawIp;
    assert!(udp_base_session_config(rt, transport, changed).is_err());
    changed = config;
    changed.pipeline.profile = pipeline::Profile::TunDrr(pipeline::TunQosConfig {
        base_quantum_bytes: 100,
        max_weight: 1,
        per_flow: changed.pipeline.queue,
    });
    assert!(udp_base_session_config(rt, transport, changed).is_err());
    let mut wrong = rt;
    wrong.compression = Compression::Lz4IfSmaller;
    assert!(Config::for_udp(wrong, transport, 4, delivery(wrong)).is_err());
    assert!(
        Config::for_udp(
            rt,
            transport.with_recovery(udp::RecoveryMode::SelectiveRepeat)?,
            4,
            delivery(rt)
        )
        .is_err()
    );
    assert!(Config::for_udp(rt, transport, 0, delivery(rt)).is_err());
    assert_eq!(config.protocol.recovery.outer_overhead_bytes, 0);
    assert!(config.protocol.receiver.body.symbol_bytes + 48 == transport.arq.max_source_bytes);
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
    let config = Config::for_udp(rt, transport, 4, delivery(rt))?;
    let (a, b, _relays) = udp_links(rt, transport, config, false).await?;
    let device = Device::new(rt.layer);
    device.change(|state| state.outgoing.push_back(packet(rt.layer, 1, 100)))?;
    let mut changed = config;
    changed.protocol.receiver.record_window -= 1;
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
async fn authenticated_raw_policy_and_native_credit_violations_fail_closed() -> TestResult {
    for bad_headers in [false, true] {
        let rt = runtime(PacketLayer::Ip);
        let transport = udp_transport(
            Duplex::Full,
            CoverProfile::OpenVpnLike,
            Protection::HmacSha256,
        )?;
        let config = Config::for_udp(rt, transport, 4, delivery(rt))?;
        let (a, b, _relays) = udp_links(rt, transport, config, false).await?;
        let (mut parts, _) =
            a.0.into_bound_parts(udp_base_session_config(rt, transport, config)?)?;
        let mut part = parts.pop().ok_or("attacker parts")?;
        let mut malicious = config.protocol;
        if bad_headers {
            malicious.native_policy = NativePolicy::EthernetHeaders;
            malicious.receiver.body.elide_payload_length = true;
            malicious.receiver.body.predictive = true;
            malicious.receiver.body.timestamp_pair_dictionary = true;
        }
        let mut endpoint = protocol::Endpoint::new(
            malicious,
            RecoveryContext {
                session: u128::from_be_bytes(part.session),
                epoch: 1,
                role: EndpointRole::Initiator,
            },
        )?;
        let input = if bad_headers {
            frames(PacketLayer::Ethernet)?[..1].to_vec()
        } else {
            (1..=3)
                .map(|value| packet(PacketLayer::Ip, value, 100))
                .collect()
        };
        let mut mapper = Pipeline::new(config.pipeline)?;
        for bytes in input {
            let channel = if bad_headers {
                0
            } else {
                let metadata = mapper.enqueue(bytes.clone(), Duration::ZERO)?;
                mapper.dequeue()?.ok_or("selected native")?;
                u8::try_from(metadata.binding.channel)?
            };
            endpoint.enqueue_admitted(protocol::ChannelId(channel), &bytes, Duration::ZERO)?;
        }
        let device = Device::new(rt.layer);
        device.change(|state| state.blocked = true)?;
        let task = tokio::spawn(run_udp(device.clone(), b, rt, transport, config));
        let mut budget = l2tunnel_reliable::OutboundBudget {
            packets: 64,
            wire_bytes: 64 * transport.path_mtu,
        };
        let mut output = vec![0; endpoint.max_packet_bytes()];
        for millis in [0, 3] {
            while let Some(length) =
                endpoint.poll_data(Duration::from_millis(millis), &mut output, &mut budget)?
            {
                part.sender.send(&output[..length]).await?;
            }
        }
        let result = timeout(Duration::from_secs(2), task).await??;
        assert!(result.is_err());
        let description = result.err().ok_or("expected rejection")?.to_string();
        assert!(
            description.contains(if bad_headers {
                "Policy"
            } else {
                "native delivery capacity"
            }),
            "{description}"
        );
        assert!(device.change(|state| state.delivered.is_empty())?);
    }
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
    let config = Config::for_udp(rt, transport, 4, delivery(rt))?;
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

#[path = "aligned_flow_tests.rs"]
mod flow_retirement;

#[tokio::test]
async fn actual_byte_flight_exceeds64_with_local2_and_real_native_pressure() -> TestResult {
    for duplex in [Duplex::Full, Duplex::Half] {
        for layer in [PacketLayer::Ethernet, PacketLayer::Ip] {
            for use_quic in [false, true] {
                let mut rt = runtime(layer);
                rt.queue_packets = 2;
                let mut native_delivery = delivery(rt);
                native_delivery.forward.max_records = 128;
                native_delivery.reverse.max_records = 128;
                native_delivery.forward.max_inflight_bytes = 131072;
                native_delivery.reverse.max_inflight_bytes = 131072;
                let a = Device::new(layer);
                let b = Device::new(layer);
                let input: Vec<_> = (0..128)
                    .map(|index| {
                        let mut bytes = packet(
                            layer,
                            (index % 4 + 1) as u8,
                            if index % 2 == 0 { 1500 } else { 40 },
                        );
                        if let Some(last) = bytes.last_mut() {
                            *last = index as u8;
                        }
                        bytes
                    })
                    .collect();
                let actual_bytes: u64 = input.iter().map(|p| p.len() as u64).sum();
                assert_eq!(actual_bytes, 64 * 1540);
                a.change(|n| {
                    n.blocked = true;
                    n.outgoing.extend(input.iter().cloned());
                })?;
                b.change(|n| {
                    n.blocked = true;
                    n.outgoing.extend(input.iter().cloned());
                })?;
                let (a_observer, a_status) = tokio::sync::watch::channel(ActorStatus::default());
                let (b_observer, b_status) = tokio::sync::watch::channel(ActorStatus::default());
                let mut tasks = JoinSet::new();
                let relays;
                if use_quic {
                    let transport = quic_transport(duplex)?;
                    let config = Config::for_quic(rt, transport, 4, native_delivery)?;
                    assert_eq!(config.pipeline.queue.packets, 2);
                    let (a_link, b_link, owned) = quic_links(rt, transport, config).await?;
                    relays = owned;
                    let binding = quic_base_session_config(rt, transport, config)?;
                    let (a_parts, ai) = a_link.0.into_bound_parts(binding)?;
                    let (b_parts, bi) = b_link.0.into_bound_parts(binding)?;
                    tasks.spawn(run_parts_observed(
                        a.clone(),
                        a_parts,
                        ai,
                        rt,
                        transport.policy()?,
                        Selection::Aligned(config),
                        Some(a_observer),
                    ));
                    tasks.spawn(run_parts_observed(
                        b.clone(),
                        b_parts,
                        bi,
                        rt,
                        transport.policy()?,
                        Selection::Aligned(config),
                        Some(b_observer),
                    ));
                } else {
                    let transport =
                        udp_transport(duplex, CoverProfile::OpenVpnLike, Protection::HmacSha256)?;
                    let config = Config::for_udp(rt, transport, 4, native_delivery)?;
                    assert_eq!(config.pipeline.queue.packets, 2);
                    let (a_link, b_link, owned) = udp_links(rt, transport, config, false).await?;
                    relays = owned;
                    let binding = udp_base_session_config(rt, transport, config)?;
                    let (a_parts, ai) = a_link.0.into_bound_parts(binding)?;
                    let (b_parts, bi) = b_link.0.into_bound_parts(binding)?;
                    tasks.spawn(run_parts_observed(
                        a.clone(),
                        a_parts,
                        ai,
                        rt,
                        transport.policy()?,
                        Selection::Aligned(config),
                        Some(a_observer),
                    ));
                    tasks.spawn(run_parts_observed(
                        b.clone(),
                        b_parts,
                        bi,
                        rt,
                        transport.policy()?,
                        Selection::Aligned(config),
                        Some(b_observer),
                    ));
                }
                timeout(Duration::from_secs(3), async {
                    loop {
                        let ready = [&a_status, &b_status].iter().all(|status| {
                            status.borrow().flight.iter().flatten().any(|s| s.outstanding.records > 64 && s.flushed_total.records > 64 && s.delivered.records == 0)
                        });
                        if ready && a.change(|n| n.writes > 0)? && b.change(|n| n.writes > 0)? { return Ok::<_, io::Error>(()); }
                        tokio::select! {
                            Some(result) = tasks.join_next() => return Err(io::Error::other(format!("actor ended under native pressure: {result:?}"))),
                            _ = sleep(Duration::from_millis(1)) => {},
                        }
                    }
                }).await.map_err(|error| format!("{duplex:?}/{layer:?}/quic={use_quic} pressure/debt: {error}; a={:?}; b={:?}; native_counts={:?}/{:?}", *a_status.borrow(), *b_status.borrow(), a.change(|n| (n.admitted,n.writes,n.delivered.len())), b.change(|n| (n.admitted,n.writes,n.delivered.len()))))??;
                for status in [&a_status, &b_status] {
                    let snapshot = *status.borrow();
                    let flight = snapshot
                        .flight
                        .iter()
                        .flatten()
                        .find(|s| s.outstanding.records > 64 && s.flushed_total.records > 64)
                        .ok_or("missing actual debt and completed first sends")?;
                    // Prove a larger link flight under actual native pressure,
                    // without making all 128 first sends a throughput deadline.
                    assert_eq!(flight.outstanding, flight.admitted);
                    assert!(flight.admitted.records <= input.len() as u64);
                    assert!(flight.admitted.bytes <= actual_bytes);
                    assert!(flight.flushed_total.records <= flight.admitted.records);
                    assert!(flight.flushed_total.bytes <= flight.admitted.bytes);
                    assert_eq!(flight.delivered.records, 0);
                    assert_eq!(flight.delivered.bytes, 0);
                    assert!(flight.retained_records <= native_delivery.forward.max_records);
                }
                for device in [&a, &b] {
                    assert!(device.change(|n| n.delivered.is_empty())?);
                    device.change(|n| n.blocked = false)?;
                }
                wait_delivery(&mut tasks, &a, &b, input.len()).await.map_err(|error| format!("{duplex:?}/{layer:?}/quic={use_quic} native delivery: {error}; a={:?}; b={:?}", *a_status.borrow(), *b_status.borrow()))?;
                timeout(Duration::from_secs(2), async {
                    loop {
                        if [&a_status, &b_status].iter().all(|s| s.borrow().flight.iter().flatten().all(|f| f.outstanding.records == 0 && f.retained_records == 0)) { return Ok::<_, io::Error>(()); }
                        tokio::select! {
                            Some(result) = tasks.join_next() => return Err(io::Error::other(format!("actor ended before exact native receipts: {result:?}"))),
                            _ = sleep(Duration::from_millis(1)) => {},
                        }
                    }
                }).await.map_err(|error| format!("{duplex:?}/{layer:?}/quic={use_quic} native receipt: {error}; a={:?}; b={:?}", *a_status.borrow(), *b_status.borrow()))??;
                for status in [&a_status, &b_status] {
                    let snapshot = *status.borrow();
                    let flights: Vec<_> = snapshot.flight.iter().flatten().collect();
                    assert!(!flights.is_empty(), "missing final sending-lane accounting");
                    for flight in flights {
                        for credit in [
                            flight.admitted,
                            flight.delivered,
                            flight.delivered_prefix,
                            flight.flushed,
                            flight.flushed_total,
                        ] {
                            assert_eq!(credit.records, input.len() as u64);
                            assert_eq!(credit.bytes, actual_bytes);
                        }
                        assert_eq!(flight.outstanding.records, 0);
                        assert_eq!(flight.outstanding.bytes, 0);
                        assert_eq!(flight.retained_records, 0);
                        assert!(flight.next_flush_deadline.is_none());
                    }
                }
                let transport =
                    udp_transport(duplex, CoverProfile::OpenVpnLike, Protection::HmacSha256)?;
                let config = Config::for_udp(rt, transport, 4, native_delivery)?;
                let classifier = l2tunnel_pipeline::Pipeline::new(config.pipeline)?;
                for device in [&a, &b] {
                    let delivered = device.change(|n| n.delivered.clone())?;
                    assert_eq!(delivered.len(), input.len());
                    assert_eq!(
                        delivered.iter().map(|p| p.len() as u64).sum::<u64>(),
                        actual_bytes
                    );
                    for frame in &input {
                        let key = classifier.classify(frame)?.key;
                        let expected: Vec<_> = input
                            .iter()
                            .filter(|p| classifier.classify(p).is_ok_and(|p| p.key == key))
                            .collect();
                        let actual: Vec<_> = delivered
                            .iter()
                            .filter(|p| classifier.classify(p).is_ok_and(|p| p.key == key))
                            .collect();
                        assert_eq!(actual, expected, "native per-flow FIFO changed");
                    }
                }
                tasks.abort_all();
                while tasks.join_next().await.is_some() {}
                drop(relays);
            }
        }
    }
    Ok(())
}
