//! Actual authenticated carriers and independent native endpoints for the rolling pump.
use super::*;
use crate::Compression;
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
fn udp_transport(
    duplex: Duplex,
    cover: CoverProfile,
    protection: Protection,
) -> io::Result<udp::Config> {
    let mut config = udp::Config::new(duplex, cover, protection, 576, false)?;
    config.arq.initial_rto = Duration::from_millis(100);
    config.arq.maximum_rto = Duration::from_millis(200);
    config.arq.max_retries = 8;
    config.control_timeout = Duration::from_secs(3);
    config.heartbeat_interval = Duration::from_millis(20);
    config.reassembly_timeout = Duration::from_secs(5);
    Ok(config)
}
fn quic_transport(duplex: Duplex) -> io::Result<quic::Config> {
    let mut config = quic::Config::new(duplex, *b"rolling-test-001", 1400, false)?;
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
    blocked_writes: usize,
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
            if state.blocked {
                state.blocked_writes += 1;
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
    if layer == PacketLayer::Ethernet && bytes.len() >= 28 {
        bytes[20..24].copy_from_slice(b"L2RF");
        bytes[24..28].copy_from_slice(b"L2RC");
    }
    bytes
}
fn frames(layer: PacketLayer) -> Result<Vec<Vec<u8>>, TestError> {
    Ok((1..9)
        .map(|value| {
            packet(
                layer,
                value,
                if value == 8 {
                    3500
                } else {
                    64 + usize::from(value) * 17
                },
            )
        })
        .collect())
}
fn small(mut value: Config) -> Config {
    let c = &mut value.scheduler.recovery;
    c.window = 8;
    c.local_window = 3;
    c.global_every = 2;
    c.max_rows = 8;
    c.handoff_sources = 2;
    c.repair_history = 32;
    value.scheduler.repair_denominator = 3;
    value.scheduler.tail_ticks = 10;
    value.scheduler.feedback_ticks = 3;
    value.scheduler.feedback_packets = 2;
    value
}
#[derive(Default)]
struct Observations {
    dropped: AtomicUsize,
    reordered: AtomicUsize,
    largest: AtomicUsize,
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
    let cert = rcgen::generate_simple_self_signed(vec!["rolling.test".to_owned()])?;
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
                "rolling.test",
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
    let cert = rcgen::generate_simple_self_signed(vec!["rolling.test".to_owned()])?;
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
            client.connect(peer, "rolling.test", &member, base),
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
            tokio::select! {Some(result)=tasks.join_next()=>return Err(io::Error::other(format!("rolling runtime ended: {result:?}"))),_=sleep(Duration::from_millis(2))=>{}}
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
    // Observe actual receiver pressure before releasing it. A fixed sleep also
    // succeeds when neither actor has run and therefore tests no backpressure.
    timeout(Duration::from_secs(8), async {
        while b.change(|state| state.blocked_writes)? == 0 {
            tokio::select! {
                Some(result) = tasks.join_next() => {
                    return Err(io::Error::other(format!("rolling runtime ended before pressure: {result:?}")));
                },
                _ = sleep(Duration::from_millis(2)) => {}
            }
        }
        Ok::<_, io::Error>(())
    })
    .await??;
    assert!(b.change(|state| state.delivered.is_empty())?);
    assert!(
        a.change(|state| state.admitted)? <= 6,
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
async fn actual_udp_rolling_tap_tun_full_half_covers_and_suites_with_loss_and_backpressure()
-> TestResult {
    for duplex in [Duplex::Full, Duplex::Half] {
        for layer in [PacketLayer::Ethernet, PacketLayer::Ip] {
            for cover in [CoverProfile::OpenVpnLike, CoverProfile::QuicLike] {
                for protection in [Protection::ChaCha20Poly1305, Protection::HmacSha256] {
                    let rt = runtime(layer);
                    let transport = udp_transport(duplex, cover, protection)?;
                    let config = small(Config::for_udp(
                        rt,
                        transport,
                        4,
                        crate::rolling::config::test_delivery(rt),
                    )?);
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
                    tasks.abort_all();
                    while tasks.join_next().await.is_some() {}
                }
            }
        }
    }
    Ok(())
}
#[tokio::test]
async fn actual_quic_rolling_tap_tun_full_half_with_loss_and_backpressure() -> TestResult {
    for duplex in [Duplex::Full, Duplex::Half] {
        for layer in [PacketLayer::Ethernet, PacketLayer::Ip] {
            let rt = runtime(layer);
            let transport = quic_transport(duplex)?;
            let config = small(Config::for_quic(
                rt,
                transport,
                4,
                crate::rolling::config::test_delivery(rt),
            )?);
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
fn full_policy_is_bound_and_geometry_rejected_before_authentication() -> TestResult {
    let rt = runtime(PacketLayer::Ip);
    let transport = udp_transport(
        Duplex::Full,
        CoverProfile::OpenVpnLike,
        Protection::HmacSha256,
    )?;
    let config = small(Config::for_udp(
        rt,
        transport,
        4,
        crate::rolling::config::test_delivery(rt),
    )?);
    let base = udp_base_session_config(rt, transport, config)?;
    assert_ne!(base, udp::base_session_config(rt, transport)?);
    for mutation in 0..13 {
        let mut changed = config;
        match mutation {
            0 => changed.epoch += 1,
            1 => changed.stream += 1,
            2 => changed.scheduler.repair_numerator = 2,
            3 => changed.scheduler.tail_ticks += 1,
            4 => changed.scheduler.feedback_ticks += 1,
            5 => changed.scheduler.feedback_packets += 1,
            6 => changed.scheduler.recovery.local_window += 1,
            7 => changed.scheduler.recovery.handoff_ticks += 1,
            8 => changed.work.field += 1,
            9 => changed.passes_per_turn += 1,
            10 => changed.pipeline.flows.idle_timeout += Duration::from_secs(1),
            11 => changed.delivery.forward.target_bandwidth_bps += 1,
            _ => changed.delivery.reverse.max_records += 1,
        }
        assert_ne!(base, udp_base_session_config(rt, transport, changed)?);
    }
    for mutation in 0..7 {
        let mut changed = config;
        match mutation {
            0 => changed.epoch = 0,
            1 => changed.work.metadata = 0,
            2 => changed.passes_per_turn = 65,
            3 => changed.scheduler.recovery.max_payload += 1,
            4 => changed.pipeline.flows.mapping = pipeline::Mapping::ConnectionRoundRobin,
            5 => changed.pipeline.profile = pipeline::Profile::TapSystem,
            _ => {
                changed.delivery.forward.metadata_limit_bytes =
                    changed.delivery.forward.metadata_bytes()?
            }
        }
        assert!(udp_base_session_config(rt, transport, changed).is_err());
    }
    Ok(())
}
#[tokio::test]
async fn changed_binding_rejects_before_device_read_and_original_control_eof_stops_peer()
-> TestResult {
    let rt = runtime(PacketLayer::Ip);
    let transport = udp_transport(
        Duplex::Full,
        CoverProfile::OpenVpnLike,
        Protection::HmacSha256,
    )?;
    let config = small(Config::for_udp(
        rt,
        transport,
        4,
        crate::rolling::config::test_delivery(rt),
    )?);
    let (a, b, _relays) = udp_links(rt, transport, config, false).await?;
    let device = Device::new(rt.layer);
    device.change(|s| s.outgoing.push_back(packet(rt.layer, 1, 100)))?;
    let mut changed = config;
    changed.stream += 1;
    assert!(
        run_udp(device.clone(), a, rt, transport, changed)
            .await
            .is_err()
    );
    assert_eq!(device.change(|s| s.admitted)?, 0);
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

#[test]
fn owner_feedback_loss_stale_tail_repeats_receipt_without_native_credit_or_sender_ledger()
-> TestResult {
    let rt = runtime(PacketLayer::Ip);
    let transport = udp_transport(
        Duplex::Full,
        CoverProfile::OpenVpnLike,
        Protection::HmacSha256,
    )?;
    let mut config = small(Config::for_udp(
        rt,
        transport,
        4,
        crate::rolling::config::test_delivery(rt),
    )?);
    config.scheduler.repair_numerator = 0;
    config.scheduler.feedback_packets = 1;
    let (a_feedback, _) = watch::channel(udp::Feedback::default());
    let (b_feedback, _) = watch::channel(udp::Feedback::default());
    let mut a = State::new(
        LaneContext {
            session: [0x71; 16],
            index: 0,
            initiator: true,
        },
        rt,
        transport.policy()?,
        config,
        a_feedback,
        None,
    )?;
    let mut b = State::new(
        LaneContext {
            session: [0x71; 16],
            index: 0,
            initiator: false,
        },
        rt,
        transport.policy()?,
        config,
        b_feedback,
        None,
    )?;
    let mut a_pipeline = Pipeline::new(config.pipeline)?;
    let mut b_pipeline = Pipeline::new(config.pipeline)?;
    let input = packet(rt.layer, 1, 100);
    a_pipeline.enqueue(input.clone(), Duration::ZERO)?;
    let selected = a_pipeline.dequeue()?.ok_or("common selected packet")?;
    assert!(a.admit(&selected, l2tunnel_flow_control::target::Micros(0))?);
    a.submit(protocol::Tick(0))?;
    let sender = a.sender.as_mut().ok_or("sender")?;
    let mut wire = vec![0; transport.policy()?.payload_bytes];
    let id = sender.pending_output().ok_or("source")?.id();
    let length = sender.encode_pending(&mut wire)?;
    sender.confirm_output(id, protocol::Tick(0))?;
    b.data(&wire[..length], protocol::Tick(0), config)?;
    for _ in 0..64 {
        b.service(protocol::Tick(0), config)?;
        b.reassemble(rt, config, protocol::Tick(0))?;
    }
    let receiver = b.receiver.as_mut().ok_or("receiver")?;
    let lost = receiver.pending_feedback().ok_or("receipt")?;
    assert_eq!(lost.prefix, 1);
    receiver.confirm_feedback(lost.id, protocol::Tick(0))?; // Reverse ownership, then loss.
    assert_eq!(b.feedback.borrow().credit, 0);
    assert_eq!(
        a.sender
            .as_ref()
            .ok_or("sender")?
            .status()
            .encoder
            .confirmed_prefix,
        0
    );
    for _ in 0..64 {
        a.service(protocol::Tick(10), config)?;
    }
    let sender = a.sender.as_mut().ok_or("sender")?;
    assert!(matches!(sender.pending_output(),Some(scheduler::Output::Repair(r)) if r.support.tail));
    let id = sender.pending_output().ok_or("tail")?.id();
    let length = sender.encode_pending(&mut wire)?;
    sender.confirm_output(id, protocol::Tick(10))?;
    b.data(&wire[..length], protocol::Tick(10), config)?;
    for _ in 0..64 {
        b.service(protocol::Tick(10), config)?;
    }
    let receiver = b.receiver.as_mut().ok_or("receiver")?;
    let fresh = receiver.pending_feedback().ok_or("fresh receipt")?;
    assert!(fresh.id > lost.id);
    let bytes = receiver
        .pending_feedback_wire()
        .ok_or("fresh wire")?
        .to_vec();
    receiver.confirm_feedback(fresh.id, protocol::Tick(10))?;
    a.control(
        udp::ControlEvent::Ack(bytes),
        protocol::Tick(10),
        l2tunnel_flow_control::target::Micros(10_000),
        l2tunnel_flow_control::target::Micros(10_000),
    )?;
    assert_eq!(a.sender.as_ref().ok_or("sender")?.deadline(), None);
    assert_eq!(b.feedback.borrow().credit, 0);
    let mut device = Device::new(rt.layer);
    device.change(|s| s.blocked = true)?;
    b.deliver(&mut device, &mut b_pipeline, || Ok(protocol::Tick(10)))?;
    assert_eq!(b.feedback.borrow().credit, 0);
    device.change(|s| s.blocked = false)?;
    b.deliver(&mut device, &mut b_pipeline, || Ok(protocol::Tick(11)))?;
    assert_eq!(device.change(|s| s.delivered.clone())?, vec![input]);
    assert_eq!(b.feedback.borrow().credit, 1);
    a.control(
        udp::ControlEvent::Credit(1),
        protocol::Tick(11),
        l2tunnel_flow_control::target::Micros(11_000),
        l2tunnel_flow_control::target::Micros(11_000),
    )?;
    assert!(
        a.control(
            udp::ControlEvent::Credit(2),
            protocol::Tick(11),
            l2tunnel_flow_control::target::Micros(11_000),
            l2tunnel_flow_control::target::Micros(11_000)
        )
        .is_err()
    );
    Ok(())
}

#[tokio::test]
async fn actual_authenticated_wrong_scope_and_credit_cannot_enter_native_path() -> TestResult {
    use tokio::io::AsyncWriteExt;
    for credit in [false, true] {
        let rt = runtime(PacketLayer::Ip);
        let transport = udp_transport(
            Duplex::Full,
            CoverProfile::OpenVpnLike,
            Protection::HmacSha256,
        )?;
        let config = small(Config::for_udp(
            rt,
            transport,
            4,
            crate::rolling::config::test_delivery(rt),
        )?);
        let (a, b, _relays) = udp_links(rt, transport, config, false).await?;
        let (mut parts, _) =
            a.0.into_bound_parts(udp_base_session_config(rt, transport, config)?)?;
        let mut part = parts.pop().ok_or("actual retained carrier")?;
        let device = Device::new(rt.layer);
        let task = tokio::spawn(run_udp(device.clone(), b, rt, transport, config));
        if credit {
            part.control.write_all(b"L2RC\x01\x03\0\x08").await?;
            part.control.write_all(&1_u64.to_be_bytes()).await?;
            part.control.flush().await?;
        } else {
            let scope = protocol::Scope {
                session: part.session,
                epoch: config.epoch,
                stream: config.stream,
                direction: 1,
            };
            let mut bytes =
                vec![0; protocol::wire::HEADER_BYTES + config.scheduler.recovery.width()?];
            protocol::wire::encode_source(
                config.scheduler.recovery,
                scope,
                protocol::SourceId(0),
                b"bad scope",
                &mut bytes,
            )?;
            part.sender.send(&bytes).await?;
        }
        let result = timeout(Duration::from_secs(2), task).await??;
        assert!(result.is_err());
        let message = result.err().ok_or("rejection")?.to_string();
        assert!(
            message.contains(if credit {
                "native credit"
            } else {
                "scope mismatch"
            }),
            "{message}"
        );
        assert!(device.change(|s| s.delivered.is_empty())?);
    }
    Ok(())
}

#[tokio::test]
async fn actual_blocked_native_expires_at_original_handoff_without_delivery() -> TestResult {
    let rt = runtime(PacketLayer::Ip);
    let transport = udp_transport(
        Duplex::Full,
        CoverProfile::OpenVpnLike,
        Protection::HmacSha256,
    )?;
    let mut config = small(Config::for_udp(
        rt,
        transport,
        4,
        crate::rolling::config::test_delivery(rt),
    )?);
    config.scheduler.recovery.handoff_ticks = 50;
    let (a_link, b_link, _relays) = udp_links(rt, transport, config, false).await?;
    let a = Device::new(rt.layer);
    let b = Device::new(rt.layer);
    a.change(|s| s.outgoing.push_back(packet(rt.layer, 1, 100)))?;
    b.change(|s| s.blocked = true)?;
    let a_task = tokio::spawn(run_udp(a, a_link, rt, transport, config));
    let result = timeout(
        Duration::from_secs(2),
        run_udp(b.clone(), b_link, rt, transport, config),
    )
    .await?;
    assert_eq!(
        result.err().ok_or("original expiry")?.kind(),
        io::ErrorKind::TimedOut
    );
    assert!(b.change(|s| s.delivered.is_empty())?);
    a_task.abort();
    let _ = a_task.await;
    Ok(())
}

#[tokio::test]
async fn rolling_flow_churn_preserves_full_half_recovery_native_and_reverse_affinity() -> TestResult
{
    for duplex in [Duplex::Full, Duplex::Half] {
        let rt = runtime(PacketLayer::Ip);
        let transport = udp_transport(duplex, CoverProfile::OpenVpnLike, Protection::HmacSha256)?;
        let mut config = small(Config::for_udp(
            rt,
            transport,
            4,
            crate::rolling::config::test_delivery(rt),
        )?);
        config.pipeline.flows.capacity = 4;
        config.pipeline.flows.idle_timeout = Duration::from_millis(10);
        let (a_link, b_link, relays) = udp_links(rt, transport, config, true).await?;
        let a = Device::new(rt.layer);
        let b = Device::new(rt.layer);
        let forward = (1..17)
            .map(|n| packet(rt.layer, n, 100 + usize::from(n)))
            .collect::<Vec<_>>();
        let reverse = (21..37)
            .map(|n| packet(rt.layer, n, 100 + usize::from(n)))
            .collect::<Vec<_>>();
        a.change(|v| v.outgoing.extend(forward.iter().cloned()))?;
        b.change(|v| {
            v.blocked = true;
            v.outgoing.extend(reverse.iter().cloned());
        })?;
        let mut tasks = JoinSet::new();
        tasks.spawn(run_udp(a.clone(), a_link, rt, transport, config));
        tasks.spawn(run_udp(b.clone(), b_link, rt, transport, config));
        sleep(Duration::from_millis(70)).await;
        assert!(b.change(|v| v.delivered.is_empty())?);
        b.change(|v| v.blocked = false)?;
        wait_delivery(&mut tasks, &a, &b, forward.len()).await?;
        for (device, mut expected) in [(&a, reverse), (&b, forward)] {
            let mut actual = device.change(|v| v.delivered.clone())?;
            expected.sort();
            actual.sort();
            assert_eq!(actual, expected);
        }
        assert!(relays.observations.dropped.load(Ordering::Relaxed) > 0);
        tasks.abort_all();
        while tasks.join_next().await.is_some() {}
    }
    Ok(())
}
