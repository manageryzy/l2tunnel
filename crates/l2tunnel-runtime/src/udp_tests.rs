//! Actual TCP/TLS plus UDP integration; in-memory devices are independent endpoints.
use super::*;
use l2tunnel_auth::{
    ClientTls, MemberAllowlist, MemberKey, ServerTls, client_connect, server_accept,
};
use l2tunnel_device::PacketLayer;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

type TestError = Box<dyn std::error::Error + Send + Sync>;
type TestResult = Result<(), TestError>;

fn native_delivery(runtime: RuntimeConfig) -> crate::managed::DeliveryConfig {
    let policy = l2tunnel_flow_control::delivery_window::Config {
        target_bandwidth_bps: 80_000_000,
        bootstrap_rtt_micros: 70_000,
        min_rtt_micros: 2_000,
        max_rtt_micros: 2_000_000,
        headroom_percent: 125,
        minimum_bytes: runtime.max_packet as u64,
        max_inflight_bytes: (runtime.max_packet * runtime.queue_packets) as u64,
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
fn runtime(layer: PacketLayer) -> RuntimeConfig {
    RuntimeConfig {
        layer,
        max_packet: 4000,
        compression: Compression::None,
        queue_packets: 2,
        poll_interval: Duration::from_millis(1),
    }
}
fn config(duplex: Duplex, cover: CoverProfile, protection: Protection) -> io::Result<Config> {
    let mut config = Config::new(duplex, cover, protection, 576, false)?;
    config.arq.initial_rto = Duration::from_millis(25);
    config.arq.maximum_rto = Duration::from_millis(100);
    config.arq.ack_delay = Duration::from_millis(1);
    config.arq.max_retries = 20;
    config.control_timeout = Duration::from_secs(2);
    config.heartbeat_interval = Duration::from_millis(10);
    config.reassembly_timeout = Duration::from_secs(2);
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
            .map_err(|_| invalid("test device poisoned"))?;
        Ok(f(&mut guard))
    }
}
impl PacketDevice for Device {
    type Error = io::Error;
    fn layer(&self) -> PacketLayer {
        self.layer
    }
    fn receive(&mut self, buffer: &mut [u8]) -> io::Result<Option<usize>> {
        if buffer.len() < l2tunnel_device::READ_BUFFER_BYTES {
            return Err(invalid("native maximum-plus-one sentinel required"));
        }
        self.change(|native| {
            native.outgoing.pop_front().map(|packet| {
                buffer[..packet.len()].copy_from_slice(&packet);
                native.admitted += 1;
                packet.len()
            })
        })
    }
    fn transmit(&mut self, packet: &[u8]) -> io::Result<()> {
        self.change(|native| {
            if native.blocked {
                return Err(io::ErrorKind::WouldBlock.into());
            }
            native.delivered.push(packet.to_vec());
            Ok(())
        })?
    }
}
fn packet(layer: PacketLayer, value: u8, length: usize) -> Vec<u8> {
    let mut bytes: Vec<u8> = (0..length)
        .map(|index| (index.wrapping_mul(17) as u8) ^ value)
        .collect();
    if layer == PacketLayer::Ip {
        bytes[0] = 0x45;
        bytes[2..4].copy_from_slice(&(length as u16).to_be_bytes());
    } else {
        bytes[12..14].copy_from_slice(&0x88b5_u16.to_be_bytes());
        bytes[14..18].copy_from_slice(b"L2MC");
    }
    bytes
}
#[derive(Default)]
struct Relays {
    tasks: JoinSet<io::Result<()>>,
    packets: Arc<AtomicUsize>,
    maximum: Arc<AtomicUsize>,
    drop_first: Arc<AtomicUsize>,
}
async fn relay(
    socket: UdpSocket,
    a: SocketAddr,
    b: SocketAddr,
    packets: Arc<AtomicUsize>,
    maximum: Arc<AtomicUsize>,
    drop_first: Arc<AtomicUsize>,
    impair: bool,
) -> io::Result<()> {
    let mut buffer = vec![0; 65_536];
    let mut count = [0_usize; 2];
    let mut held: [Option<Vec<u8>>; 2] = [None, None];
    let mut ticker = interval(Duration::from_millis(8));
    loop {
        tokio::select! {
            result = socket.recv_from(&mut buffer) => {
                let (length, source) = result?;
                let direction = if source == a {0} else if source == b {1} else {continue};
                let destination = if direction == 0 {b} else {a};
                packets.fetch_add(1, Ordering::SeqCst);
                maximum.fetch_max(length, Ordering::SeqCst);
                count[direction] += 1;
                if drop_first.fetch_update(Ordering::SeqCst, Ordering::SeqCst, |remaining| remaining.checked_sub(1)).is_ok() {continue;}
                if impair && count[direction].is_multiple_of(7) {continue;}
                if impair && count[direction].is_multiple_of(5) && held[direction].is_none() {
                    held[direction] = Some(buffer[..length].to_vec());
                } else {
                    socket.send_to(&buffer[..length], destination).await?;
                    if let Some(previous) = held[direction].take() {
                        socket.send_to(&previous, destination).await?;
                    }
                }
            }
            _ = ticker.tick() => {
                for (direction, pending) in held.iter_mut().enumerate() {
                    if let Some(bytes) = pending.take() {
                        socket.send_to(&bytes, if direction == 0 {b} else {a}).await?;
                    }
                }
            }
        }
    }
}
async fn carriers(
    runtime: RuntimeConfig,
    config: Config,
    lane: Lane,
    relays: &mut Relays,
    impair: bool,
) -> Result<(Carrier, Carrier), TestError> {
    let cert = rcgen::generate_simple_self_signed(vec!["udp-runtime.test".to_owned()])?;
    let chain = vec![cert.cert.der().to_vec()];
    let client_tls = ClientTls::from_der_roots(&chain)?;
    let server_tls = ServerTls::from_der(&chain, &cert.signing_key.serialize_der())?;
    let member = MemberKey::from_pkcs8(&MemberKey::generate_pkcs8()?)?;
    carriers_with_identity(
        runtime,
        config,
        lane,
        relays,
        impair,
        &client_tls,
        &server_tls,
        &member,
        native_delivery(runtime),
    )
    .await
}
#[allow(clippy::too_many_arguments)]
async fn carriers_with_identity(
    runtime: RuntimeConfig,
    config: Config,
    lane: Lane,
    relays: &mut Relays,
    impair: bool,
    client_tls: &ClientTls,
    server_tls: &ServerTls,
    member: &MemberKey,
    selected_delivery: crate::managed::DeliveryConfig,
) -> Result<(Carrier, Carrier), TestError> {
    let allowlist = MemberAllowlist::new(&[member.public_key()])?;
    let a = UdpSocket::bind("127.0.0.1:0").await?;
    let b = UdpSocket::bind("127.0.0.1:0").await?;
    let relay_socket = UdpSocket::bind("127.0.0.1:0").await?;
    let peer = relay_socket.local_addr()?;
    relays.tasks.spawn(relay(
        relay_socket,
        a.local_addr()?,
        b.local_addr()?,
        relays.packets.clone(),
        relays.maximum.clone(),
        relays.drop_first.clone(),
        impair,
    ));
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let a_tcp = TcpStream::connect(listener.local_addr()?).await?;
    let (b_tcp, _) = listener.accept().await?;
    a_tcp.set_nodelay(true)?;
    b_tcp.set_nodelay(true)?;
    let binding = session_config(runtime, config, lane, selected_delivery)?;
    let (a_tls, b_tls) = tokio::try_join!(
        client_connect(
            a_tcp,
            client_tls,
            "udp-runtime.test",
            member,
            binding,
            Duration::from_secs(3)
        ),
        server_accept(
            b_tcp,
            server_tls,
            &allowlist,
            binding,
            Duration::from_secs(3)
        ),
    )?;
    Ok(tokio::try_join!(
        carrier::establish(
            a_tls,
            a,
            carrier_config(runtime, config, lane, peer, selected_delivery)?
        ),
        carrier::establish(
            b_tls,
            b,
            carrier_config(runtime, config, lane, peer, selected_delivery)?
        ),
    )?)
}
async fn links(
    runtime: RuntimeConfig,
    config: Config,
    impair: bool,
) -> Result<(Link, Link, Relays), TestError> {
    links_with_delivery(runtime, config, impair, native_delivery(runtime)).await
}
async fn links_with_delivery(
    runtime: RuntimeConfig,
    config: Config,
    impair: bool,
    selected_delivery: crate::managed::DeliveryConfig,
) -> Result<(Link, Link, Relays), TestError> {
    let cert = rcgen::generate_simple_self_signed(vec!["udp-runtime.test".to_owned()])?;
    let chain = vec![cert.cert.der().to_vec()];
    let client_tls = ClientTls::from_der_roots(&chain)?;
    let server_tls = ServerTls::from_der(&chain, &cert.signing_key.serialize_der())?;
    let member = MemberKey::from_pkcs8(&MemberKey::generate_pkcs8()?)?;
    let mut relays = Relays::default();
    let (a, b) = carriers_with_identity(
        runtime,
        config,
        Lane::First,
        &mut relays,
        impair,
        &client_tls,
        &server_tls,
        &member,
        selected_delivery,
    )
    .await?;
    let (a, b) = if config.duplex == Duplex::Full {
        (
            Link::full(a, runtime, config, selected_delivery)?,
            Link::full(b, runtime, config, selected_delivery)?,
        )
    } else {
        let (c, d) = carriers_with_identity(
            runtime,
            config,
            Lane::Second,
            &mut relays,
            impair,
            &client_tls,
            &server_tls,
            &member,
            selected_delivery,
        )
        .await?;
        tokio::try_join!(
            client_pair(a, c, runtime, config, selected_delivery),
            server_pair(b, d, runtime, config, selected_delivery)
        )?
    };
    Ok((a, b, relays))
}
async fn delivered(device: &Device, count: usize) -> TestResult {
    timeout(Duration::from_secs(8), async {
        while device.change(|native| native.delivered.len())? < count {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        Ok::<_, io::Error>(())
    })
    .await??;
    Ok(())
}

#[tokio::test]
async fn real_devices_all_profiles_loss_reorder_fragmentation_and_blocked_delivery() -> TestResult {
    for duplex in [Duplex::Full, Duplex::Half] {
        for layer in [PacketLayer::Ethernet, PacketLayer::Ip] {
            for cover in [CoverProfile::OpenVpnLike, CoverProfile::QuicLike] {
                for protection in [Protection::ChaCha20Poly1305, Protection::HmacSha256] {
                    let runtime = runtime(layer);
                    let config = config(duplex, cover, protection)?;
                    let (a, b, relays) = links(runtime, config, true).await?;
                    let a_device = Device::new(layer);
                    let b_device = Device::new(layer);
                    let a_packets: Vec<_> = (0..7).map(|n| packet(layer, n, 3200)).collect();
                    let b_packets: Vec<_> = (30..37).map(|n| packet(layer, n, 2500)).collect();
                    a_device.change(|native| native.outgoing.extend(a_packets.clone()))?;
                    b_device.change(|native| {
                        native.outgoing.extend(b_packets.clone());
                        native.blocked = true;
                    })?;
                    let mut tasks = JoinSet::new();
                    tasks.spawn(run(
                        a_device.clone(),
                        a,
                        runtime,
                        config,
                        native_delivery(runtime),
                    ));
                    tasks.spawn(run(
                        b_device.clone(),
                        b,
                        runtime,
                        config,
                        native_delivery(runtime),
                    ));
                    tokio::select! {
                        result = delivered(&a_device, b_packets.len()) => result?,
                        result = tasks.join_next() => return Err(format!("runtime unexpectedly ended {result:?} duplex={duplex:?} layer={layer:?} cover={cover:?}").into()),
                    }
                    assert_eq!(
                        a_device.change(|native| native.admitted)?,
                        runtime.queue_packets
                    );
                    assert_eq!(b_device.change(|native| native.delivered.len())?, 0);
                    b_device.change(|native| native.blocked = false)?;
                    tokio::select! {
                        result = delivered(&b_device, a_packets.len()) => result?,
                        result = tasks.join_next() => return Err(format!("runtime unexpectedly ended {result:?}").into()),
                    }
                    assert_eq!(
                        a_device.change(|native| native.delivered.clone())?,
                        b_packets
                    );
                    assert_eq!(
                        b_device.change(|native| native.delivered.clone())?,
                        a_packets
                    );
                    assert!(relays.packets.load(Ordering::SeqCst) > 14);
                    assert!(
                        relays.maximum.load(Ordering::SeqCst) + config.outer_overhead_bytes
                            <= config.path_mtu
                    );
                }
            }
        }
    }
    Ok(())
}
#[tokio::test]
async fn compressed_packets_and_retained_control_eof() -> TestResult {
    let mut runtime = runtime(PacketLayer::Ethernet);
    runtime.compression = Compression::Lz4IfSmaller;
    let config = config(
        Duplex::Full,
        CoverProfile::QuicLike,
        Protection::ChaCha20Poly1305,
    )?;
    let (a, b, _relays) = links(runtime, config, false).await?;
    let a_device = Device::new(runtime.layer);
    let b_device = Device::new(runtime.layer);
    let bytes = packet(runtime.layer, 4, 3900);
    a_device.change(|native| native.outgoing.push_back(bytes.clone()))?;
    let a_task = tokio::spawn(run(a_device, a, runtime, config, native_delivery(runtime)));
    let mut b_task = tokio::spawn(run(
        b_device.clone(),
        b,
        runtime,
        config,
        native_delivery(runtime),
    ));
    tokio::select! {
        result = delivered(&b_device, 1) => result?,
        result = &mut b_task => return Err(format!("runtime unexpectedly ended {result:?}").into()),
    }
    assert_eq!(
        b_device.change(|native| native.delivered.clone())?,
        vec![bytes]
    );
    a_task.abort();
    let _ = a_task.await;
    assert!(timeout(Duration::from_secs(3), b_task).await??.is_err());
    Ok(())
}
#[test]
fn canonical_binding_and_configuration_fail_closed() -> TestResult {
    let runtime = runtime(PacketLayer::Ip);
    let config = config(
        Duplex::Half,
        CoverProfile::OpenVpnLike,
        Protection::HmacSha256,
    )?;
    assert_ne!(
        session_config(runtime, config, Lane::First, native_delivery(runtime))?,
        session_config(runtime, config, Lane::Second, native_delivery(runtime))?
    );
    let mut other = config;
    other.arq.max_retries += 1;
    assert_ne!(
        base_session_config(runtime, config, native_delivery(runtime))?,
        base_session_config(runtime, other, native_delivery(runtime))?
    );
    let mut other_runtime = runtime;
    other_runtime.queue_packets += 1;
    assert_ne!(
        base_session_config(runtime, config, native_delivery(runtime))?,
        base_session_config(other_runtime, config, native_delivery(other_runtime))?
    );
    other.heartbeat_interval = other.control_timeout;
    assert!(base_session_config(runtime, other, native_delivery(runtime)).is_err());
    other = config;
    other.arq.max_source_bytes = config.path_mtu;
    assert!(base_session_config(runtime, other, native_delivery(runtime)).is_err());
    other = config;
    other.duplex = Duplex::Full;
    assert!(session_config(runtime, other, Lane::Second, native_delivery(runtime)).is_err());
    assert!(
        Config::new(
            Duplex::Full,
            CoverProfile::QuicLike,
            Protection::HmacSha256,
            120,
            false
        )
        .is_err()
    );
    Ok(())
}
#[tokio::test]
async fn wrong_constructor_profile_and_role_fail_before_device_use() -> TestResult {
    let runtime = runtime(PacketLayer::Ip);
    let config = config(
        Duplex::Full,
        CoverProfile::OpenVpnLike,
        Protection::HmacSha256,
    )?;
    let mut relays = Relays::default();
    let (a, _b) = carriers(runtime, config, Lane::First, &mut relays, false).await?;
    let mut different = runtime;
    different.queue_packets += 1;
    assert!(Link::full(a, different, config, native_delivery(different)).is_err());
    let (a, _b, _relays) = links(runtime, config, false).await?;
    let device = Device::new(runtime.layer);
    assert!(
        run(
            device.clone(),
            a,
            different,
            config,
            native_delivery(different)
        )
        .await
        .is_err()
    );
    assert_eq!(device.change(|native| native.admitted)?, 0);
    let mut half = config;
    half.duplex = Duplex::Half;
    let (a, b) = carriers(runtime, half, Lane::First, &mut relays, false).await?;
    assert!(
        client_pair(a, b, runtime, half, native_delivery(runtime))
            .await
            .is_err()
    );
    Ok(())
}
#[tokio::test]
async fn control_parser_rejects_unknown_and_truncated_frames() -> TestResult {
    for bytes in [
        b"L2UC\x01\x04\0\0".to_vec(),
        b"L2UC\x01\x02\xff\xff".to_vec(),
        b"L2UC\x01\x03\0\x08\0".to_vec(),
    ] {
        let (a, mut b) = tokio::io::duplex(64);
        let (tx, _rx) = mpsc::channel(1);
        let writer = tokio::spawn(async move {
            b.write_all(&bytes).await?;
            b.shutdown().await
        });
        assert!(
            read_control(a, 0, tx, Duration::from_secs(1), ACK_PACKET_BYTES)
                .await
                .is_err()
        );
        writer.await??;
    }
    Ok(())
}

#[tokio::test]
async fn lost_udp_exhausts_retries_while_tls_control_stays_available() -> TestResult {
    let runtime = runtime(PacketLayer::Ip);
    let mut config = config(Duplex::Full, CoverProfile::QuicLike, Protection::HmacSha256)?;
    config.arq.max_retries = 2;
    let (a, b, mut relays) = links(runtime, config, false).await?;
    relays.tasks.abort_all();
    while relays.tasks.join_next().await.is_some() {}
    let a_device = Device::new(runtime.layer);
    let b_device = Device::new(runtime.layer);
    a_device.change(|native| native.outgoing.push_back(packet(runtime.layer, 1, 2000)))?;
    let mut tasks = JoinSet::new();
    tasks.spawn(run(a_device, a, runtime, config, native_delivery(runtime)));
    tasks.spawn(run(
        b_device.clone(),
        b,
        runtime,
        config,
        native_delivery(runtime),
    ));
    let result = timeout(Duration::from_secs(2), tasks.join_next())
        .await?
        .ok_or_else(|| invalid("missing runtime result"))??;
    let error = result
        .err()
        .ok_or_else(|| invalid("lost UDP falsely succeeded"))?;
    assert!(matches!(
        error
            .get_ref()
            .and_then(|inner| inner.downcast_ref::<RecoveryError>()),
        Some(RecoveryError::RetryExhausted { .. })
    ));
    assert_eq!(b_device.change(|native| native.delivered.len())?, 0);
    Ok(())
}

#[tokio::test]
async fn acknowledged_partial_native_packet_expiry_fails_the_link() -> TestResult {
    let runtime = runtime(PacketLayer::Ethernet);
    let mut config = config(
        Duplex::Full,
        CoverProfile::OpenVpnLike,
        Protection::ChaCha20Poly1305,
    )?;
    config.reassembly_timeout = Duration::from_millis(40);
    let (mut a, b, _relays) = links(runtime, config, false).await?;
    let mut parts = a.parts.pop().ok_or_else(|| invalid("missing peer parts"))?;
    let session = parts.control.info().session_id;
    let context = RecoveryContext {
        session: u128::from_be_bytes(session),
        epoch: 1,
        role: EndpointRole::Initiator,
    };
    let fragment_context = FragmentContext {
        session: SessionId(u64::from_be_bytes(session[..8].try_into()?)),
        epoch: Epoch(1),
    };
    let mut fragmenter = Fragmenter::new(
        fragment_context,
        FragmentConfig {
            path_mtu: config.arq.max_source_bytes,
            outer_overhead_bytes: 0,
            max_message_bytes: runtime.codec()?.max_encoded_len(),
            max_fragments: 64,
        },
        MessageId(0),
    )?;
    let record = runtime
        .codec()?
        .encode_vec(&packet(runtime.layer, 2, 3200))?;
    let fragments = fragmenter.fragment(&record)?;
    assert!(fragments.fragments.len() > 1);
    let mut engine = SelectiveRepeat::new(config.arq, context)?;
    engine.submit(&fragments.fragments[0], Duration::ZERO)?;
    let mut bytes = vec![0; config.payload_budget()?];
    let length = engine
        .poll_source(Duration::ZERO, &mut bytes)?
        .ok_or_else(|| invalid("missing source"))?;
    let (reader, writer) = tokio::io::split(parts.control);
    let (tx, mut rx) = mpsc::channel(8);
    let (feedback, changes) = watch::channel(Feedback::default());
    let mut controls = JoinSet::new();
    controls.spawn(read_control_bound(
        reader,
        0,
        tx,
        config.control_timeout,
        config.feedback_bytes(),
        *b"L2U2",
    ));
    controls.spawn(write_control_bound(
        writer,
        changes,
        {
            let mut policy = config.policy()?;
            policy.control_magic = *b"L2U2";
            policy
        },
        SharedBudget::new(config, Instant::now()),
    ));
    let device = Device::new(runtime.layer);
    let task = tokio::spawn(run(
        device.clone(),
        b,
        runtime,
        config,
        native_delivery(runtime),
    ));
    parts.sender.send(&bytes[..length]).await?;
    let (_, ack) = timeout(Duration::from_secs(1), rx.recv())
        .await?
        .ok_or_else(|| invalid("missing partial packet receipt ACK"))?;
    assert!(matches!(ack, ControlEvent::Ack(_)));
    let result = timeout(Duration::from_secs(1), task).await??;
    let error = result
        .err()
        .ok_or_else(|| invalid("incomplete native packet falsely succeeded"))?;
    assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    assert_eq!(device.change(|native| native.delivered.len())?, 0);
    drop(feedback);
    Ok(())
}

#[tokio::test]
async fn authenticated_unearned_delivery_credit_is_rejected() -> TestResult {
    let runtime = runtime(PacketLayer::Ip);
    let config = config(
        Duplex::Full,
        CoverProfile::OpenVpnLike,
        Protection::HmacSha256,
    )?;
    let (mut a, b, _relays) = links(runtime, config, false).await?;
    let mut parts = a.parts.pop().ok_or_else(|| invalid("missing peer parts"))?;
    let device = Device::new(runtime.layer);
    let task = tokio::spawn(run(
        device.clone(),
        b,
        runtime,
        config,
        native_delivery(runtime),
    ));
    write_control_frame_bound(&mut parts.control, 3, &1_u64.to_be_bytes(), *b"L2U2").await?;
    let result = timeout(Duration::from_secs(1), task).await??;
    let error = result
        .err()
        .ok_or_else(|| invalid("unearned delivery credit accepted"))?;
    assert!(error.to_string().contains("credit"));
    assert_eq!(device.change(|native| native.admitted)?, 0);
    Ok(())
}

#[tokio::test]
async fn tls_writer_coalesces_blocked_updates_and_reader_retains_partial_frames() -> TestResult {
    let config = config(
        Duplex::Full,
        CoverProfile::OpenVpnLike,
        Protection::HmacSha256,
    )?;
    let (writer, reader) = tokio::io::duplex(8);
    let (feedback, changes) = watch::channel(Feedback::default());
    let (tx, mut rx) = mpsc::channel(8);
    let mut tasks = JoinSet::new();
    tasks.spawn(write_control(
        writer,
        changes,
        config,
        SharedBudget::new(config, Instant::now()),
    ));
    tokio::time::sleep(Duration::from_millis(5)).await;
    feedback.send_modify(|value| value.credit = 1);
    tokio::time::sleep(Duration::from_millis(5)).await;
    for credit in 2..=10_000 {
        feedback.send_modify(|value| value.credit = credit);
    }
    assert_eq!(feedback.borrow().credit, 10_000);
    tasks.spawn(read_control(
        reader,
        0,
        tx,
        config.control_timeout,
        config.feedback_bytes(),
    ));
    let mut previous = 0;
    let mut count = 0;
    timeout(Duration::from_secs(1), async {
        while previous != 10_000 {
            let (_, event) = rx
                .recv()
                .await
                .ok_or_else(|| invalid("control writer ended"))?;
            if let ControlEvent::Credit(credit) = event {
                assert!(credit > previous);
                previous = credit;
                count += 1;
            }
        }
        Ok::<_, io::Error>(())
    })
    .await??;
    assert!(count <= 2);
    Ok(())
}

#[tokio::test]
async fn native_sentinel_buffer_does_not_expand_configured_packet_limit() -> TestResult {
    let runtime = runtime(PacketLayer::Ip);
    let config = config(
        Duplex::Full,
        CoverProfile::OpenVpnLike,
        Protection::HmacSha256,
    )?;
    let (a, _b, _relays) = links(runtime, config, false).await?;
    let device = Device::new(runtime.layer);
    device.change(|native| {
        native
            .outgoing
            .push_back(packet(runtime.layer, 2, runtime.max_packet + 1))
    })?;
    let result = timeout(
        Duration::from_secs(1),
        run(device.clone(), a, runtime, config, native_delivery(runtime)),
    )
    .await?;
    assert!(result.is_err());
    assert_eq!(device.change(|native| native.admitted)?, 1);
    Ok(())
}

#[tokio::test]
async fn authenticated_udp_ack_and_tls_data_cannot_cross_dispatch_boundaries() -> TestResult {
    let runtime = runtime(PacketLayer::Ip);
    let config = config(
        Duplex::Full,
        CoverProfile::QuicLike,
        Protection::ChaCha20Poly1305,
    )?;
    for udp_ack in [true, false] {
        let (mut a, b, _relays) = links(runtime, config, false).await?;
        let mut parts = a.parts.pop().ok_or_else(|| invalid("missing peer parts"))?;
        let session = u128::from_be_bytes(parts.control.info().session_id);
        let mut client_engine = SelectiveRepeat::new(
            config.arq,
            RecoveryContext {
                session,
                epoch: 1,
                role: EndpointRole::Initiator,
            },
        )?;
        let mut bytes = vec![0; config.payload_budget()?];
        let length = if udp_ack {
            let mut server_engine = SelectiveRepeat::new(
                config.arq,
                RecoveryContext {
                    session,
                    epoch: 1,
                    role: EndpointRole::Responder,
                },
            )?;
            server_engine.submit(b"data", Duration::ZERO)?;
            let length = server_engine
                .poll_source(Duration::ZERO, &mut bytes)?
                .ok_or_else(|| invalid("missing source"))?;
            client_engine.receive(&bytes[..length], Duration::ZERO)?;
            client_engine
                .poll_feedback(config.arq.ack_delay, &mut bytes)?
                .ok_or_else(|| invalid("missing feedback"))?
        } else {
            client_engine.submit(b"data", Duration::ZERO)?;
            client_engine
                .poll_source(Duration::ZERO, &mut bytes)?
                .ok_or_else(|| invalid("missing source"))?
        };
        assert_eq!(length, ACK_PACKET_BYTES);
        let device = Device::new(runtime.layer);
        let task = tokio::spawn(run(
            device.clone(),
            b,
            runtime,
            config,
            native_delivery(runtime),
        ));
        if udp_ack {
            parts.sender.send(&bytes[..length]).await?;
        } else {
            write_control_frame_bound(&mut parts.control, 2, &bytes[..length], *b"L2U2").await?;
        }
        assert!(timeout(Duration::from_secs(1), task).await??.is_err());
        assert_eq!(device.change(|native| native.delivered.len())?, 0);
    }
    Ok(())
}

#[tokio::test]
async fn cauchy_real_devices_all_profiles_loss_reorder_and_blocked_delivery() -> TestResult {
    for duplex in [Duplex::Full, Duplex::Half] {
        for layer in [PacketLayer::Ethernet, PacketLayer::Ip] {
            for cover in [CoverProfile::OpenVpnLike, CoverProfile::QuicLike] {
                for protection in [Protection::ChaCha20Poly1305, Protection::HmacSha256] {
                    let runtime = runtime(layer);
                    let config =
                        config(duplex, cover, protection)?.with_recovery(RecoveryMode::Cauchy {
                            sources: 4,
                            repairs: 2,
                            flush_after: Duration::from_millis(5),
                        })?;
                    let (a, b, relays) = links(runtime, config, true).await?;
                    let a_device = Device::new(layer);
                    let b_device = Device::new(layer);
                    let a_packets: Vec<_> = (0..7).map(|n| packet(layer, n, 3200)).collect();
                    let b_packets: Vec<_> = (30..37).map(|n| packet(layer, n, 2500)).collect();
                    a_device.change(|native| native.outgoing.extend(a_packets.clone()))?;
                    b_device.change(|native| {
                        native.outgoing.extend(b_packets.clone());
                        native.blocked = true;
                    })?;
                    let mut tasks = JoinSet::new();
                    tasks.spawn(run(
                        a_device.clone(),
                        a,
                        runtime,
                        config,
                        native_delivery(runtime),
                    ));
                    tasks.spawn(run(
                        b_device.clone(),
                        b,
                        runtime,
                        config,
                        native_delivery(runtime),
                    ));
                    tokio::select! {
                        result = delivered(&a_device, b_packets.len()) => result?,
                        result = tasks.join_next() => return Err(format!("runtime unexpectedly ended {result:?} duplex={duplex:?} layer={layer:?} cover={cover:?}").into()),
                    }
                    assert_eq!(
                        a_device.change(|native| native.admitted)?,
                        runtime.queue_packets
                    );
                    assert_eq!(b_device.change(|native| native.delivered.len())?, 0);
                    b_device.change(|native| native.blocked = false)?;
                    tokio::select! {
                        result = delivered(&b_device, a_packets.len()) => result?,
                        result = tasks.join_next() => return Err(format!("runtime unexpectedly ended {result:?}").into()),
                    }
                    assert_eq!(
                        a_device.change(|native| native.delivered.clone())?,
                        b_packets
                    );
                    assert_eq!(
                        b_device.change(|native| native.delivered.clone())?,
                        a_packets
                    );
                    assert!(relays.packets.load(Ordering::SeqCst) > 14);
                    assert!(
                        relays.maximum.load(Ordering::SeqCst) + config.outer_overhead_bytes
                            <= config.path_mtu
                    );
                }
            }
        }
    }
    Ok(())
}

#[tokio::test]
async fn real_cauchy_repair_precedes_rto_and_insufficient_rank_uses_arq() -> TestResult {
    for duplex in [Duplex::Full, Duplex::Half] {
        for layer in [PacketLayer::Ethernet, PacketLayer::Ip] {
            for losses in [1, 3] {
                let runtime = runtime(layer);
                let mut config =
                    config(duplex, CoverProfile::QuicLike, Protection::ChaCha20Poly1305)?;
                config.arq.initial_rto = Duration::from_secs(1);
                config.arq.maximum_rto = Duration::from_secs(2);
                config.reassembly_timeout = Duration::from_secs(5);
                let config = config.with_recovery(RecoveryMode::Cauchy {
                    sources: 4,
                    repairs: 2,
                    flush_after: Duration::from_millis(5),
                })?;
                let (a, b, relays) = links(runtime, config, false).await?;
                relays.drop_first.store(losses, Ordering::SeqCst);
                let a_device = Device::new(layer);
                let b_device = Device::new(layer);
                let bytes = packet(layer, 9, 1400);
                a_device.change(|native| native.outgoing.push_back(bytes.clone()))?;
                let started = Instant::now();
                let mut tasks = JoinSet::new();
                tasks.spawn(run(a_device, a, runtime, config, native_delivery(runtime)));
                tasks.spawn(run(
                    b_device.clone(),
                    b,
                    runtime,
                    config,
                    native_delivery(runtime),
                ));
                tokio::select! {
                    result = delivered(&b_device, 1) => result?,
                    result = tasks.join_next() => return Err(format!("Cauchy runtime ended {result:?}").into()),
                }
                let elapsed = started.elapsed();
                assert_eq!(
                    b_device.change(|native| native.delivered.clone())?,
                    vec![bytes]
                );
                assert_eq!(relays.drop_first.load(Ordering::SeqCst), 0);
                if losses == 1 {
                    assert!(
                        elapsed < config.arq.initial_rto,
                        "repair arrived after RTO: {elapsed:?}"
                    );
                } else {
                    assert!(
                        elapsed >= config.arq.initial_rto,
                        "insufficient rank invented early delivery: {elapsed:?}"
                    );
                }
                assert!(
                    relays.maximum.load(Ordering::SeqCst) + config.outer_overhead_bytes
                        <= config.path_mtu
                );
            }
        }
    }
    Ok(())
}

#[test]
fn shared_allowance_does_not_reset_per_lane_or_poll_and_reserves_control() -> TestResult {
    let mut config = config(Duplex::Half, CoverProfile::QuicLike, Protection::HmacSha256)?;
    let reservation = config.control_reservation();
    config.wire_budget = WireBudget {
        interval: Duration::from_millis(10),
        packets: reservation.packets + 1,
        wire_bytes: reservation.wire_bytes + config.path_mtu,
    };
    config.validate()?;
    let shared = SharedBudget::new(config, Instant::now());
    let mut a = Engine::new(
        config,
        RecoveryContext {
            session: 1,
            epoch: 1,
            role: EndpointRole::Initiator,
        },
    )?;
    let mut b = Engine::new(
        config,
        RecoveryContext {
            session: 2,
            epoch: 1,
            role: EndpointRole::Initiator,
        },
    )?;
    a.submit(&vec![1; config.arq.max_source_bytes], Duration::ZERO)?;
    b.submit(&vec![2; config.arq.max_source_bytes], Duration::ZERO)?;
    let mut bytes = vec![0; config.payload_budget()?];
    assert!(
        shared
            .poll(false, Duration::ZERO, &mut a, &mut bytes)?
            .is_some()
    );
    for _ in 0..10 {
        assert_eq!(
            shared.poll(false, Duration::ZERO, &mut b, &mut bytes)?,
            None
        );
    }
    {
        let mut ledger = shared
            .ledger
            .lock()
            .map_err(|_| invalid("test ledger poisoned"))?;
        assert_eq!(ledger.available(false).packets, 0);
        assert_eq!(ledger.remaining, reservation);
        let before = ledger.remaining;
        ledger.debit(true, config.feedback_bytes() + config.control_overhead())?;
        assert_eq!(ledger.remaining.packets, before.packets - 1);
        assert_eq!(
            ledger.remaining.wire_bytes,
            before.wire_bytes - config.feedback_bytes() - config.control_overhead()
        );
    }
    assert_eq!(
        shared.poll(false, Duration::from_millis(9), &mut b, &mut bytes)?,
        None
    );
    assert!(
        shared
            .poll(false, Duration::from_millis(10), &mut b, &mut bytes)?
            .is_some()
    );
    Ok(())
}

#[test]
fn selected_feedback_reservation_shares_all_lanes_and_refills_exactly() -> TestResult {
    for duplex in [Duplex::Full, Duplex::Half] {
        let mut policy =
            config(duplex, CoverProfile::QuicLike, Protection::HmacSha256)?.policy()?;
        let feedback = 64;
        let control_packets = if duplex == Duplex::Full { 3 } else { 6 };
        policy.wire_budget = WireBudget {
            interval: Duration::from_millis(10),
            packets: control_packets + 1,
            wire_bytes: control_packets * (feedback + policy.control_overhead)
                + policy.payload_bytes
                + policy.data_overhead,
        };
        let shared = SharedBudget::from_policy_feedback(policy, Instant::now(), feedback)?;
        let other_lane = shared.clone();
        let mut output = vec![0; policy.payload_bytes];
        let emit = |size: usize, allowance: &mut OutboundBudget| {
            if allowance.packets == 0 || allowance.wire_bytes < size {
                return Ok(None);
            }
            allowance.packets -= 1;
            allowance.wire_bytes -= size;
            Ok(Some(size))
        };
        assert_eq!(
            shared.poll_with(false, Duration::ZERO, &mut output, |_, allowance| {
                emit(policy.payload_bytes, allowance)
            })?,
            Some(policy.payload_bytes)
        );
        for _ in 0..10 {
            assert_eq!(
                other_lane.poll_with(false, Duration::ZERO, &mut output, |_, allowance| {
                    emit(1, allowance)
                })?,
                None
            );
        }
        for _ in 0..control_packets {
            assert_eq!(
                other_lane.poll_with(true, Duration::ZERO, &mut output, |_, allowance| {
                    emit(feedback, allowance)
                })?,
                Some(feedback)
            );
        }
        for control in [true, false] {
            assert_eq!(
                shared.poll_with(
                    control,
                    Duration::from_millis(9),
                    &mut output,
                    |_, allowance| { emit(1, allowance) }
                )?,
                None
            );
        }
        assert_eq!(
            other_lane.poll_with(
                false,
                Duration::from_millis(10),
                &mut output,
                |_, allowance| { emit(policy.payload_bytes, allowance) }
            )?,
            Some(policy.payload_bytes)
        );
        let ledger = shared
            .ledger
            .lock()
            .map_err(|_| invalid("test ledger poisoned"))?;
        assert_eq!(ledger.remaining.packets, control_packets);
        assert_eq!(
            ledger.remaining.wire_bytes,
            control_packets * (feedback + policy.control_overhead)
        );
    }
    Ok(())
}

#[test]
fn selected_feedback_reservation_rejects_shortage_overflow_and_unbounded_limits() -> TestResult {
    for duplex in [Duplex::Full, Duplex::Half] {
        let mut policy =
            config(duplex, CoverProfile::QuicLike, Protection::HmacSha256)?.policy()?;
        let packets = if duplex == Duplex::Full { 3 } else { 6 };
        let required =
            packets * (policy.control_overhead + 64) + policy.payload_bytes + policy.data_overhead;
        policy.wire_budget.packets = packets + 1;
        policy.wire_budget.wire_bytes = required;
        let started = Instant::now();
        assert!(SharedBudget::from_policy_feedback(policy, started, 64).is_ok());
        for feedback in [0, usize::from(u16::MAX) + 1, usize::MAX] {
            assert!(SharedBudget::from_policy_feedback(policy, started, feedback).is_err());
        }
        let mut invalid_policies = Vec::new();
        for bytes in [required - 1, 256 * 1024 * 1024 + 1] {
            let mut bad = policy;
            bad.wire_budget.wire_bytes = bytes;
            invalid_policies.push(bad);
        }
        for count in [packets, 65_537] {
            let mut bad = policy;
            bad.wire_budget.packets = count;
            invalid_policies.push(bad);
        }
        for interval in [
            Duration::ZERO,
            policy.control_timeout / 8 + Duration::from_nanos(1),
            Duration::from_secs(2),
        ] {
            let mut bad = policy;
            bad.wire_budget.interval = interval;
            invalid_policies.push(bad);
        }
        for payload in [0, usize::from(u16::MAX) + 1] {
            let mut bad = policy;
            bad.payload_bytes = payload;
            invalid_policies.push(bad);
        }
        let mut bad = policy;
        bad.control_overhead = usize::MAX;
        invalid_policies.push(bad);
        bad.control_overhead = usize::MAX / packets;
        invalid_policies.push(bad);
        bad = policy;
        bad.data_overhead = usize::MAX;
        invalid_policies.push(bad);
        bad.data_overhead = usize::MAX - policy.payload_bytes;
        invalid_policies.push(bad);
        for bad in invalid_policies {
            assert!(SharedBudget::from_policy_feedback(bad, started, 64).is_err());
        }
    }
    Ok(())
}

#[test]
fn cauchy_dimensions_and_every_budget_are_authentication_bound() -> TestResult {
    let runtime = runtime(PacketLayer::Ip);
    let config = config(
        Duplex::Full,
        CoverProfile::OpenVpnLike,
        Protection::HmacSha256,
    )?;
    let cauchy = config.with_recovery(RecoveryMode::Cauchy {
        sources: 4,
        repairs: 2,
        flush_after: Duration::from_millis(5),
    })?;
    assert!(cauchy.arq.max_source_bytes < config.arq.max_source_bytes);
    assert_ne!(
        base_session_config(runtime, cauchy, native_delivery(runtime))?,
        base_session_config(runtime, config, native_delivery(runtime))?
    );
    let mut other = cauchy;
    other.wire_budget.packets += 1;
    assert_ne!(
        base_session_config(runtime, cauchy, native_delivery(runtime))?,
        base_session_config(runtime, other, native_delivery(runtime))?
    );
    other = cauchy;
    other.wire_budget.wire_bytes += 1;
    assert_ne!(
        base_session_config(runtime, cauchy, native_delivery(runtime))?,
        base_session_config(runtime, other, native_delivery(runtime))?
    );
    other = cauchy;
    other.wire_budget.interval += Duration::from_nanos(1);
    assert_ne!(
        base_session_config(runtime, cauchy, native_delivery(runtime))?,
        base_session_config(runtime, other, native_delivery(runtime))?
    );
    assert!(
        config
            .with_recovery(RecoveryMode::Cauchy {
                sources: 17,
                repairs: 2,
                flush_after: Duration::from_millis(5)
            })
            .is_err()
    );
    assert!(
        config
            .with_recovery(RecoveryMode::Cauchy {
                sources: 4,
                repairs: 0,
                flush_after: Duration::from_millis(5)
            })
            .is_err()
    );
    assert!(
        config
            .with_recovery(RecoveryMode::Cauchy {
                sources: 4,
                repairs: 2,
                flush_after: config.arq.initial_rto
            })
            .is_err()
    );
    other = cauchy;
    other.arq.max_source_bytes = config.arq.max_source_bytes;
    assert!(base_session_config(runtime, other, native_delivery(runtime)).is_err());
    Ok(())
}

#[tokio::test]
async fn cauchy_small_shared_allowance_keeps_control_and_native_credit_live() -> TestResult {
    for duplex in [Duplex::Full, Duplex::Half] {
        let runtime = runtime(PacketLayer::Ip);
        let mut config = config(duplex, CoverProfile::OpenVpnLike, Protection::HmacSha256)?;
        config.arq.initial_rto = Duration::from_secs(1);
        config.arq.maximum_rto = Duration::from_secs(2);
        config.reassembly_timeout = Duration::from_secs(4);
        let mut config = config.with_recovery(RecoveryMode::Cauchy {
            sources: 4,
            repairs: 2,
            flush_after: Duration::from_millis(5),
        })?;
        let reserve = config.control_reservation();
        config.wire_budget = WireBudget {
            interval: Duration::from_millis(5),
            packets: reserve.packets + 1,
            wire_bytes: reserve.wire_bytes + config.path_mtu,
        };
        let (a, b, _relays) = links(runtime, config, false).await?;
        let a_device = Device::new(runtime.layer);
        let b_device = Device::new(runtime.layer);
        let a_bytes: Vec<_> = (0..3).map(|n| packet(runtime.layer, n, 1400)).collect();
        let b_bytes: Vec<_> = (10..13).map(|n| packet(runtime.layer, n, 1400)).collect();
        a_device.change(|native| native.outgoing.extend(a_bytes.clone()))?;
        b_device.change(|native| {
            native.outgoing.extend(b_bytes.clone());
            native.blocked = true;
        })?;
        let mut tasks = JoinSet::new();
        tasks.spawn(run(
            a_device.clone(),
            a,
            runtime,
            config,
            native_delivery(runtime),
        ));
        tasks.spawn(run(
            b_device.clone(),
            b,
            runtime,
            config,
            native_delivery(runtime),
        ));
        tokio::select! {
            result = delivered(&a_device, b_bytes.len()) => result?,
            result = tasks.join_next() => return Err(format!("paced Cauchy runtime ended {result:?}").into()),
        }
        assert_eq!(
            a_device.change(|native| native.admitted)?,
            runtime.queue_packets
        );
        b_device.change(|native| native.blocked = false)?;
        tokio::select! {
            result = delivered(&b_device, a_bytes.len()) => result?,
            result = tasks.join_next() => return Err(format!("paced Cauchy runtime ended {result:?}").into()),
        }
        assert_eq!(a_device.change(|native| native.delivered.clone())?, b_bytes);
        assert_eq!(b_device.change(|native| native.delivered.clone())?, a_bytes);
    }
    Ok(())
}

#[tokio::test]
async fn cauchy_truncated_envelope_and_old_ack_shape_fail_closed() -> TestResult {
    let runtime = runtime(PacketLayer::Ip);
    let config = config(
        Duplex::Full,
        CoverProfile::QuicLike,
        Protection::ChaCha20Poly1305,
    )?
    .with_recovery(RecoveryMode::Cauchy {
        sources: 4,
        repairs: 2,
        flush_after: Duration::from_millis(5),
    })?;
    for udp in [true, false] {
        let (mut a, b, _relays) = links(runtime, config, false).await?;
        let mut parts = a.parts.pop().ok_or_else(|| invalid("missing peer parts"))?;
        let device = Device::new(runtime.layer);
        let task = tokio::spawn(run(
            device.clone(),
            b,
            runtime,
            config,
            native_delivery(runtime),
        ));
        if udp {
            parts.sender.send(b"L2RF\x01\x03\0\0\0").await?;
        } else {
            write_control_frame_bound(&mut parts.control, 2, &[0; ACK_PACKET_BYTES], *b"L2U2")
                .await?;
        }
        assert!(timeout(Duration::from_secs(1), task).await??.is_err());
        assert_eq!(device.change(|native| native.delivered.len())?, 0);
    }
    Ok(())
}

#[test]
fn reliable_feedback_and_data_charge_their_distinct_enclosing_paths() -> TestResult {
    let config = config(Duplex::Full, CoverProfile::QuicLike, Protection::HmacSha256)?
        .with_recovery(RecoveryMode::Cauchy {
            sources: 1,
            repairs: 1,
            flush_after: Duration::from_millis(5),
        })?;
    let sender_budget = SharedBudget::new(config, Instant::now());
    let receiver_budget = SharedBudget::new(config, Instant::now());
    let mut sender = Engine::new(
        config,
        RecoveryContext {
            session: 7,
            epoch: 1,
            role: EndpointRole::Initiator,
        },
    )?;
    let mut receiver = Engine::new(
        config,
        RecoveryContext {
            session: 7,
            epoch: 1,
            role: EndpointRole::Responder,
        },
    )?;
    let mut bytes = vec![0; config.payload_budget()?];
    sender.submit(b"actual source payload", Duration::ZERO)?;
    let data_length = sender_budget
        .poll(false, Duration::ZERO, &mut sender, &mut bytes)?
        .ok_or_else(|| invalid("missing systematic output"))?;
    assert_eq!(
        receiver.inspect(&bytes[..data_length], config.arq.max_source_bytes)?,
        RecordKind::Systematic
    );
    receiver.receive(&bytes[..data_length], Duration::ZERO)?;
    let feedback_length = receiver_budget
        .poll(true, config.arq.ack_delay, &mut receiver, &mut bytes)?
        .ok_or_else(|| invalid("missing coded feedback"))?;
    assert_eq!(feedback_length, 56);
    assert_eq!(
        sender.inspect(&bytes[..feedback_length], config.arq.max_source_bytes)?,
        RecordKind::Feedback
    );
    let sent = sender_budget
        .ledger
        .lock()
        .map_err(|_| invalid("test ledger poisoned"))?
        .remaining;
    let replied = receiver_budget
        .ledger
        .lock()
        .map_err(|_| invalid("test ledger poisoned"))?
        .remaining;
    assert_eq!(config.wire_budget.packets - sent.packets, 1);
    assert_eq!(
        config.wire_budget.wire_bytes - sent.wire_bytes,
        data_length + config.path_mtu - config.payload_budget()?
    );
    assert_eq!(config.wire_budget.packets - replied.packets, 1);
    assert_eq!(
        config.wire_budget.wire_bytes - replied.wire_bytes,
        feedback_length + config.control_overhead()
    );
    Ok(())
}

async fn delivery_links(
    rt: RuntimeConfig,
    duplex: Duplex,
    recovery: RecoveryMode,
    policy: crate::managed::DeliveryConfig,
) -> Result<(Config, Link, Link, Relays), TestError> {
    let transport = config(duplex, CoverProfile::OpenVpnLike, Protection::HmacSha256)?
        .with_recovery(recovery)?;
    let (a, b, relays) = links_with_delivery(rt, transport, false, policy).await?;
    Ok((transport, a, b, relays))
}
crate::packet_delivery::actual_native_flight!();
