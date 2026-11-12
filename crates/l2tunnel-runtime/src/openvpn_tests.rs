use super::*;
#[tokio::test]
async fn source_and_task_first_preserve_the_same_bounded_terminal_cause() -> io::Result<()> {
    for source_first in [false, true] {
        for case in 0..4 {
            let error = carrier_error(match case {
                0 => carrier::Error::Timeout,
                1 => carrier::Error::Closed,
                2 => carrier::Error::Io(io::Error::from_raw_os_error(13)),
                _ => carrier::Error::Io(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "原因".repeat(1024),
                )),
            });
            let expected = copy_error(&error);
            let (sender, mut receiver) = mpsc::channel(1);
            let capacity = sender.clone();
            let (ready, complete) = oneshot::channel();
            let mut tasks = JoinSet::new();
            tasks.spawn(async move {
                let permit = sender.reserve().await.map_err(|_| source_ended())?;
                let result = relay_source(Err(error), &[], permit);
                let _ = ready.send(());
                result
            });
            complete.await.map_err(io::Error::other)?;
            assert!(matches!(
                capacity.try_reserve(),
                Err(mpsc::error::TrySendError::Full(()))
            ));
            let (source, task) = if source_first {
                let source = receiver.recv().await.ok_or_else(source_ended)?;
                let task = tasks
                    .join_next()
                    .await
                    .ok_or_else(source_ended)?
                    .map_err(io::Error::other)?;
                (source, task)
            } else {
                let task = tasks
                    .join_next()
                    .await
                    .ok_or_else(source_ended)?
                    .map_err(io::Error::other)?;
                let source = receiver.recv().await.ok_or_else(source_ended)?;
                (source, task)
            };
            for actual in [source.err(), task.err()] {
                let actual = actual.ok_or_else(|| invalid("missing terminal cause"))?;
                assert_eq!(actual.kind(), expected.kind());
                assert_eq!(actual.raw_os_error(), expected.raw_os_error());
                assert_eq!(actual.to_string(), expected.to_string());
                assert!(actual.to_string().len() <= DIAGNOSTIC_BYTES);
            }
            assert!(capacity.try_reserve().is_ok());
            drop(capacity);
            assert!(receiver.recv().await.is_none());
        }
    }
    Ok(())
}

#[test]
fn unreported_eof_and_lane_health_do_not_invent_inactivity() -> io::Result<()> {
    let error = source_ended();
    assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);
    assert!(!error.to_string().contains("Timeout"));
    let active = carrier::Status {
        tls_messages: 7,
        ..carrier::Status::default()
    };
    assert_eq!(carrier_health(&[active, active])?, 14);
    for terminal in [
        carrier::Terminal::Timeout,
        carrier::Terminal::Clean,
        carrier::Terminal::Failed,
        carrier::Terminal::Cancelled,
        carrier::Terminal::IncompleteClose,
    ] {
        let ended = carrier::Status {
            terminal: Some(terminal),
            ..active
        };
        let error = carrier_health(&[active, ended])
            .err()
            .ok_or_else(|| invalid("missing health error"))?;
        assert_eq!(
            error.kind(),
            if terminal == carrier::Terminal::Timeout {
                io::ErrorKind::TimedOut
            } else {
                io::ErrorKind::UnexpectedEof
            }
        );
        assert!(
            error
                .to_string()
                .contains(&format!("lane 1 terminal=Some({terminal:?})"))
        );
        assert!(!error.to_string().contains("inactivity"));
    }
    let closing = carrier::Status {
        closing: true,
        ..active
    };
    let error = carrier_health(&[closing])
        .err()
        .ok_or_else(|| invalid("missing closing error"))?;
    assert!(error.to_string().contains("terminal=None closing=true"));
    Ok(())
}

#[test]
fn native_policy_and_all_bounds_enter_canonical_binding() -> io::Result<()> {
    let baseline = DeviceConfig {
        native: RuntimeConfig {
            layer: l2tunnel_device::PacketLayer::Ip,
            max_packet: 1600,
            compression: Compression::None,
            queue_packets: 2,
            poll_interval: Duration::from_millis(1),
        },
        duplex: Duplex::Half,
        reassembly_timeout: Duration::from_secs(2),
        work_limit: 16,
        task_shutdown_timeout: Duration::from_secs(1),
    };
    let binding = baseline.base_session_config()?;
    for field in 0..9 {
        let mut value = baseline;
        match field {
            0 => value.native.max_packet += 1,
            1 => value.native.queue_packets += 1,
            2 => value.native.compression = Compression::Lz4IfSmaller,
            3 => value.duplex = Duplex::Full,
            4 => value.reassembly_timeout += Duration::from_secs(1),
            5 => value.work_limit += 1,
            6 => value.task_shutdown_timeout += Duration::from_secs(1),
            7 => value.native.layer = PacketLayer::Ethernet,
            _ => value.native.poll_interval += Duration::from_millis(1),
        }
        assert_ne!(value.base_session_config()?, binding);
    }
    assert!(geometry(baseline, FRAGMENT_HEADER_BYTES).is_err());
    assert!(geometry(baseline, FRAGMENT_HEADER_BYTES + 1).is_err());
    Ok(())
}

use l2tunnel_auth::{ClientTls, MemberAllowlist, MemberKey, ServerTls};
use l2tunnel_device::PacketLayer;
use l2tunnel_udp_control::{Path, Secret};
use std::net::SocketAddr;
use tokio::{
    net::UdpSocket,
    time::{sleep, timeout},
};
type TestError = Box<dyn std::error::Error + Send + Sync>;
type TestResult = Result<(), TestError>;
#[derive(Default)]
struct Native {
    outgoing: VecDeque<Vec<u8>>,
    delivered: Vec<Vec<u8>>,
    reads: usize,
    blocked: bool,
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
        let mut state = self
            .state
            .lock()
            .map_err(|_| invalid("test native mutex"))?;
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
            return Err(invalid("missing oversize sentinel"));
        }
        self.change(|s| {
            s.outgoing.pop_front().map(|packet| {
                output[..packet.len()].copy_from_slice(&packet);
                s.reads += 1;
                packet.len()
            })
        })
    }
    fn transmit(&mut self, bytes: &[u8]) -> io::Result<()> {
        self.change(|s| {
            if s.blocked {
                Err(io::ErrorKind::WouldBlock.into())
            } else {
                s.delivered.push(bytes.to_vec());
                Ok(())
            }
        })?
    }
}
fn packet(layer: PacketLayer, length: usize, seed: u8) -> Vec<u8> {
    let mut bytes: Vec<_> = (0..length).map(|i| ((i * 17) as u8) ^ seed).collect();
    match layer {
        PacketLayer::Ip => {
            bytes[0] = 0x45;
            bytes[2..4].copy_from_slice(&(length as u16).to_be_bytes());
        }
        PacketLayer::Ethernet => {
            bytes[12..14].copy_from_slice(&0x88b5u16.to_be_bytes());
        }
    }
    bytes
}
fn native(duplex: Duplex, layer: PacketLayer, compression: Compression) -> DeviceConfig {
    DeviceConfig {
        native: RuntimeConfig {
            layer,
            max_packet: 65_519,
            compression,
            queue_packets: 2,
            poll_interval: Duration::from_millis(1),
        },
        duplex,
        reassembly_timeout: Duration::from_secs(3),
        work_limit: 8,
        task_shutdown_timeout: Duration::from_secs(1),
    }
}
async fn links(config: DeviceConfig) -> Result<(Link, Link, Vec<SocketAddr>), TestError> {
    let ca = UdpSocket::bind("127.0.0.1:0").await?;
    let sa = UdpSocket::bind("127.0.0.1:0").await?;
    let mut addresses = vec![ca.local_addr()?, sa.local_addr()?];
    let base = config.base_session_config()?;
    let mut first = carrier::Config::new(
        Path {
            client: ca.local_addr()?,
            server: sa.local_addr()?,
        },
        base,
        carrier::Protection::ChaCha20Poly1305,
    )?;
    first.heartbeat_interval = Duration::from_millis(20);
    first.arq.initial_rto = Duration::from_millis(40);
    first.arq.maximum_rto = Duration::from_millis(100);
    first.arq.max_retries = 100;
    first.bootstrap.arq.initial_rto = Duration::from_millis(20);
    first.bootstrap.arq.maximum_rto = Duration::from_millis(80);
    first.close_timeout = Duration::from_millis(300);
    let cert = rcgen::generate_simple_self_signed(vec!["native-openvpn.test".to_owned()])?;
    let chain = vec![cert.cert.der().to_vec()];
    let ctls = ClientTls::from_der_roots(&chain)?;
    let stls = ServerTls::from_der(&chain, &cert.signing_key.serialize_der())?;
    let member = MemberKey::from_pkcs8(&MemberKey::generate_pkcs8()?)?;
    let members = MemberAllowlist::new(&[member.public_key()])?;
    if config.duplex == Duplex::Full {
        let (a, b) = tokio::try_join!(
            carrier::client_connect(
                ca,
                first,
                carrier::ClientCredentials {
                    tls: &ctls,
                    server_name: "native-openvpn.test",
                    member: &member,
                    admission: Secret::new([1; 32])
                }
            ),
            carrier::server_accept(
                sa,
                first,
                carrier::ServerCredentials {
                    tls: &stls,
                    members: &members,
                    admission: Secret::new([1; 32]),
                    cookie: Secret::new([2; 32])
                }
            )
        )?;
        Ok((
            Link::full(a, first, config)?,
            Link::full(b, first, config)?,
            addresses,
        ))
    } else {
        let cb = UdpSocket::bind("127.0.0.1:0").await?;
        let sb = UdpSocket::bind("127.0.0.1:0").await?;
        addresses.extend([cb.local_addr()?, sb.local_addr()?]);
        first.profile.traffic = carrier::Traffic::HalfDuplex {
            sender: l2tunnel_datagram::Direction::ClientToServer,
        };
        let mut second = first;
        second.bootstrap.path = Path {
            client: cb.local_addr()?,
            server: sb.local_addr()?,
        };
        second.profile.lane = carrier::LaneId(1);
        second.profile.traffic = carrier::Traffic::HalfDuplex {
            sender: l2tunnel_datagram::Direction::ServerToClient,
        };
        let profiles = [first, second];
        let (a, b) = tokio::try_join!(
            carrier::client_pair(
                [ca, cb],
                profiles,
                carrier::ClientPairCredentials {
                    tls: &ctls,
                    server_name: "native-openvpn.test",
                    member: &member,
                    admissions: [Secret::new([1; 32]), Secret::new([3; 32])]
                }
            ),
            carrier::server_pair(
                [sa, sb],
                profiles,
                carrier::ServerPairCredentials {
                    tls: &stls,
                    members: &members,
                    admissions: [Secret::new([1; 32]), Secret::new([3; 32])],
                    cookies: [Secret::new([2; 32]), Secret::new([4; 32])]
                }
            )
        )?;
        Ok((
            Link::paired(a, profiles, config)?,
            Link::paired(b, profiles, config)?,
            addresses,
        ))
    }
}
async fn delivered(device: &Device, count: usize) -> io::Result<()> {
    timeout(Duration::from_secs(8), async {
        while device.change(|s| s.delivered.len())? < count {
            sleep(Duration::from_millis(5)).await;
        }
        Ok::<_, io::Error>(())
    })
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "test native delivery"))?
}
async fn stopped(mut tasks: JoinSet<io::Result<()>>, addresses: Vec<SocketAddr>) -> TestResult {
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    tokio::task::yield_now().await;
    for address in addresses {
        let _released = UdpSocket::bind(address).await?;
    }
    Ok(())
}
#[tokio::test]
async fn actual_full_and_paired_tap_tun_none_lz4_preserve_large_packet_bytes() -> TestResult {
    for duplex in [Duplex::Full, Duplex::Half] {
        for layer in [PacketLayer::Ethernet, PacketLayer::Ip] {
            for compression in [Compression::None, Compression::Lz4IfSmaller] {
                let config = native(duplex, layer, compression);
                let (a, b, addresses) = links(config).await?;
                let (ao, bo) = (a.observer(), b.observer());
                let ad = Device::new(layer);
                let bd = Device::new(layer);
                let forward = [
                    packet(layer, 64, 1),
                    packet(layer, 3000, 2),
                    packet(layer, 65_000, 3),
                ];
                let reverse = [packet(layer, 1500, 4), packet(layer, 6000, 5)];
                ad.change(|s| s.outgoing.extend(forward.clone()))?;
                bd.change(|s| s.outgoing.extend(reverse.clone()))?;
                let mut tasks = JoinSet::new();
                tasks.spawn(run(ad.clone(), a, config));
                tasks.spawn(run(bd.clone(), b, config));
                tokio::try_join!(delivered(&bd, forward.len()), delivered(&ad, reverse.len()))?;
                assert_eq!(bd.change(|s| s.delivered.clone())?, forward);
                assert_eq!(ad.change(|s| s.delivered.clone())?, reverse);
                assert_eq!(ao.snapshot()?.native_delivered, reverse.len() as u64);
                assert_eq!(bo.snapshot()?.native_delivered, forward.len() as u64);
                stopped(tasks, addresses).await?;
                assert!(ao.snapshot()?.stopped && bo.snapshot()?.stopped);
            }
        }
    }
    Ok(())
}
#[tokio::test]
async fn blocked_native_bounds_retention_and_preserves_reverse_and_tls_progress() -> TestResult {
    for duplex in [Duplex::Full, Duplex::Half] {
        let config = native(duplex, PacketLayer::Ip, Compression::None);
        let (a, b, addresses) = links(config).await?;
        let (ao, bo) = (a.observer(), b.observer());
        let ad = Device::new(PacketLayer::Ip);
        let bd = Device::new(PacketLayer::Ip);
        ad.change(|s| {
            s.outgoing
                .extend((0..200).map(|i| packet(PacketLayer::Ip, 1600, i as u8)))
        })?;
        bd.change(|s| {
            s.blocked = true;
            s.outgoing.push_back(packet(PacketLayer::Ip, 80, 9));
        })?;
        let mut tasks = JoinSet::new();
        tasks.spawn(run(ad.clone(), a, config));
        tasks.spawn(run(bd.clone(), b, config));
        delivered(&ad, 1).await?;
        sleep(Duration::from_millis(150)).await;
        let initial = bo.snapshot()?;
        assert_eq!(initial.native_delivered, 0);
        assert_eq!(initial.native_queue_packets, 2);
        assert_eq!(initial.native_queue_bytes, 3200);
        assert!(ad.change(|s| s.reads)? < 200);
        assert!(
            initial.reassembly_messages <= 1
                && initial.reassembly_bytes <= config.native.max_packet + 16
        );
        sleep(Duration::from_millis(100)).await;
        assert!(bo.snapshot()?.tls_messages > initial.tls_messages);
        assert!(ao.snapshot()?.outbound_fragments <= 256);
        bd.change(|s| s.blocked = false)?;
        delivered(&bd, 200).await?;
        assert_eq!(bo.snapshot()?.native_delivered, 200);
        stopped(tasks, addresses).await?;
    }
    Ok(())
}
#[tokio::test]
async fn actual_native_binding_mismatch_fails_before_device_receive() -> TestResult {
    let config = native(Duplex::Full, PacketLayer::Ip, Compression::None);
    let (a, b, _addresses) = links(config).await?;
    let device = Device::new(PacketLayer::Ip);
    device.change(|s| s.outgoing.push_back(packet(PacketLayer::Ip, 80, 1)))?;
    let mut changed = config;
    changed.work_limit += 1;
    assert!(run(device.clone(), a, changed).await.is_err());
    assert_eq!(device.change(|s| s.reads)?, 0);
    drop(b);
    Ok(())
}
#[tokio::test]
async fn authenticated_bad_fragment_gap_and_expiry_are_explicit_errors() -> TestResult {
    for case in 0..3 {
        let mut config = native(Duplex::Full, PacketLayer::Ip, Compression::None);
        config.reassembly_timeout = Duration::from_millis(40);
        let (a, b, _addresses) = links(config).await?;
        let observer = a.observer();
        let device = Device::new(PacketLayer::Ip);
        let peer = b.sender.clone();
        let peer_context = context(b.send_session)?;
        let task = tokio::spawn(run(device.clone(), a, config));
        if case == 0 {
            peer.send(b"bad authenticated fragment").await?;
        } else {
            let encoded = config
                .native
                .codec()?
                .encode_vec(&packet(PacketLayer::Ip, 3000, 7))?;
            let (_, count) = geometry(config, b.send_source)?;
            let mut fragmenter = Fragmenter::new(
                peer_context,
                FragmentConfig {
                    path_mtu: b.send_source,
                    outer_overhead_bytes: 0,
                    max_message_bytes: config.native.codec()?.max_encoded_len(),
                    max_fragments: count,
                },
                MessageId(if case == 1 { 1 } else { 0 }),
            )?;
            let batch = fragmenter.fragment(&encoded)?;
            peer.send(&batch.fragments[0]).await?;
        }
        let result = timeout(Duration::from_secs(1), task).await??;
        assert!(result.is_err());
        assert!(observer.snapshot()?.stopped);
        assert!(device.change(|s| s.delivered.is_empty())?);
        drop(b);
    }
    Ok(())
}
#[tokio::test]
async fn carrier_close_with_pending_native_is_incomplete_not_success() -> TestResult {
    let config = native(Duplex::Full, PacketLayer::Ip, Compression::None);
    let (a, b, _addresses) = links(config).await?;
    let observer = a.observer();
    let device = Device::new(PacketLayer::Ip);
    device.change(|s| s.blocked = true)?;
    let peer = b.sender.clone();
    let (_, count) = geometry(config, b.send_source)?;
    let mut fragmenter = Fragmenter::new(
        context(b.send_session)?,
        FragmentConfig {
            path_mtu: b.send_source,
            outer_overhead_bytes: 0,
            max_message_bytes: config.native.codec()?.max_encoded_len(),
            max_fragments: count,
        },
        MessageId(0),
    )?;
    let batch = fragmenter.fragment(&config.native.codec()?.encode_vec(&packet(
        PacketLayer::Ip,
        100,
        3,
    ))?)?;
    let task = tokio::spawn(run(device.clone(), a, config));
    for bytes in batch.fragments {
        peer.send(&bytes).await?;
    }
    timeout(Duration::from_secs(1), async {
        while observer.snapshot()?.native_queue_packets != 1 {
            sleep(Duration::from_millis(2)).await;
        }
        Ok::<_, io::Error>(())
    })
    .await??;
    let Owner::Full(owner) = b.owner else {
        return Err("unexpected pair".into());
    };
    let closing = tokio::spawn(owner.close());
    assert!(timeout(Duration::from_secs(1), task).await??.is_err());
    assert_eq!(observer.snapshot()?.native_delivered, 0);
    assert!(observer.snapshot()?.stopped);
    let _ = closing.await?;
    Ok(())
}
