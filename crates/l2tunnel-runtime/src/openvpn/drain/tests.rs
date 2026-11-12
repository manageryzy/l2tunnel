use super::*;
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
async fn links(
    config: DrainConfig,
) -> Result<(DrainingLink, DrainingLink, Vec<SocketAddr>), TestError> {
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
    if config.device.duplex == Duplex::Full {
        let first = carrier::NativeDrainConfig::new(first, config.drain_timeout)?;
        let (a, b) = tokio::try_join!(
            carrier::client_connect_native(
                ca,
                first,
                carrier::ClientCredentials {
                    tls: &ctls,
                    server_name: "native-openvpn.test",
                    member: &member,
                    admission: Secret::new([1; 32])
                }
            ),
            carrier::server_accept_native(
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
            DrainingLink::full(a, first, config)?,
            DrainingLink::full(b, first, config)?,
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
        let profiles = [
            carrier::NativeDrainConfig::new(first, config.drain_timeout)?,
            carrier::NativeDrainConfig::new(second, config.drain_timeout)?,
        ];
        let (a, b) = tokio::try_join!(
            carrier::client_pair_native(
                [ca, cb],
                profiles,
                carrier::ClientPairCredentials {
                    tls: &ctls,
                    server_name: "native-openvpn.test",
                    member: &member,
                    admissions: [Secret::new([1; 32]), Secret::new([3; 32])]
                }
            ),
            carrier::server_pair_native(
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
            DrainingLink::paired(a, profiles, config)?,
            DrainingLink::paired(b, profiles, config)?,
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
fn config(duplex: Duplex, layer: PacketLayer, compression: Compression) -> DrainConfig {
    DrainConfig {
        device: native(duplex, layer, compression),
        drain_timeout: Duration::from_secs(2),
    }
}
async fn wait_reads(device: &Device, count: usize) -> io::Result<()> {
    timeout(Duration::from_secs(2), async {
        while device.change(|s| s.reads)? < count {
            sleep(Duration::from_millis(1)).await;
        }
        Ok::<_, io::Error>(())
    })
    .await
    .map_err(io::Error::other)?
}
#[tokio::test]
async fn actual_native_prefixes_full_half_tap_tun_none_lz4_then_clean_carrier() -> TestResult {
    for duplex in [Duplex::Full, Duplex::Half] {
        for layer in [PacketLayer::Ethernet, PacketLayer::Ip] {
            for compression in [Compression::None, Compression::Lz4IfSmaller] {
                let config = config(duplex, layer, compression);
                let (a, b, _) = links(config).await?;
                let ad = Device::new(layer);
                let bd = Device::new(layer);
                let forward = packet(layer, 4096, 19);
                let reverse = packet(layer, 3072, 37);
                ad.change(|s| s.outgoing.push_back(forward.clone()))?;
                bd.change(|s| s.outgoing.push_back(reverse.clone()))?;
                let (stopa, sa) = shutdown_request();
                let (stopb, sb) = shutdown_request();
                let ta = tokio::spawn(run_draining(ad.clone(), a, config, sa));
                let tb = tokio::spawn(run_draining(bd.clone(), b, config, sb));
                delivered(&ad, 1).await?;
                delivered(&bd, 1).await?;
                stopa.request()?;
                stopb.request()?;
                let a = timeout(Duration::from_secs(3), ta).await???;
                let b = timeout(Duration::from_secs(3), tb).await???;
                assert_eq!(ad.change(|s| s.delivered.clone())?, [reverse]);
                assert_eq!(bd.change(|s| s.delivered.clone())?, [forward]);
                assert_eq!((a.local.packets, a.local.native_bytes), (1, 4096));
                assert_eq!((b.local.packets, b.local.native_bytes), (1, 3072));
                assert_eq!(a.local, b.peer);
                assert_eq!(a.peer, b.local);
                assert!(matches!(
                    (duplex, a.carrier),
                    (Duplex::Full, CarrierClose::Full(_)) | (Duplex::Half, CarrierClose::Paired(_))
                ));
            }
        }
    }
    Ok(())
}
#[tokio::test]
async fn zero_packet_peer_only_stop_is_clean_without_reading_later_native_input() -> TestResult {
    for duplex in [Duplex::Full, Duplex::Half] {
        let cfg = config(duplex, PacketLayer::Ip, Compression::None);
        let (a, b, _) = links(cfg).await?;
        let ad = Device::new(PacketLayer::Ip);
        let bd = Device::new(PacketLayer::Ip);
        let (stopa, sa) = shutdown_request();
        let (_stopb, sb) = shutdown_request();
        stopa.request()?;
        let (a, b) = tokio::join!(
            run_draining(ad.clone(), a, cfg, sa),
            run_draining(bd.clone(), b, cfg, sb)
        );
        assert_eq!(a?.local, NativeFence::default());
        assert_eq!(b?.peer, NativeFence::default());
        assert_eq!(ad.change(|s| s.reads)?, 0);
        assert_eq!(bd.change(|s| s.reads)?, 0);
    }
    Ok(())
}
#[tokio::test]
async fn peer_stop_and_reverse_progress_survive_native_would_block_until_actual_confirmation()
-> TestResult {
    let cfg = config(Duplex::Half, PacketLayer::Ip, Compression::None);
    let (a, b, _) = links(cfg).await?;
    let ad = Device::new(PacketLayer::Ip);
    let bd = Device::new(PacketLayer::Ip);
    let forward = packet(PacketLayer::Ip, 32_000, 12);
    let reverse = packet(PacketLayer::Ip, 400, 17);
    ad.change(|s| s.outgoing.push_back(forward.clone()))?;
    bd.change(|s| {
        s.blocked = true;
        s.outgoing.push_back(reverse.clone());
    })?;
    let (stopa, sa) = shutdown_request();
    let (_stopb, sb) = shutdown_request();
    let ta = tokio::spawn(run_draining(ad.clone(), a, cfg, sa));
    let tb = tokio::spawn(run_draining(bd.clone(), b, cfg, sb));
    wait_reads(&ad, 1).await?;
    delivered(&ad, 1).await?;
    stopa.request()?;
    sleep(Duration::from_millis(40)).await;
    assert!(!ta.is_finished());
    assert!(!tb.is_finished());
    assert_eq!(bd.change(|s| s.delivered.len())?, 0);
    bd.change(|s| s.blocked = false)?;
    let a = timeout(Duration::from_secs(3), ta).await???;
    let b = timeout(Duration::from_secs(3), tb).await???;
    assert_eq!(a.local, b.peer);
    assert_eq!(b.peer.native_bytes, 32_000);
    assert!(b.peer.sources > 1);
    assert_eq!(bd.change(|s| s.delivered.clone())?, [forward]);
    assert_eq!(ad.change(|s| s.delivered.clone())?, [reverse]);
    Ok(())
}
#[tokio::test]
async fn blocked_native_deadline_returns_retained_inventory_without_restarting_for_close()
-> TestResult {
    let mut cfg = config(Duplex::Full, PacketLayer::Ip, Compression::None);
    cfg.drain_timeout = Duration::from_millis(140);
    let (a, b, _) = links(cfg).await?;
    let ad = Device::new(PacketLayer::Ip);
    let bd = Device::new(PacketLayer::Ip);
    ad.change(|s| s.outgoing.push_back(packet(PacketLayer::Ip, 4000, 1)))?;
    bd.change(|s| s.blocked = true)?;
    let (stopa, sa) = shutdown_request();
    let (_stopb, sb) = shutdown_request();
    let ta = tokio::spawn(run_draining(ad.clone(), a, cfg, sa));
    let tb = tokio::spawn(run_draining(bd.clone(), b, cfg, sb));
    wait_reads(&ad, 1).await?;
    sleep(Duration::from_millis(30)).await;
    let started = Instant::now();
    stopa.request()?;
    let a = timeout(Duration::from_secs(1), ta)
        .await??
        .err()
        .ok_or_else(|| invalid("blocked peer produced clean receipt"))?;
    let b = timeout(Duration::from_secs(1), tb)
        .await??
        .err()
        .ok_or_else(|| invalid("blocked native produced clean receipt"))?;
    assert!(started.elapsed() < Duration::from_millis(500));
    assert_eq!(a.reason.kind(), io::ErrorKind::TimedOut);
    assert_eq!(b.progress.native_confirmed, 0);
    assert_eq!(b.progress.pending_native_packets, 1);
    assert_eq!(b.progress.pending_native_bytes, 4000);
    assert_eq!(b.progress.native_completed, 1);
    Ok(())
}
#[tokio::test]
async fn canceled_shutdown_and_preexpired_original_timestamp_never_become_clean() -> TestResult {
    for expired in [false, true] {
        let mut cfg = config(Duplex::Full, PacketLayer::Ip, Compression::None);
        cfg.drain_timeout = Duration::from_millis(50);
        let (a, b, _) = links(cfg).await?;
        let (request, signal) = shutdown_request();
        if expired {
            request.request()?;
            sleep(Duration::from_millis(60)).await;
        } else {
            drop(request);
        }
        let result = run_draining(Device::new(PacketLayer::Ip), a, cfg, signal)
            .await
            .err()
            .ok_or_else(|| invalid("canceled request produced clean receipt"))?;
        assert_eq!(
            result.reason.kind(),
            if expired {
                io::ErrorKind::TimedOut
            } else {
                io::ErrorKind::Interrupted
            }
        );
        assert_eq!(result.progress.accepted, NativeFence::default());
        drop(b);
    }
    Ok(())
}
#[test]
fn native_drain_policy_binds_original_device_policy_and_new_deadline() -> io::Result<()> {
    let cfg = config(Duplex::Full, PacketLayer::Ip, Compression::None);
    let base = cfg.base_session_config()?;
    assert_ne!(base, cfg.device.base_session_config()?);
    let mut other = cfg;
    other.drain_timeout += Duration::from_millis(1);
    assert_ne!(base, other.base_session_config()?);
    other = cfg;
    other.device.work_limit += 1;
    assert_ne!(base, other.base_session_config()?);
    Ok(())
}

/// Deliberate finite CPU service makes the next microsecond tick already ready.
struct BusyDevice(Device);
impl PacketDevice for BusyDevice {
    type Error = io::Error;
    fn layer(&self) -> PacketLayer {
        self.0.layer()
    }
    fn receive(&mut self, out: &mut [u8]) -> io::Result<Option<usize>> {
        let start = Instant::now();
        while start.elapsed() < Duration::from_micros(10) {
            std::hint::spin_loop();
        }
        self.0.receive(out)
    }
    fn transmit(&mut self, bytes: &[u8]) -> io::Result<()> {
        self.0.transmit(bytes)
    }
}
#[tokio::test]
async fn perpetually_ready_poll_timer_does_not_starve_actual_source_work() -> TestResult {
    let mut cfg = config(Duplex::Full, PacketLayer::Ip, Compression::None);
    cfg.device.native.poll_interval = Duration::from_micros(1);
    let (a, b, _) = links(cfg).await?;
    let ad = Device::new(PacketLayer::Ip);
    let bd = Device::new(PacketLayer::Ip);
    let bytes = packet(PacketLayer::Ip, 12_000, 31);
    ad.change(|s| s.outgoing.push_back(bytes.clone()))?;
    bd.change(|s| s.outgoing.push_back(bytes.clone()))?;
    let (stopa, sa) = shutdown_request();
    let (stopb, sb) = shutdown_request();
    let ta = tokio::spawn(run_draining(BusyDevice(ad.clone()), a, cfg, sa));
    let tb = tokio::spawn(run_draining(BusyDevice(bd.clone()), b, cfg, sb));
    delivered(&ad, 1).await?;
    delivered(&bd, 1).await?;
    stopa.request()?;
    stopb.request()?;
    let a = timeout(Duration::from_secs(3), ta).await???;
    let b = timeout(Duration::from_secs(3), tb).await???;
    assert_eq!(a.local, b.peer);
    assert!(a.local.sources > 1);
    assert_eq!(ad.change(|s| s.delivered.clone())?, [bytes]);
    Ok(())
}
