//! Real original TCP/TLS/auth/packet owners with finite in-memory native devices.
use super::*;
use carrier::{PacketPolicy, Protection};
use l2tunnel_raw_io::handoff::{
    MessageLimits, SwitchLimits,
    pairing::{PairConfig, RawInput},
};
use std::{
    future::poll_fn,
    net::{Ipv4Addr, SocketAddrV4},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
};
use tokio::sync::mpsc;
type R<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;
#[derive(Default)]
struct Probe {
    receives: AtomicUsize,
    sends: AtomicUsize,
    dropped: AtomicUsize,
    phase: AtomicUsize,
    loss: AtomicUsize,
    blocked: AtomicBool,
    impair: AtomicBool,
    held: Mutex<Option<Vec<u8>>>,
}
struct Io {
    incoming: mpsc::Receiver<Vec<u8>>,
    outgoing: mpsc::Sender<Vec<u8>>,
    probe: Arc<Probe>,
}
impl PacketIo for Io {
    fn receive(&mut self, out: &mut [u8]) -> io::Result<Option<usize>> {
        self.probe.receives.fetch_add(1, Ordering::SeqCst);
        assert_eq!(out.len(), 65536);
        match self.incoming.try_recv() {
            Ok(p) => {
                out[..p.len()].copy_from_slice(&p);
                Ok(Some(p.len()))
            }
            Err(_) => Ok(None),
        }
    }
    fn send(&mut self, bytes: &[u8]) -> io::Result<()> {
        self.probe.sends.fetch_add(1, Ordering::SeqCst);
        if self.probe.blocked.load(Ordering::SeqCst) {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        let phase = bytes.get(40..).is_some_and(|body| {
            [Protection::ChaCha20Poly1305, Protection::HmacSha256]
                .into_iter()
                .any(|protection| {
                    l2tunnel_datagram::inspect_structural(
                        l2tunnel_datagram::CoverProfile::OpenVpnLike,
                        protection,
                        536,
                        472,
                        body,
                    )
                    .is_ok()
                })
        });
        if phase && self.probe.impair.load(Ordering::SeqCst) {
            let n = self.probe.phase.fetch_add(1, Ordering::SeqCst) + 1;
            if n.is_multiple_of(7) {
                self.probe.loss.fetch_add(1, Ordering::SeqCst);
                return Ok(());
            }
            let mut held = self
                .probe
                .held
                .lock()
                .map_err(|_| invalid("fixture held lock"))?;
            if held.is_none() && n.is_multiple_of(3) {
                *held = Some(bytes.to_vec());
                return Ok(());
            }
            self.outgoing
                .try_send(bytes.to_vec())
                .map_err(|_| io::Error::from(io::ErrorKind::WouldBlock))?;
            if let Some(old) = held.take() {
                self.outgoing
                    .try_send(old)
                    .map_err(|_| io::Error::from(io::ErrorKind::WouldBlock))?;
            }
            if n.is_multiple_of(5) {
                self.outgoing
                    .try_send(bytes.to_vec())
                    .map_err(|_| io::Error::from(io::ErrorKind::WouldBlock))?;
            }
            return Ok(());
        }
        self.outgoing
            .try_send(bytes.to_vec())
            .map_err(|_| io::Error::from(io::ErrorKind::WouldBlock))
    }
}
impl Drop for Io {
    fn drop(&mut self) {
        self.probe.dropped.fetch_add(1, Ordering::SeqCst);
    }
}
fn tcp(client: bool, lane: u16) -> l2tunnel_raw_tcp::Config {
    let a = SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 11), 45001 + lane * 2);
    let b = SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 12), 45002 + lane * 2);
    l2tunnel_raw_tcp::Config {
        local: if client { a } else { b },
        peer: if client { b } else { a },
        mtu: 576,
        send_bytes: 32768,
        receive_bytes: 32768,
        packet_slots: 16,
        random_seed: if client {
            0x3131 + u64::from(lane)
        } else {
            0x4242 + u64::from(lane)
        },
        ack_delay_millis: 1,
        keepalive_millis: 1000,
        idle_timeout_millis: 30000,
    }
}
fn inputs(half: bool) -> (RawInputs<Io>, RawInputs<Io>, Vec<Arc<Probe>>) {
    let mut probes = Vec::new();
    let mut lane = |index| {
        let (at, br) = mpsc::channel(256);
        let (bt, ar) = mpsc::channel(256);
        let a = Arc::new(Probe::default());
        let b = Arc::new(Probe::default());
        probes.push(a.clone());
        probes.push(b.clone());
        (
            RawInput {
                config: tcp(true, index),
                io: Io {
                    incoming: ar,
                    outgoing: at,
                    probe: a,
                },
            },
            RawInput {
                config: tcp(false, index),
                io: Io {
                    incoming: br,
                    outgoing: bt,
                    probe: b,
                },
            },
        )
    };
    let (a, b) = lane(0);
    if half {
        let (c, d) = lane(1);
        (
            RawInputs::Half {
                forward: a,
                reverse: c,
            },
            RawInputs::Half {
                forward: b,
                reverse: d,
            },
            probes,
        )
    } else {
        (RawInputs::Full(a), RawInputs::Full(b), probes)
    }
}
fn config(
    layer: PacketLayer,
    half: bool,
    cauchy: bool,
    protection: Protection,
) -> io::Result<Config> {
    let runtime = RuntimeConfig {
        layer,
        max_packet: 4000,
        compression: Compression::None,
        queue_packets: 2,
        poll_interval: Duration::from_millis(1),
    };
    let mut packet = PacketPolicy::new(576);
    packet.protection = protection;
    let transport = PacketPhaseConfig {
        pair: PairConfig {
            session: SessionConfig {
                layer,
                digest: ConfigDigest([0x31; 32]),
            },
            messages: MessageLimits::default(),
            driver: SwitchLimits::default(),
            timeout: Duration::from_secs(10),
        },
        packet,
    };
    let mut config = Config::new(
        runtime,
        transport,
        if half { Duplex::Half } else { Duplex::Full },
        4,
    )?;
    config.arq.initial_rto = Duration::from_millis(25);
    config.arq.maximum_rto = Duration::from_millis(100);
    config.arq.ack_delay = Duration::from_millis(1);
    config.arq.max_retries = 20;
    config.reassembly_timeout = Duration::from_secs(3);
    config.credit_interval = Duration::from_millis(5);
    if cauchy {
        config = config.with_recovery(udp::RecoveryMode::Cauchy {
            sources: 4,
            repairs: 2,
            flush_after: Duration::from_millis(2),
        })?;
    }
    config.validate()?;
    Ok(config)
}
async fn links(config: Config) -> R<(Link<Io>, Link<Io>, Vec<Arc<Probe>>)> {
    let cert = rcgen::generate_simple_self_signed(vec!["tunnel.test".to_owned()])?;
    let chain = vec![cert.cert.der().to_vec()];
    let client = ClientTls::from_der_roots(&chain)?;
    let server = ServerTls::from_der(&chain, &cert.signing_key.serialize_der())?;
    let member = MemberKey::from_pkcs8(&MemberKey::generate_pkcs8()?)?;
    let allowed = MemberAllowlist::new(&[member.public_key()])?;
    let (a, b, probes) = inputs(config.duplex == Duplex::Half);
    let mut a = begin_client(a, &client, "tunnel.test", &member, config)?;
    let mut b = begin_server(b, &server, &allowed, config)?;
    let (mut ar, mut br) = (None, None);
    poll_fn(|cx| {
        for (setup, result) in [(&mut a, &mut ar), (&mut b, &mut br)] {
            if let Some(link) = result {
                if let Poll::Ready(Err(e)) = Link::poll_progress(link, cx) {
                    return Poll::Ready(Err(e));
                }
            } else if let Poll::Ready(ready) = Pin::new(setup).poll(cx) {
                *result = Some(ready?);
            }
        }
        if ar.is_some() && br.is_some() {
            Poll::Ready(Ok(()))
        } else {
            Poll::Pending
        }
    })
    .await?;
    Ok((ar.ok_or("client link")?, br.ok_or("server link")?, probes))
}
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
        let mut native = self
            .native
            .lock()
            .map_err(|_| invalid("native fixture lock"))?;
        Ok(f(&mut native))
    }
}
impl PacketDevice for Device {
    type Error = io::Error;
    fn layer(&self) -> PacketLayer {
        self.layer
    }
    fn receive(&mut self, out: &mut [u8]) -> io::Result<Option<usize>> {
        assert!(out.len() >= l2tunnel_device::READ_BUFFER_BYTES);
        self.change(|s| {
            s.outgoing.pop_front().map(|p| {
                s.reads += 1;
                out[..p.len()].copy_from_slice(&p);
                p.len()
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
fn packet(layer: PacketLayer, tag: u8, length: usize) -> Vec<u8> {
    let mut p = vec![tag; length];
    match layer {
        PacketLayer::Ethernet => {
            p[..12].copy_from_slice(&[2, 1, 2, 3, 4, 5, 2, 6, 7, 8, 9, 10]);
            p[12..14].copy_from_slice(&0x88b5u16.to_be_bytes());
        }
        PacketLayer::Ip => {
            p[..40].fill(0);
            p[0] = 0x45;
            p[2..4].copy_from_slice(&(length as u16).to_be_bytes());
            p[8] = 64;
            p[9] = 6;
            p[12..16].copy_from_slice(&[10, 0, 0, 1]);
            p[16..20].copy_from_slice(&[10, 0, 0, 2]);
            p[20..22].copy_from_slice(&(1000 + u16::from(tag)).to_be_bytes());
            p[22..24].copy_from_slice(&2000u16.to_be_bytes());
            p[32] = 0x50;
            p[33] = if length == 40 { 0x02 } else { 0x18 };
            p[34..36].copy_from_slice(&u16::MAX.to_be_bytes());
        }
    }
    p
}
async fn wait_native(a: &Device, b: &Device, n: usize) -> R {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if a.change(|s| s.delivered.len())? == n && b.change(|s| s.delivered.len())? == n {
                return Ok::<_, io::Error>(());
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await??;
    Ok(())
}
#[tokio::test]
async fn actual_full_half_native_mux_recovery_and_protection_matrix() -> R {
    for (layer, half, cauchy, protection) in [
        (PacketLayer::Ip, false, false, Protection::ChaCha20Poly1305),
        (
            PacketLayer::Ethernet,
            true,
            false,
            Protection::ChaCha20Poly1305,
        ),
        (PacketLayer::Ip, true, true, Protection::ChaCha20Poly1305),
        (PacketLayer::Ethernet, false, true, Protection::HmacSha256),
    ] {
        let config = config(layer, half, cauchy, protection)?;
        let (a, b, probes) = links(config).await?;
        let ast = a.subscribe();
        let bst = b.subscribe();
        let ad = Device::new(layer);
        let bd = Device::new(layer);
        let forward: Vec<_> = [40, 73, 1500, 4000]
            .into_iter()
            .enumerate()
            .map(|(i, n)| packet(layer, i as u8 + 1, n))
            .collect();
        let reverse: Vec<_> = [4000, 1500, 73, 40]
            .into_iter()
            .enumerate()
            .map(|(i, n)| packet(layer, i as u8 + 10, n))
            .collect();
        ad.change(|s| s.outgoing = forward.clone().into())?;
        bd.change(|s| s.outgoing = reverse.clone().into())?;
        let ar = tokio::spawn(run(ad.clone(), a));
        let br = tokio::spawn(run(bd.clone(), b));
        wait_native(&ad, &bd, forward.len()).await?;
        assert_eq!(ad.change(|s| s.delivered.clone())?, reverse);
        assert_eq!(bd.change(|s| s.delivered.clone())?, forward);
        assert_eq!(ast.borrow().admitted.iter().sum::<u64>(), 4);
        assert_eq!(bst.borrow().delivered.iter().sum::<u64>(), 4);
        ar.abort();
        br.abort();
        let _ = ar.await;
        let _ = br.await;
        assert_eq!(ast.borrow().phase, Phase::Stopped);
        assert!(probes.iter().all(|p| p.dropped.load(Ordering::SeqCst) == 1));
    }
    Ok(())
}
#[tokio::test]
async fn actual_loss_reorder_duplicates_preserve_native_identity_and_credit() -> R {
    for (half, cauchy) in [(false, false), (true, false), (true, true)] {
        let config = config(PacketLayer::Ip, half, cauchy, Protection::ChaCha20Poly1305)?;
        let (a, b, probes) = links(config).await?;
        for p in &probes {
            p.impair.store(true, Ordering::SeqCst);
        }
        let ad = Device::new(PacketLayer::Ip);
        let bd = Device::new(PacketLayer::Ip);
        let packets: Vec<_> = (0..5)
            .map(|i| packet(PacketLayer::Ip, i + 1, 4000))
            .collect();
        ad.change(|s| s.outgoing = packets.clone().into())?;
        bd.change(|s| s.outgoing = packets.clone().into())?;
        let ast = a.subscribe();
        let bst = b.subscribe();
        let ar = tokio::spawn(run(ad.clone(), a));
        let br = tokio::spawn(run(bd.clone(), b));
        if let Err(e) = wait_native(&ad, &bd, packets.len()).await {
            eprintln!(
                "impaired half={half} client={:?} server={:?} native=({:?},{:?})",
                *ast.borrow(),
                *bst.borrow(),
                ad.change(|s| s.delivered.len())?,
                bd.change(|s| s.delivered.len())?
            );
            if ar.is_finished() {
                eprintln!("client result {:?}", ar.await);
            } else {
                ar.abort();
                let _ = ar.await;
            }
            if br.is_finished() {
                eprintln!("server result {:?}", br.await);
            } else {
                br.abort();
                let _ = br.await;
            }
            return Err(e);
        }
        assert_eq!(ad.change(|s| s.delivered.clone())?, packets);
        assert_eq!(bd.change(|s| s.delivered.clone())?, packets);
        assert_eq!(ast.borrow().admitted.iter().sum::<u64>(), 5);
        assert_eq!(bst.borrow().received.iter().sum::<u64>(), 5);
        assert!(
            probes
                .iter()
                .map(|p| p.loss.load(Ordering::SeqCst))
                .sum::<usize>()
                > 0
        );
        ar.abort();
        br.abort();
        let _ = ar.await;
        let _ = br.await;
        assert!(probes.iter().all(|p| p.dropped.load(Ordering::SeqCst) == 1));
    }
    Ok(())
}
#[tokio::test]
async fn blocked_native_keeps_confirmation_credit_bounded_and_reverse_lane_live() -> R {
    let config = config(PacketLayer::Ip, true, false, Protection::ChaCha20Poly1305)?;
    let (a, b, _) = links(config).await?;
    let ast = a.subscribe();
    let ad = Device::new(PacketLayer::Ip);
    let bd = Device::new(PacketLayer::Ip);
    let forward: Vec<_> = (0..4)
        .map(|i| packet(PacketLayer::Ip, i + 1, 1500))
        .collect();
    let reverse = vec![
        packet(PacketLayer::Ip, 10, 40),
        packet(PacketLayer::Ip, 11, 73),
        packet(PacketLayer::Ip, 12, 1500),
    ];
    ad.change(|s| s.outgoing = forward.clone().into())?;
    bd.change(|s| {
        s.outgoing = reverse.clone().into();
        s.blocked = true;
    })?;
    let ar = tokio::spawn(run(ad.clone(), a));
    let br = tokio::spawn(run(bd.clone(), b));
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            if ad.change(|s| s.delivered.len())? == 3 && ast.borrow().admitted[0] == 2 {
                return Ok::<_, io::Error>(());
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await??;
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(ast.borrow().peer_delivered[0], 0);
    assert_eq!(ast.borrow().admitted[0], 2);
    assert!(bd.change(|s| s.delivered.is_empty())?);
    assert_eq!(ad.change(|s| s.delivered.clone())?, reverse);
    bd.change(|s| s.blocked = false)?;
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            if bd.change(|s| s.delivered.len())? == 4 {
                return Ok::<_, io::Error>(());
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await??;
    assert_eq!(bd.change(|s| s.delivered.clone())?, forward);
    ar.abort();
    br.abort();
    let _ = ar.await;
    let _ = br.await;
    Ok(())
}

#[test]
fn canonical_runtime_binding_covers_native_mux_recovery_and_feedback_policy() -> R {
    let base = config(PacketLayer::Ip, false, false, Protection::ChaCha20Poly1305)?;
    let digest = base.session_config()?.digest;
    let mut cases = Vec::new();
    let mut c = base;
    c.runtime.max_packet -= 1;
    c.pipeline.parse.max_packet_bytes -= 1;
    c.pipeline.queue.bytes = c.runtime.max_packet * c.runtime.queue_packets;
    if let pipeline::Profile::TunDrr(mut qos) = c.pipeline.profile {
        qos.per_flow.bytes = c.pipeline.queue.bytes;
        qos.base_quantum_bytes = c.runtime.max_packet as u32;
        c.pipeline.profile = pipeline::Profile::TunDrr(qos);
    }
    cases.push(c);
    let mut c = base;
    c.runtime.compression = Compression::Lz4IfSmaller;
    cases.push(c);
    let mut c = base;
    c.pipeline.flows.channels += 1;
    cases.push(c);
    let mut c = base;
    c.pipeline.flows.idle_timeout += Duration::from_nanos(1);
    cases.push(c);
    let mut c = base;
    c.pipeline.flows.capacity -= 1;
    cases.push(c);
    let mut c = base;
    c.pipeline.queue.packets -= 1;
    if let pipeline::Profile::TunDrr(mut qos) = c.pipeline.profile {
        qos.per_flow.packets = c.pipeline.queue.packets;
        c.pipeline.profile = pipeline::Profile::TunDrr(qos);
    }
    cases.push(c);
    let mut c = base;
    c.arq.max_retries -= 1;
    cases.push(c);
    let mut c = base;
    c.arq.initial_rto += Duration::from_micros(1);
    cases.push(c);
    let mut c = base;
    c.credit_interval += Duration::from_micros(1);
    cases.push(c);
    let mut c = base;
    c.reassembly_timeout += Duration::from_micros(1);
    cases.push(c);
    let mut c = base;
    c.transport.pair.session.digest.0[0] ^= 1;
    cases.push(c);
    cases.push(base.with_recovery(RecoveryMode::Cauchy {
        sources: 4,
        repairs: 2,
        flush_after: Duration::from_millis(2),
    })?);
    for c in cases {
        assert_ne!(c.session_config()?.digest, digest);
    }
    let mut invalid = base;
    invalid.pipeline.flows.channels = 0;
    assert!(invalid.validate().is_err());
    let mut invalid = base;
    invalid.pipeline.queue.packets = base.runtime.queue_packets + 1;
    assert!(invalid.validate().is_err());
    let mut invalid = base;
    invalid.arq.max_source_bytes = usize::MAX;
    assert!(invalid.validate().is_err());
    let mut edge = base;
    edge.runtime.max_packet = l2tunnel_wire::MAX_PAYLOAD - l2tunnel_codec::FRAME_HEADER_BYTES;
    edge.pipeline.parse.max_packet_bytes = edge.runtime.max_packet;
    edge.pipeline.queue.bytes = edge.runtime.max_packet * edge.runtime.queue_packets;
    if let pipeline::Profile::TunDrr(mut q) = edge.pipeline.profile {
        q.per_flow.bytes = edge.pipeline.queue.bytes;
        q.base_quantum_bytes = edge.runtime.max_packet as u32;
        edge.pipeline.profile = pipeline::Profile::TunDrr(q);
    }
    edge.arq.max_source_bytes = FRAGMENT_HEADER_BYTES + 1;
    edge.arq.send_bytes = 64 * edge.arq.max_source_bytes;
    edge.arq.receive_bytes = edge.arq.send_bytes;
    assert!(edge.validate().is_err());
    let mut invalid = base;
    invalid.credit_interval = Duration::ZERO;
    assert!(invalid.validate().is_err());
    Ok(())
}
#[tokio::test]
async fn wrong_device_layer_is_rejected_before_native_poll_and_drops_original_owner() -> R {
    let config = config(PacketLayer::Ip, false, false, Protection::ChaCha20Poly1305)?;
    let (a, b, probes) = links(config).await?;
    let status = a.subscribe();
    let device = Device::new(PacketLayer::Ethernet);
    let error = run(device.clone(), a)
        .await
        .err()
        .ok_or("expected layer error")?;
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    assert_eq!(device.change(|s| s.reads)?, 0);
    assert_eq!(status.borrow().phase, Phase::Stopped);
    assert_eq!(status.borrow().fault, Some(io::ErrorKind::InvalidData));
    assert_eq!(probes[0].dropped.load(Ordering::SeqCst), 1);
    assert_eq!(probes[1].dropped.load(Ordering::SeqCst), 0);
    drop(b);
    assert_eq!(probes[1].dropped.load(Ordering::SeqCst), 1);
    Ok(())
}
async fn bad_control(bytes: Vec<u8>, kind: carrier::RecordKind) -> R<io::ErrorKind> {
    let config = config(PacketLayer::Ip, false, false, Protection::ChaCha20Poly1305)?;
    let (mut a, mut b, probes) = links(config).await?;
    let mut owner = Owner::new(
        Device::new(PacketLayer::Ip),
        a.carrier.take().ok_or("carrier")?,
        config,
        a.status.clone(),
    )?;
    let mut staged = false;
    let result = tokio::time::timeout(
        Duration::from_secs(1),
        poll_fn(|cx| {
            if !staged {
                match b
                    .carrier
                    .as_mut()
                    .ok_or_else(|| invalid("carrier"))?
                    .stage_record(PairLane::First, kind, &bytes)
                {
                    Ok(()) => staged = true,
                    Err(carrier::Error::Busy) => {}
                    Err(e) => return Poll::Ready(Err(carrier_error(e))),
                }
            }
            if let Poll::Ready(Err(e)) = b.poll_progress(cx) {
                return Poll::Ready(Err(e));
            }
            match owner.turn(cx) {
                Err(e) => Poll::Ready(Ok(e.kind())),
                Ok(progress) => {
                    if progress {
                        cx.waker().wake_by_ref();
                    }
                    Poll::Pending
                }
            }
        }),
    )
    .await??;
    drop(owner);
    drop(a);
    drop(b);
    assert!(probes.iter().all(|p| p.dropped.load(Ordering::SeqCst) == 1));
    Ok(result)
}
#[tokio::test]
async fn authenticated_impossible_credit_reserved_bytes_and_control_kind_fail_closed() -> R {
    assert_eq!(
        bad_control(
            encode(3, &1u64.to_be_bytes()),
            carrier::RecordKind::Feedback
        )
        .await?,
        io::ErrorKind::InvalidData
    );
    let mut reserved = encode(3, &0u64.to_be_bytes());
    reserved[7] = 1;
    assert_eq!(
        bad_control(reserved, carrier::RecordKind::Feedback).await?,
        io::ErrorKind::InvalidData
    );
    assert_eq!(
        bad_control(encode(3, &0u64.to_be_bytes()), carrier::RecordKind::Data).await?,
        io::ErrorKind::InvalidData
    );
    assert_eq!(
        bad_control(encode(3, &[0; 7]), carrier::RecordKind::Feedback).await?,
        io::ErrorKind::InvalidData
    );
    Ok(())
}
#[tokio::test(start_paused = true)]
async fn absent_active_peer_has_finite_liveness_failure_and_no_original_io_leak() -> R {
    let config = config(PacketLayer::Ip, false, false, Protection::ChaCha20Poly1305)?;
    let (a, b, probes) = links(config).await?;
    let status = a.subscribe();
    drop(b);
    let task = tokio::spawn(run(Device::new(PacketLayer::Ip), a));
    tokio::task::yield_now().await;
    tokio::time::advance(Duration::from_secs(16)).await;
    let error = task.await?.err().ok_or("expected liveness failure")?;
    assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    assert_eq!(status.borrow().phase, Phase::Stopped);
    assert!(probes.iter().all(|p| p.dropped.load(Ordering::SeqCst) == 1));
    Ok(())
}
#[tokio::test]
async fn authenticated_bad_native_channel_never_reaches_device() -> R {
    let config = config(PacketLayer::Ip, false, false, Protection::ChaCha20Poly1305)?;
    let (mut a, mut b, probes) = links(config).await?;
    let device = Device::new(PacketLayer::Ip);
    let mut owner = Owner::new(
        device.clone(),
        a.carrier.take().ok_or("carrier")?,
        config,
        a.status.clone(),
    )?;
    let mut sender = Owner::new(
        Device::new(PacketLayer::Ip),
        b.carrier.take().ok_or("carrier")?,
        config,
        b.status.clone(),
    )?;
    let native = packet(PacketLayer::Ip, 1, 40);
    let encoded = sender.codec.encode_vec(&native)?;
    let mut frame = vec![0xff, 0xff, 0, 0];
    frame.extend_from_slice(&encoded);
    let fragments = sender.lanes[0].fragmenter.fragment(&frame)?.fragments;
    for fragment in fragments {
        sender.lanes[0].engine.submit(&fragment, Duration::ZERO)?;
    }
    let result = tokio::time::timeout(
        Duration::from_secs(1),
        poll_fn(|cx| {
            match sender.turn(cx) {
                Err(e) => return Poll::Ready(Err(e)),
                Ok(progress) => {
                    if progress {
                        cx.waker().wake_by_ref();
                    }
                }
            }
            match owner.turn(cx) {
                Err(e) => Poll::Ready(Ok(e.kind())),
                Ok(progress) => {
                    if progress {
                        cx.waker().wake_by_ref();
                    }
                    Poll::Pending
                }
            }
        }),
    )
    .await??;
    assert_eq!(result, io::ErrorKind::InvalidData);
    assert!(device.change(|s| s.delivered.is_empty())?);
    drop(owner);
    drop(sender);
    drop(a);
    drop(b);
    assert!(probes.iter().all(|p| p.dropped.load(Ordering::SeqCst) == 1));
    Ok(())
}

#[tokio::test]
async fn invalid_local_policy_returns_unpolled_original_inputs() -> R {
    let cert = rcgen::generate_simple_self_signed(vec!["tunnel.test".to_owned()])?;
    let client = ClientTls::from_der_roots(&[cert.cert.der().to_vec()])?;
    let member = MemberKey::from_pkcs8(&MemberKey::generate_pkcs8()?)?;
    let (a, b, probes) = inputs(false);
    let mut config = config(PacketLayer::Ip, false, false, Protection::ChaCha20Poly1305)?;
    config.pipeline.flows.channels = 0;
    let failed = begin_client(a, &client, "tunnel.test", &member, config)
        .err()
        .ok_or("expected config error")?;
    assert_ne!(failed.error.kind(), io::ErrorKind::WouldBlock);
    assert!(probes.iter().all(|p| p.receives.load(Ordering::SeqCst) == 0
        && p.sends.load(Ordering::SeqCst) == 0
        && p.dropped.load(Ordering::SeqCst) == 0));
    drop(failed.inputs);
    drop(b);
    assert!(probes.iter().all(|p| p.dropped.load(Ordering::SeqCst) == 1));
    Ok(())
}
#[tokio::test]
async fn lz4_large_native_frames_include_actual_small_mtu_fragmentation() -> R {
    for half in [false, true] {
        let mut config = config(PacketLayer::Ip, half, false, Protection::ChaCha20Poly1305)?;
        config.runtime.compression = Compression::Lz4IfSmaller;
        config.validate()?;
        let small = packet(PacketLayer::Ip, 1, 4000);
        let mut large = packet(PacketLayer::Ip, 2, 4000);
        let mut state = 0x11335577u32;
        for byte in &mut large[40..] {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            *byte = (state >> 24) as u8;
        }
        let codec = config.runtime.codec()?;
        assert_eq!(codec.encode_vec(&small)?[4], 1);
        assert!(
            codec.encode_vec(&large)?.len() > config.arq.max_source_bytes - FRAGMENT_HEADER_BYTES
        );
        let packets = vec![small, large];
        let (a, b, _) = links(config).await?;
        let status = a.subscribe();
        let ad = Device::new(PacketLayer::Ip);
        let bd = Device::new(PacketLayer::Ip);
        ad.change(|s| s.outgoing = packets.clone().into())?;
        bd.change(|s| s.outgoing = packets.clone().into())?;
        let ar = tokio::spawn(run(ad.clone(), a));
        let br = tokio::spawn(run(bd.clone(), b));
        wait_native(&ad, &bd, 2).await?;
        assert_eq!(ad.change(|s| s.delivered.clone())?, packets);
        assert_eq!(bd.change(|s| s.delivered.clone())?, packets);
        assert!(status.borrow().sources.iter().sum::<u64>() > 2);
        ar.abort();
        br.abort();
        let _ = ar.await;
        let _ = br.await;
    }
    Ok(())
}

#[path = "flow_tests.rs"]
mod flow_retirement;
