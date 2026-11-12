//! Actual TLS byte accounting, bounded receiver debt and original-clock callbacks.
use super::*;
use l2tunnel_flow_control::delivery_window;
use std::collections::BTreeMap;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};
type TestResult = Result<(), Box<dyn std::error::Error + Send + Sync>>;
fn policy() -> DeliveryConfig {
    let config = delivery_window::Config {
        target_bandwidth_bps: 100_000_000,
        bootstrap_rtt_micros: 70_000,
        min_rtt_micros: 1_000,
        max_rtt_micros: 2_000_000,
        headroom_percent: 200,
        minimum_bytes: 1600,
        max_inflight_bytes: 128 * 1024,
        max_records: 128,
        max_packet_bytes: 1600,
        metadata_limit_bytes: 1024 * 1024,
        sample_ttl_micros: 4_000_000,
        flush_timeout_micros: 2_000_000,
    };
    DeliveryConfig {
        forward: config,
        reverse: config,
    }
}
fn runtime() -> RuntimeConfig {
    RuntimeConfig {
        layer: PacketLayer::Ip,
        max_packet: 1600,
        compression: Compression::None,
        queue_packets: 2,
        poll_interval: Duration::from_millis(1),
    }
}
#[test]
fn delivery_authentication_is_explicit_directional_and_local_queues_are_independent() -> TestResult
{
    let r = runtime();
    let p = policy();
    let mode = mode_config_with_delivery(r, Duplex::Half, p)?;
    assert_eq!(mode, mode_config(r, Duplex::Half)?);
    assert_eq!(mode.queue_frames, 2);
    let binding = session_config_with_delivery(r, &mode, p)?;
    assert_ne!(binding, session_config(r, &mode)?);
    let mut different = p;
    different.reverse.target_bandwidth_bps /= 2;
    assert_ne!(binding, session_config_with_delivery(r, &mode, different)?);
    let mut bad = p;
    bad.forward.max_packet_bytes = 1599;
    assert!(mode_config_with_delivery(r, Duplex::Full, bad).is_err());
    bad = p;
    bad.forward.metadata_limit_bytes = 1;
    assert!(session_config_with_delivery(r, &mode, bad).is_err());
    Ok(())
}
#[tokio::test(start_paused = true)]
async fn original_queued_flush_and_feedback_times_never_become_observer_rtt_or_renew_expiry()
-> TestResult {
    let origin = Instant::now();
    let mut window = delivery::Window::new(policy(), Role::Client, origin)?;
    assert!(window.admit(64)?);
    tokio::time::advance(Duration::from_millis(20)).await;
    // Receipt was at10ms; actual flush at5ms, but the flush callback was not yet observed.
    window.feedback(1, origin + Duration::from_millis(10))?;
    window.flush(delivery::FlushEvent {
        ordinal: 1,
        at: origin + Duration::from_millis(5),
    })?;
    assert!(window.sender.status(window.now()?)?.sample.is_none());
    assert!(window.admit(80)?);
    tokio::time::advance(Duration::from_millis(60)).await;
    window.flush(delivery::FlushEvent {
        ordinal: 2,
        at: origin + Duration::from_millis(25),
    })?;
    window.feedback(2, origin + Duration::from_millis(35))?;
    let status = window.sender.status(window.now()?)?;
    assert_eq!(
        status.sample.ok_or("missing original sample")?.raw_micros,
        10_000
    );
    assert_eq!(status.admitted.bytes, 144);
    assert_eq!(status.outstanding.bytes, 0);
    assert!(window.admit(40)?);
    tokio::time::advance(Duration::from_secs(2)).await;
    assert!(
        window
            .flush(delivery::FlushEvent {
                ordinal: 3,
                at: origin + Duration::from_millis(81)
            })
            .is_err()
    );
    assert!(window.sender.status(window.now()?)?.failed);
    Ok(())
}
#[test]
fn native_pending_limits_charge_actual_bytes_and_record_count_separately() -> TestResult {
    let mut p = policy();
    p.reverse.max_inflight_bytes = 1600;
    p.reverse.max_records = 2;
    let mut window = delivery::Window::new(p, Role::Client, Instant::now())?;
    window.receive(64, 0)?;
    window.receive(80, 1)?;
    assert_eq!(window.pending_bytes, 144);
    assert!(window.receive(40, 2).is_err());
    assert_eq!(window.pending_bytes, 144);
    window.pending_bytes = 1590;
    assert!(window.receive(40, 0).is_err());
    assert_eq!(window.pending_bytes, 1590);
    Ok(())
}
#[derive(Clone, Default)]
struct Device {
    ethernet: bool,
    outgoing: Arc<Mutex<VecDeque<Vec<u8>>>>,
    received: Arc<Mutex<Vec<Vec<u8>>>>,
    blocked: Arc<AtomicBool>,
}
impl PacketDevice for Device {
    type Error = io::Error;
    fn layer(&self) -> PacketLayer {
        if self.ethernet {
            PacketLayer::Ethernet
        } else {
            PacketLayer::Ip
        }
    }
    fn receive(&mut self, buffer: &mut [u8]) -> io::Result<Option<usize>> {
        let packet = self
            .outgoing
            .lock()
            .map_err(|_| invalid("test lock"))?
            .pop_front();
        if let Some(packet) = packet {
            buffer[..packet.len()].copy_from_slice(&packet);
            Ok(Some(packet.len()))
        } else {
            Ok(None)
        }
    }
    fn transmit(&mut self, packet: &[u8]) -> io::Result<()> {
        if self.blocked.load(Ordering::Relaxed) {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        self.received
            .lock()
            .map_err(|_| invalid("test lock"))?
            .push(packet.to_vec());
        Ok(())
    }
}
fn packet(seed: u8, layer: PacketLayer) -> Vec<u8> {
    let length = if seed.is_multiple_of(3) {
        60
    } else {
        40 + usize::from(seed) % 100
    };
    let mut packet = vec![seed; length];
    packet[..40].fill(0);
    packet[0] = 0x60;
    packet[4..6].copy_from_slice(&((length - 40) as u16).to_be_bytes());
    packet[6] = 253;
    packet[7] = 64;
    if seed.is_multiple_of(3) {
        packet[6] = 6;
        packet[52] = 0x50;
        packet[53] = 0x10;
    }
    if layer == PacketLayer::Ethernet {
        let mut frame = vec![0; 14];
        frame[..12].fill(1);
        frame[12..14].copy_from_slice(&0x86ddu16.to_be_bytes());
        frame.extend_from_slice(&packet);
        frame
    } else {
        packet
    }
}
async fn actual_case(duplex: Duplex, layer: PacketLayer) -> TestResult {
    use l2tunnel_auth::{
        ClientTls, MemberAllowlist, MemberKey, ServerTls, client_connect, server_accept,
    };
    use tokio::net::{TcpListener, TcpStream};
    let r = RuntimeConfig { layer, ..runtime() };
    let p = policy();
    let mode = mode_config_with_delivery(r, duplex, p)?;
    let binding = session_config_with_delivery(r, &mode, p)?;
    let cert = rcgen::generate_simple_self_signed(vec!["delivery.test".into()])?;
    let chain = [cert.cert.der().to_vec()];
    let client = ClientTls::from_der_roots(&chain)?;
    let server = ServerTls::from_der(&chain, &cert.signing_key.serialize_der())?;
    let member = MemberKey::from_pkcs8(&MemberKey::generate_pkcs8()?)?;
    let allow = MemberAllowlist::new(&[member.public_key()])?;
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let mut lanes = Vec::new();
    for _ in 0..if duplex == Duplex::Full { 1 } else { 2 } {
        let a = TcpStream::connect(listener.local_addr()?).await?;
        a.set_nodelay(true)?;
        let (b, _) = listener.accept().await?;
        b.set_nodelay(true)?;
        lanes.push(tokio::try_join!(
            client_connect(
                a,
                &client,
                "delivery.test",
                &member,
                binding,
                Duration::from_secs(3)
            ),
            server_accept(b, &server, &allow, binding, Duration::from_secs(3))
        )?);
    }
    let (a, b) = lanes.remove(0);
    let (a, b) = if duplex == Duplex::Full {
        (Link::full(a), Link::full(b))
    } else {
        let (a2, b2) = lanes.remove(0);
        tokio::try_join!(client_pair(a, a2), server_pair(b, b2))?
    };
    let da = Device {
        ethernet: layer == PacketLayer::Ethernet,
        ..Device::default()
    };
    let db = Device {
        ethernet: layer == PacketLayer::Ethernet,
        ..Device::default()
    };
    db.blocked.store(true, Ordering::Relaxed);
    let forward: Vec<_> = (1..=150).map(|seed| packet(seed, layer)).collect();
    let reverse: Vec<_> = (151..=230).map(|seed| packet(seed, layer)).collect();
    da.outgoing
        .lock()
        .map_err(|_| invalid("lock"))?
        .extend(forward.clone());
    db.outgoing
        .lock()
        .map_err(|_| invalid("lock"))?
        .extend(reverse.clone());
    let (ca, ra) = channel();
    let (_cb, rb) = channel();
    let (ha, pa) = profiling_channel(Duration::from_millis(100))?;
    let (hb, pb) = profiling_channel(Duration::from_millis(100))?;
    let config = |role| ManagedConfig {
        role,
        initial_mode: mode.clone(),
        transaction_settings: TransactionSettings::default(),
    };
    let a = tokio::spawn(run_managed_with_delivery(
        da.clone(),
        a,
        r,
        config(Role::Client),
        ra,
        p,
        Some(pa),
    ));
    let b = tokio::spawn(run_managed_with_delivery(
        db.clone(),
        b,
        r,
        config(Role::Server),
        rb,
        p,
        Some(pb),
    ));
    let result = async {
        tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                if ca
                    .status()
                    .is_some_and(|s| s.admitted == p.forward.max_records as u64)
                {
                    return;
                }
                tokio::task::yield_now().await;
            }
        })
        .await?;
        let blocked = ca.status().ok_or("missing status")?;
        assert!(blocked.admitted > r.queue_packets as u64);
        assert!(blocked.admitted <= p.forward.max_records as u64);
        assert!(db.received.lock().map_err(|_| invalid("lock"))?.is_empty());
        db.blocked.store(false, Ordering::Relaxed);
        tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                if da.received.lock().map_err(|_| invalid("lock"))?.len() == reverse.len()
                    && db.received.lock().map_err(|_| invalid("lock"))?.len() == forward.len()
                {
                    return Ok::<_, io::Error>(());
                }
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
        .await??;
        let outcome = tokio::time::timeout(
            Duration::from_secs(3),
            ca.switch_compression(Compression::Lz4IfSmaller),
        )
        .await??;
        assert_eq!(outcome.compression, Compression::Lz4IfSmaller);
        assert_eq!(
            ca.status()
                .ok_or("missing post-fence status")?
                .peer_delivered,
            forward.len() as u64
        );
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
    }
    .await;
    a.abort();
    b.abort();
    let _ = a.await;
    let _ = b.await;
    result?;
    assert_eq!(*da.received.lock().map_err(|_| invalid("lock"))?, reverse);
    assert_eq!(*db.received.lock().map_err(|_| invalid("lock"))?, forward);
    let a = ha.status().ok_or("missing profile")?;
    let b = hb.status().ok_or("missing profile")?;
    assert_eq!(
        a.counters["codec_encode_bytes"],
        forward.iter().map(|p| p.len() as u64).sum::<u64>()
    );
    assert_eq!(
        b.counters["codec_encode_bytes"],
        reverse.iter().map(|p| p.len() as u64).sum::<u64>()
    );
    assert_eq!(a.values["delivery_enabled"], 1);
    assert_eq!(a.high_water["configured_local_queue_packets"], 2);
    assert_eq!(a.high_water["configured_delivery_credit_packets"], 128);
    assert!(a.high_water["outgoing_queue_records"] <= 2);
    Ok(())
}
#[tokio::test]
async fn actual_tls_full_half_separate_local_queue_and_byte_debt_preserve_both_exact_streams()
-> TestResult {
    for duplex in [Duplex::Full, Duplex::Half] {
        for layer in [PacketLayer::Ip, PacketLayer::Ethernet] {
            actual_case(duplex, layer).await?;
        }
    }
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn withheld_service_grows_then_shrinks_target_using_actual_ack_bytes_and_original_receipt()
-> TestResult {
    let origin = Instant::now();
    let mut p = policy();
    p.forward.bootstrap_rtt_micros = 10_000;
    p.forward.max_inflight_bytes = 4 * 1024 * 1024;
    let mut window = delivery::Window::new(p, Role::Client, origin)?;
    let initial = window.sender.status(window.now()?)?.target_bytes;
    // The small native ACK charges40 actualbytes and one metadata slot, exactly as data.
    assert!(window.admit(40)?);
    assert!(window.admit(1500)?);
    assert_eq!(window.sender.status(window.now()?)?.outstanding.bytes, 1540);
    tokio::time::advance(Duration::from_millis(90)).await;
    window.flush(delivery::FlushEvent {
        ordinal: 1,
        at: origin + Duration::from_millis(1),
    })?;
    window.flush(delivery::FlushEvent {
        ordinal: 2,
        at: origin + Duration::from_millis(2),
    })?;
    window.feedback(2, origin + Duration::from_millis(72))?;
    let grown = window.sender.status(window.now()?)?;
    assert_eq!(grown.sample.ok_or("sample")?.raw_micros, 70_000);
    assert!(grown.target_bytes > initial);
    assert!(window.admit(60)?);
    tokio::time::advance(Duration::from_millis(10)).await;
    window.flush(delivery::FlushEvent {
        ordinal: 3,
        at: origin + Duration::from_millis(91),
    })?;
    window.feedback(3, origin + Duration::from_millis(92))?;
    let shrunk = window.sender.status(window.now()?)?;
    assert!(shrunk.target_bytes < grown.target_bytes);
    assert_eq!(shrunk.admitted.bytes, 1600);
    tokio::time::advance(Duration::from_secs(4)).await;
    let stale = window.sender.status(window.now()?)?;
    assert!(!stale.sample_fresh);
    assert_eq!(stale.target_bytes, initial);
    Ok(())
}
struct DelayedFlush {
    delay: Option<std::pin::Pin<Box<tokio::time::Sleep>>>,
}
impl AsyncWrite for DelayedFlush {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
        bytes: &[u8],
    ) -> std::task::Poll<io::Result<usize>> {
        std::task::Poll::Ready(Ok(bytes.len()))
    }
    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        context: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        use std::future::Future;
        let delay = self
            .delay
            .get_or_insert_with(|| Box::pin(tokio::time::sleep(Duration::from_millis(10))));
        if delay.as_mut().poll(context).is_pending() {
            return std::task::Poll::Pending;
        }
        self.delay = None;
        std::task::Poll::Ready(Ok(()))
    }
    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }
}
#[tokio::test(start_paused = true)]
async fn held_original_flush_events_do_not_collapse_to_latest_watch_timestamp() -> TestResult {
    let (tx, rx) = mpsc::channel(3);
    let (_ct, cr) = mpsc::channel(1);
    let (_feedback, fr) = watch::channel(0);
    let (control, _) = watch::channel(0);
    let (credit, _) = watch::channel(0);
    let (data, observed) = watch::channel(0);
    let (events, mut originals) = mpsc::channel(3);
    for ordinal in 1..=3 {
        tx.send(OutData {
            epoch: Epoch(1),
            payload: vec![0; 16],
            admitted: ordinal,
        })
        .await?;
    }
    let task = tokio::spawn(write_records(
        DelayedFlush { delay: None },
        [4; 16],
        rx,
        cr,
        fr,
        WriterProgress {
            control,
            credit,
            data,
            delivery: Some(events),
        },
        None,
    ));
    tokio::task::yield_now().await;
    for _ in 0..3 {
        tokio::time::advance(Duration::from_millis(10)).await;
        tokio::task::yield_now().await;
    }
    assert_eq!(*observed.borrow(), 3);
    let first = originals.try_recv()?;
    let second = originals.try_recv()?;
    let third = originals.try_recv()?;
    assert_eq!([first.ordinal, second.ordinal, third.ordinal], [1, 2, 3]);
    assert_eq!(
        second.at.duration_since(first.at),
        Duration::from_millis(10)
    );
    assert_eq!(
        third.at.duration_since(second.at),
        Duration::from_millis(10)
    );
    task.abort();
    let _ = task.await;
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn profile_splits_reservations_from_tls_full_flush_and_early_delivery_callbacks() -> TestResult
{
    fn read(
        window: &mut delivery::Window,
        sink: &ProfileSink,
        handle: &ProfileHandle,
    ) -> io::Result<BTreeMap<&'static str, u64>> {
        window.publish(Some(sink))?;
        sink.publish(true);
        Ok(handle
            .status()
            .ok_or_else(|| invalid("missing gauge observation"))?
            .values)
    }
    fn assert_split(values: &BTreeMap<&'static str, u64>, expected: [u64; 8]) {
        let names = [
            "delivery_reserved_bytes",
            "delivery_reserved_records",
            "delivery_unflushed_bytes",
            "delivery_unflushed_records",
            "delivery_flushed_unacknowledged_bytes",
            "delivery_flushed_unacknowledged_records",
            "delivery_delivered_awaiting_flush_callback_bytes",
            "delivery_delivered_awaiting_flush_callback_records",
        ];
        for (name, expected) in names.into_iter().zip(expected) {
            assert_eq!(values[name], expected, "{name}");
        }
        assert_eq!(
            values["delivery_reserved_bytes"],
            values["delivery_outstanding_bytes"]
        );
        assert_eq!(
            values["delivery_reserved_records"],
            values["delivery_outstanding_records"]
        );
    }
    let origin = Instant::now();
    let (handle, sink) = profiling_channel(Duration::from_millis(100))?;
    sink.publish(true);
    let disabled = handle.status().ok_or("missing legacy defaults")?.values;
    assert_eq!(disabled["delivery_enabled"], 0);
    assert_split(&disabled, [0; 8]);
    let mut window = delivery::Window::new(policy(), Role::Client, origin)?;
    assert!(window.admit(1500)?);
    assert!(window.admit(40)?);
    assert_split(
        &read(&mut window, &sink, &handle)?,
        [1540, 2, 1540, 2, 0, 0, 0, 0],
    );
    tokio::time::advance(Duration::from_millis(1)).await;
    window.flush(delivery::FlushEvent {
        ordinal: 1,
        at: Instant::now(),
    })?;
    assert_split(
        &read(&mut window, &sink, &handle)?,
        [1540, 2, 40, 1, 1500, 1, 0, 0],
    );
    tokio::time::advance(Duration::from_millis(1)).await;
    window.feedback(2, Instant::now())?;
    assert_split(
        &read(&mut window, &sink, &handle)?,
        [0, 0, 40, 1, 0, 0, 40, 1],
    );
    tokio::time::advance(Duration::from_millis(1)).await;
    window.flush(delivery::FlushEvent {
        ordinal: 2,
        at: origin + Duration::from_micros(1500),
    })?;
    let final_values = read(&mut window, &sink, &handle)?;
    assert_eq!(final_values["delivery_enabled"], 1);
    assert_split(&final_values, [0; 8]);
    window.feedback(2, origin + Duration::from_millis(2))?;
    assert_eq!(read(&mut window, &sink, &handle)?, final_values);
    Ok(())
}
