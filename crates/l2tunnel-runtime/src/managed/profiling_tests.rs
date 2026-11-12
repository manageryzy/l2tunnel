//! Enabled/disabled protocol identity and actual authenticated backpressure cases.
use super::*;
use std::{
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll},
};
use tokio::io::AsyncWrite;

type TestResult = Result<(), Box<dyn std::error::Error + Send + Sync>>;
#[tokio::test(start_paused = true)]
async fn bounded_coalesced_snapshots_validate_cadence_and_never_accumulate() -> TestResult {
    for interval in [
        Duration::ZERO,
        Duration::from_millis(99),
        Duration::from_secs(61),
        Duration::from_micros(100001),
    ] {
        assert!(profiling_channel(interval).is_err());
    }
    let (handle, sink) = profiling_channel(Duration::from_millis(100))?;
    for _ in 0..1000 {
        sink.count(PC::DriverIterations, 1);
        sink.publish(false);
    }
    assert!(handle.status().is_none());
    tokio::time::advance(Duration::from_millis(100)).await;
    sink.publish(false);
    let old = handle.status().ok_or("missing profile")?;
    assert_eq!(old.counters["driver_iterations"], 1000);
    sink.count(PC::DriverIterations, 1);
    sink.publish(false);
    assert_eq!(handle.status(), Some(old));
    sink.publish(true);
    let snapshot = handle.status().ok_or("missing terminal")?;
    assert!(snapshot.terminal);
    assert_eq!(snapshot.counters["driver_iterations"], 1001);
    assert!(snapshot.elapsed_nanos >= 100_000_000);
    Ok(())
}
#[derive(Default)]
struct MemoryWriter {
    bytes: Vec<u8>,
    fail_flush: bool,
}
impl AsyncWrite for MemoryWriter {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.bytes.extend_from_slice(bytes);
        Poll::Ready(Ok(bytes.len()))
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(if self.fail_flush {
            Err(io::ErrorKind::BrokenPipe.into())
        } else {
            Ok(())
        })
    }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}
#[tokio::test]
async fn observation_cannot_change_record_bytes_or_report_failed_flush_as_completed() -> TestResult
{
    let mut plain = MemoryWriter::default();
    let mut measured = MemoryWriter::default();
    let (handle, sink) = profiling_channel(Duration::from_millis(100))?;
    let mut a = 0;
    let mut b = 0;
    for kind in [Kind::Data, Kind::Feedback, Kind::Control] {
        write_record(&mut plain, [3; 16], &mut a, kind, Epoch(1), &[9; 32], None).await?;
        write_record(
            &mut measured,
            [3; 16],
            &mut b,
            kind,
            Epoch(1),
            &[9; 32],
            Some(&sink),
        )
        .await?;
    }
    assert_eq!(plain.bytes, measured.bytes);
    assert_eq!(a, b);
    sink.publish(true);
    let snapshot = handle.status().ok_or("missing profile")?;
    assert_eq!(snapshot.counters["records_flushed"], 3);
    assert_eq!(
        snapshot.counters["plaintext_record_bytes_flushed"],
        measured.bytes.len() as u64
    );
    let (failed_handle, failed_sink) = profiling_channel(Duration::from_millis(100))?;
    let mut failed = MemoryWriter {
        fail_flush: true,
        ..MemoryWriter::default()
    };
    assert_eq!(
        write_record(
            &mut failed,
            [3; 16],
            &mut b,
            Kind::Data,
            Epoch(1),
            &[9; 32],
            Some(&failed_sink)
        )
        .await
        .err()
        .map(|e| e.kind()),
        Some(io::ErrorKind::BrokenPipe)
    );
    failed_sink.publish(true);
    let snapshot = failed_handle
        .status()
        .ok_or("missing failed flush observation")?;
    assert_eq!(snapshot.counters["records_flushed"], 0);
    assert_eq!(snapshot.timings["transport_flush"].count, 1);
    Ok(())
}
#[derive(Clone, Default)]
struct Device {
    outgoing: Arc<Mutex<VecDeque<Vec<u8>>>>,
    received: Arc<Mutex<Vec<Vec<u8>>>>,
    blocked: Arc<AtomicBool>,
}
impl PacketDevice for Device {
    type Error = io::Error;
    fn layer(&self) -> l2tunnel_device::PacketLayer {
        l2tunnel_device::PacketLayer::Ip
    }
    fn receive(&mut self, buffer: &mut [u8]) -> io::Result<Option<usize>> {
        let packet = self
            .outgoing
            .lock()
            .map_err(|_| invalid("profile device lock"))?
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
            .map_err(|_| invalid("profile device lock"))?
            .push(packet.to_vec());
        Ok(())
    }
}
fn packet(seed: u8) -> Vec<u8> {
    let mut packet = vec![seed; 64];
    packet[..40].fill(0);
    packet[0] = 0x60;
    packet[4..6].copy_from_slice(&24u16.to_be_bytes());
    packet[6] = 253;
    packet[7] = 64;
    packet
}
async fn actual_case(duplex: Duplex, enabled: bool) -> TestResult {
    use l2tunnel_auth::{
        ClientTls, MemberAllowlist, MemberKey, ServerTls, client_connect, server_accept,
    };
    use tokio::net::{TcpListener, TcpStream};
    let runtime = RuntimeConfig {
        layer: l2tunnel_device::PacketLayer::Ip,
        max_packet: 1600,
        compression: Compression::None,
        queue_packets: 2,
        poll_interval: Duration::from_millis(1),
    };
    let cert = rcgen::generate_simple_self_signed(vec!["profile.test".into()])?;
    let chain = [cert.cert.der().to_vec()];
    let client = ClientTls::from_der_roots(&chain)?;
    let server = ServerTls::from_der(&chain, &cert.signing_key.serialize_der())?;
    let member = MemberKey::from_pkcs8(&MemberKey::generate_pkcs8()?)?;
    let allow = MemberAllowlist::new(&[member.public_key()])?;
    let mode = mode_config(runtime, duplex)?;
    let binding = session_config(runtime, &mode)?;
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
                "profile.test",
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
    let da = Device::default();
    let db = Device::default();
    db.blocked.store(true, Ordering::Relaxed);
    let first: Vec<_> = (1..=5).map(packet).collect();
    let second: Vec<_> = (11..=13).map(packet).collect();
    da.outgoing
        .lock()
        .map_err(|_| invalid("lock"))?
        .extend(first.clone());
    db.outgoing
        .lock()
        .map_err(|_| invalid("lock"))?
        .extend(second.clone());
    let (_ca, ra) = channel();
    let (_cb, rb) = channel();
    let (ha, pa) = profiling_channel(Duration::from_millis(100))?;
    let (hb, pb) = profiling_channel(Duration::from_millis(100))?;
    let ma = ManagedConfig {
        role: Role::Client,
        initial_mode: mode.clone(),
        transaction_settings: TransactionSettings::default(),
    };
    let mb = ManagedConfig {
        role: Role::Server,
        initial_mode: mode,
        transaction_settings: TransactionSettings::default(),
    };
    let a = tokio::spawn(run_managed_with_profile(
        da.clone(),
        a,
        runtime,
        ma,
        ra,
        enabled.then_some(pa),
    ));
    let b = tokio::spawn(run_managed_with_profile(
        db.clone(),
        b,
        runtime,
        mb,
        rb,
        enabled.then_some(pb),
    ));
    tokio::time::sleep(Duration::from_millis(30)).await;
    assert!(db.received.lock().map_err(|_| invalid("lock"))?.is_empty());
    db.blocked.store(false, Ordering::Relaxed);
    let result = tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            if da.received.lock().map_err(|_| invalid("lock"))?.len() == 3
                && db.received.lock().map_err(|_| invalid("lock"))?.len() == 5
            {
                return Ok::<_, io::Error>(());
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await;
    a.abort();
    b.abort();
    let _ = a.await;
    let _ = b.await;
    result??;
    assert_eq!(*da.received.lock().map_err(|_| invalid("lock"))?, second);
    assert_eq!(*db.received.lock().map_err(|_| invalid("lock"))?, first);
    if enabled {
        let a = ha.status().ok_or("missing a profile")?;
        let b = hb.status().ok_or("missing b profile")?;
        assert!(a.terminal && b.terminal);
        assert_eq!(a.counters["codec_encode_frames"], 5);
        assert_eq!(a.counters["codec_decode_frames"], 3);
        assert_eq!(b.counters["codec_encode_frames"], 3);
        assert_eq!(b.counters["codec_decode_frames"], 5);
        assert!(a.counters["data_admission_credit_blocked"] > 0);
        assert!(a.timings["credit_blocked_elapsed"].total_nanos > 0);
        assert!(b.counters["device_write_would_block"] > 0);
        assert_eq!(a.high_water["unconfirmed_native_packets"], 2);
        assert_eq!(a.high_water["configured_local_queue_packets"], 2);
        assert_eq!(a.high_water["configured_delivery_credit_packets"], 2);
    } else {
        assert!(ha.status().is_none() && hb.status().is_none());
    }
    Ok(())
}
#[tokio::test]
async fn enabled_disabled_actual_tls_full_half_preserve_exact_payload_and_backpressure()
-> TestResult {
    for duplex in [Duplex::Full, Duplex::Half] {
        for enabled in [false, true] {
            actual_case(duplex, enabled).await?;
        }
    }
    Ok(())
}
