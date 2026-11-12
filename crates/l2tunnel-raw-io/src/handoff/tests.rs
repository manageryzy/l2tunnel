use super::*;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicUsize, Ordering};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

type TestResult = Result<(), Box<dyn std::error::Error>>;
#[derive(Default)]
struct Probe {
    blocked: AtomicBool,
    lose: AtomicBool,
    noise: AtomicBool,
    errno: AtomicI32,
    calls: AtomicUsize,
    receives: AtomicUsize,
    drops: AtomicUsize,
    drop_gate: Mutex<Option<Shared>>,
    drop_unlocked: AtomicBool,
    drop_failed: AtomicBool,
    retained: Mutex<Option<Vec<u8>>>,
    sent: Mutex<Vec<Vec<u8>>>,
}
struct MemoryIo {
    identity: Box<u8>,
    incoming: mpsc::Receiver<Vec<u8>>,
    outgoing: mpsc::Sender<Vec<u8>>,
    probe: Arc<Probe>,
}
impl PacketIo for MemoryIo {
    fn receive(&mut self, output: &mut [u8]) -> io::Result<Option<usize>> {
        assert_eq!(output.len(), 65_536);
        self.probe.receives.fetch_add(1, Ordering::SeqCst);
        if self.probe.noise.load(Ordering::SeqCst) {
            output[..12].fill(0);
            return Ok(Some(12));
        }
        match self.incoming.try_recv() {
            Ok(bytes) => {
                output[..bytes.len()].copy_from_slice(&bytes);
                Ok(Some(bytes.len()))
            }
            Err(_) => Ok(None),
        }
    }
    fn send(&mut self, packet: &[u8]) -> io::Result<()> {
        let call = self.probe.calls.fetch_add(1, Ordering::SeqCst) + 1;
        if self.probe.blocked.load(Ordering::SeqCst) {
            let mut retained = self
                .probe
                .retained
                .lock()
                .map_err(|_| io::Error::other("mock lock"))?;
            if let Some(before) = retained.as_ref() {
                assert_eq!(before, packet);
            } else {
                *retained = Some(packet.to_vec());
            }
            return Err(io::ErrorKind::WouldBlock.into());
        }
        let errno = self.probe.errno.load(Ordering::SeqCst);
        if errno != 0 {
            return Err(io::Error::from_raw_os_error(errno));
        }
        if !self.probe.lose.load(Ordering::SeqCst) || !call.is_multiple_of(7) {
            self.outgoing
                .try_send(packet.to_vec())
                .map_err(|_| io::Error::from(io::ErrorKind::WouldBlock))?;
        }
        let mut sent = self
            .probe
            .sent
            .lock()
            .map_err(|_| io::Error::other("mock lock"))?;
        assert!(sent.len() < 4096);
        sent.push(packet.to_vec());
        Ok(())
    }
}
impl Drop for MemoryIo {
    fn drop(&mut self) {
        if let Ok(shared) = self.probe.drop_gate.lock()
            && let Some(shared) = shared.as_ref()
            && let Ok(gate) = shared.try_lock()
        {
            self.probe.drop_unlocked.store(true, Ordering::SeqCst);
            self.probe
                .drop_failed
                .store(gate.status.state == SwitchState::Failed, Ordering::SeqCst);
        }
        self.probe.drops.fetch_add(1, Ordering::SeqCst);
    }
}
fn config(client: bool) -> Config {
    let a = SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 41), 42001);
    let b = SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 42), 42002);
    Config {
        local: if client { a } else { b },
        peer: if client { b } else { a },
        mtu: 576,
        send_bytes: 4096,
        receive_bytes: 4096,
        packet_slots: 8,
        random_seed: if client { 0x1212 } else { 0x2323 },
        ack_delay_millis: 10,
        keepalive_millis: 1000,
        idle_timeout_millis: 30_000,
    }
}
struct End {
    stream: TrackedStream,
    handle: SwitchHandle,
    driver: SwitchDriver<MemoryIo>,
    probe: Arc<Probe>,
    identity: usize,
}
fn pair() -> io::Result<(End, End)> {
    let (at, br) = mpsc::channel(16);
    let (bt, ar) = mpsc::channel(16);
    let make = |client, incoming, outgoing| -> io::Result<End> {
        let probe = Arc::new(Probe::default());
        let identity = Box::new(if client { 1 } else { 2 });
        let address = std::ptr::from_ref(identity.as_ref()) as usize;
        let io = MemoryIo {
            identity,
            incoming,
            outgoing,
            probe: probe.clone(),
        };
        let (stream, handle, driver) = bridge_switchable(
            config(client),
            if client { Role::Client } else { Role::Server },
            io,
            SwitchLimits::default(),
        )?;
        Ok(End {
            stream,
            handle,
            driver,
            probe,
            identity: address,
        })
    };
    Ok((make(true, ar, at)?, make(false, br, bt)?))
}
struct Running {
    stream: TrackedStream,
    handle: SwitchHandle,
    task: JoinHandle<io::Result<SwitchExit<MemoryIo>>>,
    probe: Arc<Probe>,
    identity: usize,
}
impl End {
    fn run(self) -> Running {
        Running {
            stream: self.stream,
            handle: self.handle,
            task: tokio::spawn(self.driver.run()),
            probe: self.probe,
            identity: self.identity,
        }
    }
}
async fn prefixes(a: &mut Running, b: &mut Running) -> TestResult {
    let ab: Vec<u8> = (0..1501).map(|i| (i * 31) as u8).collect();
    let ba: Vec<u8> = (0..1103).map(|i| (i * 17) as u8).collect();
    tokio::time::timeout(Duration::from_secs(5), async {
        a.stream.write_all(&ab).await?;
        let mut got = vec![0; ab.len()];
        b.stream.read_exact(&mut got).await?;
        assert_eq!(got, ab);
        b.stream.write_all(&ba).await?;
        let mut got = vec![0; ba.len()];
        a.stream.read_exact(&mut got).await?;
        assert_eq!(got, ba);
        io::Result::Ok(())
    })
    .await??;
    settle(30).await;
    Ok(())
}
async fn settle(millis: usize) {
    for _ in 0..millis {
        tokio::time::advance(Duration::from_millis(1)).await;
        tokio::task::yield_now().await;
    }
}
fn request(handle: &mut SwitchHandle, remaining: Duration) -> io::Result<Duration> {
    let elapsed = lock(&handle.shared)?
        .started
        .ok_or_else(|| io::Error::other("not started"))?
        .elapsed();
    let deadline = elapsed + remaining;
    handle.request_handoff(deadline)?;
    Ok(deadline)
}
async fn finish(
    task: JoinHandle<io::Result<SwitchExit<MemoryIo>>>,
) -> Result<SwitchExit<MemoryIo>, Box<dyn std::error::Error>> {
    Ok(tokio::time::timeout(Duration::from_secs(40), task).await???)
}
fn handoff(
    exit: SwitchExit<MemoryIo>,
) -> Result<HandoffParts<MemoryIo>, Box<dyn std::error::Error>> {
    match exit {
        SwitchExit::Handoff(parts) => Ok(parts),
        SwitchExit::Clean(_) => Err("unexpected retained close".into()),
    }
}
fn proof(parts: &HandoffParts<MemoryIo>, probe: &Probe, identity: usize) -> TestResult {
    assert_eq!(
        std::ptr::from_ref(parts.inner.io.identity.as_ref()) as usize,
        identity
    );
    let proof = parts.proof();
    assert_eq!(proof.endpoint().written, proof.driver().outbound_read);
    assert_eq!(proof.endpoint().written, proof.engine().send_admitted);
    assert_eq!(proof.endpoint().read, proof.driver().inbound_written);
    assert_eq!(proof.endpoint().read, proof.engine().receive_consumed);
    assert_eq!(
        proof.driver().raw_popped_packets,
        proof.driver().raw_sent_packets
    );
    assert_eq!(
        proof.driver().raw_popped_bytes,
        proof.driver().raw_sent_bytes
    );
    let sent = probe.sent.lock().map_err(|_| "mock lock")?;
    assert_eq!(proof.driver().raw_sent_packets, sent.len() as u64);
    assert_eq!(
        proof.driver().raw_sent_bytes,
        sent.iter().map(|p| p.len() as u64).sum::<u64>()
    );
    assert!(
        sent.iter()
            .all(|p| p[usize::from(p[0] & 15) * 4 + 13] & 5 == 0)
    );
    Ok(())
}
async fn cancel(task: JoinHandle<io::Result<SwitchExit<MemoryIo>>>) {
    task.abort();
    let _ = task.await;
}

#[tokio::test(start_paused = true)]
async fn simultaneous_and_one_sided_freeze_return_original_physical_owners() -> TestResult {
    for simultaneous in [false, true] {
        let (a, b) = pair()?;
        let (mut a, mut b) = (a.run(), b.run());
        prefixes(&mut a, &mut b).await?;
        request(&mut a.handle, Duration::from_secs(2))?;
        if simultaneous {
            request(&mut b.handle, Duration::from_secs(2))?;
        }
        let ap = handoff(finish(a.task).await?)?;
        if !simultaneous {
            request(&mut b.handle, Duration::from_secs(2))?;
        }
        let bp = handoff(finish(b.task).await?)?;
        proof(&ap, &a.probe, a.identity)?;
        proof(&bp, &b.probe, b.identity)?;
        assert_eq!(ap.snapshot().tcp.send_next, bp.snapshot().tcp.receive_next);
        assert_eq!(bp.snapshot().tcp.send_next, ap.snapshot().tcp.receive_next);
        assert_eq!(a.handle.status().state, SwitchState::Handoff);
        assert!(a.stream.read(&mut [0]).await.is_err());
        assert_eq!(a.probe.drops.load(Ordering::SeqCst), 0);
        drop((a.stream, a.handle));
        assert_eq!(a.probe.drops.load(Ordering::SeqCst), 0);
        drop(ap);
        assert_eq!(a.probe.drops.load(Ordering::SeqCst), 1);
    }
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn counted_endpoint_partial_pending_and_exhaustion_are_atomic() -> TestResult {
    let (mut a, _b) = pair()?;
    let unchanged = a.handle.status();
    assert!(a.handle.request_handoff(Duration::from_secs(1)).is_err());
    assert_eq!(a.handle.status(), unchanged);
    assert_eq!(a.stream.write(&vec![7; 800]).await?, config(true).mtu);
    assert_eq!(a.handle.status().endpoint.written, 576);
    assert!(
        tokio::time::timeout(Duration::from_millis(1), a.stream.write(&[8]))
            .await
            .is_err()
    );
    assert_eq!(a.handle.status().endpoint.written, 576);
    let mut bytes = [0; 576];
    a.driver.bridge.read_exact(&mut bytes).await?;
    assert_eq!(bytes, [7; 576]);
    lock(&a.handle.shared)?.status.endpoint.written = u64::MAX - 1;
    assert!(a.stream.write(&[1, 2]).await.is_err());
    assert_eq!(a.stream.write(&[1]).await?, 1);
    assert_eq!(a.handle.status().endpoint.written, u64::MAX);
    a.driver.bridge.write_all(b"xy").await?;
    lock(&a.handle.shared)?.status.endpoint.read = u64::MAX - 1;
    let mut output = [0xa5; 4];
    assert!(a.stream.read(&mut output).await.is_err());
    assert_eq!(output, [0xa5; 4]);
    assert_eq!(a.stream.read(&mut output[..1]).await?, 1);
    assert_eq!(output[0], b'x');
    output.fill(0xa5);
    assert!(a.stream.read(&mut output[..1]).await.is_err());
    assert_eq!(output, [0xa5; 4]);
    assert_eq!(a.handle.status().endpoint.read, u64::MAX);
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn request_rejection_and_all_frozen_poll_methods_preserve_exact_fence() -> TestResult {
    let (a, b) = pair()?;
    let (mut a, mut b) = (a.run(), b.run());
    prefixes(&mut a, &mut b).await?;
    let before = a.handle.status();
    assert!(a.handle.request_handoff(Duration::ZERO).is_err());
    let now = lock(&a.handle.shared)?.started.ok_or("started")?.elapsed();
    assert!(
        a.handle
            .request_handoff(now + Duration::from_secs(31))
            .is_err()
    );
    assert_eq!(a.handle.status(), before);
    request(&mut a.handle, Duration::from_secs(2))?;
    let frozen = a.handle.status();
    assert!(
        a.handle
            .request_handoff(now + Duration::from_secs(3))
            .is_err()
    );
    assert!(a.stream.write(b"late").await.is_err());
    let mut output = [0xa5; 8];
    assert!(a.stream.read(&mut output).await.is_err());
    assert_eq!(output, [0xa5; 8]);
    assert!(a.stream.flush().await.is_err());
    assert!(a.stream.shutdown().await.is_err());
    assert_eq!(a.handle.status().endpoint, frozen.endpoint);
    request(&mut b.handle, Duration::from_secs(2))?;
    let _ = handoff(finish(a.task).await?)?;
    let _ = handoff(finish(b.task).await?)?;
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn queued_original_ciphertext_drains_without_fresh_endpoint_admission() -> TestResult {
    let (a, b) = pair()?;
    let (mut a, mut b) = (a.run(), b.run());
    prefixes(&mut a, &mut b).await?;
    let before = a.handle.status().driver.outbound_read;
    let tail = [0x91; 200];
    a.stream.write_all(&tail).await?;
    assert_eq!(a.handle.status().driver.outbound_read, before);
    request(&mut a.handle, Duration::from_secs(2))?;
    let mut actual = [0; 200];
    b.stream.read_exact(&mut actual).await?;
    assert_eq!(actual, tail);
    request(&mut b.handle, Duration::from_secs(2))?;
    let ap = handoff(finish(a.task).await?)?;
    let bp = handoff(finish(b.task).await?)?;
    assert_eq!(ap.proof().endpoint().written, 1701);
    assert_eq!(bp.proof().endpoint().read, 1701);
    proof(&ap, &a.probe, a.identity)?;
    proof(&bp, &b.probe, b.identity)?;
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn popped_ack_is_identical_across_wouldblock_and_prevents_false_transfer() -> TestResult {
    let (a, b) = pair()?;
    let (mut a, mut b) = (a.run(), b.run());
    prefixes(&mut a, &mut b).await?;
    b.probe.blocked.store(true, Ordering::SeqCst);
    a.stream.write_all(b"tail").await?;
    let mut tail = [0; 4];
    b.stream.read_exact(&mut tail).await?;
    request(&mut a.handle, Duration::from_secs(2))?;
    request(&mut b.handle, Duration::from_secs(2))?;
    settle(50).await;
    assert!(!a.task.is_finished());
    assert!(!b.task.is_finished());
    let held = b.handle.status().driver;
    assert_eq!(held.raw_popped_packets, held.raw_sent_packets + 1);
    let retained = b
        .probe
        .retained
        .lock()
        .map_err(|_| "mock lock")?
        .clone()
        .ok_or("held ACK")?;
    assert_eq!(
        held.raw_popped_bytes,
        held.raw_sent_bytes + retained.len() as u64
    );
    b.probe.blocked.store(false, Ordering::SeqCst);
    let ap = handoff(finish(a.task).await?)?;
    let bp = handoff(finish(b.task).await?)?;
    proof(&ap, &a.probe, a.identity)?;
    proof(&bp, &b.probe, b.identity)?;
    assert!(
        b.probe
            .sent
            .lock()
            .map_err(|_| "mock lock")?
            .iter()
            .any(|p| p == &retained)
    );
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn unread_incoming_ciphertext_cannot_become_a_frozen_tls_read() -> TestResult {
    let (a, b) = pair()?;
    let (mut a, mut b) = (a.run(), b.run());
    prefixes(&mut a, &mut b).await?;
    b.stream.write_all(&[3; 100]).await?;
    settle(30).await;
    let read = a.handle.status().endpoint.read;
    assert!(a.handle.status().driver.inbound_written > read);
    request(&mut a.handle, Duration::from_secs(2))?;
    let error = finish(a.task)
        .await
        .err()
        .ok_or("unread handoff succeeded")?;
    let error = error.downcast_ref::<io::Error>().ok_or("I/O error")?;
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    assert_eq!(a.handle.status().endpoint.read, read);
    assert_eq!(a.handle.status().state, SwitchState::Failed);
    cancel(b.task).await;
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn blocked_ack_uses_original_fixed_deadline_without_fin_or_rst() -> TestResult {
    let (a, b) = pair()?;
    let (mut a, mut b) = (a.run(), b.run());
    prefixes(&mut a, &mut b).await?;
    b.probe.blocked.store(true, Ordering::SeqCst);
    a.stream.write_all(b"tail").await?;
    b.stream.read_exact(&mut [0; 4]).await?;
    let deadline = request(&mut a.handle, Duration::from_millis(300))?;
    request(&mut b.handle, Duration::from_millis(300))?;
    let started = lock(&a.handle.shared)?.started.ok_or("started")?;
    let error = finish(a.task)
        .await
        .err()
        .ok_or("blocked handoff succeeded")?;
    assert_eq!(
        error.downcast_ref::<io::Error>().ok_or("I/O error")?.kind(),
        io::ErrorKind::TimedOut
    );
    assert!(started.elapsed() >= deadline);
    assert!(started.elapsed() <= deadline + Duration::from_millis(2));
    assert_eq!(a.handle.status().deadline, Some(deadline));
    assert!(finish(b.task).await.is_err());
    for probe in [a.probe, b.probe] {
        assert!(
            probe
                .sent
                .lock()
                .map_err(|_| "mock lock")?
                .iter()
                .all(|p| p[33] & 5 == 0)
        );
        assert_eq!(probe.drops.load(Ordering::SeqCst), 1);
    }
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn cancellation_before_commit_never_returns_handoff_or_sends_cleanup_reset() -> TestResult {
    for drop_handle in [false, true] {
        let (a, b) = pair()?;
        let (mut a, mut b) = (a.run(), b.run());
        prefixes(&mut a, &mut b).await?;
        b.probe.blocked.store(true, Ordering::SeqCst);
        a.stream.write_all(b"tail").await?;
        b.stream.read_exact(&mut [0; 4]).await?;
        request(&mut a.handle, Duration::from_secs(2))?;
        if drop_handle {
            drop(a.handle);
        } else {
            drop(a.stream);
        }
        let error = finish(a.task)
            .await
            .err()
            .ok_or("cancelled handoff succeeded")?;
        assert_eq!(
            error.downcast_ref::<io::Error>().ok_or("I/O error")?.kind(),
            io::ErrorKind::ConnectionAborted
        );
        assert_eq!(a.probe.drops.load(Ordering::SeqCst), 1);
        assert!(
            a.probe
                .sent
                .lock()
                .map_err(|_| "mock lock")?
                .iter()
                .all(|p| p[33] & 5 == 0)
        );
        cancel(b.task).await;
    }
    let (a, b) = pair()?;
    let (mut a, mut b) = (a.run(), b.run());
    prefixes(&mut a, &mut b).await?;
    cancel(a.task).await;
    assert_eq!(a.handle.status().state, SwitchState::Failed);
    assert!(a.stream.write(b"after cancel").await.is_err());
    assert_eq!(a.probe.drops.load(Ordering::SeqCst), 1);
    cancel(b.task).await;
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn checked_driver_counters_precede_packet_receive_pop_and_send() -> TestResult {
    let (mut a, _b) = pair()?;
    a.driver.progress.raw_received_bytes = u64::MAX - 10;
    assert!(a.driver.receive_packets().is_err());
    assert_eq!(a.probe.receives.load(Ordering::SeqCst), 0);
    a.driver.engine_mut()?.poll(Millis(0), 1)?;
    let queued = a.driver.engine()?.status().outgoing_packets;
    assert!(queued > 0);
    a.driver.progress.raw_popped_packets = u64::MAX;
    assert!(a.driver.send_packets().is_err());
    assert_eq!(a.driver.engine()?.status().outgoing_packets, queued);
    assert!(a.driver.pending_packet.is_none());
    assert_eq!(a.probe.calls.load(Ordering::SeqCst), 0);
    a.driver.progress.raw_popped_packets = 0;
    a.driver.progress.raw_sent_bytes = u64::MAX;
    assert!(a.driver.send_packets().is_err());
    assert!(a.driver.pending_packet.is_some());
    assert_eq!(a.probe.calls.load(Ordering::SeqCst), 0);
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn original_packet_syscall_error_is_preserved_without_false_send_charge() -> TestResult {
    let (a, _b) = pair()?;
    a.probe.errno.store(1, Ordering::SeqCst);
    let a = a.run();
    let error = finish(a.task).await.err().ok_or("syscall error missing")?;
    let error = error.downcast_ref::<io::Error>().ok_or("I/O error")?;
    assert_eq!(error.raw_os_error(), Some(1));
    assert_eq!(a.probe.sent.lock().map_err(|_| "mock lock")?.len(), 0);
    assert_eq!(a.probe.drops.load(Ordering::SeqCst), 1);
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn ordinary_orderly_close_stays_distinct_from_handoff_under_loss() -> TestResult {
    for loss in [false, true] {
        let (a, b) = pair()?;
        a.probe.lose.store(loss, Ordering::SeqCst);
        b.probe.lose.store(loss, Ordering::SeqCst);
        let (mut a, mut b) = (a.run(), b.run());
        prefixes(&mut a, &mut b).await?;
        a.stream.shutdown().await?;
        assert_eq!(b.stream.read(&mut [0]).await?, 0);
        b.stream.shutdown().await?;
        assert_eq!(a.stream.read(&mut [0]).await?, 0);
        for exit in [finish(a.task).await?, finish(b.task).await?] {
            assert!(matches!(exit, SwitchExit::Clean(_)));
        }
        assert_eq!(a.handle.status().state, SwitchState::Clean);
        assert_eq!(b.handle.status().state, SwitchState::Clean);
    }
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn retained_clean_close_leaves_buffered_endpoint_bytes_readable() -> TestResult {
    let (a, b) = pair()?;
    let (mut a, mut b) = (a.run(), b.run());
    prefixes(&mut a, &mut b).await?;
    b.stream.write_all(b"buffered").await?;
    b.stream.shutdown().await?;
    a.stream.shutdown().await?;
    assert!(matches!(finish(a.task).await?, SwitchExit::Clean(_)));
    assert!(matches!(finish(b.task).await?, SwitchExit::Clean(_)));
    let mut bytes = [0; 8];
    a.stream.read_exact(&mut bytes).await?;
    assert_eq!(&bytes, b"buffered");
    assert_eq!(a.stream.read(&mut [0]).await?, 0);
    assert_eq!(b.stream.read(&mut [0]).await?, 0);
    assert_eq!(a.handle.status().endpoint.read, 1111);
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn invalid_limits_zero_prefix_and_bridge_identity_cannot_create_a_proof() -> TestResult {
    for limits in [
        SwitchLimits {
            work_limit: 0,
            ..SwitchLimits::default()
        },
        SwitchLimits {
            work_limit: 1025,
            ..SwitchLimits::default()
        },
        SwitchLimits {
            max_handoff_duration: Duration::from_millis(999),
            ..SwitchLimits::default()
        },
        SwitchLimits {
            max_handoff_duration: Duration::from_secs(31),
            ..SwitchLimits::default()
        },
    ] {
        assert!(limits.validate().is_err());
    }
    for work_limit in [1, 1024] {
        SwitchLimits {
            work_limit,
            ..SwitchLimits::default()
        }
        .validate()?;
    }
    let (a, b) = pair()?;
    let (mut a, mut b) = (a.run(), b.run());
    settle(10).await;
    assert!(request(&mut a.handle, Duration::from_secs(1)).is_err());
    assert_eq!(a.handle.status().state, SwitchState::Running);
    prefixes(&mut a, &mut b).await?;
    request(&mut a.handle, Duration::from_secs(1))?;
    assert_eq!(b.handle.status().state, SwitchState::Running);
    b.stream.flush().await?;
    // A's unique handle cannot freeze B, import B's counters or authorize B's owner.
    assert_eq!(a.handle.status().state, SwitchState::Frozen);
    let _ = handoff(finish(a.task).await?)?;
    request(&mut b.handle, Duration::from_secs(1))?;
    let _ = handoff(finish(b.task).await?)?;
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn driver_bridge_overflow_precedes_external_read_or_write() -> TestResult {
    let (mut end, mut other) = pair()?;
    for now in 0..10 {
        for driver in [&mut end.driver, &mut other.driver] {
            driver.receive_packets()?;
            driver.engine_mut()?.poll(Millis(now), 8)?;
            driver.send_packets()?;
        }
    }
    assert!(end.driver.engine()?.status().established);
    // A direct owned-buffer test isolates the write preflight from TCP progress.
    end.driver.output.bytes[..2].copy_from_slice(b"xy");
    end.driver.output.length = 2;
    end.driver.progress.inbound_written = u64::MAX - 1;
    let mut tick = tokio::time::interval(Duration::from_millis(1));
    assert!(
        end.driver
            .wait_for_work(Instant::now(), &mut tick)
            .await
            .is_err()
    );
    assert_eq!(end.driver.output.offset, 0);
    let mut bytes = [0xa5; 2];
    assert!(
        tokio::time::timeout(Duration::from_millis(1), end.stream.read(&mut bytes))
            .await
            .is_err()
    );
    assert_eq!(bytes, [0xa5; 2]);
    end.driver.output.offset = end.driver.output.length;
    end.stream.write_all(b"pending").await?;
    end.driver.progress.outbound_read = u64::MAX - 1;
    assert!(
        end.driver
            .wait_for_work(Instant::now(), &mut tick)
            .await
            .is_err()
    );
    assert!(end.driver.input.empty());
    let mut original = [0; 7];
    end.driver.bridge.read_exact(&mut original).await?;
    assert_eq!(&original, b"pending");
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn continuous_malformed_receive_work_cannot_renew_handoff_deadline() -> TestResult {
    let (a, b) = pair()?;
    let (mut a, mut b) = (a.run(), b.run());
    prefixes(&mut a, &mut b).await?;
    a.probe.noise.store(true, Ordering::SeqCst);
    a.stream.write_all(b"tail").await?;
    b.stream.read_exact(&mut [0; 4]).await?;
    let calls = a.probe.receives.load(Ordering::SeqCst);
    let deadline = request(&mut a.handle, Duration::from_millis(100))?;
    let started = lock(&a.handle.shared)?.started.ok_or("started")?;
    let error = finish(a.task)
        .await
        .err()
        .ok_or("noise handoff succeeded")?;
    assert_eq!(
        error.downcast_ref::<io::Error>().ok_or("I/O error")?.kind(),
        io::ErrorKind::TimedOut
    );
    assert!(started.elapsed() >= deadline);
    assert!(started.elapsed() <= deadline + Duration::from_millis(2));
    assert!(a.handle.status().driver.discarded_packets > 0);
    assert!(a.probe.receives.load(Ordering::SeqCst) - calls <= 32 * 150);
    cancel(b.task).await;
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn consumed_bundle_cannot_commit_at_or_after_the_original_deadline() -> TestResult {
    for extra in [Duration::ZERO, Duration::from_nanos(1)] {
        let (a, b) = pair()?;
        let (mut a, mut b) = (a.run(), b.run());
        prefixes(&mut a, &mut b).await?;
        request(&mut a.handle, Duration::from_secs(1))?;
        request(&mut b.handle, Duration::from_secs(1))?;
        let ap = handoff(finish(a.task).await?)?;
        let bp = handoff(finish(b.task).await?)?;
        let sent = a.probe.sent.lock().map_err(|_| "mock lock")?.len();
        // Test the post-consume helper with an actual unique completed bundle.
        // This models synchronous consume/allocation crossing the last check;
        // it does not replace the runtime's live clock with a peer timestamp.
        let shared = Arc::new(Mutex::new(Gate::new(SwitchLimits::default())));
        let mut gate = lock(&shared)?;
        gate.status.state = SwitchState::Frozen;
        let deadline = Duration::from_secs(1);
        let error = complete_handoff(gate, ap, deadline + extra, deadline)
            .err()
            .ok_or("expired consumed bundle committed")?;
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert_eq!(lock(&shared)?.status.state, SwitchState::Failed);
        assert_eq!(a.probe.drops.load(Ordering::SeqCst), 1);
        assert_eq!(a.probe.sent.lock().map_err(|_| "mock lock")?.len(), sent);
        drop(bp);
    }
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn ready_bridge_completion_is_counted_then_rejected_after_expiry() -> TestResult {
    let (mut end, _other) = pair()?;
    end.stream.write_all(b"old").await?;
    let started = Instant::now();
    let deadline = Duration::from_millis(1);
    let endpoint = end.handle.status().endpoint;
    {
        let mut gate = lock(&end.handle.shared)?;
        gate.status.state = SwitchState::Frozen;
    }
    end.driver.request = Some(Request { endpoint, deadline });
    let read_ceiling = reserve(end.driver.progress.outbound_read, 3)?;
    // This actual read completes, but the actor does not get to process its
    // Ready result until after the fixed deadline. The shared completion path
    // must record ownership once and fail before any next I/O turn.
    let size = end
        .driver
        .bridge
        .read(&mut end.driver.input.bytes[..3])
        .await?;
    tokio::time::advance(deadline).await;
    let error = end
        .driver
        .complete_step(
            Step::Read(Ok(size)),
            TransferBounds {
                read_limit: 3,
                read_ceiling,
                write_limit: 0,
                write_ceiling: 0,
            },
            started,
        )
        .err()
        .ok_or("late ready read succeeded")?;
    assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    assert_eq!(end.driver.progress.outbound_read, 3);
    assert_eq!(end.driver.input.remaining(), b"old");
    let calls = end.probe.calls.load(Ordering::SeqCst);
    let mut tick = tokio::time::interval(Duration::from_millis(1));
    assert!(end.driver.wait_for_work(started, &mut tick).await.is_err());
    assert_eq!(end.probe.calls.load(Ordering::SeqCst), calls);
    assert_eq!(end.driver.progress.outbound_read, 3);
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn expired_consumed_io_destructor_observes_unlocked_failed_gate() -> TestResult {
    let (a, b) = pair()?;
    let (mut a, mut b) = (a.run(), b.run());
    prefixes(&mut a, &mut b).await?;
    request(&mut a.handle, Duration::from_secs(1))?;
    request(&mut b.handle, Duration::from_secs(1))?;
    let ap = handoff(finish(a.task).await?)?;
    let bp = handoff(finish(b.task).await?)?;
    let shared = Arc::new(Mutex::new(Gate::new(SwitchLimits::default())));
    let mut gate = lock(&shared)?;
    gate.status.state = SwitchState::Frozen;
    *a.probe.drop_gate.lock().map_err(|_| "mock lock")? = Some(shared.clone());
    let error = complete_handoff(gate, ap, Duration::from_secs(1), Duration::from_secs(1))
        .err()
        .ok_or("expired owner returned")?;
    assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    // try_lock in the generic I/O destructor makes this fail, rather than hang,
    // if rejection destroys the original owner under the shared gate mutex.
    assert!(a.probe.drop_unlocked.load(Ordering::SeqCst));
    assert!(a.probe.drop_failed.load(Ordering::SeqCst));
    assert_eq!(a.probe.drops.load(Ordering::SeqCst), 1);
    drop(bp);
    Ok(())
}
