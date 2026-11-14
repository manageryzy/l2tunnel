//! Writable-output scheduling on actual roots, original UDP sockets and devices.

use super::*;
use std::task::{Context, Poll, Waker};

/// A nonwaiting operation must finish on its first poll, even without readiness.
fn immediate<F: Future>(future: F) -> Result<F::Output> {
    let mut future = Box::pin(future);
    let mut context = Context::from_waker(Waker::noop());
    match future.as_mut().poll(&mut context) {
        Poll::Ready(result) => Ok(result),
        Poll::Pending => Err("native predrain waited for readiness".into()),
    }
}

async fn writable(device: &mut AsyncFd<EventDevice>) -> Result {
    let ready = tokio::time::timeout(Duration::from_secs(1), device.ready_mut(Interest::WRITABLE))
        .await??;
    assert!(ready.ready().is_writable());
    Ok(())
}

type EventRegistration = (AsyncFd<EventDevice>, UnixDatagram, Arc<AtomicUsize>);
fn event_device() -> Result<EventRegistration> {
    let (socket, peer) = UnixDatagram::pair()?;
    socket.set_nonblocking(true)?;
    peer.set_nonblocking(true)?;
    let writes = Arc::new(AtomicUsize::new(0));
    let device = AsyncFd::with_interest(
        EventDevice {
            inner: Device {
                socket,
                blocked: false,
                wouldblock: None,
            },
            time: Arc::new(AtomicU64::new(0)),
            writes: writes.clone(),
            reads: Arc::new(AtomicUsize::new(0)),
            written_at: None,
            read_at: None,
        },
        Interest::READABLE.add(Interest::WRITABLE),
    )?;
    Ok((device, peer, writes))
}

struct DrainFixture {
    socket: tokio::net::UdpSocket,
    remote_socket: tokio::net::UdpSocket,
    driver: Driver,
    remote: Driver,
    now: u64,
}
impl DrainFixture {
    async fn new(kind: cover::Appearance, pending: usize, batch: usize) -> Result<Self> {
        let mut config = config(kind);
        config.send.records.channels = 1;
        config.send.records.codec.repair_numerator = 0;
        config.receive.records = config.send.records;
        config.native.pending_packets = pending;
        config.native.pending_bytes = pending * config.send.records.max_native;
        config.work.native_write_batch = batch;
        config.lifetime.lease = Duration::from_secs(60);
        config.lifetime.ping_interval = Duration::from_secs(10);
        config.report_interval = None;
        let (a, b) = parts_pair(kind).await?;
        let end = a.deadline.max(b.deadline);
        let origin = Instant::now();
        let (socket, mut driver) = Driver::new(a, security::ConfigDigest([3; 32]), config, origin)?;
        let (remote_socket, mut remote) =
            Driver::new(b, security::ConfigDigest([3; 32]), config, origin)?;
        for owner in [&mut driver, &mut remote] {
            owner.bucket.tokens = 0;
            assert!(owner.tail(end)?.is_none());
            assert!(owner.bootstrap.deadline().is_none());
            assert!(owner.joining.deadline().is_none());
        }
        for socket in [&socket, &remote_socket] {
            let mut packet = [0; 1501];
            let mut empty = false;
            for _ in 0..128 {
                match socket.try_recv(&mut packet) {
                    Ok(_) => {}
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        empty = true;
                        break;
                    }
                    Err(error) => return Err(error.into()),
                }
            }
            assert!(
                empty,
                "bounded setup drain did not empty original UDP socket"
            );
        }
        let now = clock(origin, end)? + 20_000;
        driver.bucket.refill(now)?;
        remote.bucket.refill(now)?;
        Ok(Self {
            socket,
            remote_socket,
            driver,
            remote,
            now,
        })
    }
    fn receive_source(&mut self, number: u8) -> Result {
        let wire = source(&mut self.remote, self.now, number)?;
        self.driver.receive(
            &wire,
            self.now,
            self.driver.origin + duration(self.now),
            &resolve(self.driver.config),
        )?;
        self.now += 1;
        Ok(())
    }
}

#[tokio::test]
async fn writable_full_fifo_is_flushed_before_queued_udp_source_admission() -> Result {
    for kind in [cover::Appearance::QuicLike, cover::Appearance::MediaLike] {
        let mut fixture = DrainFixture::new(kind, 1, 1).await?;
        fixture.receive_source(1)?;
        fixture.driver.collect_native(fixture.now)?;
        assert!(!fixture.driver.native_room());
        assert_eq!(fixture.driver.native.len(), 1);
        let second = source(&mut fixture.remote, fixture.now, 2)?;
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), fixture.remote_socket.send(&second))
                .await??,
            second.len()
        );
        tokio::time::timeout(Duration::from_secs(1), fixture.socket.readable()).await??;
        let (mut device, peer, writes) = event_device()?;
        writable(&mut device).await?;
        let now = fixture.now;
        assert_eq!(
            immediate(fixture.driver.flush_native_ready(&mut device, || Ok(now)))??,
            1
        );
        assert_eq!(writes.load(Ordering::SeqCst), 1);
        assert!(fixture.driver.native.is_empty());
        assert!(fixture.driver.native_room());
        let mut wire = [0; 1501];
        let length = fixture.socket.try_recv(&mut wire)?;
        assert_eq!(&wire[..length], second);
        fixture.driver.receive(
            &wire[..length],
            now + 1,
            fixture.driver.origin + duration(now + 1),
            &resolve(fixture.driver.config),
        )?;
        fixture.driver.collect_native(now + 1)?;
        assert_eq!(fixture.driver.native.len(), 1);
        assert_eq!(fixture.driver.counters.native_backpressure_drops, 0);
        assert_eq!(
            immediate(
                fixture
                    .driver
                    .flush_native_ready(&mut device, || Ok(now + 2))
            )??,
            1
        );
        let mut native = [0; 512];
        for number in [1, 2] {
            let length = peer.recv(&mut native)?;
            assert_eq!(&native[..length], ethernet(number));
        }
        assert_eq!(
            peer.recv(&mut native).err().map(|error| error.kind()),
            Some(io::ErrorKind::WouldBlock)
        );
        assert_eq!(fixture.driver.counters.native_written, 2);
        assert_eq!(
            fixture
                .driver
                .performance
                .counters
                .native_write_batch_packets,
            2
        );
        assert_eq!(
            fixture.driver.performance.counters.native_write_would_block,
            0
        );
    }
    Ok(())
}

#[test]
fn real_runtime_bursts_drain_fifo_one_without_artificial_native_pressure() -> Result {
    for kind in [cover::Appearance::QuicLike, cover::Appearance::MediaLike] {
        for count in [16_u8, 64] {
            let mut config = config(kind);
            config.send.records.codec.repair_numerator = 0;
            config.receive.records.codec = config.send.records.codec;
            config.native.pending_packets = 1;
            config.native.pending_bytes = 512;
            config.work.native_write_batch = 1;
            config.wire.burst_bytes = 65536;
            let pair = Pair::start(kind, config, config)?;
            for socket in [&pair.client, &pair.server] {
                socket.set_read_timeout(Some(Duration::from_secs(1)))?;
                socket.set_write_timeout(Some(Duration::from_secs(1)))?;
            }
            for number in 0..count {
                assert_eq!(pair.client.send(&ethernet(number))?, 256);
                assert_eq!(pair.server.send(&ethernet(number.wrapping_add(128)))?, 256);
            }
            let mut native = [0; 512];
            for number in 0..count {
                let length = pair.server.recv(&mut native)?;
                assert_eq!(&native[..length], ethernet(number));
                let length = pair.client.recv(&mut native)?;
                assert_eq!(&native[..length], ethernet(number.wrapping_add(128)));
            }
            let stopped = pair.stop()?;
            assert_eq!(stopped.len(), 2);
            for done in stopped {
                assert_eq!(done.reason, StopReason::Cancelled);
                assert_eq!(done.snapshot.counters.native_written, u64::from(count));
                assert_eq!(done.snapshot.counters.native_backpressure_drops, 0);
                assert_eq!(done.snapshot.performance.native_write_would_block, 0);
                assert_eq!(done.snapshot.performance.native_pending_packets_high, 1);
                assert_eq!(
                    done.snapshot.performance.native_write_batch_packets,
                    u64::from(count)
                );
                assert!(
                    done.snapshot.performance.native_write_batch_packets
                        <= done.snapshot.performance.loop_turns
                );
            }
        }
    }
    Ok(())
}

#[tokio::test]
async fn pending_and_wouldblock_predrain_retain_output_and_allow_input_and_control() -> Result {
    for kind in [cover::Appearance::QuicLike, cover::Appearance::MediaLike] {
        let mut fixture = DrainFixture::new(kind, 1, 1).await?;
        fixture.receive_source(1)?;
        fixture.driver.collect_native(fixture.now)?;
        let (mut device, peer, writes) = event_device()?;
        writable(&mut device).await?;
        device.get_mut().inner.blocked = true;
        let now = fixture.now;
        let spent = immediate(fixture.driver.flush_native_ready(&mut device, || Ok(now)))??;
        assert_eq!(spent, 1);
        assert_eq!(
            fixture
                .driver
                .config
                .work
                .native_write_batch
                .saturating_sub(spent),
            0
        );
        assert_eq!(writes.load(Ordering::SeqCst), 1);
        assert_eq!(
            fixture.driver.performance.counters.native_write_would_block,
            1
        );
        assert_eq!(fixture.driver.counters.native_written, 0);
        assert_eq!(fixture.driver.native.len(), 1);
        assert_eq!(
            fixture.driver.native.front().map(|packet| packet.since()),
            Some(now)
        );
        assert_eq!(
            immediate(fixture.driver.flush_native_ready(&mut device, || Ok(now)))??,
            0
        );
        assert_eq!(writes.load(Ordering::SeqCst), 1);
        peer.send(&ethernet(9))?;
        let mut ready =
            tokio::time::timeout(Duration::from_secs(1), device.ready_mut(Interest::READABLE))
                .await??;
        let mut input = [0; READ_BUFFER_BYTES];
        assert!(
            fixture
                .driver
                .read_native(&mut ready, &mut input, || Ok(now + 1))?
        );
        drop(ready);
        assert_eq!(fixture.driver.counters.native_read, 1);
        assert!(fixture.driver.owner.legacy()?.engine.data_ready(now + 1));
        assert!(
            fixture
                .driver
                .submit(
                    now + 2,
                    fixture.driver.records.control_scope(),
                    control::Body::Ping { nonce: 1 },
                    fixture.driver.lease,
                    true,
                )?
                .is_some()
        );
        fixture.driver.send(
            &fixture.socket,
            now + 2,
            fixture.driver.origin + duration(now + 2),
        )?;
        tokio::time::timeout(Duration::from_secs(1), fixture.remote_socket.readable()).await??;
        let mut wire = [0; 1501];
        let length = fixture.remote_socket.try_recv(&mut wire)?;
        fixture.remote.receive(
            &wire[..length],
            now + 2,
            fixture.remote.origin + duration(now + 2),
            &resolve(fixture.remote.config),
        )?;
        assert_eq!(fixture.remote.remote_ping, 1);
        assert_eq!(fixture.remote.pong, Some(1));
        assert!(fixture.driver.performance.counters.control_packets > 0);
        assert_eq!(fixture.driver.native.len(), 1);
        assert_eq!(fixture.driver.counters.native_backpressure_drops, 0);
    }
    Ok(())
}

#[tokio::test]
async fn predrain_obeys_batch_attempt_quota_and_keeps_fifo_remainder_exact() -> Result {
    for kind in [cover::Appearance::QuicLike, cover::Appearance::MediaLike] {
        let mut fixture = DrainFixture::new(kind, 3, 2).await?;
        for number in 1..=3 {
            fixture.receive_source(number)?;
        }
        fixture.driver.collect_native(fixture.now)?;
        fixture.driver.collect_native(fixture.now)?;
        assert_eq!(fixture.driver.native.len(), 3);
        let (mut device, peer, writes) = event_device()?;
        writable(&mut device).await?;
        let now = fixture.now;
        assert_eq!(
            immediate(fixture.driver.flush_native_ready(&mut device, || Ok(now)))??,
            2
        );
        assert_eq!(writes.load(Ordering::SeqCst), 2);
        assert_eq!(fixture.driver.native.len(), 1);
        assert_eq!(
            fixture.driver.native.front().map(|packet| packet.bytes()),
            Some(ethernet(3).as_slice())
        );
        assert_eq!(fixture.driver.native.bytes(), 256);
        let mut native = [0; 512];
        for number in [1, 2] {
            let length = peer.recv(&mut native)?;
            assert_eq!(&native[..length], ethernet(number));
        }
        assert_eq!(
            peer.recv(&mut native).err().map(|error| error.kind()),
            Some(io::ErrorKind::WouldBlock)
        );
        assert_eq!(
            immediate(
                fixture
                    .driver
                    .flush_native_ready(&mut device, || Ok(now + 1))
            )??,
            1
        );
        let length = peer.recv(&mut native)?;
        assert_eq!(&native[..length], ethernet(3));
        assert!(fixture.driver.native.is_empty());
        assert_eq!(fixture.driver.counters.native_written, 3);
        assert_eq!(
            fixture
                .driver
                .performance
                .counters
                .native_write_batch_packets,
            3
        );
    }
    Ok(())
}

#[tokio::test]
async fn predrain_keeps_original_expiry_and_irreversible_completion_accounting() -> Result {
    for kind in [cover::Appearance::QuicLike, cover::Appearance::MediaLike] {
        for offset in [-1_i64, 0, 1] {
            let mut config = config(kind);
            config.native.stall_timeout = Duration::from_millis(50);
            config.work.native_write_batch = 1;
            let mut fixture = NativeEventFixture::new(kind, config).await?;
            let deadline = add(1, config.native.stall_timeout)?;
            let now = u64::try_from(i64::try_from(deadline)? + offset)?;
            writable(&mut fixture.device).await?;
            let result = immediate(
                fixture
                    .driver
                    .flush_native_ready(&mut fixture.device, || Ok(now)),
            )?;
            if offset < 0 {
                assert_eq!(result?, 1);
                assert_eq!(fixture.writes.load(Ordering::SeqCst), 1);
                assert_eq!(fixture.driver.counters.native_written, 1);
            } else {
                assert_eq!(
                    result.err().map(|error| error.kind()),
                    Some(io::ErrorKind::TimedOut)
                );
                assert_eq!(fixture.writes.load(Ordering::SeqCst), 0);
                assert_eq!(fixture.driver.counters.native_written, 0);
                assert_eq!(
                    fixture.driver.native.front().map(|packet| packet.since()),
                    Some(1)
                );
                assert_eq!(fixture.driver.terminal, Some(StopReason::NativeStall));
            }
        }
        for completion in [0_u8, 1, 2] {
            let mut config = config(kind);
            config.native.stall_timeout = Duration::from_millis(50);
            config.work.native_write_batch = 1;
            let mut fixture = NativeEventFixture::new(kind, config).await?;
            let deadline = add(1, config.native.stall_timeout)?;
            writable(&mut fixture.device).await?;
            let writes = fixture.writes.clone();
            let result = immediate(fixture.driver.flush_native_ready(&mut fixture.device, || {
                if writes.load(Ordering::SeqCst) == 0 {
                    return Ok(deadline - 1);
                }
                match completion {
                    0 => Ok(deadline),
                    1 => Err(io::Error::other("completion clock unavailable")),
                    _ => Ok(0),
                }
            }))?;
            assert_eq!(
                result.err().map(|error| error.kind()),
                Some(match completion {
                    0 => io::ErrorKind::TimedOut,
                    1 => io::ErrorKind::Other,
                    _ => io::ErrorKind::InvalidData,
                })
            );
            assert_eq!(fixture.writes.load(Ordering::SeqCst), 1);
            assert_eq!(fixture.driver.counters.native_written, 1);
            assert_eq!(
                fixture
                    .driver
                    .performance
                    .counters
                    .native_write_batch_packets,
                1
            );
            assert!(fixture.driver.native.is_empty());
            assert_eq!(fixture.driver.native.bytes(), 0);
            let mut native = [0; 512];
            let length = fixture.peer.recv(&mut native)?;
            assert_eq!(&native[..length], ethernet(1));
            assert_eq!(
                fixture
                    .peer
                    .recv(&mut native)
                    .err()
                    .map(|error| error.kind()),
                Some(io::ErrorKind::WouldBlock)
            );
        }
    }
    Ok(())
}
