//! Production-loop fairness with scripted time and actual authenticated I/O.

use super::*;

const QUANTUM: u32 = 4;
const SOURCES: u8 = 16;
const PREFIX: u64 = 3 * QUANTUM as u64;
const SAMPLE_MICROS: u64 = 1_000;
const MAX_SAMPLES: u64 = 512;
const REMOTE_TIME: u64 = 10_000_000;

fn fairness_config(kind: cover::Appearance) -> Config {
    let mut config = config(kind);
    config.send.records.channels = 1;
    config.send.records.codec.window = 32;
    config.send.records.codec.flow_sources = 128;
    config.send.records.codec.repair_numerator = 0;
    config.receive.records = config.send.records;
    config.work.receive_packets = QUANTUM;
    config.work.receive_interval = Duration::from_micros(SAMPLE_MICROS);
    config.work.native_read_batch = 2;
    config.work.native_write_batch = 1;
    config.native.pending_packets = 1;
    config.native.pending_bytes = 512;
    config.native.stall_timeout = Duration::from_secs(10);
    config.lifetime.lease = Duration::from_secs(60);
    config.lifetime.ping_interval = Duration::from_secs(10);
    config.lifetime.pong_timeout = Duration::from_secs(5);
    config.report_interval = Some(Duration::from_micros(1));
    config
}

fn empty_setup(socket: &tokio::net::UdpSocket) -> Result {
    let mut wire = [0; 1501];
    for _ in 0..128 {
        match socket.try_recv(&mut wire) {
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(()),
            Err(error) => return Err(error.into()),
        }
    }
    Err("bounded fairness setup drain did not reach WouldBlock".into())
}

fn ping(driver: &mut Driver) -> Result<Vec<u8>> {
    driver.submit_control(REMOTE_TIME)?;
    assert_eq!(driver.live.outstanding, Some(1));
    let emission = driver
        .control
        .poll(duration(REMOTE_TIME), 4096, &mut driver.control_wire)?
        .ok_or_else(|| protocol("fairness fixture Ping was not emitted"))?;
    let mut wire = vec![0; driver.cover.limits().max_packet_bytes];
    let sealed = driver.records.seal(
        Class::Control,
        meta(driver.outer, cover::Phase::Established),
        &driver.control_wire[..emission.bytes],
        &mut driver.seal,
        &mut wire,
    )?;
    driver.outer = driver.outer.checked_add(1).ok_or_else(exhausted)?;
    wire.truncate(sealed.bytes);
    Ok(wire)
}

async fn case(kind: cover::Appearance, blocked: bool, native_input: bool) -> Result {
    let config = fairness_config(kind);
    let (local, other) = parts_pair(kind).await?;
    for socket in [&local.socket, &other.socket] {
        empty_setup(socket)?;
    }
    let origin = Instant::now();
    let (remote_socket, mut remote) =
        Driver::new(other, security::ConfigDigest([3; 32]), config, origin)?;
    remote_socket.writable().await?;
    let mut frames = vec![ping(&mut remote)?];
    for number in 0..SOURCES {
        frames.push(source(
            &mut remote,
            REMOTE_TIME + 1 + u64::from(number),
            number,
        )?);
    }
    assert_eq!(frames.len(), usize::from(SOURCES) + 1);
    let (socket, host) = UnixDatagram::pair()?;
    socket.set_nonblocking(true)?;
    host.set_nonblocking(true)?;
    let native = ethernet(201);
    let (started, start) = oneshot::channel();
    let (cancel, cancelled) = oneshot::channel();
    let reports = Arc::new(Mutex::new(Vec::new()));
    let recorded = reports.clone();
    let mut started = Some(started);
    let mut cancel = Some(cancel);
    let base = Instant::now();
    let expired = base
        .checked_add(Duration::from_secs(61))
        .ok_or_else(exhausted)?;
    let samples = Arc::new(AtomicU64::new(0));
    let counted = samples.clone();
    let producer = async {
        start.await?;
        // The real loop has registered its descriptor and yielded with both
        // inputs empty. Queue both readiness causes in this one nonawaiting turn.
        if native_input {
            assert_eq!(host.send(&native)?, native.len());
        }
        for frame in &frames {
            assert_eq!(remote_socket.try_send(frame)?, frame.len());
        }
        Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
    };
    let runtime = run_clock(
        Device {
            socket,
            blocked,
            wouldblock: None,
        },
        local,
        security::ConfigDigest([3; 32]),
        config,
        None,
        resolve(config),
        async {
            let _ = cancelled.await;
        },
        move |snapshot| {
            if snapshot.running
                && let Some(started) = started.take()
            {
                let _ = started.send(());
            }
            if let Ok(mut reports) = recorded.lock() {
                if reports.len() < 128 {
                    reports.push(snapshot.clone());
                }
                if (snapshot.counters.received_packets >= PREFIX || reports.len() == 128)
                    && let Some(cancel) = cancel.take()
                {
                    let _ = cancel.send(());
                }
            }
        },
        move || {
            let step = counted.fetch_add(1, Ordering::SeqCst);
            if step >= MAX_SAMPLES {
                return expired;
            }
            base.checked_add(duration(step * SAMPLE_MICROS))
                .unwrap_or(expired)
        },
    );
    let (stopped, ()) = tokio::time::timeout(Duration::from_secs(1), async {
        tokio::try_join!(
            async { Ok::<_, Box<dyn std::error::Error + Send + Sync>>(runtime.await?) },
            producer
        )
    })
    .await??;
    assert_eq!(stopped.reason, StopReason::Cancelled);
    assert!(!stopped.snapshot.running);
    assert!(samples.load(Ordering::SeqCst) < MAX_SAMPLES);
    {
        let reports = reports.lock().map_err(|_| "fairness reports poisoned")?;
        let checkpoint = reports
            .iter()
            .find(|snapshot| snapshot.running && snapshot.counters.received_packets >= PREFIX)
            .ok_or("missing fixed ingress-prefix observation")?;
        assert!(
            checkpoint.counters.received_packets < u64::from(SOURCES) + 1,
            "fixture exhausted UDP backlog before observing fairness"
        );
        assert!(
            u64::from(SOURCES) + 1 - checkpoint.counters.received_packets >= u64::from(QUANTUM)
        );
        assert!(checkpoint.performance.udp_batch_limit_hits >= 3);
        assert_eq!(
            checkpoint.counters.native_read,
            u64::from(native_input),
            "continuously ready UDP starved the already queued native input"
        );
    }
    assert_eq!(
        stopped.snapshot.counters.native_read,
        u64::from(native_input)
    );
    assert!(
        stopped.snapshot.performance.native_read_batch_packets
            <= stopped.snapshot.performance.loop_turns * config.work.native_read_batch as u64
    );
    assert!(
        stopped.snapshot.performance.native_write_batch_packets
            <= stopped.snapshot.performance.loop_turns * config.work.native_write_batch as u64
    );
    assert!(
        stopped.snapshot.performance.udp_batch_packets
            <= stopped.snapshot.performance.udp_ready_events * u64::from(QUANTUM)
    );
    assert_eq!(
        stopped.snapshot.configuration,
        security::ConfigDigest([3; 32])
    );
    assert_eq!(stopped.snapshot.send, config.send);
    assert_eq!(stopped.snapshot.receive, config.receive);
    assert_eq!(stopped.snapshot.committed.epoch, policy::Epoch(0));
    assert!(stopped.snapshot.pending.is_none());
    assert!(stopped.snapshot.elapsed_micros < 1_000_000);
    if blocked {
        assert_eq!(stopped.snapshot.counters.native_written, 0);
        assert_eq!(stopped.snapshot.counters.native_pending_packets, 1);
        assert!(stopped.snapshot.performance.native_write_would_block > 0);
    } else {
        assert!(stopped.snapshot.counters.native_written > 0);
        assert_eq!(stopped.snapshot.performance.native_write_would_block, 0);
    }
    let responses = stopped.snapshot.counters.socket_accepted_packets;
    assert!((1..=128).contains(&responses));
    assert_eq!(stopped.snapshot.counters.wire_packets, responses);
    assert_eq!(stopped.snapshot.counters.socket_drops, 0);
    let response_deadline = Instant::now()
        .checked_add(Duration::from_secs(1))
        .ok_or_else(exhausted)?;
    let mut received = [0; 1501];
    for offset in 0..responses {
        let length =
            tokio::time::timeout_at(response_deadline, remote_socket.recv(&mut received)).await??;
        remote.receive(
            &received[..length],
            REMOTE_TIME + 100_000 + offset,
            remote.origin + duration(REMOTE_TIME + 100_000 + offset),
            &resolve(config),
        )?;
    }
    assert!(
        remote.challenge.is_none(),
        "protected Pong/control service did not progress during ingress"
    );
    assert!(remote.live.last_pong_micros.is_some());
    assert!(
        remote
            .control
            .source_confirmed(0, duration(REMOTE_TIME + 200_000))?
    );
    remote.collect_native(REMOTE_TIME + 200_000)?;
    if native_input {
        assert_eq!(remote.native.len(), 1);
        assert_eq!(
            remote.native.front().map(|packet| packet.bytes.as_slice()),
            Some(native.as_slice())
        );
        assert_eq!(remote.swift.stats().receiver.packets, 1);
    } else {
        assert!(remote.native.is_empty());
        assert_eq!(remote.swift.stats().receiver.packets, 0);
    }
    Ok(())
}

#[tokio::test]
async fn sustained_udp_ingress_cannot_starve_opposite_native_input() -> Result {
    for kind in [cover::Appearance::QuicLike, cover::Appearance::MediaLike] {
        for blocked in [false, true] {
            case(kind, blocked, true).await?;
        }
    }
    Ok(())
}

#[tokio::test]
async fn sustained_udp_without_native_input_preserves_control_and_work_bounds() -> Result {
    for kind in [cover::Appearance::QuicLike, cover::Appearance::MediaLike] {
        case(kind, false, false).await?;
    }
    Ok(())
}
