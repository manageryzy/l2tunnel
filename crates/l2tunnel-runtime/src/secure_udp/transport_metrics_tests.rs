//! Counters reconcile actual protected sends and injected credit waits.
use super::*;

fn reconcile(snapshot: &Snapshot) {
    let p = snapshot.performance;
    assert_eq!(
        p.bootstrap_packets + p.control_packets + p.user_packets + p.feedback_packets,
        snapshot.counters.wire_packets
    );
    assert_eq!(
        p.bootstrap_ip_bytes + p.control_ip_bytes + p.user_ip_bytes + p.feedback_ip_bytes,
        snapshot.counters.wire_bytes
    );
}

#[tokio::test]
async fn eligible_credit_wait_and_actual_wire_classes_reconcile_without_idle_inflation() -> Result {
    for kind in [cover::Appearance::QuicLike, cover::Appearance::MediaLike] {
        let mut fixture = ReadyWakeFixture::new(kind, false).await?;
        for socket in [&fixture.socket, &fixture._remote_socket] {
            let mut input = [0; 1501];
            let mut drained = false;
            for _ in 0..128 {
                match socket.try_recv(&mut input) {
                    Ok(_) => {}
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        drained = true;
                        break;
                    }
                    Err(error) => return Err(error.into()),
                }
            }
            assert!(drained);
        }
        fixture.socket.writable().await?;
        let driver = &mut *fixture.driver;
        let now = fixture.now;
        driver.bucket.last = now;
        driver.bucket.tokens = 0;
        // An empty queue with no receiver feedback must not accrue credit wait.
        driver.send(&fixture.socket, now, driver.origin + duration(now))?;
        assert_eq!(
            driver
                .snapshot(now, true)?
                .performance
                .user_credit_blocked_polls,
            0
        );
        assert_eq!(
            driver.owner.legacy_mut()?.engine.offer(now, &ethernet(9))?,
            records::Admission::Accepted
        );
        let number = driver.records.next_number(Class::User);
        let statistics = driver.owner.legacy()?.engine.stats();
        driver.send(&fixture.socket, now, driver.origin + duration(now))?;
        assert_eq!(driver.records.next_number(Class::User), number);
        assert_eq!(driver.owner.legacy()?.engine.stats(), statistics);
        let maximum = driver.send.records.codec.datagram_bytes;
        let required = driver.records.capacity(maximum)?.packet_bytes + driver.ip + driver.reserve;
        let ready = driver.bucket.ready_at(required)?;
        let middle = now + (ready - now) / 2;
        let partial = driver.snapshot(middle, true)?;
        assert_eq!(partial.performance.user_credit_blocked_polls, 1);
        assert_eq!(
            partial.performance.credit_wait_observed_micros,
            middle - now
        );
        assert_eq!(partial.performance.credit_ready_late_micros, 0);
        assert_eq!(
            driver.snapshot(middle, true)?.performance,
            partial.performance
        );
        let resumed = ready + 777;
        driver.progress(resumed)?;
        driver.send(&fixture.socket, resumed, driver.origin + duration(resumed))?;
        let sent = driver.snapshot(resumed, true)?;
        assert_eq!(sent.performance.user_packets, 1);
        assert_eq!(sent.performance.credit_wait_observed_micros, resumed - now);
        assert_eq!(sent.performance.credit_ready_late_micros, 777);
        assert_eq!(sent.performance.credit_ready_late_max_micros, 777);
        assert_eq!(sent.channels.len(), 1);
        assert_eq!(
            sent.channels[0]
                .send
                .ok_or_else(|| protocol("missing sender metrics"))?
                .stats
                .sources,
            1
        );
        reconcile(&sent);
        let mut wire = vec![0; 1501];
        let length = tokio::time::timeout(
            Duration::from_secs(1),
            fixture._remote_socket.recv(&mut wire),
        )
        .await??;
        assert_eq!(sent.performance.user_ip_bytes, (length + driver.ip) as u64);
        let remote_now = resumed + 1;
        let remote = &mut *fixture.remote;
        remote.receive(
            &wire[..length],
            remote_now,
            remote.origin + duration(remote_now),
            &resolve(remote.config),
        )?;
        remote.progress(remote_now)?;
        fixture._remote_socket.writable().await?;
        remote.send(
            &fixture._remote_socket,
            remote_now,
            remote.origin + duration(remote_now),
        )?;
        let received = remote.snapshot(remote_now, true)?;
        assert_eq!(received.performance.feedback_packets, 1);
        assert_eq!(received.performance.user_packets, 0);
        reconcile(&received);
        // A real fixed-control source uses the same charged bucket and is
        // classified independently from algorithm feedback.
        driver.submit(
            resumed,
            driver.records.control_scope(),
            control::Body::Ping { nonce: 991 },
            driver.lease,
            true,
        )?;
        driver.send(&fixture.socket, resumed, driver.origin + duration(resumed))?;
        let control = driver.snapshot(resumed, true)?;
        assert_eq!(control.performance.control_packets, 1);
        assert_eq!(control.performance.user_credit_blocked_polls, 1);
        assert!(control.performance.user_not_ready_polls > 0);
        reconcile(&control);
    }
    Ok(())
}

#[tokio::test]
async fn owed_but_not_due_feedback_is_not_counted_as_credit_blocked() -> Result {
    for kind in [cover::Appearance::QuicLike, cover::Appearance::MediaLike] {
        let config = config(kind);
        let (a, b) = parts_pair(kind).await?;
        let origin = Instant::now();
        let (socket, mut local) = Driver::new(a, security::ConfigDigest([3; 32]), config, origin)?;
        let (_, mut remote) = Driver::new(b, security::ConfigDigest([3; 32]), config, origin)?;
        let wire = source(&mut remote, 0, 1)?;
        local.receive(&wire, 1, origin + duration(1), &resolve(config))?;
        assert_eq!(local.owner.legacy()?.engine.feedback_deadline(), Some(0));
        assert!(!local.owner.legacy()?.engine.feedback_ready(1));
        local.bucket.tokens = 0;
        local.bucket.last = 1;
        local.send(&socket, 1, origin + duration(1))?;
        assert_eq!(
            local
                .snapshot(1, true)?
                .performance
                .user_credit_blocked_polls,
            0
        );
        let due = config.receive.records.codec.feedback_micros;
        assert!(local.owner.legacy()?.engine.feedback_ready(due));
        local.send(&socket, due, origin + duration(due))?;
        assert_eq!(
            local
                .snapshot(due, true)?
                .performance
                .user_credit_blocked_polls,
            1
        );
    }
    Ok(())
}

#[tokio::test]
async fn actual_native_wouldblock_and_queue_high_water_are_observable() -> Result {
    for kind in [cover::Appearance::QuicLike, cover::Appearance::MediaLike] {
        let mut selected = config(kind);
        selected.native.pending_packets = 1;
        let mut fixture = NativeEventFixture::new(kind, selected).await?;
        let initial = fixture.driver.snapshot(1, true)?;
        assert_eq!(initial.performance.native_pending_packets_high, 1);
        assert_eq!(
            initial.performance.native_pending_bytes_high,
            fixture.driver.native.bytes() as u64
        );
        fixture.device.get_mut().inner.blocked = true;
        let mut ready = fixture.device.writable_mut().await?;
        assert!(!fixture.driver.write_native(&mut ready, || Ok(1))?);
        drop(ready);
        let blocked = fixture.driver.snapshot(1, true)?;
        assert_eq!(blocked.performance.native_write_would_block, 1);
        assert_eq!(blocked.counters.native_written, 0);
        assert_eq!(blocked.counters.native_pending_packets, 1);
        assert_eq!(
            blocked.counters.native_storage_capacity_bytes,
            initial.counters.native_storage_capacity_bytes
        );
        assert!(
            blocked.counters.native_storage_capacity_bytes
                > selected.native.pending_packets * selected.send.records.max_native
        );
        fixture.driver.collect_native(2)?;
        assert_eq!(
            fixture
                .driver
                .snapshot(2, true)?
                .performance
                .native_output_full_polls,
            blocked.performance.native_output_full_polls + 1
        );
    }
    Ok(())
}
