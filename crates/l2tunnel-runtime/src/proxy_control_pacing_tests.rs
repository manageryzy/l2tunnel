//! Actual TLS peers: cumulative credit must not violate negotiated control rate.
use super::*;

enum TestHandle {
    Fixed(Handle),
    Measured(measured::Handle),
}
impl TestHandle {
    fn status(&self) -> Option<Status> {
        match self {
            Self::Fixed(h) => h.status(),
            Self::Measured(h) => h.status().map(|s| s.runtime),
        }
    }
    fn drain(&self) -> io::Result<DrainWaiter> {
        match self {
            Self::Fixed(h) => h.request_drain(),
            Self::Measured(h) => h.request_drain(),
        }
    }
}
async fn transparent_case(measure: bool, duplex: Duplex, rate: usize, count: usize) -> TestResult {
    let mut cfg = Config::new(
        RuntimeConfig {
            layer: PacketLayer::Ip,
            max_packet: 1600,
            compression: Compression::None,
            queue_packets: 64,
            poll_interval: Duration::from_millis(1),
        },
        duplex,
        RoutePolicy::new(Vec::new())?,
    )?;
    cfg.control_rate = rate;
    // Exercise multiple actual heartbeats during the low-rate transfer.
    if rate == 16 {
        cfg.timeouts.control_idle = Duration::from_secs(1);
    }
    // The finite test observer uses the existing configured startup allowance;
    // protocol startup, heartbeat and drain deadlines remain unchanged.
    let transfer_bound = cfg.timeouts.startup;
    let shutdown_bound = cfg.timeouts.shutdown;
    let da = Device::default();
    let db = Device::default();
    let (ha, hb, mut ra, mut rb) = if measure {
        let mut measured = measured::config_tests::config()?;
        measured.fixed = cfg;
        let (a, b) = measured_links(&measured).await?;
        let (ha, ca) = measured::control_channel();
        let (hb, cb) = measured::control_channel();
        let ra = tokio::spawn(measured::run(da.clone(), a, measured.clone(), ca));
        let rb = tokio::spawn(measured::run(db.clone(), b, measured, cb));
        (TestHandle::Measured(ha), TestHandle::Measured(hb), ra, rb)
    } else {
        let (a, b) = links(&cfg).await?;
        let (ha, ca) = control_channel();
        let (hb, cb) = control_channel();
        let ra = tokio::spawn(run(da.clone(), a, cfg.clone(), ca));
        let rb = tokio::spawn(run(db.clone(), b, cfg, cb));
        (TestHandle::Fixed(ha), TestHandle::Fixed(hb), ra, rb)
    };
    let transfer = timeout(transfer_bound, async {
        while ![&ha, &hb]
            .iter()
            .all(|h| h.status().is_some_and(|s| s.phase == Phase::Forwarding))
        {
            if ra.is_finished() || rb.is_finished() {
                return Err("peer failed before forwarding".into());
            }
            sleep(Duration::from_millis(1)).await;
        }
        let packets: Vec<_> = (0..count).map(|i| packet((i % 251) as u8)).collect();
        da.change(|s| s.outgoing.extend(packets.clone()))?;
        db.change(|s| s.outgoing.extend(packets.clone()))?;
        loop {
            if da.change(|s| s.received.len())? == count
                && db.change(|s| s.received.len())? == count
            {
                assert_eq!(da.change(|s| s.received.clone())?, packets);
                assert_eq!(db.change(|s| s.received.clone())?, packets);
                return Ok::<_, Failure>(());
            }
            if ra.is_finished() || rb.is_finished() {
                return Err(
                    format!("real proxy stopped: {:?}/{:?}", ha.status(), hb.status()).into(),
                );
            }
            sleep(Duration::from_millis(1)).await;
        }
    })
    .await;
    if !matches!(transfer, Ok(Ok(()))) {
        eprintln!(
            "control pacing failed measured={measure} duplex={duplex:?} rate={rate}: {transfer:?}; received={}/{}; status={:?}/{:?}",
            da.change(|s| s.received.len())?,
            db.change(|s| s.received.len())?,
            ha.status(),
            hb.status()
        );
        ra.abort();
        rb.abort();
        let _ = ra.await;
        let _ = rb.await;
        return Err(
            "healthy real peers must forward every packet without control rate/liveness failure"
                .into(),
        );
    }
    eprintln!("transfer completed measured={measure} duplex={duplex:?} rate={rate}");
    let drain_end = tokio::time::Instant::now() + shutdown_bound;
    let waiter = ha.drain()?;
    let drained = tokio::time::timeout_at(drain_end, waiter.wait()).await;
    if !matches!(drained, Ok(Ok(_))) {
        eprintln!(
            "drain failed measured={measure} duplex={duplex:?} rate={rate}: {drained:?}; status={:?}/{:?}",
            ha.status(),
            hb.status()
        );
        ra.abort();
        rb.abort();
        let _ = ra.await;
        let _ = rb.await;
        return Err("real peer drain failed".into());
    }
    let report = drained??;
    assert_eq!(report.local_transparent_packets, count as u64);
    assert_eq!(report.native_confirmed_packets, count as u64);
    assert_eq!(tokio::time::timeout_at(drain_end, &mut ra).await???, report);
    assert_eq!(
        tokio::time::timeout_at(drain_end, &mut rb)
            .await???
            .native_confirmed_packets,
        count as u64
    );
    assert_eq!(
        report.tls_lanes_closed,
        if duplex == Duplex::Full { 1 } else { 2 }
    );
    Ok(())
}
#[tokio::test]
async fn proxy_control_pacing_real_peers_forward_2000_packets_and_drain() -> TestResult {
    for measure in [false, true] {
        for duplex in [Duplex::Full, Duplex::Half] {
            transparent_case(measure, duplex, 256, 2000).await?;
        }
    }
    Ok(())
}
#[tokio::test]
async fn proxy_control_pacing_lowest_rate_keeps_heartbeat_latest_credit_and_drain() -> TestResult {
    for measure in [false, true] {
        for duplex in [Duplex::Full, Duplex::Half] {
            transparent_case(measure, duplex, 16, 192).await?;
        }
    }
    Ok(())
}
