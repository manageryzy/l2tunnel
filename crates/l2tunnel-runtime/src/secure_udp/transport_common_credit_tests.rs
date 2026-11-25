//! Session receiver credit through two real drivers and their original UDP
//! sockets (`docs/modules/receiver-credit.md`, MOD-RCREDIT-06).
use super::*;

#[derive(Debug, Default)]
struct Stats {
    /// Datagrams side 0 handed to its socket.
    sent: u64,
    /// Datagrams side 1 read from its socket.
    read: u64,
    /// Read datagrams discarded as loss before side 1 saw them.
    lost: u64,
    /// Largest number of datagrams waiting in side 1's socket after a turn.
    peak_queued: u64,
    /// Native frames delivered at side 1.
    delivered: usize,
}

fn lose(rng: &mut u64, percent: u64) -> bool {
    *rng ^= *rng << 13;
    *rng ^= *rng >> 7;
    *rng ^= *rng << 17;
    *rng % 100 < percent
}

/// One deterministic turn on the injected clock. Side 1 reads at most
/// `budget` datagrams from its real socket, leaving the rest queued in the
/// kernel buffer. Both sides discard `loss` percent of what they read, so
/// Credits are lost as well as data, feedback and control.
async fn limited_turn(
    fixture: &mut Fixture,
    budget: usize,
    loss: u64,
    rng: &mut u64,
    stats: &mut Stats,
) -> Result {
    split_turn(fixture, budget, [loss, loss], rng, stats).await
}

/// As `limited_turn`, with separate loss percentages for side 0 to side 1
/// (`loss[0]`) and side 1 to side 0 (`loss[1]`).
async fn split_turn(
    fixture: &mut Fixture,
    budget: usize,
    loss: [u64; 2],
    rng: &mut u64,
    stats: &mut Stats,
) -> Result {
    fixture.now = fixture
        .now
        .checked_add(1000)
        .ok_or("fixture time exhausted")?;
    let now = fixture.now;
    let mut sent = [0; 2];
    for (side, endpoint) in fixture.endpoints.iter_mut().enumerate() {
        assert!(
            endpoint.driver.check_expiry(now)?,
            "session expired at {now}"
        );
        endpoint
            .driver
            .admit_common(|| Ok(duration(now)))
            .map_err(|e| format!("side {side} admit: {e}"))?;
        endpoint.driver.collect_native(now)?;
        endpoint
            .driver
            .progress_common(now)
            .map_err(|e| format!("side {side} progress: {e}"))?;
        endpoint.driver.service_common_rolling(now)?;
        endpoint.driver.service_selected_control(now)?;
        endpoint.driver.submit_control(now)?;
        let before = endpoint.driver.counters.socket_accepted_packets;
        let instant = endpoint.driver.origin + duration(now);
        endpoint
            .driver
            .send_sampled(&endpoint.socket, now, instant, || instant)
            .map_err(|e| format!("side {side} send: {e}"))?;
        sent[side] = endpoint.driver.counters.socket_accepted_packets - before;
    }
    stats.sent += sent[0];
    tokio::task::yield_now().await;
    // Side 0 receives every datagram from side 1, minus the same loss.
    for _ in 0..sent[1] {
        let mut input = [0; 1501];
        let target = &mut fixture.endpoints[0];
        let bytes =
            tokio::time::timeout(Duration::from_secs(1), target.socket.recv(&mut input)).await??;
        if lose(rng, loss[1]) {
            stats.lost += 1;
            continue;
        }
        target.driver.receive_selected(
            &input[..bytes],
            now,
            target.driver.origin + duration(now),
        )?;
    }
    // Side 1 drains at most `budget`. Tokio's readiness can lag datagrams
    // already queued in the kernel (seen under a loaded parallel test run), so
    // wait for readiness whenever side 0's sends are known to be unread.
    let target = &mut fixture.endpoints[1];
    for _ in 0..budget {
        let mut input = [0; 1501];
        let bytes = loop {
            match target.socket.try_recv(&mut input) {
                Ok(bytes) => break Some(bytes),
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    if stats.read >= stats.sent {
                        break None;
                    }
                    tokio::time::timeout(Duration::from_secs(1), target.socket.readable())
                        .await??;
                }
                Err(error) => return Err(error.into()),
            }
        };
        let Some(bytes) = bytes else {
            break;
        };
        stats.read += 1;
        if lose(rng, loss[0]) {
            stats.lost += 1;
            continue;
        }
        target
            .driver
            .receive_selected(&input[..bytes], now, target.driver.origin + duration(now))
            .map_err(|e| format!("side 1 receive: {e}"))?;
    }
    stats.peak_queued = stats.peak_queued.max(stats.sent - stats.read);
    for endpoint in &mut fixture.endpoints {
        endpoint.driver.collect_native(now)?;
        for _ in 0..endpoint.driver.config.work.native_write_batch {
            if endpoint.driver.native.is_empty() {
                break;
            }
            let mut ready = tokio::time::timeout(
                Duration::from_secs(1),
                endpoint.device.ready_mut(Interest::WRITABLE),
            )
            .await??;
            if !endpoint.driver.write_native(&mut ready, || Ok(now))? {
                break;
            }
        }
        endpoint.driver.progress_common(now)?;
    }
    let mut output = [0; 513];
    loop {
        match fixture.endpoints[1].host.recv(&mut output) {
            Ok(_) => stats.delivered += 1,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

/// Admit up to `frames` native frames into side 0 as fast as it accepts them
/// and run until side 1 delivered them all.
async fn transfer(
    fixture: &mut Fixture,
    frames: usize,
    budget: usize,
    loss: u64,
    turns: usize,
) -> Result<Stats> {
    let mut stats = Stats::default();
    let mut rng = 0x9e37_79b9_7f4a_7c15_u64;
    let mut admitted = 0;
    for _ in 0..turns {
        while admitted < frames && fixture.endpoints[0].driver.can_admit_native()? {
            let packet = frame(40_000 + (admitted % 4) as u16, admitted as u8);
            fixture.admit(0, &packet).await?;
            admitted += 1;
        }
        if let Err(error) = limited_turn(fixture, budget, loss, &mut rng, &mut stats).await {
            let rejected = fixture.endpoints.each_ref().map(|endpoint| {
                let c = endpoint.driver.counters;
                (c.rejected_packets, c.replay_rejections)
            });
            return Err(format!(
                "turn failed after {admitted} admitted: {error} {stats:?} \
                 (rejected, replay) per side {rejected:?}"
            )
            .into());
        }
        if stats.delivered == frames {
            break;
        }
    }
    Ok(stats)
}

/// Start the catalog on Aligned (1) or Packed (2) instead of Swift.
fn contracts_from(
    kind: cover::Appearance,
    initial: usize,
) -> Result<[CommonTransactionContract; 2]> {
    contracts_from_with(kind, initial, |_| {})
}

/// As `contracts_from`, with the shared base resources edited first.
fn contracts_from_with(
    kind: cover::Appearance,
    initial: usize,
    edit: fn(&mut Config),
) -> Result<[CommonTransactionContract; 2]> {
    use l2tunnel::record_configuration as c;
    let widen = |recovery: &mut l2tunnel_reliable::ReliableConfig| {
        // An ARQ window above credit's minimum floor, so credit can bind.
        let original = recovery.arq.max_source_bytes;
        recovery.arq.send_records = 64;
        recovery.arq.receive_records = 64;
        recovery.arq.send_bytes = 64 * original;
        recovery.arq.receive_bytes = 64 * original;
        recovery.max_restored_packets = 64 + recovery.fec.block.max_sources;
        // Loss runs in both directions: the fixture's four retries can
        // exhaust on an unlucky source at 10% loss (seen in about one run in
        // three), which tests the ARQ budget rather than credit.
        recovery.arq.max_retries = 8;
        recovery.max_restored_bytes =
            recovery.max_restored_packets * recovery.fec.block.max_source_bytes;
    };
    let mut values = udp_values(kind)?;
    for value in &mut values {
        let d = value.descriptor();
        let profile = match *d.profile() {
            c::Profile::Aligned {
                mut forward,
                mut reverse,
            } => {
                widen(&mut forward.recovery);
                widen(&mut reverse.recovery);
                for receiver in [&mut forward.receiver, &mut reverse.receiver] {
                    receiver.source_window = 256;
                    receiver.lookahead_records = 64;
                    receiver.record_window = 64;
                }
                c::Profile::Aligned { forward, reverse }
            }
            c::Profile::Packed {
                mut forward,
                mut reverse,
            } => {
                widen(&mut forward.base.recovery);
                widen(&mut reverse.base.recovery);
                for receiver in [&mut forward.base.receiver, &mut reverse.base.receiver] {
                    receiver.source_window = 256;
                    receiver.lookahead_records = 64;
                    receiver.record_window = 64;
                    receiver.lookahead_bytes *= 16;
                    receiver.lookahead_fragments *= 16;
                }
                c::Profile::Packed { forward, reverse }
            }
            other => other,
        };
        *value = C::new(
            value.envelope(),
            c::Descriptor::new(
                d.path_mtu(),
                d.duplex(),
                *d.direction(mg::Role::Client).common(),
                *d.direction(mg::Role::Server).common(),
                profile,
            )?,
        )?;
    }
    let descriptors = values.map(|value| *value.descriptor());
    contracts_with_catalog_and_base(
        kind,
        Catalog::new(descriptors[initial], &descriptors)?,
        16,
        edit,
    )
}

fn credit(fixture: &Fixture, side: usize) -> Result<CreditSnapshot> {
    let driver = &fixture.endpoints[side].driver;
    let snapshot = driver.snapshot_common(fixture.now, true)?;
    Ok(snapshot.credit.ok_or("credit snapshot")?)
}

#[tokio::test]
async fn credit_holds_a_slow_receiver_socket_without_kernel_drops() -> Result {
    for initial in [1, 2] {
        slow_receiver(initial)
            .await
            .map_err(|error| format!("profile {initial}: {error}"))?;
    }
    Ok(())
}

async fn slow_receiver(initial: usize) -> Result {
    let kind = cover::Appearance::QuicLike;
    let mut fixture = Fixture::from_contracts(kind, contracts_from(kind, initial)?).await?;
    // A window below the fixture's ARQ window, so credit (not ARQ) limits.
    let narrow = l2tunnel_flow_control::session_credit::Config {
        floor_datagrams: 16,
        ceiling_datagrams: 32,
        floor_bytes: 16 * 1500,
        ceiling_bytes: 32 * 1500,
        period: Duration::from_millis(10),
        idle_period: Duration::from_millis(250),
    };
    for endpoint in &mut fixture.endpoints {
        let driver = &mut endpoint.driver;
        let (rate, burst) = (driver.bucket.rate, driver.bucket.burst);
        let mtu = driver.config.path_mtu;
        let range = driver.config.security.packets_per_key;
        driver.common.as_deref_mut().ok_or("runtime")?.credit =
            Some(crate::secure_udp::transport::credit::State::new(
                narrow,
                mtu,
                rate,
                u64::try_from(burst)?,
                range,
            )?);
    }
    let frames = 2_000;
    // Side 1 drains two datagrams per millisecond; side 0 could send its
    // whole send batch every turn.
    let mut stats = transfer(&mut fixture, frames, 2, 0, 40_000).await?;
    assert_eq!(stats.delivered, frames, "{stats:?}");
    // Drain what is still queued, then nothing may be missing at the socket.
    let mut rng = 0;
    for _ in 0..200 {
        limited_turn(&mut fixture, 4096, 0, &mut rng, &mut stats).await?;
    }
    assert_eq!(stats.read, stats.sent, "kernel receive drops: {stats:?}");
    let receiver = credit(&fixture, 1)?;
    let sender = credit(&fixture, 0)?.sender.ok_or("sender credit")?;
    assert!(receiver.receiver.issued > 0, "{receiver:?}");
    assert!(receiver.allowance_readback, "{receiver:?}");
    assert!(sender.accepted > 0, "{sender:?}");
    assert!(
        sender.credit_blocked + sender.pacing_blocked > 0,
        "{sender:?}"
    );
    // The queue at the slow receiver stayed at the granted data window plus
    // a few ungated feedback and control datagrams, well below the ARQ
    // window (64) that would otherwise have been the only bound.
    assert!(
        stats.peak_queued <= narrow.ceiling_datagrams + 8,
        "{stats:?}"
    );
    assert!(stats.peak_queued < 64, "{stats:?}");
    Ok(())
}

#[tokio::test]
async fn credit_survives_heavy_loss_of_every_forward_datagram() -> Result {
    for initial in [1, 2] {
        heavy_loss(initial)
            .await
            .map_err(|error| format!("profile {initial}: {error}"))?;
    }
    Ok(())
}

async fn heavy_loss(initial: usize) -> Result {
    let kind = cover::Appearance::QuicLike;
    let mut fixture = Fixture::from_contracts(kind, contracts_from(kind, initial)?).await?;
    let frames = 600;
    // 10% of every datagram in both directions (data, feedback, control and
    // Credit) is lost; liveness is asserted by `check_expiry` every turn.
    let stats = transfer(&mut fixture, frames, 4096, 10, 60_000).await?;
    assert_eq!(stats.delivered, frames, "{stats:?}");
    assert!(stats.lost > 0);
    let receiver = credit(&fixture, 1)?;
    let sender = credit(&fixture, 0)?.sender.ok_or("sender credit")?;
    assert!(receiver.receiver.issued > 0);
    assert!(sender.accepted > 0);
    assert_eq!(receiver.rejected, 0);
    Ok(())
}

/// A short outage loses the whole in-flight tail; credit must not hinder the
/// original fixture's recovery. (Its 8-record ARQ window is below credit's
/// minimum floor, so this does not bind credit; the lost-tail release itself
/// is tested in `l2tunnel-flow-control`. The range-bound outage case is
/// `one_way_outage_keeps_data_within_the_receive_range`.)
#[tokio::test]
async fn credit_does_not_hinder_recovery_after_an_outage() -> Result {
    for initial in [1, 2] {
        outage(initial)
            .await
            .map_err(|error| format!("profile {initial}: {error}"))?;
    }
    Ok(())
}

async fn outage(initial: usize) -> Result {
    let kind = cover::Appearance::QuicLike;
    let descriptors = udp_values(kind)?.map(|value| *value.descriptor());
    let plain =
        contracts_with_catalog(kind, Catalog::new(descriptors[initial], &descriptors)?, 16)?;
    let mut fixture = Fixture::from_contracts(kind, plain).await?;
    let frames = 400;
    let mut stats = Stats::default();
    let mut rng = 0x2545_f491_4f6c_dd1d_u64;
    let mut admitted = 0;
    for turn in 0..30_000 {
        while admitted < frames && fixture.endpoints[0].driver.can_admit_native()? {
            let packet = frame(40_000 + (admitted % 4) as u16, admitted as u8);
            fixture.admit(0, &packet).await?;
            admitted += 1;
        }
        // Everything in both directions is lost for 10 ms after 20 ms: the
        // whole in-flight tail at this fixture's 1 ms round trip.
        let loss = if (20..30).contains(&turn) { 100 } else { 0 };
        limited_turn(&mut fixture, 4096, loss, &mut rng, &mut stats).await?;
        if stats.delivered == frames {
            break;
        }
    }
    assert_eq!(stats.delivered, frames, "{stats:?}");
    assert!(stats.lost > 0);
    let sender = credit(&fixture, 0)?.sender.ok_or("sender credit")?;
    assert!(sender.accepted > 0, "{sender:?}");
    Ok(())
}

/// Buffer metrics carry the requested and effective credit (MOD-RCREDIT-05):
/// a `credit` report section and a `CreditWindow` gauge whose item capacity is
/// the granted window.
#[tokio::test]
async fn buffer_metrics_report_requested_and_effective_credit() -> Result {
    let kind = cover::Appearance::QuicLike;
    let mut fixture = Fixture::from_contracts(kind, contracts_from(kind, 2)?).await?;
    let path = std::env::temp_dir().join(format!(
        "l2tunnel-credit-buffer-metrics-{}.bmetrics",
        std::process::id()
    ));
    let observer = crate::buffer_metrics::Observer::for_test(
        fixture.endpoints[0].driver.origin,
        path.clone(),
    )?;
    fixture.endpoints[0]
        .driver
        .common
        .as_deref_mut()
        .ok_or("Common owner")?
        .buffer_metrics = Some(observer);
    let stats = transfer(&mut fixture, 300, 4096, 0, 20_000).await?;
    assert_eq!(stats.delivered, 300, "{stats:?}");
    let now = fixture.now;
    let driver = &mut fixture.endpoints[0].driver;
    driver.sample_common_buffers(now);
    driver.finish_buffer_metrics(now);
    // The report is written when the observer is dropped.
    drop(
        driver
            .common
            .as_deref_mut()
            .ok_or("Common owner")?
            .buffer_metrics
            .take(),
    );
    let json: serde_json::Value = serde_json::from_slice(&std::fs::read(&path)?)?;
    std::fs::remove_file(&path)?;
    let credit = &json["credit"];
    assert_eq!(credit["requested"]["floor_datagrams"], 64, "{credit}");
    assert_eq!(credit["requested"]["period_us"], 10_000, "{credit}");
    let sender = &credit["sender"];
    assert!(
        sender["accepted"].as_u64().ok_or("accepted")? > 0,
        "{credit}"
    );
    let window = sender["window"].as_u64().ok_or("window")?;
    assert!(window >= 64, "{credit}");
    let site = json["sites"]
        .as_array()
        .ok_or("sites")?
        .iter()
        .find(|site| site["site"] == "CreditWindow")
        .ok_or("CreditWindow site")?;
    assert_eq!(site["items"]["capacity"], window, "{site}");
    assert!(site["items"]["samples"].as_u64().ok_or("samples")? > 0);
    Ok(())
}

/// Key rotation through the whole Common UDP path at the shortest key
/// interval the range floor allows (MOD-RCREDIT-09: four credit ceilings of
/// 16 datagrams): data numbered well past several key generations is opened,
/// with no rejected packets, and every frame is delivered.
#[tokio::test]
async fn common_data_crosses_key_generations_at_the_floor_interval() -> Result {
    const INTERVAL: u64 = 64;
    for initial in [1, 2] {
        let kind = cover::Appearance::QuicLike;
        let contracts = contracts_from_with(kind, initial, |base| {
            base.security.packets_per_key = INTERVAL;
            if let Some(credit) = base.credit.as_mut() {
                credit.floor_datagrams = 16;
                credit.ceiling_datagrams = INTERVAL / 4;
            }
        })?;
        let mut fixture = Fixture::from_contracts(kind, contracts).await?;
        let stats = transfer(&mut fixture, 300, 4096, 0, 20_000)
            .await
            .map_err(|error| format!("profile {initial}: {error}"))?;
        assert_eq!(stats.delivered, 300, "profile {initial}: {stats:?}");
        let receiver = fixture.endpoints[1].driver.counters;
        assert!(
            receiver.received_packets > 3 * INTERVAL,
            "profile {initial}: {receiver:?}"
        );
        assert_eq!(receiver.rejected_packets, 0, "profile {initial}");
        let sender = credit(&fixture, 0)?.sender.ok_or("sender credit")?;
        assert_eq!(sender.range, INTERVAL, "profile {initial}");
    }
    Ok(())
}

/// A one-way outage (side 0 to side 1 lost, the reverse path up) at the
/// shortest key interval: the idle receiver's heartbeats let the sender
/// declare its tail lost and send again, so without the range bound its
/// numbers would pass the receiver's 64-packet range and the data scope
/// would never open again (MOD-RCREDIT-10).
#[tokio::test]
async fn one_way_outage_keeps_data_within_the_receive_range() -> Result {
    const INTERVAL: u64 = 64;
    for initial in [1, 2] {
        let kind = cover::Appearance::QuicLike;
        let contracts = contracts_from_with(kind, initial, |base| {
            base.security.packets_per_key = INTERVAL;
            if let Some(credit) = base.credit.as_mut() {
                credit.floor_datagrams = 16;
                credit.ceiling_datagrams = INTERVAL / 4;
                credit.idle_period = Duration::from_millis(20);
            }
        })?;
        let mut fixture = Fixture::from_contracts(kind, contracts).await?;
        let frames = 300;
        let mut stats = Stats::default();
        let mut rng = 0x5851_f42d_4c95_7f2d_u64;
        let mut admitted = 0;
        for turn in 0..30_000 {
            while admitted < frames && fixture.endpoints[0].driver.can_admit_native()? {
                let packet = frame(40_000 + (admitted % 4) as u16, admitted as u8);
                fixture.admit(0, &packet).await?;
                admitted += 1;
            }
            // 400 ms: several heartbeat and retry rounds, inside liveness.
            let forward = if (20..420).contains(&turn) { 100 } else { 0 };
            split_turn(&mut fixture, 4096, [forward, 0], &mut rng, &mut stats)
                .await
                .map_err(|error| format!("profile {initial} turn {turn}: {error} {stats:?}"))?;
            if stats.delivered == frames {
                break;
            }
        }
        assert_eq!(
            stats.delivered,
            frames,
            "profile {initial}: {stats:?} sender {:?} receiver {:?} B {:?}",
            credit(&fixture, 0)?.sender,
            credit(&fixture, 1)?.receiver,
            fixture.endpoints[1].driver.counters
        );
        assert_eq!(
            fixture.endpoints[1].driver.counters.rejected_packets, 0,
            "profile {initial}"
        );
        let sender = credit(&fixture, 0)?.sender.ok_or("sender credit")?;
        assert!(sender.range_blocked > 0, "profile {initial}: {sender:?}");
        assert!(sender.range_probes > 0, "profile {initial}: {sender:?}");
        assert!(sender.declared_lost > 0, "profile {initial}: {sender:?}");
    }
    Ok(())
}

/// A record-receive range below four configured credit ceilings no longer
/// refuses setup (owner decision 2026-11-24): the runtime runs with the
/// ceiling at a quarter of the range, reports requested and effective, and
/// still delivers. Only a range below 64 datagrams, too small for any valid
/// window, is refused.
#[tokio::test]
async fn small_record_receive_range_clamps_the_credit_ceiling() -> Result {
    let kind = cover::Appearance::QuicLike;
    let below = contracts_from_with(kind, 1, |base| {
        base.security.packets_per_key = 63;
    });
    let error = below.err().ok_or("a range of 63 was accepted")?;
    assert!(
        error
            .to_string()
            .contains("record-receive range below 64 datagrams"),
        "{error}"
    );
    let contracts = contracts_from_with(kind, 1, |base| {
        base.security.packets_per_key = 64;
    })?;
    let mut fixture = Fixture::from_contracts(kind, contracts).await?;
    let stats = transfer(&mut fixture, 300, 4096, 0, 20_000).await?;
    assert_eq!(stats.delivered, 300, "{stats:?}");
    assert_eq!(fixture.endpoints[1].driver.counters.rejected_packets, 0);
    for side in 0..2 {
        let snapshot = credit(&fixture, side)?;
        assert_eq!(snapshot.configured.ceiling_datagrams, 2048);
        assert_eq!(
            (
                snapshot.effective.floor_datagrams,
                snapshot.effective.ceiling_datagrams
            ),
            (16, 16)
        );
        // The data socket was asked for the byte ceiling before data; the
        // allowance follows whatever the kernel granted.
        assert_eq!(
            snapshot.requested_receive_buffer,
            Some(snapshot.effective.ceiling_bytes)
        );
        assert_eq!(
            snapshot.requested_send_buffer,
            Some(snapshot.effective.ceiling_bytes.min(4 << 20))
        );
        assert!(snapshot.send_buffer_readback.is_some());
        assert!(snapshot.allowance_readback);
    }
    let sender = credit(&fixture, 0)?.sender.ok_or("sender credit")?;
    assert_eq!(sender.range, 64);
    Ok(())
}

/// Credit gate refusals under active demand record timed wait episodes and
/// log2 histograms on `Site::CreditWindow` (for both `.bmetrics` and the live
/// CSR `flow_control.session_credit.window.shared.user.wait.*`), and idle
/// checks (`has_demand == false`) never fabricate blocked time.
#[tokio::test]
async fn credit_window_records_timed_waits_and_histograms_only_under_demand() -> Result {
    let kind = cover::Appearance::QuicLike;
    let mut fixture = Fixture::from_contracts(kind, contracts_from(kind, 2)?).await?;
    let path = std::env::temp_dir().join(format!(
        "l2tunnel-credit-waits-{}.bmetrics",
        std::process::id()
    ));
    let observer = crate::buffer_metrics::Observer::for_test(
        fixture.endpoints[0].driver.origin,
        path.clone(),
    )?;
    fixture.endpoints[0]
        .driver
        .common
        .as_deref_mut()
        .ok_or("Common owner")?
        .buffer_metrics = Some(observer);

    // 1. Send burst at fixed t=100 until pacing gates -> records PolicyPacing wait.
    let driver = &mut fixture.endpoints[0].driver;
    let mut now = 100_u64;
    let mut seq = 1_u64;
    while seq <= 64 {
        if driver.credit_gate(seq, now, true)? {
            driver.credit_sent(seq, 1200, now)?;
            seq += 1;
        } else if let Some(wake) = driver.credit_wake(now) {
            now = wake.max(now + 1);
        } else {
            break;
        }
    }
    assert_eq!(seq, 65, "floor window of 64 datagrams should fill");
    // Ensure pacing tokens are refilled so the next gate check hits PeerCredit,
    // not PolicyPacing.
    now += 20_000;
    // Idle check must NOT open a PeerCredit wait episode.
    assert!(!driver.credit_gate(seq, now, false)?);
    let block_start = now + 100;
    assert!(!driver.credit_gate(seq, block_start, true)?);
    assert!(!driver.credit_gate(seq, block_start + 500, true)?);
    // Idle check closes the wait at block_start + 1_000 without fabricating further blocked time.
    let block_end = block_start + 1_000;
    assert!(!driver.credit_gate(seq, block_end, false)?);
    let final_now = block_end + 200;
    driver.sample_common_buffers(final_now);

    // Check live CSR registers directly from the observer.
    let mut table = l2tunnel_meters::Table::new(l2tunnel_meters::Limits::for_entries(512, 96))?;
    driver
        .common
        .as_deref()
        .and_then(|r| r.buffer_metrics.as_ref())
        .ok_or("observer")?
        .write_csr(&mut table, final_now)?;
    table.seal()?;
    let peer = "flow_control.session_credit.window.shared.user.wait.peer_credit";
    assert_eq!(table.get(&format!("{peer}.episodes")), Some(1));
    assert_eq!(table.get(&format!("{peer}.completed_episodes")), Some(1));
    assert_eq!(table.get(&format!("{peer}.completed_us")), Some(1_000));
    assert_eq!(table.get(&format!("{peer}.max_us")), Some(1_000));
    // 1_000 us falls in bucket 9 ([512, 1024) us).
    assert_eq!(table.get(&format!("{peer}.hist.b09")), Some(1));
    let pacing = "flow_control.session_credit.window.shared.user.wait.policy_pacing";
    assert!(
        table.get(&format!("{pacing}.episodes")).unwrap_or(0) > 0,
        "burst should have triggered at least one PolicyPacing episode"
    );
    assert!(
        table.get(&format!("{pacing}.completed_us")).unwrap_or(0) > 0,
        "PolicyPacing completed_us should be nonzero"
    );

    // Check `.bmetrics` persistence includes both completed_us and the 24-bucket histogram.
    driver.finish_buffer_metrics(final_now);
    drop(
        driver
            .common
            .as_deref_mut()
            .ok_or("Common owner")?
            .buffer_metrics
            .take(),
    );
    let json: serde_json::Value = serde_json::from_slice(&std::fs::read(&path)?)?;
    std::fs::remove_file(&path)?;
    let site = json["sites"]
        .as_array()
        .ok_or("sites")?
        .iter()
        .find(|s| s["site"] == "CreditWindow")
        .ok_or("CreditWindow site")?;
    let peer_credit = site["reasons"]
        .as_array()
        .ok_or("reasons")?
        .iter()
        .find(|r| r["reason"] == "PeerCredit")
        .ok_or("PeerCredit reason")?;
    assert_eq!(peer_credit["blocked"]["episodes"], 1, "{peer_credit}");
    assert_eq!(
        peer_credit["blocked"]["completed_us"], 1_000,
        "{peer_credit}"
    );
    let hist = peer_credit["blocked"]["histogram"]
        .as_array()
        .ok_or("histogram array")?;
    assert_eq!(hist.len(), 24);
    assert_eq!(hist[9], 1);
    let policy_pacing = site["reasons"]
        .as_array()
        .ok_or("reasons")?
        .iter()
        .find(|r| r["reason"] == "PolicyPacing")
        .ok_or("PolicyPacing reason")?;
    assert!(
        policy_pacing["blocked"]["completed_us"]
            .as_u64()
            .unwrap_or(0)
            > 0,
        "{policy_pacing}"
    );
    Ok(())
}
