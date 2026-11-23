//! Two authenticated Common drivers, connected UDP sockets and Unix packet devices.
use super::*;

fn tcp_golden(name: &str) -> Result<Vec<u8>> {
    let fields = include_str!("../../../l2tunnel-codec/tests/data/tcp-header-goldens.tsv")
        .lines()
        .map(|line| line.split('\t').collect::<Vec<_>>())
        .find(|row| row.first() == Some(&"tcp_timestamp") && row.get(1) == Some(&name))
        .ok_or("TCP golden absent")?;
    fields[3]
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair)?, 16).map_err(Into::into))
        .collect::<Result<Vec<_>>>()
}

fn contracts_targeted(kind: cover::Appearance) -> Result<[CommonTransactionContract; 2]> {
    let mut selected = values(kind, rolling::wire::SourceWire::TargetedExact)?;
    let old = selected[3];
    let d = old.descriptor();
    let c::Profile::Rolling { mut config, stream } = *d.profile() else {
        return Err("rolling absent".into());
    };
    for dir in [&mut config.forward, &mut config.reverse] {
        dir.scheduler.repair_numerator = 0;
        dir.receiver.body.independent_short_frame_bytes = 32;
        dir.packing.sender.body = dir.receiver.body;
    }
    selected[3] = C::new(
        old.envelope(),
        c::Descriptor::new(
            d.path_mtu(),
            d.duplex(),
            *d.direction(mg::Role::Client).common(),
            *d.direction(mg::Role::Server).common(),
            c::Profile::Rolling { config, stream },
        )?,
    )?;
    let all = selected.map(|item| *item.descriptor());
    contracts_with_catalog_and_work(kind, Catalog::new(all[3], &all)?, 16, Some(work()))
}

async fn read_datagram(fixture: &Fixture, side: usize) -> Result<Vec<u8>> {
    let mut buf = [0; 1501];
    let n = tokio::time::timeout(
        Duration::from_secs(1),
        fixture.endpoints[side].socket.recv(&mut buf),
    )
    .await??;
    Ok(buf[..n].to_vec())
}
fn ingest(fixture: &mut Fixture, side: usize, wire: &[u8]) -> Result {
    let e = &mut fixture.endpoints[side];
    e.driver
        .receive_selected(wire, fixture.now, e.driver.origin + duration(fixture.now))?;
    Ok(())
}

#[tokio::test]
async fn udp_burst_uses_the_exact_credit_earned_before_its_source_poll() -> Result {
    let kind = cover::Appearance::QuicLike;
    let mut fixture = Fixture::from_contracts(kind, contracts_targeted(kind)?).await?;
    for i in 0..3 {
        fixture.admit(0, &frame(40_000, i)).await?;
    }
    let now = fixture.now;
    let endpoint = &mut fixture.endpoints[0];
    let driver = &mut endpoint.driver;
    let epoch = driver.common_state()?.epoch();
    driver.service_common_rolling(now)?;
    driver.bucket.refill(now)?;
    driver
        .bucket
        .charge(driver.bucket.allowance() - driver.reserve)?;
    assert!(!driver.send_common_user_with(now, |_| Err(io::ErrorKind::InvalidData.into()))?);
    let cost = driver
        .common_state()?
        .engine(epoch)?
        .ready_rolling_data_wire_bytes()?
        .ok_or("ready Packed original")?;
    let eligible = driver.bucket.ready_at(cost + driver.reserve)?;
    assert!(eligible > now);
    let origin = driver.origin;
    let accepted = driver.counters.socket_accepted_ip_bytes;
    let start = origin + duration(now);
    driver.send_sampled(&endpoint.socket, now, start, || {
        origin + duration(eligible - 1)
    })?;
    assert_eq!(driver.counters.socket_accepted_ip_bytes, accepted);
    driver.send_sampled(&endpoint.socket, now, start, || origin + duration(eligible))?;
    assert_eq!(
        driver.counters.socket_accepted_ip_bytes - accepted,
        cost as u64
    );
    let wire = read_datagram(&fixture, 1).await?;
    assert_eq!(wire.len() + fixture.endpoints[0].driver.ip, cost);
    Ok(())
}

#[tokio::test]
async fn udp_read_pressure_returns_to_the_existing_targeted_receive_grant() -> Result {
    let kind = cover::Appearance::QuicLike;
    let old = contracts_targeted(kind)?;
    let limits = rolling_records::IngressLimits {
        slots: 4,
        capacity_bytes: 100_000,
    };
    let contracts = contracts_with_catalog_and_options(
        kind,
        old[0].catalog().clone(),
        16,
        Some(work()),
        Some(limits),
    )?;
    let mut fixture = Fixture::from_contracts(kind, contracts).await?;
    let mut wires = Vec::new();
    for id in 0..5 {
        fixture.admit(0, &frame(40_000, 82 + id as u8)).await?;
        wires.push(transmit_source(&mut fixture, rolling::SourceId(id))?);
    }
    let mut check = 1;
    for (id, expected) in wires.iter().take(4).enumerate() {
        let actual = read_datagram(&fixture, 1).await?;
        assert_eq!(&actual, expected);
        ingest(&mut fixture, 1, &actual)?;
        assert_eq!(
            fixture.endpoints[1]
                .driver
                .yield_targeted_udp_batch(id as u64 + 1, 16, &mut check)?,
            id == 3
        );
    }
    // A fifth physical packet is still readable. The first four have each
    // spent one read. The normal outer-loop grant advances the real decoder.
    let now = fixture.now;
    let driver = &mut fixture.endpoints[1].driver;
    let before = driver
        .common_state()?
        .engine(driver.common_state()?.epoch())?
        .rolling_ingress_status()
        .ok_or("queue")?;
    assert_eq!(before.packets, 3);
    assert_eq!(driver.performance.counters.udp_rolling_pressure_yields, 1);
    driver.service_common_rolling(now)?;
    assert!(
        driver
            .common_state()?
            .engine(driver.common_state()?.epoch())?
            .rolling_ingress_status()
            .ok_or("serviced queue")?
            .packets
            < before.packets
    );
    let last = read_datagram(&fixture, 1).await?;
    assert_eq!(last, wires[4]);
    ingest(&mut fixture, 1, &last)?;
    assert_eq!(
        fixture.endpoints[1]
            .driver
            .counters
            .native_backpressure_drops,
        0
    );
    Ok(())
}
async fn early_native(fixture: &mut Fixture) -> Result<Vec<u8>> {
    let now = fixture.now;
    let e = &mut fixture.endpoints[1];
    drop(
        tokio::time::timeout(
            Duration::from_secs(1),
            e.device.ready_mut(Interest::WRITABLE),
        )
        .await??,
    );
    let written = e.driver.counters.native_written;
    for _ in 0..256 {
        e.driver.progress_common(now)?;
        e.driver.service_common_rolling(now)?;
        // The loop's initial collection precedes this decoder grant. A newly
        // restored record must reach the writable device before selecting again.
        assert!(e.driver.native.is_empty());
        let spent = e
            .driver
            .flush_native_ready(&mut e.device, || Ok(now))
            .await?;
        assert!(spent <= e.driver.config.work.native_write_batch);
        if e.driver.counters.native_written > written {
            assert_eq!(e.driver.counters.native_written, written + 1);
            let mut buf = [0; 256];
            let n = e.host.recv(&mut buf)?;
            return Ok(buf[..n].to_vec());
        }
    }
    Err("second channel could not deliver its complete TCP record across source zero".into())
}
async fn reverse_request(fixture: &mut Fixture) -> Result<(Vec<u8>, Option<Vec<u8>>)> {
    let mut prior_ack = None;
    for _ in 0..100 {
        fixture.now += 200;
        let now = fixture.now;
        let e = &mut fixture.endpoints[1];
        e.driver.progress_common(now)?;
        e.driver.service_common_rolling(now)?;
        e.driver
            .send_common_user_with(now, |_| Err(io::ErrorKind::WouldBlock.into()))?;
        let Some(held) = e.driver.common.as_ref().and_then(|r| r.sealed.as_ref()) else {
            continue;
        };
        let token = held.carrier.as_ref().ok_or("feedback token")?;
        assert_eq!(token.emission().kind, engine::EmissionKind::Feedback);
        let plain = &e.driver.buffers.frame[..token.emission().bytes];
        let tag = plain[0];
        assert!(
            e.driver
                .flush_common_wire_with(now, |bytes| e.socket.try_send(bytes))?
        );
        let wire = read_datagram(fixture, 0).await?;
        if tag == 5 {
            return Ok((wire, prior_ack));
        }
        assert_eq!(tag, 3);
        prior_ack = Some(wire);
    }
    Err("no actual reverse named feedback".into())
}

#[test]
fn protected_udp_targeted_gap_retries_retained_original_and_charges_local_mux_pressure() -> Result {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(async {
            let kind = cover::Appearance::QuicLike;
            let mut fixture = Fixture::from_contracts(kind, contracts_targeted(kind)?).await?;
            let a = tcp_golden("initial")?;
            let b = tcp_golden("new_static_context")?;
            let epoch = fixture.endpoints[0].driver.common_state()?.epoch();
            fixture.admit(0, &a).await?;
            let original = transmit_source(&mut fixture, rolling::SourceId(0))?;
            assert_eq!(read_datagram(&fixture, 1).await?, original);
            // Source zero was physically accepted on the selected socket but lost.
            fixture.admit(0, &b).await?;
            // Timestamp context and context-dependent data are separate sources.
            // Channel zero's data waits; both complete units of channel one can pass.
            for id in 1..=3 {
                let delivered = transmit_source(&mut fixture, rolling::SourceId(id))?;
                assert_eq!(read_datagram(&fixture, 1).await?, delivered);
                ingest(&mut fixture, 1, &delivered)?;
                let e = &mut fixture.endpoints[1];
                for _ in 0..16 {
                    e.driver.service_common_rolling(fixture.now)?;
                }
            }
            assert_eq!(
                early_native(&mut fixture)
                    .await
                    .map_err(|e| format!("early B: {e}"))?,
                b
            );
            let (request, old_ack) = reverse_request(&mut fixture).await?;
            let filler = frame(41_001, 97);
            fixture.admit(0, &filler).await?;
            fixture.now += 20_000;
            let before = fixture.endpoints[0]
                .driver
                .common_state()?
                .engine(epoch)?
                .rolling_repair_budget()
                .ok_or("sender budget")?;
            ingest(&mut fixture, 0, &request)?;
            ingest(
                &mut fixture,
                0,
                &old_ack.ok_or("fixture did not retain early ACK")?,
            )?;
            let now = fixture.now;
            // Bind the actual emitted retry through WouldBlock and repeated preparation.
            let sender = &mut fixture.endpoints[0];
            sender.driver.service_common_rolling(now)?;
            for _ in 0..8 {
                sender
                    .driver
                    .send_common_user_with(now, |_| Err(io::ErrorKind::WouldBlock.into()))?;
                if sender
                    .driver
                    .common
                    .as_ref()
                    .is_some_and(|r| r.sealed.is_some())
                {
                    break;
                }
                sender.driver.service_common_rolling(now)?;
            }
            let runtime = sender.driver.common.as_ref().ok_or("runtime")?;
            let held = runtime.sealed.as_ref().ok_or("retry was not sealed")?;
            let token = held.carrier.as_ref().ok_or("immutable physical token")?;
            let cost = held.cost;
            let retry = runtime.wire[..held.sealed.bytes].to_vec();
            let plain = &sender.driver.buffers.frame[..token.emission().bytes];
            assert_eq!(plain.first(), Some(&1));
            assert_eq!(plain.get(1), Some(&0));
            let mut requested = before;
            requested.named_requests.first += 1;
            assert_eq!(
                sender
                    .driver
                    .common_state()?
                    .engine(epoch)?
                    .rolling_repair_budget(),
                Some(requested)
            );
            sender
                .driver
                .send_common_user_with(now, |_| Err(io::ErrorKind::WouldBlock.into()))?;
            assert!(
                sender
                    .driver
                    .flush_common_wire_with(now, |bytes| sender.socket.try_send(bytes))?
            );
            let after = sender
                .driver
                .common_state()?
                .engine(epoch)?
                .rolling_repair_budget()
                .ok_or("charged")?;
            assert_eq!(after.full_weight_retries, before.full_weight_retries + 1);
            assert_eq!(
                after.earned_half_bytes - before.earned_half_bytes,
                2 * cost as u64
            );
            assert_ne!(retry, original);
            assert_eq!(read_datagram(&fixture, 1).await?, retry);
            ingest(&mut fixture, 1, &retry)?;
            assert_eq!(
                early_native(&mut fixture)
                    .await
                    .map_err(|e| format!("recovered A: {e}"))?,
                a
            );
            // Authentic duplicate Records data cannot deliver an original twice.
            ingest(&mut fixture, 1, &retry)?;
            let mut extra = Vec::new();
            for _ in 0..500 {
                fixture.turn().await?;
                let e = &fixture.endpoints[1];
                let mut b = [0; 512];
                if let Ok(n) = e.host.recv(&mut b) {
                    extra.push(b[..n].to_vec());
                }
                if fixture.endpoints.iter().all(|e| {
                    e.driver
                        .common_state()
                        .is_ok_and(|s| s.engine(epoch).is_ok_and(|x| x.drained().unwrap_or(false)))
                }) {
                    break;
                }
            }
            for e in &fixture.endpoints {
                assert!(e.driver.common_state()?.engine(epoch)?.drained()?);
                assert_eq!((e.socket.local_addr()?, e.socket.peer_addr()?), e.original);
            }
            assert_eq!(extra, [filler]);
            Ok(())
        })
}

#[tokio::test]
async fn one_targeted_sender_grant_crosses_multiple_physical_accepts_but_not_would_block() -> Result
{
    let mut fixture = queued_targeted_sender().await?;
    let epoch = fixture.endpoints[0].driver.common_state()?.epoch();
    let sender = &mut fixture.endpoints[0];
    let now = fixture.now;
    assert!(
        sender
            .driver
            .common_state()?
            .engine(epoch)?
            .rolling_repair_budget()
            .ok_or("targeted sender")?
            .queued_fresh
            >= 2
    );
    // A zero metadata grant cannot select a second datagram after a physical
    // receipt, even when other components still have unused capacity.
    sender.driver.config.rolling_work = Some(rolling::WorkBudget {
        metadata: 0,
        ..work()
    });
    sender.driver.service_common_rolling(now)?;
    assert!(
        sender
            .driver
            .send_common_user_with(now, |bytes| sender.socket.try_send(bytes))?
    );
    assert!(
        !sender
            .driver
            .send_common_user_with(now, |bytes| sender.socket.try_send(bytes))?
    );
    sender.driver.config.rolling_work = Some(work());
    sender.driver.service_common_rolling(now)?;
    let phys = sender.driver.counters.socket_accepted_packets;
    let (steps, used, grant) = {
        let runtime = sender.driver.common.as_ref().ok_or("runtime")?;
        (
            runtime.rolling_scheduler_steps,
            runtime.rolling_work_used,
            runtime.rolling_sender_grant.ok_or("sender grant")?,
        )
    };
    for _ in 0..2 {
        assert!(
            !sender
                .driver
                .send_common_user_with(now, |_| Err(io::ErrorKind::WouldBlock.into()))?
        );
        let runtime = sender.driver.common.as_ref().ok_or("runtime")?;
        assert_eq!(runtime.rolling_sender_grant, Some(grant));
        assert_eq!(runtime.rolling_work_used, used);
        assert_eq!(sender.driver.counters.socket_accepted_packets, phys);
    }
    let held = {
        let runtime = sender.driver.common.as_ref().ok_or("runtime")?;
        let sealed = runtime.sealed.as_ref().ok_or("original custody")?;
        runtime.wire[..sealed.sealed.bytes].to_vec()
    };
    let instant = sender.driver.origin + duration(now);
    sender
        .driver
        .send_sampled(&sender.socket, now, instant, || instant)?;
    let runtime = sender.driver.common.as_ref().ok_or("runtime")?;
    assert_eq!(runtime.rolling_scheduler_steps, steps);
    assert!(sender.driver.counters.socket_accepted_packets >= phys + 2);
    let delta = std::array::from_fn::<_, 3, _>(|idx| runtime.rolling_work_used[idx] - used[idx]);
    assert_eq!(delta[0], 0);
    assert!(delta[1] > 0 && delta[1] <= grant.1.copies as u64);
    assert!(delta[2] > 0 && delta[2] <= grant.1.metadata as u64);
    let mut accepted = Vec::new();
    for _ in phys - 1..sender.driver.counters.socket_accepted_packets {
        accepted.push(read_datagram(&fixture, 1).await?);
    }
    assert!(accepted.iter().any(|datagram| datagram == &held));
    assert!(accepted.windows(2).all(|pair| pair[0] != pair[1]));
    Ok(())
}

async fn queued_targeted_sender() -> Result<Fixture> {
    let kind = cover::Appearance::QuicLike;
    let mut fixture = Fixture::from_contracts(kind, contracts_targeted(kind)?).await?;
    let epoch = fixture.endpoints[0].driver.common_state()?.epoch();
    // Retain a prepared source and queue later sealed sources before this turn.
    for i in 0..5 {
        fixture.admit(0, &frame(41_001, 70 + i)).await?;
        let sender = &mut fixture.endpoints[0];
        let mut entry = sender.driver.common_state_mut()?.entry(epoch)?;
        assert!(entry.admit_borrowed(engine::Tick(fixture.now))?.is_some());
        fixture.now += 10_000;
        sender.driver.service_common_rolling(fixture.now)?;
    }
    Ok(fixture)
}

#[tokio::test]
async fn deferred_whole_receipt_retires_original_without_using_an_ended_turn_or_late_cap() -> Result
{
    #[derive(Clone, Copy)]
    enum Boundary {
        NextTurn,
        Terminal,
        Late,
        InvalidGrant,
    }
    for boundary in [
        Boundary::NextTurn,
        Boundary::Terminal,
        Boundary::Late,
        Boundary::InvalidGrant,
    ] {
        let mut fixture = queued_targeted_sender().await?;
        let endpoint = &mut fixture.endpoints[0];
        let driver = &mut endpoint.driver;
        let now = fixture.now;
        assert!(!driver.send_common_user_with(now, |_| Err(io::ErrorKind::WouldBlock.into()))?);
        let runtime = driver.common.as_ref().ok_or("runtime")?;
        assert!(runtime.rolling_sender_grant.is_some());
        let used = runtime.rolling_work_used;
        let pending = runtime.sealed.as_ref().ok_or("sealed output")?;
        let epoch = core::Epoch(pending.scope.epoch.0);
        let accepted_before = driver.counters.socket_accepted_packets;
        let bytes_before = driver.counters.socket_accepted_ip_bytes;
        let id = carrier::UserIdentity {
            scope: pending.scope,
            number: pending.sealed.number,
            bytes: pending.sealed.bytes,
            deadline: driver.origin + duration(pending.deadline),
        };
        let accepted = driver.origin + duration(now);
        let observed = accepted + Duration::from_micros(10);
        let receipt = carrier::AcceptedReceipt {
            record_bytes: id.bytes,
            udp_bytes: Some(id.bytes),
            charged_bytes: pending.cost,
            socket_ip_bytes: Some(pending.cost),
            boundary: crate::secure_udp::SendBoundary::SocketAccepted,
            accepted_at: accepted,
            deadline: id.deadline,
        };
        let fresh = driver
            .common_state()?
            .engine(epoch)?
            .rolling_repair_budget()
            .ok_or("targeted sender")?
            .queued_fresh;
        assert!(fresh >= 2);
        assert_eq!(
            endpoint.socket.try_send(&runtime.wire[..id.bytes])?,
            id.bytes
        );
        match boundary {
            Boundary::Terminal => {
                let mut udp: carrier::IoOwner =
                    tokio::net::UdpSocket::bind("127.0.0.1:0").await?.into();
                driver.complete_carrier_io_terminal(&mut udp, None, || observed)?;
            }
            Boundary::NextTurn => driver.clear_rolling_sender_grant(),
            Boundary::Late => {}
            Boundary::InvalidGrant => {
                // Inject a selector error after a genuine physical receipt.
                let (_, grant) = driver
                    .common
                    .as_mut()
                    .and_then(|r| r.rolling_sender_grant.as_mut())
                    .ok_or("active sender grant")?;
                grant.field = usize::MAX;
            }
        }
        let result =
            driver.complete_common_carrier(id, receipt, matches!(boundary, Boundary::Late), || {
                observed
            });
        match boundary {
            Boundary::Late => assert_eq!(
                result.err().ok_or("missing late failure")?.kind(),
                io::ErrorKind::TimedOut
            ),
            Boundary::InvalidGrant => assert!(
                result
                    .err()
                    .ok_or("missing selector failure")?
                    .to_string()
                    .contains("WorkLimit")
            ),
            Boundary::NextTurn | Boundary::Terminal => assert!(result?),
        }
        assert_eq!(driver.counters.socket_accepted_packets, accepted_before + 1);
        assert_eq!(
            driver.counters.socket_accepted_ip_bytes,
            bytes_before + receipt.charged_bytes as u64
        );
        let runtime = driver.common.as_ref().ok_or("runtime")?;
        assert!(runtime.sealed.is_none());
        assert_eq!(runtime.rolling_work_used, used);
        let engine = driver.common_state()?.engine(epoch)?;
        assert!(engine.pending_carrier_output().is_none());
        assert_eq!(
            engine
                .rolling_repair_budget()
                .ok_or("targeted sender")?
                .queued_fresh,
            fresh
        );
        assert_eq!(read_datagram(&fixture, 1).await?.len(), id.bytes);
    }
    Ok(())
}
