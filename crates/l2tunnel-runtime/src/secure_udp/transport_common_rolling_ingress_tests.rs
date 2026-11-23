//! Actual protected UDP burst and per-generation decoder input ownership.
//! This finite fixture does not qualify full8192 or run a fresh handshake.
use super::*;

#[tokio::test]
async fn trace_marks_exact_rolling_record_number_accepted_or_fifo_full() -> Result {
    let kind = cover::Appearance::QuicLike;
    let old = short_contracts(kind)?;
    let limits = rolling_records::IngressLimits {
        slots: 1,
        capacity_bytes: 100_000,
    };
    let contracts = contracts_with_catalog_and_options(
        kind,
        old[0].catalog().clone(),
        1,
        Some(work()),
        Some(limits),
    )?;
    let mut fixture = Fixture::from_contracts(kind, contracts).await?;
    let directory =
        std::env::temp_dir().join(format!("l2t-rolling-admission-{}", std::process::id()));
    std::fs::create_dir(&directory)?;
    let receiver = &mut fixture.endpoints[1].driver;
    receiver
        .common
        .as_deref_mut()
        .ok_or("common peer")?
        .reverse_trace = Some(reverse_trace::Trace::in_directory(
        &directory,
        true,
        reverse_trace::Direction::Forward,
        receiver.origin,
    )?);
    let mut pns = Vec::new();
    for id in 0..3 {
        fixture.admit(0, &frame(40_000 + id as u16, 82)).await?;
        let wire = transmit_source(&mut fixture, rolling::SourceId(id))?;
        let endpoint = &mut fixture.endpoints[1];
        let mut buf = [0; 1501];
        let n =
            tokio::time::timeout(Duration::from_secs(1), endpoint.socket.recv(&mut buf)).await??;
        assert_eq!(&buf[..n], wire);
        endpoint.driver.receive_selected(
            &buf[..n],
            fixture.now,
            endpoint.driver.origin + duration(fixture.now),
        )?;
        pns.push(
            fixture.endpoints[0]
                .driver
                .records
                .next_number(Class::User)
                .0
                - 1,
        );
    }
    let endpoint = &mut fixture.endpoints[1].driver;
    assert_eq!(endpoint.counters.native_backpressure_drops, 1);
    drop(
        endpoint
            .common
            .as_deref_mut()
            .ok_or("common peer")?
            .reverse_trace
            .take(),
    );
    let saved = std::fs::read_to_string(
        directory.join(format!("forward-records-b-{}.tsv", std::process::id())),
    )?;
    let rows: Vec<_> = saved
        .lines()
        .skip(2)
        .map(|line| line.split('\t').collect::<Vec<_>>())
        .collect();
    for (pn, result) in pns.iter().zip(["accepted", "accepted", "fifo_full"]) {
        let same: Vec<_> = rows
            .iter()
            .filter(|row| row[2].parse::<u64>() == Ok(*pn))
            .collect();
        assert_eq!(same.len(), 2);
        assert_eq!(same[0][3], "opened");
        assert_eq!(&same[1][3..], ["admission", result]);
    }
    std::fs::remove_dir_all(directory)?;
    Ok(())
}

#[test]
fn actual_common_wire_ingress_retains_burst_replay_and_drains_before_switch() -> Result {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(Box::pin(async {
            let kind = cover::Appearance::QuicLike;
            let old = short_contracts(kind)?;
            let limits = rolling_records::IngressLimits {
                slots: 2,
                capacity_bytes: 100_000,
            };
            let contracts = contracts_with_catalog_and_options(
                kind,
                old[0].catalog().clone(),
                1,
                Some(rolling::WorkBudget {
                    field: 1,
                    copies: 1,
                    metadata: 1,
                }),
                Some(limits),
            )?;
            assert_ne!(
                old[0].resources().common_resource_digest(1024)?,
                contracts[0].resources().common_resource_digest(1024)?
            );
            let target = contracts[0]
                .catalog()
                .configurations(contracts[0].envelope())?
                .into_iter()
                .find(|value| matches!(value.descriptor().profile(), c::Profile::Swift { .. }))
                .ok_or("actual Swift target")?;
            let mut fixture = Fixture::from_contracts(kind, contracts).await?;
            let idle =
                fixture.endpoints[1]
                    .driver
                    .wake_common_with_custody(fixture.now, false, false)?;
            assert!(!idle.work_ready);
            assert!(idle.at >= fixture.endpoints[1].driver.origin + duration(fixture.now + 100));
            let originals = [long_frame()?, frame(40_000, 82)];
            let mut wires = Vec::new();
            for (id, original) in originals.iter().enumerate() {
                fixture.admit(0, original).await?;
                wires.push(transmit_source(&mut fixture, rolling::SourceId(id as u32))?);
            }
            let now = fixture.now;
            let endpoint = &mut fixture.endpoints[1];
            let before = endpoint.driver.counters;
            let mut input = [0; 1501];
            for wire in &wires {
                let length =
                    tokio::time::timeout(Duration::from_secs(1), endpoint.socket.recv(&mut input))
                        .await??;
                assert_eq!(&input[..length], wire);
                endpoint.driver.receive_selected(
                    &input[..length],
                    now,
                    endpoint.driver.origin + duration(now),
                )?;
            }
            let epoch = endpoint.driver.common_state()?.epoch();
            let queued = endpoint
                .driver
                .common_state()?
                .engine(epoch)?
                .rolling_ingress_status()
                .ok_or("actual input queue")?;
            assert_eq!(queued.limits, limits);
            assert_eq!(queued.packets, 1);
            assert!(queued.bytes > 0 && queued.capacity_bytes < limits.capacity_bytes);
            assert_eq!(queued.oldest_received, Some(engine::Tick(now)));
            assert_eq!(
                endpoint.driver.counters.native_backpressure_drops,
                before.native_backpressure_drops
            );
            // A duplicate protected packet is rejected by the SAME Records replay
            // owner before it can acquire another queue slot or decoder identity.
            endpoint.driver.receive_selected(
                &wires[0],
                now,
                endpoint.driver.origin + duration(now),
            )?;
            assert_eq!(
                endpoint.driver.counters.replay_rejections,
                before.replay_rejections + 1
            );
            assert_eq!(
                endpoint
                    .driver
                    .common_state()?
                    .engine(epoch)?
                    .rolling_ingress_status(),
                Some(queued)
            );
            endpoint.driver.service_common_rolling(now)?;
            let held = endpoint
                .driver
                .common_state()?
                .engine(epoch)?
                .rolling_ingress_status()
                .ok_or("actual held input")?;
            assert_eq!(held.packets, 1);
            assert_eq!(held.oldest_received, queued.oldest_received);
            let wake = endpoint
                .driver
                .wake_common_with_custody(now, false, false)?;
            assert!(wake.work_ready);
            assert!(wake.at <= endpoint.driver.origin + duration(now));
            let before_work = endpoint
                .driver
                .snapshot_common(now, true)?
                .rolling_work_used;
            let mut wait = std::pin::pin!(wake.wait(None));
            let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
            // Runnable work is cooperative, not a Ready spin or a future timer.
            assert!(std::future::Future::poll(wait.as_mut(), &mut cx).is_pending());
            assert!(std::future::Future::poll(wait.as_mut(), &mut cx).is_ready());
            assert_eq!(
                endpoint
                    .driver
                    .snapshot_common(now, true)?
                    .rolling_work_used,
                before_work
            );
            endpoint.driver.service_common_rolling(now)?;
            let after_work = endpoint
                .driver
                .snapshot_common(now, true)?
                .rolling_work_used;
            // One existing step per direction: each still has the original unit
            // allowance. Selecting Work itself granted and charged no work.
            for (before, after) in before_work.into_iter().zip(after_work) {
                assert!(after >= before && after - before <= 2);
            }
            assert!(after_work[2] > before_work[2]);
            let mut actual = Vec::new();
            let mut output = [0; 1024];
            for _ in 0..30_000 {
                endpoint.driver.progress_common(now)?;
                endpoint.driver.collect_native(now)?;
                endpoint.driver.service_common_rolling(now)?;
                endpoint.driver.service_selected_control(now)?;
                endpoint.driver.submit_control(now)?;
                endpoint.driver.collect_native(now)?;
                if !endpoint.driver.native.is_empty() {
                    let mut ready = tokio::time::timeout(
                        Duration::from_secs(1),
                        endpoint.device.ready_mut(Interest::WRITABLE),
                    )
                    .await??;
                    assert!(endpoint.driver.write_native(&mut ready, || Ok(now))?);
                    let length = endpoint.host.recv(&mut output)?;
                    actual.push(output[..length].to_vec());
                }
                if actual.len() == originals.len() {
                    break;
                }
            }
            assert_eq!(actual, originals);
            let snapshot = endpoint.driver.snapshot_common(now, true)?;
            assert_eq!(snapshot.rolling_ingress, Some(limits));
            let input_status = snapshot.rolling_input.ok_or("actual queue snapshot")?;
            assert_eq!(input_status.packets, 0);
            assert_eq!(input_status.bytes, 0);
            assert_eq!(input_status.capacity_bytes, queued.capacity_bytes);
            assert_eq!(input_status.allocations, queued.allocations);
            assert_eq!(
                endpoint.driver.counters.native_backpressure_drops,
                before.native_backpressure_drops
            );
            assert_eq!(endpoint.driver.counters.native_written, 2);
            assert_eq!(
                (endpoint.socket.local_addr()?, endpoint.socket.peer_addr()?),
                endpoint.original
            );
            // Real reverse feedback and fixed Control continue through the original
            // protected sockets; the existing transaction owner must drain the queue.
            fixture.switch(target).await?;
            for endpoint in &fixture.endpoints {
                let snapshot = endpoint.driver.snapshot_common(fixture.now, true)?;
                assert_eq!(snapshot.current, target);
                assert_eq!(snapshot.rolling_ingress, Some(limits));
                assert_eq!(snapshot.rolling_input, None);
                assert_eq!(
                    (endpoint.socket.local_addr()?, endpoint.socket.peer_addr()?),
                    endpoint.original
                );
            }
            Ok(())
        }))
}
