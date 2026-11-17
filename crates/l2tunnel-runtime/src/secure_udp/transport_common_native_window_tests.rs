//! Genuine protected UDP and whole Unix packet-device writes, not TAP qualification.
use super::*;
use l2tunnel::record_configuration as c;

fn with_window(value: C) -> Result<C> {
    let descriptor = value.descriptor();
    let common = |role| {
        let view = descriptor.direction(role);
        let old = view.common();
        c::CommonDirection::new(
            old.traffic(),
            old.pipeline(),
            old.bytes_per_second(),
            old.burst_bytes(),
            c::NativeWindow::Delivery(l2tunnel::flow_control::delivery_window::Config {
                target_bandwidth_bps: 100_000_000,
                bootstrap_rtt_micros: 10_000,
                min_rtt_micros: 1,
                max_rtt_micros: 120_000,
                headroom_percent: 100,
                minimum_bytes: view.max_native() as u64,
                max_inflight_bytes: (view.max_native() * 8) as u64,
                max_records: 8,
                max_packet_bytes: view.max_native() as u64,
                metadata_limit_bytes: 1 << 20,
                sample_ttl_micros: 100_000,
                flush_timeout_micros: 2_000_000,
            }),
        )
    };
    Ok(C::new(
        value.envelope(),
        c::Descriptor::new(
            descriptor.path_mtu(),
            descriptor.duplex(),
            common(mg::Role::Client)?,
            common(mg::Role::Server)?,
            *descriptor.profile(),
        )?,
    )?)
}

#[test]
fn common_native_delivery_waits_for_real_device_and_drains_before_epoch_retirement() -> Result {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(async {
            let kind = cover::Appearance::QuicLike;
            let original = udp_values(kind)?;
            let values = [with_window(original[1])?, with_window(original[2])?];
            let descriptors = values.map(|value| *value.descriptor());
            let contracts =
                contracts_with_catalog(kind, Catalog::new(descriptors[0], &descriptors)?, 16)?;
            let mut fixture = Fixture::from_contracts(kind, contracts).await?;
            let first = frame(42_000, 7);
            fixture.admit(0, &first).await?;
            for _ in 0..30 {
                fixture.turn_with_held_native(Some(1)).await?;
            }
            let a = &fixture.endpoints[0].driver;
            let status = a
                .common_state()?
                .engine(a.common_state()?.epoch())?
                .native_window_status(l2tunnel::record_engine::Tick(fixture.now))?
                .ok_or("native delivery owner")?;
            assert_eq!(status.admitted.records, 1);
            assert_eq!(status.flushed_total.records, 1);
            assert_eq!(status.delivered.records, 0);
            assert_eq!(fixture.endpoints[1].driver.counters.native_written, 0);
            assert!(
                !a.common_state()?
                    .engine(a.common_state()?.epoch())?
                    .drained()?
            );
            let mut delivered = false;
            for _ in 0..100 {
                fixture.turn().await?;
                let a = &fixture.endpoints[0].driver;
                let status = a
                    .common_state()?
                    .engine(a.common_state()?.epoch())?
                    .native_window_status(l2tunnel::record_engine::Tick(fixture.now))?
                    .ok_or("native delivery owner")?;
                if status.delivered.records == 1 {
                    assert_eq!(status.delivered.bytes, first.len() as u64);
                    assert_eq!(status.outstanding.records, 0);
                    delivered = true;
                    break;
                }
            }
            assert!(delivered);
            let mut actual = [0; 512];
            let n = fixture.endpoints[1].host.recv(&mut actual)?;
            assert_eq!(&actual[..n], first);
            fixture.exchange_all_channels(20).await?;
            let contract = fixture.endpoints[0]
                .driver
                .common
                .as_ref()
                .ok_or("Common owner")?
                .contract
                .clone();
            let target = C::new(
                contract.envelope(),
                *contract
                    .catalog()
                    .descriptors()
                    .iter()
                    .find(|d| **d != contract.catalog().initial())
                    .ok_or("next actual profile")?,
            )?;
            fixture.switch(target).await?;
            fixture.exchange_all_channels(40).await?;
            for endpoint in &fixture.endpoints {
                let snapshot = endpoint.driver.snapshot_common(fixture.now, true)?;
                let windows: Vec<_> = snapshot.native_delivery.into_iter().flatten().collect();
                assert_eq!(windows.len(), 1);
                assert_eq!(windows[0].epoch, snapshot.epoch.0);
                assert_eq!(windows[0].send.ok_or("window")?.outstanding.records, 0);
                assert!(!windows[0].pending_receipt);
            }
            Ok(())
        })
}
