//! Actual bounded rolling service and physical output custody in the common loop.
use super::*;
use l2tunnel::{
    codec, fec::rolling, record_configuration as c, record_engine as engine, rolling_records,
};

fn work() -> rolling::WorkBudget {
    rolling::WorkBudget {
        field: 4096,
        copies: 4096,
        metadata: 4096,
    }
}

fn values(kind: cover::Appearance, source_wire: rolling::wire::SourceWire) -> Result<[C; 4]> {
    let old = udp_values(kind)?;
    let c::Profile::Packed { forward, reverse } = *old[2].descriptor().profile() else {
        return Err("actual packed fixture absent".into());
    };
    let direction = |packed: l2tunnel_aligned::packed::Config| {
        let mut receiver = packed.base.receiver;
        receiver.lifetime_ticks = 5_000_000;
        rolling_records::DirectionConfig {
            native_policy: packed.base.native_policy,
            receiver,
            packing: codec::packed_sender::Config {
                sender: codec::aligned_sender::Config {
                    body: receiver.body,
                    channels: receiver.channels,
                    first_record: receiver.first_record,
                },
                packing: codec::packed::Config {
                    symbol_bytes: receiver.body.symbol_bytes,
                    hold_micros: packed.hold_micros,
                },
                max_units: packed.max_units,
                first_unit: receiver.first_source,
                work_limit: packed.work_limit,
            },
            codec_stage_micros: 1_000_000,
            scheduler: rolling::scheduler::Policy {
                recovery: rolling::Config {
                    window: 16,
                    local_window: 4,
                    global_every: 2,
                    max_payload: 1024,
                    max_rows: 16,
                    repair_history: 64,
                    handoff_sources: 2,
                    job_ticks: 1_000_000,
                    debt_ticks: 10_000_000,
                    handoff_ticks: 2_000_000,
                    memory_bytes: 16 << 20,
                },
                repair_numerator: 1,
                repair_denominator: 2,
                tail_ticks: 1000,
                feedback_ticks: 100,
                feedback_packets: 2,
                memory_bytes: 16 << 20,
                source_wire,
            },
        }
    };
    let overhead = config(kind).control.wire_overhead;
    let descriptor = old[0].descriptor();
    let rolling = C::new(
        old[0].envelope(),
        c::Descriptor::new(
            descriptor.path_mtu(),
            descriptor.duplex(),
            *descriptor.direction(mg::Role::Client).common(),
            *descriptor.direction(mg::Role::Server).common(),
            c::Profile::Rolling {
                config: rolling_records::Config {
                    forward: direction(forward),
                    reverse: direction(reverse),
                    geometry: engine::Geometry {
                        forward_overhead_bytes: overhead,
                        reverse_overhead_bytes: overhead,
                    },
                    native_stall_micros: 10_000_000,
                },
                stream: 17,
            },
        )?,
    )?;
    Ok([old[0], old[1], old[2], rolling])
}

fn selected(
    kind: cover::Appearance,
    wire: rolling::wire::SourceWire,
    initial: usize,
) -> Result<([CommonTransactionContract; 2], [C; 4])> {
    let values = values(kind, wire)?;
    let descriptors = values.map(|value| *value.descriptor());
    let catalog = Catalog::new(descriptors[initial], &descriptors)?;
    Ok((
        contracts_with_catalog_and_work(kind, catalog, 16, Some(work()))?,
        values,
    ))
}

fn retain_first_source(fixture: &mut Fixture) -> Result<u64> {
    // Native admission enters the common queue first. Its actual compact owner
    // is populated by poll, so service subsequent bounded packing/work turns.
    for _ in 0..16 {
        fixture.now = fixture.now.checked_add(1000).ok_or("fixture time")?;
        let now = fixture.now;
        let endpoint = &mut fixture.endpoints[0];
        endpoint.driver.progress_common(now)?;
        endpoint.driver.service_common_rolling(now)?;
        assert!(
            !endpoint.driver.send_common_user_with(now, |_| {
                Err(io::Error::from(io::ErrorKind::WouldBlock))
            })?
        );
        if endpoint
            .driver
            .common
            .as_ref()
            .is_some_and(|runtime| runtime.sealed.is_some())
        {
            return Ok(now);
        }
    }
    Err("actual rolling source was not prepared under bounded service".into())
}

#[test]
fn actual_rolling_requires_explicit_authenticated_work_and_preserves_absent_digest() -> Result {
    let kind = cover::Appearance::QuicLike;
    let (contracts, values) = selected(kind, rolling::wire::SourceWire::Exact, 0)?;
    let mut resources = contracts[0].resources();
    let original = resources.common_resource_digest(1024)?;
    resources.rolling_work = None;
    let absent = resources.common_resource_digest(1024)?;
    assert_ne!(original, absent);
    let descriptors = values.map(|value| *value.descriptor());
    let catalog = Catalog::new(descriptors[0], &descriptors)?;
    assert!(contracts_with_catalog(kind, catalog, 16).is_err());
    for bad in [0, rolling::MAX_STEP_WORK + 1] {
        for component in 0..3 {
            let mut cap = work();
            match component {
                0 => cap.field = bad,
                1 => cap.copies = bad,
                _ => cap.metadata = bad,
            }
            resources.rolling_work = Some(cap);
            assert!(resources.validate_common_resources(1024).is_err());
        }
    }
    resources.rolling_work = None;
    assert_eq!(resources.common_resource_digest(1024)?, absent);
    resources.rolling_work = Some(rolling::WorkBudget { field: 1, ..work() });
    assert_ne!(resources.common_resource_digest(1024)?, original);
    Ok(())
}

#[test]
fn actual_original_udp_switches_all_four_record_families_with_bounded_rolling_work() -> Result {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(async {
            for kind in [cover::Appearance::QuicLike, cover::Appearance::MediaLike] {
                for wire in [
                    rolling::wire::SourceWire::Padded,
                    rolling::wire::SourceWire::Exact,
                ] {
                    let (contracts, values) = selected(kind, wire, 0)?;
                    let mut fixture = Fixture::from_contracts(kind, contracts).await?;
                    fixture.exchange_all_channels(1).await?;
                    for (number, target) in [values[3], values[1], values[2], values[0]]
                        .into_iter()
                        .enumerate()
                    {
                        fixture.switch(target).await?;
                        fixture.exchange_all_channels(number as u8 + 20).await?;
                        for endpoint in &fixture.endpoints {
                            let snapshot = endpoint.driver.snapshot_common(fixture.now, true)?;
                            assert_eq!(snapshot.current, target);
                            assert_eq!(snapshot.rolling_work, Some(work()));
                            assert!(snapshot.rolling_scheduler_steps > 0);
                            assert!(snapshot.rolling_work_used[1] > 0);
                            assert_eq!(
                                (endpoint.socket.local_addr()?, endpoint.socket.peer_addr()?),
                                endpoint.original
                            );
                        }
                    }
                }
            }
            Ok(())
        })
}

#[test]
fn actual_rolling_wouldblock_keeps_token_then_whole_udp_loss_recovers_without_reseal() -> Result {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(async {
            for kind in [cover::Appearance::QuicLike, cover::Appearance::MediaLike] {
                let (contracts, _) = selected(kind, rolling::wire::SourceWire::Exact, 3)?;
                let mut fixture = Fixture::from_contracts(kind, contracts).await?;
                let packet = frame(40_000, 93);
                fixture.admit(0, &packet).await?;
                let now = retain_first_source(&mut fixture)?;
                let endpoint = &mut fixture.endpoints[0];
                let blocked = |_: &[u8]| Err(io::Error::from(io::ErrorKind::WouldBlock));
                assert!(!endpoint.driver.send_common_user_with(now, blocked)?);
                let runtime = endpoint.driver.common.as_ref().ok_or("common runtime")?;
                let pending = runtime.sealed.as_ref().ok_or("actual rolling output")?;
                let token = pending
                    .carrier
                    .as_ref()
                    .ok_or("actual rolling carrier token")?;
                assert!(matches!(
                    token.emission().kind,
                    engine::EmissionKind::Source(_)
                ));
                let original = (
                    pending.scope,
                    pending.sealed,
                    pending.cost,
                    pending.deadline,
                    token.emission(),
                );
                let wire_bytes = runtime.wire[..pending.sealed.bytes].to_vec();
                let next = endpoint.driver.records.next_number(Class::User);
                let debit = endpoint.driver.bucket.tokens;
                let accepted = endpoint.driver.counters.socket_accepted_packets;
                for _ in 0..3 {
                    assert!(!endpoint.driver.send_common_user_with(now, blocked)?);
                    let runtime = endpoint.driver.common.as_ref().ok_or("common runtime")?;
                    let pending = runtime.sealed.as_ref().ok_or("retained rolling output")?;
                    let token = pending.carrier.as_ref().ok_or("retained rolling token")?;
                    assert_eq!(
                        (
                            pending.scope,
                            pending.sealed,
                            pending.cost,
                            pending.deadline,
                            token.emission()
                        ),
                        original
                    );
                    assert_eq!(&runtime.wire[..pending.sealed.bytes], wire_bytes);
                    assert_eq!(endpoint.driver.records.next_number(Class::User), next);
                    assert_eq!(endpoint.driver.bucket.tokens, debit);
                    assert_eq!(endpoint.driver.counters.socket_accepted_packets, accepted);
                }
                assert!(
                    endpoint
                        .driver
                        .flush_common_wire_with(now, |bytes| endpoint.socket.try_send(bytes))?
                );
                assert!(
                    endpoint
                        .driver
                        .common
                        .as_ref()
                        .ok_or("common runtime")?
                        .sealed
                        .is_none()
                );
                assert!(
                    endpoint
                        .driver
                        .common_state()?
                        .engine(core::Epoch(original.0.epoch.0))?
                        .pending_carrier_output()
                        .is_none()
                );
                assert_eq!(
                    endpoint.driver.counters.socket_accepted_packets,
                    accepted + 1
                );
                assert_eq!(endpoint.driver.bucket.tokens, debit);
                // The real UDP socket accepted the whole original. Discard it at the
                // peer socket to model path loss; no plaintext or peer receipt is forged.
                let mut lost = [0; 1501];
                let bytes = tokio::time::timeout(
                    Duration::from_secs(1),
                    fixture.endpoints[1].socket.recv(&mut lost),
                )
                .await??;
                assert_eq!(&lost[..bytes], wire_bytes);
                let mut recovered = false;
                for _ in 0..500 {
                    fixture.turn().await?;
                    let mut received = [0; 1024];
                    match fixture.endpoints[1].host.recv(&mut received) {
                        Ok(bytes) => {
                            assert_eq!(&received[..bytes], packet);
                            recovered = true;
                            break;
                        }
                        Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                        Err(error) => return Err(error.into()),
                    }
                }
                assert!(
                    recovered,
                    "actual rolling repair did not recover the dropped UDP original"
                );
                assert!(
                    fixture.endpoints[0]
                        .driver
                        .performance
                        .counters
                        .user_packets
                        > 1
                );
            }
            Ok(())
        })
}

#[test]
fn actual_rolling_late_whole_write_records_physical_fact_and_retires_original_token() -> Result {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(async {
            let kind = cover::Appearance::QuicLike;
            let (contracts, _) = selected(kind, rolling::wire::SourceWire::Exact, 3)?;
            let mut fixture = Fixture::from_contracts(kind, contracts).await?;
            fixture.admit(0, &frame(40_000, 94)).await?;
            let now = retain_first_source(&mut fixture)?;
            let endpoint = &mut fixture.endpoints[0];
            assert!(
                !endpoint
                    .driver
                    .send_common_user_with(now, |_| Err(io::Error::from(
                        io::ErrorKind::WouldBlock
                    )))?
            );
            let pending = endpoint
                .driver
                .common
                .as_ref()
                .ok_or("common runtime")?
                .sealed
                .as_ref()
                .ok_or("actual source")?;
            let cap = pending.deadline;
            let epoch = core::Epoch(pending.scope.epoch.0);
            let cost = pending.cost;
            let accepted = endpoint.driver.counters.socket_accepted_packets;
            let accepted_bytes = endpoint.driver.counters.socket_accepted_ip_bytes;
            assert!(now < cap);
            let result = endpoint.driver.send_common_user_sampled(
                now,
                |bytes| endpoint.socket.try_send(bytes),
                || Ok(cap),
            );
            assert!(result.is_err());
            assert_eq!(
                endpoint.driver.counters.socket_accepted_packets,
                accepted + 1
            );
            assert_eq!(
                endpoint.driver.counters.socket_accepted_ip_bytes,
                accepted_bytes + cost as u64
            );
            assert!(
                endpoint
                    .driver
                    .common
                    .as_ref()
                    .ok_or("common runtime")?
                    .sealed
                    .is_none()
            );
            assert!(
                endpoint
                    .driver
                    .common_state()?
                    .engine(epoch)?
                    .pending_carrier_output()
                    .is_none()
            );
            // This is an injected post-write clock boundary around a real whole UDP
            // write, not a claim that the kernel blocked for the original lifetime.
            Ok(())
        })
}
