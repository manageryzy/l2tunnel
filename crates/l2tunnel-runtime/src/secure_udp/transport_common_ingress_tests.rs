//! Actual reserved Common ingress, original protected UDP and Unix packet-device bytes.
//! The shared fixture authenticates the complete current catalog before data service.
use super::*;
use l2tunnel_pipeline::ack_coalescing as ack;

fn policy() -> ack::Policy {
    ack::Policy {
        selection: ack::Selection::Benchmark,
        interval: Duration::from_millis(5),
        max_hold: Duration::from_millis(100),
        max_flows: 2,
        max_ack_bytes: 130,
    }
}
fn checksum(bytes: &[u8]) -> u16 {
    let sum = bytes.chunks_exact(2).fold(0u32, |sum, bytes| {
        sum + u32::from(u16::from_be_bytes([bytes[0], bytes[1]]))
    });
    let sum = (sum & 0xffff) + (sum >> 16);
    let sum = (sum & 0xffff) + (sum >> 16);
    !(sum as u16)
}
fn packet(number: u32) -> Vec<u8> {
    let mut bytes = vec![0; 54];
    bytes[..14].copy_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 8, 0]);
    let ip = &mut bytes[14..];
    ip[0] = 0x45;
    ip[2..4].copy_from_slice(&40u16.to_be_bytes());
    ip[6] = 0x40;
    ip[8] = 64;
    ip[9] = 6;
    ip[12..20].copy_from_slice(&[10, 0, 0, 1, 10, 0, 0, 2]);
    let value = checksum(&ip[..20]);
    ip[10..12].copy_from_slice(&value.to_be_bytes());
    let tcp = &mut ip[20..];
    tcp[..4].copy_from_slice(&[0x9c, 0x40, 1, 0xbb]);
    tcp[4..8].copy_from_slice(&123u32.to_be_bytes());
    tcp[8..12].copy_from_slice(&number.to_be_bytes());
    tcp[12] = 0x50;
    tcp[13] = 0x10;
    tcp[14..16].copy_from_slice(&4096u16.to_be_bytes());
    let mut pseudo = Vec::from([10, 0, 0, 1, 10, 0, 0, 2, 0, 6, 0, 20]);
    pseudo.extend_from_slice(tcp);
    let value = checksum(&pseudo);
    tcp[16..18].copy_from_slice(&value.to_be_bytes());
    bytes
}
fn selected_contracts(kind: cover::Appearance) -> Result<[CommonTransactionContract; 2]> {
    ingress_contracts(kind, false)
}
fn ingress_contracts(
    kind: cover::Appearance,
    tun_flow_limit: bool,
) -> Result<[CommonTransactionContract; 2]> {
    ingress_contracts_with(kind, tun_flow_limit, true)
}

/// Same contracts with ACK coalescing selected or left out of the resources.
fn ingress_contracts_with(
    kind: cover::Appearance,
    tun_flow_limit: bool,
    coalesce_acks: bool,
) -> Result<[CommonTransactionContract; 2]> {
    use l2tunnel::record_configuration as c;
    let old = contracts(kind)?;
    let descriptors = old[0]
        .catalog()
        .descriptors()
        .iter()
        .filter(|value| !tun_flow_limit || matches!(value.profile(), c::Profile::Swift { .. }))
        .map(|value| {
            let update = |role| -> Result<c::CommonDirection> {
                let current = value.direction(role).common();
                let mut pipeline = current.pipeline();
                let traffic = if tun_flow_limit {
                    pipeline.profile =
                        l2tunnel_pipeline::Profile::TunDrr(l2tunnel_pipeline::TunQosConfig {
                            base_quantum_bytes: 1024,
                            max_weight: 1,
                            per_flow: l2tunnel_pipeline::QueueLimits {
                                bytes: 1024,
                                packets: 4,
                            },
                        });
                    core::traffic::TrafficPolicy {
                        layer: core::traffic::NetworkLayer::Tun,
                        tcp: core::traffic::TcpControl::System,
                        qos: core::traffic::Qos::WeightedDeficit,
                    }
                } else {
                    pipeline.queue.packets = 2;
                    if let l2tunnel_pipeline::Profile::TunDrr(mut qos) = pipeline.profile {
                        qos.per_flow.packets = 2;
                        pipeline.profile = l2tunnel_pipeline::Profile::TunDrr(qos);
                    }
                    current.traffic()
                };
                Ok(c::CommonDirection::new(
                    traffic,
                    pipeline,
                    current.bytes_per_second(),
                    current.burst_bytes(),
                    current.native_window(),
                )?)
            };
            let mut profile = *value.profile();
            if tun_flow_limit && let c::Profile::Swift { forward, reverse } = &mut profile {
                forward.layer = records::Layer::Ip;
                reverse.layer = records::Layer::Ip;
            }
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(c::Descriptor::new(
                value.path_mtu(),
                value.duplex(),
                update(mg::Role::Client)?,
                update(mg::Role::Server)?,
                profile,
            )?)
        })
        .collect::<Result<Vec<_>>>()?;
    let initial = descriptors
        .iter()
        .copied()
        .find(|value| matches!(value.profile(), c::Profile::Swift { .. }))
        .ok_or("Swift initial missing")?;
    let catalog = Catalog::new(initial, &descriptors)?;
    let make = |value: &CommonTransactionContract| -> Result<CommonTransactionContract> {
        let mut resources = value.resources();
        resources.ack_coalescing = coalesce_acks.then(policy);
        Ok(CommonTransactionContract::new_compact_wire(
            value.expected_configuration(),
            value.role(),
            [resources; 2],
            value.cover(),
            value.ipv6(),
            value.envelope(),
            catalog.clone(),
            value.settings(),
            value.compact_wire(),
        )?)
    };
    Ok([make(&old[0])?, make(&old[1])?])
}
async fn read(fixture: &mut Fixture, input: &mut buffers::Inputs, bytes: &[u8]) -> Result<bool> {
    let endpoint = &mut fixture.endpoints[0];
    assert_eq!(endpoint.host.send(bytes)?, bytes.len());
    let mut ready = tokio::time::timeout(
        Duration::from_secs(1),
        endpoint.device.ready_mut(Interest::READABLE),
    )
    .await??;
    Ok(endpoint
        .driver
        .read_native(&mut ready, &mut input.native, || Ok(fixture.now))?)
}
async fn turn(fixture: &mut Fixture, inputs: &mut [buffers::Inputs; 2]) -> Result {
    for (endpoint, input) in fixture.endpoints.iter_mut().zip(inputs) {
        endpoint
            .driver
            .service_common_ingress(fixture.now, &mut input.native)?;
    }
    fixture.turn().await
}
#[test]
fn pending_decode_yields_to_original_ack_within_one_directional_grant() -> Result {
    use l2tunnel::fec::rolling as fec;
    use l2tunnel::record_engine as engine;
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(Box::pin(async {
            let kind = cover::Appearance::QuicLike;
            let values = super::rolling::values(kind, fec::wire::SourceWire::TargetedExact)?;
            let descriptors = values.map(|v| *v.descriptor());
            let grant = fec::WorkBudget {
                field: 1024,
                copies: 1024,
                metadata: 1024,
            };
            let base = contracts_with_catalog_and_work(
                kind,
                Catalog::new(descriptors[3], &descriptors)?,
                16,
                Some(grant),
            )?;
            let make = |old: &CommonTransactionContract| -> Result<CommonTransactionContract> {
                let mut resources = old.resources();
                resources.ack_coalescing = Some(ack::Policy {
                    max_hold: Duration::from_millis(20),
                    ..policy()
                });
                Ok(CommonTransactionContract::new_compact_wire(
                    old.expected_configuration(),
                    old.role(),
                    [resources; 2],
                    old.cover(),
                    old.ipv6(),
                    old.envelope(),
                    old.catalog().clone(),
                    old.settings(),
                    old.compact_wire(),
                )?)
            };
            for (guarded, expire, waiting_feedback) in [
                (false, true, false),
                (true, false, false),
                (true, true, false),
                (true, false, true),
            ] {
                let mut fixture =
                    Fixture::from_contracts(kind, [make(&base[0])?, make(&base[1])?]).await?;
                let mut input = fixture.endpoints[0].driver.take_inputs()?;
                assert!(read(&mut fixture, &mut input, &packet(100)).await?);
                for _ in 0..8 {
                    fixture.turn().await?;
                }
                assert!(read(&mut fixture, &mut input, &packet(101)).await?);
                let start = fixture.now;
                let due = start + 5000;
                let expires = start + 20000;
                let driver = &mut fixture.endpoints[0].driver;
                let epoch = driver.common_state()?.epoch();
                let pending_feedback = if waiting_feedback {
                    // Commit a distinct short equation and physically select
                    // its feedback. The carrier does not confirm this output.
                    let mut witnesses = driver
                        .common
                        .as_ref()
                        .ok_or("missing runtime")?
                        .witnesses
                        .clone();
                    let mut entry = driver.common_state_mut()?.entry(epoch)?;
                    let mut prior = [2, 1, 4, 0, 0, 0];
                    entry.accept_authenticated(
                        engine::Tick(start),
                        24,
                        engine::EmissionKind::Repair,
                        &mut prior,
                    )?;
                    let mut selected = None;
                    for turn in 1..=20 {
                        let t = engine::Tick(start + turn * 100);
                        entry.step(t, grant)?;
                        if let Some(output) = entry.poll(
                            t,
                            314,
                            false,
                            &mut [0; 1500],
                            &mut l2tunnel_reliable::OutboundBudget {
                                packets: 1,
                                wire_bytes: 1500,
                            },
                            &mut witnesses,
                        )? {
                            assert_eq!(output.kind, engine::EmissionKind::Feedback);
                            selected = entry.pending_carrier_output();
                            break;
                        }
                    }
                    Some(selected.ok_or("expected an actual unconfirmed feedback record")?)
                } else {
                    None
                };
                // A valid regular equation spanning eight missing sources. Its
                // initialization alone exceeds this test's first receive slice.
                let mut repair = vec![0; 1027];
                repair[..3].copy_from_slice(&[2, 2, 8]);
                let preceding = due - 1682;
                driver
                    .common_state_mut()?
                    .entry(epoch)?
                    .accept_authenticated(
                        engine::Tick(preceding),
                        25,
                        engine::EmissionKind::Repair,
                        &mut repair,
                    )?;
                assert!(driver.common_state()?.engine(epoch)?.has_targeted_decode());
                assert_eq!(
                    driver
                        .common_state()?
                        .engine(epoch)?
                        .targeted_decode_feedback_ready(),
                    Some(waiting_feedback)
                );
                if !guarded {
                    // The previous driver spent its entire direction grant before
                    // sampling the held ACK again, 34 us beyond its original cap.
                    driver
                        .common_state_mut()?
                        .entry(epoch)?
                        .step(engine::Tick(preceding), grant)?;
                    assert_eq!(
                        driver
                            .service_due_acks(expires + 34)
                            .err()
                            .ok_or("unsliced decode crossed the original ACK deadline")?
                            .to_string(),
                        "original held ACK ingress deadline"
                    );
                    continue;
                }
                let runtime = driver.common.as_ref().ok_or("missing runtime")?;
                let (before, turns) = (runtime.rolling_work_used, runtime.rolling_scheduler_steps);
                let mut ticks = [due - 1, if expire { expires } else { due }].into_iter();
                let result = if let Some(token) = pending_feedback {
                    let mut checkpoints = 0;
                    let last = driver.service_common_rolling_sampled(preceding, || {
                        checkpoints += 1;
                        Ok(due - 1)
                    })?;
                    assert!(checkpoints > 0);
                    assert_eq!(last, due - 1);
                    let entry = driver.common_state_mut()?.entry(epoch)?;
                    assert_eq!(entry.pending_carrier_output(), Some(token));
                    let owner = driver.common_state()?.engine(epoch)?;
                    assert_eq!(
                        owner
                            .ingress_snapshot()
                            .ok_or("held ACK")?
                            .usage
                            .held
                            .packets,
                        1
                    );
                    assert_eq!(owner.queue_usage().packets, 0);
                    driver.service_due_acks(due)?;
                    Ok(due)
                } else {
                    let result = driver.service_common_rolling_sampled(preceding, || {
                        ticks
                            .next()
                            .ok_or_else(|| io::Error::other("checked clock after ACK transfer"))
                    });
                    assert_eq!(ticks.next(), None);
                    result
                };
                let engine = driver.common_state()?.engine(epoch)?;
                let ack = engine.ingress_snapshot().ok_or("ingress observation")?;
                if expire {
                    assert_eq!(
                        result
                            .err()
                            .ok_or("late decoder checkpoint accepted an expired ACK")?
                            .to_string(),
                        "original held ACK ingress deadline"
                    );
                    assert_eq!(ack.usage.held.packets, 1);
                    assert_eq!(ack.expiry, Some(engine::Tick(expires)));
                    let (held, service, last_completed) = engine
                        .earliest_held_ack_service()
                        .ok_or("missing expired candidate")?;
                    assert_eq!(held.deadline, Duration::from_micros(due));
                    assert_eq!(
                        service.first_due_service,
                        Some(Duration::from_micros(expires))
                    );
                    assert_eq!(service.blocked, 0);
                    assert_eq!(service.last_blocked, None);
                    assert!(last_completed.is_none_or(|at| at < held.deadline));
                } else {
                    assert_eq!(result?, due);
                    assert_eq!(ack.statistics.flushed, 1);
                    assert_eq!(ack.usage.held.packets, 0);
                    assert_eq!(engine.queue_usage().packets, 1);
                    let r = driver.common.as_ref().ok_or("missing runtime")?;
                    let used =
                        std::array::from_fn::<_, 3, _>(|i| r.rolling_work_used[i] - before[i]);
                    assert_eq!(r.rolling_scheduler_steps, turns + 2);
                    let (_, retained) = r.rolling_sender_grant.ok_or("original sender reserve")?;
                    let sender_spent = [
                        grant.field - retained.field,
                        grant.copies - retained.copies,
                        grant.metadata - retained.metadata,
                    ];
                    assert!(used[1] > sender_spent[1] as u64 + 128);
                    for (combined, sent) in used.into_iter().zip(sender_spent) {
                        assert!(combined >= sent as u64 && combined - sent as u64 <= 1024);
                    }
                }
            }
            Ok(())
        }))
}

#[test]
fn protocol_stage_boundaries_service_original_ack_or_expire_it() -> Result {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(async {
            for expire in [false, true] {
                let kind = cover::Appearance::QuicLike;
                let mut fixture = Fixture::from_contracts(kind, selected_contracts(kind)?).await?;
                let mut input = fixture.endpoints[0].driver.take_inputs()?;
                assert!(read(&mut fixture, &mut input, &packet(100)).await?);
                for _ in 0..8 {
                    fixture.turn().await?;
                }
                assert!(read(&mut fixture, &mut input, &packet(101)).await?);
                let driver = &mut fixture.endpoints[0].driver;
                let epoch = driver.common_state()?.epoch();
                let start = fixture.now;
                let due = start + u64::try_from(policy().interval.as_micros())?;
                let limit = start + u64::try_from(policy().max_hold.as_micros())?;
                let mut timing = crate::initialization_timing::Timing::disabled();
                // The clock crosses the deadline after native collection. No further
                // read is allowed after a successful transfer to the record owner.
                let mut ticks = [start, due - 1, if expire { limit } else { due }].into_iter();
                let result = driver.service_common_protocol_stages(
                    start,
                    &mut input.native,
                    &mut timing,
                    || {
                        ticks
                            .next()
                            .ok_or_else(|| io::Error::other("clock read with no held ACK"))
                    },
                );
                assert_eq!(ticks.next(), None);
                if expire {
                    let error = result.err().ok_or("missed original ACK expiry")?;
                    assert_eq!(error.kind(), io::ErrorKind::TimedOut);
                    assert_eq!(error.to_string(), "original held ACK ingress deadline");
                    assert!(!driver.common_state()?.engine(epoch)?.ingress_empty());
                } else {
                    assert_eq!(result?, due);
                    assert!(driver.common_state()?.engine(epoch)?.ingress_empty());
                    assert_eq!(
                        driver.service_common_protocol_stages(
                            due,
                            &mut input.native,
                            &mut timing,
                            || { Err(io::Error::other("idle path sampled the held ACK clock")) }
                        )?,
                        due
                    );
                }
            }
            Ok(())
        })
}

#[test]
fn physical_device_write_services_opposite_ack_when_it_becomes_due() -> Result {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(async {
            let kind = cover::Appearance::QuicLike;
            let mut fixture = Fixture::from_contracts(kind, selected_contracts(kind)?).await?;
            let mut input = fixture.endpoints[0].driver.take_inputs()?;
            assert!(read(&mut fixture, &mut input, &packet(100)).await?);
            let payload = frame(40_101, 17);
            fixture.admit(1, &payload).await?;
            for _ in 0..32 {
                fixture.turn_with_held_native(Some(0)).await?;
                if !fixture.endpoints[0].driver.native.is_empty() {
                    break;
                }
            }
            assert!(!fixture.endpoints[0].driver.native.is_empty());
            assert!(read(&mut fixture, &mut input, &packet(101)).await?);
            let start = fixture.now;
            let due = start + u64::try_from(policy().interval.as_micros())?;
            let endpoint = &mut fixture.endpoints[0];
            let epoch = endpoint.driver.common_state()?.epoch();
            assert!(
                !endpoint
                    .driver
                    .common_state()?
                    .engine(epoch)?
                    .ingress_empty()
            );
            let before = endpoint.driver.counters.native_written;
            let mut ticks = [start, due].into_iter();
            let mut ready = tokio::time::timeout(
                Duration::from_secs(1),
                endpoint.device.ready_mut(Interest::WRITABLE),
            )
            .await??;
            assert_eq!(
                endpoint.driver.write_native_batch(&mut ready, 1, || {
                    ticks
                        .next()
                        .ok_or_else(|| io::Error::other("unexpected device clock read"))
                })?,
                1
            );
            assert_eq!(ticks.next(), None);
            assert_eq!(endpoint.driver.counters.native_written, before + 1);
            assert!(
                endpoint
                    .driver
                    .common_state()?
                    .engine(epoch)?
                    .ingress_empty()
            );
            let mut delivered = [0; 513];
            let len = endpoint.host.recv(&mut delivered)?;
            assert_eq!(&delivered[..len], payload.as_slice());
            Ok(())
        })
}

#[test]
fn busy_carrier_progress_flushes_due_ack_before_next_outer_turn() -> Result {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(async {
            let kind = cover::Appearance::QuicLike;
            let mut fixture = Fixture::from_contracts(kind, selected_contracts(kind)?).await?;
            let mut input = fixture.endpoints[0].driver.take_inputs()?;
            assert!(read(&mut fixture, &mut input, &packet(100)).await?);
            // Free the single downstream slot before holding a later cumulative ACK.
            for _ in 0..8 {
                fixture.turn().await?;
            }
            assert!(read(&mut fixture, &mut input, &packet(101)).await?);
            let driver = &mut fixture.endpoints[0].driver;
            let epoch = driver.common_state()?.epoch();
            let due = fixture.now + u64::try_from(policy().interval.as_micros())?;
            assert_eq!(
                driver.common.as_ref().and_then(|r| r.next_ack_service),
                Some(due)
            );
            driver.progress_common(due - 1)?;
            assert!(!driver.common_state()?.engine(epoch)?.ingress_empty());
            driver.progress_common(due)?;
            assert!(driver.common_state()?.engine(epoch)?.ingress_empty());
            assert_eq!(
                driver.common.as_ref().and_then(|r| r.next_ack_service),
                None
            );
            Ok(())
        })
}

#[test]
fn sending_reopens_a_capacity_blocked_native_read_before_select() -> Result {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(async {
            let kind = cover::Appearance::QuicLike;
            let mut fixture = Fixture::from_contracts(kind, selected_contracts(kind)?).await?;
            let mut inputs = fixture.endpoints[0].driver.take_inputs()?;
            assert!(read(&mut fixture, &mut inputs, &packet(100)).await?);
            assert!(read(&mut fixture, &mut inputs, &packet(101)).await?);
            assert!(!read(&mut fixture, &mut inputs, &packet(101)).await?);
            let now = fixture.now;
            let [sender, _peer] = fixture.endpoints;
            let mut driver = sender.driver;
            let mut socket = carrier::IoOwner::from(sender.socket);
            let at = driver.origin + duration(now);
            let before = driver.counters.native_read;
            assert_eq!(
                driver
                    .performance
                    .counters
                    .native_ingress_shared_packet_refusals,
                1
            );
            assert_eq!(
                driver
                    .performance
                    .counters
                    .native_ingress_flow_packet_refusals,
                0
            );
            assert!(!driver.can_admit_native()?);
            driver.send_and_retry_native_ingress(&mut socket, &inputs.native, now, at, || at)?;
            assert!(driver.can_admit_native()?);
            assert_eq!(driver.counters.native_read, before + 1);
            driver.send_and_retry_native_ingress(&mut socket, &inputs.native, now, at, || at)?;
            assert_eq!(driver.counters.native_read, before + 1);
            Ok(())
        })
}

#[tokio::test]
async fn retained_tcp_data_retries_only_after_flow_bytes_are_available() -> Result {
    let kind = cover::Appearance::QuicLike;
    let mut fixture = Fixture::from_contracts(kind, ingress_contracts(kind, true)?).await?;
    let mut input = fixture.endpoints[0].driver.take_inputs()?;
    let mut bytes = packet(100)[14..].to_vec();
    bytes.resize(600, 7);
    bytes[2..4].copy_from_slice(&600_u16.to_be_bytes());
    assert!(read(&mut fixture, &mut input, &bytes).await?);
    assert!(!read(&mut fixture, &mut input, &bytes).await?);
    let now = fixture.now;
    let [endpoint, _peer] = fixture.endpoints;
    let mut driver = endpoint.driver;
    let before = driver.counters.native_read;
    let pending = driver
        .common
        .as_ref()
        .and_then(|r| r.pending_ingress)
        .ok_or("missing input")?;
    assert!(pending.flow_byte_wait.is_some());
    for _ in 0..4 {
        driver.service_common_ingress(now, &mut input.native)?;
    }
    assert_eq!(
        driver
            .performance
            .counters
            .native_ingress_flow_byte_refusals,
        1
    );
    assert_eq!(
        driver.common.as_ref().and_then(|r| r.pending_ingress),
        Some(pending)
    );
    let mut socket = carrier::IoOwner::from(endpoint.socket);
    let at = driver.origin + duration(now);
    driver.send_and_retry_native_ingress(&mut socket, &input.native, now, at, || at)?;
    assert_eq!(driver.counters.native_read, before + 1);
    assert!(driver.can_admit_native()?);
    Ok(())
}

#[tokio::test]
async fn plain_pipeline_flow_byte_refusal_is_retained_backpressure_not_a_session_failure() -> Result
{
    // Without ACK coalescing the Pipeline refuses directly; a full per-flow
    // queue under loss previously stopped the whole session as a protocol error.
    let kind = cover::Appearance::QuicLike;
    let contracts = ingress_contracts_with(kind, true, false)?;
    let mut fixture = Fixture::from_contracts(kind, contracts).await?;
    let mut input = fixture.endpoints[0].driver.take_inputs()?;
    let mut bytes = packet(100)[14..].to_vec();
    bytes.resize(600, 7);
    bytes[2..4].copy_from_slice(&600_u16.to_be_bytes());
    assert!(read(&mut fixture, &mut input, &bytes).await?);
    assert!(!read(&mut fixture, &mut input, &bytes).await?);
    let now = fixture.now;
    let [endpoint, _peer] = fixture.endpoints;
    let mut driver = endpoint.driver;
    assert!(driver.terminal.is_none());
    let before = driver.counters.native_read;
    let pending = driver
        .common
        .as_ref()
        .and_then(|r| r.pending_ingress)
        .ok_or("refused original must stay retained")?;
    assert!(pending.flow_byte_wait.is_some());
    assert_eq!(
        driver
            .performance
            .counters
            .native_ingress_flow_byte_refusals,
        1
    );
    let mut socket = carrier::IoOwner::from(endpoint.socket);
    let at = driver.origin + duration(now);
    driver.send_and_retry_native_ingress(&mut socket, &input.native, now, at, || at)?;
    assert_eq!(driver.counters.native_read, before + 1);
    assert!(driver.can_admit_native()?);
    Ok(())
}

#[test]
fn real_benchmark_ingress_retains_refused_duplicate_and_drains_before_negotiated_switch() -> Result
{
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(async {
            let kind = cover::Appearance::QuicLike;
            let contracts = selected_contracts(kind)?;
            let packed = contracts[0]
                .catalog()
                .configurations(contracts[0].envelope())?
                .into_iter()
                .find(|value| {
                    matches!(
                        value.descriptor().profile(),
                        l2tunnel::record_configuration::Profile::Packed { .. }
                    )
                })
                .ok_or("Packed target missing")?;
            let mut fixture = Fixture::from_contracts(kind, contracts).await?;
            let mut inputs = [
                fixture.endpoints[0].driver.take_inputs()?,
                fixture.endpoints[1].driver.take_inputs()?,
            ];
            let first = packet(100);
            let advancing = packet(101);
            let duplicate = packet(101);
            assert!(read(&mut fixture, &mut inputs[0], &first).await?);
            assert!(read(&mut fixture, &mut inputs[0], &advancing).await?);
            let epoch = fixture.endpoints[0].driver.common_state()?.epoch();
            assert!(
                !fixture.endpoints[0]
                    .driver
                    .common_state()?
                    .engine(epoch)?
                    .drained()?
            );
            assert!(!read(&mut fixture, &mut inputs[0], &duplicate).await?);
            let pending = fixture.endpoints[0]
                .driver
                .common
                .as_ref()
                .ok_or("Common missing")?
                .pending_ingress
                .ok_or("actual retained read missing")?;
            assert_eq!(&inputs[0].native[..pending.bytes], duplicate);
            assert_eq!(pending.received, fixture.now);
            assert!(!fixture.endpoints[0].driver.can_admit_native()?);
            let status = fixture.endpoints[0]
                .driver
                .snapshot_common(fixture.now, true)?;
            assert_eq!(status.pending_ingress_bytes, Some(duplicate.len()));
            let actual = status.ack_ingress.ok_or("actual ACK owner missing")?;
            assert_eq!(
                (actual.usage.allocations, actual.statistics.flushed),
                (2, 1)
            );
            assert_eq!(actual.statistics.duplicates, 0);
            assert!(
                fixture.endpoints[0]
                    .driver
                    .common_state_mut()?
                    .entry(epoch)?
                    .enqueue_borrowed(l2tunnel::record_engine::Tick(fixture.now), &first)
                    .is_err()
            );
            let before = fixture.endpoints[0].driver.common_state()?.usage();
            let (sender, mut result) = oneshot::channel();
            fixture.endpoints[0]
                .driver
                .request_common(fixture.now, packed, sender)?;
            let mut answer = None;
            let mut received = Vec::new();
            let mut settled = false;
            for _ in 0..1000 {
                turn(&mut fixture, &mut inputs).await?;
                let mut output = [0; 1025];
                for _ in 0..8 {
                    match fixture.endpoints[1].host.recv(&mut output) {
                        Ok(size) => received.push(output[..size].to_vec()),
                        Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                        Err(error) => return Err(error.into()),
                    }
                }
                if answer.is_none() {
                    match result.try_recv() {
                        Ok(value) => {
                            answer = Some(value.map_err(|error| {
                                io::Error::other(format!("actual switch: {error:?}"))
                            })?)
                        }
                        Err(oneshot::error::TryRecvError::Empty) => {}
                        Err(error) => return Err(error.into()),
                    }
                }
                if answer.is_some()
                    && fixture.endpoints.iter().all(|endpoint| {
                        endpoint.driver.common_state().is_ok_and(|state| {
                            state.peer().operation().is_none() && state.can_admit_data()
                        })
                    })
                {
                    settled = true;
                    break;
                }
            }
            assert!(
                settled,
                "actual ACK custody did not settle negotiated switch"
            );
            assert_eq!(answer, Some(core::Epoch(epoch.0 + 1)));
            assert_eq!(received, vec![first, advancing, duplicate]);
            assert!(
                fixture.endpoints[0]
                    .driver
                    .common
                    .as_ref()
                    .ok_or("Common missing")?
                    .pending_ingress
                    .is_none()
            );
            let state = fixture.endpoints[0].driver.common_state()?;
            let installed = state
                .engine(state.epoch())?
                .ingress_snapshot()
                .ok_or("new generation ACK owner missing")?;
            assert_eq!(installed.policy, policy());
            assert_eq!(installed.statistics.received, 0);
            assert!(state.usage().peak_bytes >= before.capacity_bytes);
            for _ in 0..50 {
                turn(&mut fixture, &mut inputs).await?;
            }
            assert!(
                fixture.endpoints.iter().all(|endpoint| endpoint
                    .driver
                    .live
                    .last_pong_micros
                    .is_some())
            );
            Ok(())
        })
}
