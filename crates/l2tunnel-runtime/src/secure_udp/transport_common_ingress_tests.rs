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
    use l2tunnel::record_configuration as c;
    let old = contracts(kind)?;
    let descriptors = old[0]
        .catalog()
        .descriptors()
        .iter()
        .map(|value| {
            let update = |role| -> Result<c::CommonDirection> {
                let current = value.direction(role).common();
                let mut pipeline = current.pipeline();
                pipeline.queue.packets = 2;
                if let l2tunnel_pipeline::Profile::TunDrr(mut qos) = pipeline.profile {
                    qos.per_flow.packets = 2;
                    pipeline.profile = l2tunnel_pipeline::Profile::TunDrr(qos);
                }
                Ok(c::CommonDirection::new(
                    current.traffic(),
                    pipeline,
                    current.bytes_per_second(),
                    current.burst_bytes(),
                    current.native_window(),
                )?)
            };
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(c::Descriptor::new(
                value.path_mtu(),
                value.duplex(),
                update(mg::Role::Client)?,
                update(mg::Role::Server)?,
                *value.profile(),
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
        resources.ack_coalescing = Some(policy());
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
