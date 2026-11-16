//! Actual protected UDP Research consumption. The imported secure test Parts are
//! real; this fixture does not claim a new catalog-bound initial handshake.
use super::*;
use l2tunnel::{fec::research, research_records};

fn policies() -> [research::Profile; 3] {
    [
        research::Profile::Recursive {
            taps: 1,
            width: 1,
            reset: 1,
            fresh_interval: 0,
        },
        research::Profile::Recursive {
            taps: 1,
            width: 1,
            reset: 1,
            fresh_interval: 2,
        },
        research::Profile::Accumulator {
            lanes: 3,
            window: 16,
        },
    ]
}
fn selected_research(
    policy: research::Profile,
) -> Result<([CommonTransactionContract; 2], [C; 2])> {
    let kind = cover::Appearance::QuicLike;
    let original = values(kind, rolling::wire::SourceWire::Exact)?;
    let c::Profile::Rolling { config, stream } = *original[3].descriptor().profile() else {
        return Err("actual rolling composition absent".into());
    };
    let direction = |d: rolling_records::DirectionConfig| research_records::DirectionConfig {
        native_policy: d.native_policy,
        receiver: d.receiver,
        packing: d.packing,
        codec_stage_micros: d.codec_stage_micros,
        scheduler: research::Config {
            recovery: d.scheduler.recovery,
            profile: policy,
            feedback_ticks: 100,
            memory_bytes: 16 << 20,
        },
    };
    let descriptor = original[3].descriptor();
    let research = c::Descriptor::new(
        descriptor.path_mtu(),
        descriptor.duplex(),
        *descriptor.direction(mg::Role::Client).common(),
        *descriptor.direction(mg::Role::Server).common(),
        c::Profile::Research {
            config: research_records::Config {
                forward: direction(config.forward),
                reverse: direction(config.reverse),
                geometry: config.geometry,
                native_stall_micros: config.native_stall_micros,
            },
            stream,
        },
    )?;
    let catalog = Catalog::new(research, &[*original[0].descriptor(), research])?;
    let configurations = [original[0], C::new(original[0].envelope(), research)?];
    Ok((
        contracts_with_catalog_and_options(
            kind,
            catalog,
            16,
            Some(work()),
            Some(rolling_records::IngressLimits {
                slots: 16,
                capacity_bytes: 1 << 20,
            }),
        )?,
        configurations,
    ))
}
fn variable_frame(marker: u8, length: usize) -> Result<Vec<u8>> {
    let mut bytes = frame(40_000 + u16::from(marker), marker);
    bytes.resize(length, marker);
    bytes[16..18].copy_from_slice(&u16::try_from(length - 14)?.to_be_bytes());
    bytes[38..40].copy_from_slice(&u16::try_from(length - 34)?.to_be_bytes());
    bytes[24..26].fill(0);
    let sum: u32 = bytes[14..34]
        .chunks_exact(2)
        .map(|v| u32::from(u16::from_be_bytes([v[0], v[1]])))
        .sum();
    let sum = (sum & 0xffff) + (sum >> 16);
    let sum = (sum & 0xffff) + (sum >> 16);
    bytes[24..26].copy_from_slice(&(!(sum as u16)).to_be_bytes());
    Ok(bytes)
}
#[derive(Default)]
struct Impairment {
    lost_source: [bool; 2],
    lost_feedback: [bool; 2],
    repairs: [usize; 2],
    fallback: [bool; 2],
    delayed: Option<Vec<u8>>,
    reordered: bool,
}
fn receive_wire(target: &mut Endpoint, now: u64, wire: &[u8]) -> Result {
    let before = target.driver.counters;
    target
        .driver
        .receive_selected(wire, now, target.driver.origin + duration(now), None)?;
    assert_eq!(
        target.driver.counters.received_packets,
        before.received_packets + 1
    );
    assert_eq!(
        target.driver.counters.rejected_packets,
        before.rejected_packets
    );
    assert_eq!(
        target.driver.counters.replay_rejections,
        before.replay_rejections
    );
    Ok(())
}
async fn impaired_turn(
    fixture: &mut Fixture,
    impairment: &mut Impairment,
    hold_native: bool,
) -> Result {
    fixture.now = fixture.now.checked_add(1000).ok_or("fixture time")?;
    let now = fixture.now;
    for side in 0..2 {
        let mut controls = 0;
        let mut user = None;
        {
            let endpoint = &mut fixture.endpoints[side];
            assert!(endpoint.driver.check_expiry(now)?);
            endpoint.driver.admit_common(|| Ok(duration(now)))?;
            endpoint.driver.collect_native(now)?;
            endpoint.driver.progress_common(now)?;
            endpoint.driver.service_common_rolling(now)?;
            endpoint.driver.service_selected_control(now, None)?;
            endpoint.driver.submit_control(now)?;
            for _ in 0..endpoint.driver.config.work.send_batch {
                let Some(bytes) = endpoint.driver.prepare_control(now)? else {
                    break;
                };
                endpoint
                    .driver
                    .handed(&endpoint.socket, bytes, performance::WireKind::Control)?;
                controls += 1;
            }
            // Select and retain the real sealed output before inspecting its
            // typed token; neither a parser nor a copied label is authority.
            assert!(!endpoint.driver.send_common_user_with(now, |_| {
                Err(io::Error::from(io::ErrorKind::WouldBlock))
            })?);
            if let Some(pending) = endpoint
                .driver
                .common
                .as_ref()
                .and_then(|v| v.sealed.as_ref())
            {
                let emission = pending
                    .carrier
                    .as_ref()
                    .ok_or("actual Research output")?
                    .emission();
                user = Some(emission.kind);
                if emission.kind == engine::EmissionKind::Repair {
                    let configuration = endpoint.driver.common_state()?.current();
                    let c::DirectionProfile::Research { config, .. } = configuration
                        .descriptor()
                        .local(common_contract::mg_role(endpoint.driver.info.role))
                        .send()
                        .profile()
                    else {
                        return Err("actual Research send policy".into());
                    };
                    let research::wire::View::Repair(repair) = research::wire::inspect(
                        config.scheduler,
                        &endpoint.driver.buffers.frame[..emission.bytes],
                    )?
                    else {
                        return Err("actual immutable repair body".into());
                    };
                    impairment.fallback[side] |= config
                        .scheduler
                        .profile
                        .mode(u32::try_from(repair.equation.id.0)?)?
                        == research::RepairMode::Fallback;
                }
                assert!(
                    endpoint
                        .driver
                        .flush_common_wire_with(now, |wire| endpoint.socket.try_send(wire))?
                );
            }
        }
        let target = &mut fixture.endpoints[1 - side];
        for _ in 0..controls {
            let mut wire = [0; 1501];
            let bytes = tokio::time::timeout(Duration::from_secs(1), target.socket.recv(&mut wire))
                .await??;
            receive_wire(target, now, &wire[..bytes])?;
        }
        if let Some(kind) = user {
            let mut wire = [0; 1501];
            let bytes = tokio::time::timeout(Duration::from_secs(1), target.socket.recv(&mut wire))
                .await??;
            let wire = &wire[..bytes];
            match kind {
                engine::EmissionKind::Source(_) if !impairment.lost_source[side] => {
                    // Physical whole-write completion already consumed the exact
                    // carrier token before this real socket packet is discarded.
                    impairment.lost_source[side] = true;
                }
                engine::EmissionKind::Feedback if !impairment.lost_feedback[side] => {
                    impairment.lost_feedback[side] = true;
                }
                engine::EmissionKind::Source(_) if side == 0 && !impairment.reordered => {
                    if let Some(held) = impairment.delayed.take() {
                        receive_wire(target, now, wire)?;
                        // This packet had not been authenticated/opened. Its
                        // observed runtime arrival is this later receive boundary.
                        receive_wire(target, now, &held)?;
                        impairment.reordered = true;
                    } else {
                        impairment.delayed = Some(wire.to_vec());
                    }
                }
                _ => {
                    if kind == engine::EmissionKind::Repair {
                        impairment.repairs[side] += 1;
                    }
                    receive_wire(target, now, wire)?;
                }
            }
        }
    }
    for endpoint in &mut fixture.endpoints {
        endpoint.driver.collect_native(now)?;
        if !hold_native {
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
        }
        endpoint.driver.progress_common(now)?;
        assert_eq!(
            (endpoint.socket.local_addr()?, endpoint.socket.peer_addr()?),
            endpoint.original
        );
    }
    Ok(())
}
#[test]
fn actual_research_udp_three_policies_recover_loss_reorder_native_pressure_and_switch() -> Result {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(async {
            for policy in policies() {
                let (contracts, values) = selected_research(policy)?;
                let mut fixture =
                    Fixture::from_contracts(cover::Appearance::QuicLike, contracts).await?;
                let originals = fixture.endpoints.each_ref().map(|v| v.original);
                let initial_epoch = fixture.endpoints[0].driver.common_state()?.epoch();
                let expected = [
                    vec![
                        variable_frame(42, 1024)?,
                        variable_frame(43, 975)?,
                        variable_frame(46, 513)?,
                    ],
                    vec![
                        variable_frame(44, 997)?,
                        variable_frame(45, 1024)?,
                        variable_frame(47, 589)?,
                    ],
                ];
                for side in 0..2 {
                    for packet in &expected[1 - side] {
                        fixture.admit(side, packet).await?;
                    }
                }
                let mut impairment = Impairment::default();
                let mut received: [Vec<Vec<u8>>; 2] = [Vec::new(), Vec::new()];
                let mut held_native = false;
                let mut complete = false;
                for turn in 0..1000 {
                    impaired_turn(&mut fixture, &mut impairment, turn < 50).await?;
                    if turn < 50 {
                        held_native |= fixture
                            .endpoints
                            .iter()
                            .any(|v| !v.driver.native.is_empty());
                        assert!(
                            fixture
                                .endpoints
                                .iter()
                                .all(|v| v.driver.counters.native_written == 0)
                        );
                    }
                    for (side, received) in received.iter_mut().enumerate() {
                        for _ in 0..8 {
                            let mut packet = [0; 1024];
                            match fixture.endpoints[side].host.recv(&mut packet) {
                                Ok(bytes) => received.push(packet[..bytes].to_vec()),
                                Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                                Err(error) => return Err(error.into()),
                            }
                        }
                    }
                    if received.each_ref().map(Vec::len) == [3, 3]
                        && fixture.endpoints.iter().all(|v| {
                            v.driver.common_state().is_ok_and(|s| {
                                s.engine(s.epoch())
                                    .is_ok_and(|e| e.drained().unwrap_or(false))
                            })
                        })
                    {
                        complete = true;
                        break;
                    }
                }
                assert!(complete && held_native && impairment.reordered);
                assert_eq!(impairment.lost_source, [true; 2]);
                assert_eq!(impairment.lost_feedback, [true; 2]);
                assert!(impairment.repairs.into_iter().all(|v| v > 0));
                if matches!(
                    policy,
                    research::Profile::Recursive {
                        fresh_interval: 2,
                        ..
                    }
                ) {
                    assert_eq!(impairment.fallback, [true; 2]);
                }
                for side in 0..2 {
                    let mut expected = expected[side].clone();
                    expected.sort();
                    received[side].sort();
                    assert_eq!(received[side], expected);
                    let state = fixture.endpoints[side].driver.common_state()?;
                    let owner = state.engine(state.epoch())?;
                    let (sender, receiver) = owner
                        .research_status()
                        .ok_or("actual selected Research owner")?;
                    assert!(
                        sender.sent_repairs > 0
                            && sender.terminal.is_none()
                            && receiver.terminal.is_none()
                    );
                    assert_eq!(owner.native_counts()?.committed.iter().sum::<u64>(), 3);
                }
                fixture.switch(values[0]).await?;
                fixture.exchange_all_channels(100).await?;
                fixture.switch(values[1]).await?;
                fixture.exchange_all_channels(120).await?;
                for (side, endpoint) in fixture.endpoints.iter().enumerate() {
                    let status = endpoint.driver.snapshot_common(fixture.now, true)?;
                    assert_eq!(status.current, values[1]);
                    assert_eq!(status.epoch.0, initial_epoch.0 + 2);
                    assert_eq!(status.physical_scope.epoch.0, status.epoch.0);
                    assert!(
                        status.operation.is_none() && status.liveness.last_pong_micros.is_some()
                    );
                    assert!(status.rolling_work_used[1] > 0);
                    assert_eq!(
                        (endpoint.socket.local_addr()?, endpoint.socket.peer_addr()?),
                        originals[side]
                    );
                }
            }
            Ok(())
        })
}

#[test]
fn actual_research_udp_wouldblock_keeps_ciphertext_number_token_debit_and_original_cap() -> Result {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(async {
            let (contracts, _) = selected_research(policies()[2])?;
            let mut fixture =
                Fixture::from_contracts(cover::Appearance::QuicLike, contracts).await?;
            fixture.admit(0, &variable_frame(46, 1024)?).await?;
            let now = retain_first_source(&mut fixture)?;
            let endpoint = &mut fixture.endpoints[0];
            let runtime = endpoint.driver.common.as_ref().ok_or("Common owner")?;
            let pending = runtime
                .sealed
                .as_ref()
                .ok_or("actual sealed Research source")?;
            let token = pending.carrier.as_ref().ok_or("actual carrier token")?;
            let original = (
                pending.scope,
                pending.sealed,
                pending.cost,
                pending.deadline,
                token.emission(),
            );
            let wire = runtime.wire[..pending.sealed.bytes].to_vec();
            let number = endpoint.driver.records.next_number(Class::User);
            let debit = endpoint.driver.bucket.tokens;
            let accepted = endpoint.driver.counters.socket_accepted_packets;
            for _ in 0..3 {
                assert!(
                    !endpoint
                        .driver
                        .send_common_user_with(now, |_| Err(io::Error::from(
                            io::ErrorKind::WouldBlock
                        )))?
                );
                let runtime = endpoint.driver.common.as_ref().ok_or("retained owner")?;
                let pending = runtime.sealed.as_ref().ok_or("retained Research source")?;
                assert_eq!(
                    (
                        pending.scope,
                        pending.sealed,
                        pending.cost,
                        pending.deadline,
                        pending.carrier.as_ref().ok_or("retained token")?.emission()
                    ),
                    original
                );
                assert_eq!(&runtime.wire[..pending.sealed.bytes], wire);
                assert_eq!(endpoint.driver.records.next_number(Class::User), number);
                assert_eq!(endpoint.driver.bucket.tokens, debit);
                assert_eq!(endpoint.driver.counters.socket_accepted_packets, accepted);
            }
            assert!(now < original.3);
            // Whole acceptance is irreversible even at the original hard cap.
            assert!(
                endpoint
                    .driver
                    .send_common_user_sampled(
                        now,
                        |bytes| endpoint.socket.try_send(bytes),
                        || Ok(original.3)
                    )
                    .is_err()
            );
            assert_eq!(
                endpoint.driver.counters.socket_accepted_packets,
                accepted + 1
            );
            assert!(
                endpoint
                    .driver
                    .common
                    .as_ref()
                    .ok_or("owner")?
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
            assert_eq!(endpoint.driver.bucket.tokens, debit);
            Ok(())
        })
}
