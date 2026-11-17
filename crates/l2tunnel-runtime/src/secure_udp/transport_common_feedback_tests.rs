//! Real old-reader feedback after an authenticated switch to a smaller burst.
use super::*;
use l2tunnel::record_configuration as c;

type Counts = (Vec<u64>, Vec<u64>, Vec<u64>);

fn old_counts(fixture: &Fixture, epoch: core::Epoch) -> Result<[Counts; 2]> {
    let collect = |endpoint: &Endpoint| -> Result<Counts> {
        let counts = endpoint
            .driver
            .common_state()?
            .engine(epoch)?
            .native_counts()?;
        Ok((
            counts.admitted.to_vec(),
            counts.prepared.to_vec(),
            counts.committed.to_vec(),
        ))
    };
    Ok([
        collect(&fixture.endpoints[0])?,
        collect(&fixture.endpoints[1])?,
    ])
}

fn smaller_swift_contracts(
    kind: cover::Appearance,
) -> Result<([CommonTransactionContract; 2], C, usize)> {
    let original = contracts(kind)?;
    let old = original[0].initial();
    let descriptor = old.descriptor();
    let c::Profile::Swift {
        mut forward,
        mut reverse,
    } = *descriptor.profile()
    else {
        return Err("initial fixture must use Swift".into());
    };
    // A complete worst-case Swift feedback block still fits. This test does not
    // qualify the separately open sub-140-byte feedback/request-list problem.
    forward.codec.datagram_bytes = 160;
    reverse.codec.datagram_bytes = 160;
    let burst = 160 + original[0].geometry().forward_overhead_bytes + original[0].reserve()?;
    let direction = |role| -> Result<c::CommonDirection> {
        let old = descriptor.direction(role).common();
        Ok(c::CommonDirection::new(
            old.traffic(),
            old.pipeline(),
            old.bytes_per_second(),
            burst,
            old.native_window(),
        )?)
    };
    let small = c::Descriptor::new(
        descriptor.path_mtu(),
        descriptor.duplex(),
        direction(mg::Role::Client)?,
        direction(mg::Role::Server)?,
        c::Profile::Swift { forward, reverse },
    )?;
    let target = C::new(old.envelope(), small)?;
    let catalog = Catalog::new(*descriptor, &[*descriptor, small])?;
    Ok((contracts_with_catalog(kind, catalog, 16)?, target, burst))
}

async fn receive_one(endpoint: &mut Endpoint, now: u64) -> Result {
    let mut input = [0; 1501];
    let bytes =
        tokio::time::timeout(Duration::from_secs(1), endpoint.socket.recv(&mut input)).await??;
    let before = endpoint.driver.counters;
    endpoint.driver.receive_selected(
        &input[..bytes],
        now,
        endpoint.driver.origin + duration(now),
    )?;
    assert_eq!(
        endpoint.driver.counters.received_packets,
        before.received_packets + 1
    );
    assert_eq!(
        endpoint.driver.counters.rejected_packets,
        before.rejected_packets
    );
    assert_eq!(
        endpoint.driver.counters.replay_rejections,
        before.replay_rejections
    );
    assert_eq!(endpoint.driver.live.last_verified_micros, Some(now));
    Ok(())
}

#[test]
fn promoted_smaller_burst_keeps_real_old_reader_feedback_and_native_counts() -> Result {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(async {
            for kind in [cover::Appearance::QuicLike, cover::Appearance::MediaLike] {
                let (contracts, target, burst) = smaller_swift_contracts(kind)?;
                let mut fixture = Fixture::from_contracts(kind, contracts).await?;
                let old = fixture.endpoints[0].driver.source_scope;
                let epoch = core::Epoch(old.epoch.0);
                let target_epoch = core::Epoch(epoch.0.checked_add(1).ok_or("epoch overflow")?);
                let expected = [frame(41000, 111), frame(42000, 112)];
                let mut originals = Vec::new();
                for (side, packet) in expected.iter().enumerate() {
                    fixture.admit(side, packet).await?;
                    let endpoint = &mut fixture.endpoints[side];
                    endpoint.driver.progress_common(fixture.now)?;
                    let mut bytes = None;
                    assert!(endpoint.driver.send_common_user_with(fixture.now, |wire| {
                        let sent = endpoint.socket.try_send(wire)?;
                        bytes = Some(sent);
                        Ok(sent)
                    })?);
                    let wire = bytes.ok_or("actual original User was not handed to UDP")?;
                    let body_bytes = wire
                        .checked_add(endpoint.driver.ip)
                        .and_then(|n| n.checked_sub(endpoint.driver.config.control.wire_overhead))
                        .ok_or("original body geometry")?;
                    assert_eq!(
                        endpoint.driver.records.capacity(body_bytes)?.packet_bytes,
                        wire
                    );
                    let body = endpoint.driver.buffers.frame[..body_bytes].to_vec();
                    assert_eq!(body[0] & swift::KIND_MASK, swift::KIND_SOURCE);
                    originals.push((
                        body,
                        endpoint
                            .driver
                            .counters
                            .user_number
                            .ok_or("original PN absent")?,
                    ));
                }
                for endpoint in &mut fixture.endpoints {
                    receive_one(endpoint, fixture.now).await?;
                }
                let mut delivered: [Vec<Vec<u8>>; 2] = [Vec::new(), Vec::new()];
                let mut drained = false;
                for _ in 0..500 {
                    fixture.turn().await?;
                    for (side, packets) in delivered.iter_mut().enumerate() {
                        let mut output = [0; 1024];
                        match fixture.endpoints[side].host.recv(&mut output) {
                            Ok(bytes) => packets.push(output[..bytes].to_vec()),
                            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                            Err(error) => return Err(error.into()),
                        }
                    }
                    if fixture.endpoints.iter().all(|endpoint| {
                        endpoint.driver.common_state().is_ok_and(|state| {
                            state.engine(epoch).is_ok_and(|engine| {
                                engine.drained().unwrap_or(false)
                                    && engine.feedback_opportunity().is_ok_and(|at| at.is_none())
                            })
                        })
                    }) && delivered.iter().all(|packets| packets.len() == 1)
                    {
                        drained = true;
                        break;
                    }
                }
                assert!(
                    drained,
                    "real originals/native writes and feedback must finish before switching"
                );
                assert_eq!(delivered[0], vec![expected[1].clone()]);
                assert_eq!(delivered[1], vec![expected[0].clone()]);
                let counts = old_counts(&fixture, epoch)?;
                for (_, prepared, committed) in &counts {
                    assert_eq!(prepared, committed);
                    assert_eq!(committed.iter().sum::<u64>(), 1);
                }

                let (reply, mut answer) = oneshot::channel();
                fixture.endpoints[0]
                    .driver
                    .request_common(fixture.now, target, reply)?;
                let mut retained = None;
                for _ in 0..1500 {
                    fixture.turn().await?;
                    retained = fixture.endpoints.iter().position(|endpoint| {
                        endpoint.driver.source_scope.epoch.0 == target_epoch.0
                            && endpoint
                                .driver
                                .records
                                .additional_data()
                                .is_some_and(|r| r.scope == old)
                            && endpoint
                                .driver
                                .common_state()
                                .is_ok_and(|state| state.engine(epoch).is_ok())
                    });
                    if retained.is_some() {
                        break;
                    }
                }
                let receiver =
                    retained.ok_or("no physical promotion with original reader retained")?;
                let sender = 1 - receiver;
                assert_eq!(old_counts(&fixture, epoch)?, counts);
                let written = fixture
                    .endpoints
                    .each_ref()
                    .map(|e| e.driver.counters.native_written);
                {
                    let endpoint = &fixture.endpoints[receiver];
                    assert_eq!(endpoint.driver.bucket.burst, burst);
                    assert_eq!(endpoint.driver.source_scope.epoch.0, target_epoch.0);
                    assert!(endpoint.driver.common_state()?.engine(epoch)?.drained()?);
                    assert!(
                        endpoint
                            .driver
                            .common_state()?
                            .engine(epoch)?
                            .feedback_opportunity()?
                            .is_none()
                    );
                    // The old maximum is genuinely unaffordable under the selected
                    // exact new burst; it must never be requested just to send ACKs.
                    let old_max = if receiver == 0 { 256 } else { 320 };
                    assert!(
                        old_max
                            + endpoint.driver.config.control.wire_overhead
                            + endpoint.driver.reserve
                            > burst
                    );
                }
                {
                    let endpoint = &mut fixture.endpoints[sender];
                    let (body, original_number) = &originals[sender];
                    let next = endpoint.driver.records.next_number(Class::User);
                    assert!(next.0 > original_number.0);
                    let sealed = endpoint.driver.records.seal_user_in(
                        old,
                        meta(endpoint.driver.outer, cover::Phase::Established),
                        body,
                        &mut endpoint.driver.buffers.seal,
                        &mut endpoint.driver.buffers.wire,
                    )?;
                    assert_eq!(sealed.number, next);
                    // This is controlled late peer input: the real old source body,
                    // sealed once with the actual surviving security owner. The
                    // original socket handoff still incurs its actual wire debit.
                    let accepted = endpoint.driver.counters.socket_accepted_packets;
                    let before = endpoint.driver.bucket.tokens;
                    endpoint.driver.handed(
                        &endpoint.socket,
                        sealed.bytes,
                        performance::WireKind::Data,
                    )?;
                    assert_eq!(
                        endpoint.driver.counters.socket_accepted_packets,
                        accepted + 1
                    );
                    assert_eq!(
                        before - endpoint.driver.bucket.tokens,
                        (sealed.bytes + endpoint.driver.ip) as u128 * SCALE
                    );
                    assert_eq!(endpoint.driver.counters.socket_drops, 0);
                }
                receive_one(&mut fixture.endpoints[receiver], fixture.now).await?;
                {
                    let endpoint = &mut fixture.endpoints[receiver];
                    endpoint.driver.collect_common_native(fixture.now)?;
                    assert!(endpoint.driver.native.is_empty());
                    let engine = endpoint.driver.common_state()?.engine(epoch)?;
                    assert!(engine.drained()?);
                    let (at, bytes) = engine
                        .feedback_opportunity()?
                        .ok_or("fresh old duplicate owes feedback")?;
                    assert!(at.0 <= fixture.now);
                    assert_eq!(bytes, swift::FEEDBACK_HEADER);
                    endpoint.driver.wake_common(fixture.now)?;
                    let full_wire = bytes + endpoint.driver.config.control.wire_overhead;
                    let required = full_wire + endpoint.driver.reserve;
                    let original_cap = endpoint
                        .driver
                        .common_state()?
                        .operation_deadline()
                        .ok_or("promoted generation lost original operation cap")?;
                    // Management copies may have consumed the new bucket's
                    // remaining credit. Service the genuine feedback readiness,
                    // without enlarging the burst or assigning synthetic tokens.
                    let ready = endpoint
                        .driver
                        .bucket
                        .ready_at(required)?
                        .max(at.0)
                        .max(fixture.now);
                    assert!(duration(ready) < original_cap);
                    assert!(endpoint.driver.check_expiry(ready)?);
                    endpoint.driver.bucket.refill(ready)?;
                    fixture.now = ready;
                    assert!(endpoint.driver.bucket.allowance() >= required);
                    assert_eq!(
                        endpoint.driver.common_state()?.operation_deadline(),
                        Some(original_cap)
                    );
                    assert_eq!(endpoint.driver.bucket.burst, burst);
                    assert_eq!(
                        endpoint
                            .driver
                            .common_state()?
                            .engine(epoch)?
                            .feedback_opportunity()?,
                        Some((at, bytes))
                    );
                    let before = endpoint.driver.bucket.tokens;
                    let accepted = endpoint.driver.counters.socket_accepted_packets;
                    let feedback = endpoint.driver.performance.counters.feedback_packets;
                    let number = endpoint.driver.records.next_feedback_number();
                    let user_number = endpoint.driver.counters.user_number;
                    let next_user = endpoint.driver.records.next_number(Class::User);
                    assert!(
                        endpoint
                            .driver
                            .send_common_user(&endpoint.socket, fixture.now)?
                    );
                    assert_eq!(
                        endpoint
                            .driver
                            .snapshot_common(fixture.now, true)?
                            .compact_feedback_number,
                        Some(number)
                    );
                    assert_eq!(endpoint.driver.counters.user_number, user_number);
                    assert_eq!(endpoint.driver.records.next_number(Class::User), next_user);
                    assert_eq!(
                        endpoint.driver.buffers.frame[0] & swift::KIND_MASK,
                        swift::KIND_FEEDBACK
                    );
                    assert_eq!(
                        before - endpoint.driver.bucket.tokens,
                        full_wire as u128 * SCALE
                    );
                    assert_eq!(
                        endpoint.driver.counters.socket_accepted_packets,
                        accepted + 1
                    );
                    assert_eq!(
                        endpoint.driver.performance.counters.feedback_packets,
                        feedback + 1
                    );
                    assert_eq!(endpoint.driver.bucket.burst, burst);
                }
                receive_one(&mut fixture.endpoints[sender], fixture.now).await?;
                assert_eq!(old_counts(&fixture, epoch)?, counts);
                assert_eq!(
                    fixture
                        .endpoints
                        .each_ref()
                        .map(|e| e.driver.counters.native_written),
                    written
                );
                for endpoint in &fixture.endpoints {
                    let mut output = [0; 1024];
                    assert_eq!(
                        endpoint.host.recv(&mut output).err().map(|e| e.kind()),
                        Some(io::ErrorKind::WouldBlock)
                    );
                    assert_eq!(
                        (endpoint.socket.local_addr()?, endpoint.socket.peer_addr()?),
                        endpoint.original
                    );
                }
                let mut settled = false;
                for _ in 0..1000 {
                    fixture.turn().await?;
                    match answer.try_recv() {
                        Ok(value) => {
                            let actual = value.map_err(|error| {
                                io::Error::other(format!("actual switch result: {error:?}"))
                            })?;
                            assert_eq!(actual, target_epoch);
                            settled = true;
                            break;
                        }
                        Err(oneshot::error::TryRecvError::Empty) => {}
                        Err(error) => return Err(error.into()),
                    }
                }
                assert!(
                    settled,
                    "actual original-cap transaction must still complete"
                );
            }
            Ok(())
        })
}
