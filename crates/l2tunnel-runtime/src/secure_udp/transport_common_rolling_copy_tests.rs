//! Three actual protected UDP copies retain one recovery source and one native.
use super::*;
use codec::source_copy::{Policy, Scope as CopyScope};

fn selected_copies(kind: cover::Appearance) -> Result<([CommonTransactionContract; 2], [C; 4])> {
    let mut selected = values(kind, rolling::wire::SourceWire::Exact)?;
    let old = selected[3];
    let descriptor = old.descriptor();
    let c::Profile::Rolling { config, stream } = *descriptor.profile() else {
        return Err("actual rolling fixture absent".into());
    };
    let copies = rolling_records::CopyPolicies {
        forward: Policy {
            max_unit_bytes: config.forward.packing.packing.symbol_bytes,
            copies: 3,
            scope: CopyScope::AllShort,
        },
        reverse: Policy::ONE,
    };
    selected[3] = C::new(
        old.envelope(),
        c::Descriptor::new(
            descriptor.path_mtu(),
            descriptor.duplex(),
            *descriptor.direction(mg::Role::Client).common(),
            *descriptor.direction(mg::Role::Server).common(),
            c::Profile::RollingCopies {
                config,
                stream,
                copies,
            },
        )?,
    )?;
    let descriptors = selected.map(|value| *value.descriptor());
    let catalog = Catalog::new(descriptors[3], &descriptors)?;
    Ok((
        contracts_with_catalog_and_work(kind, catalog, 16, Some(work()))?,
        selected,
    ))
}

async fn receive_copy(endpoint: &mut Endpoint, now: u64, expected: &[u8]) -> Result {
    let mut input = [0; 1501];
    let bytes =
        tokio::time::timeout(Duration::from_secs(1), endpoint.socket.recv(&mut input)).await??;
    assert_eq!(&input[..bytes], expected);
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
    Ok(())
}

#[test]
fn actual_udp_rolling_three_copies_survive_first_loss_early_feedback_and_mode_switch() -> Result {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(async {
            for kind in [cover::Appearance::QuicLike, cover::Appearance::MediaLike] {
                let (contracts, values) = selected_copies(kind)?;
                let mut fixture = Fixture::from_contracts(kind, contracts).await?;
                let original = frame(40_000, 96);
                fixture.admit(0, &original).await?;
                let first_at = retain_first_source(&mut fixture)?;
                let epoch = fixture.endpoints[0].driver.common_state()?.epoch();
                let held = fixture.endpoints[0]
                    .driver
                    .common_state_mut()?
                    .entry(epoch)?
                    .pending_carrier_output()
                    .ok_or("actual first copy token")?;
                let (scope, first_sealed, cost, cap, first_plain, first_wire) = {
                    let endpoint = &fixture.endpoints[0];
                    let runtime = endpoint.driver.common.as_ref().ok_or("common runtime")?;
                    let pending = runtime.sealed.as_ref().ok_or("sealed first copy")?;
                    assert_eq!(pending.carrier.as_ref(), Some(&held));
                    let emission = held.emission();
                    assert!(matches!(emission.kind, engine::EmissionKind::Source(_)));
                    (
                        pending.scope,
                        pending.sealed,
                        pending.cost,
                        pending.deadline,
                        endpoint.driver.buffers.frame[..emission.bytes].to_vec(),
                        runtime.wire[..pending.sealed.bytes].to_vec(),
                    )
                };
                let c::Profile::RollingCopies { config, stream, .. } =
                    *values[3].descriptor().profile()
                else {
                    return Err("selected copy profile absent".into());
                };
                let context = held.context();
                let source_scope = rolling::Scope {
                    session: context.session.to_be_bytes(),
                    epoch: context.epoch,
                    stream,
                    direction: match context.role {
                        mg::Role::Client => 0,
                        mg::Role::Server => 1,
                    },
                };
                let rolling::wire::compact::View::Data(rolling::wire::View::Source {
                    id,
                    original: packed,
                    ..
                }) = rolling::wire::compact::inspect(
                    config.forward.scheduler.recovery,
                    source_scope,
                    &first_plain,
                )?
                else {
                    return Err("actual first source absent".into());
                };
                assert_eq!(id, rolling::SourceId(0));
                assert!(!packed.is_empty());
                assert!(first_at < cap);
                let initial = fixture.endpoints[0].driver.counters;
                let debit = fixture.endpoints[0].driver.bucket.tokens;
                let next = fixture.endpoints[0].driver.records.next_number(Class::User);
                for _ in 0..3 {
                    let endpoint = &mut fixture.endpoints[0];
                    assert!(!endpoint.driver.send_common_user_with(first_at, |_| Err(
                        io::Error::from(io::ErrorKind::WouldBlock)
                    ))?);
                    let runtime = endpoint.driver.common.as_ref().ok_or("common runtime")?;
                    let pending = runtime.sealed.as_ref().ok_or("retained first copy")?;
                    assert_eq!(pending.carrier.as_ref(), Some(&held));
                    assert_eq!(
                        (
                            pending.scope,
                            pending.sealed,
                            pending.cost,
                            pending.deadline
                        ),
                        (scope, first_sealed, cost, cap)
                    );
                    assert_eq!(&runtime.wire[..pending.sealed.bytes], first_wire);
                    assert_eq!(endpoint.driver.records.next_number(Class::User), next);
                    assert_eq!(endpoint.driver.bucket.tokens, debit);
                    assert_eq!(
                        endpoint.driver.counters.socket_accepted_packets,
                        initial.socket_accepted_packets
                    );
                }
                {
                    let endpoint = &mut fixture.endpoints[0];
                    assert!(endpoint.driver.flush_common_wire_with(first_at, |bytes| {
                        endpoint.socket.try_send(bytes)
                    })?);
                }
                // Actual UDP accepted the first whole copy. Discard it only after
                // receiving from the original peer socket: no peer receipt exists.
                let mut lost = [0; 1501];
                let bytes = tokio::time::timeout(
                    Duration::from_secs(1),
                    fixture.endpoints[1].socket.recv(&mut lost),
                )
                .await??;
                assert_eq!(&lost[..bytes], first_wire);
                assert_eq!(fixture.endpoints[1].driver.counters.native_written, 0);

                let mut numbers = vec![first_sealed.number];
                let mut wires = vec![first_wire];
                for ordinal in 2..=3 {
                    fixture.now = fixture.now.checked_add(100).ok_or("fixture time")?;
                    let now = fixture.now;
                    let endpoint = &mut fixture.endpoints[0];
                    endpoint.driver.progress_common(now)?;
                    let before_debit = endpoint.driver.bucket.tokens;
                    let before_packets = endpoint.driver.counters.wire_packets;
                    assert!(!endpoint.driver.send_common_user_with(now, |_| Err(
                        io::Error::from(io::ErrorKind::WouldBlock)
                    ))?);
                    let runtime = endpoint.driver.common.as_ref().ok_or("common runtime")?;
                    let pending = runtime.sealed.as_ref().ok_or("sealed subsequent copy")?;
                    let token = pending
                        .carrier
                        .as_ref()
                        .ok_or("subsequent physical copy token")?;
                    assert_eq!(token.generation(), held.generation());
                    assert_eq!(token.emission().kind, held.emission().kind);
                    assert_eq!(pending.scope, scope);
                    assert_eq!(pending.deadline, cap);
                    assert_eq!(pending.cost, cost);
                    assert_eq!(
                        &endpoint.driver.buffers.frame[..token.emission().bytes],
                        first_plain
                    );
                    assert_eq!(pending.sealed.number.0, first_sealed.number.0 + ordinal - 1);
                    assert_eq!(
                        endpoint.driver.bucket.tokens,
                        before_debit - cost as u128 * SCALE
                    );
                    assert_eq!(endpoint.driver.counters.wire_packets, before_packets + 1);
                    let wire = runtime.wire[..pending.sealed.bytes].to_vec();
                    assert!(wires.iter().all(|old| old != &wire));
                    numbers.push(pending.sealed.number);
                    assert!(
                        endpoint
                            .driver
                            .flush_common_wire_with(now, |bytes| endpoint.socket.try_send(bytes))?
                    );
                    receive_copy(&mut fixture.endpoints[1], now, &wire).await?;
                    wires.push(wire);

                    if ordinal == 2 {
                        // Service only the actual receiving owner, leaving copy3
                        // unsent. Real feedback must traverse the same protected
                        // UDP path while the sender still owns its source copies.
                        let mut returned = false;
                        for _ in 0..32 {
                            fixture.now = fixture.now.checked_add(100).ok_or("feedback time")?;
                            let now = fixture.now;
                            let endpoint = &mut fixture.endpoints[1];
                            endpoint.driver.progress_common(now)?;
                            endpoint.driver.service_common_rolling(now)?;
                            let mut sent_bytes = None;
                            let sent = endpoint.driver.send_common_user_with(now, |bytes| {
                                let length = endpoint.socket.try_send(bytes)?;
                                sent_bytes = Some(length);
                                Ok(length)
                            })?;
                            if sent {
                                let wire_length = sent_bytes.ok_or("actual feedback handoff")?;
                                let body_length = wire_length
                                    .checked_add(endpoint.driver.ip)
                                    .and_then(|length| {
                                        length.checked_sub(
                                            endpoint.driver.config.control.wire_overhead,
                                        )
                                    })
                                    .ok_or("actual feedback geometry")?;
                                assert_eq!(
                                    endpoint.driver.records.capacity_for(
                                        record::compact::Kind::Feedback,
                                        body_length,
                                    )?.packet_bytes,
                                    wire_length
                                );
                                let rolling::wire::compact::View::Feedback(feedback) =
                                    rolling::wire::compact::inspect(
                                        config.forward.scheduler.recovery,
                                        source_scope,
                                        &endpoint.driver.buffers.frame[..body_length],
                                    )?
                                else {
                                    return Err("actual compact feedback union absent".into());
                                };
                                assert_eq!(feedback.prefix, 1);
                                assert_eq!(feedback.observed_end, 1);
                                let mut wire = [0; 1501];
                                let bytes = tokio::time::timeout(
                                    Duration::from_secs(1),
                                    fixture.endpoints[0].socket.recv(&mut wire),
                                )
                                .await??;
                                let sender = &mut fixture.endpoints[0];
                                let before = sender.driver.counters;
                                sender.driver.receive_selected(
                                    &wire[..bytes],
                                    now,
                                    sender.driver.origin + duration(now),
                                )?;
                                assert_eq!(
                                    sender.driver.counters.received_packets,
                                    before.received_packets + 1
                                );
                                assert_eq!(
                                    sender.driver.counters.replay_rejections,
                                    before.replay_rejections
                                );
                                assert_eq!(
                                    sender.driver.counters.rejected_packets,
                                    before.rejected_packets
                                );
                                assert!(!sender.driver.common_state()?.engine(epoch)?.drained()?);
                                assert_eq!(
                                    sender.driver.counters.socket_accepted_packets,
                                    initial.socket_accepted_packets + 2
                                );
                                returned = true;
                                break;
                            }
                        }
                        assert!(returned, "actual early reverse feedback before final copy");
                    }
                }
                assert_eq!(numbers.len(), 3);
                assert_eq!(
                    fixture.endpoints[0].driver.counters.wire_packets,
                    initial.wire_packets + 2
                );
                assert_eq!(
                    fixture.endpoints[0].driver.counters.socket_accepted_packets,
                    initial.socket_accepted_packets + 3
                );
                assert_eq!(
                    fixture.endpoints[0]
                        .driver
                        .counters
                        .socket_accepted_ip_bytes,
                    initial.socket_accepted_ip_bytes + 3 * cost as u64
                );

                let mut native = Vec::new();
                let mut drained = false;
                for _ in 0..500 {
                    fixture.turn().await?;
                    let mut packet = [0; 1024];
                    for _ in 0..16 {
                        match fixture.endpoints[1].host.recv(&mut packet) {
                            Ok(bytes) => native.push(packet[..bytes].to_vec()),
                            Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                            Err(error) => return Err(error.into()),
                        }
                    }
                    if native.len() == 1
                        && fixture.endpoints.iter().all(|endpoint| {
                            endpoint.driver.common_state().is_ok_and(|state| {
                                state
                                    .engine(epoch)
                                    .is_ok_and(|e| e.drained().unwrap_or(false))
                            })
                        })
                    {
                        drained = true;
                        break;
                    }
                }
                assert!(drained, "actual repeated source/native debt must drain");
                assert_eq!(native, vec![original]);
                assert_eq!(fixture.endpoints[1].driver.counters.native_written, 1);
                let counts = fixture.endpoints[1]
                    .driver
                    .common_state()?
                    .engine(epoch)?
                    .native_counts()?;
                assert_eq!(counts.prepared.iter().sum::<u64>(), 1);
                assert_eq!(counts.committed.iter().sum::<u64>(), 1);
                assert_eq!(counts.prepared, counts.committed);
                assert_eq!(
                    fixture.endpoints[0]
                        .driver
                        .common_state()?
                        .engine(epoch)?
                        .statistics()
                        .admitted,
                    1
                );
                let before = fixture
                    .endpoints
                    .each_ref()
                    .map(|endpoint| endpoint.driver.records.next_number(Class::Control).0);
                fixture.switch(values[0]).await?;
                fixture.exchange_all_channels(97).await?;
                for (side, endpoint) in fixture.endpoints.iter().enumerate() {
                    assert_eq!(
                        endpoint.driver.snapshot_common(fixture.now, true)?.current,
                        values[0]
                    );
                    assert!(endpoint.driver.records.next_number(Class::Control).0 > before[side]);
                    assert_eq!(
                        (endpoint.socket.local_addr()?, endpoint.socket.peer_addr()?),
                        endpoint.original
                    );
                }
            }
            Ok(())
        })
}
