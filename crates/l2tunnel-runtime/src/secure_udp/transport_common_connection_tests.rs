//! Actual authenticated original-UDP per-connection I/O with current route grammar.
use super::*;
use l2tunnel::{
    connection_records as connections, record_configuration as c, record_engine as engine,
};

fn selected(kind: cover::Appearance) -> Result<[CommonTransactionContract; 2]> {
    let (old_contracts, old_values) = compact::selected_compact(kind)?;
    let c::Profile::AlignedCompact {
        mut forward,
        mut reverse,
    } = *old_values[0].descriptor().profile()
    else {
        return Err("actual Compact fixture absent".into());
    };
    for direction in [&mut forward, &mut reverse] {
        direction.receiver.channels = 1;
        direction.recovery = l2tunnel_reliable::CompactReliableConfig::new(
            direction.recovery.arq(),
            old_contracts[0].geometry().forward_overhead_bytes + connections::route::HEADER_BYTES,
        )?;
    }
    let common = |role| -> Result<c::CommonDirection> {
        let old = old_values[0].descriptor().direction(role).common();
        let mut policy = old.pipeline();
        policy.flows.channels = 16;
        policy.flows.capacity = 32;
        policy.flows.mapping = l2tunnel_pipeline::Mapping::ConnectionRoundRobinLearned;
        policy.queue = l2tunnel_pipeline::QueueLimits {
            bytes: 32768,
            packets: 32,
        };
        Ok(c::CommonDirection::new(
            old.traffic(),
            policy,
            old.bytes_per_second(),
            65536,
            old.native_window(),
        )?)
    };
    let descriptor = c::Descriptor::new(
        old_values[0].descriptor().path_mtu(),
        core::Duplex::Full,
        common(mg::Role::Client)?,
        common(mg::Role::Server)?,
        c::Profile::PerConnectionCompact {
            forward: connections::Direction {
                compact: forward,
                owners: 16,
                incarnation: 17,
                unreliable: Some(connections::UnreliableConfig {
                    max_bytes: 96,
                    hold_micros: 100_000,
                }),
            },
            reverse: connections::Direction {
                compact: reverse,
                owners: 16,
                incarnation: 17,
                unreliable: Some(connections::UnreliableConfig {
                    max_bytes: 96,
                    hold_micros: 100_000,
                }),
            },
        },
    )?;
    let catalog = Catalog::new(descriptor, &[descriptor])?;
    let make = |original: &CommonTransactionContract| -> Result<CommonTransactionContract> {
        let mut resources = original.resources();
        resources.connection_ingress = Some(ConnectionIngressLimits {
            slots: 2,
            capacity_bytes: 1 << 20,
        });
        Ok(CommonTransactionContract::new_compact_wire(
            original.expected_configuration(),
            original.role(),
            [resources; 2],
            original.cover(),
            original.ipv6(),
            original.envelope(),
            catalog.clone(),
            original.settings(),
            original.compact_wire(),
        )?)
    };
    Ok([make(&old_contracts[0])?, make(&old_contracts[1])?])
}
fn checksum(bytes: &[u8]) -> u16 {
    let mut sum = 0u32;
    for pair in bytes.chunks(2) {
        sum += u32::from(u16::from_be_bytes([
            pair[0],
            pair.get(1).copied().unwrap_or(0),
        ]));
    }
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}
fn tcp(port: u16, reverse: bool, payload: bool) -> Result<Vec<u8>> {
    let mut bytes = vec![0; if payload { 114 } else { 54 }];
    bytes[..12].copy_from_slice(&[2, 0, 0, 0, 0, 1, 2, 0, 0, 0, 0, 2]);
    bytes[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
    let ip = &mut bytes[14..];
    ip[0] = 0x45;
    let length = u16::try_from(ip.len())?;
    ip[2..4].copy_from_slice(&length.to_be_bytes());
    ip[8] = 64;
    ip[9] = 6;
    ip[12..20].copy_from_slice(if reverse {
        &[192, 0, 2, 2, 192, 0, 2, 1]
    } else {
        &[192, 0, 2, 1, 192, 0, 2, 2]
    });
    let (source, destination) = if reverse { (443, port) } else { (port, 443) };
    ip[20..22].copy_from_slice(&source.to_be_bytes());
    ip[22..24].copy_from_slice(&destination.to_be_bytes());
    ip[31] = 7;
    ip[32] = 0x50;
    ip[33] = if payload { 0x18 } else { 0x10 };
    ip[34..36].copy_from_slice(&4096u16.to_be_bytes());
    if payload {
        ip[40..].fill(0x71);
    }
    let value = checksum(&ip[..20]);
    ip[10..12].copy_from_slice(&value.to_be_bytes());
    let mut pseudo = ip[12..20].to_vec();
    pseudo.extend_from_slice(&[0, 6]);
    pseudo.extend_from_slice(&u16::try_from(ip.len() - 20)?.to_be_bytes());
    pseudo.extend_from_slice(&ip[20..]);
    let value = checksum(&pseudo);
    ip[36..38].copy_from_slice(&value.to_be_bytes());
    Ok(bytes)
}
struct Wire {
    bytes: Vec<u8>,
    kind: engine::EmissionKind,
    owner: u16,
}
fn emit(endpoint: &mut Endpoint, now: u64) -> Result<Option<Wire>> {
    endpoint.driver.bucket.refill(now)?;
    endpoint
        .driver
        .send_common_user_with(now, |_| Err(io::ErrorKind::WouldBlock.into()))?;
    let Some(pending) = endpoint
        .driver
        .common
        .as_ref()
        .and_then(|runtime| runtime.sealed.as_ref())
    else {
        return Ok(None);
    };
    let token = pending
        .carrier
        .as_ref()
        .ok_or("actual connection carrier token")?;
    let kind = token.emission().kind;
    let owner = connections::route::decode_compact(
        &endpoint.driver.buffers.frame[..token.emission().bytes],
    )?
    .0
    .owner
    .index();
    let number = pending.sealed.number;
    let cap = pending.deadline;
    assert!(
        cap > now,
        "soft recovery wakes cannot expire physical custody"
    );
    let debit = endpoint.driver.bucket.tokens;
    let wire = endpoint
        .driver
        .common
        .as_ref()
        .ok_or("actual runtime")?
        .wire[..pending.sealed.bytes]
        .to_vec();
    let next = endpoint.driver.records.next_number(Class::User);
    assert!(
        !endpoint
            .driver
            .send_common_user_with(now, |_| Err(io::ErrorKind::WouldBlock.into()))?
    );
    let pending = endpoint
        .driver
        .common
        .as_ref()
        .and_then(|runtime| runtime.sealed.as_ref())
        .ok_or("retained output")?;
    assert_eq!((pending.sealed.number, pending.deadline), (number, cap));
    assert_eq!(endpoint.driver.records.next_number(Class::User), next);
    assert_eq!(endpoint.driver.bucket.tokens, debit);
    assert!(
        endpoint
            .driver
            .flush_common_wire_with(now, |bytes| endpoint.socket.try_send(bytes))?
    );
    assert_eq!(endpoint.driver.bucket.tokens, debit);
    Ok(Some(Wire {
        bytes: wire,
        kind,
        owner,
    }))
}
async fn receive(endpoint: &mut Endpoint, now: u64, wire: &Wire, lose: bool) -> Result {
    let mut bytes = [0; 1501];
    let length =
        tokio::time::timeout(Duration::from_secs(1), endpoint.socket.recv(&mut bytes)).await??;
    assert_eq!(&bytes[..length], wire.bytes);
    if !lose {
        endpoint.driver.receive_selected(
            &bytes[..length],
            now,
            endpoint.driver.origin + duration(now),
        )?;
    }
    Ok(())
}
async fn native(endpoint: &mut Endpoint, now: u64) -> Result<Vec<Vec<u8>>> {
    for _ in 0..64 {
        endpoint.driver.collect_native(now)?;
        if !endpoint.driver.native.is_empty() {
            let mut ready = tokio::time::timeout(
                Duration::from_secs(1),
                endpoint.device.ready_mut(Interest::WRITABLE),
            )
            .await??;
            endpoint.driver.write_native(&mut ready, || Ok(now))?;
        }
    }
    let mut result = Vec::new();
    let mut bytes = [0; 513];
    for _ in 0..32 {
        match endpoint.host.recv(&mut bytes) {
            Ok(length) => result.push(bytes[..length].to_vec()),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
            Err(error) => return Err(error.into()),
        }
    }
    Ok(result)
}
async fn raw(fixture: &mut Fixture, lose: bool) -> Result<Wire> {
    for _ in 0..64 {
        let wire =
            emit(&mut fixture.endpoints[1], fixture.now)?.ok_or("actual reverse raw output")?;
        let is_raw = wire.kind == engine::EmissionKind::UnreliableNative;
        receive(
            &mut fixture.endpoints[0],
            fixture.now,
            &wire,
            lose && is_raw,
        )
        .await?;
        if is_raw {
            return Ok(wire);
        }
    }
    Err("bounded raw output service".into())
}

#[test]
fn original_udp_sixteen_compact_owners_lossy_raw_ack_and_native_pressure_keep_custody() -> Result {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(async {
            let kind = cover::Appearance::QuicLike;
            let mut fixture = Fixture::from_contracts(kind, selected(kind)?).await?;
            let expected = (0..16)
                .map(|id| tcp(41000 + id, false, true))
                .collect::<Result<Vec<_>>>()?;
            for packet in &expected {
                fixture.admit(0, packet).await?;
            }
            let mut lost = false;
            let mut idle = false;
            for _ in 0..128 {
                let Some(wire) = emit(&mut fixture.endpoints[0], fixture.now)? else {
                    idle = true;
                    break;
                };
                assert_eq!(
                    wire.kind,
                    engine::EmissionKind::Source(engine::SourceForm::DirectArq)
                );
                let lose = !lost && wire.owner == 0;
                receive(&mut fixture.endpoints[1], fixture.now, &wire, lose).await?;
                lost |= lose;
            }
            assert!(
                lost && idle,
                "all bounded first-flight outputs were serviced"
            );
            // No feedback was sent and no time advanced: owner0 cannot retry. The
            // other fifteen actual recovery owners must nevertheless reach native I/O.
            let independent = native(&mut fixture.endpoints[1], fixture.now).await?;
            assert_eq!(independent.len(), 15);
            for packet in &expected[1..] {
                assert!(independent.contains(packet));
            }
            assert!(!independent.contains(&expected[0]));
            let mut recovered = Vec::new();
            for _ in 0..500 {
                fixture.turn().await?;
                recovered.extend(native(&mut fixture.endpoints[1], fixture.now).await?);
                if recovered == vec![expected[0].clone()]
                    && fixture.endpoints.iter().all(|endpoint| {
                        endpoint.driver.common_state().is_ok_and(|state| {
                            state
                                .engine(state.epoch())
                                .is_ok_and(|owner| owner.drained().unwrap_or(false))
                        })
                    })
                {
                    break;
                }
            }
            assert_eq!(recovered, vec![expected[0].clone()]);
            let ack = tcp(41001, true, false)?;
            fixture.admit(1, &ack).await?;
            let lost_ack = raw(&mut fixture, true).await?;
            assert_eq!(lost_ack.owner, 1);
            assert!(
                native(&mut fixture.endpoints[0], fixture.now)
                    .await?
                    .is_empty()
            );
            // A real earlier UDP receipt is held unopened, then observed after a
            // newer input. Its original received time creates an earlier queue cap.
            fixture.admit(1, &ack).await?;
            let older_received = fixture.now;
            let delayed = raw(&mut fixture, true).await?;
            fixture.now = fixture
                .now
                .checked_add(90_000)
                .ok_or("fixture time exhausted")?;
            fixture.admit(1, &ack).await?;
            let first = raw(&mut fixture, false).await?;
            {
                let target = &mut fixture.endpoints[0];
                let epoch = target.driver.common_state()?.epoch();
                let width = target
                    .driver
                    .common_state()?
                    .engine(epoch)?
                    .configuration()
                    .descriptor()
                    .local(common_contract::mg_role(target.driver.info.role))
                    .receive()
                    .channels();
                // Each bounded call visits one actual owner. Keep time fixed and
                // retain the first real native token without writing it.
                for _ in 0..width {
                    target.driver.collect_native(fixture.now)?;
                    if !target.driver.native.is_empty() {
                        break;
                    }
                }
                let held = target
                    .driver
                    .common_state()?
                    .engine(epoch)?
                    .pending_native()
                    .ok_or("actual raw owner native pressure")?;
                assert!(matches!(
                    held.identity(),
                    engine::ProfileIdentity::UnreliableNative(identity)
                        if identity.owner.index() == 1
                ));
                assert_eq!(held.deadline().0, fixture.now + 100_000);
            }
            assert_eq!(fixture.endpoints[0].driver.native.len(), 1);
            fixture.admit(1, &ack).await?;
            let queued = raw(&mut fixture, false).await?;
            assert_ne!(first.bytes, queued.bytes);
            {
                let target = &mut fixture.endpoints[0];
                target.driver.receive_selected_at(
                    &delayed.bytes,
                    older_received,
                    fixture.now,
                    target.driver.origin + duration(fixture.now),
                )?;
            }
            let before = fixture.endpoints[0]
                .driver
                .snapshot_common(fixture.now, true)?;
            let input = before
                .connection_input
                .ok_or("actual deferred queue status")?;
            assert_eq!((input.packets, input.retained, input.admitted), (2, 2, 0));
            assert_eq!(input.deadline_micros, Some(older_received + 100_000));
            // A raw carrier can hold the outgoing body across a receive turn.
            // A retry of the queued incoming ACK must leave that buffer intact.
            let driver = &mut fixture.endpoints[0].driver;
            let transmit = driver.buffers.frame.clone();
            driver.retry_common_connection_input(fixture.now)?;
            assert_eq!(driver.buffers.frame, transmit);
            let retried = driver
                .snapshot_common(fixture.now, true)?
                .connection_input
                .ok_or("retried queue status")?;
            assert!(retried.retried > input.retried);
            let cap = fixture.now + 100_000;
            fixture.now = older_received
                .checked_add(101_000)
                .ok_or("fixture time exhausted")?;
            let replay = before.counters.replay_rejections;
            for _ in 0..8 {
                fixture.turn_with_held_native(Some(0)).await?;
            }
            let held = fixture.endpoints[0]
                .driver
                .snapshot_common(fixture.now, true)?;
            let retained = held.connection_input.ok_or("retained queue status")?;
            assert_eq!(
                (retained.packets, retained.deadline_micros, retained.expired),
                (1, Some(cap), 1)
            );
            assert_eq!(held.counters.replay_rejections, replay);
            assert!(retained.retried > input.retried);
            let mut delivered = native(&mut fixture.endpoints[0], fixture.now).await?;
            for _ in 0..64 {
                fixture.turn().await?;
                delivered.extend(native(&mut fixture.endpoints[0], fixture.now).await?);
                if delivered.len() == 2
                    && fixture
                        .endpoints
                        .iter()
                        .all(|endpoint| endpoint.driver.live.last_pong_micros.is_some())
                {
                    break;
                }
            }
            assert_eq!(delivered, vec![ack.clone(), ack]);
            let target = &mut fixture.endpoints[0];
            let snapshot = target.driver.snapshot_common(fixture.now, true)?;
            let input = snapshot
                .connection_input
                .ok_or("actual released queue status")?;
            assert_eq!(
                (
                    input.packets,
                    input.retained,
                    input.admitted,
                    input.dropped_full,
                    input.expired
                ),
                (0, 2, 1, 0, 1)
            );
            let connections = snapshot.connections.ok_or("actual installed collection")?;
            assert_eq!(connections.owners, 16);
            assert!(!connections.flow_reuse);
            assert_eq!(
                (
                    connections.unreliable.received,
                    connections.unreliable.native_written
                ),
                (2, 2)
            );
            let counts = target
                .driver
                .common_state()?
                .engine(snapshot.epoch)?
                .native_counts()?;
            assert!(
                counts
                    .prepared
                    .iter()
                    .chain(counts.committed)
                    .all(|count| *count == 0)
            );
            target.driver.receive_selected(
                &queued.bytes,
                fixture.now,
                target.driver.origin + duration(fixture.now),
            )?;
            assert_eq!(target.driver.counters.replay_rejections, replay + 1);
            for endpoint in &fixture.endpoints {
                assert!(endpoint.driver.live.last_pong_micros.is_some());
                assert_eq!(endpoint.driver.terminal, None);
                assert_eq!(
                    (endpoint.socket.local_addr()?, endpoint.socket.peer_addr()?),
                    endpoint.original
                );
            }
            Ok(())
        })
}
