//! Real Common Compact I/O; imported real session evidence is not a new setup proof.
use super::*;
use l2tunnel::record_configuration as c;
use l2tunnel::record_engine as engine;
use l2tunnel_aligned as aligned;
use l2tunnel_codec::source_copy;
use l2tunnel_recovery::{
    CompactArqConfig, CompactBounds, CompactPacketKind, CompactPacketView, CompactRecovery,
    CompactTiming, SourceId, inspect_compact_body,
};
use l2tunnel_reliable::CompactReliableConfig;

pub(super) fn direction(
    old: aligned::Config,
    reverse: bool,
    overhead: usize,
) -> Result<aligned::CompactConfig> {
    let bounds = old.recovery.arq;
    Ok(aligned::CompactConfig {
        native_policy: old.native_policy,
        receiver: old.receiver,
        recovery: CompactReliableConfig::new(
            CompactArqConfig::new(
                CompactBounds {
                    max_source_bytes: bounds.max_source_bytes,
                    send_bytes: bounds.send_bytes,
                    receive_bytes: bounds.receive_bytes,
                    send_records: bounds.send_records,
                    receive_records: bounds.receive_records,
                },
                CompactTiming {
                    nominal_rtt: Duration::from_millis(if reverse { 90 } else { 70 }),
                    feedback_interval: Duration::from_millis(if reverse { 3 } else { 5 }),
                    feedback_packets: if reverse { 3 } else { 2 },
                },
                if reverse { 400 } else { 200 },
                if reverse { 64 } else { 48 },
                8,
                if reverse {
                    CompactRecovery::FirstFlight
                } else {
                    CompactRecovery::Guarded
                },
            )?,
            overhead,
        )?,
        max_recovery_packet_bytes: 1024,
        copies: source_copy::Policy::ONE,
    })
}

pub(super) fn selected_compact(
    kind: cover::Appearance,
) -> Result<([CommonTransactionContract; 2], [C; 2])> {
    let old = catalog_fixture::values().map_err(|e| io::Error::other(e.to_string()))?;
    let overhead = config(kind).control.wire_overhead;
    let mut values = [old[1], old[2]];
    for (output, original) in values.iter_mut().zip([old[1], old[2]]) {
        let descriptor = original.descriptor();
        let profile = match *descriptor.profile() {
            c::Profile::Aligned { forward, reverse } => c::Profile::AlignedCompact {
                forward: direction(forward, false, overhead)?,
                reverse: direction(reverse, true, overhead)?,
            },
            c::Profile::Packed { forward, reverse } => c::Profile::PackedCompact {
                forward: aligned::packed::CompactConfig {
                    base: direction(forward.base, false, overhead)?,
                    hold_micros: forward.hold_micros,
                    max_units: forward.max_units,
                    work_limit: forward.work_limit,
                },
                reverse: aligned::packed::CompactConfig {
                    base: direction(reverse.base, true, overhead)?,
                    hold_micros: reverse.hold_micros,
                    max_units: reverse.max_units,
                    work_limit: reverse.work_limit,
                },
            },
            _ => return Err("actual Aligned/Packed fixture member missing".into()),
        };
        *output = C::new(
            original.envelope(),
            c::Descriptor::new(
                descriptor.path_mtu(),
                descriptor.duplex(),
                *descriptor.direction(mg::Role::Client).common(),
                *descriptor.direction(mg::Role::Server).common(),
                profile,
            )?,
        )?;
    }
    let descriptors = values.map(|value| *value.descriptor());
    let catalog = Catalog::new(descriptors[0], &descriptors)?;
    Ok((contracts_with_catalog(kind, catalog, 16)?, values))
}

struct Held {
    token: l2tunnel::record_bank::CarrierOutputToken,
    wire: Vec<u8>,
    plain: Vec<u8>,
    number: security::PacketNumber,
}

fn hold_output(endpoint: &mut Endpoint, now: u64, expected: engine::EmissionKind) -> Result<Held> {
    endpoint.driver.bucket.refill(now)?;
    let before = endpoint.driver.bucket.tokens;
    let counters = endpoint.driver.counters;
    let number = if expected == engine::EmissionKind::Feedback {
        endpoint.driver.records.next_feedback_number()
    } else {
        endpoint.driver.records.next_number(Class::User)
    };
    assert!(
        !endpoint
            .driver
            .send_common_user_with(now, |_| Err(io::ErrorKind::WouldBlock.into()))?
    );
    let epoch = endpoint.driver.common_state()?.epoch();
    let token = endpoint
        .driver
        .common_state_mut()?
        .entry(epoch)?
        .pending_carrier_output()
        .ok_or("actual Compact physical output missing")?;
    assert_eq!(token.emission().kind, expected);
    let (scope, sealed, cost, cap, wire, plain) = {
        let runtime = endpoint
            .driver
            .common
            .as_ref()
            .ok_or("Common runtime missing")?;
        let pending = runtime
            .sealed
            .as_ref()
            .ok_or("actual protected output missing")?;
        assert_eq!(pending.carrier.as_ref(), Some(&token));
        (
            pending.scope,
            pending.sealed,
            pending.cost,
            pending.deadline,
            runtime.wire[..pending.sealed.bytes].to_vec(),
            endpoint.driver.buffers.frame[..token.emission().bytes].to_vec(),
        )
    };
    assert_eq!(sealed.number, number);
    assert_eq!(before - endpoint.driver.bucket.tokens, cost as u128 * SCALE);
    assert_eq!(
        endpoint.driver.counters.wire_packets,
        counters.wire_packets + 1
    );
    assert_eq!(
        endpoint.driver.counters.socket_accepted_packets,
        counters.socket_accepted_packets
    );
    let debit = endpoint.driver.bucket.tokens;
    let next = endpoint.driver.records.next_number(Class::User);
    for _ in 0..2 {
        assert!(
            !endpoint
                .driver
                .send_common_user_with(now, |_| Err(io::ErrorKind::WouldBlock.into()))?
        );
        let runtime = endpoint
            .driver
            .common
            .as_ref()
            .ok_or("Common runtime missing")?;
        let pending = runtime
            .sealed
            .as_ref()
            .ok_or("retained protected output missing")?;
        assert_eq!(pending.carrier.as_ref(), Some(&token));
        assert_eq!(
            (
                pending.scope,
                pending.sealed,
                pending.cost,
                pending.deadline
            ),
            (scope, sealed, cost, cap)
        );
        assert_eq!(&runtime.wire[..pending.sealed.bytes], wire);
        assert_eq!(endpoint.driver.records.next_number(Class::User), next);
        assert_eq!(endpoint.driver.bucket.tokens, debit);
        assert_eq!(
            endpoint.driver.counters.wire_packets,
            counters.wire_packets + 1
        );
        assert_eq!(
            endpoint.driver.counters.socket_accepted_packets,
            counters.socket_accepted_packets
        );
    }
    assert!(
        endpoint
            .driver
            .flush_common_wire_with(now, |bytes| endpoint.socket.try_send(bytes))?
    );
    assert_eq!(
        endpoint.driver.counters.socket_accepted_packets,
        counters.socket_accepted_packets + 1
    );
    assert_eq!(endpoint.driver.bucket.tokens, debit);
    assert_eq!(endpoint.driver.records.next_number(Class::User), next);
    Ok(Held {
        token,
        wire,
        plain,
        number,
    })
}

fn inspect<'a>(held: &'a Held, policy: CompactArqConfig) -> Result<CompactPacketView<'a>> {
    // This parser observes actual emitted plaintext; it grants no session authority.
    let (&kind, body) = held
        .plain
        .split_first()
        .ok_or("actual Compact union absent")?;
    let kind = match (kind, held.token.emission().kind) {
        (1, engine::EmissionKind::Source(engine::SourceForm::DirectArq)) => CompactPacketKind::Data,
        (2, engine::EmissionKind::Feedback) => CompactPacketKind::Feedback,
        _ => return Err("actual Compact union differs from owned emission".into()),
    };
    Ok(inspect_compact_body(kind, body, policy)?)
}

async fn receive_output(endpoint: &mut Endpoint, now: u64, held: &Held, lose: bool) -> Result {
    let mut packet = [0; 1501];
    let bytes =
        tokio::time::timeout(Duration::from_secs(1), endpoint.socket.recv(&mut packet)).await??;
    assert_eq!(&packet[..bytes], held.wire);
    if !lose {
        let before = endpoint.driver.counters;
        endpoint.driver.receive_selected(
            &packet[..bytes],
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
    }
    Ok(())
}

#[test]
fn actual_common_compact_loss_feedback_custody_and_negotiated_packed_switch() -> Result {
    tokio::runtime::Builder::new_current_thread().enable_all().build()?.block_on(async {
        let kind = cover::Appearance::QuicLike;
        let (contracts, values) = selected_compact(kind)?;
        for (value, tag) in values.iter().zip([6, 7]) {
            let mut bytes = [0; c::CONFIGURATION_BYTES];
            value.encode_into(&mut bytes)?;
            assert_eq!(bytes[5], tag);
            assert_eq!(C::decode(&bytes)?, *value);
        }
        let c::Profile::AlignedCompact { forward, reverse } = *values[0].descriptor().profile()
            else { return Err("selected Compact profile missing".into()); };
        let geometry = l2tunnel_reliable::storage::CompactPlan::for_duplex(forward.recovery, reverse.recovery)?;
        assert_eq!(geometry.send_max_packet_bytes(), l2tunnel_reliable::ENVELOPE_BYTES + reverse.recovery.arq().maximum_feedback_bytes());
        assert_ne!(forward.receiver.channels, reverse.receiver.channels);
        assert_ne!(forward.recovery.arq().timing(), reverse.recovery.arq().timing());
        // The reused fixture performs actual Noise/member authentication. Its
        // imported session does not establish this case's catalog-bound H0.
        let mut fixture = Fixture::from_contracts(kind, contracts).await?;
        let epoch = fixture.endpoints[0].driver.common_state()?.epoch();
        let first = frame(40_000, 101);
        let second = frame(40_000, 102);
        fixture.admit(0, &first).await?;
        let original = hold_output(&mut fixture.endpoints[0], fixture.now,
            engine::EmissionKind::Source(engine::SourceForm::DirectArq))?;
        let (source, serial, payload) = match inspect(&original, forward.recovery.arq())? {
            CompactPacketView::Data { source, serial, payload } => (source, serial, payload.to_vec()),
            _ => return Err("actual Compact source absent".into()),
        };
        assert_eq!(source, SourceId(0));
        // Network loss is injected after actual whole UDP acceptance, by reading
        // and discarding the datagram on the same original receiving socket.
        receive_output(&mut fixture.endpoints[1], fixture.now, &original, true).await?;
        fixture.admit(0, &second).await?;
        let later = hold_output(&mut fixture.endpoints[0], fixture.now,
            engine::EmissionKind::Source(engine::SourceForm::DirectArq))?;
        assert!(matches!(inspect(&later, forward.recovery.arq())?, CompactPacketView::Data { source: SourceId(1), .. }));
        receive_output(&mut fixture.endpoints[1], fixture.now, &later, false).await?;
        let (feedback_at, feedback_bytes) = fixture.endpoints[1].driver.common_state()?.engine(epoch)?
            .feedback_opportunity()?.ok_or("actual Compact feedback deadline absent")?;
        fixture.now = fixture.now.max(feedback_at.0);
        let feedback = hold_output(&mut fixture.endpoints[1], fixture.now, engine::EmissionKind::Feedback)?;
        assert_eq!(feedback.plain.len(), feedback_bytes);
        assert!(matches!(inspect(&feedback, forward.recovery.arq())?, CompactPacketView::Feedback(value) if value.prefix == 0));
        receive_output(&mut fixture.endpoints[0], fixture.now, &feedback, true).await?;
        let retry_at = fixture.endpoints[0].driver.common_state()?.engine(epoch)?
            .deadline()?.ok_or("accepted Compact source lost its actual retry wake")?.0;
        fixture.now = fixture.now.max(retry_at);
        let retry = hold_output(&mut fixture.endpoints[0], fixture.now,
            engine::EmissionKind::Source(engine::SourceForm::DirectArq))?;
        match inspect(&retry, forward.recovery.arq())? {
            CompactPacketView::Data { source: actual, serial: attempt, payload: actual_payload } => {
                assert_eq!(actual, source);
                assert!(attempt > serial);
                assert_eq!(actual_payload, payload);
            }
            _ => return Err("actual same-source retry absent".into()),
        }
        assert!(retry.number.0 > original.number.0);
        assert_ne!(retry.wire, original.wire);
        receive_output(&mut fixture.endpoints[1], fixture.now, &retry, false).await?;
        let mut delivered = Vec::new();
        let mut drained = false;
        for _ in 0..500 {
            fixture.turn().await?;
            let mut output = [0; 1024];
            for _ in 0..16 {
                match fixture.endpoints[1].host.recv(&mut output) {
                    Ok(bytes) => delivered.push(output[..bytes].to_vec()),
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                    Err(error) => return Err(error.into()),
                }
            }
            if delivered.len() == 2 && fixture.endpoints.iter().all(|endpoint| endpoint.driver
                .common_state().is_ok_and(|state| state.engine(state.epoch()).is_ok_and(|engine| engine.drained().unwrap_or(false)))) {
                drained = true;
                break;
            }
        }
        assert!(drained, "actual Compact retransmission/native debt did not drain");
        assert_eq!(delivered, vec![first, second]);
        let target = &mut fixture.endpoints[1];
        let before = target.driver.counters.replay_rejections;
        target.driver.receive_selected(&retry.wire, fixture.now, target.driver.origin + duration(fixture.now))?;
        assert_eq!(target.driver.counters.replay_rejections, before + 1);
        let next_epoch = fixture.switch(values[1]).await?;
        assert_eq!(next_epoch.0, epoch.0 + 1);
        fixture.exchange_all_channels(111).await?;
        for _ in 0..100 {
            if fixture.endpoints.iter().all(|endpoint| endpoint.driver.live.last_pong_micros.is_some()) { break; }
            fixture.turn().await?;
        }
        for endpoint in &fixture.endpoints {
            let snapshot = endpoint.driver.snapshot_common(fixture.now, true)?;
            assert_eq!(snapshot.current, values[1]);
            assert_eq!(snapshot.epoch, next_epoch);
            assert!(endpoint.driver.live.last_pong_micros.is_some());
            assert_eq!(endpoint.driver.terminal, None);
            assert_eq!((endpoint.socket.local_addr()?, endpoint.socket.peer_addr()?), endpoint.original);
            assert!(!snapshot.resource_preallocation_complete);
        }
        Ok(())
    })
}
