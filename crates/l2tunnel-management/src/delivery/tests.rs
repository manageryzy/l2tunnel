use super::*;

fn settings() -> Settings {
    Settings {
        recovery: ArqConfig {
            max_source_bytes: 128,
            send_bytes: 512,
            receive_bytes: 512,
            send_records: 4,
            receive_records: 4,
            initial_rto: Duration::from_millis(20),
            maximum_rto: Duration::from_millis(80),
            ack_delay: Duration::ZERO,
            max_retries: 8,
        },
        interval: Duration::from_millis(10),
        packets_per_interval: 4,
        bytes_per_interval: 1024,
        wire_overhead: 64,
    }
}
fn binding(role: Role) -> Binding {
    Binding {
        session: SessionId([3; 16]),
        lane: LaneId(7),
        local_role: role,
        control_epoch: 1,
    }
}
fn ingress(sender: Role) -> Ingress {
    Ingress::AuthenticatedManagement {
        session: SessionId([3; 16]),
        lane: LaneId(7),
        sender,
    }
}
fn pair(settings: Settings, expires: Duration) -> Result<[Service; 2], Error> {
    Ok([
        Service::new(settings, binding(Role::Client), Duration::ZERO, expires)?,
        Service::new(settings, binding(Role::Server), Duration::ZERO, expires)?,
    ])
}

#[test]
fn control_sources_survive_loss_reorder_duplicates_and_lost_receipts() -> Result<(), Error> {
    let mut peers = pair(settings(), Duration::from_secs(2))?;
    let sources: Vec<Vec<u8>> = (0..20)
        .map(|id| {
            let mut source = vec![id; 40 + usize::from(id) * 3];
            source.extend_from_slice(&[0, 0]);
            source
        })
        .collect();
    let mut admitted = 0;
    let mut delivered = Vec::new();
    let mut pending: Vec<(u64, usize, Vec<u8>)> = Vec::new();
    let mut packet = [0; 256];
    let mut output = [0; 128];
    let mut dropped_source = false;
    let mut dropped_receipt = false;
    let mut charged = [0u64; 2];
    for tick in 0..2000 {
        let now = Duration::from_millis(tick);
        while admitted < sources.len() {
            match peers[0].submit(&sources[admitted], now) {
                Ok(id) => {
                    assert_eq!(id as usize, admitted);
                    admitted += 1;
                }
                Err(Error::Recovery(
                    RecoveryError::Capacity(_) | RecoveryError::SequenceWindow,
                )) => break,
                result => {
                    result?;
                }
            }
        }
        let arriving = std::mem::take(&mut pending);
        for (at, target, wire) in arriving {
            if at > tick {
                pending.push((at, target, wire));
                continue;
            }
            let sender = if target == 1 {
                Role::Client
            } else {
                Role::Server
            };
            peers[target].receive(ingress(sender), &wire, now)?;
        }
        for side in 0..2 {
            while let Some(emission) = peers[side].poll(now, usize::MAX, &mut packet)? {
                assert_eq!(
                    emission.wire_bytes,
                    emission.bytes + settings().wire_overhead
                );
                charged[side] += emission.wire_bytes as u64;
                let wire = packet[..emission.bytes].to_vec();
                if side == 0 && !dropped_source {
                    dropped_source = true;
                    continue;
                }
                if side == 1 && !dropped_receipt {
                    dropped_receipt = true;
                    continue;
                }
                pending.push((
                    tick + if tick % 2 == 0 { 5 } else { 1 },
                    1 - side,
                    wire.clone(),
                ));
                if side == 0 {
                    pending.push((tick + 8, 1, wire));
                }
            }
            assert!(peers[side].retained().send_records <= 4);
            assert!(peers[side].retained().receive_records <= 4);
            assert!(peers[side].retained().send_bytes <= 512);
        }
        while let Some((id, length)) = peers[1].deliver(&mut output, now)? {
            assert_eq!(id as usize, delivered.len());
            delivered.push(output[..length].to_vec());
        }
        if delivered.len() == sources.len()
            && peers.iter().all(Service::drained)
            && pending.is_empty()
        {
            break;
        }
    }
    assert_eq!(delivered, sources);
    assert!(peers.iter().all(Service::drained));
    assert!(dropped_source && dropped_receipt);
    assert_eq!(peers[0].statistics().emitted_wire_bytes, charged[0]);
    assert_eq!(peers[1].statistics().emitted_wire_bytes, charged[1]);
    Ok(())
}

#[test]
fn verified_origin_and_fixed_binding_precede_recovery_mutation() -> Result<(), Error> {
    let [mut left, mut right] = pair(settings(), Duration::from_secs(1))?;
    left.submit(b"L2MC management-looking bytes\0\0", Duration::ZERO)?;
    let mut packet = [0; 256];
    let emitted = left
        .poll(Duration::ZERO, usize::MAX, &mut packet)?
        .ok_or(Error::Settings)?;
    let wire = &packet[..emitted.bytes];
    for untrusted in [Ingress::UserTraffic, Ingress::Unauthenticated] {
        assert_eq!(
            right.receive(untrusted, wire, Duration::ZERO),
            Err(Error::Origin)
        );
    }
    for wrong in [
        Ingress::AuthenticatedManagement {
            session: SessionId([4; 16]),
            lane: LaneId(7),
            sender: Role::Client,
        },
        Ingress::AuthenticatedManagement {
            session: SessionId([3; 16]),
            lane: LaneId(8),
            sender: Role::Client,
        },
        ingress(Role::Server),
    ] {
        assert_eq!(
            right.receive(wrong, wire, Duration::ZERO),
            Err(Error::Binding)
        );
        assert_eq!(right.retained(), Retained::default());
    }
    assert!(
        right
            .receive(ingress(Role::Client), &wire[..10], Duration::ZERO)
            .is_err()
    );
    right.receive(ingress(Role::Client), wire, Duration::ZERO)?;
    let mut conflict = wire.to_vec();
    let last = conflict.len() - 1;
    conflict[last] ^= 1;
    assert_eq!(
        right.receive(ingress(Role::Client), &conflict, Duration::ZERO),
        Err(Error::Recovery(RecoveryError::ConflictingDuplicate))
    );
    assert!(matches!(
        right.deliver(&mut [0; 1], Duration::ZERO),
        Err(Error::Recovery(RecoveryError::OutputTooSmall { .. }))
    ));
    let mut output = [0; 128];
    let (_, length) = right
        .deliver(&mut output, Duration::ZERO)?
        .ok_or(Error::Settings)?;
    assert_eq!(&output[..length], b"L2MC management-looking bytes\0\0");
    Ok(())
}

#[test]
fn feedback_reservation_shared_allowance_and_small_output_preserve_attempts() -> Result<(), Error> {
    let mut config = settings();
    config.packets_per_interval = 2;
    config.bytes_per_interval = 348;
    let [mut left, mut right] = pair(config, Duration::from_secs(1))?;
    for _ in 0..4 {
        left.submit(&[9; 128], Duration::ZERO)?;
        right.submit(&[8; 128], Duration::ZERO)?;
    }
    let mut packet = [0; 256];
    assert_eq!(
        left.poll(Duration::ZERO, usize::MAX, &mut [0; 1]),
        Err(Error::OutputTooSmall)
    );
    // Shared allowance preserves the first receipt as well as the source.
    assert_eq!(left.poll(Duration::ZERO, 347, &mut packet)?, None);
    assert_eq!(left.statistics(), Statistics::default());
    let source = left
        .poll(Duration::ZERO, 348, &mut packet)?
        .ok_or(Error::Settings)?;
    assert_eq!(
        source,
        Emission {
            bytes: 172,
            wire_bytes: 236
        }
    );
    let received = packet[..source.bytes].to_vec();
    right
        .poll(Duration::ZERO, 348, &mut packet)?
        .ok_or(Error::Settings)?;
    right.receive(ingress(Role::Client), &received, Duration::ZERO)?;
    assert_eq!(
        right.deadline(),
        Duration::ZERO,
        "source reservation hid ready feedback"
    );
    assert_eq!(right.poll(Duration::ZERO, 111, &mut packet)?, None);
    let receipt = right
        .poll(Duration::ZERO, 112, &mut packet)?
        .ok_or(Error::Settings)?;
    assert_eq!(
        receipt,
        Emission {
            bytes: 48,
            wire_bytes: 112
        }
    );
    assert_eq!(right.statistics().emitted_wire_bytes, 348);
    assert_eq!(right.poll(Duration::ZERO, usize::MAX, &mut packet)?, None);
    // Three unsent sources wait for the next interval, ahead of the sent
    // source's 20 ms retry; reserved feedback did not consume their attempts.
    assert_eq!(right.deadline(), Duration::from_millis(10));
    left.receive(
        ingress(Role::Server),
        &packet[..receipt.bytes],
        Duration::ZERO,
    )?;
    assert_eq!(left.retained().send_records, 3);
    Ok(())
}

#[test]
fn duplicates_and_budget_refills_never_extend_original_expiry() -> Result<(), Error> {
    let [mut left, mut right] = pair(settings(), Duration::from_millis(100))?;
    left.submit(b"fixed context", Duration::ZERO)?;
    let mut packet = [0; 256];
    let emission = left
        .poll(Duration::ZERO, usize::MAX, &mut packet)?
        .ok_or(Error::Settings)?;
    let wire = packet[..emission.bytes].to_vec();
    right.receive(ingress(Role::Client), &wire, Duration::from_millis(1))?;
    right.receive(ingress(Role::Client), &wire, Duration::from_millis(99))?;
    assert_eq!(
        right.receive(ingress(Role::Client), &wire, Duration::from_millis(98)),
        Err(Error::NonMonotonicTime)
    );
    assert_eq!(
        right.receive(ingress(Role::Client), &wire, Duration::from_millis(100)),
        Err(Error::Expired)
    );
    assert_eq!(
        right.poll(Duration::from_millis(100), usize::MAX, &mut packet),
        Err(Error::Expired)
    );
    assert_eq!(
        right.deliver(&mut packet, Duration::from_millis(100)),
        Err(Error::Expired)
    );
    assert_eq!(
        right.submit(b"late", Duration::from_millis(100)),
        Err(Error::Expired)
    );
    assert!(right.deadline() <= Duration::from_millis(100));
    Ok(())
}

#[test]
fn shared_budget_exhaustion_waits_for_refill_or_external_allowance() -> Result<(), Error> {
    let [mut left, _] = pair(settings(), Duration::from_secs(1))?;
    left.submit(b"queued source", Duration::ZERO)?;
    let mut packet = [0; 256];
    for tick in [0, 10, 20] {
        let now = Duration::from_millis(tick);
        assert_eq!(left.poll(now, 0, &mut packet)?, None);
        assert_eq!(left.deadline(), now + settings().interval);
        assert_eq!(left.statistics(), Statistics::default());
    }
    // External budget restoration triggers a poll without waiting for refill.
    let emission = left
        .poll(Duration::from_millis(21), usize::MAX, &mut packet)?
        .ok_or(Error::Settings)?;
    let view = l2tunnel_recovery::inspect_packet(
        &packet[..emission.bytes],
        RecoveryContext {
            session: u128::from_be_bytes([3; 16]),
            epoch: 1,
            role: EndpointRole::Responder,
        },
        128,
    )?;
    assert!(matches!(
        view,
        l2tunnel_recovery::PacketView::Data {
            source: l2tunnel_recovery::SourceId(0),
            ..
        }
    ));
    Ok(())
}

#[test]
fn continuing_valid_duplicates_preserve_first_sources_retries_and_feedback() -> Result<(), Error> {
    let mut config = settings();
    config.packets_per_interval = 2;
    config.bytes_per_interval = 348;
    let mut peers = pair(config, Duration::from_secs(1))?;
    let mut packet = [0; 256];
    let mut first_sources: [Vec<u8>; 2] = std::array::from_fn(|_| Vec::new());
    let mut attempts = [[0_u32; 4]; 2];
    let mut receipts = [0_u32; 2];
    for side in 0..2 {
        for id in 0..4 {
            peers[side].submit(&[side as u8 + id; 128], Duration::ZERO)?;
        }
        let first = peers[side]
            .poll(Duration::ZERO, 348, &mut packet)?
            .ok_or(Error::Settings)?;
        first_sources[side] = packet[..first.bytes].to_vec();
        attempts[side][0] = 1;
    }
    // No receipts are delivered back: both full send ledgers retain four
    // sources, so first sends and due retries must share each bounded interval.
    for tick in 1..=8 {
        let now = Duration::from_millis(tick * 10);
        for side in 0..2 {
            let sender = if side == 0 {
                Role::Server
            } else {
                Role::Client
            };
            peers[side].receive(ingress(sender), &first_sources[1 - side], now)?;
            let receipt = peers[side]
                .poll(now, 348, &mut packet)?
                .ok_or(Error::Settings)?;
            assert_eq!(receipt.wire_bytes, 112);
            receipts[side] += 1;
            // Replenish due feedback before every poll. It cannot consume the
            // final source opportunity merely because it is considered first.
            peers[side].receive(ingress(sender), &first_sources[1 - side], now)?;
            let source = peers[side]
                .poll(now, 236, &mut packet)?
                .ok_or(Error::Settings)?;
            assert_eq!(source.wire_bytes, 236);
            let view = l2tunnel_recovery::inspect_packet(
                &packet[..source.bytes],
                RecoveryContext {
                    session: u128::from_be_bytes([3; 16]),
                    epoch: 1,
                    role: if side == 0 {
                        EndpointRole::Responder
                    } else {
                        EndpointRole::Initiator
                    },
                },
                128,
            )?;
            let l2tunnel_recovery::PacketView::Data { source, .. } = view else {
                return Err(Error::Settings);
            };
            attempts[side][source.0 as usize] += 1;
            peers[side].receive(ingress(sender), &first_sources[1 - side], now)?;
            assert_eq!(peers[side].poll(now, 0, &mut packet)?, None);
            assert_eq!(peers[side].deadline(), now + config.interval);
            assert_eq!(peers[side].retained().send_records, 4);
        }
    }
    for side in 0..2 {
        assert_eq!(receipts[side], 8);
        assert!(attempts[side].iter().all(|count| *count > 0));
        assert!(attempts[side][0] >= 3, "due retries were starved");
        assert!(attempts[side][1] >= 2, "later source retry was starved");
        assert_eq!(peers[side].statistics().emitted_wire_bytes, 236 + 8 * 348);
    }
    Ok(())
}

#[test]
fn reserved_retry_and_shared_allowance_do_not_busy_wake_on_feedback() -> Result<(), Error> {
    for packets_per_interval in [2, 4] {
        let mut config = settings();
        config.packets_per_interval = packets_per_interval;
        let [mut left, mut right] = pair(config, Duration::from_secs(1))?;
        left.submit(&[1; 128], Duration::ZERO)?;
        right.submit(&[2; 128], Duration::ZERO)?;
        let mut packet = [0; 256];
        left.poll(Duration::ZERO, 348, &mut packet)?
            .ok_or(Error::Settings)?;
        let source = right
            .poll(Duration::ZERO, 348, &mut packet)?
            .ok_or(Error::Settings)?;
        let incoming = packet[..source.bytes].to_vec();
        let now = Duration::from_millis(10);
        left.receive(ingress(Role::Server), &incoming, now)?;
        let receipt = left.poll(now, 348, &mut packet)?.ok_or(Error::Settings)?;
        assert_eq!(receipt.wire_bytes, 112);
        let now = Duration::from_millis(11);
        left.receive(ingress(Role::Server), &incoming, now)?;
        // The retained local source is not due until 20 ms. With four packet
        // slots, remembered shared allowance alone must preserve its wire cost.
        assert_eq!(left.deadline(), Duration::from_millis(20));
        assert_eq!(left.poll(now, 236, &mut packet)?, None);
        assert_eq!(left.deadline(), Duration::from_millis(20));
        let now = Duration::from_millis(20);
        assert_eq!(
            left.poll(now, 348, &mut packet)?
                .ok_or(Error::Settings)?
                .wire_bytes,
            112
        );
        left.receive(ingress(Role::Server), &incoming, now)?;
        let retry = left.poll(now, 236, &mut packet)?.ok_or(Error::Settings)?;
        assert_eq!(retry.wire_bytes, 236);
        assert_eq!(left.deadline(), Duration::from_millis(30));
    }
    Ok(())
}

#[test]
fn silent_peer_and_invalid_resource_bounds_fail_explicitly() -> Result<(), Error> {
    let mut config = settings();
    config.recovery.max_retries = 0;
    let [mut left, _] = pair(config, Duration::from_secs(1))?;
    left.submit(b"never confirmed", Duration::ZERO)?;
    let mut packet = [0; 256];
    left.poll(Duration::ZERO, usize::MAX, &mut packet)?
        .ok_or(Error::Settings)?;
    assert!(matches!(
        left.poll(Duration::from_millis(20), usize::MAX, &mut packet),
        Err(Error::Recovery(RecoveryError::RetryExhausted { .. }))
    ));
    let mut bad = settings();
    bad.wire_overhead = usize::MAX;
    assert!(matches!(
        Service::new(
            bad,
            binding(Role::Client),
            Duration::ZERO,
            Duration::from_secs(1)
        ),
        Err(Error::Settings)
    ));
    assert!(matches!(
        Service::new(
            settings(),
            binding(Role::Client),
            Duration::MAX,
            Duration::MAX
        ),
        Err(Error::Settings)
    ));
    Ok(())
}

#[test]
fn exact_source_receipt_custody_checks_verified_ack_and_original_time() -> Result<(), Error> {
    let [mut left, mut right] = pair(settings(), Duration::from_secs(1))?;
    assert!(!left.source_confirmed(0, Duration::ZERO)?);
    let source = left.submit(b"last directional barrier\0", Duration::ZERO)?;
    let mut packet = [0; 256];
    let data = left
        .poll(Duration::ZERO, usize::MAX, &mut packet)?
        .ok_or(Error::Settings)?;
    assert!(!left.source_confirmed(source, Duration::ZERO)?);
    right.receive(ingress(Role::Client), &packet[..data.bytes], Duration::ZERO)?;
    assert!(!left.source_confirmed(source, Duration::ZERO)?);
    let receipt = right
        .poll(Duration::ZERO, usize::MAX, &mut packet)?
        .ok_or(Error::Settings)?;
    assert_eq!(
        left.receive(
            Ingress::UserTraffic,
            &packet[..receipt.bytes],
            Duration::ZERO
        ),
        Err(Error::Origin)
    );
    assert!(!left.source_confirmed(source, Duration::ZERO)?);
    let now = Duration::from_millis(1);
    left.receive(ingress(Role::Server), &packet[..receipt.bytes], now)?;
    left.submit(b"unrelated later command", now)?;
    assert!(!left.drained());
    assert!(left.source_confirmed(source, now)?);
    assert!(!left.source_confirmed(source + 1, now)?);
    assert!(!left.source_confirmed(u64::MAX, now)?);
    assert_eq!(
        left.source_confirmed(source, Duration::ZERO),
        Err(Error::NonMonotonicTime)
    );
    assert_eq!(
        left.source_confirmed(source, Duration::from_secs(1)),
        Err(Error::Expired)
    );
    Ok(())
}
