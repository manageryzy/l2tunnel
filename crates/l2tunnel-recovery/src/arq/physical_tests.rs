use super::*;
use crate::storage::{Limits, Plan};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn config() -> ArqConfig {
    ArqConfig {
        max_source_bytes: 16,
        send_bytes: 64,
        receive_bytes: 64,
        send_records: 4,
        receive_records: 4,
        initial_rto: ms(10),
        maximum_rto: ms(80),
        ack_delay: Duration::ZERO,
        max_retries: 4,
    }
}

fn context(role: EndpointRole) -> RecoveryContext {
    RecoveryContext {
        session: 0x1234,
        epoch: 7,
        role,
    }
}

fn ms(value: u64) -> Duration {
    Duration::from_millis(value)
}

fn make(role: EndpointRole, reserved: bool, physical: bool) -> TestResult<SelectiveRepeat> {
    let mut owner = if reserved {
        SelectiveRepeat::new_reserved(
            config(),
            context(role),
            Limits {
                capacity_bytes: Plan::for_arq(config())?.capacity_bytes(),
            },
        )?
    } else {
        SelectiveRepeat::new(config(), context(role))?
    };
    if physical {
        owner.enable_physical_send_confirmation()?;
    }
    Ok(owner)
}

fn emit_source(owner: &mut SelectiveRepeat, now: Duration) -> TestResult<Vec<u8>> {
    let mut output = [0; DATA_HEADER_BYTES + 16];
    let length = owner
        .poll_source(now, &mut output)?
        .ok_or("missing source")?;
    Ok(output[..length].to_vec())
}

fn emit_ack(owner: &mut SelectiveRepeat, now: Duration) -> TestResult<Vec<u8>> {
    let mut output = [0; ACK_PACKET_BYTES];
    let length = owner
        .poll_feedback(now, &mut output)?
        .ok_or("missing ACK")?;
    assert_eq!(length, ACK_PACKET_BYTES);
    Ok(output.to_vec())
}

fn token(owner: &SelectiveRepeat, source: u64) -> TestResult<PhysicalTransmission> {
    Ok(owner
        .pending_transmission(SourceId(source))
        .ok_or("missing custody token")?)
}

#[test]
fn explicit_mode_preserves_legacy_wire_and_arms_retry_only_after_whole_send() -> TestResult {
    for reserved in [false, true] {
        let mut selected = make(EndpointRole::Initiator, reserved, true)?;
        let mut legacy = make(EndpointRole::Initiator, reserved, false)?;
        let payload = [0x81, 0, 0xff, 0x4b, 0, 0x29, 0];
        assert_eq!(selected.submit(&payload, ms(0))?, 0);
        assert_eq!(legacy.submit(&payload, ms(0))?, 0);
        let selected_wire = emit_source(&mut selected, ms(0))?;
        assert_eq!(selected_wire, emit_source(&mut legacy, ms(0))?);
        let mut expected = [0; DATA_HEADER_BYTES + 7];
        expected[..8].copy_from_slice(b"L2AR\x01\x01\x01\x00");
        expected[22] = 0x12;
        expected[23] = 0x34;
        expected[31] = 7;
        expected[43] = 7;
        expected[44..].copy_from_slice(&payload);
        assert_eq!(selected_wire, expected);
        assert_eq!(legacy.source_deadline(), Some(ms(10)));
        assert_eq!(legacy.pending_transmission(SourceId(0)), None);
        assert_eq!(selected.source_deadline(), None);
        let first = token(&selected, 0)?;
        assert_eq!(emit_source(&mut legacy, ms(10))?, selected_wire);
        assert_eq!(legacy.statistics().retransmissions, 1);
        assert_eq!(selected.poll_source(ms(10_000), &mut [0; 60])?, None);
        assert_eq!(selected.statistics().transmissions, 1);
        assert_eq!(selected.statistics().retransmissions, 0);
        assert_eq!(selected.pending_transmission(SourceId(0)), Some(first));
        selected.confirm_transmission(ms(10_000), first)?;
        assert_eq!(selected.source_deadline(), Some(ms(10_010)));
        assert_eq!(selected.poll_source(ms(10_009), &mut [0; 60])?, None);
        assert_eq!(emit_source(&mut selected, ms(10_010))?, selected_wire);
        let retry = token(&selected, 0)?;
        assert_ne!(retry, first);
        assert_eq!(selected.source_deadline(), None);
        selected.confirm_transmission(ms(10_100), retry)?;
        assert_eq!(selected.source_deadline(), Some(ms(10_120)));
        assert_eq!(selected.statistics().retransmissions, 1);
        assert_eq!(
            selected.enable_physical_send_confirmation(),
            Err(RecoveryError::InvalidConfig)
        );
    }
    Ok(())
}

#[test]
fn independent_sources_accept_out_of_order_physical_completion_and_real_bitmap_ack() -> TestResult {
    for reserved in [false, true] {
        let mut sender = make(EndpointRole::Initiator, reserved, true)?;
        let mut receiver = make(EndpointRole::Responder, reserved, true)?;
        let first = [0xb1, 0, 0x39, 0];
        let second = [0xc2, 0xff, 0, 0x48, 0];
        sender.submit(&first, ms(0))?;
        sender.submit(&second, ms(0))?;
        let wire0 = emit_source(&mut sender, ms(0))?;
        let token0 = token(&sender, 0)?;
        let wire1 = emit_source(&mut sender, ms(0))?;
        let token1 = token(&sender, 1)?;
        assert_eq!(sender.0.pending_transmissions, 2);
        sender.confirm_transmission(ms(10), token1)?;
        receiver.receive(&wire1, ms(10))?;
        let ack1 = emit_ack(&mut receiver, ms(10))?;
        assert_eq!(
            inspect_packet(&ack1, context(EndpointRole::Initiator), 16)?,
            PacketView::Ack {
                prefix: 0,
                bitmap: 2
            }
        );
        sender.receive(&ack1, ms(10))?;
        assert!(sender.source_confirmed(SourceId(1))?);
        assert!(!sender.source_confirmed(SourceId(0))?);
        assert_eq!(sender.pending_transmission(SourceId(0)), Some(token0));
        assert_eq!(sender.retained().send_records, 1);
        assert_eq!(receiver.poll_delivered(&mut [0; 16])?, None);

        sender.confirm_transmission(ms(20), token0)?;
        receiver.receive(&wire0, ms(20))?;
        sender.receive(&emit_ack(&mut receiver, ms(20))?, ms(20))?;
        assert!(sender.source_confirmed(SourceId(0))?);
        assert!(sender.drained());
        let mut delivered = [0; 16];
        assert_eq!(
            receiver.poll_delivered(&mut delivered)?,
            Some((0, first.len()))
        );
        assert_eq!(&delivered[..first.len()], &first);
        assert_eq!(
            receiver.poll_delivered(&mut delivered)?,
            Some((1, second.len()))
        );
        assert_eq!(&delivered[..second.len()], &second);
        assert!(receiver.drained());
    }
    Ok(())
}

#[test]
fn first_flight_ack_before_local_send_confirmation_is_rejected_without_time_change() -> TestResult {
    for reserved in [false, true] {
        let mut sender = make(EndpointRole::Initiator, reserved, true)?;
        let mut receiver = make(EndpointRole::Responder, reserved, true)?;
        sender.submit(&[0x19, 0, 0xe7], ms(0))?;
        let packet = emit_source(&mut sender, ms(0))?;
        let prepared = token(&sender, 0)?;
        // The peer can generate structural feedback before the caller reports
        // its own whole-send observation. No authentication is inferred here.
        receiver.receive(&packet, ms(5))?;
        let ack = emit_ack(&mut receiver, ms(5))?;
        let statistics = sender.statistics();
        let retained = sender.retained();
        assert_eq!(
            sender.receive(&ack, ms(5)),
            Err(RecoveryError::UnsentAcknowledgement)
        );
        assert_eq!(sender.0.last_now, ms(0));
        assert_eq!(sender.statistics(), statistics);
        assert_eq!(sender.retained(), retained);
        assert_eq!(sender.pending_transmission(SourceId(0)), Some(prepared));
        sender.confirm_transmission(ms(0), prepared)?;
        sender.receive(&ack, ms(5))?;
        assert!(sender.source_confirmed(SourceId(0))?);
        assert!(sender.drained());
    }
    Ok(())
}

#[test]
fn older_ack_while_retry_is_held_confirms_source_but_retains_exact_custody() -> TestResult {
    for reserved in [false, true] {
        let mut sender = make(EndpointRole::Initiator, reserved, true)?;
        let mut receiver = make(EndpointRole::Responder, reserved, true)?;
        let payload = [0xf3, 0, 0x41, 0xff, 0];
        sender.submit(&payload, ms(0))?;
        let original = emit_source(&mut sender, ms(0))?;
        let first = token(&sender, 0)?;
        sender.confirm_transmission(ms(0), first)?;
        receiver.receive(&original, ms(0))?;
        let old_ack = emit_ack(&mut receiver, ms(0))?;
        assert_eq!(emit_source(&mut sender, ms(10))?, original);
        let held_retry = token(&sender, 0)?;
        assert_ne!(held_retry, first);
        sender.receive(&old_ack, ms(10))?;
        assert!(sender.source_confirmed(SourceId(0))?);
        assert_eq!(sender.retained().send_records, 1);
        assert_eq!(sender.retained().send_bytes, payload.len());
        assert_eq!(
            sender
                .0
                .sent
                .get(&SourceId(0))
                .ok_or("missing retained retry")?
                .payload,
            payload
        );
        assert_eq!(sender.pending_transmission(SourceId(0)), Some(held_retry));
        assert!(!sender.drained());
        assert_eq!(sender.poll_source(ms(1_000), &mut [0; 60])?, None);
        assert_eq!(sender.statistics().transmissions, 2);
        assert_eq!(sender.source_deadline(), None);
        sender.confirm_transmission(ms(1_000), held_retry)?;
        assert_eq!(sender.retained().send_records, 0);
        assert_eq!(sender.retained().send_bytes, 0);
        assert!(sender.source_confirmed(SourceId(0))?);
        assert!(sender.drained());
        assert_eq!(
            sender.confirm_transmission(Duration::MAX, held_retry),
            Err(RecoveryError::InvalidTransmission)
        );
        sender.receive(&old_ack, ms(1_000))?;
        assert_eq!(sender.poll_source(ms(1_000), &mut [0; 60])?, None);
        assert!(sender.drained());
        assert_eq!(sender.submit(&[0x55, 0], ms(1_000))?, 1);
    }
    Ok(())
}

#[test]
fn foreign_wrong_and_repeated_tokens_do_not_move_time_or_counters() -> TestResult {
    for reserved in [false, true] {
        let mut owner = make(EndpointRole::Initiator, reserved, true)?;
        let mut foreign = make(EndpointRole::Initiator, reserved, true)?;
        owner.submit(&[0xe1, 0, 0x93], ms(0))?;
        foreign.submit(&[0xe1, 0, 0x93], ms(0))?;
        assert_eq!(
            emit_source(&mut owner, ms(0))?,
            emit_source(&mut foreign, ms(0))?
        );
        let local = token(&owner, 0)?;
        let other = token(&foreign, 0)?;
        assert_ne!(local, other);
        let mut wrong = local;
        wrong.serial += 1;
        let statistics = owner.statistics();
        let retained = owner.retained();
        for invalid in [other, wrong] {
            assert_eq!(
                owner.confirm_transmission(Duration::MAX, invalid),
                Err(RecoveryError::InvalidTransmission)
            );
            assert_eq!(owner.statistics(), statistics);
            assert_eq!(owner.retained(), retained);
            assert_eq!(owner.0.last_now, ms(0));
            assert_eq!(owner.0.pending_transmissions, 1);
            assert_eq!(owner.failure(), None);
        }
        owner.confirm_transmission(ms(5), local)?;
        assert_eq!(owner.source_deadline(), Some(ms(15)));
        assert_eq!(
            owner.confirm_transmission(Duration::MAX, local),
            Err(RecoveryError::InvalidTransmission)
        );
        assert_eq!(owner.0.last_now, ms(5));
        assert_eq!(owner.statistics(), statistics);
        assert_eq!(owner.0.pending_transmissions, 0);
        assert_eq!(owner.failure(), None);
        assert_eq!(owner.poll_source(ms(5), &mut [0; 60])?, None);
    }
    Ok(())
}

#[test]
fn invalid_or_overflowing_physical_time_consumes_custody_and_latches_failure() -> TestResult {
    for reserved in [false, true] {
        for overflow in [false, true] {
            let mut owner = make(EndpointRole::Initiator, reserved, true)?;
            owner.submit(&[0xb7, 0, 0x91], ms(10))?;
            owner.submit(&[0xc8, 0x81, 0], ms(10))?;
            emit_source(&mut owner, ms(10))?;
            let first = token(&owner, 0)?;
            emit_source(&mut owner, ms(10))?;
            let second = token(&owner, 1)?;
            assert_eq!(owner.poll_source(ms(20), &mut [0; 60])?, None);
            let statistics = owner.statistics();
            let retained = owner.retained();
            let (now, expected) = if overflow {
                (Duration::MAX, RecoveryError::TimeOverflow)
            } else {
                (ms(19), RecoveryError::NonMonotonicTime)
            };
            assert_eq!(owner.confirm_transmission(now, first), Err(expected));
            assert_eq!(owner.pending_transmission(SourceId(0)), None);
            assert_eq!(owner.0.pending_transmissions, 1);
            assert_eq!(owner.statistics(), statistics);
            assert_eq!(owner.retained(), retained);
            assert_eq!(owner.failure(), Some(expected));
            assert_eq!(owner.source_confirmed(SourceId(0)), Err(expected));
            assert_eq!(
                owner.confirm_transmission(Duration::MAX, first),
                Err(RecoveryError::InvalidTransmission)
            );
            // A later physical fact must also consume its exact custody even
            // after the first accepted packet latched the timing failure.
            assert_eq!(owner.confirm_transmission(ms(20), second), Err(expected));
            assert_eq!(owner.pending_transmission(SourceId(1)), None);
            assert_eq!(owner.0.pending_transmissions, 0);
            assert_eq!(owner.failure(), Some(expected));
            assert_eq!(owner.poll_source(ms(20), &mut [0; 60]), Err(expected));
            assert!(!owner.drained());
        }
    }
    Ok(())
}

#[test]
fn physical_serial_exhaustion_never_reuses_token_or_changes_output() -> TestResult {
    for reserved in [false, true] {
        let mut owner = make(EndpointRole::Initiator, reserved, true)?;
        owner.submit(&[0xe5, 0], ms(0))?;
        owner.submit(&[0xf6, 0, 0x17], ms(0))?;
        owner.0.next_transmission = u64::MAX - 1;
        emit_source(&mut owner, ms(0))?;
        let last = token(&owner, 0)?;
        assert_eq!(last.serial, u64::MAX);
        owner.confirm_transmission(ms(0), last)?;
        let statistics = owner.statistics();
        let retained = owner.retained();
        let mut output = [0xa5; 60];
        assert_eq!(
            owner.poll_source(ms(0), &mut output),
            Err(RecoveryError::CounterExhausted)
        );
        assert_eq!(output, [0xa5; 60]);
        assert_eq!(owner.statistics(), statistics);
        assert_eq!(owner.retained(), retained);
        assert_eq!(owner.pending_transmission(SourceId(1)), None);
        assert_eq!(owner.0.pending_transmissions, 0);
        assert_eq!(owner.0.next_transmission, u64::MAX);
    }
    Ok(())
}

#[test]
fn delayed_completion_observation_arms_actual_acceptance_time_and_rejects_impossible_intervals()
-> TestResult {
    for reserved in [false, true] {
        let mut owner = make(EndpointRole::Initiator, reserved, true)?;
        owner.submit(&[0xd5, 0, 0x3a, 0], ms(5))?;
        let original = emit_source(&mut owner, ms(5))?;
        let prepared = token(&owner, 0)?;
        assert_eq!(owner.poll_source(ms(30), &mut [0; 60])?, None);
        assert_eq!(owner.source_deadline(), None);
        owner.confirm_transmission_at(ms(35), ms(10), prepared)?;
        assert_eq!(owner.0.last_now, ms(35));
        assert_eq!(owner.source_deadline(), Some(ms(20)));
        assert_eq!(emit_source(&mut owner, ms(35))?, original);
        let retry = token(&owner, 0)?;
        assert_ne!(retry, prepared);
        assert_eq!(owner.statistics().retransmissions, 1);
        assert_eq!(owner.source_deadline(), None);
        owner.confirm_transmission_at(ms(50), ms(40), retry)?;
        assert_eq!(owner.source_deadline(), Some(ms(60)));
        assert_eq!(owner.failure(), None);

        for accepted in [ms(4), ms(36)] {
            let mut owner = make(EndpointRole::Initiator, reserved, true)?;
            owner.submit(&[0xe6, 0, 0xb1], ms(5))?;
            emit_source(&mut owner, ms(5))?;
            let prepared = token(&owner, 0)?;
            assert_eq!(owner.poll_source(ms(30), &mut [0; 60])?, None);
            let statistics = owner.statistics();
            let retained = owner.retained();
            assert_eq!(
                owner.confirm_transmission_at(ms(35), accepted, prepared),
                Err(RecoveryError::NonMonotonicTime)
            );
            assert_eq!(owner.pending_transmission(SourceId(0)), None);
            assert_eq!(owner.0.pending_transmissions, 0);
            assert_eq!(owner.statistics(), statistics);
            assert_eq!(owner.retained(), retained);
            assert_eq!(owner.failure(), Some(RecoveryError::NonMonotonicTime));
            assert_eq!(owner.source_deadline(), None);
            assert_eq!(
                owner.confirm_transmission_at(ms(35), ms(10), prepared),
                Err(RecoveryError::InvalidTransmission)
            );
        }
    }
    Ok(())
}
