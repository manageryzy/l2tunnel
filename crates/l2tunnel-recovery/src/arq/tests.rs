use super::*;

#[test]
fn separate_feedback_and_source_poll_preserve_ownership_and_canonical_inspection()
-> Result<(), RecoveryError> {
    let (mut left, mut right) = pair()?;
    left.submit(b"forward", ms(0))?;
    right.submit(b"reverse", ms(0))?;
    let mut packet = [0_u8; 172];
    assert_eq!(left.poll_feedback(ms(0), &mut packet)?, None);
    assert_eq!(left.statistics().transmissions, 0);
    assert_eq!(left.retained().send_records, 1);
    let length = left
        .poll_source(ms(0), &mut packet)?
        .ok_or(RecoveryError::MalformedPacket)?;
    assert_eq!(
        inspect_packet(&packet[..length], context(EndpointRole::Responder), 128)?,
        PacketView::Data {
            source: SourceId(0),
            payload: b"forward"
        }
    );
    right.receive(&packet[..length], ms(0))?;
    let mut short = [0xa5; ACK_PACKET_BYTES - 1];
    assert_eq!(
        right.poll_feedback(ms(1), &mut short),
        Err(RecoveryError::OutputTooSmall {
            required: ACK_PACKET_BYTES
        })
    );
    assert_eq!(short, [0xa5; ACK_PACKET_BYTES - 1]);
    assert_eq!(right.statistics().transmissions, 0);
    let length = right
        .poll_feedback(ms(1), &mut packet)?
        .ok_or(RecoveryError::MalformedPacket)?;
    assert_eq!(
        inspect_packet(&packet[..length], context(EndpointRole::Initiator), 128)?,
        PacketView::Ack {
            prefix: 1,
            bitmap: 0
        }
    );
    left.receive(&packet[..length], ms(1))?;
    assert_eq!(left.retained().send_records, 0);
    assert_eq!(right.retained().send_records, 1);
    assert_eq!(right.statistics().transmissions, 0);
    let length = right
        .poll_source(ms(1), &mut packet)?
        .ok_or(RecoveryError::MalformedPacket)?;
    assert!(matches!(
        inspect_packet(&packet[..length], context(EndpointRole::Initiator), 128)?,
        PacketView::Data {
            source: SourceId(0),
            payload: b"reverse"
        }
    ));
    assert_eq!(right.statistics().transmissions, 1);
    assert_eq!(right.poll_feedback(ms(1), &mut packet)?, None);
    assert_eq!(
        inspect_packet(&packet[..length], context(EndpointRole::Responder), 128),
        Err(RecoveryError::WrongContext)
    );
    assert_eq!(
        inspect_packet(&packet[..length], context(EndpointRole::Initiator), 0),
        Err(RecoveryError::InvalidConfig)
    );
    for truncated in 0..length {
        assert!(
            inspect_packet(&packet[..truncated], context(EndpointRole::Initiator), 128).is_err()
        );
    }
    Ok(())
}

fn config() -> ArqConfig {
    ArqConfig {
        max_source_bytes: 128,
        send_bytes: 4_096,
        receive_bytes: 4_096,
        send_records: 32,
        receive_records: 32,
        initial_rto: Duration::from_millis(10),
        maximum_rto: Duration::from_millis(80),
        ack_delay: Duration::from_millis(1),
        max_retries: 12,
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

fn pair() -> Result<(SelectiveRepeat, SelectiveRepeat), RecoveryError> {
    Ok((
        SelectiveRepeat::new(config(), context(EndpointRole::Initiator))?,
        SelectiveRepeat::new(config(), context(EndpointRole::Responder))?,
    ))
}

fn emit<E: RecoveryEngine<Error = RecoveryError>>(
    engine: &mut E,
    now: Duration,
) -> Result<Vec<u8>, RecoveryError> {
    let mut packet = vec![0; 1_024];
    let size = engine
        .poll(now, &mut packet)?
        .ok_or(RecoveryError::MalformedPacket)?;
    packet.truncate(size);
    Ok(packet)
}

fn ack(prefix: u64, bitmap: u64) -> Vec<u8> {
    let mut packet = vec![0; ACK_PACKET_BYTES];
    write_common(
        &mut packet,
        context(EndpointRole::Responder),
        Profile::Selective,
        2,
    );
    packet[32..40].copy_from_slice(&prefix.to_be_bytes());
    packet[40..48].copy_from_slice(&bitmap.to_be_bytes());
    packet
}

#[test]
fn exact_payload_delivery_and_small_buffers_preserve_ownership() -> Result<(), RecoveryError> {
    let (mut sender, mut receiver) = pair()?;
    let payload = [0, 255, 9, 3, 1, 128, 10];
    assert_eq!(sender.submit(&payload, ms(0))?, 0);
    assert_eq!(
        sender.poll(ms(0), &mut [0; 4]),
        Err(RecoveryError::OutputTooSmall {
            required: DATA_HEADER_BYTES + payload.len()
        })
    );
    assert_eq!(sender.statistics().transmissions, 0);
    let packet = emit(&mut sender, ms(0))?;
    receiver.receive(&packet, ms(0))?;
    assert_eq!(
        receiver.poll_delivered(&mut [0; 6]),
        Err(RecoveryError::OutputTooSmall {
            required: payload.len()
        })
    );
    assert_eq!(receiver.retained().receive_bytes, payload.len());
    let mut output = [0; 128];
    assert_eq!(
        receiver.poll_delivered(&mut output)?,
        Some((0, payload.len()))
    );
    assert_eq!(&output[..payload.len()], &payload);
    assert_eq!(receiver.poll_delivered(&mut output)?, None);
    assert_eq!(receiver.poll(ms(0), &mut [0; 128])?, None);
    assert_eq!(receiver.deadline(), Some(ms(1)));
    assert_eq!(
        receiver.poll(ms(1), &mut [0; ACK_PACKET_BYTES - 1]),
        Err(RecoveryError::OutputTooSmall {
            required: ACK_PACKET_BYTES
        })
    );
    assert_eq!(receiver.deadline(), Some(ms(1)));
    sender.receive(&emit(&mut receiver, ms(1))?, ms(1))?;
    assert!(sender.drained());
    assert!(receiver.drained());
    Ok(())
}

#[test]
fn truncation_context_profile_and_trailing_data_are_rejected() -> Result<(), RecoveryError> {
    let (mut sender, mut receiver) = pair()?;
    sender.submit(b"nonzero payload", ms(0))?;
    let packet = emit(&mut sender, ms(0))?;
    for length in 0..packet.len() {
        assert!(receiver.receive(&packet[..length], ms(0)).is_err());
    }
    let mut trailing = packet.clone();
    trailing.push(0);
    assert_eq!(
        receiver.receive(&trailing, ms(0)),
        Err(RecoveryError::MalformedPacket)
    );
    for offset in [7, 8, 24] {
        let mut wrong = packet.clone();
        wrong[offset] ^= 1;
        assert_eq!(
            receiver.receive(&wrong, ms(0)),
            Err(RecoveryError::WrongContext)
        );
    }
    let mut wrong = packet.clone();
    wrong[5] = Profile::CarrierOnly.code();
    assert_eq!(
        receiver.receive(&wrong, ms(0)),
        Err(RecoveryError::WrongProfile)
    );
    wrong = packet.clone();
    wrong[4] = 2;
    assert_eq!(
        receiver.receive(&wrong, ms(0)),
        Err(RecoveryError::MalformedPacket)
    );
    wrong = packet.clone();
    wrong[32..40].copy_from_slice(&u64::MAX.to_be_bytes());
    assert_eq!(
        receiver.receive(&wrong, ms(0)),
        Err(RecoveryError::CounterExhausted)
    );
    assert_eq!(receiver.retained(), Retained::default());
    receiver.receive(&packet, ms(0))?;
    Ok(())
}

#[test]
fn future_unsent_and_noncanonical_acknowledgements_cannot_free_payload() -> Result<(), RecoveryError>
{
    let (mut sender, _) = pair()?;
    sender.submit(b"pending", ms(0))?;
    assert_eq!(
        sender.receive(&ack(1, 0), ms(0)),
        Err(RecoveryError::UnsentAcknowledgement)
    );
    emit(&mut sender, ms(0))?;
    let complete_ack = ack(1, 0);
    for length in 0..complete_ack.len() {
        assert!(sender.receive(&complete_ack[..length], ms(0)).is_err());
        assert_eq!(sender.retained().send_bytes, 7);
    }
    assert_eq!(
        sender.receive(&ack(2, 0), ms(0)),
        Err(RecoveryError::UnsentAcknowledgement)
    );
    assert_eq!(
        sender.receive(&ack(0, 1_u64 << 63), ms(0)),
        Err(RecoveryError::UnsentAcknowledgement)
    );
    assert_eq!(
        sender.receive(&ack(0, 1), ms(0)),
        Err(RecoveryError::MalformedPacket)
    );
    assert_eq!(sender.retained().send_bytes, 7);
    sender.receive(&ack(1, 0), ms(0))?;
    sender.receive(&ack(0, 0), ms(0))?;
    sender.receive(&ack(1, 0), ms(0))?;
    assert_eq!(sender.retained().send_bytes, 0);
    Ok(())
}

#[test]
fn conflicting_duplicates_fail_and_delivered_ids_never_return() -> Result<(), RecoveryError> {
    let (mut sender, mut receiver) = pair()?;
    sender.submit(b"same bytes", ms(0))?;
    let packet = emit(&mut sender, ms(0))?;
    receiver.receive(&packet, ms(0))?;
    receiver.receive(&packet, ms(0))?;
    let mut conflicting = packet.clone();
    conflicting[DATA_HEADER_BYTES] ^= 1;
    assert_eq!(
        receiver.receive(&conflicting, ms(0)),
        Err(RecoveryError::ConflictingDuplicate)
    );
    receiver.poll_delivered(&mut [0; 128])?;
    receiver.receive(&packet, ms(0))?;
    assert_eq!(receiver.poll_delivered(&mut [0; 128])?, None);
    assert_eq!(receiver.statistics().received_unique, 1);
    assert_eq!(receiver.statistics().duplicates, 2);
    Ok(())
}

#[test]
fn timeout_backoff_and_finite_exhaustion_are_explicit() -> Result<(), RecoveryError> {
    let mut settings = config();
    settings.maximum_rto = ms(25);
    settings.max_retries = 2;
    let mut sender = SelectiveRepeat::new(settings, context(EndpointRole::Initiator))?;
    sender.submit(b"lost", ms(0))?;
    let first = emit(&mut sender, ms(0))?;
    assert_eq!(sender.deadline(), Some(ms(10)));
    assert_eq!(sender.poll(ms(9), &mut [0; 128])?, None);
    assert_eq!(emit(&mut sender, ms(10))?, first);
    assert_eq!(sender.deadline(), Some(ms(30)));
    assert_eq!(emit(&mut sender, ms(30))?, first);
    assert_eq!(sender.deadline(), Some(ms(55)));
    let exhausted = RecoveryError::RetryExhausted {
        source: SourceId(0),
    };
    assert_eq!(sender.poll(ms(55), &mut [0; 128]), Err(exhausted));
    assert_eq!(sender.failure(), Some(exhausted));
    assert_eq!(sender.submit(b"new", ms(56)), Err(exhausted));
    assert_eq!(sender.deadline(), None);
    assert!(!sender.drained());
    assert_eq!(sender.statistics().transmissions, 3);
    assert_eq!(sender.statistics().retransmissions, 2);
    assert_eq!(sender.retained().send_bytes, 4);
    Ok(())
}

#[test]
fn lost_final_ack_recovers_after_application_delivery() -> Result<(), RecoveryError> {
    let (mut sender, mut receiver) = pair()?;
    sender.submit(b"tail", ms(0))?;
    receiver.receive(&emit(&mut sender, ms(0))?, ms(0))?;
    receiver.poll_delivered(&mut [0; 128])?;
    let _lost_ack = emit(&mut receiver, ms(1))?;
    receiver.receive(&emit(&mut sender, ms(10))?, ms(10))?;
    assert_eq!(receiver.poll_delivered(&mut [0; 128])?, None);
    sender.receive(&emit(&mut receiver, ms(11))?, ms(11))?;
    assert!(sender.drained());
    assert!(receiver.drained());
    assert_eq!(receiver.statistics().delivered, 1);
    assert_eq!(receiver.statistics().duplicates, 1);
    Ok(())
}

#[test]
fn selective_ack_holes_do_not_expand_the_send_span() -> Result<(), RecoveryError> {
    let mut settings = config();
    settings.send_records = 2;
    let mut sender = SelectiveRepeat::new(settings, context(EndpointRole::Initiator))?;
    let mut receiver = SelectiveRepeat::new(settings, context(EndpointRole::Responder))?;
    sender.submit(b"zero", ms(0))?;
    sender.submit(b"one", ms(0))?;
    let zero = emit(&mut sender, ms(0))?;
    receiver.receive(&emit(&mut sender, ms(0))?, ms(0))?;
    let selective = emit(&mut receiver, ms(1))?;
    assert_eq!(u64::from_be_bytes(field(&selective, 32)?), 0);
    assert_eq!(u64::from_be_bytes(field(&selective, 40)?), 2);
    sender.receive(&selective, ms(1))?;
    assert_eq!(sender.retained().send_records, 1);
    let gate = sender.admission_snapshot(3)?;
    assert_eq!((gate.records, gate.records_capacity), (1, 2));
    assert!(!gate.records_full && !gate.bytes_full && gate.sequence_full);
    assert_eq!(
        (gate.next_source, gate.span_base),
        (SourceId(2), Some(SourceId(0)))
    );
    let oldest = gate.oldest.ok_or(RecoveryError::MalformedPacket)?;
    assert_eq!(
        (oldest.source, oldest.attempts, oldest.acknowledged),
        (SourceId(0), 1, false)
    );
    assert_eq!(
        sender.submit(b"two", ms(1)),
        Err(RecoveryError::SequenceWindow)
    );
    receiver.receive(&zero, ms(1))?;
    sender.receive(&emit(&mut receiver, ms(2))?, ms(2))?;
    let released = sender.admission_snapshot(3)?;
    assert_eq!(
        (released.records, released.span_base, released.oldest),
        (0, None, None)
    );
    assert!(!released.records_full && !released.bytes_full && !released.sequence_full);
    assert_eq!(sender.submit(b"two", ms(2))?, 2);
    Ok(())
}

#[test]
fn source_bytes_counts_and_receiver_backpressure_are_bounded() -> Result<(), RecoveryError> {
    let mut settings = config();
    settings.max_source_bytes = 8;
    settings.send_bytes = 16;
    settings.receive_bytes = 8;
    settings.send_records = 3;
    let mut sender = SelectiveRepeat::new(settings, context(EndpointRole::Initiator))?;
    let mut receiver = SelectiveRepeat::new(settings, context(EndpointRole::Responder))?;
    assert_eq!(
        sender.submit(&[1; 9], ms(0)),
        Err(RecoveryError::SourceTooLarge)
    );
    sender.submit(&[1; 8], ms(0))?;
    sender.submit(&[2; 8], ms(0))?;
    sender.submit(&[], ms(0))?;
    assert_eq!(
        sender.submit(&[], ms(0)),
        Err(RecoveryError::Capacity(BufferSide::Send))
    );
    receiver.receive(&emit(&mut sender, ms(0))?, ms(0))?;
    let second = emit(&mut sender, ms(0))?;
    assert_eq!(
        receiver.receive(&second, ms(0)),
        Err(RecoveryError::Capacity(BufferSide::Receive))
    );
    assert_eq!(receiver.retained().receive_bytes, 8);
    receiver.poll_delivered(&mut [0; 8])?;
    receiver.receive(&second, ms(0))?;
    assert_eq!(receiver.retained().receive_bytes, 8);
    Ok(())
}

#[test]
fn highest_bitmap_bit_and_reorder_window_are_bounded() -> Result<(), RecoveryError> {
    let mut settings = config();
    settings.send_records = 64;
    settings.receive_records = 64;
    let mut sender = SelectiveRepeat::new(settings, context(EndpointRole::Initiator))?;
    let mut receiver = SelectiveRepeat::new(settings, context(EndpointRole::Responder))?;
    let mut last = Vec::new();
    for id in 0..64 {
        sender.submit(&[id], ms(0))?;
        last = emit(&mut sender, ms(0))?;
    }
    receiver.receive(&last, ms(0))?;
    let feedback = emit(&mut receiver, ms(1))?;
    assert_eq!(u64::from_be_bytes(field(&feedback, 40)?), 1_u64 << 63);
    sender.receive(&feedback, ms(1))?;
    assert_eq!(sender.retained().send_records, 63);
    last[32..40].copy_from_slice(&64_u64.to_be_bytes());
    assert_eq!(
        receiver.receive(&last, ms(1)),
        Err(RecoveryError::SequenceWindow)
    );
    assert_eq!(receiver.retained().receive_records, 1);
    Ok(())
}

#[test]
fn due_feedback_cannot_starve_ready_data() -> Result<(), RecoveryError> {
    let (mut left, mut right) = pair()?;
    left.submit(b"left", ms(0))?;
    right.submit(b"right", ms(0))?;
    let incoming = emit(&mut left, ms(0))?;
    right.receive(&incoming, ms(0))?;
    assert_eq!(emit(&mut right, ms(1))?[6], 2);
    right.receive(&incoming, ms(1))?;
    assert_eq!(emit(&mut right, ms(2))?[6], 1);
    Ok(())
}

#[test]
fn carrier_only_is_explicit_and_never_retries_or_acks() -> Result<(), RecoveryError> {
    let mut left = CarrierOnly::new(config(), context(EndpointRole::Initiator))?;
    let mut right = CarrierOnly::new(config(), context(EndpointRole::Responder))?;
    left.submit(b"first", ms(0))?;
    left.submit(b"second", ms(0))?;
    let first = emit(&mut left, ms(0))?;
    let second = emit(&mut left, ms(0))?;
    assert!(left.drained());
    assert_eq!(left.deadline(), None);
    assert_eq!(left.poll(ms(100), &mut [0; 128])?, None);
    assert_eq!(
        right.receive(&second, ms(0)),
        Err(RecoveryError::UnexpectedSequence)
    );
    right.receive(&first, ms(0))?;
    right.receive(&second, ms(0))?;
    assert_eq!(right.poll(ms(100), &mut [0; 128])?, None);
    assert_eq!(right.statistics().feedback_sent, 0);
    let mut output = [0; 128];
    assert_eq!(right.poll_delivered(&mut output)?, Some((0, 5)));
    assert_eq!(&output[..5], b"first");
    assert_eq!(right.poll_delivered(&mut output)?, Some((1, 6)));
    assert_eq!(&output[..6], b"second");
    assert!(right.drained());
    Ok(())
}

#[test]
fn time_regression_overflow_and_invalid_configuration_are_explicit() -> Result<(), RecoveryError> {
    let (mut sender, _) = pair()?;
    sender.submit(b"valid", ms(5))?;
    assert_eq!(
        sender.poll(ms(4), &mut [0; 128]),
        Err(RecoveryError::NonMonotonicTime)
    );
    assert_eq!(sender.statistics().transmissions, 0);
    let mut settings = config();
    settings.initial_rto = Duration::MAX;
    settings.maximum_rto = Duration::MAX;
    let mut sender = SelectiveRepeat::new(settings, context(EndpointRole::Initiator))?;
    sender.submit(b"valid", ms(1))?;
    assert_eq!(
        sender.poll(ms(1), &mut [0; 128]),
        Err(RecoveryError::TimeOverflow)
    );
    assert_eq!(sender.statistics().transmissions, 0);
    settings.send_records = 65;
    assert!(matches!(
        SelectiveRepeat::new(settings, context(EndpointRole::Initiator)),
        Err(RecoveryError::InvalidConfig)
    ));
    Ok(())
}

#[test]
fn independent_engines_recover_bidirectional_bytes_over_loss_reorder_and_duplicates()
-> Result<(), RecoveryError> {
    let (mut left, mut right) = pair()?;
    let expected_left: Vec<Vec<u8>> = (0..12)
        .map(|source| {
            (0..source * 3)
                .map(|offset| (source * 31 + offset * 17) as u8)
                .collect()
        })
        .collect();
    let expected_right: Vec<Vec<u8>> = (0..12)
        .map(|source| {
            (0..source * 2 + 1)
                .map(|offset| (source * 13 + offset * 29) as u8)
                .collect()
        })
        .collect();
    for payload in &expected_left {
        left.submit(payload, ms(0))?;
    }
    for payload in &expected_right {
        right.submit(payload, ms(0))?;
    }
    let mut network: Vec<(u64, bool, Vec<u8>)> = Vec::new();
    let mut emitted = 0_u64;
    let mut left_delivered = Vec::new();
    let mut right_delivered = Vec::new();
    let mut packets_dropped = 0;
    let mut packets_duplicated = 0;
    for tick in 0..2_000 {
        for (to_right, engine) in [(true, &mut left), (false, &mut right)] {
            for _ in 0..2 {
                let mut packet = vec![0; engine.max_packet_bytes()];
                let Some(size) = engine.poll(ms(tick), &mut packet)? else {
                    break;
                };
                packet.truncate(size);
                emitted += 1;
                if tick < 200 && emitted.is_multiple_of(5) {
                    packets_dropped += 1;
                    continue;
                }
                let due = tick + 1 + (emitted * 7) % 11;
                if emitted.is_multiple_of(4) {
                    network.push((due + 3, to_right, packet.clone()));
                    packets_duplicated += 1;
                }
                network.push((due, to_right, packet));
            }
        }
        // Reverse removal order intentionally delivers ready packets out of order.
        for index in (0..network.len()).rev() {
            if network[index].0 <= tick {
                let (_, to_right, packet) = network.swap_remove(index);
                if to_right {
                    right.receive(&packet, ms(tick))?;
                } else {
                    left.receive(&packet, ms(tick))?;
                }
            }
        }
        for (engine, delivered) in [
            (&mut left, &mut left_delivered),
            (&mut right, &mut right_delivered),
        ] {
            let mut output = [0; 128];
            while let Some((source, length)) = engine.poll_delivered(&mut output)? {
                assert_eq!(source, delivered.len() as u64);
                delivered.push(output[..length].to_vec());
            }
        }
        if network.is_empty() && left.drained() && right.drained() {
            break;
        }
    }
    assert_eq!(right_delivered, expected_left);
    assert_eq!(left_delivered, expected_right);
    assert!(left.drained() && right.drained());
    assert!(packets_dropped > 0 && packets_duplicated > 0);
    assert!(left.statistics().retransmissions + right.statistics().retransmissions > 0);
    assert!(left.statistics().duplicates + right.statistics().duplicates > 0);
    assert_eq!(left.retained(), Retained::default());
    assert_eq!(right.retained(), Retained::default());
    Ok(())
}

#[test]
fn source_confirmation_requires_the_exact_allocated_peer_receipt() -> Result<(), RecoveryError> {
    let (mut left, mut right) = pair()?;
    assert!(!left.source_confirmed(SourceId(0))?);
    left.submit(b"first\0\0", ms(0))?;
    left.submit(b"second\0", ms(0))?;
    assert!(!left.source_confirmed(SourceId(0))?);
    assert_eq!(
        left.receive(&ack(1, 0), ms(0)),
        Err(RecoveryError::UnsentAcknowledgement)
    );
    let mut packet = [0; 256];
    let first = left
        .poll_source(ms(0), &mut packet)?
        .ok_or(RecoveryError::MalformedPacket)?;
    let first = packet[..first].to_vec();
    let second = left
        .poll_source(ms(0), &mut packet)?
        .ok_or(RecoveryError::MalformedPacket)?;
    right.receive(&packet[..second], ms(0))?;
    assert!(!left.source_confirmed(SourceId(0))?);
    assert!(!left.source_confirmed(SourceId(1))?);
    let receipt = right
        .poll_feedback(ms(1), &mut packet)?
        .ok_or(RecoveryError::MalformedPacket)?;
    left.receive(&packet[..receipt], ms(1))?;
    assert!(!left.source_confirmed(SourceId(0))?);
    assert!(left.source_confirmed(SourceId(1))?);
    assert!(!left.source_confirmed(SourceId(2))?);
    assert!(!left.source_confirmed(SourceId(u64::MAX))?);
    let retained = left.retained();
    assert_eq!(
        left.receive(&ack(3, 0), ms(1)),
        Err(RecoveryError::UnsentAcknowledgement)
    );
    assert_eq!(left.retained(), retained);
    assert!(!left.source_confirmed(SourceId(0))?);
    right.receive(&first, ms(1))?;
    let receipt = right
        .poll_feedback(ms(2), &mut packet)?
        .ok_or(RecoveryError::MalformedPacket)?;
    left.receive(&packet[..receipt], ms(2))?;
    let stats = left.statistics();
    assert!(left.source_confirmed(SourceId(0))?);
    assert!(left.source_confirmed(SourceId(1))?);
    assert_eq!(left.statistics(), stats);
    Ok(())
}

#[test]
fn retry_failure_cannot_be_observed_as_confirmed_custody() -> Result<(), RecoveryError> {
    let mut policy = config();
    policy.max_retries = 0;
    let mut sender = SelectiveRepeat::new(policy, context(EndpointRole::Initiator))?;
    sender.submit(b"lost final command", ms(0))?;
    let mut packet = [0; 256];
    assert!(sender.poll_source(ms(0), &mut packet)?.is_some());
    assert!(!sender.source_confirmed(SourceId(0))?);
    let error = sender
        .poll_source(ms(10), &mut packet)
        .err()
        .ok_or(RecoveryError::MalformedPacket)?;
    assert!(matches!(error, RecoveryError::RetryExhausted { .. }));
    assert_eq!(sender.source_confirmed(SourceId(0)), Err(error));
    assert_eq!(sender.source_confirmed(SourceId(1)), Err(error));
    Ok(())
}
