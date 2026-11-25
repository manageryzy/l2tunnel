use super::*;
mod kcp_like;
type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;
fn ms(value: u64) -> Duration {
    Duration::from_millis(value)
}
fn context(role: EndpointRole) -> RecoveryContext {
    RecoveryContext {
        session: 0x0102,
        epoch: 7,
        role,
    }
}
fn config(
    mode: CompactRecovery,
    window: usize,
    history: usize,
    feedback_bytes: usize,
) -> std::result::Result<CompactArqConfig, RecoveryError> {
    CompactArqConfig::new(
        CompactBounds {
            max_source_bytes: 8,
            send_bytes: window * 8,
            receive_bytes: window * 8,
            send_records: window,
            receive_records: window,
        },
        CompactTiming {
            nominal_rtt: ms(70),
            feedback_interval: ms(5),
            feedback_packets: 64,
        },
        feedback_bytes,
        history,
        8,
        mode,
    )
}
fn pair(mode: CompactRecovery) -> Result<(CompactRepeat, CompactRepeat)> {
    let policy = config(mode, 16, 64, 78)?;
    Ok((
        CompactRepeat::new(policy, context(EndpointRole::Initiator))?,
        CompactRepeat::new(policy, context(EndpointRole::Responder))?,
    ))
}
fn emit(
    owner: &mut CompactRepeat,
    now: Duration,
    accepted: Duration,
    bytes: &[u8],
) -> Result<Vec<u8>> {
    let source = SourceId(owner.submit(bytes, now)?);
    let mut packet = vec![0; owner.send_max_packet_bytes()];
    let size = owner.poll_source(now, &mut packet)?.ok_or("source")?;
    let token = owner.pending_transmission(source).ok_or("physical token")?;
    owner.confirm_transmission_at(accepted, accepted, token)?;
    packet.truncate(size);
    Ok(packet)
}
fn feedback(owner: &mut CompactRepeat, now: Duration) -> Result<Vec<u8>> {
    let mut out = vec![0; owner.send_max_packet_bytes()];
    let size = owner.poll_feedback(now, &mut out)?.ok_or("feedback")?;
    out.truncate(size);
    Ok(out)
}

#[test]
fn v2_exact_fields_full64_parser_and_physical_timer_from_original_acceptance() -> Result {
    let policy = config(CompactRecovery::Guarded, 16, 64, 78)?;
    let mut sender = CompactRepeat::new(policy, context(EndpointRole::Initiator))?;
    sender.submit(b"real", Duration::ZERO)?;
    let mut packet = [0xaa; 128];
    let size = sender
        .poll_source(Duration::ZERO, &mut packet)?
        .ok_or("source")?;
    assert_eq!(size, 56);
    assert_eq!(&packet[..8], b"L2AR\x02\x01\x01\x00");
    assert_eq!(&packet[8..24], &0x0102_u128.to_be_bytes());
    assert_eq!(&packet[24..32], &7_u64.to_be_bytes());
    assert_eq!(&packet[32..40], &0_u64.to_be_bytes());
    assert_eq!(&packet[40..48], &1_u64.to_be_bytes());
    assert_eq!(&packet[48..52], &4_u32.to_be_bytes());
    assert_eq!(&packet[52..56], b"real");
    let first = sender
        .pending_transmission(SourceId(0))
        .ok_or("physical token")?;
    assert_eq!(sender.deadline(), None);
    assert_eq!(sender.poll_source(ms(3000), &mut packet)?, None);
    sender.confirm_transmission_at(ms(4000), ms(3000), first)?;
    assert_eq!(sender.source_deadline(), Some(ms(3150)));
    assert_eq!(
        sender.confirm_transmission(ms(4000), first),
        Err(RecoveryError::InvalidTransmission)
    );
    sender
        .poll_source(ms(4000), &mut packet)?
        .ok_or("already due retry")?;
    assert_eq!(u64::from_be_bytes(field(&packet, 40)?), 2);
    assert_eq!(sender.statistics().retransmissions, 1);
    packet[7] = 1;
    packet[32..40].copy_from_slice(&(u64::MAX - 1).to_be_bytes());
    packet[40..48].copy_from_slice(&u64::MAX.to_be_bytes());
    assert!(
        matches!(inspect_compact_packet(&packet[..size], context(EndpointRole::Initiator), policy)?,
        CompactPacketView::Data { source: SourceId(value), serial: u64::MAX, payload: b"real" } if value == u64::MAX - 1)
    );
    packet[4] = 1;
    assert_eq!(
        inspect_compact_packet(&packet[..size], context(EndpointRole::Initiator), policy),
        Err(RecoveryError::MalformedPacket)
    );
    Ok(())
}

#[test]
fn held_physical_feedback_is_transactional_then_original_arrival_samples_receiver_delay() -> Result
{
    let (mut sender, mut receiver) = pair(CompactRecovery::Guarded)?;
    sender.submit(b"source", Duration::ZERO)?;
    let mut packet = [0; 128];
    let size = sender
        .poll_source(Duration::ZERO, &mut packet)?
        .ok_or("source")?;
    let token = sender
        .pending_transmission(SourceId(0))
        .ok_or("physical token")?;
    receiver.receive(&packet[..size], ms(40))?;
    let ack = feedback(&mut receiver, ms(45))?;
    assert_eq!(ack.len(), 76);
    assert_eq!(&ack[..8], b"L2AR\x02\x01\x02\x01");
    assert_eq!(&ack[32..40], &1_u64.to_be_bytes());
    assert_eq!(&ack[40..48], &1_u64.to_be_bytes());
    assert_eq!(&ack[48..52], &[0; 4]);
    assert_eq!(&ack[52..60], &1_u64.to_be_bytes());
    assert_eq!(&ack[60..68], &5000_u64.to_be_bytes());
    assert_eq!(&ack[68..76], &1_u64.to_be_bytes());
    let before = (sender.timing()?, sender.retained(), sender.statistics());
    assert_eq!(
        sender.receive_at(&ack, ms(110), ms(150)),
        Err(RecoveryError::FeedbackAwaitingPhysical)
    );
    assert_eq!(
        (sender.timing()?, sender.retained(), sender.statistics()),
        before
    );
    sender.confirm_transmission_at(ms(150), ms(10), token)?;
    sender.receive_at(&ack, ms(110), ms(150))?;
    let timing = sender.timing()?;
    assert_eq!(timing.sampled_serial, 1);
    assert!((timing.srtt_seconds.ok_or("sample")? - 0.095).abs() < 1e-15);
    assert!((timing.rttvar_seconds - 0.0475).abs() < 1e-15);
    assert!(timing.rto.abs_diff(ms(295)) <= Duration::from_nanos(1));
    assert!(sender.source_confirmed(SourceId(0))?);
    assert_eq!(sender.retained().send_records, 0);
    assert_eq!(sender.statistics().transmissions, 1);
    assert_eq!(delay_micros(Duration::from_nanos(2500))?, 2);
    assert_eq!(delay_micros(Duration::from_nanos(3500))?, 4);
    Ok(())
}

#[test]
fn exactly_three_later_bits_first_flight_once_and_stale_feedback_new_echo() -> Result {
    for mode in [CompactRecovery::Guarded, CompactRecovery::FirstFlight] {
        let (mut sender, mut receiver) = pair(mode)?;
        let packets = (0..4)
            .map(|index| emit(&mut sender, Duration::ZERO, Duration::ZERO, &[index]))
            .collect::<Result<Vec<_>>>()?;
        receiver.receive(&packets[1], ms(30))?;
        receiver.receive(&packets[2], ms(30))?;
        let two = feedback(&mut receiver, ms(35))?;
        sender.receive(&two, ms(70))?;
        let mut out = [0; 128];
        assert_eq!(sender.poll_source(ms(70), &mut out)?, None);
        receiver.receive(&packets[3], ms(36))?;
        let three = feedback(&mut receiver, ms(40))?;
        // Last receipt retained the original repeat deadline at40ms.
        sender.receive(&three, ms(75))?;
        let retry = sender.poll_source(ms(75), &mut out)?;
        if mode == CompactRecovery::Guarded {
            assert_eq!(retry, None);
            assert!(sender.poll_source(ms(90), &mut out)?.is_none());
        } else {
            let size = retry.ok_or("initial-flight exemption")?;
            assert!(matches!(
                inspect_compact_packet(
                    &out[..size],
                    context(EndpointRole::Responder),
                    config(mode, 16, 64, 78)?
                )?,
                CompactPacketView::Data {
                    source: SourceId(0),
                    serial: 5,
                    ..
                }
            ));
            let token = sender
                .pending_transmission(SourceId(0))
                .ok_or("retry receipt")?;
            sender.confirm_transmission(ms(75), token)?;
            sender.receive(&three, ms(80))?;
            assert_eq!(sender.poll_source(ms(80), &mut out)?, None);
            receiver.receive(&out[..size], ms(90))?;
            let mut newer_echo = feedback(&mut receiver, ms(95))?;
            // Positive confirmations and a newer unambiguous RTT echo remain
            // valid even when the feedback output serial is stale.
            newer_echo[68..76].copy_from_slice(&1_u64.to_be_bytes());
            sender.receive(&newer_echo, ms(130))?;
            assert_eq!(sender.timing()?.sampled_serial, 5);
            assert!(sender.source_confirmed(SourceId(0))?);
            assert_eq!(sender.statistics().retransmissions, 1);
        }
    }
    Ok(())
}

fn incoming(config: CompactArqConfig, source: u64, serial: u64, payload: &[u8]) -> Result<Vec<u8>> {
    let descriptor = CompactPacketView::Data {
        source: SourceId(source),
        serial,
        payload,
    };
    let mut bytes = vec![0; descriptor.legacy_encoded_len()?];
    descriptor.encode_legacy_into(
        context(EndpointRole::Initiator),
        config.recovery(),
        &mut bytes,
    )?;
    Ok(bytes)
}

#[test]
fn rotating_feedback_reaches8192_and_keeps_three_charged_tail_reports_and_strict_padding() -> Result
{
    let policy = config(CompactRecovery::Guarded, 8192, 4, 77)?;
    let mut receiver = CompactRepeat::new(policy, context(EndpointRole::Responder))?;
    let source = incoming(policy, 8191, u64::MAX, b"last")?;
    receiver.receive(&source, Duration::ZERO)?;
    let usage = receiver.storage_usage().ok_or("reserved usage")?;
    let mut now = ms(5);
    for chunk in 0..1024_u64 {
        if chunk != 0 {
            receiver.receive(&source, now)?;
        }
        let bytes = feedback(&mut receiver, now)?;
        let CompactPacketView::Feedback(parsed) =
            inspect_compact_packet(&bytes, context(EndpointRole::Initiator), policy)?
        else {
            return Err("feedback kind".into());
        };
        assert_eq!(parsed.start, chunk * 8);
        assert_eq!(parsed.count, 8);
        assert_eq!(parsed.echo, u64::MAX);
        assert_eq!(
            parsed.bitmap,
            if chunk == 1023 { &[0x80][..] } else { &[0][..] }
        );
        now += ms(5);
        assert_eq!(receiver.storage_usage(), Some(usage));
    }
    // Last duplicate arms one current and two additional ordinary lossy reports.
    feedback(&mut receiver, now)?;
    now += ms(5);
    feedback(&mut receiver, now)?;
    assert_eq!(receiver.poll_feedback(now + ms(5), &mut [0; 128])?, None);
    assert_eq!(receiver.statistics().feedback_sent, 1026);
    assert_eq!(receiver.retained().receive_records, 1);
    let mut invalid = feedback_bytes(policy, 0, 1, 1, &[2])?;
    assert_eq!(
        inspect_compact_packet(&invalid, context(EndpointRole::Initiator), policy),
        Err(RecoveryError::MalformedPacket)
    );
    invalid = feedback_bytes(policy, 0, 1, 1, &[1])?;
    invalid[50] = 1;
    assert_eq!(
        inspect_compact_packet(&invalid, context(EndpointRole::Initiator), policy),
        Err(RecoveryError::MalformedPacket)
    );
    Ok(())
}
fn feedback_bytes(
    config: CompactArqConfig,
    prefix: u64,
    start: u64,
    count: u16,
    bitmap: &[u8],
) -> Result<Vec<u8>> {
    let descriptor = CompactPacketView::Feedback(CompactFeedback {
        prefix,
        start,
        count: 0,
        echo: 0,
        receiver_delay_us: 0,
        serial: 1,
        bitmap: &[],
    });
    let mut bytes = vec![0; descriptor.legacy_encoded_len()?];
    descriptor.encode_legacy_into(
        context(EndpointRole::Responder),
        config.recovery(),
        &mut bytes,
    )?;
    // Start with the shared canonical header, then inject the requested bitmap
    // verbatim so malformed padding remains a parser test, not an encode refusal.
    bytes[48..50].copy_from_slice(&count.to_be_bytes());
    bytes.extend_from_slice(bitmap);
    Ok(bytes)
}

#[test]
fn history_refusal_does_not_burn_output_attempt_or_serial_and_attempt_limit_is_honest() -> Result {
    let policy = config(CompactRecovery::Guarded, 16, 1, 78)?;
    let mut sender = CompactRepeat::new(policy, context(EndpointRole::Initiator))?;
    let first = emit(&mut sender, Duration::ZERO, Duration::ZERO, b"one")?;
    sender.submit(b"two", Duration::ZERO)?;
    let mut out = [0xaa; 128];
    let before = sender.statistics();
    assert_eq!(
        sender.poll_source(Duration::ZERO, &mut out),
        Err(RecoveryError::HistoryCapacity)
    );
    assert_eq!(out, [0xaa; 128]);
    assert_eq!(sender.statistics(), before);
    assert_eq!(sender.pending_transmission(SourceId(1)), None);
    let mut receiver = CompactRepeat::new(policy, context(EndpointRole::Responder))?;
    receiver.receive(&first, ms(1))?;
    sender.receive(&feedback(&mut receiver, ms(6))?, ms(10))?;
    let size = sender
        .poll_source(ms(10), &mut out)?
        .ok_or("history released")?;
    assert!(matches!(
        inspect_compact_packet(&out[..size], context(EndpointRole::Responder), policy)?,
        CompactPacketView::Data {
            source: SourceId(1),
            serial: 2,
            ..
        }
    ));
    let bounded = CompactArqConfig::new(
        policy.bounds(),
        policy.timing(),
        78,
        4,
        1,
        CompactRecovery::Guarded,
    )?;
    let plan = crate::storage::CompactPlan::for_compact(bounded, bounded)?;
    assert!(matches!(
        CompactRepeat::new_duplex_reserved(
            bounded,
            bounded,
            context(EndpointRole::Initiator),
            crate::storage::Limits {
                capacity_bytes: plan.capacity_bytes() - 1
            }
        ),
        Err(crate::storage::Error::Limit { .. })
    ));
    let mut sender = CompactRepeat::new_duplex_reserved(
        bounded,
        bounded,
        context(EndpointRole::Initiator),
        crate::storage::Limits {
            capacity_bytes: plan.capacity_bytes(),
        },
    )?;
    let usage = sender.storage_usage().ok_or("actual reserved singleton")?;
    assert_eq!(usage.capacity_bytes, plan.capacity_bytes());
    assert_eq!(
        usage.allocations,
        5 + bounded.bounds().send_records + bounded.bounds().receive_records
    );
    let more = CompactRepeat::new_duplex_reserved(
        bounded,
        bounded,
        context(EndpointRole::Initiator),
        crate::storage::Limits {
            capacity_bytes: plan.capacity_bytes() + 1,
        },
    )?;
    assert_eq!(
        more.storage_usage().ok_or("plus one usage")?.capacity_bytes,
        usage.capacity_bytes
    );
    assert_eq!(
        more.storage_usage().ok_or("plus one usage")?.limit_bytes,
        usage.limit_bytes + 1
    );
    emit(&mut sender, Duration::ZERO, Duration::ZERO, b"one")?;
    assert_eq!(
        sender.poll_source(ms(150), &mut out),
        Err(RecoveryError::RetryExhausted {
            source: SourceId(0)
        })
    );
    assert!(!sender.drained());
    assert_eq!(sender.statistics().transmissions, 1);
    assert_eq!(sender.retained().send_records, 1);
    config(CompactRecovery::Guarded, 65_535, 1, 77)?.validate()?;
    Ok(())
}

#[test]
fn bounded_gap_uses_any_last_feedback_and_only_advancing_qualified_prefix() -> Result {
    let mode = CompactRecovery::BoundedGap {
        min_interval: ms(5),
    };
    let mut policy = config(mode, 16, 8, 78)?;
    policy.timing.feedback_interval = ms(10);
    let mut receiver = CompactRepeat::new(policy, context(EndpointRole::Responder))?;
    for (source, serial) in [(1, 1), (3, 2), (4, 3)] {
        receiver.receive(&incoming(policy, source, serial, &[source as u8])?, ms(10))?;
    }
    assert_eq!(receiver.feedback_deadline(), Some(ms(10)));
    let first = feedback(&mut receiver, ms(10))?;
    assert!(matches!(
        inspect_compact_packet(&first, context(EndpointRole::Initiator), policy)?,
        CompactPacketView::Feedback(CompactFeedback { prefix: 0, .. })
    ));
    receiver.receive(&incoming(policy, 5, 4, b"five")?, ms(11))?;
    assert_eq!(receiver.feedback_deadline(), Some(ms(20)));
    receiver.receive(&incoming(policy, 0, 5, b"zero")?, ms(12))?;
    assert_eq!(receiver.feedback_deadline(), Some(ms(20)));
    receiver.receive(&incoming(policy, 6, 6, b"six")?, ms(15))?;
    assert_eq!(receiver.feedback_deadline(), Some(ms(15)));
    let second = feedback(&mut receiver, ms(15))?;
    assert!(matches!(
        inspect_compact_packet(&second, context(EndpointRole::Initiator), policy)?,
        CompactPacketView::Feedback(CompactFeedback { prefix: 2, .. })
    ));
    receiver.receive(&incoming(policy, 6, 7, b"six")?, ms(16))?;
    assert_eq!(receiver.feedback_deadline(), Some(ms(25)));
    assert_eq!(receiver.statistics().duplicates, 1);
    Ok(())
}

#[test]
fn newer_echo_cannot_retire_an_earlier_unobserved_physical_history_entry() -> Result {
    let (mut sender, mut receiver) = pair(CompactRecovery::Guarded)?;
    sender.submit(b"held", Duration::ZERO)?;
    sender.submit(b"later", Duration::ZERO)?;
    let mut first = [0; 128];
    let mut second = [0; 128];
    sender
        .poll_source(Duration::ZERO, &mut first)?
        .ok_or("held first")?;
    let old = sender
        .pending_transmission(SourceId(0))
        .ok_or("first token")?;
    let size = sender
        .poll_source(Duration::ZERO, &mut second)?
        .ok_or("second")?;
    let newer = sender
        .pending_transmission(SourceId(1))
        .ok_or("second token")?;
    sender.confirm_transmission(ms(10), newer)?;
    receiver.receive(&second[..size], ms(40))?;
    let ack = feedback(&mut receiver, ms(45))?;
    let before = (sender.timing()?, sender.retained(), sender.statistics());
    assert_eq!(
        sender.receive_at(&ack, ms(80), ms(100)),
        Err(RecoveryError::FeedbackAwaitingPhysical)
    );
    assert_eq!(
        (sender.timing()?, sender.retained(), sender.statistics()),
        before
    );
    sender.confirm_transmission_at(ms(100), ms(15), old)?;
    sender.receive_at(&ack, ms(80), ms(100))?;
    assert_eq!(sender.timing()?.sampled_serial, 2);
    assert!(sender.source_confirmed(SourceId(1))?);
    assert!(!sender.source_confirmed(SourceId(0))?);
    assert_eq!(sender.source_deadline(), Some(ms(165)));
    Ok(())
}

#[test]
fn retry_failure_snapshot_preserves_original_attempt_times_and_last_applied_feedback() -> Result {
    let original = config(CompactRecovery::Guarded, 16, 64, 78)?;
    let policy = CompactArqConfig::new(
        original.bounds(),
        original.timing(),
        original.maximum_feedback_bytes(),
        original.history_entries(),
        2,
        original.recovery(),
    )?;
    let mut sender = CompactRepeat::new(policy, context(EndpointRole::Initiator))?;
    let mut receiver = CompactRepeat::new(policy, context(EndpointRole::Responder))?;
    let usage = sender.storage_usage();
    sender.submit(b"lost", ms(0))?;
    let mut bytes = [0; 128];
    sender
        .poll_source(ms(0), &mut bytes)?
        .ok_or("first attempt")?;
    assert_eq!(sender.retry_failure_snapshot(), None);
    let first = sender
        .pending_transmission(SourceId(0))
        .ok_or("first custody")?;
    sender.confirm_transmission_at(ms(20), ms(10), first)?;
    let later = emit(&mut sender, ms(20), ms(20), b"later")?;
    receiver.receive(&later, ms(50))?;
    let ack = feedback(&mut receiver, ms(55))?;
    sender.receive_at(&ack, ms(100), ms(100))?;
    assert_eq!(sender.statistics().feedback_received, 1);
    sender
        .poll_source(ms(160), &mut bytes)?
        .ok_or("only retry")?;
    let retry = sender
        .pending_transmission(SourceId(0))
        .ok_or("retry custody")?;
    sender.confirm_transmission_at(ms(500), ms(170), retry)?;
    assert_eq!(sender.retry_failure_snapshot(), None);
    assert_eq!(
        sender.poll_source(ms(501), &mut bytes),
        Err(RecoveryError::RetryExhausted {
            source: SourceId(0)
        })
    );
    let snapshot = sender
        .retry_failure_snapshot()
        .ok_or("exact failed owner")?;
    assert_eq!(
        (snapshot.failed_at, snapshot.last_successful_at),
        (ms(501), ms(500))
    );
    assert_eq!(
        (
            snapshot.source,
            snapshot.attempts,
            snapshot.maximum_attempts,
            snapshot.source_bytes
        ),
        (SourceId(0), 2, 2, 4)
    );
    assert_eq!(
        (
            snapshot.attempt_serial,
            snapshot.prepared_at,
            snapshot.accepted_at
        ),
        (3, ms(160), Some(ms(170)))
    );
    assert_eq!(snapshot.retry_at, ms(170).checked_add(snapshot.attempt_rto));
    assert!(!snapshot.fast && !snapshot.physical_pending && !snapshot.acknowledged);
    assert_eq!(
        (
            snapshot.send_base,
            snapshot.next_source,
            snapshot.retained.send_records
        ),
        (0, 2, 1)
    );
    assert_eq!(snapshot.maximum_peer_feedback_serial, 1);
    assert_eq!(
        snapshot.last_peer_feedback,
        Some(CompactPeerFeedbackSnapshot {
            arrival: ms(100),
            prefix: 0,
            start: 0,
            count: 2,
            echo: 2,
            receiver_delay_us: 5000,
            serial: 1,
        })
    );
    assert_eq!(
        (
            snapshot.statistics.transmissions,
            snapshot.statistics.retransmissions
        ),
        (3, 1)
    );
    assert_eq!(snapshot.statistics.feedback_received, 1);
    assert_eq!(sender.storage_usage(), usage);
    assert_eq!(
        sender.poll_source(ms(2000), &mut bytes),
        Err(RecoveryError::RetryExhausted {
            source: SourceId(0)
        })
    );
    assert_eq!(sender.retry_failure_snapshot(), Some(snapshot));
    Ok(())
}

#[test]
fn retry_failure_snapshot_distinguishes_fast_limit_before_armed_timeout() -> Result {
    let original = config(CompactRecovery::FirstFlight, 16, 64, 78)?;
    let policy = CompactArqConfig::new(
        original.bounds(),
        original.timing(),
        original.maximum_feedback_bytes(),
        original.history_entries(),
        1,
        original.recovery(),
    )?;
    let mut sender = CompactRepeat::new(policy, context(EndpointRole::Initiator))?;
    let mut receiver = CompactRepeat::new(policy, context(EndpointRole::Responder))?;
    let mut packets = Vec::new();
    for byte in 0..4 {
        packets.push(emit(&mut sender, ms(0), ms(0), &[byte])?);
    }
    for packet in &packets[1..] {
        receiver.receive(packet, ms(30))?;
    }
    // Independent prepared custody may still be settled after this owner fails.
    sender.submit(b"held", ms(0))?;
    let mut bytes = [0; 128];
    sender
        .poll_source(ms(0), &mut bytes)?
        .ok_or("held attempt")?;
    let held = sender
        .pending_transmission(SourceId(4))
        .ok_or("held custody")?;
    let ack = feedback(&mut receiver, ms(35))?;
    sender.receive_at(&ack, ms(70), ms(70))?;
    assert_eq!(
        sender.poll_source(ms(70), &mut bytes),
        Err(RecoveryError::RetryExhausted {
            source: SourceId(0)
        })
    );
    let snapshot = sender.retry_failure_snapshot().ok_or("fast failed owner")?;
    assert_eq!(
        (
            snapshot.failed_at,
            snapshot.attempts,
            snapshot.maximum_attempts
        ),
        (ms(70), 1, 1)
    );
    assert!(snapshot.fast);
    assert!(
        snapshot
            .retry_at
            .is_some_and(|deadline| deadline > snapshot.failed_at)
    );
    assert_eq!(
        (
            snapshot.statistics.transmissions,
            snapshot.statistics.retransmissions
        ),
        (5, 0)
    );
    assert_eq!(
        snapshot.last_peer_feedback.ok_or("applied feedback")?.count,
        4
    );
    assert_eq!(
        sender.confirm_transmission_at(ms(2000), ms(100), held),
        Err(RecoveryError::RetryExhausted {
            source: SourceId(0)
        })
    );
    assert_eq!(sender.retry_failure_snapshot(), Some(snapshot));
    Ok(())
}

mod history_range {
    use super::*;

    fn owner() -> Result<CompactRepeat> {
        Ok(CompactRepeat::new(
            config(CompactRecovery::Guarded, 16, 3, 78)?,
            context(EndpointRole::Initiator),
        )?)
    }

    fn apply(
        owner: &mut CompactRepeat,
        prefix: u64,
        echo: u64,
        serial: u64,
        received: Duration,
        observed: Duration,
    ) -> std::result::Result<(), RecoveryError> {
        owner.receive_view_at(
            CompactPacketView::Feedback(CompactFeedback {
                prefix,
                start: prefix,
                count: 0,
                echo,
                receiver_delay_us: 0,
                serial,
                bitmap: &[],
            }),
            received,
            observed,
        )
    }

    fn history(owner: &CompactRepeat) -> Result<Vec<(u64, Option<Duration>)>> {
        let state = owner.engine.compact.as_ref().ok_or("selected state")?;
        let mut entries = state
            .history
            .iter()
            .flatten()
            .map(|entry| (entry.serial, entry.accepted))
            .collect::<Vec<_>>();
        entries.sort_by_key(|entry| entry.0);
        Ok(entries)
    }

    fn prepare(owner: &mut CompactRepeat, now: Duration) -> Result<PhysicalTransmission> {
        let source = SourceId(owner.submit(b"held", now)?);
        owner
            .poll_source(now, &mut [0; 128])?
            .ok_or("prepared source")?;
        Ok(owner.pending_transmission(source).ok_or("actual token")?)
    }

    #[test]
    fn history_range_same_source_retries_wrap_without_encoder_refusal_holes() -> Result {
        let mut owner = owner()?;
        let source = SourceId(owner.submit(b"retry", ms(0))?);
        let mut now = ms(0);
        for serial in 1..=7 {
            let before = history(&owner)?;
            assert_eq!(
                owner.poll_source_with::<u64, ()>(now, |_| Ok(None)),
                Ok(None)
            );
            assert_eq!(
                owner.poll_source_with::<u64, u8>(now, |_| Err(7)),
                Err(CompactPollError::Encode(7))
            );
            assert_eq!(history(&owner)?, before);
            assert_eq!(owner.engine.next_transmission, serial - 1);
            let selected = owner.poll_source_with::<u64, RecoveryError>(now, |view| {
                let CompactPacketView::Data {
                    source: actual,
                    serial,
                    ..
                } = view
                else {
                    return Err(RecoveryError::MalformedPacket);
                };
                assert_eq!(actual, source);
                Ok(Some(serial))
            })?;
            assert_eq!(selected, Some(serial));
            let token = owner
                .pending_transmission(source)
                .ok_or("actual retry token")?;
            owner.confirm_transmission_at(now, now, token)?;
            let arrival = now + ms(35);
            // Sample the attempt while explicitly leaving the source missing.
            apply(&mut owner, 0, serial, serial, arrival, arrival)?;
            assert!(history(&owner)?.is_empty());
            assert_eq!(owner.retained().send_records, 1);
            now = owner.source_deadline().ok_or("next finite retry")?;
        }
        assert_eq!(owner.statistics().transmissions, 7);
        assert_eq!(owner.statistics().retransmissions, 6);
        Ok(())
    }

    #[test]
    fn history_range_wrap_retirement_preserves_later_entries_and_reuses_backing() -> Result {
        let mut owner = owner()?;
        let usage = owner.storage_usage();
        let state = owner.engine.compact.as_ref().ok_or("state")?;
        let allocation = (state.history.as_ptr(), state.history.capacity());
        for _ in 0..3 {
            emit(&mut owner, ms(0), ms(0), b"first")?;
        }
        apply(&mut owner, 1, 1, 1, ms(1), ms(1))?;
        emit(&mut owner, ms(2), ms(2), b"reuse")?;
        // Serials 2 and 3 straddle the end of the actual three-slot ring.
        assert_eq!(
            owner
                .engine
                .compact
                .as_ref()
                .ok_or("state")?
                .history_prefix_ranges(3),
            [2..3, 0..1]
        );
        apply(&mut owner, 3, 3, 2, ms(3), ms(3))?;
        assert_eq!(history(&owner)?, vec![(4, Some(ms(2)))]);
        assert_eq!(owner.retained().send_records, 1);
        assert!(!owner.source_confirmed(SourceId(3))?);
        for _ in 0..2 {
            emit(&mut owner, ms(4), ms(4), b"next")?;
        }
        apply(&mut owner, 6, 6, 3, ms(5), ms(5))?;
        assert!(history(&owner)?.is_empty());
        assert_eq!(owner.retained().send_records, 0);
        for round in 0..40_u64 {
            let now = ms(10 + round * 3);
            for _ in 0..3 {
                emit(&mut owner, now, now, b"cycles")?;
            }
            let end = 9 + round * 3;
            apply(&mut owner, end, end, 4 + round, now + ms(1), now + ms(1))?;
            assert!(history(&owner)?.is_empty());
            assert_eq!(owner.retained().send_records, 0);
            assert_eq!(owner.storage_usage(), usage);
            let state = owner.engine.compact.as_ref().ok_or("state")?;
            assert_eq!(
                (state.history.as_ptr(), state.history.capacity()),
                allocation
            );
        }
        Ok(())
    }

    #[test]
    fn history_range_pending_prefix_refuses_atomically_and_preserves_newer_token() -> Result {
        let mut owner = owner()?;
        for _ in 0..2 {
            emit(&mut owner, ms(0), ms(0), b"warm")?;
        }
        apply(&mut owner, 2, 2, 1, ms(1), ms(1))?;
        let older = prepare(&mut owner, ms(2))?; // Serial 3, slot 0.
        let echo = prepare(&mut owner, ms(2))?; // Serial 4, slot 1.
        owner.confirm_transmission_at(ms(3), ms(2), echo)?;
        let newer = prepare(&mut owner, ms(3))?; // Serial 5, slot 2.
        let before = format!("{:?}", owner.engine);
        // No positive ACK depends on the held source; the history prefix alone
        // must prevent a newer accepted echo from erasing its actual token.
        assert_eq!(
            apply(&mut owner, 2, 4, 2, ms(4), ms(4)),
            Err(RecoveryError::FeedbackAwaitingPhysical)
        );
        assert_eq!(format!("{:?}", owner.engine), before);
        owner.confirm_transmission_at(ms(5), ms(2), older)?;
        apply(&mut owner, 4, 4, 2, ms(4), ms(5))?;
        assert_eq!(history(&owner)?, vec![(5, None)]);
        assert_eq!(owner.pending_transmission(SourceId(4)), Some(newer));
        assert_eq!(owner.retained().send_records, 1);
        owner.confirm_transmission_at(ms(6), ms(3), newer)?;
        apply(&mut owner, 5, 5, 3, ms(7), ms(7))?;
        assert!(history(&owner)?.is_empty());
        assert_eq!(owner.retained().send_records, 0);
        Ok(())
    }

    #[test]
    fn history_range_stale_echo_cannot_clear_reused_slots_but_new_echo_still_applies() -> Result {
        let mut owner = owner()?;
        for _ in 0..3 {
            emit(&mut owner, ms(0), ms(0), b"first")?;
        }
        apply(&mut owner, 3, 3, 10, ms(1), ms(1))?;
        for _ in 0..3 {
            emit(&mut owner, ms(2), ms(2), b"reuse")?;
        }
        let before = (owner.timing()?, owner.retained(), history(&owner)?);
        apply(&mut owner, 3, 3, 1, ms(3), ms(3))?;
        assert_eq!(
            (owner.timing()?, owner.retained(), history(&owner)?),
            before
        );
        // Feedback output serial may be stale while its actual echo and ACKs
        // are new. Preserve the established independent authorities.
        apply(&mut owner, 5, 5, 1, ms(4), ms(4))?;
        assert_eq!(owner.timing()?.sampled_serial, 5);
        assert_eq!(history(&owner)?, vec![(6, Some(ms(2)))]);
        assert!(owner.source_confirmed(SourceId(3))?);
        assert!(owner.source_confirmed(SourceId(4))?);
        assert!(!owner.source_confirmed(SourceId(5))?);
        Ok(())
    }

    #[test]
    fn history_range_guard_overflow_preserves_complete_feedback_state() -> Result {
        let mut policy = config(CompactRecovery::Guarded, 16, 3, 78)?;
        policy.timing.nominal_rtt = Duration::ZERO;
        let mut owner = CompactRepeat::new(policy, context(EndpointRole::Initiator))?;
        emit(&mut owner, ms(0), ms(0), b"old")?;
        // Retire the first source without sampling its retained transmission.
        apply(&mut owner, 1, 0, 1, ms(1), ms(1))?;
        let near_limit = Duration::MAX - ms(50);
        emit(&mut owner, near_limit, near_limit, b"new")?;
        let before = format!("{:?}", owner.engine);
        // Original arrival is preserved despite arbitrarily delayed observation.
        // The new RTT sample enlarges the guard for the later unacknowledged
        // source beyond Duration::MAX. No RTT/history/ACK mutation may precede it.
        assert_eq!(
            apply(&mut owner, 1, 1, 2, ms(1000), Duration::MAX - ms(10)),
            Err(RecoveryError::TimeOverflow)
        );
        assert_eq!(format!("{:?}", owner.engine), before);
        assert_eq!(owner.timing()?.sampled_serial, 0);
        assert_eq!(history(&owner)?.len(), 2);
        assert_eq!(owner.failure(), None);
        Ok(())
    }

    #[test]
    fn history_range_is_bounded_without_serial_limit_overflow() -> Result {
        let mut owner = owner()?;
        let state = owner.engine.compact.as_mut().ok_or("state")?;
        state.sampled = u64::MAX - 3;
        let ranges = state.history_prefix_ranges(u64::MAX);
        assert_eq!(ranges.iter().map(std::ops::Range::len).sum::<usize>(), 3);
        assert!(ranges.iter().all(|range| range.end <= state.history.len()));
        state.sampled = u64::MAX;
        assert_eq!(state.history_prefix_ranges(u64::MAX), [0..0, 0..0]);
        state.sampled = 0;
        assert_eq!(
            state
                .history_prefix_ranges(u64::MAX)
                .iter()
                .map(std::ops::Range::len)
                .sum::<usize>(),
            state.history.len()
        );
        Ok(())
    }
}

#[test]
fn admitted_body_history_backpressure_skips_caller_and_encoder() -> Result {
    let policy = config(CompactRecovery::Guarded, 1, 2, 78)?;
    let mut sender = CompactRepeat::new(policy, context(EndpointRole::Initiator))?;
    sender.submit(b"source", Duration::ZERO)?;
    let mut output = [0; 128];
    for now in [Duration::ZERO, ms(150)] {
        sender
            .poll_source(now, &mut output)?
            .ok_or("allowed attempt")?;
        let physical = sender.pending_transmission(SourceId(0)).ok_or("physical")?;
        sender.confirm_transmission_at(now, now, physical)?;
    }
    assert_eq!(sender.source_body_bytes(ms(300))?, None);
    assert_eq!(sender.source_deadline(), None);
    let before = sender.statistics();
    let blocked: std::result::Result<Option<usize>, CompactPollError<&str>> = sender
        .poll_admitted_body_with(
            ms(300),
            CompactPacketKind::Data,
            &mut [],
            |_| Err("admission must not run"),
            |_| Err("encoder must not run"),
        );
    assert_eq!(blocked, Ok(None));
    assert_eq!(sender.statistics(), before);
    assert_eq!(sender.engine.last_now, ms(150));
    assert_eq!(sender.failure(), None);
    Ok(())
}

#[test]
fn admitted_body_refusal_preserves_clock_selection_and_physical_custody() -> Result {
    let (mut sender, _) = pair(CompactRecovery::Guarded)?;
    sender.submit(b"source", Duration::ZERO)?;
    let before = sender.statistics();
    let refused: std::result::Result<Option<usize>, CompactPollError<&str>> = sender
        .poll_admitted_body_with(
            ms(50),
            CompactPacketKind::Data,
            &mut [],
            |_| Ok(false),
            |_| Err("encoder must not run"),
        );
    assert_eq!(refused, Ok(None));
    assert_eq!(sender.engine.last_now, Duration::ZERO);
    assert_eq!(sender.statistics(), before);
    assert_eq!(sender.pending_transmission(SourceId(0)), None);
    let rejected: std::result::Result<Option<usize>, CompactPollError<&str>> = sender
        .poll_admitted_body_with(
            ms(50),
            CompactPacketKind::Data,
            &mut [],
            |_| Err("caller output limit"),
            |_| Err("encoder must not run"),
        );
    assert_eq!(
        rejected,
        Err(CompactPollError::Encode("caller output limit"))
    );
    assert_eq!(sender.engine.last_now, Duration::ZERO);
    let expected = sender
        .source_body_bytes(Duration::ZERO)?
        .ok_or("source extent")?;
    let mut output = [0; 64];
    let length = sender
        .poll_admitted_body_with(
            Duration::ZERO,
            CompactPacketKind::Data,
            &mut [],
            |bytes| Ok::<_, RecoveryError>(bytes == expected),
            |view| view.encode_compact_into(&mut output).map(Some),
        )?
        .ok_or("source")?;
    assert_eq!(length, expected);
    assert_eq!(sender.engine.pending_transmissions, 1);
    assert_eq!(sender.source_deadline(), None);
    let physical = sender
        .pending_transmission(SourceId(0))
        .ok_or("actual token")?;
    sender.confirm_transmission_at(ms(3), ms(3), physical)?;
    assert_eq!(sender.source_deadline(), Some(ms(153)));
    Ok(())
}

#[test]
fn admitted_body_preserves_retry_failure_after_caller_preflight() -> Result {
    let (mut sender, _) = pair(CompactRecovery::Guarded)?;
    sender.submit(b"source", Duration::ZERO)?;
    let mut now = Duration::ZERO;
    let mut output = [0; 128];
    for _ in 0..sender.send_config()?.maximum_attempts {
        sender
            .poll_source(now, &mut output)?
            .ok_or("allowed attempt")?;
        let physical = sender.pending_transmission(SourceId(0)).ok_or("physical")?;
        sender.confirm_transmission_at(now, now, physical)?;
        now = sender.source_deadline().ok_or("retry deadline")?;
    }
    let refused: std::result::Result<Option<usize>, CompactPollError<&str>> = sender
        .poll_admitted_body_with(
            now,
            CompactPacketKind::Data,
            &mut [],
            |_| Ok(false),
            |_| Err("encoder must not run"),
        );
    assert_eq!(refused, Ok(None));
    assert_eq!(sender.failure(), None);
    let rejected: std::result::Result<Option<usize>, CompactPollError<&str>> = sender
        .poll_admitted_body_with(
            now,
            CompactPacketKind::Data,
            &mut [],
            |_| Err("caller output limit"),
            |_| Err("encoder must not run"),
        );
    assert_eq!(
        rejected,
        Err(CompactPollError::Encode("caller output limit"))
    );
    assert_eq!(sender.failure(), None);
    let exhausted: std::result::Result<Option<usize>, CompactPollError<&str>> = sender
        .poll_admitted_body_with(
            now,
            CompactPacketKind::Data,
            &mut [],
            |_| Ok(true),
            |_| Err("encoder must not run"),
        );
    assert_eq!(
        exhausted,
        Err(CompactPollError::Recovery(RecoveryError::RetryExhausted {
            source: SourceId(0)
        }))
    );
    assert_eq!(
        sender.failure(),
        Some(RecoveryError::RetryExhausted {
            source: SourceId(0)
        })
    );
    Ok(())
}

#[test]
fn admitted_body_feedback_matches_existing_peek_and_emit() -> Result {
    let (mut sender, mut left) = pair(CompactRecovery::Guarded)?;
    let (_, mut right) = pair(CompactRecovery::Guarded)?;
    let packet = emit(&mut sender, Duration::ZERO, Duration::ZERO, b"data")?;
    left.receive(&packet, ms(40))?;
    right.receive(&packet, ms(40))?;
    let expected = left.feedback_body_bytes(ms(45))?.ok_or("feedback extent")?;
    let mut a = [0; 128];
    let mut b = [0; 128];
    let mut bitmap_a = [0; 128];
    let mut bitmap_b = [0; 128];
    let la = left
        .poll_feedback_with(ms(45), &mut bitmap_a, |view| {
            view.encode_compact_into(&mut a).map(Some)
        })?
        .ok_or("old output")?;
    let lb = right
        .poll_admitted_body_with(
            ms(45),
            CompactPacketKind::Feedback,
            &mut bitmap_b,
            |bytes| Ok::<_, RecoveryError>(bytes == expected),
            |view| view.encode_compact_into(&mut b).map(Some),
        )?
        .ok_or("new output")?;
    assert_eq!(la, lb);
    assert_eq!(&a[..la], &b[..lb]);
    assert_eq!(left.statistics(), right.statistics());
    assert_eq!(left.feedback_deadline(), right.feedback_deadline());
    Ok(())
}

#[test]
fn wide_receive_reserves_and_serves_receipt_journal() -> Result {
    let small = config(CompactRecovery::Guarded, 64, 16, 128)?;
    let small_owner = CompactRepeat::new(small, context(EndpointRole::Responder))?;
    assert_eq!(small_owner.receipt_serial(), None);
    assert!(small_owner.received_after(0)?.is_none());

    let wide = config(CompactRecovery::Guarded, 128, 16, 128)?;
    let plan = crate::storage::CompactPlan::for_compact(wide, wide)?;
    let mut receiver = CompactRepeat::new_duplex_reserved(
        wide,
        wide,
        context(EndpointRole::Responder),
        crate::storage::Limits {
            capacity_bytes: plan.capacity_bytes(),
        },
    )?;
    let usage = receiver.storage_usage().ok_or("wide usage")?;
    assert_eq!(usage.capacity_bytes, plan.capacity_bytes());
    assert_eq!(
        usage.allocations,
        6 + wide.bounds().send_records + wide.bounds().receive_records
    );
    assert_eq!(receiver.receipt_serial(), Some(0));
    assert_eq!(
        receiver.received_after(0)?.ok_or("empty journal")?.count(),
        0
    );

    receiver.receive(&incoming(wide, 2, 1, b"two")?, ms(10))?;
    receiver.receive(&incoming(wide, 0, 2, b"zero")?, ms(11))?;
    // Duplicate must not advance the receipt journal.
    receiver.receive(&incoming(wide, 2, 3, b"two")?, ms(12))?;
    assert_eq!(receiver.receipt_serial(), Some(2));
    let seen: Vec<_> = receiver
        .received_after(0)?
        .ok_or("after 0")?
        .map(|entry| (entry.serial, entry.source, entry.bytes.to_vec()))
        .collect();
    assert_eq!(
        seen,
        vec![
            (1, SourceId(2), b"two".to_vec()),
            (2, SourceId(0), b"zero".to_vec()),
        ]
    );
    let tail: Vec<_> = receiver
        .received_after(1)?
        .ok_or("after 1")?
        .map(|entry| (entry.serial, entry.source))
        .collect();
    assert_eq!(tail, vec![(2, SourceId(0))]);
    assert_eq!(receiver.received_after(2)?.ok_or("after 2")?.count(), 0);
    // Delivering source 0 drops it from retained payloads while keeping journal order.
    let mut out = [0; 64];
    assert_eq!(receiver.poll_delivered(&mut out)?, Some((0, 4)));
    let remaining: Vec<_> = receiver
        .received_after(0)?
        .ok_or("after deliver")?
        .map(|entry| (entry.serial, entry.source))
        .collect();
    assert_eq!(remaining, vec![(1, SourceId(2))]);
    Ok(())
}

#[test]
fn compact_feedback_handles_held_acknowledged_flight_below_base() -> Result {
    let (mut sender, mut receiver) = pair(CompactRecovery::Guarded)?;
    let mut pkt0 = [0; 128];
    let mut pkt1 = [0; 128];
    let mut pkt2 = [0; 128];
    // Send and physically confirm 0, 1, 2.
    sender.submit(b"zero", Duration::ZERO)?;
    sender.submit(b"one", Duration::ZERO)?;
    sender.submit(b"two", Duration::ZERO)?;
    let l0 = sender
        .poll_source(Duration::ZERO, &mut pkt0)?
        .ok_or("pkt0")?;
    let t0 = sender.pending_transmission(SourceId(0)).ok_or("t0")?;
    sender.confirm_transmission_at(ms(1), ms(1), t0)?;
    let l1 = sender.poll_source(ms(1), &mut pkt1)?.ok_or("pkt1")?;
    let t1 = sender.pending_transmission(SourceId(1)).ok_or("t1")?;
    sender.confirm_transmission_at(ms(2), ms(2), t1)?;
    let l2 = sender.poll_source(ms(2), &mut pkt2)?.ok_or("pkt2")?;
    let t2 = sender.pending_transmission(SourceId(2)).ok_or("t2")?;
    sender.confirm_transmission_at(ms(3), ms(3), t2)?;

    // Retry source 0 so it has attempts == 2 and transmission != 0 (held physically).
    let retry_at = sender.source_deadline().ok_or("retry deadline")?;
    let mut retry0 = [0; 128];
    sender.poll_source(retry_at, &mut retry0)?.ok_or("retry0")?;
    let held0 = sender.pending_transmission(SourceId(0)).ok_or("held0")?;

    // Peer acknowledges source 0 (from original copy) and source 2; source 1 is unacked.
    receiver.receive(&pkt0[..l0], ms(20))?;
    receiver.receive(&pkt2[..l2], ms(21))?;
    let fb1 = feedback(&mut receiver, ms(30))?;
    sender.receive(&fb1, retry_at)?;
    assert!(sender.source_confirmed(SourceId(0))?);
    assert!(!sender.source_confirmed(SourceId(1))?);
    assert!(sender.source_confirmed(SourceId(2))?);
    // Source 0 stays retained below base until physical confirmation, while source 2 was freed.
    assert_eq!(sender.retained().send_records, 2);

    // Second feedback acknowledges source 1 while source 0 is still held below base.
    receiver.receive(&pkt1[..l1], ms(35))?;
    let fb2 = feedback(&mut receiver, ms(45))?;
    sender.receive(&fb2, retry_at + ms(1))?;
    assert!(sender.source_confirmed(SourceId(1))?);
    assert_eq!(sender.retained().send_records, 1);

    // Confirming the held retry of source 0 frees it cleanly and drains sender.
    sender.confirm_transmission_at(retry_at + ms(2), retry_at + ms(2), held0)?;
    assert_eq!(sender.retained().send_records, 0);
    assert_eq!(sender.retained().send_bytes, 0);
    Ok(())
}
