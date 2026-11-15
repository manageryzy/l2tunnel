use super::*;
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

fn incoming(config: CompactArqConfig, source: u64, serial: u64, payload: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0; COMPACT_DATA_HEADER_BYTES + payload.len()];
    common(
        &mut bytes,
        context(EndpointRole::Initiator),
        config.recovery(),
        1,
    );
    bytes[32..40].copy_from_slice(&source.to_be_bytes());
    bytes[40..48].copy_from_slice(&serial.to_be_bytes());
    bytes[48..52].copy_from_slice(&(payload.len() as u32).to_be_bytes());
    bytes[52..].copy_from_slice(payload);
    bytes
}

#[test]
fn rotating_feedback_reaches8192_and_keeps_three_charged_tail_reports_and_strict_padding() -> Result
{
    let policy = config(CompactRecovery::Guarded, 8192, 4, 77)?;
    let mut receiver = CompactRepeat::new(policy, context(EndpointRole::Responder))?;
    let source = incoming(policy, 8191, u64::MAX, b"last");
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
    let mut invalid = feedback_bytes(policy, 0, 1, 1, &[2]);
    assert_eq!(
        inspect_compact_packet(&invalid, context(EndpointRole::Initiator), policy),
        Err(RecoveryError::MalformedPacket)
    );
    invalid = feedback_bytes(policy, 0, 1, 1, &[1]);
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
) -> Vec<u8> {
    let mut bytes = vec![0; COMPACT_FEEDBACK_HEADER_BYTES + bitmap.len()];
    common(
        &mut bytes,
        context(EndpointRole::Responder),
        config.recovery(),
        2,
    );
    bytes[32..40].copy_from_slice(&prefix.to_be_bytes());
    bytes[40..48].copy_from_slice(&start.to_be_bytes());
    bytes[48..50].copy_from_slice(&count.to_be_bytes());
    bytes[68..76].copy_from_slice(&1_u64.to_be_bytes());
    bytes[76..].copy_from_slice(bitmap);
    bytes
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
        receiver.receive(&incoming(policy, source, serial, &[source as u8]), ms(10))?;
    }
    assert_eq!(receiver.feedback_deadline(), Some(ms(10)));
    let first = feedback(&mut receiver, ms(10))?;
    assert!(matches!(
        inspect_compact_packet(&first, context(EndpointRole::Initiator), policy)?,
        CompactPacketView::Feedback(CompactFeedback { prefix: 0, .. })
    ));
    receiver.receive(&incoming(policy, 5, 4, b"five"), ms(11))?;
    assert_eq!(receiver.feedback_deadline(), Some(ms(20)));
    receiver.receive(&incoming(policy, 0, 5, b"zero"), ms(12))?;
    assert_eq!(receiver.feedback_deadline(), Some(ms(20)));
    receiver.receive(&incoming(policy, 6, 6, b"six"), ms(15))?;
    assert_eq!(receiver.feedback_deadline(), Some(ms(15)));
    let second = feedback(&mut receiver, ms(15))?;
    assert!(matches!(
        inspect_compact_packet(&second, context(EndpointRole::Initiator), policy)?,
        CompactPacketView::Feedback(CompactFeedback { prefix: 2, .. })
    ));
    receiver.receive(&incoming(policy, 6, 7, b"six"), ms(16))?;
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
