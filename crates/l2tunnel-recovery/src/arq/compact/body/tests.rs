use super::*;
type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
fn ms(value: u64) -> Duration {
    Duration::from_millis(value)
}
fn policy() -> Result<CompactArqConfig> {
    Ok(CompactArqConfig::new(
        CompactBounds {
            max_source_bytes: 32,
            send_bytes: 512,
            receive_bytes: 512,
            send_records: 16,
            receive_records: 16,
        },
        CompactTiming {
            nominal_rtt: ms(70),
            feedback_interval: ms(5),
            feedback_packets: 64,
        },
        78,
        64,
        8,
        CompactRecovery::Guarded,
    )?)
}
fn context(role: EndpointRole) -> RecoveryContext {
    RecoveryContext {
        session: u128::MAX - 2,
        epoch: u64::MAX - 3,
        role,
    }
}

#[test]
fn compact_body_golden_full_counter_domains_and_canonical_refusals() -> Result {
    let policy = policy()?;
    let data = CompactPacketView::Data {
        source: SourceId(u64::MAX - 1),
        serial: u64::MAX,
        payload: b"x",
    };
    let mut output = [0xaa; 128];
    let size = data.encode_compact_into(&mut output)?;
    assert_eq!(size, 21);
    assert_eq!(output[0], 0xfe);
    assert_eq!(&output[1..9], &[0xff; 8]);
    assert_eq!(output[9], 1);
    assert_eq!(&output[10..19], &[0xff; 9]);
    assert_eq!(&output[19..21], &[1, b'x']);
    assert_eq!(
        inspect_compact_body(CompactPacketKind::Data, &output[..size], policy)?,
        data
    );
    let feedback = CompactPacketView::Feedback(CompactFeedback {
        prefix: 129,
        start: 257,
        count: 9,
        echo: 16_384,
        receiver_delay_us: 128,
        serial: 1,
        bitmap: &[2, 1],
    });
    let expected = [0x81, 1, 0x80, 1, 9, 0x80, 0x80, 1, 0x80, 1, 1, 2, 1];
    let size = feedback.encode_compact_into(&mut output)?;
    assert_eq!(&output[..size], &expected);
    assert_eq!(
        inspect_compact_body(CompactPacketKind::Feedback, &expected, policy)?,
        feedback
    );
    let original = output;
    assert_eq!(
        feedback.encode_compact_into(&mut output[..size - 1]),
        Err(RecoveryError::OutputTooSmall { required: size })
    );
    assert_eq!(output, original);
    for malformed in [
        &[0x80, 0, 1][..],
        &[0, 0x81, 0][..],
        &[0xff; 10][..],
        &[0, 0][..],
    ] {
        assert!(inspect_compact_body(CompactPacketKind::Data, malformed, policy).is_err());
    }
    for malformed in [
        &[0, 0, 0, 0, 0, 1, 0][..],          // Trailing bitmap for count zero.
        &[0, 0, 1, 0, 0, 1, 1][..],          // Prefix bit contradicts the prefix.
        &[0, 1, 1, 0, 0, 1, 2][..],          // Nonzero unused bitmap bit.
        &[0, 0, 0x80, 0x80, 4, 0, 0, 1][..], // Count exceeds u16.
    ] {
        assert_eq!(
            inspect_compact_body(CompactPacketKind::Feedback, malformed, policy),
            Err(RecoveryError::MalformedPacket)
        );
    }
    Ok(())
}

#[test]
fn compact_body_actual_owner_transactional_encoder_and_original_physical_ack_race() -> Result {
    let policy = policy()?;
    let mut a = CompactRepeat::new(policy, context(EndpointRole::Initiator))?;
    let mut b = CompactRepeat::new(policy, context(EndpointRole::Responder))?;
    let source = SourceId(a.submit(b"real bytes", ms(0))?);
    let before = a.statistics();
    assert_eq!(
        a.poll_source_with(ms(0), |_| Ok::<_, RecoveryError>(None::<usize>))?,
        None
    );
    assert_eq!(a.statistics(), before);
    assert_eq!(a.pending_transmission(source), None);
    assert_eq!(
        a.poll_source_with(ms(0), |_| Err::<Option<usize>, _>(
            RecoveryError::OutputTooSmall { required: 12 }
        )),
        Err(CompactPollError::Encode(RecoveryError::OutputTooSmall {
            required: 12
        }))
    );
    assert_eq!(a.statistics(), before);
    let mut output = [0; 128];
    let size = a
        .poll_source_with(ms(0), |view| {
            view.encode_compact_into(&mut output).map(Some)
        })?
        .ok_or("actual source")?;
    assert_eq!(size, 12);
    assert_eq!(a.statistics().wire_bytes_emitted, size as u64);
    let physical = a.pending_transmission(source).ok_or("physical token")?;
    b.receive_view_at(
        inspect_compact_body(CompactPacketKind::Data, &output[..size], policy)?,
        ms(10),
        ms(12),
    )?;
    let mut bitmap = [0; 2];
    let expected = b
        .feedback_body_bytes(ms(15))?
        .ok_or("feedback opportunity")?;
    let before = b.statistics();
    assert_eq!(
        b.poll_feedback_with(ms(15), &mut bitmap, |_| Ok::<_, RecoveryError>(
            None::<usize>
        ))?,
        None
    );
    assert_eq!(b.statistics(), before);
    assert_eq!(b.feedback_body_bytes(ms(15))?, Some(expected));
    let size = b
        .poll_feedback_with(ms(15), &mut bitmap, |view| {
            view.encode_compact_into(&mut output).map(Some)
        })?
        .ok_or("actual feedback")?;
    assert_eq!(size, expected);
    let feedback = inspect_compact_body(CompactPacketKind::Feedback, &output[..size], policy)?;
    let before = a.statistics();
    assert_eq!(
        a.receive_view_at(feedback, ms(20), ms(30)),
        Err(RecoveryError::FeedbackAwaitingPhysical)
    );
    assert_eq!(a.statistics(), before);
    a.confirm_transmission_at(ms(30), ms(2), physical)?;
    assert_eq!(a.source_deadline(), Some(ms(152)));
    a.receive_view_at(feedback, ms(20), ms(30))?;
    assert!(a.source_confirmed(source)?);
    assert!(a.timing()?.srtt_seconds.is_some());
    let mut delivered = [0; 32];
    assert_eq!(b.poll_delivered(&mut delivered)?, Some((source.0, 10)));
    assert_eq!(&delivered[..10], b"real bytes");
    assert_eq!(b.poll_delivered(&mut delivered)?, None);
    Ok(())
}
