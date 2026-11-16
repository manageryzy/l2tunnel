use super::*;

type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

fn context(role: EndpointRole) -> RecoveryContext {
    RecoveryContext {
        session: 0x0102,
        epoch: 7,
        role,
    }
}

fn policy() -> Result<CompactArqConfig> {
    Ok(CompactArqConfig::new(
        CompactBounds {
            max_source_bytes: 8,
            send_bytes: 64,
            receive_bytes: 64,
            send_records: 8,
            receive_records: 8,
        },
        CompactTiming {
            nominal_rtt: Duration::from_millis(70),
            feedback_interval: Duration::from_millis(5),
            feedback_packets: 64,
        },
        78,
        32,
        8,
        CompactRecovery::Guarded,
    )?)
}

#[test]
fn borrowed_descriptor_preserves_actual_source_and_gap_feedback_golden_bytes() -> Result {
    let policy = policy()?;
    let mut sender = CompactRepeat::new(policy, context(EndpointRole::Initiator))?;
    let mut receiver = CompactRepeat::new(policy, context(EndpointRole::Responder))?;
    let source = SourceId(sender.submit(&[0, 0xff, 0x7e, 1], Duration::ZERO)?);
    let mut packet = [0xaa; 128];
    let length = sender
        .poll_source(Duration::ZERO, &mut packet)?
        .ok_or("actual source")?;
    let source_golden: [u8; 56] = [
        b'L', b'2', b'A', b'R', 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 0, 0,
        0, 0, 0, 0, 0, 7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 4, 0, 0xff,
        0x7e, 1,
    ];
    assert_eq!(&packet[..length], source_golden);
    let token = sender
        .pending_transmission(source)
        .ok_or("actual custody")?;
    sender.confirm_transmission(Duration::ZERO, token)?;
    // Lose source zero and deliver the next real source, producing a gap bitmap.
    sender.submit(b"next", Duration::ZERO)?;
    let length = sender
        .poll_source(Duration::ZERO, &mut packet)?
        .ok_or("next source")?;
    receiver.receive(&packet[..length], Duration::from_millis(1))?;
    let mut feedback = [0xaa; 128];
    let length = receiver
        .poll_feedback(Duration::from_millis(6), &mut feedback)?
        .ok_or("actual gap feedback")?;
    let feedback_golden: [u8; 77] = [
        b'L', b'2', b'A', b'R', 2, 1, 2, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 0, 0,
        0, 0, 0, 0, 0, 7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0x13, 0x88, 0, 0, 0, 0, 0, 0, 0, 1, 2,
    ];
    assert_eq!(&feedback[..length], feedback_golden);
    for (bytes, sender_role) in [
        (&source_golden[..], EndpointRole::Initiator),
        (&feedback_golden[..], EndpointRole::Responder),
    ] {
        let peer_role = match sender_role {
            EndpointRole::Initiator => EndpointRole::Responder,
            EndpointRole::Responder => EndpointRole::Initiator,
        };
        let view = inspect_compact_packet(bytes, context(peer_role), policy)?;
        assert_eq!(view.legacy_encoded_len()?, bytes.len());
        let mut encoded = [0xaa; 128];
        let length =
            view.encode_legacy_into(context(sender_role), CompactRecovery::Guarded, &mut encoded)?;
        assert_eq!(&encoded[..length], bytes);
        assert!(encoded[length..].iter().all(|byte| *byte == 0xaa));
    }
    Ok(())
}

#[test]
fn borrowed_descriptor_rejects_noncanonical_fields_and_short_output_atomically() -> Result {
    let valid = CompactFeedback {
        prefix: 1,
        start: 3,
        count: 9,
        echo: u64::MAX,
        receiver_delay_us: u64::MAX,
        serial: u64::MAX,
        bitmap: &[0xa5, 1],
    };
    let mut output = [0xaa; 128];
    for invalid in [
        CompactPacketView::Data {
            source: SourceId(u64::MAX),
            serial: 1,
            payload: b"real",
        },
        CompactPacketView::Data {
            source: SourceId(0),
            serial: 0,
            payload: b"real",
        },
        CompactPacketView::Feedback(CompactFeedback {
            bitmap: &[0],
            ..valid
        }),
        CompactPacketView::Feedback(CompactFeedback {
            bitmap: &[0, 2],
            ..valid
        }),
        CompactPacketView::Feedback(CompactFeedback { start: 0, ..valid }),
        CompactPacketView::Feedback(CompactFeedback {
            start: u64::MAX,
            ..valid
        }),
        CompactPacketView::Feedback(CompactFeedback { serial: 0, ..valid }),
        CompactPacketView::Feedback(CompactFeedback {
            start: valid.prefix,
            ..valid
        }),
    ] {
        assert!(invalid.legacy_encoded_len().is_err());
        assert!(
            invalid
                .encode_legacy_into(
                    context(EndpointRole::Responder),
                    CompactRecovery::Guarded,
                    &mut output
                )
                .is_err()
        );
        assert_eq!(output, [0xaa; 128]);
    }
    for valid in [
        CompactPacketView::Data {
            source: SourceId(u64::MAX - 1),
            serial: u64::MAX,
            payload: b"real",
        },
        CompactPacketView::Feedback(valid),
    ] {
        let required = valid.legacy_encoded_len()?;
        assert_eq!(
            valid.encode_legacy_into(
                context(EndpointRole::Responder),
                CompactRecovery::Guarded,
                &mut output[..required - 1],
            ),
            Err(RecoveryError::OutputTooSmall { required }),
        );
        assert_eq!(output, [0xaa; 128]);
        let length = valid.encode_legacy_into(
            context(EndpointRole::Responder),
            CompactRecovery::Guarded,
            &mut output,
        )?;
        assert_eq!(
            inspect_compact_packet(
                &output[..length],
                context(EndpointRole::Initiator),
                policy()?
            )?,
            valid,
        );
        output.fill(0xaa);
    }
    Ok(())
}
