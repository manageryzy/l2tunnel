use super::*;

fn selected_pair(
    repairs: usize,
    reserved: bool,
) -> Result<(Reliable, Reliable), Box<dyn std::error::Error>> {
    let config = ReliableConfig {
        repair_symbols: repairs,
        ..config()
    };
    let mut a = physical::owner(config, EndpointRole::Initiator, reserved)?;
    let mut b = physical::owner(config, EndpointRole::Responder, reserved)?;
    a.enable_physical_send_confirmation()?;
    b.enable_physical_send_confirmation()?;
    a.enable_compact_wire_with_overheads(37, 49)?;
    b.enable_compact_wire_with_overheads(37, 49)?;
    Ok((a, b))
}
fn allowance() -> OutboundBudget {
    OutboundBudget {
        packets: 100,
        wire_bytes: 100_000,
    }
}

#[test]
fn selected_arq_exact_bytes_charge_replay_and_original_physical_deadline() -> TestResult {
    for reserved in [false, true] {
        let (mut a, mut b) = selected_pair(0, reserved)?;
        let usage = a.storage_usage();
        a.submit(b"payload", time(0))?;
        let mut output = vec![0xa5; a.max_packet_bytes()];
        let mut small = OutboundBudget {
            packets: 1,
            wire_bytes: 45,
        };
        assert_eq!(a.poll_data(time(0), &mut output, &mut small)?, None);
        assert_eq!(a.arq_statistics().transmissions, 0);
        assert!(output.iter().all(|byte| *byte == 0xa5));
        small.wire_bytes += 1;
        let length = a
            .poll_data(time(0), &mut output, &mut small)?
            .ok_or("source")?;
        assert_eq!(&output[..length], b"\x01\x00payload");
        let extent = a.inspect_output_extent(&output[..length])?;
        assert_eq!(
            (
                extent.header_bytes,
                extent.payload_bytes,
                extent.systematic_coded_fill_bytes
            ),
            (2, 7, 0)
        );
        assert_eq!(
            small,
            OutboundBudget {
                packets: 0,
                wire_bytes: 0
            }
        );
        let token = a.pending_output().ok_or("physical")?;
        assert_eq!(token.wire_bytes, 46);
        assert_eq!(a.arq.source_deadline(), None);
        let original = output[..length].to_vec();
        assert_eq!(a.poll_data(time(400), &mut output, &mut allowance())?, None);
        assert_eq!(a.pending_output(), Some(token));
        a.confirm_output_at(time(401), time(400), token)?;
        assert_eq!(a.arq.source_deadline(), Some(time(500)));
        b.receive(&original, time(400))?;
        b.receive(&original, time(400))?;
        assert_eq!(deliveries(&mut b)?, vec![(0, b"payload".to_vec())]);
        let mut feedback = vec![0; b.max_packet_bytes()];
        let mut exact = OutboundBudget {
            packets: 1,
            wire_bytes: 51,
        };
        assert_eq!(b.poll_feedback(time(401), &mut feedback, &mut exact)?, None);
        exact.wire_bytes += 1;
        let n = b
            .poll_feedback(time(401), &mut feedback, &mut exact)?
            .ok_or("feedback")?;
        assert_eq!(&feedback[..n], &[2, 1, 0]);
        let extent = b.inspect_output_extent(&feedback[..n])?;
        assert_eq!(
            (extent.kind, extent.header_bytes, extent.payload_bytes),
            (RecordKind::Feedback, n, 0)
        );
        assert_eq!(
            exact,
            OutboundBudget {
                packets: 0,
                wire_bytes: 0
            }
        );
        a.receive(&feedback[..n], time(401))?;
        assert!(a.drained());
        assert_eq!(a.storage_usage(), usage);
    }
    Ok(())
}

#[test]
fn selected_fec_recovers_real_loss_without_legacy_context_in_coded_sources() -> TestResult {
    for reserved in [false, true] {
        let (mut a, mut b) = selected_pair(2, reserved)?;
        let input = sources();
        submit_all(&mut a, &input)?;
        let mut output = vec![0; a.max_packet_bytes()];
        let mut packets = Vec::new();
        let mut observed_fill = false;
        while let Some(n) = a.poll_data(time(0), &mut output, &mut allowance())? {
            let bytes = output[..n].to_vec();
            let view = a.inspect_output_record(&bytes)?;
            let before = a.arq_statistics();
            let extent = a.inspect_output_extent(&bytes)?;
            assert_eq!(a.arq_statistics(), before);
            assert_eq!(extent.kind, view.kind);
            assert_eq!(
                extent.header_bytes + extent.payload_bytes + extent.systematic_coded_fill_bytes,
                n
            );
            if view.kind == RecordKind::Repair {
                assert_eq!(
                    extent.payload_bytes,
                    view.fec.ok_or("repair equation")?.payload.len()
                );
                assert_eq!(extent.systematic_coded_fill_bytes, 0);
            }
            if let Some((source, payload)) = view.source {
                assert_eq!(payload, input[source.0 as usize]);
                assert_eq!(extent.payload_bytes, payload.len());
                observed_fill |= extent.systematic_coded_fill_bytes != 0;
            }
            for end in 0..bytes.len() {
                assert!(a.inspect_output_extent(&bytes[..end]).is_err());
            }
            assert!(
                bytes
                    .windows(4)
                    .all(|window| window != b"L2AR" && window != b"L2RF")
            );
            let token = a.pending_output().ok_or("output")?;
            assert_eq!(token.wire_bytes, n + 37);
            a.confirm_output(time(0), token)?;
            packets.push(bytes);
        }
        assert_eq!(packets.len(), 5);
        assert!(observed_fill);
        for packet in packets.iter().skip(2) {
            b.receive(packet, time(0))?;
        }
        assert_eq!(deliveries(&mut b)?, indexed(&input));
        assert_eq!(b.statistics().repaired_unique_sources, 2);
        let mut feedback = vec![0; b.max_packet_bytes()];
        let n = b
            .poll_feedback(time(1), &mut feedback, &mut allowance())?
            .ok_or("ACK")?;
        a.receive(&feedback[..n], time(1))?;
        assert!(a.drained());
    }
    Ok(())
}

#[test]
fn selected_parser_rejects_noncanonical_union_and_legacy_fallback() -> TestResult {
    let (mut a, b) = selected_pair(0, true)?;
    assert!(b.inspect_peer(&[1, 0x80, 0, 3]).is_err());
    assert!(b.inspect_peer(&[2, 1, 0, 0]).is_err());
    assert!(b.inspect_peer(&[2, 0, 1]).is_err());
    assert!(b.inspect_peer(b"L2RF\x01\x01\0\0").is_err());
    assert!(b.inspect_peer(&[3, 0, 0, 0]).is_err());
    for malformed in [b"".as_slice(), &[1], &[1, 0x80], &[2, 1], &[4, 0]] {
        assert!(a.inspect_output_extent(malformed).is_err());
    }
    let (old, _) = endpoints()?;
    assert_eq!(
        old.inspect_output_extent(&[1, 0, 5]),
        Err(Error::InvalidConfig)
    );
    a.submit(b"one", time(0))?;
    assert_eq!(a.enable_compact_wire(49), Err(Error::InvalidConfig));
    Ok(())
}
