//! Wide base-ARQ ACK: windows above 64 up to `MAX_ARQ_WINDOW`.
use super::*;

type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

fn ms(value: u64) -> Duration {
    Duration::from_millis(value)
}
fn context(role: EndpointRole) -> RecoveryContext {
    RecoveryContext {
        session: 0x0515_71de,
        epoch: 3,
        role,
    }
}
fn config(window: usize) -> ArqConfig {
    ArqConfig {
        max_source_bytes: 16,
        send_bytes: 16 * window,
        receive_bytes: 16 * window,
        send_records: window,
        receive_records: window,
        initial_rto: ms(40),
        maximum_rto: ms(320),
        ack_delay: Duration::ZERO,
        max_retries: 16,
    }
}
fn make(window: usize, role: EndpointRole, reserved: bool) -> Result<SelectiveRepeat> {
    let config = config(window);
    Ok(if reserved {
        let plan = crate::storage::DuplexPlan::for_arq(config, config)?;
        SelectiveRepeat::new_reserved(
            config,
            context(role),
            crate::storage::Limits {
                capacity_bytes: plan.capacity_bytes(),
            },
        )?
    } else {
        SelectiveRepeat::new(config, context(role))?
    })
}
fn payload(source: u64) -> Vec<u8> {
    let length = (source % 16) as usize;
    (0..length)
        .map(|i| (source as u8).wrapping_mul(31) ^ i as u8)
        .collect()
}

#[test]
fn legacy_windows_keep_their_exact_feedback_and_wide_maxima_follow_the_window() {
    for window in [1, 4, 64] {
        let c = config(window);
        assert!(!c.wide_feedback());
        assert_eq!(c.ack_packet_bytes(), ACK_PACKET_BYTES);
        assert_eq!(
            c.feedback_body_max_bytes(),
            ARQ_BODY_FEEDBACK_MAX_HEADER_BYTES
        );
        assert_eq!(c.wide_bitmap_max_bytes(), 0);
    }
    for (window, bitmap) in [(65, 9), (1024, 128), (MAX_ARQ_WINDOW, 1024)] {
        let c = config(window);
        assert!(c.wide_feedback());
        assert_eq!(c.wide_bitmap_max_bytes(), bitmap);
        assert_eq!(c.ack_packet_bytes(), WIDE_ACK_HEADER_BYTES + bitmap);
        assert_eq!(
            c.feedback_body_max_bytes(),
            ARQ_BODY_DATA_MAX_HEADER_BYTES + bitmap
        );
    }
    // Either window above 64 selects the wide form for the direction.
    let mixed = ArqConfig {
        receive_records: 65,
        ..config(64)
    };
    assert!(mixed.wide_feedback());
    assert_eq!(mixed.wide_bitmap_max_bytes(), 9);
}

#[test]
fn legacy_window_feedback_bytes_are_unchanged() -> Result {
    let mut sender = make(64, EndpointRole::Initiator, true)?;
    let mut receiver = make(64, EndpointRole::Responder, true)?;
    let mut packet = vec![0; sender.max_packet_bytes()];
    for source in 0..3 {
        sender.submit(&payload(source), ms(0))?;
        let size = sender.poll(ms(0), &mut packet)?.ok_or("source")?;
        if source != 1 {
            receiver.receive(&packet[..size], ms(0))?;
        }
    }
    let size = receiver.poll_feedback(ms(0), &mut packet)?.ok_or("ack")?;
    assert_eq!(size, ACK_PACKET_BYTES);
    assert_eq!(packet[6], 2);
    assert_eq!(
        inspect_packet(&packet[..size], context(EndpointRole::Initiator), 16)?,
        PacketView::Ack {
            prefix: 1,
            bitmap: 0b10
        }
    );
    Ok(())
}

#[test]
fn wide_ack_acknowledges_far_beyond_offset_64_in_both_encodings() -> Result {
    for reserved in [false, true] {
        for body in [false, true] {
            let mut sender = make(1024, EndpointRole::Initiator, reserved)?;
            let mut receiver = make(1024, EndpointRole::Responder, reserved)?;
            let mut packet = vec![0; sender.max_packet_bytes().max(2048)];
            // More than 64 sources in flight at once, with one early loss.
            for source in 0..1000_u64 {
                sender.submit(&payload(source), ms(0))?;
            }
            assert_eq!(sender.retained().send_records, 1000);
            for source in 0..1000_u64 {
                let size = if body {
                    sender.poll_source_body(ms(0), &mut packet)?
                } else {
                    sender.poll_source(ms(0), &mut packet)?
                }
                .ok_or("source")?;
                if source == 5 {
                    continue;
                }
                if body {
                    let view = inspect_body_for(false, &packet[..size], 16, config(1024))?;
                    receiver.receive_view(view, ms(0))?;
                } else {
                    receiver.receive(&packet[..size], ms(0))?;
                }
            }
            let size = if body {
                receiver.poll_feedback_body(ms(0), &mut packet)?
            } else {
                receiver.poll_feedback(ms(0), &mut packet)?
            }
            .ok_or("ack")?;
            // Offsets 1..=994 relative to prefix 5, so 125 bitmap bytes.
            let header = if body {
                varint_len(5)
            } else {
                WIDE_ACK_HEADER_BYTES
            };
            assert_eq!(size, header + 125);
            let view = if body {
                inspect_body_for(true, &packet[..size], 16, config(1024))?
            } else {
                assert_eq!(packet[6], 3);
                inspect_packet_for(
                    &packet[..size],
                    context(EndpointRole::Initiator),
                    16,
                    config(1024),
                )?
            };
            let PacketView::WideAck { prefix, bitmap } = view else {
                return Err("expected wide ACK".into());
            };
            assert_eq!(prefix, 5);
            assert_eq!(bitmap.len(), 125);
            assert_eq!(view.acknowledges(SourceId(4)), Some(true));
            assert_eq!(view.acknowledges(SourceId(5)), Some(false));
            assert_eq!(view.acknowledges(SourceId(70)), Some(true));
            assert_eq!(view.acknowledges(SourceId(999)), Some(true));
            assert_eq!(view.acknowledges(SourceId(1000)), Some(false));
            sender.receive_view(view, ms(1))?;
            // Only the lost source remains retained.
            assert_eq!(sender.retained().send_records, 1);
            assert!(!sender.source_confirmed(SourceId(5))?);
            assert!(sender.source_confirmed(SourceId(999))?);
        }
    }
    Ok(())
}

#[test]
fn non_canonical_oversized_and_cross_format_feedback_is_refused() -> Result {
    let wide = config(1024);
    let legacy = config(64);
    let initiator = context(EndpointRole::Initiator);
    let mut packet = vec![0; WIDE_ACK_HEADER_BYTES + 129];
    write_common(
        &mut packet,
        context(EndpointRole::Responder),
        Profile::Selective,
        3,
    );
    packet[32..40].copy_from_slice(&5_u64.to_be_bytes());
    let check =
        |bytes: &[u8], direction| inspect_packet_for(bytes, initiator, 16, direction).is_ok();
    // Canonical one-byte bitmap acknowledging offset 1.
    packet[40] = 0b10;
    assert!(check(&packet[..41], wide));
    // Bit zero set, trailing zero byte, or longer than ceil(window / 8).
    packet[40] = 0b11;
    assert!(!check(&packet[..41], wide));
    packet[40] = 0b10;
    packet[41] = 0;
    assert!(!check(&packet[..42], wide));
    packet[40 + 128] = 1;
    assert!(!check(&packet[..40 + 129], wide));
    // A wide ACK is malformed in a legacy direction, and the reverse.
    assert!(!check(&packet[..41], legacy));
    let mut old = [0; ACK_PACKET_BYTES];
    write_common(
        &mut old,
        context(EndpointRole::Responder),
        Profile::Selective,
        2,
    );
    assert!(check(&old, legacy));
    assert!(!check(&old, wide));
    // Bodies: canonical rules and the direction-selected form.
    let mut body = Vec::new();
    body.push(5);
    body.push(0b100);
    assert!(inspect_body_for(true, &body, 16, wide).is_ok());
    body.push(0);
    assert!(inspect_body_for(true, &body, 16, wide).is_err());
    body.truncate(1);
    body.push(1);
    assert!(inspect_body_for(true, &body, 16, wide).is_err());
    body.truncate(1);
    body.extend(std::iter::repeat_n(0xff_u8, 128));
    body[1] = 0xfe;
    assert!(inspect_body_for(true, &body, 16, wide).is_ok());
    body.push(1);
    assert!(inspect_body_for(true, &body, 16, wide).is_err());
    // Prefix plus highest offset must not overflow.
    let overflow = [
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01, 0x02,
    ];
    assert!(inspect_body_for(true, &overflow, 16, wide).is_err());
    // A sender in a legacy direction refuses a typed wide view, and the reverse.
    let mut sender = make(64, EndpointRole::Initiator, false)?;
    assert_eq!(
        sender.receive_view(
            PacketView::WideAck {
                prefix: 0,
                bitmap: &[]
            },
            ms(0)
        ),
        Err(RecoveryError::MalformedPacket)
    );
    let mut sender = make(1024, EndpointRole::Initiator, false)?;
    assert_eq!(
        sender.receive_view(
            PacketView::Ack {
                prefix: 0,
                bitmap: 0
            },
            ms(0)
        ),
        Err(RecoveryError::MalformedPacket)
    );
    Ok(())
}

#[test]
fn wide_ack_cannot_acknowledge_unsent_sources() -> Result {
    let mut sender = make(256, EndpointRole::Initiator, true)?;
    let mut packet = vec![0; 512];
    for source in 0..100 {
        sender.submit(&payload(source), ms(0))?;
        sender.poll_source(ms(0), &mut packet)?.ok_or("source")?;
    }
    // Bit 100 relative to prefix 0 claims source 100, which was never sent.
    let mut bitmap = [0_u8; 13];
    bitmap[12] = 1 << 4;
    assert_eq!(
        sender.receive_view(
            PacketView::WideAck {
                prefix: 0,
                bitmap: &bitmap
            },
            ms(1)
        ),
        Err(RecoveryError::UnsentAcknowledgement)
    );
    assert_eq!(sender.retained().send_records, 100);
    Ok(())
}

#[test]
fn large_windows_transfer_every_byte_over_loss_reorder_and_duplicates() -> Result {
    for reserved in [false, true] {
        let mut left = make(2048, EndpointRole::Initiator, reserved)?;
        let mut right = make(2048, EndpointRole::Responder, reserved)?;
        let total = 6000_u64;
        let mut submitted = 0;
        let mut network: Vec<(u64, bool, Vec<u8>)> = Vec::new();
        let mut emitted = 0_u64;
        let mut delivered = 0_u64;
        let mut most_in_flight = 0;
        let mut dropped = 0;
        for tick in 0..20_000_u64 {
            while submitted < total && left.submit(&payload(submitted), ms(tick)).is_ok() {
                submitted += 1;
            }
            most_in_flight = most_in_flight.max(left.retained().send_records);
            for (to_right, engine) in [(true, &mut left), (false, &mut right)] {
                for _ in 0..64 {
                    let mut packet = vec![0; engine.max_packet_bytes()];
                    let Some(size) = engine.poll(ms(tick), &mut packet)? else {
                        break;
                    };
                    packet.truncate(size);
                    emitted += 1;
                    if emitted.is_multiple_of(7) {
                        dropped += 1;
                        continue;
                    }
                    let due = tick + 20 + (emitted * 7) % 11;
                    if emitted.is_multiple_of(13) {
                        network.push((due + 3, to_right, packet.clone()));
                    }
                    network.push((due, to_right, packet));
                }
            }
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
            let mut output = [0; 64];
            while let Some((source, length)) = right.poll_delivered(&mut output)? {
                assert_eq!(source, delivered);
                assert_eq!(&output[..length], payload(source).as_slice());
                delivered += 1;
            }
            if delivered == total && network.is_empty() && left.drained() {
                break;
            }
        }
        assert_eq!(delivered, total, "reserved={reserved}");
        assert!(left.drained());
        assert!(dropped > 0);
        assert!(left.statistics().retransmissions > 0);
        // The point of the wide ACK: far more than 64 sources were in flight.
        assert!(most_in_flight > 1000, "in flight {most_in_flight}");
    }
    Ok(())
}

/// Send sources `0..count` at `now`, returning nothing (sources are retained).
fn send_all(sender: &mut SelectiveRepeat, count: u64, now: Duration) -> Result {
    let mut packet = vec![0; 256];
    for source in 0..count {
        sender.submit(&payload(source), now)?;
        let size = sender.poll_source(now, &mut packet)?.ok_or("source")?;
        assert!(size > 0);
    }
    Ok(())
}
/// Wide bitmap acknowledging exactly the given offsets above the prefix.
fn bits(offsets: &[u64]) -> Vec<u8> {
    let length = offsets
        .iter()
        .max()
        .map_or(0, |highest| (highest / 8) as usize + 1);
    let mut bitmap = vec![0; length];
    for offset in offsets {
        bitmap[(offset / 8) as usize] |= 1 << (offset % 8);
    }
    bitmap
}
fn oldest_retry(sender: &SelectiveRepeat) -> Result<Option<Duration>> {
    Ok(sender
        .admission_snapshot(0)?
        .oldest
        .and_then(|flight| flight.retry_at))
}

#[test]
fn adaptive_rto_follows_rfc6298_smoothing_and_karn() -> Result {
    for reserved in [false, true] {
        let mut sender = make(256, EndpointRole::Initiator, reserved)?;
        // Before any sample the first timer is the configured initial RTO.
        send_all(&mut sender, 1, ms(0))?;
        assert_eq!(oldest_retry(&sender)?, Some(ms(40)));
        // One sample of 30 ms: srtt 30, rttvar 15, RTO = 30 + 4 * 15 = 90 ms.
        sender.receive_view(
            PacketView::WideAck {
                prefix: 1,
                bitmap: &[],
            },
            ms(30),
        )?;
        let mut packet = vec![0; 256];
        sender.submit(&payload(1), ms(30))?;
        sender.poll_source(ms(30), &mut packet)?.ok_or("source")?;
        assert_eq!(oldest_retry(&sender)?, Some(ms(120)));
        // A timeout retry doubles that flight's timer (90 -> 180 ms).
        sender.poll_source(ms(120), &mut packet)?.ok_or("retry")?;
        assert_eq!(oldest_retry(&sender)?, Some(ms(300)));
        // Karn: releasing the retried flight gives no sample, so a new first
        // send still uses the 90 ms RTO from the single valid sample.
        sender.receive_view(
            PacketView::WideAck {
                prefix: 2,
                bitmap: &[],
            },
            ms(301),
        )?;
        sender.submit(&payload(2), ms(301))?;
        sender.poll_source(ms(301), &mut packet)?.ok_or("source")?;
        assert_eq!(oldest_retry(&sender)?, Some(ms(391)));
        // A second sample of 10 ms: rttvar = (3*15 + 20) / 4 = 16.25,
        // srtt = (7*30 + 10) / 8 = 27.5, RTO = 27.5 + 65 = 92.5 ms.
        sender.receive_view(
            PacketView::WideAck {
                prefix: 3,
                bitmap: &[],
            },
            ms(311),
        )?;
        sender.submit(&payload(3), ms(311))?;
        sender.poll_source(ms(311), &mut packet)?.ok_or("source")?;
        assert_eq!(
            oldest_retry(&sender)?,
            Some(ms(311) + Duration::from_micros(92_500))
        );
    }
    Ok(())
}

#[test]
fn adaptive_rto_is_floored_and_capped() -> Result {
    let mut sender = make(256, EndpointRole::Initiator, true)?;
    let mut packet = vec![0; 256];
    // A 1 ms sample gives 1 + 2 = 3 ms, raised to the 20 ms floor.
    send_all(&mut sender, 1, ms(0))?;
    sender.receive_view(
        PacketView::WideAck {
            prefix: 1,
            bitmap: &[],
        },
        ms(1),
    )?;
    sender.submit(&payload(1), ms(1))?;
    sender.poll_source(ms(1), &mut packet)?.ok_or("source")?;
    assert_eq!(oldest_retry(&sender)?, Some(ms(1) + ADAPTIVE_RTO_FLOOR));
    // A 300 ms sample after that is capped at maximum_rto (320 ms).
    sender.receive_view(
        PacketView::WideAck {
            prefix: 2,
            bitmap: &[],
        },
        ms(301),
    )?;
    sender.submit(&payload(2), ms(301))?;
    sender.poll_source(ms(301), &mut packet)?.ok_or("source")?;
    assert_eq!(oldest_retry(&sender)?, Some(ms(301 + 320)));
    Ok(())
}

#[test]
fn fast_resend_follows_transmission_order_evidence_without_doubling() -> Result {
    let mut sender = make(256, EndpointRole::Initiator, true)?;
    let mut packet = vec![0; 256];
    // Establish srtt = 30 ms (RTO 90 ms). Source 0 is transmission 1.
    send_all(&mut sender, 1, ms(0))?;
    sender.receive_view(
        PacketView::WideAck {
            prefix: 1,
            bitmap: &[],
        },
        ms(30),
    )?;
    // Sources 1..=10 are transmissions 2..=11.
    for source in 1..=10 {
        sender.submit(&payload(source), ms(30))?;
        sender.poll_source(ms(30), &mut packet)?.ok_or("source")?;
    }
    // Source 1 is missing while copies sent after it (2..=10) arrived: it is
    // due at once, long before its 120 ms timer, with no wall-clock wait.
    let gap = bits(&(1..=9).collect::<Vec<_>>());
    sender.receive_view(
        PacketView::WideAck {
            prefix: 1,
            bitmap: &gap,
        },
        ms(50),
    )?;
    assert_eq!(sender.statistics().fast_retransmissions, 1);
    let size = sender
        .poll_source(ms(50), &mut packet)?
        .ok_or("fast resend")?;
    assert_eq!(
        inspect_packet_for(
            &packet[..size],
            context(EndpointRole::Responder),
            16,
            config(256)
        )?,
        PacketView::Data {
            source: SourceId(1),
            payload: &payload(1)
        }
    );
    assert_eq!(sender.statistics().retransmissions, 1);
    // Its next timer is the adaptive RTO, not doubled. The ACK at 50 ms
    // released sources 2..=10 (a 20 ms sample): rttvar = (3*15 + 10) / 4 =
    // 13.75, srtt = (7*30 + 20) / 8 = 28.75, so RTO = 28.75 + 55 = 83.75 ms.
    assert_eq!(
        oldest_retry(&sender)?,
        Some(ms(50) + Duration::from_micros(83_750))
    );
    // The same evidence again, however late (a queue-inflated RTT), cannot
    // re-send the copy still in flight: nothing sent after it is acknowledged.
    for at in [80, 120] {
        sender.receive_view(
            PacketView::WideAck {
                prefix: 1,
                bitmap: &gap,
            },
            ms(at),
        )?;
        assert_eq!(sender.statistics().fast_retransmissions, 1);
        assert_eq!(sender.poll_source(ms(at), &mut packet)?, None);
    }
    // Three copies sent after the resend (sources 11..=13) are acknowledged
    // while source 1 is still missing: that resend was lost too.
    for source in 11..=13 {
        sender.submit(&payload(source), ms(125))?;
        sender.poll_source(ms(125), &mut packet)?.ok_or("source")?;
    }
    sender.receive_view(
        PacketView::WideAck {
            prefix: 1,
            bitmap: &bits(&(1..=12).collect::<Vec<_>>()),
        },
        ms(130),
    )?;
    assert_eq!(sender.statistics().fast_retransmissions, 2);
    assert!(sender.poll_source(ms(130), &mut packet)?.is_some());
    // Fewer than three later transmissions acknowledged are not loss evidence.
    let mut other = make(256, EndpointRole::Initiator, true)?;
    send_all(&mut other, 1, ms(0))?;
    other.receive_view(
        PacketView::WideAck {
            prefix: 1,
            bitmap: &[],
        },
        ms(30),
    )?;
    for source in 1..=3 {
        other.submit(&payload(source), ms(30))?;
        other.poll_source(ms(30), &mut packet)?.ok_or("source")?;
    }
    other.receive_view(
        PacketView::WideAck {
            prefix: 1,
            bitmap: &bits(&[1, 2]),
        },
        ms(70),
    )?;
    assert_eq!(other.statistics().fast_retransmissions, 0);
    Ok(())
}

#[test]
fn legacy_windows_keep_the_classic_timer_and_never_fast_resend() -> Result {
    let mut sender = make(64, EndpointRole::Initiator, true)?;
    let mut packet = vec![0; 256];
    send_all(&mut sender, 1, ms(0))?;
    // Classic: an ACK sample does not change the fixed initial RTO.
    sender.receive_view(
        PacketView::Ack {
            prefix: 1,
            bitmap: 0,
        },
        ms(30),
    )?;
    for source in 1..=10 {
        sender.submit(&payload(source), ms(30))?;
        sender.poll_source(ms(30), &mut packet)?.ok_or("source")?;
    }
    assert_eq!(oldest_retry(&sender)?, Some(ms(70)));
    // Gap evidence never resends early on a classic direction.
    sender.receive_view(
        PacketView::Ack {
            prefix: 1,
            bitmap: 0b11_1111_1110,
        },
        ms(65),
    )?;
    assert_eq!(sender.statistics().fast_retransmissions, 0);
    assert_eq!(sender.poll_source(ms(65), &mut packet)?, None);
    // The timeout retry doubles from the fixed 40 ms: 70 + 80 ms.
    sender.poll_source(ms(70), &mut packet)?.ok_or("retry")?;
    assert_eq!(oldest_retry(&sender)?, Some(ms(150)));
    Ok(())
}

/// The window-independent wide ACK path (no observation) and the full-window
/// observed path give identical results, state and later output.
#[test]
fn wide_ack_fast_path_matches_the_full_window_path() -> Result {
    let mut state = 0x2545_f491_4f6c_dd1d_u64;
    let mut next = move || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    for reserved in [true, false] {
        let mut fast = make(256, EndpointRole::Initiator, reserved)?;
        let mut full = make(256, EndpointRole::Initiator, reserved)?;
        let (mut out_fast, mut out_full) = (vec![0; 256], vec![0; 256]);
        let mut sent = 0_u64;
        let mut now = ms(0);
        for _ in 0..20_000 {
            now += Duration::from_micros(next() % 4_000);
            match next() % 8 {
                0..=2 => {
                    let a = fast.submit(&payload(sent), now);
                    let b = full.submit(&payload(sent), now);
                    assert_eq!(a, b);
                    if a.is_ok() {
                        sent += 1;
                    }
                }
                3..=4 => {
                    let a = fast.poll_source(now, &mut out_fast);
                    let b = full.poll_source(now, &mut out_full);
                    assert_eq!(a, b);
                    if let Ok(Some(size)) = a {
                        assert_eq!(out_fast[..size], out_full[..size]);
                    }
                }
                _ => {
                    let prefix = if sent == 0 { 0 } else { next() % (sent + 1) };
                    let span = sent.saturating_sub(prefix + 1).min(255);
                    let mut bitmap = vec![0_u8; (span as usize).div_ceil(8) + 1];
                    for offset in 1..=span {
                        if next() % 3 != 0 {
                            bitmap[(offset / 8) as usize] |= 1 << (offset % 8);
                        }
                    }
                    while bitmap.last() == Some(&0) {
                        bitmap.pop();
                    }
                    let view = PacketView::WideAck {
                        prefix,
                        bitmap: &bitmap,
                    };
                    let mut observation = None;
                    let a = fast.receive_view(view, now);
                    let b = full.receive_view_observed(view, now, &mut observation);
                    assert_eq!(a, b);
                }
            }
            assert_eq!(fast.statistics(), full.statistics());
            assert_eq!(fast.retained(), full.retained());
            assert_eq!(fast.admission_snapshot(0), full.admission_snapshot(0));
        }
        assert!(fast.statistics().fast_retransmissions > 0);
        assert!(fast.statistics().retransmissions > 0);
    }
    Ok(())
}
