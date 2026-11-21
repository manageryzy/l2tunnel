use super::*;

const CONFIG: KcpLikeConfig = KcpLikeConfig {
    fast_resend: 2,
    interval_ms: 10,
    minimum_rto_ms: 30,
    maximum_rto_ms: 320,
};

#[test]
fn canonical_parameters_and_rto_bounds() -> Result {
    assert_eq!(CONFIG.encode()?, [0, 2, 0, 10, 0, 30, 1, 64]);
    assert_eq!(KcpLikeConfig::decode(CONFIG.encode()?)?, CONFIG);
    for invalid in [
        KcpLikeConfig {
            fast_resend: 0,
            ..CONFIG
        },
        KcpLikeConfig {
            interval_ms: 0,
            ..CONFIG
        },
        KcpLikeConfig {
            interval_ms: 5001,
            ..CONFIG
        },
        KcpLikeConfig {
            minimum_rto_ms: 0,
            ..CONFIG
        },
        KcpLikeConfig {
            maximum_rto_ms: 29,
            ..CONFIG
        },
    ] {
        assert_eq!(invalid.encode(), Err(RecoveryError::InvalidConfig));
        assert_eq!(
            config(CompactRecovery::KcpLike(invalid), 16, 64, 78),
            Err(RecoveryError::InvalidConfig)
        );
    }
    assert_eq!(CONFIG.estimated_rto(None, 0.0)?, ms(200));
    assert_eq!(CONFIG.estimated_rto(Some(0.075), 0.001)?, ms(85));
    assert_eq!(CONFIG.estimated_rto(Some(0.075), 0.010)?, ms(115));
    assert_eq!(CONFIG.estimated_rto(Some(0.001), 0.0)?, ms(30));
    assert_eq!(CONFIG.estimated_rto(Some(2.0), 0.2)?, ms(320));
    Ok(())
}

#[test]
fn timeout_uses_actual_paid_time_and_capped_per_attempt_backoff() -> Result {
    let (mut tx, _) = pair(CompactRecovery::KcpLike(CONFIG))?;
    let id = SourceId(tx.submit(b"held", ms(0))?);
    let mut buf = [0; 128];
    assert!(tx.poll_source(ms(0), &mut buf)?.is_some());
    assert_eq!(tx.source_deadline(), None);
    assert_eq!(tx.poll_source(ms(299), &mut buf)?, None);
    let token = tx.pending_transmission(id).ok_or("held original")?;
    tx.confirm_transmission_at(ms(300), ms(280), token)?;
    for (due, paid, duration) in [(480, 500, 300), (800, 805, 320), (1125, 1130, 320)] {
        assert_eq!(tx.source_deadline(), Some(ms(due)));
        assert_eq!(tx.poll_source(ms(due - 1), &mut buf)?, None);
        assert!(tx.poll_source(ms(due), &mut buf)?.is_some());
        let token = tx.pending_transmission(id).ok_or("retry physical token")?;
        assert_eq!(tx.source_deadline(), None);
        tx.confirm_transmission(ms(paid), token)?;
        assert_eq!(tx.source_deadline(), Some(ms(paid + duration)));
    }
    assert_eq!(tx.statistics().retransmissions, 3);
    assert!(!tx.source_confirmed(id)?);
    Ok(())
}

#[test]
fn idle_ack_repeats_do_not_count_again_and_distinct_real_evidence_recovers_old_hole() -> Result {
    let mode = CompactRecovery::KcpLike(CONFIG);
    let (mut tx, mut rx) = pair(mode)?;
    let _erased = emit(&mut tx, ms(0), ms(0), b"gap")?;
    let later = emit(&mut tx, ms(1), ms(2), b"later")?;
    rx.receive(&later, ms(30))?;
    let first = feedback(&mut rx, ms(35))?;
    let second = feedback(&mut rx, ms(40))?;
    let third = feedback(&mut rx, ms(45))?;
    tx.receive(&first, ms(60))?;
    let mut buf = [0; 128];
    tx.receive(&first, ms(61))?;
    assert_eq!(tx.poll_source(ms(61), &mut buf)?, None);
    assert!(tx.source_confirmed(SourceId(1))?);
    assert!(!tx.source_confirmed(SourceId(0))?);
    assert_eq!(tx.timing()?.rto, ms(159)); // (60 - 2 - 5) ms, first variance = sample / 2.
    tx.receive(&second, ms(62))?;
    tx.receive(&third, ms(63))?;
    assert_eq!(tx.poll_source(ms(63), &mut buf)?, None);
    assert_eq!(tx.source_deadline(), Some(ms(200)));
    let newest = emit(&mut tx, ms(64), ms(65), b"next")?;
    rx.receive(&newest, ms(100))?;
    let distinct = feedback(&mut rx, ms(105))?;
    tx.receive(&distinct, ms(140))?;
    let size = tx.poll_source(ms(140), &mut buf)?.ok_or("fast retry")?;
    let restored = buf[..size].to_vec();
    let token = tx.pending_transmission(SourceId(0)).ok_or("fast token")?;
    tx.confirm_transmission(ms(145), token)?;
    // Unchanged attempt RTO for a fast retransmission. No timer starts while unpaid.
    assert_eq!(tx.source_deadline(), Some(ms(345)));
    tx.receive(&first, ms(146))?;
    tx.receive(&feedback(&mut rx, ms(110))?, ms(147))?;
    assert_eq!(tx.poll_source(ms(147), &mut buf)?, None);
    assert_eq!(rx.poll_delivered(&mut buf)?, None);
    rx.receive(&restored, ms(180))?;
    assert_eq!(rx.poll_delivered(&mut buf)?, Some((0, 3)));
    assert_eq!(&buf[..3], b"gap");
    assert_eq!(rx.poll_delivered(&mut buf)?, Some((1, 5)));
    assert_eq!(rx.poll_delivered(&mut buf)?, Some((2, 4)));
    assert_eq!(&buf[..4], b"next");
    tx.receive(&feedback(&mut rx, ms(185))?, ms(220))?;
    assert!(tx.source_confirmed(SourceId(0))?);
    assert_eq!(tx.source_deadline(), None);
    assert_eq!(tx.retained().send_records, 0);
    Ok(())
}

#[test]
fn reordered_data_batch_counts_its_qualifying_higher_source_only_once() -> Result {
    let (mut tx, mut rx) = pair(CompactRecovery::KcpLike(CONFIG))?;
    let mut sources = Vec::new();
    for id in 0..5u8 {
        let at = ms(u64::from(id) * 10);
        sources.push(emit(&mut tx, at, at, &[id])?);
    }
    // With source 2 lost, the last arrival (1) is too low for fast ACK. The
    // pinned C conservative representative for this input is source 3 at 30 ms.
    rx.receive(&sources[0], ms(60))?;
    rx.receive(&sources[3], ms(61))?;
    rx.receive(&sources[1], ms(62))?;
    let first = feedback(&mut rx, ms(65))?;
    let repeat = feedback(&mut rx, ms(70))?;
    // Erase the first feedback: its independently emitted positive repeat still counts once.
    tx.receive(&repeat, ms(105))?;
    let timing = tx.timing()?;
    assert_eq!(timing.sampled_serial, 4); // Source 3's one-based physical attempt number.
    assert_eq!(timing.rto, ms(198)); // 105 - paid 30 - receiver hold (70 - 61) = 66 ms.
    let mut buf = [0; 128];
    assert_eq!(tx.poll_source(ms(105), &mut buf)?, None);
    tx.receive(&first, ms(106))?;
    assert_eq!(tx.poll_source(ms(106), &mut buf)?, None);
    rx.receive(&sources[4], ms(72))?;
    tx.receive(&feedback(&mut rx, ms(77))?, ms(112))?;
    let len = tx
        .poll_source(ms(112), &mut buf)?
        .ok_or("fast repair after two genuine batches")?;
    let token = tx
        .pending_transmission(SourceId(2))
        .ok_or("lost source 2")?;
    tx.confirm_transmission(ms(113), token)?;
    rx.receive(&buf[..len], ms(148))?;
    for id in 0..5 {
        assert_eq!(rx.poll_delivered(&mut buf)?, Some((id, 1)));
        assert_eq!(buf[0], id as u8);
    }
    tx.receive(&feedback(&mut rx, ms(153))?, ms(188))?;
    assert_eq!(tx.retained().send_records, 0);
    Ok(())
}
