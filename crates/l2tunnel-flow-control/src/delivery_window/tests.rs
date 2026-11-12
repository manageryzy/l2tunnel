use super::*;
type TestResult = Result<(), Box<dyn std::error::Error>>;
fn config() -> Config {
    Config {
        target_bandwidth_bps: 80_000_000,
        bootstrap_rtt_micros: 70_000,
        min_rtt_micros: 2_000,
        max_rtt_micros: 200_000,
        headroom_percent: 125,
        minimum_bytes: 1500,
        max_inflight_bytes: 4_000_000,
        max_records: 8192,
        max_packet_bytes: 1500,
        metadata_limit_bytes: 1_000_000,
        sample_ttl_micros: 1_000_000,
        flush_timeout_micros: 2_000_000,
    }
}
#[test]
fn bootstrap_80mbps_70ms_has_875kb_separate_actual_byte_and_record_limits() -> TestResult {
    let mut c = Controller::new(config(), Micros(0))?;
    assert_eq!(c.status(Micros(0))?.target_bytes, 875_000);
    for _ in 0..583 {
        c.admit(1500, Micros(0))?;
    }
    c.admit(500, Micros(0))?;
    assert_eq!(c.preview_admit(1, Micros(0)), Err(Error::Blocked));
    assert_eq!(
        c.status(Micros(0))?.outstanding,
        Credit {
            bytes: 875_000,
            records: 584
        }
    );
    let mut cfg = config();
    cfg.max_records = 2;
    let mut small = Controller::new(cfg, Micros(0))?;
    let first = small.admit(40, Micros(0))?;
    small.admit(40, Micros(0))?;
    assert_eq!(small.preview_admit(40, Micros(0)), Err(Error::Blocked));
    assert_eq!(small.credit_at_record(1)?, first);
    assert_eq!(small.status(Micros(0))?.outstanding.bytes, 80);
    Ok(())
}
#[test]
fn measured_rtt_grows_shrinks_clamps_and_stales_without_revoking_debt() -> TestResult {
    let mut c = Controller::new(config(), Micros(0))?;
    let first = c.admit(100, Micros(0))?;
    c.confirm_flushed(1, Micros(100))?;
    c.delivered(first, Micros(140_100))?;
    assert_eq!(c.status(Micros(140_100))?.target_bytes, 1_750_000);
    for _ in 0..1166 {
        c.admit(1500, Micros(140_100))?;
    }
    let second = c.credit_at_record(2)?;
    c.confirm_flushed(c.admitted.records, Micros(140_100))?;
    c.delivered(second, Micros(142_100))?;
    let s = c.status(Micros(142_100))?;
    assert_eq!(s.sample.map(|s| s.smoothed_micros), Some(122_750));
    assert_eq!(s.outstanding.bytes, 1_747_500);
    assert!(s.outstanding.bytes > s.target_bytes);
    assert_eq!(c.preview_admit(1, Micros(142_100)), Err(Error::Blocked));
    assert_eq!(c.status(Micros(1_142_100))?.target_bytes, 875_000);
    assert!(!c.status(Micros(1_142_100))?.sample_fresh);
    Ok(())
}
#[test]
fn cumulative_feedback_uses_actual_small_bytes_and_latest_known_full_flush() -> TestResult {
    let mut c = Controller::new(config(), Micros(0))?;
    c.admit(40, Micros(0))?;
    c.confirm_flushed(1, Micros(10))?;
    let end = c.admit(60, Micros(20))?;
    c.confirm_flushed(2, Micros(30))?;
    c.delivered(end, Micros(70_030))?;
    let s = c.status(Micros(70_030))?;
    assert_eq!(s.outstanding, Credit::default());
    assert_eq!(
        s.sample.map(|s| (s.flushed_at, s.raw_micros)),
        Some((Micros(30), 70_000))
    );
    assert_eq!(s.retained_records, 0);
    assert_eq!(c.delivered(end, Micros(70_031))?, Update::Duplicate);
    assert_eq!(c.status(Micros(70_031))?.sample, s.sample);
    assert_eq!(
        c.delivered(
            Credit {
                bytes: 40,
                records: 1
            },
            Micros(70_032)
        ),
        Err(Error::Stale)
    );
    assert_eq!(
        c.delivered(
            Credit {
                bytes: 101,
                records: 2
            },
            Micros(70_032)
        ),
        Err(Error::Feedback)
    );
    assert_eq!(
        c.delivered(
            Credit {
                bytes: 101,
                records: 3
            },
            Micros(70_032)
        ),
        Err(Error::Feedback)
    );
    Ok(())
}
#[test]
fn early_feedback_never_invents_flush_timestamp_and_pending_metadata_is_bounded() -> TestResult {
    let mut cfg = config();
    cfg.max_records = 2;
    let mut c = Controller::new(cfg, Micros(0))?;
    let a = c.admit(40, Micros(0))?;
    let b = c.admit(60, Micros(0))?;
    c.delivered(b, Micros(100))?;
    assert_eq!(c.status(Micros(100))?.outstanding.bytes, 0);
    assert_eq!(c.status(Micros(100))?.retained_records, 2);
    assert_eq!(c.preview_admit(1, Micros(100)), Err(Error::Blocked));
    assert_eq!(c.status(Micros(100))?.sample, None);
    c.confirm_flushed(a.records, Micros(200))?;
    assert_eq!(c.status(Micros(200))?.retained_records, 1);
    c.confirm_flushed(b.records, Micros(200))?;
    assert_eq!(c.status(Micros(200))?.sample, None);
    let next = c.admit(20, Micros(201))?;
    assert_eq!(
        next,
        Credit {
            bytes: 120,
            records: 3
        }
    );
    Ok(())
}
#[test]
fn retries_cannot_renew_original_flush_deadline_and_expiry_is_terminal() -> TestResult {
    let mut c = Controller::new(config(), Micros(100))?;
    let a = c.admit(40, Micros(100))?;
    c.delivered(a, Micros(200))?;
    c.delivered(a, Micros(1_000_000))?;
    c.confirm_flushed(0, Micros(1_999_999))?;
    assert_eq!(
        c.status(Micros(2_000_099))?.next_flush_deadline,
        Some(Micros(2_000_100))
    );
    c.tick(Micros(2_000_099))?;
    assert_eq!(
        c.confirm_flushed(1, Micros(2_000_100)),
        Err(Error::FlushExpired)
    );
    assert_eq!(c.tick(Micros(2_000_101)), Err(Error::FlushExpired));
    assert!(c.status(Micros(2_000_101))?.failed);
    Ok(())
}
#[test]
fn invalid_bounds_time_and_feedback_preserve_accounting() -> TestResult {
    let cfg = config();
    let mut bad = cfg;
    bad.metadata_limit_bytes = cfg.metadata_bytes()? - 1;
    assert!(matches!(
        Controller::new(bad, Micros(0)),
        Err(Error::Configuration)
    ));
    bad = cfg;
    bad.max_inflight_bytes = 64 * 1024 * 1024 + 1;
    assert!(matches!(
        Controller::new(bad, Micros(0)),
        Err(Error::Configuration)
    ));
    assert!(matches!(
        Controller::new(cfg, Micros(u64::MAX)),
        Err(Error::Time)
    ));
    let mut c = Controller::new(cfg, Micros(0))?;
    let a = c.admit(100, Micros(10))?;
    let before = c.status(Micros(10))?;
    assert_eq!(
        c.delivered(Credit { bytes: 99, ..a }, Micros(11)),
        Err(Error::Feedback)
    );
    assert_eq!(c.confirm_flushed(2, Micros(11)), Err(Error::Flush));
    assert_eq!(c.admit(0, Micros(11)), Err(Error::Packet));
    assert_eq!(c.admit(1501, Micros(11)), Err(Error::Packet));
    assert_eq!(c.tick(Micros(9)), Err(Error::Time));
    assert_eq!(c.status(Micros(10))?, before);
    Ok(())
}

#[test]
fn sample_clamps_ring_wrap_and_cumulative_overflow_are_bounded() -> TestResult {
    let mut cfg = config();
    cfg.max_records = 2;
    let mut c = Controller::new(cfg, Micros(0))?;
    for (start, elapsed, expected) in [(0, 1, 2000), (2_000_000, 400_000, 200_000)] {
        let end = c.admit(40, Micros(start))?;
        c.confirm_flushed(end.records, Micros(start))?;
        c.delivered(end, Micros(start + elapsed))?;
        let s = c.status(Micros(start + elapsed))?;
        assert_eq!(s.sample.map(|s| s.smoothed_micros), Some(expected));
        assert_eq!(s.sample.map(|s| s.raw_micros), Some(elapsed));
        assert_eq!(s.retained_records, 0);
    }
    for i in 0..20 {
        let at = Micros(2_500_000 + i * 10);
        let end = c.admit(60, at)?;
        c.confirm_flushed(end.records, at)?;
        c.delivered(end, Micros(at.0 + 1))?;
    }
    assert_eq!(c.status(Micros(2_500_191))?.outstanding, Credit::default());
    c.admitted = Credit {
        bytes: u64::MAX,
        records: u64::MAX,
    };
    c.delivered = c.admitted;
    assert_eq!(c.preview_admit(1, Micros(2_500_192)), Err(Error::Exhausted));
    Ok(())
}

#[test]
fn original_flush_and_feedback_timestamps_survive_later_actor_operations() -> TestResult {
    let mut c = Controller::new(config(), Micros(0))?;
    let first = c.admit(100, Micros(100))?;
    c.admit(200, Micros(200))?;
    // Actual writer completion precedes a later admission, but callback arrives later.
    c.confirm_flushed_at(first.records, Micros(150), Micros(300))?;
    c.tick(Micros(400))?;
    c.delivered_at(first, Micros(250), Micros(500))?;
    let sample = c.status(Micros(500))?.sample.ok_or("original sample")?;
    assert_eq!(
        (sample.flushed_at, sample.feedback_at, sample.raw_micros),
        (Micros(150), Micros(250), 100)
    );
    assert!(!c.status(Micros(1_000_250))?.sample_fresh);
    assert_eq!(c.status(Micros(1_000_250))?.target_bytes, 875_000);
    Ok(())
}
#[test]
fn forged_actual_event_times_fail_before_accounting_mutation() -> TestResult {
    let mut c = Controller::new(config(), Micros(0))?;
    let end = c.admit(100, Micros(100))?;
    let before = c.status(Micros(100))?;
    assert_eq!(
        c.confirm_flushed_at(1, Micros(99), Micros(200)),
        Err(Error::Time)
    );
    assert_eq!(
        c.confirm_flushed_at(1, Micros(201), Micros(200)),
        Err(Error::Time)
    );
    assert_eq!(
        c.delivered_at(end, Micros(99), Micros(200)),
        Err(Error::Time)
    );
    assert_eq!(
        c.delivered_at(end, Micros(201), Micros(200)),
        Err(Error::Time)
    );
    assert_eq!(c.status(Micros(100))?, before);
    c.confirm_flushed_at(1, Micros(150), Micros(200))?;
    assert_eq!(
        c.delivered_at(end, Micros(190), Micros(199)),
        Err(Error::Time)
    );
    Ok(())
}
#[test]
fn delayed_actual_flush_never_resamples_old_feedback_or_revives_expiry() -> TestResult {
    let mut c = Controller::new(config(), Micros(0))?;
    let end = c.admit(100, Micros(100))?;
    c.delivered_at(end, Micros(200), Micros(300))?;
    c.confirm_flushed_at(1, Micros(150), Micros(400))?;
    assert_eq!(c.status(Micros(400))?.sample, None);
    c.delivered_at(end, Micros(200), Micros(500))?;
    assert_eq!(c.status(Micros(500))?.sample, None);
    let mut expired = Controller::new(config(), Micros(0))?;
    expired.admit(100, Micros(100))?;
    assert_eq!(
        expired.confirm_flushed_at(1, Micros(150), Micros(2_000_100)),
        Err(Error::FlushExpired)
    );
    assert_eq!(
        expired.confirm_flushed_at(1, Micros(150), Micros(2_000_101)),
        Err(Error::FlushExpired)
    );
    assert_eq!(
        expired.status(Micros(2_000_101))?.next_flush_deadline,
        Some(Micros(2_000_100))
    );
    Ok(())
}

fn assert_prefix_split(s: Status) {
    for (a, f, d) in [
        (s.admitted.bytes, s.flushed.bytes, s.delivered.bytes),
        (s.admitted.records, s.flushed.records, s.delivered.records),
    ] {
        assert!(a >= f && a >= d);
        let unflushed_undelivered = a - f.max(d);
        let flushed_unacknowledged = f.saturating_sub(d);
        let delivered_awaiting_flush = d.saturating_sub(f);
        assert_eq!(a - d, unflushed_undelivered + flushed_unacknowledged);
        assert_eq!(a - f, unflushed_undelivered + delivered_awaiting_flush);
    }
}
#[test]
fn flushed_actual_byte_prefix_exposes_local_reservation_and_early_feedback_split() -> TestResult {
    let mut c = Controller::new(config(), Micros(0))?;
    assert_eq!(c.status(Micros(0))?.flushed, Credit::default());
    assert_prefix_split(c.status(Micros(0))?);
    let first = c.admit(40, Micros(0))?;
    let second = c.admit(60, Micros(0))?;
    let third = c.admit(100, Micros(0))?;
    c.confirm_flushed(first.records, Micros(10))?;
    c.delivered(second, Micros(20))?;
    let early = c.status(Micros(20))?;
    assert_eq!(early.admitted, third);
    assert_eq!(early.flushed, first);
    assert_eq!(early.delivered, second);
    assert_eq!(
        early.outstanding,
        Credit {
            bytes: 100,
            records: 1
        }
    );
    assert_eq!(early.admitted.bytes - early.flushed.bytes, 160);
    assert_eq!(early.delivered.bytes - early.flushed.bytes, 60);
    assert_prefix_split(early);
    c.confirm_flushed(second.records, Micros(30))?;
    let caught_up = c.status(Micros(30))?;
    assert_eq!(caught_up.flushed, second);
    assert_eq!(caught_up.sample, early.sample);
    assert_prefix_split(caught_up);
    c.confirm_flushed(third.records, Micros(40))?;
    let handed_off = c.status(Micros(40))?;
    assert_eq!(handed_off.flushed, third);
    assert_eq!(handed_off.flushed.bytes - handed_off.delivered.bytes, 100);
    assert_prefix_split(handed_off);
    c.delivered(third, Micros(50))?;
    c.confirm_flushed(third.records, Micros(60))?;
    c.delivered(third, Micros(60))?;
    let done = c.status(Micros(60))?;
    assert_eq!(done.flushed, third);
    assert_eq!(done.outstanding, Credit::default());
    assert_eq!(done.retained_records, 0);
    assert_prefix_split(done);
    Ok(())
}

#[test]
fn selective_small_channel_delivery_releases_only_its_own_actual_bytes() -> TestResult {
    let mut c = Controller::new(config(), Micros(0))?;
    let a = c.admit(1500, Micros(0))?;
    let b = c.admit(40, Micros(0))?;
    // B can finish its packed source before A finishes every fragment.
    c.confirm_record_flushed_at(b.records, Micros(10), Micros(20))?;
    c.delivered_record_at(b.records, Micros(70_010), Micros(70_020))?;
    let s = c.status(Micros(70_020))?;
    assert_eq!(
        s.delivered,
        Credit {
            bytes: 40,
            records: 1
        }
    );
    assert_eq!(s.delivered_prefix, Credit::default());
    assert_eq!(s.flushed, Credit::default());
    assert_eq!(
        s.flushed_total,
        Credit {
            bytes: 40,
            records: 1
        }
    );
    assert_eq!(s.outstanding, a);
    assert_eq!(s.retained_records, 2);
    assert_eq!(s.next_flush_deadline, Some(Micros(2_000_000)));
    assert_eq!(s.sample.map(|s| s.raw_micros), Some(70_000));
    assert_eq!(c.credit_at_record(1)?, a);
    assert_eq!(
        c.delivered_record(b.records, Micros(70_021))?,
        Update::Duplicate
    );
    assert_eq!(c.status(Micros(70_021))?.sample, s.sample);
    c.confirm_record_flushed(a.records, Micros(70_030))?;
    c.delivered_record(a.records, Micros(140_030))?;
    let done = c.status(Micros(140_030))?;
    assert_eq!(done.delivered, b);
    assert_eq!(done.delivered_prefix, b);
    assert_eq!(done.flushed, b);
    assert_eq!(done.flushed_total, b);
    assert_eq!(done.retained_records, 0);
    Ok(())
}

#[test]
fn selective_ack_before_flush_retains_bounded_span_and_never_resamples() -> TestResult {
    let mut cfg = config();
    cfg.max_records = 2;
    let mut c = Controller::new(cfg, Micros(0))?;
    c.admit(1500, Micros(0))?;
    c.admit(40, Micros(0))?;
    c.delivered_record_at(2, Micros(100), Micros(200))?;
    assert_eq!(c.status(Micros(200))?.sample, None);
    assert_eq!(c.preview_admit(1, Micros(200)), Err(Error::Blocked));
    c.confirm_record_flushed_at(2, Micros(50), Micros(300))?;
    c.delivered_record_at(2, Micros(100), Micros(400))?;
    let early = c.status(Micros(400))?;
    assert_eq!(early.retained_records, 2);
    assert_eq!(early.sample, None);
    assert_eq!(early.flushed, Credit::default());
    assert_eq!(early.next_flush_deadline, Some(Micros(2_000_000)));
    c.confirm_record_flushed_at(1, Micros(25), Micros(500))?;
    assert_eq!(c.status(Micros(500))?.retained_records, 2);
    c.delivered_record(1, Micros(600))?;
    assert_eq!(
        c.status(Micros(600))?.sample.map(|s| s.raw_micros),
        Some(575)
    );
    assert_eq!(c.status(Micros(600))?.retained_records, 0);
    c.admit(40, Micros(601))?;
    Ok(())
}

#[test]
fn later_selective_completion_cannot_erase_earlier_original_flush_deadline() -> TestResult {
    let mut c = Controller::new(config(), Micros(0))?;
    c.admit(1500, Micros(100))?;
    c.admit(40, Micros(200))?;
    c.delivered_record(2, Micros(300))?;
    c.confirm_record_flushed_at(2, Micros(250), Micros(400))?;
    c.delivered_record(1, Micros(500))?;
    assert_eq!(c.status(Micros(500))?.outstanding, Credit::default());
    assert_eq!(c.status(Micros(500))?.retained_records, 2);
    assert_eq!(
        c.status(Micros(500))?.next_flush_deadline,
        Some(Micros(2_000_100))
    );
    assert_eq!(
        c.confirm_record_flushed_at(1, Micros(150), Micros(2_000_100)),
        Err(Error::FlushExpired)
    );
    assert_eq!(
        c.confirm_flushed_at(2, Micros(250), Micros(2_000_101)),
        Err(Error::FlushExpired)
    );
    assert!(c.status(Micros(2_000_101))?.failed);
    Ok(())
}

#[test]
fn selective_and_cumulative_feedback_overlap_without_double_release_or_new_sample() -> TestResult {
    let mut c = Controller::new(config(), Micros(0))?;
    let a = c.admit(1500, Micros(0))?;
    let b = c.admit(40, Micros(0))?;
    c.admit(60, Micros(0))?;
    c.confirm_record_flushed(2, Micros(10))?;
    c.delivered_record(2, Micros(20))?;
    c.confirm_flushed(3, Micros(30))?;
    c.delivered(a, Micros(40))?;
    let s = c.status(Micros(40))?;
    assert_eq!(s.delivered, b);
    assert_eq!(s.delivered_prefix, b);
    assert_eq!(s.flushed_total, s.admitted);
    assert_eq!(s.sample.map(|s| s.flushed_at), Some(Micros(30)));
    assert_eq!(c.delivered(b, Micros(50))?, Update::Duplicate);
    assert_eq!(c.delivered_record(2, Micros(50))?, Update::Duplicate);
    assert_eq!(c.status(Micros(50))?.sample, s.sample);
    assert_eq!(c.delivered(a, Micros(50)), Err(Error::Stale));
    c.delivered(c.credit_at_record(3)?, Micros(60))?;
    assert_eq!(c.status(Micros(60))?.retained_records, 0);
    Ok(())
}

#[test]
fn selective_invalid_id_time_and_byte_boundary_preserve_state() -> TestResult {
    let mut c = Controller::new(config(), Micros(0))?;
    let a = c.admit(1500, Micros(100))?;
    c.admit(40, Micros(200))?;
    let before = c.status(Micros(200))?;
    for id in [0, 3, u64::MAX] {
        assert_eq!(c.delivered_record(id, Micros(300)), Err(Error::Feedback));
        assert_eq!(c.confirm_record_flushed(id, Micros(300)), Err(Error::Flush));
    }
    for (actual, observed) in [(99, 300), (301, 300)] {
        assert_eq!(
            c.delivered_record_at(1, Micros(actual), Micros(observed)),
            Err(Error::Time)
        );
        assert_eq!(
            c.confirm_record_flushed_at(1, Micros(actual), Micros(observed)),
            Err(Error::Time)
        );
    }
    assert_eq!(c.status(Micros(200))?, before);
    c.delivered_record(2, Micros(300))?;
    let after = c.status(Micros(300))?;
    assert_eq!(
        c.delivered_record_at(1, Micros(250), Micros(400)),
        Err(Error::Time)
    );
    assert_eq!(
        c.delivered_at(Credit { bytes: 40, ..a }, Micros(400), Micros(400)),
        Err(Error::Feedback)
    );
    assert_eq!(c.status(Micros(300))?, after);
    Ok(())
}

#[test]
fn selective_ring_wrap_and_original_times_remain_bounded() -> TestResult {
    let mut cfg = config();
    cfg.max_records = 2;
    let mut c = Controller::new(cfg, Micros(0))?;
    for i in 0..20 {
        let t = i * 100;
        let a = c.admit(1500, Micros(t))?;
        let b = c.admit(40, Micros(t))?;
        c.confirm_record_flushed(b.records, Micros(t + 10))?;
        c.delivered_record(b.records, Micros(t + 20))?;
        assert_eq!(c.preview_admit(1, Micros(t + 20)), Err(Error::Blocked));
        c.confirm_record_flushed(a.records, Micros(t + 30))?;
        c.delivered_record(a.records, Micros(t + 40))?;
        let s = c.status(Micros(t + 40))?;
        assert_eq!(s.retained_records, 0);
        assert_eq!(s.flushed, b);
        assert_eq!(s.flushed_total, b);
        assert_eq!(s.delivered_prefix, b);
        assert_eq!(
            c.confirm_record_flushed(b.records, Micros(t + 50))?,
            Update::Duplicate
        );
        assert_eq!(
            c.delivered_record(a.records, Micros(t + 50))?,
            Update::Duplicate
        );
    }
    Ok(())
}

#[test]
fn selective_more_than64_mixed_size_records_have_exact_independent_totals() -> TestResult {
    let mut cfg = config();
    cfg.max_records = 128;
    let mut c = Controller::new(cfg, Micros(0))?;
    for i in 0..128 {
        c.admit(if i % 2 == 0 { 1500 } else { 40 }, Micros(0))?;
    }
    for record in (2..=128).step_by(2) {
        c.confirm_record_flushed_at(record, Micros(record), Micros(10_000 + record * 10))?;
        c.delivered_record_at(record, Micros(1000 + record), Micros(10_001 + record * 10))?;
    }
    let s = c.status(Micros(20_000))?;
    assert_eq!(
        s.delivered,
        Credit {
            bytes: 64 * 40,
            records: 64
        }
    );
    assert_eq!(s.flushed_total, s.delivered);
    assert_eq!(s.flushed, Credit::default());
    assert_eq!(s.delivered_prefix, Credit::default());
    assert_eq!(
        s.outstanding,
        Credit {
            bytes: 64 * 1500,
            records: 64
        }
    );
    assert_eq!(s.retained_records, 128);
    for record in (1..=127).step_by(2) {
        c.confirm_record_flushed_at(record, Micros(record), Micros(30_000 + record * 10))?;
        c.delivered_record_at(record, Micros(3000 + record), Micros(30_001 + record * 10))?;
    }
    let done = c.status(Micros(40_000))?;
    assert_eq!(done.retained_records, 0);
    assert_eq!(done.delivered_prefix, done.admitted);
    assert_eq!(done.flushed, done.admitted);
    assert_eq!(done.flushed_total, done.admitted);
    Ok(())
}
