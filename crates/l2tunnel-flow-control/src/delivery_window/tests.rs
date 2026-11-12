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
