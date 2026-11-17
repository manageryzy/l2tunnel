use super::*;
use std::time::Duration;

type Result = std::result::Result<(), Box<dyn std::error::Error>>;
fn at(origin: Instant, micros: u64) -> Instant {
    origin + Duration::from_micros(micros)
}
fn identity(origin: Instant, token: u64, lane: u8) -> Identity<u64> {
    Identity {
        token,
        lane,
        bytes: 21,
        cost: 61,
        deadline: at(origin, 100),
    }
}
fn receipt(origin: Instant, accepted: u64) -> AcceptedReceipt {
    AcceptedReceipt {
        record_bytes: 21,
        udp_bytes: None,
        charged_bytes: 61,
        socket_ip_bytes: Some(61),
        boundary: crate::secure_udp::SendBoundary::SocketAccepted,
        accepted_at: at(origin, accepted),
        deadline: at(origin, 100),
    }
}
#[test]
fn raw_custody_exact_token_stages_ignore_duplicate_observation_and_preserve_deadline() {
    let origin = Instant::now();
    let mut value = Tracker::new(origin);
    value.commit(Class::User, identity(origin, 7, 1), at(origin, 10));
    let fact = receipt(origin, 20);
    value.observe(Class::User, 1, 7, fact, at(origin, 25));
    value.observe(Class::User, 1, 7, fact, at(origin, 27));
    value.take(Class::User, 1, fact, at(origin, 31));
    value.finish(at(origin, 40));
    let row = value.rows[2];
    assert_eq!(
        (row.committed, row.physical_observed, row.upper_taken),
        (1, 1, 1)
    );
    assert_eq!(
        (
            row.commit_to_physical.samples,
            row.commit_to_physical.sum_us
        ),
        (1, 10)
    );
    assert_eq!(
        (
            row.physical_to_observe.samples,
            row.physical_to_observe.sum_us
        ),
        (1, 5)
    );
    assert_eq!(
        (row.observe_to_take.samples, row.observe_to_take.sum_us),
        (1, 6)
    );
    assert_eq!(value.duplicate_observations, 1);
    assert_eq!(value.identity_mismatches, 0);
    assert_eq!(fact.deadline, at(origin, 100));
    assert!(!value.invalid_clock);
}
#[test]
fn raw_custody_wrong_token_lane_and_upper_receipt_do_not_retire_the_valid_flight() {
    let origin = Instant::now();
    let mut value = Tracker::new(origin);
    value.commit(Class::Control, identity(origin, 9, 0), at(origin, 5));
    let fact = receipt(origin, 12);
    value.observe(Class::Control, 0, 8, fact, at(origin, 15));
    value.observe(Class::Control, 1, 9, fact, at(origin, 16));
    value.observe(Class::Control, 0, 9, fact, at(origin, 17));
    let altered = AcceptedReceipt {
        deadline: at(origin, 101),
        ..fact
    };
    value.take(Class::Control, 0, altered, at(origin, 19));
    value.take(Class::Control, 0, fact, at(origin, 23));
    value.finish(at(origin, 25));
    assert_eq!(value.identity_mismatches, 3);
    assert_eq!(value.rows[1].physical_observed, 1);
    assert_eq!(value.rows[1].upper_taken, 1);
    assert_eq!(value.rows[1].observe_to_take.sum_us, 6);
    assert!(value.flight[1].is_none());
}
#[test]
fn raw_custody_terminal_censors_only_unresolved_stages_and_keeps_late_physical_fact() -> Result {
    let origin = Instant::now();
    let mut value = Tracker::new(origin);
    value.commit(Class::User, identity(origin, 1, 0), at(origin, 5));
    value.commit(Class::Control, identity(origin, 1, 1), at(origin, 8));
    let late = receipt(origin, 100);
    value.observe(Class::Control, 1, 1, late, at(origin, 105));
    value.finish(at(origin, 120));
    value.finish(at(origin, 200));
    assert_eq!(
        value.rows[0].censored_before_physical_observation.samples,
        1
    );
    assert_eq!(
        value.rows[0].censored_before_physical_observation.sum_us,
        115
    );
    assert_eq!(value.rows[0].physical_observed, 0);
    assert_eq!(value.rows[3].censored_after_physical_observation.sum_us, 15);
    assert_eq!(value.rows[3].commit_to_physical.sum_us, 92);
    assert_eq!(value.rows[3].physical_to_observe.sum_us, 5);
    assert_eq!(value.rows[3].late_physical, 1);
    assert_eq!(value.rows[3].upper_taken, 0);
    let mut bytes = Vec::new();
    value.write(&mut bytes, 4096)?;
    let json: serde_json::Value = serde_json::from_slice(&bytes)?;
    assert!(json["blocked_union"].is_null());
    assert_eq!(
        json["raw_custody"]["rows"][0]["censored_before_physical_observation"]["sum_us"],
        115
    );
    assert_eq!(json["raw_custody"]["rows"][3]["late_physical"], 1);
    Ok(())
}
#[test]
fn raw_custody_invalid_clock_and_overflow_are_visible_without_success_samples() {
    let origin = Instant::now();
    let mut value = Tracker::new(origin);
    value.commit(Class::User, identity(origin, 1, 0), at(origin, 10));
    value.observe(Class::User, 0, 1, receipt(origin, 9), at(origin, 15));
    assert!(value.invalid_clock);
    assert_eq!(value.rows[0].physical_observed, 0);
    value.finish(at(origin, 20));
    assert_eq!(
        value.rows[0].censored_before_physical_observation.sum_us,
        10
    );
    let mut total = Total {
        samples: 1,
        sum_us: u64::MAX,
        max_us: 0,
    };
    let mut overflow = false;
    assert!(total.sample(origin, at(origin, 1), &mut overflow));
    assert!(overflow);
    assert_eq!(total.sum_us, u64::MAX);
}
