use super::*;

#[test]
fn rank_callback_requires_positive_flight_or_late_alias() -> Result<(), Box<dyn std::error::Error>>
{
    let mut lane = PathRecovery::new(0, 8, 100, 3)?;
    lane.sent(0, &[(0, 1)], 0)?;
    lane.sent(1, &[(0, 2)], 1)?;
    lane.sent(2, &[(1, 0)], 2)?;
    assert_eq!(lane.take_due(100), Some((0, vec![(0, 1)])));
    let mut evidence = Vec::new();
    let selective = AckBlock::new(0, 0, 0, std::iter::once(2..3).collect())?;
    lane.acknowledge_with_members(&selective, 101, |m| evidence.push(m))?;
    lane.acknowledge_with_members(&selective, 102, |m| evidence.push(m))?;
    let alias = AckBlock::new(0, 0, 1, vec![])?;
    lane.acknowledge_with_members(&alias, 103, |m| evidence.push(m))?;
    let expired = AckBlock::new(0, 2, 2, vec![])?;
    lane.acknowledge_with_members(&expired, 104, |m| evidence.push(m))?;
    let native = AckBlock::new(LOGICAL_GROUP, 0, 2, vec![])?;
    lane.acknowledge_with_members(&native, 105, |m| evidence.push(m))?;
    assert_eq!(evidence, [(1, 0), (0, 1)]);
    Ok(())
}

type Test = Result<(), Box<dyn std::error::Error>>;

#[test]
fn repeated_native_ack_advances_only_the_path_clock() -> Test {
    let mut lane = PathRecovery::new(0, 2, 90, 3)?.with_rtt_tracking(90, 500, 1)?;
    lane.sent(0, &[(4, 0)], 10)?;
    lane.observe_logical_time(20)?;
    assert_eq!(lane.observe_logical_time(19), Err(Error::Clock));
    assert_eq!(lane.sent(1, &[(5, 0)], 19), Err(Error::Clock));
    assert_eq!(lane.timing().samples, 0);
    assert_eq!(lane.next_deadline(), Some(100));
    assert_eq!(lane.take_due(100), Some((0, vec![(4, 0)])));
    Ok(())
}

#[test]
fn samples_at_the_same_rto_still_shape_the_next_timeout() -> Test {
    let mut lane = PathRecovery::new(0, 8, 90, 3)?.with_rtt_tracking(90, 500, 1)?;
    lane.sent(0, &[(0, 0)], 0)?;
    lane.sent(1, &[(1, 0)], 1)?;
    let first = AckBlock::new(0, 0, 1, vec![])?;
    lane.acknowledge(&first, 10)?;
    lane.acknowledge(&first, 11)?;
    assert_eq!(lane.timing().samples, 1);
    lane.sent(2, &[(2, 0)], 12)?;
    let selective = AckBlock::new(0, 0, 0, std::iter::once(2..3).collect())?;
    lane.acknowledge(&selective, 32)?;
    assert_eq!(
        lane.timing(),
        Timing {
            adaptive: true,
            samples: 2,
            srtt_us: Some(11),
            rttvar_us: Some(6),
            rto_us: 90
        }
    );
    assert_eq!(lane.next_deadline(), Some(91));
    assert_eq!(lane.take_due(91), Some((1, vec![(1, 0)])));
    lane.sent(3, &[(1, 0), (3, 0)], 92)?;
    let late = AckBlock::new(0, 0, 2, vec![])?;
    lane.acknowledge(&late, 210)?;
    lane.acknowledge(&late, 211)?;
    assert_eq!(lane.timing().samples, 3);
    assert_eq!(lane.timing().rto_us, 252);
    assert_eq!(lane.next_deadline(), Some(344));
    assert_eq!(lane.take_due(344), Some((3, vec![(3, 0)])));
    Ok(())
}

#[test]
fn late_original_ack_updates_timing_without_acknowledging_replacement() -> Test {
    let mut lane = PathRecovery::new(0, 8, 90_000, 3)?.with_rtt_tracking(90_000, 500_000, 1_000)?;
    lane.sent(0, &[(0, 0)], 0)?;
    assert_eq!(lane.take_due(90_000), Some((0, vec![(0, 0)])));
    lane.sent(1, &[(0, 0), (1, 0)], 90_010)?;
    let ack = AckBlock::new(0, 0, 1, vec![])?;
    lane.acknowledge(&ack, 120_000)?;
    assert_eq!(
        lane.timing(),
        Timing {
            adaptive: true,
            samples: 1,
            srtt_us: Some(120_000),
            rttvar_us: Some(60_000),
            rto_us: 360_000
        }
    );
    assert_eq!(lane.outstanding(), 1);
    assert_eq!(lane.next_deadline(), Some(450_010));
    lane.acknowledge(&ack, 121_000)?;
    assert_eq!(lane.timing().samples, 1);
    assert!(!lane.needs_retry((0, 0)));
    assert_eq!(lane.take_due(450_010), Some((1, vec![(1, 0)])));
    Ok(())
}

#[test]
fn logical_release_and_floor_are_not_rtt_samples_but_later_physical_receipt_is() -> Test {
    let mut lane = PathRecovery::new(0, 2, 90_000, 3)?.with_rtt_tracking(90_000, 500_000, 1_000)?;
    lane.sent(0, &[(0, 0)], 0)?;
    lane.acknowledge(&AckBlock::new(LOGICAL_GROUP, 0, 1, vec![])?, 70_000)?;
    assert_eq!((lane.outstanding(), lane.timing().samples), (0, 0));
    lane.acknowledge(&AckBlock::new(0, 1, 1, vec![])?, 71_000)?;
    assert_eq!(lane.timing().samples, 0);
    lane.acknowledge(&AckBlock::new(0, 0, 1, vec![])?, 72_000)?;
    assert_eq!(lane.timing().srtt_us, Some(72_000));
    assert_eq!(lane.timing().rto_us, 216_000);
    // More physical payments may retire measurement history without forgiving debt.
    lane.sent(1, &[], 72_001)?;
    lane.sent(2, &[], 72_002)?;
    assert_eq!(
        lane.timing.as_ref().map(Tracker::timing).map(|t| t.samples),
        Some(1)
    );
    Ok(())
}

#[test]
fn rtt_samples_use_highest_new_ack_and_do_not_postpone_selective_gap() -> Test {
    let mut lane = PathRecovery::new(0, 8, 90_000, 3)?.with_rtt_tracking(90_000, 500_000, 1_000)?;
    for seq in 0..4 {
        lane.sent(seq, &[(seq, 0)], seq * 1_000)?;
    }
    lane.acknowledge(
        &AckBlock::new(0, 0, 0, std::iter::once(1..4).collect())?,
        73_000,
    )?;
    assert_eq!(lane.timing().srtt_us, Some(70_000));
    assert_eq!(lane.next_deadline(), Some(73_000));
    lane.sent(4, &[(4, 0)], 73_001)?;
    lane.acknowledge(
        &AckBlock::new(0, 0, 0, std::iter::once(4..5).collect())?,
        473_001,
    )?;
    assert_eq!(lane.next_deadline(), Some(73_000));
    assert_eq!(
        lane.take_due_with_reason(473_001),
        Some((0, vec![(0, 0)], Reason::SelectiveGap))
    );
    assert!(lane.timing().rto_us <= 500_000);
    Ok(())
}

#[test]
fn adaptive_deadline_overflow_rejects_without_consuming_the_sample() -> Test {
    let mut lane = PathRecovery::new(0, 2, 90, 3)?.with_rtt_tracking(90, 500, 1)?;
    lane.sent(0, &[(0, 0)], u64::MAX - 100)?;
    let ack = AckBlock::new(0, 0, 1, vec![])?;
    assert_eq!(lane.acknowledge(&ack, u64::MAX - 50), Err(Error::Clock));
    assert_eq!(lane.timing().samples, 0);
    assert_eq!(lane.outstanding(), 1);
    assert_eq!(lane.next_deadline(), Some(u64::MAX - 10));
    Ok(())
}

#[test]
fn repeated_sparse_ack_counts_each_higher_packet_once_and_rebatch_gets_a_fresh_timer() -> Test {
    let mut lane = PathRecovery::new(1, 4, 90_000, 3)?;
    for seq in 0..4 {
        lane.sent(seq, &[(seq, 1)], seq * 100)?;
    }
    assert!(!lane.can_send());
    let two = AckBlock::new(1, 0, 0, std::iter::once(1..3).collect())?;
    lane.acknowledge(&two, 70_000)?;
    lane.acknowledge(&two, 70_250)?;
    assert!(lane.take_due(70_250).is_none());
    let third = AckBlock::new(1, 0, 0, std::iter::once(3..4).collect())?;
    lane.acknowledge(&third, 71_000)?;
    assert_eq!(
        lane.take_due_with_reason(71_000),
        Some((0, vec![(0, 1)], Reason::SelectiveGap))
    );
    lane.sent(4, &[(0, 1)], 72_000)?;
    lane.acknowledge(&two, 72_100)?;
    assert_eq!(lane.next_deadline(), Some(162_000));
    assert!(lane.take_due(161_999).is_none());
    assert_eq!(
        lane.take_due_with_reason(162_000),
        Some((4, vec![(0, 1)], Reason::Timeout))
    );
    Ok(())
}

#[test]
fn physical_floor_cannot_forgive_missing_data_and_native_ack_cancels_only_one_group() -> Test {
    let mut first = PathRecovery::new(0, 2, 90_000, 3)?;
    let mut second = PathRecovery::new(1, 2, 90_000, 3)?;
    first.sent(0, &[(7, 0), (8, 0)], 0)?;
    second.sent(0, &[(7, 1)], 0)?;
    assert!(
        first
            .acknowledge(&AckBlock::new(0, 0, 2, vec![])?, 1)
            .is_err()
    );
    assert!(
        first
            .acknowledge(&AckBlock::new(1, 0, 1, vec![])?, 1)
            .is_err()
    );
    assert_eq!(first.outstanding(), 1);
    let committed = AckBlock::new(LOGICAL_GROUP, 0, 0, std::iter::once(7..8).collect())?;
    first.acknowledge(&committed, 2)?;
    second.acknowledge(&committed, 2)?;
    assert_eq!(second.next_deadline(), None);
    first.acknowledge(&AckBlock::new(0, 1, 1, vec![])?, 3)?;
    assert_eq!(
        first.take_due_with_reason(3),
        Some((0, vec![(8, 0)], Reason::ExpiredHistory))
    );
    Ok(())
}

#[test]
fn a_lost_final_packet_is_retried_from_actual_payment_even_with_no_feedback() -> Test {
    let mut lane = PathRecovery::new(5, 1, 90_000, 3)?;
    assert_eq!(lane.next_deadline(), None);
    assert_eq!(lane.sent(1, &[(0, 5)], 3), Err(Error::Sequence));
    lane.sent(0, &[(0, 5)], 50_000)?;
    assert_eq!(lane.sent(1, &[(1, 5)], 51_000), Err(Error::Full));
    assert_eq!(lane.next_deadline(), Some(140_000));
    assert!(lane.take_due(139_999).is_none());
    assert_eq!(lane.take_due(140_000), Some((0, vec![(0, 5)])));
    lane.sent(1, &[(0, 5)], 140_010)?;
    lane.acknowledge(&AckBlock::new(5, 0, 2, vec![])?, 211_000)?;
    assert_eq!(lane.outstanding(), 0);
    assert_eq!(lane.next_deadline(), None);
    Ok(())
}

#[test]
fn a_late_physical_receipt_cancels_the_member_without_confirming_the_replacement_pn() -> Test {
    let mut lane = PathRecovery::new(0, 4, 1000, 3)?;
    lane.sent(0, &[(9, 0)], 0)?;
    assert_eq!(lane.take_due(1000), Some((0, vec![(9, 0)])));
    assert!(lane.needs_retry((9, 0)));
    lane.sent(1, &[(9, 0), (10, 0)], 1002)?;
    lane.acknowledge(&AckBlock::new(0, 0, 1, vec![])?, 1003)?;
    assert!(!lane.needs_retry((9, 0)));
    assert_eq!(lane.outstanding(), 1);
    assert_eq!(lane.take_due(2002), Some((1, vec![(10, 0)])));
    Ok(())
}
