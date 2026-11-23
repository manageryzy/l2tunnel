use super::*;

fn originals(policy: &mut Policy, group: u64, now: u64) -> Result<()> {
    for ordinal in 0..policy.n {
        policy.original_paid(group, ordinal, now)?;
    }
    Ok(())
}

#[test]
fn only_distinct_actual_originals_enable_the_oldest_startup_group() -> Result<()> {
    let mut p = Policy::new(3)?;
    originals(&mut p, 128, 0)?;
    p.original_paid(1, 0, 1)?;
    p.original_paid(1, 0, 1)?;
    p.original_paid(1, 2, 2)?;
    assert_eq!(p.candidate(2, |_, _| true)?, None);
    originals(&mut p, 2, 3)?;
    p.original_paid(1, 1, 4)?;
    let first = Member {
        group: 1,
        ordinal: 1,
    };
    assert_eq!(p.candidate(4, |_, _| true)?, Some(first));
    // A normal packet may take the idle opportunity before any immutable head exists.
    assert_eq!(p.candidate(5, |_, _| true)?, Some(first));
    assert_eq!(p.stats.frozen_members, 0);
    assert_eq!(p.stats.eligible_groups, 2);
    p.release(2);
    let mut paid = Vec::new();
    for _ in 0..3 {
        let next = p.candidate(6, |_, _| true)?.ok_or(Error::Payment)?;
        p.freeze(next, 6)?;
        assert_eq!(p.candidate(6, |_, _| true)?, None);
        assert_eq!(
            p.paid(
                Member {
                    group: 2,
                    ordinal: 0
                },
                6
            ),
            Err(Error::Payment)
        );
        p.paid(next, 6)?;
        assert_eq!(p.paid(next, 6), Err(Error::Payment));
        paid.push(next.ordinal);
    }
    assert_eq!(paid, [1, 2, 0]);
    assert_eq!(p.stats.completed_rounds, 1);
    assert_eq!(p.stats.paid_members, 3);
    assert_eq!(p.candidate(7, |_, _| true)?, None);
    Ok(())
}

#[test]
fn expiry_uses_first_paid_time_and_a_frozen_packet_survives_release() -> Result<()> {
    let mut p = Policy::new(2)?;
    p.original_paid(0, 0, 13)?;
    p.original_paid(0, 1, 13 + AGE_LIMIT_US)?;
    assert_eq!(p.candidate(13 + AGE_LIMIT_US, |_, _| true)?, None);
    let start = 14 + AGE_LIMIT_US;
    originals(&mut p, 1, start)?;
    let m = p.candidate(start, |_, _| true)?.ok_or(Error::Payment)?;
    p.freeze(m, start + AGE_LIMIT_US - 1)?;
    p.release(1);
    assert_eq!(p.candidate(start + AGE_LIMIT_US, |_, _| true)?, None);
    assert_eq!(p.stats.paid_members, 0);
    p.paid(m, start + AGE_LIMIT_US + 1)?;
    originals(&mut p, 1, start + AGE_LIMIT_US + 2)?;
    assert_eq!(p.candidate(start + AGE_LIMIT_US + 2, |_, _| true)?, None);
    assert_eq!(p.stats.paid_members, 1);
    assert_eq!(p.stats.late_paid_members, 1);
    assert_eq!(p.stats.completed_rounds, 0);
    assert_eq!(p.stats.expired_groups, 1);
    Ok(())
}

#[test]
fn positive_member_and_group_rank_remove_only_unfrozen_optional_work() -> Result<()> {
    let mut p = Policy::new(3)?;
    originals(&mut p, 0, 0)?;
    originals(&mut p, 1, 0)?;
    originals(&mut p, 2, 0)?;
    // Group zero has known rank. Ordinal one is already positively known on group one.
    let m = p
        .candidate(1, |g, o| g != 0 && !(g == 1 && o == 1))?
        .ok_or(Error::Payment)?;
    assert_eq!(
        m,
        Member {
            group: 1,
            ordinal: 2
        }
    );
    assert_eq!(p.stats.members_skipped, 4);
    p.release(1);
    assert_eq!(p.freeze(m, 1), Err(Error::Payment));
    let next = p.candidate(1, |_, _| true)?.ok_or(Error::Payment)?;
    assert_eq!(next.group, 2);
    assert_eq!(p.freeze(next, AGE_LIMIT_US), Err(Error::Payment));
    assert_eq!(p.candidate(AGE_LIMIT_US, |_, _| true)?, None);
    assert_eq!(p.stats.paid_members, 0);
    Ok(())
}

#[test]
fn full_ordinal_range_and_injected_clock_are_checked() -> Result<()> {
    assert!(matches!(Policy::new(0), Err(Error::Configuration)));
    let mut p = Policy::new(255)?;
    assert_eq!(p.original_paid(127, 255, 0), Err(Error::Ordinal));
    originals(&mut p, 127, u64::MAX - 1)?;
    assert_eq!(p.candidate(0, |_, _| true), Err(Error::Clock));
    let mut seen = [false; 255];
    for _ in 0..255 {
        let m = p.candidate(u64::MAX, |_, _| true)?.ok_or(Error::Payment)?;
        assert!(!std::mem::replace(&mut seen[usize::from(m.ordinal)], true));
        p.freeze(m, u64::MAX)?;
        p.paid(m, u64::MAX)?;
    }
    assert!(seen.into_iter().all(|v| v));
    assert_eq!(p.candidate(u64::MAX, |_, _| true)?, None);
    assert_eq!(p.stats.completed_rounds, 1);
    Ok(())
}

#[test]
fn first_three_idle_payments_cover_three_groups_before_any_second_copy() -> Result<()> {
    let mut p = Policy::new(3)?;
    for group in [2, 1, 0] {
        originals(&mut p, group, 0)?;
    }
    for (turn, group) in [0, 1, 2, 0].into_iter().enumerate() {
        let now = turn as u64;
        let m = p.candidate(now, |_, _| true)?.ok_or(Error::Payment)?;
        assert_eq!(m.group, group);
        p.freeze(m, now)?;
        assert_eq!(p.candidate(now, |_, _| true)?, None);
        p.paid(m, now)?;
    }
    assert_eq!(p.stats.paid_members, 4);
    assert_eq!(p.stats.completed_rounds, 0);
    Ok(())
}

#[test]
fn late_eligible_old_group_gets_service_and_a_retired_frozen_copy_cannot_requeue() -> Result<()> {
    let mut p = Policy::new(2)?;
    p.original_paid(1, 0, 0)?;
    originals(&mut p, 2, 0)?;
    originals(&mut p, 3, 0)?;
    let frozen = p.candidate(0, |_, _| true)?.ok_or(Error::Payment)?;
    assert_eq!(frozen.group, 2);
    p.freeze(frozen, 0)?;
    p.original_paid(1, 1, 1)?;
    p.release(2);
    assert_eq!(p.candidate(1, |_, _| true)?, None);
    p.paid(frozen, 2)?;
    // Group one is now eligible; its older logical hole keeps the tie-break.
    for id in [1, 3, 1, 3] {
        let m = p.candidate(2, |_, _| true)?.ok_or(Error::Payment)?;
        assert_eq!(m.group, id);
        p.freeze(m, 2)?;
        p.paid(m, 2)?;
    }
    assert_eq!(p.candidate(AGE_LIMIT_US, |_, _| true)?, None);
    assert_eq!(p.stats.completed_rounds, 2);
    Ok(())
}
