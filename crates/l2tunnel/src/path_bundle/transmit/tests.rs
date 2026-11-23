use super::*;
use l2tunnel_pipeline::path_ack::AckBlock;
use std::ops::Range;

type Test<T = ()> = Result<T, Box<dyn std::error::Error>>;
fn ms(t: u64) -> Duration {
    Duration::from_millis(t)
}
fn config(entries: u8) -> PathConfig {
    PathConfig {
        mtu: 1200,
        outer_bytes: 49,
        max_hold: ms(10),
        max_entries: entries,
    }
}
fn block(path: u8, next: u64, ranges: Vec<Range<u64>>) -> Test<AckBatch> {
    Ok(AckBatch::new(vec![AckBlock::new(path, 0, next, ranges)?])?)
}
fn pay(t: &mut Transmitter, path: PathId, now: Duration) -> Test<BatchId> {
    let ready = t.prepare(path, now, None)?.ok_or("no prepared batch")?;
    let id = ready.id;
    t.confirm(id)?;
    Ok(id)
}

#[test]
fn ordinary_member_deadline_survives_prepare_until_payment_and_excludes_promotions() -> Test {
    let (a, b) = (PathId::new(0)?, PathId::new(1)?);
    let mut tx = Transmitter::new(&[config(4); 2], 2, 600, 4)?;
    let first = tx.admit(ms(1), b"first")?;
    let second = tx.admit(ms(2), b"second")?;
    assert_eq!(tx.unpaid_natural_deadline(a, first)?, Some(ms(11)));
    tx.fill_path_once(a, ms(2), 4)?;
    let frozen = tx
        .prepare(a, ms(11), None)?
        .ok_or("first payment is due")?
        .id;
    assert_eq!(tx.unpaid_natural_deadline(a, first)?, Some(ms(11)));
    assert_eq!(tx.unpaid_natural_deadline(a, second)?, Some(ms(12)));
    tx.confirm(frozen)?;
    assert_eq!(tx.unpaid_natural_deadline(a, first)?, None);
    assert!(matches!(
        tx.stage_recovery_once(a, ms(12), first, 1)?,
        RecoveryStage::First(_)
    ));
    assert_eq!(tx.unpaid_natural_deadline(b, first)?, None);
    assert_eq!(tx.unpaid_natural_deadline(b, second)?, Some(ms(12)));
    assert_eq!(tx.oldest_unconfirmed(), Some(first));
    Ok(())
}

#[test]
fn checkpoint_head_uses_admission_and_batch_deadlines_without_mistaking_custody_for_work() -> Test {
    let p = PathId::new(0)?;
    let mut tx = Transmitter::new(&[config(4); 2], 2, 600, 4)?;
    assert!(!tx.has_due_head(p, ms(100))?);
    tx.admit(ms(1), b"first")?;
    assert!(!tx.has_due_head(p, ms(10))?);
    assert!(tx.has_due_head(p, ms(11))?);
    tx.fill_path_once(p, ms(11), 1)?;
    assert!(tx.has_due_head(p, ms(11))?);
    let id = tx.prepare(p, ms(11), None)?.ok_or("due head")?.id;
    assert!(!tx.has_due_head(p, ms(12))?);
    tx.confirm(id)?;
    assert_eq!(tx.oldest_unconfirmed(), Some(0));
    assert!(!tx.has_due_head(p, ms(2_000))?);
    Ok(())
}

#[test]
fn distinct_positive_ordinals_cannot_retire_a_source_or_hide_an_older_hole() -> Test {
    let mut tx = Transmitter::new(&[config(8); 3], 2, 600, 2)?;
    tx.admit(ms(0), b"earlier hole")?;
    tx.admit(ms(0), b"later")?;
    for p in 0..2 {
        let path = PathId::new(p)?;
        tx.fill_path(path, ms(0), 2)?;
        pay(&mut tx, path, ms(10))?;
    }
    for _ in 0..2 {
        tx.observe_paid_member_receipt(1, 0);
    }
    tx.observe_paid_member_receipt(1, 2);
    tx.observe_paid_member_receipt(u64::MAX, 1);
    assert!(tx.peer_has_member(1, 0));
    assert!(!tx.peer_has_rank(1));
    tx.observe_paid_member_receipt(1, 1);
    assert!(tx.peer_has_rank(1));
    assert!(!tx.peer_has_rank(0));
    assert_eq!(tx.admit(ms(11), b"new"), Err(Error::WindowFull));
    let p2 = PathId::new(2)?;
    tx.fill_path(p2, ms(11), 2)?;
    let p = tx.prepare(p2, ms(21), None)?.ok_or("remaining initial")?;
    assert_eq!(config(8).decode(p2, p.bytes)?.count, 2);
    let id = p.id;
    tx.confirm(id)?;
    assert_eq!(
        tx.apply_ack(&block(LOGICAL_GROUP, 0, std::iter::once(1..2).collect())?)?,
        1
    );
    tx.observe_paid_member_receipt(1, 0);
    assert!(!tx.peer_has_rank(1));
    assert_eq!(tx.oldest_unconfirmed(), Some(0));
    assert_eq!(tx.admit(ms(21), b"new"), Err(Error::WindowFull));
    assert_eq!(tx.apply_ack(&block(LOGICAL_GROUP, 2, vec![])?)?, 1);
    assert_eq!(tx.admit(ms(21), b"new")?, 2);
    Ok(())
}

#[test]
fn promoted_first_flight_keeps_deadline_and_excludes_duplicate_natural_send() -> Test {
    let (p0, p1, p2) = (PathId::new(0)?, PathId::new(1)?, PathId::new(2)?);
    let mut tx = Transmitter::new(&[config(4); 3], 2, 600, 4)?;
    tx.admit(ms(1), b"native")?;
    assert_eq!(tx.member_state(0, 0)?, MemberState::Unstaged);
    assert!(matches!(
        tx.stage_recovery_once(p1, ms(20), 0, 0)?,
        RecoveryStage::First(_)
    ));
    assert_eq!(
        tx.member_state(0, 0)?,
        MemberState::Staged {
            paths: [2, 0, 0, 0]
        }
    );
    assert_eq!(tx.fill_path_once(p0, ms(20), 4)?, 0);
    assert_eq!(tx.next_wake(p0)?, None);
    let held = tx.prepare(p1, ms(20), None)?.ok_or("due first flight")?;
    assert_eq!(held.deadline, ms(11));
    let (id, bytes) = (held.id, held.bytes.to_vec());
    assert_eq!(
        tx.stage_recovery_once(p2, ms(20), 0, 0)?,
        RecoveryStage::AlreadyStaged {
            paths: [2, 0, 0, 0]
        }
    );
    assert_eq!(
        tx.apply_ack(&block(LOGICAL_GROUP, 1, vec![])?),
        Err(Error::Unpaid)
    );
    assert_eq!(tx.prepare(p1, ms(21), None)?.ok_or("frozen")?.bytes, bytes);
    tx.confirm(id)?;
    assert_eq!(tx.member_state(0, 0)?, MemberState::Paid);
    assert!(matches!(
        tx.stage_recovery_once(p0, ms(21), 0, 0)?,
        RecoveryStage::Retry(_)
    ));
    assert_eq!(
        tx.member_state(0, 0)?,
        MemberState::Staged {
            paths: [1, 0, 0, 0]
        }
    );
    tx.fill_path_once(p2, ms(21), 4)?;
    pay(&mut tx, p2, ms(21))?;
    assert_eq!(tx.apply_ack(&block(LOGICAL_GROUP, 1, vec![])?)?, 1);
    assert_eq!(
        tx.stage_recovery_once(p0, ms(21), 0, 0)?,
        RecoveryStage::Released
    );
    pay(&mut tx, p0, ms(31))?;
    assert_eq!(tx.member_state(0, 0)?, MemberState::Released);
    Ok(())
}

#[test]
fn explicit_replicas_remain_pending_until_each_actual_path_payment() -> Test {
    let (p0, p1) = (PathId::new(0)?, PathId::new(1)?);
    let mut tx = Transmitter::new(&[config(1); 3], 2, 600, 4)?;
    tx.admit(ms(0), b"native")?;
    tx.fill_path_once(p0, ms(0), 1)?;
    tx.request_batched_position(p0, ms(0), 0, 0)?;
    tx.request_batched_position(p1, ms(0), 0, 0)?;
    assert_eq!(
        tx.member_state(0, 0)?,
        MemberState::Staged {
            paths: [3, 0, 0, 0]
        }
    );
    pay(&mut tx, p0, ms(0))?;
    assert_eq!(
        tx.member_state(0, 0)?,
        MemberState::Staged {
            paths: [3, 0, 0, 0]
        }
    );
    pay(&mut tx, p0, ms(0))?;
    assert_eq!(
        tx.member_state(0, 0)?,
        MemberState::Staged {
            paths: [2, 0, 0, 0]
        }
    );
    pay(&mut tx, p1, ms(0))?;
    assert_eq!(tx.member_state(0, 0)?, MemberState::Paid);
    assert_eq!(
        tx.apply_ack(&block(LOGICAL_GROUP, 1, vec![])?),
        Err(Error::Unpaid)
    );
    Ok(())
}

#[test]
fn rejected_promotion_leaves_natural_first_flight_available_after_bounded_scan() -> Test {
    let (p0, p1) = (PathId::new(0)?, PathId::new(1)?);
    let mut tx = Transmitter::new(&[config(1); 3], 2, 600, 4)?;
    for _ in 0..3 {
        tx.admit(ms(0), b"native")?;
    }
    tx.stage_recovery_once(p1, ms(0), 0, 0)?;
    tx.stage_recovery_once(p1, ms(0), 1, 0)?;
    assert_eq!(
        tx.stage_recovery_once(p1, ms(0), 2, 0),
        Err(Error::Path(path_batch::Error::Backpressure))
    );
    assert_eq!(tx.member_state(2, 0)?, MemberState::Unstaged);
    assert_eq!(tx.fill_path_once(p0, ms(0), 1)?, 0);
    assert_eq!(tx.fill_path_once(p0, ms(0), 2)?, 1);
    let packet = tx.prepare(p0, ms(0), None)?.ok_or("unlost first flight")?;
    let entries: Vec<_> = config(1)
        .decode(p0, packet.bytes)?
        .entries()
        .map(|s| (s.generation, s.ordinal))
        .collect();
    assert_eq!(entries, [(2, 0)]);
    Ok(())
}

#[test]
fn blocked_path_does_not_delay_other_lanes_or_reopen_logical_credit() -> Test {
    let p0 = PathId::new(0)?;
    let p1 = PathId::new(1)?;
    let p2 = PathId::new(2)?;
    let mut t = Transmitter::new(&[config(1); 3], 2, 600, 2)?;
    assert_eq!(t.admit(ms(3), b"old")?, 0);
    assert_eq!(t.admit(ms(4), b"new")?, 1);
    assert_eq!(t.fill_path(p0, ms(5), 1)?, 1);
    let held = t.prepare(p0, ms(5), None)?.ok_or("blocked path")?;
    let (id, wire) = (held.id, held.bytes.to_vec());
    for path in [p1, p2] {
        assert_eq!(t.fill_path(path, ms(5), 2)?, 2);
        pay(&mut t, path, ms(5))?;
        pay(&mut t, path, ms(5))?;
    }
    assert_eq!(t.apply_ack(&block(1, 2, vec![])?)?, 0);
    let selective = block(LOGICAL_GROUP, 0, std::iter::once(1..2).collect())?;
    assert_eq!(t.apply_ack(&selective)?, 1);
    assert_eq!(t.apply_ack(&selective)?, 0);
    assert_eq!(
        t.admit(ms(6), b"blocked by old hole"),
        Err(Error::WindowFull)
    );
    assert_eq!(t.oldest_unconfirmed(), Some(0));
    assert!(!t.request(p2, ms(6), 1, 0)?);
    assert_eq!(t.apply_ack(&block(LOGICAL_GROUP, 2, vec![])?)?, 1);
    assert_eq!(t.admit(ms(6), b"resumed")?, 2);
    let still = t
        .prepare(p0, ms(8), None)?
        .ok_or("retained ciphertext input")?;
    assert_eq!((still.id, still.bytes), (id, wire.as_slice()));
    t.confirm(id)?;
    assert_eq!(
        t.confirm(id),
        Err(Error::Path(path_batch::Error::StaleReceipt))
    );
    assert_eq!(t.oldest_unconfirmed(), Some(2));
    Ok(())
}

#[test]
fn peer_delivery_requires_distinct_paid_ordinals_and_validates_whole_ack_before_release() -> Test {
    let p0 = PathId::new(0)?;
    let p1 = PathId::new(1)?;
    let p2 = PathId::new(2)?;
    let mut t = Transmitter::new(&[config(1); 3], 2, 600, 8)?;
    t.admit(ms(0), b"source zero")?;
    t.admit(ms(0), b"source one")?;
    t.fill_path(p0, ms(0), 1)?;
    pay(&mut t, p0, ms(0))?;
    assert!(t.request(p1, ms(1), 0, 0)?);
    let repeat = t
        .prepare(p1, ms(1), None)?
        .ok_or("migrated original ordinal")?;
    let decoded = config(1).decode(p1, repeat.bytes)?;
    let one = decoded.entries().next().ok_or("shard")?;
    assert_eq!((one.generation, one.ordinal), (0, 0));
    let repeated_id = repeat.id;
    t.confirm(repeated_id)?;
    assert_eq!(
        t.apply_ack(&block(LOGICAL_GROUP, 1, vec![])?),
        Err(Error::Unpaid)
    );
    t.fill_path(p2, ms(1), 1)?;
    let id = t.prepare(p2, ms(1), None)?.ok_or("staged but unpaid")?.id;
    assert_eq!(
        t.apply_ack(&block(LOGICAL_GROUP, 1, vec![])?),
        Err(Error::Unpaid)
    );
    t.confirm(id)?;
    assert_eq!(
        t.apply_ack(&block(LOGICAL_GROUP, 2, vec![])?),
        Err(Error::Unpaid)
    );
    assert_eq!(
        t.apply_ack(&block(LOGICAL_GROUP, 1, std::iter::once(2..3).collect())?),
        Err(Error::Unknown)
    );
    assert_eq!(t.oldest_unconfirmed(), Some(0));
    assert_eq!(t.apply_ack(&block(LOGICAL_GROUP, 1, vec![])?)?, 1);
    assert_eq!(t.oldest_unconfirmed(), Some(1));
    Ok(())
}

#[test]
fn backlog_uses_original_deadline_and_oldest_probe_can_rotate_on_the_surviving_path() -> Test {
    let p0 = PathId::new(0)?;
    let p1 = PathId::new(1)?;
    let mut t = Transmitter::new(&[config(4); 3], 2, 600, 4)?;
    t.admit(ms(3), b"first native")?;
    t.admit(ms(7), b"second native")?;
    assert_eq!(t.next_wake(p0)?, Some(ms(13)));
    assert_eq!(t.fill_path(p0, ms(10), 2)?, 2);
    assert!(t.prepare(p0, ms(12), None)?.is_none());
    assert_eq!(t.next_wake(p0)?, Some(ms(13)));
    let batch = t.prepare(p0, ms(13), None)?.ok_or("oldest deadline")?;
    assert_eq!(batch.deadline, ms(13));
    assert_eq!(config(4).decode(p0, batch.bytes)?.count, 2);
    let id = batch.id;
    t.confirm(id)?;
    assert_eq!(t.retry_oldest(p1, ms(15))?, Some((0, 0)));
    pay(&mut t, p1, ms(15))?;
    assert_eq!(t.retry_oldest(p1, ms(16))?, Some((0, 1)));
    pay(&mut t, p1, ms(16))?;
    assert_eq!(t.apply_ack(&block(LOGICAL_GROUP, 1, vec![])?)?, 1);
    assert!(matches!(t.request(p1, ms(16), 2, 1), Err(Error::Unknown)));
    assert!(matches!(t.request(p1, ms(16), 1, 3), Err(Error::Unknown)));
    assert!(t.admit(ms(2), b"time reversal").is_err());
    assert_eq!(t.next_generation(), 2);
    Ok(())
}

#[test]
fn named_repairs_on_one_path_share_a_single_paid_datagram_and_oldest_deadline() -> Test {
    let lane = PathId::new(0)?;
    let config = config(4);
    let mut tx = Transmitter::new(&[config; 3], 2, 600, 4)?;
    tx.admit(ms(0), b"old")?;
    tx.admit(ms(1), b"later")?;
    tx.request_batched(lane, ms(2), 0, 1)?;
    tx.request_batched(lane, ms(6), 1, 2)?;
    assert!(tx.prepare(lane, ms(11), None)?.is_none());
    let batch = tx.prepare(lane, ms(12), None)?.ok_or("repair deadline")?;
    let ids: Vec<_> = config
        .decode(lane, batch.bytes)?
        .entries()
        .map(|s| (s.generation, s.ordinal))
        .collect();
    assert_eq!(ids, [(0, 1), (1, 2)]);
    let id = batch.id;
    tx.confirm(id)?;
    assert_eq!(tx.oldest_unconfirmed(), Some(0));
    Ok(())
}
