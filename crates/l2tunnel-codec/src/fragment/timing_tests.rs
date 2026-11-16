//! Actual legacy/reserved fragment custody, without new wire or session authority.
use super::*;

fn owner(reserved_backing: bool, window: usize) -> Result<Reassembler> {
    let config = ReassemblyConfig {
        max_lifetime_ticks: 10,
        replay_window: window,
        ..config()
    };
    if reserved_backing {
        reserved(config)
    } else {
        Ok(Reassembler::new(context(), config)?)
    }
}
fn batch(id: u64, body: &[u8]) -> Result<FragmentBatch> {
    Ok(Fragmenter::new(context(), send_config(), MessageId(id))?.fragment(body)?)
}
fn retained(owner: &Reassembler, id: u64) -> Result<(u64, u64, u16)> {
    let pending = owner
        .pending
        .get(&MessageId(id))
        .ok_or("actual pending message")?;
    Ok((pending.first_received, pending.deadline, pending.received))
}
fn pointers(owner: &Reassembler) -> Result<Option<Vec<(usize, usize)>>> {
    if owner.storage_usage().is_some() {
        inventory(owner).map(Some)
    } else {
        Ok(None)
    }
}
fn complete(
    status: TimedReassemblyStatus,
    id: u64,
    length: usize,
    received: u64,
    cap: u64,
) -> Result {
    let TimedReassemblyStatus::Complete {
        message,
        length: actual,
        timing,
    } = status
    else {
        return Err("actual timed completion missing".into());
    };
    assert_eq!((message, actual), (MessageId(id), length));
    assert_eq!(timing.first_received_ticks(), received);
    assert_eq!(timing.deadline_ticks(), cap);
    Ok(())
}

#[test]
fn timed_unique_fragments_tighten_original_age_after_refusals_and_reuse_actual_backing() -> Result {
    for reserved_backing in [false, true] {
        let mut owner = owner(reserved_backing, 64)?;
        let usage = owner.storage_usage();
        let before = pointers(&owner)?;
        let original = [0x31; 48];
        let fragments = batch(1, &original)?.fragments;
        let mut output = [0xa5; 128];
        assert_eq!(
            owner.accept_at_until(&fragments[2], 20, 22, 100, &mut output)?,
            TimedReassemblyStatus::Pending {
                message: MessageId(1),
                received: 1,
                total: 3
            }
        );
        assert_eq!(retained(&owner, 1)?, (20, 30, 1));
        assert_eq!(
            owner.accept_at_until(&fragments[2], 1, 23, 2, &mut output)?,
            TimedReassemblyStatus::Duplicate {
                message: MessageId(1)
            }
        );
        let mut conflict = fragments[2].clone();
        conflict[FRAGMENT_HEADER_BYTES] ^= 1;
        assert_eq!(
            owner.accept_at_until(&conflict, 1, 24, 2, &mut output),
            Err(FragmentError::Conflict)
        );
        assert_eq!(retained(&owner, 1)?, (20, 30, 1));
        assert_eq!(output, [0xa5; 128]);
        assert!(matches!(
            owner.accept_at_until(&fragments[0], 18, 25, 100, &mut output)?,
            TimedReassemblyStatus::Pending { received: 2, .. }
        ));
        assert_eq!(retained(&owner, 1)?, (18, 28, 2));
        let mut short = [0xa5; 47];
        assert_eq!(
            owner.accept_at_until(&fragments[1], 17, 26, 100, &mut short),
            Err(FragmentError::OutputTooSmall)
        );
        assert_eq!(short, [0xa5; 47]);
        assert_eq!(retained(&owner, 1)?, (18, 28, 2));
        complete(
            owner.accept_at_until(&fragments[1], 17, 26, 100, &mut output)?,
            1,
            original.len(),
            17,
            27,
        )?;
        assert_eq!(&output[..48], original);
        assert_eq!(&output[48..], &[0xa5; 80]);
        assert_eq!(
            (
                owner.pending_messages(),
                owner.reserved_bytes(),
                owner.reserved_fragments()
            ),
            (0, 0, 0)
        );
        output.fill(0xa5);
        assert_eq!(
            owner.accept_at_until(&fragments[1], 1, 27, 2, &mut output)?,
            TimedReassemblyStatus::Duplicate {
                message: MessageId(1)
            }
        );
        assert_eq!(output, [0xa5; 128]);
        assert_eq!(owner.storage_usage(), usage);
        assert_eq!(pointers(&owner)?, before);
        if let Some(usage) = usage {
            assert_eq!(
                usage.capacity_bytes,
                storage::Plan::for_reassembly(owner.config)?.capacity_bytes()
            );
            assert_eq!(usage.allocations, 3 + 2 * owner.config.max_messages);
        }
    }
    Ok(())
}

#[test]
fn timed_expired_unique_input_is_explicit_and_tombstones_without_completed_output() -> Result {
    for reserved_backing in [false, true] {
        let mut owner = owner(reserved_backing, 4)?;
        let usage = owner.storage_usage();
        let before = pointers(&owner)?;
        let fragments = batch(1, &[0x42; 32])?.fragments;
        let mut output = [0xa5; 128];
        assert_eq!(
            owner.accept_at_until(&fragments[0], 2, 12, 100, &mut output)?,
            TimedReassemblyStatus::Expired {
                message: MessageId(1)
            }
        );
        assert_eq!(owner.pending_messages(), 0);
        assert_eq!(owner.retired_messages(), 1);
        assert_eq!(
            owner.accept_at_until(&fragments[1], 3, 13, 100, &mut output)?,
            TimedReassemblyStatus::Duplicate {
                message: MessageId(1)
            }
        );
        assert_eq!(output, [0xa5; 128]);
        let single = batch(2, &[0x61])?.fragments;
        complete(
            owner.accept_at_until(&single[0], 20, 21, 25, &mut output)?,
            2,
            1,
            20,
            25,
        )?;
        assert_eq!(output[0], 0x61);
        output.fill(0xa5);
        let active = batch(3, &[0x73; 32])?.fragments;
        owner.accept_at_until(&active[0], 30, 31, 50, &mut output)?;
        assert_eq!(retained(&owner, 3)?, (30, 40, 1));
        assert_eq!(
            owner.accept_at_until(&active[1], 31, 32, 32, &mut []),
            Err(FragmentError::OutputTooSmall)
        );
        assert_eq!(retained(&owner, 3)?, (30, 40, 1));
        assert_eq!(
            owner.accept_at_until(&active[1], 31, 32, 32, &mut output)?,
            TimedReassemblyStatus::Expired {
                message: MessageId(3)
            }
        );
        assert_eq!(output, [0xa5; 128]);
        assert_eq!(
            (
                owner.pending_messages(),
                owner.reserved_bytes(),
                owner.reserved_fragments()
            ),
            (0, 0, 0)
        );
        assert_eq!(
            owner.accept_at_until(&active[0], 31, 33, 50, &mut output)?,
            TimedReassemblyStatus::Duplicate {
                message: MessageId(3)
            }
        );
        let high = batch(10, &[0x6a])?.fragments;
        complete(
            owner.accept_at_until(&high[0], 34, 34, 50, &mut output)?,
            10,
            1,
            34,
            44,
        )?;
        output.fill(0xa5);
        assert_eq!(
            owner.accept_at_until(&fragments[0], 34, 35, 100, &mut output),
            Err(FragmentError::StaleMessage)
        );
        let expired_single = batch(11, &[0x6b])?.fragments;
        assert_eq!(
            owner.accept_at_until(&expired_single[0], 30, 41, 31, &mut output)?,
            TimedReassemblyStatus::Expired {
                message: MessageId(11)
            }
        );
        assert_eq!(output, [0xa5; 128]);
        let retry = batch(12, &[0x6c])?.fragments;
        assert_eq!(
            owner.accept_at_until(&retry[0], 40, 42, 47, &mut []),
            Err(FragmentError::OutputTooSmall)
        );
        complete(
            owner.accept_at_until(&retry[0], 40, 42, 47, &mut output)?,
            12,
            1,
            40,
            47,
        )?;
        assert_eq!(output[0], 0x6c);
        assert_eq!(owner.storage_usage(), usage);
        assert_eq!(pointers(&owner)?, before);
    }
    Ok(())
}

#[test]
fn timed_parser_clock_and_overflow_refusals_keep_the_existing_cleanup_order() -> Result {
    for reserved_backing in [false, true] {
        let mut owner = owner(reserved_backing, 64)?;
        let fragments = batch(1, &[0x54; 32])?.fragments;
        let mut output = [0xa5; 128];
        owner.accept_at_until(&fragments[0], 3, 5, 100, &mut output)?;
        assert_eq!(retained(&owner, 1)?, (3, 13, 1));
        assert_eq!(
            owner.accept_at_until(&fragments[1][..39], 0, 100, 1, &mut output),
            Err(FragmentError::Truncated)
        );
        let mut foreign = fragments[1].clone();
        foreign[4] ^= 1;
        assert_eq!(
            owner.accept_at_until(&foreign, 0, 100, 1, &mut output),
            Err(FragmentError::WrongContext)
        );
        assert_eq!(owner.last_time, Some(5));
        assert_eq!(retained(&owner, 1)?, (3, 13, 1));
        assert_eq!(
            owner.accept_at_until(&fragments[1], 8, 7, 100, &mut output),
            Err(FragmentError::TimeWentBackwards)
        );
        assert_eq!(
            owner.accept_at_until(&fragments[1], 3, 4, 100, &mut output),
            Err(FragmentError::TimeWentBackwards)
        );
        assert_eq!(owner.last_time, Some(5));
        assert_eq!(retained(&owner, 1)?, (3, 13, 1));
        let overflow = batch(2, &[0x62])?.fragments;
        assert_eq!(
            owner.accept_at_until(
                &overflow[0],
                u64::MAX - 5,
                u64::MAX - 5,
                u64::MAX,
                &mut output
            ),
            Err(FragmentError::DeadlineOverflow)
        );
        // Valid input first cleans the already expired old owner, then the new
        // deadline addition refuses. The invalid new ID is never published.
        assert_eq!(owner.last_time, Some(u64::MAX - 5));
        assert_eq!(owner.highest, Some(MessageId(1)));
        assert_eq!(owner.pending_messages(), 0);
        assert_eq!(owner.retired_messages(), 1);
        assert_eq!(output, [0xa5; 128]);
    }
    Ok(())
}

#[test]
fn legacy_and_timed_existing_completion_near_clock_limit_do_not_add_new_lifetime() -> Result {
    for reserved_backing in [false, true] {
        for timed in [false, true] {
            let mut owner = owner(reserved_backing, 64)?;
            let before = pointers(&owner)?;
            let fragments = batch(1, &[0x29; 32])?.fragments;
            let first = u64::MAX - 15;
            let observed = u64::MAX - 8;
            let mut output = [0xa5; 128];
            if timed {
                owner.accept_at_until(&fragments[0], first, first, u64::MAX, &mut output)?;
                complete(
                    owner.accept_at_until(
                        &fragments[1],
                        observed,
                        observed,
                        u64::MAX,
                        &mut output,
                    )?,
                    1,
                    32,
                    first,
                    u64::MAX - 5,
                )?;
            } else {
                assert!(matches!(
                    owner.accept(&fragments[0], first, &mut output)?,
                    ReassemblyStatus::Pending { received: 1, .. }
                ));
                assert_eq!(
                    owner.accept(&fragments[1], observed, &mut output)?,
                    ReassemblyStatus::Complete {
                        message: MessageId(1),
                        length: 32
                    }
                );
            }
            assert_eq!(&output[..32], &[0x29; 32]);
            assert_eq!(&output[32..], &[0xa5; 96]);
            assert_eq!(pointers(&owner)?, before);
        }
    }
    Ok(())
}

#[test]
fn complete_arrival_is_maximum_distinct_input_while_first_arrival_keeps_original_cap() -> Result {
    for reserved_backing in [false, true] {
        let mut owner = owner(reserved_backing, 64)?;
        let usage = owner.storage_usage();
        let pointers_before = pointers(&owner)?;
        let original = [0x71; 48];
        let fragments = batch(9, &original)?.fragments;
        let mut output = [0; 48];
        owner.accept_at_until(&fragments[2], 20, 22, 100, &mut output)?;
        owner.accept_at_until(&fragments[0], 18, 24, 100, &mut output)?;
        // Duplicate time is not a new whole-body arrival and cannot renew age.
        owner.accept_at_until(&fragments[0], 25, 25, 100, &mut output)?;
        let TimedReassemblyStatus::Complete { timing, .. } =
            owner.accept_at_until(&fragments[1], 19, 26, 100, &mut output)?
        else {
            return Err("real complete body missing".into());
        };
        assert_eq!(timing.first_received_ticks(), 18);
        assert_eq!(timing.complete_received_ticks(), 20);
        assert_eq!(timing.deadline_ticks(), 28);
        assert_eq!(output, original);
        assert_eq!(owner.storage_usage(), usage);
        assert_eq!(pointers(&owner)?, pointers_before);
    }
    Ok(())
}

#[test]
fn precise_complete_arrival_orders_equal_ticks_without_changing_first_arrival_cap() -> Result {
    for reserved_backing in [false, true] {
        for after in [false, true] {
            let mut owner = owner(reserved_backing, 64)?;
            let usage = owner.storage_usage();
            let before = pointers(&owner)?;
            let fragments = batch(1, &[0x63; 48])?.fragments;
            let mut output = [0xa5; 128];
            let order = |n| CausalTime::from_nanos(n);
            owner.accept_ordered_at_until(&fragments[2], 20, 22, 28, order(20_200), &mut output)?;
            owner.accept_ordered_at_until(&fragments[0], 20, 23, 28, order(20_100), &mut output)?;
            // A duplicate observed later cannot acquire causal or lifetime custody.
            assert!(matches!(
                owner.accept_ordered_at_until(
                    &fragments[2],
                    20,
                    24,
                    28,
                    order(20_999),
                    &mut output
                )?,
                TimedReassemblyStatus::Duplicate { .. }
            ));
            let final_arrival = if after { 20_800 } else { 20_300 };
            let TimedReassemblyStatus::Complete { timing, length, .. } = owner
                .accept_ordered_at_until(
                    &fragments[1],
                    20,
                    25,
                    28,
                    order(final_arrival),
                    &mut output,
                )?
            else {
                return Err("actual complete body".into());
            };
            assert_eq!(
                (
                    timing.first_received_ticks(),
                    timing.complete_received_ticks(),
                    timing.deadline_ticks()
                ),
                (20, 20, 28)
            );
            assert_eq!(timing.complete_order(), Some(order(final_arrival)));
            assert_eq!(
                timing.complete_order().ok_or("exact arrival")? <= order(20_500),
                !after
            );
            assert_eq!(&output[..length], &[0x63; 48]);
            assert_eq!(owner.storage_usage(), usage);
            assert_eq!(pointers(&owner)?, before);
        }
    }
    Ok(())
}
