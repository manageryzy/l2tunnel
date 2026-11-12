use super::*;

const SCOPE: Scope = Scope {
    session: 17,
    epoch: 4,
    direction: Direction::Forward,
};
const FLOW: FlowId = FlowId(1);

fn credit(bytes: u64, records: u64) -> Credit {
    Credit { bytes, records }
}

fn capacity(bytes: u64, records: u64, max_flows: usize) -> Capacity {
    Capacity {
        credit: credit(bytes, records),
        max_flows,
    }
}

fn pair(bytes: u64, records: u64) -> Result<(SenderCredits, ReceiverCredits), CreditError> {
    let mut sender = SenderCredits::new(SCOPE, capacity(bytes, records, 4))?;
    let mut receiver = ReceiverCredits::new(SCOPE, capacity(bytes, records, 4))?;
    sender.open_flow(FLOW)?;
    receiver.open_flow(FLOW)?;
    Ok((sender, receiver))
}

#[test]
fn granted_unreceived_data_reserves_aggregate_capacity() -> Result<(), CreditError> {
    let (_, mut receiver) = pair(100, 4)?;
    receiver.open_flow(FlowId(2))?;
    receiver.grant(FLOW, credit(80, 3))?;
    assert_eq!(receiver.reserved(), credit(80, 3));
    assert_eq!(
        receiver.grant(FlowId(2), credit(21, 1)),
        Err(CreditError::ReceiverPressure)
    );
    assert_eq!(receiver.reserved(), credit(80, 3));
    assert_eq!(
        receiver.grant(FlowId(2), credit(20, 2)),
        Err(CreditError::ReceiverPressure)
    );
    receiver.grant(FlowId(2), credit(20, 1))?;
    assert_eq!(receiver.reserved(), credit(100, 4));
    Ok(())
}

#[test]
fn zero_sender_credit_recovers_after_release_and_regrant() -> Result<(), CreditError> {
    let (mut sender, mut receiver) = pair(10, 1)?;
    let initial = receiver.grant(FLOW, credit(10, 1))?;
    sender.apply_grant(initial)?;
    let record = sender.admit(FLOW, 10)?;
    assert_eq!(
        sender.admit(FLOW, 1),
        Err(CreditError::SenderExhausted(LimitDomain::Flow))
    );
    assert_eq!(receiver.receive(record)?, Received::New);
    sender.apply_release(receiver.release_next(FLOW)?)?;
    assert_eq!(receiver.reserved(), credit(0, 0));
    // Free receiver memory can renew ordinary exhausted sender credit immediately.
    sender.apply_grant(receiver.grant(FLOW, credit(20, 2))?)?;
    sender.apply_grant(initial)?; // Old updates cannot revoke the new allowance.
    let next = sender.admit(FLOW, 10)?;
    assert_eq!(next.id, RecordId(1));
    assert_eq!(next.byte_start, 10);
    assert_eq!(receiver.reserved(), credit(10, 1));
    Ok(())
}

#[test]
fn retries_duplicates_and_old_release_do_not_recreate_credit() -> Result<(), CreditError> {
    let (mut sender, mut receiver) = pair(10, 2)?;
    let grant = receiver.grant(FLOW, credit(10, 2))?;
    sender.apply_grant(grant)?;
    let first = sender.admit(FLOW, 4)?;
    let second = sender.admit(FLOW, 6)?;
    for _ in 0..20 {
        assert_eq!(sender.retry(FLOW, first.id)?, first);
        sender.apply_grant(grant)?;
    }
    assert_eq!(sender.admitted(), credit(10, 2));
    assert_eq!(sender.retained(), credit(10, 2));
    receiver.receive(first)?;
    assert_eq!(receiver.receive(first)?, Received::Duplicate);
    receiver.receive(second)?;
    let release_one = receiver.release_next(FLOW)?;
    let release_two = receiver.release_next(FLOW)?;
    sender.apply_release(release_two)?;
    sender.apply_release(release_one)?;
    sender.apply_release(release_two)?;
    assert_eq!(sender.retained(), credit(0, 0));
    assert_eq!(
        sender.retry(FLOW, first.id),
        Err(CreditError::MissingRecord)
    );
    assert_eq!(receiver.receive(first)?, Received::AlreadyReleased);
    assert_eq!(
        sender.admit(FLOW, 0),
        Err(CreditError::SenderExhausted(LimitDomain::Flow))
    );
    Ok(())
}

#[test]
fn records_reorder_but_cannot_release_across_a_gap() -> Result<(), CreditError> {
    let (mut sender, mut receiver) = pair(10, 3)?;
    sender.apply_grant(receiver.grant(FLOW, credit(10, 3))?)?;
    let first = sender.admit(FLOW, 3)?;
    let second = sender.admit(FLOW, 0)?;
    let third = sender.admit(FLOW, 7)?;
    receiver.receive(third)?;
    assert_eq!(receiver.release_next(FLOW), Err(CreditError::MissingRecord));
    receiver.receive(second)?;
    receiver.receive(first)?;
    for expected in [credit(3, 1), credit(3, 2), credit(10, 3)] {
        let release = receiver.release_next(FLOW)?;
        assert_eq!(release.consumed, expected);
        sender.apply_release(release)?;
    }
    assert_eq!(receiver.reserved(), credit(0, 0));
    Ok(())
}

#[test]
fn malformed_record_ranges_never_free_reservations() -> Result<(), CreditError> {
    let (mut sender, mut receiver) = pair(20, 4)?;
    sender.apply_grant(receiver.grant(FLOW, credit(20, 4))?)?;
    let first = sender.admit(FLOW, 5)?;
    let second = sender.admit(FLOW, 5)?;
    receiver.receive(second)?;
    assert_eq!(
        receiver.receive(Record {
            byte_start: 1,
            ..first
        }),
        Err(CreditError::InvalidOffset)
    );
    assert_eq!(
        receiver.receive(Record {
            byte_len: 6,
            ..first
        }),
        Err(CreditError::InvalidOffset)
    );
    assert_eq!(
        receiver.receive(Record {
            byte_len: 4,
            ..first
        }),
        Err(CreditError::InvalidOffset)
    );
    receiver.receive(first)?;
    assert_eq!(
        receiver.receive(Record {
            byte_len: 4,
            ..second
        }),
        Err(CreditError::InvalidOffset)
    );
    assert_eq!(
        receiver.receive(Record {
            byte_len: 21,
            ..first
        }),
        Err(CreditError::GrantExceeded)
    );
    assert_eq!(receiver.reserved(), credit(20, 4));
    Ok(())
}

#[test]
fn session_admission_and_local_retention_are_independent_limits() -> Result<(), CreditError> {
    let mut sender = SenderCredits::new(SCOPE, capacity(5, 2, 2))?;
    for flow in [FLOW, FlowId(2)] {
        sender.open_flow(flow)?;
        sender.apply_grant(Grant {
            scope: SCOPE,
            flow,
            flow_limit: credit(10, 3),
            session_limit: credit(10, 3),
        })?;
    }
    sender.admit(FLOW, 5)?;
    assert_eq!(sender.admit(FLOW, 1), Err(CreditError::LocalRetention));
    sender.apply_release(Release {
        scope: SCOPE,
        flow: FLOW,
        consumed: credit(5, 1),
    })?;
    sender.admit(FlowId(2), 5)?;
    assert_eq!(
        sender.admit(FLOW, 1),
        Err(CreditError::SenderExhausted(LimitDomain::Session))
    );
    assert_eq!(sender.admitted(), credit(10, 2));
    Ok(())
}

#[test]
fn empty_records_still_exhaust_count_and_metadata_budget() -> Result<(), CreditError> {
    let (mut sender, mut receiver) = pair(0, 2)?;
    sender.apply_grant(receiver.grant(FLOW, credit(0, 2))?)?;
    for _ in 0..2 {
        let record = sender.admit(FLOW, 0)?;
        receiver.receive(record)?;
    }
    assert_eq!(
        sender.admit(FLOW, 0),
        Err(CreditError::SenderExhausted(LimitDomain::Flow))
    );
    assert_eq!(
        receiver.grant(FLOW, credit(0, 3)),
        Err(CreditError::ReceiverPressure)
    );
    assert_eq!(sender.retained(), credit(0, 2));
    Ok(())
}

#[test]
fn scope_and_release_boundary_failures_are_atomic() -> Result<(), CreditError> {
    let (mut sender, mut receiver) = pair(10, 2)?;
    let grant = receiver.grant(FLOW, credit(10, 2))?;
    let wrong = Scope {
        epoch: SCOPE.epoch + 1,
        ..SCOPE
    };
    assert_eq!(
        sender.apply_grant(Grant {
            scope: wrong,
            ..grant
        }),
        Err(CreditError::WrongScope)
    );
    sender.apply_grant(grant)?;
    let record = sender.admit(FLOW, 6)?;
    assert_eq!(
        receiver.receive(Record {
            scope: wrong,
            ..record
        }),
        Err(CreditError::WrongScope)
    );
    for consumed in [credit(5, 1), credit(6, 0), credit(7, 1), credit(6, 2)] {
        assert_eq!(
            sender.apply_release(Release {
                scope: SCOPE,
                flow: FLOW,
                consumed
            }),
            Err(CreditError::InvalidOffset)
        );
        assert_eq!(sender.retained(), credit(6, 1));
    }
    receiver.receive(record)?;
    sender.apply_release(receiver.release_next(FLOW)?)?;
    Ok(())
}

#[test]
fn drained_retirement_reclaims_unused_grants_without_reusing_ids() -> Result<(), CreditError> {
    let (mut sender, mut receiver) = pair(100, 10)?;
    sender.apply_grant(receiver.grant(FLOW, credit(100, 10))?)?;
    let record = sender.admit(FLOW, 20)?;
    assert_eq!(
        sender.retire(FLOW, RetirementMode::Drained),
        Err(CreditError::OutstandingRecords)
    );
    receiver.receive(record)?;
    sender.apply_release(receiver.release_next(FLOW)?)?;
    let final_offset = sender.retire(FLOW, RetirementMode::Drained)?;
    receiver.retire(final_offset, RetirementMode::Drained)?;
    assert_eq!(receiver.reserved(), credit(0, 0));
    assert_eq!(receiver.active_flows(), 0);
    assert_eq!(sender.active_flows(), 0);
    assert_eq!(
        receiver.open_flow(FLOW),
        Err(CreditError::FlowIdNotIncreasing)
    );
    assert_eq!(
        sender.open_flow(FLOW),
        Err(CreditError::FlowIdNotIncreasing)
    );
    assert_eq!(receiver.receive(record), Err(CreditError::UnknownFlow));
    assert_eq!(
        receiver.retire(final_offset, RetirementMode::Drained),
        Err(CreditError::UnknownFlow)
    );
    let new_flow = FlowId(2);
    receiver.open_flow(new_flow)?;
    sender.open_flow(new_flow)?;
    let grant = receiver.grant(new_flow, credit(100, 10))?;
    assert_eq!(grant.session_limit, credit(200, 20));
    sender.apply_grant(grant)?;
    sender.admit(new_flow, 100)?;
    assert_eq!(receiver.reserved(), credit(100, 10));
    Ok(())
}

#[test]
fn loss_requires_explicit_abandon_and_final_offset_cannot_hide_received_data()
-> Result<(), CreditError> {
    let (mut sender, mut receiver) = pair(20, 3)?;
    sender.apply_grant(receiver.grant(FLOW, credit(20, 3))?)?;
    sender.admit(FLOW, 5)?; // Lost record.
    let second = sender.admit(FLOW, 5)?;
    receiver.receive(second)?;
    let wrong = FinalOffset {
        scope: SCOPE,
        flow: FLOW,
        admitted: credit(5, 1),
    };
    assert_eq!(
        receiver.retire(wrong, RetirementMode::Abandon),
        Err(CreditError::InvalidOffset)
    );
    let inconsistent = FinalOffset {
        scope: SCOPE,
        flow: FLOW,
        admitted: credit(11, 2),
    };
    assert_eq!(
        receiver.retire(inconsistent, RetirementMode::Abandon),
        Err(CreditError::InvalidOffset)
    );
    let final_offset = sender.retire(FLOW, RetirementMode::Abandon)?;
    assert_eq!(
        receiver.retire(final_offset, RetirementMode::Drained),
        Err(CreditError::OutstandingRecords)
    );
    receiver.retire(final_offset, RetirementMode::Abandon)?;
    assert_eq!(receiver.reserved(), credit(0, 0));
    assert_eq!(sender.retained(), credit(0, 0));
    Ok(())
}

#[test]
fn stale_smaller_grants_never_revoke_reservations() -> Result<(), CreditError> {
    let (_, mut receiver) = pair(10, 3)?;
    receiver.grant(FLOW, credit(8, 2))?;
    let stale = receiver.grant(FLOW, credit(4, 1))?;
    assert_eq!(stale.flow_limit, credit(8, 2));
    let mixed = receiver.grant(FLOW, credit(6, 3))?;
    assert_eq!(mixed.flow_limit, credit(8, 3));
    assert_eq!(receiver.reserved(), credit(8, 3));
    Ok(())
}

#[test]
fn arithmetic_exhaustion_rejects_before_state_mutation() -> Result<(), CreditError> {
    let (mut sender, mut receiver) = pair(u64::MAX, 3)?;
    sender.apply_grant(receiver.grant(FLOW, credit(u64::MAX, 3))?)?;
    let record = sender.admit(FLOW, u64::MAX)?;
    assert_eq!(sender.admit(FLOW, 1), Err(CreditError::Overflow));
    assert_eq!(sender.admitted(), credit(u64::MAX, 1));
    assert_eq!(
        receiver.receive(Record {
            byte_start: 1,
            ..record
        }),
        Err(CreditError::Overflow)
    );
    assert_eq!(
        receiver.receive(Record {
            id: RecordId(u64::MAX),
            ..record
        }),
        Err(CreditError::Overflow)
    );
    receiver.receive(record)?;
    sender.apply_release(receiver.release_next(FLOW)?)?;
    let final_offset = sender.retire(FLOW, RetirementMode::Drained)?;
    receiver.retire(final_offset, RetirementMode::Drained)?;
    receiver.open_flow(FlowId(2))?;
    assert_eq!(
        receiver.grant(FlowId(2), credit(1, 1)),
        Err(CreditError::Overflow)
    );
    assert_eq!(receiver.reserved(), credit(0, 0));
    Ok(())
}

#[test]
fn flow_capacity_and_monotonic_ids_bound_metadata() -> Result<(), CreditError> {
    let mut receiver = ReceiverCredits::new(SCOPE, capacity(1, 1, 1))?;
    receiver.open_flow(FLOW)?;
    assert_eq!(
        receiver.open_flow(FlowId(2)),
        Err(CreditError::TooManyFlows)
    );
    receiver.retire(
        FinalOffset {
            scope: SCOPE,
            flow: FLOW,
            admitted: credit(0, 0),
        },
        RetirementMode::Drained,
    )?;
    receiver.open_flow(FlowId(2))?;
    assert_eq!(
        receiver.open_flow(FLOW),
        Err(CreditError::FlowIdNotIncreasing)
    );
    assert_eq!(receiver.active_flows(), 1);
    assert!(matches!(
        ReceiverCredits::new(SCOPE, capacity(0, 0, 1)),
        Err(CreditError::InvalidCapacity)
    ));
    assert!(matches!(
        SenderCredits::new(SCOPE, capacity(0, 1, 0)),
        Err(CreditError::InvalidCapacity)
    ));
    Ok(())
}

#[test]
fn all_small_reorderings_preserve_prefix_release_and_resource_bounds() -> Result<(), CreditError> {
    for ordering in [
        [0, 1, 2],
        [0, 2, 1],
        [1, 0, 2],
        [1, 2, 0],
        [2, 0, 1],
        [2, 1, 0],
    ] {
        let (mut sender, mut receiver) = pair(12, 3)?;
        sender.apply_grant(receiver.grant(FLOW, credit(12, 3))?)?;
        let records = [
            sender.admit(FLOW, 3)?,
            sender.admit(FLOW, 4)?,
            sender.admit(FLOW, 5)?,
        ];
        for index in ordering {
            receiver.receive(records[index])?;
            assert_eq!(receiver.reserved(), credit(12, 3));
        }
        for expected in [credit(3, 1), credit(7, 2), credit(12, 3)] {
            let release = receiver.release_next(FLOW)?;
            assert_eq!(release.consumed, expected);
            sender.apply_release(release)?;
            assert_eq!(sender.retained(), receiver.reserved());
        }
        let final_offset = sender.retire(FLOW, RetirementMode::Drained)?;
        receiver.retire(final_offset, RetirementMode::Drained)?;
        assert_eq!(receiver.reserved(), credit(0, 0));
    }
    Ok(())
}

#[test]
fn a_final_offset_cannot_claim_bytes_without_any_record() -> Result<(), CreditError> {
    let (_, mut receiver) = pair(10, 2)?;
    receiver.grant(FLOW, credit(10, 2))?;
    let malformed = FinalOffset {
        scope: SCOPE,
        flow: FLOW,
        admitted: credit(1, 0),
    };
    assert_eq!(
        receiver.retire(malformed, RetirementMode::Abandon),
        Err(CreditError::InvalidOffset)
    );
    assert_eq!(receiver.reserved(), credit(10, 2));
    Ok(())
}

#[test]
fn admission_preview_is_authoritative_and_never_spends_credit() -> Result<(), CreditError> {
    let (mut sender, mut receiver) = pair(10, 2)?;
    assert_eq!(sender.preview_admit(FLOW, 5), sender.admit(FLOW, 5));
    sender.apply_grant(receiver.grant(FLOW, credit(10, 2))?)?;
    let expected = sender.preview_admit(FLOW, 6)?;
    for _ in 0..100 {
        assert_eq!(sender.preview_admit(FLOW, 6)?, expected);
        assert_eq!(sender.admitted(), credit(0, 0));
        assert_eq!(sender.retained(), credit(0, 0));
    }
    assert_eq!(sender.admit(FLOW, 6)?, expected);
    assert_eq!(sender.preview_admit(FLOW, 5), sender.admit(FLOW, 5));
    assert_eq!(
        sender.preview_admit(FLOW, u64::MAX),
        Err(CreditError::Overflow)
    );
    let second = sender.preview_admit(FLOW, 4)?;
    assert_eq!(sender.admit(FLOW, 4)?, second);
    assert_eq!(sender.preview_admit(FLOW, 0), sender.admit(FLOW, 0));
    assert_eq!(sender.admitted(), credit(10, 2));
    Ok(())
}
