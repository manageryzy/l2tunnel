use super::*;
use crate::{
    ChannelId, Direction, Epoch, SessionId,
    striped_group::{SealedGroup, Sender},
};

const PROFILE: Profile = Profile {
    data_cells: 3,
    parity_cells: 1,
    max_wire_bytes: 100,
    max_body_bytes: 100,
};
const SCOPE: FecContext = FecContext {
    session: SessionId([9; 16]),
    epoch: Epoch(7),
    channel: ChannelId(3),
    direction: Direction::ClientToServer,
};
const ZERO: GenerationId = GenerationId(0);

fn group(base: u64, originals: &[&[u8]]) -> Result<SealedGroup, Error> {
    let mut tx = Sender::new(PROFILE, 1, GenerationId(base), 0)?;
    for src in originals {
        tx.submit(0, src)?;
    }
    tx.poll_group(1)?.ok_or(Error::Unsealed)
}
fn wire(group: &SealedGroup, index: u8) -> Result<Vec<u8>, Error> {
    let mut bytes = vec![0; PROFILE.max_wire_bytes];
    let used = group.write_packet(index, &mut bytes)?;
    bytes.truncate(used);
    Ok(bytes)
}

#[test]
fn future_groups_commit_early_and_bytes_always_remain_for_unknown_oldest() -> Result<(), Error> {
    let reserve = ReceiveWindow::frontier_reserve(PROFILE, 16)?;
    assert_eq!(reserve, 400);
    let mut rx = ReceiveWindow::new(PROFILE, SCOPE, ZERO, 16, reserve + 13)?;
    let future = group(4, &[b"y"])?;
    let mut scratch = [0; 100];
    // 1+1 at width 3: 2 * 6 canonical body bytes plus one reassembled byte.
    assert_eq!(
        rx.accept_authenticated(SCOPE, &wire(&future, 1)?, &mut scratch)?,
        ReceiveAdmission::Accepted
    );
    assert_eq!(rx.expanded_bytes(), 13);
    assert_eq!(rx.pending_original(GenerationId(4))?, Some(b"y".as_slice()));
    let later = group(5, &[b"z"])?;
    assert_eq!(
        rx.accept_authenticated(SCOPE, &wire(&later, 0)?, &mut scratch),
        Err(Error::Capacity)
    );
    assert!(rx.commit_original(GenerationId(4))?);
    assert_eq!(rx.expanded_bytes(), 0);
    assert!(!rx.commit_original(GenerationId(4))?);
    for id in 5..=15 {
        let value = [id as u8];
        let next = group(id, &[&value])?;
        assert_eq!(
            rx.accept_authenticated(SCOPE, &wire(&next, 0)?, &mut scratch)?,
            ReceiveAdmission::Accepted
        );
        assert_eq!(rx.expanded_bytes(), 13);
        assert_eq!(
            rx.pending_original(GenerationId(id))?,
            Some(value.as_slice())
        );
        assert!(rx.commit_original(GenerationId(id))?);
        assert_eq!(rx.expanded_bytes(), 0);
        assert_eq!(rx.confirmed_through(), None);
    }
    assert_eq!(rx.group_count(), 12);
    assert_eq!(rx.uncommitted_in_groups(), 0);
    assert_eq!(rx.uncommitted_through_sealed(), 4);
    assert_eq!(rx.frontier(), Some(ZERO));
    assert_eq!(
        rx.accept_authenticated(SCOPE, &wire(&group(16, &[b"!"])?, 0)?, &mut scratch),
        Err(Error::WindowBlocked)
    );
    let mut missing = [ZERO; 16];
    let used = rx.missing_ids(ZERO, 16, &mut missing)?;
    assert_eq!(
        &missing[..used],
        &[ZERO, GenerationId(1), GenerationId(2), GenerationId(3)]
    );
    let old = group(0, &[&[1; 62], &[2; 61], &[3; 61], &[4; 62]])?;
    assert_eq!(
        rx.accept_authenticated(SCOPE, &wire(&old, 3)?, &mut scratch)?,
        ReceiveAdmission::Accepted
    );
    assert_eq!(rx.expanded_bytes(), 4 * 88);
    rx.accept_authenticated(SCOPE, &wire(&old, 0)?, &mut scratch)?;
    assert!(rx.commit_original(ZERO)?);
    assert_eq!(rx.confirmed_through(), Some(ZERO));
    assert_eq!(rx.commit_original(GenerationId(1)), Err(Error::Unsealed));
    assert_eq!(rx.recover_missing(ZERO), Err(Error::InsufficientRank));
    rx.accept_authenticated(SCOPE, &wire(&old, 1)?, &mut scratch)?;
    assert!(rx.can_recover(ZERO));
    let used = rx.missing_ids(ZERO, 16, &mut missing)?;
    assert_eq!(&missing[..used], &[GenerationId(2)]);
    assert_eq!(rx.recover_missing(ZERO)?, 1);
    assert_eq!(rx.missing_ids(ZERO, 16, &mut missing)?, 0);
    for n in [3, 2, 1] {
        assert!(rx.commit_original(GenerationId(n))?);
    }
    assert_eq!(rx.confirmed_through(), Some(GenerationId(15)));
    assert_eq!(rx.uncommitted_through_sealed(), 0);
    assert_eq!(rx.group_count(), 0);
    assert_eq!(rx.expanded_bytes(), 0);
    assert_eq!(
        rx.accept_authenticated(SCOPE, &wire(&old, 2)?, &mut scratch)?,
        ReceiveAdmission::Retired
    );
    assert_eq!(
        rx.accept_authenticated(SCOPE, &wire(&later, 0)?, &mut scratch)?,
        ReceiveAdmission::Retired
    );
    Ok(())
}

#[test]
fn completed_range_keeps_shape_width_and_overlap_but_no_longer_compares_retired_bytes()
-> Result<(), Error> {
    let mut scratch = [0; 100];
    let mut rx = ReceiveWindow::new(PROFILE, SCOPE, ZERO, 16, 416)?;
    let base = GenerationId(4);
    let future = group(4, &[b"a", b"b", b"c", b"d"])?;
    for ordinal in 0..3 {
        rx.accept_authenticated(SCOPE, &wire(&future, ordinal)?, &mut scratch)?;
        assert!(rx.commit_original(GenerationId(base.0 + u64::from(ordinal)))?);
    }
    assert_eq!(rx.expanded_bytes(), 16);
    let changed = group(4, &[b"w", b"x", b"y", b"z"])?;
    assert_eq!(
        rx.accept_authenticated(SCOPE, &wire(&changed, 0)?, &mut scratch),
        Err(Error::Conflict)
    );
    assert_eq!(rx.commit_original(GenerationId(7)), Err(Error::Unsealed));
    assert_eq!(
        rx.accept_authenticated(SCOPE, &wire(&group(8, &[b"g"])?, 0)?, &mut scratch),
        Err(Error::Capacity)
    );
    assert!(rx.can_recover(base));
    assert_eq!(rx.recover_missing(base)?, 1);
    assert_eq!(rx.pending_original(GenerationId(7))?, Some(b"d".as_slice()));
    assert!(rx.commit_original(GenerationId(7))?);
    assert_eq!(rx.expanded_bytes(), 0);
    assert!(!rx.can_recover(base));
    assert_eq!(rx.recover_missing(base)?, 0);
    assert_eq!(rx.pending_original(GenerationId(7))?, None);
    assert!(!rx.commit_original(GenerationId(6))?);

    for conflicting in [
        group(3, &[b"u", b"v"])?,
        group(7, &[b"u", b"v"])?,
        group(4, &[b"x"])?,
        group(4, &[[3; 10].as_slice(); 4])?,
    ] {
        assert_eq!(
            rx.accept_authenticated(SCOPE, &wire(&conflicting, 0)?, &mut scratch),
            Err(Error::Conflict)
        );
    }
    // After all four native commits the two authenticated late datagrams have
    // the same range, shape and width. Neither can change data or the receipt.
    for late in [wire(&changed, 0)?, wire(&future, 3)?] {
        assert_eq!(
            rx.accept_authenticated(SCOPE, &late, &mut [])?,
            ReceiveAdmission::Retired
        );
    }
    assert_eq!(rx.confirmed_through(), None);
    assert_eq!(rx.observed_through(), Some(GenerationId(6)));
    assert_eq!(rx.sealed_through(), Some(GenerationId(7)));
    Ok(())
}

#[test]
fn rejects_scope_overlap_distinct_geometry_far_ids_and_bad_scratch_without_custody()
-> Result<(), Error> {
    let mut rx = ReceiveWindow::new(PROFILE, SCOPE, GenerationId(8), 8, 1000)?;
    let a = group(10, &[b"aa", b"b", b"c", b"d"])?;
    let late = wire(&a, 2)?;
    let mut scratch = [0; 100];
    let mut wrong = SCOPE;
    wrong.epoch = Epoch(8);
    assert_eq!(
        rx.accept_authenticated(wrong, &late, &mut scratch),
        Err(Error::ContextMismatch)
    );
    assert!(matches!(
        rx.accept_authenticated(SCOPE, &late, &mut []),
        Err(Error::OutputTooSmall { .. })
    ));
    assert_eq!(rx.group_count(), 0);
    let mut missing = [ZERO; 8];
    assert_eq!(rx.missing_ids(GenerationId(8), 8, &mut missing)?, 0);
    rx.accept_authenticated(SCOPE, &late, &mut scratch)?;
    let bytes = rx.expanded_bytes();
    assert_eq!(
        rx.accept_authenticated(SCOPE, &late, &mut scratch)?,
        ReceiveAdmission::Duplicate
    );
    let mut conflict = late;
    *conflict.last_mut().ok_or(Error::Malformed)? ^= 1;
    assert_eq!(
        rx.accept_authenticated(SCOPE, &conflict, &mut scratch),
        Err(Error::Conflict)
    );
    for overlap in [
        group(9, &[b"x", b"y"])?,
        group(13, &[b"x", b"y"])?,
        group(10, &[b"x"])?,
        group(10, &[[1; 16].as_slice(); 4])?,
    ] {
        assert_eq!(
            rx.accept_authenticated(SCOPE, &wire(&overlap, 0)?, &mut scratch),
            Err(Error::Conflict)
        );
    }
    let farther = group(15, &[b"x", b"y"])?;
    assert_eq!(
        rx.accept_authenticated(SCOPE, &wire(&farther, 0)?, &mut scratch),
        Err(Error::WindowBlocked)
    );
    assert_eq!(rx.expanded_bytes(), bytes);
    let n = rx.missing_ids(GenerationId(8), 8, &mut missing)?;
    assert_eq!(
        &missing[..n],
        &[
            GenerationId(8),
            GenerationId(9),
            GenerationId(10),
            GenerationId(11),
            GenerationId(13)
        ]
    );
    assert_eq!(
        rx.missing_ids(GenerationId(8), 9, &mut missing),
        Err(Error::InvalidConfig)
    );
    Ok(())
}

#[test]
fn nonwrapping_terminal_and_configuration_limits() -> Result<(), Error> {
    let reserve = ReceiveWindow::frontier_reserve(PROFILE, 1)?;
    assert!(ReceiveWindow::new(PROFILE, SCOPE, ZERO, 1, reserve - 1).is_err());
    assert!(ReceiveWindow::new(PROFILE, SCOPE, ZERO, 0, reserve).is_err());
    let max = GenerationId(u64::MAX);
    let mut rx = ReceiveWindow::new(PROFILE, SCOPE, max, 1, reserve)?;
    let end = group(max.0, &[b"only"])?;
    let packet = wire(&end, 1)?;
    let mut scratch = [0; 100];
    rx.accept_authenticated(SCOPE, &packet, &mut scratch)?;
    assert_eq!(rx.expanded_bytes(), 20);
    assert!(rx.commit_original(max)?);
    assert_eq!(rx.frontier(), None);
    assert_eq!(rx.confirmed_through(), Some(max));
    assert!(!rx.commit_original(max)?);
    assert_eq!(
        rx.accept_authenticated(SCOPE, &packet, &mut scratch)?,
        ReceiveAdmission::Retired
    );
    assert_eq!(rx.expanded_bytes(), 0);
    Ok(())
}

#[test]
fn a_sealed_tail_can_be_requested_without_claiming_every_member_was_transmitted()
-> Result<(), Error> {
    let mut rx = ReceiveWindow::new(PROFILE, SCOPE, ZERO, 8, 800)?;
    let g = group(0, &[b"a", b"b", b"c", b"d"])?;
    let mut scratch = [0; 100];
    let mut out = [ZERO; 8];
    assert_eq!((rx.observed_through(), rx.sealed_through()), (None, None));
    rx.accept_authenticated(SCOPE, &wire(&g, 0)?, &mut scratch)?;
    assert_eq!(rx.observed_through(), Some(ZERO));
    assert_eq!(rx.sealed_through(), Some(GenerationId(3)));
    assert_eq!(rx.confirmed_through(), None);
    assert_eq!(rx.missing_ids(ZERO, 8, &mut out)?, 3);
    assert_eq!(
        out[..3],
        [GenerationId(1), GenerationId(2), GenerationId(3)]
    );
    assert!(rx.commit_original(ZERO)?);
    assert_eq!(rx.confirmed_through(), Some(ZERO));
    Ok(())
}

#[test]
fn partial_head_retains_early_rows_across_ring_wrap_and_joins_committed_neighbors()
-> Result<(), Box<dyn std::error::Error>> {
    let plan = ReceivePlan::for_window(PROFILE, 8, 4096)?;
    assert_eq!(plan.physical_slots(), 11);
    let limits = storage::Limits {
        capacity_bytes: plan.capacity_bytes(),
    };
    assert!(matches!(
        ReceiveWindow::new_reserved(plan, storage::Limits { capacity_bytes: limits.capacity_bytes - 1 }, SCOPE, ZERO),
        Err(storage::Error::Limit { required, .. }) if required == limits.capacity_bytes
    ));
    let mut rx = ReceiveWindow::new_reserved(plan, limits, SCOPE, ZERO)?;
    let storage = rx.storage_usage();
    let mut scratch = [0; 100];
    for start in [0, 11, 22, 33] {
        let head = group(start, &[b"old-a", b"old-b", b"old-c", b"old-d"])?;
        for i in 0..3 {
            rx.accept_authenticated(SCOPE, &wire(&head, i)?, &mut scratch)?;
            assert!(rx.commit_original(GenerationId(start + u64::from(i)))?);
        }
        assert_eq!(rx.frontier(), Some(GenerationId(start + 3)));
        // Fill the entire available right aperture, above the old missing
        // ordinal. Bridge two pre-existing committed runs from the middle.
        for i in [10_u64, 9, 5, 7, 8, 6, 4] {
            let future = group(start + i, &[[i as u8, 1, 2].as_slice()])?;
            rx.accept_authenticated(SCOPE, &wire(&future, 1)?, &mut scratch)?;
            assert!(rx.commit_original(GenerationId(start + i))?);
        }
        assert_eq!(rx.group_count(), 8);
        assert_eq!(
            rx.accept_authenticated(SCOPE, &wire(&head, 0)?, &mut scratch)?,
            ReceiveAdmission::Duplicate
        );
        assert_eq!(rx.recover_missing(GenerationId(start))?, 1);
        assert_eq!(
            rx.pending_original(GenerationId(start + 3))?,
            Some(b"old-d".as_slice())
        );
        assert!(rx.commit_original(GenerationId(start + 3))?);
        assert_eq!(rx.confirmed_through(), Some(GenerationId(start + 10)));
        assert_eq!(rx.group_count(), 0);
        assert_eq!(rx.expanded_bytes(), 0);
        assert_eq!(rx.storage_usage(), storage);
    }
    Ok(())
}

#[test]
fn priced_single_flow_window_allocates_one_shared_solver_and_canonical_slots()
-> Result<(), Box<dyn std::error::Error>> {
    let profile = Profile {
        data_cells: 4,
        parity_cells: 1,
        max_body_bytes: 1451,
        max_wire_bytes: 1451,
    };
    let plan = ReceivePlan::for_window(profile, 8192, 48 << 20)?;
    let limits = storage::Limits {
        capacity_bytes: plan.capacity_bytes(),
    };
    let rx = ReceiveWindow::new_reserved(plan, limits, SCOPE, ZERO)?;
    assert_eq!(plan.physical_slots(), 8196);
    assert_eq!(plan.row_bytes(), 8196 * 1451);
    assert_eq!(plan.recovery_bytes(), 7838);
    assert_eq!(
        plan.row_bytes() + plan.index_bytes() + plan.recovery_bytes(),
        plan.capacity_bytes()
    );
    assert_eq!(
        rx.storage_usage(),
        storage::Usage {
            limit_bytes: plan.capacity_bytes(),
            capacity_bytes: plan.capacity_bytes(),
            allocations: 3
        }
    );
    eprintln!(
        "mixed receive window: {} canonical bytes, {} index bytes, {} GF bytes, {} total bytes",
        plan.row_bytes(),
        plan.index_bytes(),
        plan.recovery_bytes(),
        rx.storage_usage().capacity_bytes
    );
    Ok(())
}
