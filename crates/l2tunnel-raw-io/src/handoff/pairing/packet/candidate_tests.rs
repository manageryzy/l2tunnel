//! Bounded opportunities for untrusted final candidates, without authenticated authority.
use super::*;
use crate::handoff::pairing::packet::compact::{FinalKind, FinalMetadata};

fn selected_fixture(slots: u16) -> R<GateState> {
    let mut policy = PacketPolicy::new(576);
    policy.queue_packets = slots;
    let (mut state, _) = fixture_with_policy(policy)?;
    state.final_context = Some([7; 32]);
    Ok(state)
}

fn insert(state: &mut GateState, kind: FinalKind, number: u32) -> R {
    let route = match kind {
        FinalKind::CarrierControl => 1,
        FinalKind::Control => 0,
        FinalKind::Data => 0x80,
        FinalKind::Feedback => 0xc0,
    };
    state.ingest_final(&outer(
        &[route, 0, 0, 0, 0],
        2000 + number * 6,
        1000,
        32768,
    )?)?;
    Ok(())
}

fn selected_metadata(state: &mut GateState) -> R<(usize, FinalMetadata)> {
    let index = state.select_final_candidate()?.ok_or("candidate")?;
    let metadata = state.incoming[index].final_metadata.ok_or("metadata")?;
    Ok((index, metadata))
}

#[test]
fn mixed_candidate_shares_keep_exact_original_total_and_storage() -> R {
    for slots in [2, 3, 8, 64] {
        let mut state = selected_fixture(slots)?;
        let capacity = state.incoming.capacity();
        let upper = (usize::from(slots) / 2).min(4);
        let bulk = usize::from(slots) - upper;
        assert_eq!(state.final_upper_capacity(), upper);
        assert_eq!(state.final_bulk_capacity(), bulk);
        // A retained authenticated bootstrap record consumes the bulk allowance.
        state.records_outstanding = 1;
        let mut number = 0;
        for (kind, count) in [
            (FinalKind::Data, bulk - 1),
            (FinalKind::Control, upper),
            (FinalKind::CarrierControl, 4),
        ] {
            for _ in 0..count {
                insert(&mut state, kind, number)?;
                number += 1;
            }
        }
        assert_eq!(
            state.incoming.len() + state.records_outstanding,
            usize::from(slots) + 4
        );
        for kind in [
            FinalKind::Data,
            FinalKind::Feedback,
            FinalKind::Control,
            FinalKind::CarrierControl,
        ] {
            insert(&mut state, kind, number)?;
            number += 1;
        }
        assert_eq!(
            state.incoming.len() + state.records_outstanding,
            usize::from(slots) + 4
        );
        assert_eq!(state.rejected_packets, 4);
        assert_eq!(state.incoming.capacity(), capacity);
        assert_eq!(state.ranges.occupied_bytes(), 0);
    }
    Ok(())
}

#[test]
fn forged_kind_floods_leave_bounded_turns_for_each_other_class() -> R {
    let mut state = selected_fixture(64)?;
    let capacity = state.incoming.capacity();
    for number in 0..60 {
        insert(&mut state, FinalKind::Data, number)?;
    }
    for number in 60..64 {
        insert(&mut state, FinalKind::Control, number)?;
        insert(&mut state, FinalKind::CarrierControl, number + 4)?;
    }
    for turn in 0..30 {
        let (index, metadata) = selected_metadata(&mut state)?;
        let expected = match turn % 3 {
            0 => FinalKind::CarrierControl,
            1 => FinalKind::Control,
            _ => FinalKind::Data,
        };
        assert_eq!(metadata.kind(), expected);
        // Simulate a failed sole-verifier attempt: only the candidate is removed.
        state.consume_final_candidate(index)?;
        state.reject_final()?;
        insert(&mut state, expected, 100 + turn)?;
        assert_eq!(state.incoming.len(), 68);
        assert_eq!(state.incoming.capacity(), capacity);
        assert_eq!(state.ranges.occupied_bytes(), 0);
        let fence = state.fence.as_ref().ok_or("fence")?;
        assert_eq!((fence.retired, fence.peer_retired), (0, 0));
    }
    assert_eq!(state.rejected_packets, 30);
    Ok(())
}

#[test]
fn selected_candidate_stays_pinned_when_other_classes_arrive() -> R {
    let mut state = selected_fixture(8)?;
    insert(&mut state, FinalKind::Data, 0)?;
    let (index, selected) = selected_metadata(&mut state)?;
    insert(&mut state, FinalKind::Control, 1)?;
    insert(&mut state, FinalKind::CarrierControl, 2)?;
    assert_eq!(selected_metadata(&mut state)?, (index, selected));
    let later = state.incoming[1].final_metadata.ok_or("later metadata")?;
    assert!(matches!(
        state.selected_final_candidate(later),
        Err(Error::Proof)
    ));
    assert_eq!(state.selected_final_candidate(selected)?, index);
    state.consume_final_candidate(index)?;
    let (index, selected) = selected_metadata(&mut state)?;
    assert_eq!(selected.kind(), FinalKind::CarrierControl);
    state.consume_final_candidate(index)?;
    assert_eq!(selected_metadata(&mut state)?.1.kind(), FinalKind::Control);
    Ok(())
}

#[test]
fn capacity_one_keeps_a_shared_upper_and_bulk_slot() -> R {
    let mut state = selected_fixture(1)?;
    assert_eq!(state.final_upper_capacity(), 0);
    assert_eq!(state.final_bulk_capacity(), 1);
    insert(&mut state, FinalKind::Control, 0)?;
    insert(&mut state, FinalKind::Data, 1)?;
    assert_eq!(state.incoming.len(), 1);
    assert_eq!(state.rejected_packets, 1);
    let (index, metadata) = selected_metadata(&mut state)?;
    assert_eq!(metadata.kind(), FinalKind::Control);
    state.consume_final_candidate(index)?;
    insert(&mut state, FinalKind::Data, 1)?;
    insert(&mut state, FinalKind::Control, 2)?;
    assert_eq!(state.incoming.len(), 1);
    assert_eq!(state.rejected_packets, 2);
    assert_eq!(selected_metadata(&mut state)?.1.kind(), FinalKind::Data);
    Ok(())
}
