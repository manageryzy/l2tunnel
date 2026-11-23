use super::*;
use crate::{ChannelId, Direction, Epoch, FecContext, SessionId, striped::Admission};

const PROFILE: Profile = Profile {
    data_cells: 8,
    parity_cells: 2,
    max_body_bytes: 1450,
    max_wire_bytes: 1450,
};
const CONTEXT: FecContext = FecContext {
    session: SessionId([3; 16]),
    epoch: Epoch(42),
    channel: ChannelId(1),
    direction: Direction::ClientToServer,
};
fn wire(group: &SealedGroup, index: u8) -> Result<Vec<u8>, Error> {
    let mut bytes = vec![0; PROFILE.max_wire_bytes];
    let used = group.write_packet(index, &mut bytes)?;
    bytes.truncate(used);
    Ok(bytes)
}

#[test]
fn seals_full_or_on_first_deadline_and_keeps_drain_ids_without_wrap() -> Result<(), Error> {
    let mut sender = Sender::new(PROFILE, 10, GenerationId(u64::MAX - 12), 0)?;
    for offset in 0..10 {
        assert_eq!(
            sender.submit(offset, &[offset as u8]),
            Ok(GenerationId(u64::MAX - 12 + offset))
        );
    }
    assert_eq!(sender.next_wake(), Some(9));
    assert_eq!(sender.submit(9, b"full"), Err(Error::Capacity));
    let full = sender.poll_group(9)?.ok_or(Error::Unsealed)?;
    assert_eq!(
        (full.shape(), full.geometry().data_cells()),
        (GroupShape::Originals(10), 8)
    );
    assert_ne!(wire(&full, 0)?, wire(&full, 1)?);
    sender.submit(20, b"x")?;
    sender.submit(27, b"y")?;
    assert_eq!(sender.next_wake(), Some(30));
    assert!(sender.poll_group(29)?.is_none());
    assert_eq!(sender.submit(30, b"due"), Err(Error::Capacity));
    let short = sender.poll_group(30)?.ok_or(Error::Unsealed)?;
    assert_eq!(
        (
            short.shape(),
            short.generation(),
            short.geometry().data_cells()
        ),
        (GroupShape::Originals(2), GenerationId(u64::MAX - 2), 1)
    );
    assert_eq!(sender.submit(29, b"x"), Err(Error::TimeBackwards));
    assert_eq!(sender.submit(30, b"z"), Ok(GenerationId(u64::MAX)));
    assert_eq!(sender.submit(30, b"z"), Err(Error::SymbolExhausted));
    let final_group = sender.poll_group(40)?.ok_or(Error::Unsealed)?;
    assert_eq!(final_group.generation(), GenerationId(u64::MAX));
    assert_eq!(sender.next_wake(), None);
    assert_eq!(sender.formation.full_groups, 1);
    assert_eq!(sender.formation.short_groups, 1);
    assert_eq!(sender.formation.lone_splits, 1);
    assert_eq!(sender.formation.batches, 3);
    Ok(())
}

#[test]
fn short_batch_splits_only_the_oversize_source_and_drains_at_its_original_deadline()
-> Result<(), Error> {
    let mut sender = Sender::new(PROFILE, 2, GenerationId(127), 0)?;
    let bound = sender.max_original();
    assert!(bound > 1000);
    assert_eq!(
        sender.submit(0, &vec![42; bound + 1]),
        Err(Error::PacketTooLarge)
    );
    let mut scratch = vec![0; PROFILE.max_body_bytes];
    let originals = [vec![14; bound], vec![18; 9], vec![20; 6]];
    for source in &originals {
        sender.submit(0, source)?;
    }
    assert!(
        originals[0].len() > PROFILE.original_limit(GroupShape::Originals(3), GenerationId(127))?
    );
    assert!(
        originals[1].len() < PROFILE.original_limit(GroupShape::Originals(2), GenerationId(128))?
    );
    assert_eq!(sender.submit(2, b"held"), Err(Error::Capacity));
    let split = sender.poll_group(2)?.ok_or(Error::Unsealed)?;
    assert_eq!(split.generation(), GenerationId(127));
    assert_eq!(split.shape(), GroupShape::Split(bound as u16));
    let mut received =
        ReceiveGroup::open_authenticated(PROFILE, CONTEXT, &wire(&split, 1)?, &mut scratch)?;
    assert_eq!(
        received.pending_original(GenerationId(127))?,
        Some(originals[0].as_slice())
    );
    assert!(received.commit_original(GenerationId(127))?);
    assert_eq!(
        received.accept_authenticated(CONTEXT, &wire(&split, 0)?, &mut scratch)?,
        Admission::Accepted
    );
    assert_eq!(sender.next_wake(), Some(2));
    assert_eq!(sender.submit(2, b"still frozen"), Err(Error::Capacity));
    let pair = sender.poll_group(2)?.ok_or(Error::Unsealed)?;
    assert_eq!(pair.generation(), GenerationId(128));
    assert_eq!(pair.shape(), GroupShape::Originals(2));
    let mut received =
        ReceiveGroup::open_authenticated(PROFILE, CONTEXT, &wire(&pair, 1)?, &mut scratch)?;
    assert_eq!(received.recover_missing()?, 1);
    for (offset, source) in originals[1..].iter().enumerate() {
        let id = GenerationId(128 + offset as u64);
        assert_eq!(received.pending_original(id)?, Some(source.as_slice()));
        assert!(received.commit_original(id)?);
    }
    assert!(sender.poll_group(2)?.is_none());
    assert_eq!(sender.formation.mtu_splits, 1);
    assert_eq!(sender.formation.short_groups, 1);
    assert_eq!(sender.formation.batches, 1);
    assert_eq!(sender.formation.hold_ticks, 2);
    assert_eq!(
        sender.submit(u64::MAX, b"no deadline"),
        Err(Error::DeadlineOverflow)
    );
    Ok(())
}

#[test]
fn singleton_duplicate_byte_is_delivered_once_and_conflicts_do_not_mutate() -> Result<(), Error> {
    let mut sender = Sender::new(PROFILE, 4, GenerationId(3), 0)?;
    let id = sender.submit(2, b"X")?;
    let group = sender.poll_group(6)?.ok_or(Error::Unsealed)?;
    let mut scratch = vec![0; PROFILE.max_body_bytes];
    for first in [0, 1] {
        let first_wire = wire(&group, first)?;
        let mut malformed = first_wire.clone();
        *malformed.last_mut().ok_or(Error::Malformed)? ^= 1;
        assert!(matches!(
            ReceiveGroup::open_authenticated(PROFILE, CONTEXT, &malformed, &mut scratch),
            Err(Error::Conflict)
        ));
        let mut received =
            ReceiveGroup::open_authenticated(PROFILE, CONTEXT, &first_wire, &mut scratch)?;
        assert!(received.can_recover());
        assert_eq!(received.pending_original(id)?, Some(b"X".as_slice()));
        let mut wrong = CONTEXT;
        wrong.epoch = Epoch(4);
        assert_eq!(
            received.accept_authenticated(wrong, &first_wire, &mut scratch),
            Err(Error::ContextMismatch)
        );
        assert_eq!(
            received.accept_authenticated(CONTEXT, &malformed, &mut scratch),
            Err(Error::Conflict)
        );
        assert_eq!(
            received.accept_authenticated(CONTEXT, &first_wire, &mut scratch),
            Ok(Admission::Duplicate)
        );
        assert!(received.commit_original(id)?);
        assert!(!received.commit_original(id)?);
        assert_eq!(
            received.accept_authenticated(CONTEXT, &wire(&group, 1 - first)?, &mut scratch),
            Ok(Admission::Accepted)
        );
        assert_eq!(received.pending_original(id)?, None);
    }
    Ok(())
}

#[test]
fn old_missing_inputs_after_excess_loss_do_not_hold_a_later_group() -> Result<(), Error> {
    let mut sender = Sender::new(PROFILE, 1, GenerationId(100), 0)?;
    let mut scratch = vec![0; PROFILE.max_body_bytes];
    for i in 0..10 {
        sender.submit(0, &[i; 12])?;
    }
    let old = sender.poll_group(0)?.ok_or(Error::Unsealed)?;
    let mut old_rx =
        ReceiveGroup::open_authenticated(PROFILE, CONTEXT, &wire(&old, 9)?, &mut scratch)?;
    for i in 0..6 {
        old_rx.accept_authenticated(CONTEXT, &wire(&old, i)?, &mut scratch)?;
    }
    assert_eq!(old_rx.recover_missing(), Err(Error::InsufficientRank));
    assert_eq!(old_rx.pending_original(GenerationId(106))?, None);
    assert!(old_rx.commit_original(GenerationId(109))?);
    for i in 0..10 {
        sender.submit(1, &[i; 8])?;
    }
    let new = sender.poll_group(1)?.ok_or(Error::Unsealed)?;
    let mut new_rx =
        ReceiveGroup::open_authenticated(PROFILE, CONTEXT, &wire(&new, 0)?, &mut scratch)?;
    for i in 0..10 {
        if i > 0 {
            new_rx.accept_authenticated(CONTEXT, &wire(&new, i)?, &mut scratch)?;
        }
        assert!(new_rx.commit_original(GenerationId(110 + u64::from(i)))?);
    }
    assert_eq!(
        old_rx.accept_authenticated(CONTEXT, &wire(&old, 7)?, &mut scratch),
        Ok(Admission::Accepted)
    );
    assert_eq!(old_rx.pending_original(GenerationId(106))?, None);
    assert_eq!(old_rx.recover_missing(), Ok(2));
    for i in [6, 8] {
        let id = GenerationId(100 + i);
        assert_eq!(old_rx.pending_original(id)?, Some([i as u8; 12].as_slice()));
        assert!(old_rx.commit_original(id)?);
    }
    Ok(())
}
