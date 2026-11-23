use super::*;
use crate::striped_group::SealedGroup;

const EXPERIMENT: Profile = Profile {
    data_cells: 10,
    parity_cells: 2,
    ..PROFILE
};

fn group(profile: Profile, base: GenerationId, count: u8) -> Result<SealedGroup, Error> {
    let mut tx = Sender::new(profile, 1, base, 0)?;
    for i in 0..count {
        tx.submit(0, &[i])?;
    }
    tx.poll_group(1)?.ok_or(Error::Unsealed)
}

fn accept(rx: &mut ScheduledReceiver, tick: u64, group: &SealedGroup, i: u8) -> Result<(), Error> {
    let mut wire = [0; 100];
    let used = group.write_packet(i, &mut wire)?;
    rx.accept_authenticated(tick, rx.context, &wire[..used], &mut [0; 100])?;
    Ok(())
}

fn paid_names(rx: &mut ScheduledReceiver, tick: u64) -> Result<Vec<u64>, Error> {
    let msg = rx.prepare_feedback(tick)?.ok_or(Error::Unsealed)?;
    let names = msg.missing().ok_or(Error::Unsealed)?;
    rx.confirm_feedback(tick, msg, OUTER + msg.wire_len())?;
    Ok(names.ids().map(|id| id.0 - START.0).collect())
}

fn receiver(profile: Profile) -> Result<ScheduledReceiver, Error> {
    ScheduledReceiver::new(
        profile,
        context(Direction::ClientToServer),
        START,
        0,
        128,
        24_000,
        TIMING,
    )
}

#[test]
fn residual_rank_rechecks_reordered_members_and_a_lost_paid_request() -> Result<(), Error> {
    let block = group(EXPERIMENT, START, 12)?;
    let mut rx = receiver(EXPERIMENT)?;
    for i in [0, 2, 3, 5, 6, 7, 8, 10] {
        accept(&mut rx, 1, &block, i)?;
    }
    let ready = GenerationId(START.0 + 8);
    assert_eq!(rx.window().pending_original(ready)?, Some([8].as_slice()));
    assert!(rx.commit_original(1, ready)?);
    assert_eq!(rx.window().confirmed_through(), None);
    let msg = rx.prepare_feedback(3)?.ok_or(Error::Unsealed)?;
    assert_eq!(
        msg.missing(),
        Some(Missing::new(GenerationId(START.0 + 1), 0b1001)?)
    );
    accept(&mut rx, 4, &block, 9)?;
    accept(&mut rx, 4, &block, 9)?; // A duplicate contributes no rank.
    assert_eq!(rx.prepare_feedback(4)?, Some(msg));
    rx.confirm_feedback(4, msg, OUTER + msg.wire_len())?; // Lost reverse datagram.
    assert_eq!(paid_names(&mut rx, 12)?, vec![1]);
    assert_eq!(paid_names(&mut rx, 20)?, vec![1]); // Lost forward named response.
    accept(&mut rx, 21, &block, 1)?;
    assert_eq!(rx.poll_recovery(21)?, Some((START, 2)));
    for i in [4, 11] {
        assert_eq!(
            rx.window().pending_original(GenerationId(START.0 + i))?,
            Some([i as u8].as_slice())
        );
    }
    assert!(rx.prepare_feedback(28)?.is_none());
    Ok(())
}

#[test]
fn wholly_erased_group_remains_requestable_until_authenticated_shape_arrives() -> Result<(), Error>
{
    let gap = group(EXPERIMENT, START, 12)?;
    let later = group(EXPERIMENT, GenerationId(START.0 + 12), 1)?;
    let mut rx = receiver(EXPERIMENT)?;
    accept(&mut rx, 1, &later, 1)?;
    assert!(rx.commit_original(1, GenerationId(START.0 + 12))?);
    assert_eq!(paid_names(&mut rx, 3)?, (0..12).collect::<Vec<_>>());
    assert_eq!(paid_names(&mut rx, 11)?, (0..12).collect::<Vec<_>>());
    accept(&mut rx, 12, &gap, 11)?;
    assert_eq!(paid_names(&mut rx, 19)?, (0..9).collect::<Vec<_>>());
    for i in 0..9 {
        accept(&mut rx, 20, &gap, i)?;
    }
    assert_eq!(rx.poll_recovery(20)?, Some((START, 2)));
    for i in 0..12 {
        let id = GenerationId(START.0 + i);
        assert_eq!(
            rx.window().pending_original(id)?,
            Some([i as u8].as_slice())
        );
        assert!(rx.commit_original(20, id)?);
    }
    assert_eq!(
        rx.window().confirmed_through(),
        Some(GenerationId(START.0 + 12))
    );
    Ok(())
}

#[test]
fn shortened_geometry_across_feedback_pages_preserves_one_rank_budget() -> Result<(), Error> {
    let base = GenerationId(START.0 + 62);
    let short = group(EXPERIMENT, base, 7)?;
    assert_eq!(short.geometry().data_cells(), 5);
    let mut rx = receiver(EXPERIMENT)?;
    accept(&mut rx, 1, &short, 5)?;
    accept(&mut rx, 1, &short, 6)?;
    assert_eq!(paid_names(&mut rx, 3)?, (0..64).collect::<Vec<_>>());
    assert_eq!(paid_names(&mut rx, 5)?, vec![64]);
    for i in [0, 1, 2] {
        accept(&mut rx, 6, &short, i)?;
    }
    assert_eq!(rx.poll_recovery(6)?, Some((base, 2)));
    let old = Profile {
        data_cells: 4,
        parity_cells: 1,
        ..PROFILE
    };
    let mut baseline = receiver(old)?;
    let block = group(old, START, 5)?;
    for i in [0, 2, 4] {
        accept(&mut baseline, 1, &block, i)?;
    }
    assert_eq!(paid_names(&mut baseline, 3)?, vec![1, 3]);
    Ok(())
}
