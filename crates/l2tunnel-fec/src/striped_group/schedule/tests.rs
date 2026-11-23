mod residual_rank;

use super::*;
use crate::{ChannelId, Direction, Epoch, SessionId, striped_group::Sender};

const PROFILE: Profile = Profile {
    data_cells: 3,
    parity_cells: 1,
    max_wire_bytes: 100,
    max_body_bytes: 100,
};
const TIMING: RecoveryTiming = RecoveryTiming {
    gap_delay: 2,
    gap_repeat: 8,
    ack_delay: 1,
    quiet: 12,
};
const START: GenerationId = GenerationId(u32::MAX as u64 + 7);
const OUTER: usize = 49;

fn context(direction: Direction) -> FecContext {
    FecContext {
        direction,
        session: SessionId([42; 16]),
        epoch: Epoch(9),
        channel: ChannelId(1),
    }
}

fn take(tx: &mut ScheduledSender, now: u64) -> Result<(DataToken, Vec<u8>), Error> {
    tx.prepare_data(now)?
        .map(|(key, bytes)| (key, bytes.to_vec()))
        .ok_or(Error::Unsealed)
}

#[test]
fn quote_prices_pending_and_future_ack_and_gap_without_advancing_the_scan() -> Result<(), Error> {
    let ctx = context(Direction::ServerToClient);
    let first = GenerationId(3);
    let timing = RecoveryTiming {
        ack_delay: 6,
        ..TIMING
    };
    let mut tx = Sender::new(PROFILE, 1, first, 0)?;
    for value in 0..4 {
        tx.submit(0, &[value])?;
    }
    let group = tx.poll_group(0)?.ok_or(Error::Unsealed)?;
    let mut scratch = [0; 100];
    let mut wire = [0; 100];
    let mut gap = ScheduledReceiver::new(PROFILE, ctx, first, 0, 8, 800, timing)?;
    let mut all = ScheduledReceiver::new(PROFILE, ctx, first, 0, 8, 800, timing)?;
    assert_eq!(all.feedback_opportunity()?, None);
    for i in 0..4 {
        let n = group.write_packet(i, &mut wire)?;
        all.accept_authenticated(1, ctx, &wire[..n], &mut scratch)?;
        all.commit_original(1, GenerationId(first.0 + u64::from(i)))?;
        if i == 0 || i == 2 {
            gap.accept_authenticated(1, ctx, &wire[..n], &mut scratch)?;
            gap.commit_original(1, GenerationId(first.0 + u64::from(i)))?;
        }
    }
    for _ in 0..2 {
        assert_eq!(gap.feedback_opportunity()?, Some((3, 5)));
        assert_eq!(all.feedback_opportunity()?, Some((7, 3)));
        assert_eq!(all.next_wake(), Some(3));
    }
    assert!(gap.prepare_feedback(2)?.is_none());
    let message = gap.prepare_feedback(3)?.ok_or(Error::Unsealed)?;
    assert_eq!(message.missing(), Some(Missing::new(GenerationId(4), 5)?));
    let mut encoded = [0; 5];
    assert_eq!(message.encode(&mut encoded)?, 5);
    let n = group.write_packet(1, &mut wire)?;
    gap.accept_authenticated(4, ctx, &wire[..n], &mut scratch)?;
    assert_eq!(gap.feedback_opportunity()?, Some((4, 5)));
    assert_eq!(gap.prepare_feedback(4)?, Some(message));
    assert_eq!(gap.stats(), Paid::default());
    assert!(all.prepare_feedback(3)?.is_none());
    assert_eq!(all.feedback_opportunity()?, Some((7, 3)));
    assert!(all.prepare_feedback(6)?.is_none());
    assert_eq!(
        all.prepare_feedback(7)?.ok_or(Error::Unsealed)?.wire_len(),
        3
    );
    Ok(())
}

#[test]
fn read_only_quote_never_skips_an_empty_local_scan_page() -> Result<(), Error> {
    let ctx = context(Direction::ClientToServer);
    let mut rx = ScheduledReceiver::new(PROFILE, ctx, START, 0, 128, 24_000, TIMING)?;
    let mut wire = [0; 100];
    let mut scratch = [0; 100];
    for offset in (0..64).chain(std::iter::once(66)) {
        let mut tx = Sender::new(PROFILE, 1, GenerationId(START.0 + offset), 0)?;
        tx.submit(0, &[offset as u8])?;
        let group = tx.poll_group(1)?.ok_or(Error::Unsealed)?;
        let n = group.write_packet(0, &mut wire)?;
        rx.accept_authenticated(1, ctx, &wire[..n], &mut scratch)?;
    }
    assert_eq!(rx.feedback_opportunity()?, None);
    assert_eq!(rx.feedback_opportunity()?, None);
    assert_eq!(rx.next_wake(), Some(3));
    assert!(rx.prepare_feedback(3)?.is_none());
    let expected = Feedback::new(
        ctx,
        FeedbackId(1),
        None,
        Some(Missing::new(GenerationId(START.0 + 64), 3)?),
    )?;
    assert_eq!(rx.feedback_opportunity()?, Some((3, expected.wire_len())));
    assert_eq!(rx.prepare_feedback(3)?, Some(expected));
    Ok(())
}

#[test]
fn narrow_carrier_alternates_a_distant_named_retry_with_the_quiet_frontier() -> Result<(), Error> {
    let ctx = context(Direction::ClientToServer);
    let mut tx = ScheduledSender::new(PROFILE, ctx, START, 1, 0, 8, TIMING)?;
    for i in 0..4 {
        tx.submit(0, &[i])?;
    }
    for _ in 0..4 {
        let (token, bytes) = take(&mut tx, 0)?;
        tx.confirm_data(0, token, bytes.len() + OUTER)?;
    }
    let distant = GenerationId(START.0 + 2);
    let missing = Missing::new(distant, 1)?;
    tx.receive_feedback(1, Feedback::new(ctx, FeedbackId(1), None, Some(missing))?)?;
    let (quiet, bytes) = take(&mut tx, TIMING.quiet)?;
    assert_eq!(quiet.kind(), DataKind::Quiet(START));
    tx.confirm_data(TIMING.quiet, quiet, bytes.len() + OUTER)?;
    // The next actual write can be late enough for quiet to be due again.
    let (named, bytes) = take(&mut tx, TIMING.quiet * 3)?;
    assert_eq!(named.kind(), DataKind::Named(distant));
    tx.confirm_data(TIMING.quiet * 3, named, bytes.len() + OUTER)?;
    assert_eq!(
        take(&mut tx, TIMING.quiet * 4)?.0.kind(),
        DataKind::Quiet(START)
    );
    Ok(())
}

#[test]
fn fresh_holes_get_their_own_delay_while_older_paid_requests_wait_to_repeat() -> Result<(), Error> {
    let ctx = context(Direction::ClientToServer);
    let mut rx = ScheduledReceiver::new(PROFILE, ctx, START, 0, 16, 2400, TIMING)?;
    let receive = |rx: &mut ScheduledReceiver, now, offset| -> Result<(), Error> {
        let id = GenerationId(START.0 + offset);
        let mut sender = Sender::new(PROFILE, 1, id, 0)?;
        sender.submit(0, b"new seal")?;
        let group = sender.poll_group(1)?.ok_or(Error::Unsealed)?;
        let mut wire = [0; 100];
        let n = group.write_packet(0, &mut wire)?;
        rx.accept_authenticated(now, ctx, &wire[..n], &mut [0; 100])?;
        rx.commit_original(now, id)?;
        Ok(())
    };
    receive(&mut rx, 1, 1)?;
    let old = rx.prepare_feedback(3)?.ok_or(Error::Unsealed)?;
    assert_eq!(old.missing(), Some(Missing::new(START, 1)?));
    // A new hole becomes visible while this first request is held by the carrier.
    receive(&mut rx, 4, 3)?;
    assert_eq!(rx.prepare_feedback(6)?, Some(old));
    rx.confirm_feedback(6, old, old.wire_len() + OUTER)?;
    let new = rx.prepare_feedback(6)?.ok_or(Error::Unsealed)?;
    assert_eq!(
        new.missing(),
        Some(Missing::new(GenerationId(START.0 + 2), 1)?)
    );
    rx.confirm_feedback(7, new, new.wire_len() + OUTER)?;
    assert!(rx.prepare_feedback(13)?.is_none());
    let repeat = rx.prepare_feedback(14)?.ok_or(Error::Unsealed)?;
    assert_eq!(repeat.missing(), old.missing());
    rx.confirm_feedback(14, repeat, repeat.wire_len() + OUTER)?;
    let newer_repeat = rx.prepare_feedback(15)?.ok_or(Error::Unsealed)?;
    assert_eq!(newer_repeat.missing(), new.missing());
    // Resolve the newer source before its prepared retry actually leaves.
    receive(&mut rx, 16, 2)?;
    rx.confirm_feedback(16, newer_repeat, newer_repeat.wire_len() + OUTER)?;
    receive(&mut rx, 17, 0)?;
    for now in [18, 26] {
        let ack = rx.prepare_feedback(now)?.ok_or(Error::Unsealed)?;
        assert_eq!(ack.missing(), None);
        rx.confirm_feedback(now, ack, ack.wire_len() + OUTER)?;
    }
    assert_eq!(rx.next_wake(), None);
    Ok(())
}

#[test]
fn authenticated_gap_and_local_recovery_drain_earlier_loss_in_both_directions()
-> Result<(), Box<dyn std::error::Error>> {
    for direction in [Direction::ClientToServer, Direction::ServerToClient] {
        let ctx = context(direction);
        let mut tx = if direction == Direction::ClientToServer {
            ScheduledSender::new(PROFILE, ctx, START, 1, 0, 8, TIMING)?
        } else {
            let plan = crate::striped_group::TransmitPlan::for_window(PROFILE, 8)?;
            let limits = crate::storage::Limits {
                capacity_bytes: plan.capacity_bytes(),
            };
            let tx = ScheduledSender::new_reserved_custody(plan, limits, ctx, START, 1, 0, TIMING)?;
            assert_eq!(
                tx.custody_storage_usage().map(|u| u.capacity_bytes),
                Some(plan.capacity_bytes())
            );
            tx
        };
        let mut rx = ScheduledReceiver::new(PROFILE, ctx, START, 0, 8, 800, TIMING)?;
        let mut scratch = [0; 100];
        let mut paid = 0;
        for group in 0..2 {
            for ordinal in 0..4 {
                let index = group * 4 + ordinal;
                assert_eq!(
                    tx.submit(0, &[index])?,
                    GenerationId(START.0 + u64::from(index))
                );
            }
            for ordinal in 0..4 {
                let (token, wire) = take(&mut tx, 0)?;
                assert!(matches!(token.kind(), DataKind::Fresh(_)));
                assert_eq!(take(&mut tx, 0)?, (token, wire.clone()));
                assert_eq!(tx.next_wake(), None);
                assert_eq!(
                    tx.confirm_data(0, token, wire.len() - 1),
                    Err(Error::Conflict)
                );
                let ip = wire.len() + OUTER;
                tx.confirm_data(0, token, ip)?;
                paid += ip;
                if !matches!((group, ordinal), (0, 0 | 1) | (1, 3)) {
                    rx.accept_authenticated(1, ctx, &wire, &mut scratch)?;
                }
            }
        }
        assert_eq!(
            tx.stats().fresh,
            Paid {
                packets: 8,
                ip_bytes: paid as u64
            }
        );
        assert_eq!(rx.poll_recovery(2)?, None);
        assert_eq!(rx.poll_recovery(3)?, Some((GenerationId(START.0 + 4), 1)));
        for index in 2..8u8 {
            let id = GenerationId(START.0 + u64::from(index));
            assert_eq!(rx.window().pending_original(id)?, Some([index].as_slice()));
            rx.commit_original(3, id)?;
        }
        assert_eq!(rx.window().confirmed_through(), None);
        let request = rx.prepare_feedback(3)?.ok_or(Error::Unsealed)?;
        assert_eq!(request.missing(), Some(Missing::new(START, 3)?));
        assert_eq!(rx.prepare_feedback(4)?, Some(request));
        assert_eq!(rx.stats(), Paid::default());
        let bogus = Feedback::new(
            ctx,
            request.id(),
            None,
            Some(Missing::new(GenerationId(START.0 + 8), 1)?),
        )?;
        assert_eq!(tx.receive_feedback(4, bogus), Err(Error::UnknownGeneration));
        let wrong = Feedback::new(
            FecContext {
                epoch: Epoch(10),
                ..ctx
            },
            request.id(),
            None,
            request.missing(),
        )?;
        assert_eq!(tx.receive_feedback(4, wrong), Err(Error::ContextMismatch));
        rx.confirm_feedback(4, request, request.wire_len() + OUTER)?;
        assert!(tx.receive_feedback(4, request)?);
        assert!(!tx.receive_feedback(4, request)?);
        let (first, wire) = take(&mut tx, 4)?;
        assert_eq!(first.kind(), DataKind::Named(START));
        tx.confirm_data(4, first, wire.len() + OUTER)?;
        rx.accept_authenticated(5, ctx, &wire, &mut scratch)?;
        assert_eq!(rx.poll_recovery(5)?, Some((START, 1)));
        for index in 0..2u8 {
            let id = GenerationId(START.0 + u64::from(index));
            assert_eq!(rx.window().pending_original(id)?, Some([index].as_slice()));
            rx.commit_original(5, id)?;
        }
        // A retry sealed before acknowledgement remains payable even after
        // its transmit group's custody has been released by incoming feedback.
        let (blocked, bytes) = take(&mut tx, 5)?;
        let ack = rx.prepare_feedback(6)?.ok_or(Error::Unsealed)?;
        assert_eq!(ack.confirmed_through(), Some(GenerationId(START.0 + 7)));
        rx.confirm_feedback(6, ack, ack.wire_len() + OUTER)?;
        tx.receive_feedback(6, ack)?;
        assert_eq!(tx.retained(), 0);
        assert_eq!(take(&mut tx, 7)?, (blocked, bytes.clone()));
        tx.confirm_data(7, blocked, bytes.len() + OUTER)?;
        assert_eq!(tx.stats().named.packets, 2);
        assert_eq!(tx.next_wake(), None);
    }
    Ok(())
}

#[test]
fn lost_singleton_and_both_cumulative_transmissions_recover_from_a_quiet_original()
-> Result<(), Error> {
    let ctx = context(Direction::ServerToClient);
    let max = GenerationId(u64::MAX);
    let mut tx = ScheduledSender::new(PROFILE, ctx, max, 2, 0, 1, TIMING)?;
    let mut rx = ScheduledReceiver::new(PROFILE, ctx, max, 0, 1, 300, TIMING)?;
    let mut scratch = [0; 100];
    tx.submit(0, b"tail")?;
    assert_eq!(tx.next_wake(), Some(2));
    assert!(tx.prepare_data(1)?.is_none());
    for sent in [2, 5] {
        let (key, bytes) = take(&mut tx, sent)?;
        tx.confirm_data(sent, key, OUTER + bytes.len())?;
    }
    assert_eq!(tx.next_wake(), Some(17));
    let (key, bytes) = take(&mut tx, 17)?;
    assert_eq!(key.kind(), DataKind::Quiet(max));
    assert_eq!(take(&mut tx, 23)?, (key, bytes.clone()));
    tx.confirm_data(23, key, bytes.len() + OUTER)?;
    assert_eq!(tx.next_wake(), Some(35));
    rx.accept_authenticated(23, ctx, &bytes, &mut scratch)?;
    assert_eq!(rx.window().pending_original(max)?, Some(b"tail".as_slice()));
    rx.commit_original(23, max)?;
    for lost in [24, 32] {
        let feedback = rx.prepare_feedback(lost)?.ok_or(Error::Unsealed)?;
        assert_eq!(feedback.confirmed_through(), Some(max));
        assert_eq!(feedback.missing(), None);
        rx.confirm_feedback(lost, feedback, feedback.wire_len() + OUTER)?;
    }
    assert_eq!(rx.next_wake(), None);
    let (key, bytes) = take(&mut tx, 35)?;
    tx.confirm_data(35, key, bytes.len() + OUTER)?;
    assert_eq!(
        rx.accept_authenticated(36, ctx, &bytes, &mut scratch)?,
        ReceiveAdmission::Retired
    );
    assert!(!rx.commit_original(36, max)?);
    let final_ack = rx.prepare_feedback(37)?.ok_or(Error::Unsealed)?;
    let count = final_ack.wire_len() + OUTER;
    rx.confirm_feedback(37, final_ack, count)?;
    assert!(tx.receive_feedback(38, final_ack)?);
    assert_eq!(tx.confirmed_through(), Some(max));
    assert_eq!(tx.retained(), 0);
    assert_eq!(tx.stats().quiet.packets, 2);
    assert_eq!(rx.stats().packets, 3);
    assert_eq!(tx.next_wake(), None);
    Ok(())
}

#[test]
fn a_bounded_scan_names_all_long_lived_gaps_and_then_revisits_the_oldest() -> Result<(), Error> {
    let ctx = context(Direction::ClientToServer);
    let mut rx = ScheduledReceiver::new(PROFILE, ctx, START, 0, 160, 800, TIMING)?;
    let later = GenerationId(START.0 + 150);
    let mut remote = Sender::new(PROFILE, 1, later, 0)?;
    remote.submit(0, b"arrived independently")?;
    let group = remote.poll_group(1)?.ok_or(Error::Unsealed)?;
    let mut bytes = [0; 100];
    let n = group.write_packet(0, &mut bytes)?;
    rx.accept_authenticated(1, ctx, &bytes[..n], &mut [0; 100])?;
    rx.commit_original(1, later)?;
    for (tick, offset, mask) in [
        (3, 0, u64::MAX),
        (5, 64, u64::MAX),
        (7, 128, (1 << 22) - 1),
        (15, 0, u64::MAX),
    ] {
        let feedback = rx.prepare_feedback(tick)?.ok_or(Error::Unsealed)?;
        assert_eq!(
            feedback.missing(),
            Some(Missing::new(GenerationId(START.0 + offset), mask)?)
        );
        assert_eq!(feedback.confirmed_through(), None);
        rx.confirm_feedback(tick, feedback, feedback.wire_len() + OUTER)?;
    }
    Ok(())
}
