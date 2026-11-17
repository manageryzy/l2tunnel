//! Actual raw owner receive fairness; record authentication remains unchanged.
use super::*;
use std::task::Poll;

async fn poll_raw_once(socket: &mut RawIo, receive: bool) -> Result {
    socket.begin_turn();
    poll_raw_current_turn(socket, receive).await
}

async fn poll_raw_current_turn(socket: &mut RawIo, receive: bool) -> Result {
    let raw = socket.final_raw_mut().ok_or("actual raw owner")?;
    poll_fn(|cx| {
        Poll::Ready(match raw.poll_ready(cx, receive) {
            Poll::Ready(Err(error)) => Err(error),
            Poll::Ready(Ok(())) | Poll::Pending => Ok(()),
        })
    })
    .await?;
    Ok(())
}

fn stage_candidate(pair: &mut SelectedRuntimePair, management: bool, value: u8) -> Result {
    let (kind, raw_kind, scope) = if management {
        (
            record::compact::Kind::Control,
            raw_compact::FinalKind::Control,
            pair.ad.records.control_scope(),
        )
    } else {
        (
            record::compact::Kind::Data,
            raw_compact::FinalKind::Data,
            pair.ad.records.active_data(),
        )
    };
    // The fixture targets raw candidate scheduling, not an algorithm decoder or
    // management semantic dispatcher. Both bodies use the actual Records owner.
    let body = [value; 8];
    let capacity = pair.ad.records.capacity_for(kind, body.len())?;
    let metadata = pair
        .a
        .final_raw_mut()
        .ok_or("actual sender")?
        .prepare_final(raw_kind, capacity.packet_bytes)?
        .ok_or("actual lane reservation")?;
    let mut workspace = [0; 1500];
    let mut wire = [0; 1500];
    let sealed = pair.ad.records.seal_compact_with_carrier(
        kind,
        scope,
        meta(0, cover::Phase::Established),
        &body,
        &metadata.aad(),
        &mut workspace,
        &mut wire,
    )?;
    let deadline = pair.ad.origin + duration(pair.ad.lease);
    let raw = pair.a.final_raw_mut().ok_or("actual sender")?;
    let progress = if management {
        raw.stage_control(&wire[..sealed.bytes], sealed.bytes + 40, deadline, false)?
    } else {
        raw.try_user(
            raw_carrier::UserIdentity {
                scope,
                number: sealed.number,
                bytes: sealed.bytes,
                deadline,
            },
            &wire[..sealed.bytes],
        )?
    };
    assert!(matches!(progress, raw_carrier::SendProgress::Pending));
    Ok(())
}

async fn flush_candidates(pair: &mut SelectedRuntimePair, management: bool) -> Result {
    poll_raw_once(&mut pair.a, false).await?;
    assert!(pair.a.take_user()?.is_some());
    assert_eq!(pair.a.take_control()?.is_some(), management);
    Ok(())
}

async fn accept_candidate(pair: &mut SelectedRuntimePair, lane: u8, value: u8) -> Result {
    let mut wire = [0; 1500];
    let (bytes, arrived, _) = pair.b.try_receive_at_ready(&mut wire).await?;
    let metadata = pair.b.final_input_metadata().ok_or("pinned candidate")?;
    assert_eq!(metadata.aad()[32], lane);
    assert!(arrived.is_some());
    // Re-reading a pinned candidate neither changes its identity nor advances
    // the lane cursor before this sole verifier's result is consumed.
    let mut repeated = [0; 1500];
    assert_eq!(pair.b.try_receive_at_ready(&mut repeated).await?.0, bytes);
    assert_eq!(&wire[..bytes], &repeated[..bytes]);
    assert_eq!(pair.b.final_input_metadata(), Some(metadata));
    let mut workspace = [0; 1500];
    let mut plain = [0; 1500];
    let opened = pair.bd.records.open_compact_with_carrier(
        &wire[..bytes],
        &metadata.aad(),
        &mut workspace,
        &mut plain,
    )?;
    assert!(opened.authenticated);
    assert_eq!(&plain[..opened.bytes], &[value; 8]);
    pair.b.commit_final_input(
        metadata,
        Some(raw_compact::FinalAcceptance::record(
            (),
            opened.authenticated,
        )),
    )?;
    Ok(())
}

fn receive_calls(pair: &SelectedRuntimePair) -> [usize; 2] {
    [
        pair.probes[1].receive_calls.load(Ordering::Relaxed),
        pair.probes[3].receive_calls.load(Ordering::Relaxed),
    ]
}

#[tokio::test]
async fn half_raw_drains_both_received_lanes_and_rotates_under_first_lane_load() -> Result {
    let mut pair = Box::pin(selected_runtime_pair(
        true,
        security::compact::Protection::HmacSha256,
    ))
    .await?;
    for _ in 0..4 {
        progress_owner(&mut pair.a, &mut pair.ad).await?;
        progress_owner(&mut pair.b, &mut pair.bd).await?;
    }
    assert_eq!(pair.ad.config.security.packets_per_key, 8);
    let deadline = pair.ad.origin + duration(pair.ad.lease);
    // More than one original key interval: each turn supplies First data and
    // Second management. Drain both without another PacketIo receive call.
    for value in 0..12 {
        stage_candidate(&mut pair, false, value)?;
        stage_candidate(&mut pair, true, value + 32)?;
        flush_candidates(&mut pair, true).await?;
        poll_raw_once(&mut pair.b, true).await?;
        let calls = receive_calls(&pair);
        accept_candidate(&mut pair, 0, value).await?;
        accept_candidate(&mut pair, 1, value + 32).await?;
        let mut empty = [0; 1500];
        assert!(matches!(
            pair.b.try_receive_at_ready(&mut empty).await,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock
        ));
        assert_eq!(receive_calls(&pair), calls);
        assert_eq!(pair.ad.origin + duration(pair.ad.lease), deadline);
    }
    // If only one candidate is consumed in a turn, a new First packet must not
    // overtake the already retained Second candidate on the next turn.
    stage_candidate(&mut pair, false, 90)?;
    stage_candidate(&mut pair, true, 91)?;
    flush_candidates(&mut pair, true).await?;
    poll_raw_once(&mut pair.b, true).await?;
    accept_candidate(&mut pair, 0, 90).await?;
    stage_candidate(&mut pair, false, 92)?;
    flush_candidates(&mut pair, false).await?;
    poll_raw_once(&mut pair.b, true).await?;
    let calls = receive_calls(&pair);
    accept_candidate(&mut pair, 1, 91).await?;
    accept_candidate(&mut pair, 0, 92).await?;
    assert_eq!(receive_calls(&pair), calls);
    let snapshot = pair
        .b
        .final_raw_mut()
        .ok_or("actual receiver")?
        .buffer_snapshot(Instant::now());
    let second = snapshot.carrier.lanes[1].ok_or("actual Second lane")?;
    assert_eq!(second.upper_control.counters.accepted.packets, 13);
    assert_eq!(second.upper_control.counters.capacity_refused.packets, 0);
    assert_eq!(second.upper_control.counters.verifier_rejected.packets, 0);
    assert_eq!(second.upper_control.queued_packets, 0);
    assert_eq!(pair.bd.records.compact_check_status().control, 0);
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn raw_new_final_output_progresses_after_idle_receipt_poll_without_new_turn() -> Result {
    for half in [false, true] {
        let mut pair = Box::pin(selected_runtime_pair(
            half,
            security::compact::Protection::HmacSha256,
        ))
        .await?;
        for _ in 0..4 {
            progress_owner(&mut pair.a, &mut pair.ad).await?;
            progress_owner(&mut pair.b, &mut pair.bd).await?;
        }
        for management in [false, true] {
            let now = Instant::now();
            let deadline = pair.ad.origin + duration(pair.ad.lease);
            // Reproduce the real Driver order: poll retained receipts before
            // committing fresh, authenticated User or Control ciphertext.
            pair.a.begin_turn();
            pair.a.observe_completions().await;
            stage_candidate(&mut pair, management, 31)?;
            assert!(pair.a.take_user()?.is_none());
            assert!(pair.a.take_control()?.is_none());
            poll_raw_current_turn(&mut pair.a, false).await?;
            let progress = if management {
                pair.a.take_control()?.ok_or("same-turn Control receipt")?.0
            } else {
                pair.a.take_user()?.ok_or("same-turn User receipt")?.1
            };
            let raw_carrier::SendProgress::Whole { receipt, late } = progress else {
                return Err("same-turn receipt was not physical".into());
            };
            assert!(!late);
            assert_eq!(receipt.accepted_at, now);
            assert_eq!(receipt.deadline, deadline);
            assert_eq!(Instant::now(), now);
        }
    }
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn raw_fresh_output_repoll_keeps_original_turn_quota_and_pending_identity() -> Result {
    for half in [false, true] {
        let mut pair = Box::pin(selected_runtime_pair(
            half,
            security::compact::Protection::HmacSha256,
        ))
        .await?;
        for _ in 0..4 {
            progress_owner(&mut pair.a, &mut pair.ad).await?;
            progress_owner(&mut pair.b, &mut pair.bd).await?;
        }
        let now = Instant::now();
        let deadline = pair.ad.origin + duration(pair.ad.lease);
        pair.a.begin_turn();
        pair.a.observe_completions().await;
        let mut accepted = 0;
        // Each real PacketIo receive/authentication reservation and each send
        // spends the same original 32-unit budget. Fresh commits cannot reset it.
        for value in 0..=32 {
            stage_candidate(&mut pair, false, value)?;
            poll_raw_current_turn(&mut pair.a, false).await?;
            if let Some((_, raw_carrier::SendProgress::Whole { receipt, late })) =
                pair.a.take_user()?
            {
                assert!(!late);
                assert_eq!(receipt.accepted_at, now);
                assert_eq!(receipt.deadline, deadline);
                accepted += 1;
            } else {
                break;
            }
        }
        assert!(accepted > 0 && accepted < 32);
        let before = pair
            .a
            .final_raw_mut()
            .ok_or("actual raw owner")?
            .buffer_snapshot(now);
        let pending = before.user.ok_or("quota-blocked User")?;
        assert!(pending.token_retained);
        assert!(!pending.receipt_retained);
        assert_eq!(pending.deadline, deadline);
        let lane = before.carrier.lanes[0].ok_or("actual data lane")?;
        assert!(lane.send_io.turn_budget_refusals > 0);
        assert_eq!(lane.send_io.would_block_observations, 0);
        assert_eq!(lane.send_io.pacing_refusals, 0);
        for _ in 0..3 {
            poll_raw_current_turn(&mut pair.a, false).await?;
            assert!(pair.a.take_user()?.is_none());
        }
        let retained = pair
            .a
            .final_raw_mut()
            .ok_or("actual raw owner")?
            .buffer_snapshot(now);
        assert_eq!(retained.user, Some(pending));
        assert_eq!(
            retained.carrier.lanes[0].ok_or("actual data lane")?.send_io,
            lane.send_io
        );
        // Only the next caller work turn replenishes the original quota.
        poll_raw_once(&mut pair.a, false).await?;
        let (_, progress) = pair.a.take_user()?.ok_or("next-turn physical receipt")?;
        let raw_carrier::SendProgress::Whole { receipt, late } = progress else {
            return Err("next-turn receipt was not physical".into());
        };
        assert!(!late);
        assert_eq!(receipt.accepted_at, now);
        assert_eq!(receipt.deadline, deadline);
        assert_eq!(Instant::now(), now);
    }
    Ok(())
}
