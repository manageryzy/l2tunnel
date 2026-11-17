//! Actual paired raw owners with a sole external verifier and unchanged receipts.
use super::*;
use crate::handoff::pairing::packet::compact::{
    BootstrapDirection, FinalAcceptance, FinalControl, FinalKind,
};

#[test]
fn compact_final_raw_authenticated_source_route_retains_data_authority() {
    for slot in 0..64 {
        let route = if slot < 22 { 2 + slot } else { 58 + slot };
        assert_eq!(FinalKind::inspect(&[route]), Some(FinalKind::Data));
        assert_eq!(FinalKind::inspect(&[0x80 | slot]), Some(FinalKind::Data));
        assert_eq!(
            FinalKind::inspect(&[0xc0 | slot]),
            Some(FinalKind::Feedback)
        );
    }
    assert_eq!(FinalKind::inspect(&[0]), Some(FinalKind::Control));
    assert_eq!(FinalKind::inspect(&[1]), Some(FinalKind::CarrierControl));
    for invalid in (24..80).chain(122..128) {
        assert_eq!(FinalKind::inspect(&[invalid]), None);
    }
    assert_eq!(FinalKind::inspect(&[]), None);
}

async fn tick(a: &mut PacketCarrier<Link>, b: &mut PacketCarrier<Link>) -> R {
    poll_fn(|cx| {
        for carrier in [&mut *a, &mut *b] {
            if let Poll::Ready(Err(error)) = carrier.poll_progress(cx) {
                return Poll::Ready(Err(error));
            }
        }
        Poll::Ready(Ok(()))
    })
    .await?;
    Ok(())
}

async fn selected(half: bool, fault: Arc<Fault>) -> R<(PacketCarrier<Link>, PacketCarrier<Link>)> {
    let (mut a, mut b) = run(half, fault, Arc::new(Fault::default()), false).await?;
    a.enable_final_records([0x42; 32], |_, bytes| bytes == b"setup-tail")?;
    b.enable_final_records([0x42; 32], |_, bytes| bytes == b"setup-tail")?;
    for _ in 0..3 {
        tick(&mut a, &mut b).await?;
    }
    assert_eq!(a.final_context, b.final_context);
    Ok((a, b))
}

#[tokio::test]
async fn compact_final_raw_retained_retry_checks_its_original_direction() -> R {
    for half in [false, true] {
        let (mut a, mut b) = run(
            half,
            Arc::new(Fault::default()),
            Arc::new(Fault::default()),
            false,
        )
        .await?;
        let original_deadlines = [a.deadline, b.deadline];
        a.enable_final_records([0x42; 32], |direction, body| {
            body == match direction {
                BootstrapDirection::Incoming => b"to-a",
                BootstrapDirection::Outgoing => b"to-b",
            }
        })?;
        b.enable_final_records([0x42; 32], |direction, body| {
            body == match direction {
                BootstrapDirection::Incoming => b"to-b",
                BootstrapDirection::Outgoing => b"to-a",
            }
        })?;
        for _ in 0..3 {
            tick(&mut a, &mut b).await?;
        }
        for lane in [PairLane::First, PairLane::Second]
            .into_iter()
            .take(if half { 2 } else { 1 })
        {
            assert!(matches!(
                a.stage_bootstrap_record_tracked(lane, RecordKind::Feedback, b"to-a"),
                Err(Error::Configuration)
            ));
            let a_token = a.stage_bootstrap_record_tracked(lane, RecordKind::Feedback, b"to-b")?;
            let b_token = b.stage_bootstrap_record_tracked(lane, RecordKind::Feedback, b"to-a")?;
            for _ in 0..3 {
                tick(&mut a, &mut b).await?;
            }
            assert_eq!(
                a.take_sent_record(lane)?
                    .ok_or("local retry receipt")?
                    .token,
                a_token
            );
            assert_eq!(
                b.take_sent_record(lane)?.ok_or("peer retry receipt")?.token,
                b_token
            );
            assert_eq!(a.record().ok_or("local retry input")?.bytes, b"to-a");
            assert_eq!(b.record().ok_or("peer retry input")?.bytes, b"to-b");
            a.consume_record()?;
            b.consume_record()?;
        }
        assert_eq!([a.deadline, b.deadline], original_deadlines);
    }
    Ok(())
}

#[tokio::test]
async fn compact_final_raw_exact_bytes_and_wouldblock_receipt_full_and_half() -> R {
    for half in [false, true] {
        let fault = Arc::new(Fault::default());
        let (mut a, mut b) = selected(half, fault.clone()).await?;
        let geometry = a.final_geometry()?;
        assert_eq!(geometry.ip_tcp_bytes, 40);
        assert_eq!(geometry.record_overhead_bytes, 0);
        assert_eq!(geometry.max_record_bytes, 536);
        assert!(matches!(
            a.stage_setup_record(PairLane::First, RecordKind::Data, b"legacy"),
            Err(Error::Configuration)
        ));
        let protected = [0x80, 0, 0, 0, 0, 0x41, 0x42, 0x43, 0x44];
        let prepare = a.prepare_final_record(PairLane::First, FinalKind::Data, protected.len())?;
        let metadata = prepare.metadata();
        assert!(matches!(
            a.prepare_final_record(PairLane::First, FinalKind::Feedback, 21),
            Err(Error::Busy)
        ));
        let receipt = a.commit_final_record(prepare, &protected)?;
        let exact = a.lanes[0]
            .as_ref()
            .ok_or("lane")?
            .pending
            .as_ref()
            .ok_or("pending")?
            .bytes
            .clone();
        assert_eq!(exact.len(), 40 + protected.len());
        assert_eq!(&exact[40..], &protected);
        fault.block_all.store(true, Ordering::SeqCst);
        for _ in 0..3 {
            tick(&mut a, &mut b).await?;
        }
        assert!(a.take_sent_record(PairLane::First)?.is_none());
        assert_eq!(
            fault.pending.lock().map_err(|_| "lock")?.as_deref(),
            Some(exact.as_slice())
        );
        assert!(b.final_input(PairLane::First)?.is_none());
        fault.block_all.store(false, Ordering::SeqCst);
        poll_fn(|cx| {
            for carrier in [&mut a, &mut b] {
                if let Poll::Ready(Err(error)) = carrier.poll_progress(cx) {
                    return Poll::Ready(Err(error));
                }
            }
            match b.final_input(PairLane::First) {
                Ok(Some(_)) => Poll::Ready(Ok(())),
                Ok(None) => Poll::Pending,
                Err(error) => Poll::Ready(Err(error)),
            }
        })
        .await?;
        let sent = a.take_sent_record(PairLane::First)?.ok_or("receipt")?;
        assert_eq!(sent.token, receipt);
        assert!(a.take_sent_record(PairLane::First)?.is_none());
        let input = b.final_input(PairLane::First)?.ok_or("input")?;
        assert_eq!(input.metadata(), metadata);
        assert_eq!(input.bytes(), protected);
        assert!(input.received_at() >= sent.sent_at);
        let arrival = input.received_at();
        drop(input);
        assert_eq!(b.earliest_final_candidate_at()?, Some(arrival));
        assert_eq!(b.earliest_final_candidate_at()?, Some(arrival));
        assert_eq!(b.earliest_authenticated_record_at()?, None);
        b.commit_final_input(
            PairLane::First,
            metadata,
            Some(FinalAcceptance::record((), false)),
        )?;
        assert!(b.final_input(PairLane::First)?.is_none());
        assert_eq!(b.earliest_final_candidate_at()?, None);
    }
    Ok(())
}

fn make_final(
    sender: &mut PacketCarrier<Link>,
    lane: PairLane,
    kind: FinalKind,
    control: Option<FinalControl>,
) -> R<(super::super::super::compact::FinalMetadata, Vec<u8>)> {
    let token = if let Some(control) = control {
        sender.prepare_final_control(lane, control, 37)?
    } else {
        sender.prepare_final_record(lane, kind, 37)?
    };
    let metadata = token.metadata();
    let mut protected = vec![0; 37];
    protected[0] = match kind {
        FinalKind::Data => 0x80,
        FinalKind::Feedback => 0xc0,
        FinalKind::Control => 0,
        FinalKind::CarrierControl => 1,
    };
    let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, &[0x61; 32]);
    let mut authentication = metadata.aad().to_vec();
    authentication.extend_from_slice(&protected[..5]);
    protected[5..].copy_from_slice(ring::hmac::sign(&key, &authentication).as_ref());
    sender.commit_final_record(token, &protected)?;
    Ok((
        metadata,
        sender.lanes[lane.index()]
            .as_ref()
            .ok_or("lane")?
            .pending
            .as_ref()
            .ok_or("pending")?
            .bytes
            .clone(),
    ))
}

#[tokio::test]
async fn compact_final_raw_metadata_rejection_and_short_data_never_retire_peer_credit() -> R {
    let (mut a, mut b) = selected(false, Arc::new(Fault::default())).await?;
    // Put real outstanding sequence space on the receiving owner so forged or
    // short-check peer ACK fields have credit they could incorrectly grant.
    let (reverse, _) = make_final(&mut b, PairLane::First, FinalKind::Data, None)?;
    tick(&mut a, &mut b).await?;
    tick(&mut a, &mut b).await?;
    b.take_sent_record(PairLane::First)?
        .ok_or("reverse receipt")?;
    a.commit_final_input(
        PairLane::First,
        reverse,
        Some(FinalAcceptance::record((), true)),
    )?;
    let before = lock(&b.lanes[0].as_ref().ok_or("lane")?.io.state)?
        .fence
        .as_ref()
        .ok_or("fence")?
        .peer_retired;
    let (data, original) = make_final(&mut a, PairLane::First, FinalKind::Data, None)?;
    let config = lock(&a.lanes[0].as_ref().ok_or("lane")?.io.state)?.config;
    let peer_config = lock(&b.lanes[0].as_ref().ok_or("lane")?.io.state)?.config;
    let parsed = packet::inspect(peer_config, &original)?;
    let mut wrong = vec![0; original.len()];
    packet::encode(
        config,
        parsed.sequence + 1,
        parsed.acknowledgment,
        parsed.window,
        parsed.payload,
        &mut wrong,
    )?;
    lock(&b.lanes[0].as_ref().ok_or("lane")?.io.state)?.ingest_final(&wrong)?;
    let input = b.final_input(PairLane::First)?.ok_or("altered candidate")?;
    let altered = input.metadata();
    let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, &[0x61; 32]);
    let mut authentication = altered.aad().to_vec();
    authentication.extend_from_slice(&input.bytes()[..5]);
    assert!(ring::hmac::verify(&key, &authentication, &input.bytes()[5..]).is_err());
    drop(input);
    b.commit_final_input(PairLane::First, altered, None)?;
    tick(&mut a, &mut b).await?;
    tick(&mut a, &mut b).await?;
    a.take_sent_record(PairLane::First)?.ok_or("data receipt")?;
    b.commit_final_input(
        PairLane::First,
        data,
        Some(FinalAcceptance::record((), true)),
    )?;
    assert_eq!(
        lock(&b.lanes[0].as_ref().ok_or("lane")?.io.state)?
            .fence
            .as_ref()
            .ok_or("fence")?
            .peer_retired,
        before
    );
    let (feedback, _) = make_final(&mut a, PairLane::First, FinalKind::Feedback, None)?;
    tick(&mut a, &mut b).await?;
    tick(&mut a, &mut b).await?;
    assert!(matches!(
        b.commit_final_input(
            PairLane::First,
            feedback,
            Some(FinalAcceptance::record((), false))
        ),
        Err(Error::Proof)
    ));
    b.commit_final_input(
        PairLane::First,
        feedback,
        Some(FinalAcceptance::record((), true)),
    )?;
    assert!(
        lock(&b.lanes[0].as_ref().ok_or("lane")?.io.state)?
            .fence
            .as_ref()
            .ok_or("fence")?
            .peer_retired
            > before
    );
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn compact_final_raw_activation_at_setup_deadline_is_terminal_and_preserves_receipts() -> R {
    for half in [false, true] {
        let (mut a, mut b) = run(
            half,
            Arc::new(Fault::default()),
            Arc::new(Fault::default()),
            false,
        )
        .await?;
        let deadline = a.setup_deadline();
        assert!(matches!(
            a.enable_final_records([0; 32], |_, _| true),
            Err(Error::Configuration)
        ));
        assert!(a.fault.is_none());
        let token =
            a.stage_setup_record_tracked(PairLane::First, RecordKind::Data, b"setup-tail")?;
        poll_fn(|cx| {
            for carrier in [&mut a, &mut b] {
                if let Poll::Ready(Err(error)) = carrier.poll_progress(cx) {
                    return Poll::Ready(Err(error));
                }
            }
            if a.lanes[0]
                .as_ref()
                .is_some_and(|lane| lane.completed.is_some())
            {
                Poll::Ready(Ok(()))
            } else {
                Poll::Pending
            }
        })
        .await?;
        let sent = a.lanes[0]
            .as_ref()
            .ok_or("original lane")?
            .completed
            .ok_or("physical receipt")?;
        assert_eq!(sent.token, token);
        for lane in a.lanes.iter().flatten() {
            let state = lock(&lane.io.state)?;
            assert!(state.final_context.is_none());
            assert!(state.bootstrap_filter.is_none());
        }
        tokio::time::advance(deadline.saturating_duration_since(Instant::now())).await;
        assert_eq!(Instant::now(), deadline);
        // The original setup cap bounds every pre-final operation, including
        // activation, even when the raw liveness lease would still be live.
        assert!(matches!(
            a.enable_final_records([0x42; 32], |_, bytes| bytes == b"setup-tail"),
            Err(Error::Expired)
        ));
        assert_eq!(a.setup_deadline(), deadline);
        assert!(!a.final_records_enabled());
        assert!(a.lanes.iter().all(Option::is_none));
        assert!(a.records.is_empty());
        assert!(matches!(a.fault, Some(Error::Expired)));
        assert!(matches!(
            a.enable_final_records([0; 32], |_, _| true),
            Err(Error::Expired)
        ));
        let observed = a.take_sent_record_observed(PairLane::First)?;
        let actual = observed.sent.ok_or("original receipt was lost")?;
        assert_eq!(actual.token, sent.token);
        assert_eq!(actual.sent_at, sent.sent_at);
        assert!(matches!(observed.failure, Some(Error::Expired)));
        let repeated = a.take_sent_record_observed(PairLane::First)?;
        assert!(repeated.sent.is_none());
        assert!(matches!(repeated.failure, Some(Error::Expired)));
    }
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn compact_final_raw_bootstrap_cap_and_existing_custody_are_not_renewed() -> R {
    let fault = Arc::new(Fault::default());
    let (mut a, mut b) = run(false, fault.clone(), Arc::new(Fault::default()), false).await?;
    let token = a.stage_setup_record_tracked(PairLane::First, RecordKind::Data, b"setup-tail")?;
    let pending = a.lanes[0]
        .as_ref()
        .ok_or("lane")?
        .pending
        .as_ref()
        .ok_or("pending")?
        .bytes
        .clone();
    let deadline = a.deadline;
    a.enable_final_records([0x42; 32], |_, bytes| bytes == b"setup-tail")?;
    b.enable_final_records([0x42; 32], |_, bytes| bytes == b"setup-tail")?;
    assert_eq!(a.deadline, deadline);
    assert_eq!(
        a.lanes[0]
            .as_ref()
            .ok_or("lane")?
            .pending
            .as_ref()
            .ok_or("pending")?
            .bytes,
        pending
    );
    tick(&mut a, &mut b).await?;
    tick(&mut a, &mut b).await?;
    assert_eq!(
        a.take_sent_record(PairLane::First)?
            .ok_or("bootstrap receipt")?
            .token,
        token
    );
    assert_eq!(b.record().ok_or("bootstrap tail")?.bytes, b"setup-tail");
    b.consume_record()?;
    assert!(matches!(
        a.stage_bootstrap_record_tracked(PairLane::First, RecordKind::Data, b"old-user"),
        Err(Error::Configuration)
    ));
    let original_liveness = a.lanes[0].as_ref().ok_or("lane")?.last_alive;
    let until = deadline.saturating_duration_since(Instant::now());
    assert!(until < Duration::from_secs(14));
    tokio::time::advance(until).await;
    tick(&mut a, &mut b).await?;
    let lane = a.lanes[0].as_ref().ok_or("lane")?;
    assert!(lane.sealer.is_none());
    assert!(lock(&lane.io.state)?.opener.is_none());
    assert_eq!(lane.last_alive, original_liveness);
    assert!(matches!(
        a.enable_final_records([0x42; 32], |_, bytes| bytes == b"setup-tail"),
        Err(Error::Configuration)
    ));
    assert!(a.final_records_enabled());
    a.check_live()?;
    assert!(matches!(
        a.stage_bootstrap_record_tracked(PairLane::First, RecordKind::Data, b"setup-tail"),
        Err(Error::Expired)
    ));
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn compact_final_raw_strong_liveness_uses_every_original_lane() -> R {
    for half in [false, true] {
        let (mut a, mut b) = selected(half, Arc::new(Fault::default())).await?;
        let before: Vec<_> = a
            .lanes
            .iter()
            .flatten()
            .map(|lane| lane.last_alive)
            .collect();
        tokio::time::advance(Duration::from_secs(5)).await;
        for lane in [PairLane::First, PairLane::Second]
            .into_iter()
            .take(if half { 2 } else { 1 })
        {
            let ping = a.poll_final_control(lane)?.ok_or("ping due")?;
            let FinalControl::Ping(nonce) = ping else {
                return Err("expected ping".into());
            };
            let (metadata, _) = make_final(&mut a, lane, FinalKind::CarrierControl, Some(ping))?;
            tick(&mut a, &mut b).await?;
            tick(&mut a, &mut b).await?;
            a.take_sent_record(lane)?.ok_or("ping receipt")?;
            b.commit_final_input(lane, metadata, Some(FinalAcceptance::control((), ping)))?;
            let pong = b.poll_final_control(lane)?.ok_or("pong due")?;
            assert_eq!(pong, FinalControl::Pong(nonce));
            let (metadata, packet) =
                make_final(&mut b, lane, FinalKind::CarrierControl, Some(pong))?;
            tick(&mut a, &mut b).await?;
            tick(&mut a, &mut b).await?;
            b.take_sent_record(lane)?.ok_or("pong receipt")?;
            let arrival = a.final_input(lane)?.ok_or("pong input")?.received_at();
            a.commit_final_input(lane, metadata, Some(FinalAcceptance::control((), pong)))?;
            let owner = a.lanes[lane.index()].as_ref().ok_or("lane")?;
            assert_eq!(owner.last_alive, arrival);
            assert!(owner.last_alive > before[lane.index()]);
            assert!(owner.ping.is_none());
            lock(&owner.io.state)?.ingest_final(&packet)?;
            assert!(a.final_input(lane)?.is_none());
        }
    }
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn compact_final_raw_blocked_bootstrap_ciphertext_cannot_outlive_original_cap() -> R {
    let fault = Arc::new(Fault::default());
    let (mut a, mut b) = run(false, fault.clone(), Arc::new(Fault::default()), false).await?;
    a.stage_setup_record_tracked(PairLane::First, RecordKind::Data, b"setup-tail")?;
    a.enable_final_records([0x42; 32], |_, bytes| bytes == b"setup-tail")?;
    b.enable_final_records([0x42; 32], |_, bytes| bytes == b"setup-tail")?;
    fault.block_all.store(true, Ordering::SeqCst);
    tick(&mut a, &mut b).await?;
    assert!(fault.pending.lock().map_err(|_| "lock")?.is_some());
    tokio::time::advance(a.deadline.saturating_duration_since(Instant::now())).await;
    fault.block_all.store(false, Ordering::SeqCst);
    poll_fn(|cx| {
        assert!(matches!(
            a.poll_progress(cx),
            Poll::Ready(Err(Error::Expired))
        ));
        Poll::Ready(())
    })
    .await;
    let observation = a.take_sent_record_observed(PairLane::First)?;
    assert!(observation.sent.is_none());
    assert!(matches!(observation.failure, Some(Error::Expired)));
    assert!(b.record().is_none());
    Ok(())
}
