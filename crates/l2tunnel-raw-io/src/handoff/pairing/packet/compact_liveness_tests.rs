//! Loss and custody checks for the original raw liveness deadline.
use super::*;
use crate::handoff::pairing::packet::compact::FinalMetadata;

const CONTROL_BYTES: usize = 5 + 9 + 32;
const CONTROL_WIRE_BYTES: usize = 40 + CONTROL_BYTES;

fn stage_control(
    sender: &mut PacketCarrier<Link>,
    fault: &Fault,
    lane: PairLane,
    control: FinalControl,
) -> R<(FinalMetadata, Vec<u8>, RecordToken)> {
    let token = sender.prepare_final_control(lane, control, CONTROL_BYTES)?;
    let metadata = token.metadata();
    let mut protected = [0; CONTROL_BYTES];
    protected[0] = 1;
    protected[1..5].copy_from_slice(&metadata.aad()[35..39]);
    assert_eq!(control.encode(&mut protected[5..14])?, 9);
    // This lower-owner fixture supplies the existing external verification seam.
    // It authenticates the complete control and raw AAD with maintained HMAC;
    // Records encryption and its independent replay tests remain upstream.
    let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, &[0x62; 32]);
    let mut authenticated = metadata.aad().to_vec();
    authenticated.extend_from_slice(&protected[..14]);
    protected[14..].copy_from_slice(ring::hmac::sign(&key, &authenticated).as_ref());
    let receipt = sender.commit_final_record(token, &protected)?;
    let packet = sender.lanes[lane.index()]
        .as_ref()
        .ok_or("lane")?
        .pending
        .as_ref()
        .ok_or("pending control")?
        .bytes
        .clone();
    assert_eq!(packet.len(), CONTROL_WIRE_BYTES);
    // Keep entries after observing a send so an accidental duplicate still
    // counts. WouldBlock bypasses the counter until actual link acceptance.
    fault
        .staged_final_controls
        .lock()
        .map_err(|_| "test lock")?
        .push(packet.clone());
    Ok((metadata, packet, receipt))
}

#[test]
fn unstaged_raw_tcp_payload_with_control_route_remains_on_the_link() -> R {
    let (RawInputs::Full(sender), RawInputs::Full(mut peer), _) = support::inputs(false) else {
        return Err("expected full-duplex link".into());
    };
    let fault = Arc::new(Fault::default());
    fault.drop_final_controls.store(true, Ordering::SeqCst);
    let mut link = Link {
        inner: sender.io,
        fault: fault.clone(),
    };
    // The observed false positive had 86 TCP payload bytes (126 IP bytes).
    // Also check a same-length lookalike: length plus route is insufficient.
    for payload_len in [86, CONTROL_BYTES] {
        let mut body = vec![0x64; payload_len];
        body[0] = 1;
        let mut packet = vec![0; 40 + payload_len];
        l2tunnel_raw_tcp::packet::encode(sender.config, 123, 456, 1000, &body, &mut packet)?;
        assert_eq!(packet.get(40), Some(&1));
        link.send(&packet)?;
        assert_eq!(peer.io.incoming.try_recv()?, packet);
    }
    assert_eq!(fault.final_control_packets.load(Ordering::SeqCst), 0);
    assert_eq!(fault.final_control_bytes.load(Ordering::SeqCst), 0);
    Ok(())
}

fn accept_control(
    receiver: &mut PacketCarrier<Link>,
    lane: PairLane,
) -> R<(FinalControl, Instant)> {
    let input = receiver
        .final_input(lane)?
        .ok_or("authenticated control candidate")?;
    assert_eq!(input.bytes().len(), CONTROL_BYTES);
    let metadata = input.metadata();
    let received_at = input.received_at();
    let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, &[0x62; 32]);
    let mut authenticated = metadata.aad().to_vec();
    authenticated.extend_from_slice(&input.bytes()[..14]);
    ring::hmac::verify(&key, &authenticated, &input.bytes()[14..])
        .map_err(|_| "invalid test control authentication")?;
    let control = FinalControl::decode(&input.bytes()[5..14])?;
    drop(input);
    receiver.commit_final_input(lane, metadata, Some(FinalAcceptance::control((), control)))?;
    Ok((control, received_at))
}

async fn flush(a: &mut PacketCarrier<Link>, b: &mut PacketCarrier<Link>) -> R {
    for _ in 0..3 {
        tick(a, b).await?;
    }
    Ok(())
}

async fn lost_control_is_retried(drop_ping: bool) -> R {
    for half in [false, true] {
        let af = Arc::new(Fault::default());
        let bf = Arc::new(Fault::default());
        let (mut a, mut b) = selected_faults(half, af.clone(), bf.clone()).await?;
        let endpoints = [a.lane_endpoints()?, b.lane_endpoints()?];
        let setup_caps = [a.setup_deadline(), b.setup_deadline()];
        let lanes: Vec<_> = [PairLane::First, PairLane::Second]
            .into_iter()
            .take(if half { 2 } else { 1 })
            .collect();
        let alive: Vec<_> = a
            .lanes
            .iter()
            .flatten()
            .map(|lane| lane.last_alive)
            .collect();
        let mut previous = Vec::new();
        tokio::time::advance(Duration::from_secs(5)).await;
        for attempt in 0..3 {
            if attempt > 0 {
                tokio::time::advance(TRANSITION_RETRY_INTERVAL - Duration::from_nanos(1)).await;
                for &lane in &lanes {
                    assert!(a.poll_final_control(lane)?.is_none());
                }
                tokio::time::advance(Duration::from_nanos(1)).await;
            }
            let lost = attempt < 2;
            af.drop_final_controls
                .store(drop_ping && lost, Ordering::SeqCst);
            bf.drop_final_controls
                .store(!drop_ping && lost, Ordering::SeqCst);
            for &lane in &lanes {
                let ping = a.poll_final_control(lane)?.ok_or("Ping due")?;
                let FinalControl::Ping(nonce) = ping else {
                    return Err("Ping required".into());
                };
                let (metadata, packet, token) = stage_control(&mut a, &af, lane, ping)?;
                if attempt == 0 {
                    previous.push((ping, metadata, packet.clone()));
                } else {
                    let prior = &mut previous[lane.index()];
                    assert_eq!(ping, prior.0);
                    assert_ne!(metadata, prior.1);
                    assert_ne!(packet, prior.2);
                    *prior = (ping, metadata, packet);
                }
                flush(&mut a, &mut b).await?;
                assert_eq!(
                    a.take_sent_record(lane)?.ok_or("accepted Ping")?.token,
                    token
                );
                assert!(a.take_sent_record(lane)?.is_none());
                if drop_ping && lost {
                    assert!(b.final_input(lane)?.is_none());
                } else {
                    assert_eq!(accept_control(&mut b, lane)?.0, ping);
                    let pong = b.poll_final_control(lane)?.ok_or("Pong obligation")?;
                    assert_eq!(pong, FinalControl::Pong(nonce));
                    let (_, pong_packet, pong_token) = stage_control(&mut b, &bf, lane, pong)?;
                    flush(&mut a, &mut b).await?;
                    assert_eq!(
                        b.take_sent_record(lane)?.ok_or("accepted Pong")?.token,
                        pong_token
                    );
                    assert!(b.lanes[lane.index()].as_ref().ok_or("lane")?.pong.is_none());
                    if lost {
                        assert!(a.final_input(lane)?.is_none());
                    } else {
                        let (accepted, arrival) = accept_control(&mut a, lane)?;
                        assert_eq!(accepted, pong);
                        let owner = a.lanes[lane.index()].as_ref().ok_or("lane")?;
                        assert_eq!(owner.last_alive, arrival);
                        assert!(owner.last_alive > alive[lane.index()]);
                        assert!(owner.ping.is_none());
                        // Exact packet replay cannot renew liveness again.
                        lock(&owner.io.state)?.ingest_final(&pong_packet)?;
                        assert!(a.final_input(lane)?.is_none());
                        assert_eq!(
                            a.lanes[lane.index()].as_ref().ok_or("lane")?.last_alive,
                            arrival
                        );
                    }
                }
                if lost {
                    assert_eq!(
                        a.lanes[lane.index()].as_ref().ok_or("lane")?.last_alive,
                        alive[lane.index()]
                    );
                }
            }
        }
        let a_packets = 3 * lanes.len();
        let b_packets = if drop_ping {
            lanes.len()
        } else {
            3 * lanes.len()
        };
        assert_eq!(af.final_control_packets.load(Ordering::SeqCst), a_packets);
        assert_eq!(
            af.final_control_bytes.load(Ordering::SeqCst),
            a_packets * CONTROL_WIRE_BYTES
        );
        assert_eq!(bf.final_control_packets.load(Ordering::SeqCst), b_packets);
        assert_eq!(
            bf.final_control_bytes.load(Ordering::SeqCst),
            b_packets * CONTROL_WIRE_BYTES
        );
        assert_eq!([a.lane_endpoints()?, b.lane_endpoints()?], endpoints);
        assert_eq!([a.setup_deadline(), b.setup_deadline()], setup_caps);
    }
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn compact_final_raw_liveness_retries_dropped_ping_full_and_half() -> R {
    Box::pin(lost_control_is_retried(true)).await
}

#[tokio::test(start_paused = true)]
async fn compact_final_raw_liveness_retries_dropped_pong_full_and_half() -> R {
    Box::pin(lost_control_is_retried(false)).await
}

#[tokio::test(start_paused = true)]
async fn compact_final_raw_liveness_retry_cancellation_and_wouldblock_keep_custody() -> R {
    let fault = Arc::new(Fault::default());
    let (mut a, mut b) = selected(false, fault.clone()).await?;
    let lane = PairLane::First;
    let original_alive = a.lanes[0].as_ref().ok_or("lane")?.last_alive;
    tokio::time::advance(Duration::from_secs(5)).await;
    let ping = a.poll_final_control(lane)?.ok_or("Ping due")?;
    fault.drop_final_controls.store(true, Ordering::SeqCst);
    stage_control(&mut a, &fault, lane, ping)?;
    flush(&mut a, &mut b).await?;
    a.take_sent_record(lane)?.ok_or("original Ping receipt")?;
    let last_ping = a.lanes[0].as_ref().ok_or("lane")?.last_ping;
    assert!(matches!(
        a.prepare_final_control(lane, ping, CONTROL_BYTES),
        Err(Error::Busy)
    ));
    tokio::time::advance(TRANSITION_RETRY_INTERVAL).await;
    let prepared = a.prepare_final_control(lane, ping, CONTROL_BYTES)?;
    let metadata = prepared.metadata();
    a.cancel_final_record(prepared)?;
    assert_eq!(a.lanes[0].as_ref().ok_or("lane")?.last_ping, last_ping);
    assert_eq!(
        a.lanes[0].as_ref().ok_or("lane")?.last_alive,
        original_alive
    );
    let FinalControl::Ping(mut wrong) = ping else {
        return Err("Ping required".into());
    };
    wrong[0] ^= 1;
    assert!(matches!(
        a.prepare_final_control(lane, FinalControl::Ping(wrong), CONTROL_BYTES),
        Err(Error::Busy)
    ));
    fault.drop_final_controls.store(false, Ordering::SeqCst);
    fault.block_all.store(true, Ordering::SeqCst);
    let (retry_metadata, packet, token) = stage_control(&mut a, &fault, lane, ping)?;
    assert_eq!(retry_metadata, metadata);
    flush(&mut a, &mut b).await?;
    assert!(a.take_sent_record(lane)?.is_none());
    assert!(a.poll_final_control(lane)?.is_none());
    assert_eq!(fault.final_control_packets.load(Ordering::SeqCst), 1);
    tokio::time::advance(Duration::from_secs(1)).await;
    flush(&mut a, &mut b).await?;
    assert!(a.next_wake()? >= Instant::now());
    assert_eq!(
        fault.pending.lock().map_err(|_| "lock")?.as_deref(),
        Some(packet.as_slice())
    );
    assert_eq!(
        a.lanes[0].as_ref().ok_or("lane")?.last_alive,
        original_alive
    );
    fault.block_all.store(false, Ordering::SeqCst);
    flush(&mut a, &mut b).await?;
    let receipt = a.take_sent_record(lane)?.ok_or("accepted retained retry")?;
    assert_eq!(receipt.token, token);
    assert_eq!(
        a.lanes[0].as_ref().ok_or("lane")?.last_ping,
        receipt.sent_at
    );
    assert!(a.take_sent_record(lane)?.is_none());
    assert!(a.poll_final_control(lane)?.is_none());
    assert_eq!(fault.final_control_packets.load(Ordering::SeqCst), 2);
    assert_eq!(
        fault.final_control_bytes.load(Ordering::SeqCst),
        2 * CONTROL_WIRE_BYTES
    );
    assert_eq!(accept_control(&mut b, lane)?.0, ping);
    assert_eq!(
        a.lanes[0].as_ref().ok_or("lane")?.last_alive,
        original_alive
    );
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn compact_final_raw_liveness_retry_dead_peer_expires_at_original_cap() -> R {
    let fault = Arc::new(Fault::default());
    let (mut a, mut b) = selected(false, fault.clone()).await?;
    let lane = PairLane::First;
    let last_alive = a.lanes[0].as_ref().ok_or("lane")?.last_alive;
    let deadline = last_alive + Duration::from_secs(15);
    fault.drop_final_controls.store(true, Ordering::SeqCst);
    let mut due = Instant::now() + Duration::from_secs(5);
    let mut challenge = None;
    let mut final_receipt = None;
    let mut attempts = 0;
    // The fixed interval and original cap bound the number of accepted attempts.
    for _ in 0..60 {
        if due >= deadline {
            break;
        }
        tokio::time::advance(due.saturating_duration_since(Instant::now())).await;
        let ping = a.poll_final_control(lane)?.ok_or("bounded retry")?;
        if let Some(original) = challenge {
            assert_eq!(ping, original);
        } else {
            challenge = Some(ping);
        }
        let (_, _, token) = stage_control(&mut a, &fault, lane, ping)?;
        flush(&mut a, &mut b).await?;
        let sent = a.lanes[0]
            .as_ref()
            .ok_or("lane")?
            .completed
            .ok_or("accepted retry")?;
        assert_eq!(sent.token, token);
        attempts += 1;
        due += TRANSITION_RETRY_INTERVAL;
        if due < deadline {
            assert_eq!(
                a.take_sent_record(lane)?.ok_or("retry receipt")?.token,
                token
            );
        } else {
            final_receipt = Some(sent);
        }
    }
    let final_receipt = final_receipt.ok_or("original expiry must bound retries")?;
    assert!(attempts > 2);
    assert!(a.poll_final_control(lane)?.is_none());
    assert_eq!(a.lanes[0].as_ref().ok_or("lane")?.last_alive, last_alive);
    assert_eq!(fault.final_control_packets.load(Ordering::SeqCst), attempts);
    assert_eq!(
        fault.final_control_bytes.load(Ordering::SeqCst),
        attempts * CONTROL_WIRE_BYTES
    );
    tokio::time::advance(
        deadline.saturating_duration_since(Instant::now()) - Duration::from_nanos(1),
    )
    .await;
    a.check_live()?;
    tokio::time::advance(Duration::from_nanos(1)).await;
    assert_eq!(Instant::now(), deadline);
    assert!(matches!(a.poll_final_control(lane), Err(Error::Expired)));
    assert!(a.lanes.iter().all(Option::is_none));
    let observed = a.take_sent_record_observed(lane)?;
    let receipt = observed.sent.ok_or("accepted retry retained at expiry")?;
    assert_eq!(receipt.token, final_receipt.token);
    assert_eq!(receipt.sent_at, final_receipt.sent_at);
    assert!(matches!(observed.failure, Some(Error::Expired)));
    let repeated = a.take_sent_record_observed(lane)?;
    assert!(repeated.sent.is_none());
    assert!(matches!(repeated.failure, Some(Error::Expired)));
    Ok(())
}
