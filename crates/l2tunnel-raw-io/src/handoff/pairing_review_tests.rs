//! Independent owner-boundary regressions using the original TLS and raw drivers.
use super::test_support::*;
use super::*;
use std::{
    future::poll_fn,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    task::Waker,
};

fn poll_setup(
    setup: &mut PairSetup<'_, PacketLink>,
) -> Poll<Result<PairedRaw<PacketLink>, PairError>> {
    Pin::new(setup).poll(&mut Context::from_waker(Waker::noop()))
}

fn pending_setup(setup: &mut PairSetup<'_, PacketLink>) -> R {
    match poll_setup(setup) {
        Poll::Pending => Ok(()),
        Poll::Ready(Err(error)) => Err(error.into()),
        Poll::Ready(Ok(_)) => Err("unexpected completed pairing".into()),
    }
}

fn progress(owner: &mut PairedRaw<PacketLink>) -> R {
    match owner.poll_progress(&mut Context::from_waker(Waker::noop())) {
        Poll::Ready(Err(error)) => Err(error.into()),
        _ => Ok(()),
    }
}

async fn tick() {
    tokio::time::advance(Duration::from_millis(1)).await;
}

fn assert_destroyed(probes: &[std::sync::Arc<Probe>]) {
    for probe in probes {
        assert_eq!(probe.dropped.load(Ordering::SeqCst), 1);
    }
}

#[tokio::test(start_paused = true)]
async fn genuine_cross_wired_half_groups_reject_before_pair_authority() -> R {
    let (client, server, member, allowed) = fixture()?;
    let (a1, b1, mut probes) = inputs(true);
    let (a2, b2, other_probes) = inputs(true);
    probes.extend(other_probes);
    let RawInputs::Half {
        forward: b1f,
        reverse: b1r,
    } = b1
    else {
        return Err("half fixture".into());
    };
    let RawInputs::Half {
        forward: b2f,
        reverse: b2r,
    } = b2
    else {
        return Err("half fixture".into());
    };
    let mut setups = [
        begin_pair_client(a1, &client, "tunnel.test", &member, config())?,
        begin_pair_client(a2, &client, "tunnel.test", &member, config())?,
        begin_pair_server(
            RawInputs::Half {
                forward: b1f,
                reverse: b2r,
            },
            &server,
            &allowed,
            config(),
        )?,
        begin_pair_server(
            RawInputs::Half {
                forward: b2f,
                reverse: b1r,
            },
            &server,
            &allowed,
            config(),
        )?,
    ];
    // Finish all eight genuine member authentications, but retain each actual
    // driver once its local auth phase ends. No owner/identity is manufactured.
    for _ in 0..2000 {
        for setup in &mut setups {
            if setup.phase == 0 {
                pending_setup(setup)?;
            } else {
                setup
                    .group
                    .as_mut()
                    .ok_or("group absent")?
                    .drive(&mut Context::from_waker(Waker::noop()))?;
            }
        }
        if setups.iter().all(|setup| setup.phase == 1) {
            break;
        }
        tick().await;
    }
    assert!(setups.iter().all(|setup| setup.phase == 1));
    let sessions = setups
        .iter()
        .map(|setup| {
            let group = setup.group.as_ref().ok_or("group absent")?;
            let mut ids = Vec::new();
            for owner in &group.owners {
                let info = owner.as_ref().ok_or("TLS owner absent")?.info();
                assert_eq!(info.member, member.public_key());
                ids.push(info.session_id);
            }
            assert_ne!(ids[0], ids[1]);
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(ids)
        })
        .collect::<R<Vec<_>>>()?;
    assert_eq!(sessions[0][0], sessions[2][0]);
    assert_eq!(sessions[0][1], sessions[3][1]);
    assert_eq!(sessions[1][0], sessions[3][0]);
    assert_eq!(sessions[1][1], sessions[2][1]);
    let mut rejected = false;
    'service: for _ in 0..2000 {
        for (index, setup) in setups.iter_mut().enumerate() {
            match poll_setup(setup) {
                Poll::Pending => {}
                Poll::Ready(Err(PairError::Protocol)) if index < 2 => {
                    rejected = true;
                    break 'service;
                }
                Poll::Ready(Err(error)) => return Err(error.into()),
                Poll::Ready(Ok(_)) => return Err("cross-wired authority escaped".into()),
            }
        }
        tick().await;
    }
    assert!(rejected);
    drop(setups);
    assert_destroyed(&probes);
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn completed_first_auth_cannot_renew_stuck_second_lane_deadline() -> R {
    let (client, server, member, allowed) = fixture()?;
    let (a, b, probes) = inputs(true);
    for i in [2, 3] {
        probes[i].blocked.store(true, Ordering::SeqCst);
    }
    let mut a = begin_pair_client(a, &client, "tunnel.test", &member, config())?;
    let mut b = begin_pair_server(b, &server, &allowed, config())?;
    let original = a.status().ok_or("status")?.deadline;
    assert_eq!(original, b.status().ok_or("status")?.deadline);
    for _ in 0..2000 {
        pending_setup(&mut a)?;
        pending_setup(&mut b)?;
        if [&a, &b].iter().all(|setup| {
            setup
                .group
                .as_ref()
                .is_some_and(|group| group.owners[0].is_some())
        }) {
            break;
        }
        tick().await;
    }
    for setup in [&a, &b] {
        let group = setup.group.as_ref().ok_or("group")?;
        assert!(group.owners[0].is_some());
        assert!(group.owners[1].is_none());
        assert!(setup.setups[1].is_some());
        assert_eq!(setup.phase, 0);
        assert_eq!(setup.status().ok_or("status")?.deadline, original);
        assert!(
            group.owners[0]
                .as_ref()
                .ok_or("owner")?
                .status()
                .records
                .incoming
                .wire_bytes
                > 0
        );
    }
    tokio::time::advance(original - Instant::now()).await;
    for setup in [&mut a, &mut b] {
        assert!(matches!(
            poll_setup(setup),
            Poll::Ready(Err(PairError::Expired))
        ));
        let group = setup.group.as_ref().ok_or("group")?;
        assert!(group.owners.iter().all(Option::is_none));
        assert!(group.drivers.iter().all(Option::is_none));
        assert!(group.roots.iter().all(Option::is_none));
        assert!(setup.setups.iter().all(Option::is_none));
        assert!(matches!(
            setup.status().ok_or("status")?.fault,
            Some(PairError::Expired)
        ));
    }
    assert_destroyed(&probes);
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn dropping_each_setup_phase_destroys_only_its_original_owners_without_io() -> R {
    for target in 0..=3 {
        for client_first in [false, true] {
            let (client, server, member, allowed) = fixture()?;
            let (a, b, probes) = inputs(true);
            let mut a = begin_pair_client(a, &client, "tunnel.test", &member, config())?;
            let mut b = begin_pair_server(b, &server, &allowed, config())?;
            for _ in 0..2000 {
                if b.phase == target {
                    break;
                }
                pending_setup(&mut a)?;
                pending_setup(&mut b)?;
                tick().await;
            }
            assert_eq!(b.phase, target);
            let counters: Vec<_> = probes
                .iter()
                .map(|p| {
                    (
                        p.received.load(Ordering::SeqCst),
                        p.sent.load(Ordering::SeqCst),
                    )
                })
                .collect();
            if client_first {
                drop(a);
                for (i, probe) in probes.iter().enumerate() {
                    assert_eq!(
                        probe.dropped.load(Ordering::SeqCst),
                        usize::from(i % 2 == 0)
                    );
                }
                drop(b);
            } else {
                drop(b);
                for (i, probe) in probes.iter().enumerate() {
                    assert_eq!(
                        probe.dropped.load(Ordering::SeqCst),
                        usize::from(i % 2 == 1)
                    );
                }
                drop(a);
            }
            assert_destroyed(&probes);
            for (p, before) in probes.iter().zip(counters) {
                assert_eq!(
                    (
                        p.received.load(Ordering::SeqCst),
                        p.sent.load(Ordering::SeqCst)
                    ),
                    before
                );
            }
        }
    }
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn one_received_accepted_lane_never_becomes_paired_before_original_expiry() -> R {
    let (client, server, member, allowed) = fixture()?;
    let (a, b, probes) = inputs(true);
    let mut a = begin_pair_client(a, &client, "tunnel.test", &member, config())?;
    let mut b = begin_pair_server(b, &server, &allowed, config())?;
    let original = a.status().ok_or("status")?.deadline;
    for _ in 0..2000 {
        pending_setup(&mut a)?;
        pending_setup(&mut b)?;
        if b.phase == 3 {
            break;
        }
        tick().await;
    }
    assert_eq!(b.phase, 3);
    assert_eq!(a.phase, 3);
    assert_eq!(b.staged, [false; 2]);
    // Keep the exact original reverse driver unpolled while the server's local
    // TLS Accepted flush and the other lane complete. A stream flush does not
    // establish that this later raw send/WouldBlock boundary has been reached.
    let reverse_service = Arc::new(AtomicBool::new(false));
    let service = reverse_service.clone();
    let mut original_driver = b.group.as_mut().ok_or("group")?.drivers[1]
        .take()
        .ok_or("original reverse driver")?;
    b.group.as_mut().ok_or("group")?.drivers[1] = Some(Box::pin(poll_fn(move |cx| {
        if service.load(Ordering::SeqCst) {
            original_driver.as_mut().poll(cx)
        } else {
            Poll::Pending
        }
    })));
    probes[3].blocked.store(true, Ordering::SeqCst);
    let mut ready = None;
    let mut observed_local_only = false;
    for _ in 0..2000 {
        pending_setup(&mut a)?;
        if let Some(owner) = ready.as_mut() {
            progress(owner)?;
        } else if let Poll::Ready(result) = poll_setup(&mut b) {
            ready = Some(result?);
        }
        if a.finished == [true, false] && ready.is_some() {
            if !observed_local_only {
                assert!(probes[3].pending.lock().map_err(|_| "lock")?.is_none());
                observed_local_only = true;
                reverse_service.store(true, Ordering::SeqCst);
            }
            // Local TLS completion cannot stand in for the later raw packet
            // boundary. Keep the same ready owner alive until that exact send
            // has actually encountered WouldBlock, under the original bounds.
            if probes[3].pending.lock().map_err(|_| "lock")?.is_some() {
                break;
            }
        }
        tick().await;
    }
    assert!(observed_local_only);
    let ready = ready.ok_or("server did not finish local TLS flush")?;
    assert!(ready.status().paired);
    assert_eq!(a.finished, [true, false]);
    assert!(!a.status().ok_or("status")?.paired);
    let messages = a.status().ok_or("status")?.messages;
    assert_eq!(messages[0].ok_or("first")?.incoming.completed_messages, 2);
    assert_eq!(messages[1].ok_or("second")?.incoming.completed_messages, 1);
    assert!(probes[3].pending.lock().map_err(|_| "lock")?.is_some());
    assert_eq!(ready.status().deadline, original);
    tokio::time::advance(original - Instant::now()).await;
    assert!(matches!(
        poll_setup(&mut a),
        Poll::Ready(Err(PairError::Expired))
    ));
    // The other side's local success conveys neither peer completion nor clean close.
    ready.abort();
    assert_destroyed(&probes);
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn borrowed_service_cancellation_keeps_exact_blocked_packet_and_reverse_progress() -> R {
    let (mut a, mut b, probes) = paired(true).await?;
    let original = a.status().deadline;
    let before = a.status().messages[0].ok_or("first")?.outgoing;
    let payload = b"one owned message survives cancelled borrowed service";
    probes[0].blocked.store(true, Ordering::SeqCst);
    a.stage_message(PairLane::First, payload)?;
    for _ in 0..2000 {
        progress(&mut a)?;
        progress(&mut b)?;
        if probes[0].pending.lock().map_err(|_| "lock")?.is_some() {
            break;
        }
        tick().await;
    }
    let retained = probes[0]
        .pending
        .lock()
        .map_err(|_| "lock")?
        .clone()
        .ok_or("no retained packet")?;
    let sent = probes[0].sent.load(Ordering::SeqCst);
    let status = a.status();
    let bridge = status.bridges[0].ok_or("bridge")?.driver;
    assert!(bridge.raw_popped_packets > bridge.raw_sent_packets);
    let mut borrowed = Box::pin(poll_fn(|cx| match a.poll_progress(cx) {
        Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
        _ => Poll::Pending::<Result<(), PairError>>,
    }));
    assert!(
        borrowed
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending()
    );
    drop(borrowed);
    // A different original lane remains serviceable while the first driver
    // retains its WouldBlock packet. Dropping the borrow neither respawns nor
    // replaces any owner and does not charge the logical message a second time.
    let reverse = b"reverse while forward packet is retained";
    b.stage_message(PairLane::Second, reverse)?;
    for _ in 0..2000 {
        progress(&mut a)?;
        progress(&mut b)?;
        if a.message(PairLane::Second) == Some(reverse.as_slice()) {
            break;
        }
        tick().await;
    }
    assert_eq!(a.message(PairLane::Second), Some(reverse.as_slice()));
    assert_eq!(
        probes[0].pending.lock().map_err(|_| "lock")?.as_ref(),
        Some(&retained)
    );
    assert_eq!(probes[0].sent.load(Ordering::SeqCst), sent);
    assert_eq!(a.status().deadline, original);
    assert_eq!(
        a.status().messages[0]
            .ok_or("first")?
            .outgoing
            .reserved_messages,
        before.reserved_messages + 1
    );
    a.consume_message(PairLane::Second)?;
    probes[0].blocked.store(false, Ordering::SeqCst);
    for _ in 0..2000 {
        progress(&mut a)?;
        progress(&mut b)?;
        if b.message(PairLane::First) == Some(payload.as_slice())
            && !a.status().messages[0].ok_or("first")?.send_pending
        {
            break;
        }
        tick().await;
    }
    assert_eq!(b.message(PairLane::First), Some(payload.as_slice()));
    assert!(!a.status().messages[0].ok_or("first")?.send_pending);
    assert!(probes[0].pending.lock().map_err(|_| "lock")?.is_none());
    assert!(probes[0].sent.load(Ordering::SeqCst) > sent);
    assert_eq!(a.status().deadline, original);
    assert_eq!(
        a.status().messages[0]
            .ok_or("first")?
            .outgoing
            .reserved_messages,
        before.reserved_messages + 1
    );
    a.abort();
    b.abort();
    assert_destroyed(&probes);
    Ok(())
}
