use super::test_support::*;
use super::*;
use std::{future::poll_fn, sync::atomic::Ordering, task::Waker};
#[tokio::test]
async fn actual_full_half_pairing_keeps_all_original_owners_and_keys() -> R {
    for half in [false, true] {
        let (mut a, mut b, probes) = paired(half).await?;
        assert_eq!(a.info().transcript_digest, b.info().transcript_digest);
        assert_eq!(
            a.info().lanes,
            b.info().lanes.map(|v| v.map(|mut x| {
                x.peer_member = None;
                x
            }))
        );
        assert!(a.info().is_client);
        assert!(!b.info().is_client);
        let ak = &a.group.keys.as_ref().ok_or("keys")?._values;
        let bk = &b.group.keys.as_ref().ok_or("keys")?._values;
        assert_eq!(ak, bk);
        for i in 0..a.group.profile.count * 6 {
            for j in 0..i {
                assert_ne!(ak[i], ak[j]);
            }
        }
        assert!(a.group.roots.iter().all(Option::is_none));
        transfer(&mut a, &mut b, PairLane::First, b"bounded first").await?;
        b.consume_message(PairLane::First)?;
        transfer(
            &mut b,
            &mut a,
            if half {
                PairLane::Second
            } else {
                PairLane::First
            },
            b"bounded reverse",
        )
        .await?;
        for status in [a.status(), b.status()] {
            for lane in status.messages.into_iter().flatten() {
                assert!(lane.records.incoming.wire_bytes > 0);
                assert!(lane.records.outgoing.wire_bytes > 0);
                assert!(lane.incoming.completed_messages >= 1);
                assert!(lane.outgoing.completed_messages >= 1);
            }
        }
        a.abort();
        b.abort();
        for p in probes {
            assert_eq!(p.dropped.load(Ordering::SeqCst), 1);
        }
    }
    Ok(())
}
#[tokio::test]
async fn bad_second_policy_returns_exact_unpolled_inputs_and_fractional_time_rejects() -> R {
    let (c, _, m, _) = fixture()?;
    let (a, b, probes) = inputs(true);
    drop(b);
    let RawInputs::Half {
        forward,
        mut reverse,
    } = a
    else {
        return Err("half".into());
    };
    reverse.config.receive_bytes = 0;
    let failure = begin_pair_client(
        RawInputs::Half { forward, reverse },
        &c,
        "tunnel.test",
        &m,
        config(),
    )
    .err()
    .ok_or("accepted")?;
    for i in [0, 2] {
        assert_eq!(probes[i].received.load(Ordering::SeqCst), 0);
        assert_eq!(probes[i].dropped.load(Ordering::SeqCst), 0);
    }
    drop(failure);
    for p in probes {
        assert_eq!(p.dropped.load(Ordering::SeqCst), 1);
    }
    let (a, b, _) = inputs(false);
    drop(b);
    let mut cfg = config();
    cfg.timeout += Duration::from_nanos(1);
    assert!(begin_pair_client(a, &c, "tunnel.test", &m, cfg).is_err());
    Ok(())
}
#[tokio::test(start_paused = true)]
async fn original_factory_deadline_expires_before_first_poll_and_drops_every_input() -> R {
    let (c, _, m, _) = fixture()?;
    let (a, b, probes) = inputs(true);
    drop(b);
    let mut cfg = config();
    cfg.timeout = Duration::from_millis(1);
    let setup = begin_pair_client(a, &c, "tunnel.test", &m, cfg)?;
    tokio::time::advance(Duration::from_millis(2)).await;
    assert!(matches!(setup.await, Err(PairError::Expired)));
    for p in probes {
        assert_eq!(p.received.load(Ordering::SeqCst), 0);
        assert_eq!(p.dropped.load(Ordering::SeqCst), 1);
    }
    Ok(())
}
#[tokio::test]
async fn owned_private_driver_yields_with_always_ready_noise_and_keeps_other_lane_fair() -> R {
    let (c, _, m, _) = fixture()?;
    let (a, b, probes) = inputs(true);
    drop(b);
    for i in [0, 2] {
        probes[i].noise.store(true, Ordering::SeqCst);
    }
    let mut cfg = config();
    cfg.driver.work_limit = 3;
    let mut setup = begin_pair_client(a, &c, "tunnel.test", &m, cfg)?;
    let mut cx = Context::from_waker(Waker::noop());
    for _ in 0..4 {
        let before = [
            probes[0].received.load(Ordering::SeqCst),
            probes[2].received.load(Ordering::SeqCst),
        ];
        assert!(Pin::new(&mut setup).poll(&mut cx).is_pending());
        for (j, i) in [0, 2].into_iter().enumerate() {
            let delta = probes[i].received.load(Ordering::SeqCst) - before[j];
            assert!(delta <= 3);
        }
    }
    assert!(probes[0].received.load(Ordering::SeqCst) > 0);
    assert!(probes[2].received.load(Ordering::SeqCst) > 0);
    drop(setup);
    for p in probes {
        assert_eq!(p.dropped.load(Ordering::SeqCst), 1);
    }
    Ok(())
}
#[tokio::test]
async fn slow_first_driver_expiry_stops_later_lane_io() -> R {
    let (c, _, m, _) = fixture()?;
    let (a, b, probes) = inputs(true);
    drop(b);
    let mut cfg = config();
    cfg.timeout = Duration::from_millis(20);
    let mut setup = begin_pair_client(a, &c, "tunnel.test", &m, cfg)?;
    probes[0].delay_ms.store(30, Ordering::SeqCst);
    let result = Pin::new(&mut setup).poll(&mut Context::from_waker(Waker::noop()));
    assert!(matches!(result, Poll::Ready(Err(PairError::Expired))));
    assert_eq!(probes[0].received.load(Ordering::SeqCst), 1);
    assert_eq!(probes[2].received.load(Ordering::SeqCst), 0);
    drop(setup);
    for p in probes {
        assert_eq!(p.dropped.load(Ordering::SeqCst), 1);
    }
    Ok(())
}
#[tokio::test]
async fn completed_delivery_is_retained_and_local_rejection_does_not_kill_pair() -> R {
    let (mut a, mut b, _) = paired(false).await?;
    assert!(matches!(
        a.stage_message(PairLane::Second, b"no"),
        Err(PairError::Configuration)
    ));
    assert!(a.status().fault.is_none());
    transfer(&mut a, &mut b, PairLane::First, b"one").await?;
    let old = b.status().messages[0].ok_or("status")?.incoming;
    a.stage_message(PairLane::First, b"two")?;
    for _ in 0..20 {
        poll_fn(|cx| {
            let _ = a.poll_progress(cx);
            let _ = b.poll_progress(cx);
            Poll::Ready(())
        })
        .await;
        tokio::task::yield_now().await;
    }
    assert_eq!(b.message(PairLane::First), Some(&b"one"[..]));
    assert_eq!(b.status().messages[0].ok_or("status")?.incoming, old);
    b.consume_message(PairLane::First)?;
    poll_fn(|cx| {
        if let Poll::Ready(Err(e)) = a.poll_progress(cx) {
            return Poll::Ready(Err(e));
        }
        if let Poll::Ready(Err(e)) = b.poll_progress(cx) {
            return Poll::Ready(Err(e));
        }
        if b.message(PairLane::First) == Some(&b"two"[..]) {
            Poll::Ready(Ok(()))
        } else {
            Poll::Pending
        }
    })
    .await?;
    Ok(())
}
#[test]
fn canonical_payload_resource_and_parser_boundaries() -> R {
    let cfg = config();
    let raw = raw(true, 0);
    let bytes = profile::encoding(cfg, raw, 2)?;
    assert!(bytes.len() <= 512);
    let charge = profile::payload_charge(raw, 2)?;
    assert!(charge.peak_payload > charge.retained_payload);
    let mut big = raw;
    big.packet_slots = 1024;
    big.mtu = 65_535;
    big.send_bytes = 4_194_304;
    big.receive_bytes = 4_194_304;
    assert!(matches!(
        profile::payload_charge(big, 2),
        Err(PairError::Capacity)
    ));
    let t = [0x5a; TRANSCRIPT];
    let record = encode(2, 1, &t);
    assert_eq!(decode(&record, 2, 1)?, t);
    for end in 0..RECORD {
        assert!(decode(&record[..end], 2, 1).is_err());
    }
    for index in 0..8 {
        let mut bad = record;
        bad[index] ^= 1;
        assert!(decode(&bad, 2, 1).is_err());
    }
    assert!(decode(&record, 1, 1).is_err());
    assert!(decode(&record, 2, 0).is_err());
    Ok(())
}

async fn settle(a: &mut PairedRaw<PacketLink>, b: &mut PairedRaw<PacketLink>) -> R {
    for _ in 0..100 {
        for p in [&mut *a, &mut *b] {
            if let Poll::Ready(Err(e)) = p.poll_progress(&mut Context::from_waker(Waker::noop())) {
                return Err(e.into());
            }
        }
        tokio::time::advance(Duration::from_millis(1)).await;
    }
    for _ in 0..8 {
        for p in [&mut *a, &mut *b] {
            if let Poll::Ready(Err(e)) = p.poll_progress(&mut Context::from_waker(Waker::noop())) {
                return Err(e.into());
            }
        }
    }
    Ok(())
}
#[tokio::test(start_paused = true)]
async fn actual_yielded_unpublished_bridge_read_is_retained_on_abort_and_expiry() -> R {
    for expire in [false, true] {
        let (mut a, mut b, probes) = paired(false).await?;
        settle(&mut a, &mut b).await?;
        let old = a.status().bridges[0].ok_or("bridge")?.driver.outbound_read;
        a.stage_message(PairLane::First, b"x")?;
        let mut sent = false;
        for _ in 0..16 {
            let owner = a.group.owners[0].as_mut().ok_or("owner")?;
            if let Poll::Ready(result) = owner.poll_send(&mut Context::from_waker(Waker::noop())) {
                result?;
                sent = true;
                break;
            }
        }
        assert!(sent);
        let written = a.status().bridges[0].ok_or("bridge")?.endpoint.written;
        assert!(written > old);
        // The raw driver was waiting for this bridge read. It completes that
        // actual read, then YieldOnce returns Pending before the next publish.
        a.group.drive(&mut Context::from_waker(Waker::noop()))?;
        assert_eq!(
            a.status().bridges[0].ok_or("bridge")?.driver.outbound_read,
            old
        );
        let status = if expire {
            tokio::time::advance(a.status().deadline - Instant::now()).await;
            assert!(matches!(
                a.poll_progress(&mut Context::from_waker(Waker::noop())),
                Poll::Ready(Err(PairError::Expired))
            ));
            a.status()
        } else {
            a.abort().status
        };
        assert_eq!(
            status.bridges[0].ok_or("final")?.driver.outbound_read,
            written
        );
        assert_eq!(
            status.bridges[0].ok_or("final")?.state,
            super::super::SwitchState::Failed
        );
        assert_eq!(probes[0].dropped.load(Ordering::SeqCst), 1);
        drop(b);
    }
    Ok(())
}
#[tokio::test(start_paused = true)]
async fn idle_timer_only_pass_reports_pending_not_progress() -> R {
    let (mut a, mut b, _) = paired(false).await?;
    settle(&mut a, &mut b).await?;
    let mut observed = false;
    for _ in 0..8 {
        tokio::time::advance(Duration::from_millis(1)).await;
        let before = a.status();
        let result = a.poll_progress(&mut Context::from_waker(Waker::noop()));
        let after = a.status();
        if before.bridges[0].ok_or("before")?.elapsed != after.bridges[0].ok_or("after")?.elapsed {
            assert_eq!(
                before.bridges.map(without_elapsed),
                after.bridges.map(without_elapsed)
            );
            assert_eq!(before.messages, after.messages);
            assert!(result.is_pending());
            observed = true;
        }
    }
    assert!(observed);
    Ok(())
}
