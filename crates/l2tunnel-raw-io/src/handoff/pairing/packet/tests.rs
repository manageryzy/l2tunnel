use super::super::test_support::{self as support, PacketLink, Probe, R};
use super::*;
use std::{future::poll_fn, sync::atomic::Ordering};
fn config() -> PacketPhaseConfig {
    PacketPhaseConfig {
        pair: support::config(),
        packet: PacketPolicy::new(576),
    }
}
fn resize(inputs: RawInputs<PacketLink>) -> RawInputs<PacketLink> {
    let resize = |mut input: RawInput<PacketLink>| {
        input.config.send_bytes = 32_768;
        input.config.receive_bytes = 32_768;
        input.config.packet_slots = 16;
        input
    };
    match inputs {
        RawInputs::Full(a) => RawInputs::Full(resize(a)),
        RawInputs::Half { forward, reverse } => RawInputs::Half {
            forward: resize(forward),
            reverse: resize(reverse),
        },
    }
}
async fn transitioned(
    half: bool,
) -> R<(
    PacketCarrier<PacketLink>,
    PacketCarrier<PacketLink>,
    Vec<Arc<Probe>>,
)> {
    transitioned_policy(half, Protection::ChaCha20Poly1305).await
}
async fn transitioned_policy(
    half: bool,
    protection: Protection,
) -> R<(
    PacketCarrier<PacketLink>,
    PacketCarrier<PacketLink>,
    Vec<Arc<Probe>>,
)> {
    let mut config = config();
    config.packet.protection = protection;
    let (c, s, m, allowed) = support::fixture()?;
    let (a, b, probes) = support::inputs(half);
    let mut a = begin_packet_client(resize(a), &c, "tunnel.test", &m, config)?;
    let mut b = begin_packet_server(resize(b), &s, &allowed, config)?;
    let (mut ar, mut br) = (None, None);
    poll_fn(|cx| {
        for (setup, owner) in [(&mut a, &mut ar), (&mut b, &mut br)] {
            if let Some(ready) = owner {
                if let Poll::Ready(Err(e)) = PacketCarrier::poll_progress(ready, cx) {
                    return Poll::Ready(Err(e));
                }
            } else if let Poll::Ready(result) = Pin::new(setup).poll(cx) {
                *owner = Some(result?);
            }
        }
        if ar.is_some() && br.is_some() {
            Poll::Ready(Ok(()))
        } else {
            Poll::Pending
        }
    })
    .await?;
    Ok((
        ar.ok_or("client absent")?,
        br.ok_or("server absent")?,
        probes,
    ))
}
async fn transfer(
    a: &mut PacketCarrier<PacketLink>,
    b: &mut PacketCarrier<PacketLink>,
    lane: PairLane,
    kind: RecordKind,
    bytes: &[u8],
) -> R {
    a.stage_record(lane, kind, bytes)?;
    poll_fn(|cx| {
        if let Poll::Ready(Err(e)) = a.poll_progress(cx) {
            return Poll::Ready(Err(e));
        }
        if let Poll::Ready(Err(e)) = b.poll_progress(cx) {
            return Poll::Ready(Err(e));
        }
        if b.record().is_some() {
            Poll::Ready(Ok(()))
        } else {
            Poll::Pending
        }
    })
    .await?;
    let record = b.record().ok_or("record absent")?;
    assert_eq!(record.bytes, bytes);
    assert_eq!(record.lane, lane);
    assert_eq!(record.kind, kind);
    b.consume_record()?;
    Ok(())
}
#[tokio::test]
async fn actual_original_full_tls_packet_transition_and_bidirectional_records() -> R {
    let (mut a, mut b, probes) = transitioned(false).await?;
    transfer(
        &mut a,
        &mut b,
        PairLane::First,
        RecordKind::Data,
        b"client original tuple",
    )
    .await?;
    transfer(
        &mut b,
        &mut a,
        PairLane::First,
        RecordKind::Data,
        b"server original tuple",
    )
    .await?;
    assert!(probes.iter().all(|p| p.dropped.load(Ordering::SeqCst) == 0));
    a.abort();
    b.abort();
    assert!(probes.iter().all(|p| p.dropped.load(Ordering::SeqCst) == 1));
    Ok(())
}
#[tokio::test]
async fn actual_original_half_tls_packet_transition_and_bulk_direction() -> R {
    let (mut a, mut b, probes) = transitioned(true).await?;
    transfer(
        &mut a,
        &mut b,
        PairLane::First,
        RecordKind::Data,
        b"forward",
    )
    .await?;
    transfer(
        &mut b,
        &mut a,
        PairLane::Second,
        RecordKind::Data,
        b"reverse",
    )
    .await?;
    transfer(
        &mut b,
        &mut a,
        PairLane::First,
        RecordKind::Feedback,
        b"reverse feedback",
    )
    .await?;
    assert!(matches!(
        a.stage_record(PairLane::Second, RecordKind::Data, b"wrong lane"),
        Err(Error::Configuration)
    ));
    a.abort();
    b.abort();
    assert!(probes.iter().all(|p| p.dropped.load(Ordering::SeqCst) == 1));
    Ok(())
}

#[tokio::test]
async fn actual_hmac_full_and_half_original_owner_transition() -> R {
    for half in [false, true] {
        let (mut a, mut b, _) = transitioned_policy(half, Protection::HmacSha256).await?;
        transfer(
            &mut a,
            &mut b,
            PairLane::First,
            RecordKind::Data,
            b"authenticated cleartext",
        )
        .await?;
        transfer(
            &mut b,
            &mut a,
            if half {
                PairLane::Second
            } else {
                PairLane::First
            },
            RecordKind::Data,
            b"reverse authenticated cleartext",
        )
        .await?;
    }
    Ok(())
}

#[tokio::test]
async fn tracked_record_requires_actual_send_and_preserves_original_receipt_time() -> R {
    let (mut a, mut b, probes) = transitioned(false).await?;
    probes[0].blocked.store(true, Ordering::SeqCst);
    let token =
        a.stage_record_tracked(PairLane::First, RecordKind::Data, b"exact tracked bytes")?;
    let deadline = Instant::now() + Duration::from_secs(3);
    tokio::time::timeout_at(
        deadline,
        poll_fn(|cx| {
            if let Poll::Ready(Err(e)) = a.poll_progress(cx) {
                return Poll::Ready(Err(e));
            }
            if probes[0]
                .pending
                .lock()
                .map_err(|_| Error::Proof)?
                .is_some()
            {
                Poll::Ready(Ok(()))
            } else {
                cx.waker().wake_by_ref();
                Poll::Pending
            }
        }),
    )
    .await??;
    assert!(a.take_sent_record(PairLane::First)?.is_none());
    assert!(matches!(
        a.stage_record_tracked(PairLane::First, RecordKind::Data, b"cannot replace pending"),
        Err(Error::Busy)
    ));
    let released = Instant::now();
    probes[0].blocked.store(false, Ordering::SeqCst);
    tokio::time::timeout_at(
        deadline,
        poll_fn(|cx| {
            if let Poll::Ready(Err(e)) = a.poll_progress(cx) {
                return Poll::Ready(Err(e));
            }
            if let Poll::Ready(Err(e)) = b.poll_progress(cx) {
                return Poll::Ready(Err(e));
            }
            if b.record().is_some() {
                Poll::Ready(Ok(()))
            } else {
                cx.waker().wake_by_ref();
                Poll::Pending
            }
        }),
    )
    .await??;
    assert!(matches!(
        a.stage_record_tracked(
            PairLane::First,
            RecordKind::Data,
            b"completion slot remains owned"
        ),
        Err(Error::Busy)
    ));
    let sent = a
        .take_sent_record(PairLane::First)?
        .ok_or("missing send receipt")?;
    assert_eq!(sent.token, token);
    assert_eq!(sent.lane, PairLane::First);
    assert!(sent.sent_at >= released);
    assert!(a.take_sent_record(PairLane::First)?.is_none());
    let received = b.record().ok_or("missing authenticated record")?;
    assert_eq!(received.bytes, b"exact tracked bytes");
    let receipt = received.received_at;
    assert!(receipt >= sent.sent_at);
    tokio::time::sleep(Duration::from_millis(5)).await;
    assert_eq!(b.record().ok_or("retained record")?.received_at, receipt);
    b.consume_record()?;
    a.abort();
    b.abort();
    Ok(())
}

#[test]
fn maintained_raw_record_geometry_keeps_both_protections_exact() -> R {
    for (protection, overhead) in [
        (Protection::ChaCha20Poly1305, 152usize),
        (Protection::HmacSha256, 168usize),
    ] {
        let mut policy = PacketPolicy::new(1500);
        policy.protection = protection;
        let geometry = policy.record_geometry()?;
        assert_eq!(geometry.ip_tcp_bytes, 40);
        assert_eq!(
            geometry.record_overhead_bytes + geometry.ip_tcp_bytes,
            overhead
        );
        assert_eq!(geometry.max_record_bytes, policy.max_record_bytes()?);
        assert_eq!(geometry.ip_bytes(geometry.max_record_bytes)?, 1500);
        assert!(matches!(
            geometry.ip_bytes(geometry.max_record_bytes + 1),
            Err(Error::Capacity)
        ));
        assert!(matches!(geometry.ip_bytes(0), Err(Error::Capacity)));
        assert_eq!(
            policy.configuration_digest(ConfigDigest([9; 32]))?,
            policy.digest(ConfigDigest([9; 32]))?
        );
    }
    Ok(())
}
