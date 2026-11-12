use super::super::super::test_support::{self as support, PacketLink, R};
use super::*;
use std::{
    future::poll_fn,
    sync::atomic::{AtomicBool, AtomicUsize, Ordering},
};
#[derive(Default)]
struct Fault {
    drops: Mutex<Vec<usize>>,
    phases: AtomicUsize,
    blocked: AtomicBool,
    block_all: AtomicBool,
    pending: Mutex<Option<Vec<u8>>>,
}
struct Link {
    inner: PacketLink,
    fault: Arc<Fault>,
}
impl PacketIo for Link {
    fn receive(&mut self, out: &mut [u8]) -> io::Result<Option<usize>> {
        self.inner.receive(out)
    }
    fn send(&mut self, bytes: &[u8]) -> io::Result<()> {
        let phase = bytes.get(40..).is_some_and(|p| {
            l2tunnel_datagram::inspect_structural(
                CoverProfile::OpenVpnLike,
                Protection::ChaCha20Poly1305,
                536,
                472,
                p,
            )
            .is_ok()
        });
        if self.fault.block_all.load(Ordering::SeqCst)
            || (phase && self.fault.blocked.load(Ordering::SeqCst))
        {
            let mut pending = self
                .fault
                .pending
                .lock()
                .map_err(|_| io::Error::other("test lock"))?;
            if let Some(old) = pending.as_ref() {
                assert_eq!(old, bytes);
            } else {
                *pending = Some(bytes.to_vec());
            }
            return Err(io::ErrorKind::WouldBlock.into());
        }
        if phase {
            let index = self.fault.phases.fetch_add(1, Ordering::SeqCst) + 1;
            if self
                .fault
                .drops
                .lock()
                .map_err(|_| io::Error::other("test lock"))?
                .contains(&index)
            {
                return Ok(());
            }
        }
        self.inner.send(bytes)
    }
}
fn wrap(inputs: RawInputs<PacketLink>, fault: Arc<Fault>) -> RawInputs<Link> {
    let wrap = |mut input: RawInput<PacketLink>| {
        input.config.send_bytes = 32768;
        input.config.receive_bytes = 32768;
        input.config.packet_slots = 16;
        RawInput {
            config: input.config,
            io: Link {
                inner: input.io,
                fault: fault.clone(),
            },
        }
    };
    match inputs {
        RawInputs::Full(a) => RawInputs::Full(wrap(a)),
        RawInputs::Half { forward, reverse } => RawInputs::Half {
            forward: wrap(forward),
            reverse: wrap(reverse),
        },
    }
}
fn config() -> PacketPhaseConfig {
    PacketPhaseConfig {
        pair: support::config(),
        packet: PacketPolicy::new(576),
    }
}
async fn run(
    half: bool,
    a_fault: Arc<Fault>,
    b_fault: Arc<Fault>,
    early: bool,
) -> R<(PacketCarrier<Link>, PacketCarrier<Link>)> {
    let (c, s, m, allow) = support::fixture()?;
    let (a, b, _) = support::inputs(half);
    let mut a = begin_packet_client(wrap(a, a_fault), &c, "tunnel.test", &m, config())?;
    let mut b = begin_packet_server(wrap(b, b_fault), &s, &allow, config())?;
    let (mut ar, mut br) = (None, None);
    let mut early_staged = false;
    poll_fn(|cx| {
        for (setup, result) in [(&mut a, &mut ar), (&mut b, &mut br)] {
            if let Some(carrier) = result {
                if let Poll::Ready(Err(e)) = PacketCarrier::poll_progress(carrier, cx) {
                    return Poll::Ready(Err(e));
                }
            } else if let Poll::Ready(ready) = Pin::new(setup).poll(cx) {
                *result = Some(ready?);
            }
        }
        if early
            && ar.is_none()
            && !early_staged
            && let Some(server) = br.as_mut()
        {
            server.stage_record(
                if half {
                    PairLane::Second
                } else {
                    PairLane::First
                },
                RecordKind::Data,
                b"early authenticated recovery",
            )?;
            early_staged = true;
        }
        if ar.is_some() && br.is_some() {
            Poll::Ready(Ok(()))
        } else {
            Poll::Pending
        }
    })
    .await?;
    if early {
        assert!(early_staged);
    }
    Ok((ar.ok_or("client")?, br.ok_or("server")?))
}
#[tokio::test]
async fn actual_hello_commit_and_commitack_loss_retries_preserve_full_and_half_groups() -> R {
    for (half, client, index) in [
        (false, true, 1),
        (false, false, 1),
        (false, true, 2),
        (false, false, 2),
        (true, false, 3),
    ] {
        let a = Arc::new(Fault::default());
        let b = Arc::new(Fault::default());
        if client {
            a.drops.lock().map_err(|_| "test lock")?.push(index);
        } else {
            b.drops.lock().map_err(|_| "test lock")?.push(index);
        }
        let (a, b) = run(half, a, b, false).await?;
        a.abort();
        b.abort();
    }
    Ok(())
}
#[tokio::test]
async fn early_data_does_not_block_commitack_after_ready_follower_loses_first_ack() -> R {
    let a = Arc::new(Fault::default());
    let b = Arc::new(Fault::default());
    b.drops.lock().map_err(|_| "test lock")?.push(2);
    let (mut client, server) = run(false, a, b, true).await?;
    assert_eq!(
        client.record().ok_or("early record")?.bytes,
        b"early authenticated recovery"
    );
    client.consume_record()?;
    client.abort();
    server.abort();
    Ok(())
}
#[tokio::test]
async fn cancelled_borrow_keeps_exact_original_protected_packet_through_wouldblock() -> R {
    let af = Arc::new(Fault::default());
    let bf = Arc::new(Fault::default());
    let (mut a, mut b) = run(false, af.clone(), bf, false).await?;
    af.blocked.store(true, Ordering::SeqCst);
    a.stage_record(PairLane::First, RecordKind::Data, b"held bytes")?;
    for _ in 0..3 {
        poll_fn(|cx| {
            let _ = a.poll_progress(cx);
            let _ = b.poll_progress(cx);
            Poll::Ready(())
        })
        .await;
    }
    assert!(af.pending.lock().map_err(|_| "test lock")?.is_some());
    assert!(b.record().is_none());
    let before = a.lanes[0].as_ref().ok_or("lane")?.sealer.usage();
    af.blocked.store(false, Ordering::SeqCst);
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
    assert_eq!(before, a.lanes[0].as_ref().ok_or("lane")?.sealer.usage());
    assert_eq!(b.record().ok_or("record")?.bytes, b"held bytes");
    Ok(())
}
#[tokio::test(start_paused = true)]
async fn expired_cached_transition_and_old_ack_cannot_send_on_active_carrier() -> R {
    let af = Arc::new(Fault::default());
    let bf = Arc::new(Fault::default());
    let (mut a, mut b) = run(false, af.clone(), bf.clone(), false).await?;
    let now = Instant::now();
    let a_lane = a.lanes[0].as_mut().ok_or("lane")?;
    lock(&a_lane.io.state)?.deadline = now + Duration::from_millis(20);
    let config = lock(&a_lane.io.state)?.config;
    let mut old = vec![0; 40];
    packet::encode(
        config,
        a_lane.proof.next,
        a_lane.proof.receive,
        a_lane.proof.window,
        &[],
        &mut old,
    )?;
    lock(&a_lane.io.state)?.old_reply = Some(old);
    af.block_all.store(true, Ordering::SeqCst);
    a_lane.progress()?;
    assert!(a_lane.io.pending());
    let old_sent = lock(&a_lane.io.state)?.sent_packets;
    b.deadline = now + Duration::from_millis(20);
    let lane = b.lanes[0].as_mut().ok_or("lane")?;
    lock(&lane.io.state)?.deadline = b.deadline;
    bf.blocked.store(true, Ordering::SeqCst);
    let body = wire::commit(
        wire::Kind::CommitAck,
        1,
        b.commit_proof.ok_or("proof")?,
        b.info.transcript_digest,
        b.policy_digest,
    );
    lane.stage(wire::Kind::CommitAck, &body, b.transaction)?;
    lane.progress()?;
    assert!(lane.io.pending());
    let sent = bf.phases.load(Ordering::SeqCst);
    tokio::time::advance(Duration::from_millis(21)).await;
    bf.blocked.store(false, Ordering::SeqCst);
    a_lane.expire_controls()?;
    af.block_all.store(false, Ordering::SeqCst);
    a_lane.progress()?;
    assert_eq!(lock(&a_lane.io.state)?.sent_packets, old_sent);
    assert!(!a_lane.io.pending());
    assert!(lock(&a_lane.io.state)?.old_reply.is_none());
    lane.progress()?;
    assert!(lane.pending.is_none());
    assert!(!lane.io.pending());
    assert_eq!(bf.phases.load(Ordering::SeqCst), sent);
    // The old responder uses the same unchanged expiry, including held WouldBlock.
    let config = lock(&lane.io.state)?.config;
    let mut old = vec![0; 40];
    packet::encode(
        config,
        lane.proof.next,
        lane.proof.receive,
        lane.proof.window,
        &[],
        &mut old,
    )?;
    lock(&lane.io.state)?.old_reply = Some(old);
    bf.block_all.store(true, Ordering::SeqCst);
    lane.progress()?;
    assert!(!lane.io.pending());
    assert!(lock(&lane.io.state)?.old_reply.is_none());
    b.stage_record(
        PairLane::First,
        RecordKind::Data,
        b"active after setup expiry",
    )?;
    bf.block_all.store(false, Ordering::SeqCst);
    poll_fn(|cx| {
        if let Poll::Ready(Err(e)) = a.poll_progress(cx) {
            return Poll::Ready(Err(e));
        }
        if let Poll::Ready(Err(e)) = b.poll_progress(cx) {
            return Poll::Ready(Err(e));
        }
        if a.record().is_some() {
            Poll::Ready(Ok(()))
        } else {
            Poll::Pending
        }
    })
    .await?;
    assert_eq!(
        a.record().ok_or("record")?.bytes,
        b"active after setup expiry"
    );
    Ok(())
}
#[tokio::test(start_paused = true)]
async fn factory_to_first_poll_deadline_is_terminal_and_drops_originals_once() -> R {
    let (c, _, m, _) = support::fixture()?;
    let (a, b, probes) = support::inputs(false);
    drop(b);
    let mut config = config();
    config.pair.timeout = Duration::from_millis(1);
    let mut setup = begin_packet_client(
        wrap(a, Arc::new(Fault::default())),
        &c,
        "tunnel.test",
        &m,
        config,
    )?;
    tokio::time::advance(Duration::from_millis(2)).await;
    assert!(matches!(
        poll_fn(|cx| Pin::new(&mut setup).poll(cx)).await,
        Err(Error::Expired)
    ));
    assert!(probes.iter().all(|p| p.dropped.load(Ordering::SeqCst) == 1));
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn actual_fresh_liveness_pong_refreshes_both_original_lanes() -> R {
    let (mut a, mut b) = run(
        true,
        Arc::new(Fault::default()),
        Arc::new(Fault::default()),
        false,
    )
    .await?;
    let before = Instant::now();
    tokio::time::advance(Duration::from_secs(5)).await;
    poll_fn(|cx| {
        if let Poll::Ready(Err(e)) = a.poll_progress(cx) {
            return Poll::Ready(Err(e));
        }
        if let Poll::Ready(Err(e)) = b.poll_progress(cx) {
            return Poll::Ready(Err(e));
        }
        if a.lanes
            .iter()
            .chain(b.lanes.iter())
            .flatten()
            .all(|d| d.last_alive > before && d.ping.is_none())
        {
            Poll::Ready(Ok(()))
        } else {
            Poll::Pending
        }
    })
    .await?;
    Ok(())
}
