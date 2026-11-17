//! Bootstrap transaction, setup-only physical custody and original owner release.
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
    drop_final_controls: AtomicBool,
    final_control_packets: AtomicUsize,
    final_control_bytes: AtomicUsize,
    blocked: AtomicBool,
    block_all: AtomicBool,
    fail_receive: AtomicBool,
    pending: Mutex<Option<Vec<u8>>>,
}
struct Link {
    inner: PacketLink,
    fault: Arc<Fault>,
}
impl PacketIo for Link {
    fn receive(&mut self, out: &mut [u8]) -> io::Result<Option<usize>> {
        if self.fault.fail_receive.load(Ordering::SeqCst) {
            return Err(io::ErrorKind::BrokenPipe.into());
        }
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
        if bytes.get(40) == Some(&1) {
            self.fault
                .final_control_packets
                .fetch_add(1, Ordering::SeqCst);
            self.fault
                .final_control_bytes
                .fetch_add(bytes.len(), Ordering::SeqCst);
            if self.fault.drop_final_controls.load(Ordering::SeqCst) {
                return Ok(());
            }
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

// The preflight tests use only this type, never an actual PacketIo value.
struct MetadataOnly<const N: usize> {
    _bytes: [u8; N],
}
impl<const N: usize> PacketIo for MetadataOnly<N> {
    fn receive(&mut self, _: &mut [u8]) -> io::Result<Option<usize>> {
        Err(io::ErrorKind::Unsupported.into())
    }
    fn send(&mut self, _: &[u8]) -> io::Result<()> {
        Err(io::ErrorKind::Unsupported.into())
    }
}

#[test]
fn packet_phase_preflight_accepts_full_half_without_runtime_or_io_owner() -> R {
    assert!(tokio::runtime::Handle::try_current().is_err());
    for client in [false, true] {
        let first = support::raw(client, 0);
        let second = support::raw(client, 1);
        config().preflight::<MetadataOnly<0>>(first, None)?;
        config().preflight::<MetadataOnly<0>>(first, Some(second))?;
        let (_, _, full_count) = configuration::<MetadataOnly<0>>(config(), first, None)?;
        let (_, _, half_count) = configuration::<MetadataOnly<0>>(config(), first, Some(second))?;
        assert_eq!((full_count, half_count), (1, 2));
    }
    Ok(())
}

#[test]
fn packet_phase_preflight_preserves_configuration_and_geometry_refusals() -> R {
    let first = support::raw(true, 0);
    assert!(matches!(
        config().preflight::<MetadataOnly<0>>(first, Some(first)),
        Err(Error::Pair(PairError::Configuration))
    ));
    let mut second = support::raw(true, 1);
    second.receive_bytes += 1;
    assert!(matches!(
        config().preflight::<MetadataOnly<0>>(first, Some(second)),
        Err(Error::Pair(PairError::Configuration))
    ));
    let mut bad = first;
    bad.packet_slots = 1025;
    assert!(matches!(
        config().preflight::<MetadataOnly<0>>(bad, None),
        Err(Error::Pair(PairError::Configuration))
    ));
    let mut phase = config();
    phase.packet.queue_packets = 65;
    assert!(matches!(
        phase.preflight::<MetadataOnly<0>>(first, None),
        Err(Error::Configuration)
    ));
    let mut phase = config();
    phase.pair.timeout += Duration::from_nanos(1);
    assert!(matches!(
        phase.preflight::<MetadataOnly<0>>(first, None),
        Err(Error::Pair(PairError::Configuration))
    ));
    let mut phase = config();
    phase.pair.messages.bytes_per_direction = 911;
    assert!(matches!(
        phase.preflight::<MetadataOnly<0>>(first, None),
        Err(Error::Configuration)
    ));
    Ok(())
}

#[test]
fn packet_phase_preflight_preserves_payload_and_concrete_metadata_caps() -> R {
    let mut first = support::raw(true, 0);
    let mut second = support::raw(true, 1);
    for raw in [&mut first, &mut second] {
        raw.send_bytes = 4_194_304;
        raw.receive_bytes = 4_194_304;
        raw.packet_slots = 1024;
        l2tunnel_raw_tcp::IpConfig::from(*raw).validate()?;
    }
    assert!(matches!(
        config().preflight::<MetadataOnly<0>>(first, Some(second)),
        Err(Error::Pair(PairError::Capacity))
    ));
    assert!(matches!(
        config().preflight::<MetadataOnly<1_048_576>>(support::raw(true, 0), None),
        Err(Error::Capacity)
    ));
    Ok(())
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
            server.stage_setup_record(
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
    for setup in [&a, &b] {
        let snapshot = setup.diagnostic_snapshot();
        assert_eq!(snapshot.outcome, SetupOutcome::Ready);
        assert_eq!(snapshot.stage, SetupStage::PacketConfirmation);
        assert_eq!(snapshot.deadline, setup.deadline);
        assert!(snapshot.pair_stage.is_none());
    }
    Ok((ar.ok_or("client")?, br.ok_or("server")?))
}

#[tokio::test(start_paused = true)]
async fn packet_setup_snapshot_is_read_only_and_retains_original_deadline_failure() -> R {
    let (c, s, m, allow) = support::fixture()?;
    for half in [false, true] {
        let (a, b, probes) = support::inputs(half);
        let fault = Arc::new(Fault::default());
        for probe in &probes {
            probe.blocked.store(true, Ordering::SeqCst);
        }
        let mut a = begin_packet_client(wrap(a, fault.clone()), &c, "tunnel.test", &m, config())?;
        let mut b = begin_packet_server(wrap(b, fault), &s, &allow, config())?;
        let initial = a.diagnostic_snapshot();
        assert_eq!(initial.stage, SetupStage::Pairing);
        assert_eq!(initial.pair_stage, Some(SetupPairStage::Authentication));
        assert_eq!(initial.outcome, SetupOutcome::Pending);
        assert_eq!(initial.lanes[1].is_some(), half);
        for lane in initial.lanes.iter().flatten() {
            assert!(lane.messages.is_none());
            assert!(lane.transition.is_none());
            assert!(lane.control_staged.is_none());
        }
        let before: Vec<_> = probes
            .iter()
            .map(|probe| probe.received.load(Ordering::SeqCst))
            .collect();
        assert_eq!(a.diagnostic_snapshot(), initial);
        assert_eq!(a.terminal_setup.capacity(), 1);
        assert!(a.terminal_setup.is_empty());
        for (probe, before) in probes.iter().zip(before) {
            assert_eq!(probe.received.load(Ordering::SeqCst), before);
        }
        poll_fn(|cx| {
            assert!(Pin::new(&mut a).poll(cx).is_pending());
            assert!(Pin::new(&mut b).poll(cx).is_pending());
            Poll::Ready(())
        })
        .await;
        tokio::time::advance(initial.deadline - Instant::now()).await;
        for setup in [&mut a, &mut b] {
            let result = poll_fn(|cx| Pin::new(&mut *setup).poll(cx)).await;
            assert!(matches!(result, Err(Error::Expired)));
            let failed = setup.diagnostic_snapshot();
            assert_eq!(failed.deadline, initial.deadline);
            assert_eq!(failed.stage, SetupStage::Pairing);
            assert_eq!(failed.outcome, SetupOutcome::Failed);
            assert_eq!(failed.observed_at, initial.deadline);
            assert!(setup.setup.is_none());
            assert!(setup.paired.is_none());
        }
        let failed = [a.diagnostic_snapshot(), b.diagnostic_snapshot()];
        tokio::time::advance(Duration::from_millis(1)).await;
        for (setup, failed) in [&mut a, &mut b].into_iter().zip(failed) {
            assert!(poll_fn(|cx| Pin::new(&mut *setup).poll(cx)).await.is_err());
            assert_eq!(setup.diagnostic_snapshot(), failed);
        }
        assert!(
            probes
                .iter()
                .all(|probe| probe.dropped.load(Ordering::SeqCst) == 1)
        );
    }
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn packet_setup_snapshot_keeps_detached_confirmation_before_terminal_release() -> R {
    let (c, s, m, allow) = support::fixture()?;
    let (a, b, probes) = support::inputs(false);
    let af = Arc::new(Fault::default());
    let bf = Arc::new(Fault::default());
    af.blocked.store(true, Ordering::SeqCst);
    bf.blocked.store(true, Ordering::SeqCst);
    let mut a = begin_packet_client(wrap(a, af), &c, "tunnel.test", &m, config())?;
    let mut b = begin_packet_server(wrap(b, bf), &s, &allow, config())?;
    poll_fn(|cx| {
        for setup in [&mut a, &mut b] {
            match Pin::new(&mut *setup).poll(cx) {
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Ready(Ok(_)) => return Poll::Ready(Err(Error::Proof)),
                Poll::Pending => {}
            }
        }
        if a.stage == 5 && b.stage == 5 {
            Poll::Ready(Ok(()))
        } else {
            Poll::Pending
        }
    })
    .await?;
    let pending = a.diagnostic_snapshot();
    assert_eq!(pending.stage, SetupStage::PacketConfirmation);
    assert!(pending.lanes.iter().flatten().all(|lane| lane.frozen));
    assert!(pending.pair_stage.is_none());
    for lane in pending.lanes.iter().flatten() {
        assert!(lane.messages.is_some());
        assert!(lane.transition.is_some());
        assert!(lane.gate.ok_or("gate observation")?.installed);
    }
    tokio::time::advance(a.deadline - Instant::now()).await;
    for setup in [&mut a, &mut b] {
        assert!(matches!(
            poll_fn(|cx| Pin::new(&mut *setup).poll(cx)).await,
            Err(Error::Expired)
        ));
        let failed = setup.diagnostic_snapshot();
        assert_eq!(failed.stage, SetupStage::PacketConfirmation);
        assert_eq!(failed.outcome, SetupOutcome::Failed);
        assert!(
            failed
                .lanes
                .iter()
                .flatten()
                .all(|lane| lane.transition.is_some())
        );
        assert!(setup.carrier.is_none());
        assert_eq!(setup.terminal_setup.len(), 1);
    }
    assert!(
        probes
            .iter()
            .all(|probe| probe.dropped.load(Ordering::SeqCst) == 1)
    );
    Ok(())
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
    let arrival = client
        .record()
        .ok_or("actual authenticated raw input")?
        .received_at;
    let earliest = client
        .earliest_authenticated_record_at()?
        .ok_or("retained raw arrival")?;
    assert!(earliest <= arrival);
    assert_eq!(client.earliest_authenticated_record_at()?, Some(earliest));
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
    a.stage_setup_record(PairLane::First, RecordKind::Data, b"held bytes")?;
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
    let before = a.lanes[0]
        .as_ref()
        .ok_or("lane")?
        .sealer
        .as_ref()
        .ok_or("bootstrap protector")?
        .usage();
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
    assert_eq!(
        before,
        a.lanes[0]
            .as_ref()
            .ok_or("lane")?
            .sealer
            .as_ref()
            .ok_or("bootstrap protector")?
            .usage()
    );
    assert_eq!(b.record().ok_or("record")?.bytes, b"held bytes");
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn late_expiry_preserves_each_actual_original_lane_send_once() -> R {
    let af = Arc::new(Fault::default());
    let bf = Arc::new(Fault::default());
    let (mut a, mut b) = run(true, af, bf, false).await?;
    let first = a.stage_setup_record_tracked(PairLane::First, RecordKind::Data, b"source\0\xff")?;
    let second =
        a.stage_setup_record_tracked(PairLane::Second, RecordKind::Feedback, b"control\xff\0")?;
    poll_fn(|cx| {
        for carrier in [&mut a, &mut b] {
            if let Poll::Ready(Err(error)) = carrier.poll_progress(cx) {
                return Poll::Ready(Err(error));
            }
        }
        if a.lanes
            .iter()
            .flatten()
            .all(|lane| lane.completed.is_some())
            && b.records.len() == 2
        {
            Poll::Ready(Ok(()))
        } else {
            Poll::Pending
        }
    })
    .await?;
    let accepted: Vec<_> = a
        .lanes
        .iter()
        .flatten()
        .map(|lane| lane.completed.ok_or("missing actual send receipt"))
        .collect::<Result<_, _>>()?;
    assert_eq!(accepted.len(), 2);
    assert_eq!(accepted[0].token, first);
    assert_eq!(accepted[1].token, second);
    for _ in 0..2 {
        let record = b.record().ok_or("missing protected peer record")?;
        match record.lane {
            PairLane::First => assert_eq!(record.bytes, b"source\0\xff"),
            PairLane::Second => assert_eq!(record.bytes, b"control\xff\0"),
        }
        b.consume_record()?;
    }
    tokio::time::advance(Duration::from_secs(16)).await;
    // Legacy refusal still releases I/O. The explicit observer retains only
    // already completed physical facts, not the carrier or pending ciphertext.
    assert!(matches!(
        a.take_sent_record(PairLane::First),
        Err(Error::Expired)
    ));
    assert!(a.lanes.iter().all(Option::is_none));
    for (lane, accepted) in [PairLane::First, PairLane::Second]
        .into_iter()
        .zip(accepted)
    {
        let observed = a.take_sent_record_observed(lane)?;
        assert!(matches!(observed.failure, Some(Error::Expired)));
        let sent = observed.sent.ok_or("late physical receipt was lost")?;
        assert_eq!(sent.token, accepted.token);
        assert_eq!(sent.lane, lane);
        assert_eq!(sent.sent_at, accepted.sent_at);
        let repeated = a.take_sent_record_observed(lane)?;
        assert!(repeated.sent.is_none());
        assert!(matches!(repeated.failure, Some(Error::Expired)));
    }
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn failed_physical_observer_never_invents_an_unsent_wouldblock_receipt() -> R {
    let af = Arc::new(Fault::default());
    let bf = Arc::new(Fault::default());
    let (mut a, mut b) = run(false, af.clone(), bf, false).await?;
    af.blocked.store(true, Ordering::SeqCst);
    a.stage_setup_record_tracked(PairLane::First, RecordKind::Data, b"not physically sent")?;
    for _ in 0..3 {
        poll_fn(|cx| {
            let _ = a.poll_progress(cx);
            let _ = b.poll_progress(cx);
            Poll::Ready(())
        })
        .await;
    }
    let held = af.pending.lock().map_err(|_| "test lock")?.clone();
    assert!(held.is_some());
    assert!(a.lanes[0].as_ref().ok_or("lane")?.completed.is_none());
    // A nonexistent lane is rejected before expiry or any receipt is consumed.
    tokio::time::advance(Duration::from_secs(16)).await;
    assert!(matches!(
        a.take_sent_record_observed(PairLane::Second),
        Err(Error::Configuration),
    ));
    assert!(a.fault.is_none());
    assert!(a.lanes[0].is_some());
    let observed = a.take_sent_record_observed(PairLane::First)?;
    assert!(observed.sent.is_none());
    assert!(matches!(observed.failure, Some(Error::Expired)));
    assert!(a.lanes.iter().all(Option::is_none));
    assert_eq!(*af.pending.lock().map_err(|_| "test lock")?, held);
    let repeated = a.take_sent_record_observed(PairLane::First)?;
    assert!(repeated.sent.is_none());
    assert!(matches!(repeated.failure, Some(Error::Expired)));
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn physical_observer_preserves_first_failure_and_legacy_successful_receipts() -> R {
    let af = Arc::new(Fault::default());
    let bf = Arc::new(Fault::default());
    let (mut a, mut b) = run(false, af.clone(), bf, false).await?;
    let token =
        a.stage_setup_record_tracked(PairLane::First, RecordKind::Data, b"physical fact")?;
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
    let original = a.lanes[0]
        .as_ref()
        .ok_or("lane")?
        .completed
        .ok_or("receipt")?;
    af.fail_receive.store(true, Ordering::SeqCst);
    let failed = poll_fn(|cx| Poll::Ready(a.poll_progress(cx))).await;
    assert!(matches!(
        failed,
        Poll::Ready(Err(Error::Io {
            kind: io::ErrorKind::BrokenPipe,
            ..
        })),
    ));
    assert!(matches!(
        a.fail(Error::Expired),
        Error::Io {
            kind: io::ErrorKind::BrokenPipe,
            ..
        },
    ));
    let observed = a.take_sent_record_observed(PairLane::First)?;
    let sent = observed.sent.ok_or("failed physical receipt was lost")?;
    assert_eq!(sent.token, token);
    assert_eq!(sent.sent_at, original.sent_at);
    assert!(matches!(
        observed.failure,
        Some(Error::Io {
            kind: io::ErrorKind::BrokenPipe,
            ..
        }),
    ));
    assert!(a.take_sent_record_observed(PairLane::First)?.sent.is_none());

    let (mut a, mut b) = run(
        false,
        Arc::new(Fault::default()),
        Arc::new(Fault::default()),
        false,
    )
    .await?;
    let token =
        a.stage_setup_record_tracked(PairLane::First, RecordKind::Data, b"legacy receipt")?;
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
    assert_eq!(
        a.take_sent_record(PairLane::First)?
            .ok_or("legacy receipt")?
            .token,
        token
    );
    let observed = a.take_sent_record_observed(PairLane::First)?;
    assert!(observed.sent.is_none());
    assert!(observed.failure.is_none());
    let token =
        a.stage_setup_record_tracked(PairLane::First, RecordKind::Data, b"live observer")?;
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
    let observed = a.take_sent_record_observed(PairLane::First)?;
    assert_eq!(observed.sent.ok_or("live receipt")?.token, token);
    assert!(observed.failure.is_none());
    let repeated = a.take_sent_record_observed(PairLane::First)?;
    assert!(repeated.sent.is_none());
    assert!(repeated.failure.is_none());
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
    assert!(matches!(
        b.stage_setup_record(PairLane::First, RecordKind::Data, b"expired setup retry"),
        Err(Error::Expired)
    ));
    assert!(b.lanes.iter().all(Option::is_none));
    assert!(matches!(b.check_live(), Err(Error::Expired)));
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

#[tokio::test(start_paused = true)]
async fn half_one_way_records_return_same_lane_window_after_actual_physical_send() -> R {
    let af = Arc::new(Fault::default());
    let bf = Arc::new(Fault::default());
    let (mut a, mut b) = run(true, af, bf.clone(), false).await?;
    tokio::time::timeout(Duration::from_secs(1), async {
        // Finish existing transition output before holding the real reverse
        // packet adapter; no transition owner or original cap is replaced.
        poll_fn(|cx| {
            for carrier in [&mut a, &mut b] {
                if let Poll::Ready(Err(error)) = carrier.poll_progress(cx) {
                    return Poll::Ready(Err(error));
                }
            }
            if [&a, &b].into_iter().all(|carrier| {
                carrier
                    .lanes
                    .iter()
                    .flatten()
                    .all(|lane| lane.pending.is_none())
            }) {
                Poll::Ready(Ok(()))
            } else {
                Poll::Pending
            }
        })
        .await?;
        let start = lock(&a.lanes[0].as_ref().ok_or("lane")?.io.state)?
            .fence
            .as_ref()
            .ok_or("fence")?
            .sent;
        let horizon = lock(&a.lanes[0].as_ref().ok_or("lane")?.io.state)?
            .fence
            .as_ref()
            .ok_or("fence")?
            .peer_horizon;
        let threshold = b.lanes[0].as_ref().ok_or("lane")?.retirement_threshold()?;
        let mut body = [0x5a; 384];
        bf.block_all.store(true, Ordering::SeqCst);
        let mut next = 0u16;
        // Real one-way arrivals cross the actual horizon-derived batching
        // threshold. Below it no standalone Window may consume a nonce.
        loop {
            assert!(next < 96);
            body[..2].copy_from_slice(&next.to_be_bytes());
            let token = a.stage_setup_record_tracked(PairLane::First, RecordKind::Data, &body)?;
            let mut sent = None;
            let mut received = false;
            poll_fn(|cx| {
                for carrier in [&mut a, &mut b] {
                    if let Poll::Ready(Err(error)) = carrier.poll_progress(cx) {
                        return Poll::Ready(Err(error));
                    }
                }
                if sent.is_none() {
                    sent = a.take_sent_record(PairLane::First)?;
                }
                if let Some(record) = b.record() {
                    assert_eq!(record.bytes, body);
                    assert!(!received);
                    b.consume_record()?;
                    received = true;
                }
                if sent.is_some() && received {
                    Poll::Ready(Ok(()))
                } else {
                    Poll::Pending
                }
            })
            .await?;
            assert_eq!(sent.ok_or("source receipt")?.token, token);
            next += 1;
            let lane = b.lanes[0].as_ref().ok_or("lane")?;
            if lane
                .retirement_required
                .saturating_sub(lane.retirement_reported)
                >= threshold
            {
                break;
            }
            assert!(
                !lane
                    .pending
                    .as_ref()
                    .is_some_and(|pending| pending.kind == wire::Kind::Window),
                "below-threshold arrival must stay coalesced"
            );
        }
        poll_fn(|cx| {
            for carrier in [&mut a, &mut b] {
                if let Poll::Ready(Err(error)) = carrier.poll_progress(cx) {
                    return Poll::Ready(Err(error));
                }
            }
            if b.lanes[0].as_ref().is_some_and(|lane| {
                lane.pending
                    .as_ref()
                    .is_some_and(|pending| pending.kind == wire::Kind::Window)
            }) {
                Poll::Ready(Ok(()))
            } else {
                Poll::Pending
            }
        })
        .await?;
        let lane = b.lanes[0].as_ref().ok_or("lane")?;
        let required = lane.retirement_required;
        let reported = lane.retirement_reported;
        assert!(required.saturating_sub(reported) >= threshold);
        let frozen = lane.pending.as_ref().ok_or("held window")?.bytes.clone();
        let usage = lane.sealer.as_ref().ok_or("bootstrap protector")?.usage();
        for _ in 0..4 {
            poll_fn(|cx| {
                if let Poll::Ready(Err(error)) = b.poll_progress(cx) {
                    return Poll::Ready(Err(error));
                }
                Poll::Ready(Ok(()))
            })
            .await?;
            let lane = b.lanes[0].as_ref().ok_or("lane")?;
            assert_eq!(lane.pending.as_ref().ok_or("held window")?.bytes, frozen);
            assert_eq!(lane.retirement_reported, reported);
            assert_eq!(
                lane.sealer.as_ref().ok_or("bootstrap protector")?.usage(),
                usage
            );
        }
        bf.block_all.store(false, Ordering::SeqCst);
        poll_fn(|cx| {
            for carrier in [&mut a, &mut b] {
                if let Poll::Ready(Err(error)) = carrier.poll_progress(cx) {
                    return Poll::Ready(Err(error));
                }
            }
            let peer_retired = lock(&a.lanes[0].as_ref().ok_or(Error::Proof)?.io.state)?
                .fence
                .as_ref()
                .ok_or(Error::Proof)?
                .peer_retired;
            if peer_retired >= required {
                Poll::Ready(Ok(()))
            } else {
                Poll::Pending
            }
        })
        .await?;
        assert!(b.lanes[0].as_ref().ok_or("lane")?.retirement_reported >= required);
        // More real one-way records than the original finite lane horizon.
        // There is no upper reverse payload or fabricated retirement credit.
        for number in next..96 {
            body[..2].copy_from_slice(&number.to_be_bytes());
            let mut token = None;
            let mut written = false;
            let mut received = false;
            poll_fn(|cx| {
                if token.is_none() {
                    match a.stage_setup_record_tracked(PairLane::First, RecordKind::Data, &body) {
                        Ok(value) => token = Some(value),
                        Err(Error::Busy) => {}
                        Err(error) => return Poll::Ready(Err(error)),
                    }
                }
                for carrier in [&mut a, &mut b] {
                    if let Poll::Ready(Err(error)) = carrier.poll_progress(cx) {
                        return Poll::Ready(Err(error));
                    }
                }
                if let Some(sent) = a.take_sent_record(PairLane::First)? {
                    assert_eq!(Some(sent.token), token);
                    assert!(!written);
                    written = true;
                }
                if let Some(record) = b.record() {
                    assert_eq!(record.kind, RecordKind::Data);
                    assert_eq!(record.lane, PairLane::First);
                    assert_eq!(record.bytes, body);
                    assert!(!received);
                    b.consume_record()?;
                    received = true;
                }
                assert!(a.record().is_none(), "Window is not an upper record");
                if written && received {
                    Poll::Ready(Ok(()))
                } else {
                    Poll::Pending
                }
            })
            .await?;
        }
        let end = lock(&a.lanes[0].as_ref().ok_or("lane")?.io.state)?
            .fence
            .as_ref()
            .ok_or("fence")?
            .sent;
        assert!(end - start > horizon);
        poll_fn(|cx| {
            for carrier in [&mut a, &mut b] {
                if let Poll::Ready(Err(error)) = carrier.poll_progress(cx) {
                    return Poll::Ready(Err(error));
                }
            }
            if b.lanes[0].as_ref().is_some_and(|lane| {
                lane.retirement_required
                    .saturating_sub(lane.retirement_reported)
                    < threshold
                    && lane.pending.is_none()
            }) {
                Poll::Ready(Ok(()))
            } else {
                Poll::Pending
            }
        })
        .await?;
        let quiet = [
            a.lanes[0]
                .as_ref()
                .ok_or("lane")?
                .sealer
                .as_ref()
                .ok_or("bootstrap protector")?
                .usage(),
            b.lanes[0]
                .as_ref()
                .ok_or("lane")?
                .sealer
                .as_ref()
                .ok_or("bootstrap protector")?
                .usage(),
        ];
        for _ in 0..4 {
            poll_fn(|cx| {
                for carrier in [&mut a, &mut b] {
                    if let Poll::Ready(Err(error)) = carrier.poll_progress(cx) {
                        return Poll::Ready(Err(error));
                    }
                }
                Poll::Ready(Ok(()))
            })
            .await?;
        }
        assert_eq!(
            quiet,
            [
                a.lanes[0]
                    .as_ref()
                    .ok_or("lane")?
                    .sealer
                    .as_ref()
                    .ok_or("bootstrap protector")?
                    .usage(),
                b.lanes[0]
                    .as_ref()
                    .ok_or("lane")?
                    .sealer
                    .as_ref()
                    .ok_or("bootstrap protector")?
                    .usage()
            ]
        );
        Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
    })
    .await??;
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn full_upper_feedback_piggybacks_retirement_before_idle_window_claims_slot() -> R {
    let (mut a, mut b) = run(
        false,
        Arc::new(Fault::default()),
        Arc::new(Fault::default()),
        false,
    )
    .await?;
    tokio::time::timeout(Duration::from_secs(1), async {
        poll_fn(|cx| {
            for carrier in [&mut a, &mut b] {
                if let Poll::Ready(Err(error)) = carrier.poll_progress(cx) {
                    return Poll::Ready(Err(error));
                }
            }
            if [&a, &b].into_iter().all(|carrier| {
                carrier
                    .lanes
                    .iter()
                    .flatten()
                    .all(|lane| lane.pending.is_none())
            }) {
                Poll::Ready(Ok(()))
            } else {
                Poll::Pending
            }
        })
        .await?;
        a.stage_setup_record(PairLane::First, RecordKind::Data, b"actual upper source")?;
        poll_fn(|cx| {
            for carrier in [&mut a, &mut b] {
                if let Poll::Ready(Err(error)) = carrier.poll_progress(cx) {
                    return Poll::Ready(Err(error));
                }
            }
            if b.record().is_some() {
                Poll::Ready(Ok(()))
            } else {
                Poll::Pending
            }
        })
        .await?;
        assert_eq!(b.record().ok_or("source")?.bytes, b"actual upper source");
        b.consume_record()?;
        let lane = b.lanes[0].as_ref().ok_or("lane")?;
        let required = lane.retirement_required;
        assert!(required > lane.retirement_reported);
        assert!(
            lane.pending.is_none(),
            "new receive must leave the real upper output opportunity"
        );
        let token = b.stage_setup_record_tracked(
            PairLane::First,
            RecordKind::Feedback,
            b"actual upper feedback",
        )?;
        let mut sent = None;
        poll_fn(|cx| {
            for carrier in [&mut a, &mut b] {
                if let Poll::Ready(Err(error)) = carrier.poll_progress(cx) {
                    return Poll::Ready(Err(error));
                }
            }
            if sent.is_none() {
                sent = b.take_sent_record(PairLane::First)?;
            }
            if sent.is_some() && a.record().is_some() {
                Poll::Ready(Ok(()))
            } else {
                Poll::Pending
            }
        })
        .await?;
        assert_eq!(sent.ok_or("feedback receipt")?.token, token);
        assert_eq!(
            a.record().ok_or("feedback")?.bytes,
            b"actual upper feedback"
        );
        a.consume_record()?;
        assert!(b.lanes[0].as_ref().ok_or("lane")?.retirement_reported >= required);
        Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
    })
    .await??;
    Ok(())
}

#[path = "compact_tests.rs"]
mod compact_tests;

mod transition_reservation {
    use super::*;

    fn reservation_inputs(inputs: RawInputs<PacketLink>, fault: Arc<Fault>) -> R<RawInputs<Link>> {
        let RawInputs::Full(mut input) = wrap(inputs, fault) else {
            return Err("full reservation fixture required".into());
        };
        // The ordinary sixteen-slot fixture advertises only 16 * 536 bytes,
        // which correctly stops at twenty-one unretired Hellos. This test needs
        // enough actual initial window to reach the existing transition limit.
        input.config.packet_slots = 32;
        Ok(RawInputs::Full(input))
    }

    fn failure(
        stage: &str,
        losses: (bool, bool),
        a: &PacketSetup<'_, Link>,
        b: &PacketSetup<'_, Link>,
        error: &dyn std::fmt::Display,
    ) -> Box<dyn std::error::Error + Send + Sync> {
        format!(
            "delayed Hello {stage}, lost Commit/Ack={losses:?}, now={:?}: {error}; client={:?}; server={:?}",
            Instant::now(),
            a.diagnostic_snapshot(),
            b.diagnostic_snapshot(),
        )
        .into()
    }

    fn poll_peer(
        setup: &mut PacketSetup<'_, Link>,
        ready: &mut Option<PacketCarrier<Link>>,
        fault: &Fault,
        lose: Option<wire::Kind>,
        loss_observed: &mut bool,
        cx: &mut Context<'_>,
    ) -> R {
        let carrier = ready.as_ref().or(setup.carrier.as_ref());
        if !*loss_observed
            && let Some(kind) = lose
            && carrier.is_some_and(|carrier| {
                carrier.lanes[0]
                    .as_ref()
                    .and_then(|lane| lane.pending.as_ref())
                    .is_some_and(|pending| pending.kind == kind)
            })
        {
            // The test targets the actual selected phase, not ciphertext shape
            // or a guessed ordinal. PacketIo still reports a complete lost send.
            let index = fault.phases.load(Ordering::SeqCst) + 1;
            fault.drops.lock().map_err(|_| "test lock")?.push(index);
            *loss_observed = true;
        }
        if let Some(carrier) = ready {
            if let Poll::Ready(Err(error)) = carrier.poll_progress(cx) {
                return Err(error.into());
            }
        } else if let Poll::Ready(result) = Pin::new(setup).poll(cx) {
            *ready = Some(result?);
        }
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn delayed_peer_hello_reserves_original_final_attempts_and_keeps_loss_recovery() -> R {
        for (lose_commit, lose_ack) in [(false, false), (true, false), (false, true), (true, true)]
        {
            let (c, s, m, allow) = support::fixture()?;
            let (a, b, _) = support::inputs(false);
            let af = Arc::new(Fault::default());
            let bf = Arc::new(Fault::default());
            // Retain the server's exact first Hello in actual PacketIo custody.
            // The client keeps receiving no peer Hello while its sends complete.
            bf.blocked.store(true, Ordering::SeqCst);
            let mut a = begin_packet_client(
                reservation_inputs(a, af.clone())?,
                &c,
                "tunnel.test",
                &m,
                config(),
            )?;
            let mut b =
                begin_packet_server(reservation_inputs(b, bf.clone())?, &s, &allow, config())?;
            let original_caps = [a.deadline, b.deadline];
            poll_fn(|cx| -> Poll<R> {
                for setup in [&mut a, &mut b] {
                    match Pin::new(&mut *setup).poll(cx) {
                        Poll::Ready(Err(error)) => return Poll::Ready(Err(error.into())),
                        Poll::Ready(Ok(_)) => {
                            return Poll::Ready(Err("early completion".into()));
                        }
                        Poll::Pending => {}
                    }
                }
                if a.carrier.is_some()
                    && b.carrier.is_some()
                    && bf.pending.lock().map_err(|_| "test lock")?.is_some()
                {
                    Poll::Ready(Ok(()))
                } else {
                    Poll::Pending
                }
            })
            .await
            .map_err(|error| {
                failure("bootstrap", (lose_commit, lose_ack), &a, &b, error.as_ref())
            })?;
            let hello_bytes = config().packet.overhead() - 40 + wire::HEADER + wire::HELLO;
            for setup in [&a, &b] {
                let lane = setup
                    .carrier
                    .as_ref()
                    .and_then(|carrier| carrier.lanes[0].as_ref())
                    .ok_or("actual reservation lane")?;
                let state = lock(&lane.io.state)?;
                let fence = state.fence.as_ref().ok_or("actual reservation fence")?;
                assert!(
                    fence.peer_horizon >= u64::from(TRANSITION_MAX_COPIES) * hello_bytes as u64,
                    "the actual peer window must admit all transition copies without returned retirement"
                );
            }
            poll_fn(|cx| -> Poll<R> {
                for setup in [&mut a, &mut b] {
                    match Pin::new(&mut *setup).poll(cx) {
                        Poll::Ready(Err(error)) => return Poll::Ready(Err(error.into())),
                        Poll::Ready(Ok(_)) => return Poll::Ready(Err("early completion".into())),
                        Poll::Pending => {}
                    }
                }
                if a.carrier.as_ref().is_some_and(|carrier| {
                    carrier.lanes[0].as_ref().is_some_and(|lane| {
                        lane.copies == TRANSITION_MAX_COPIES - TRANSITION_FINAL_RESERVE
                            && lane.pending.is_none()
                    })
                }) {
                    Poll::Ready(Ok(()))
                } else {
                    Poll::Pending
                }
            })
            .await
            .map_err(|error| {
                failure(
                    "waiting for thirty Hellos",
                    (lose_commit, lose_ack),
                    &a,
                    &b,
                    error.as_ref(),
                )
            })?;
            // Cross the old thirty-two-Hello exhaustion interval without
            // renewing setup, resetting copies or changing the retry cadence.
            tokio::time::advance(Duration::from_secs(1)).await;
            poll_fn(|cx| -> Poll<R> {
                for setup in [&mut a, &mut b] {
                    if let Poll::Ready(result) = Pin::new(setup).poll(cx) {
                        return Poll::Ready(Err(match result {
                            Err(error) => error.into(),
                            Ok(_) => "early completion".into(),
                        }));
                    }
                }
                Poll::Ready(Ok(()))
            })
            .await
            .map_err(|error| {
                failure(
                    "after the delayed interval",
                    (lose_commit, lose_ack),
                    &a,
                    &b,
                    error.as_ref(),
                )
            })?;
            let client = a.carrier.as_ref().ok_or("actual client carrier")?;
            let lane = client.lanes[0].as_ref().ok_or("actual client lane")?;
            assert_eq!(lane.copies, 30);
            assert!(!lane.hello);
            assert!(lane.transition_kind(true, false, false, false).is_none());
            assert!(client.next_wake()? > Instant::now());
            assert_eq!(af.phases.load(Ordering::SeqCst), 30);
            assert_eq!([a.deadline, b.deadline], original_caps);
            assert_eq!(
                b.carrier
                    .as_ref()
                    .and_then(|carrier| carrier.lanes[0].as_ref())
                    .and_then(|lane| lane.pending.as_ref())
                    .map(|pending| pending.kind),
                Some(wire::Kind::Hello),
                "the withheld packet must be the server's actual first Hello"
            );
            bf.blocked.store(false, Ordering::SeqCst);
            let (mut ar, mut br) = (None, None);
            let (mut commit_lost, mut ack_lost) = (false, false);
            poll_fn(|cx| -> Poll<R> {
                poll_peer(
                    &mut a,
                    &mut ar,
                    &af,
                    lose_commit.then_some(wire::Kind::Commit),
                    &mut commit_lost,
                    cx,
                )?;
                poll_peer(
                    &mut b,
                    &mut br,
                    &bf,
                    lose_ack.then_some(wire::Kind::CommitAck),
                    &mut ack_lost,
                    cx,
                )?;
                if ar.is_some() && br.is_some() {
                    Poll::Ready(Ok(()))
                } else {
                    Poll::Pending
                }
            })
            .await
            .map_err(|error| {
                failure(
                    "completing final phases",
                    (lose_commit, lose_ack),
                    &a,
                    &b,
                    error.as_ref(),
                )
            })?;
            assert_eq!((commit_lost, ack_lost), (lose_commit, lose_ack));
            let client = ar.ok_or("ready client")?;
            let server = br.ok_or("ready server")?;
            for (carrier, cap) in [(&client, original_caps[0]), (&server, original_caps[1])] {
                assert!(carrier.ready);
                assert_eq!(carrier.setup_deadline(), cap);
                assert!(Instant::now() < cap);
                assert!(carrier.lanes.iter().flatten().all(|lane| lane.copies <= 32));
            }
            assert!(client.lanes[0].as_ref().ok_or("client lane")?.sent_commit);
            assert!(server.lanes[0].as_ref().ok_or("server lane")?.sent_ack);
            assert!(af.phases.load(Ordering::SeqCst) <= 32);
            assert!(bf.phases.load(Ordering::SeqCst) <= 32);
            client.abort();
            server.abort();
        }
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn reserved_attempt_selection_and_wake_preserve_total_limit_and_original_expiry() -> R {
        let (mut client, server) = run(
            false,
            Arc::new(Fault::default()),
            Arc::new(Fault::default()),
            false,
        )
        .await?;
        // Exercise both roles' selection against the same actual retained lane;
        // no packets are sent while setting up these finite boundary states.
        let lane = client.lanes[0].as_mut().ok_or("actual lane")?;
        assert!(lane.pending.is_none());
        lane.copies = 30;
        lane.hello_reply = true;
        lane.last_transition_kind = Some(wire::Kind::Commit);
        assert_eq!(
            lane.transition_kind(true, false, true, false),
            Some(wire::Kind::Commit)
        );
        assert_eq!(
            lane.transition_kind(false, false, true, true),
            Some(wire::Kind::CommitAck)
        );
        assert_eq!(lane.transition_kind(false, false, true, false), None);
        assert_eq!(lane.transition_kind(true, false, false, false), None);
        lane.copies = 31;
        assert_eq!(
            lane.transition_kind(true, false, true, false),
            Some(wire::Kind::Commit)
        );
        lane.copies = 32;
        assert_eq!(lane.transition_kind(true, false, true, false), None);
        assert_eq!(lane.transition_kind(false, false, true, true), None);
        assert!(!lane.retry_due(Instant::now() + Duration::from_secs(1)));
        client.ready = false;
        lane.last_transition = Some(Instant::now() - Duration::from_secs(1));
        // Refresh only the existing physical-service tick to exclude that
        // independent ready event from this transition-deadline assertion.
        client
            .tick
            .as_mut()
            .reset(Instant::now() + Duration::from_millis(1));
        assert!(client.next_wake()? > Instant::now());
        let cap = client.setup_deadline();
        tokio::time::advance(cap - Instant::now()).await;
        assert!(matches!(client.check_live(), Err(Error::Expired)));
        assert!(client.lanes.iter().all(Option::is_none));
        assert_eq!(client.setup_deadline(), cap);
        server.abort();
        Ok(())
    }
}

#[tokio::test(start_paused = true)]
async fn actual_pair_hello_loss_reports_stale_window_proof_without_weakening_authentication() -> R {
    let (c, s, member, allow) = support::fixture()?;
    let (a_input, b_input, _) = support::inputs(false);
    let af = Arc::new(Fault::default());
    let bf = Arc::new(Fault::default());
    af.drops.lock().map_err(|_| "fault lock")?.push(1);
    bf.drops.lock().map_err(|_| "fault lock")?.extend([1, 2]);
    let mut a = begin_packet_client(
        wrap(a_input, af.clone()),
        &c,
        "tunnel.test",
        &member,
        config(),
    )?;
    let mut b = begin_packet_server(wrap(b_input, bf.clone()), &s, &allow, config())?;
    let deadlines = [a.deadline, b.deadline];
    // Stop the actual original owners immediately after TCP/TLS handoff and
    // before either first Hello. No fabricated authentication or carrier is used.
    poll_fn(|cx| {
        for setup in [&mut a, &mut b] {
            if setup.stage < 5
                && let Poll::Ready(result) = Pin::new(setup).poll(cx)
            {
                return Poll::Ready(Err(match result {
                    Ok(_) => "unexpected ready carrier before Hello".into(),
                    Err(error) => Box::new(error) as Box<dyn std::error::Error + Send + Sync>,
                }));
            }
        }
        if a.stage == 5 && b.stage == 5 {
            Poll::Ready(Ok(()))
        } else {
            Poll::Pending
        }
    })
    .await?;
    let carrier = a.carrier.as_mut().ok_or("client carrier")?;
    let lane = carrier.lanes[0].as_mut().ok_or("client lane")?;
    let shift = if lane.proof.peer_scale == 255 {
        0
    } else {
        lane.proof.peer_scale
    };
    let actual_peer_window = lane.proof.peer_window;
    // Fault injection models a frozen peer observation preceding a legal TCP
    // window update. This fixture proves branch attribution after real encrypted
    // Hello loss/retry; it does not claim to reproduce smoltcp's window timing.
    lane.proof.peer_window = actual_peer_window
        .checked_sub(1u32 << shift)
        .ok_or("window")?;
    {
        let mut state = lock(&lane.io.state)?;
        state.local_proof = Some(lane.proof);
        state.fence.as_mut().ok_or("fence")?.peer_horizon =
            super::horizon_bytes(carrier.policy, u64::from(lane.proof.peer_window), shift)?;
    }
    let mut hello = wire::Hello::parse(&carrier.local_hello)?;
    hello.lanes[0] = Some(lane.proof);
    carrier.local_hello = hello.encode()?;
    let stale_peer_window = lane.proof.peer_window;
    poll_fn(|cx| {
        if let Poll::Ready(result) = Pin::new(&mut a).poll(cx) {
            return Poll::Ready(Err(match result {
                Ok(_) => "unexpected client ready before proof refusal".into(),
                Err(error) => Box::new(error) as Box<dyn std::error::Error + Send + Sync>,
            }));
        }
        if let Poll::Ready(result) = Pin::new(&mut b).poll(cx) {
            // The authenticated gate retains the exact proof refusal below.
            // Its PacketIo boundary wraps that refusal in io::Error::other;
            // Detached::progress preserves this original outer I/O category.
            assert!(
                matches!(
                    &result,
                    Err(Error::Io {
                        kind: io::ErrorKind::Other,
                        raw_os_error: None,
                    })
                ),
                "unexpected encrypted Hello retry result: ready={}, error={:?}, snapshot={:?}",
                result.is_ok(),
                result.as_ref().err(),
                b.diagnostic_snapshot(),
            );
            return Poll::Ready(Ok(()));
        }
        Poll::Pending
    })
    .await?;
    assert!(
        af.phases.load(Ordering::SeqCst) >= 2,
        "actual Hello retry required"
    );
    let snapshot = b.diagnostic_snapshot();
    assert_eq!(snapshot.deadline, deadlines[1]);
    assert_eq!(snapshot.stage, SetupStage::PacketConfirmation);
    assert_eq!(snapshot.outcome, SetupOutcome::Failed);
    let gate = snapshot.lanes[0].ok_or("lane")?.gate.ok_or("gate")?;
    let Some(SetupProofFailure::Hello(value)) = gate.proof_failure else {
        return Err("missing complementary proof diagnostic".into());
    };
    assert_eq!(value.boundary, SetupProofBoundary::AuthenticatedHello);
    assert!(value.identity_matches && value.stream_bytes_match && value.sequence_matches);
    assert!(value.local_peer_window_matches && value.options_match && value.scales_match);
    assert!(!value.peer_peer_window_matches);
    assert_eq!(value.local_scaled_window, actual_peer_window);
    assert_eq!(value.peer_peer_window, stale_peer_window);
    assert!(gate.faulted);
    assert!(b.carrier.is_none());
    assert_eq!(a.deadline, deadlines[0]);
    assert_eq!(b.terminal_setup.len(), 1);
    assert_eq!(b.diagnostic_snapshot(), snapshot);
    Ok(())
}
