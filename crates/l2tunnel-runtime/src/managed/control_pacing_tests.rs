//! Legal authenticated management retries, buffered delivery and bounded service.
use super::*;
use std::{
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
};
type TestResult = Result<(), Box<dyn std::error::Error + Send + Sync>>;
fn fixture() -> io::Result<(Driver, Vec<Record>, mpsc::Receiver<OutControl>)> {
    let runtime = RuntimeConfig {
        layer: PacketLayer::Ip,
        max_packet: 1600,
        compression: Compression::None,
        queue_packets: 2,
        poll_interval: Duration::from_millis(1),
    };
    let mode = mode_config(runtime, Duplex::Full)?;
    let next = ModeConfig {
        compression: PayloadCompression::Lz4,
        ..mode.clone()
    };
    let session = SessionId([9; 16]);
    let settings = TransactionSettings {
        retry_ms: 1,
        phase_timeout_ms: 5000,
        reconcile_timeout_ms: 15000,
    };
    settings.validate().map_err(io::Error::other)?;
    let identity = |role| Identity {
        session,
        role,
        local: EndpointId(if role == Role::Client { 1 } else { 2 }),
        remote: EndpointId(if role == Role::Client { 2 } else { 1 }),
        lane: LaneId(0),
    };
    let mut coordinator = Peer::new(
        identity(Role::Client),
        Epoch(1),
        mode.clone(),
        &[mode.clone(), next.clone()],
        settings,
        Tick(0),
    )
    .map_err(io::Error::other)?;
    let peer = Peer::new(
        identity(Role::Server),
        Epoch(1),
        mode.clone(),
        &[mode, next.clone()],
        settings,
        Tick(0),
    )
    .map_err(io::Error::other)?;
    coordinator
        .propose(next, Tick(0))
        .map_err(io::Error::other)?;
    let first = coordinator
        .staged(Fence::new(&[0]).map_err(io::Error::other)?, Tick(0))
        .map_err(io::Error::other)?
        .outbound
        .ok_or_else(|| invalid("missing prepare"))?;
    let (sender, writer) = mpsc::channel(CONTROL_SLOTS);
    let (_flushed, flushed) = watch::channel(0);
    let driver = Driver {
        peer,
        codecs: Codecs::new(runtime)?,
        runtime,
        origin: Ingress::AuthenticatedManagement {
            session,
            lane: LaneId(0),
            sender: Role::Client,
        },
        role: Role::Server,
        admitted: 0,
        delivered: 0,
        received: 0,
        peer_delivered: 0,
        drain: None,
        pending: None,
        control_out: ControlSender {
            sender,
            flushed,
            pending: VecDeque::with_capacity(CONTROL_SLOTS),
            next: 0,
        },
        native_pending: VecDeque::with_capacity(2),
        delivery: None,
    };
    let mut bodies = vec![first];
    for millis in 1..=256 {
        bodies.push(
            coordinator
                .poll(Tick(millis))
                .map_err(io::Error::other)?
                .outbound
                .ok_or_else(|| invalid("missing retry"))?,
        );
    }
    let frames = bodies
        .into_iter()
        .enumerate()
        .map(|(ordinal, payload)| Record {
            received_at: None,
            header: Header {
                kind: Kind::Control,
                epoch: Epoch(0),
                packet_number: ordinal as u64,
                session: [9; 16],
                lane: 0,
            },
            payload,
        })
        .collect();
    Ok((driver, frames, writer))
}
#[test]
fn legal_one_ms_retries_buffered_below_original_deadline_do_not_close_healthy_management()
-> TestResult {
    let (mut receiver, frames, _writer) = fixture()?;
    for (ordinal, frame) in frames.into_iter().enumerate() {
        let result = receiver.input(frame, Tick(300), None);
        assert!(
            result.is_ok(),
            "valid buffered management frame{} rejected: {:?}",
            ordinal + 1,
            result
        );
    }
    assert_ne!(receiver.peer.phase(), Phase::Failed);
    Ok(())
}
#[tokio::test(start_paused = true)]
async fn reader_backpressures_buffered_valid_controls_without_renewing_original_phase_deadline()
-> TestResult {
    let (mut receiver, frames, _writer) = fixture()?;
    let mut bytes = Vec::new();
    for frame in frames {
        let body = wire::encode(frame.header, &frame.payload).map_err(wire_error)?;
        bytes.extend_from_slice(&u32::try_from(body.len())?.to_be_bytes());
        bytes.extend_from_slice(&body);
    }
    let (tx, mut rx) = mpsc::channel(2);
    let start = Instant::now();
    let task = tokio::spawn(read_records(
        std::io::Cursor::new(bytes),
        [9; 16],
        1616,
        tx,
        None,
        false,
    ));
    for _ in 0..257 {
        let Incoming::Record(frame) = rx.recv().await.ok_or("missing frame")? else {
            return Err("early EOF".into());
        };
        receiver.input(
            frame,
            Tick(300 + u64::try_from(start.elapsed().as_millis())?),
            None,
        )?;
    }
    assert!(start.elapsed() >= super::super::proxy::control_interval(CONTROL_RATE)? * 256);
    assert_ne!(receiver.peer.phase(), Phase::Failed);
    // First request was observed at300ms; repeated legal requests do not move
    // its original5s follower deadline to the final paced frame's receipt.
    assert!(matches!(
        receiver
            .peer
            .poll(Tick(5300))
            .map_err(io::Error::other)?
            .event,
        Some(Event::Failed)
    ));
    task.abort();
    let _ = task.await;
    Ok(())
}
#[derive(Default)]
struct OutputState {
    buffer: Vec<u8>,
    flushed: Vec<(Kind, Instant)>,
}
#[derive(Clone, Default)]
struct Recorder(Arc<Mutex<OutputState>>);
impl AsyncWrite for Recorder {
    fn poll_write(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.0
            .lock()
            .map_err(|_| invalid("recorder lock"))?
            .buffer
            .extend_from_slice(bytes);
        Poll::Ready(Ok(bytes.len()))
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut state = self.0.lock().map_err(|_| invalid("recorder lock"))?;
        let (header, _) = wire::decode(
            state
                .buffer
                .get(4..)
                .ok_or_else(|| invalid("missing prefix"))?,
            CONTROL_BYTES,
        )
        .map_err(wire_error)?;
        state.flushed.push((header.kind, Instant::now()));
        state.buffer.clear();
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}
#[tokio::test(start_paused = true)]
async fn paced_pending_control_keeps_data_and_native_feedback_alive_without_catchup() -> TestResult
{
    let interval = super::super::proxy::control_interval(CONTROL_RATE)?;
    let recorder = Recorder::default();
    let (data_tx, data) = mpsc::channel(2);
    let (control_tx, control) = mpsc::channel(2);
    let (credit_tx, credit) = watch::channel(0);
    data_tx
        .send(OutData {
            epoch: Epoch(1),
            payload: vec![9; 32],
            admitted: 1,
        })
        .await?;
    for sequence in 1..=2 {
        control_tx
            .send(OutControl {
                sequence,
                bytes: vec![9; 32],
            })
            .await?;
    }
    credit_tx.send_replace(7);
    let (control_progress, mut observed) = watch::channel(0);
    let (credit_progress, credit_observed) = watch::channel(0);
    let (data_progress, data_observed) = watch::channel(0);
    let (events, mut originals) = mpsc::channel(2);
    let task = tokio::spawn(write_records(
        recorder.clone(),
        [7; 16],
        data,
        control,
        credit,
        WriterProgress {
            control: control_progress,
            credit: credit_progress,
            data: data_progress,
            delivery: Some(events),
        },
        None,
    ));
    tokio::task::yield_now().await;
    assert_eq!(*observed.borrow(), 1);
    assert_eq!(*credit_observed.borrow(), 7);
    assert_eq!(*data_observed.borrow(), 1);
    assert_eq!(originals.try_recv()?.ordinal, 1);
    let initial = recorder
        .0
        .lock()
        .map_err(|_| invalid("lock"))?
        .flushed
        .clone();
    assert_eq!(
        initial.iter().map(|v| v.0).collect::<Vec<_>>(),
        [Kind::Control, Kind::Feedback, Kind::Data]
    );
    control_tx
        .send(OutControl {
            sequence: 3,
            bytes: vec![9; 32],
        })
        .await?;
    tokio::time::advance(Duration::from_millis(100)).await;
    tokio::task::yield_now().await;
    assert_eq!(*observed.borrow(), 2); // An old timer cannot grant catch-up slots.
    // Follow the actual next timer rather than assuming submillisecond timer
    // deadlines wake on an exactly equal manual advance (Tokio rounds timers).
    observed.borrow_and_update();
    tokio::time::timeout(interval + Duration::from_millis(1), async {
        while *observed.borrow_and_update() < 3 {
            observed
                .changed()
                .await
                .map_err(|_| invalid("writer stopped"))?;
        }
        Ok::<_, io::Error>(())
    })
    .await??;
    assert_eq!(*observed.borrow(), 3);
    let output = recorder
        .0
        .lock()
        .map_err(|_| invalid("lock"))?
        .flushed
        .clone();
    let controls: Vec<_> = output.iter().filter(|v| v.0 == Kind::Control).collect();
    assert_eq!(controls.len(), 3);
    for pair in controls.windows(2) {
        assert!(pair[1].1.duration_since(pair[0].1) >= interval);
    }
    task.abort();
    let _ = task.await;
    Ok(())
}
