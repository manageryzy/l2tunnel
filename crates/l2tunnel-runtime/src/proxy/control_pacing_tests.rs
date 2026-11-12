//! Deterministic tests of the actual shared actor and physical writer.
use super::*;
use std::{
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
};
use tokio::io::{AsyncReadExt, AsyncWrite};

#[tokio::test(start_paused = true)]
async fn cumulative_credit_coalesces_and_reserves_liveness_before_latest_prefix() -> io::Result<()>
{
    let (mut a, _users, mut controls) = actor(true)?;
    a.config.control_rate = 16;
    a.delivered = Credit {
        bytes: 100,
        packets: 1,
    };
    a.service_control()?;
    assert!(matches!(
        controls.try_recv(),
        Ok(Output::Control(Frame::Credit(Credit { packets: 1, .. })))
    ));
    let mut p = *a.writers[0].progress.borrow();
    p.credit = a.queued_credit;
    let (sender, receiver) = watch::channel(p);
    a.writers[0].progress = receiver;
    for n in 2..=100 {
        a.delivered = Credit {
            bytes: n * 100,
            packets: n,
        };
        a.service_control()?;
        assert!(controls.try_recv().is_err());
    }
    assert_eq!(a.queued_credit.packets, 1);
    a.writers[0].pending_pong = Some(1);
    tokio::time::advance(transport::control_interval(16)? * 4).await;
    a.service_control()?;
    assert!(matches!(
        controls.try_recv(),
        Ok(Output::Control(Frame::Pong(1)))
    ));
    assert!(matches!(
        controls.try_recv(),
        Ok(Output::Control(Frame::Credit(Credit {
            packets: 100,
            bytes: 10000
        })))
    ));
    assert_eq!(a.queued_credit, a.delivered);
    sender.send_replace(p);
    // A queued-but-unflushed latest prefix cannot authorize another credit.
    a.delivered = Credit {
        bytes: 10100,
        packets: 101,
    };
    tokio::time::advance(transport::control_interval(16)? * 4).await;
    a.service_control()?;
    assert!(controls.try_recv().is_err());
    Ok(())
}

#[derive(Default)]
struct Trace {
    bytes: Vec<u8>,
    flushes: Vec<Instant>,
    fail_flush: Option<usize>,
}
struct Sink(Arc<Mutex<Trace>>);
impl AsyncWrite for Sink {
    fn poll_write(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        let mut state = self.0.lock().map_err(|_| invalid("trace lock"))?;
        state.bytes.extend_from_slice(bytes);
        Poll::Ready(Ok(bytes.len()))
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut state = self.0.lock().map_err(|_| invalid("trace lock"))?;
        if state.fail_flush == Some(state.flushes.len() + 1) {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        state.flushes.push(Instant::now());
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

#[tokio::test(start_paused = true)]
async fn every_physical_control_kind_is_paced_without_catchup_or_failed_flush_progress()
-> io::Result<()> {
    for rate in [16, 256] {
        let (a, _users, _controls) = actor(true)?;
        let start = a.writers[0].start;
        let trace = Arc::new(Mutex::new(Trace::default()));
        let (controls, crx) = mpsc::channel(8);
        let (_users, urx) = mpsc::channel(1);
        let (progress, prx) = watch::channel(Progress::default());
        let (events, _events) = mpsc::channel(8);
        let task = tokio::spawn(transport::writer(
            Sink(trace.clone()),
            Direction {
                index: 0,
                lane: 0,
                session: [9; 16],
                bulk: true,
            },
            rate,
            crx,
            urx,
            progress,
            events,
        ));
        let producer = tokio::spawn(async move {
            controls
                .send(Output::Control(Frame::Start(start)))
                .await
                .map_err(error)?;
            controls
                .send(Output::Control(Frame::Ready(start)))
                .await
                .map_err(error)?;
            for n in 1..=24 {
                controls
                    .send(Output::Control(Frame::Credit(Credit {
                        bytes: n * 100,
                        packets: n,
                    })))
                    .await
                    .map_err(error)?;
                controls
                    .send(Output::Control(Frame::Ping(n)))
                    .await
                    .map_err(error)?;
                controls
                    .send(Output::Control(Frame::Pong(n)))
                    .await
                    .map_err(error)?;
            }
            for frame in [
                Frame::Quiesce,
                Frame::Barrier(Fence::default()),
                Frame::Ack(Fence::default()),
            ] {
                controls.send(Output::Control(frame)).await.map_err(error)?;
            }
            controls.send(Output::Close).await.map_err(error)?;
            Ok::<_, io::Error>(())
        });
        while trace
            .lock()
            .map_err(|_| invalid("trace lock"))?
            .flushes
            .is_empty()
        {
            tokio::task::yield_now().await;
        }
        // Miss many nominal slots. Actual full flush, rather than the old due
        // timestamp, must anchor the next slot; no catch-up control burst is legal.
        tokio::time::advance(Duration::from_secs(5)).await;
        producer.await.map_err(error)??;
        task.await.map_err(error)??;
        let state = trace.lock().map_err(|_| invalid("trace lock"))?;
        assert_eq!(state.flushes.len(), 77);
        for pair in state.flushes.windows(2) {
            assert!(pair[1].duration_since(pair[0]) >= transport::control_interval(rate)?);
        }
        for at in &state.flushes {
            assert!(
                state
                    .flushes
                    .iter()
                    .filter(
                        |next| **next >= *at && next.duration_since(*at) < Duration::from_secs(1)
                    )
                    .count()
                    <= rate
            );
        }
        assert_eq!(prx.borrow().credit.packets, 24);
        assert!(
            prx.borrow().quiesce && prx.borrow().barrier.is_some() && prx.borrow().ack.is_some()
        );
    }
    let (a, _users, _controls) = actor(true)?;
    let start = a.writers[0].start;
    for fail_flush in 2..=7 {
        let trace = Arc::new(Mutex::new(Trace {
            fail_flush: Some(fail_flush),
            ..Trace::default()
        }));
        let (controls, crx) = mpsc::channel(8);
        let (_users, urx) = mpsc::channel(1);
        let (progress, prx) = watch::channel(Progress::default());
        let (events, _events) = mpsc::channel(8);
        let credit = Credit {
            bytes: 100,
            packets: 1,
        };
        let frames = [
            Frame::Start(start),
            Frame::Ready(start),
            Frame::Credit(credit),
            Frame::Pong(1),
            Frame::Quiesce,
            Frame::Barrier(Fence::default()),
            Frame::Ack(Fence::default()),
        ];
        for frame in frames {
            controls.try_send(Output::Control(frame)).map_err(error)?;
        }
        let result = transport::writer(
            Sink(trace),
            Direction {
                index: 0,
                lane: 0,
                session: [9; 16],
                bulk: true,
            },
            16,
            crx,
            urx,
            progress,
            events,
        )
        .await;
        assert_eq!(
            result
                .err()
                .ok_or_else(|| invalid("expected failed full control flush"))?
                .kind(),
            io::ErrorKind::BrokenPipe
        );
        let observed = *prx.borrow();
        assert_eq!(observed.ready, fail_flush > 2);
        assert_eq!(
            observed.credit,
            if fail_flush > 3 {
                credit
            } else {
                Credit::default()
            }
        );
        assert_eq!(observed.pong, u64::from(fail_flush > 4));
        assert_eq!(observed.quiesce, fail_flush > 5);
        assert_eq!(observed.barrier.is_some(), fail_flush > 6);
        assert!(observed.ack.is_none());
    }
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn waiting_control_slot_keeps_actual_user_records_serviceable() -> io::Result<()> {
    let (a, _users, _controls) = actor(true)?;
    let start = a.writers[0].start;
    let (writer, mut reader) = tokio::io::duplex(8192);
    let (controls, crx) = mpsc::channel(8);
    let (users, urx) = mpsc::channel(1);
    let (progress, _progress) = watch::channel(Progress::default());
    let (events, _events) = mpsc::channel(8);
    let task = tokio::spawn(transport::writer(
        writer,
        Direction {
            index: 0,
            lane: 0,
            session: [9; 16],
            bulk: true,
        },
        16,
        crx,
        urx,
        progress,
        events,
    ));
    async fn frame(reader: &mut tokio::io::DuplexStream) -> io::Result<Vec<u8>> {
        let length = reader.read_u32().await? as usize;
        let mut bytes = vec![0; length];
        reader.read_exact(&mut bytes).await?;
        Ok(bytes)
    }
    controls
        .send(Output::Control(Frame::Start(start)))
        .await
        .map_err(error)?;
    let _ = frame(&mut reader).await?;
    controls
        .send(Output::Control(Frame::Ready(start)))
        .await
        .map_err(error)?;
    let _ = frame(&mut reader).await?;
    controls
        .send(Output::Control(Frame::Credit(Credit {
            bytes: 100,
            packets: 1,
        })))
        .await
        .map_err(error)?;
    tokio::task::yield_now().await;
    users.send(vec![17; 24]).await.map_err(error)?;
    let bytes = tokio::time::timeout(Duration::from_millis(1), frame(&mut reader))
        .await
        .map_err(error)??;
    let (header, _) = crate::wire::decode(&bytes, 1600).map_err(crate::wire_error)?;
    assert_eq!(header.kind, crate::wire::Kind::Data);
    task.abort();
    assert!(task.await.is_err());
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn buffered_or_unpaced_controls_receive_bounded_service_without_false_failure()
-> io::Result<()> {
    use tokio::io::AsyncWriteExt;
    let (a, _users, _controls) = actor(true)?;
    let expected = a.writers[0].start;
    let mut config = a.config;
    config.control_rate = 16;
    let (mut sender, reader) = tokio::io::duplex(8192);
    let (events, mut received) = mpsc::channel(64);
    let (users, _users) = mpsc::channel(1);
    let (quiesce, _quiesce) = watch::channel(None);
    let task = tokio::spawn(transport::reader(
        reader,
        Direction {
            index: 0,
            lane: 0,
            session: [9; 16],
            bulk: true,
        },
        expected,
        (config, false),
        events,
        users,
        quiesce,
    ));
    let frames = [Frame::Start(expected), Frame::Ready(expected)]
        .into_iter()
        .chain((1..=15).map(Frame::Ping));
    for (number, frame) in frames.enumerate() {
        let bytes = crate::wire::encode(
            crate::wire::Header {
                kind: crate::wire::Kind::Control,
                epoch: l2tunnel_core::Epoch(1),
                packet_number: number as u64,
                session: [9; 16],
                lane: 0,
            },
            &frame.encode(),
        )
        .map_err(crate::wire_error)?;
        sender.write_u32(bytes.len() as u32).await?;
        sender.write_all(&bytes).await?;
    }
    // All 17 records already reside in the bounded duplex buffer. Reader
    // service remains <=16/s; it must neither reject nor process them in a burst.
    let began = Instant::now();
    for n in 0..17 {
        let _ = received
            .recv()
            .await
            .ok_or_else(|| invalid("reader stopped"))?;
        assert!(began.elapsed() >= transport::control_interval(16)? * n);
        assert!(!task.is_finished());
    }
    assert!(began.elapsed() >= Duration::from_secs(1));
    task.abort();
    assert!(task.await.is_err());
    Ok(())
}

#[test]
fn infeasible_pacing_deadlines_are_rejected_before_io() -> io::Result<()> {
    let (a, _users, _controls) = actor(true)?;
    for rate in [16, 256, 1024] {
        let mut config = a.config.clone();
        config.control_rate = rate;
        let slot = transport::control_interval(rate)?;
        let rounding = |duration: Duration| -> io::Result<Duration> {
            let nanos = duration.as_nanos();
            let millis = u64::try_from(nanos.div_ceil(1_000_000)).map_err(error)?;
            Ok(Duration::from_millis(millis.max(10)))
        };
        config.timeouts.startup = rounding(slot * 2)?;
        config.timeouts.control_idle = rounding(slot * 12 + config.runtime.poll_interval * 2)?;
        config.timeouts.shutdown = rounding(slot * 32 + config.runtime.poll_interval * 4)?;
        // The supported integral-millisecond boundary is legal; one millisecond
        // below it is not. This validates policy before any native/TLS I/O.
        config.validate()?;
        for field in 0..3 {
            let mut bad = config.clone();
            match field {
                0 => bad.timeouts.startup -= Duration::from_millis(1),
                1 => bad.timeouts.control_idle -= Duration::from_millis(1),
                _ => bad.timeouts.shutdown -= Duration::from_millis(1),
            }
            assert!(bad.validate().is_err(), "rate={rate} field={field}");
        }
    }
    let mut legal_before_pacing = a.config;
    legal_before_pacing.control_rate = 16;
    legal_before_pacing.timeouts.startup = Duration::from_millis(10);
    assert_eq!(
        legal_before_pacing
            .validate()
            .err()
            .ok_or_else(|| invalid("expected infeasible startup rejection"))?
            .to_string(),
        "proxy deadlines cannot service configured control rate"
    );
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn direct_actor_retains_original_30ms_drain_deadline_before_ready() -> io::Result<()> {
    let (mut a, _users, mut controls) = actor(true)?;
    // This intentionally bypasses the new public service-reservation floor to
    // test the original deadline mechanism, rather than extending its 30ms.
    a.config.timeouts.shutdown = Duration::from_millis(30);
    a.started = false;
    a.starts.fill(false);
    a.ready.fill(false);
    a.writers[0].ready = false;
    let began = Instant::now();
    a.drain(began)?;
    a.service_control()?;
    assert!(a.shutdown()?.is_none());
    assert!(controls.try_recv().is_err());
    tokio::time::advance(Duration::from_millis(20)).await;
    a.drain(Instant::now())?;
    assert_eq!(a.deadline, Some(began + Duration::from_millis(30)));
    a.check_shutdown_deadline(began + Duration::from_millis(29))?;
    let failure = a
        .check_shutdown_deadline(began + Duration::from_millis(30))
        .err()
        .ok_or_else(|| invalid("original deadline incorrectly renewed"))?;
    assert_eq!(failure.kind(), io::ErrorKind::TimedOut);
    assert_eq!(failure.to_string(), "proxy original shutdown deadline");
    assert!(!a.quiesce_queued);
    Ok(())
}
