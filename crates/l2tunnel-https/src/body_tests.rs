use super::*;
use std::{
    future::poll_fn,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};
use tokio::io::AsyncWriteExt;
struct Sink {
    blocked: Arc<AtomicBool>,
    step: usize,
    flushes: Arc<AtomicU64>,
}
impl AsyncWrite for Sink {
    fn poll_write(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        Poll::Ready(Ok(data.len().min(self.step)))
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.blocked.load(Ordering::Relaxed) {
            Poll::Pending
        } else {
            self.flushes.fetch_add(1, Ordering::Relaxed);
            Poll::Ready(Ok(()))
        }
    }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}
#[tokio::test]
async fn unrelated_control_flush_and_partial_data_cannot_satisfy_later_data_target()
-> io::Result<()> {
    for client in [false, true] {
        for step in [1, 7, 64] {
            let blocked = Arc::new(AtomicBool::new(false));
            let flushes = Arc::new(AtomicU64::new(0));
            let (mut io, witness) = FlushIo::new(
                Sink {
                    blocked: blocked.clone(),
                    step,
                    flushes: flushes.clone(),
                },
                client,
            );
            if client {
                io.write_all(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n").await?;
            }
            witness.work.store(1000, Ordering::Relaxed);
            let control = [0, 0, 8, 6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
            // The old generation predicate would accept this unrelated flush
            // while the new cumulative DATA target of five bytes is still held.
            let staged_generation = flushes.load(Ordering::Relaxed);
            io.write_all(&control).await?;
            io.flush().await?;
            assert_eq!(witness.data.load(Ordering::Relaxed), 0);
            assert!(flushes.load(Ordering::Relaxed) > staged_generation);
            assert!(witness.data.load(Ordering::Relaxed) < 5);
            io.write_all(&[0, 0, 5, 0, 0, 0, 0, 0, 1, 11, 22]).await?;
            io.flush().await?;
            assert_eq!(witness.data.load(Ordering::Relaxed), 2);
            io.write_all(&[33, 44, 55]).await?;
            blocked.store(true, Ordering::Relaxed);
            poll_fn(|cx| {
                assert!(Pin::new(&mut io).poll_flush(cx).is_pending());
                Poll::Ready(())
            })
            .await;
            assert_eq!(witness.data.load(Ordering::Relaxed), 2);
            blocked.store(false, Ordering::Relaxed);
            io.flush().await?;
            assert_eq!(witness.data.load(Ordering::Relaxed), 5);
            io.write_all(&[0, 0, 0, 0, 1, 0, 0, 0, 1]).await?;
            assert!(!witness.end.load(Ordering::Relaxed));
            io.flush().await?;
            assert!(witness.end.load(Ordering::Relaxed));
        }
    }
    Ok(())
}
#[tokio::test]
async fn zero_write_and_counter_exhaustion_fail_without_replaying_observation() -> io::Result<()> {
    let (mut io, witness) = FlushIo::new(
        Sink {
            blocked: Arc::new(AtomicBool::new(false)),
            step: 0,
            flushes: Arc::new(AtomicU64::new(0)),
        },
        false,
    );
    assert_eq!(
        io.write_all(&[1]).await.err().map(|e| e.kind()),
        Some(io::ErrorKind::WriteZero)
    );
    assert_eq!(witness.data.load(Ordering::Relaxed), 0);
    assert_eq!(io.wire.head, 0);
    let mut wire = Wire::new(false);
    wire.bytes = u64::MAX;
    assert!(wire.observe(&[0, 0, 1, 0, 0, 0, 0, 0, 1, 23]).is_err());
    assert_eq!(wire.bytes, u64::MAX);
    Ok(())
}

#[tokio::test]
async fn exact_io_turn_budget_yields_then_resumes_without_reobserving_bytes() -> io::Result<()> {
    let (mut io, w) = FlushIo::new(
        Sink {
            blocked: Arc::new(AtomicBool::new(false)),
            step: 1,
            flushes: Arc::new(AtomicU64::new(0)),
        },
        false,
    );
    w.reset();
    poll_fn(|cx| {
        for _ in 0..64 {
            assert!(matches!(
                Pin::new(&mut io).poll_write(cx, &[0]),
                Poll::Ready(Ok(1))
            ));
        }
        let before = io.wire.head;
        assert!(Pin::new(&mut io).poll_write(cx, &[0]).is_pending());
        assert_eq!(io.wire.head, before);
        w.reset();
        assert!(matches!(
            Pin::new(&mut io).poll_write(cx, &[0]),
            Poll::Ready(Ok(1))
        ));
        Poll::Ready(())
    })
    .await;
    Ok(())
}
