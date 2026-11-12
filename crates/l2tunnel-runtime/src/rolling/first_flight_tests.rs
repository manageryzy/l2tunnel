use super::*;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use tokio::sync::Notify;
struct Sender {
    entered: Arc<AtomicBool>,
    release: Arc<Notify>,
    fail: bool,
}
impl DatagramSend for Sender {
    async fn send(&mut self, _: &[u8]) -> io::Result<()> {
        self.entered.store(true, Ordering::SeqCst);
        self.release.notified().await;
        if self.fail {
            Err(io::Error::other("injected datagram send failure"))
        } else {
            Ok(())
        }
    }
}
#[tokio::test]
async fn first_flight_timestamp_requires_actual_successful_datagram_handoff() -> io::Result<()> {
    for fail in [false, true] {
        let entered = Arc::new(AtomicBool::new(false));
        let release = Arc::new(Notify::new());
        let (tx, rx) = mpsc::channel(1);
        let (sent, mut events) = mpsc::channel(1);
        let task = tokio::spawn(write_datagrams(
            Sender {
                entered: entered.clone(),
                release: release.clone(),
                fail,
            },
            rx,
            0,
            sent,
        ));
        tx.send(owner::Outbound {
            bytes: vec![1, 2, 3],
            native_complete: Some(7),
        })
        .await
        .map_err(io::Error::other)?;
        tokio::time::timeout(Duration::from_secs(1), async {
            while !entered.load(Ordering::SeqCst) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .map_err(io::Error::other)?;
        assert!(
            events.try_recv().is_err(),
            "queue handoff and pending send are not first-flight success"
        );
        let released = Instant::now();
        release.notify_one();
        if fail {
            assert!(task.await.map_err(io::Error::other)?.is_err());
            assert!(events.try_recv().is_err());
        } else {
            let (lane, ordinal, at) = tokio::time::timeout(Duration::from_secs(1), events.recv())
                .await
                .map_err(io::Error::other)?
                .ok_or_else(|| invalid("completion event"))?;
            assert_eq!((lane, ordinal), (0, 7));
            assert!(at >= released && at <= Instant::now());
            task.abort();
            let _ = task.await;
        }
    }
    Ok(())
}
