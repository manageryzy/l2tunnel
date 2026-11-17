//! Actual output-owner fixtures. No inherited process descriptors are replaced.
use super::output::{self, MAX_LINE, MAX_LINES, Sink};
use std::{
    io::{self, Write},
    sync::{Arc, Mutex, mpsc},
    time::Duration,
};
use tokio::time::Instant;

struct Unblock(Option<mpsc::SyncSender<()>>);
impl Unblock {
    fn release(&mut self) {
        if let Some(sender) = self.0.take() {
            let _result = sender.try_send(());
        }
    }
}
impl Drop for Unblock {
    fn drop(&mut self) {
        self.release();
    }
}
struct Gated {
    entered: Option<tokio::sync::oneshot::Sender<()>>,
    gate: Option<mpsc::Receiver<()>>,
    bytes: Arc<Mutex<Vec<u8>>>,
}
impl Write for Gated {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if let Some(entered) = self.entered.take() {
            let _result = entered.send(());
        }
        if let Some(gate) = self.gate.take() {
            gate.recv().map_err(io::Error::other)?;
        }
        self.bytes
            .lock()
            .map_err(|_| io::Error::other("fixture lock"))?
            .extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
type Fixture = (
    Sink,
    Unblock,
    tokio::sync::oneshot::Receiver<()>,
    Arc<Mutex<Vec<u8>>>,
);
fn gated() -> io::Result<Fixture> {
    let (sender, receiver) = mpsc::sync_channel(1);
    let (entered, observed) = tokio::sync::oneshot::channel();
    let bytes = Arc::new(Mutex::new(Vec::new()));
    let sink = Sink::with_worker(Gated {
        entered: Some(entered),
        gate: Some(receiver),
        bytes: Arc::clone(&bytes),
    })?;
    Ok((sink, Unblock(Some(sender)), observed, bytes))
}
async fn wait_started(observed: tokio::sync::oneshot::Receiver<()>) -> io::Result<()> {
    tokio::time::timeout(Duration::from_secs(1), observed)
        .await
        .map_err(|_| io::Error::other("writer did not enter actual write"))?
        .map_err(io::Error::other)
}
async fn drain(sink: &mut Sink) -> io::Result<()> {
    tokio::time::timeout(Duration::from_secs(1), async {
        while sink.has_pending() {
            sink.flush_turn();
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await
    .map_err(|_| io::Error::other("writer custody drain"))
}

#[tokio::test(flavor = "current_thread")]
async fn blocked_regular_writer_preserves_service_polling_fifo_and_total_line_custody()
-> io::Result<()> {
    let (mut sink, mut release, entered, bytes) = gated()?;
    sink.emit(serde_json::json!({"index":0,"body":"a".repeat(MAX_LINE / 2)}));
    sink.flush_turn();
    wait_started(entered).await?;
    for index in 1..MAX_LINES {
        sink.emit(serde_json::json!({"index":index,"body":"a".repeat(MAX_LINE / 2)}));
    }
    sink.emit(serde_json::json!({"index":"must refuse"}));
    let held = output::test_health(&mut sink);
    assert_eq!(held.written_bytes, 0);
    assert_eq!(
        held.dropped_lines, 1,
        "the worker-held line owns one of four permits"
    );
    // Run and the actual retained service API remain in this same task,
    // matching the CLI's select coupling. Its local status stays responsive
    // while the output owner is inside a deliberately blocked Write call.
    let (handle, run) = crate::service::channel();
    let request = crate::local::Request {
        version: crate::local::VERSION,
        action: crate::local::Action::Status {},
    };
    let response = tokio::time::timeout(Duration::from_secs(1), async {
        tokio::select! {
            biased;
            result = run => Err(io::Error::other(format!("service stopped: {result:?}"))),
            result = handle.lifecycle_request(request) => Ok(result),
        }
    })
    .await
    .map_err(|_| io::Error::other("service polling blocked by writer"))??;
    assert!(response.ok);
    assert_eq!(response.code, "ok");
    release.release();
    drain(&mut sink).await?;
    let saved = bytes
        .lock()
        .map_err(|_| io::Error::other("fixture lock"))?
        .clone();
    let lines = saved
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>();
    assert_eq!(lines.len(), MAX_LINES);
    for (index, line) in lines.iter().enumerate() {
        let value: serde_json::Value = serde_json::from_slice(line)?;
        assert_eq!(value["index"], index);
    }
    // A later lifecycle event reuses the same Sink/worker after its earlier queue drained.
    sink.emit(serde_json::json!({"event":"later generation"}));
    drain(&mut sink).await?;
    assert_eq!(output::test_health(&mut sink).write_errors, 0);
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn blocked_regular_finish_is_bounded_unresolved_and_does_not_join() -> io::Result<()> {
    let (mut sink, mut release, entered, _bytes) = gated()?;
    sink.emit(serde_json::json!({"event":"terminal"}));
    sink.flush_turn();
    wait_started(entered).await?;
    let deadline = Instant::now() + output::DRAIN_CAP;
    let report = tokio::time::timeout(Duration::from_secs(1), sink.finish_until(deadline))
        .await
        .map_err(|_| io::Error::other("finish joined blocked worker"))?;
    assert!(report.timed_out && !report.completed && !report.failed);
    assert_eq!(report.unresolved_lines, 1);
    assert!(report.unresolved_bytes > 0);
    let health = output::test_health(&mut sink);
    assert_eq!(health.written_bytes, 0);
    assert_eq!(health.dropped_lines, 0);
    assert_eq!(health.shutdown_timeouts, 1);
    drop(sink);
    // Releasing only after Sink destruction proves Drop did not join this worker.
    release.release();
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn cancelling_regular_finish_censors_original_custody_without_renewal() -> io::Result<()> {
    let (mut sink, mut release, entered, _bytes) = gated()?;
    sink.emit(serde_json::json!({"event":"cancellation"}));
    sink.flush_turn();
    wait_started(entered).await?;
    {
        let finish = sink.finish_until(Instant::now() + output::DRAIN_CAP);
        tokio::pin!(finish);
        tokio::select! {
            biased;
            _ = &mut finish => return Err(io::Error::other("blocked finish unexpectedly completed")),
            () = tokio::task::yield_now() => {},
        }
    }
    let health = output::test_health(&mut sink);
    assert_eq!(health.unresolved_lines, 1);
    assert!(health.unresolved_bytes > 0);
    assert_eq!(health.shutdown_timeouts, 0);
    assert_eq!(health.dropped_lines, 0);
    sink.emit(serde_json::json!({"event":"closed"}));
    assert_eq!(output::test_health(&mut sink).dropped_lines, 1);
    release.release();
    Ok(())
}
