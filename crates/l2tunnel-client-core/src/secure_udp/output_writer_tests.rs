use super::*;
use std::{sync::atomic::AtomicUsize, time::Duration};

struct Short {
    calls: Arc<AtomicUsize>,
    bytes: Arc<AtomicUsize>,
}
impl Write for Short {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let count = bytes.len().min(8192);
        self.bytes.fetch_add(count, Ordering::AcqRel);
        self.calls.fetch_add(1, Ordering::AcqRel);
        Ok(count)
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
async fn until(mut condition: impl FnMut() -> bool) -> io::Result<()> {
    tokio::time::timeout(Duration::from_secs(1), async {
        while !condition() {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await
    .map_err(|_| io::Error::other("writer fixture progress"))
}
#[tokio::test]
async fn actual_worker_grants_keep_four_call_and_byte_limits_and_exact_partial_custody()
-> io::Result<()> {
    let calls = Arc::new(AtomicUsize::new(0));
    let bytes = Arc::new(AtomicUsize::new(0));
    let mut worker = Handle::new(Short {
        calls: Arc::clone(&calls),
        bytes: Arc::clone(&bytes),
    })?;
    assert!(matches!(
        worker.enqueue(vec![7; MAX_LINE]),
        Admission::Accepted
    ));
    for turn in 1..=4 {
        worker.grant();
        until(|| worker.snapshot().written_bytes == (turn * 32768) as u64).await?;
        assert_eq!(calls.load(Ordering::Acquire), turn * WRITE_CALLS);
        assert_eq!(bytes.load(Ordering::Acquire), turn * 32768);
        assert_eq!(worker.snapshot().pending_bytes, MAX_LINE - turn * 32768);
    }
    until(|| worker.snapshot().pending_lines == 0).await?;
    worker.close();
    Ok(())
}
struct Fails(io::ErrorKind);
impl Write for Fails {
    fn write(&mut self, _bytes: &[u8]) -> io::Result<usize> {
        Err(self.0.into())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
#[tokio::test]
async fn actual_worker_failure_releases_queued_and_current_permits_once() -> io::Result<()> {
    let mut worker = Handle::new(Fails(io::ErrorKind::BrokenPipe))?;
    for _ in 0..MAX_LINES {
        assert!(matches!(worker.enqueue(vec![1; 32]), Admission::Accepted));
    }
    assert!(matches!(worker.enqueue(vec![2]), Admission::Full(_)));
    worker.grant();
    until(|| worker.snapshot().disabled && worker.snapshot().pending_lines == 0).await?;
    let stopped = worker.snapshot();
    assert_eq!((stopped.pending_bytes, stopped.written_bytes), (0, 0));
    assert_eq!((stopped.write_errors, stopped.broken_pipe), (1, 1));
    assert_eq!(stopped.dropped_lines, MAX_LINES as u64);
    assert_eq!(stopped.dropped_bytes, (32 * MAX_LINES) as u64);
    assert!(matches!(worker.enqueue(vec![3]), Admission::Closed(_)));
    assert_eq!(worker.snapshot().dropped_lines, MAX_LINES as u64);
    Ok(())
}

struct Gate {
    entered: Option<tokio::sync::oneshot::Sender<()>>,
    release: mpsc::Receiver<()>,
    first: bool,
    calls: Arc<AtomicUsize>,
}
impl Write for Gate {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.calls.fetch_add(1, Ordering::AcqRel);
        if self.first {
            self.first = false;
            if let Some(entered) = self.entered.take() {
                let _result = entered.send(());
            }
            self.release.recv().map_err(io::Error::other)?;
        }
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
#[tokio::test]
async fn blocked_writer_coalesces_grants_and_each_grant_writes_at_most_64k() -> io::Result<()> {
    let calls = Arc::new(AtomicUsize::new(0));
    let (release, gate) = mpsc::sync_channel(1);
    let (entered, observed) = tokio::sync::oneshot::channel();
    let mut worker = Handle::new(Gate {
        entered: Some(entered),
        release: gate,
        first: true,
        calls: Arc::clone(&calls),
    })?;
    for _ in 0..2 {
        assert!(matches!(
            worker.enqueue(vec![7; MAX_LINE]),
            Admission::Accepted
        ));
    }
    worker.grant();
    tokio::time::timeout(Duration::from_secs(1), observed)
        .await
        .map_err(|_| io::Error::other("first write did not start"))?
        .map_err(io::Error::other)?;
    for _ in 0..32 {
        worker.grant();
    }
    release.try_send(()).map_err(io::Error::other)?;
    until(|| {
        worker.snapshot().written_bytes == (2 * WRITE_BYTES) as u64
            && !worker.shared.grant.load(Ordering::Acquire)
    })
    .await?;
    assert_eq!(calls.load(Ordering::Acquire), 2);
    assert_eq!(
        worker.snapshot().pending_bytes,
        2 * MAX_LINE - 2 * WRITE_BYTES
    );
    Ok(())
}
struct Panics;
impl Write for Panics {
    fn write(&mut self, _bytes: &[u8]) -> io::Result<usize> {
        // Deliberately model an abnormal platform writer, without a panic hook
        // writing to this test process's inherited stderr.
        std::panic::resume_unwind(Box::new("controlled fixture writer unwind"))
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
#[tokio::test]
async fn unwinding_writer_marks_failure_before_zero_custody_can_look_complete() -> io::Result<()> {
    let mut worker = Handle::new(Panics)?;
    assert!(matches!(worker.enqueue(vec![9; 16]), Admission::Accepted));
    worker.grant();
    until(|| worker.snapshot().disabled && worker.shared.exited.load(Ordering::Acquire)).await?;
    let state = worker.snapshot();
    assert!(state.disabled);
    assert_eq!(state.write_errors, 1);
    assert_eq!(state.written_bytes, 0);
    assert_eq!(state.dropped_bytes, 0);
    assert_eq!((state.pending_lines, state.pending_bytes), (1, 16));
    Ok(())
}
