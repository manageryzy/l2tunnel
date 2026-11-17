//! Owned blocking platform setup with release on abandoned foreground futures.
//!
//! Windows driver creation may be an uninterruptible OS call. Cancellation waits
//! for that call and releases its result; this boundary promises ownership, not
//! a hard cancellation latency. No thread or eventual device owner is detached.
use std::{io, thread};
use tokio::sync::oneshot;

/// Sole owner of a blocking setup worker and any result not yet claimed.
pub struct Setup<T> {
    worker: Option<thread::JoinHandle<io::Result<T>>>,
    ready: Option<oneshot::Receiver<()>>,
}

impl<T: Send + 'static> Setup<T> {
    /// Start one owned OS setup call; thread-creation failure returns directly.
    pub fn spawn(work: impl FnOnce() -> io::Result<T> + Send + 'static) -> io::Result<Self> {
        let (ready, notification) = oneshot::channel();
        let worker = thread::Builder::new()
            .name("l2tunnel-wintun-setup".into())
            .spawn(move || {
                let result = work();
                // Readiness means only that the blocking call returned. Its
                // actual result remains owned by the join handle until finish.
                let _ = ready.send(());
                result
            })?;
        Ok(Self {
            worker: Some(worker),
            ready: Some(notification),
        })
    }

    /// Await call completion without claiming its result. This future is cancel-safe.
    /// Readiness is neither driver success nor a successful native tunnel receipt.
    pub async fn wait(&mut self) -> io::Result<()> {
        let Some(ready) = &mut self.ready else {
            return Ok(());
        };
        let result = ready.await;
        self.ready = None;
        result.map_err(|_| io::Error::other("platform setup worker ended before notification"))
    }

    /// Join the exact worker and claim its actual result once; a panicked worker
    /// becomes a bounded error without resuming or copying its panic payload.
    pub async fn finish(&mut self) -> io::Result<T> {
        // A lost notification can mean worker panic. Always join it rather than
        // returning early and implying that an unobserved worker has released.
        let _ = self.wait().await;
        self.worker
            .take()
            .ok_or_else(|| io::Error::other("platform setup result already claimed"))?
            .join()
            .map_err(|_| io::Error::other("platform setup worker panicked"))?
    }
}

impl<T> Drop for Setup<T> {
    fn drop(&mut self) {
        // This may wait for the OS call. It is intentional: dropping the parent
        // future must not leave setup creating an adapter after cancellation.
        if let Some(worker) = self.worker.take() {
            let result = worker.join();
            drop(result);
        }
    }
}

#[cfg(test)]
#[path = "setup_tests.rs"]
mod tests;
