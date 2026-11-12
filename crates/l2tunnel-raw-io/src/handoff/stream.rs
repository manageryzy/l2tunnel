use super::*;
use std::pin::Pin;
use std::sync::{Arc, Mutex, MutexGuard};
use std::task::{Context, Poll, Waker};
use tokio::io::{AsyncRead, AsyncWrite, DuplexStream, ReadBuf};
use tokio::time::Instant;

#[derive(Clone, Copy)]
pub(super) struct Request {
    pub endpoint: EndpointProgress,
    pub deadline: Duration,
}
pub(super) struct Gate {
    pub status: SwitchStatus,
    pub started: Option<Instant>,
    pub limits: SwitchLimits,
    pub command: Option<Request>,
    pub stream_alive: bool,
    pub handle_alive: bool,
    pub shutdown: bool,
    pub eof: bool,
    pub read_waker: Option<Waker>,
    pub write_waker: Option<Waker>,
    pub driver_waker: Option<Waker>,
}
pub(super) type Shared = Arc<Mutex<Gate>>;
pub(super) fn lock(shared: &Shared) -> io::Result<MutexGuard<'_, Gate>> {
    shared.lock().map_err(|_| aborted("switch gate poisoned"))
}
impl Gate {
    pub fn new(limits: SwitchLimits) -> Self {
        Self {
            status: SwitchStatus::default(),
            started: None,
            limits,
            command: None,
            stream_alive: true,
            handle_alive: true,
            shutdown: false,
            eof: false,
            read_waker: None,
            write_waker: None,
            driver_waker: None,
        }
    }
    fn usable(&self) -> io::Result<()> {
        match self.status.state {
            SwitchState::NotStarted | SwitchState::Running | SwitchState::Clean => Ok(()),
            _ => Err(aborted("tracked stream is frozen or terminal")),
        }
    }
    pub fn take_wakers(&mut self) -> [Option<Waker>; 3] {
        [
            self.read_waker.take(),
            self.write_waker.take(),
            self.driver_waker.take(),
        ]
    }
}
pub(super) fn wake(wakers: [Option<Waker>; 3]) {
    for waker in wakers.into_iter().flatten() {
        waker.wake();
    }
}
/// Original bounded stream endpoint, counted from construction and frozen atomically.
///
/// It has no inner-stream accessor, cloning or counter import. Pending/error
/// polls charge zero; successful partial operations charge exactly their progress.
/// Once frozen, every read/write/flush/shutdown poll fails explicitly.
pub struct TrackedStream {
    pub(super) inner: DuplexStream,
    pub(super) shared: Shared,
}
impl AsyncRead for TrackedStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let mut gate = lock(&this.shared)?;
        gate.usable()?;
        let possible = output.remaining();
        let ceiling = reserve(gate.status.endpoint.read, possible)?;
        let before = output.filled().len();
        let result = Pin::new(&mut this.inner).poll_read(cx, output);
        match &result {
            Poll::Ready(Ok(())) => {
                let actual = output.filled().len() - before;
                gate.status.endpoint.read = charged(ceiling, possible, actual);
                gate.eof |= actual == 0 && possible > 0;
                gate.read_waker = None;
            }
            Poll::Pending => gate.read_waker = Some(cx.waker().clone()),
            Poll::Ready(Err(_)) => {}
        }
        result
    }
}
impl AsyncWrite for TrackedStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let mut gate = lock(&this.shared)?;
        gate.usable()?;
        let ceiling = reserve(gate.status.endpoint.written, bytes.len())?;
        let result = Pin::new(&mut this.inner).poll_write(cx, bytes);
        match &result {
            Poll::Ready(Ok(size)) => {
                gate.status.endpoint.written = charged(ceiling, bytes.len(), *size);
                gate.write_waker = None;
            }
            Poll::Pending => gate.write_waker = Some(cx.waker().clone()),
            Poll::Ready(Err(_)) => {}
        }
        result
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let gate = lock(&this.shared)?;
        gate.usable()?;
        Pin::new(&mut this.inner).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let mut gate = lock(&this.shared)?;
        gate.usable()?;
        let result = Pin::new(&mut this.inner).poll_shutdown(cx);
        if matches!(result, Poll::Ready(Ok(()))) {
            gate.shutdown = true;
        }
        result
    }
}
impl Drop for TrackedStream {
    fn drop(&mut self) {
        let wakers = if let Ok(mut gate) = self.shared.lock() {
            gate.stream_alive = false;
            gate.take_wakers()
        } else {
            [None, None, None]
        };
        wake(wakers);
    }
}
/// Unique control handle for this exact bridge; no public fence constructor.
pub struct SwitchHandle {
    pub(super) shared: Shared,
}
impl SwitchHandle {
    /// Read the coalesced local observation, not a transferable completion proof.
    pub fn status(&self) -> SwitchStatus {
        match self.shared.lock() {
            Ok(gate) => gate.status,
            Err(_) => SwitchStatus {
                state: SwitchState::Failed,
                ..SwitchStatus::default()
            },
        }
    }
    /// Atomically freeze both endpoint directions and request a single handoff.
    ///
    /// `deadline` is absolute since run started; reject before start, after close,
    /// without positive duplex prefixes, or beyond the configured remaining bound.
    /// Rejection changes no state. Acceptance cannot be undone or extended.
    pub fn request_handoff(&mut self, deadline: Duration) -> io::Result<()> {
        let wakers = {
            let mut gate = lock(&self.shared)?;
            let started = gate.started.ok_or_else(|| {
                io::Error::new(io::ErrorKind::NotConnected, "switch driver not started")
            })?;
            let elapsed = started.elapsed();
            let remaining = deadline
                .checked_sub(elapsed)
                .ok_or_else(|| invalid("stale handoff deadline"))?;
            if remaining.is_zero()
                || remaining > gate.limits.max_handoff_duration
                || started.checked_add(deadline).is_none()
            {
                return Err(invalid("handoff deadline bound"));
            }
            if gate.status.state != SwitchState::Running
                || gate.command.is_some()
                || !gate.stream_alive
                || gate.shutdown
                || gate.eof
                || gate.status.endpoint.written == 0
                || gate.status.endpoint.read == 0
                || !gate
                    .status
                    .engine
                    .is_some_and(|s| s.state == l2tunnel_raw_tcp::State::Established)
            {
                return Err(aborted("handoff is unavailable for this bridge"));
            }
            let endpoint = gate.status.endpoint;
            gate.command = Some(Request { endpoint, deadline });
            gate.status.state = SwitchState::Frozen;
            gate.status.deadline = Some(deadline);
            gate.take_wakers()
        };
        wake(wakers);
        Ok(())
    }
}
impl Drop for SwitchHandle {
    fn drop(&mut self) {
        let wakers = if let Ok(mut gate) = self.shared.lock() {
            gate.handle_alive = false;
            gate.take_wakers()
        } else {
            [None, None, None]
        };
        wake(wakers);
    }
}
