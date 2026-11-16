//! Bounded adaptation of the existing proxy byte stream to Common records.
//!
//! The internal datagram port carries one opaque, length-prefixed proxy frame.
//! Legacy shutdown remains explicitly refused; retained-close selection keeps
//! the actual Common recovery owner live through the actor's original cap. Its `Ip` layer
//! describes the eventual proxy TUN
//! attachment only: these bytes must enter Common's typed proxy-record API and
//! must never pass through a native IP parser. No TCP, authentication, ordering,
//! or recovery state machine lives here.

use l2tunnel_codec::aligned_receiver::RecordIdentity;
use l2tunnel_device::{PacketDevice, PacketLayer};
use std::io;
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::net::UnixDatagram;
use std::pin::Pin;
use std::sync::{Arc, Mutex, MutexGuard};
use std::task::{Context, Poll, Waker};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::UnixDatagram as AsyncDatagram;
use tokio::time::{Instant, Sleep, sleep_until};

#[derive(Clone, Copy)]
struct Failure {
    kind: io::ErrorKind,
    message: &'static str,
}
impl Failure {
    fn error(self) -> io::Error {
        io::Error::new(self.kind, self.message)
    }
}
struct Pending {
    generation: u64,
    arrived: Instant,
    deadline: Instant,
    sent: bool,
    identity: Option<RecordIdentity>,
    completed: bool,
    final_record: bool,
}
struct Retirement {
    cap: Option<Instant>,
    identity: Option<RecordIdentity>,
    source: Option<l2tunnel_recovery::SourceId>,
    physical: bool,
    confirmed: bool,
    peer_eof: bool,
    actor_joined: bool,
    retired: bool,
    waiter: Option<Waker>,
}
struct State {
    retirement: Option<Retirement>,
    generation: u64,
    pending: Option<Pending>,
    failure: Option<Failure>,
    reader: Option<Waker>,
    writer: Option<Waker>,
}
impl State {
    fn check(&self) -> io::Result<()> {
        match self.failure {
            Some(failure) => Err(failure.error()),
            None => Ok(()),
        }
    }
    fn fail(&mut self, kind: io::ErrorKind, message: &'static str) -> io::Error {
        let failure = *self.failure.get_or_insert(Failure { kind, message });
        if let Some(waker) = self.retirement.as_mut().and_then(|r| r.waiter.take()) {
            waker.wake();
        }
        if let Some(waker) = self.reader.take() {
            waker.wake();
        }
        if let Some(waker) = self.writer.take() {
            waker.wake();
        }
        failure.error()
    }
}

/// One retained outgoing slot shared with Common's physical completion owner.
#[derive(Clone)]
pub(crate) struct Bridge(Arc<Mutex<State>>);
impl Bridge {
    fn lock(&self) -> io::Result<MutexGuard<'_, State>> {
        self.0
            .lock()
            .map_err(|_| io::Error::other("proxy Common bridge lock poisoned"))
    }
    /// Preserve the existing actor's exact original drain cap.
    pub(crate) fn set_drain_cap(&self, cap: Instant) -> io::Result<()> {
        let mut state = self.lock()?;
        state.check()?;
        if Instant::now() >= cap {
            return Err(state.fail(io::ErrorKind::TimedOut, "proxy Common original drain cap"));
        }
        let retirement = state.retirement.as_mut().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::Unsupported,
                "Common retained close not selected",
            )
        })?;
        retirement.cap = Some(retirement.cap.map_or(cap, |old| old.min(cap)));
        Ok(())
    }
    /// Bind a final identity only to an actual maintained-parser source.
    pub(crate) fn bind_final_source(
        &self,
        identity: RecordIdentity,
        source: l2tunnel_recovery::SourceId,
    ) -> io::Result<()> {
        let mut state = self.lock()?;
        state.check()?;
        let retirement = state.retirement.as_mut().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::Unsupported,
                "Common retained close not selected",
            )
        })?;
        if retirement.identity != Some(identity)
            || retirement.source.is_some_and(|old| old != source)
        {
            return Err(state.fail(io::ErrorKind::InvalidData, "Common final source mismatch"));
        }
        retirement.source = Some(source);
        Ok(())
    }
    pub(crate) fn final_identity(&self) -> io::Result<Option<RecordIdentity>> {
        let state = self.lock()?;
        state.check()?;
        Ok(state.retirement.as_ref().and_then(|r| r.identity))
    }
    pub(crate) fn final_source(&self) -> io::Result<Option<l2tunnel_recovery::SourceId>> {
        let state = self.lock()?;
        state.check()?;
        Ok(state.retirement.as_ref().and_then(|r| r.source))
    }
    /// Same actor cap, for the sole Driver's existing wake calculation.
    pub(crate) fn retirement_deadline(&self) -> io::Result<Option<Instant>> {
        let state = self.lock()?;
        state.check()?;
        Ok(state
            .retirement
            .as_ref()
            .filter(|r| !r.retired)
            .and_then(|r| r.cap))
    }
    /// Observe exact final-source debt through the same issuing ARQ owner.
    /// Engine drain is only local custody here; actor fences and peer EOF are
    /// separate mandatory evidence, and no peer's own result is inferred.
    pub(crate) fn advance_retirement(
        &self,
        source: Option<l2tunnel_recovery::SourceId>,
        source_retired: bool,
        custody_drained: bool,
    ) -> io::Result<()> {
        let mut state = self.lock()?;
        state.check()?;
        let Some(retirement) = state.retirement.as_mut() else {
            return Ok(());
        };
        let Some(cap) = retirement.cap else {
            return Ok(());
        };
        if retirement.retired {
            return Ok(());
        }
        if source != retirement.source {
            return Err(state.fail(
                io::ErrorKind::InvalidData,
                "Common final source observation mismatch",
            ));
        }
        if Instant::now() < cap {
            if source.is_some() && source_retired && retirement.physical {
                retirement.confirmed = true;
            }
            return Ok(());
        }
        if retirement.confirmed
            && source_retired
            && retirement.physical
            && retirement.peer_eof
            && retirement.actor_joined
            && custody_drained
        {
            retirement.retired = true;
            if let Some(waker) = retirement.waiter.take() {
                waker.wake();
            }
            Ok(())
        } else {
            Err(state.fail(
                io::ErrorKind::TimedOut,
                "Common final ARQ debt at original cap",
            ))
        }
    }
    /// Called only after this actor's actual fences, EOF events and child joins.
    /// The same Driver certifies local retained custody at the original cap;
    /// this wait never turns elapsed time or a physical write into peer receipt.
    pub(crate) async fn wait_retired(&self) -> io::Result<()> {
        let cap = {
            let mut state = self.lock()?;
            state.check()?;
            let retirement = state.retirement.as_mut().ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Common retirement owner missing",
                )
            })?;
            let cap = retirement.cap.ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Common retirement lacks actor cap",
                )
            })?;
            retirement.actor_joined = true;
            cap
        };
        let timer = sleep_until(cap);
        tokio::pin!(timer);
        std::future::poll_fn(|cx| {
            let mut state = self.lock()?;
            state.check()?;
            let retirement = state.retirement.as_mut().ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Common retirement owner missing",
                )
            })?;
            if retirement.retired {
                return Poll::Ready(Ok(()));
            }
            retirement.waiter = Some(cx.waker().clone());
            // Register the original boundary once. Driver's independent exact
            // cap wake performs the real ownership check, including held output.
            let _ = timer.as_mut().poll(cx);
            Poll::Pending
        })
        .await
    }
    /// Original first-write arrival and immutable transport deadline.
    pub(crate) fn timing(&self) -> io::Result<(Instant, Instant)> {
        let state = self.lock()?;
        state.check()?;
        let pending = state
            .pending
            .as_ref()
            .filter(|pending| pending.sent && !pending.completed)
            .ok_or_else(|| io::Error::other("proxy Common bridge has no sent record"))?;
        Ok((pending.arrived, pending.deadline))
    }
    /// Bind the exact identity allocated by successful Common record admission.
    pub(crate) fn admitted(&self, identity: RecordIdentity) -> io::Result<()> {
        let mut state = self.lock()?;
        state.check()?;
        let Some(pending) = state.pending.as_mut() else {
            return Err(state.fail(
                io::ErrorKind::InvalidData,
                "proxy Common admission without slot",
            ));
        };
        if !pending.sent || pending.completed || pending.identity.is_some_and(|old| old != identity)
        {
            return Err(state.fail(
                io::ErrorKind::InvalidData,
                "proxy Common admission mismatch",
            ));
        }
        if Instant::now() >= pending.deadline {
            return Err(state.fail(io::ErrorKind::TimedOut, "proxy Common admission deadline"));
        }
        pending.identity = Some(identity);
        if pending.final_record {
            let retirement = state.retirement.as_mut().ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Common final record not selected",
                )
            })?;
            if retirement.identity.is_some_and(|old| old != identity) {
                return Err(state.fail(io::ErrorKind::InvalidData, "Common final identity changed"));
            }
            retirement.identity = Some(identity);
        }
        Ok(())
    }
    /// Exact unresolved Common record whose physical output is still required.
    pub(crate) fn pending_identity(&self) -> Option<RecordIdentity> {
        let state = self.0.lock().ok()?;
        if state.failure.is_some() {
            return None;
        }
        state
            .pending
            .as_ref()
            .filter(|pending| !pending.completed)
            .and_then(|pending| pending.identity)
    }
    /// Release a writer only for its exact physical completion before its cap.
    /// Queue admission, a different identity, or an observation after the original
    /// deadline cannot advance the existing proxy writer's counters or fences.
    pub(crate) fn complete(
        &self,
        identity: RecordIdentity,
        accepted_at: Instant,
        observed_at: Instant,
    ) -> io::Result<()> {
        let mut state = self.lock()?;
        state.check()?;
        let Some(pending) = state.pending.as_mut() else {
            return Err(state.fail(
                io::ErrorKind::InvalidData,
                "proxy Common completion without slot",
            ));
        };
        if !pending.sent || pending.completed || pending.identity != Some(identity) {
            return Err(state.fail(
                io::ErrorKind::InvalidData,
                "proxy Common completion mismatch",
            ));
        }
        if accepted_at < pending.arrived || observed_at < accepted_at {
            return Err(state.fail(
                io::ErrorKind::InvalidData,
                "proxy Common completion time order",
            ));
        }
        if observed_at >= pending.deadline {
            return Err(state.fail(
                io::ErrorKind::TimedOut,
                "proxy Common physical completion deadline",
            ));
        }
        pending.completed = true;
        if pending.final_record {
            let retirement = state.retirement.as_mut().ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Common final physical owner missing",
                )
            })?;
            retirement.physical = true;
        }
        if let Some(waker) = state.writer.take() {
            waker.wake();
        }
        Ok(())
    }
    /// Terminal failure wakes both stream directions and never fabricates EOF.
    pub(crate) fn fail(&self) {
        if let Ok(mut state) = self.0.lock() {
            state.fail(io::ErrorKind::BrokenPipe, "proxy Common transport failed");
        }
    }
}

/// Internal opaque record port; not a native IP device despite its attachment tag.
pub(crate) struct RecordPort {
    socket: UnixDatagram,
    receive: Vec<u8>,
    maximum: usize,
    receive_closed: bool,
    transmit_closed: bool,
    bridge: Bridge,
}
impl AsRawFd for RecordPort {
    fn as_raw_fd(&self) -> RawFd {
        self.socket.as_raw_fd()
    }
}
impl PacketDevice for RecordPort {
    type Error = io::Error;
    fn layer(&self) -> PacketLayer {
        PacketLayer::Ip
    }
    fn receive(&mut self, buffer: &mut [u8]) -> io::Result<Option<usize>> {
        self.bridge.lock()?.check()?;
        if self.receive_closed {
            return Ok(None);
        }
        let size = match self.socket.recv(&mut self.receive) {
            Ok(size) => size,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(None),
            Err(error) => return Err(error),
        };
        validate(&self.receive[..size], self.maximum)?;
        if buffer.len() < size {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "proxy Common receive storage",
            ));
        }
        buffer[..size].copy_from_slice(&self.receive[..size]);
        self.receive_closed = size == 1;
        Ok(Some(size))
    }
    fn transmit(&mut self, packet: &[u8]) -> io::Result<()> {
        self.bridge.lock()?.check()?;
        if self.transmit_closed {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "proxy Common record after EOF",
            ));
        }
        validate(packet, self.maximum)?;
        let size = self.socket.send(packet)?;
        if size != packet.len() {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "proxy Common partial datagram",
            ));
        }
        self.transmit_closed = packet == [0];
        if self.transmit_closed {
            let mut state = self.bridge.lock()?;
            if let Some(retirement) = &mut state.retirement {
                retirement.peer_eof = true;
            }
        }
        Ok(())
    }
}

/// Existing proxy reader/writer interface with one retained outgoing frame.
pub(crate) struct Stream {
    socket: AsyncDatagram,
    bridge: Bridge,
    maximum: usize,
    stall: Duration,
    output: Vec<u8>,
    generation: Option<u64>,
    deadline: Option<Pin<Box<Sleep>>>,
    input: Vec<u8>,
    input_size: usize,
    input_offset: usize,
    read_closed: bool,
    shutdown_started: bool,
    write_closed: bool,
}

/// Create bounded local adaptation; `maximum` includes the four-byte frame prefix.
pub(crate) fn pair(maximum: usize, stall: Duration) -> io::Result<(RecordPort, Stream, Bridge)> {
    pair_selected(maximum, stall, false)
}
pub(crate) fn pair_retained(
    maximum: usize,
    stall: Duration,
) -> io::Result<(RecordPort, Stream, Bridge)> {
    pair_selected(maximum, stall, true)
}
fn pair_selected(
    maximum: usize,
    stall: Duration,
    retained: bool,
) -> io::Result<(RecordPort, Stream, Bridge)> {
    if !(5..=65_535).contains(&maximum) || stall.is_zero() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "proxy Common bridge bounds",
        ));
    }
    let (port, stream) = UnixDatagram::pair()?;
    port.set_nonblocking(true)?;
    stream.set_nonblocking(true)?;
    let bridge = Bridge(Arc::new(Mutex::new(State {
        retirement: retained.then_some(Retirement {
            cap: None,
            identity: None,
            source: None,
            physical: false,
            confirmed: false,
            peer_eof: false,
            actor_joined: false,
            retired: false,
            waiter: None,
        }),
        generation: 0,
        pending: None,
        failure: None,
        reader: None,
        writer: None,
    })));
    Ok((
        RecordPort {
            socket: port,
            receive: vec![0; maximum + 1],
            maximum,
            receive_closed: false,
            transmit_closed: false,
            bridge: bridge.clone(),
        },
        Stream {
            socket: AsyncDatagram::from_std(stream)?,
            bridge: bridge.clone(),
            maximum,
            stall,
            output: Vec::with_capacity(maximum),
            generation: None,
            deadline: None,
            input: vec![0; maximum + 1],
            input_size: 0,
            input_offset: 0,
            read_closed: false,
            shutdown_started: false,
            write_closed: false,
        },
        bridge,
    ))
}

fn validate(bytes: &[u8], maximum: usize) -> io::Result<()> {
    if bytes == [0] {
        return Ok(());
    }
    if bytes.len() > maximum || bytes.len() < 5 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "proxy Common record length",
        ));
    }
    let prefix = [bytes[0], bytes[1], bytes[2], bytes[3]];
    let body = usize::try_from(u32::from_be_bytes(prefix)).map_err(io::Error::other)?;
    if body.checked_add(4) != Some(bytes.len()) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "proxy Common frame boundary",
        ));
    }
    Ok(())
}
impl Stream {
    fn begin(&mut self, state: &mut State) -> io::Result<()> {
        if self.generation.is_some() {
            return Ok(());
        }
        if state.pending.is_some() {
            return Err(state.fail(io::ErrorKind::InvalidData, "proxy Common overlapping write"));
        }
        let arrived = Instant::now();
        let deadline = arrived.checked_add(self.stall).ok_or_else(|| {
            state.fail(
                io::ErrorKind::InvalidInput,
                "proxy Common deadline overflow",
            )
        })?;
        let deadline = state
            .retirement
            .as_ref()
            .and_then(|r| r.cap)
            .map_or(deadline, |cap| deadline.min(cap));
        let generation = state.generation.checked_add(1).ok_or_else(|| {
            state.fail(
                io::ErrorKind::InvalidData,
                "proxy Common generation exhausted",
            )
        })?;
        state.generation = generation;
        state.pending = Some(Pending {
            generation,
            arrived,
            deadline,
            sent: false,
            identity: None,
            completed: false,
            final_record: false,
        });
        self.generation = Some(generation);
        self.deadline = Some(Box::pin(sleep_until(deadline)));
        Ok(())
    }
    fn expired(&mut self, state: &mut State, cx: &mut Context<'_>) -> io::Result<()> {
        if let Some(deadline) = self.deadline.as_mut()
            && deadline.as_mut().poll(cx).is_ready()
        {
            return Err(state.fail(
                io::ErrorKind::TimedOut,
                "proxy Common original write deadline",
            ));
        }
        Ok(())
    }
    fn poll_flush_record(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let bridge = self.bridge.clone();
        let mut state = bridge.lock()?;
        state.check()?;
        let Some(generation) = self.generation else {
            return Poll::Ready(Ok(()));
        };
        let Some(pending) = state.pending.as_ref() else {
            return Poll::Ready(Err(
                state.fail(io::ErrorKind::InvalidData, "proxy Common lost write")
            ));
        };
        if pending.generation != generation {
            return Poll::Ready(Err(
                state.fail(io::ErrorKind::InvalidData, "proxy Common write generation")
            ));
        }
        if pending.completed {
            state.pending = None;
            state.writer = None;
            self.output.clear();
            self.generation = None;
            self.deadline = None;
            return Poll::Ready(Ok(()));
        }
        self.expired(&mut state, cx)?;
        state.writer = Some(cx.waker().clone());
        if !state.pending.as_ref().is_some_and(|pending| pending.sent) {
            if let Err(error) = validate(&self.output, self.maximum) {
                return Poll::Ready(Err(
                    state.fail(error.kind(), "proxy Common incomplete flush")
                ));
            }
            match self.socket.poll_send(cx, &self.output) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => {
                    return Poll::Ready(Err(
                        state.fail(error.kind(), "proxy Common datagram write")
                    ));
                }
                Poll::Ready(Ok(size)) if size != self.output.len() => {
                    return Poll::Ready(Err(
                        state.fail(io::ErrorKind::WriteZero, "proxy Common partial record")
                    ));
                }
                Poll::Ready(Ok(_)) => {
                    if let Some(pending) = state.pending.as_mut() {
                        pending.sent = true;
                    }
                }
            }
        }
        // Sending to the internal port only transfers custody. The existing proxy
        // writer remains blocked until Common reports this record's physical I/O.
        Poll::Pending
    }
}
impl AsyncWrite for Stream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let bridge = this.bridge.clone();
        let mut state = bridge.lock()?;
        state.check()?;
        if this.shutdown_started || this.write_closed {
            return Poll::Ready(Err(
                state.fail(io::ErrorKind::BrokenPipe, "Common write after final record")
            ));
        }
        if bytes.is_empty() {
            return Poll::Ready(Ok(0));
        }
        this.begin(&mut state)?;
        this.expired(&mut state, cx)?;
        state.writer = Some(cx.waker().clone());
        let target = if this.output.len() < 4 {
            4
        } else {
            let prefix = [
                this.output[0],
                this.output[1],
                this.output[2],
                this.output[3],
            ];
            let body = usize::try_from(u32::from_be_bytes(prefix)).map_err(io::Error::other)?;
            let Some(target) = body
                .checked_add(4)
                .filter(|size| *size <= this.maximum && body > 0)
            else {
                return Poll::Ready(Err(state.fail(
                    io::ErrorKind::InvalidData,
                    "proxy Common outgoing frame bound",
                )));
            };
            target
        };
        if this.output.len() == target {
            return Poll::Pending;
        }
        let accepted = bytes.len().min(target - this.output.len());
        this.output.extend_from_slice(&bytes[..accepted]);
        Poll::Ready(Ok(accepted))
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.get_mut().poll_flush_record(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.write_closed {
            return Poll::Ready(Ok(()));
        }
        if !this.shutdown_started {
            match this.poll_flush_record(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(result) => result?,
            }
            let bridge = this.bridge.clone();
            let mut state = bridge.lock()?;
            state.check()?;
            if state.retirement.as_ref().and_then(|r| r.cap).is_none() {
                return Poll::Ready(Err(state.fail(
                    io::ErrorKind::Unsupported,
                    "Common proxy graceful close requires retained reliable EOF retirement",
                )));
            }
            this.begin(&mut state)?;
            state
                .pending
                .as_mut()
                .ok_or_else(|| io::Error::other("Common final slot missing"))?
                .final_record = true;
            this.output.push(0);
            this.shutdown_started = true;
        }
        match this.poll_flush_record(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(result) => {
                result?;
                this.write_closed = true;
                Poll::Ready(Ok(()))
            }
        }
    }
}
impl AsyncRead for Stream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let bridge = this.bridge.clone();
        let mut state = bridge.lock()?;
        state.check()?;
        state.reader = Some(cx.waker().clone());
        if output.remaining() == 0 || this.read_closed {
            return Poll::Ready(Ok(()));
        }
        if this.input_offset == this.input_size {
            let mut input = ReadBuf::new(&mut this.input);
            match this.socket.poll_recv(cx, &mut input) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => {
                    return Poll::Ready(
                        Err(state.fail(error.kind(), "proxy Common datagram read")),
                    );
                }
                Poll::Ready(Ok(())) => {}
            }
            let bytes = input.filled();
            if let Err(error) = validate(bytes, this.maximum) {
                return Poll::Ready(Err(
                    state.fail(error.kind(), "proxy Common incoming record bound")
                ));
            }
            if bytes == [0] {
                this.read_closed = true;
                return Poll::Ready(Ok(()));
            }
            this.input_size = bytes.len();
            this.input_offset = 0;
        }
        let size = output.remaining().min(this.input_size - this.input_offset);
        output.put_slice(&this.input[this.input_offset..this.input_offset + size]);
        this.input_offset += size;
        Poll::Ready(Ok(()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use l2tunnel_codec::aligned_receiver::{ChannelId, RecordId};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::task::Wake;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn identity(record: u64) -> RecordIdentity {
        RecordIdentity {
            channel: ChannelId(0),
            record: RecordId(record),
        }
    }
    fn poll_flush_once(stream: &mut Stream) -> Poll<io::Result<()>> {
        let mut cx = Context::from_waker(Waker::noop());
        Pin::new(stream).poll_flush(&mut cx)
    }

    #[tokio::test(start_paused = true)]
    async fn partial_writes_need_exact_physical_completion() -> io::Result<()> {
        let (mut port, mut stream, bridge) = pair(64, Duration::from_secs(10))?;
        let first = Instant::now();
        stream.write_all(&[0, 0]).await?;
        tokio::time::advance(Duration::from_secs(2)).await;
        stream.write_all(&[0, 4]).await?;
        stream.write_all(&[1, 2]).await?;
        stream.write_all(&[3, 4]).await?;
        let mut bytes = [0; 65];
        assert_eq!(port.receive(&mut bytes)?, None);
        stream.socket.writable().await?;
        assert!(poll_flush_once(&mut stream).is_pending());
        assert_eq!(port.receive(&mut bytes)?, Some(8));
        assert_eq!(&bytes[..8], &[0, 0, 0, 4, 1, 2, 3, 4]);
        assert_eq!(bridge.timing()?, (first, first + Duration::from_secs(10)));
        bridge.admitted(identity(3))?;
        assert_eq!(bridge.pending_identity(), Some(identity(3)));
        assert!(poll_flush_once(&mut stream).is_pending());
        let mut cx = Context::from_waker(Waker::noop());
        assert!(Pin::new(&mut stream).poll_write(&mut cx, &[9]).is_pending());
        let now = Instant::now();
        bridge.complete(identity(3), now, now)?;
        stream.flush().await?;
        assert_eq!(bridge.pending_identity(), None);
        assert!(bridge.timing().is_err());
        stream.write_all(&[0, 0, 0, 1, 8]).await?;
        assert!(poll_flush_once(&mut stream).is_pending());
        assert_eq!(port.receive(&mut bytes)?, Some(5));
        bridge.admitted(identity(4))?;
        assert!(bridge.complete(identity(3), now, now).is_err());
        assert!(stream.flush().await.is_err());
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn physical_observation_cannot_renew_first_write_cap() -> io::Result<()> {
        let (mut port, mut stream, bridge) = pair(32, Duration::from_secs(10))?;
        let first = Instant::now();
        stream.write_all(&[0, 0, 0, 1]).await?;
        tokio::time::advance(Duration::from_secs(5)).await;
        stream.write_all(&[7]).await?;
        stream.socket.writable().await?;
        assert!(poll_flush_once(&mut stream).is_pending());
        let mut bytes = [0; 33];
        assert_eq!(port.receive(&mut bytes)?, Some(5));
        bridge.admitted(identity(1))?;
        tokio::time::advance(Duration::from_secs(5)).await;
        let error = bridge
            .complete(identity(1), first + Duration::from_secs(6), Instant::now())
            .err()
            .ok_or_else(|| io::Error::other("late receipt unexpectedly completed"))?;
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert!(stream.flush().await.is_err());
        Ok(())
    }

    #[tokio::test]
    async fn shutdown_refuses_clean_close_after_prior_physical_completion() -> io::Result<()> {
        let (mut port, mut stream, bridge) = pair(32, Duration::from_secs(10))?;
        stream.write_all(&[0, 0, 0, 1, 9]).await?;
        stream.socket.writable().await?;
        let mut cx = Context::from_waker(Waker::noop());
        assert!(Pin::new(&mut stream).poll_shutdown(&mut cx).is_pending());
        let mut bytes = [0; 33];
        assert_eq!(port.receive(&mut bytes)?, Some(5));
        assert_eq!(&bytes[..5], &[0, 0, 0, 1, 9]);
        bridge.admitted(identity(8))?;
        assert!(Pin::new(&mut stream).poll_shutdown(&mut cx).is_pending());
        let now = Instant::now();
        bridge.complete(identity(8), now, now)?;
        let error = stream
            .shutdown()
            .await
            .err()
            .ok_or_else(|| io::Error::other("Common close unexpectedly succeeded"))?;
        assert_eq!(error.kind(), io::ErrorKind::Unsupported);
        let error = port
            .socket
            .recv(&mut bytes)
            .err()
            .ok_or_else(|| io::Error::other("unsupported close emitted a synthetic EOF"))?;
        assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
        assert!(stream.read(&mut bytes).await.is_err());
        assert!(stream.write_all(&[0, 0, 0, 1, 5]).await.is_err());
        Ok(())
    }

    #[tokio::test]
    async fn peer_frames_are_read_progressively_and_truncation_fails() -> io::Result<()> {
        let (mut port, mut stream, _) = pair(16, Duration::from_secs(10))?;
        let frame = [0, 0, 0, 4, 11, 12, 13, 14];
        port.transmit(&frame)?;
        let mut prefix = [0; 4];
        stream.read_exact(&mut prefix).await?;
        assert_eq!(prefix, [0, 0, 0, 4]);
        let mut body = [0; 4];
        stream.read_exact(&mut body).await?;
        assert_eq!(body, [11, 12, 13, 14]);
        let oversized = [1; 18];
        assert_eq!(port.socket.send(&oversized)?, oversized.len());
        let error = stream
            .read(&mut body)
            .await
            .err()
            .ok_or_else(|| io::Error::other("oversized datagram unexpectedly accepted"))?;
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        Ok(())
    }

    struct Notice(AtomicBool);
    impl Wake for Notice {
        fn wake(self: Arc<Self>) {
            self.0.store(true, Ordering::SeqCst);
        }
    }
    #[tokio::test]
    async fn terminal_failure_wakes_both_directions_without_eof() -> io::Result<()> {
        let (_port, mut stream, bridge) = pair(32, Duration::from_secs(10))?;
        let reader = Arc::new(Notice(AtomicBool::new(false)));
        let writer = Arc::new(Notice(AtomicBool::new(false)));
        let reader_waker = Waker::from(reader.clone());
        let writer_waker = Waker::from(writer.clone());
        let mut bytes = [0; 8];
        let mut input = ReadBuf::new(&mut bytes);
        assert!(
            Pin::new(&mut stream)
                .poll_read(&mut Context::from_waker(&reader_waker), &mut input)
                .is_pending()
        );
        stream.write_all(&[0, 0, 0, 1, 9]).await?;
        stream.socket.writable().await?;
        assert!(
            Pin::new(&mut stream)
                .poll_flush(&mut Context::from_waker(&writer_waker))
                .is_pending()
        );
        reader.0.store(false, Ordering::SeqCst);
        writer.0.store(false, Ordering::SeqCst);
        bridge.fail();
        assert!(reader.0.load(Ordering::SeqCst));
        assert!(writer.0.load(Ordering::SeqCst));
        assert!(stream.read(&mut bytes).await.is_err());
        assert!(stream.flush().await.is_err());
        Ok(())
    }
}

#[cfg(test)]
#[path = "common_retirement_tests.rs"]
mod retirement_tests;
