use super::stream::{Gate, Request, Shared, lock, wake};
use super::*;
use l2tunnel_raw_tcp::handoff::{Error as TrackedError, HandoffError, TrackedEngine};
use l2tunnel_raw_tcp::{CloseReason, Error as EngineError, Millis, ReadOutcome, Role, State};
use std::future::{pending, poll_fn};
use std::sync::{Arc, Mutex, MutexGuard};
use std::task::Poll;
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
use tokio::time::{Instant, Interval};

struct Buffer {
    bytes: Vec<u8>,
    length: usize,
    offset: usize,
}
impl Buffer {
    fn new(size: usize) -> Self {
        Self {
            bytes: vec![0; size],
            length: 0,
            offset: 0,
        }
    }
    fn empty(&self) -> bool {
        self.length == self.offset
    }
    fn remaining(&self) -> &[u8] {
        &self.bytes[self.offset..self.length]
    }
}
/// Separately supervised original TCP owner with exact retained I/O accounting.
///
/// No task is spawned. Cancellation drops the original I/O without a cleanup
/// poll, FIN/RST, successful handoff result or same-tuple rollback.
pub struct SwitchDriver<I: PacketIo> {
    io: Option<I>,
    engine: Option<TrackedEngine>,
    bridge: DuplexStream,
    shared: Shared,
    config: Config,
    limits: SwitchLimits,
    progress: BridgeProgress,
    input: Buffer,
    output: Buffer,
    raw_input: Vec<u8>,
    pending_packet: Option<Vec<u8>>,
    request: Option<Request>,
    caller_eof: bool,
    peer_eof: bool,
    bridge_shutdown: bool,
    closed_send: bool,
    close_started: Option<Millis>,
    parent_deadline: Option<Instant>,
}
/// Build an original bounded counted bridge, unique handle and supervised driver.
/// Construction validates geometry without opening sockets or starting a clock.
pub fn bridge_switchable<I: PacketIo>(
    config: Config,
    role: Role,
    io: I,
    limits: SwitchLimits,
) -> io::Result<(TrackedStream, SwitchHandle, SwitchDriver<I>)> {
    Ok(PreparedBridge::new(config, role, limits)?.attach(io))
}
/// Fallible allocation without adopting any caller packet owner.
pub(super) struct PreparedBridge {
    config: Config,
    limits: SwitchLimits,
    engine: TrackedEngine,
    stream: DuplexStream,
    bridge: DuplexStream,
    shared: Shared,
    input: Buffer,
    output: Buffer,
    raw_input: Vec<u8>,
}
impl PreparedBridge {
    pub(super) fn new(config: Config, role: Role, limits: SwitchLimits) -> io::Result<Self> {
        geometry(config)?;
        limits.validate()?;
        let engine = TrackedEngine::new(config, role, Millis(0)).map_err(tracked_error)?;
        let (stream, bridge) = tokio::io::duplex(config.mtu);
        Ok(Self {
            config,
            limits,
            engine,
            stream,
            bridge,
            shared: Arc::new(Mutex::new(Gate::new(limits))),
            input: Buffer::new(config.mtu),
            output: Buffer::new(config.mtu),
            raw_input: vec![0; 65_536],
        })
    }
    pub(super) fn attach<I: PacketIo>(
        self,
        io: I,
    ) -> (TrackedStream, SwitchHandle, SwitchDriver<I>) {
        let stream = TrackedStream {
            inner: self.stream,
            shared: self.shared.clone(),
        };
        let handle = SwitchHandle {
            shared: self.shared.clone(),
        };
        let driver = SwitchDriver {
            io: Some(io),
            engine: Some(self.engine),
            bridge: self.bridge,
            shared: self.shared,
            config: self.config,
            limits: self.limits,
            progress: BridgeProgress::default(),
            input: self.input,
            output: self.output,
            raw_input: self.raw_input,
            pending_packet: None,
            request: None,
            caller_eof: false,
            peer_eof: false,
            bridge_shutdown: false,
            closed_send: false,
            close_started: None,
            parent_deadline: None,
        };
        (stream, handle, driver)
    }
}

impl<I: PacketIo> Drop for SwitchDriver<I> {
    fn drop(&mut self) {
        let wakers = if let Ok(mut gate) = self.shared.lock() {
            if self.parent_deadline.is_some() {
                // The owned pair reports actual completed I/O even when a slow
                // adapter crosses its deadline before the normal publish point.
                gate.status.driver = self.progress;
                gate.status.engine = self.engine.as_ref().map(TrackedEngine::status);
                if let Some(started) = gate.started {
                    gate.status.elapsed = started.elapsed();
                }
            }
            if !matches!(gate.status.state, SwitchState::Handoff | SwitchState::Clean) {
                gate.status.state = SwitchState::Failed;
            }
            gate.take_wakers()
        } else {
            [None, None, None]
        };
        wake(wakers);
    }
}
impl<I: PacketIo> SwitchDriver<I> {
    /// Run until maintained clean close, a unique local handoff, or terminal failure.
    /// A caller must supervise and join/cancel this future with its TLS owner.
    pub async fn run(self) -> io::Result<SwitchExit<I>> {
        self.run_inner(None).await
    }
    pub(super) async fn run_owned_pair(self, deadline: Instant) -> io::Result<SwitchExit<I>> {
        self.run_inner(Some(deadline)).await
    }
    async fn run_inner(mut self, deadline: Option<Instant>) -> io::Result<SwitchExit<I>> {
        self.parent_deadline = deadline;
        self.check_parent()?;
        let started = Instant::now();
        {
            let mut gate = lock(&self.shared)?;
            gate.started = Some(started);
            gate.status.state = SwitchState::Running;
            gate.status.engine = Some(self.engine()?.status());
        }
        let mut tick = tokio::time::interval(Duration::from_millis(1));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            self.check_parent()?;
            self.observe_request(started)?;
            let elapsed = started.elapsed();
            let now = Millis(u64::try_from(elapsed.as_millis()).map_err(io::Error::other)?);
            if !self.engine()?.status().established
                && elapsed >= Duration::from_millis(self.config.idle_timeout_millis)
            {
                return Err(timeout("raw TCP handshake deadline"));
            }
            self.receive_packets()?;
            self.check_parent()?;
            let work_limit = self.limits.work_limit;
            self.engine_mut()?
                .poll(now, work_limit)
                .map_err(tracked_error)?;
            self.check_parent()?;
            self.send_packets()?;
            self.check_parent()?;
            self.move_stream_bytes()?;
            self.check_parent()?;
            self.publish(started)?;
            if let Some(parts) = self.try_handoff(started, now)? {
                // No await, user callback or further I/O after the gate's commit.
                return Ok(SwitchExit::Handoff(parts));
            }
            if self.clean_close(now)? {
                lock(&self.shared)?.status.state = SwitchState::Clean;
                return Ok(SwitchExit::Clean(self.counters()));
            }
            self.wait_for_work(started, &mut tick).await?;
            self.check_parent()?;
            if self.parent_deadline.is_some() {
                // Outside select: Pending must escape this driver poll even when
                // every wait branch is ready. No second pass in the same poll.
                YieldOnce(false).await;
            }
        }
    }
    fn check_parent(&self) -> io::Result<()> {
        if self.parent_deadline.is_some_and(|at| Instant::now() >= at) {
            Err(timeout("original raw pair deadline"))
        } else {
            Ok(())
        }
    }
    fn engine(&self) -> io::Result<&TrackedEngine> {
        self.engine
            .as_ref()
            .ok_or_else(|| aborted("TCP owner already transferred"))
    }
    fn engine_mut(&mut self) -> io::Result<&mut TrackedEngine> {
        self.engine
            .as_mut()
            .ok_or_else(|| aborted("TCP owner already transferred"))
    }
    fn observe_request(&mut self, started: Instant) -> io::Result<()> {
        let mut gate = lock(&self.shared)?;
        if let Some(request) = gate.command.take() {
            if self.request.is_some() {
                return Err(aborted("duplicate private handoff command"));
            }
            self.request = Some(request);
        }
        if let Some(request) = self.request {
            if !gate.stream_alive || !gate.handle_alive {
                return Err(aborted("handoff endpoint or handle cancelled"));
            }
            if started.elapsed() >= request.deadline {
                return Err(timeout("raw handoff deadline"));
            }
        }
        Ok(())
    }
    fn receive_packets(&mut self) -> io::Result<()> {
        for _ in 0..self.limits.work_limit {
            self.check_parent()?;
            let packets = reserve(self.progress.raw_received_packets, 1)?;
            let bytes = reserve(self.progress.raw_received_bytes, self.raw_input.len())?;
            let discarded = reserve(self.progress.discarded_packets, 1)?;
            let io = self
                .io
                .as_mut()
                .ok_or_else(|| aborted("packet owner already transferred"))?;
            let size = match io.receive(&mut self.raw_input) {
                Ok(Some(size)) => size,
                Ok(None) => {
                    self.check_parent()?;
                    break;
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    self.check_parent()?;
                    break;
                }
                Err(error) => return Err(error),
            };
            if size > self.raw_input.len() {
                return Err(io::Error::other("packet adapter exceeded sentinel"));
            }
            self.progress.raw_received_packets = packets;
            self.progress.raw_received_bytes = charged(bytes, self.raw_input.len(), size);
            self.check_parent()?;
            let engine = self
                .engine
                .as_mut()
                .ok_or_else(|| aborted("TCP owner already transferred"))?;
            match engine.ingest(&self.raw_input[..size]) {
                Ok(()) => {}
                Err(TrackedError::Engine(
                    EngineError::Malformed
                    | EngineError::Checksum
                    | EngineError::Tuple
                    | EngineError::Mtu
                    | EngineError::QueueFull,
                )) => {
                    self.progress.discarded_packets = discarded;
                }
                Err(error) => return Err(tracked_error(error)),
            }
        }
        Ok(())
    }
    fn send_packets(&mut self) -> io::Result<()> {
        for _ in 0..self.limits.work_limit {
            self.check_parent()?;
            if self.pending_packet.is_none() {
                if self.engine()?.status().outgoing_packets == 0 {
                    break;
                }
                let packets = reserve(self.progress.raw_popped_packets, 1)?;
                let bytes = reserve(self.progress.raw_popped_bytes, self.config.mtu)?;
                let packet = self
                    .engine_mut()?
                    .pop_packet()
                    .ok_or_else(|| aborted("missing queued engine packet"))?;
                if packet.len() > self.config.mtu {
                    return Err(io::Error::other("engine packet exceeds MTU"));
                }
                self.progress.raw_popped_packets = packets;
                self.progress.raw_popped_bytes = charged(bytes, self.config.mtu, packet.len());
                self.pending_packet = Some(packet);
            }
            let packet = self
                .pending_packet
                .as_ref()
                .ok_or_else(|| aborted("missing retained raw packet"))?;
            let packets = reserve(self.progress.raw_sent_packets, 1)?;
            let bytes = reserve(self.progress.raw_sent_bytes, packet.len())?;
            let io = self
                .io
                .as_mut()
                .ok_or_else(|| aborted("packet owner already transferred"))?;
            match io.send(packet) {
                Ok(()) => {
                    self.progress.raw_sent_packets = packets;
                    self.progress.raw_sent_bytes = bytes;
                    self.pending_packet = None;
                    self.check_parent()?;
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    self.check_parent()?;
                    break;
                }
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }
    fn move_stream_bytes(&mut self) -> io::Result<()> {
        let state = self.engine()?.status().state;
        if !self.input.empty() && matches!(state, State::Established | State::CloseWait) {
            let engine = self
                .engine
                .as_mut()
                .ok_or_else(|| aborted("TCP owner already transferred"))?;
            let size = engine
                .write(self.input.remaining())
                .map_err(tracked_error)?;
            self.input.offset += size;
        }
        if self.request.is_some() {
            // A frozen reader cannot consume any further ciphertext. Inbound
            // bytes already outside its fence are a failure, never synthetic reads.
            self.inbound_fence()?;
            if state != State::Established || self.caller_eof || self.peer_eof || self.closed_send {
                return Err(aborted("TCP closed during handoff"));
            }
            return Ok(());
        }
        if self.caller_eof
            && self.input.empty()
            && self.engine()?.status().established
            && !self.closed_send
        {
            self.engine_mut()?.close();
            self.closed_send = true;
        }
        if self.output.empty() && !self.peer_eof {
            let possible = self
                .engine()?
                .status()
                .receive_bytes
                .min(self.output.bytes.len());
            reserve(self.progress.inbound_written, possible)?;
            let engine = self
                .engine
                .as_mut()
                .ok_or_else(|| aborted("TCP owner already transferred"))?;
            match engine.read(&mut self.output.bytes).map_err(tracked_error)? {
                ReadOutcome::Data(size) => {
                    self.output.length = size;
                    self.output.offset = 0;
                }
                ReadOutcome::Pending => {}
                ReadOutcome::Eof => self.peer_eof = true,
            }
        }
        Ok(())
    }
    fn inbound_fence(&self) -> io::Result<()> {
        let request = self
            .request
            .ok_or_else(|| aborted("missing private freeze fence"))?;
        if self.progress.inbound_written != request.endpoint.read
            || self.engine()?.progress().receive_consumed != request.endpoint.read
            || !self.output.empty()
            || self.engine()?.status().receive_bytes != 0
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unread ciphertext beyond frozen endpoint",
            ));
        }
        Ok(())
    }
    fn publish(&self, started: Instant) -> io::Result<()> {
        let mut gate = lock(&self.shared)?;
        gate.status.elapsed = started.elapsed();
        gate.status.driver = self.progress;
        gate.status.engine = Some(self.engine()?.status());
        Ok(())
    }
    fn try_handoff(
        &mut self,
        started: Instant,
        now: Millis,
    ) -> io::Result<Option<HandoffParts<I>>> {
        let Some(request) = self.request else {
            return Ok(None);
        };
        self.inbound_fence()?;
        let progress = self.engine()?.progress();
        if self.progress.outbound_read > request.endpoint.written
            || progress.send_admitted > request.endpoint.written
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "outbound ciphertext exceeds frozen endpoint",
            ));
        }
        if self.progress.outbound_read != request.endpoint.written
            || progress.send_admitted != request.endpoint.written
            || !self.input.empty()
            || self.pending_packet.is_some()
            || self.progress.raw_popped_packets != self.progress.raw_sent_packets
            || self.progress.raw_popped_bytes != self.progress.raw_sent_bytes
        {
            return Ok(None);
        }
        let gate = lock(&self.shared)?;
        if !gate.stream_alive || !gate.handle_alive || gate.status.state != SwitchState::Frozen {
            return Err(aborted("handoff cancelled before commit"));
        }
        if started.elapsed() >= request.deadline {
            return Err(timeout("raw handoff deadline"));
        }
        let engine = self
            .engine
            .take()
            .ok_or_else(|| aborted("TCP owner already transferred"))?;
        let tcp = match engine.try_into_quiescent(now) {
            Ok(tcp) => tcp,
            Err((engine, error)) => {
                self.engine = Some(engine);
                return match error {
                    HandoffError::NotQuiescent | HandoffError::QueuedPacket => Ok(None),
                    _ => Err(io::Error::other(error)),
                };
            }
        };
        let io = self
            .io
            .take()
            .ok_or_else(|| aborted("packet owner already transferred"))?;
        let proof = BridgeProof {
            endpoint: request.endpoint,
            driver: self.progress,
            engine: progress,
        };
        let parts = HandoffParts {
            inner: Box::new(OwnedHandoff { io, tcp, proof }),
        };
        // Consuming/dropping the old stack and allocating the fixed bundle are
        // synchronous, but may still cross the deadline. Recheck live time.
        complete_handoff(gate, parts, started.elapsed(), request.deadline).map(Some)
    }
    fn clean_close(&mut self, now: Millis) -> io::Result<bool> {
        let status = self.engine()?.status();
        if status.state != State::Closed {
            return Ok(false);
        }
        if status.close_reason != Some(CloseReason::Clean) {
            return Err(crate::engine_error(EngineError::Terminated(
                status.close_reason.unwrap_or(CloseReason::Unexpected),
            )));
        }
        if self.request.is_some() {
            return Err(aborted("retained close cannot satisfy handoff"));
        }
        if status.established
            && self.caller_eof
            && self.peer_eof
            && self.bridge_shutdown
            && self.input.empty()
            && self.output.empty()
            && status.send_bytes == 0
            && status.receive_bytes == 0
            && status.outgoing_packets == 0
            && self.pending_packet.is_none()
        {
            return Ok(true);
        }
        let since = *self.close_started.get_or_insert(now);
        if now.0 - since.0 >= self.config.idle_timeout_millis {
            return Err(timeout("raw final bridge/packet drain deadline"));
        }
        Ok(false)
    }
    fn counters(&self) -> Counters {
        Counters {
            received_packets: self.progress.raw_received_packets - self.progress.discarded_packets,
            sent_packets: self.progress.raw_sent_packets,
            discarded_packets: self.progress.discarded_packets,
            sent_bytes: self.progress.outbound_read,
            received_bytes: self.progress.inbound_written,
        }
    }
    async fn wait_for_work(&mut self, started: Instant, tick: &mut Interval) -> io::Result<()> {
        // A new command may have arrived during the bounded synchronous pass.
        // Reject expiry before constructing any ready bridge-I/O future.
        self.check_parent()?;
        self.observe_request(started)?;
        let mut read_limit = self.input.bytes.len();
        if let Some(request) = self.request {
            let remaining = request
                .endpoint
                .written
                .checked_sub(self.progress.outbound_read)
                .ok_or_else(|| aborted("outbound fence underflow"))?;
            read_limit = read_limit.min(usize::try_from(remaining).unwrap_or(usize::MAX));
        }
        let can_read = !self.caller_eof
            && self.input.empty()
            && self.engine()?.status().established
            && read_limit > 0;
        let can_write = !self.output.empty() && self.request.is_none();
        let read_ceiling = if can_read {
            reserve(self.progress.outbound_read, read_limit)?
        } else {
            0
        };
        let write_limit = self.output.length - self.output.offset;
        let write_ceiling = if can_write {
            reserve(self.progress.inbound_written, write_limit)?
        } else {
            0
        };
        let deadline = self
            .request
            .map(|request| {
                started
                    .checked_add(request.deadline)
                    .ok_or_else(|| invalid("unrepresentable handoff deadline"))
            })
            .transpose()?;
        let deadline = match (deadline, self.parent_deadline) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        };
        let shared = &self.shared;
        let requested = self.request.is_some();
        let result = {
            let (mut reader, mut writer) = tokio::io::split(&mut self.bridge);
            tokio::select! {
                result = reader.read(&mut self.input.bytes[..read_limit]), if can_read => Step::Read(result),
                step = async {
                    if can_write { Step::Write(writer.write(self.output.remaining()).await) }
                    else { Step::Shutdown(writer.shutdown().await) }
                }, if can_write || (self.peer_eof && !self.bridge_shutdown && !requested) => step,
                result = poll_fn(|cx| {
                    let mut gate = match lock(shared) { Ok(gate) => gate, Err(error) => return Poll::Ready(Err(error)) };
                    if gate.command.is_some() || (requested && (!gate.handle_alive || !gate.stream_alive)) {
                        return Poll::Ready(Ok(()));
                    }
                    gate.driver_waker = Some(cx.waker().clone());
                    Poll::Pending
                }) => Step::Wake(result),
                _ = async { match deadline { Some(deadline) => tokio::time::sleep_until(deadline).await, None => pending().await } } => Step::Deadline,
                _ = tick.tick() => Step::Wake(Ok(())),
            }
        };
        self.complete_step(
            result,
            TransferBounds {
                read_limit,
                read_ceiling,
                write_limit,
                write_ceiling,
            },
            started,
        )
    }
    fn complete_step(
        &mut self,
        result: Step,
        bounds: TransferBounds,
        started: Instant,
    ) -> io::Result<()> {
        let TransferBounds {
            read_limit,
            read_ceiling,
            write_limit,
            write_ceiling,
        } = bounds;
        match result {
            Step::Read(result) => {
                let size = result?;
                self.progress.outbound_read = charged(read_ceiling, read_limit, size);
                self.input.length = size;
                self.input.offset = 0;
                self.caller_eof = size == 0;
            }
            Step::Write(result) => {
                let size = result?;
                if size == 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "caller bridge closed",
                    ));
                }
                self.progress.inbound_written = charged(write_ceiling, write_limit, size);
                self.output.offset += size;
            }
            Step::Shutdown(result) => {
                result?;
                self.bridge_shutdown = true;
            }
            Step::Wake(result) => result?,
            Step::Deadline => return Err(timeout("raw handoff deadline")),
        }
        // Charge completed I/O exactly before rejecting ready-after-expiry.
        // A ready branch cannot postpone the deadline or start another turn.
        self.observe_request(started)?;
        self.check_parent()
    }
}
struct YieldOnce(bool);
impl std::future::Future for YieldOnce {
    type Output = ();
    fn poll(mut self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> Poll<()> {
        if self.0 {
            Poll::Ready(())
        } else {
            self.0 = true;
            cx.waker().wake_by_ref();
            Poll::Pending
        }
    }
}
struct TransferBounds {
    read_limit: usize,
    read_ceiling: u64,
    write_limit: usize,
    write_ceiling: u64,
}
fn complete_handoff<I: PacketIo>(
    mut gate: MutexGuard<'_, Gate>,
    parts: HandoffParts<I>,
    elapsed: Duration,
    deadline: Duration,
) -> io::Result<HandoffParts<I>> {
    if elapsed >= deadline {
        gate.status.state = SwitchState::Failed;
        // PacketIo is generic: its destructor may query/drop the same handle.
        // Never run that user-owned destruction while the gate is locked.
        drop(gate);
        drop(parts);
        return Err(timeout("raw handoff deadline after consume"));
    }
    gate.status.state = SwitchState::Handoff;
    gate.status.elapsed = elapsed;
    drop(gate);
    // No await, callback or further I/O before the unique owner is returned.
    Ok(parts)
}
enum Step {
    Read(io::Result<usize>),
    Write(io::Result<usize>),
    Shutdown(io::Result<()>),
    Wake(io::Result<()>),
    Deadline,
}
fn tracked_error(error: TrackedError) -> io::Error {
    match error {
        TrackedError::Engine(error) => crate::engine_error(error),
        _ => io::Error::other(error),
    }
}
fn timeout(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::TimedOut, message)
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
