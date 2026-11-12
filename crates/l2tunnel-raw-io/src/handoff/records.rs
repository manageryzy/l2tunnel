//! Bounded TLS envelope observation; no TLS validation or freeze capability.
use super::{SwitchHandle, SwitchState, TrackedStream};
use std::{
    fmt, io,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// Largest envelope payload accepted by this adapter (below rustls's 18432 limit).
pub const MAX_RECORD_PAYLOAD: u16 = 18_431;
/// Lifetime wire-byte ceiling per direction, including all record headers.
pub const MAX_DIRECTION_BYTES: u64 = 4 * 1024 * 1024;
/// Lifetime started-record ceiling; never reset by a TLS KeyUpdate.
///
/// Pinned rustls 0.23.45 ring TLS AES suites have a 2^24 confidentiality limit;
/// their QUIC limits are separate. This envelope bound proves no crypto quiescence.
pub const MAX_DIRECTION_RECORDS: u64 = 65_536;
/// Maximum bytes offered to the endpoint in one poll.
pub const MAX_POLL_BYTES: usize = 4096;
/// Maximum vectored-write slices accepted, matching pinned rustls ChunkVecBuffer.
pub const MAX_IO_SLICES: usize = 64;

/// Independent lifetime limits for one direction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DirectionLimits {
    /// Wire bytes including headers, in 5..=MAX_DIRECTION_BYTES.
    pub wire_bytes: u64,
    /// Started records, in 1..=MAX_DIRECTION_RECORDS.
    pub records: u64,
}
impl Default for DirectionLimits {
    fn default() -> Self {
        Self {
            wire_bytes: MAX_DIRECTION_BYTES,
            records: 16_384,
        }
    }
}
/// Fixed envelope limits; TLS determines protocol and cryptographic validity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecordLimits {
    /// Actual incoming endpoint progress limits.
    pub incoming: DirectionLimits,
    /// Actual outgoing endpoint progress limits.
    pub outgoing: DirectionLimits,
    /// Nonzero payload ceiling, at most MAX_RECORD_PAYLOAD.
    pub max_payload: u16,
}
impl Default for RecordLimits {
    fn default() -> Self {
        Self {
            incoming: DirectionLimits::default(),
            outgoing: DirectionLimits::default(),
            max_payload: MAX_RECORD_PAYLOAD,
        }
    }
}
impl RecordLimits {
    pub(super) fn validate(self) -> Result<(), AttachError> {
        if !(1..=MAX_RECORD_PAYLOAD).contains(&self.max_payload)
            || [self.incoming, self.outgoing].iter().any(|v| {
                !(5..=MAX_DIRECTION_BYTES).contains(&v.wire_bytes)
                    || !(1..=MAX_DIRECTION_RECORDS).contains(&v.records)
            })
        {
            return Err(AttachError::InvalidLimits);
        }
        Ok(())
    }
}
/// Attachment failure, returned with the unchanged original endpoint.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AttachError {
    /// Limits are zero, inverted or outside the fixed ceiling.
    InvalidLimits,
    /// Endpoint bytes were already used or its lifecycle is not fresh/live.
    NotFresh,
    /// The original bridge mutex was poisoned.
    GatePoisoned,
}
impl fmt::Display for AttachError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "record attachment: {self:?}")
    }
}
impl std::error::Error for AttachError {}
/// Direction of the first terminal envelope fault.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecordDirection {
    /// Ciphertext consumed from the original endpoint.
    Incoming,
    /// Ciphertext accepted by the original endpoint.
    Outgoing,
}
/// Terminal cause; no user data or cryptographic material is retained.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecordFaultKind {
    /// Lifetime byte budget cannot hold the next header or complete body.
    ByteLimit,
    /// No next started-record slot remains.
    RecordLimit,
    /// Exact accounting cannot be represented.
    Arithmetic,
    /// Declared envelope payload exceeds the configured maximum.
    RecordLength,
    /// EOF occurred within a header or body.
    TruncatedRecord,
    /// A nonempty endpoint write returned zero.
    WriteZero,
    /// Actual endpoint error; the first returned error is preserved unchanged.
    Io {
        /// Original standard error category.
        kind: io::ErrorKind,
        /// Original platform error number, when present.
        raw_os_error: Option<i32>,
    },
}
/// First sticky terminal cause; subsequent operations do no endpoint I/O.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecordFault {
    /// Direction whose operation failed.
    pub direction: RecordDirection,
    /// Original first cause.
    pub kind: RecordFaultKind,
}
impl RecordFault {
    fn error(self) -> io::Error {
        let kind = match self.kind {
            RecordFaultKind::TruncatedRecord => io::ErrorKind::UnexpectedEof,
            RecordFaultKind::WriteZero => io::ErrorKind::WriteZero,
            RecordFaultKind::Io { kind, .. } => kind,
            _ => io::ErrorKind::InvalidData,
        };
        io::Error::new(kind, self)
    }
}
impl fmt::Display for RecordFault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "record envelope fault: {self:?}")
    }
}
impl std::error::Error for RecordFault {}
/// Copied envelope progress; never an authenticated or transferable proof.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RecordProgress {
    /// Actual successful endpoint bytes, including headers.
    pub wire_bytes: u64,
    /// Headers for which at least one byte was actually transferred.
    pub started_records: u64,
    /// Fully observed envelopes, including zero-payload envelopes.
    pub completed_records: u64,
    /// Header bytes held, 0..=5; remains five during the body.
    pub header_bytes: u8,
    /// Remaining declared body bytes.
    pub body_remaining: u16,
}
impl RecordProgress {
    /// Envelope alignment only; inspect fault/EOF/shutdown separately.
    pub fn at_boundary(&self) -> bool {
        self.header_bytes == 0 && self.body_remaining == 0
    }
}
/// Copied diagnostic state, incapable of constructing a new observer.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RecordStatus {
    /// Original incoming byte/record progress.
    pub incoming: RecordProgress,
    /// Original outgoing byte/record progress.
    pub outgoing: RecordProgress,
    /// Actual clean endpoint EOF; not a TLS freeze boundary.
    pub read_eof: bool,
    /// Any explicit shutdown attempt, including a cancelled Pending attempt.
    pub shutdown_started: bool,
    /// An actual successful endpoint shutdown.
    pub shutdown_completed: bool,
    /// First sticky terminal fault.
    pub fault: Option<RecordFault>,
}
#[derive(Clone, Copy, Default)]
struct Parser {
    header: [u8; 5],
    progress: RecordProgress,
}
impl Parser {
    fn allowance(
        self,
        limits: DirectionLimits,
        available: usize,
    ) -> Result<usize, RecordFaultKind> {
        let p = self.progress;
        // Reserve every potentially changed counter before endpoint side effects.
        p.completed_records
            .checked_add(1)
            .ok_or(RecordFaultKind::Arithmetic)?;
        if p.at_boundary() {
            p.started_records
                .checked_add(1)
                .ok_or(RecordFaultKind::Arithmetic)?;
            if p.started_records >= limits.records {
                return Err(RecordFaultKind::RecordLimit);
            }
        }
        let phase = if p.header_bytes < 5 {
            5 - usize::from(p.header_bytes)
        } else {
            usize::from(p.body_remaining)
        };
        let next = p
            .wire_bytes
            .checked_add(phase as u64)
            .ok_or(RecordFaultKind::Arithmetic)?;
        if next > limits.wire_bytes {
            return Err(RecordFaultKind::ByteLimit);
        }
        Ok(phase.min(available).min(MAX_POLL_BYTES))
    }
    fn advance(
        &mut self,
        bytes: &[u8],
        limits: DirectionLimits,
        maximum: u16,
    ) -> Result<(), RecordFaultKind> {
        // allowance preflights arithmetic; the caller passes only actual bounded progress.
        let p = &mut self.progress;
        if p.at_boundary() {
            p.started_records += 1;
        }
        p.wire_bytes += bytes.len() as u64;
        if p.header_bytes < 5 {
            let at = usize::from(p.header_bytes);
            self.header[at..at + bytes.len()].copy_from_slice(bytes);
            p.header_bytes += bytes.len() as u8;
            if p.header_bytes != 5 {
                return Ok(());
            }
            p.body_remaining = u16::from_be_bytes([self.header[3], self.header[4]]);
            if p.body_remaining > maximum {
                return Err(RecordFaultKind::RecordLength);
            }
            if p.wire_bytes
                .checked_add(u64::from(p.body_remaining))
                .ok_or(RecordFaultKind::Arithmetic)?
                > limits.wire_bytes
            {
                return Err(RecordFaultKind::ByteLimit);
            }
        } else {
            p.body_remaining -= bytes.len() as u16;
        }
        if p.body_remaining == 0 {
            p.completed_records += 1;
            p.header_bytes = 0;
        }
        Ok(())
    }
}
/// Original endpoint with bounded envelope accounting from its first byte.
///
/// A record boundary does not prove empty TLS buffers. No inner accessor,
/// reset, adoption, unwrapping or freeze capability is supplied. The generic
/// implementation has only a fresh-TrackedStream public constructor.
pub struct RecordIo<S> {
    inner: S,
    limits: RecordLimits,
    incoming: Parser,
    outgoing: Parser,
    read_eof: bool,
    shutdown_started: bool,
    shutdown_completed: bool,
    fault: Option<RecordFault>,
}
impl RecordIo<TrackedStream> {
    /// Attach before any endpoint bytes were consumed or accepted.
    /// All failure paths return the same original stream without I/O or mutation.
    pub fn attach(
        stream: TrackedStream,
        limits: RecordLimits,
    ) -> Result<Self, (TrackedStream, AttachError)> {
        let valid = limits.validate().and_then(|()| {
            let gate = stream
                .shared
                .lock()
                .map_err(|_| AttachError::GatePoisoned)?;
            if !matches!(
                gate.status.state,
                SwitchState::NotStarted | SwitchState::Running
            ) || gate.status.endpoint.read != 0
                || gate.status.endpoint.written != 0
                || gate.command.is_some()
                || gate.eof
                || gate.shutdown
                || !gate.stream_alive
                || !gate.handle_alive
            {
                return Err(AttachError::NotFresh);
            }
            Ok(())
        });
        if let Err(error) = valid {
            return Err((stream, error));
        }
        Ok(Self::new(stream, limits))
    }
    /// Whether this observer contains the endpoint paired with this exact handle.
    /// This is an identity query, not authentication or quiescence evidence.
    pub fn belongs_to(&self, handle: &SwitchHandle) -> bool {
        Arc::ptr_eq(&self.inner.shared, &handle.shared)
    }
}
impl<S> RecordIo<S> {
    fn new(inner: S, limits: RecordLimits) -> Self {
        Self {
            inner,
            limits,
            incoming: Parser::default(),
            outgoing: Parser::default(),
            read_eof: false,
            shutdown_started: false,
            shutdown_completed: false,
            fault: None,
        }
    }
    /// Immutable envelope limits; changing policy requires a new original connection.
    pub fn limits(&self) -> RecordLimits {
        self.limits
    }
    /// Copied diagnostics, including a fault latched after successful header progress.
    pub fn status(&self) -> RecordStatus {
        RecordStatus {
            incoming: self.incoming.progress,
            outgoing: self.outgoing.progress,
            read_eof: self.read_eof,
            shutdown_started: self.shutdown_started,
            shutdown_completed: self.shutdown_completed,
            fault: self.fault,
        }
    }
    fn usable(&self) -> io::Result<()> {
        self.fault.map_or(Ok(()), |v| Err(v.error()))
    }
    fn fail(&mut self, direction: RecordDirection, kind: RecordFaultKind) -> io::Error {
        (*self.fault.get_or_insert(RecordFault { direction, kind })).error()
    }
    fn io_failure(&mut self, direction: RecordDirection, error: io::Error) -> io::Error {
        let _ = self.fail(
            direction,
            RecordFaultKind::Io {
                kind: error.kind(),
                raw_os_error: error.raw_os_error(),
            },
        );
        error
    }
}
impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for RecordIo<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.usable()?;
        if output.remaining() == 0 || this.read_eof {
            return Poll::Ready(Ok(()));
        }
        let count = match this
            .incoming
            .allowance(this.limits.incoming, output.remaining())
        {
            Ok(n) => n,
            Err(kind) => return Poll::Ready(Err(this.fail(RecordDirection::Incoming, kind))),
        };
        let mut scratch = [0; MAX_POLL_BYTES];
        let mut input = ReadBuf::new(&mut scratch[..count]);
        match Pin::new(&mut this.inner).poll_read(cx, &mut input) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(e)) => Poll::Ready(Err(this.io_failure(RecordDirection::Incoming, e))),
            Poll::Ready(Ok(())) => {
                if input.filled().is_empty() {
                    if !this.incoming.progress.at_boundary() {
                        return Poll::Ready(Err(
                            this.fail(RecordDirection::Incoming, RecordFaultKind::TruncatedRecord)
                        ));
                    }
                    this.read_eof = true;
                    return Poll::Ready(Ok(()));
                }
                // A received header's length is known only after its bytes were read.
                // Return all actual progress and latch rejection before any body I/O.
                if let Err(kind) = this.incoming.advance(
                    input.filled(),
                    this.limits.incoming,
                    this.limits.max_payload,
                ) {
                    let _ = this.fail(RecordDirection::Incoming, kind);
                }
                output.put_slice(input.filled());
                Poll::Ready(Ok(()))
            }
        }
    }
}
impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for RecordIo<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        this.usable()?;
        if this.shutdown_started {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        if bytes.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let count = match this.outgoing.allowance(this.limits.outgoing, bytes.len()) {
            Ok(n) => n,
            Err(kind) => return Poll::Ready(Err(this.fail(RecordDirection::Outgoing, kind))),
        };
        let mut preview = this.outgoing;
        if let Err(kind) = preview.advance(
            &bytes[..count],
            this.limits.outgoing,
            this.limits.max_payload,
        ) {
            return Poll::Ready(Err(this.fail(RecordDirection::Outgoing, kind)));
        }
        match Pin::new(&mut this.inner).poll_write(cx, &bytes[..count]) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(e)) => Poll::Ready(Err(this.io_failure(RecordDirection::Outgoing, e))),
            Poll::Ready(Ok(0)) => Poll::Ready(Err(
                this.fail(RecordDirection::Outgoing, RecordFaultKind::WriteZero)
            )),
            Poll::Ready(Ok(n)) => {
                let Some(actual) = bytes.get(..n).filter(|_| n <= count) else {
                    return Poll::Ready(Err(this.io_failure(
                        RecordDirection::Outgoing,
                        io::Error::other("invalid endpoint write count"),
                    )));
                };
                if let Err(kind) =
                    this.outgoing
                        .advance(actual, this.limits.outgoing, this.limits.max_payload)
                {
                    let _ = this.fail(RecordDirection::Outgoing, kind);
                }
                Poll::Ready(Ok(n))
            }
        }
    }
    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffers: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        self.usable()?;
        if buffers.len() > MAX_IO_SLICES {
            return Poll::Ready(Err(io::ErrorKind::InvalidInput.into()));
        }
        let bytes = buffers
            .iter()
            .find(|v| !v.is_empty())
            .map_or(&[][..], |v| v.as_ref());
        self.as_mut().poll_write(cx, bytes)
    }
    fn is_write_vectored(&self) -> bool {
        false
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.usable()?;
        match Pin::new(&mut this.inner).poll_flush(cx) {
            Poll::Ready(Err(e)) => Poll::Ready(Err(this.io_failure(RecordDirection::Outgoing, e))),
            result => result,
        }
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.usable()?;
        if this.shutdown_completed {
            return Poll::Ready(Ok(()));
        }
        this.shutdown_started = true;
        match Pin::new(&mut this.inner).poll_shutdown(cx) {
            Poll::Ready(Ok(())) => {
                this.shutdown_completed = true;
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(this.io_failure(RecordDirection::Outgoing, e))),
            result => result,
        }
    }
}
#[cfg(test)]
#[path = "records_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "records_tls_tests.rs"]
mod tls_tests;
