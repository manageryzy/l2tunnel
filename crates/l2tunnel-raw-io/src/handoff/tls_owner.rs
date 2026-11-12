//! Exclusive authenticated message ownership; no Seal, freeze or handoff authority.
use super::{
    AttachError, RecordFault, RecordIo, RecordLimits, RecordStatus, SwitchHandle, TrackedStream,
};
use l2tunnel_auth::{
    self as auth, AuthenticatedIo, ClientTls, MemberAllowlist, MemberKey, ServerTls, SessionConfig,
    SessionInfo,
};
use l2tunnel_core::ConfigDigest;
use l2tunnel_device::PacketLayer;
use std::{
    fmt,
    future::Future,
    io,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    time::{Instant, Sleep, sleep_until},
};
use tokio_rustls::{
    TlsStream,
    rustls::{CipherSuite, ProtocolVersion, pki_types::ServerName},
};
const HEADER: usize = 8;
const MAX_PAYLOAD: usize = 4096;
const MAX_BYTES: u64 = 1024 * 1024;
const MAGIC: &[u8; 6] = b"L2RM\x01\0";

/// Fixed symmetric plaintext and ciphertext lifetime budgets for bootstrap messages.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MessageLimits {
    /// Ciphertext observer limits; incoming and outgoing must be equal.
    pub records: RecordLimits,
    /// Maximum nonempty payload, in 1..=4096.
    pub max_payload: u16,
    /// Lifetime message reservations per direction, in 1..=256.
    pub messages_per_direction: u16,
    /// Lifetime framed plaintext bytes per direction, in 9..=1 MiB.
    pub bytes_per_direction: u64,
}
impl Default for MessageLimits {
    fn default() -> Self {
        Self {
            records: RecordLimits::default(),
            max_payload: 4096,
            messages_per_direction: 256,
            bytes_per_direction: MAX_BYTES,
        }
    }
}
impl MessageLimits {
    pub(super) fn validate(self) -> Result<(), StartError> {
        self.records.validate().map_err(StartError::Attach)?;
        if self.records.incoming != self.records.outgoing
            || !(1..=4096).contains(&self.max_payload)
            || !(1..=256).contains(&self.messages_per_direction)
            || !(9..=MAX_BYTES).contains(&self.bytes_per_direction)
        {
            return Err(StartError::Limits);
        }
        Ok(())
    }
}
/// Local pre-I/O factory rejection; original endpoint and handle are returned.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StartError {
    /// Invalid finite or asymmetric budget.
    Limits,
    /// Original endpoint attachment validation failed.
    Attach(AttachError),
    /// The exact original bridge identities differ.
    Identity,
    /// Timeout is outside 1 ms..=30 s, cannot be represented, or already expired.
    Deadline,
    /// No current Tokio runtime; timer enablement is a documented local precondition.
    Runtime,
    /// Invalid or excessively long certificate verification name.
    VerificationName,
}
impl fmt::Display for StartError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "TLS owner start: {self:?}")
    }
}
impl std::error::Error for StartError {}
/// Rejected factory with unchanged original owners. No authentication was polled.
pub struct StartFailure {
    /// Exact original tracked stream, reusable subject to its unchanged lifecycle.
    pub stream: TrackedStream,
    /// Exact supplied unique handle.
    pub handle: SwitchHandle,
    /// Local rejection reason.
    pub error: StartError,
}
impl fmt::Debug for StartFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StartFailure")
            .field("error", &self.error)
            .finish_non_exhaustive()
    }
}
impl fmt::Display for StartFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.error.fmt(f)
    }
}
impl std::error::Error for StartFailure {}
/// Terminal setup failure. No reusable TLS owner or clean driver result is implied.
#[derive(Debug)]
pub enum SetupFailure {
    /// Original total deadline expired, including time before first poll.
    Expired,
    /// Existing certificate/member/config authentication failed.
    Authentication(auth::Error),
    /// Maintained TLS result does not match the original owner/configuration/profile.
    Invariant,
    /// A completed Setup must not be polled again.
    Completed,
}
impl fmt::Display for SetupFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Authentication(e) => write!(f, "TLS owner authentication: {e}"),
            other => write!(f, "TLS owner setup: {other:?}"),
        }
    }
}
impl std::error::Error for SetupFailure {}

/// Compute the owner-specific authenticated configuration from validated symmetric limits.
/// No supplied digest or numeric identity can construct an authenticated owner.
pub fn message_session_config(
    base: SessionConfig,
    limits: MessageLimits,
) -> Result<SessionConfig, StartError> {
    limits.validate()?;
    let mut hash = ring::digest::Context::new(&ring::digest::SHA256);
    hash.update(b"l2tunnel/raw-tls-message-owner/v1\0");
    hash.update(&base.digest.0);
    hash.update(&[match base.layer {
        PacketLayer::Ethernet => 1,
        PacketLayer::Ip => 2,
    }]);
    hash.update(&limits.records.incoming.wire_bytes.to_be_bytes());
    hash.update(&limits.records.incoming.records.to_be_bytes());
    hash.update(&limits.records.max_payload.to_be_bytes());
    hash.update(&limits.max_payload.to_be_bytes());
    hash.update(&limits.messages_per_direction.to_be_bytes());
    hash.update(&limits.bytes_per_direction.to_be_bytes());
    hash.update(MAGIC);
    hash.update(&(HEADER as u16).to_be_bytes());
    let mut digest = [0; 32];
    digest.copy_from_slice(hash.finish().as_ref());
    Ok(SessionConfig {
        layer: base.layer,
        digest: ConfigDigest(digest),
    })
}
type Authentication<'a> = Pin<
    Box<
        dyn Future<Output = Result<AuthenticatedIo<RecordIo<TrackedStream>>, auth::Error>>
            + Send
            + 'a,
    >,
>;
/// Owns one pending authentication future. Borrowed-poll cancellation preserves it.
/// Drop is terminal and signals the separately caller-owned driver; it does not join it.
pub struct Setup<'a> {
    future: Option<Authentication<'a>>,
    handle: Option<SwitchHandle>,
    limits: MessageLimits,
    expected: SessionConfig,
    deadline: Instant,
    timer: Pin<Box<Sleep>>,
    done: bool,
    export_lane: Option<u32>,
    future_bytes: usize,
}
fn prepare(
    start: Instant,
    stream: TrackedStream,
    handle: SwitchHandle,
    base: SessionConfig,
    limits: MessageLimits,
    timeout: Duration,
) -> Result<
    (
        RecordIo<TrackedStream>,
        SwitchHandle,
        SessionConfig,
        Instant,
    ),
    StartFailure,
> {
    let checked = (|| {
        let config = message_session_config(base, limits)?;
        if !(Duration::from_millis(1)..=Duration::from_secs(30)).contains(&timeout) {
            return Err(StartError::Deadline);
        }
        let deadline = start.checked_add(timeout).ok_or(StartError::Deadline)?;
        tokio::runtime::Handle::try_current().map_err(|_| StartError::Runtime)?;
        if !Arc::ptr_eq(&stream.shared, &handle.shared) {
            return Err(StartError::Identity);
        }
        if Instant::now() >= deadline {
            return Err(StartError::Deadline);
        }
        Ok((config, deadline))
    })();
    let (expected, deadline) = match checked {
        Ok(v) => v,
        Err(error) => {
            return Err(StartFailure {
                stream,
                handle,
                error,
            });
        }
    };
    match RecordIo::attach(stream, limits.records) {
        Ok(stream) => Ok((stream, handle, expected, deadline)),
        Err((stream, error)) => Err(StartFailure {
            stream,
            handle,
            error: StartError::Attach(error),
        }),
    }
}
/// Start actual TLS/member authentication on a fresh original endpoint.
/// Caller retains/drives/joins its original SwitchDriver; no worker is spawned here.
///
/// # Panics
/// The current Tokio runtime must have its time driver enabled, as required by
/// the existing auth/TLS timeout implementation. Runtime presence is checked;
/// Tokio exposes no supported timer-enablement query. Poll Setup/owner in that
/// runtime. Peer input never selects this runtime configuration.
#[allow(clippy::too_many_arguments)]
pub fn begin_client<'a>(
    stream: TrackedStream,
    handle: SwitchHandle,
    tls: &'a ClientTls,
    verification_name: &'a str,
    member: &'a MemberKey,
    base: SessionConfig,
    limits: MessageLimits,
    timeout: Duration,
) -> Result<Setup<'a>, StartFailure> {
    client_setup(
        stream,
        handle,
        tls,
        verification_name,
        member,
        base,
        limits,
        timeout,
        Instant::now(),
        None,
    )
}
#[allow(clippy::too_many_arguments)]
pub(super) fn client_setup<'a>(
    stream: TrackedStream,
    handle: SwitchHandle,
    tls: &'a ClientTls,
    verification_name: &'a str,
    member: &'a MemberKey,
    base: SessionConfig,
    limits: MessageLimits,
    timeout: Duration,
    start: Instant,
    export_lane: Option<u32>,
) -> Result<Setup<'a>, StartFailure> {
    if verification_name.is_empty()
        || verification_name.len() > 253
        || ServerName::try_from(verification_name).is_err()
    {
        return Err(StartFailure {
            stream,
            handle,
            error: StartError::VerificationName,
        });
    }
    let (stream, handle, expected, deadline) =
        prepare(start, stream, handle, base, limits, timeout)?;
    let future = async move {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .ok_or(auth::Error::TimedOut)?;
        auth::client_connect_io(stream, tls, verification_name, member, expected, remaining).await
    };
    let future_bytes = std::mem::size_of_val(&future);
    Ok(Setup {
        future_bytes,
        future: Some(Box::pin(future)),
        handle: Some(handle),
        limits,
        expected,
        deadline,
        timer: Box::pin(sleep_until(deadline)),
        done: false,
        export_lane,
    })
}
/// Start actual allowlisted TLS/member acceptance on a fresh original endpoint.
/// The same original deadline covers authentication and all later message operations.
///
/// # Panics
/// Like `begin_client`, this requires a Tokio runtime with its time driver enabled.
/// Runtime presence alone cannot validate timer enablement through supported APIs.
#[allow(clippy::too_many_arguments)]
pub fn begin_server<'a>(
    stream: TrackedStream,
    handle: SwitchHandle,
    tls: &'a ServerTls,
    members: &'a MemberAllowlist,
    base: SessionConfig,
    limits: MessageLimits,
    timeout: Duration,
) -> Result<Setup<'a>, StartFailure> {
    server_setup(
        stream,
        handle,
        tls,
        members,
        base,
        limits,
        timeout,
        Instant::now(),
        None,
    )
}
#[allow(clippy::too_many_arguments)]
pub(super) fn server_setup<'a>(
    stream: TrackedStream,
    handle: SwitchHandle,
    tls: &'a ServerTls,
    members: &'a MemberAllowlist,
    base: SessionConfig,
    limits: MessageLimits,
    timeout: Duration,
    start: Instant,
    export_lane: Option<u32>,
) -> Result<Setup<'a>, StartFailure> {
    let (stream, handle, expected, deadline) =
        prepare(start, stream, handle, base, limits, timeout)?;
    let future = async move {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .ok_or(auth::Error::TimedOut)?;
        auth::server_accept_io(stream, tls, members, expected, remaining).await
    };
    let future_bytes = std::mem::size_of_val(&future);
    Ok(Setup {
        future_bytes,
        future: Some(Box::pin(future)),
        handle: Some(handle),
        limits,
        expected,
        deadline,
        timer: Box::pin(sleep_until(deadline)),
        done: false,
        export_lane,
    })
}
impl Setup<'_> {
    pub(super) fn metadata_bytes(&self) -> Option<usize> {
        std::mem::size_of::<Self>().checked_add(self.future_bytes)
    }
    fn failure(&mut self, error: SetupFailure) -> Poll<Result<TlsMessageOwner, SetupFailure>> {
        self.done = true;
        self.future = None;
        self.handle = None;
        Poll::Ready(Err(error))
    }
}
impl Future for Setup<'_> {
    type Output = Result<TlsMessageOwner, SetupFailure>;
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        if this.done {
            return Poll::Ready(Err(SetupFailure::Completed));
        }
        if Instant::now() >= this.deadline {
            return this.failure(SetupFailure::Expired);
        }
        let Some(future) = this.future.as_mut() else {
            return this.failure(SetupFailure::Invariant);
        };
        let result = future.as_mut().poll(cx);
        if Instant::now() >= this.deadline {
            return this.failure(SetupFailure::Expired);
        }
        match result {
            Poll::Pending => {
                if this.timer.as_mut().poll(cx).is_ready() {
                    return this.failure(SetupFailure::Expired);
                }
                Poll::Pending
            }
            Poll::Ready(Err(e)) => this.failure(SetupFailure::Authentication(e)),
            Poll::Ready(Ok(authenticated)) => {
                if authenticated.profile() != auth::TlsIoProfile::TcpTls {
                    return this.failure(SetupFailure::Invariant);
                }
                let roots = match this
                    .export_lane
                    .map(|lane| export_roots(&authenticated, lane))
                    .transpose()
                {
                    Ok(roots) => roots,
                    Err(error) => return this.failure(SetupFailure::Authentication(error)),
                };
                let (stream, info) = authenticated.into_parts();
                let valid_cipher = stream
                    .get_ref()
                    .1
                    .negotiated_cipher_suite()
                    .is_some_and(|s| {
                        matches!(
                            s.suite(),
                            CipherSuite::TLS13_AES_128_GCM_SHA256
                                | CipherSuite::TLS13_AES_256_GCM_SHA384
                                | CipherSuite::TLS13_CHACHA20_POLY1305_SHA256
                        )
                    });
                if info.config != this.expected
                    || stream.get_ref().1.protocol_version() != Some(ProtocolVersion::TLSv1_3)
                    || !valid_cipher
                    || stream.get_ref().0.status().fault.is_some()
                    || !this
                        .handle
                        .as_ref()
                        .is_some_and(|h| stream.get_ref().0.belongs_to(h))
                {
                    return this.failure(SetupFailure::Invariant);
                }
                let Some(handle) = this.handle.take() else {
                    return this.failure(SetupFailure::Invariant);
                };
                let owner = TlsMessageOwner {
                    exact: Exact::new(stream, this.limits, this.deadline),
                    handle,
                    info,
                    roots,
                };
                if Instant::now() >= this.deadline {
                    return this.failure(SetupFailure::Expired);
                }
                this.future = None;
                this.done = true;
                Poll::Ready(Ok(owner))
            }
        }
    }
}

fn export_roots<S>(io: &AuthenticatedIo<S>, lane: u32) -> Result<[auth::Secret; 6], auth::Error> {
    collect_roots(lane, |purpose, direction, lane| {
        io.export_key(purpose, direction, lane)
    })
}
// Internal finite collector: production always passes the actual retained TLS
// exporter. Tests can inject one provider error without a public secret constructor.
pub(super) fn collect_roots(
    lane: u32,
    mut export: impl FnMut(auth::KeyPurpose, auth::Direction, u32) -> Result<auth::Secret, auth::Error>,
) -> Result<[auth::Secret; 6], auth::Error> {
    use auth::{
        Direction::{ClientToServer, ServerToClient},
        KeyPurpose::{Data, LaneJoin, Management},
    };
    Ok([
        export(LaneJoin, ClientToServer, lane)?,
        export(LaneJoin, ServerToClient, lane)?,
        export(Management, ClientToServer, lane)?,
        export(Management, ServerToClient, lane)?,
        export(Data, ClientToServer, lane)?,
        export(Data, ServerToClient, lane)?,
    ])
}
/// First terminal fault, or a recoverable local staging/delivery error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MessageError {
    /// Original total deadline expired; terminal.
    Expired,
    /// Invalid incoming magic/version/reserved/length; terminal.
    Envelope,
    /// Actual EOF during this bootstrap protocol; terminal even at a message boundary.
    Eof,
    /// Ciphertext observer latched a first fault; terminal.
    Record(RecordFault),
    /// Lifetime plaintext byte/message budget exhausted; terminal on receive.
    Capacity,
    /// Checked accounting exhausted; terminal.
    Arithmetic,
    /// Nonempty backend write returned zero; terminal.
    WriteZero,
    /// Maintained TLS/I/O error category and optional original errno; terminal.
    Io {
        /// Standard error category.
        kind: io::ErrorKind,
        /// Original syscall errno when supplied.
        raw_os_error: Option<i32>,
    },
    /// An outgoing message is already owned; recoverable, no mutation.
    Busy,
    /// Empty/oversized local payload or insufficient lifetime staging capacity; recoverable.
    Payload,
    /// No completed message is available to consume; recoverable.
    NoMessage,
}
impl fmt::Display for MessageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "TLS message owner: {self:?}")
    }
}
impl std::error::Error for MessageError {}
/// Plaintext counters. Ciphertext and physical driver progress are separate.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct MessageProgress {
    /// Lifetime full-frame reservation, including all eight-byte headers.
    pub reserved_bytes: u64,
    /// Lifetime message slots reserved (no refund after staging).
    pub reserved_messages: u64,
    /// Actually accepted or delivered plaintext, including message headers.
    pub plaintext_bytes: u64,
    /// Messages with at least one actual plaintext byte transferred.
    pub started_messages: u64,
    /// Full received messages or fully written-and-flushed outgoing messages.
    pub completed_messages: u64,
}
/// Copied diagnostics only; this cannot authorize a freeze or physical ownership transfer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MessageStatus {
    /// Actual original ciphertext observer state.
    pub records: RecordStatus,
    /// Incoming plaintext progress.
    pub incoming: MessageProgress,
    /// Outgoing plaintext progress.
    pub outgoing: MessageProgress,
    /// Retained incoming frame prefix, including header.
    pub incoming_offset: usize,
    /// Retained outgoing frame offset, including header.
    pub outgoing_offset: usize,
    /// A complete incoming message is retained for the caller.
    pub message_available: bool,
    /// One outgoing frame is retained through its actual TLS flush.
    pub send_pending: bool,
    /// First terminal owner fault, if any.
    pub fault: Option<MessageError>,
}
struct Frame {
    bytes: [u8; HEADER + MAX_PAYLOAD],
    offset: usize,
    length: usize,
    complete: bool,
    progress: MessageProgress,
}
impl Frame {
    fn new() -> Self {
        Self {
            bytes: [0; HEADER + MAX_PAYLOAD],
            offset: 0,
            length: 0,
            complete: false,
            progress: MessageProgress::default(),
        }
    }
}
struct Exact<S> {
    io: S,
    limits: MessageLimits,
    deadline: Instant,
    timer: Pin<Box<Sleep>>,
    incoming: Frame,
    outgoing: Frame,
    fault: Option<MessageError>,
}
impl<S> Exact<S> {
    fn new(io: S, limits: MessageLimits, deadline: Instant) -> Self {
        Self {
            io,
            limits,
            deadline,
            timer: Box::pin(sleep_until(deadline)),
            incoming: Frame::new(),
            outgoing: Frame::new(),
            fault: None,
        }
    }
    fn fail(&mut self, error: MessageError) -> MessageError {
        *self.fault.get_or_insert(error)
    }
    fn live(&mut self) -> Result<(), MessageError> {
        if let Some(e) = self.fault {
            return Err(e);
        }
        if Instant::now() >= self.deadline {
            return Err(self.fail(MessageError::Expired));
        }
        Ok(())
    }
    fn pending(&mut self, cx: &mut Context<'_>, wake: bool) -> Poll<Result<(), MessageError>> {
        self.live()?;
        if self.timer.as_mut().poll(cx).is_ready() {
            return Poll::Ready(Err(self.fail(MessageError::Expired)));
        }
        if wake {
            cx.waker().wake_by_ref();
        }
        Poll::Pending
    }
    fn stage(&mut self, payload: &[u8]) -> Result<(), MessageError> {
        self.live()?;
        if self.outgoing.length != 0 {
            return Err(MessageError::Busy);
        }
        if payload.is_empty() || payload.len() > usize::from(self.limits.max_payload) {
            return Err(MessageError::Payload);
        }
        let length = HEADER + payload.len();
        let p = self.outgoing.progress;
        let bytes = p
            .reserved_bytes
            .checked_add(length as u64)
            .ok_or_else(|| self.fail(MessageError::Arithmetic))?;
        let messages = p
            .reserved_messages
            .checked_add(1)
            .ok_or_else(|| self.fail(MessageError::Arithmetic))?;
        if bytes > self.limits.bytes_per_direction
            || messages > u64::from(self.limits.messages_per_direction)
        {
            return Err(MessageError::Payload);
        }
        self.outgoing.bytes[..6].copy_from_slice(MAGIC);
        self.outgoing.bytes[6..8].copy_from_slice(&(payload.len() as u16).to_be_bytes());
        self.outgoing.bytes[8..length].copy_from_slice(payload);
        self.outgoing.length = length;
        self.outgoing.offset = 0;
        self.outgoing.progress.reserved_bytes = bytes;
        self.outgoing.progress.reserved_messages = messages;
        self.live()
    }
    fn consume(&mut self) -> Result<(), MessageError> {
        self.live()?;
        if !self.incoming.complete {
            return Err(MessageError::NoMessage);
        }
        self.incoming.offset = 0;
        self.incoming.length = 0;
        self.incoming.complete = false;
        self.live()
    }
    fn message(&self) -> Option<&[u8]> {
        (self.fault.is_none() && Instant::now() < self.deadline && self.incoming.complete)
            .then(|| &self.incoming.bytes[HEADER..self.incoming.length])
    }
}
fn io_error(e: io::Error) -> MessageError {
    MessageError::Io {
        kind: e.kind(),
        raw_os_error: e.raw_os_error(),
    }
}
impl<S: AsyncRead + AsyncWrite + Unpin> Exact<S> {
    fn poll_send(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), MessageError>> {
        self.live()?;
        if self.outgoing.length == 0 {
            return Poll::Ready(Ok(()));
        }
        let f = &self.outgoing;
        if f.progress.completed_messages.checked_add(1).is_none()
            || f.progress.started_messages.checked_add(1).is_none()
            || f.progress
                .plaintext_bytes
                .checked_add((f.length - f.offset) as u64)
                .is_none()
        {
            return Poll::Ready(Err(self.fail(MessageError::Arithmetic)));
        }
        if self.outgoing.offset == self.outgoing.length {
            let result = Pin::new(&mut self.io).poll_flush(cx);
            self.live()?;
            match result {
                Poll::Pending => self.pending(cx, false),
                Poll::Ready(Err(e)) => Poll::Ready(Err(self.fail(io_error(e)))),
                Poll::Ready(Ok(())) => {
                    self.outgoing.progress.completed_messages += 1;
                    self.outgoing.offset = 0;
                    self.outgoing.length = 0;
                    Poll::Ready(Ok(()))
                }
            }
        } else {
            let result = Pin::new(&mut self.io).poll_write(
                cx,
                &self.outgoing.bytes[self.outgoing.offset..self.outgoing.length],
            );
            match result {
                Poll::Pending => self.pending(cx, false),
                Poll::Ready(Err(e)) => Poll::Ready(Err(self.fail(io_error(e)))),
                Poll::Ready(Ok(0)) => Poll::Ready(Err(self.fail(MessageError::WriteZero))),
                Poll::Ready(Ok(n)) => {
                    if n > self.outgoing.length - self.outgoing.offset {
                        return Poll::Ready(Err(self.fail(MessageError::Io {
                            kind: io::ErrorKind::InvalidData,
                            raw_os_error: None,
                        })));
                    }
                    if self.outgoing.offset == 0 {
                        self.outgoing.progress.started_messages += 1;
                    }
                    self.outgoing.offset += n;
                    self.outgoing.progress.plaintext_bytes += n as u64;
                    self.pending(cx, true)
                }
            }
        }
    }
    fn poll_receive(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), MessageError>> {
        self.live()?;
        if self.incoming.complete {
            return Poll::Ready(Ok(()));
        }
        let f = &self.incoming;
        let first = f.offset == 0;
        if first
            && (f.progress.reserved_messages >= u64::from(self.limits.messages_per_direction)
                || f.progress
                    .reserved_bytes
                    .checked_add(HEADER as u64)
                    .is_none_or(|n| n > self.limits.bytes_per_direction))
        {
            return Poll::Ready(Err(self.fail(MessageError::Capacity)));
        }
        let end = if f.offset < HEADER { HEADER } else { f.length };
        if f.progress
            .plaintext_bytes
            .checked_add((end - f.offset) as u64)
            .is_none()
            || f.progress.started_messages.checked_add(1).is_none()
            || f.progress.completed_messages.checked_add(1).is_none()
        {
            return Poll::Ready(Err(self.fail(MessageError::Arithmetic)));
        }
        let mut buf = ReadBuf::new(&mut self.incoming.bytes[self.incoming.offset..end]);
        let result = Pin::new(&mut self.io).poll_read(cx, &mut buf);
        let n = buf.filled().len();
        match result {
            Poll::Pending => self.pending(cx, false),
            Poll::Ready(Err(e)) => Poll::Ready(Err(self.fail(io_error(e)))),
            Poll::Ready(Ok(())) => {
                if n == 0 {
                    return Poll::Ready(Err(self.fail(MessageError::Eof)));
                }
                if first {
                    self.incoming.progress.reserved_messages += 1;
                    self.incoming.progress.reserved_bytes += HEADER as u64;
                    self.incoming.progress.started_messages += 1;
                }
                self.incoming.offset += n;
                self.incoming.progress.plaintext_bytes += n as u64;
                self.live()?;
                if self.incoming.offset == HEADER && self.incoming.length == 0 {
                    let payload = usize::from(u16::from_be_bytes([
                        self.incoming.bytes[6],
                        self.incoming.bytes[7],
                    ]));
                    if &self.incoming.bytes[..6] != MAGIC
                        || payload == 0
                        || payload > usize::from(self.limits.max_payload)
                    {
                        return Poll::Ready(Err(self.fail(MessageError::Envelope)));
                    }
                    let Some(total) = self
                        .incoming
                        .progress
                        .reserved_bytes
                        .checked_add(payload as u64)
                    else {
                        return Poll::Ready(Err(self.fail(MessageError::Arithmetic)));
                    };
                    if total > self.limits.bytes_per_direction {
                        return Poll::Ready(Err(self.fail(MessageError::Capacity)));
                    }
                    self.incoming.progress.reserved_bytes = total;
                    self.incoming.length = HEADER + payload;
                } else if self.incoming.offset == self.incoming.length {
                    self.incoming.complete = true;
                    self.incoming.progress.completed_messages += 1;
                    self.live()?;
                    return Poll::Ready(Ok(()));
                }
                self.pending(cx, true)
            }
        }
    }
}
/// Exclusive whole TLS wrapper and exact-message state. No underlying I/O is exposed.
pub struct TlsMessageOwner {
    exact: Exact<TlsStream<RecordIo<TrackedStream>>>,
    handle: SwitchHandle,
    info: SessionInfo,
    roots: Option<[auth::Secret; 6]>,
}
impl TlsMessageOwner {
    pub(super) fn take_roots(&mut self) -> Option<[auth::Secret; 6]> {
        self.roots.take()
    }
    pub(super) fn is_client(&self) -> bool {
        matches!(self.exact.io, TlsStream::Client(_))
    }
    pub(super) fn same_bridge(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.handle.shared, &other.handle.shared)
    }
    pub(super) fn bridge_status(&self) -> super::SwitchStatus {
        self.handle.status()
    }
    /// Actual authenticated member/server identities and owner-bound configuration.
    pub fn info(&self) -> &SessionInfo {
        &self.info
    }
    /// Original deadline, unchanged from factory creation through message lifetime.
    pub fn deadline(&self) -> Instant {
        self.exact.deadline
    }
    /// Copied diagnostics, not authentication, quiescence or transfer authority.
    pub fn status(&self) -> MessageStatus {
        MessageStatus {
            records: self.exact.io.get_ref().0.status(),
            incoming: self.exact.incoming.progress,
            outgoing: self.exact.outgoing.progress,
            incoming_offset: self.exact.incoming.offset,
            outgoing_offset: self.exact.outgoing.offset,
            message_available: self.exact.message().is_some(),
            send_pending: self.exact.outgoing.length != 0,
            fault: self.exact.fault,
        }
    }
    fn checked(&mut self) -> Result<(), MessageError> {
        self.exact.live()?;
        if let Some(fault) = self.exact.io.get_ref().0.status().fault {
            return Err(self.exact.fail(MessageError::Record(fault)));
        }
        // The immutable original pairing is retained; this is not a freeze predicate.
        if !self.exact.io.get_ref().0.belongs_to(&self.handle) {
            return Err(self.exact.fail(MessageError::Io {
                kind: io::ErrorKind::InvalidData,
                raw_os_error: None,
            }));
        }
        Ok(())
    }
    fn after_io(
        &mut self,
        result: Poll<Result<(), MessageError>>,
    ) -> Poll<Result<(), MessageError>> {
        // Called only after checked() succeeded immediately before the backend poll.
        // Preserve earlier faults by never reaching this path once they are latched.
        // A fresh generic TLS I/O error may be caused by the original envelope fault.
        if matches!(self.exact.fault, Some(MessageError::Io { .. }))
            && let Some(fault) = self.exact.io.get_ref().0.status().fault
        {
            self.exact.fault = Some(MessageError::Record(fault));
        }
        self.checked()?;
        result
    }
    /// Reserve/copy one complete nonempty message; Busy/invalid staging does no I/O.
    pub fn stage_message(&mut self, payload: &[u8]) -> Result<(), MessageError> {
        self.checked()?;
        self.exact.stage(payload)
    }
    /// Resume the retained frame and its actual TLS flush, preserving partial offsets.
    pub fn poll_send(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), MessageError>> {
        self.checked()?;
        let result = self.exact.poll_send(cx);
        self.after_io(result)
    }
    /// Read only exact remaining header/body space; completed delivery blocks further reads.
    pub fn poll_receive(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), MessageError>> {
        self.checked()?;
        let result = self.exact.poll_receive(cx);
        self.after_io(result)
    }
    /// Borrow a validated complete message while live; never partial or expired bytes.
    pub fn message(&self) -> Option<&[u8]> {
        self.exact.message()
    }
    /// Release only the completed local slot; no TLS polling or hidden-input drain.
    pub fn consume_message(&mut self) -> Result<(), MessageError> {
        self.checked()?;
        self.exact.consume()
    }

    pub(super) fn freeze_terminal(
        mut self: Box<Self>,
        permit: super::pairing::packet::ArmedLane,
    ) -> Result<FrozenTls, super::pairing::packet::Error> {
        use super::pairing::packet::Error;
        self.checked()
            .map_err(|e| Error::Pair(super::pairing::PairError::Message(e)))?;
        if self.exact.outgoing.length != 0
            || !self.exact.incoming.complete
            || !permit.matches(&self.handle, self.exact.message().ok_or(Error::TlsFreeze)?)
        {
            return Err(Error::TlsFreeze);
        }
        let before = self.status().records;
        if before.fault.is_some()
            || before.read_eof
            || before.shutdown_started
            || before.shutdown_completed
            || !before.incoming.at_boundary()
            || !before.outgoing.at_boundary()
        {
            return Err(Error::TlsFreeze);
        }
        // Exact reads stopped at the terminal frame. No transport read or flush
        // occurs here. The empty backend write exposes deferred KeyUpdate output;
        // newly produced output is rejected, never discarded or silently flushed.
        macro_rules! check {
            ($stream:expr) => {{
                use std::io::Write;
                let connection = $stream.get_mut().1;
                if connection.is_handshaking() || connection.wants_write() {
                    return Err(Error::TlsFreeze);
                }
                let state = connection
                    .process_new_packets()
                    .map_err(|_| Error::TlsFreeze)?;
                if state.plaintext_bytes_to_read() != 0
                    || state.tls_bytes_to_write() != 0
                    || state.peer_has_closed()
                {
                    return Err(Error::TlsFreeze);
                }
                if connection
                    .writer()
                    .write(&[])
                    .map_err(|_| Error::TlsFreeze)?
                    != 0
                    || connection.wants_write()
                {
                    return Err(Error::TlsFreeze);
                }
                let state = connection
                    .process_new_packets()
                    .map_err(|_| Error::TlsFreeze)?;
                if state.plaintext_bytes_to_read() != 0
                    || state.tls_bytes_to_write() != 0
                    || state.peer_has_closed()
                {
                    return Err(Error::TlsFreeze);
                }
            }};
        }
        match &mut self.exact.io {
            TlsStream::Client(stream) => check!(stream),
            TlsStream::Server(stream) => check!(stream),
        }
        self.checked()
            .map_err(|e| Error::Pair(super::pairing::PairError::Message(e)))?;
        if self.status().records != before {
            return Err(Error::TlsFreeze);
        }
        // Keep the complete TLS object and terminal parser bytes. There is no
        // public accessor or further TLS poll on FrozenTls.
        Ok(FrozenTls { owner: self })
    }
}

pub(super) struct FrozenTls {
    owner: Box<TlsMessageOwner>,
}
impl FrozenTls {
    pub(super) fn status(&self) -> MessageStatus {
        self.owner.status()
    }
    pub(super) fn request(&mut self) -> Result<(), super::pairing::packet::Error> {
        let deadline = self.owner.exact.deadline;
        if Instant::now() >= deadline {
            return Err(super::pairing::packet::Error::Expired);
        }
        let start = super::stream::lock(&self.owner.handle.shared)?
            .started
            .ok_or(super::pairing::packet::Error::Proof)?;
        let duration = deadline
            .checked_duration_since(start)
            .ok_or(super::pairing::packet::Error::Expired)?;
        self.owner.handle.request_handoff(duration)?;
        if Instant::now() >= deadline {
            return Err(super::pairing::packet::Error::Expired);
        }
        Ok(())
    }
}
#[cfg(test)]
#[path = "tls_owner_tests.rs"]
mod tests;
