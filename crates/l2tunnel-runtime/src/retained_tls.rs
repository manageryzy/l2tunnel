//! Bounded record I/O on the original authenticated retained TCP/TLS owners.
//!
//! TLS protection remains additional to the selected inner Common protection.
//! A receipt observes the whole framed record flushed through the maintained
//! TLS stream; it does not assert an IP packet write, TCP acknowledgment or peer
//! delivery. This adapter owns no recovery algorithm, timer task or native I/O.

use crate::buffer_metrics::{
    Class as MetricClass, Collector, Extent, Key, Lane as MetricLane, Observer, Occupancy, Reason,
    Site,
};
use l2tunnel_auth::{AuthenticatedConnection, SessionInfo, TlsIoProfile};
use l2tunnel_core::{ConfigDigest, Duplex};
use l2tunnel_security::Role;
use ring::digest;
use std::{
    alloc::Layout,
    io,
    net::SocketAddr,
    pin::Pin,
    sync::atomic::{AtomicU64, Ordering},
    task::{Context, Poll},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    time::{Instant, timeout_at},
};

#[path = "retained_failure.rs"]
pub(crate) mod failure;
use failure::Failure;
#[path = "retained_tls_observations.rs"]
mod observations;

/// Four-byte checked length and one explicit bootstrap/final discriminator.
pub const FRAMING_BYTES: usize = 5;
const MAX_RECORD_BYTES: usize = 65535;
const IO_STEPS: usize = 32;
static NEXT_OWNER: AtomicU64 = AtomicU64::new(1);

/// Framing is a parsing choice, never proof of inner authentication.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Framing {
    /// Original Noise/member/bootstrap bytes, with their original setup cap.
    Bootstrap,
    /// Selected established Common Records bytes.
    Final,
}
impl Framing {
    fn byte(self) -> u8 {
        match self {
            Self::Bootstrap => 0,
            Self::Final => 1,
        }
    }
    fn parse(byte: u8) -> io::Result<Self> {
        match byte {
            0 => Ok(Self::Bootstrap),
            1 => Ok(Self::Final),
            _ => Err(invalid("unknown retained TLS framing")),
        }
    }
}

/// Local bounded admission class; it grants no receive-side authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Class {
    /// One retained user-data or recovery output.
    User,
    /// One independently reserved management/bootstrap output.
    Control,
}
impl Class {
    fn index(self) -> usize {
        match self {
            Self::User => 0,
            Self::Control => 1,
        }
    }
}

/// Public observations copied from an actual original authenticated TCP stream.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LaneInfo {
    /// Original TLS/member authentication result, including its exact digest.
    pub session: SessionInfo,
    /// Actual retained TCP local endpoint.
    pub local_addr: SocketAddr,
    /// Actual retained TCP peer endpoint.
    pub peer_addr: SocketAddr,
    /// Actual local TCP unsent threshold readback, absent when unavailable.
    /// This is neither dynamic occupancy nor a hard byte bound on the queue.
    pub tcp_notsent_lowat_bytes: Option<u32>,
}
/// Full/paired identity in global First (C2S bulk), Second (S2C bulk) order.
/// Copying this value cannot construct an authenticated Link or Adapter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Info {
    /// The sole Full connection, or the First Half connection.
    pub first: LaneInfo,
    /// The independently authenticated Second Half connection, if selected.
    pub second: Option<LaneInfo>,
    /// Role observed from the actual TLS/member proof.
    pub role: Role,
    /// Actual original connection topology.
    pub duplex: Duplex,
}

/// Actual authenticated ownership, retaining the existing pairing implementation.
pub struct Link {
    inner: crate::Link,
    info: Info,
    setup_deadline: Instant,
    limits: Limits,
}
impl Link {
    /// Consume one already authenticated original TCP/TLS connection.
    pub fn full(
        connection: AuthenticatedConnection,
        setup_deadline: Instant,
        limits: Limits,
    ) -> io::Result<Self> {
        before(setup_deadline)?;
        let first = lane_info(&connection, limits)?;
        before(setup_deadline)?;
        let info = Info {
            first,
            second: None,
            role: role(first.session),
            duplex: Duplex::Full,
        };
        Ok(Self {
            inner: crate::Link::full(connection),
            info,
            setup_deadline,
            limits,
        })
    }
    /// Original authenticated public observations, not a construction capability.
    pub fn info(&self) -> Info {
        self.info
    }
    /// The original overall establishment cap supplied by the owning factory.
    pub fn setup_deadline(&self) -> Instant {
        self.setup_deadline
    }
    /// Commit framing limits and the actual observed TCP/TLS lane topology.
    pub fn policy_digest(&self, limits: Limits) -> io::Result<ConfigDigest> {
        if limits != self.limits {
            return Err(input("retained TLS limits differ from original owner"));
        }
        policy_digest(self.info.duplex, limits)
    }
}

/// Pair the original authenticated client streams within the unchanged setup cap.
pub async fn client_pair(
    first: AuthenticatedConnection,
    second: AuthenticatedConnection,
    setup_deadline: Instant,
    limits: Limits,
) -> io::Result<Link> {
    paired(first, second, setup_deadline, limits, Role::Initiator).await
}
/// Pair the original authenticated server streams within the unchanged setup cap.
pub async fn server_pair(
    first: AuthenticatedConnection,
    second: AuthenticatedConnection,
    setup_deadline: Instant,
    limits: Limits,
) -> io::Result<Link> {
    paired(first, second, setup_deadline, limits, Role::Responder).await
}
async fn paired(
    first: AuthenticatedConnection,
    second: AuthenticatedConnection,
    setup_deadline: Instant,
    limits: Limits,
    expected_role: Role,
) -> io::Result<Link> {
    before(setup_deadline)?;
    let first_info = lane_info(&first, limits)?;
    let second_info = lane_info(&second, limits)?;
    if role(first_info.session) != expected_role || role(second_info.session) != expected_role {
        return Err(input("retained TLS pair role mismatch"));
    }
    let inner = timeout_at(setup_deadline, async {
        match expected_role {
            Role::Initiator => crate::client_pair(first, second).await,
            Role::Responder => crate::server_pair(first, second).await,
        }
    })
    .await
    .map_err(|_| expired())??;
    before(setup_deadline)?;
    Ok(Link {
        inner,
        info: Info {
            first: first_info,
            second: Some(second_info),
            role: expected_role,
            duplex: Duplex::Half,
        },
        setup_deadline,
        limits,
    })
}
fn lane_info(connection: &AuthenticatedConnection, limits: Limits) -> io::Result<LaneInfo> {
    if connection.profile() != TlsIoProfile::TcpTls {
        return Err(input(
            "retained TLS requires the actual TCP authentication profile",
        ));
    }
    Ok(LaneInfo {
        session: *connection.info(),
        local_addr: connection.local_addr()?,
        peer_addr: connection.peer_addr()?,
        tcp_notsent_lowat_bytes: connection
            .configure_tcp_notsent_lowat(limits.tcp_notsent_lowat_bytes()?)?,
    })
}
fn role(info: SessionInfo) -> Role {
    if info.peer_member.is_some() {
        Role::Responder
    } else {
        Role::Initiator
    }
}

/// Explicit finite framing limits, bound by the higher-level session contract.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Limits {
    /// Maximum original record body, excluding the five framing bytes.
    pub max_record_bytes: usize,
    /// Maximum age of one partial input or admitted output; progress never renews it.
    pub record_timeout: Duration,
}
impl Limits {
    /// Local unsent-data threshold derived from two maximum framed records.
    /// Kernel buffering can overshoot this threshold; it is not an exact FIFO
    /// capacity, physical-byte charge or limit on unacknowledged TCP flight.
    pub fn tcp_notsent_lowat_bytes(self) -> io::Result<u32> {
        self.validate()?;
        tcp_notsent_lowat_bytes(self.max_record_bytes)
    }

    /// Validate bounds without allocating or accessing a connection.
    pub fn validate(self) -> io::Result<()> {
        if !(1..=MAX_RECORD_BYTES).contains(&self.max_record_bytes)
            || self.record_timeout.is_zero()
            || self.record_timeout > Duration::from_secs(120)
        {
            return Err(input("invalid retained TLS framing limits"));
        }
        Ok(())
    }
}

/// Derive the local TCP unsent threshold from the maximum framed record size.
/// This scheduling preference is independent of the wire policy commitment.
pub fn tcp_notsent_lowat_bytes(max_record_bytes: usize) -> io::Result<u32> {
    if !(1..=MAX_RECORD_BYTES).contains(&max_record_bytes) {
        return Err(input("invalid retained TLS record size for TCP threshold"));
    }
    max_record_bytes
        .checked_add(FRAMING_BYTES)
        .and_then(|bytes| bytes.checked_mul(2))
        .and_then(|bytes| u32::try_from(bytes).ok())
        .ok_or_else(exhausted)
}

/// Canonical pre-authentication policy for the retained TCP/TLS adapter.
/// Public Link construction verifies `TlsIoProfile::TcpTls` on every real lane;
/// this commitment cannot relabel an OpenVPN or raw-packet owner as a TLS stream.
pub fn policy_digest(duplex: Duplex, limits: Limits) -> io::Result<ConfigDigest> {
    limits.validate()?;
    let mut hash = digest::Context::new(&digest::SHA256);
    hash.update(b"l2tunnel/retained-tls/common-framing/v1\0");
    hash.update(&[1, if duplex == Duplex::Full { 1 } else { 2 }]);
    hash.update(
        &u64::try_from(limits.max_record_bytes)
            .map_err(io::Error::other)?
            .to_be_bytes(),
    );
    hash.update(&limits.record_timeout.as_secs().to_be_bytes());
    hash.update(&limits.record_timeout.subsec_nanos().to_be_bytes());
    hash.update(&[FRAMING_BYTES as u8, 1, 1]);
    let mut bytes = [0; 32];
    bytes.copy_from_slice(hash.finish().as_ref());
    Ok(ConfigDigest(bytes))
}

/// Exact new adapter storage; preexisting TLS/boxed-stream resources are separate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Plan {
    info: Info,
    limits: Limits,
    lanes: usize,
    capacity: usize,
}
impl Plan {
    /// Pure framing/storage preflight on the actual original owner.
    pub fn new(link: &Link, limits: Limits) -> io::Result<Self> {
        limits.validate()?;
        if limits != link.limits {
            return Err(input("retained TLS plan differs from original limits"));
        }
        let lanes = if link.info.duplex == Duplex::Half {
            2
        } else {
            1
        };
        let outputs = limits
            .max_record_bytes
            .checked_add(FRAMING_BYTES)
            .and_then(|n| n.checked_mul(2))
            .ok_or_else(exhausted)?;
        let capacity = Layout::array::<Lane>(lanes)
            .map_err(io::Error::other)?
            .size()
            .checked_add(std::mem::size_of::<Adapter>())
            .and_then(|n| n.checked_add(limits.max_record_bytes.checked_mul(lanes)?))
            .and_then(|n| n.checked_add(outputs))
            .ok_or_else(exhausted)?;
        Ok(Self {
            info: link.info,
            limits,
            lanes,
            capacity,
        })
    }
    /// Adapter inline bytes and every newly allocated lane/input/output backing.
    pub fn capacity_bytes(self) -> usize {
        self.capacity
    }
    /// Lane vector, each lane input, and the two persistent class output buffers.
    pub fn allocations(self) -> usize {
        self.lanes + 3
    }
    /// Exact selected body bound and immutable record-age policy.
    pub fn limits(self) -> Limits {
        self.limits
    }
}

/// The only completion boundary this maintained stream adapter can observe.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SendBoundary {
    /// Whole application framing written and flushed through original TLS.
    TlsStreamFlushed,
}
/// Actual whole-stream flush fact, retained even if its original cap was crossed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Receipt {
    /// Original submitted record body bytes.
    pub record_bytes: usize,
    /// Exact application stream bytes including the five-byte framing.
    pub framed_bytes: usize,
    /// Original caller cap, also bounded by the setup cap for bootstrap records.
    pub deadline: Instant,
    /// Immutable minimum of the caller cap and local record-age limit.
    pub operation_deadline: Instant,
    /// Actual observation immediately after the successful whole flush.
    pub flushed_at: Instant,
    /// True when the successful whole flush crossed either immutable cap.
    pub late: bool,
    /// Maintained stream flush, never an invented physical datagram receipt.
    pub boundary: SendBoundary,
    /// Global original lane, zero for First or one for Second.
    pub lane: usize,
}
/// One retained completed input; the inner record verifier still owns authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Received {
    /// Original body copied to the caller's output.
    pub bytes: usize,
    /// Exact explicit outer framing discriminator.
    pub framing: Framing,
    /// Completion time of this whole original application frame.
    pub received_at: Instant,
    /// Global original physical lane.
    pub lane: usize,
}

/// Move-only submission identity tied to the issuing original adapter.
pub struct Token {
    owner: u64,
    serial: u64,
    class: Class,
    deadline: Instant,
    operation_deadline: Instant,
    consumed: bool,
}
impl Token {
    /// Original immutable cap, never renewed by a cancelled wait or retry.
    pub fn deadline(&self) -> Instant {
        self.deadline
    }
    /// Immutable local I/O cap after bounding the caller's original deadline.
    pub fn operation_deadline(&self) -> Instant {
        self.operation_deadline
    }
    /// Original trusted local admission class.
    pub fn class(&self) -> Class {
        self.class
    }
}

struct Output {
    bytes: Vec<u8>,
    pending: Option<Pending>,
}
struct Pending {
    serial: u64,
    lane: usize,
    length: usize,
    offset: usize,
    deadline: Instant,
    operation_deadline: Instant,
    receipt: Option<Receipt>,
}
struct Lane {
    reader: Pin<Box<dyn AsyncRead + Send>>,
    writer: Pin<Box<dyn AsyncWrite + Send>>,
    input: Input,
    active: Option<Class>,
    prefer_control: bool,
}
struct Input {
    prefix: [u8; FRAMING_BYTES],
    prefix_used: usize,
    bytes: Vec<u8>,
    body_used: usize,
    length: Option<usize>,
    deadline: Option<Instant>,
    ready: Option<Received>,
}
impl Input {
    fn new(maximum: usize) -> io::Result<Self> {
        Ok(Self {
            prefix: [0; FRAMING_BYTES],
            prefix_used: 0,
            bytes: buffer(maximum)?,
            body_used: 0,
            length: None,
            deadline: None,
            ready: None,
        })
    }
    fn reset(&mut self) {
        self.prefix_used = 0;
        self.body_used = 0;
        self.length = None;
        self.deadline = None;
        self.ready = None;
    }
}

/// Sole reader/writer of the original authenticated Full/Half TLS connections.
/// Callers must wake no later than `next_deadline`; no independent timer is spawned.
pub struct Adapter {
    owner: u64,
    next: Option<u64>,
    info: Info,
    setup_deadline: Instant,
    plan: Plan,
    lanes: Vec<Lane>,
    output: [Output; 2],
    control_lane: usize,
    receive_lane: usize,
    failed: Option<Failure>,
    metrics: Option<Observer>,
}
impl Adapter {
    /// Allocate the preflighted new storage after the enclosing retained-budget check.
    pub fn new(link: Link, plan: Plan) -> io::Result<Self> {
        before(link.setup_deadline)?;
        if Plan::new(&link, plan.limits)? != plan {
            return Err(input("retained TLS plan differs from actual owner"));
        }
        let owner = NEXT_OWNER
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_add(1))
            .map_err(|_| exhausted())?;
        let crate::Link {
            reader,
            writer,
            reverse_reader,
            reverse_writer,
            ..
        } = link.inner;
        let mut lanes = Vec::new();
        lanes
            .try_reserve_exact(plan.lanes)
            .map_err(io::Error::other)?;
        if lanes.capacity() != plan.lanes {
            return Err(input("retained TLS lane capacity differs from plan"));
        }
        let mut add_lane = |reader, writer| -> io::Result<()> {
            lanes.push(Lane {
                reader,
                writer,
                input: Input::new(plan.limits.max_record_bytes)?,
                active: None,
                prefer_control: true,
            });
            Ok(())
        };
        match (link.info.duplex, reverse_reader, reverse_writer) {
            (Duplex::Full, None, None) => add_lane(reader, writer)?,
            (Duplex::Half, Some(reverse_reader), Some(reverse_writer)) => match link.info.role {
                Role::Initiator => {
                    add_lane(reverse_reader, writer)?;
                    add_lane(reader, reverse_writer)?;
                }
                Role::Responder => {
                    add_lane(reader, reverse_writer)?;
                    add_lane(reverse_reader, writer)?;
                }
            },
            _ => return Err(input("retained TLS original lane topology differs")),
        }
        let maximum = plan
            .limits
            .max_record_bytes
            .checked_add(FRAMING_BYTES)
            .ok_or_else(exhausted)?;
        let mut adapter = Self {
            owner,
            next: Some(0),
            info: link.info,
            setup_deadline: link.setup_deadline,
            plan,
            lanes,
            output: [
                Output {
                    bytes: buffer(maximum)?,
                    pending: None,
                },
                Output {
                    bytes: buffer(maximum)?,
                    pending: None,
                },
            ],
            control_lane: 0,
            receive_lane: 0,
            failed: None,
            metrics: Observer::from_environment("retained_tls")?,
        };
        for class in [Class::User, Class::Control] {
            metric_output(&mut adapter.metrics, class, &adapter.output[class.index()]);
        }
        for (index, lane) in adapter.lanes.iter().enumerate() {
            metric_input(&mut adapter.metrics, index, &lane.input, plan.limits);
        }
        Ok(adapter)
    }
    /// Public actual-session observations; this does not release the stream owners.
    pub fn info(&self) -> Info {
        self.info
    }
    /// Exact new storage admitted by the enclosing runtime.
    pub fn plan(&self) -> Plan {
        self.plan
    }
    /// Actual selected framing policy, matching the pre-authentication helper.
    pub fn policy_digest(&self) -> io::Result<ConfigDigest> {
        policy_digest(self.info.duplex, self.plan.limits)
    }
    /// Original overall setup cap; final stream traffic does not renew it.
    pub fn setup_deadline(&self) -> Instant {
        self.setup_deadline
    }
    /// Original First lane endpoints, with all Half endpoints available through info.
    pub fn addresses(&self) -> (SocketAddr, SocketAddr) {
        (self.info.first.local_addr, self.info.first.peer_addr)
    }
    /// Earliest immutable pending I/O cap; idle connections are governed by Common.
    pub fn next_deadline(&self) -> Option<Instant> {
        self.output
            .iter()
            .filter_map(|output| output.pending.as_ref())
            .filter(|pending| pending.receipt.is_none())
            .map(|pending| pending.operation_deadline)
            .chain(self.lanes.iter().filter_map(|lane| lane.input.deadline))
            .min()
    }
    /// Whether a complete bounded input already awaits the sole receiver.
    pub fn receive_ready(&self) -> bool {
        self.lanes.iter().any(|lane| lane.input.ready.is_some())
    }
    /// Earliest completed retained input observation, solely for causal ordering.
    /// This does not authenticate the inner record or advance any receive state.
    pub fn earliest_input_at(&self) -> Option<Instant> {
        self.lanes
            .iter()
            .filter_map(|lane| lane.input.ready.map(|received| received.received_at))
            .min()
    }
    /// Observe the first terminal failure without altering its cause or receipts.
    pub fn check_failure(&self) -> io::Result<()> {
        match &self.failed {
            Some(error) => Err(error.error()),
            None => Ok(()),
        }
    }
    /// Exact first read-side closure at a record boundary, never retirement proof.
    pub(crate) fn peer_close_error(&self, error: &io::Error) -> bool {
        self.failed
            .as_ref()
            .is_some_and(|failure| failure.is_peer_close(error))
    }
    #[cfg(any(unix, test))]
    pub(crate) fn retained_output_empty(&self) -> bool {
        self.output.iter().all(|output| output.pending.is_none())
    }
    /// Reserve exactly one class slot and copy one complete immutable framed record.
    /// Busy admits nothing and never advances the local submission serial.
    pub fn try_send(
        &mut self,
        class: Class,
        bytes: &[u8],
        original_deadline: Instant,
        framing: Framing,
    ) -> io::Result<Token> {
        self.check_failure()?;
        if bytes.is_empty() || bytes.len() > self.plan.limits.max_record_bytes {
            return Err(input("retained TLS record size"));
        }
        let deadline = match framing {
            Framing::Bootstrap => original_deadline.min(self.setup_deadline),
            Framing::Final => original_deadline,
        };
        before(deadline)?;
        let output = &mut self.output[class.index()];
        if output.pending.is_some() {
            metric_blocked(&mut self.metrics, submission_key(class), Reason::QueueFull);
            return Err(io::ErrorKind::WouldBlock.into());
        }
        let serial = self.next.ok_or_else(exhausted)?;
        let operation_deadline = Instant::now()
            .checked_add(self.plan.limits.record_timeout)
            .ok_or_else(exhausted)?
            .min(deadline);
        let lane = match class {
            Class::User => {
                usize::from(self.info.duplex == Duplex::Half && self.info.role == Role::Responder)
            }
            Class::Control => self.control_lane,
        };
        let length = bytes
            .len()
            .checked_add(FRAMING_BYTES)
            .ok_or_else(exhausted)?;
        let encoded_length = u32::try_from(bytes.len() + 1).map_err(io::Error::other)?;
        output.bytes[..4].copy_from_slice(&encoded_length.to_be_bytes());
        output.bytes[4] = framing.byte();
        output.bytes[FRAMING_BYTES..length].copy_from_slice(bytes);
        output.pending = Some(Pending {
            serial,
            lane,
            length,
            offset: 0,
            deadline,
            operation_deadline,
            receipt: None,
        });
        metric_output(&mut self.metrics, class, output);
        self.next = serial.checked_add(1);
        if class == Class::Control {
            self.control_lane = (lane + 1) % self.plan.lanes;
        }
        Ok(Token {
            owner: self.owner,
            serial,
            class,
            deadline,
            operation_deadline,
            consumed: false,
        })
    }
    /// Poll the original submitted bytes without rebuilding or restarting I/O.
    /// A completed late flush is returned as a fact with `late=true`; the owner
    /// is terminal and must not be treated as a successfully drained connection.
    pub fn poll_send(
        &mut self,
        cx: &mut Context<'_>,
        token: &mut Token,
    ) -> Poll<io::Result<Receipt>> {
        if token.owner != self.owner || token.consumed {
            return Poll::Ready(Err(input("retained TLS send token ownership")));
        }
        let index = token.class.index();
        if self.output[index].pending.as_ref().map(|p| p.serial) != Some(token.serial) {
            return Poll::Ready(Err(input("retained TLS send token identity")));
        }
        let _ = self.poll_progress(cx);
        if let Some(receipt) = self.output[index].pending.as_ref().and_then(|p| p.receipt) {
            self.output[index].pending = None;
            token.consumed = true;
            metric_progress(
                &mut self.metrics,
                submission_key(token.class),
                Reason::QueueFull,
            );
            metric_output(&mut self.metrics, token.class, &self.output[index]);
            return Poll::Ready(Ok(receipt));
        }
        if let Err(error) = self.check_failure() {
            self.output[index].pending = None;
            token.consumed = true;
            return Poll::Ready(Err(error));
        }
        Poll::Pending
    }
    /// Service both class outputs and both original readers with bounded work.
    /// The caller owns wake timing and must also poll by `next_deadline`.
    pub fn poll_progress(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if let Err(error) = self.check_failure() {
            return Poll::Ready(Err(error));
        }
        if self
            .next_deadline()
            .is_some_and(|deadline| Instant::now() >= deadline)
        {
            return Poll::Ready(Err(self.fail(expired(), "pending-deadline")));
        }
        let mut progressed = false;
        for index in 0..self.lanes.len() {
            match poll_write(
                &mut self.lanes[index],
                index,
                &mut self.output,
                &mut self.metrics,
                cx,
            ) {
                Ok(progress) => progressed |= progress,
                Err(error) => return Poll::Ready(Err(self.fail(error, "write-or-flush"))),
            }
            if self.output.iter().any(|output| {
                output
                    .pending
                    .as_ref()
                    .and_then(|pending| pending.receipt)
                    .is_some_and(|receipt| receipt.late)
            }) {
                return Poll::Ready(Err(self.fail(expired(), "late-flush")));
            }
            match poll_read(
                &mut self.lanes[index],
                index,
                self.plan.limits,
                &mut self.metrics,
                cx,
            ) {
                Ok(progress) => progressed |= progress,
                Err(error) => {
                    let peer_close = error.kind() == io::ErrorKind::UnexpectedEof
                        && self.lanes.iter().all(|lane| {
                            lane.input.prefix_used == 0
                                && lane.input.body_used == 0
                                && lane.input.ready.is_none()
                        });
                    return Poll::Ready(Err(self.fail_with_close(error, peer_close, "read")));
                }
            }
        }
        if progressed
            && self.output.iter().any(|output| {
                output
                    .pending
                    .as_ref()
                    .is_some_and(|pending| pending.receipt.is_none())
            })
        {
            // A completed class can expose another queued record on the same
            // lane without a new socket edge. Polling its token must not stall.
            cx.waker().wake_by_ref();
        }
        if progressed || self.receive_ready() {
            Poll::Ready(Ok(()))
        } else {
            Poll::Pending
        }
    }
    /// Receive exactly one complete frame from the same retained stream owners.
    /// Cancelling this wait preserves every partial prefix/body byte and deadline.
    pub fn poll_receive(
        &mut self,
        cx: &mut Context<'_>,
        output: &mut [u8],
    ) -> Poll<io::Result<Received>> {
        if let Poll::Ready(Err(error)) = self.poll_progress(cx) {
            return Poll::Ready(Err(error));
        }
        for offset in 0..self.lanes.len() {
            let index = (self.receive_lane + offset) % self.lanes.len();
            let input = &mut self.lanes[index].input;
            if let Some(received) = input.ready {
                if output.len() < received.bytes {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "retained TLS receive output too small",
                    )));
                }
                output[..received.bytes].copy_from_slice(&input.bytes[..received.bytes]);
                input.reset();
                metric_input(&mut self.metrics, index, input, self.plan.limits);
                self.receive_lane = (index + 1) % self.lanes.len();
                return Poll::Ready(Ok(received));
            }
        }
        Poll::Pending
    }
    fn fail(&mut self, error: io::Error, site: &'static str) -> io::Error {
        self.fail_with_close(error, false, site)
    }
    fn fail_with_close(
        &mut self,
        error: io::Error,
        peer_close: bool,
        site: &'static str,
    ) -> io::Error {
        if self.failed.is_none() {
            let kind = error.kind();
            self.failed = Some(Failure::new(error, peer_close));
            if let Some(metrics) = self.metrics.as_mut() {
                metrics.finish_at(metrics.now());
            }
            observations::trace_failure(self, kind, site);
            // Both original Half connections fail together. Completed output facts
            // remain available through their original tokens after the I/O drops.
            self.lanes.clear();
        }
        match &self.failed {
            Some(error) => error.error(),
            None => invalid("retained TLS terminal state missing"),
        }
    }
}

fn poll_write(
    lane: &mut Lane,
    index: usize,
    outputs: &mut [Output; 2],
    metrics: &mut Option<Observer>,
    cx: &mut Context<'_>,
) -> io::Result<bool> {
    if lane.active.is_none() {
        let order = if lane.prefer_control {
            [Class::Control, Class::User]
        } else {
            [Class::User, Class::Control]
        };
        lane.active = order.into_iter().find(|class| {
            outputs[class.index()]
                .pending
                .as_ref()
                .is_some_and(|pending| pending.lane == index && pending.receipt.is_none())
        });
        if let Some(class) = lane.active {
            lane.prefer_control = class == Class::User;
        }
    }
    observations::writer_dependency(lane, index, outputs, metrics);
    let Some(class) = lane.active else {
        return Ok(false);
    };
    let write_key = lane_key(Site::TlsWrite, index, metric_class(class));
    let flush_key = lane_key(Site::TlsFlush, index, metric_class(class));
    metric_resumed(metrics, write_key, Reason::WorkBudget);
    let output = &mut outputs[class.index()];
    let Some(pending) = output.pending.as_mut() else {
        return Err(invalid("retained TLS active output missing"));
    };
    let mut progressed = false;
    for _ in 0..IO_STEPS {
        if Instant::now() >= pending.operation_deadline {
            return Err(expired());
        }
        if pending.offset < pending.length {
            match lane
                .writer
                .as_mut()
                .poll_write(cx, &output.bytes[pending.offset..pending.length])
            {
                Poll::Pending => {
                    metric_blocked(metrics, write_key, Reason::IoPending);
                    return Ok(progressed);
                }
                Poll::Ready(Err(error)) => return Err(error),
                Poll::Ready(Ok(0)) => return Err(io::ErrorKind::WriteZero.into()),
                Poll::Ready(Ok(bytes)) => {
                    pending.offset = pending.offset.checked_add(bytes).ok_or_else(exhausted)?;
                    if pending.offset > pending.length {
                        return Err(invalid("retained TLS writer exceeded original record"));
                    }
                    metric_progress(metrics, write_key, Reason::IoPending);
                    progressed = true;
                }
            }
        } else {
            match lane.writer.as_mut().poll_flush(cx) {
                Poll::Pending => {
                    metric_blocked(metrics, flush_key, Reason::FlushPending);
                    return Ok(progressed);
                }
                Poll::Ready(Err(error)) => return Err(error),
                Poll::Ready(Ok(())) => {
                    let flushed_at = Instant::now();
                    pending.receipt = Some(Receipt {
                        record_bytes: pending.length - FRAMING_BYTES,
                        framed_bytes: pending.length,
                        deadline: pending.deadline,
                        operation_deadline: pending.operation_deadline,
                        flushed_at,
                        late: flushed_at >= pending.operation_deadline,
                        boundary: SendBoundary::TlsStreamFlushed,
                        lane: index,
                    });
                    metric_progress(metrics, flush_key, Reason::FlushPending);
                    metric_output(metrics, class, output);
                    lane.active = None;
                    return Ok(true);
                }
            }
        }
    }
    metric_blocked(metrics, write_key, Reason::WorkBudget);
    cx.waker().wake_by_ref();
    Ok(progressed)
}
fn poll_read(
    lane: &mut Lane,
    index: usize,
    limits: Limits,
    metrics: &mut Option<Observer>,
    cx: &mut Context<'_>,
) -> io::Result<bool> {
    let input = &mut lane.input;
    let key = lane_key(Site::TlsInput, index, MetricClass::Shared);
    metric_resumed(metrics, key, Reason::WorkBudget);
    if input.ready.is_some() {
        return Ok(false);
    }
    let mut progressed = false;
    for _ in 0..IO_STEPS {
        if input
            .deadline
            .is_some_and(|deadline| Instant::now() >= deadline)
        {
            return Err(expired());
        }
        let destination = if input.prefix_used < FRAMING_BYTES {
            &mut input.prefix[input.prefix_used..]
        } else {
            let length = input
                .length
                .ok_or_else(|| invalid("retained TLS missing parsed length"))?;
            &mut input.bytes[input.body_used..length]
        };
        let mut read = ReadBuf::new(destination);
        match lane.reader.as_mut().poll_read(cx, &mut read) {
            Poll::Pending => {
                if input.prefix_used != 0 || input.body_used != 0 {
                    metric_blocked(metrics, key, Reason::Dependency);
                }
                metric_input(metrics, index, input, limits);
                return Ok(progressed);
            }
            Poll::Ready(Err(error)) => return Err(error),
            Poll::Ready(Ok(())) => {
                let bytes = read.filled().len();
                if bytes == 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "retained TLS original stream ended",
                    ));
                }
                let now = Instant::now();
                if input.deadline.is_none() {
                    input.deadline = Some(
                        now.checked_add(limits.record_timeout)
                            .ok_or_else(exhausted)?,
                    );
                }
                if input.deadline.is_some_and(|deadline| now >= deadline) {
                    return Err(expired());
                }
                metric_resumed(metrics, key, Reason::Dependency);
                progressed = true;
                if input.prefix_used < FRAMING_BYTES {
                    input.prefix_used += bytes;
                    if input.prefix_used == FRAMING_BYTES {
                        let encoded = u32::from_be_bytes(
                            input.prefix[..4]
                                .try_into()
                                .map_err(|_| invalid("retained TLS length prefix"))?,
                        );
                        let length = usize::try_from(encoded).map_err(io::Error::other)?;
                        if length < 2 || length - 1 > limits.max_record_bytes {
                            return Err(invalid("retained TLS framed length exceeds bound"));
                        }
                        Framing::parse(input.prefix[4])?;
                        input.length = Some(length - 1);
                    }
                } else {
                    input.body_used += bytes;
                    if Some(input.body_used) == input.length {
                        input.ready = Some(Received {
                            bytes: input.body_used,
                            framing: Framing::parse(input.prefix[4])?,
                            received_at: now,
                            lane: index,
                        });
                        input.deadline = None;
                        metric_input(metrics, index, input, limits);
                        return Ok(true);
                    }
                }
            }
        }
    }
    metric_input(metrics, index, input, limits);
    metric_blocked(metrics, key, Reason::WorkBudget);
    cx.waker().wake_by_ref();
    Ok(progressed)
}

fn metric_class(class: Class) -> MetricClass {
    match class {
        Class::User => MetricClass::User,
        Class::Control => MetricClass::Management,
    }
}
fn submission_key(class: Class) -> Key {
    Key {
        site: Site::TlsSubmission,
        lane: MetricLane::Shared,
        class: metric_class(class),
    }
}
fn lane_key(site: Site, index: usize, class: MetricClass) -> Key {
    Key {
        site,
        lane: MetricLane::at(index),
        class,
    }
}
fn metric_update(metrics: &mut Option<Observer>, update: impl FnOnce(&mut Collector, u64)) {
    if let Some(metrics) = metrics.as_mut() {
        let now = metrics.now();
        // Terminal receipt cleanup may continue after the first failure. Keep
        // unresolved intervals censored at that failure instead of extending them.
        if !metrics.is_finished() {
            update(metrics.collector(), now);
        }
    }
}
fn metric_blocked(metrics: &mut Option<Observer>, key: Key, reason: Reason) {
    metric_update(metrics, |collector, now| {
        let _ = collector.blocked(key, reason, now);
    });
}
fn metric_progress(metrics: &mut Option<Observer>, key: Key, reason: Reason) {
    metric_update(metrics, |collector, now| {
        let _ = collector.progress(key, reason, now);
    });
}
fn metric_resumed(metrics: &mut Option<Observer>, key: Key, reason: Reason) {
    metric_update(metrics, |collector, now| {
        if collector
            .reason(key, reason, now)
            .is_ok_and(|state| state.blocked.open_us.is_some())
        {
            let _ = collector.progress(key, reason, now);
        }
    });
}
fn metric_output(metrics: &mut Option<Observer>, class: Class, output: &Output) {
    let key = submission_key(class);
    metric_update(metrics, |collector, now| {
        let _ = collector.sample(
            key,
            now,
            Occupancy {
                bytes: Some(Extent {
                    used: output
                        .pending
                        .as_ref()
                        .map_or(0, |pending| pending.length as u64),
                    capacity: Some(output.bytes.len() as u64),
                }),
                items: Some(Extent {
                    used: u64::from(output.pending.is_some()),
                    capacity: Some(1),
                }),
            },
        );
        let _ = collector.sample(
            Key {
                site: Site::TlsReceipt,
                ..key
            },
            now,
            Occupancy {
                bytes: None,
                items: Some(Extent {
                    used: u64::from(
                        output
                            .pending
                            .as_ref()
                            .is_some_and(|pending| pending.receipt.is_some()),
                    ),
                    capacity: Some(1),
                }),
            },
        );
    });
}
fn metric_input(metrics: &mut Option<Observer>, index: usize, input: &Input, limits: Limits) {
    // An occupied input cell suppresses another read, but says nothing about
    // whether more peer bytes are ready. Record occupancy, not an inferred wait.
    metric_update(metrics, |collector, now| {
        let _ = collector.sample(
            lane_key(Site::TlsInput, index, MetricClass::Shared),
            now,
            Occupancy {
                bytes: Some(Extent {
                    used: (input.prefix_used + input.body_used) as u64,
                    capacity: Some((limits.max_record_bytes + FRAMING_BYTES) as u64),
                }),
                items: Some(Extent {
                    used: u64::from(input.prefix_used != 0 || input.body_used != 0),
                    capacity: Some(1),
                }),
            },
        );
    });
}
fn buffer(bytes: usize) -> io::Result<Vec<u8>> {
    let mut result = Vec::new();
    result.try_reserve_exact(bytes).map_err(io::Error::other)?;
    if result.capacity() != bytes {
        return Err(input("retained TLS buffer capacity differs from plan"));
    }
    result.resize(bytes, 0);
    Ok(result)
}
fn before(deadline: Instant) -> io::Result<()> {
    if Instant::now() >= deadline {
        Err(expired())
    } else {
        Ok(())
    }
}
fn input(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}
fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
fn exhausted() -> io::Error {
    io::Error::other("retained TLS checked capacity or counter exhausted")
}
fn expired() -> io::Error {
    io::Error::new(
        io::ErrorKind::TimedOut,
        "retained TLS original record cap expired",
    )
}

#[cfg(test)]
#[path = "retained_tls_tests.rs"]
mod tests;

// Internal timer/framing regressions may use a synthetic stream without exposing
// a public authentication constructor or claiming actual TLS/member evidence.
#[cfg(test)]
pub(crate) fn test_framing_adapter(
    capacity: usize,
) -> io::Result<(Adapter, tokio::io::DuplexStream)> {
    tests::framing_pair(capacity)
}
