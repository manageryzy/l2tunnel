//! Actual maintained-owner custody, separate from physical datagram acceptance.
use super::maintained::{Authenticated, Geometry, Kind, Lane, Request};
use crate::retained_tls as tls;
use l2tunnel_auth::SessionConfig;
use l2tunnel_core::Duplex;
use l2tunnel_quic::common as quic;
use std::{
    alloc::Layout,
    future::{Future, poll_fn},
    io,
    net::SocketAddr,
    pin::Pin,
    sync::atomic::{AtomicU64, Ordering},
    task::{Context, Poll},
};
use tokio::time::{Instant, sleep_until};

static NEXT_OWNER: AtomicU64 = AtomicU64::new(1);

/// Trusted local scheduling class, never authentication for incoming records.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Class {
    /// Ordinary user data follows the actual directional lane.
    User,
    /// Bootstrap, authenticated feedback and management remain bidirectional.
    Control,
}
impl Class {
    fn index(self) -> usize {
        usize::from(self == Self::Control)
    }
}
/// Actual outer framing fact, preserved before removing any outer bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Framing {
    /// Retained bounded original setup traffic.
    Bootstrap,
    /// Exact selected final Common record.
    Final,
}
/// Complete maintained acceptance; physical transmission remains unobserved.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Receipt {
    /// Original caller record bytes.
    pub record_bytes: usize,
    /// Actual application bytes handed to the maintained transport.
    pub framed_bytes: usize,
    /// Configured conservative charge, never measured physical IP bytes.
    pub charged_bytes: usize,
    /// Actual named maintained acceptance time.
    pub accepted_at: Instant,
    /// Immutable effective operation deadline.
    pub deadline: Instant,
    /// Whether acceptance crossed the original effective cap.
    pub late: bool,
    /// Explicit maintained boundary, never an OS-acceptance alias.
    pub boundary: crate::secure_udp::SendBoundary,
    /// Original global lane index.
    pub lane: usize,
}
/// Failure preserves any actual late maintained acceptance.
#[derive(Debug)]
pub enum SendFailure {
    /// Original cap expired, possibly after a complete maintained acceptance.
    Expired {
        /// Actual acceptance, if already observed.
        accepted: Option<Receipt>,
    },
    /// Actual owner, configuration or transport failure.
    Io(io::Error),
    /// Wrong owner, stale or already consumed move-only ticket.
    Ticket,
}
impl std::fmt::Display for SendFailure {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(out, "maintained send: {self:?}")
    }
}
impl std::error::Error for SendFailure {}
/// One complete untrusted record copied from its actual original lane.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Received {
    /// Caller bytes copied to the output slice.
    pub bytes: usize,
    /// Unambiguous setup/final framing fact.
    pub framing: Framing,
    /// Original maintained receive observation.
    pub received_at: Instant,
    /// Actual original global lane.
    pub lane: usize,
}
/// Move-only original submission identity. Actual pending I/O remains with Carrier.
pub struct PendingSend {
    owner: u64,
    serial: u64,
    class: Class,
    deadline: Instant,
    bytes: usize,
    consumed: bool,
}
impl PendingSend {
    /// Original immutable effective cap.
    pub fn deadline(&self) -> Instant {
        self.deadline
    }
    /// Original trusted local class.
    pub fn class(&self) -> Class {
        self.class
    }
    /// Exact retained caller record bytes.
    pub fn record_bytes(&self) -> usize {
        self.bytes
    }
}
enum Backend {
    Tls(Vec<tls::Adapter>),
    Quic(Vec<quic::Carrier>),
}
enum Pending {
    Tls(tls::Token),
    Quic(quic::PendingSend),
}
struct Output {
    serial: u64,
    lane: usize,
    framing: Framing,
    pending: Pending,
    result: Option<Result<Receipt, SendFailure>>,
}

/// Sole genuine Full/Half transport owner through Common setup and final traffic.
pub struct Carrier {
    backend: Backend,
    proof: Authenticated,
    owner: u64,
    next: Option<u64>,
    output: [Option<Output>; 2],
    input: [Option<quic::Received>; 2],
    control_lane: usize,
    receive_lane: usize,
    final_records: bool,
    capacity: usize,
    allocations: usize,
    failed: Option<io::Error>,
}
impl Carrier {
    /// Preflight new retained TLS/wrapper backing, verify real policy and then own it.
    pub fn tls(
        link: tls::Link,
        limits: tls::Limits,
        request: Request,
        base: SessionConfig,
        maximum_capacity_bytes: usize,
    ) -> io::Result<Self> {
        if request.kind != Kind::TlsStream
            || request.duplex != link.info().duplex
            || request.policy != link.policy_digest(limits)?
            || request.geometry.framing_bytes != tls::FRAMING_BYTES
            || request.geometry.max_record_bytes != limits.max_record_bytes
            || request.geometry.max_bootstrap_bytes > limits.max_record_bytes
        {
            return Err(invalid(
                "actual TLS policy differs from requested maintained carrier",
            ));
        }
        let info = link.info();
        let lane = |value: tls::LaneInfo| Lane {
            info: value.session,
            local: value.local_addr,
            peer: value.peer_addr,
        };
        let proof = Authenticated::checked(
            request,
            base,
            [Some(lane(info.first)), info.second.map(lane)],
            [Some(base), info.second.map(|_| base)],
            link.setup_deadline(),
        )?;
        let plan = tls::Plan::new(&link, limits)?;
        let capacity = plan
            .capacity_bytes()
            .checked_add(std::mem::size_of::<Self>())
            .ok_or_else(exhausted)?;
        capacity_cap(capacity, maximum_capacity_bytes)?;
        let allocations = plan.allocations().checked_add(1).ok_or_else(exhausted)?;
        let mut backing = Vec::new();
        backing.try_reserve_exact(1).map_err(io::Error::other)?;
        if backing.capacity() != 1 {
            return Err(invalid("maintained TLS singleton capacity differs"));
        }
        let adapter = tls::Adapter::new(link, plan)?;
        backing.push(adapter);
        Self::finish(Backend::Tls(backing), proof, capacity, allocations)
    }

    /// Own genuine selected Quinn lanes after validating their actual pair proof.
    /// Capacity includes concrete wrapper/lane backing and bounded copied records;
    /// maintained allocator metadata and boxed-future storage remain separately
    /// bounded by the selected profile, without an allocator-completeness claim.
    pub fn quic(
        values: Vec<quic::Carrier>,
        request: Request,
        base: SessionConfig,
        maximum_capacity_bytes: usize,
    ) -> io::Result<Self> {
        request.validate()?;
        let count = if request.duplex == Duplex::Half { 2 } else { 1 };
        if request.kind != Kind::QuicDatagram || values.len() != count || values.capacity() != count
        {
            return Err(invalid("actual QUIC original lane count/capacity"));
        }
        let first = values
            .first()
            .ok_or_else(|| invalid("missing actual QUIC lane"))?;
        let profiles = [
            first.profile(),
            values
                .get(1)
                .map_or(first.profile(), quic::Carrier::profile),
        ];
        if request.policy != quic::policy_digest(&profiles[..count]).map_err(quic_error)? {
            return Err(invalid(
                "actual QUIC policy differs from requested maintained carrier",
            ));
        }
        let mut lanes = [None, None];
        let mut expected = [None, None];
        for (index, value) in values.iter().enumerate() {
            let profile = value.profile();
            let valid_lane = match (request.duplex, index, profile.traffic) {
                (Duplex::Full, 0, l2tunnel_quic::Traffic::FullDuplex) => {
                    profile.lane == 0 && value.pair_binding().is_none()
                }
                (
                    Duplex::Half,
                    0,
                    l2tunnel_quic::Traffic::HalfDuplex {
                        sender: l2tunnel_auth::Direction::ClientToServer,
                    },
                ) => profile.lane == 0,
                (
                    Duplex::Half,
                    1,
                    l2tunnel_quic::Traffic::HalfDuplex {
                        sender: l2tunnel_auth::Direction::ServerToClient,
                    },
                ) => profile.lane == 1,
                _ => false,
            };
            if !valid_lane
                || value.setup_deadline() != first.setup_deadline()
                || value.final_records()
                || (request.duplex == Duplex::Half
                    && (value.pair_binding().is_none()
                        || value.pair_binding() != first.pair_binding()))
            {
                return Err(invalid("QUIC lane has no matching actual Full/Half proof"));
            }
            let actual = value.geometry();
            let geometry = Geometry {
                path_mtu: actual.path_mtu,
                max_record_bytes: actual.maximum_record_bytes,
                max_bootstrap_bytes: actual.maximum_bootstrap_bytes,
                charged_overhead_bytes: actual.ip_udp_bytes + actual.quic_allowance_bytes,
                bootstrap_overhead_bytes: actual.ip_udp_bytes + actual.quic_allowance_bytes + 48,
                framing_bytes: 0,
            };
            if geometry != request.geometry {
                return Err(invalid("actual QUIC geometry differs"));
            }
            let (local, peer) = value.addresses();
            lanes[index] = Some(Lane {
                info: *value.info(),
                local,
                peer,
            });
            expected[index] =
                Some(l2tunnel_quic::session_config(base, profile).map_err(quic_error)?);
        }
        let proof = Authenticated::checked(request, base, lanes, expected, first.setup_deadline())?;
        let capacity = Layout::array::<quic::Carrier>(values.capacity())
            .map_err(io::Error::other)?
            .size()
            .checked_add(std::mem::size_of::<Self>())
            .and_then(|value| {
                value.checked_add(request.geometry.max_record_bytes.checked_mul(count + 2)?)
            })
            .ok_or_else(exhausted)?;
        capacity_cap(capacity, maximum_capacity_bytes)?;
        Self::finish(Backend::Quic(values), proof, capacity, 1 + count + 2)
    }
    fn finish(
        backend: Backend,
        proof: Authenticated,
        capacity: usize,
        allocations: usize,
    ) -> io::Result<Self> {
        let owner = NEXT_OWNER
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                value.checked_add(1)
            })
            .map_err(|_| exhausted())?;
        Ok(Self {
            backend,
            proof,
            owner,
            next: Some(0),
            output: [None, None],
            input: [None, None],
            control_lane: 0,
            receive_lane: 0,
            final_records: false,
            capacity,
            allocations,
            failed: None,
        })
    }
    /// Actual verified proof; copying it never constructs an owner.
    pub fn authenticated(&self) -> Authenticated {
        self.proof
    }
    /// Immutable requested geometry verified against actual maintained owners.
    pub fn geometry(&self) -> Geometry {
        self.proof.requested().geometry
    }
    /// Original first-lane local/peer addresses; proof exposes both Half lanes.
    pub fn addresses(&self) -> (SocketAddr, SocketAddr) {
        match &self.backend {
            Backend::Tls(value) => value[0].addresses(),
            Backend::Quic(values) => values[0].addresses(),
        }
    }
    /// Accounted new adapter backing; maintained allocator metadata is separate.
    pub fn capacity_bytes(&self) -> usize {
        self.capacity
    }
    /// Bounded owned backing count; no complete maintained-allocator claim.
    pub fn allocations(&self) -> usize {
        self.allocations
    }
    /// Original absolute setup deadline retained through every handoff.
    pub fn setup_deadline(&self) -> Instant {
        self.proof.deadline()
    }
    /// True only after explicit authenticated final-record handoff.
    pub fn final_records(&self) -> bool {
        self.final_records
    }
    /// Earliest immutable partial/queued I/O deadline, never a renewed timeout.
    pub fn next_deadline(&self) -> Option<Instant> {
        let pending = self
            .output
            .iter()
            .flatten()
            .filter(|value| value.result.is_none())
            .map(|value| match &value.pending {
                Pending::Tls(token) => token.deadline(),
                Pending::Quic(token) => token.deadline(),
            })
            .min();
        let inner = match &self.backend {
            Backend::Tls(value) => value[0].next_deadline(),
            Backend::Quic(_) => None,
        };
        pending.into_iter().chain(inner).min()
    }
    /// Earliest completed untrusted input observation, only for causal deferral.
    /// Authentication, replay and liveness remain owned by the inner Records.
    pub fn earliest_input_at(&self) -> Option<Instant> {
        let cached = self
            .input
            .iter()
            .flatten()
            .map(|value| value.received_at)
            .min();
        let inner = match &self.backend {
            Backend::Tls(value) => value[0].earliest_input_at(),
            Backend::Quic(_) => None,
        };
        cached.into_iter().chain(inner).min()
    }
    /// Whether a complete bounded input is already retained by this owner.
    pub fn receive_ready(&self) -> bool {
        self.input.iter().any(Option::is_some)
            || match &self.backend {
                Backend::Tls(value) => value[0].receive_ready(),
                Backend::Quic(_) => false,
            }
    }
    /// First terminal maintained failure, without destroying saved completions.
    pub fn check_failure(&self) -> io::Result<()> {
        if let Some(error) = &self.failed {
            return Err(copy_error(error));
        }
        match &self.backend {
            Backend::Tls(value) => value[0].check_failure(),
            Backend::Quic(values) => {
                for value in values {
                    value.check_failure().map_err(quic_error)?;
                }
                Ok(())
            }
        }
    }
    /// Enable final records after the caller installed its authenticated Common owner.
    pub fn select_final_records(&mut self, original_deadline: Instant) -> io::Result<()> {
        self.check_failure()?;
        if self.final_records || original_deadline != self.setup_deadline() {
            return Err(invalid("maintained final handoff original deadline"));
        }
        if Instant::now() >= original_deadline {
            return Err(io::ErrorKind::TimedOut.into());
        }
        if let Backend::Quic(values) = &mut self.backend {
            for value in values {
                value
                    .select_final_records(original_deadline)
                    .map_err(quic_error)?;
            }
        }
        self.final_records = true;
        Ok(())
    }
    /// Reserve one independent User/Control slot without rebuilding pending bytes.
    pub fn try_send(
        &mut self,
        class: Class,
        bytes: &[u8],
        deadline: Instant,
        framing: Framing,
    ) -> io::Result<PendingSend> {
        self.check_failure()?;
        self.geometry()
            .charge(bytes.len(), framing == Framing::Bootstrap)?;
        if framing == Framing::Final && !self.final_records {
            return Err(invalid("maintained final records not selected"));
        }
        if self.output[class.index()].is_some() {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        let serial = self.next.ok_or_else(exhausted)?;
        let control_lane = self.control_lane;
        let server = self.proof.info()?.peer_member.is_some();
        let (pending, lane, effective) = match &mut self.backend {
            Backend::Tls(value) => {
                let token =
                    value[0].try_send(tls_class(class), bytes, deadline, tls_framing(framing))?;
                let effective = token.operation_deadline();
                (Pending::Tls(token), 0, effective)
            }
            Backend::Quic(values) => {
                let lane = if class == Class::Control {
                    control_lane
                } else {
                    usize::from(values.len() == 2 && server)
                };
                let token = values[lane]
                    .try_send(quic_class(class), bytes, deadline, quic_framing(framing))
                    .map_err(quic_error)?;
                let effective = token.deadline();
                (Pending::Quic(token), lane, effective)
            }
        };
        self.next = serial.checked_add(1);
        self.output[class.index()] = Some(Output {
            serial,
            lane,
            framing,
            pending,
            result: None,
        });
        if class == Class::Control {
            self.control_lane = (control_lane + 1) % self.lane_count();
        }
        Ok(PendingSend {
            owner: self.owner,
            serial,
            class,
            deadline: effective,
            bytes: bytes.len(),
            consumed: false,
        })
    }
    fn lane_count(&self) -> usize {
        if self.proof.requested().duplex == Duplex::Half {
            2
        } else {
            1
        }
    }
    /// Service existing pending operations and original reliable lifecycle monitors.
    pub fn poll_progress(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let geometry = self.geometry();
        let mut progress = false;
        for output in self.output.iter_mut().flatten() {
            if output.result.is_some() {
                continue;
            }
            let ready = match (&mut self.backend, &mut output.pending) {
                (Backend::Tls(adapter), Pending::Tls(token)) => {
                    match adapter[0].poll_send(cx, token) {
                        Poll::Pending => None,
                        Poll::Ready(result) => {
                            Some(result.map_err(SendFailure::Io).and_then(|value| {
                                let charged = geometry
                                    .charge(
                                        value.record_bytes,
                                        output.framing == Framing::Bootstrap,
                                    )
                                    .map_err(SendFailure::Io)?;
                                let receipt = Receipt {
                                    record_bytes: value.record_bytes,
                                    framed_bytes: value.framed_bytes,
                                    charged_bytes: charged,
                                    accepted_at: value.flushed_at,
                                    deadline: value.operation_deadline,
                                    late: value.late,
                                    boundary: crate::secure_udp::SendBoundary::TlsStreamFlushed,
                                    lane: value.lane,
                                };
                                if value.late {
                                    Err(SendFailure::Expired {
                                        accepted: Some(receipt),
                                    })
                                } else {
                                    Ok(receipt)
                                }
                            }))
                        }
                    }
                }
                (Backend::Quic(_), Pending::Quic(token)) => match Pin::new(token).poll(cx) {
                    Poll::Pending => None,
                    Poll::Ready(value) => Some(map_quic_send(value, output.lane)),
                },
                _ => Some(Err(SendFailure::Ticket)),
            };
            if let Some(result) = ready {
                output.result = Some(result);
                progress = true;
            }
        }
        let mut failed = None;
        match &mut self.backend {
            Backend::Tls(value) => match value[0].poll_progress(cx) {
                Poll::Ready(Ok(())) => progress = true,
                Poll::Ready(Err(error)) => failed = Some(error),
                Poll::Pending => {}
            },
            Backend::Quic(values) => {
                for (lane, value) in values.iter_mut().enumerate() {
                    if let Poll::Ready(Err(error)) = value.poll_maintenance(cx) {
                        failed = Some(quic_error(error));
                    }
                    if self.input[lane].is_none() {
                        match value.poll_recv_framed(cx) {
                            Poll::Ready(Ok(received)) => {
                                self.input[lane] = Some(received);
                                progress = true;
                            }
                            Poll::Ready(Err(error)) => failed = Some(quic_error(error)),
                            Poll::Pending => {}
                        }
                    }
                }
            }
        }
        if self.failed.is_none() {
            self.failed = failed;
        }
        if let Some(error) = &self.failed {
            return Poll::Ready(Err(copy_error(error)));
        }
        if progress || self.receive_ready() {
            Poll::Ready(Ok(()))
        } else {
            Poll::Pending
        }
    }
    /// Complete the original move-only token, preserving late acceptance facts.
    pub fn poll_send(
        &mut self,
        cx: &mut Context<'_>,
        token: &mut PendingSend,
    ) -> Poll<Result<Receipt, SendFailure>> {
        let index = token.class.index();
        if token.owner != self.owner
            || token.consumed
            || self.output[index].as_ref().map(|value| value.serial) != Some(token.serial)
        {
            return Poll::Ready(Err(SendFailure::Ticket));
        }
        let _ = self.poll_progress(cx);
        if let Some(result) = self.output[index]
            .as_mut()
            .and_then(|value| value.result.take())
        {
            self.output[index] = None;
            token.consumed = true;
            return Poll::Ready(result);
        }
        if let Err(error) = self.check_failure() {
            self.output[index] = None;
            token.consumed = true;
            return Poll::Ready(Err(SendFailure::Io(error)));
        }
        Poll::Pending
    }
    /// Copy one complete record without changing any inner replay/liveness authority.
    pub fn poll_recv(
        &mut self,
        cx: &mut Context<'_>,
        output: &mut [u8],
    ) -> Poll<io::Result<Received>> {
        let _ = self.poll_progress(cx);
        if let Err(error) = self.check_failure() {
            return Poll::Ready(Err(error));
        }
        let received = if let Backend::Tls(value) = &mut self.backend {
            match value[0].poll_receive(cx, output) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Ready(Ok(value)) => Received {
                    bytes: value.bytes,
                    framing: match value.framing {
                        tls::Framing::Bootstrap => Framing::Bootstrap,
                        tls::Framing::Final => Framing::Final,
                    },
                    received_at: value.received_at,
                    lane: value.lane,
                },
            }
        } else {
            let Some(lane) = (0..self.lane_count())
                .map(|offset| (self.receive_lane + offset) % self.lane_count())
                .find(|&lane| self.input[lane].is_some())
            else {
                return Poll::Pending;
            };
            let value = self.input[lane]
                .as_ref()
                .ok_or_else(|| invalid("maintained input ownership"))?;
            if output.len() < value.bytes.len() {
                return Poll::Ready(Err(invalid("maintained receive output too small")));
            }
            let value = self.input[lane]
                .take()
                .ok_or_else(|| invalid("maintained input ownership"))?;
            output[..value.bytes.len()].copy_from_slice(&value.bytes);
            self.receive_lane = (lane + 1) % self.lane_count();
            Received {
                bytes: value.bytes.len(),
                framing: match value.framing {
                    quic::Framing::Bootstrap => Framing::Bootstrap,
                    quic::Framing::Final => Framing::Final,
                },
                received_at: value.received_at,
                lane,
            }
        };
        // This is a rejection-only physical-lane filter. The inner Records owner
        // remains the sole authority for authentication, replay and liveness.
        let wrong_data_lane = received.framing == Framing::Final
            && output
                .first()
                .is_some_and(|byte| (128..=191).contains(byte))
            && self.proof.requested().duplex == Duplex::Half
            && received.lane != usize::from(self.proof.info()?.peer_member.is_none());
        if wrong_data_lane
            || (received.framing == Framing::Final && !self.final_records)
            || (received.framing == Framing::Bootstrap && Instant::now() >= self.setup_deadline())
        {
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
        Poll::Ready(Ok(received))
    }
    /// Async setup send using the same sole pending owner and unchanged cap.
    pub async fn send(
        &mut self,
        class: Class,
        bytes: &[u8],
        deadline: Instant,
        framing: Framing,
    ) -> io::Result<Receipt> {
        let mut token = self.try_send(class, bytes, deadline, framing)?;
        let cap = token.deadline();
        let timer = sleep_until(cap);
        tokio::pin!(timer);
        poll_fn(|cx| {
            // Service exact original completions before observing expiry; a late
            // accepted record must remain a named receipt, never an unsent claim.
            if let Poll::Ready(result) = self.poll_send(cx, &mut token) {
                return Poll::Ready(result.map_err(send_error));
            }
            timer
                .as_mut()
                .reset(self.next_deadline().map_or(cap, |next| next.min(cap)));
            if timer.as_mut().poll(cx).is_ready() {
                if let Poll::Ready(result) = self.poll_send(cx, &mut token) {
                    return Poll::Ready(result.map_err(send_error));
                }
                if Instant::now() >= cap {
                    return Poll::Ready(Err(io::ErrorKind::TimedOut.into()));
                }
                cx.waker().wake_by_ref();
            }
            Poll::Pending
        })
        .await
    }
    /// Async setup receive; cancelling retains partial TLS input and original age.
    pub async fn recv(&mut self, output: &mut [u8], deadline: Instant) -> io::Result<Received> {
        let timer = sleep_until(deadline);
        tokio::pin!(timer);
        poll_fn(|cx| {
            if let Poll::Ready(result) = self.poll_recv(cx, output) {
                return Poll::Ready(result);
            }
            // A newly observed partial TLS prefix creates an earlier immutable
            // deadline even when the peer supplies no further readiness event.
            timer.as_mut().reset(
                self.next_deadline()
                    .map_or(deadline, |next| next.min(deadline)),
            );
            if timer.as_mut().poll(cx).is_ready() {
                if let Poll::Ready(result) = self.poll_recv(cx, output) {
                    return Poll::Ready(result);
                }
                if Instant::now() >= deadline {
                    return Poll::Ready(Err(io::ErrorKind::TimedOut.into()));
                }
                cx.waker().wake_by_ref();
            }
            Poll::Pending
        })
        .await
    }
}
fn capacity_cap(bytes: usize, maximum: usize) -> io::Result<()> {
    if bytes > maximum {
        Err(invalid("maintained adapter exceeds supplied capacity"))
    } else {
        Ok(())
    }
}
fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}
fn exhausted() -> io::Error {
    io::Error::other("maintained adapter capacity or identity exhausted")
}
fn copy_error(error: &io::Error) -> io::Error {
    io::Error::new(error.kind(), error.to_string())
}
fn quic_error(error: l2tunnel_quic::Error) -> io::Error {
    match error {
        l2tunnel_quic::Error::Io(error) => error,
        l2tunnel_quic::Error::TimedOut => io::ErrorKind::TimedOut.into(),
        error => io::Error::other(error),
    }
}
fn send_error(error: SendFailure) -> io::Error {
    match error {
        SendFailure::Io(error) => error,
        SendFailure::Expired { .. } => io::ErrorKind::TimedOut.into(),
        SendFailure::Ticket => invalid("maintained send ticket"),
    }
}
fn tls_class(value: Class) -> tls::Class {
    match value {
        Class::User => tls::Class::User,
        Class::Control => tls::Class::Control,
    }
}
fn quic_class(value: Class) -> quic::Class {
    match value {
        Class::User => quic::Class::User,
        Class::Control => quic::Class::Control,
    }
}
fn tls_framing(value: Framing) -> tls::Framing {
    match value {
        Framing::Bootstrap => tls::Framing::Bootstrap,
        Framing::Final => tls::Framing::Final,
    }
}
fn quic_framing(value: Framing) -> quic::Framing {
    match value {
        Framing::Bootstrap => quic::Framing::Bootstrap,
        Framing::Final => quic::Framing::Final,
    }
}
fn map_quic_send(
    value: Result<quic::SendReceipt, quic::SendFailure>,
    lane: usize,
) -> Result<Receipt, SendFailure> {
    let map = |value: quic::SendReceipt| Receipt {
        record_bytes: value.record_bytes,
        framed_bytes: value.carrier_bytes,
        charged_bytes: value.charged_bytes,
        accepted_at: value.accepted_at,
        deadline: value.deadline,
        late: value.accepted_at >= value.deadline,
        boundary: crate::secure_udp::SendBoundary::QuicDatagramAccepted,
        lane,
    };
    match value {
        Ok(value) => Ok(map(value)),
        Err(quic::SendFailure::Expired { accepted }) => Err(SendFailure::Expired {
            accepted: accepted.map(map),
        }),
        Err(quic::SendFailure::Transport(error)) => Err(SendFailure::Io(quic_error(error))),
        Err(quic::SendFailure::Consumed) => Err(SendFailure::Ticket),
    }
}

#[cfg(test)]
impl Drop for Carrier {
    fn drop(&mut self) {
        if std::env::var_os("L2TUNNEL_MAINTAINED_TRACE").is_none() {
            return;
        }
        if let Backend::Quic(values) = &self.backend {
            for (lane, value) in values.iter().enumerate() {
                eprintln!(
                    "MAINTAINED_QUIC_FINAL role={} lane={lane} session={:?} accepted={:?} quinn={:?}",
                    if value.info().peer_member.is_none() {
                        "client"
                    } else {
                        "server"
                    },
                    value.info().session_id,
                    value.acceptance_status(),
                    value.transport_statistics()
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use l2tunnel_auth::{MemberAllowlist, MemberKey};
    use l2tunnel_core::ConfigDigest;
    use l2tunnel_device::PacketLayer;
    use l2tunnel_quic::{self as transport, DatagramFormat, EndpointLimits, Profile};
    use std::time::Duration;
    type Failure = Box<dyn std::error::Error + Send + Sync>;

    async fn full() -> Result<(quic::Carrier, quic::Carrier, Request, SessionConfig), Failure> {
        let mut profile = Profile::new(*b"maintained-test1");
        profile.datagram_format = DatagramFormat::CommonCompact;
        profile.max_datagram_bytes = 1072;
        let base = SessionConfig {
            layer: PacketLayer::Ip,
            digest: ConfigDigest([82; 32]),
        };
        let cert = rcgen::generate_simple_self_signed(vec!["wrapper.test".to_owned()])?;
        let chain = vec![cert.cert.der().to_vec()];
        let limits = EndpointLimits::default();
        let client = transport::ClientEndpoint::bind(
            "127.0.0.1:0".parse()?,
            &transport::ClientConfig::from_der_roots(&chain, profile, limits)?,
        )?;
        let server = transport::ServerEndpoint::bind(
            "127.0.0.1:0".parse()?,
            &transport::ServerConfig::from_der(
                &chain,
                &cert.signing_key.serialize_der(),
                profile,
                limits,
            )?,
        )?;
        let key = MemberKey::from_pkcs8(&MemberKey::generate_pkcs8()?)?;
        let members = MemberAllowlist::new(&[key.public_key()])?;
        let (a, b) = tokio::try_join!(
            client.connect(server.local_addr()?, "wrapper.test", &key, base),
            server.accept(&members, base)
        )?;
        let deadline = Instant::now() + Duration::from_secs(4);
        let request = Request {
            kind: Kind::QuicDatagram,
            duplex: Duplex::Full,
            geometry: Geometry {
                path_mtu: 1228,
                max_record_bytes: 1072,
                max_bootstrap_bytes: 1024,
                charged_overhead_bytes: 156,
                bootstrap_overhead_bytes: 204,
                framing_bytes: 0,
            },
            policy: quic::policy_digest(&[profile])?,
        };
        Ok((
            quic::Carrier::new(a, profile, base, deadline)?,
            quic::Carrier::new(b, profile, base, deadline)?,
            request,
            base,
        ))
    }
    #[tokio::test]
    async fn wrapper_checks_actual_policy_capacity_and_retains_named_quic_custody()
    -> Result<(), Failure> {
        let (a, b, request, base) = full().await?;
        assert!(Carrier::quic(vec![a], request, base, 0).is_err());
        let mut wrong = request;
        wrong.policy.0[0] ^= 1;
        assert!(Carrier::quic(vec![b], wrong, base, usize::MAX).is_err());
        let (a, b, request, base) = full().await?;
        let mut a = Carrier::quic(vec![a], request, base, 1_000_000)?;
        let mut b = Carrier::quic(vec![b], request, base, 1_000_000)?;
        assert_eq!(a.authenticated().binding(), b.authenticated().binding());
        assert_eq!(a.authenticated().common_configuration(), base);
        let cap = a.setup_deadline();
        let input = [0x80; 9];
        let receipt = a
            .send(Class::Control, &input, cap, Framing::Bootstrap)
            .await?;
        assert_eq!(
            receipt.boundary,
            crate::secure_udp::SendBoundary::QuicDatagramAccepted
        );
        assert_eq!(receipt.framed_bytes, 57);
        assert_eq!(receipt.charged_bytes, 213);
        let mut output = [0; 1072];
        assert_eq!(b.recv(&mut output, cap).await?.framing, Framing::Bootstrap);
        a.select_final_records(cap)?;
        b.select_final_records(cap)?;
        let mut token = a.try_send(Class::User, &input, cap, Framing::Final)?;
        let mut control = a.try_send(Class::Control, &input, cap, Framing::Final)?;
        assert!(
            matches!(a.try_send(Class::User,&input,cap,Framing::Final),Err(error) if error.kind()==io::ErrorKind::WouldBlock)
        );
        assert!(matches!(
            poll_fn(|cx| b.poll_send(cx, &mut token)).await,
            Err(SendFailure::Ticket)
        ));
        let receipt = poll_fn(|cx| a.poll_send(cx, &mut token)).await?;
        assert_eq!(receipt.record_bytes, 9);
        assert_eq!(receipt.framed_bytes, 9);
        assert_eq!(receipt.charged_bytes, 165);
        assert!(matches!(
            poll_fn(|cx| a.poll_send(cx, &mut token)).await,
            Err(SendFailure::Ticket)
        ));
        poll_fn(|cx| a.poll_send(cx, &mut control)).await?;
        assert_eq!(b.recv(&mut output, cap).await?.framing, Framing::Final);
        assert_eq!(&output[..9], &input);
        assert_eq!(b.recv(&mut output, cap).await?.framing, Framing::Final);
        Ok(())
    }
    #[tokio::test(start_paused = true)]
    async fn synthetic_tls_setup_helper_wakes_at_original_partial_input_deadline()
    -> Result<(), Failure> {
        use tokio::io::AsyncWriteExt;
        // Only this private test constructs synthetic framing custody. Public
        // factories continue requiring actual member-authenticated TLS owners.
        let (adapter, mut peer) = tls::test_framing_adapter(16)?;
        let info = adapter.info();
        let base = info.first.session.config;
        let request = Request {
            kind: Kind::TlsStream,
            duplex: Duplex::Full,
            geometry: Geometry {
                path_mtu: 1500,
                max_record_bytes: 1024,
                max_bootstrap_bytes: 1024,
                charged_overhead_bytes: 69,
                bootstrap_overhead_bytes: 69,
                framing_bytes: 5,
            },
            policy: adapter.policy_digest()?,
        };
        let proof = Authenticated::checked(
            request,
            base,
            [
                Some(Lane {
                    info: info.first.session,
                    local: info.first.local_addr,
                    peer: info.first.peer_addr,
                }),
                None,
            ],
            [Some(base), None],
            adapter.setup_deadline(),
        )?;
        let mut carrier = Carrier::finish(Backend::Tls(vec![adapter]), proof, 0, 0)?;
        let start = Instant::now();
        peer.write_all(&[0]).await?;
        let error = carrier
            .recv(&mut [0; 1024], start + Duration::from_secs(5))
            .await
            .err()
            .ok_or_else(|| {
                io::Error::other("stalled prefix must expire under its original one-second cap")
            })?;
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert_eq!(Instant::now() - start, Duration::from_secs(1));
        assert!(carrier.earliest_input_at().is_none());
        assert_eq!(
            carrier.check_failure().err().map(|error| error.kind()),
            Some(io::ErrorKind::TimedOut)
        );
        Ok(())
    }
}
