//! Actual original-datagram custody for the existing sole runtime loop.
use super::maintained_carrier::MaintainedIo;
use super::raw_carrier::{NoRaw, RawBacking};
use super::*;
use crate::secure_udp::original_datagram::{
    OriginalDatagram, PendingSend, SendClass, SendFailure, SendReceipt,
};
use std::{
    alloc::Layout,
    task::{Context, Poll},
};

pub(in crate::secure_udp) use super::raw_carrier::{AcceptedReceipt, SendProgress, UserIdentity};

/// Actual framing fact retained by the outer owner, not inferred from payload.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum InputFraming {
    Bootstrap,
    Final,
}
impl From<l2tunnel_openvpn::wire_carrier::common::ReceiveFraming> for InputFraming {
    fn from(value: l2tunnel_openvpn::wire_carrier::common::ReceiveFraming) -> Self {
        match value {
            l2tunnel_openvpn::wire_carrier::common::ReceiveFraming::DataV1 => Self::Bootstrap,
            l2tunnel_openvpn::wire_carrier::common::ReceiveFraming::Final => Self::Final,
        }
    }
}

struct Pending {
    ticket: Option<PendingSend>,
    result: Option<Result<SendReceipt, SendFailure>>,
    deadline: Instant,
}
struct User {
    identity: UserIdentity,
    pending: Pending,
}
struct Control {
    bytes: usize,
    bootstrap: bool,
    cost: usize,
    pending: Pending,
}
pub(super) struct CarrierIo {
    datagram: OriginalDatagram,
    control_bytes: Vec<u8>,
    input: Vec<u8>,
    input_length: Option<usize>,
    input_framing: Option<InputFraming>,
    user: Option<User>,
    control: Option<Control>,
}
/// Exact new adapter backing only; nested TLS/actor resources remain separate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct Plan {
    maximum: usize,
    capacity: usize,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct Usage {
    pub(super) capacity_bytes: usize,
    pub(super) allocations: usize,
}
impl Plan {
    pub(super) fn for_original(datagram: &OriginalDatagram) -> io::Result<Self> {
        let geometry = datagram.geometry();
        geometry.full_ip_bytes(geometry.max_datagram_bytes)?;
        let maximum = geometry.max_datagram_bytes;
        let input = maximum.checked_add(1).ok_or_else(exhausted)?;
        let capacity = Layout::array::<CarrierIo>(1)
            .map_err(invalid)?
            .size()
            .checked_add(std::mem::size_of::<IoOwner>())
            .ok_or_else(exhausted)?
            .checked_add(Layout::array::<u8>(maximum).map_err(invalid)?.size())
            .and_then(|v| v.checked_add(input))
            .ok_or_else(exhausted)?;
        Ok(Self { maximum, capacity })
    }
    pub(super) fn capacity_bytes(self) -> usize {
        self.capacity
    }
}
/// Sole real socket owner. Carrier-only backing does not enlarge bare-UDP frames.
pub(super) enum IoOwner<R: RawBacking = NoRaw> {
    Udp(tokio::net::UdpSocket),
    Carrier(Vec<CarrierIo>),
    Raw(Vec<R>),
    Maintained(Vec<MaintainedIo>),
}
impl From<tokio::net::UdpSocket> for IoOwner {
    fn from(socket: tokio::net::UdpSocket) -> Self {
        Self::Udp(socket)
    }
}
impl IoOwner {
    pub(super) fn from_maintained(
        carrier: crate::secure_udp::maintained_io::Carrier,
    ) -> io::Result<Self> {
        MaintainedIo::new(carrier).map(Self::Maintained)
    }
    pub(super) fn from_original(datagram: OriginalDatagram) -> io::Result<Self> {
        if datagram.outer_info().is_none()
            || datagram.geometry().extra_wire_bytes != usize::from(!datagram.final_records())
        {
            return Err(invalid(
                "selected carrier requires the actual opaque outer owner",
            ));
        }
        let plan = Plan::for_original(&datagram)?;
        let mut values = Vec::new();
        values.try_reserve_exact(1).map_err(io::Error::other)?;
        if values.capacity() != 1 {
            return Err(protocol("carrier singleton capacity differs"));
        }
        let control_bytes = buffer(plan.maximum)?;
        let input = buffer(plan.maximum.checked_add(1).ok_or_else(exhausted)?)?;
        values.push(CarrierIo {
            datagram,
            control_bytes,
            input,
            input_length: None,
            input_framing: None,
            user: None,
            control: None,
        });
        let result = Self::Carrier(values);
        if result.adapter_capacity_bytes()? != plan.capacity_bytes() {
            return Err(protocol("actual carrier adapter capacity differs"));
        }
        Ok(result)
    }
}
impl<R: RawBacking> IoOwner<R> {
    pub(super) fn from_raw(raw: R) -> io::Result<Self> {
        let mut values = Vec::new();
        values.try_reserve_exact(1).map_err(io::Error::other)?;
        if values.capacity() != 1 {
            return Err(protocol("raw singleton capacity differs"));
        }
        values.push(raw);
        Ok(Self::Raw(values))
    }
    pub(super) fn begin_turn(&mut self) {
        if let Self::Raw(values) = self {
            values[0].begin_turn();
        }
    }
    pub(super) fn check_physical_failure(&self) -> io::Result<()> {
        match self {
            Self::Raw(values) => values[0].check_failure(),
            Self::Maintained(values) => values[0].check_failure(),
            _ => Ok(()),
        }
    }
    fn check_retained_physical_failure(&self) -> io::Result<()> {
        match self {
            Self::Maintained(values) => values[0].check_retained_failure(),
            _ => self.check_physical_failure(),
        }
    }
    pub(super) fn physical_wake(&self) -> io::Result<Option<Instant>> {
        match self {
            Self::Raw(values) => values[0].next_wake().map(Some),
            Self::Maintained(values) => Ok(values[0].next_deadline()),
            _ => Ok(None),
        }
    }
    pub(super) fn adapter_capacity_bytes(&self) -> io::Result<usize> {
        match self {
            Self::Udp(_) => Ok(0),
            Self::Maintained(values) => values[0].usage().map(|usage| usage.capacity_bytes),
            Self::Raw(values) => values
                .first()
                .ok_or_else(|| protocol("missing raw singleton"))?
                .capacity_bytes()?
                .checked_add(std::mem::size_of::<Self>())
                .ok_or_else(exhausted),
            Self::Carrier(values) => {
                let value = values
                    .first()
                    .ok_or_else(|| protocol("missing carrier singleton"))?;
                Layout::array::<CarrierIo>(values.capacity())
                    .map_err(invalid)?
                    .size()
                    .checked_add(std::mem::size_of::<IoOwner>())
                    .ok_or_else(exhausted)?
                    .checked_add(value.control_bytes.capacity())
                    .and_then(|v| v.checked_add(value.input.capacity()))
                    .ok_or_else(exhausted)
            }
        }
    }
    pub(super) fn adapter_usage(&self) -> io::Result<Usage> {
        Ok(Usage {
            capacity_bytes: self.adapter_capacity_bytes()?,
            allocations: match self {
                Self::Udp(_) => 0,
                Self::Maintained(values) => values[0].usage()?.allocations,
                Self::Carrier(_) => 3,
                Self::Raw(values) => values[0].allocations(),
            },
        })
    }

    pub(super) fn addresses(&self) -> io::Result<(std::net::SocketAddr, std::net::SocketAddr)> {
        match self {
            Self::Udp(socket) => Ok((socket.local_addr()?, socket.peer_addr()?)),
            Self::Carrier(values) => Ok(values[0].datagram.addresses()),
            Self::Raw(values) => Ok(values[0].addresses()),
            Self::Maintained(values) => Ok(values[0].addresses()),
        }
    }
    pub(super) fn extra_wire_bytes(&self) -> usize {
        match self {
            Self::Udp(_) | Self::Raw(_) | Self::Maintained(_) => 0,
            Self::Carrier(values) => values[0].datagram.geometry().extra_wire_bytes,
        }
    }
    pub(super) fn ip_wire_bytes(&self) -> io::Result<usize> {
        match self {
            Self::Udp(socket) => Ok(if socket.local_addr()?.is_ipv6() {
                48
            } else {
                28
            }),
            Self::Maintained(values) => Ok(values[0].geometry().charged_overhead_bytes),
            Self::Raw(values) => values[0]
                .geometry()
                .ip_tcp_bytes
                .checked_add(values[0].geometry().record_overhead_bytes)
                .ok_or_else(exhausted),
            Self::Carrier(values) => {
                let geometry = values[0].datagram.geometry();
                geometry
                    .ip_udp_bytes
                    .checked_add(geometry.extra_wire_bytes)
                    .ok_or_else(exhausted)
            }
        }
    }
    pub(super) fn maximum_datagram_bytes(&self) -> Option<usize> {
        match self {
            Self::Udp(_) => None,
            Self::Raw(values) => Some(values[0].geometry().max_record_bytes),
            Self::Maintained(values) => Some(values[0].geometry().max_record_bytes),
            Self::Carrier(values) => Some(values[0].datagram.geometry().max_datagram_bytes),
        }
    }
    pub(super) fn is_raw(&self) -> bool {
        matches!(self, Self::Raw(_))
    }
    pub(super) fn is_maintained(&self) -> bool {
        matches!(self, Self::Maintained(_))
    }
    #[cfg(unix)]
    pub(super) fn retained_peer_close(&self, error: &io::Error) -> bool {
        match self {
            Self::Maintained(values) => values[0].retained_peer_close(error),
            _ => false,
        }
    }
    pub(super) fn is_carrier(&self) -> bool {
        !matches!(self, Self::Udp(_))
    }
    pub(super) fn user_pending(&self) -> bool {
        match self {
            Self::Udp(_) => false,
            Self::Carrier(values) => values[0]
                .user
                .as_ref()
                .is_some_and(|u| u.pending.result.is_none()),
            Self::Raw(values) => values[0].user_pending(),
            Self::Maintained(values) => values[0].user_pending(),
        }
    }

    fn user_precedes_control(&self) -> bool {
        match self {
            Self::Raw(values) => values[0].user_precedes_control(),
            _ => false,
        }
    }

    pub(super) fn control_pending(&self) -> bool {
        match self {
            Self::Udp(_) => false,
            Self::Carrier(values) => values[0].control.is_some(),
            Self::Raw(values) => values[0].control_pending(),
            Self::Maintained(values) => values[0].control_pending(),
        }
    }

    pub(super) fn receive_ready(&self) -> bool {
        match self {
            Self::Udp(_) => true,
            Self::Raw(values) => values[0].receive_ready(),
            Self::Maintained(values) => values[0].receive_ready(),
            Self::Carrier(values) => values[0].input_length.is_some(),
        }
    }
    pub(super) fn deadline(&self) -> Option<Instant> {
        match self {
            Self::Udp(_) => None,
            Self::Raw(values) => values[0].deadline(),
            Self::Maintained(values) => values[0].next_deadline(),
            Self::Carrier(values) => {
                let value = &values[0];
                value
                    .user
                    .as_ref()
                    .map(|u| u.pending.deadline)
                    .into_iter()
                    .chain(value.control.as_ref().map(|c| c.pending.deadline))
                    .chain(value.datagram.expires())
                    .min()
            }
        }
    }
    pub(super) fn admission_wake(&self, now: Instant) -> Option<Instant> {
        match self {
            Self::Udp(_) | Self::Raw(_) => None,
            Self::Maintained(values) => values[0].admission_wake(now),
            Self::Carrier(values) => {
                let value = &values[0];
                if value
                    .user
                    .as_ref()
                    .is_some_and(|u| u.pending.ticket.is_none() && u.pending.result.is_none())
                    || value
                        .control
                        .as_ref()
                        .is_some_and(|c| c.pending.ticket.is_none() && c.pending.result.is_none())
                {
                    now.checked_add(Duration::from_millis(1))
                        .map(|at| self.deadline().map_or(at, |cap| at.min(cap)))
                } else {
                    None
                }
            }
        }
    }
    pub(super) fn try_user(
        &mut self,
        identity: UserIdentity,
        bytes: &[u8],
    ) -> io::Result<SendProgress> {
        self.try_user_inner(identity, bytes, false)
    }
    pub(super) fn try_user_held(
        &mut self,
        identity: UserIdentity,
        bytes: &[u8],
    ) -> io::Result<SendProgress> {
        self.try_user_inner(identity, bytes, true)
    }
    fn try_user_inner(
        &mut self,
        identity: UserIdentity,
        bytes: &[u8],
        hold: bool,
    ) -> io::Result<SendProgress> {
        match self {
            Self::Udp(socket) => udp_write(socket, bytes, identity.deadline),
            Self::Maintained(values) => values[0].try_user(identity, bytes, hold),
            Self::Raw(values) => {
                if hold {
                    values[0].try_user_held(identity, bytes)
                } else {
                    values[0].try_user(identity, bytes)
                }
            }
            Self::Carrier(values) => {
                let value = &mut values[0];
                if bytes.len() != identity.bytes {
                    return Err(protocol("carrier user length differs"));
                }
                if let Some(user) = &value.user {
                    if user.identity != identity {
                        return Err(protocol("carrier user identity changed while pending"));
                    }
                } else {
                    value.datagram.geometry().full_ip_bytes(bytes.len())?;
                    value.user = Some(User {
                        identity,
                        pending: Pending {
                            ticket: None,
                            result: None,
                            deadline: identity.deadline,
                        },
                    });
                }
                let user = value
                    .user
                    .as_mut()
                    .ok_or_else(|| protocol("missing user custody"))?;
                begin(&value.datagram, &mut user.pending, SendClass::User, bytes)?;
                if hold {
                    return Ok(SendProgress::Pending);
                }
                if let Some(result) = user.pending.result.take() {
                    value.user = None;
                    complete(result)
                } else {
                    Ok(SendProgress::Pending)
                }
            }
        }
    }
    pub(super) fn user_accepted_at(&self) -> Option<Instant> {
        match self {
            Self::Udp(_) => None,
            Self::Raw(values) => values[0].user_accepted_at(),
            Self::Maintained(values) => values[0].user_accepted_at(),
            Self::Carrier(values) => values[0]
                .user
                .as_ref()
                .and_then(|u| u.pending.result.as_ref())
                .and_then(|r| match r {
                    Ok(receipt)
                    | Err(SendFailure::Expired {
                        accepted: Some(receipt),
                    }) => Some(receipt.accepted_at),
                    _ => None,
                }),
        }
    }
    pub(super) fn input_for_ordering_before(&self, accepted: Instant) -> io::Result<bool> {
        match self {
            Self::Raw(values) => Ok(values[0]
                .earliest_input_for_ordering_at()?
                .is_some_and(|at| at <= accepted)),
            Self::Maintained(values) => Ok(values[0]
                .earliest_input_at()
                .is_some_and(|at| at <= accepted)),
            // OpenVPN payloads have not passed Records yet. Their inner
            // authenticated observation is assigned at the sole opener, not
            // inferred from an unobservable OS/network queue timestamp.
            Self::Udp(_) | Self::Carrier(_) => Ok(false),
        }
    }
    pub(super) fn final_raw_mut(&mut self) -> Option<&mut R> {
        match self {
            Self::Raw(values) if values[0].geometry().record_overhead_bytes == 0 => {
                Some(&mut values[0])
            }
            _ => None,
        }
    }
    #[cfg(test)]
    pub(super) fn stage_control(
        &mut self,
        bytes: &[u8],
        cost: usize,
        deadline: Instant,
    ) -> io::Result<SendProgress> {
        self.stage_control_with_bootstrap(bytes, cost, deadline, false)
    }
    fn stage_control_with_bootstrap(
        &mut self,
        bytes: &[u8],
        cost: usize,
        deadline: Instant,
        bootstrap: bool,
    ) -> io::Result<SendProgress> {
        match self {
            Self::Udp(socket) => udp_write(socket, bytes, deadline),
            Self::Raw(values) => values[0].stage_control(bytes, cost, deadline, bootstrap),
            Self::Maintained(values) => values[0].stage_control(bytes, cost, deadline, bootstrap),
            Self::Carrier(values) => {
                let value = &mut values[0];
                if value.control.is_some() {
                    return Err(protocol("carrier Control slot already retained"));
                }
                let actual = if bootstrap {
                    value.datagram.bootstrap_ip_bytes(bytes.len())?
                } else {
                    value.datagram.geometry().full_ip_bytes(bytes.len())?
                };
                if actual != cost {
                    return Err(protocol("carrier Control full-IP charge differs"));
                }
                let target = value
                    .control_bytes
                    .get_mut(..bytes.len())
                    .ok_or_else(|| invalid("carrier Control capacity"))?;
                target.copy_from_slice(bytes);
                let mut pending = Pending {
                    ticket: None,
                    result: None,
                    deadline,
                };
                begin_selected(
                    &value.datagram,
                    &mut pending,
                    SendClass::Control,
                    bytes,
                    bootstrap,
                )?;
                value.control = Some(Control {
                    bytes: bytes.len(),
                    bootstrap,
                    cost,
                    pending,
                });
                Ok(SendProgress::Pending)
            }
        }
    }
    pub(super) fn take_control(&mut self) -> io::Result<Option<(SendProgress, usize)>> {
        if let Self::Raw(values) = self {
            return values[0].take_control();
        }
        if let Self::Maintained(values) = self {
            return values[0].take_control();
        }
        let Self::Carrier(values) = self else {
            return Ok(None);
        };
        let value = &mut values[0];
        let Some(control) = &mut value.control else {
            return Ok(None);
        };
        let Some(result) = control.pending.result.take() else {
            return Ok(None);
        };
        let cost = control.cost;
        value.control = None;
        complete(result).map(|progress| Some((progress, cost)))
    }
    pub(super) fn take_user(&mut self) -> io::Result<Option<(UserIdentity, SendProgress)>> {
        if let Self::Raw(values) = self {
            return values[0].take_user();
        }
        if let Self::Maintained(values) = self {
            return values[0].take_user();
        }
        let Self::Carrier(values) = self else {
            return Ok(None);
        };
        let value = &mut values[0];
        let Some(user) = &mut value.user else {
            return Ok(None);
        };
        let Some(result) = user.pending.result.take() else {
            return Ok(None);
        };
        let identity = user.identity;
        value.user = None;
        complete(result).map(|progress| Some((identity, progress)))
    }
    pub(super) fn final_input_metadata(&self) -> Option<raw_compact::FinalMetadata> {
        match self {
            Self::Raw(values) => values[0].final_input_metadata(),
            _ => None,
        }
    }
    pub(super) fn commit_final_input(
        &mut self,
        metadata: raw_compact::FinalMetadata,
        verdict: Option<raw_compact::FinalAcceptance<()>>,
    ) -> io::Result<()> {
        match self {
            Self::Raw(values) => values[0].commit_final_input(metadata, verdict),
            _ => Err(protocol("final raw candidate has no actual carrier owner")),
        }
    }
    pub(super) fn try_receive_at(
        &mut self,
        output: &mut [u8],
    ) -> io::Result<(usize, Option<Instant>, Option<InputFraming>)> {
        if let Self::Raw(values) = self {
            return values[0]
                .try_receive(output)
                .map(|(bytes, at)| (bytes, Some(at), None));
        }
        if let Self::Maintained(values) = self {
            return values[0].receive(output);
        }
        let bytes = self.try_receive(output)?;
        let framing = match self {
            Self::Carrier(values) => values[0].input_framing.take(),
            _ => None,
        };
        Ok((bytes, None, framing))
    }
    /// Promote at most one ready maintained input during the caller's bounded
    /// receive batch. Pending remains WouldBlock: this never waits for new input
    /// or consumes the separately retained send-completion receipts.
    pub(super) async fn try_receive_at_ready(
        &mut self,
        output: &mut [u8],
    ) -> io::Result<(usize, Option<Instant>, Option<InputFraming>)> {
        if let Self::Maintained(values) = self
            && !values[0].receive_ready()
        {
            std::future::poll_fn(|cx| {
                Poll::Ready(match values[0].poll_ready(cx, true) {
                    Poll::Ready(Err(error)) => Err(error),
                    Poll::Ready(Ok(())) | Poll::Pending => Ok(()),
                })
            })
            .await?;
        }
        self.try_receive_at(output)
    }
    pub(super) fn try_receive(&mut self, output: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::Udp(socket) => socket.try_recv(output),
            Self::Maintained(values) => values[0].receive(output).map(|(bytes, _, _)| bytes),
            Self::Raw(values) => values[0].try_receive(output).map(|(bytes, _)| bytes),
            Self::Carrier(values) => {
                let value = &mut values[0];
                let length = value.input_length.ok_or(io::ErrorKind::WouldBlock)?;
                if output.is_empty() {
                    return Err(invalid("empty carrier receive capacity"));
                }
                let copied = length.min(output.len());
                output[..copied].copy_from_slice(&value.input[..copied]);
                value.input_length = None;
                Ok(copied)
            }
        }
    }
    pub(super) async fn ready(&mut self, receive: bool) -> io::Result<()> {
        match self {
            Self::Udp(socket) if receive => socket.readable().await,
            Self::Udp(_) => std::future::pending().await,
            Self::Raw(values) => std::future::poll_fn(|cx| values[0].poll_ready(cx, receive)).await,
            Self::Maintained(values) => {
                std::future::poll_fn(|cx| values[0].poll_ready(cx, receive)).await
            }
            Self::Carrier(values) => {
                std::future::poll_fn(|cx| values[0].poll_ready(cx, receive)).await
            }
        }
    }
    pub(super) async fn observe_completions(&mut self) {
        if let Self::Maintained(values) = self {
            std::future::poll_fn(|cx| {
                let _ = values[0].poll_ready(cx, false);
                Poll::Ready(())
            })
            .await;
        }
        if let Self::Raw(values) = self {
            std::future::poll_fn(|cx| {
                let _ = values[0].poll_ready(cx, false);
                Poll::Ready(())
            })
            .await;
        }
        if let Self::Carrier(values) = self {
            std::future::poll_fn(|cx| {
                values[0].poll_pending(cx);
                Poll::Ready(())
            })
            .await;
        }
    }
}
impl CarrierIo {
    fn poll_pending(&mut self, cx: &mut Context<'_>) -> bool {
        let mut ready = false;
        if let Some(user) = &mut self.user {
            ready |= poll(&self.datagram, &mut user.pending, cx);
        }
        if let Some(control) = &mut self.control {
            if let Err(error) = begin_selected(
                &self.datagram,
                &mut control.pending,
                SendClass::Control,
                &self.control_bytes[..control.bytes],
                control.bootstrap,
            ) {
                control.pending.result = Some(Err(SendFailure::Io(error)));
            }
            ready |= poll(&self.datagram, &mut control.pending, cx);
        }
        ready
    }
    fn poll_ready(&mut self, cx: &mut Context<'_>, receive: bool) -> Poll<io::Result<()>> {
        let mut ready = self.poll_pending(cx);
        if ready {
            return Poll::Ready(Ok(()));
        }
        if receive {
            if self.input_length.is_some() {
                ready = true;
            } else {
                match self.datagram.poll_receive_framed(cx, &mut self.input) {
                    Poll::Pending => {}
                    Poll::Ready(Ok((length, framing))) => {
                        self.input_length = Some(length);
                        self.input_framing = framing.map(Into::into);
                        ready = true;
                    }
                    Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                }
            }
        }
        if ready {
            Poll::Ready(Ok(()))
        } else {
            Poll::Pending
        }
    }
}
fn begin(
    datagram: &OriginalDatagram,
    pending: &mut Pending,
    class: SendClass,
    bytes: &[u8],
) -> io::Result<()> {
    begin_selected(datagram, pending, class, bytes, false)
}
fn begin_selected(
    datagram: &OriginalDatagram,
    pending: &mut Pending,
    class: SendClass,
    bytes: &[u8],
    bootstrap: bool,
) -> io::Result<()> {
    if pending.ticket.is_none() && pending.result.is_none() {
        let result = if bootstrap {
            datagram.begin_bootstrap_send(class, bytes, pending.deadline)
        } else {
            datagram.begin_send(class, bytes, pending.deadline)
        };
        match result {
            Ok(ticket) => pending.ticket = Some(ticket),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}
fn poll(datagram: &OriginalDatagram, pending: &mut Pending, cx: &mut Context<'_>) -> bool {
    if pending.result.is_some() {
        return true;
    }
    if let Some(ticket) = &mut pending.ticket
        && let Poll::Ready(result) = datagram.poll_send(cx, ticket)
    {
        pending.result = Some(result);
        pending.ticket = None;
        return true;
    }
    false
}
fn complete(result: Result<SendReceipt, SendFailure>) -> io::Result<SendProgress> {
    match result {
        Ok(receipt) => Ok(SendProgress::Whole {
            receipt: receipt.into(),
            late: false,
        }),
        Err(SendFailure::Expired {
            accepted: Some(receipt),
        }) => Ok(SendProgress::Whole {
            receipt: receipt.into(),
            late: true,
        }),
        Err(error @ SendFailure::Expired { accepted: None }) => {
            Err(io::Error::new(io::ErrorKind::TimedOut, error))
        }
        Err(SendFailure::Io(error)) => Err(error),
        Err(SendFailure::Ticket) => Err(protocol("original carrier ticket refused")),
    }
}
fn udp_write(
    socket: &tokio::net::UdpSocket,
    bytes: &[u8],
    deadline: Instant,
) -> io::Result<SendProgress> {
    if Instant::now() >= deadline {
        return Err(io::ErrorKind::TimedOut.into());
    }
    let written = socket.try_send(bytes)?;
    if written != bytes.len() {
        return Err(io::Error::new(
            io::ErrorKind::WriteZero,
            "partial original UDP write",
        ));
    }
    let accepted_at = Instant::now();
    let overhead = if socket.local_addr()?.is_ipv6() {
        48
    } else {
        28
    };
    Ok(SendProgress::Whole {
        receipt: AcceptedReceipt {
            record_bytes: written,
            udp_bytes: Some(written),
            charged_bytes: written.checked_add(overhead).ok_or_else(exhausted)?,
            socket_ip_bytes: Some(written.checked_add(overhead).ok_or_else(exhausted)?),
            boundary: super::super::SendBoundary::SocketAccepted,
            accepted_at,
            deadline,
        },
        late: accepted_at >= deadline,
    })
}
fn buffer(bytes: usize) -> io::Result<Vec<u8>> {
    let mut result = Vec::new();
    result.try_reserve_exact(bytes).map_err(io::Error::other)?;
    if result.capacity() != bytes {
        return Err(protocol("carrier buffer capacity differs"));
    }
    result.resize(bytes, 0);
    Ok(result)
}

impl Driver {
    pub(super) fn complete_carrier_io<R: RawBacking>(
        &mut self,
        socket: &mut IoOwner<R>,
        mut sample: impl FnMut() -> Instant,
    ) -> io::Result<()> {
        self.complete_carrier_io_inner(socket, false, None, &mut sample)
    }
    pub(super) fn complete_carrier_io_terminal<R: RawBacking>(
        &mut self,
        socket: &mut IoOwner<R>,
        prior_error: Option<&io::Error>,
        mut sample: impl FnMut() -> Instant,
    ) -> io::Result<()> {
        self.complete_carrier_io_inner(socket, true, prior_error, &mut sample)
    }
    fn complete_carrier_io_inner<R: RawBacking>(
        &mut self,
        socket: &mut IoOwner<R>,
        terminal: bool,
        prior_error: Option<&io::Error>,
        mut sample: impl FnMut() -> Instant,
    ) -> io::Result<()> {
        // Both physical facts survive errors. Only the Research User receipt
        // may wait for older bounded raw candidates to reach Records verification.
        // Deferral grants no authentication, retirement, or liveness authority.
        let control = socket.take_control();
        let ordering = (|| -> io::Result<bool> {
            let Some(accepted) = socket.user_accepted_at() else {
                return Ok(false);
            };
            let pending = self.common.as_deref().and_then(|r| r.sealed.as_ref());
            let Some(pending) = pending else {
                return Ok(false);
            };
            let now = clock(self.origin, sample())?;
            if terminal
                || now >= pending.deadline
                || !self.research_physical_output(pending.scope)?
            {
                return Ok(false);
            }
            socket.input_for_ordering_before(accepted)
        })();
        let user = if ordering.as_ref().is_ok_and(|held| *held) {
            Ok(None)
        } else {
            socket.take_user()
        };
        let control = control.and_then(|value| {
            if let Some((SendProgress::Whole { receipt, late }, cost)) = value {
                self.observe_carrier_acceptance(receipt)?;
                if cost != receipt.charged_bytes
                    || receipt.udp_bytes.is_some_and(|bytes| {
                        bytes < receipt.record_bytes || bytes > receipt.charged_bytes
                    })
                {
                    return Err(protocol("carrier Control physical charge differs"));
                }
                let observed = sample();
                clock(self.origin, observed)?;
                if late || receipt.accepted_at >= receipt.deadline || observed >= receipt.deadline {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "whole Control write crossed original cap",
                    ));
                }
            }
            Ok(())
        });
        let user = user.and_then(|value| match value {
            Some((identity, SendProgress::Whole { receipt, late })) => self
                .complete_common_carrier(identity, receipt, late, &mut sample)
                .map(|_| ()),
            _ => Ok(()),
        });
        control?;
        user?;
        ordering?;
        let failure = if terminal {
            socket.check_retained_physical_failure()
        } else {
            socket.check_physical_failure()
        };
        if let Err(error) = failure {
            // Only the exact error already held by the caller may be excluded
            // from receipt settlement. A retained close must still defeat an
            // otherwise successful cancellation; newly sampled background
            // closures are excluded by the retained-only query above.
            #[cfg(unix)]
            let repeated_close = terminal
                && prior_error.is_some_and(|original| socket.retained_peer_close(original))
                && socket.retained_peer_close(&error);
            #[cfg(not(unix))]
            let repeated_close = {
                let _ = prior_error;
                false
            };
            if !repeated_close {
                return Err(error);
            }
        }
        let observed = sample();
        clock(self.origin, observed)?;
        if socket.deadline().is_some_and(|cap| observed >= cap) {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "original carrier custody/lifetime cap",
            ));
        }
        Ok(())
    }
    pub(super) fn send_selected_io_sampled<R: RawBacking>(
        &mut self,
        socket: &mut IoOwner<R>,
        now: u64,
        instant: Instant,
        mut sample: impl FnMut() -> Instant,
    ) -> io::Result<()> {
        if let IoOwner::Udp(socket) = socket {
            return if self.common.is_some() {
                self.send_sampled(socket, now, instant, sample)
            } else {
                self.send(socket, now, instant)
            };
        }
        if self.common.is_none() {
            return Err(invalid("carrier requires actual Common owner"));
        }
        self.performance.counters.send_calls =
            self.performance.counters.send_calls.saturating_add(1);
        self.performance.checked(now);
        for _ in 0..self.config.work.send_batch {
            let instant = sample().max(instant);
            let now = clock(self.origin, instant)?.max(now);
            if !self.check_expiry(now)? {
                break;
            }
            // Retry existing ciphertext before a new Control claims the same
            // raw Full slot. Independent Half lanes keep their usual priority.
            if socket.user_precedes_control() {
                if !self.send_common_carrier(socket, now, &mut sample)? {
                    break;
                }
                continue;
            }
            if !socket.control_pending() {
                if let Some((bytes, cap)) = self.tail_with_cap(instant)? {
                    self.stage_carrier_control(
                        socket,
                        bytes,
                        cap,
                        performance::WireKind::Bootstrap,
                    )?;
                    continue;
                }
                if self.outer == u32::MAX {
                    return Err(exhausted());
                }
                if socket.final_raw_mut().is_some() {
                    // A retained body gets the next available data extent before
                    // another fresh control occupies Full's sole lane. If the
                    // data horizon is closed, reserved strong controls still run.
                    if self.common.as_deref().is_some_and(|r| r.unsealed.is_some())
                        && (self.send_common_carrier(socket, now, &mut sample)?
                            || self.common.as_deref().is_some_and(|r| r.unsealed.is_none()))
                    {
                        continue;
                    }
                    if self.send_raw_services(socket, now)? {
                        continue;
                    }
                } else if let Some(bytes) = self.prepare_control(now)? {
                    let cap = self
                        .origin
                        .checked_add(self.control.expiry())
                        .ok_or_else(exhausted)?;
                    self.stage_carrier_control(socket, bytes, cap, performance::WireKind::Control)?;
                    continue;
                }
            }
            if !self.send_common_carrier(socket, now, &mut sample)? {
                break;
            }
        }
        Ok(())
    }
    pub(super) fn stage_carrier_control<R: RawBacking>(
        &mut self,
        socket: &mut IoOwner<R>,
        bytes: usize,
        cap: Instant,
        kind: performance::WireKind,
    ) -> io::Result<()> {
        let bootstrap = matches!(kind, performance::WireKind::Bootstrap);
        let physical = if bootstrap {
            self.bootstrap_ip_bytes()
        } else {
            self.ip
        };
        let cost = bytes.checked_add(physical).ok_or_else(exhausted)?;
        self.bucket.charge(cost)?;
        self.performance.sent(kind, cost);
        self.outer = self.outer.checked_add(1).ok_or_else(exhausted)?;
        self.counters.wire_packets = self.counters.wire_packets.saturating_add(1);
        self.counters.wire_bytes = self.counters.wire_bytes.saturating_add(cost as u64);
        match socket.stage_control_with_bootstrap(
            &self.buffers.wire[..bytes],
            cost,
            cap,
            bootstrap,
        )? {
            SendProgress::Pending => Ok(()),
            SendProgress::Whole { .. } => {
                Err(protocol("carrier Control unexpectedly bypassed ticket"))
            }
        }
    }
    pub(super) fn wake_selected_io<R: RawBacking>(
        &self,
        socket: &IoOwner<R>,
        now: u64,
    ) -> io::Result<Instant> {
        let mut wake = if socket.is_carrier() && self.common.is_some() {
            self.wake_common_with_custody(now, socket.user_pending(), socket.control_pending())?
        } else {
            self.wake(now)?
        };
        if let Some(cap) = socket.deadline() {
            wake = wake.min(cap);
        }
        if let Some(physical) = socket.physical_wake()? {
            wake = wake.min(physical);
        }
        if let Some(at) = socket.admission_wake(Instant::now()) {
            wake = wake.min(at);
        }
        Ok(wake)
    }
}

#[cfg(test)]
#[path = "transport_carrier_tests.rs"]
mod tests;

impl Driver {
    pub(super) fn observe_carrier_acceptance(
        &mut self,
        receipt: AcceptedReceipt,
    ) -> io::Result<()> {
        let expected = self
            .common
            .as_deref()
            .and_then(|runtime| runtime.contract.maintained_outer())
            .map_or(super::super::SendBoundary::SocketAccepted, |outer| {
                outer.requested().kind.send_boundary()
            });
        if receipt.boundary != expected
            || receipt.socket_ip_bytes.is_some()
                != (expected == super::super::SendBoundary::SocketAccepted)
        {
            return Err(protocol(
                "carrier receipt boundary differs from actual selected owner",
            ));
        }
        if let Some(bytes) = receipt.socket_ip_bytes {
            self.counters.socket_accepted_packets =
                self.counters.socket_accepted_packets.saturating_add(1);
            self.counters.socket_accepted_ip_bytes = self
                .counters
                .socket_accepted_ip_bytes
                .saturating_add(bytes as u64);
        } else {
            self.counters.maintained_accepted_records =
                self.counters.maintained_accepted_records.saturating_add(1);
            self.counters.maintained_accepted_record_bytes = self
                .counters
                .maintained_accepted_record_bytes
                .saturating_add(receipt.record_bytes as u64);
            self.counters.maintained_accepted_charge_bytes = self
                .counters
                .maintained_accepted_charge_bytes
                .saturating_add(receipt.charged_bytes as u64);
        }
        Ok(())
    }
}
