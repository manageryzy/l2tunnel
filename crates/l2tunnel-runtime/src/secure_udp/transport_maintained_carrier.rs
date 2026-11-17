//! Bounded maintained-carrier custody for the existing sole Common loop.
use super::carrier::{AcceptedReceipt, SendProgress, Usage, UserIdentity};
use super::*;
use crate::secure_udp::maintained_io::{self as wire, Carrier, Class, Framing};
use std::{
    alloc::Layout,
    task::{Context, Poll},
};

struct Pending {
    ticket: Option<wire::PendingSend>,
    result: Option<Result<wire::Receipt, wire::SendFailure>>,
    deadline: Instant,
}
struct User {
    identity: UserIdentity,
    pending: Pending,
}
struct Control {
    bytes: usize,
    cost: usize,
    framing: Framing,
    pending: Pending,
}

pub(super) struct MaintainedIo {
    carrier: Carrier,
    input: Vec<u8>,
    input_meta: Option<wire::Received>,
    control_bytes: Vec<u8>,
    user: Option<User>,
    control: Option<Control>,
}
impl MaintainedIo {
    pub(super) fn capacity_for(carrier: &Carrier) -> io::Result<usize> {
        carrier
            .capacity_bytes()
            .checked_sub(std::mem::size_of::<Carrier>())
            .and_then(|v| v.checked_add(std::mem::size_of::<Self>()))
            .and_then(|v| v.checked_add(std::mem::size_of::<super::carrier::IoOwner>()))
            .and_then(|v| {
                v.checked_add(
                    carrier
                        .geometry()
                        .max_record_bytes
                        .max(carrier.geometry().max_bootstrap_bytes)
                        .checked_mul(2)?,
                )
            })
            .ok_or_else(exhausted)
    }
    pub(super) fn new(carrier: Carrier) -> io::Result<Vec<Self>> {
        let maximum = carrier
            .geometry()
            .max_record_bytes
            .max(carrier.geometry().max_bootstrap_bytes);
        let mut values = Vec::new();
        values.try_reserve_exact(1).map_err(io::Error::other)?;
        if values.capacity() != 1 {
            return Err(protocol("maintained singleton capacity differs"));
        }
        values.push(Self {
            carrier,
            input: buffer(maximum)?,
            input_meta: None,
            control_bytes: buffer(maximum)?,
            user: None,
            control: None,
        });
        Ok(values)
    }
    pub(super) fn usage(&self) -> io::Result<Usage> {
        Ok(Usage {
            capacity_bytes: self
                .carrier
                .capacity_bytes()
                .checked_sub(std::mem::size_of::<Carrier>())
                .and_then(|v| v.checked_add(Layout::new::<Self>().size()))
                .and_then(|v| v.checked_add(std::mem::size_of::<super::carrier::IoOwner>()))
                .and_then(|v| v.checked_add(self.input.capacity()))
                .and_then(|v| v.checked_add(self.control_bytes.capacity()))
                .ok_or_else(exhausted)?,
            allocations: self
                .carrier
                .allocations()
                .checked_add(3)
                .ok_or_else(exhausted)?,
        })
    }
    pub(super) fn addresses(&self) -> (std::net::SocketAddr, std::net::SocketAddr) {
        self.carrier.addresses()
    }
    pub(super) fn geometry(&self) -> crate::secure_udp::maintained::Geometry {
        self.carrier.geometry()
    }
    pub(super) fn check_failure(&self) -> io::Result<()> {
        self.carrier.check_failure()
    }
    #[cfg(unix)]
    pub(super) fn retained_peer_close(&self, error: &io::Error) -> bool {
        let lower = self.carrier.retained_peer_close(error);
        let earliest = self.earliest_input_at();
        #[cfg(debug_assertions)]
        if std::env::var_os("L2TUNNEL_MEASURED_TRACE").is_some() {
            eprintln!(
                "MAINTAINED_CLOSE_CUSTODY user={} control={} input_meta={} earliest={earliest:?} lower={lower}",
                self.user.is_some(),
                self.control.is_some(),
                self.input_meta.is_some(),
            );
        }
        self.user.is_none()
            && self.control.is_none()
            && self.input_meta.is_none()
            && earliest.is_none()
            && lower
    }
    pub(super) fn next_deadline(&self) -> Option<Instant> {
        self.carrier
            .next_deadline()
            .into_iter()
            .chain(self.user.as_ref().map(|u| u.pending.deadline))
            .chain(self.control.as_ref().map(|c| c.pending.deadline))
            .min()
    }
    pub(super) fn user_pending(&self) -> bool {
        self.user
            .as_ref()
            .is_some_and(|u| u.pending.result.is_none())
    }
    pub(super) fn control_pending(&self) -> bool {
        self.control.is_some()
    }
    pub(super) fn receive_ready(&self) -> bool {
        self.input_meta.is_some()
    }
    pub(super) fn earliest_input_at(&self) -> Option<Instant> {
        self.input_meta
            .map(|value| value.received_at)
            .into_iter()
            .chain(self.carrier.earliest_input_at())
            .min()
    }
    pub(super) fn admission_wake(&self, now: Instant) -> Option<Instant> {
        let waiting = self
            .user
            .as_ref()
            .is_some_and(|u| u.pending.ticket.is_none() && u.pending.result.is_none())
            || self
                .control
                .as_ref()
                .is_some_and(|c| c.pending.ticket.is_none() && c.pending.result.is_none());
        if waiting {
            now.checked_add(Duration::from_millis(1))
                .map(|at| self.next_deadline().map_or(at, |cap| at.min(cap)))
        } else {
            None
        }
    }
    pub(super) fn try_user(
        &mut self,
        identity: UserIdentity,
        bytes: &[u8],
        hold: bool,
    ) -> io::Result<SendProgress> {
        if bytes.len() != identity.bytes {
            return Err(protocol("maintained User length differs"));
        }
        if let Some(user) = &self.user {
            if user.identity != identity {
                return Err(protocol("maintained User changed while pending"));
            }
        } else {
            self.carrier.geometry().charge(bytes.len(), false)?;
            self.user = Some(User {
                identity,
                pending: pending(identity.deadline),
            });
        }
        let user = self
            .user
            .as_mut()
            .ok_or_else(|| protocol("missing maintained User custody"))?;
        begin(
            &mut self.carrier,
            &mut user.pending,
            Class::User,
            bytes,
            Framing::Final,
        )?;
        if hold {
            return Ok(SendProgress::Pending);
        }
        if let Some(result) = user.pending.result.take() {
            self.user = None;
            complete(result)
        } else {
            Ok(SendProgress::Pending)
        }
    }
    pub(super) fn stage_control(
        &mut self,
        bytes: &[u8],
        cost: usize,
        deadline: Instant,
        bootstrap: bool,
    ) -> io::Result<SendProgress> {
        if self.control.is_some() {
            return Err(protocol("maintained Control slot already occupied"));
        }
        if self.carrier.geometry().charge(bytes.len(), bootstrap)? != cost {
            return Err(protocol("maintained Control admission charge differs"));
        }
        self.control_bytes
            .get_mut(..bytes.len())
            .ok_or_else(|| invalid("maintained Control capacity"))?
            .copy_from_slice(bytes);
        let framing = if bootstrap {
            Framing::Bootstrap
        } else {
            Framing::Final
        };
        let mut pending = pending(deadline);
        begin(
            &mut self.carrier,
            &mut pending,
            Class::Control,
            bytes,
            framing,
        )?;
        self.control = Some(Control {
            bytes: bytes.len(),
            cost,
            framing,
            pending,
        });
        Ok(SendProgress::Pending)
    }
    pub(super) fn take_control(&mut self) -> io::Result<Option<(SendProgress, usize)>> {
        let Some(control) = &mut self.control else {
            return Ok(None);
        };
        let Some(result) = control.pending.result.take() else {
            return Ok(None);
        };
        let cost = control.cost;
        self.control = None;
        complete(result).map(|progress| Some((progress, cost)))
    }
    pub(super) fn take_user(&mut self) -> io::Result<Option<(UserIdentity, SendProgress)>> {
        let Some(user) = &mut self.user else {
            return Ok(None);
        };
        let Some(result) = user.pending.result.take() else {
            return Ok(None);
        };
        let identity = user.identity;
        self.user = None;
        complete(result).map(|progress| Some((identity, progress)))
    }
    pub(super) fn user_accepted_at(&self) -> Option<Instant> {
        self.user
            .as_ref()
            .and_then(|u| u.pending.result.as_ref())
            .and_then(|r| match r {
                Ok(receipt)
                | Err(wire::SendFailure::Expired {
                    accepted: Some(receipt),
                }) => Some(receipt.accepted_at),
                _ => None,
            })
    }
    pub(super) fn receive(
        &mut self,
        out: &mut [u8],
    ) -> io::Result<(usize, Option<Instant>, Option<super::carrier::InputFraming>)> {
        let meta = self.input_meta.as_ref().ok_or(io::ErrorKind::WouldBlock)?;
        if meta.bytes > out.len() {
            return Err(invalid("maintained receive output too small"));
        }
        out[..meta.bytes].copy_from_slice(&self.input[..meta.bytes]);
        let meta = self
            .input_meta
            .take()
            .ok_or_else(|| protocol("missing maintained input metadata"))?;
        let framing = match meta.framing {
            Framing::Bootstrap => super::carrier::InputFraming::Bootstrap,
            Framing::Final => super::carrier::InputFraming::Final,
        };
        Ok((meta.bytes, Some(meta.received_at), Some(framing)))
    }
    pub(super) fn poll_ready(
        &mut self,
        cx: &mut Context<'_>,
        receive: bool,
    ) -> Poll<io::Result<()>> {
        let mut ready = false;
        if let Some(user) = &mut self.user {
            ready |= poll(&mut self.carrier, &mut user.pending, cx);
        }
        if let Some(control) = &mut self.control {
            if let Err(error) = begin(
                &mut self.carrier,
                &mut control.pending,
                Class::Control,
                &self.control_bytes[..control.bytes],
                control.framing,
            ) {
                control.pending.result = Some(Err(wire::SendFailure::Io(error)));
            }
            ready |= poll(&mut self.carrier, &mut control.pending, cx);
        }
        // Completed receipts must reach the Common owner even if the connection
        // became terminal in the same poll. Failure is checked after both slots.
        if let Poll::Ready(Err(error)) = self.carrier.poll_progress(cx) {
            return if ready {
                Poll::Ready(Ok(()))
            } else {
                Poll::Ready(Err(error))
            };
        }
        if receive && self.input_meta.is_none() {
            match self.carrier.poll_recv(cx, &mut self.input) {
                Poll::Ready(Ok(meta)) => self.input_meta = Some(meta),
                Poll::Ready(Err(error)) => {
                    return if ready {
                        Poll::Ready(Ok(()))
                    } else {
                        Poll::Ready(Err(error))
                    };
                }
                Poll::Pending => {}
            }
        }
        if ready || (receive && self.input_meta.is_some()) {
            Poll::Ready(Ok(()))
        } else {
            Poll::Pending
        }
    }
}
fn pending(deadline: Instant) -> Pending {
    Pending {
        ticket: None,
        result: None,
        deadline,
    }
}
fn begin(
    carrier: &mut Carrier,
    pending: &mut Pending,
    class: Class,
    bytes: &[u8],
    framing: Framing,
) -> io::Result<()> {
    if pending.ticket.is_none() && pending.result.is_none() {
        match carrier.try_send(class, bytes, pending.deadline, framing) {
            Ok(ticket) => pending.ticket = Some(ticket),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}
fn poll(carrier: &mut Carrier, pending: &mut Pending, cx: &mut Context<'_>) -> bool {
    if pending.result.is_some() {
        return true;
    }
    if let Some(ticket) = &mut pending.ticket
        && let Poll::Ready(result) = carrier.poll_send(cx, ticket)
    {
        pending.result = Some(result);
        pending.ticket = None;
        return true;
    }
    false
}
fn complete(result: Result<wire::Receipt, wire::SendFailure>) -> io::Result<SendProgress> {
    let receipt = match result {
        Ok(receipt)
        | Err(wire::SendFailure::Expired {
            accepted: Some(receipt),
        }) => receipt,
        Err(wire::SendFailure::Expired { accepted: None }) => {
            return Err(io::ErrorKind::TimedOut.into());
        }
        Err(wire::SendFailure::Io(error)) => return Err(error),
        Err(wire::SendFailure::Ticket) => return Err(protocol("maintained send ticket refused")),
    };
    Ok(SendProgress::Whole {
        receipt: AcceptedReceipt {
            record_bytes: receipt.record_bytes,
            udp_bytes: None,
            charged_bytes: receipt.charged_bytes,
            socket_ip_bytes: None,
            boundary: receipt.boundary,
            accepted_at: receipt.accepted_at,
            deadline: receipt.deadline,
        },
        late: receipt.late,
    })
}
fn buffer(size: usize) -> io::Result<Vec<u8>> {
    let mut out = Vec::new();
    out.try_reserve_exact(size).map_err(io::Error::other)?;
    if out.capacity() != size {
        return Err(protocol("maintained buffer capacity differs"));
    }
    out.resize(size, 0);
    Ok(out)
}
