//! Explicit original-socket send custody for UDP and raw OpenVPN substrates.
//!
//! This module does not construct Noise/member Parts or install a Common Driver.
//! An OpenVPN submission is pending until its existing actor reports a whole
//! physical write. Its outer admission ledger overlaps any inner policy ledger;
//! adding the two counters does not measure network bytes.

use l2tunnel_openvpn::wire_carrier::common as openvpn;
use std::{
    future::Future,
    io,
    net::SocketAddr,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    task::{Context, Poll},
};
use tokio::{
    io::ReadBuf,
    net::UdpSocket,
    sync::{OwnedSemaphorePermit, Semaphore},
    time::{Instant, timeout_at},
};

pub use openvpn::Class as SendClass;

static NEXT_OWNER: AtomicU64 = AtomicU64::new(1);

/// Exact physical datagram geometry for this already connected original socket.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Geometry {
    /// Complete IP-packet ceiling, including any OpenVPN DataV1 opcode.
    pub path_mtu: usize,
    /// Largest caller datagram before the outer carrier adds its opcode.
    pub max_datagram_bytes: usize,
    /// IP/UDP bytes: 28 for IPv4 or 48 for IPv6.
    pub ip_udp_bytes: usize,
    /// Additional selected carrier bytes: zero for UDP or one for raw DataV1.
    pub extra_wire_bytes: usize,
}
impl Geometry {
    /// Checked complete physical cost; no header is silently counted twice.
    pub fn full_ip_bytes(self, bytes: usize) -> io::Result<usize> {
        if bytes == 0 || bytes > self.max_datagram_bytes {
            return Err(invalid("original datagram length"));
        }
        bytes
            .checked_add(self.ip_udp_bytes)
            .and_then(|value| value.checked_add(self.extra_wire_bytes))
            .filter(|value| *value <= self.path_mtu)
            .ok_or_else(|| invalid("original datagram physical geometry"))
    }
}

/// One whole socket acceptance, never queue admission or peer delivery.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SendReceipt {
    /// Exact original caller datagram bytes.
    pub datagram_bytes: usize,
    /// Physical UDP payload bytes, including any outer opcode.
    pub udp_bytes: usize,
    /// Complete configured physical IP bytes.
    pub ip_bytes: usize,
    /// Actual post-write observation time.
    pub accepted_at: Instant,
    /// Immutable original cap, additionally bounded by an outer lifetime.
    pub deadline: Instant,
}
/// Physical facts survive a late result; no rollback or successful drain is implied.
#[derive(Debug)]
pub enum SendFailure {
    /// Original cap expired; preserve any observed whole write.
    Expired {
        /// Actual acceptance when a whole write crossed the cap.
        accepted: Option<SendReceipt>,
    },
    /// Local socket/carrier failure.
    Io(io::Error),
    /// Ticket was consumed or belongs to another actual socket owner.
    Ticket,
}
impl std::fmt::Display for SendFailure {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(out, "original datagram send: {self:?}")
    }
}
impl std::error::Error for SendFailure {}

struct Udp {
    socket: UdpSocket,
    user: Arc<Semaphore>,
    control: Arc<Semaphore>,
}
// One selected real owner stays inline; no alternate carrier or packet keys exist.
#[allow(clippy::large_enum_variant)]
enum Backend {
    Udp(Udp),
    OpenVpn(openvpn::Carrier),
}

/// Sole real connected socket owner, or its existing single-reader OpenVPN actor.
pub struct OriginalDatagram {
    owner: u64,
    backend: Backend,
    geometry: Geometry,
    local: SocketAddr,
    peer: SocketAddr,
}
enum Pending {
    Udp {
        bytes: Vec<u8>,
        _permit: OwnedSemaphorePermit,
    },
    OpenVpn(openvpn::PendingSend),
    Done,
}
/// Move-only datagram custody tied to its issuing original socket owner.
pub struct PendingSend {
    owner: u64,
    class: SendClass,
    deadline: Instant,
    pending: Pending,
}
impl PendingSend {
    /// Retained original absolute deadline, never restarted by WouldBlock.
    pub fn deadline(&self) -> Instant {
        self.deadline
    }
    /// Trusted local pacing class, never incoming authentication authority.
    pub fn class(&self) -> SendClass {
        self.class
    }
}
impl OriginalDatagram {
    /// Retain an actual connected UDP socket with bounded per-class pending custody.
    /// Each ticket owns one fallibly copied datagram; no new socket/task is created.
    pub fn udp(
        socket: UdpSocket,
        path_mtu: usize,
        maximum: usize,
        pending_per_class: usize,
    ) -> io::Result<Self> {
        let (local, peer) = (socket.local_addr()?, socket.peer_addr()?);
        if local.is_ipv4() != peer.is_ipv4()
            || !(256..=65535).contains(&path_mtu)
            || pending_per_class == 0
            || pending_per_class > Semaphore::MAX_PERMITS
        {
            return Err(invalid("original UDP ownership bounds"));
        }
        let geometry = Geometry {
            path_mtu,
            max_datagram_bytes: maximum,
            ip_udp_bytes: if local.is_ipv4() { 28 } else { 48 },
            extra_wire_bytes: 0,
        };
        geometry.full_ip_bytes(maximum)?;
        pending_per_class
            .checked_mul(2)
            .and_then(|count| count.checked_mul(maximum))
            .ok_or_else(|| invalid("original UDP complete pending-byte capacity overflows"))?;
        Ok(Self {
            owner: next_owner()?,
            backend: Backend::Udp(Udp {
                socket,
                user: Arc::new(Semaphore::new(pending_per_class)),
                control: Arc::new(Semaphore::new(pending_per_class)),
            }),
            geometry,
            local,
            peer,
        })
    }
    /// Retain the real raw carrier, its TLS owner and original socket actor.
    /// This does not install Noise, membership, a cover policy or a Common Driver.
    pub fn openvpn(carrier: openvpn::Carrier) -> io::Result<Self> {
        let (local, peer) = carrier.addresses();
        let config = carrier.config();
        let geometry = Geometry {
            path_mtu: config.path_mtu,
            max_datagram_bytes: config.max_record_bytes,
            ip_udp_bytes: config
                .outer_overhead_bytes
                .checked_sub(1)
                .ok_or_else(|| invalid("OpenVPN overhead"))?,
            extra_wire_bytes: 1,
        };
        geometry.full_ip_bytes(geometry.max_datagram_bytes)?;
        Ok(Self {
            owner: next_owner()?,
            backend: Backend::OpenVpn(carrier),
            geometry,
            local,
            peer,
        })
    }
    /// Exact original endpoint pair; no proxy socket or caller-asserted endpoint.
    pub fn addresses(&self) -> (SocketAddr, SocketAddr) {
        (self.local, self.peer)
    }
    /// Actual extra-opcode and full-IP geometry for admission/accounting integration.
    pub fn geometry(&self) -> Geometry {
        self.geometry
    }
    /// Original outer expiry, absent for a bare UDP socket without a session owner.
    pub fn expires(&self) -> Option<Instant> {
        match &self.backend {
            Backend::Udp(_) => None,
            Backend::OpenVpn(carrier) => Some(carrier.expires()),
        }
    }
    /// Existing outer admissions only, not additive physical-byte observations.
    pub fn outer_wire_status(&self) -> io::Result<Option<l2tunnel_openvpn::WireStatus>> {
        match &self.backend {
            Backend::Udp(_) => Ok(None),
            Backend::OpenVpn(carrier) => carrier.wire_status().map(Some).map_err(carrier_error),
        }
    }
    /// Actual outer whole writes, including TLS. Never sum with overlapping admissions.
    pub fn outer_physical_status(&self) -> io::Result<Option<openvpn::PhysicalStatus>> {
        match &self.backend {
            Backend::Udp(_) => Ok(None),
            Backend::OpenVpn(carrier) => carrier.physical_status().map(Some).map_err(carrier_error),
        }
    }
    /// Actual retained TLS/member proof, distinct from later common Noise admission.
    pub fn outer_info(&self) -> Option<&l2tunnel_auth::SessionInfo> {
        match &self.backend {
            Backend::Udp(_) => None,
            Backend::OpenVpn(carrier) => Some(carrier.outer_info()),
        }
    }
    /// Retain access to the real outer TLS stream; no second socket or session is created.
    pub fn outer_control(
        &mut self,
    ) -> Option<&mut l2tunnel_auth::AuthenticatedIo<tokio::io::DuplexStream>> {
        match &mut self.backend {
            Backend::Udp(_) => None,
            Backend::OpenVpn(carrier) => Some(carrier.control()),
        }
    }
    /// Retain one datagram without reporting a physical write. WouldBlock admits nothing.
    pub fn begin_send(
        &self,
        class: SendClass,
        bytes: &[u8],
        deadline: Instant,
    ) -> io::Result<PendingSend> {
        self.geometry.full_ip_bytes(bytes.len())?;
        let deadline = self.expires().map_or(deadline, |outer| outer.min(deadline));
        check(deadline)?;
        let pending = match &self.backend {
            Backend::OpenVpn(carrier) => Pending::OpenVpn(
                carrier
                    .try_send_until(class, bytes, deadline)
                    .map_err(carrier_error)?,
            ),
            Backend::Udp(udp) => {
                let slots = if class == SendClass::User {
                    &udp.user
                } else {
                    &udp.control
                };
                let permit = slots
                    .clone()
                    .try_acquire_owned()
                    .map_err(|error| match error {
                        tokio::sync::TryAcquireError::NoPermits => {
                            io::Error::from(io::ErrorKind::WouldBlock)
                        }
                        tokio::sync::TryAcquireError::Closed => {
                            io::Error::from(io::ErrorKind::BrokenPipe)
                        }
                    })?;
                let mut packet = Vec::new();
                packet
                    .try_reserve_exact(bytes.len())
                    .map_err(io::Error::other)?;
                packet.extend_from_slice(bytes);
                check(deadline)?;
                Pending::Udp {
                    bytes: packet,
                    _permit: permit,
                }
            }
        };
        Ok(PendingSend {
            owner: self.owner,
            class,
            deadline,
            pending,
        })
    }
    /// Poll the actual issuing socket's whole-write completion, preserving custody on WB.
    /// Callers manually polling must also wake at ticket.deadline(); wait_send does so.
    pub fn poll_send(
        &self,
        cx: &mut Context<'_>,
        ticket: &mut PendingSend,
    ) -> Poll<Result<SendReceipt, SendFailure>> {
        if ticket.owner != self.owner {
            return Poll::Ready(Err(SendFailure::Ticket));
        }
        let result = match (&self.backend, &mut ticket.pending) {
            (_, Pending::Done) => return Poll::Ready(Err(SendFailure::Ticket)),
            (Backend::OpenVpn(_), Pending::OpenVpn(pending)) => match Pin::new(pending).poll(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(result) => result.map(map_receipt).map_err(|error| match error {
                    openvpn::SendFailure::Expired { accepted } => SendFailure::Expired {
                        accepted: accepted.map(map_receipt),
                    },
                    openvpn::SendFailure::Transport(error) => SendFailure::Io(carrier_error(error)),
                    openvpn::SendFailure::Consumed => SendFailure::Ticket,
                }),
            },
            (Backend::Udp(udp), Pending::Udp { bytes, .. }) => {
                if Instant::now() >= ticket.deadline {
                    Err(SendFailure::Expired { accepted: None })
                } else {
                    let ip_bytes = self
                        .geometry
                        .full_ip_bytes(bytes.len())
                        .map_err(SendFailure::Io)?;
                    let sent = match udp.socket.poll_send_to(cx, bytes, self.peer) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(result) => result,
                    };
                    match sent {
                        Ok(length) if length == bytes.len() => {
                            let accepted_at = Instant::now();
                            let receipt = SendReceipt {
                                datagram_bytes: length,
                                udp_bytes: length,
                                ip_bytes,
                                accepted_at,
                                deadline: ticket.deadline,
                            };
                            if accepted_at >= ticket.deadline {
                                Err(SendFailure::Expired {
                                    accepted: Some(receipt),
                                })
                            } else {
                                Ok(receipt)
                            }
                        }
                        Ok(_) => Err(SendFailure::Io(io::Error::new(
                            io::ErrorKind::WriteZero,
                            "partial original UDP write",
                        ))),
                        Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                            return Poll::Pending;
                        }
                        Err(error) => Err(SendFailure::Io(error)),
                    }
                }
            }
            _ => return Poll::Ready(Err(SendFailure::Ticket)),
        };
        ticket.pending = Pending::Done;
        Poll::Ready(result)
    }
    /// Await physical completion under the same cap without consuming a pending ticket
    /// on timeout; an eventual physical fact can still be observed by polling it.
    pub async fn wait_send(&self, ticket: &mut PendingSend) -> Result<SendReceipt, SendFailure> {
        let deadline = ticket.deadline;
        timeout_at(
            deadline,
            std::future::poll_fn(|cx| self.poll_send(cx, ticket)),
        )
        .await
        .unwrap_or(Err(SendFailure::Expired { accepted: None }))
    }
    /// Poll the unique receive owner. Caller storage must include one oversize byte.
    /// Received OpenVPN bodies remain untrusted until the existing common owner opens them.
    pub fn poll_receive(
        &mut self,
        cx: &mut Context<'_>,
        output: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        if output.len() <= self.geometry.max_datagram_bytes {
            return Poll::Ready(Err(invalid(
                "original receive requires maximum plus one byte",
            )));
        }
        match &mut self.backend {
            Backend::Udp(udp) => {
                let mut buffer = ReadBuf::new(output);
                match udp.socket.poll_recv(cx, &mut buffer) {
                    Poll::Pending => Poll::Pending,
                    Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
                    Poll::Ready(Ok(())) => {
                        let length = buffer.filled().len();
                        Poll::Ready(if length > self.geometry.max_datagram_bytes {
                            Err(invalid("oversize original UDP input"))
                        } else {
                            Ok(length)
                        })
                    }
                }
            }
            Backend::OpenVpn(carrier) => carrier.poll_recv(cx).map(|result| {
                result.map_err(carrier_error).and_then(|packet| {
                    if packet.len() > self.geometry.max_datagram_bytes {
                        return Err(invalid("oversize original carrier input"));
                    }
                    output[..packet.len()].copy_from_slice(&packet);
                    Ok(packet.len())
                })
            }),
        }
    }
}
fn map_receipt(value: openvpn::SendReceipt) -> SendReceipt {
    SendReceipt {
        datagram_bytes: value.record_bytes,
        udp_bytes: value.udp_bytes,
        ip_bytes: value.ip_bytes,
        accepted_at: value.accepted_at,
        deadline: value.deadline,
    }
}
fn next_owner() -> io::Result<u64> {
    NEXT_OWNER
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
            value.checked_add(1)
        })
        .map_err(|_| io::Error::other("original datagram owner exhausted"))
}
fn check(deadline: Instant) -> io::Result<()> {
    if Instant::now() >= deadline {
        Err(io::ErrorKind::TimedOut.into())
    } else {
        Ok(())
    }
}
fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}
fn carrier_error(error: l2tunnel_openvpn::wire_carrier::Error) -> io::Error {
    use l2tunnel_openvpn::wire_carrier::Error;
    match error {
        Error::Io(error) => error,
        Error::Timeout => io::ErrorKind::TimedOut.into(),
        Error::Closed => io::ErrorKind::BrokenPipe.into(),
        error => io::Error::other(error),
    }
}

#[cfg(test)]
#[path = "original_datagram_tests.rs"]
mod tests;
