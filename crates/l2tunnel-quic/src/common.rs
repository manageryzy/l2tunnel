//! Selected Common records on the original maintained QUIC connection.
//!
//! Bootstrap retains the post-member capability envelope. After an explicit
//! authenticated handoff, final records retain only their Common protection;
//! maintained QUIC AEAD remains an additional outer protection layer. No final
//! payload is authenticated or replay-accepted by this opaque adapter.

use super::*;
use std::future::Future;
use tokio::time::{Instant, timeout_at};

mod send;
pub use send::{AcceptanceStatus, PendingSend, SendFailure, SendReceipt};

/// Trusted local scheduling class, never incoming authentication authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Class {
    /// User records obey the authenticated native direction on a half lane.
    User,
    /// Bootstrap, feedback and management remain bidirectional on every lane.
    Control,
}

/// Unambiguous DATAGRAM framing, selected before removing any bootstrap bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Framing {
    /// Original capability/session/sequence envelope, with its 48 bytes removed.
    Bootstrap,
    /// Exact Common Carrier-layout bytes; the Common owner must validate them.
    Final,
}

/// One untrusted Common record from the actual maintained connection.
pub struct Received {
    /// Complete caller record without a private carrier envelope.
    pub bytes: Vec<u8>,
    /// Explicit framing fact; never inferred from the stripped inner payload.
    pub framing: Framing,
    /// Local observation after maintained QUIC yielded the complete DATAGRAM.
    pub received_at: Instant,
}

/// Selected geometry and conservative charge, not physical packet observations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Geometry {
    /// Fixed configured IP ceiling; QUIC packetization can coalesce records.
    pub path_mtu: usize,
    /// Complete final Common DATAGRAM maximum.
    pub maximum_record_bytes: usize,
    /// Maximum caller bootstrap payload before its 48-byte envelope.
    pub maximum_bootstrap_bytes: usize,
    /// IPv4/UDP or IPv6/UDP allowance.
    pub ip_udp_bytes: usize,
    /// Explicit conservative QUIC allowance, not measured wire overhead.
    pub quic_allowance_bytes: usize,
    /// Configured byte bound for each maintained DATAGRAM queue.
    pub maintained_queue_bytes: usize,
    /// Conservative maintained send-entry count at the selected 9-byte minimum.
    pub maximum_queued_send_entries: usize,
    /// Bounded outstanding adapter tickets for each trusted scheduling class.
    pub pending_per_class: usize,
}
impl Geometry {
    /// Exact submitted carrier bytes; final records add no private envelope.
    pub fn carrier_bytes(self, record_bytes: usize, framing: Framing) -> Result<usize, Error> {
        let maximum = match framing {
            Framing::Bootstrap => self.maximum_bootstrap_bytes,
            Framing::Final => self.maximum_record_bytes,
        };
        if record_bytes == 0 || record_bytes > maximum {
            return Err(Error::Size);
        }
        record_bytes
            .checked_add(if framing == Framing::Bootstrap {
                HEADER
            } else {
                0
            })
            .ok_or(Error::Size)
    }
    /// Admission estimate only; QUIC ACKs, packetization and retries are separate.
    pub fn charged_bytes(self, record_bytes: usize, framing: Framing) -> Result<usize, Error> {
        self.carrier_bytes(record_bytes, framing)?
            .checked_add(self.ip_udp_bytes)
            .and_then(|value| value.checked_add(self.quic_allowance_bytes))
            .filter(|value| *value <= self.path_mtu)
            .ok_or(Error::Size)
    }
}

type Input = Pin<Box<dyn Future<Output = Result<Bytes, Error>> + Send>>;

/// Actual authenticated owner, retained through bootstrap and final Common use.
/// Dropping this handle closes its original reliable stream and QUIC connection.
pub struct Carrier {
    control: Control,
    receiver: DatagramReceiver,
    session: Arc<Session>,
    token: Zeroizing<[u8; 16]>,
    sequence: std::sync::Mutex<Option<u64>>,
    input: Option<Input>,
    geometry: Geometry,
    setup_deadline: Instant,
    selected_deadline: Option<Instant>,
    user: Arc<Semaphore>,
    priority: Arc<Semaphore>,
    ledger: send::Ledger,
    local: SocketAddr,
    peer: SocketAddr,
    pair_binding: Option<[u8; 32]>,
}

impl Carrier {
    /// Consume a real connection after matching its full authenticated profile/base.
    /// A half lane is admitted only by the paired challenge constructors below.
    pub fn new(
        connection: AuthenticatedConnection,
        expected: Profile,
        base: SessionConfig,
        setup_deadline: Instant,
    ) -> Result<Self, Error> {
        if expected.traffic != Traffic::FullDuplex || expected.lane != 0 {
            return Err(Error::Configuration(
                "Common half lane requires actual pairing",
            ));
        }
        checked(connection, expected, base, setup_deadline)
    }

    /// Actual outer membership and fresh session, never synthesized by this adapter.
    pub fn info(&self) -> &SessionInfo {
        &self.session.info
    }
    /// Exact selected profile bound before outer member authentication.
    pub fn profile(&self) -> Profile {
        self.session.profile
    }
    /// Actual completed pair challenge shared by the two original half lanes.
    pub fn pair_binding(&self) -> Option<[u8; 32]> {
        self.pair_binding
    }
    /// Actual original local/peer UDP endpoints. Migration remains disabled.
    pub fn addresses(&self) -> (SocketAddr, SocketAddr) {
        (self.local, self.peer)
    }
    /// Configured maximums and explicit conservative maintained-carrier charges.
    pub fn geometry(&self) -> Geometry {
        self.geometry
    }
    /// Original accepted setup cap; traffic and retries never renew it.
    pub fn setup_deadline(&self) -> Instant {
        self.setup_deadline
    }
    /// Whether exact Common final bytes have been explicitly enabled on this owner.
    pub fn final_records(&self) -> bool {
        self.selected_deadline.is_some()
    }
    /// Actual maintained Quinn transport observations, independent of inner record custody.
    /// UDP and frame counters are Quinn observations, not a Common send receipt.
    pub fn transport_statistics(&self) -> quinn::ConnectionStats {
        self.session.connection.stats()
    }
    /// Actual maintained-queue acceptance counters; never physical IP counters.
    pub fn acceptance_status(&self) -> Result<AcceptanceStatus, Error> {
        self.ledger.status()
    }
    /// Observe maintained failure without changing any Common security state.
    pub fn check_failure(&self) -> Result<(), Error> {
        self.session.check()
    }

    /// Enable the disjoint final namespace after the caller authenticated its
    /// compact contract and installed its fresh Common protection/replay owner.
    pub fn select_final_records(&mut self, original_deadline: Instant) -> Result<(), Error> {
        self.session.check()?;
        before(original_deadline)?;
        if original_deadline != self.setup_deadline || self.selected_deadline.is_some() {
            return Err(Error::Configuration(
                "Common handoff changed the original cap",
            ));
        }
        self.selected_deadline = Some(original_deadline);
        Ok(())
    }

    /// Retain exact copied bytes and one class slot. WouldBlock admits nothing.
    /// Successful construction is custody only; completion is Quinn acceptance.
    pub fn try_send(
        &self,
        class: Class,
        record: &[u8],
        deadline: Instant,
        framing: Framing,
    ) -> Result<PendingSend, Error> {
        self.session.check()?;
        if class == Class::User && !self.profile().traffic.allows(self.session.send_direction) {
            return Err(Error::Direction);
        }
        if framing == Framing::Final && (!self.final_records() || !final_prefix(record)) {
            return Err(Error::Configuration("final Common record is not selected"));
        }
        let deadline = if framing == Framing::Bootstrap {
            deadline.min(self.setup_deadline)
        } else {
            deadline
        };
        let deadline = deadline.min(Instant::now() + self.profile().io_timeout);
        before(deadline)?;
        let carrier_bytes = self.geometry.carrier_bytes(record.len(), framing)?;
        let charged_bytes = self.geometry.charged_bytes(record.len(), framing)?;
        let slots = if class == Class::User {
            self.user.clone()
        } else {
            self.priority.clone()
        };
        let permit = slots.try_acquire_owned().map_err(|error| match error {
            tokio::sync::TryAcquireError::NoPermits => Error::Io(io::ErrorKind::WouldBlock.into()),
            tokio::sync::TryAcquireError::Closed => Error::Transport,
        })?;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(carrier_bytes)
            .map_err(|_| Error::Capacity)?;
        if framing == Framing::Bootstrap {
            let mut next = self.sequence.lock().map_err(|_| Error::Transport)?;
            let sequence = next.ok_or(Error::Exhausted)?;
            *next = sequence.checked_add(1);
            bytes.extend_from_slice(b"L2QD");
            bytes.push(1);
            bytes.push(direction_byte(self.session.send_direction));
            bytes.extend_from_slice(
                &u16::try_from(record.len())
                    .map_err(|_| Error::Size)?
                    .to_be_bytes(),
            );
            bytes.extend_from_slice(&self.session.info.session_id);
            bytes.extend_from_slice(&self.token[..]);
            bytes.extend_from_slice(&sequence.to_be_bytes());
        }
        bytes.extend_from_slice(record);
        before(deadline)?;
        Ok(PendingSend::new(
            self.session.clone(),
            self.ledger.clone(),
            permit,
            class,
            Bytes::from(bytes),
            record.len(),
            charged_bytes,
            deadline,
        ))
    }

    /// Continuously poll the original reliable stream for EOF/error. Application
    /// feedback/control never uses this stream after the paired setup completes.
    pub fn poll_maintenance(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        if let Err(error) = self.session.check() {
            return Poll::Ready(Err(error));
        }
        let mut byte = [0; 1];
        let mut input = ReadBuf::new(&mut byte);
        match Pin::new(&mut self.control).poll_read(cx, &mut input) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(error)) => Poll::Ready(Err(Error::Io(error))),
            Poll::Ready(Ok(())) => {
                self.session.close();
                Poll::Ready(Err(if input.filled().is_empty() {
                    Error::Transport
                } else {
                    Error::Protocol("unexpected Common lifecycle stream bytes")
                }))
            }
        }
    }

    /// Receive a bounded untrusted record with its explicit outer framing fact.
    /// Bootstrap capability/replay validation is retained; final validation belongs
    /// exclusively to the installed Common owner. No trial parsing is used.
    pub fn poll_recv_framed(&mut self, cx: &mut Context<'_>) -> Poll<Result<Received, Error>> {
        if let Poll::Ready(result) = self.poll_maintenance(cx) {
            return Poll::Ready(result.and(Err(Error::Transport)));
        }
        for _ in 0..8 {
            let session = self.session.clone();
            let input = self.input.get_or_insert_with(|| {
                Box::pin(async move {
                    session
                        .connection
                        .read_datagram()
                        .await
                        .map_err(|_| Error::Transport)
                })
            });
            let packet = match input.as_mut().poll(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(result) => {
                    self.input = None;
                    result?
                }
            };
            let received_at = Instant::now();
            if packet.len() > self.geometry.maximum_record_bytes {
                continue;
            }
            let framing = if packet.starts_with(b"L2QD") {
                if received_at >= self.setup_deadline {
                    continue;
                }
                Framing::Bootstrap
            } else if self.final_records() && final_prefix(&packet) {
                Framing::Final
            } else {
                continue;
            };
            let capacity = if framing == Framing::Bootstrap {
                self.geometry.maximum_bootstrap_bytes
            } else {
                packet.len()
            };
            let mut bytes = Vec::new();
            bytes
                .try_reserve_exact(capacity)
                .map_err(|_| Error::Capacity)?;
            if framing == Framing::Bootstrap {
                bytes.resize(capacity, 0);
                let super::Received::Packet { len, .. } = self.receiver.admit(&packet, &mut bytes)
                else {
                    continue;
                };
                bytes.truncate(len);
            } else {
                bytes.extend_from_slice(&packet);
            }
            return Poll::Ready(Ok(Received {
                bytes,
                framing,
                received_at,
            }));
        }
        cx.waker().wake_by_ref();
        Poll::Pending
    }
}

fn final_prefix(bytes: &[u8]) -> bool {
    bytes.len() >= 9
        && bytes
            .first()
            .is_some_and(|first| *first <= 1 || *first >= 128)
}
fn before(deadline: Instant) -> Result<(), Error> {
    if Instant::now() >= deadline {
        Err(Error::TimedOut)
    } else {
        Ok(())
    }
}

fn checked(
    value: AuthenticatedConnection,
    expected: Profile,
    base: SessionConfig,
    setup_deadline: Instant,
) -> Result<Carrier, Error> {
    before(setup_deadline)?;
    if expected.datagram_format != DatagramFormat::CommonCompact
        || value.profile() != expected
        || value.info().config != session_config(base, expected)?
    {
        return Err(Error::Configuration(
            "actual selected Common QUIC profile differs",
        ));
    }
    let local = value.local_addr()?;
    let peer = value.peer_addr();
    let ip_udp_bytes = if local.is_ipv6() { 48 } else { 28 };
    let geometry = Geometry {
        path_mtu: usize::from(expected.udp_payload_ceiling) + ip_udp_bytes,
        maximum_record_bytes: expected.max_datagram_bytes,
        maximum_bootstrap_bytes: expected.maximum_bootstrap_bytes(),
        ip_udp_bytes,
        quic_allowance_bytes: 128,
        maintained_queue_bytes: expected.datagram_queue_bytes()?,
        maximum_queued_send_entries: expected.maximum_queued_send_entries()?,
        pending_per_class: expected.queued_datagrams,
    };
    geometry.charged_bytes(geometry.maximum_record_bytes, Framing::Final)?;
    let (control, sender, receiver) = value.into_parts();
    Ok(Carrier {
        control,
        receiver,
        session: sender.session,
        token: sender.token,
        sequence: std::sync::Mutex::new(sender.next),
        input: None,
        geometry,
        setup_deadline,
        selected_deadline: None,
        user: Arc::new(Semaphore::new(expected.queued_datagrams)),
        priority: Arc::new(Semaphore::new(expected.queued_datagrams)),
        ledger: send::Ledger::new(),
        local,
        peer,
        pair_binding: None,
    })
}

/// Challenge-bind the client's two actual directional connections before Common.
pub async fn client_pair(
    first: AuthenticatedConnection,
    second: AuthenticatedConnection,
    expected: [Profile; 2],
    base: SessionConfig,
    setup_deadline: Instant,
) -> Result<[Carrier; 2], Error> {
    pair(first, second, expected, base, setup_deadline, true).await
}
/// Server counterpart retaining both original controls and independent sessions.
pub async fn server_pair(
    first: AuthenticatedConnection,
    second: AuthenticatedConnection,
    expected: [Profile; 2],
    base: SessionConfig,
    setup_deadline: Instant,
) -> Result<[Carrier; 2], Error> {
    pair(first, second, expected, base, setup_deadline, false).await
}
async fn pair(
    first: AuthenticatedConnection,
    second: AuthenticatedConnection,
    expected: [Profile; 2],
    base: SessionConfig,
    setup_deadline: Instant,
    client: bool,
) -> Result<[Carrier; 2], Error> {
    if expected[0].lane != 0
        || expected[1].lane != 1
        || expected[0].traffic
            != (Traffic::HalfDuplex {
                sender: Direction::ClientToServer,
            })
        || expected[1].traffic
            != (Traffic::HalfDuplex {
                sender: Direction::ServerToClient,
            })
    {
        return Err(Error::Configuration("Common paired lane directions"));
    }
    let mut first = checked(first, expected[0], base, setup_deadline)?;
    let mut second = checked(second, expected[1], base, setup_deadline)?;
    let (a, b) = (*first.info(), *second.info());
    if a.peer_member.is_none() != client
        || b.peer_member.is_none() != client
        || a.member != b.member
        || a.server != b.server
        || a.session_id == b.session_id
    {
        return Err(Error::Configuration(
            "Common pair identity, role or session mismatch",
        ));
    }
    let challenge = timeout_at(setup_deadline, async {
        const PREFIX: &[u8; 16] = b"L2Q-COM-PAIR-V1\0";
        let mut challenge = [0; 48];
        if client {
            first.control.read_exact(&mut challenge).await?;
            if &challenge[..16] != PREFIX {
                return Err(Error::Protocol("Common pair challenge"));
            }
            second.control.write_all(&challenge).await?;
            second.control.flush().await?;
            for control in [&mut first.control, &mut second.control] {
                let mut accepted = [0; 48];
                control.read_exact(&mut accepted).await?;
                if accepted != challenge {
                    return Err(Error::Protocol("Common pair acceptance"));
                }
            }
        } else {
            challenge[..16].copy_from_slice(PREFIX);
            SystemRandom::new()
                .fill(&mut challenge[16..])
                .map_err(|_| Error::Random)?;
            first.control.write_all(&challenge).await?;
            first.control.flush().await?;
            let mut echoed = [0; 48];
            second.control.read_exact(&mut echoed).await?;
            if echoed != challenge {
                return Err(Error::Protocol("Common pair proof"));
            }
            for control in [&mut first.control, &mut second.control] {
                control.write_all(&challenge).await?;
                control.flush().await?;
            }
        }
        Ok::<[u8; 48], Error>(challenge)
    })
    .await
    .map_err(|_| Error::TimedOut)??;
    before(setup_deadline)?;
    let mut paired = ring::digest::Context::new(&SHA256);
    paired.update(b"l2tunnel/genuine-quic/common-pair/v1\0");
    paired.update(&challenge);
    paired.update(&a.session_id);
    paired.update(&b.session_id);
    let mut binding = [0; 32];
    binding.copy_from_slice(paired.finish().as_ref());
    first.pair_binding = Some(binding);
    second.pair_binding = Some(binding);
    Ok([first, second])
}

/// Canonical ordered carrier profiles, independent of later fresh session IDs.
/// This commitment belongs in the requested policy before TLS/member exchange.
pub fn policy_digest(profiles: &[Profile]) -> Result<l2tunnel_core::ConfigDigest, Error> {
    if !(1..=2).contains(&profiles.len()) {
        return Err(Error::Configuration("Common profile lane count"));
    }
    let mut digest = ring::digest::Context::new(&SHA256);
    digest.update(b"l2tunnel/genuine-quic/common-policy/v1\0");
    digest.update(&(profiles.len() as u64).to_be_bytes());
    for &profile in profiles {
        if profile.datagram_format != DatagramFormat::CommonCompact {
            return Err(Error::Configuration(
                "Common policy requires selected framing",
            ));
        }
        let canonical = session_config(
            SessionConfig {
                layer: l2tunnel_device::PacketLayer::Ip,
                digest: l2tunnel_core::ConfigDigest([0; 32]),
            },
            profile,
        )?;
        digest.update(&canonical.digest.0);
    }
    let mut out = [0; 32];
    out.copy_from_slice(digest.finish().as_ref());
    Ok(l2tunnel_core::ConfigDigest(out))
}

#[cfg(test)]
mod tests;
