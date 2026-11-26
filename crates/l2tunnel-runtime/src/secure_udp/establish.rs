//! Same-connected-socket cookie admission, maintained Noise and final-flight service.
//!
//! This runtime does not establish existing member identity or release user data.
//! The returned bootstrap tail must share the sole session socket reader.

use super::diagnostics::{self, Reporter, Stage};
use super::raw_carrier_io::{NoRaw, RawBacking};
use l2tunnel::live_tuning;
use l2tunnel_cover as cover;
use l2tunnel_handshake as hs;
use l2tunnel_security as security;
use l2tunnel_udp_control as gate;
use ring::{
    digest,
    rand::{SecureRandom, SystemRandom},
};
use std::{fmt, io, net::SocketAddr, time::Duration};
use tokio::{
    net::UdpSocket,
    time::{Instant, sleep_until, timeout_at},
};
use zeroize::Zeroize;

/// Explicit selected initial authority; the legacy root handoff is unchanged.
#[path = "establish_refresh.rs"]
pub mod refresh;

/// Explicit same-owner outer carrier admission and selected Noise custody.
#[path = "establish_carrier.rs"]
pub mod carrier;

/// Explicit original raw TCP owner and initial-only inner authentication.
#[path = "establish_raw_carrier.rs"]
pub mod raw_carrier;

/// Initial-only Noise on an actual retained TLS or genuine QUIC owner.
#[path = "establish_maintained.rs"]
pub mod maintained;

// Only the carrier branch needs retained send tickets. The UDP branch keeps its
// original borrowed I/O and test hooks, without a per-packet allocation.
#[allow(clippy::large_enum_variant)]
pub(in crate::secure_udp) enum SocketBacking<R: RawBacking = NoRaw> {
    Udp(UdpSocket),
    Carrier(super::original_datagram::OriginalDatagram),
    Raw(R),
    Maintained(super::maintained_io::Carrier),
}
impl<R: RawBacking> SocketBacking<R> {
    pub(in crate::secure_udp) fn local_addr(&self) -> io::Result<SocketAddr> {
        match self {
            Self::Udp(socket) => socket.local_addr(),
            Self::Carrier(socket) => Ok(socket.addresses().0),
            Self::Raw(socket) => Ok(socket.addresses().0),
            Self::Maintained(socket) => Ok(socket.addresses().0),
        }
    }
    pub(in crate::secure_udp) fn peer_addr(&self) -> io::Result<SocketAddr> {
        match self {
            Self::Udp(socket) => socket.peer_addr(),
            Self::Carrier(socket) => Ok(socket.addresses().1),
            Self::Raw(socket) => Ok(socket.addresses().1),
            Self::Maintained(socket) => Ok(socket.addresses().1),
        }
    }
    fn physical_overhead(&self) -> io::Result<usize> {
        match self {
            Self::Udp(socket) => Ok(if socket.local_addr()?.is_ipv4() {
                28
            } else {
                48
            }),
            Self::Carrier(socket) => {
                let geometry = socket.geometry();
                geometry
                    .ip_udp_bytes
                    .checked_add(geometry.extra_wire_bytes)
                    .ok_or_else(|| io::Error::other("carrier physical overhead overflow"))
            }
            Self::Raw(socket) => socket
                .geometry()
                .ip_tcp_bytes
                .checked_add(socket.geometry().record_overhead_bytes)
                .ok_or_else(|| io::Error::other("raw physical overhead overflow")),
            // This existing setup seam carries a configured admission allowance;
            // maintained transports do not expose a per-record physical IP fact.
            Self::Maintained(socket) => Ok(socket.geometry().bootstrap_overhead_bytes),
        }
    }
    pub(in crate::secure_udp) fn receive_capacity(&self, maximum: usize) -> io::Result<usize> {
        let maximum = match self {
            Self::Udp(_) => maximum,
            Self::Carrier(socket) => maximum.max(socket.geometry().max_datagram_bytes),
            Self::Raw(socket) => maximum.max(socket.geometry().max_record_bytes),
            Self::Maintained(socket) => maximum.max(socket.geometry().max_bootstrap_bytes),
        };
        maximum
            .checked_add(1)
            .ok_or_else(|| io::Error::other("receive bound overflow"))
    }
    pub(in crate::secure_udp) fn into_udp(self) -> io::Result<UdpSocket> {
        match self {
            Self::Udp(socket) => Ok(socket),
            Self::Carrier(_) | Self::Raw(_) | Self::Maintained(_) => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "carrier custody is not a UDP handoff",
            )),
        }
    }
    pub(in crate::secure_udp) fn into_carrier(
        self,
    ) -> io::Result<super::original_datagram::OriginalDatagram> {
        match self {
            Self::Carrier(socket) => Ok(socket),
            Self::Udp(_) | Self::Raw(_) | Self::Maintained(_) => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "noncarrier custody is not an original-datagram handoff",
            )),
        }
    }
    pub(in crate::secure_udp) fn into_raw(self) -> io::Result<R> {
        match self {
            Self::Raw(socket) => Ok(socket),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "actual raw custody required",
            )),
        }
    }
    pub(in crate::secure_udp) fn into_maintained(
        self,
    ) -> io::Result<super::maintained_io::Carrier> {
        match self {
            Self::Maintained(socket) => Ok(socket),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "actual maintained custody required",
            )),
        }
    }
    pub(in crate::secure_udp) async fn recv_from_udp(
        &mut self,
        output: &mut [u8],
    ) -> io::Result<(usize, SocketAddr)> {
        match self {
            Self::Udp(socket) => socket.recv_from(output).await,
            _ => Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "dynamic client endpoints require raw UDP socket",
            )),
        }
    }
    pub(in crate::secure_udp) async fn send_to_udp(
        &mut self,
        data: &[u8],
        target: SocketAddr,
    ) -> io::Result<usize> {
        match self {
            Self::Udp(socket) => socket.send_to(data, target).await,
            _ => Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "dynamic client endpoints require raw UDP socket",
            )),
        }
    }
    pub(in crate::secure_udp) async fn connect_udp(
        &mut self,
        target: SocketAddr,
    ) -> io::Result<()> {
        match self {
            Self::Udp(socket) => socket.connect(target).await,
            _ => Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "dynamic client endpoints require raw UDP socket",
            )),
        }
    }
    pub(in crate::secure_udp) async fn recv(&mut self, output: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::Udp(socket) => socket.recv(output).await,
            Self::Carrier(socket) => {
                std::future::poll_fn(|cx| socket.poll_receive(cx, output)).await
            }
            Self::Raw(socket) => {
                std::future::poll_fn(|cx| {
                    socket.begin_turn();
                    match socket.poll_ready(cx, true) {
                        std::task::Poll::Ready(Ok(())) => match socket.try_receive(output) {
                            Ok((bytes, _)) => std::task::Poll::Ready(Ok(bytes)),
                            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                                std::task::Poll::Pending
                            }
                            Err(error) => std::task::Poll::Ready(Err(error)),
                        },
                        std::task::Poll::Ready(Err(error)) => std::task::Poll::Ready(Err(error)),
                        std::task::Poll::Pending => std::task::Poll::Pending,
                    }
                })
                .await
            }
            Self::Maintained(socket) => {
                let deadline = socket.setup_deadline();
                let received = socket.recv(output, deadline).await?;
                // Initial parsers never reinterpret selected final records as
                // bootstrap, even if a peer races its own completed handoff.
                Ok(
                    if received.framing == super::maintained_io::Framing::Bootstrap {
                        received.bytes
                    } else {
                        0
                    },
                )
            }
        }
    }
    pub(in crate::secure_udp) async fn send_control(
        &mut self,
        bytes: &[u8],
        deadline: Instant,
    ) -> io::Result<()> {
        if let Self::Maintained(socket) = self {
            socket
                .send(
                    super::maintained_io::Class::Control,
                    bytes,
                    deadline,
                    super::maintained_io::Framing::Bootstrap,
                )
                .await?;
            return Ok(());
        }
        if let Self::Raw(socket) = self {
            return timeout_at(
                deadline,
                std::future::poll_fn(|cx| socket.poll_setup_send(cx, bytes, deadline)),
            )
            .await
            .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))?;
        }
        let Self::Carrier(socket) = self else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "carrier send requires carrier custody",
            ));
        };
        let mut ticket = loop {
            before(Instant::now(), deadline)
                .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))?;
            match socket.begin_send(
                super::original_datagram::SendClass::Control,
                bytes,
                deadline,
            ) {
                Ok(ticket) => break ticket,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    let wake = Instant::now()
                        .checked_add(Duration::from_millis(1))
                        .ok_or_else(|| io::Error::other("carrier wake overflow"))?
                        .min(deadline);
                    sleep_until(wake).await;
                }
                Err(error) => return Err(error),
            }
        };
        let cap = ticket.deadline();
        let receipt = socket
            .wait_send(&mut ticket)
            .await
            .map_err(|error| match error {
                super::original_datagram::SendFailure::Expired { accepted } => io::Error::new(
                    io::ErrorKind::TimedOut,
                    super::original_datagram::SendFailure::Expired { accepted },
                ),
                super::original_datagram::SendFailure::Io(error) => error,
                super::original_datagram::SendFailure::Ticket => {
                    io::Error::other(super::original_datagram::SendFailure::Ticket)
                }
            })?;
        if Instant::now() >= cap {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                super::original_datagram::SendFailure::Expired {
                    accepted: Some(receipt),
                },
            ));
        }
        Ok(())
    }
}

/// Handshake-cover tag around an exact legacy admission record.
pub const GATE_TAG: u8 = 0x80;
/// Handshake-cover tag around a complete authenticated bootstrap ARQ packet.
pub const CONTROL_TAG: u8 = 0x81;
/// Smallest bootstrap ARQ source, the largest frame without live tuning.
const FRAME_BYTES: usize = 100;
/// Largest setup-stream frame: header plus an Initiation with the largest
/// live-tuning proposal. Frames larger than one ARQ source are split.
const MAX_FRAME_BYTES: usize = 4 + hs::MAX_INITIATION_BYTES;
const MAX_CONFIRM_BYTES: usize = hs::CONTEXT_CONFIRM_BYTES;

/// Live-tuning exchange of one setup (docs/modules/live-tuning.md,
/// decisions 3, 4 and 6).
pub enum Tuning<'a> {
    /// No proposal: the handshake is byte-for-byte the original, and a
    /// responder refuses any carried proposal as not offered.
    Off,
    /// Initiator: carry `proposal` in message 1 and bind `context`, the root
    /// of the catalog this end derived from it, into both confirmations.
    Propose {
        /// Encoded choices, at most [`hs::MAX_INITIATION_PAYLOAD`] bytes.
        proposal: &'a [u8],
        /// Root of the catalog generated from the base plan and `proposal`.
        context: [u8; 32],
    },
    /// Responder: judge a carried proposal. `Ok(root)` accepts and binds the
    /// derived catalog root; `Err` refuses, and the initiator receives the
    /// reason in the authenticated message 2.
    Judge(&'a mut Judge<'a>),
}
/// Responder judgment of one carried proposal.
pub type Judge<'a> = dyn FnMut(&[u8]) -> Result<[u8; 32], live_tuning::Refusal> + Send + 'a;

/// Caller-verified public context, without a caller-selected session identifier.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Binding {
    /// Complete configuration/capability/resource digest.
    pub configuration: [u8; 32],
    /// Canonical global carrier IDs, media policy and appearance digest.
    pub carrier: [u8; 32],
    /// Existing outer ownership/handshake binding.
    pub outer: [u8; 32],
    /// Existing member provisioning context; not verification by itself.
    pub member: [u8; 32],
}

/// Explicit finite bootstrap policy. No new CLI/default is selected here.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Config {
    /// Existing admission/ARQ bounds and independently provisioned key identifier.
    pub gate: gate::Config,
    /// Actual complementary local/peer appearance configuration.
    pub cover: cover::Config,
    /// Required maintained fixed Noise profile, without fallback.
    pub profile: hs::Profile,
    /// Caller-verified canonical context.
    pub binding: Binding,
    /// Maximum received datagrams processed per gate interval, in 1..=4096.
    pub receive_packets_per_interval: u32,
}
impl Config {
    /// Derive the expected public prologue for the exact selected session.
    /// This performs no I/O and proves neither Noise nor member possession.
    pub fn expected_binding(
        self,
        peers: Peers,
        session: hs::SessionId,
    ) -> Result<hs::Binding, Error> {
        session_binding(setup(self, peers)?, session.0)
    }
}

/// Owned pinned Noise credentials, independent of admission and member credentials.
pub struct Identity {
    /// Owned explicitly provisioned local X25519 key.
    pub local: hs::LocalSecret,
    /// Explicit remote X25519 public-key pin.
    pub peer: hs::PeerKey,
    /// Additional independent PSK only for the explicitly selected IKpsk2 profile.
    pub psk: Option<hs::Psk>,
}

/// Public pinned keys in one canonical global role order.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Peers {
    /// Initiating client's public key.
    pub initiator: hs::PeerKey,
    /// Responding server's public key.
    pub responder: hs::PeerKey,
}

/// Saturating observations, never authority for protocol progress.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Statistics {
    /// Datagrams examined by this owner, including discarded input.
    pub received_datagrams: u64,
    /// Input discarded without authentication or protocol progress.
    pub ignored_datagrams: u64,
    /// Attempted complete covered records handed to a bounded socket/send slot.
    /// The historical name does not imply a maintained transport datagram.
    pub emitted_datagrams: u64,
    /// Attempted original covered-record bytes, excluding outer framing/protection.
    /// For maintained TLS/QUIC this historical name is not a UDP or IP wire count.
    pub emitted_udp_bytes: u64,
    /// Complete datagrams accepted by the native socket during establishment.
    pub socket_sent_datagrams: u64,
    /// UDP payload bytes accepted by the native socket during establishment.
    pub socket_sent_udp_bytes: u64,
    /// Complete bootstrap records accepted by TLS flush or Quinn's send facility.
    /// These are not native socket writes, TCP ACKs or peer deliveries.
    pub maintained_accepted_records: u64,
    /// Original covered bootstrap bytes at the named maintained acceptance boundary.
    /// Outer framing, TLS/QUIC encryption and retransmissions are not included.
    pub maintained_accepted_record_bytes: u64,
    /// Admitted send attempts lost to a transient path/socket condition.
    pub socket_drops: u64,
    /// Transient receive failures, charged against the finite receive-work quota.
    pub socket_receive_errors: u64,
    /// New Noise encryptions, excluding exact transport retries.
    pub noise_flights: u64,
    /// Exact already-verified Noise frames encountered again.
    pub noise_duplicates: u64,
    /// Stateless Retry packets produced under the existing server quota.
    pub gate_retries: u64,
    /// Fresh authenticated bootstrap MAC packet identities.
    pub bootstrap_fresh: u64,
    /// Authenticated bootstrap packet identities already seen.
    pub bootstrap_replays: u64,
}

/// Runtime/configuration or maintained-protocol failure without secret contents.
#[derive(Debug)]
pub enum Error {
    /// A trusted policy, credential selection or fixed socket path is invalid.
    Configuration(&'static str),
    /// The original absolute deadline expired or monotonic conversion failed.
    Deadline,
    /// Caller/runtime cryptographic entropy failed or supplied an all-zero nonce.
    Entropy,
    /// An authenticated bootstrap stream violated its exact fixed flight grammar.
    Protocol,
    /// Caller output cannot hold the complete configured bootstrap packet.
    OutputTooSmall,
    /// Existing admission/recovery primitive rejected the operation.
    Gate(gate::Error),
    /// Maintained pinned-key Noise primitive rejected the exchange.
    Noise(hs::Error),
    /// Selected managed initial custody rejected the consuming handoff.
    Refresh(hs::refresh::Error),
    /// Selected bounded appearance codec rejected the operation.
    Cover(cover::Error),
    /// Native socket I/O failed; no retry/default migration is inferred.
    Io(io::Error),
    /// A live-tuning proposal was refused: by this responder, or by the
    /// server in its authenticated verdict.
    Tuning(live_tuning::Refusal),
}
impl fmt::Display for Error {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(output, "secure UDP establishment: {self:?}")
    }
}
impl std::error::Error for Error {}
impl From<gate::Error> for Error {
    fn from(value: gate::Error) -> Self {
        Self::Gate(value)
    }
}
impl From<hs::Error> for Error {
    fn from(value: hs::Error) -> Self {
        Self::Noise(value)
    }
}
impl From<hs::refresh::Error> for Error {
    fn from(value: hs::refresh::Error) -> Self {
        Self::Refresh(value)
    }
}
impl From<cover::Error> for Error {
    fn from(value: cover::Error) -> Self {
        Self::Cover(value)
    }
}
impl From<io::Error> for Error {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

/// Explicit native-runtime entropy provider; pure libraries never create this.
pub struct RuntimeEntropy(SystemRandom);
impl RuntimeEntropy {
    /// Use the maintained runtime OS entropy provider, with no fallback.
    pub fn new() -> Self {
        Self(SystemRandom::new())
    }
}
impl Default for RuntimeEntropy {
    fn default() -> Self {
        Self::new()
    }
}
impl hs::Entropy for RuntimeEntropy {
    fn fill(&mut self, output: &mut [u8; 32]) -> Result<(), hs::EntropyError> {
        self.0.fill(output).map_err(|_| hs::EntropyError)
    }
}

#[derive(Clone, Copy)]
struct Setup {
    config: Config,
    gate: gate::Config,
    max_wire: usize,
}

/// Reusable server cookie/quarantine owner; retain it across failed attempts.
pub struct ServerAdmission {
    setup: Setup,
    peers: Peers,
    gate: gate::ServerGate,
    origin: Instant,
}
impl ServerAdmission {
    /// Bind one fixed path/configuration and independent secret keys.
    pub fn new(
        config: Config,
        peers: Peers,
        admission: gate::Secret,
        cookie: gate::Secret,
        origin: Instant,
    ) -> Result<Self, Error> {
        Self::with_extra(config, peers, admission, cookie, origin, 0)
    }
    fn with_extra(
        config: Config,
        peers: Peers,
        admission: gate::Secret,
        cookie: gate::Secret,
        origin: Instant,
        extra: usize,
    ) -> Result<Self, Error> {
        let setup = setup_with_extra(config, peers, extra)?;
        let gate = gate::ServerGate::new(setup.gate, admission, cookie, Duration::ZERO)?;
        Ok(Self {
            setup,
            peers,
            gate,
            origin,
        })
    }
    fn with_physical_overhead(
        config: Config,
        peers: Peers,
        admission: gate::Secret,
        cookie: gate::Secret,
        origin: Instant,
        physical: usize,
    ) -> Result<Self, Error> {
        let setup = setup_with_physical_overhead(config, peers, physical)?;
        let gate = gate::ServerGate::new(setup.gate, admission, cookie, Duration::ZERO)?;
        Ok(Self {
            setup,
            peers,
            gate,
            origin,
        })
    }
    /// Current bounded gate counters and pending/quarantine count.
    pub fn statistics(&self) -> gate::GateStatistics {
        self.gate.statistics()
    }
    /// Public canonical pinned keys, without any private material.
    pub const fn peers(&self) -> Peers {
        self.peers
    }
    /// Original explicit policy; the derived admission digest is internal.
    pub const fn config(&self) -> Config {
        self.setup.config
    }
}

/// Pinned Noise establishment, before the parent's required member proof.
pub struct Established {
    /// The exact originally supplied connected socket.
    pub socket: UdpSocket,
    /// Opaque root released only by completed confirmed Noise.
    pub root: security::SessionRoot,
    /// Actual root session/transcript, never a caller-hard-coded session ID.
    pub binding: security::SessionBinding,
    /// Exact public prologue context authenticated by this Noise exchange.
    pub authenticated: hs::Binding,
    /// Public keys in canonical global order for later identity binding.
    pub peers: Peers,
    /// Actual selected local/peer cover used from the first gate packet.
    pub cover: cover::Config,
    /// Remaining bounded bootstrap custody for the sole-reader session owner.
    pub tail: BootstrapTail,
    /// Continue this outer appearance counter across tail and normal records.
    pub next_outer: u32,
    /// Unchanged caller deadline to retain during subsequent member joining.
    pub deadline: Instant,
    /// Establishment observations at this handoff, not member/native readiness.
    pub statistics: Statistics,
}

// The material variants are created only by the corresponding actual Noise finish.
// Public metadata cannot convert the legacy root into selected initial authority.
#[allow(clippy::large_enum_variant)] // Transfer the actual bounded owner without a second root/allocation.
pub(in crate::secure_udp) enum InitialMaterial {
    Legacy(security::SessionRoot),
    Managed(hs::refresh::ConfirmedInitial),
}
impl InitialMaterial {
    pub(in crate::secure_udp) fn binding(&self) -> security::SessionBinding {
        match self {
            Self::Legacy(root) => root.binding(),
            Self::Managed(initial) => initial.binding(),
        }
    }
    pub(in crate::secure_udp) fn role(&self) -> security::Role {
        match self {
            Self::Legacy(root) => root.role(),
            Self::Managed(initial) => initial.role(),
        }
    }
}

pub(in crate::secure_udp) struct EstablishedState<R: RawBacking = NoRaw> {
    pub(in crate::secure_udp) socket: SocketBacking<R>,
    pub(in crate::secure_udp) material: InitialMaterial,
    pub(in crate::secure_udp) binding: security::SessionBinding,
    pub(in crate::secure_udp) authenticated: hs::Binding,
    pub(in crate::secure_udp) peers: Peers,
    pub(in crate::secure_udp) cover: cover::Config,
    pub(in crate::secure_udp) tail: BootstrapTail,
    pub(in crate::secure_udp) next_outer: u32,
    pub(in crate::secure_udp) deadline: Instant,
    pub(in crate::secure_udp) statistics: Statistics,
    // Selected Joining must continue the actual confirmed Noise time domain.
    pub(in crate::secure_udp) origin: Instant,
}
impl EstablishedState {
    fn into_legacy(self) -> Result<Established, Error> {
        let InitialMaterial::Legacy(root) = self.material else {
            return Err(Error::Protocol);
        };
        Ok(Established {
            socket: self.socket.into_udp()?,
            root,
            binding: self.binding,
            authenticated: self.authenticated,
            peers: self.peers,
            cover: self.cover,
            tail: self.tail,
            next_outer: self.next_outer,
            deadline: self.deadline,
            statistics: self.statistics,
        })
    }
}
impl From<Established> for EstablishedState {
    fn from(value: Established) -> Self {
        Self {
            socket: SocketBacking::Udp(value.socket),
            material: InitialMaterial::Legacy(value.root),
            binding: value.binding,
            authenticated: value.authenticated,
            peers: value.peers,
            cover: value.cover,
            tail: value.tail,
            next_outer: value.next_outer,
            deadline: value.deadline,
            statistics: value.statistics,
            // Preserve the existing legacy member clock origin.
            origin: Instant::now(),
        }
    }
}

struct Core {
    control: Option<gate::ControlEngine>,
    setup: Setup,
    origin: Instant,
    end: Instant,
    last: Instant,
    scratch: Vec<u8>,
    protected: Vec<u8>,
    statistics: Statistics,
}
impl Core {
    fn new(
        setup: Setup,
        ticket: gate::PathTicket,
        origin: Instant,
        deadline: Instant,
        statistics: Statistics,
    ) -> Result<Self, Error> {
        let now = Instant::now();
        before(now, deadline)?;
        let end = deadline.min(
            origin
                .checked_add(ticket.deadline())
                .ok_or(Error::Deadline)?,
        );
        before(now, end)?;
        let control = gate::ControlEngine::new(ticket, elapsed(origin, now)?)?;
        let scratch = vec![0; control.max_datagram_bytes()];
        let protected = vec![0; setup.config.cover.limits().max_protected_bytes];
        Ok(Self {
            control: Some(control),
            setup,
            origin,
            end,
            last: now,
            scratch,
            protected,
            statistics,
        })
    }
    fn retire(&mut self) {
        self.control = None;
        self.scratch.zeroize();
        self.protected.zeroize();
    }
    fn observe(&mut self, now: Instant) -> Result<bool, Error> {
        if now < self.last {
            self.retire();
            return Err(Error::Deadline);
        }
        self.last = now;
        if now >= self.end {
            self.retire();
            return Ok(false);
        }
        Ok(self.control.is_some())
    }
    fn receive_peer(
        &mut self,
        body: &[u8],
        peer: SocketAddr,
        now: Instant,
    ) -> Result<Option<gate::ReceiveOutcome>, Error> {
        if !self.observe(now)? || body.first() != Some(&CONTROL_TAG) {
            return Ok(None);
        }
        match self.control.as_mut().ok_or(Error::Protocol)?.receive(
            peer,
            &body[1..],
            elapsed(self.origin, now)?,
        ) {
            Ok(outcome) => {
                match outcome {
                    gate::ReceiveOutcome::Fresh => {
                        self.statistics.bootstrap_fresh =
                            self.statistics.bootstrap_fresh.saturating_add(1)
                    }
                    gate::ReceiveOutcome::Replay => {
                        self.statistics.bootstrap_replays =
                            self.statistics.bootstrap_replays.saturating_add(1)
                    }
                }
                Ok(Some(outcome))
            }
            Err(gate::Error::Malformed | gate::Error::Authentication) => {
                self.statistics.ignored_datagrams =
                    self.statistics.ignored_datagrams.saturating_add(1);
                Ok(None)
            }
            Err(error) => Err(error.into()),
        }
    }
    fn poll(
        &mut self,
        now: Instant,
        outer: cover::PacketMeta,
        output: &mut [u8],
    ) -> Result<Option<usize>, Error> {
        if !self.observe(now)? {
            return Ok(None);
        }
        if outer.phase != cover::Phase::Handshake {
            return Err(Error::Configuration("bootstrap outer phase"));
        }
        if output.len() < self.setup.max_wire {
            return Err(Error::OutputTooSmall);
        }
        let Some(length) = self
            .control
            .as_mut()
            .ok_or(Error::Protocol)?
            .poll(elapsed(self.origin, now)?, &mut self.scratch)?
        else {
            return Ok(None);
        };
        self.protected[0] = CONTROL_TAG;
        self.protected[1..1 + length].copy_from_slice(&self.scratch[..length]);
        let bytes = self
            .setup
            .config
            .cover
            .encode(outer, &self.protected[..1 + length], output)?;
        emitted(&mut self.statistics, bytes);
        Ok(Some(bytes))
    }
    fn deadline(&self) -> Option<Instant> {
        let control = self.control.as_ref()?;
        if self.last >= self.end {
            return None;
        }
        let due = self.origin.checked_add(control.deadline())?.min(self.end);
        Some(if due <= self.last {
            self.last
                .checked_add(self.setup.gate.interval)?
                .min(self.end)
        } else {
            due
        })
    }
}

/// Remaining final ciphertext and authenticated ARQ service, without a socket reader.
pub struct BootstrapTail {
    core: Core,
    confirmation: Option<hs::ConfirmationCache>,
    peer_confirmation: [u8; MAX_CONFIRM_BYTES],
    peer_confirmation_len: usize,
    parser: Parser,
    peer: SocketAddr,
}
impl BootstrapTail {
    /// Original immutable bootstrap lifetime, independent of retransmission wakes.
    pub fn expiry(&self) -> Instant {
        self.core.end
    }
    /// Consume only handshake-tagged authenticated bootstrap packets.
    /// Other records and bad MACs cannot grant authority or trigger a response.
    pub fn receive(&mut self, decoded: cover::Decoded<'_>, now: Instant) -> Result<bool, Error> {
        match self.core.observe(now) {
            Ok(true) => {}
            Ok(false) => {
                self.retire();
                return Ok(false);
            }
            Err(error) => {
                self.retire();
                return Err(error);
            }
        }
        if decoded.phase != cover::Phase::Handshake
            || decoded.protected.first() != Some(&CONTROL_TAG)
        {
            return Ok(false);
        }
        self.core.statistics.received_datagrams =
            self.core.statistics.received_datagrams.saturating_add(1);
        let accepted = match self.core.receive_peer(decoded.protected, self.peer, now) {
            Ok(accepted) => accepted,
            Err(error) => {
                self.retire();
                return Err(error);
            }
        };
        if self.core.control.is_none() {
            self.confirmation = None;
            return Ok(false);
        }
        if accepted.is_some() {
            loop {
                let parsed = self.parser.read(
                    self.core.control.as_mut().ok_or(Error::Protocol)?,
                    elapsed(self.core.origin, now)?,
                );
                let frame = match parsed {
                    Ok(Some(frame)) => frame,
                    Ok(None) => break,
                    Err(error) => {
                        self.retire();
                        return Err(error);
                    }
                };
                if frame.kind != hs::FlightKind::Confirmation
                    || frame.bytes[..frame.length]
                        != self.peer_confirmation[..self.peer_confirmation_len]
                {
                    self.retire();
                    return Err(Error::Protocol);
                }
            }
        }
        Ok(accepted.is_some())
    }
    /// Emit one complete covered attempt after output preflight. The caller owns
    /// the packet until physical socket handoff and supplies the shared outer counter.
    pub fn poll(
        &mut self,
        now: Instant,
        outer: cover::PacketMeta,
        output: &mut [u8],
    ) -> Result<Option<usize>, Error> {
        let result = self.core.poll(now, outer, output);
        if result
            .as_ref()
            .is_err_and(|error| !matches!(error, Error::OutputTooSmall))
        {
            self.retire();
        }
        if self.core.control.is_none() {
            self.confirmation = None;
        }
        result
    }
    /// Next finite retry/refill/expiry wake, absent after retirement.
    pub fn deadline(&self) -> Option<Instant> {
        self.core.deadline()
    }
    /// Whether local bootstrap byte ownership and receipts have drained.
    pub fn drained(&self) -> bool {
        self.core
            .control
            .as_ref()
            .is_none_or(gate::ControlEngine::drained)
    }
    /// Current saturating bounded-service diagnostics.
    pub const fn statistics(&self) -> Statistics {
        self.core.statistics
    }
    /// Current retained bootstrap-control gauges, absent after custody retirement.
    pub fn control_statistics(&self) -> Option<gate::ControlStatistics> {
        self.core
            .control
            .as_ref()
            .map(gate::ControlEngine::statistics)
    }
    /// Complete caller-output requirement, excluding IP/UDP.
    pub const fn max_packet_bytes(&self) -> usize {
        self.core.setup.max_wire
    }
    fn retire(&mut self) {
        self.core.retire();
        self.confirmation = None;
        self.peer_confirmation.zeroize();
    }
}

struct Frame {
    kind: hs::FlightKind,
    bytes: Vec<u8>,
    length: usize,
}
// Heap buffers keep the setup and tail futures, which are moved by value,
// as small as before the larger live-tuning frames.
struct Parser {
    bytes: Box<[u8; MAX_FRAME_BYTES]>,
    used: usize,
}
impl Parser {
    fn new() -> Self {
        Self {
            bytes: Box::new([0; MAX_FRAME_BYTES]),
            used: 0,
        }
    }
    fn read(
        &mut self,
        control: &mut gate::ControlEngine,
        now: Duration,
    ) -> Result<Option<Frame>, Error> {
        loop {
            let needed = if self.used < 4 {
                4
            } else {
                let length = usize::from(u16::from_be_bytes([self.bytes[2], self.bytes[3]]));
                // The handshake checks the exact length for its state.
                let allowed = match self.bytes[1] {
                    1 => (96..=hs::MAX_INITIATION_BYTES).contains(&length),
                    2 => (48..=hs::MAX_RESPONSE_BYTES).contains(&length),
                    3 => length == hs::PLAIN_CONFIRM_BYTES || length == hs::CONTEXT_CONFIRM_BYTES,
                    _ => return Err(Error::Protocol),
                };
                if self.bytes[0] != 1 || !allowed {
                    return Err(Error::Protocol);
                }
                4 + length
            };
            if self.used < needed {
                let count = control.read(&mut self.bytes[self.used..needed], now)?;
                if count == 0 {
                    return Ok(None);
                }
                self.used += count;
                continue;
            }
            let kind = match self.bytes[1] {
                1 => hs::FlightKind::Initiation,
                2 => hs::FlightKind::Response,
                3 => hs::FlightKind::Confirmation,
                _ => return Err(Error::Protocol),
            };
            let length = needed - 4;
            let bytes = self.bytes[4..needed].to_vec();
            self.used = 0;
            return Ok(Some(Frame {
                kind,
                bytes,
                length,
            }));
        }
    }
}

struct Quota {
    left: u32,
    limit: u32,
    refill: Instant,
    interval: Duration,
}
impl Quota {
    fn new(config: Config, now: Instant) -> Result<Self, Error> {
        Ok(Self {
            left: config.receive_packets_per_interval,
            limit: config.receive_packets_per_interval,
            refill: now
                .checked_add(config.gate.interval)
                .ok_or(Error::Deadline)?,
            interval: config.gate.interval,
        })
    }
    fn ready(&mut self, now: Instant) -> Result<bool, Error> {
        if now >= self.refill {
            self.left = self.limit;
            self.refill = now.checked_add(self.interval).ok_or(Error::Deadline)?;
        }
        Ok(self.left > 0)
    }
    fn charge(&mut self) {
        self.left = self.left.saturating_sub(1);
    }
}

/// Establish pinned Noise after admission on the supplied connected client socket.
/// User release still requires the parent's actual member proof.
pub async fn connect(
    socket: UdpSocket,
    config: Config,
    identity: Identity,
    admission: gate::Secret,
    deadline: Instant,
    entropy: &mut (impl hs::Entropy + Send),
) -> Result<Established, Error> {
    connect_observed(
        socket,
        config,
        identity,
        admission,
        deadline,
        entropy,
        &mut |_| {},
    )
    .await
}

/// Establish with fixed-size stage/counter observations; no protocol choices change.
#[allow(clippy::too_many_arguments)] // Additive observation preserves the existing setup parameters.
pub async fn connect_observed(
    socket: UdpSocket,
    config: Config,
    identity: Identity,
    admission: gate::Secret,
    deadline: Instant,
    entropy: &mut (impl hs::Entropy + Send),
    observe: &mut diagnostics::Observer<'_>,
) -> Result<Established, Error> {
    connect_tuned(
        socket,
        config,
        identity,
        admission,
        deadline,
        entropy,
        observe,
        Tuning::Off,
    )
    .await
}

/// [`connect_observed`] with a live-tuning proposal
/// (docs/modules/live-tuning.md); `Tuning::Off` is the original exchange.
#[allow(clippy::too_many_arguments)] // The observed inputs plus the live-tuning hook.
pub async fn connect_tuned(
    socket: UdpSocket,
    config: Config,
    identity: Identity,
    admission: gate::Secret,
    deadline: Instant,
    entropy: &mut (impl hs::Entropy + Send),
    observe: &mut diagnostics::Observer<'_>,
    tuning: Tuning<'_>,
) -> Result<Established, Error> {
    let mut report = Reporter::new(observe);
    // One setup allocation keeps instrumentation from multiplying caller stack storage.
    let result = Box::pin(connect_inner(
        SocketBacking::<NoRaw>::Udp(socket),
        config,
        identity,
        admission,
        deadline,
        entropy,
        &mut report,
        None,
        tuning,
    ))
    .await;
    if let Err(error) = &result {
        report.fail(diagnostics::establishment_reason(error));
    }
    result.and_then(EstablishedState::into_legacy)
}

#[allow(clippy::too_many_arguments)] // Same bounded setup inputs plus a borrowed observation sink.
async fn connect_inner<R: RawBacking>(
    mut socket: SocketBacking<R>,
    config: Config,
    identity: Identity,
    admission: gate::Secret,
    deadline: Instant,
    entropy: &mut (impl hs::Entropy + Send),
    report: &mut Reporter<'_, '_>,
    selection: Option<hs::refresh::Selection>,
    tuning: Tuning<'_>,
) -> Result<EstablishedState<R>, Error> {
    let peers = Peers {
        initiator: identity.local.public_key(),
        responder: identity.peer,
    };
    let setup = setup_with_physical_overhead(config, peers, socket.physical_overhead()?)?;
    socket_path(&socket, setup.gate.path, hs::Role::Initiator)?;
    let origin = Instant::now();
    before(origin, deadline)?;
    let mut client = gate::ClientGate::new(setup.gate, admission, nonce(entropy)?, Duration::ZERO)?;
    let mut statistics = Statistics::default();
    report.stage(Stage::Admission);
    report.bootstrap(statistics, None);
    let mut next_outer = 0;
    let mut quota = Quota::new(config, origin)?;
    let mut input = vec![0; socket.receive_capacity(config.cover.limits().max_packet_bytes)?];
    let mut output = vec![0; config.cover.limits().max_packet_bytes];
    let ticket = loop {
        report.bootstrap(statistics, None);
        let now = Instant::now();
        before(now, deadline)?;
        if let Some(frame) = client.poll(elapsed(origin, now)?)? {
            let length = gate_packet(setup, &frame, next_outer, &mut output)?;
            report.bootstrap(statistics, None);
            let accepted = send_backing(&mut socket, &output[..length], deadline).await?;
            sent(&mut statistics, length, accepted);
            advance(&mut next_outer)?;
            emitted(&mut statistics, length);
        }
        report.bootstrap(statistics, None);
        let ready = quota.ready(now)?;
        let wake = now
            .checked_add(setup.gate.interval)
            .ok_or(Error::Deadline)?
            .min(deadline);
        tokio::select! {
            received = socket.recv(&mut input), if ready => {
                before(Instant::now(), deadline)?;
                quota.charge();
                let Some(length) = received_length(received, &mut statistics)? else { continue; };
                statistics.received_datagrams = statistics.received_datagrams.saturating_add(1);
                report.bootstrap(statistics, None);
                let Some(frame) = gate_body(setup, &input[..length]) else { ignored(&mut statistics); continue; };
                if let Some(ticket) = client.receive_retry(setup.gate.path.server, frame, elapsed(origin, Instant::now())?)? { break ticket; }
                ignored(&mut statistics);
            }
            _ = sleep_until(if ready { wake } else { wake.min(quota.refill) }) => {}
        }
    };
    Exchange {
        socket,
        setup,
        identity,
        peers,
        ticket,
        origin,
        deadline,
        statistics,
        next_outer,
        client: Some(client),
    }
    .run(entropy, None, report, selection, tuning)
    .await
}

/// Establish pinned Noise after a valid return-path Echo on the original server socket.
/// The supplied admission owner retains quarantine across success, failure and cancellation.
pub async fn accept(
    socket: UdpSocket,
    identity: Identity,
    admission: &mut ServerAdmission,
    deadline: Instant,
    entropy: &mut (impl hs::Entropy + Send),
) -> Result<Established, Error> {
    accept_observed(socket, identity, admission, deadline, entropy, &mut |_| {}).await
}

/// Accept with actual bounded observations; the admission owner remains retained.
pub async fn accept_observed(
    socket: UdpSocket,
    identity: Identity,
    admission: &mut ServerAdmission,
    deadline: Instant,
    entropy: &mut (impl hs::Entropy + Send),
    observe: &mut diagnostics::Observer<'_>,
) -> Result<Established, Error> {
    accept_tuned(
        socket,
        identity,
        admission,
        deadline,
        entropy,
        observe,
        Tuning::Off,
    )
    .await
}

/// [`accept_observed`] that judges a carried live-tuning proposal
/// (docs/modules/live-tuning.md); `Tuning::Off` refuses any proposal.
pub async fn accept_tuned(
    socket: UdpSocket,
    identity: Identity,
    admission: &mut ServerAdmission,
    deadline: Instant,
    entropy: &mut (impl hs::Entropy + Send),
    observe: &mut diagnostics::Observer<'_>,
    tuning: Tuning<'_>,
) -> Result<Established, Error> {
    let mut report = Reporter::new(observe);
    report.server(admission.statistics());
    let result = Box::pin(accept_inner(
        SocketBacking::<NoRaw>::Udp(socket),
        identity,
        admission,
        deadline,
        entropy,
        &mut report,
        None,
        tuning,
    ))
    .await;
    report.server(admission.statistics());
    if let Err(error) = &result {
        report.fail(diagnostics::establishment_reason(error));
    }
    result.and_then(EstablishedState::into_legacy)
}

#[allow(clippy::too_many_arguments)] // Same bounded setup inputs plus the live-tuning hook.
async fn accept_inner<R: RawBacking>(
    mut socket: SocketBacking<R>,
    identity: Identity,
    admission: &mut ServerAdmission,
    deadline: Instant,
    entropy: &mut (impl hs::Entropy + Send),
    report: &mut Reporter<'_, '_>,
    selection: Option<hs::refresh::Selection>,
    tuning: Tuning<'_>,
) -> Result<EstablishedState<R>, Error> {
    let peers = Peers {
        initiator: identity.peer,
        responder: identity.local.public_key(),
    };
    if peers != admission.peers {
        return Err(Error::Configuration("server pinned keys"));
    }
    let setup = admission.setup;
    socket_path(&socket, setup.gate.path, hs::Role::Responder)?;
    let origin = admission.origin;
    let now = Instant::now();
    before(now, deadline)?;
    elapsed(origin, now)?;
    let mut statistics = Statistics::default();
    report.stage(Stage::Admission);
    report.bootstrap(statistics, None);
    let mut next_outer = 0;
    let mut quota = Quota::new(setup.config, now)?;
    if setup_with_physical_overhead(setup.config, admission.peers, socket.physical_overhead()?)?
        .gate
        != setup.gate
    {
        return Err(Error::Configuration("actual carrier bootstrap geometry"));
    }
    let mut input = vec![0; socket.receive_capacity(setup.config.cover.limits().max_packet_bytes)?];
    let mut output = vec![0; setup.config.cover.limits().max_packet_bytes];
    let mut server_nonce = nonce(entropy)?;
    let dynamic_client = setup.gate.path.is_dynamic_client();
    let ticket = loop {
        report.bootstrap(statistics, None);
        let now = Instant::now();
        before(now, deadline)?;
        report.bootstrap(statistics, None);
        let ready = quota.ready(now)?;
        let wake = if ready {
            deadline
        } else {
            quota.refill.min(deadline)
        };
        let received_peer: Option<(io::Result<usize>, SocketAddr)> = if dynamic_client {
            tokio::select! {
                received = socket.recv_from_udp(&mut input), if ready => {
                    match received {
                        Ok((len, src)) => Some((Ok(len), src)),
                        Err(err) => Some((Err(err), setup.gate.path.client)),
                    }
                }
                _ = sleep_until(wake) => None,
            }
        } else {
            tokio::select! {
                received = socket.recv(&mut input), if ready => {
                    Some((received, setup.gate.path.client))
                }
                _ = sleep_until(wake) => None,
            }
        };
        let Some((received, src_addr)) = received_peer else {
            continue;
        };
        before(Instant::now(), deadline)?;
        quota.charge();
        let Some(length) = received_length(received, &mut statistics)? else {
            continue;
        };
        statistics.received_datagrams = statistics.received_datagrams.saturating_add(1);
        report.bootstrap(statistics, None);
        let Some(frame) = gate_body(setup, &input[..length]) else {
            ignored(&mut statistics);
            continue;
        };
        let event = admission.gate.receive(
            src_addr,
            frame,
            server_nonce,
            elapsed(origin, Instant::now())?,
        )?;
        report.server(admission.statistics());
        match event {
            gate::GateEvent::Retry(retry) => {
                let length = gate_packet(setup, &retry, next_outer, &mut output)?;
                report.bootstrap(statistics, None);
                let accepted = if dynamic_client {
                    timeout_at(deadline, socket.send_to_udp(&output[..length], src_addr))
                        .await
                        .map_err(|_| Error::Deadline)?
                        .is_ok_and(|sent| sent == length)
                        .into()
                } else {
                    send_backing(&mut socket, &output[..length], deadline).await?
                };
                sent(&mut statistics, length, accepted);
                advance(&mut next_outer)?;
                emitted(&mut statistics, length);
                statistics.gate_retries = statistics.gate_retries.saturating_add(1);
                report.bootstrap(statistics, None);
                server_nonce = nonce(entropy)?;
            }
            gate::GateEvent::Accepted(ticket) => {
                if dynamic_client {
                    socket.connect_udp(src_addr).await?;
                }
                break ticket;
            }
            _ => ignored(&mut statistics),
        }
    };
    let session = ticket.session();
    let result = Exchange {
        socket,
        setup,
        identity,
        peers,
        ticket,
        origin,
        deadline,
        statistics,
        next_outer,
        client: None,
    }
    .run(entropy, Some(admission), report, selection, tuning)
    .await;
    admission
        .gate
        .finish(session, elapsed(origin, Instant::now())?)?;
    result
}

struct Exchange<R: RawBacking> {
    socket: SocketBacking<R>,
    setup: Setup,
    identity: Identity,
    peers: Peers,
    ticket: gate::PathTicket,
    origin: Instant,
    deadline: Instant,
    statistics: Statistics,
    next_outer: u32,
    client: Option<gate::ClientGate>,
}
impl<R: RawBacking> Exchange<R> {
    async fn run(
        mut self,
        entropy: &mut (impl hs::Entropy + Send),
        mut server: Option<&mut ServerAdmission>,
        report: &mut Reporter<'_, '_>,
        selection: Option<hs::refresh::Selection>,
        mut tuning: Tuning<'_>,
    ) -> Result<EstablishedState<R>, Error> {
        report.stage(Stage::Noise);
        let role = if self.client.is_some() {
            hs::Role::Initiator
        } else {
            hs::Role::Responder
        };
        let session = self.ticket.session();
        let authenticated = session_binding(self.setup, session)?;
        let mut core = Core::new(
            self.setup,
            self.ticket,
            self.origin,
            self.deadline,
            self.statistics,
        )?;
        report.bootstrap(
            core.statistics,
            core.control.as_ref().map(gate::ControlEngine::statistics),
        );
        let config = hs::Config {
            role,
            profile: self.setup.config.profile,
            binding: authenticated,
            deadline: hs_time(self.origin, core.end)?,
        };
        let now = hs_time(self.origin, Instant::now())?;
        let mut handshake = match selection {
            Some(selection) => hs::Handshake::new_refreshable(
                config,
                selection,
                self.identity.local,
                self.identity.peer,
                self.identity.psk,
                now,
                entropy,
            )?,
            None => hs::Handshake::new(
                config,
                self.identity.local,
                self.identity.peer,
                self.identity.psk,
                now,
                entropy,
            )?,
        };
        match tuning {
            Tuning::Off => {}
            Tuning::Propose { proposal, context } if role == hs::Role::Initiator => {
                if proposal.is_empty() {
                    return Err(Error::Configuration("empty live-tuning proposal"));
                }
                handshake.set_initiation_payload(proposal)?;
                handshake.set_confirmation_context(context)?;
            }
            Tuning::Judge(_) if role == hs::Role::Responder => {}
            _ => return Err(Error::Configuration("live-tuning role")),
        }
        // A refused proposal: the responder still delivers its verdict in
        // message 2 and then ends; the initiator ends on reading it.
        let mut refused: Option<live_tuning::Refusal> = None;
        let mut parser = Parser::new();
        let mut pending = vec![0; MAX_FRAME_BYTES];
        let mut pending_len = 0;
        let mut pending_sent = 0;
        let mut peer_confirmation = [0; MAX_CONFIRM_BYTES];
        let mut peer_confirmation_len = 0;
        let mut quota = Quota::new(self.setup.config, Instant::now())?;
        let mut input = vec![
            0;
            self.socket.receive_capacity(
                self.setup.config.cover.limits().max_packet_bytes
            )?
        ];
        let mut output = vec![0; self.setup.config.cover.limits().max_packet_bytes];
        let mut server_nonce = if server.is_some() {
            Some(nonce(entropy)?)
        } else {
            None
        };
        loop {
            report.bootstrap(
                core.statistics,
                core.control.as_ref().map(gate::ControlEngine::statistics),
            );
            if let Some(server) = server.as_deref() {
                report.server(server.statistics());
            }
            let now = Instant::now();
            if let Err(error) = before(now, core.end) {
                return Err(refused.map_or(error, Error::Tuning));
            }
            loop {
                if pending_sent == pending_len {
                    let Some(next) = handshake.next_flight() else {
                        break;
                    };
                    if refused.is_some() && next != hs::FlightKind::Response {
                        break;
                    }
                    let flight = handshake.write(hs_time(self.origin, now)?, &mut pending[4..])?;
                    let length = u16::try_from(flight.bytes)
                        .map_err(|_| Error::Protocol)?
                        .to_be_bytes();
                    pending[..4].copy_from_slice(&[
                        1,
                        flight_kind(flight.kind),
                        length[0],
                        length[1],
                    ]);
                    pending_len = 4 + flight.bytes;
                    pending_sent = 0;
                    core.statistics.noise_flights = core.statistics.noise_flights.saturating_add(1);
                    report.bootstrap(
                        core.statistics,
                        core.control.as_ref().map(gate::ControlEngine::statistics),
                    );
                }
                // A frame larger than one ARQ source continues in the next.
                let written = core.control.as_mut().ok_or(Error::Protocol)?.write(
                    &pending[pending_sent..pending_len],
                    elapsed(self.origin, now)?,
                )?;
                if written == 0 {
                    break;
                }
                pending_sent += written;
            }
            if let Some(client) = &mut self.client
                && let Some(frame) = client.poll(elapsed(self.origin, now)?)?
            {
                let length = gate_packet(self.setup, &frame, self.next_outer, &mut output)?;
                report.bootstrap(
                    core.statistics,
                    core.control.as_ref().map(gate::ControlEngine::statistics),
                );
                let accepted = send_backing(&mut self.socket, &output[..length], core.end).await?;
                sent(&mut core.statistics, length, accepted);
                advance(&mut self.next_outer)?;
                emitted(&mut core.statistics, length);
            }
            while let Some(length) =
                core.poll(Instant::now(), metadata(self.next_outer), &mut output)?
            {
                report.bootstrap(
                    core.statistics,
                    core.control.as_ref().map(gate::ControlEngine::statistics),
                );
                let accepted = send_backing(&mut self.socket, &output[..length], core.end).await?;
                sent(&mut core.statistics, length, accepted);
                advance(&mut self.next_outer)?;
            }
            if let Some(refusal) = refused {
                let delivered = pending_sent == pending_len
                    && handshake.next_flight() != Some(hs::FlightKind::Response)
                    && core
                        .control
                        .as_ref()
                        .is_none_or(gate::ControlEngine::drained);
                if role == hs::Role::Initiator || delivered {
                    return Err(Error::Tuning(refusal));
                }
            }
            if handshake.is_complete() && pending_sent == pending_len {
                before(Instant::now(), core.end)?;
                let now = hs_time(self.origin, Instant::now())?;
                let (material, confirmation) = if selection.is_some() {
                    let confirmed = handshake.finish_refreshable_with_confirmation(now)?;
                    (
                        InitialMaterial::Managed(confirmed.initial),
                        confirmed.confirmation,
                    )
                } else {
                    let confirmed = handshake.finish_with_confirmation(now)?;
                    (
                        InitialMaterial::Legacy(confirmed.root),
                        confirmed.confirmation,
                    )
                };
                let binding = material.binding();
                let statistics = core.statistics;
                report.bootstrap(
                    statistics,
                    core.control.as_ref().map(gate::ControlEngine::statistics),
                );
                let actual_peer = self
                    .socket
                    .peer_addr()
                    .unwrap_or_else(|_| peer(self.setup.gate.path, role));
                let tail = BootstrapTail {
                    core,
                    confirmation: Some(confirmation),
                    peer_confirmation,
                    peer_confirmation_len,
                    parser,
                    peer: actual_peer,
                };
                return Ok(EstablishedState {
                    socket: self.socket,
                    material,
                    binding,
                    authenticated,
                    peers: self.peers,
                    cover: self.setup.config.cover,
                    tail,
                    next_outer: self.next_outer,
                    deadline: self.deadline,
                    statistics,
                    origin: self.origin,
                });
            }
            let now = Instant::now();
            let ready = quota.ready(now)?;
            let mut wake = core.deadline().unwrap_or(core.end).min(core.end);
            if self.client.is_some() {
                wake = wake.min(
                    now.checked_add(self.setup.gate.interval)
                        .ok_or(Error::Deadline)?,
                );
            }
            if !ready {
                wake = wake.min(quota.refill);
            }
            if wake <= now {
                wake = now
                    .checked_add(self.setup.gate.interval)
                    .ok_or(Error::Deadline)?
                    .min(core.end);
            }
            report.bootstrap(
                core.statistics,
                core.control.as_ref().map(gate::ControlEngine::statistics),
            );
            if let Some(server) = server.as_deref() {
                report.server(server.statistics());
            }
            tokio::select! {
                received = self.socket.recv(&mut input), if ready => {
                    let now = Instant::now();
                    before(now, core.end)?;
                    quota.charge();
                    let Some(length) = received_length(received, &mut core.statistics)? else { continue; };
                    core.statistics.received_datagrams = core.statistics.received_datagrams.saturating_add(1);
                    report.bootstrap(core.statistics, core.control.as_ref().map(gate::ControlEngine::statistics));
                    let decoded = match self.setup.config.cover.decode(&input[..length]) {
                        Ok(decoded) if decoded.phase == cover::Phase::Handshake => decoded,
                        _ => { ignored(&mut core.statistics); continue; }
                    };
                    let actual_peer = self
                        .socket
                        .peer_addr()
                        .unwrap_or_else(|_| peer(self.setup.gate.path, role));
                    if decoded.protected.first() == Some(&GATE_TAG) {
                        if let Some(server) = server.as_deref_mut()
                            && decoded.protected.len() == 1 + gate::GATE_BYTES {
                                let fresh_nonce = server_nonce.ok_or(Error::Protocol)?;
                                match server.gate.receive(actual_peer, &decoded.protected[1..], fresh_nonce, elapsed(self.origin, now)?)? {
                                    gate::GateEvent::Retry(frame) => {
                                        let length = gate_packet(self.setup, &frame, self.next_outer, &mut output)?;
                                        report.bootstrap(core.statistics, core.control.as_ref().map(gate::ControlEngine::statistics));
                let accepted = send_backing(&mut self.socket, &output[..length], core.end).await?;
                                        sent(&mut core.statistics, length, accepted);
                                        advance(&mut self.next_outer)?;
                                        emitted(&mut core.statistics, length);
                                        core.statistics.gate_retries = core.statistics.gate_retries.saturating_add(1);
                                        server_nonce = Some(nonce(entropy)?);
                                    }
                                    gate::GateEvent::Accepted(ticket) => server.gate.finish(ticket.session(), elapsed(self.origin, now)?)?,
                                    _ => {}
                                }
                        }
                        ignored(&mut core.statistics);
                        continue;
                    }
                    let Some(outcome) = core.receive_peer(decoded.protected, actual_peer, now)? else { ignored(&mut core.statistics); continue; };
                    if outcome == gate::ReceiveOutcome::Fresh
                        && let Some(client) = &mut self.client {
                        client.confirm_peer_control(elapsed(self.origin, now)?)?;
                    }
                    report.bootstrap(core.statistics, core.control.as_ref().map(gate::ControlEngine::statistics));
                    while let Some(frame) = parser.read(core.control.as_mut().ok_or(Error::Protocol)?, elapsed(self.origin, now)?)? {
                        report.bootstrap(core.statistics, core.control.as_ref().map(gate::ControlEngine::statistics));
                        let outcome = handshake.read(hs_time(self.origin, now)?, frame.kind, &frame.bytes[..frame.length])?;
                        if frame.kind == hs::FlightKind::Confirmation {
                            peer_confirmation[..frame.length].copy_from_slice(&frame.bytes[..frame.length]);
                            peer_confirmation_len = frame.length;
                        }
                        if outcome == hs::ReadOutcome::Accepted {
                            refused = refused.or(judge(&mut handshake, &mut tuning, role, frame.kind)?);
                        }
                        if outcome == hs::ReadOutcome::Duplicate { core.statistics.noise_duplicates = core.statistics.noise_duplicates.saturating_add(1); }
                    }
                }
                _ = sleep_until(wake) => {}
            }
        }
    }
}

fn setup(config: Config, peers: Peers) -> Result<Setup, Error> {
    setup_with_extra(config, peers, 0)
}
fn setup_with_extra(config: Config, peers: Peers, extra: usize) -> Result<Setup, Error> {
    if extra > 1 {
        return Err(Error::Configuration("unsupported carrier overhead"));
    }
    let ip = if config.gate.path.client.is_ipv4() {
        28usize
    } else {
        48usize
    };
    setup_with_physical_overhead(
        config,
        peers,
        ip.checked_add(extra)
            .ok_or(Error::Configuration("carrier overhead"))?,
    )
}
fn setup_with_physical_overhead(
    config: Config,
    peers: Peers,
    physical: usize,
) -> Result<Setup, Error> {
    if !(1..=4096).contains(&config.receive_packets_per_interval)
        || !(FRAME_BYTES..=4096).contains(&config.gate.arq.max_source_bytes)
        || peers.initiator == peers.responder
    {
        return Err(Error::Configuration("bounded bootstrap selection"));
    }
    let minimum = if config.gate.path.client.is_ipv4() {
        28
    } else {
        48
    };
    if physical < minimum || physical >= config.gate.path_mtu {
        return Err(Error::Configuration("actual physical geometry"));
    }
    let cover_bytes = match config.cover.appearance() {
        cover::Appearance::QuicLike => 30,
        cover::Appearance::MediaLike => cover::MEDIA_OVERHEAD,
        cover::Appearance::TlsLike => cover::TLS_OVERHEAD,
    };
    let protected = config
        .gate
        .arq
        .max_source_bytes
        .checked_add(gate::CONTROL_OVERHEAD + l2tunnel_recovery::DATA_HEADER_BYTES + 1)
        .ok_or(Error::Configuration("bootstrap lengths"))?;
    let actual_overhead = config.cover.overhead(cover::Phase::Handshake, protected)?;
    let max_wire = protected
        .checked_add(actual_overhead)
        .ok_or(Error::Configuration("covered lengths"))?;
    if config.gate.outer_overhead != physical + 1 + cover_bytes
        || actual_overhead != cover_bytes
        || config
            .cover
            .overhead(cover::Phase::Handshake, gate::GATE_BYTES + 1)?
            != cover_bytes
        || max_wire > config.cover.limits().max_packet_bytes
        || max_wire
            .checked_add(physical)
            .is_none_or(|bytes| bytes > config.gate.path_mtu)
    {
        return Err(Error::Configuration("exact bootstrap cover/MTU accounting"));
    }
    let mut context = digest::Context::new(&digest::SHA256);
    context.update(b"l2tunnel/secure-udp-establish/v1\0");
    context.update(&config.gate.base_profile);
    context.update(&[
        GATE_TAG,
        CONTROL_TAG,
        1,
        1,
        2,
        3,
        match config.profile {
            hs::Profile::Ik => 1,
            hs::Profile::IkPsk2 => 2,
        },
        match config.cover.appearance() {
            cover::Appearance::QuicLike => 1,
            cover::Appearance::MediaLike => 2,
            cover::Appearance::TlsLike => 3,
        },
    ]);
    for field in [
        config.binding.configuration,
        config.binding.carrier,
        config.binding.outer,
        config.binding.member,
        peers.initiator.0,
        peers.responder.0,
    ] {
        context.update(&field);
    }
    for value in [
        config.cover.limits().max_packet_bytes as u64,
        config.cover.limits().max_protected_bytes as u64,
        u64::from(config.receive_packets_per_interval),
    ] {
        context.update(&value.to_be_bytes());
    }
    let mut gate = config.gate;
    gate.base_profile.copy_from_slice(context.finish().as_ref());
    gate.profile_digest()?;
    Ok(Setup {
        config,
        gate,
        max_wire,
    })
}
fn session_binding(setup: Setup, session: [u8; 16]) -> Result<hs::Binding, Error> {
    Ok(hs::Binding {
        session: hs::SessionId(session),
        configuration: setup.config.binding.configuration,
        carrier: setup.config.binding.carrier,
        outer: outer_binding(setup, session)?,
        member: setup.config.binding.member,
    })
}
fn outer_binding(setup: Setup, session: [u8; 16]) -> Result<[u8; 32], Error> {
    let mut context = digest::Context::new(&digest::SHA256);
    context.update(b"l2tunnel/secure-udp-noise-outer/v1\0");
    context.update(&setup.config.binding.outer);
    context.update(&setup.gate.profile_digest()?);
    context.update(&session);
    let mut result = [0; 32];
    result.copy_from_slice(context.finish().as_ref());
    Ok(result)
}
fn socket_path<R: RawBacking>(
    socket: &SocketBacking<R>,
    path: gate::Path,
    role: hs::Role,
) -> Result<(), Error> {
    if path.is_dynamic_client() {
        match role {
            hs::Role::Initiator => {
                let local = socket.local_addr()?;
                if local.is_ipv4() != path.client.is_ipv4()
                    || local.port() == 0
                    || socket.peer_addr()? != path.server
                {
                    return Err(Error::Configuration("actual dynamic client UDP path"));
                }
            }
            hs::Role::Responder => {
                if socket.local_addr()? != path.server {
                    return Err(Error::Configuration("actual dynamic responder UDP bind"));
                }
            }
        }
        return Ok(());
    }
    let (local, remote) = match role {
        hs::Role::Initiator => (path.client, path.server),
        hs::Role::Responder => (path.server, path.client),
    };
    if socket.local_addr()? != local || socket.peer_addr()? != remote {
        return Err(Error::Configuration("actual fixed connected UDP path"));
    }
    Ok(())
}
fn peer(path: gate::Path, role: hs::Role) -> SocketAddr {
    if role == hs::Role::Initiator {
        path.server
    } else {
        path.client
    }
}
fn nonce(entropy: &mut impl hs::Entropy) -> Result<[u8; 16], Error> {
    let mut material = zeroize::Zeroizing::new([0; 32]);
    entropy.fill(&mut material).map_err(|_| Error::Entropy)?;
    let mut nonce = [0; 16];
    nonce.copy_from_slice(&material[..16]);
    if nonce == [0; 16] {
        return Err(Error::Entropy);
    }
    Ok(nonce)
}
fn elapsed(origin: Instant, now: Instant) -> Result<Duration, Error> {
    now.checked_duration_since(origin).ok_or(Error::Deadline)
}
fn hs_time(origin: Instant, now: Instant) -> Result<hs::Time, Error> {
    Ok(hs::Time(
        u64::try_from(elapsed(origin, now)?.as_micros()).map_err(|_| Error::Deadline)?,
    ))
}
fn before(now: Instant, deadline: Instant) -> Result<(), Error> {
    if now >= deadline {
        Err(Error::Deadline)
    } else {
        Ok(())
    }
}
/// Live-tuning step after an accepted flight: the responder judges a carried
/// proposal and sets its verdict; the initiator reads the verdict. Returns
/// the refusal, if any.
fn judge(
    handshake: &mut hs::Handshake,
    tuning: &mut Tuning<'_>,
    role: hs::Role,
    kind: hs::FlightKind,
) -> Result<Option<live_tuning::Refusal>, Error> {
    if handshake.initiation_payload().is_empty() {
        return Ok(None);
    }
    match (role, kind) {
        (hs::Role::Responder, hs::FlightKind::Initiation) => {
            let proposal = handshake.initiation_payload().to_vec();
            let verdict = match tuning {
                Tuning::Judge(judge) => judge(&proposal),
                _ => Err(live_tuning::Refusal::NotOffered),
            };
            handshake.set_response_payload(&live_tuning::encode_verdict(verdict.map(|_| ())))?;
            match verdict {
                Ok(root) => {
                    handshake.set_confirmation_context(root)?;
                    Ok(None)
                }
                Err(refusal) => Ok(Some(refusal)),
            }
        }
        (hs::Role::Initiator, hs::FlightKind::Response) => {
            Ok(live_tuning::decode_verdict(handshake.response_payload()).err())
        }
        _ => Ok(None),
    }
}
fn flight_kind(kind: hs::FlightKind) -> u8 {
    match kind {
        hs::FlightKind::Initiation => 1,
        hs::FlightKind::Response => 2,
        hs::FlightKind::Confirmation => 3,
    }
}
fn metadata(number: u32) -> cover::PacketMeta {
    cover::PacketMeta {
        phase: cover::Phase::Handshake,
        packet_number: cover::PacketNumber(number),
        media_timestamp: cover::MediaTimestamp(number),
    }
}
fn advance(number: &mut u32) -> Result<(), Error> {
    *number = number
        .checked_add(1)
        .ok_or(Error::Configuration("outer packet counter exhausted"))?;
    Ok(())
}
fn emitted(statistics: &mut Statistics, bytes: usize) {
    statistics.emitted_datagrams = statistics.emitted_datagrams.saturating_add(1);
    statistics.emitted_udp_bytes = statistics.emitted_udp_bytes.saturating_add(bytes as u64);
}
fn ignored(statistics: &mut Statistics) {
    statistics.ignored_datagrams = statistics.ignored_datagrams.saturating_add(1);
}
enum SendAcceptance {
    Socket,
    Maintained,
    Dropped,
}
impl From<bool> for SendAcceptance {
    fn from(accepted: bool) -> Self {
        if accepted {
            Self::Socket
        } else {
            Self::Dropped
        }
    }
}
fn sent(statistics: &mut Statistics, bytes: usize, accepted: impl Into<SendAcceptance>) {
    match accepted.into() {
        SendAcceptance::Socket => {
            statistics.socket_sent_datagrams = statistics.socket_sent_datagrams.saturating_add(1);
            statistics.socket_sent_udp_bytes = statistics
                .socket_sent_udp_bytes
                .saturating_add(bytes as u64);
        }
        SendAcceptance::Maintained => {
            statistics.maintained_accepted_records =
                statistics.maintained_accepted_records.saturating_add(1);
            statistics.maintained_accepted_record_bytes = statistics
                .maintained_accepted_record_bytes
                .saturating_add(bytes as u64);
        }
        SendAcceptance::Dropped => {
            statistics.socket_drops = statistics.socket_drops.saturating_add(1);
        }
    }
}
fn received_length(
    result: io::Result<usize>,
    statistics: &mut Statistics,
) -> Result<Option<usize>, Error> {
    match result {
        Ok(length) => Ok(Some(length)),
        Err(error) if path_loss(&error) => {
            statistics.socket_receive_errors = statistics.socket_receive_errors.saturating_add(1);
            Ok(None)
        }
        Err(error) => Err(error.into()),
    }
}
/// Native path conditions consume a bounded attempt, preserving retained ARQ.
pub(super) fn path_loss(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::WouldBlock
            | io::ErrorKind::ConnectionRefused
            | io::ErrorKind::PermissionDenied
            | io::ErrorKind::HostUnreachable
            | io::ErrorKind::NetworkUnreachable
            | io::ErrorKind::NetworkDown
    )
}
fn gate_packet(
    setup: Setup,
    frame: &gate::GateFrame,
    number: u32,
    output: &mut [u8],
) -> Result<usize, Error> {
    let mut body = [0; gate::GATE_BYTES + 1];
    body[0] = GATE_TAG;
    body[1..].copy_from_slice(frame);
    Ok(setup.config.cover.encode(metadata(number), &body, output)?)
}
fn gate_body(setup: Setup, packet: &[u8]) -> Option<&[u8]> {
    let decoded = setup.config.cover.decode(packet).ok()?;
    (decoded.phase == cover::Phase::Handshake
        && decoded.protected.len() == gate::GATE_BYTES + 1
        && decoded.protected[0] == GATE_TAG)
        .then_some(&decoded.protected[1..])
}
async fn send_backing<R: RawBacking>(
    socket: &mut SocketBacking<R>,
    bytes: &[u8],
    deadline: Instant,
) -> Result<SendAcceptance, Error> {
    match socket {
        SocketBacking::Udp(socket) => send(socket, bytes, deadline).await.map(Into::into),
        SocketBacking::Carrier(_) | SocketBacking::Raw(_) => {
            socket.send_control(bytes, deadline).await?;
            Ok(SendAcceptance::Socket)
        }
        SocketBacking::Maintained(_) => {
            socket.send_control(bytes, deadline).await?;
            Ok(SendAcceptance::Maintained)
        }
    }
}
async fn send(socket: &UdpSocket, bytes: &[u8], deadline: Instant) -> Result<bool, Error> {
    #[cfg(test)]
    {
        let mut accepted = false;
        for packet in tests::outbound(bytes) {
            accepted |= send_exact(socket, &packet, deadline).await?;
        }
        Ok(accepted)
    }
    #[cfg(not(test))]
    {
        send_exact(socket, bytes, deadline).await
    }
}
async fn send_exact(socket: &UdpSocket, bytes: &[u8], deadline: Instant) -> Result<bool, Error> {
    before(Instant::now(), deadline)?;
    #[cfg(test)]
    if let Some(error) = tests::send_error(bytes) {
        return if path_loss(&error) {
            Ok(false)
        } else {
            Err(error.into())
        };
    }
    let result = timeout_at(deadline, socket.send(bytes))
        .await
        .map_err(|_| Error::Deadline)?;
    before(Instant::now(), deadline)?;
    let sent = match result {
        Ok(sent) => sent,
        Err(error) if path_loss(&error) => return Ok(false),
        Err(error) => return Err(error.into()),
    };
    if sent != bytes.len() {
        return Err(Error::Io(io::Error::new(
            io::ErrorKind::WriteZero,
            "incomplete UDP send",
        )));
    }
    Ok(true)
}

#[cfg(test)]
// Fixture construction and assertion failures are test failures, never packet paths.
#[allow(clippy::expect_used, clippy::panic)]
#[path = "establish_tests.rs"]
mod tests;
