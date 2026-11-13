//! Same-connected-socket cookie admission, maintained Noise and final-flight service.
//!
//! This runtime does not establish existing member identity or release user data.
//! The returned bootstrap tail must share the sole session socket reader.

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

/// Handshake-cover tag around an exact legacy admission record.
pub const GATE_TAG: u8 = 0x80;
/// Handshake-cover tag around a complete authenticated bootstrap ARQ packet.
pub const CONTROL_TAG: u8 = 0x81;
const FRAME_BYTES: usize = 100;
const CONFIRM_BYTES: usize = 73;

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
    /// Complete covered packets handed to a bounded socket/send slot.
    pub emitted_datagrams: u64,
    /// Complete covered UDP payload bytes handed off, excluding IP/UDP.
    pub emitted_udp_bytes: u64,
    /// Complete datagrams accepted by the native socket during establishment.
    pub socket_sent_datagrams: u64,
    /// UDP payload bytes accepted by the native socket during establishment.
    pub socket_sent_udp_bytes: u64,
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
    /// Selected bounded appearance codec rejected the operation.
    Cover(cover::Error),
    /// Native socket I/O failed; no retry/default migration is inferred.
    Io(io::Error),
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
        let setup = setup(config, peers)?;
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
    peer_confirmation: [u8; CONFIRM_BYTES],
    parser: Parser,
    peer: SocketAddr,
}
impl BootstrapTail {
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
                    || frame.bytes[..frame.length] != self.peer_confirmation
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
    bytes: [u8; hs::MAX_FLIGHT_BYTES],
    length: usize,
}
struct Parser {
    bytes: [u8; FRAME_BYTES],
    used: usize,
}
impl Parser {
    fn new() -> Self {
        Self {
            bytes: [0; FRAME_BYTES],
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
                let expected = match self.bytes[1] {
                    1 => 96,
                    2 => 48,
                    3 => CONFIRM_BYTES,
                    _ => return Err(Error::Protocol),
                };
                if self.bytes[0] != 1 || length != expected {
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
            let mut bytes = [0; hs::MAX_FLIGHT_BYTES];
            bytes[..length].copy_from_slice(&self.bytes[4..needed]);
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
    let peers = Peers {
        initiator: identity.local.public_key(),
        responder: identity.peer,
    };
    let setup = setup(config, peers)?;
    socket_path(&socket, setup.gate.path, hs::Role::Initiator)?;
    let origin = Instant::now();
    before(origin, deadline)?;
    let mut client = gate::ClientGate::new(setup.gate, admission, nonce(entropy)?, Duration::ZERO)?;
    let mut statistics = Statistics::default();
    let mut next_outer = 0;
    let mut quota = Quota::new(config, origin)?;
    let mut input = vec![0; config.cover.limits().max_packet_bytes + 1];
    let mut output = vec![0; config.cover.limits().max_packet_bytes];
    let ticket = loop {
        let now = Instant::now();
        before(now, deadline)?;
        if let Some(frame) = client.poll(elapsed(origin, now)?)? {
            let length = gate_packet(setup, &frame, next_outer, &mut output)?;
            let accepted = send(&socket, &output[..length], deadline).await?;
            sent(&mut statistics, length, accepted);
            advance(&mut next_outer)?;
            emitted(&mut statistics, length);
        }
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
    .run(entropy, None)
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
    let mut next_outer = 0;
    let mut quota = Quota::new(setup.config, now)?;
    let mut input = vec![0; setup.config.cover.limits().max_packet_bytes + 1];
    let mut output = vec![0; setup.config.cover.limits().max_packet_bytes];
    let mut server_nonce = nonce(entropy)?;
    let ticket = loop {
        let now = Instant::now();
        before(now, deadline)?;
        let ready = quota.ready(now)?;
        let wake = if ready {
            deadline
        } else {
            quota.refill.min(deadline)
        };
        tokio::select! {
            received = socket.recv(&mut input), if ready => {
                before(Instant::now(), deadline)?;
                quota.charge();
                let Some(length) = received_length(received, &mut statistics)? else { continue; };
                statistics.received_datagrams = statistics.received_datagrams.saturating_add(1);
                let Some(frame) = gate_body(setup, &input[..length]) else { ignored(&mut statistics); continue; };
                match admission.gate.receive(setup.gate.path.client, frame, server_nonce, elapsed(origin, Instant::now())?)? {
                    gate::GateEvent::Retry(retry) => {
                        let length = gate_packet(setup, &retry, next_outer, &mut output)?;
                        let accepted = send(&socket, &output[..length], deadline).await?;
                        sent(&mut statistics, length, accepted);
                        advance(&mut next_outer)?;
                        emitted(&mut statistics, length);
                        statistics.gate_retries = statistics.gate_retries.saturating_add(1);
                        server_nonce = nonce(entropy)?;
                    }
                    gate::GateEvent::Accepted(ticket) => break ticket,
                    _ => ignored(&mut statistics),
                }
            }
            _ = sleep_until(wake) => {}
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
    .run(entropy, Some(admission))
    .await;
    admission
        .gate
        .finish(session, elapsed(origin, Instant::now())?)?;
    result
}

struct Exchange {
    socket: UdpSocket,
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
impl Exchange {
    async fn run(
        mut self,
        entropy: &mut (impl hs::Entropy + Send),
        mut server: Option<&mut ServerAdmission>,
    ) -> Result<Established, Error> {
        let role = if self.client.is_some() {
            hs::Role::Initiator
        } else {
            hs::Role::Responder
        };
        let session = self.ticket.session();
        let outer = outer_binding(self.setup, session)?;
        let authenticated = hs::Binding {
            session: hs::SessionId(session),
            configuration: self.setup.config.binding.configuration,
            carrier: self.setup.config.binding.carrier,
            outer,
            member: self.setup.config.binding.member,
        };
        let mut core = Core::new(
            self.setup,
            self.ticket,
            self.origin,
            self.deadline,
            self.statistics,
        )?;
        let mut handshake = hs::Handshake::new(
            hs::Config {
                role,
                profile: self.setup.config.profile,
                binding: authenticated,
                deadline: hs_time(self.origin, core.end)?,
            },
            self.identity.local,
            self.identity.peer,
            self.identity.psk,
            hs_time(self.origin, Instant::now())?,
            entropy,
        )?;
        let mut parser = Parser::new();
        let mut pending = [0; FRAME_BYTES];
        let mut pending_len = 0;
        let mut peer_confirmation = [0; CONFIRM_BYTES];
        let mut quota = Quota::new(self.setup.config, Instant::now())?;
        let mut input = vec![0; self.setup.config.cover.limits().max_packet_bytes + 1];
        let mut output = vec![0; self.setup.config.cover.limits().max_packet_bytes];
        let mut server_nonce = if server.is_some() {
            Some(nonce(entropy)?)
        } else {
            None
        };
        loop {
            let now = Instant::now();
            before(now, core.end)?;
            loop {
                if pending_len == 0 {
                    let Some(_) = handshake.next_flight() else {
                        break;
                    };
                    let flight = handshake.write(hs_time(self.origin, now)?, &mut pending[4..])?;
                    pending[..4].copy_from_slice(&[
                        1,
                        flight_kind(flight.kind),
                        0,
                        flight.bytes as u8,
                    ]);
                    pending_len = 4 + flight.bytes;
                    core.statistics.noise_flights = core.statistics.noise_flights.saturating_add(1);
                }
                let written = core
                    .control
                    .as_mut()
                    .ok_or(Error::Protocol)?
                    .write(&pending[..pending_len], elapsed(self.origin, now)?)?;
                if written == 0 {
                    break;
                }
                if written != pending_len {
                    return Err(Error::Protocol);
                }
                pending_len = 0;
            }
            if let Some(client) = &mut self.client
                && let Some(frame) = client.poll(elapsed(self.origin, now)?)?
            {
                let length = gate_packet(self.setup, &frame, self.next_outer, &mut output)?;
                let accepted = send(&self.socket, &output[..length], core.end).await?;
                sent(&mut core.statistics, length, accepted);
                advance(&mut self.next_outer)?;
                emitted(&mut core.statistics, length);
            }
            while let Some(length) =
                core.poll(Instant::now(), metadata(self.next_outer), &mut output)?
            {
                let accepted = send(&self.socket, &output[..length], core.end).await?;
                sent(&mut core.statistics, length, accepted);
                advance(&mut self.next_outer)?;
            }
            if handshake.is_complete() && pending_len == 0 {
                before(Instant::now(), core.end)?;
                let confirmed =
                    handshake.finish_with_confirmation(hs_time(self.origin, Instant::now())?)?;
                let binding = confirmed.root.binding();
                let statistics = core.statistics;
                let peer = peer(self.setup.gate.path, role);
                let tail = BootstrapTail {
                    core,
                    confirmation: Some(confirmed.confirmation),
                    peer_confirmation,
                    parser,
                    peer,
                };
                return Ok(Established {
                    socket: self.socket,
                    root: confirmed.root,
                    binding,
                    authenticated,
                    peers: self.peers,
                    cover: self.setup.config.cover,
                    tail,
                    next_outer: self.next_outer,
                    deadline: self.deadline,
                    statistics,
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
            tokio::select! {
                received = self.socket.recv(&mut input), if ready => {
                    let now = Instant::now();
                    before(now, core.end)?;
                    quota.charge();
                    let Some(length) = received_length(received, &mut core.statistics)? else { continue; };
                    core.statistics.received_datagrams = core.statistics.received_datagrams.saturating_add(1);
                    let decoded = match self.setup.config.cover.decode(&input[..length]) {
                        Ok(decoded) if decoded.phase == cover::Phase::Handshake => decoded,
                        _ => { ignored(&mut core.statistics); continue; }
                    };
                    if decoded.protected.first() == Some(&GATE_TAG) {
                        if let Some(server) = server.as_deref_mut()
                            && decoded.protected.len() == 1 + gate::GATE_BYTES {
                                let fresh_nonce = server_nonce.ok_or(Error::Protocol)?;
                                match server.gate.receive(self.setup.gate.path.client, &decoded.protected[1..], fresh_nonce, elapsed(self.origin, now)?)? {
                                    gate::GateEvent::Retry(frame) => {
                                        let length = gate_packet(self.setup, &frame, self.next_outer, &mut output)?;
                                        let accepted = send(&self.socket, &output[..length], core.end).await?;
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
                    let Some(outcome) = core.receive_peer(decoded.protected, peer(self.setup.gate.path, role), now)? else { ignored(&mut core.statistics); continue; };
                    if outcome == gate::ReceiveOutcome::Fresh
                        && let Some(client) = &mut self.client {
                        client.confirm_peer_control(elapsed(self.origin, now)?)?;
                    }
                    while let Some(frame) = parser.read(core.control.as_mut().ok_or(Error::Protocol)?, elapsed(self.origin, now)?)? {
                        let outcome = handshake.read(hs_time(self.origin, now)?, frame.kind, &frame.bytes[..frame.length])?;
                        if frame.kind == hs::FlightKind::Confirmation { peer_confirmation.copy_from_slice(&frame.bytes[..frame.length]); }
                        if outcome == hs::ReadOutcome::Duplicate { core.statistics.noise_duplicates = core.statistics.noise_duplicates.saturating_add(1); }
                    }
                }
                _ = sleep_until(wake) => {}
            }
        }
    }
}

fn setup(config: Config, peers: Peers) -> Result<Setup, Error> {
    if !(1..=4096).contains(&config.receive_packets_per_interval)
        || !(FRAME_BYTES..=4096).contains(&config.gate.arq.max_source_bytes)
        || peers.initiator == peers.responder
    {
        return Err(Error::Configuration("bounded bootstrap selection"));
    }
    let ip = if config.gate.path.client.is_ipv4() {
        28
    } else {
        48
    };
    let cover_bytes = match config.cover.appearance() {
        cover::Appearance::QuicLike => 30,
        cover::Appearance::MediaLike => cover::MEDIA_OVERHEAD,
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
    if config.gate.outer_overhead != ip + 1 + cover_bytes
        || actual_overhead != cover_bytes
        || config
            .cover
            .overhead(cover::Phase::Handshake, gate::GATE_BYTES + 1)?
            != cover_bytes
        || max_wire > config.cover.limits().max_packet_bytes
        || max_wire
            .checked_add(ip)
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
fn socket_path(socket: &UdpSocket, path: gate::Path, role: hs::Role) -> Result<(), Error> {
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
fn sent(statistics: &mut Statistics, bytes: usize, accepted: bool) {
    if accepted {
        statistics.socket_sent_datagrams = statistics.socket_sent_datagrams.saturating_add(1);
        statistics.socket_sent_udp_bytes = statistics
            .socket_sent_udp_bytes
            .saturating_add(bytes as u64);
    } else {
        statistics.socket_drops = statistics.socket_drops.saturating_add(1);
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
