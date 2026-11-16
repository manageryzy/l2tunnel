//! Additive actual OpenVPN outer-wire carrier, preserving the historical custom path.
//!
//! Genuine TLS/member trust and existing packet protection are reused. Data remains
//! an opaque selected Swift/management/record body, without mandatory carrier ARQ.
//! Standard endpoint key-method/PUSH negotiation is deliberately not implemented.
use crate::{Profile, WireBudget};
use l2tunnel_auth::{
    AuthenticatedIo, ClientTls, Direction, KeyPurpose, MemberAllowlist, MemberKey, ServerTls,
    SessionConfig, SessionInfo, TlsIoProfile,
};
use l2tunnel_datagram::{DatagramConfig, KeyContext, SessionId};
use l2tunnel_openvpn_wire::{
    self as wire,
    control::{self, Role},
};
use l2tunnel_recovery::ArqConfig;
use std::{net::SocketAddr, time::Duration};
use tokio::{
    io::DuplexStream,
    net::UdpSocket,
    sync::{mpsc, oneshot},
    task::JoinHandle,
    time::{Instant, timeout_at},
};

mod actor;
/// Explicit opaque-record substrate for an external common security owner.
pub mod common;
#[cfg(test)]
mod tests;

/// Explicit complete policy for this additive no-tls-auth OpenVPN UDP profile.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Config {
    /// Existing upper-layer layer/digest, included in actual TLS/member binding.
    pub base: SessionConfig,
    /// Existing protection/lane/key-use policy; outer overhead includes OpenVPN's opcode.
    pub profile: Profile,
    /// Actual control-only TLS-fragment recovery, never user-data reliability.
    pub control_arq: ArqConfig,
    /// Original reset plus TLS/member deadline, without per-phase restart.
    pub handshake_timeout: Duration,
    /// Original retained session/control lifetime, not an idle timeout renewal.
    pub lifetime: Duration,
    /// Each bounded user-data channel's packet slots.
    pub packet_slots: usize,
    /// Each direction's bounded TLS byte adapter.
    pub stream_bytes: usize,
    /// Finite actor timer spacing.
    pub poll_interval: Duration,
    /// Maximum control/packet work per actor wake.
    pub work_limit: usize,
    /// Existing shared control/data full-IP wire admission policy.
    pub wire_budget: WireBudget,
}
impl Config {
    /// Validate exact extra opcode overhead and all finite local ownership bounds.
    pub fn validate(self) -> Result<(), Error> {
        self.profile.canonical().map_err(|_| Error::Configuration)?;
        let overhead = self.profile.outer_overhead_bytes;
        let udp = self
            .profile
            .path_mtu
            .checked_sub(overhead.checked_sub(1).ok_or(Error::Configuration)?)
            .ok_or(Error::Configuration)?;
        control::Config {
            local: wire::SessionId([0; 8]),
            max_datagram_bytes: udp,
            arq: self.control_arq,
            lifetime: self.lifetime,
        }
        .validate()?;
        let budget = self.wire_budget;
        if self.profile.cover != crate::CoverProfile::OpenVpnLike
            || !matches!(overhead, 29 | 49)
            || self.handshake_timeout.is_zero()
            || self.handshake_timeout > Duration::from_secs(120)
            || self.handshake_timeout > self.lifetime
            || self.lifetime > Duration::from_secs(86400)
            || !(1..=1024).contains(&self.packet_slots)
            || !(1024..=1_048_576).contains(&self.stream_bytes)
            || self.poll_interval.is_zero()
            || self.poll_interval > self.handshake_timeout
            || !(1..=1024).contains(&self.work_limit)
            || budget.interval.is_zero()
            || budget.interval > Duration::from_secs(1)
            || !(4..=4096).contains(&budget.packets)
            || budget.ip_bytes > 16 * 1024 * 1024
            || !(2..budget.packets).contains(&budget.reserved_control_packets)
            || budget.reserved_control_bytes
                < self
                    .profile
                    .path_mtu
                    .checked_mul(2)
                    .ok_or(Error::Configuration)?
            || budget
                .reserved_control_bytes
                .checked_add(self.profile.path_mtu)
                .is_none_or(|bytes| bytes > budget.ip_bytes)
            || budget.maximum_control_packets < budget.reserved_control_packets
            || budget.maximum_control_packets >= budget.packets
        {
            return Err(Error::Configuration);
        }
        Ok(())
    }
    /// Domain-separate this exact wire/layout/policy from historical custom bootstrap.
    pub fn session_config(self) -> Result<SessionConfig, Error> {
        self.validate()?;
        let mut hash = ring::digest::Context::new(&ring::digest::SHA256);
        hash.update(b"l2tunnel/openvpn-wire/v1/no-tls-auth/data-v1\0");
        hash.update(&self.base.digest.0);
        hash.update(&[match self.base.layer {
            l2tunnel_device::PacketLayer::Ethernet => 1,
            l2tunnel_device::PacketLayer::Ip => 2,
        }]);
        hash.update(&self.profile.canonical().map_err(|_| Error::Configuration)?);
        for value in [
            self.control_arq.max_source_bytes,
            self.control_arq.send_bytes,
            self.control_arq.receive_bytes,
            self.control_arq.send_records,
            self.control_arq.receive_records,
            self.packet_slots,
            self.stream_bytes,
            self.work_limit,
            self.wire_budget.packets,
            self.wire_budget.ip_bytes,
            self.wire_budget.reserved_control_packets,
            self.wire_budget.reserved_control_bytes,
            self.wire_budget.maximum_control_packets,
        ] {
            hash.update(
                &u64::try_from(value)
                    .map_err(|_| Error::Configuration)?
                    .to_be_bytes(),
            );
        }
        hash.update(&self.control_arq.max_retries.to_be_bytes());
        for time in [
            self.control_arq.initial_rto,
            self.control_arq.maximum_rto,
            self.control_arq.ack_delay,
            self.handshake_timeout,
            self.lifetime,
            self.poll_interval,
            self.wire_budget.interval,
        ] {
            hash.update(&time.as_secs().to_be_bytes());
            hash.update(&time.subsec_nanos().to_be_bytes());
        }
        let digest = hash.finish();
        Ok(SessionConfig {
            layer: self.base.layer,
            digest: l2tunnel_core::ConfigDigest(
                digest
                    .as_ref()
                    .try_into()
                    .map_err(|_| Error::Configuration)?,
            ),
        })
    }
}
/// Typed carrier failures, without secrets or packet bytes.
#[derive(Debug)]
pub enum Error {
    /// Invalid local/profile/connected-socket geometry.
    Configuration,
    /// Real OpenVPN control transport failure.
    Control(control::Error),
    /// Standard packet grammar failure.
    Wire(wire::Error),
    /// Existing maintained TLS/member trust failure.
    Authentication(l2tunnel_auth::Error),
    /// Existing inner AEAD/HMAC/replay/key-use failure.
    Datagram(l2tunnel_datagram::Error),
    /// Existing shared exact wire ledger refused admission.
    Admission(crate::Error),
    /// A bounded local byte allocation failed.
    Allocation,
    /// Bulk data is disabled in this global direction; TLS control remains available.
    DirectionDisabled,
    /// Physical I/O failure.
    Io(std::io::Error),
    /// Original full reset/TLS/member deadline expired.
    Timeout,
    /// Owner is closed, failed or cancelled.
    Closed,
}
impl std::fmt::Display for Error {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(out, "OpenVPN wire carrier: {self:?}")
    }
}
impl std::error::Error for Error {}
impl From<control::Error> for Error {
    fn from(error: control::Error) -> Self {
        Self::Control(error)
    }
}
impl From<wire::Error> for Error {
    fn from(error: wire::Error) -> Self {
        Self::Wire(error)
    }
}
impl From<l2tunnel_auth::Error> for Error {
    fn from(error: l2tunnel_auth::Error) -> Self {
        Self::Authentication(error)
    }
}
impl From<l2tunnel_datagram::Error> for Error {
    fn from(error: l2tunnel_datagram::Error) -> Self {
        Self::Datagram(error)
    }
}
impl From<std::io::Error> for Error {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

/// Client trust remains anchored in our actual certificate roots/name and member key.
pub struct ClientCredentials<'a> {
    /// Existing maintained TLS policy; no accept-all verifier.
    pub tls: &'a ClientTls,
    /// Verified server name, with existing no-SNI behavior preserved.
    pub server_name: &'a str,
    /// Actual existing member proof identity.
    pub member: &'a MemberKey,
}
/// Server identity and actual member authorization policy.
pub struct ServerCredentials<'a> {
    /// Existing maintained TLS certificate policy.
    pub tls: &'a ServerTls,
    /// Actual final member allowlist.
    pub members: &'a MemberAllowlist,
}
struct Submission {
    bytes: Vec<u8>,
    final_record: bool,
    control: bool,
    completion: oneshot::Sender<Result<(), Error>>,
    custody: Option<common::send::Custody>,
}
// Exactly one selected data owner stays inline; opaque activation creates no
// exporter sealer/opener and this tag never grants authentication to input.
#[allow(clippy::large_enum_variant)]
enum Data {
    Protected(crate::data::ProtectedDatagrams),
    Opaque,
}
impl Data {
    fn open<'a>(&'a mut self, packet: &'a [u8]) -> Result<&'a [u8], Error> {
        match self {
            Self::Protected(owner) => owner.open(packet).map_err(Error::Datagram),
            Self::Opaque => Ok(packet),
        }
    }
}
struct Activation {
    data: Data,
    reply: oneshot::Sender<()>,
}

/// Actual authenticated same-socket carrier; data has no implicit recovery algorithm.
pub struct Carrier {
    connection: AuthenticatedIo<DuplexStream>,
    input: mpsc::Sender<Submission>,
    output: mpsc::Receiver<common::Received>,
    actor: JoinHandle<Result<(), Error>>,
    maximum: usize,
    sending: bool,
    local: SocketAddr,
    peer: SocketAddr,
    config: Config,
    budget: crate::budget::Budget,
}
impl Carrier {
    /// Actual TLS/member session observations, not asserted outer session IDs.
    pub fn info(&self) -> &SessionInfo {
        self.connection.info()
    }
    /// Exact original UDP endpoint pair; no second data socket is created.
    pub fn addresses(&self) -> (SocketAddr, SocketAddr) {
        (self.local, self.peer)
    }
    /// Exact effective policy authenticated by the member exchange.
    pub fn config(&self) -> Config {
        self.config
    }
    /// Shared control/data IP-wire admissions, distinct from physical delivery.
    pub fn wire_status(&self) -> Result<crate::WireStatus, Error> {
        self.budget.status().map_err(Error::Admission)
    }
    /// Retained real TLS control stream over OpenVPN control records on that same socket.
    pub fn control(&mut self) -> &mut AuthenticatedIo<DuplexStream> {
        &mut self.connection
    }
    /// Protect and physically submit one opaque upper record, without carrier user ARQ.
    /// Cancellation after queue admission may still permit the owned datagram to send.
    pub async fn send(&self, bytes: &[u8]) -> Result<(), Error> {
        if !self.sending {
            return Err(Error::DirectionDisabled);
        }
        if bytes.is_empty() || bytes.len() > self.maximum {
            return Err(Error::Configuration);
        }
        let (completion, response) = oneshot::channel();
        let mut owned = Vec::new();
        owned
            .try_reserve_exact(bytes.len())
            .map_err(|_| Error::Allocation)?;
        owned.extend_from_slice(bytes);
        self.input
            .send(Submission {
                final_record: false,
                bytes: owned,
                control: false,
                completion,
                custody: None,
            })
            .await
            .map_err(|_| Error::Closed)?;
        response.await.map_err(|_| Error::Closed)?
    }
    /// Receive exact authenticated/replay-checked bytes in arrival order; loss stays visible.
    pub async fn recv(&mut self) -> Result<Vec<u8>, Error> {
        self.output
            .recv()
            .await
            .ok_or(Error::Closed)
            .map(|packet| packet.bytes)
    }
}
impl Drop for Carrier {
    fn drop(&mut self) {
        self.actor.abort();
    }
}

struct Started {
    io: Option<DuplexStream>,
    activation: mpsc::Sender<Activation>,
    input: Option<mpsc::Sender<Submission>>,
    priority: Option<mpsc::Sender<Submission>>,
    output: Option<mpsc::Receiver<common::Received>>,
    actor: Option<JoinHandle<Result<(), Error>>>,
    local: SocketAddr,
    peer: SocketAddr,
    budget: crate::budget::Budget,
    raw: Option<common::send::Shared>,
}
impl Drop for Started {
    fn drop(&mut self) {
        if let Some(actor) = &self.actor {
            actor.abort();
        }
    }
}

fn before_deadline(deadline: Instant) -> Result<(), Error> {
    // A ready future may finish before timeout_at polls its expired timer.
    if Instant::now() >= deadline {
        Err(Error::Timeout)
    } else {
        Ok(())
    }
}

fn start(
    socket: UdpSocket,
    config: Config,
    role: Role,
    started: Instant,
) -> Result<Started, Error> {
    config.validate()?;
    let local = socket.local_addr()?;
    let peer = socket.peer_addr()?;
    if local.is_ipv4() != peer.is_ipv4()
        || config.profile.outer_overhead_bytes != if local.is_ipv4() { 29 } else { 49 }
    {
        return Err(Error::Configuration);
    }
    let mut session = [0; 8];
    ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut session)
        .map_err(|_| Error::Configuration)?;
    let maximum = config.profile.path_mtu - (config.profile.outer_overhead_bytes - 1);
    let transport = control::Transport::new(
        control::Config {
            local: wire::SessionId(session),
            max_datagram_bytes: maximum,
            arq: config.control_arq,
            lifetime: config.lifetime,
        },
        role,
        Duration::ZERO,
    )?;
    let (io, bridge) = tokio::io::duplex(config.stream_bytes);
    let (input, submissions) = mpsc::channel(config.packet_slots);
    let (outputs, output) = mpsc::channel(config.packet_slots);
    let (activation, activate) = mpsc::channel(1);
    let budget = crate::budget::Budget::new(config.wire_budget, started);
    let actor = tokio::spawn(actor::run(actor::Inputs {
        socket,
        settings: actor::Settings {
            path_mtu: config.profile.path_mtu,
            ip_overhead: config.profile.outer_overhead_bytes - 1,
            max_source_bytes: config.control_arq.max_source_bytes,
            max_payload_bytes: config.profile.max_payload_bytes,
            crypto_bytes: maximum,
            poll_interval: config.poll_interval,
            work_limit: config.work_limit,
            receiving: permits(
                config.profile,
                if role == Role::Client {
                    l2tunnel_datagram::Direction::ServerToClient
                } else {
                    l2tunnel_datagram::Direction::ClientToServer
                },
            ),
        },
        transport,
        bridge,
        submissions,
        priority: None,
        outputs,
        activate,
        started,
        budget: budget.clone(),
        physical: None,
        final_records: None,
        #[cfg(test)]
        user_gate: None,
    }));
    Ok(Started {
        io: Some(io),
        activation,
        input: Some(input),
        priority: None,
        output: Some(output),
        actor: Some(actor),
        local,
        peer,
        budget,
        raw: None,
    })
}

/// Reset, real verified TLS/member exchange and protected DataV1 on the original connected UDP socket.
pub async fn client_connect(
    socket: UdpSocket,
    config: Config,
    credentials: ClientCredentials<'_>,
) -> Result<Carrier, Error> {
    let started = Instant::now();
    let deadline = started
        .checked_add(config.handshake_timeout)
        .ok_or(Error::Configuration)?;
    let mut parts = start(socket, config, Role::Client, started)?;
    let session = config.session_config()?;
    before_deadline(deadline)?;
    let io = parts.io.take().ok_or(Error::Closed)?;
    let connection = timeout_at(
        deadline,
        l2tunnel_auth::client_connect_profile_io(
            io,
            credentials.tls,
            credentials.server_name,
            credentials.member,
            session,
            TlsIoProfile::OpenVpnLikeTls,
            config.handshake_timeout,
        ),
    )
    .await;
    before_deadline(deadline)?;
    let connection = connection.map_err(|_| Error::Timeout)??;
    activate(parts, connection, config, false, deadline).await
}
/// Server counterpart; its connected UDP socket accepts only the configured peer tuple.
pub async fn server_accept(
    socket: UdpSocket,
    config: Config,
    credentials: ServerCredentials<'_>,
) -> Result<Carrier, Error> {
    let started = Instant::now();
    let deadline = started
        .checked_add(config.handshake_timeout)
        .ok_or(Error::Configuration)?;
    let mut parts = start(socket, config, Role::Server, started)?;
    let session = config.session_config()?;
    before_deadline(deadline)?;
    let io = parts.io.take().ok_or(Error::Closed)?;
    let connection = timeout_at(
        deadline,
        l2tunnel_auth::server_accept_profile_io(
            io,
            credentials.tls,
            credentials.members,
            session,
            TlsIoProfile::OpenVpnLikeTls,
            config.handshake_timeout,
        ),
    )
    .await;
    before_deadline(deadline)?;
    let connection = connection.map_err(|_| Error::Timeout)??;
    activate(parts, connection, config, true, deadline).await
}
async fn activate(
    mut parts: Started,
    connection: AuthenticatedIo<DuplexStream>,
    config: Config,
    server: bool,
    deadline: Instant,
) -> Result<Carrier, Error> {
    before_deadline(deadline)?;
    let direction = |sending: bool| {
        if sending != server {
            Direction::ClientToServer
        } else {
            Direction::ServerToClient
        }
    };
    let outbound =
        connection.export_key(KeyPurpose::Data, direction(true), config.profile.lane.0)?;
    let inbound =
        connection.export_key(KeyPurpose::Data, direction(false), config.profile.lane.0)?;
    let packet_config = |direction| DatagramConfig {
        context: KeyContext {
            session: SessionId(connection.info().session_id),
            direction,
            lane: config.profile.lane,
            generation: config.profile.generation,
        },
        cover: config.profile.cover,
        protection: config.profile.protection,
        path_mtu: config.profile.path_mtu,
        outer_overhead_bytes: config.profile.outer_overhead_bytes,
        max_payload_bytes: config.profile.max_payload_bytes,
        max_packets_per_key: config.profile.max_packets_per_key,
        max_payload_bytes_per_key: config.profile.max_payload_bytes_per_key,
    };
    let to_datagram = |direction| {
        if direction == Direction::ClientToServer {
            l2tunnel_datagram::Direction::ClientToServer
        } else {
            l2tunnel_datagram::Direction::ServerToClient
        }
    };
    let protected = crate::data::ProtectedDatagrams::new(
        packet_config(to_datagram(direction(true))),
        outbound.expose_bytes(),
        packet_config(to_datagram(direction(false))),
        inbound.expose_bytes(),
    )?;
    before_deadline(deadline)?;
    let (reply, response) = oneshot::channel();
    let activated = timeout_at(deadline, async {
        parts
            .activation
            .send(Activation {
                data: Data::Protected(protected),
                reply,
            })
            .await
            .map_err(|_| Error::Closed)?;
        response.await.map_err(|_| Error::Closed)
    })
    .await;
    before_deadline(deadline)?;
    activated.map_err(|_| Error::Timeout)??;
    let input = parts.input.take().ok_or(Error::Closed)?;
    let output = parts.output.take().ok_or(Error::Closed)?;
    let actor = parts.actor.take().ok_or(Error::Closed)?;
    let direction = if server {
        l2tunnel_datagram::Direction::ServerToClient
    } else {
        l2tunnel_datagram::Direction::ClientToServer
    };
    let sending = permits(config.profile, direction);
    let carrier = Carrier {
        connection,
        input,
        output,
        actor,
        maximum: config.profile.max_payload_bytes,
        sending,
        local: parts.local,
        peer: parts.peer,
        config,
        budget: parts.budget.clone(),
    };
    before_deadline(deadline)?;
    Ok(carrier)
}

fn permits(profile: Profile, direction: l2tunnel_datagram::Direction) -> bool {
    profile.traffic == crate::Traffic::FullDuplex
        || profile.traffic == crate::Traffic::HalfDuplex { sender: direction }
}
