//! Explicit original-socket substrate for externally protected common records.
//!
//! Outer TLS/member authentication is retained, but no exporter packet key,
//! PacketSealer or PacketOpener is created. Received opaque bytes are untrusted
//! until the caller's existing common security owner authenticates/replay-checks
//! them. This module does not create Noise, member Parts or a management FSM.
use super::{
    Activation, ClientCredentials, Data, Error, ServerCredentials, Started, Submission, actor,
    before_deadline, control, wire,
};
use crate::WireBudget;
use l2tunnel_auth::{AuthenticatedIo, SessionConfig, SessionInfo, TlsIoProfile};
use l2tunnel_recovery::ArqConfig;
use std::{net::SocketAddr, time::Duration};
use tokio::{
    io::DuplexStream,
    net::UdpSocket,
    sync::{mpsc, oneshot},
    task::JoinHandle,
    time::{Instant, timeout_at},
};

/// Explicit complete outer-wire policy, with no inner cipher/key-use settings.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Config {
    /// Caller's complete common policy binding, retained in actual TLS/member proof.
    pub base: SessionConfig,
    /// Complete physical IP-packet ceiling.
    pub path_mtu: usize,
    /// IP/UDP plus one DataV1 opcode byte: 29 for IPv4 or 49 for IPv6.
    pub outer_overhead_bytes: usize,
    /// Largest opaque nonempty caller record, including its common security bytes.
    pub max_record_bytes: usize,
    /// Existing bounded control-only TLS-fragment recovery.
    pub control_arq: ArqConfig,
    /// Original whole reset plus TLS/member deadline.
    pub handshake_timeout: Duration,
    /// Original absolute control/session lifetime, never extended by traffic.
    pub lifetime: Duration,
    /// Packet count of each bounded User, Control and receive channel.
    pub packet_slots: usize,
    /// Exact bounded TLS byte adapter capacity in each direction.
    pub stream_bytes: usize,
    /// Finite sole-actor timer cadence.
    pub poll_interval: Duration,
    /// Maximum packet/control work per actor wake.
    pub work_limit: usize,
    /// Shared full-IP allowance for outer TLS, common management and user records.
    pub wire_budget: WireBudget,
}
impl Config {
    /// Validate exact raw geometry without reserving an unused protected-data owner.
    pub fn validate(self) -> Result<(), Error> {
        if !matches!(self.outer_overhead_bytes, 29 | 49)
            || !(256..=65535).contains(&self.path_mtu)
            || self.max_record_bytes == 0
            || self
                .max_record_bytes
                .checked_add(self.outer_overhead_bytes)
                .is_none_or(|bytes| bytes > self.path_mtu)
            || self.handshake_timeout.is_zero()
            || self.handshake_timeout > Duration::from_secs(120)
            || self.handshake_timeout > self.lifetime
            || self.lifetime > Duration::from_secs(86400)
            || !(1..=1024).contains(&self.packet_slots)
            || !(1024..=1_048_576).contains(&self.stream_bytes)
            || self.poll_interval.is_zero()
            || self.poll_interval > self.handshake_timeout
            || !(1..=1024).contains(&self.work_limit)
        {
            return Err(Error::Configuration);
        }
        control::Config {
            local: wire::SessionId([0; 8]),
            max_datagram_bytes: self.path_mtu - (self.outer_overhead_bytes - 1),
            arq: self.control_arq,
            lifetime: self.lifetime,
        }
        .validate()?;
        let budget = self.wire_budget;
        if budget.interval.is_zero()
            || budget.interval > Duration::from_secs(1)
            || !(4..=4096).contains(&budget.packets)
            || budget.ip_bytes > 16 * 1024 * 1024
            || !(2..budget.packets).contains(&budget.reserved_control_packets)
            || budget.reserved_control_bytes
                < self.path_mtu.checked_mul(2).ok_or(Error::Configuration)?
            || budget
                .reserved_control_bytes
                .checked_add(self.path_mtu)
                .is_none_or(|bytes| bytes > budget.ip_bytes)
            || budget.maximum_control_packets < budget.reserved_control_packets
            || budget.maximum_control_packets >= budget.packets
        {
            return Err(Error::Configuration);
        }
        Ok(())
    }
    /// Exact separate authentication domain; protected-mode peers cannot fall back here.
    pub fn session_config(self) -> Result<SessionConfig, Error> {
        self.validate()?;
        let mut hash = ring::digest::Context::new(&ring::digest::SHA256);
        hash.update(b"l2tunnel/openvpn-wire/common-opaque/v1/no-tls-auth/data-v1\0");
        hash.update(&self.base.digest.0);
        hash.update(&[match self.base.layer {
            l2tunnel_device::PacketLayer::Ethernet => 1,
            l2tunnel_device::PacketLayer::Ip => 2,
        }]);
        for value in [
            self.path_mtu,
            self.outer_overhead_bytes,
            self.max_record_bytes,
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
        let mut bytes = [0; 32];
        bytes.copy_from_slice(hash.finish().as_ref());
        Ok(SessionConfig {
            layer: self.base.layer,
            digest: l2tunnel_core::ConfigDigest(bytes),
        })
    }
    fn actor(self) -> actor::Settings {
        actor::Settings {
            path_mtu: self.path_mtu,
            ip_overhead: self.outer_overhead_bytes - 1,
            max_source_bytes: self.control_arq.max_source_bytes,
            max_payload_bytes: self.max_record_bytes,
            crypto_bytes: 0,
            poll_interval: self.poll_interval,
            work_limit: self.work_limit,
            receiving: true,
        }
    }
}

/// Trusted local pacing classification; never authentication or peer authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Class {
    /// Ordinary records use the allowance outside the retained control reservation.
    User,
    /// Locally produced common management shares the bounded control allowance.
    Control,
}

/// Retained outer TLS control and unmodified caller-owned common record bytes.
///
/// Incoming records deliberately undergo no authentication/replay acceptance here.
/// The caller must retain exactly one common security owner and enforce its own
/// User/Control and full/half-direction policy after authenticated dispatch.
pub struct Carrier {
    connection: AuthenticatedIo<DuplexStream>,
    input: mpsc::Sender<Submission>,
    priority: mpsc::Sender<Submission>,
    output: mpsc::Receiver<Vec<u8>>,
    actor: JoinHandle<Result<(), Error>>,
    config: Config,
    budget: crate::budget::Budget,
    local: SocketAddr,
    peer: SocketAddr,
}
impl Carrier {
    /// Actual outer TLS/member proof, explicitly distinct from common Noise membership.
    pub fn outer_info(&self) -> &SessionInfo {
        self.connection.info()
    }
    /// Exact original connected UDP endpoint pair.
    pub fn addresses(&self) -> (SocketAddr, SocketAddr) {
        (self.local, self.peer)
    }
    /// Exact effective outer-resource policy authenticated by this separate factory.
    pub fn config(&self) -> Config {
        self.config
    }
    /// Shared exact-IP admissions, without asserting physical peer delivery.
    pub fn wire_status(&self) -> Result<crate::WireStatus, Error> {
        self.budget.status().map_err(Error::Admission)
    }
    /// The original real TLS stream remains available over OpenVPN control records.
    pub fn control(&mut self) -> &mut AuthenticatedIo<DuplexStream> {
        &mut self.connection
    }
    /// Send exact already-protected common bytes, adding only the standard opcode.
    /// Completes after one whole socket write, with no cipher operation or user ARQ.
    /// Local class selection reserves pacing only; cancellation may still send bytes.
    pub async fn send(&self, class: Class, record: &[u8]) -> Result<(), Error> {
        if record.is_empty() || record.len() > self.config.max_record_bytes {
            return Err(Error::Configuration);
        }
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(record.len())
            .map_err(|_| Error::Allocation)?;
        bytes.extend_from_slice(record);
        let (completion, response) = oneshot::channel();
        let input = if class == Class::Control {
            &self.priority
        } else {
            &self.input
        };
        input
            .send(Submission {
                bytes,
                control: class == Class::Control,
                completion,
            })
            .await
            .map_err(|_| Error::Closed)?;
        response.await.map_err(|_| Error::Closed)?
    }
    /// Receive exact untrusted opaque bytes in arrival order; common security must open them.
    /// The caller authenticates and replay-checks them; this substrate does not filter duplicates.
    pub async fn recv(&mut self) -> Result<Vec<u8>, Error> {
        self.output.recv().await.ok_or(Error::Closed)
    }
}
impl Drop for Carrier {
    fn drop(&mut self) {
        self.actor.abort();
    }
}

fn start(
    socket: UdpSocket,
    config: Config,
    role: control::Role,
    started: Instant,
) -> Result<Started, Error> {
    config.validate()?;
    let local = socket.local_addr()?;
    let peer = socket.peer_addr()?;
    if local.is_ipv4() != peer.is_ipv4()
        || config.outer_overhead_bytes != if local.is_ipv4() { 29 } else { 49 }
    {
        return Err(Error::Configuration);
    }
    let mut session = [0; 8];
    ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut session)
        .map_err(|_| Error::Configuration)?;
    let transport = control::Transport::new(
        control::Config {
            local: wire::SessionId(session),
            max_datagram_bytes: config.path_mtu - (config.outer_overhead_bytes - 1),
            arq: config.control_arq,
            lifetime: config.lifetime,
        },
        role,
        Duration::ZERO,
    )?;
    let (io, bridge) = tokio::io::duplex(config.stream_bytes);
    let (input, submissions) = mpsc::channel(config.packet_slots);
    let (priority, priority_input) = mpsc::channel(config.packet_slots);
    let (outputs, output) = mpsc::channel(config.packet_slots);
    let (activation, activate) = mpsc::channel(1);
    let budget = crate::budget::Budget::new(config.wire_budget, started);
    let actor = tokio::spawn(actor::run(actor::Inputs {
        socket,
        settings: config.actor(),
        transport,
        bridge,
        submissions,
        priority: Some(priority_input),
        outputs,
        activate,
        started,
        budget: budget.clone(),
    }));
    Ok(Started {
        io: Some(io),
        activation,
        input: Some(input),
        priority: Some(priority),
        output: Some(output),
        actor: Some(actor),
        local,
        peer,
        budget,
    })
}

/// Explicit client raw-data activation after actual outer reset and verified TLS/member proof.
pub async fn client_connect(
    socket: UdpSocket,
    config: Config,
    credentials: ClientCredentials<'_>,
) -> Result<Carrier, Error> {
    let started = Instant::now();
    let deadline = started
        .checked_add(config.handshake_timeout)
        .ok_or(Error::Configuration)?;
    let mut parts = start(socket, config, control::Role::Client, started)?;
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
    activate(parts, connection, config, deadline).await
}
/// Explicit server counterpart on the originally connected socket, without packet exporter keys.
pub async fn server_accept(
    socket: UdpSocket,
    config: Config,
    credentials: ServerCredentials<'_>,
) -> Result<Carrier, Error> {
    let started = Instant::now();
    let deadline = started
        .checked_add(config.handshake_timeout)
        .ok_or(Error::Configuration)?;
    let mut parts = start(socket, config, control::Role::Server, started)?;
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
    activate(parts, connection, config, deadline).await
}
async fn activate(
    mut parts: Started,
    connection: AuthenticatedIo<DuplexStream>,
    config: Config,
    deadline: Instant,
) -> Result<Carrier, Error> {
    before_deadline(deadline)?;
    let (reply, response) = oneshot::channel();
    let activated = timeout_at(deadline, async {
        parts
            .activation
            .send(Activation {
                data: Data::Opaque,
                reply,
            })
            .await
            .map_err(|_| Error::Closed)?;
        response.await.map_err(|_| Error::Closed)
    })
    .await;
    before_deadline(deadline)?;
    activated.map_err(|_| Error::Timeout)??;
    let carrier = Carrier {
        connection,
        input: parts.input.take().ok_or(Error::Closed)?,
        priority: parts.priority.take().ok_or(Error::Closed)?,
        output: parts.output.take().ok_or(Error::Closed)?,
        actor: parts.actor.take().ok_or(Error::Closed)?,
        config,
        budget: parts.budget.clone(),
        local: parts.local,
        peer: parts.peer,
    };
    before_deadline(deadline)?;
    Ok(carrier)
}

#[cfg(test)]
mod tests;
