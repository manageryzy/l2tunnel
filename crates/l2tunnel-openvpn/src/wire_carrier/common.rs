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

pub(super) mod send;
pub use send::{PendingSend, PhysicalStatus, SendFailure, SendReceipt};

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

/// Exact outer framing observed by the original socket actor, not authentication.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReceiveFraming {
    /// An explicit OpenVPN DataV1 packet, with its opcode removed.
    DataV1,
    /// A selected final record received without an OpenVPN data wrapper.
    Final,
}

/// Untrusted record bytes with the actor's unambiguous outer framing fact.
pub struct Received {
    /// Exact caller record; authentication remains with the common owner.
    pub bytes: Vec<u8>,
    /// Framing selected before stripping any outer bytes.
    pub framing: ReceiveFraming,
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
    output: mpsc::Receiver<Received>,
    actor: JoinHandle<Result<(), Error>>,
    config: Config,
    budget: crate::budget::Budget,
    local: SocketAddr,
    peer: SocketAddr,
    shared: send::Shared,
}
impl Carrier {
    /// Select the disjoint final-record namespace on this actual authenticated owner.
    /// The caller must bind the same selection before Noise/member establishment.
    /// Retained TLS and DataV1 setup tails keep their original absolute cap only.
    pub fn select_final_records(&mut self, setup_deadline: Instant) -> Result<(), Error> {
        before_deadline(setup_deadline)?;
        if setup_deadline > self.shared.expires {
            return Err(Error::Configuration);
        }
        self.shared
            .final_records
            .set(setup_deadline)
            .map_err(|_| Error::Configuration)
    }
    /// True only after this owner explicitly selected final, unwrapped records.
    pub fn final_records(&self) -> bool {
        self.shared.final_records.get().is_some()
    }
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
    /// Actual whole socket writes, including outer TLS traffic. These overlap
    /// admission counters and must never be added to an inner policy ledger.
    pub fn physical_status(&self) -> Result<PhysicalStatus, Error> {
        self.shared.physical.status()
    }
    /// Original absolute outer lifetime; traffic and ticket retries never renew it.
    pub fn expires(&self) -> Instant {
        self.shared.expires
    }
    /// The original real TLS stream remains available over OpenVPN control records.
    pub fn control(&mut self) -> &mut AuthenticatedIo<DuplexStream> {
        &mut self.connection
    }
    /// Send exact already-protected common bytes, adding only the standard opcode.
    /// Completes after one whole socket write, with no cipher operation or user ARQ.
    /// Local class selection reserves pacing only; cancellation may still send bytes.
    pub async fn send(&self, class: Class, record: &[u8]) -> Result<(), Error> {
        self.validate_send(record, self.shared.expires, self.final_records())?;
        let permit = timeout_at(
            self.shared.expires,
            self.shared.slots(class).acquire_owned(),
        )
        .await
        .map_err(|_| Error::Timeout)?
        .map_err(|_| Error::Closed)?;
        let (submission, pending) = self.submission(
            class,
            record,
            self.shared.expires,
            permit,
            self.final_records(),
        )?;
        let input = if class == Class::Control {
            &self.priority
        } else {
            &self.input
        };
        timeout_at(self.shared.expires, input.send(submission))
            .await
            .map_err(|_| Error::Timeout)?
            .map_err(|_| Error::Closed)?;
        match pending.await {
            Ok(_) => Ok(()),
            Err(SendFailure::Expired { .. }) => Err(Error::Timeout),
            Err(SendFailure::Transport(error)) => Err(error),
            Err(SendFailure::Consumed) => Err(Error::Closed),
        }
    }
    /// Begin one bounded original-cap send without waiting for local capacity.
    /// WouldBlock means no submission, encoding, wire debit or physical write.
    /// Success returns custody only; the move-only ticket reports the whole write.
    pub fn try_send_until(
        &self,
        class: Class,
        record: &[u8],
        deadline: Instant,
    ) -> Result<PendingSend, Error> {
        self.try_send_selected_until(class, record, deadline, self.final_records())
    }
    /// Retain one original DataV1 setup tail under the immutable setup cap.
    pub fn try_send_bootstrap_until(
        &self,
        class: Class,
        record: &[u8],
        deadline: Instant,
    ) -> Result<PendingSend, Error> {
        let deadline = self
            .shared
            .final_records
            .get()
            .map_or(deadline, |cap| deadline.min(*cap));
        self.try_send_selected_until(class, record, deadline, false)
    }
    fn try_send_selected_until(
        &self,
        class: Class,
        record: &[u8],
        deadline: Instant,
        final_record: bool,
    ) -> Result<PendingSend, Error> {
        let deadline = deadline.min(self.shared.expires);
        self.validate_send(record, deadline, final_record)?;
        let permit = self
            .shared
            .slots(class)
            .try_acquire_owned()
            .map_err(|error| match error {
                tokio::sync::TryAcquireError::NoPermits => {
                    Error::Io(std::io::ErrorKind::WouldBlock.into())
                }
                tokio::sync::TryAcquireError::Closed => Error::Closed,
            })?;
        let (submission, pending) =
            self.submission(class, record, deadline, permit, final_record)?;
        let input = if class == Class::Control {
            &self.priority
        } else {
            &self.input
        };
        input.try_send(submission).map_err(|error| match error {
            mpsc::error::TrySendError::Full(_) => Error::Io(std::io::ErrorKind::WouldBlock.into()),
            mpsc::error::TrySendError::Closed(_) => Error::Closed,
        })?;
        Ok(pending)
    }
    fn validate_send(
        &self,
        record: &[u8],
        deadline: Instant,
        final_record: bool,
    ) -> Result<(), Error> {
        if record.is_empty() || record.len() > self.config.max_record_bytes {
            return Err(Error::Configuration);
        }
        if final_record && (!self.final_records() || !super::actor::final_prefix(record)) {
            return Err(Error::Configuration);
        }
        record
            .len()
            .checked_add(self.config.outer_overhead_bytes - usize::from(final_record))
            .filter(|bytes| *bytes <= self.config.path_mtu)
            .ok_or(Error::Configuration)?;
        before_deadline(deadline)?;
        Ok(())
    }
    fn submission(
        &self,
        class: Class,
        record: &[u8],
        deadline: Instant,
        permit: tokio::sync::OwnedSemaphorePermit,
        final_record: bool,
    ) -> Result<(Submission, PendingSend), Error> {
        self.validate_send(record, deadline, final_record)?;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(record.len())
            .map_err(|_| Error::Allocation)?;
        bytes.extend_from_slice(record);
        before_deadline(deadline)?;
        let (completion, _) = oneshot::channel();
        let (response, receiver) = oneshot::channel();
        Ok((
            Submission {
                bytes,
                final_record,
                control: class == Class::Control,
                completion,
                custody: Some(send::Custody {
                    deadline,
                    class,
                    record_bytes: record.len(),
                    response,
                    _permit: permit,
                }),
            },
            PendingSend {
                response: Some(receiver),
                deadline,
                class,
                record_bytes: record.len(),
            },
        ))
    }
    /// Receive exact untrusted opaque bytes in arrival order; common security must open them.
    /// The caller authenticates and replay-checks them; this substrate does not filter duplicates.
    pub async fn recv(&mut self) -> Result<Vec<u8>, Error> {
        self.recv_framed().await.map(|packet| packet.bytes)
    }
    /// Receive bytes and their original framing without inspecting the inner payload.
    pub async fn recv_framed(&mut self) -> Result<Received, Error> {
        self.output.recv().await.ok_or(Error::Closed)
    }
    /// Poll the unique raw receive owner without adding another reader or queue.
    pub fn poll_recv(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<Vec<u8>, Error>> {
        self.poll_recv_framed(cx)
            .map(|result| result.map(|packet| packet.bytes))
    }
    /// Poll the same bounded queue while preserving its explicit outer framing.
    pub fn poll_recv_framed(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<Received, Error>> {
        self.output
            .poll_recv(cx)
            .map(|packet| packet.ok_or(Error::Closed))
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
    let expires = started
        .checked_add(config.lifetime)
        .ok_or(Error::Configuration)?;
    let shared = send::Shared::new(
        config
            .packet_slots
            .checked_add(2)
            .ok_or(Error::Configuration)?,
        expires,
    );
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
        physical: Some(shared.physical.clone()),
        final_records: Some(shared.final_records.clone()),
        #[cfg(test)]
        user_gate: Some(shared.user_gate.clone()),
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
        raw: Some(shared),
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
    client_connect_from(socket, config, credentials, started, deadline).await
}
/// Retain the accepted operation's original absolute cap across the outer handshake.
/// The configured maximum also applies; neither phase restarts that deadline.
pub async fn client_connect_until(
    socket: UdpSocket,
    config: Config,
    credentials: ClientCredentials<'_>,
    accepted_deadline: Instant,
) -> Result<Carrier, Error> {
    let started = Instant::now();
    let deadline = started
        .checked_add(config.handshake_timeout)
        .ok_or(Error::Configuration)?
        .min(accepted_deadline);
    before_deadline(deadline)?;
    client_connect_from(socket, config, credentials, started, deadline).await
}
async fn client_connect_from(
    socket: UdpSocket,
    config: Config,
    credentials: ClientCredentials<'_>,
    started: Instant,
    deadline: Instant,
) -> Result<Carrier, Error> {
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
    server_accept_from(socket, config, credentials, started, deadline).await
}
/// Server counterpart retaining the same externally accepted original setup cap.
pub async fn server_accept_until(
    socket: UdpSocket,
    config: Config,
    credentials: ServerCredentials<'_>,
    accepted_deadline: Instant,
) -> Result<Carrier, Error> {
    let started = Instant::now();
    let deadline = started
        .checked_add(config.handshake_timeout)
        .ok_or(Error::Configuration)?
        .min(accepted_deadline);
    before_deadline(deadline)?;
    server_accept_from(socket, config, credentials, started, deadline).await
}
async fn server_accept_from(
    socket: UdpSocket,
    config: Config,
    credentials: ServerCredentials<'_>,
    started: Instant,
    deadline: Instant,
) -> Result<Carrier, Error> {
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
    let shared = parts.raw.take().ok_or(Error::Closed)?;
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
        shared,
    };
    before_deadline(deadline)?;
    Ok(carrier)
}

#[cfg(test)]
mod tests;
