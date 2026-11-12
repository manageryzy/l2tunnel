use crate::{Config, Error, Traffic};
use l2tunnel_auth::{
    AuthenticatedIo, ClientTls, Direction, KeyPurpose, MemberAllowlist, MemberKey, ServerTls,
    SessionInfo, TlsIoProfile,
};
use l2tunnel_datagram::{DatagramConfig, KeyContext, PacketOpener, PacketSealer, SessionId};
use l2tunnel_recovery::{EndpointRole, RecoveryContext, SelectiveRepeat};
use l2tunnel_udp_control::{ClientGate, ControlEngine, GateEvent, Secret, ServerGate};
use ring::rand::{SecureRandom, SystemRandom};
use std::{
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::{
    io::DuplexStream,
    net::UdpSocket,
    sync::{OwnedSemaphorePermit, Semaphore, mpsc, oneshot, watch},
    task::JoinHandle,
    time::{Instant, timeout, timeout_at},
};

/// Actual server-verification/member policy plus separately provisioned admission key.
pub struct ClientCredentials<'a> {
    /// Restricted maintained TLS client policy.
    pub tls: &'a ClientTls,
    /// Certificate verification name; it is not sent as SNI.
    pub server_name: &'a str,
    /// Final membership identity, distinct from admission.
    pub member: &'a MemberKey,
    /// Bootstrap permission key, never an asserted TLS exporter.
    pub admission: Secret,
}
/// Actual server certificate, final member allowlist and independent admission keys.
pub struct ServerCredentials<'a> {
    /// Maintained TLS server policy and certificate identity.
    pub tls: &'a ServerTls,
    /// Final membership authorization.
    pub members: &'a MemberAllowlist,
    /// Provisioned bootstrap permission key.
    pub admission: Secret,
    /// Independent server-only return-path cookie key.
    pub cookie: Secret,
}
/// Supervised terminal state; outer traffic cannot reset these outcomes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Terminal {
    /// Explicit protocol, application and actual socket output drain completed.
    Clean,
    /// A finite lifetime/inactivity deadline ended the session.
    Timeout,
    /// Protocol, cryptographic or supervised I/O failure.
    Failed,
    /// Owner cancellation/drop; this is not clean close.
    Cancelled,
    /// Explicit close could not drain every owned handoff in time.
    IncompleteClose,
}
/// Non-secret counters; admission accounting and actual UDP transmission are distinct.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Status {
    /// Actual profile/member success released data capability.
    pub authenticated: bool,
    /// User admission is frozen for distributed close.
    pub closing: bool,
    /// Complete packets admitted into data recovery.
    pub admitted_packets: u64,
    /// Complete packets copied into application receive buffers.
    pub delivered_packets: u64,
    /// Outgoing packets charged before retained socket handoff.
    pub admitted_datagrams: u64,
    /// Exact configured IP bytes charged at admission.
    pub admitted_ip_bytes: u64,
    /// Datagram writes actually accepted by the UDP socket.
    pub transmitted_datagrams: u64,
    /// Authenticated fresh internal TLS heartbeat/control messages.
    pub tls_messages: u64,
    /// Discarded unauthenticated, wrong-tuple or replay input.
    pub discarded_datagrams: u64,
    /// Terminal state, if observed.
    pub terminal: Option<Terminal>,
}
/// Successful explicit close evidence, not produced by dropping a handle.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CloseReceipt {
    /// Final counters after all owned outputs and application handoffs drained.
    pub status: Status,
}

#[derive(Default)]
pub(crate) struct Sources {
    pub sealed: bool,
    pub admitted_bytes: u64,
    pub consumed_bytes: u64,
    pub accepted_prefix: u64,
    pub ceiling: Option<(u64, u64)>,
}
pub(crate) struct State {
    pub sources: Sources,
    pub status: Status,
    pub close_started: Option<Instant>,
    pub data_drained: bool,
    pub tls_finished: bool,
}
pub(crate) struct Shared {
    pub state: Mutex<State>,
    pub terminal: watch::Sender<Option<Terminal>>,
    pub receive_slots: Arc<Semaphore>,
    pub send_slots: Arc<Semaphore>,
}
impl Shared {
    pub fn modify<T>(
        &self,
        operation: impl FnOnce(&mut State) -> Result<T, Error>,
    ) -> Result<T, Error> {
        let mut state = self.state.lock().map_err(|_| Error::Closed)?;
        operation(&mut state)
    }
    pub fn begin_close(&self) -> Result<(), Error> {
        self.modify(|state| {
            state.close_started.get_or_insert_with(Instant::now);
            state.status.closing = true;
            Ok(())
        })
    }
    pub fn finish(&self, reason: Terminal) {
        self.terminal.send_if_modified(|value| {
            if value.is_some() {
                return false;
            }
            *value = Some(reason);
            true
        });
        let actual = *self.terminal.borrow();
        let _ = self.modify(|state| {
            state.status.terminal = actual;
            Ok(())
        });
    }
    pub fn check(&self) -> Result<(), Error> {
        match *self.terminal.borrow() {
            None => Ok(()),
            Some(Terminal::Timeout) => Err(Error::Timeout),
            Some(Terminal::IncompleteClose) => Err(Error::IncompleteClose),
            Some(_) => Err(Error::Closed),
        }
    }
}
pub(crate) fn increment(value: &mut u64) -> Result<(), Error> {
    *value = value
        .checked_add(1)
        .ok_or(Error::Configuration("counter exhausted"))?;
    Ok(())
}
pub(crate) struct Submission {
    pub _slot: OwnedSemaphorePermit,
    pub bytes: Vec<u8>,
    pub reply: oneshot::Sender<Result<(), Error>>,
}
pub(crate) struct Received {
    pub bytes: Vec<u8>,
    pub _slot: OwnedSemaphorePermit,
}
pub(crate) struct DataState {
    pub sealer: PacketSealer,
    pub opener: PacketOpener,
    pub recovery: SelectiveRepeat,
    pub may_send: bool,
    pub may_receive: bool,
    pub context: RecoveryContext,
}
pub(crate) enum Activation {
    Promote(oneshot::Sender<Result<(), Error>>),
    Enable {
        data: Box<DataState>,
        reply: oneshot::Sender<Result<(), Error>>,
    },
}

/// Bounded user packet admission; clones share one common lane and queue.
#[derive(Clone)]
pub struct PacketSender {
    sender: mpsc::Sender<Submission>,
    shared: Arc<Shared>,
    maximum: usize,
    allowed: bool,
}
impl PacketSender {
    /// Wait for bounded admission into recovery. Cancellation after queue insertion
    /// does not retract the accepted packet; it may still be delivered to the peer.
    pub async fn send(&self, packet: &[u8]) -> Result<(), Error> {
        self.shared.check()?;
        if !self.allowed {
            return Err(Error::DirectionDisabled);
        }
        if packet.is_empty() || packet.len() > self.maximum {
            return Err(Error::PacketTooLarge);
        }
        let mut terminal = self.shared.terminal.subscribe();
        let slot = tokio::select! {
            value = self.shared.send_slots.clone().acquire_owned() => value.map_err(|_| Error::Closed)?,
            _ = terminal.changed() => return self.shared.check().and(Err(Error::Closed)),
        };
        let permit = tokio::select! {
            value = self.sender.reserve() => value.map_err(|_| Error::Closed)?,
            _ = terminal.changed() => return self.shared.check().and(Err(Error::Closed)),
        };
        let (reply, result) = oneshot::channel();
        // Serialize close against the actual enqueue, including previously reserved slots.
        self.shared.modify(|state| {
            if state.status.closing || state.status.terminal.is_some() || state.sources.sealed {
                return Err(Error::Closed);
            }
            permit.send(Submission {
                _slot: slot,
                bytes: packet.to_vec(),
                reply,
            });
            Ok(())
        })?;
        tokio::select! {
            value = result => value.map_err(|_| Error::Closed)?,
            _ = terminal.changed() => self.shared.check().and(Err(Error::Closed)),
        }
    }
}
/// Bounded receiver retaining its exact packet and semaphore slot on small output.
pub struct PacketReceiver {
    receiver: mpsc::Receiver<Received>,
    pending: Option<Received>,
    shared: Arc<Shared>,
}
impl PacketReceiver {
    /// Transfer one whole packet into caller ownership. This is not native delivery.
    pub async fn receive(&mut self, output: &mut [u8]) -> Result<usize, Error> {
        self.shared.check()?;
        if self.pending.is_none() {
            let mut terminal = self.shared.terminal.subscribe();
            self.pending = Some(tokio::select! {
                value = self.receiver.recv() => value.ok_or(Error::Closed)?,
                _ = terminal.changed() => return self.shared.check().and(Err(Error::Closed)),
            });
        }
        self.shared.check()?;
        let packet = self.pending.as_ref().ok_or(Error::Closed)?;
        if output.len() < packet.bytes.len() {
            return Err(Error::OutputTooSmall);
        }
        let length = packet.bytes.len();
        self.shared.modify(|state| {
            let count = state
                .status
                .delivered_packets
                .checked_add(1)
                .ok_or(Error::Configuration("source count exhausted"))?;
            let bytes = state
                .sources
                .consumed_bytes
                .checked_add(length as u64)
                .ok_or(Error::Configuration("source bytes exhausted"))?;
            if state
                .sources
                .ceiling
                .is_some_and(|(n, b)| count > n || bytes > b || (count == n && bytes != b))
            {
                return Err(Error::Configuration("source consumption beyond fence"));
            }
            state.status.delivered_packets = count;
            state.sources.consumed_bytes = bytes;
            Ok(())
        })?;
        output[..length].copy_from_slice(&packet.bytes);
        self.pending = None;
        Ok(length)
    }
}

/// Owns both supervised tasks; dropping it cancels data handles and aborts tasks.
pub struct Control {
    pub(crate) shared: Arc<Shared>,
    tasks: Vec<JoinHandle<Result<(), Error>>>,
    close_timeout: Duration,
}
impl Control {
    pub(crate) fn supervise_pair(&mut self, other: &Self) {
        let a = self.shared.clone();
        let b = other.shared.clone();
        self.tasks.push(tokio::spawn(async move {
            let mut ar = a.terminal.subscribe(); let mut br = b.terminal.subscribe();
            loop {
                let av = *ar.borrow(); let bv = *br.borrow();
                if let Some(reason) = av.filter(|v| *v != Terminal::Clean) { b.finish(reason); return Ok(()); }
                if let Some(reason) = bv.filter(|v| *v != Terminal::Clean) { a.finish(reason); return Ok(()); }
                if av == Some(Terminal::Clean) && bv == Some(Terminal::Clean) { return Ok(()); }
                tokio::select! { value = ar.changed(), if av.is_none() => { value.map_err(|_| Error::Closed)?; }, value = br.changed(), if bv.is_none() => { value.map_err(|_| Error::Closed)?; } }
            }
        }));
    }
    /// Snapshot bounded ownership/counter state.
    pub fn status(&self) -> Result<Status, Error> {
        self.shared.modify(|state| Ok(state.status))
    }
    /// Freeze admission and require distributed TLS/data/output/application drain.
    pub async fn close(mut self) -> Result<CloseReceipt, Error> {
        if *self.shared.terminal.borrow() != Some(Terminal::Clean) {
            self.shared.check()?;
        }
        self.shared.begin_close()?;
        let deadline = self.shared.modify(|state| {
            state
                .close_started
                .and_then(|start| start.checked_add(self.close_timeout))
                .ok_or(Error::Configuration("close deadline overflow"))
        })?;
        if Instant::now() >= deadline {
            self.shared.finish(Terminal::IncompleteClose);
            return Err(Error::IncompleteClose);
        }
        let shared = self.shared.clone();
        let mut terminal = shared.terminal.subscribe();
        let completed = timeout_at(deadline, async {
            let reason = loop {
                let value = *terminal.borrow();
                if let Some(value) = value {
                    break value;
                }
                terminal.changed().await.map_err(|_| Error::Closed)?;
            };
            if reason != Terminal::Clean {
                return shared.check().and(Err(Error::Closed));
            }
            // Keep every handle in the owner while awaiting it: cancellation or an
            // earlier failed join must abort both current and not-yet-awaited tasks.
            for (index, task) in self.tasks.iter_mut().enumerate() {
                #[cfg(test)]
                if !task.is_finished() {
                    eprintln!(
                        "CLOSE_JOIN_PENDING shared={:p} task={index} state={:?}",
                        Arc::as_ptr(&shared),
                        shared.modify(|s| Ok((
                            s.status,
                            s.data_drained,
                            s.tls_finished,
                            s.close_started.map(|t| t.elapsed())
                        )))
                    );
                }
                #[cfg(not(test))]
                let _ = index;
                task.await.map_err(|_| Error::Closed)??;
                // timeout_at may poll a ready join before an expired timer. A
                // completed child cannot authorize a later owner completion.
                if Instant::now() >= deadline {
                    return Err(Error::IncompleteClose);
                }
            }
            Ok(())
        })
        .await;
        match completed {
            Ok(result) => result?,
            Err(_) => {
                #[cfg(test)]
                eprintln!(
                    "CLOSE_OWNER_TIMEOUT shared={:p} state={:?} tasks={:?}",
                    Arc::as_ptr(&self.shared),
                    self.shared.modify(|s| Ok((
                        s.status,
                        s.data_drained,
                        s.tls_finished,
                        s.close_started.map(|t| t.elapsed())
                    ))),
                    self.tasks
                        .iter()
                        .map(JoinHandle::is_finished)
                        .collect::<Vec<_>>()
                );
                self.shared.finish(Terminal::IncompleteClose);
                return Err(Error::IncompleteClose);
            }
        }
        if Instant::now() >= deadline {
            self.shared.finish(Terminal::IncompleteClose);
            return Err(Error::IncompleteClose);
        }
        self.tasks.clear(); // All handles are completed; only now may ownership end.
        Ok(CloseReceipt {
            status: self.status()?,
        })
    }
}
impl Drop for Control {
    fn drop(&mut self) {
        self.shared.finish(Terminal::Cancelled);
        for task in &self.tasks {
            task.abort();
        }
    }
}
/// Actual member-authenticated standalone UDP capability and its retained owners.
pub struct Carrier {
    info: SessionInfo,
    control: Control,
    sender: PacketSender,
    receiver: PacketReceiver,
}
impl Carrier {
    /// Actual identities and the canonical accepted configuration.
    pub fn info(&self) -> &SessionInfo {
        &self.info
    }
    /// Transfer all three bounded owners; Control must remain alive for data work.
    pub fn split(self) -> (Control, PacketSender, PacketReceiver) {
        (self.control, self.sender, self.receiver)
    }
}

struct Started {
    io: DuplexStream,
    activate: mpsc::Sender<Activation>,
    control: Control,
    sender: PacketSender,
    receiver: PacketReceiver,
}

pub(crate) struct Prepared {
    pub connection: AuthenticatedIo<DuplexStream>,
    activate: mpsc::Sender<Activation>,
    pub(crate) control: Control,
    sender: PacketSender,
    receiver: PacketReceiver,
    pub config: Config,
    server: bool,
}

/// Establish real admission/TLS/member authentication over this exact UDP socket.
pub async fn client_connect(
    socket: UdpSocket,
    config: Config,
    credentials: ClientCredentials<'_>,
) -> Result<Carrier, Error> {
    let started = Instant::now();
    let budget = super::budget::Budget::new(config.wire_budget, started);
    enable(prepare_client(socket, config, credentials, started, budget).await?).await
}

pub(crate) async fn prepare_client(
    socket: UdpSocket,
    config: Config,
    credentials: ClientCredentials<'_>,
    started: Instant,
    budget: super::budget::Budget,
) -> Result<Prepared, Error> {
    validate_socket(&socket, config, false)?;
    let gate_config = config.gate_config()?;
    let mut gate = ClientGate::new(
        gate_config,
        credentials.admission,
        nonce()?,
        started.elapsed(),
    )?;
    let mut frame = [0; 145];
    let ticket = timeout(gate_config.handshake_timeout, async {
        loop {
            let outgoing = budget.transaction(|budget| {
                if budget.permits(true, gate_config.path_mtu) && let Some(bytes) = gate.poll(started.elapsed())? {
                    budget.charge(true, bytes.len() + gate_config.outer_overhead, None)?;
                    return Ok(Some(bytes));
                }
                Ok(None)
            })?;
            if let Some(bytes) = outgoing {
                if socket.send_to(&bytes, gate_config.path.server).await? != bytes.len() { return Err(Error::Configuration("partial UDP gate write")); }
                budget.gate_sent()?;
            }
            tokio::select! {
                received = socket.recv_from(&mut frame) => {
                    let (length, peer) = received?;
                    if let Some(ticket) = gate.receive_retry(peer, &frame[..length], started.elapsed())? { return Ok::<_, Error>(ticket); }
                }
                _ = tokio::time::sleep(config.poll_interval) => {}
            }
        }
    }).await.map_err(|_| Error::Timeout)??;
    let engine = ControlEngine::new(ticket, started.elapsed())?;
    let parts = start(socket, config, false, engine, Some(gate), started, budget)?;
    let connection = l2tunnel_auth::client_connect_profile_io(
        parts.io,
        credentials.tls,
        credentials.server_name,
        credentials.member,
        config.session_config()?,
        TlsIoProfile::OpenVpnLikeTls,
        config.authentication_timeout,
    )
    .await?;
    prepare(
        parts.activate,
        parts.control,
        parts.sender,
        parts.receiver,
        connection,
        config,
        false,
    )
    .await
}

/// Accept one configured fixed peer; no unbounded wildcard listener is introduced.
pub async fn server_accept(
    socket: UdpSocket,
    config: Config,
    credentials: ServerCredentials<'_>,
) -> Result<Carrier, Error> {
    let started = Instant::now();
    let budget = super::budget::Budget::new(config.wire_budget, started);
    enable(prepare_server(socket, config, credentials, started, budget).await?).await
}

pub(crate) async fn prepare_server(
    socket: UdpSocket,
    config: Config,
    credentials: ServerCredentials<'_>,
    started: Instant,
    budget: super::budget::Budget,
) -> Result<Prepared, Error> {
    validate_socket(&socket, config, true)?;
    let gate_config = config.gate_config()?;
    let mut gate = ServerGate::new(
        gate_config,
        credentials.admission,
        credentials.cookie,
        started.elapsed(),
    )?;
    let mut frame = [0; 145];
    let ticket = timeout(gate_config.handshake_timeout, async {
        loop {
            let (length, peer) = socket.recv_from(&mut frame).await?;
            let event = budget.transaction(|budget| {
                if frame.get(2) == Some(&1) && !budget.permits(true, gate_config.path_mtu) {
                    return Ok(GateEvent::Ignored);
                }
                let event = gate.receive(peer, &frame[..length], nonce()?, started.elapsed())?;
                if let GateEvent::Retry(bytes) = &event {
                    budget.charge(true, bytes.len() + gate_config.outer_overhead, None)?;
                }
                Ok(event)
            })?;
            match event {
                GateEvent::Retry(bytes) => {
                    if socket.send_to(&bytes, gate_config.path.client).await? != bytes.len() {
                        return Err(Error::Configuration("partial UDP gate write"));
                    }
                    budget.gate_sent()?;
                }
                GateEvent::Accepted(ticket) => return Ok::<_, Error>(ticket),
                GateEvent::Ignored | GateEvent::Duplicate(_) => {}
            }
        }
    })
    .await
    .map_err(|_| Error::Timeout)??;
    let engine = ControlEngine::new(ticket, started.elapsed())?;
    let parts = start(socket, config, true, engine, None, started, budget)?;
    let connection = l2tunnel_auth::server_accept_profile_io(
        parts.io,
        credentials.tls,
        credentials.members,
        config.session_config()?,
        TlsIoProfile::OpenVpnLikeTls,
        config.authentication_timeout,
    )
    .await?;
    prepare(
        parts.activate,
        parts.control,
        parts.sender,
        parts.receiver,
        connection,
        config,
        true,
    )
    .await
}

fn start(
    socket: UdpSocket,
    config: Config,
    server: bool,
    engine: ControlEngine,
    gate: Option<ClientGate>,
    started: Instant,
    budget: super::budget::Budget,
) -> Result<Started, Error> {
    let (io, port) = tokio::io::duplex(config.stream_bytes);
    let (terminal, _) = watch::channel(None);
    let shared = Arc::new(Shared {
        state: Mutex::new(State {
            sources: Sources::default(),
            status: Status::default(),
            close_started: None,
            data_drained: false,
            tls_finished: false,
        }),
        terminal,
        receive_slots: Arc::new(Semaphore::new(config.packet_slots)),
        send_slots: Arc::new(Semaphore::new(config.packet_slots)),
    });
    budget.report(&shared)?;
    let (activate, activation) = mpsc::channel(2);
    let (sender, input) = mpsc::channel(config.packet_slots);
    let (output, receiver) = mpsc::channel(config.packet_slots);
    let driver_shared = shared.clone();
    let driver = tokio::spawn(async move {
        let result = super::driver::run(
            socket,
            config,
            server,
            engine,
            gate,
            started,
            port,
            activation,
            input,
            output,
            driver_shared.clone(),
            budget,
        )
        .await;
        if let Err(error) = &result {
            driver_shared.finish(terminal_for(error));
        }
        result
    });
    let allowed = permits(config.profile.traffic, direction(server));
    Ok(Started {
        io,
        activate,
        control: Control {
            shared: shared.clone(),
            tasks: vec![driver],
            close_timeout: config.close_timeout,
        },
        sender: PacketSender {
            sender,
            shared: shared.clone(),
            maximum: config.arq.max_source_bytes,
            allowed,
        },
        receiver: PacketReceiver {
            receiver,
            pending: None,
            shared,
        },
    })
}

// Only this private path receives an actual verified TLS capability and creates keys.
async fn prepare(
    activate: mpsc::Sender<Activation>,
    control: Control,
    sender: PacketSender,
    receiver: PacketReceiver,
    connection: AuthenticatedIo<DuplexStream>,
    config: Config,
    server: bool,
) -> Result<Prepared, Error> {
    if connection.profile() != TlsIoProfile::OpenVpnLikeTls
        || connection.info().config != config.session_config()?
        || connection.info().peer_member.is_some() != server
    {
        return Err(Error::Configuration(
            "actual authentication profile binding",
        ));
    }
    let (reply, ready) = oneshot::channel();
    activate
        .send(Activation::Promote(reply))
        .await
        .map_err(|_| Error::Closed)?;
    timeout(config.authentication_timeout, ready)
        .await
        .map_err(|_| Error::Timeout)?
        .map_err(|_| Error::Closed)??;
    Ok(Prepared {
        connection,
        activate,
        control,
        sender,
        receiver,
        config,
        server,
    })
}

pub(crate) async fn enable(prepared: Prepared) -> Result<Carrier, Error> {
    enable_native(prepared, None).await
}
pub(crate) async fn enable_native(
    prepared: Prepared,
    native: Option<crate::native::Attachment>,
) -> Result<Carrier, Error> {
    let Prepared {
        connection,
        activate,
        mut control,
        sender,
        receiver,
        config,
        server,
    } = prepared;
    let info = *connection.info();
    let send = direction(server);
    let receive = direction(!server);
    let outbound = connection.export_key(
        KeyPurpose::Data,
        auth_direction(send),
        config.profile.lane.0,
    )?;
    let inbound = connection.export_key(
        KeyPurpose::Data,
        auth_direction(receive),
        config.profile.lane.0,
    )?;
    let data = DataState {
        sealer: PacketSealer::new(packet_config(config, info, send), outbound.expose_bytes())?,
        opener: PacketOpener::new(packet_config(config, info, receive), inbound.expose_bytes())?,
        recovery: SelectiveRepeat::new(
            config.arq,
            RecoveryContext {
                session: u128::from_be_bytes(info.session_id),
                epoch: 1,
                role: if server {
                    EndpointRole::Responder
                } else {
                    EndpointRole::Initiator
                },
            },
        )?,
        may_send: permits(config.profile.traffic, send),
        may_receive: permits(config.profile.traffic, receive),
        context: RecoveryContext {
            session: u128::from_be_bytes(info.session_id),
            epoch: 1,
            role: if server {
                EndpointRole::Responder
            } else {
                EndpointRole::Initiator
            },
        },
    };
    let (reply, ready) = oneshot::channel();
    activate
        .send(Activation::Enable {
            data: Box::new(data),
            reply,
        })
        .await
        .map_err(|_| Error::Closed)?;
    timeout(config.authentication_timeout, ready)
        .await
        .map_err(|_| Error::Timeout)?
        .map_err(|_| Error::Closed)??;
    let shared = control.shared.clone();
    control.tasks.push(tokio::spawn(async move {
        let result =
            super::heartbeat::run(connection, config, server, shared.clone(), native).await;
        if let Err(error) = &result {
            shared.finish(terminal_for(error));
        }
        result
    }));
    Ok(Carrier {
        info,
        control,
        sender,
        receiver,
    })
}
pub(crate) fn direction(server: bool) -> l2tunnel_datagram::Direction {
    if server {
        l2tunnel_datagram::Direction::ServerToClient
    } else {
        l2tunnel_datagram::Direction::ClientToServer
    }
}
fn auth_direction(value: l2tunnel_datagram::Direction) -> Direction {
    match value {
        l2tunnel_datagram::Direction::ClientToServer => Direction::ClientToServer,
        l2tunnel_datagram::Direction::ServerToClient => Direction::ServerToClient,
    }
}
fn permits(traffic: Traffic, sender: l2tunnel_datagram::Direction) -> bool {
    traffic == Traffic::FullDuplex || traffic == Traffic::HalfDuplex { sender }
}
fn packet_config(
    config: Config,
    info: SessionInfo,
    direction: l2tunnel_datagram::Direction,
) -> DatagramConfig {
    DatagramConfig {
        context: KeyContext {
            session: SessionId(info.session_id),
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
    }
}
fn validate_socket(socket: &UdpSocket, config: Config, server: bool) -> Result<(), Error> {
    config.validate()?;
    let (local, peer) = if server {
        (config.bootstrap.path.server, config.bootstrap.path.client)
    } else {
        (config.bootstrap.path.client, config.bootstrap.path.server)
    };
    if socket.local_addr()? != local || socket.peer_addr().is_ok_and(|actual| actual != peer) {
        return Err(Error::Configuration(
            "socket differs from fixed authenticated tuple",
        ));
    }
    Ok(())
}
pub(crate) fn nonce() -> Result<[u8; 16], Error> {
    let mut nonce = [0; 16];
    SystemRandom::new()
        .fill(&mut nonce)
        .map_err(|_| Error::Configuration("nonce generation"))?;
    if nonce == [0; 16] {
        return Err(Error::Configuration("zero nonce"));
    }
    Ok(nonce)
}
pub(crate) fn terminal_for(error: &Error) -> Terminal {
    match error {
        Error::Timeout | Error::Control(l2tunnel_udp_control::Error::Expired) => Terminal::Timeout,
        Error::IncompleteClose => Terminal::IncompleteClose,
        _ => Terminal::Failed,
    }
}

#[cfg(test)]
mod supervision_tests {
    use super::*;
    fn control() -> Control {
        let (terminal, _) = watch::channel(None);
        Control {
            shared: Arc::new(Shared {
                state: Mutex::new(State {
                    sources: Sources::default(),
                    status: Status::default(),
                    close_started: None,
                    data_drained: false,
                    tls_finished: false,
                }),
                terminal,
                receive_slots: Arc::new(Semaphore::new(1)),
                send_slots: Arc::new(Semaphore::new(1)),
            }),
            tasks: Vec::new(),
            close_timeout: Duration::from_secs(1),
        }
    }
    #[tokio::test]
    async fn any_failed_lane_revokes_sibling_but_clean_waits_for_both() -> Result<(), Error> {
        for first in [0, 1] {
            let mut a = control();
            let b = control();
            a.supervise_pair(&b);
            if first == 0 {
                a.shared.finish(Terminal::Timeout);
            } else {
                b.shared.finish(Terminal::Timeout);
            }
            timeout(Duration::from_secs(1), async {
                while a.status()?.terminal.is_none() || b.status()?.terminal.is_none() {
                    tokio::task::yield_now().await;
                }
                Ok::<_, Error>(())
            })
            .await
            .map_err(|_| Error::Timeout)??;
            assert_eq!(a.status()?.terminal, Some(Terminal::Timeout));
            assert_eq!(b.status()?.terminal, Some(Terminal::Timeout));
            assert!(
                matches!(a.shared.check(), Err(Error::Timeout))
                    && matches!(b.shared.check(), Err(Error::Timeout))
            );
        }
        let mut a = control();
        let b = control();
        a.supervise_pair(&b);
        a.shared.finish(Terminal::Clean);
        tokio::task::yield_now().await;
        assert_eq!(b.status()?.terminal, None);
        b.shared.finish(Terminal::Clean);
        for task in a.tasks.drain(..) {
            task.await.map_err(|_| Error::Closed)??;
        }
        Ok(())
    }
    struct DropFlag(std::sync::Arc<std::sync::atomic::AtomicBool>);
    impl Drop for DropFlag {
        fn drop(&mut self) {
            self.0.store(true, std::sync::atomic::Ordering::SeqCst);
        }
    }
    async fn pending_owner() -> Result<
        (
            JoinHandle<Result<(), Error>>,
            std::sync::Arc<std::sync::atomic::AtomicBool>,
        ),
        Error,
    > {
        let dropped = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let flag = DropFlag(dropped.clone());
        let (ready, started) = oneshot::channel();
        let task = tokio::spawn(async move {
            let _flag = flag;
            let _ = ready.send(());
            std::future::pending::<Result<(), Error>>().await
        });
        started.await.map_err(|_| Error::Closed)?;
        Ok((task, dropped))
    }
    async fn assert_aborted(
        flags: &[std::sync::Arc<std::sync::atomic::AtomicBool>],
    ) -> Result<(), Error> {
        timeout(Duration::from_secs(1), async {
            while flags
                .iter()
                .any(|flag| !flag.load(std::sync::atomic::Ordering::SeqCst))
            {
                tokio::task::yield_now().await;
            }
        })
        .await
        .map_err(|_| Error::Timeout)
    }
    #[tokio::test]
    async fn expired_original_deadline_rejects_already_clean_ready_owners() -> Result<(), Error> {
        let value = control();
        value.shared.modify(|state| {
            state.close_started = Some(Instant::now() - Duration::from_secs(2));
            state.status.closing = true;
            Ok(())
        })?;
        value.shared.finish(Terminal::Clean);
        // timeout_at polls an already-ready inner future before its timer. Ready
        // terminal state and empty joins therefore need an explicit time check.
        assert!(matches!(value.close().await, Err(Error::IncompleteClose)));
        Ok(())
    }
    #[tokio::test]
    async fn ready_join_after_executor_stall_cannot_finish_past_original_deadline()
    -> Result<(), Error> {
        let mut value = control();
        value.close_timeout = Duration::from_millis(20);
        value.shared.finish(Terminal::Clean);
        // This current-thread runtime first polls close into its pending join.
        // The owned task then deliberately stalls that executor past the bound;
        // timeout_at may next see its ready join before polling the elapsed timer.
        value.tasks.push(tokio::spawn(async {
            std::thread::sleep(Duration::from_millis(40));
            Ok(())
        }));
        assert!(matches!(value.close().await, Err(Error::IncompleteClose)));
        Ok(())
    }
    #[tokio::test]
    async fn earlier_peer_close_bounds_terminal_wait_and_pair_supervisor_join() -> Result<(), Error>
    {
        for clean in [false, true] {
            let mut a = control();
            let b = control();
            a.close_timeout = Duration::from_millis(100);
            a.shared.modify(|state| {
                state.close_started = Some(Instant::now() - Duration::from_millis(80));
                state.status.closing = true;
                Ok(())
            })?;
            if clean {
                a.shared.finish(Terminal::Clean);
                a.supervise_pair(&b);
            }
            let result = timeout(Duration::from_millis(60), a.close())
                .await
                .map_err(|_| Error::Timeout)?;
            assert!(matches!(result, Err(Error::IncompleteClose)));
            assert_eq!(b.status()?.terminal, None);
        }
        Ok(())
    }
    #[tokio::test]
    async fn stalled_join_is_bounded_and_aborts_current_and_remaining_owned_tasks()
    -> Result<(), Error> {
        let mut value = control();
        value.close_timeout = Duration::from_millis(25);
        let (first, a) = pending_owner().await?;
        let (second, b) = pending_owner().await?;
        value.tasks.extend([first, second]);
        value.shared.finish(Terminal::Clean);
        let result = timeout(Duration::from_millis(100), value.close())
            .await
            .map_err(|_| Error::Timeout)?;
        assert!(matches!(result, Err(Error::IncompleteClose)));
        assert_aborted(&[a, b]).await
    }
    #[tokio::test]
    async fn cancelling_during_join_retains_abort_ownership_of_every_task() -> Result<(), Error> {
        let mut value = control();
        let (first, a) = pending_owner().await?;
        let (second, b) = pending_owner().await?;
        value.tasks.extend([first, second]);
        value.shared.finish(Terminal::Clean);
        let closing = tokio::spawn(value.close());
        tokio::time::sleep(Duration::from_millis(5)).await;
        closing.abort();
        assert!(closing.await.is_err());
        assert_aborted(&[a, b]).await
    }
}

#[cfg(test)]
mod source_tests {
    use super::*;
    #[tokio::test]
    async fn receive_ceiling_and_overflow_rejection_preserve_output_and_pending()
    -> Result<(), Error> {
        for overflow in [false, true] {
            let (terminal, _) = watch::channel(None);
            let shared = Arc::new(Shared {
                state: Mutex::new(State {
                    sources: Sources::default(),
                    status: Status::default(),
                    close_started: None,
                    data_drained: false,
                    tls_finished: false,
                }),
                terminal,
                receive_slots: Arc::new(Semaphore::new(1)),
                send_slots: Arc::new(Semaphore::new(1)),
            });
            let (_tx, rx) = mpsc::channel(1);
            let slot = shared
                .receive_slots
                .clone()
                .acquire_owned()
                .await
                .map_err(|_| Error::Closed)?;
            let mut receiver = PacketReceiver {
                receiver: rx,
                pending: Some(Received {
                    bytes: b"held".to_vec(),
                    _slot: slot,
                }),
                shared: shared.clone(),
            };
            shared.modify(|s| {
                if overflow {
                    s.sources.consumed_bytes = u64::MAX;
                } else {
                    s.sources.ceiling = Some((1, 3));
                }
                Ok(())
            })?;
            let mut output = [0xa5; 8];
            assert!(receiver.receive(&mut output).await.is_err());
            assert_eq!(output, [0xa5; 8]);
            assert_eq!(shared.receive_slots.available_permits(), 0);
            assert_eq!(
                receiver.pending.as_ref().ok_or(Error::Closed)?.bytes,
                b"held"
            );
            shared.modify(|s| {
                assert_eq!(s.status.delivered_packets, 0);
                s.sources.consumed_bytes = 0;
                s.sources.ceiling = Some((1, 4));
                Ok(())
            })?;
            assert_eq!(receiver.receive(&mut output).await?, 4);
            assert_eq!(&output[..4], b"held");
            assert_eq!(shared.receive_slots.available_permits(), 1);
        }
        Ok(())
    }
    #[tokio::test]
    async fn sealed_sender_rejects_new_enqueue_even_with_available_reservations()
    -> Result<(), Error> {
        let (terminal, _) = watch::channel(None);
        let shared = Arc::new(Shared {
            state: Mutex::new(State {
                sources: Sources {
                    sealed: true,
                    ..Default::default()
                },
                status: Status::default(),
                close_started: None,
                data_drained: false,
                tls_finished: false,
            }),
            terminal,
            receive_slots: Arc::new(Semaphore::new(1)),
            send_slots: Arc::new(Semaphore::new(1)),
        });
        let (tx, mut rx) = mpsc::channel(1);
        let sender = PacketSender {
            sender: tx,
            shared: shared.clone(),
            maximum: 32,
            allowed: true,
        };
        assert!(matches!(
            sender.send(b"after seal").await,
            Err(Error::Closed)
        ));
        assert!(rx.try_recv().is_err());
        assert_eq!(shared.send_slots.available_permits(), 1);
        Ok(())
    }
}
