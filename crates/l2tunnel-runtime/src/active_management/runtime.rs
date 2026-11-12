//! Native actor integration; all long-lived stream framing lives in active.
use super::*;
use crate::active::{
    ControlWriter, Event as Input, ExternalOutputs, Frame, LaneMode, ReadProfile, WORK, micros,
};
use crate::{Compression, Link, PacketDevice, PacketLayer};
use l2tunnel_active::observation::{self, Observer as Measurements};
use l2tunnel_active::{
    Active, Direction, ExternalDrain, Micros, PreparedEpoch, RetiredEpoch, RetirementPolicy,
};
use l2tunnel_flow_control::wire::{self, WIRE_LEN};
use l2tunnel_management::transaction::{Effects, Event, Fence, Identity, Peer, Phase, Tick};
use l2tunnel_management::{EndpointId, Ingress, LaneId, Role, SessionId};
use l2tunnel_packet::{FlowKey, classify};
use l2tunnel_pipeline::PipelineError;
use std::collections::{BTreeMap, VecDeque};
use std::fmt;
use tokio::sync::{mpsc, oneshot, watch};
use tokio::task::JoinSet;
use tokio::time::{Instant, MissedTickBehavior, interval};

const SLOTS: usize = 8;

/// Bounded local proposal failure; no error implies a completed switch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ControlError {
    /// One proposal is already pending or queued.
    Busy,
    /// Only the authenticated initiator may propose changes.
    NotCoordinator,
    /// This exact policy was not authenticated in the finite catalog.
    Unsupported,
    /// Peer reconciliation safely aborted before commit.
    Aborted,
    /// Runtime ended or completion was cancelled; success is not implied.
    Closed,
}
impl fmt::Display for ControlError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "active management: {self:?}")
    }
}
impl std::error::Error for ControlError {}

/// Coalesced local state, not a claim of simultaneous peer state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Status {
    /// Latest actual ownership/native/measurement counters.
    pub traffic: active::Status,
    /// Locally committed epoch.
    pub epoch: Epoch,
    /// Locally committed complete mutable policy.
    pub mode: Mode,
    /// Canonical immutable-bound policy digest for this epoch.
    pub digest: ConfigDigest,
    /// Local distributed transaction phase.
    pub phase: Phase,
    /// Native admission gate including Final and actual management flush.
    pub admitting: bool,
    /// Current-epoch originals admitted per negotiated channel; at most 256 entries.
    pub admitted_by_channel: Vec<u64>,
    /// Current-epoch originals handed to the writer per channel.
    pub handed_by_channel: Vec<u64>,
    /// Current-epoch actual native confirmations per channel.
    pub delivered_by_channel: Vec<u64>,
}
struct Request {
    mode: Mode,
    reply: oneshot::Sender<Result<SwitchOutcome, ControlError>>,
}
/// Cloneable bounded local interface; raw peer control injection is unavailable.
#[derive(Clone)]
pub struct ControlHandle {
    sender: mpsc::Sender<Request>,
    state: watch::Receiver<Option<Status>>,
}
impl ControlHandle {
    /// Select an authenticated catalog entry and await both-peer completion.
    pub async fn switch_policy(&self, mode: Mode) -> Result<SwitchOutcome, ControlError> {
        let (reply, response) = oneshot::channel();
        self.sender
            .try_send(Request { mode, reply })
            .map_err(|error| match error {
                mpsc::error::TrySendError::Full(_) => ControlError::Busy,
                mpsc::error::TrySendError::Closed(_) => ControlError::Closed,
            })?;
        response.await.map_err(|_| ControlError::Closed)?
    }
    /// Latest snapshot, absent before validated startup.
    pub fn status(&self) -> Option<Status> {
        self.state.borrow().clone()
    }
    /// Subscribe without retaining an unbounded event history.
    pub fn subscribe(&self) -> watch::Receiver<Option<Status>> {
        self.state.clone()
    }
}
/// Unique runtime endpoint; dropping it fails pending requests and marks stopped.
pub struct ControlReceiver {
    requests: mpsc::Receiver<Request>,
    state: watch::Sender<Option<Status>>,
}
impl Drop for ControlReceiver {
    fn drop(&mut self) {
        self.state.send_modify(|state| {
            if let Some(state) = state {
                state.traffic.running = false;
                state.admitting = false;
            }
        });
    }
}
/// Allocate one queued proposal and one coalesced observation, without I/O.
pub fn channel() -> (ControlHandle, ControlReceiver) {
    let (sender, requests) = mpsc::channel(1);
    let (state, receiver) = watch::channel(None);
    (
        ControlHandle {
            sender,
            state: receiver,
        },
        ControlReceiver { requests, state },
    )
}

struct Output {
    sender: mpsc::Sender<Frame>,
    flushed: watch::Receiver<u64>,
    pending: VecDeque<(u64, Vec<u8>)>,
    produced: u64,
}
impl Output {
    fn send(&mut self, bytes: Vec<u8>) -> io::Result<()> {
        let limits = l2tunnel_management::Limits {
            max_frame_bytes: 4096,
            ..Default::default()
        };
        let frame = l2tunnel_management::Frame::decode(&bytes, limits).map_err(io::Error::other)?;
        let flushed = *self.flushed.borrow();
        while self
            .pending
            .front()
            .is_some_and(|(number, _)| *number <= flushed)
        {
            self.pending.pop_front();
        }
        for (_, existing) in &self.pending {
            let old =
                l2tunnel_management::Frame::decode(existing, limits).map_err(io::Error::other)?;
            if old.header.request == frame.header.request {
                let mut identity = frame.header;
                identity.packet = old.header.packet;
                if identity != old.header || frame.body != old.body {
                    return Err(invalid("conflicting active management retry"));
                }
                return Ok(());
            }
        }
        if self.pending.len() >= SLOTS {
            return Err(invalid("active management output bound"));
        }
        let number = increment(self.produced)?;
        self.sender
            .try_send(Frame {
                kind: 5,
                channel: 0,
                body: bytes.clone(),
            })
            .map_err(|_| invalid("active management writer unavailable"))?;
        self.pending.push_back((number, bytes));
        self.produced = number;
        Ok(())
    }
    fn drained(&self) -> bool {
        self.produced == *self.flushed.borrow()
            && self.sender.capacity() == self.sender.max_capacity()
    }
}

struct Driver {
    peer: Peer<Policy>,
    origin: Ingress,
    role: Role,
    catalog: Catalog,
    staged: Option<PreparedEpoch>,
    retired: Option<RetiredEpoch>,
    drain: Option<(Fence, Fence)>,
    admitted: Vec<u64>,
    handed: Vec<u64>,
    delivered: Vec<u64>,
    pending: Option<oneshot::Sender<Result<SwitchOutcome, ControlError>>>,
    completion: Option<Result<SwitchOutcome, ControlError>>,
    output: Output,
    rate_at: Tick,
    received: u32,
    external: ExternalDrain,
}
fn increment(value: u64) -> io::Result<u64> {
    value
        .checked_add(1)
        .ok_or_else(|| invalid("active management counter exhausted"))
}
fn tick(now: Micros) -> Tick {
    Tick(now.0 / 1000)
}
fn count(values: &mut [u64], channel: u16) -> io::Result<()> {
    let value = values
        .get_mut(usize::from(channel))
        .ok_or_else(|| invalid("active epoch channel bound"))?;
    *value = increment(*value)?;
    Ok(())
}
fn empty(engine: &Active) -> bool {
    let s = engine.status();
    s.queued.packets == 0
        && s.queued.bytes == 0
        && s.sender_retained.records == 0
        && s.receiver_payload.records == 0
        && s.receiver_reserved.records == 0
        && s.outgoing_flows == 0
        && s.incoming_flows == 0
        && s.pending_controls == 0
        && s.pending_retirement.is_none()
        && !s.renewal_required
}
fn external_drain(
    external: &ExternalOutputs,
    flushed: [u64; 3],
    outputs: [&mpsc::Sender<Frame>; 3],
    measurements: &Option<Measurements>,
) -> io::Result<ExternalDrain> {
    let queued = outputs
        .into_iter()
        .map(|output| output.max_capacity() - output.capacity())
        .sum::<usize>()
        + measurements
            .as_ref()
            .map_or(0, Measurements::pending_outputs);
    external.drain(flushed[0], flushed[1], flushed[2], queued)
}
impl Driver {
    fn can_admit(&self, engine: &Active) -> bool {
        self.peer.can_admit_data()
            && self.output.drained()
            && engine.status().pending_retirement.is_none()
    }
    fn effects(
        &mut self,
        mut effects: Effects<Policy>,
        engine: &mut Active,
        settings: &mut active::Settings,
        measurements: &mut Option<Measurements>,
        runtime: RuntimeConfig,
        now: Micros,
    ) -> io::Result<()> {
        for _ in 0..4 {
            if let Some(bytes) = effects.outbound {
                self.output.send(bytes)?;
            }
            match effects.event {
                Some(Event::Stage { ticket, config }) => {
                    if self.staged.is_some() || self.retired.is_some() {
                        return Err(invalid("active epoch staging already occupied"));
                    }
                    let target = active::Settings {
                        channels: config.mode.channels,
                        dscp_weights: config.mode.dscp_weights,
                        ..*settings
                    };
                    let mut next = target.engine_config(runtime, self.peer_session())?;
                    next.epoch = ticket.epoch.0;
                    self.staged = Some(engine.prepare_epoch(next, now).map_err(io::Error::other)?);
                    effects = self
                        .peer
                        .staged(
                            Fence::new(&self.admitted).map_err(io::Error::other)?,
                            tick(now),
                        )
                        .map_err(io::Error::other)?;
                    continue;
                }
                Some(Event::Drain { local, peer }) => {
                    if local.counts() != self.admitted
                        || peer.counts().len() != self.delivered.len()
                        || self
                            .handed
                            .iter()
                            .zip(local.counts())
                            .any(|(got, max)| got > max)
                        || self
                            .delivered
                            .iter()
                            .zip(peer.counts())
                            .any(|(got, max)| got > max)
                    {
                        return Err(invalid("active progress exceeds declared channel fence"));
                    }
                    self.drain = Some((local, peer));
                }
                Some(Event::Committed(_)) => {
                    // The actor only confirms its barrier after all external old
                    // traffic flushed; no new old ownership is created afterward.
                    let staged = self
                        .staged
                        .take()
                        .ok_or_else(|| invalid("missing staged active epoch"))?;
                    self.retired = Some(
                        engine
                            .commit_epoch(staged, now, self.external)
                            .map_err(io::Error::other)?,
                    );
                    let mode = self.peer.active_config().mode;
                    settings.channels = mode.channels;
                    settings.dscp_weights = mode.dscp_weights;
                    *measurements = if settings.adaptive {
                        Some(
                            Measurements::new(settings.observation_config(runtime)?, engine, now)
                                .map_err(io::Error::other)?,
                        )
                    } else {
                        None
                    };
                    self.admitted = vec![0; usize::from(mode.channels)];
                    self.handed = self.admitted.clone();
                    self.delivered = self.admitted.clone();
                }
                Some(Event::Retired(_)) => {
                    self.retired = None;
                    self.drain = None;
                    self.completion = Some(Ok(SwitchOutcome {
                        epoch: self.peer.active_epoch(),
                        digest: configuration_digest(self.peer.active_config())
                            .map_err(io::Error::other)?,
                        mode: self.peer.active_config().mode,
                    }));
                }
                Some(Event::Aborted(_)) => {
                    self.staged = None;
                    self.retired = None;
                    self.drain = None;
                    self.completion = Some(Err(ControlError::Aborted));
                }
                Some(Event::Failed) => return Err(invalid("active policy transaction failed")),
                Some(Event::Uncertain(_)) | None => {}
            }
            return Ok(());
        }
        Err(invalid("active management internal transition bound"))
    }
    fn peer_session(&self) -> u128 {
        match self.origin {
            Ingress::AuthenticatedManagement { session, .. } => u128::from_be_bytes(session.0),
            _ => 0,
        }
    }
    fn observation(
        &self,
        body: &[u8],
        engine: &Active,
        measurements: &mut Option<Measurements>,
        now: Micros,
    ) -> io::Result<()> {
        let message = observation::decode(body).map_err(io::Error::other)?;
        let (scope, incoming, flow) = match message {
            observation::Message::Demand { snapshot, .. } => {
                (snapshot.scope, true, Some(snapshot.flow))
            }
            observation::Message::Ping { scope, .. } => (scope, false, None),
            observation::Message::Pong { scope, .. } => (scope, true, None),
        };
        if let Some(old) = &self.retired
            && scope.epoch == old.epoch()
        {
            let local = if self.role == Role::Client {
                Direction::Forward
            } else {
                Direction::Reverse
            };
            let expected = if incoming {
                if local == Direction::Forward {
                    Direction::Reverse
                } else {
                    Direction::Forward
                }
            } else {
                local
            };
            if scope.session != self.peer_session() || scope.direction != expected {
                return Err(invalid("old observation scope"));
            }
            if let Some(flow) = flow {
                old.check_control(
                    &wire::encode(wire::Message::Open { scope, flow }).map_err(io::Error::other)?,
                )
                .map_err(io::Error::other)?;
            }
            // The complete local barrier already flushed prior Pong/FinalAck.
            // Late optional retries cannot generate new old-epoch ownership.
            return Ok(());
        }
        measurements
            .as_mut()
            .ok_or_else(|| invalid("unnegotiated managed observation"))?
            .receive(engine, body, now)
            .map_err(io::Error::other)
    }
    fn receive(&mut self, body: &[u8], now: Micros, allowance: u32) -> io::Result<Effects<Policy>> {
        if tick(now).0.saturating_sub(self.rate_at.0) >= 1000 {
            self.rate_at = tick(now);
            self.received = 0;
        }
        self.received = self
            .received
            .checked_add(1)
            .ok_or_else(|| invalid("management receive counter"))?;
        if self.received > allowance {
            return Err(invalid("active management input rate bound"));
        }
        match self.peer.receive(self.origin, body, tick(now)) {
            Ok(effects) => Ok(effects),
            Err(transaction::Error::Admission(
                l2tunnel_management::Error::PacketReplay
                | l2tunnel_management::Error::PacketTooOld
                | l2tunnel_management::Error::RequestRetired,
            )) => Ok(Effects::default()),
            Err(error) => Err(io::Error::other(error)),
        }
    }
    fn request(
        &mut self,
        request: Request,
        engine: &Active,
        now: Micros,
    ) -> io::Result<Effects<Policy>> {
        let error = if self.role != Role::Client {
            Some(ControlError::NotCoordinator)
        } else if self.pending.is_some() || !self.can_admit(engine) {
            Some(ControlError::Busy)
        } else if !self
            .catalog
            .policies
            .iter()
            .any(|policy| policy.mode == request.mode)
        {
            Some(ControlError::Unsupported)
        } else {
            None
        };
        if let Some(error) = error {
            let _ = request.reply.send(Err(error));
            return Ok(Effects::default());
        }
        let policy = Policy {
            mode: request.mode,
            ..self.catalog.initial.clone()
        };
        let effects = self
            .peer
            .propose(policy, tick(now))
            .map_err(io::Error::other)?;
        self.pending = Some(request.reply);
        self.completion = None;
        Ok(effects)
    }
    fn finish(&mut self, engine: &Active) {
        if self.can_admit(engine)
            && let Some(result) = self.completion.take()
            && let Some(reply) = self.pending.take()
        {
            let _ = reply.send(result);
        }
    }
}

/// Run authenticated catalog switching on the original full or paired TCP lanes.
/// Only explicit all-flow drain and matching peer commit/retirement reopen admission.
/// Cancellation, EOF, uncertain failure and failed native writes never report success.
pub async fn run<D: PacketDevice<Error = io::Error>>(
    mut device: D,
    mut link: Link,
    runtime: RuntimeConfig,
    config: Config,
    mut control: ControlReceiver,
) -> io::Result<()> {
    let binding = session_config(runtime, &config)?;
    let mut settings = config.initial;
    let (session, direction) = active::logical_session(&link, binding, settings)?;
    if device.layer() != PacketLayer::Ip {
        return Err(invalid("managed active runtime requires TUN"));
    }
    let role = if direction == Direction::Forward {
        Role::Client
    } else {
        Role::Server
    };
    let (local, remote) = if role == Role::Client {
        (EndpointId(1), EndpointId(2))
    } else {
        (EndpointId(2), EndpointId(1))
    };
    let catalog = config.catalog(runtime)?;
    let peer = Peer::new(
        Identity {
            session: SessionId(session),
            role,
            local,
            remote,
            lane: LaneId(0),
        },
        Epoch(1),
        catalog.initial.clone(),
        &catalog.policies,
        config.transaction,
        Tick(0),
    )
    .map_err(io::Error::other)?;
    let origin = Ingress::AuthenticatedManagement {
        session: SessionId(session),
        lane: LaneId(0),
        sender: if role == Role::Client {
            Role::Server
        } else {
            Role::Client
        },
    };
    let engine_config = settings.engine_config(runtime, u128::from_be_bytes(session))?;
    let mut engine = Active::new(engine_config, direction, Micros(0)).map_err(io::Error::other)?;
    let mut measurements = if settings.adaptive {
        Some(
            Measurements::new(settings.observation_config(runtime)?, &engine, Micros(0))
                .map_err(io::Error::other)?,
        )
    } else {
        None
    };
    let codec = runtime.codec()?;
    let maximum = WIRE_LEN + codec.max_encoded_len();
    let (control_tx, mut control_rx) = mpsc::channel(SLOTS);
    let (data_tx, mut data_rx) = mpsc::channel(runtime.queue_packets);
    let (out_control, control_output) = mpsc::channel(SLOTS);
    let (out_data, data_output) = mpsc::channel(runtime.queue_packets);
    let (out_observation, observation_output) = mpsc::channel(SLOTS);
    let (out_management, management_output) = mpsc::channel(SLOTS);
    let (flush_tx, flush_rx) = watch::channel(0);
    let (control_flush_tx, control_flush_rx) = watch::channel(0);
    let (observation_flush_tx, observation_flush_rx) = watch::channel(0);
    let (management_flush_tx, management_flush_rx) = watch::channel(0);
    let control_writer = ControlWriter {
        flushed: control_flush_tx,
        observations: Some((observation_output, observation_flush_tx)),
        management: Some((management_output, management_flush_tx)),
    };
    let mut tasks = JoinSet::new();
    if settings.duplex == Duplex::Half {
        let reverse_reader = link
            .reverse_reader
            .take()
            .ok_or_else(|| invalid("missing managed control reader"))?;
        let reverse_writer = link
            .reverse_writer
            .take()
            .ok_or_else(|| invalid("missing managed control writer"))?;
        tasks.spawn(active::read_lane_profile(
            link.reader,
            LaneMode::Bulk,
            session,
            maximum,
            ReadProfile {
                settings,
                management: true,
            },
            control_tx.clone(),
            data_tx.clone(),
        ));
        tasks.spawn(active::read_lane_profile(
            reverse_reader,
            LaneMode::Control,
            session,
            maximum,
            ReadProfile {
                settings,
                management: true,
            },
            control_tx,
            data_tx,
        ));
        tasks.spawn(active::write_lane(
            link.writer,
            session,
            settings,
            None,
            Some(data_output),
            Some(flush_tx),
            None,
        ));
        tasks.spawn(active::write_lane(
            reverse_writer,
            session,
            settings,
            Some(control_output),
            None,
            None,
            Some(control_writer),
        ));
    } else {
        tasks.spawn(active::read_lane_profile(
            link.reader,
            LaneMode::Mixed,
            session,
            maximum,
            ReadProfile {
                settings,
                management: true,
            },
            control_tx,
            data_tx,
        ));
        tasks.spawn(active::write_lane(
            link.writer,
            session,
            settings,
            Some(control_output),
            Some(data_output),
            Some(flush_tx),
            Some(control_writer),
        ));
    }
    let mut driver = Driver {
        peer,
        origin,
        role,
        catalog,
        staged: None,
        retired: None,
        drain: None,
        admitted: vec![0; usize::from(settings.channels)],
        handed: vec![0; usize::from(settings.channels)],
        delivered: vec![0; usize::from(settings.channels)],
        pending: None,
        completion: None,
        output: Output {
            sender: out_management,
            flushed: management_flush_rx,
            pending: VecDeque::new(),
            produced: 0,
        },
        rate_at: Tick(0),
        received: 0,
        external: ExternalDrain::default(),
    };
    let started = Instant::now();
    let mut ticker = interval(runtime.poll_interval);
    ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
    let mut native = vec![0; l2tunnel_device::READ_BUFFER_BYTES];
    let mut pending = None::<Vec<u8>>;
    let mut weights = BTreeMap::<FlowKey, u32>::new();
    let mut external = ExternalOutputs::default();
    let (mut admitted, mut delivered, mut retired_flows) = (0_u64, 0_u64, 0_u64);
    let mut retiring = None::<FlowKey>;
    let mut feedback = l2tunnel_active::Feedback::default();
    let mut demanding_flows = 0;
    loop {
        let mut request = None;
        let event = tokio::select! {
            Some(result) = tasks.join_next() => return match result { Ok(Err(error)) => Err(error), Err(error) => Err(io::Error::other(error)), Ok(Ok(())) => Err(invalid("active managed task stopped")) },
            Some(event) = control_rx.recv() => Some(event),
            Some(event) = data_rx.recv() => Some(event),
            Some(value) = control.requests.recv() => { request = Some(value); None },
            _ = ticker.tick() => None,
        };
        let now = micros(started.elapsed())?;
        driver.external = external_drain(
            &external,
            [
                *flush_rx.borrow(),
                *control_flush_rx.borrow(),
                *observation_flush_rx.borrow(),
            ],
            [&out_data, &out_control, &out_observation],
            &measurements,
        )?;
        if let Some(request) = request {
            let effects = driver.request(request, &engine, now)?;
            driver.effects(
                effects,
                &mut engine,
                &mut settings,
                &mut measurements,
                runtime,
                now,
            )?;
        }
        if let Some(event) = event {
            match event {
                Input::Management(body) => {
                    let effects =
                        driver.receive(&body, now, settings.control_packets_per_second)?;
                    driver.effects(
                        effects,
                        &mut engine,
                        &mut settings,
                        &mut measurements,
                        runtime,
                        now,
                    )?;
                }
                Input::Control(token) => {
                    let scope = wire::decode(&token).map_err(io::Error::other)?.scope();
                    if let Some(old) = &driver.retired
                        && old.epoch() == scope.epoch
                        && driver.peer.reader(Epoch(scope.epoch)).is_some()
                    {
                        old.check_control(&token).map_err(io::Error::other)?;
                    } else if scope.epoch == driver.peer.active_epoch().0 {
                        engine
                            .receive_control(&token, now)
                            .map_err(io::Error::other)?;
                    } else {
                        return Err(invalid("unknown active control epoch"));
                    }
                }
                Input::Data(channel, body) => {
                    let token = body
                        .get(..WIRE_LEN)
                        .ok_or_else(|| invalid("managed active data token"))?;
                    let encoded = body
                        .get(WIRE_LEN..)
                        .ok_or_else(|| invalid("managed active data body"))?;
                    if runtime.compression == Compression::None && encoded.get(4) != Some(&0) {
                        return Err(invalid("managed active compression mismatch"));
                    }
                    let payload = codec.decode_vec(encoded).map_err(io::Error::other)?;
                    engine
                        .receive_data(token, channel, &payload, now)
                        .map_err(io::Error::other)?;
                }
                Input::Observation(body) => {
                    driver.observation(&body, &engine, &mut measurements, now)?
                }
            }
        }
        if retiring.is_some() && engine.status().pending_retirement.is_none() {
            let key = retiring
                .take()
                .ok_or_else(|| invalid("missing managed retirement key"))?;
            weights
                .remove(&key)
                .ok_or_else(|| invalid("missing managed retirement weight"))?;
            retired_flows = increment(retired_flows)?;
        }
        let mut native_pressure = false;
        for _ in 0..WORK {
            let Some(packet) = engine.delivery() else {
                break;
            };
            if let Some((_, peer)) = &driver.drain
                && driver
                    .delivered
                    .get(usize::from(packet.channel))
                    .zip(peer.counts().get(usize::from(packet.channel)))
                    .is_none_or(|(delivered, fence)| delivered >= fence)
            {
                return Err(invalid("active native record exceeds peer channel fence"));
            }
            match device.transmit(packet.payload) {
                Ok(()) => {
                    let (record, channel) = (packet.record, packet.channel);
                    if settings.adaptive {
                        engine
                            .confirm_delivery_at(record, now)
                            .map_err(io::Error::other)?;
                    } else {
                        engine.confirm_delivery(record).map_err(io::Error::other)?;
                    }
                    count(&mut driver.delivered, channel)?;
                    delivered = increment(delivered)?;
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    native_pressure = true;
                    break;
                }
                Err(error) => return Err(error),
            }
        }
        if let Some(observed) = &mut measurements {
            if driver.can_admit(&engine) && retiring.is_none() {
                observed.tick(&engine, now).map_err(io::Error::other)?;
            }
            let sample = observed.feedback(&engine, now).map_err(io::Error::other)?;
            feedback = sample.feedback;
            feedback.receiver_pressure = native_pressure;
            demanding_flows = sample.demanding.len();
            if driver.can_admit(&engine) {
                engine
                    .update_targets(now, feedback, &sample.demanding)
                    .map_err(io::Error::other)?;
            }
        }
        for _ in 0..WORK {
            if !driver.can_admit(&engine) {
                break;
            }
            if pending.is_none() {
                match device.receive(&mut native) {
                    Ok(Some(length)) if length <= runtime.max_packet => {
                        pending = Some(native[..length].to_vec())
                    }
                    Ok(Some(_)) => return Err(invalid("managed active native MTU")),
                    Ok(None) => break,
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                    Err(error) => return Err(error),
                }
            }
            let packet = pending
                .as_ref()
                .ok_or_else(|| invalid("missing managed native packet"))?;
            let key = classify(PacketLayer::Ip, packet, engine_config.pipeline.parse)
                .map_err(io::Error::other)?
                .key;
            let weight = weights
                .get(&key)
                .copied()
                .unwrap_or_else(|| active::weight_for(packet, settings));
            match engine.enqueue_ip(packet, weight, now) {
                Ok(metadata) => {
                    count(&mut driver.admitted, metadata.binding.channel)?;
                    weights.insert(key, weight);
                    pending = None;
                    admitted = increment(admitted)?;
                }
                Err(
                    l2tunnel_active::Error::Pipeline(
                        PipelineError::Budget(_)
                        | PipelineError::Flow(l2tunnel_packet::FlowError::Capacity),
                    )
                    | l2tunnel_active::Error::FlowFrozen,
                ) => break,
                Err(error) => return Err(io::Error::other(error)),
            }
        }
        for _ in 0..WORK {
            let Ok(permit) = out_control.try_reserve() else {
                break;
            };
            let Some(token) = engine.poll_control().map_err(io::Error::other)? else {
                break;
            };
            permit.send(Frame {
                kind: 1,
                channel: 0,
                body: token.to_vec(),
            });
            external.control = increment(external.control)?;
        }
        for _ in 0..WORK {
            let Ok(permit) = out_data.try_reserve() else {
                break;
            };
            let Some(packet) = engine.poll_data().map_err(io::Error::other)? else {
                break;
            };
            let encoded = codec
                .encode_vec(&packet.payload)
                .map_err(io::Error::other)?;
            let mut body = Vec::with_capacity(WIRE_LEN + encoded.len());
            body.extend_from_slice(&packet.token);
            body.extend_from_slice(&encoded);
            count(&mut driver.handed, packet.channel)?;
            permit.send(Frame {
                kind: 2,
                channel: packet.channel,
                body,
            });
            external.data = increment(external.data)?;
        }
        if engine.status().pending_controls == 0
            && let Some(measurements) = &mut measurements
        {
            for _ in 0..WORK {
                let Ok(permit) = out_observation.try_reserve() else {
                    break;
                };
                let Some(body) = measurements.poll_output(now).map_err(io::Error::other)? else {
                    break;
                };
                permit.send(Frame {
                    kind: 4,
                    channel: 0,
                    body: body.to_vec(),
                });
                external.observation = increment(external.observation)?;
            }
        }
        let (data_flushed, control_flushed, observation_flushed) = (
            *flush_rx.borrow(),
            *control_flush_rx.borrow(),
            *observation_flush_rx.borrow(),
        );
        if control_flushed == external.control {
            engine.poll_retirement(now).map_err(io::Error::other)?;
        }
        let drain = external_drain(
            &external,
            [data_flushed, control_flushed, observation_flushed],
            [&out_data, &out_control, &out_observation],
            &measurements,
        )?;
        driver.external = drain;
        let switching = !driver.peer.can_admit_data();
        if retiring.is_none() && drain.pending_outputs == 0 {
            let candidate = if switching {
                engine.drained_candidate()
            } else {
                engine.idle_candidate(now)
            }
            .map_err(io::Error::other)?;
            if let Some(key) = candidate {
                let same_pending = pending
                    .as_ref()
                    .map(|packet| {
                        classify(PacketLayer::Ip, packet, engine_config.pipeline.parse)
                            .map(|packet| packet.key == key)
                    })
                    .transpose()
                    .map_err(io::Error::other)?
                    .unwrap_or(false);
                if switching || !same_pending {
                    let policy = RetirementPolicy {
                        retry_micros: micros(settings.retirement_retry)?.0,
                        max_attempts: settings.retirement_max_attempts,
                    };
                    let result = if switching {
                        engine.request_drained_retirement(&key, now, policy, drain)
                    } else {
                        engine.request_idle_retirement(&key, now, policy, drain)
                    };
                    match result {
                        Ok(_) => retiring = Some(key),
                        Err(l2tunnel_active::Error::Credit(
                            l2tunnel_flow_control::CreditError::OutstandingRecords,
                        )) => {}
                        Err(error) => return Err(io::Error::other(error)),
                    }
                }
            }
        }
        if empty(&engine)
            && drain.pending_outputs == 0
            && let Some((local, peer)) = &driver.drain
            && matches!(
                driver.peer.phase(),
                Phase::Draining | Phase::FollowerReady | Phase::FollowerDraining
            )
            && local.counts() == driver.admitted
            && local.counts() == driver.handed
            && peer.counts() == driver.delivered
        {
            driver.retired = Some(engine.drained_reader(drain).map_err(io::Error::other)?);
            let effects = driver
                .peer
                .confirm_drained(local, peer, tick(now))
                .map_err(io::Error::other)?;
            driver.effects(
                effects,
                &mut engine,
                &mut settings,
                &mut measurements,
                runtime,
                now,
            )?;
        }
        let effects = driver.peer.poll(tick(now)).map_err(io::Error::other)?;
        driver.effects(
            effects,
            &mut engine,
            &mut settings,
            &mut measurements,
            runtime,
            now,
        )?;
        driver.finish(&engine);
        control.state.send_replace(Some(Status {
            epoch: driver.peer.active_epoch(),
            mode: driver.peer.active_config().mode,
            digest: configuration_digest(driver.peer.active_config()).map_err(io::Error::other)?,
            phase: driver.peer.phase(),
            admitting: driver.can_admit(&engine),
            admitted_by_channel: driver.admitted.clone(),
            handed_by_channel: driver.handed.clone(),
            delivered_by_channel: driver.delivered.clone(),
            traffic: active::Status {
                running: true,
                engine: engine.status(),
                admitted,
                flushed: data_flushed,
                delivered,
                pending_native: pending.is_some(),
                handed: external.data,
                control_handed: external.control,
                control_flushed,
                retired_flows,
                adaptive: settings.adaptive,
                feedback,
                demanding_flows,
                observation_handed: external.observation,
                observation_flushed,
            },
        }));
    }
}

#[cfg(test)]
mod tests;
