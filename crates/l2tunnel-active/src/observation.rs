//! Optional authenticated observation framing and bounded measured feedback.
//!
//! This module does not authenticate inputs or change targets. Callers negotiate
//! this frame kind, authenticate it, reserve external output capacity, and retain
//! separate service for mandatory credit messages. RTT includes runtime queues.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use crate::{Active, ActiveConfig, Credit, Direction, Feedback, FlowId, Micros, Scope};

/// Fixed version-one observation frame size, independent of the credit codec.
pub const WIRE_LEN: usize = 96;

/// Authoritative admission result for the actual retained FIFO head.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BlockReason {
    /// No queued demand, or the queued head can be admitted now.
    Ready,
    /// Advertised per-flow grant cannot admit the head.
    FlowCredit,
    /// Advertised aggregate grant cannot admit the head.
    SessionCredit,
    /// Local sender retention is full; this is not peer-credit exhaustion.
    LocalRetention,
}

/// Nonmutating actual queue/credit observation for one local flow.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LocalDemand {
    /// Authenticated data direction being observed.
    pub scope: Scope,
    /// Monotonic live outgoing flow identity.
    pub flow: FlowId,
    /// Actual original payload bytes and packet count retained before admission.
    pub queued: Credit,
    /// Exact FIFO head bytes, zero only for an empty queue.
    pub head_bytes: u64,
    /// Aggregate unique logical sender retention, repeated rather than additive.
    pub in_flight: Credit,
    /// Result of authoritative ledger preflight on that exact head.
    pub blocked: BlockReason,
}

/// Actual cumulative native consumption sampled at a timed successful confirmation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativeSample {
    /// Incoming data direction consumed by this endpoint.
    pub scope: Scope,
    /// Cumulative actual consumed bytes/records, including static confirmations.
    pub confirmed: Credit,
    /// Local monotonic successful native consumption time.
    pub at: Micros,
    /// Elapsed local time since this record's first accepted receipt.
    pub queue_delay_micros: u64,
}

/// Strict fixed-size authenticated-carrier observation payload.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Message {
    /// Actual demand with a globally increasing source observation sequence.
    Demand {
        /// Positive sequence; duplicates never refresh receiver freshness.
        sequence: u64,
        /// Exact local queued-head and aggregate-retention snapshot.
        snapshot: LocalDemand,
    },
    /// Request an echo for the requester's incoming data direction.
    Ping {
        /// Data-direction scope, not the direction of this control packet.
        scope: Scope,
        /// Positive source-monotonic nonce.
        nonce: u64,
    },
    /// Echo exactly the original scope and nonce.
    Pong {
        /// Original requested data-direction scope.
        scope: Scope,
        /// Exact requested nonce.
        nonce: u64,
    },
}

/// Strict observation framing rejection, before any state mutation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WireError {
    /// Frame has a different exact length.
    Length,
    /// Magic, version, kind, direction or reason is unsupported.
    Tag,
    /// Reserved or unused bytes are nonzero.
    Reserved,
    /// Positive IDs or count/byte/head relationships are inconsistent.
    Value,
}

impl std::fmt::Display for WireError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "observation framing failed: {self:?}")
    }
}
impl std::error::Error for WireError {}

/// Encode canonical version-one framing without allocation.
pub fn encode(message: Message) -> Result<[u8; WIRE_LEN], WireError> {
    let mut out = [0; WIRE_LEN];
    out[..3].copy_from_slice(b"LA\x01");
    let (kind, scope, sequence) = match message {
        Message::Demand { sequence, snapshot } => {
            validate_snapshot(snapshot)?;
            out[5] = match snapshot.blocked {
                BlockReason::Ready => 0,
                BlockReason::FlowCredit => 1,
                BlockReason::SessionCredit => 2,
                BlockReason::LocalRetention => 3,
            };
            for (offset, value) in [
                (40, snapshot.flow.0),
                (48, snapshot.queued.bytes),
                (56, snapshot.queued.records),
                (64, snapshot.head_bytes),
                (72, snapshot.in_flight.bytes),
                (80, snapshot.in_flight.records),
            ] {
                out[offset..offset + 8].copy_from_slice(&value.to_be_bytes());
            }
            (1, snapshot.scope, sequence)
        }
        Message::Ping { scope, nonce } => (2, scope, nonce),
        Message::Pong { scope, nonce } => (3, scope, nonce),
    };
    if sequence == 0 {
        return Err(WireError::Value);
    }
    out[3] = kind;
    out[4] = match scope.direction {
        Direction::Forward => 0,
        Direction::Reverse => 1,
    };
    out[8..24].copy_from_slice(&scope.session.to_be_bytes());
    out[24..32].copy_from_slice(&scope.epoch.to_be_bytes());
    out[32..40].copy_from_slice(&sequence.to_be_bytes());
    Ok(out)
}

/// Decode exact fixed framing; unknown/contradictory data never reaches an engine.
pub fn decode(input: &[u8]) -> Result<Message, WireError> {
    if input.len() != WIRE_LEN {
        return Err(WireError::Length);
    }
    if &input[..3] != b"LA\x01" {
        return Err(WireError::Tag);
    }
    if input[6..8]
        .iter()
        .chain(&input[88..])
        .any(|byte| *byte != 0)
    {
        return Err(WireError::Reserved);
    }
    let direction = match input[4] {
        0 => Direction::Forward,
        1 => Direction::Reverse,
        _ => return Err(WireError::Tag),
    };
    let scope = Scope {
        session: u128::from_be_bytes(input[8..24].try_into().map_err(|_| WireError::Length)?),
        epoch: word(input, 24)?,
        direction,
    };
    let sequence = word(input, 32)?;
    if sequence == 0 {
        return Err(WireError::Value);
    }
    match input[3] {
        1 => {
            let blocked = match input[5] {
                0 => BlockReason::Ready,
                1 => BlockReason::FlowCredit,
                2 => BlockReason::SessionCredit,
                3 => BlockReason::LocalRetention,
                _ => return Err(WireError::Tag),
            };
            let snapshot = LocalDemand {
                scope,
                flow: FlowId(word(input, 40)?),
                queued: Credit {
                    bytes: word(input, 48)?,
                    records: word(input, 56)?,
                },
                head_bytes: word(input, 64)?,
                in_flight: Credit {
                    bytes: word(input, 72)?,
                    records: word(input, 80)?,
                },
                blocked,
            };
            validate_snapshot(snapshot)?;
            Ok(Message::Demand { sequence, snapshot })
        }
        kind @ (2 | 3) => {
            if input[5] != 0 || input[40..].iter().any(|byte| *byte != 0) {
                return Err(WireError::Reserved);
            }
            Ok(if kind == 2 {
                Message::Ping {
                    scope,
                    nonce: sequence,
                }
            } else {
                Message::Pong {
                    scope,
                    nonce: sequence,
                }
            })
        }
        _ => Err(WireError::Tag),
    }
}

fn word(input: &[u8], offset: usize) -> Result<u64, WireError> {
    Ok(u64::from_be_bytes(
        input
            .get(offset..offset + 8)
            .ok_or(WireError::Length)?
            .try_into()
            .map_err(|_| WireError::Length)?,
    ))
}

fn validate_snapshot(snapshot: LocalDemand) -> Result<(), WireError> {
    if u128::from(snapshot.in_flight.records) * 20 > u128::from(snapshot.in_flight.bytes)
        || u128::from(snapshot.queued.records) * 20 > u128::from(snapshot.queued.bytes)
        || (snapshot.in_flight.records == 0 && snapshot.in_flight.bytes != 0)
        || (snapshot.queued.records == 0
            && (snapshot.queued.bytes != 0
                || snapshot.head_bytes != 0
                || snapshot.blocked != BlockReason::Ready))
        || (snapshot.queued.records > 0
            && (snapshot.head_bytes < 20 || snapshot.head_bytes > snapshot.queued.bytes))
    {
        return Err(WireError::Value);
    }
    Ok(())
}

/// Explicit finite timing, output-rate and negotiated peer-accounting bounds.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Config {
    /// Minimum interval between local demand publications.
    pub publication_micros: u64,
    /// Remote demand expires after this local receive-time age.
    pub demand_ttl_micros: u64,
    /// Minimum interval between local probe output handoffs.
    pub probe_interval_micros: u64,
    /// Finite outstanding probe lifetime after handoff.
    pub probe_timeout_micros: u64,
    /// Maximum age of an actual RTT/native measurement used for feedback.
    pub measurement_ttl_micros: u64,
    /// Minimum actual elapsed time between native rate anchor samples.
    pub rate_window_micros: u64,
    /// Fixed interval resetting the finite emission allowance.
    pub output_interval_micros: u64,
    /// Frames emitted per interval, in 1..=4096; unused allowance does not accumulate.
    pub output_burst: u32,
    /// Negotiated remote original-queue byte/count ceiling.
    pub peer_queue: Credit,
    /// Negotiated remote unique logical sender-retention byte/count ceiling.
    pub peer_retained: Credit,
}

impl Config {
    /// Conservative optional observation defaults; peers must negotiate both caps.
    pub fn new(peer_queue: Credit, peer_retained: Credit) -> Self {
        Self {
            publication_micros: 10_000,
            demand_ttl_micros: 1_000_000,
            probe_interval_micros: 100_000,
            probe_timeout_micros: 500_000,
            measurement_ttl_micros: 1_000_000,
            rate_window_micros: 10_000,
            output_interval_micros: 10_000,
            output_burst: 32,
            peer_queue,
            peer_retained,
        }
    }

    fn validate(self) -> Result<(), Error> {
        if [
            self.publication_micros,
            self.demand_ttl_micros,
            self.probe_interval_micros,
            self.probe_timeout_micros,
            self.measurement_ttl_micros,
            self.rate_window_micros,
            self.output_interval_micros,
            self.peer_queue.bytes,
            self.peer_queue.records,
            self.peer_retained.bytes,
            self.peer_retained.records,
        ]
        .contains(&0)
            || !(1..=4096).contains(&self.output_burst)
            || self.demand_ttl_micros < self.publication_micros
            || self.measurement_ttl_micros < self.rate_window_micros
        {
            return Err(Error::InvalidConfig);
        }
        Ok(())
    }
}

/// Bounded optional-observation rejection; no packet is implicitly dropped.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// Timing, output or negotiated peer bounds are invalid.
    InvalidConfig,
    /// Wrong engine configuration or data-direction scope.
    WrongScope,
    /// Framing rejection before state mutation.
    Wire(WireError),
    /// Authoritative local queue snapshot failed.
    Active(crate::Error),
    /// Input exceeds negotiated peer queue/retention/head bounds.
    Bounds,
    /// Demand refers to an unopened future remote flow.
    UnknownFlow,
    /// An authenticated sequence was reused with different observations.
    ConflictingSequence,
    /// Injected observer or engine time moved backward.
    NonMonotonicTime,
    /// Checked counters, deadlines or rate exhausted their integer domain.
    RenewalRequired,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "active observation failed: {self:?}")
    }
}
impl std::error::Error for Error {}
impl From<WireError> for Error {
    fn from(value: WireError) -> Self {
        Self::Wire(value)
    }
}
impl From<crate::Error> for Error {
    fn from(value: crate::Error) -> Self {
        Self::Active(value)
    }
}

/// Fresh measured inputs; callers explicitly merge real pressure and update targets.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObservationFeedback {
    /// No pressure or measured value is synthesized from configured capacities.
    pub feedback: Feedback,
    /// Fresh actual queued remote flows, bounded by live receive capacity.
    pub demanding: Vec<FlowId>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
enum Key {
    Demand(FlowId),
    Ping,
    Pong,
}

#[derive(Clone, Copy)]
struct Remote {
    sequence: u64,
    received_at: Micros,
    snapshot: LocalDemand,
}

#[derive(Clone, Copy)]
struct Probe {
    nonce: u64,
    sent_at: Micros,
    deadline: Micros,
}

/// Independent bounded optional observations for exactly one Active endpoint.
pub struct Observer {
    config: Config,
    engine: ActiveConfig,
    send_scope: Scope,
    receive_scope: Scope,
    last_time: Micros,
    last_publication: Option<Micros>,
    last_probe: Option<Micros>,
    sequence: u64,
    nonce: u64,
    peer_nonce: u64,
    pending: BTreeMap<Key, Message>,
    order: VecDeque<Key>,
    remote: BTreeMap<FlowId, Remote>,
    aggregate: Option<(u64, Credit, Micros)>,
    probe: Option<Probe>,
    rtt: Option<(u64, Micros)>,
    native_seen: u64,
    native_anchor: Option<NativeSample>,
    rate: Option<(u64, Micros)>,
    sojourn: Option<(u64, Micros)>,
    output_start: Micros,
    output_left: u32,
}

impl Observer {
    /// Bind to one engine's negotiated configuration and complementary scopes.
    pub fn new(config: Config, active: &Active, now: Micros) -> Result<Self, Error> {
        config.validate()?;
        active.check_time(now)?;
        now.0
            .checked_add(config.probe_timeout_micros)
            .ok_or(Error::RenewalRequired)?;
        active
            .config
            .send_capacity
            .max_flows
            .checked_add(2)
            .ok_or(Error::InvalidConfig)?;
        Ok(Self {
            config,
            engine: active.config,
            send_scope: active.send_scope,
            receive_scope: active.receive_scope,
            last_time: now,
            last_publication: None,
            last_probe: None,
            sequence: 0,
            nonce: 0,
            peer_nonce: 0,
            pending: BTreeMap::new(),
            order: VecDeque::new(),
            remote: BTreeMap::new(),
            aggregate: None,
            probe: None,
            rtt: None,
            native_seen: 0,
            native_anchor: None,
            rate: None,
            sojourn: None,
            output_start: now,
            output_left: config.output_burst,
        })
    }

    /// Publish actual bounded snapshots and schedule at most one finite-lifetime probe.
    pub fn tick(&mut self, active: &Active, now: Micros) -> Result<(), Error> {
        self.check(active, now)?;
        let publish = self
            .last_publication
            .is_none_or(|last| now.0 - last.0 >= self.config.publication_micros);
        let snapshots = if publish {
            active.demand_snapshots()?
        } else {
            Vec::new()
        };
        let next_sequence = self
            .sequence
            .checked_add(snapshots.len() as u64)
            .ok_or(Error::RenewalRequired)?;
        let expired = self.probe.is_some_and(|probe| now >= probe.deadline);
        let schedule_probe = (self.probe.is_none() || expired)
            && !self.pending.contains_key(&Key::Ping)
            && self
                .last_probe
                .is_none_or(|last| now.0 - last.0 >= self.config.probe_interval_micros);
        let next_nonce = if schedule_probe {
            self.nonce.checked_add(1).ok_or(Error::RenewalRequired)?
        } else {
            self.nonce
        };
        self.prune(active);
        if publish {
            for snapshot in snapshots {
                self.sequence += 1; // Preflight proved the complete bounded batch fits.
                self.queue(
                    Key::Demand(snapshot.flow),
                    Message::Demand {
                        sequence: self.sequence,
                        snapshot,
                    },
                );
            }
            self.sequence = next_sequence;
            self.last_publication = Some(now);
        }
        if expired {
            self.probe = None;
        }
        if schedule_probe {
            self.nonce = next_nonce;
            self.queue(
                Key::Ping,
                Message::Ping {
                    scope: self.receive_scope,
                    nonce: self.nonce,
                },
            );
        }
        self.last_time = now;
        Ok(())
    }

    /// Accept one authenticated observation; duplicate/reordered data never refreshes age.
    pub fn receive(&mut self, active: &Active, input: &[u8], now: Micros) -> Result<(), Error> {
        self.check(active, now)?;
        let message = decode(input)?;
        match message {
            Message::Demand { sequence, snapshot } => {
                if snapshot.scope != self.receive_scope {
                    return Err(Error::WrongScope);
                }
                if !crate::fits(snapshot.queued, self.config.peer_queue)
                    || !crate::fits(snapshot.in_flight, self.config.peer_retained)
                    || snapshot.head_bytes > self.engine.pipeline.parse.max_packet_bytes as u64
                {
                    return Err(Error::Bounds);
                }
                if !active.incoming.contains_key(&snapshot.flow) {
                    if active
                        .highest_incoming
                        .is_none_or(|highest| snapshot.flow > highest)
                    {
                        return Err(Error::UnknownFlow);
                    }
                } else {
                    if let Some(previous) = self.remote.get(&snapshot.flow) {
                        if sequence == previous.sequence && snapshot != previous.snapshot {
                            return Err(Error::ConflictingSequence);
                        }
                        if sequence <= previous.sequence {
                            self.last_time = now;
                            return Ok(());
                        }
                    }
                    self.prune(active);
                    self.remote.insert(
                        snapshot.flow,
                        Remote {
                            sequence,
                            received_at: now,
                            snapshot,
                        },
                    );
                    if self
                        .aggregate
                        .is_none_or(|(previous, _, _)| sequence > previous)
                    {
                        self.aggregate = Some((sequence, snapshot.in_flight, now));
                    }
                }
            }
            Message::Ping { scope, nonce } => {
                if scope != self.send_scope {
                    return Err(Error::WrongScope);
                }
                if nonce > self.peer_nonce {
                    self.peer_nonce = nonce;
                    self.queue(Key::Pong, Message::Pong { scope, nonce });
                }
            }
            Message::Pong { scope, nonce } => {
                if scope != self.receive_scope {
                    return Err(Error::WrongScope);
                }
                if let Some(probe) = self.probe
                    && nonce == probe.nonce
                {
                    if now < probe.deadline && now > probe.sent_at {
                        let elapsed = now.0 - probe.sent_at.0;
                        let smoothed = self
                            .rtt
                            .filter(|(_, at)| now.0 - at.0 < self.config.measurement_ttl_micros)
                            .map_or(elapsed, |(old, _)| {
                                ((u128::from(old) * 7 + u128::from(elapsed)) / 8) as u64
                            });
                        self.rtt = Some((smoothed, now));
                    }
                    self.probe = None;
                }
            }
        }
        self.last_time = now;
        Ok(())
    }

    /// Hand off one rate-gated frame after external capacity reservation.
    /// Probe timing starts here and includes all later runtime/peer queueing.
    pub fn poll_output(&mut self, now: Micros) -> Result<Option<[u8; WIRE_LEN]>, Error> {
        self.check_time(now)?;
        let refill = now.0 - self.output_start.0 >= self.config.output_interval_micros;
        let left = if refill {
            self.config.output_burst
        } else {
            self.output_left
        };
        let Some(key) = self.order.front().copied().filter(|_| left > 0) else {
            self.last_time = now;
            return Ok(None);
        };
        let message = *self.pending.get(&key).ok_or(Error::Bounds)?;
        let output = encode(message)?;
        let probe = if let Message::Ping { nonce, .. } = message {
            Some(Probe {
                nonce,
                sent_at: now,
                deadline: Micros(
                    now.0
                        .checked_add(self.config.probe_timeout_micros)
                        .ok_or(Error::RenewalRequired)?,
                ),
            })
        } else {
            None
        };
        self.order.pop_front();
        self.pending.remove(&key);
        if refill {
            self.output_start = now;
        }
        self.output_left = left - 1;
        if let Some(probe) = probe {
            self.probe = Some(probe);
            self.last_probe = Some(now);
        }
        self.last_time = now;
        Ok(Some(output))
    }

    /// Derive fresh inputs without changing targets or manufacturing pressure.
    /// Merge actual runtime pressure explicitly before calling Active::update_targets.
    pub fn feedback(&mut self, active: &Active, now: Micros) -> Result<ObservationFeedback, Error> {
        self.check(active, now)?;
        self.observe_native(active.native_sample())?;
        self.prune(active);
        let mut demanding = Vec::with_capacity(self.remote.len());
        let mut exhausted = false;
        for (flow, row) in &self.remote {
            if now.0 - row.received_at.0 < self.config.demand_ttl_micros
                && row.snapshot.queued.records > 0
            {
                demanding.push(*flow);
                exhausted |= matches!(
                    row.snapshot.blocked,
                    BlockReason::FlowCredit | BlockReason::SessionCredit
                );
            }
        }
        let fresh = |sample: Option<(u64, Micros)>| {
            sample
                .filter(|(_, at)| now.0 - at.0 < self.config.measurement_ttl_micros)
                .map(|(value, _)| value)
        };
        let in_flight = self
            .aggregate
            .filter(|(_, _, at)| now.0 - at.0 < self.config.demand_ttl_micros)
            .map_or(Credit::default(), |(_, credit, _)| credit);
        self.last_time = now;
        Ok(ObservationFeedback {
            feedback: Feedback {
                rtt_micros: fresh(self.rtt),
                delivery_bytes_per_second: fresh(self.rate),
                in_flight,
                queue_delay_micros: fresh(self.sojourn).unwrap_or(0),
                sender_credit_exhausted: exhausted,
                ..Feedback::default()
            },
            demanding,
        })
    }

    /// Current finite output count; caller queues are accounted independently.
    pub fn pending_outputs(&self) -> usize {
        self.pending.len()
    }

    fn check_time(&self, now: Micros) -> Result<(), Error> {
        if now < self.last_time {
            Err(Error::NonMonotonicTime)
        } else {
            Ok(())
        }
    }

    fn check(&self, active: &Active, now: Micros) -> Result<(), Error> {
        self.check_time(now)?;
        if active.config != self.engine || active.send_scope != self.send_scope {
            return Err(Error::WrongScope);
        }
        if now < active.last_time {
            return Err(Error::NonMonotonicTime);
        }
        Ok(())
    }

    fn queue(&mut self, key: Key, message: Message) {
        if !self.pending.contains_key(&key) {
            self.order.push_back(key);
        }
        self.pending.insert(key, message);
    }

    fn prune(&mut self, active: &Active) {
        self.remote
            .retain(|flow, _| active.incoming.contains_key(flow));
        let live: BTreeSet<_> = active
            .pipeline
            .tun_flow_heads()
            .into_iter()
            .flatten()
            .map(|head| FlowId(head.snapshot.binding.id.0))
            .collect();
        self.pending.retain(|key, _| match key {
            Key::Demand(flow) => live.contains(flow),
            Key::Ping | Key::Pong => true,
        });
        self.order.retain(|key| self.pending.contains_key(key));
    }

    fn observe_native(&mut self, sample: Option<NativeSample>) -> Result<(), Error> {
        let Some(sample) = sample.filter(|sample| sample.confirmed.records > self.native_seen)
        else {
            return Ok(());
        };
        if let Some(anchor) = self.native_anchor {
            let elapsed = sample
                .at
                .0
                .checked_sub(anchor.at.0)
                .ok_or(Error::NonMonotonicTime)?;
            let bytes = sample
                .confirmed
                .bytes
                .checked_sub(anchor.confirmed.bytes)
                .ok_or(Error::RenewalRequired)?;
            if elapsed >= self.config.rate_window_micros {
                let rate = u64::try_from(u128::from(bytes) * 1_000_000 / u128::from(elapsed))
                    .map_err(|_| Error::RenewalRequired)?;
                self.rate = (rate > 0).then_some((rate, sample.at));
                self.native_anchor = Some(sample);
            }
        } else {
            self.native_anchor = Some(sample);
        }
        self.native_seen = sample.confirmed.records;
        self.sojourn = Some((sample.queue_delay_micros, sample.at));
        Ok(())
    }
}

#[cfg(test)]
mod tests;
