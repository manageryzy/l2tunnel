//! Bounded transparent-TUN credit composition with actual packet ownership.
//!
//! The caller authenticates every input, supplies monotonic time/feedback, and
//! reliably transfers outputs. Only [`Active::confirm_delivery`] releases native
//! receive buffers; network receipt and recovery ACKs do not. This crate performs
//! no I/O, cryptography, recovery, endpoint TCP rewriting or TAP policy changes.
//! Open messages need reliable ordered delivery. Other messages may reorder.

use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, VecDeque};
use std::fmt;
use std::time::Duration;

pub use l2tunnel_flow_control::target::{Feedback, Micros, TargetConfig, TargetPlan};
pub use l2tunnel_flow_control::{Capacity, Credit, Direction, FinalOffset, FlowId, Record, Scope};
pub use l2tunnel_pipeline::{FlowKey, PacketMetadata, PipelineConfig, QueueUsage};

use l2tunnel_flow_control::target::{TargetController, TargetError};
use l2tunnel_flow_control::wire::{self, Message, WIRE_LEN};
use l2tunnel_flow_control::{
    CreditError, Grant, Received, ReceiverCredits, RecordId, SenderCredits,
};
use l2tunnel_pipeline::{DequeueError, Mapping, Pipeline, PipelineError, Profile};

mod retirement;
use retirement::PendingRetirement;
pub use retirement::{ExternalDrain, RetirementPolicy};

mod epoch;
pub use epoch::{EpochCommitError, PreparedEpoch, RetiredEpoch};

pub mod observation;
use observation::{BlockReason, LocalDemand, NativeSample};

/// Immutable resource and scope configuration for a pair of independent directions.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ActiveConfig {
    /// Authenticated session identity, independent of MUX channel numbers.
    pub session: u128,
    /// Negotiated configuration epoch; changing it requires staged drained rotation.
    pub epoch: u64,
    /// Native IP, CRC affinity and common bounded user-packet admission.
    pub pipeline: PipelineConfig,
    /// Maximum sent logical retention; flow count must match the pipeline.
    pub send_capacity: Capacity,
    /// Maximum incoming reservations, including granted-but-unreceived data.
    pub receive_capacity: Capacity,
    /// Incoming target policy; its flow/session capacities must match the receiver.
    pub target: TargetConfig,
}

/// Bounded validation/admission failures, never a request to silently drop data.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// Incompatible capacities or insufficient protected bootstrap floors.
    InvalidConfig,
    /// Epoch rotation changed immutable configuration or did not increment exactly once.
    InvalidEpoch,
    /// Old flow registrations, promises, payloads or controls have not fully drained.
    EpochNotDrained,
    /// Only transparent TUN with deterministic CRC mapping is currently supported.
    UnsupportedProfile,
    /// Strict credit-token framing failure.
    Wire(wire::Error),
    /// Authoritative ledger rejected this operation.
    Credit(CreditError),
    /// Packet parsing, scheduling or original-packet queue admission failed.
    Pipeline(PipelineError),
    /// Injected target observation or configuration is invalid.
    Target(TargetError),
    /// Token belongs to another session, epoch or direction.
    WrongScope,
    /// Control/data method received the wrong token kind.
    WrongMessage,
    /// Abandoned retirement is not supported; only exact drained barriers are safe here.
    UnsupportedRetirement,
    /// Retirement interval/count is zero or its first deadline would overflow.
    InvalidRetirementPolicy,
    /// A different flow already owns the single serialized retirement barrier.
    RetirementBusy,
    /// Caller reports retained external output or recovery state.
    ExternalPending,
    /// The source flow has not reached the configured idle age.
    NotIdle,
    /// Final offsets differ from the exact pending barrier or cached acknowledgment.
    FinalMismatch,
    /// The finite final retry allowance was exhausted; the flow remains frozen.
    RetirementRetriesExhausted,
    /// This canonical key is frozen until its pending final barrier completes.
    FlowFrozen,
    /// The record's declared bytes differ from its actual native payload length.
    Length,
    /// Channel does not match negotiated CRC affinity.
    Channel,
    /// A remote flow changed canonical key, or another live remote ID owns it.
    FlowKey,
    /// A referenced remote flow was never opened.
    UnknownFlow,
    /// A retained duplicate descriptor carried different bytes.
    ConflictingPayload,
    /// Native confirmation is ahead of the contiguous per-flow prefix.
    NonContiguous,
    /// Confirmation differs from the retained record descriptor.
    RecordMismatch,
    /// Injected time decreased; the failed call did not advance time.
    NonMonotonicTime,
    /// Cumulative counters exhausted; drain and renew the authenticated session.
    RenewalRequired,
    /// Defensive component-accounting inconsistency.
    Invariant,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "active credit failed: {self:?}")
    }
}
impl std::error::Error for Error {}
impl From<CreditError> for Error {
    fn from(value: CreditError) -> Self {
        Self::Credit(value)
    }
}
impl From<wire::Error> for Error {
    fn from(value: wire::Error) -> Self {
        Self::Wire(value)
    }
}
impl From<PipelineError> for Error {
    fn from(value: PipelineError) -> Self {
        Self::Pipeline(value)
    }
}
impl From<TargetError> for Error {
    fn from(value: TargetError) -> Self {
        Self::Target(value)
    }
}

/// A newly admitted original packet; caller recovery owns any retransmission copy.
#[derive(Debug, Eq, PartialEq)]
pub struct Data {
    /// Canonical fixed-size token, framed separately from the payload.
    pub token: [u8; WIRE_LEN],
    /// Typed logical identity used to attribute recovery and downstream release.
    pub record: Record,
    /// Deterministic common-MUX affinity; never an authorization credential.
    pub channel: u16,
    /// Exact unmodified native IP packet.
    pub payload: Vec<u8>,
}

/// Ownership handed to a caller with a separately bounded reliable output path.
#[derive(Debug, Eq, PartialEq)]
pub enum Output {
    /// Authenticated session control, outside user-packet MUX admission.
    Control([u8; WIRE_LEN]),
    /// User data that already passed pipeline and unique logical-credit admission.
    Data(Data),
}

/// Actual receive outcome; retries never create a second native delivery.
pub type ReceiveOutcome = Received;

/// Borrowed next contiguous native delivery, retained until explicit confirmation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Delivery<'a> {
    /// Exact token to confirm only after downstream consumption succeeds.
    pub record: Record,
    /// Validated CRC affinity of this packet.
    pub channel: u16,
    /// Original native bytes, still owned by the engine.
    pub payload: &'a [u8],
}

/// Idempotent actual-consumption result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConfirmOutcome {
    /// A contiguous native buffer was released and cumulative feedback queued.
    Confirmed,
    /// This record lies below the already confirmed prefix; nothing changed.
    AlreadyConfirmed,
}

/// Fixed-size resource observations; the caller's recovery/native copies are separate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Status {
    /// Original source packets awaiting actual sender admission.
    pub queued: QueueUsage,
    /// Unique sent bytes/counts awaiting downstream release.
    pub sender_retained: Credit,
    /// Incoming promises, including payloads that have never arrived.
    pub receiver_reserved: Credit,
    /// Actual original payloads retained pending native consumption.
    pub receiver_payload: Credit,
    /// Protected first-packet capacity for unopened receive slots.
    pub protected_unopened: Credit,
    /// Coalesced Open/Grant/Release tokens waiting to be transferred.
    pub pending_controls: usize,
    /// Live local outgoing flow count; no silent eviction occurs.
    pub outgoing_flows: usize,
    /// Live remote incoming flow count.
    pub incoming_flows: usize,
    /// Latest adaptive aggregate target before protected-floor allocation.
    pub target: Credit,
    /// A counter or final retry reached its renewal boundary; delivery can still drain.
    pub renewal_required: bool,
    /// Single outgoing flow frozen pending its exact final acknowledgment.
    pub pending_retirement: Option<FlowId>,
    /// One incoming final acknowledgment retained for idempotent retries.
    pub cached_final_ack: Option<FlowId>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
enum ControlKey {
    Open(FlowId),
    Grant(FlowId),
    Release(FlowId),
    Final(FlowId),
    FinalAck(FlowId),
}

struct Pending {
    record: Record,
    channel: u16,
    payload: Box<[u8]>,
    received_at: Micros,
}

struct Incoming {
    key: Option<FlowKey>,
    grant: Grant,
    released: Credit,
    target: Credit,
    pending: BTreeMap<RecordId, Pending>,
}

/// Two independently scoped directions composed without clocks, sockets or threads.
pub struct Active {
    config: ActiveConfig,
    send_scope: Scope,
    receive_scope: Scope,
    pipeline: Pipeline,
    sender: SenderCredits,
    receiver: ReceiverCredits,
    controller: TargetController,
    incoming: BTreeMap<FlowId, Incoming>,
    keys: BTreeMap<FlowKey, FlowId>,
    controls: BTreeMap<ControlKey, Message>,
    control_order: VecDeque<ControlKey>,
    control_capacity: usize,
    floor: Credit,
    floor_pool: Credit,
    issued: Credit,
    payload: Credit,
    target: Credit,
    last_time: Micros,
    last_delivery: Option<FlowId>,
    prefer_control: bool,
    renewal_required: bool,
    highest_outgoing: Option<FlowId>,
    highest_incoming: Option<FlowId>,
    retiring: Option<PendingRetirement>,
    completed_final: Option<FinalOffset>,
    cached_final: Option<FinalOffset>,
    native_delivered: Credit,
    native_sample: Option<NativeSample>,
}

impl Active {
    /// Validate protected floors and construct a TUN-only pair of empty ledgers.
    pub fn new(config: ActiveConfig, direction: Direction, now: Micros) -> Result<Self, Error> {
        if !matches!(config.pipeline.profile, Profile::TunDrr(_))
            || config.pipeline.flows.mapping != Mapping::Crc32
        {
            return Err(Error::UnsupportedProfile);
        }
        let floor = Credit {
            bytes: u64::try_from(config.pipeline.parse.max_packet_bytes)
                .map_err(|_| Error::InvalidConfig)?,
            records: 1,
        };
        let floor_pool = scale(floor, config.receive_capacity.max_flows)?;
        if config.send_capacity.max_flows != config.pipeline.flows.capacity
            || config.receive_capacity.max_flows != config.target.max_flows
            || config.receive_capacity.credit != config.target.session_cap
            || !fits(floor, config.send_capacity.credit)
            || !fits(floor_pool, config.target.minimum)
        {
            return Err(Error::InvalidConfig);
        }
        let control_capacity = config
            .receive_capacity
            .max_flows
            .checked_mul(2)
            .and_then(|n| n.checked_add(config.send_capacity.max_flows))
            .and_then(|n| n.checked_add(2))
            .ok_or(Error::InvalidConfig)?;
        let send_scope = Scope {
            session: config.session,
            epoch: config.epoch,
            direction,
        };
        let receive_scope = Scope {
            direction: match direction {
                Direction::Forward => Direction::Reverse,
                Direction::Reverse => Direction::Forward,
            },
            ..send_scope
        };
        Ok(Self {
            pipeline: Pipeline::new(config.pipeline)?,
            sender: SenderCredits::new(send_scope, config.send_capacity)?,
            receiver: ReceiverCredits::new(receive_scope, config.receive_capacity)?,
            controller: TargetController::new(config.target, now)?,
            config,
            send_scope,
            receive_scope,
            incoming: BTreeMap::new(),
            keys: BTreeMap::new(),
            controls: BTreeMap::new(),
            control_order: VecDeque::new(),
            control_capacity,
            floor,
            floor_pool,
            issued: Credit::default(),
            payload: Credit::default(),
            target: config.target.initial,
            last_time: now,
            last_delivery: None,
            prefer_control: true,
            renewal_required: false,
            highest_outgoing: None,
            highest_incoming: None,
            retiring: None,
            completed_final: None,
            cached_final: None,
            native_delivered: Credit::default(),
            native_sample: None,
        })
    }

    /// Admit unchanged native IP using the common bounded per-flow pipeline.
    /// Failed parsing, weight, time or capacity admission changes no flow counters.
    pub fn enqueue_ip(
        &mut self,
        packet: &[u8],
        weight: u32,
        now: Micros,
    ) -> Result<PacketMetadata, Error> {
        self.check_time(now)?;
        self.check_renewal()?;
        let classification = self
            .pipeline
            .classify(packet)
            .map_err(PipelineError::Parse)?;
        if self
            .retiring
            .as_ref()
            .is_some_and(|pending| pending.key == classification.key)
        {
            return Err(Error::FlowFrozen);
        }
        let new = self.pipeline.flow(&classification.key).is_none();
        let metadata = self
            .pipeline
            .enqueue_weighted(packet.to_vec(), weight, Duration::from_micros(now.0))
            .map_err(|error| Error::Pipeline(error.kind))?;
        if new {
            // Equal capacities, strictly monotonic pipeline IDs and no retirement
            // make this registration infallible after successful pipeline admission.
            let flow = FlowId(metadata.binding.id.0);
            self.sender.open_flow(flow).map_err(|_| Error::Invariant)?;
            self.highest_outgoing = Some(flow);
            self.queue_control(
                ControlKey::Open(flow),
                Message::Open {
                    scope: self.send_scope,
                    flow,
                },
            )?;
        }
        self.last_time = now;
        Ok(metadata)
    }

    /// Apply an authenticated control token; new Opens must be delivered in order.
    pub fn receive_control(&mut self, token: &[u8], now: Micros) -> Result<(), Error> {
        self.check_time(now)?;
        let message = wire::decode(token)?;
        match message {
            Message::Open { scope, flow } => {
                self.check_scope(scope, self.receive_scope)?;
                if let Some(state) = self.incoming.get(&flow) {
                    self.queue_control(ControlKey::Grant(flow), Message::Grant(state.grant))?;
                } else {
                    self.check_renewal()?;
                    if self.highest_incoming.is_some_and(|last| flow <= last) {
                        return Err(Error::Credit(CreditError::FlowIdNotIncreasing));
                    }
                    // Preflight cumulative overflow before mutating the new-flow ledger.
                    if let Err(error) = add(self.issued, self.floor) {
                        self.renewal_required = true;
                        return Err(error);
                    }
                    self.receiver.open_flow(flow)?;
                    let grant = self
                        .receiver
                        .grant(flow, self.floor)
                        .map_err(|_| Error::Invariant)?;
                    self.issued = grant.session_limit;
                    self.highest_incoming = Some(flow);
                    self.incoming.insert(
                        flow,
                        Incoming {
                            key: None,
                            grant,
                            released: Credit::default(),
                            target: self.floor,
                            pending: BTreeMap::new(),
                        },
                    );
                    self.queue_control(ControlKey::Grant(flow), Message::Grant(grant))?;
                }
            }
            Message::Grant(grant) => {
                self.check_scope(grant.scope, self.send_scope)?;
                if let Err(error) = self.sender.apply_grant(grant)
                    && !(error == CreditError::UnknownFlow
                        && self.highest_outgoing.is_some_and(|last| grant.flow <= last))
                {
                    return Err(error.into());
                }
            }
            Message::Release(release) => {
                self.check_scope(release.scope, self.send_scope)?;
                if let Err(error) = self.sender.apply_release(release)
                    && !(error == CreditError::UnknownFlow
                        && self
                            .highest_outgoing
                            .is_some_and(|last| release.flow <= last))
                {
                    return Err(error.into());
                }
            }
            Message::Final { offset, mode } => {
                self.handle_final(offset, mode)?;
            }
            Message::FinalAck { offset, mode } => {
                self.handle_final_ack(offset, mode, now)?;
            }
            Message::Record(_) => return Err(Error::WrongMessage),
        }
        self.last_time = now;
        Ok(())
    }

    /// Validate and retain authenticated actual bytes under an existing reservation.
    /// Scope, declared length, packet key and deterministic channel precede mutation.
    pub fn receive_data(
        &mut self,
        token: &[u8],
        channel: u16,
        payload: &[u8],
        now: Micros,
    ) -> Result<ReceiveOutcome, Error> {
        self.check_time(now)?;
        let Message::Record(record) = wire::decode(token)? else {
            return Err(Error::WrongMessage);
        };
        self.check_scope(record.scope, self.receive_scope)?;
        if u64::try_from(payload.len()).map_err(|_| Error::Length)? != record.byte_len {
            return Err(Error::Length);
        }
        let classification = self
            .pipeline
            .classify(payload)
            .map_err(PipelineError::Parse)?;
        let expected = classification.key.crc32() % u32::from(self.config.pipeline.flows.channels);
        if u32::from(channel) != expected {
            return Err(Error::Channel);
        }
        let state = self.incoming.get(&record.flow).ok_or(Error::UnknownFlow)?;
        if state.key.is_some_and(|key| key != classification.key)
            || self
                .keys
                .get(&classification.key)
                .is_some_and(|flow| *flow != record.flow)
        {
            return Err(Error::FlowKey);
        }
        if state
            .pending
            .get(&record.id)
            .is_some_and(|old| old.record == record && old.payload.as_ref() != payload)
        {
            return Err(Error::ConflictingPayload);
        }
        let outcome = self.receiver.receive(record)?;
        if outcome == Received::New {
            let retained = add(
                self.payload,
                Credit {
                    bytes: record.byte_len,
                    records: 1,
                },
            )?;
            let state = self
                .incoming
                .get_mut(&record.flow)
                .ok_or(Error::Invariant)?;
            state.key = Some(classification.key);
            state.pending.insert(
                record.id,
                Pending {
                    record,
                    channel,
                    payload: payload.into(),
                    received_at: now,
                },
            );
            self.keys.insert(classification.key, record.flow);
            self.payload = retained;
        }
        self.last_time = now;
        Ok(outcome)
    }

    /// Update unissued target policy from caller measurements and known remote demand.
    /// Existing promises remain valid even after pressure reduces the new target.
    pub fn update_targets(
        &mut self,
        now: Micros,
        feedback: Feedback,
        demanding: &[FlowId],
    ) -> Result<TargetPlan, Error> {
        self.check_time(now)?;
        self.check_renewal()?;
        if demanding.len() > self.config.target.max_flows {
            return Err(Error::Target(TargetError::TooManyFlows));
        }
        if demanding
            .iter()
            .any(|flow| !self.incoming.contains_key(flow))
        {
            return Err(Error::UnknownFlow);
        }
        let plan = self.controller.update(now, feedback, demanding)?;
        self.target = plan.total();
        for state in self.incoming.values_mut() {
            state.target = self.floor;
        }
        for allocation in plan.flows() {
            self.incoming
                .get_mut(&allocation.flow)
                .ok_or(Error::Invariant)?
                .target = maximum(allocation.credit, self.floor);
        }
        self.replenish()?;
        self.last_time = now;
        Ok(plan)
    }

    /// Transfer one control or credit-admitted data output to caller ownership.
    /// Alternates control/data when both are ready; blocked heads do not stall others.
    pub fn poll_output(&mut self) -> Result<Option<Output>, Error> {
        if self.prefer_control
            && let Some(output) = self.poll_control()?
        {
            self.prefer_control = false;
            return Ok(Some(Output::Control(output)));
        }
        if let Some(data) = self.poll_data()? {
            self.prefer_control = true;
            return Ok(Some(Output::Data(data)));
        }
        let output = self.poll_control()?;
        if output.is_some() {
            self.prefer_control = false;
        }
        Ok(output.map(Output::Control))
    }

    /// Transfer one admitted user packet after reserving external data-queue room.
    /// Does not remove control tokens. Split-poll callers own bounded control service
    /// and data fairness; use `poll_output` for the built-in alternating policy.
    pub fn poll_data(&mut self) -> Result<Option<Data>, Error> {
        let sender = RefCell::new(&mut self.sender);
        let failure = Cell::new(None);
        let packet = self
            .pipeline
            .dequeue_with(
                |candidate| {
                    sender.try_borrow().is_ok_and(|ledger| {
                        match ledger.preview_admit(
                            FlowId(candidate.binding.id.0),
                            candidate.packet_bytes as u64,
                        ) {
                            Ok(_) => true,
                            Err(CreditError::SenderExhausted(_) | CreditError::LocalRetention) => {
                                false
                            }
                            Err(error) => {
                                failure.set(Some(error));
                                false
                            }
                        }
                    })
                },
                |candidate| {
                    sender
                        .try_borrow_mut()
                        .map_err(|_| Error::Invariant)?
                        .admit(
                            FlowId(candidate.binding.id.0),
                            candidate.packet_bytes as u64,
                        )
                        .map_err(Error::Credit)
                },
            )
            .map_err(|error| match error {
                DequeueError::Pipeline(error) => Error::Pipeline(error),
                DequeueError::Commit(error) => error,
            })?;
        if failure.get() == Some(CreditError::Overflow) {
            self.renewal_required = true;
        }
        if let Some(admitted) = packet {
            return Ok(Some(Data {
                token: wire::encode(Message::Record(admitted.permit))?,
                record: admitted.permit,
                channel: admitted.packet.metadata.binding.channel,
                payload: admitted.packet.payload,
            }));
        }
        if let Some(error) = failure.get() {
            return Err(Error::Credit(error));
        }
        Ok(None)
    }

    /// Borrow a contiguous native head, rotating across flows after confirmation.
    /// Bounded work is at most two ordered-map traversals over configured live flows.
    pub fn delivery(&self) -> Option<Delivery<'_>> {
        let after = self
            .incoming
            .iter()
            .filter(|(flow, _)| self.last_delivery.is_none_or(|last| **flow > last))
            .find_map(|(_, state)| ready(state));
        after
            .or_else(|| self.incoming.values().find_map(ready))
            .map(|pending| Delivery {
                record: pending.record,
                channel: pending.channel,
                payload: &pending.payload,
            })
    }

    /// Confirm actual successful downstream consumption, then release and replenish.
    /// Never call after a failed native write. Old confirmations are idempotent;
    /// a counter-renewal boundary still commits this release and is exposed in status.
    pub fn confirm_delivery(&mut self, record: Record) -> Result<ConfirmOutcome, Error> {
        self.check_scope(record.scope, self.receive_scope)?;
        let state = self.incoming.get(&record.flow).ok_or(Error::UnknownFlow)?;
        if record.id.0 < state.released.records {
            let end = record
                .byte_start
                .checked_add(record.byte_len)
                .ok_or(Error::RecordMismatch)?;
            return if end <= state.released.bytes {
                Ok(ConfirmOutcome::AlreadyConfirmed)
            } else {
                Err(Error::RecordMismatch)
            };
        }
        if record.id.0 != state.released.records {
            return Err(Error::NonContiguous);
        }
        if state
            .pending
            .get(&record.id)
            .is_none_or(|pending| pending.record != record)
        {
            return Err(Error::RecordMismatch);
        }
        let delivered = add(
            self.native_delivered,
            Credit {
                bytes: record.byte_len,
                records: 1,
            },
        )?;
        let release = self.receiver.release_next(record.flow)?;
        let state = self
            .incoming
            .get_mut(&record.flow)
            .ok_or(Error::Invariant)?;
        state.pending.remove(&record.id);
        state.released = release.consumed;
        self.payload = subtract(
            self.payload,
            Credit {
                bytes: record.byte_len,
                records: 1,
            },
        )?;
        self.last_delivery = Some(record.flow);
        self.native_delivered = delivered;
        self.queue_control(ControlKey::Release(record.flow), Message::Release(release))?;
        self.replenish()?;
        Ok(ConfirmOutcome::Confirmed)
    }

    /// Confirm actual native consumption with its injected monotonic timestamp.
    /// A duplicate never refreshes a sample or the first-receipt queue age.
    pub fn confirm_delivery_at(
        &mut self,
        record: Record,
        now: Micros,
    ) -> Result<ConfirmOutcome, Error> {
        self.check_time(now)?;
        let received_at = self
            .incoming
            .get(&record.flow)
            .and_then(|state| state.pending.get(&record.id))
            .map(|pending| pending.received_at);
        let outcome = self.confirm_delivery(record)?;
        if outcome == ConfirmOutcome::Confirmed {
            let received_at = received_at.ok_or(Error::Invariant)?;
            self.native_sample = Some(NativeSample {
                scope: self.receive_scope,
                confirmed: self.native_delivered,
                at: now,
                queue_delay_micros: now.0.checked_sub(received_at.0).ok_or(Error::Invariant)?,
            });
        }
        self.last_time = now;
        Ok(outcome)
    }

    /// Latest actual timed native consumption; static confirmation creates no sample.
    pub fn native_sample(&self) -> Option<NativeSample> {
        self.native_sample
    }

    /// Observe exact queued heads and authoritative credit preflight without mutation.
    /// Each row repeats aggregate retained credit; receivers must never sum those rows.
    pub fn demand_snapshots(&self) -> Result<Vec<LocalDemand>, Error> {
        let mut snapshots = Vec::with_capacity(self.pipeline.registered_flows());
        for head in self.pipeline.tun_flow_heads()? {
            let flow = FlowId(head.snapshot.binding.id.0);
            let blocked = if let Some(bytes) = head.packet_bytes {
                match self.sender.preview_admit(flow, bytes as u64) {
                    Ok(_) => BlockReason::Ready,
                    Err(CreditError::SenderExhausted(l2tunnel_flow_control::LimitDomain::Flow)) => {
                        BlockReason::FlowCredit
                    }
                    Err(CreditError::SenderExhausted(
                        l2tunnel_flow_control::LimitDomain::Session,
                    )) => BlockReason::SessionCredit,
                    Err(CreditError::LocalRetention) => BlockReason::LocalRetention,
                    Err(error) => return Err(error.into()),
                }
            } else {
                BlockReason::Ready
            };
            snapshots.push(LocalDemand {
                scope: self.send_scope,
                flow,
                queued: Credit {
                    bytes: head.snapshot.queued.bytes as u64,
                    records: head.snapshot.queued.packets as u64,
                },
                head_bytes: head.packet_bytes.unwrap_or(0) as u64,
                in_flight: self.sender.retained(),
                blocked,
            });
        }
        snapshots.sort_unstable_by_key(|snapshot| snapshot.flow);
        Ok(snapshots)
    }

    /// Observe separate actual payload, issued promises and external handoff domains.
    pub fn status(&self) -> Status {
        Status {
            queued: self.pipeline.usage(),
            sender_retained: self.sender.retained(),
            receiver_reserved: self.receiver.reserved(),
            receiver_payload: self.payload,
            protected_unopened: self.protected(),
            pending_controls: self.controls.len(),
            outgoing_flows: self.pipeline.registered_flows(),
            incoming_flows: self.incoming.len(),
            target: self.target,
            renewal_required: self.renewal_required,
            pending_retirement: self.retiring.as_ref().map(|pending| pending.offset.flow),
            cached_final_ack: self.cached_final.map(|offset| offset.flow),
        }
    }

    fn check_time(&self, now: Micros) -> Result<(), Error> {
        if now < self.last_time {
            Err(Error::NonMonotonicTime)
        } else {
            Ok(())
        }
    }

    fn check_renewal(&self) -> Result<(), Error> {
        if self.renewal_required {
            Err(Error::RenewalRequired)
        } else {
            Ok(())
        }
    }

    fn check_scope(&self, got: Scope, expected: Scope) -> Result<(), Error> {
        if got == expected {
            Ok(())
        } else {
            Err(Error::WrongScope)
        }
    }

    fn protected(&self) -> Credit {
        // Construction proved the full pool multiplication fits; counts only decrease.
        let count = (self.config.receive_capacity.max_flows - self.incoming.len()) as u64;
        Credit {
            bytes: self.floor.bytes * count,
            records: count,
        }
    }

    fn queue_control(&mut self, key: ControlKey, message: Message) -> Result<(), Error> {
        if !self.controls.contains_key(&key) {
            if self.controls.len() >= self.control_capacity {
                return Err(Error::Invariant);
            }
            self.control_order.push_back(key);
        }
        self.controls.insert(key, message);
        Ok(())
    }

    /// Transfer one control token after reserving external control-queue room.
    /// This never dequeues user data or consumes sender credit, so bulk backpressure
    /// cannot block Grant/Release service. The caller must enforce a finite rate/burst.
    pub fn poll_control(&mut self) -> Result<Option<[u8; WIRE_LEN]>, Error> {
        let Some(key) = self.control_order.front().copied() else {
            return Ok(None);
        };
        let message = *self.controls.get(&key).ok_or(Error::Invariant)?;
        let token = wire::encode(message)?;
        self.control_order.pop_front();
        self.controls.remove(&key);
        Ok(Some(token))
    }

    fn replenish(&mut self) -> Result<(), Error> {
        if self.renewal_required {
            return Ok(());
        }
        let flows: Vec<_> = self.incoming.keys().copied().collect();
        // Restore every live floor first, including non-demanding flows. Released
        // bytes/counts free exactly this room even when old surplus exceeds target.
        for flow in &flows {
            let state = self.incoming.get(flow).ok_or(Error::Invariant)?;
            let desired = match add(state.released, self.floor) {
                Ok(value) => value,
                Err(Error::RenewalRequired) => {
                    self.renewal_required = true;
                    return Ok(());
                }
                Err(error) => return Err(error),
            };
            if !self.issue(*flow, desired)? {
                return Ok(());
            }
        }
        let target = subtract(maximum(self.target, self.floor_pool), self.protected())?;
        for flow in flows {
            let state = self.incoming.get(&flow).ok_or(Error::Invariant)?;
            let desired = match add(state.released, state.target) {
                Ok(value) => maximum(value, state.grant.flow_limit),
                Err(Error::RenewalRequired) => {
                    self.renewal_required = true;
                    return Ok(());
                }
                Err(error) => return Err(error),
            };
            let outstanding = self.receiver.reserved();
            let delta = subtract(desired, state.grant.flow_limit)?;
            let increment = Credit {
                bytes: delta
                    .bytes
                    .min(target.bytes.saturating_sub(outstanding.bytes)),
                records: delta
                    .records
                    .min(target.records.saturating_sub(outstanding.records)),
            };
            let next = add(state.grant.flow_limit, increment)?;
            if !self.issue(flow, next)? {
                return Ok(());
            }
        }
        Ok(())
    }

    fn issue(&mut self, flow: FlowId, desired: Credit) -> Result<bool, Error> {
        let state = self.incoming.get(&flow).ok_or(Error::Invariant)?;
        let next = maximum(state.grant.flow_limit, desired);
        let delta = subtract(next, state.grant.flow_limit)?;
        if delta == Credit::default() {
            return Ok(true);
        }
        if add(self.issued, delta).is_err() {
            self.renewal_required = true;
            return Ok(false);
        }
        let grant = self.receiver.grant(flow, next)?;
        self.issued = grant.session_limit;
        self.incoming.get_mut(&flow).ok_or(Error::Invariant)?.grant = grant;
        self.queue_control(ControlKey::Grant(flow), Message::Grant(grant))?;
        Ok(true)
    }
}

fn fits(a: Credit, b: Credit) -> bool {
    a.bytes <= b.bytes && a.records <= b.records
}

fn ready(state: &Incoming) -> Option<&Pending> {
    state.pending.get(&RecordId(state.released.records))
}
fn maximum(a: Credit, b: Credit) -> Credit {
    Credit {
        bytes: a.bytes.max(b.bytes),
        records: a.records.max(b.records),
    }
}
fn add(a: Credit, b: Credit) -> Result<Credit, Error> {
    Ok(Credit {
        bytes: a.bytes.checked_add(b.bytes).ok_or(Error::RenewalRequired)?,
        records: a
            .records
            .checked_add(b.records)
            .ok_or(Error::RenewalRequired)?,
    })
}
fn subtract(a: Credit, b: Credit) -> Result<Credit, Error> {
    Ok(Credit {
        bytes: a.bytes.checked_sub(b.bytes).ok_or(Error::Invariant)?,
        records: a.records.checked_sub(b.records).ok_or(Error::Invariant)?,
    })
}
fn scale(a: Credit, count: usize) -> Result<Credit, Error> {
    let count = u64::try_from(count).map_err(|_| Error::InvalidConfig)?;
    Ok(Credit {
        bytes: a.bytes.checked_mul(count).ok_or(Error::InvalidConfig)?,
        records: a.records.checked_mul(count).ok_or(Error::InvalidConfig)?,
    })
}

#[cfg(test)]
mod tests;
