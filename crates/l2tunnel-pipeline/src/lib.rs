//! Bounded unchanged-packet scheduling for separate TAP and transparent-TUN profiles.
//!
//! TAP retains ordinary common-MUX FIFO/round-robin service. Only TUN selects
//! per-flow weighted DRR and optional externally committed sender credit. This
//! library performs no device I/O, TCP rewriting, authentication or congestion control.
//!
//! ```
//! use l2tunnel_pipeline::*;
//! use std::time::Duration;
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let mut pipeline = Pipeline::new(PipelineConfig {
//!     profile: Profile::TapSystem,
//!     flows: FlowTableConfig { capacity: 64, channels: 16, mapping: Mapping::Crc32,
//!         idle_timeout: Duration::from_secs(60) },
//!     parse: ParseLimits { max_packet_bytes: 1600, ..ParseLimits::default() },
//!     queue: QueueLimits { bytes: 16000, packets: 32 },
//! })?;
//! let frame = vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0x88, 0xb5];
//! let metadata = pipeline.enqueue(frame.clone(), Duration::ZERO)?;
//! let packet = pipeline.dequeue()?.ok_or("expected original frame")?;
//! assert_eq!(packet.payload, frame);
//! assert_eq!(packet.metadata.binding, metadata.binding);
//! # Ok(())
//! # }
//! ```

use std::collections::BTreeMap;
use std::convert::Infallible;
use std::time::Duration;

use l2tunnel_mux::Mux;
use l2tunnel_packet::{FlowTable, classify};
use l2tunnel_qos::{ClassConfig, ClassId, FlowConfig, Scheduler, SchedulerConfig};

mod backing;
/// Complete checked fallible Pipeline backing and actual retained capacity.
pub mod storage;

use backing::{ById, MetadataPool, MetadataQueue, States};

pub use l2tunnel_packet::{
    Binding, Classification, FlowId, FlowKey, FlowTableConfig, Mapping, PacketLayer, ParseError,
    ParseLimits,
};

/// Aggregate retained original-packet byte and count limits across all stages.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QueueLimits {
    /// Maximum original packet bytes.
    pub bytes: usize,
    /// Maximum retained packet count.
    pub packets: usize,
}

/// Observed original-packet retention, excluding fixed/count-bounded metadata.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct QueueUsage {
    /// Original packet bytes still owned by this pipeline.
    pub bytes: usize,
    /// Original packets still owned by this pipeline.
    pub packets: usize,
}

/// Trusted flat per-flow DRR policy, available only for transparent TUN.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TunQosConfig {
    /// Base quantum in original packet bytes.
    pub base_quantum_bytes: u32,
    /// Highest permitted trusted per-flow multiplier.
    pub max_weight: u32,
    /// Retained byte/count limits per flow, including a selected head.
    pub per_flow: QueueLimits,
}

/// Explicit native-packet profile; TAP never silently inherits TUN QoS.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Profile {
    /// Ethernet/ARP/VLAN/opaque frames through common channel FIFO/RR only.
    TapSystem,
    /// Native IP packets through flat weighted DRR then common MUX admission.
    TunDrr(TunQosConfig),
}

/// Fixed configuration for one direction, tenant, session and epoch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PipelineConfig {
    /// Explicit TAP versus TUN scheduling policy.
    pub profile: Profile,
    /// Channel mapping, flow capacity and nonzero idle age.
    pub flows: FlowTableConfig,
    /// Bounded structural inspection and maximum original packet length.
    pub parse: ParseLimits,
    /// Shared original-packet byte/count bounds across stages.
    pub queue: QueueLimits,
}

impl PipelineConfig {
    /// Validate complete scalar policy without constructing packet owners.
    pub fn validate(self) -> Result<(), PipelineError> {
        let minimum = match self.profile {
            Profile::TapSystem => 14,
            Profile::TunDrr(_) => 20,
        };
        if self.queue.bytes < self.parse.max_packet_bytes
            || self.queue.packets == 0
            || self.parse.max_packet_bytes < minimum
        {
            return Err(PipelineError::InvalidConfig);
        }
        let mut header = [0u8; 14];
        header[12..14].copy_from_slice(&0x88b5u16.to_be_bytes());
        classify(PacketLayer::Ethernet, &header, self.parse).map_err(PipelineError::Parse)?;
        self.flows.validate().map_err(PipelineError::Flow)?;
        // The preceding bounds also establish every scalar MUX constructor check.
        if let Profile::TunDrr(policy) = self.profile {
            if policy.max_weight == 0 {
                return Err(PipelineError::InvalidConfig);
            }
            let scheduler = scheduler_config(self, policy);
            scheduler
                .validate(&TUN_CLASSES)
                .map_err(PipelineError::QosConfig)?;
            scheduler
                .flow_quantum(Some(1), policy.max_weight)
                .map_err(PipelineError::QosFlow)?;
        }
        Ok(())
    }
}

/// Metadata returned on admission and final handoff.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PacketMetadata {
    /// Canonical classification, with original header observations.
    pub classification: Classification,
    /// Local monotonic flow ID and negotiated MUX channel.
    pub binding: Binding,
}

/// One unchanged original packet handed to the caller.
#[derive(Debug, Eq, PartialEq)]
pub struct Packet {
    /// Original frame/packet bytes, without any inserted headers.
    pub payload: Vec<u8>,
    /// Classification and affinity.
    pub metadata: PacketMetadata,
}

/// One bounded, nonmutating idle-registration scan; retirement still needs drain proof.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IdleScan {
    /// Resume strictly after this key; `None` starts a new pass.
    pub after: Option<FlowKey>,
    /// Number of registrations examined, never greater than the supplied work.
    pub examined: usize,
    /// First idle locally empty candidate, excluding the caller's pinned key.
    pub candidate: Option<(FlowKey, Binding)>,
}

/// A FIFO head offered to a pure credit-eligibility check and later commit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Candidate {
    /// Stable canonical flow identity.
    pub key: FlowKey,
    /// Local flow and channel assignment.
    pub binding: Binding,
    /// Logical original-packet bytes to charge if selected.
    pub packet_bytes: usize,
}

/// Successful final handoff with the caller's committed credit or permit token.
#[derive(Debug, Eq, PartialEq)]
pub struct Admitted<T> {
    /// Unchanged selected packet.
    pub packet: Packet,
    /// Token returned by the single successful credit commit.
    pub permit: T,
}

/// Actual borrowed-byte handoff, without allocating or returning a payload owner.
#[derive(Debug, Eq, PartialEq)]
pub struct Admission<T> {
    /// Exact classification and selected flow/channel affinity.
    pub metadata: PacketMetadata,
    /// Token returned by the single successful downstream admission.
    pub permit: T,
}

struct Handoff<T> {
    metadata: PacketMetadata,
    permit: T,
    payload: Option<Vec<u8>>,
}

/// Fixed-size observation of one retained flow registration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FlowSnapshot {
    /// Local identity and affinity.
    pub binding: Binding,
    /// Immutable registered weight; always one for TAP.
    pub weight: u32,
    /// Original packets retained anywhere in this pipeline for the flow.
    pub queued: QueueUsage,
    /// Last successful ingress admission or affinity-learning time.
    pub last_activity: Duration,
}

/// Read-only TUN head observation; inspecting it never earns DRR deficit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FlowHead {
    /// Stable canonical native-packet key.
    pub key: FlowKey,
    /// Actual live registration and retained queue accounting.
    pub snapshot: FlowSnapshot,
    /// Exact next retained packet length, absent for an empty queue.
    pub packet_bytes: Option<usize>,
}

/// Which configured original-packet resource would be exceeded.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Budget {
    /// Shared retained bytes.
    Bytes,
    /// Shared retained packet count.
    Packets,
    /// TUN per-flow retained bytes.
    FlowBytes,
    /// TUN per-flow retained packet count.
    FlowPackets,
}

/// Explicit configuration, policy, parsing or bounded-state failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PipelineError {
    /// Zero/inconsistent limits or unsupported maximum weight.
    InvalidConfig,
    /// Packet structure or parser limit is invalid.
    Parse(ParseError),
    /// Flow assignment, time, capacity or learned-channel failure.
    Flow(l2tunnel_packet::FlowError),
    /// DRR configuration is invalid.
    QosConfig(l2tunnel_qos::ConfigError),
    /// DRR registration failed without admission.
    QosFlow(l2tunnel_qos::FlowError),
    /// Defensive internal DRR failure.
    Schedule(l2tunnel_qos::ScheduleError),
    /// Original packet budget is full.
    Budget(Budget),
    /// The requested trusted weight is zero or exceeds its configured maximum.
    InvalidWeight,
    /// Existing flow policy cannot change before retirement.
    WeightChanged,
    /// This per-flow QoS operation is deliberately unavailable for TAP.
    TunOnly,
    /// Local packets still exist, so a flow cannot retire.
    Busy,
    /// An explicitly allocating compatibility ingress or owned handoff failed.
    Allocation,
    /// Defensive internal component-accounting inconsistency.
    Invariant,
}

impl std::fmt::Display for PipelineError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "packet pipeline failed: {self:?}")
    }
}
impl std::error::Error for PipelineError {}

/// Rejected admission returns the original input and leaves all resources intact.
#[derive(Debug, Eq, PartialEq)]
pub struct EnqueueError {
    /// Rejection reason.
    pub kind: PipelineError,
    /// Original input, including its original spare allocation capacity.
    pub payload: Vec<u8>,
}

impl std::fmt::Display for EnqueueError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.kind.fmt(formatter)
    }
}
impl std::error::Error for EnqueueError {}

/// Final selection failure; a rejected external commit leaves its packet queued.
#[derive(Debug, Eq, PartialEq)]
pub enum DequeueError<E> {
    /// Pipeline configuration or invariant failure.
    Pipeline(PipelineError),
    /// Caller declined credit commit; no packet was removed.
    Commit(E),
}

impl<E: std::fmt::Display> std::fmt::Display for DequeueError<E> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Pipeline(error) => error.fmt(formatter),
            Self::Commit(error) => write!(formatter, "packet credit commit rejected: {error}"),
        }
    }
}
impl<E: std::error::Error + 'static> std::error::Error for DequeueError<E> {}

struct FlowState {
    snapshot: FlowSnapshot,
    metadata: MetadataQueue,
}

/// Bounded actual-payload scheduler with explicit TAP/TUN semantics.
pub struct Pipeline {
    config: PipelineConfig,
    flows: FlowTable,
    states: States,
    by_id: ById,
    qos: Option<Scheduler>,
    mux: Mux,
    channel_metadata: Vec<MetadataQueue>,
    metadata_pool: MetadataPool,
    usage: QueueUsage,
    storage: Option<storage::Usage>,
}

impl Pipeline {
    /// Construct without I/O; validate every bound and the largest allowed weight.
    pub fn new(config: PipelineConfig) -> Result<Self, PipelineError> {
        config.validate()?;
        let flows = FlowTable::new(config.flows).map_err(PipelineError::Flow)?;
        let mux = Mux::new(
            config.flows.channels,
            config.queue.bytes,
            config.queue.packets,
        )
        .map_err(|_| PipelineError::InvalidConfig)?;
        let qos = match config.profile {
            Profile::TapSystem => None,
            Profile::TunDrr(policy) => Some(
                Scheduler::new(scheduler_config(config, policy), &TUN_CLASSES)
                    .map_err(PipelineError::QosConfig)?,
            ),
        };
        Ok(Self {
            config,
            flows,
            states: States::Legacy(BTreeMap::new()),
            by_id: ById::Legacy(BTreeMap::new()),
            qos,
            mux,
            channel_metadata: (0..config.flows.channels)
                .map(|_| MetadataQueue::new(false))
                .collect(),
            metadata_pool: MetadataPool::Legacy,
            usage: QueueUsage::default(),
            storage: None,
        })
    }

    /// Classify according to the explicit native layer, without changing state.
    pub fn classify(&self, packet: &[u8]) -> Result<Classification, ParseError> {
        let layer = match self.config.profile {
            Profile::TapSystem => PacketLayer::Ethernet,
            Profile::TunDrr(_) => PacketLayer::Ip,
        };
        classify(layer, packet, self.config.parse)
    }

    /// Admit an unchanged packet with the default trusted weight of one.
    pub fn enqueue(
        &mut self,
        payload: Vec<u8>,
        now: Duration,
    ) -> Result<PacketMetadata, EnqueueError> {
        self.enqueue_weighted(payload, 1, now)
    }

    /// Admit with a trusted immutable flow weight; TAP accepts only weight one.
    ///
    /// A parse, budget, policy or flow failure preserves the original input,
    /// IDs, channel cursor, timers, registrations and queue accounting.
    pub fn enqueue_weighted(
        &mut self,
        payload: Vec<u8>,
        weight: u32,
        now: Duration,
    ) -> Result<PacketMetadata, EnqueueError> {
        self.enqueue_input(Input::Owned(payload), weight, now)
            .map_err(|(kind, input)| EnqueueError {
                kind,
                payload: input.into_owned(),
            })
    }

    /// Admit borrowed original bytes with trusted weight one.
    ///
    /// Reserved backing copies once into its actual retained slab without a
    /// temporary Vec. Legacy backing is an explicitly allocating convenience.
    pub fn enqueue_borrowed(
        &mut self,
        bytes: &[u8],
        now: Duration,
    ) -> Result<PacketMetadata, PipelineError> {
        self.enqueue_borrowed_weighted(bytes, 1, now)
    }

    /// Admit borrowed unchanged bytes with the same trusted immutable weight policy.
    pub fn enqueue_borrowed_weighted(
        &mut self,
        bytes: &[u8],
        weight: u32,
        now: Duration,
    ) -> Result<PacketMetadata, PipelineError> {
        self.enqueue_input(Input::Borrowed(bytes), weight, now)
            .map_err(|(kind, _)| kind)
    }

    fn enqueue_input<'a>(
        &mut self,
        input: Input<'a>,
        weight: u32,
        now: Duration,
    ) -> Result<PacketMetadata, (PipelineError, Input<'a>)> {
        let classification = match self.classify(input.bytes()) {
            Ok(value) => value,
            Err(error) => return Err((PipelineError::Parse(error), input)),
        };
        let key = classification.key;
        let (total, per_flow) = match self.preflight(key, input.bytes().len(), weight) {
            Ok(value) => value,
            Err(kind) => return Err((kind, input)),
        };
        let new = !self.states.contains_key(&key);
        let transaction = match self.flows.prepare_assign(key, now) {
            Ok(value) => value,
            Err(error) => return Err((PipelineError::Flow(error), input)),
        };
        if !self.metadata_pool.has_room()
            || new && (!self.states.has_room() || !self.by_id.has_room())
        {
            return Err((PipelineError::Invariant, input));
        }
        let binding = transaction.binding();
        let sidecar = if self.qos.is_some() {
            if new {
                MetadataQueue::new(self.metadata_pool.is_reserved())
                    .validate_push(&self.metadata_pool)
            } else {
                self.states
                    .get(&key)
                    .ok_or(PipelineError::Invariant)
                    .and_then(|state| state.metadata.validate_push(&self.metadata_pool))
            }
        } else {
            self.channel_metadata
                .get(usize::from(binding.channel))
                .ok_or(PipelineError::Invariant)
                .and_then(|queue| queue.validate_push(&self.metadata_pool))
        };
        if let Err(kind) = sidecar {
            return Err((kind, input));
        }
        if new && self.by_id.get(&binding.id).is_some()
            || !new && self.by_id.get(&binding.id) != Some(&key)
        {
            return Err((PipelineError::Invariant, input));
        }
        // A legacy borrowed convenience reserves before scheduler registration,
        // so allocation failure cannot invalidate an existing DRR selection.
        let input = match input.prepare(self.metadata_pool.is_reserved()) {
            Ok(input) => input,
            Err(input) => return Err((PipelineError::Allocation, input)),
        };
        if new
            && let Some(qos) = &mut self.qos
            && let Err(error) = qos.register_flow(qos_flow(binding.id, weight))
        {
            return Err((PipelineError::QosFlow(error), input));
        }
        let admitted = match (&mut self.qos, input) {
            (Some(qos), Input::Owned(payload)) => qos
                .enqueue(l2tunnel_qos::FlowId::new(binding.id.0), payload)
                .map_err(|error| (qos_admission_error(error.kind), Input::Owned(error.payload))),
            (Some(qos), Input::Borrowed(bytes)) => qos
                .enqueue_borrowed(l2tunnel_qos::FlowId::new(binding.id.0), bytes)
                .map_err(|error| (qos_admission_error(error), Input::Borrowed(bytes))),
            (None, Input::Owned(payload)) => {
                self.mux.push(binding.channel, payload).map_err(|error| {
                    let (l2tunnel_mux::AdmissionError::Budget(payload)
                    | l2tunnel_mux::AdmissionError::Channel(payload)) = error;
                    (PipelineError::Invariant, Input::Owned(payload))
                })
            }
            (None, Input::Borrowed(bytes)) => self
                .mux
                .push_borrowed(binding.channel, bytes)
                .map_err(|error| (mux_admission_error(error), Input::Borrowed(bytes))),
        };
        if let Err(error) = admitted {
            if new && let Some(qos) = &mut self.qos {
                let _ = qos.remove_flow(l2tunnel_qos::FlowId::new(binding.id.0));
            }
            return Err(error);
        }
        let binding = transaction.commit();
        let metadata = PacketMetadata {
            classification,
            binding,
        };
        if new {
            self.states
                .insert(
                    key,
                    FlowState {
                        snapshot: FlowSnapshot {
                            binding,
                            weight,
                            queued: QueueUsage::default(),
                            last_activity: now,
                        },
                        metadata: MetadataQueue::new(self.metadata_pool.is_reserved()),
                    },
                )
                .map_err(|kind| (kind, Input::Borrowed(&[])))?;
        }
        let state = self
            .states
            .get_mut(&key)
            .ok_or((PipelineError::Invariant, Input::Borrowed(&[])))?;
        if self.qos.is_some() {
            state
                .metadata
                .push(&mut self.metadata_pool, metadata)
                .map_err(|kind| (kind, Input::Borrowed(&[])))?;
        } else {
            self.channel_metadata
                .get_mut(usize::from(binding.channel))
                .ok_or((PipelineError::Invariant, Input::Borrowed(&[])))?
                .push(&mut self.metadata_pool, metadata)
                .map_err(|kind| (kind, Input::Borrowed(&[])))?;
        }
        state.snapshot.queued = per_flow;
        state.snapshot.last_activity = now;
        self.by_id
            .insert(binding.id, key)
            .map_err(|kind| (kind, Input::Borrowed(&[])))?;
        self.usage = total;
        Ok(metadata)
    }

    /// Learn an already-authenticated channel without admitting a user packet.
    ///
    /// Learned registrations consume bounded flow capacity, never queue capacity.
    pub fn learn(
        &mut self,
        key: FlowKey,
        channel: u16,
        weight: u32,
        now: Duration,
    ) -> Result<Binding, PipelineError> {
        self.validate_weight(key, weight)?;
        let new = !self.states.contains_key(&key);
        let transaction = self
            .flows
            .prepare_learn(key, channel, now)
            .map_err(PipelineError::Flow)?;
        let binding = transaction.binding();
        if new && (!self.states.has_room() || !self.by_id.has_room()) {
            return Err(PipelineError::Invariant);
        }
        if new && let Some(qos) = &mut self.qos {
            qos.register_flow(qos_flow(binding.id, weight))
                .map_err(PipelineError::QosFlow)?;
        }
        let binding = transaction.commit();
        if new {
            self.states.insert(
                key,
                FlowState {
                    snapshot: FlowSnapshot {
                        binding,
                        weight,
                        queued: QueueUsage::default(),
                        last_activity: now,
                    },
                    metadata: MetadataQueue::new(self.metadata_pool.is_reserved()),
                },
            )?;
        }
        self.states
            .get_mut(&key)
            .ok_or(PipelineError::Invariant)?
            .snapshot
            .last_activity = now;
        self.by_id.insert(binding.id, key)?;
        Ok(binding)
    }

    /// Hand off one packet when the caller has aggregate downstream capacity.
    ///
    /// TUN selects all flows as eligible; use `dequeue_with` for external credit.
    pub fn dequeue(&mut self) -> Result<Option<Packet>, PipelineError> {
        match self.offer_front(|_, _| Ok::<_, Infallible>(Some(()))) {
            Ok(value) => Ok(value.map(|admitted| admitted.packet)),
            Err(DequeueError::Pipeline(error)) => Err(error),
            Err(DequeueError::Commit(never)) => match never {},
        }
    }

    /// Skip credit-blocked TUN heads, then commit only the selected packet.
    ///
    /// `eligible` checks each active FIFO head once and must never consume credit.
    /// `commit` runs once after selection; failure retains the original bytes and
    /// accounting. Both callbacks and handoff run in this exclusive actor without
    /// I/O or intervening mutation. `None` includes the all-blocked case. TAP
    /// rejects this operation so custom per-flow policy is never silently enabled.
    pub fn dequeue_with<T, E, F, C>(
        &mut self,
        eligible: F,
        commit: C,
    ) -> Result<Option<Admitted<T>>, DequeueError<E>>
    where
        F: FnMut(Candidate) -> bool,
        C: FnOnce(Candidate) -> Result<T, E>,
    {
        self.offer_with(eligible, |metadata, bytes| {
            commit(Candidate {
                key: metadata.classification.key,
                binding: metadata.binding,
                packet_bytes: bytes.len(),
            })
            .map(Some)
        })
    }

    /// Offer exact retained bytes and metadata, using TAP RR or all-eligible TUN.
    ///
    /// `None` or a downstream error retains the actual allocation and accounting.
    /// `Some` transfers the original packet and the returned admission token once.
    pub fn offer_front<T, E>(
        &mut self,
        offer: impl FnOnce(PacketMetadata, &[u8]) -> Result<Option<T>, E>,
    ) -> Result<Option<Admitted<T>>, DequeueError<E>> {
        self.offer_front_inner(offer, true).and_then(owned_handoff)
    }

    /// Offer actual retained bytes and release their slot only after Some permit.
    ///
    /// No owned payload is created or returned. Reserved backing performs no
    /// allocation; refusal retains the same packet, metadata and service debit.
    pub fn offer_front_borrowed<T, E>(
        &mut self,
        offer: impl FnOnce(PacketMetadata, &[u8]) -> Result<Option<T>, E>,
    ) -> Result<Option<Admission<T>>, DequeueError<E>> {
        self.offer_front_inner(offer, false).map(borrowed_handoff)
    }

    fn offer_front_inner<T, E>(
        &mut self,
        offer: impl FnOnce(PacketMetadata, &[u8]) -> Result<Option<T>, E>,
        owned: bool,
    ) -> Result<Option<Handoff<T>>, DequeueError<E>> {
        if self.qos.is_some() {
            return self.offer_with_inner(|_| true, offer, owned);
        }
        let states = &mut self.states;
        let by_id = &self.by_id;
        let channel_metadata = &mut self.channel_metadata;
        let pool = &mut self.metadata_pool;
        let usage = &mut self.usage;
        let mut entered = false;
        let commit = |channel, bytes: &[u8]| {
            entered = true;
            let error = || DequeueError::Pipeline(PipelineError::Invariant);
            let metadata_queue = channel_metadata
                .get_mut(usize::from(channel))
                .ok_or_else(error)?;
            metadata_queue
                .validate_pop(pool)
                .map_err(DequeueError::Pipeline)?;
            let metadata = metadata_queue.front(pool).ok_or_else(error)?;
            let key = metadata.classification.key;
            let state = states.get_mut(&key).ok_or_else(error)?;
            if metadata.binding.channel != channel
                || state.snapshot.binding != metadata.binding
                || by_id.get(&metadata.binding.id) != Some(&key)
                || metadata.classification.observed_bytes != bytes.len()
            {
                return Err(error());
            }
            let flow_usage = subtract_usage(state.snapshot.queued, bytes.len())
                .map_err(DequeueError::Pipeline)?;
            let total_usage =
                subtract_usage(*usage, bytes.len()).map_err(DequeueError::Pipeline)?;
            let Some(token) = offer(metadata, bytes).map_err(DequeueError::Commit)? else {
                return Ok(None);
            };
            if metadata_queue.pop(pool) != Some(metadata) {
                return Err(error());
            }
            state.snapshot.queued = flow_usage;
            *usage = total_usage;
            Ok(Some((metadata, token)))
        };
        let selected = if owned {
            self.mux.offer_front(commit).map(|selected| {
                selected.map(|(_, payload, (metadata, permit))| Handoff {
                    metadata,
                    permit,
                    payload: Some(payload),
                })
            })
        } else {
            self.mux.offer_front_borrowed(commit).map(|selected| {
                selected.map(|(_, (metadata, permit))| Handoff {
                    metadata,
                    permit,
                    payload: None,
                })
            })
        }
        .map_err(mux_offer_error)?;
        match selected {
            None if !entered && self.usage != QueueUsage::default() => {
                Err(DequeueError::Pipeline(PipelineError::Invariant))
            }
            value => Ok(value),
        }
    }

    /// Select an eligible TUN head, then offer its exact retained bytes once.
    ///
    /// Eligibility retains existing DRR traversal semantics. Downstream refusal
    /// spends no service debit and does not move bytes through a second queue.
    /// TAP rejects this per-flow policy before either callback is entered.
    pub fn offer_with<T, E>(
        &mut self,
        eligible: impl FnMut(Candidate) -> bool,
        offer: impl FnOnce(PacketMetadata, &[u8]) -> Result<Option<T>, E>,
    ) -> Result<Option<Admitted<T>>, DequeueError<E>> {
        self.offer_with_inner(eligible, offer, true)
            .and_then(owned_handoff)
    }

    /// Apply the same TUN eligibility/DRR commit without returning owned bytes.
    pub fn offer_with_borrowed<T, E>(
        &mut self,
        eligible: impl FnMut(Candidate) -> bool,
        offer: impl FnOnce(PacketMetadata, &[u8]) -> Result<Option<T>, E>,
    ) -> Result<Option<Admission<T>>, DequeueError<E>> {
        self.offer_with_inner(eligible, offer, false)
            .map(borrowed_handoff)
    }

    fn offer_with_inner<T, E>(
        &mut self,
        mut eligible: impl FnMut(Candidate) -> bool,
        offer: impl FnOnce(PacketMetadata, &[u8]) -> Result<Option<T>, E>,
        owned: bool,
    ) -> Result<Option<Handoff<T>>, DequeueError<E>> {
        let error = DequeueError::Pipeline;
        let qos = self
            .qos
            .as_mut()
            .ok_or_else(|| error(PipelineError::TunOnly))?;
        let states = &self.states;
        let by_id = &self.by_id;
        let mut inconsistent = false;
        let selected = qos
            .peek_eligible(|id, packet_bytes| {
                let Some(key) = by_id.get(&FlowId(id.value())) else {
                    inconsistent = true;
                    return false;
                };
                let Some(state) = states.get(key) else {
                    inconsistent = true;
                    return false;
                };
                eligible(Candidate {
                    key: *key,
                    binding: state.snapshot.binding,
                    packet_bytes,
                })
            })
            .map_err(|source| error(PipelineError::Schedule(source)))?;
        if inconsistent {
            return Err(error(PipelineError::Invariant));
        }
        let Some(head) = selected else {
            return Ok(None);
        };
        let key = *self
            .by_id
            .get(&FlowId(head.flow.value()))
            .ok_or_else(|| error(PipelineError::Invariant))?;
        let state = self
            .states
            .get_mut(&key)
            .ok_or_else(|| error(PipelineError::Invariant))?;
        state
            .metadata
            .validate_pop(&self.metadata_pool)
            .map_err(error)?;
        let metadata = state
            .metadata
            .front(&self.metadata_pool)
            .ok_or_else(|| error(PipelineError::Invariant))?;
        if metadata.classification.key != key
            || metadata.classification.observed_bytes != head.packet_bytes
            || metadata.binding != state.snapshot.binding
            || metadata.binding.id != FlowId(head.flow.value())
            || self.by_id.get(&metadata.binding.id) != Some(&key)
            || state.metadata.len() != state.snapshot.queued.packets
        {
            return Err(error(PipelineError::Invariant));
        }
        let flow_usage = subtract_usage(state.snapshot.queued, head.packet_bytes).map_err(error)?;
        let total_usage = subtract_usage(self.usage, head.packet_bytes).map_err(error)?;
        let mux = &mut self.mux;
        let usage = &mut self.usage;
        let pool = &mut self.metadata_pool;
        let commit = |actual, bytes: &[u8]| {
            if actual != head {
                return Err(error(PipelineError::Invariant));
            }
            let admitted = mux
                .offer_selected(metadata.binding.channel, bytes, |_, bytes| {
                    offer(metadata, bytes).map_err(DequeueError::Commit)
                })
                .map_err(mux_offer_error)?;
            let Some(token) = admitted else {
                return Ok(None);
            };
            if state.metadata.pop(pool) != Some(metadata) {
                return Err(error(PipelineError::Invariant));
            }
            state.snapshot.queued = flow_usage;
            *usage = total_usage;
            Ok(Some(token))
        };
        let selected = if owned {
            qos.offer_selected(commit).map(|selected| {
                selected.map(|(selected, permit)| Handoff {
                    metadata,
                    permit,
                    payload: Some(selected.payload),
                })
            })
        } else {
            qos.offer_selected_borrowed(commit).map(|selected| {
                selected.map(|(_, permit)| Handoff {
                    metadata,
                    permit,
                    payload: None,
                })
            })
        }
        .map_err(|source| match source {
            l2tunnel_qos::OfferError::Schedule(source) => error(PipelineError::Schedule(source)),
            l2tunnel_qos::OfferError::Downstream(source) => source,
        })?;
        Ok(selected)
    }

    /// Aggregate original-packet retention across every stage.
    pub fn usage(&self) -> QueueUsage {
        self.usage
    }

    /// Count of live registrations, including idle learned entries.
    pub fn registered_flows(&self) -> usize {
        self.states.len()
    }

    /// Observe a flow without refreshing its idle age.
    pub fn flow(&self, key: &FlowKey) -> Option<FlowSnapshot> {
        self.states.get(key).map(|state| state.snapshot)
    }

    /// Inspect each live TUN FIFO head without allocation, selection or mutation.
    /// Work is bounded by configured flow capacity; TAP keeps its system policy.
    pub fn tun_flow_heads(&self) -> Result<impl Iterator<Item = FlowHead> + '_, PipelineError> {
        if !matches!(self.config.profile, Profile::TunDrr(_)) {
            return Err(PipelineError::TunOnly);
        }
        Ok(self.states.iter().map(|(key, state)| FlowHead {
            key: *key,
            snapshot: state.snapshot,
            packet_bytes: state
                .metadata
                .front(&self.metadata_pool)
                .map(|packet| packet.classification.observed_bytes),
        }))
    }

    /// Find the oldest locally empty idle flow; external drain is still required.
    pub fn idle_candidate(
        &self,
        now: Duration,
    ) -> Result<Option<(FlowKey, Binding)>, PipelineError> {
        self.flows.oldest_idle(now).map_err(PipelineError::Flow)?;
        Ok(self
            .states
            .iter()
            .filter(|(_, state)| {
                state.snapshot.queued.packets == 0
                    && now - state.snapshot.last_activity >= self.config.flows.idle_timeout
            })
            .min_by_key(|(_, state)| state.snapshot.last_activity)
            .map(|(key, state)| (*key, state.snapshot.binding)))
    }

    /// Examine at most `work` registrations in canonical key order, without allocation.
    ///
    /// A removed cursor key remains valid. Reaching the end resets the cursor for
    /// the next call; zero work still validates time. `excluded` pins a selected
    /// packet whose queue accounting has already been released. The caller must
    /// separately prove downstream registration dependencies drained before using
    /// `retire_idle_drained`; this observation grants no delivery or drain credit.
    pub fn idle_step(
        &self,
        now: Duration,
        after: Option<FlowKey>,
        work: usize,
        excluded: Option<FlowKey>,
    ) -> Result<IdleScan, PipelineError> {
        self.flows.validate_time(now).map_err(PipelineError::Flow)?;
        let mut result = IdleScan {
            after,
            examined: 0,
            candidate: None,
        };
        let mut entries = self.states.after(after);
        for _ in 0..work {
            let Some((key, state)) = entries.next() else {
                result.after = None;
                break;
            };
            result.after = Some(*key);
            result.examined += 1;
            if Some(*key) != excluded
                && state.snapshot.queued.packets == 0
                && now - state.snapshot.last_activity >= self.config.flows.idle_timeout
            {
                result.candidate = Some((*key, state.snapshot.binding));
                break;
            }
        }
        Ok(result)
    }

    /// Retire only an idle locally empty flow after caller-established external drain.
    pub fn retire_idle_drained(
        &mut self,
        key: &FlowKey,
        now: Duration,
    ) -> Result<Binding, PipelineError> {
        let state = self
            .states
            .get(key)
            .ok_or(PipelineError::Flow(l2tunnel_packet::FlowError::UnknownFlow))?;
        if state.snapshot.queued.packets != 0 {
            return Err(PipelineError::Busy);
        }
        let binding = self
            .flows
            .retire_idle(key, now)
            .map_err(PipelineError::Flow)?;
        if let Some(qos) = &mut self.qos {
            qos.remove_flow(l2tunnel_qos::FlowId::new(binding.id.0))
                .map_err(PipelineError::QosFlow)?;
        }
        self.states.remove(key);
        self.by_id.remove(&binding.id);
        Ok(binding)
    }

    /// Retire an empty flow after an explicit downstream drain, without an idle wait.
    /// The caller must freeze admission and complete its reliable final barrier first.
    pub fn retire_drained(&mut self, key: &FlowKey) -> Result<Binding, PipelineError> {
        let state = self
            .states
            .get(key)
            .ok_or(PipelineError::Flow(l2tunnel_packet::FlowError::UnknownFlow))?;
        if state.snapshot.queued.packets != 0 {
            return Err(PipelineError::Busy);
        }
        let binding = self
            .flows
            .remove_drained(key)
            .ok_or(PipelineError::Invariant)?;
        if let Some(qos) = &mut self.qos {
            qos.remove_flow(l2tunnel_qos::FlowId::new(binding.id.0))
                .map_err(PipelineError::QosFlow)?;
        }
        self.states.remove(key);
        self.by_id.remove(&binding.id);
        Ok(binding)
    }

    /// Inherit nonreusable IDs from a completely retired pipeline into a fresh one.
    /// Caller authorization and downstream ownership are outside this local proof.
    pub fn continue_ids_from(&mut self, previous: &Self) -> Result<(), PipelineError> {
        if self.usage != QueueUsage::default()
            || previous.usage != QueueUsage::default()
            || !self.states.is_empty()
            || !previous.states.is_empty()
            || !self.by_id.is_empty()
            || !previous.by_id.is_empty()
        {
            return Err(PipelineError::Busy);
        }
        self.flows
            .continue_ids_from(&previous.flows)
            .map_err(PipelineError::Flow)
    }

    fn validate_weight(&self, key: FlowKey, weight: u32) -> Result<(), PipelineError> {
        match self.config.profile {
            Profile::TapSystem if weight != 1 => return Err(PipelineError::TunOnly),
            Profile::TunDrr(policy) if weight == 0 || weight > policy.max_weight => {
                return Err(PipelineError::InvalidWeight);
            }
            _ => {}
        }
        if self
            .states
            .get(&key)
            .is_some_and(|state| state.snapshot.weight != weight)
        {
            return Err(PipelineError::WeightChanged);
        }
        Ok(())
    }

    fn preflight(
        &self,
        key: FlowKey,
        length: usize,
        weight: u32,
    ) -> Result<(QueueUsage, QueueUsage), PipelineError> {
        self.validate_weight(key, weight)?;
        let total = add_usage(
            self.usage,
            length,
            self.config.queue,
            Budget::Bytes,
            Budget::Packets,
        )?;
        let old = self
            .states
            .get(&key)
            .map_or(QueueUsage::default(), |state| state.snapshot.queued);
        let per_flow = match self.config.profile {
            Profile::TapSystem => add_usage(
                old,
                length,
                self.config.queue,
                Budget::Bytes,
                Budget::Packets,
            )?,
            Profile::TunDrr(policy) => add_usage(
                old,
                length,
                policy.per_flow,
                Budget::FlowBytes,
                Budget::FlowPackets,
            )?,
        };
        Ok((total, per_flow))
    }
}

enum Input<'a> {
    Owned(Vec<u8>),
    Borrowed(&'a [u8]),
}

impl<'a> Input<'a> {
    fn bytes(&self) -> &[u8] {
        match self {
            Self::Owned(bytes) => bytes,
            Self::Borrowed(bytes) => bytes,
        }
    }
    fn prepare(self, reserved: bool) -> Result<Self, Self> {
        match self {
            Self::Borrowed(bytes) if !reserved => {
                let mut owned = Vec::new();
                if owned.try_reserve_exact(bytes.len()).is_err() {
                    return Err(Self::Borrowed(bytes));
                }
                owned.extend_from_slice(bytes);
                Ok(Self::Owned(owned))
            }
            input => Ok(input),
        }
    }
    fn into_owned(self) -> Vec<u8> {
        match self {
            Self::Owned(bytes) => bytes,
            Self::Borrowed(bytes) => bytes.to_vec(),
        }
    }
}

fn owned_handoff<T, E>(
    handoff: Option<Handoff<T>>,
) -> Result<Option<Admitted<T>>, DequeueError<E>> {
    handoff
        .map(|handoff| {
            let payload = handoff
                .payload
                .ok_or(DequeueError::Pipeline(PipelineError::Invariant))?;
            Ok(Admitted {
                packet: Packet {
                    payload,
                    metadata: handoff.metadata,
                },
                permit: handoff.permit,
            })
        })
        .transpose()
}

fn borrowed_handoff<T>(handoff: Option<Handoff<T>>) -> Option<Admission<T>> {
    handoff.map(|handoff| Admission {
        metadata: handoff.metadata,
        permit: handoff.permit,
    })
}

fn qos_admission_error(error: l2tunnel_qos::AdmissionErrorKind) -> PipelineError {
    match error {
        l2tunnel_qos::AdmissionErrorKind::Allocation => PipelineError::Allocation,
        _ => PipelineError::Invariant,
    }
}

fn mux_admission_error(error: l2tunnel_mux::BorrowedAdmissionError) -> PipelineError {
    match error {
        l2tunnel_mux::BorrowedAdmissionError::Allocation => PipelineError::Allocation,
        _ => PipelineError::Invariant,
    }
}

fn mux_offer_error<E>(source: l2tunnel_mux::OfferError<DequeueError<E>>) -> DequeueError<E> {
    match source {
        l2tunnel_mux::OfferError::Downstream(error) => error,
        l2tunnel_mux::OfferError::Allocation => DequeueError::Pipeline(PipelineError::Allocation),
        _ => DequeueError::Pipeline(PipelineError::Invariant),
    }
}

fn subtract_usage(old: QueueUsage, length: usize) -> Result<QueueUsage, PipelineError> {
    if length == 0 {
        return Err(PipelineError::Invariant);
    }
    let remaining = QueueUsage {
        bytes: old
            .bytes
            .checked_sub(length)
            .ok_or(PipelineError::Invariant)?,
        packets: old.packets.checked_sub(1).ok_or(PipelineError::Invariant)?,
    };
    if (remaining.packets == 0) != (remaining.bytes == 0) {
        return Err(PipelineError::Invariant);
    }
    Ok(remaining)
}

const TUN_CLASSES: [ClassConfig; 1] = [ClassConfig {
    id: ClassId::new(0),
    weight: 1,
}];

fn scheduler_config(config: PipelineConfig, policy: TunQosConfig) -> SchedulerConfig {
    SchedulerConfig {
        base_quantum_bytes: policy.base_quantum_bytes,
        max_classes: 1,
        max_flows: config.flows.capacity,
        max_packet_bytes: config.parse.max_packet_bytes,
        max_queued_bytes: config.queue.bytes,
        max_queued_packets: config.queue.packets,
        per_flow_bytes: policy.per_flow.bytes,
        per_flow_packets: policy.per_flow.packets,
    }
}

fn qos_flow(id: FlowId, weight: u32) -> FlowConfig {
    FlowConfig {
        id: l2tunnel_qos::FlowId::new(id.0),
        class: ClassId::new(0),
        weight,
    }
}

fn add_usage(
    old: QueueUsage,
    bytes: usize,
    limit: QueueLimits,
    byte_error: Budget,
    count_error: Budget,
) -> Result<QueueUsage, PipelineError> {
    let bytes = old
        .bytes
        .checked_add(bytes)
        .filter(|value| *value <= limit.bytes)
        .ok_or(PipelineError::Budget(byte_error))?;
    let packets = old
        .packets
        .checked_add(1)
        .filter(|value| *value <= limit.packets)
        .ok_or(PipelineError::Budget(count_error))?;
    Ok(QueueUsage { bytes, packets })
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod validation_tests;

#[cfg(test)]
mod handoff_tests;

#[cfg(test)]
mod storage_tests;
