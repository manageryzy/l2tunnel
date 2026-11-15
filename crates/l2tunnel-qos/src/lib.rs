//! Bounded byte-accounted weighted deficit round-robin scheduling.
//!
//! This is a flat per-flow scheduler: effective quantum is the base quantum times
//! class weight times flow weight. Aggregate class guarantees, AQM, classification,
//! receiver credit, congestion control and pacing remain outside this primitive.
//! All opaque user packets use the same admission path, without probe exceptions.
use std::collections::{BTreeMap, VecDeque};
use std::fmt;

mod backing;
pub mod storage;

/// Caller-assigned local flow identity; peer generation/replay checks are external.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct FlowId(u64);

impl FlowId {
    /// Construct an opaque flow identifier.
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Return the underlying identifier.
    pub const fn value(self) -> u64 {
        self.0
    }
}

/// Caller-assigned traffic class identity.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ClassId(u16);

impl ClassId {
    /// Construct an opaque class identifier.
    pub const fn new(value: u16) -> Self {
        Self(value)
    }

    /// Return the underlying identifier.
    pub const fn value(self) -> u16 {
        self.0
    }
}

/// Fixed resource bounds for one scheduling direction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SchedulerConfig {
    /// Base byte quantum, multiplied by class and flow weights.
    pub base_quantum_bytes: u32,
    /// Maximum configured classes.
    pub max_classes: usize,
    /// Maximum registered flows, including idle flows.
    pub max_flows: usize,
    /// Maximum accepted opaque packet length.
    pub max_packet_bytes: usize,
    /// Maximum payload bytes retained across all flows.
    pub max_queued_bytes: usize,
    /// Maximum packets retained across all flows.
    pub max_queued_packets: usize,
    /// Maximum payload bytes retained by any one flow.
    pub per_flow_bytes: usize,
    /// Maximum packets retained by any one flow.
    pub per_flow_packets: usize,
}

impl SchedulerConfig {
    /// Validate limits and class policy without allocating scheduler storage.
    pub fn validate(self, classes: &[ClassConfig]) -> Result<(), ConfigError> {
        if self.base_quantum_bytes == 0
            || self.max_classes == 0
            || self.max_flows == 0
            || self.max_packet_bytes == 0
            || self.max_queued_bytes == 0
            || self.max_queued_packets == 0
            || self.per_flow_bytes == 0
            || self.per_flow_packets == 0
        {
            return Err(ConfigError::ZeroLimit);
        }
        if self.max_packet_bytes > self.per_flow_bytes
            || self.per_flow_bytes > self.max_queued_bytes
            || self.per_flow_packets > self.max_queued_packets
        {
            return Err(ConfigError::InconsistentBounds);
        }
        if classes.is_empty() {
            return Err(ConfigError::NoClasses);
        }
        if classes.len() > self.max_classes {
            return Err(ConfigError::TooManyClasses);
        }
        // ClassId covers the complete u16 domain; validation needs no heap map.
        let mut seen = [0_u64; 1024];
        for class in classes {
            if class.weight == 0 {
                return Err(ConfigError::ZeroWeight);
            }
            weighted_quantum(self, class.weight, 1).ok_or(ConfigError::Arithmetic)?;
            let index = usize::from(class.id.value());
            let mask = 1_u64 << (index % 64);
            let word = &mut seen[index / 64];
            if *word & mask != 0 {
                return Err(ConfigError::DuplicateClass);
            }
            *word |= mask;
        }
        Ok(())
    }

    /// Validate one weight against an existing class and return its byte quantum.
    /// A missing class is checked after zero flow weight, matching registration.
    /// The supplied class weight must come from validated class configuration.
    pub fn flow_quantum(
        self,
        class_weight: Option<u32>,
        flow_weight: u32,
    ) -> Result<u64, FlowError> {
        if flow_weight == 0 {
            return Err(FlowError::ZeroWeight);
        }
        let class_weight = class_weight.ok_or(FlowError::UnknownClass)?;
        weighted_quantum(self, class_weight, flow_weight).ok_or(FlowError::Arithmetic)
    }
}

/// An immutable class multiplier; not an aggregate class bandwidth guarantee.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClassConfig {
    /// Unique local class identifier.
    pub id: ClassId,
    /// Nonzero multiplier used by every registered flow in this class.
    pub weight: u32,
}

/// Registration settings for one local flow.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FlowConfig {
    /// Unique local flow identifier.
    pub id: FlowId,
    /// An existing configured class.
    pub class: ClassId,
    /// Nonzero per-flow quantum multiplier.
    pub weight: u32,
}

/// Configuration validation failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConfigError {
    /// A resource limit or base quantum is zero.
    ZeroLimit,
    /// Per-flow or per-packet bounds exceed their enclosing bounds.
    InconsistentBounds,
    /// At least one class must be configured.
    NoClasses,
    /// The class count exceeds the configured limit.
    TooManyClasses,
    /// Two class entries use the same identifier.
    DuplicateClass,
    /// A class weight is zero.
    ZeroWeight,
    /// A quantum or its maximum deficit cannot be represented.
    Arithmetic,
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid scheduler configuration: {self:?}")
    }
}

impl std::error::Error for ConfigError {}

/// Flow registration or mutation failure; rejected operations preserve state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FlowError {
    /// This flow identifier is already registered.
    Duplicate,
    /// The requested flow is not registered.
    UnknownFlow,
    /// The requested class is not configured.
    UnknownClass,
    /// The maximum registered flow count has been reached.
    Capacity,
    /// Removal and weight changes require an empty queue.
    Busy,
    /// The requested weight is zero.
    ZeroWeight,
    /// The weighted quantum or maximum deficit is not representable.
    Arithmetic,
}

impl fmt::Display for FlowError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "scheduler flow operation failed: {self:?}")
    }
}

impl std::error::Error for FlowError {}

/// Why a packet was rejected without changing scheduler state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdmissionErrorKind {
    /// The supplied flow is not registered.
    UnknownFlow,
    /// Empty packets are not admitted.
    EmptyPacket,
    /// Packet length exceeds the configured maximum.
    PacketTooLarge,
    /// Global retained payload bytes would exceed their limit.
    GlobalBytes,
    /// Global retained packet count would exceed its limit.
    GlobalPackets,
    /// This flow's retained payload bytes would exceed their limit.
    FlowBytes,
    /// This flow's retained packet count would exceed its limit.
    FlowPackets,
    /// Internal fixed-pool/index/ring state is inconsistent; no packet was copied.
    Invariant,
    /// Legacy borrowed-copy convenience could not reserve caller-independent bytes.
    Allocation,
}

/// Rejected admission with ownership of the original payload.
#[derive(Debug, Eq, PartialEq)]
pub struct AdmissionError {
    /// Typed rejection reason.
    pub kind: AdmissionErrorKind,
    /// Original payload, including its original allocation.
    pub payload: Vec<u8>,
}

impl fmt::Display for AdmissionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "scheduler packet admission failed: {:?}", self.kind)
    }
}

impl std::error::Error for AdmissionError {}

/// Defensive scheduling failure; validated public inputs should not produce one.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ScheduleError {
    /// A checked counter or deficit operation failed.
    Arithmetic,
    /// Internal queue/ring/accounting state is inconsistent.
    Invariant,
    /// Caller-owned output for an allocating convenience method could not be reserved.
    Allocation,
}

impl fmt::Display for ScheduleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "scheduler state failure: {self:?}")
    }
}

impl std::error::Error for ScheduleError {}

/// Selected-head refusal before service, preserving scheduler error categories.
#[derive(Debug, Eq, PartialEq)]
pub enum OfferError<E> {
    /// Defensive scheduling or checked-arithmetic failure before admission.
    Schedule(ScheduleError),
    /// Downstream admission error; the selected payload remains retained.
    Downstream(E),
}

/// One selected packet; selection is not a grant of path congestion allowance.
#[derive(Debug, Eq, PartialEq)]
pub struct ScheduledPacket {
    /// Flow whose FIFO supplied the packet.
    pub flow: FlowId,
    /// Configured traffic class for later attribution.
    pub class: ClassId,
    /// Unchanged opaque user packet.
    pub payload: Vec<u8>,
}

/// Non-consuming view of one selected FIFO head.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PacketHead {
    /// Flow owning the packet.
    pub flow: FlowId,
    /// Configured traffic class.
    pub class: ClassId,
    /// Original retained packet bytes.
    pub packet_bytes: usize,
}

struct Flow {
    class: ClassId,
    quantum: u64,
    deficit: u64,
    bytes: usize,
    packets: VecDeque<Box<[u8]>>,
    eligible: bool,
    fixed: Option<backing::Fifo>,
}
impl Flow {
    fn packet_count(&self) -> usize {
        self.fixed.map_or_else(|| self.packets.len(), |q| q.len)
    }
}

#[derive(Clone, Copy)]
struct Service {
    head: PacketHead,
    deficit: u64,
    flow_bytes: usize,
    queued_bytes: usize,
    queued_packets: usize,
    last: bool,
}
impl Service {
    fn commit_flow(self, flow: &mut Flow) {
        flow.deficit = if self.last { 0 } else { self.deficit };
        flow.bytes = self.flow_bytes;
    }
}

/// One direction's bounded, work-conserving flat weighted DRR scheduler.
///
/// Empty registered flows are absent from the active ring. Class weights are
/// immutable; flow weights/removal may change only when the flow is empty. These
/// local operations are not a negotiated peer configuration switch.
pub struct Scheduler {
    config: SchedulerConfig,
    classes: BTreeMap<ClassId, u32>,
    flows: BTreeMap<FlowId, Flow>,
    active: VecDeque<FlowId>,
    in_visit: bool,
    queued_bytes: usize,
    queued_packets: usize,
    selected: Option<PacketHead>,
    // The unused legacy containers above stay empty and allocate no backing for
    // a reserved owner. Their actual inline headers belong to size_of<Self>.
    reserved: Option<backing::Reserved>,
}

impl Scheduler {
    /// Validate configuration and construct an empty scheduler without I/O.
    pub fn new(config: SchedulerConfig, classes: &[ClassConfig]) -> Result<Self, ConfigError> {
        config.validate(classes)?;
        let class_map = classes
            .iter()
            .map(|class| (class.id, class.weight))
            .collect();
        Ok(Self {
            config,
            classes: class_map,
            flows: BTreeMap::new(),
            active: VecDeque::new(),
            in_visit: false,
            queued_bytes: 0,
            queued_packets: 0,
            selected: None,
            reserved: None,
        })
    }

    /// Reserve the complete actual class/flow/ring/packet/slab inventory fallibly.
    pub fn new_reserved(
        config: SchedulerConfig,
        classes: &[ClassConfig],
        limits: storage::Limits,
    ) -> Result<Self, storage::Error> {
        let plan = storage::Plan::for_scheduler(config, classes)?;
        let mut allocation = storage::Allocation::new(plan, limits)?;
        let reserved = backing::Reserved::new(plan, classes, &mut allocation)?;
        Ok(Self {
            config,
            classes: BTreeMap::new(),
            flows: BTreeMap::new(),
            active: VecDeque::new(),
            in_visit: false,
            queued_bytes: 0,
            queued_packets: 0,
            selected: None,
            reserved: Some(reserved),
        })
    }

    /// Actual retained managed heap; allocating construction returns None.
    pub fn storage_usage(&self) -> Option<storage::Usage> {
        self.reserved.as_ref().and_then(|r| r.usage)
    }

    /// Register an idle flow; registration alone earns no deficit or ring entry.
    pub fn register_flow(&mut self, config: FlowConfig) -> Result<(), FlowError> {
        if self.flow(config.id).is_some() {
            return Err(FlowError::Duplicate);
        }
        if self.registered_flows() >= self.config.max_flows {
            return Err(FlowError::Capacity);
        }
        let quantum = self.flow_quantum(config.class, config.weight)?;
        let flow = Flow {
            class: config.class,
            quantum,
            deficit: 0,
            bytes: 0,
            packets: VecDeque::new(),
            eligible: true,
            fixed: None,
        };
        if let Some(reserved) = &mut self.reserved {
            reserved.insert(config.id, flow)?;
        } else {
            self.flows.insert(config.id, flow);
        }
        self.selected = None;
        Ok(())
    }

    /// Change an empty flow's weight; active queues cannot gain a mid-visit boost.
    pub fn set_flow_weight(&mut self, id: FlowId, weight: u32) -> Result<(), FlowError> {
        let flow = self.flow(id).ok_or(FlowError::UnknownFlow)?;
        if flow.packet_count() != 0 {
            return Err(FlowError::Busy);
        }
        let quantum = self.flow_quantum(flow.class, weight)?;
        let flow = self.flow_mut(id).ok_or(FlowError::UnknownFlow)?;
        flow.quantum = quantum;
        self.selected = None;
        Ok(())
    }

    /// Remove an empty flow without discarding packets from any flow.
    ///
    /// Reuse of the numeric ID is locally allowed. The caller must separately
    /// enforce peer/session generation and retirement rules before reuse.
    pub fn remove_flow(&mut self, id: FlowId) -> Result<(), FlowError> {
        let flow = self.flow(id).ok_or(FlowError::UnknownFlow)?;
        if flow.packet_count() != 0 {
            return Err(FlowError::Busy);
        }
        if let Some(reserved) = &mut self.reserved {
            reserved.remove(id)?;
        } else {
            self.flows.remove(&id);
        }
        self.selected = None;
        Ok(())
    }

    /// Admit an opaque packet under the same byte/count policy as every user packet.
    ///
    /// A rejected packet is returned unchanged and no scheduler state is changed.
    /// Accepted storage discards excess caller allocation capacity.
    pub fn enqueue(&mut self, id: FlowId, payload: Vec<u8>) -> Result<(), AdmissionError> {
        if let Some(kind) = self.admission_failure(id, payload.len()) {
            return Err(AdmissionError { kind, payload });
        }
        if let Some(reserved) = &mut self.reserved {
            let prepared = match reserved.preflight_enqueue(id, payload.len()) {
                Ok(prepared) => prepared,
                Err(kind) => return Err(AdmissionError { kind, payload }),
            };
            reserved.enqueue(id, &payload, prepared);
            self.queued_bytes += payload.len();
            self.queued_packets += 1;
            self.selected = None;
            return Ok(());
        }
        let Some(flow) = self.flows.get_mut(&id) else {
            return Err(AdmissionError {
                kind: AdmissionErrorKind::UnknownFlow,
                payload,
            });
        };
        // admission_failure checked all additions against their enclosing bounds.
        let length = payload.len();
        if flow.packets.is_empty() {
            self.active.push_back(id);
        }
        flow.bytes += length;
        self.queued_bytes += length;
        self.queued_packets += 1;
        flow.packets.push_back(payload.into_boxed_slice());
        self.selected = None;
        Ok(())
    }

    /// Admit borrowed bytes through the same policy and actual queue ownership.
    /// Reserved backing copies once into its slab without allocation; the legacy
    /// convenience path fallibly creates its owned normalized payload first.
    pub fn enqueue_borrowed(
        &mut self,
        id: FlowId,
        payload: &[u8],
    ) -> Result<(), AdmissionErrorKind> {
        if let Some(error) = self.admission_failure(id, payload.len()) {
            return Err(error);
        }
        if let Some(reserved) = &mut self.reserved {
            let prepared = reserved.preflight_enqueue(id, payload.len())?;
            reserved.enqueue(id, payload, prepared);
            self.queued_bytes += payload.len();
            self.queued_packets += 1;
            self.selected = None;
            return Ok(());
        }
        let mut owned = Vec::new();
        owned
            .try_reserve_exact(payload.len())
            .map_err(|_| AdmissionErrorKind::Allocation)?;
        owned.extend_from_slice(payload);
        self.enqueue(id, owned).map_err(|e| e.kind)
    }

    /// Select one FIFO packet whenever at least one flow is queued.
    ///
    /// Deficit-only empty rounds are skipped arithmetically. Work is a constant
    /// number of active-ring scans, independent of packet-length/quantum ratio.
    /// Call only when downstream can retain one maximum-sized packet: receiver
    /// credit, MUX admission, path congestion allowance and pacing are external.
    pub fn dequeue(&mut self) -> Result<Option<ScheduledPacket>, ScheduleError> {
        self.dequeue_eligible(|_, _| true)
    }

    /// Select and remove an eligible head; the callback must only inspect credit.
    ///
    /// The callback receives each active FIFO head exactly once per call. A
    /// blocked flow retains its bytes and resets its deficit; it cannot block
    /// other eligible flows or accumulate a later burst. `None` may mean all
    /// retained flows are blocked, not that the queue is empty.
    pub fn dequeue_eligible<F>(
        &mut self,
        eligible: F,
    ) -> Result<Option<ScheduledPacket>, ScheduleError>
    where
        F: FnMut(FlowId, usize) -> bool,
    {
        self.peek_eligible(eligible)?;
        self.dequeue_peeked()
    }

    /// Select without removing a packet or charging its deficit.
    ///
    /// Eligibility is a pure once-per-active-head snapshot for this call. Work
    /// is a constant number of active-flow scans; blocked deficits reset to zero.
    /// Successful queue/flow mutations invalidate selection. The caller may
    /// commit external credit then call `dequeue_peeked` in the same actor with
    /// no intervening mutation. Repeated peeks cannot consume or bank credit.
    pub fn peek_eligible<F>(&mut self, mut eligible: F) -> Result<Option<PacketHead>, ScheduleError>
    where
        F: FnMut(FlowId, usize) -> bool,
    {
        self.selected = None;
        let mut any = false;
        for index in 0..self.active_flows() {
            let id = self.active_id(index).ok_or(ScheduleError::Invariant)?;
            let length = self.front_length(id).ok_or(ScheduleError::Invariant)?;
            let flow = self.flow_mut(id).ok_or(ScheduleError::Invariant)?;
            flow.eligible = eligible(id, length);
            if flow.eligible {
                any = true;
            } else {
                flow.deficit = 0;
            }
        }
        if !any {
            self.in_visit = false;
            return if self.active_flows() == 0
                && (self.queued_packets != 0 || self.queued_bytes != 0)
            {
                Err(ScheduleError::Invariant)
            } else {
                Ok(None)
            };
        }
        if self.in_visit {
            if let Some(head) = self.peek_visit()? {
                self.selected = Some(head);
                return Ok(self.selected);
            }
            self.rotate()?;
        }
        if let Some(head) = self.scan_round()? {
            self.selected = Some(head);
            return Ok(self.selected);
        }
        self.skip_empty_rounds()?;
        self.selected = Some(self.scan_round()?.ok_or(ScheduleError::Invariant)?);
        Ok(self.selected)
    }

    /// Commit the last still-valid selected head once, without new eligibility calls.
    ///
    /// A failed external credit commit can leave the selection and payload intact.
    /// Successful queue/flow mutation requires a fresh peek before calling again.
    pub fn dequeue_peeked(&mut self) -> Result<Option<ScheduledPacket>, ScheduleError> {
        match self.offer_selected(|_, _| Ok::<_, std::convert::Infallible>(Some(()))) {
            Ok(packet) => Ok(packet.map(|(packet, ())| packet)),
            Err(OfferError::Schedule(error)) => Err(error),
            Err(OfferError::Downstream(never)) => match never {},
        }
    }

    /// Offer the actual selected bytes without another eligibility scan or debit.
    ///
    /// Selection retains the existing DRR traversal/credit semantics. `None` or
    /// an error from downstream keeps that selection and original FIFO allocation;
    /// only `Some` spends the preflighted service charge and transfers ownership.
    pub fn offer_selected<T, E>(
        &mut self,
        offer: impl FnOnce(PacketHead, &[u8]) -> Result<Option<T>, E>,
    ) -> Result<Option<(ScheduledPacket, T)>, OfferError<E>> {
        let mut payload = Vec::new();
        self.offer_selected_into(Some(&mut payload), offer)
            .map(|result| {
                result.map(|(head, token)| {
                    (
                        ScheduledPacket {
                            flow: head.flow,
                            class: head.class,
                            payload,
                        },
                        token,
                    )
                })
            })
    }

    /// Offer exact selected bytes, then recycle actual custody only after Some.
    /// Neither refusal nor successful reserved service allocates an owned output.
    pub fn offer_selected_borrowed<T, E>(
        &mut self,
        offer: impl FnOnce(PacketHead, &[u8]) -> Result<Option<T>, E>,
    ) -> Result<Option<(PacketHead, T)>, OfferError<E>> {
        self.offer_selected_into(None, offer)
    }

    fn service_preflight(&self) -> Result<Option<Service>, ScheduleError> {
        let Some(selected) = self.selected else {
            return Ok(None);
        };
        if self.peek_visit()? != Some(selected) {
            return Err(ScheduleError::Invariant);
        }
        let flow = self.flow(selected.flow).ok_or(ScheduleError::Invariant)?;
        let length = selected.packet_bytes;
        if length == 0 {
            return Err(ScheduleError::Invariant);
        }
        let charge = u64::try_from(length).map_err(|_| ScheduleError::Arithmetic)?;
        let deficit = flow
            .deficit
            .checked_sub(charge)
            .ok_or(ScheduleError::Arithmetic)?;
        let flow_bytes = flow
            .bytes
            .checked_sub(length)
            .ok_or(ScheduleError::Arithmetic)?;
        let queued_bytes = self
            .queued_bytes
            .checked_sub(length)
            .ok_or(ScheduleError::Arithmetic)?;
        let queued_packets = self
            .queued_packets
            .checked_sub(1)
            .ok_or(ScheduleError::Arithmetic)?;
        let last = flow.packet_count() == 1;
        if last != (flow_bytes == 0) || (queued_packets == 0) != (queued_bytes == 0) {
            return Err(ScheduleError::Invariant);
        }
        Ok(Some(Service {
            head: selected,
            deficit,
            flow_bytes,
            queued_bytes,
            queued_packets,
            last,
        }))
    }

    fn offer_selected_into<T, E>(
        &mut self,
        mut output: Option<&mut Vec<u8>>,
        offer: impl FnOnce(PacketHead, &[u8]) -> Result<Option<T>, E>,
    ) -> Result<Option<(PacketHead, T)>, OfferError<E>> {
        let schedule = OfferError::Schedule;
        let Some(service) = self.service_preflight().map_err(schedule)? else {
            return Ok(None);
        };
        let token = if let Some(reserved) = &mut self.reserved {
            let parts = reserved.service(service).map_err(schedule)?;
            if let Some(output) = output.as_deref_mut() {
                output
                    .try_reserve_exact(parts.bytes.len())
                    .map_err(|_| schedule(ScheduleError::Allocation))?;
                output.extend_from_slice(parts.bytes);
            }
            let Some(token) = offer(service.head, parts.bytes).map_err(OfferError::Downstream)?
            else {
                return Ok(None);
            };
            parts.commit(service);
            token
        } else {
            let flow = self
                .flows
                .get_mut(&service.head.flow)
                .ok_or_else(|| schedule(ScheduleError::Invariant))?;
            let front = flow
                .packets
                .front_mut()
                .ok_or_else(|| schedule(ScheduleError::Invariant))?;
            let Some(token) = offer(service.head, front).map_err(OfferError::Downstream)? else {
                return Ok(None);
            };
            let payload = std::mem::take(front);
            flow.packets.pop_front();
            service.commit_flow(flow);
            if service.last {
                flow.packets = VecDeque::new();
            }
            if let Some(output) = output {
                *output = payload.into_vec();
            }
            token
        };
        self.queued_bytes = service.queued_bytes;
        self.queued_packets = service.queued_packets;
        if service.last {
            if let Some(reserved) = &mut self.reserved {
                reserved.pop_active();
            } else {
                self.active.pop_front();
            }
            self.in_visit = false;
        }
        self.selected = None;
        Ok(Some((service.head, token)))
    }

    /// Payload bytes retained inside this scheduler, excluding downstream queues.
    pub fn queued_bytes(&self) -> usize {
        self.queued_bytes
    }

    /// Number of packets retained inside this scheduler.
    pub fn queued_packets(&self) -> usize {
        self.queued_packets
    }

    /// Registered flow count, including idle flows.
    pub fn registered_flows(&self) -> usize {
        self.reserved
            .as_ref()
            .map_or_else(|| self.flows.len(), |r| r.registered())
    }

    /// Nonempty flow count; only these entries are traversed for scheduling.
    pub fn active_flows(&self) -> usize {
        self.reserved
            .as_ref()
            .map_or_else(|| self.active.len(), |r| r.active_len())
    }

    fn flow_quantum(&self, class: ClassId, weight: u32) -> Result<u64, FlowError> {
        let class_weight = self.reserved.as_ref().map_or_else(
            || self.classes.get(&class).copied(),
            |r| r.class_weight(class),
        );
        self.config.flow_quantum(class_weight, weight)
    }

    fn admission_failure(&self, id: FlowId, length: usize) -> Option<AdmissionErrorKind> {
        let Some(flow) = self.flow(id) else {
            return Some(AdmissionErrorKind::UnknownFlow);
        };
        if length == 0 {
            Some(AdmissionErrorKind::EmptyPacket)
        } else if length > self.config.max_packet_bytes {
            Some(AdmissionErrorKind::PacketTooLarge)
        } else if self
            .queued_bytes
            .checked_add(length)
            .is_none_or(|total| total > self.config.max_queued_bytes)
        {
            Some(AdmissionErrorKind::GlobalBytes)
        } else if self.queued_packets >= self.config.max_queued_packets {
            Some(AdmissionErrorKind::GlobalPackets)
        } else if flow
            .bytes
            .checked_add(length)
            .is_none_or(|total| total > self.config.per_flow_bytes)
        {
            Some(AdmissionErrorKind::FlowBytes)
        } else if flow.packet_count() >= self.config.per_flow_packets {
            Some(AdmissionErrorKind::FlowPackets)
        } else {
            None
        }
    }

    fn rotate(&mut self) -> Result<(), ScheduleError> {
        if let Some(reserved) = &mut self.reserved {
            reserved.rotate()?;
        } else {
            let id = self.active.pop_front().ok_or(ScheduleError::Invariant)?;
            self.active.push_back(id);
        }
        self.in_visit = false;
        Ok(())
    }

    fn scan_round(&mut self) -> Result<Option<PacketHead>, ScheduleError> {
        for _ in 0..self.active_flows() {
            let id = self.active_id(0).ok_or(ScheduleError::Invariant)?;
            let flow = self.flow_mut(id).ok_or(ScheduleError::Invariant)?;
            if !flow.eligible {
                self.rotate()?;
                continue;
            }
            flow.deficit = flow
                .deficit
                .checked_add(flow.quantum)
                .ok_or(ScheduleError::Arithmetic)?;
            self.in_visit = true;
            if let Some(packet) = self.peek_visit()? {
                return Ok(Some(packet));
            }
            self.rotate()?;
        }
        Ok(None)
    }

    fn peek_visit(&self) -> Result<Option<PacketHead>, ScheduleError> {
        let id = self.active_id(0).ok_or(ScheduleError::Invariant)?;
        let flow = self.flow(id).ok_or(ScheduleError::Invariant)?;
        let length = self.front_length(id).ok_or(ScheduleError::Invariant)?;
        let charge = u64::try_from(length).map_err(|_| ScheduleError::Arithmetic)?;
        Ok(
            (flow.eligible && charge <= flow.deficit).then_some(PacketHead {
                flow: id,
                class: flow.class,
                packet_bytes: length,
            }),
        )
    }

    fn skip_empty_rounds(&mut self) -> Result<(), ScheduleError> {
        let mut next_round = u64::MAX;
        for index in 0..self.active_flows() {
            let id = self.active_id(index).ok_or(ScheduleError::Invariant)?;
            let flow = self.flow(id).ok_or(ScheduleError::Invariant)?;
            if !flow.eligible {
                continue;
            }
            let length = self.front_length(id).ok_or(ScheduleError::Invariant)?;
            let charge = u64::try_from(length).map_err(|_| ScheduleError::Arithmetic)?;
            let missing = charge
                .checked_sub(flow.deficit)
                .filter(|value| *value != 0)
                .ok_or(ScheduleError::Invariant)?;
            next_round = next_round.min(missing.div_ceil(flow.quantum));
        }
        let skip = next_round.checked_sub(1).ok_or(ScheduleError::Invariant)?;
        for index in 0..self.active_flows() {
            let id = self.active_id(index).ok_or(ScheduleError::Invariant)?;
            let flow = self.flow_mut(id).ok_or(ScheduleError::Invariant)?;
            if !flow.eligible {
                continue;
            }
            let credit = skip
                .checked_mul(flow.quantum)
                .ok_or(ScheduleError::Arithmetic)?;
            flow.deficit = flow
                .deficit
                .checked_add(credit)
                .ok_or(ScheduleError::Arithmetic)?;
        }
        Ok(())
    }
    fn flow(&self, id: FlowId) -> Option<&Flow> {
        self.reserved
            .as_ref()
            .map_or_else(|| self.flows.get(&id), |r| r.flow(id))
    }
    fn flow_mut(&mut self, id: FlowId) -> Option<&mut Flow> {
        if let Some(reserved) = &mut self.reserved {
            reserved.flow_mut(id)
        } else {
            self.flows.get_mut(&id)
        }
    }
    fn active_id(&self, index: usize) -> Option<FlowId> {
        self.reserved
            .as_ref()
            .map_or_else(|| self.active.get(index).copied(), |r| r.active(index))
    }
    fn front_length(&self, id: FlowId) -> Option<usize> {
        let flow = self.flow(id)?;
        self.reserved.as_ref().map_or_else(
            || flow.packets.front().map(|p| p.len()),
            |r| r.packet_len(flow),
        )
    }
}

fn weighted_quantum(config: SchedulerConfig, class_weight: u32, flow_weight: u32) -> Option<u64> {
    let quantum = u64::from(config.base_quantum_bytes)
        .checked_mul(u64::from(class_weight))?
        .checked_mul(u64::from(flow_weight))?;
    let maximum_packet = u64::try_from(config.max_packet_bytes).ok()?;
    quantum.checked_add(maximum_packet.checked_sub(1)?)?;
    Some(quantum)
}

#[cfg(test)]
mod validation_tests;

#[cfg(test)]
mod handoff_tests;

#[cfg(test)]
mod tests {
    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn config() -> SchedulerConfig {
        SchedulerConfig {
            base_quantum_bytes: 64,
            max_classes: 4,
            max_flows: 64,
            max_packet_bytes: 1_500,
            max_queued_bytes: 32_000_000,
            max_queued_packets: 20_000,
            per_flow_bytes: 16_000_000,
            per_flow_packets: 10_000,
        }
    }

    fn class(id: u16, weight: u32) -> ClassConfig {
        ClassConfig {
            id: ClassId::new(id),
            weight,
        }
    }

    fn flow(id: u64, class_id: u16, weight: u32) -> FlowConfig {
        FlowConfig {
            id: FlowId::new(id),
            class: ClassId::new(class_id),
            weight,
        }
    }

    #[test]
    fn rejects_zero_limits_weights_and_invalid_bounds() {
        let original = config();
        let mut variants = vec![original; 8];
        variants[0].base_quantum_bytes = 0;
        variants[1].max_classes = 0;
        variants[2].max_flows = 0;
        variants[3].max_packet_bytes = 0;
        variants[4].max_queued_bytes = 0;
        variants[5].max_queued_packets = 0;
        variants[6].per_flow_bytes = 0;
        variants[7].per_flow_packets = 0;
        for invalid in variants {
            assert!(matches!(
                Scheduler::new(invalid, &[class(1, 1)]),
                Err(ConfigError::ZeroLimit)
            ));
        }
        assert!(matches!(
            Scheduler::new(original, &[]),
            Err(ConfigError::NoClasses)
        ));
        assert!(matches!(
            Scheduler::new(original, &[class(1, 0)]),
            Err(ConfigError::ZeroWeight)
        ));
        assert!(matches!(
            Scheduler::new(original, &[class(1, 1), class(1, 2)]),
            Err(ConfigError::DuplicateClass)
        ));
        let mut invalid = original;
        invalid.max_classes = 1;
        assert!(matches!(
            Scheduler::new(invalid, &[class(1, 1), class(2, 1)]),
            Err(ConfigError::TooManyClasses)
        ));
        invalid = original;
        invalid.max_packet_bytes = invalid.per_flow_bytes + 1;
        assert!(matches!(
            Scheduler::new(invalid, &[class(1, 1)]),
            Err(ConfigError::InconsistentBounds)
        ));
        invalid = original;
        invalid.per_flow_bytes = invalid.max_queued_bytes + 1;
        assert!(matches!(
            Scheduler::new(invalid, &[class(1, 1)]),
            Err(ConfigError::InconsistentBounds)
        ));
        invalid = original;
        invalid.per_flow_packets = invalid.max_queued_packets + 1;
        assert!(matches!(
            Scheduler::new(invalid, &[class(1, 1)]),
            Err(ConfigError::InconsistentBounds)
        ));
    }

    #[test]
    fn rejects_weight_overflow_and_bad_registration() -> TestResult {
        let mut limits = config();
        limits.base_quantum_bytes = u32::MAX;
        let mut scheduler = Scheduler::new(limits, &[class(1, u32::MAX)])?;
        assert_eq!(
            scheduler.register_flow(flow(1, 1, u32::MAX)),
            Err(FlowError::Arithmetic)
        );
        assert_eq!(
            scheduler.register_flow(flow(1, 1, 0)),
            Err(FlowError::ZeroWeight)
        );
        assert_eq!(
            scheduler.register_flow(flow(1, 2, 1)),
            Err(FlowError::UnknownClass)
        );
        scheduler.register_flow(flow(1, 1, 1))?;
        assert_eq!(
            scheduler.register_flow(flow(1, 1, 1)),
            Err(FlowError::Duplicate)
        );
        assert_eq!(
            scheduler.set_flow_weight(FlowId::new(1), u32::MAX),
            Err(FlowError::Arithmetic)
        );
        assert_eq!(
            scheduler.set_flow_weight(FlowId::new(99), 1),
            Err(FlowError::UnknownFlow)
        );
        assert_eq!(
            scheduler.remove_flow(FlowId::new(99)),
            Err(FlowError::UnknownFlow)
        );
        limits = config();
        limits.max_flows = 1;
        let mut scheduler = Scheduler::new(limits, &[class(1, 1)])?;
        scheduler.register_flow(flow(1, 1, 1))?;
        assert_eq!(
            scheduler.register_flow(flow(2, 1, 1)),
            Err(FlowError::Capacity)
        );
        Ok(())
    }

    #[test]
    fn rejects_maximum_deficit_overflow_without_allocation() {
        let mut limits = config();
        limits.base_quantum_bytes = u32::MAX;
        limits.max_packet_bytes = usize::MAX;
        limits.per_flow_bytes = usize::MAX;
        limits.max_queued_bytes = usize::MAX;
        if usize::BITS == 64 {
            assert!(matches!(
                Scheduler::new(limits, &[class(1, 1)]),
                Err(ConfigError::Arithmetic)
            ));
        }
    }

    #[test]
    fn rejected_payloads_and_accounting_are_unchanged() -> TestResult {
        let mut scheduler = Scheduler::new(config(), &[class(1, 1)])?;
        scheduler.register_flow(flow(1, 1, 1))?;
        for (id, packet, reason) in [
            (2, vec![7], AdmissionErrorKind::UnknownFlow),
            (1, vec![], AdmissionErrorKind::EmptyPacket),
            (1, vec![9; 1_501], AdmissionErrorKind::PacketTooLarge),
        ] {
            let expected = packet.clone();
            let rejected = scheduler
                .enqueue(FlowId::new(id), packet)
                .err()
                .ok_or("expected rejection")?;
            assert_eq!(rejected.kind, reason);
            assert_eq!(rejected.payload, expected);
            assert_eq!(scheduler.queued_bytes(), 0);
            assert_eq!(scheduler.queued_packets(), 0);
            assert_eq!(scheduler.active_flows(), 0);
        }
        Ok(())
    }

    #[test]
    fn enforces_global_and_flow_byte_count_limits() -> TestResult {
        for (global_bytes, flow_bytes, global_count, flow_count, reason) in [
            (6, 6, 4, 4, AdmissionErrorKind::GlobalBytes),
            (12, 6, 4, 4, AdmissionErrorKind::FlowBytes),
            (12, 12, 2, 2, AdmissionErrorKind::GlobalPackets),
            (12, 12, 4, 2, AdmissionErrorKind::FlowPackets),
        ] {
            let mut limits = config();
            limits.max_packet_bytes = 3;
            limits.max_queued_bytes = global_bytes;
            limits.per_flow_bytes = flow_bytes;
            limits.max_queued_packets = global_count;
            limits.per_flow_packets = flow_count;
            let mut scheduler = Scheduler::new(limits, &[class(1, 1)])?;
            scheduler.register_flow(flow(1, 1, 1))?;
            scheduler.enqueue(FlowId::new(1), vec![1; 3])?;
            scheduler.enqueue(FlowId::new(1), vec![2; 3])?;
            let rejected = scheduler
                .enqueue(FlowId::new(1), vec![3])
                .err()
                .ok_or("expected budget rejection")?;
            assert_eq!(rejected.kind, reason);
            assert_eq!(rejected.payload, vec![3]);
            assert_eq!(scheduler.queued_bytes(), 6);
            assert_eq!(scheduler.queued_packets(), 2);
            assert_eq!(
                scheduler.dequeue()?.ok_or("first packet")?.payload,
                vec![1; 3]
            );
            scheduler.enqueue(FlowId::new(1), vec![3])?;
            assert_eq!(
                scheduler.dequeue()?.ok_or("second packet")?.payload,
                vec![2; 3]
            );
            assert_eq!(scheduler.dequeue()?.ok_or("third packet")?.payload, vec![3]);
            assert_eq!(scheduler.dequeue()?, None);
            assert_eq!(scheduler.queued_bytes(), 0);
            assert_eq!(scheduler.queued_packets(), 0);
        }
        Ok(())
    }

    #[test]
    fn combined_flows_share_global_budget_and_fifo_is_preserved() -> TestResult {
        let mut limits = config();
        limits.max_packet_bytes = 4;
        limits.max_queued_bytes = 8;
        limits.per_flow_bytes = 8;
        let mut scheduler = Scheduler::new(limits, &[class(1, 1)])?;
        scheduler.register_flow(flow(1, 1, 1))?;
        scheduler.register_flow(flow(2, 1, 1))?;
        scheduler.enqueue(FlowId::new(1), vec![1; 3])?;
        scheduler.enqueue(FlowId::new(2), vec![2; 4])?;
        scheduler.enqueue(FlowId::new(1), vec![3])?;
        assert_eq!(
            scheduler
                .enqueue(FlowId::new(2), vec![4])
                .err()
                .ok_or("global budget")?
                .kind,
            AdmissionErrorKind::GlobalBytes
        );
        let mut received = Vec::new();
        while let Some(packet) = scheduler.dequeue()? {
            received.push((packet.flow.value(), packet.payload));
        }
        assert_eq!(
            received,
            vec![(1, vec![1; 3]), (1, vec![3]), (2, vec![2; 4])]
        );
        assert_eq!(scheduler.queued_bytes(), 0);
        Ok(())
    }

    #[test]
    fn normalizes_spare_payload_capacity() -> TestResult {
        let mut scheduler = Scheduler::new(config(), &[class(1, 1)])?;
        scheduler.register_flow(flow(1, 1, 1))?;
        let mut packet = Vec::with_capacity(1_000_000);
        packet.push(42);
        scheduler.enqueue(FlowId::new(1), packet)?;
        assert_eq!(scheduler.queued_bytes(), 1);
        let released = scheduler.dequeue()?.ok_or("packet")?;
        assert_eq!(released.payload, vec![42]);
        assert_eq!(released.payload.capacity(), 1);
        Ok(())
    }

    #[test]
    fn sustained_backlog_receives_weighted_byte_shares() -> TestResult {
        let mut scheduler = Scheduler::new(config(), &[class(1, 1)])?;
        scheduler.register_flow(flow(1, 1, 1))?;
        scheduler.register_flow(flow(2, 1, 3))?;
        for _ in 0..4_096 {
            scheduler.enqueue(FlowId::new(1), vec![1])?;
            scheduler.enqueue(FlowId::new(2), vec![2])?;
        }
        let mut bytes = [0_usize; 2];
        for _ in 0..4_096 {
            let packet = scheduler.dequeue()?.ok_or("backlogged packet")?;
            let index = usize::try_from(packet.flow.value() - 1)?;
            bytes[index] += packet.payload.len();
        }
        assert_eq!(bytes, [1_024, 3_072]);
        Ok(())
    }

    #[test]
    fn class_and_flow_weights_multiply_without_claiming_class_caps() -> TestResult {
        let mut limits = config();
        limits.base_quantum_bytes = 1;
        limits.max_queued_packets = 30_000;
        let mut scheduler = Scheduler::new(limits, &[class(1, 2), class(2, 1)])?;
        scheduler.register_flow(flow(1, 1, 1))?;
        scheduler.register_flow(flow(2, 1, 2))?;
        scheduler.register_flow(flow(3, 2, 1))?;
        for id in 1..=3 {
            for _ in 0..5_000 {
                scheduler.enqueue(FlowId::new(id), vec![1])?;
            }
        }
        let mut bytes = [0_usize; 3];
        for _ in 0..7_000 {
            let packet = scheduler.dequeue()?.ok_or("backlogged packet")?;
            let index = usize::try_from(packet.flow.value() - 1)?;
            bytes[index] += packet.payload.len();
        }
        assert_eq!(bytes, [2_000, 4_000, 1_000]);
        Ok(())
    }

    #[test]
    fn unequal_packet_sizes_are_fair_in_bytes_not_packet_counts() -> TestResult {
        let mut limits = config();
        limits.base_quantum_bytes = 300;
        let mut scheduler = Scheduler::new(limits, &[class(1, 1)])?;
        scheduler.register_flow(flow(1, 1, 1))?;
        scheduler.register_flow(flow(2, 1, 1))?;
        for _ in 0..4_000 {
            scheduler.enqueue(FlowId::new(1), vec![1; 100])?;
            scheduler.enqueue(FlowId::new(2), vec![2; 1_500])?;
        }
        let mut bytes = [0_usize; 2];
        let mut packets = [0_usize; 2];
        for _ in 0..3_000 {
            let packet = scheduler.dequeue()?.ok_or("backlogged packet")?;
            let index = usize::try_from(packet.flow.value() - 1)?;
            bytes[index] += packet.payload.len();
            packets[index] += 1;
        }
        assert!(
            bytes[0].abs_diff(bytes[1]) <= 1_800,
            "byte shares: {bytes:?}"
        );
        assert!(packets[0] > packets[1] * 10);
        Ok(())
    }

    #[test]
    fn tiny_quantum_large_packets_progress_in_one_dequeue() -> TestResult {
        let mut limits = config();
        limits.base_quantum_bytes = 1;
        limits.max_packet_bytes = 8_000_000;
        let mut scheduler = Scheduler::new(limits, &[class(1, 1)])?;
        scheduler.register_flow(flow(1, 1, 1))?;
        scheduler.register_flow(flow(2, 1, 3))?;
        scheduler.enqueue(FlowId::new(1), vec![1; 8_000_000])?;
        scheduler.enqueue(FlowId::new(2), vec![2; 8_000_000])?;
        let first = scheduler.dequeue()?.ok_or("large packet must progress")?;
        assert_eq!(first.flow, FlowId::new(2));
        assert_eq!(first.payload.len(), 8_000_000);
        let second = scheduler
            .dequeue()?
            .ok_or("remaining packet must progress")?;
        assert_eq!(second.flow, FlowId::new(1));
        assert_eq!(second.payload.len(), 8_000_000);
        assert_eq!(scheduler.dequeue()?, None);
        Ok(())
    }

    #[test]
    fn idle_flows_do_not_enter_ring_or_bank_credit() -> TestResult {
        let mut limits = config();
        limits.base_quantum_bytes = 1;
        limits.max_flows = 10_000;
        let mut scheduler = Scheduler::new(limits, &[class(1, 1)])?;
        for id in 0..10_000 {
            scheduler.register_flow(flow(id, 1, 1))?;
        }
        assert_eq!(scheduler.registered_flows(), 10_000);
        assert_eq!(scheduler.active_flows(), 0);
        for _ in 0..100 {
            scheduler.enqueue(FlowId::new(9_999), vec![1; 1_500])?;
            assert_eq!(scheduler.active_flows(), 1);
            assert!(scheduler.dequeue()?.is_some());
        }
        scheduler.enqueue(FlowId::new(0), vec![0; 2])?;
        scheduler.enqueue(FlowId::new(9_999), vec![1])?;
        assert_eq!(scheduler.active_flows(), 2);
        assert_eq!(
            scheduler.dequeue()?.ok_or("smaller packet")?.flow,
            FlowId::new(9_999)
        );
        assert_eq!(
            scheduler.dequeue()?.ok_or("remaining packet")?.flow,
            FlowId::new(0)
        );
        assert_eq!(scheduler.active_flows(), 0);
        Ok(())
    }

    #[test]
    fn dynamic_operations_require_drain_and_reset_deficit() -> TestResult {
        let mut scheduler = Scheduler::new(config(), &[class(1, 1)])?;
        scheduler.register_flow(flow(1, 1, 1))?;
        scheduler.enqueue(FlowId::new(1), vec![1])?;
        assert_eq!(scheduler.remove_flow(FlowId::new(1)), Err(FlowError::Busy));
        assert_eq!(
            scheduler.set_flow_weight(FlowId::new(1), 4),
            Err(FlowError::Busy)
        );
        assert_eq!(scheduler.queued_packets(), 1);
        assert!(scheduler.dequeue()?.is_some());
        scheduler.set_flow_weight(FlowId::new(1), 2)?;
        assert_eq!(
            scheduler.set_flow_weight(FlowId::new(1), 0),
            Err(FlowError::ZeroWeight)
        );
        let state = scheduler
            .flows
            .get(&FlowId::new(1))
            .ok_or("registered flow")?;
        assert_eq!(state.deficit, 0);
        assert_eq!(state.quantum, 128);
        scheduler.remove_flow(FlowId::new(1))?;
        scheduler.register_flow(flow(1, 1, 1))?;
        assert_eq!(scheduler.registered_flows(), 1);
        assert_eq!(scheduler.active_flows(), 0);
        assert_eq!(scheduler.dequeue()?, None);
        Ok(())
    }

    #[test]
    fn payload_contents_cannot_create_a_priority_bypass() -> TestResult {
        let mut first = Scheduler::new(config(), &[class(1, 1)])?;
        let mut second = Scheduler::new(config(), &[class(1, 1)])?;
        for id in 1..=3 {
            first.register_flow(flow(id, 1, 1))?;
            second.register_flow(flow(id, 1, 1))?;
            for length in [40, 64, 100, 1_500] {
                first.enqueue(FlowId::new(id), vec![0; length])?;
                second.enqueue(FlowId::new(id), vec![u8::MAX; length])?;
            }
        }
        while let Some(a) = first.dequeue()? {
            let b = second.dequeue()?.ok_or("matching packet")?;
            assert_eq!(a.flow, b.flow);
            assert_eq!(a.class, b.class);
            assert_eq!(a.payload.len(), b.payload.len());
        }
        assert_eq!(second.dequeue()?, None);
        Ok(())
    }

    #[test]
    fn skipped_rounds_match_textbook_drr_traces() -> TestResult {
        // The reference visits every flow on every full round, without an active
        // ring or empty-round skipping, and emits an entire visit at once.
        for count in [1_usize, 2, 4, 16, 64] {
            let mut limits = config();
            limits.base_quantum_bytes = 1;
            let mut scheduler = Scheduler::new(limits, &[class(1, 1), class(2, 3)])?;
            let mut queues = vec![VecDeque::new(); count];
            let mut deficits = vec![0_usize; count];
            let mut quanta = Vec::new();
            for (index, queue) in queues.iter_mut().enumerate() {
                let id = u64::try_from(index)?;
                let class_id = if index % 2 == 0 { 1 } else { 2 };
                let class_weight = if class_id == 1 { 1 } else { 3 };
                let weight = u32::try_from(index % 7 + 1)?;
                scheduler.register_flow(flow(id, class_id, weight))?;
                quanta.push(usize::try_from(weight)? * class_weight);
                for sequence in 0..64 {
                    let length = (index * 13 + sequence * 97) % 256 + 1;
                    scheduler.enqueue(FlowId::new(id), vec![0; length])?;
                    queue.push_back(length);
                }
            }
            let mut reference = Vec::new();
            while queues.iter().any(|queue| !queue.is_empty()) {
                for index in 0..count {
                    if queues[index].is_empty() {
                        continue;
                    }
                    deficits[index] += quanta[index];
                    while let Some(&length) = queues[index].front() {
                        if length > deficits[index] {
                            break;
                        }
                        deficits[index] -= length;
                        queues[index].pop_front();
                        reference.push((u64::try_from(index)?, length));
                    }
                    if queues[index].is_empty() {
                        deficits[index] = 0;
                    }
                }
            }
            for (id, length) in reference {
                let packet = scheduler.dequeue()?.ok_or("reference packet")?;
                assert_eq!((packet.flow.value(), packet.payload.len()), (id, length));
            }
            assert_eq!(scheduler.dequeue()?, None);
            assert_eq!(scheduler.queued_bytes(), 0);
            assert_eq!(scheduler.queued_packets(), 0);
        }
        Ok(())
    }

    #[test]
    fn eligibility_skips_blocked_flow_without_bank_or_unbounded_callbacks() -> TestResult {
        let mut limits = config();
        limits.base_quantum_bytes = 1;
        let mut scheduler = Scheduler::new(limits, &[class(1, 1)])?;
        scheduler.register_flow(flow(1, 1, 1))?;
        scheduler.register_flow(flow(2, 1, 1))?;
        scheduler.enqueue(FlowId::new(1), vec![1; 1500])?;
        scheduler.enqueue(FlowId::new(2), vec![2; 100])?;
        let mut calls = BTreeMap::new();
        let selected = scheduler
            .dequeue_eligible(|id, _| {
                *calls.entry(id).or_insert(0) += 1;
                id == FlowId::new(2)
            })?
            .ok_or("eligible packet")?;
        assert_eq!(selected.flow, FlowId::new(2));
        assert_eq!(calls.values().copied().collect::<Vec<_>>(), vec![1, 1]);
        assert_eq!(
            (scheduler.queued_bytes(), scheduler.queued_packets()),
            (1500, 1)
        );
        for _ in 0..1000 {
            assert_eq!(scheduler.dequeue_eligible(|_, _| false)?, None);
        }
        assert_eq!(
            scheduler
                .flows
                .get(&FlowId::new(1))
                .ok_or("blocked flow")?
                .deficit,
            0
        );
        scheduler.enqueue(FlowId::new(2), vec![2])?;
        assert_eq!(
            scheduler.dequeue()?.ok_or("small packet")?.flow,
            FlowId::new(2)
        );
        assert_eq!(
            scheduler.dequeue()?.ok_or("large packet")?.payload,
            vec![1; 1500]
        );
        assert_eq!(
            (scheduler.queued_bytes(), scheduler.queued_packets()),
            (0, 0)
        );
        Ok(())
    }

    #[test]
    fn selected_head_is_nonconsuming_single_use_and_mutation_invalidated() -> TestResult {
        let mut scheduler = Scheduler::new(config(), &[class(1, 1)])?;
        scheduler.register_flow(flow(1, 1, 1))?;
        scheduler.enqueue(FlowId::new(1), vec![1; 100])?;
        let selected = scheduler
            .peek_eligible(|_, _| true)?
            .ok_or("selected packet")?;
        let deficit = scheduler.flows.get(&FlowId::new(1)).ok_or("flow")?.deficit;
        for _ in 0..100 {
            assert_eq!(scheduler.peek_eligible(|_, _| true)?, Some(selected));
            assert_eq!(
                (scheduler.queued_bytes(), scheduler.queued_packets()),
                (100, 1)
            );
            assert_eq!(
                scheduler.flows.get(&FlowId::new(1)).ok_or("flow")?.deficit,
                deficit
            );
        }
        scheduler.enqueue(FlowId::new(1), vec![2; 100])?;
        assert_eq!(scheduler.dequeue_peeked()?, None);
        assert_eq!(scheduler.peek_eligible(|_, _| true)?, Some(selected));
        assert_eq!(
            scheduler
                .dequeue_peeked()?
                .ok_or("committed packet")?
                .payload,
            vec![1; 100]
        );
        assert_eq!(scheduler.dequeue_peeked()?, None);
        assert_eq!(
            scheduler.dequeue()?.ok_or("second packet")?.payload,
            vec![2; 100]
        );
        Ok(())
    }
}
