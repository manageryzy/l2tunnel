//! Explicit owned/benchmark TCP ACK custody before ordinary Pipeline admission.
//!
//! Transparent modes never construct this owner. Every forwarded original still
//! enters the actual Pipeline. This module neither authenticates the selection
//! nor generates, rewrites, transmits or physically confirms any TCP packet.
use super::{
    Binding, Budget, FlowKey, PacketMetadata, Pipeline, PipelineConfig, PipelineError, Profile,
    QueueUsage,
};
use std::{alloc::Layout, fmt, time::Duration};

/// Inspect a complete pure TCP ACK using the maintained packet and checksum checks.
/// This read-only predicate grants no authentication, admission or transport authority.
pub fn is_complete_pure_tcp_ack(
    bytes: &[u8],
    classification: l2tunnel_packet::Classification,
    maximum: usize,
) -> bool {
    packet::inspect(bytes, classification, maximum).is_some()
}

mod packet;
use packet::{Key, Signature};

/// Explicit local execution scope; these labels confer no remote authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Selection {
    /// Caller already owns TCP generation, independently of this component.
    OwnedTcp,
    /// An explicitly selected benchmark models generated ACK ingress.
    Benchmark,
}

/// Complete optional policy, with no product defaults.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Policy {
    /// Explicit scope; transparent production modes must refuse this policy.
    pub selection: Selection,
    /// First-candidate hold interval; zero forwards all input immediately.
    pub interval: Duration,
    /// Maximum original held-candidate age, never renewed by a replacement.
    pub max_hold: Duration,
    /// Actual retained directional histories and candidate slots.
    pub max_flows: usize,
    /// Actual bytes reserved per pending ACK; larger frames bypass unchanged.
    pub max_ack_bytes: usize,
}

/// Real heap allowance, excluding this owner's inline header.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Limits {
    /// Maximum actual two-allocation capacity.
    pub capacity_bytes: usize,
}

/// Scalar, custody or actual downstream admission refusal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// Invalid complete policy or a different issuing Pipeline configuration.
    Policy,
    /// Checked layout/arithmetic cannot be represented.
    Layout,
    /// Required heap exceeds the explicit allowance.
    Limit {
        /// Required complete heap capacity.
        required: usize,
        /// Supplied complete heap allowance.
        limit: usize,
    },
    /// A real fallible reservation failed.
    Allocation,
    /// Actual backing or retention inventory disagrees.
    Invariant,
    /// Every configured directional history slot is retained.
    Capacity,
    /// A requested retirement still has pending original ACK custody.
    Busy,
    /// Injected time regressed or a new original cap is already expired.
    Time,
    /// An existing original held-candidate cap expired; custody is not delivered.
    Expired,
    /// An exact event counter would wrap.
    Counter,
    /// Bounded progression requires positive work/cadence.
    Work,
    /// Actual Pipeline refused admission; the new input remains caller-owned.
    Pipeline(PipelineError),
}
impl fmt::Display for Error {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(output, "ACK ingress: {self:?}")
    }
}
impl std::error::Error for Error {}

/// Complete coalescer heap plan; the existing Pipeline heaps are separate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Plan {
    config: PipelineConfig,
    policy: Policy,
    bytes: usize,
    slab_bytes: usize,
}
impl Plan {
    /// Validate all scalar/layout bounds before the first selected allocation.
    pub fn for_pipeline(config: PipelineConfig, policy: Policy) -> Result<Self, Error> {
        config.validate().map_err(Error::Pipeline)?;
        if policy.selection == Selection::OwnedTcp && matches!(config.profile, Profile::TapSystem) {
            return Err(Error::Policy);
        }
        let minimum = if matches!(config.profile, Profile::TapSystem) {
            54
        } else {
            40
        };
        if policy.max_flows == 0
            || policy.max_flows > config.flows.capacity
            || policy.max_ack_bytes < minimum
            || policy.max_ack_bytes > config.parse.max_packet_bytes
            || policy.max_hold.is_zero()
            || (!policy.interval.is_zero() && policy.interval >= policy.max_hold)
        {
            return Err(Error::Policy);
        }
        let slab_bytes = policy
            .max_flows
            .checked_mul(policy.max_ack_bytes)
            .ok_or(Error::Layout)?;
        let metadata = Layout::array::<Option<State>>(policy.max_flows)
            .map_err(|_| Error::Layout)?
            .size();
        let slab = Layout::array::<u8>(slab_bytes)
            .map_err(|_| Error::Layout)?
            .size();
        let bytes = metadata.checked_add(slab).ok_or(Error::Layout)?;
        Ok(Self {
            config,
            policy,
            bytes,
            slab_bytes,
        })
    }
    /// Exact immutable Pipeline configuration to which this owner is attached.
    pub const fn config(&self) -> PipelineConfig {
        self.config
    }
    /// Complete explicit selected policy.
    pub const fn policy(&self) -> Policy {
        self.policy
    }
    /// Actual two-allocation heap capacity; inline ownership is counted by the parent.
    pub const fn capacity_bytes(&self) -> usize {
        self.bytes
    }
}

/// Actual observed physical backing plus logical originals still retained here.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Usage {
    /// Original complete heap allowance.
    pub limit_bytes: usize,
    /// Exact observed retained Rust allocation layouts.
    pub capacity_bytes: usize,
    /// Actual nonempty heap allocations, always two for this plan.
    pub allocations: usize,
    /// Original packets held here, in addition to Pipeline usage.
    pub held: QueueUsage,
    /// Directional histories currently retained, including empty candidates.
    pub histories: usize,
}

/// Coalescing facts, separate from TCP generation, tunnel feedback and copies.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Statistics {
    /// Inputs consumed once, including immediately forwarded originals.
    pub received: u64,
    /// Checksum-valid ACK-only inputs with supported static/options geometry.
    pub eligible: u64,
    /// Passively first observed ACKs forwarded to establish a baseline.
    pub first_observation: u64,
    /// Unsent advancing candidates replaced by a newer comparable ACK.
    pub superseded: u64,
    /// Distinct duplicate ACK inputs forwarded individually.
    pub duplicates: u64,
    /// Held advancing originals actually admitted to the Pipeline.
    pub flushed: u64,
    /// Inputs forwarded without suppression, excluding known duplicates.
    pub bypassed: u64,
    /// Refused ingest attempts; incoming bytes remain caller-owned.
    pub refusals: u64,
}

/// Exact retained candidate timing; no physical-send or delivery assertion.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Pending {
    /// Canonical underlying connection identity.
    pub flow: FlowKey,
    /// Actual unchanged retained packet length.
    pub bytes: usize,
    /// Original first candidate creation in this ingress owner, not inferred TCP generation.
    pub first_created: Duration,
    /// Exact selected replacement observation in this ingress owner.
    pub latest_created: Duration,
    /// Original coalescing deadline, unchanged by replacements.
    pub deadline: Duration,
    /// Earliest caller/original maximum hold cap, never moved later.
    pub expires: Duration,
}

#[derive(Clone, Copy)]
struct State {
    key: Key,
    binding: Binding,
    last_ack: u32,
    signature: Option<Signature>,
    pending: Option<Pending>,
}

/// Successful consumption of the caller's exact original packet.
#[allow(clippy::large_enum_variant)] // Exact bounded Copy metadata without a packet-time allocation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Admission {
    /// Actual unchanged original entered the ordinary Pipeline.
    Forwarded(PacketMetadata),
    /// Original bytes now occupy one actual pending slab slot.
    Held,
    /// A newer advance replaced the one unsent same-semantic candidate.
    Superseded,
}

enum Forward {
    First(bool),
    Duplicate(bool),
    Bypass(bool),
}

/// Actual bounded service results; blocked candidates retain bytes and caps.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Progress {
    /// Actual slots visited, at most min(work, configured slots).
    pub visited: usize,
    /// Original candidates transferred through actual Pipeline admission.
    pub forwarded: usize,
    /// Candidates refused by downstream budget/flow capacity this call.
    pub blocked: usize,
}

/// One real bounded owner, attached by its caller to the exact issuing Pipeline.
///
/// Route every benchmark ingress through this owner. A caller must retain the
/// current read buffer on refusal and include this owner in generation drain.
/// It cannot transfer pending old-generation bytes to another Pipeline.
pub struct Ingress {
    plan: Plan,
    slots: Vec<Option<State>>,
    slab: Vec<u8>,
    usage: Usage,
    statistics: Statistics,
    now: Duration,
    cursor: usize,
    failure: Option<Error>,
}
impl Ingress {
    /// Reserve actual metadata and payload backing fallibly, with no fallback.
    pub fn new(plan: Plan, limits: Limits) -> Result<Self, Error> {
        if plan.bytes > limits.capacity_bytes {
            return Err(Error::Limit {
                required: plan.bytes,
                limit: limits.capacity_bytes,
            });
        }
        let mut slots = reserve::<Option<State>>(plan.policy.max_flows)?;
        let mut slab = reserve::<u8>(plan.slab_bytes)?;
        slots.resize(plan.policy.max_flows, None);
        slab.resize(plan.slab_bytes, 0);
        let actual = Layout::array::<Option<State>>(slots.capacity())
            .map_err(|_| Error::Layout)?
            .size()
            .checked_add(slab.capacity())
            .ok_or(Error::Layout)?;
        if actual != plan.bytes {
            return Err(Error::Invariant);
        }
        Ok(Self {
            plan,
            slots,
            slab,
            usage: Usage {
                limit_bytes: limits.capacity_bytes,
                capacity_bytes: actual,
                allocations: 2,
                held: QueueUsage::default(),
                histories: 0,
            },
            statistics: Statistics::default(),
            now: Duration::ZERO,
            cursor: 0,
            failure: None,
        })
    }
    /// Exact explicit selected policy, never an authenticated capability claim.
    pub const fn policy(&self) -> Policy {
        self.plan.policy
    }
    /// Actual unchanged backing and logical pending originals.
    pub const fn usage(&self) -> Usage {
        self.usage
    }
    /// Separate coalescing counters; these never stand for native delivery.
    pub const fn statistics(&self) -> Statistics {
        self.statistics
    }
    /// Existing terminal failure, if an original held cap expired.
    pub const fn failure(&self) -> Option<Error> {
        self.failure
    }
    /// Observe each real retained original and its immutable timing.
    pub fn pending(&self) -> impl Iterator<Item = Pending> + '_ {
        self.slots
            .iter()
            .flatten()
            .filter_map(|state| state.pending)
            .take(self.usage.held.packets)
    }
    /// Whether a connection still has unsent ingress custody.
    pub fn retains_flow(&self, key: &FlowKey) -> bool {
        self.pending().any(|pending| pending.flow == *key)
    }
    /// True only when no candidate remains here; downstream drain is separate.
    pub fn is_empty(&self) -> bool {
        self.usage.held.packets == 0
    }
    /// Earliest pending coalescing wake or hard original cap.
    pub fn deadline(&self) -> Option<Duration> {
        self.pending()
            .map(|pending| pending.deadline.min(pending.expires))
            .min()
    }
    /// Avoid renewing a cap or spinning on a past due/backpressured candidate.
    /// The cadence is supplied by the existing runtime, never chosen here.
    pub fn wake_at(&self, now: Duration, cadence: Duration) -> Result<Option<Duration>, Error> {
        if let Some(error) = self.failure {
            return Err(error);
        }
        if cadence.is_zero() {
            return Err(Error::Work);
        }
        let retry = now.checked_add(cadence).ok_or(Error::Time)?;
        Ok(self
            .pending()
            .map(|pending| {
                (if pending.deadline <= now {
                    retry
                } else {
                    pending.deadline
                })
                .min(pending.expires)
            })
            .min())
    }
    /// Consume input only on success. Older candidates may have transferred
    /// before a new input is refused; the caller retries only that new input.
    pub fn ingest(
        &mut self,
        pipeline: &mut Pipeline,
        bytes: &[u8],
        now: Duration,
        original_cap: Duration,
    ) -> Result<Admission, Error> {
        self.ingest_at(pipeline, bytes, now, now, original_cap)
    }
    /// Preserve the first actual read observation through delayed downstream admission.
    /// This is the same ingress transition; retry cannot start a new hold interval.
    pub fn ingest_at(
        &mut self,
        pipeline: &mut Pipeline,
        bytes: &[u8],
        received: Duration,
        now: Duration,
        original_cap: Duration,
    ) -> Result<Admission, Error> {
        let result = self.ingest_inner(pipeline, bytes, received, now, original_cap);
        if result.is_err() {
            self.statistics.refusals = increment(self.statistics.refusals)?;
        }
        result
    }
    fn ingest_inner(
        &mut self,
        pipeline: &mut Pipeline,
        bytes: &[u8],
        received: Duration,
        now: Duration,
        original_cap: Duration,
    ) -> Result<Admission, Error> {
        self.check(pipeline, now)?;
        if received > now || original_cap <= now {
            return Err(Error::Time);
        }
        let timing = super::PacketTiming {
            received,
            admitted: now,
            original_deadline: Some(original_cap),
        };
        let classification = pipeline
            .classify(bytes)
            .map_err(|error| Error::Pipeline(PipelineError::Parse(error)))?;
        let evidence = packet::inspect(bytes, classification, self.plan.policy.max_ack_bytes);
        let Some(ack) = evidence else {
            let key = (classification.kind == l2tunnel_packet::PacketKind::Tcp)
                .then_some(classification.key);
            self.flush_matching(pipeline, key, now)?;
            let admitted = self.forward(
                pipeline,
                bytes,
                classification.key,
                timing,
                Forward::Bypass(false),
            )?;
            if self.usage.histories != 0 {
                for slot in &mut self.slots {
                    if slot.is_some_and(|state| key.is_none_or(|key| state.key.flow == key)) {
                        *slot = None;
                        self.usage.histories -= 1;
                    }
                }
            }
            return Ok(admitted);
        };
        let index = self
            .slots
            .iter()
            .position(|state| state.is_some_and(|state| state.key == ack.key));
        let index = match index {
            Some(index) => index,
            None => {
                let index = self
                    .slots
                    .iter()
                    .position(Option::is_none)
                    .ok_or(Error::Capacity)?;
                let admitted = self.forward(
                    pipeline,
                    bytes,
                    ack.key.flow,
                    timing,
                    Forward::First(ack.signature.is_some()),
                )?;
                let Admission::Forwarded(metadata) = admitted else {
                    return Err(Error::Invariant);
                };
                self.slots[index] = Some(State {
                    key: ack.key,
                    binding: metadata.binding,
                    last_ack: ack.acknowledged,
                    signature: ack.signature,
                    pending: None,
                });
                self.usage.histories = self
                    .usage
                    .histories
                    .checked_add(1)
                    .ok_or(Error::Invariant)?;
                return Ok(admitted);
            }
        };
        let state = self.slots[index].ok_or(Error::Invariant)?;
        if pipeline
            .flow(&state.key.flow)
            .is_none_or(|flow| flow.binding != state.binding)
        {
            return Err(Error::Invariant);
        }
        let distance = ack.acknowledged.wrapping_sub(state.last_ack);
        let duplicate = distance == 0;
        let advances = distance != 0 && distance < (1 << 31);
        let equivalent = ack.signature.is_some() && ack.signature == state.signature;
        let already_due = received
            .checked_add(self.plan.policy.interval)
            .ok_or(Error::Time)?
            <= now;
        if !advances || !equivalent || self.plan.policy.interval.is_zero() || already_due {
            self.emit(pipeline, index, now)?;
            let admitted = self.forward(
                pipeline,
                bytes,
                ack.key.flow,
                timing,
                if duplicate {
                    Forward::Duplicate(ack.signature.is_some())
                } else {
                    Forward::Bypass(ack.signature.is_some())
                },
            )?;
            let state = self.slots[index].as_mut().ok_or(Error::Invariant)?;
            if advances {
                state.last_ack = ack.acknowledged;
            }
            state.signature = ack.signature;
            return Ok(admitted);
        }
        if state.pending.is_some_and(|pending| pending.deadline <= now) {
            self.emit(pipeline, index, now)?;
        }
        let previous = self.slots[index].ok_or(Error::Invariant)?.pending;
        let held = self.admission_budget(pipeline, ack.key.flow, bytes.len(), previous)?;
        let mut next = self.statistics;
        next.received = increment(next.received)?;
        next.eligible = increment(next.eligible)?;
        if previous.is_some() {
            next.superseded = increment(next.superseded)?;
        }
        let pending = if let Some(previous) = previous {
            Pending {
                bytes: bytes.len(),
                latest_created: received,
                expires: previous.expires.min(original_cap),
                ..previous
            }
        } else {
            Pending {
                flow: ack.key.flow,
                bytes: bytes.len(),
                first_created: received,
                latest_created: received,
                deadline: received
                    .checked_add(self.plan.policy.interval)
                    .ok_or(Error::Time)?,
                expires: received
                    .checked_add(self.plan.policy.max_hold)
                    .ok_or(Error::Time)?
                    .min(original_cap),
            }
        };
        let start = index
            .checked_mul(self.plan.policy.max_ack_bytes)
            .ok_or(Error::Invariant)?;
        self.slab
            .get_mut(start..start + bytes.len())
            .ok_or(Error::Invariant)?
            .copy_from_slice(bytes);
        let state = self.slots[index].as_mut().ok_or(Error::Invariant)?;
        state.pending = Some(pending);
        state.last_ack = ack.acknowledged;
        state.signature = ack.signature;
        self.usage.held = held;
        self.statistics = next;
        self.now = now;
        Ok(if previous.is_some() {
            Admission::Superseded
        } else {
            Admission::Held
        })
    }
    /// Visit bounded actual slots; drain ignores the soft deadline but never the
    /// original hard cap. Budget/flow refusals retain the exact candidate.
    pub fn advance(
        &mut self,
        pipeline: &mut Pipeline,
        now: Duration,
        draining: bool,
        work: usize,
    ) -> Result<Progress, Error> {
        self.check(pipeline, now)?;
        if work == 0 {
            return Err(Error::Work);
        }
        let mut progress = Progress::default();
        for _ in 0..work.min(self.slots.len()) {
            let index = self.cursor;
            self.cursor = (index + 1) % self.slots.len();
            progress.visited += 1;
            if self.slots[index]
                .and_then(|state| state.pending)
                .is_some_and(|pending| draining || pending.deadline <= now)
            {
                match self.emit(pipeline, index, now) {
                    Ok(true) => progress.forwarded += 1,
                    Ok(false) => {}
                    Err(Error::Pipeline(
                        PipelineError::Budget(_)
                        | PipelineError::Flow(l2tunnel_packet::FlowError::Capacity),
                    )) => progress.blocked += 1,
                    Err(error) => return Err(error),
                }
            }
        }
        self.now = now;
        Ok(progress)
    }
    /// Caller first proves downstream drain. Pending ingress refuses retirement;
    /// actual Pipeline retirement succeeds before matching histories are cleared.
    pub fn retire_drained(
        &mut self,
        pipeline: &mut Pipeline,
        key: &FlowKey,
    ) -> Result<Binding, Error> {
        if pipeline.config != self.plan.config {
            return Err(Error::Policy);
        }
        if self.retains_flow(key) {
            return Err(Error::Busy);
        }
        let binding = pipeline.retire_drained(key).map_err(Error::Pipeline)?;
        for slot in &mut self.slots {
            if slot.is_some_and(|state| state.key.flow == *key) {
                *slot = None;
            }
        }
        self.usage.histories = self.slots.iter().flatten().count();
        Ok(binding)
    }
    fn check(&mut self, pipeline: &Pipeline, now: Duration) -> Result<(), Error> {
        if pipeline.config != self.plan.config {
            return Err(Error::Policy);
        }
        if let Some(error) = self.failure {
            return Err(error);
        }
        if now < self.now {
            return Err(Error::Time);
        }
        if self.pending().any(|pending| now >= pending.expires) {
            self.failure = Some(Error::Expired);
            return Err(Error::Expired);
        }
        Ok(())
    }
    fn admission_budget(
        &self,
        pipeline: &Pipeline,
        key: FlowKey,
        bytes: usize,
        replaced: Option<Pending>,
    ) -> Result<QueueUsage, Error> {
        pipeline.validate_weight(key, 1).map_err(Error::Pipeline)?;
        let held = if let Some(pending) = replaced {
            QueueUsage {
                bytes: self
                    .usage
                    .held
                    .bytes
                    .checked_sub(pending.bytes)
                    .ok_or(Error::Invariant)?,
                packets: self
                    .usage
                    .held
                    .packets
                    .checked_sub(1)
                    .ok_or(Error::Invariant)?,
            }
        } else {
            self.usage.held
        };
        let next = super::add_usage(
            held,
            bytes,
            self.plan.config.queue,
            Budget::Bytes,
            Budget::Packets,
        )
        .map_err(Error::Pipeline)?;
        let pipeline_usage = pipeline.usage();
        if pipeline_usage
            .bytes
            .checked_add(next.bytes)
            .ok_or(Error::Layout)?
            > self.plan.config.queue.bytes
        {
            return Err(Error::Pipeline(PipelineError::Budget(Budget::Bytes)));
        }
        if pipeline_usage
            .packets
            .checked_add(next.packets)
            .ok_or(Error::Layout)?
            > self.plan.config.queue.packets
        {
            return Err(Error::Pipeline(PipelineError::Budget(Budget::Packets)));
        }
        if let Profile::TunDrr(policy) = self.plan.config.profile {
            let mut own = QueueUsage::default();
            for pending in self.pending().filter(|pending| pending.flow == key) {
                own.bytes = own.bytes.checked_add(pending.bytes).ok_or(Error::Layout)?;
                own.packets = own.packets.checked_add(1).ok_or(Error::Layout)?;
            }
            if let Some(pending) = replaced {
                own.bytes = own
                    .bytes
                    .checked_sub(pending.bytes)
                    .ok_or(Error::Invariant)?;
                own.packets = own.packets.checked_sub(1).ok_or(Error::Invariant)?;
            }
            let actual = pipeline
                .flow(&key)
                .map_or(QueueUsage::default(), |state| state.queued);
            let combined = QueueUsage {
                bytes: actual.bytes.checked_add(own.bytes).ok_or(Error::Layout)?,
                packets: actual
                    .packets
                    .checked_add(own.packets)
                    .ok_or(Error::Layout)?,
            };
            super::add_usage(
                combined,
                bytes,
                policy.per_flow,
                Budget::FlowBytes,
                Budget::FlowPackets,
            )
            .map_err(Error::Pipeline)?;
        }
        Ok(next)
    }
    fn forward(
        &mut self,
        pipeline: &mut Pipeline,
        bytes: &[u8],
        key: FlowKey,
        timing: super::PacketTiming,
        disposition: Forward,
    ) -> Result<Admission, Error> {
        let now = timing.admitted;
        let (eligible, first, duplicate) = match disposition {
            Forward::First(eligible) => (eligible, true, false),
            Forward::Duplicate(eligible) => (eligible, false, true),
            Forward::Bypass(eligible) => (eligible, false, false),
        };
        self.admission_budget(pipeline, key, bytes.len(), None)?;
        let mut next = self.statistics;
        next.received = increment(next.received)?;
        if eligible {
            next.eligible = increment(next.eligible)?;
        }
        if first {
            next.first_observation = increment(next.first_observation)?;
        }
        if duplicate {
            next.duplicates = increment(next.duplicates)?;
        } else {
            next.bypassed = increment(next.bypassed)?;
        }
        let metadata = pipeline
            .enqueue_borrowed_capped(
                bytes,
                timing.received,
                now,
                timing.original_deadline.ok_or(Error::Invariant)?,
            )
            .map_err(Error::Pipeline)?;
        self.statistics = next;
        self.now = now;
        Ok(Admission::Forwarded(metadata))
    }
    fn flush_matching(
        &mut self,
        pipeline: &mut Pipeline,
        key: Option<FlowKey>,
        now: Duration,
    ) -> Result<(), Error> {
        if self.is_empty() {
            return Ok(());
        }
        for index in 0..self.slots.len() {
            if self.slots[index].is_some_and(|state| key.is_none_or(|key| state.key.flow == key)) {
                self.emit(pipeline, index, now)?;
            }
        }
        Ok(())
    }
    fn emit(
        &mut self,
        pipeline: &mut Pipeline,
        index: usize,
        now: Duration,
    ) -> Result<bool, Error> {
        let Some(state) = self.slots[index] else {
            return Ok(false);
        };
        let Some(pending) = state.pending else {
            return Ok(false);
        };
        if pipeline
            .flow(&pending.flow)
            .is_none_or(|flow| flow.binding != state.binding)
        {
            return Err(Error::Invariant);
        }
        let held = QueueUsage {
            bytes: self
                .usage
                .held
                .bytes
                .checked_sub(pending.bytes)
                .ok_or(Error::Invariant)?,
            packets: self
                .usage
                .held
                .packets
                .checked_sub(1)
                .ok_or(Error::Invariant)?,
        };
        let mut next = self.statistics;
        next.flushed = increment(next.flushed)?;
        let start = index
            .checked_mul(self.plan.policy.max_ack_bytes)
            .ok_or(Error::Invariant)?;
        let bytes = self
            .slab
            .get(start..start + pending.bytes)
            .ok_or(Error::Invariant)?;
        pipeline
            .enqueue_borrowed_capped(bytes, pending.first_created, now, pending.expires)
            .map_err(Error::Pipeline)?;
        self.slots[index].as_mut().ok_or(Error::Invariant)?.pending = None;
        self.usage.held = held;
        self.statistics = next;
        self.now = now;
        Ok(true)
    }
}
fn increment(value: u64) -> Result<u64, Error> {
    value.checked_add(1).ok_or(Error::Counter)
}
fn reserve<T>(count: usize) -> Result<Vec<T>, Error> {
    Layout::array::<T>(count).map_err(|_| Error::Layout)?;
    let mut output = Vec::new();
    output
        .try_reserve_exact(count)
        .map_err(|_| Error::Allocation)?;
    if output.capacity() != count {
        return Err(Error::Invariant);
    }
    Ok(output)
}

#[cfg(test)]
mod tests;
