//! Explicit whole-group reservation and actual per-fragment physical custody.
//! Caller-owned Records authentication/replay and ciphertext stay outside this owner.
use super::*;
use crate::codec;

/// Independent bounded actual reassembly owners, scoped by authenticated kind.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReassemblyPolicies {
    /// Systematic Rolling source fragments.
    pub systematic: codec::ReassemblyConfig,
    /// Rolling repair fragments.
    pub repair: codec::ReassemblyConfig,
    /// Independently serviced reverse feedback fragments.
    pub feedback: codec::ReassemblyConfig,
}
impl ReassemblyPolicies {
    fn values(self) -> [codec::ReassemblyConfig; 3] {
        [self.systematic, self.repair, self.feedback]
    }
}
/// Complete selected policy for one globally ordered direction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FragmentDirection {
    /// Canonical sender geometry and exact full outer cost.
    pub framing: codec::FragmentConfig,
    /// Actual opposite receiver limits, not derived capacity defaults.
    pub reassembly: ReassemblyPolicies,
    /// Distinct systematic/repair/feedback labels; never enclosing authority.
    pub labels: [codec::SessionId; 3],
    /// First unused message ID in the actual directional Fragmenter.
    pub first_message: codec::MessageId,
}
/// Immutable explicit global selection; the parent authenticates every field.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FragmentPolicy {
    /// Initiator-to-responder policy.
    pub forward: FragmentDirection,
    /// Responder-to-initiator policy.
    pub reverse: FragmentDirection,
}
impl FragmentPolicy {
    /// Exact Rolling output accounting policy, with no changed body/source geometry.
    pub const fn output_framing(self) -> rolling_records::OutputFraming {
        rolling_records::OutputFraming {
            forward: self.forward.framing,
            reverse: self.reverse.framing,
        }
    }
    fn local(self, role: Role) -> (FragmentDirection, FragmentDirection) {
        match role {
            Role::Client => (self.forward, self.reverse),
            Role::Server => (self.reverse, self.forward),
        }
    }
    pub(super) fn validate(
        self,
        c: &configuration::Configuration,
        geometry: Geometry,
    ) -> Result<(), Error> {
        match c.descriptor().profile() {
            configuration::Profile::Research { config, .. } => {
                self.validate_records(*config, c, geometry)
            }
            _ => {
                let (config, _) = rolling_policy(c)?;
                self.validate_records(config, c, geometry)
            }
        }
    }
    fn validate_records<P: rolling_records::recovery::RecoveryPolicy>(
        self,
        config: rolling_records::Config<P>,
        c: &configuration::Configuration,
        geometry: Geometry,
    ) -> Result<(), Error> {
        if config.geometry != geometry {
            return Err(Error::Geometry);
        }
        self.output_framing()
            .validate(config)
            .map_err(Error::Rolling)?;
        for (direction, selected) in [
            (config.forward, self.forward),
            (config.reverse, self.reverse),
        ] {
            if selected.framing.path_mtu != c.descriptor().path_mtu() {
                return Err(Error::Geometry);
            }
            if selected.labels[0] == selected.labels[1]
                || selected.labels[0] == selected.labels[2]
                || selected.labels[1] == selected.labels[2]
            {
                return Err(Error::FragmentPolicy);
            }
            let maximum = direction.maximum_packet_bytes().map_err(Error::Rolling)?;
            let chunk = selected
                .framing
                .geometry(maximum)
                .map_err(Error::Fragment)?
                .chunk_bytes();
            for (index, limits) in selected.reassembly.values().into_iter().enumerate() {
                codec::fragment_storage::Plan::for_reassembly(limits)
                    .map_err(|_| Error::Configuration)?;
                let required = if index == 2 {
                    P::FEEDBACK_BYTES
                } else {
                    maximum
                };
                let actual = selected
                    .framing
                    .geometry(required)
                    .map_err(Error::Fragment)?;
                if limits.max_message_bytes < required
                    || usize::from(limits.max_fragment_payload_bytes) < chunk
                    || usize::from(limits.max_fragments_per_message) < actual.fragments()
                {
                    return Err(Error::Geometry);
                }
            }
        }
        Ok(())
    }
}
pub(super) fn rolling_policy(
    c: &configuration::Configuration,
) -> Result<(rolling_records::Config, rolling_records::CopyPolicies), Error> {
    match c.descriptor().profile() {
        configuration::Profile::Rolling { config, .. } => {
            Ok((*config, rolling_records::CopyPolicies::ONE))
        }
        configuration::Profile::RollingCopies { config, copies, .. } => Ok((*config, *copies)),
        _ => Err(Error::FragmentPolicy),
    }
}

/// Immutable local observation of one actually reserved logical copy/group.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FragmentGroup {
    /// Actual Fragmenter message identity, not a protection number.
    pub message: codec::MessageId,
    /// Complete unchanged logical Rolling body length.
    pub logical_bytes: usize,
    /// Exact whole physical packet reservation.
    pub packets: usize,
    /// Exact complete full-wire reservation, debited once.
    pub wire_bytes: usize,
    /// Authenticated outer category the caller must preserve for every fragment.
    pub kind: EmissionKind,
    /// Logical native witnesses initialized only once, not per fragment.
    pub witnesses: usize,
    /// Original immutable minimum caller/owner cap.
    pub deadline: Tick,
}
/// One caller-buffer physical emission; wire cost is observation, not a second debit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FragmentEmission {
    /// Exact physical inner bytes and caller-supplied fresh protection number.
    pub emission: Emission,
    /// Original whole group identity.
    pub message: codec::MessageId,
    /// Zero-based physical ordinal in that group.
    pub index: usize,
    /// Exact complete group count.
    pub count: usize,
    prepared_at: Tick,
}
/// Move-only actual pending physical witness; no public construction or I/O proof.
#[derive(Debug, Eq, PartialEq)]
pub struct FragmentOutputToken {
    context: Context,
    digest: ConfigDigest,
    group: rolling_records::PreparedOutput,
    fragment: FragmentEmission,
}
impl FragmentOutputToken {
    /// Full issuing Engine origin, never truncated to the wire label.
    pub const fn context(&self) -> Context {
        self.context
    }
    /// Exact issuing complete configuration.
    pub const fn digest(&self) -> ConfigDigest {
        self.digest
    }
    /// Exact retained physical output metadata.
    pub const fn emission(&self) -> FragmentEmission {
        self.fragment
    }
}
/// Actual local physical receipt consumed exactly once.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FragmentReceipt {
    /// This physical fragment completed; the logical copy remains held.
    More,
    /// Every whole physical fragment completed and logical custody was consumed.
    GroupComplete(FragmentGroup),
}
/// Input custody after existing external authentication and replay commit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FragmentAdmission {
    /// Actual reassembler retained a unique incomplete fragment.
    Pending,
    /// Existing actual tombstone or exact duplicate; no body admission.
    Duplicate,
    /// Unique valid input had exhausted its original lifetime/caller cap.
    Expired,
    /// Complete body entered the actual Rolling receiver/input queue.
    Accepted,
    /// Complete original body is retained on genuine Rolling Busy, not dropped.
    Held,
}
/// Actual per-kind bounded receive custody, with no reconstructed authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FragmentIngressSnapshot {
    /// Actual incomplete messages: systematic, repair, feedback.
    pub pending: [usize; 3],
    /// Original arrivals of complete bodies held on actual Rolling Busy.
    pub held_received: [Option<Tick>; 3],
    /// Original effective caps of those same held bodies.
    pub held_caps: [Option<Tick>; 3],
    /// Actual final-fragment Records number retained only as observation metadata.
    pub held_numbers: [Option<u64>; 3],
}
/// Actual finite counters; reserved cost and physical cost remain separate.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct FragmentStatistics {
    /// Logical groups whose whole common budget was reserved once.
    pub groups_reserved: u64,
    /// Whole physical writes explicitly observed, including final late facts.
    pub packets_written: u64,
    /// Exact full-wire bytes of those observed whole writes.
    pub wire_bytes_written: u64,
    /// Complete logical groups whose every physical write was observed.
    pub groups_written: u64,
}
/// Constructor failures for actual selected fragment backing.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FragmentStorageError {
    /// Maintained codec constructor/geometry failure.
    Codec(codec::FragmentError),
    /// Actual maintained reserved reassembly failure.
    Reassembly(codec::fragment_storage::Error),
    /// Complete layout overflow or impossible actual capacity.
    Layout,
    /// Actual fallible slab reservation failed.
    Allocation,
    /// Actual observed retained backing differs from the admitted plan.
    Invariant,
}
impl fmt::Display for FragmentStorageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "fragment backing: {self:?}")
    }
}
impl std::error::Error for FragmentStorageError {}
#[derive(Clone, Copy)]
pub(super) struct Plan {
    policy: FragmentPolicy,
    send: FragmentDirection,
    receive: FragmentDirection,
    reassembly: [codec::fragment_storage::Plan; 3],
    logical_bytes: usize,
    encoded_bytes: usize,
    compact_feedback: Option<(usize, usize)>,
    compact_receive_feedback: Option<usize>,
    heap_bytes: usize,
}
impl Plan {
    pub(super) fn new(
        policy: FragmentPolicy,
        context: Context,
        send_max: usize,
        compact_feedback: Option<(usize, usize)>,
    ) -> Result<Self, FragmentStorageError> {
        let (send, receive) = policy.local(context.role);
        let compact_receive_feedback = compact_feedback
            .map(|(overhead, _)| {
                overhead
                    .checked_sub(send.framing.outer_overhead_bytes)
                    .and_then(|delta| receive.framing.outer_overhead_bytes.checked_add(delta))
                    .ok_or(FragmentStorageError::Layout)
            })
            .transpose()?;
        let limits = receive.reassembly.values();
        let reassembly = [
            codec::fragment_storage::Plan::for_reassembly(limits[0])
                .map_err(FragmentStorageError::Reassembly)?,
            codec::fragment_storage::Plan::for_reassembly(limits[1])
                .map_err(FragmentStorageError::Reassembly)?,
            codec::fragment_storage::Plan::for_reassembly(limits[2])
                .map_err(FragmentStorageError::Reassembly)?,
        ];
        let mut encoded_bytes = send
            .framing
            .geometry(send_max)
            .map_err(FragmentStorageError::Codec)?
            .encoded_bytes();
        if let Some((overhead, feedback)) = compact_feedback {
            let mut framing = send.framing;
            framing.outer_overhead_bytes = overhead;
            encoded_bytes = encoded_bytes.max(
                framing
                    .geometry(feedback)
                    .map_err(FragmentStorageError::Codec)?
                    .encoded_bytes(),
            );
        }
        let mut heap_bytes = slab_layout(send_max)?
            .checked_add(slab_layout(encoded_bytes)?)
            .ok_or(FragmentStorageError::Layout)?;
        for (owner, limits) in reassembly.into_iter().zip(limits) {
            heap_bytes = heap_bytes
                .checked_add(owner.capacity_bytes())
                .and_then(|n| n.checked_add(slab_layout(limits.max_message_bytes).ok()?))
                .ok_or(FragmentStorageError::Layout)?;
        }
        Ok(Self {
            policy,
            send,
            receive,
            reassembly,
            logical_bytes: send_max,
            encoded_bytes,
            compact_feedback,
            compact_receive_feedback,
            heap_bytes,
        })
    }
    pub(super) fn heap_bytes(self) -> usize {
        self.heap_bytes
    }
    pub(super) fn policy(self) -> FragmentPolicy {
        self.policy
    }
}
fn slab_layout(length: usize) -> Result<usize, FragmentStorageError> {
    std::alloc::Layout::array::<u8>(length)
        .map(|layout| layout.size())
        .map_err(|_| FragmentStorageError::Layout)
}
fn slab(length: usize) -> Result<Vec<u8>, FragmentStorageError> {
    slab_layout(length)?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(length)
        .map_err(|_| FragmentStorageError::Allocation)?;
    if bytes.capacity() != length {
        return Err(FragmentStorageError::Invariant);
    }
    bytes.resize(length, 0);
    Ok(bytes)
}
#[derive(Clone, Copy)]
struct Input {
    received: Tick,
    completed: Tick,
    completed_order: Option<codec::CausalTime>,
    cap: Tick,
    number: u64,
    kind: EmissionKind,
    length: usize,
}
struct Lane {
    receiver: codec::Reassembler,
    complete: Vec<u8>,
    held: Option<Input>,
}
impl Lane {
    fn new(
        plan: codec::fragment_storage::Plan,
        context: codec::FragmentContext,
    ) -> Result<Self, FragmentStorageError> {
        let receiver = codec::Reassembler::new_reserved(
            context,
            plan.config(),
            codec::fragment_storage::Limits {
                capacity_bytes: plan.capacity_bytes(),
            },
        )
        .map_err(FragmentStorageError::Reassembly)?;
        let complete = slab(plan.config().max_message_bytes)?;
        Ok(Self {
            receiver,
            complete,
            held: None,
        })
    }
}
struct Group {
    metadata: FragmentGroup,
    layout: codec::FragmentLayout,
    token: CarrierOutputToken,
    key: rolling_records::PreparedOutput,
    next: usize,
    pending: Option<FragmentEmission>,
    accepted: Option<Tick>,
    accepted_order: Option<codec::CausalTime>,
}
pub(super) struct State {
    plan: Plan,
    senders: [codec::Fragmenter; 3],
    lanes: [Lane; 3],
    logical: Vec<u8>,
    encoded: Vec<u8>,
    group: Option<Group>,
    statistics: FragmentStatistics,
}
impl State {
    pub(super) fn compact_feedback_overhead(&self) -> Option<usize> {
        self.plan.compact_feedback.map(|value| value.0)
    }
    pub(super) fn new(plan: Plan, context: Context) -> Result<Self, FragmentStorageError> {
        let epoch = crate::core::Epoch(context.epoch);
        let make_sender = |index| {
            let mut framing = plan.send.framing;
            if index == 2
                && let Some((overhead, _)) = plan.compact_feedback
            {
                framing.outer_overhead_bytes = overhead;
            }
            codec::Fragmenter::new(
                codec::FragmentContext {
                    session: plan.send.labels[index],
                    epoch,
                },
                framing,
                plan.send.first_message,
            )
            .map_err(FragmentStorageError::Codec)
        };
        let make_receiver = |index| {
            Lane::new(
                plan.reassembly[index],
                codec::FragmentContext {
                    session: plan.receive.labels[index],
                    epoch,
                },
            )
        };
        let value = Self {
            plan,
            senders: [make_sender(0)?, make_sender(1)?, make_sender(2)?],
            lanes: [make_receiver(0)?, make_receiver(1)?, make_receiver(2)?],
            logical: slab(plan.logical_bytes)?,
            encoded: slab(plan.encoded_bytes)?,
            group: None,
            statistics: FragmentStatistics::default(),
        };
        if value.usage()?.0 != plan.heap_bytes {
            return Err(FragmentStorageError::Invariant);
        }
        Ok(value)
    }
    pub(super) fn usage(&self) -> Result<(usize, usize), FragmentStorageError> {
        let mut bytes = self
            .logical
            .capacity()
            .checked_add(self.encoded.capacity())
            .ok_or(FragmentStorageError::Layout)?;
        let mut allocations =
            usize::from(self.logical.capacity() != 0) + usize::from(self.encoded.capacity() != 0);
        for lane in &self.lanes {
            let usage = lane
                .receiver
                .storage_usage()
                .ok_or(FragmentStorageError::Invariant)?;
            bytes = bytes
                .checked_add(lane.complete.capacity())
                .and_then(|n| n.checked_add(usage.capacity_bytes))
                .ok_or(FragmentStorageError::Layout)?;
            allocations = allocations
                .checked_add(usage.allocations)
                .and_then(|n| n.checked_add(usize::from(lane.complete.capacity() != 0)))
                .ok_or(FragmentStorageError::Layout)?;
        }
        Ok((bytes, allocations))
    }
    pub(super) fn deadline(&self) -> Option<Tick> {
        self.group
            .as_ref()
            .map(|g| g.metadata.deadline)
            .into_iter()
            .chain(self.lanes.iter().filter_map(|l| l.held.map(|i| i.cap)))
            .chain(
                self.lanes
                    .iter()
                    .filter_map(|l| l.receiver.deadline().map(Tick)),
            )
            .min()
    }
    pub(super) fn tick(&mut self, now: Tick) -> Result<(), Error> {
        if self
            .group
            .as_ref()
            .is_some_and(|g| now >= g.metadata.deadline)
            || self
                .lanes
                .iter()
                .any(|l| l.held.is_some_and(|i| now >= i.cap))
        {
            return Err(Error::Expired);
        }
        for lane in &mut self.lanes {
            lane.receiver.expire_count(now.0).map_err(Error::Fragment)?;
        }
        Ok(())
    }
    pub(super) fn drained(&self) -> bool {
        self.group.is_none()
            && self
                .lanes
                .iter()
                .all(|l| l.held.is_none() && l.receiver.pending_messages() == 0)
    }
}
fn lane_index(kind: EmissionKind) -> Result<usize, Error> {
    match kind {
        EmissionKind::Source(SourceForm::SystematicFec) => Ok(0),
        EmissionKind::Repair => Ok(1),
        EmissionKind::Feedback => Ok(2),
        _ => Err(Error::Kind),
    }
}

impl Engine {
    /// Exact active immutable selection; None owns no fragment heaps.
    pub fn fragment_policy(&self) -> Option<FragmentPolicy> {
        self.fragments.as_ref().map(|s| s.plan.policy)
    }
    /// Exact actual pending/held input custody; this does not manufacture peer proof.
    pub fn fragment_ingress_snapshot(&self) -> Option<FragmentIngressSnapshot> {
        let state = self.fragments.as_ref()?;
        Some(FragmentIngressSnapshot {
            pending: std::array::from_fn(|i| state.lanes[i].receiver.pending_messages()),
            held_received: std::array::from_fn(|i| state.lanes[i].held.map(|v| v.received)),
            held_caps: std::array::from_fn(|i| state.lanes[i].held.map(|v| v.cap)),
            held_numbers: std::array::from_fn(|i| state.lanes[i].held.map(|v| v.number)),
        })
    }
    /// Actual finite reservation/physical observations, not delivery inference.
    pub fn fragment_statistics(&self) -> Option<FragmentStatistics> {
        self.fragments.as_ref().map(|s| s.statistics)
    }
    /// Observe the same actual logical group without assigning another ID or debit.
    pub fn pending_fragment_group(&self) -> Option<FragmentGroup> {
        self.fragments.as_ref()?.group.as_ref().map(|g| g.metadata)
    }
    /// Reserve the complete group once; this does not seal or send any fragment.
    pub fn reserve_fragment_group(
        &mut self,
        now: Tick,
        prospective_number: u64,
        allow_data: bool,
        budget: &mut OutboundBudget,
        witnesses: &mut [receiver::UnitWitness],
    ) -> Result<Option<FragmentGroup>, Error> {
        self.reserve_fragment_group_until(
            now,
            prospective_number,
            allow_data,
            Tick(u64::MAX),
            budget,
            witnesses,
        )
    }
    /// Preserve an original external operation/session cap across all fragments.
    #[allow(clippy::too_many_arguments)] // Explicit original cap extends the existing real output contract.
    pub fn reserve_fragment_group_until(
        &mut self,
        now: Tick,
        prospective_number: u64,
        allow_data: bool,
        original_cap: Tick,
        budget: &mut OutboundBudget,
        witnesses: &mut [receiver::UnitWitness],
    ) -> Result<Option<FragmentGroup>, Error> {
        if self.fragments.is_none() {
            return Err(Error::FragmentPolicy);
        }
        self.advance(now)?;
        if let Some(group) = self.pending_fragment_group() {
            return Ok(Some(group));
        }
        if now >= original_cap {
            return self.fail(Error::Expired);
        }
        if witnesses.len() < self.witnesses {
            return Err(Error::Witnesses {
                required: self.witnesses,
            });
        }
        let state = self.fragments.as_mut().ok_or(Error::Invariant)?;
        // Exhaustion/geometry are preflighted before actual Rolling custody or a
        // shared debit changes. The actual next ID remains owned by Fragmenter.
        if state
            .senders
            .iter()
            .any(|owner| owner.next_message().is_none())
        {
            return Err(Error::Fragment(codec::FragmentError::Exhausted));
        }
        state.senders[0]
            .geometry(self.send_max)
            .map_err(Error::Fragment)?;
        let groups = state
            .statistics
            .groups_reserved
            .checked_add(1)
            .ok_or(Error::Arithmetic)?;
        let emitted = self
            .statistics
            .emitted
            .checked_add(1)
            .ok_or(Error::Arithmetic)?;
        let maximum = state
            .plan
            .send
            .framing
            .geometry(self.send_max)
            .map_err(Error::Fragment)?;
        let feedback_maximum = state
            .plan
            .compact_feedback
            .map(|(_, bytes)| state.senders[2].geometry(bytes).map_err(Error::Fragment))
            .transpose()?;
        let max_packets = feedback_maximum
            .as_ref()
            .map_or(maximum.fragments(), |feedback| {
                feedback.fragments().max(maximum.fragments())
            });
        let max_wire = feedback_maximum
            .as_ref()
            .map_or(maximum.wire_bytes(), |feedback| {
                feedback.wire_bytes().max(maximum.wire_bytes())
            });
        state
            .statistics
            .packets_written
            .checked_add(u64::try_from(max_packets).map_err(|_| Error::Arithmetic)?)
            .ok_or(Error::Arithmetic)?;
        state
            .statistics
            .wire_bytes_written
            .checked_add(u64::try_from(max_wire).map_err(|_| Error::Arithmetic)?)
            .ok_or(Error::Arithmetic)?;
        state
            .statistics
            .groups_written
            .checked_add(1)
            .ok_or(Error::Arithmetic)?;
        let before = *budget;
        let (prepared, owner_deadline) = match &mut self.owner {
            Owner::Rolling(endpoint) => {
                endpoint
                    .step(now, crate::fec::rolling::WorkBudget::default())
                    .map_err(Error::Rolling)?;
                (
                    endpoint
                        .prepare_output(
                            now,
                            prospective_number,
                            allow_data,
                            &mut state.logical,
                            budget,
                            witnesses,
                        )
                        .map_err(Error::Rolling)?,
                    endpoint.deadline(),
                )
            }
            Owner::Research(endpoint) => {
                endpoint
                    .step(now, crate::fec::rolling::WorkBudget::default())
                    .map_err(Error::Rolling)?;
                (
                    endpoint
                        .prepare_output(
                            now,
                            prospective_number,
                            allow_data,
                            &mut state.logical,
                            budget,
                            witnesses,
                        )
                        .map_err(Error::Rolling)?,
                    endpoint.deadline(),
                )
            }
            _ => return Err(Error::FragmentPolicy),
        };
        let Some(prepared) = prepared else {
            if *budget != before {
                return self.fail(Error::Invariant);
            }
            return Ok(None);
        };
        let index = lane_index(prepared.kind)?;
        let geometry = state.senders[index]
            .geometry(prepared.bytes)
            .map_err(Error::Fragment)?;
        if prepared.packets != geometry.fragments()
            || prepared.wire_bytes != geometry.wire_bytes()
            || before.packets.checked_sub(budget.packets) != Some(prepared.packets)
            || before.wire_bytes.checked_sub(budget.wire_bytes) != Some(prepared.wire_bytes)
        {
            return self.fail(Error::Invariant);
        }
        let owner_cap = owner_deadline.unwrap_or(original_cap).min(original_cap);
        if now >= owner_cap {
            return self.fail(Error::Expired);
        }
        let layout = state.senders[index]
            .fragment_into(&state.logical[..prepared.bytes], &mut state.encoded)
            .map_err(Error::Fragment)?
            .layout();
        let metadata = FragmentGroup {
            message: layout.message(),
            logical_bytes: prepared.bytes,
            packets: prepared.packets,
            wire_bytes: prepared.wire_bytes,
            kind: prepared.kind,
            witnesses: prepared.witnesses,
            deadline: owner_cap,
        };
        let token = self
            .pending_whole_carrier_output()
            .ok_or(Error::Invariant)?;
        let state = self.fragments.as_mut().ok_or(Error::Invariant)?;
        state.group = Some(Group {
            metadata,
            layout,
            token,
            key: prepared,
            next: 0,
            pending: None,
            accepted: None,
            accepted_order: None,
        });
        state.statistics.groups_reserved = groups;
        self.statistics.emitted = emitted;
        Ok(Some(metadata))
    }
    /// Emit exactly one reserved fragment using its then-fresh caller PN.
    /// No shared budget is accepted: full group reservation already paid once.
    /// Held retry returns original metadata without rewriting caller plaintext;
    /// the caller must retain original ciphertext and never reseal that PN.
    pub fn poll_reserved_fragment(
        &mut self,
        now: Tick,
        number: u64,
        output: &mut [u8],
    ) -> Result<Option<FragmentEmission>, Error> {
        if self.fragments.is_none() {
            return Err(Error::FragmentPolicy);
        }
        self.advance(now)?;
        if let Err(error) = self.owner.tick(now) {
            return self.fail(error);
        }
        let state = self.fragments.as_mut().ok_or(Error::Invariant)?;
        let Some(group) = state.group.as_mut() else {
            return Ok(None);
        };
        if let Some(pending) = group.pending {
            return Ok(Some(pending));
        }
        let range = group
            .layout
            .fragment_range(group.next)
            .ok_or(Error::Invariant)?;
        let source = state.encoded.get(range).ok_or(Error::Invariant)?;
        if output.len() < source.len() {
            return Err(Error::Output {
                required: source.len(),
            });
        }
        let wire_bytes = source
            .len()
            .checked_add(if group.metadata.kind == EmissionKind::Feedback {
                state
                    .plan
                    .compact_feedback
                    .map_or(state.plan.send.framing.outer_overhead_bytes, |value| {
                        value.0
                    })
            } else {
                state.plan.send.framing.outer_overhead_bytes
            })
            .ok_or(Error::Arithmetic)?;
        let fragment = FragmentEmission {
            emission: Emission {
                bytes: source.len(),
                kind: group.metadata.kind,
                wire_bytes,
                security_number: number,
                witnesses: 0,
            },
            message: group.metadata.message,
            index: group.next,
            count: group.metadata.packets,
            prepared_at: now,
        };
        output[..source.len()].copy_from_slice(source);
        group.pending = Some(fragment);
        Ok(Some(fragment))
    }
    /// Move-only local witness for exactly the retained physical fragment.
    pub fn pending_fragment_output(&self) -> Option<FragmentOutputToken> {
        let group = self.fragments.as_ref()?.group.as_ref()?;
        Some(FragmentOutputToken {
            context: self.context,
            digest: self.digest,
            group: group.key,
            fragment: group.pending?,
        })
    }
    /// Consume one whole physical write; only the final ordinal releases the copy.
    pub fn confirm_fragment_at(
        &mut self,
        now: Tick,
        accepted: Tick,
        token: FragmentOutputToken,
    ) -> Result<FragmentReceipt, Error> {
        self.confirm_fragment_inner(now, accepted, None, token)
    }
    /// Preserve the same clock origin's precise whole-send acceptance order.
    pub fn confirm_fragment_ordered_at(
        &mut self,
        now: Tick,
        accepted: Tick,
        order: codec::CausalTime,
        token: FragmentOutputToken,
    ) -> Result<FragmentReceipt, Error> {
        self.confirm_fragment_inner(now, accepted, Some(order), token)
    }
    fn confirm_fragment_inner(
        &mut self,
        now: Tick,
        accepted: Tick,
        order: Option<codec::CausalTime>,
        token: FragmentOutputToken,
    ) -> Result<FragmentReceipt, Error> {
        if self.pending_fragment_output().as_ref() != Some(&token) {
            return Err(Error::Token);
        }
        // Check time while original group custody is still present, but consume
        // the matching physical fact even if it makes this Engine terminal.
        let timing = if accepted < token.fragment.prepared_at || accepted > now {
            self.fail(Error::Time)
        } else {
            self.advance(now)
        };
        let state = self.fragments.as_mut().ok_or(Error::Invariant)?;
        let group = state.group.as_mut().ok_or(Error::Invariant)?;
        group.pending = None;
        group.next = group.next.checked_add(1).ok_or(Error::Arithmetic)?;
        group.accepted_order = match (group.accepted, group.accepted_order, order) {
            (None, _, current) => current,
            (Some(_), Some(previous), Some(current)) => Some(previous.max(current)),
            _ => None,
        };
        group.accepted = Some(group.accepted.map_or(accepted, |at| at.max(accepted)));
        state.statistics.packets_written = state
            .statistics
            .packets_written
            .checked_add(1)
            .ok_or(Error::Arithmetic)?;
        state.statistics.wire_bytes_written = state
            .statistics
            .wire_bytes_written
            .checked_add(
                u64::try_from(token.fragment.emission.wire_bytes).map_err(|_| Error::Arithmetic)?,
            )
            .ok_or(Error::Arithmetic)?;
        let complete = group.next == group.metadata.packets;
        if !complete {
            timing?;
            return Ok(FragmentReceipt::More);
        }
        let group = state.group.take().ok_or(Error::Invariant)?;
        state.statistics.groups_written = state
            .statistics
            .groups_written
            .checked_add(1)
            .ok_or(Error::Arithmetic)?;
        let result = self.confirm_whole_carrier_output_at(
            now,
            group.accepted.ok_or(Error::Invariant)?,
            group.accepted_order,
            group.token,
        );
        timing?;
        result?;
        Ok(FragmentReceipt::GroupComplete(group.metadata))
    }
    /// Classify every authenticated LX fragment, including non-first fragments,
    /// using exact selected labels under this full Engine context and epoch.
    /// Validate complete immutable fragment geometry and its selected physical MTU.
    /// This structural preflight grants no authentication, replay or admission authority.
    pub fn inspect_fragment_kind(&self, fragment: &[u8]) -> Result<EmissionKind, Error> {
        let state = self.fragments.as_ref().ok_or(Error::FragmentPolicy)?;
        let header = codec::inspect_fragment_context(fragment).map_err(Error::Fragment)?;
        if header.epoch.0 != self.context.epoch {
            return Err(Error::Fragment(codec::FragmentError::WrongContext));
        }
        let index = state
            .plan
            .receive
            .labels
            .iter()
            .position(|label| *label == header.session)
            .ok_or(Error::Fragment(codec::FragmentError::WrongContext))?;
        state.lanes[index]
            .receiver
            .validate_fragment(fragment)
            .map_err(Error::Fragment)?;
        let overhead = if index == 2 {
            state
                .plan
                .compact_receive_feedback
                .unwrap_or(state.plan.receive.framing.outer_overhead_bytes)
        } else {
            state.plan.receive.framing.outer_overhead_bytes
        };
        if fragment
            .len()
            .checked_add(overhead)
            .ok_or(Error::Arithmetic)?
            > state.plan.receive.framing.path_mtu
        {
            return Err(Error::PacketSize);
        }
        Ok(match index {
            0 => EmissionKind::Source(SourceForm::SystematicFec),
            1 => EmissionKind::Repair,
            2 => EmissionKind::Feedback,
            _ => return Err(Error::Invariant),
        })
    }
    /// Accept only already authenticated/replay-checked fragments for this exact
    /// full Engine generation. Kind selects an independent actual reassembler.
    pub fn accept_fragment_authenticated_until(
        &mut self,
        received: Tick,
        now: Tick,
        original_cap: Tick,
        number: u64,
        fragment: &[u8],
    ) -> Result<FragmentAdmission, Error> {
        self.accept_fragment_inner(received, now, original_cap, number, None, fragment)
    }
    /// Preserve precise authenticated observation alongside unchanged arrival age.
    pub fn accept_fragment_authenticated_ordered_until(
        &mut self,
        received: Tick,
        now: Tick,
        original_cap: Tick,
        number: u64,
        order: codec::CausalTime,
        fragment: &[u8],
    ) -> Result<FragmentAdmission, Error> {
        self.accept_fragment_inner(received, now, original_cap, number, Some(order), fragment)
    }
    fn accept_fragment_inner(
        &mut self,
        received: Tick,
        now: Tick,
        original_cap: Tick,
        number: u64,
        order: Option<codec::CausalTime>,
        fragment: &[u8],
    ) -> Result<FragmentAdmission, Error> {
        if self.fragments.is_none() {
            return Err(Error::FragmentPolicy);
        }
        if received > now {
            return Err(Error::Time);
        }
        let kind = self.inspect_fragment_kind(fragment)?;
        let index = lane_index(kind)?;
        self.advance(now)?;
        let state = self.fragments.as_mut().ok_or(Error::Invariant)?;
        let lane = &mut state.lanes[index];
        if lane.held.is_some() {
            return Err(Error::FragmentBusy);
        }
        let status = match order {
            Some(order) => lane.receiver.accept_ordered_at_until(
                fragment,
                received.0,
                now.0,
                original_cap.0,
                order,
                &mut lane.complete,
            ),
            None => lane.receiver.accept_at_until(
                fragment,
                received.0,
                now.0,
                original_cap.0,
                &mut lane.complete,
            ),
        }
        .map_err(Error::Fragment)?;
        match status {
            codec::TimedReassemblyStatus::Pending { .. } => Ok(FragmentAdmission::Pending),
            codec::TimedReassemblyStatus::Duplicate { .. } => Ok(FragmentAdmission::Duplicate),
            codec::TimedReassemblyStatus::Expired { .. } => Ok(FragmentAdmission::Expired),
            codec::TimedReassemblyStatus::Complete { length, timing, .. } => {
                lane.held = Some(Input {
                    received: Tick(timing.first_received_ticks()),
                    completed: Tick(timing.complete_received_ticks()),
                    completed_order: timing.complete_order(),
                    cap: Tick(timing.deadline_ticks()),
                    number,
                    kind,
                    length,
                });
                match self.retry_fragment_lane(now, index)? {
                    true => Ok(FragmentAdmission::Accepted),
                    false => Ok(FragmentAdmission::Held),
                }
            }
        }
    }
    fn retry_fragment_lane(&mut self, now: Tick, index: usize) -> Result<bool, Error> {
        // Research support is frozen at actual complete send acceptance. Its
        // already complete feedback body must wait until that receipt orders it.
        if index == 2
            && matches!(&self.owner, Owner::Research(_))
            && self.pending_whole_carrier_output().is_some_and(|p| {
                matches!(
                    p.emission().kind,
                    EmissionKind::Source(_) | EmissionKind::Repair
                )
            })
        {
            let state = self.fragments.as_mut().ok_or(Error::FragmentPolicy)?;
            let lane = &mut state.lanes[index];
            let Some(input) = lane.held else {
                return Ok(false);
            };
            let Owner::Research(endpoint) = &mut self.owner else {
                return Err(Error::Invariant);
            };
            match endpoint.retain_feedback_until(
                input.completed,
                now,
                input.cap,
                input.number,
                input.completed_order,
                &lane.complete[..input.length],
            ) {
                Ok(true) => {
                    lane.held = None;
                    return Ok(true);
                }
                Ok(false) | Err(crate::rolling_records::Error::Busy) => return Ok(false),
                Err(error) => return self.fail(Error::Rolling(error)),
            }
        }
        let state = self.fragments.as_mut().ok_or(Error::FragmentPolicy)?;
        let lane = &mut state.lanes[index];
        let Some(input) = lane.held else {
            return Ok(false);
        };
        if now >= input.cap {
            return self.fail(Error::Expired);
        }
        let received =
            if input.kind == EmissionKind::Feedback && matches!(&self.owner, Owner::Research(_)) {
                input.completed
            } else {
                input.received
            };
        let result = self.owner.accept_until(
            received,
            now,
            input.cap,
            input.number,
            input.kind,
            &mut lane.complete[..input.length],
        );
        match result {
            Ok(()) => {
                lane.held = None;
                Ok(true)
            }
            Err(Error::Rolling(error)) if error.is_backpressure() => Ok(false),
            Err(error) => self.fail(error),
        }
    }
    // The actual whole-output witness was checked by carrier.rs. No new
    // authority or queue is created: consume the existing complete-body slot.
    pub(super) fn research_fragment_feedback_at_completion(
        &mut self,
        now: Tick,
        accepted: Tick,
        order: Option<codec::CausalTime>,
        before: bool,
    ) -> Result<(), Error> {
        if let Owner::Research(endpoint) = &mut self.owner {
            endpoint
                .feedback_at_completion(now, accepted, order, before)
                .map_err(Error::Rolling)?;
        } else {
            return Ok(());
        }
        let Some(state) = &mut self.fragments else {
            return Ok(());
        };
        let lane = &mut state.lanes[2];
        let Some(input) = lane.held else {
            return Ok(());
        };
        let earlier = match (input.completed_order, order) {
            (Some(arrived), Some(sent)) => arrived <= sent,
            // Existing tick-only APIs retain their caller ordering convention.
            // Actual async carriers always supply precise observations above.
            _ => input.completed <= accepted,
        };
        if earlier != before {
            return Ok(());
        }
        if now >= input.cap {
            return self.fail(Error::Expired);
        }
        let result = self.owner.accept_until(
            input.completed,
            now,
            input.cap,
            input.number,
            input.kind,
            &mut lane.complete[..input.length],
        );
        match result {
            Ok(()) => {
                lane.held = None;
                Ok(())
            }
            Err(error) => self.fail(error),
        }
    }

    /// Retry at most the three existing completion slots, feedback first.
    /// No authentication, replay commit, received age or caller cap is renewed.
    pub fn retry_fragment_inputs(&mut self, now: Tick) -> Result<usize, Error> {
        if self.fragments.is_none() {
            return Err(Error::FragmentPolicy);
        }
        self.advance(now)?;
        let mut accepted = 0;
        for index in [2, 0, 1] {
            accepted += usize::from(self.retry_fragment_lane(now, index)?);
        }
        Ok(accepted)
    }
}
