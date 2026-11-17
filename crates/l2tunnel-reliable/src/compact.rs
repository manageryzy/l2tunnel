//! Explicit R0 composition of the maintained Compact recovery owner.
use super::*;
use l2tunnel_recovery::{
    CompactArqConfig, CompactPacketView, CompactRepeat, inspect_compact_packet,
};
mod output;
pub use output::{CompactOutput, CompactOutputError, CompactOverheads};

/// Complete R0 data-direction policy, with no unused FEC configuration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CompactReliableConfig {
    arq: CompactArqConfig,
    outer_overhead_bytes: usize,
}
impl CompactReliableConfig {
    /// Validate exact nested policy and outer per-emission accounting.
    pub fn new(arq: CompactArqConfig, outer_overhead_bytes: usize) -> Result<Self, Error> {
        let value = Self {
            arq,
            outer_overhead_bytes,
        };
        value.validate()?;
        Ok(value)
    }
    /// Exact selected recovery policy.
    pub const fn arq(self) -> CompactArqConfig {
        self.arq
    }
    /// Exact external charge, excluding the Reliable envelope.
    pub const fn outer_overhead_bytes(self) -> usize {
        self.outer_overhead_bytes
    }
    /// Validate the source direction without allocation or a recovery owner.
    /// This policy's feedback is sent in the opposite direction. The duplex
    /// CompactPlan checks both crossed feedback ceilings with their actual
    /// outbound overhead; a direction alone cannot infer that peer geometry.
    pub fn validate(self) -> Result<(), Error> {
        self.arq.validate()?;
        let body = self
            .arq
            .bounds()
            .max_source_bytes
            .checked_add(l2tunnel_recovery::COMPACT_DATA_HEADER_BYTES)
            .ok_or(Error::InvalidConfig)?;
        packet_maximum(body, self.outer_overhead_bytes).map(|_| ())
    }
}

pub(super) enum Policies {
    Legacy {
        send: ReliableConfig,
        receive: ReliableConfig,
    },
    Compact {
        send: CompactReliableConfig,
        receive: CompactReliableConfig,
    },
}
impl Reliable {
    /// Borrow the actual maintained v1/v2 output fields without admitting data,
    /// minting a physical receipt or granting authentication to parser metadata.
    pub fn inspect_output_record<'a>(
        &self,
        packet: &'a [u8],
    ) -> Result<StructuralRecord<'a>, Error> {
        self.inspect_output(packet)?;
        if self.compact_wire.is_some() {
            return self.selected_inspect(packet, true);
        }
        if self.arq.is_compact() {
            return self.compact_inspect(packet, true);
        }
        let config = self.legacy_send()?;
        inspect_record_view(
            packet,
            self.maximum_packet,
            config.arq.max_source_bytes,
            config.fec.block,
            opposite_context(self.context),
            self.send_fec,
        )
    }

    pub(super) fn legacy_send(&self) -> Result<&ReliableConfig, Error> {
        match &self.policies {
            Policies::Legacy { send, .. } => Ok(send),
            Policies::Compact { .. } => Err(Error::InvalidConfig),
        }
    }
    pub(super) fn legacy_receive(&self) -> Result<&ReliableConfig, Error> {
        match &self.policies {
            Policies::Legacy { receive, .. } => Ok(receive),
            Policies::Compact { .. } => Err(Error::InvalidConfig),
        }
    }
    pub(super) fn outer_overhead(&self) -> usize {
        if let Some(overheads) = self.compact_wire {
            return overheads.data;
        }
        match &self.policies {
            Policies::Legacy { send, .. } => send.outer_overhead_bytes,
            Policies::Compact { send, .. } => send.outer_overhead_bytes,
        }
    }
    /// Construct one symmetric explicitly selected Compact R0 owner.
    pub fn new_compact(
        config: CompactReliableConfig,
        context: RecoveryContext,
    ) -> Result<Self, Error> {
        Self::new_compact_duplex(config, config, context)
    }
    /// Fallibly reserve complete selected backing; no dynamic fallback exists.
    pub fn new_compact_duplex(
        send: CompactReliableConfig,
        receive: CompactReliableConfig,
        context: RecoveryContext,
    ) -> Result<Self, Error> {
        let plan =
            storage::CompactPlan::for_duplex(send, receive).map_err(selected_storage_error)?;
        Self::new_compact_duplex_reserved(
            send,
            receive,
            context,
            storage::Limits {
                capacity_bytes: plan.capacity_bytes(),
            },
        )
        .map_err(selected_storage_error)
    }
    /// Construct the same wrapper with one actual selected recovery owner.
    pub fn new_compact_duplex_reserved(
        send: CompactReliableConfig,
        receive: CompactReliableConfig,
        context: RecoveryContext,
        limits: storage::Limits,
    ) -> Result<Self, storage::Error> {
        let plan = storage::CompactPlan::for_duplex(send, receive)?;
        if plan.capacity_bytes() > limits.capacity_bytes {
            return Err(storage::Error::Limit {
                required: plan.capacity_bytes(),
                limit: limits.capacity_bytes,
            });
        }
        let arq = CompactRepeat::new_duplex_reserved(
            send.arq,
            receive.arq,
            context,
            l2tunnel_recovery::storage::Limits {
                capacity_bytes: plan.arq.capacity_bytes(),
            },
        )
        .map_err(storage::Error::Recovery)?;
        let nested = arq.storage_usage().ok_or(storage::Error::Invariant)?;
        if nested.capacity_bytes != plan.arq.capacity_bytes() {
            return Err(storage::Error::Invariant);
        }
        let mut allocation = storage::Allocation::new(limits.capacity_bytes);
        let mut scratch = allocation.vec(plan.scratch_bytes)?;
        scratch.resize(plan.scratch_bytes, 0);
        let building = backing::Building::reserved(0, 0, &mut allocation)?;
        let outgoing = backing::Queue::reserved(0, 0, &mut allocation)?;
        let restored = backing::RestoredMap::reserved(0, 0, &mut allocation)?;
        let fec_deadlines = backing::Deadlines::reserved(0, &mut allocation)?;
        let expired = backing::expired(0, &mut allocation)?;
        let wrapper = allocation.usage();
        let bytes = storage::add(nested.capacity_bytes, wrapper.capacity_bytes)?;
        let allocations = storage::add(nested.allocations, wrapper.allocations)?;
        if bytes != plan.capacity_bytes() || wrapper.allocations != 1 {
            return Err(storage::Error::Invariant);
        }
        let instance = NEXT_PHYSICAL_OWNER
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                value.checked_add(1)
            })
            .map_err(|_| storage::Error::Reliable(Error::Exhausted))?;
        Ok(Self {
            policies: Policies::Compact { send, receive },
            context,
            arq: recovery_owner::Owner::Compact(arq),
            decoder: None,
            send_fec: fec_context(context, false),
            receive_fec: fec_context(context, true),
            building,
            building_deadline: None,
            next_fresh_source: 0,
            next_generation: None,
            outgoing,
            restored,
            restored_bytes: 0,
            fec_deadlines,
            encoder: None,
            expired,
            usage: Some(storage::Usage {
                limit_bytes: limits.capacity_bytes,
                capacity_bytes: bytes,
                allocations,
            }),
            scratch,
            maximum_packet: plan.send_maximum,
            receive_maximum_packet: plan.receive_maximum,
            prefer_feedback: true,
            now: Duration::ZERO,
            failure: None,
            statistics: Statistics::default(),
            physical_instance: Some(instance),
            next_output: 1,
            pending_output: None,
            independent_feedback: None,
            compact_wire: None,
            diagnostics: Vec::new(),
        })
    }
    /// Admit using original authenticated arrival and monotonic observation.
    /// A retryable physical-feedback race changes no wrapper clock or state.
    pub fn receive_at(
        &mut self,
        packet: &[u8],
        received: Duration,
        observed: Duration,
    ) -> Result<(), Error> {
        let before = (!self.diagnostics.is_empty()).then(|| self.arq.retained());
        let result = self.receive_at_inner(packet, received, observed);
        self.observe_retirement(
            before,
            observed,
            None,
            diagnostics::staged::RetirementKind::Input,
            result.is_ok(),
        );
        result
    }
    fn receive_at_inner(
        &mut self,
        packet: &[u8],
        received: Duration,
        observed: Duration,
    ) -> Result<(), Error> {
        if self.compact_wire.is_some() {
            return self.receive_selected(packet, received, observed);
        }
        if !self.arq.is_compact() {
            if received > observed {
                return Err(Error::NonMonotonicTime);
            }
            return self.receive_legacy(packet, observed);
        }
        self.check_time(observed)?;
        if received > observed {
            return Err(Error::NonMonotonicTime);
        }
        self.compact_inspect(packet, false)
            .or_else(|error| self.fail(error))?;
        let (_, inner) =
            envelope(packet, self.receive_maximum_packet).or_else(|error| self.fail(error))?;
        match self.arq.receive_at(inner, received, observed) {
            Ok(()) => self.advance(observed),
            Err(
                error @ (RecoveryError::FeedbackAwaitingPhysical
                | RecoveryError::Capacity(_)
                | RecoveryError::SequenceWindow
                | RecoveryError::HistoryCapacity),
            ) => Err(error.into()),
            Err(error) => self.fail(error.into()),
        }
    }
    pub(super) fn compact_inspect<'a>(
        &self,
        packet: &'a [u8],
        outgoing: bool,
    ) -> Result<StructuralRecord<'a>, Error> {
        let Policies::Compact { send, receive } = &self.policies else {
            return Err(Error::InvalidConfig);
        };
        let (source, feedback, context, maximum) = if outgoing {
            (
                send.arq,
                receive.arq,
                opposite_context(self.context),
                self.maximum_packet,
            )
        } else {
            (
                receive.arq,
                send.arq,
                self.context,
                self.receive_maximum_packet,
            )
        };
        inspect_compact_view(packet, maximum, source, feedback, context)
    }
    pub(super) fn poll_compact_inner(
        &mut self,
        now: Duration,
        output: &mut [u8],
        budget: &mut OutboundBudget,
        allow_feedback: bool,
        allow_data: bool,
    ) -> Result<Option<usize>, Error> {
        self.check_time(now)?;
        if output.len() < self.maximum_packet {
            return Err(Error::OutputTooSmall {
                required: self.maximum_packet,
            });
        }
        if allow_feedback
            && (self.prefer_feedback || !allow_data)
            && let Some(bytes) = self.emit_compact(now, true, output, budget)?
        {
            return Ok(Some(bytes));
        }
        if allow_data && let Some(bytes) = self.emit_compact(now, false, output, budget)? {
            return Ok(Some(bytes));
        }
        if allow_feedback && let Some(bytes) = self.emit_compact(now, true, output, budget)? {
            return Ok(Some(bytes));
        }
        self.advance(now)?;
        Ok(None)
    }
    fn emit_compact(
        &mut self,
        now: Duration,
        feedback: bool,
        output: &mut [u8],
        budget: &mut OutboundBudget,
    ) -> Result<Option<usize>, Error> {
        if self.compact_wire.is_some() {
            return self.emit_compact_wire(now, feedback, output, budget);
        }
        let Some(inner) = self.arq.compact_packet_bytes(now, feedback)? else {
            return Ok(None);
        };
        let bytes = inner.checked_add(ENVELOPE_BYTES).ok_or(Error::Exhausted)?;
        if !self.allowed(bytes, budget)? {
            return Ok(None);
        }
        let before = self.arq.statistics().retransmissions;
        let emitted = if feedback {
            self.arq.poll_feedback(now, &mut self.scratch)?
        } else {
            self.arq.poll_source(now, &mut self.scratch)?
        };
        if emitted != Some(inner) {
            return self.fail(Error::Malformed);
        }
        self.advance(now)?;
        let emission = if feedback {
            Emission::Feedback
        } else if self.arq.statistics().retransmissions > before {
            Emission::Retry
        } else {
            Emission::Source
        };
        self.emit_scratch(
            if feedback { 2 } else { 1 },
            inner,
            emission,
            output,
            budget,
        )
        .map(Some)
    }
}

pub(super) fn packet_maximum(inner: usize, overhead: usize) -> Result<usize, Error> {
    let packet = ENVELOPE_BYTES
        .checked_add(inner)
        .ok_or(Error::InvalidConfig)?;
    if packet > 65_507 || packet.checked_add(overhead).is_none_or(|n| n > 65_535) {
        return Err(Error::InvalidConfig);
    }
    Ok(packet)
}
fn selected_storage_error(error: storage::Error) -> Error {
    match error {
        storage::Error::Reliable(error) => error,
        storage::Error::Recovery(l2tunnel_recovery::storage::Error::Recovery(error)) => {
            Error::Arq(error)
        }
        storage::Error::Allocation
        | storage::Error::Recovery(l2tunnel_recovery::storage::Error::Allocation) => {
            Error::Allocation
        }
        _ => Error::InvalidConfig,
    }
}
pub(super) fn inspect_compact_view<'a>(
    packet: &'a [u8],
    maximum: usize,
    source: CompactArqConfig,
    feedback: CompactArqConfig,
    context: RecoveryContext,
) -> Result<StructuralRecord<'a>, Error> {
    let (kind, inner) = envelope(packet, maximum)?;
    if kind != 1 && kind != 2 {
        return Err(Error::Malformed);
    }
    let mut value = StructuralRecord {
        sender: opposite_context(context),
        kind: RecordKind::Feedback,
        source: None,
        fec: None,
    };
    match (
        kind,
        inspect_compact_packet(inner, context, if kind == 1 { source } else { feedback })?,
    ) {
        (
            1,
            CompactPacketView::Data {
                source, payload, ..
            },
        ) => {
            value.kind = RecordKind::Source;
            value.source = Some((source, payload));
        }
        (2, CompactPacketView::Feedback(_)) => {}
        _ => return Err(Error::Malformed),
    }
    Ok(value)
}
/// Observe selected v2 record structure; this authenticates no sender or receipt.
/// Source and feedback policies are complete independent data-direction policies.
pub fn inspect_compact_structural(
    packet: &[u8],
    sender: EndpointRole,
    maximum_packet: usize,
    source: CompactArqConfig,
    feedback: CompactArqConfig,
) -> Result<StructuralRecord<'_>, Error> {
    if !(1..=65_507).contains(&maximum_packet) {
        return Err(Error::InvalidConfig);
    }
    source.validate()?;
    feedback.validate()?;
    let (_, inner) = envelope(packet, maximum_packet)?;
    let context = RecoveryContext {
        session: u128::from_be_bytes(
            inner
                .get(8..24)
                .ok_or(Error::Malformed)?
                .try_into()
                .map_err(|_| Error::Malformed)?,
        ),
        epoch: u64::from_be_bytes(
            inner
                .get(24..32)
                .ok_or(Error::Malformed)?
                .try_into()
                .map_err(|_| Error::Malformed)?,
        ),
        role: sender,
    };
    inspect_compact_view(
        packet,
        maximum_packet,
        source,
        feedback,
        opposite_context(context),
    )
}
