//! Bounded real-payload systematic block FEC with selective-repeat fallback.
//!
//! Enclosing authentication/replay, negotiated budgets and congestion control
//! belong to the caller. Every emitted copy consumes an explicit wire allowance.
use l2tunnel_fec as fec;
use l2tunnel_recovery::{
    ACK_PACKET_BYTES, ArqConfig, DATA_HEADER_BYTES, EndpointRole, PacketView, PhysicalTransmission,
    RecoveryContext, RecoveryEngine, RecoveryError, Retained, SelectiveRepeat,
    Statistics as ArqStatistics, inspect_packet,
};
mod backing;
mod compact;
mod recovery_owner;
mod selected_wire;
mod wire_extent;
pub use compact::{
    CompactOutput, CompactOutputError, CompactOverheads, CompactReliableConfig,
    inspect_compact_structural,
};
pub use wire_extent::RecoveryExtent;
pub mod diagnostics;
mod legacy_layout;
pub mod storage;
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

// Local output custody only; this identity never enters the wire or crypto.
static NEXT_PHYSICAL_OWNER: AtomicU64 = AtomicU64::new(1);

/// Reliable envelope bytes preceding a strict ARQ or FEC packet.
pub const ENVELOPE_BYTES: usize = 8;
/// Hard restored-source staging count, independent of payload-byte capacity.
pub const MAX_RESTORED_PACKETS: usize = 256;
/// Hard restored-source payload storage, including complete ARQ record headers.
pub const MAX_RESTORED_BYTES: usize = 4 * 1024 * 1024;

/// Previously negotiated limits for one bidirectional reliable coding domain.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReliableConfig {
    /// Real source identity, retention, receiver window and timeout policy.
    pub arq: ArqConfig,
    /// Receiver coding limits; block.max_sources is also the sending block target.
    pub fec: fec::DecoderConfig,
    /// Cauchy repairs for a full block; zero selects direct selective repeat
    /// without block collection, coding state or a partial-flush delay.
    pub repair_symbols: usize,
    /// Positive maximum partial-block age, shorter than ARQ's initial RTO.
    pub flush_after: Duration,
    /// Exact-source staging slots, at least one send window plus one FEC block.
    pub max_restored_packets: usize,
    /// Bytes for staged complete ARQ source records, including their headers.
    pub max_restored_bytes: usize,
    /// Per-emission protection/underlay bytes charged outside this envelope.
    pub outer_overhead_bytes: usize,
}

/// Caller-owned common transmission allowance for ACKs, sources and repairs.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct OutboundBudget {
    /// Remaining outer packet emissions, including feedback and retransmissions.
    pub packets: usize,
    /// Remaining actual wire bytes including configured outer overhead.
    pub wire_bytes: usize,
}

/// Strictly validated record classification for carrier routing.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecordKind {
    /// Direct ARQ source copy retaining its original logical identity.
    Source,
    /// Direct bounded ARQ receipt feedback, suitable for a retained control lane.
    Feedback,
    /// FEC systematic vector exposing one complete original ARQ record.
    Systematic,
    /// Real encoded FEC repair equation.
    Repair,
}

/// One exact caller-held output awaiting whole-carrier acceptance.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PreparedOutput {
    instance: u64,
    serial: u64,
    transmission: Option<PhysicalTransmission>,
    prepared_at: Duration,
    /// Exact initialized bytes in the selected output representation: a legacy
    /// Reliable packet, or a context-free algorithm body from typed polling.
    pub bytes: usize,
    /// Already reserved complete wire charge, including outer overhead once.
    pub wire_bytes: usize,
    /// Actual maintained-parser classification of this emitted record.
    pub kind: RecordKind,
}

/// Borrowed structural inspection, with no authentication, replay or recovery admission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StructuralRecord<'a> {
    /// Observed logical session/epoch and expected original sender role.
    pub sender: RecoveryContext,
    /// Canonically validated envelope and nested packet classification.
    pub kind: RecordKind,
    /// Exact original source for direct/systematic records; absent for feedback/repair.
    pub source: Option<(l2tunnel_recovery::SourceId, &'a [u8])>,
    /// Validated borrowed FEC vector/equation when the envelope carries FEC.
    pub fec: Option<fec::SymbolView<'a>>,
}

/// Observe untrusted context, then use the maintained exact envelope/ARQ/FEC parsers.
/// The supplied sender role and finite negotiated geometry remain mandatory.
/// This allocates no engine, verifies no tag and admits no source; never substitute
/// it for authenticated runtime ingress. FEC repairs expose no restored source.
pub fn inspect_structural(
    packet: &[u8],
    sender: EndpointRole,
    maximum_packet: usize,
    max_source_bytes: usize,
    block: fec::BlockConfig,
) -> Result<StructuralRecord<'_>, Error> {
    if !(1..=65_507).contains(&maximum_packet) || !(1..=65_535).contains(&max_source_bytes) {
        return Err(Error::InvalidConfig);
    }
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
    inspect_record_view(
        packet,
        maximum_packet,
        max_source_bytes,
        block,
        opposite_context(context),
        fec_context(context, false),
    )
}

fn inspect_record_view(
    packet: &[u8],
    maximum_packet: usize,
    max_source_bytes: usize,
    block: fec::BlockConfig,
    arq_context: RecoveryContext,
    fec_context: fec::FecContext,
) -> Result<StructuralRecord<'_>, Error> {
    let (kind, inner) = envelope(packet, maximum_packet)?;
    let mut value = StructuralRecord {
        sender: opposite_context(arq_context),
        kind: RecordKind::Feedback,
        source: None,
        fec: None,
    };
    match kind {
        1 | 2 => match inspect_packet(inner, arq_context, max_source_bytes)? {
            PacketView::Data { source, payload } if kind == 1 => {
                value.kind = RecordKind::Source;
                value.source = Some((source, payload));
            }
            PacketView::Ack { .. } if kind == 2 => {}
            _ => return Err(Error::Malformed),
        },
        3 => {
            let symbol = fec::inspect(inner, fec_context, block)?;
            if symbol.kind == fec::SymbolKind::Systematic {
                let length = usize::from(u16::from_be_bytes(
                    symbol
                        .payload
                        .get(..2)
                        .ok_or(Error::Malformed)?
                        .try_into()
                        .map_err(|_| Error::Malformed)?,
                ));
                let source = symbol.payload.get(2..2 + length).ok_or(Error::Malformed)?;
                let PacketView::Data { source, payload } =
                    inspect_packet(source, arq_context, max_source_bytes)?
                else {
                    return Err(Error::Malformed);
                };
                value.kind = RecordKind::Systematic;
                value.source = Some((source, payload));
            } else {
                value.kind = RecordKind::Repair;
            }
            value.fec = Some(symbol);
        }
        _ => return Err(Error::Malformed),
    }
    Ok(value)
}

/// Explicit configuration, backpressure or fail-closed protocol error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// Contradictory or excessive composition limits.
    InvalidConfig,
    /// Selected fallible backing reservation failed.
    Allocation,
    /// Unknown/noncanonical reliable envelope or unexpected inner packet kind.
    Malformed,
    /// Restored-source byte/count headroom is full; the new input was not admitted.
    RestoredCapacity,
    /// Same restored identity differs, or a decoded block is not a contiguous source list.
    SourceConflict,
    /// Caller output cannot hold the configured maximum complete reliable packet.
    OutputTooSmall {
        /// Required caller-buffer capacity.
        required: usize,
    },
    /// Monotonic time moved backwards.
    NonMonotonicTime,
    /// Duration or millisecond deadline arithmetic cannot continue.
    TimeOverflow,
    /// Generation or source/wire arithmetic cannot continue without a new context.
    Exhausted,
    /// Underlying selective-repeat error; retry exhaustion is terminal.
    Arq(RecoveryError),
    /// Malformed or conflicting coding input; authenticated protocol failures are terminal.
    Fec(fec::Error),
    /// No matching exact caller-held physical output belongs to this owner.
    OutputToken,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "reliable block error: {self:?}")
    }
}
impl std::error::Error for Error {}
impl From<RecoveryError> for Error {
    fn from(value: RecoveryError) -> Self {
        Self::Arq(value)
    }
}
impl From<fec::Error> for Error {
    fn from(value: fec::Error) -> Self {
        Self::Fec(value)
    }
}

/// Saturating observations; none controls admission or changes protocol decisions.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Statistics {
    /// Complete reliable packets emitted into caller ownership.
    pub emitted_packets: u64,
    /// Actual charged bytes including the configured external overhead.
    pub emitted_wire_bytes: u64,
    /// Emitted FEC systematic packets.
    pub systematic_packets: u64,
    /// First transmissions of direct ARQ-only sources, excluding timeout retries.
    pub source_packets: u64,
    /// Emitted Cauchy repair packets.
    pub repair_packets: u64,
    /// Emitted direct ARQ timeout retry packets.
    pub retry_packets: u64,
    /// Emitted direct ARQ feedback packets.
    pub feedback_packets: u64,
    /// Completed decoded source vectors, including redundant already-known sources.
    pub decoded_source_vectors: u64,
    /// New ARQ sources actually admitted from full-block reconstruction.
    pub repaired_unique_sources: u64,
    /// Optional FEC packets skipped because of bounded/expired/terminal coding state.
    pub skipped_fec_packets: u64,
    /// Incomplete or undelivered coding generations explicitly expired.
    pub expired_generations: u64,
}

/// Bounded storage observations, separate from cryptographic or logical-flow credit.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Storage {
    /// Underlying source payload/count retention.
    pub arq: Retained,
    /// Complete encoded ARQ sources in the partial outgoing block.
    pub building_packets: usize,
    /// Bytes in that partial block.
    pub building_bytes: usize,
    /// Sealed reliable output packets waiting for common wire allowance.
    pub outbound_packets: usize,
    /// Exact reliable output bytes waiting for transmission, excluding outer headers.
    pub outbound_bytes: usize,
    /// Recovered/source records awaiting bounded ARQ admission.
    pub restored_packets: usize,
    /// Complete ARQ bytes in restored staging.
    pub restored_bytes: usize,
    /// Current live-generation logical reservation; neither configured capacity nor allocated backing.
    pub fec_reserved_bytes: usize,
    /// Actual Block/Direct ARQ staging bounds and decoder gauges. Compact ARQ
    /// constructs none of these block pools, so its value is absent.
    pub block: Option<diagnostics::Buffers>,
}

#[derive(Clone, Copy)]
enum OutputScope {
    Combined,
    Data,
    Feedback,
}

#[derive(Clone, Copy)]
enum Emission {
    Source,
    Systematic,
    Repair,
    Retry,
    Feedback,
}
struct Outgoing {
    bytes: Vec<u8>,
    emission: Emission,
}
struct Restored {
    bytes: Vec<u8>,
    recovered: bool,
}

/// One independently owned reliable block endpoint with no socket or system clock.
pub struct Reliable {
    policies: compact::Policies,
    context: RecoveryContext,
    arq: recovery_owner::Owner,
    decoder: Option<fec::Decoder>,
    send_fec: fec::FecContext,
    receive_fec: fec::FecContext,
    building: backing::Building,
    building_deadline: Option<Duration>,
    next_fresh_source: u64,
    next_generation: Option<fec::GenerationId>,
    outgoing: backing::Queue,
    restored: backing::RestoredMap,
    restored_bytes: usize,
    fec_deadlines: backing::Deadlines,
    encoder: Option<fec::BlockEncoder>,
    expired: Vec<fec::ExpiredGeneration>,
    usage: Option<storage::Usage>,
    scratch: Vec<u8>,
    maximum_packet: usize,
    receive_maximum_packet: usize,
    prefer_feedback: bool,
    now: Duration,
    failure: Option<Error>,
    statistics: Statistics,
    physical_instance: Option<u64>,
    next_output: u64,
    pending_output: Option<PreparedOutput>,
    independent_feedback: Option<PreparedOutput>,
    compact_wire: Option<CompactOverheads>,
    // Opt-in fixed sidecar, reserved in the original construction plan.
    diagnostics: Vec<diagnostics::Snapshot>,
}

impl ReliableConfig {
    /// Exact maximum actual inner output after validating the complete policy.
    /// This excludes configured outer overhead and allocates no protocol owner.
    pub fn maximum_packet_bytes(self) -> Result<usize, Error> {
        self.maximum_packet()
    }

    /// Validate complete geometry and limits without constructing any engine.
    pub fn validate(self) -> Result<(), Error> {
        self.maximum_packet().map(|_| ())
    }

    fn maximum_packet(self) -> Result<usize, Error> {
        let config = self;
        config.arq.validate()?;
        let count = config.fec.block.max_sources;
        let source_bytes = DATA_HEADER_BYTES
            .checked_add(config.arq.max_source_bytes)
            .ok_or(Error::InvalidConfig)?;
        let width = source_bytes.checked_add(2).ok_or(Error::InvalidConfig)?;
        let symbols = count
            .checked_add(config.repair_symbols)
            .ok_or(Error::InvalidConfig)?;
        let fec_packet = fec::HEADER_BYTES
            .checked_add(count)
            .and_then(|n| n.checked_add(width))
            .ok_or(Error::InvalidConfig)?;
        let maximum_packet = fec_packet
            .checked_add(ENVELOPE_BYTES)
            .ok_or(Error::InvalidConfig)?;
        let restore_min = config
            .arq
            .send_records
            .checked_add(count)
            .ok_or(Error::InvalidConfig)?;
        let work = count
            .checked_mul(2)
            .and_then(|n| n.checked_add(1))
            .and_then(|n| n.checked_mul(count.checked_add(width)?))
            .and_then(|n| n.checked_add(16))
            .ok_or(Error::InvalidConfig)?;
        let reservation = count
            .checked_mul(3)
            .and_then(|n| n.checked_add(config.fec.max_symbols_per_generation))
            .and_then(|n| n.checked_mul(count.checked_add(width)?))
            .ok_or(Error::InvalidConfig)?;
        if count == 0
            || count > config.arq.send_records
            || count > config.arq.receive_records
            || config.arq.send_records > config.arq.receive_records
            || symbols > 256
            || config.fec.block.max_source_bytes != source_bytes
            || source_bytes > fec::MAX_SOURCE_BYTES
            || config.fec.block.max_packet_bytes < fec_packet
            || config.fec.block.max_packet_bytes > 65_507 - ENVELOPE_BYTES
            || work as u64 > config.fec.block.max_work_per_symbol
            || reservation > config.fec.max_reserved_bytes
            || config.fec.max_symbols_per_generation < symbols
            || config.flush_after.is_zero()
            || config.flush_after >= config.arq.initial_rto
            || !(restore_min..=MAX_RESTORED_PACKETS).contains(&config.max_restored_packets)
            || config.max_restored_bytes
                < config
                    .max_restored_packets
                    .checked_mul(source_bytes)
                    .ok_or(Error::InvalidConfig)?
            || config.max_restored_bytes > MAX_RESTORED_BYTES
            || config.outer_overhead_bytes > 65_535
        {
            return Err(Error::InvalidConfig);
        }
        config.fec.validate()?;
        if config.repair_symbols == 0 {
            ENVELOPE_BYTES
                .checked_add(source_bytes.max(ACK_PACKET_BYTES))
                .ok_or(Error::InvalidConfig)
        } else {
            Ok(maximum_packet)
        }
    }
}

impl Reliable {
    /// Compatibility-only pre-RRS inline layout for the existing codec scalar
    /// acceptance gate. This is not actual reserved capacity or Usage; enclosing
    /// storage plans must charge the current real `size_of::<Reliable>()`.
    pub const fn legacy_inline_bytes() -> usize {
        legacy_layout::reliable_bytes()
    }

    /// Validate canonical cross-module limits before constructing bounded state.
    pub fn new(config: ReliableConfig, context: RecoveryContext) -> Result<Self, Error> {
        Self::new_duplex(config, config, context)
    }

    /// Construct one actual owner with complete independent data-direction policies.
    pub fn new_duplex(
        config: ReliableConfig,
        receive_config: ReliableConfig,
        context: RecoveryContext,
    ) -> Result<Self, Error> {
        let maximum_packet = config.maximum_packet()?;
        let receive_maximum_packet = receive_config.maximum_packet()?;
        let count = if config.repair_symbols == 0 {
            0
        } else {
            config.fec.block.max_sources
        };
        let symbols = count
            .checked_add(config.repair_symbols)
            .ok_or(Error::InvalidConfig)?;
        let arq = SelectiveRepeat::new_duplex(config.arq, receive_config.arq, context)?;
        let send_fec = fec_context(context, false);
        let receive_fec = fec_context(context, true);
        let decoder = if receive_config.repair_symbols == 0 {
            None
        } else {
            Some(fec::Decoder::new(receive_fec, receive_config.fec)?)
        };
        let scratch = vec![0; arq.send_max_packet_bytes()];
        Ok(Self {
            policies: compact::Policies::Legacy {
                send: config,
                receive: receive_config,
            },
            context,
            arq: recovery_owner::Owner::Legacy(arq),
            decoder,
            send_fec,
            receive_fec,
            building: backing::Building::legacy(count),
            building_deadline: None,
            next_fresh_source: 0,
            next_generation: Some(fec::GenerationId(0)),
            outgoing: backing::Queue::legacy(symbols),
            restored: backing::RestoredMap::legacy(),
            restored_bytes: 0,
            fec_deadlines: backing::Deadlines::legacy(),
            encoder: None,
            expired: Vec::new(),
            usage: None,
            scratch,
            maximum_packet,
            receive_maximum_packet,
            prefer_feedback: true,
            now: Duration::ZERO,
            failure: None,
            statistics: Statistics::default(),
            physical_instance: None,
            next_output: 1,
            pending_output: None,
            independent_feedback: None,
            compact_wire: None,
            diagnostics: Vec::new(),
        })
    }

    /// Provision every actual nested and wrapper owner before publication.
    pub fn new_duplex_reserved(
        config: ReliableConfig,
        receive_config: ReliableConfig,
        context: RecoveryContext,
        limits: storage::Limits,
    ) -> Result<Self, storage::Error> {
        Self::new_reserved_with_plan(
            storage::Plan::for_duplex(config, receive_config)?,
            context,
            limits,
        )
    }
    /// Construct the exact validated plan, including optional pre-admitted diagnostics.
    pub fn new_reserved_with_plan(
        plan: storage::Plan,
        context: RecoveryContext,
        limits: storage::Limits,
    ) -> Result<Self, storage::Error> {
        if plan.capacity_bytes() > limits.capacity_bytes {
            return Err(storage::Error::Limit {
                required: plan.capacity_bytes(),
                limit: limits.capacity_bytes,
            });
        }
        let mut allocation = storage::Allocation::new(limits.capacity_bytes);
        Self::reserved_with(
            plan.send_config(),
            plan.receive_config(),
            context,
            plan,
            &mut allocation,
        )
    }
    pub(crate) fn reserved_with(
        config: ReliableConfig,
        receive_config: ReliableConfig,
        context: RecoveryContext,
        plan: storage::Plan,
        a: &mut storage::Allocation,
    ) -> Result<Self, storage::Error> {
        let arq = SelectiveRepeat::new_duplex_reserved(
            config.arq,
            receive_config.arq,
            context,
            l2tunnel_recovery::storage::Limits {
                capacity_bytes: plan.arq.capacity_bytes(),
            },
        )
        .map_err(storage::Error::Recovery)?;
        let send_fec = fec_context(context, false);
        let receive_fec = fec_context(context, true);
        let encoder = plan
            .encoder
            .map(|p| {
                fec::BlockEncoder::new_reserved(
                    send_fec,
                    config.fec.block,
                    fec::storage::Limits {
                        capacity_bytes: p.capacity_bytes(),
                    },
                )
            })
            .transpose()
            .map_err(storage::Error::Fec)?;
        let decoder = plan
            .decoder
            .map(|p| {
                fec::Decoder::new_reserved(
                    receive_fec,
                    receive_config.fec,
                    fec::storage::Limits {
                        capacity_bytes: p.capacity_bytes(),
                    },
                )
            })
            .transpose()
            .map_err(storage::Error::Fec)?;
        let arq_usage = arq.storage_usage().ok_or(storage::Error::Invariant)?;
        let encoder_usage = encoder
            .as_ref()
            .map(|e| e.storage_usage().ok_or(storage::Error::Invariant))
            .transpose()?;
        let decoder_usage = decoder
            .as_ref()
            .map(|e| e.storage_usage().ok_or(storage::Error::Invariant))
            .transpose()?;
        if arq_usage.capacity_bytes != plan.arq.capacity_bytes()
            || encoder_usage.map_or(0, |u| u.capacity_bytes)
                != plan.encoder.map_or(0, |p| p.capacity_bytes())
            || decoder_usage.map_or(0, |u| u.capacity_bytes)
                != plan.decoder.map_or(0, |p| p.capacity_bytes())
        {
            return Err(storage::Error::Invariant);
        }
        let maximum_packet = config.maximum_packet().map_err(storage::Error::Reliable)?;
        let receive_maximum_packet = receive_config
            .maximum_packet()
            .map_err(storage::Error::Reliable)?;
        let sources = plan.encoder.map_or(0, |_| config.fec.block.max_sources);
        let generations = plan
            .decoder
            .map_or(0, |_| receive_config.fec.max_generations);
        let building = backing::Building::reserved(
            sources,
            DATA_HEADER_BYTES + config.arq.max_source_bytes,
            a,
        )?;
        let outgoing =
            backing::Queue::reserved(sources + config.repair_symbols, maximum_packet, a)?;
        let restored = backing::RestoredMap::reserved(
            receive_config.max_restored_packets,
            DATA_HEADER_BYTES + receive_config.arq.max_source_bytes,
            a,
        )?;
        let fec_deadlines = backing::Deadlines::reserved(generations, a)?;
        let expired = backing::expired(generations, a)?;
        let mut scratch = a.vec(arq.send_max_packet_bytes())?;
        scratch.resize(arq.send_max_packet_bytes(), 0);
        let mut diagnostics = a.vec::<diagnostics::Snapshot>(usize::from(plan.diagnostics))?;
        if plan.diagnostics {
            diagnostics.push(diagnostics::Snapshot::new(context, encoder.is_some()));
        }
        let wrapper = a.usage();
        let bytes = storage::add(
            wrapper.capacity_bytes,
            storage::add(
                arq_usage.capacity_bytes,
                storage::add(
                    encoder_usage.map_or(0, |u| u.capacity_bytes),
                    decoder_usage.map_or(0, |u| u.capacity_bytes),
                )?,
            )?,
        )?;
        let allocations = storage::add(
            wrapper.allocations,
            storage::add(
                arq_usage.allocations,
                storage::add(
                    encoder_usage.map_or(0, |u| u.allocations),
                    decoder_usage.map_or(0, |u| u.allocations),
                )?,
            )?,
        )?;
        if bytes != plan.capacity_bytes() {
            return Err(storage::Error::Invariant);
        }
        let usage = storage::Usage {
            limit_bytes: wrapper.limit_bytes,
            capacity_bytes: bytes,
            allocations,
        };
        Ok(Self {
            policies: compact::Policies::Legacy {
                send: config,
                receive: receive_config,
            },
            context,
            arq: recovery_owner::Owner::Legacy(arq),
            decoder,
            send_fec,
            receive_fec,
            building,
            building_deadline: None,
            next_fresh_source: 0,
            next_generation: Some(fec::GenerationId(0)),
            outgoing,
            restored,
            restored_bytes: 0,
            fec_deadlines,
            encoder,
            expired,
            usage: Some(usage),
            scratch,
            maximum_packet,
            receive_maximum_packet,
            prefer_feedback: true,
            now: Duration::ZERO,
            failure: None,
            statistics: Statistics::default(),
            physical_instance: None,
            next_output: 1,
            pending_output: None,
            independent_feedback: None,
            compact_wire: None,
            diagnostics,
        })
    }
    /// Select physical-attempt timing before any local/peer traffic is used.
    /// Existing constructors retain their original poll-time handoff semantics.
    pub fn enable_physical_send_confirmation(&mut self) -> Result<(), Error> {
        self.running()?;
        if self.physical_instance.is_some()
            || self.now != Duration::ZERO
            || self.next_fresh_source != 0
            || self.statistics != Statistics::default()
            || !self.building.is_empty()
            || !self.outgoing.is_empty()
            || !self.restored.is_empty()
        {
            return Err(Error::InvalidConfig);
        }
        let instance = NEXT_PHYSICAL_OWNER
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                value.checked_add(1)
            })
            .map_err(|_| Error::Exhausted)?;
        self.arq.enable_physical_send_confirmation()?;
        self.physical_instance = Some(instance);
        Ok(())
    }
    /// Observe exact output custody, including after an unrelated terminal error.
    pub fn pending_output(&self) -> Option<PreparedOutput> {
        self.pending_output.or(self.independent_feedback)
    }
    /// Exact main-lane custody. Legacy combined polling may put feedback here.
    /// Independently prepared feedback never occupies this slot.
    pub fn pending_data_output(&self) -> Option<PreparedOutput> {
        self.pending_output
    }
    /// Exact independently prepared feedback, without borrowing data custody.
    pub fn pending_feedback_output(&self) -> Option<PreparedOutput> {
        self.independent_feedback.or(self
            .pending_output
            .filter(|output| output.kind == RecordKind::Feedback))
    }
    /// Consume one exact whole-carrier observation before later timing checks.
    /// Wrong, foreign and repeated witnesses cannot mutate time or another flight.
    pub fn confirm_output(&mut self, now: Duration, output: PreparedOutput) -> Result<(), Error> {
        self.confirm_output_at(now, now, output)
    }
    /// Separate the actual whole-write instant from later receipt observation.
    /// The accepted instant must lie within this output's original custody span.
    pub fn confirm_output_at(
        &mut self,
        observed: Duration,
        accepted: Duration,
        output: PreparedOutput,
    ) -> Result<(), Error> {
        if self.pending_output == Some(output) {
            self.pending_output = None;
        } else if self.independent_feedback == Some(output) {
            self.independent_feedback = None;
        } else {
            return Err(Error::OutputToken);
        }
        let prior = self.failure();
        let window = if accepted < output.prepared_at || accepted > observed {
            Err(Error::NonMonotonicTime)
        } else {
            Ok(())
        };
        let physical = if let Some(transmission) = output.transmission {
            self.arq
                .confirm_transmission_at(observed, accepted, transmission)
                .map_err(Error::Arq)
        } else {
            Ok(())
        };
        let timing = self
            .check_time(observed)
            .and_then(|()| self.advance(observed));
        if let Some(error) = prior {
            return Err(error);
        }
        window
            .and(physical)
            .and(timing)
            .or_else(|error| self.fail(error))
    }
    /// Actual complete backing, including idle nested and wrapper storage.
    pub fn storage_usage(&self) -> Option<storage::Usage> {
        self.usage
    }

    /// Read the authoritative ARQ source allocator without consuming an identity.
    /// The snapshot expires at this exclusive owner's next successful submit.
    pub fn next_source_id(&self) -> Result<u64, Error> {
        self.running()?;
        if !self.arq.is_compact() && self.next_generation.is_none() {
            return Err(Error::Exhausted);
        }
        Ok(self.arq.next_source_id()?.0)
    }

    /// Admit exactly one new logical source; repairs/retries never call this method.
    pub fn submit(&mut self, source: &[u8], now: Duration) -> Result<u64, Error> {
        self.check_time(now)?;
        if !self.arq.is_compact() && self.next_generation.is_none() {
            return Err(Error::Exhausted);
        }
        let source = self.arq.submit(source, now)?;
        self.now = now;
        Ok(source)
    }

    /// Consume one complete record after lower-layer integrity and replay checks.
    /// Resource pressure is retryable; malformed authenticated protocol input fails closed.
    pub fn receive(&mut self, packet: &[u8], now: Duration) -> Result<(), Error> {
        self.receive_at(packet, now, now)
    }
    fn receive_legacy(&mut self, packet: &[u8], now: Duration) -> Result<(), Error> {
        self.check_time(now)?;
        let (kind, inner) = match envelope(packet, self.receive_maximum_packet) {
            Ok(view) => view,
            Err(error) => return self.fail(error),
        };
        match kind {
            1 => {
                self.source_id(inner).or_else(|error| self.fail(error))?;
                self.ensure_restored(1, inner.len(), now)?;
                self.advance(now)?;
                self.enqueue(inner, false)?;
                self.pump()?;
            }
            2 => {
                match inspect_packet(
                    inner,
                    self.context,
                    self.legacy_send()?.arq.max_source_bytes,
                ) {
                    Ok(PacketView::Ack { .. }) => {}
                    Ok(_) => return self.fail(Error::Malformed),
                    Err(error) => return self.fail(error.into()),
                }
                self.arq
                    .receive(inner, now)
                    .or_else(|error| self.fail(error.into()))?;
                self.advance(now)?;
            }
            3 if self.legacy_receive()?.repair_symbols != 0 => self.receive_fec(inner, now)?,
            _ => return self.fail(Error::Malformed),
        }
        Ok(())
    }

    /// Emit at most one record under a common mandatory packet/byte allowance.
    /// Caller output is unchanged when no packet is emitted or an error is returned.
    pub fn poll(
        &mut self,
        now: Duration,
        output: &mut [u8],
        budget: &mut OutboundBudget,
    ) -> Result<Option<usize>, Error> {
        self.poll_selected(now, output, budget, true, true)
    }

    /// Emit due feedback only, charging the same common allowance as user copies.
    /// This does not collect, seal or transmit an outgoing source generation.
    pub fn poll_feedback(
        &mut self,
        now: Duration,
        output: &mut [u8],
        budget: &mut OutboundBudget,
    ) -> Result<Option<usize>, Error> {
        self.poll_selected(now, output, budget, true, false)
    }

    /// Emit feedback through its own one-slot physical custody while a data or
    /// repair output is held by a backpressured carrier. The same ARQ encoder,
    /// clock and wire budget remain authoritative. Existing polling methods
    /// retain their original single-output behavior. Physical mode is required.
    pub fn poll_feedback_independent(
        &mut self,
        now: Duration,
        output: &mut [u8],
        budget: &mut OutboundBudget,
    ) -> Result<Option<usize>, Error> {
        if self.physical_instance.is_none() {
            return Err(Error::InvalidConfig);
        }
        self.poll_selected_scoped(now, output, budget, true, false, OutputScope::Feedback)
    }

    /// Emit a systematic, repair or original-ID retry while retaining due feedback.
    /// The caller must service feedback separately with a bounded shared allowance.
    pub fn poll_data(
        &mut self,
        now: Duration,
        output: &mut [u8],
        budget: &mut OutboundBudget,
    ) -> Result<Option<usize>, Error> {
        self.poll_selected(now, output, budget, false, true)
    }

    /// Emit through the existing main output slot while independently held
    /// feedback retains its separate exact witness. Legacy poll/poll_data keep
    /// their original combined-slot gate; physical mode is mandatory here.
    pub fn poll_data_independent(
        &mut self,
        now: Duration,
        output: &mut [u8],
        budget: &mut OutboundBudget,
    ) -> Result<Option<usize>, Error> {
        if self.physical_instance.is_none() {
            return Err(Error::InvalidConfig);
        }
        self.poll_selected_scoped(now, output, budget, false, true, OutputScope::Data)
    }

    /// Observe actual peer ARQ receipt for an allocated source. Physical output
    /// alone is never confirmation; a held retry may still own its exact bytes.
    pub fn source_confirmed(&self, source: l2tunnel_recovery::SourceId) -> Result<bool, Error> {
        self.running()?;
        Ok(self.arq.source_confirmed(source)?)
    }

    /// Confirmed source with no remaining exact physical retry custody.
    pub fn source_retired(&self, source: l2tunnel_recovery::SourceId) -> Result<bool, Error> {
        Ok(self.source_confirmed(source)? && self.arq.pending_transmission(source).is_none())
    }

    /// Inspect the actual source identity with the maintained output grammar.
    /// This is structural observation, never an authentication or receipt proof.
    pub fn inspect_output_source(
        &self,
        packet: &[u8],
    ) -> Result<Option<l2tunnel_recovery::SourceId>, Error> {
        let view = if self.compact_wire.is_some() {
            self.selected_inspect(packet, true)?
        } else if self.arq.is_compact() {
            self.compact_inspect(packet, true)?
        } else {
            inspect_record_view(
                packet,
                self.maximum_packet,
                self.legacy_send()?.arq.max_source_bytes,
                self.legacy_send()?.fec.block,
                opposite_context(self.context),
                self.send_fec,
            )?
        };
        Ok(view.source.map(|(source, _)| source))
    }

    /// Classify a complete outgoing record with the authoritative inner parsers.
    /// This checks local sending role/session/epoch and all encoding bounds; it
    /// neither authenticates bytes nor advances sender/receiver state.
    pub fn inspect_output(&self, packet: &[u8]) -> Result<RecordKind, Error> {
        if self.compact_wire.is_some() {
            return self.selected_inspect(packet, true).map(|view| view.kind);
        }
        if self.arq.is_compact() {
            return self.compact_inspect(packet, true).map(|view| view.kind);
        }
        self.inspect_record(
            packet,
            opposite_context(self.context),
            self.send_fec,
            *self.legacy_send()?,
            self.maximum_packet,
        )
    }

    /// Classify one authenticated peer record without mutating recovery state.
    /// This uses the receiving role/session/epoch and authoritative inner parsers,
    /// allowing callers to reject feedback on data lanes or data on control lanes.
    /// Lower-layer integrity/replay verification must precede this operation.
    pub fn inspect_peer(&self, packet: &[u8]) -> Result<RecordKind, Error> {
        if self.compact_wire.is_some() {
            return self.selected_inspect(packet, false).map(|view| view.kind);
        }
        if self.arq.is_compact() {
            return self.compact_inspect(packet, false).map(|view| view.kind);
        }
        self.inspect_record(
            packet,
            self.context,
            self.receive_fec,
            *self.legacy_receive()?,
            self.receive_maximum_packet,
        )
    }

    fn inspect_record(
        &self,
        packet: &[u8],
        arq_context: RecoveryContext,
        fec_context: fec::FecContext,
        config: ReliableConfig,
        maximum_packet: usize,
    ) -> Result<RecordKind, Error> {
        let view = inspect_record_view(
            packet,
            maximum_packet,
            config.arq.max_source_bytes,
            config.fec.block,
            arq_context,
            fec_context,
        )?;
        if config.repair_symbols == 0 && view.fec.is_some() {
            return Err(Error::Malformed);
        }
        Ok(view.kind)
    }

    fn poll_selected(
        &mut self,
        now: Duration,
        output: &mut [u8],
        budget: &mut OutboundBudget,
        allow_feedback: bool,
        allow_data: bool,
    ) -> Result<Option<usize>, Error> {
        self.poll_selected_scoped(
            now,
            output,
            budget,
            allow_feedback,
            allow_data,
            OutputScope::Combined,
        )
    }

    fn poll_selected_scoped(
        &mut self,
        now: Duration,
        output: &mut [u8],
        budget: &mut OutboundBudget,
        allow_feedback: bool,
        allow_data: bool,
        scope: OutputScope,
    ) -> Result<Option<usize>, Error> {
        let Some(instance) = self.physical_instance else {
            return self.poll_selected_inner(now, output, budget, allow_feedback, allow_data);
        };
        let blocked = match scope {
            OutputScope::Feedback => self.pending_feedback_output().is_some(),
            OutputScope::Data => self.pending_data_output().is_some(),
            OutputScope::Combined => self.pending_output().is_some(),
        };
        if blocked {
            self.check_time(now)?;
            self.advance(now)?;
            self.pump()?;
            return Ok(None);
        }
        self.running()?;
        let next = self
            .next_output
            .checked_add(1)
            .ok_or(Error::Exhausted)
            .or_else(|error| self.fail(error))?;
        let Some(bytes) =
            self.poll_selected_inner(now, output, budget, allow_feedback, allow_data)?
        else {
            return Ok(None);
        };
        let view = if self.compact_wire.is_some() {
            self.selected_inspect(&output[..bytes], true)
        } else if self.arq.is_compact() {
            self.compact_inspect(&output[..bytes], true)
        } else {
            inspect_record_view(
                &output[..bytes],
                self.maximum_packet,
                self.legacy_send()?.arq.max_source_bytes,
                self.legacy_send()?.fec.block,
                opposite_context(self.context),
                self.send_fec,
            )
        }
        .or_else(|error| self.fail(error))?;
        let transmission = if let Some((source, _)) = view.source {
            Some(
                self.arq
                    .pending_transmission(source)
                    .ok_or(Error::OutputToken)
                    .or_else(|error| self.fail(error))?,
            )
        } else {
            None
        };
        let prepared = PreparedOutput {
            instance,
            serial: self.next_output,
            transmission,
            prepared_at: now,
            bytes,
            wire_bytes: bytes
                .checked_add(self.selected_overhead(view.kind))
                .ok_or(Error::Exhausted)?,
            kind: view.kind,
        };
        if matches!(scope, OutputScope::Feedback) {
            if prepared.kind != RecordKind::Feedback {
                return self.fail(Error::OutputToken);
            }
            self.independent_feedback = Some(prepared);
        } else {
            self.pending_output = Some(prepared);
        }
        self.next_output = next;
        Ok(Some(bytes))
    }

    fn poll_selected_inner(
        &mut self,
        now: Duration,
        output: &mut [u8],
        budget: &mut OutboundBudget,
        allow_feedback: bool,
        allow_data: bool,
    ) -> Result<Option<usize>, Error> {
        if self.arq.is_compact() {
            return self.poll_compact_inner(now, output, budget, allow_feedback, allow_data);
        }
        self.check_time(now)?;
        if output.len() < self.maximum_packet {
            return Err(Error::OutputTooSmall {
                required: self.maximum_packet,
            });
        }
        self.advance(now)?;
        self.pump()?;
        if allow_feedback
            && (self.prefer_feedback || !allow_data)
            && let Some(length) = self.feedback(output, budget)?
        {
            return Ok(Some(length));
        }
        if allow_data
            && self.outgoing.is_empty()
            && self
                .building_deadline
                .is_some_and(|deadline| now >= deadline)
        {
            self.seal()?;
        }
        if allow_data && let Some(length) = self.emit_front(output, budget)? {
            return Ok(Some(length));
        }
        let source_allowed = if self.compact_wire.is_some() {
            self.arq
                .body_packet_bytes(now, false)?
                .map(|bytes| self.allowed(1 + bytes, budget))
                .transpose()?
                .unwrap_or(false)
        } else {
            self.allowed(self.maximum_packet, budget)?
        };
        if allow_data && self.outgoing.is_empty() && source_allowed {
            for _ in 0..self.legacy_send()?.fec.block.max_sources {
                let emitted = if self.compact_wire.is_some() {
                    self.arq.poll_source_body(now, &mut self.scratch)?
                } else {
                    self.arq.poll_source(now, &mut self.scratch)?
                };
                let Some(length) = emitted else {
                    break;
                };
                let own = opposite_context(self.context);
                let source_view = if self.compact_wire.is_some() {
                    l2tunnel_recovery::inspect_body(
                        false,
                        &self.scratch[..length],
                        self.legacy_send()?.arq.max_source_bytes,
                    )?
                } else {
                    inspect_packet(
                        &self.scratch[..length],
                        own,
                        self.legacy_send()?.arq.max_source_bytes,
                    )?
                };
                let source = match source_view {
                    PacketView::Data { source, .. } => source.0,
                    _ => return self.fail(Error::Malformed),
                };
                if source < self.next_fresh_source {
                    return self
                        .emit_scratch(1, length, Emission::Retry, output, budget)
                        .map(Some);
                }
                if source != self.next_fresh_source {
                    return self.fail(Error::SourceConflict);
                }
                if self.legacy_send()?.repair_symbols == 0 {
                    self.next_fresh_source = self
                        .next_fresh_source
                        .checked_add(1)
                        .ok_or(Error::Exhausted)?;
                    return self
                        .emit_scratch(1, length, Emission::Source, output, budget)
                        .map(Some);
                }
                if self.building.is_empty() {
                    self.building_deadline = Some(
                        now.checked_add(self.legacy_send()?.flush_after)
                            .ok_or(Error::TimeOverflow)?,
                    );
                }
                self.building.push(&self.scratch[..length])?;
                self.next_fresh_source = self
                    .next_fresh_source
                    .checked_add(1)
                    .ok_or(Error::Exhausted)?;
                if self.building.len() == self.legacy_send()?.fec.block.max_sources {
                    self.seal()?;
                    if let Some(length) = self.emit_front(output, budget)? {
                        return Ok(Some(length));
                    }
                    break;
                }
            }
        }
        if allow_feedback {
            self.feedback(output, budget)
        } else {
            Ok(None)
        }
    }

    /// Copy one original ordered source. Small destinations leave it retained.
    /// Freed receiver space is serviced by the next poll/receive call.
    pub fn poll_delivered(&mut self, output: &mut [u8]) -> Result<Option<(u64, usize)>, Error> {
        self.running()?;
        Ok(self.arq.poll_delivered(output)?)
    }

    /// Borrow validated retained source payloads without consuming ordered custody.
    ///
    /// Direct and FEC-restored sources share the actual bounded ARQ owner.
    /// Observation changes neither ACK state nor the delivery cursor; early
    /// consumers must keep original identities and deduplicate ordered replay.
    pub fn received_sources(&self) -> Result<impl Iterator<Item = (u64, &[u8])>, Error> {
        self.running()?;
        Ok(self
            .arq
            .received_sources()?
            .map(|(source, bytes)| (source.0, bytes)))
    }

    /// Actual next ARQ feedback deadline, independently of data/coding work.
    pub fn feedback_deadline(&self) -> Option<Duration> {
        if self.failure().is_some() || self.pending_output().is_some() {
            None
        } else {
            self.arq.feedback_deadline()
        }
    }

    /// Next feedback deadline and exact current body length, excluding outer
    /// carrier overhead. Compact uses its actual rotating bitmap selection.
    pub fn feedback_opportunity(&self) -> Result<Option<(Duration, usize)>, Error> {
        let Some(at) = self.feedback_deadline() else {
            return Ok(None);
        };
        if self.compact_wire.is_some() {
            return Ok(self
                .arq
                .body_packet_bytes(at.max(self.now), true)?
                .map(|bytes| (at, bytes + 1)));
        }
        let body = if self.arq.is_compact() {
            let Some(bytes) = self.arq.compact_packet_bytes(at.max(self.now), true)? else {
                return Ok(None);
            };
            bytes
        } else {
            l2tunnel_recovery::ACK_PACKET_BYTES
        };
        let bytes = body.checked_add(ENVELOPE_BYTES).ok_or(Error::Exhausted)?;
        Ok(Some((at, bytes)))
    }

    /// Service bounded receive-FEC cache eviction using caller-injected time.
    /// This does not poll ARQ, prepare output, confirm a held physical token or
    /// renew any original deadline. It remains usable while output is retained.
    pub fn tick(&mut self, now: Duration) -> Result<(), Error> {
        self.check_time(now)?;
        self.advance(now)
    }

    /// Original receive-coding expiry, independent of queued output wakeups.
    pub fn expiry_deadline(&self) -> Option<Duration> {
        if self.failure().is_some() {
            None
        } else {
            self.fec_deadlines.minimum().map(Duration::from_millis)
        }
    }

    /// Earliest ARQ, partial-block or coding expiry service deadline.
    pub fn deadline(&self) -> Option<Duration> {
        if self.failure().is_some() {
            return None;
        }
        if self.pending_output().is_some() {
            return self.expiry_deadline();
        }
        if !self.outgoing.is_empty() || !self.restored.is_empty() {
            return Some(self.now);
        }
        self.arq
            .deadline()
            .into_iter()
            .chain(self.building_deadline)
            .chain(self.expiry_deadline())
            .min()
    }

    /// Next ACK opportunity for the explicit independent-feedback polling API.
    /// A held main data output cannot hide this free physical lane. The old
    /// feedback_deadline retains the original combined-slot polling contract.
    pub fn feedback_deadline_independent(&self) -> Option<Duration> {
        if self.failure().is_some() || self.pending_feedback_output().is_some() {
            None
        } else {
            self.arq.feedback_deadline()
        }
    }

    /// Earliest actionable independent data/feedback wake or original hard expiry.
    /// Only the occupied lane's soft opportunities are suppressed; neither an
    /// opposite-lane receipt nor a retry renews an existing timer. The original
    /// deadline method remains paired with the combined-slot polling APIs.
    pub fn deadline_independent(&self) -> Option<Duration> {
        if self.failure().is_some() {
            return None;
        }
        let data = if self.pending_data_output().is_some() {
            None
        } else if !self.outgoing.is_empty() || !self.restored.is_empty() {
            Some(self.now)
        } else {
            self.arq
                .source_deadline()
                .into_iter()
                .chain(self.building_deadline)
                .min()
        };
        data.into_iter()
            .chain(self.feedback_deadline_independent())
            .chain(self.expiry_deadline())
            .min()
    }

    /// Full logical/retention drain; terminal FEC tombstones do not block it.
    pub fn drained(&self) -> bool {
        self.failure().is_none()
            && self.pending_output.is_none()
            && self.independent_feedback.is_none()
            && self.arq.drained()
            && self.building.is_empty()
            && self.outgoing.is_empty()
            && self.restored.is_empty()
            && self
                .decoder
                .as_ref()
                .is_none_or(|decoder| decoder.generation_count() == 0)
    }
    /// Maximum complete returned packet, excluding configured outer overhead.
    pub fn max_packet_bytes(&self) -> usize {
        self.maximum_packet.max(self.receive_maximum_packet)
    }
    /// Exact local complete emission ceiling, excluding external overhead.
    pub fn send_max_packet_bytes(&self) -> usize {
        self.maximum_packet
    }
    /// Exact peer complete packet ceiling used by authenticated ingress.
    pub fn receive_max_packet_bytes(&self) -> usize {
        self.receive_maximum_packet
    }
    /// Actual wrapper-level transmission/recovery observations.
    pub fn statistics(&self) -> Statistics {
        self.statistics
    }
    /// Exact failed shared CompactARQ owner; legacy recovery returns None.
    pub fn compact_retry_failure_snapshot(
        &self,
    ) -> Option<l2tunnel_recovery::CompactRetryFailureSnapshot> {
        self.arq.compact().ok()?.retry_failure_snapshot()
    }
    /// Underlying stable source/attempt/receipt statistics.
    pub fn arq_statistics(&self) -> ArqStatistics {
        self.arq.statistics()
    }
    /// Sticky protocol/retry failure, requiring session reconciliation/replacement.
    pub fn failure(&self) -> Option<Error> {
        self.failure.or_else(|| self.arq.failure().map(Error::Arq))
    }
    /// Read-only exact output-budget observations; None means diagnostics were not selected.
    pub fn output_wait_snapshot(&self, now: Duration) -> Option<diagnostics::Snapshot> {
        self.diagnostics.first().copied().map(|v| v.observed(now))
    }
    fn block_buffers(&self) -> Option<diagnostics::Buffers> {
        let compact::Policies::Legacy { send, receive } = self.policies else {
            return None;
        };
        // The allocating owner creates its encoder only inside seal(). Both
        // owners retain the same configured queues before/after that temporary
        // encoder exists; backing allocation is not an operational capacity.
        let building = if send.repair_symbols == 0 {
            0
        } else {
            send.fec.block.max_sources
        };
        Some(diagnostics::Buffers {
            building_packets_capacity: building,
            building_deadline: self.building_deadline,
            outbound_packets_capacity: building + send.repair_symbols,
            outbound_packet_bytes_maximum: self.maximum_packet,
            restored_packets_capacity: receive.max_restored_packets,
            restored_bytes_capacity: receive.max_restored_bytes,
            physical_packets: [
                usize::from(self.pending_output.is_some()),
                usize::from(self.independent_feedback.is_some()),
            ],
            physical_bytes: [
                self.pending_output.map_or(0, |v| v.bytes),
                self.independent_feedback.map_or(0, |v| v.bytes),
            ],
            physical_packets_capacity: usize::from(self.physical_instance.is_some()),
            decoder_present: self.decoder.is_some(),
            decoder: if self.diagnostics.is_empty() {
                None
            } else {
                self.decoder.as_ref().map(fec::Decoder::buffer_snapshot)
            },
        })
    }
    fn output_operation(&self) -> Option<diagnostics::Operation> {
        let front = self.outgoing.front()?;
        let view = self.inspect_output_record(&front.bytes).ok()?.fec?;
        Some(diagnostics::Operation {
            generation: view.generation.0,
            symbol: view.symbol.0,
            bytes: front.bytes.len(),
        })
    }

    /// Current bounded owned storage, without counting external caller packets.
    pub fn storage(&self) -> Storage {
        Storage {
            arq: self.arq.retained(),
            building_packets: self.building.len(),
            building_bytes: self.building.iter().map(Vec::len).sum(),
            outbound_packets: self.outgoing.len(),
            outbound_bytes: self.outgoing.bytes(),
            restored_packets: self.restored.len(),
            restored_bytes: self.restored_bytes,
            fec_reserved_bytes: self
                .decoder
                .as_ref()
                .map_or(0, fec::Decoder::reserved_bytes),
            block: self.block_buffers(),
        }
    }

    fn receive_fec(&mut self, inner: &[u8], now: Duration) -> Result<(), Error> {
        let view = fec::inspect(inner, self.receive_fec, self.legacy_receive()?.fec.block)
            .or_else(|error| self.fail(error.into()))?;
        self.receive_fec_view(view, now)
    }

    fn receive_fec_view(&mut self, view: fec::SymbolView<'_>, now: Duration) -> Result<(), Error> {
        let maximum_source_bytes = self.legacy_receive()?.arq.max_source_bytes;
        let compact = self.compact_wire.is_some();
        let systematic = if view.kind == fec::SymbolKind::Systematic {
            let length = usize::from(u16::from_be_bytes(
                view.payload
                    .get(..2)
                    .ok_or(Error::Malformed)?
                    .try_into()
                    .map_err(|_| Error::Malformed)?,
            ));
            let source = view.payload.get(2..2 + length).ok_or(Error::Malformed)?;
            self.source_id(source).or_else(|error| self.fail(error))?;
            Some(source)
        } else {
            None
        };
        let maximum = view
            .source_count
            .checked_mul(view.coded_bytes - 2)
            .ok_or(Error::Exhausted)?;
        self.ensure_restored(view.source_count, maximum, now)?;
        self.advance(now)?;
        let ticks = milliseconds(now)?;
        let mut diagnostics = self.diagnostics.first_mut();
        let refused = |reason| {
            if let Some(state) = diagnostics.as_deref_mut() {
                let index = match reason {
                    fec::DecoderCapacity::SymbolSlots => 0,
                    fec::DecoderCapacity::GenerationSlots => 1,
                    fec::DecoderCapacity::LogicalReservation => 2,
                };
                state.capacity_refused(index, now);
            }
        };
        let decoder = self.decoder.as_mut().ok_or(Error::Malformed)?;
        let accepted = if compact {
            decoder.accept_compact_view_observed(view, ticks, refused)
        } else {
            decoder.accept_view_observed(view, ticks, refused)
        };
        match accepted {
            Ok(fec::AcceptStatus::Complete(_)) => {
                let checked = (|| -> Result<(), Error> {
                    let mut sources = self
                        .decoder
                        .as_ref()
                        .ok_or(Error::Malformed)?
                        .decoded_sources(view.generation)?;
                    let first = self.source_id(sources.next().ok_or(Error::Malformed)?)?;
                    for (index, source) in self
                        .decoder
                        .as_ref()
                        .ok_or(Error::Malformed)?
                        .decoded_sources(view.generation)?
                        .enumerate()
                    {
                        let identity = self.source_id(source)?;
                        if identity != first.checked_add(index as u64).ok_or(Error::Exhausted)? {
                            return Err(Error::SourceConflict);
                        }
                        if self
                            .restored
                            .get(&identity)
                            .is_some_and(|old| old.bytes != source)
                        {
                            return Err(Error::SourceConflict);
                        }
                    }
                    Ok(())
                })();
                if let Err(error) = checked {
                    return self.fail(error);
                }
                let direct_identity = systematic
                    .map(|source| self.source_id(source))
                    .transpose()?;
                let sources = self
                    .decoder
                    .as_ref()
                    .ok_or(Error::Malformed)?
                    .decoded_sources(view.generation)?;
                let count = sources.len();
                for source in sources {
                    let identity =
                        source_id_selected(self.context, maximum_source_bytes, source, compact)?;
                    if !self.restored.contains_key(&identity) {
                        let total = self
                            .restored_bytes
                            .checked_add(source.len())
                            .ok_or(Error::Exhausted)?;
                        self.restored.insert(
                            identity,
                            source,
                            Some(identity) != direct_identity,
                        )?;
                        self.restored_bytes = total;
                    }
                }
                self.decoder
                    .as_mut()
                    .ok_or(Error::Malformed)?
                    .commit_decoded(view.generation)?;
                self.fec_deadlines.remove(&view.generation);
                self.statistics.decoded_source_vectors = self
                    .statistics
                    .decoded_source_vectors
                    .saturating_add(count as u64);
            }
            Ok(_) => {
                self.fec_deadlines.insert(
                    view.generation,
                    ticks
                        .checked_add(self.legacy_receive()?.fec.max_lifetime_ticks)
                        .ok_or(Error::TimeOverflow)?,
                )?;
                if let Some(source) = systematic {
                    self.enqueue(source, false)?;
                }
            }
            Err(
                fec::Error::Capacity
                | fec::Error::Expired
                | fec::Error::StaleGeneration
                | fec::Error::WindowBlocked
                | fec::Error::AlreadyCompleted
                | fec::Error::CompletePending,
            ) => {
                self.statistics.skipped_fec_packets =
                    self.statistics.skipped_fec_packets.saturating_add(1);
                if let Some(source) = systematic {
                    self.enqueue(source, false)?;
                }
            }
            Err(error) => return self.fail(error.into()),
        }
        self.pump()
    }

    fn seal(&mut self) -> Result<(), Error> {
        if self.building.is_empty() {
            return Ok(());
        }
        if !self.outgoing.is_empty() {
            return Err(Error::Exhausted);
        }
        let Some(generation) = self.next_generation else {
            return self.fail(Error::Exhausted);
        };
        let count = self.building.len();
        let repairs = count
            .checked_mul(self.legacy_send()?.repair_symbols)
            .ok_or(Error::Exhausted)?
            .div_ceil(self.legacy_send()?.fec.block.max_sources);
        let block = self.legacy_send()?.fec.block;
        let mut legacy_encoder;
        let encoder = if let Some(encoder) = &mut self.encoder {
            encoder.seal_sources(generation, self.building.iter().map(Vec::as_slice))?;
            encoder
        } else {
            let sources: Vec<_> = self.building.iter().map(Vec::as_slice).collect();
            legacy_encoder = fec::BlockEncoder::new(self.send_fec, generation, block, &sources)?;
            &mut legacy_encoder
        };
        let size = ENVELOPE_BYTES + fec::HEADER_BYTES + count + encoder.coded_bytes();
        if self.compact_wire.is_some() {
            for index in 0..count {
                self.outgoing.push(size, Emission::Systematic, |output| {
                    Ok(
                        encoder.systematic_with(fec::SourceId(index as u16), |view| {
                            selected_wire::encode_symbol(view, output)
                        })?,
                    )
                })?;
            }
            for repair in 0..repairs {
                self.outgoing.push(size, Emission::Repair, |output| {
                    Ok(encoder.cauchy_repair_with(repair as u16, |view| {
                        selected_wire::encode_symbol(view, output)
                    })?)
                })?;
            }
            self.building.clear();
            self.building_deadline = None;
            self.next_generation = generation.0.checked_add(1).map(fec::GenerationId);
            return Ok(());
        }
        for index in 0..count {
            self.outgoing.push(size, Emission::Systematic, |output| {
                let bytes = encoder
                    .systematic_into(fec::SourceId(index as u16), &mut output[ENVELOPE_BYTES..])?;
                write_header(3, output);
                Ok(ENVELOPE_BYTES + bytes)
            })?;
        }
        for repair in 0..repairs {
            self.outgoing.push(size, Emission::Repair, |output| {
                let bytes =
                    encoder.cauchy_repair_into(repair as u16, &mut output[ENVELOPE_BYTES..])?;
                write_header(3, output);
                Ok(ENVELOPE_BYTES + bytes)
            })?;
        }
        self.building.clear();
        self.building_deadline = None;
        self.next_generation = generation.0.checked_add(1).map(fec::GenerationId);
        Ok(())
    }

    fn feedback(
        &mut self,
        output: &mut [u8],
        budget: &mut OutboundBudget,
    ) -> Result<Option<usize>, Error> {
        if self.compact_wire.is_some() {
            let Some(body) = self.arq.body_packet_bytes(self.now, true)? else {
                return Ok(None);
            };
            let charge = (1 + body)
                .checked_add(self.selected_overhead(RecordKind::Feedback))
                .ok_or(Error::Exhausted)?;
            if budget.packets == 0 || budget.wire_bytes < charge {
                return Ok(None);
            }
            let Some(length) = self.arq.poll_feedback_body(self.now, &mut self.scratch)? else {
                return Ok(None);
            };
            return self
                .emit_scratch(2, length, Emission::Feedback, output, budget)
                .map(Some);
        }
        if !self.allowed(ENVELOPE_BYTES + ACK_PACKET_BYTES, budget)? {
            return Ok(None);
        }
        let Some(length) = self.arq.poll_feedback(self.now, &mut self.scratch)? else {
            return Ok(None);
        };
        self.emit_scratch(2, length, Emission::Feedback, output, budget)
            .map(Some)
    }

    fn emit_front(
        &mut self,
        output: &mut [u8],
        budget: &mut OutboundBudget,
    ) -> Result<Option<usize>, Error> {
        let Some(front) = self.outgoing.front() else {
            return Ok(None);
        };
        let allowed = self.allowed(front.bytes.len(), budget)?;
        let length = front.bytes.len();
        let emission = front.emission;
        // Canonical inspection runs only for an opted-in actual refusal or its
        // matching completion. It neither polls nor copies retained payloads.
        let inspect = self
            .diagnostics
            .first()
            .is_some_and(|v| !allowed || v.pending.is_some());
        let operation = if inspect {
            self.output_operation()
        } else {
            None
        };
        if !allowed {
            let charge = length.checked_add(self.outer_overhead());
            if let Some(state) = self.diagnostics.first_mut() {
                if let (Some(operation), Some(charge)) = (operation, charge) {
                    state.refused(
                        operation,
                        self.now,
                        [budget.packets == 0, budget.wire_bytes < charge],
                    );
                } else {
                    state.identity_mismatch = true;
                }
            }
            return Ok(None);
        }
        // Reborrow after read-only identity inspection; the exact head is unchanged.
        let front = self.outgoing.front().ok_or(Error::Exhausted)?;
        output[..length].copy_from_slice(&front.bytes);
        self.outgoing.discard_front()?;
        self.charge(length, emission, budget)?;
        if inspect && let Some(state) = self.diagnostics.first_mut() {
            if let Some(operation) = operation {
                state.progress(operation, self.now);
            } else {
                state.identity_mismatch = true;
            }
        }
        Ok(Some(length))
    }
    fn emit_scratch(
        &mut self,
        kind: u8,
        length: usize,
        emission: Emission,
        output: &mut [u8],
        budget: &mut OutboundBudget,
    ) -> Result<usize, Error> {
        let prefix = if self.compact_wire.is_some() {
            1
        } else {
            ENVELOPE_BYTES
        };
        let bytes = prefix.checked_add(length).ok_or(Error::Exhausted)?;
        let overhead = self.selected_overhead(if kind == 2 {
            RecordKind::Feedback
        } else {
            RecordKind::Source
        });
        let charge = bytes.checked_add(overhead).ok_or(Error::Exhausted)?;
        if budget.packets == 0 || budget.wire_bytes < charge || output.len() < bytes {
            return Err(Error::Exhausted);
        }
        if self.compact_wire.is_some() {
            output[0] = kind;
        } else {
            write_header(kind, output);
        }
        output[prefix..bytes].copy_from_slice(&self.scratch[..length]);
        self.charge(bytes, emission, budget)?;
        Ok(bytes)
    }
    fn charge(
        &mut self,
        bytes: usize,
        emission: Emission,
        budget: &mut OutboundBudget,
    ) -> Result<(), Error> {
        let kind = if matches!(emission, Emission::Feedback) {
            RecordKind::Feedback
        } else {
            RecordKind::Source
        };
        let charge = bytes
            .checked_add(self.selected_overhead(kind))
            .ok_or(Error::Exhausted)?;
        self.charge_exact(charge, emission, budget)
    }

    fn charge_exact(
        &mut self,
        charge: usize,
        emission: Emission,
        budget: &mut OutboundBudget,
    ) -> Result<(), Error> {
        if budget.packets == 0 || budget.wire_bytes < charge {
            return Err(Error::Exhausted);
        }
        budget.packets -= 1;
        budget.wire_bytes -= charge;
        self.statistics.emitted_packets = self.statistics.emitted_packets.saturating_add(1);
        self.statistics.emitted_wire_bytes = self
            .statistics
            .emitted_wire_bytes
            .saturating_add(charge as u64);
        let statistic = match emission {
            Emission::Source => &mut self.statistics.source_packets,
            Emission::Systematic => &mut self.statistics.systematic_packets,
            Emission::Repair => &mut self.statistics.repair_packets,
            Emission::Retry => &mut self.statistics.retry_packets,
            Emission::Feedback => &mut self.statistics.feedback_packets,
        };
        *statistic = statistic.saturating_add(1);
        self.prefer_feedback = !matches!(emission, Emission::Feedback);
        Ok(())
    }

    fn allowed(&self, bytes: usize, budget: &OutboundBudget) -> Result<bool, Error> {
        Ok(budget.packets > 0
            && budget.wire_bytes
                >= bytes
                    .checked_add(self.outer_overhead())
                    .ok_or(Error::Exhausted)?)
    }

    fn ensure_restored(
        &mut self,
        packets: usize,
        bytes: usize,
        now: Duration,
    ) -> Result<(), Error> {
        // Preserve the existing short-circuit gate and error precedence.
        let reason = if self
            .restored
            .len()
            .checked_add(packets)
            .ok_or(Error::Exhausted)?
            > self.legacy_receive()?.max_restored_packets
        {
            Some(3)
        } else if self
            .restored_bytes
            .checked_add(bytes)
            .ok_or(Error::Exhausted)?
            > self.legacy_receive()?.max_restored_bytes
        {
            Some(4)
        } else {
            None
        };
        if let Some(reason) = reason {
            if let Some(state) = self.diagnostics.first_mut() {
                state.capacity_refused(reason, now);
            }
            return Err(Error::RestoredCapacity);
        }
        Ok(())
    }

    fn source_id(&self, bytes: &[u8]) -> Result<u64, Error> {
        source_id_selected(
            self.context,
            self.legacy_receive()?.arq.max_source_bytes,
            bytes,
            self.compact_wire.is_some(),
        )
    }

    fn validate_duplicate(&mut self, identity: u64, bytes: &[u8]) -> Result<(), Error> {
        if self
            .restored
            .get(&identity)
            .is_some_and(|previous| previous.bytes != bytes)
        {
            return self.fail(Error::SourceConflict);
        }
        Ok(())
    }

    fn enqueue(&mut self, bytes: &[u8], recovered: bool) -> Result<(), Error> {
        let identity = self.source_id(bytes).or_else(|error| self.fail(error))?;
        self.validate_duplicate(identity, bytes)?;
        if self.restored.contains_key(&identity) {
            return Ok(());
        }
        let total = self
            .restored_bytes
            .checked_add(bytes.len())
            .ok_or(Error::Exhausted)?;
        self.restored.insert(identity, bytes, recovered)?;
        self.restored_bytes = total;
        Ok(())
    }

    fn pump(&mut self) -> Result<(), Error> {
        if self.arq.is_compact() {
            return Ok(());
        }
        for _ in 0..self.legacy_receive()?.max_restored_packets {
            let Some((&identity, record)) = self.restored.first_key_value() else {
                break;
            };
            let previous = self.arq.statistics().received_unique;
            let received = if self.compact_wire.is_some() {
                self.arq.receive_body(&record.bytes, false, self.now)
            } else {
                self.arq.receive(&record.bytes, self.now)
            };
            match received {
                Ok(()) => {
                    if record.recovered && self.arq.statistics().received_unique > previous {
                        self.statistics.repaired_unique_sources =
                            self.statistics.repaired_unique_sources.saturating_add(1);
                    }
                    self.restored_bytes -= record.bytes.len();
                    self.restored.remove(&identity);
                }
                Err(RecoveryError::Capacity(_) | RecoveryError::SequenceWindow) => break,
                Err(error) => return self.fail(error.into()),
            }
        }
        Ok(())
    }

    fn advance(&mut self, now: Duration) -> Result<(), Error> {
        if let Some(decoder) = &mut self.decoder {
            if self.usage.is_some() {
                let count = decoder.expire_into(milliseconds(now)?, &mut self.expired)?;
                for generation in &self.expired[..count] {
                    self.fec_deadlines.remove(&generation.generation);
                    self.statistics.expired_generations =
                        self.statistics.expired_generations.saturating_add(1);
                }
            } else {
                for generation in decoder.expire(milliseconds(now)?)? {
                    self.fec_deadlines.remove(&generation.generation);
                    self.statistics.expired_generations =
                        self.statistics.expired_generations.saturating_add(1);
                }
            }
        }
        self.now = now;
        Ok(())
    }

    fn check_time(&self, now: Duration) -> Result<(), Error> {
        self.running()?;
        if now < self.now {
            return Err(Error::NonMonotonicTime);
        }
        if self.arq.is_compact() {
            return Ok(());
        }
        now.checked_add(self.legacy_send()?.arq.maximum_rto)
            .ok_or(Error::TimeOverflow)?;
        now.checked_add(self.legacy_send()?.flush_after)
            .ok_or(Error::TimeOverflow)?;
        milliseconds(now)?
            .checked_add(self.legacy_receive()?.fec.max_lifetime_ticks)
            .ok_or(Error::TimeOverflow)?;
        Ok(())
    }
    fn running(&self) -> Result<(), Error> {
        self.failure().map_or(Ok(()), Err)
    }
    fn fail<T>(&mut self, error: Error) -> Result<T, Error> {
        self.failure = Some(error);
        Err(error)
    }
}

fn milliseconds(now: Duration) -> Result<u64, Error> {
    u64::try_from(now.as_millis()).map_err(|_| Error::TimeOverflow)
}
fn opposite_context(context: RecoveryContext) -> RecoveryContext {
    RecoveryContext {
        role: match context.role {
            EndpointRole::Initiator => EndpointRole::Responder,
            EndpointRole::Responder => EndpointRole::Initiator,
        },
        ..context
    }
}
fn fec_context(context: RecoveryContext, peer: bool) -> fec::FecContext {
    let role = if peer {
        opposite_context(context).role
    } else {
        context.role
    };
    fec::FecContext {
        session: fec::SessionId(context.session.to_be_bytes()),
        epoch: fec::Epoch(context.epoch),
        channel: fec::ChannelId(0),
        direction: match role {
            EndpointRole::Initiator => fec::Direction::ClientToServer,
            EndpointRole::Responder => fec::Direction::ServerToClient,
        },
    }
}
fn write_header(kind: u8, output: &mut [u8]) {
    output[..ENVELOPE_BYTES].copy_from_slice(&[b'L', b'2', b'R', b'F', 1, kind, 0, 0]);
}
fn source_id_selected(
    context: RecoveryContext,
    maximum: usize,
    bytes: &[u8],
    compact: bool,
) -> Result<u64, Error> {
    let view = if compact {
        l2tunnel_recovery::inspect_body(false, bytes, maximum)?
    } else {
        inspect_packet(bytes, context, maximum)?
    };
    match view {
        PacketView::Data { source, .. } => Ok(source.0),
        _ => Err(Error::Malformed),
    }
}
#[cfg(test)]
fn wrap(kind: u8, inner: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(ENVELOPE_BYTES + inner.len());
    bytes.extend_from_slice(b"L2RF");
    bytes.extend_from_slice(&[1, kind, 0, 0]);
    bytes.extend_from_slice(inner);
    bytes
}
fn envelope(packet: &[u8], maximum: usize) -> Result<(u8, &[u8]), Error> {
    let header = packet.get(..ENVELOPE_BYTES).ok_or(Error::Malformed)?;
    if packet.len() > maximum
        || header[..4] != *b"L2RF"
        || header[4] != 1
        || !(1..=3).contains(&header[5])
        || header[6..8] != [0; 2]
    {
        return Err(Error::Malformed);
    }
    Ok((header[5], &packet[ENVELOPE_BYTES..]))
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod directional_tests;

#[cfg(test)]
mod storage_tests;

#[cfg(test)]
mod compact_tests;
