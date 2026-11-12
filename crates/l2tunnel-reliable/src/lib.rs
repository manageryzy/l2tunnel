//! Bounded real-payload systematic block FEC with selective-repeat fallback.
//!
//! Enclosing authentication/replay, negotiated budgets and congestion control
//! belong to the caller. Every emitted copy consumes an explicit wire allowance.
use l2tunnel_fec as fec;
use l2tunnel_recovery::{
    ACK_PACKET_BYTES, ArqConfig, DATA_HEADER_BYTES, EndpointRole, PacketView, RecoveryContext,
    RecoveryEngine, RecoveryError, Retained, SelectiveRepeat, Statistics as ArqStatistics,
    inspect_packet,
};
use std::collections::{BTreeMap, VecDeque};
use std::fmt;
use std::time::Duration;

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
    /// Cauchy repairs for a full block; partial blocks round their ratio upward.
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
    /// Existing FEC decoder reservation, including its bounded scratch allowance.
    pub fec_reserved_bytes: usize,
}

#[derive(Clone, Copy)]
enum Emission {
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
    config: ReliableConfig,
    context: RecoveryContext,
    arq: SelectiveRepeat,
    decoder: fec::Decoder,
    send_fec: fec::FecContext,
    receive_fec: fec::FecContext,
    building: Vec<Vec<u8>>,
    building_deadline: Option<Duration>,
    next_fresh_source: u64,
    next_generation: Option<fec::GenerationId>,
    outgoing: VecDeque<Outgoing>,
    restored: BTreeMap<u64, Restored>,
    restored_bytes: usize,
    fec_deadlines: BTreeMap<fec::GenerationId, u64>,
    scratch: Vec<u8>,
    maximum_packet: usize,
    prefer_feedback: bool,
    now: Duration,
    failure: Option<Error>,
    statistics: Statistics,
}

impl Reliable {
    /// Validate canonical cross-module limits before constructing bounded state.
    pub fn new(config: ReliableConfig, context: RecoveryContext) -> Result<Self, Error> {
        let arq = SelectiveRepeat::new(config.arq, context)?;
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
            || config.repair_symbols == 0
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
        let send_fec = fec_context(context, false);
        let receive_fec = fec_context(context, true);
        let decoder = fec::Decoder::new(receive_fec, config.fec)?;
        let scratch = vec![0; arq.max_packet_bytes()];
        Ok(Self {
            config,
            context,
            arq,
            decoder,
            send_fec,
            receive_fec,
            building: Vec::with_capacity(count),
            building_deadline: None,
            next_fresh_source: 0,
            next_generation: Some(fec::GenerationId(0)),
            outgoing: VecDeque::with_capacity(symbols),
            restored: BTreeMap::new(),
            restored_bytes: 0,
            fec_deadlines: BTreeMap::new(),
            scratch,
            maximum_packet,
            prefer_feedback: true,
            now: Duration::ZERO,
            failure: None,
            statistics: Statistics::default(),
        })
    }

    /// Read the authoritative ARQ source allocator without consuming an identity.
    /// The snapshot expires at this exclusive owner's next successful submit.
    pub fn next_source_id(&self) -> Result<u64, Error> {
        self.running()?;
        if self.next_generation.is_none() {
            return Err(Error::Exhausted);
        }
        Ok(self.arq.next_source_id()?.0)
    }

    /// Admit exactly one new logical source; repairs/retries never call this method.
    pub fn submit(&mut self, source: &[u8], now: Duration) -> Result<u64, Error> {
        self.check_time(now)?;
        if self.next_generation.is_none() {
            return Err(Error::Exhausted);
        }
        let source = self.arq.submit(source, now)?;
        self.now = now;
        Ok(source)
    }

    /// Consume one complete record after lower-layer integrity and replay checks.
    /// Resource pressure is retryable; malformed authenticated protocol input fails closed.
    pub fn receive(&mut self, packet: &[u8], now: Duration) -> Result<(), Error> {
        self.check_time(now)?;
        let (kind, inner) = match envelope(packet, self.maximum_packet) {
            Ok(view) => view,
            Err(error) => return self.fail(error),
        };
        match kind {
            1 => {
                self.source_id(inner).or_else(|error| self.fail(error))?;
                self.ensure_restored(1, inner.len())?;
                self.advance(now)?;
                self.enqueue(inner.to_vec(), false)?;
                self.pump()?;
            }
            2 => {
                match inspect_packet(inner, self.context, self.config.arq.max_source_bytes) {
                    Ok(PacketView::Ack { .. }) => {}
                    Ok(_) => return self.fail(Error::Malformed),
                    Err(error) => return self.fail(error.into()),
                }
                self.arq
                    .receive(inner, now)
                    .or_else(|error| self.fail(error.into()))?;
                self.advance(now)?;
            }
            3 => self.receive_fec(inner, now)?,
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

    /// Classify a complete outgoing record with the authoritative inner parsers.
    /// This checks local sending role/session/epoch and all encoding bounds; it
    /// neither authenticates bytes nor advances sender/receiver state.
    pub fn inspect_output(&self, packet: &[u8]) -> Result<RecordKind, Error> {
        self.inspect_record(packet, opposite_context(self.context), self.send_fec)
    }

    /// Classify one authenticated peer record without mutating recovery state.
    /// This uses the receiving role/session/epoch and authoritative inner parsers,
    /// allowing callers to reject feedback on data lanes or data on control lanes.
    /// Lower-layer integrity/replay verification must precede this operation.
    pub fn inspect_peer(&self, packet: &[u8]) -> Result<RecordKind, Error> {
        self.inspect_record(packet, self.context, self.receive_fec)
    }

    fn inspect_record(
        &self,
        packet: &[u8],
        arq_context: RecoveryContext,
        fec_context: fec::FecContext,
    ) -> Result<RecordKind, Error> {
        Ok(inspect_record_view(
            packet,
            self.maximum_packet,
            self.config.arq.max_source_bytes,
            self.config.fec.block,
            arq_context,
            fec_context,
        )?
        .kind)
    }

    fn poll_selected(
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
        if allow_data && self.outgoing.is_empty() && self.allowed(self.maximum_packet, budget)? {
            for _ in 0..self.config.fec.block.max_sources {
                let Some(length) = self.arq.poll_source(now, &mut self.scratch)? else {
                    break;
                };
                let own = opposite_context(self.context);
                let source = match inspect_packet(
                    &self.scratch[..length],
                    own,
                    self.config.arq.max_source_bytes,
                )? {
                    PacketView::Data { source, .. } => source.0,
                    _ => return self.fail(Error::Malformed),
                };
                if source < self.next_fresh_source {
                    let bytes = wrap(1, &self.scratch[..length]);
                    return self.emit(bytes, Emission::Retry, output, budget).map(Some);
                }
                if source != self.next_fresh_source {
                    return self.fail(Error::SourceConflict);
                }
                if self.building.is_empty() {
                    self.building_deadline = Some(
                        now.checked_add(self.config.flush_after)
                            .ok_or(Error::TimeOverflow)?,
                    );
                }
                self.building.push(self.scratch[..length].to_vec());
                self.next_fresh_source = self
                    .next_fresh_source
                    .checked_add(1)
                    .ok_or(Error::Exhausted)?;
                if self.building.len() == self.config.fec.block.max_sources {
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

    /// Earliest ARQ, partial-block or coding expiry service deadline.
    pub fn deadline(&self) -> Option<Duration> {
        if self.failure().is_some() {
            return None;
        }
        if !self.outgoing.is_empty() || !self.restored.is_empty() {
            return Some(self.now);
        }
        self.arq
            .deadline()
            .into_iter()
            .chain(self.building_deadline)
            .chain(
                self.fec_deadlines
                    .values()
                    .copied()
                    .map(Duration::from_millis),
            )
            .min()
    }

    /// Full logical/retention drain; terminal FEC tombstones do not block it.
    pub fn drained(&self) -> bool {
        self.failure().is_none()
            && self.arq.drained()
            && self.building.is_empty()
            && self.outgoing.is_empty()
            && self.restored.is_empty()
            && self.decoder.generation_count() == 0
    }
    /// Maximum complete returned packet, excluding configured outer overhead.
    pub fn max_packet_bytes(&self) -> usize {
        self.maximum_packet
    }
    /// Actual wrapper-level transmission/recovery observations.
    pub fn statistics(&self) -> Statistics {
        self.statistics
    }
    /// Underlying stable source/attempt/receipt statistics.
    pub fn arq_statistics(&self) -> ArqStatistics {
        self.arq.statistics()
    }
    /// Sticky protocol/retry failure, requiring session reconciliation/replacement.
    pub fn failure(&self) -> Option<Error> {
        self.failure.or_else(|| self.arq.failure().map(Error::Arq))
    }
    /// Current bounded owned storage, without counting external caller packets.
    pub fn storage(&self) -> Storage {
        Storage {
            arq: self.arq.retained(),
            building_packets: self.building.len(),
            building_bytes: self.building.iter().map(Vec::len).sum(),
            outbound_packets: self.outgoing.len(),
            outbound_bytes: self.outgoing.iter().map(|entry| entry.bytes.len()).sum(),
            restored_packets: self.restored.len(),
            restored_bytes: self.restored_bytes,
            fec_reserved_bytes: self.decoder.reserved_bytes(),
        }
    }

    fn receive_fec(&mut self, inner: &[u8], now: Duration) -> Result<(), Error> {
        let view = fec::inspect(inner, self.receive_fec, self.config.fec.block)
            .or_else(|error| self.fail(error.into()))?;
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
        self.ensure_restored(view.source_count, maximum)?;
        self.advance(now)?;
        let ticks = milliseconds(now)?;
        let accepted = self.decoder.accept(inner, ticks);
        match accepted {
            Ok(fec::AcceptStatus::Complete(_)) => {
                let block = self
                    .decoder
                    .take_decoded(view.generation)
                    .or_else(|error| self.fail(error.into()))?;
                self.fec_deadlines.remove(&view.generation);
                let first = self
                    .source_id(block.sources.first().ok_or(Error::Malformed)?)
                    .or_else(|error| self.fail(error))?;
                for (index, source) in block.sources.iter().enumerate() {
                    let identity = self.source_id(source).or_else(|error| self.fail(error))?;
                    if identity != first.checked_add(index as u64).ok_or(Error::Exhausted)? {
                        return self.fail(Error::SourceConflict);
                    }
                    self.validate_duplicate(identity, source)?;
                }
                self.statistics.decoded_source_vectors = self
                    .statistics
                    .decoded_source_vectors
                    .saturating_add(block.sources.len() as u64);
                let direct_identity = systematic
                    .map(|source| self.source_id(source))
                    .transpose()?;
                for source in block.sources {
                    let recovered = Some(self.source_id(&source)?) != direct_identity;
                    self.enqueue(source, recovered)?;
                }
            }
            Ok(_) => {
                self.fec_deadlines.entry(view.generation).or_insert(
                    ticks
                        .checked_add(self.config.fec.max_lifetime_ticks)
                        .ok_or(Error::TimeOverflow)?,
                );
                if let Some(source) = systematic {
                    self.enqueue(source.to_vec(), false)?;
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
                    self.enqueue(source.to_vec(), false)?;
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
        let sources: Vec<_> = self.building.iter().map(Vec::as_slice).collect();
        let count = sources.len();
        let mut encoder =
            fec::BlockEncoder::new(self.send_fec, generation, self.config.fec.block, &sources)?;
        let repairs = count
            .checked_mul(self.config.repair_symbols)
            .ok_or(Error::Exhausted)?
            .div_ceil(self.config.fec.block.max_sources);
        let mut outgoing = VecDeque::with_capacity(count + repairs);
        for index in 0..count {
            let packet = encoder.systematic(fec::SourceId(
                u16::try_from(index).map_err(|_| Error::Exhausted)?,
            ))?;
            outgoing.push_back(Outgoing {
                bytes: wrap(3, &packet.bytes),
                emission: Emission::Systematic,
            });
        }
        for repair in 0..repairs {
            let coefficients = fec::cauchy_coefficients(count as u16, repair as u16)?;
            let packet = encoder.repair(&coefficients)?;
            outgoing.push_back(Outgoing {
                bytes: wrap(3, &packet.bytes),
                emission: Emission::Repair,
            });
        }
        self.outgoing = outgoing;
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
        if !self.allowed(ENVELOPE_BYTES + ACK_PACKET_BYTES, budget)? {
            return Ok(None);
        }
        let Some(length) = self.arq.poll_feedback(self.now, &mut self.scratch)? else {
            return Ok(None);
        };
        self.emit(
            wrap(2, &self.scratch[..length]),
            Emission::Feedback,
            output,
            budget,
        )
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
        if !self.allowed(front.bytes.len(), budget)? {
            return Ok(None);
        }
        let packet = self.outgoing.pop_front().ok_or(Error::Exhausted)?;
        self.emit(packet.bytes, packet.emission, output, budget)
            .map(Some)
    }

    fn emit(
        &mut self,
        bytes: Vec<u8>,
        emission: Emission,
        output: &mut [u8],
        budget: &mut OutboundBudget,
    ) -> Result<usize, Error> {
        let charge = bytes
            .len()
            .checked_add(self.config.outer_overhead_bytes)
            .ok_or(Error::Exhausted)?;
        if budget.packets == 0 || budget.wire_bytes < charge || output.len() < bytes.len() {
            return Err(Error::Exhausted);
        }
        output[..bytes.len()].copy_from_slice(&bytes);
        budget.packets -= 1;
        budget.wire_bytes -= charge;
        self.statistics.emitted_packets = self.statistics.emitted_packets.saturating_add(1);
        self.statistics.emitted_wire_bytes = self
            .statistics
            .emitted_wire_bytes
            .saturating_add(charge as u64);
        let statistic = match emission {
            Emission::Systematic => &mut self.statistics.systematic_packets,
            Emission::Repair => &mut self.statistics.repair_packets,
            Emission::Retry => &mut self.statistics.retry_packets,
            Emission::Feedback => &mut self.statistics.feedback_packets,
        };
        *statistic = statistic.saturating_add(1);
        self.prefer_feedback = !matches!(emission, Emission::Feedback);
        Ok(bytes.len())
    }

    fn allowed(&self, bytes: usize, budget: &OutboundBudget) -> Result<bool, Error> {
        Ok(budget.packets > 0
            && budget.wire_bytes
                >= bytes
                    .checked_add(self.config.outer_overhead_bytes)
                    .ok_or(Error::Exhausted)?)
    }

    fn ensure_restored(&self, packets: usize, bytes: usize) -> Result<(), Error> {
        if self
            .restored
            .len()
            .checked_add(packets)
            .ok_or(Error::Exhausted)?
            > self.config.max_restored_packets
            || self
                .restored_bytes
                .checked_add(bytes)
                .ok_or(Error::Exhausted)?
                > self.config.max_restored_bytes
        {
            return Err(Error::RestoredCapacity);
        }
        Ok(())
    }

    fn source_id(&self, bytes: &[u8]) -> Result<u64, Error> {
        match inspect_packet(bytes, self.context, self.config.arq.max_source_bytes)? {
            PacketView::Data { source, .. } => Ok(source.0),
            _ => Err(Error::Malformed),
        }
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

    fn enqueue(&mut self, bytes: Vec<u8>, recovered: bool) -> Result<(), Error> {
        let identity = self.source_id(&bytes).or_else(|error| self.fail(error))?;
        self.validate_duplicate(identity, &bytes)?;
        if self.restored.contains_key(&identity) {
            return Ok(());
        }
        self.restored_bytes = self
            .restored_bytes
            .checked_add(bytes.len())
            .ok_or(Error::Exhausted)?;
        self.restored
            .insert(identity, Restored { bytes, recovered });
        Ok(())
    }

    fn pump(&mut self) -> Result<(), Error> {
        for _ in 0..self.config.max_restored_packets {
            let Some((&identity, record)) = self.restored.first_key_value() else {
                break;
            };
            let previous = self.arq.statistics().received_unique;
            match self.arq.receive(&record.bytes, self.now) {
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
        let expired = self.decoder.expire(milliseconds(now)?)?;
        for generation in expired {
            self.fec_deadlines.remove(&generation.generation);
            self.statistics.expired_generations =
                self.statistics.expired_generations.saturating_add(1);
        }
        self.now = now;
        Ok(())
    }

    fn check_time(&self, now: Duration) -> Result<(), Error> {
        self.running()?;
        if now < self.now {
            return Err(Error::NonMonotonicTime);
        }
        now.checked_add(self.config.arq.maximum_rto)
            .ok_or(Error::TimeOverflow)?;
        now.checked_add(self.config.flush_after)
            .ok_or(Error::TimeOverflow)?;
        milliseconds(now)?
            .checked_add(self.config.fec.max_lifetime_ticks)
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
