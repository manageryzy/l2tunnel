//! Selected CompactARQ behavior over the same payload and physical-custody owner.
use super::*;

/// Explicit v2 source prefix, including the common context.
pub const COMPACT_DATA_HEADER_BYTES: usize = 52;
/// Explicit v2 fixed feedback prefix before its little-bit-order bitmap.
pub const COMPACT_FEEDBACK_HEADER_BYTES: usize = 76;
const MAX_WINDOW: usize = 65_535;

/// Python behavior selection; these do not select a carrier or grant authentication.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CompactRecovery {
    /// Three-later receipt qualification plus the actual RTT guard.
    Guarded,
    /// Only an initial attempt can bypass that guard.
    FirstFlight,
    /// First-flight behavior plus one rate-limited early report per advancing gap.
    BoundedGap {
        /// Positive minimum since any previous feedback output.
        min_interval: Duration,
    },
}
impl CompactRecovery {
    fn code(self) -> u8 {
        match self {
            Self::Guarded => 1,
            Self::FirstFlight => 2,
            Self::BoundedGap { .. } => 3,
        }
    }
}
/// Complete independent source and payload bounds, validated by CompactArqConfig.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CompactBounds {
    /// Largest actual source payload, in1..=65535 bytes.
    pub max_source_bytes: usize,
    /// Logical retained send payload byte limit.
    pub send_bytes: usize,
    /// Logical retained receive payload byte limit.
    pub receive_bytes: usize,
    /// Maximum sending source count and contiguous-base ID span, in1..=65535.
    pub send_records: usize,
    /// Maximum receiving ID span and retained source count, in1..=65535.
    pub receive_records: usize,
}
/// Explicit timing policy, not access to a hidden path or real clock.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CompactTiming {
    /// Configured nominal round trip; zero supports an explicit zero-delay baseline.
    pub nominal_rtt: Duration,
    /// Positive ordinary feedback interval.
    pub feedback_interval: Duration,
    /// Receipt-event threshold, including duplicate receipt events.
    pub feedback_packets: usize,
}
/// Fully checked immutable data-direction policy; no secret defaults or clamps.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CompactArqConfig {
    bounds: CompactBounds,
    timing: CompactTiming,
    maximum_feedback_bytes: usize,
    history_entries: usize,
    maximum_attempts: u32,
    recovery: CompactRecovery,
}
impl CompactArqConfig {
    /// Validate exact bounds/timing before allocation, I/O or state mutation.
    pub fn new(
        bounds: CompactBounds,
        timing: CompactTiming,
        maximum_feedback_bytes: usize,
        history_entries: usize,
        maximum_attempts: u32,
        recovery: CompactRecovery,
    ) -> Result<Self, RecoveryError> {
        let value = Self {
            bounds,
            timing,
            maximum_feedback_bytes,
            history_entries,
            maximum_attempts,
            recovery,
        };
        value.validate()?;
        Ok(value)
    }
    /// Exact requested source/payload bounds.
    pub const fn bounds(self) -> CompactBounds {
        self.bounds
    }
    /// Exact requested injected-time policy.
    pub const fn timing(self) -> CompactTiming {
        self.timing
    }
    /// Complete feedback packet capacity, including its76-byte fixed prefix.
    pub const fn maximum_feedback_bytes(self) -> usize {
        self.maximum_feedback_bytes
    }
    /// Exact finite unsampled transmission-history slot count.
    pub const fn history_entries(self) -> usize {
        self.history_entries
    }
    /// Exact finite total attempts per source, including its original.
    pub const fn maximum_attempts(self) -> u32 {
        self.maximum_attempts
    }
    /// Exact selected behavior.
    pub const fn recovery(self) -> CompactRecovery {
        self.recovery
    }
    /// Validate represented fields without allocating.
    pub fn validate(self) -> Result<(), RecoveryError> {
        let b = self.bounds;
        if !(1..=MAX_WINDOW).contains(&b.max_source_bytes)
            || b.send_bytes < b.max_source_bytes
            || b.receive_bytes < b.max_source_bytes
            || !(1..=MAX_WINDOW).contains(&b.send_records)
            || !(1..=MAX_WINDOW).contains(&b.receive_records)
            || self.timing.feedback_interval.is_zero()
            || self.timing.feedback_packets == 0
            || !(COMPACT_FEEDBACK_HEADER_BYTES
                ..=COMPACT_FEEDBACK_HEADER_BYTES + MAX_WINDOW.div_ceil(8))
                .contains(&self.maximum_feedback_bytes)
            || self.history_entries == 0
            || u64::try_from(self.history_entries).is_err()
            || self.maximum_attempts == 0
            || matches!(self.recovery, CompactRecovery::BoundedGap { min_interval } if min_interval.is_zero())
        {
            return Err(RecoveryError::InvalidConfig);
        }
        seconds_duration(
            (2.0 * self.timing.nominal_rtt.as_secs_f64()
                + 2.0 * self.timing.feedback_interval.as_secs_f64())
            .max(0.02),
        )?;
        self.timing
            .nominal_rtt
            .checked_add(
                self.timing
                    .feedback_interval
                    .checked_mul(2)
                    .ok_or(RecoveryError::TimeOverflow)?,
            )
            .ok_or(RecoveryError::TimeOverflow)?;
        Ok(())
    }
    fn base(self) -> ArqConfig {
        ArqConfig {
            max_source_bytes: self.bounds.max_source_bytes,
            send_bytes: self.bounds.send_bytes,
            receive_bytes: self.bounds.receive_bytes,
            send_records: self.bounds.send_records,
            receive_records: self.bounds.receive_records,
            initial_rto: Duration::from_millis(20),
            maximum_rto: Duration::from_millis(20),
            ack_delay: Duration::ZERO,
            max_retries: 0,
        }
    }
}
/// Public copied estimator facts; binary64 seconds are diagnostic, not a clock.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct CompactTimingSnapshot {
    /// Latest accepted unambiguous echoed attempt.
    pub sampled_serial: u64,
    /// Smoothed round trip in binary64 seconds, absent before the first sample.
    pub srtt_seconds: Option<f64>,
    /// Smoothed deviation in binary64 seconds.
    pub rttvar_seconds: f64,
    /// Current adaptive RTO quantized to the nearest nanosecond.
    pub rto: Duration,
}
/// Borrowed validated explicit feedback fields; no authentication is established.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CompactFeedback<'a> {
    /// Contiguous confirmed receive prefix.
    pub prefix: u64,
    /// Independently rotating bitmap's first source.
    pub start: u64,
    /// Number of meaningful low-order bits.
    pub count: u16,
    /// Actual attempt echoed by the receiver.
    pub echo: u64,
    /// Receiver hold interval, ties-to-even microseconds.
    pub receiver_delay_us: u64,
    /// Monotonic, nonwrapping peer feedback output serial.
    pub serial: u64,
    /// Exact bitmap bytes; unused high final bits are zero.
    pub bitmap: &'a [u8],
}
impl CompactFeedback<'_> {
    fn bit(self, offset: usize) -> bool {
        self.bitmap[offset / 8] & (1 << (offset % 8)) != 0
    }
    fn acknowledges(self, source: SourceId) -> bool {
        source.0 < self.prefix
            || (source.0 >= self.start
                && source.0 - self.start < u64::from(self.count)
                && self.bit((source.0 - self.start) as usize))
    }
}
/// Borrowed source or feedback fields for transmission and parsed reception.
///
/// The descriptor carries no authentication, replay or physical-send authority.
/// The legacy serializer preserves L2ARv2; the context-free body serializer is
/// selected explicitly by an enclosing authenticated format.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CompactPacketView<'a> {
    /// Stable source identity, unique attempt serial and exact opaque payload.
    Data {
        /// Stable original source.
        source: SourceId,
        /// Per-attempt wire serial.
        serial: u64,
        /// Unchanged actual source bytes.
        payload: &'a [u8],
    },
    /// Actual variable receipt window.
    Feedback(CompactFeedback<'a>),
}

/// Algorithm branch supplied by the enclosing authenticated packet union.
/// This value alone establishes no authentication or recovery authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CompactPacketKind {
    /// One unchanged source payload and its distinct attempt serial.
    Data,
    /// One receipt bitmap and RTT/receiver-delay observation.
    Feedback,
}

/// Recovery preflight or caller encoder refusal; neither commits an output.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CompactPollError<E> {
    /// The actual selected recovery owner refused the operation.
    Recovery(RecoveryError),
    /// The enclosing encoder refused before accepting the borrowed output.
    Encode(E),
}
impl<E> From<RecoveryError> for CompactPollError<E> {
    fn from(error: RecoveryError) -> Self {
        Self::Recovery(error)
    }
}
impl<E: fmt::Display> fmt::Display for CompactPollError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Recovery(error) => fmt::Display::fmt(error, f),
            Self::Encode(error) => fmt::Display::fmt(error, f),
        }
    }
}
impl<E: std::error::Error + 'static> std::error::Error for CompactPollError<E> {}

mod diagnostics;
pub use diagnostics::{CompactPeerFeedbackSnapshot, CompactRetryFailureSnapshot};

mod body;
pub use body::{
    COMPACT_BODY_DATA_MAX_HEADER_BYTES, COMPACT_BODY_FEEDBACK_MAX_HEADER_BYTES,
    inspect_compact_body,
};
mod wire;
use wire::parse_compact;
/// Validate encoding/context/profile only; caller supplies authentication and replay.
pub fn inspect_compact_packet<'a>(
    packet: &'a [u8],
    context: RecoveryContext,
    policy: CompactArqConfig,
) -> Result<CompactPacketView<'a>, RecoveryError> {
    policy.validate()?;
    parse_compact(packet, context, policy)
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct History {
    serial: u64,
    accepted: Option<Duration>,
}
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct Meta {
    source: Option<SourceId>,
    serial: u64,
    accepted: Option<Duration>,
    fast: bool,
}
#[derive(Debug)]
pub(crate) struct State {
    send: CompactArqConfig,
    receive: CompactArqConfig,
    pub(super) base: u64,
    metadata: Vec<Meta>,
    history: Vec<Option<History>>,
    sampled: u64,
    srtt: Option<f64>,
    rttvar: f64,
    last_received_serial: u64,
    last_received_at: Duration,
    highest_received: Option<u64>,
    feedback_serial: u64,
    received_feedback_serial: u64,
    last_peer_feedback: Option<CompactPeerFeedbackSnapshot>,
    retry_failure: Option<CompactRetryFailureSnapshot>,
    bitmap_cursor: u64,
    feedback_events: usize,
    feedback_repeats: u8,
    last_feedback: Option<Duration>,
    notified_gap: Option<u64>,
}
/// The legacy owner retains an empty Vec header; only selected construction
/// reserves the actual singleton State and charges its real layout once.
#[derive(Debug)]
pub(super) struct Cell(Vec<State>);
impl Cell {
    pub(super) const fn empty() -> Self {
        Self(Vec::new())
    }
    pub(super) fn as_ref(&self) -> Option<&State> {
        self.0.first()
    }
    pub(super) fn as_mut(&mut self) -> Option<&mut State> {
        self.0.first_mut()
    }
    pub(super) fn is_some(&self) -> bool {
        !self.0.is_empty()
    }
}
impl State {
    fn meta(&self, source: SourceId) -> &Meta {
        &self.metadata[(source.0 % self.metadata.len() as u64) as usize]
    }
    fn meta_mut(&mut self, source: SourceId) -> &mut Meta {
        let index = (source.0 % self.metadata.len() as u64) as usize;
        &mut self.metadata[index]
    }
    fn history(&self, serial: u64) -> Option<History> {
        self.history[(serial % self.history.len() as u64) as usize]
            .filter(|entry| entry.serial == serial)
    }
    fn rto_with(&self, srtt: Option<f64>, rttvar: f64) -> Result<Duration, RecoveryError> {
        let feedback = 2.0 * self.send.timing.feedback_interval.as_secs_f64();
        seconds_duration(match srtt {
            None => (2.0 * self.send.timing.nominal_rtt.as_secs_f64() + feedback).max(0.02),
            Some(srtt) => (srtt + 4.0 * rttvar + feedback)
                .max(1.25 * srtt + feedback)
                .max(0.02),
        })
    }
    fn rto(&self) -> Result<Duration, RecoveryError> {
        self.rto_with(self.srtt, self.rttvar)
    }
    fn history_slot(&self, serial: u64) -> Result<usize, RecoveryError> {
        let index = (serial % self.history.len() as u64) as usize;
        if self.history[index].is_some() {
            Err(RecoveryError::HistoryCapacity)
        } else {
            Ok(index)
        }
    }
    pub(super) fn confirm(
        &mut self,
        source: SourceId,
        serial: u64,
        accepted: Duration,
    ) -> Result<(), RecoveryError> {
        let index = (serial % self.history.len() as u64) as usize;
        let history = self.history[index]
            .as_mut()
            .filter(|entry| entry.serial == serial)
            .ok_or(RecoveryError::InvalidTransmission)?;
        history.accepted = Some(accepted);
        self.meta_mut(source).accepted = Some(accepted);
        Ok(())
    }
}

/// One actual shared recovery Engine with explicit v2 policy and fallible storage.
#[derive(Debug)]
pub struct CompactRepeat {
    engine: Engine,
    send_maximum: usize,
    receive_maximum: usize,
}
impl CompactRepeat {
    /// Fallibly construct exact selected backing; never falls back to dynamic storage.
    pub fn new_duplex(
        send: CompactArqConfig,
        receive: CompactArqConfig,
        context: RecoveryContext,
    ) -> Result<Self, RecoveryError> {
        let plan =
            crate::storage::CompactPlan::for_compact(send, receive).map_err(storage_error)?;
        Self::new_duplex_reserved(
            send,
            receive,
            context,
            crate::storage::Limits {
                capacity_bytes: plan.capacity_bytes(),
            },
        )
        .map_err(storage_error)
    }
    /// Construct one symmetric selected owner.
    pub fn new(config: CompactArqConfig, context: RecoveryContext) -> Result<Self, RecoveryError> {
        Self::new_duplex(config, config, context)
    }
    /// Reserve all actual source, history and selected metadata before publication.
    pub fn new_duplex_reserved(
        send: CompactArqConfig,
        receive: CompactArqConfig,
        context: RecoveryContext,
        limits: crate::storage::Limits,
    ) -> Result<Self, crate::storage::Error> {
        let plan = crate::storage::CompactPlan::for_compact(send, receive)?;
        if plan.capacity_bytes() > limits.capacity_bytes {
            return Err(crate::storage::Error::Limit {
                required: plan.capacity_bytes(),
                limit: limits.capacity_bytes,
            });
        }
        let mut allocation = crate::storage::Allocation::new(limits.capacity_bytes);
        let mut sent = allocation.vec::<SendSlot>(send.bounds.send_records)?;
        let mut received = allocation.vec::<ReceiveSlot>(receive.bounds.receive_records)?;
        for _ in 0..send.bounds.send_records {
            sent.push(SendSlot {
                source: None,
                flight: Flight {
                    prepared_at: Duration::ZERO,
                    transmission: 0,
                    acknowledged: false,
                    payload: allocation.vec(send.bounds.max_source_bytes)?,
                    attempts: 0,
                    retry_at: None,
                    rto: Duration::ZERO,
                },
            });
        }
        for _ in 0..receive.bounds.receive_records {
            received.push(ReceiveSlot {
                source: None,
                payload: allocation.vec(receive.bounds.max_source_bytes)?,
            });
        }
        let mut metadata = allocation.vec::<Meta>(send.bounds.send_records)?;
        metadata.resize(send.bounds.send_records, Meta::default());
        let mut history = allocation.vec::<Option<History>>(send.history_entries)?;
        history.resize(send.history_entries, None);
        let mut selected = allocation.vec::<State>(1)?;
        selected.push(State {
            send,
            receive,
            base: 0,
            metadata,
            history,
            sampled: 0,
            srtt: None,
            rttvar: 0.0,
            last_received_serial: 0,
            last_received_at: Duration::ZERO,
            highest_received: None,
            feedback_serial: 0,
            received_feedback_serial: 0,
            last_peer_feedback: None,
            retry_failure: None,
            bitmap_cursor: 0,
            feedback_events: 0,
            feedback_repeats: 0,
            last_feedback: None,
            notified_gap: None,
        });
        let usage = allocation.usage();
        if usage.capacity_bytes != plan.capacity_bytes()
            || usage.allocations != 5 + send.bounds.send_records + receive.bounds.receive_records
        {
            return Err(crate::storage::Error::Invariant);
        }
        let mut engine = Engine::from_backing(
            (send.base(), receive.base()),
            context,
            Profile::Selective,
            Sent::Indexed(sent),
            Received::Indexed(received),
            Some(usage),
        );
        engine.compact = Cell(selected);
        engine
            .enable_physical_send_confirmation()
            .map_err(crate::storage::Error::Recovery)?;
        Ok(Self {
            engine,
            send_maximum: (COMPACT_DATA_HEADER_BYTES + send.bounds.max_source_bytes)
                .max(receive.maximum_feedback_bytes),
            receive_maximum: (COMPACT_DATA_HEADER_BYTES + receive.bounds.max_source_bytes)
                .max(send.maximum_feedback_bytes),
        })
    }
    /// Exact next original source identity without mutation.
    pub fn next_source_id(&self) -> Result<SourceId, RecoveryError> {
        self.engine.running()?;
        self.engine
            .next_source
            .checked_add(1)
            .ok_or(RecoveryError::CounterExhausted)?;
        Ok(SourceId(self.engine.next_source))
    }
    /// Preserve actual arrival separately from monotonic observation/custody time.
    pub fn receive_at(
        &mut self,
        packet: &[u8],
        received: Duration,
        observed: Duration,
    ) -> Result<(), RecoveryError> {
        self.engine.compact_receive(packet, received, observed)
    }
    /// Admit an already authenticated context-free descriptor through the same
    /// recovery transition, preserving original arrival and observation times.
    pub fn receive_view_at(
        &mut self,
        view: CompactPacketView<'_>,
        received: Duration,
        observed: Duration,
    ) -> Result<(), RecoveryError> {
        self.engine.compact_receive_view(view, received, observed)
    }

    /// Offer one actual selected body to a final encoder. The caller provides
    /// feedback bitmap scratch (at most the negotiated bitmap byte capacity).
    /// None or encoder error commits no output; scratch may be overwritten.
    pub fn poll_with<T, E>(
        &mut self,
        now: Duration,
        bitmap: &mut [u8],
        encode: impl FnOnce(CompactPacketView<'_>) -> Result<Option<T>, E>,
    ) -> Result<Option<T>, CompactPollError<E>> {
        let selected = self.engine.compact_selection(now, true, true)?;
        self.engine
            .compact_emit_with(now, selected, bitmap, true, encode)
    }

    /// Offer only a source from the same source/retry/history selection.
    pub fn poll_source_with<T, E>(
        &mut self,
        now: Duration,
        encode: impl FnOnce(CompactPacketView<'_>) -> Result<Option<T>, E>,
    ) -> Result<Option<T>, CompactPollError<E>> {
        let selected = self.engine.compact_selection(now, false, true)?;
        self.engine
            .compact_emit_with(now, selected, &mut [], true, encode)
    }

    /// Offer only due feedback with the same bounded bitmap cursor and repeats.
    pub fn poll_feedback_with<T, E>(
        &mut self,
        now: Duration,
        bitmap: &mut [u8],
        encode: impl FnOnce(CompactPacketView<'_>) -> Result<Option<T>, E>,
    ) -> Result<Option<T>, CompactPollError<E>> {
        let selected = self.engine.compact_selection(now, true, false)?;
        self.engine
            .compact_emit_with(now, selected, bitmap, true, encode)
    }
    /// Actual source attempt awaiting local whole-carrier acceptance.
    pub fn pending_transmission(&self, source: SourceId) -> Option<PhysicalTransmission> {
        self.engine.pending_transmission(source)
    }
    /// Confirm at one injected time.
    pub fn confirm_transmission(
        &mut self,
        now: Duration,
        token: PhysicalTransmission,
    ) -> Result<(), RecoveryError> {
        self.confirm_transmission_at(now, now, token)
    }
    /// Arm the frozen attempt RTO from original actual acceptance, once only.
    pub fn confirm_transmission_at(
        &mut self,
        observed: Duration,
        accepted: Duration,
        token: PhysicalTransmission,
    ) -> Result<(), RecoveryError> {
        self.engine
            .confirm_transmission_at(observed, accepted, token)
    }
    /// Exact due source packet length from the same selection used by emission.
    /// A full next history slot is not a source opportunity. Direct poll_source
    /// still returns its typed refusal; feedback and fatal attempt checks remain.
    /// Observation changes no clock, attempt, history, output or feedback cursor.
    pub fn source_packet_bytes(&self, now: Duration) -> Result<Option<usize>, RecoveryError> {
        let selected = self.engine.compact_selection(now, false, true)?;
        if let Some(Selection::Source { source, .. }) = selected
            && self.engine.compact_source_blocked(source)?
        {
            return Ok(None);
        }
        Ok(selected.map(Selection::bytes))
    }
    /// Exact due feedback length, including its actual rotating bitmap.
    /// Observation changes no clock, serial, repeat count or feedback cursor.
    pub fn feedback_packet_bytes(&self, now: Duration) -> Result<Option<usize>, RecoveryError> {
        Ok(self
            .engine
            .compact_selection(now, true, false)?
            .map(Selection::bytes))
    }
    /// Exact context-free source opportunity from the same current selection.
    pub fn source_body_bytes(&self, now: Duration) -> Result<Option<usize>, RecoveryError> {
        let selected = self.engine.compact_selection(now, false, true)?;
        if let Some(Selection::Source { source, .. }) = selected
            && self.engine.compact_source_blocked(source)?
        {
            return Ok(None);
        }
        self.engine.compact_body_bytes(now, selected)
    }
    /// Exact context-free feedback opportunity, including current delay varint.
    pub fn feedback_body_bytes(&self, now: Duration) -> Result<Option<usize>, RecoveryError> {
        let selected = self.engine.compact_selection(now, true, false)?;
        self.engine.compact_body_bytes(now, selected)
    }
    /// Conservative full-counter context-free local maximum; no wire context.
    pub fn send_max_body_bytes(&self) -> Result<usize, RecoveryError> {
        let state = self
            .engine
            .compact
            .as_ref()
            .ok_or(RecoveryError::InvalidConfig)?;
        Ok(
            (COMPACT_BODY_DATA_MAX_HEADER_BYTES + state.send.bounds.max_source_bytes).max(
                COMPACT_BODY_FEEDBACK_MAX_HEADER_BYTES + state.receive.maximum_feedback_bytes
                    - COMPACT_FEEDBACK_HEADER_BYTES,
            ),
        )
    }
    /// Conservative full-counter context-free peer maximum.
    pub fn receive_max_body_bytes(&self) -> Result<usize, RecoveryError> {
        let state = self
            .engine
            .compact
            .as_ref()
            .ok_or(RecoveryError::InvalidConfig)?;
        Ok(
            (COMPACT_BODY_DATA_MAX_HEADER_BYTES + state.receive.bounds.max_source_bytes).max(
                COMPACT_BODY_FEEDBACK_MAX_HEADER_BYTES + state.send.maximum_feedback_bytes
                    - COMPACT_FEEDBACK_HEADER_BYTES,
            ),
        )
    }
    /// Emit due feedback without emitting a source.
    pub fn poll_feedback(
        &mut self,
        now: Duration,
        output: &mut [u8],
    ) -> Result<Option<usize>, RecoveryError> {
        self.engine.poll_selected(now, output, true, false)
    }
    /// Emit a ready original, timeout retry or qualified fast retry.
    pub fn poll_source(
        &mut self,
        now: Duration,
        output: &mut [u8],
    ) -> Result<Option<usize>, RecoveryError> {
        self.engine.poll_selected(now, output, false, true)
    }
    /// Local output maximum, respecting the opposite direction's feedback policy.
    pub fn send_max_packet_bytes(&self) -> usize {
        self.send_maximum
    }
    /// Peer output maximum.
    pub fn receive_max_packet_bytes(&self) -> usize {
        self.receive_maximum
    }
    /// Largest either-direction packet.
    pub fn max_packet_bytes(&self) -> usize {
        self.send_max_packet_bytes()
            .max(self.receive_max_packet_bytes())
    }
    /// Actual selected backing; no packet-time allocation or allocator/RSS claim.
    pub fn storage_usage(&self) -> Option<crate::storage::Usage> {
        self.engine.storage_usage
    }
    /// Existing diagnostic counters from the same owner.
    pub fn statistics(&self) -> Statistics {
        self.engine.statistics
    }
    /// Actual shared payload retention.
    pub fn retained(&self) -> Retained {
        Retained {
            send_records: self.engine.sent.len(),
            send_bytes: self.engine.send_bytes,
            receive_records: self.engine.received.len(),
            receive_bytes: self.engine.receive_bytes,
        }
    }
    /// Exact selected sending data policy.
    pub fn send_config(&self) -> Result<CompactArqConfig, RecoveryError> {
        self.engine
            .compact
            .as_ref()
            .map(|state| state.send)
            .ok_or(RecoveryError::InvalidConfig)
    }
    /// Exact selected receiving data policy.
    pub fn receive_config(&self) -> Result<CompactArqConfig, RecoveryError> {
        self.engine
            .compact
            .as_ref()
            .map(|state| state.receive)
            .ok_or(RecoveryError::InvalidConfig)
    }
    /// Actual positive receipt, distinct from local whole-carrier handoff.
    pub fn source_confirmed(&self, source: SourceId) -> Result<bool, RecoveryError> {
        self.engine.running()?;
        Ok(source.0 < self.engine.next_source
            && self
                .engine
                .sent
                .get(&source)
                .is_none_or(|flight| flight.acknowledged))
    }
    /// Next actual source attempt opportunity.
    pub fn source_deadline(&self) -> Option<Duration> {
        self.engine.source_deadline()
    }
    /// Next ordinary or bounded-gap feedback opportunity.
    pub fn feedback_deadline(&self) -> Option<Duration> {
        self.engine.ack_at
    }
    /// Borrow actual retained received payloads, without minting native completion.
    pub fn received_sources(
        &self,
    ) -> Result<impl Iterator<Item = (SourceId, &[u8])>, RecoveryError> {
        self.engine.running()?;
        Ok(self
            .engine
            .received
            .iter()
            .map(|(source, bytes)| (*source, bytes.as_slice())))
    }
    /// Actual estimator snapshot with explicit nearest-nanosecond scheduling.
    pub fn timing(&self) -> Result<CompactTimingSnapshot, RecoveryError> {
        let state = self
            .engine
            .compact
            .as_ref()
            .ok_or(RecoveryError::InvalidConfig)?;
        Ok(CompactTimingSnapshot {
            sampled_serial: state.sampled,
            srtt_seconds: state.srtt,
            rttvar_seconds: state.rttvar,
            rto: state.rto()?,
        })
    }
    /// Sticky finite attempt/time failure, never successful drain.
    pub fn failure(&self) -> Option<RecoveryError> {
        self.engine.failure
    }
}
impl RecoveryEngine for CompactRepeat {
    type Error = RecoveryError;
    fn submit(&mut self, bytes: &[u8], now: Duration) -> Result<u64, RecoveryError> {
        self.engine.submit(bytes, now)
    }
    fn receive(&mut self, bytes: &[u8], now: Duration) -> Result<(), RecoveryError> {
        self.receive_at(bytes, now, now)
    }
    fn poll(&mut self, now: Duration, out: &mut [u8]) -> Result<Option<usize>, RecoveryError> {
        self.engine.poll(now, out)
    }
    fn poll_delivered(&mut self, out: &mut [u8]) -> Result<Option<(u64, usize)>, RecoveryError> {
        self.engine.poll_delivered(out)
    }
    fn deadline(&self) -> Option<Duration> {
        self.engine.deadline()
    }
    fn drained(&self) -> bool {
        self.engine.failure.is_none()
            && self.engine.sent.is_empty()
            && self.engine.received.is_empty()
            && self.engine.ack_at.is_none()
            && self.engine.pending_transmissions == 0
    }
}

fn storage_error(error: crate::storage::Error) -> RecoveryError {
    match error {
        crate::storage::Error::Recovery(error) => error,
        crate::storage::Error::Allocation => RecoveryError::Allocation,
        _ => RecoveryError::InvalidConfig,
    }
}
fn seconds_duration(seconds: f64) -> Result<Duration, RecoveryError> {
    Duration::try_from_secs_f64(seconds).map_err(|_| RecoveryError::TimeOverflow)
}
fn delay_micros(delay: Duration) -> Result<u64, RecoveryError> {
    let micros = (delay.as_secs_f64() * 1_000_000.0).round_ties_even();
    if !micros.is_finite() || !(0.0..18_446_744_073_709_551_616.0).contains(&micros) {
        return Err(RecoveryError::TimeOverflow);
    }
    Ok(micros as u64)
}
#[derive(Clone, Copy)]
enum Selection {
    Source {
        source: SourceId,
        required: usize,
    },
    Feedback {
        start: u64,
        count: u16,
        required: usize,
    },
}
impl Selection {
    fn bytes(self) -> usize {
        match self {
            Self::Source { required, .. } | Self::Feedback { required, .. } => required,
        }
    }
}

impl Engine {
    fn compact_source_blocked(&self, source: SourceId) -> Result<bool, RecoveryError> {
        let state = self.compact.as_ref().ok_or(RecoveryError::InvalidConfig)?;
        let flight = self
            .sent
            .get(&source)
            .ok_or(RecoveryError::MalformedPacket)?;
        // Capacity cannot conceal the selected source's finite attempt failure.
        if flight.attempts >= state.send.maximum_attempts {
            return Ok(false);
        }
        let serial = self
            .next_transmission
            .checked_add(1)
            .ok_or(RecoveryError::CounterExhausted)?;
        Ok(matches!(
            state.history_slot(serial),
            Err(RecoveryError::HistoryCapacity)
        ))
    }

    pub(super) fn compact_source_deadline(&self) -> Option<Duration> {
        let state = self.compact.as_ref()?;
        self.sent
            .iter()
            .filter(|(_, flight)| !flight.acknowledged && flight.transmission == 0)
            // No local timer frees a history slot: real peer feedback does.
            // Errors remain actionable so normal polling exposes fatal limits.
            .filter(|(source, _)| !self.compact_source_blocked(**source).unwrap_or(false))
            .filter_map(|(source, flight)| {
                if state.meta(*source).fast {
                    Some(self.last_now)
                } else {
                    flight
                        .retry_at
                        .or_else(|| (flight.attempts == 0).then_some(self.last_now))
                }
            })
            .min()
    }

    pub(super) fn compact_receive(
        &mut self,
        bytes: &[u8],
        received: Duration,
        observed: Duration,
    ) -> Result<(), RecoveryError> {
        self.check_time(observed)?;
        if received > observed {
            return Err(RecoveryError::NonMonotonicTime);
        }
        let state = self.compact.as_ref().ok_or(RecoveryError::InvalidConfig)?;
        // Source uses the receiving data policy; feedback describes our send policy.
        let policy = if bytes.get(6) == Some(&2) {
            state.send
        } else {
            state.receive
        };
        let view = parse_compact(bytes, self.context, policy)?;
        self.compact_receive_view(view, received, observed)
    }

    fn compact_receive_view(
        &mut self,
        view: CompactPacketView<'_>,
        received: Duration,
        observed: Duration,
    ) -> Result<(), RecoveryError> {
        self.check_time(observed)?;
        if received > observed {
            return Err(RecoveryError::NonMonotonicTime);
        }
        let state = self.compact.as_ref().ok_or(RecoveryError::InvalidConfig)?;
        view.validate_policy(match view {
            CompactPacketView::Data { .. } => state.receive,
            CompactPacketView::Feedback(_) => state.send,
        })?;
        match view {
            CompactPacketView::Data {
                source,
                serial,
                payload,
            } => {
                let due = received
                    .checked_add(state.receive.timing.feedback_interval)
                    .ok_or(RecoveryError::TimeOverflow)?;
                let events = state
                    .feedback_events
                    .checked_add(1)
                    .ok_or(RecoveryError::CounterExhausted)?;
                if let CompactRecovery::BoundedGap { min_interval } = state.receive.recovery
                    && let Some(at) = state.last_feedback
                {
                    at.checked_add(min_interval)
                        .ok_or(RecoveryError::TimeOverflow)?;
                }
                self.receive_source(source, payload, observed)?;
                let state = self.compact.as_mut().ok_or(RecoveryError::InvalidConfig)?;
                state.last_received_serial = serial;
                state.last_received_at = received;
                state.highest_received = Some(
                    state
                        .highest_received
                        .map_or(source.0, |old| old.max(source.0)),
                );
                state.feedback_events = events;
                state.feedback_repeats = 2;
                self.ack_at = Some(if events >= state.receive.timing.feedback_packets {
                    self.ack_at.map_or(observed, |old| old.min(observed))
                } else {
                    self.ack_at.map_or(due, |old| old.min(due))
                });
                if let CompactRecovery::BoundedGap { min_interval } = state.receive.recovery {
                    let later = self
                        .received
                        .keys()
                        .filter(|source| source.0 >= self.receive_prefix)
                        .count();
                    let allowed = state
                        .last_feedback
                        .and_then(|at| at.checked_add(min_interval));
                    if later >= 3
                        && state.notified_gap != Some(self.receive_prefix)
                        && state
                            .last_feedback
                            .is_none_or(|_| allowed.is_some_and(|at| observed >= at))
                    {
                        state.notified_gap = Some(self.receive_prefix);
                        self.ack_at = Some(self.ack_at.map_or(observed, |old| old.min(observed)));
                    }
                }
            }
            CompactPacketView::Feedback(feedback) => self.compact_feedback(feedback, received)?,
        }
        self.last_now = observed;
        Ok(())
    }

    fn compact_feedback(
        &mut self,
        feedback: CompactFeedback<'_>,
        arrival: Duration,
    ) -> Result<(), RecoveryError> {
        let state = self.compact.as_ref().ok_or(RecoveryError::InvalidConfig)?;
        if feedback.prefix > self.next_source
            || feedback
                .start
                .checked_add(u64::from(feedback.count))
                .is_none_or(|end| end > self.next_source)
            || feedback.echo > self.next_transmission
        {
            return Err(RecoveryError::UnsentAcknowledgement);
        }
        for offset in 0..usize::from(feedback.count) {
            if feedback.bit(offset) && feedback.start + offset as u64 >= self.next_source {
                return Err(RecoveryError::UnsentAcknowledgement);
            }
        }
        for (source, flight) in self.sent.iter() {
            if feedback.acknowledges(*source) {
                if flight.attempts == 0 {
                    return Err(RecoveryError::UnsentAcknowledgement);
                }
                if flight.attempts == 1 && flight.transmission != 0 {
                    return Err(RecoveryError::FeedbackAwaitingPhysical);
                }
            }
        }
        let sample = if feedback.echo > state.sampled {
            match state.history(feedback.echo) {
                Some(History { accepted: None, .. }) => {
                    return Err(RecoveryError::FeedbackAwaitingPhysical);
                }
                Some(History {
                    accepted: Some(at), ..
                }) => {
                    let sample = (arrival.as_secs_f64()
                        - at.as_secs_f64()
                        - feedback.receiver_delay_us as f64 / 1_000_000.0)
                        .max(0.0);
                    let (srtt, variance) = match state.srtt {
                        None => (sample, sample / 2.0),
                        Some(old) => (
                            0.875 * old + 0.125 * sample,
                            0.75 * state.rttvar + 0.25 * (old - sample).abs(),
                        ),
                    };
                    if state
                        .history
                        .iter()
                        .flatten()
                        .any(|entry| entry.serial <= feedback.echo && entry.accepted.is_none())
                    {
                        return Err(RecoveryError::FeedbackAwaitingPhysical);
                    }
                    state.rto_with(Some(srtt), variance)?;
                    Some((srtt, variance))
                }
                None => None,
            }
        } else {
            None
        };
        let srtt = sample.map(|value| value.0).or(state.srtt).unwrap_or(0.0);
        let guard = seconds_duration(
            state.send.timing.nominal_rtt.as_secs_f64().max(srtt)
                + 2.0 * state.send.timing.feedback_interval.as_secs_f64(),
        )?;
        // Preflight every potentially failing guard addition before ACK/RTT mutation.
        for (source, flight) in self.sent.iter() {
            if flight.transmission == 0
                && !feedback.acknowledges(*source)
                && let Some(at) = state.meta(*source).accepted
            {
                at.checked_add(guard).ok_or(RecoveryError::TimeOverflow)?;
            }
        }
        let state = self.compact.as_mut().ok_or(RecoveryError::InvalidConfig)?;
        if let Some((srtt, variance)) = sample {
            state.srtt = Some(srtt);
            state.rttvar = variance;
            state.sampled = feedback.echo;
            for entry in &mut state.history {
                if entry.is_some_and(|entry| entry.serial <= feedback.echo) {
                    *entry = None;
                }
            }
        }
        let mut released = 0;
        self.sent.retain(|source, flight| {
            if !feedback.acknowledges(*source) {
                return true;
            }
            state.meta_mut(*source).fast = false;
            if flight.transmission != 0 {
                flight.acknowledged = true;
                return true;
            }
            released += flight.payload.len();
            false
        });
        self.send_bytes -= released;
        state.base = self
            .sent
            .iter()
            .filter(|(_, flight)| !flight.acknowledged)
            .map(|(source, _)| source.0)
            .min()
            .unwrap_or(self.next_source);
        if feedback.serial > state.received_feedback_serial {
            state.received_feedback_serial = feedback.serial;
            let mut later = feedback
                .bitmap
                .iter()
                .map(|byte| byte.count_ones() as usize)
                .sum::<usize>();
            for offset in 0..usize::from(feedback.count) {
                if feedback.bit(offset) {
                    later -= 1;
                    continue;
                }
                if later < 3 {
                    continue;
                }
                let source = SourceId(feedback.start + offset as u64);
                let Some(flight) = self.sent.get(&source) else {
                    continue;
                };
                let meta = state.meta(source);
                if flight.transmission != 0
                    || flight.acknowledged
                    || flight.attempts == 0
                    || feedback.echo <= meta.serial
                {
                    continue;
                }
                let expedited = !matches!(state.send.recovery, CompactRecovery::Guarded)
                    && flight.attempts == 1;
                if expedited
                    || meta
                        .accepted
                        .is_some_and(|at| at.checked_add(guard).is_some_and(|due| arrival >= due))
                {
                    state.meta_mut(source).fast = true;
                }
            }
        }
        state.last_peer_feedback = Some(CompactPeerFeedbackSnapshot {
            arrival,
            prefix: feedback.prefix,
            start: feedback.start,
            count: feedback.count,
            echo: feedback.echo,
            receiver_delay_us: feedback.receiver_delay_us,
            serial: feedback.serial,
        });
        self.statistics.feedback_received = self.statistics.feedback_received.saturating_add(1);
        Ok(())
    }

    fn compact_selection(
        &self,
        now: Duration,
        allow_feedback: bool,
        allow_sources: bool,
    ) -> Result<Option<Selection>, RecoveryError> {
        self.check_time(now)?;
        let state = self.compact.as_ref().ok_or(RecoveryError::InvalidConfig)?;
        let source = allow_sources
            .then(|| {
                self.sent
                    .iter()
                    .filter(|(source, flight)| {
                        !flight.acknowledged
                            && flight.transmission == 0
                            && (flight.attempts == 0
                                || flight.retry_at.is_some_and(|at| at <= now)
                                || state.meta(**source).fast)
                    })
                    .map(|(source, flight)| {
                        (
                            if flight.attempts == 0 {
                                2
                            } else if state.meta(*source).fast {
                                0
                            } else {
                                1
                            },
                            flight.retry_at.unwrap_or(now),
                            *source,
                        )
                    })
                    .min()
                    .map(|(_, _, source)| source)
            })
            .flatten();
        let feedback = allow_feedback && self.ack_at.is_some_and(|at| at <= now);
        if feedback && (!self.prefer_data || source.is_none()) {
            let mut start = self.receive_prefix.max(state.bitmap_cursor);
            if state.highest_received.is_none_or(|highest| start > highest) {
                start = self.receive_prefix;
            }
            let available = state
                .highest_received
                .map_or(0, |highest| (highest + 1).saturating_sub(start));
            let capacity =
                (state.receive.maximum_feedback_bytes - COMPACT_FEEDBACK_HEADER_BYTES) * 8;
            let count = available.min(capacity.min(MAX_WINDOW) as u64) as u16;
            let required = COMPACT_FEEDBACK_HEADER_BYTES + usize::from(count).div_ceil(8);
            return Ok(Some(Selection::Feedback {
                start,
                count,
                required,
            }));
        }
        let Some(source) = source else {
            return Ok(None);
        };
        let flight = self
            .sent
            .get(&source)
            .ok_or(RecoveryError::MalformedPacket)?;
        let required = COMPACT_DATA_HEADER_BYTES
            .checked_add(flight.payload.len())
            .ok_or(RecoveryError::SourceTooLarge)?;
        Ok(Some(Selection::Source { source, required }))
    }

    fn compact_body_bytes(
        &self,
        now: Duration,
        selected: Option<Selection>,
    ) -> Result<Option<usize>, RecoveryError> {
        let state = self.compact.as_ref().ok_or(RecoveryError::InvalidConfig)?;
        match selected {
            Some(Selection::Source { source, .. }) => {
                let flight = self
                    .sent
                    .get(&source)
                    .ok_or(RecoveryError::MalformedPacket)?;
                let serial = self
                    .next_transmission
                    .checked_add(1)
                    .ok_or(RecoveryError::CounterExhausted)?;
                CompactPacketView::Data {
                    source,
                    serial,
                    payload: &flight.payload,
                }
                .compact_encoded_len()
                .map(Some)
            }
            Some(Selection::Feedback { start, count, .. }) => {
                let serial = state
                    .feedback_serial
                    .checked_add(1)
                    .ok_or(RecoveryError::CounterExhausted)?;
                let delay = delay_micros(
                    now.checked_sub(state.last_received_at)
                        .ok_or(RecoveryError::NonMonotonicTime)?,
                )?;
                Ok(Some(body::feedback_body_len(
                    self.receive_prefix,
                    start,
                    count,
                    state.last_received_serial,
                    delay,
                    serial,
                )))
            }
            None => Ok(None),
        }
    }

    pub(super) fn compact_poll(
        &mut self,
        now: Duration,
        output: &mut [u8],
        allow_feedback: bool,
        allow_sources: bool,
    ) -> Result<Option<usize>, RecoveryError> {
        let selected = self.compact_selection(now, allow_feedback, allow_sources)?;
        let state = self.compact.as_ref().ok_or(RecoveryError::InvalidConfig)?;
        let context = self.context;
        let result = match selected {
            Some(Selection::Feedback { required, .. }) => {
                // Preserve the legacy serial/output/time error precedence.
                state
                    .feedback_serial
                    .checked_add(1)
                    .ok_or(RecoveryError::CounterExhausted)?;
                ensure_output(output, required)?;
                let mode = state.receive.recovery;
                let (header, bitmap) =
                    output[..required].split_at_mut(COMPACT_FEEDBACK_HEADER_BYTES);
                self.compact_emit_with(now, selected, bitmap, false, |view| {
                    view.encode_legacy_header(context, mode, header)?;
                    Ok(Some(required))
                })
            }
            Some(Selection::Source { source, required }) => {
                let flight = self
                    .sent
                    .get(&source)
                    .ok_or(RecoveryError::MalformedPacket)?;
                if flight.attempts >= state.send.maximum_attempts {
                    let error = RecoveryError::RetryExhausted { source };
                    self.note_compact_retry_failure(source, now);
                    self.failure = Some(error);
                    return Err(error);
                }
                ensure_output(output, required)?;
                let mode = state.send.recovery;
                self.compact_emit_with(now, selected, &mut [], false, |view| {
                    view.encode_legacy_into(context, mode, output).map(Some)
                })
            }
            None => {
                self.last_now = now;
                return Ok(None);
            }
        };
        result.map_err(|error| match error {
            CompactPollError::Recovery(error) | CompactPollError::Encode(error) => error,
        })
    }

    // The callback sees the actual borrowed source/bitmap. Its Some result is
    // the only output commit point for both serializers; None/errors preserve
    // attempt, history, feedback cursor and physical custody.
    fn compact_emit_with<T, E>(
        &mut self,
        now: Duration,
        selected: Option<Selection>,
        bitmap: &mut [u8],
        compact_body: bool,
        encode: impl FnOnce(CompactPacketView<'_>) -> Result<Option<T>, E>,
    ) -> Result<Option<T>, CompactPollError<E>> {
        let state = self.compact.as_ref().ok_or(RecoveryError::InvalidConfig)?;
        if let Some(Selection::Feedback { start, count, .. }) = selected {
            let serial = state
                .feedback_serial
                .checked_add(1)
                .ok_or(RecoveryError::CounterExhausted)?;
            let delay = delay_micros(
                now.checked_sub(state.last_received_at)
                    .ok_or(RecoveryError::NonMonotonicTime)?,
            )?;
            let next_feedback = if state.feedback_repeats > 0 {
                Some(
                    now.checked_add(state.receive.timing.feedback_interval)
                        .ok_or(RecoveryError::TimeOverflow)?,
                )
            } else {
                None
            };
            let bitmap_bytes = usize::from(count).div_ceil(8);
            ensure_output(bitmap, bitmap_bytes)?;
            let bitmap = &mut bitmap[..bitmap_bytes];
            bitmap.fill(0);
            for offset in 0..usize::from(count) {
                if self.received.contains_key(&SourceId(start + offset as u64)) {
                    bitmap[offset / 8] |= 1 << (offset % 8);
                }
            }
            let view = CompactPacketView::Feedback(CompactFeedback {
                prefix: self.receive_prefix,
                start,
                count,
                echo: state.last_received_serial,
                receiver_delay_us: delay,
                serial,
                bitmap,
            });
            let required = if compact_body {
                view.compact_encoded_len()?
            } else {
                view.legacy_encoded_len()?
            };
            let Some(result) = encode(view).map_err(CompactPollError::Encode)? else {
                return Ok(None);
            };
            let state = self.compact.as_mut().ok_or(RecoveryError::InvalidConfig)?;
            state.bitmap_cursor = start + u64::from(count);
            if state
                .highest_received
                .is_none_or(|highest| state.bitmap_cursor > highest)
            {
                state.bitmap_cursor = self.receive_prefix;
            }
            state.feedback_serial = serial;
            state.feedback_events = 0;
            state.feedback_repeats = state.feedback_repeats.saturating_sub(1);
            state.last_feedback = Some(now);
            self.ack_at = next_feedback;
            self.prefer_data = true;
            self.last_now = now;
            self.statistics.feedback_sent = self.statistics.feedback_sent.saturating_add(1);
            self.statistics.wire_bytes_emitted = self
                .statistics
                .wire_bytes_emitted
                .saturating_add(required as u64);
            return Ok(Some(result));
        }
        let Some(Selection::Source { source, .. }) = selected else {
            self.last_now = now;
            return Ok(None);
        };
        let flight = self
            .sent
            .get(&source)
            .ok_or(RecoveryError::MalformedPacket)?;
        if flight.attempts >= state.send.maximum_attempts {
            let error = RecoveryError::RetryExhausted { source };
            self.note_compact_retry_failure(source, now);
            self.failure = Some(error);
            return Err(error.into());
        }
        let serial = self
            .next_transmission
            .checked_add(1)
            .ok_or(RecoveryError::CounterExhausted)?;
        let history_index = state.history_slot(serial)?;
        let rto = state.rto()?;
        now.checked_add(rto).ok_or(RecoveryError::TimeOverflow)?;
        let view = CompactPacketView::Data {
            source,
            serial,
            payload: &flight.payload,
        };
        let required = if compact_body {
            view.compact_encoded_len()?
        } else {
            view.legacy_encoded_len()?
        };
        let Some(result) = encode(view).map_err(CompactPollError::Encode)? else {
            return Ok(None);
        };
        let flight = self
            .sent
            .get_mut(&source)
            .ok_or(RecoveryError::MalformedPacket)?;
        let retry = flight.attempts > 0;
        flight.attempts += 1;
        flight.prepared_at = now;
        flight.transmission = serial;
        flight.retry_at = None;
        flight.rto = rto;
        let state = self.compact.as_mut().ok_or(RecoveryError::InvalidConfig)?;
        state.history[history_index] = Some(History {
            serial,
            accepted: None,
        });
        let old = *state.meta(source);
        *state.meta_mut(source) = Meta {
            source: Some(source),
            serial,
            accepted: if old.source == Some(source) {
                old.accepted
            } else {
                None
            },
            fast: false,
        };
        self.next_transmission = serial;
        self.pending_transmissions += 1;
        self.prefer_data = false;
        self.last_now = now;
        self.statistics.transmissions = self.statistics.transmissions.saturating_add(1);
        self.statistics.retransmissions = self
            .statistics
            .retransmissions
            .saturating_add(u64::from(retry));
        self.statistics.wire_bytes_emitted = self
            .statistics
            .wire_bytes_emitted
            .saturating_add(required as u64);
        Ok(Some(result))
    }
}

#[cfg(test)]
#[path = "compact/python_differential.rs"]
mod python_differential;
#[cfg(test)]
mod tests;
