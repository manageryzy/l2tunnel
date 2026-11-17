//! Scalar evidence from the actual failed owner; never retry or admission authority.
use super::*;

/// Header facts from the last successfully applied peer feedback. No bitmap or
/// payload is retained. Arrival is the caller's original authenticated time.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CompactPeerFeedbackSnapshot {
    /// Original authenticated arrival of this successfully applied feedback.
    pub arrival: Duration,
    /// Peer-reported contiguous receipt prefix.
    pub prefix: u64,
    /// First source represented in the omitted bitmap.
    pub start: u64,
    /// Number of meaningful bits in the omitted bitmap.
    pub count: u16,
    /// Peer-echoed transmission serial.
    pub echo: u64,
    /// Peer-reported delay subtracted by the existing RTT estimator.
    pub receiver_delay_us: u64,
    /// Actual feedback serial; this may be older than the maximum applied serial.
    pub serial: u64,
}

/// Allocation-free evidence for a sticky CompactARQ RetryExhausted failure.
/// All times are injected Duration values from this owner's existing clock domain.
/// The getter never advances time, retries, clears custody or invents peer delivery.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct CompactRetryFailureSnapshot {
    /// Exact source reported by the actual RetryExhausted transition.
    pub source: SourceId,
    /// Exact injected poll time which first detected the finite attempt failure.
    pub failed_at: Duration,
    /// Last successful engine clock update before that failed poll.
    pub last_successful_at: Duration,
    /// Attempts actually prepared, including the original.
    pub attempts: u32,
    /// Unchanged negotiated total attempt limit.
    pub maximum_attempts: u32,
    /// Original retained source payload length; no bytes are exposed.
    pub source_bytes: usize,
    /// Last prepared source attempt's wire serial.
    pub attempt_serial: u64,
    /// Last attempt's original local preparation time.
    pub prepared_at: Duration,
    /// Last attempt's confirmed whole-carrier acceptance, if available.
    pub accepted_at: Option<Duration>,
    /// Actual armed retry deadline for that attempt.
    pub retry_at: Option<Duration>,
    /// RTO captured when that attempt was prepared, before physical acceptance.
    pub attempt_rto: Duration,
    /// Existing fast-retry flag at failure; it can coexist with an elapsed RTO.
    pub fast: bool,
    /// Whether a prepared attempt still has unconsumed physical custody.
    pub physical_pending: bool,
    /// Actual positive peer acknowledgement state of the retained source.
    pub acknowledged: bool,
    /// Oldest unconfirmed outgoing source used for the current send-window base.
    pub send_base: u64,
    /// Next original outgoing source identity.
    pub next_source: u64,
    /// Next source-attempt allocator value already used by this owner.
    pub latest_transmission_serial: u64,
    /// Actual retained source counts and bytes, separate from native delivery.
    pub retained: Retained,
    /// Unchanged outgoing source and byte bounds.
    pub send_bounds: CompactBounds,
    /// Unchanged incoming source and byte bounds.
    pub receive_bounds: CompactBounds,
    /// Local contiguous incoming source receipt prefix.
    pub receive_prefix: u64,
    /// Next incoming source waiting for ordered local delivery.
    pub deliver_next: u64,
    /// Highest incoming source accepted by this recovery owner.
    pub highest_received: Option<u64>,
    /// Most recently applied peer feedback header; not a history or bitmap.
    pub last_peer_feedback: Option<CompactPeerFeedbackSnapshot>,
    /// Maximum peer feedback serial applied, independent of reordered headers.
    pub maximum_peer_feedback_serial: u64,
    /// Next local recovery feedback opportunity, if armed.
    pub local_feedback_at: Option<Duration>,
    /// Last locally emitted recovery feedback serial.
    pub local_feedback_serial: u64,
    /// Receipt events since the last local feedback output.
    pub local_feedback_events: usize,
    /// Remaining ordinary local lossy feedback repeats.
    pub local_feedback_repeats: u8,
    /// Last local feedback preparation time, not whole-carrier acceptance.
    pub last_local_feedback_at: Option<Duration>,
    /// Existing estimator snapshot; an observation error stays explicit.
    pub timing: Result<CompactTimingSnapshot, RecoveryError>,
    /// Existing source/attempt/receipt counters; no new event log is maintained.
    pub statistics: Statistics,
}

impl CompactRepeat {
    /// Read scalar state captured at the actual failure, including when later
    /// terminal physical settlement changes live custody. No failure means None.
    pub fn retry_failure_snapshot(&self) -> Option<CompactRetryFailureSnapshot> {
        self.engine.compact.as_ref()?.retry_failure
    }
}

impl Engine {
    pub(super) fn note_compact_retry_failure(&mut self, source: SourceId, now: Duration) {
        let Some(state) = self.compact.as_ref() else {
            return;
        };
        if state.retry_failure.is_some() {
            return;
        }
        let Some(flight) = self.sent.get(&source) else {
            return;
        };
        let metadata = state.meta(source);
        let snapshot = CompactRetryFailureSnapshot {
            source,
            failed_at: now,
            last_successful_at: self.last_now,
            attempts: flight.attempts,
            maximum_attempts: state.send.maximum_attempts,
            source_bytes: flight.payload.len(),
            attempt_serial: metadata.serial,
            prepared_at: flight.prepared_at,
            accepted_at: metadata.accepted,
            retry_at: flight.retry_at,
            attempt_rto: flight.rto,
            fast: metadata.fast,
            physical_pending: flight.transmission != 0,
            acknowledged: flight.acknowledged,
            send_base: state.base,
            next_source: self.next_source,
            latest_transmission_serial: self.next_transmission,
            retained: Retained {
                send_records: self.sent.len(),
                send_bytes: self.send_bytes,
                receive_records: self.received.len(),
                receive_bytes: self.receive_bytes,
            },
            send_bounds: state.send.bounds,
            receive_bounds: state.receive.bounds,
            receive_prefix: self.receive_prefix,
            deliver_next: self.deliver_next,
            highest_received: state.highest_received,
            last_peer_feedback: state.last_peer_feedback,
            maximum_peer_feedback_serial: state.received_feedback_serial,
            local_feedback_at: self.ack_at,
            local_feedback_serial: state.feedback_serial,
            local_feedback_events: state.feedback_events,
            local_feedback_repeats: state.feedback_repeats,
            last_local_feedback_at: state.last_feedback,
            timing: state.rto().map(|rto| CompactTimingSnapshot {
                sampled_serial: state.sampled,
                srtt_seconds: state.srtt,
                rttvar_seconds: state.rttvar,
                rto,
            }),
            statistics: self.statistics,
        };
        if let Some(state) = self.compact.as_mut() {
            state.retry_failure = Some(snapshot);
        }
    }
}
