//! Bounded scalar observations. Counters never grant protocol authority.
use super::compact::{FinalKind, FinalOutputToken};
use tokio::time::Instant;

/// Packet and payload-byte observations, saturated independently at `u64::MAX`.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PacketCount {
    /// Number of candidates, not socket wait episodes.
    pub packets: u64,
    /// Protected TCP payload bytes; excludes IPv4/TCP headers.
    pub payload_bytes: u64,
}
impl PacketCount {
    pub(super) fn record(&mut self, bytes: usize) {
        self.packets = self.packets.saturating_add(1);
        self.payload_bytes = self.payload_bytes.saturating_add(bytes as u64);
    }
}

/// Cumulative observations for one untrusted candidate class.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CandidateCounters {
    /// Candidates admitted to bounded custody.
    pub admitted: PacketCount,
    /// Rejections because the candidate class or shared allowance was full.
    pub capacity_refused: PacketCount,
    /// Rejections by raw geometry/range preflight, before a verifier verdict.
    pub preflight_rejected: PacketCount,
    /// Rejections by the sole Records verifier, including authentication/replay failure.
    pub verifier_rejected: PacketCount,
    /// Candidates accepted by the sole Records verifier and raw owner.
    pub accepted: PacketCount,
    /// Maximum simultaneous candidates of this class, excluding bootstrap custody.
    pub high_water_packets: usize,
    /// Maximum simultaneous protected payload bytes of this class.
    pub high_water_payload_bytes: usize,
}

/// One untrusted class. A priority label only schedules verification opportunities.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CandidateBufferSnapshot {
    /// Maximum candidate slots usable by this class, shared where explicitly marked.
    pub capacity_packets: usize,
    /// Maximum protected payload bytes in those slots, before bootstrap sharing.
    pub capacity_payload_bytes: usize,
    /// Candidates currently awaiting a consumed verifier verdict.
    pub queued_packets: usize,
    /// Protected payload bytes currently retained for those candidates.
    pub queued_payload_bytes: usize,
    /// Age at the snapshot boundary of this class's oldest original arrival.
    pub oldest_age_micros: Option<u64>,
    /// Lifetime class observations; drops are not blocking episodes.
    pub counters: CandidateCounters,
}

/// Actual reason that an otherwise valid final prepare could not reserve its lane.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FinalPrepareBlocked {
    /// The lane already holds an output or an unconsumed completion witness.
    LocalCustody {
        /// An encoded output remains owned.
        pending: bool,
        /// The PacketIo wrapper retains an exact pending send identity.
        packet_io_pending: bool,
        /// An uncommitted final reservation remains owned.
        prepared: bool,
        /// The upper caller has not consumed its physical completion token.
        tracked: bool,
        /// A physical completion receipt remains owned.
        completed: bool,
    },
    /// The requested extent exceeds the authenticated peer horizon after reserve.
    PeerHorizon {
        /// End of the requested extent relative to the local sequence origin.
        requested_end: u64,
        /// Greatest permitted end after this kind's fixed reserve.
        allowed_end: u64,
        /// Current allocated extent end.
        allocated: u64,
        /// Latest authenticated peer retirement.
        peer_retired: u64,
        /// Negotiated peer horizon.
        horizon_bytes: u64,
        /// Fixed bytes reserved for higher-priority kinds.
        reserved_bytes: u64,
    },
    /// The existing ping identity/retry rule refused this attempt.
    ControlRetry,
}

/// One pre-seal result. A blocked attempt has consumed no nonce or extent.
pub enum FinalPrepareOutcome {
    /// Exact metadata reservation owned by the caller.
    Ready(FinalOutputToken),
    /// Observed refusal; this does not claim a socket wait or future progress.
    Blocked(FinalPrepareBlocked),
}

/// Per-kind prepare observations, not inferred waiting duration.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PrepareSnapshot {
    /// Successful reservations.
    pub ready: u64,
    /// Attempts refused by retained local custody.
    pub local_custody_refusals: u64,
    /// Attempts refused by the authenticated peer horizon.
    pub peer_horizon_refusals: u64,
    /// Attempts refused by the existing control retry rule.
    pub control_retry_refusals: u64,
    /// Latest observed refusal; historical even after a later successful reservation.
    pub last_refusal: Option<FinalPrepareBlocked>,
}
impl PrepareSnapshot {
    pub(super) fn refuse(&mut self, reason: FinalPrepareBlocked) {
        let count = match reason {
            FinalPrepareBlocked::LocalCustody { .. } => &mut self.local_custody_refusals,
            FinalPrepareBlocked::PeerHorizon { .. } => &mut self.peer_horizon_refusals,
            FinalPrepareBlocked::ControlRetry => &mut self.control_retry_refusals,
        };
        *count = count.saturating_add(1);
        self.last_refusal = Some(reason);
    }
}
pub(super) const fn prepare_index(kind: FinalKind) -> usize {
    match kind {
        FinalKind::Data => 0,
        FinalKind::Feedback => 1,
        FinalKind::Control => 2,
        FinalKind::CarrierControl => 3,
    }
}

/// Send-boundary observations. Local scheduling refusals are separate from PacketIo.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SendIoSnapshot {
    /// Send attempts refused by the local per-turn work quota, before PacketIo.
    pub turn_budget_refusals: u64,
    /// Send attempts refused by local byte/packet pacing, before PacketIo.
    pub pacing_refusals: u64,
    /// Actual calls to the owned PacketIo send method.
    pub packet_io_attempts: u64,
    /// Actual PacketIo sends returning `WouldBlock`.
    pub would_block_observations: u64,
    /// Runs starting at an actual PacketIo `WouldBlock`; local refusals do not start runs.
    pub would_block_episodes: u64,
    /// Open runs ended by actual PacketIo success.
    pub resumed_episodes: u64,
    /// Open runs ended by explicit pending-send cancellation.
    pub cancelled_episodes: u64,
    /// An actual PacketIo refusal has not yet been followed by success/cancellation.
    pub blocked: bool,
}
impl SendIoSnapshot {
    pub(super) fn would_block(&mut self) {
        self.would_block_observations = self.would_block_observations.saturating_add(1);
        if !self.blocked {
            self.would_block_episodes = self.would_block_episodes.saturating_add(1);
        }
        self.blocked = true;
    }
    pub(super) fn success(&mut self) {
        if self.blocked {
            self.resumed_episodes = self.resumed_episodes.saturating_add(1);
        }
        self.blocked = false;
    }
    pub(super) fn cancel(&mut self) {
        if self.blocked {
            self.cancelled_episodes = self.cancelled_episodes.saturating_add(1);
        }
        self.blocked = false;
    }
}

/// Exact lane custody and horizon observations at one finite boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LaneBufferSnapshot {
    /// Carrier-control candidates, sharing four slots with bootstrap control.
    pub carrier_control: CandidateBufferSnapshot,
    /// Upper-control candidates.
    pub upper_control: CandidateBufferSnapshot,
    /// Data and feedback candidates, sharing with authenticated bootstrap records.
    pub bulk: CandidateBufferSnapshot,
    /// Actual combined final candidate allowance, including the four control slots.
    pub candidate_capacity_packets: usize,
    /// At queue capacity one, upper control and bulk share their one reported slot.
    pub upper_bulk_shared_slot: bool,
    /// Authenticated bootstrap records retaining slots from the bulk allowance.
    pub bootstrap_records_outstanding: usize,
    /// Bootstrap-control cells currently sharing the four carrier-control slots.
    pub bootstrap_control_queued: usize,
    /// All gate rejections, including unclassified malformed packets and bootstrap traffic.
    pub total_gate_rejected_packets: u64,
    /// Currently pinned untrusted kind, awaiting a consumed verdict.
    pub selected_kind: Option<FinalKind>,
    /// Original-arrival age of that pinned candidate, not time spent running crypto.
    pub selected_age_micros: Option<u64>,
    /// Exact negotiated local receive horizon, if the fence is installed.
    pub local_horizon_bytes: Option<u64>,
    /// Exact negotiated peer receive horizon, if the fence is installed.
    pub peer_horizon_bytes: Option<u64>,
    /// Allocated output bytes not yet retired by authenticated peer reports.
    pub send_debt_bytes: Option<u64>,
    /// Latest local receive retirement relative to the original sequence origin.
    pub retired_bytes: Option<u64>,
    /// Protected output payload bytes in an uncommitted reservation.
    pub prepared_payload_bytes: usize,
    /// Actual encoded IPv4/TCP bytes retained by the pending output owner.
    pub pending_ip_bytes: usize,
    /// Whether the exact physical send identity remains pending.
    pub packet_io_pending: bool,
    /// Whether a tracked output token remains owned.
    pub tracked: bool,
    /// Whether a physical completion receipt remains owned.
    pub completed: bool,
    /// Data, feedback, upper-control, carrier-control prepare observations, in that order.
    pub prepare: [PrepareSnapshot; 4],
    /// Actual PacketIo and separate local scheduling observations.
    pub send_io: SendIoSnapshot,
}

/// Snapshot does no I/O and grants no replay, credit, delivery or liveness authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BufferSnapshot {
    /// Observation boundary; terminal snapshots retain their original timestamp and ages.
    pub captured_at: Instant,
    /// True when captured immediately before terminal owner release.
    pub terminal: bool,
    /// Present original lanes. Missing lanes are distinct from unavailable observations.
    pub lanes: [Option<LaneBufferSnapshot>; 2],
    /// Bit `i` means the original lane existed but its state lock was unavailable.
    pub unavailable_lanes: u8,
}
pub(super) fn age_micros(now: Instant, then: Instant) -> u64 {
    now.saturating_duration_since(then)
        .as_micros()
        .min(u128::from(u64::MAX)) as u64
}

#[cfg(test)]
#[path = "diagnostics_tests.rs"]
mod tests;
