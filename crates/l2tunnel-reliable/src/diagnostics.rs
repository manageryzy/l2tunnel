//! Bounded observations of actual retained block output, using caller-injected time.
//! Packing delay, missing equations and physical custody are not inferred waits.
use super::{EndpointRole, RecoveryContext};
use std::time::Duration;
#[path = "staged_diagnostics.rs"]
pub mod staged;

/// Operational block staging bounds; byte reservations are not queue capacities.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Buffers {
    /// Configured maximum sources in the one partial block; zero with no repair policy.
    /// Independent of whether the encoder backing is reserved or created lazily.
    pub building_packets_capacity: usize,
    /// Original partial-block flush deadline; deliberate packing hold, not blockage.
    pub building_deadline: Option<Duration>,
    /// Configured sealed systematic and repair slots for the one outgoing block.
    pub outbound_packets_capacity: usize,
    /// Maximum encoded bytes of one output; no independent aggregate byte budget exists.
    pub outbound_packet_bytes_maximum: usize,
    /// Actual restored-source admission count bound.
    pub restored_packets_capacity: usize,
    /// Actual restored-source admission byte bound, including recovery headers.
    pub restored_bytes_capacity: usize,
    /// Main/independent-feedback slot occupancy; these are custody, not blocked time.
    pub physical_packets: [usize; 2],
    /// Exact caller-held body bytes of these same two slots.
    pub physical_bytes: [usize; 2],
    /// Per-slot operational capacity; zero when physical confirmation is not enabled.
    pub physical_packets_capacity: usize,
    /// Whether this policy actually constructed a receive decoder.
    pub decoder_present: bool,
    /// Detailed metadata scan, present only when the decoder and opt-in sidecar exist.
    /// Disabled diagnostic owners do not walk live generations during ordinary status.
    pub decoder: Option<l2tunnel_fec::DecoderBuffers>,
}

/// Existing immutable outgoing symbol identity within this recovery owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Operation {
    /// Complete generation, without modular truncation.
    pub generation: u64,
    /// Complete systematic/repair symbol ID.
    pub symbol: u32,
    /// Exact encoded output body bytes.
    pub bytes: usize,
}
/// Completed and censored refusal-to-progress populations, never added across reasons.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Totals {
    /// Successfully emitted previously refused symbols.
    pub completed_episodes: u64,
    /// Sum of completed observed durations, including scheduling delay.
    pub completed: Duration,
    /// Longest completed observed duration.
    pub maximum_completed: Duration,
    /// Unresolved symbols frozen at a fresh terminal observation.
    pub censored_episodes: u64,
    /// Sum of observed censored portions.
    pub censored: Duration,
    /// Longest observed censored portion.
    pub maximum_censored: Duration,
}
/// One exact retained queue head; it is never replaced by a guessed next symbol.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Pending {
    /// Actual canonical encoded head identity.
    pub operation: Operation,
    /// First refusal time, never renewed by a repeated attempt.
    pub since: Duration,
    /// Latest actual refusal.
    pub last_refusal: Duration,
    /// Packet-budget and wire-byte-budget first refusals, respectively.
    pub reasons_since: [Option<Duration>; 2],
}
/// Last progress or terminal identity only; there is no per-event history.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Resolved {
    /// Exact emitted or censored head.
    pub operation: Operation,
    /// First refusal.
    pub since: Duration,
    /// Actual emission or terminal sample, not physical acceptance.
    pub at: Duration,
    /// True when the symbol was not emitted before observation stopped.
    pub censored: bool,
}
/// One optional bounded sidecar. Outer providers retain epoch/config/owner labels.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Snapshot {
    /// Complete recovery epoch.
    pub epoch: u64,
    /// Original sender role: initiator 0, responder 1.
    pub send_direction: u8,
    /// True only when this sender constructed the sealed Block FEC output queue.
    /// Direct ARQ capacity counters remain available, but its output wait is unmeasured.
    pub sealed_output_present: bool,
    /// Injected observation tick.
    pub observed_at: Duration,
    /// Fresh terminal sample, absent while live. No owner error is rewritten.
    pub terminal_at: Option<Duration>,
    /// Actual repeated refusal counts: packet allowance, then wire-byte allowance.
    pub refusals: [u64; 2],
    /// Overlapping per-reason refusal-to-same-symbol-emission populations.
    pub reasons: [Totals; 2],
    /// One-head union, not the sum of the two reasons.
    pub union: Totals,
    /// Actual unresolved immutable head.
    pub pending: Option<Pending>,
    /// Last resolved head only.
    pub last_resolved: Option<Resolved>,
    /// Actual input refusals only: decoder symbol slots, generation slots, logical
    /// reservation, restored packet slots, restored byte budget. These are not waits.
    pub capacity_refusals: [u64; 5],
    /// Opt-in same-source identity and actual gate/retirement observations.
    pub staged: staged::Snapshot,
    /// Diagnostic time regressed; no protocol clock is changed.
    pub clock_regression: bool,
    /// Actual head identity differed before corresponding progress.
    pub identity_mismatch: bool,
    /// Counter/duration overflow makes the diagnostic invalid, never the protocol.
    pub overflow: bool,
}
impl Snapshot {
    pub(crate) fn new(context: RecoveryContext, sealed_output_present: bool) -> Self {
        Self {
            epoch: context.epoch,
            send_direction: match context.role {
                EndpointRole::Initiator => 0,
                EndpointRole::Responder => 1,
            },
            sealed_output_present,
            observed_at: Duration::ZERO,
            terminal_at: None,
            refusals: [0; 2],
            reasons: [Totals::default(); 2],
            union: Totals::default(),
            pending: None,
            last_resolved: None,
            capacity_refusals: [0; 5],
            staged: staged::Snapshot::default(),
            clock_regression: false,
            identity_mismatch: false,
            overflow: false,
        }
    }
    pub(crate) fn source_refused(
        &mut self,
        now: Duration,
        gate: l2tunnel_recovery::AdmissionSnapshot,
    ) {
        if self.observe(now) {
            self.staged.refused(now, gate);
        }
    }
    pub(crate) fn source_admitted(&mut self, source: u64, bytes: usize, now: Duration) {
        if self.observe(now) {
            self.staged.admitted(source, bytes, now);
        }
    }
    pub(crate) fn source_ack(
        &mut self,
        view: l2tunnel_recovery::PacketView<'_>,
        before: Option<staged::AckBoundary>,
        after: Option<staged::AckBoundary>,
        received: Duration,
        observed: Duration,
    ) {
        if self.observe(observed) {
            self.staged.ack(view, before, after, received, observed);
        }
    }
    pub(crate) fn source_retired(
        &mut self,
        before: l2tunnel_recovery::Retained,
        after: l2tunnel_recovery::Retained,
        now: Duration,
        accepted: Option<Duration>,
        kind: staged::RetirementKind,
        succeeded: bool,
    ) {
        if after.send_records < before.send_records || after.send_bytes < before.send_bytes {
            // Keep the actual irreversible release even if the original operation
            // reports a clock error. Only diagnostic validity changes here.
            self.observe(now);
            self.staged
                .retired(before, after, now, accepted, kind, succeeded);
        }
    }
    fn observe(&mut self, now: Duration) -> bool {
        if self.terminal_at.is_some() {
            return false;
        }
        if now < self.observed_at {
            self.clock_regression = true;
            return false;
        }
        self.observed_at = now;
        true
    }
    /// Sample a fresh read-only owner state at a caller-owned clock boundary.
    pub fn observed(mut self, now: Duration) -> Self {
        self.observe(now);
        self
    }
    /// Freeze a fresh read-only terminal sample without claiming output progress.
    /// A cached snapshot must retain its own older observation boundary instead.
    pub fn censor(mut self, now: Duration) -> Self {
        if self.observe(now) {
            self.staged.censor(now);
            self.close(now, true);
            self.terminal_at = Some(now);
        }
        self
    }
    pub(crate) fn capacity_refused(&mut self, index: usize, now: Duration) {
        if !self.observe(now) {
            return;
        }
        if let Some(count) = self.capacity_refusals.get_mut(index) {
            increment(count, &mut self.overflow);
        } else {
            self.identity_mismatch = true;
        }
    }
    pub(crate) fn refused(&mut self, op: Operation, now: Duration, reasons: [bool; 2]) {
        if !self.observe(now) {
            return;
        }
        let pending = self.pending.get_or_insert(Pending {
            operation: op,
            since: now,
            last_refusal: now,
            reasons_since: [None; 2],
        });
        if pending.operation != op {
            self.identity_mismatch = true;
            return;
        }
        pending.last_refusal = now;
        for (index, refused) in reasons.into_iter().enumerate() {
            if refused {
                increment(&mut self.refusals[index], &mut self.overflow);
                pending.reasons_since[index].get_or_insert(now);
            }
        }
    }
    pub(crate) fn progress(&mut self, op: Operation, now: Duration) {
        if !self.observe(now) {
            return;
        }
        let Some(pending) = self.pending else {
            return;
        };
        if pending.operation != op {
            self.identity_mismatch = true;
            return;
        }
        self.close(now, false);
    }
    fn close(&mut self, now: Duration, censored: bool) {
        let Some(pending) = self.pending.take() else {
            return;
        };
        add(
            &mut self.union,
            now - pending.since,
            censored,
            &mut self.overflow,
        );
        for (totals, since) in self.reasons.iter_mut().zip(pending.reasons_since) {
            if let Some(since) = since {
                add(totals, now - since, censored, &mut self.overflow);
            }
        }
        self.last_resolved = Some(Resolved {
            operation: pending.operation,
            since: pending.since,
            at: now,
            censored,
        });
    }
}
fn increment(value: &mut u64, invalid: &mut bool) {
    if let Some(next) = value.checked_add(1) {
        *value = next;
    } else {
        *invalid = true;
    }
}
fn add(totals: &mut Totals, elapsed: Duration, censored: bool, invalid: &mut bool) {
    let (count, sum, maximum) = if censored {
        (
            &mut totals.censored_episodes,
            &mut totals.censored,
            &mut totals.maximum_censored,
        )
    } else {
        (
            &mut totals.completed_episodes,
            &mut totals.completed,
            &mut totals.maximum_completed,
        )
    };
    increment(count, invalid);
    if let Some(next) = sum.checked_add(elapsed) {
        *sum = next;
    } else {
        *invalid = true;
    }
    *maximum = (*maximum).max(elapsed);
}
