//! Exact retained-operation refusal-to-progress intervals using injected microseconds.
//! No occupancy, idle poll, timer hold or physical receipt is treated as admission.
use super::*;

/// Exact receiving data-head admission observations, separate from sender waits.
pub mod ingress;

/// Actual operation boundary; each site owns at most one unresolved operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Site {
    /// Sealed compact source refused by its selected recovery sender.
    SourceAdmission,
    /// Decoded source refused by the record receiver before ordered handoff.
    DecodedHandoff,
    /// Ready immutable feedback refused by the caller's exact output budget.
    FeedbackBudget,
}
impl Site {
    pub(crate) const fn index(self) -> usize {
        match self {
            Self::SourceAdmission => 0,
            Self::DecodedHandoff => 1,
            Self::FeedbackBudget => 2,
        }
    }
}
/// Exact actual refusal, without inferring a more specific hidden cause.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Reason {
    /// The recovery owner returned Busy, including its selected scheduling policy.
    RecoveryBusy,
    /// The recovery owner returned Capacity.
    RecoveryCapacity,
    /// The record composition returned Busy.
    RecordBusy,
    /// The record receiver returned Capacity.
    RecordCapacity,
    /// The record receiver returned RecordWindow.
    RecordWindow,
    /// The ready feedback needs more physical packets than the caller permits.
    PacketBudget,
    /// The ready feedback needs more physical bytes than the caller permits.
    WireByteBudget,
}
impl Reason {
    const fn index(self) -> usize {
        match self {
            Self::RecoveryBusy => 0,
            Self::RecoveryCapacity => 1,
            Self::RecordBusy => 2,
            Self::RecordCapacity => 3,
            Self::RecordWindow => 4,
            Self::PacketBudget => 5,
            Self::WireByteBudget => 6,
        }
    }
    pub(super) fn from_error(error: Error) -> Option<Self> {
        match error {
            Error::Busy => Some(Self::RecordBusy),
            Error::Rolling(rolling::Error::Busy) => Some(Self::RecoveryBusy),
            Error::Rolling(rolling::Error::Capacity) => Some(Self::RecoveryCapacity),
            Error::Receiver(receiver::Error::Capacity) => Some(Self::RecordCapacity),
            Error::Receiver(receiver::Error::RecordWindow) => Some(Self::RecordWindow),
            _ => None,
        }
    }
}
/// Exact immutable operation, scoped by the surrounding Endpoint and site.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Operation {
    /// SourceId for source sites; FeedbackId for the feedback site.
    pub id: u64,
    /// Actual initialized recovery bytes, excluding authentication/carrier overhead.
    pub bytes: usize,
    /// Original stage, decoder handoff-cohort, or feedback output deadline.
    pub deadline: Option<Tick>,
    /// Exact physical packet requirement for feedback; zero for source sites.
    pub packets: usize,
    /// Exact complete output debit for feedback; zero for source sites.
    pub wire_bytes: usize,
    /// Selected source copy count; zero outside sealed source admission.
    pub copies: u8,
}
/// Completed and censored populations; units are injected microseconds.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Totals {
    /// Same-operation successful progress episodes.
    pub completed_episodes: u64,
    /// Sum of completed observed durations.
    pub completed_us: u64,
    /// Longest completed observed duration.
    pub maximum_completed_us: u64,
    /// Unresolved episodes frozen at an observed terminal boundary.
    pub censored_episodes: u64,
    /// Sum of their observed portions.
    pub censored_us: u64,
    /// Longest observed censored portion.
    pub maximum_censored_us: u64,
}
/// One retained operation; repeated attempts preserve its first refusal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Pending {
    /// Exact same-operation witness.
    pub operation: Operation,
    /// First actual refusal time.
    pub since: Tick,
    /// Latest actual refusal time.
    pub last_refusal: Tick,
    /// First refusal by reason, in the documented Reason declaration order.
    pub reasons_since: [Option<Tick>; 7],
}
/// Last completed or censored operation only; no per-packet event history.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Resolved {
    /// Original operation witness.
    pub operation: Operation,
    /// First actual refusal.
    pub since: Tick,
    /// Observed progress or censor time.
    pub at: Tick,
    /// True means no successful same-operation progress was observed.
    pub censored: bool,
}
/// One bounded site; reason intervals can overlap and must not be added.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SiteSnapshot {
    /// Actual refusal attempts by Reason, including repeated attempts.
    pub refusals: [u64; 7],
    /// Refusal-to-progress populations by Reason; overlaps are intentional.
    pub reasons: [Totals; 7],
    /// Union for this one retained-operation site only.
    pub union: Totals,
    /// Current unresolved actual operation.
    pub pending: Option<Pending>,
    /// Most recent completed/censored identity.
    pub last_resolved: Option<Resolved>,
}
/// Actual boundary that freezes unresolved observations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Terminal {
    /// Actual pure owner failure at its injected observation time.
    OwnerFailure,
    /// Fresh runtime source observation before terminal settlement.
    MetricStop,
    /// Fresh source observation when the owning Driver is dropped.
    DriverDrop,
}
/// Complete fixed-cardinality diagnostic; external runtime preserves configuration digest.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Snapshot {
    /// Local Endpoint identity, not wire authentication authority.
    pub instance: u64,
    /// Full sending session, epoch, stream and global direction.
    pub send_scope: rolling::Scope,
    /// Current injected observation; after censoring this is frozen.
    pub observed_at: Tick,
    /// Exact first terminal observation.
    pub terminal: Option<(Tick, Terminal)>,
    /// Source admission, decoded handoff and feedback budget, in that order.
    pub sites: [SiteSnapshot; 3],
    /// Available only when actual bounded receive ingress was selected.
    pub ingress_admission: Option<ingress::Snapshot>,
    /// Invalid diagnostic time; protocol time checks remain independent.
    pub clock_regression: bool,
    /// Another operation was named while an earlier one remained unresolved.
    pub identity_mismatch: bool,
    /// A counter or accumulated duration exceeded its representation.
    pub overflow: bool,
}
impl Snapshot {
    pub(super) fn new(instance: u64, send_scope: rolling::Scope, now: Tick) -> Self {
        Self {
            instance,
            send_scope,
            observed_at: now,
            terminal: None,
            sites: [SiteSnapshot::default(); 3],
            ingress_admission: None,
            clock_regression: false,
            identity_mismatch: false,
            overflow: false,
        }
    }
    pub(super) fn observe(&mut self, now: Tick) -> bool {
        if self.terminal.is_some() {
            return false;
        }
        if now < self.observed_at {
            self.clock_regression = true;
            return false;
        }
        self.observed_at = now;
        true
    }
    pub(super) fn refuse(&mut self, site: Site, operation: Operation, reason: Reason, now: Tick) {
        if !self.observe(now) {
            return;
        }
        let row = &mut self.sites[site.index()];
        let index = reason.index();
        increment(&mut row.refusals[index], &mut self.overflow);
        let pending = row.pending.get_or_insert(Pending {
            operation,
            since: now,
            last_refusal: now,
            reasons_since: [None; 7],
        });
        if pending.operation != operation {
            self.identity_mismatch = true;
            return;
        }
        pending.last_refusal = now;
        pending.reasons_since[index].get_or_insert(now);
    }
    pub(super) fn progress(&mut self, site: Site, operation: Operation, now: Tick) {
        if !self.observe(now) {
            return;
        }
        let row = &mut self.sites[site.index()];
        if let Some(pending) = row.pending {
            if pending.operation != operation {
                self.identity_mismatch = true;
                return;
            }
            close(row, now, false, &mut self.overflow);
        }
    }
    pub(super) fn ingress_refused(
        &mut self,
        input: ingress::Input,
        blocker: Option<rolling::expiry::DecoderJob>,
        now: Tick,
    ) {
        if !self.observe(now) {
            return;
        }
        if let Some(value) = &mut self.ingress_admission {
            value.refuse(
                input,
                blocker,
                now,
                &mut self.identity_mismatch,
                &mut self.overflow,
            );
        }
    }
    pub(super) fn ingress_completed(
        &mut self,
        input: ingress::Input,
        outcome: ingress::Outcome,
        admitted_job: Option<rolling::expiry::DecoderJob>,
        now: Tick,
    ) {
        if !self.observe(now) {
            return;
        }
        if let Some(value) = &mut self.ingress_admission {
            if let Some(elapsed) = now.0.checked_sub(input.received.0) {
                value
                    .residence
                    .removed(elapsed, true, outcome, &mut self.overflow);
            } else {
                self.clock_regression = true;
            }
            value.complete(
                input,
                outcome,
                admitted_job,
                now,
                &mut self.identity_mismatch,
                &mut self.overflow,
            );
        }
    }
    pub(super) fn independent_ingress_completed(
        &mut self,
        input: ingress::Input,
        head: bool,
        now: Tick,
    ) {
        if head {
            self.ingress_completed(input, ingress::Outcome::Independent, None, now);
        } else if self.observe(now)
            && let Some(value) = &mut self.ingress_admission
        {
            if let Some(elapsed) = now.0.checked_sub(input.received.0) {
                value.residence.removed(
                    elapsed,
                    true,
                    ingress::Outcome::Independent,
                    &mut self.overflow,
                );
            } else {
                self.clock_regression = true;
            }
        }
    }
    /// Copy at caller-supplied observation time without advancing any protocol owner.
    pub fn observed(mut self, now: Tick) -> Self {
        self.observe(now);
        self
    }
    /// Freeze a fresh observation without treating unresolved work as progress.
    /// Runtime callers must sample the live owner immediately before invoking this.
    pub fn censor(mut self, now: Tick, boundary: Terminal) -> Self {
        self.stop(now, boundary);
        self
    }
    pub(super) fn stop(&mut self, now: Tick, boundary: Terminal) {
        let fresh = self.observed_at == now;
        if !self.observe(now) {
            return;
        }
        for row in &mut self.sites {
            close(row, now, true, &mut self.overflow);
        }
        if let Some(value) = &mut self.ingress_admission {
            value.stop(now, fresh, &mut self.overflow);
        }
        self.terminal = Some((now, boundary));
    }
}
fn increment(value: &mut u64, overflow: &mut bool) {
    if let Some(next) = value.checked_add(1) {
        *value = next;
    } else {
        *overflow = true;
    }
}
fn add(totals: &mut Totals, elapsed: u64, censored: bool, overflow: &mut bool) {
    let (count, sum, max) = if censored {
        (
            &mut totals.censored_episodes,
            &mut totals.censored_us,
            &mut totals.maximum_censored_us,
        )
    } else {
        (
            &mut totals.completed_episodes,
            &mut totals.completed_us,
            &mut totals.maximum_completed_us,
        )
    };
    increment(count, overflow);
    if let Some(next) = sum.checked_add(elapsed) {
        *sum = next;
    } else {
        *overflow = true;
    }
    *max = (*max).max(elapsed);
}
fn close(row: &mut SiteSnapshot, now: Tick, censored: bool, overflow: &mut bool) {
    let Some(pending) = row.pending.take() else {
        return;
    };
    add(&mut row.union, now.0 - pending.since.0, censored, overflow);
    for (total, since) in row.reasons.iter_mut().zip(pending.reasons_since) {
        if let Some(since) = since {
            add(total, now.0 - since.0, censored, overflow);
        }
    }
    row.last_resolved = Some(Resolved {
        operation: pending.operation,
        since: pending.since,
        at: now,
        censored,
    });
}
impl<P: RecoveryPolicy> Endpoint<P> {
    /// Exact opt-in diagnostics; unavailable means no backing was selected.
    /// No queue, timer, receipt or protocol state is advanced by observation.
    pub fn wait_snapshot(&self, now: Tick) -> Option<Snapshot> {
        self.waits.first().copied().map(|value| {
            let mut snapshot = value.observed(now);
            // An immutable failed owner retains the exact original terminal tick.
            // Otherwise this is a bounded current metadata sample, not a wait.
            let at = snapshot.observed_at;
            if let (Some(row), Some(owner)) = (&mut snapshot.ingress_admission, &self.ingress) {
                let mut ages = ingress::residence::Distribution::default();
                for packet in owner.queue.iter() {
                    let input = packet.metadata();
                    if matches!(
                        input.kind,
                        record_engine::EmissionKind::Source(_)
                            | record_engine::EmissionKind::Repair
                    ) {
                        if let Some(age) = at.0.checked_sub(input.received.0) {
                            ages.record(age, &mut snapshot.overflow);
                        } else {
                            snapshot.clock_regression = true;
                        }
                    }
                }
                row.residence.retained_ages = Some(ages);
                row.residence.retained_at = Some(at);
            }
            snapshot
        })
    }
    pub(super) fn note_direct_ingress_admission(
        &mut self,
        received: Tick,
        now: Tick,
        outcome: rolling::Begin,
    ) {
        let outcome = match outcome {
            rolling::Begin::Staged => ingress::Outcome::Staged,
            rolling::Begin::Duplicate => ingress::Outcome::Duplicate,
            rolling::Begin::Stale => ingress::Outcome::Stale,
        };
        if let Some(waits) = self.waits.first_mut()
            && waits.observe(now)
            && let Some(row) = &mut waits.ingress_admission
        {
            if let Some(elapsed) = now.0.checked_sub(received.0) {
                row.residence
                    .removed(elapsed, false, outcome, &mut waits.overflow);
            } else {
                waits.clock_regression = true;
            }
        }
    }
}
