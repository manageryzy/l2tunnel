//! Actual retained restored-source refusal to admission by the same ARQ owner.
//! Cells follow existing reserved slots, not the current sorted queue head.
use super::{Totals, add, increment};
use std::time::Duration;

/// Source identity in the receiving recovery direction, not a native packet identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Operation {
    /// Full source ID, without modulo truncation.
    pub source: u64,
    /// Original retained recovery body extent, including its recovery fields.
    pub bytes: usize,
    /// The actual original restored record was produced by FEC recovery.
    pub recovered: bool,
}
/// An actual refused source, including overlapping first-reason boundaries.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Pending {
    /// Exact retained source and extent.
    pub operation: Operation,
    /// First actual ARQ refusal; never renewed.
    pub since: Duration,
    /// Latest actual ARQ refusal for this source.
    pub last_refusal: Duration,
    /// Capacity and SequenceWindow first refusals, respectively.
    pub reasons_since: [Option<Duration>; 2],
}
/// Last or maximum same-source admission/censor context; not an event history.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Resolved {
    /// Exact episode, preserving its original first and latest refusal.
    pub pending: Pending,
    /// Admission or fresh terminal sample boundary.
    pub at: Duration,
    /// Unresolved at observation stop rather than admitted to ARQ.
    pub censored: bool,
}
/// Simultaneously open source episodes; their durations may overlap.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Open {
    /// Number of genuinely refused sources still retained.
    pub episodes: u64,
    /// Sum of per-source observed elapsed time, not an owner blocked-time union.
    pub elapsed: Duration,
    /// Maximum per-source observed elapsed time.
    pub maximum: Duration,
}
/// Fixed summary, copied only at the existing provider sampling boundary.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Snapshot {
    /// Configured restored count; exactly this many optional cells were prepaid.
    pub cells: usize,
    /// Original configured restored byte bound, not a new diagnostics allowance.
    pub restored_bytes_capacity: usize,
    /// Snapshot clock, injected by the caller.
    pub observed_at: Duration,
    /// Fresh terminal boundary; absent while the snapshot is live.
    pub terminal_at: Option<Duration>,
    /// Actual repeated refusal counts: Capacity, then SequenceWindow.
    pub refusals: [u64; 2],
    /// Source duration populations; sources overlap and are never added as an owner union.
    pub sources: Totals,
    /// Overlapping first-reason-to-admission/terminal populations.
    pub reasons: [Totals; 2],
    /// Observed unresolved sources; occupancy without a refusal is excluded.
    pub open: Open,
    /// Open per-reason populations, overlapping each other and the source population.
    pub reasons_open: [Open; 2],
    /// Exact longest currently open source; equal durations retain lowest slot order.
    pub maximum_open: Option<Pending>,
    /// Last actual same-source progress, not a fabricated terminal ordering.
    pub last_completed: Option<Resolved>,
    /// Exact longest completed source; equal durations keep the first observation.
    pub maximum_completed: Option<Resolved>,
    /// Exact longest terminal-censored source.
    pub maximum_censored: Option<Resolved>,
    /// Refusals that could not be tracked; never silently presented as zero waits.
    pub omitted_refusals: u64,
    /// Slot/source mismatch or impossible reason; protocol behavior is unchanged.
    pub identity_mismatch: bool,
    /// Injected time regressed; invalid diagnostics do not rewrite protocol errors.
    pub clock_regression: bool,
    /// Counter/duration arithmetic overflow.
    pub overflow: bool,
    /// A terminal request lacked an exactly fresh sampled population.
    pub terminal_unavailable: bool,
}

pub(crate) type Cell = Option<Pending>;

impl Snapshot {
    pub(crate) fn new(cells: usize, restored_bytes_capacity: usize) -> Self {
        Self {
            cells,
            restored_bytes_capacity,
            ..Self::default()
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
    pub(crate) fn refused(
        &mut self,
        cell: Option<&mut Cell>,
        operation: Operation,
        now: Duration,
        reason: usize,
    ) {
        if !self.observe(now) {
            return;
        }
        let Some(count) = self.refusals.get_mut(reason) else {
            self.identity_mismatch = true;
            return;
        };
        increment(count, &mut self.overflow);
        let Some(cell) = cell else {
            increment(&mut self.omitted_refusals, &mut self.overflow);
            return;
        };
        let pending = cell.get_or_insert(Pending {
            operation,
            since: now,
            last_refusal: now,
            reasons_since: [None; 2],
        });
        if pending.operation != operation {
            self.identity_mismatch = true;
            increment(&mut self.omitted_refusals, &mut self.overflow);
            return;
        }
        pending.last_refusal = now;
        pending.reasons_since[reason].get_or_insert(now);
    }
    pub(crate) fn admitted(
        &mut self,
        cell: Option<&mut Cell>,
        operation: Operation,
        now: Duration,
    ) {
        if !self.observe(now) {
            return;
        }
        let Some(cell) = cell else {
            return;
        };
        let Some(pending) = *cell else {
            return;
        };
        if pending.operation != operation {
            self.identity_mismatch = true;
            return;
        }
        *cell = None;
        let elapsed = now - pending.since;
        let resolved = Resolved {
            pending,
            at: now,
            censored: false,
        };
        if self.maximum_completed.is_none() || elapsed > self.sources.maximum_completed {
            self.maximum_completed = Some(resolved);
        }
        add(&mut self.sources, elapsed, false, &mut self.overflow);
        for (total, since) in self.reasons.iter_mut().zip(pending.reasons_since) {
            if let Some(since) = since {
                add(total, now - since, false, &mut self.overflow);
            }
        }
        self.last_completed = Some(resolved);
    }
    pub(crate) fn sampled(mut self, cells: &[Cell], now: Duration) -> Self {
        if !self.observe(now) {
            return self;
        }
        if cells.len() != self.cells {
            self.identity_mismatch = true;
        }
        self.open = Open::default();
        self.reasons_open = [Open::default(); 2];
        self.maximum_open = None;
        // Only the opt-in, throttled snapshot scans these bounded diagnostic cells.
        // pump() indexes the actual slot yielded by its existing minimum-source scan.
        for pending in cells.iter().flatten() {
            let Some(elapsed) = now.checked_sub(pending.since) else {
                self.clock_regression = true;
                continue;
            };
            if self.maximum_open.is_none() || elapsed > self.open.maximum {
                self.maximum_open = Some(*pending);
            }
            observe_open(&mut self.open, elapsed, &mut self.overflow);
            for (open, since) in self.reasons_open.iter_mut().zip(pending.reasons_since) {
                if let Some(since) = since {
                    if let Some(elapsed) = now.checked_sub(since) {
                        observe_open(open, elapsed, &mut self.overflow);
                    } else {
                        self.clock_regression = true;
                    }
                }
            }
        }
        self
    }
    pub(crate) fn censor(&mut self, now: Duration) {
        if self.terminal_at.is_some() {
            return;
        }
        if now != self.observed_at {
            self.terminal_unavailable = true;
            return;
        }
        merge_censored(&mut self.sources, self.open, &mut self.overflow);
        for (total, open) in self.reasons.iter_mut().zip(self.reasons_open) {
            merge_censored(total, open, &mut self.overflow);
        }
        self.maximum_censored = self.maximum_open.map(|pending| Resolved {
            pending,
            at: now,
            censored: true,
        });
        self.maximum_open = None;
        self.open = Open::default();
        self.reasons_open = [Open::default(); 2];
        self.terminal_at = Some(now);
    }
}
fn observe_open(value: &mut Open, elapsed: Duration, overflow: &mut bool) {
    increment(&mut value.episodes, overflow);
    if let Some(next) = value.elapsed.checked_add(elapsed) {
        value.elapsed = next;
    } else {
        *overflow = true;
    }
    value.maximum = value.maximum.max(elapsed);
}
fn merge_censored(value: &mut Totals, open: Open, overflow: &mut bool) {
    if let Some(next) = value.censored_episodes.checked_add(open.episodes) {
        value.censored_episodes = next;
    } else {
        *overflow = true;
    }
    if let Some(next) = value.censored.checked_add(open.elapsed) {
        value.censored = next;
    } else {
        *overflow = true;
    }
    value.maximum_censored = value.maximum_censored.max(open.maximum);
}
