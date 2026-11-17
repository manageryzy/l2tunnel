//! Exact retained-source refusal-to-admission observations using injected time.
//!
//! Counters describe observed progress, not continuous fullness. Reasons can overlap;
//! their durations must not be added. No observation changes protocol authority.
use std::time::Duration;

/// Actual reason returned while the same staged source remains locally retained.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Reason {
    /// ARQ refused its retained source-count or byte capacity.
    SendCapacity,
    /// ARQ refused the next source's permitted sequence span.
    SequenceWindow,
}
impl Reason {
    const fn index(self) -> usize {
        match self {
            Self::SendCapacity => 0,
            Self::SequenceWindow => 1,
        }
    }
}

/// Completed and censored populations are separate; open time is not included.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Totals {
    /// Same-source successful admission episodes.
    pub completed_episodes: u64,
    /// Sum of completed refusal-to-admission durations within this owner.
    pub completed: Duration,
    /// Longest completed episode.
    pub maximum_completed: Duration,
    /// Episodes frozen without successful same-source admission.
    pub censored_episodes: u64,
    /// Sum of observed censored portions within this owner.
    pub censored: Duration,
    /// Longest observed censored portion.
    pub maximum_censored: Duration,
}

/// One source identity remains stable across all retryable admission attempts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Pending {
    /// Authoritative recovery source ID, not a record or packet number.
    pub source: u64,
    /// Exact staged recovery payload length, without copying its bytes.
    pub bytes: usize,
    /// First actual admission refusal for this source.
    pub since: Duration,
    /// Latest actual refusal; repeated attempts never renew `since`.
    pub last_refusal: Duration,
    /// First observed refusal for each Reason, in SendCapacity/SequenceWindow order.
    pub reasons_since: [Option<Duration>; 2],
}

/// Last resolved identity only; there is no per-packet history.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Resolved {
    /// Exact source that ended this episode.
    pub source: u64,
    /// Exact staged payload length.
    pub bytes: usize,
    /// Its original refusal time.
    pub since: Duration,
    /// Actual successful admission or diagnostic terminal observation time.
    pub at: Duration,
    /// False means observed same-source admission; true means unresolved terminal.
    pub censored: bool,
}

/// Boundary that froze an unresolved source observation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Terminal {
    /// The actual pure owner entered a terminal failure at injected time.
    OwnerFailure,
    /// The caller stopped metrics on a fresh owner snapshot before settlement.
    MetricStop,
}

/// Bounded owner-local observations; external runtime supplies epoch/config/incarnation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Snapshot {
    /// Injected snapshot time, frozen at an earlier terminal observation when present.
    pub observed_at: Duration,
    /// Exact first terminal observation, if the owner was censored.
    pub terminal_at: Option<Duration>,
    /// Exact terminal observation boundary, absent before censoring.
    pub terminal: Option<Terminal>,
    /// Counts of actual rejected attempts, including repeated refusals.
    pub refusals: [u64; 2],
    /// Each reason's refusal-to-same-source-admission totals; they can overlap.
    pub reasons: [Totals; 2],
    /// Union for the one staged source; never a sum of the two reasons.
    pub union: Totals,
    /// Current unresolved source; absence is distinct from a zero-length payload.
    pub pending: Option<Pending>,
    /// Exact observed open portion, absent when there is no open source or time is invalid.
    pub open: Option<Duration>,
    /// Most recent completed/censored identity, retained without an event log.
    pub last_resolved: Option<Resolved>,
    /// Observation time regressed; affected timing must not be treated as valid.
    pub clock_regression: bool,
    /// An operation named another source while an earlier one still owned the stage.
    pub identity_mismatch: bool,
    /// A diagnostic counter or duration exhausted its representable range.
    pub overflow: bool,
}

impl Snapshot {
    /// Freeze only this diagnostic copy at an actual caller-owned terminal edge.
    /// A stale sample must not be passed here: it may name an already admitted source.
    pub fn censor(mut self, at: Duration) -> Self {
        if self.terminal_at.is_some() {
            return self;
        }
        if at < self.observed_at {
            self.clock_regression = true;
            return self;
        }
        self.observed_at = at;
        self.terminal_at = Some(at);
        self.terminal = Some(Terminal::MetricStop);
        if let Some(pending) = self.pending.take() {
            if let Some(elapsed) = at.checked_sub(pending.since) {
                add(&mut self.union, elapsed, true, &mut self.overflow);
                for (totals, since) in self.reasons.iter_mut().zip(pending.reasons_since) {
                    if let Some(since) = since {
                        if let Some(elapsed) = at.checked_sub(since) {
                            add(totals, elapsed, true, &mut self.overflow);
                        } else {
                            self.clock_regression = true;
                        }
                    }
                }
                self.last_resolved = Some(Resolved {
                    source: pending.source,
                    bytes: pending.bytes,
                    since: pending.since,
                    at,
                    censored: true,
                });
            } else {
                self.clock_regression = true;
                self.pending = Some(pending);
            }
        }
        self.open = None;
        self
    }
}

#[derive(Default)]
pub(super) struct State {
    now: Duration,
    terminal_at: Option<Duration>,
    refusals: [u64; 2],
    reasons: [Totals; 2],
    union: Totals,
    pending: Option<Pending>,
    last_resolved: Option<Resolved>,
    clock_regression: bool,
    identity_mismatch: bool,
    overflow: bool,
}
impl State {
    pub(super) fn observe(&mut self, now: Duration) -> bool {
        if self.terminal_at.is_some() {
            return false;
        }
        if now < self.now {
            self.clock_regression = true;
            return false;
        }
        self.now = now;
        true
    }
    pub(super) fn refused(&mut self, source: u64, bytes: usize, now: Duration, reason: Reason) {
        if !self.observe(now) {
            return;
        }
        let index = reason.index();
        count(&mut self.refusals[index], &mut self.overflow);
        let pending = self.pending.get_or_insert(Pending {
            source,
            bytes,
            since: now,
            last_refusal: now,
            reasons_since: [None; 2],
        });
        if pending.source != source || pending.bytes != bytes {
            self.identity_mismatch = true;
            return;
        }
        pending.last_refusal = now;
        pending.reasons_since[index].get_or_insert(now);
    }
    pub(super) fn admitted(&mut self, source: u64, bytes: usize, now: Duration) {
        if !self.observe(now) {
            return;
        }
        let Some(pending) = self.pending else {
            return;
        };
        if pending.source != source || pending.bytes != bytes {
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
            source: pending.source,
            bytes: pending.bytes,
            since: pending.since,
            at: now,
            censored,
        });
    }
    pub(super) fn stop(&mut self, now: Duration) {
        if self.observe(now) {
            self.close(now, true);
            self.terminal_at = Some(now);
        }
    }
    pub(super) fn stop_observed(&mut self) {
        self.stop(self.now);
    }
    pub(super) fn snapshot(&self, now: Duration) -> Snapshot {
        let observed_at = self.terminal_at.unwrap_or(now);
        let invalid_time = observed_at < self.now;
        Snapshot {
            observed_at,
            terminal_at: self.terminal_at,
            terminal: self.terminal_at.map(|_| Terminal::OwnerFailure),
            refusals: self.refusals,
            reasons: self.reasons,
            union: self.union,
            pending: self.pending,
            open: self
                .pending
                .and_then(|pending| observed_at.checked_sub(pending.since)),
            last_resolved: self.last_resolved,
            clock_regression: self.clock_regression || invalid_time,
            identity_mismatch: self.identity_mismatch,
            overflow: self.overflow,
        }
    }
}
fn count(value: &mut u64, overflow: &mut bool) {
    match value.checked_add(1) {
        Some(next) => *value = next,
        None => *overflow = true,
    }
}
fn add(totals: &mut Totals, elapsed: Duration, censored: bool, overflow: &mut bool) {
    let (episodes, duration, maximum) = if censored {
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
    count(episodes, overflow);
    match duration.checked_add(elapsed) {
        Some(total) => *duration = total,
        None => *overflow = true,
    }
    *maximum = (*maximum).max(elapsed);
}

#[cfg(test)]
mod tests {
    use super::*;
    fn ms(value: u64) -> Duration {
        Duration::from_millis(value)
    }
    #[test]
    fn exact_source_admission_closes_overlapping_reasons_once_and_terminal_censors() {
        let mut state = State::default();
        state.refused(5, 20, ms(0), Reason::SendCapacity);
        state.refused(5, 20, ms(10), Reason::SendCapacity);
        state.refused(5, 20, ms(20), Reason::SequenceWindow);
        state.admitted(5, 20, ms(40));
        let done = state.snapshot(ms(40));
        assert_eq!(done.refusals, [2, 1]);
        assert_eq!(done.union.completed, ms(40));
        assert_eq!(done.union.completed_episodes, 1);
        assert_eq!(done.reasons[0].completed, ms(40));
        assert_eq!(done.reasons[1].completed, ms(20));
        assert!(done.pending.is_none());
        state.refused(6, 21, ms(50), Reason::SendCapacity);
        state.stop(ms(70));
        state.stop(ms(90));
        let stopped = state.snapshot(ms(100));
        assert_eq!(stopped.observed_at, ms(70));
        assert_eq!(stopped.union.censored, ms(20));
        assert_eq!(stopped.union.censored_episodes, 1);
        assert!(matches!(
            stopped.last_resolved,
            Some(Resolved {
                source: 6,
                censored: true,
                ..
            })
        ));
        assert!(!stopped.clock_regression);
    }
    #[test]
    fn unrelated_source_and_regressed_time_never_clear_original_wait() {
        let mut state = State::default();
        state.refused(3, 9, ms(10), Reason::SequenceWindow);
        state.admitted(4, 9, ms(20));
        state.admitted(3, 9, ms(5));
        let snapshot = state.snapshot(ms(25));
        assert!(snapshot.identity_mismatch && snapshot.clock_regression);
        assert_eq!(snapshot.pending.map(|v| v.source), Some(3));
        assert_eq!(snapshot.union.completed_episodes, 0);
        assert_eq!(snapshot.open, Some(ms(15)));
    }
}
