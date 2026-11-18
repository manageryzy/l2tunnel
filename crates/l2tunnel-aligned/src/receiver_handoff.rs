//! Exact ordered recovery-source refusal through release into the codec receiver.
//!
//! A single real handoff owns this cell. Preview, inner Packed units, missing context
//! and native consumer waits are not represented. Injected time never changes policy.
use std::time::Duration;

/// Actual retryable outer admission result; Capacity has several resource meanings.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Reason {
    /// The canonical receiver returned Capacity for the held source.
    Capacity,
    /// The canonical receiver returned RecordWindow for the held source.
    RecordWindow,
}
impl Reason {
    const fn index(self) -> usize {
        match self {
            Self::Capacity => 0,
            Self::RecordWindow => 1,
        }
    }
}

/// Why the existing owner released the whole source; none implies native delivery.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Release {
    /// The ordinary Aligned unit was accepted by the receiver.
    Admitted,
    /// The ordered Aligned unit had already been admitted by preview.
    AlreadyObserved,
    /// The final Packed outer transaction succeeded, including existing floor filtering.
    PackedBatch,
}

/// Identity of the actual immutable handoff, scoped by the enclosing endpoint.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Identity {
    /// Original recovery source, not the native record or wire packet number.
    pub source: u64,
    /// Exact retained recovery body extent.
    pub bytes: usize,
    /// Original handoff lifetime cap, never renewed by observation.
    pub deadline: Duration,
}

/// One actually refused source; repeated attempts retain its first refusal tick.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Pending {
    /// Exact source, length and original cap.
    pub identity: Identity,
    /// First actual Capacity/RecordWindow refusal.
    pub since: Duration,
    /// Most recent actual refusal for this source.
    pub last_refusal: Duration,
    /// Actual first returned reason.
    pub first_reason: Reason,
    /// Actual latest returned reason, not a continuously true cause predicate.
    pub last_reason: Reason,
}

/// A completed or censored source interval, retained without an event history.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Resolved {
    /// The exact original source episode.
    pub pending: Pending,
    /// Actual release or terminal observation time.
    pub at: Duration,
    /// Actual release classification; absent means censored, not successful admission.
    pub release: Option<Release>,
}

/// Completed/censored populations exclude the still-open interval.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Totals {
    /// Successfully released source episodes.
    pub completed_episodes: u64,
    /// Sum of completed source intervals; this owner has only one live cell.
    pub completed: Duration,
    /// Longest completed source interval.
    pub maximum_completed: Duration,
    /// Sources still held at a terminal observation.
    pub censored_episodes: u64,
    /// Sum of observed censored portions.
    pub censored: Duration,
    /// Longest censored portion.
    pub maximum_censored: Duration,
}

/// A fresh snapshot may be censored at the caller's metric-stop boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Terminal {
    /// The actual endpoint failed at its last accepted injected time.
    OwnerFailure,
    /// The runtime stopped observation on a freshly sampled endpoint.
    MetricStop,
}

/// Fixed scalar observation; the runtime adds configuration and full owner identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Snapshot {
    /// Actual endpoint epoch, checked against the external provider slot.
    pub epoch: u64,
    /// Actual receiving direction: 0 initiator-to-responder, 1 reverse.
    pub receive_direction: u8,
    /// True means one Packed container; inner failing unit identity is unavailable.
    pub packed: bool,
    /// Snapshot time, frozen at an earlier actual terminal boundary if present.
    pub observed_at: Duration,
    /// First terminal observation time.
    pub terminal_at: Option<Duration>,
    /// Boundary responsible for terminal censoring.
    pub terminal: Option<Terminal>,
    /// Cached terminal sampling could not establish the source's current ownership.
    pub terminal_unavailable: bool,
    /// Actual Capacity and RecordWindow returned-attempt counts, respectively.
    pub refusals: [u64; 2],
    /// Whole-source populations; reasons are counts, not additive wait intervals.
    pub totals: Totals,
    /// Current actual source episode, absent if none was refused and retained.
    pub pending: Option<Pending>,
    /// Latest source release/censor context only.
    pub last_resolved: Option<Resolved>,
    /// Exact source behind the maximum completed interval.
    pub maximum_completed: Option<Resolved>,
    /// Exact source behind the maximum censored interval.
    pub maximum_censored: Option<Resolved>,
    /// Injected diagnostic time regressed.
    pub clock_regression: bool,
    /// An operation differed from the still-retained source identity.
    pub identity_mismatch: bool,
    /// A diagnostic count/duration overflowed; protocol behavior is unaffected.
    pub overflow: bool,
}

impl Snapshot {
    /// Censor this copy only when a fresh owner observation proves current custody.
    pub fn censor(mut self, at: Duration) -> Self {
        if self.terminal_at.is_some() {
            return self;
        }
        if at != self.observed_at || self.clock_regression || self.identity_mismatch {
            self.terminal_unavailable = true;
            return self;
        }
        self.close(at, None);
        self.terminal_at = Some(at);
        self.terminal = Some(Terminal::MetricStop);
        self
    }
    fn close(&mut self, at: Duration, release: Option<Release>) {
        let Some(pending) = self.pending else { return };
        let Some(elapsed) = at.checked_sub(pending.since) else {
            self.clock_regression = true;
            return;
        };
        self.pending = None;
        let resolved = Resolved {
            pending,
            at,
            release,
        };
        let (count, sum, maximum, context) = if release.is_some() {
            (
                &mut self.totals.completed_episodes,
                &mut self.totals.completed,
                &mut self.totals.maximum_completed,
                &mut self.maximum_completed,
            )
        } else {
            (
                &mut self.totals.censored_episodes,
                &mut self.totals.censored,
                &mut self.totals.maximum_censored,
                &mut self.maximum_censored,
            )
        };
        increment(count, &mut self.overflow);
        match sum.checked_add(elapsed) {
            Some(value) => *sum = value,
            None => self.overflow = true,
        }
        if context.is_none() || elapsed > *maximum {
            *maximum = elapsed;
            *context = Some(resolved);
        }
        self.last_resolved = Some(resolved);
    }
}

pub(super) struct State(Snapshot);
impl State {
    pub(super) fn new(scope: super::receiver::Scope, packed: bool) -> Self {
        Self(Snapshot {
            epoch: scope.epoch.0,
            receive_direction: match scope.direction {
                super::receiver::Direction::InitiatorToResponder => 0,
                super::receiver::Direction::ResponderToInitiator => 1,
            },
            packed,
            observed_at: Duration::ZERO,
            terminal_at: None,
            terminal: None,
            terminal_unavailable: false,
            refusals: [0; 2],
            totals: Totals::default(),
            pending: None,
            last_resolved: None,
            maximum_completed: None,
            maximum_censored: None,
            clock_regression: false,
            identity_mismatch: false,
            overflow: false,
        })
    }
    fn observe(&mut self, now: Duration) -> bool {
        if self.0.terminal_at.is_some() {
            return false;
        }
        if now < self.0.observed_at {
            self.0.clock_regression = true;
            return false;
        }
        self.0.observed_at = now;
        true
    }
    pub(super) fn refused(&mut self, identity: Identity, now: Duration, reason: Reason) {
        if !self.observe(now) {
            return;
        }
        increment(&mut self.0.refusals[reason.index()], &mut self.0.overflow);
        let pending = self.0.pending.get_or_insert(Pending {
            identity,
            since: now,
            last_refusal: now,
            first_reason: reason,
            last_reason: reason,
        });
        if pending.identity != identity {
            self.0.identity_mismatch = true;
            return;
        }
        pending.last_refusal = now;
        pending.last_reason = reason;
    }
    pub(super) fn released(&mut self, identity: Identity, now: Duration, release: Release) {
        if !self.observe(now) {
            return;
        }
        let Some(pending) = self.0.pending else {
            return;
        };
        if pending.identity != identity {
            self.0.identity_mismatch = true;
            return;
        }
        self.0.close(now, Some(release));
    }
    pub(super) fn stop(&mut self, now: Duration) {
        if self.observe(now) {
            self.0.close(now, None);
            self.0.terminal_at = Some(now);
            self.0.terminal = Some(Terminal::OwnerFailure);
        }
    }
    pub(super) fn snapshot(&self, now: Duration) -> Snapshot {
        let mut value = self.0;
        if value.terminal_at.is_none() {
            value.clock_regression |= now < value.observed_at;
            value.observed_at = now;
        }
        value
    }
}

fn increment(value: &mut u64, overflow: &mut bool) {
    match value.checked_add(1) {
        Some(next) => *value = next,
        None => *overflow = true,
    }
}
