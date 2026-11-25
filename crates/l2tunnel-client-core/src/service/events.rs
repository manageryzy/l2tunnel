//! Exact bounded service event log, recorded when the state lock is released.
//!
//! One locked section is one atomic published transition. The lock guard
//! compares that published state with the last recorded one before the mutex
//! is released, so no published lifecycle state, accepted operation, setup
//! stage or completion is skipped. Events are observations of the local
//! service only; they are never peer-confirmed progress.
use super::*;

/// Retained events; older events are reported as a gap, never synthesized.
pub(super) const EVENT_CAPACITY: usize = 256;
/// Maximum events returned by one page.
pub const EVENT_PAGE_LIMIT: usize = 32;

/// Kind of a retained accepted operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OperationKind {
    /// Setup from idle with the accepted plan.
    Connect,
    /// Release the live generation, then set up the accepted plan.
    Reconnect,
    /// Abort the live generation.
    Disconnect,
    /// Existing typed local apply action (proxy drain).
    Apply,
    /// Complete Common configuration switch.
    CommonSwitch,
    /// Selected connection-reuse protocol request.
    ConnectionReuse,
    /// Service-owned device change.
    Device,
    /// Service-owned route change.
    Route,
    /// Profile store change.
    Profile,
    /// Service stop.
    Stop,
    /// Server session ended and listening again.
    SessionKick,
}
impl OperationKind {
    pub(super) fn of(fingerprint: &Fingerprint) -> Self {
        match fingerprint {
            Fingerprint::Connect(_) => Self::Connect,
            Fingerprint::Reconnect(_) => Self::Reconnect,
            Fingerprint::Disconnect => Self::Disconnect,
            Fingerprint::Apply(_) => Self::Apply,
            Fingerprint::Common(_) => Self::CommonSwitch,
            Fingerprint::ConnectionReuse(_) => Self::ConnectionReuse,
            Fingerprint::Host(super::host::HostChange::Device(_)) => Self::Device,
            Fingerprint::Host(super::host::HostChange::Route(_)) => Self::Route,
            Fingerprint::Profile(_) => Self::Profile,
            Fingerprint::Stop => Self::Stop,
            Fingerprint::Kick => Self::SessionKick,
            Fingerprint::ProfileConnect {
                reconnect: false, ..
            } => Self::Connect,
            Fingerprint::ProfileConnect {
                reconnect: true, ..
            } => Self::Reconnect,
        }
    }
}
/// Short name of an actual completion; details stay in the retained entry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OutcomeName {
    /// Actual runtime readiness.
    Connected,
    /// Original owners were dropped.
    Aborted,
    /// Typed apply response reported success.
    Applied,
    /// Typed apply response reported a definitive refusal.
    Rejected,
    /// Peer-confirmed Common epoch.
    CommonCommitted,
    /// Definitive Common refusal before commit.
    CommonRefused,
    /// Connection reuse confirmed.
    ReuseConfirmed,
    /// Connection reuse refused.
    ReuseRefused,
    /// Setup cancelled before readiness.
    Cancelled,
    /// Ownership ended with an uncertain peer outcome.
    OutcomeUnknown,
    /// Original deadline or local/runtime failure.
    Failed,
    /// Device or route change applied.
    HostApplied,
    /// Device or route change refused.
    HostRefused,
    /// Profile store changed.
    ProfileApplied,
    /// Profile store change refused.
    ProfileRefused,
}
impl OutcomeName {
    /// Classify an actual completion without reinterpreting it.
    pub fn of(completed: &Completed) -> Self {
        match completed {
            Completed::Connected { .. } => Self::Connected,
            Completed::Aborted => Self::Aborted,
            Completed::Applied(_) => Self::Applied,
            Completed::Rejected(_) => Self::Rejected,
            Completed::Common { outcome: Ok(_), .. } => Self::CommonCommitted,
            Completed::Common {
                outcome: Err(_), ..
            } => Self::CommonRefused,
            Completed::ConnectionReuse { outcome: Ok(_), .. } => Self::ReuseConfirmed,
            Completed::ConnectionReuse {
                outcome: Err(_), ..
            } => Self::ReuseRefused,
            Completed::Cancelled => Self::Cancelled,
            Completed::OutcomeUnknown => Self::OutcomeUnknown,
            Completed::Failed(_) => Self::Failed,
            Completed::Host(Ok(_)) => Self::HostApplied,
            Completed::Host(Err(_)) => Self::HostRefused,
            Completed::Profile(Ok(_)) => Self::ProfileApplied,
            Completed::Profile(Err(_)) => Self::ProfileRefused,
        }
    }
}
/// One recorded transition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EventKind {
    /// A new operation entry was retained.
    OperationAccepted {
        /// Accepted operation.
        operation: OperationId,
        /// Its kind.
        kind: OperationKind,
    },
    /// A retained setup record reached a new actual stage.
    OperationProgress {
        /// Setup operation.
        operation: OperationId,
        /// Stage reached.
        stage: SetupStage,
    },
    /// A retained operation obtained its actual completion.
    OperationCompleted {
        /// Completed operation.
        operation: OperationId,
        /// Short completion name.
        outcome: OutcomeName,
    },
    /// The published lifecycle tuple changed.
    Lifecycle {
        /// Service phase.
        phase: Phase,
        /// Pending operation.
        operation: Option<OperationId>,
        /// Current/last live generation.
        generation: Option<OperationId>,
        /// Latest generation termination.
        terminal: Option<Terminal>,
    },
}
/// Sequenced event.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Event {
    /// Monotonic sequence starting at 1.
    pub sequence: u64,
    /// Recorded transition.
    pub kind: EventKind,
}
/// Bounded page of events after a cursor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EventPage {
    /// Events with sequence greater than the cursor, oldest first.
    pub events: Vec<Event>,
    /// Cursor for the next page (last returned sequence, or the input cursor).
    pub next: u64,
    /// Events after the cursor were evicted; read a full snapshot.
    pub gap: bool,
}
/// Per-entry recording progress.
#[derive(Clone, Copy, Debug, Default)]
pub(super) struct Reported {
    accepted: bool,
    stage: Option<SetupStage>,
    completed: bool,
}
type Tuple = (
    Phase,
    Option<OperationId>,
    Option<OperationId>,
    Option<Terminal>,
);
pub(super) struct EventLog {
    ring: VecDeque<Event>,
    last: u64,
    lifecycle: Option<Tuple>,
}
impl EventLog {
    pub(super) fn new() -> Self {
        Self {
            ring: VecDeque::with_capacity(EVENT_CAPACITY),
            last: 0,
            lifecycle: None,
        }
    }
    pub(super) fn last(&self) -> u64 {
        self.last
    }
    fn push(&mut self, kind: EventKind) -> bool {
        // A u64 sequence cannot be exhausted by a bounded local service; if it
        // ever were, stop recording rather than wrap and reorder cursors.
        let Some(sequence) = self.last.checked_add(1) else {
            return false;
        };
        if self.ring.len() == EVENT_CAPACITY {
            self.ring.pop_front();
        }
        self.ring.push_back(Event { sequence, kind });
        self.last = sequence;
        true
    }
    pub(super) fn page(&self, after: u64, limit: usize) -> EventPage {
        let limit = limit.clamp(1, EVENT_PAGE_LIMIT);
        let oldest = self
            .ring
            .front()
            .map_or(self.last.saturating_add(1), |event| event.sequence);
        let gap = after.saturating_add(1) < oldest && after < self.last;
        let events: Vec<Event> = self
            .ring
            .iter()
            .filter(|event| event.sequence > after)
            .take(limit)
            .copied()
            .collect();
        let next = events
            .last()
            .map_or(after.min(self.last), |event| event.sequence);
        EventPage { events, next, gap }
    }
}
impl State {
    /// Append events for every change since the last release. Returns whether
    /// anything was appended.
    pub(super) fn record_events(&mut self) -> bool {
        let Self {
            entries,
            events,
            snapshot,
            ..
        } = self;
        let mut appended = false;
        for entry in entries.iter_mut() {
            let operation = entry.accepted.operation;
            let stage = entry.setup.as_ref().map(|record| record.observation.stage);
            if !entry.reported.accepted {
                appended |= events.push(EventKind::OperationAccepted {
                    operation,
                    kind: OperationKind::of(&entry.fingerprint),
                });
                entry.reported.accepted = true;
                entry.reported.stage = stage;
            }
            if let Some(stage) = stage
                && entry.reported.stage != Some(stage)
            {
                appended |= events.push(EventKind::OperationProgress { operation, stage });
                entry.reported.stage = Some(stage);
            }
            if let Some(result) = &entry.result
                && !entry.reported.completed
            {
                appended |= events.push(EventKind::OperationCompleted {
                    operation,
                    outcome: OutcomeName::of(result),
                });
                entry.reported.completed = true;
            }
        }
        let tuple = (
            snapshot.phase,
            snapshot.operation,
            snapshot.generation,
            snapshot.terminal,
        );
        if events.lifecycle != Some(tuple) {
            appended |= events.push(EventKind::Lifecycle {
                phase: tuple.0,
                operation: tuple.1,
                generation: tuple.2,
                terminal: tuple.3,
            });
            events.lifecycle = Some(tuple);
        }
        appended
    }
}
/// Mutex guard that records the published state before release.
pub(super) struct StateGuard<'a> {
    guard: std::sync::MutexGuard<'a, State>,
    changed: &'a watch::Sender<()>,
}
impl<'a> StateGuard<'a> {
    pub(super) fn new(
        guard: std::sync::MutexGuard<'a, State>,
        changed: &'a watch::Sender<()>,
    ) -> Self {
        Self { guard, changed }
    }
}
impl std::ops::Deref for StateGuard<'_> {
    type Target = State;
    fn deref(&self) -> &State {
        &self.guard
    }
}
impl std::ops::DerefMut for StateGuard<'_> {
    fn deref_mut(&mut self) -> &mut State {
        &mut self.guard
    }
}
impl Drop for StateGuard<'_> {
    fn drop(&mut self) {
        if self.guard.record_events() {
            // Synchronous watch publication; waiters lock the state later, so
            // notifying under the mutex cannot re-enter or deadlock it.
            self.changed.send_replace(());
        }
    }
}
/// Random service identity; a fallback keeps service construction infallible.
pub(super) fn instance() -> u64 {
    use ring::rand::SecureRandom;
    let mut bytes = [0; 8];
    if ring::rand::SystemRandom::new().fill(&mut bytes).is_ok() {
        return u64::from_be_bytes(bytes);
    }
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(1, |value| value.as_nanos() as u64)
        ^ u64::from(std::process::id()).rotate_left(32)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lifecycle(phase: Phase) -> EventKind {
        EventKind::Lifecycle {
            phase,
            operation: None,
            generation: None,
            terminal: None,
        }
    }

    #[test]
    fn page_reports_gap_only_for_evicted_events() {
        let mut log = EventLog::new();
        assert_eq!(
            log.page(0, 8),
            EventPage {
                events: vec![],
                next: 0,
                gap: false
            }
        );
        for _ in 0..EVENT_CAPACITY + 10 {
            assert!(log.push(lifecycle(Phase::Disconnected)));
        }
        let page = log.page(0, 100);
        assert!(page.gap);
        assert_eq!(page.events.len(), EVENT_PAGE_LIMIT);
        assert_eq!(page.events[0].sequence, 11);
        let page = log.page(10, 4);
        assert!(!page.gap);
        assert_eq!(page.next, 14);
        let last = log.last();
        let page = log.page(last, 4);
        assert!(!page.gap && page.events.is_empty() && page.next == last);
        // A cursor beyond the log is clamped to the log, never trusted.
        let page = log.page(last + 50, 4);
        assert!(!page.gap && page.events.is_empty() && page.next == last);
    }

    fn kinds(handle: &Handle, after: u64) -> Vec<EventKind> {
        let page = handle.events(after, EVENT_PAGE_LIMIT);
        assert!(!page.gap);
        page.events.iter().map(|event| event.kind).collect()
    }

    fn seed(handle: &Handle, fingerprint: Fingerprint, setup: bool) -> OperationId {
        let mut state = handle.0.lock();
        let operation = OperationId(state.last_key + 1);
        let accepted = Accepted {
            operation,
            deadline: None,
        };
        state.entries.push_back(Entry {
            accepted,
            fingerprint,
            result: None,
            cancel: false,
            setup: setup.then(|| {
                setup::Record::new(operation, Instant::now(), std::time::Duration::from_secs(5))
            }),
            reported: Reported::default(),
        });
        state.last_key = operation.0;
        state.snapshot.operation = Some(operation);
        state.snapshot.phase = Phase::Preparing;
        operation
    }

    #[tokio::test]
    async fn every_published_transition_is_one_exact_event() {
        let (handle, run) = channel();
        assert_eq!(kinds(&handle, 0), vec![lifecycle(Phase::Disconnected)]);
        let base = handle.event_cursor();
        // A refused submission publishes nothing.
        assert_eq!(handle.disconnect(RequestKey(1)), Err(SubmitError::State));
        assert_eq!(
            handle.reconnect_retained(RequestKey(1)),
            Err(SubmitError::State)
        );
        let _ = handle.snapshot();
        assert_eq!(handle.event_cursor(), base);

        let operation = seed(&handle, Fingerprint::Connect(Arc::new(())), true);
        setup::stage(&handle.0, operation, SetupStage::SocketBind);
        setup::stage(&handle.0, operation, SetupStage::SocketBind);
        let waiter = {
            let handle = handle.clone();
            let cursor = handle.event_cursor();
            tokio::spawn(async move { handle.wait_event(cursor).await })
        };
        owner::finish(&handle.0, operation, Completed::Cancelled);
        assert_eq!(waiter.await.ok(), Some(Ok(())));
        assert_eq!(
            kinds(&handle, base),
            vec![
                EventKind::OperationAccepted {
                    operation,
                    kind: OperationKind::Connect
                },
                EventKind::Lifecycle {
                    phase: Phase::Preparing,
                    operation: Some(operation),
                    generation: None,
                    terminal: None
                },
                EventKind::OperationProgress {
                    operation,
                    stage: SetupStage::SocketBind
                },
                EventKind::OperationCompleted {
                    operation,
                    outcome: OutcomeName::Cancelled
                },
                lifecycle(Phase::Disconnected),
            ]
        );
        let view = handle.operation(operation);
        assert!(matches!(
            view,
            Ok(OperationView {
                kind: OperationKind::Connect,
                result: Some(Completed::Cancelled),
                ..
            })
        ));
        assert_eq!(
            handle.operation(OperationId(9)).err(),
            Some(SubmitError::FutureKey)
        );

        // Dropping the owner during an apply records an uncertain outcome.
        let cursor = handle.event_cursor();
        let apply = seed(
            &handle,
            Fingerprint::Apply(local::Request {
                version: local::VERSION,
                action: local::Action::DrainProxy {},
            }),
            false,
        );
        drop(run);
        let events = kinds(&handle, cursor);
        assert_eq!(events.len(), 4, "{events:?}");
        assert!(matches!(
            events[0],
            EventKind::OperationAccepted { operation, kind: OperationKind::Apply } if operation == apply
        ));
        assert!(matches!(
            events[2],
            EventKind::OperationCompleted { operation, outcome: OutcomeName::OutcomeUnknown } if operation == apply
        ));
        assert!(matches!(
            events[3],
            EventKind::Lifecycle {
                phase: Phase::Closed,
                operation: None,
                ..
            }
        ));
        let cursor = handle.event_cursor();
        assert_eq!(handle.wait_event(cursor).await, Err(SubmitError::Closed));
    }
}
