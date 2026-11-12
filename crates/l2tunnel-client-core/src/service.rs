//! One retained managed-TCP lifecycle for authorized local frontends.
//!
//! This first slice supports the existing managed TCP/frame profile only. Other
//! profile factories remain independent; there is no implicit fallback. Handles
//! and waiters do not own or cancel the actor. The caller retains and polls Run.
use crate::{ConnectionConfig, local};
use l2tunnel_runtime::managed;
use std::{
    collections::VecDeque,
    future::Future,
    io,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
};
use tokio::{
    sync::{Notify, watch},
    time::Instant,
};
mod prepared;
pub use prepared::{Attachment, Client, Options, Prepared, Server};
mod owner;
#[cfg(test)]
mod tests;
const RETAINED: usize = 32;

/// Monotonic local request ordinal; not a secret or a peer transaction identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct RequestKey(u64);
impl RequestKey {
    /// Construct an ordinal; only the actor's next key or a retained replay is accepted.
    pub fn new(value: u64) -> Option<Self> {
        (value != 0).then_some(Self(value))
    }
    /// Exact monotonically increasing ordinal.
    pub fn value(self) -> u64 {
        self.0
    }
}
/// Accepted operation identifier, stable for identical retries.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct OperationId(u64);
impl OperationId {
    /// Exact service-local ordinal, not a peer wire identifier.
    pub fn value(self) -> u64 {
        self.0
    }
}
/// A reserved operation slot. It does not prove a peer or device changed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Accepted {
    /// Stable operation ID.
    pub operation: OperationId,
    /// Original accepted setup expiry, absent for runtime-owned apply deadlines.
    pub deadline: Option<Instant>,
}
/// Service-side lifecycle state, distinct from the peer transaction phase.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Phase {
    /// No retained session.
    Disconnected,
    /// An accepted plan is waiting for its original setup owner.
    Preparing,
    /// Real socket/authentication setup is being driven; not an authentication witness.
    Authenticating,
    /// Authentication, device opening and the runtime's first live status completed.
    Connected,
    /// Existing runtime peer transaction is awaiting its own actual result.
    Applying,
    /// Explicit local abort is releasing original owners.
    Stopping,
    /// Setup/runtime failed; no clean close claim.
    Failed,
    /// The service Run was dropped.
    Closed,
}
/// Bounded non-secret failure. Provider/peer-controlled error strings are not copied.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Failure {
    /// Actual local error category.
    pub kind: io::ErrorKind,
}
/// Actual completion of an accepted operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Completed {
    /// Exact live runtime generation. Authentication alone cannot produce this.
    Connected {
        /// Exact service generation which reached actual runtime readiness.
        generation: OperationId,
    },
    /// Original managed owners were dropped; this is deliberately not clean drain.
    Aborted,
    /// Existing typed control response, obtained after runtime completion/rejection.
    Applied(local::Response),
    /// Existing runtime definitively rejected/aborted the proposal before commit.
    Rejected(local::Response),
    /// Setup was explicitly cancelled before becoming live.
    Cancelled,
    /// Service ownership ended during an accepted apply. Peer outcome may have
    /// committed; this is never a rollback or a cancelled transaction claim.
    OutcomeUnknown,
    /// Original deadline or actual factory/runtime failure.
    Failed(Failure),
}
/// Why a live generation stopped; none of these mean peer-confirmed clean close.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Terminal {
    /// Explicit disconnect, reconnect or service owner cancellation.
    Aborted,
    /// Actual managed runtime returned or failed.
    Failed(Failure),
}
/// Actual currently retained setup listener, associated with its operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Listening {
    /// Setup operation which owns this listener, not a previous live generation.
    pub operation: OperationId,
    /// Actual kernel-bound address.
    pub address: std::net::SocketAddr,
}
/// Latest lifecycle plus the existing actual runtime observation.
#[derive(Clone, Debug)]
pub struct Snapshot {
    /// Current local lifecycle stage.
    pub phase: Phase,
    /// Pending operation, if any.
    pub operation: Option<OperationId>,
    /// Current/last live generation.
    pub generation: Option<OperationId>,
    /// Actual bound listener address, useful before first peer arrives.
    pub listening: Option<Listening>,
    /// Current actual managed status, never inferred from the requested profile.
    pub runtime: Option<managed::Status>,
    /// Latest actual generation termination.
    pub terminal: Option<Terminal>,
}
/// Submission rejection before additional protocol/device work.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SubmitError {
    /// One operation is already active.
    Busy,
    /// Same retained key describes different parameters or a different Prepared identity.
    Conflict,
    /// This accepted key/result has been retired from bounded history.
    Expired,
    /// Key was never issued as the next sequential ordinal.
    FutureKey,
    /// Service stopped or its monotonic sequence is exhausted.
    Closed,
    /// Operation is inappropriate in the current local state.
    State,
    /// Profile/method/version is unsupported and nothing was submitted.
    Unsupported,
}
#[derive(Clone)]
enum Fingerprint {
    Connect(Arc<()>),
    Reconnect(Arc<()>),
    Disconnect,
    Apply(local::Request),
}
impl Fingerprint {
    fn same(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Connect(a), Self::Connect(b)) | (Self::Reconnect(a), Self::Reconnect(b)) => {
                Arc::ptr_eq(a, b)
            }
            (Self::Disconnect, Self::Disconnect) => true,
            (Self::Apply(a), Self::Apply(b)) => a == b,
            _ => false,
        }
    }
}
struct Entry {
    accepted: Accepted,
    fingerprint: Fingerprint,
    result: Option<Completed>,
    cancel: bool,
}
enum Command {
    Connect(Prepared),
    Reconnect(Prepared),
    Disconnect,
    Apply(local::Request),
}
struct Job {
    accepted: Accepted,
    command: Command,
}
struct State {
    snapshot: Snapshot,
    control: Option<managed::ControlHandle>,
    profile: Option<managed::ProfileHandle>,
    queued: Option<Job>,
    entries: VecDeque<Entry>,
    terminals: VecDeque<(OperationId, Terminal)>,
    last_key: u64,
    retired_through: u64,
}
struct Shared {
    state: Mutex<State>,
    wake: Notify,
    changed: watch::Sender<()>,
}
impl Shared {
    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        // No user/provider code runs under this mutex. Recovering a poisoned local
        // observation lock never authorizes a peer action or panics on a request.
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
    fn changed(&self) {
        self.changed.send_replace(());
    }
}
/// Cloneable local request/status handle; dropping it never stops Run.
#[derive(Clone)]
pub struct Handle(Arc<Shared>);
impl Handle {
    /// Next permitted request key. Concurrent writers must handle Conflict/Busy;
    /// merely reading this value does not reserve anything or extend a deadline.
    pub fn next_key(&self) -> Result<RequestKey, SubmitError> {
        let state = self.0.lock();
        if state.snapshot.phase == Phase::Closed {
            return Err(SubmitError::Closed);
        }
        state
            .last_key
            .checked_add(1)
            .and_then(RequestKey::new)
            .ok_or(SubmitError::Closed)
    }
    /// Wake stream for lifecycle changes; use snapshot() for fresh runtime counters.
    pub fn subscribe(&self) -> watch::Receiver<()> {
        self.0.changed.subscribe()
    }
    /// Latest local lifecycle and the maintained runtime's current status.
    pub fn snapshot(&self) -> Snapshot {
        let state = self.0.lock();
        let mut snapshot = state.snapshot.clone();
        snapshot.runtime = state
            .control
            .as_ref()
            .and_then(managed::ControlHandle::status)
            .or(snapshot.runtime);
        snapshot
    }
    /// Actual profiler for exactly this current/last generation. A different
    /// generation never exposes its clock or counters through this lookup.
    pub fn profile(
        &self,
        generation: OperationId,
    ) -> Result<Option<managed::ProfileHandle>, SubmitError> {
        let state = self.0.lock();
        if state.snapshot.generation != Some(generation) {
            return Err(SubmitError::State);
        }
        Ok(state.profile.clone())
    }
    /// Submit managed TCP setup; clones of Prepared retain the exact identity.
    /// Caller credential parsing precedes Prepared/acceptance and is excluded
    /// from this bound. Acceptance starts it before queued socket/device work.
    pub fn connect(&self, plan: Prepared, key: RequestKey) -> Result<Accepted, SubmitError> {
        self.submit(
            Fingerprint::Connect(plan.identity.clone()),
            Command::Connect(plan),
            key,
        )
    }
    /// Abort original owners. Managed TCP has no clean-drain implementation.
    pub fn disconnect(&self, key: RequestKey) -> Result<Accepted, SubmitError> {
        self.submit(Fingerprint::Disconnect, Command::Disconnect, key)
    }
    /// Abort and release the old generation before any replacement setup I/O.
    pub fn reconnect(&self, plan: Prepared, key: RequestKey) -> Result<Accepted, SubmitError> {
        self.submit(
            Fingerprint::Reconnect(plan.identity.clone()),
            Command::Reconnect(plan),
            key,
        )
    }
    /// Submit the existing compression action; no cancellation/rollback is exposed.
    /// Peer transaction deadlines and commit reconciliation remain runtime-owned.
    pub fn apply(&self, request: local::Request, key: RequestKey) -> Result<Accepted, SubmitError> {
        if request.version != local::VERSION
            || !matches!(request.action, local::Action::SwitchCompression { .. })
        {
            return Err(SubmitError::Unsupported);
        }
        self.submit(
            Fingerprint::Apply(request.clone()),
            Command::Apply(request),
            key,
        )
    }
    fn submit(
        &self,
        fingerprint: Fingerprint,
        command: Command,
        key: RequestKey,
    ) -> Result<Accepted, SubmitError> {
        let mut state = self.0.lock();
        if state.snapshot.phase == Phase::Closed {
            return Err(SubmitError::Closed);
        }
        if key.0 <= state.last_key {
            if key.0 <= state.retired_through {
                return Err(SubmitError::Expired);
            }
            let entry = state
                .entries
                .iter()
                .find(|e| e.accepted.operation.0 == key.0)
                .ok_or(SubmitError::Expired)?;
            return if entry.fingerprint.same(&fingerprint) {
                Ok(entry.accepted)
            } else {
                Err(SubmitError::Conflict)
            };
        }
        if state.last_key.checked_add(1) != Some(key.0) {
            return Err(SubmitError::FutureKey);
        }
        if state.snapshot.operation.is_some() {
            return Err(SubmitError::Busy);
        }
        let connected = state.control.is_some();
        match &command {
            Command::Connect(_) if connected => return Err(SubmitError::State),
            Command::Reconnect(_) | Command::Disconnect | Command::Apply(_) if !connected => {
                return Err(SubmitError::State);
            }
            _ => {}
        }
        // No credential/provider/device work occurs here. Acceptance starts the
        // one absolute bound, including any scheduling delay before first poll.
        let deadline = match &command {
            Command::Connect(p) | Command::Reconnect(p) => Some(
                Instant::now()
                    .checked_add(p.data.connection.handshake_timeout)
                    .ok_or(SubmitError::Closed)?,
            ),
            _ => None,
        };
        let accepted = Accepted {
            operation: OperationId(key.0),
            deadline,
        };
        if state.entries.len() == RETAINED {
            let retired = state.entries.pop_front().ok_or(SubmitError::Closed)?;
            state.retired_through = retired.accepted.operation.0;
        }
        state.last_key = key.0;
        state.entries.push_back(Entry {
            accepted,
            fingerprint,
            result: None,
            cancel: false,
        });
        state.snapshot.operation = Some(accepted.operation);
        state.snapshot.phase = match command {
            Command::Connect(_) => Phase::Preparing,
            Command::Apply(_) => Phase::Applying,
            _ => Phase::Stopping,
        };
        state.queued = Some(Job { accepted, command });
        drop(state);
        self.0.changed();
        self.0.wake.notify_one();
        Ok(accepted)
    }
    /// Cancel setup/reconnect only. Applied peer transactions cannot be rolled back.
    pub fn cancel(&self, id: OperationId) -> Result<(), SubmitError> {
        let mut state = self.0.lock();
        let missing = if id.0 <= state.retired_through {
            SubmitError::Expired
        } else {
            SubmitError::State
        };
        let entry = state
            .entries
            .iter_mut()
            .find(|e| e.accepted.operation == id)
            .ok_or(missing)?;
        if entry.result.is_some() {
            return Err(SubmitError::State);
        }
        if !matches!(
            entry.fingerprint,
            Fingerprint::Connect(_) | Fingerprint::Reconnect(_)
        ) {
            return Err(SubmitError::Unsupported);
        }
        entry.cancel = true;
        drop(state);
        self.0.wake.notify_one();
        Ok(())
    }
    /// Wait for actual completion. Dropping this future has no cancellation effect.
    pub async fn wait(&self, id: OperationId) -> Result<Completed, SubmitError> {
        let mut changed = self.subscribe();
        loop {
            {
                let state = self.0.lock();
                if let Some(entry) = state.entries.iter().find(|e| e.accepted.operation == id) {
                    if let Some(result) = &entry.result {
                        return Ok(result.clone());
                    }
                } else {
                    return Err(if id.0 <= state.retired_through {
                        SubmitError::Expired
                    } else {
                        SubmitError::State
                    });
                }
            }
            changed.changed().await.map_err(|_| SubmitError::Closed)?;
        }
    }
    /// Wait for an actual retained generation to stop, independently of operation acceptance.
    pub async fn wait_stopped(&self, generation: OperationId) -> Result<Terminal, SubmitError> {
        let mut changed = self.subscribe();
        loop {
            {
                let state = self.0.lock();
                if let Some((_, terminal)) =
                    state.terminals.iter().find(|(id, _)| *id == generation)
                {
                    return Ok(*terminal);
                }
                if state
                    .terminals
                    .front()
                    .is_some_and(|(id, _)| *id > generation)
                {
                    return Err(SubmitError::Expired);
                }
                if state.snapshot.phase == Phase::Closed {
                    return Err(SubmitError::Closed);
                }
                if generation.0 > state.last_key {
                    return Err(SubmitError::FutureKey);
                }
                if state.snapshot.generation != Some(generation) {
                    return Err(SubmitError::State);
                }
            }
            changed.changed().await.map_err(|_| SubmitError::Closed)?;
        }
    }
    /// Adapt the existing authorized local API without creating a new local wire.
    pub async fn request(&self, request: local::Request) -> local::Response {
        if request.version != local::VERSION {
            return response("unsupported_version");
        }
        if matches!(request.action, local::Action::Status {}) {
            let control = self.0.lock().control.clone();
            return match control {
                Some(control) => {
                    crate::session_control::Control::managed(control)
                        .request(request)
                        .await
                }
                None => response("closed"),
            };
        }
        // Local-v1 has no idempotency field. Serialize key allocation+submission
        // under retry-free admission; a concurrent submit returns Busy/Conflict.
        let accepted = self.next_key().and_then(|key| self.apply(request, key));
        match accepted {
            Ok(accepted) => match self.wait(accepted.operation).await {
                Ok(Completed::Applied(result) | Completed::Rejected(result)) => result,
                Ok(Completed::OutcomeUnknown) => response("outcome_unknown"),
                _ => response("closed"),
            },
            Err(SubmitError::Unsupported) => response("unsupported"),
            Err(SubmitError::Busy | SubmitError::Conflict) => response("busy"),
            Err(_) => response("closed"),
        }
    }
}
fn response(code: &str) -> local::Response {
    local::Response {
        version: local::VERSION,
        ok: false,
        code: code.into(),
        state: None,
    }
}
type RunFuture = Pin<Box<dyn Future<Output = io::Result<()>> + Send>>;
/// Sole lifecycle actor. No task is implicitly spawned. Original inline managed
/// socket/device futures drop before the completion guard publishes cancellation.
pub struct Run {
    future: RunFuture,
    _completion: Completion,
}
impl Future for Run {
    type Output = io::Result<()>;
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.future.as_mut().poll(cx)
    }
}
struct Completion(Arc<Shared>);
impl Drop for Completion {
    fn drop(&mut self) {
        let mut state = self.0.lock();
        state.snapshot.phase = Phase::Closed;
        state.snapshot.listening = None;
        if let Some(control) = state.control.take() {
            state.snapshot.runtime = control.status();
        }
        if let Some(generation) = state.snapshot.generation
            && !state.terminals.iter().any(|(id, _)| *id == generation)
        {
            // Evict before insertion: pushing into the full fixed-capacity deque
            // would grow its allocation even if the count were trimmed later.
            if state.terminals.len() == RETAINED {
                state.terminals.pop_front();
            }
            state.terminals.push_back((generation, Terminal::Aborted));
        }
        for entry in &mut state.entries {
            if entry.result.is_none() {
                entry.result = Some(if matches!(entry.fingerprint, Fingerprint::Apply(_)) {
                    Completed::OutcomeUnknown
                } else {
                    Completed::Cancelled
                });
            }
        }
        state.snapshot.operation = None;
        // Keep an already observed runtime failure; dropping an idle service
        // must not rewrite its actual terminal outcome as a fresh local abort.
        if let Some(generation) = state.snapshot.generation
            && let Some((_, terminal)) = state.terminals.iter().find(|(id, _)| *id == generation)
        {
            state.snapshot.terminal = Some(*terminal);
        }
        let queued = state.queued.take();
        drop(state);
        drop(queued);
        self.0.changed();
    }
}
/// Allocate a fixed-size service with one operation/session slot and 32 retained
/// operation results/identities plus 32 terminal generation outcomes.
pub fn channel() -> (Handle, Run) {
    let (changed, _) = watch::channel(());
    let shared = Arc::new(Shared {
        state: Mutex::new(State {
            snapshot: Snapshot {
                phase: Phase::Disconnected,
                operation: None,
                generation: None,
                listening: None,
                runtime: None,
                terminal: None,
            },
            control: None,
            profile: None,
            queued: None,
            entries: VecDeque::with_capacity(RETAINED),
            terminals: VecDeque::with_capacity(RETAINED),
            last_key: 0,
            retired_through: 0,
        }),
        wake: Notify::new(),
        changed,
    });
    (
        Handle(shared.clone()),
        Run {
            future: Box::pin(owner::run(shared.clone())),
            _completion: Completion(shared),
        },
    )
}
