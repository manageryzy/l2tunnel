//! One retained lifecycle owner for authorized local frontends.
//!
//! Current Common carrier profiles share this retained owner. There is no
//! implicit carrier fallback or credential migration.
//! Handles and waiters do not own or cancel the actor. The caller retains and
//! polls Run.
use crate::{ConnectionConfig, local};
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
mod connection_reuse;
mod prepared;
pub use prepared::{Attachment, Client, Prepared, Server};
mod common_local;
mod common_reuse_local;
mod owner;
mod proxy_backend;
#[cfg(unix)]
pub use proxy_backend::ProxyCommonFrame;
pub use proxy_backend::{ProxyFrame, ProxyProfile};
mod setup;
pub use setup::{SetupFailure, SetupFailureReason, SetupObservation, SetupOutcome, SetupStage};
#[cfg(all(test, unix))]
#[path = "service/tests/atomic_local.rs"]
mod atomic_local_tests;
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
    /// The original owners are being released before terminal publication or reconnect.
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
    /// Existing typed control response. Proxy drain explicitly reports local
    /// acceptance; only the separate actual terminal carries closure proof.
    Applied(local::Response),
    /// Existing runtime definitively rejected/aborted the proposal before commit.
    Rejected(local::Response),
    /// Actual complete Common-profile result, without a Swift-only DTO conversion.
    /// Closed or uncertain peer outcomes use OutcomeUnknown instead.
    Common {
        /// Exact originally submitted complete configuration.
        configuration: l2tunnel::record_configuration::Configuration,
        /// Confirmed epoch or definitive runtime refusal.
        outcome: Result<l2tunnel_core::Epoch, l2tunnel_runtime::secure_udp::transport::SwitchError>,
    },
    /// Exact result of the selected reuse protocol on this same runtime owner.
    ConnectionReuse {
        /// Original bounded owner/flow request retained for exact replay.
        request: local::ConnectionReuseRequest,
        /// Original actual service generation owning this runtime request.
        generation: u64,
        /// Actual protocol confirmation/refusal; no timeout implies rollback.
        outcome: Result<
            l2tunnel_runtime::secure_udp::transport::ConnectionReuseOutcome,
            l2tunnel_runtime::secure_udp::transport::ConnectionReuseError,
        >,
    },
    /// Setup was explicitly cancelled before becoming live.
    Cancelled,
    /// Service ownership ended during an accepted apply. Peer outcome may have
    /// committed; this is never a rollback or a cancelled transaction claim.
    OutcomeUnknown,
    /// Original deadline or actual factory/runtime failure.
    Failed(Failure),
}
/// Why a live generation stopped; only explicit Closed carries a clean proxy proof.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Terminal {
    /// Explicit disconnect, reconnect or service owner cancellation.
    Aborted,
    /// The selected proxy completed its actual authenticated drain and joined children.
    Closed,
    /// Actual runtime returned or failed.
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
/// Actual selected mixed-profile runtime observation for shared embedding clients.
/// Local APIv4 and shared frontends project this same retained view.
#[derive(Clone, Debug)]
pub struct SecureUdpCommonFrame {
    /// Complete effective startup plan and authenticated finite catalog. A carrier
    /// bound profile also retains the original requested envelope and policy.
    pub requested: Arc<crate::secure_udp::common_transaction_profile::Profile>,
    /// Authentication evidence from the original retained UDP socket.
    pub info: l2tunnel_runtime::secure_udp::member::Info,
    /// Actual runtime observation; absent before readiness, never fabricated.
    pub runtime: Option<l2tunnel_runtime::secure_udp::transport::CommonSnapshot>,
    /// Exact local service generation.
    pub generation: u64,
    /// Actual service release, separate from the last runtime observation.
    pub service_terminal: Option<Terminal>,
}
impl SecureUdpCommonFrame {
    /// Bounded complete-configuration observation without credentials or payloads.
    pub fn status(&self) -> io::Result<crate::secure_udp::common_status::Status> {
        let mut status = crate::secure_udp::common_status::Status::observe(
            &self.requested,
            self.info,
            self.generation,
            self.runtime.as_ref(),
        )?;
        status.service_terminal = self.service_terminal.map(|value| format!("{value:?}"));
        if self.service_terminal.is_some() {
            status.running = false;
        }
        Ok(status)
    }
}
/// Actual observation of the one live or last backend; variants are never merged.
#[derive(Clone, Debug)]
pub enum Observation {
    /// Exact fixed/measured TCP proxy owner, separate from Common profiles.
    Proxy(Box<ProxyFrame>),
    /// Explicit mixed-profile Common owner; no Swift status projection.
    SecureUdpCommon(Box<SecureUdpCommonFrame>),
}
impl Observation {
    fn record_service_terminal(&mut self, terminal: Terminal) {
        match self {
            Self::Proxy(frame) => frame.service_terminal = Some(terminal),
            Self::SecureUdpCommon(frame) => frame.service_terminal = Some(terminal),
        }
    }
    /// Actual fixed/measured proxy observation, absent for other selections.
    pub fn proxy(&self) -> Option<&ProxyFrame> {
        match self {
            Self::Proxy(frame) => Some(frame),
            _ => None,
        }
    }
    /// Actual complete Common observation, absent for other backend selections.
    pub fn secure_udp_common(&self) -> Option<&SecureUdpCommonFrame> {
        match self {
            Self::SecureUdpCommon(frame) => Some(frame),
            _ => None,
        }
    }
}
/// Authoritative handles of the live backend. Its presence is the live-session
/// predicate; it is not a capability flag or a second lifecycle state machine.
#[derive(Clone)]
enum ObservedBackend {
    Proxy(Arc<proxy_backend::Backend>),
    SecureUdpCommon(Arc<SecureUdpCommonBackend>),
}
struct SecureUdpCommonBackend {
    requested: Arc<crate::secure_udp::common_transaction_profile::Profile>,
    info: l2tunnel_runtime::secure_udp::member::Info,
    counters: Mutex<Option<l2tunnel_runtime::secure_udp::transport::CommonSnapshot>>,
    switcher: l2tunnel_runtime::secure_udp::transport::CommonControlHandle,
    generation: u64,
}
impl ObservedBackend {
    fn observe(&self) -> Option<Observation> {
        match self {
            Self::Proxy(proxy) => Some(Observation::Proxy(Box::new(proxy.observe()))),
            Self::SecureUdpCommon(secure) => Some(Observation::SecureUdpCommon(Box::new(
                SecureUdpCommonFrame {
                    requested: secure.requested.clone(),
                    info: secure.info,
                    runtime: secure
                        .counters
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .clone(),
                    generation: secure.generation,
                    service_terminal: None,
                },
            ))),
        }
    }
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
    /// Current actual backend status, never inferred from the requested profile.
    pub runtime: Option<Observation>,
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
    /// A complete canonical value is outside this selected envelope/catalog.
    InvalidConfiguration,
}
#[derive(Clone)]
// Retained history owns complete fixed-size values; boxing would add per-request
// allocations to an already bounded local control path.
#[allow(clippy::large_enum_variant)]
enum Fingerprint {
    Connect(Arc<()>),
    Reconnect(Arc<()>),
    Disconnect,
    Apply(local::Request),
    Common(l2tunnel::record_configuration::Configuration),
    ConnectionReuse(local::ConnectionReuseRequest),
}
impl Fingerprint {
    fn is_apply(&self) -> bool {
        matches!(
            self,
            Self::Apply(_) | Self::Common(_) | Self::ConnectionReuse(_)
        )
    }
    fn same(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Connect(a), Self::Connect(b)) | (Self::Reconnect(a), Self::Reconnect(b)) => {
                Arc::ptr_eq(a, b)
            }
            (Self::Disconnect, Self::Disconnect) => true,
            (Self::Apply(a), Self::Apply(b)) => a == b,
            (Self::Common(a), Self::Common(b)) => a == b,
            (Self::ConnectionReuse(a), Self::ConnectionReuse(b)) => a == b,
            _ => false,
        }
    }
}
struct Entry {
    accepted: Accepted,
    fingerprint: Fingerprint,
    result: Option<Completed>,
    cancel: bool,
    setup: Option<setup::Record>,
}
// The sole queued command retains its complete value without another allocation.
#[allow(clippy::large_enum_variant)]
enum Command {
    Connect(Prepared),
    Reconnect(Prepared),
    Disconnect,
    Apply(local::Request),
    Common(l2tunnel::record_configuration::Configuration),
    ConnectionReuse(local::ConnectionReuseRequest),
}
struct Job {
    accepted: Accepted,
    command: Command,
}
struct TerminalRecord {
    generation: OperationId,
    terminal: Terminal,
    // Inline bounded data only; no runtime/control/cancellation owner is retained.
    proxy_close_report: Option<local::ProxyCloseReport>,
}
struct State {
    snapshot: Snapshot,
    backend: Option<ObservedBackend>,
    queued: Option<Job>,
    entries: VecDeque<Entry>,
    /// Latest accepted setup plan, kept so a local lifecycle request can
    /// connect again without re-parsing credentials.
    plan: Option<Prepared>,
    terminals: VecDeque<TerminalRecord>,
    last_key: u64,
    retired_through: u64,
}
impl State {
    /// Arbitrate an idle runtime exit against disconnect admission under the same lock.
    fn claim_runtime_exit(&mut self) -> bool {
        if matches!(
            self.queued.as_ref().map(|job| &job.command),
            Some(Command::Disconnect)
        ) {
            return false;
        }
        if self.snapshot.operation.is_none() {
            self.snapshot.phase = Phase::Stopping;
        }
        true
    }
}
struct LocalView {
    version: u16,
    snapshot: Snapshot,
    backend: Option<ObservedBackend>,
}
enum LocalAdmissionError {
    Version(Box<local::Response>),
    Submit(SubmitError),
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
        Self::snapshot_locked(&state)
    }
    fn snapshot_locked(state: &State) -> Snapshot {
        let mut snapshot = state.snapshot.clone();
        snapshot.runtime = state
            .backend
            .as_ref()
            .and_then(ObservedBackend::observe)
            .or(snapshot.runtime);
        snapshot
    }
    /// Latest fixed-size evidence for exactly one retained accepted setup.
    /// Reading never refreshes time, performs I/O or adopts another generation.
    pub fn setup_observation(
        &self,
        id: OperationId,
    ) -> Result<Option<SetupObservation>, SubmitError> {
        let state = self.0.lock();
        if let Some(entry) = state
            .entries
            .iter()
            .find(|entry| entry.accepted.operation == id)
        {
            return Ok(entry.setup.as_ref().map(|record| record.observation));
        }
        Err(if id.0 <= state.retired_through {
            SubmitError::Expired
        } else if id.0 > state.last_key {
            SubmitError::FutureKey
        } else {
            SubmitError::State
        })
    }
    /// Submit setup for the prepared backend; clones of Prepared retain the exact identity.
    /// Caller credential parsing precedes Prepared/acceptance and is excluded
    /// from this bound. Acceptance starts it before queued socket/device work.
    pub fn connect(&self, plan: Prepared, key: RequestKey) -> Result<Accepted, SubmitError> {
        self.submit(
            Fingerprint::Connect(plan.identity.clone()),
            Command::Connect(plan),
            key,
        )
    }
    /// Abort original owners. No supported backend has a clean-drain implementation.
    pub fn disconnect(&self, key: RequestKey) -> Result<Accepted, SubmitError> {
        self.submit(Fingerprint::Disconnect, Command::Disconnect, key)
    }
    /// Abort and release the old generation before any replacement setup I/O.
    /// After backend failure, an already retained plan also permits a fresh
    /// authenticated replacement. This does not resume the failed protocol state.
    pub fn reconnect(&self, plan: Prepared, key: RequestKey) -> Result<Accepted, SubmitError> {
        self.submit(
            Fingerprint::Reconnect(plan.identity.clone()),
            Command::Reconnect(plan),
            key,
        )
    }
    /// Submit the existing compression action; no cancellation/rollback is exposed.
    /// Peer transaction deadlines and commit reconciliation remain runtime-owned.
    /// A live datagram backend has a fixed profile: a new key is rejected as
    /// Unsupported without consuming it, queueing a command or sending anything.
    /// Retained keys still replay their original acceptance.
    pub fn apply(&self, request: local::Request, key: RequestKey) -> Result<Accepted, SubmitError> {
        if !local::supported_version(request.version)
            || !matches!(request.action, local::Action::DrainProxy {})
        {
            return Err(SubmitError::Unsupported);
        }
        self.submit(
            Fingerprint::Apply(request.clone()),
            Command::Apply(request),
            key,
        )
    }
    /// Submit a complete supported Common value through the same retained actor.
    /// Retained keys replay their exact acceptance before fresh validation.
    pub fn apply_common(
        &self,
        configuration: l2tunnel::record_configuration::Configuration,
        key: RequestKey,
    ) -> Result<Accepted, SubmitError> {
        self.submit(
            Fingerprint::Common(configuration),
            Command::Common(configuration),
            key,
        )
    }
    fn submit(
        &self,
        fingerprint: Fingerprint,
        command: Command,
        key: RequestKey,
    ) -> Result<Accepted, SubmitError> {
        self.submit_locked(self.0.lock(), fingerprint, command, key)
    }
    fn submit_locked(
        &self,
        mut state: std::sync::MutexGuard<'_, State>,
        fingerprint: Fingerprint,
        command: Command,
        key: RequestKey,
    ) -> Result<Accepted, SubmitError> {
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
        if state.snapshot.operation.is_some() || state.snapshot.phase == Phase::Stopping {
            return Err(SubmitError::Busy);
        }
        if matches!(&state.backend, Some(ObservedBackend::Proxy(backend)) if backend.awaiting_release())
        {
            // Retained keys above still replay, but no new work can replace an
            // owner whose actual child joins have not yet completed.
            return Err(SubmitError::Busy);
        }
        let connected = state.backend.is_some();
        if let Command::Common(configuration) = &command {
            let Some(ObservedBackend::SecureUdpCommon(backend)) = &state.backend else {
                return Err(if connected {
                    SubmitError::Unsupported
                } else {
                    SubmitError::State
                });
            };
            backend
                .requested
                .runtime_contract(backend.info.role)
                .and_then(|contract| contract.resolve(*configuration))
                .map_err(|_| SubmitError::InvalidConfiguration)?;
        }
        let reuse_timeout = if let Command::ConnectionReuse(request) = &command {
            Some(connection_reuse::validate(&state, *request)?)
        } else {
            None
        };
        // Each apply action belongs to one backend; any other pairing is
        // refused without consuming the key or sending anything.
        if let Command::Apply(request) = &command
            && let Some(backend) = &state.backend
        {
            let fits = match request.action {
                local::Action::DrainProxy {} => {
                    request.version == local::VERSION
                        && matches!(backend, ObservedBackend::Proxy(_))
                }
                _ => false,
            };
            if !fits {
                return Err(SubmitError::Unsupported);
            }
        }
        match &command {
            Command::Connect(_) if connected => return Err(SubmitError::State),
            Command::Reconnect(_) if !connected && state.plan.is_none() => {
                return Err(SubmitError::State);
            }
            Command::Disconnect | Command::Apply(_) if !connected => {
                return Err(SubmitError::State);
            }
            _ => {}
        }
        // No credential/provider/device work occurs here. Acceptance starts the
        // one absolute bound, including any scheduling delay before first poll.
        let accepted_at = Instant::now();
        let deadline = match &command {
            Command::Connect(p) | Command::Reconnect(p) => Some(
                accepted_at
                    .checked_add(p.setup_timeout())
                    .ok_or(SubmitError::Closed)?,
            ),
            Command::ConnectionReuse(_) => Some(
                accepted_at
                    .checked_add(reuse_timeout.ok_or(SubmitError::State)?)
                    .ok_or(SubmitError::Closed)?,
            ),
            Command::Disconnect => match &state.backend {
                Some(ObservedBackend::Proxy(backend)) => Some(
                    accepted_at
                        .checked_add(backend.stop_timeout())
                        .ok_or(SubmitError::Closed)?,
                ),
                _ => None,
            },
            _ => None,
        };
        if let Command::Connect(p) | Command::Reconnect(p) = &command {
            state.plan = Some(p.clone());
        }
        let accepted = Accepted {
            operation: OperationId(key.0),
            deadline,
        };
        if state.entries.len() == RETAINED {
            let retired = state.entries.pop_front().ok_or(SubmitError::Closed)?;
            state.retired_through = retired.accepted.operation.0;
        }
        state.last_key = key.0;
        let setup = match &command {
            Command::Connect(plan) | Command::Reconnect(plan) => Some(setup::Record::new(
                accepted.operation,
                accepted_at,
                plan.setup_timeout(),
            )),
            _ => None,
        };
        state.entries.push_back(Entry {
            accepted,
            fingerprint,
            result: None,
            cancel: false,
            setup,
        });
        state.snapshot.operation = Some(accepted.operation);
        state.snapshot.phase = match command {
            Command::Connect(_) => Phase::Preparing,
            Command::Apply(_) => Phase::Applying,
            Command::Common(_) => Phase::Applying,
            Command::ConnectionReuse(_) => Phase::Applying,
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
    /// Wait for the first completed operation after `after` (zero for the
    /// first ever) and return its ordinal with its actual completion. A
    /// frontend follows operations other local clients submitted this way.
    pub async fn wait_next(&self, after: u64) -> Result<(OperationId, Completed), SubmitError> {
        let mut changed = self.subscribe();
        loop {
            {
                let state = self.0.lock();
                if after < state.retired_through {
                    return Err(SubmitError::Expired);
                }
                if let Some(entry) = state
                    .entries
                    .iter()
                    .find(|entry| entry.accepted.operation.0 > after)
                    && let Some(result) = &entry.result
                {
                    return Ok((entry.accepted.operation, result.clone()));
                }
                if state.snapshot.phase == Phase::Closed {
                    return Err(SubmitError::Closed);
                }
            }
            changed.changed().await.map_err(|_| SubmitError::Closed)?;
        }
    }
    fn terminal_record(
        state: &State,
        generation: OperationId,
    ) -> Result<Option<&TerminalRecord>, SubmitError> {
        if let Some(record) = state
            .terminals
            .iter()
            .find(|record| record.generation == generation)
        {
            return Ok(Some(record));
        }
        if state
            .terminals
            .front()
            .is_some_and(|record| record.generation > generation)
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
        Ok(None)
    }
    /// Read an actual successful proxy drain report from the bounded terminal ledger.
    /// Active or non-clean generations have no report. This retains no runtime owner.
    /// Retired/unknown identities have the same errors as `wait_stopped`.
    pub fn proxy_close_report(
        &self,
        generation: OperationId,
    ) -> Result<Option<local::ProxyCloseReport>, SubmitError> {
        Ok(Self::terminal_record(&self.0.lock(), generation)?
            .and_then(|record| record.proxy_close_report.clone()))
    }
    /// Wait for an actual retained generation to stop, independently of operation acceptance.
    pub async fn wait_stopped(&self, generation: OperationId) -> Result<Terminal, SubmitError> {
        let mut changed = self.subscribe();
        loop {
            {
                let state = self.0.lock();
                if let Some(record) = Self::terminal_record(&state, generation)? {
                    return Ok(record.terminal);
                }
            }
            changed.changed().await.map_err(|_| SubmitError::Closed)?;
        }
    }
    /// Adapt the existing authorized local API without creating a new local wire.
    pub async fn request(&self, request: local::Request) -> local::Response {
        if matches!(request.action, local::Action::Status {}) {
            return self.request_status(request, false).await;
        }
        if let Some(response) = self.api_version(&request) {
            return response;
        }
        if matches!(
            &request.action,
            local::Action::SwitchCommonConfiguration { .. }
                | local::Action::CommonCatalog { .. }
                | local::Action::ReuseConnection { .. }
        ) {
            let mut response = self.common_request(request).await;
            self.common_reply_key(&mut response);
            return response;
        }
        let version = request.version;
        let refusal = |code| {
            let mut response = response(code);
            response.version = version;
            response
        };
        // Local-v1 has no idempotency field. Serialize key allocation+submission
        // under retry-free admission; a concurrent submit returns Busy/Conflict.
        let accepted = self.next_key().and_then(|key| self.apply(request, key));
        match accepted {
            Ok(accepted) => match self.wait(accepted.operation).await {
                Ok(Completed::Applied(result) | Completed::Rejected(result)) => result,
                Ok(Completed::OutcomeUnknown) => refusal("outcome_unknown"),
                _ => refusal("closed"),
            },
            Err(SubmitError::Unsupported) => refusal("unsupported"),
            Err(SubmitError::InvalidConfiguration) => refusal("invalid_configuration"),
            Err(SubmitError::Busy | SubmitError::Conflict) => refusal("busy"),
            Err(_) => refusal("closed"),
        }
    }
}
impl Handle {
    fn selected_version(&self) -> u16 {
        Self::selected_version_locked(&self.0.lock())
    }
    fn selected_version_locked(state: &State) -> u16 {
        {
            match &state.backend {
                Some(ObservedBackend::SecureUdpCommon(_)) => local::COMMON_VERSION,
                Some(_) => local::VERSION,
                None => match &state.plan {
                    Some(plan) if plan.secure_udp_common() => local::COMMON_VERSION,
                    _ => local::VERSION,
                },
            }
        }
    }
    fn api_version(&self, request: &local::Request) -> Option<local::Response> {
        Self::version_refusal(request.version, self.selected_version())
    }
    fn version_refusal(version: u16, selected: u16) -> Option<local::Response> {
        let code = if selected == local::COMMON_VERSION && matches!(version, 1..=3) {
            Some("requires_version_4")
        } else if version != selected {
            Some("unsupported_version")
        } else {
            None
        };
        code.map(|code| local::Response {
            version,
            ok: false,
            code: code.into(),
            state: None,
        })
    }
    fn local_view_locked(state: &State) -> LocalView {
        LocalView {
            version: Self::selected_version_locked(state),
            snapshot: Self::snapshot_locked(state),
            backend: state.backend.clone(),
        }
    }
    fn local_view(&self, version: u16) -> Result<LocalView, Box<local::Response>> {
        let state = self.0.lock();
        if let Some(response) =
            Self::version_refusal(version, Self::selected_version_locked(&state))
        {
            return Err(Box::new(response));
        }
        Ok(Self::local_view_locked(&state))
    }
    async fn request_status(&self, request: local::Request, idle_ok: bool) -> local::Response {
        let view = match self.local_view(request.version) {
            Ok(view) => view,
            Err(response) => return *response,
        };
        let mut response = Self::status_from_view(view, request, idle_ok).await;
        self.common_reply_key(&mut response);
        response
    }
    async fn status_from_view(
        view: LocalView,
        _request: local::Request,
        idle_ok: bool,
    ) -> local::Response {
        match view.backend {
            Some(ObservedBackend::Proxy(_)) => Self::proxy_status_from(view.snapshot, true, "ok"),
            Some(ObservedBackend::SecureUdpCommon(_)) => {
                Self::common_status_from(view.snapshot, true, "ok")
            }
            None if view
                .snapshot
                .runtime
                .as_ref()
                .and_then(Observation::proxy)
                .is_some() =>
            {
                Self::proxy_status_from(
                    view.snapshot,
                    idle_ok,
                    if idle_ok { "ok" } else { "closed" },
                )
            }
            None if idle_ok => {
                Self::lifecycle_reply_from(view.version, view.snapshot, false, true, "ok")
            }
            None if view.version == local::COMMON_VERSION => {
                Self::common_status_from(view.snapshot, false, "closed")
            }
            None => local::Response {
                version: view.version,
                ..response("closed")
            },
        }
    }
    fn submit_local_lifecycle(
        &self,
        version: u16,
        reconnect: bool,
    ) -> Result<Accepted, LocalAdmissionError> {
        let state = self.0.lock();
        if let Some(response) =
            Self::version_refusal(version, Self::selected_version_locked(&state))
        {
            return Err(LocalAdmissionError::Version(Box::new(response)));
        }
        let key = state
            .last_key
            .checked_add(1)
            .and_then(RequestKey::new)
            .ok_or(LocalAdmissionError::Submit(SubmitError::Closed))?;
        let (fingerprint, command) = if reconnect {
            let plan = state
                .plan
                .clone()
                .ok_or(LocalAdmissionError::Submit(SubmitError::Closed))?;
            if state.backend.is_some() {
                (
                    Fingerprint::Reconnect(plan.identity.clone()),
                    Command::Reconnect(plan),
                )
            } else {
                (
                    Fingerprint::Connect(plan.identity.clone()),
                    Command::Connect(plan),
                )
            }
        } else {
            (Fingerprint::Disconnect, Command::Disconnect)
        };
        self.submit_locked(state, fingerprint, command, key)
            .map_err(LocalAdmissionError::Submit)
    }
    /// Local API including lifecycle commands: `disconnect` aborts the live
    /// generation and leaves the service idle; `reconnect` replaces it, or
    /// connects again when idle, using the latest accepted plan. Each reply
    /// reports the actual completion, not mere acceptance. Every other
    /// request is answered exactly as [`Self::request`] does. A frontend that
    /// exits when its generation stops should keep using `request`.
    pub async fn lifecycle_request(&self, request: local::Request) -> local::Response {
        let version = request.version;
        let reconnect = match request.action {
            local::Action::Disconnect {} => false,
            local::Action::Reconnect {} => true,
            local::Action::Status {} => return self.request_status(request, true).await,
            _ => return self.request(request).await,
        };
        let accepted = self.submit_local_lifecycle(version, reconnect);
        match accepted {
            Ok(accepted) => match self.wait(accepted.operation).await {
                Ok(Completed::Connected { .. } | Completed::Aborted) => {
                    self.lifecycle_reply(version, true, "ok", true)
                }
                Ok(Completed::Cancelled) => self.lifecycle_reply(version, false, "cancelled", true),
                Ok(Completed::Failed(_)) => self.lifecycle_reply(version, false, "failed", true),
                _ => self.lifecycle_reply(version, false, "closed", true),
            },
            Err(LocalAdmissionError::Version(response)) => *response,
            Err(LocalAdmissionError::Submit(SubmitError::Busy | SubmitError::Conflict)) => {
                self.lifecycle_reply(version, false, "busy", false)
            }
            Err(LocalAdmissionError::Submit(SubmitError::State)) => {
                self.lifecycle_reply(version, false, "state", false)
            }
            Err(_) => self.lifecycle_reply(version, false, "closed", false),
        }
    }
    fn lifecycle_reply(
        &self,
        version: u16,
        ok: bool,
        code: &str,
        accepted: bool,
    ) -> local::Response {
        let view = Self::local_view_locked(&self.0.lock());
        if let Some(refusal) = Self::version_refusal(version, view.version) {
            return if accepted {
                local::Response {
                    version,
                    ..response("outcome_unknown")
                }
            } else {
                refusal
            };
        }
        let mut response = Self::lifecycle_reply_from(
            view.version,
            view.snapshot,
            view.backend.is_some(),
            ok,
            code,
        );
        self.common_reply_key(&mut response);
        response
    }
    fn lifecycle_reply_from(
        version: u16,
        snapshot: Snapshot,
        connected: bool,
        ok: bool,
        code: &str,
    ) -> local::Response {
        if version == local::COMMON_VERSION {
            return Self::common_status_from(snapshot, ok, code);
        }
        if snapshot
            .runtime
            .as_ref()
            .and_then(Observation::proxy)
            .is_some()
        {
            return Self::proxy_status_from(snapshot, ok, code);
        }
        let _ = (snapshot, connected);
        local::Response {
            version,
            ok,
            ..response(code)
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
/// Sole lifecycle actor. Original managed/base UDP owners stay inline. Selected
/// proxy actors own spawned TLS I/O: explicit disconnect observes actual joins;
/// dropping Run only requests their abort and never proves their release.
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
        let proxy_unreleased = matches!(&state.backend,
            Some(ObservedBackend::Proxy(backend)) if !backend.released());
        if let Some(backend) = state.backend.take() {
            state.snapshot.runtime = backend.observe();
        }
        if let Some(generation) = state.snapshot.generation
            && !state
                .terminals
                .iter()
                .any(|record| record.generation == generation)
        {
            // Evict before insertion: pushing into the full fixed-capacity deque
            // would grow its allocation even if the count were trimmed later.
            if state.terminals.len() == RETAINED {
                state.terminals.pop_front();
            }
            let terminal = if proxy_unreleased {
                Terminal::Failed(Failure {
                    kind: io::ErrorKind::Interrupted,
                })
            } else {
                Terminal::Aborted
            };
            state.terminals.push_back(TerminalRecord {
                generation,
                terminal,
                proxy_close_report: None,
            });
        }
        for entry in &mut state.entries {
            if entry.result.is_none() {
                if let Some(record) = &mut entry.setup {
                    record.owner_closed(Instant::now());
                }
                entry.result = Some(if entry.fingerprint.is_apply() {
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
            && let Some(record) = state
                .terminals
                .iter()
                .find(|record| record.generation == generation)
        {
            state.snapshot.terminal = Some(record.terminal);
        }
        if let Some(terminal) = state.snapshot.terminal
            && let Some(observation) = &mut state.snapshot.runtime
        {
            observation.record_service_terminal(terminal);
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
    create_channel(None)
}

/// Create an idle service with an explicitly provisioned reconnect plan.
/// No socket or device is opened until the first successful submission.
pub fn channel_with_plan(plan: Prepared) -> (Handle, Run) {
    create_channel(Some(plan))
}

fn create_channel(plan: Option<Prepared>) -> (Handle, Run) {
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
            backend: None,
            queued: None,
            entries: VecDeque::with_capacity(RETAINED),
            plan,
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
