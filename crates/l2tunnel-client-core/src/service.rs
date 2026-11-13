//! One retained lifecycle owner for authorized local frontends.
//!
//! Existing managed TCP, TLS-bootstrapped UDP/Swift and explicitly selected
//! same-socket secure UDP/Swift share this owner. Other profile factories remain
//! independent; there is no implicit carrier fallback or credential migration.
//! Handles and waiters do not own or cancel the actor. The caller retains and
//! polls Run.
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
#[cfg(unix)]
pub use prepared::SWIFT_LISTEN;
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
/// Requested and effective base UDP profile with the latest actual lane status.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UdpFrame {
    /// Settings the caller prepared, including custom cover and protection suite.
    pub requested: crate::udp::Settings,
    /// Runtime profile returned by the authenticated factory for this generation.
    pub effective: l2tunnel_runtime::udp::Config,
    /// Canonical native delivery policy bound into authentication.
    pub delivery: managed::DeliveryConfig,
    /// Last published lanes. An absent lane is unknown, never zero or ready.
    /// Local queue, native delivery flight and recovery retention stay separate.
    pub lanes: l2tunnel_runtime::udp::Snapshot,
}
/// Requested and effective swift profile with the latest runtime counters.
#[cfg(unix)]
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct SwiftFrame {
    /// Settings the caller prepared.
    pub requested: crate::swift::Settings,
    /// Runtime policy of this endpoint, derived by the authenticated factory.
    pub effective: l2tunnel_runtime::swift::Config,
    /// Effective kernel receive buffer of the data socket in bytes.
    pub receive_buffer: usize,
    /// Latest counters the runtime reported; zero before its first report.
    pub counters: l2tunnel_runtime::swift::Snapshot,
    /// Service generation that owns this session.
    pub generation: u64,
}
/// Same-socket authenticated carrier with its actual native transport observation.
#[cfg(unix)]
#[derive(Clone, Debug)]
pub struct SecureUdpFrame {
    /// Immutable globally authenticated startup/profile construction contract.
    pub requested: crate::secure_udp::profile::Profile,
    /// Actual member and exact public Noise binding, with original endpoints.
    pub info: l2tunnel_runtime::secure_udp::member::Info,
    /// Absent until the real transport publishes its first readiness observation.
    pub runtime: Option<l2tunnel_runtime::secure_udp::transport::Snapshot>,
    /// Exact service generation.
    pub generation: u64,
}
#[cfg(unix)]
impl SecureUdpFrame {
    /// Bounded version2 public observation without credentials or user payloads.
    pub fn status(&self) -> io::Result<crate::secure_udp::status::Status> {
        crate::secure_udp::status::Status::observe(
            self.requested,
            self.info,
            self.generation,
            self.runtime.as_ref(),
        )
    }
}
#[cfg(unix)]
impl SwiftFrame {
    /// Flat non-secret status for the local API.
    pub fn status(&self) -> crate::swift::Status {
        let current = self.current();
        crate::swift::Status {
            generation: self.generation,
            forward_kbit: current.forward_kbit,
            reverse_kbit: current.reverse_kbit,
            path_mtu: current.path_mtu as u64,
            window: current.window as u64,
            repair_permille: u64::from(current.repair_permille),
            channels: current.channels as u64,
            ..crate::swift::Status::new(self.effective, &self.counters)
        }
    }
    /// Settings in force: the requested ones until a negotiated change.
    pub fn current(&self) -> crate::swift::Settings {
        match self.counters.policy {
            Some(policy) => self.requested.with_policy(policy),
            None => self.requested,
        }
    }
}
/// Actual observation of the one live or last backend; variants are never merged.
#[derive(Clone, Debug)]
pub enum Observation {
    /// Existing managed TCP/TLS runtime status.
    Managed(managed::Status),
    /// Base system/frame UDP runtime status, boxed because it carries two lanes.
    UdpFrame(Box<UdpFrame>),
    /// Swift runtime status.
    #[cfg(unix)]
    Swift(Box<SwiftFrame>),
    /// Explicit same-connected-UDP common-session transport.
    #[cfg(unix)]
    SecureUdp(Box<SecureUdpFrame>),
}
impl Observation {
    /// Managed status, absent for every other backend.
    pub fn managed(&self) -> Option<&managed::Status> {
        match self {
            Self::Managed(status) => Some(status),
            _ => None,
        }
    }
    /// Base UDP observation, absent for every other backend.
    pub fn udp_frame(&self) -> Option<&UdpFrame> {
        match self {
            Self::UdpFrame(frame) => Some(frame),
            _ => None,
        }
    }
    /// Swift observation, absent for every other backend.
    #[cfg(unix)]
    pub fn swift(&self) -> Option<&SwiftFrame> {
        match self {
            Self::Swift(frame) => Some(frame),
            _ => None,
        }
    }
    /// Distinct new carrier observation, absent for legacy TLS Swift.
    #[cfg(unix)]
    pub fn secure_udp(&self) -> Option<&SecureUdpFrame> {
        match self {
            Self::SecureUdp(frame) => Some(frame),
            _ => None,
        }
    }
}
/// Authoritative handles of the live backend. Its presence is the live-session
/// predicate; it is not a capability flag or a second lifecycle state machine.
#[derive(Clone)]
enum ObservedBackend {
    Managed {
        control: managed::ControlHandle,
        profile: Option<managed::ProfileHandle>,
    },
    UdpFrame(Arc<UdpBackend>),
    #[cfg(unix)]
    Swift(Arc<SwiftBackend>),
    #[cfg(unix)]
    SecureUdp(Arc<SecureUdpBackend>),
}
#[cfg(unix)]
struct SecureUdpBackend {
    requested: crate::secure_udp::profile::Profile,
    info: l2tunnel_runtime::secure_udp::member::Info,
    counters: Mutex<Option<l2tunnel_runtime::secure_udp::transport::Snapshot>>,
    switcher: l2tunnel_runtime::secure_udp::transport::ControlHandle,
    generation: u64,
}
#[cfg(unix)]
struct SwiftBackend {
    requested: crate::swift::Settings,
    effective: l2tunnel_runtime::swift::Config,
    receive_buffer: usize,
    counters: Mutex<l2tunnel_runtime::swift::Snapshot>,
    switcher: l2tunnel_runtime::swift::Switcher,
    connection: ConnectionConfig,
    client: bool,
    generation: u64,
}
struct UdpBackend {
    observer: l2tunnel_runtime::udp::Observer,
    requested: crate::udp::Settings,
    effective: l2tunnel_runtime::udp::Config,
    delivery: managed::DeliveryConfig,
}
impl ObservedBackend {
    fn observe(&self) -> Option<Observation> {
        match self {
            Self::Managed { control, .. } => control.status().map(Observation::Managed),
            Self::UdpFrame(udp) => Some(Observation::UdpFrame(Box::new(UdpFrame {
                requested: udp.requested,
                effective: udp.effective,
                delivery: udp.delivery,
                lanes: udp.observer.status(),
            }))),
            #[cfg(unix)]
            Self::Swift(swift) => {
                let counters = *swift
                    .counters
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                // After a negotiated change the effective policy is derived
                // from the committed one, exactly as the runtime derived it.
                let effective = counters
                    .policy
                    .and_then(|policy| {
                        swift
                            .requested
                            .with_policy(policy)
                            .runtime(swift.connection, swift.client)
                            .ok()
                    })
                    .map_or(swift.effective, |mut config| {
                        config.report_interval = swift.effective.report_interval;
                        config
                    });
                Some(Observation::Swift(Box::new(SwiftFrame {
                    requested: swift.requested,
                    effective,
                    receive_buffer: swift.receive_buffer,
                    counters,
                    generation: swift.generation,
                })))
            }
            #[cfg(unix)]
            Self::SecureUdp(secure) => Some(Observation::SecureUdp(Box::new(SecureUdpFrame {
                requested: secure.requested,
                info: secure.info,
                runtime: secure
                    .counters
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .clone(),
                generation: secure.generation,
            }))),
        }
    }
    fn managed(&self) -> Option<&managed::ControlHandle> {
        match self {
            Self::Managed { control, .. } => Some(control),
            _ => None,
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
    backend: Option<ObservedBackend>,
    queued: Option<Job>,
    entries: VecDeque<Entry>,
    /// Latest accepted setup plan, kept so a local lifecycle request can
    /// connect again without re-parsing credentials.
    plan: Option<Prepared>,
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
            .backend
            .as_ref()
            .and_then(ObservedBackend::observe)
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
        Ok(match &state.backend {
            Some(ObservedBackend::Managed { profile, .. }) => profile.clone(),
            _ => None,
        })
    }
    /// Latest-snapshot subscription for exactly this live base UDP generation.
    /// It has no history queue and reading it refreshes no timer or counter.
    pub fn datagram_observer(
        &self,
        generation: OperationId,
    ) -> Result<Option<l2tunnel_runtime::udp::Observer>, SubmitError> {
        let state = self.0.lock();
        if state.snapshot.generation != Some(generation) {
            return Err(SubmitError::State);
        }
        Ok(match &state.backend {
            Some(ObservedBackend::UdpFrame(udp)) => Some(udp.observer.clone()),
            _ => None,
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
            || !matches!(
                request.action,
                local::Action::SwitchCompression { .. } | local::Action::SetSwiftPolicy { .. }
            )
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
        let connected = state.backend.is_some();
        // Each apply action belongs to one backend; any other pairing is
        // refused without consuming the key or sending anything.
        if let Command::Apply(request) = &command
            && let Some(backend) = &state.backend
        {
            let fits = match request.action {
                local::Action::SwitchCompression { .. } => {
                    request.version == local::VERSION && backend.managed().is_some()
                }
                #[cfg(unix)]
                local::Action::SetSwiftPolicy { .. } => {
                    (request.version == local::VERSION
                        && matches!(backend, ObservedBackend::Swift(_)))
                        || (request.version == local::SECURE_UDP_VERSION
                            && matches!(backend, ObservedBackend::SecureUdp(_)))
                }
                _ => false,
            };
            if !fits {
                return Err(SubmitError::Unsupported);
            }
        }
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
                    .checked_add(p.setup_timeout())
                    .ok_or(SubmitError::Closed)?,
            ),
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
        if let Some(response) = self.api_version(&request) {
            return response;
        }
        let version = request.version;
        let refusal = |code| {
            let mut response = response(code);
            response.version = version;
            response
        };
        if matches!(request.action, local::Action::Status {}) {
            let backend = self.0.lock().backend.clone();
            return match backend {
                Some(ObservedBackend::Managed { control, .. }) => {
                    crate::session_control::Control::managed(control)
                        .request(request)
                        .await
                }
                // The local v1 status schema describes managed sessions only.
                // Typed in-process status is Handle::snapshot, not a new IPC wire.
                Some(ObservedBackend::UdpFrame(_)) => response("unsupported"),
                #[cfg(unix)]
                Some(ObservedBackend::Swift(_)) => self.swift_status(true, "ok"),
                #[cfg(unix)]
                Some(ObservedBackend::SecureUdp(_)) => self.secure_udp_status(true, "ok"),
                #[cfg(unix)]
                None if version == local::SECURE_UDP_VERSION => {
                    self.secure_udp_status(false, "closed")
                }
                None => refusal("closed"),
            };
        }
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
            Err(SubmitError::Busy | SubmitError::Conflict) => refusal("busy"),
            Err(_) => refusal("closed"),
        }
    }
}
impl Handle {
    fn api_version(&self, request: &local::Request) -> Option<local::Response> {
        #[cfg(unix)]
        let secure = {
            let state = self.0.lock();
            state.plan.as_ref().is_some_and(Prepared::secure_udp)
                || matches!(&state.backend, Some(ObservedBackend::SecureUdp(_)))
        };
        #[cfg(not(unix))]
        let secure = false;
        let code = if secure && request.version == local::VERSION {
            Some("requires_version_2")
        } else if request.version
            != if secure {
                local::SECURE_UDP_VERSION
            } else {
                local::VERSION
            }
        {
            Some("unsupported_version")
        } else {
            None
        };
        code.map(|code| local::Response {
            version: request.version,
            ok: false,
            code: code.into(),
            state: None,
        })
    }
    /// Local API including lifecycle commands: `disconnect` aborts the live
    /// generation and leaves the service idle; `reconnect` replaces it, or
    /// connects again when idle, using the latest accepted plan. Each reply
    /// reports the actual completion, not mere acceptance. Every other
    /// request is answered exactly as [`Self::request`] does. A frontend that
    /// exits when its generation stops should keep using `request`.
    pub async fn lifecycle_request(&self, request: local::Request) -> local::Response {
        if let Some(response) = self.api_version(&request) {
            return response;
        }
        let accepted = match request.action {
            local::Action::Disconnect {} => self.next_key().and_then(|key| self.disconnect(key)),
            local::Action::Reconnect {} => {
                let (plan, connected) = {
                    let state = self.0.lock();
                    (state.plan.clone(), state.backend.is_some())
                };
                let Some(plan) = plan else {
                    return self.lifecycle_reply(false, "closed");
                };
                self.next_key().and_then(|key| {
                    if connected {
                        self.reconnect(plan, key)
                    } else {
                        self.connect(plan, key)
                    }
                })
            }
            local::Action::Status {} if self.0.lock().backend.is_none() => {
                return self.lifecycle_reply(true, "ok");
            }
            _ => return self.request(request).await,
        };
        match accepted {
            Ok(accepted) => match self.wait(accepted.operation).await {
                Ok(Completed::Connected { .. } | Completed::Aborted) => {
                    self.lifecycle_reply(true, "ok")
                }
                Ok(Completed::Cancelled) => self.lifecycle_reply(false, "cancelled"),
                Ok(Completed::Failed(_)) => self.lifecycle_reply(false, "failed"),
                _ => self.lifecycle_reply(false, "closed"),
            },
            Err(SubmitError::Busy | SubmitError::Conflict) => self.lifecycle_reply(false, "busy"),
            Err(SubmitError::State) => self.lifecycle_reply(false, "state"),
            Err(_) => self.lifecycle_reply(false, "closed"),
        }
    }
    fn lifecycle_reply(&self, ok: bool, code: &str) -> local::Response {
        #[cfg(unix)]
        if self
            .0
            .lock()
            .plan
            .as_ref()
            .is_some_and(Prepared::secure_udp)
        {
            return self.secure_udp_status(ok, code);
        }
        #[cfg(unix)]
        if matches!(self.snapshot().runtime, Some(Observation::Swift(_)) | None) {
            return self.swift_status(ok, code);
        }
        local::Response {
            ok,
            ..response(code)
        }
    }
    /// Lifecycle phase and, when a swift generation exists, its last counters.
    #[cfg(unix)]
    fn swift_status(&self, ok: bool, code: &str) -> local::Response {
        let snapshot = self.snapshot();
        let phase = match snapshot.phase {
            Phase::Connected => "forwarding",
            Phase::Disconnected => "disconnected",
            Phase::Preparing | Phase::Authenticating => "connecting",
            Phase::Applying => "applying",
            Phase::Stopping => "stopping",
            Phase::Failed => "failed",
            Phase::Closed => "closed",
        };
        local::Response {
            version: local::VERSION,
            ok,
            code: code.into(),
            state: Some(local::Snapshot {
                epoch: snapshot
                    .runtime
                    .as_ref()
                    .and_then(Observation::swift)
                    .map_or(0, |frame| frame.counters.policy_epoch),
                phase: phase.into(),
                compression: local::Compression::Off,
                active: None,
                proxy: None,
                openvpn_drain: None,
                raw_packet: None,
                rolling: None,
                swift: snapshot
                    .runtime
                    .as_ref()
                    .and_then(Observation::swift)
                    .map(SwiftFrame::status),
                secure_udp: None,
            }),
        }
    }
    #[cfg(unix)]
    fn secure_udp_status(&self, ok: bool, code: &str) -> local::Response {
        let snapshot = self.snapshot();
        let frame = snapshot.runtime.as_ref().and_then(Observation::secure_udp);
        let mut status = match frame.map(SecureUdpFrame::status).transpose() {
            Ok(status) => status,
            Err(_) => {
                return local::Response {
                    version: local::SECURE_UDP_VERSION,
                    ok: false,
                    code: "status_unavailable".into(),
                    state: None,
                };
            }
        };
        if let Some(status) = &mut status
            && self.0.lock().backend.is_none()
        {
            status.running = false;
            status.terminal = snapshot.terminal.map(|terminal| format!("{terminal:?}"));
        }
        let phase = match snapshot.phase {
            Phase::Connected => "forwarding",
            Phase::Disconnected => "disconnected",
            Phase::Preparing | Phase::Authenticating => "connecting",
            Phase::Applying => "applying",
            Phase::Stopping => "stopping",
            Phase::Failed => "failed",
            Phase::Closed => "closed",
        };
        local::Response {
            version: local::SECURE_UDP_VERSION,
            ok,
            code: code.into(),
            state: Some(local::Snapshot {
                epoch: status.as_ref().map_or(0, |status| status.policy_epoch),
                phase: phase.into(),
                compression: local::Compression::Off,
                active: None,
                proxy: None,
                openvpn_drain: None,
                raw_packet: None,
                rolling: None,
                swift: None,
                secure_udp: status,
            }),
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
/// and base UDP socket/device futures drop before the completion guard publishes
/// cancellation.
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
        if let Some(backend) = state.backend.take() {
            state.snapshot.runtime = backend.observe();
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
            backend: None,
            queued: None,
            entries: VecDeque::with_capacity(RETAINED),
            plan: None,
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
