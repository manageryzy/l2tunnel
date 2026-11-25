//! Toolkit-independent GUI state. The worker performs every exchange; the
//! model only decides what to request and what to show. Messages from an
//! earlier attachment or event follower are ignored, never merged.
use crate::stats::{History, Sample};
use l2tunnel_client_core::local::elevate::{StartRequest, Started};
use l2tunnel_client_core::local::keys::KeyReference;
use l2tunnel_client_core::local::tunnel_test::{TestRequest, TestState};
use l2tunnel_client_core::local::{
    DeviceChange, DeviceState, EventBody, EventState, Feature, Metrics, OperationReply,
    OperationResult, OperationState, ProfileChange, ProfileEntry, ProfileSummary, RouteChange,
    RouteState, ServiceId, ServiceInfo, ServiceStatus, SessionState, TerminalState, TuningSetting,
    TuningView,
};
use l2tunnel_client_core::secure_udp::common_status::CanonicalConfiguration;
use std::collections::VecDeque;
use std::path::PathBuf;

/// Most retained log lines.
pub const LOG_LINES: usize = 200;
/// Recent events replayed when a window first follows a service.
pub const BACKLOG: u64 = 64;
/// Displayed status rows.
pub const ROWS: [&str; 7] = [
    "State",
    "Operation",
    "Outer carrier",
    "UDP cover",
    "Peer",
    "Algorithm",
    "Epoch",
];

/// User actions.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Action {
    /// Connect when idle or replace the live session (local `reconnect`).
    Reconnect,
    /// Abort the live session.
    Disconnect,
    /// Disconnect and end the service process.
    Stop,
    /// End the live server session and listen again.
    Kick,
    /// Cancel the pending setup.
    Cancel,
    /// Hot switch to the selected catalog configuration.
    Switch,
    /// Hot switch to a live-tuning setting.
    Tune,
    /// Service-owned device change.
    Device,
    /// Service-owned route change.
    Route,
    /// Profile store change.
    Profile,
    /// Connect with a stored profile.
    ProfileConnect,
}

/// What a submitting action carries.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Payload {
    /// Switch target.
    Switch(CanonicalConfiguration),
    /// Live-tuning setting to switch to.
    Tune(TuningSetting),
    /// Device change.
    Device(DeviceChange),
    /// Route change.
    Route(RouteChange),
    /// Profile store change.
    Profile(ProfileChange),
    /// Connect with (or replace the session by) a stored profile.
    ProfileConnect {
        /// Profile name.
        name: String,
        /// Replace a live session.
        replace: bool,
    },
}
impl Action {
    fn name(self) -> &'static str {
        match self {
            Self::Reconnect => "reconnect",
            Self::Disconnect => "disconnect",
            Self::Stop => "service stop",
            Self::Kick => "session kick",
            Self::Cancel => "cancel",
            Self::Switch => "switch",
            Self::Tune => "tune",
            Self::Device => "device change",
            Self::Route => "route change",
            Self::Profile => "profile change",
            Self::ProfileConnect => "profile connect",
        }
    }
}

/// Read-only exchanges that do not change service state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Query {
    /// `service_info`.
    Info,
    /// `metrics`.
    Metrics,
    /// `device_list`.
    Devices,
    /// `route_list`.
    Routes,
    /// `profile_list`.
    Profiles,
    /// `profile_get`.
    Profile(String),
    /// `profile_validate`.
    Check(String),
    /// `profile_keys`.
    Keys(String),
    /// `session_list`.
    Sessions,
    /// One catalog page.
    Catalog {
        /// Exact session generation.
        generation: u64,
        /// Exact catalog root.
        catalog: [u8; 32],
        /// First canonical index.
        offset: u16,
    },
    /// `test_start`.
    TestStart(TestRequest),
    /// `test_get` of the latest test.
    TestGet,
    /// `test_cancel`.
    TestCancel(u64),
    /// `tuning_get`.
    Tuning,
}

/// Catalogs up to this size are shown as one list.
pub const CATALOG_ALL: usize = 32;

/// Append `page` to `shown` when both belong to the same short catalog and
/// `page` continues it; otherwise `page` replaces what was shown.
pub fn merge_catalog(shown: Option<CatalogView>, page: CatalogView) -> CatalogView {
    match shown {
        Some(mut view)
            if view.generation == page.generation
                && view.root == page.root
                && usize::from(page.total) <= CATALOG_ALL
                && usize::from(view.offset) + view.entries.len() == usize::from(page.offset) =>
        {
            view.entries.extend(page.entries);
            view.total = page.total;
            view.next = page.next;
            view
        }
        _ => page,
    }
}

/// One displayed catalog page.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CatalogView {
    /// Service generation the page was read from.
    pub generation: u64,
    /// Catalog root the page belongs to.
    pub root: [u8; 32],
    /// First index of this page.
    pub offset: u16,
    /// Total configurations in the catalog.
    pub total: u16,
    /// Next page offset.
    pub next: Option<u16>,
    /// Configurations on this page.
    pub entries: Vec<CanonicalConfiguration>,
}

/// Result of an action exchange.
#[derive(Debug)]
pub enum ActionOutcome {
    /// The service replied (accepted or refused).
    Reply(Box<OperationReply>),
    /// No reply; the text says whether anything may have been submitted.
    Failed(String),
}

/// Worker result delivered to the model.
#[derive(Debug)]
pub enum Message {
    /// `status` exchange result.
    Status {
        /// Attachment generation the exchange belongs to.
        attach: u64,
        /// Whether to (re)start the event follower afterwards.
        start_follower: bool,
        /// Service reply, or the transport error text.
        result: Result<Box<OperationReply>, String>,
    },
    /// Action exchange result.
    Action {
        /// Attachment generation the exchange belongs to.
        attach: u64,
        /// User action.
        action: Action,
        /// Exchange outcome.
        outcome: ActionOutcome,
    },
    /// `operation_get` result after a completion event.
    Show {
        /// Attachment generation the exchange belongs to.
        attach: u64,
        /// Service reply, or the transport error text.
        result: Result<Box<OperationReply>, String>,
    },
    /// One event page from the follower.
    Events {
        /// Attachment generation the exchange belongs to.
        attach: u64,
        /// Event follower generation.
        follower: u64,
        /// Service reply carrying the event page.
        reply: Box<OperationReply>,
    },
    /// A read-only query result.
    Query {
        /// Attachment generation the exchange belongs to.
        attach: u64,
        /// The query.
        query: Query,
        /// Service reply, or the transport error text.
        result: Result<Box<OperationReply>, String>,
    },
    /// A member revocation finished.
    Revoked {
        /// Attachment generation the exchange belongs to.
        attach: u64,
        /// Summary, or the reason it stopped.
        result: Result<String, String>,
    },
    /// The elevated service start finished.
    Started {
        /// The answering service, or why none answers.
        result: Result<Started, String>,
    },
    /// A diagnostic export finished.
    Exported {
        /// Written file, or the error text.
        result: Result<PathBuf, String>,
    },
    /// The follower stopped (refusal or lost service).
    FollowerEnded {
        /// Attachment generation the exchange belongs to.
        attach: u64,
        /// Event follower generation.
        follower: u64,
        /// Refusal code or transport error text.
        reason: String,
    },
}

/// Exchange requested from the worker.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Command {
    /// Read status; optionally (re)start the follower from its cursor.
    Status {
        /// Attachment generation the exchange belongs to.
        attach: u64,
        /// Service control socket.
        path: PathBuf,
        /// Whether to (re)start the event follower afterwards.
        start_follower: bool,
    },
    /// Submit or cancel.
    Act {
        /// Attachment generation the exchange belongs to.
        attach: u64,
        /// Service control socket.
        path: PathBuf,
        /// User action.
        action: Action,
        /// Operation to act on or read.
        operation: Option<u64>,
        /// Service instance identity to require.
        service: Option<ServiceId>,
        /// What the action submits.
        payload: Option<Payload>,
    },
    /// Read-only query.
    Query {
        /// Attachment generation the exchange belongs to.
        attach: u64,
        /// Service control socket.
        path: PathBuf,
        /// The query.
        query: Query,
    },
    /// Read one operation.
    Show {
        /// Attachment generation the exchange belongs to.
        attach: u64,
        /// Service control socket.
        path: PathBuf,
        /// Operation to act on or read.
        operation: u64,
        /// Service instance identity to require.
        service: Option<ServiceId>,
    },
    /// Replace the follower with one starting after `after`.
    Follow {
        /// Attachment generation the exchange belongs to.
        attach: u64,
        /// Event follower generation.
        follower: u64,
        /// Service control socket.
        path: PathBuf,
        /// Event cursor to continue after.
        after: u64,
        /// Service instance identity to require.
        service: Option<ServiceId>,
    },
    /// Trust a new member key on the running server profile and replace
    /// the session.
    Revoke {
        /// Attachment generation the exchange belongs to.
        attach: u64,
        /// Service control socket.
        path: PathBuf,
        /// New member public key file (absolute, readable by the service).
        allow_key: PathBuf,
    },
    /// Write a redacted diagnostic report to a new file.
    Export {
        /// Service control socket.
        path: PathBuf,
        /// Destination that must not exist yet.
        destination: PathBuf,
        /// Keep IP addresses in the report.
        include_addresses: bool,
    },
    /// Install or start the platform service through the administrator
    /// prompt and wait until it answers.
    StartService(Box<StartRequest>),
    /// Stop the follower.
    StopFollower,
}

/// What the window draws.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct View {
    /// Status rows in `ROWS` order.
    pub rows: [String; 7],
    /// Connect/Reconnect enabled.
    pub connect: bool,
    /// Disconnect enabled.
    pub disconnect: bool,
    /// Cancel setup enabled.
    pub cancel: bool,
    /// Label of the connect button.
    pub connect_label: &'static str,
}

/// GUI state.
#[derive(Debug, Default)]
pub struct Model {
    attach: u64,
    path: Option<PathBuf>,
    status: Option<ServiceStatus>,
    service: Option<ServiceId>,
    follower: Option<u64>,
    next_follower: u64,
    busy: Option<Action>,
    refreshing: bool,
    dirty: bool,
    /// One-line notice under the buttons.
    pub notice: String,
    /// Bounded event/action log, oldest first.
    pub log: VecDeque<String>,
    /// A resynchronization should be scheduled.
    pub retry: bool,
    info: Option<ServiceInfo>,
    devices: Option<Vec<DeviceState>>,
    routes: Option<Vec<RouteState>>,
    profiles: Option<Vec<ProfileSummary>>,
    profile: Option<ProfileEntry>,
    keys: Option<(String, Vec<KeyReference>)>,
    sessions: Option<Vec<SessionState>>,
    /// Latest tunnel test.
    test: Option<TestState>,
    exporting: bool,
    starting: bool,
    started: Option<PathBuf>,
    stage: Option<String>,
    metrics: Option<Metrics>,
    history: History,
    catalog: Option<CatalogView>,
    target: Option<CanonicalConfiguration>,
    /// Live-tuning controls and the (generation, epoch) they were read for.
    tuning: Option<TuningView>,
    tuning_for: Option<(u64, Option<u64>)>,
    in_flight: Vec<Query>,
    /// Reads asked for while the same read was in flight; sent again when
    /// it answers, so a reply from before a change never stays on screen.
    again: Vec<Query>,
    /// Last logged event sequence per service instance, so a restarted
    /// follower continues instead of logging events twice.
    seen: Option<(ServiceId, u64)>,
}

fn dash<T: ToString>(value: Option<T>) -> String {
    value.map_or_else(|| "—".to_owned(), |value| value.to_string())
}
fn bounded(text: &str) -> String {
    text.chars().take(128).collect()
}
/// Short text of a termination.
pub fn terminal_text(terminal: &TerminalState) -> String {
    match terminal {
        TerminalState::Aborted => "aborted".into(),
        TerminalState::Closed => "closed".into(),
        TerminalState::Failed { error_kind } => format!("failed ({error_kind})"),
    }
}
/// Short text of a completion.
pub fn result_text(result: &OperationResult) -> String {
    match result {
        OperationResult::Connected { generation } => format!("connected (generation {generation})"),
        OperationResult::Aborted => "aborted".into(),
        OperationResult::Applied { code } => format!("applied ({code})"),
        OperationResult::Rejected { code } => format!("rejected ({code})"),
        OperationResult::CommonCommitted { epoch, .. } => format!("committed (epoch {epoch})"),
        OperationResult::CommonRefused { reason, .. } => format!("refused ({reason})"),
        OperationResult::ReuseConfirmed { generation } => {
            format!("reuse confirmed (generation {generation})")
        }
        OperationResult::ReuseRefused { reason, .. } => format!("reuse refused ({reason})"),
        OperationResult::Cancelled => "cancelled".into(),
        OperationResult::OutcomeUnknown => "outcome unknown".into(),
        OperationResult::Failed { error_kind } => format!("failed ({error_kind})"),
        OperationResult::HostApplied { summary } => format!("applied ({summary})"),
        OperationResult::HostRefused { reason } => format!("refused ({reason})"),
        OperationResult::ProfileApplied { summary } => format!("applied ({summary})"),
        OperationResult::ProfileRefused { reason } => format!("refused ({reason})"),
    }
}
/// One line for an operation, as the CLI prints it.
pub fn operation_text(state: &OperationState) -> String {
    let mut text = format!("operation {} ({}): {}", state.id, state.kind, state.state);
    if let Some(result) = &state.result {
        text += &format!(", {}", result_text(result));
    }
    if let Some(setup) = &state.setup {
        text += &format!(", setup {} {}", setup.stage, setup.outcome);
        if let Some(failure) = &setup.failure {
            text += &format!(" [{failure}]");
        }
    }
    if state.cancel_requested {
        text += ", cancel requested";
    }
    text
}
/// One line for an event, as the CLI prints it.
pub fn event_text(event: &EventState) -> String {
    let sequence = event.sequence;
    match &event.event {
        EventBody::OperationAccepted { operation, kind } => {
            format!("#{sequence} operation {operation} accepted ({kind})")
        }
        EventBody::OperationProgress { operation, stage } => {
            format!("#{sequence} operation {operation} reached {stage}")
        }
        EventBody::OperationCompleted { operation, outcome } => {
            format!("#{sequence} operation {operation} completed: {outcome}")
        }
        EventBody::Lifecycle {
            phase,
            operation,
            generation,
            terminal,
        } => format!(
            "#{sequence} phase {phase}, operation {}, generation {}, terminal {}",
            dash(*operation),
            dash(*generation),
            dash(terminal.as_ref().map(terminal_text))
        ),
    }
}
/// Project a status onto the rows; carrier details only from a running observation.
pub fn status_rows(status: &ServiceStatus) -> [String; 7] {
    let mut rows: [String; 7] = std::array::from_fn(|_| "—".to_owned());
    rows[0] = bounded(&status.phase);
    rows[1] = dash(status.operation);
    let common = status
        .observation
        .as_ref()
        .and_then(|observation| observation.common.as_ref());
    match common {
        Some(common)
            if status.phase == "connected"
                && common.running
                && common.terminal.is_none()
                && common.service_terminal.is_none() =>
        {
            let maintained = common
                .maintained_carrier
                .as_ref()
                .and_then(|carrier| carrier.effective.as_ref());
            let (outer, cover) = if let Some(raw) = &common.raw_carrier {
                (raw.effective.clone(), Some(raw.inner_cover.clone()))
            } else if let Some(original) = &common.original_carrier {
                (original.effective.clone(), Some(original.udp_cover.clone()))
            } else if let Some(maintained) = maintained {
                (maintained.carrier.clone(), None)
            } else if matches!(common.carrier.as_str(), "quic-like" | "media-like") {
                ("UDP".to_owned(), Some(common.carrier.clone()))
            } else {
                (common.carrier.clone(), None)
            };
            rows[2] = bounded(&outer);
            rows[3] = cover.map_or_else(|| "—".to_owned(), |cover| bounded(&cover));
            rows[4] = bounded(&common.peer);
            rows[5] = bounded(&common.algorithm);
            rows[6] = dash(common.epoch);
        }
        _ => {
            if let Some(terminal) = &status.terminal {
                rows[0] = format!("{} ({})", rows[0], terminal_text(terminal));
            }
        }
    }
    rows
}

impl Model {
    /// Select a socket (empty detaches) and read its status.
    pub fn attach(&mut self, path: &str) -> Vec<Command> {
        let mut commands = vec![StopFollower];
        self.attach += 1;
        self.path = (!path.trim().is_empty()).then(|| PathBuf::from(path.trim()));
        self.status = None;
        self.service = None;
        self.follower = None;
        self.busy = None;
        self.refreshing = false;
        self.dirty = false;
        self.retry = false;
        self.notice.clear();
        self.info = None;
        self.devices = None;
        self.routes = None;
        self.profiles = None;
        self.profile = None;
        self.keys = None;
        self.sessions = None;
        self.test = None;
        self.metrics = None;
        self.history.clear();
        self.catalog = None;
        self.target = None;
        self.tuning = None;
        self.tuning_for = None;
        self.in_flight.clear();
        self.again.clear();
        self.seen = None;
        commands.extend(self.refresh(true));
        commands
    }
    /// The retry timer fired: read status and restart the follower.
    pub fn resync(&mut self) -> Vec<Command> {
        self.retry = false;
        self.refresh(true)
    }
    fn refresh(&mut self, start_follower: bool) -> Vec<Command> {
        let Some(path) = self.path.clone() else {
            return Vec::new();
        };
        if self.refreshing {
            self.dirty = true;
            return Vec::new();
        }
        self.refreshing = true;
        vec![Command::Status {
            attach: self.attach,
            path,
            start_follower,
        }]
    }
    /// Submit an action unless one is already in flight.
    pub fn act(&mut self, action: Action) -> Vec<Command> {
        if self.path.is_none() || self.busy.is_some() {
            return Vec::new();
        }
        let operation = self.status.as_ref().and_then(|status| status.operation);
        if action == Action::Cancel && operation.is_none() {
            return Vec::new();
        }
        let payload = match action {
            Action::Switch => match self.target.clone() {
                Some(target) => Some(Payload::Switch(target)),
                None => return Vec::new(),
            },
            _ => None,
        };
        self.submit(action, payload)
    }
    /// Hot-switch to a live-tuning setting.
    pub fn tune(&mut self, setting: TuningSetting) -> Vec<Command> {
        self.submit(Action::Tune, Some(Payload::Tune(setting)))
    }
    /// The live session's (generation, epoch), when connected.
    fn session_key(&self) -> Option<(u64, Option<u64>)> {
        self.status
            .as_ref()
            .and_then(|status| status.observation.as_ref())
            .and_then(|observation| observation.common.as_ref())
            .map(|common| (common.generation, common.epoch))
    }
    /// Read the live-tuning controls when they belong to another session or
    /// epoch than the live one.
    pub fn refresh_tuning(&mut self) -> Vec<Command> {
        let Some(key) = self.session_key() else {
            self.tuning = None;
            self.tuning_for = None;
            return Vec::new();
        };
        if self.tuning_for == Some(key) {
            return Vec::new();
        }
        self.tuning_for = Some(key);
        self.query(Query::Tuning)
    }
    /// Latest live-tuning controls of the live session.
    pub fn tuning(&self) -> Option<&TuningView> {
        self.tuning.as_ref().filter(|_| {
            self.session_key()
                .is_some_and(|key| self.tuning_for == Some(key))
        })
    }
    /// Submit a device change.
    pub fn change_device(&mut self, change: DeviceChange) -> Vec<Command> {
        self.submit(Action::Device, Some(Payload::Device(change)))
    }
    /// Submit a profile store change.
    pub fn change_profile(&mut self, change: ProfileChange) -> Vec<Command> {
        self.submit(Action::Profile, Some(Payload::Profile(change)))
    }
    /// Connect with a stored profile (`replace` replaces a live session).
    pub fn connect_profile(&mut self, name: String, replace: bool) -> Vec<Command> {
        self.submit(
            Action::ProfileConnect,
            Some(Payload::ProfileConnect { name, replace }),
        )
    }
    /// Read the profile list.
    pub fn refresh_profiles(&mut self) -> Vec<Command> {
        self.query(Query::Profiles)
    }
    /// Load one profile for editing.
    pub fn load_profile(&mut self, name: String) -> Vec<Command> {
        self.profile = None;
        self.query(Query::Profile(name))
    }
    /// Ask the service to build the profile's plan.
    pub fn check_profile(&mut self, name: String) -> Vec<Command> {
        self.query(Query::Check(name))
    }
    /// Read the live server session.
    pub fn refresh_sessions(&mut self) -> Vec<Command> {
        self.query(Query::Sessions)
    }
    /// Latest session list.
    pub fn sessions(&self) -> Option<&[SessionState]> {
        self.sessions.as_deref()
    }
    /// Latest tunnel test.
    pub fn test(&self) -> Option<&TestState> {
        self.test.as_ref()
    }
    /// Start a speed or ping test.
    pub fn start_test(&mut self, request: TestRequest) -> Vec<Command> {
        self.query(Query::TestStart(request))
    }
    /// Read the latest test (polled while one runs).
    pub fn refresh_test(&mut self) -> Vec<Command> {
        self.query(Query::TestGet)
    }
    /// Cancel test `id`.
    pub fn cancel_test(&mut self, id: u64) -> Vec<Command> {
        self.query(Query::TestCancel(id))
    }
    /// Revoke the running server profile's member (two keyed operations).
    pub fn revoke(&mut self, allow_key: PathBuf) -> Vec<Command> {
        let Some(path) = self.path.clone() else {
            return Vec::new();
        };
        if self.busy.is_some() {
            return Vec::new();
        }
        self.busy = Some(Action::Profile);
        self.notice = "Revoking member: saving the profile, then replacing the session…".into();
        vec![Command::Revoke {
            attach: self.attach,
            path,
            allow_key,
        }]
    }
    /// Install or start the platform service through the administrator
    /// prompt (owner decision 2026-11-24); one start at a time.
    pub fn start_service(&mut self, request: StartRequest) -> Vec<Command> {
        if self.starting {
            return Vec::new();
        }
        self.starting = true;
        self.notice = "Starting the service: answer the administrator prompt…".into();
        vec![Command::StartService(Box::new(request))]
    }
    /// Latest setup stage of the pending operation, from the event stream.
    pub fn setup_stage(&self) -> Option<&str> {
        self.stage.as_deref().filter(|_| {
            self.status
                .as_ref()
                .is_some_and(|status| status.operation.is_some())
        })
    }
    /// An elevated start is in progress.
    pub fn starting(&self) -> bool {
        self.starting
    }
    /// No service answers: nothing is attached, or the attached service was
    /// lost (not while the first status exchange is still running).
    pub fn offline(&self) -> bool {
        self.status.is_none() && !self.refreshing
    }
    /// Socket of a service that was just started, once, so the window's
    /// service field shows what is attached.
    pub fn take_started(&mut self) -> Option<PathBuf> {
        self.started.take()
    }
    /// Read the key files a stored profile names.
    pub fn profile_keys(&mut self, name: String) -> Vec<Command> {
        self.query(Query::Keys(name))
    }
    /// Latest key references and the profile they belong to.
    pub fn keys(&self) -> Option<&(String, Vec<KeyReference>)> {
        self.keys.as_ref()
    }
    /// Latest profile list.
    pub fn profiles(&self) -> Option<&[ProfileSummary]> {
        self.profiles.as_deref()
    }
    /// Latest loaded profile.
    pub fn loaded_profile(&self) -> Option<&ProfileEntry> {
        self.profile.as_ref()
    }
    /// Submit a route change.
    pub fn change_route(&mut self, change: RouteChange) -> Vec<Command> {
        self.submit(Action::Route, Some(Payload::Route(change)))
    }
    fn submit(&mut self, action: Action, payload: Option<Payload>) -> Vec<Command> {
        let Some(path) = self.path.clone() else {
            return Vec::new();
        };
        if self.busy.is_some() {
            return Vec::new();
        }
        let operation = self.status.as_ref().and_then(|status| status.operation);
        self.busy = Some(action);
        self.notice = format!("Submitting {}…", action.name());
        vec![Command::Act {
            attach: self.attach,
            path,
            action,
            operation,
            service: self.service,
            payload,
        }]
    }
    fn append(&mut self, line: String) {
        if self.log.len() == LOG_LINES {
            self.log.pop_front();
        }
        self.log.push_back(line);
    }
    fn query(&mut self, query: Query) -> Vec<Command> {
        let Some(path) = self.path.clone() else {
            return Vec::new();
        };
        let kind = std::mem::discriminant(&query);
        if self
            .in_flight
            .iter()
            .any(|pending| std::mem::discriminant(pending) == kind)
        {
            // Reads that follow a change are repeated; periodic polls
            // (metrics, a running test) and test actions are not.
            if matches!(
                query,
                Query::Devices
                    | Query::Routes
                    | Query::Profiles
                    | Query::Tuning
                    | Query::Sessions
                    | Query::Info
                    | Query::Profile(_)
                    | Query::Keys(_)
                    | Query::Check(_)
            ) {
                self.again
                    .retain(|waiting| std::mem::discriminant(waiting) != kind);
                self.again.push(query);
            }
            return Vec::new();
        }
        self.in_flight.push(query.clone());
        vec![Command::Query {
            attach: self.attach,
            path,
            query,
        }]
    }
    /// Whether the attached service serves `feature`; `Err` carries the reason.
    pub fn capability(&self, feature: Feature) -> Result<(), String> {
        let Some(info) = &self.info else {
            return Err("service capabilities not read yet".into());
        };
        match info.capability(feature) {
            Some(capability) if capability.available => Ok(()),
            Some(capability) => Err(capability
                .reason
                .clone()
                .unwrap_or_else(|| "unavailable".into())),
            None => Err("not offered by this service version".into()),
        }
    }
    /// The one-second timer fired: sample metrics when the service serves
    /// them, and the session list (uptime, counters) once it was opened.
    pub fn poll_metrics(&mut self) -> Vec<Command> {
        if self.status.is_none() {
            return Vec::new();
        }
        let mut commands = Vec::new();
        if self.sessions.is_some() && self.capability(Feature::Sessions).is_ok() {
            commands.extend(self.refresh_sessions());
        }
        if self.capability(Feature::Metrics).is_err() {
            self.metrics = None;
            return commands;
        }
        commands.extend(self.query(Query::Metrics));
        commands
    }
    /// Read the catalog page starting at `offset` of the running session.
    pub fn catalog_page(&mut self, offset: u16) -> Vec<Command> {
        let Some(common) = self
            .status
            .as_ref()
            .and_then(|status| status.observation.as_ref())
            .and_then(|observation| observation.common.as_ref())
        else {
            return Vec::new();
        };
        let query = Query::Catalog {
            generation: common.generation,
            catalog: common.catalog,
            offset,
        };
        self.query(query)
    }
    /// Export diagnostics to `destination` (one export at a time).
    pub fn export(&mut self, destination: PathBuf, include_addresses: bool) -> Vec<Command> {
        let Some(path) = self.path.clone() else {
            return Vec::new();
        };
        if self.exporting {
            return Vec::new();
        }
        self.exporting = true;
        self.notice = "Exporting diagnostics…".into();
        vec![Command::Export {
            path,
            destination,
            include_addresses,
        }]
    }
    /// An export is running.
    pub fn exporting(&self) -> bool {
        self.exporting
    }
    /// Read the device list.
    pub fn refresh_devices(&mut self) -> Vec<Command> {
        self.query(Query::Devices)
    }
    /// Read the route list.
    pub fn refresh_routes(&mut self) -> Vec<Command> {
        self.query(Query::Routes)
    }
    /// Latest device list.
    pub fn devices(&self) -> Option<&[DeviceState]> {
        self.devices.as_deref()
    }
    /// Latest route list.
    pub fn routes(&self) -> Option<&[RouteState]> {
        self.routes.as_deref()
    }
    /// Choose (or clear) the switch target.
    pub fn select_target(&mut self, target: Option<CanonicalConfiguration>) {
        self.target = target;
    }
    /// Selected switch target.
    pub fn target(&self) -> Option<&CanonicalConfiguration> {
        self.target.as_ref()
    }
    /// Latest service identity.
    pub fn info(&self) -> Option<&ServiceInfo> {
        self.info.as_ref()
    }
    /// Latest status.
    pub fn status(&self) -> Option<&ServiceStatus> {
        self.status.as_ref()
    }
    /// Latest metrics sample.
    pub fn metrics(&self) -> Option<&Metrics> {
        self.metrics.as_ref()
    }
    /// Retained metrics history.
    pub fn history(&self) -> &History {
        &self.history
    }
    /// Displayed catalog page.
    pub fn catalog(&self) -> Option<&CatalogView> {
        self.catalog.as_ref()
    }
    /// Whether the displayed catalog page is missing or belongs to another
    /// generation or catalog than the live session's.
    pub fn catalog_stale(&self) -> bool {
        let live = self
            .status
            .as_ref()
            .and_then(|status| status.observation.as_ref())
            .and_then(|observation| observation.common.as_ref())
            .map(|common| (common.generation, common.catalog));
        live.is_some()
            && self
                .catalog
                .as_ref()
                .map(|view| (view.generation, view.root))
                != live
    }
    /// Whether an action is in flight.
    pub fn busy(&self) -> bool {
        self.busy.is_some()
    }
    /// Identity of the attached service instance.
    pub fn service(&self) -> Option<ServiceId> {
        self.service
    }
    /// Attached socket path.
    pub fn path(&self) -> Option<&std::path::Path> {
        self.path.as_deref()
    }
    /// Where a new follower starts: after the last logged event of this
    /// service instance, else the recent backlog before its cursor.
    fn follow_after(&self) -> u64 {
        match (self.seen, self.service) {
            (Some((seen, next)), Some(service)) if seen == service => next,
            _ => self
                .status
                .as_ref()
                .map_or(0, |status| status.event_cursor.saturating_sub(BACKLOG)),
        }
    }
    fn lost_service(&mut self, notice: String) -> Vec<Command> {
        self.info = None;
        self.metrics = None;
        self.status = None;
        self.follower = None;
        self.notice = notice;
        self.retry = true;
        vec![StopFollower]
    }
    /// Apply one worker result and return the follow-up exchanges.
    pub fn handle(&mut self, message: Message) -> Vec<Command> {
        let current = |attach: u64| attach == self.attach;
        match message {
            Message::Status {
                attach,
                start_follower,
                result,
            } if current(attach) => {
                self.refreshing = false;
                let mut commands = Vec::new();
                match result {
                    Ok(reply) if reply.ok && reply.status.is_some() => {
                        let restarted = reply.service.is_some() && reply.service != self.service;
                        self.service = reply.service.or(self.service);
                        self.status = reply.status;
                        if self.notice.starts_with("Service") {
                            self.notice.clear();
                        }
                        if (start_follower || restarted || self.follower.is_none())
                            && let Some(path) = self.path.clone()
                        {
                            self.next_follower += 1;
                            self.follower = Some(self.next_follower);
                            commands.push(Command::Follow {
                                attach,
                                follower: self.next_follower,
                                path,
                                after: self.follow_after(),
                                service: self.service,
                            });
                        }
                    }
                    Ok(reply) => {
                        return self.lost_service(format!(
                            "Service refused status: {}",
                            bounded(&reply.code)
                        ));
                    }
                    Err(error) => {
                        return self
                            .lost_service(format!("Service unavailable: {}", bounded(&error)));
                    }
                }
                commands.extend(self.query(Query::Info));
                if self.dirty {
                    self.dirty = false;
                    commands.extend(self.refresh(false));
                }
                commands
            }
            Message::Query {
                attach,
                query,
                result,
            } if current(attach) => {
                let kind = std::mem::discriminant(&query);
                self.in_flight
                    .retain(|pending| std::mem::discriminant(pending) != kind);
                let again = self
                    .again
                    .iter()
                    .position(|waiting| std::mem::discriminant(waiting) == kind)
                    .map(|index| self.again.remove(index));
                let Ok(reply) = result else {
                    return again.map(|query| self.query(query)).unwrap_or_default();
                };
                match query {
                    Query::Info => self.info = reply.info,
                    Query::Devices => {
                        if reply.ok {
                            self.devices = reply.devices;
                        } else {
                            self.notice = format!("device list refused: {}", bounded(&reply.code));
                        }
                    }
                    Query::Profiles => {
                        if reply.ok {
                            self.profiles = reply.profiles;
                        } else {
                            // An empty list stops automatic retries; Refresh retries.
                            self.profiles = Some(Vec::new());
                            self.notice = format!("profile list refused: {}", bounded(&reply.code));
                        }
                    }
                    Query::Profile(name) => {
                        if reply.ok {
                            self.profile = reply.profile;
                        } else {
                            self.notice = format!("profile {name}: {}", bounded(&reply.code));
                        }
                    }
                    Query::TestStart(_) | Query::TestGet | Query::TestCancel(_) => {
                        if let Some(test) = reply.test.and_then(|test| test.test) {
                            self.test = Some(test);
                        }
                        if !reply.ok && reply.code != "unknown_test" {
                            self.notice = format!("test refused: {}", bounded(&reply.code));
                        }
                    }
                    Query::Tuning => {
                        if reply.ok {
                            self.tuning = reply.tuning.map(|view| *view);
                        } else {
                            self.tuning = None;
                            if reply.code != "closed" {
                                self.notice = format!("tuning refused: {}", bounded(&reply.code));
                            }
                        }
                    }
                    Query::Sessions => {
                        if !reply.ok {
                            self.notice = format!("session list refused: {}", bounded(&reply.code));
                        }
                        self.sessions = Some(reply.sessions.unwrap_or_default());
                    }
                    Query::Keys(name) => {
                        if !reply.ok {
                            self.notice = format!("profile {name}: {}", bounded(&reply.code));
                        }
                        // A refusal shows an empty table instead of retrying.
                        self.keys = Some((name, reply.keys.unwrap_or_default()));
                    }
                    Query::Check(name) => {
                        self.notice = match &reply.check {
                            Some(check) if check.valid => {
                                format!("{name} is valid: {}", bounded(&check.summary))
                            }
                            Some(check) => format!(
                                "{name} is not runnable: {}",
                                bounded(check.reason.as_deref().unwrap_or("unknown reason"))
                            ),
                            None => format!("profile {name}: {}", bounded(&reply.code)),
                        };
                    }
                    Query::Routes => {
                        if reply.ok {
                            self.routes = reply.routes;
                        } else {
                            self.notice = format!("route list refused: {}", bounded(&reply.code));
                        }
                    }
                    Query::Metrics => {
                        self.metrics = reply.metrics.map(|metrics| *metrics);
                        if let (Some(metrics), Some(service)) = (&self.metrics, self.service) {
                            self.history.push(Sample::of(service.0, metrics));
                        }
                    }
                    Query::Catalog {
                        generation,
                        catalog,
                        ..
                    } => {
                        if let Some(page) = reply
                            .observation
                            .and_then(|observation| observation.common)
                            .and_then(|common| common.catalog_page)
                        {
                            let page = CatalogView {
                                generation,
                                root: catalog,
                                offset: page.offset,
                                total: page.total,
                                next: page.next,
                                entries: page.configurations,
                            };
                            self.catalog = Some(merge_catalog(self.catalog.take(), page));
                        } else if !reply.ok {
                            self.notice = format!("catalog refused: {}", bounded(&reply.code));
                        }
                    }
                }
                again.map(|query| self.query(query)).unwrap_or_default()
            }
            Message::Action {
                attach,
                action,
                outcome,
            } if current(attach) => {
                self.busy = None;
                self.notice = match outcome {
                    ActionOutcome::Reply(reply) if reply.ok => {
                        let id = dash(reply.operation.as_ref().map(|state| state.id));
                        if action == Action::Cancel {
                            format!("Cancellation requested for operation {id}")
                        } else if action == Action::Switch {
                            self.target = None;
                            format!("Operation {id} accepted (switch)")
                        } else {
                            format!("Operation {id} accepted ({})", action.name())
                        }
                    }
                    ActionOutcome::Reply(reply) => match &reply.check {
                        Some(check) => format!(
                            "{} refused: {} ({})",
                            action.name(),
                            bounded(&reply.code),
                            bounded(check.reason.as_deref().unwrap_or(""))
                        ),
                        None => format!("{} refused: {}", action.name(), bounded(&reply.code)),
                    },
                    ActionOutcome::Failed(text) => format!("{} failed: {}", action.name(), text),
                };
                self.append(self.notice.clone());
                self.refresh(false)
            }
            Message::Show { attach, result } if current(attach) => {
                if let Ok(reply) = result
                    && let Some(state) = &reply.operation
                {
                    self.notice = operation_text(state);
                    self.append(self.notice.clone());
                }
                Vec::new()
            }
            Message::Events {
                attach,
                follower,
                reply,
            } if current(attach) && Some(follower) == self.follower => {
                let mut commands = Vec::new();
                let Some(batch) = reply.events else {
                    return commands;
                };
                if let Some(service) = self.service {
                    self.seen = Some((service, batch.next));
                }
                if batch.gap {
                    self.append("Older events were evicted; status resynchronized".into());
                    if reply.status.is_some() {
                        self.status = reply.status;
                    }
                }
                for event in &batch.events {
                    self.append(event_text(event));
                    match &event.event {
                        EventBody::OperationProgress { stage, .. } => {
                            self.stage = Some(stage.clone());
                        }
                        EventBody::OperationAccepted { .. }
                        | EventBody::OperationCompleted { .. } => self.stage = None,
                        _ => {}
                    }
                    if let EventBody::OperationCompleted { operation, .. } = &event.event
                        && let Some(path) = self.path.clone()
                    {
                        commands.push(Command::Show {
                            attach,
                            path,
                            operation: *operation,
                            service: self.service,
                        });
                    }
                }
                if batch.gap || !batch.events.is_empty() {
                    commands.extend(self.refresh(false));
                    // Changes and session ends alter devices and routes.
                    if self.devices.is_some() {
                        commands.extend(self.refresh_devices());
                    }
                    if self.routes.is_some() {
                        commands.extend(self.refresh_routes());
                    }
                    if self.profiles.is_some() {
                        commands.extend(self.refresh_profiles());
                    }
                    if self.sessions.is_some() {
                        commands.extend(self.refresh_sessions());
                    }
                }
                commands
            }
            Message::Revoked { attach, result } if current(attach) => {
                self.busy = None;
                self.notice = match result {
                    Ok(summary) => summary,
                    Err(reason) => format!("Member revoke stopped: {}", bounded(&reason)),
                };
                self.append(self.notice.clone());
                let mut commands = self.refresh(false);
                commands.extend(self.refresh_sessions());
                commands
            }
            Message::Started { result } => {
                self.starting = false;
                match result {
                    Ok(started) => {
                        let commands = self.attach(&started.socket.to_string_lossy());
                        self.notice = if started.already_running {
                            "Service already running; attached".into()
                        } else if started.installed {
                            "Service installed and started; attached".into()
                        } else {
                            "Service started; attached".into()
                        };
                        self.append(self.notice.clone());
                        self.started = Some(started.socket);
                        commands
                    }
                    Err(reason) => {
                        self.notice = format!("Service not started: {}", bounded(&reason));
                        self.append(self.notice.clone());
                        Vec::new()
                    }
                }
            }
            Message::Exported { result } => {
                self.exporting = false;
                self.notice = match result {
                    Ok(file) => format!("Diagnostics written to {}", file.display()),
                    Err(error) => format!("Diagnostics export failed: {}", bounded(&error)),
                };
                Vec::new()
            }
            Message::FollowerEnded {
                attach,
                follower,
                reason,
            } if current(attach) && Some(follower) == self.follower => self.lost_service(format!(
                "Service: event stream ended ({})",
                bounded(&reason)
            )),
            // Stale result of an earlier attachment or follower.
            _ => Vec::new(),
        }
    }
    /// Current projection.
    pub fn view(&self) -> View {
        let Some(status) = &self.status else {
            let mut rows: [String; 7] = std::array::from_fn(|_| "—".to_owned());
            rows[0] = if self.path.is_some() {
                "unavailable".into()
            } else {
                "not attached".into()
            };
            return View {
                rows,
                connect: false,
                disconnect: false,
                cancel: false,
                connect_label: "Connect",
            };
        };
        let idle = self.busy.is_none();
        let pending = status.operation.is_some();
        let connected = status.phase == "connected";
        View {
            rows: status_rows(status),
            connect: idle
                && !pending
                && matches!(
                    status.phase.as_str(),
                    "disconnected" | "failed" | "connected"
                ),
            disconnect: idle && connected && !pending,
            cancel: idle
                && pending
                && matches!(status.phase.as_str(), "preparing" | "authenticating"),
            connect_label: if connected { "Reconnect" } else { "Connect" },
        }
    }
}
use Command::StopFollower;

#[cfg(test)]
#[path = "model_tests.rs"]
mod tests;
