//! Toolkit-independent GUI state. The worker performs every exchange; the
//! model only decides what to request and what to show. Messages from an
//! earlier attachment or event follower are ignored, never merged.
use crate::stats::{History, Sample};
use l2tunnel_client_core::local::elevate::{StartRequest, Started};
use l2tunnel_client_core::local::keys::KeyReference;
use l2tunnel_client_core::local::tunnel_test::{TestRequest, TestState};
use l2tunnel_client_core::local::{
    CarrierSwitchView, DeviceChange, DeviceState, EventBody, EventState, Feature, MeterPage,
    MeterSide, Metrics, OperationReply, OperationResult, OperationState, ProfileChange,
    ProfileEntry, ProfileSummary, RouteChange, RouteState, ServiceId, ServiceInfo, ServiceStatus,
    SessionState, SocksFlows, SocksSettings, SocksStatus, TerminalState, TuningSetting, TuningView,
};
use l2tunnel_client_core::secure_udp::common_status::CanonicalConfiguration;
use std::collections::{BTreeMap, VecDeque};
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
    /// `meters_read`.
    Meters {
        /// Local or remote peer CSR.
        side: MeterSide,
        /// Whole-segment prefix (empty for all).
        prefix: String,
        /// Optional pagination cursor (last path of previous page).
        cursor: Option<String>,
    },
    /// `rate_budget_set`.
    RateBudgetSet {
        /// Local upload wire budget in bytes/s.
        send_rate: u64,
        /// Peer send (local download) wire budget in bytes/s.
        receive_rate: u64,
    },
    /// `socks_get`.
    SocksGet,
    /// `socks_flows`.
    SocksFlows,
    /// `socks_set`.
    SocksSet(Box<SocksSettings>),
    /// `carrier_switch_get`.
    CarrierSwitchGet,
    /// `carrier_switch`.
    CarrierSwitch(String),
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
    catalog_for: Option<(u64, [u8; 32])>,
    catalog_error: Option<String>,
    target: Option<CanonicalConfiguration>,
    /// Live-tuning controls and the (generation, epoch) they were read for.
    tuning: Option<TuningView>,
    tuning_for: Option<(u64, Option<u64>)>,
    tuning_error: Option<String>,
    /// Live speed-budget update in flight and last error.
    rate_budget_busy: bool,
    rate_budget_error: Option<String>,
    /// SOCKS5 entry status, active flows, and error state.
    socks: Option<SocksStatus>,
    socks_flows: Option<SocksFlows>,
    socks_busy: bool,
    socks_error: Option<String>,
    /// Live in-session carrier switch view, busy flag, and error state.
    carrier_switch: Option<CarrierSwitchView>,
    carrier_switch_busy: bool,
    carrier_switch_error: Option<String>,
    /// Latest CSR meter page, previous snapshot for rates, and error state.
    meters: Option<MeterPage>,
    meters_prev: Option<(MeterSide, u64, u64, BTreeMap<String, u64>)>,
    meters_request: Option<(MeterSide, String)>,
    meters_error: Option<String>,
    /// Last action completion result so modal forms know whether to close or show an error.
    action_result: Option<(Action, Result<String, String>)>,
    /// Last diagnostic export completion result.
    exported: Option<Result<PathBuf, String>>,
    /// Sequence boundary of the initial event backlog; historical completions
    /// at or below this sequence are not fetched via `OperationGet`.
    backlog_end: Option<u64>,
    in_flight: Vec<Query>,
    /// Reads asked for while the same read was in flight; sent again when
    /// it answers, so a reply from before a change never stays on screen.
    again: Vec<Query>,
    /// Last logged event sequence per service instance, so a restarted
    /// follower continues instead of logging events twice.
    seen: Option<(ServiceId, u64)>,
}

fn friendly_query_error(error: &str) -> String {
    if error.contains("unexpected end of file") {
        "not supported by this service version (update or restart the service)".into()
    } else {
        bounded(error)
    }
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
        self.catalog_for = None;
        self.catalog_error = None;
        self.target = None;
        self.tuning = None;
        self.tuning_for = None;
        self.tuning_error = None;
        self.meters = None;
        self.meters_prev = None;
        self.meters_request = None;
        self.meters_error = None;
        self.socks = None;
        self.socks_flows = None;
        self.socks_busy = false;
        self.socks_error = None;
        self.carrier_switch = None;
        self.carrier_switch_busy = false;
        self.carrier_switch_error = None;
        self.action_result = None;
        self.exported = None;
        self.backlog_end = None;
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
            self.tuning_error = None;
            return Vec::new();
        };
        if self.tuning_for == Some(key) {
            return Vec::new();
        }
        self.tuning_for = Some(key);
        self.tuning_error = None;
        self.query(Query::Tuning)
    }
    /// Manually retry loading live-tuning controls for the current session.
    pub fn retry_tuning(&mut self) -> Vec<Command> {
        self.tuning_for = None;
        self.tuning_error = None;
        self.refresh_tuning()
    }
    /// Latest live-tuning controls of the live session.
    pub fn tuning(&self) -> Option<&TuningView> {
        self.tuning.as_ref().filter(|_| {
            self.session_key()
                .is_some_and(|key| self.tuning_for == Some(key))
        })
    }
    /// Why live-tuning controls could not be read for the live session.
    pub fn tuning_error(&self) -> Option<&str> {
        self.tuning_error.as_deref().filter(|_| {
            self.session_key()
                .is_some_and(|key| self.tuning_for == Some(key))
        })
    }
    /// Whether a live-tuning query is currently in flight.
    pub fn tuning_loading(&self) -> bool {
        self.in_flight
            .iter()
            .any(|pending| matches!(pending, Query::Tuning))
    }
    /// Refresh service metadata (version, uptime, capabilities).
    pub fn refresh_info(&mut self) -> Vec<Command> {
        self.query(Query::Info)
    }
    /// Read one page of CSR meter registers.
    pub fn refresh_meters(
        &mut self,
        side: MeterSide,
        prefix: String,
        cursor: Option<String>,
    ) -> Vec<Command> {
        if cursor.is_none() {
            self.meters_error = None;
        }
        if self.meters_request.as_ref() != Some(&(side, prefix.clone())) {
            self.meters = None;
            self.meters_prev = None;
            self.meters_error = None;
        }
        self.meters_request = Some((side, prefix.clone()));
        self.query(Query::Meters {
            side,
            prefix,
            cursor,
        })
    }
    /// Latest CSR meter page.
    pub fn meters(&self) -> Option<&MeterPage> {
        self.meters.as_ref()
    }
    /// Why CSR meters could not be read.
    pub fn meters_error(&self) -> Option<&str> {
        self.meters_error.as_deref()
    }
    /// Whether a CSR meter read is in flight.
    pub fn meters_loading(&self) -> bool {
        self.in_flight
            .iter()
            .any(|pending| matches!(pending, Query::Meters { .. }))
    }
    /// Per-second rate of register `path` against the previous snapshot of the
    /// same side and session generation, when monotonically advancing.
    pub fn meter_rate(&self, path: &str, value: u64) -> Option<f64> {
        let current = self.meters.as_ref()?;
        let (side, generation, prev_ms, prev_map) = self.meters_prev.as_ref()?;
        if *side != current.side
            || *generation != current.generation
            || current.sampled_ms <= *prev_ms
        {
            return None;
        }
        let before = prev_map.get(path)?;
        let delta = value.checked_sub(*before)?;
        let seconds = (current.sampled_ms - *prev_ms) as f64 / 1000.0;
        (seconds > 0.0).then_some(delta as f64 / seconds)
    }
    /// Consume the latest completion result for `action`, if it matches.
    pub fn take_action_result(&mut self, action: Action) -> Option<Result<String, String>> {
        if self
            .action_result
            .as_ref()
            .is_some_and(|(kind, _)| *kind == action)
        {
            self.action_result.take().map(|(_, result)| result)
        } else {
            None
        }
    }
    /// Consume the latest diagnostic export completion result.
    pub fn take_exported(&mut self) -> Option<Result<PathBuf, String>> {
        self.exported.take()
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
        if self.socks.is_some() && self.capability(Feature::Socks5).is_ok() {
            commands.extend(self.query(Query::SocksFlows));
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
    /// generation or catalog than the live session's. Returns `false` when the
    /// current session's catalog already failed so the UI does not spin-retry.
    pub fn catalog_stale(&self) -> bool {
        let live = self
            .status
            .as_ref()
            .and_then(|status| status.observation.as_ref())
            .and_then(|observation| observation.common.as_ref())
            .map(|common| (common.generation, common.catalog));
        let Some(live) = live else {
            return false;
        };
        if self.catalog_error.is_some() && self.catalog_for == Some(live) {
            return false;
        }
        self.catalog
            .as_ref()
            .map(|view| (view.generation, view.root))
            != Some(live)
    }
    /// Why the current session's catalog could not be read.
    pub fn catalog_error(&self) -> Option<&str> {
        let live = self
            .status
            .as_ref()
            .and_then(|status| status.observation.as_ref())
            .and_then(|observation| observation.common.as_ref())
            .map(|common| (common.generation, common.catalog));
        self.catalog_error
            .as_deref()
            .filter(|_| live.is_some() && self.catalog_for == live)
    }
    /// Clear the catalog error and fetch page 0 again.
    pub fn retry_catalog(&mut self) -> Vec<Command> {
        self.catalog_error = None;
        self.catalog_for = None;
        self.catalog_page(0)
    }
    /// Whether an action is in flight.
    pub fn busy(&self) -> bool {
        self.busy.is_some()
    }
    /// Negotiate a live wire speed-budget update (bytes/s) with the peer.
    pub fn set_rate_budget(&mut self, send_rate: u64, receive_rate: u64) -> Vec<Command> {
        if self.rate_budget_busy {
            return Vec::new();
        }
        self.rate_budget_busy = true;
        self.rate_budget_error = None;
        self.query(Query::RateBudgetSet {
            send_rate,
            receive_rate,
        })
    }
    /// Whether a live speed-budget update is in flight.
    pub fn rate_budget_busy(&self) -> bool {
        self.rate_budget_busy
    }
    /// Last speed-budget error, if any.
    pub fn rate_budget_error(&self) -> Option<&str> {
        self.rate_budget_error.as_deref()
    }
    /// Read SOCKS5 status and active flows.
    pub fn refresh_socks(&mut self) -> Vec<Command> {
        self.socks_error = None;
        let mut commands = self.query(Query::SocksGet);
        commands.extend(self.query(Query::SocksFlows));
        commands
    }
    /// Apply updated SOCKS5 settings.
    pub fn apply_socks(&mut self, settings: SocksSettings) -> Vec<Command> {
        if self.socks_busy {
            return Vec::new();
        }
        self.socks_busy = true;
        self.socks_error = None;
        self.query(Query::SocksSet(Box::new(settings)))
    }
    /// Latest SOCKS5 status.
    pub fn socks(&self) -> Option<&SocksStatus> {
        self.socks.as_ref()
    }
    /// Latest SOCKS5 flows.
    pub fn socks_flows(&self) -> Option<&SocksFlows> {
        self.socks_flows.as_ref()
    }
    /// Whether a SOCKS5 status or flows query is in flight.
    pub fn socks_loading(&self) -> bool {
        self.in_flight
            .iter()
            .any(|query| matches!(query, Query::SocksGet | Query::SocksFlows))
    }
    /// Whether a SOCKS5 settings apply is in flight.
    pub fn socks_busy(&self) -> bool {
        self.socks_busy
    }
    /// Last SOCKS5 error, if any.
    pub fn socks_error(&self) -> Option<&str> {
        self.socks_error.as_deref()
    }
    /// Read live carrier-switch targets and current carrier state.
    pub fn refresh_carrier_switch(&mut self) -> Vec<Command> {
        self.carrier_switch_error = None;
        self.query(Query::CarrierSwitchGet)
    }
    /// Perform a live in-session make-before-break carrier / UDP cover switch.
    pub fn switch_carrier(&mut self, target: String) -> Vec<Command> {
        if self.carrier_switch_busy {
            return Vec::new();
        }
        self.carrier_switch_busy = true;
        self.carrier_switch_error = None;
        self.query(Query::CarrierSwitch(target))
    }
    /// Latest live carrier-switch view.
    pub fn carrier_switch(&self) -> Option<&CarrierSwitchView> {
        self.carrier_switch.as_ref()
    }
    /// Whether a live carrier-switch read is in flight.
    pub fn carrier_switch_loading(&self) -> bool {
        self.in_flight
            .iter()
            .any(|query| matches!(query, Query::CarrierSwitchGet))
    }
    /// Whether a live carrier switch is in flight.
    pub fn carrier_switch_busy(&self) -> bool {
        self.carrier_switch_busy
    }
    /// Last live carrier-switch error, if any.
    pub fn carrier_switch_error(&self) -> Option<&str> {
        self.carrier_switch_error.as_deref()
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
                let mut need_info = self.info.is_none();
                match result {
                    Ok(reply) if reply.ok && reply.status.is_some() => {
                        let restarted = reply.service.is_some() && reply.service != self.service;
                        let previous_state = self
                            .status
                            .as_ref()
                            .map(|status| (status.phase.clone(), status.generation));
                        let next_state = reply
                            .status
                            .as_ref()
                            .map(|status| (status.phase.clone(), status.generation));
                        if restarted || previous_state != next_state {
                            need_info = true;
                        }
                        self.service = reply.service.or(self.service);
                        self.status = reply.status;
                        if self.notice.starts_with("Service") {
                            self.notice.clear();
                        }
                        if (start_follower || restarted || self.follower.is_none())
                            && let Some(path) = self.path.clone()
                        {
                            let after = self.follow_after();
                            let cursor =
                                self.status.as_ref().map_or(0, |status| status.event_cursor);
                            // Suppress `OperationGet` hydration for historical backlog
                            // events that already happened before this window attached.
                            self.backlog_end = (after < cursor).then_some(cursor);
                            self.next_follower += 1;
                            self.follower = Some(self.next_follower);
                            commands.push(Command::Follow {
                                attach,
                                follower: self.next_follower,
                                path,
                                after,
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
                if need_info {
                    commands.extend(self.query(Query::Info));
                }
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
                let reply = match result {
                    Ok(reply) => reply,
                    Err(error) => {
                        let text = friendly_query_error(&error);
                        match query {
                            Query::Tuning => {
                                self.tuning = None;
                                self.tuning_error = Some(text);
                            }
                            Query::Catalog {
                                generation,
                                catalog,
                                ..
                            } => {
                                self.catalog_for = Some((generation, catalog));
                                self.catalog_error = Some(text);
                            }
                            Query::Meters { side, prefix, .. } => {
                                if self.meters_request.as_ref() == Some(&(side, prefix)) {
                                    self.meters_error = Some(text);
                                }
                            }
                            Query::RateBudgetSet { .. } => {
                                self.rate_budget_busy = false;
                                self.rate_budget_error = Some(text);
                            }
                            Query::SocksGet | Query::SocksFlows => {
                                self.socks_error = Some(text);
                            }
                            Query::SocksSet(_) => {
                                self.socks_busy = false;
                                self.socks_error = Some(text);
                            }
                            Query::CarrierSwitchGet => {
                                self.carrier_switch_error = Some(text);
                            }
                            Query::CarrierSwitch(_) => {
                                self.carrier_switch_busy = false;
                                self.carrier_switch_error = Some(text);
                            }
                            Query::Profiles if self.profiles.is_none() => {
                                self.profiles = Some(Vec::new());
                                self.notice = format!("profile list failed: {text}");
                            }
                            Query::Sessions if self.sessions.is_none() => {
                                self.sessions = Some(Vec::new());
                                self.notice = format!("session list failed: {text}");
                            }
                            Query::Keys(name) if self.keys.is_none() => {
                                self.keys = Some((name, Vec::new()));
                                self.notice = format!("profile keys failed: {text}");
                            }
                            _ => {}
                        }
                        return again.map(|query| self.query(query)).unwrap_or_default();
                    }
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
                            self.tuning_error = None;
                        } else {
                            self.tuning = None;
                            if reply.code != "closed" {
                                let reason = format!("refused ({})", bounded(&reply.code));
                                self.notice = format!("tuning {reason}");
                                self.tuning_error = Some(reason);
                            } else {
                                self.tuning_error = Some("service is closed".into());
                            }
                        }
                    }
                    Query::Meters {
                        side,
                        prefix,
                        cursor,
                    } => {
                        if self.meters_request.as_ref() == Some(&(side, prefix)) {
                            if reply.ok
                                && let Some(page) = reply.meters
                            {
                                let page = *page;
                                self.meters_error = None;
                                if cursor.is_some()
                                    && let Some(existing) = &mut self.meters
                                    && existing.side == page.side
                                    && existing.generation == page.generation
                                {
                                    existing.entries.extend(page.entries);
                                    existing.next = page.next;
                                    existing.sampled_ms = page.sampled_ms;
                                    existing.age_ms = page.age_ms;
                                } else {
                                    if let Some(previous) = &self.meters
                                        && previous.side == page.side
                                        && previous.generation == page.generation
                                        && page.sampled_ms > previous.sampled_ms
                                    {
                                        let snapshot = previous
                                            .entries
                                            .iter()
                                            .map(|entry| (entry.path.clone(), entry.value))
                                            .collect();
                                        self.meters_prev = Some((
                                            previous.side,
                                            previous.generation,
                                            previous.sampled_ms,
                                            snapshot,
                                        ));
                                    }
                                    self.meters = Some(page);
                                }
                            } else if !reply.ok {
                                self.meters_error = Some(match reply.code.as_str() {
                                    "peer_timeout" => {
                                        "peer did not answer (the remote server may be on an older build)".into()
                                    }
                                    "remote_unavailable" => {
                                        "remote meters are not available on this carrier or service version".into()
                                    }
                                    "peer_unsupported" => {
                                        "the remote peer does not support in-band meters".into()
                                    }
                                    "busy" => {
                                        "another meter read is in flight (rate limited to 4/s)".into()
                                    }
                                    "not_running" => {
                                        "no active session to read meters from".into()
                                    }
                                    _ => format!("refused ({})", bounded(&reply.code)),
                                });
                            } else {
                                self.meters_error = Some("service replied without meters".into());
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
                    Query::RateBudgetSet {
                        send_rate,
                        receive_rate,
                    } => {
                        self.rate_budget_busy = false;
                        if reply.ok {
                            self.rate_budget_error = None;
                            if reply.status.is_some() {
                                self.status = reply.status;
                            }
                            let up = crate::stats::rate_text(
                                crate::stats::Rate::SentBits,
                                Some(send_rate as f64 * 8.0),
                            );
                            let down = crate::stats::rate_text(
                                crate::stats::Rate::SentBits,
                                Some(receive_rate as f64 * 8.0),
                            );
                            let msg = format!("Speed budget updated: Up {up} · Down {down}");
                            self.notice = msg.clone();
                            self.append(msg);
                            let mut next = self.refresh(false);
                            if let Some(q) = again {
                                next.extend(self.query(q));
                            }
                            return next;
                        } else {
                            let reason = match reply.code.as_str() {
                                "peer_timeout" => {
                                    "peer did not confirm (restart the server on the latest build)"
                                        .into()
                                }
                                "invalid_rate" => {
                                    "rate must be between 1 Mb/s and 10 Gb/s".into()
                                }
                                "busy" => "another speed-budget update is in flight".into(),
                                "unsupported" => {
                                    "speed-budget tuning is not supported by this service or backend"
                                        .into()
                                }
                                "not_running" => "connect first to tune the speed budget".into(),
                                _ => format!("refused ({})", bounded(&reply.code)),
                            };
                            self.rate_budget_error = Some(reason);
                        }
                    }
                    Query::SocksGet => {
                        if reply.ok {
                            self.socks = reply.socks.map(|status| *status);
                            self.socks_error = None;
                        } else {
                            self.socks_error =
                                Some(format!("SOCKS5 status refused ({})", bounded(&reply.code)));
                        }
                    }
                    Query::SocksFlows => {
                        if reply.ok {
                            self.socks_flows = reply.socks_flows.map(|flows| *flows);
                        } else {
                            self.socks_error =
                                Some(format!("SOCKS5 flows refused ({})", bounded(&reply.code)));
                        }
                    }
                    Query::SocksSet(_) => {
                        self.socks_busy = false;
                        if let Some(status) = reply.socks {
                            self.socks = Some(*status);
                        }
                        if reply.ok {
                            self.socks_error = None;
                            let summary = self
                                .socks
                                .as_ref()
                                .and_then(|status| status.listening.as_ref())
                                .map_or_else(
                                    || "SOCKS5 listener stopped".to_owned(),
                                    |addr| format!("SOCKS5 listening on {addr}"),
                                );
                            self.notice = summary.clone();
                            self.append(summary);
                            let mut next = self.query(Query::SocksFlows);
                            if let Some(q) = again {
                                next.extend(self.query(q));
                            }
                            return next;
                        } else {
                            let reason = match reply.code.as_str() {
                                "not_proxy_profile" => {
                                    "SOCKS5 needs a connected TCP-proxy profile".into()
                                }
                                "invalid_settings" => "SOCKS5 settings failed validation".into(),
                                "bind_failed" => self
                                    .socks
                                    .as_ref()
                                    .and_then(|status| status.last_error.clone())
                                    .unwrap_or_else(|| {
                                        "could not bind SOCKS5 listen address".into()
                                    }),
                                "unsupported" => {
                                    "SOCKS5 is only available on the client role".into()
                                }
                                _ => format!("SOCKS5 refused ({})", bounded(&reply.code)),
                            };
                            self.socks_error = Some(reason);
                        }
                    }
                    Query::CarrierSwitchGet => {
                        if reply.ok {
                            self.carrier_switch = reply.carrier_switch.map(|view| *view);
                            self.carrier_switch_error = None;
                        } else if reply.code != "not_running" {
                            self.carrier_switch_error = Some(format!(
                                "carrier targets refused ({})",
                                bounded(&reply.code)
                            ));
                        }
                    }
                    Query::CarrierSwitch(target) => {
                        self.carrier_switch_busy = false;
                        if let Some(view) = reply.carrier_switch {
                            self.carrier_switch = Some(*view);
                        }
                        if reply.ok {
                            self.carrier_switch_error = None;
                            if reply.status.is_some() {
                                self.status = reply.status;
                            }
                            let msg = format!("Carrier switched live to {target}");
                            self.notice = msg.clone();
                            self.append(msg);
                            let mut next = self.refresh(false);
                            if let Some(q) = again {
                                next.extend(self.query(q));
                            }
                            return next;
                        } else {
                            let reason = match reply.code.as_str() {
                                "unsupported_carrier" => {
                                    "live carrier switch is only supported on UDP Common sessions"
                                        .into()
                                }
                                "not_coordinator" => {
                                    "only the client can initiate a live carrier switch".into()
                                }
                                "probe_failed" => {
                                    "standby UDP probe failed; kept the active carrier".into()
                                }
                                "peer_timeout" => {
                                    "peer did not answer (restart the server on the latest build)"
                                        .into()
                                }
                                "busy" => "another carrier switch is in progress".into(),
                                _ => format!("carrier switch refused ({})", bounded(&reply.code)),
                            };
                            self.carrier_switch_error = Some(reason);
                        }
                    }
                    Query::Catalog {
                        generation,
                        catalog,
                        ..
                    } => {
                        self.catalog_for = Some((generation, catalog));
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
                            self.catalog_error = None;
                        } else if !reply.ok {
                            let reason = format!("refused ({})", bounded(&reply.code));
                            self.notice = format!("catalog {reason}");
                            self.catalog_error = Some(reason);
                        } else {
                            self.catalog_error =
                                Some("service replied without catalog page".into());
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
                let result = match outcome {
                    ActionOutcome::Reply(reply) if reply.ok => {
                        let id = dash(reply.operation.as_ref().map(|state| state.id));
                        let message = if action == Action::Cancel {
                            format!("Cancellation requested for operation {id}")
                        } else if action == Action::Switch {
                            self.target = None;
                            format!("Operation {id} accepted (switch)")
                        } else {
                            format!("Operation {id} accepted ({})", action.name())
                        };
                        Ok(message)
                    }
                    ActionOutcome::Reply(reply) => Err(match &reply.check {
                        Some(check) => format!(
                            "{} refused: {} ({})",
                            action.name(),
                            bounded(&reply.code),
                            bounded(check.reason.as_deref().unwrap_or(""))
                        ),
                        None => format!("{} refused: {}", action.name(), bounded(&reply.code)),
                    }),
                    ActionOutcome::Failed(text) => {
                        Err(format!("{} failed: {}", action.name(), text))
                    }
                };
                self.notice = match &result {
                    Ok(message) | Err(message) => message.clone(),
                };
                self.action_result = Some((action, result));
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
                    let historical = self.backlog_end.is_some_and(|end| event.sequence <= end);
                    match &event.event {
                        EventBody::OperationProgress { stage, .. } => {
                            self.stage = Some(stage.clone());
                        }
                        EventBody::OperationAccepted { .. }
                        | EventBody::OperationCompleted { .. } => self.stage = None,
                        _ => {}
                    }
                    if !historical
                        && let EventBody::OperationCompleted { operation, .. } = &event.event
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
                if self.backlog_end.is_some_and(|end| batch.next >= end) {
                    self.backlog_end = None;
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
                self.notice = match &result {
                    Ok(file) => format!("Diagnostics written to {}", file.display()),
                    Err(error) => format!("Diagnostics export failed: {}", bounded(error)),
                };
                self.exported = Some(result);
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
