//! Version-5 asynchronous operation DTOs (`docs/modules/local-operations.md`).
//!
//! Mutating actions return an accepted operation immediately. Separate
//! bounded long-poll actions read, wait for and cancel operations and read the
//! service's exact event log. Versions 1 and 4 keep their own types and bytes.
use super::{ConnectionReuseRequest, Snapshot};
use crate::secure_udp::common_status::CanonicalConfiguration;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Local API version carrying the asynchronous operation model.
pub const OPERATIONS_VERSION: u16 = 5;
/// Longest single long-poll accepted by the service, in milliseconds.
pub const WAIT_LIMIT_MS: u32 = 30_000;
/// Most events in one page.
pub const EVENTS_LIMIT: u16 = 32;
/// Most catalog configurations in one page.
pub const CATALOG_LIMIT: u16 = 4;

/// Random identity of one service instance, as 16 lowercase hex characters.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ServiceId(pub u64);
impl Serialize for ServiceId {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&format!("{:016x}", self.0))
    }
}
impl<'de> Deserialize<'de> for ServiceId {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        Self::parse(&text)
            .ok_or_else(|| serde::de::Error::custom("service must be 16 lowercase hex"))
    }
}
impl ServiceId {
    /// Parse exactly 16 lowercase hex characters.
    pub fn parse(text: &str) -> Option<Self> {
        (text.len() == 16
            && text
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)))
        .then(|| u64::from_str_radix(text, 16).ok().map(Self))
        .flatten()
    }
}
/// A 32-byte digest as 64 lowercase hex characters.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Digest(pub [u8; 32]);
impl Serialize for Digest {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let text: String = self.0.iter().map(|byte| format!("{byte:02x}")).collect();
        serializer.serialize_str(&text)
    }
}
impl<'de> Deserialize<'de> for Digest {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        Self::parse(&text)
            .ok_or_else(|| serde::de::Error::custom("digest must be 64 lowercase hex"))
    }
}
impl Digest {
    /// Parse exactly 64 lowercase hex characters.
    pub fn parse(text: &str) -> Option<Self> {
        if text.len() != 64
            || !text
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return None;
        }
        let mut bytes = [0; 32];
        for (byte, pair) in bytes.iter_mut().zip(text.as_bytes().chunks_exact(2)) {
            let pair = std::str::from_utf8(pair).ok()?;
            *byte = u8::from_str_radix(pair, 16).ok()?;
        }
        Some(Self(bytes))
    }
}

/// Version-5 action.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "command", rename_all = "snake_case", deny_unknown_fields)]
pub enum OperationAction {
    /// Service lifecycle, current backend observation and event cursor.
    Status {},
    /// Service version, role, uptime and per-feature capabilities.
    ServiceInfo {},
    /// One snapshot of cumulative counters.
    Metrics {},
    /// One page of meter CSR registers under a whole-segment prefix.
    MetersRead {
        /// Local session or the authenticated peer.
        side: super::MeterSide,
        /// Whole-segment prefix; empty reads everything.
        #[serde(default)]
        prefix: String,
        /// Last path of the previous page.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        cursor: Option<String>,
        /// Most entries, 1..=256.
        limit: u16,
    },
    /// One page of the meter catalog under a prefix.
    MetersCatalog {
        /// Whole-segment prefix; empty lists everything.
        #[serde(default)]
        prefix: String,
        /// Pattern index to continue from.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        cursor: Option<u32>,
        /// Most entries, 1..=256.
        limit: u16,
    },
    /// Devices visible to the service (TUN/TAP first), with ownership.
    DeviceList {},
    /// Main-table routes, with ownership.
    RouteList {},
    /// Create, configure or delete a service-owned device.
    Device {
        /// Nonzero sequential service idempotency key.
        request_key: u64,
        /// The change.
        change: super::DeviceChange,
    },
    /// Add or remove a service-owned route, or route everything through the tunnel.
    Route {
        /// Nonzero sequential service idempotency key.
        request_key: u64,
        /// The change.
        change: super::RouteChange,
    },
    /// Disconnect, then end the service process (daemon only).
    ServiceStop {
        /// Nonzero sequential service idempotency key.
        request_key: u64,
    },
    /// The live server session (at most one: the server is point-to-point).
    SessionList {},
    /// End the live server session and listen again with the same plan.
    SessionKick {
        /// Nonzero sequential service idempotency key.
        request_key: u64,
    },
    /// Stored profiles with revision, role and default flag.
    ProfileList {},
    /// One stored profile document.
    ProfileGet {
        /// Profile name.
        name: String,
    },
    /// Build the stored profile's plan without opening anything.
    ProfileValidate {
        /// Profile name.
        name: String,
    },
    /// Key files the stored profile references, with public keys.
    ProfileKeys {
        /// Profile name.
        name: String,
    },
    /// Save, delete or choose the default profile.
    Profile {
        /// Nonzero sequential service idempotency key.
        request_key: u64,
        /// The change.
        change: super::ProfileChange,
    },
    /// Connect with a stored profile; with `replace`, replace a live session
    /// (a controlled reconnect, never a hot switch). The profile's plan
    /// becomes the retained plan for later `reconnect`.
    ProfileConnect {
        /// Nonzero sequential service idempotency key.
        request_key: u64,
        /// Profile name.
        name: String,
        /// Replace a live session instead of refusing with `state`.
        #[serde(default)]
        replace: bool,
    },
    /// Connect from idle with the service's retained plan.
    Connect {
        /// Nonzero sequential service idempotency key.
        request_key: u64,
    },
    /// Replace the live generation, or connect when idle, with the retained plan.
    Reconnect {
        /// Nonzero sequential service idempotency key.
        request_key: u64,
    },
    /// Abort the live generation; not a peer-confirmed clean close.
    Disconnect {
        /// Nonzero sequential service idempotency key.
        request_key: u64,
    },
    /// Begin an explicit proxy drain; acceptance is not closure.
    DrainProxy {
        /// Nonzero sequential service idempotency key.
        request_key: u64,
    },
    /// Negotiate one complete Common configuration.
    SwitchCommonConfiguration {
        /// Exact complete canonical value.
        configuration: CanonicalConfiguration,
        /// Nonzero sequential service idempotency key.
        request_key: u64,
    },
    /// Retire one claimed owner through the selected reuse protocol.
    ReuseConnection {
        /// Exact owner and distinct canonical keys.
        request: ConnectionReuseRequest,
        /// Nonzero sequential service idempotency key.
        request_key: u64,
    },
    /// Read one retained operation without waiting.
    OperationGet {
        /// Operation ordinal.
        operation: u64,
        /// Expected service instance; a mismatch is refused.
        #[serde(default)]
        service: Option<ServiceId>,
    },
    /// Wait at most `timeout_ms` for an operation's actual completion.
    OperationWait {
        /// Operation ordinal.
        operation: u64,
        /// One through [`WAIT_LIMIT_MS`].
        timeout_ms: u32,
        /// Expected service instance; a mismatch is refused.
        #[serde(default)]
        service: Option<ServiceId>,
    },
    /// Request local cancellation of a pending setup.
    OperationCancel {
        /// Operation ordinal.
        operation: u64,
        /// Expected service instance; a mismatch is refused.
        #[serde(default)]
        service: Option<ServiceId>,
    },
    /// Read events after a cursor, waiting at most `timeout_ms` for one.
    Events {
        /// Last sequence already seen (zero for the oldest retained).
        after: u64,
        /// One through [`EVENTS_LIMIT`].
        limit: u16,
        /// Zero through [`WAIT_LIMIT_MS`].
        timeout_ms: u32,
        /// Expected service instance; a mismatch is refused.
        #[serde(default)]
        service: Option<ServiceId>,
    },
    /// Read one bounded page of the authenticated Common catalog.
    Catalog {
        /// Exact service generation.
        generation: u64,
        /// Exact authenticated catalog root.
        catalog: Digest,
        /// First canonical index.
        offset: u16,
        /// One through [`CATALOG_LIMIT`].
        limit: u16,
    },
    /// The live session's tuning controls: current setting and choices
    /// (docs/modules/live-tuning.md, decision 10).
    TuningGet {},
    /// Hot-switch the live session to `setting`; the service resolves it to
    /// the exact member of the session's authenticated catalog.
    TuningSwitch {
        /// Nonzero sequential service idempotency key.
        request_key: u64,
        /// The wanted setting.
        setting: super::TuningSetting,
    },
    /// Start a speed or ping test through the tunnel (not a keyed operation).
    TestStart {
        /// The test.
        test: super::tunnel_test::TestRequest,
    },
    /// The latest test, or test `id`, waiting at most `timeout_ms` for its end.
    TestGet {
        /// Test number; absent reads the latest.
        #[serde(default)]
        id: Option<u64>,
        /// Zero through [`WAIT_LIMIT_MS`].
        #[serde(default)]
        timeout_ms: u32,
    },
    /// Cancel a running test.
    TestCancel {
        /// Test number.
        id: u64,
    },
    /// Negotiate a live wire speed-budget update (bytes/s) with the authenticated peer.
    RateBudgetSet {
        /// Local upload wire budget in bytes/s (`125_000..=1_250_000_000`).
        send_rate: u64,
        /// Peer send (local download) wire budget in bytes/s (`125_000..=1_250_000_000`).
        receive_rate: u64,
    },
    /// Read SOCKS5 entry settings, listener status and flow counters (`DGUI-08`).
    SocksGet {},
    /// Apply SOCKS5 entry settings, starting or stopping the local listener (`DGUI-08`).
    SocksSet {
        /// Complete validated settings (password is optional when already stored).
        settings: super::SocksSettings,
    },
    /// Read active and recently ended SOCKS5 flows (`DGUI-08`).
    SocksFlows {},
    /// Read live in-session carrier-switch state and selectable targets (`DGUI-14`).
    CarrierSwitchGet {},
    /// Negotiate a make-before-break live carrier / UDP cover switch (`DGUI-14`).
    CarrierSwitch {
        /// Canonical target identifier (`quic-like`, `media-like`, `tls-like`).
        target: String,
    },
}
impl OperationAction {
    /// Whether the action submits a keyed service operation.
    pub fn submits(&self) -> bool {
        matches!(
            self,
            Self::Connect { .. }
                | Self::Reconnect { .. }
                | Self::Profile { .. }
                | Self::ProfileConnect { .. }
                | Self::ServiceStop { .. }
                | Self::SessionKick { .. }
                | Self::Disconnect { .. }
                | Self::DrainProxy { .. }
                | Self::SwitchCommonConfiguration { .. }
                | Self::TuningSwitch { .. }
                | Self::ReuseConnection { .. }
                | Self::Device { .. }
                | Self::Route { .. }
        )
    }
    /// Longest time the service may hold the request before replying.
    pub fn hold_ms(&self) -> u32 {
        match self {
            Self::OperationWait { timeout_ms, .. }
            | Self::Events { timeout_ms, .. }
            | Self::TestGet { timeout_ms, .. } => (*timeout_ms).min(WAIT_LIMIT_MS),
            Self::MetersRead {
                side: super::MeterSide::Remote,
                ..
            } => u32::try_from(l2tunnel_meters::wire::DEADLINE_MS).unwrap_or(WAIT_LIMIT_MS),
            _ => 0,
        }
    }
}
/// One version-5 request.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(try_from = "OperationRequestWire")]
pub struct OperationRequest {
    /// Must equal [`OPERATIONS_VERSION`].
    pub version: u16,
    /// Requested action.
    pub action: OperationAction,
}
impl OperationRequest {
    /// Construct a version-5 request.
    pub fn new(action: OperationAction) -> Self {
        Self {
            version: OPERATIONS_VERSION,
            action,
        }
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OperationRequestWire {
    version: u16,
    action: OperationAction,
}
impl TryFrom<OperationRequestWire> for OperationRequest {
    type Error = &'static str;
    fn try_from(value: OperationRequestWire) -> Result<Self, Self::Error> {
        if value.version != OPERATIONS_VERSION {
            return Err("operation requests require API version5");
        }
        Ok(Self {
            version: value.version,
            action: value.action,
        })
    }
}

/// Termination of a live generation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum TerminalState {
    /// Explicit disconnect, reconnect or owner cancellation.
    Aborted,
    /// Selected proxy completed its authenticated drain.
    Closed,
    /// Runtime failed.
    Failed {
        /// Local error category.
        error_kind: String,
    },
}
/// Service status.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceStatus {
    /// `disconnected`, `preparing`, `authenticating`, `connected`, `applying`,
    /// `stopping`, `failed` or `closed`.
    pub phase: String,
    /// Pending operation.
    pub operation: Option<u64>,
    /// Current/last live generation.
    pub generation: Option<u64>,
    /// Latest generation termination.
    pub terminal: Option<TerminalState>,
    /// Advisory next sequential request key; not a reservation.
    pub next_request_key: Option<u64>,
    /// Latest recorded event sequence.
    pub event_cursor: u64,
    /// Bound setup listener address.
    pub listening: Option<String>,
    /// Existing version-1/4 backend projection, unchanged.
    pub observation: Option<Snapshot>,
    /// Stored profile the current plan came from, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile: Option<String>,
    /// Milliseconds since the live session connected (connected phase only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub connected_ms: Option<u64>,
}
/// Latest setup evidence of a connect/reconnect operation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SetupState {
    /// Last actual stage reached.
    pub stage: String,
    /// `pending`, `ready`, `failed`, `cancelled` or `owner_closed`.
    pub outcome: String,
    /// Failure provenance, when failed.
    pub failure: Option<String>,
    /// Sampled elapsed time.
    pub elapsed_micros: u64,
}
/// Actual completion of an operation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case", deny_unknown_fields)]
pub enum OperationResult {
    /// Actual runtime readiness of this generation.
    Connected {
        /// Live generation.
        generation: u64,
    },
    /// Original owners were dropped.
    Aborted,
    /// Typed apply success.
    Applied {
        /// Backend outcome code.
        code: String,
    },
    /// Typed apply refusal.
    Rejected {
        /// Backend outcome code.
        code: String,
    },
    /// Peer-confirmed Common epoch.
    CommonCommitted {
        /// Committed epoch.
        epoch: u64,
        /// Submitted complete configuration.
        configuration: CanonicalConfiguration,
    },
    /// Definitive Common refusal before commit.
    CommonRefused {
        /// Bounded runtime reason.
        reason: String,
        /// Submitted complete configuration.
        configuration: CanonicalConfiguration,
    },
    /// Connection reuse confirmed.
    ReuseConfirmed {
        /// Owning generation.
        generation: u64,
    },
    /// Connection reuse refused.
    ReuseRefused {
        /// Owning generation.
        generation: u64,
        /// Bounded runtime reason.
        reason: String,
    },
    /// Setup cancelled before readiness.
    Cancelled,
    /// Ownership ended with an uncertain peer outcome; never a rollback.
    OutcomeUnknown,
    /// Original deadline or local/runtime failure.
    Failed {
        /// Local error category.
        error_kind: String,
    },
    /// A device or route change took effect.
    HostApplied {
        /// Bounded description of what changed.
        summary: String,
    },
    /// A device or route change was refused; nothing was left half-applied.
    HostRefused {
        /// Bounded reason.
        reason: String,
    },
    /// The profile store changed.
    ProfileApplied {
        /// Bounded summary.
        summary: String,
    },
    /// The profile store refused the change and is unchanged.
    ProfileRefused {
        /// Bounded reason.
        reason: String,
    },
}
impl OperationResult {
    /// Whether the completion is a success.
    pub fn succeeded(&self) -> bool {
        matches!(
            self,
            Self::Connected { .. }
                | Self::Aborted
                | Self::Applied { .. }
                | Self::CommonCommitted { .. }
                | Self::ReuseConfirmed { .. }
                | Self::HostApplied { .. }
                | Self::ProfileApplied { .. }
        )
    }
}
/// One retained operation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperationState {
    /// Operation ordinal (equal to its request key).
    pub id: u64,
    /// `connect`, `reconnect`, `disconnect`, `apply`, `common_switch` or `connection_reuse`.
    pub kind: String,
    /// `pending` or `completed`.
    pub state: String,
    /// Remaining time to the original deadline, if the operation has one.
    pub deadline_ms: Option<u64>,
    /// A local cancellation was requested; not proof of cancellation.
    pub cancel_requested: bool,
    /// Latest setup evidence.
    pub setup: Option<SetupState>,
    /// Actual completion.
    pub result: Option<OperationResult>,
}
/// One recorded event.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum EventBody {
    /// New operation retained.
    OperationAccepted {
        /// Operation ordinal.
        operation: u64,
        /// Operation kind.
        kind: String,
    },
    /// Setup reached a new stage.
    OperationProgress {
        /// Operation ordinal.
        operation: u64,
        /// Stage reached.
        stage: String,
    },
    /// Operation completed.
    OperationCompleted {
        /// Operation ordinal.
        operation: u64,
        /// Short completion name.
        outcome: String,
    },
    /// Published lifecycle changed.
    Lifecycle {
        /// Service phase.
        phase: String,
        /// Pending operation.
        operation: Option<u64>,
        /// Current/last generation.
        generation: Option<u64>,
        /// Latest termination.
        terminal: Option<TerminalState>,
    },
}
/// Sequenced event.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EventState {
    /// Monotonic sequence.
    pub sequence: u64,
    /// Recorded transition.
    pub event: EventBody,
}
/// Bounded event page.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EventBatch {
    /// Events after the cursor, oldest first.
    pub events: Vec<EventState>,
    /// Cursor for the next request.
    pub next: u64,
    /// Events were evicted; the reply carries a full status to resynchronize.
    pub gap: bool,
}
/// One version-5 reply.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperationReply {
    /// Always [`OPERATIONS_VERSION`].
    pub version: u16,
    /// The request was served as asked (`running` and `accepted` are ok).
    pub ok: bool,
    /// Machine-readable bounded outcome code.
    pub code: String,
    /// Service instance, absent only when the endpoint has no service handle.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service: Option<ServiceId>,
    /// Service status.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<ServiceStatus>,
    /// Operation view.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operation: Option<OperationState>,
    /// Event page.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub events: Option<EventBatch>,
    /// Backend observation (Common catalog page).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observation: Option<Snapshot>,
    /// Service identity and capabilities (`service_info`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub info: Option<super::ServiceInfo>,
    /// Counter snapshot (`metrics`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metrics: Option<Box<super::Metrics>>,
    /// Meter registers (`meters_read`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub meters: Option<Box<super::MeterPage>>,
    /// Meter catalog page (`meters_catalog`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub meter_catalog: Option<Box<super::MeterCatalogPage>>,
    /// Device listing (`device_list`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub devices: Option<Vec<super::DeviceState>>,
    /// Route listing (`route_list`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub routes: Option<Vec<super::RouteState>>,
    /// Stored profiles (`profile_list`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profiles: Option<Vec<super::ProfileSummary>>,
    /// One profile (`profile_get`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile: Option<super::ProfileEntry>,
    /// Plan check (`profile_validate`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub check: Option<super::ProfileCheck>,
    /// Server sessions (`session_list`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sessions: Option<Vec<super::SessionState>>,
    /// Referenced key files (`profile_keys`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keys: Option<Vec<super::keys::KeyReference>>,
    /// Responder and test state (`test_start`, `test_get`, `test_cancel`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub test: Option<Box<super::tunnel_test::TestReply>>,
    /// Live-tuning controls (`tuning_get`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tuning: Option<Box<super::TuningView>>,
    /// SOCKS5 entry status and settings (`socks_get`, `socks_set`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub socks: Option<Box<super::SocksStatus>>,
    /// Active and recent SOCKS5 flows (`socks_flows`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub socks_flows: Option<Box<super::SocksFlows>>,
    /// Live carrier-switch status and selectable targets (`carrier_switch_get`, `carrier_switch`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub carrier_switch: Option<Box<super::CarrierSwitchView>>,
}
impl OperationReply {
    /// Reply carrying only an outcome code.
    pub fn code(ok: bool, code: &str, service: Option<ServiceId>) -> Self {
        Self {
            version: OPERATIONS_VERSION,
            ok,
            code: code.into(),
            service,
            status: None,
            operation: None,
            events: None,
            observation: None,
            info: None,
            metrics: None,
            meters: None,
            meter_catalog: None,
            devices: None,
            routes: None,
            profiles: None,
            profile: None,
            check: None,
            keys: None,
            sessions: None,
            test: None,
            tuning: None,
            socks: None,
            socks_flows: None,
            carrier_switch: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requests_are_strict_and_version_bound() {
        let request: OperationRequest = serde_json::from_str(
            r#"{"version":5,"action":{"command":"operation_wait","operation":3,"timeout_ms":100,"service":"00000000000000ff"}}"#,
        )
        .unwrap_or_else(|_| OperationRequest::new(OperationAction::Status {}));
        assert_eq!(
            request.action,
            OperationAction::OperationWait {
                operation: 3,
                timeout_ms: 100,
                service: Some(ServiceId(255))
            }
        );
        for text in [
            r#"{"version":4,"action":{"command":"status"}}"#,
            r#"{"version":5,"action":{"command":"status","extra":1}}"#,
            r#"{"version":5,"action":{"command":"reconnect"}}"#,
            r#"{"version":5,"action":{"command":"unknown"}}"#,
            r#"{"version":5,"action":{"command":"operation_get","operation":1,"service":"FF00000000000000"}}"#,
            r#"{"version":5,"action":{"command":"catalog","generation":1,"catalog":"00","offset":0,"limit":1}}"#,
            r#"{"version":5,"action":{"command":"status"},"other":0}"#,
        ] {
            assert!(
                serde_json::from_str::<OperationRequest>(text).is_err(),
                "{text}"
            );
        }
        assert_eq!(Digest::parse(&"ab".repeat(32)), Some(Digest([0xab; 32])));
        assert_eq!(Digest::parse(&"AB".repeat(32)), None);
        assert_eq!(ServiceId::parse("+000000000000001"), None);
    }

    #[test]
    fn replies_round_trip_and_reject_unknown_fields() -> Result<(), serde_json::Error> {
        let mut reply = OperationReply::code(true, "running", Some(ServiceId(7)));
        reply.operation = Some(OperationState {
            id: 2,
            kind: "reconnect".into(),
            state: "pending".into(),
            deadline_ms: Some(10),
            cancel_requested: false,
            setup: None,
            result: None,
        });
        let text = serde_json::to_string(&reply)?;
        assert!(text.contains(r#""service":"0000000000000007""#));
        assert_eq!(serde_json::from_str::<OperationReply>(&text)?, reply);
        assert!(
            serde_json::from_str::<OperationReply>(r#"{"version":5,"ok":true,"code":"ok","x":1}"#)
                .is_err()
        );
        Ok(())
    }
}
