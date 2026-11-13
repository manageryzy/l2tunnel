//! Existing strict local control DTOs, independent of socket/OS transport.
use serde::{Deserialize, Serialize};

/// Current strict local protocol version.
pub const VERSION: u16 = 1;
/// Supported local policy changes; peer authorization still applies separately.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Compression {
    /// Preserve native bytes without compression.
    Off,
    /// Use independent LZ4 only if it is smaller.
    Lz4,
}
/// Local action, independent of wire-management frame bytes.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "command", rename_all = "snake_case", deny_unknown_fields)]
pub enum Action {
    /// Query current committed state and pending phase.
    Status {},
    /// Abort the live session and leave the service idle; the reply reports
    /// the actual release, never a peer-confirmed clean close.
    Disconnect {},
    /// Replace the live session, or connect again when idle, with the
    /// service's latest accepted plan; the reply reports actual readiness.
    Reconnect {},
    /// Begin proxy drain; acceptance and terminal outcome are separate.
    DrainProxy {},
    /// Submit a standalone native drain; acceptance is not actual completion.
    DrainOpenVpn {},
    /// Request a coordinated peer switch; completion is not a local file edit.
    SwitchCompression {
        /// Target independent packet compression policy.
        compression: Compression,
    },
    /// Negotiate a new swift policy on the live session. Absent values keep
    /// what is in force; the reply reports the committed epoch.
    SetSwiftPolicy {
        /// Requested values.
        policy: SwiftChange,
    },
    /// Request an exact policy from the session's authenticated active catalog.
    SwitchActivePolicy {
        /// Complete channel/weight policy; partial local mutations are not supported.
        policy: crate::active_managed::Policy,
    },
}
/// Swift policy values to change; every field is optional.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SwiftChange {
    /// Client-to-server budget in kilobits of IP bytes per second.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub forward_kbit: Option<u64>,
    /// Server-to-client budget.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reverse_kbit: Option<u64>,
    /// Ordering channels.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub channels: Option<u64>,
    /// Sources covered by one repair.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub window: Option<u64>,
    /// Proportional repairs per thousand sources.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repair_permille: Option<u64>,
    /// IP path MTU.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path_mtu: Option<u64>,
}
/// One finite, versioned local request.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    /// Must equal [`VERSION`].
    pub version: u16,
    /// Requested operation.
    pub action: Action,
}
/// Non-secret service state shared by CLI and future GUI.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Snapshot {
    /// Committed data configuration epoch.
    pub epoch: u64,
    /// Current transaction phase; this is not inferred from a pending request.
    pub phase: String,
    /// Currently committed compression.
    pub compression: Compression,
    /// Present only for the distinct managed active profile; legacy bytes stay unchanged.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub active: Option<ActiveSnapshot>,
    /// Present only for an explicit proxy profile; omitted from legacy replies.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proxy: Option<ProxySnapshot>,
    /// Present only for the explicit standalone native-drain profile.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub openvpn_drain: Option<crate::openvpn::drain::Snapshot>,
    /// Actual explicit raw packet selection and bounded logical runtime status.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub raw_packet: Option<crate::raw_packet::Snapshot>,
    /// Present only for an explicitly authenticated rolling session.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rolling: Option<crate::rolling::Snapshot>,
    /// Present only for an explicitly authenticated swift session.
    #[cfg(unix)]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub swift: Option<crate::swift::Status>,
}
/// Immutable authenticated proxy configuration and observed local lifecycle.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProxySnapshot {
    /// Exact immutable authenticated configuration digest in lowercase hexadecimal.
    pub digest: String,
    /// This frontend successfully submitted a drain command; not completion.
    pub drain_accepted: bool,
    /// Last actual runtime snapshot, absent before its first iteration.
    pub runtime: Option<ProxyStatus>,
    /// Populated only after the actual run future returns.
    pub terminal: Option<ProxyTerminal>,
    /// Actual measured profile capabilities/aggregate; absent for fixed proxy.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub measured: Option<crate::proxy_measured::LocalSnapshot>,
}
/// Observed runtime counters without credentials or application payloads.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProxyStatus {
    /// Actual runtime phase name.
    pub phase: String,
    /// Lifetime allocated proxy owners.
    pub flows: usize,
    /// Active proxy owners.
    pub active: usize,
    /// Explicitly stopped or refused owners.
    pub stopped: usize,
    /// Cleanly retired owners.
    pub retired: usize,
    /// Retained common-arbiter bytes.
    pub queued_bytes: usize,
    /// Retained common-arbiter records.
    pub queued_records: usize,
    /// Transparent native bytes admitted to the writer.
    pub transparent_admitted_bytes: u64,
    /// Transparent packets admitted to the writer.
    pub transparent_admitted_packets: u64,
    /// Peer packets actually written to the native device.
    pub native_confirmed_packets: u64,
}
/// Actual run result, distinct from a locally accepted request.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case", deny_unknown_fields)]
pub enum ProxyTerminal {
    /// Exact coordinated closure completed.
    Closed {
        /// Final runtime accounting, including stopped flows.
        report: ProxyCloseReport,
    },
    /// The runtime failed; no complete-delivery claim.
    Failed {
        /// Bounded non-secret diagnostic produced by the runtime wrapper.
        error: String,
    },
}
/// Finite completed-drain accounting; not an application-consumption guarantee.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProxyCloseReport {
    /// Local user records handed to the carrier.
    pub local_user_records: u64,
    /// Peer user records received.
    pub peer_user_records: u64,
    /// Local transparent packets admitted.
    pub local_transparent_packets: u64,
    /// Peer transparent packets written to the device.
    pub native_confirmed_packets: u64,
    /// Cleanly retired proxy flows.
    pub clean_flows: usize,
    /// Explicitly stopped or refused proxy flows.
    pub stopped_flows: usize,
    /// Original authenticated physical lanes closed.
    pub tls_lanes_closed: usize,
}
/// Actual active policy and admission state, for CLI and future GUI status.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActiveSnapshot {
    /// Complete locally committed policy.
    pub policy: crate::active_managed::Policy,
    /// Local admission gate including real Final and management flush barriers.
    pub admitting: bool,
    /// Whether the runtime still owns its authenticated lanes and device.
    pub running: bool,
    /// Canonical committed policy digest, lowercase hexadecimal.
    pub digest: String,
}
/// Structured response, including the actual observed state on rejection.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Response {
    /// Response schema version.
    pub version: u16,
    /// Action-specific success; DrainProxy means accepted submission, not terminal closure.
    pub ok: bool,
    /// Machine-readable bounded outcome code.
    pub code: String,
    /// Current observed state, when available.
    pub state: Option<Snapshot>,
}

#[cfg(test)]
mod tests;
