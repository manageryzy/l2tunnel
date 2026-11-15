//! Existing strict local control DTOs, independent of socket/OS transport.
use serde::{Deserialize, Serialize};

/// Current strict local protocol version.
pub const VERSION: u16 = 1;
/// Explicit new-profile observations/actions; never an automatic v1 downgrade.
pub const SECURE_UDP_VERSION: u16 = 2;
/// Explicit complete-configuration backend; never an automatic v1/v2 downgrade.
pub const TRANSACTION_VERSION: u16 = 3;
/// Explicit full Common configurations, with independently bounded catalog pages.
pub const COMMON_VERSION: u16 = 4;
/// Versions understood by the bounded local transport; backends gate actions.
pub fn supported_version(version: u16) -> bool {
    matches!(
        version,
        VERSION | SECURE_UDP_VERSION | TRANSACTION_VERSION | COMMON_VERSION
    )
}
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
    /// Negotiate one complete canonical value from the selected transaction catalog.
    SwitchSwiftConfiguration {
        /// Exact checked canonical bytes, without a partial-policy conversion.
        configuration: crate::secure_udp::transaction_status::CanonicalConfiguration,
    },
    /// Negotiate one full Common configuration through the existing service actor.
    SwitchCommonConfiguration {
        /// Exact complete anchored canonical bytes.
        configuration: crate::secure_udp::common_status::CanonicalConfiguration,
        /// Explicit nonzero service idempotency key, retained across retries.
        request_key: u64,
    },
    /// Read one bounded page without consuming a service operation key.
    CommonCatalog {
        /// Exact service generation, preventing cross-reconnect page mixing.
        generation: u64,
        /// Exact authenticated complete catalog root.
        catalog: [u8; 32],
        /// First canonical catalog index.
        offset: u16,
        /// Number of members, from one through four.
        limit: u16,
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
#[serde(try_from = "RequestWire")]
pub struct Request {
    /// Must equal [`VERSION`].
    pub version: u16,
    /// Requested operation.
    pub action: Action,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RequestWire {
    version: u16,
    action: Action,
}
impl TryFrom<RequestWire> for Request {
    type Error = &'static str;
    fn try_from(value: RequestWire) -> Result<Self, Self::Error> {
        if matches!(
            value.action,
            Action::SwitchCommonConfiguration { .. } | Action::CommonCatalog { .. }
        ) && value.version != COMMON_VERSION
        {
            return Err("Common actions require explicit API version4");
        }
        Ok(Self {
            version: value.version,
            action: value.action,
        })
    }
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
    /// Present only in explicit version2 replies for the common secure UDP profile.
    #[cfg(unix)]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secure_udp: Option<crate::secure_udp::status::Status>,
    /// Present only for explicit version3 complete-configuration observations.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transaction: Option<crate::secure_udp::transaction_status::Status>,
    /// Present only for explicit APIv4 complete mixed-profile observations.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_common"
    )]
    pub common: Option<crate::secure_udp::common_status::Status>,
}
fn deserialize_common<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<crate::secure_udp::common_status::Status>, D::Error> {
    // A present Common field is a real observation. Reject null, so older
    // version parsers do not silently accept a formerly unknown field.
    crate::secure_udp::common_status::Status::deserialize(deserializer).map(Some)
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
#[serde(try_from = "ResponseWire")]
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

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ResponseWire {
    version: u16,
    ok: bool,
    code: String,
    state: Option<Snapshot>,
}
impl TryFrom<ResponseWire> for Response {
    type Error = &'static str;
    fn try_from(value: ResponseWire) -> Result<Self, Self::Error> {
        if value.version != COMMON_VERSION
            && value
                .state
                .as_ref()
                .is_some_and(|state| state.common.is_some())
        {
            return Err("Common observations require explicit API version4");
        }
        if value.version == COMMON_VERSION
            && value.state.as_ref().is_some_and(|state| {
                let old = state.active.is_some()
                    || state.proxy.is_some()
                    || state.openvpn_drain.is_some()
                    || state.raw_packet.is_some()
                    || state.rolling.is_some()
                    || state.transaction.is_some();
                #[cfg(unix)]
                {
                    old || state.swift.is_some() || state.secure_udp.is_some()
                }
                #[cfg(not(unix))]
                {
                    old
                }
            })
        {
            return Err("APIv4 cannot project a legacy backend");
        }
        Ok(Self {
            version: value.version,
            ok: value.ok,
            code: value.code,
            state: value.state,
        })
    }
}

#[cfg(test)]
mod tests;
