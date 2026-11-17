//! Existing strict local control DTOs, independent of socket/OS transport.
use serde::{Deserialize, Serialize};

#[path = "schema/connection_reuse.rs"]
mod connection_reuse;
pub use connection_reuse::{CanonicalFlowKey, ConnectionReuseRequest};
#[path = "schema/proxy_common.rs"]
mod proxy_common;
pub use proxy_common::{ProxyCommonCover, ProxyCommonStatus};

/// Current strict local protocol version.
pub const VERSION: u16 = 1;
/// Explicit full Common configurations, with independently bounded catalog pages.
pub const COMMON_VERSION: u16 = 4;
/// Versions understood by the bounded local transport; backends gate actions.
pub fn supported_version(version: u16) -> bool {
    matches!(version, VERSION | COMMON_VERSION)
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
    /// Negotiate one full Common configuration through the existing service actor.
    SwitchCommonConfiguration {
        /// Exact complete anchored canonical bytes.
        configuration: crate::secure_udp::common_status::CanonicalConfiguration,
        /// Explicit nonzero service idempotency key, retained across retries.
        request_key: u64,
    },
    /// Retire one claimed owner through the selected authenticated reuse protocol.
    /// This action is additive API4; no default profile is changed.
    ReuseConnection {
        /// Exact owner and distinct canonical old/replacement keys.
        request: ConnectionReuseRequest,
        /// Exact nonzero retained service idempotency key.
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
            Action::SwitchCommonConfiguration { .. }
                | Action::CommonCatalog { .. }
                | Action::ReuseConnection { .. }
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
    /// Present only for an explicit proxy profile; omitted from legacy replies.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proxy: Option<ProxySnapshot>,
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
    /// Explicit Common proxy observation; omitted for every legacy TLS proxy.
    /// Heap-held so absent new observations do not enlarge every legacy API future.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub common: Option<Box<ProxyCommonStatus>>,
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
            && value
                .state
                .as_ref()
                .is_some_and(|state| state.proxy.is_some())
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
