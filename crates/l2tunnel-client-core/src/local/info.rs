//! Version-5 service identity and capability discovery. Frontends show a
//! feature as unavailable with the service's reason instead of hiding it.
use serde::{Deserialize, Serialize};

/// Most capabilities reported in one reply.
pub const CAPABILITY_LIMIT: usize = 16;
/// Longest capability reason.
pub const REASON_LIMIT: usize = 160;

/// Which side of the tunnel the service runs.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    /// Connects to a peer (`l2tunnel-linux`, `l2tunnel-windows`).
    Client,
    /// Accepts members (`l2tunneld`).
    Server,
    /// No retained plan yet.
    Unconfigured,
}

/// A frontend feature area.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Feature {
    /// Connect, reconnect, disconnect and cancel.
    Lifecycle,
    /// Authenticated configuration catalog and hot switching.
    Catalog,
    /// Cumulative counters (`metrics`).
    Metrics,
    /// Meter CSR registers (`meters_read`, `meters_catalog`).
    Meters,
    /// Service-owned TUN/TAP devices.
    Devices,
    /// Service-owned routes.
    Routes,
    /// SOCKS5 entry over the TCP-proxy profile.
    Socks5,
    /// Service-owned profile store.
    Profiles,
    /// Member keys and trusted peers.
    Keys,
    /// Server sessions: list, kick, revoke.
    Sessions,
    /// `service_stop` ends the service process.
    Stop,
    /// Speed and ping tests through the tunnel.
    Tests,
}

/// Whether one feature is served, and why not.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Capability {
    /// Feature area.
    pub feature: Feature,
    /// The service serves it now.
    pub available: bool,
    /// Bounded reason when unavailable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}
impl Capability {
    /// An available feature.
    pub fn available(feature: Feature) -> Self {
        Self {
            feature,
            available: true,
            reason: None,
        }
    }
    /// An unavailable feature with a bounded reason.
    pub fn unavailable(feature: Feature, reason: &str) -> Self {
        Self {
            feature,
            available: false,
            reason: Some(reason.chars().take(REASON_LIMIT).collect()),
        }
    }
}

/// Service identity for the top bar and the Management page.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceInfo {
    /// Service software version.
    pub version: String,
    /// Service role.
    pub role: Role,
    /// Highest local API version served.
    pub api: u16,
    /// Milliseconds since this service instance started.
    pub uptime_ms: u64,
    /// One entry per feature, at most [`CAPABILITY_LIMIT`].
    pub capabilities: Vec<Capability>,
}
impl ServiceInfo {
    /// Capability of one feature; absent means an older service without it.
    pub fn capability(&self, feature: Feature) -> Option<&Capability> {
        self.capabilities
            .iter()
            .find(|capability| capability.feature == feature)
    }
}
