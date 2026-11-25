//! Version-5 live in-session carrier / UDP cover switching DTOs (`DGUI-14`).
use serde::{Deserialize, Serialize};

/// One selectable carrier or UDP cover target reported by `carrier_switch_get`.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CarrierChoice {
    /// Canonical target identifier (`quic-like`, `media-like`, `tls-like`, `tcp`, `quic`).
    pub id: String,
    /// Human-readable label shown in CLI and GUI.
    pub label: String,
    /// Whether this target can be switched to live right now without reconnecting.
    pub available: bool,
    /// Bounded reason when `available` is false (never hidden silently).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// Live carrier-switch status and available targets returned by
/// `carrier_switch_get` and `carrier_switch`.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CarrierSwitchView {
    /// Effective outer carrier family (`udp`, `tcp`, `quic`, `raw-packet`, `openvpn-like`).
    pub current_carrier: String,
    /// Effective UDP cover (`quic-like`, `media-like`, `tls-like`), when applicable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub current_cover: Option<String>,
    /// Current active local endpoint.
    pub local: String,
    /// Current active peer endpoint.
    pub peer: String,
    /// Cumulative live carrier switches committed in this session.
    pub switches: u64,
    /// All known carrier/cover targets with live availability and reasons.
    pub choices: Vec<CarrierChoice>,
}
