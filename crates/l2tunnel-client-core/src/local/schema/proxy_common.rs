//! Bounded Common facts inside the explicitly selected proxy observation.
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

/// Exact selected inner appearance; no dissector/interoperability claim.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum ProxyCommonCover {
    /// Requested QUIC-shaped inner appearance.
    #[serde(rename = "quic-like")]
    QuicLike,
    /// Requested RTP/media-shaped inner appearance.
    #[serde(rename = "media-like")]
    MediaLike,
}
/// Actual typed Proxy backend facts, never a native-Common API4 authority.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProxyCommonStatus {
    /// Complete requested fixed proxy session policy.
    pub requested_proxy_digest: [u8; 32],
    /// Exact policy installed by the actual authenticated proxy owner.
    pub effective_proxy_digest: [u8; 32],
    /// Requested Common configuration bound to the explicit proxy policy.
    pub requested_configuration: [u8; 32],
    /// Configuration observed from actual completed Noise/member authentication.
    pub effective_configuration: [u8; 32],
    /// Requested authenticated carrier binding; no socket or key escapes.
    pub requested_carrier: [u8; 32],
    /// Actual completed authentication carrier binding.
    pub effective_carrier: [u8; 32],
    /// Explicit requested inner cover.
    pub requested_cover: ProxyCommonCover,
    /// Absent until actual Common installation.
    pub effective_cover: Option<ProxyCommonCover>,
    /// Original local endpoint of the retained authenticated socket.
    pub local_addr: SocketAddr,
    /// Original peer endpoint of the retained authenticated socket.
    pub peer_addr: SocketAddr,
    /// Actual Common installation has been observed.
    pub installed: bool,
    /// Last actual Common runtime running observation.
    pub running: bool,
    /// Actual Common epoch, absent before its first report.
    pub epoch: Option<u64>,
    /// Actual outstanding authenticated liveness challenge.
    pub outstanding_ping: Option<u64>,
    /// Unrenewed original challenge deadline in the Driver clock.
    pub original_ping_deadline_micros: Option<u64>,
    /// Last fresh authenticated record observation.
    pub last_verified_micros: Option<u64>,
    /// Last correctly matching fresh authenticated Pong.
    pub last_pong_micros: Option<u64>,
    /// Actual installed switching capability, false for immutable v1.
    pub hot_switch: bool,
    /// Actual selected retirement capability, false for legacy v1.
    pub graceful_close: bool,
    /// Native advertised-window qualification, distinct from proxy credit.
    pub exact_tcp_rwnd_control: bool,
    /// Owned children are still releasing under the original cleanup cap.
    pub releasing: bool,
    /// Actual child joins have completed; dropping a Run is not this proof.
    pub released: bool,
}
