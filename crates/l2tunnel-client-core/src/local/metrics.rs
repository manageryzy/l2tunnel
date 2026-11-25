//! Version-5 `metrics`: one snapshot of cumulative counters. Frontends poll it,
//! derive rates from successive samples and keep their own bounded history.
//! Carrier lanes, MUX channels and inner flows stay separate; a measurement the
//! running profile does not report is listed in `unreported`, never invented.
use serde::{Deserialize, Serialize};

/// Most lanes reported in one reply.
pub const LANE_LIMIT: usize = 8;
/// Most channels reported in one reply.
pub const CHANNEL_LIMIT: usize = 32;
/// Most inner flows reported in one reply.
pub const FLOW_LIMIT: usize = 64;

/// Aggregate outer-wire counters of the running session.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WireCounters {
    /// Attempted complete-wire packets.
    pub sent_packets: u64,
    /// Attempted complete IP-wire bytes.
    pub sent_bytes: u64,
    /// Datagrams the local socket accepted (not proof of delivery).
    pub accepted_packets: u64,
    /// IP bytes the local socket accepted.
    pub accepted_bytes: u64,
    /// Transient send drops.
    pub send_drops: u64,
    /// Complete received datagrams examined.
    pub received_packets: u64,
    /// Transient receive errors.
    pub receive_errors: u64,
    /// Rejected authentication/parser/scope inputs.
    pub rejected_packets: u64,
    /// Replay rejections.
    pub replay_rejections: u64,
}

/// Tunnel device (TUN/TAP) counters of the running session.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceCounters {
    /// Complete packets read from the device.
    pub read_packets: u64,
    /// Completed device writes.
    pub written_packets: u64,
    /// Oversized device input.
    pub oversize: u64,
    /// Input refused under output pressure.
    pub backpressure_drops: u64,
    /// Packets waiting to be written now.
    pub pending_packets: u64,
    /// Bytes waiting to be written now.
    pub pending_bytes: u64,
}

/// One authenticated carrier lane (a physical connection).
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LaneMetrics {
    /// Lane index.
    pub lane: u16,
    /// Effective carrier of this lane.
    pub carrier: String,
    /// Local endpoint.
    pub local: String,
    /// Remote endpoint.
    pub remote: String,
    /// Per-lane counters, when the profile reports them.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wire: Option<WireCounters>,
}

/// One MUX channel (an ordering/admission domain).
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChannelMetrics {
    /// Channel index.
    pub channel: u16,
    /// Bytes queued now.
    pub queued_bytes: u64,
    /// Admitted records.
    pub admitted: u64,
    /// Refused or dropped records.
    pub dropped: u64,
}

/// One classified inner flow (a user connection).
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FlowMetrics {
    /// Flow identifier.
    pub flow: u64,
    /// Bounded description (for example the 5-tuple or SOCKS5 target).
    pub label: String,
    /// Bytes sent toward the peer.
    pub sent_bytes: u64,
    /// Bytes received from the peer.
    pub received_bytes: u64,
    /// Flow state.
    pub state: String,
}

/// One metrics sample.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Metrics {
    /// Session generation the counters belong to; a change restarts every series.
    pub generation: u64,
    /// Service-monotonic sampling time (milliseconds since the service started).
    pub sampled_ms: u64,
    /// Effective carrier.
    pub carrier: String,
    /// Runtime time of the observation, when reported.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime_micros: Option<u64>,
    /// Aggregate outer-wire counters.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wire: Option<WireCounters>,
    /// Tunnel device counters.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device: Option<DeviceCounters>,
    /// Selected outgoing IP-wire rate (bytes per second), when paced.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub selected_send_rate: Option<u64>,
    /// Peer's selected incoming IP-wire rate (bytes per second).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub selected_receive_rate: Option<u64>,
    /// Outgoing MUX width.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub send_channels: Option<u16>,
    /// Incoming MUX width.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receive_channels: Option<u16>,
    /// Smoothed round-trip time, when measured.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rtt_micros: Option<u64>,
    /// Carrier lanes, at most [`LANE_LIMIT`].
    pub lanes: Vec<LaneMetrics>,
    /// MUX channels, at most [`CHANNEL_LIMIT`].
    pub channels: Vec<ChannelMetrics>,
    /// Inner flows, at most [`FLOW_LIMIT`]; the busiest first.
    pub flows: Vec<FlowMetrics>,
    /// Measurements the running profile does not report (bounded names).
    pub unreported: Vec<String>,
}
