//! Current Common native-delivery observations.
use serde::{Deserialize, Serialize};

/// Actual native reservation/flush/device accounting, never a TCP advertised window.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeFlight {
    /// Actual original-native accounting in the named domain.
    pub admitted_bytes: u64,
    /// Actual original-native accounting in the named domain.
    pub admitted_records: u64,
    /// Actual original-native accounting in the named domain.
    pub delivered_bytes: u64,
    /// Actual original-native accounting in the named domain.
    pub delivered_records: u64,
    /// Actual original-native accounting in the named domain.
    pub flushed_bytes: u64,
    /// Actual original-native accounting in the named domain.
    pub flushed_records: u64,
    /// Actual original-native accounting in the named domain.
    pub flushed_total_bytes: u64,
    /// Actual original-native accounting in the named domain.
    pub flushed_total_records: u64,
    /// Actual original-native accounting in the named domain.
    pub outstanding_bytes: u64,
    /// Actual original-native accounting in the named domain.
    pub outstanding_records: u64,
    /// Actual original-native accounting in the named domain.
    pub target_bytes: u64,
    /// Latest genuine flush-to-feedback duration, absent before first observation.
    pub raw_rtt_micros: Option<u64>,
    /// EWMA from that same sample; may be retained after its TTL expires.
    pub smoothed_rtt_micros: Option<u64>,
    /// Original authenticated feedback timestamp relative to runtime startup.
    pub sample_at_micros: Option<u64>,
    /// Whether the retained sample is currently within policy TTL.
    pub sample_fresh: bool,
    /// Metadata still waiting for remote delivery or observed original send.
    pub retained_records: usize,
}
impl From<l2tunnel_flow_control::delivery_window::Status> for NativeFlight {
    fn from(s: l2tunnel_flow_control::delivery_window::Status) -> Self {
        Self {
            admitted_bytes: s.admitted.bytes,
            admitted_records: s.admitted.records,
            delivered_bytes: s.delivered.bytes,
            delivered_records: s.delivered.records,
            flushed_bytes: s.flushed.bytes,
            flushed_records: s.flushed.records,
            flushed_total_bytes: s.flushed_total.bytes,
            flushed_total_records: s.flushed_total.records,
            outstanding_bytes: s.outstanding.bytes,
            outstanding_records: s.outstanding.records,
            target_bytes: s.target_bytes,
            raw_rtt_micros: s.sample.map(|v| v.raw_micros),
            smoothed_rtt_micros: s.sample.map(|v| v.smoothed_micros),
            sample_at_micros: s.sample.map(|v| v.feedback_at.0),
            sample_fresh: s.sample_fresh,
            retained_records: s.retained_records,
        }
    }
}
