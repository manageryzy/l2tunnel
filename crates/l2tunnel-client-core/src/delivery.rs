//! Strict shared bandwidth-delay policy for versioned client configurations.
use serde::{Deserialize, Serialize};
use std::io;

/// Complete native delivery policy; serialization requires every field.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    forward_bandwidth_bps: u64,
    reverse_bandwidth_bps: u64,
    bootstrap_rtt_micros: u64,
    min_rtt_micros: u64,
    max_rtt_micros: u64,
    headroom_percent: u16,
    minimum_bytes: u64,
    max_inflight_bytes: u64,
    max_records: usize,
    metadata_limit_bytes: usize,
    sample_ttl_micros: u64,
    flush_timeout_micros: u64,
}
impl Policy {
    /// Validate and bind native packet size to both canonical directions.
    pub fn config(
        &self,
        max_packet: usize,
    ) -> io::Result<l2tunnel_runtime::managed::DeliveryConfig> {
        let direction = |target_bandwidth_bps| l2tunnel_flow_control::delivery_window::Config {
            target_bandwidth_bps,
            bootstrap_rtt_micros: self.bootstrap_rtt_micros,
            min_rtt_micros: self.min_rtt_micros,
            max_rtt_micros: self.max_rtt_micros,
            headroom_percent: self.headroom_percent,
            minimum_bytes: self.minimum_bytes,
            max_inflight_bytes: self.max_inflight_bytes,
            max_records: self.max_records,
            max_packet_bytes: max_packet as u64,
            metadata_limit_bytes: self.metadata_limit_bytes,
            sample_ttl_micros: self.sample_ttl_micros,
            flush_timeout_micros: self.flush_timeout_micros,
        };
        let result = l2tunnel_runtime::managed::DeliveryConfig {
            forward: direction(self.forward_bandwidth_bps),
            reverse: direction(self.reverse_bandwidth_bps),
        };
        for config in [result.forward, result.reverse] {
            config.validate().map_err(io::Error::other)?;
        }
        Ok(result)
    }
}
