//! Runtime performance observations shared by embedding frontends.
//! Counters retain their runtime units and do not imply throughput guarantees.
use l2tunnel_runtime::secure_udp::transport;
use serde::Serialize;

/// Saturating runtime counters and current bucket gauge; all fields retain runtime units.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize)]
pub struct Driver {
    /// Same named observation and units as transport::Performance.
    pub loop_turns: u64,
    /// Same named observation and units as transport::Performance.
    pub udp_ready_events: u64,
    /// Same named observation and units as transport::Performance.
    pub native_ready_events: u64,
    /// Same named observation and units as transport::Performance.
    pub timer_events: u64,
    /// Same named observation and units as transport::Performance.
    pub request_events: u64,
    /// Same named observation and units as transport::Performance.
    pub udp_batch_packets: u64,
    /// Same named observation and units as transport::Performance.
    pub udp_batch_limit_hits: u64,
    /// Original UDP batches returned early for runnable targeted receive work.
    pub udp_rolling_pressure_yields: u64,
    /// Same named observation and units as transport::Performance.
    pub native_read_batch_packets: u64,
    /// Same named observation and units as transport::Performance.
    pub native_read_batch_limit_hits: u64,
    /// Same named observation and units as transport::Performance.
    pub native_write_batch_packets: u64,
    /// Same named observation and units as transport::Performance.
    pub native_write_batch_limit_hits: u64,
    /// Same named observation and units as transport::Performance.
    pub send_calls: u64,
    /// Same named observation and units as transport::Performance.
    pub send_batch_limit_hits: u64,
    /// Same named observation and units as transport::Performance.
    pub bootstrap_packets: u64,
    /// Same named observation and units as transport::Performance.
    pub bootstrap_ip_bytes: u64,
    /// Same named observation and units as transport::Performance.
    pub control_packets: u64,
    /// Same named observation and units as transport::Performance.
    pub control_ip_bytes: u64,
    /// Same named observation and units as transport::Performance.
    pub user_packets: u64,
    /// Same named observation and units as transport::Performance.
    pub user_ip_bytes: u64,
    /// Same named observation and units as transport::Performance.
    pub feedback_packets: u64,
    /// Same named observation and units as transport::Performance.
    pub feedback_ip_bytes: u64,
    /// Same named observation and units as transport::Performance.
    pub user_credit_blocked_polls: u64,
    /// Same named observation and units as transport::Performance.
    pub user_not_ready_polls: u64,
    /// Same named observation and units as transport::Performance.
    pub credit_wait_observed_micros: u64,
    /// Same named observation and units as transport::Performance.
    pub credit_ready_late_micros: u64,
    /// Same named observation and units as transport::Performance.
    pub credit_ready_late_max_micros: u64,
    /// Same named observation and units as transport::Performance.
    pub native_read_would_block: u64,
    /// Same named observation and units as transport::Performance.
    pub native_write_would_block: u64,
    /// Same named observation and units as transport::Performance.
    pub native_output_full_polls: u64,
    /// Same named observation and units as transport::Performance.
    pub native_pending_packets_high: u64,
    /// Same named observation and units as transport::Performance.
    pub native_pending_bytes_high: u64,
    /// Same named observation and units as transport::Performance.
    pub refill_generated_bytes: u64,
    /// Same named observation and units as transport::Performance.
    pub refill_discarded_bytes: u64,
    /// Same named observation and units as transport::Performance.
    pub bucket_tokens_bytes: u64,
    /// Actual maintained TLS/QUIC readiness, separate from raw UDP readiness.
    pub maintained_ready_events: u64,
    /// Complete records observed at the maintained boundary.
    pub maintained_batch_records: u64,
    /// Actual maintained receive work-bound hits.
    pub maintained_batch_limit_hits: u64,
}
impl From<transport::Performance> for Driver {
    fn from(value: transport::Performance) -> Self {
        Self {
            loop_turns: value.loop_turns,
            udp_ready_events: value.udp_ready_events,
            native_ready_events: value.native_ready_events,
            timer_events: value.timer_events,
            request_events: value.request_events,
            udp_batch_packets: value.udp_batch_packets,
            udp_batch_limit_hits: value.udp_batch_limit_hits,
            udp_rolling_pressure_yields: value.udp_rolling_pressure_yields,
            native_read_batch_packets: value.native_read_batch_packets,
            native_read_batch_limit_hits: value.native_read_batch_limit_hits,
            native_write_batch_packets: value.native_write_batch_packets,
            native_write_batch_limit_hits: value.native_write_batch_limit_hits,
            send_calls: value.send_calls,
            send_batch_limit_hits: value.send_batch_limit_hits,
            bootstrap_packets: value.bootstrap_packets,
            bootstrap_ip_bytes: value.bootstrap_ip_bytes,
            control_packets: value.control_packets,
            control_ip_bytes: value.control_ip_bytes,
            user_packets: value.user_packets,
            user_ip_bytes: value.user_ip_bytes,
            feedback_packets: value.feedback_packets,
            feedback_ip_bytes: value.feedback_ip_bytes,
            user_credit_blocked_polls: value.user_credit_blocked_polls,
            user_not_ready_polls: value.user_not_ready_polls,
            credit_wait_observed_micros: value.credit_wait_observed_micros,
            credit_ready_late_micros: value.credit_ready_late_micros,
            credit_ready_late_max_micros: value.credit_ready_late_max_micros,
            native_read_would_block: value.native_read_would_block,
            native_write_would_block: value.native_write_would_block,
            native_output_full_polls: value.native_output_full_polls,
            native_pending_packets_high: value.native_pending_packets_high,
            native_pending_bytes_high: value.native_pending_bytes_high,
            refill_generated_bytes: value.refill_generated_bytes,
            refill_discarded_bytes: value.refill_discarded_bytes,
            bucket_tokens_bytes: value.bucket_tokens_bytes,
            maintained_ready_events: value.maintained_ready_events,
            maintained_batch_records: value.maintained_batch_records,
            maintained_batch_limit_hits: value.maintained_batch_limit_hits,
        }
    }
}
