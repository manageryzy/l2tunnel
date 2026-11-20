//! The estimator, conservative fast ACK and nodelay=1 timeout increment follow
//! `ikcp_update_ack`, `ikcp_parse_fastack` and `ikcp_flush` in the repository's
//! pinned skywind3000/kcp C source (8004f7eba5d1bf33f0691eef5f887f2cd3140cb5).
//! The Compact profile uses its own authenticated receipt format and attempt
//! serials. Timers start at complete physical payment, preserve fractional
//! milliseconds and subtract reported receiver delay. Existing Compact feedback
//! scheduling, admission and congestion policy remain separately specified.
use super::{Duration, History, Meta, RecoveryError, seconds_duration};

/// Negotiated KCP-like recovery parameters, represented by four big-endian u16s.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KcpLikeConfig {
    /// Distinct fresh feedback reports qualifying a missing attempt for fast retry.
    pub fast_resend: u16,
    /// Timing granularity in milliseconds, from 1 to 5000 inclusive.
    pub interval_ms: u16,
    /// Smallest estimated or backed-off physical retransmission timeout.
    pub minimum_rto_ms: u16,
    /// Largest estimated or backed-off physical retransmission timeout.
    pub maximum_rto_ms: u16,
}

impl KcpLikeConfig {
    /// Validate the complete descriptor before construction or wire use.
    pub fn validate(self) -> Result<(), RecoveryError> {
        if self.fast_resend == 0
            || !(1..=5000).contains(&self.interval_ms)
            || self.minimum_rto_ms == 0
            || self.maximum_rto_ms < self.minimum_rto_ms
        {
            return Err(RecoveryError::InvalidConfig);
        }
        Ok(())
    }

    /// Encode exactly eight canonical descriptor bytes.
    pub fn encode(self) -> Result<[u8; 8], RecoveryError> {
        self.validate()?;
        let mut bytes = [0; 8];
        for (chunk, field) in bytes.chunks_exact_mut(2).zip([
            self.fast_resend,
            self.interval_ms,
            self.minimum_rto_ms,
            self.maximum_rto_ms,
        ]) {
            chunk.copy_from_slice(&field.to_be_bytes());
        }
        Ok(bytes)
    }

    /// Parse and validate exactly eight canonical descriptor bytes.
    pub fn decode(bytes: [u8; 8]) -> Result<Self, RecoveryError> {
        let [a, b, c, d, e, f, g, h] = bytes;
        let config = Self {
            fast_resend: u16::from_be_bytes([a, b]),
            interval_ms: u16::from_be_bytes([c, d]),
            minimum_rto_ms: u16::from_be_bytes([e, f]),
            maximum_rto_ms: u16::from_be_bytes([g, h]),
        };
        config.validate()?;
        Ok(config)
    }

    pub(super) fn estimated_rto(
        self,
        srtt: Option<f64>,
        variance: f64,
    ) -> Result<Duration, RecoveryError> {
        let seconds = srtt.map_or(0.2, |rtt| {
            rtt + (4.0 * variance).max(f64::from(self.interval_ms) / 1000.0)
        });
        seconds_duration(seconds.clamp(
            f64::from(self.minimum_rto_ms) / 1000.0,
            f64::from(self.maximum_rto_ms) / 1000.0,
        ))
    }

    pub(super) fn timeout_backoff(self, previous: Duration) -> Duration {
        previous
            .saturating_add(previous / 2)
            .min(Duration::from_millis(u64::from(self.maximum_rto_ms)))
    }
}

impl Meta {
    pub(super) fn observe_fast_ack(
        &mut self,
        config: KcpLikeConfig,
        higher: History,
        arrival: Duration,
    ) {
        // A rotated bitmap can include a higher source received long before a
        // retry. Require the echoed payment itself to prove a later attempt.
        if higher.serial > self.serial
            && let (Some(current), Some(reported)) = (self.accepted, higher.accepted)
            && current <= reported
            && reported <= arrival
        {
            self.fast_reports = self.fast_reports.saturating_add(1);
            self.fast |= self.fast_reports >= config.fast_resend;
        }
    }
}
