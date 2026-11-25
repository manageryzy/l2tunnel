//! Bounded automatic outage and lease-expiry recovery for fixed-peer sessions (`CL-38`).
//!
//! When enabled, recoverable session terminations (`lease_expired`, `peer_timeout`,
//! transient `io_error`) schedule a bounded exponential-backoff fresh-authentication
//! reconnect (fresh Noise DH handshake + Ed25519 member proof on a new generation).
//! Old-session nonces and packets are never replayed. Any explicit user command
//! (`disconnect`, `connect`, `reconnect`, `stop`) immediately cancels pending recovery.

use std::time::Duration;
use tokio::time::Instant;

use crate::local::{RecoveryStatus, Role};

use super::{Observation, Terminal};

/// Hard upper bound on automatic recovery retries per outage episode.
pub const MAX_RECOVERY_ATTEMPTS: u32 = 20;

/// Bounded automatic recovery policy for a service instance (`CL-38`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AutoRecoveryPolicy {
    /// Whether automatic fresh-authentication recovery is active.
    pub enabled: bool,
    /// Maximum consecutive recovery attempts before transitioning to `recovery_exhausted`.
    pub max_attempts: u32,
    /// Initial backoff delay before the first retry after a peer timeout or I/O outage.
    pub initial_backoff: Duration,
    /// Upper cap on exponential backoff between retries.
    pub max_backoff: Duration,
}

impl Default for AutoRecoveryPolicy {
    fn default() -> Self {
        Self {
            enabled: false,
            max_attempts: 6,
            initial_backoff: Duration::from_secs(1),
            max_backoff: Duration::from_secs(30),
        }
    }
}

impl AutoRecoveryPolicy {
    /// Standard daemon policy: bounded automatic recovery enabled (`6` attempts, `1s..=30s`).
    #[must_use]
    pub fn default_enabled() -> Self {
        Self {
            enabled: true,
            ..Self::default()
        }
    }

    fn effective_max_attempts(self) -> u32 {
        self.max_attempts.min(MAX_RECOVERY_ATTEMPTS)
    }
}

/// Extract a distinct, bounded snake_case termination reason from a stopped session.
pub(super) fn classify_stop_reason(
    observation: Option<&Observation>,
    terminal: Terminal,
) -> &'static str {
    if let Some(Observation::SecureUdpCommon(frame)) = observation
        && let Some(runtime) = &frame.runtime
        && let Some(reason) = runtime.terminal
    {
        use l2tunnel_runtime::secure_udp::transport::StopReason;
        return match reason {
            StopReason::Cancelled => "cancelled",
            StopReason::ProxyRetired => "proxy_retired",
            StopReason::LeaseExpired => "lease_expired",
            StopReason::PeerTimeout => "peer_timeout",
            StopReason::NativeStall => "native_stall",
            StopReason::PolicyTimeout => "policy_timeout",
            StopReason::Protocol => "protocol",
            StopReason::CounterExhausted => "counter_exhausted",
            StopReason::Io(_) => "io_error",
        };
    }
    match terminal {
        Terminal::Aborted => "cancelled",
        Terminal::Closed => "closed",
        Terminal::Failed(failure) => match failure.kind {
            std::io::ErrorKind::TimedOut => "timed_out",
            std::io::ErrorKind::ConnectionRefused => "connection_refused",
            std::io::ErrorKind::PermissionDenied => "permission_denied",
            std::io::ErrorKind::NotFound => "not_found",
            std::io::ErrorKind::InvalidInput | std::io::ErrorKind::InvalidData => "protocol",
            _ => "io_error",
        },
    }
}

/// Only lease expiry, peer liveness timeout, and transient I/O errors are automatically
/// recoverable; explicit cancellation and authentication/protocol mismatches never retry.
pub(super) fn is_recoverable(reason: &str) -> bool {
    matches!(
        reason,
        "lease_expired" | "counter_exhausted" | "peer_timeout" | "io_error"
    )
}

#[derive(Clone, Debug)]
struct PendingRecovery {
    attempt: u32,
    retry_at: Instant,
    reason: &'static str,
    role: Role,
}

/// Service-owned bounded recovery scheduler.
#[derive(Debug, Default)]
pub(super) struct RecoveryTracker {
    policy: AutoRecoveryPolicy,
    pending: Option<PendingRecovery>,
    total_recoveries: u64,
    last_reason: Option<&'static str>,
    last_attempt: u32,
    exhausted: bool,
}

impl RecoveryTracker {
    pub(super) fn set_policy(&mut self, policy: AutoRecoveryPolicy) {
        self.policy = policy;
        if !policy.enabled {
            self.pending = None;
            self.exhausted = false;
        }
    }

    /// Cancel any scheduled retry (called on explicit user Disconnect/Connect/Reconnect/Stop).
    pub(super) fn cancel(&mut self) {
        self.pending = None;
        self.exhausted = false;
        self.last_attempt = 0;
    }

    /// Schedule the first recovery attempt after an unexpected session stop.
    /// Returns `true` if a retry was scheduled.
    pub(super) fn schedule_on_stop(&mut self, reason: &'static str, role: Role) -> bool {
        if !self.policy.enabled || !is_recoverable(reason) || matches!(role, Role::Unconfigured) {
            self.pending = None;
            return false;
        }
        let max_attempts = self.policy.effective_max_attempts();
        if max_attempts == 0 {
            self.pending = None;
            return false;
        }
        let delay = self.backoff(1, reason, role);
        let now = Instant::now();
        self.exhausted = false;
        self.last_reason = Some(reason);
        self.last_attempt = 1;
        self.pending = Some(PendingRecovery {
            attempt: 1,
            retry_at: now + delay,
            reason,
            role,
        });
        true
    }

    /// Record a failed recovery attempt and either schedule the next backoff or exhaust.
    /// Returns `true` if exhausted.
    pub(super) fn record_attempt_failure(&mut self, reason: &'static str, role: Role) -> bool {
        let max_attempts = self.policy.effective_max_attempts();
        let next_attempt = self.last_attempt.saturating_add(1);
        if !self.policy.enabled || next_attempt > max_attempts {
            self.pending = None;
            self.exhausted = true;
            self.last_reason = Some(reason);
            return true;
        }
        let delay = self.backoff(next_attempt, reason, role);
        let now = Instant::now();
        self.last_attempt = next_attempt;
        self.last_reason = Some(reason);
        self.pending = Some(PendingRecovery {
            attempt: next_attempt,
            retry_at: now + delay,
            reason,
            role,
        });
        false
    }

    /// Record a successful automatic fresh-authentication recovery.
    pub(super) fn mark_recovered(&mut self) {
        self.pending = None;
        self.exhausted = false;
        self.last_attempt = 0;
        self.total_recoveries = self.total_recoveries.saturating_add(1);
    }

    /// Next scheduled retry timestamp, attempt number, reason, and role, if any.
    pub(super) fn next_retry(&self) -> Option<(Instant, u32, &'static str, Role)> {
        self.pending
            .as_ref()
            .map(|p| (p.retry_at, p.attempt, p.reason, p.role))
    }

    /// Clear `pending` just before executing the due attempt (retaining `last_attempt`/`last_reason`).
    pub(super) fn take_due(&mut self) -> Option<(u32, &'static str, Role)> {
        let pending = self.pending.take()?;
        self.last_attempt = pending.attempt;
        self.last_reason = Some(pending.reason);
        Some((pending.attempt, pending.reason, pending.role))
    }

    /// Project observable recovery status for `ServiceStatus`.
    pub(super) fn snapshot(&self, now: Instant) -> Option<RecoveryStatus> {
        let max_attempts = self.policy.effective_max_attempts();
        if let Some(pending) = &self.pending {
            let remaining = pending.retry_at.saturating_duration_since(now);
            let next_retry_ms = Some(u64::try_from(remaining.as_millis()).unwrap_or(u64::MAX));
            return Some(RecoveryStatus {
                active: true,
                attempt: pending.attempt,
                max_attempts,
                next_retry_ms,
                reason: pending.reason.to_owned(),
                total_recoveries: self.total_recoveries,
            });
        }
        if self.exhausted || self.total_recoveries > 0 {
            return Some(RecoveryStatus {
                active: false,
                attempt: self.last_attempt,
                max_attempts,
                next_retry_ms: None,
                reason: self.last_reason.unwrap_or("recovered").to_owned(),
                total_recoveries: self.total_recoveries,
            });
        }
        None
    }

    fn backoff(&self, attempt: u32, reason: &str, role: Role) -> Duration {
        // Server re-listens first (50 ms socket settle); client waits slightly longer
        // (200 ms) on lease/counter rotation so the server listener is already bound
        // before the client sends its fresh Noise M1.
        if attempt <= 1 {
            if role == Role::Server {
                return Duration::from_millis(50);
            }
            if matches!(reason, "lease_expired" | "counter_exhausted") {
                return Duration::from_millis(200);
            }
        }
        let shift = attempt.saturating_sub(1).min(16);
        let factor = 1_u32.checked_shl(shift).unwrap_or(u32::MAX);
        self.policy
            .initial_backoff
            .saturating_mul(factor)
            .min(self.policy.max_backoff)
    }
}
