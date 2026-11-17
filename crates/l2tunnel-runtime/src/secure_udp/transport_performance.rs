//! Saturating observations of scheduling and credit, never protocol authority.

use super::{Bucket, SCALE};

/// Cumulative runtime counters; compare only within one session and policy epoch.
/// Historical `*_ip_bytes` names mean configured admission charges on maintained
/// TLS/QUIC. Their actual packetization, ACKs and retries require separate capture.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Performance {
    /// Complete outer driver iterations.
    pub loop_turns: u64,
    /// UDP readable branches selected, including stale readiness.
    pub udp_ready_events: u64,
    /// Maintained TLS/QUIC adapter readiness, never UDP socket readability.
    pub maintained_ready_events: u64,
    /// Complete logical records returned by maintained TLS/QUIC adapters.
    pub maintained_batch_records: u64,
    /// Maintained record batches consuming the current ingress work quota.
    pub maintained_batch_limit_hits: u64,
    /// Native readiness observations processed, including pre-drain and stale readiness.
    pub native_ready_events: u64,
    /// Timer branches actually selected.
    pub timer_events: u64,
    /// Local command branches selected, including channel closure.
    pub request_events: u64,
    /// Actual datagrams returned in UDP receive batches.
    pub udp_batch_packets: u64,
    /// UDP batches that consumed their complete configured/current quota.
    pub udp_batch_limit_hits: u64,
    /// Physical native packets read, including size rejection or post-I/O expiry.
    pub native_read_batch_packets: u64,
    /// Native read batches that consumed their complete configured quota.
    pub native_read_batch_limit_hits: u64,
    /// Physical native packet writes, including terminal post-I/O expiry/errors.
    pub native_write_batch_packets: u64,
    /// Native turns that emitted the complete configured packet-write ceiling.
    pub native_write_batch_limit_hits: u64,
    /// Calls to the wire scheduler.
    pub send_calls: u64,
    /// Send calls that used every configured emission slot.
    pub send_batch_limit_hits: u64,
    /// Charged bootstrap/joining attempts, including transient socket failures.
    pub bootstrap_packets: u64,
    /// Complete IP bytes charged for bootstrap/joining attempts.
    pub bootstrap_ip_bytes: u64,
    /// Charged authenticated management attempts, including ARQ receipts/retries.
    pub control_packets: u64,
    /// Complete IP bytes charged for management attempts.
    pub control_ip_bytes: u64,
    /// Charged Swift source/repair/retransmission attempts, excluding feedback.
    pub user_packets: u64,
    /// Complete IP bytes charged for non-feedback Swift attempts.
    pub user_ip_bytes: u64,
    /// Charged Swift feedback attempts, inside the common User record class.
    pub feedback_packets: u64,
    /// Complete IP bytes charged for Swift feedback attempts.
    pub feedback_ip_bytes: u64,
    /// Send polls with eligible Swift work blocked by full-record/reserve credit.
    pub user_credit_blocked_polls: u64,
    /// Send polls with sufficient credit but no eligible Swift work.
    pub user_not_ready_polls: u64,
    /// Time from credit-blocked observation to next send check, including scheduling.
    pub credit_wait_observed_micros: u64,
    /// Summed lateness of those checks beyond the saved credit-ready timestamp.
    pub credit_ready_late_micros: u64,
    /// Largest observed credit-ready lateness; not a scheduler percentile.
    pub credit_ready_late_max_micros: u64,
    /// Native receive steps that actually returned WouldBlock/no packet.
    pub native_read_would_block: u64,
    /// Native transmit steps that actually returned WouldBlock.
    pub native_write_would_block: u64,
    /// Native collection polls blocked by the bounded output queue.
    pub native_output_full_polls: u64,
    /// Largest observed local native output packet count.
    pub native_pending_packets_high: u64,
    /// Largest observed local native output byte count.
    pub native_pending_bytes_high: u64,
    /// Generated refill credit, excluding initial burst; includes fractional carry.
    pub refill_generated_bytes: u64,
    /// Generated credit discarded at the burst cap; includes idle intervals.
    pub refill_discarded_bytes: u64,
    /// Available complete IP-byte credit at the last actual refill/charge.
    pub bucket_tokens_bytes: u64,
}

#[derive(Default)]
pub(super) struct State {
    pub(super) counters: Performance,
    credit_wait: Option<(u64, u64)>,
}

impl State {
    pub(super) fn sent(&mut self, kind: WireKind, bytes: usize) {
        let (packets, cost) = match kind {
            WireKind::Bootstrap => (
                &mut self.counters.bootstrap_packets,
                &mut self.counters.bootstrap_ip_bytes,
            ),
            WireKind::Control => (
                &mut self.counters.control_packets,
                &mut self.counters.control_ip_bytes,
            ),
            WireKind::Data => (
                &mut self.counters.user_packets,
                &mut self.counters.user_ip_bytes,
            ),
            WireKind::Feedback => (
                &mut self.counters.feedback_packets,
                &mut self.counters.feedback_ip_bytes,
            ),
        };
        *packets = packets.saturating_add(1);
        *cost = cost.saturating_add(bytes as u64);
    }

    pub(super) fn blocked(&mut self, now: u64, ready: u64) {
        self.counters.user_credit_blocked_polls =
            self.counters.user_credit_blocked_polls.saturating_add(1);
        self.credit_wait.get_or_insert((now, ready));
    }

    pub(super) fn checked(&mut self, now: u64) {
        if let Some((since, ready)) = self.credit_wait.take() {
            wait(&mut self.counters, since, ready, now);
        }
    }

    pub(super) fn snapshot(&self, now: u64, bucket: &Bucket) -> Performance {
        let mut result = self.counters;
        if let Some((since, ready)) = self.credit_wait {
            wait(&mut result, since, ready, now);
        }
        result.refill_generated_bytes = bytes(bucket.generated);
        result.refill_discarded_bytes = bytes(bucket.discarded);
        result.bucket_tokens_bytes = bucket.allowance() as u64;
        result
    }
}

pub(super) enum WireKind {
    Bootstrap,
    Control,
    Data,
    Feedback,
}

fn bytes(scaled: u128) -> u64 {
    u64::try_from(scaled / SCALE).unwrap_or(u64::MAX)
}

fn wait(counters: &mut Performance, since: u64, ready: u64, now: u64) {
    counters.credit_wait_observed_micros = counters
        .credit_wait_observed_micros
        .saturating_add(now.saturating_sub(since));
    let late = now.saturating_sub(ready);
    counters.credit_ready_late_micros = counters.credit_ready_late_micros.saturating_add(late);
    counters.credit_ready_late_max_micros = counters.credit_ready_late_max_micros.max(late);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn open_wait_snapshots_are_nonmutating_and_do_not_double_count() {
        let bucket = Bucket::new(1_000_000, 2000);
        let mut state = State::default();
        state.blocked(100, 400);
        let first = state.snapshot(300, &bucket);
        assert_eq!(first.credit_wait_observed_micros, 200);
        assert_eq!(first.credit_ready_late_micros, 0);
        assert_eq!(state.snapshot(300, &bucket), first);
        state.checked(500);
        assert_eq!(
            state.snapshot(500, &bucket).credit_wait_observed_micros,
            400
        );
        assert_eq!(state.snapshot(500, &bucket).credit_ready_late_micros, 100);
        state.checked(600);
        assert_eq!(
            state.snapshot(600, &bucket).credit_wait_observed_micros,
            400
        );
        state.blocked(600, 650);
        state.checked(900);
        let result = state.snapshot(900, &bucket);
        assert_eq!(result.credit_wait_observed_micros, 700);
        assert_eq!(result.credit_ready_late_micros, 350);
        assert_eq!(result.credit_ready_late_max_micros, 250);
        assert_eq!(result.user_credit_blocked_polls, 2);
    }

    #[test]
    fn refill_credit_counts_fractional_carry_cap_loss_and_rate_changes() -> std::io::Result<()> {
        let mut bucket = Bucket::new(500_000, 1000);
        bucket.charge(1000)?;
        bucket.refill(1)?;
        assert_eq!(bucket.allowance(), 0);
        bucket.refill(2)?;
        assert_eq!(bucket.allowance(), 1);
        bucket.refill(3002)?;
        let state = State::default();
        let result = state.snapshot(3002, &bucket);
        assert_eq!(result.refill_generated_bytes, 1501);
        assert_eq!(result.refill_discarded_bytes, 501);
        assert_eq!(result.bucket_tokens_bytes, 1000);
        let before = (bucket.tokens, bucket.generated, bucket.discarded);
        assert!(bucket.refill(3001).is_err());
        assert_eq!(before, (bucket.tokens, bucket.generated, bucket.discarded));
        bucket.rate = 1_000_000;
        bucket.charge(1000)?;
        bucket.refill(3502)?;
        let result = state.snapshot(3502, &bucket);
        assert_eq!(result.refill_generated_bytes, 2001);
        assert_eq!(result.refill_discarded_bytes, 501);
        assert_eq!(result.bucket_tokens_bytes, 500);
        Ok(())
    }

    #[test]
    fn observation_saturation_cannot_wrap_or_change_credit() {
        let bucket = Bucket::new(1, 2000);
        let mut state = State::default();
        state.counters.credit_wait_observed_micros = u64::MAX - 1;
        state.counters.credit_ready_late_micros = u64::MAX - 1;
        state.counters.user_credit_blocked_polls = u64::MAX;
        state.blocked(1, 2);
        state.checked(100);
        let result = state.snapshot(100, &bucket);
        assert_eq!(result.credit_wait_observed_micros, u64::MAX);
        assert_eq!(result.credit_ready_late_micros, u64::MAX);
        assert_eq!(result.user_credit_blocked_polls, u64::MAX);
        assert_eq!(bucket.allowance(), 2000);
    }
}
