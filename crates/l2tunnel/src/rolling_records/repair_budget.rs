//! Credit accepted solicited retries against whole future proactive repairs.
use super::*;

/// Per-sender counters over actual physical retry charges and prospective
/// regular-repair charges. Half-byte units retain odd-sized half credits.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RepairBudgetStatus {
    /// Named request identities independent of ordinary cumulative feedback.
    pub named_requests: scheduler::RequestCounts,
    /// Admitted originals beyond authenticated cumulative confirmation, including queued originals.
    pub unconfirmed_sources: u32,
    /// Fresh originals waiting for their first encoder service turn.
    pub queued_fresh: usize,
    /// Maximum simultaneous queued originals since sender construction.
    pub peak_queued_fresh: usize,
    /// Maximum fresh originals held ahead of encoder service.
    pub fresh_queue_limit: usize,
    /// Remaining credit available for this direction.
    pub balance_half_bytes: u64,
    /// Bound of 32 selected path MTUs in half-byte units.
    pub cap_half_bytes: u64,
    /// Credit earned before saturation, in half-bytes.
    pub earned_half_bytes: u64,
    /// Excess credit dropped when the bounded balance was full.
    pub capped_half_bytes: u64,
    /// Residual credit expired at complete confirmation.
    pub expired_half_bytes: u64,
    /// Complete prospective regular repair opportunities.
    pub regular_opportunities: u64,
    /// Complete wire bytes of all prospective regular repairs.
    pub opportunity_wire_bytes: u64,
    /// Number of whole regular repairs displaced by accepted retries.
    pub displaced_repairs: u64,
    /// Complete wire bytes of the displaced opportunities.
    pub displaced_wire_bytes: u64,
    /// Accepted requested retries credited at half their wire cost.
    pub half_weight_retries: u64,
    /// Accepted requested retries credited at their full wire cost.
    pub full_weight_retries: u64,
    /// Complete accepted physical cost of solicited original retransmissions.
    pub requested_retry_wire_bytes: u64,
    /// Whole silent-oldest retries accepted by the carrier.
    pub quiet_probes: u64,
    /// Complete accepted physical cost of silent-oldest retries.
    pub quiet_probe_wire_bytes: u64,
    /// Complete accepted physical cost of emitted regular equations.
    pub regular_wire_bytes: u64,
    /// Complete accepted physical cost of policy copies beyond the first source ordinal.
    pub copy_wire_bytes: u64,
    /// Whether the most recent solicited retry sampled elevated queue pressure.
    pub full_credit: bool,
}

pub(super) struct Budget {
    status: RepairBudgetStatus,
    // Segment tree over ring slots. A query returns the largest actual source
    // extent over exactly this repair's support, even across ring wrap. It
    // takes logarithmic metadata visits and reads no retained payload bytes.
    maxima: Vec<u16>,
}

impl Budget {
    pub(super) fn heap_bytes(window: usize) -> usize {
        // The validated FEC window is in 1..=8192.
        2 * window.next_power_of_two() * size_of::<u16>()
    }

    pub(super) fn new(window: usize) -> Result<Self, Error> {
        let count = Self::heap_bytes(window) / size_of::<u16>();
        let mut maxima = Vec::new();
        maxima
            .try_reserve_exact(count)
            .map_err(|_| Error::Allocation)?;
        maxima.resize(count, 0);
        Ok(Self {
            status: RepairBudgetStatus::default(),
            maxima,
        })
    }

    pub(super) fn capacity_bytes(&self) -> usize {
        self.maxima.capacity() * size_of::<u16>()
    }

    pub(super) fn configured(&self) -> bool {
        self.status.cap_half_bytes != 0
    }

    pub(super) fn record_source(
        &mut self,
        id: rolling::SourceId,
        bytes: usize,
    ) -> Result<(), Error> {
        let leaves = self.maxima.len() / 2;
        let mut index = leaves + (id.0 as usize % leaves);
        let extent = u16::try_from(bytes.checked_add(2).ok_or(Error::Arithmetic)?)
            .map_err(|_| Error::Arithmetic)?;
        self.maxima[index] = extent;
        while index > 1 {
            index /= 2;
            let maximum = self.maxima[index * 2].max(self.maxima[index * 2 + 1]);
            if maximum == self.maxima[index] {
                break;
            }
            self.maxima[index] = maximum;
        }
        Ok(())
    }

    fn maximum(&self, mut lo: usize, mut hi: usize) -> u16 {
        let leaves = self.maxima.len() / 2;
        lo += leaves;
        hi += leaves;
        let mut maximum = 0;
        while lo < hi {
            if lo % 2 == 1 {
                maximum = maximum.max(self.maxima[lo]);
                lo += 1;
            }
            if hi % 2 == 1 {
                hi -= 1;
                maximum = maximum.max(self.maxima[hi]);
            }
            lo /= 2;
            hi /= 2;
        }
        maximum
    }

    fn extent(&self, support: rolling::Support) -> usize {
        let leaves = self.maxima.len() / 2;
        let lo = support.start as usize % leaves;
        let hi = lo + (support.end - support.start) as usize;
        let maximum = self.maximum(lo, hi.min(leaves));
        usize::from(if hi > leaves {
            maximum.max(self.maximum(0, hi - leaves))
        } else {
            maximum
        })
    }

    pub(super) fn accepted_retry(&mut self, wire_bytes: usize, full_credit: bool) {
        let status = &mut self.status;
        status.requested_retry_wire_bytes = status
            .requested_retry_wire_bytes
            .saturating_add(wire_bytes as u64);
        status.full_credit = full_credit;
        let amount = if full_credit {
            status.full_weight_retries = status.full_weight_retries.saturating_add(1);
            (wire_bytes as u64).saturating_mul(2)
        } else {
            status.half_weight_retries = status.half_weight_retries.saturating_add(1);
            wire_bytes as u64
        };
        let increase = amount.min(status.cap_half_bytes - status.balance_half_bytes);
        status.earned_half_bytes = status.earned_half_bytes.saturating_add(amount);
        status.capped_half_bytes = status.capped_half_bytes.saturating_add(amount - increase);
        status.balance_half_bytes += increase;
    }

    pub(super) fn accepted(&mut self, pending: PreparedOutput) {
        let bytes = pending.wire_bytes as u64;
        match (pending.id, pending.source_copy) {
            (OutputId::Data(scheduler::OutputId::Source(_)), Some(copy)) if copy.ordinal() > 1 => {
                self.status.copy_wire_bytes = self.status.copy_wire_bytes.saturating_add(bytes);
            }
            (OutputId::Data(scheduler::OutputId::Source(_)), None) => {
                if let Some(full) = pending.retry_full_credit {
                    self.accepted_retry(pending.wire_bytes, full);
                } else {
                    self.status.quiet_probes = self.status.quiet_probes.saturating_add(1);
                    self.status.quiet_probe_wire_bytes =
                        self.status.quiet_probe_wire_bytes.saturating_add(bytes);
                }
            }
            (OutputId::Data(scheduler::OutputId::Repair(_)), _) => {
                // Targeted senders use an original for silence; every emitted equation is regular.
                self.status.regular_wire_bytes =
                    self.status.regular_wire_bytes.saturating_add(bytes);
            }
            _ => {}
        }
    }

    fn regular(&mut self, wire_bytes: u64) -> bool {
        let status = &mut self.status;
        status.regular_opportunities = status.regular_opportunities.saturating_add(1);
        status.opportunity_wire_bytes = status.opportunity_wire_bytes.saturating_add(wire_bytes);
        if wire_bytes > status.balance_half_bytes / 2 {
            return false;
        }
        status.balance_half_bytes -= 2 * wire_bytes;
        status.displaced_repairs = status.displaced_repairs.saturating_add(1);
        status.displaced_wire_bytes = status.displaced_wire_bytes.saturating_add(wire_bytes);
        true
    }

    fn expire(&mut self) {
        self.status.expired_half_bytes = self
            .status
            .expired_half_bytes
            .saturating_add(self.status.balance_half_bytes);
        self.status.balance_half_bytes = 0;
    }
}

impl<P: RecoveryPolicy> Endpoint<P> {
    /// Configure the bounded retry credit before the first native admission.
    /// The MTU is the actual local directional carrier path budget.
    pub fn enable_queue_aware_repair_budget(&mut self, mtu: u16) -> Result<(), Error> {
        let budget = self.repair_budget.as_mut().ok_or(Error::Configuration)?;
        if mtu == 0 || budget.configured() || self.statistics != Statistics::default() {
            return Err(Error::Configuration);
        }
        self.packing
            .enable_fragment_tail_packing()
            .map_err(Error::Sender)?;
        budget.status.cap_half_bytes = 2 * 32 * u64::from(mtu);
        Ok(())
    }

    /// Sample the age of this sender's oldest local unadmitted MUX frame.
    pub fn observe_mux_wait_micros(&mut self, age: u64) {
        if self.repair_budget.is_some() {
            P::observe_mux_wait(&mut self.sender, age);
        }
    }

    /// Current credit and wire-cost accounting for the selected direction.
    pub fn repair_budget_status(&self) -> Option<RepairBudgetStatus> {
        self.repair_budget.as_ref().map(|b| {
            let state = P::send_state(&self.sender);
            RepairBudgetStatus {
                named_requests: P::request_counts(&self.sender),
                unconfirmed_sources: state.next_source - state.encoder.confirmed_prefix,
                queued_fresh: state.queued_fresh,
                peak_queued_fresh: state.peak_queued_fresh,
                fresh_queue_limit: state.fresh_queue_limit,
                ..b.status
            }
        })
    }

    pub(super) fn expire_confirmed_credit(&mut self) {
        if let Some(budget) = &mut self.repair_budget
            && budget.status.balance_half_bytes != 0
        {
            let state = P::send_state(&self.sender);
            if state.encoder.confirmed_prefix == state.next_source {
                budget.expire();
            }
        }
    }

    pub(super) fn step_sender(
        &mut self,
        now: Tick,
        work: rolling::WorkBudget,
    ) -> Result<rolling::WorkUsed, Error> {
        let Some(budget) = &mut self.repair_budget else {
            return P::send_step(&mut self.sender, rolling_tick(now), work).map_err(Error::Rolling);
        };
        let compact = self.compact_feedback_overhead.is_some();
        let overhead = self.overhead;
        let framing = self.framing;
        P::send_step_filtered(&mut self.sender, rolling_tick(now), work, |id, support| {
            let extent = budget.extent(support);
            let length = if compact {
                rolling::wire::compact::repair_len(id, support.end, extent)?
            } else {
                P::HEADER_BYTES
                    .checked_add(extent)
                    .ok_or(rolling::Error::Length)?
            };
            let (_, wire_bytes) =
                wire_charge(framing, length, overhead).map_err(|_| rolling::Error::Length)?;
            Ok(budget.regular(wire_bytes as u64))
        })
        .map_err(Error::Rolling)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quoted_extent_matches_every_window_across_ring_wrap() -> Result<(), Error> {
        let mut budget = Budget::new(29)?;
        let mut lengths = Vec::new();
        for id in 0u32..130 {
            let size = 3 + ((id as usize * 23) % 53);
            lengths.push(size);
            budget.record_source(rolling::SourceId(id), size)?;
            for count in 1..=29u32.min(id + 1) {
                let support = rolling::Support {
                    start: id + 1 - count,
                    end: id + 1,
                    tail: false,
                    seed: 0,
                };
                let expected = lengths[support.start as usize..support.end as usize]
                    .iter()
                    .max()
                    .ok_or(Error::Identity)?
                    + 2;
                assert_eq!(budget.extent(support), expected);
            }
        }
        Ok(())
    }

    #[test]
    fn bounded_half_byte_credit_spends_only_whole_repairs() -> Result<(), Error> {
        let mut budget = Budget::new(8)?;
        budget.status.cap_half_bytes = 100;
        budget.accepted_retry(11, false);
        budget.accepted_retry(11, true);
        budget.accepted_retry(11, true);
        budget.accepted_retry(11, false);
        assert_eq!(budget.status.balance_half_bytes, 66);
        assert!(!budget.regular(34));
        assert!(budget.regular(33));
        budget.accepted_retry(101, false);
        budget.expire();
        assert_eq!(budget.status.expired_half_bytes, 100);
        assert_eq!(budget.status.capped_half_bytes, 1);
        assert_eq!(budget.status.earned_half_bytes, 167);
        Ok(())
    }
}
