//! Original-receive to successful data-removal residence, distinct from Busy intervals.
use super::*;

/// Fixed logarithmic microsecond buckets; the final bucket includes u64::MAX.
pub const BUCKETS: usize = 32;
/// Inclusive bucket ceiling. Quantiles use these ceilings, never exact claims.
pub const fn upper(index: usize) -> u64 {
    if index >= BUCKETS - 1 {
        u64::MAX
    } else {
        (1u64 << index) - 1
    }
}
/// One disjoint input population; repeated polls do not add samples.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Distribution {
    /// Successfully removed inputs, or currently retained inputs for an age sample.
    pub count: u64,
    /// Exact summed injected microseconds, independent of overlapping waits.
    pub sum_us: u64,
    /// Largest actual residence/age.
    pub maximum_us: u64,
    /// Inputs with at least 100000 microseconds residence/age.
    pub at_least_100ms: u64,
    /// Fixed inclusive-ceiling bucket counts.
    pub buckets: [u64; BUCKETS],
}
impl Distribution {
    pub(in crate::rolling_records) fn record(&mut self, elapsed: u64, overflow: &mut bool) {
        let index = (u64::BITS - elapsed.leading_zeros()) as usize;
        let index = index.min(BUCKETS - 1);
        increment(&mut self.count, overflow);
        increment(&mut self.buckets[index], overflow);
        if let Some(sum) = self.sum_us.checked_add(elapsed) {
            self.sum_us = sum;
        } else {
            *overflow = true;
        }
        self.maximum_us = self.maximum_us.max(elapsed);
        if elapsed >= 100_000 {
            increment(&mut self.at_least_100ms, overflow);
        }
    }
    /// Nearest-rank p99 inclusive histogram ceiling; absent for an empty population.
    pub fn p99_upper_us(&self) -> Option<u64> {
        if self.count == 0 {
            return None;
        }
        let rank = self.count - self.count / 100;
        let mut seen = 0u64;
        for (index, count) in self.buckets.iter().enumerate() {
            seen = seen.checked_add(*count)?;
            if seen >= rank {
                return Some(upper(index));
            }
        }
        None
    }
}
/// Prepaid fixed summary. Queue age is a current snapshot, never added repeatedly.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Snapshot {
    /// All successful direct/queued data removals; not all are new decoder jobs.
    pub all: Distribution,
    /// Direct successful receive-to-admission age; bypassing FIFO need not mean zero age.
    pub immediate: Distribution,
    /// Original authenticated arrival to actual successful queued removal.
    pub queued: Distribution,
    /// Direct outcomes in Staged, Duplicate, Stale order.
    pub immediate_outcomes: [u64; 3],
    /// Queued outcomes in Staged, Duplicate, Stale order.
    pub queued_outcomes: [u64; 3],
    /// Age of each still-queued data input at the exact snapshot tick.
    pub retained_ages: Option<Distribution>,
    /// Exact age snapshot tick; terminal population is censored only when frozen here.
    pub retained_at: Option<Tick>,
}
impl Snapshot {
    pub(in crate::rolling_records) fn removed(
        &mut self,
        elapsed: u64,
        queued: bool,
        outcome: Outcome,
        overflow: &mut bool,
    ) {
        self.all.record(elapsed, overflow);
        let (population, outcomes) = if queued {
            (&mut self.queued, &mut self.queued_outcomes)
        } else {
            (&mut self.immediate, &mut self.immediate_outcomes)
        };
        population.record(elapsed, overflow);
        increment(&mut outcomes[outcome.index()], overflow);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn histogram_bounds_empty_threshold_and_overflow_are_explicit() {
        let mut value = Distribution::default();
        let mut overflow = false;
        assert_eq!(value.p99_upper_us(), None);
        for elapsed in [0, 99_999, 100_000] {
            value.record(elapsed, &mut overflow);
        }
        assert_eq!(value.count, 3);
        assert_eq!(value.sum_us, 199_999);
        assert_eq!(value.at_least_100ms, 1);
        assert_eq!(value.p99_upper_us(), Some(131_071));
        assert!(!overflow);
        value.record(u64::MAX, &mut overflow);
        assert!(overflow);
        assert_eq!(value.maximum_us, u64::MAX);
        assert_eq!(value.p99_upper_us(), Some(u64::MAX));
    }
}
