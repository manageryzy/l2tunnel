//! Wait intervals with log2 histograms, occupancy gauges and refusal counts.
//!
//! Time is an injected monotonic microsecond tick. A wait begins only when
//! eligible work actually cannot advance; repeated refusals keep the first
//! begin time. A terminal boundary censors an open wait: it counts in the
//! censored scalars and never in the histogram.

use std::fmt;

use crate::table::{Table, TableError};

/// Histogram buckets per wait cause.
pub const BUCKETS: usize = 24;

/// Bucket `i` counts completed waits in `[2^i, 2^(i+1))` µs. Bucket 0 also
/// counts waits under 1 µs; the last bucket counts everything from 2^23 µs.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Histogram {
    counts: [u64; BUCKETS],
}

impl Histogram {
    /// Bucket index of one duration.
    pub const fn bucket(micros: u64) -> usize {
        if micros < 2 {
            return 0;
        }
        let index = (63 - micros.leading_zeros()) as usize;
        if index >= BUCKETS { BUCKETS - 1 } else { index }
    }

    /// Lower bound of bucket `index` in µs (0 for the first bucket).
    pub const fn lower_bound(index: usize) -> u64 {
        if index == 0 { 0 } else { 1 << index }
    }

    /// Record one completed duration. Returns false on counter saturation.
    pub fn record(&mut self, micros: u64) -> bool {
        let slot = &mut self.counts[Self::bucket(micros)];
        match slot.checked_add(1) {
            Some(value) => {
                *slot = value;
                true
            }
            None => false,
        }
    }

    /// Bucket counts.
    pub const fn counts(&self) -> &[u64; BUCKETS] {
        &self.counts
    }

    /// Build from counts read back from registers.
    pub const fn from_counts(counts: [u64; BUCKETS]) -> Self {
        Self { counts }
    }

    /// Upper bound in µs of the bucket holding quantile `q` (0..=1), or None
    /// when empty. The last bucket is open-ended and reports its lower bound.
    pub fn quantile(&self, q: f64) -> Option<u64> {
        let total: u64 = self.counts.iter().fold(0, |sum, n| sum.saturating_add(*n));
        if total == 0 || !(0.0..=1.0).contains(&q) {
            return None;
        }
        // Rank of the sample at quantile q, 1-based.
        let rank = ((q * total as f64).ceil() as u64).clamp(1, total);
        let mut seen = 0_u64;
        for (index, count) in self.counts.iter().enumerate() {
            seen = seen.saturating_add(*count);
            if seen >= rank {
                return Some(if index + 1 == BUCKETS {
                    Self::lower_bound(index)
                } else {
                    (1_u64 << (index + 1)) - 1
                });
            }
        }
        None
    }
}

/// One wait cause.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Wait {
    since: Option<u64>,
    episodes: u64,
    completed_episodes: u64,
    censored_episodes: u64,
    completed_us: u64,
    censored_us: u64,
    max_us: u64,
    histogram: Histogram,
    invalid: bool,
}

/// Snapshot of one wait cause at a sample time.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct WaitSnapshot {
    /// Waits begun.
    pub episodes: u64,
    /// Waits that ended on observed progress.
    pub completed_episodes: u64,
    /// Waits frozen by a terminal boundary.
    pub censored_episodes: u64,
    /// Total completed wait time.
    pub completed_us: u64,
    /// Total censored wait time.
    pub censored_us: u64,
    /// Age of the wait open now, if any.
    pub open_us: Option<u64>,
    /// Longest wait, including the one open now.
    pub max_us: u64,
    /// Completed waits by duration.
    pub histogram: Histogram,
    /// Clock regression or counter saturation was observed.
    pub invalid: bool,
}

impl Wait {
    /// Work cannot advance at `now`. Returns true when a new episode began;
    /// a repeated refusal keeps the first begin time.
    pub fn begin(&mut self, now: u64) -> bool {
        if self.since.is_some() {
            return false;
        }
        self.since = Some(now);
        self.episodes = self.add(self.episodes, 1);
        true
    }

    /// Whether a wait is open.
    pub const fn is_open(&self) -> bool {
        self.since.is_some()
    }

    /// Observed progress at `now` ends the open wait, if any, and returns its
    /// duration.
    pub fn end(&mut self, now: u64) -> Option<u64> {
        let elapsed = self.close(now)?;
        self.completed_episodes = self.add(self.completed_episodes, 1);
        self.completed_us = self.add(self.completed_us, elapsed);
        if !self.histogram.record(elapsed) {
            self.invalid = true;
        }
        Some(elapsed)
    }

    /// A terminal boundary at `now` freezes the open wait as censored.
    pub fn censor(&mut self, now: u64) -> Option<u64> {
        let elapsed = self.close(now)?;
        self.censored_episodes = self.add(self.censored_episodes, 1);
        self.censored_us = self.add(self.censored_us, elapsed);
        Some(elapsed)
    }

    /// Read the state at `now` without changing it.
    pub fn snapshot(&self, now: u64) -> WaitSnapshot {
        let open_us = self.since.map(|since| now.saturating_sub(since));
        WaitSnapshot {
            episodes: self.episodes,
            completed_episodes: self.completed_episodes,
            censored_episodes: self.censored_episodes,
            completed_us: self.completed_us,
            censored_us: self.censored_us,
            open_us,
            max_us: self.max_us.max(open_us.unwrap_or(0)),
            histogram: self.histogram,
            invalid: self.invalid || self.since.is_some_and(|since| now < since),
        }
    }

    fn close(&mut self, now: u64) -> Option<u64> {
        let since = self.since.take()?;
        let elapsed = now.checked_sub(since).unwrap_or_else(|| {
            self.invalid = true;
            0
        });
        self.max_us = self.max_us.max(elapsed);
        Some(elapsed)
    }

    fn add(&mut self, value: u64, amount: u64) -> u64 {
        value.checked_add(amount).unwrap_or_else(|| {
            self.invalid = true;
            u64::MAX
        })
    }
}

impl WaitSnapshot {
    /// Write the wait block under `base` (for example
    /// `runtime.native_ingress.lane0.user.wait.buffer_capacity`).
    pub fn write(&self, table: &mut Table, base: &dyn fmt::Display) -> Result<(), TableError> {
        table.put(format_args!("{base}.episodes"), self.episodes)?;
        table.put(
            format_args!("{base}.completed_episodes"),
            self.completed_episodes,
        )?;
        table.put(
            format_args!("{base}.censored_episodes"),
            self.censored_episodes,
        )?;
        table.put(format_args!("{base}.completed_us"), self.completed_us)?;
        table.put(format_args!("{base}.censored_us"), self.censored_us)?;
        table.put(format_args!("{base}.open_us"), self.open_us.unwrap_or(0))?;
        table.put(format_args!("{base}.max_us"), self.max_us)?;
        table.put(format_args!("{base}.invalid"), u64::from(self.invalid))?;
        for (index, count) in self.histogram.counts().iter().enumerate() {
            table.put(format_args!("{base}.hist.b{index:02}"), *count)?;
        }
        Ok(())
    }
}

/// One sampled extent; unknown capacity stays `None`, never zero.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Extent {
    /// Retained now.
    pub used: u64,
    /// Operational capacity, when known.
    pub capacity: Option<u64>,
}

/// Sampled occupancy of one owner, items and bytes independently.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Gauge {
    /// Samples taken.
    pub samples: u64,
    /// Latest items sample.
    pub items: Option<Extent>,
    /// Latest bytes sample.
    pub bytes: Option<Extent>,
    /// Highest sampled items.
    pub high_water_items: u64,
    /// Highest sampled bytes.
    pub high_water_bytes: u64,
}

impl Gauge {
    /// Record one sample. Returns false when a used value exceeds its
    /// capacity; the sample is then not recorded.
    pub fn sample(&mut self, items: Option<Extent>, bytes: Option<Extent>) -> bool {
        let fits = |extent: Option<Extent>| {
            extent.is_none_or(|value| value.capacity.is_none_or(|capacity| value.used <= capacity))
        };
        if !fits(items) || !fits(bytes) {
            return false;
        }
        self.samples = self.samples.saturating_add(1);
        if let Some(value) = items {
            self.high_water_items = self.high_water_items.max(value.used);
            self.items = Some(value);
        }
        if let Some(value) = bytes {
            self.high_water_bytes = self.high_water_bytes.max(value.used);
            self.bytes = Some(value);
        }
        true
    }

    /// Write the occupancy block under `base`. Absent extents and unknown
    /// capacities are omitted, never written as zero.
    pub fn write(&self, table: &mut Table, base: &dyn fmt::Display) -> Result<(), TableError> {
        table.put(format_args!("{base}.samples"), self.samples)?;
        if let Some(items) = self.items {
            table.put(format_args!("{base}.occupancy_items"), items.used)?;
            table.put(
                format_args!("{base}.high_water_items"),
                self.high_water_items,
            )?;
            if let Some(capacity) = items.capacity {
                table.put(format_args!("{base}.capacity_items"), capacity)?;
            }
        }
        if let Some(bytes) = self.bytes {
            table.put(format_args!("{base}.occupancy_bytes"), bytes.used)?;
            table.put(
                format_args!("{base}.high_water_bytes"),
                self.high_water_bytes,
            )?;
            if let Some(capacity) = bytes.capacity {
                table.put(format_args!("{base}.capacity_bytes"), capacity)?;
            }
        }
        Ok(())
    }
}

/// Refusal, drop and progress counts of one owner.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Refusals {
    /// Refused admissions, repeated polls included.
    pub refusals: u64,
    /// Refusals without an independent identity, so not timed.
    pub untimed_refusals: u64,
    /// Discarded items.
    pub drops: u64,
    /// Observed progress events.
    pub progress: u64,
}

impl Refusals {
    /// Write the refusal block under `base`.
    pub fn write(&self, table: &mut Table, base: &dyn fmt::Display) -> Result<(), TableError> {
        table.put(format_args!("{base}.refusals"), self.refusals)?;
        table.put(
            format_args!("{base}.untimed_refusals"),
            self.untimed_refusals,
        )?;
        table.put(format_args!("{base}.drops"), self.drops)?;
        table.put(format_args!("{base}.progress"), self.progress)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::table::Limits;

    #[test]
    fn buckets_are_log2() {
        assert_eq!(Histogram::bucket(0), 0);
        assert_eq!(Histogram::bucket(1), 0);
        assert_eq!(Histogram::bucket(2), 1);
        assert_eq!(Histogram::bucket(3), 1);
        assert_eq!(Histogram::bucket(4), 2);
        assert_eq!(Histogram::bucket((1 << 23) - 1), 22);
        assert_eq!(Histogram::bucket(1 << 23), 23);
        assert_eq!(Histogram::bucket(u64::MAX), 23);
    }

    #[test]
    fn repeated_refusal_keeps_first_time_and_censoring_skips_histogram() {
        let mut wait = Wait::default();
        assert!(wait.begin(10));
        assert!(!wait.begin(20));
        assert_eq!(wait.snapshot(30).open_us, Some(20));
        assert_eq!(wait.end(40), Some(30));
        assert_eq!(wait.end(50), None);
        assert!(wait.begin(100));
        assert_eq!(wait.censor(1_100), Some(1_000));
        let snapshot = wait.snapshot(2_000);
        assert_eq!(snapshot.episodes, 2);
        assert_eq!(snapshot.completed_episodes, 1);
        assert_eq!(snapshot.censored_episodes, 1);
        assert_eq!(snapshot.completed_us, 30);
        assert_eq!(snapshot.censored_us, 1_000);
        assert_eq!(snapshot.max_us, 1_000);
        assert_eq!(snapshot.histogram.counts()[Histogram::bucket(30)], 1);
        assert_eq!(snapshot.histogram.counts().iter().sum::<u64>(), 1);
        assert!(!snapshot.invalid);
    }

    #[test]
    fn clock_regression_is_visible_not_fatal() {
        let mut wait = Wait::default();
        wait.begin(100);
        assert!(wait.snapshot(50).invalid);
        assert_eq!(wait.end(50), Some(0));
        assert!(wait.snapshot(60).invalid);
    }

    #[test]
    fn quantiles_from_buckets() {
        let mut histogram = Histogram::default();
        for micros in [3, 3, 3, 100, 5_000] {
            histogram.record(micros);
        }
        assert_eq!(histogram.quantile(0.5), Some(3));
        assert_eq!(histogram.quantile(0.8), Some(127));
        assert_eq!(histogram.quantile(1.0), Some(8_191));
        assert_eq!(Histogram::default().quantile(0.5), None);
        let mut slow = Histogram::default();
        slow.record(u64::MAX);
        assert_eq!(slow.quantile(0.5), Some(1 << 23));
    }

    #[test]
    fn gauge_omits_unknown_values() -> Result<(), Box<dyn std::error::Error>> {
        let mut gauge = Gauge::default();
        assert!(gauge.sample(
            None,
            Some(Extent {
                used: 10,
                capacity: None
            })
        ));
        assert!(!gauge.sample(
            Some(Extent {
                used: 3,
                capacity: Some(2)
            }),
            None
        ));
        let mut table = Table::new(Limits::for_entries(64, 64))?;
        gauge.write(&mut table, &"runtime.native_output")?;
        Refusals::default().write(&mut table, &"runtime.native_output")?;
        Wait::default()
            .snapshot(0)
            .write(&mut table, &"runtime.native_output.wait.queue_full")?;
        table.seal()?;
        assert_eq!(table.get("runtime.native_output.occupancy_bytes"), Some(10));
        assert_eq!(table.get("runtime.native_output.capacity_bytes"), None);
        assert_eq!(table.get("runtime.native_output.occupancy_items"), None);
        assert_eq!(
            table.get("runtime.native_output.wait.queue_full.hist.b23"),
            Some(0)
        );
        Ok(())
    }
}
