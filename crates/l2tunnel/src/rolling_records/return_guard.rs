//! Bounded local limit on sheddable sender extras relative to delivered peer traffic.
//!
//! Uses only injected ticks and fixed storage. First copies of local sources,
//! feedback, requested retries and control are counted but never shed. The
//! guard engages only while first copies fit the budget, so a bulk sender is
//! never limited. See `docs/modules/delivery-policy.md`.
use super::{ReturnGuard, Tick};

const BUCKETS: usize = 8;
const BUCKET_MICROS: u64 = 125_000;
/// Below this window budget the return traffic is a few packets and shedding
/// would only remove startup redundancy, so the guard stays disengaged.
pub(super) const MIN_BUDGET_BYTES: u64 = 16 * 1024;

/// Class of one accepted local output.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Class {
    /// First physical copy of a local source.
    First,
    /// Output the guard never sheds: feedback, requested retries, quiet probes.
    Required,
    /// Sheddable redundancy: source copies after the first, regular repairs.
    Extra,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct Bucket {
    epoch: u64,
    delivered: u64,
    first: u64,
    required: u64,
    extra: u64,
}

/// Observable requested/effective guard state and cumulative shed counts.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ReturnGuardStatus {
    /// Requested configuration of this sending direction.
    pub requested: ReturnGuard,
    /// Effective ratio after default resolution; `None` measures only.
    pub effective_per_mille: Option<u16>,
    /// Whether the most recent window had first copies within the budget.
    pub engaged: bool,
    /// Native bytes committed from the peer within the window.
    pub window_delivered_bytes: u64,
    /// Accepted wire bytes of first source copies within the window.
    pub window_first_bytes: u64,
    /// Accepted wire bytes of never-shed outputs within the window.
    pub window_required_bytes: u64,
    /// Accepted wire bytes of sheddable extras within the window.
    pub window_extra_bytes: u64,
    /// Sources admitted with their extra copies removed.
    pub shed_copy_sources: u64,
    /// Estimated wire bytes of the removed copies.
    pub shed_copy_bytes: u64,
    /// Regular repair opportunities displaced by the guard.
    pub shed_repairs: u64,
    /// Estimated wire bytes of the displaced repairs.
    pub shed_repair_bytes: u64,
}

pub(super) struct Guard {
    buckets: [Bucket; BUCKETS],
    latest: u64,
    status: ReturnGuardStatus,
}

impl Guard {
    pub(super) fn new(requested: ReturnGuard, effective_per_mille: Option<u16>) -> Self {
        Self {
            buckets: [Bucket::default(); BUCKETS],
            latest: 0,
            status: ReturnGuardStatus {
                requested,
                effective_per_mille,
                ..ReturnGuardStatus::default()
            },
        }
    }
    fn bucket(&mut self, now: Tick) -> Option<&mut Bucket> {
        let epoch = now.0 / BUCKET_MICROS;
        if epoch.saturating_add(BUCKETS as u64) <= self.latest {
            // Older than the window: count nothing rather than corrupt it.
            return None;
        }
        self.latest = self.latest.max(epoch);
        let bucket = &mut self.buckets[(epoch % BUCKETS as u64) as usize];
        if bucket.epoch != epoch {
            *bucket = Bucket {
                epoch,
                ..Bucket::default()
            };
        }
        Some(bucket)
    }
    fn totals(&self) -> Bucket {
        let mut total = Bucket::default();
        for b in &self.buckets {
            if b.epoch <= self.latest && b.epoch + BUCKETS as u64 > self.latest {
                total.delivered = total.delivered.saturating_add(b.delivered);
                total.first = total.first.saturating_add(b.first);
                total.required = total.required.saturating_add(b.required);
                total.extra = total.extra.saturating_add(b.extra);
            }
        }
        total
    }
    pub(super) fn delivered(&mut self, now: Tick, bytes: usize) {
        if let Some(b) = self.bucket(now) {
            b.delivered = b.delivered.saturating_add(bytes as u64);
        }
    }
    pub(super) fn sent(&mut self, now: Tick, class: Class, bytes: usize) {
        if let Some(b) = self.bucket(now) {
            let field = match class {
                Class::First => &mut b.first,
                Class::Required => &mut b.required,
                Class::Extra => &mut b.extra,
            };
            *field = field.saturating_add(bytes as u64);
        }
    }
    /// Whether an extra of `bytes` must be shed now.
    fn refuse(&mut self, now: Tick, bytes: u64) -> bool {
        let Some(per_mille) = self.status.effective_per_mille else {
            return false;
        };
        self.bucket(now);
        let t = self.totals();
        let budget = t.delivered.saturating_mul(u64::from(per_mille)) / 1000;
        if budget < MIN_BUDGET_BYTES || t.first > budget {
            return false;
        }
        t.first
            .saturating_add(t.required)
            .saturating_add(t.extra)
            .saturating_add(bytes)
            > budget
    }
    /// Decide whether a source's extra copies, estimated at `bytes`, are removed.
    pub(super) fn shed_copies(&mut self, now: Tick, bytes: usize) -> bool {
        let shed = self.refuse(now, bytes as u64);
        if shed {
            self.status.shed_copy_sources = self.status.shed_copy_sources.saturating_add(1);
            self.status.shed_copy_bytes = self.status.shed_copy_bytes.saturating_add(bytes as u64);
        }
        shed
    }
    /// Decide whether a regular repair estimated at `bytes` is displaced.
    pub(super) fn shed_repair(&mut self, now: Tick, bytes: u64) -> bool {
        let shed = self.refuse(now, bytes);
        if shed {
            self.status.shed_repairs = self.status.shed_repairs.saturating_add(1);
            self.status.shed_repair_bytes = self.status.shed_repair_bytes.saturating_add(bytes);
        }
        shed
    }
    pub(super) fn enabled(&self) -> bool {
        self.status.effective_per_mille.is_some()
    }
    pub(super) fn status(&self) -> ReturnGuardStatus {
        let t = self.totals();
        let engaged = self.status.effective_per_mille.is_some_and(|per_mille| {
            let budget = t.delivered.saturating_mul(u64::from(per_mille)) / 1000;
            budget >= MIN_BUDGET_BYTES && t.first <= budget
        });
        ReturnGuardStatus {
            engaged,
            window_delivered_bytes: t.delivered,
            window_first_bytes: t.first,
            window_required_bytes: t.required,
            window_extra_bytes: t.extra,
            ..self.status
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn guard() -> Guard {
        Guard::new(ReturnGuard::on(100), Some(100))
    }
    const S: u64 = 1_000_000;

    #[test]
    fn off_guard_never_sheds_but_still_measures() {
        let mut g = Guard::new(ReturnGuard::OFF, None);
        g.delivered(Tick(0), 1000);
        g.sent(Tick(0), Class::Extra, 10_000);
        assert!(!g.shed_copies(Tick(0), 10_000));
        assert!(!g.shed_repair(Tick(0), 10_000));
        let s = g.status();
        assert!(!s.engaged);
        assert_eq!(
            (s.window_delivered_bytes, s.window_extra_bytes),
            (1000, 10_000)
        );
        assert_eq!(s.shed_copy_sources + s.shed_repairs, 0);
    }

    #[test]
    fn return_path_sheds_extras_beyond_the_ratio() {
        let mut g = guard();
        g.delivered(Tick(0), 1_000_000); // budget 100_000
        g.sent(Tick(0), Class::First, 30_000);
        g.sent(Tick(0), Class::Required, 20_000);
        g.sent(Tick(0), Class::Extra, 40_000);
        assert!(!g.shed_copies(Tick(1), 10_000)); // exactly at the budget
        assert!(g.shed_copies(Tick(1), 10_001));
        assert!(g.shed_repair(Tick(1), 10_001));
        let s = g.status();
        assert!(s.engaged);
        assert_eq!((s.shed_copy_sources, s.shed_copy_bytes), (1, 10_001));
        assert_eq!((s.shed_repairs, s.shed_repair_bytes), (1, 10_001));
    }

    #[test]
    fn bulk_sender_is_never_engaged() {
        let mut g = guard();
        g.delivered(Tick(0), 1_000_000); // budget 100_000
        g.sent(Tick(0), Class::First, 100_001);
        assert!(!g.shed_repair(Tick(0), 1_000_000));
        assert!(!g.shed_copies(Tick(0), 1_000_000));
        assert!(!g.status().engaged);
    }

    #[test]
    fn startup_below_the_budget_floor_does_not_shed() {
        let mut g = guard();
        assert!(!g.shed_copies(Tick(0), 1));
        g.delivered(Tick(0), 163_830); // budget 16_383, one byte under the floor
        assert!(!g.shed_copies(Tick(0), 100_000));
        assert!(!g.status().engaged);
        g.delivered(Tick(0), 10); // budget 16_384
        assert!(g.status().engaged);
        assert!(!g.shed_copies(Tick(0), 16_384));
        assert!(g.shed_copies(Tick(0), 16_385));
    }

    #[test]
    fn window_forgets_old_buckets() {
        let mut g = guard();
        g.delivered(Tick(0), 1_000_000);
        g.sent(Tick(0), Class::First, 1_000);
        g.sent(Tick(0), Class::Extra, 99_000);
        assert!(g.shed_repair(Tick(0), 1));
        // One full window later the old delivery and extras no longer count.
        g.delivered(Tick(S), 200_000);
        g.sent(Tick(S), Class::First, 100);
        let s = g.status();
        assert_eq!(
            (s.window_delivered_bytes, s.window_extra_bytes),
            (200_000, 0)
        );
        assert!(!g.shed_repair(Tick(S), 19_900));
        assert!(g.shed_repair(Tick(S), 19_901));
    }

    #[test]
    fn late_observations_older_than_the_window_are_ignored() {
        let mut g = guard();
        g.delivered(Tick(10 * S), 1_000);
        g.delivered(Tick(0), u64::MAX as usize);
        assert_eq!(g.status().window_delivered_bytes, 1_000);
    }

    #[test]
    fn counters_saturate_instead_of_wrapping() {
        let mut g = guard();
        g.delivered(Tick(0), usize::MAX);
        g.delivered(Tick(0), usize::MAX);
        g.sent(Tick(0), Class::Required, usize::MAX);
        g.sent(Tick(0), Class::Required, usize::MAX);
        assert_eq!(g.status().window_delivered_bytes, u64::MAX);
        assert!(g.shed_repair(Tick(0), 1));
    }
}
