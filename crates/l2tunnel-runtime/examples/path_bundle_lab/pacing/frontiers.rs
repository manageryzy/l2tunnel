//! Prefer overdue original members while reserving ordinary DATA turns for every eligible path.
use super::{Class, rotate};
use crate::endpoint::{Charge, Driver, Kind, PathId, Role, us};
use serde::Serialize;
use std::time::Duration;

pub(super) const PREFERRED_LIMIT: u8 = 3;
const SCAN_LIMIT: usize = 8;

#[derive(Serialize)]
pub(crate) struct Frontiers {
    pub(crate) natural_paid_high_water: Vec<Option<u64>>,
    pub(crate) preferred_data_payments: u64,
    pub(crate) ordinary_data_payments: u64,
    pub(crate) scan_exhaustions: u64,
    pub(crate) prepared_without_candidate: u64,
    #[serde(skip)]
    search: Vec<u64>,
    #[serde(skip)]
    pub(super) ordinary_cursor: u8,
    #[serde(skip)]
    preferred_since_ordinary: u8,
    #[serde(skip)]
    pub(super) chosen: Option<u8>,
}

impl Frontiers {
    pub(super) fn new(n: u8) -> Self {
        Self {
            natural_paid_high_water: vec![None; usize::from(n)],
            preferred_data_payments: 0,
            ordinary_data_payments: 0,
            scan_exhaustions: 0,
            prepared_without_candidate: 0,
            search: vec![0; usize::from(n)],
            ordinary_cursor: 0,
            preferred_since_ordinary: 0,
            chosen: None,
        }
    }

    pub(super) fn data_paid(&mut self, slot: u8, n: u8) {
        if self.chosen.take() == Some(slot) {
            self.preferred_data_payments += 1;
            self.preferred_since_ordinary += 1;
        } else {
            self.ordinary_data_payments += 1;
            self.preferred_since_ordinary = 0;
            self.ordinary_cursor = rotate(slot, 1, n);
        }
    }

    fn can_prefer(&self) -> bool {
        self.preferred_since_ordinary < PREFERRED_LIMIT
    }

    pub(crate) fn record_natural_payments(&mut self, slot: u8, charges: &[Charge]) {
        let h = &mut self.natural_paid_high_water[usize::from(slot)];
        for c in charges {
            if c.role == Role::Fresh && c.price == Role::Fresh && c.ordinal == slot {
                *h = (*h).max(Some(c.id));
            }
        }
    }

    fn oldest<E>(
        &mut self,
        slot: u8,
        floor: u64,
        end: u64,
        mut due: impl FnMut(u64) -> Result<Option<Duration>, E>,
    ) -> Result<Option<(u64, Duration)>, E> {
        let cursor = &mut self.search[usize::from(slot)];
        *cursor = (*cursor).max(floor);
        for _ in 0..SCAN_LIMIT {
            if *cursor == end {
                return Ok(None);
            }
            if let Some(at) = due(*cursor)? {
                return Ok(Some((*cursor, at)));
            }
            // Only positive payment, permanent natural delegation or logical
            // retirement can remove an admitted candidate from this search.
            *cursor += 1;
        }
        self.scan_exhaustions += u64::from(*cursor < end);
        Ok(None)
    }

    fn select<E>(
        &mut self,
        n: u8,
        range: std::ops::Range<u64>,
        available: impl Fn(u8) -> bool,
        mut deadline: impl FnMut(u8, u64) -> Result<Option<Duration>, E>,
        can_stage: impl Fn(u8, u64, Duration) -> bool,
    ) -> Result<Option<(u8, u64)>, E> {
        if !self.can_prefer() {
            return Ok(None);
        }
        let mut best = None;
        for offset in 0..n {
            let slot = rotate(self.ordinary_cursor, offset, n);
            if !available(slot) {
                continue;
            }
            let Some((gid, due)) =
                self.oldest(slot, range.start, range.end, |g| deadline(slot, g))?
            else {
                continue;
            };
            if can_stage(slot, gid, due) {
                // Paid high water breaks a tie, then ordinary rotation decides.
                let candidate = (
                    gid,
                    self.natural_paid_high_water[usize::from(slot)],
                    offset,
                    slot,
                );
                best = Some(best.map_or(candidate, |old| candidate.min(old)));
            }
        }
        Ok(best.map(|(g, _, _, slot)| (slot, g)))
    }
}

fn contains_original(head: &Kind, slot: u8, gid: u64) -> bool {
    matches!(head, Kind::Data(_, charges) if charges.iter().any(|c| c.role == Role::Fresh && c.ordinal == slot && c.id == gid))
}

impl Driver {
    pub(super) fn preferred_original(
        &mut self,
        now: u64,
    ) -> crate::endpoint::Result<Option<(u8, u64)>> {
        let Some(s) = self.pacing.as_mut() else {
            return Ok(None);
        };
        let Some(f) = s.frontiers.as_mut() else {
            return Ok(None);
        };
        let Some(floor) = self.tx.oldest_unconfirmed() else {
            return Ok(None);
        };
        let end = self.tx.next_generation();
        f.select(
            self.cfg.n,
            floor..end,
            |slot| {
                let i = usize::from(slot);
                !s.blocked[i] && self.physical.get(i).is_none_or(|p| p.can_send())
            },
            |slot, g| Ok(self.tx.unpaid_natural_deadline(PathId::new(slot)?, g)?),
            |slot, g, due| {
                self.wire[usize::from(slot)]
                    .as_ref()
                    .map_or(due <= us(now), |p| contains_original(&p.kind, slot, g))
            },
        )
    }

    pub(super) fn stage_preferred_original(
        &mut self,
        slot: u8,
        gid: u64,
        now: u64,
        pass: super::Pass,
    ) -> crate::endpoint::Result<bool> {
        let ready = self.stage_class(Class::Data, slot, now, pass)?;
        let Some(f) = self.pacing.as_mut().and_then(|s| s.frontiers.as_mut()) else {
            return Err("missing original frontier policy".into());
        };
        if ready
            && self.wire[usize::from(slot)]
                .as_ref()
                .is_some_and(|p| contains_original(&p.kind, slot, gid))
        {
            f.chosen = Some(slot);
            return Ok(true);
        }
        // A frozen repair-only head still belongs to the ordinary rotation.
        // Neither a speculative prepare nor a socket refusal advances a turn.
        f.prepared_without_candidate += u64::from(ready);
        Ok(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::endpoint::pacing::Scheduler;

    #[test]
    fn fewer_originals_per_datagram_on_one_path_do_not_leave_its_paid_groups_far_behind() {
        let mut f = Frontiers::new(3);
        let mut paid = [0u64; 3];
        let per_packet = [4, 1, 2];
        for _ in 0..120 {
            let chosen = f
                .select(
                    3,
                    0..1000,
                    |_| true,
                    |p, g| Ok::<_, ()>((g >= paid[usize::from(p)]).then_some(Duration::ZERO)),
                    |_, _, _| true,
                )
                .unwrap();
            f.chosen = chosen.map(|(p, _)| p);
            let p = f.chosen.unwrap_or(f.ordinary_cursor);
            let i = usize::from(p);
            paid[i] += per_packet[i];
            f.natural_paid_high_water[i] = Some(paid[i] - 1);
            f.data_paid(p, 3);
        }
        // A pure physical-packet round robin ends at [160, 40, 80].
        assert!(paid.iter().max().unwrap() - paid.iter().min().unwrap() <= 8);
        assert_eq!(f.ordinary_data_payments, 30);
    }

    #[test]
    fn eligible_ordinary_paths_get_one_in_four_successful_data_turns_even_with_a_fixed_laggard() {
        let mut s = Scheduler::new(100_000_000, 1500, 12, 1)
            .unwrap()
            .with_original_frontiers(true);
        let mut ordinary = Vec::new();
        for turn in 0..96 {
            let now = (turn + 1) * 1000;
            let f = s.frontiers.as_mut().unwrap();
            let slot = if f.can_prefer() {
                f.chosen = Some(0);
                0
            } else {
                ordinary.push(f.ordinary_cursor);
                f.ordinary_cursor
            };
            s.paid(Class::Data, slot, 500, now);
            s.paid(Class::Ack, 11, 60, now + 100);
        }
        assert_eq!(ordinary, (0..12).chain(0..12).collect::<Vec<_>>());
        let f = s.frontiers.as_ref().unwrap();
        assert_eq!(
            (f.preferred_data_payments, f.ordinary_data_payments),
            (72, 24)
        );
    }

    #[test]
    fn blocked_and_unpaid_reservations_leave_the_ordinary_cursor_unchanged() {
        let mut s = Scheduler::new(100_000_000, 1500, 12, 1)
            .unwrap()
            .with_original_frontiers(true);
        s.paid(Class::Data, 1, 1500, 0);
        s.frontiers.as_mut().unwrap().chosen = Some(5);
        s.reserve(Class::Data, 5, 1, 122);
        s.block(5, 122);
        let f = s.frontiers.as_ref().unwrap();
        assert_eq!(f.ordinary_cursor, 2);
        assert_eq!((f.chosen, f.preferred_data_payments), (None, 0));
        s.writable(5);
        s.frontiers.as_mut().unwrap().chosen = Some(5);
        s.paid(Class::Data, 5, 1500, 122);
        assert_eq!(s.path(Class::Data, 0), 2);
        assert_eq!(s.frontiers.as_ref().unwrap().preferred_data_payments, 1);
    }

    #[test]
    fn bounded_search_resumes_past_retired_or_delegated_members_and_stops_at_the_oldest_debt() {
        let mut f = Frontiers::new(3);
        let due = Duration::from_micros(500);
        let candidate = |id| Ok::<_, ()>((id == 27).then_some(due));
        for _ in 0..3 {
            assert_eq!(f.oldest(1, 0, 100, candidate), Ok(None));
        }
        assert_eq!(f.oldest(1, 0, 100, candidate), Ok(Some((27, due))));
        f.natural_paid_high_water[1] = Some(90);
        assert_eq!(f.oldest(1, 0, 100, candidate), Ok(Some((27, due))));
        assert_eq!((f.scan_exhaustions, f.search[1]), (3, 27));
        assert_eq!(f.oldest(1, 80, 80, candidate), Ok(None));
    }
}
