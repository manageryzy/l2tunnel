//! Share one egress opportunity with each completed input operation.

use super::{Reservation, Scheduler, Stats};
use crate::endpoint::{Driver, PathId, Result, us};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Opportunity {
    Idle,
    NoEligibleWork,
    Reserved(u8),
    Select,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Outcome {
    Idle,
    NoEligibleWork,
    ReservedPaid,
    SelectedPaid,
    SelectedReserved,
    SelectedWithoutHandoff,
}

impl Stats {
    fn checkpoint(&mut self, outcome: Outcome) {
        match outcome {
            Outcome::Idle => (),
            Outcome::NoEligibleWork => self.checkpoint_no_eligible_work += 1,
            Outcome::ReservedPaid => self.reserved_payments_at_input_checkpoint += 1,
            Outcome::SelectedPaid => {
                self.checkpoint_selections_attempted += 1;
                self.checkpoint_selections_paid += 1;
            }
            Outcome::SelectedReserved => {
                self.checkpoint_selections_attempted += 1;
                self.checkpoint_selections_reserved += 1;
            }
            Outcome::SelectedWithoutHandoff => {
                self.checkpoint_selections_attempted += 1;
                self.checkpoint_selections_without_handoff += 1;
            }
        }
    }
}

// Only a completed input can create a new selection. A wake without input can
// still serve the exact reservation that caused it. The two actions are exclusive.
fn opportunity(
    held: Option<Reservation>,
    now: u64,
    actual_input: bool,
    eligible: impl FnOnce() -> Result<bool>,
) -> Result<Opportunity> {
    Ok(match held {
        Some(r) if now >= r.ready => Opportunity::Reserved(r.slot),
        Some(_) => Opportunity::Idle,
        None if !actual_input => Opportunity::Idle,
        None if eligible()? => Opportunity::Select,
        None => Opportunity::NoEligibleWork,
    })
}

impl Driver {
    // No group/window walk, ciphertext construction or mutations here. A
    // tombstone at a fresh cursor may hide eligible work until ordinary egress.
    fn has_checkpoint_work(&self, scheduler: &Scheduler, now: u64) -> Result<bool> {
        let empty_writable =
            |slot: u8| !scheduler.blocked(slot) && self.wire[usize::from(slot)].is_none();
        if self.requests.has_ready(empty_writable) {
            return Ok(true);
        }
        let control_due = self.ack.due(now).is_some_and(|d| d <= now)
            || (self.requests.is_empty() && self.gaps.wake().is_some_and(|d| d <= now));
        for slot in 0..self.cfg.n {
            if scheduler.blocked(slot) {
                continue;
            }
            let i = usize::from(slot);
            if self.wire[i].is_some() || control_due {
                return Ok(true);
            }
            if let Some(state) = &self.path_ready
                && state.path_wake(slot, now)?.is_some_and(|t| t <= now)
            {
                return Ok(true);
            }
            if let Some(ledger) = self.physical.get(i) {
                // Taking an expired flight can release physical send credit.
                if ledger.next_deadline().is_some_and(|d| d <= now) {
                    return Ok(true);
                }
                if !ledger.can_send() {
                    continue;
                }
            }
            if self.recovery.has_queued_repair(slot)
                || self.tx.has_due_head(PathId::new(slot)?, us(now))?
            {
                return Ok(true);
            }
        }
        Ok(false)
    }

    pub(crate) fn pay_at_input_checkpoint(&mut self, actual_input: bool) -> Result<()> {
        let Some(s) = &self.pacing else {
            return Ok(());
        };
        let now = self.origin.elapsed().as_micros() as u64;
        let outcome = match opportunity(s.waiting, now, actual_input, || {
            self.has_checkpoint_work(s, now)
        })? {
            Opportunity::Idle => Outcome::Idle,
            Opportunity::NoEligibleWork => Outcome::NoEligibleWork,
            Opportunity::Reserved(slot) => {
                if self.send_pending(slot)? {
                    Outcome::ReservedPaid
                } else {
                    Outcome::Idle
                }
            }
            Opportunity::Select => {
                if self.paced_step(now, super::Pass::Input)? {
                    Outcome::SelectedPaid
                } else if self.pacing.as_ref().is_some_and(|s| s.waiting.is_some()) {
                    Outcome::SelectedReserved
                } else {
                    Outcome::SelectedWithoutHandoff
                }
            }
        };
        self.pacing
            .as_mut()
            .ok_or("missing egress budget")?
            .stats
            .checkpoint(outcome);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::endpoint::pacing::Class;
    use std::cell::Cell;

    #[test]
    fn reservations_and_idle_wakes_skip_work_selection_even_after_would_block() -> Result<()> {
        let mut s = Scheduler::new(100_000_000, 1500, 6, 2)?;
        s.paid(Class::Data, 0, 1500, 0);
        s.reserve(Class::Ack, 3, 1, 122);
        let probes = Cell::new(0);
        let eligible = || {
            probes.set(probes.get() + 1);
            Ok(true)
        };
        assert_eq!(
            opportunity(s.waiting, 121, true, eligible)?,
            Opportunity::Idle
        );
        assert_eq!(
            opportunity(s.waiting, 122, false, eligible)?,
            Opportunity::Reserved(3)
        );
        s.block(3, 122);
        assert!(s.blocked(3));
        assert_eq!(s.stats.paid_packets, 1);
        assert_eq!(
            opportunity(s.waiting, 123, false, eligible)?,
            Opportunity::Idle
        );
        assert_eq!(probes.get(), 0);
        assert_eq!(
            opportunity(s.waiting, 123, true, eligible)?,
            Opportunity::Select
        );
        assert_eq!(probes.get(), 1);
        Ok(())
    }

    #[test]
    fn empty_input_event_skips_selection_and_funded_new_work_keeps_regular_class_order()
    -> Result<()> {
        let mut s = Scheduler::new(100_000_000, 1500, 6, 2)?;
        let empty = opportunity(None, 0, true, || Ok(false))?;
        assert_eq!(empty, Opportunity::NoEligibleWork);
        s.stats.checkpoint(Outcome::NoEligibleWork);
        assert_eq!(s.stats.checkpoint_no_eligible_work, 1);
        assert_eq!(s.stats.checkpoint_selections_attempted, 0);
        for (now, class) in [(0, Class::Ack), (100, Class::Request), (200, Class::Data)] {
            assert_eq!(
                opportunity(None, now, true, || Ok(true))?,
                Opportunity::Select
            );
            assert_eq!(s.classes()[0], class);
            assert_eq!(s.ready_at(now, 60), now);
            s.paid(class, 0, 60, now);
            s.stats.checkpoint(Outcome::SelectedPaid);
        }
        s.stats.checkpoint(Outcome::SelectedReserved);
        s.stats.checkpoint(Outcome::SelectedWithoutHandoff);
        assert_eq!(s.stats.checkpoint_selections_attempted, 5);
        assert_eq!(s.stats.checkpoint_selections_paid, 3);
        assert_eq!(s.stats.checkpoint_selections_reserved, 1);
        assert_eq!(s.stats.checkpoint_selections_without_handoff, 1);
        assert_eq!(s.stats.paid_packets, 3);
        Ok(())
    }
}
