//! Preallocated atomic decisions for two-version rows and small metadata cells.
//!
//! A transaction publishes every changed cell with one decision. Aborted values
//! remain unreadable and are reclaimed when their bounded version is replaced.
use super::{Error, add, mul, slots};
use std::mem::size_of;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct Ticket {
    slot: usize,
    serial: u64,
}
#[derive(Clone, Copy)]
struct Decision {
    serial: u64,
    references: usize,
    committed: bool,
}
pub(super) struct Pool {
    decisions: Vec<Decision>,
    free: Vec<usize>,
    next: u64,
}
impl Pool {
    fn count(cells: usize) -> Result<usize, Error> {
        add(mul(2, cells)?, 1)
    }
    pub fn memory_bound(cells: usize) -> Result<usize, Error> {
        mul(
            Self::count(cells)?,
            add(size_of::<Decision>(), size_of::<usize>())?,
        )
    }
    pub fn new(cells: usize) -> Result<Self, Error> {
        let count = Self::count(cells)?;
        let decisions = slots(
            count,
            Decision {
                serial: 0,
                references: 0,
                committed: false,
            },
        )?;
        let mut free = slots(count, 0)?;
        for (index, slot) in free.iter_mut().enumerate() {
            *slot = index;
        }
        Ok(Self {
            decisions,
            free,
            next: 1,
        })
    }
    fn entry(&self, ticket: Ticket) -> Result<&Decision, Error> {
        self.decisions
            .get(ticket.slot)
            .filter(|d| d.serial == ticket.serial && d.references != 0)
            .ok_or(Error::Identity)
    }
    fn entry_mut(&mut self, ticket: Ticket) -> Result<&mut Decision, Error> {
        self.decisions
            .get_mut(ticket.slot)
            .filter(|d| d.serial == ticket.serial && d.references != 0)
            .ok_or(Error::Identity)
    }
    pub fn begin(&mut self) -> Result<Ticket, Error> {
        let next = self.next.checked_add(1).ok_or(Error::Exhausted)?;
        let slot = self.free.pop().ok_or(Error::Capacity)?;
        let ticket = Ticket {
            slot,
            serial: self.next,
        };
        self.decisions[slot] = Decision {
            serial: ticket.serial,
            references: 1,
            committed: false,
        };
        self.next = next;
        Ok(ticket)
    }
    fn retain(&mut self, ticket: Ticket) -> Result<(), Error> {
        let entry = self.entry_mut(ticket)?;
        entry.references = entry.references.checked_add(1).ok_or(Error::Exhausted)?;
        Ok(())
    }
    pub fn release(&mut self, ticket: Ticket) -> Result<(), Error> {
        let entry = self.entry_mut(ticket)?;
        entry.references -= 1;
        if entry.references == 0 {
            if self.free.len() >= self.decisions.len() {
                return Err(Error::Identity);
            }
            self.free.push(ticket.slot);
        }
        Ok(())
    }
    pub fn commit(&mut self, ticket: Ticket) -> Result<(), Error> {
        self.entry_mut(ticket)?.committed = true;
        self.release(ticket)
    }
    fn committed(&self, ticket: Ticket) -> Result<bool, Error> {
        Ok(self.entry(ticket)?.committed)
    }
}

/// Two preallocated versions retain the old committed value across a pending job.
#[derive(Clone, Copy)]
pub(super) struct Cell<T: Copy + Default> {
    values: [T; 2],
    tickets: [Option<Ticket>; 2],
}
impl<T: Copy + Default> Cell<T> {
    pub fn new() -> Self {
        Self {
            values: [T::default(); 2],
            tickets: [None; 2],
        }
    }
    pub fn selected(&self, pool: &Pool, active: Option<Ticket>) -> Result<Option<usize>, Error> {
        let mut selected: Option<(usize, u64)> = None;
        for (index, ticket) in self.tickets.iter().enumerate() {
            if let Some(ticket) = ticket
                && (Some(*ticket) == active || pool.committed(*ticket)?)
                && selected.is_none_or(|(_, serial)| ticket.serial > serial)
            {
                selected = Some((index, ticket.serial));
            }
        }
        Ok(selected.map(|(index, _)| index))
    }
    pub fn get(&self, pool: &Pool, active: Option<Ticket>) -> Result<T, Error> {
        Ok(self
            .selected(pool, active)?
            .map_or_else(T::default, |index| self.values[index]))
    }
    /// Select the writable version. Some(base) requires its payload to be copied;
    /// an already prepared version returns None and must never be copied again.
    pub fn prepare(
        &mut self,
        pool: &mut Pool,
        active: Ticket,
    ) -> Result<(usize, Option<usize>), Error> {
        if let Some(index) = self
            .tickets
            .iter()
            .position(|ticket| *ticket == Some(active))
        {
            return Ok((index, None));
        }
        let base = self.selected(pool, None)?;
        let target = base.map_or(0, |index| 1 - index);
        pool.retain(active)?;
        if let Some(old) = self.tickets[target] {
            pool.release(old)?;
        }
        self.tickets[target] = Some(active);
        Ok((target, base))
    }
    pub fn set(&mut self, pool: &mut Pool, active: Ticket, value: T) -> Result<(), Error> {
        let (target, _) = self.prepare(pool, active)?;
        self.values[target] = value;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn aborted_versions_stay_hidden_across_later_commits_and_pool_reuse() -> Result<(), Error> {
        let mut pool = Pool::new(2)?;
        let mut a = Cell::<Option<u32>>::new();
        let mut b = Cell::<Option<u32>>::new();
        let first = pool.begin()?;
        a.set(&mut pool, first, Some(1))?;
        b.set(&mut pool, first, Some(2))?;
        pool.commit(first)?;
        let aborted = pool.begin()?;
        a.set(&mut pool, aborted, Some(99))?;
        assert_eq!(a.get(&pool, Some(aborted))?, Some(99));
        assert_eq!(a.get(&pool, None)?, Some(1));
        pool.release(aborted)?;
        let next = pool.begin()?;
        b.set(&mut pool, next, Some(3))?;
        pool.commit(next)?;
        assert_eq!(a.get(&pool, None)?, Some(1));
        assert_eq!(b.get(&pool, None)?, Some(3));
        for value in 4..200 {
            let pending = pool.begin()?;
            a.set(&mut pool, pending, Some(u32::MAX))?;
            b.set(&mut pool, pending, Some(u32::MAX))?;
            pool.release(pending)?;
            let live = pool.begin()?;
            a.set(&mut pool, live, Some(value))?;
            b.set(&mut pool, live, Some(value + 1))?;
            pool.commit(live)?;
            assert_eq!(a.get(&pool, None)?, Some(value));
            assert_eq!(b.get(&pool, None)?, Some(value + 1));
            assert!(!pool.free.is_empty());
        }
        assert!(pool.committed(aborted).is_err());
        Ok(())
    }
    #[test]
    fn vacant_aborts_zero_change_commits_and_exhaustion_preserve_pool_ownership()
    -> Result<(), Error> {
        let mut pool = Pool::new(1)?;
        let mut value = Cell::<Option<u32>>::new();
        let count = pool.free.len();
        for _ in 0..100 {
            let ticket = pool.begin()?;
            pool.commit(ticket)?;
            assert_eq!(pool.free.len(), count);
        }
        let aborted = pool.begin()?;
        value.set(&mut pool, aborted, Some(7))?;
        pool.release(aborted)?;
        assert_eq!(
            value.get(&pool, None)?,
            None,
            "aborted first version must not become a default value"
        );
        let free = pool.free.clone();
        pool.next = u64::MAX;
        assert_eq!(pool.begin(), Err(Error::Exhausted));
        assert_eq!(pool.free, free);
        assert_eq!(value.get(&pool, None)?, None);
        Ok(())
    }
}
