//! Exact byte occupancy across the negotiated raw reorder horizon.
//!
//! A lost packet leaves a hole, not another retained interval allocation. One
//! circular bit per byte represents every possible gap pattern in the bounded
//! horizon. Validation never advances the floor or changes authenticated state.

use super::Error;

pub(super) struct Ranges {
    words: Vec<u64>,
    limit: u64,
    retired: u64,
    floor: u64,
}

impl Ranges {
    pub(super) fn planned_capacity_bytes(horizon: u32) -> Result<usize, Error> {
        if !(1..=1_048_576).contains(&horizon) {
            return Err(Error::Configuration);
        }
        usize::try_from(horizon)
            .map_err(|_| Error::Capacity)?
            .div_ceil(u64::BITS as usize)
            .checked_mul(std::mem::size_of::<u64>())
            .ok_or(Error::Capacity)
    }

    pub(super) fn new(horizon: u32) -> Result<Self, Error> {
        let bytes = Self::planned_capacity_bytes(horizon)?;
        let count = bytes / std::mem::size_of::<u64>();
        let mut words = Vec::new();
        words
            .try_reserve_exact(count)
            .map_err(|_| Error::Capacity)?;
        if words.capacity() != count {
            return Err(Error::Capacity);
        }
        words.resize(count, 0);
        Ok(Self {
            words,
            limit: u64::from(horizon),
            retired: 0,
            floor: 0,
        })
    }

    pub(super) fn capacity_bytes(&self) -> usize {
        self.words.capacity() * std::mem::size_of::<u64>()
    }

    pub(super) fn validate(
        &self,
        start: u64,
        end: u64,
        retired: u64,
        horizon: u64,
    ) -> Result<(), Error> {
        let floor = retired
            .max(self.retired)
            .saturating_sub(horizon)
            .max(self.floor);
        if horizon == 0 || horizon > self.limit || end > retired || start < floor || start >= end {
            return Err(Error::Proof);
        }
        // A future extent can wrap over stale ring slots. Only bytes within
        // the still-live part of the previous committed extent may overlap.
        if self.overlaps(start, end.min(self.retired)) {
            return Err(Error::Proof);
        }
        Ok(())
    }

    pub(super) fn commit(
        &mut self,
        start: u64,
        end: u64,
        retired: u64,
        horizon: u64,
    ) -> Result<(), Error> {
        self.validate(start, end, retired, horizon)?;
        // Reordered bootstrap packets supply their own end before the shared
        // fence exists. Their arrival must never move the committed watermark.
        let retired = retired.max(self.retired);
        let capacity = self.words.len() as u64 * u64::from(u64::BITS);
        if retired - self.retired >= capacity {
            self.words.fill(0);
        } else {
            self.set(self.retired, retired, false);
        }
        self.set(start, end, true);
        self.retired = retired;
        self.floor = retired.saturating_sub(horizon).max(self.floor);
        Ok(())
    }

    fn overlaps(&self, mut start: u64, end: u64) -> bool {
        while start < end {
            let (index, mask, count) = self.word(start, end);
            if self.words[index] & mask != 0 {
                return true;
            }
            start += count;
        }
        false
    }

    fn set(&mut self, mut start: u64, end: u64, occupied: bool) {
        while start < end {
            let (index, mask, count) = self.word(start, end);
            if occupied {
                self.words[index] |= mask;
            } else {
                self.words[index] &= !mask;
            }
            start += count;
        }
    }

    fn word(&self, start: u64, end: u64) -> (usize, u64, u64) {
        let shift = start % u64::from(u64::BITS);
        let count = (end - start).min(u64::from(u64::BITS) - shift);
        let index = (start / u64::from(u64::BITS) % self.words.len() as u64) as usize;
        let mask = (u64::MAX >> (u64::from(u64::BITS) - count)) << shift;
        (index, mask, count)
    }

    #[cfg(test)]
    pub(super) fn occupied_bytes(&self) -> u64 {
        self.words
            .iter()
            .map(|word| u64::from(word.count_ones()))
            .sum()
    }
}

#[cfg(test)]
#[path = "ranges_tests.rs"]
mod tests;
