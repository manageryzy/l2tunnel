//! Only physically paid gap requests acquire a repeat deadline. Every live
//! source lies in one negotiated aperture, so the deadline for its absolute ID
//! can be looked up by a single modulo slot and removed on native commitment.
use super::{Error, GenerationId, Index, Missing};

pub(super) struct NamedTimers {
    deadlines: Index<(u64, GenerationId), ()>,
    slots: Vec<u64>,
}

impl NamedTimers {
    pub(super) fn planned_bytes(limit: usize) -> Result<usize, Error> {
        let deadlines = Index::<(u64, GenerationId), ()>::planned_bytes(limit)
            .map_err(|_| Error::Arithmetic)?;
        let slots = std::alloc::Layout::array::<u64>(limit).map_err(|_| Error::Arithmetic)?;
        deadlines.checked_add(slots.size()).ok_or(Error::Arithmetic)
    }

    pub(super) fn new(limit: usize) -> Result<Self, Error> {
        let expected = Self::planned_bytes(limit)?;
        let deadlines = Index::new(limit).map_err(|_| Error::Capacity)?;
        let mut slots = Vec::new();
        slots
            .try_reserve_exact(limit)
            .map_err(|_| Error::Capacity)?;
        slots.resize(limit, 0);
        let timers = Self { deadlines, slots };
        if timers.capacity_bytes() != expected {
            return Err(Error::Capacity);
        }
        Ok(timers)
    }

    pub(super) fn capacity_bytes(&self) -> usize {
        self.deadlines.capacity_bytes() + self.slots.capacity() * size_of::<u64>()
    }

    fn slot(&self, id: GenerationId) -> usize {
        (id.0 % self.slots.len() as u64) as usize
    }

    pub(super) fn first(&self) -> Option<(u64, GenerationId)> {
        self.deadlines.first().map(|(pair, ())| pair)
    }

    pub(super) fn remove(&mut self, id: GenerationId) {
        let slot = self.slot(id);
        let time = self.slots[slot];
        if time != 0 && self.deadlines.remove((time, id)).is_some() {
            self.slots[slot] = 0;
        }
    }

    pub(super) fn arm(&mut self, id: GenerationId, due: u64) -> Result<(), Error> {
        self.remove(id);
        self.deadlines
            .insert((due, id), ())
            .map_err(|_| Error::Capacity)?;
        let slot = self.slot(id);
        self.slots[slot] = due;
        Ok(())
    }

    // Only called with IDs in the live aperture and its earliest due timer.
    pub(super) fn due_mask(
        &self,
        now: u64,
        first: GenerationId,
        span: usize,
    ) -> Result<Missing, Error> {
        let mut mask = 0;
        for offset in 0..span {
            let id = GenerationId(first.0 + offset as u64);
            let due = self.slots[self.slot(id)];
            if due != 0 && due <= now {
                mask |= 1 << offset;
            }
        }
        Missing::new(first, mask)
    }
}
