//! Regular opportunities reserved in physical systematic-source order.
use super::*;

#[derive(Clone, Copy)]
pub(super) struct Entry {
    pub id: RepairId,
    pub support: Support,
    pub deadline: Tick,
}

const CAPACITY: usize = 16;
pub(super) struct Queue {
    entries: [Option<Entry>; CAPACITY],
    // A later global support may start before the oldest queued local support.
    minima: [u32; CAPACITY * 2],
    front: usize,
    len: usize,
}
impl Queue {
    pub(super) fn new() -> Self {
        Self {
            entries: [None; CAPACITY],
            minima: [u32::MAX; CAPACITY * 2],
            front: 0,
            len: 0,
        }
    }
    pub(super) fn front(&self) -> Option<Entry> {
        self.entries[self.front]
    }
    pub(super) fn blocks_overwrite(&self, old: u32) -> bool {
        old >= self.minima[1]
    }
    fn set(&mut self, slot: usize, entry: Option<Entry>) {
        self.entries[slot] = entry;
        let mut index = CAPACITY + slot;
        self.minima[index] = entry.map_or(u32::MAX, |e| e.support.start);
        while index > 1 {
            index /= 2;
            self.minima[index] = self.minima[index * 2].min(self.minima[index * 2 + 1]);
        }
    }
    pub(super) fn push(&mut self, entry: Entry) -> Result<(), Error> {
        if self.len == CAPACITY {
            return Err(Error::Capacity);
        }
        self.set((self.front + self.len) % CAPACITY, Some(entry));
        self.len += 1;
        Ok(())
    }
    pub(super) fn pop(&mut self) {
        self.set(self.front, None);
        self.front = (self.front + 1) % CAPACITY;
        self.len -= 1;
    }
    pub(super) fn clear(&mut self) {
        if self.len != 0 {
            *self = Self::new();
        }
    }
}
