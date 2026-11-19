//! A small custody FIFO separate from the encoder's immutable repair support.
use super::*;

const LIMIT: usize = 8;

#[derive(Clone, Copy, Default)]
pub(super) struct Entry {
    pub id: u32,
    pub created: u64,
    pub due: u64,
    pub copies: u8,
    pub len: usize,
}

pub(in crate::rolling) struct Queue {
    entries: Vec<Entry>,
    payloads: Vec<u8>,
    width: usize,
    head: usize,
    earliest: Option<usize>,
    pub(super) len: usize,
    pub(super) peak: usize,
    pub(super) payload_bytes: usize,
}

impl Queue {
    fn count(policy: Policy) -> usize {
        if policy.source_wire.is_targeted() {
            LIMIT.min(policy.recovery.window)
        } else {
            0
        }
    }
    pub(in crate::rolling) fn plan(policy: Policy) -> Result<storage::Usage, storage::Error> {
        let count = Self::count(policy);
        storage::requested::<Entry>(count)?.join(storage::requested::<u8>(mul(
            count,
            policy.recovery.max_payload,
        )?)?)
    }
    pub(super) fn bytes(policy: Policy) -> Result<usize, Error> {
        mul(
            Self::count(policy),
            add(std::mem::size_of::<Entry>(), policy.recovery.max_payload)?,
        )
    }
    pub(super) fn new(policy: Policy) -> Result<Self, Error> {
        let count = Self::count(policy);
        Ok(Self {
            entries: slots(count, Entry::default())?,
            payloads: bytes(mul(count, policy.recovery.max_payload)?)?,
            width: policy.recovery.max_payload,
            head: 0,
            earliest: None,
            len: 0,
            peak: 0,
            payload_bytes: 0,
        })
    }
    pub(super) fn usage(&self) -> Result<storage::Usage, storage::Error> {
        storage::Usage::vector(&self.entries)?.join(storage::Usage::vector(&self.payloads)?)
    }
    pub(super) fn limit(&self) -> usize {
        self.entries.len()
    }
    pub(super) fn push(&mut self, entry: Entry, original: &[u8]) -> Result<(), Error> {
        if self.len == self.limit() {
            return Err(Error::Busy);
        }
        let i = (self.head + self.len) % self.limit();
        self.entries[i] = entry;
        if self
            .earliest
            .is_none_or(|old| self.entries[old].due > entry.due)
        {
            self.earliest = Some(i);
        }
        self.payloads[i * self.width..i * self.width + entry.len].copy_from_slice(original);
        self.len += 1;
        self.payload_bytes += entry.len;
        self.peak = self.peak.max(self.len);
        Ok(())
    }
    pub(super) fn front(&self) -> Option<(Entry, &[u8])> {
        if self.len == 0 {
            return None;
        }
        let entry = self.entries[self.head];
        let start = self.head * self.width;
        Some((entry, &self.payloads[start..start + entry.len]))
    }
    pub(super) fn pop(&mut self) {
        let removed = self.head;
        self.head = (self.head + 1) % self.limit();
        self.len -= 1;
        self.payload_bytes -= self.entries[removed].len;
        if self.earliest == Some(removed) {
            // Packing timestamps from separate MUX channels can be unordered.
            // Scan at most seven slots on removal, keep all deadline polls O(1).
            self.earliest = (0..self.len)
                .map(|i| (self.head + i) % self.limit())
                .min_by_key(|&i| self.entries[i].due);
        }
    }
    pub(super) fn earliest(&self) -> Option<Entry> {
        self.earliest.map(|i| self.entries[i])
    }
}
