//! Receipt journal for wide receive directions (more than 64 records): every
//! newly stored source in arrival order, so early consumers visit only new
//! receipts instead of rescanning the whole receive window. Windows of at most
//! 64 never construct it.
use super::{ArqConfig, Engine, SourceId};
use std::collections::VecDeque;

/// One stored receipt; storage plans charge `receive_records` of these.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ReceiptEntry {
    serial: u64,
    source: u64,
}

#[derive(Debug)]
pub(super) struct Journal {
    ring: VecDeque<ReceiptEntry>,
    capacity: usize,
    /// Serial of the latest receipt; the first receipt is serial 1.
    serial: u64,
}

impl Journal {
    /// `storage` must have capacity for the receive window.
    pub(super) fn new(config: ArqConfig, storage: Vec<ReceiptEntry>) -> Self {
        debug_assert!(storage.capacity() >= config.receive_records);
        Self {
            ring: VecDeque::from(storage),
            capacity: config.receive_records,
            serial: 0,
        }
    }
    pub(super) fn dynamic(config: ArqConfig) -> Self {
        Self::new(config, Vec::with_capacity(config.receive_records))
    }
    pub(super) fn record(&mut self, source: SourceId) {
        self.serial += 1;
        if self.ring.len() >= self.capacity {
            self.ring.pop_front();
        }
        self.ring.push_back(ReceiptEntry {
            serial: self.serial,
            source: source.0,
        });
    }
}

impl Engine {
    /// Latest receipt serial, if this direction keeps a journal.
    pub(super) fn receipt_serial(&self) -> Option<u64> {
        self.receipts.as_ref().map(|journal| journal.serial)
    }

    /// Receipts after `cursor` whose sources are still retained, in arrival
    /// order, starting in O(1). `None` when no journal exists or `cursor`
    /// already fell out of the ring; the caller then scans every retained source.
    pub(super) fn receipts_after(
        &self,
        cursor: u64,
    ) -> Option<impl Iterator<Item = (u64, SourceId, &Vec<u8>)>> {
        let journal = self.receipts.as_ref()?;
        let first = journal
            .ring
            .front()
            .map_or(journal.serial + 1, |entry| entry.serial);
        if cursor.checked_add(1)? < first || cursor > journal.serial {
            return None;
        }
        let start = usize::try_from(cursor + 1 - first).ok()?;
        Some(journal.ring.range(start..).filter_map(|entry| {
            let source = SourceId(entry.source);
            self.received
                .get(&source)
                .map(|payload| (entry.serial, source, payload))
        }))
    }
}
