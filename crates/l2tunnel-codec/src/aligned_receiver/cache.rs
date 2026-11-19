//! Inline derived state: no additional allocation or admission authority.
use super::{Proof, Record, Tick};
use std::sync::OnceLock;

#[derive(Clone, Copy, Default, Debug, Eq, PartialEq)]
pub(super) struct Retention {
    pub sources: usize,
    pub proof_bytes: usize,
    pub records: usize,
    pub native_records: usize,
    pub record_bytes: usize,
    pub fragment_slots: usize,
    pub tombstones: usize,
    pub compacted: usize,
}
impl Retention {
    // Every record/source has already passed the original finite reservation.
    // These counts mirror live ownership, including transactional replacements.
    pub fn add_proof(&mut self, proof: &Proof) {
        self.sources += 1;
        self.proof_bytes += proof.bytes.len();
    }
    pub fn remove_proof(&mut self, proof: &Proof) {
        self.sources -= 1;
        self.proof_bytes -= proof.bytes.len();
    }
    pub fn add_record(&mut self, record: &Record) {
        self.records += 1;
        self.native_records += usize::from(record.native_pending());
        self.record_bytes += record.bytes.len();
        self.fragment_slots += record.pieces.len();
        self.tombstones += usize::from(record.early_delivered);
        self.compacted += usize::from(record.compacted);
    }
    pub fn remove_record(&mut self, record: &Record) {
        self.records -= 1;
        self.native_records -= usize::from(record.native_pending());
        self.record_bytes -= record.bytes.len();
        self.fragment_slots -= record.pieces.len();
        self.tombstones -= usize::from(record.early_delivered);
        self.compacted -= usize::from(record.compacted);
    }
    pub fn is_empty(self) -> bool {
        self.sources == 0 && self.records == 0
    }
}

// OnceLock preserves the owner's Send/Sync properties and permits an exact
// lazy minimum through the existing shared-reference deadline API. Its value
// is inline. Only immutable queries may race, and they see the same ledger.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct Minimum {
    deadline: Tick,
    owners: usize,
}
pub(super) type Checkpoint = Option<Option<Minimum>>;
pub(super) struct DeadlineCache(OnceLock<Option<Minimum>>);
impl Default for DeadlineCache {
    fn default() -> Self {
        Self(OnceLock::from(None))
    }
}
impl DeadlineCache {
    pub fn checkpoint(&self) -> Checkpoint {
        self.0.get().copied()
    }
    pub fn restore(&mut self, value: Checkpoint) {
        self.0 = value.map_or_else(OnceLock::new, OnceLock::from);
    }
    pub fn insert(&mut self, deadline: Tick) {
        if let Some(value) = self.0.get_mut() {
            match value {
                Some(old) if old.deadline == deadline => old.owners += 1,
                Some(old) if old.deadline < deadline => {}
                _ => {
                    *value = Some(Minimum {
                        deadline,
                        owners: 1,
                    })
                }
            }
        }
    }
    pub fn remove(&mut self, deadline: Tick, empty: bool) {
        if empty {
            self.0 = OnceLock::from(None);
        } else if let Some(Some(value)) = self.0.get_mut()
            && value.deadline == deadline
        {
            if value.owners > 1 {
                value.owners -= 1;
            } else {
                // Insertion commonly creates a record and proof at the same
                // tick. Removing its proof must not invalidate that live record.
                // Recount only after the last owner of the minimum is removed.
                self.0.take();
            }
        }
    }
    pub fn get(&self, deadlines: impl Iterator<Item = Tick>) -> Option<Tick> {
        self.0
            .get_or_init(|| {
                deadlines.fold(None, |minimum: Option<Minimum>, deadline| match minimum {
                    Some(mut old) if old.deadline == deadline => {
                        old.owners += 1;
                        Some(old)
                    }
                    Some(old) if old.deadline < deadline => Some(old),
                    _ => Some(Minimum {
                        deadline,
                        owners: 1,
                    }),
                })
            })
            .map(|value| value.deadline)
    }
}
