//! Fixed optional backing for exact sparse, externally supplied GF coefficients.
use super::*;

/// Maximum nonzero terms in one explicitly described equation.
pub const MAX_TERMS: usize = 255;
const TERM_BYTES: usize = 5;
const ROW_BYTES: usize = MAX_TERMS * TERM_BYTES;

/// One authenticated explicit source coefficient; terms must be strictly ordered.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Term {
    /// Absolute original source identity.
    pub source: SourceId,
    /// Nonzero GF(256) coefficient over the existing polynomial 0x11d.
    pub coefficient: u8,
}

pub(crate) fn support(terms: &[Term], feedback: bool, window: usize) -> Result<Support, Error> {
    if terms.is_empty() || terms.len() > MAX_TERMS {
        return Err(Error::Length);
    }
    let mut previous = None;
    for term in terms {
        if term.coefficient == 0
            || term.source.0 == u32::MAX
            || previous.is_some_and(|old| old >= term.source.0)
        {
            return Err(Error::Identity);
        }
        previous = Some(term.source.0);
    }
    let start = terms[0].source.0;
    let end = terms[terms.len() - 1].source.0 + 1;
    if end - start > window as u32 {
        return Err(Error::Capacity);
    }
    Ok(Support {
        start,
        end,
        seed: u32::from(feedback),
        tail: false,
    })
}

// Canonical five-byte terms exclude Rust padding and permit byte-budget-one
// publication. Admission performs one fixed <=1275-byte copy, like payload input.
pub(super) struct Row {
    bytes: Vec<u8>,
    count: usize,
}
impl Row {
    pub(super) fn memory_bound() -> usize {
        ROW_BYTES
    }
    pub(super) fn new() -> Result<Self, Error> {
        Ok(Self {
            bytes: bytes(ROW_BYTES)?,
            count: 0,
        })
    }
    pub(super) fn requested_storage() -> Result<storage::Usage, storage::Error> {
        storage::requested::<u8>(ROW_BYTES)
    }
    pub(super) fn storage_usage(&self) -> Result<storage::Usage, storage::Error> {
        storage::Usage::vector(&self.bytes)
    }
    pub(super) fn load(&mut self, terms: &[Term]) {
        for (at, term) in terms.iter().enumerate() {
            let offset = at * TERM_BYTES;
            self.bytes[offset..offset + 4].copy_from_slice(&term.source.0.to_be_bytes());
            self.bytes[offset + 4] = term.coefficient;
        }
        self.count = terms.len();
    }
    fn source(&self, at: usize) -> u32 {
        let offset = at * TERM_BYTES;
        u32::from_be_bytes([
            self.bytes[offset],
            self.bytes[offset + 1],
            self.bytes[offset + 2],
            self.bytes[offset + 3],
        ])
    }
    // At most eight source comparisons per existing metadata visit (255 terms).
    pub(super) fn coefficient(&self, id: u32) -> u8 {
        let mut left = 0;
        let mut right = self.count;
        while left < right {
            let middle = left + (right - left) / 2;
            match self.source(middle).cmp(&id) {
                std::cmp::Ordering::Less => left = middle + 1,
                std::cmp::Ordering::Greater => right = middle,
                std::cmp::Ordering::Equal => return self.bytes[middle * TERM_BYTES + 4],
            }
        }
        0
    }
    pub(super) fn len(&self) -> usize {
        self.count * TERM_BYTES
    }
}

pub(super) struct DecoderState {
    pub(super) input: Row,
    history: Vec<u8>,
    counts: Vec<u16>,
}
impl DecoderState {
    pub(super) fn memory_bound(history: usize) -> Result<usize, Error> {
        add(
            ROW_BYTES,
            mul(ROW_BYTES + std::mem::size_of::<u16>(), history)?,
        )
    }
    pub(super) fn new(history: usize) -> Result<Self, Error> {
        Ok(Self {
            input: Row::new()?,
            history: bytes(mul(ROW_BYTES, history)?)?,
            counts: slots(history, 0)?,
        })
    }
    pub(super) fn requested_storage(history: usize) -> Result<storage::Usage, storage::Error> {
        Row::requested_storage()?
            .join(storage::requested::<u8>(mul(ROW_BYTES, history)?)?)?
            .join(storage::requested::<u16>(history)?)
    }
    pub(super) fn storage_usage(&self) -> Result<storage::Usage, storage::Error> {
        self.input
            .storage_usage()?
            .join(storage::Usage::vector(&self.history)?)?
            .join(storage::Usage::vector(&self.counts)?)
    }
    pub(super) fn matches(&self, slot: usize, terms: &[Term]) -> bool {
        usize::from(self.counts[slot]) == terms.len()
            && terms.iter().enumerate().all(|(at, term)| {
                let offset = slot * ROW_BYTES + at * TERM_BYTES;
                self.history[offset..offset + 4] == term.source.0.to_be_bytes()
                    && self.history[offset + 4] == term.coefficient
            })
    }
    pub(super) fn copy_history_byte(&mut self, slot: usize, at: usize) {
        self.history[slot * ROW_BYTES + at] = self.input.bytes[at];
    }
    pub(super) fn commit(&mut self, slot: usize) {
        self.counts[slot] = self.input.count as u16;
    }
}

#[cfg(test)]
mod tests;
