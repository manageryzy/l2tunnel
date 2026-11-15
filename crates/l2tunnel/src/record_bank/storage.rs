//! Complete retained layouts for two actual inline common Engines.
use super::{Bank, engine};
use std::{fmt, mem::size_of};

/// Complete Bank allowance, including caller-accounted external storage once.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Limits {
    /// Maximum admitted retained Rust layout capacity.
    pub capacity_bytes: usize,
}

/// Observed retained layouts, distinct from occupancy, RSS and physical proof.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Usage {
    /// Original complete construction allowance.
    pub limit_bytes: usize,
    /// Complete inline Bank, including both Engine slot extents.
    pub fixed_bytes: usize,
    /// Caller-accounted shared external capacity, counted once.
    pub external_bytes: usize,
    /// Actual retained occupied-slot heap, excluding inline Engine headers.
    pub engine_bytes: usize,
    /// Complete target heap precharged during synchronous construction.
    pub building_bytes: usize,
    /// Complete current fixed, external, retained and building charge.
    pub capacity_bytes: usize,
    /// Highest admitted charge, including failed construction attempts.
    pub peak_bytes: usize,
    /// Successful nonzero nested reservations retained by occupied slots.
    pub allocations: usize,
}

/// Resource, custody or actual underlying Engine refusal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// Actual reserved Engine construction failed.
    Storage(engine::storage::Error),
    /// Actual packet/native Engine operation or drain failed.
    Engine(engine::Error),
    /// A checked complete layout or accounting sum cannot be represented.
    Layout,
    /// Complete current plus target charge exceeds the allowance.
    Limit {
        /// Complete required capacity.
        required: usize,
        /// Supplied complete allowance.
        limit: usize,
    },
    /// Both actual slots remain retained.
    Slots,
    /// Foreign, retired, virgin, consumed or otherwise mismatched local identity.
    Stale,
    /// Nonwrapping Bank-instance or slot-generation space is exhausted.
    Exhausted,
    /// Actual queue, duplex profile or native custody remains undrained.
    NotDrained,
    /// Actual nested observations disagree with the admitted construction.
    Invariant,
}
impl fmt::Display for Error {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(output, "common record Bank: {self:?}")
    }
}
impl std::error::Error for Error {}

/// Allocation-free initial Bank inventory, with an exact actual Engine plan.
#[derive(Clone, Copy)]
pub struct Plan {
    initial: engine::storage::Plan,
    external_bytes: usize,
    capacity_bytes: usize,
}
impl Plan {
    /// Count both inline slots once, the initial actual heap and shared external storage.
    pub fn for_bank(initial: engine::storage::Plan, external_bytes: usize) -> Result<Self, Error> {
        let capacity_bytes = size_of::<Bank>()
            .checked_add(external_bytes)
            .and_then(|bytes| bytes.checked_add(initial.heap_bytes()))
            .ok_or(Error::Layout)?;
        Ok(Self {
            initial,
            external_bytes,
            capacity_bytes,
        })
    }
    /// Exact original complete Engine plan, without reconstructing configuration.
    pub const fn initial(&self) -> &engine::storage::Plan {
        &self.initial
    }
    /// Exact shared external subtotal; actual external ownership stays separate.
    pub const fn external_bytes(&self) -> usize {
        self.external_bytes
    }
    /// Complete initial inline-plus-heap-plus-external layout.
    pub const fn capacity_bytes(&self) -> usize {
        self.capacity_bytes
    }
}
