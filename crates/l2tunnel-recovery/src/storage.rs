//! Checked, fallible backing for the existing selective-repeat engine.
//!
//! Charges are requested owned allocation layouts, not allocator overhead, RSS,
//! physical pages, clocks or a guarantee against operating-system overcommit.

use crate::{ArqConfig, RecoveryError};
use std::{alloc::Layout, fmt};

/// Heap-only backing budget for one actual recovery owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Limits {
    /// Maximum requested metadata and persistent payload layout bytes.
    pub capacity_bytes: usize,
}

/// Validated allocation-free inventory for one bidirectional recovery engine.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Plan {
    config: ArqConfig,
    capacity_bytes: usize,
}

impl Plan {
    /// Validate the existing ARQ contract and calculate every backing layout.
    pub fn for_arq(config: ArqConfig) -> Result<Self, Error> {
        config.validate().map_err(Error::Recovery)?;
        let capacity_bytes = array_bytes::<crate::arq::SendSlot>(config.send_records)?
            .checked_add(array_bytes::<crate::arq::ReceiveSlot>(
                config.receive_records,
            )?)
            .and_then(|metadata| {
                config
                    .send_records
                    .checked_add(config.receive_records)
                    .and_then(|count| count.checked_mul(config.max_source_bytes))
                    .and_then(|payload| metadata.checked_add(payload))
            })
            .ok_or(Error::Layout)?;
        Ok(Self {
            config,
            capacity_bytes,
        })
    }

    /// Exact immutable protocol settings used by this plan.
    pub fn config(&self) -> ArqConfig {
        self.config
    }

    /// Complete heap-only requested layout, including currently empty slots.
    pub fn capacity_bytes(&self) -> usize {
        self.capacity_bytes
    }
}

/// Observation of actual retained backing; never accepted as allocation authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Usage {
    /// Original construction limit, independent of current logical payloads.
    pub limit_bytes: usize,
    /// Actual retained requested layout, including idle payload buffers.
    pub capacity_bytes: usize,
    /// Successful explicit nonzero backing reservations, not OS allocations.
    pub allocations: usize,
}

/// Construction failures, separate from existing packet/recovery errors.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// Existing configuration validation rejected the settings.
    Recovery(RecoveryError),
    /// A checked element layout or total cannot be represented.
    Layout,
    /// Complete backing exceeds the supplied heap-only budget.
    Limit {
        /// Complete required layout bytes.
        required: usize,
        /// Supplied heap-only limit bytes.
        limit: usize,
    },
    /// A fallible backing reservation failed.
    Allocation,
    /// Actual capacity differs from the validated exact inventory.
    Invariant,
}
impl fmt::Display for Error {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(output, "recovery storage error: {self:?}")
    }
}
impl std::error::Error for Error {}

pub(crate) fn array_bytes<T>(count: usize) -> Result<usize, Error> {
    Layout::array::<T>(count)
        .map(|layout| layout.size())
        .map_err(|_| Error::Layout)
}

pub(crate) struct Allocation {
    limit: usize,
    used: usize,
    allocations: usize,
    #[cfg(test)]
    fail_at: Option<usize>,
    #[cfg(test)]
    attempts: usize,
}
impl Allocation {
    pub(crate) fn new(limit: usize) -> Self {
        Self {
            limit,
            used: 0,
            allocations: 0,
            #[cfg(test)]
            fail_at: None,
            #[cfg(test)]
            attempts: 0,
        }
    }

    pub(crate) fn vec<T>(&mut self, count: usize) -> Result<Vec<T>, Error> {
        let bytes = array_bytes::<T>(count)?;
        let total = self.used.checked_add(bytes).ok_or(Error::Layout)?;
        if total > self.limit {
            return Err(Error::Limit {
                required: total,
                limit: self.limit,
            });
        }
        #[cfg(test)]
        {
            self.attempts += 1;
            if self.fail_at == Some(self.attempts) {
                return Err(Error::Allocation);
            }
        }
        let mut values = Vec::new();
        values
            .try_reserve_exact(count)
            .map_err(|_| Error::Allocation)?;
        if values.capacity() != count {
            return Err(Error::Invariant);
        }
        self.used = total;
        self.allocations += usize::from(bytes != 0);
        Ok(values)
    }

    pub(crate) fn usage(&self) -> Usage {
        Usage {
            limit_bytes: self.limit,
            capacity_bytes: self.used,
            allocations: self.allocations,
        }
    }

    #[cfg(test)]
    pub(crate) fn attempts(&self) -> usize {
        self.attempts
    }

    #[cfg(test)]
    pub(crate) fn failing(limit: usize, fail_at: usize) -> Self {
        Self {
            fail_at: Some(fail_at),
            ..Self::new(limit)
        }
    }
}
