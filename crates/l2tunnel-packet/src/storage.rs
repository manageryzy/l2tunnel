//! Fallible retained heap inventory for the actual fixed-capacity FlowTable.
use crate::{FlowError, FlowTableConfig, flow};
use std::{alloc::Layout, fmt};

/// Explicit retained heap allowance; enclosing inline owners are counted separately.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Limits {
    /// Maximum managed heap capacity.
    pub capacity_bytes: usize,
}

/// Actual retained capacity, independent of the number of live registrations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Usage {
    /// Original construction allowance.
    pub limit_bytes: usize,
    /// Actual retained heap capacity, excluding the inline FlowTable.
    pub capacity_bytes: usize,
    /// Successful nonzero fallible reservations.
    pub allocations: usize,
}

/// Construction failure without a legacy allocating fallback.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// Existing scalar flow-table validation failure.
    Flow(FlowError),
    /// A complete array layout cannot be represented.
    Layout,
    /// Complete required backing exceeds the supplied allowance.
    Limit {
        /// Required retained heap capacity.
        required: usize,
        /// Supplied retained heap allowance.
        limit: usize,
    },
    /// A fallible backing reservation failed.
    Allocation,
    /// Actual retained capacity differs from its admitted plan.
    Invariant,
}
impl fmt::Display for Error {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(output, "flow-table storage: {self:?}")
    }
}
impl std::error::Error for Error {}

/// Allocation-free validated complete fixed-capacity flow-table plan.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Plan {
    config: FlowTableConfig,
    capacity_bytes: usize,
}
impl Plan {
    /// Preserve existing scalar validation before computing the complete backing layout.
    pub fn for_config(config: FlowTableConfig) -> Result<Self, Error> {
        config.validate().map_err(Error::Flow)?;
        Ok(Self {
            config,
            capacity_bytes: array_bytes::<flow::Cell>(config.capacity)?,
        })
    }
    /// Complete retained heap layout, excluding the inline FlowTable header.
    pub const fn capacity_bytes(&self) -> usize {
        self.capacity_bytes
    }
    /// Exact unchanged configuration bound to this plan.
    pub const fn config(&self) -> FlowTableConfig {
        self.config
    }

    pub(crate) fn check(&self, limits: Limits) -> Result<(), Error> {
        if self.capacity_bytes > limits.capacity_bytes {
            Err(Error::Limit {
                required: self.capacity_bytes,
                limit: limits.capacity_bytes,
            })
        } else {
            Ok(())
        }
    }
}

pub(crate) fn array_bytes<T>(count: usize) -> Result<usize, Error> {
    Layout::array::<T>(count)
        .map(|layout| layout.size())
        .map_err(|_| Error::Layout)
}

#[derive(Default)]
pub(crate) struct Allocation {
    #[cfg(test)]
    pub(crate) attempts: usize,
    #[cfg(test)]
    fail_at: Option<usize>,
}
impl Allocation {
    pub(crate) fn reserve<T>(&mut self, count: usize) -> Result<Vec<T>, Error> {
        array_bytes::<T>(count)?;
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
        Ok(values)
    }
    #[cfg(test)]
    pub(crate) fn failing(attempt: usize) -> Self {
        Self {
            fail_at: Some(attempt),
            ..Self::default()
        }
    }
}
