//! Actual fallible heap backing for the existing block FEC owners.
use crate::{BlockConfig, DecoderConfig};
use std::{alloc::Layout, fmt};

/// Heap-only requested allocation-layout budget.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Limits {
    /// Complete retained heap allowance.
    pub capacity_bytes: usize,
}
/// Observed actual backing, including idle reusable buffers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Usage {
    /// Original constructor allowance.
    pub limit_bytes: usize,
    /// Actual requested retained layout.
    pub capacity_bytes: usize,
    /// Explicit successful nonzero reservations.
    pub allocations: usize,
}
/// Construction errors, separate from protocol errors.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// Existing configuration error.
    Fec(crate::Error),
    /// Checked layout or sum overflow.
    Layout,
    /// Complete plan exceeds the supplied allowance.
    Limit {
        /// Required layout.
        required: usize,
        /// Supplied allowance.
        limit: usize,
    },
    /// Fallible reservation failed.
    Allocation,
    /// Observed capacity disagrees with the plan.
    Invariant,
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "FEC storage error: {self:?}")
    }
}
impl std::error::Error for Error {}

/// Allocation-free inventory of one reusable block encoder.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EncoderPlan {
    config: BlockConfig,
    bytes: usize,
}
impl EncoderPlan {
    /// Validate existing scalar limits and inventory actual retained buffers.
    pub fn for_encoder(config: BlockConfig) -> Result<Self, Error> {
        config.validate().map_err(Error::Fec)?;
        let n = config.max_sources;
        let w = config
            .max_source_bytes
            .checked_add(2)
            .ok_or(Error::Layout)?;
        let bytes = add(array_bytes::<Vec<u8>>(n)?, add(mul(n, w)?, add(n, w)?)?)?;
        Ok(Self { config, bytes })
    }
    /// Complete original scalar configuration.
    pub fn config(&self) -> BlockConfig {
        self.config
    }
    /// Complete heap-only requested layout.
    pub fn capacity_bytes(&self) -> usize {
        self.bytes
    }
}
/// Allocation-free inventory of one decoder and its shared row transaction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DecoderPlan {
    config: DecoderConfig,
    bytes: usize,
}
impl DecoderPlan {
    /// Validate existing logical bounds, then inventory all physical backing.
    pub fn for_decoder(config: DecoderConfig) -> Result<Self, Error> {
        config.validate().map_err(Error::Fec)?;
        let bytes = crate::decoder::backing::reserved_bytes(config)?;
        Ok(Self { config, bytes })
    }
    /// Complete original scalar configuration.
    pub fn config(&self) -> DecoderConfig {
        self.config
    }
    /// Actual heap capacity, distinct from logical equation reservations.
    pub fn capacity_bytes(&self) -> usize {
        self.bytes
    }
}
pub(crate) fn add(a: usize, b: usize) -> Result<usize, Error> {
    a.checked_add(b).ok_or(Error::Layout)
}
pub(crate) fn mul(a: usize, b: usize) -> Result<usize, Error> {
    a.checked_mul(b).ok_or(Error::Layout)
}
pub(crate) fn array_bytes<T>(n: usize) -> Result<usize, Error> {
    Layout::array::<T>(n)
        .map(|l| l.size())
        .map_err(|_| Error::Layout)
}
pub(crate) struct Allocation {
    used: usize,
    count: usize,
    limit: usize,
    #[cfg(test)]
    fail_at: Option<usize>,
    #[cfg(test)]
    attempts: usize,
}
impl Allocation {
    pub(crate) fn new(limit: usize) -> Self {
        Self {
            used: 0,
            count: 0,
            limit,
            #[cfg(test)]
            fail_at: None,
            #[cfg(test)]
            attempts: 0,
        }
    }
    pub(crate) fn vec<T>(&mut self, n: usize) -> Result<Vec<T>, Error> {
        let bytes = array_bytes::<T>(n)?;
        let total = add(self.used, bytes)?;
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
        let mut v = Vec::new();
        v.try_reserve_exact(n).map_err(|_| Error::Allocation)?;
        if v.capacity() != n {
            return Err(Error::Invariant);
        }
        self.used = total;
        self.count += usize::from(bytes != 0);
        Ok(v)
    }
    pub(crate) fn usage(&self) -> Usage {
        Usage {
            limit_bytes: self.limit,
            capacity_bytes: self.used,
            allocations: self.count,
        }
    }
    #[cfg(test)]
    pub(crate) fn failing(limit: usize, fail_at: usize) -> Self {
        Self {
            fail_at: Some(fail_at),
            ..Self::new(limit)
        }
    }
}
