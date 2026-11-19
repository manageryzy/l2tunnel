//! Checked heap layouts for the actual Aligned/Packed codec owners.
//! Counts exclude inline owners, allocator overhead, caller outputs and RSS.
use crate::{aligned_receiver, aligned_sender, packed_sender};
use std::{alloc::Layout, fmt, mem::size_of};

/// Explicit maximum retained managed heap layout.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Limits {
    /// Maximum actual metadata and payload capacity in bytes.
    pub capacity_bytes: usize,
}
/// Actual construction observation, never allocation authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Usage {
    /// Original explicit construction budget.
    pub limit_bytes: usize,
    /// Actual retained requested heap layouts, including idle buffers.
    pub capacity_bytes: usize,
    /// Successful explicit nonzero backing reservations.
    pub allocations: usize,
}
/// Construction error without allocating fallback.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// Existing sender configuration or context failure.
    Sender(aligned_sender::Error),
    /// Existing Packed sender configuration or context failure.
    PackedSender(packed_sender::Error),
    /// Existing receiver configuration or context failure.
    Receiver(aligned_receiver::Error),
    /// An element layout or checked aggregate cannot be represented.
    Layout,
    /// Complete requested backing exceeds the explicit budget.
    Limit {
        /// Complete required managed heap layout.
        required: usize,
        /// Supplied maximum managed heap layout.
        limit: usize,
    },
    /// A fallible reservation failed.
    Allocation,
    /// Actual capacity differs from the validated requested inventory.
    Invariant,
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "aligned storage: {self:?}")
    }
}
impl std::error::Error for Error {}

/// Allocation-free exact inventory for one actual sender.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SenderPlan {
    config: aligned_sender::Config,
    capacity: usize,
    ip_headers: bool,
}
impl SenderPlan {
    /// Validate the existing complete sender policy before calculating layouts.
    pub fn for_config(config: aligned_sender::Config) -> Result<Self, Error> {
        config.memory_bound_bytes().map_err(Error::Sender)?;
        Ok(Self {
            ip_headers: false,
            config,
            capacity: aligned_sender::Sender::reserved_bytes(config)?,
        })
    }
    /// Select native-IP header state before construction; no policy or bound is reduced.
    pub fn for_ip_config(config: aligned_sender::Config) -> Result<Self, Error> {
        let mut plan = Self::for_config(config)?;
        plan.ip_headers = true;
        Ok(plan)
    }
    /// Whether the actual selected state is native-IP header compression.
    pub fn ip_headers(&self) -> bool {
        self.ip_headers
    }
    /// Exact immutable sender policy.
    pub fn config(&self) -> aligned_sender::Config {
        self.config
    }
    /// Complete managed heap capacity, excluding inline Self.
    pub fn capacity_bytes(&self) -> usize {
        self.capacity
    }
}
/// Allocation-free exact inventory for one actual timed Packed sender.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PackedSenderPlan {
    config: packed_sender::Config,
    capacity: usize,
    ip_headers: bool,
}
impl PackedSenderPlan {
    /// Validate complete packing/body policy before calculating layouts.
    pub fn for_config(config: packed_sender::Config) -> Result<Self, Error> {
        config.memory_bound_bytes().map_err(Error::PackedSender)?;
        Ok(Self {
            ip_headers: false,
            config,
            capacity: packed_sender::Sender::reserved_bytes(config)?,
        })
    }
    /// Select native-IP header state before construction; no policy or bound is reduced.
    pub fn for_ip_config(config: packed_sender::Config) -> Result<Self, Error> {
        let mut plan = Self::for_config(config)?;
        plan.ip_headers = true;
        Ok(plan)
    }
    /// Whether the actual selected state is native-IP header compression.
    pub fn ip_headers(&self) -> bool {
        self.ip_headers
    }
    /// Exact immutable packing/body policy.
    pub fn config(&self) -> packed_sender::Config {
        self.config
    }
    /// Complete managed heap capacity, excluding inline Self.
    pub fn capacity_bytes(&self) -> usize {
        self.capacity
    }
}
/// Allocation-free exact inventory for live receiver and touched-version journals.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReceiverPlan {
    limits: aligned_receiver::Limits,
    capacity: usize,
    ip_headers: bool,
}
impl ReceiverPlan {
    /// Validate all existing receive maxima without reducing them to fit a budget.
    pub fn for_limits(limits: aligned_receiver::Limits) -> Result<Self, Error> {
        limits.memory_bound_bytes().map_err(Error::Receiver)?;
        Ok(Self {
            ip_headers: false,
            limits,
            capacity: aligned_receiver::Receiver::reserved_bytes(limits, false)?,
        })
    }
    /// Select native-IP header state before construction; no policy or bound is reduced.
    pub fn for_ip_limits(limits: aligned_receiver::Limits) -> Result<Self, Error> {
        let mut plan = Self::for_limits(limits)?;
        plan.ip_headers = true;
        Ok(plan)
    }
    /// Provision compact replay slots alongside the native IP decoder.
    pub fn for_ip_limits_with_early_replay(
        limits: aligned_receiver::Limits,
    ) -> Result<Self, Error> {
        let mut plan = Self::for_ip_limits(limits)?;
        plan.capacity = aligned_receiver::Receiver::reserved_bytes(limits, true)?;
        Ok(plan)
    }
    /// Whether the actual selected state is native-IP header compression.
    pub fn ip_headers(&self) -> bool {
        self.ip_headers
    }
    /// Exact immutable receiver policy.
    pub fn limits(&self) -> aligned_receiver::Limits {
        self.limits
    }
    /// Complete actual backing, including idle transaction versions.
    pub fn capacity_bytes(&self) -> usize {
        self.capacity
    }
}

pub(crate) fn array_bytes<T>(count: usize) -> Result<usize, Error> {
    if count != 0 && size_of::<T>() == 0 {
        return Err(Error::Layout);
    }
    Layout::array::<T>(count)
        .map(|l| l.size())
        .map_err(|_| Error::Layout)
}
pub(crate) fn sum(parts: &[usize]) -> Result<usize, Error> {
    parts
        .iter()
        .try_fold(0usize, |n, p| n.checked_add(*p).ok_or(Error::Layout))
}
pub(crate) fn product(a: usize, b: usize) -> Result<usize, Error> {
    a.checked_mul(b)
        .filter(|n| *n <= isize::MAX as usize)
        .ok_or(Error::Layout)
}
pub(crate) struct Allocation {
    limit: usize,
    used: usize,
    allocations: usize,
    #[cfg(test)]
    pub(crate) fail_at: Option<usize>,
    #[cfg(test)]
    attempts: usize,
}
impl Allocation {
    pub(crate) fn new(required: usize, limits: Limits) -> Result<Self, Error> {
        if required > limits.capacity_bytes {
            return Err(Error::Limit {
                required,
                limit: limits.capacity_bytes,
            });
        }
        Ok(Self {
            limit: limits.capacity_bytes,
            used: 0,
            allocations: 0,
            #[cfg(test)]
            fail_at: None,
            #[cfg(test)]
            attempts: 0,
        })
    }
    pub(crate) fn vec<T>(&mut self, count: usize) -> Result<Vec<T>, Error> {
        let bytes = array_bytes::<T>(count)?;
        let used = self.used.checked_add(bytes).ok_or(Error::Layout)?;
        if used > self.limit {
            return Err(Error::Limit {
                required: used,
                limit: self.limit,
            });
        }
        if count == 0 {
            return Ok(Vec::new());
        }
        #[cfg(test)]
        {
            self.attempts += 1;
            if self.fail_at == Some(self.attempts) {
                return Err(Error::Allocation);
            }
        }
        let mut result = Vec::new();
        result
            .try_reserve_exact(count)
            .map_err(|_| Error::Allocation)?;
        if result.capacity() != count {
            return Err(Error::Invariant);
        }
        self.used = used;
        self.allocations += 1;
        Ok(result)
    }
    pub(crate) fn bytes(&mut self, count: usize) -> Result<Vec<u8>, Error> {
        let mut bytes = self.vec(count)?;
        bytes.resize(count, 0);
        Ok(bytes)
    }
    pub(crate) fn usage(&self) -> Usage {
        Usage {
            limit_bytes: self.limit,
            capacity_bytes: self.used,
            allocations: self.allocations,
        }
    }
    pub(crate) fn finish(&self, expected: usize) -> Result<Usage, Error> {
        if self.used != expected {
            return Err(Error::Invariant);
        }
        Ok(self.usage())
    }
}
