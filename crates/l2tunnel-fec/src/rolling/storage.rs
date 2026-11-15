//! Exact requested and observed rolling scheduler heap capacities.
//!
//! Owner headers are excluded: an embedding owner must count each inline header
//! once. These are retained Rust allocation layouts, not allocator bookkeeping,
//! resident memory, kernel storage or a promise that an allocation cannot fail.
use super::{Config, Decoder, Encoder, Tick, deadline, scheduler};
use std::fmt;

/// Heap capacity admitted independently of the legacy conservative owner caps.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Limits {
    /// Maximum summed retained nested allocation capacities, in bytes.
    pub capacity_bytes: usize,
}

/// Observed capacities of the actual encoder/decoder and their existing buffers.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Usage {
    /// Actual summed `Vec::capacity() * size_of::<T>()`, excluding owner headers.
    pub capacity_bytes: usize,
    /// Actual nonempty retained allocations; no allocation-call history is implied.
    pub allocations: usize,
}

impl Usage {
    pub(super) fn vector<T>(value: &Vec<T>) -> Result<Self, Error> {
        Ok(Self {
            capacity_bytes: value
                .capacity()
                .checked_mul(std::mem::size_of::<T>())
                .ok_or(Error::Overflow)?,
            allocations: usize::from(value.capacity() != 0 && std::mem::size_of::<T>() != 0),
        })
    }

    pub(super) fn join(self, other: Self) -> Result<Self, Error> {
        Ok(Self {
            capacity_bytes: self
                .capacity_bytes
                .checked_add(other.capacity_bytes)
                .ok_or(Error::Overflow)?,
            allocations: self
                .allocations
                .checked_add(other.allocations)
                .ok_or(Error::Overflow)?,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Kind {
    Sender,
    Receiver,
}

/// Allocation-free complete requested heap layout for one existing scheduler.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Plan {
    policy: scheduler::Policy,
    kind: Kind,
    usage: Usage,
}

impl Plan {
    /// Plan the actual sender buffers and preserve both legacy reservation guards.
    pub fn for_sender(policy: scheduler::Policy) -> Result<Self, Error> {
        policy.validate()?;
        if Encoder::memory_bound(policy.recovery)? > policy.recovery.memory_bytes
            || scheduler::Sender::memory_bound(policy)? > policy.memory_bytes
        {
            return Err(Error::Recovery(super::Error::Capacity));
        }
        Ok(Self {
            policy,
            kind: Kind::Sender,
            usage: Encoder::requested_storage(policy.recovery)?,
        })
    }

    /// Plan every real decoder bank, decision/free pool, history and scratch buffer.
    pub fn for_receiver(policy: scheduler::Policy) -> Result<Self, Error> {
        policy.validate()?;
        if Decoder::memory_bound(policy.recovery)? > policy.recovery.memory_bytes
            || scheduler::Receiver::memory_bound(policy)? > policy.memory_bytes
        {
            return Err(Error::Recovery(super::Error::Capacity));
        }
        Ok(Self {
            policy,
            kind: Kind::Receiver,
            usage: Decoder::requested_storage(policy.recovery)?,
        })
    }

    /// Complete unchanged recovery and scheduling policy used to construct this plan.
    pub fn policy(self) -> scheduler::Policy {
        self.policy
    }

    /// Complete requested nested heap bytes, excluding inline owner headers.
    pub fn capacity_bytes(self) -> usize {
        self.usage.capacity_bytes
    }

    /// Number of real fixed nonempty allocation reservations in the requested layout.
    pub fn allocations(self) -> usize {
        self.usage.allocations
    }

    pub(super) fn admit(self, limits: Limits, now: Tick) -> Result<(), Error> {
        // All constructor-time additions precede the first nested allocation.
        let config = self.policy.recovery;
        deadline(now, config.job_ticks)?;
        deadline(now, config.debt_ticks)?;
        match self.kind {
            Kind::Sender => {
                deadline(now, self.policy.tail_ticks)?;
            }
            Kind::Receiver => {
                deadline(now, config.handoff_ticks)?;
                deadline(now, self.policy.feedback_ticks)?;
            }
        }
        if self.capacity_bytes() > limits.capacity_bytes {
            return Err(Error::Capacity);
        }
        Ok(())
    }

    pub(super) fn verify(self, usage: Usage, limits: Limits) -> Result<(), Error> {
        if usage.capacity_bytes > limits.capacity_bytes {
            return Err(Error::Capacity);
        }
        // try_reserve_exact is fallible and may legally retain extra capacity.
        // Reject that layout instead of publishing a falsely exact observation.
        if usage != self.usage {
            return Err(Error::Layout);
        }
        Ok(())
    }
}

/// Explicit arithmetic, configured-capacity and underlying recovery failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// A checked complete heap-layout calculation overflowed.
    Overflow,
    /// Requested or observed nested heap capacity exceeds the admitted limit.
    Capacity,
    /// The actual retained layout differs from the pre-admitted exact plan.
    Layout,
    /// Existing policy, conservative cap, time, allocation or recovery refusal.
    Recovery(super::Error),
}

impl From<super::Error> for Error {
    fn from(value: super::Error) -> Self {
        Self::Recovery(value)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "rolling storage: {self:?}")
    }
}
impl std::error::Error for Error {}

pub(super) fn requested<T>(count: usize) -> Result<Usage, Error> {
    Ok(Usage {
        capacity_bytes: count
            .checked_mul(std::mem::size_of::<T>())
            .ok_or(Error::Overflow)?,
        allocations: usize::from(count != 0 && std::mem::size_of::<T>() != 0),
    })
}

pub(super) fn width(config: Config) -> Result<usize, Error> {
    Ok(config.width()?)
}

#[cfg(test)]
mod tests;
