//! Exact retained heap inventories; allocator metadata and caller buffers are excluded.
use super::{Config, Receiver, Sender, Tick, deadline, rolling};
pub use rolling::storage::{Error, Limits, Usage};

/// Pre-admission heap plan for one complete legacy protocol owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Plan {
    config: Config,
    usage: Usage,
}
impl Plan {
    /// Plan every encoder, flight, frozen equation and feedback-copy allocation.
    pub fn for_sender(config: Config) -> Result<Self, Error> {
        config.validate()?;
        if Sender::memory_bound(config)? > config.memory_bytes
            || rolling::Encoder::explicit_memory_bound(config.recovery)?
                > config.recovery.memory_bytes
        {
            return Err(Error::Capacity);
        }
        Ok(Self {
            config,
            usage: Sender::requested_storage(config)?,
        })
    }
    /// Plan the selected sender including its finite metadata-only unsent queue.
    pub fn for_sender_admission(config: Config) -> Result<Self, Error> {
        config.validate()?;
        if Sender::memory_bound_admission(config)? > config.memory_bytes
            || rolling::Encoder::explicit_memory_bound(config.recovery)?
                > config.recovery.memory_bytes
        {
            return Err(Error::Capacity);
        }
        Ok(Self {
            config,
            usage: Sender::requested_storage_in(config, true)?,
        })
    }
    /// Plan all decoder banks, exact coefficient history and receipt buffers.
    pub fn for_receiver(config: Config) -> Result<Self, Error> {
        config.validate()?;
        if Receiver::memory_bound(config)? > config.memory_bytes
            || rolling::Decoder::explicit_memory_bound(config.recovery)?
                > config.recovery.memory_bytes
        {
            return Err(Error::Capacity);
        }
        Ok(Self {
            config,
            usage: Receiver::requested_storage(config)?,
        })
    }
    /// Summed requested nested capacities, excluding inline owner headers.
    pub fn capacity_bytes(self) -> usize {
        self.usage.capacity_bytes
    }
    /// Number of nonempty retained vector allocations.
    pub fn allocations(self) -> usize {
        self.usage.allocations
    }
    pub(super) fn admit(self, limits: Limits, now: Tick) -> Result<(), Error> {
        for ticks in [
            self.config.recovery.job_ticks,
            self.config.recovery.debt_ticks,
            self.config.recovery.handoff_ticks,
            self.config.fec_wait_ticks,
            self.config.feedback_wait_ticks,
            self.config.rto_min_ticks,
        ] {
            deadline(now, ticks)?;
        }
        if self.usage.capacity_bytes > limits.capacity_bytes {
            return Err(Error::Capacity);
        }
        Ok(())
    }
    pub(super) fn verify(self, actual: Usage, limits: Limits) -> Result<(), Error> {
        if actual.capacity_bytes > limits.capacity_bytes {
            return Err(Error::Capacity);
        }
        if actual != self.usage {
            return Err(Error::Layout);
        }
        Ok(())
    }
}
pub(super) fn requested<T>(count: usize) -> Result<Usage, Error> {
    Ok(Usage {
        capacity_bytes: count
            .checked_mul(std::mem::size_of::<T>())
            .ok_or(Error::Overflow)?,
        allocations: usize::from(count != 0 && std::mem::size_of::<T>() != 0),
    })
}
pub(super) fn vector<T>(value: &Vec<T>) -> Result<Usage, Error> {
    requested::<T>(value.capacity())
}
pub(super) fn join(a: Usage, b: Usage) -> Result<Usage, Error> {
    Ok(Usage {
        capacity_bytes: a
            .capacity_bytes
            .checked_add(b.capacity_bytes)
            .ok_or(Error::Overflow)?,
        allocations: a
            .allocations
            .checked_add(b.allocations)
            .ok_or(Error::Overflow)?,
    })
}
