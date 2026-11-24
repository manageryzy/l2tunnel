//! Actual requested and observed heap backing, reusing the existing rolling inventory.
use super::{Config, Receiver, Sender, Tick, deadline, rolling};
pub use rolling::storage::{Error, Limits, Usage};

/// Complete pre-admission plan for one research owner, excluding its inline header.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Plan {
    config: Config,
    receiver: bool,
    usage: Usage,
}
impl Plan {
    /// Plan existing encoder vectors under both conservative memory guards.
    pub fn for_sender(config: Config) -> Result<Self, Error> {
        config.validate()?;
        if Sender::memory_bound(config)? > config.memory_bytes
            || rolling::Encoder::sliding_memory_bound(config.recovery)?
                > config.recovery.memory_bytes
        {
            return Err(Error::Capacity);
        }
        Ok(Self {
            config,
            receiver: false,
            usage: rolling::Encoder::sliding_requested_storage(config.recovery)?,
        })
    }
    /// Plan all existing decoder banks, transaction metadata, history and scratch.
    pub fn for_receiver(config: Config) -> Result<Self, Error> {
        config.validate()?;
        if Receiver::memory_bound(config)? > config.memory_bytes
            || rolling::Decoder::sliding_memory_bound(config.recovery)?
                > config.recovery.memory_bytes
        {
            return Err(Error::Capacity);
        }
        Ok(Self {
            config,
            receiver: true,
            usage: rolling::Decoder::sliding_requested_storage(config.recovery)?,
        })
    }
    /// Exact requested retained allocation capacities; allocator/RSS overhead is excluded.
    pub fn capacity_bytes(self) -> usize {
        self.usage.capacity_bytes
    }
    /// Number of nonempty nested fixed vector allocations.
    pub fn allocations(self) -> usize {
        self.usage.allocations
    }
    pub(super) fn admit(self, limits: Limits, now: Tick) -> Result<(), Error> {
        for ticks in [
            self.config.feedback_ticks,
            self.config.recovery.job_ticks,
            self.config.recovery.debt_ticks,
        ] {
            deadline(now, ticks)?;
        }
        if self.receiver {
            deadline(now, self.config.recovery.handoff_ticks)?;
        }
        if self.usage.capacity_bytes > limits.capacity_bytes {
            return Err(Error::Capacity);
        }
        Ok(())
    }
    pub(super) fn verify(self, usage: Usage, limits: Limits) -> Result<(), Error> {
        if usage.capacity_bytes > limits.capacity_bytes {
            return Err(Error::Capacity);
        }
        if usage != self.usage {
            return Err(Error::Layout);
        }
        Ok(())
    }
}
