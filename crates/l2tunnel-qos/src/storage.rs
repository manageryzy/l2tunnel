//! Complete fallible backing for the actual weighted-DRR Scheduler.
use super::{ClassConfig, ConfigError, FlowId, SchedulerConfig, backing};
use std::{alloc::Layout, fmt};

/// Explicit maximum retained managed heap layout.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Limits {
    /// Actual class/flow/ring/packet/slab allowance, excluding inline owners.
    pub capacity_bytes: usize,
}
/// Actual complete retained backing, not allocator overhead or RSS.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Usage {
    /// Original explicit construction allowance.
    pub limit_bytes: usize,
    /// Actual retained managed heap layouts, including idle slots.
    pub capacity_bytes: usize,
    /// Successful nonzero backing reservations.
    pub allocations: usize,
}
/// Construction refusal without reduced dimensions or allocating fallback.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// Existing Scheduler scalar validation failure.
    Configuration(ConfigError),
    /// A checked product, aggregate or Rust array layout cannot be represented.
    Layout,
    /// Complete requested capacity exceeds the explicit limit.
    Limit {
        /// Full actual backing requirement.
        required: usize,
        /// Supplied construction allowance.
        limit: usize,
    },
    /// Fallible backing reservation failed.
    Allocation,
    /// Actual backing capacity disagrees with the checked inventory.
    Invariant,
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "scheduler storage: {self:?}")
    }
}
impl std::error::Error for Error {}

/// Allocation-free complete inventory for one direction's Scheduler.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Plan {
    config: SchedulerConfig,
    classes: usize,
    bytes: usize,
}
impl Plan {
    /// Preserve existing scalar validation before calculating physical backing.
    pub fn for_scheduler(config: SchedulerConfig, classes: &[ClassConfig]) -> Result<Self, Error> {
        config.validate(classes).map_err(Error::Configuration)?;
        let slab = config
            .max_queued_packets
            .checked_mul(config.max_packet_bytes)
            .ok_or(Error::Layout)?;
        let bytes = sum(&[
            array::<ClassConfig>(classes.len())?,
            array::<Option<backing::Registered>>(config.max_flows)?,
            array::<backing::Index>(config.max_flows)?,
            array::<usize>(config.max_flows)?,
            array::<FlowId>(config.max_flows)?,
            array::<backing::Packet>(config.max_queued_packets)?,
            array::<usize>(config.max_queued_packets)?,
            array::<u8>(slab)?,
        ])?;
        Ok(Self {
            config,
            classes: classes.len(),
            bytes,
        })
    }
    /// Complete original scalar policy.
    pub fn config(&self) -> SchedulerConfig {
        self.config
    }
    /// Number of immutable classes actually supplied at construction.
    pub fn class_count(&self) -> usize {
        self.classes
    }
    /// Actual retained managed heap capacity, excluding inline Scheduler headers.
    pub fn capacity_bytes(&self) -> usize {
        self.bytes
    }
}
fn array<T>(count: usize) -> Result<usize, Error> {
    if count != 0 && std::mem::size_of::<T>() == 0 {
        return Err(Error::Layout);
    }
    Layout::array::<T>(count)
        .map(|l| l.size())
        .map_err(|_| Error::Layout)
}
fn sum(parts: &[usize]) -> Result<usize, Error> {
    parts
        .iter()
        .try_fold(0usize, |a, b| a.checked_add(*b).ok_or(Error::Layout))
}
pub(super) struct Allocation {
    limit: usize,
    used: usize,
    count: usize,
    #[cfg(test)]
    pub(super) fail_at: Option<usize>,
    #[cfg(test)]
    attempts: usize,
    #[cfg(test)]
    pub(super) trace: Option<std::rc::Rc<std::cell::RefCell<Vec<backing::Event>>>>,
}
impl Allocation {
    pub(super) fn new(plan: Plan, limits: Limits) -> Result<Self, Error> {
        if plan.bytes > limits.capacity_bytes {
            return Err(Error::Limit {
                required: plan.bytes,
                limit: limits.capacity_bytes,
            });
        }
        Ok(Self {
            limit: limits.capacity_bytes,
            used: 0,
            count: 0,
            #[cfg(test)]
            fail_at: None,
            #[cfg(test)]
            attempts: 0,
            #[cfg(test)]
            trace: None,
        })
    }
    pub(super) fn vec<T>(&mut self, count: usize) -> Result<Vec<T>, Error> {
        let used = sum(&[self.used, array::<T>(count)?])?;
        if used > self.limit {
            return Err(Error::Invariant);
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
        self.count += 1;
        Ok(result)
    }
    pub(super) fn finish(&self, plan: Plan) -> Result<Usage, Error> {
        if self.used != plan.bytes {
            return Err(Error::Invariant);
        }
        Ok(Usage {
            limit_bytes: self.limit,
            capacity_bytes: self.used,
            allocations: self.count,
        })
    }
}
