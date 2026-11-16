//! Fallible exact heap backing for the existing reassembly algorithm.
use super::{FragmentError, ReassemblyConfig, backing::PendingSlot};
use std::{alloc::Layout, fmt};

/// Heap-only capacity available to one actual Reassembler.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Limits {
    /// Requested retained layout ceiling.
    pub capacity_bytes: usize,
}
/// Checked allocation-free inventory; fields cannot grant forged backing.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Plan {
    config: ReassemblyConfig,
    capacity_bytes: usize,
}
impl Plan {
    /// Validate the existing config and calculate every persistent layout.
    pub fn for_reassembly(config: ReassemblyConfig) -> Result<Self, Error> {
        super::validate_reassembly(config).map_err(Error::Fragment)?;
        let presence = usize::from(config.max_fragments_per_message).min(config.max_message_bytes);
        let per_slot = array_bytes::<u8>(config.max_message_bytes)?
            .checked_add(array_bytes::<u8>(presence)?)
            .ok_or(Error::Layout)?;
        // Actual slot layout includes original first-arrival and deadline metadata
        // once. No separate scalar charge or additional reservation represents it.
        let capacity_bytes = array_bytes::<PendingSlot>(config.max_messages)?
            .checked_add(
                per_slot
                    .checked_mul(config.max_messages)
                    .ok_or(Error::Layout)?,
            )
            .and_then(|total| {
                total.checked_add(
                    array_bytes::<Option<super::MessageId>>(config.replay_window).ok()?,
                )
            })
            .and_then(|total| {
                total.checked_add(array_bytes::<super::MessageId>(config.max_messages).ok()?)
            })
            .ok_or(Error::Layout)?;
        Ok(Self {
            config,
            capacity_bytes,
        })
    }
    /// Exact validated receiver limits.
    pub fn config(&self) -> ReassemblyConfig {
        self.config
    }
    /// Complete managed heap, excluding the inline Reassembler header.
    pub fn capacity_bytes(&self) -> usize {
        self.capacity_bytes
    }
}
/// Actual persistent layouts, including empty slots, not RSS or pages.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Usage {
    /// Original supplied heap limit.
    pub limit_bytes: usize,
    /// Actual retained requested layouts.
    pub capacity_bytes: usize,
    /// Successful explicit nonzero reservations.
    pub allocations: usize,
}
/// Constructor-only failures; existing packet error meanings are unchanged.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// Existing configuration validation failed.
    Fragment(FragmentError),
    /// Checked layout or arithmetic cannot be represented.
    Layout,
    /// Complete backing exceeds the supplied limit.
    Limit {
        /// Required heap layouts.
        required: usize,
        /// Supplied heap limit.
        limit: usize,
    },
    /// A fallible reservation failed.
    Allocation,
    /// Actual capacity disagrees with the checked inventory.
    Invariant,
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "fragment storage error: {self:?}")
    }
}
impl std::error::Error for Error {}

pub(super) fn array_bytes<T>(count: usize) -> Result<usize, Error> {
    if std::mem::size_of::<T>() == 0 {
        return Err(Error::Layout);
    }
    Layout::array::<T>(count)
        .map(|layout| layout.size())
        .map_err(|_| Error::Layout)
}
pub(super) struct Allocation {
    limit: usize,
    used: usize,
    allocations: usize,
    #[cfg(test)]
    fail_at: Option<usize>,
    #[cfg(test)]
    attempts: usize,
    #[cfg(test)]
    pub(super) trace: std::rc::Rc<std::cell::RefCell<Vec<DropEvent>>>,
}
#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum DropEvent {
    Before(usize),
    After(usize),
}
impl Allocation {
    pub(super) fn new(limit: usize) -> Self {
        Self {
            limit,
            used: 0,
            allocations: 0,
            #[cfg(test)]
            fail_at: None,
            #[cfg(test)]
            attempts: 0,
            #[cfg(test)]
            trace: std::rc::Rc::default(),
        }
    }
    pub(super) fn vec<T>(&mut self, count: usize) -> Result<Vec<T>, Error> {
        let bytes = array_bytes::<T>(count)?;
        let total = self.used.checked_add(bytes).ok_or(Error::Layout)?;
        if total > self.limit {
            return Err(Error::Limit {
                required: total,
                limit: self.limit,
            });
        }
        if bytes == 0 {
            return Ok(Vec::new());
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
        self.allocations += 1;
        Ok(values)
    }
    pub(super) fn usage(&self) -> Usage {
        Usage {
            limit_bytes: self.limit,
            capacity_bytes: self.used,
            allocations: self.allocations,
        }
    }
    #[cfg(test)]
    pub(super) fn failing(limit: usize, fail_at: usize) -> Self {
        Self {
            fail_at: Some(fail_at),
            ..Self::new(limit)
        }
    }
}
