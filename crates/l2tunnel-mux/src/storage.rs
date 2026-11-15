//! Checked complete retained heap inventory for queued or inline-only MUX owners.
use crate::{Lane, Slot};
use std::{alloc::Layout, fmt};

/// Explicit managed heap allowance, excluding the enclosing inline MUX.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Limits {
    /// Maximum retained heap capacity.
    pub capacity_bytes: usize,
}
/// Actual retained capacity, independent of logical occupied bytes/frames.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Usage {
    /// Original construction allowance.
    pub limit_bytes: usize,
    /// Actual complete retained heap capacity.
    pub capacity_bytes: usize,
    /// Successful nonzero fallible reservations.
    pub allocations: usize,
}
/// Fallible construction refusal without a legacy fallback.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// Existing logical limits or the explicit physical maximum are invalid.
    Configuration,
    /// A checked array layout, product or sum cannot be represented.
    Layout,
    /// Complete required heap exceeds the supplied allowance.
    Limit {
        /// Required managed heap capacity.
        required: usize,
        /// Supplied allowance.
        limit: usize,
    },
    /// A fallible reservation failed.
    Allocation,
    /// Actual capacity differs from the admitted plan.
    Invariant,
}
impl fmt::Display for Error {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(output, "MUX storage: {self:?}")
    }
}
impl std::error::Error for Error {}

/// Allocation-free complete queue or inline-only handoff inventory.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Plan {
    channels: u16,
    byte_limit: usize,
    frame_limit: usize,
    max_frame_bytes: Option<usize>,
    capacity_bytes: usize,
}
impl Plan {
    /// Plan globally reusable frame slots and their full physical payload slabs.
    pub fn for_queue(
        channels: u16,
        byte_limit: usize,
        frame_limit: usize,
        max_frame_bytes: usize,
    ) -> Result<Self, Error> {
        validate(channels, byte_limit, frame_limit)?;
        if max_frame_bytes == 0 {
            return Err(Error::Configuration);
        }
        let slab = frame_limit
            .checked_mul(max_frame_bytes)
            .ok_or(Error::Layout)?;
        let capacity_bytes = sum(&[
            array_bytes::<Lane>(usize::from(channels))?,
            array_bytes::<Slot>(frame_limit)?,
            array_bytes::<usize>(frame_limit)?,
            array_bytes::<u8>(slab)?,
        ])?;
        Ok(Self {
            channels,
            byte_limit,
            frame_limit,
            max_frame_bytes: Some(max_frame_bytes),
            capacity_bytes,
        })
    }
    /// Plan actual inline-only empty-MUX admission, without unused payload queues.
    pub fn for_handoff(
        channels: u16,
        byte_limit: usize,
        frame_limit: usize,
    ) -> Result<Self, Error> {
        validate(channels, byte_limit, frame_limit)?;
        Ok(Self {
            channels,
            byte_limit,
            frame_limit,
            max_frame_bytes: None,
            capacity_bytes: 0,
        })
    }
    /// Complete retained heap, excluding the enclosing inline MUX header.
    pub const fn capacity_bytes(&self) -> usize {
        self.capacity_bytes
    }
    /// Full exact configured channel width.
    pub const fn channels(&self) -> u16 {
        self.channels
    }
    /// Unchanged shared logical byte limit.
    pub const fn byte_limit(&self) -> usize {
        self.byte_limit
    }
    /// Unchanged shared logical frame limit.
    pub const fn frame_limit(&self) -> usize {
        self.frame_limit
    }
    /// Explicit physical queue slot maximum; absent for inline-only handoff.
    pub const fn max_frame_bytes(&self) -> Option<usize> {
        self.max_frame_bytes
    }
    /// Whether this actual owner has no queued-payload backing.
    pub const fn is_handoff(&self) -> bool {
        self.max_frame_bytes.is_none()
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

pub(crate) fn validate(channels: u16, bytes: usize, frames: usize) -> Result<(), Error> {
    if !(1..=256).contains(&channels) || bytes == 0 || frames == 0 {
        Err(Error::Configuration)
    } else {
        Ok(())
    }
}
pub(crate) fn array_bytes<T>(count: usize) -> Result<usize, Error> {
    Layout::array::<T>(count)
        .map(|layout| layout.size())
        .map_err(|_| Error::Layout)
}
pub(crate) fn sum(parts: &[usize]) -> Result<usize, Error> {
    parts.iter().try_fold(0usize, |total, value| {
        total.checked_add(*value).ok_or(Error::Layout)
    })
}
pub(crate) fn reserve<T>(count: usize) -> Result<Vec<T>, Error> {
    array_bytes::<T>(count)?;
    let mut values = Vec::new();
    values
        .try_reserve_exact(count)
        .map_err(|_| Error::Allocation)?;
    Ok(values)
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
        #[cfg(test)]
        {
            self.attempts += 1;
            if self.fail_at == Some(self.attempts) {
                return Err(Error::Allocation);
            }
        }
        reserve(count)
    }
    pub(crate) fn copy(&mut self, bytes: &[u8]) -> Result<Vec<u8>, Error> {
        let mut output = self.reserve(bytes.len())?;
        output.extend_from_slice(bytes);
        Ok(output)
    }
    #[cfg(test)]
    pub(crate) fn failing(attempt: usize) -> Self {
        Self {
            fail_at: Some(attempt),
            ..Self::default()
        }
    }
}
pub(crate) fn copy(bytes: &[u8]) -> Result<Vec<u8>, Error> {
    Allocation::default().copy(bytes)
}
