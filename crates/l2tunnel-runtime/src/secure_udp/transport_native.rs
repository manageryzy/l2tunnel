//! Runtime I/O error adaptation over the single reusable native custody owner.

use std::io;

use l2tunnel::native_storage as storage;

pub(super) type Plan<T> = storage::Plan<T>;
pub(super) type Packet<T> = storage::Packet<T>;

/// Retain the existing runtime API over the one actual pure Queue.
pub(super) struct Queue<T> {
    inner: storage::Queue<T>,
}

fn construction_error(error: storage::Error) -> io::Error {
    let kind = match error {
        storage::Error::Configuration | storage::Error::Layout | storage::Error::Invariant => {
            io::ErrorKind::InvalidInput
        }
        storage::Error::Allocation => io::ErrorKind::OutOfMemory,
        storage::Error::Limit { .. } => io::ErrorKind::Other,
    };
    kind.into()
}

fn packet_error(error: storage::Error) -> io::Error {
    let kind = match error {
        storage::Error::Configuration | storage::Error::Layout => io::ErrorKind::InvalidInput,
        storage::Error::Allocation => io::ErrorKind::OutOfMemory,
        storage::Error::Invariant | storage::Error::Limit { .. } => io::ErrorKind::InvalidData,
    };
    kind.into()
}

impl<T> Queue<T> {
    #[cfg(test)]
    pub(super) fn new(packets: usize, bytes: usize, max_native: usize) -> io::Result<Self> {
        Self::with_plan(Self::plan(packets, bytes, max_native)?)
    }

    pub(super) fn plan(packets: usize, bytes: usize, max_native: usize) -> io::Result<Plan<T>> {
        Plan::for_queue(storage::Config {
            packets,
            bytes,
            max_native,
        })
        .map_err(construction_error)
    }

    pub(super) fn with_plan(plan: Plan<T>) -> io::Result<Self> {
        let limits = storage::Limits {
            capacity_bytes: plan.capacity_bytes(),
        };
        Ok(Self {
            inner: storage::Queue::new_reserved(plan, limits).map_err(construction_error)?,
        })
    }

    pub(super) fn len(&self) -> usize {
        self.inner.len()
    }
    pub(super) fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
    pub(super) fn bytes(&self) -> usize {
        self.inner.bytes()
    }
    pub(super) fn capacity_bytes(&self) -> usize {
        self.inner.storage_usage().capacity_bytes
    }
    pub(super) fn can_acquire(&self) -> bool {
        self.inner.can_acquire()
    }

    pub(super) fn acquire(&mut self) -> Option<Lease<'_, T>> {
        self.inner.acquire().map(|inner| Lease { inner })
    }

    pub(super) fn iter(&self) -> impl Iterator<Item = &Packet<T>> {
        self.inner.iter()
    }

    pub(super) fn front(&self) -> Option<&Packet<T>> {
        self.inner.front()
    }

    pub(super) fn complete_front(&mut self) -> io::Result<()> {
        self.inner.complete_front().map_err(packet_error)
    }
}

/// Existing copy-in path borrows the same preallocated pure-owner lease.
pub(super) struct Lease<'a, T> {
    inner: storage::Lease<'a, T>,
}
impl<T> Lease<'_, T> {
    pub(super) fn output(&mut self) -> io::Result<&mut [u8]> {
        self.inner.output().map_err(packet_error)
    }
    pub(super) fn publish(self, metadata: T, since: u64, length: usize) -> io::Result<()> {
        self.inner
            .publish(metadata, since, length)
            .map_err(packet_error)
    }
    pub(super) fn copy(self, metadata: T, since: u64, input: &[u8]) -> io::Result<()> {
        self.inner
            .copy(metadata, since, input)
            .map_err(packet_error)
    }
}

#[cfg(test)]
#[path = "transport_native_tests.rs"]
mod tests;
