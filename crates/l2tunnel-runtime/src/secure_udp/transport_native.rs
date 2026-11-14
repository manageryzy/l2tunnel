//! Fallible fixed storage for extracted native packets awaiting physical writes.

use std::{alloc::Layout, collections::VecDeque, io, mem::size_of};

/// One retained packet, without authority to assert device completion.
pub(super) struct Packet<T> {
    metadata: T,
    since: u64,
    payload: Vec<u8>,
}

impl<T> Packet<T> {
    pub(super) fn metadata(&self) -> &T {
        &self.metadata
    }

    pub(super) fn since(&self) -> u64 {
        self.since
    }

    pub(super) fn bytes(&self) -> &[u8] {
        &self.payload
    }
}

/// Exactly one FIFO and a reusable pool of complete native-packet buffers.
///
/// T is trusted fixed metadata, not an additional payload owner. Requested heap
/// layouts include the ready/free headers and every empty or occupied buffer;
/// they exclude this inline owner, allocator overhead, RSS and kernel storage.
pub(super) struct Queue<T> {
    ready: VecDeque<Packet<T>>,
    free: Vec<Vec<u8>>,
    packets: usize,
    limit: usize,
    maximum: usize,
    bytes: usize,
    capacity_bytes: usize,
}

fn invalid() -> io::Error {
    io::ErrorKind::InvalidInput.into()
}

fn invariant() -> io::Error {
    io::ErrorKind::InvalidData.into()
}

fn layout<T>(count: usize) -> io::Result<usize> {
    if size_of::<T>() == 0 {
        return Err(invalid());
    }
    Layout::array::<T>(count)
        .map(|value| value.size())
        .map_err(|_| invalid())
}

#[derive(Default)]
struct Allocation {
    attempts: usize,
    #[cfg(test)]
    fail_at: Option<usize>,
}

impl Allocation {
    fn attempt(&mut self) -> io::Result<()> {
        self.attempts = self.attempts.checked_add(1).ok_or_else(invalid)?;
        #[cfg(test)]
        if self.fail_at == Some(self.attempts) {
            return Err(io::ErrorKind::OutOfMemory.into());
        }
        Ok(())
    }

    fn vector<T>(&mut self, count: usize) -> io::Result<Vec<T>> {
        layout::<T>(count)?;
        self.attempt()?;
        let mut result = Vec::new();
        result
            .try_reserve_exact(count)
            .map_err(|_| io::Error::from(io::ErrorKind::OutOfMemory))?;
        if result.capacity() != count {
            return Err(invalid());
        }
        Ok(result)
    }

    fn deque<T>(&mut self, count: usize) -> io::Result<VecDeque<T>> {
        layout::<T>(count)?;
        self.attempt()?;
        let mut result = VecDeque::new();
        result
            .try_reserve_exact(count)
            .map_err(|_| io::Error::from(io::ErrorKind::OutOfMemory))?;
        if result.capacity() != count {
            return Err(invalid());
        }
        Ok(result)
    }
}

impl<T> Queue<T> {
    /// Fully reserve every header and payload before publishing this owner.
    pub(super) fn new(packets: usize, bytes: usize, max_native: usize) -> io::Result<Self> {
        Self::allocate(packets, bytes, max_native, &mut Allocation::default())
    }

    fn allocate(
        packets: usize,
        bytes: usize,
        max_native: usize,
        allocation: &mut Allocation,
    ) -> io::Result<Self> {
        if packets == 0 || max_native == 0 || bytes < max_native {
            return Err(invalid());
        }
        let payload_bytes = layout::<u8>(max_native)?
            .checked_mul(packets)
            .ok_or_else(invalid)?;
        let capacity_bytes = layout::<Packet<T>>(packets)?
            .checked_add(layout::<Vec<u8>>(packets)?)
            .and_then(|headers| headers.checked_add(payload_bytes))
            .ok_or_else(invalid)?;
        let ready = allocation.deque(packets)?;
        let mut free = allocation.vector(packets)?;
        for _ in 0..packets {
            free.push(allocation.vector(max_native)?);
        }
        Ok(Self {
            ready,
            free,
            packets,
            limit: bytes,
            maximum: max_native,
            bytes: 0,
            capacity_bytes,
        })
    }

    pub(super) fn len(&self) -> usize {
        self.ready.len()
    }

    pub(super) fn is_empty(&self) -> bool {
        self.ready.is_empty()
    }

    pub(super) fn bytes(&self) -> usize {
        self.bytes
    }

    pub(super) fn capacity_bytes(&self) -> usize {
        self.capacity_bytes
    }

    /// Preserve the existing conservative whole-maximum-packet admission rule.
    pub(super) fn can_acquire(&self) -> bool {
        !self.free.is_empty()
            && self.ready.len() < self.packets
            && self
                .bytes
                .checked_add(self.maximum)
                .is_some_and(|bytes| bytes <= self.limit)
    }

    /// Hold an existing empty buffer before extracting an Engine packet.
    pub(super) fn acquire(&mut self) -> Option<Lease<'_, T>> {
        if !self.can_acquire() {
            return None;
        }
        let payload = self.free.pop()?;
        Some(Lease {
            queue: self,
            payload: Some(payload),
        })
    }

    #[cfg(test)]
    pub(super) fn front_metadata_mut(&mut self) -> Option<&mut T> {
        self.ready.front_mut().map(|packet| &mut packet.metadata)
    }

    #[cfg(test)]
    pub(super) fn iter(&self) -> impl Iterator<Item = &Packet<T>> {
        self.ready.iter()
    }

    pub(super) fn front(&self) -> Option<&Packet<T>> {
        self.ready.front()
    }

    /// Recycle exactly one item only after complete physical device acceptance.
    /// Every fallible accounting/capacity check precedes FIFO or pool mutation.
    pub(super) fn complete_front(&mut self) -> io::Result<()> {
        let packet = self.ready.front().ok_or_else(invariant)?;
        let bytes = self
            .bytes
            .checked_sub(packet.payload.len())
            .ok_or_else(invariant)?;
        if packet.payload.is_empty()
            || packet.payload.len() > self.maximum
            || packet.payload.capacity() != self.maximum
            || self.bytes > self.limit
            || self.ready.len().checked_add(self.free.len()) != Some(self.packets)
            || self.free.len() >= self.free.capacity()
            || (self.ready.len() == 1 && bytes != 0)
        {
            return Err(invariant());
        }
        let packet = self.ready.pop_front().ok_or_else(invariant)?;
        let mut payload = packet.payload;
        payload.clear();
        self.free.push(payload);
        self.bytes = bytes;
        Ok(())
    }
}

/// Exclusive buffer custody; dropping it returns the original allocation.
pub(super) struct Lease<'a, T> {
    queue: &'a mut Queue<T>,
    payload: Option<Vec<u8>>,
}

impl<T> Lease<'_, T> {
    /// Copy one complete native packet without changing its origin or first age.
    /// Refusal returns the leased buffer through Drop and enqueues nothing.
    pub(super) fn copy(mut self, metadata: T, since: u64, input: &[u8]) -> io::Result<()> {
        if input.is_empty() || input.len() > self.queue.maximum {
            return Err(invalid());
        }
        let bytes = self
            .queue
            .bytes
            .checked_add(input.len())
            .ok_or_else(invariant)?;
        let payload = self.payload.as_ref().ok_or_else(invariant)?;
        if bytes > self.queue.limit
            || self.queue.ready.len() >= self.queue.packets
            || self.queue.ready.len() >= self.queue.ready.capacity()
            || !payload.is_empty()
            || payload.capacity() != self.queue.maximum
        {
            return Err(invariant());
        }
        let mut payload = self.payload.take().ok_or_else(invariant)?;
        payload.extend_from_slice(input);
        self.queue.ready.push_back(Packet {
            metadata,
            since,
            payload,
        });
        self.queue.bytes = bytes;
        Ok(())
    }
}

impl<T> Drop for Lease<'_, T> {
    fn drop(&mut self) {
        if let Some(mut payload) = self.payload.take() {
            payload.clear();
            // Acquisition removed exactly one buffer. This exclusive borrow
            // prevents another producer or completion from consuming its slot.
            self.queue.free.push(payload);
        }
    }
}

#[cfg(test)]
#[path = "transport_native_tests.rs"]
mod tests;
