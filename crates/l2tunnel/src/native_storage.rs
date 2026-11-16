//! Actual preallocated native-packet custody, with caller-observed completion.
//!
//! This is the existing ready FIFO/free-buffer owner extracted from the runtime.
//! It performs no I/O, clock sampling, authentication or native-delivery proof.
//! Usage counts this Queue's allocations; arbitrary heaps inside T remain the
//! caller's responsibility. Selected runtime metadata is fixed inline data.

use std::{alloc::Layout, collections::VecDeque, marker::PhantomData, mem::size_of};

/// Original independent packet, logical-byte and maximum-packet bounds.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Config {
    /// Number of actual reusable complete-packet buffers.
    pub packets: usize,
    /// Maximum logical ready payload bytes.
    pub bytes: usize,
    /// Exact reserved capacity of each payload buffer.
    pub max_native: usize,
}

/// Complete Queue-owned heap allowance, excluding its inline header.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Limits {
    /// Maximum retained requested allocation layouts.
    pub capacity_bytes: usize,
}

/// Actual Queue-owned backing, including all idle buffers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Usage {
    /// Original complete construction allowance.
    pub limit_bytes: usize,
    /// Actual ready/free metadata and payload allocation-layout capacity.
    pub capacity_bytes: usize,
    /// Explicit retained nonempty allocations, not process allocations.
    pub allocations: usize,
}

/// Explicit configuration, layout, admission or actual backing failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// Zero/inconsistent geometry, empty input or invalid initialized length.
    Configuration,
    /// A checked layout, count, product or total cannot be represented.
    Layout,
    /// Complete actual Queue backing exceeds the supplied allowance.
    Limit {
        /// Complete required Queue heap capacity.
        required: usize,
        /// Supplied allowance.
        limit: usize,
    },
    /// An actual fallible reservation failed.
    Allocation,
    /// Actual capacity, free/ready inventory or retained accounting disagrees.
    Invariant,
}
impl std::fmt::Display for Error {
    fn fmt(&self, output: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(output, "native custody storage failed: {self:?}")
    }
}
impl std::error::Error for Error {}

/// One retained original packet, without authority to assert physical completion.
pub struct Packet<T> {
    metadata: T,
    since: u64,
    payload: Vec<u8>,
}
impl<T> Packet<T> {
    /// Exact caller-supplied fixed metadata, with its original ownership.
    pub fn metadata(&self) -> &T {
        &self.metadata
    }
    /// Original caller-injected first age, never refreshed by observation.
    pub fn since(&self) -> u64 {
        self.since
    }
    /// Exact initialized original bytes retained until complete acknowledgment.
    pub fn bytes(&self) -> &[u8] {
        &self.payload
    }
}

/// Immutable allocation-free complete plan tied to the actual metadata type.
pub struct Plan<T> {
    config: Config,
    capacity_bytes: usize,
    allocations: usize,
    metadata: PhantomData<fn() -> T>,
}
impl<T> Plan<T> {
    /// Validate every original bound and full actual layout before allocation.
    pub fn for_queue(config: Config) -> Result<Self, Error> {
        if config.packets == 0 || config.max_native == 0 || config.bytes < config.max_native {
            return Err(Error::Configuration);
        }
        let payload_bytes = layout::<u8>(config.max_native)?
            .checked_mul(config.packets)
            .ok_or(Error::Layout)?;
        let capacity_bytes = layout::<Packet<T>>(config.packets)?
            .checked_add(layout::<Vec<u8>>(config.packets)?)
            .and_then(|headers| headers.checked_add(payload_bytes))
            .ok_or(Error::Layout)?;
        let allocations = config.packets.checked_add(2).ok_or(Error::Layout)?;
        Ok(Self {
            config,
            capacity_bytes,
            allocations,
            metadata: PhantomData,
        })
    }
    /// Exact original geometry; no byte/count dimension is silently clamped.
    pub fn config(&self) -> Config {
        self.config
    }
    /// Complete actual Queue heap, excluding inline Self and arbitrary T heaps.
    pub fn capacity_bytes(&self) -> usize {
        self.capacity_bytes
    }
}

/// Exactly one ready FIFO and its actual reusable complete-packet buffer pool.
pub struct Queue<T> {
    ready: VecDeque<Packet<T>>,
    free: Vec<Vec<u8>>,
    packets: usize,
    limit: usize,
    maximum: usize,
    bytes: usize,
    usage: Usage,
}

fn layout<T>(count: usize) -> Result<usize, Error> {
    if size_of::<T>() == 0 {
        return Err(Error::Layout);
    }
    Layout::array::<T>(count)
        .map(|value| value.size())
        .map_err(|_| Error::Layout)
}

#[derive(Default)]
struct Allocation {
    attempts: usize,
    #[cfg(test)]
    fail_at: Option<usize>,
}
impl Allocation {
    fn attempt(&mut self) -> Result<(), Error> {
        self.attempts = self.attempts.checked_add(1).ok_or(Error::Layout)?;
        #[cfg(test)]
        if self.fail_at == Some(self.attempts) {
            return Err(Error::Allocation);
        }
        Ok(())
    }
    fn vector<T>(&mut self, count: usize) -> Result<Vec<T>, Error> {
        layout::<T>(count)?;
        self.attempt()?;
        let mut result = Vec::new();
        result
            .try_reserve_exact(count)
            .map_err(|_| Error::Allocation)?;
        if result.capacity() != count {
            return Err(Error::Invariant);
        }
        Ok(result)
    }
    fn deque<T>(&mut self, count: usize) -> Result<VecDeque<T>, Error> {
        layout::<T>(count)?;
        self.attempt()?;
        let mut result = VecDeque::new();
        result
            .try_reserve_exact(count)
            .map_err(|_| Error::Allocation)?;
        if result.capacity() != count {
            return Err(Error::Invariant);
        }
        Ok(result)
    }
}

impl<T> Queue<T> {
    /// Provision all P+2 actual reservations after complete limit preflight.
    /// No legacy fallback or payload allocation occurs during later service.
    pub fn new_reserved(plan: Plan<T>, limits: Limits) -> Result<Self, Error> {
        Self::allocate_plan(plan, limits, &mut Allocation::default())
    }
    fn allocate_plan(
        plan: Plan<T>,
        limits: Limits,
        allocation: &mut Allocation,
    ) -> Result<Self, Error> {
        if plan.capacity_bytes > limits.capacity_bytes {
            return Err(Error::Limit {
                required: plan.capacity_bytes,
                limit: limits.capacity_bytes,
            });
        }
        let Config {
            packets,
            bytes: limit,
            max_native: maximum,
        } = plan.config;
        let ready = allocation.deque(packets)?;
        let mut free = allocation.vector(packets)?;
        for _ in 0..packets {
            free.push(allocation.vector(maximum)?);
        }
        let actual = layout::<Packet<T>>(ready.capacity())?
            .checked_add(layout::<Vec<u8>>(free.capacity())?)
            .and_then(|bytes| {
                free.iter().try_fold(bytes, |bytes, payload| {
                    bytes.checked_add(payload.capacity())
                })
            })
            .ok_or(Error::Layout)?;
        if actual != plan.capacity_bytes {
            return Err(Error::Invariant);
        }
        Ok(Self {
            ready,
            free,
            packets,
            limit,
            maximum,
            bytes: 0,
            usage: Usage {
                limit_bytes: limits.capacity_bytes,
                capacity_bytes: actual,
                allocations: plan.allocations,
            },
        })
    }
    /// Actual retained Queue-owned layouts, independent of occupied packet bytes.
    pub fn storage_usage(&self) -> Usage {
        self.usage
    }
    /// Actual ready packet count, excluding a temporarily acquired lease.
    pub fn len(&self) -> usize {
        self.ready.len()
    }
    /// Whether no published original packet awaits physical acknowledgment.
    pub fn is_empty(&self) -> bool {
        self.ready.is_empty()
    }
    /// Logical bytes retained in published ready packets.
    pub fn bytes(&self) -> usize {
        self.bytes
    }
    /// Original conservative whole-maximum-packet admission, without mutation.
    pub fn can_acquire(&self) -> bool {
        !self.free.is_empty()
            && self.ready.len() < self.packets
            && self
                .bytes
                .checked_add(self.maximum)
                .is_some_and(|bytes| bytes <= self.limit)
    }
    /// Hold an actual existing buffer before advancing packet extraction.
    pub fn acquire(&mut self) -> Option<Lease<'_, T>> {
        if !self.can_acquire() {
            return None;
        }
        let payload = self.free.pop()?;
        Some(Lease {
            queue: self,
            payload: Some(payload),
        })
    }
    /// Observe the immutable FIFO head without refreshing its age or completing it.
    pub fn front(&self) -> Option<&Packet<T>> {
        self.ready.front()
    }
    /// Observe at most P retained packets in FIFO order without mutation.
    pub fn iter(&self) -> impl Iterator<Item = &Packet<T>> {
        self.ready.iter()
    }
    /// Move the retained head to the tail without completing or copying it.
    /// A caller may scan at most its initial length to service independent work.
    pub fn rotate_front(&mut self) -> Result<(), Error> {
        if self.ready.is_empty() {
            return Err(Error::Invariant);
        }
        self.ready.rotate_left(1);
        Ok(())
    }
    /// Recycle exactly one complete packet after caller-observed physical acceptance.
    /// Every fallible accounting check precedes FIFO/free-pool mutation.
    pub fn complete_front(&mut self) -> Result<(), Error> {
        let packet = self.ready.front().ok_or(Error::Invariant)?;
        let bytes = self
            .bytes
            .checked_sub(packet.payload.len())
            .ok_or(Error::Invariant)?;
        if packet.payload.is_empty()
            || packet.payload.len() > self.maximum
            || packet.payload.capacity() != self.maximum
            || self.bytes > self.limit
            || self.ready.len().checked_add(self.free.len()) != Some(self.packets)
            || self.free.len() >= self.free.capacity()
            || (self.ready.len() == 1 && bytes != 0)
        {
            return Err(Error::Invariant);
        }
        let packet = self.ready.pop_front().ok_or(Error::Invariant)?;
        let mut payload = packet.payload;
        payload.clear();
        self.free.push(payload);
        self.bytes = bytes;
        Ok(())
    }

    #[cfg(test)]
    fn new(packets: usize, bytes: usize, max_native: usize) -> Result<Self, Error> {
        Self::with_plan(Self::plan(packets, bytes, max_native)?)
    }
    #[cfg(test)]
    fn plan(packets: usize, bytes: usize, max_native: usize) -> Result<Plan<T>, Error> {
        Plan::for_queue(Config {
            packets,
            bytes,
            max_native,
        })
    }
    #[cfg(test)]
    fn with_plan(plan: Plan<T>) -> Result<Self, Error> {
        let limits = Limits {
            capacity_bytes: plan.capacity_bytes(),
        };
        Self::new_reserved(plan, limits)
    }
    #[cfg(test)]
    fn allocate(
        packets: usize,
        bytes: usize,
        max_native: usize,
        allocation: &mut Allocation,
    ) -> Result<Self, Error> {
        let plan = Self::plan(packets, bytes, max_native)?;
        let limits = Limits {
            capacity_bytes: plan.capacity_bytes(),
        };
        Self::allocate_plan(plan, limits, allocation)
    }
    #[cfg(test)]
    fn capacity_bytes(&self) -> usize {
        self.usage.capacity_bytes
    }
}

/// Exclusive actual buffer custody; Drop returns the same allocation unpublished.
pub struct Lease<'a, T> {
    queue: &'a mut Queue<T>,
    payload: Option<Vec<u8>>,
}
impl<T> Lease<'_, T> {
    fn publication(&self, length: usize) -> Result<usize, Error> {
        if length == 0 || length > self.queue.maximum {
            return Err(Error::Configuration);
        }
        let bytes = self
            .queue
            .bytes
            .checked_add(length)
            .ok_or(Error::Invariant)?;
        let payload = self.payload.as_ref().ok_or(Error::Invariant)?;
        if bytes > self.queue.limit
            || self.queue.ready.len() >= self.queue.packets
            || self.queue.ready.len() >= self.queue.ready.capacity()
            || payload.capacity() != self.queue.maximum
            || payload.len() > self.queue.maximum
        {
            return Err(Error::Invariant);
        }
        Ok(bytes)
    }
    /// Copy one complete original packet and retain its metadata/first age.
    /// This preserves the existing runtime path over the same publication commit.
    pub fn copy(mut self, metadata: T, since: u64, input: &[u8]) -> Result<(), Error> {
        self.publication(input.len())?;
        let payload = self.payload.as_mut().ok_or(Error::Invariant)?;
        if !payload.is_empty() {
            return Err(Error::Invariant);
        }
        payload.extend_from_slice(input);
        self.publish(metadata, since, input.len())
    }
    /// Initialize and borrow this existing maximum-sized output buffer.
    /// The returned slice cannot resize or replace admitted backing.
    pub fn output(&mut self) -> Result<&mut [u8], Error> {
        let payload = self.payload.as_mut().ok_or(Error::Invariant)?;
        if payload.capacity() != self.queue.maximum || payload.len() > self.queue.maximum {
            return Err(Error::Invariant);
        }
        payload.resize(self.queue.maximum, 0);
        Ok(payload.as_mut_slice())
    }
    /// Publish exactly the initialized packet prefix without copying or completing it.
    /// Failure enqueues nothing and returns the leased allocation through Drop.
    pub fn publish(mut self, metadata: T, since: u64, length: usize) -> Result<(), Error> {
        let bytes = self.publication(length)?;
        if length > self.payload.as_ref().ok_or(Error::Invariant)?.len() {
            return Err(Error::Configuration);
        }
        let mut payload = self.payload.take().ok_or(Error::Invariant)?;
        payload.truncate(length);
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
            // Acquisition removed exactly one buffer under this exclusive borrow.
            self.queue.free.push(payload);
        }
    }
}

#[cfg(test)]
#[path = "native_storage/tests.rs"]
mod tests;
