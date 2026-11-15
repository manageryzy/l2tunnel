//! Fallible owned-capacity reservation for two complete Swift record engines.
//!
//! Capacity counts requested allocation layouts and the inline [`Set`] layout,
//! not allocator overhead, process RSS, physical pages or runtime stacks. The
//! exact-reservation construction claim is bound to the reviewed Rust 1.92
//! standard library. External storage is an explicit caller-accounted charge;
//! this module cannot bound allocations made by arbitrary external code.

use crate::records;
use std::alloc::Layout;
use std::collections::VecDeque;
use std::mem::size_of;

/// Validate a non-zero-sized element array before allocation or accounting.
pub(crate) fn array_bytes<T>(count: usize) -> Result<usize, crate::Error> {
    if size_of::<T>() == 0 {
        return Err(crate::Error::Storage);
    }
    Layout::array::<T>(count)
        .map(|layout| layout.size())
        .map_err(|_| crate::Error::Storage)
}

/// One constructor's fallible exact-layout allocation allowance.
pub(crate) struct Allocation {
    limit: usize,
    used: usize,
    allocations: usize,
    #[cfg(test)]
    fail_at: Option<usize>,
}

impl Allocation {
    /// Start a constructor with an already admitted heap-layout allowance.
    pub(crate) fn new(limit: usize) -> Self {
        Self {
            limit,
            used: 0,
            allocations: 0,
            #[cfg(test)]
            fail_at: None,
        }
    }

    fn charge(&mut self, bytes: usize) -> Result<usize, crate::Error> {
        let previous = self.used;
        let used = previous.checked_add(bytes).ok_or(crate::Error::Storage)?;
        if used > self.limit {
            return Err(crate::Error::Storage);
        }
        let allocations = self
            .allocations
            .checked_add(1)
            .ok_or(crate::Error::Storage)?;
        self.used = used;
        self.allocations = allocations;
        #[cfg(test)]
        if self.fail_at == Some(allocations) {
            self.used = previous;
            return Err(crate::Error::Allocation);
        }
        Ok(previous)
    }

    /// Reserve an empty vector's exact backing layout, without initializing T.
    pub(crate) fn vec<T>(&mut self, count: usize) -> Result<Vec<T>, crate::Error> {
        let bytes = array_bytes::<T>(count)?;
        let mut vector = Vec::new();
        if bytes == 0 {
            return Ok(vector);
        }
        let previous = self.charge(bytes)?;
        if vector.try_reserve_exact(count).is_err() {
            self.used = previous;
            return Err(crate::Error::Allocation);
        }
        if vector.capacity() != count {
            drop(vector);
            self.used = previous;
            return Err(crate::Error::Storage);
        }
        Ok(vector)
    }

    /// Reserve an empty deque's exact backing layout, without initializing T.
    pub(crate) fn deque<T>(&mut self, count: usize) -> Result<VecDeque<T>, crate::Error> {
        let bytes = array_bytes::<T>(count)?;
        let mut deque = VecDeque::new();
        if bytes == 0 {
            return Ok(deque);
        }
        let previous = self.charge(bytes)?;
        if deque.try_reserve_exact(count).is_err() {
            self.used = previous;
            return Err(crate::Error::Allocation);
        }
        if deque.capacity() != count {
            drop(deque);
            self.used = previous;
            return Err(crate::Error::Storage);
        }
        Ok(deque)
    }

    /// Successfully created backing layouts, including retained empty capacity.
    pub(crate) fn used(&self) -> usize {
        self.used
    }

    /// Nonzero allocation attempts, including a failed or injected attempt.
    #[cfg(test)]
    pub(crate) fn allocations(&self) -> usize {
        self.allocations
    }
}

/// Maximum controlled owner capacity, including its actual fixed header.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Limits {
    /// Requested layout bytes available to the selected complete owner.
    pub capacity_bytes: usize,
}

/// Validated duplex configuration and its exact per-engine heap-layout capacity.
///
/// Planning performs no allocation. Inline engine headers are counted once by
/// [`Set`], rather than charged again to each heap plan.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Plan {
    send: records::Config,
    receive: records::Config,
    capacity_bytes: usize,
}

impl Plan {
    /// Validate exact directional configurations and all heap-layout arithmetic.
    pub fn for_engine(send: records::Config, receive: records::Config) -> Result<Self, Error> {
        let capacity_bytes = records::Engine::reserved_heap_bytes(send, receive)?;
        Ok(Self {
            send,
            receive,
            capacity_bytes,
        })
    }

    /// Complete engine heap capacity, excluding the inline engine header.
    pub fn capacity_bytes(&self) -> usize {
        self.capacity_bytes
    }

    /// Exact locally sending configuration supplied to the constructor.
    pub fn send_config(&self) -> records::Config {
        self.send
    }

    /// Exact locally receiving configuration supplied to the constructor.
    pub fn receive_config(&self) -> records::Config {
        self.receive
    }
}

/// Actual single-owner layout, separate from a parent generation bank's headers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OwnedUsage {
    /// Original complete single-owner allowance.
    pub limit_bytes: usize,
    /// Exact inline Owned header, including the one actual Engine.
    pub fixed_bytes: usize,
    /// Actual retained heap layouts, including idle reusable storage.
    pub heap_bytes: usize,
    /// Successful explicit nonzero reservations in this constructor.
    pub allocations: usize,
}

/// Move-only actual reserved duplex engine, without an embedded generation Set.
///
/// A parent counts this header inside its actual enum/slot and adds only the
/// reported heap. Restricted Entry operations provide no mutable Engine escape.
pub struct Owned {
    engine: records::Engine,
    usage: OwnedUsage,
}
impl Owned {
    /// Admit the exact inline-plus-heap layout before the first allocation.
    pub fn new(plan: Plan, limits: Limits) -> Result<Self, Error> {
        Self::build(plan, limits, Allocation::new(plan.capacity_bytes))
    }

    fn build(plan: Plan, limits: Limits, mut allocation: Allocation) -> Result<Self, Error> {
        let total = size_of::<Self>()
            .checked_add(plan.capacity_bytes)
            .ok_or(Error::Budget)?;
        if total > limits.capacity_bytes {
            return Err(Error::Budget);
        }
        let engine = records::Engine::new_reserved(plan.send, plan.receive, &mut allocation)?;
        if allocation.used() != plan.capacity_bytes {
            drop(engine);
            return Err(records::Error::Codec(crate::Error::Storage).into());
        }
        Ok(Self {
            engine,
            usage: OwnedUsage {
                limit_bytes: limits.capacity_bytes,
                fixed_bytes: size_of::<Self>(),
                heap_bytes: allocation.used(),
                allocations: allocation.allocations,
            },
        })
    }

    /// Immutable actual algorithm observations, without replacement authority.
    pub fn engine(&self) -> &records::Engine {
        &self.engine
    }

    /// Borrow restricted existing packet operations from this exact owner.
    pub fn entry(&mut self) -> Entry<'_> {
        Entry {
            engine: &mut self.engine,
        }
    }

    /// Exact successful backing observations; not allocator overhead or RSS.
    pub const fn usage(&self) -> OwnedUsage {
        self.usage
    }
}

/// Local slot/generation token, without authenticated session or epoch authority.
///
/// Tokens are meaningful only within their originating Set. They do not provide
/// cross-Set identity and must not substitute for the runtime's actual Scope.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EngineId {
    slot: usize,
    generation: u64,
}

/// Current and peak requested-layout charges; not logical queue occupancy or RSS.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Usage {
    /// Configured complete owner ceiling.
    pub limit_bytes: usize,
    /// Exact inline Set layout, including both possible engine headers.
    pub fixed_bytes: usize,
    /// Caller-accounted external capacity retained for the Set lifetime.
    pub external_bytes: usize,
    /// Complete heap layouts of published engine slots.
    pub engine_bytes: usize,
    /// Complete target precharge while a constructor is running.
    pub building_bytes: usize,
    /// Highest admitted combined charge, including failed construction attempts.
    pub peak_bytes: usize,
}

/// Explicit admission, ownership, drain or underlying record-engine failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// Fixed, external and engine charges exceed the ceiling or overflow.
    Budget,
    /// Both engine slots are still owned.
    Slots,
    /// The supplied local slot/generation is absent or retired.
    Stale,
    /// The nonwrapping generation space has been exhausted.
    Exhausted,
    /// At least one pure engine direction still retains undrained custody.
    NotDrained,
    /// Configuration, storage, allocation or record-engine failure.
    Engine(records::Error),
}

impl std::fmt::Display for Error {
    fn fmt(&self, output: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Budget => output.write_str("Swift storage capacity exceeded"),
            Self::Slots => output.write_str("both Swift storage slots remain owned"),
            Self::Stale => output.write_str("stale Swift storage slot"),
            Self::Exhausted => output.write_str("Swift storage generation exhausted"),
            Self::NotDrained => output.write_str("Swift storage engine has not drained"),
            Self::Engine(error) => std::fmt::Display::fmt(error, output),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Engine(error) => Some(error),
            _ => None,
        }
    }
}

impl From<records::Error> for Error {
    fn from(error: records::Error) -> Self {
        Self::Engine(error)
    }
}

struct Slot {
    generation: u64,
    capacity_bytes: usize,
    engine: records::Engine,
}

/// Sole owner of at most two reserved engines and their aggregate capacity.
///
/// Two slots permit current plus prepared, then current plus draining. Preparing
/// storage is not a negotiated switch. Runtime scope/fence/proof checks remain
/// required before activation or retirement. Dropping the Set releases storage
/// without claiming clean physical or peer-confirmed completion.
pub struct Set {
    limits: Limits,
    external_bytes: usize,
    engine_bytes: usize,
    building_bytes: usize,
    peak_bytes: usize,
    next_generation: Option<u64>,
    slots: [Option<Slot>; 2],
    #[cfg(test)]
    fail_at: Option<usize>,
    #[cfg(test)]
    last_allocations: usize,
}

impl Set {
    /// Admit fixed and caller-accounted storage before allocating any engine.
    pub fn new(limits: Limits, external_capacity_bytes: usize) -> Result<Self, Error> {
        let initial = size_of::<Self>()
            .checked_add(external_capacity_bytes)
            .ok_or(Error::Budget)?;
        if initial > limits.capacity_bytes {
            return Err(Error::Budget);
        }
        Ok(Self {
            limits,
            external_bytes: external_capacity_bytes,
            engine_bytes: 0,
            building_bytes: 0,
            peak_bytes: initial,
            next_generation: Some(1),
            slots: [None, None],
            #[cfg(test)]
            fail_at: None,
            #[cfg(test)]
            last_allocations: 0,
        })
    }

    /// Precharge and fully construct an engine before publishing a local token.
    ///
    /// On failure, partial storage is dropped before releasing the construction
    /// charge. The attempted peak is retained, with no slot/generation consumed.
    pub fn prepare(&mut self, plan: Plan) -> Result<EngineId, Error> {
        let index = self
            .slots
            .iter()
            .position(Option::is_none)
            .ok_or(Error::Slots)?;
        let generation = self.next_generation.ok_or(Error::Exhausted)?;
        let engine_bytes = self
            .engine_bytes
            .checked_add(plan.capacity_bytes)
            .ok_or(Error::Budget)?;
        let total = size_of::<Self>()
            .checked_add(self.external_bytes)
            .and_then(|bytes| bytes.checked_add(engine_bytes))
            .ok_or(Error::Budget)?;
        if total > self.limits.capacity_bytes {
            return Err(Error::Budget);
        }
        self.building_bytes = plan.capacity_bytes;
        self.peak_bytes = self.peak_bytes.max(total);
        let mut allocation = Allocation::new(plan.capacity_bytes);
        #[cfg(test)]
        {
            allocation.fail_at = self.fail_at;
        }
        let built = records::Engine::new_reserved(plan.send, plan.receive, &mut allocation);
        let built = match built {
            Ok(engine) if allocation.used() == plan.capacity_bytes => Ok(engine),
            Ok(engine) => {
                drop(engine);
                Err(records::Error::Codec(crate::Error::Storage))
            }
            Err(error) => Err(error),
        };
        #[cfg(test)]
        {
            self.last_allocations = allocation.allocations();
        }
        let engine = match built {
            Ok(engine) => engine,
            Err(error) => {
                self.building_bytes = 0;
                return Err(error.into());
            }
        };
        self.slots[index] = Some(Slot {
            generation,
            capacity_bytes: plan.capacity_bytes,
            engine,
        });
        self.engine_bytes = engine_bytes;
        self.building_bytes = 0;
        self.next_generation = generation.checked_add(1);
        Ok(EngineId {
            slot: index,
            generation,
        })
    }

    fn slot(&self, id: EngineId) -> Result<&Slot, Error> {
        self.slots
            .get(id.slot)
            .and_then(Option::as_ref)
            .filter(|slot| slot.generation == id.generation)
            .ok_or(Error::Stale)
    }

    /// Borrow immutable observations from the exact currently owned engine.
    pub fn engine(&self, id: EngineId) -> Result<&records::Engine, Error> {
        Ok(&self.slot(id)?.engine)
    }

    /// Borrow only packet operations, without exposing mutable engine ownership.
    pub fn entry(&mut self, id: EngineId) -> Result<Entry<'_>, Error> {
        let slot = self
            .slots
            .get_mut(id.slot)
            .and_then(Option::as_mut)
            .filter(|slot| slot.generation == id.generation)
            .ok_or(Error::Stale)?;
        Ok(Entry {
            engine: &mut slot.engine,
        })
    }

    /// Drop an engine only after both pure directions report drained.
    ///
    /// Physical completion, authenticated peer fences and control proof custody
    /// are additional runtime prerequisites; these queries cannot prove them.
    pub fn retire(&mut self, id: EngineId) -> Result<(), Error> {
        let slot = self.slot(id)?;
        if !slot.engine.send_drained() || !slot.engine.receive_drained() {
            return Err(Error::NotDrained);
        }
        let remaining = self
            .engine_bytes
            .checked_sub(slot.capacity_bytes)
            .ok_or(Error::Engine(records::Error::Codec(crate::Error::Storage)))?;
        let retired = self.slots[id.slot].take();
        drop(retired);
        self.engine_bytes = remaining;
        Ok(())
    }

    /// Observe fixed/external, published, building and retained peak charges.
    pub fn usage(&self) -> Usage {
        Usage {
            limit_bytes: self.limits.capacity_bytes,
            fixed_bytes: size_of::<Self>(),
            external_bytes: self.external_bytes,
            engine_bytes: self.engine_bytes,
            building_bytes: self.building_bytes,
            peak_bytes: self.peak_bytes,
        }
    }
}

/// Restricted mutable packet operations on one reserved engine.
///
/// This is not a mutable Engine reference and cannot extract or replace it.
///
/// ```compile_fail
/// use l2tunnel_swift::{records, storage};
/// fn cannot_extract(entry: &mut storage::Entry<'_>) {
///     let _: &mut records::Engine = entry;
/// }
/// ```
pub struct Entry<'a> {
    engine: &'a mut records::Engine,
}

impl Entry<'_> {
    /// Retain a native packet through the engine's existing admission policy.
    pub fn offer(&mut self, now: u64, packet: &[u8]) -> Result<records::Admission, records::Error> {
        self.engine.offer(now, packet)
    }

    /// Retain a packet and return its actual channel/native identity.
    pub fn offer_identified(
        &mut self,
        now: u64,
        packet: &[u8],
    ) -> Result<records::IdentifiedAdmission, records::Error> {
        self.engine.offer_identified(now, packet)
    }

    /// Retain a packet on a checked selected channel using the actual shared budget.
    pub fn offer_on_channel_identified(
        &mut self,
        now: u64,
        channel: records::ChannelId,
        packet: &[u8],
    ) -> Result<records::IdentifiedAdmission, records::Error> {
        self.engine
            .offer_on_channel_identified(now, channel, packet)
    }

    /// Produce the exact borrowed body and actual algorithm branch without an ownership escape.
    pub fn poll_emission(
        &mut self,
        now: u64,
        number: records::RecordNumber,
        allow_data: bool,
    ) -> Result<Option<records::Emission<'_>>, records::Error> {
        self.engine.poll_emission(now, number, allow_data)
    }

    /// Produce an existing numbered body without allocation or ownership escape.
    pub fn poll(
        &mut self,
        now: u64,
        number: records::RecordNumber,
        allow_data: bool,
    ) -> Result<Option<&[u8]>, records::Error> {
        self.engine.poll(now, number, allow_data)
    }

    /// Apply an already authenticated and replay-checked body in workspace.
    pub fn accept(
        &mut self,
        now: u64,
        number: records::RecordNumber,
        body: &mut [u8],
    ) -> Result<(), records::Error> {
        self.engine.accept(now, number, body)
    }

    /// Extract complete native bytes, without claiming physical completion.
    pub fn pop(&mut self) -> Result<Option<&[u8]>, records::Error> {
        self.engine.pop()
    }

    /// Extract complete native bytes and their actual ordered channel identity.
    pub fn pop_identified(&mut self) -> Result<Option<records::NativePacket<'_>>, records::Error> {
        self.engine.pop_identified()
    }
}

#[cfg(test)]
mod tests;
