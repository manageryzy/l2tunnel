//! Checked provisioning of the actual Streamed cell, metadata and scratch.

use super::{
    Outgoing, Settings, SettingsV2, Streamed, delivery, io, messages, raw_packet_bytes,
    wrapper_layout,
};
use std::{
    alloc::Layout,
    fmt,
    ops::{Deref, DerefMut},
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Constructor-only wrapper capacity; message heaps have independent limits.
pub(crate) struct Limits {
    /// Maximum retained wrapper layout bytes.
    pub capacity_bytes: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Exact immutable wrapper geometry, without authentication or allocated backing.
pub(crate) struct Plan {
    selected: Settings,
    lifecycle: Option<messages::Settings>,
    base: delivery::Settings,
    envelope: usize,
    raw: usize,
    capacity_bytes: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Actual reserved wrapper backing, including idle metadata and scratch.
pub(crate) struct Usage {
    /// Original constructor-only bound.
    pub limit_bytes: usize,
    /// Actual cell, outgoing metadata and scratch layout bytes.
    pub capacity_bytes: usize,
    /// Actual nonzero backing reservations retained by this wrapper.
    pub allocations: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Wrapper construction failure, separate from protocol/message admission errors.
pub(crate) enum Error {
    /// Invalid or overflowing requested layout.
    Layout,
    /// A checked plan belongs to different immutable settings.
    PlanMismatch,
    /// The constructor-only bound cannot hold the complete wrapper.
    Limit { required: usize, limit: usize },
    /// A real wrapper reservation failed or was locally refused in a test.
    Allocation,
    /// Actual backing differs from its exact immutable geometry.
    Invariant,
}
impl fmt::Display for Error {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(output, "control wrapper storage error: {self:?}")
    }
}
impl std::error::Error for Error {}
impl From<Error> for io::Error {
    fn from(error: Error) -> Self {
        let kind = match error {
            Error::Layout | Error::PlanMismatch => io::ErrorKind::InvalidInput,
            Error::Allocation => io::ErrorKind::OutOfMemory,
            Error::Limit { .. } | Error::Invariant => io::ErrorKind::Other,
        };
        Self::new(kind, error)
    }
}

impl Plan {
    /// Compute every wrapper layout without constructing a control/message owner.
    pub(crate) fn new(selected: Settings, base: delivery::Settings) -> io::Result<Self> {
        Self::for_selection(selected, None, base)
    }

    /// Include all four actual owners and outgoing metadata for explicit v2.
    #[allow(dead_code)] // Actual v2 provisioning is protocol-tested; selected fresh-DH Driver follows separately.
    pub(crate) fn new_v2(selected: SettingsV2, base: delivery::Settings) -> io::Result<Self> {
        Self::for_selection(selected.first_three(), Some(selected.streams[3]), base)
    }

    fn for_selection(
        selected: Settings,
        lifecycle: Option<messages::Settings>,
        base: delivery::Settings,
    ) -> io::Result<Self> {
        let envelope = selected
            .streams
            .iter()
            .chain(lifecycle.iter())
            .map(|settings| settings.max_message_bytes)
            .max()
            .ok_or(Error::Layout)?;
        let raw = raw_packet_bytes(base).map_err(|_| Error::Layout)?;
        Layout::array::<Streamed>(1).map_err(|_| Error::Layout)?;
        let capacity_bytes = wrapper_layout(
            [
                selected.streams[0].max_outbound_messages,
                selected.streams[1].max_outbound_messages,
                selected.streams[2].max_outbound_messages,
                lifecycle.map_or(0, |settings| settings.max_outbound_messages),
            ],
            envelope,
            raw,
            if lifecycle.is_some() { 4 } else { 0 },
        )
        .map_err(|_| Error::Layout)?;
        Ok(Self {
            selected,
            lifecycle,
            base,
            envelope,
            raw,
            capacity_bytes,
        })
    }

    /// Exact requested retained layout, without allocator metadata or message heaps.
    pub(crate) fn capacity_bytes(&self) -> usize {
        self.capacity_bytes
    }

    pub(super) fn check(
        &self,
        selected: &Settings,
        base: &delivery::Settings,
        limits: Limits,
    ) -> io::Result<()> {
        self.check_selection(selected, None, base, limits)
    }

    pub(super) fn check_selection(
        &self,
        selected: &Settings,
        lifecycle: Option<messages::Settings>,
        base: &delivery::Settings,
        limits: Limits,
    ) -> io::Result<()> {
        if self.selected != *selected || self.lifecycle != lifecycle || self.base != *base {
            return Err(Error::PlanMismatch.into());
        }
        if self.capacity_bytes > limits.capacity_bytes {
            return Err(Error::Limit {
                required: self.capacity_bytes,
                limit: limits.capacity_bytes,
            }
            .into());
        }
        Ok(())
    }

    pub(super) fn provision(
        &self,
        limits: Limits,
        allocation: &mut Allocation,
        build: impl FnOnce([Vec<Outgoing>; 4], Vec<u8>, Vec<u8>) -> io::Result<Streamed>,
    ) -> io::Result<StreamedStorage> {
        self.check_selection(&self.selected, self.lifecycle, &self.base, limits)?;
        let mut construction = Construction::new(allocation);
        construction.cell = allocation.vec(Slot::Cell, 1)?;
        for (i, settings) in self.selected.streams.iter().enumerate() {
            construction.outgoing[i] =
                allocation.vec(Slot::Outgoing(i), settings.max_outbound_messages)?;
        }
        if let Some(settings) = self.lifecycle {
            construction.outgoing[3] =
                allocation.vec(Slot::Outgoing(3), settings.max_outbound_messages)?;
        }
        construction.envelope = allocation.vec(Slot::Envelope, self.envelope)?;
        construction.envelope.resize(self.envelope, 0);
        construction.raw = allocation.vec(Slot::Raw, self.raw)?;
        construction.raw.resize(self.raw, 0);
        let value = build(
            std::mem::take(&mut construction.outgoing),
            std::mem::take(&mut construction.envelope),
            std::mem::take(&mut construction.raw),
        )?;
        construction.cell.push(value);
        let reserved = Reserved {
            values: std::mem::take(&mut construction.cell),
            limit_bytes: limits.capacity_bytes,
        };
        let usage = reserved.usage()?;
        if usage.capacity_bytes != self.capacity_bytes {
            return Err(Error::Invariant.into());
        }
        #[cfg(test)]
        if let Some(trace) = &allocation.trace {
            let value = &reserved.values[0];
            trace.borrow_mut().record(Event::for_vec(
                Kind::Published,
                Slot::Cell,
                &reserved.values,
            ));
            if let super::StreamOwners::Four(owners) = &value.owners {
                trace
                    .borrow_mut()
                    .record(Event::for_vec(Kind::Published, Slot::Owners, owners));
            }
            for (i, values) in value.outgoing.iter().enumerate() {
                if values.capacity() == 0 {
                    continue;
                }
                trace.borrow_mut().record(Event::for_vec(
                    Kind::Published,
                    Slot::Outgoing(i),
                    values,
                ));
            }
            trace.borrow_mut().record(Event::for_vec(
                Kind::Published,
                Slot::Envelope,
                &value.envelope,
            ));
            trace
                .borrow_mut()
                .record(Event::for_vec(Kind::Published, Slot::Raw, &value.raw));
        }
        Ok(StreamedStorage::Reserved(reserved))
    }
}

pub(super) enum StreamedStorage {
    Legacy(Box<Streamed>),
    Reserved(Reserved),
}

pub(super) struct Reserved {
    values: Vec<Streamed>,
    limit_bytes: usize,
}
impl Reserved {
    fn usage(&self) -> io::Result<Usage> {
        if self.values.len() != 1 || self.values.capacity() != 1 {
            return Err(Error::Invariant.into());
        }
        let value = &self.values[0];
        let capacity_bytes = wrapper_layout(
            value.outgoing.each_ref().map(|values| values.capacity()),
            value.envelope.capacity(),
            value.raw.capacity(),
            value.owners.heap_capacity(),
        )
        .map_err(|_| Error::Layout)?;
        let allocations = 1
            + usize::from(value.owners.heap_capacity() != 0)
            + value
                .outgoing
                .iter()
                .filter(|values| values.capacity() != 0)
                .count()
            + usize::from(value.envelope.capacity() != 0)
            + usize::from(value.raw.capacity() != 0);
        Ok(Usage {
            limit_bytes: self.limit_bytes,
            capacity_bytes,
            allocations,
        })
    }
}
impl StreamedStorage {
    pub(super) fn usage(&self) -> io::Result<Option<Usage>> {
        match self {
            Self::Legacy(_) => Ok(None),
            Self::Reserved(reserved) => reserved.usage().map(Some),
        }
    }
}
impl Deref for StreamedStorage {
    type Target = Streamed;
    fn deref(&self) -> &Self::Target {
        match self {
            Self::Legacy(value) => value,
            // The private reserved constructor publishes exactly one immutable cell.
            Self::Reserved(reserved) => &reserved.values[0],
        }
    }
}
impl DerefMut for StreamedStorage {
    fn deref_mut(&mut self) -> &mut Self::Target {
        match self {
            Self::Legacy(value) => value,
            Self::Reserved(reserved) => &mut reserved.values[0],
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Slot {
    Cell,
    Owners,
    Outgoing(usize),
    Envelope,
    Raw,
}

#[derive(Default)]
pub(super) struct Allocation {
    #[cfg(test)]
    fail_at: Option<usize>,
    #[cfg(test)]
    attempts: usize,
    #[cfg(test)]
    trace: Option<TraceHandle>,
    #[cfg(test)]
    pub(super) owner_observer: Option<Box<dyn FnMut(super::StreamConstructionDrop)>>,
}
impl Allocation {
    pub(super) fn vec<T>(&mut self, _slot: Slot, count: usize) -> io::Result<Vec<T>> {
        Layout::array::<T>(count).map_err(|_| Error::Layout)?;
        #[cfg(test)]
        {
            self.attempts += 1;
            if self.fail_at == Some(self.attempts) {
                return Err(Error::Allocation.into());
            }
        }
        let mut values = Vec::new();
        values
            .try_reserve_exact(count)
            .map_err(|_| Error::Allocation)?;
        if values.capacity() != count {
            return Err(Error::Invariant.into());
        }
        #[cfg(test)]
        if let Some(trace) = &self.trace {
            trace
                .borrow_mut()
                .record(Event::for_vec(Kind::Reserved, _slot, &values));
        }
        Ok(values)
    }

    #[cfg(test)]
    pub(super) fn traced(fail_at: Option<usize>, trace: TraceHandle) -> Self {
        Self {
            fail_at,
            trace: Some(trace),
            ..Self::default()
        }
    }
    #[cfg(test)]
    pub(super) fn attempts(&self) -> usize {
        self.attempts
    }
}

struct Construction {
    cell: Vec<Streamed>,
    outgoing: [Vec<Outgoing>; 4],
    envelope: Vec<u8>,
    raw: Vec<u8>,
    #[cfg(test)]
    trace: Option<TraceHandle>,
}
impl Construction {
    fn new(_allocation: &Allocation) -> Self {
        Self {
            cell: Vec::new(),
            outgoing: std::array::from_fn(|_| Vec::new()),
            envelope: Vec::new(),
            raw: Vec::new(),
            #[cfg(test)]
            trace: _allocation.trace.clone(),
        }
    }
    fn release<T>(&self, values: Vec<T>, _slot: Slot) {
        #[cfg(test)]
        let event = Event::for_vec(Kind::BeforeDrop, _slot, &values);
        #[cfg(test)]
        if values.capacity() != 0
            && let Some(trace) = &self.trace
        {
            trace.borrow_mut().record(event);
        }
        // The same actual drop executes for production and local observation.
        drop(values);
        #[cfg(test)]
        if event.capacity != 0
            && let Some(trace) = &self.trace
        {
            trace.borrow_mut().record(Event {
                kind: Kind::AfterDrop,
                ..event
            });
        }
    }
}
impl Drop for Construction {
    fn drop(&mut self) {
        let cell = std::mem::take(&mut self.cell);
        self.release(cell, Slot::Cell);
        for (i, values) in std::mem::take(&mut self.outgoing).into_iter().enumerate() {
            self.release(values, Slot::Outgoing(i));
        }
        let envelope = std::mem::take(&mut self.envelope);
        self.release(envelope, Slot::Envelope);
        let raw = std::mem::take(&mut self.raw);
        self.release(raw, Slot::Raw);
    }
}

#[cfg(test)]
pub(super) type TraceHandle = std::rc::Rc<std::cell::RefCell<Trace>>;
#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Kind {
    Reserved,
    BeforeDrop,
    AfterDrop,
    Published,
}
#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct Event {
    pub(super) kind: Kind,
    pub(super) slot: Slot,
    pub(super) pointer: usize,
    pub(super) capacity: usize,
    pub(super) element_bytes: usize,
}
#[cfg(test)]
impl Event {
    fn for_vec<T>(kind: Kind, slot: Slot, values: &Vec<T>) -> Self {
        Self {
            kind,
            slot,
            pointer: values.as_ptr() as usize,
            capacity: values.capacity(),
            element_bytes: std::mem::size_of::<T>(),
        }
    }
}
#[cfg(test)]
#[derive(Default)]
pub(super) struct Trace {
    events: [Option<Event>; 32],
    count: usize,
    pub(super) overflow: bool,
}
#[cfg(test)]
impl Trace {
    fn record(&mut self, event: Event) {
        if let Some(slot) = self.events.get_mut(self.count) {
            *slot = Some(event);
            self.count += 1;
        } else {
            self.overflow = true;
        }
    }
    pub(super) fn events(&self) -> impl Iterator<Item = Event> + '_ {
        self.events.iter().take(self.count).flatten().copied()
    }
}
