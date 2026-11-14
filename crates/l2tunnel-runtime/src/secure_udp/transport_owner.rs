//! Exclusive data/control state selected by the existing sole I/O owner.

use super::{core, io, policy, protocol, records, transactions};
use l2tunnel_swift::storage;

pub(super) struct Legacy {
    pub(super) engine: records::Engine,
    pub(super) coordinator: policy::Coordinator,
}

// Preserve the legacy inline owner. Generic's larger State has one explicitly
// fallible cell, so its two-engine layout does not inflate every legacy future.
#[allow(clippy::large_enum_variant)]
pub(super) enum DataOwner {
    Legacy(Legacy),
    Generic(ReservedState),
}

/// One fallibly reserved State; no mutation of the backing vector is exposed.
pub(super) struct ReservedState {
    values: Vec<transactions::State>,
}
impl ReservedState {
    pub(super) fn new(state: transactions::State) -> io::Result<Self> {
        std::alloc::Layout::array::<transactions::State>(1).map_err(io::Error::other)?;
        let mut values = Vec::new();
        values.try_reserve_exact(1).map_err(io::Error::other)?;
        if values.capacity() != 1 {
            return Err(io::Error::other("generic State cell capacity differs"));
        }
        values.push(state);
        Ok(Self { values })
    }
}
impl std::ops::Deref for ReservedState {
    type Target = transactions::State;
    fn deref(&self) -> &Self::Target {
        // Only new constructs this private cell, always at immutable length one.
        &self.values[0]
    }
}
impl std::ops::DerefMut for ReservedState {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.values[0]
    }
}

impl DataOwner {
    pub(super) fn legacy(&self) -> io::Result<&Legacy> {
        match self {
            Self::Legacy(legacy) => Ok(legacy),
            Self::Generic(_) => Err(protocol("legacy policy operation on generic data owner")),
        }
    }

    pub(super) fn legacy_mut(&mut self) -> io::Result<&mut Legacy> {
        match self {
            Self::Legacy(legacy) => Ok(legacy),
            Self::Generic(_) => Err(protocol("legacy policy operation on generic data owner")),
        }
    }

    pub(super) fn engine(&self, epoch: core::Epoch) -> io::Result<&records::Engine> {
        match self {
            // Legacy directional hooks retain one engine while the two record
            // scopes cross independently; its existing scope guards stay live.
            Self::Legacy(legacy) => Ok(&legacy.engine),
            Self::Generic(state) => state.engine(epoch),
        }
    }

    pub(super) fn entry(&mut self, epoch: core::Epoch) -> io::Result<Entry<'_>> {
        match self {
            Self::Legacy(legacy) => Ok(Entry::Legacy(&mut legacy.engine)),
            Self::Generic(state) => state.entry(epoch).map(Entry::Reserved),
        }
    }
}

pub(super) enum Entry<'a> {
    Legacy(&'a mut records::Engine),
    Reserved(storage::Entry<'a>),
}

impl Entry<'_> {
    pub(super) fn offer_identified(
        &mut self,
        now: u64,
        packet: &[u8],
    ) -> Result<records::IdentifiedAdmission, records::Error> {
        match self {
            Self::Legacy(engine) => engine.offer_identified(now, packet),
            Self::Reserved(entry) => entry.offer_identified(now, packet),
        }
    }

    pub(super) fn poll(
        &mut self,
        now: u64,
        number: records::RecordNumber,
        allow_data: bool,
    ) -> Result<Option<&[u8]>, records::Error> {
        match self {
            Self::Legacy(engine) => engine.poll(now, number, allow_data),
            Self::Reserved(entry) => entry.poll(now, number, allow_data),
        }
    }

    pub(super) fn accept(
        &mut self,
        now: u64,
        number: records::RecordNumber,
        body: &mut [u8],
    ) -> Result<(), records::Error> {
        match self {
            Self::Legacy(engine) => engine.accept(now, number, body),
            Self::Reserved(entry) => entry.accept(now, number, body),
        }
    }

    pub(super) fn pop_identified(
        &mut self,
    ) -> Result<Option<records::NativePacket<'_>>, records::Error> {
        match self {
            Self::Legacy(engine) => engine.pop_identified(),
            Self::Reserved(entry) => entry.pop_identified(),
        }
    }
}
