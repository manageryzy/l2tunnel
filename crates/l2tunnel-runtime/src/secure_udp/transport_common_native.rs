//! Exactly one selected native pool; original profile identities are never coerced.
use super::*;
use l2tunnel::{record_bank, record_engine};

#[derive(Clone, Copy)]
pub(super) struct CommonNative {
    pub(super) origin: NativeOrigin,
    pub(super) token: record_bank::NativeToken,
    pub(super) identity: record_engine::ProfileIdentity,
    pub(super) deadline: u64,
}

pub(super) enum OutputQueue {
    Swift(native_storage::Queue<Native>),
    Common(native_storage::Queue<CommonNative>),
}
impl From<native_storage::Queue<Native>> for OutputQueue {
    fn from(queue: native_storage::Queue<Native>) -> Self {
        Self::Swift(queue)
    }
}
impl OutputQueue {
    pub(super) fn len(&self) -> usize {
        match self {
            Self::Swift(q) => q.len(),
            Self::Common(q) => q.len(),
        }
    }
    pub(super) fn is_empty(&self) -> bool {
        match self {
            Self::Swift(q) => q.is_empty(),
            Self::Common(q) => q.is_empty(),
        }
    }
    pub(super) fn bytes(&self) -> usize {
        match self {
            Self::Swift(q) => q.bytes(),
            Self::Common(q) => q.bytes(),
        }
    }
    pub(super) fn capacity_bytes(&self) -> usize {
        match self {
            Self::Swift(q) => q.capacity_bytes(),
            Self::Common(q) => q.capacity_bytes(),
        }
    }
    pub(super) fn can_acquire(&self) -> bool {
        match self {
            Self::Swift(q) => q.can_acquire(),
            Self::Common(q) => q.can_acquire(),
        }
    }
    pub(super) fn oldest_since(&self) -> Option<u64> {
        match self {
            Self::Swift(q) => q.front().map(|p| p.since()),
            Self::Common(q) => q.front().map(|p| p.since()),
        }
    }
    pub(super) fn common_deadline(&self) -> Option<u64> {
        match self {
            Self::Common(q) => q.front().map(|p| p.metadata().deadline),
            Self::Swift(_) => None,
        }
    }
    // Compatibility access is typed Swift-only. The explicit Common branch
    // uses common()/common_mut(), never an invented Swift metadata value.
    pub(super) fn front(&self) -> Option<&native_storage::Packet<Native>> {
        match self {
            Self::Swift(q) => q.front(),
            Self::Common(_) => None,
        }
    }
    pub(super) fn acquire(&mut self) -> Option<native_storage::Lease<'_, Native>> {
        match self {
            Self::Swift(q) => q.acquire(),
            Self::Common(_) => None,
        }
    }
    pub(super) fn complete_front(&mut self) -> io::Result<()> {
        match self {
            Self::Swift(q) => q.complete_front(),
            Self::Common(q) => q.complete_front(),
        }
    }
    pub(super) fn common(&self) -> io::Result<&native_storage::Queue<CommonNative>> {
        match self {
            Self::Common(q) => Ok(q),
            Self::Swift(_) => Err(protocol("common native operation on Swift pool")),
        }
    }
    pub(super) fn common_mut(&mut self) -> io::Result<&mut native_storage::Queue<CommonNative>> {
        match self {
            Self::Common(q) => Ok(q),
            Self::Swift(_) => Err(protocol("common native operation on Swift pool")),
        }
    }
    #[cfg(test)]
    pub(super) fn iter(&self) -> impl Iterator<Item = &native_storage::Packet<Native>> {
        let queue = match self {
            Self::Swift(q) => Some(q),
            Self::Common(_) => None,
        };
        queue.into_iter().flat_map(native_storage::Queue::iter)
    }
}
