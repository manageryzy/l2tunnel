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
    Common(native_storage::Queue<CommonNative>),
}
impl OutputQueue {
    pub(super) fn len(&self) -> usize {
        let Self::Common(queue) = self;
        queue.len()
    }
    pub(super) fn is_empty(&self) -> bool {
        let Self::Common(queue) = self;
        queue.is_empty()
    }
    pub(super) fn bytes(&self) -> usize {
        let Self::Common(queue) = self;
        queue.bytes()
    }
    pub(super) fn capacity_bytes(&self) -> usize {
        let Self::Common(queue) = self;
        queue.capacity_bytes()
    }
    pub(super) fn can_acquire(&self) -> bool {
        let Self::Common(queue) = self;
        queue.can_acquire()
    }
    pub(super) fn oldest_since(&self) -> Option<u64> {
        let Self::Common(queue) = self;
        queue.front().map(|packet| packet.since())
    }
    pub(super) fn common_deadline(&self) -> Option<u64> {
        let Self::Common(queue) = self;
        queue.front().map(|packet| packet.metadata().deadline)
    }
    pub(super) fn complete_front(&mut self) -> io::Result<()> {
        let Self::Common(queue) = self;
        queue.complete_front()
    }
    pub(super) fn common(&self) -> io::Result<&native_storage::Queue<CommonNative>> {
        let Self::Common(queue) = self;
        Ok(queue)
    }
    pub(super) fn common_mut(&mut self) -> io::Result<&mut native_storage::Queue<CommonNative>> {
        let Self::Common(queue) = self;
        Ok(queue)
    }
}
