//! Actual legacy or fixed-capacity registration and metadata ownership.

use std::collections::{BTreeMap, VecDeque, btree_map};
use std::ops::Bound::{Excluded, Unbounded};
use std::slice;

use crate::{FlowId, FlowKey, FlowState, PacketMetadata, PipelineError};

pub(crate) type StateEntry = (FlowKey, FlowState);
pub(crate) type IdEntry = (FlowId, FlowKey);

pub(crate) enum States {
    Legacy(BTreeMap<FlowKey, FlowState>),
    Reserved(Vec<StateEntry>),
}

impl States {
    pub(crate) fn len(&self) -> usize {
        match self {
            Self::Legacy(values) => values.len(),
            Self::Reserved(values) => values.len(),
        }
    }
    pub(crate) fn is_empty(&self) -> bool {
        self.len() == 0
    }
    pub(crate) fn get(&self, key: &FlowKey) -> Option<&FlowState> {
        match self {
            Self::Legacy(values) => values.get(key),
            Self::Reserved(values) => values
                .binary_search_by_key(key, |entry| entry.0)
                .ok()
                .and_then(|index| values.get(index).map(|entry| &entry.1)),
        }
    }
    pub(crate) fn get_mut(&mut self, key: &FlowKey) -> Option<&mut FlowState> {
        match self {
            Self::Legacy(values) => values.get_mut(key),
            Self::Reserved(values) => values
                .binary_search_by_key(key, |entry| entry.0)
                .ok()
                .and_then(|index| values.get_mut(index).map(|entry| &mut entry.1)),
        }
    }
    pub(crate) fn has_room(&self) -> bool {
        match self {
            Self::Legacy(_) => true,
            Self::Reserved(values) => values.len() < values.capacity(),
        }
    }
    pub(crate) fn insert(&mut self, key: FlowKey, state: FlowState) -> Result<(), PipelineError> {
        match self {
            Self::Legacy(values) => {
                values.insert(key, state);
            }
            Self::Reserved(values) => {
                let index = values
                    .binary_search_by_key(&key, |entry| entry.0)
                    .err()
                    .ok_or(PipelineError::Invariant)?;
                if values.len() >= values.capacity() {
                    return Err(PipelineError::Invariant);
                }
                values.insert(index, (key, state));
            }
        }
        Ok(())
    }
    pub(crate) fn remove(&mut self, key: &FlowKey) -> Option<FlowState> {
        match self {
            Self::Legacy(values) => values.remove(key),
            Self::Reserved(values) => values
                .binary_search_by_key(key, |entry| entry.0)
                .ok()
                .map(|index| values.remove(index).1),
        }
    }
    pub(crate) fn iter(&self) -> StateIter<'_> {
        match self {
            Self::Legacy(values) => StateIter::Legacy(values.iter()),
            Self::Reserved(values) => StateIter::Reserved(values.iter()),
        }
    }
    pub(crate) fn after(&self, after: Option<FlowKey>) -> StateIter<'_> {
        match self {
            Self::Legacy(values) => {
                StateIter::Range(values.range((after.map_or(Unbounded, Excluded), Unbounded)))
            }
            Self::Reserved(values) => {
                let start = after.map_or(0, |key| values.partition_point(|entry| entry.0 <= key));
                StateIter::Reserved(values[start..].iter())
            }
        }
    }
}

pub(crate) enum StateIter<'a> {
    Legacy(btree_map::Iter<'a, FlowKey, FlowState>),
    Range(btree_map::Range<'a, FlowKey, FlowState>),
    Reserved(slice::Iter<'a, StateEntry>),
}

impl<'a> Iterator for StateIter<'a> {
    type Item = (&'a FlowKey, &'a FlowState);
    fn next(&mut self) -> Option<Self::Item> {
        match self {
            Self::Legacy(values) => values.next(),
            Self::Range(values) => values.next(),
            Self::Reserved(values) => values.next().map(|(key, state)| (key, state)),
        }
    }
}

pub(crate) enum ById {
    Legacy(BTreeMap<FlowId, FlowKey>),
    Reserved(Vec<IdEntry>),
}

impl ById {
    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        match self {
            Self::Legacy(values) => values.len(),
            Self::Reserved(values) => values.len(),
        }
    }
    pub(crate) fn is_empty(&self) -> bool {
        match self {
            Self::Legacy(values) => values.is_empty(),
            Self::Reserved(values) => values.is_empty(),
        }
    }
    pub(crate) fn has_room(&self) -> bool {
        match self {
            Self::Legacy(_) => true,
            Self::Reserved(values) => values.len() < values.capacity(),
        }
    }
    pub(crate) fn get(&self, id: &FlowId) -> Option<&FlowKey> {
        match self {
            Self::Legacy(values) => values.get(id),
            Self::Reserved(values) => values
                .binary_search_by_key(id, |entry| entry.0)
                .ok()
                .and_then(|index| values.get(index).map(|entry| &entry.1)),
        }
    }
    pub(crate) fn insert(&mut self, id: FlowId, key: FlowKey) -> Result<(), PipelineError> {
        match self {
            Self::Legacy(values) => {
                values.insert(id, key);
            }
            Self::Reserved(values) => match values.binary_search_by_key(&id, |entry| entry.0) {
                Ok(index) => values[index].1 = key,
                Err(index) => {
                    if values.len() >= values.capacity() {
                        return Err(PipelineError::Invariant);
                    }
                    values.insert(index, (id, key));
                }
            },
        }
        Ok(())
    }
    pub(crate) fn remove(&mut self, id: &FlowId) {
        match self {
            Self::Legacy(values) => {
                values.remove(id);
            }
            Self::Reserved(values) => {
                if let Ok(index) = values.binary_search_by_key(id, |entry| entry.0) {
                    values.remove(index);
                }
            }
        }
    }
}

pub(crate) struct MetadataSlot {
    pub(crate) value: Option<PacketMetadata>,
    pub(crate) next: Option<usize>,
}

pub(crate) enum MetadataPool {
    Legacy,
    Reserved {
        slots: Vec<MetadataSlot>,
        free: Option<usize>,
        available: usize,
    },
}

impl MetadataPool {
    pub(crate) fn is_reserved(&self) -> bool {
        matches!(self, Self::Reserved { .. })
    }
    pub(crate) fn has_room(&self) -> bool {
        match self {
            Self::Legacy => true,
            Self::Reserved { available, .. } => *available > 0,
        }
    }
}

pub(crate) enum MetadataQueue {
    Legacy(VecDeque<PacketMetadata>),
    Reserved {
        head: Option<usize>,
        tail: Option<usize>,
        len: usize,
    },
}

impl MetadataQueue {
    pub(crate) fn new(reserved: bool) -> Self {
        if reserved {
            Self::Reserved {
                head: None,
                tail: None,
                len: 0,
            }
        } else {
            Self::Legacy(VecDeque::new())
        }
    }
    pub(crate) fn len(&self) -> usize {
        match self {
            Self::Legacy(values) => values.len(),
            Self::Reserved { len, .. } => *len,
        }
    }
    pub(crate) fn front(&self, pool: &MetadataPool) -> Option<PacketMetadata> {
        match (self, pool) {
            (Self::Legacy(values), MetadataPool::Legacy) => values.front().copied(),
            (Self::Reserved { head, .. }, MetadataPool::Reserved { slots, .. }) => {
                slots.get((*head)?).and_then(|slot| slot.value)
            }
            _ => None,
        }
    }
    pub(crate) fn validate_push(&self, pool: &MetadataPool) -> Result<(), PipelineError> {
        match (self, pool) {
            (Self::Legacy(_), MetadataPool::Legacy) => Ok(()),
            (
                Self::Reserved { head, tail, len },
                MetadataPool::Reserved {
                    slots,
                    free,
                    available,
                },
            ) => {
                let index = (*free).ok_or(PipelineError::Invariant)?;
                let slot = slots.get(index).ok_or(PipelineError::Invariant)?;
                if slot.value.is_some()
                    || *available == 0
                    || *available > slots.len()
                    || (*len == 0) != head.is_none()
                    || (*len == 0) != tail.is_none()
                    || len.checked_add(1).is_none()
                {
                    return Err(PipelineError::Invariant);
                }
                if let Some(tail) = tail {
                    let previous = slots.get(*tail).ok_or(PipelineError::Invariant)?;
                    if previous.value.is_none() || previous.next.is_some() || *tail == index {
                        return Err(PipelineError::Invariant);
                    }
                }
                Ok(())
            }
            _ => Err(PipelineError::Invariant),
        }
    }
    pub(crate) fn validate_pop(&self, pool: &MetadataPool) -> Result<(), PipelineError> {
        match (self, pool) {
            (Self::Legacy(values), MetadataPool::Legacy) if !values.is_empty() => Ok(()),
            (
                Self::Reserved { head, tail, len },
                MetadataPool::Reserved {
                    slots, available, ..
                },
            ) => {
                let index = (*head).ok_or(PipelineError::Invariant)?;
                let slot = slots.get(index).ok_or(PipelineError::Invariant)?;
                let remaining = len.checked_sub(1).ok_or(PipelineError::Invariant)?;
                let available = available.checked_add(1).ok_or(PipelineError::Invariant)?;
                if slot.value.is_none()
                    || tail.is_none()
                    || (remaining == 0) != slot.next.is_none()
                    || available > slots.len()
                {
                    return Err(PipelineError::Invariant);
                }
                Ok(())
            }
            _ => Err(PipelineError::Invariant),
        }
    }
    #[cfg(test)]
    pub(crate) fn front_mut<'a>(
        &'a mut self,
        pool: &'a mut MetadataPool,
    ) -> Option<&'a mut PacketMetadata> {
        match (self, pool) {
            (Self::Legacy(values), MetadataPool::Legacy) => values.front_mut(),
            (Self::Reserved { head, .. }, MetadataPool::Reserved { slots, .. }) => {
                slots.get_mut((*head)?).and_then(|slot| slot.value.as_mut())
            }
            _ => None,
        }
    }
    pub(crate) fn push(
        &mut self,
        pool: &mut MetadataPool,
        metadata: PacketMetadata,
    ) -> Result<(), PipelineError> {
        self.validate_push(pool)?;
        match (self, pool) {
            (Self::Legacy(values), MetadataPool::Legacy) => values.push_back(metadata),
            (
                Self::Reserved { head, tail, len },
                MetadataPool::Reserved {
                    slots,
                    free,
                    available,
                },
            ) => {
                let index = free.ok_or(PipelineError::Invariant)?;
                let slot = slots.get(index).ok_or(PipelineError::Invariant)?;
                if slot.value.is_some()
                    || *available == 0
                    || (*len == 0) != head.is_none()
                    || (*len == 0) != tail.is_none()
                {
                    return Err(PipelineError::Invariant);
                }
                let next_free = slot.next;
                let next_len = len.checked_add(1).ok_or(PipelineError::Invariant)?;
                if let Some(previous) = *tail {
                    let previous = slots.get_mut(previous).ok_or(PipelineError::Invariant)?;
                    if previous.value.is_none() || previous.next.is_some() {
                        return Err(PipelineError::Invariant);
                    }
                    previous.next = Some(index);
                } else {
                    *head = Some(index);
                }
                let slot = slots.get_mut(index).ok_or(PipelineError::Invariant)?;
                slot.value = Some(metadata);
                slot.next = None;
                *tail = Some(index);
                *len = next_len;
                *free = next_free;
                *available -= 1;
            }
            _ => return Err(PipelineError::Invariant),
        }
        Ok(())
    }
    pub(crate) fn pop(&mut self, pool: &mut MetadataPool) -> Option<PacketMetadata> {
        self.validate_pop(pool).ok()?;
        match (self, pool) {
            (Self::Legacy(values), MetadataPool::Legacy) => {
                let result = values.pop_front();
                if values.is_empty() {
                    *values = VecDeque::new();
                }
                result
            }
            (
                Self::Reserved { head, tail, len },
                MetadataPool::Reserved {
                    slots,
                    free,
                    available,
                },
            ) => {
                let index = (*head)?;
                let slot = slots.get_mut(index)?;
                let metadata = slot.value?;
                let remaining = len.checked_sub(1)?;
                let available_next = available.checked_add(1)?;
                let next = slot.next;
                if (remaining == 0) != next.is_none() || available_next > slots.len() {
                    return None;
                }
                let slot = slots.get_mut(index)?;
                slot.value = None;
                slot.next = *free;
                *head = next;
                if remaining == 0 {
                    *tail = None;
                }
                *len = remaining;
                *free = Some(index);
                *available = available_next;
                Some(metadata)
            }
            _ => None,
        }
    }
}
