//! Storage substitution only; parsing, IDs, replay and deadlines stay in Reassembler.
use super::{
    BTreeMap, BTreeSet, FragmentError, MessageId, ParsedFragment, Pending, ReassemblyConfig,
    storage, write_fragment,
};

pub(super) struct PendingSlot {
    pub(super) message: Option<MessageId>,
    pub(super) pending: Pending,
}
pub(super) enum PendingStore {
    Legacy(BTreeMap<MessageId, Pending>),
    Reserved(Vec<PendingSlot>),
}
// This temporary guard uses the same explicit releases in every build. Only
// bounded test observation is conditional; no observer survives construction.
struct Construction {
    slots: Vec<PendingSlot>,
    present: Vec<u8>,
    buffer: Vec<u8>,
    tags: Vec<Option<MessageId>>,
    expired: Vec<MessageId>,
    #[cfg(test)]
    trace: std::rc::Rc<std::cell::RefCell<Vec<storage::DropEvent>>>,
}
impl Construction {
    fn new(_allocation: &storage::Allocation) -> Self {
        Self {
            slots: Vec::new(),
            present: Vec::new(),
            buffer: Vec::new(),
            tags: Vec::new(),
            expired: Vec::new(),
            #[cfg(test)]
            trace: std::rc::Rc::clone(&_allocation.trace),
        }
    }
}
impl Drop for Construction {
    fn drop(&mut self) {
        #[cfg(test)]
        let bytes = self.slots.capacity() * std::mem::size_of::<PendingSlot>()
            + self
                .slots
                .iter()
                .map(|slot| slot.pending.present.capacity() + slot.pending.buffer.capacity())
                .sum::<usize>()
            + self.present.capacity()
            + self.buffer.capacity()
            + self.tags.capacity() * std::mem::size_of::<Option<MessageId>>()
            + self.expired.capacity() * std::mem::size_of::<MessageId>();
        #[cfg(test)]
        if bytes != 0 {
            self.trace
                .borrow_mut()
                .push(storage::DropEvent::Before(bytes));
        }
        drop(std::mem::take(&mut self.slots));
        drop(std::mem::take(&mut self.present));
        drop(std::mem::take(&mut self.buffer));
        drop(std::mem::take(&mut self.tags));
        drop(std::mem::take(&mut self.expired));
        #[cfg(test)]
        if bytes != 0 {
            self.trace
                .borrow_mut()
                .push(storage::DropEvent::After(bytes));
        }
    }
}
pub(super) fn reserved(
    config: ReassemblyConfig,
    allocation: &mut storage::Allocation,
) -> Result<(PendingStore, RetiredStore, Vec<MessageId>), storage::Error> {
    let mut construction = Construction::new(allocation);
    construction.slots = allocation.vec(config.max_messages)?;
    let presence = usize::from(config.max_fragments_per_message).min(config.max_message_bytes);
    for _ in 0..config.max_messages {
        construction.present = allocation.vec(presence)?;
        construction.buffer = allocation.vec(config.max_message_bytes)?;
        construction.slots.push(PendingSlot {
            message: None,
            pending: Pending {
                chunk: 0,
                count: 0,
                received: 0,
                present: std::mem::take(&mut construction.present),
                buffer: std::mem::take(&mut construction.buffer),
                first_received: 0,
                deadline: 0,
            },
        });
    }
    construction.tags = allocation.vec(config.replay_window)?;
    construction.tags.resize(config.replay_window, None);
    construction.expired = allocation.vec(config.max_messages)?;
    Ok((
        PendingStore::Reserved(std::mem::take(&mut construction.slots)),
        RetiredStore::Reserved {
            tags: std::mem::take(&mut construction.tags),
            cleared_before: 0,
        },
        std::mem::take(&mut construction.expired),
    ))
}
impl PendingStore {
    pub(super) fn iter(&self) -> impl Iterator<Item = (&MessageId, &Pending)> {
        let (legacy, reserved) = match self {
            Self::Legacy(values) => (Some(values), None),
            Self::Reserved(slots) => (None, Some(slots)),
        };
        legacy.into_iter().flat_map(|values| values.iter()).chain(
            reserved
                .into_iter()
                .flat_map(|slots| slots.iter())
                .filter_map(|slot| slot.message.as_ref().map(|id| (id, &slot.pending))),
        )
    }
    pub(super) fn keys(&self) -> impl Iterator<Item = &MessageId> {
        self.iter().map(|(id, _)| id)
    }
    pub(super) fn values(&self) -> impl Iterator<Item = &Pending> {
        self.iter().map(|(_, value)| value)
    }
    pub(super) fn len(&self) -> usize {
        self.iter().count()
    }
    pub(super) fn contains_key(&self, id: &MessageId) -> bool {
        self.get(id).is_some()
    }
    pub(super) fn get(&self, id: &MessageId) -> Option<&Pending> {
        self.iter()
            .find_map(|(other, value)| (other == id).then_some(value))
    }
    pub(super) fn get_mut(&mut self, id: &MessageId) -> Option<&mut Pending> {
        match self {
            Self::Legacy(values) => values.get_mut(id),
            Self::Reserved(slots) => slots
                .iter_mut()
                .find(|slot| slot.message == Some(*id))
                .map(|slot| &mut slot.pending),
        }
    }
    pub(super) fn insert(
        &mut self,
        parsed: &ParsedFragment<'_>,
        first_received: u64,
        deadline: u64,
    ) -> Result<(), FragmentError> {
        match self {
            Self::Legacy(values) => {
                let mut pending = Pending {
                    chunk: parsed.chunk,
                    count: parsed.count,
                    received: 1,
                    present: vec![0; usize::from(parsed.count)],
                    buffer: vec![0; parsed.length],
                    first_received,
                    deadline,
                };
                write_fragment(&mut pending, parsed)?;
                values.insert(parsed.message, pending);
            }
            Self::Reserved(slots) => {
                let slot = slots
                    .iter_mut()
                    .find(|slot| slot.message.is_none())
                    .ok_or(FragmentError::Arithmetic)?;
                if slot.pending.buffer.capacity() < parsed.length
                    || slot.pending.present.capacity() < usize::from(parsed.count)
                {
                    return Err(FragmentError::Arithmetic);
                }
                slot.pending.buffer.clear();
                slot.pending.buffer.resize(parsed.length, 0);
                slot.pending.present.clear();
                slot.pending.present.resize(usize::from(parsed.count), 0);
                slot.pending.chunk = parsed.chunk;
                slot.pending.count = parsed.count;
                slot.pending.received = 1;
                slot.pending.first_received = first_received;
                slot.pending.deadline = deadline;
                write_fragment(&mut slot.pending, parsed)?;
                slot.message = Some(parsed.message);
            }
        }
        Ok(())
    }
    pub(super) fn release(
        &mut self,
        id: MessageId,
        output: Option<&mut [u8]>,
    ) -> Result<(), FragmentError> {
        let pending = self.get(&id).ok_or(FragmentError::Arithmetic)?;
        if output
            .as_ref()
            .is_some_and(|output| output.len() < pending.buffer.len())
        {
            return Err(FragmentError::OutputTooSmall);
        }
        match self {
            Self::Legacy(values) => {
                let pending = values.remove(&id).ok_or(FragmentError::Arithmetic)?;
                if let Some(output) = output {
                    output[..pending.buffer.len()].copy_from_slice(&pending.buffer);
                }
            }
            Self::Reserved(slots) => {
                let slot = slots
                    .iter_mut()
                    .find(|slot| slot.message == Some(id))
                    .ok_or(FragmentError::Arithmetic)?;
                if let Some(output) = output {
                    output[..slot.pending.buffer.len()].copy_from_slice(&slot.pending.buffer);
                }
                slot.message = None;
                slot.pending.buffer.clear();
                slot.pending.present.clear();
            }
        }
        Ok(())
    }
}
pub(super) enum RetiredStore {
    Legacy(BTreeSet<MessageId>),
    Reserved {
        tags: Vec<Option<MessageId>>,
        cleared_before: u64,
    },
}
impl RetiredStore {
    pub(super) fn contains(&self, id: &MessageId) -> bool {
        match self {
            Self::Legacy(values) => values.contains(id),
            Self::Reserved { tags: values, .. } => {
                let index = (id.0 % values.len() as u64) as usize;
                values.get(index).is_some_and(|value| *value == Some(*id))
            }
        }
    }
    pub(super) fn insert(&mut self, id: MessageId) -> Result<(), FragmentError> {
        match self {
            Self::Legacy(values) => {
                values.insert(id);
            }
            Self::Reserved { tags: values, .. } => {
                let index = (id.0 % values.len() as u64) as usize;
                *values.get_mut(index).ok_or(FragmentError::Arithmetic)? = Some(id);
            }
        }
        Ok(())
    }
    pub(super) fn retain_floor(&mut self, floor: u64) {
        match self {
            Self::Legacy(values) => values.retain(|id| id.0 >= floor),
            Self::Reserved {
                tags,
                cleared_before,
            } => {
                // The enclosing full-ID replay floor is authoritative. Touch only
                // departing positions; a large jump clears the bounded table once.
                if floor.saturating_sub(*cleared_before) >= tags.len() as u64 {
                    tags.fill(None);
                } else {
                    let width = tags.len() as u64;
                    for id in *cleared_before..floor {
                        if let Some(value) = tags.get_mut((id % width) as usize)
                            && value.is_some_and(|value| value.0 < floor)
                        {
                            *value = None;
                        }
                    }
                }
                *cleared_before = floor;
            }
        }
    }
    pub(super) fn len(&self) -> usize {
        match self {
            Self::Legacy(values) => values.len(),
            Self::Reserved { tags, .. } => tags.iter().flatten().count(),
        }
    }
}
