//! Persistent slot backing; logical messages, receipts and deadlines stay in Owner.
use super::*;
use l2tunnel_codec::FragmentLayout;

pub(super) struct OutboundSlot {
    meta: Option<Meta>,
    original: Vec<u8>,
    encoded: Vec<u8>,
    sources: SourceFifo,
}
pub(super) struct SourceFifo {
    ids: Vec<u64>,
    consumed: usize,
}
impl SourceFifo {
    fn front(&self) -> Option<&u64> {
        self.ids.get(self.consumed)
    }
    fn pop_front(&mut self) -> Option<u64> {
        let id = self.front().copied()?;
        self.consumed += 1;
        Some(id)
    }
    fn clear(&mut self) {
        self.ids.clear();
        self.consumed = 0;
    }
    fn is_empty(&self) -> bool {
        self.consumed == self.ids.len()
    }
}
struct Meta {
    ticket: Ticket,
    deadline: Duration,
    layout: Option<FragmentLayout>,
    next_fragment: usize,
    accepted: bool,
    confirmed: bool,
}
pub(super) enum OutboundStore {
    Legacy(VecDeque<Outbound>),
    Reserved {
        slots: Vec<OutboundSlot>,
        order: Vec<usize>,
    },
}
pub(super) struct Entry<'a> {
    pub(super) ticket: Ticket,
    pub(super) deadline: Duration,
    pub(super) bytes: &'a [u8],
    pub(super) batch: Batch<'a>,
    pub(super) next_fragment: usize,
    pub(super) sources: Sources<'a>,
    pub(super) accepted: bool,
    pub(super) confirmed: bool,
}
pub(super) enum Sources<'a> {
    Legacy(&'a VecDeque<u64>),
    Reserved(&'a SourceFifo),
}
impl<'a> Sources<'a> {
    pub(super) fn len(&self) -> usize {
        match self {
            Self::Legacy(values) => values.len(),
            Self::Reserved(values) => values.ids.len() - values.consumed,
        }
    }
    pub(super) fn front(&self) -> Option<&'a u64> {
        match self {
            Self::Legacy(values) => values.front(),
            Self::Reserved(values) => values.front(),
        }
    }
    pub(super) fn is_empty(&self) -> bool {
        match self {
            Self::Legacy(values) => values.is_empty(),
            Self::Reserved(values) => values.is_empty(),
        }
    }
    pub(super) fn can_push(&self) -> bool {
        match self {
            Self::Legacy(_) => true,
            Self::Reserved(values) => values.ids.len() < values.ids.capacity(),
        }
    }
}
pub(super) enum SourcesMut<'a> {
    Legacy(&'a mut VecDeque<u64>),
    Reserved(&'a mut SourceFifo),
}
impl SourcesMut<'_> {
    pub(super) fn push_back(&mut self, source: u64) -> Result<(), Error> {
        match self {
            Self::Legacy(values) => values.push_back(source),
            Self::Reserved(values) => {
                if values.ids.len() >= values.ids.capacity() {
                    return Err(Error::Protocol);
                }
                values.ids.push(source);
            }
        }
        Ok(())
    }
    pub(super) fn pop_front(&mut self) -> Option<u64> {
        match self {
            Self::Legacy(values) => values.pop_front(),
            Self::Reserved(values) => values.pop_front(),
        }
    }
}
pub(super) struct Batch<'a> {
    pub(super) fragments: Fragments<'a>,
}
pub(super) enum Fragments<'a> {
    Legacy(&'a [Vec<u8>]),
    Reserved(Option<FragmentLayout>, &'a [u8]),
}
impl<'a> Fragments<'a> {
    pub(super) fn len(&self) -> usize {
        match self {
            Self::Legacy(values) => values.len(),
            Self::Reserved(layout, _) => layout.map_or(0, |value| value.fragments()),
        }
    }
    pub(super) fn get(&self, index: usize) -> Option<&'a [u8]> {
        match self {
            Self::Legacy(values) => values.get(index).map(Vec::as_slice),
            Self::Reserved(layout, bytes) => bytes.get(layout.as_ref()?.fragment_range(index)?),
        }
    }
}
pub(super) struct EntryMut<'a> {
    pub(super) ticket: Ticket,
    pub(super) next_fragment: &'a mut usize,
    pub(super) sources: SourcesMut<'a>,
    pub(super) accepted: &'a mut bool,
}
impl<'a> Entry<'a> {
    fn legacy(value: &'a Outbound) -> Self {
        Self {
            ticket: value.ticket,
            deadline: value.deadline,
            bytes: &value.bytes,
            batch: Batch {
                fragments: Fragments::Legacy(&value.batch.fragments),
            },
            next_fragment: value.next_fragment,
            sources: Sources::Legacy(&value.sources),
            accepted: value.accepted,
            confirmed: value.confirmed,
        }
    }
    fn reserved(slot: &'a OutboundSlot) -> Option<Self> {
        let meta = slot.meta.as_ref()?;
        Some(Self {
            ticket: meta.ticket,
            deadline: meta.deadline,
            bytes: &slot.original,
            batch: Batch {
                fragments: Fragments::Reserved(meta.layout, &slot.encoded),
            },
            next_fragment: meta.next_fragment,
            sources: Sources::Reserved(&slot.sources),
            accepted: meta.accepted,
            confirmed: meta.confirmed,
        })
    }
}
struct Construction {
    slots: Vec<OutboundSlot>,
    order: Vec<usize>,
    original: Vec<u8>,
    encoded: Vec<u8>,
    sources: Vec<u64>,
    #[cfg(test)]
    trace: std::rc::Rc<std::cell::RefCell<Vec<storage::DropEvent>>>,
}
impl Construction {
    fn new(_allocation: &storage::Allocation) -> Self {
        Self {
            slots: Vec::new(),
            order: Vec::new(),
            original: Vec::new(),
            encoded: Vec::new(),
            sources: Vec::new(),
            #[cfg(test)]
            trace: std::rc::Rc::clone(&_allocation.trace),
        }
    }
}
impl Drop for Construction {
    fn drop(&mut self) {
        #[cfg(test)]
        let bytes = self.slots.capacity() * std::mem::size_of::<OutboundSlot>()
            + self
                .slots
                .iter()
                .map(|slot| {
                    slot.original.capacity()
                        + slot.encoded.capacity()
                        + slot.sources.ids.capacity() * std::mem::size_of::<u64>()
                })
                .sum::<usize>()
            + self.order.capacity() * std::mem::size_of::<usize>()
            + self.original.capacity()
            + self.encoded.capacity()
            + self.sources.capacity() * std::mem::size_of::<u64>();
        #[cfg(test)]
        if bytes != 0 {
            self.trace
                .borrow_mut()
                .push(storage::DropEvent::Before(bytes));
        }
        // Actual failure cleanup and successful empty-guard cleanup are identical
        // in production and tests; only the local observation is conditional.
        drop(std::mem::take(&mut self.slots));
        drop(std::mem::take(&mut self.order));
        drop(std::mem::take(&mut self.original));
        drop(std::mem::take(&mut self.encoded));
        drop(std::mem::take(&mut self.sources));
        #[cfg(test)]
        if bytes != 0 {
            self.trace
                .borrow_mut()
                .push(storage::DropEvent::After(bytes));
        }
    }
}
impl OutboundStore {
    pub(super) fn reserved(
        plan: &storage::Plan,
        allocation: &mut storage::Allocation,
    ) -> Result<Self, storage::Error> {
        let mut construction = Construction::new(allocation);
        construction.slots = allocation.vec(plan.settings.max_outbound_messages)?;
        construction.order = allocation.vec(plan.settings.max_outbound_messages)?;
        for _ in 0..plan.settings.max_outbound_messages {
            construction.original = allocation.vec(plan.original)?;
            construction.encoded = allocation.vec(plan.batch)?;
            construction.sources = allocation.vec(plan.fragments)?;
            construction.slots.push(OutboundSlot {
                meta: None,
                original: std::mem::take(&mut construction.original),
                encoded: std::mem::take(&mut construction.encoded),
                sources: SourceFifo {
                    ids: std::mem::take(&mut construction.sources),
                    consumed: 0,
                },
            });
        }
        Ok(Self::Reserved {
            slots: std::mem::take(&mut construction.slots),
            order: std::mem::take(&mut construction.order),
        })
    }
    pub(super) fn iter(&self) -> impl Iterator<Item = Entry<'_>> {
        let (legacy, reserved) = match self {
            Self::Legacy(values) => (Some(values), None),
            Self::Reserved { slots, order } => (None, Some((slots, order))),
        };
        legacy
            .into_iter()
            .flat_map(|values| values.iter().map(Entry::legacy))
            .chain(reserved.into_iter().flat_map(|(slots, order)| {
                order
                    .iter()
                    .filter_map(move |index| slots.get(*index).and_then(Entry::reserved))
            }))
    }
    pub(super) fn len(&self) -> usize {
        match self {
            Self::Legacy(values) => values.len(),
            Self::Reserved { order, .. } => order.len(),
        }
    }
    pub(super) fn is_empty(&self) -> bool {
        self.len() == 0
    }
    pub(super) fn get(&self, index: usize) -> Option<Entry<'_>> {
        match self {
            Self::Legacy(values) => values.get(index).map(Entry::legacy),
            Self::Reserved { slots, order } => {
                slots.get(*order.get(index)?).and_then(Entry::reserved)
            }
        }
    }
    pub(super) fn get_mut(&mut self, index: usize) -> Option<EntryMut<'_>> {
        match self {
            Self::Legacy(values) => {
                let entry = values.get_mut(index)?;
                Some(EntryMut {
                    ticket: entry.ticket,
                    next_fragment: &mut entry.next_fragment,
                    sources: SourcesMut::Legacy(&mut entry.sources),
                    accepted: &mut entry.accepted,
                })
            }
            Self::Reserved { slots, order } => {
                let slot = slots.get_mut(*order.get(index)?)?;
                let meta = slot.meta.as_mut()?;
                Some(EntryMut {
                    ticket: meta.ticket,
                    next_fragment: &mut meta.next_fragment,
                    sources: SourcesMut::Reserved(&mut slot.sources),
                    accepted: &mut meta.accepted,
                })
            }
        }
    }
    #[allow(clippy::too_many_arguments)] // The existing immutable ticket inputs are separate from backing.
    pub(super) fn insert(
        &mut self,
        fragmenter: &mut Fragmenter,
        binding: delivery::Binding,
        id: SubmissionId,
        bytes: &[u8],
        digest: [u8; 32],
        deadline: Duration,
    ) -> Result<Ticket, Error> {
        match self {
            Self::Legacy(values) => {
                let batch = fragmenter.fragment(bytes).map_err(Error::Fragment)?;
                let ticket = Ticket {
                    binding,
                    submission: id,
                    message: batch.message.0,
                    length: bytes.len(),
                    digest,
                    received: false,
                };
                values.push_back(Outbound {
                    ticket,
                    deadline,
                    bytes: bytes.to_vec(),
                    batch,
                    next_fragment: 0,
                    sources: VecDeque::new(),
                    accepted: false,
                    confirmed: false,
                });
                Ok(ticket)
            }
            Self::Reserved { slots, order } => {
                let index = slots
                    .iter()
                    .position(|slot| slot.meta.is_none())
                    .ok_or(Error::Protocol)?;
                let slot = slots.get_mut(index).ok_or(Error::Protocol)?;
                let count = bytes.len().div_ceil(fragmenter.chunk_bytes());
                let batch_bytes = count
                    .checked_mul(FRAGMENT_HEADER_BYTES)
                    .and_then(|headers| headers.checked_add(bytes.len()))
                    .ok_or(Error::Protocol)?;
                if order.len() >= order.capacity()
                    || slot.original.capacity() < bytes.len()
                    || slot.encoded.capacity() < batch_bytes
                    || slot.sources.ids.capacity() < count
                {
                    return Err(Error::Protocol);
                }
                slot.encoded.resize(batch_bytes, 0);
                let layout = match fragmenter.fragment_into(bytes, &mut slot.encoded) {
                    Ok(view) => view.layout(),
                    Err(error) => {
                        slot.encoded.clear();
                        return Err(Error::Fragment(error));
                    }
                };
                slot.original.clear();
                slot.original.extend_from_slice(bytes);
                slot.sources.clear();
                let ticket = Ticket {
                    binding,
                    submission: id,
                    message: layout.message().0,
                    length: bytes.len(),
                    digest,
                    received: false,
                };
                slot.meta = Some(Meta {
                    ticket,
                    deadline,
                    layout: Some(layout),
                    next_fragment: 0,
                    accepted: false,
                    confirmed: false,
                });
                order.push(index);
                Ok(ticket)
            }
        }
    }
    pub(super) fn remove(&mut self, index: usize) -> Option<()> {
        match self {
            Self::Legacy(values) => values.remove(index).map(|_| ()),
            Self::Reserved { slots, order } => {
                if index >= order.len() {
                    return None;
                }
                let slot = slots.get_mut(order.remove(index))?;
                slot.meta = None;
                slot.original.clear();
                slot.encoded.clear();
                slot.sources.clear();
                Some(())
            }
        }
    }
    pub(super) fn finish(&mut self, index: usize) -> Option<(usize, usize)> {
        let ready = self.get(index).is_some_and(|entry| {
            !entry.confirmed
                && entry.accepted
                && entry.sources.is_empty()
                && entry.next_fragment == entry.batch.fragments.len()
        });
        if !ready {
            return None;
        }
        match self {
            Self::Legacy(values) => {
                let entry = values.get_mut(index)?;
                let released = (
                    entry.bytes.len(),
                    entry.batch.fragments.iter().map(Vec::len).sum(),
                );
                entry.bytes.clear();
                entry.bytes.shrink_to_fit();
                entry.batch.fragments.clear();
                entry.batch.fragments.shrink_to_fit();
                entry.confirmed = true;
                Some(released)
            }
            Self::Reserved { slots, order } => {
                let slot = slots.get_mut(*order.get(index)?)?;
                let meta = slot.meta.as_mut()?;
                let released = (slot.original.len(), slot.encoded.len());
                slot.original.clear();
                slot.encoded.clear();
                slot.sources.clear();
                meta.layout = None;
                meta.confirmed = true;
                Some(released)
            }
        }
    }
}

#[cfg(test)]
impl OutboundStore {
    pub(super) fn inventory(&self) -> Vec<(usize, usize, usize)> {
        let Self::Reserved { slots, order } = self else {
            return Vec::new();
        };
        let mut values = vec![
            (
                slots.as_ptr() as usize,
                slots.capacity(),
                std::mem::size_of::<OutboundSlot>(),
            ),
            (
                order.as_ptr() as usize,
                order.capacity(),
                std::mem::size_of::<usize>(),
            ),
        ];
        for slot in slots {
            values.extend([
                (slot.original.as_ptr() as usize, slot.original.capacity(), 1),
                (slot.encoded.as_ptr() as usize, slot.encoded.capacity(), 1),
                (
                    slot.sources.ids.as_ptr() as usize,
                    slot.sources.ids.capacity(),
                    std::mem::size_of::<u64>(),
                ),
            ]);
        }
        values
    }
    pub(super) fn source_cursor(&self, index: usize) -> Option<(usize, usize, usize)> {
        let Self::Reserved { slots, order } = self else {
            return None;
        };
        let source = &slots.get(*order.get(index)?)?.sources;
        Some((source.ids.len(), source.consumed, source.ids.capacity()))
    }
}

pub(super) struct ArrivalSlot {
    message: Option<MessageId>,
    deadline: Duration,
}
pub(super) enum Arrivals {
    Legacy(BTreeMap<MessageId, Duration>),
    Reserved(Vec<ArrivalSlot>),
}
impl Arrivals {
    pub(super) fn earliest(&self) -> Option<(MessageId, Duration)> {
        match self {
            Self::Legacy(values) => values
                .iter()
                .map(|(message, deadline)| (*message, *deadline))
                .min_by_key(|(message, deadline)| (*deadline, *message)),
            Self::Reserved(slots) => slots
                .iter()
                .filter_map(|slot| slot.message.map(|message| (message, slot.deadline)))
                .min_by_key(|(message, deadline)| (*deadline, *message)),
        }
    }
    pub(super) fn reserved(
        count: usize,
        allocation: &mut storage::Allocation,
    ) -> Result<Self, storage::Error> {
        let mut slots = allocation.vec(count)?;
        for _ in 0..count {
            slots.push(ArrivalSlot {
                message: None,
                deadline: Duration::ZERO,
            });
        }
        Ok(Self::Reserved(slots))
    }
    pub(super) fn contains(&self, id: MessageId) -> bool {
        match self {
            Self::Legacy(values) => values.contains_key(&id),
            Self::Reserved(slots) => slots.iter().any(|slot| slot.message == Some(id)),
        }
    }
    pub(super) fn insert(&mut self, id: MessageId, deadline: Duration) -> Result<(), Error> {
        match self {
            Self::Legacy(values) => {
                values.insert(id, deadline);
            }
            Self::Reserved(slots) => {
                let slot = slots
                    .iter_mut()
                    .find(|slot| slot.message.is_none())
                    .ok_or(Error::Protocol)?;
                slot.message = Some(id);
                slot.deadline = deadline;
            }
        }
        Ok(())
    }
    pub(super) fn remove(&mut self, id: &MessageId) -> Option<Duration> {
        match self {
            Self::Legacy(values) => values.remove(id),
            Self::Reserved(slots) => {
                let slot = slots.iter_mut().find(|slot| slot.message == Some(*id))?;
                slot.message = None;
                Some(slot.deadline)
            }
        }
    }
}
#[cfg(test)]
impl Arrivals {
    pub(super) fn inventory(&self) -> Option<(usize, usize, usize)> {
        match self {
            Self::Legacy(_) => None,
            Self::Reserved(slots) => Some((
                slots.as_ptr() as usize,
                slots.capacity(),
                std::mem::size_of::<ArrivalSlot>(),
            )),
        }
    }
}
