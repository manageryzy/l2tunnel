//! Fixed backing operations; the Scheduler retains the sole DRR implementation.
use super::*;

#[derive(Clone, Copy, Debug, Default)]
pub(super) struct Fifo {
    pub(super) head: Option<usize>,
    pub(super) tail: Option<usize>,
    pub(super) len: usize,
}
pub(super) struct Registered {
    id: FlowId,
    flow: Flow,
}
#[derive(Clone, Copy)]
pub(super) struct Index {
    id: FlowId,
    slot: usize,
}
#[derive(Clone, Copy, Default)]
pub(super) struct Packet {
    next: Option<usize>,
    len: usize,
}
pub(super) struct Reserved {
    pub(super) classes: Vec<ClassConfig>,
    slots: Vec<Option<Registered>>,
    index: Vec<Index>,
    free_flows: Vec<usize>,
    ring: Vec<FlowId>,
    head: usize,
    len: usize,
    packets: Vec<Packet>,
    free_packets: Vec<usize>,
    slab: Vec<u8>,
    width: usize,
    pub(super) usage: Option<storage::Usage>,
}
impl Reserved {
    pub(super) fn new(
        plan: storage::Plan,
        classes: &[ClassConfig],
        a: &mut storage::Allocation,
    ) -> Result<Self, storage::Error> {
        let c = plan.config();
        let mut build = Construction::default();
        #[cfg(test)]
        {
            build.trace = a.trace.clone();
        }
        build.classes = a.vec(classes.len())?;
        build.classes.extend_from_slice(classes);
        build.classes.sort_unstable_by_key(|c| c.id);
        build.slots = a.vec(c.max_flows)?;
        build.slots.resize_with(c.max_flows, || None);
        build.index = a.vec(c.max_flows)?;
        build.free_flows = a.vec(c.max_flows)?;
        build.free_flows.extend((0..c.max_flows).rev());
        build.ring = a.vec(c.max_flows)?;
        build.ring.resize(c.max_flows, FlowId::new(0));
        build.packets = a.vec(c.max_queued_packets)?;
        build
            .packets
            .resize(c.max_queued_packets, Packet::default());
        build.free_packets = a.vec(c.max_queued_packets)?;
        build.free_packets.extend((0..c.max_queued_packets).rev());
        let size = c
            .max_queued_packets
            .checked_mul(c.max_packet_bytes)
            .ok_or(storage::Error::Layout)?;
        build.slab = a.vec(size)?;
        build.slab.resize(size, 0);
        let usage = a.finish(plan)?;
        let result = Self {
            classes: std::mem::take(&mut build.classes),
            slots: std::mem::take(&mut build.slots),
            index: std::mem::take(&mut build.index),
            free_flows: std::mem::take(&mut build.free_flows),
            ring: std::mem::take(&mut build.ring),
            head: 0,
            len: 0,
            packets: std::mem::take(&mut build.packets),
            free_packets: std::mem::take(&mut build.free_packets),
            slab: std::mem::take(&mut build.slab),
            width: c.max_packet_bytes,
            usage: Some(usage),
        };
        #[cfg(test)]
        if let Some(trace) = &build.trace {
            trace.borrow_mut().push(Event::Transferred {
                bytes: usage.capacity_bytes,
            });
        }
        Ok(result)
    }
    fn slot(&self, id: FlowId) -> Option<usize> {
        let i = self.index.binary_search_by_key(&id, |i| i.id).ok()?;
        let slot = self.index.get(i)?.slot;
        (self.slots.get(slot)?.as_ref()?.id == id).then_some(slot)
    }
    pub(super) fn flow(&self, id: FlowId) -> Option<&Flow> {
        Some(&self.slots.get(self.slot(id)?)?.as_ref()?.flow)
    }
    pub(super) fn flow_mut(&mut self, id: FlowId) -> Option<&mut Flow> {
        let slot = self.slot(id)?;
        Some(&mut self.slots.get_mut(slot)?.as_mut()?.flow)
    }
    pub(super) fn registered(&self) -> usize {
        self.index.len()
    }
    pub(super) fn insert(&mut self, id: FlowId, mut flow: Flow) -> Result<(), FlowError> {
        let slot = *self.free_flows.last().ok_or(FlowError::Capacity)?;
        let index = self
            .index
            .binary_search_by_key(&id, |i| i.id)
            .err()
            .ok_or(FlowError::Duplicate)?;
        if self.index.len() == self.index.capacity()
            || self.slots.get(slot).is_none_or(Option::is_some)
        {
            return Err(FlowError::Capacity);
        }
        flow.fixed = Some(Fifo::default());
        self.free_flows.pop();
        self.slots[slot] = Some(Registered { id, flow });
        self.index.insert(index, Index { id, slot });
        Ok(())
    }
    pub(super) fn remove(&mut self, id: FlowId) -> Result<(), FlowError> {
        let index = self
            .index
            .binary_search_by_key(&id, |i| i.id)
            .map_err(|_| FlowError::UnknownFlow)?;
        let slot = self.index[index].slot;
        if self.free_flows.len() == self.free_flows.capacity()
            || self.slots.get(slot).is_none_or(Option::is_none)
        {
            return Err(FlowError::Arithmetic);
        }
        self.index.remove(index);
        self.slots[slot] = None;
        self.free_flows.push(slot);
        Ok(())
    }
    pub(super) fn class_weight(&self, id: ClassId) -> Option<u32> {
        Some(
            self.classes
                .get(self.classes.binary_search_by_key(&id, |c| c.id).ok()?)?
                .weight,
        )
    }
    pub(super) fn active_len(&self) -> usize {
        self.len
    }
    pub(super) fn active(&self, offset: usize) -> Option<FlowId> {
        if offset >= self.len
            || self.len > self.ring.len()
            || self.ring.is_empty()
            || self.head >= self.ring.len()
        {
            return None;
        }
        let end = self.ring.len() - self.head;
        self.ring
            .get(if offset >= end {
                offset - end
            } else {
                self.head + offset
            })
            .copied()
    }
    pub(super) fn rotate(&mut self) -> Result<(), ScheduleError> {
        let id = self.active(0).ok_or(ScheduleError::Invariant)?;
        self.pop_active();
        self.push_active(id);
        Ok(())
    }
    pub(super) fn pop_active(&mut self) {
        self.head = if self.head + 1 == self.ring.len() {
            0
        } else {
            self.head + 1
        };
        self.len -= 1;
    }
    fn push_active(&mut self, id: FlowId) {
        let end = self.ring.len() - self.head;
        let slot = if self.len >= end {
            self.len - end
        } else {
            self.head + self.len
        };
        self.ring[slot] = id;
        self.len += 1;
    }
    pub(super) fn packet_len(&self, flow: &Flow) -> Option<usize> {
        Some(self.front(flow)?.len())
    }
    pub(super) fn front(&self, flow: &Flow) -> Option<&[u8]> {
        let slot = flow.fixed?.head?;
        let packet = self.packets.get(slot)?;
        if packet.len == 0 || packet.len > self.width {
            return None;
        }
        let start = slot.checked_mul(self.width)?;
        self.slab.get(start..start.checked_add(packet.len)?)
    }
    pub(super) fn preflight_enqueue(
        &self,
        id: FlowId,
        length: usize,
    ) -> Result<Enqueue, AdmissionErrorKind> {
        let bad = AdmissionErrorKind::Invariant;
        let flow_slot = self.slot(id).ok_or(bad)?;
        let flow = &self.slots[flow_slot].as_ref().ok_or(bad)?.flow;
        let queue = flow.fixed.ok_or(bad)?;
        let slot = *self.free_packets.last().ok_or(bad)?;
        let packet = self.packets.get(slot).ok_or(bad)?;
        let start = slot.checked_mul(self.width).ok_or(bad)?;
        let end = start.checked_add(length).ok_or(bad)?;
        if packet.len != 0
            || packet.next.is_some()
            || length > self.width
            || end > self.slab.len()
            || self.len > self.ring.len()
            || self.head >= self.ring.len()
            || queue.len == usize::MAX
        {
            return Err(bad);
        }
        let activate = queue.len == 0;
        if activate {
            if queue.head.is_some()
                || queue.tail.is_some()
                || self.len >= self.ring.len()
                || self.head >= self.ring.len()
            {
                return Err(bad);
            }
        } else {
            let head = self.packets.get(queue.head.ok_or(bad)?).ok_or(bad)?;
            let tail = self.packets.get(queue.tail.ok_or(bad)?).ok_or(bad)?;
            if head.len == 0 || tail.len == 0 || tail.next.is_some() {
                return Err(bad);
            }
        }
        Ok(Enqueue {
            flow_slot,
            slot,
            start,
            end,
            queue,
            activate,
        })
    }
    pub(super) fn enqueue(&mut self, id: FlowId, bytes: &[u8], prepared: Enqueue) {
        let Enqueue {
            flow_slot,
            slot,
            start,
            end,
            mut queue,
            activate,
        } = prepared;
        self.slab[start..end].copy_from_slice(bytes);
        self.free_packets.pop();
        self.packets[slot] = Packet {
            next: None,
            len: bytes.len(),
        };
        if let Some(tail) = queue.tail {
            self.packets[tail].next = Some(slot);
        } else {
            queue.head = Some(slot);
        }
        queue.tail = Some(slot);
        queue.len += 1;
        if let Some(flow) = &mut self.slots[flow_slot] {
            flow.flow.fixed = Some(queue);
            flow.flow.bytes += bytes.len();
        }
        if activate {
            self.push_active(id);
        }
    }
    pub(super) fn service(&mut self, service: Service) -> Result<Parts<'_>, ScheduleError> {
        let error = ScheduleError::Invariant;
        let flow_slot = self.slot(service.head.flow).ok_or(error)?;
        let queue = self
            .slots
            .get(flow_slot)
            .and_then(Option::as_ref)
            .ok_or(error)?
            .flow
            .fixed
            .ok_or(error)?;
        let slot = queue.head.ok_or(error)?;
        let packet = self.packets.get(slot).ok_or(error)?;
        if queue.len == 0
            || packet.len != service.head.packet_bytes
            || packet.len > self.width
            || self.free_packets.len() == self.free_packets.capacity()
            || service.last != (queue.len == 1)
            || service.last != packet.next.is_none()
            || (service.last && queue.tail != Some(slot))
        {
            return Err(error);
        }
        if self
            .free_packets
            .len()
            .checked_add(service.queued_packets)
            .and_then(|n| n.checked_add(1))
            != Some(self.packets.len())
        {
            return Err(error);
        }
        if !service.last {
            let next = self.packets.get(packet.next.ok_or(error)?).ok_or(error)?;
            let tail = self.packets.get(queue.tail.ok_or(error)?).ok_or(error)?;
            if next.len == 0
                || next.len > self.width
                || tail.len == 0
                || tail.len > self.width
                || tail.next.is_some()
                || (queue.len == 2 && packet.next != queue.tail)
            {
                return Err(error);
            }
        }
        let next = Fifo {
            head: packet.next,
            tail: if service.last { None } else { queue.tail },
            len: queue.len - 1,
        };
        let start = slot.checked_mul(self.width).ok_or(error)?;
        let bytes = self
            .slab
            .get(start..start.checked_add(packet.len).ok_or(error)?)
            .ok_or(error)?;
        let flow = &mut self
            .slots
            .get_mut(flow_slot)
            .and_then(Option::as_mut)
            .ok_or(error)?
            .flow;
        let packet = self.packets.get_mut(slot).ok_or(error)?;
        Ok(Parts {
            flow,
            packet,
            free: &mut self.free_packets,
            bytes,
            next,
            slot,
        })
    }
}

#[cfg(test)]
#[path = "storage_tests.rs"]
mod tests;
pub(super) struct Enqueue {
    flow_slot: usize,
    slot: usize,
    start: usize,
    end: usize,
    queue: Fifo,
    activate: bool,
}
pub(super) struct Parts<'a> {
    flow: &'a mut Flow,
    packet: &'a mut Packet,
    free: &'a mut Vec<usize>,
    pub(super) bytes: &'a [u8],
    next: Fifo,
    slot: usize,
}
impl Parts<'_> {
    pub(super) fn commit(self, service: Service) {
        *self.packet = Packet::default();
        self.free.push(self.slot);
        self.flow.fixed = Some(self.next);
        service.commit_flow(self.flow);
    }
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Event {
    BeforeDrop { bytes: usize },
    AfterDrop,
    Transferred { bytes: usize },
}
#[derive(Default)]
struct Construction {
    classes: Vec<ClassConfig>,
    slots: Vec<Option<Registered>>,
    index: Vec<Index>,
    free_flows: Vec<usize>,
    ring: Vec<FlowId>,
    packets: Vec<Packet>,
    free_packets: Vec<usize>,
    slab: Vec<u8>,
    #[cfg(test)]
    trace: Option<std::rc::Rc<std::cell::RefCell<Vec<Event>>>>,
}
impl Drop for Construction {
    fn drop(&mut self) {
        let occupied = self.classes.capacity() != 0
            || self.slots.capacity() != 0
            || self.index.capacity() != 0
            || self.free_flows.capacity() != 0
            || self.ring.capacity() != 0
            || self.packets.capacity() != 0
            || self.free_packets.capacity() != 0
            || self.slab.capacity() != 0;
        if !occupied {
            return;
        }
        #[cfg(test)]
        if let Some(trace) = &self.trace {
            let bytes = self.classes.capacity() * std::mem::size_of::<ClassConfig>()
                + self.slots.capacity() * std::mem::size_of::<Option<Registered>>()
                + self.index.capacity() * std::mem::size_of::<Index>()
                + (self.free_flows.capacity() + self.free_packets.capacity())
                    * std::mem::size_of::<usize>()
                + self.ring.capacity() * std::mem::size_of::<FlowId>()
                + self.packets.capacity() * std::mem::size_of::<Packet>()
                + self.slab.capacity();
            trace.borrow_mut().push(Event::BeforeDrop { bytes });
        }
        drop(std::mem::take(&mut self.classes));
        drop(std::mem::take(&mut self.slots));
        drop(std::mem::take(&mut self.index));
        drop(std::mem::take(&mut self.free_flows));
        drop(std::mem::take(&mut self.ring));
        drop(std::mem::take(&mut self.packets));
        drop(std::mem::take(&mut self.free_packets));
        drop(std::mem::take(&mut self.slab));
        #[cfg(test)]
        if let Some(trace) = &self.trace {
            trace.borrow_mut().push(Event::AfterDrop);
        }
    }
}
