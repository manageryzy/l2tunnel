//! Bounded FIFO-per-channel admission with round-robin service.
//! Frame classification and negotiated connection mapping remain planned.
use std::collections::VecDeque;
use std::convert::Infallible;

/// Actual fallible queue slabs or inline-only handoff inventory.
pub mod storage;

/// Admission failure returns ownership of the rejected frame.
#[derive(Debug, Eq, PartialEq)]
pub enum AdmissionError {
    /// Channel outside the configured pool.
    Channel(Vec<u8>),
    /// Shared byte/count budget exhausted or empty frame.
    Budget(Vec<u8>),
}

/// Refusal before ownership transfer, or the downstream admission error.
#[derive(Debug, Eq, PartialEq)]
pub enum OfferError<E> {
    /// Channel outside the configured pool.
    Channel,
    /// Empty frame or the configured byte/count bound cannot admit it.
    Budget,
    /// Borrowed transit requires an entirely empty MUX owner.
    Busy,
    /// Defensive internal queue/accounting inconsistency.
    Invariant,
    /// An explicitly owned reserved-slab copy failed before callback entry.
    Allocation,
    /// Downstream refused without transferring this queue's ownership.
    Downstream(E),
}

/// Borrowed ingress failure; the caller retains its unchanged input bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BorrowedAdmissionError {
    /// Channel outside the configured pool.
    Channel,
    /// Empty input, logical byte/count pressure or explicit physical slot maximum.
    Budget,
    /// The selected inline-only handoff owner has no payload queue.
    Unavailable,
    /// Defensive backing or accounting inconsistency.
    Invariant,
    /// An explicitly legacy allocating borrowed-input copy failed.
    Allocation,
}

#[derive(Clone, Copy, Default)]
pub(crate) struct Lane {
    head: Option<usize>,
    tail: Option<usize>,
}
#[derive(Clone, Copy, Default)]
pub(crate) struct Slot {
    length: usize,
    next: Option<usize>,
}
struct Reserved {
    lanes: Vec<Lane>,
    slots: Vec<Slot>,
    free: Vec<usize>,
    bytes: Vec<u8>,
    max_frame: usize,
}
#[cfg(test)]
type DropTrace = std::rc::Rc<std::cell::RefCell<Vec<[usize; 4]>>>;
#[derive(Default)]
struct Provisioned {
    lanes: Vec<Lane>,
    slots: Vec<Slot>,
    free: Vec<usize>,
    bytes: Vec<u8>,
    #[cfg(test)]
    trace: Option<DropTrace>,
}
impl Drop for Provisioned {
    fn drop(&mut self) {
        #[cfg(test)]
        let capacities = [
            self.lanes.capacity(),
            self.slots.capacity(),
            self.free.capacity(),
            self.bytes.capacity(),
        ];
        // The same actual cleanup runs in production and observed test construction.
        drop(std::mem::take(&mut self.lanes));
        drop(std::mem::take(&mut self.slots));
        drop(std::mem::take(&mut self.free));
        drop(std::mem::take(&mut self.bytes));
        #[cfg(test)]
        if let Some(trace) = &self.trace {
            trace.borrow_mut().push(capacities);
        }
    }
}
enum Backing {
    Legacy(Vec<VecDeque<Box<[u8]>>>),
    Reserved(Reserved),
    Handoff,
}

#[derive(Clone, Copy)]
struct PushPlan {
    index: usize,
    bytes: usize,
    frames: usize,
    slot: usize,
    tail: Option<usize>,
    start: usize,
    end: usize,
}
#[derive(Clone, Copy)]
struct Release {
    slot: usize,
    next: Option<usize>,
    start: usize,
    end: usize,
}
struct Selection {
    index: usize,
    next: usize,
    bytes: usize,
    frames: usize,
    release: Option<Release>,
}

impl Reserved {
    fn push(&mut self, plan: PushPlan, bytes: &[u8]) {
        // All ranges, link targets and free-list room were checked before mutation.
        self.bytes[plan.start..plan.end].copy_from_slice(bytes);
        self.free.pop();
        self.slots[plan.slot] = Slot {
            length: bytes.len(),
            next: None,
        };
        if let Some(tail) = plan.tail {
            self.slots[tail].next = Some(plan.slot);
        } else {
            self.lanes[plan.index].head = Some(plan.slot);
        }
        self.lanes[plan.index].tail = Some(plan.slot);
    }
}

trait ReturnMode {
    type Output;
    fn legacy(frame: &mut Box<[u8]>) -> Self::Output;
    fn reserved(
        bytes: &[u8],
        allocation: &mut storage::Allocation,
    ) -> Result<Self::Output, storage::Error>;
}
struct Owned;
impl ReturnMode for Owned {
    type Output = Vec<u8>;
    fn legacy(frame: &mut Box<[u8]>) -> Self::Output {
        std::mem::take(frame).into_vec()
    }
    fn reserved(
        bytes: &[u8],
        allocation: &mut storage::Allocation,
    ) -> Result<Self::Output, storage::Error> {
        allocation.copy(bytes)
    }
}
struct Borrowed;
impl ReturnMode for Borrowed {
    type Output = ();
    fn legacy(_: &mut Box<[u8]>) {}
    fn reserved(_: &[u8], _: &mut storage::Allocation) -> Result<Self::Output, storage::Error> {
        Ok(())
    }
}
type OfferResult<T, E, O> = Result<Option<(u16, O, T)>, OfferError<E>>;
type Front<'a> = (&'a [u8], Option<Release>);

/// One original queued frame and the downstream's actual admission token.
pub type Offered<T> = (u16, Vec<u8>, T);

/// One direction's shared queue for all user frames, including measurements.
pub struct Mux {
    backing: Backing,
    channels: u16,
    byte_limit: usize,
    queued_bytes: usize,
    next: usize,
    frame_limit: usize,
    queued_frames: usize,
    usage: Option<storage::Usage>,
}

impl Mux {
    /// Construct a common channel pool with shared payload-byte and frame-count bounds.
    pub fn new(channels: u16, byte_limit: usize, frame_limit: usize) -> Result<Self, &'static str> {
        storage::validate(channels, byte_limit, frame_limit).map_err(|_| "invalid queue limits")?;
        Ok(Self {
            backing: Backing::Legacy(vec![VecDeque::new(); usize::from(channels)]),
            channels,
            byte_limit,
            queued_bytes: 0,
            next: 0,
            frame_limit,
            queued_frames: 0,
            usage: None,
        })
    }

    /// Fallibly reserve globally reusable queue slots and their complete physical slabs.
    pub fn new_reserved(
        channels: u16,
        byte_limit: usize,
        frame_limit: usize,
        max_frame_bytes: usize,
        limits: storage::Limits,
    ) -> Result<Self, storage::Error> {
        Self::with_plan(
            storage::Plan::for_queue(channels, byte_limit, frame_limit, max_frame_bytes)?,
            limits,
        )
    }
    /// Construct actual inline-only selected-channel handoff, without payload backing.
    pub fn new_handoff_reserved(
        channels: u16,
        byte_limit: usize,
        frame_limit: usize,
        limits: storage::Limits,
    ) -> Result<Self, storage::Error> {
        Self::with_plan(
            storage::Plan::for_handoff(channels, byte_limit, frame_limit)?,
            limits,
        )
    }
    /// Admit the complete heap plan before its first fallible reservation.
    pub fn with_plan(plan: storage::Plan, limits: storage::Limits) -> Result<Self, storage::Error> {
        Self::with_allocation(
            plan,
            limits,
            &mut storage::Allocation::default(),
            Provisioned::default(),
        )
    }

    fn with_allocation(
        plan: storage::Plan,
        limits: storage::Limits,
        allocation: &mut storage::Allocation,
        mut provisioned: Provisioned,
    ) -> Result<Self, storage::Error> {
        plan.check(limits)?;
        let (backing, capacity_bytes, allocations) = if let Some(max_frame) = plan.max_frame_bytes()
        {
            provisioned.lanes = allocation.reserve::<Lane>(usize::from(plan.channels()))?;
            provisioned
                .lanes
                .resize(usize::from(plan.channels()), Lane::default());
            provisioned.slots = allocation.reserve::<Slot>(plan.frame_limit())?;
            provisioned
                .slots
                .resize(plan.frame_limit(), Slot::default());
            provisioned.free = allocation.reserve::<usize>(plan.frame_limit())?;
            provisioned.free.extend((0..plan.frame_limit()).rev());
            let slab = plan
                .frame_limit()
                .checked_mul(max_frame)
                .ok_or(storage::Error::Layout)?;
            provisioned.bytes = allocation.reserve::<u8>(slab)?;
            provisioned.bytes.resize(slab, 0);
            let capacity_bytes = storage::sum(&[
                storage::array_bytes::<Lane>(provisioned.lanes.capacity())?,
                storage::array_bytes::<Slot>(provisioned.slots.capacity())?,
                storage::array_bytes::<usize>(provisioned.free.capacity())?,
                storage::array_bytes::<u8>(provisioned.bytes.capacity())?,
            ])?;
            if capacity_bytes != plan.capacity_bytes() {
                return Err(storage::Error::Invariant);
            }
            (
                Backing::Reserved(Reserved {
                    lanes: std::mem::take(&mut provisioned.lanes),
                    slots: std::mem::take(&mut provisioned.slots),
                    free: std::mem::take(&mut provisioned.free),
                    bytes: std::mem::take(&mut provisioned.bytes),
                    max_frame,
                }),
                capacity_bytes,
                4,
            )
        } else {
            (Backing::Handoff, 0, 0)
        };
        if capacity_bytes != plan.capacity_bytes() {
            return Err(storage::Error::Invariant);
        }
        Ok(Self {
            backing,
            channels: plan.channels(),
            byte_limit: plan.byte_limit(),
            queued_bytes: 0,
            next: 0,
            frame_limit: plan.frame_limit(),
            queued_frames: 0,
            usage: Some(storage::Usage {
                limit_bytes: limits.capacity_bytes,
                capacity_bytes,
                allocations,
            }),
        })
    }
    /// Actual retained heap capacity; legacy allocating construction reports None.
    pub const fn storage_usage(&self) -> Option<storage::Usage> {
        self.usage
    }
    /// Admit an opaque frame using the same policy for every traffic class.
    pub fn push(&mut self, channel: u16, frame: Vec<u8>) -> Result<(), AdmissionError> {
        let plan = match self.prepare_push(channel, frame.len()) {
            Ok(plan) => plan,
            Err(BorrowedAdmissionError::Channel) => return Err(AdmissionError::Channel(frame)),
            Err(_) => return Err(AdmissionError::Budget(frame)),
        };
        match &mut self.backing {
            Backing::Legacy(lanes) => lanes[plan.index].push_back(frame.into_boxed_slice()),
            Backing::Reserved(backing) => backing.push(plan, &frame),
            Backing::Handoff => return Err(AdmissionError::Budget(frame)),
        }
        self.queued_bytes = plan.bytes;
        self.queued_frames = plan.frames;
        Ok(())
    }

    /// Copy ingress into actual reserved slabs without allocation or ownership transfer.
    /// Legacy construction explicitly allocates; inline-only handoff refuses queue ingress.
    pub fn push_borrowed(
        &mut self,
        channel: u16,
        bytes: &[u8],
    ) -> Result<(), BorrowedAdmissionError> {
        let plan = self.prepare_push(channel, bytes.len())?;
        match &mut self.backing {
            Backing::Legacy(lanes) => {
                let copied =
                    storage::copy(bytes).map_err(|_| BorrowedAdmissionError::Allocation)?;
                lanes[plan.index].push_back(copied.into_boxed_slice());
            }
            Backing::Reserved(backing) => backing.push(plan, bytes),
            Backing::Handoff => return Err(BorrowedAdmissionError::Unavailable),
        }
        self.queued_bytes = plan.bytes;
        self.queued_frames = plan.frames;
        Ok(())
    }
    /// Release one frame when downstream capacity is available.
    pub fn pop(&mut self) -> Option<(u16, Vec<u8>)> {
        match self.offer_front(|_, _| Ok::<_, Infallible>(Some(()))) {
            Ok(packet) => packet.map(|(channel, bytes, ())| (channel, bytes)),
            Err(OfferError::Downstream(never)) => match never {},
            Err(_) => None,
        }
    }

    /// Offer the actual RR head, retaining its allocation and cursor on refusal.
    ///
    /// `Some` commits exactly one original frame. The callback must return `None`
    /// only if it admitted nothing; arbitrary downstream side effects cannot be undone.
    pub fn offer_front<T, E>(
        &mut self,
        offer: impl FnOnce(u16, &[u8]) -> Result<Option<T>, E>,
    ) -> Result<Option<Offered<T>>, OfferError<E>> {
        self.offer_inner::<T, E, Owned>(offer, &mut storage::Allocation::default())
    }

    /// Offer the retained RR head without copying or allocating on reserved storage.
    /// None/error retains exact custody; Some releases the slot after downstream admit.
    pub fn offer_front_borrowed<T, E>(
        &mut self,
        offer: impl FnOnce(u16, &[u8]) -> Result<Option<T>, E>,
    ) -> Result<Option<(u16, T)>, OfferError<E>> {
        self.offer_inner::<T, E, Borrowed>(offer, &mut storage::Allocation::default())
            .map(|offered| offered.map(|(channel, (), token)| (channel, token)))
    }

    fn offer_inner<T, E, R: ReturnMode>(
        &mut self,
        offer: impl FnOnce(u16, &[u8]) -> Result<Option<T>, E>,
        allocation: &mut storage::Allocation,
    ) -> OfferResult<T, E, R::Output> {
        let Some(plan) = self.prepare_offer().map_err(|()| OfferError::Invariant)? else {
            return Ok(None);
        };
        // The checked full channel width makes this conversion exact.
        let channel = plan.index as u16;
        let (payload, token) = match &mut self.backing {
            Backing::Legacy(lanes) => {
                let frame = lanes[plan.index].front_mut().ok_or(OfferError::Invariant)?;
                let Some(token) = offer(channel, frame).map_err(OfferError::Downstream)? else {
                    return Ok(None);
                };
                let payload = R::legacy(frame);
                lanes[plan.index].pop_front();
                (payload, token)
            }
            Backing::Reserved(backing) => {
                let release = plan.release.ok_or(OfferError::Invariant)?;
                let bytes = &backing.bytes[release.start..release.end];
                // Owned convenience copies fallibly before the callback; borrowed mode is ().
                let payload = R::reserved(bytes, allocation).map_err(|_| OfferError::Allocation)?;
                let Some(token) = offer(channel, bytes).map_err(OfferError::Downstream)? else {
                    return Ok(None);
                };
                backing.lanes[plan.index].head = release.next;
                if release.next.is_none() {
                    backing.lanes[plan.index].tail = None;
                }
                backing.slots[release.slot] = Slot::default();
                backing.free.push(release.slot);
                (payload, token)
            }
            Backing::Handoff => return Err(OfferError::Invariant),
        };
        self.queued_bytes = plan.bytes;
        self.queued_frames = plan.frames;
        self.next = plan.next;
        Ok(Some((channel, payload, token)))
    }

    /// Offer bytes retained by the upstream owner through this empty MUX policy.
    ///
    /// No queue or payload allocation is made. Success leaves the same empty
    /// counters and eventual RR cursor as immediate push/pop of this channel.
    pub fn offer_selected<T, E>(
        &mut self,
        channel: u16,
        bytes: &[u8],
        offer: impl FnOnce(u16, &[u8]) -> Result<Option<T>, E>,
    ) -> Result<Option<T>, OfferError<E>> {
        let index = usize::from(channel);
        if index >= usize::from(self.channels) {
            return Err(OfferError::Channel);
        }
        let channels = self.check_layout().map_err(|()| OfferError::Invariant)?;
        if bytes.is_empty() || bytes.len() > self.byte_limit || self.frame_limit == 0 {
            return Err(OfferError::Budget);
        }
        if self.queued_bytes != 0
            || self.queued_frames != 0
            || match &self.backing {
                Backing::Legacy(lanes) => lanes.iter().any(|lane| !lane.is_empty()),
                Backing::Reserved(backing) => backing
                    .lanes
                    .iter()
                    .any(|lane| lane.head.is_some() || lane.tail.is_some()),
                Backing::Handoff => false,
            }
        {
            return Err(OfferError::Busy);
        }
        let next = (index + 1) % channels;
        let token = offer(channel, bytes).map_err(OfferError::Downstream)?;
        if token.is_some() {
            self.next = next;
        }
        Ok(token)
    }

    fn check_layout(&self) -> Result<usize, ()> {
        let channels = usize::from(self.channels);
        if !(1..=256).contains(&channels) || self.next >= channels {
            return Err(());
        }
        match &self.backing {
            Backing::Legacy(lanes) if lanes.len() != channels => return Err(()),
            Backing::Reserved(backing) => {
                if backing.lanes.len() != channels
                    || backing.slots.len() != self.frame_limit
                    || backing.free.len() > self.frame_limit
                    || backing.max_frame == 0
                    || backing.slots.len().checked_mul(backing.max_frame)
                        != Some(backing.bytes.len())
                    || backing.free.capacity() < self.frame_limit
                {
                    return Err(());
                }
            }
            _ => {}
        }
        Ok(channels)
    }

    fn prepare_push(
        &self,
        channel: u16,
        length: usize,
    ) -> Result<PushPlan, BorrowedAdmissionError> {
        let index = usize::from(channel);
        if index >= usize::from(self.channels) {
            return Err(BorrowedAdmissionError::Channel);
        }
        self.check_layout()
            .map_err(|()| BorrowedAdmissionError::Invariant)?;
        let available = self
            .byte_limit
            .checked_sub(self.queued_bytes)
            .ok_or(BorrowedAdmissionError::Invariant)?;
        if self.queued_frames > self.frame_limit {
            return Err(BorrowedAdmissionError::Invariant);
        }
        if length == 0 || self.queued_frames == self.frame_limit || length > available {
            return Err(BorrowedAdmissionError::Budget);
        }
        let mut plan = PushPlan {
            index,
            bytes: self
                .queued_bytes
                .checked_add(length)
                .ok_or(BorrowedAdmissionError::Invariant)?,
            frames: self
                .queued_frames
                .checked_add(1)
                .ok_or(BorrowedAdmissionError::Invariant)?,
            slot: 0,
            tail: None,
            start: 0,
            end: 0,
        };
        if let Backing::Reserved(backing) = &self.backing {
            if length > backing.max_frame {
                return Err(BorrowedAdmissionError::Budget);
            }
            if backing.free.len() != self.frame_limit - self.queued_frames {
                return Err(BorrowedAdmissionError::Invariant);
            }
            let slot = *backing
                .free
                .last()
                .ok_or(BorrowedAdmissionError::Invariant)?;
            let cell = backing
                .slots
                .get(slot)
                .ok_or(BorrowedAdmissionError::Invariant)?;
            if cell.length != 0 || cell.next.is_some() {
                return Err(BorrowedAdmissionError::Invariant);
            }
            let lane = &backing.lanes[index];
            if lane.head.is_none() != lane.tail.is_none() {
                return Err(BorrowedAdmissionError::Invariant);
            }
            if let Some(head) = lane.head
                && backing
                    .slots
                    .get(head)
                    .is_none_or(|entry| entry.length == 0)
            {
                return Err(BorrowedAdmissionError::Invariant);
            }
            if let Some(tail) = lane.tail
                && backing
                    .slots
                    .get(tail)
                    .is_none_or(|entry| entry.length == 0 || entry.next.is_some())
            {
                return Err(BorrowedAdmissionError::Invariant);
            }
            let start = slot
                .checked_mul(backing.max_frame)
                .ok_or(BorrowedAdmissionError::Invariant)?;
            let end = start
                .checked_add(length)
                .ok_or(BorrowedAdmissionError::Invariant)?;
            if end > backing.bytes.len() {
                return Err(BorrowedAdmissionError::Invariant);
            }
            plan.slot = slot;
            plan.tail = lane.tail;
            plan.start = start;
            plan.end = end;
        } else if matches!(self.backing, Backing::Handoff) {
            return Err(BorrowedAdmissionError::Unavailable);
        }
        Ok(plan)
    }

    fn front(&self, index: usize) -> Result<Option<Front<'_>>, ()> {
        match &self.backing {
            Backing::Legacy(lanes) => Ok(lanes[index].front().map(|frame| (frame.as_ref(), None))),
            Backing::Handoff => Ok(None),
            Backing::Reserved(backing) => {
                let lane = &backing.lanes[index];
                if lane.head.is_none() != lane.tail.is_none() {
                    return Err(());
                }
                let Some(slot) = lane.head else {
                    return Ok(None);
                };
                let cell = backing.slots.get(slot).ok_or(())?;
                if cell.length == 0 || cell.length > backing.max_frame {
                    return Err(());
                }
                let tail = lane.tail.ok_or(())?;
                let tail_cell = backing.slots.get(tail).ok_or(())?;
                if tail_cell.length == 0
                    || tail_cell.next.is_some()
                    || ((slot == tail) != cell.next.is_none())
                {
                    return Err(());
                }
                if let Some(next) = cell.next
                    && (next == slot
                        || backing
                            .slots
                            .get(next)
                            .is_none_or(|entry| entry.length == 0))
                {
                    return Err(());
                }
                let start = slot.checked_mul(backing.max_frame).ok_or(())?;
                let end = start.checked_add(cell.length).ok_or(())?;
                let bytes = backing.bytes.get(start..end).ok_or(())?;
                Ok(Some((
                    bytes,
                    Some(Release {
                        slot,
                        next: cell.next,
                        start,
                        end,
                    }),
                )))
            }
        }
    }

    fn prepare_offer(&self) -> Result<Option<Selection>, ()> {
        let channels = self.check_layout()?;
        if self.queued_bytes > self.byte_limit || self.queued_frames > self.frame_limit {
            return Err(());
        }
        if let Backing::Reserved(backing) = &self.backing
            && backing.free.len() != self.frame_limit - self.queued_frames
        {
            return Err(());
        }
        let mut index = self.next;
        for _ in 0..channels {
            let next = (index + 1) % channels;
            if let Some((frame, release)) = self.front(index)? {
                if frame.is_empty() {
                    return Err(());
                }
                let bytes = self.queued_bytes.checked_sub(frame.len()).ok_or(())?;
                let frames = self.queued_frames.checked_sub(1).ok_or(())?;
                if (frames == 0) != (bytes == 0) {
                    return Err(());
                }
                return Ok(Some(Selection {
                    index,
                    next,
                    bytes,
                    frames,
                    release,
                }));
            }
            index = next;
        }
        if self.queued_bytes != 0 || self.queued_frames != 0 {
            return Err(());
        }
        Ok(None)
    }

    #[cfg(test)]
    fn legacy_lanes(&self) -> &[VecDeque<Box<[u8]>>] {
        match &self.backing {
            Backing::Legacy(lanes) => lanes,
            _ => &[],
        }
    }
    /// Payload bytes retained in the shared queue.
    pub fn queued_bytes(&self) -> usize {
        self.queued_bytes
    }
}

#[cfg(test)]
mod handoff_tests;

#[cfg(test)]
mod storage_tests;

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn bounded_fair_fifo_admission() -> Result<(), &'static str> {
        let mut mux = Mux::new(2, 6, 3)?;
        assert!(mux.push(0, vec![1, 1]).is_ok());
        assert!(mux.push(0, vec![2, 2]).is_ok());
        assert!(mux.push(1, vec![3, 3]).is_ok());
        assert_eq!(mux.push(1, vec![9]), Err(AdmissionError::Budget(vec![9])));
        assert_eq!(mux.push(2, vec![9]), Err(AdmissionError::Channel(vec![9])));
        assert_eq!(mux.pop(), Some((0, vec![1, 1])));
        assert_eq!(mux.pop(), Some((1, vec![3, 3])));
        assert_eq!(mux.pop(), Some((0, vec![2, 2])));
        assert_eq!(mux.pop(), None);
        assert_eq!(mux.queued_bytes(), 0);
        Ok(())
    }
    #[test]
    fn spare_capacity_and_small_frames_are_bounded() -> Result<(), &'static str> {
        let mut mux = Mux::new(1, 1024, 2)?;
        let mut reserved = Vec::with_capacity(1024 * 1024);
        reserved.push(7);
        assert!(mux.push(0, reserved).is_ok());
        assert!(mux.push(0, vec![8]).is_ok());
        assert_eq!(mux.push(0, vec![9]), Err(AdmissionError::Budget(vec![9])));
        let (_, first) = mux.pop().ok_or("missing frame")?;
        assert_eq!(first.len(), 1);
        assert_eq!(first.capacity(), 1);
        assert!(mux.push(0, vec![9]).is_ok());
        Ok(())
    }
}
