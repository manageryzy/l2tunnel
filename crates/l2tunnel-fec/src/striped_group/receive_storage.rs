//! Fixed source slots for one direction. A split singleton's full original
//! determines both canonical rows, including all protected lengths and zeros.
use super::{GroupShape, Profile, ReceiveWindow};
use crate::{
    Error, GenerationId,
    storage::{self, Allocation},
    striped::{Geometry, RecoveryPlan, RecoveryScratch},
};

/// Exact heap backing of the receive window, including its one local GF transaction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReceivePlan {
    pub(super) profile: Profile,
    pub(super) sources: usize,
    pub(super) expanded: usize,
    pub(super) frontier: usize,
    slots: usize,
    stride: usize,
    gf: RecoveryPlan,
    bytes: usize,
}

impl ReceivePlan {
    /// Validate the logical credit and price row slots, identities and GF scratch.
    pub fn for_window(
        profile: Profile,
        sources: usize,
        expanded_limit: usize,
    ) -> Result<Self, storage::Error> {
        let frontier =
            ReceiveWindow::frontier_reserve(profile, sources).map_err(storage::Error::Fec)?;
        if expanded_limit < frontier {
            return Err(storage::Error::Fec(Error::InvalidConfig));
        }
        let nominal = usize::from(profile.data_cells + profile.parity_cells);
        // When the frontier points inside a partially delivered group, its
        // earlier physical rows can still authenticate retries and solve erasures.
        let slots = storage::add(sources, sources.min(nominal) - 1)?;
        let stride = profile.max_body_bytes.min(usize::from(u16::MAX));
        let gf = RecoveryPlan::for_profile(profile).map_err(storage::Error::Fec)?;
        let rows = storage::array_bytes::<u8>(storage::mul(slots, stride)?)?;
        let bytes = storage::add(
            storage::add(storage::array_bytes::<Slot>(slots)?, rows)?,
            gf.heap_bytes(),
        )?;
        Ok(Self {
            profile,
            sources,
            expanded: expanded_limit,
            frontier,
            slots,
            stride,
            gf,
            bytes,
        })
    }

    /// Retained array capacities in bytes, excluding the inline owner.
    pub const fn capacity_bytes(self) -> usize {
        self.bytes
    }

    /// Source aperture plus the still-live prefix of one partially committed group.
    pub const fn physical_slots(self) -> usize {
        self.slots
    }

    /// Bytes reserved for canonical rows or split originals at the stable slot stride.
    pub const fn row_bytes(self) -> usize {
        self.slots * self.stride
    }
    /// Identity, delivery and completed-run metadata, including empty slots.
    pub const fn index_bytes(self) -> usize {
        self.slots * size_of::<Slot>()
    }
    /// Shared transaction backing used for any one open group.
    pub const fn recovery_bytes(self) -> usize {
        self.gf.heap_bytes()
    }
}

#[derive(Clone, Copy)]
pub(super) struct Group {
    pub base: GenerationId,
    pub last: GenerationId,
    pub shape: GroupShape,
    pub geometry: Geometry,
    pub received: u16,
    pub remaining: u16,
    pub longest: usize,
    pub restored: bool,
    pub split_seen: u8,
}

impl Group {
    pub fn expanded(self) -> usize {
        self.geometry.packet_count() * self.geometry.body_bytes()
            + match self.shape {
                GroupShape::Split(n) => usize::from(n),
                GroupShape::Originals(_) => 0,
            }
    }
}

/// Both boundary slots of a contiguous run of fully committed groups carry
/// this summary. Closing an old hole jumps the run even after many early writes.
#[derive(Clone, Copy)]
pub(super) struct Completed {
    pub first: GenerationId,
    pub last: GenerationId,
    pub groups: usize,
}

#[derive(Clone, Copy, Default)]
pub(super) struct Slot {
    owner: Option<GenerationId>,
    pub group: Option<Group>,
    pub received: bool,
    pub delivered: bool,
    pub completed: Option<Completed>,
}

pub(super) struct Rows {
    slots: Vec<Slot>,
    bodies: Vec<u8>,
    stride: usize,
}

impl Rows {
    pub fn reserve(
        plan: ReceivePlan,
        limit: usize,
    ) -> Result<(Self, RecoveryScratch, storage::Usage), storage::Error> {
        if plan.bytes > limit {
            return Err(storage::Error::Limit {
                required: plan.bytes,
                limit,
            });
        }
        let mut allocation = Allocation::new(limit);
        let mut slots = allocation.vec(plan.slots)?;
        let mut bodies = allocation.vec(plan.slots * plan.stride)?;
        slots.resize(plan.slots, Slot::default());
        bodies.resize(bodies.capacity(), 0);
        let scratch = RecoveryScratch::new(plan.gf).map_err(storage::Error::Fec)?;
        let mut usage = allocation.usage();
        usage.capacity_bytes = storage::add(usage.capacity_bytes, scratch.reserved_bytes())?;
        usage.allocations += 1;
        if usage.capacity_bytes != plan.bytes {
            return Err(storage::Error::Invariant);
        }
        Ok((
            Self {
                slots,
                bodies,
                stride: plan.stride,
            },
            scratch,
            usage,
        ))
    }

    fn index(&self, id: GenerationId) -> usize {
        (id.0 % self.slots.len() as u64) as usize
    }
    pub fn slot(&self, id: GenerationId) -> &Slot {
        &self.slots[self.index(id)]
    }
    pub fn slot_mut(&mut self, id: GenerationId) -> &mut Slot {
        let i = self.index(id);
        &mut self.slots[i]
    }
    pub fn body(&self, id: GenerationId, len: usize) -> &[u8] {
        let start = self.index(id) * self.stride;
        &self.bodies[start..start + len]
    }
    pub fn body_mut(&mut self, id: GenerationId, len: usize) -> &mut [u8] {
        let start = self.index(id) * self.stride;
        &mut self.bodies[start..start + len]
    }

    pub fn group(&self, id: GenerationId, frontier: Option<GenerationId>) -> Option<Group> {
        let frontier = frontier?;
        let base = self.slot(id).owner?;
        let g = self.slot(base).group?;
        (base == g.base && base <= id && id <= g.last && frontier <= g.last).then_some(g)
    }
    pub fn open(&mut self, group: Group) {
        for n in group.base.0..=group.last.0 {
            *self.slot_mut(GenerationId(n)) = Slot {
                owner: Some(group.base),
                ..Slot::default()
            };
        }
    }
    pub fn join_completed(&mut self, group: Group, frontier: GenerationId) {
        let mut run = Completed {
            first: group.base,
            last: group.last,
            groups: 1,
        };
        if let Some(previous) = group.base.0.checked_sub(1).map(GenerationId)
            && previous >= frontier
            && let Some(left) = self.slot(previous).completed
            && left.last == previous
        {
            run.first = left.first;
            run.groups += left.groups;
        }
        if let Some(next) = group.last.0.checked_add(1).map(GenerationId)
            && let Some(right) = self.slot(next).completed
            && right.first == next
        {
            run.last = right.last;
            run.groups += right.groups;
        }
        self.slot_mut(run.first).completed = Some(run);
        self.slot_mut(run.last).completed = Some(run);
    }
}
