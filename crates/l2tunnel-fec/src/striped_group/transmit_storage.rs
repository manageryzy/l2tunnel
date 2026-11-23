use std::collections::VecDeque;

use super::{GroupHeader, GroupShape, Profile, SealedGroup, original_limit};
use crate::{Error, GenerationId, storage};

/// Exact retained heap for one transmit window, excluding the inline owner,
/// the enclosing scheduler, native queues, and receive-side storage.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransmitPlan {
    pub(super) profile: Profile,
    pub(super) sources: usize,
    staging: usize,
    stride: usize,
    scratch: usize,
    bytes: usize,
}

impl TransmitPlan {
    /// Inventory fixed staging, group metadata, retained members and encoding scratch.
    pub fn for_window(profile: Profile, sources: usize) -> Result<Self, storage::Error> {
        use storage::{Error::Layout, array_bytes};
        if sources == 0 {
            return Err(storage::Error::Fec(Error::InvalidConfig));
        }
        let max_original = original_limit(profile).map_err(storage::Error::Fec)?;
        let n = usize::from(profile.data_cells + profile.parity_cells);
        let max_body = usize::from(u16::MAX).min(profile.max_body_bytes);
        // A split singleton occupies both physical members in its one logical slot.
        let split_pair = (max_original.div_ceil(2) + 2) * 4;
        let stride = max_body.max(split_pair);
        let staging = array_bytes::<u8>(n.checked_mul(max_original).ok_or(Layout)?)?;
        let scratch =
            array_bytes::<u8>(n.min(sources).max(2).checked_mul(max_body).ok_or(Layout)?)?;
        let arena = array_bytes::<u8>(sources.checked_mul(stride).ok_or(Layout)?)?;
        let headers = array_bytes::<GroupHeader>(sources)?;
        let bytes = [staging, scratch, arena, headers]
            .into_iter()
            .try_fold(0usize, |sum, n| sum.checked_add(n).ok_or(Layout))?;
        Ok(Self {
            profile,
            sources,
            staging,
            stride,
            scratch,
            bytes,
        })
    }

    /// Exact heap capacity, excluding allocator bookkeeping.
    pub const fn capacity_bytes(self) -> usize {
        self.bytes
    }
}

pub(super) enum Groups {
    Growing(VecDeque<SealedGroup>),
    Reserved {
        headers: VecDeque<GroupHeader>,
        arena: Vec<u8>,
        scratch: Vec<u8>,
        plan: TransmitPlan,
        usage: storage::Usage,
    },
}

impl Groups {
    pub(super) fn reserved(
        plan: TransmitPlan,
        limit: usize,
        staged: usize,
    ) -> Result<Self, storage::Error> {
        let mut alloc = storage::Allocation::new(plan.bytes - plan.staging);
        let mut arena = alloc.vec::<u8>(plan.sources * plan.stride)?;
        let mut scratch = alloc.vec::<u8>(plan.scratch)?;
        arena.resize(arena.capacity(), 0);
        scratch.resize(scratch.capacity(), 0);
        let mut headers = VecDeque::new();
        headers
            .try_reserve_exact(plan.sources)
            .map_err(|_| storage::Error::Allocation)?;
        if headers.capacity() != plan.sources || staged != plan.staging {
            return Err(storage::Error::Invariant);
        }
        let usage = storage::Usage {
            limit_bytes: limit,
            capacity_bytes: plan.bytes,
            allocations: 4,
        };
        Ok(Self::Reserved {
            headers,
            arena,
            scratch,
            plan,
            usage,
        })
    }

    pub(super) fn len(&self) -> usize {
        match self {
            Self::Growing(q) => q.len(),
            Self::Reserved { headers, .. } => headers.len(),
        }
    }

    pub(super) fn header(&self, i: usize) -> Option<GroupHeader> {
        match self {
            Self::Growing(q) => q.get(i).map(|g| g.header),
            Self::Reserved { headers, .. } => headers.get(i).copied(),
        }
    }

    pub(super) fn find(&self, id: GenerationId) -> usize {
        match self {
            Self::Growing(q) => q.partition_point(|g| g.header.last_source() < id),
            Self::Reserved { headers, .. } => headers.partition_point(|g| g.last_source() < id),
        }
    }

    fn member_offset(plan: TransmitPlan, group: GroupHeader, ordinal: u8) -> usize {
        let (id, within) = match group.shape {
            GroupShape::Originals(_) => (group.generation.0 + u64::from(ordinal), 0),
            GroupShape::Split(_) => (
                group.generation.0,
                usize::from(ordinal) * group.geometry.body_bytes(),
            ),
        };
        (id % plan.sources as u64) as usize * plan.stride + within
    }

    pub(super) fn seal(
        &mut self,
        profile: Profile,
        header: GroupHeader,
        originals: &[&[u8]],
    ) -> Result<(), Error> {
        match self {
            Self::Growing(groups) => {
                groups.push_back(SealedGroup::seal(profile, header, originals)?)
            }
            Self::Reserved {
                headers,
                arena,
                scratch,
                plan,
                ..
            } => {
                if headers.len() == plan.sources {
                    return Err(Error::Capacity);
                }
                let used = header.geometry.encode_group_into(originals, scratch)?;
                for (i, body) in scratch[..used]
                    .chunks_exact(header.geometry.body_bytes())
                    .enumerate()
                {
                    let start = Self::member_offset(*plan, header, i as u8);
                    arena[start..start + body.len()].copy_from_slice(body);
                }
                headers.push_back(header);
            }
        }
        Ok(())
    }

    pub(super) fn write(&self, i: usize, ordinal: u8, out: &mut [u8]) -> Result<usize, Error> {
        match self {
            Self::Growing(groups) => groups[i].write_packet(ordinal, out),
            Self::Reserved {
                headers,
                arena,
                plan,
                ..
            } => {
                let h = headers[i];
                let start = Self::member_offset(*plan, h, ordinal);
                plan.profile.encode(
                    h.shape,
                    h.generation,
                    ordinal,
                    h.geometry,
                    &arena[start..start + h.geometry.body_bytes()],
                    out,
                )
            }
        }
    }

    pub(super) fn pop_front(&mut self) {
        match self {
            Self::Growing(groups) => {
                groups.pop_front();
            }
            Self::Reserved { headers, .. } => {
                headers.pop_front();
            }
        }
    }
}
