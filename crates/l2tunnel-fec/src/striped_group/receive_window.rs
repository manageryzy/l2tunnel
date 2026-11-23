//! Cross-group custody for a single authenticated direction.
use super::{
    GroupShape, Profile, ReceivePlan,
    receive_storage::{Group, Rows},
};
use crate::{
    Error, FecContext, GenerationId, mixed_datagram::Packet, storage, striped::RecoveryScratch,
};

/// Physical custody disposition within the configured source window.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReceiveAdmission {
    /// This distinct physical member was admitted.
    Accepted,
    /// A retained member matched an earlier copy byte for byte.
    Duplicate,
    /// Its logical range was delivered and cannot be delivered again.
    Retired,
}

impl From<crate::striped::Admission> for ReceiveAdmission {
    fn from(value: crate::striped::Admission) -> Self {
        match value {
            crate::striped::Admission::Accepted => Self::Accepted,
            crate::striped::Admission::Duplicate => Self::Duplicate,
        }
    }
}

/// Locally solvable mixed groups share one GF workspace. Outstanding sources
/// and a partially committed head group occupy fixed, generation-tagged slots.
/// The negotiated expanded-byte credit still charges the canonical rows and
/// split original independently of their compact in-memory representation.
pub struct ReceiveWindow {
    profile: Profile,
    context: FecContext,
    first: GenerationId,
    next: Option<GenerationId>,
    confirmed: Option<GenerationId>,
    observed: Option<GenerationId>,
    sealed: Option<GenerationId>,
    source_limit: u64,
    expanded_limit: usize,
    oldest_reserve: usize,
    expanded: usize,
    groups: usize,
    pending_in_groups: usize,
    committed_ahead: usize,
    rows: Rows,
    scratch: RecoveryScratch,
    usage: storage::Usage,
}

impl ReceiveWindow {
    /// Protect the largest possible frontier group, including a split singleton.
    pub fn frontier_reserve(profile: Profile, source_limit: usize) -> Result<usize, Error> {
        if source_limit == 0 {
            return Err(Error::InvalidConfig);
        }
        super::original_limit(profile)?;
        let nominal = usize::from(profile.data_cells) + usize::from(profile.parity_cells);
        let body = profile.max_body_bytes.min(usize::from(u16::MAX));
        body.checked_mul(3.max(nominal.min(source_limit)))
            .ok_or(Error::Arithmetic)
    }

    /// Construct the same bounded window using its exact backing allowance.
    pub fn new(
        profile: Profile,
        context: FecContext,
        first: GenerationId,
        source_limit: usize,
        expanded_limit: usize,
    ) -> Result<Self, Error> {
        let create = || {
            let plan = ReceivePlan::for_window(profile, source_limit, expanded_limit)?;
            Self::new_reserved(
                plan,
                storage::Limits {
                    capacity_bytes: plan.capacity_bytes(),
                },
                context,
                first,
            )
        };
        create().map_err(|error| match error {
            storage::Error::Fec(e) => e,
            storage::Error::Layout => Error::Arithmetic,
            _ => Error::Capacity,
        })
    }

    /// Allocate all physical rows, ranges and the shared decoding transaction before use.
    pub fn new_reserved(
        plan: ReceivePlan,
        limits: storage::Limits,
        context: FecContext,
        first: GenerationId,
    ) -> Result<Self, storage::Error> {
        let (rows, scratch, usage) = Rows::reserve(plan, limits.capacity_bytes)?;
        Ok(Self {
            profile: plan.profile,
            context,
            first,
            next: Some(first),
            confirmed: None,
            observed: None,
            sealed: None,
            source_limit: plan.sources as u64,
            expanded_limit: plan.expanded,
            oldest_reserve: plan.frontier,
            expanded: 0,
            groups: 0,
            pending_in_groups: 0,
            committed_ahead: 0,
            rows,
            scratch,
            usage,
        })
    }

    /// Actual preallocated heap capacity including idle rows and local decode scratch.
    pub const fn storage_usage(&self) -> storage::Usage {
        self.usage
    }
    /// Highest contiguous ID whose native consumer has confirmed delivery.
    pub const fn confirmed_through(&self) -> Option<GenerationId> {
        self.confirmed
    }
    /// Oldest uncommitted logical ID. None after committing the maximum ID.
    pub const fn frontier(&self) -> Option<GenerationId> {
        self.next
    }
    /// Last logical ID of an authenticated group that still has retained metadata.
    pub fn group_end(&self, base: GenerationId) -> Option<GenerationId> {
        self.group_start(base).map(|g| g.last)
    }
    /// Highest logical ID of a physical member actually admitted.
    pub const fn observed_through(&self) -> Option<GenerationId> {
        self.observed
    }
    /// Highest logical ID in an authenticated sealed interval.
    pub const fn sealed_through(&self) -> Option<GenerationId> {
        self.sealed
    }
    /// Logical expanded bytes charged against negotiated receive credit.
    pub const fn expanded_bytes(&self) -> usize {
        self.expanded
    }
    /// Number of retained groups, including out-of-order committed groups.
    pub const fn group_count(&self) -> usize {
        self.groups
    }

    /// Logical IDs in admitted groups still awaiting native commit.
    pub const fn uncommitted_in_groups(&self) -> usize {
        self.pending_in_groups
    }

    /// Outstanding IDs through the highest authenticated sealed group. This
    /// includes entirely unseen groups below that horizon and excludes early
    /// native commits. Only the sender can observe debt beyond this horizon.
    pub fn uncommitted_through_sealed(&self) -> usize {
        match (self.next, self.sealed) {
            (Some(next), Some(end)) if next <= end => {
                (end.0 - next.0) as usize + 1 - self.committed_ahead
            }
            _ => 0,
        }
    }

    fn group_start(&self, base: GenerationId) -> Option<Group> {
        self.rows.group(base, self.next).filter(|g| g.base == base)
    }

    /// Admit one authenticated envelope without evicting an old gap. A group
    /// has at most 256 members, irrespective of the size of the receive window.
    pub fn accept_authenticated(
        &mut self,
        context: FecContext,
        wire: &[u8],
        scratch: &mut [u8],
    ) -> Result<ReceiveAdmission, Error> {
        if context != self.context {
            return Err(Error::ContextMismatch);
        }
        let (shape, packet) = self.profile.inspect(wire)?;
        let base = packet.generation();
        if base < self.first {
            return Err(Error::StaleGeneration);
        }
        let count = match shape {
            GroupShape::Originals(q) => q,
            GroupShape::Split(_) => 1,
        };
        let last = GenerationId(
            base.0
                .checked_add(u64::from(count - 1))
                .ok_or(Error::Arithmetic)?,
        );
        let Some(frontier) = self.next else {
            return Ok(ReceiveAdmission::Retired);
        };
        let existing = self.group_start(base);
        let group = if let Some(g) = existing {
            if g.shape != shape || g.geometry != packet.geometry() {
                return Err(Error::Conflict);
            }
            if g.remaining == 0 {
                return Ok(ReceiveAdmission::Retired);
            }
            g
        } else {
            if (base.0..=last.0).any(|id| self.rows.group(GenerationId(id), self.next).is_some()) {
                return Err(Error::Conflict);
            }
            if last < frontier {
                return Ok(ReceiveAdmission::Retired);
            }
            if base < frontier {
                return Err(Error::Conflict);
            }
            if last.0 - frontier.0 >= self.source_limit {
                return Err(Error::WindowBlocked);
            }
            let g = Group {
                base,
                last,
                shape,
                geometry: packet.geometry(),
                remaining: count,
                received: 0,
                longest: 0,
                restored: false,
                split_seen: 0,
            };
            let total = self
                .expanded
                .checked_add(g.expanded())
                .ok_or(Error::Arithmetic)?;
            if total > self.expanded_limit {
                return Err(Error::Capacity);
            }
            if base > frontier {
                let current = self
                    .rows
                    .group(frontier, self.next)
                    .map_or(0, Group::expanded);
                if total - current > self.expanded_limit - self.oldest_reserve {
                    return Err(Error::Capacity);
                }
            }
            g
        };
        let (admission, id) = self.admit(group, &packet, existing.is_none(), scratch)?;
        self.observed = Some(self.observed.map_or(id, |old| old.max(id)));
        self.sealed = Some(self.sealed.map_or(last, |old| old.max(last)));
        Ok(admission)
    }

    fn admit(
        &mut self,
        mut g: Group,
        packet: &Packet<'_>,
        opening: bool,
        scratch: &mut [u8],
    ) -> Result<(ReceiveAdmission, GenerationId), Error> {
        let used = packet.geometry().body_bytes();
        if scratch.len() < used {
            return Err(Error::OutputTooSmall { required: used });
        }
        let ordinal = packet.index();
        let split = match g.shape {
            GroupShape::Split(total) => Some(packet.split_original(total)?),
            GroupShape::Originals(_) => None,
        };
        let id = if split.is_some() {
            g.base
        } else {
            GenerationId(g.base.0 + u64::from(ordinal))
        };
        let received = if split.is_some() {
            g.split_seen & (1 << ordinal) != 0
        } else {
            !opening && self.rows.slot(id).received
        };
        if !opening {
            if let Some((left, right)) = split {
                let original = self.rows.body(id, left.len() + right.len());
                if !original.starts_with(left) || &original[left.len()..] != right {
                    return Err(Error::Conflict);
                }
            } else if received || g.restored {
                packet.write_body(scratch)?;
                if self.rows.body(id, used) != &scratch[..used] {
                    return Err(Error::Conflict);
                }
            }
            if received {
                return Ok((ReceiveAdmission::Duplicate, id));
            }
        }
        let longest = g.longest.max(packet.original().len());
        if usize::from(g.received) + 1 == g.geometry.packet_count() {
            g.geometry.check_longest(longest)?;
        }
        if let Some((left, right)) = split {
            if opening {
                let dst = self.rows.body_mut(id, left.len() + right.len());
                dst[..left.len()].copy_from_slice(left);
                dst[left.len()..].copy_from_slice(right);
            }
            g.split_seen |= 1 << ordinal;
        } else if !g.restored {
            // Expand directly into the permanent row. A late physical copy of
            // a restored row already passed the full byte comparison above.
            packet.write_body(self.rows.body_mut(id, used))?;
        }
        if opening {
            self.rows.open(g);
            self.groups += 1;
            self.pending_in_groups += usize::from(g.remaining);
            self.expanded += g.expanded();
        }
        self.rows.slot_mut(id).received = true;
        g.received += 1;
        g.longest = longest;
        self.rows.slot_mut(g.base).group = Some(g);
        Ok((ReceiveAdmission::Accepted, id))
    }

    /// Borrow an available native original independently of earlier groups.
    pub fn pending_original(&self, id: GenerationId) -> Result<Option<&[u8]>, Error> {
        let Some(g) = self.rows.group(id, self.next) else {
            return Ok(None);
        };
        let slot = self.rows.slot(id);
        if slot.delivered || !(slot.received || g.restored) {
            return Ok(None);
        }
        match g.shape {
            GroupShape::Split(total) => Ok(Some(self.rows.body(id, usize::from(total)))),
            GroupShape::Originals(_) => {
                // Admission canonicalizes physical rows. GF validates the full
                // length and padding before publishing a recovered row.
                let row = self.rows.body(id, g.geometry.systematic_bytes());
                let len = usize::from(u16::from_be_bytes([row[0], row[1]]));
                row.get(2..2 + len).map(Some).ok_or(Error::InvalidSource)
            }
        }
    }

    /// Check whether this group meets its local erasure recovery threshold.
    pub fn can_recover(&self, base: GenerationId) -> bool {
        self.group_start(base)
            .is_some_and(|g| g.remaining != 0 && g.received >= g.geometry.data_cells())
    }

    /// Reconstruct one group transactionally, borrowing the shared GF buffer.
    pub fn recover_missing(&mut self, base: GenerationId) -> Result<usize, Error> {
        let mut g = self.group_start(base).ok_or(Error::UnknownGeneration)?;
        let n = g.geometry.packet_count();
        if matches!(g.shape, GroupShape::Split(_))
            || g.remaining == 0
            || g.restored
            || usize::from(g.received) == n
        {
            return Ok(0);
        }
        if g.received < g.geometry.data_cells() {
            return Err(Error::InsufficientRank);
        }
        let body = g.geometry.body_bytes();
        let mut arrived = [false; 256];
        for (i, seen) in arrived[..n].iter_mut().enumerate() {
            *seen = self.rows.slot(GenerationId(base.0 + i as u64)).received;
        }
        let rows = &self.rows;
        let (canonical, longest) = self.scratch.recover(g.geometry, &arrived[..n], |i| {
            Some(rows.body(GenerationId(base.0 + i as u64), body))
        })?;
        for (i, row) in canonical.chunks_exact(body).enumerate() {
            if !arrived[i] {
                self.rows
                    .body_mut(GenerationId(base.0 + i as u64), body)
                    .copy_from_slice(row);
            }
        }
        g.restored = true;
        g.longest = longest;
        self.rows.slot_mut(base).group = Some(g);
        Ok(n - usize::from(g.received))
    }

    /// Commit only after a native handoff. Fully delivered neighboring groups
    /// merge at their endpoints, so a late old gap can retire a long prefix at once.
    pub fn commit_original(&mut self, id: GenerationId) -> Result<bool, Error> {
        if id < self.first {
            return Err(Error::StaleGeneration);
        }
        if self.confirmed.is_some_and(|known| id <= known) {
            return Ok(false);
        }
        let mut g = self
            .rows
            .group(id, self.next)
            .ok_or(Error::UnknownGeneration)?;
        let slot = self.rows.slot_mut(id);
        if slot.delivered {
            return Ok(false);
        }
        if !slot.received && !g.restored {
            return Err(Error::Unsealed);
        }
        slot.delivered = true;
        self.pending_in_groups -= 1;
        self.committed_ahead += 1;
        g.remaining -= 1;
        self.rows.slot_mut(g.base).group = Some(g);
        if g.remaining == 0 {
            self.expanded -= g.expanded();
            self.rows
                .join_completed(g, self.next.ok_or(Error::Arithmetic)?);
        }
        if self.next == Some(id) {
            self.advance();
            let last = self.confirmed.ok_or(Error::Arithmetic)?;
            self.committed_ahead -= (last.0 - id.0) as usize + 1;
        }
        Ok(true)
    }

    fn advance(&mut self) {
        while let Some(next) = self.next {
            let Some(g) = self.rows.group(next, self.next) else {
                break;
            };
            let confirmed = if g.remaining == 0 {
                let Some(run) = self.rows.slot(g.base).completed else {
                    break;
                };
                self.groups -= run.groups;
                run.last
            } else if self.rows.slot(next).delivered {
                next
            } else {
                break;
            };
            self.confirmed = Some(confirmed);
            self.next = confirmed.0.checked_add(1).map(GenerationId);
        }
    }

    /// Select among already missing IDs for a rank-limited reverse request.
    /// A wholly unseen interval has no authenticated shape, so keep it eligible.
    pub(super) fn needed_for_rank(&self, id: GenerationId) -> bool {
        let Some(group) = self.rows.group(id, self.next) else {
            return true;
        };
        if group.restored || group.received >= group.geometry.data_cells() {
            return false;
        }
        // Recover the last m missing members locally. Selecting all earlier
        // missing IDs gives exactly k - received requests across the entire
        // group, even if a feedback bitmap or timer covers only part of it.
        // Each accepted distinct member can only shrink this selected set.
        let spare = usize::from(group.geometry.parity_cells());
        (id.0..=group.last.0)
            .filter(|&value| !self.rows.slot(GenerationId(value)).received)
            .nth(spare)
            .is_some()
    }

    /// Fill oldest first with missing logical IDs in the requested bounded span.
    pub fn missing_ids(
        &self,
        start: GenerationId,
        span: usize,
        out: &mut [GenerationId],
    ) -> Result<usize, Error> {
        let (Some(frontier), Some(horizon)) = (self.next, self.sealed) else {
            return Ok(0);
        };
        let span = u64::try_from(span).map_err(|_| Error::InvalidConfig)?;
        if span > self.source_limit {
            return Err(Error::InvalidConfig);
        }
        if span == 0 || out.is_empty() {
            return Ok(0);
        }
        let last = horizon.0.min(start.0.saturating_add(span - 1));
        let mut used = 0;
        for value in frontier.0.max(start.0)..=last {
            let id = GenerationId(value);
            if self.rows.group(id, self.next).is_some_and(|g| {
                let s = self.rows.slot(id);
                s.delivered || s.received || g.restored
            }) {
                continue;
            }
            out[used] = id;
            used += 1;
            if used == out.len() {
                break;
            }
        }
        Ok(used)
    }
}

#[cfg(test)]
mod tests;
