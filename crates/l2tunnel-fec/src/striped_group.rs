//! Deadline-bounded mixed packet groups. A generation ID names the first logical
//! original. Named retries can retain the immutable physical group independently
//! of subsequent groups. Time, outer authentication and admission credit belong
//! to the caller.

use crate::{
    Error, GenerationId,
    mixed_datagram::{GroupShape, Profile},
    striped::Geometry,
};

mod receive;
pub use receive::ReceiveGroup;
pub(crate) use receive::split_cells;
/// Compact cumulative and named feedback for this authenticated coding profile.
pub mod feedback;
mod receive_window;
pub use receive_window::{ReceiveAdmission, ReceiveWindow};
mod receive_storage;
pub use receive_storage::ReceivePlan;
pub mod schedule;
mod transmit;
pub use transmit::{FreshMember, TransmitWindow};
mod transmit_storage;
pub use transmit_storage::TransmitPlan;
#[cfg(test)]
mod tests;

/// Largest logical original guaranteed to fit both a full group and a timed-out
/// singleton. Reserve the longest possible ID so progress never depends on a
/// later transition in its wire length.
pub fn original_limit(profile: Profile) -> Result<usize, Error> {
    let full = profile
        .data_cells
        .checked_add(profile.parity_cells)
        .ok_or(Error::InvalidDimensions)?;
    let last = GenerationId(u64::MAX);
    let mut upper = profile.original_limit(GroupShape::Originals(full), last)?;
    let mut lower = 0;
    while lower < upper {
        let length = lower + (upper - lower).div_ceil(2);
        let shape = GroupShape::Split(u16::try_from(length).map_err(|_| Error::Arithmetic)?);
        match profile.original_limit(shape, last) {
            Ok(capacity) if length.div_ceil(2) <= capacity => lower = length,
            Ok(_) | Err(Error::PacketTooLarge) => upper = length - 1,
            Err(error) => return Err(error),
        }
    }
    if lower == 0 {
        Err(Error::PacketTooLarge)
    } else {
        Ok(lower)
    }
}

/// Local FEC formation evidence. These values never travel on the wire.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GroupSeal {
    /// Injected sender tick of the successful seal.
    pub at: u64,
    /// Original first-source deadline, shared by all groups from this batch.
    pub deadline: u64,
    /// Count of earlier sources sealed from this same input batch.
    pub batch_offset: u16,
    /// All source slots available for this decision, including the selected prefix.
    pub remaining: u16,
    /// Largest logical source among these remaining slots, before splitting.
    pub longest: u16,
    /// Logical source slots selected, counting a split source only once.
    pub selected: u16,
}

/// One immutable group. All physical members already contain their parity.
#[derive(Clone, Copy)]
struct GroupHeader {
    seal: GroupSeal,
    generation: GenerationId,
    shape: GroupShape,
    geometry: Geometry,
}

/// Owned sealed group returned by the standalone group sender.
pub struct SealedGroup {
    profile: Profile,
    header: GroupHeader,
    bodies: Vec<u8>,
}

impl SealedGroup {
    fn seal(profile: Profile, header: GroupHeader, originals: &[&[u8]]) -> Result<Self, Error> {
        let geometry = header.geometry;
        let mut bodies = vec![0; geometry.body_bytes() * geometry.packet_count()];
        geometry.encode_group_into(originals, &mut bodies)?;
        Ok(Self {
            profile,
            header,
            bodies,
        })
    }

    /// Absolute ID of the first logical original.
    pub const fn generation(&self) -> GenerationId {
        self.header.generation
    }

    /// Actual number of ordinary originals, or the original length for a singleton.
    pub const fn shape(&self) -> GroupShape {
        self.header.shape
    }

    /// Effective dimensions and cell width, including for short groups.
    pub const fn geometry(&self) -> Geometry {
        self.header.geometry
    }

    /// Borrow the same complete canonical body for a first send or a retry.
    pub fn body(&self, index: u8) -> Result<&[u8], Error> {
        let begin = usize::from(index) * self.geometry().body_bytes();
        self.bodies
            .get(begin..begin + self.geometry().body_bytes())
            .ok_or(Error::InvalidDimensions)
    }

    /// Encode a mixed physical member for the authenticated carrier. The
    /// returned count is its actual plaintext cost with virtual padding removed.
    pub fn write_packet(&self, index: u8, output: &mut [u8]) -> Result<usize, Error> {
        self.profile.encode(
            self.shape(),
            self.generation(),
            index,
            self.geometry(),
            self.body(index)?,
            output,
        )
    }
}

/// At most one open group. When a group fills or reaches its first input's
/// deadline, poll before admitting another input at that same time.
pub struct Sender {
    profile: Profile,
    hold_ticks: u64,
    max_original: usize,
    next: Option<GenerationId>,
    staged: Vec<u8>,
    lengths: [u16; 256],
    front: usize,
    end: usize,
    staged_first: GenerationId,
    deadline: Option<u64>,
    last_tick: u64,
    formation: GroupFormation,
}

/// Successful seals in one sender epoch. Reoffering a pending datagram has no effect.
#[derive(Debug, Default, Clone, Copy, Eq, PartialEq)]
pub struct GroupFormation {
    /// Ordinary groups reaching the negotiated number of originals.
    pub full_groups: u64,
    /// Ordinary groups containing fewer than the negotiated number of originals.
    pub short_groups: u64,
    /// Only one source was present when its input batch first sealed.
    pub lone_splits: u64,
    /// At least two sources remained and no ordinary prefix fit the wire budget.
    pub mtu_splits: u64,
    /// One source remained after another group had sealed from the same batch.
    pub trailing_splits: u64,
    /// Input batches whose first group sealed (possibly before the deadline).
    pub batches: u64,
    /// Total first-source admission to first seal time across these batches.
    pub hold_ticks: u64,
    /// Total time past the original deadline at first seal, in caller ticks.
    pub late_ticks: u64,
    /// Maximum time past the original deadline at first seal, in caller ticks.
    pub max_late_ticks: u64,
}

impl Sender {
    /// Create an empty sender in a nonrepeating ID domain. Ticks are injected.
    pub fn new(
        profile: Profile,
        hold_ticks: u64,
        first: GenerationId,
        now: u64,
    ) -> Result<Self, Error> {
        if hold_ticks == 0 {
            return Err(Error::InvalidConfig);
        }
        let max_original = original_limit(profile)?;
        let count = usize::from(profile.data_cells + profile.parity_cells);
        let capacity = max_original.checked_mul(count).ok_or(Error::Arithmetic)?;
        let mut staged = Vec::new();
        staged
            .try_reserve_exact(capacity)
            .map_err(|_| Error::Capacity)?;
        if staged.capacity() != capacity {
            return Err(Error::Capacity);
        }
        staged.resize(capacity, 0);
        Ok(Self {
            profile,
            hold_ticks,
            max_original,
            next: Some(first),
            staged,
            lengths: [0; 256],
            front: 0,
            end: 0,
            staged_first: first,
            deadline: None,
            last_tick: now,
            formation: GroupFormation::default(),
        })
    }

    /// Maximum admitted logical source length at all source IDs.
    pub const fn max_original(&self) -> usize {
        self.max_original
    }

    /// Next time a group can be polled, including immediate work for a full group.
    pub fn next_wake(&self) -> Option<u64> {
        if self.full() || self.front != 0 {
            Some(self.last_tick)
        } else {
            self.deadline
        }
    }

    fn full(&self) -> bool {
        self.end - self.front == usize::from(self.profile.data_cells + self.profile.parity_cells)
    }

    fn observe(&mut self, now: u64) -> Result<(), Error> {
        if now < self.last_tick {
            return Err(Error::TimeBackwards);
        }
        self.last_tick = now;
        Ok(())
    }

    /// Take a copy and assign an absolute logical ID only after admission.
    pub fn submit(&mut self, now: u64, original: &[u8]) -> Result<GenerationId, Error> {
        self.observe(now)?;
        if self.full() || self.front != 0 || self.deadline.is_some_and(|time| now >= time) {
            return Err(Error::Capacity);
        }
        if original.is_empty() {
            return Err(Error::InvalidSource);
        }
        if original.len() > self.max_original {
            return Err(Error::PacketTooLarge);
        }
        let id = self.next.ok_or(Error::SymbolExhausted)?;
        if self.end == self.front {
            self.deadline = Some(
                now.checked_add(self.hold_ticks)
                    .ok_or(Error::DeadlineOverflow)?,
            );
            self.staged_first = id;
        }
        let start = self.end * self.max_original;
        self.staged[start..start + original.len()].copy_from_slice(original);
        self.lengths[self.end] = original.len() as u16;
        self.end += 1;
        self.next = id.0.checked_add(1).map(GenerationId);
        Ok(id)
    }

    /// Seal at most one group. At expiry, emit the largest contiguous prefix
    /// fitting its shortened geometry, or split the first source. The rest of
    /// this batch remains immediately payable at the same original deadline.
    pub fn poll_group(&mut self, now: u64) -> Result<Option<SealedGroup>, Error> {
        let profile = self.profile;
        self.poll_with(now, |header, originals| {
            SealedGroup::seal(profile, header, originals)
        })
    }

    fn poll_with<T>(
        &mut self,
        now: u64,
        seal: impl FnOnce(GroupHeader, &[&[u8]]) -> Result<T, Error>,
    ) -> Result<Option<T>, Error> {
        self.observe(now)?;
        if self.front == self.end {
            return Ok(None);
        }
        if self.front == 0 && !self.full() && self.deadline.is_none_or(|time| now < time) {
            return Ok(None);
        }
        let count = self.end - self.front;
        let first = GenerationId(self.staged_first.0 + self.front as u64);
        let mut refs: [&[u8]; 256] = [&[]; 256];
        let mut largest = [0; 256];
        let mut maximum = 0;
        for (index, i) in (self.front..self.end).enumerate() {
            let start = i * self.max_original;
            let length = self.lengths[i];
            refs[index] = &self.staged[start..start + usize::from(length)];
            maximum = maximum.max(length);
            largest[index] = maximum;
        }
        let profile = self.profile;
        let header = |shape: GroupShape, originals: &[&[u8]]| -> Result<GroupHeader, Error> {
            let (k, m) = shape.dimensions(profile.data_cells, profile.parity_cells)?;
            let geometry = Geometry::for_group(k, m, originals, profile.max_body_bytes)?;
            Ok(GroupHeader {
                seal: GroupSeal {
                    at: now,
                    deadline: self.deadline.ok_or(Error::Unsealed)?,
                    batch_offset: self.front as u16,
                    remaining: count as u16,
                    longest: maximum,
                    selected: match shape {
                        GroupShape::Originals(n) => n,
                        GroupShape::Split(_) => 1,
                    },
                },
                generation: first,
                shape,
                geometry,
            })
        };
        for take in (2..=count).rev() {
            let shape = GroupShape::Originals(take as u16);
            // The largest member also pays the largest parity width. Shorter
            // members share that width and have a smaller compact wire size.
            let capacity = match self.profile.original_limit(shape, first) {
                Ok(limit) => limit,
                Err(Error::PacketTooLarge) => 0,
                Err(error) => return Err(error),
            };
            if usize::from(largest[take - 1]) <= capacity {
                let originals = &refs[..take];
                let sealed = seal(header(shape, originals)?, originals)?;
                self.consume(take, now);
                return Ok(Some(sealed));
            }
        }
        let source = refs[0];
        let shape = GroupShape::Split(source.len() as u16);
        let (left, rest) = source.split_at(source.len().div_ceil(2));
        let right = if rest.is_empty() { left } else { rest };
        let originals = [left, right];
        let sealed = seal(header(shape, &originals)?, &originals)?;
        self.consume(1, now);
        Ok(Some(sealed))
    }
    fn consume(&mut self, sources: usize, now: u64) {
        let remaining = self.end - self.front;
        let counter = match sources {
            1 if remaining > 1 => &mut self.formation.mtu_splits,
            1 if self.front > 0 => &mut self.formation.trailing_splits,
            1 => &mut self.formation.lone_splits,
            n if n == usize::from(self.profile.data_cells + self.profile.parity_cells) => {
                &mut self.formation.full_groups
            }
            _ => &mut self.formation.short_groups,
        };
        *counter = counter.saturating_add(1);
        if self.front == 0
            && let Some(deadline) = self.deadline
        {
            let held = now - (deadline - self.hold_ticks);
            let late = now.saturating_sub(deadline);
            self.formation.batches = self.formation.batches.saturating_add(1);
            self.formation.hold_ticks = self.formation.hold_ticks.saturating_add(held);
            self.formation.late_ticks = self.formation.late_ticks.saturating_add(late);
            self.formation.max_late_ticks = self.formation.max_late_ticks.max(late);
        }
        self.front += sources;
        if self.front == self.end {
            self.deadline = None;
            self.front = 0;
            self.end = 0;
        }
    }
}
