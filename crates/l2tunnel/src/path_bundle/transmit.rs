//! Immutable native groups retained until authenticated logical delivery confirmation.
use l2tunnel_fec::path_shards::Profile;
use l2tunnel_pipeline::path_ack::{AckBatch, LOGICAL_GROUP, MAX_WINDOW};
use l2tunnel_pipeline::path_batch::{
    self, BatchId, PathBatcher, PathConfig, PathId, Prepared, Shard,
};
use std::collections::VecDeque;
use std::time::Duration;

mod pending;
use pending::Pending;

/// Local state of one immutable member, before or after carrier payment.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MemberState {
    /// No accepted first flight and no successful carrier payment.
    Unstaged,
    /// Accepted, possibly frozen bytes. Bits identify their actual physical paths.
    Staged {
        /// Physical slot bitset, including every accepted explicit replica.
        paths: [u64; 4],
    },
    /// At least one carrier payment, with no currently staged copy.
    Paid,
    /// Logical delivery has already released the group.
    Released,
}

/// Result of coalescing default recovery producers without changing explicit replicas.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecoveryStage {
    /// The request took custody of a not-yet-staged first flight.
    First(path_batch::EntryPosition),
    /// A previously paid member was accepted for another carrier payment.
    Retry(path_batch::EntryPosition),
    /// Another producer already owns pending bytes; no new entry was accepted.
    AlreadyStaged {
        /// Physical slots currently holding at least one pending copy.
        paths: [u64; 4],
    },
    /// Logical delivery made the request obsolete.
    Released,
}

/// Local sender errors. Failed confirmations leave the same custody available for retry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// Invalid geometry, lane, record limit or logical window.
    Configuration,
    /// Admission would exceed the sequence span from the oldest outstanding group.
    WindowFull,
    /// The local group sequence space has reached its exclusive end.
    Exhausted,
    /// A local allocation failed.
    Allocation,
    /// The supplied clock predates admission, or an absolute deadline overflows.
    Clock,
    /// A peer names a group not issued in this epoch or an unnegotiated ordinal.
    Unknown,
    /// The peer claims group delivery before K distinct shard ordinals were paid.
    Unpaid,
    /// Encoding a native record failed.
    Codec(l2tunnel_fec::Error),
    /// The physical path refused staging, preparation or confirmation.
    Path(path_batch::Error),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "path bundle transmitter: {self:?}")
    }
}
impl std::error::Error for Error {}
impl From<path_batch::Error> for Error {
    fn from(value: path_batch::Error) -> Self {
        Self::Path(value)
    }
}
impl From<l2tunnel_fec::Error> for Error {
    fn from(value: l2tunnel_fec::Error) -> Self {
        Self::Codec(value)
    }
}

struct Group {
    bodies: Vec<Vec<u8>>,
    born: Duration,
    paid: [u64; 4],
    promoted: [u64; 4],
    pending: Vec<Pending>,
    distinct: u8,
    // 32 bytes plus a one-byte count per retained group, bounded by the negotiated window.
    peer_ordinals: [u64; 4],
    peer_distinct: u8,
    probe: u8,
}

/// Positive authenticated evidence available while a staged entry is still mutable.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReceiptEvidence {
    /// No positive evidence for this member.
    None,
    /// This specific ordinal was positively acknowledged on a paid path.
    Member,
    /// K distinct member ordinals were positively acknowledged across paths.
    Rank,
    /// The group has already transferred logical native custody.
    Native,
}

impl Group {
    fn was_paid(&self, ordinal: u8) -> bool {
        self.paid[usize::from(ordinal / 64)] & (1 << (ordinal % 64)) != 0
    }

    fn promoted(&self, ordinal: u8) -> bool {
        self.promoted[usize::from(ordinal / 64)] & (1 << (ordinal % 64)) != 0
    }

    fn paid(&mut self, ordinal: u8) {
        let word = &mut self.paid[usize::from(ordinal / 64)];
        let bit = 1u64 << (ordinal % 64);
        if *word & bit == 0 {
            *word |= bit;
            self.distinct += 1;
        }
    }
}

struct Lane {
    config: PathConfig,
    fresh: u64,
}

/// Sending half of one authenticated session, direction and epoch. Each physical lane
/// advances its own cursor. ACKs for carrier packets do not convey native group delivery.
pub struct Transmitter {
    profile: Profile,
    threshold: u8,
    max_hold: Duration,
    window: usize,
    next: u64,
    last_admit: Duration,
    // One slot per issued ID from the oldest hole. Selective delivery drops bodies
    // immediately while the vacant slot still bounds how far admission can advance.
    groups: VecDeque<Option<Group>>,
    lanes: Vec<Lane>,
    batches: PathBatcher,
    receipt: Vec<(u64, u8)>,
}

impl Transmitter {
    /// Negotiate common shard sizes against every path's plaintext MTU. The 27-byte
    /// allowance covers maximal DATA/path/sequence/count, generation, extent and
    /// migrated ordinal fields, including at the end of the sequence space.
    pub fn new(
        configs: &[PathConfig],
        threshold: u8,
        max_native: u16,
        window: usize,
    ) -> Result<Self, Error> {
        let paths = u8::try_from(configs.len()).map_err(|_| Error::Configuration)?;
        if paths == 0 || !(1..=MAX_WINDOW).contains(&window) {
            return Err(Error::Configuration);
        }
        let mut lanes = Vec::new();
        lanes
            .try_reserve_exact(configs.len())
            .map_err(|_| Error::Allocation)?;
        let mut min_payload = usize::MAX;
        let mut max_hold = Duration::ZERO;
        let mut max_entries = 0;
        for &config in configs {
            min_payload = min_payload.min(config.payload_limit()?);
            max_hold = max_hold.max(config.max_hold);
            max_entries = max_entries.max(config.max_entries);
            lanes.push(Lane { config, fresh: 0 });
        }
        let max_shard = min_payload
            .checked_sub(27)
            .and_then(|v| u16::try_from(v).ok())
            .ok_or(Error::Configuration)?;
        let profile = Profile::new(paths, threshold, max_native, max_shard)?;
        let mut groups = VecDeque::new();
        groups
            .try_reserve_exact(window)
            .map_err(|_| Error::Allocation)?;
        let mut receipt = Vec::new();
        receipt
            .try_reserve_exact(usize::from(max_entries))
            .map_err(|_| Error::Allocation)?;
        Ok(Self {
            profile,
            threshold,
            max_hold,
            window,
            next: 0,
            last_admit: Duration::ZERO,
            groups,
            lanes,
            batches: PathBatcher::new(configs)?,
            receipt,
        })
    }

    /// Exclusive high end of the admitted logical generation space.
    pub fn next_generation(&self) -> u64 {
        self.next
    }
    /// First retained logical group, including groups whose first flight was fully erased.
    pub fn oldest_unconfirmed(&self) -> Option<u64> {
        (!self.groups.is_empty()).then(|| self.floor())
    }

    /// Original absolute deadline for a canonical first payment still owed on
    /// this path. Enqueueing or preparing that DATA does not settle its payment.
    /// A promoted member already has a separate owner for its first attempt.
    pub fn unpaid_natural_deadline(
        &self,
        path: PathId,
        id: u64,
    ) -> Result<Option<Duration>, Error> {
        let hold = self.lane(path)?.config.max_hold;
        Ok(self
            .live_group(id)
            .filter(|g| !g.was_paid(path.get()) && !g.promoted(path.get()))
            .map(|g| g.born + hold))
    }
    fn floor(&self) -> u64 {
        self.next - self.groups.len() as u64
    }

    /// Supply only members mapped from authenticated positive DATA ACKs for this sending
    /// session, direction and epoch. A paid DATA timeout or an advanced floor is insufficient.
    /// This hint can suppress later repairs but never releases native source custody.
    pub fn observe_paid_member_receipt(&mut self, id: u64, ordinal: u8) {
        let Some(offset) = id
            .checked_sub(self.floor())
            .and_then(|v| usize::try_from(v).ok())
        else {
            return;
        };
        let Some(Some(group)) = self.groups.get_mut(offset) else {
            return;
        };
        if usize::from(ordinal) >= group.bodies.len() || !group.was_paid(ordinal) {
            return;
        }
        let word = &mut group.peer_ordinals[usize::from(ordinal / 64)];
        let bit = 1u64 << (ordinal % 64);
        if *word & bit == 0 {
            *word |= bit;
            group.peer_distinct += 1;
        }
    }

    fn live_group(&self, id: u64) -> Option<&Group> {
        let index = usize::try_from(id.checked_sub(self.floor())?).ok()?;
        self.groups.get(index)?.as_ref()
    }

    /// Whether positively acknowledged DATA collectively cover K distinct coding ordinals.
    pub fn peer_has_rank(&self, id: u64) -> bool {
        self.live_group(id)
            .is_some_and(|g| g.peer_distinct >= self.threshold)
    }

    /// Whether the specific coding ordinal was positively confirmed on any path.
    pub fn peer_has_member(&self, id: u64, ordinal: u8) -> bool {
        self.live_group(id).is_some_and(|g| {
            g.peer_ordinals[usize::from(ordinal / 64)] & (1u64 << (ordinal % 64)) != 0
        })
    }

    /// Filter locally staged entries before preparing a carrier packet. A removed entry
    /// relinquishes its pending position without a payment or native custody release.
    pub fn retain_due(
        &mut self,
        path: PathId,
        now: Duration,
        mut keep: impl FnMut(
            path_batch::EntryPosition,
            path_batch::EntryPosition,
            u64,
            u8,
            ReceiptEvidence,
        ) -> bool,
    ) -> Result<(), Error> {
        let floor = self.floor();
        let groups = &mut self.groups;
        let threshold = self.threshold;
        self.batches
            .retain_due(path, now, |old, new, id, ordinal| {
                let group = id
                    .checked_sub(floor)
                    .and_then(|i| usize::try_from(i).ok())
                    .and_then(|i| groups.get_mut(i))
                    .and_then(Option::as_mut);
                let evidence = match group.as_ref() {
                    None => ReceiptEvidence::Native,
                    Some(g) if g.peer_distinct >= threshold => ReceiptEvidence::Rank,
                    Some(g)
                        if g.peer_ordinals[usize::from(ordinal / 64)]
                            & (1u64 << (ordinal % 64))
                            != 0 =>
                    {
                        ReceiptEvidence::Member
                    }
                    Some(_) => ReceiptEvidence::None,
                };
                let retain = keep(old, new, id, ordinal, evidence);
                if !retain && let Some(g) = group {
                    g.pending[usize::from(ordinal)].remove(path.get());
                }
                retain
            })?;
        Ok(())
    }

    /// Admit a complete native record exactly once. An error consumes neither an ID nor a slot.
    pub fn admit(&mut self, now: Duration, native: &[u8]) -> Result<u64, Error> {
        if self.groups.len() == self.window {
            return Err(Error::WindowFull);
        }
        if now < self.last_admit || now.checked_add(self.max_hold).is_none() {
            return Err(Error::Clock);
        }
        let next = self.next.checked_add(1).ok_or(Error::Exhausted)?;
        let bodies = self.profile.encode(native)?;
        let mut pending = Vec::new();
        pending
            .try_reserve_exact(bodies.len())
            .map_err(|_| Error::Allocation)?;
        pending.resize_with(bodies.len(), Pending::default);
        let id = self.next;
        self.groups.push_back(Some(Group {
            bodies,
            born: now,
            paid: [0; 4],
            promoted: [0; 4],
            pending,
            distinct: 0,
            peer_ordinals: [0; 4],
            peer_distinct: 0,
            probe: 0,
        }));
        self.next = next;
        self.last_admit = now;
        Ok(id)
    }

    fn lane(&self, path: PathId) -> Result<&Lane, Error> {
        self.lanes
            .get(usize::from(path.get()))
            .ok_or(Error::Path(path_batch::Error::UnknownPath))
    }

    /// Offer up to `grant` logical slots to this path, counting selective tombstones as
    /// bounded work. A full path accepts a partial result; the other lanes stay independent.
    pub fn fill_path(&mut self, path: PathId, now: Duration, grant: usize) -> Result<usize, Error> {
        self.fill_path_limited(path, now, grant, usize::MAX)
    }

    /// Scan bounded tombstones and promoted first flights, accepting at most one member.
    pub fn fill_path_once(
        &mut self,
        path: PathId,
        now: Duration,
        scan_limit: usize,
    ) -> Result<usize, Error> {
        self.fill_path_limited(path, now, scan_limit, 1)
    }

    /// The next lane cursor and its batch head's current clock deadline, in constant work.
    /// Immediately after a successful single-member fill the cursor follows the accepted ID.
    pub fn staging_cursor_and_head_wake(
        &self,
        path: PathId,
    ) -> Result<(u64, Option<Duration>), Error> {
        Ok((self.lane(path)?.fresh, self.batches.next_wake(path)?))
    }

    fn fill_path_limited(
        &mut self,
        path: PathId,
        now: Duration,
        grant: usize,
        max_accepted: usize,
    ) -> Result<usize, Error> {
        let floor = self.floor();
        let lane = self
            .lanes
            .get_mut(usize::from(path.get()))
            .ok_or(Error::Path(path_batch::Error::UnknownPath))?;
        if now < self.last_admit {
            return Err(Error::Clock);
        }
        lane.fresh = lane.fresh.max(floor);
        let mut accepted = 0;
        for _ in 0..grant.min(self.groups.len()) {
            if lane.fresh == self.next || accepted == max_accepted {
                break;
            }
            if let Some(group) = &mut self.groups[(lane.fresh - floor) as usize]
                && !group.promoted(path.get())
            {
                group.pending[usize::from(path.get())].reserve(path.get())?;
                let born_due = group.born + lane.config.max_hold;
                let shard = Shard {
                    generation: lane.fresh,
                    ordinal: path.get(),
                    bytes: &group.bodies[usize::from(path.get())],
                };
                match self.batches.enqueue(path, now, Some(born_due), shard) {
                    Ok(()) => {
                        group.pending[usize::from(path.get())].add_reserved(path.get());
                        accepted += 1;
                    }
                    Err(path_batch::Error::Backpressure) => break,
                    Err(e) => return Err(e.into()),
                }
            }
            lane.fresh += 1;
        }
        Ok(accepted)
    }

    /// Bytes left on the next unfrozen physical head for an authenticated ACK suffix.
    pub fn ack_space(&self, path: PathId) -> Result<Option<usize>, Error> {
        Ok(self.batches.ack_space(path)?)
    }

    /// Constant-work ingress hint for an unfrozen path. Check the batch head
    /// and exactly one fresh cursor entry. Normal egress owns the complete
    /// wake calculation and advances past retired or delegated entries.
    pub fn has_due_head(&self, path: PathId, now: Duration) -> Result<bool, Error> {
        let lane = self.lane(path)?;
        if self.batches.next_wake(path)?.is_some_and(|at| at <= now) {
            return Ok(true);
        }
        let id = lane.fresh.max(self.floor());
        Ok(self.live_group(id).is_some_and(|group| {
            !group.promoted(path.get()) && group.born + lane.config.max_hold <= now
        }))
    }

    /// Earliest path deadline including admitted work that this path has yet to stage.
    /// A frozen head requires carrier writability, independent of the clock.
    pub fn next_wake(&self, path: PathId) -> Result<Option<Duration>, Error> {
        let lane = self.lane(path)?;
        let batch = self.batches.next_wake(path)?;
        if batch.is_none() && self.batches.oldest_deadline(path)?.is_some() {
            return Ok(None);
        }
        let index = (lane.fresh.max(self.floor()) - self.floor()) as usize;
        let upstream = self
            .groups
            .iter()
            .skip(index)
            .flatten()
            .find(|g| !g.promoted(path.get()))
            .map(|g| g.born + lane.config.max_hold);
        Ok(match (batch, upstream) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        })
    }

    /// Prepare a complete physical DATA or DATA+ACK. Retry its unchanged bytes after
    /// WouldBlock; the upper owner retains any actual protected carrier bytes and nonce.
    pub fn prepare(
        &mut self,
        path: PathId,
        now: Duration,
        ack: Option<&[u8]>,
    ) -> Result<Option<Prepared<'_>>, Error> {
        Ok(self.batches.prepare(path, now, ack)?)
    }

    /// Apply successful carrier payment from the exact frozen entries of this batch.
    /// Recovered group credit counts each ordinal once, even across retransmission paths.
    pub fn confirm(&mut self, id: BatchId) -> Result<(), Error> {
        let config = self.lane(id.path())?.config;
        let bytes = self.batches.prepared_bytes(id)?;
        let decoded = config.decode(id.path(), bytes)?;
        self.receipt.clear();
        self.receipt
            .extend(decoded.entries().map(|s| (s.generation, s.ordinal)));
        self.batches.confirm(id)?;
        let floor = self.floor();
        for &(group, ordinal) in &self.receipt {
            if group >= floor
                && let Some(Some(slot)) = self.groups.get_mut((group - floor) as usize)
            {
                slot.paid(ordinal);
                slot.pending[usize::from(ordinal)].remove(id.path().get());
            }
        }
        Ok(())
    }

    /// Accept an authenticated batch for this owner's precise epoch and direction. Only
    /// logical block 255 conveys group custody. Check every assertion before releasing any.
    pub fn apply_ack(&mut self, batch: &AckBatch) -> Result<usize, Error> {
        let Some(block) = batch.blocks().last().filter(|b| b.path() == LOGICAL_GROUP) else {
            return Ok(0);
        };
        if block.next() > self.next || block.ranges().last().is_some_and(|r| r.end > self.next) {
            return Err(Error::Unknown);
        }
        let floor = self.floor();
        for (i, group) in self.groups.iter().enumerate() {
            if group.as_ref().is_some_and(|g| g.distinct < self.threshold)
                && block.acknowledges(floor + i as u64)
            {
                return Err(Error::Unpaid);
            }
        }
        let mut released = 0;
        for (i, group) in self.groups.iter_mut().enumerate() {
            if group.is_some() && block.acknowledges(floor + i as u64) {
                *group = None;
                released += 1;
            }
        }
        while self.groups.front().is_some_and(Option::is_none) {
            self.groups.pop_front();
        }
        Ok(released)
    }

    /// Enqueue a named outstanding ordinal on any live path. A late name for an already
    /// acknowledged group is idempotent. Backpressure leaves the request with the caller.
    pub fn request(
        &mut self,
        path: PathId,
        now: Duration,
        id: u64,
        ordinal: u8,
    ) -> Result<bool, Error> {
        Ok(self
            .enqueue_retry(path, now, id, ordinal, Some(now))?
            .is_some())
    }

    /// Batch a named retry with other entries until this path fills or its normal deadline arrives.
    pub fn request_batched(
        &mut self,
        path: PathId,
        now: Duration,
        id: u64,
        ordinal: u8,
    ) -> Result<bool, Error> {
        Ok(self
            .request_batched_position(path, now, id, ordinal)?
            .is_some())
    }

    /// Return the accepted local packet and entry position, including repeated identical shards.
    pub fn request_batched_position(
        &mut self,
        path: PathId,
        now: Duration,
        id: u64,
        ordinal: u8,
    ) -> Result<Option<path_batch::EntryPosition>, Error> {
        self.enqueue_retry(path, now, id, ordinal, None)
    }

    /// Inspect all accepted producers, including explicit replicas and frozen packets.
    pub fn member_state(&self, id: u64, ordinal: u8) -> Result<MemberState, Error> {
        if usize::from(ordinal) >= self.lanes.len() || id >= self.next {
            return Err(Error::Unknown);
        }
        let Some(index) = id.checked_sub(self.floor()) else {
            return Ok(MemberState::Released);
        };
        let Some(group) = &self.groups[index as usize] else {
            return Ok(MemberState::Released);
        };
        Ok(
            if let Some(paths) = group.pending[usize::from(ordinal)].paths() {
                MemberState::Staged { paths }
            } else if group.was_paid(ordinal) {
                MemberState::Paid
            } else {
                MemberState::Unstaged
            },
        )
    }

    /// Share one pending payment across default recovery producers. A first-flight
    /// promotion retains its original deadline and replaces the natural lane entry.
    /// Explicit copies remain available through `request_batched_position`.
    pub fn stage_recovery_once(
        &mut self,
        path: PathId,
        now: Duration,
        id: u64,
        ordinal: u8,
    ) -> Result<RecoveryStage, Error> {
        self.lane(path)?;
        let first = match self.member_state(id, ordinal)? {
            MemberState::Staged { paths } => return Ok(RecoveryStage::AlreadyStaged { paths }),
            MemberState::Released => return Ok(RecoveryStage::Released),
            MemberState::Unstaged => true,
            MemberState::Paid => false,
        };
        let index = (id - self.floor()) as usize;
        let latest = if first {
            self.groups[index]
                .as_ref()
                .map(|g| g.born + self.lanes[usize::from(ordinal)].config.max_hold)
        } else {
            None
        };
        let Some(position) = self.enqueue_retry(path, now, id, ordinal, latest)? else {
            return Ok(RecoveryStage::Released);
        };
        if first {
            if let Some(group) = &mut self.groups[index] {
                group.promoted[usize::from(ordinal / 64)] |= 1 << (ordinal % 64);
            }
            Ok(RecoveryStage::First(position))
        } else {
            Ok(RecoveryStage::Retry(position))
        }
    }

    fn enqueue_retry(
        &mut self,
        path: PathId,
        now: Duration,
        id: u64,
        ordinal: u8,
        latest: Option<Duration>,
    ) -> Result<Option<path_batch::EntryPosition>, Error> {
        self.lane(path)?;
        if usize::from(ordinal) >= self.lanes.len() || id >= self.next {
            return Err(Error::Unknown);
        }
        if now < self.last_admit {
            return Err(Error::Clock);
        }
        let Some(index) = id.checked_sub(self.floor()) else {
            return Ok(None);
        };
        let Some(group) = &mut self.groups[index as usize] else {
            return Ok(None);
        };
        group.pending[usize::from(ordinal)].reserve(path.get())?;
        let position = self.batches.enqueue_position(
            path,
            now,
            latest,
            Shard {
                generation: id,
                ordinal,
                bytes: &group.bodies[usize::from(ordinal)],
            },
        )?;
        group.pending[usize::from(ordinal)].add_reserved(path.get());
        Ok(Some(position))
    }

    /// Probe the oldest still-paid group. Rotate its named ordinal only after the
    /// request enters this path; the receiver can rebuild rank without subsequent DATA.
    pub fn retry_oldest(
        &mut self,
        path: PathId,
        now: Duration,
    ) -> Result<Option<(u64, u8)>, Error> {
        self.lane(path)?;
        let Some(Some(group)) = self.groups.front() else {
            return Ok(None);
        };
        if group.distinct == 0 {
            return Ok(None);
        }
        let id = self.floor();
        let ordinal = group.probe;
        self.request(path, now, id, ordinal)?;
        let count = self.lanes.len();
        if let Some(Some(group)) = self.groups.front_mut() {
            group.probe = if usize::from(ordinal) + 1 == count {
                0
            } else {
                ordinal + 1
            };
        }
        Ok(Some((id, ordinal)))
    }
}

#[cfg(test)]
mod tests;
