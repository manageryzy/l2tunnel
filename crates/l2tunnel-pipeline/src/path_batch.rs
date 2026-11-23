//! Independent bounded batching for previously encoded group shards.
//!
//! Construct one owner per authenticated session, epoch and direction. Each
//! negotiated path gets a FIFO of two MTU-sized buffers. A prepared datagram
//! retains its exact plaintext while the carrier retains any external ciphertext,
//! nonce and ACK receipt token through a partial or blocked handoff. Only
//! complete carrier acceptance may confirm it. No packet schedules another path.

use std::{fmt, mem, time::Duration};

mod trim;
mod wire;
pub use wire::{Decoded, entry_len};

/// Negotiated physical slot. Value 255 is reserved for another namespace.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct PathId(u8);

impl PathId {
    /// Check an external slot before indexing a path binding.
    pub const fn new(slot: u8) -> Result<Self, Error> {
        if slot == u8::MAX {
            Err(Error::UnknownPath)
        } else {
            Ok(Self(slot))
        }
    }
    /// Wire value.
    pub const fn get(self) -> u8 {
        self.0
    }
}

/// One immutable encoded group shard. Its bytes can contain many inner frame fragments.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Shard<'a> {
    /// Global group identity in this direction and epoch. The exclusive end is reserved.
    pub generation: u64,
    /// FEC member, independent of the selected carrier slot during retries.
    pub ordinal: u8,
    /// Complete codec-owned body, never split by this batcher.
    pub bytes: &'a [u8],
}

/// Independent limits for one actual physical path.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PathConfig {
    /// Maximum whole physical IP packet size.
    pub mtu: usize,
    /// Bytes reserved for this path's network, carrier and protection layers.
    pub outer_bytes: usize,
    /// Maximum age of the oldest buffered shard before sending.
    pub max_hold: Duration,
    /// Maximum entries per physical DATA payload, at least one.
    pub max_entries: u8,
}

impl PathConfig {
    /// Available batch plaintext bytes after the path's external charges.
    pub fn payload_limit(self) -> Result<usize, Error> {
        let limit = self
            .mtu
            .checked_sub(self.outer_bytes)
            .ok_or(Error::InvalidConfig)?;
        if self.max_entries == 0
            || self.mtu > usize::from(u16::MAX)
            || limit < wire::header_len(0) + 3
        {
            return Err(Error::InvalidConfig);
        }
        Ok(limit)
    }

    /// Decode and enforce the configured physical MTU and entry-count policy.
    pub fn decode(self, path: PathId, bytes: &[u8]) -> Result<Decoded<'_>, Error> {
        let value = Decoded::parse(path, self.payload_limit()?, bytes)?;
        if value.count > self.max_entries {
            return Err(Error::TooLarge);
        }
        Ok(value)
    }
}

/// Failures preserve unconfirmed data. Backpressure has path-local scope.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// Invalid physical limits or no negotiated slots.
    InvalidConfig,
    /// Unknown or reserved physical slot.
    UnknownPath,
    /// The payload names a different authenticated path.
    WrongPath,
    /// Fixed storage could not be reserved.
    Allocation,
    /// An empty shard has no representation.
    EmptyShard,
    /// One complete shard or packet exceeds the selected bound.
    TooLarge,
    /// Both local datagrams are occupied; the caller retains the input.
    Backpressure,
    /// The supplied local time decreased on this path.
    TimeBackwards,
    /// The timer is outside the caller's duration domain.
    DeadlineOverflow,
    /// A reserved sequence or generation would be issued.
    Exhausted,
    /// A handoff completion did not identify this path's current preparation.
    StaleReceipt,
    /// Invalid, noncanonical or truncated authenticated plaintext.
    Malformed,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "physical path batch: {self:?}")
    }
}
impl std::error::Error for Error {}

/// Identity of one per-path DATA batch, usable only on its issuing session owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BatchId {
    path: PathId,
    sequence: u64,
}

impl BatchId {
    /// Physical carrier slot.
    pub const fn path(self) -> PathId {
        self.path
    }
    /// Path-local DATA sequence starting at zero, separate from the external nonce.
    pub const fn sequence(self) -> u64 {
        self.sequence
    }
}

/// Exact local position of an accepted shard in an immutable path DATA packet.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EntryPosition {
    /// Receipt of the packet to which the entry was appended.
    pub batch: BatchId,
    /// Zero-based entry index in that packet, independent of the coding ordinal.
    pub index: u8,
}

/// Borrowed, frozen carrier handoff. Repeated preparation returns the same value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Prepared<'a> {
    /// Receipt for complete carrier acceptance.
    pub id: BatchId,
    /// Earliest deadline of the packed input shards, fixed through backpressure.
    pub deadline: Duration,
    /// Exact DATA v1 or DATA+ACK v1 plaintext.
    pub bytes: &'a [u8],
    /// Exact ACK already attached to this batch, including its discriminant.
    /// Retain the corresponding ACK token until this batch is paid.
    pub attached_ack: Option<&'a [u8]>,
    /// Additional bytes that fit the MTU; prepared bytes are already frozen.
    pub remaining_bytes: usize,
}

struct Buffer {
    bytes: Vec<u8>,
    sequence: u64,
    count: u8,
    deadline: Duration,
    opened_at: Duration,
    closed: bool,
}

impl Buffer {
    fn new(limit: usize) -> Result<Self, Error> {
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(limit)
            .map_err(|_| Error::Allocation)?;
        if bytes.capacity() != limit {
            return Err(Error::Allocation);
        }
        Ok(Self {
            bytes,
            sequence: 0,
            count: 0,
            deadline: Duration::ZERO,
            opened_at: Duration::ZERO,
            closed: false,
        })
    }

    fn start(&mut self, path: PathId, sequence: u64, deadline: Duration, now: Duration) {
        self.sequence = sequence;
        self.deadline = deadline;
        self.opened_at = now;
        self.bytes.extend_from_slice(&[wire::DATA, path.get()]);
        wire::put_varint(sequence, &mut self.bytes);
        self.bytes.push(0);
    }

    fn clear(&mut self) {
        self.bytes.clear();
        self.count = 0;
        self.closed = false;
    }
}

struct Lane {
    config: PathConfig,
    limit: usize,
    open: Buffer,
    ready: Buffer,
    frozen_data_len: Option<usize>,
    next: u64,
    clock: Duration,
}

impl Lane {
    fn observe(&mut self, now: Duration) -> Result<(), Error> {
        if now < self.clock {
            return Err(Error::TimeBackwards);
        }
        self.clock = now;
        Ok(())
    }

    fn promote(&mut self) {
        mem::swap(&mut self.ready, &mut self.open);
    }

    fn open_sequence(&self) -> Result<u64, Error> {
        self.next
            .checked_add(u64::from(self.ready.count != 0))
            .filter(|n| *n < u64::MAX)
            .ok_or(Error::Exhausted)
    }

    fn due(&self) -> bool {
        self.open.count != 0 && (self.open.closed || self.clock >= self.open.deadline)
    }
}

/// Two fixed buffers per slot; no runtime I/O, scheduler task or real clock.
pub struct PathBatcher {
    lanes: Vec<Lane>,
}

impl PathBatcher {
    /// Configs bind slots 0 through configs.len()-1 for the lifetime of this epoch.
    pub fn new(configs: &[PathConfig]) -> Result<Self, Error> {
        if configs.is_empty() || configs.len() > usize::from(u8::MAX) {
            return Err(Error::InvalidConfig);
        }
        let mut lanes = Vec::new();
        lanes
            .try_reserve_exact(configs.len())
            .map_err(|_| Error::Allocation)?;
        for &config in configs {
            let limit = config.payload_limit()?;
            lanes.push(Lane {
                config,
                limit,
                open: Buffer::new(limit)?,
                ready: Buffer::new(limit)?,
                next: 0,
                frozen_data_len: None,
                clock: Duration::ZERO,
            });
        }
        Ok(Self { lanes })
    }

    fn lane(&self, path: PathId) -> Result<&Lane, Error> {
        self.lanes
            .get(usize::from(path.get()))
            .ok_or(Error::UnknownPath)
    }
    fn lane_mut(&mut self, path: PathId) -> Result<&mut Lane, Error> {
        self.lanes
            .get_mut(usize::from(path.get()))
            .ok_or(Error::UnknownPath)
    }

    /// Actual reserved heap bytes, excluding allocator bookkeeping.
    pub fn capacity_bytes(&self) -> usize {
        self.lanes.capacity() * size_of::<Lane>()
            + self
                .lanes
                .iter()
                .map(|lane| lane.open.bytes.capacity() + lane.ready.bytes.capacity())
                .sum::<usize>()
    }

    /// Oldest unsent absolute deadline, including data already waiting for writability.
    pub fn oldest_deadline(&self, path: PathId) -> Result<Option<Duration>, Error> {
        let lane = self.lane(path)?;
        Ok([&lane.ready, &lane.open]
            .into_iter()
            .filter(|b| b.count != 0)
            .map(|b| b.deadline)
            .min())
    }

    /// Bytes available to a piggyback ACK on the next unexposed DATA packet.
    /// None means this path is empty or its head is already frozen.
    pub fn ack_space(&self, path: PathId) -> Result<Option<usize>, Error> {
        let lane = self.lane(path)?;
        if lane.frozen_data_len.is_some() {
            return Ok(None);
        }
        let head = if lane.ready.count != 0 {
            &lane.ready
        } else {
            &lane.open
        };
        Ok((head.count != 0).then(|| lane.limit - head.bytes.len()))
    }

    /// Writability drives a frozen handoff; a waiting path needs no busy timer.
    pub fn next_wake(&self, path: PathId) -> Result<Option<Duration>, Error> {
        let lane = self.lane(path)?;
        Ok(if lane.frozen_data_len.is_some() {
            None
        } else if lane.ready.count != 0 || lane.open.closed {
            Some(lane.clock)
        } else {
            (lane.open.count != 0).then_some(lane.open.deadline)
        })
    }

    /// Copy one complete immutable shard. An optional upstream absolute deadline
    /// can shorten the path hold. The caller retains its input on every refusal.
    pub fn enqueue(
        &mut self,
        path: PathId,
        now: Duration,
        latest: Option<Duration>,
        shard: Shard<'_>,
    ) -> Result<(), Error> {
        self.enqueue_position(path, now, latest, shard).map(|_| ())
    }

    /// Enqueue and return the exact local position for caller-owned payment accounting.
    pub fn enqueue_position(
        &mut self,
        path: PathId,
        now: Duration,
        latest: Option<Duration>,
        shard: Shard<'_>,
    ) -> Result<EntryPosition, Error> {
        let extra = entry_len(path, shard)?;
        let lane = self.lane_mut(path)?;
        lane.observe(now)?;
        let sequence = if lane.open.count == 0 {
            lane.open_sequence()?
        } else {
            lane.open.sequence
        };
        if extra > lane.limit.saturating_sub(wire::header_len(sequence)) {
            return Err(Error::TooLarge);
        }
        // Work assembled at one injected instant may share an already-due packet.
        // It remains immediately payable; a later turn cannot extend its hold.
        let expired_before_turn = now > lane.open.opened_at && now >= lane.open.deadline;
        if lane.open.count != 0
            && (lane.open.closed
                || expired_before_turn
                || extra > lane.limit - lane.open.bytes.len())
        {
            lane.open.closed = true;
            if lane.ready.count != 0 {
                return Err(Error::Backpressure);
            }
            lane.promote();
        }
        if lane.open.count == 0 {
            let seq = lane.open_sequence()?;
            if extra > lane.limit.saturating_sub(wire::header_len(seq)) {
                return Err(Error::TooLarge);
            }
            let deadline = match (now.checked_add(lane.config.max_hold), latest) {
                (Some(a), Some(b)) => a.min(b),
                (Some(a), None) | (None, Some(a)) => a,
                (None, None) => return Err(Error::DeadlineOverflow),
            };
            lane.open.start(path, seq, deadline, now);
        } else if let Some(due) = latest {
            lane.open.deadline = lane.open.deadline.min(due);
        }
        let b = &mut lane.open;
        wire::append(path, shard, &mut b.bytes)?;
        b.count += 1;
        b.bytes[wire::header_len(b.sequence) - 1] = b.count;
        b.closed = b.count == lane.config.max_entries || lane.limit - b.bytes.len() < 3;
        Ok(EntryPosition {
            batch: BatchId {
                path,
                sequence: b.sequence,
            },
            index: b.count - 1,
        })
    }

    /// Offer the next DATA or DATA+ACK. A due nonempty ACK may flush this
    /// path early. A full DATA datagram is handed off without waiting for ACK
    /// space. Inspect attached_ack and confirm the separate ACK token only
    /// after the carrier accepts these exact frozen bytes.
    pub fn prepare(
        &mut self,
        path: PathId,
        now: Duration,
        due_ack: Option<&[u8]>,
    ) -> Result<Option<Prepared<'_>>, Error> {
        let lane = self.lane_mut(path)?;
        lane.observe(now)?;
        let due_ack = due_ack.filter(|b| !b.is_empty());
        if lane.ready.count == 0 {
            if lane.open.count == 0 || (!lane.due() && due_ack.is_none()) {
                return Ok(None);
            }
            lane.promote();
        }
        let b = &mut lane.ready;
        let data_len = if let Some(len) = lane.frozen_data_len {
            len
        } else {
            let len = b.bytes.len();
            if let Some(ack) = due_ack.filter(|ack| ack.len() <= lane.limit - len) {
                crate::path_ack::AckBatch::decode(ack).map_err(|_| Error::Malformed)?;
                b.bytes[0] = wire::DATA_ACK;
                b.bytes.extend_from_slice(ack);
            }
            lane.frozen_data_len = Some(len);
            len
        };
        Ok(Some(Prepared {
            id: BatchId {
                path,
                sequence: b.sequence,
            },
            deadline: b.deadline,
            bytes: &b.bytes,
            attached_ack: (data_len != b.bytes.len()).then(|| &b.bytes[data_len..]),
            remaining_bytes: lane.limit - b.bytes.len(),
        }))
    }

    /// Borrow the exact still-frozen plaintext for this path's handoff receipt.
    pub fn prepared_bytes(&self, id: BatchId) -> Result<&[u8], Error> {
        let lane = self.lane(id.path)?;
        if lane.frozen_data_len.is_none() || lane.ready.sequence != id.sequence {
            return Err(Error::StaleReceipt);
        }
        Ok(&lane.ready.bytes)
    }

    /// Complete a paid handoff exactly once. A failed or partial send must
    /// keep its token and call prepare again when that same path is writable.
    pub fn confirm(&mut self, id: BatchId) -> Result<(), Error> {
        let lane = self.lane_mut(id.path)?;
        if lane.frozen_data_len.is_none() || lane.ready.sequence != id.sequence {
            return Err(Error::StaleReceipt);
        }
        lane.next = id.sequence + 1;
        lane.frozen_data_len = None;
        lane.ready.clear();
        Ok(())
    }
}

#[cfg(test)]
mod tests;
