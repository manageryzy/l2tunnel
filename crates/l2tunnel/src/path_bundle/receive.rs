use std::collections::{BTreeMap, BTreeSet};

use l2tunnel_fec::path_shards::{Profile, RecordReceiver};
use l2tunnel_fec::{FecContext, GenerationId};
use l2tunnel_pipeline::path_ack::AckBlock;
use l2tunnel_pipeline::path_batch::Shard;

/// Logical receive failures. A caller retains the native output until it is committed.
#[derive(Debug)]
pub enum ReceiveError {
    /// Invalid local limits or coding dimensions.
    Configuration,
    /// The group is beyond the bounded live receive window.
    Window,
    /// Native data for this group has not been reconstructed.
    Incomplete,
    /// Authentication was performed under a different coding domain.
    Context,
    /// Invalid member or local FEC capacity.
    Codec(l2tunnel_fec::Error),
    /// Invalid confirmation snapshot.
    Ack(l2tunnel_pipeline::path_ack::Error),
}
impl std::fmt::Display for ReceiveError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "multipath receive: {self:?}")
    }
}
impl std::error::Error for ReceiveError {}
impl From<l2tunnel_fec::Error> for ReceiveError {
    fn from(e: l2tunnel_fec::Error) -> Self {
        Self::Codec(e)
    }
}

enum Slot {
    Collecting {
        coder: RecordReceiver,
        members: [u64; 4],
        count: u8,
        length: u16,
    },
    Ready(Vec<u8>),
}

/// A single logical receive direction. Physical receipt and native delivery use separate state.
pub struct Receiver {
    domain: FecContext,
    profile: Profile,
    n: u8,
    k: u8,
    capacity: u64,
    next: u64,
    horizon: u64,
    slots: BTreeMap<u64, Slot>,
    delivered: BTreeSet<u64>,
}

impl Receiver {
    /// Allocate groups lazily, up to the negotiated record, path and group limits.
    pub fn new(
        domain: FecContext,
        n: u8,
        k: u8,
        max_native: u16,
        max_shard: u16,
        window: usize,
    ) -> Result<Self, ReceiveError> {
        if !(1..=8192).contains(&window) {
            return Err(ReceiveError::Configuration);
        }
        Ok(Self {
            domain,
            profile: Profile::new(n, k, max_native, max_shard)?,
            n,
            k,
            capacity: window as u64,
            next: 0,
            horizon: 0,
            slots: BTreeMap::new(),
            delivered: BTreeSet::new(),
        })
    }

    /// Admit a verified member using its immutable coding ordinal, including retries on other paths.
    /// True signals a newly ready native record. A duplicate cannot enqueue it twice.
    pub fn accept(&mut self, domain: FecContext, shard: Shard<'_>) -> Result<bool, ReceiveError> {
        if domain != self.domain {
            return Err(ReceiveError::Context);
        }
        let id = shard.generation;
        if id == u64::MAX || shard.ordinal >= self.n {
            return Err(ReceiveError::Configuration);
        }
        if id < self.next || self.delivered.contains(&id) {
            return Ok(false);
        }
        if id - self.next >= self.capacity {
            return Err(ReceiveError::Window);
        }
        let length = RecordReceiver::original_length(shard.bytes)?;
        let group = GenerationId(id);
        use std::collections::btree_map::Entry;
        let slot = match self.slots.entry(id) {
            Entry::Vacant(v) => {
                let mut coder = RecordReceiver::new(self.profile, domain, group, length)?;
                coder.accept_authenticated(domain, group, shard.ordinal, shard.bytes)?;
                v.insert(Slot::Collecting {
                    coder,
                    members: [0; 4],
                    count: 0,
                    length,
                })
            }
            Entry::Occupied(o) => {
                let value = o.into_mut();
                match value {
                    Slot::Ready(_) => return Ok(false),
                    Slot::Collecting { coder, .. } => {
                        coder.accept_authenticated(domain, group, shard.ordinal, shard.bytes)?;
                    }
                }
                value
            }
        };
        self.horizon = self.horizon.max(id + 1);
        let Slot::Collecting {
            coder,
            members,
            count,
            length,
        } = slot
        else {
            return Ok(false);
        };
        let word = &mut members[usize::from(shard.ordinal / 64)];
        let bit = 1 << (shard.ordinal % 64);
        if *word & bit != 0 {
            return Ok(false);
        }
        *word |= bit;
        *count += 1;
        if *count < self.k {
            return Ok(false);
        }
        let mut bytes = vec![0; usize::from(*length)];
        if let Err(error) = coder.recover_into(&mut bytes) {
            // No partial native result or unrepairable rank is retained.
            self.slots.remove(&id);
            return Err(error.into());
        }
        *slot = Slot::Ready(bytes);
        Ok(true)
    }

    /// Borrow exactly one complete native datagram, even when an earlier group is missing.
    pub fn ready(&self, group: u64) -> Option<&[u8]> {
        match self.slots.get(&group) {
            Some(Slot::Ready(bytes)) => Some(bytes),
            _ => None,
        }
    }

    /// Commit after the complete native handoff. Return false for an already delivered group.
    pub fn commit(&mut self, group: u64) -> Result<bool, ReceiveError> {
        if group < self.next || self.delivered.contains(&group) {
            return Ok(false);
        }
        if self.ready(group).is_none() {
            return Err(ReceiveError::Incomplete);
        }
        self.slots.remove(&group);
        self.delivered.insert(group);
        while self.delivered.remove(&self.next) {
            self.next += 1;
        }
        Ok(true)
    }

    /// Exclusive cumulative native confirmation. Physical observations never move this value.
    pub fn confirmed_prefix(&self) -> u64 {
        self.next
    }

    /// Exclusive upper end evidenced by physically accepted group members.
    pub fn observed_end(&self) -> u64 {
        self.horizon
    }

    /// Number of live group positions, including delivered selective receipts above a gap.
    pub fn retained_groups(&self) -> usize {
        self.slots.len() + self.delivered.len()
    }

    /// Snapshot up to eight selective runs. Use the returned cursor for a subsequent page.
    pub fn confirmation(&self, cursor: u64) -> Result<(AckBlock, Option<u64>), ReceiveError> {
        let mut spans: Vec<std::ops::Range<u64>> = Vec::with_capacity(8);
        let mut continuation = None;
        for &id in self.delivered.range(cursor.max(self.next)..) {
            if let Some(last) = spans.last_mut()
                && last.end == id
            {
                last.end = id + 1;
            } else if spans.len() == 8 {
                continuation = Some(id);
                break;
            } else {
                spans.push(id..id + 1);
            }
        }
        let block = AckBlock::new(255, 0, self.next, spans).map_err(ReceiveError::Ack)?;
        Ok((block, continuation))
    }

    /// Select K-rank distinct missing ordinals for an observed gap. A sender-owned quiet timer
    /// covers a completely erased tail beyond this receiver's observation horizon.
    pub fn missing(&self, group: u64) -> Vec<u8> {
        self.missing_from(group, 0)
    }

    /// Select missing ordinals starting at the caller's rotating retry cursor.
    pub fn missing_from(&self, group: u64, start: u8) -> Vec<u8> {
        if group < self.next || group >= self.horizon || self.delivered.contains(&group) {
            return vec![];
        }
        let ordinals = (0..u16::from(self.n))
            .map(|offset| ((u16::from(start) + offset) % u16::from(self.n)) as u8);
        match self.slots.get(&group) {
            Some(Slot::Ready(_)) => vec![],
            Some(Slot::Collecting { members, count, .. }) => ordinals
                .filter(|i| members[usize::from(i / 64)] & (1 << (i % 64)) == 0)
                .take(usize::from(self.k - *count))
                .collect(),
            None => ordinals.take(usize::from(self.k)).collect(),
        }
    }
}
