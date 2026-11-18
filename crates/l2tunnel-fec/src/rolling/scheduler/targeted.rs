//! Bounded gap requests and retained-original retry scheduling for C48.

use super::*;

pub(super) const GAP: u64 = 2_000;
const REPEAT: u64 = 80_000;
pub(super) const PROBE: u64 = 140_000;
const MAX_IDS: usize = 8;
const NONE: u32 = u32::MAX;
const PARKED: usize = 3;

/// Local sender counts for authenticated, explicitly named source IDs.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RequestCounts {
    /// First request for a source still in sender custody.
    pub first: u64,
    /// A newer request serial for the same retained source.
    pub repeated: u64,
    /// Repeated IDs coalesced while the original retry remained in the FIFO.
    pub coalesced_queued: u64,
    /// Repeated IDs coalesced while a prepared retry awaited physical ownership.
    pub coalesced_prepared: u64,
    /// IDs seen again at or below their last accepted request serial.
    pub duplicate_or_older: u64,
    /// IDs already retired by authenticated cumulative confirmation.
    pub confirmed: u64,
}

/// One authenticated request. The receipt prefix is independent of the named span.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GapRequest {
    /// Authenticated forward coding stream whose originals are requested.
    pub scope: Scope,
    /// Immutable feedback output identity.
    pub id: FeedbackId,
    /// Cumulative receiver receipt, excluding all unconfirmed older sources.
    pub prefix: u32,
    /// First named missing source.
    pub start: u32,
    /// Bit i requests the source at start + i. At most eight bits are set.
    pub mask: u32,
}
impl GapRequest {
    pub(crate) fn validate(self, config: Config) -> Result<(), Error> {
        if self.id.0 == 0
            || self.id.0 == u64::MAX
            || self.mask & 1 == 0
            || self.mask.count_ones() > MAX_IDS as u32
            || self.start < self.prefix
        {
            return Err(Error::Identity);
        }
        let last = self
            .start
            .checked_add(31 - self.mask.leading_zeros())
            .ok_or(Error::Identity)?;
        if last == u32::MAX || (last - self.prefix) as usize >= config.window {
            return Err(Error::Identity);
        }
        Ok(())
    }
    pub(super) fn full_byte(self, index: usize) -> u8 {
        let shell = Feedback {
            scope: self.scope,
            id: self.id,
            prefix: self.prefix,
            observed_end: self.start,
            deficit: self.mask,
        };
        if index == 5 { 5 } else { shell.byte(index) }
    }
    pub(super) fn decode_full(config: Config, bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != FEEDBACK_BYTES
            || &bytes[..4] != b"L2RF"
            || bytes[4..8] != [1, 5, 0, 0]
            || bytes[37..40] != [0; 3]
            || bytes[60..64] != [0; 4]
        {
            return Err(Error::Format);
        }
        let scope = Scope {
            session: bytes[8..24].try_into().map_err(|_| Error::Length)?,
            epoch: u64::from_be_bytes(bytes[24..32].try_into().map_err(|_| Error::Length)?),
            stream: u32::from_be_bytes(bytes[32..36].try_into().map_err(|_| Error::Length)?),
            direction: bytes[36],
        };
        let word = |p: usize| -> Result<u32, Error> {
            Ok(u32::from_be_bytes(
                bytes[p..p + 4].try_into().map_err(|_| Error::Length)?,
            ))
        };
        let request = Self {
            scope,
            id: FeedbackId(u64::from_be_bytes(
                bytes[40..48].try_into().map_err(|_| Error::Length)?,
            )),
            prefix: word(48)?,
            start: word(52)?,
            mask: word(56)?,
        };
        request.validate(config)?;
        Ok(request)
    }
}

// Each modulo-window slot belongs to at most one FIFO. A newer generation may
// remove its obsolete predecessor in O(1), including from the middle of a FIFO.
#[derive(Clone, Copy)]
struct Entry {
    id: u32,
    before: u32,
    after: u32,
    list: usize,
    stamp: u64,
    full_credit: bool,
}
const EMPTY: Entry = Entry {
    id: NONE,
    before: NONE,
    after: NONE,
    list: 2,
    stamp: 0,
    full_credit: false,
};
pub(in crate::rolling) struct Queues {
    entries: Vec<Entry>,
    head: [u32; 2],
    tail: [u32; 2],
}
impl Queues {
    fn count(policy: Policy) -> usize {
        if policy.source_wire.is_targeted() {
            policy.recovery.window
        } else {
            0
        }
    }
    pub(in crate::rolling) fn plan(policy: Policy) -> Result<storage::Usage, storage::Error> {
        storage::requested::<Entry>(Self::count(policy))
    }
    pub(super) fn bytes(policy: Policy) -> Result<usize, Error> {
        mul(Self::count(policy), std::mem::size_of::<Entry>())
    }
    pub(super) fn new(policy: Policy) -> Result<Self, Error> {
        Ok(Self {
            entries: slots(Self::count(policy), EMPTY)?,
            head: [NONE; 2],
            tail: [NONE; 2],
        })
    }
    pub(super) fn usage(&self) -> Result<storage::Usage, storage::Error> {
        storage::Usage::vector(&self.entries)
    }
    fn slot(&self, id: u32) -> usize {
        id as usize % self.entries.len()
    }
    fn remove(&mut self, slot: usize) {
        let e = self.entries[slot];
        if e.list >= 2 {
            return;
        }
        if e.before == NONE {
            self.head[e.list] = e.after;
        } else {
            self.entries[e.before as usize].after = e.after;
        }
        if e.after == NONE {
            self.tail[e.list] = e.before;
        } else {
            self.entries[e.after as usize].before = e.before;
        }
        self.entries[slot].list = 2;
    }
    fn push(&mut self, id: u32, list: usize, stamp: u64) {
        let slot = self.slot(id);
        self.remove(slot);
        let before = self.tail[list];
        self.entries[slot] = Entry {
            id,
            before,
            after: NONE,
            list,
            stamp,
            full_credit: false,
        };
        if before == NONE {
            self.head[list] = slot as u32;
        } else {
            self.entries[before as usize].after = slot as u32;
        }
        self.tail[list] = slot as u32;
    }
    fn first(&self, list: usize) -> Option<Entry> {
        self.entries.get(self.head[list] as usize).copied()
    }
    pub(super) fn has_retries(&self) -> bool {
        self.head[0] != NONE
    }
    pub(super) fn enqueue_retry(
        &mut self,
        id: u32,
        serial: u64,
        full_credit: bool,
        prepared: bool,
        counts: &mut RequestCounts,
    ) -> bool {
        let slot = self.slot(id);
        let entry = &mut self.entries[slot];
        if entry.id == id {
            if entry.stamp >= serial {
                counts.duplicate_or_older = counts.duplicate_or_older.saturating_add(1);
                return false;
            }
            counts.repeated = counts.repeated.saturating_add(1);
            entry.stamp = serial;
            if entry.list == 0 {
                counts.coalesced_queued = counts.coalesced_queued.saturating_add(1);
                return false;
            }
            if prepared {
                counts.coalesced_prepared = counts.coalesced_prepared.saturating_add(1);
                return false;
            }
        } else {
            counts.first = counts.first.saturating_add(1);
        }
        self.push(id, 0, serial);
        self.entries[slot].full_credit = full_credit;
        true
    }
    pub(super) fn next_retry(
        &mut self,
        prefix: u32,
        budget: &mut WorkBudget,
    ) -> Option<(SourceId, bool)> {
        // Sender::step paid the first metadata visit before choosing this
        // queue. Only further stale entries need additional charged visits.
        let mut first = true;
        while let Some(e) = self.first(0) {
            if !first && !spend(&mut budget.metadata) {
                return None;
            }
            first = false;
            let slot = self.slot(e.id);
            self.remove(slot);
            if e.id >= prefix {
                return Some((SourceId(e.id), e.full_credit));
            }
        }
        None
    }
}

#[derive(Clone, Copy, Default)]
struct Selected {
    id: u32,
    list: usize,
    due: u64,
}
#[derive(Clone, Copy, Default)]
struct Custody {
    id: u32,
    copies: u32,
}
pub(in crate::rolling) struct GapTracker {
    queues: Queues,
    custody: Vec<Custody>,
    seen: u32,
    prefer_old: bool,
    next_batch: Tick,
    prefix: u32,
    ids: [Selected; MAX_IDS],
    count: usize,
}
impl GapTracker {
    pub(in crate::rolling) fn plan(policy: Policy) -> Result<storage::Usage, storage::Error> {
        Queues::plan(policy)?.join(storage::requested::<Custody>(Queues::count(policy))?)
    }
    pub(super) fn bytes(policy: Policy) -> Result<usize, Error> {
        add(
            Queues::bytes(policy)?,
            mul(Queues::count(policy), std::mem::size_of::<Custody>())?,
        )
    }
    pub(super) fn usage(&self) -> Result<storage::Usage, storage::Error> {
        self.queues
            .usage()?
            .join(storage::Usage::vector(&self.custody)?)
    }
    pub(super) fn new(policy: Policy) -> Result<Self, Error> {
        Ok(Self {
            queues: Queues::new(policy)?,
            custody: slots(Queues::count(policy), Custody::default())?,
            seen: 0,
            prefer_old: false,
            next_batch: Tick(0),
            prefix: 0,
            ids: [Selected::default(); MAX_IDS],
            count: 0,
        })
    }
    fn park_due(&mut self, candidate: Selected) {
        let slot = self.queues.slot(candidate.id);
        self.queues.remove(slot);
        // 0/1 are active lists, 2 is detached. Parked entries retain their
        // original list and already-matured eligibility stamp.
        self.queues.entries[slot].list = PARKED + candidate.list;
        self.queues.entries[slot].stamp = candidate.due;
    }
    pub(super) fn hold(&mut self, id: u32) -> Result<(), Error> {
        let slot = self.queues.slot(id);
        let held = &mut self.custody[slot];
        if held.id != id {
            *held = Custody { id, copies: 0 };
        }
        held.copies = held.copies.checked_add(1).ok_or(Error::Capacity)?;
        if let Some(i) = self.ids[..self.count].iter().position(|v| v.id == id) {
            self.park_due(self.ids[i]);
            self.ids.copy_within(i + 1..self.count, i);
            self.count -= 1;
        }
        Ok(())
    }
    pub(super) fn release(&mut self, id: u32) {
        let slot = self.queues.slot(id);
        let held = &mut self.custody[slot];
        if held.id != id || held.copies == 0 {
            return;
        }
        held.copies -= 1;
        let entry = self.queues.entries[slot];
        if held.copies != 0 || entry.id != id || entry.list < PARKED {
            return;
        }
        // Only due entries were parked. Put the mature item ahead of any
        // later timer while preserving its stamp and the shared batch cap.
        let list = entry.list - PARKED;
        let after = self.queues.head[list];
        let item = &mut self.queues.entries[slot];
        item.list = list;
        item.before = NONE;
        item.after = after;
        if after == NONE {
            self.queues.tail[list] = slot as u32;
        } else {
            self.queues.entries[after as usize].before = slot as u32;
        }
        self.queues.head[list] = slot as u32;
    }
    pub(super) fn wake(&self, decoder: &Decoder, now: Tick) -> Option<Tick> {
        if self.queues.entries.is_empty() {
            return None;
        }
        let state = decoder.status();
        if self.count > 0 || self.seen < state.observed_end {
            return Some(now);
        }
        if state.decoded_prefix == state.observed_end {
            return None;
        }
        (0..2)
            .filter_map(|i| self.queues.first(i))
            .map(|e| Tick(e.stamp).max(self.next_batch))
            .min()
    }
    pub(super) fn observe(
        &mut self,
        decoder: &Decoder,
        now: Tick,
        budget: &mut WorkBudget,
    ) -> Result<(), Error> {
        if self.queues.entries.is_empty() {
            return Ok(());
        }
        let status = decoder.status();
        self.seen = self.seen.max(status.decoded_prefix);
        while self.seen < status.observed_end && spend(&mut budget.metadata) {
            let index = self.seen;
            if decoder.decoded_source(SourceId(index))?.is_none() {
                self.queues.push(index, 0, deadline(now, GAP)?.0);
            }
            self.seen += 1;
        }
        Ok(())
    }
    pub(super) fn poll(
        &mut self,
        decoder: &Decoder,
        scope: Scope,
        id: FeedbackId,
        now: Tick,
        budget: &mut WorkBudget,
    ) -> Result<Option<GapRequest>, Error> {
        if self.queues.entries.is_empty() {
            return Ok(None);
        }
        let status = decoder.status();
        if self.count == 0 && now >= self.next_batch {
            let again = deadline(now, REPEAT)?;
            while self.count < MAX_IDS {
                let first = usize::from(self.prefer_old);
                let Some(list) = [first, 1 - first]
                    .into_iter()
                    .find(|&q| self.queues.first(q).is_some_and(|e| e.stamp <= now.0))
                else {
                    break;
                };
                if !spend(&mut budget.metadata) {
                    break;
                }
                let entry = self.queues.first(list).ok_or(Error::Identity)?;
                let slot = self.queues.slot(entry.id);
                self.queues.remove(slot);
                if entry.id < status.decoded_prefix
                    || decoder.decoded_source(SourceId(entry.id))?.is_some()
                {
                    continue;
                }
                let candidate = Selected {
                    id: entry.id,
                    list,
                    due: entry.stamp,
                };
                let held = self.custody[slot];
                if held.id == entry.id && held.copies != 0 {
                    self.park_due(candidate);
                    continue;
                }
                self.ids[self.count] = candidate;
                self.count += 1;
                self.prefer_old = list == 0;
                self.queues.push(entry.id, 1, again.0);
            }
            if self.count > 0 {
                self.ids[..self.count].sort_unstable_by_key(|v| v.id);
                self.prefix = status.decoded_prefix;
                self.next_batch = deadline(now, GAP)?;
            }
        }
        if self.count == 0 {
            return Ok(None);
        }
        let start = self.ids[0].id;
        let n = self.ids[..self.count].partition_point(|v| v.id - start < 32);
        let mask = self.ids[..n]
            .iter()
            .fold(0, |m, v| m | (1 << (v.id - start)));
        self.ids.copy_within(n..self.count, 0);
        self.count -= n;
        Ok(Some(GapRequest {
            scope,
            id,
            prefix: self.prefix,
            start,
            mask,
        }))
    }
}
