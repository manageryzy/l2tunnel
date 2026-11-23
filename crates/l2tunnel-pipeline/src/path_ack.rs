//! Compact ACKs shared across the physical paths of one authenticated direction and epoch.
//! The caller authenticates the enclosing record before using these contents. Physical DATA
//! numbers start at zero per path, survive socket migration, and exclude pure ACK and control
//! records. A received physical packet does not establish logical group custody.

use std::collections::BTreeSet;
use std::ops::Range;

/// Complete pure-ACK tag, also used at the start of the DATA+ACK suffix.
pub const TAG: u8 = 0xa1;
/// Reserved block for the upper layer's stable logical group confirmations.
pub const LOGICAL_GROUP: u8 = 255;
/// Maximum path blocks per feedback body, including the optional logical block.
pub const MAX_BLOCKS: usize = 8;
/// Maximum noncontiguous received intervals in one block.
pub const MAX_RANGES: usize = 8;
/// Maximum observations retained by a physical path, or selective span beyond a logical prefix.
pub const MAX_WINDOW: usize = 8192;

/// A malformed peer body, illegal configuration or transaction failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// Noncanonical, truncated, overflowing or inconsistent wire fields.
    Invalid,
    /// The encoded batch does not fit the caller's buffer.
    ShortBuffer,
    /// Local policy, physical path or sequence is outside its supported domain.
    Configuration,
    /// Fallible storage reservation failed.
    Capacity,
    /// The supplied completion does not name the current prepared send.
    Stale,
    /// This epoch has exhausted its local transaction identifiers.
    Exhausted,
    /// Injected time moved backwards.
    Time,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "path ACK {self:?}")
    }
}
impl std::error::Error for Error {}

fn reserved<T>(n: usize) -> Result<Vec<T>, Error> {
    let mut out = Vec::new();
    out.try_reserve_exact(n).map_err(|_| Error::Capacity)?;
    Ok(out)
}

fn byte(input: &mut &[u8]) -> Result<u8, Error> {
    let (&first, rest) = input.split_first().ok_or(Error::Invalid)?;
    *input = rest;
    Ok(first)
}

pub(super) fn take(input: &mut &[u8]) -> Result<u64, Error> {
    let mut value = 0;
    for index in 0..10 {
        let part = byte(input)?;
        if index == 9 && part > 1 {
            return Err(Error::Invalid);
        }
        value |= u64::from(part & 127) << (index * 7);
        if part < 128 {
            return if index != 0 && part == 0 {
                Err(Error::Invalid)
            } else {
                Ok(value)
            };
        }
    }
    Err(Error::Invalid)
}

pub(super) fn width(n: u64) -> usize {
    ((64 - n.leading_zeros()).max(1) as usize).div_ceil(7)
}

pub(super) fn put(mut n: u64, out: &mut [u8], pos: &mut usize) {
    while n >= 128 {
        out[*pos] = (n as u8 & 127) | 128;
        *pos += 1;
        n >>= 7;
    }
    out[*pos] = n as u8;
    *pos += 1;
}

/// Positive receipts for one physical path, or for the logical owner when path is 255.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AckBlock {
    path: u8,
    floor: u64,
    next: u64,
    ranges: Vec<Range<u64>>,
}

impl AckBlock {
    /// Create one canonical block. Below a physical floor, prior reception is unknown.
    pub fn new(path: u8, floor: u64, next: u64, ranges: Vec<Range<u64>>) -> Result<Self, Error> {
        if ranges.len() > MAX_RANGES || floor > next || (path == LOGICAL_GROUP && floor != 0) {
            return Err(Error::Invalid);
        }
        let mut end = next;
        for range in &ranges {
            if range.start <= end || range.end <= range.start {
                return Err(Error::Invalid);
            }
            end = range.end;
        }
        let origin = if path == LOGICAL_GROUP { next } else { floor };
        if end - origin > MAX_WINDOW as u64 {
            return Err(Error::Invalid);
        }
        Ok(Self {
            path,
            floor,
            next,
            ranges,
        })
    }

    /// Physical path index or the dedicated logical block tag.
    pub fn path(&self) -> u8 {
        self.path
    }
    /// Lower bound of the observed interval, inclusive.
    pub fn floor(&self) -> u64 {
        self.floor
    }
    /// Exclusive upper bound of the consecutive receipt beginning at the floor.
    pub fn next(&self) -> u64 {
        self.next
    }
    /// Additional disjoint positive receipt intervals, in increasing order.
    pub fn ranges(&self) -> &[Range<u64>] {
        &self.ranges
    }
    /// Whether this specific block supplies positive evidence for a sequence.
    pub fn acknowledges(&self, seq: u64) -> bool {
        (self.floor..self.next).contains(&seq) || self.ranges.iter().any(|r| r.contains(&seq))
    }
    fn wire_len(&self) -> usize {
        let mut n = 2 + width(self.floor) + width(self.next);
        let mut end = self.next;
        for r in &self.ranges {
            n += width(r.start - end) + width(r.end - r.start);
            end = r.end;
        }
        n
    }
}

/// Complete canonical body. Either carrier form uses the same bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AckBatch {
    blocks: Vec<AckBlock>,
}

impl AckBatch {
    /// Create a batch in strictly increasing path order.
    pub fn new(blocks: Vec<AckBlock>) -> Result<Self, Error> {
        if blocks.is_empty()
            || blocks.len() > MAX_BLOCKS
            || blocks.windows(2).any(|b| b[0].path >= b[1].path)
        {
            return Err(Error::Invalid);
        }
        Ok(Self { blocks })
    }
    /// Blocks in canonical path order.
    pub fn blocks(&self) -> &[AckBlock] {
        &self.blocks
    }
    /// Exact encoded size, including the A1 tag.
    pub fn wire_len(&self) -> usize {
        2 + self.blocks.iter().map(AckBlock::wire_len).sum::<usize>()
    }
    /// Serialize to caller storage; an undersized output is untouched.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, Error> {
        let n = self.wire_len();
        if out.len() < n {
            return Err(Error::ShortBuffer);
        }
        out[0] = TAG;
        out[1] = self.blocks.len() as u8;
        let mut pos = 2;
        for b in &self.blocks {
            out[pos] = b.path;
            pos += 1;
            put(b.floor, out, &mut pos);
            put(b.next, out, &mut pos);
            out[pos] = b.ranges.len() as u8;
            pos += 1;
            let mut end = b.next;
            for r in &b.ranges {
                put(r.start - end, out, &mut pos);
                put(r.end - r.start, out, &mut pos);
                end = r.end;
            }
        }
        Ok(n)
    }
    /// Parse exactly one complete batch, rejecting alternate representations and trailing bytes.
    pub fn decode(mut input: &[u8]) -> Result<Self, Error> {
        if byte(&mut input)? != TAG {
            return Err(Error::Invalid);
        }
        let count = usize::from(byte(&mut input)?);
        if !(1..=MAX_BLOCKS).contains(&count) {
            return Err(Error::Invalid);
        }
        let mut blocks = reserved(count)?;
        for _ in 0..count {
            let path = byte(&mut input)?;
            let floor = take(&mut input)?;
            let next = take(&mut input)?;
            let nr = usize::from(byte(&mut input)?);
            if nr > MAX_RANGES {
                return Err(Error::Invalid);
            }
            let mut ranges = reserved(nr)?;
            let mut end = next;
            for _ in 0..nr {
                let start = end.checked_add(take(&mut input)?).ok_or(Error::Invalid)?;
                end = start.checked_add(take(&mut input)?).ok_or(Error::Invalid)?;
                ranges.push(start..end);
            }
            blocks.push(AckBlock::new(path, floor, next, ranges)?);
        }
        if !input.is_empty() {
            return Err(Error::Invalid);
        }
        Self::new(blocks)
    }
}

/// Distinguishes a newly observed physical sequence from repeated or retired ones.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Observation {
    /// Received in the retained observation window for the first time.
    New,
    /// Seen already. A new feedback obligation covers possible prior ACK loss.
    Duplicate,
    /// Older than the current floor. Its arrival elicits a window update.
    Retired,
}

/// A DATA packet may carry feedback before the ordinary batching deadline.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Opportunity {
    /// An independently payable outgoing DATA packet has room for an ACK suffix.
    Piggyback,
    /// Send a standalone ACK only after the count or oldest deadline is reached.
    Standalone,
}

#[derive(Clone, Copy)]
enum Publication {
    New,
    Armed(u64),
    Repeated,
}

struct SelectiveRepeat {
    delay: u64,
    slots: Vec<Publication>,
    due: BTreeSet<(u64, u64)>,
}

impl SelectiveRepeat {
    fn new(window: usize, delay: u64) -> Result<Self, Error> {
        if delay == 0 {
            return Err(Error::Configuration);
        }
        let mut slots = reserved(window)?;
        slots.resize(window, Publication::New);
        Ok(Self {
            delay,
            slots,
            due: BTreeSet::new(),
        })
    }
    fn forget(&mut self, seq: u64) {
        let i = (seq % self.slots.len() as u64) as usize;
        if let Publication::Armed(at) = self.slots[i] {
            self.due.remove(&(at, seq));
        }
        self.slots[i] = Publication::New;
    }
    fn deadline(&self) -> Option<u64> {
        self.due.first().map(|&(at, _)| at)
    }
    fn ready(&self, i: usize, now: u64) -> bool {
        matches!(self.slots[i],Publication::Armed(at) if at<=now)
    }
    fn would_overflow(&self, block: &AckBlock, floor: u64, paid: u64) -> bool {
        paid.checked_add(self.delay).is_none()
            && block.ranges().iter().any(|r| {
                (r.start.max(floor)..r.end).any(|s| {
                    matches!(
                        self.slots[(s % self.slots.len() as u64) as usize],
                        Publication::New
                    )
                })
            })
    }
    fn confirm(&mut self, block: &AckBlock, current_floor: u64, paid: u64) {
        // An old immutable receipt can pay after its slots were recycled.
        for span in
            std::iter::once(block.floor()..block.next()).chain(block.ranges().iter().cloned())
        {
            let selective = span.start > block.next();
            if !selective && self.deadline().is_none_or(|due| due > paid) {
                continue;
            }
            for seq in span.start.max(current_floor)..span.end {
                let i = (seq % self.slots.len() as u64) as usize;
                match self.slots[i] {
                    Publication::New if selective => {
                        let due = paid.saturating_add(self.delay);
                        self.slots[i] = Publication::Armed(due);
                        self.due.insert((due, seq));
                    }
                    Publication::Armed(at) if at <= paid => {
                        self.due.remove(&(at, seq));
                        self.slots[i] = Publication::Repeated;
                    }
                    _ => (),
                }
            }
        }
    }
}

struct Path {
    id: u8,
    floor: u64,
    next: u64,
    high: u64,
    range_cursor: u64,
    // Circular slots: absent, observed/clean, or observed/needing selective publication.
    slots: Vec<u8>,
    count: usize,
    oldest: Option<u64>,
    backlog: bool,
    repeat: Option<SelectiveRepeat>,
}

impl Path {
    fn slot(&self, seq: u64) -> usize {
        (seq % self.slots.len() as u64) as usize
    }
    fn observe(&mut self, seq: u64, end: u64, now: u64, threshold: usize) -> Observation {
        self.oldest.get_or_insert(now);
        self.count = self.count.saturating_add(1).min(threshold);
        if seq < self.floor {
            return Observation::Retired;
        }
        let floor = end.saturating_sub(self.slots.len() as u64);
        if floor > self.floor {
            if floor - self.floor >= self.slots.len() as u64 {
                self.slots.fill(0);
                if let Some(r) = &mut self.repeat {
                    r.slots.fill(Publication::New);
                    r.due.clear();
                }
            } else {
                for retired in self.floor..floor {
                    let i = self.slot(retired);
                    self.slots[i] = 0;
                    if let Some(r) = &mut self.repeat {
                        r.forget(retired);
                    }
                }
            }
            self.floor = floor;
            self.next = self.next.max(floor);
        }
        let i = self.slot(seq);
        let seen = self.slots[i] != 0;
        self.slots[i] = if seq < self.next { 1 } else { 2 };
        self.high = self.high.max(end);
        while self.next < self.high {
            let i = self.slot(self.next);
            if self.slots[i] == 0 {
                break;
            }
            self.slots[i] = 1;
            self.next += 1;
        }
        if seen {
            Observation::Duplicate
        } else {
            Observation::New
        }
    }

    fn snapshot(&self, now: u64) -> Result<(AckBlock, Option<u64>), Error> {
        let mut ranges = reserved(MAX_RANGES)?;
        let mut resume = None;
        let mut last_selected = self.next;
        let pivot = self.range_cursor.max(self.next);
        // Walk whole runs on each side of the cursor. New neighboring data may have
        // merged two runs since the previous scan, so never split at the pivot.
        'pages: for wrapped in [false, true] {
            if wrapped && pivot == self.next {
                break;
            }
            let mut i = self.next;
            while i < self.high {
                if self.slots[self.slot(i)] == 0 {
                    i += 1;
                    continue;
                }
                let start = i;
                let mut dirty = false;
                while i < self.high && self.slots[self.slot(i)] != 0 {
                    let slot = self.slot(i);
                    dirty |= self.slots[slot] == 2
                        || self.repeat.as_ref().is_some_and(|r| r.ready(slot, now));
                    i += 1;
                }
                if dirty && (i <= pivot) == wrapped {
                    if ranges.len() == MAX_RANGES {
                        resume = Some(last_selected);
                        break 'pages;
                    }
                    ranges.push(start..i);
                    last_selected = i;
                }
            }
        }
        ranges.sort_unstable_by_key(|r| r.start);
        Ok((
            AckBlock::new(self.id, self.floor, self.next, ranges)?,
            resume,
        ))
    }

    fn reserve_snapshot(&mut self, block: &AckBlock, resume: Option<u64>) {
        for r in block.ranges() {
            for seq in r.clone() {
                let i = self.slot(seq);
                self.slots[i] = 1;
            }
        }
        self.range_cursor = resume.unwrap_or(self.next);
        self.backlog = resume.is_some();
        self.count = usize::from(self.backlog);
        if !self.backlog {
            self.oldest = None;
        }
    }
}

/// One immutable owned transmission attempt, movable to another authenticated return path.
#[derive(Debug)]
pub struct PreparedAck {
    token: u64,
    batch: AckBatch,
    prepared_at: u64,
    oldest: u64,
    count: usize,
    forced: bool,
}

impl PreparedAck {
    /// Owner-local send token; one successful send confirms it exactly once.
    pub fn token(&self) -> u64 {
        self.token
    }
    /// Immutable canonical payload until its first successful carrier handoff.
    pub fn batch(&self) -> &AckBatch {
        &self.batch
    }
}

/// Bounded physical DATA observations for one authenticated session, direction and epoch.
/// Pure feedback/control records never call `observe_data`. Paths can move between
/// sockets without changing their IDs. Reusing an ID for a new sequence space requires
/// a fresh epoch. There are no clock, network, authentication or logical custody owners here.
pub struct AckReceiver {
    paths: Vec<Path>,
    threshold: usize,
    delay: u64,
    now: u64,
    cursor: usize,
    next_token: Option<u64>,
    pending: Option<PreparedAck>,
}

impl AckReceiver {
    /// Register sorted, unique physical path IDs; `window` is retained per path.
    /// All timestamps and `max_delay` use the caller's same monotonic units.
    pub fn new(ids: &[u8], window: usize, count: usize, max_delay: u64) -> Result<Self, Error> {
        Self::configured(ids, window, count, max_delay, None)
    }

    /// Reannounce a paid selective receipt once after `repeat_delay` while its observation
    /// is retained. A naturally paid covering ACK can discharge the repeat. Pure ACKs do
    /// not generate receipts for each other. Uses the same caller clock as `max_delay`.
    pub fn with_selective_repeat(
        ids: &[u8],
        window: usize,
        count: usize,
        max_delay: u64,
        repeat_delay: u64,
    ) -> Result<Self, Error> {
        Self::configured(ids, window, count, max_delay, Some(repeat_delay))
    }

    fn configured(
        ids: &[u8],
        window: usize,
        count: usize,
        max_delay: u64,
        repeat: Option<u64>,
    ) -> Result<Self, Error> {
        if ids.is_empty()
            || ids.len() > usize::from(LOGICAL_GROUP)
            || ids.last() == Some(&LOGICAL_GROUP)
            || ids.windows(2).any(|p| p[0] >= p[1])
            || !(1..=MAX_WINDOW).contains(&window)
            || !(1..=usize::from(u16::MAX)).contains(&count)
            || max_delay == 0
        {
            return Err(Error::Configuration);
        }
        let mut paths = reserved(ids.len())?;
        for &id in ids {
            let mut slots = reserved(window)?;
            slots.resize(window, 0);
            paths.push(Path {
                id,
                slots,
                floor: 0,
                next: 0,
                high: 0,
                range_cursor: 0,
                oldest: None,
                count: 0,
                backlog: false,
                repeat: repeat
                    .map(|delay| SelectiveRepeat::new(window, delay))
                    .transpose()?,
            });
        }
        Ok(Self {
            paths,
            threshold: count,
            delay: max_delay,
            now: 0,
            cursor: 0,
            next_token: Some(1),
            pending: None,
        })
    }

    /// Record authenticated positive arrival of a DATA or DATA+ACK physical datagram.
    /// A duplicate must reach this obligation even when application delivery is suppressed.
    pub fn observe_data(&mut self, path: u8, seq: u64, now: u64) -> Result<Observation, Error> {
        if now < self.now {
            return Err(Error::Time);
        }
        now.checked_add(self.delay).ok_or(Error::Exhausted)?;
        let end = seq.checked_add(1).ok_or(Error::Configuration)?;
        let i = self
            .paths
            .binary_search_by_key(&path, |p| p.id)
            .map_err(|_| Error::Configuration)?;
        self.now = now;
        Ok(self.paths[i].observe(seq, end, now, self.threshold))
    }

    /// Earliest standalone send deadline. Immediate output is reported at the current clock.
    pub fn next_deadline(&self) -> Option<u64> {
        let mut count = self.pending.as_ref().map_or(0, |p| p.count);
        let mut oldest = self.pending.as_ref().map(|p| p.oldest);
        let mut forced = self.pending.as_ref().is_some_and(|p| p.forced);
        for p in &self.paths {
            count = count.saturating_add(p.count);
            if let Some(t) = p.oldest {
                oldest = Some(oldest.map_or(t, |x| x.min(t)));
            }
            forced |= p.backlog;
        }
        let ordinary = if forced || count >= self.threshold {
            Some(self.now)
        } else {
            oldest.map(|t| t + self.delay)
        };
        ordinary
            .into_iter()
            .chain(
                self.paths
                    .iter()
                    .filter_map(|p| p.repeat.as_ref()?.deadline()),
            )
            .min()
    }

    /// Whether an outgoing DATA packet can carry useful feedback at this instant.
    /// A future repeat alone never emits a premature empty page.
    pub fn can_piggyback(&self, now: u64) -> bool {
        self.pending.is_some()
            || self.paths.iter().any(|p| {
                p.count != 0
                    || p.repeat
                        .as_ref()
                        .and_then(SelectiveRepeat::deadline)
                        .is_some_and(|t| t <= now)
            })
    }

    /// Prepare or return the current immutable payload. Preparation and a blocked send do
    /// not confirm an ACK. If a suffix is too large, keep it for a later eligible send.
    pub fn prepare(
        &mut self,
        now: u64,
        opportunity: Opportunity,
    ) -> Result<Option<&PreparedAck>, Error> {
        if now < self.now {
            return Err(Error::Time);
        }
        self.now = now;
        let Some(due) = self.next_deadline() else {
            return Ok(None);
        };
        if (opportunity == Opportunity::Standalone && now < due) || !self.can_piggyback(now) {
            return Ok(None);
        }
        if self.pending.is_none() {
            let token = self.next_token.ok_or(Error::Exhausted)?;
            let mut selected = reserved(MAX_BLOCKS)?;
            let mut blocks = reserved(MAX_BLOCKS)?;
            let mut cursor = self.cursor;
            for _ in 0..self.paths.len() {
                let i = cursor;
                cursor = (i + 1) % self.paths.len();
                if self.paths[i].count != 0
                    || self.paths[i]
                        .repeat
                        .as_ref()
                        .and_then(SelectiveRepeat::deadline)
                        .is_some_and(|t| t <= now)
                {
                    let (block, backlog) = self.paths[i].snapshot(now)?;
                    selected.push((i, backlog));
                    blocks.push(block);
                    if blocks.len() == MAX_BLOCKS {
                        break;
                    }
                }
            }
            blocks.sort_unstable_by_key(AckBlock::path);
            let batch = AckBatch::new(blocks)?;
            let mut oldest = now;
            let mut count = 0usize;
            let mut forced = false;
            for (i, backlog) in selected {
                let p = &mut self.paths[i];
                oldest = oldest.min(p.oldest.unwrap_or(now));
                count = count.saturating_add(p.count);
                forced |= p.backlog;
                // The chosen public paths came from our sorted registry.
                let pos = batch.blocks.partition_point(|b| b.path < p.id);
                p.reserve_snapshot(&batch.blocks[pos], backlog);
            }
            self.pending = Some(PreparedAck {
                token,
                batch,
                prepared_at: now,
                oldest,
                count,
                forced,
            });
            self.cursor = cursor;
            self.next_token = token.checked_add(1);
        }
        Ok(self.pending.as_ref())
    }

    /// Confirm the immutable token at actual successful complete carrier handoff. `now`
    /// may be later than `paid_at` if more DATA arrived before completion was observed.
    pub fn confirm_paid(&mut self, token: u64, paid_at: u64, now: u64) -> Result<(), Error> {
        let pending = self
            .pending
            .as_ref()
            .filter(|p| p.token == token)
            .ok_or(Error::Stale)?;
        if now < self.now || paid_at > now || paid_at < pending.prepared_at {
            return Err(Error::Time);
        }
        for block in pending.batch.blocks() {
            let path = &self.paths[self.paths.partition_point(|p| p.id < block.path)];
            if path
                .repeat
                .as_ref()
                .is_some_and(|r| r.would_overflow(block, path.floor, paid_at))
            {
                return Err(Error::Exhausted);
            }
        }
        for block in pending.batch.blocks() {
            let index = self.paths.partition_point(|p| p.id < block.path);
            let path = &mut self.paths[index];
            if let Some(repeat) = &mut path.repeat {
                repeat.confirm(block, path.floor, paid_at);
            }
        }
        self.now = now;
        self.pending = None;
        Ok(())
    }
}

#[cfg(test)]
mod tests;
