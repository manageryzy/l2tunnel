//! Source reception, online repair decoding, ordered unpacking and feedback.
use super::{
    Config, Error, FEEDBACK_HEADER, FRAME_PREFIX, KIND_FEEDBACK, KIND_REPAIR, KIND_SOURCE,
    MAX_REQUESTS, REORDER_SOURCES, REPAIR_HEADER, ReceiverStats, SOURCE_HEADER, expand, gf,
    read_u32,
};
use std::collections::VecDeque;

/// One pending equation: `sum(coefficient * vector(sequence)) = data`, where a
/// source vector is its 16-bit length followed by its bytes, zero extended.
struct Row {
    /// Unknown sources only, ascending by sequence. The first is the pivot and
    /// has coefficient one; no other row mentions any row's pivot.
    terms: Vec<(u64, u8)>,
    data: Vec<u8>,
}

fn add_scaled(target: &mut Vec<u8>, source: &[u8], factor: u8) {
    if target.len() < source.len() {
        target.resize(source.len(), 0);
    }
    gf::mul_add(target, source, factor);
}

/// `target += factor * other` over sparse ascending term lists.
fn add_terms(
    target: &mut Vec<(u64, u8)>,
    other: &[(u64, u8)],
    factor: u8,
    scratch: &mut Vec<(u64, u8)>,
) {
    scratch.clear();
    let (mut a, mut b) = (0, 0);
    while a < target.len() || b < other.len() {
        let left = target.get(a).copied();
        let right = other.get(b).copied();
        match (left, right) {
            (Some((x, c)), Some((y, _))) if x < y => {
                scratch.push((x, c));
                a += 1;
            }
            (Some((x, _)), Some((y, d))) if y < x => {
                scratch.push((y, gf::mul(d, factor)));
                b += 1;
            }
            (Some((x, c)), Some((_, d))) => {
                let value = c ^ gf::mul(d, factor);
                if value != 0 {
                    scratch.push((x, value));
                }
                a += 1;
                b += 1;
            }
            (Some(term), None) => {
                scratch.push(term);
                a += 1;
            }
            (None, Some((y, d))) => {
                scratch.push((y, gf::mul(d, factor)));
                b += 1;
            }
            (None, None) => break,
        }
    }
    std::mem::swap(target, scratch);
}

fn coefficient_of(terms: &[(u64, u8)], sequence: u64) -> Option<(usize, u8)> {
    terms
        .binary_search_by_key(&sequence, |term| term.0)
        .ok()
        .map(|index| (index, terms[index].1))
}

const FEEDBACK_REPEATS: u8 = 2;

/// One direction's receiving engine.
pub struct Receiver {
    config: Config,
    /// Next source to unpack; everything below was delivered in order.
    base: u64,
    /// One past the highest source known to exist.
    end: u64,
    /// Sequence of `slots[0]`; history below `base` is kept for repairs.
    floor: u64,
    slots: VecDeque<Option<Vec<u8>>>,
    rows: Vec<Row>,
    scratch_terms: Vec<(u64, u8)>,
    scratch_vector: Vec<u8>,
    /// Ordered recovered bytes not yet cut into native packets.
    stream: VecDeque<u8>,
    dirty: bool,
    /// Highest sequence known when feedback was last produced.
    reported_end: u64,
    /// Unprompted repeats of the latest feedback still owed, so one lost
    /// acknowledgement does not leave an idle sender waiting for its probe.
    repeats: u8,
    last_feedback: u64,
    spare: Vec<Vec<u8>>,
    stats: ReceiverStats,
}

impl Receiver {
    /// Allocate bounded state.
    pub fn new(config: Config) -> Result<Self, Error> {
        config.validate()?;
        Ok(Self {
            config,
            base: 0,
            end: 0,
            floor: 0,
            slots: VecDeque::new(),
            rows: Vec::new(),
            scratch_terms: Vec::new(),
            scratch_vector: Vec::new(),
            stream: VecDeque::new(),
            dirty: false,
            reported_end: 0,
            repeats: 0,
            last_feedback: 0,
            spare: Vec::new(),
            stats: ReceiverStats::default(),
        })
    }
    /// Begin at an arbitrary sequence, as a long-lived session would be.
    #[cfg(test)]
    pub(crate) fn start_at(&mut self, sequence: u64) {
        (self.base, self.end, self.floor, self.reported_end) =
            (sequence, sequence, sequence, sequence);
    }
    #[cfg(test)]
    pub(crate) fn debug_state(&self) -> String {
        format!(
            "base {} end {} floor {} rows {:?} stream {} dirty {}",
            self.base,
            self.end,
            self.floor,
            self.rows
                .iter()
                .map(|row| row.terms.clone())
                .collect::<Vec<_>>(),
            self.stream.len(),
            self.dirty
        )
    }
    /// Current counters.
    pub fn stats(&self) -> ReceiverStats {
        self.stats
    }
    /// Sources known to exist that are not yet delivered in order.
    pub fn pending(&self) -> u32 {
        // Bounded by the flow window, which fits 16 bits.
        (self.end - self.base) as u32
    }
    fn slot(&self, sequence: u64) -> Option<&Vec<u8>> {
        let index = usize::try_from(sequence.checked_sub(self.floor)?).ok()?;
        self.slots.get(index)?.as_ref()
    }
    fn known(&self, sequence: u64) -> bool {
        sequence < self.base || self.slot(sequence).is_some()
    }
    /// Extend knowledge of the highest sequence; reject one beyond the flow bound.
    fn observe_end(&mut self, end: u64) -> Result<(), Error> {
        if end > self.end {
            let limit = self.base + self.config.flow_sources as u64;
            if end > limit {
                return Err(Error::Malformed);
            }
            self.end = end;
            let needed = (self.end - self.floor) as usize;
            if self.slots.len() < needed {
                self.slots.resize_with(needed, || None);
            }
        }
        Ok(())
    }
    /// Accept one authenticated datagram body of kind source or repair. `seed`
    /// is the same per-datagram number the sender used.
    pub fn on_datagram(&mut self, seed: u64, body: &[u8]) -> Result<(), Error> {
        self.dirty = true;
        match body.first() {
            Some(&KIND_SOURCE) => {
                let wire =
                    read_u32(body.get(1..).ok_or(Error::Malformed)?).ok_or(Error::Malformed)?;
                let sequence = expand(self.base, wire).ok_or(Error::Malformed)?;
                let payload = body.get(SOURCE_HEADER..).ok_or(Error::Malformed)?;
                if payload.is_empty() || payload.len() > self.config.symbol_bytes() {
                    return Err(Error::Malformed);
                }
                let end = sequence.checked_add(1).ok_or(Error::Malformed)?;
                if self.known(sequence) {
                    self.stats.duplicates += 1;
                    return Ok(());
                }
                self.observe_end(end)?;
                let mut owned = self.spare.pop().unwrap_or_default();
                owned.clear();
                owned.extend_from_slice(payload);
                self.stats.sources += 1;
                self.learn(sequence, owned)?;
            }
            Some(&KIND_REPAIR) => {
                let wire =
                    read_u32(body.get(1..).ok_or(Error::Malformed)?).ok_or(Error::Malformed)?;
                let end = expand(self.base, wire).ok_or(Error::Malformed)?;
                let count = u64::from(*body.get(5).ok_or(Error::Malformed)?);
                let data = body.get(REPAIR_HEADER..).ok_or(Error::Malformed)?;
                if count == 0
                    || count as usize > self.config.window
                    || count > end
                    || data.len() < 3
                    || data.len() > self.config.symbol_bytes() + 2
                {
                    return Err(Error::Malformed);
                }
                let start = end - count;
                // The sender only covers unconfirmed sources, which are never
                // below what this receiver has acknowledged; older equations
                // are late duplicates of resolved history.
                if end <= self.base || start < self.floor {
                    self.stats.duplicates += 1;
                    return Ok(());
                }
                self.observe_end(end)?;
                self.equation(seed, start, end, data)?;
            }
            _ => return Err(Error::Malformed),
        }
        self.advance()
    }
    /// Reduce a received equation against known sources and held rows.
    fn equation(&mut self, seed: u64, start: u64, end: u64, data: &[u8]) -> Result<(), Error> {
        let mut vector = std::mem::take(&mut self.scratch_vector);
        vector.clear();
        vector.extend_from_slice(data);
        let mut terms = Vec::new();
        for sequence in start..end {
            let factor = gf::coefficient(seed, sequence as u32);
            if sequence < self.base || self.slot(sequence).is_some() {
                let Some(payload) = self.slot(sequence) else {
                    // History below the floor was already excluded by the caller.
                    self.scratch_vector = vector;
                    return Err(Error::Malformed);
                };
                if payload.len() + 2 > vector.len() {
                    self.scratch_vector = vector;
                    return Err(Error::Malformed);
                }
                let length = (payload.len() as u16).to_be_bytes();
                gf::mul_add(&mut vector[..2], &length, factor);
                gf::mul_add(&mut vector[2..], payload, factor);
            } else {
                terms.push((sequence, factor));
            }
        }
        if terms.is_empty() {
            self.stats.useless_repairs += 1;
            self.scratch_vector = vector;
            return Ok(());
        }
        // Bounded equations: make room by forgetting the one about the oldest
        // source. Removing a reduced row keeps the rest reduced, and its
        // unknowns simply become eligible for explicit requests again.
        if self.rows.len() >= 2 * self.config.window
            && let Some(oldest) = (0..self.rows.len())
                .min_by_key(|index| self.rows[*index].terms.first().map(|term| term.0))
        {
            self.rows.swap_remove(oldest);
        }
        let row = Row {
            terms,
            data: vector.clone(),
        };
        self.scratch_vector = vector;
        if self.insert(row)? {
            self.stats.useful_repairs += 1;
        } else {
            self.stats.useless_repairs += 1;
        }
        self.solve()
    }
    /// Reduce a row by every held pivot, normalise it and clear its own pivot
    /// from the other rows. Returns whether it added an independent equation.
    fn insert(&mut self, mut row: Row) -> Result<bool, Error> {
        for other in &self.rows {
            let Some(&(pivot, _)) = other.terms.first() else {
                continue;
            };
            if let Some((_, factor)) = coefficient_of(&row.terms, pivot) {
                add_terms(
                    &mut row.terms,
                    &other.terms,
                    factor,
                    &mut self.scratch_terms,
                );
                add_scaled(&mut row.data, &other.data, factor);
            }
        }
        let Some(&(pivot, lead)) = row.terms.first() else {
            // A consistent sender leaves no residue in a dependent equation.
            return if row.data.iter().any(|byte| *byte != 0) {
                Err(Error::Malformed)
            } else {
                Ok(false)
            };
        };
        let inverse = gf::inv(lead).ok_or(Error::Malformed)?;
        for term in &mut row.terms {
            term.1 = gf::mul(term.1, inverse);
        }
        gf::scale(&mut row.data, inverse);
        for other in &mut self.rows {
            if let Some((_, factor)) = coefficient_of(&other.terms, pivot) {
                add_terms(
                    &mut other.terms,
                    &row.terms,
                    factor,
                    &mut self.scratch_terms,
                );
                add_scaled(&mut other.data, &row.data, factor);
            }
        }
        self.rows.push(row);
        Ok(true)
    }
    /// Turn every single-unknown row into a recovered source.
    fn solve(&mut self) -> Result<(), Error> {
        while let Some(index) = self.rows.iter().position(|row| row.terms.len() == 1) {
            let row = self.rows.swap_remove(index);
            let sequence = row.terms[0].0;
            let length = usize::from(u16::from_be_bytes([
                *row.data.first().ok_or(Error::Malformed)?,
                *row.data.get(1).ok_or(Error::Malformed)?,
            ]));
            if length == 0
                || length > self.config.symbol_bytes()
                || row.data.len() < 2 + length
                || row.data[2 + length..].iter().any(|byte| *byte != 0)
            {
                return Err(Error::Malformed);
            }
            let mut payload = row.data;
            payload.truncate(2 + length);
            payload.drain(..2);
            self.stats.recovered += 1;
            // In reduced form no other row mentions this pivot.
            self.store(sequence, payload);
        }
        Ok(())
    }
    fn store(&mut self, sequence: u64, payload: Vec<u8>) {
        if let Some(index) = sequence
            .checked_sub(self.floor)
            .and_then(|offset| usize::try_from(offset).ok())
            && let Some(slot) = self.slots.get_mut(index)
        {
            *slot = Some(payload);
        }
    }
    /// Record a directly received source and substitute it into held rows.
    fn learn(&mut self, sequence: u64, payload: Vec<u8>) -> Result<(), Error> {
        let length = (payload.len() as u16).to_be_bytes();
        let mut repivot = Vec::new();
        let mut index = 0;
        while index < self.rows.len() {
            let row = &mut self.rows[index];
            if let Some((position, factor)) = coefficient_of(&row.terms, sequence) {
                if row.data.len() < payload.len() + 2 {
                    row.data.resize(payload.len() + 2, 0);
                }
                gf::mul_add(&mut row.data[..2], &length, factor);
                gf::mul_add(&mut row.data[2..], &payload, factor);
                row.terms.remove(position);
                if row.terms.is_empty() {
                    // A consistent sender leaves nothing behind.
                    if row.data.iter().any(|byte| *byte != 0) {
                        return Err(Error::Malformed);
                    }
                    self.rows.swap_remove(index);
                    continue;
                }
                if position == 0 {
                    repivot.push(self.rows.swap_remove(index));
                    continue;
                }
            }
            index += 1;
        }
        self.store(sequence, payload);
        // A row that lost its pivot is reinserted; its remaining unknowns are
        // not pivots of any other row, so only normalisation is needed.
        for row in repivot {
            self.insert(row)?;
        }
        self.solve()
    }
    /// Move in-order sources into the byte stream and trim history.
    fn advance(&mut self) -> Result<(), Error> {
        while self.base < self.end {
            let index = (self.base - self.floor) as usize;
            let Some(Some(payload)) = self.slots.get(index) else {
                break;
            };
            self.stream.extend(payload.iter());
            self.base += 1;
        }
        // Keep one window of delivered history for repairs still in flight.
        let keep = self.base.saturating_sub(self.config.window as u64);
        while self.floor < keep {
            if let Some(Some(mut payload)) = self.slots.pop_front()
                && self.spare.len() < 64
            {
                payload.clear();
                self.spare.push(payload);
            }
            self.floor += 1;
        }
        // Everything the flow bound admits plus one unfinished packet.
        let bound = self.config.flow_sources * self.config.symbol_bytes()
            + self.config.max_packet
            + FRAME_PREFIX;
        if self.stream.len() > bound {
            return Err(Error::Malformed);
        }
        Ok(())
    }
    /// Copy the next complete native packet into `output` (cleared first).
    pub fn pop_packet(&mut self, output: &mut Vec<u8>) -> Result<bool, Error> {
        output.clear();
        let (Some(high), Some(low)) = (self.stream.front(), self.stream.get(1)) else {
            return Ok(false);
        };
        let length = usize::from(u16::from_be_bytes([*high, *low]));
        if length == 0 || length > self.config.max_packet {
            return Err(Error::Malformed);
        }
        if self.stream.len() < FRAME_PREFIX + length {
            return Ok(false);
        }
        self.stream.drain(..FRAME_PREFIX);
        crate::byte_queue::append_prefix(&mut self.stream, length, output)?;
        self.stats.packets += 1;
        Ok(true)
    }
    /// Earliest time feedback becomes due, if any is owed.
    pub fn deadline(&self) -> Option<u64> {
        (self.dirty || self.repeats > 0).then(|| {
            self.last_feedback
                .saturating_add(self.config.feedback_micros)
        })
    }
    /// Write a feedback datagram body into `output` when one is due.
    ///
    /// It carries the in-order prefix, the highest known sequence, how many
    /// sources inside the newest window are still missing, and explicit
    /// requests for missing sources that no held equation already determines:
    /// those older than the coding window, and all of them once no new source
    /// has arrived since the previous feedback.
    pub fn feedback(&mut self, now: u64, output: &mut Vec<u8>) -> bool {
        if !(self.dirty || self.repeats > 0)
            || now
                < self
                    .last_feedback
                    .saturating_add(self.config.feedback_micros)
        {
            return false;
        }
        output.clear();
        output.push(KIND_FEEDBACK);
        output.extend_from_slice(&(self.base as u32).to_be_bytes());
        output.extend_from_slice(&(self.end as u32).to_be_bytes());
        let coded_from = self
            .end
            .saturating_sub(self.config.window as u64)
            .max(self.base);
        let mut recent = 0u16;
        for sequence in coded_from..self.end {
            if self.slot(sequence).is_none() {
                recent = recent.saturating_add(1);
            }
        }
        output.extend_from_slice(&recent.to_be_bytes());
        output.push(0);
        // While new sources keep arriving, a gap is left alone until coding
        // can no longer cover it, or, without proportional repairs, until a
        // few later sources show it is not mere reordering. Once sources stop
        // nothing will age the gap, so it is requested like any older one.
        let settled = if self.config.repair_numerator == 0 {
            self.end
                .saturating_sub(u64::from(REORDER_SOURCES))
                .max(self.base)
        } else {
            coded_from
        };
        let request_to = if self.end == self.reported_end {
            self.end
        } else {
            settled
        };
        self.reported_end = self.end;
        let mut requests = 0;
        for sequence in self.base..request_to {
            if requests == MAX_REQUESTS {
                break;
            }
            let offset = sequence - self.base;
            if offset > u64::from(u16::MAX) {
                break;
            }
            // A row's pivot is determined once that row's other unknowns
            // arrive, so asking for it as well would only buy a duplicate.
            if self.slot(sequence).is_none()
                && !self
                    .rows
                    .iter()
                    .any(|row| row.terms.first().is_some_and(|term| term.0 == sequence))
            {
                output.extend_from_slice(&(offset as u16).to_be_bytes());
                requests += 1;
            }
        }
        output[FEEDBACK_HEADER - 1] = requests as u8;
        self.repeats = if self.dirty {
            FEEDBACK_REPEATS
        } else {
            self.repeats.saturating_sub(1)
        };
        self.dirty = false;
        self.last_feedback = now;
        self.stats.feedback += 1;
        true
    }
}

#[cfg(test)]
#[path = "receiver_byte_queue_tests.rs"]
mod byte_queue_tests;
