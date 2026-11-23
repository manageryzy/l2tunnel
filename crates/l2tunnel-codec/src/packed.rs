//! Exact Python packed containers and one bounded timed source buffer.
//!
//! Authenticate before parsing. Context-dependent bodies still require the
//! existing transactional aligned decoder. This module does not allocate source
//! identities, acknowledge channel records, or deliver native packets.

use std::fmt;

/// Reserved packed-source channel; ordinary units must use a lower channel.
pub const PACKED_CHANNEL: u8 = 255;
/// Maximum number of units represented by the one-byte container count.
pub const MAX_UNITS: usize = 255;

/// Parsing or state failure; rejected operations preserve retained source bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// Invalid symbol geometry, hold interval or physical copy count.
    Configuration,
    /// Malformed container, unit, explicit record, fragment or padding.
    Malformed,
    /// Caller time went backwards relative to a previously accepted operation.
    ClockRegression,
    /// The first-unit deadline cannot be represented.
    ClockExhausted,
    /// No sealed source exists to confirm.
    NoPending,
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "packed source: {self:?}")
    }
}
impl std::error::Error for Error {}

fn geometry(symbol_bytes: usize) -> Result<(), Error> {
    if !(9..=65_535).contains(&symbol_bytes) {
        return Err(Error::Configuration);
    }
    Ok(())
}

/// Validate one complete, unpadded aligned unit without changing any context.
///
/// Implicit-length/prediction/dictionary payloads need the receiving channel's
/// context for a subsequent exact-length check, as in the Python reference.
pub fn validate_unit(unit: &[u8], symbol_bytes: usize) -> Result<(), Error> {
    geometry(symbol_bytes)?;
    if unit.first() == Some(&PACKED_CHANNEL) {
        return Err(Error::Malformed);
    }
    validate_aligned_unit(unit, symbol_bytes)
}

// Aligned admits channel 255; only the Packed container reserves that value.
pub(crate) fn validate_aligned_unit(unit: &[u8], symbol_bytes: usize) -> Result<(), Error> {
    geometry(symbol_bytes)?;
    if !(4..=symbol_bytes).contains(&unit.len()) {
        return Err(Error::Malformed);
    }
    let body = &unit[3..];
    let body = if body[0] == crate::aligned_body::FIXED_ANCHOR_TAG {
        crate::aligned_body::fixed_anchor_parts(body)
            .map_err(|_| Error::Malformed)?
            .1
    } else {
        body
    };
    match body[0] {
        4 => {
            if body.len() <= 5 {
                return Err(Error::Malformed);
            }
            let total = usize::from(u16::from_be_bytes([body[1], body[2]]));
            let offset = usize::from(u16::from_be_bytes([body[3], body[4]]));
            let capacity = symbol_bytes - 8;
            if offset >= total
                || offset % capacity != 0
                || body.len() != 5 + capacity.min(total - offset)
            {
                return Err(Error::Malformed);
            }
        }
        6 => {
            validate_delta_header(&body[1..], None)?;
        }
        tag if tag & 7 == 7 => {
            validate_delta_header(&body[1..], Some(tag & 0xf8))?;
        }
        tag if tag & 7 == 5 => {}
        _ => {
            if crate::aligned_receiver::explicit_length(body).map_err(|_| Error::Malformed)?
                != body.len()
            {
                return Err(Error::Malformed);
            }
        }
    }
    Ok(())
}

fn validate_delta_header(bytes: &[u8], supplied_mask: Option<u8>) -> Result<(), Error> {
    let (mask, mut position) = match supplied_mask {
        Some(mask) => (mask, 0),
        None => (*bytes.first().ok_or(Error::Malformed)?, 1),
    };
    for bit in 0..8 {
        if mask & (1 << bit) != 0 {
            let mut terminated = false;
            for _ in 0..5 {
                let byte = *bytes.get(position).ok_or(Error::Malformed)?;
                position += 1;
                if byte < 128 {
                    terminated = true;
                    break;
                }
            }
            if !terminated {
                return Err(Error::Malformed);
            }
        }
    }
    Ok(())
}

/// A completely framing-validated borrowed container; decoder state is external.
#[derive(Clone, Copy, Debug)]
pub struct Container<'a> {
    bytes: &'a [u8],
    count: u8,
}
impl<'a> Container<'a> {
    /// Number of complete aligned units (2..255).
    pub fn len(&self) -> usize {
        usize::from(self.count)
    }
    /// Valid containers are never empty.
    pub fn is_empty(&self) -> bool {
        false
    }
    /// Borrow each exact original unit after complete prevalidation.
    pub fn units(&self) -> Units<'a> {
        Units {
            bytes: self.bytes,
            position: 2,
            remaining: self.count,
        }
    }
    /// Meaningful container length, excluding optional zero padding.
    pub fn encoded_len(&self) -> usize {
        self.bytes.len()
    }
}

/// Borrowed iterator constructed only from a fully validated container.
#[derive(Clone)]
pub struct Units<'a> {
    bytes: &'a [u8],
    position: usize,
    remaining: u8,
}
impl<'a> Iterator for Units<'a> {
    type Item = &'a [u8];
    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 {
            return None;
        }
        let size = usize::from(u16::from_be_bytes([
            self.bytes[self.position],
            self.bytes[self.position + 1],
        ]));
        self.position += 2;
        let unit = &self.bytes[self.position..self.position + size];
        self.position += size;
        self.remaining -= 1;
        Some(unit)
    }
    fn size_hint(&self) -> (usize, Option<usize>) {
        let count = usize::from(self.remaining);
        (count, Some(count))
    }
}
impl ExactSizeIterator for Units<'_> {}
impl std::iter::FusedIterator for Units<'_> {}

/// Validate the entire multi-unit source and zero padding before returning units.
pub fn parse(payload: &[u8], symbol_bytes: usize) -> Result<Container<'_>, Error> {
    geometry(symbol_bytes)?;
    if !(2..=symbol_bytes).contains(&payload.len())
        || payload[0] != PACKED_CHANNEL
        || payload[1] < 2
    {
        return Err(Error::Malformed);
    }
    let count = payload[1];
    let mut position = 2;
    for _ in 0..count {
        let size_bytes = payload
            .get(position..position + 2)
            .ok_or(Error::Malformed)?;
        let size = usize::from(u16::from_be_bytes([size_bytes[0], size_bytes[1]]));
        position += 2;
        let unit = payload
            .get(position..position + size)
            .ok_or(Error::Malformed)?;
        validate_unit(unit, symbol_bytes)?;
        position += size;
    }
    if payload[position..].iter().any(|byte| *byte != 0) {
        return Err(Error::Malformed);
    }
    Ok(Container {
        bytes: &payload[..position],
        count,
    })
}

/// Exact fixed geometry and maximum delay after the first accepted unit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Config {
    /// Complete symbol capacity (9..65535); excludes any outer authentication.
    pub symbol_bytes: usize,
    /// Positive integer microseconds, at most the Python profile's 1 ms bound.
    pub hold_micros: u64,
}
impl Config {
    /// Historical allocating-owner scalar guard, not actual reserved capacity.
    pub fn memory_bound_bytes(self) -> Result<usize, Error> {
        geometry(self.symbol_bytes)?;
        if !(1..=1000).contains(&self.hold_micros) {
            return Err(Error::Configuration);
        }
        Ok(self.symbol_bytes + std::mem::size_of::<LegacyLayout>())
    }
}
/// Why a source became immutable and eligible for recovery ownership.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SealReason {
    /// First-unit maximum hold elapsed.
    Timer,
    /// Caller explicitly requested all pending work.
    Explicit,
    /// Another unit would exceed the symbol capacity.
    Capacity,
    /// Adjacent units require different physical copy policies.
    CopyPolicy,
    /// This unit cannot share with another equal-sized unit.
    LargeUnit,
    /// The one-byte count cannot admit another unit.
    UnitLimit,
}
/// Admission result; both retry variants leave the new input with the caller.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Push {
    /// This unit was accepted, possibly immediately sealing its source.
    Accepted,
    /// Previous work was sealed; hand it off and retry this unchanged input.
    FlushRequired,
    /// A sealed source still owns the only buffer; no new unit was accepted.
    Backpressure,
}
impl Push {
    /// Classify the actual non-consuming push result; no clock or state is changed.
    pub const fn buffer_refusal(self) -> Option<crate::diagnostics::PackingBlock> {
        match self {
            Self::Accepted => None,
            Self::FlushRequired => Some(crate::diagnostics::PackingBlock::FlushRequired),
            Self::Backpressure => Some(crate::diagnostics::PackingBlock::SealedSource),
        }
    }
}
/// Immutable source awaiting bounded recovery handoff.
#[derive(Clone, Copy, Debug)]
pub struct Pending<'a> {
    /// Exact meaningful Python bytes; any coding zero-extension is external.
    pub payload: &'a [u8],
    /// Physical copies requested by the common configured policy (1..4).
    pub copies: u8,
    /// Complete original units in this source.
    pub units: u8,
    /// The first event that sealed the source.
    pub reason: SealReason,
}
/// Current bounded ownership, without cumulative delivery or ACK claims.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Status {
    /// Complete original units currently retained.
    pub units: u8,
    /// Exact meaningful source bytes including all container lengths.
    pub bytes: usize,
    /// First-unit absolute deadline; does not renew while pending.
    pub deadline_micros: Option<u64>,
    /// A sealed source must be handed off before new input can enter.
    pub sealed: bool,
}
/// One fixed-size buffer, no internal source queue and no ambient clock.
pub struct Packer {
    config: Config,
    buffer: Vec<u8>,
    length: usize,
    count: u8,
    copies: u8,
    deadline: Option<u64>,
    last_now: u64,
    reason: Option<SealReason>,
}
// Exact original field types retain the old scalar bound after fallible Vec
// backing was added. Actual new owner headers are charged by their real plans.
#[allow(dead_code)]
pub(crate) struct LegacyLayout {
    config: Config,
    buffer: Box<[u8]>,
    length: usize,
    count: u8,
    copies: u8,
    deadline: Option<u64>,
    last_now: u64,
    reason: Option<SealReason>,
}
impl Packer {
    pub(crate) fn new_in(
        config: Config,
        allocation: &mut crate::aligned_storage::Allocation,
    ) -> Result<Self, crate::aligned_storage::Error> {
        Ok(Self {
            config,
            buffer: allocation.bytes(config.symbol_bytes)?,
            length: 0,
            count: 0,
            copies: 0,
            deadline: None,
            last_now: 0,
            reason: None,
        })
    }
    /// Validate all limits before allocating the sole symbol buffer.
    pub fn new(config: Config) -> Result<Self, Error> {
        config.memory_bound_bytes()?;
        Ok(Self {
            config,
            buffer: vec![0; config.symbol_bytes],
            length: 0,
            count: 0,
            copies: 0,
            deadline: None,
            last_now: 0,
            reason: None,
        })
    }
    fn clock(&self, now: u64) -> Result<(), Error> {
        if now < self.last_now {
            return Err(Error::ClockRegression);
        }
        Ok(())
    }
    /// Admit an exact unit; a retry outcome does not consume the caller's unit.
    pub fn push(&mut self, unit: &[u8], copies: u8, now: u64) -> Result<Push, Error> {
        self.clock(now)?;
        validate_unit(unit, self.config.symbol_bytes)?;
        if !(1..=4).contains(&copies) {
            return Err(Error::Configuration);
        }
        if self.reason.is_some() {
            return Ok(Push::Backpressure);
        }
        let deadline = if self.count == 0 {
            Some(
                now.checked_add(self.config.hold_micros)
                    .ok_or(Error::ClockExhausted)?,
            )
        } else {
            self.deadline
        };
        let extra = if self.count == 0 {
            0
        } else if self.count == 1 {
            6
        } else {
            2
        };
        let projected = self.length + extra + unit.len();
        let seal = if self.deadline.is_some_and(|at| now >= at) {
            Some(SealReason::Timer)
        } else if self.count > 0 && self.copies != copies {
            Some(SealReason::CopyPolicy)
        } else if usize::from(self.count) == MAX_UNITS {
            Some(SealReason::UnitLimit)
        } else if self.count > 0 && projected > self.config.symbol_bytes {
            Some(SealReason::Capacity)
        } else {
            None
        };
        self.last_now = now;
        if let Some(reason) = seal {
            self.reason = Some(reason);
            return Ok(Push::FlushRequired);
        }
        if self.count == 1 {
            self.buffer.copy_within(0..self.length, 4);
            self.buffer[0] = PACKED_CHANNEL;
            self.buffer[2..4].copy_from_slice(&(self.length as u16).to_be_bytes());
            self.length += 4;
        }
        if self.count > 0 {
            self.buffer[self.length..self.length + 2]
                .copy_from_slice(&(unit.len() as u16).to_be_bytes());
            self.length += 2;
        }
        self.buffer[self.length..self.length + unit.len()].copy_from_slice(unit);
        self.length += unit.len();
        self.count += 1;
        self.copies = copies;
        self.deadline = deadline;
        if self.count > 1 {
            self.buffer[1] = self.count;
        }
        if unit.len() > (self.config.symbol_bytes - 6) / 2 {
            self.reason = Some(SealReason::LargeUnit);
        }
        Ok(Push::Accepted)
    }
    /// Seal elapsed work. Repeated ticks cannot emit or duplicate a source.
    pub fn tick(&mut self, now: u64) -> Result<(), Error> {
        self.clock(now)?;
        self.last_now = now;
        if self.reason.is_none() && self.deadline.is_some_and(|at| now >= at) {
            self.reason = Some(SealReason::Timer);
        }
        Ok(())
    }
    /// Seal current work without inventing an empty source or changing its bytes.
    pub fn flush(&mut self) {
        if self.count > 0 && self.reason.is_none() {
            self.reason = Some(SealReason::Explicit);
        }
    }
    /// Borrow one immutable source; the same bytes remain until `commit`.
    pub fn pending(&self) -> Option<Pending<'_>> {
        self.reason.map(|reason| Pending {
            payload: &self.buffer[..self.length],
            copies: self.copies,
            units: self.count,
            reason,
        })
    }
    /// Confirm actual bounded recovery ownership; this is not peer/native receipt.
    pub fn commit(&mut self) -> Result<(), Error> {
        if self.reason.is_none() {
            return Err(Error::NoPending);
        }
        self.length = 0;
        self.count = 0;
        self.copies = 0;
        self.deadline = None;
        self.reason = None;
        Ok(())
    }
    /// Snapshot exact local retained bytes and the original deadline.
    pub fn status(&self) -> Status {
        Status {
            units: self.count,
            bytes: self.length,
            deadline_micros: self.deadline,
            sealed: self.reason.is_some(),
        }
    }
    /// Exact source occupancy; partial timer holds are not marked as blocked.
    pub fn buffer_snapshot(&self) -> crate::diagnostics::PackingBuffers {
        crate::diagnostics::PackingBuffers {
            source: crate::diagnostics::Retention {
                items: usize::from(self.count != 0),
                item_capacity: 1,
                bytes: self.length,
                byte_capacity: self.config.symbol_bytes,
            },
            units: usize::from(self.count),
            unit_capacity: MAX_UNITS,
            sealed: self.reason,
        }
    }
}

#[cfg(test)]
#[path = "packed_tests.rs"]
mod tests;
