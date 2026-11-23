//! Feedback for one direction of an established striped group stream.
//! The enclosing authenticated feedback record selects the session, epoch,
//! coding channel and data direction. No field in this body selects an owner.
use crate::{Error, FecContext, GenerationId, rolling::wire::compact};

const VERSION: u8 = 0x10;
const CUMULATIVE: u8 = 1;
const NAMED: u8 = 2;

/// One tag and at most four canonical unsigned 64-bit varints.
pub const MAX_WIRE_BYTES: usize = 41;

/// Nonzero feedback serial scoped to a single data direction and epoch.
/// Repeated sends of the same logical feedback retain this serial.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct FeedbackId(pub u64);

/// Named originals spanning at most 64 adjacent absolute source IDs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Missing {
    first: GenerationId,
    mask: u64,
}

impl Missing {
    /// Bit zero must name the first missing source. Every set bit must fit the ID space.
    pub fn new(first: GenerationId, mask: u64) -> Result<Self, Error> {
        if mask & 1 == 0 {
            return Err(Error::Malformed);
        }
        let last_offset = u64::from(63 - mask.leading_zeros());
        first.0.checked_add(last_offset).ok_or(Error::Arithmetic)?;
        Ok(Self { first, mask })
    }

    /// Lowest named absolute source.
    pub const fn first(self) -> GenerationId {
        self.first
    }

    /// Set bits name source IDs relative to the lowest.
    pub const fn mask(self) -> u64 {
        self.mask
    }

    /// Iterate the named IDs in ascending order without allocating.
    pub fn ids(self) -> impl Iterator<Item = GenerationId> {
        let mut remaining = self.mask;
        std::iter::from_fn(move || {
            if remaining == 0 {
                return None;
            }
            let offset = u64::from(remaining.trailing_zeros());
            remaining &= remaining - 1;
            // Construction checked the highest set bit.
            Some(GenerationId(self.first.0 + offset))
        })
    }
}

/// One authenticated cumulative acknowledgment, named request, or both.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Feedback {
    context: FecContext,
    id: FeedbackId,
    confirmed_through: Option<GenerationId>,
    missing: Option<Missing>,
}

impl Feedback {
    /// Build an immutable logical receipt. Cumulative coverage is inclusive.
    pub fn new(
        context: FecContext,
        id: FeedbackId,
        confirmed_through: Option<GenerationId>,
        missing: Option<Missing>,
    ) -> Result<Self, Error> {
        if id.0 == 0 || (confirmed_through.is_none() && missing.is_none()) {
            return Err(Error::Malformed);
        }
        if let (Some(last), Some(named)) = (confirmed_through, missing)
            && named.first <= last
        {
            return Err(Error::Malformed);
        }
        Ok(Self {
            context,
            id,
            confirmed_through,
            missing,
        })
    }

    /// Authenticated coding context of the data being acknowledged.
    pub const fn context(self) -> FecContext {
        self.context
    }

    /// Immutable logical serial independent of physical carrier packet numbers.
    pub const fn id(self) -> FeedbackId {
        self.id
    }

    /// Highest contiguous committed source, including the last representable ID.
    pub const fn confirmed_through(self) -> Option<GenerationId> {
        self.confirmed_through
    }

    /// Missing source IDs beyond this message's cumulative acknowledgment.
    pub const fn missing(self) -> Option<Missing> {
        self.missing
    }

    /// Exact compact plaintext size before the selected carrier's protection.
    pub fn wire_len(self) -> usize {
        1 + compact::len(self.id.0)
            + self
                .confirmed_through
                .map_or(0, |last| compact::len(last.0))
            + self
                .missing
                .map_or(0, |set| compact::len(set.first.0) + compact::len(set.mask))
    }

    /// Encode one complete receipt. If the output is too short it remains untouched.
    pub fn encode(self, output: &mut [u8]) -> Result<usize, Error> {
        let required = self.wire_len();
        let out = output
            .get_mut(..required)
            .ok_or(Error::OutputTooSmall { required })?;
        out[0] = VERSION
            | u8::from(self.confirmed_through.is_some())
            | (u8::from(self.missing.is_some()) << 1);
        let mut pos = 1;
        compact::write(self.id.0, out, &mut pos);
        if let Some(last) = self.confirmed_through {
            compact::write(last.0, out, &mut pos);
        }
        if let Some(set) = self.missing {
            compact::write(set.first.0, out, &mut pos);
            compact::write(set.mask, out, &mut pos);
        }
        Ok(pos)
    }

    /// Decode under the data-owner context selected by the authenticated feedback path.
    pub fn decode(context: FecContext, input: &[u8]) -> Result<Self, Error> {
        let Some(&tag) = input.first() else {
            return Err(Error::Malformed);
        };
        if tag & !(CUMULATIVE | NAMED) != VERSION || input.len() > MAX_WIRE_BYTES {
            return Err(Error::Malformed);
        }
        let mut pos = 1;
        let mut field = || compact::read(input, &mut pos).map_err(|_| Error::Malformed);
        let id = FeedbackId(field()?);
        let last = if tag & CUMULATIVE != 0 {
            Some(GenerationId(field()?))
        } else {
            None
        };
        let named = if tag & NAMED != 0 {
            Some(Missing::new(GenerationId(field()?), field()?)?)
        } else {
            None
        };
        if pos != input.len() {
            return Err(Error::Malformed);
        }
        Self::new(context, id, last, named)
    }
}

/// Suppresses duplicate logical feedback while accepting unseen reordered requests
/// within the latest 64 serials. Outer authenticated packet replay is independent.
#[derive(Clone, Copy, Debug)]
pub struct ReplayWindow {
    context: FecContext,
    highest: u64,
    seen: u64,
}

impl ReplayWindow {
    /// Start a fresh ledger for one negotiated epoch and coding direction.
    pub const fn new(context: FecContext) -> Self {
        Self {
            context,
            highest: 0,
            seen: 0,
        }
    }

    /// Consume a generation-valid receipt once. Repeats and retired serials are
    /// no-ops. Validate peer claims before committing this receipt or a staged copy.
    pub fn accept(&mut self, receipt: Feedback) -> Result<bool, Error> {
        if receipt.context != self.context {
            return Err(Error::ContextMismatch);
        }
        let serial = receipt.id.0;
        if serial > self.highest {
            let advance = serial - self.highest;
            self.seen = if advance < 64 {
                self.seen << advance
            } else {
                0
            } | 1;
            self.highest = serial;
            return Ok(true);
        }
        let distance = self.highest - serial;
        if distance >= 64 || self.seen & (1 << distance) != 0 {
            return Ok(false);
        }
        self.seen |= 1 << distance;
        Ok(true)
    }
}

#[cfg(test)]
mod tests;
