//! Canonical absolute identities around exact original Python packing bytes.
//!
//! This framing does not authenticate data. Existing authenticated recovery must
//! bind every byte, validate the outer recovery source and transactionally admit
//! the distinct consecutive unit-ID space before any native delivery.

use crate::{
    aligned_receiver::{RecordId, Scope, SourceId, SymbolIdentity},
    packed,
    source_identity::{self, Layout, word64},
};
use std::fmt;

/// Fixed source identity header, before per-unit u64 record IDs and inner bytes.
pub const HEADER_BYTES: usize = Layout::Packed.header_bytes();
/// Negotiated finite source geometry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Config {
    /// Exact capacity for the meaningful Python source payload.
    pub symbol_bytes: usize,
    /// Ordinary channel count, 1..255 (channel255 is the packing marker).
    pub channels: u16,
    /// Maximum units in one source, 1..255.
    pub max_units: u8,
}
impl Config {
    /// Maximum full source bytes, bounded to the existing u16 source format.
    pub fn max_source_bytes(self) -> Result<usize, Error> {
        if !(9..=65_535).contains(&self.symbol_bytes)
            || !(1..=255).contains(&self.channels)
            || self.max_units == 0
        {
            return Err(Error::Configuration);
        }
        let size = HEADER_BYTES + 8 * usize::from(self.max_units) + self.symbol_bytes;
        if size > 65_535 {
            return Err(Error::Configuration);
        }
        Ok(size)
    }
}
/// Recovery-source identity plus a separate absolute aligned-unit sequence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Identity {
    /// Exact authenticated session, epoch and direction.
    pub scope: Scope,
    /// Actual ID allocated to this complete source by the recovery owner.
    pub source: SourceId,
    /// Distinct unit sequence; slot i has SourceId(first_unit + i).
    pub first_unit: SourceId,
}
/// Explicit framing failure; rejected encoding never changes caller output.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// Invalid negotiated geometry or nonzero-session requirement.
    Configuration,
    /// Unknown version, flags, geometry, length, padding or inner container.
    Malformed,
    /// Envelope belongs to a different authenticated scope.
    Scope,
    /// Count, ordinary channel or absolute-record/modular-serial mismatch.
    Identity,
    /// The distinct absolute unit space would wrap inside this source.
    Exhausted,
    /// Caller storage cannot contain the complete canonical source.
    OutputTooSmall {
        /// Full required source bytes.
        needed: usize,
    },
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "packed envelope: {self:?}")
    }
}
impl std::error::Error for Error {}

fn scope_valid(scope: Scope) -> Result<(), Error> {
    if scope.session == [0; 16] {
        return Err(Error::Configuration);
    }
    Ok(())
}
fn count_valid(config: Config, identity: Identity, count: usize) -> Result<(), Error> {
    config.max_source_bytes()?;
    scope_valid(identity.scope)?;
    if count == 0 || count > usize::from(config.max_units) {
        return Err(Error::Identity);
    }
    identity
        .first_unit
        .0
        .checked_add(count as u64 - 1)
        .ok_or(Error::Exhausted)?;
    Ok(())
}
enum PayloadUnits<'a> {
    Single(Option<&'a [u8]>),
    Packed(packed::Units<'a>),
}
impl<'a> Iterator for PayloadUnits<'a> {
    type Item = &'a [u8];
    fn next(&mut self) -> Option<Self::Item> {
        match self {
            Self::Single(unit) => unit.take(),
            Self::Packed(units) => units.next(),
        }
    }
}
fn payload_units(payload: &[u8], config: Config, count: usize) -> Result<PayloadUnits<'_>, Error> {
    if count == 1 {
        packed::validate_unit(payload, config.symbol_bytes).map_err(|_| Error::Malformed)?;
        Ok(PayloadUnits::Single(Some(payload)))
    } else {
        let container =
            packed::parse(payload, config.symbol_bytes).map_err(|_| Error::Malformed)?;
        if container.len() != count || container.encoded_len() != payload.len() {
            return Err(Error::Identity);
        }
        Ok(PayloadUnits::Packed(container.units()))
    }
}
fn check_unit(unit: &[u8], record: RecordId, config: Config) -> Result<(), Error> {
    // Both payload variants were completely framing validated before this call.
    if u16::from(unit[0]) >= config.channels
        || u16::from_be_bytes([unit[1], unit[2]]) != record.0 as u16
    {
        return Err(Error::Identity);
    }
    Ok(())
}

/// Encode all authenticated identities only after complete unit/count validation.
pub fn encode(
    config: Config,
    identity: Identity,
    records: &[RecordId],
    payload: &[u8],
    output: &mut [u8],
) -> Result<usize, Error> {
    count_valid(config, identity, records.len())?;
    let units = payload_units(payload, config, records.len())?;
    for (unit, record) in units.zip(records) {
        check_unit(unit, *record, config)?;
    }
    let needed = HEADER_BYTES + 8 * records.len() + payload.len();
    if output.len() < needed {
        return Err(Error::OutputTooSmall { needed });
    }
    output[..HEADER_BYTES].fill(0);
    source_identity::encode(
        Layout::Packed,
        source_identity::Identity {
            scope: identity.scope,
            source: identity.source,
        },
        output,
    )
    .map_err(header_error)?;
    output[6] = records.len() as u8;
    output[8..10].copy_from_slice(&(config.symbol_bytes as u16).to_be_bytes());
    output[10..12].copy_from_slice(&(payload.len() as u16).to_be_bytes());
    output[44..52].copy_from_slice(&identity.first_unit.0.to_be_bytes());
    for (index, record) in records.iter().enumerate() {
        let start = HEADER_BYTES + index * 8;
        output[start..start + 8].copy_from_slice(&record.0.to_be_bytes());
    }
    output[HEADER_BYTES + records.len() * 8..needed].copy_from_slice(payload);
    Ok(needed)
}
/// Completely validated immutable source; replay state remains external.
pub struct View<'a> {
    identity: Identity,
    records: &'a [u8],
    payload: &'a [u8],
    config: Config,
    count: u8,
}
impl<'a> View<'a> {
    /// Copy the validated recovery and distinct absolute-unit identity.
    pub fn identity(&self) -> Identity {
        self.identity
    }
    /// Meaningful original Python payload, without invented padding or metadata.
    pub fn payload(&self) -> &'a [u8] {
        self.payload
    }
    /// Number of original aligned units, always nonzero.
    pub fn len(&self) -> usize {
        usize::from(self.count)
    }
    /// A validated envelope is never empty.
    pub fn is_empty(&self) -> bool {
        false
    }
    /// Iterate complete units and their full identities after total validation.
    pub fn units(&self) -> Result<Units<'a>, Error> {
        Ok(Units {
            identity: self.identity,
            records: self.records,
            payload: payload_units(self.payload, self.config, self.len())?,
            index: 0,
            remaining: self.len(),
        })
    }
}
/// One original aligned unit ready for later transactional receiver admission.
#[derive(Debug)]
pub struct Unit<'a> {
    /// `source` here is the separate unit ID, not the enclosing recovery source.
    pub identity: SymbolIdentity,
    /// Exact original channel/serial/body bytes, without coding zero-extension.
    pub bytes: &'a [u8],
}
/// Bounded borrowed iteration over already validated source units.
pub struct Units<'a> {
    identity: Identity,
    records: &'a [u8],
    payload: PayloadUnits<'a>,
    index: usize,
    remaining: usize,
}
impl<'a> Iterator for Units<'a> {
    type Item = Unit<'a>;
    fn next(&mut self) -> Option<Self::Item> {
        let bytes = self.payload.next()?;
        let record = RecordId(word64(self.records, self.index * 8));
        let source = SourceId(self.identity.first_unit.0 + self.index as u64);
        self.index += 1;
        self.remaining -= 1;
        Some(Unit {
            identity: SymbolIdentity {
                scope: self.identity.scope,
                source,
                record,
            },
            bytes,
        })
    }
    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.remaining, Some(self.remaining))
    }
}
impl ExactSizeIterator for Units<'_> {}
impl std::iter::FusedIterator for Units<'_> {}

/// Check expected scope and all framing/identity bytes before exposing any unit.
pub fn decode(config: Config, expected: Scope, input: &[u8]) -> Result<View<'_>, Error> {
    config.max_source_bytes()?;
    scope_valid(expected)?;
    if input.len() < HEADER_BYTES
        || input[7] != 0
        || input[52..56] != [0; 4]
        || usize::from(u16::from_be_bytes([input[8], input[9]])) != config.symbol_bytes
    {
        return Err(Error::Malformed);
    }
    let header = source_identity::decode(Layout::Packed, expected, input).map_err(header_error)?;
    let identity = Identity {
        scope: header.identity.scope,
        source: header.identity.source,
        first_unit: SourceId(word64(header.tail, 0)),
    };
    let count = usize::from(input[6]);
    count_valid(config, identity, count)?;
    let payload_len = usize::from(u16::from_be_bytes([input[10], input[11]]));
    let body_start = HEADER_BYTES + 8 * count;
    if body_start + payload_len != input.len() {
        return Err(Error::Malformed);
    }
    let payload = &input[body_start..];
    let records = &input[HEADER_BYTES..body_start];
    for (index, unit) in payload_units(payload, config, count)?.enumerate() {
        check_unit(unit, RecordId(word64(records, index * 8)), config)?;
    }
    Ok(View {
        identity,
        records,
        payload,
        config,
        count: count as u8,
    })
}
fn header_error(error: source_identity::Error) -> Error {
    match error {
        source_identity::Error::Malformed => Error::Malformed,
        source_identity::Error::Scope => Error::Scope,
    }
}

#[cfg(test)]
#[path = "packed_envelope_tests.rs"]
mod tests;
