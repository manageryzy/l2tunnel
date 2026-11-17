//! Exact absolute-identity envelope for an externally authenticated aligned symbol.
//! This parser supplies no integrity protection or cryptographic evidence.

use crate::{
    aligned_receiver::{RecordId, Scope, SymbolIdentity},
    source_identity::{self, Layout},
};
use std::fmt;

mod compact;
pub(crate) use compact::validate_unit as validate_compact_unit;
pub use compact::{decode_compact, encode_compact};

/// Bytes added before the unchanged Python aligned symbol.
pub const HEADER_BYTES: usize = Layout::Aligned.header_bytes();
/// Envelope format version, independent of the Python inner format.
pub const VERSION: u8 = source_identity::VERSION;

/// Structural, scope or caller-buffer failure, without state mutation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// Invalid negotiated symbol/channel/scope bounds.
    Configuration,
    /// Invalid magic/version/direction/length or low16 record serial.
    Malformed,
    /// Session, epoch or direction differs from the expected authenticated scope.
    Scope,
    /// The caller has insufficient output capacity.
    OutputTooSmall {
        /// Complete envelope capacity required.
        needed: usize,
    },
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "aligned envelope: {self:?}")
    }
}
impl std::error::Error for Error {}

/// Borrowed parsed bytes, not proof that a carrier authenticated them.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct View<'a> {
    /// Full original symbol identity.
    pub identity: SymbolIdentity,
    /// Channel/serial/body bytes, including padding only in the full-symbol format.
    pub symbol: &'a [u8],
}

/// Encode one complete symbol. Failure leaves output unchanged.
pub fn encode(identity: SymbolIdentity, symbol: &[u8], output: &mut [u8]) -> Result<usize, Error> {
    if identity.scope.session == [0; 16] || !(9..=65535).contains(&symbol.len()) {
        return Err(Error::Configuration);
    }
    if u16::from_be_bytes([symbol[1], symbol[2]]) != identity.record.0 as u16 {
        return Err(Error::Malformed);
    }
    let needed = HEADER_BYTES + symbol.len();
    if output.len() < needed {
        return Err(Error::OutputTooSmall { needed });
    }
    source_identity::encode(
        Layout::Aligned,
        source_identity::Identity {
            scope: identity.scope,
            source: identity.source,
        },
        output,
    )
    .map_err(header_error)?;
    output[6..8].copy_from_slice(&(symbol.len() as u16).to_be_bytes());
    output[40..48].copy_from_slice(&identity.record.0.to_be_bytes());
    output[HEADER_BYTES..needed].copy_from_slice(symbol);
    Ok(needed)
}

/// Parse exact negotiated geometry and identity after carrier authentication.
/// This checks the full inner channel and serial; body validation is separate.
pub fn decode(
    expected: Scope,
    symbol_bytes: usize,
    channels: u16,
    input: &[u8],
) -> Result<View<'_>, Error> {
    if expected.session == [0; 16]
        || !(9..=65535).contains(&symbol_bytes)
        || !(1..=256).contains(&channels)
    {
        return Err(Error::Configuration);
    }
    if input.len() != HEADER_BYTES + symbol_bytes
        || usize::from(u16::from_be_bytes([input[6], input[7]])) != symbol_bytes
    {
        return Err(Error::Malformed);
    }
    let header = source_identity::decode(Layout::Aligned, expected, input).map_err(header_error)?;
    let record = RecordId(source_identity::word64(header.tail, 0));
    let symbol = &input[HEADER_BYTES..];
    if u16::from(symbol[0]) >= channels
        || u16::from_be_bytes([symbol[1], symbol[2]]) != record.0 as u16
    {
        return Err(Error::Malformed);
    }
    Ok(View {
        identity: SymbolIdentity {
            scope: header.identity.scope,
            source: header.identity.source,
            record,
        },
        symbol,
    })
}

fn header_error(error: source_identity::Error) -> Error {
    match error {
        source_identity::Error::Malformed => Error::Malformed,
        source_identity::Error::Scope => Error::Scope,
    }
}
