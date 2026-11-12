//! Exact absolute-identity envelope for an externally authenticated aligned symbol.
//! This parser supplies no integrity protection or cryptographic evidence.

use crate::aligned_receiver::{Direction, RecordId, Scope, SourceId, SymbolIdentity};
use l2tunnel_core::Epoch;
use std::fmt;

/// Bytes added before the unchanged Python aligned symbol.
pub const HEADER_BYTES: usize = 48;
/// Envelope format version, independent of the Python inner format.
pub const VERSION: u8 = 1;

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
    /// Unchanged channel/serial/body/padding bytes.
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
    output[..4].copy_from_slice(b"L2AS");
    output[4] = VERSION;
    output[5] = match identity.scope.direction {
        Direction::InitiatorToResponder => 0,
        Direction::ResponderToInitiator => 1,
    };
    output[6..8].copy_from_slice(&(symbol.len() as u16).to_be_bytes());
    output[8..24].copy_from_slice(&identity.scope.session);
    output[24..32].copy_from_slice(&identity.scope.epoch.0.to_be_bytes());
    output[32..40].copy_from_slice(&identity.source.0.to_be_bytes());
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
        || input[..4] != *b"L2AS"
        || input[4] != VERSION
        || usize::from(u16::from_be_bytes([input[6], input[7]])) != symbol_bytes
    {
        return Err(Error::Malformed);
    }
    let direction = match input[5] {
        0 => Direction::InitiatorToResponder,
        1 => Direction::ResponderToInitiator,
        _ => return Err(Error::Malformed),
    };
    let mut session = [0; 16];
    session.copy_from_slice(&input[8..24]);
    let scope = Scope {
        session,
        epoch: Epoch(word(input, 24)),
        direction,
    };
    if scope != expected {
        return Err(Error::Scope);
    }
    let record = RecordId(word(input, 40));
    let symbol = &input[HEADER_BYTES..];
    if u16::from(symbol[0]) >= channels
        || u16::from_be_bytes([symbol[1], symbol[2]]) != record.0 as u16
    {
        return Err(Error::Malformed);
    }
    Ok(View {
        identity: SymbolIdentity {
            scope,
            source: SourceId(word(input, 32)),
            record,
        },
        symbol,
    })
}

fn word(input: &[u8], offset: usize) -> u64 {
    let mut value = [0; 8];
    value.copy_from_slice(&input[offset..offset + 8]);
    u64::from_be_bytes(value)
}
