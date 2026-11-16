//! Shared identity fields of the two maintained source-envelope layouts.
//!
//! This borrowed structural view supplies no authentication or replay authority.
//! Each format still validates its own geometry and unit/record identities.

use crate::aligned_receiver::{Direction, Scope, SourceId};
use l2tunnel_core::Epoch;

pub(crate) const VERSION: u8 = 1;

#[derive(Clone, Copy)]
pub(crate) enum Layout {
    Aligned,
    Packed,
}
impl Layout {
    pub(crate) const fn header_bytes(self) -> usize {
        match self {
            Self::Aligned => 48,
            Self::Packed => 56,
        }
    }
    const fn magic(self) -> &'static [u8; 4] {
        match self {
            Self::Aligned => b"L2AS",
            Self::Packed => b"L2PK",
        }
    }
    const fn session_offset(self) -> usize {
        match self {
            Self::Aligned => 8,
            Self::Packed => 12,
        }
    }
}

/// A recovery source, distinct from Packed's first unit and each native record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Identity {
    pub(crate) scope: Scope,
    pub(crate) source: SourceId,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Error {
    Malformed,
    Scope,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "source identity: {self:?}")
    }
}
impl std::error::Error for Error {}

/// The common identity and borrowed format-specific tail of a complete header.
pub(crate) struct View<'a> {
    pub(crate) identity: Identity,
    pub(crate) tail: &'a [u8],
}

/// Read a canonical legacy header after the caller's format-geometry preflight.
pub(crate) fn decode(layout: Layout, expected: Scope, input: &[u8]) -> Result<View<'_>, Error> {
    let header = input.get(..layout.header_bytes()).ok_or(Error::Malformed)?;
    if header[..4] != *layout.magic() || header[4] != VERSION {
        return Err(Error::Malformed);
    }
    let direction = match header[5] {
        0 => Direction::InitiatorToResponder,
        1 => Direction::ResponderToInitiator,
        _ => return Err(Error::Malformed),
    };
    let start = layout.session_offset();
    let mut session = [0; 16];
    session.copy_from_slice(&header[start..start + 16]);
    let scope = Scope {
        session,
        epoch: Epoch(word64(header, start + 16)),
        direction,
    };
    if scope != expected {
        return Err(Error::Scope);
    }
    Ok(View {
        identity: Identity {
            scope,
            source: SourceId(word64(header, start + 24)),
        },
        tail: &header[start + 32..],
    })
}

/// Write only shared fields, preserving each legacy format's other header bytes.
/// The caller validates the complete source and output capacity before any write.
pub(crate) fn encode(layout: Layout, identity: Identity, output: &mut [u8]) -> Result<(), Error> {
    let header = output
        .get_mut(..layout.header_bytes())
        .ok_or(Error::Malformed)?;
    header[..4].copy_from_slice(layout.magic());
    header[4] = VERSION;
    header[5] = match identity.scope.direction {
        Direction::InitiatorToResponder => 0,
        Direction::ResponderToInitiator => 1,
    };
    let start = layout.session_offset();
    header[start..start + 16].copy_from_slice(&identity.scope.session);
    header[start + 16..start + 24].copy_from_slice(&identity.scope.epoch.0.to_be_bytes());
    header[start + 24..start + 32].copy_from_slice(&identity.source.0.to_be_bytes());
    Ok(())
}

// All callers read fixed fields only after validating their enclosing extent.
pub(crate) fn word64(input: &[u8], start: usize) -> u64 {
    let mut value = [0; 8];
    value.copy_from_slice(&input[start..start + 8]);
    u64::from_be_bytes(value)
}

#[cfg(test)]
#[path = "source_identity_tests.rs"]
mod tests;
