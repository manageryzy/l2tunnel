//! Strict structural routing only; caller authentication must cover every byte.
use super::OwnerId;
use std::fmt;

/// Exact route bytes charged in each directional Compact external overhead.
pub const HEADER_BYTES: usize = 24;
/// Complete UDP payload bound, before any additional selected security/cover bytes.
pub const MAX_PACKET_BYTES: usize = 65_507;

/// Explicit record path; none grants management authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Class {
    /// Actual maintained Compact source bytes.
    Source,
    /// Actual maintained Compact receipt feedback bytes.
    Feedback,
    /// Complete native bytes that bypass recovery only; not installed here.
    UnreliableNative,
}

/// Exact untrusted route metadata, not an authenticated owner claim.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Header {
    /// Bounded actual connection-owner index.
    pub owner: OwnerId,
    /// Positive fixed cohort incarnation, separate from epoch and packet number.
    pub incarnation: u64,
    /// Explicit structural path.
    pub class: Class,
    /// Positive only for the independently retired unreliable-native path.
    pub unreliable_serial: u64,
}

/// Strict route grammar failure, without allocating or admitting a body.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// Truncated, empty-body, oversized or nonexact header output.
    Length,
    /// Unsupported magic, version or class.
    Prefix,
    /// Owner index is outside the complete supported0..256 domain.
    Owner,
    /// Zero incarnation or incompatible unreliable serial.
    Identity,
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "connection route: {self:?}")
    }
}
impl std::error::Error for Error {}

impl Header {
    fn encoded(self) -> Result<[u8; HEADER_BYTES], Error> {
        if self.owner.index() >= 256 {
            return Err(Error::Owner);
        }
        if self.incarnation == 0
            || (self.class == Class::UnreliableNative) != (self.unreliable_serial > 0)
        {
            return Err(Error::Identity);
        }
        let mut bytes = [0; HEADER_BYTES];
        bytes[..4].copy_from_slice(b"L2PC");
        bytes[4] = 1;
        bytes[5] = match self.class {
            Class::Source => 1,
            Class::Feedback => 2,
            Class::UnreliableNative => 3,
        };
        bytes[6..8].copy_from_slice(&self.owner.index().to_be_bytes());
        bytes[8..16].copy_from_slice(&self.incarnation.to_be_bytes());
        bytes[16..24].copy_from_slice(&self.unreliable_serial.to_be_bytes());
        Ok(bytes)
    }

    /// Validate all scalars before writing the exact header output.
    pub fn encode(self, output: &mut [u8]) -> Result<(), Error> {
        if output.len() != HEADER_BYTES {
            return Err(Error::Length);
        }
        let bytes = self.encoded()?;
        output.copy_from_slice(&bytes);
        Ok(())
    }
}

/// Parse one complete routed packet; authentication/replay checks remain external.
pub fn decode(input: &[u8]) -> Result<(Header, &[u8]), Error> {
    if input.len() <= HEADER_BYTES || input.len() > MAX_PACKET_BYTES {
        return Err(Error::Length);
    }
    if &input[..4] != b"L2PC" || input[4] != 1 {
        return Err(Error::Prefix);
    }
    let class = match input[5] {
        1 => Class::Source,
        2 => Class::Feedback,
        3 => Class::UnreliableNative,
        _ => return Err(Error::Prefix),
    };
    let owner = u16::from_be_bytes([input[6], input[7]]);
    if owner >= 256 {
        return Err(Error::Owner);
    }
    let mut incarnation = [0; 8];
    incarnation.copy_from_slice(&input[8..16]);
    let mut serial = [0; 8];
    serial.copy_from_slice(&input[16..24]);
    let header = Header {
        owner: OwnerId(owner),
        incarnation: u64::from_be_bytes(incarnation),
        class,
        unreliable_serial: u64::from_be_bytes(serial),
    };
    header.encoded()?;
    Ok((header, &input[HEADER_BYTES..]))
}
