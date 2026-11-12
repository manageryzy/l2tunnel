//! Exact LTPM version-one records; parsing is not evidence of authentication.
//!
//! The caller must separately verify session/configuration, role, allocated flow,
//! replay/freshness and negotiated resource limits before using these values.
use crate::{Scope, Window};
use std::fmt;

/// Fixed header bytes shared by every measurement kind.
pub const HEADER_BYTES: usize = 48;
/// Exact complete Demand record length.
pub const DEMAND_BYTES: usize = 104;
/// Exact complete EchoRequest or EchoReply record length.
pub const ECHO_BYTES: usize = 56;
/// Largest complete record, independent of caller-supplied input length.
pub const MAX_RECORD_BYTES: usize = DEMAND_BYTES;
/// Canonical wire version; no extension/padding is accepted.
pub const VERSION: u8 = 1;

/// Original stream direction, derived from negotiated table roles by the caller.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Direction {
    /// The origination role's application stream toward the accepting side.
    OriginatorToAcceptor = 1,
    /// The accepting side's application stream toward the origination side.
    AcceptorToOriginator = 2,
}
/// Claimed record scope; these fields alone establish no authenticated authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Header {
    /// Nonzero session, epoch and lifetime flow identifier.
    pub scope: Scope,
    /// Original stream described by this observation/request.
    pub direction: Direction,
    /// Nonzero serial; monotonicity and duplicate handling require an owner.
    pub serial: u64,
}
/// Bounded-format producer hints, never an acknowledgment or memory release.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Demand {
    /// Cumulative original bytes/records produced for reliable transport.
    pub produced: Window,
    /// Cumulative peer grant observed by that producer.
    pub observed_grant: Window,
    /// Original unread native receive-ring bytes; table bounds are checked later.
    pub native_unread_bytes: u64,
    /// Original payload bytes of the producer's retained Data record.
    pub pending_data_bytes: u64,
    /// Unread native data exhausted the observed byte grant.
    pub byte_blocked: bool,
    /// Unread native data exhausted the observed record grant.
    pub record_blocked: bool,
}
/// Exact measurement payload without any peer timestamp or target command.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Body {
    /// Producer demand hint under the separately authenticated session.
    Demand(Demand),
    /// Request a matching reply for a locally tracked nonzero nonce.
    EchoRequest {
        /// Nonzero nonce; matching and exhaustion rules require an owner.
        nonce: u64,
    },
    /// Echo the request nonce; this does not itself establish an RTT sample.
    EchoReply {
        /// Original nonzero request nonce.
        nonce: u64,
    },
}
/// Complete structurally representable record, with no retained state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Record {
    /// Claimed original-stream identity and serial.
    pub header: Header,
    /// Exact closed payload family.
    pub body: Body,
}

/// Invalid intrinsic values shared by encoding and decoding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InvalidField {
    /// Session, epoch, flow or serial is zero.
    Identity,
    /// Produced bytes or records exceed the corresponding observed grant.
    CounterOrder,
    /// A blocked flag has no unread native bytes or its grant is not exhausted.
    BlockedFlags,
    /// An echo nonce is zero.
    Nonce,
}
/// Bounded structural parse failure, with no output or state mutation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DecodeError {
    /// Length differs from the exact closed format for the selected kind.
    Length,
    /// The four-byte magic is not LTPM.
    Magic,
    /// Unsupported format version.
    Version,
    /// Unknown measurement kind.
    Kind,
    /// Unknown original-stream direction.
    Direction,
    /// A reserved byte or flag bit is nonzero.
    Reserved,
    /// A decoded intrinsic value is invalid.
    Invalid(InvalidField),
}
/// Rejected encoding; every error leaves the entire output unchanged.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EncodeError {
    /// A caller-constructed intrinsic value is invalid.
    Invalid(InvalidField),
    /// Complete record capacity is unavailable.
    OutputTooSmall {
        /// Exact prefix capacity required by this kind.
        needed: usize,
    },
}
impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "LTPM decode: {self:?}")
    }
}
impl std::error::Error for DecodeError {}
impl fmt::Display for EncodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "LTPM encode: {self:?}")
    }
}
impl std::error::Error for EncodeError {}

/// Parse one exact complete record without allocation or side effects.
/// This does not verify cryptographic identity, allocated flows or replay order.
pub fn decode(bytes: &[u8]) -> Result<Record, DecodeError> {
    if bytes.len() != DEMAND_BYTES && bytes.len() != ECHO_BYTES {
        return Err(DecodeError::Length);
    }
    if bytes[..4] != *b"LTPM" {
        return Err(DecodeError::Magic);
    }
    if bytes[4] != VERSION {
        return Err(DecodeError::Version);
    }
    let expected = match bytes[5] {
        1 => DEMAND_BYTES,
        2 | 3 => ECHO_BYTES,
        _ => return Err(DecodeError::Kind),
    };
    if bytes.len() != expected {
        return Err(DecodeError::Length);
    }
    let direction = match bytes[6] {
        1 => Direction::OriginatorToAcceptor,
        2 => Direction::AcceptorToOriginator,
        _ => return Err(DecodeError::Direction),
    };
    if bytes[7] != 0 {
        return Err(DecodeError::Reserved);
    }
    let mut session = [0; 16];
    session.copy_from_slice(&bytes[8..24]);
    let header = Header {
        scope: Scope {
            session,
            epoch: word(bytes, 24),
            flow: word(bytes, 32),
        },
        direction,
        serial: word(bytes, 40),
    };
    let body = if bytes[5] == 1 {
        if bytes[96] & !3 != 0 || bytes[97..104].iter().any(|b| *b != 0) {
            return Err(DecodeError::Reserved);
        }
        Body::Demand(Demand {
            produced: Window {
                bytes: word(bytes, 48),
                records: word(bytes, 56),
            },
            observed_grant: Window {
                bytes: word(bytes, 64),
                records: word(bytes, 72),
            },
            native_unread_bytes: word(bytes, 80),
            pending_data_bytes: word(bytes, 88),
            byte_blocked: bytes[96] & 1 != 0,
            record_blocked: bytes[96] & 2 != 0,
        })
    } else if bytes[5] == 2 {
        Body::EchoRequest {
            nonce: word(bytes, 48),
        }
    } else {
        Body::EchoReply {
            nonce: word(bytes, 48),
        }
    };
    let record = Record { header, body };
    validate(record).map_err(DecodeError::Invalid)?;
    Ok(record)
}

/// Encode into the exact prefix and leave any trailing capacity unchanged.
/// Intrinsic validation precedes the capacity check; no fallible step follows
/// the first output write. No table, authentication or observation is created.
pub fn encode(record: Record, output: &mut [u8]) -> Result<usize, EncodeError> {
    validate(record).map_err(EncodeError::Invalid)?;
    let (kind, needed) = match record.body {
        Body::Demand(_) => (1, DEMAND_BYTES),
        Body::EchoRequest { .. } => (2, ECHO_BYTES),
        Body::EchoReply { .. } => (3, ECHO_BYTES),
    };
    if output.len() < needed {
        return Err(EncodeError::OutputTooSmall { needed });
    }
    output[..needed].fill(0);
    output[..4].copy_from_slice(b"LTPM");
    output[4] = VERSION;
    output[5] = kind;
    output[6] = record.header.direction as u8;
    output[8..24].copy_from_slice(&record.header.scope.session);
    put(output, 24, record.header.scope.epoch);
    put(output, 32, record.header.scope.flow);
    put(output, 40, record.header.serial);
    match record.body {
        Body::Demand(demand) => {
            put(output, 48, demand.produced.bytes);
            put(output, 56, demand.produced.records);
            put(output, 64, demand.observed_grant.bytes);
            put(output, 72, demand.observed_grant.records);
            put(output, 80, demand.native_unread_bytes);
            put(output, 88, demand.pending_data_bytes);
            output[96] = u8::from(demand.byte_blocked) | (u8::from(demand.record_blocked) << 1);
        }
        Body::EchoRequest { nonce } | Body::EchoReply { nonce } => put(output, 48, nonce),
    }
    Ok(needed)
}

fn validate(record: Record) -> Result<(), InvalidField> {
    let header = record.header;
    if header.scope.session == [0; 16]
        || header.scope.epoch == 0
        || header.scope.flow == 0
        || header.serial == 0
    {
        return Err(InvalidField::Identity);
    }
    match record.body {
        Body::Demand(demand) => {
            if !demand.observed_grant.contains(demand.produced) {
                return Err(InvalidField::CounterOrder);
            }
            if (demand.byte_blocked
                && (demand.native_unread_bytes == 0
                    || demand.produced.bytes != demand.observed_grant.bytes))
                || (demand.record_blocked
                    && (demand.native_unread_bytes == 0
                        || demand.produced.records != demand.observed_grant.records))
            {
                return Err(InvalidField::BlockedFlags);
            }
        }
        Body::EchoRequest { nonce: 0 } | Body::EchoReply { nonce: 0 } => {
            return Err(InvalidField::Nonce);
        }
        _ => {}
    }
    Ok(())
}

// All call sites first establish the closed format's full constant length.
fn word(bytes: &[u8], at: usize) -> u64 {
    let mut value = [0; 8];
    value.copy_from_slice(&bytes[at..at + 8]);
    u64::from_be_bytes(value)
}
fn put(bytes: &mut [u8], at: usize, value: u64) {
    bytes[at..at + 8].copy_from_slice(&value.to_be_bytes());
}

#[cfg(test)]
mod tests;
