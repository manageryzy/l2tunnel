//! Bounded opaque packet protection with maintained cryptographic primitives.
//!
//! This crate performs no handshake, transport, clock or device work. A consumed
//! authenticated split-key handoff establishes [`SessionRoot`]; typed domains,
//! authenticated metadata, replay and adjacent key generations protect records.
//! [`swift_v2`] preserves the existing Swift packet format explicitly.

/// Explicit compact v3 packet protection, with separate negotiated data checks.
pub mod compact;
mod context;
mod keys;
mod record;
mod replay;
pub mod swift_v2;

/// Explicit fresh-DH key lifecycle with continuing packet/replay ownership.
pub mod refresh;

pub use context::{
    ConfigDigest, Direction, Epoch, LaneId, Limits, Metadata, Protection, Purpose, Role,
    SessionBinding, SessionId, SessionRoot,
};
pub use record::{Opened, Receiver, Sealed, Sender};
use std::fmt;

/// Current draft common framing version; Swift compatibility has its own format.
pub const VERSION: u8 = 1;
/// Exact common version/suite/packet-number prefix length, excluding the tag.
pub const COMMON_PREFIX_BYTES: usize = 10;
/// Fixed authenticated replay window in packet numbers.
pub const REPLAY_PACKETS: u64 = 4096;
/// Maximum opaque record body, before packet protection.
pub const MAX_BODY_BYTES: usize = 65_000;
/// Absolute complete protected-packet ceiling, excluding the outer carrier.
pub const MAX_PACKET_BYTES: usize = 65_507;
/// Maximum additional authenticated carrier/header bytes.
pub const MAX_METADATA_BYTES: usize = 256;
/// Maximum packets protected under one key generation.
pub const MAX_PACKETS_PER_KEY: u64 = 1 << 28;
/// Maximum body bytes under one common-format key generation.
pub const MAX_BODY_BYTES_PER_KEY: u64 = 1 << 40;
/// Maximum distinct directional purpose/lane owners derived from one session root.
pub const MAX_DOMAINS: usize = 64;

/// Nonwrapping packet identity; the protection owner assigns sending numbers.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct PacketNumber(pub u64);
/// Ratchet generation determined by the packet number and authenticated interval.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct KeyGeneration(pub u64);

/// Bounded rejection with no secret, provider error or payload bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// A length, byte-use bound or generation interval is invalid.
    InvalidLimits,
    /// The same directional domain already has an owner.
    DomainInUse,
    /// The session's fixed domain-owner limit is exhausted.
    DomainCapacity,
    /// A body or authenticated metadata exceeds its fixed bound.
    TooLarge,
    /// A caller buffer cannot hold the complete result or receive workspace.
    OutputTooSmall,
    /// The format, exact length or compatibility body is invalid.
    Malformed,
    /// Version or protection does not match the authenticated selection.
    ContextMismatch,
    /// The maintained primitive rejected authentication.
    Authentication,
    /// The authenticated packet number was previously accepted or is too old.
    Replay,
    /// The claimed key generation is neither current nor adjacent.
    Generation,
    /// No further unique packet number can be reserved.
    CounterExhausted,
    /// The key's authenticated byte-use budget requires a fresh session/key contract.
    KeyUsageExhausted,
    /// A maintained key derivation or cryptographic operation failed.
    Crypto,
}

impl fmt::Display for Error {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(output, "packet protection error: {self:?}")
    }
}
impl std::error::Error for Error {}

#[cfg(test)]
mod tests;
