//! Explicitly negotiated stream framing inside one authenticated Control owner.
//!
//! This additive contract preserves existing recovery and L2SC bytes. A parsed
//! wrapper grants no authority, selects no runtime mode and creates no security
//! counter. The embedding session must authenticate the exact complete bytes.

use crate::delivery;
use l2tunnel_recovery::{ACK_PACKET_BYTES, DATA_HEADER_BYTES};
use std::fmt;

/// Fixed additive wrapper outside one unchanged reliable control packet.
pub const HEADER_BYTES: usize = 8;
/// Draft wrapper version, explicitly bound by the authenticated configuration.
pub const VERSION: u8 = 1;

/// Fixed logical service domains sharing one physical lane and security owner.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum Stream {
    /// Generic transactions and explicitly supported profile commands.
    Transaction = 1,
    /// Ping/Pong independent of incomplete transactions and data feedback.
    Liveness = 2,
    /// Actual scoped recovery feedback and native completion receipts.
    DataFeedback = 3,
}

impl Stream {
    /// Every explicitly assigned stream, without a default or fallback.
    pub const ALL: [Self; 3] = [Self::Transaction, Self::Liveness, Self::DataFeedback];

    pub(crate) const fn index(self) -> usize {
        self as usize - 1
    }

    fn decode(value: u8) -> Result<Self, Error> {
        match value {
            1 => Ok(Self::Transaction),
            2 => Ok(Self::Liveness),
            3 => Ok(Self::DataFeedback),
            _ => Err(Error::Stream),
        }
    }
}

/// Bound on the complete inner recovery packet, excluding this wrapper.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Limits {
    /// At least one complete ACK fits; wrapper plus payload is at most 65535 bytes.
    pub max_packet_bytes: usize,
}

impl Limits {
    /// Check bounds before parsing or touching caller output.
    pub fn validate(self) -> Result<(), Error> {
        if !(ACK_PACKET_BYTES..=65_535 - HEADER_BYTES).contains(&self.max_packet_bytes) {
            return Err(Error::Limits);
        }
        Ok(())
    }
}

/// Borrowed wrapper. Exact management authentication remains the caller's duty.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Frame<'a> {
    /// Immutable logical recovery/sequence domain selected by this frame.
    pub stream: Stream,
    /// One unchanged recovery packet; its engine validates the inner grammar.
    pub packet: &'a [u8],
}

impl<'a> Frame<'a> {
    /// Encode atomically after all configured size and output checks succeed.
    pub fn encode(self, output: &mut [u8], limits: Limits) -> Result<usize, Error> {
        limits.validate()?;
        if !(DATA_HEADER_BYTES..=limits.max_packet_bytes).contains(&self.packet.len()) {
            return Err(Error::Length);
        }
        let bytes = HEADER_BYTES
            .checked_add(self.packet.len())
            .ok_or(Error::Length)?;
        let output = output.get_mut(..bytes).ok_or(Error::Output)?;
        output[..4].copy_from_slice(b"L2CF");
        output[4] = VERSION;
        output[5] = self.stream as u8;
        output[6..8].fill(0);
        output[HEADER_BYTES..].copy_from_slice(self.packet);
        Ok(bytes)
    }

    /// Parse a bounded exact wrapper without allocation or granting authority.
    pub fn decode(input: &'a [u8], limits: Limits) -> Result<Self, Error> {
        limits.validate()?;
        let header = input.get(..HEADER_BYTES).ok_or(Error::Length)?;
        let packet = &input[HEADER_BYTES..];
        if !(DATA_HEADER_BYTES..=limits.max_packet_bytes).contains(&packet.len()) {
            return Err(Error::Length);
        }
        if &header[..4] != b"L2CF" || header[4] != VERSION {
            return Err(Error::Version);
        }
        if header[6..8] != [0, 0] {
            return Err(Error::Reserved);
        }
        Ok(Self {
            stream: Stream::decode(header[5])?,
            packet,
        })
    }
}

/// Derive a disjoint fixed ARQ context; never changes the common security owner.
///
/// Both peers bind this mapping, bounds and base epoch in their authenticated
/// configuration. Recreating an active stream with reused source IDs is forbidden.
pub fn delivery_binding(
    binding: delivery::Binding,
    stream: Stream,
) -> Result<delivery::Binding, Error> {
    if binding.control_epoch == 0 {
        return Err(Error::Context);
    }
    let control_epoch = binding
        .control_epoch
        .checked_mul(Stream::ALL.len() as u64)
        .and_then(|epoch| epoch.checked_add(stream as u64))
        .ok_or(Error::Context)?;
    Ok(delivery::Binding {
        control_epoch,
        ..binding
    })
}

/// Strict wrapper or fixed-context configuration failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// Local packet bounds cannot contain this contract.
    Limits,
    /// Input or supplied recovery packet is outside configured bounds.
    Length,
    /// Magic or explicitly negotiated version does not match.
    Version,
    /// Reserved bytes are nonzero.
    Reserved,
    /// No such logical stream is defined by this contract.
    Stream,
    /// Complete caller output cannot fit; it remains unchanged.
    Output,
    /// Fixed recovery context is zero or overflows its disjoint namespace.
    Context,
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "control stream wrapper error: {self:?}")
    }
}

impl std::error::Error for Error {}

/// Stream-local authenticated envelope admission, separate from transaction effects.
pub mod gate;

#[cfg(test)]
mod tests;
