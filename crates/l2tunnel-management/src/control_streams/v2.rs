//! Explicit four-stream version on one authenticated common Control owner.
//!
//! Version, stream set, mapping and all resource limits must be authenticated by
//! setup. No wrapper or Lifecycle parser grants refresh admission or key authority.

use super::{Error, Limits, Stream};
use crate::delivery;

/// Independently selected L2CF four-stream wire version.
pub const VERSION: u8 = 2;
/// Same fixed wrapper geometry as v1, with an explicit version discriminator.
pub const HEADER_BYTES: usize = super::HEADER_BYTES;
/// Exact selected domains in bounded service order.
pub const ALL: [Stream; 4] = [
    Stream::Transaction,
    Stream::Liveness,
    Stream::DataFeedback,
    Stream::Lifecycle,
];

/// One unchanged recovery packet under the explicitly selected four-stream wire.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Frame<'a> {
    /// Explicit logical stream; never inferred from body bytes.
    pub stream: Stream,
    /// Complete unchanged packet belonging to that stream's actual recovery owner.
    pub packet: &'a [u8],
}
impl<'a> Frame<'a> {
    /// Encode after all bounds/output checks, leaving failed output unchanged.
    pub fn encode(self, output: &mut [u8], limits: Limits) -> Result<usize, Error> {
        super::Frame {
            stream: self.stream,
            packet: self.packet,
        }
        .encode_version(output, limits, VERSION)
    }
    /// Require exactly v2. A v1 input never upgrades the selected owner.
    pub fn decode(input: &'a [u8], limits: Limits) -> Result<Self, Error> {
        let frame = super::Frame::decode_version(input, limits, VERSION)?;
        Ok(Self {
            stream: frame.stream,
            packet: frame.packet,
        })
    }
}

/// Explicit checked v2 context map. The authenticated version is part of the
/// namespace contract; this scalar alone is not globally unique across versions.
/// Never recreate a live stream or convert an existing session between versions.
pub fn delivery_binding(
    binding: delivery::Binding,
    stream: Stream,
) -> Result<delivery::Binding, Error> {
    if binding.control_epoch == 0 {
        return Err(Error::Context);
    }
    let control_epoch = binding
        .control_epoch
        .checked_mul(4)
        .and_then(|epoch| epoch.checked_add(stream as u64))
        .ok_or(Error::Context)?;
    Ok(delivery::Binding {
        control_epoch,
        ..binding
    })
}

/// Fixed Lifecycle discriminator prefix inside SessionRefreshV1 ProfileControl.
pub const LIFECYCLE_HEADER_BYTES: usize = 8;
/// Explicit body shape; parsing never authenticates its nested material.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum LifecycleKind {
    /// Actual protected route4 request, consumed by the existing Records owner.
    Request = 1,
    /// Actual maintained Noise refresh flight or exact cached copy.
    NoiseFlight = 2,
    /// Actual protected route4 activation, consumed by the existing Records owner.
    Activation = 3,
}
/// Bounded typed Lifecycle bytes, without a lifecycle state machine or authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Lifecycle<'a> {
    /// Exact selected dispatch grammar.
    pub kind: LifecycleKind,
    /// Complete borrowed original material; never plaintext-derived admission.
    pub bytes: &'a [u8],
}
impl<'a> Lifecycle<'a> {
    /// Check the complete typed body before any caller output changes.
    pub fn encoded_len(self, maximum: usize) -> Result<usize, Error> {
        let length = LIFECYCLE_HEADER_BYTES
            .checked_add(self.bytes.len())
            .ok_or(Error::Length)?;
        if self.bytes.is_empty()
            || length > maximum
            || maximum > crate::session_control::MAX_LIFECYCLE_BYTES
        {
            return Err(Error::Length);
        }
        Ok(length)
    }
    /// Encode one exact body; retries retain these same original bytes.
    pub fn encode(self, output: &mut [u8], maximum: usize) -> Result<usize, Error> {
        let length = self.encoded_len(maximum)?;
        let target = output.get_mut(..length).ok_or(Error::Output)?;
        target[..8].copy_from_slice(&[b'L', b'2', b'R', b'L', 1, self.kind as u8, 0, 0]);
        target[8..].copy_from_slice(self.bytes);
        Ok(length)
    }
    /// Parse only the exact typed framing; the selected Records/Noise owner
    /// remains responsible for authentication, phase, pins, transcript and caps.
    pub fn decode(input: &'a [u8], maximum: usize) -> Result<Self, Error> {
        let header = input.get(..8).ok_or(Error::Length)?;
        if &header[..4] != b"L2RL" || header[4] != 1 {
            return Err(Error::Version);
        }
        if header[6..8] != [0, 0] {
            return Err(Error::Reserved);
        }
        let kind = match header[5] {
            1 => LifecycleKind::Request,
            2 => LifecycleKind::NoiseFlight,
            3 => LifecycleKind::Activation,
            _ => return Err(Error::Stream),
        };
        let value = Self {
            kind,
            bytes: &input[8..],
        };
        value.encoded_len(maximum)?;
        Ok(value)
    }
}

#[cfg(test)]
mod tests;
