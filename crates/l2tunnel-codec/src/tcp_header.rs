//! Legacy Python-compatible L2 and explicitly selected native-IP TCP header records.
//!
//! This inner format has no authentication, epoch or context identifier. Feed it
//! only authenticated, ordered records in one isolated peer/channel/direction/epoch.
//! It cannot detect a valid stale record decoded against an existing wrong context.
//! Existing `FrameCodec` bytes and API are independent and unchanged.

use std::fmt;
mod core;
pub(crate) use core::{Context as IpContext, View as ContextView};

/// Complete Ethernet/IPv4/TCP timestamp context size.
pub const CONTEXT_BYTES: usize = 66;
/// Complete native IPv4-options/TCP-options header bound (IHL60 plus TCP60).
pub const MAX_IP_HEADER_BYTES: usize = 120;
/// Maximum original frame representable by the Python u16 record lengths.
pub const MAX_FRAME_BYTES: usize = 65_535;
#[cfg(test)]
const DYNAMIC_BYTES: usize = 23;
#[cfg(test)]
const DYNAMIC: [(usize, usize); 5] = [(18, 20), (38, 46), (47, 50), (52, 54), (58, 66)];

/// Exact Python encoder profile; unsupported frames always retain their original bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HeaderProfile {
    /// Context plus a fixed 23-byte dynamic header for each eligible frame.
    TcpTimestamp,
    /// Context plus field mask and modular unsigned LEB128 deltas.
    TcpDelta,
}
/// Kind of a decoded native frame record, for later negotiated-policy enforcement.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecordKind {
    /// Fixed dynamic timestamp header record (kind 1).
    Timestamp,
    /// Complete raw frame fallback (kind 2).
    Raw,
    /// Modular dynamic header delta record (legacy3 or native-IP9).
    Delta,
}
/// One successfully consumed complete inner record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Decoded {
    /// Context was installed, without emitting a native frame.
    Context {
        /// Complete input bytes consumed: legacy69, or3 plus native header bytes.
        consumed: usize,
    },
    /// Exactly one native frame was written into the caller's output.
    Frame {
        /// Complete bytes consumed from the start of the supplied input.
        consumed: usize,
        /// Native bytes written; raw empty frames are representable.
        written: usize,
        /// Actual encoded record kind; both profiles can be parsed as in Python.
        kind: RecordKind,
    },
}
/// Explicit bounded parser, configuration or caller-buffer error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// Local maximum must be in 1..=65535.
    Configuration,
    /// A frame exceeds the configured or format maximum.
    FrameTooLarge,
    /// Caller output cannot hold the complete result; state remains unchanged.
    OutputTooSmall {
        /// Exact required capacity for this record/encoding.
        needed: usize,
    },
    /// One complete record is not present; retain input and retry with more bytes.
    Truncated,
    /// Dynamic data arrived without a context, including after reset.
    MissingContext,
    /// Unknown kind or invalid context length/structural/header-checksum fields.
    InvalidRecord,
    /// A delta continuation exceeds the Python five-byte limit.
    DeltaOverflow,
    /// Checked arithmetic exceeded the supported format bound.
    LengthOverflow,
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Configuration => f.write_str("TCP header maximum must be 1..=65535"),
            Self::FrameTooLarge => f.write_str("TCP header frame exceeds bound"),
            Self::OutputTooSmall { needed } => write!(f, "TCP header output needs {needed} bytes"),
            Self::Truncated => f.write_str("truncated TCP header record"),
            Self::MissingContext => f.write_str("TCP header context is missing"),
            Self::InvalidRecord => f.write_str("invalid TCP header record or context"),
            Self::DeltaOverflow => f.write_str("TCP header delta exceeds five bytes"),
            Self::LengthOverflow => f.write_str("TCP header length overflow"),
        }
    }
}
impl std::error::Error for Error {}

/// One bounded encoder context, isolated to a single ordered outer stream.
#[derive(Clone)]
pub struct HeaderEncoder {
    profile: HeaderProfile,
    maximum: usize,
    context: Option<[u8; CONTEXT_BYTES]>,
}
impl HeaderEncoder {
    /// Construct without allocation or I/O; native eligibility is checked per frame.
    pub fn new(profile: HeaderProfile, max_frame_bytes: usize) -> Result<Self, Error> {
        validate_maximum(max_frame_bytes)?;
        Ok(Self {
            profile,
            maximum: max_frame_bytes,
            context: None,
        })
    }
    /// Safe output capacity for every permitted frame, including initial context.
    pub fn max_encoded_len(&self) -> usize {
        self.maximum + 29
    }
    #[cfg(test)]
    pub(crate) fn context(&self) -> Option<&[u8; CONTEXT_BYTES]> {
        self.context.as_ref()
    }
    /// Whether this direction has established an eligible TCP header context.
    pub fn has_context(&self) -> bool {
        self.context.is_some()
    }
    /// Clear context at a caller-authorized, drained epoch/channel boundary.
    pub fn reset(&mut self) {
        self.context = None;
    }
    /// Encode one complete frame; output may contain context plus a frame record.
    /// Capacity/format failure does not change context or emit a partial result.
    pub fn encode(&mut self, frame: &[u8], output: &mut [u8]) -> Result<usize, Error> {
        let previous = self
            .context
            .as_ref()
            .map(|bytes| core::context(bytes, core::Format::Ethernet))
            .transpose()?;
        let result = core::encode(
            self.profile,
            self.maximum,
            core::Format::Ethernet,
            previous,
            frame,
            output,
        )?;
        self.context = result
            .next
            .map(|context| context.bytes().try_into().map_err(|_| Error::InvalidRecord))
            .transpose()?;
        Ok(result.written)
    }
}

/// Incremental record decoder with one fixed context and no retained input buffer.
#[derive(Clone)]
pub struct HeaderDecoder {
    maximum: usize,
    context: Option<[u8; CONTEXT_BYTES]>,
}
impl HeaderDecoder {
    /// Construct a bounded decoder; context records do not require native output space.
    pub fn new(max_frame_bytes: usize) -> Result<Self, Error> {
        validate_maximum(max_frame_bytes)?;
        Ok(Self {
            maximum: max_frame_bytes,
            context: None,
        })
    }
    #[cfg(test)]
    pub(crate) fn context(&self) -> Option<&[u8; CONTEXT_BYTES]> {
        self.context.as_ref()
    }
    /// Whether a context is available for dynamic records in this direction/epoch.
    pub fn has_context(&self) -> bool {
        self.context.is_some()
    }
    /// Clear context after the caller has negotiated/drained the previous epoch.
    pub fn reset(&mut self) {
        self.context = None;
    }
    /// Decode exactly one record from input. Return consumed bytes; leave any suffix to the caller.
    /// An error leaves context unchanged. Both dynamic kinds are accepted as in Python.
    pub fn decode_next(&mut self, input: &[u8], output: &mut [u8]) -> Result<Decoded, Error> {
        let previous = self
            .context
            .as_ref()
            .map(|bytes| core::context(bytes, core::Format::Ethernet))
            .transpose()?;
        let result = core::decode(
            self.maximum,
            core::Format::Ethernet,
            previous,
            input,
            output,
        )?;
        self.context = result
            .next
            .map(|context| context.bytes().try_into().map_err(|_| Error::InvalidRecord))
            .transpose()?;
        Ok(result.event)
    }
}
/// Bounded explicitly selected native IPv4/IPv6 TCP delta encoder.
/// Unsupported or non-regenerable packets remain exact raw records; no L2 prefix is fabricated.
#[derive(Clone)]
pub struct IpHeaderEncoder {
    maximum: usize,
    context: Option<IpContext>,
}
impl IpHeaderEncoder {
    /// Select native-IP context8/delta9 before any packet; no I/O or allocation.
    pub fn new(maximum: usize) -> Result<Self, Error> {
        validate_maximum(maximum)?;
        Ok(Self {
            maximum,
            context: None,
        })
    }
    /// Sufficient complete output capacity, including a new context.
    pub fn max_encoded_len(&self) -> usize {
        self.maximum + 29
    }
    /// Whether one native header context is retained.
    pub fn has_context(&self) -> bool {
        self.context.is_some()
    }
    /// Reset only at an authenticated drained boundary.
    pub fn reset(&mut self) {
        self.context = None;
    }
    pub(crate) fn context_view(&self) -> Option<ContextView<'_>> {
        self.context.as_ref().map(IpContext::view)
    }
    /// Encode atomically using the maintained shared delta/checksum core.
    pub fn encode(&mut self, packet: &[u8], output: &mut [u8]) -> Result<usize, Error> {
        let result = core::encode(
            HeaderProfile::TcpDelta,
            self.maximum,
            core::Format::Ip,
            self.context,
            packet,
            output,
        )?;
        self.context = result.next;
        Ok(result.written)
    }
}
/// Bounded native-IP decoder; legacy context/delta records are refused.
#[derive(Clone)]
pub struct IpHeaderDecoder {
    maximum: usize,
    context: Option<IpContext>,
}
impl IpHeaderDecoder {
    /// Select the additive context8/delta9 format explicitly.
    pub fn new(maximum: usize) -> Result<Self, Error> {
        validate_maximum(maximum)?;
        Ok(Self {
            maximum,
            context: None,
        })
    }
    /// Whether one native header context is retained.
    pub fn has_context(&self) -> bool {
        self.context.is_some()
    }
    /// Reset only at an authenticated drained boundary.
    pub fn reset(&mut self) {
        self.context = None;
    }
    pub(crate) fn context_view(&self) -> Option<ContextView<'_>> {
        self.context.as_ref().map(IpContext::view)
    }
    /// Decode one complete native-IP record without retained input or allocation.
    pub fn decode_next(&mut self, input: &[u8], output: &mut [u8]) -> Result<Decoded, Error> {
        let result = core::decode(self.maximum, core::Format::Ip, self.context, input, output)?;
        self.context = result.next;
        Ok(result.event)
    }
}
impl HeaderEncoder {
    pub(crate) fn context_view(&self) -> Option<ContextView<'_>> {
        self.context
            .as_ref()
            .and_then(|bytes| core::view(bytes, core::Format::Ethernet).ok())
    }
}
impl HeaderDecoder {
    pub(crate) fn context_view(&self) -> Option<ContextView<'_>> {
        self.context
            .as_ref()
            .and_then(|bytes| core::view(bytes, core::Format::Ethernet).ok())
    }
}
fn validate_maximum(maximum: usize) -> Result<(), Error> {
    if !(1..=MAX_FRAME_BYTES).contains(&maximum) {
        Err(Error::Configuration)
    } else {
        Ok(())
    }
}
fn capacity(output: &[u8], needed: usize) -> Result<(), Error> {
    if output.len() < needed {
        Err(Error::OutputTooSmall { needed })
    } else {
        Ok(())
    }
}
fn raw(frame: &[u8], output: &mut [u8]) -> Result<usize, Error> {
    let size = u16::try_from(frame.len()).map_err(|_| Error::FrameTooLarge)?;
    let needed = 3 + frame.len();
    capacity(output, needed)?;
    output[0] = 2;
    output[1..3].copy_from_slice(&size.to_be_bytes());
    output[3..needed].copy_from_slice(frame);
    Ok(needed)
}
#[cfg(test)]
fn dynamic(header: &[u8; CONTEXT_BYTES]) -> [u8; DYNAMIC_BYTES] {
    let mut result = [0; DYNAMIC_BYTES];
    let mut offset = 0;
    for (start, end) in DYNAMIC {
        let length = end - start;
        result[offset..offset + length].copy_from_slice(&header[start..end]);
        offset += length;
    }
    result
}
#[cfg(test)]
fn restore_header(
    context: &[u8; CONTEXT_BYTES],
    values: &[u8; DYNAMIC_BYTES],
    payload: &[u8],
) -> Result<[u8; CONTEXT_BYTES], Error> {
    let context = core::context(context, core::Format::Ethernet)?;
    let widths = [2, 4, 4, 1, 2, 2, 4, 4];
    let mut cursor = 0;
    let fields = std::array::from_fn(|bit| {
        let width = widths[bit];
        let value = values[cursor..cursor + width]
            .iter()
            .fold(0, |n, byte| (n << 8) | u64::from(*byte));
        cursor += width;
        value
    });
    core::restore(&context, &fields, payload)?
        .bytes()
        .try_into()
        .map_err(|_| Error::InvalidRecord)
}
// Internet checksum, not a cryptographic authenticator. Fold each word so no
// unchecked accumulator growth depends on caller packet length.
fn checksum(parts: &[&[u8]]) -> u16 {
    let mut sum = 0u32;
    let mut high = None;
    for part in parts {
        for byte in *part {
            if let Some(previous) = high.take() {
                sum += u32::from(u16::from_be_bytes([previous, *byte]));
                sum = (sum & 65535) + (sum >> 16);
            } else {
                high = Some(*byte);
            }
        }
    }
    if let Some(previous) = high {
        sum += u32::from(previous) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 65535) + (sum >> 16);
    }
    !(sum as u16)
}

#[cfg(test)]
#[path = "tcp_header_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "tcp_header/ip_tests.rs"]
mod ip_tests;
