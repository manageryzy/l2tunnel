//! Exact Python aligned-body transforms, with bounded transactional contexts.
//!
//! This module does not assign channel serials, fragment, reorder, deduplicate or
//! deliver short frames early. The caller must supply authenticated ordered bodies
//! from one peer/channel/direction/epoch and negotiate drained resets.

use crate::tcp_header::{self, CONTEXT_BYTES, HeaderDecoder, HeaderEncoder, HeaderProfile};
use std::fmt;

const ECHO_DELTAS: [u32; 16] = [
    0, 1, 17, 18, 19, 20, 36, 37, 38, 55, 56, 74, 75, 92, 93, 111,
];

/// Bounded body format settings; flags control encoding, while decoding accepts
/// every supported kind, as does the Python receiver.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Config {
    /// Maximum complete native frame, in 1..=65535.
    pub max_frame_bytes: usize,
    /// Complete coding symbol size including the future three-byte channel prefix.
    pub symbol_bytes: usize,
    /// Omit an unchanged explicit payload length when the body fits one symbol.
    pub elide_payload_length: bool,
    /// Predict contiguous IPID/sequence and unchanged ACK when eligible.
    pub predictive: bool,
    /// Use the Python fixed timestamp pair dictionary; requires prediction.
    pub timestamp_pair_dictionary: bool,
    /// Force complete frames up to this length into kind 2; zero disables it.
    pub independent_short_frame_bytes: usize,
}
impl Config {
    fn validate(self) -> Result<Self, Error> {
        if !(1..=65_535).contains(&self.max_frame_bytes)
            || !(9..=65_535).contains(&self.symbol_bytes)
            || (self.timestamp_pair_dictionary && !self.predictive)
            || self.independent_short_frame_bytes > self.symbol_bytes - 6
        {
            return Err(Error::Configuration);
        }
        Ok(self)
    }
    /// Capacity available after the enclosing three-byte channel/serial prefix.
    pub fn body_capacity(self) -> Result<usize, Error> {
        Ok(self.validate()?.symbol_bytes - 3)
    }
}
/// Exact complete record kind, independent of the selected encoding flags.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BodyKind {
    /// Fixed timestamp dynamic header (kind 1).
    Timestamp,
    /// Complete unmodified frame (kind 2).
    Raw,
    /// Explicit payload length and delta mask (kind 3).
    Delta,
    /// Implicit payload length and explicit delta mask (kind 6).
    Elided,
    /// Implicit payload length and predicted IPID/sequence/ACK (low bits 7).
    Predictive,
    /// Fixed timestamp delta pair (low bits 5).
    TimestampPair,
}
/// Nonoverlapping ranges of meaningful records in the caller's output buffer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EncodedBodies {
    /// Context at `0..context_len`, either zero or 69 bytes.
    pub context_len: usize,
    /// Frame body at `context_len..context_len+body_len`.
    pub body_len: usize,
    /// Actual frame-body format, for outer negotiated-policy enforcement.
    pub kind: BodyKind,
}
impl EncodedBodies {
    /// Total meaningful bytes in the caller's buffer, excluding all symbol padding.
    pub fn written(self) -> usize {
        self.context_len + self.body_len
    }
}
/// How the caller presents one complete body.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Padding {
    /// Exactly one body, with no trailing bytes; may be a reassembled explicit record.
    Exact,
    /// Exactly symbol size minus three bytes, with all trailing bytes zero.
    ZeroExtended,
}
/// One context or native frame from a complete body.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Decoded {
    /// Installed a context without delivering a native frame.
    Context {
        /// Meaningful input bytes excluding padding.
        consumed: usize,
    },
    /// Reconstructed one native frame.
    Frame {
        /// Meaningful input bytes excluding padding.
        consumed: usize,
        /// Native bytes copied to caller output.
        written: usize,
        /// Actual encoded body format.
        kind: BodyKind,
    },
}
/// Bounded parsing/configuration failures; caller output and context are unchanged.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// Invalid frame/symbol/threshold bounds or dictionary without prediction.
    Configuration,
    /// Underlying header parser or native frame bound failed.
    Header(tcp_header::Error),
    /// Encoded body exceeds the format or implicit-symbol bound.
    RecordTooLarge,
    /// Exact input has trailing bytes, or padding is nonzero/wrong-sized.
    Padding,
    /// Unknown body kind or invalid implicit payload context.
    InvalidRecord,
    /// Caller output is too small for the complete result.
    OutputTooSmall {
        /// Required capacity.
        needed: usize,
    },
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Configuration => f.write_str("invalid aligned body configuration"),
            Self::Header(error) => write!(f, "aligned header: {error}"),
            Self::RecordTooLarge => f.write_str("aligned record exceeds its bound"),
            Self::Padding => f.write_str("invalid aligned body padding"),
            Self::InvalidRecord => f.write_str("invalid aligned body record"),
            Self::OutputTooSmall { needed } => write!(f, "aligned output needs {needed} bytes"),
        }
    }
}
impl std::error::Error for Error {}
impl From<tcp_header::Error> for Error {
    fn from(value: tcp_header::Error) -> Self {
        Self::Header(value)
    }
}

/// One body encoder and fixed bounded staging allocation, with transactional context.
pub struct Encoder {
    config: Config,
    header: HeaderEncoder,
    scratch: Vec<u8>,
}
impl Encoder {
    /// Validate bounds and allocate at most maximum native bytes plus 29 scratch bytes.
    pub fn new(config: Config) -> Result<Self, Error> {
        let config = config.validate()?;
        let header = HeaderEncoder::new(HeaderProfile::TcpDelta, config.max_frame_bytes)?;
        let scratch = vec![0; header.max_encoded_len()];
        Ok(Self {
            config,
            header,
            scratch,
        })
    }
    /// Copy fixed context only; staging retains its own bounded scratch allocation.
    pub(crate) fn copy_context_from(&mut self, other: &Self) {
        self.header = other.header.clone();
    }
    /// Sufficient allocation for context plus body, never including symbol padding.
    pub fn max_encoded_len(&self) -> usize {
        self.scratch.len()
    }
    /// Whether an eligible header context is available.
    pub fn has_context(&self) -> bool {
        self.header.has_context()
    }
    /// Clear context only at an outer-authorized drained boundary.
    pub fn reset(&mut self) {
        self.header.reset();
    }
    /// Encode context plus one body into disjoint consecutive output ranges.
    /// Any error leaves caller output and prior header context unchanged.
    pub fn encode(&mut self, frame: &[u8], output: &mut [u8]) -> Result<EncodedBodies, Error> {
        self.encode_selected(frame, output, false)
    }
    /// Encode an explicitly selected raw native packet as kind 2, preserving context.
    /// Raw length plus three bytes must fit the u16 body limit; failure is atomic.
    pub fn encode_raw(&mut self, frame: &[u8], output: &mut [u8]) -> Result<EncodedBodies, Error> {
        self.encode_selected(frame, output, true)
    }
    fn encode_selected(
        &mut self,
        frame: &[u8],
        output: &mut [u8],
        raw: bool,
    ) -> Result<EncodedBodies, Error> {
        if frame.len() > self.config.max_frame_bytes {
            return Err(tcp_header::Error::FrameTooLarge.into());
        }
        let short = raw
            || (self.config.independent_short_frame_bytes != 0
                && frame.len() <= self.config.independent_short_frame_bytes);
        let mut staged = self.header.clone();
        let written = if short {
            self.scratch[0] = 2;
            self.scratch[1..3].copy_from_slice(&(frame.len() as u16).to_be_bytes());
            self.scratch[3..3 + frame.len()].copy_from_slice(frame);
            frame.len() + 3
        } else {
            staged.encode(frame, &mut self.scratch)?
        };
        let context_len = if self.scratch[0] == 0 { 69 } else { 0 };
        let mut body_len = written - context_len;
        if body_len > 65_535 {
            return Err(Error::RecordTooLarge);
        }
        let previous = self.header.context();
        let body_capacity = self.config.symbol_bytes - 3;
        if self.config.predictive
            && context_len == 0
            && self.scratch[0] == 3
            && let Some(context) = previous
            && frame.len() >= CONTEXT_BYTES
            && frame.len() - CONTEXT_BYTES == payload_length(context)?
            && word16(frame, 18) == word16(context, 18).wrapping_add(1)
            && word32(frame, 38)
                == word32(context, 38).wrapping_add((frame.len() - CONTEXT_BYTES) as u32)
            && frame[42..46] == context[42..46]
        {
            let payload = frame.len() - CONTEXT_BYTES;
            let skip = 5 + if payload == 0 {
                0
            } else {
                varint_len(payload as u32)
            };
            let packed_len = 1 + body_len - skip;
            let mask = self.scratch[3];
            if packed_len <= body_capacity {
                let pair = if self.config.timestamp_pair_dictionary && mask & 0x38 == 0 {
                    pair_index(
                        word32(frame, 58).wrapping_sub(word32(context, 58)),
                        word32(frame, 62).wrapping_sub(word32(context, 62)),
                    )
                } else {
                    None
                };
                if let Some(index) = pair {
                    self.scratch[0] = 5 | (index << 3);
                    self.scratch[1..1 + payload].copy_from_slice(&frame[CONTEXT_BYTES..]);
                    body_len = 1 + payload;
                } else {
                    self.scratch.copy_within(skip..body_len, 1);
                    self.scratch[0] = (mask & 0xf8) | 7;
                    body_len = packed_len;
                }
            }
        }
        let length_context = if context_len != 0 {
            staged.context()
        } else {
            previous
        };
        if self.config.elide_payload_length
            && self.scratch[context_len] == 3
            && body_len - 2 <= body_capacity
            && let Some(context) = length_context
            && usize::from(word16(&self.scratch, context_len + 1)) == payload_length(context)?
        {
            self.scratch
                .copy_within(context_len + 3..context_len + body_len, context_len + 1);
            self.scratch[context_len] = 6;
            body_len -= 2;
        }
        let result = EncodedBodies {
            context_len,
            body_len,
            kind: kind(self.scratch[context_len])?,
        };
        require_output(output, result.written())?;
        output[..result.written()].copy_from_slice(&self.scratch[..result.written()]);
        self.header = staged;
        Ok(result)
    }
}

/// One body decoder, with fixed expanded-record and native-output staging buffers.
pub struct Decoder {
    config: Config,
    header: HeaderDecoder,
    expanded: Vec<u8>,
    native: Vec<u8>,
}
impl Decoder {
    /// Validate bounds and allocate at most twice maximum native bytes plus 44 bytes.
    pub fn new(config: Config) -> Result<Self, Error> {
        let config = config.validate()?;
        Ok(Self {
            config,
            header: HeaderDecoder::new(config.max_frame_bytes)?,
            expanded: vec![0; config.max_frame_bytes + 44],
            native: vec![0; config.max_frame_bytes],
        })
    }
    // Both receiver instances use the same validated body configuration. Copy
    // only fixed header state, retaining each decoder's bounded scratch storage.
    pub(crate) fn copy_context_from(&mut self, other: &Self) {
        self.header = other.header.clone();
    }
    /// Whether an eligible header context is available.
    pub fn has_context(&self) -> bool {
        self.header.has_context()
    }
    /// Clear context only at an outer-authorized drained boundary.
    pub fn reset(&mut self) {
        self.header.reset();
    }
    /// Decode one complete body. Padding, output and parsing checks precede commit.
    pub fn decode_body(
        &mut self,
        input: &[u8],
        padding: Padding,
        output: &mut [u8],
    ) -> Result<Decoded, Error> {
        let body_capacity = self.config.symbol_bytes - 3;
        if padding == Padding::ZeroExtended && input.len() != body_capacity {
            return Err(Error::Padding);
        }
        if input.len() > 65_535 {
            return Err(Error::RecordTooLarge);
        }
        let tag = *input.first().ok_or(tcp_header::Error::Truncated)?;
        let implicit = tag == 6 || tag & 7 == 7 || tag & 7 == 5;
        let mut staged = self.header.clone();
        let (decoded, inserted) = if implicit {
            if input.len() > body_capacity {
                return Err(Error::RecordTooLarge);
            }
            let context = self
                .header
                .context()
                .ok_or(tcp_header::Error::MissingContext)?;
            let payload = payload_length(context)?;
            let header_bytes = if tag == 6 { 2 } else { 1 };
            if payload > body_capacity - header_bytes {
                return Err(Error::InvalidRecord);
            }
            self.expanded[0] = 3;
            self.expanded[1..3].copy_from_slice(&(payload as u16).to_be_bytes());
            let mut cursor = 3;
            if tag != 6 {
                let mut mask = (tag & 0xf8) | 1 | if payload == 0 { 0 } else { 2 };
                let pair = if tag & 7 == 5 {
                    Some((
                        18 + u32::from(tag >> 7),
                        ECHO_DELTAS[usize::from((tag >> 3) & 15)],
                    ))
                } else {
                    None
                };
                if let Some((_, echo)) = pair {
                    mask =
                        1 | if payload == 0 { 0 } else { 2 } | 64 | if echo == 0 { 0 } else { 128 };
                }
                self.expanded[cursor] = mask;
                cursor += 1;
                append_varint(&mut self.expanded, &mut cursor, 1);
                if payload != 0 {
                    append_varint(&mut self.expanded, &mut cursor, payload as u32);
                }
                if let Some((timestamp, echo)) = pair {
                    append_varint(&mut self.expanded, &mut cursor, timestamp);
                    if echo != 0 {
                        append_varint(&mut self.expanded, &mut cursor, echo);
                    }
                }
            }
            let inserted = cursor - 1;
            // Only the bounded semantic prefix is needed for parsing. A large
            // zero-extended symbol can be much larger than the configured native
            // frame limit; validate its untouched suffix after decoding.
            let copied = (input.len() - 1).min(self.expanded.len() - cursor);
            let end = cursor + copied;
            self.expanded[cursor..end].copy_from_slice(&input[1..1 + copied]);
            (
                staged.decode_next(&self.expanded[..end], &mut self.native)?,
                inserted,
            )
        } else {
            (staged.decode_next(input, &mut self.native)?, 0)
        };
        let (consumed, written) = match decoded {
            tcp_header::Decoded::Context { consumed } => (consumed, 0),
            tcp_header::Decoded::Frame {
                consumed, written, ..
            } => (consumed, written),
        };
        let consumed = consumed.checked_sub(inserted).ok_or(Error::InvalidRecord)?;
        if consumed > input.len() {
            return Err(Error::InvalidRecord);
        }
        match padding {
            Padding::Exact if consumed != input.len() => return Err(Error::Padding),
            Padding::ZeroExtended if input[consumed..].iter().any(|byte| *byte != 0) => {
                return Err(Error::Padding);
            }
            _ => {}
        }
        require_output(output, written)?;
        let result = if tag == 0 {
            Decoded::Context { consumed }
        } else {
            Decoded::Frame {
                consumed,
                written,
                kind: kind(tag)?,
            }
        };
        output[..written].copy_from_slice(&self.native[..written]);
        self.header = staged;
        Ok(result)
    }
}
fn kind(tag: u8) -> Result<BodyKind, Error> {
    match tag {
        1 => Ok(BodyKind::Timestamp),
        2 => Ok(BodyKind::Raw),
        3 => Ok(BodyKind::Delta),
        6 => Ok(BodyKind::Elided),
        _ if tag & 7 == 7 => Ok(BodyKind::Predictive),
        _ if tag & 7 == 5 => Ok(BodyKind::TimestampPair),
        _ => Err(Error::InvalidRecord),
    }
}
fn word16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_be_bytes([bytes[offset], bytes[offset + 1]])
}
fn word32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_be_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}
fn payload_length(context: &[u8; CONTEXT_BYTES]) -> Result<usize, Error> {
    usize::from(word16(context, 16))
        .checked_sub(52)
        .ok_or(Error::InvalidRecord)
}
fn varint_len(mut value: u32) -> usize {
    let mut len = 1;
    while value >= 128 {
        value >>= 7;
        len += 1;
    }
    len
}
fn append_varint(output: &mut [u8], cursor: &mut usize, mut value: u32) {
    while value >= 128 {
        output[*cursor] = (value as u8 & 127) | 128;
        *cursor += 1;
        value >>= 7;
    }
    output[*cursor] = value as u8;
    *cursor += 1;
}
fn pair_index(timestamp: u32, echo: u32) -> Option<u8> {
    if timestamp != 18 && timestamp != 19 {
        return None;
    }
    ECHO_DELTAS
        .iter()
        .position(|value| *value == echo)
        .map(|index| ((timestamp - 18) * 16) as u8 + index as u8)
}
fn require_output(output: &[u8], needed: usize) -> Result<(), Error> {
    if output.len() < needed {
        Err(Error::OutputTooSmall { needed })
    } else {
        Ok(())
    }
}

#[cfg(test)]
#[path = "aligned_body_tests.rs"]
mod tests;
