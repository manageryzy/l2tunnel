//! Exact Python aligned-body transforms, with bounded transactional contexts.
//!
//! This module does not assign channel serials, fragment, reorder, deduplicate or
//! deliver short frames early. The caller must supply authenticated ordered bodies
//! from one peer/channel/direction/epoch and negotiate drained resets.

use crate::tcp_header::{self, HeaderDecoder, HeaderEncoder, HeaderProfile};
use std::fmt;
mod header;
mod stateless;
pub(crate) use header::DecoderState;
use header::EncoderHeader;
pub use stateless::{LZ4_TAG, lz4_available};

/// Explicit native-IP delta referring to a full context by record backdistance.
pub const FIXED_ANCHOR_TAG: u8 = 11;
/// Maximum record distance from a fixed-anchor body to its context.
pub const MAX_ANCHOR_DISTANCE: u8 = 8;

/// Validate the wrapper and borrow its single existing native-IP delta body.
/// Payload length and delta fields are validated by the corresponding body parser.
pub fn fixed_anchor_parts(body: &[u8]) -> Result<(u8, &[u8]), Error> {
    let [
        FIXED_ANCHOR_TAG,
        distance @ 1..=MAX_ANCHOR_DISTANCE,
        inner @ ..,
    ] = body
    else {
        return Err(Error::InvalidRecord);
    };
    match inner.first() {
        Some(6 | 9) => Ok((*distance, inner)),
        Some(tag) if tag & 7 == 5 || tag & 7 == 7 => Ok((*distance, inner)),
        _ => Err(Error::InvalidRecord),
    }
}

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
/// Explicit native encoding selected by the enclosing authenticated policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Encoding {
    /// Existing protocol-compatible header/context encoding.
    Headers,
    /// Header deltas with periodic full contexts in the existing wire grammar.
    RefreshedHeaders,
    /// Native-IP deltas independently derived from an explicitly named full context.
    FixedAnchorHeaders,
    /// Exact raw packet with no compression or context.
    Raw,
    /// Stateless LZ4 only when its complete body is smaller than raw.
    Lz4,
}

/// Exact complete record kind, independent of the selected encoding flags.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BodyKind {
    /// Fixed timestamp dynamic header (kind 1).
    Timestamp,
    /// Complete unmodified frame (kind 2).
    Raw,
    /// Independent LZ4 block with explicit encoded and original lengths (kind 10).
    Lz4,
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
    /// Original native length used by this successful encoding, before compression.
    pub original_native_bytes: usize,
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
    /// Observe this successful encoding before unit or fragment framing is added.
    pub fn observation(self) -> NativeEncodingObservation {
        NativeEncodingObservation {
            original_native_bytes: self.original_native_bytes,
            context_bytes: self.context_len,
            encoded_body_bytes: self.body_len,
            framing_bytes: 0,
            kind: self.kind,
        }
    }
}
/// One successfully encoded native packet, never a retry or physical receipt.
/// Body bytes include the body's own tag/length syntax. Context is separate.
/// Sender observations add the complete packet's channel/serial and fragment
/// framing, excluding packing containers, recovery, Records and carrier bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativeEncodingObservation {
    /// Exact original native packet length, including meaningful zero bytes.
    pub original_native_bytes: usize,
    /// Separate context records emitted because of this native packet.
    pub context_bytes: usize,
    /// Complete encoded native body, including its internal syntax.
    pub encoded_body_bytes: usize,
    /// Generated unit/fragment framing; zero for the body encoder alone.
    pub framing_bytes: usize,
    /// Actual selected body encoding; LZ4 gain is whole-packet, not header-only.
    pub kind: BodyKind,
}
impl NativeEncodingObservation {
    /// Signed original minus context/body bytes; expansion is negative.
    pub fn codec_net_gain_bytes(self) -> i128 {
        self.original_native_bytes as i128
            - self.context_bytes as i128
            - self.encoded_body_bytes as i128
    }
    /// Signed gain after complete unit/fragment framing, before packing/recovery.
    pub fn net_gain_bytes(self) -> i128 {
        self.codec_net_gain_bytes() - self.framing_bytes as i128
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
    /// The maintained LZ4 provider is disabled in this build.
    CompressionUnavailable,
    /// Compressed input or its exact original-length claim is malformed.
    Compression,
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
            Self::CompressionUnavailable => f.write_str("aligned LZ4 support is unavailable"),
            Self::Compression => f.write_str("invalid aligned LZ4 body"),
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
    header: EncoderHeader,
    scratch: Vec<u8>,
}
#[allow(dead_code)]
struct LegacyEncoder {
    config: Config,
    header: HeaderEncoder,
    scratch: Vec<u8>,
}
impl Encoder {
    pub(crate) const fn legacy_inline_bytes() -> usize {
        std::mem::size_of::<LegacyEncoder>()
    }
}
impl Encoder {
    fn scratch_bytes(config: Config) -> Result<usize, Error> {
        let config = config.validate()?;
        let bytes = config.max_frame_bytes + 29;
        #[cfg(feature = "lz4")]
        let bytes = bytes.max(5 + lz4_flex::block::get_maximum_output_size(config.max_frame_bytes));
        Ok(bytes)
    }
    pub(crate) fn reserved_bytes(config: Config) -> Result<usize, crate::aligned_storage::Error> {
        let bytes = Self::scratch_bytes(config).map_err(|error| {
            crate::aligned_storage::Error::Sender(crate::aligned_sender::Error::Body(error))
        })?;
        crate::aligned_storage::array_bytes::<u8>(bytes)
    }
    pub(crate) fn new_in_mode(
        config: Config,
        allocation: &mut crate::aligned_storage::Allocation,
        ip: bool,
    ) -> Result<Self, crate::aligned_storage::Error> {
        let map = |e| crate::aligned_storage::Error::Sender(crate::aligned_sender::Error::Body(e));
        let config = config.validate().map_err(map)?;
        let header = EncoderHeader::new(config.max_frame_bytes, ip)
            .map_err(Error::Header)
            .map_err(map)?;
        let scratch = allocation.bytes(Self::scratch_bytes(config).map_err(map)?)?;
        Ok(Self {
            config,
            header,
            scratch,
        })
    }
    /// Validate bounds and reserve the larger header or maintained-LZ4 scratch bound.
    pub fn new(config: Config) -> Result<Self, Error> {
        Self::new_mode(config, false)
    }
    /// Explicit native-IP TCP header coding; legacy constructors retain Ethernet bytes.
    pub fn new_ip(config: Config) -> Result<Self, Error> {
        Self::new_mode(config, true)
    }
    fn new_mode(config: Config, ip: bool) -> Result<Self, Error> {
        let config = config.validate()?;
        let header = EncoderHeader::new(config.max_frame_bytes, ip)?;
        let scratch = vec![0; Self::scratch_bytes(config)?];
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
        self.header.max_encoded_len()
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
        self.encode_selected(frame, output, false, None)
    }
    /// Encode an explicitly selected raw native packet as kind 2, preserving context.
    /// Raw length plus three bytes must fit the u16 body limit; failure is atomic.
    pub fn encode_raw(&mut self, frame: &[u8], output: &mut [u8]) -> Result<EncodedBodies, Error> {
        self.encode_selected(frame, output, true, None)
    }
    pub(crate) fn encode_fixed_anchor(
        &mut self,
        frame: &[u8],
        output: &mut [u8],
        distance: u8,
    ) -> Result<EncodedBodies, Error> {
        if !matches!(self.header, EncoderHeader::Ip(_))
            || !(1..=MAX_ANCHOR_DISTANCE).contains(&distance)
        {
            return Err(Error::Configuration);
        }
        self.encode_selected(frame, output, false, Some(distance))
    }
    fn encode_selected(
        &mut self,
        frame: &[u8],
        output: &mut [u8],
        raw: bool,
        fixed_distance: Option<u8>,
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
        let context_len = if matches!(self.scratch[0], 0 | 8) {
            3 + usize::from(word16(&self.scratch, 1))
        } else {
            0
        };
        let mut body_len = written - context_len;
        if body_len > 65_535 {
            return Err(Error::RecordTooLarge);
        }
        let previous = self.header.view();
        let body_capacity =
            self.config.symbol_bytes - 3 - usize::from(fixed_distance.is_some()) * 2;
        if self.config.predictive
            && context_len == 0
            && self.scratch[0] == self.header.delta_tag()
            && let Some(context) = previous
            && let Some(current) = context.packet(frame)
            && frame.len() - current.header_bytes() == context.payload_length()?
            && match (current.ipid(), context.ipid()) {
                (Some(value), Some(old)) => value == old.wrapping_add(1),
                (None, None) => true,
                _ => false,
            }
            && current.sequence()
                == context
                    .sequence()
                    .wrapping_add((frame.len() - current.header_bytes()) as u32)
            && current.ack() == context.ack()
        {
            let payload = frame.len() - current.header_bytes();
            let skip = 4
                + usize::from(current.ipid().is_some())
                + if payload == 0 {
                    0
                } else {
                    varint_len(payload as u32)
                };
            let packed_len = 1 + body_len.checked_sub(skip).ok_or(Error::InvalidRecord)?;
            let mask = self.scratch[3];
            if packed_len <= body_capacity {
                let pair = if self.config.timestamp_pair_dictionary && mask & 0x38 == 0 {
                    current.timestamps().zip(context.timestamps()).and_then(
                        |((timestamp, echo), (old_timestamp, old_echo))| {
                            pair_index(
                                timestamp.wrapping_sub(old_timestamp),
                                echo.wrapping_sub(old_echo),
                            )
                        },
                    )
                } else {
                    None
                };
                if let Some(index) = pair {
                    self.scratch[0] = 5 | (index << 3);
                    self.scratch[1..1 + payload].copy_from_slice(&frame[current.header_bytes()..]);
                    body_len = 1 + payload;
                } else {
                    self.scratch.copy_within(skip..body_len, 1);
                    self.scratch[0] = (mask & 0xf8) | 7;
                    body_len = packed_len;
                }
            }
        }
        let length_context = if context_len != 0 {
            staged.view()
        } else {
            previous
        };
        if self.config.elide_payload_length
            && self.scratch[context_len] == self.header.delta_tag()
            && body_len - 2 <= body_capacity
            && let Some(context) = length_context
            && usize::from(word16(&self.scratch, context_len + 1)) == context.payload_length()?
        {
            self.scratch
                .copy_within(context_len + 3..context_len + body_len, context_len + 1);
            self.scratch[context_len] = 6;
            body_len -= 2;
        }
        let kind = kind(self.scratch[context_len])?;
        let wrapper = fixed_distance.filter(|_| kind != BodyKind::Raw);
        let wrapped_len = body_len + usize::from(wrapper.is_some()) * 2;
        if wrapped_len > usize::from(u16::MAX) {
            return Err(Error::RecordTooLarge);
        }
        let result = EncodedBodies {
            original_native_bytes: frame.len(),
            context_len,
            body_len: wrapped_len,
            kind,
        };
        require_output(output, result.written())?;
        if let Some(distance) = wrapper {
            output[..context_len].copy_from_slice(&self.scratch[..context_len]);
            output[context_len..context_len + 2].copy_from_slice(&[
                FIXED_ANCHOR_TAG,
                if context_len == 0 { distance } else { 1 },
            ]);
            output[context_len + 2..result.written()]
                .copy_from_slice(&self.scratch[context_len..context_len + body_len]);
        } else {
            output[..result.written()].copy_from_slice(&self.scratch[..result.written()]);
        }
        self.header = staged;
        Ok(result)
    }
}

/// One body decoder, with fixed expanded-record and native-output staging buffers.
pub struct Decoder {
    config: Config,
    header: DecoderState,
    expanded: Vec<u8>,
    native: Vec<u8>,
}
#[allow(dead_code)]
struct LegacyDecoder {
    config: Config,
    header: HeaderDecoder,
    expanded: Vec<u8>,
    native: Vec<u8>,
}
impl Decoder {
    pub(crate) const fn legacy_inline_bytes() -> usize {
        std::mem::size_of::<LegacyDecoder>()
    }
}
impl Decoder {
    pub(crate) fn reserved_bytes(config: Config) -> Result<usize, crate::aligned_storage::Error> {
        crate::aligned_storage::sum(&[
            crate::aligned_storage::array_bytes::<u8>(
                config
                    .max_frame_bytes
                    .checked_add(44)
                    .ok_or(crate::aligned_storage::Error::Layout)?,
            )?,
            crate::aligned_storage::array_bytes::<u8>(config.max_frame_bytes)?,
        ])
    }
    pub(crate) fn new_in_mode(
        config: Config,
        allocation: &mut crate::aligned_storage::Allocation,
        ip: bool,
    ) -> Result<Self, crate::aligned_storage::Error> {
        let map =
            |e| crate::aligned_storage::Error::Receiver(crate::aligned_receiver::Error::Body(e));
        let config = config.validate().map_err(map)?;
        Ok(Self {
            config,
            header: DecoderState::new(config.max_frame_bytes, ip)
                .map_err(Error::Header)
                .map_err(map)?,
            expanded: allocation.bytes(config.max_frame_bytes + 44)?,
            native: allocation.bytes(config.max_frame_bytes)?,
        })
    }
    pub(crate) fn checkpoint(&self) -> DecoderState {
        self.header.clone()
    }
    pub(crate) fn restore(&mut self, header: DecoderState) {
        self.header = header;
    }
    /// Validate bounds and allocate at most twice maximum native bytes plus 44 bytes.
    pub fn new(config: Config) -> Result<Self, Error> {
        Self::new_mode(config, false)
    }
    /// Explicit native-IP TCP header coding; legacy constructors retain Ethernet bytes.
    pub fn new_ip(config: Config) -> Result<Self, Error> {
        Self::new_mode(config, true)
    }
    fn new_mode(config: Config, ip: bool) -> Result<Self, Error> {
        let config = config.validate()?;
        Ok(Self {
            config,
            header: DecoderState::new(config.max_frame_bytes, ip)?,
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
        self.decode_inner(input, padding, 0, output)
    }

    /// The caller installs the named full context before decoding this body.
    pub(crate) fn decode_fixed_anchor_body(
        &mut self,
        wrapped: &[u8],
        padding: Padding,
        output: &mut [u8],
    ) -> Result<Decoded, Error> {
        if !matches!(self.header, DecoderState::Ip(_)) {
            return Err(Error::Configuration);
        }
        if wrapped.len() > usize::from(u16::MAX) {
            return Err(Error::RecordTooLarge);
        }
        let (_, inner) = fixed_anchor_parts(wrapped)?;
        match self.decode_inner(inner, padding, 2, output)? {
            Decoded::Frame {
                consumed,
                written,
                kind,
            } => Ok(Decoded::Frame {
                consumed: consumed + 2,
                written,
                kind,
            }),
            Decoded::Context { .. } => Err(Error::InvalidRecord),
        }
    }
    fn decode_inner(
        &mut self,
        input: &[u8],
        padding: Padding,
        prefix_bytes: usize,
        output: &mut [u8],
    ) -> Result<Decoded, Error> {
        let body_capacity = self.config.symbol_bytes - 3;
        if padding == Padding::ZeroExtended && input.len() != body_capacity - prefix_bytes {
            return Err(Error::Padding);
        }
        if input.len() > 65_535 {
            return Err(Error::RecordTooLarge);
        }
        let tag = *input.first().ok_or(tcp_header::Error::Truncated)?;
        if tag == LZ4_TAG {
            return self.decode_lz4(input, padding, output);
        }
        let implicit = tag == 6 || tag & 7 == 7 || tag & 7 == 5;
        let mut staged = self.header.clone();
        let (decoded, inserted) = if implicit {
            if input.len() > body_capacity {
                return Err(Error::RecordTooLarge);
            }
            let context = self
                .header
                .view()
                .ok_or(tcp_header::Error::MissingContext)?;
            let payload = context.payload_length()?;
            let header_bytes = if tag == 6 { 2 } else { 1 };
            if payload > body_capacity - header_bytes {
                return Err(Error::InvalidRecord);
            }
            self.expanded[0] = self.header.delta_tag();
            self.expanded[1..3].copy_from_slice(&(payload as u16).to_be_bytes());
            let mut cursor = 3;
            if tag != 6 {
                let mut mask = (tag & 0xf8) | context.prediction_mask(payload);
                let pair = if tag & 7 == 5 {
                    Some((
                        18 + u32::from(tag >> 7),
                        ECHO_DELTAS[usize::from((tag >> 3) & 15)],
                    ))
                } else {
                    None
                };
                if let Some((_, echo)) = pair {
                    mask = context.prediction_mask(payload) | 64 | if echo == 0 { 0 } else { 128 };
                }
                self.expanded[cursor] = mask;
                cursor += 1;
                if context.ipid().is_some() {
                    append_varint(&mut self.expanded, &mut cursor, 1);
                }
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
        let result = if matches!(tag, 0 | 8) {
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
        LZ4_TAG => Ok(BodyKind::Lz4),
        3 | 9 => Ok(BodyKind::Delta),
        6 => Ok(BodyKind::Elided),
        _ if tag & 7 == 7 => Ok(BodyKind::Predictive),
        _ if tag & 7 == 5 => Ok(BodyKind::TimestampPair),
        _ => Err(Error::InvalidRecord),
    }
}
fn word16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_be_bytes([bytes[offset], bytes[offset + 1]])
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
