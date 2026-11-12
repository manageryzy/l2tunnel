use crate::RecordCodec;
use std::fmt;

/// Fixed bytes preceding each draft complete-frame body.
pub const FRAME_HEADER_BYTES: usize = 16;
/// Hard ceiling for configurable frame size; deployments should use tighter bounds.
pub const MAX_FRAME_BYTES: usize = 16 * 1024 * 1024;
/// Hard ceiling for an unfragmented encoded frame record.
pub const MAX_RECORD_BYTES: usize = MAX_FRAME_BYTES + FRAME_HEADER_BYTES;

/// Negotiated packet-device layer; inner bytes are not parsed by this codec.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FrameLayer {
    /// A complete opaque Ethernet frame from TAP, including unsupported EtherTypes.
    Ethernet,
    /// A complete opaque IP packet from TUN; IP validation belongs to the classifier.
    Ip,
}

impl FrameLayer {
    fn wire(self) -> u8 {
        match self {
            Self::Ethernet => 1,
            Self::Ip => 2,
        }
    }
}

/// Stateless encoding policy; receiving LZ4 requires the optional build feature.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Compression {
    /// Always encode the original packet bytes.
    None,
    /// Try an independent LZ4 block and select it only when strictly shorter.
    Lz4IfSmaller,
}

/// Negotiated layer and local memory limits for complete-frame records.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CodecConfig {
    /// Expected layer on both encode and decode.
    pub layer: FrameLayer,
    /// Maximum original frame length, between one and `MAX_FRAME_BYTES`.
    pub max_frame_bytes: usize,
    /// Encoding compression policy; no dictionary state is retained.
    pub compression: Compression,
}

/// Explicit frame validation/encoding failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CodecError {
    /// Configured frame size is zero or exceeds the hard ceiling.
    InvalidConfig,
    /// A zero-byte user packet cannot be represented.
    EmptyFrame,
    /// Original or stored length exceeds the configured bound.
    FrameTooLarge,
    /// Caller destination cannot hold the complete result.
    OutputTooSmall,
    /// The fixed header is incomplete.
    Truncated,
    /// The record magic is not recognized.
    InvalidMagic,
    /// The record version is not supported.
    UnsupportedVersion,
    /// The device-layer identifier is unknown.
    UnsupportedLayer,
    /// The encoded layer differs from the negotiated layer.
    LayerMismatch,
    /// The body encoding is unknown.
    UnsupportedEncoding,
    /// Reserved bits are nonzero.
    Reserved,
    /// Body length, exact framing or compression-saving invariant is invalid.
    InvalidLength,
    /// The build does not include the LZ4 feature.
    CompressionUnavailable,
    /// LZ4 decoding failed or did not produce the exact original length.
    MalformedCompression,
    /// Checked size arithmetic failed.
    Arithmetic,
}

impl fmt::Display for CodecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "frame codec error: {self:?}")
    }
}

impl std::error::Error for CodecError {}

/// Stateless complete-frame codec with bounded, failure-atomic caller buffers.
pub struct FrameCodec {
    config: CodecConfig,
}

struct ParsedRecord<'a> {
    encoding: u8,
    original_length: usize,
    body: &'a [u8],
}

impl FrameCodec {
    /// Validate local limits without allocating a packet buffer or performing I/O.
    pub fn new(config: CodecConfig) -> Result<Self, CodecError> {
        if !(1..=MAX_FRAME_BYTES).contains(&config.max_frame_bytes) {
            return Err(CodecError::InvalidConfig);
        }
        if config.compression == Compression::Lz4IfSmaller && !cfg!(feature = "lz4") {
            return Err(CodecError::CompressionUnavailable);
        }
        Ok(Self { config })
    }

    /// Maximum encoded length for this codec; compressed expansion is never used.
    pub fn max_encoded_len(&self) -> usize {
        self.config.max_frame_bytes + FRAME_HEADER_BYTES
    }

    /// Encode an opaque frame into a bounded owned record.
    pub fn encode_vec(&self, frame: &[u8]) -> Result<Vec<u8>, CodecError> {
        if frame.is_empty() {
            return Err(CodecError::EmptyFrame);
        }
        if frame.len() > self.config.max_frame_bytes {
            return Err(CodecError::FrameTooLarge);
        }
        let compressed = self.compress(frame);
        let (encoding, body) = match compressed.as_ref() {
            Some(body) if body.len() < frame.len() => (1_u8, body.as_slice()),
            _ => (0_u8, frame),
        };
        let total = FRAME_HEADER_BYTES
            .checked_add(body.len())
            .ok_or(CodecError::Arithmetic)?;
        let mut record = Vec::with_capacity(total);
        record.extend_from_slice(b"LF");
        record.extend_from_slice(&[1, self.config.layer.wire(), encoding, 0, 0, 0]);
        record.extend_from_slice(
            &u32::try_from(frame.len())
                .map_err(|_| CodecError::Arithmetic)?
                .to_be_bytes(),
        );
        record.extend_from_slice(
            &u32::try_from(body.len())
                .map_err(|_| CodecError::Arithmetic)?
                .to_be_bytes(),
        );
        record.extend_from_slice(body);
        Ok(record)
    }

    /// Validate record framing and return its exact original size before allocation.
    /// Compressed body validity is checked by decoding, not by this size preflight.
    pub fn decoded_len(&self, record: &[u8]) -> Result<usize, CodecError> {
        Ok(self.parse(record)?.original_length)
    }

    /// Decode only after validating lengths, returning exactly one original frame.
    pub fn decode_vec(&self, record: &[u8]) -> Result<Vec<u8>, CodecError> {
        let parsed = self.parse(record)?;
        if parsed.encoding == 0 {
            return Ok(parsed.body.to_vec());
        }
        #[cfg(feature = "lz4")]
        {
            let mut output = vec![0; parsed.original_length];
            let written = lz4_flex::block::decompress_into(parsed.body, &mut output)
                .map_err(|_| CodecError::MalformedCompression)?;
            if written != parsed.original_length {
                return Err(CodecError::MalformedCompression);
            }
            Ok(output)
        }
        #[cfg(not(feature = "lz4"))]
        Err(CodecError::CompressionUnavailable)
    }

    fn compress(&self, frame: &[u8]) -> Option<Vec<u8>> {
        #[cfg(feature = "lz4")]
        {
            if self.config.compression == Compression::Lz4IfSmaller {
                return Some(lz4_flex::block::compress(frame));
            }
        }
        #[cfg(not(feature = "lz4"))]
        let _ = frame;
        None
    }

    fn parse<'a>(&self, record: &'a [u8]) -> Result<ParsedRecord<'a>, CodecError> {
        let header = record
            .get(..FRAME_HEADER_BYTES)
            .ok_or(CodecError::Truncated)?;
        if header.get(..2) != Some(b"LF") {
            return Err(CodecError::InvalidMagic);
        }
        if header[2] != 1 {
            return Err(CodecError::UnsupportedVersion);
        }
        if !matches!(header[3], 1 | 2) {
            return Err(CodecError::UnsupportedLayer);
        }
        if header[3] != self.config.layer.wire() {
            return Err(CodecError::LayerMismatch);
        }
        if !matches!(header[4], 0 | 1) {
            return Err(CodecError::UnsupportedEncoding);
        }
        if header[5..8] != [0, 0, 0] {
            return Err(CodecError::Reserved);
        }
        let original_length = read_u32(header, 8)?;
        let stored_length = read_u32(header, 12)?;
        if original_length == 0 || stored_length == 0 {
            return Err(CodecError::InvalidLength);
        }
        if original_length > self.config.max_frame_bytes
            || stored_length > self.config.max_frame_bytes
        {
            return Err(CodecError::FrameTooLarge);
        }
        let body = record
            .get(FRAME_HEADER_BYTES..)
            .ok_or(CodecError::Truncated)?;
        if body.len() != stored_length
            || (header[4] == 0 && original_length != stored_length)
            || (header[4] == 1 && stored_length >= original_length)
        {
            return Err(CodecError::InvalidLength);
        }
        Ok(ParsedRecord {
            encoding: header[4],
            original_length,
            body,
        })
    }
}

impl RecordCodec for FrameCodec {
    type Error = CodecError;

    fn encode(&mut self, frame: &[u8], output: &mut [u8]) -> Result<usize, Self::Error> {
        let record = self.encode_vec(frame)?;
        let destination = output
            .get_mut(..record.len())
            .ok_or(CodecError::OutputTooSmall)?;
        destination.copy_from_slice(&record);
        Ok(record.len())
    }

    fn decode(&mut self, record: &[u8], output: &mut [u8]) -> Result<usize, Self::Error> {
        let length = self.parse(record)?.original_length;
        if output.len() < length {
            return Err(CodecError::OutputTooSmall);
        }
        let frame = self.decode_vec(record)?;
        let destination = output.get_mut(..length).ok_or(CodecError::OutputTooSmall)?;
        destination.copy_from_slice(&frame);
        Ok(length)
    }

    fn reset(&mut self) {}
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<usize, CodecError> {
    let end = offset.checked_add(4).ok_or(CodecError::Arithmetic)?;
    let value: [u8; 4] = bytes
        .get(offset..end)
        .ok_or(CodecError::Truncated)?
        .try_into()
        .map_err(|_| CodecError::Truncated)?;
    usize::try_from(u32::from_be_bytes(value)).map_err(|_| CodecError::Arithmetic)
}

#[cfg(test)]
mod tests;
