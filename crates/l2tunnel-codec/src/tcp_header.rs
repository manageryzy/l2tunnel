//! Python-compatible timestamp/delta Ethernet TCP header records.
//!
//! This inner format has no authentication, epoch or context identifier. Feed it
//! only authenticated, ordered records in one isolated peer/channel/direction/epoch.
//! It cannot detect a valid stale record decoded against an existing wrong context.
//! Existing `FrameCodec` bytes and API are independent and unchanged.

use std::fmt;

/// Complete Ethernet/IPv4/TCP timestamp context size.
pub const CONTEXT_BYTES: usize = 66;
/// Maximum original frame representable by the Python u16 record lengths.
pub const MAX_FRAME_BYTES: usize = 65_535;
const DYNAMIC_BYTES: usize = 23;
const DYNAMIC: [(usize, usize); 5] = [(18, 20), (38, 46), (47, 50), (52, 54), (58, 66)];
const DELTA: [(usize, usize); 8] = [
    (18, 20),
    (38, 42),
    (42, 46),
    (47, 48),
    (48, 50),
    (52, 54),
    (58, 62),
    (62, 66),
];

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
    /// Modular dynamic header delta record (kind 3).
    Delta,
}
/// One successfully consumed complete inner record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Decoded {
    /// Context was installed, without emitting a native frame.
    Context {
        /// Complete input bytes consumed, always 69.
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
        if frame.len() > self.maximum {
            return Err(Error::FrameTooLarge);
        }
        if !eligible(frame) {
            return raw(frame, output);
        }
        let header: [u8; CONTEXT_BYTES] = frame[..CONTEXT_BYTES]
            .try_into()
            .map_err(|_| Error::InvalidRecord)?;
        let fields = dynamic(&header);
        let payload = &frame[CONTEXT_BYTES..];
        if restore_header(&header, &fields, payload)? != header {
            return raw(frame, output);
        }
        let context_required = match &self.context {
            None => true,
            Some(context) => restore_header(context, &fields, payload)? != header,
        };
        let mut prefix = [0; 113];
        let mut cursor = 0;
        if context_required {
            prefix[..3].copy_from_slice(&[0, 0, 66]);
            prefix[3..69].copy_from_slice(&header);
            cursor = 69;
        }
        let len = u16::try_from(payload.len()).map_err(|_| Error::LengthOverflow)?;
        prefix[cursor] = match self.profile {
            HeaderProfile::TcpTimestamp => 1,
            HeaderProfile::TcpDelta => 3,
        };
        prefix[cursor + 1..cursor + 3].copy_from_slice(&len.to_be_bytes());
        cursor += 3;
        match self.profile {
            HeaderProfile::TcpTimestamp => {
                prefix[cursor..cursor + DYNAMIC_BYTES].copy_from_slice(&fields);
                cursor += DYNAMIC_BYTES;
            }
            HeaderProfile::TcpDelta => {
                let previous = if context_required {
                    header
                } else {
                    self.context.ok_or(Error::MissingContext)?
                };
                let mask_offset = cursor;
                cursor += 1;
                for (bit, (start, end)) in DELTA.into_iter().enumerate() {
                    let mask = (1_u64 << ((end - start) * 8)) - 1;
                    let mut difference = (number(&header[start..end])
                        .wrapping_sub(number(&previous[start..end])))
                        & mask;
                    if difference == 0 {
                        continue;
                    }
                    prefix[mask_offset] |= 1 << bit;
                    while difference >= 128 {
                        push(&mut prefix, &mut cursor, (difference as u8 & 127) | 128)?;
                        difference >>= 7;
                    }
                    push(&mut prefix, &mut cursor, difference as u8)?;
                }
            }
        }
        let needed = cursor
            .checked_add(payload.len())
            .ok_or(Error::LengthOverflow)?;
        capacity(output, needed)?;
        output[..cursor].copy_from_slice(&prefix[..cursor]);
        output[cursor..needed].copy_from_slice(payload);
        if context_required || self.profile == HeaderProfile::TcpDelta {
            self.context = Some(header);
        }
        Ok(needed)
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
        if input.len() < 3 {
            return Err(Error::Truncated);
        }
        let size = usize::from(u16::from_be_bytes([input[1], input[2]]));
        match input[0] {
            0 => {
                if size != CONTEXT_BYTES {
                    return Err(Error::InvalidRecord);
                }
                let body = input.get(3..69).ok_or(Error::Truncated)?;
                let context: [u8; CONTEXT_BYTES] =
                    body.try_into().map_err(|_| Error::InvalidRecord)?;
                let original_len = usize::from(u16::from_be_bytes([context[16], context[17]])) + 14;
                if !structure(&context)
                    || original_len < CONTEXT_BYTES
                    || original_len > self.maximum
                    || checksum(&[&context[14..34]]) != 0
                {
                    return Err(Error::InvalidRecord);
                }
                self.context = Some(context);
                Ok(Decoded::Context { consumed: 69 })
            }
            2 => {
                if size > self.maximum {
                    return Err(Error::FrameTooLarge);
                }
                let end = 3 + size;
                let body = input.get(3..end).ok_or(Error::Truncated)?;
                capacity(output, size)?;
                output[..size].copy_from_slice(body);
                Ok(Decoded::Frame {
                    consumed: end,
                    written: size,
                    kind: RecordKind::Raw,
                })
            }
            1 | 3 => self.decode_dynamic(input, size, output),
            _ => Err(Error::InvalidRecord),
        }
    }
    fn decode_dynamic(
        &mut self,
        input: &[u8],
        size: usize,
        output: &mut [u8],
    ) -> Result<Decoded, Error> {
        let mut context = self.context.ok_or(Error::MissingContext)?;
        let written = CONTEXT_BYTES
            .checked_add(size)
            .filter(|n| *n <= self.maximum)
            .ok_or(Error::FrameTooLarge)?;
        let mut cursor = 3;
        let fields = if input[0] == 1 {
            let bytes = input
                .get(cursor..cursor + DYNAMIC_BYTES)
                .ok_or(Error::Truncated)?;
            cursor += DYNAMIC_BYTES;
            bytes.try_into().map_err(|_| Error::InvalidRecord)?
        } else {
            let mask = *input.get(cursor).ok_or(Error::Truncated)?;
            cursor += 1;
            for (bit, (start, end)) in DELTA.into_iter().enumerate() {
                if mask & (1 << bit) == 0 {
                    continue;
                }
                let difference = read_varint(input, &mut cursor)?;
                let width = end - start;
                let mask = (1_u64 << (width * 8)) - 1;
                let value = (number(&context[start..end]) + difference) & mask;
                context[start..end].copy_from_slice(&value.to_be_bytes()[8 - width..]);
            }
            dynamic(&context)
        };
        let end = cursor.checked_add(size).ok_or(Error::LengthOverflow)?;
        let payload = input.get(cursor..end).ok_or(Error::Truncated)?;
        capacity(output, written)?;
        let restored = restore_header(&context, &fields, payload)?;
        output[..CONTEXT_BYTES].copy_from_slice(&restored);
        output[CONTEXT_BYTES..written].copy_from_slice(payload);
        if input[0] == 3 {
            self.context = Some(restored);
        }
        Ok(Decoded::Frame {
            consumed: end,
            written,
            kind: if input[0] == 1 {
                RecordKind::Timestamp
            } else {
                RecordKind::Delta
            },
        })
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
fn eligible(frame: &[u8]) -> bool {
    frame.len() >= CONTEXT_BYTES
        && frame.len() <= MAX_FRAME_BYTES
        && structure(frame)
        && usize::from(u16::from_be_bytes([frame[16], frame[17]])) == frame.len() - 14
}
fn structure(header: &[u8]) -> bool {
    header.len() >= CONTEXT_BYTES
        && header[12..15] == [8, 0, 0x45]
        && header[23] == 6
        && header[46] >> 4 == 8
        && header[54..58] == [1, 1, 8, 10]
        && u16::from_be_bytes([header[20], header[21]]) & 0x3fff == 0
}
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
fn number(bytes: &[u8]) -> u64 {
    bytes.iter().fold(0, |n, b| (n << 8) | u64::from(*b))
}
fn push(output: &mut [u8], offset: &mut usize, byte: u8) -> Result<(), Error> {
    *output.get_mut(*offset).ok_or(Error::LengthOverflow)? = byte;
    *offset += 1;
    Ok(())
}
fn read_varint(input: &[u8], cursor: &mut usize) -> Result<u64, Error> {
    let mut value = 0;
    for shift in [0, 7, 14, 21, 28] {
        let byte = *input.get(*cursor).ok_or(Error::Truncated)?;
        *cursor += 1;
        value |= u64::from(byte & 127) << shift;
        if byte < 128 {
            return Ok(value);
        }
    }
    Err(Error::DeltaOverflow)
}
fn restore_header(
    context: &[u8; CONTEXT_BYTES],
    fields: &[u8; DYNAMIC_BYTES],
    payload: &[u8],
) -> Result<[u8; CONTEXT_BYTES], Error> {
    let ip_len = payload
        .len()
        .checked_add(52)
        .and_then(|n| u16::try_from(n).ok())
        .ok_or(Error::LengthOverflow)?;
    let tcp_len = payload
        .len()
        .checked_add(32)
        .and_then(|n| u16::try_from(n).ok())
        .ok_or(Error::LengthOverflow)?;
    let mut header = *context;
    let mut offset = 0;
    for (start, end) in DYNAMIC {
        let length = end - start;
        header[start..end].copy_from_slice(&fields[offset..offset + length]);
        offset += length;
    }
    header[16..18].copy_from_slice(&ip_len.to_be_bytes());
    header[24..26].fill(0);
    header[50..52].fill(0);
    let ip_checksum = checksum(&[&header[14..34]]);
    header[24..26].copy_from_slice(&ip_checksum.to_be_bytes());
    let mut pseudo = [0; 12];
    pseudo[..8].copy_from_slice(&header[26..34]);
    pseudo[9] = 6;
    pseudo[10..].copy_from_slice(&tcp_len.to_be_bytes());
    let tcp_checksum = checksum(&[&pseudo, &header[34..], payload]);
    header[50..52].copy_from_slice(&tcp_checksum.to_be_bytes());
    Ok(header)
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
