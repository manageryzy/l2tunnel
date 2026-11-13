//! Bounded outer appearance codecs around opaque, independently protected records.
//!
//! These formats are not QUIC transport, a media codec or a WebRTC implementation.
//! They provide no authentication, replay checking, packet-number ownership, clock,
//! congestion control or I/O. The caller must authenticate the selected profile and
//! verify the returned protected bytes before granting any session authority.
#![no_std]
#![forbid(unsafe_code)]

use core::fmt;

/// Largest complete encoded UDP payload accepted by this codec.
pub const MAX_PACKET_BYTES: usize = 65_507;
/// Fixed QUIC-like short-header overhead, including a four-byte packet number.
pub const QUIC_ESTABLISHED_OVERHEAD: usize = 13;
/// RTP header plus the two-byte private protected-body length.
pub const MEDIA_OVERHEAD: usize = 14;

const QUIC_VERSION: u32 = 1;
const QUIC_INITIAL: u8 = 0xc3;
const QUIC_SHORT: u8 = 0x43;
const QUIC_INITIAL_FIXED: usize = 28;
const RTP_VERSION: u8 = 0x80;

/// Explicit appearance choice, independent of the inner data/recovery algorithm.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Appearance {
    /// QUIC-looking long Initial and short established headers, without QUIC crypto.
    QuicLike,
    /// Minimal extension-free RTP layout carrying a private, length-delimited payload.
    MediaLike,
}

/// Outer framing phase; this marker never proves handshake completion.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Phase {
    /// Common inner handshake bytes.
    Handshake,
    /// Common inner session records, including data and authenticated management.
    Established,
}

/// Fixed eight-byte outer connection identifier, not an authentication identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConnectionId(pub [u8; 8]);

/// Expected directional QUIC-like connection identifiers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConnectionIds {
    /// Destination identifier checked on incoming packets and source on Initial output.
    pub local: ConnectionId,
    /// Destination identifier emitted on output and expected source on incoming Initials.
    pub peer: ConnectionId,
}

/// RTP synchronization source, not a trusted endpoint identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Ssrc(pub u32);

/// Fixed RTP direction and payload-type policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MediaConfig {
    /// Synchronization source emitted on output.
    pub local_ssrc: Ssrc,
    /// Synchronization source required on input.
    pub peer_ssrc: Ssrc,
    /// Seven-bit RTP payload type; codec interoperability is not implied.
    pub payload_type: u8,
}

/// Complete outer packet and opaque-body bounds; neither includes IP/UDP headers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Limits {
    /// Maximum complete encoded UDP payload, at most [`MAX_PACKET_BYTES`].
    pub max_packet_bytes: usize,
    /// Maximum nonempty inner protected body.
    pub max_protected_bytes: usize,
}

/// Caller-owned outer packet number, independent of inner cryptographic counters.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PacketNumber(pub u32);

/// Caller-supplied wrapping RTP timestamp; this codec never reads a real clock.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MediaTimestamp(pub u32);

/// Caller-supplied outer fields; no mutable counter or timer is retained here.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PacketMeta {
    /// Explicit outer phase marker.
    pub phase: Phase,
    /// Full four-byte QUIC-like number; media emits only its low sixteen bits.
    pub packet_number: PacketNumber,
    /// Wrapping RTP timestamp; ignored by the QUIC-like layout.
    pub media_timestamp: MediaTimestamp,
}

/// Observed outer sequence field, never a cryptographic replay or nonce identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OuterSequence {
    /// Complete four-byte unprotected QUIC-like packet number.
    Quic(PacketNumber),
    /// RTP's sixteen-bit wrapping sequence field, without inferred high bits.
    Media(u16),
}

/// Borrowed result of structural validation, without cryptographic acceptance.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Decoded<'a> {
    /// Phase declared by the outer framing, not evidence of session state.
    pub phase: Phase,
    /// Exact transmitted outer sequence field.
    pub sequence: OuterSequence,
    /// Supplied RTP timestamp, absent for QUIC-like packets.
    pub media_timestamp: Option<MediaTimestamp>,
    /// Exact opaque body, including all trailing zero bytes.
    pub protected: &'a [u8],
}

/// Checked immutable framing policy, with no state or allocation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Config {
    appearance: Appearance,
    ids: ConnectionIds,
    media: MediaConfig,
    limits: Limits,
}

impl Config {
    /// Validate complete bounds and media payload type before any packet operation.
    ///
    /// QUIC-like bounds must fit the largest configured body in both phases.
    pub fn new(
        appearance: Appearance,
        ids: ConnectionIds,
        media: MediaConfig,
        limits: Limits,
    ) -> Result<Self, Error> {
        if limits.max_protected_bytes == 0
            || limits.max_protected_bytes > usize::from(u16::MAX)
            || limits.max_packet_bytes > MAX_PACKET_BYTES
            || media.payload_type > 127
        {
            return Err(Error::Configuration);
        }
        let value = Self {
            appearance,
            ids,
            media,
            limits,
        };
        if value.encoded_len(Phase::Handshake, limits.max_protected_bytes)?
            > limits.max_packet_bytes
        {
            return Err(Error::Configuration);
        }
        Ok(value)
    }

    /// Selected appearance.
    pub const fn appearance(self) -> Appearance {
        self.appearance
    }

    /// Checked complete-packet and protected-body limits.
    pub const fn limits(self) -> Limits {
        self.limits
    }

    /// Exact outer overhead for a nonempty body of this length.
    pub fn overhead(self, phase: Phase, protected_bytes: usize) -> Result<usize, Error> {
        self.validate_body(protected_bytes)?;
        match (self.appearance, phase) {
            (Appearance::QuicLike, Phase::Handshake) => QUIC_INITIAL_FIXED
                .checked_add(varint_bytes(quic_length(protected_bytes)?)?)
                .ok_or(Error::PacketTooLarge),
            (Appearance::QuicLike, Phase::Established) => Ok(QUIC_ESTABLISHED_OVERHEAD),
            (Appearance::MediaLike, _) => Ok(MEDIA_OVERHEAD),
        }
    }

    /// Encode into caller storage; every error leaves the output unchanged.
    pub fn encode(
        self,
        meta: PacketMeta,
        protected: &[u8],
        output: &mut [u8],
    ) -> Result<usize, Error> {
        self.validate_body(protected.len())?;
        let total = self.encoded_len(meta.phase, protected.len())?;
        if total > self.limits.max_packet_bytes {
            return Err(Error::PacketTooLarge);
        }
        if output.len() < total {
            return Err(Error::OutputTooSmall);
        }
        let offset = match (self.appearance, meta.phase) {
            (Appearance::QuicLike, Phase::Handshake) => {
                let length = quic_length(protected.len())?;
                let width = varint_bytes(length)?;
                output[0] = QUIC_INITIAL;
                output[1..5].copy_from_slice(&QUIC_VERSION.to_be_bytes());
                output[5] = 8;
                output[6..14].copy_from_slice(&self.ids.peer.0);
                output[14] = 8;
                output[15..23].copy_from_slice(&self.ids.local.0);
                output[23] = 0; // Empty token, encoded as a one-byte QUIC varint.
                write_varint(length, width, &mut output[24..24 + width]);
                output[24 + width..28 + width].copy_from_slice(&meta.packet_number.0.to_be_bytes());
                28 + width
            }
            (Appearance::QuicLike, Phase::Established) => {
                output[0] = QUIC_SHORT;
                output[1..9].copy_from_slice(&self.ids.peer.0);
                output[9..13].copy_from_slice(&meta.packet_number.0.to_be_bytes());
                QUIC_ESTABLISHED_OVERHEAD
            }
            (Appearance::MediaLike, phase) => {
                output[0] = RTP_VERSION;
                output[1] =
                    self.media.payload_type | if phase == Phase::Handshake { 0x80 } else { 0 };
                let sequence = (meta.packet_number.0 as u16).to_be_bytes();
                output[2..4].copy_from_slice(&sequence);
                output[4..8].copy_from_slice(&meta.media_timestamp.0.to_be_bytes());
                output[8..12].copy_from_slice(&self.media.local_ssrc.0.to_be_bytes());
                let length = protected.len() as u16;
                output[12..14].copy_from_slice(&length.to_be_bytes());
                MEDIA_OVERHEAD
            }
        };
        output[offset..total].copy_from_slice(protected);
        Ok(total)
    }

    /// Strictly inspect one complete datagram, borrowing the exact opaque body.
    ///
    /// No authentication or replay state is changed. The caller must authenticate
    /// the body and treat these outer fields as untrusted metadata.
    pub fn decode(self, packet: &[u8]) -> Result<Decoded<'_>, Error> {
        if packet.len() > self.limits.max_packet_bytes {
            return Err(Error::PacketTooLarge);
        }
        match self.appearance {
            Appearance::QuicLike => self.decode_quic(packet),
            Appearance::MediaLike => self.decode_media(packet),
        }
    }

    fn validate_body(self, length: usize) -> Result<(), Error> {
        if length == 0 {
            Err(Error::EmptyPayload)
        } else if length > self.limits.max_protected_bytes {
            Err(Error::PayloadTooLarge)
        } else {
            Ok(())
        }
    }

    fn encoded_len(self, phase: Phase, protected_bytes: usize) -> Result<usize, Error> {
        protected_bytes
            .checked_add(self.overhead(phase, protected_bytes)?)
            .ok_or(Error::PacketTooLarge)
    }

    fn decode_quic(self, packet: &[u8]) -> Result<Decoded<'_>, Error> {
        let first = *packet.first().ok_or(Error::Truncated)?;
        let (phase, offset, number) = match first {
            QUIC_INITIAL => {
                let fixed = packet.get(..24).ok_or(Error::Truncated)?;
                if fixed[1..5] != QUIC_VERSION.to_be_bytes()
                    || fixed[5] != 8
                    || fixed[14] != 8
                    || fixed[23] != 0
                {
                    return Err(Error::Malformed);
                }
                if fixed[6..14] != self.ids.local.0 || fixed[15..23] != self.ids.peer.0 {
                    return Err(Error::IdentifierMismatch);
                }
                let (length, width) = read_varint(packet.get(24..).ok_or(Error::Truncated)?)?;
                let number_at = 24 + width;
                let expected = number_at.checked_add(length).ok_or(Error::PacketTooLarge)?;
                if expected != packet.len() || length <= 4 {
                    return Err(Error::Malformed);
                }
                let number = read_u32(packet, number_at)?;
                (Phase::Handshake, number_at + 4, number)
            }
            QUIC_SHORT => {
                let fixed = packet
                    .get(..QUIC_ESTABLISHED_OVERHEAD)
                    .ok_or(Error::Truncated)?;
                if fixed[1..9] != self.ids.local.0 {
                    return Err(Error::IdentifierMismatch);
                }
                (
                    Phase::Established,
                    QUIC_ESTABLISHED_OVERHEAD,
                    read_u32(fixed, 9)?,
                )
            }
            _ => return Err(Error::Malformed),
        };
        let protected = packet.get(offset..).ok_or(Error::Truncated)?;
        self.validate_body(protected.len())?;
        Ok(Decoded {
            phase,
            sequence: OuterSequence::Quic(PacketNumber(number)),
            media_timestamp: None,
            protected,
        })
    }

    fn decode_media(self, packet: &[u8]) -> Result<Decoded<'_>, Error> {
        let fixed = packet.get(..MEDIA_OVERHEAD).ok_or(Error::Truncated)?;
        if fixed[0] != RTP_VERSION || fixed[1] & 0x7f != self.media.payload_type {
            return Err(Error::Malformed);
        }
        if read_u32(fixed, 8)? != self.media.peer_ssrc.0 {
            return Err(Error::IdentifierMismatch);
        }
        let length = usize::from(u16::from_be_bytes([fixed[12], fixed[13]]));
        let protected = packet.get(MEDIA_OVERHEAD..).ok_or(Error::Truncated)?;
        if length != protected.len() {
            return Err(Error::Malformed);
        }
        self.validate_body(length)?;
        Ok(Decoded {
            phase: if fixed[1] & 0x80 != 0 {
                Phase::Handshake
            } else {
                Phase::Established
            },
            sequence: OuterSequence::Media(u16::from_be_bytes([fixed[2], fixed[3]])),
            media_timestamp: Some(MediaTimestamp(read_u32(fixed, 4)?)),
            protected,
        })
    }
}

fn read_u32(packet: &[u8], offset: usize) -> Result<u32, Error> {
    let end = offset.checked_add(4).ok_or(Error::Malformed)?;
    let bytes = packet.get(offset..end).ok_or(Error::Truncated)?;
    Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn varint_bytes(value: usize) -> Result<usize, Error> {
    match value {
        0..=63 => Ok(1),
        64..=16_383 => Ok(2),
        16_384..=1_073_741_823 => Ok(4),
        _ => Err(Error::PacketTooLarge),
    }
}

fn quic_length(protected_bytes: usize) -> Result<usize, Error> {
    protected_bytes.checked_add(4).ok_or(Error::PacketTooLarge)
}

fn write_varint(value: usize, width: usize, output: &mut [u8]) {
    let bytes = (value as u32).to_be_bytes();
    output.copy_from_slice(&bytes[4 - width..]);
    output[0] |= match width {
        2 => 0x40,
        4 => 0x80,
        _ => 0,
    };
}

fn read_varint(input: &[u8]) -> Result<(usize, usize), Error> {
    let first = *input.first().ok_or(Error::Truncated)?;
    let width = 1_usize << (first >> 6);
    let bytes = input.get(..width).ok_or(Error::Truncated)?;
    if width > 4 {
        return Err(Error::Malformed);
    }
    let mut value = usize::from(first & 0x3f);
    for byte in &bytes[1..] {
        value = value.checked_mul(256).ok_or(Error::Malformed)?;
        value = value
            .checked_add(usize::from(*byte))
            .ok_or(Error::Malformed)?;
    }
    if varint_bytes(value)? != width {
        return Err(Error::Malformed);
    }
    Ok((value, width))
}

/// Explicit configuration, capacity and peer-framing failures with no payload data.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// Inconsistent complete-packet/body limits or invalid media payload type.
    Configuration,
    /// No independently protected body was supplied or received.
    EmptyPayload,
    /// Body exceeds the configured bound.
    PayloadTooLarge,
    /// Complete packet exceeds the configured or supported bound.
    PacketTooLarge,
    /// Caller output cannot hold the complete packet; no output was modified.
    OutputTooSmall,
    /// Packet ends before a required structural field.
    Truncated,
    /// Flags, version, canonical lengths or exact profile layout do not match.
    Malformed,
    /// Expected destination/source connection identifier or peer SSRC differs.
    IdentifierMismatch,
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Configuration => "invalid cover configuration",
            Self::EmptyPayload => "empty protected cover body",
            Self::PayloadTooLarge => "protected cover body exceeds limit",
            Self::PacketTooLarge => "cover packet exceeds limit",
            Self::OutputTooSmall => "cover output buffer too small",
            Self::Truncated => "truncated cover header",
            Self::Malformed => "invalid cover framing",
            Self::IdentifierMismatch => "cover identifier mismatch",
        })
    }
}

impl core::error::Error for Error {}

#[cfg(test)]
extern crate std;

#[cfg(test)]
mod tests;
