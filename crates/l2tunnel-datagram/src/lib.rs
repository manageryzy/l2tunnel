//! Bounded authenticated datagrams for an already authenticated session.
//!
//! This library has no UDP bootstrap, socket or device integration. Its prefix
//! layouts are project-specific; it does not implement OpenVPN or QUIC handshakes
//! or endpoint interoperability.
//! Traffic keys use maintained ring HKDF, ChaCha20-Poly1305 or HMAC-SHA256.
use ring::{aead, hkdf, hmac};
use std::convert::Infallible;
use std::fmt;
use zeroize::Zeroizing;

/// Fixed common-header bytes, excluding the custom cover prefix and tag.
pub const HEADER_BYTES: usize = 44;
/// Portable UDP payload ceiling used before all allocation and cryptographic work.
pub const MAX_DATAGRAM_BYTES: usize = 65_507;
/// Fixed authenticated out-of-order acceptance window in packets.
pub const REPLAY_WINDOW_PACKETS: u64 = 128;
/// Conservative maximum permitted packet-use budget per derived key.
pub const MAX_PACKETS_PER_KEY: u64 = 1 << 32;
/// Conservative maximum permitted plaintext-byte budget per derived key.
pub const MAX_PAYLOAD_BYTES_PER_KEY: u64 = 1 << 40;

/// Authenticated TLS-session identity; no secrecy is implied by this identifier.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SessionId(pub [u8; 16]);
/// Physical lane identity within an authenticated session.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LaneId(pub u32);
/// Nonwrapping authenticated key generation; never reuse it with the same exporter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KeyGeneration(pub u32);
/// Monotonic packet counter scoped to one derived sending key.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct PacketNumber(pub u64);

/// Global cryptographic direction, independent of the local endpoint's viewpoint.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Direction {
    /// Client sends and server receives.
    ClientToServer,
    /// Server sends and client receives.
    ServerToClient,
}

impl Direction {
    fn wire(self) -> u8 {
        match self {
            Self::ClientToServer => 1,
            Self::ServerToClient => 2,
        }
    }
}

/// Project-specific UDP prefix layout for authenticated tunnel datagrams.
///
/// These layouts do not implement OpenVPN or QUIC handshakes or interoperability.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CoverProfile {
    /// Four-byte prefix: `0x48` followed by a 24-bit lane-ID hint.
    OpenVpnLike,
    /// Nine-byte prefix: `0x40` followed by an eight-byte session-ID hint.
    QuicLike,
}

impl CoverProfile {
    fn wire(self) -> u8 {
        match self {
            Self::OpenVpnLike => 1,
            Self::QuicLike => 2,
        }
    }

    fn prefix_bytes(self) -> usize {
        match self {
            Self::OpenVpnLike => 4,
            Self::QuicLike => 9,
        }
    }
}

/// Authenticated negotiated protection; no unauthenticated plaintext variant exists.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Protection {
    /// ChaCha20-Poly1305 encryption plus a 16-byte integrity tag.
    ChaCha20Poly1305,
    /// Visible payload authenticated with a distinct HMAC-SHA256 key and full tag.
    HmacSha256,
}

impl Protection {
    fn wire(self) -> u8 {
        match self {
            Self::ChaCha20Poly1305 => 1,
            Self::HmacSha256 => 2,
        }
    }

    fn tag_bytes(self) -> usize {
        match self {
            Self::ChaCha20Poly1305 => 16,
            Self::HmacSha256 => 32,
        }
    }
}

/// Exact context bound into both key derivation and every authenticated header.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KeyContext {
    /// Established authenticated TLS session identity.
    pub session: SessionId,
    /// Global sending direction.
    pub direction: Direction,
    /// Authenticated lane identity.
    pub lane: LaneId,
    /// Authenticated key generation; must not wrap or be reused.
    pub generation: KeyGeneration,
}

/// Fixed local packet/key limits and previously authenticated profile selection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DatagramConfig {
    /// Authenticated context for this directional key.
    pub context: KeyContext,
    /// Project-specific prefix layout; see [`CoverProfile`] for protocol boundaries.
    pub cover: CoverProfile,
    /// Required protection suite; peers cannot select a downgrade by header bits.
    pub protection: Protection,
    /// Complete path packet budget, including configured outer headers.
    pub path_mtu: usize,
    /// Actual IP/UDP/other underlay bytes outside this protected datagram.
    pub outer_overhead_bytes: usize,
    /// Maximum nonzero plaintext record length.
    pub max_payload_bytes: usize,
    /// Maximum accepted/sealed packet count under this key, at most 2^32.
    pub max_packets_per_key: u64,
    /// Maximum plaintext bytes accepted/sealed under this key, at most 2^40.
    pub max_payload_bytes_per_key: u64,
}

impl DatagramConfig {
    /// Exact prefix/common-header/tag overhead, excluding outer IP/UDP headers.
    pub fn wire_overhead(&self) -> usize {
        self.cover.prefix_bytes() + HEADER_BYTES + self.protection.tag_bytes()
    }

    fn validate(self) -> Result<Limits, Error> {
        let budget = self
            .path_mtu
            .checked_sub(self.outer_overhead_bytes)
            .ok_or(Error::InvalidConfig)?
            .min(MAX_DATAGRAM_BYTES);
        let maximum = self
            .max_payload_bytes
            .checked_add(self.wire_overhead())
            .ok_or(Error::InvalidConfig)?;
        if self.max_payload_bytes == 0
            || self.max_payload_bytes > usize::from(u16::MAX)
            || maximum > budget
            || !(1..=MAX_PACKETS_PER_KEY).contains(&self.max_packets_per_key)
            || !(1..=MAX_PAYLOAD_BYTES_PER_KEY).contains(&self.max_payload_bytes_per_key)
            || self.max_payload_bytes as u64 > self.max_payload_bytes_per_key
        {
            return Err(Error::InvalidConfig);
        }
        Ok(Limits {
            header: self.cover.prefix_bytes() + HEADER_BYTES,
            maximum,
        })
    }
}

#[derive(Clone, Copy)]
struct Limits {
    header: usize,
    maximum: usize,
}

/// Explicit packet rejection; no error exposes key or plaintext bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// MTU, payload or per-key limits are zero, inconsistent or excessive.
    InvalidConfig,
    /// Zero-byte user payloads are not represented by this version.
    EmptyPayload,
    /// Payload/datagram exceeds the negotiated local bound.
    PayloadTooLarge,
    /// Caller destination cannot hold the entire result.
    OutputTooSmall,
    /// Header, prefix, version, reserved fields or exact lengths are invalid.
    Malformed,
    /// Session, direction, lane, generation, suite or cover mismatches configuration.
    ContextMismatch,
    /// AEAD/HMAC verification failed.
    Authentication,
    /// Packet has already been accepted or is below the replay window.
    Replay,
    /// Monotonic packet numbering cannot continue without a new key context.
    CounterExhausted,
    /// Packet or plaintext-byte use budget requires a fresh key context.
    KeyUsageExhausted,
    /// A maintained cryptographic API rejected derivation or sealing.
    Crypto,
    /// Checked packet arithmetic failed.
    Arithmetic,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "protected datagram error: {self:?}")
    }
}

impl std::error::Error for Error {}

/// Per-key successful receive or attempted cryptographic send use.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Usage {
    /// Packets charged to this key; replayed/rejected receives are never charged.
    pub packets: u64,
    /// Plaintext bytes charged to this key; encapsulation is accounted separately.
    pub payload_bytes: u64,
}

impl Usage {
    fn next(self, config: DatagramConfig, bytes: usize) -> Result<Self, Error> {
        let packets = self
            .packets
            .checked_add(1)
            .ok_or(Error::KeyUsageExhausted)?;
        let payload_bytes = self
            .payload_bytes
            .checked_add(u64::try_from(bytes).map_err(|_| Error::Arithmetic)?)
            .ok_or(Error::KeyUsageExhausted)?;
        if packets > config.max_packets_per_key || payload_bytes > config.max_payload_bytes_per_key
        {
            return Err(Error::KeyUsageExhausted);
        }
        Ok(Self {
            packets,
            payload_bytes,
        })
    }
}

/// Successful caller-buffer sealing metadata.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SealedPacket {
    /// Nonce-bearing packet number used exactly once by this sealer.
    pub packet: PacketNumber,
    /// Total prefix/header/payload/tag bytes written.
    pub wire_len: usize,
}

/// One owned, fully protected datagram ready for an external UDP adapter.
#[derive(Debug, Eq, PartialEq)]
pub struct SealedDatagram {
    /// Assigned nonce-bearing packet number.
    pub packet: PacketNumber,
    /// Complete custom protected wire packet.
    pub bytes: Vec<u8>,
}

/// Authenticated opening metadata, provisional inside a checked validator.
///
/// Returned success means output, replay and receive usage have committed.
/// A checked validator observes these values before any such commit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OpenedPacket {
    /// Authenticated packet number; newly accepted only on returned success.
    pub packet: PacketNumber,
    /// Authenticated plaintext length; copied to caller storage only on success.
    pub payload_len: usize,
}

/// Packet validation failed before output, replay or receive usage committed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CheckedOpenError<E> {
    /// Existing framing, cryptographic, replay or resource validation failed.
    Datagram(Error),
    /// The caller rejected the authenticated plaintext or enclosing metadata.
    Rejected(E),
}

impl<E> fmt::Display for CheckedOpenError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Datagram(error) => write!(f, "checked datagram: {error}"),
            // The caller's error may contain sensitive validation context. Keep
            // generic formatting safe; typed inspection remains available.
            Self::Rejected(_) => f.write_str("authenticated datagram rejected by caller"),
        }
    }
}

impl<E: std::error::Error + 'static> std::error::Error for CheckedOpenError<E> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Datagram(error) => Some(error),
            Self::Rejected(error) => Some(error),
        }
    }
}

impl<E> From<Error> for CheckedOpenError<E> {
    fn from(error: Error) -> Self {
        Self::Datagram(error)
    }
}

enum TrafficKey {
    Aead(Box<aead::LessSafeKey>),
    Mac(hmac::Key),
}

impl TrafficKey {
    fn new(config: DatagramConfig, exporter: &[u8; 32]) -> Result<Self, Error> {
        let material = derive_key(config, exporter)?;
        match config.protection {
            Protection::ChaCha20Poly1305 => {
                let key = aead::UnboundKey::new(&aead::CHACHA20_POLY1305, &material[..])
                    .map_err(|_| Error::Crypto)?;
                Ok(Self::Aead(Box::new(aead::LessSafeKey::new(key))))
            }
            Protection::HmacSha256 => {
                Ok(Self::Mac(hmac::Key::new(hmac::HMAC_SHA256, &material[..])))
            }
        }
    }

    fn seal(
        &self,
        number: PacketNumber,
        header: Vec<u8>,
        payload: &[u8],
    ) -> Result<Vec<u8>, Error> {
        let header_length = header.len();
        let mut datagram = header;
        datagram.extend_from_slice(payload);
        match self {
            Self::Aead(key) => {
                let (aad, body) = datagram.split_at_mut(header_length);
                let tag = key
                    .seal_in_place_separate_tag(nonce(number), aead::Aad::from(&*aad), body)
                    .map_err(|_| Error::Crypto)?;
                datagram.extend_from_slice(tag.as_ref());
            }
            Self::Mac(key) => {
                let tag = hmac::sign(key, &datagram);
                datagram.extend_from_slice(tag.as_ref());
            }
        }
        Ok(datagram)
    }

    fn open(
        &self,
        number: PacketNumber,
        datagram: &[u8],
        header_length: usize,
        payload_length: usize,
    ) -> Result<Zeroizing<Vec<u8>>, Error> {
        let header = datagram.get(..header_length).ok_or(Error::Malformed)?;
        match self {
            Self::Aead(key) => {
                let mut scratch = Zeroizing::new(
                    datagram
                        .get(header_length..)
                        .ok_or(Error::Malformed)?
                        .to_vec(),
                );
                let opened = key
                    .open_in_place(nonce(number), aead::Aad::from(header), &mut scratch)
                    .map_err(|_| Error::Authentication)?;
                if opened.len() != payload_length {
                    return Err(Error::Malformed);
                }
                scratch.truncate(payload_length);
                Ok(scratch)
            }
            Self::Mac(key) => {
                let tag_offset = header_length
                    .checked_add(payload_length)
                    .ok_or(Error::Arithmetic)?;
                let authenticated = datagram.get(..tag_offset).ok_or(Error::Malformed)?;
                let tag = datagram.get(tag_offset..).ok_or(Error::Malformed)?;
                hmac::verify(key, authenticated, tag).map_err(|_| Error::Authentication)?;
                Ok(Zeroizing::new(
                    datagram
                        .get(header_length..tag_offset)
                        .ok_or(Error::Malformed)?
                        .to_vec(),
                ))
            }
        }
    }
}

/// Unique counter owner for one directional derived sending key.
///
/// This type intentionally has no Clone/Debug/reset. Recreating it with the same
/// exporter/context would reuse nonces; reconnect or use an authenticated fresh
/// generation instead. Ordinary QoS/codec changes must retain this object.
pub struct PacketSealer {
    config: DatagramConfig,
    limits: Limits,
    key: TrafficKey,
    next: Option<PacketNumber>,
    usage: Usage,
}

impl PacketSealer {
    /// Derive a new key and start its one permitted sending counter at zero.
    pub fn new(config: DatagramConfig, exporter_secret: &[u8; 32]) -> Result<Self, Error> {
        let limits = config.validate()?;
        Ok(Self {
            config,
            limits,
            key: TrafficKey::new(config, exporter_secret)?,
            next: Some(PacketNumber(0)),
            usage: Usage::default(),
        })
    }

    /// Seal one bounded payload; local validation failures consume no packet number.
    pub fn seal_vec(&mut self, payload: &[u8]) -> Result<SealedDatagram, Error> {
        self.validate_payload(payload.len())?;
        let number = self.next.ok_or(Error::CounterExhausted)?;
        let usage = self.usage.next(self.config, payload.len())?;
        let header = encode_header(self.config, number, payload.len())?;
        // Reserve the nonce before invoking crypto: even a failed seal cannot reuse it.
        self.next = number.0.checked_add(1).map(PacketNumber);
        self.usage = usage;
        let bytes = self.key.seal(number, header, payload)?;
        Ok(SealedDatagram {
            packet: number,
            bytes,
        })
    }

    /// Seal into caller storage; every failure leaves its bytes unchanged.
    pub fn seal_into(&mut self, payload: &[u8], output: &mut [u8]) -> Result<SealedPacket, Error> {
        let needed = self.validate_payload(payload.len())?;
        if output.len() < needed {
            return Err(Error::OutputTooSmall);
        }
        let sealed = self.seal_vec(payload)?;
        let destination = output
            .get_mut(..sealed.bytes.len())
            .ok_or(Error::OutputTooSmall)?;
        destination.copy_from_slice(&sealed.bytes);
        Ok(SealedPacket {
            packet: sealed.packet,
            wire_len: sealed.bytes.len(),
        })
    }

    /// Maximum configured complete datagram length, within the supplied path budget.
    pub fn max_datagram_bytes(&self) -> usize {
        self.limits.maximum
    }

    /// Copy attempted cryptographic send usage for key-rotation decisions.
    pub fn usage(&self) -> Usage {
        self.usage
    }

    fn validate_payload(&self, length: usize) -> Result<usize, Error> {
        if length == 0 {
            return Err(Error::EmptyPayload);
        }
        if length > self.config.max_payload_bytes {
            return Err(Error::PayloadTooLarge);
        }
        length
            .checked_add(self.config.wire_overhead())
            .ok_or(Error::Arithmetic)
    }
}

#[derive(Clone, Copy, Default)]
struct ReplayWindow {
    highest: Option<PacketNumber>,
    seen: u128,
}

impl ReplayWindow {
    fn propose(self, packet: PacketNumber) -> Result<Self, Error> {
        let Some(highest) = self.highest else {
            return Ok(Self {
                highest: Some(packet),
                seen: 1,
            });
        };
        if packet > highest {
            let distance = packet.0.checked_sub(highest.0).ok_or(Error::Arithmetic)?;
            let seen = if distance >= REPLAY_WINDOW_PACKETS {
                1
            } else {
                (self.seen << distance) | 1
            };
            return Ok(Self {
                highest: Some(packet),
                seen,
            });
        }
        let age = highest.0.checked_sub(packet.0).ok_or(Error::Arithmetic)?;
        if age >= REPLAY_WINDOW_PACKETS {
            return Err(Error::Replay);
        }
        let bit = 1_u128 << age;
        if self.seen & bit != 0 {
            return Err(Error::Replay);
        }
        Ok(Self {
            highest: self.highest,
            seen: self.seen | bit,
        })
    }
}

/// Authenticated opener with a fixed replay bitmap and failure-atomic output.
///
/// Keys and state are private and cannot be reset or cloned through this API.
pub struct PacketOpener {
    config: DatagramConfig,
    limits: Limits,
    key: TrafficKey,
    replay: ReplayWindow,
    usage: Usage,
}

impl PacketOpener {
    /// Derive a receive key from authenticated exporter/context information.
    pub fn new(config: DatagramConfig, exporter_secret: &[u8; 32]) -> Result<Self, Error> {
        let limits = config.validate()?;
        Ok(Self {
            config,
            limits,
            key: TrafficKey::new(config, exporter_secret)?,
            replay: ReplayWindow::default(),
            usage: Usage::default(),
        })
    }

    /// Authenticate and open exactly one unseen bounded datagram.
    ///
    /// Replay proposals, usage and caller output commit only after authentication
    /// and exact format success. Failed authentication never advances the window.
    pub fn open(&mut self, datagram: &[u8], output: &mut [u8]) -> Result<OpenedPacket, Error> {
        match self.open_checked(datagram, output, |_, _| Ok::<(), Infallible>(())) {
            Ok(opened) => Ok(opened),
            Err(CheckedOpenError::Datagram(error)) => Err(error),
            Err(CheckedOpenError::Rejected(never)) => match never {},
        }
    }

    /// Authenticate, validate enclosing metadata, then atomically accept one packet.
    ///
    /// The validator runs exactly once after authentication and bounded local
    /// checks, with provisional metadata and immutable plaintext. It must only
    /// validate: external callback side effects cannot be rolled back here.
    /// Rejection preserves all caller output, replay and receive usage, allowing
    /// the same packet to be retried. Existing zeroizing scratch is discarded on
    /// success, rejection or unwinding; plaintext is never retained by this API.
    /// The callback is not invoked on framing, authentication, replay, output or
    /// key-budget errors. Do not log secrets/plaintext in the caller's error.
    pub fn open_checked<E>(
        &mut self,
        datagram: &[u8],
        output: &mut [u8],
        validate: impl FnOnce(OpenedPacket, &[u8]) -> Result<(), E>,
    ) -> Result<OpenedPacket, CheckedOpenError<E>> {
        let (packet, length) = parse_header(self.config, self.limits, datagram)?;
        if output.len() < length {
            return Err(Error::OutputTooSmall.into());
        }
        let replay = self.replay.propose(packet)?;
        let usage = self.usage.next(self.config, length)?;
        let plaintext = self
            .key
            .open(packet, datagram, self.limits.header, length)?;
        if plaintext.len() != length {
            return Err(Error::Malformed.into());
        }
        let opened = OpenedPacket {
            packet,
            payload_len: length,
        };
        validate(opened, &plaintext).map_err(CheckedOpenError::Rejected)?;
        let destination = output.get_mut(..length).ok_or(Error::OutputTooSmall)?;
        destination.copy_from_slice(&plaintext);
        self.replay = replay;
        self.usage = usage;
        Ok(opened)
    }

    /// Maximum configured complete datagram size before authentication/allocation.
    pub fn max_datagram_bytes(&self) -> usize {
        self.limits.maximum
    }

    /// Copy successful unique authenticated receive usage.
    pub fn usage(&self) -> Usage {
        self.usage
    }

    /// Highest successfully authenticated and delivered packet number, if any.
    pub fn highest_packet(&self) -> Option<PacketNumber> {
        self.replay.highest
    }
}

fn cover_prefix(config: DatagramConfig) -> Vec<u8> {
    match config.cover {
        CoverProfile::OpenVpnLike => {
            let lane = config.context.lane.0.to_be_bytes();
            vec![0x48, lane[1], lane[2], lane[3]]
        }
        CoverProfile::QuicLike => {
            let mut prefix = Vec::with_capacity(9);
            prefix.push(0x40);
            prefix.extend_from_slice(&config.context.session.0[..8]);
            prefix
        }
    }
}

fn encode_header(
    config: DatagramConfig,
    number: PacketNumber,
    length: usize,
) -> Result<Vec<u8>, Error> {
    let mut header = cover_prefix(config);
    header.extend_from_slice(b"LD");
    header.extend_from_slice(&[
        1,
        config.cover.wire(),
        config.protection.wire(),
        config.context.direction.wire(),
        0,
        0,
    ]);
    header.extend_from_slice(&config.context.session.0);
    header.extend_from_slice(&config.context.lane.0.to_be_bytes());
    header.extend_from_slice(&config.context.generation.0.to_be_bytes());
    header.extend_from_slice(&number.0.to_be_bytes());
    header.extend_from_slice(
        &u16::try_from(length)
            .map_err(|_| Error::Arithmetic)?
            .to_be_bytes(),
    );
    header.extend_from_slice(&[0, 0]);
    Ok(header)
}

fn parse_header(
    config: DatagramConfig,
    limits: Limits,
    packet: &[u8],
) -> Result<(PacketNumber, usize), Error> {
    if packet.len() > limits.maximum {
        return Err(Error::PayloadTooLarge);
    }
    let prefix_length = config.cover.prefix_bytes();
    if packet.get(..prefix_length) != Some(cover_prefix(config).as_slice()) {
        return Err(Error::Malformed);
    }
    let header = packet
        .get(prefix_length..limits.header)
        .ok_or(Error::Malformed)?;
    if header.get(..2) != Some(b"LD")
        || header[2] != 1
        || header[6..8] != [0, 0]
        || header[42..44] != [0, 0]
    {
        return Err(Error::Malformed);
    }
    if header[3] != config.cover.wire()
        || header[4] != config.protection.wire()
        || header[5] != config.context.direction.wire()
        || header[8..24] != config.context.session.0
        || u32::from_be_bytes(array(header, 24)?) != config.context.lane.0
        || u32::from_be_bytes(array(header, 28)?) != config.context.generation.0
    {
        return Err(Error::ContextMismatch);
    }
    let number = PacketNumber(u64::from_be_bytes(array(header, 32)?));
    let length = usize::from(u16::from_be_bytes(array(header, 40)?));
    if length == 0 {
        return Err(Error::EmptyPayload);
    }
    if length > config.max_payload_bytes {
        return Err(Error::PayloadTooLarge);
    }
    let expected = length
        .checked_add(config.wire_overhead())
        .ok_or(Error::Arithmetic)?;
    if packet.len() != expected {
        return Err(Error::Malformed);
    }
    Ok((number, length))
}

/// Observed unauthenticated header and body for bounded offline structural audit.
/// This is not `OpenedPacket`: no tag, key, identity, replay or usage check occurs.
/// Under AEAD the borrowed body remains ciphertext, never verified plaintext.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StructuralDatagram<'a> {
    /// Untrusted context, checked only for canonical header consistency.
    pub context: KeyContext,
    /// Untrusted counter; no replay admission is performed.
    pub number: PacketNumber,
    /// Exact declared body (ciphertext for AEAD), excluding the trailing tag.
    pub body: &'a [u8],
    /// Exact unverified tag bytes.
    pub tag: &'a [u8],
}

/// Inspect complete framing without authenticating or mutating a live owner.
/// Expected cover/suite and byte ceilings remain caller policy. Context is read
/// as an observation, then the existing exact parser checks prefix, reserved
/// bytes, context duplication and declared length. Never use this result to
/// authorize runtime ingress or bypass `PacketOpener` authentication/replay.
pub fn inspect_structural(
    cover: CoverProfile,
    protection: Protection,
    max_datagram_bytes: usize,
    max_payload_bytes: usize,
    packet: &[u8],
) -> Result<StructuralDatagram<'_>, Error> {
    if max_datagram_bytes > MAX_DATAGRAM_BYTES || packet.len() > max_datagram_bytes {
        return Err(Error::PayloadTooLarge);
    }
    let header = packet
        .get(cover.prefix_bytes()..cover.prefix_bytes() + HEADER_BYTES)
        .ok_or(Error::Malformed)?;
    let context = KeyContext {
        session: SessionId(array(header, 8)?),
        direction: match header[5] {
            1 => Direction::ClientToServer,
            2 => Direction::ServerToClient,
            _ => return Err(Error::Malformed),
        },
        lane: LaneId(u32::from_be_bytes(array(header, 24)?)),
        generation: KeyGeneration(u32::from_be_bytes(array(header, 28)?)),
    };
    let config = DatagramConfig {
        context,
        cover,
        protection,
        path_mtu: max_datagram_bytes,
        outer_overhead_bytes: 0,
        max_payload_bytes,
        max_packets_per_key: MAX_PACKETS_PER_KEY,
        max_payload_bytes_per_key: MAX_PAYLOAD_BYTES_PER_KEY,
    };
    let limits = config.validate()?;
    let (number, length) = parse_header(config, limits, packet)?;
    let end = limits.header.checked_add(length).ok_or(Error::Arithmetic)?;
    Ok(StructuralDatagram {
        context,
        number,
        body: packet.get(limits.header..end).ok_or(Error::Malformed)?,
        tag: packet.get(end..).ok_or(Error::Malformed)?,
    })
}

fn array<const N: usize>(bytes: &[u8], offset: usize) -> Result<[u8; N], Error> {
    let end = offset.checked_add(N).ok_or(Error::Arithmetic)?;
    bytes
        .get(offset..end)
        .ok_or(Error::Malformed)?
        .try_into()
        .map_err(|_| Error::Malformed)
}

fn nonce(number: PacketNumber) -> aead::Nonce {
    let mut bytes = [0; 12];
    bytes[4..].copy_from_slice(&number.0.to_be_bytes());
    aead::Nonce::assume_unique_for_key(bytes)
}

struct KeyLength;

impl hkdf::KeyType for KeyLength {
    fn len(&self) -> usize {
        32
    }
}

fn derive_key(config: DatagramConfig, exporter: &[u8; 32]) -> Result<Zeroizing<[u8; 32]>, Error> {
    let salt = hkdf::Salt::new(hkdf::HKDF_SHA256, b"l2tunnel/datagram/extract/v1");
    let prk = salt.extract(exporter);
    let mut info = Vec::with_capacity(64);
    info.extend_from_slice(b"l2tunnel/datagram/key/v1\0");
    info.extend_from_slice(&[
        config.protection.wire(),
        config.cover.wire(),
        config.context.direction.wire(),
    ]);
    info.extend_from_slice(&config.context.session.0);
    info.extend_from_slice(&config.context.lane.0.to_be_bytes());
    info.extend_from_slice(&config.context.generation.0.to_be_bytes());
    let info_parts = [info.as_slice()];
    let okm = prk
        .expand(&info_parts, KeyLength)
        .map_err(|_| Error::Crypto)?;
    let mut material = Zeroizing::new([0; 32]);
    okm.fill(&mut material[..]).map_err(|_| Error::Crypto)?;
    Ok(material)
}

#[cfg(test)]
mod tests;
