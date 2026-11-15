//! OpenVPN UDP outer packets without tls-auth/tls-crypt, plus real control reliability.
//!
//! Outer session/key labels provide routing, not authentication. TLS and protected
//! data remain maintained, independently authenticated inner protocols. No I/O,
//! real clock, platform handles, privileges or packet-data recovery is owned here.

/// Existing selective repeat translated into actual OpenVPN control records.
pub mod control;

/// OpenVPN's eight-byte control session identifier, not an authenticated identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SessionId(pub [u8; 8]);

/// Standard UDP opcodes supported by this explicit no-tls-auth outer profile.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Opcode {
    /// Graceful control-session reset, parsed but not automatically activated.
    SoftReset = 3,
    /// Reliable TLS ciphertext fragment.
    Control = 4,
    /// Explicit control packet-ID acknowledgments.
    Ack = 5,
    /// Data ciphertext with only opcode/key ID in the outer header.
    DataV1 = 6,
    /// Initial key-method-2 reset from the client.
    HardResetClientV2 = 7,
    /// Initial key-method-2 reset from the server.
    HardResetServerV2 = 8,
    /// Data ciphertext with a three-byte peer ID.
    DataV2 = 9,
}
impl Opcode {
    fn parse(value: u8) -> Result<Self, Error> {
        match value {
            3 => Ok(Self::SoftReset),
            4 => Ok(Self::Control),
            5 => Ok(Self::Ack),
            6 => Ok(Self::DataV1),
            7 => Ok(Self::HardResetClientV2),
            8 => Ok(Self::HardResetServerV2),
            9 => Ok(Self::DataV2),
            _ => Err(Error::Opcode),
        }
    }
    fn data(self) -> bool {
        matches!(self, Self::DataV1 | Self::DataV2)
    }
}

/// Structural refusal before output mutation or any authentication decision.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// Unknown opcode for the selected profile.
    Opcode,
    /// Required outer fields are absent.
    Truncated,
    /// Fields, payload presence or conditional session/packet-ID grammar disagree.
    Layout,
    /// A key ID, peer ID, ACK count or complete datagram bound is excessive.
    Bounds,
    /// Caller output cannot hold the complete packet.
    Output,
}
impl std::fmt::Display for Error {
    fn fmt(&self, output: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(output, "OpenVPN outer packet: {self:?}")
    }
}
impl std::error::Error for Error {}

/// Borrowed network-order ACK array, preserving every full 32-bit packet ID.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Acks<'a>(&'a [u8]);
impl Acks<'_> {
    /// Exact ACK count, bounded by the wire's one-byte count.
    pub fn len(&self) -> usize {
        self.0.len() / 4
    }
    /// Whether no remote-session field is present.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
    /// Iterate complete unsigned big-endian packet IDs, without allocation.
    pub fn iter(&self) -> impl Iterator<Item = u32> + '_ {
        self.0
            .chunks_exact(4)
            .map(|bytes| u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }
}

/// Borrowed actual control layout; ACK-only records have no own packet ID.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Control<'a> {
    /// Exact control opcode.
    pub opcode: Opcode,
    /// Three-bit key selector.
    pub key_id: u8,
    /// Sender's original control-session ID.
    pub session: SessionId,
    /// Explicit receipt packet IDs.
    pub acks: Acks<'a>,
    /// Receiver session, required exactly when ACKs are present.
    pub remote: Option<SessionId>,
    /// Sender packet ID, absent for ACK-only packets.
    pub packet_id: Option<u32>,
    /// Exact TLS ciphertext bytes, present only for Control.
    pub payload: &'a [u8],
}

/// One actual standard outer UDP record, without payload authentication authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Packet<'a> {
    /// Reset, ACK or TLS control fragment.
    Control(Control<'a>),
    /// Exact opaque protected data bytes; no extra private length field is added.
    Data {
        /// Three-bit key selector.
        key_id: u8,
        /// Optional 24-bit peer ID for DataV2.
        peer_id: Option<u32>,
        /// Unmodified inner authenticated bytes.
        payload: &'a [u8],
    },
}

fn take<'a>(bytes: &'a [u8], at: &mut usize, length: usize) -> Result<&'a [u8], Error> {
    let end = at.checked_add(length).ok_or(Error::Bounds)?;
    let value = bytes.get(*at..end).ok_or(Error::Truncated)?;
    *at = end;
    Ok(value)
}
fn session(bytes: &[u8], at: &mut usize) -> Result<SessionId, Error> {
    Ok(SessionId(
        take(bytes, at, 8)?
            .try_into()
            .map_err(|_| Error::Truncated)?,
    ))
}

/// Parse one complete UDP packet in the explicit no-tls-auth/tls-crypt profile.
pub fn decode(bytes: &[u8]) -> Result<Packet<'_>, Error> {
    if bytes.len() > 65507 {
        return Err(Error::Bounds);
    }
    let first = *bytes.first().ok_or(Error::Truncated)?;
    let opcode = Opcode::parse(first >> 3)?;
    let key_id = first & 7;
    let mut at = 1;
    if opcode.data() {
        let peer_id = if opcode == Opcode::DataV2 {
            let id = take(bytes, &mut at, 3)?;
            Some(u32::from_be_bytes([0, id[0], id[1], id[2]]))
        } else {
            None
        };
        let payload = bytes.get(at..).ok_or(Error::Truncated)?;
        if payload.is_empty() {
            return Err(Error::Layout);
        }
        return Ok(Packet::Data {
            key_id,
            peer_id,
            payload,
        });
    }
    let local = session(bytes, &mut at)?;
    let count = usize::from(take(bytes, &mut at, 1)?[0]);
    let acks = Acks(take(
        bytes,
        &mut at,
        count.checked_mul(4).ok_or(Error::Bounds)?,
    )?);
    let remote = if count == 0 {
        None
    } else {
        Some(session(bytes, &mut at)?)
    };
    let packet_id = if opcode == Opcode::Ack {
        None
    } else {
        Some(u32::from_be_bytes(
            take(bytes, &mut at, 4)?
                .try_into()
                .map_err(|_| Error::Truncated)?,
        ))
    };
    let payload = bytes.get(at..).ok_or(Error::Truncated)?;
    if (opcode == Opcode::Control) == payload.is_empty() {
        return Err(Error::Layout);
    }
    if opcode == Opcode::Ack && acks.is_empty() {
        return Err(Error::Layout);
    }
    Ok(Packet::Control(Control {
        opcode,
        key_id,
        session: local,
        acks,
        remote,
        packet_id,
        payload,
    }))
}

/// Encode standard control fields; all checks precede the first output write.
#[allow(clippy::too_many_arguments)] // Each conditional standard wire field is explicit.
pub fn encode_control(
    opcode: Opcode,
    key_id: u8,
    local: SessionId,
    acks: &[u32],
    remote: Option<SessionId>,
    packet_id: Option<u32>,
    payload: &[u8],
    output: &mut [u8],
) -> Result<usize, Error> {
    if opcode.data()
        || (opcode == Opcode::Ack) != packet_id.is_none()
        || acks.is_empty() != remote.is_none()
        || (opcode == Opcode::Control) == payload.is_empty()
        || (opcode == Opcode::Ack && acks.is_empty())
    {
        return Err(Error::Layout);
    }
    if key_id > 7 || acks.len() > 255 {
        return Err(Error::Bounds);
    }
    let length = 10usize
        .checked_add(acks.len().checked_mul(4).ok_or(Error::Bounds)?)
        .and_then(|n| n.checked_add(if remote.is_some() { 8 } else { 0 }))
        .and_then(|n| n.checked_add(if packet_id.is_some() { 4 } else { 0 }))
        .and_then(|n| n.checked_add(payload.len()))
        .ok_or(Error::Bounds)?;
    if length > 65507 {
        return Err(Error::Bounds);
    }
    if output.len() < length {
        return Err(Error::Output);
    }
    output[0] = (opcode as u8) << 3 | key_id;
    output[1..9].copy_from_slice(&local.0);
    output[9] = acks.len() as u8;
    let mut at = 10;
    for id in acks {
        output[at..at + 4].copy_from_slice(&id.to_be_bytes());
        at += 4;
    }
    if let Some(remote) = remote {
        output[at..at + 8].copy_from_slice(&remote.0);
        at += 8;
    }
    if let Some(id) = packet_id {
        output[at..at + 4].copy_from_slice(&id.to_be_bytes());
        at += 4;
    }
    output[at..length].copy_from_slice(payload);
    Ok(length)
}

/// Encode DataV1 or DataV2 without changing, trimming or interpreting protected bytes.
pub fn encode_data(
    key_id: u8,
    peer_id: Option<u32>,
    payload: &[u8],
    output: &mut [u8],
) -> Result<usize, Error> {
    if key_id > 7 || peer_id.is_some_and(|id| id > 0xff_ffff) {
        return Err(Error::Bounds);
    }
    if payload.is_empty() {
        return Err(Error::Layout);
    }
    let header = if peer_id.is_some() { 4usize } else { 1 };
    let length = header.checked_add(payload.len()).ok_or(Error::Bounds)?;
    if length > 65507 {
        return Err(Error::Bounds);
    }
    if output.len() < length {
        return Err(Error::Output);
    }
    let opcode = if peer_id.is_some() {
        Opcode::DataV2
    } else {
        Opcode::DataV1
    };
    output[0] = (opcode as u8) << 3 | key_id;
    if let Some(id) = peer_id {
        output[1..4].copy_from_slice(&id.to_be_bytes()[1..]);
    }
    output[header..length].copy_from_slice(payload);
    Ok(length)
}

#[cfg(test)]
mod tests;
