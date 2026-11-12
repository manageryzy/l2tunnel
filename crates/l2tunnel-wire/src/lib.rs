//! Draft inner framing. This codec does not authenticate records or freeze wire v1.
use l2tunnel_core::Epoch;

/// Fixed draft header bytes, before payload and protection overhead.
pub const HEADER_LEN: usize = 44;
/// Accepted draft version.
pub const VERSION: u8 = 1;
/// Maximum inner record payload; PMTU fragmentation is separate.
pub const MAX_PAYLOAD: usize = 65_535;

/// Record purpose inside an authenticated carrier/protected datagram.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Kind {
    /// User frames, including TCP SYN/ACK and measurements.
    Data = 1,
    /// Session lifecycle and configuration.
    Control = 2,
    /// Recovery acknowledgment.
    Feedback = 3,
    /// Coded recovery symbol.
    Repair = 4,
}

/// Header values remain untrusted until the enclosing authenticator is checked.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Header {
    /// Record purpose.
    pub kind: Kind,
    /// Configuration generation.
    pub epoch: Epoch,
    /// Packet counter scoped to session, key epoch, lane, and direction.
    pub packet_number: u64,
    /// Session identity supplied by the future authenticated runtime.
    pub session: [u8; 16],
    /// Carrier lane, distinct from the MUX channel inside payload records.
    pub lane: u16,
}

/// Record validation failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DecodeError {
    /// Truncated record or trailing bytes.
    Length,
    /// Unsupported version.
    Version,
    /// Unknown kind or nonzero reserved bits.
    Reserved,
    /// Payload exceeds the configured bound.
    TooLarge,
}

/// Encode a draft inner record; encryption/authentication is external.
pub fn encode(header: Header, payload: &[u8]) -> Result<Vec<u8>, DecodeError> {
    if payload.len() > MAX_PAYLOAD {
        return Err(DecodeError::TooLarge);
    }
    let mut out = Vec::with_capacity(HEADER_LEN + payload.len());
    out.extend_from_slice(&[VERSION, header.kind as u8, 0, 0]);
    out.extend_from_slice(&header.epoch.0.to_be_bytes());
    out.extend_from_slice(&header.packet_number.to_be_bytes());
    out.extend_from_slice(&header.session);
    out.extend_from_slice(&header.lane.to_be_bytes());
    out.extend_from_slice(&[0, 0]);
    let length = u32::try_from(payload.len()).map_err(|_| DecodeError::TooLarge)?;
    out.extend_from_slice(&length.to_be_bytes());
    out.extend_from_slice(payload);
    Ok(out)
}

/// Decode exactly one record without allocation; no authenticity is established.
pub fn decode(record: &[u8], maximum: usize) -> Result<(Header, &[u8]), DecodeError> {
    if record.len() < HEADER_LEN {
        return Err(DecodeError::Length);
    }
    if record[0] != VERSION {
        return Err(DecodeError::Version);
    }
    if record[2..4] != [0, 0] || record[38..40] != [0, 0] {
        return Err(DecodeError::Reserved);
    }
    let kind = match record[1] {
        1 => Kind::Data,
        2 => Kind::Control,
        3 => Kind::Feedback,
        4 => Kind::Repair,
        _ => return Err(DecodeError::Reserved),
    };
    let length = u32::from_be_bytes(record[40..44].try_into().map_err(|_| DecodeError::Length)?);
    let length = usize::try_from(length).map_err(|_| DecodeError::TooLarge)?;
    if length > maximum.min(MAX_PAYLOAD) {
        return Err(DecodeError::TooLarge);
    }
    if record.len() - HEADER_LEN != length {
        return Err(DecodeError::Length);
    }
    let header = Header {
        kind,
        epoch: Epoch(u64::from_be_bytes(
            record[4..12].try_into().map_err(|_| DecodeError::Length)?,
        )),
        packet_number: u64::from_be_bytes(
            record[12..20].try_into().map_err(|_| DecodeError::Length)?,
        ),
        session: record[20..36].try_into().map_err(|_| DecodeError::Length)?,
        lane: u16::from_be_bytes(record[36..38].try_into().map_err(|_| DecodeError::Length)?),
    };
    Ok((header, &record[HEADER_LEN..]))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn round_trip_and_all_truncations() -> Result<(), DecodeError> {
        let h = Header {
            kind: Kind::Data,
            epoch: Epoch(7),
            packet_number: u64::MAX,
            session: [3; 16],
            lane: 15,
        };
        let bytes = encode(h, b"test frame")?;
        assert_eq!(decode(&bytes, 64)?, (h, b"test frame".as_slice()));
        for end in 0..bytes.len() {
            assert!(decode(&bytes[..end], 64).is_err());
        }
        assert_eq!(decode(&bytes, 2), Err(DecodeError::TooLarge));
        let mut extra = bytes.clone();
        extra.push(0);
        assert_eq!(decode(&extra, 64), Err(DecodeError::Length));
        Ok(())
    }
    #[test]
    fn rejects_unsupported_and_oversize_records() -> Result<(), DecodeError> {
        let h = Header {
            kind: Kind::Data,
            epoch: Epoch(0),
            packet_number: 0,
            session: [0; 16],
            lane: 0,
        };
        let bytes = encode(h, b"x")?;
        for offset in [0, 1, 2, 3, 38, 39] {
            let mut changed = bytes.clone();
            changed[offset] = 255;
            assert!(decode(&changed, MAX_PAYLOAD).is_err());
        }
        assert_eq!(
            encode(h, &vec![0; MAX_PAYLOAD + 1]),
            Err(DecodeError::TooLarge)
        );
        Ok(())
    }
    #[test]
    fn exact_maximum_and_hostile_declared_lengths() -> Result<(), DecodeError> {
        let h = Header {
            kind: Kind::Data,
            epoch: Epoch(0),
            packet_number: 0,
            session: [0; 16],
            lane: 0,
        };
        let bytes = encode(h, &vec![42; MAX_PAYLOAD])?;
        assert_eq!(decode(&bytes, MAX_PAYLOAD)?.1.len(), MAX_PAYLOAD);
        for declared in [0_u32, 1, 65534, 65536, u32::MAX] {
            let mut changed = bytes.clone();
            changed[40..44].copy_from_slice(&declared.to_be_bytes());
            assert!(decode(&changed, MAX_PAYLOAD).is_err());
        }
        Ok(())
    }
}
