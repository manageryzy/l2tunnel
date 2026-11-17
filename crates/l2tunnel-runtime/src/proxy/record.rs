//! Minimal application union on Common's authenticated ordered record port.
//! Session, epoch, direction and replay state belong to Common. The local byte
//! adapter adds one bounded u32 length; it does not repeat those protocol fields.
use std::io;

pub(super) const HEADER_LEN: usize = 1;
pub(super) const FRAME_OVERHEAD: usize = 4 + HEADER_LEN;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Kind {
    Data,
    Control,
}

pub(super) fn encode(kind: Kind, body: &[u8]) -> io::Result<Vec<u8>> {
    let length = body
        .len()
        .checked_add(HEADER_LEN)
        .filter(|length| *length <= u16::MAX as usize + HEADER_LEN)
        .ok_or_else(|| super::invalid("proxy record length"))?;
    let mut result = Vec::new();
    result.try_reserve_exact(length).map_err(io::Error::other)?;
    result.push(match kind {
        Kind::Data => 0,
        Kind::Control => 1,
    });
    result.extend_from_slice(body);
    Ok(result)
}

pub(super) fn decode(record: &[u8], maximum: usize) -> io::Result<(Kind, &[u8])> {
    let (kind, body) = record
        .split_first()
        .ok_or_else(|| super::invalid("proxy empty record"))?;
    if body.len() > maximum.min(u16::MAX as usize) {
        return Err(super::invalid("proxy record length"));
    }
    let kind = match kind {
        0 => Kind::Data,
        1 => Kind::Control,
        _ => return Err(super::invalid("proxy record kind")),
    };
    Ok((kind, body))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_union_rejects_unknown_empty_and_oversized_bodies() -> io::Result<()> {
        for kind in [Kind::Data, Kind::Control] {
            let bytes = encode(kind, b"payload\0")?;
            assert_eq!(bytes.len(), 9);
            assert_eq!(decode(&bytes, 8)?, (kind, b"payload\0".as_slice()));
            assert!(decode(&bytes, 7).is_err());
        }
        assert!(decode(&[], 8).is_err());
        assert!(decode(&[2], 8).is_err());
        assert!(encode(Kind::Data, &vec![0; u16::MAX as usize + 1]).is_err());
        Ok(())
    }
}
