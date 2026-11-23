//! DATA v1 plaintext. The selected carrier binds the path, session, epoch and
//! authentication outside this grammar. Decode only after verifying that binding.

use super::{Error, PathId, Shard};

pub(super) const DATA: u8 = 0x01;
pub(super) const DATA_ACK: u8 = 0x02;

pub(super) fn varint_len(value: u64) -> usize {
    ((u64::BITS - value.leading_zeros()).max(1) as usize).div_ceil(7)
}

pub(super) fn put_varint(mut value: u64, out: &mut Vec<u8>) {
    while value >= 128 {
        out.push(value as u8 | 0x80);
        value >>= 7;
    }
    out.push(value as u8);
}

fn take_byte(input: &mut &[u8]) -> Result<u8, Error> {
    let (&byte, tail) = input.split_first().ok_or(Error::Malformed)?;
    *input = tail;
    Ok(byte)
}

fn varint(input: &mut &[u8]) -> Result<u64, Error> {
    let mut value = 0u64;
    for i in 0..10 {
        let byte = take_byte(input)?;
        if i == 9 && byte > 1 {
            return Err(Error::Malformed);
        }
        value |= u64::from(byte & 127) << (i * 7);
        if byte < 128 {
            return if i != 0 && byte == 0 {
                Err(Error::Malformed)
            } else {
                Ok(value)
            };
        }
    }
    Err(Error::Malformed)
}

pub(super) fn header_len(sequence: u64) -> usize {
    3 + varint_len(sequence)
}

fn extent(path: PathId, shard: Shard<'_>) -> Result<u64, Error> {
    if shard.generation == u64::MAX {
        return Err(Error::Exhausted);
    }
    let len = u16::try_from(shard.bytes.len()).map_err(|_| Error::TooLarge)?;
    if len == 0 {
        return Err(Error::EmptyShard);
    }
    Ok((u64::from(len) << 1) | u64::from(path.get() != shard.ordinal))
}

/// Exact bytes added by one entry, including any explicit physical ordinal.
pub fn entry_len(path: PathId, shard: Shard<'_>) -> Result<usize, Error> {
    let size = extent(path, shard)?;
    Ok(varint_len(shard.generation) + varint_len(size) + (size as usize & 1) + shard.bytes.len())
}

pub(super) fn append(path: PathId, shard: Shard<'_>, out: &mut Vec<u8>) -> Result<(), Error> {
    let size = extent(path, shard)?;
    put_varint(shard.generation, out);
    put_varint(size, out);
    if path.get() != shard.ordinal {
        out.push(shard.ordinal);
    }
    out.extend_from_slice(shard.bytes);
    Ok(())
}

pub(super) fn shard<'a>(path: PathId, bytes: &mut &'a [u8]) -> Result<Shard<'a>, Error> {
    let generation = varint(bytes)?;
    if generation == u64::MAX {
        return Err(Error::Malformed);
    }
    let extent = varint(bytes)?;
    let len = u16::try_from(extent >> 1).map_err(|_| Error::Malformed)?;
    if len == 0 {
        return Err(Error::Malformed);
    }
    let ordinal = if extent & 1 == 0 {
        path.get()
    } else {
        let explicit = take_byte(bytes)?;
        if explicit == path.get() {
            return Err(Error::Malformed);
        }
        explicit
    };
    let (value, tail) = bytes
        .split_at_checked(usize::from(len))
        .ok_or(Error::Malformed)?;
    *bytes = tail;
    Ok(Shard {
        generation,
        ordinal,
        bytes: value,
    })
}

/// Entire validated authenticated DATA payload, borrowing the original buffer.
#[derive(Clone, Copy, Debug)]
pub struct Decoded<'a> {
    /// Physical path bound to the authenticated carrier.
    pub path: PathId,
    /// Per-path DATA sequence; a pure ACK does not consume one.
    pub sequence: u64,
    /// Number of shard entries.
    pub count: u8,
    entries: &'a [u8],
    /// Complete validated ACK v1 including its discriminant.
    pub ack: Option<&'a [u8]>,
}

impl<'a> Decoded<'a> {
    /// Validate the complete payload and all bounds before exposing any entry.
    pub fn parse(
        expected_path: PathId,
        payload_limit: usize,
        bytes: &'a [u8],
    ) -> Result<Self, Error> {
        if bytes.len() > payload_limit.min(usize::from(u16::MAX)) {
            return Err(Error::TooLarge);
        }
        let mut input = bytes;
        let tag = take_byte(&mut input)?;
        if !matches!(tag, DATA | DATA_ACK) {
            return Err(Error::Malformed);
        }
        let path = PathId::new(take_byte(&mut input)?)?;
        if path != expected_path {
            return Err(Error::WrongPath);
        }
        let sequence = varint(&mut input)?;
        if sequence == u64::MAX {
            return Err(Error::Malformed);
        }
        let count = take_byte(&mut input)?;
        if count == 0 {
            return Err(Error::Malformed);
        }
        let start = input;
        for _ in 0..count {
            shard(path, &mut input)?;
        }
        let entries = &start[..start.len() - input.len()];
        let ack = if tag == DATA_ACK {
            crate::path_ack::AckBatch::decode(input).map_err(|_| Error::Malformed)?;
            Some(input)
        } else if input.is_empty() {
            None
        } else {
            return Err(Error::Malformed);
        };
        Ok(Self {
            path,
            sequence,
            count,
            entries,
            ack,
        })
    }

    /// Iterate validated generation, ordinal and opaque bytes without allocating.
    pub fn entries(self) -> impl Iterator<Item = Shard<'a>> {
        let mut rest = self.entries;
        (0..self.count).filter_map(move |_| shard(self.path, &mut rest).ok())
    }
}
