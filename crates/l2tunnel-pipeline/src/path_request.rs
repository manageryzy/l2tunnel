//! Authenticated A3 gap feedback. It names the stable group and desired coding
//! ordinals, independently of which physical path delivers each replacement.
use super::path_ack::{Error, put, take, width};

/// Complete selective repair request, limited to 64 ordered groups per message.
#[derive(Debug, Eq, PartialEq)]
pub struct ShardRequest {
    paths: u8,
    rows: Vec<(u64, Vec<u8>)>,
}

impl ShardRequest {
    /// Validate local requests. Repeated ordinals and the sentinel group ID are invalid.
    pub fn new(paths: u8, mut rows: Vec<(u64, Vec<u8>)>) -> Result<Self, Error> {
        if paths == 0 || !(1..=64).contains(&rows.len()) {
            return Err(Error::Invalid);
        }
        let mut lower = 0;
        for (id, ordinals) in &mut rows {
            if *id < lower
                || *id == u64::MAX
                || ordinals.is_empty()
                || ordinals.len() > usize::from(paths)
            {
                return Err(Error::Invalid);
            }
            ordinals.sort_unstable();
            if ordinals.last().is_some_and(|last| *last >= paths)
                || ordinals.windows(2).any(|pair| pair[0] == pair[1])
            {
                return Err(Error::Invalid);
            }
            lower = *id + 1;
        }
        Ok(Self { paths, rows })
    }

    /// Borrow requested ordinals in ascending order for each stable group ID.
    pub fn rows(&self) -> &[(u64, Vec<u8>)] {
        &self.rows
    }

    /// Exact wire length under the negotiated number of physical paths.
    pub fn wire_len(&self) -> usize {
        let mask = usize::from(self.paths).div_ceil(8);
        let mut lower = 0;
        let mut size = 2;
        for (id, _) in &self.rows {
            size += width(*id - lower) + mask;
            lower = *id + 1;
        }
        size
    }

    /// Write the complete canonical message. Insufficient output leaves it untouched.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, Error> {
        let n = self.wire_len();
        let out = out.get_mut(..n).ok_or(Error::Capacity)?;
        out[..2].copy_from_slice(&[0xa3, self.rows.len() as u8]);
        let mask = usize::from(self.paths).div_ceil(8);
        let mut pos = 2;
        let mut lower = 0;
        for (id, ordinals) in &self.rows {
            put(id - lower, out, &mut pos);
            let bits = &mut out[pos..pos + mask];
            bits.fill(0);
            for &i in ordinals {
                bits[usize::from(i / 8)] |= 1 << (i % 8);
            }
            pos += mask;
            lower = *id + 1;
        }
        Ok(n)
    }

    /// Check negotiated ordinal bounds, gaps and trailing bytes before returning any request.
    pub fn decode(paths: u8, input: &[u8]) -> Result<Self, Error> {
        let Some(([0xa3, count], mut rest)) = input.split_first_chunk::<2>() else {
            return Err(Error::Invalid);
        };
        let count = *count;
        if paths == 0 || !(1..=64).contains(&count) {
            return Err(Error::Invalid);
        }
        let mask = usize::from(paths).div_ceil(8);
        let mut lower: u64 = 0;
        let mut rows = Vec::with_capacity(usize::from(count));
        for _ in 0..count {
            let id = lower.checked_add(take(&mut rest)?).ok_or(Error::Invalid)?;
            lower = id.checked_add(1).ok_or(Error::Invalid)?;
            let (bits, tail) = rest.split_at_checked(mask).ok_or(Error::Invalid)?;
            rest = tail;
            if !paths.is_multiple_of(8) && bits[mask - 1] >> (paths % 8) != 0 {
                return Err(Error::Invalid);
            }
            let ordinals: Vec<_> = (0..paths)
                .filter(|i| bits[usize::from(i / 8)] & (1 << (i % 8)) != 0)
                .collect();
            if ordinals.is_empty() {
                return Err(Error::Invalid);
            }
            rows.push((id, ordinals));
        }
        if !rest.is_empty() {
            return Err(Error::Invalid);
        }
        Ok(Self { paths, rows })
    }
}
