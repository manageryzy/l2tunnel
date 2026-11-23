//! Horizontal fragments of a single native record for independently batched physical paths.
//! The negotiated session authenticates the generation, ordinal and body before admission.

use crate::rolling::wire::compact;
use crate::striped::{Admission, Geometry, Receiver};
use crate::{Error, FecContext, GenerationId};

/// Negotiated coding dimensions and local allocation/record limits.
#[derive(Clone, Copy, Debug)]
pub struct Profile {
    paths: u8,
    threshold: u8,
    max_record: u16,
    max_shard: u16,
}

impl Profile {
    /// Path ordinals are 0 through N-1. K=N selects uncoded horizontal fragmentation.
    pub fn new(paths: u8, threshold: u8, max_record: u16, max_shard: u16) -> Result<Self, Error> {
        if threshold == 0 || threshold > paths || max_record == 0 || max_shard == 0 {
            return Err(Error::InvalidConfig);
        }
        let profile = Self {
            paths,
            threshold,
            max_record,
            max_shard,
        };
        profile.layout(usize::from(max_record))?;
        Ok(profile)
    }

    fn part(self, length: usize, index: u8) -> std::ops::Range<usize> {
        let n = usize::from(self.paths);
        let i = usize::from(index);
        length * i / n..length * (i + 1) / n
    }

    fn layout(self, length: usize) -> Result<Option<Geometry>, Error> {
        if length == 0 || length > usize::from(self.max_record) {
            return Err(Error::InvalidSource);
        }
        let longest = length.div_ceil(usize::from(self.paths));
        let mut required = compact::len(length as u64) + longest;
        let geometry = if self.paths == self.threshold {
            None
        } else {
            let parity = self.paths - self.threshold;
            let width = (longest + 2).div_ceil(usize::from(self.threshold));
            let shape = Geometry::new(
                self.threshold.into(),
                parity.into(),
                width,
                usize::from(u16::MAX),
            )?;
            required += usize::from(parity) * width;
            Some(shape)
        };
        if required > usize::from(self.max_shard) {
            return Err(Error::PacketTooLarge);
        }
        Ok(geometry)
    }

    /// Seal N immutable shards from this record alone, before any socket's batch deadline.
    pub fn encode(self, original: &[u8]) -> Result<Vec<Vec<u8>>, Error> {
        let length = original.len();
        let geometry = self.layout(length)?;
        let direct = (0..self.paths)
            .map(|i| &original[self.part(length, i)])
            .collect::<Vec<_>>();
        let mut rows = Vec::new();
        if let Some(g) = geometry {
            let sources = direct
                .iter()
                .map(|&s| if s.is_empty() { &[0][..] } else { s })
                .collect::<Vec<_>>();
            rows.resize(g.body_bytes() * usize::from(self.paths), 0);
            g.encode_group_into(&sources, &mut rows)?;
        }
        let mut header = [0; 3];
        let mut used = 0;
        compact::write(length as u64, &mut header, &mut used);
        let mut shards = Vec::with_capacity(usize::from(self.paths));
        for (i, data) in direct.iter().enumerate() {
            let parity = geometry.map_or(&[][..], |g| {
                &rows[i * g.body_bytes() + g.systematic_bytes()..(i + 1) * g.body_bytes()]
            });
            let mut shard = Vec::with_capacity(used + data.len() + parity.len());
            shard.extend_from_slice(&header[..used]);
            shard.extend_from_slice(data);
            shard.extend_from_slice(parity);
            shards.push(shard);
        }
        Ok(shards)
    }
}

enum State {
    Plain {
        parts: Vec<Option<Vec<u8>>>,
        count: usize,
    },
    Coded {
        geometry: Geometry,
        receiver: Box<Receiver>,
        row: Vec<u8>,
    },
}

/// One logical group, independent of which authenticated path carried each distinct ordinal.
pub struct RecordReceiver {
    profile: Profile,
    context: FecContext,
    group: GenerationId,
    length: u16,
    state: State,
}

impl RecordReceiver {
    /// Obtain the claimed record size without allocating. The profile enforces the local limit.
    pub fn original_length(body: &[u8]) -> Result<u16, Error> {
        let size = compact::read(body, &mut 0).map_err(|_| Error::Malformed)?;
        u16::try_from(size)
            .ok()
            .filter(|n| *n != 0)
            .ok_or(Error::InvalidSource)
    }

    /// Reserve only one bounded group after carrier authentication and session admission.
    pub fn new(
        profile: Profile,
        context: FecContext,
        group: GenerationId,
        length: u16,
    ) -> Result<Self, Error> {
        let state = match profile.layout(usize::from(length))? {
            Some(geometry) => State::Coded {
                geometry,
                receiver: Box::new(Receiver::new(context, group, geometry)?),
                row: vec![0; geometry.body_bytes()],
            },
            None => State::Plain {
                parts: vec![None; usize::from(profile.paths)],
                count: 0,
            },
        };
        Ok(Self {
            profile,
            context,
            group,
            length,
            state,
        })
    }

    /// Accept one original ordinal, including a retransmission over a different physical path.
    pub fn accept_authenticated(
        &mut self,
        context: FecContext,
        group: GenerationId,
        ordinal: u8,
        body: &[u8],
    ) -> Result<Admission, Error> {
        if context != self.context || group != self.group {
            return Err(Error::ContextMismatch);
        }
        if ordinal >= self.profile.paths || Self::original_length(body)? != self.length {
            return Err(Error::Malformed);
        }
        let length = usize::from(self.length);
        let size = self.profile.part(length, ordinal).len();
        let payload = &body[compact::len(length as u64)..];
        match &mut self.state {
            State::Plain { parts, count } => {
                if payload.len() != size {
                    return Err(Error::Malformed);
                }
                let slot = &mut parts[usize::from(ordinal)];
                if let Some(stored) = slot {
                    return if stored == payload {
                        Ok(Admission::Duplicate)
                    } else {
                        Err(Error::Conflict)
                    };
                }
                *slot = Some(payload.to_vec());
                *count += 1;
                Ok(Admission::Accepted)
            }
            State::Coded {
                geometry,
                receiver,
                row,
            } => {
                let systematic = geometry.systematic_bytes();
                if payload.len() != size + geometry.body_bytes() - systematic {
                    return Err(Error::Malformed);
                }
                let (data, parity) = payload.split_at(size);
                row[..systematic].fill(0);
                row[..2].copy_from_slice(&(size.max(1) as u16).to_be_bytes());
                row[2..2 + size].copy_from_slice(data);
                row[systematic..].copy_from_slice(parity);
                receiver.accept_authenticated(context, group, ordinal, row)
            }
        }
    }

    /// Copy the complete native record once K distinct members exist. Retries are idempotent.
    pub fn recover_into(&mut self, output: &mut [u8]) -> Result<usize, Error> {
        let length = usize::from(self.length);
        let output = output
            .get_mut(..length)
            .ok_or(Error::OutputTooSmall { required: length })?;
        match &mut self.state {
            State::Plain { count, .. } if *count < usize::from(self.profile.threshold) => {
                return Err(Error::InsufficientRank);
            }
            State::Coded { receiver, .. } => {
                receiver.recover_missing()?;
            }
            _ => (),
        }
        // Validate all reconstructed extents before publishing any bytes to the caller.
        for i in 0..self.profile.paths {
            let range = self.profile.part(length, i);
            let raw = self.part(i)?;
            let valid = match self.state {
                State::Coded { .. } if range.is_empty() => raw == [0],
                _ => raw.len() == range.len(),
            };
            if !valid {
                return Err(Error::InvalidSource);
            }
        }
        for i in 0..self.profile.paths {
            let range = self.profile.part(length, i);
            output[range.clone()].copy_from_slice(&self.part(i)?[..range.len()]);
        }
        Ok(length)
    }

    fn part(&self, ordinal: u8) -> Result<&[u8], Error> {
        let raw = match &self.state {
            State::Plain { parts, .. } => parts[usize::from(ordinal)].as_deref(),
            State::Coded { receiver, .. } => receiver.original(ordinal)?,
        };
        raw.ok_or(Error::InsufficientRank)
    }
}
