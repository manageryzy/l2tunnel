use crate::{
    Error, FecContext, GenerationId,
    mixed_datagram::{GroupShape, Packet, Profile},
    original_length,
    striped::{Admission, Geometry, Receiver},
};

/// Logical delivery for one authenticated group. An owner can keep several
/// groups live under its byte credit and service them in any order.
pub struct ReceiveGroup {
    profile: Profile,
    generation: GenerationId,
    shape: GroupShape,
    geometry: Geometry,
    receiver: Receiver,
    split_original: Option<Vec<u8>>,
    committed: [bool; 256],
}

impl ReceiveGroup {
    /// Parse and admit the first authenticated member. The caller may reuse
    /// the same canonical expansion scratch across groups.
    pub fn open_authenticated(
        profile: Profile,
        context: FecContext,
        wire: &[u8],
        scratch: &mut [u8],
    ) -> Result<Self, Error> {
        let (shape, packet) = profile.inspect(wire)?;
        let generation = packet.generation();
        let geometry = packet.geometry();
        let mut group = Self {
            profile,
            generation,
            shape,
            geometry,
            receiver: Receiver::new(context, generation, geometry)?,
            split_original: None,
            committed: [false; 256],
        };
        group.admit(context, shape, &packet, scratch)?;
        Ok(group)
    }

    /// Accept a new member or a byte-identical named retry under the same
    /// authenticated session, direction, epoch, generation and geometry.
    pub fn accept_authenticated(
        &mut self,
        context: FecContext,
        wire: &[u8],
        scratch: &mut [u8],
    ) -> Result<Admission, Error> {
        let (shape, packet) = self.profile.inspect(wire)?;
        self.admit(context, shape, &packet, scratch)
    }

    fn admit(
        &mut self,
        context: FecContext,
        shape: GroupShape,
        packet: &Packet<'_>,
        scratch: &mut [u8],
    ) -> Result<Admission, Error> {
        if packet.generation() != self.generation {
            return Err(Error::ContextMismatch);
        }
        if shape != self.shape || packet.geometry() != self.geometry {
            return Err(Error::Conflict);
        }
        let used = packet.write_body(scratch)?;
        let body = &scratch[..used];
        let split = if let GroupShape::Split(total) = shape {
            let (left, right) = split_parts(total, packet.index(), self.geometry, body)?;
            if let Some(original) = &self.split_original
                && (!original.starts_with(left) || &original[left.len()..] != right)
            {
                return Err(Error::Conflict);
            }
            Some((left, right))
        } else {
            None
        };
        let result =
            self.receiver
                .accept_authenticated(context, self.generation, packet.index(), body)?;
        if self.split_original.is_none()
            && let Some((left, right)) = split
        {
            let mut original = Vec::with_capacity(left.len() + right.len());
            original.extend_from_slice(left);
            original.extend_from_slice(right);
            self.split_original = Some(original);
        }
        Ok(result)
    }

    /// First absolute logical source ID of this group.
    pub const fn generation(&self) -> GenerationId {
        self.generation
    }

    /// Number of input records or size of the single split input.
    pub const fn shape(&self) -> GroupShape {
        self.shape
    }

    fn logical_index(&self, id: GenerationId) -> Result<u8, Error> {
        let count = match self.shape {
            GroupShape::Originals(count) => count,
            GroupShape::Split(_) => 1,
        };
        id.0.checked_sub(self.generation.0)
            .filter(|&n| n < u64::from(count))
            .map(|n| n as u8)
            .ok_or(Error::UnknownGeneration)
    }

    /// Whether all missing members can be reconstructed when needed.
    pub fn can_recover(&self) -> bool {
        self.receiver.can_recover()
    }

    /// Reconstruct missing ordinary originals only on explicit demand. Either
    /// member of a singleton already contains the complete logical original.
    pub fn recover_missing(&mut self) -> Result<usize, Error> {
        if self.split_original.is_some() {
            return Ok(0);
        }
        self.receiver.recover_missing()
    }

    /// Borrow an intact or recovered original until its successful delivery.
    pub fn pending_original(&self, id: GenerationId) -> Result<Option<&[u8]>, Error> {
        let index = self.logical_index(id)?;
        if self.committed[usize::from(index)] {
            return Ok(None);
        }
        match self.shape {
            GroupShape::Originals(_) => self.receiver.original(index),
            GroupShape::Split(_) => Ok(self.split_original.as_deref()),
        }
    }

    /// Commit after successful delivery. An already committed ID is idempotent.
    pub fn commit_original(&mut self, id: GenerationId) -> Result<bool, Error> {
        let index = usize::from(self.logical_index(id)?);
        if self.committed[index] {
            return Ok(false);
        }
        if self.pending_original(id)?.is_none() {
            return Err(Error::Unsealed);
        }
        self.committed[index] = true;
        Ok(true)
    }
}

// For 1+1 the sole Cauchy coefficient is inverse(0 XOR 1) = 1.
// The one parity cell is therefore the other packet's protected original.
// Validate both halves before exposing anything, even if it is the first arrival.
fn split_parts(
    total: u16,
    index: u8,
    geometry: Geometry,
    body: &[u8],
) -> Result<(&[u8], &[u8]), Error> {
    let (own, other) = body.split_at(geometry.cell_bytes());
    split_cells(total, index, geometry, own, other)
}

pub(crate) fn split_cells<'a>(
    total: u16,
    index: u8,
    geometry: Geometry,
    own: &'a [u8],
    other: &'a [u8],
) -> Result<(&'a [u8], &'a [u8]), Error> {
    let (first, second) = if index == 0 {
        (own, other)
    } else {
        (other, own)
    };
    let left_len = original_length(first)?;
    let right_len = original_length(second)?;
    if left_len != usize::from(total.div_ceil(2))
        || right_len != usize::from((total / 2).max(1))
        || geometry.cell_bytes() != left_len + 2
    {
        return Err(Error::InvalidSource);
    }
    let left = &first[2..2 + left_len];
    let right = &second[2..2 + right_len];
    if total == 1 {
        if left != right {
            return Err(Error::Conflict);
        }
        return Ok((left, &[]));
    }
    Ok((left, right))
}
