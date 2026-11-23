//! Systematic Cauchy array code for complete physical packets.
//!
//! A group has `n = k + m` physical packets. Each has its **own** original in
//! the first `k` cells, plus `m` parity cells, all of the same byte width. In
//! stripe `s`, systematic column `c` resides in packet `(s + c) % n`; parity
//! column `r` in packet `(s + k + r) % n`. Each stripe therefore puts exactly
//! one cell in every packet. Its systematic generator is an identity matrix
//! above a Cauchy matrix on disjoint GF(256) coordinates. Any square Cauchy
//! submatrix is invertible, so any `k` distinct valid packets recover every
//! stripe, including all original lengths.
//!
//! The caller authenticates the group, geometry, index and body together,
//! supplies the enclosing wire budget, and owns delivery deduplication and
//! deadlines. Parity requires the originals of a sealed group. Receipt makes
//! an intact packet available immediately and never initiates reconstruction.

use crate::{Error, FecContext, GenerationId, field};

mod restore;
pub use restore::{RecoveryPlan, RecoveryScratch};
#[cfg(test)]
mod tests;

/// Verified cell counts and width for one group.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Geometry {
    data: u16,
    parity: u16,
    width: usize,
}

impl Geometry {
    /// Check authenticated dimensions against the local body limit after outer framing.
    pub fn new(
        data_cells: u16,
        parity_cells: u16,
        cell_bytes: usize,
        max_body_bytes: usize,
    ) -> Result<Self, Error> {
        let count = usize::from(data_cells) + usize::from(parity_cells);
        if data_cells == 0 || parity_cells == 0 || count > 256 || cell_bytes == 0 {
            return Err(Error::InvalidDimensions);
        }
        let body = cell_bytes.checked_mul(count).ok_or(Error::Arithmetic)?;
        if body > max_body_bytes.min(usize::from(u16::MAX)) {
            return Err(Error::PacketTooLarge);
        }
        if cell_bytes * usize::from(data_cells) < 3 {
            return Err(Error::InvalidDimensions);
        }
        Ok(Self {
            data: data_cells,
            parity: parity_cells,
            width: cell_bytes,
        })
    }

    /// Choose the minimum width for exactly n nonempty originals.
    pub fn for_group(
        data_cells: u16,
        parity_cells: u16,
        originals: &[&[u8]],
        max_body_bytes: usize,
    ) -> Result<Self, Error> {
        if data_cells == 0 || originals.len() != usize::from(data_cells) + usize::from(parity_cells)
        {
            return Err(Error::InvalidDimensions);
        }
        let longest = originals.iter().map(|s| s.len()).max().unwrap_or(0);
        if originals.iter().any(|source| source.is_empty()) || longest > usize::from(u16::MAX) {
            return Err(Error::InvalidSource);
        }
        Self::new(
            data_cells,
            parity_cells,
            (longest + 2).div_ceil(usize::from(data_cells)),
            max_body_bytes,
        )
    }

    /// Systematic cells in each physical packet, also the recovery threshold.
    pub const fn data_cells(self) -> u16 {
        self.data
    }

    /// Parity cells in each physical packet, also the tolerated erasure count.
    pub const fn parity_cells(self) -> u16 {
        self.parity
    }

    /// Distinct physical packet indices in the sealed group.
    pub fn packet_count(self) -> usize {
        usize::from(self.data) + usize::from(self.parity)
    }

    /// Actual bytes per cell, including cells carrying the protected length field.
    pub const fn cell_bytes(self) -> usize {
        self.width
    }

    /// Exact FEC body on each physical packet. Enclosing headers are separate.
    pub fn body_bytes(self) -> usize {
        self.packet_count() * self.width
    }

    /// Maximum original payload length after the protected two-byte length.
    pub fn original_capacity(self) -> usize {
        self.systematic_bytes() - 2
    }

    pub(crate) fn systematic_bytes(self) -> usize {
        usize::from(self.data) * self.width
    }

    pub(crate) fn packet(self, index: u8) -> Result<usize, Error> {
        let packet = usize::from(index);
        if packet < self.packet_count() {
            Ok(packet)
        } else {
            Err(Error::InvalidDimensions)
        }
    }

    pub(crate) fn original(self, systematic: &[u8]) -> Result<&[u8], Error> {
        if systematic.len() != self.systematic_bytes() {
            return Err(Error::Malformed);
        }
        let length = usize::from(u16::from_be_bytes([systematic[0], systematic[1]]));
        if length == 0
            || length > self.original_capacity()
            || systematic[2 + length..].iter().any(|&b| b != 0)
        {
            return Err(Error::InvalidSource);
        }
        Ok(&systematic[2..2 + length])
    }

    fn coefficients(self) -> Result<Vec<u8>, Error> {
        let k = usize::from(self.data);
        let mut rows = vec![0; k * usize::from(self.parity)];
        for (r, row) in (0..self.parity).zip(rows.chunks_exact_mut(k)) {
            field::cauchy_into(self.data, r, row)?;
        }
        Ok(rows)
    }

    pub(crate) fn check_longest(self, length: usize) -> Result<(), Error> {
        if (length + 2).div_ceil(usize::from(self.data)) == self.width {
            Ok(())
        } else {
            Err(Error::InvalidSource)
        }
    }

    /// Write all canonical members into caller-owned consecutive packet slots.
    /// Systematic cells are filled before any parity is written. Each parity
    /// cell depends exclusively on cells in other physical members.
    pub fn encode_group_into(self, originals: &[&[u8]], out: &mut [u8]) -> Result<usize, Error> {
        if Self::for_group(self.data, self.parity, originals, self.body_bytes())? != self {
            return Err(Error::InvalidDimensions);
        }
        let n = self.packet_count();
        let body = self.body_bytes();
        let required = n * body;
        let out = out
            .get_mut(..required)
            .ok_or(Error::OutputTooSmall { required })?;
        for (slot, original) in out.chunks_exact_mut(body).zip(originals) {
            slot[..2].copy_from_slice(&(original.len() as u16).to_be_bytes());
            slot[2..2 + original.len()].copy_from_slice(original);
            slot[2 + original.len()..].fill(0);
        }
        let k = usize::from(self.data);
        let mut weights = [0; 256];
        for row in 0..self.parity {
            field::cauchy_into(self.data, row, &mut weights[..k])?;
            for packet in 0..n {
                let (before, rest) = out.split_at_mut(packet * body);
                let (current, after) = rest.split_at_mut(body);
                let start = (k + usize::from(row)) * self.width;
                let destination = &mut current[start..start + self.width];
                let stripe = (packet + n - k - usize::from(row)) % n;
                for (col, &weight) in weights[..k].iter().enumerate() {
                    let source = (stripe + col) % n;
                    // The parity row and the systematic column occupy distinct
                    // physical members of this stripe.
                    let (side, i): (&[u8], _) = if source < packet {
                        (before, source)
                    } else {
                        (after, source - packet - 1)
                    };
                    let offset = i * body + col * self.width;
                    tape_reed_solomon::gf::mul_slice_xor(
                        destination,
                        &side[offset..offset + self.width],
                        weight,
                    );
                }
            }
        }
        Ok(required)
    }

    fn write_parity(
        self,
        packet: usize,
        row_stride: usize,
        originals: &[u8],
        rows: &[u8],
        out: &mut [u8],
    ) {
        let n = self.packet_count();
        let k = usize::from(self.data);
        for (r, (weights, destination)) in rows
            .chunks_exact(k)
            .zip(out.chunks_exact_mut(self.width))
            .enumerate()
        {
            destination.fill(0);
            let stripe = (packet + n - k - r) % n;
            for (c, &weight) in weights.iter().enumerate() {
                let source = ((stripe + c) % n) * row_stride + c * self.width;
                tape_reed_solomon::gf::mul_slice_xor(
                    destination,
                    &originals[source..source + self.width],
                    weight,
                );
            }
        }
    }
}

/// Sealed physical packet group. Packet generation uses caller-owned output.
pub struct Encoder {
    geometry: Geometry,
    originals: Vec<u8>,
    coefficients: Vec<u8>,
}

impl Encoder {
    /// Validate and retain all originals before any group packet can be emitted.
    pub fn new(geometry: Geometry, originals: &[&[u8]]) -> Result<Self, Error> {
        if Geometry::for_group(
            geometry.data,
            geometry.parity,
            originals,
            geometry.body_bytes(),
        )? != geometry
        {
            return Err(Error::InvalidDimensions);
        }
        let stride = geometry.systematic_bytes();
        let mut storage = vec![0; stride * geometry.packet_count()];
        for (slot, source) in storage.chunks_exact_mut(stride).zip(originals) {
            let len = u16::try_from(source.len()).map_err(|_| Error::InvalidSource)?;
            slot[..2].copy_from_slice(&len.to_be_bytes());
            slot[2..2 + source.len()].copy_from_slice(source);
        }
        Ok(Self {
            geometry,
            originals: storage,
            coefficients: geometry.coefficients()?,
        })
    }

    /// Copy this packet's systematic original followed by parity protecting other packets.
    pub fn write_packet(&self, index: u8, output: &mut [u8]) -> Result<usize, Error> {
        let g = self.geometry;
        let p = g.packet(index)?;
        let body = g.body_bytes();
        let out = output
            .get_mut(..body)
            .ok_or(Error::OutputTooSmall { required: body })?;
        let stride = g.systematic_bytes();
        out[..stride].copy_from_slice(&self.originals[p * stride..(p + 1) * stride]);
        g.write_parity(
            p,
            stride,
            &self.originals,
            &self.coefficients,
            &mut out[stride..],
        );
        Ok(body)
    }
}

/// Outcome for a previously authenticated physical packet.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Admission {
    /// A distinct, previously unseen physical packet was retained.
    Accepted,
    /// The same index and all packet bytes matched an earlier physical arrival.
    Duplicate,
}

/// One bounded single-group receiver. Scope and geometry are fixed at construction.
pub struct Receiver {
    context: FecContext,
    generation: GenerationId,
    geometry: Geometry,
    bytes: Vec<u8>,
    arrived: [bool; 256],
    count: usize,
    longest: usize,
    restored: bool,
}

impl Receiver {
    /// Reserve at most n whole bodies in the authenticated group.
    pub fn new(
        context: FecContext,
        generation: GenerationId,
        geometry: Geometry,
    ) -> Result<Self, Error> {
        Ok(Self {
            context,
            generation,
            geometry,
            bytes: vec![0; geometry.packet_count() * geometry.body_bytes()],
            arrived: [false; 256],
            count: 0,
            longest: 0,
            restored: false,
        })
    }

    /// Validate and retain one physical body without decoding any parity.
    pub fn accept_authenticated(
        &mut self,
        context: FecContext,
        generation: GenerationId,
        index: u8,
        body: &[u8],
    ) -> Result<Admission, Error> {
        if context != self.context || generation != self.generation {
            return Err(Error::ContextMismatch);
        }
        let g = self.geometry;
        let p = g.packet(index)?;
        let w = g.body_bytes();
        if body.len() != w {
            return Err(Error::Malformed);
        }
        let slot = &mut self.bytes[p * w..(p + 1) * w];
        // After recovery every retained slot holds its complete canonical codeword.
        if self.arrived[p] || self.restored {
            if slot != body {
                return Err(Error::Conflict);
            }
            if self.arrived[p] {
                return Ok(Admission::Duplicate);
            }
        }
        let len = g.original(&body[..g.systematic_bytes()])?.len();
        let longest = self.longest.max(len);
        if self.count + 1 == g.packet_count() {
            g.check_longest(longest)?;
        }
        slot.copy_from_slice(body);
        self.longest = longest;
        self.arrived[p] = true;
        self.count += 1;
        Ok(Admission::Accepted)
    }

    /// Count distinct actually received packets, excluding reconstructed ones.
    pub const fn received_count(&self) -> usize {
        self.count
    }

    /// Whether enough physical packets have arrived for exact group recovery.
    pub fn can_recover(&self) -> bool {
        self.count >= usize::from(self.geometry.data)
    }

    /// Borrow an original immediately upon arrival or after explicit reconstruction.
    pub fn original(&self, index: u8) -> Result<Option<&[u8]>, Error> {
        let g = self.geometry;
        let p = g.packet(index)?;
        if !self.arrived[p] && !self.restored {
            return Ok(None);
        }
        let offset = p * g.body_bytes();
        Ok(Some(g.original(
            &self.bytes[offset..offset + g.systematic_bytes()],
        )?))
    }

    /// Recover all missing originals transactionally on demand; returns their count.
    /// An intact group takes the zero-work path even if this is called.
    pub fn recover_missing(&mut self) -> Result<usize, Error> {
        if self.restored || self.count == self.geometry.packet_count() {
            return Ok(0);
        }
        if !self.can_recover() {
            return Err(Error::InsufficientRank);
        }
        let plan = RecoveryPlan::for_geometry(self.geometry);
        self.recover_missing_with_scratch(&mut RecoveryScratch::new(plan)?)
    }

    /// Recover with shared caller-owned scratch. Successful recovery updates only
    /// missing physical slots. Errors leave retained rows and delivery state intact.
    pub fn recover_missing_with_scratch(
        &mut self,
        scratch: &mut RecoveryScratch,
    ) -> Result<usize, Error> {
        let g = self.geometry;
        let arrived = &self.arrived[..g.packet_count()];
        let missing = arrived.len() - self.count;
        if missing == 0 || self.restored {
            return Ok(0);
        }
        if !self.can_recover() {
            return Err(Error::InsufficientRank);
        }
        let stride = g.body_bytes();
        let (bytes, longest) = scratch.recover(g, arrived, |p| {
            Some(&self.bytes[p * stride..(p + 1) * stride])
        })?;
        for (p, slot) in self.bytes.chunks_exact_mut(stride).enumerate() {
            if !arrived[p] {
                slot.copy_from_slice(&bytes[p * stride..(p + 1) * stride]);
            }
        }
        self.longest = longest;
        self.restored = true;
        Ok(missing)
    }
}
