//! Erased-cell reconstruction using just the missing square Cauchy submatrix.
use super::{Error, Geometry, field};
use crate::mixed_datagram::{GroupShape, Profile};

/// Heap layout of the reusable transaction for a single group at a time.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecoveryPlan {
    bytes: usize,
}

impl RecoveryPlan {
    /// Reserve all canonical rows, Cauchy coefficients, erased-column equations,
    /// coordinate vectors and one parity suffix for the verified geometry.
    pub fn for_geometry(g: Geometry) -> Self {
        let k = usize::from(g.data);
        let m = usize::from(g.parity);
        let erased = k.min(m);
        // A Geometry has at most 256 members and at most 65535 bytes per body.
        let bytes =
            g.packet_count() * g.body_bytes() + k * m + erased * g.width + 4 * erased + m * g.width;
        Self { bytes }
    }

    /// Cover every shortened geometry at its expanded body ceiling, including
    /// the 1+1 geometry also used by a split singleton.
    pub fn for_profile(profile: Profile) -> Result<Self, Error> {
        let n = profile
            .data_cells
            .checked_add(profile.parity_cells)
            .ok_or(Error::InvalidDimensions)?;
        GroupShape::Originals(n).dimensions(profile.data_cells, profile.parity_cells)?;
        let ceiling = profile.max_body_bytes.min(usize::from(u16::MAX));
        (2..=n)
            .filter_map(|q| {
                let (k, m) = GroupShape::Originals(q)
                    .dimensions(profile.data_cells, profile.parity_cells)
                    .ok()?;
                Geometry::new(k, m, ceiling / usize::from(q), ceiling)
                    .ok()
                    .map(Self::for_geometry)
            })
            .max_by_key(|plan| plan.bytes)
            .ok_or(Error::InvalidDimensions)
    }

    /// Actual byte capacity of the one heap allocation made from this plan.
    pub const fn heap_bytes(self) -> usize {
        self.bytes
    }
}

/// One reusable, transactional local decoder. Every successful result borrows
/// this buffer until the caller commits its missing rows.
pub struct RecoveryScratch {
    bytes: Vec<u8>,
}

impl RecoveryScratch {
    /// Allocate the exact planned capacity before any packet arrives.
    pub fn new(plan: RecoveryPlan) -> Result<Self, Error> {
        let mut bytes = crate::storage::Allocation::new(plan.bytes)
            .vec(plan.bytes)
            .map_err(|_| Error::Capacity)?;
        bytes.resize(plan.bytes, 0);
        Ok(Self { bytes })
    }

    /// Retained heap capacity available to successive groups.
    pub fn reserved_bytes(&self) -> usize {
        self.bytes.capacity()
    }

    /// Read each received row once from caller custody. Return the complete,
    /// validated canonical group and its longest original. No borrowed input
    /// is changed on any error and no scratch contents survive as caller state.
    pub fn recover<'r>(
        &mut self,
        g: Geometry,
        arrived: &[bool],
        row: impl Fn(usize) -> Option<&'r [u8]>,
    ) -> Result<(&[u8], usize), Error> {
        let n = g.packet_count();
        if arrived.len() != n {
            return Err(Error::InvalidDimensions);
        }
        let survivors = arrived.iter().filter(|&&v| v).count();
        if survivors < usize::from(g.data) {
            return Err(Error::InsufficientRank);
        }
        let required = RecoveryPlan::for_geometry(g).heap_bytes();
        let bytes = self
            .bytes
            .get_mut(..required)
            .ok_or(Error::OutputTooSmall { required })?;
        let (result, work) = bytes.split_at_mut(n * g.body_bytes());
        for (p, slot) in result.chunks_exact_mut(g.body_bytes()).enumerate() {
            if arrived[p] {
                let src = row(p)
                    .filter(|bytes| bytes.len() == slot.len())
                    .ok_or(Error::Malformed)?;
                slot.copy_from_slice(src);
            }
        }
        let longest = recover(g, arrived, result, work, survivors == usize::from(g.data))?;
        Ok((result, longest))
    }
}

/// GF products for one axis of the inverse of C(i,j) = 1 / (x_i + y_j).
/// With disjoint coordinates, every denominator in these products is nonzero.
fn gains(axis: &[u8], other: &[u8], output: &mut [u8]) -> Result<(), Error> {
    for (&x, gain) in axis.iter().zip(output) {
        let mut numerator = 1;
        for &y in other {
            numerator = field::multiply(numerator, x ^ y);
        }
        let mut denominator = 1;
        for &u in axis {
            if u != x {
                denominator = field::multiply(denominator, x ^ u);
            }
        }
        *gain = field::multiply(
            numerator,
            field::inverse(denominator).ok_or(Error::InvalidCoefficients)?,
        );
    }
    Ok(())
}

fn recover(
    g: Geometry,
    arrived: &[bool],
    result: &mut [u8],
    work: &mut [u8],
    square: bool,
) -> Result<usize, Error> {
    let n = g.packet_count();
    let k = usize::from(g.data);
    let m = usize::from(g.parity);
    let w = g.cell_bytes();
    let stride = g.body_bytes();
    let max_missing = k.min(m);
    let (weights, work) = work.split_at_mut(k * m);
    for (r, row) in (0..g.parity).zip(weights.chunks_exact_mut(k)) {
        field::cauchy_into(g.data, r, row)?;
    }
    let (rhs, work) = work.split_at_mut(max_missing * w);
    let (xs, work) = work.split_at_mut(max_missing);
    let (ys, work) = work.split_at_mut(max_missing);
    let (xg, work) = work.split_at_mut(max_missing);
    let (yg, parity) = work.split_at_mut(max_missing);
    for stripe in 0..n {
        let mut missing = 0;
        for c in (0..k).filter(|c| !arrived[(stripe + c) % n]) {
            ys[missing] = c as u8;
            missing += 1;
        }
        let ys = &ys[..missing];
        if ys.is_empty() {
            continue;
        }
        // At least k packets were received. Each erased systematic column
        // has a distinct available parity equation in this stripe.
        let xs = &mut xs[..missing];
        for (slot, r) in xs
            .iter_mut()
            .zip((k..n).filter(|r| arrived[(stripe + r) % n]))
        {
            *slot = r as u8;
        }
        // Subtract systematic cells already available in this stripe. Each
        // remaining equation now refers only to the erased columns in ys.
        for (&x, row) in xs.iter().zip(rhs.chunks_exact_mut(w)) {
            let column = usize::from(x);
            let pos = (stripe + column) % n * stride + column * w;
            row.copy_from_slice(&result[pos..pos + w]);
            for c in 0..k {
                let packet = (stripe + c) % n;
                if arrived[packet] {
                    let offset = packet * stride + c * w;
                    tape_reed_solomon::gf::mul_slice_xor(
                        row,
                        &result[offset..offset + w],
                        weights[(column - k) * k + c],
                    );
                }
            }
        }
        if let [column] = ys {
            // A single erased column needs the reciprocal of 1/(x XOR y).
            let c = usize::from(*column);
            let pos = (stripe + c) % n * stride + c * w;
            let dst = &mut result[pos..pos + w];
            tape_reed_solomon::gf::mul_slice(dst, &rhs[..w], xs[0] ^ column);
            continue;
        }
        // For this square Cauchy submatrix, inverse[j,i] is
        // yg[j] * xg[i] / (xs[i] + ys[j]), in characteristic two.
        gains(xs, ys, xg)?;
        gains(ys, xs, yg)?;
        for (&y, &scale) in ys.iter().zip(yg.iter()) {
            let c = usize::from(y);
            let pos = (stripe + c) % n * stride + c * w;
            let dst = &mut result[pos..pos + w];
            dst.fill(0);
            for ((&x, &gain), row) in xs.iter().zip(xg.iter()).zip(rhs.chunks_exact(w)) {
                let weight = weights[(usize::from(x) - k) * k + c];
                let factor = field::multiply(field::multiply(scale, gain), weight);
                tape_reed_solomon::gf::mul_slice_xor(dst, row, factor);
            }
        }
    }

    // Validate the protected lengths, padding and all redundant observations
    // before publishing any restored source or accepting a later physical copy.
    // Exactly k survivors supply a square system in every stripe. All received
    // parity was used in the solution. Extra survivors supply independent checks.
    let mut longest = 0;
    for (packet, &was_received) in arrived.iter().enumerate() {
        let offset = packet * stride;
        let end = offset + g.systematic_bytes();
        longest = longest.max(g.original(&result[offset..end])?.len());
        if was_received && square {
            continue;
        }
        g.write_parity(packet, stride, result, weights, parity);
        let expected = &mut result[end..offset + stride];
        if was_received && expected != parity {
            return Err(Error::Conflict);
        }
        if !was_received {
            expected.copy_from_slice(parity);
        }
    }
    g.check_longest(longest)?;
    Ok(longest)
}
