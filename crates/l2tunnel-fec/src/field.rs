//! Safe finite-field error-correction arithmetic, not cryptography.
use crate::{Error, MAX_SOURCES};

/// Multiply bytes in GF(256), polynomial 0x11d, in eight polynomial steps.
pub fn multiply(mut left: u8, mut right: u8) -> u8 {
    let mut product = 0;
    for _ in 0..8 {
        if right & 1 != 0 {
            product ^= left;
        }
        let high = left & 0x80 != 0;
        left <<= 1;
        if high {
            left ^= 0x1d;
        }
        right >>= 1;
    }
    product
}

/// Multiplicative inverse, or None for the field's zero element.
pub fn inverse(value: u8) -> Option<u8> {
    if value == 0 {
        return None;
    }
    let mut result = 1;
    let mut base = value;
    let mut exponent = 254_u8;
    while exponent != 0 {
        if exponent & 1 != 0 {
            result = multiply(result, base);
        }
        base = multiply(base, base);
        exponent >>= 1;
    }
    Some(result)
}

/// Exact compact.py counter coefficient, including intentional modulo-2^32 math.
///
/// This deterministic coding coefficient is not a cryptographic random value.
pub fn compact_coefficient(seed: u32, source: u32) -> u8 {
    let mut value = seed ^ source.wrapping_mul(0x9e37_79b9);
    value ^= value >> 16;
    value = value.wrapping_mul(0x85eb_ca6b);
    value ^= value >> 13;
    value = value.wrapping_mul(0xc2b2_ae35);
    (value ^ (value >> 16)) as u8
}

/// Bounded compact.py coefficient vector over contiguous absolute source IDs.
///
/// Source IDs do not wrap. An all-zero result is allowed here, but cannot encode
/// a repair; choose another seed if the generated row has no nonzero entry.
pub fn compact_coefficients(seed: u32, first_source: u32, count: u16) -> Result<Vec<u8>, Error> {
    if count == 0 || usize::from(count) > MAX_SOURCES {
        return Err(Error::InvalidCoefficients);
    }
    let last = first_source
        .checked_add(u32::from(count) - 1)
        .ok_or(Error::Arithmetic)?;
    Ok((first_source..=last)
        .map(|source| compact_coefficient(seed, source))
        .collect())
}

/// Exact coding.py Cauchy row; source count plus repair index must be below 256.
pub fn cauchy_coefficients(sources: u16, repair_index: u16) -> Result<Vec<u8>, Error> {
    let column = sources
        .checked_add(repair_index)
        .ok_or(Error::InvalidCoefficients)?;
    if sources == 0 || column >= 256 {
        return Err(Error::InvalidCoefficients);
    }
    (0..sources)
        .map(|source| inverse((source ^ column) as u8).ok_or(Error::InvalidCoefficients))
        .collect()
}
