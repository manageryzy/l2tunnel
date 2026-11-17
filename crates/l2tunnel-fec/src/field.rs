//! Safe finite-field error-correction arithmetic, not cryptography.
use crate::{Error, MAX_SOURCES};

// One process-static 768-byte lookup, evaluated at compile time. This changes
// only the implementation of a charged GF operation: no caller budget, phase,
// pause cursor, allocation plan or packet format depends on these table reads.
// This is error-correction arithmetic, not a constant-time cryptographic API.
struct FieldTables {
    logarithm: [u8; 256],
    exponential: [u8; 512],
}

impl FieldTables {
    const fn new() -> Self {
        let mut tables = Self {
            logarithm: [0; 256],
            exponential: [0; 512],
        };
        let mut value = 1_u16;
        let mut exponent = 0;
        // Two generates all 255 nonzero elements for polynomial 0x11d.
        while exponent < 255 {
            tables.exponential[exponent] = value as u8;
            tables.logarithm[value as usize] = exponent as u8;
            value <<= 1;
            if value & 0x100 != 0 {
                value ^= 0x11d;
            }
            exponent += 1;
        }
        // Repetition avoids a runtime modulo for log(a) + log(b), at most 508.
        while exponent < tables.exponential.len() {
            tables.exponential[exponent] = tables.exponential[exponent - 255];
            exponent += 1;
        }
        tables
    }
}

static FIELD_TABLES: FieldTables = FieldTables::new();

/// Multiply bytes in GF(256), polynomial 0x11d, using a fixed static lookup.
///
/// The table contains no protocol state or cryptographic key material. This is
/// the same one GF byte operation charged by existing FEC work budgets.
#[inline]
pub fn multiply(left: u8, right: u8) -> u8 {
    if left == 0 || right == 0 {
        return 0;
    }
    let exponent = usize::from(FIELD_TABLES.logarithm[usize::from(left)])
        + usize::from(FIELD_TABLES.logarithm[usize::from(right)]);
    FIELD_TABLES.exponential[exponent]
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
    cauchy_column(sources, repair_index)?;
    let mut result = vec![0; usize::from(sources)];
    cauchy_into(sources, repair_index, &mut result)?;
    Ok(result)
}

pub(crate) fn cauchy_into(sources: u16, repair_index: u16, output: &mut [u8]) -> Result<(), Error> {
    let column = cauchy_column(sources, repair_index)?;
    let required = usize::from(sources);
    if output.len() < required {
        return Err(Error::OutputTooSmall { required });
    }
    for (source, coefficient) in output[..required].iter_mut().enumerate() {
        *coefficient = inverse((source as u16 ^ column) as u8).ok_or(Error::InvalidCoefficients)?;
    }
    Ok(())
}

pub(crate) fn cauchy_column(sources: u16, repair_index: u16) -> Result<u16, Error> {
    let column = sources
        .checked_add(repair_index)
        .ok_or(Error::InvalidCoefficients)?;
    if sources == 0 || column >= 256 {
        return Err(Error::InvalidCoefficients);
    }
    Ok(column)
}

#[cfg(test)]
mod table_tests {
    use super::*;

    // Independent of logarithms and the generator recurrence: multiply the
    // binary polynomials first, then reduce high terms by the modulus.
    fn reference_product(left: u8, right: u8) -> u8 {
        let mut polynomial = 0_u16;
        for bit in 0..8 {
            if right & (1 << bit) != 0 {
                polynomial ^= u16::from(left) << bit;
            }
        }
        for bit in (8..=14).rev() {
            if polynomial & (1 << bit) != 0 {
                polynomial ^= 0x11d << (bit - 8);
            }
        }
        polynomial as u8
    }

    #[test]
    fn static_products_match_all_independent_polynomial_reductions() {
        for left in 0_u8..=u8::MAX {
            for right in 0_u8..=u8::MAX {
                assert_eq!(
                    multiply(left, right),
                    reference_product(left, right),
                    "GF product {left} * {right}",
                );
            }
        }
    }

    #[test]
    fn static_table_cycle_indexes_and_storage_are_bounded() {
        assert_eq!(std::mem::size_of::<FieldTables>(), 768);
        let mut seen = [false; 256];
        for exponent in 0..255 {
            let value = FIELD_TABLES.exponential[exponent];
            assert_ne!(value, 0);
            assert!(!seen[usize::from(value)]);
            seen[usize::from(value)] = true;
            assert_eq!(
                usize::from(FIELD_TABLES.logarithm[usize::from(value)]),
                exponent
            );
        }
        assert!(seen[1..].iter().all(|value| *value));
        for exponent in 255..512 {
            assert_eq!(
                FIELD_TABLES.exponential[exponent],
                FIELD_TABLES.exponential[exponent % 255],
            );
        }
        for left in 1_u8..=u8::MAX {
            for right in 1_u8..=u8::MAX {
                let exponent = usize::from(FIELD_TABLES.logarithm[usize::from(left)])
                    + usize::from(FIELD_TABLES.logarithm[usize::from(right)]);
                assert!(exponent <= 508);
            }
        }
    }
}
