//! GF(2^8) arithmetic over the polynomial x^8 + x^4 + x^3 + x^2 + 1 (0x11D).

const fn build() -> [[u8; 256]; 256] {
    let mut exp = [0u8; 512];
    let mut log = [0u8; 256];
    let mut value: u16 = 1;
    let mut index = 0;
    while index < 255 {
        exp[index] = value as u8;
        log[value as usize] = index as u8;
        value <<= 1;
        if value & 0x100 != 0 {
            value ^= 0x11D;
        }
        index += 1;
    }
    while index < 512 {
        exp[index] = exp[index - 255];
        index += 1;
    }
    let mut table = [[0u8; 256]; 256];
    let mut a = 1;
    while a < 256 {
        let mut b = 1;
        while b < 256 {
            table[a][b] = exp[log[a] as usize + log[b] as usize];
            b += 1;
        }
        a += 1;
    }
    table
}

static MUL: [[u8; 256]; 256] = build();

/// Field product.
pub fn mul(a: u8, b: u8) -> u8 {
    MUL[usize::from(a)][usize::from(b)]
}

/// Multiplicative inverse; zero has none.
pub fn inv(a: u8) -> Option<u8> {
    if a == 0 {
        return None;
    }
    (1..=255u8).find(|candidate| mul(a, *candidate) == 1)
}

/// `destination[i] ^= factor * source[i]` over the common prefix.
pub fn mul_add(destination: &mut [u8], source: &[u8], factor: u8) {
    match factor {
        0 => (),
        1 => {
            for (d, s) in destination.iter_mut().zip(source) {
                *d ^= *s;
            }
        }
        _ => {
            let row = &MUL[usize::from(factor)];
            for (d, s) in destination.iter_mut().zip(source) {
                *d ^= row[usize::from(*s)];
            }
        }
    }
}

/// `values[i] = factor * values[i]`.
pub fn scale(values: &mut [u8], factor: u8) {
    if factor == 1 {
        return;
    }
    let row = &MUL[usize::from(factor)];
    for value in values {
        *value = row[usize::from(*value)];
    }
}

/// Deterministic nonzero coefficient both peers derive from a repair's seed
/// and a source sequence number. It carries no secrecy; packets are
/// authenticated by the carrier.
pub fn coefficient(seed: u64, sequence: u32) -> u8 {
    let mut x = seed ^ (u64::from(sequence).wrapping_mul(0x9E37_79B9_7F4A_7C15));
    x ^= x >> 30;
    x = x.wrapping_mul(0xBF58_476D_1CE4_E5B9);
    x ^= x >> 27;
    x = x.wrapping_mul(0x94D0_49BB_1331_11EB);
    x ^= x >> 31;
    1 + (x % 255) as u8
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn field_axioms_hold_for_every_element() {
        for a in 0..=255u8 {
            assert_eq!(mul(a, 1), a);
            assert_eq!(mul(a, 0), 0);
            if let Some(inverse) = inv(a) {
                assert_eq!(mul(a, inverse), 1);
            } else {
                assert_eq!(a, 0);
            }
            for b in [3u8, 29, 200, 255] {
                assert_eq!(mul(a, b), mul(b, a));
                for c in [7u8, 91] {
                    assert_eq!(mul(a, b ^ c), mul(a, b) ^ mul(a, c));
                    assert_eq!(mul(mul(a, b), c), mul(a, mul(b, c)));
                }
            }
        }
        // x * x^7 reduces by the generator polynomial.
        assert_eq!(mul(2, 0x80), 0x1D);
    }
    #[test]
    fn vector_helpers_match_scalar_products() {
        let source: Vec<u8> = (0..=255).collect();
        for factor in [0u8, 1, 2, 77, 255] {
            let mut destination = vec![0x5A; 256];
            mul_add(&mut destination, &source, factor);
            let mut scaled = source.clone();
            scale(&mut scaled, factor.max(1));
            for (index, value) in destination.iter().enumerate() {
                assert_eq!(*value, 0x5A ^ mul(factor, index as u8));
                assert_eq!(scaled[index], mul(factor.max(1), index as u8));
            }
        }
        assert!((0..10_000u32).all(|s| coefficient(42, s) != 0));
        assert_ne!(coefficient(1, 5), coefficient(2, 5));
    }
}
