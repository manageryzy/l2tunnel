// Process-static GF(256) multiplication rows for the already budgeted Rolling
// chunks. This is error-correction arithmetic, not a cryptographic primitive.
// The 64 KiB read-only table is generated at compile time: no owner allocation,
// runtime table construction, extra field-work credit or packet state exists.
const fn multiplication_rows() -> [[u8; 256]; 256] {
    let mut rows = [[0; 256]; 256];
    let mut factor = 0;
    while factor < 256 {
        let mut bit = 1;
        let mut product = factor as u16;
        while bit < 256 {
            let mut lower = 0;
            while lower < bit {
                rows[factor][bit + lower] = rows[factor][lower] ^ product as u8;
                lower += 1;
            }
            product <<= 1;
            if product & 0x100 != 0 {
                product ^= 0x11d;
            }
            bit <<= 1;
        }
        factor += 1;
    }
    rows
}
pub(super) static MULTIPLICATION_ROWS: [[u8; 256]; 256] = multiplication_rows();

pub(super) fn nonzero_bytes(word: u64) -> usize {
    // The low seven bits plus 127 cannot carry across any byte boundary.
    let high =
        (((word & 0x7f7f_7f7f_7f7f_7f7f) + 0x7f7f_7f7f_7f7f_7f7f) | word) & 0x8080_8080_8080_8080;
    high.count_ones() as usize
}

// The caller has already bounded and validated both slices and charges every
// logical GF byte, including zeros. Skip only physically redundant zero-word
// loads/stores. COUNT tracks exact before/after coefficient counts; payload
// chunks compile without those counters. No phase or source boundary is crossed.
pub(super) fn xor_scaled<const COUNT: bool>(
    destination: &mut [u8],
    input: &[u8],
    factor: u8,
) -> (usize, usize) {
    if factor == 0 {
        return (0, 0);
    }
    let table = &MULTIPLICATION_ROWS[usize::from(factor)];
    let (mut removed, mut added) = (0, 0);
    let mut destinations = destination.chunks_exact_mut(8);
    let mut inputs = input.chunks_exact(8);
    for (destination, input) in destinations.by_ref().zip(inputs.by_ref()) {
        let mut input_bytes = [0; 8];
        input_bytes.copy_from_slice(input);
        let input_word = u64::from_ne_bytes(input_bytes);
        if input_word == 0 {
            continue;
        }
        if COUNT {
            // Build the eight independent table products, then XOR/store and
            // count the word once. This avoids per-byte coefficient count
            // updates while preserving the same skipped words and exact totals.
            let product = if factor == 1 {
                input_word
            } else {
                u64::from_ne_bytes(input_bytes.map(|value| table[usize::from(value)]))
            };
            let mut old_bytes = [0; 8];
            old_bytes.copy_from_slice(destination);
            let old = u64::from_ne_bytes(old_bytes);
            let new = old ^ product;
            destination.copy_from_slice(&new.to_ne_bytes());
            removed += nonzero_bytes(old);
            added += nonzero_bytes(new);
        } else if factor == 1 {
            // Retain the existing payload kernel: the measured word-table
            // change benefits coefficient counting, not sparse payload blocks.
            let mut old_bytes = [0; 8];
            old_bytes.copy_from_slice(destination);
            let old = u64::from_ne_bytes(old_bytes);
            destination.copy_from_slice(&(old ^ input_word).to_ne_bytes());
        } else {
            for (destination, value) in destination.iter_mut().zip(input) {
                *destination ^= table[usize::from(*value)];
            }
        }
    }
    for (destination, value) in destinations
        .into_remainder()
        .iter_mut()
        .zip(inputs.remainder())
    {
        if COUNT {
            removed += usize::from(*destination != 0);
        }
        *destination ^= table[usize::from(*value)];
        if COUNT {
            added += usize::from(*destination != 0);
        }
    }
    (removed, added)
}
