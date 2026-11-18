// Standalone timing fixture for the PackedWire receiver sensitivity study.
// Compile with rustc -O. The included kernel is the current Rust payload path.
#[path = "../../crates/l2tunnel-fec/src/rolling/gf_batch.rs"]
mod gf_batch;

use std::hint::black_box;
use std::time::Instant;

fn measure(dense: bool) -> Vec<f64> {
    const SYMBOL: usize = 1460;
    const ROWS: usize = 8192;
    let mut state = 7u32;
    let input: Vec<u8> = (0..SYMBOL * ROWS)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            if dense { state as u8 } else { 0 }
        })
        .collect();
    let mut dst = vec![0u8; SYMBOL];
    let mut samples = Vec::new();
    for round in 0..9 {
        let start = Instant::now();
        for (i, row) in black_box(&input).chunks_exact(SYMBOL).enumerate() {
            let factor = ((i + round) % 255 + 1) as u8;
            gf_batch::xor_scaled::<false>(black_box(&mut dst), row, factor);
        }
        let nanos = start.elapsed().as_secs_f64() * 1e9;
        black_box(&dst);
        if round > 0 {
            samples.push(nanos / input.len() as f64);
        }
    }
    samples
}

fn main() {
    println!(
        "{{\"zero_ns_per_byte\":{:?},\"dense_ns_per_byte\":{:?}}}",
        measure(false),
        measure(true)
    );
}
