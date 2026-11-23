//! TCP-shaped 32-bit sequence and acknowledgment numbers for 64-bit byte positions.
//!
//! Positions are counted from the base number agreed at handoff and wrap modulo
//! 2^32 on the wire, as in RFC 9293. No field is added: the receiver recovers the
//! unique 64-bit position within 2^31 of a position it already holds. Every caller
//! then bounds the result by its byte horizon (at most 64 KiB << 14 = 1 GiB),
//! which is far below 2^31, so a recovered position is never ambiguous.

/// Wire number of `position` bytes after `base`.
pub(in crate::handoff::pairing::packet) fn wire(base: u32, position: u64) -> u32 {
    // Truncation to the low 32 bits is the modular sequence space itself.
    base.wrapping_add(position as u32)
}

/// Unique non-negative position of `number` within 2^31 of `reference`.
pub(in crate::handoff::pairing::packet) fn position(
    base: u32,
    number: u32,
    reference: u64,
) -> Option<u64> {
    let delta = number.wrapping_sub(base).wrapping_sub(reference as u32) as i32;
    reference.checked_add_signed(i64::from(delta))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn positions_round_trip_across_the_wrap_for_any_base() {
        for base in [0, 1, 4_284_835_201, u32::MAX - 263, u32::MAX] {
            for position_value in [0u64, 263, 264, 10_131_831, 1 << 32, (1 << 32) + 5, 3 << 33] {
                let number = wire(base, position_value);
                for reference in [
                    position_value,
                    position_value.saturating_sub(1 << 20),
                    position_value + (1 << 20),
                ] {
                    assert_eq!(position(base, number, reference), Some(position_value));
                }
            }
        }
    }

    #[test]
    fn the_failed_lab_run_continues_past_the_old_limit() {
        // Router capture of the exhausted run: first 4_284_835_201, last 0xfffffef8.
        let base = 4_284_835_201;
        let at_limit = u64::from(0xffff_fef8u32 - base);
        let next = at_limit + 1_460;
        let number = wire(base, next);
        assert!(number < base, "the wire number wrapped");
        assert_eq!(position(base, number, at_limit), Some(next));
    }

    #[test]
    fn positions_before_zero_and_beyond_half_the_space_are_not_recovered_as_valid() {
        assert_eq!(position(100, 99, 0), None);
        // More than 2^31 ahead reads as behind the reference: here before zero.
        let far = wire(7, 1_000_000 + (1 << 31) + 1);
        assert_eq!(position(7, far, 1_000_000), None);
        // With room behind, it maps to the nearer (older) position, which the
        // caller's horizon check then rejects.
        let reference = 3u64 << 31;
        let ahead = wire(7, reference + (1 << 31) + 1);
        assert_eq!(
            position(7, ahead, reference),
            Some(reference - ((1 << 31) - 1))
        );
    }
}
