//! Exact bounded support and coefficient policies for the three research modes.
//!
//! The recursive equation is expanded over original source IDs. This computes
//! the same parity value as accumulating every intervening check, including a
//! check whose transmitted slot was replaced by fresh fallback. A fallback slot
//! never resets or removes that implicit history. The only reset is the agreed
//! periodic repair-serial boundary. No payload or clock is held by this policy.

use sha2::{Digest, Sha256};

use crate::field::compact_coefficient;
use crate::rolling::{Error, MAX_WINDOW, Support};

/// Fixed repair credit numerator from the Python checkpoint scheduler.
pub const REPAIR_NUMERATOR: u32 = 26;
/// Fixed repair credit denominator from the Python checkpoint scheduler.
pub const REPAIR_DENOMINATOR: u32 = 125;
/// Packet seeds multiply the full nonwrapping repair serial modulo 2^32.
pub const SERIAL_MULTIPLIER: u32 = 2_654_435_761;
/// Hard CPU bound: at most this many single-block SHA256 evaluations per source.
pub const MAX_TAPS: u8 = 16;
/// Maximum independently repeated accumulator coefficient lanes.
pub const MAX_LANES: u16 = 256;

/// Negotiated pure policy; validate before allocating an owner or accepting input.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Profile {
    /// Source-regular recursive parity, optionally replacing periodic wire slots.
    Recursive {
        /// One future check in each of these bands; zero selects dense control.
        taps: u8,
        /// Number of repairs in a tap band; zero only for dense control.
        width: u16,
        /// Reset after this many repairs, including fallback replacement slots.
        reset: u16,
        /// Replace every Nth slot with fresh prefix coefficients; zero disables.
        fresh_interval: u16,
    },
    /// Repeated lane coefficients over an acknowledged-prefix-bounded window.
    Accumulator {
        /// Repeated seed count; zero selects the fresh dense control.
        lanes: u16,
        /// Local support span; every sixteenth slot uses the full unacked prefix.
        window: u16,
    },
}

/// Actual coefficient construction used by one charged repair slot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RepairMode {
    /// Fresh counter coefficients, including dense-control and global slots.
    Dense,
    /// Source-regular recursively accumulated checks since the periodic reset.
    Recursive,
    /// A fresh-prefix replacement; recursive check history still advances.
    Fallback,
    /// A repeated lane seed over the configured rolling support.
    Accumulator,
}

impl Profile {
    /// Check scalar limits and the hard scheduled-support ceiling without allocation.
    ///
    /// Unacknowledged global support still needs an independent owner bound:
    /// feedback loss must cause backpressure, never implicit support truncation.
    pub fn validate(self) -> Result<(), Error> {
        match self {
            Self::Recursive {
                taps,
                width,
                reset,
                fresh_interval,
            } => {
                if taps > MAX_TAPS
                    || reset == 0
                    || (taps == 0 && (width != 0 || fresh_interval != 0))
                    || (taps != 0 && width == 0)
                {
                    return Err(Error::Configuration);
                }
            }
            Self::Accumulator { lanes, window } => {
                if lanes > MAX_LANES || window == 0 || usize::from(window) > MAX_WINDOW {
                    return Err(Error::Configuration);
                }
            }
        }
        if self.minimum_window_unchecked() > MAX_WINDOW {
            return Err(Error::Configuration);
        }
        Ok(())
    }

    /// Conservative source-history span under the fixed 26/125 send schedule.
    ///
    /// Five extra sources cover the largest gap between charged repair slots.
    /// The owner must additionally bound the unacknowledged prefix needed for
    /// global/fallback repair and reject pressure rather than shorten a support.
    pub fn minimum_window(self) -> Result<usize, Error> {
        self.validate()?;
        Ok(self.minimum_window_unchecked())
    }

    fn minimum_window_unchecked(self) -> usize {
        match self {
            Self::Recursive { taps: 0, .. } => 128,
            Self::Recursive {
                taps, width, reset, ..
            } => {
                let span = u32::from(reset) + u32::from(taps) * u32::from(width);
                (u64::from(span) * u64::from(REPAIR_DENOMINATOR))
                    .div_ceil(u64::from(REPAIR_NUMERATOR)) as usize
                    + 5
            }
            Self::Accumulator { window, .. } => usize::from(window),
        }
    }

    /// Determine the mode from the complete one-based serial, never its low bits.
    pub fn mode(self, serial: u32) -> Result<RepairMode, Error> {
        self.validate()?;
        if serial == 0 {
            return Err(Error::Identity);
        }
        Ok(match self {
            Self::Recursive { taps: 0, .. } => RepairMode::Dense,
            Self::Recursive { fresh_interval, .. }
                if fresh_interval != 0 && serial.is_multiple_of(u32::from(fresh_interval)) =>
            {
                RepairMode::Fallback
            }
            Self::Recursive { .. } => RepairMode::Recursive,
            Self::Accumulator { lanes: 0, .. } => RepairMode::Dense,
            Self::Accumulator { .. } if serial.is_multiple_of(16) => RepairMode::Dense,
            Self::Accumulator { .. } => RepairMode::Accumulator,
        })
    }

    /// Derive the exact nonempty support, checked against the common hard limit.
    ///
    /// Recursive spans intentionally ignore feedback. Dense global and fallback
    /// spans start at the authenticated cumulative receipt; local dense/lane
    /// spans also respect that receipt. No expired/forgotten source is removed
    /// from a still-required equation. A missing retained source is an owner error.
    pub fn support(self, end: u32, confirmed: u32, serial: u32) -> Result<Support, Error> {
        let mode = self.mode(serial)?;
        if end == 0 || confirmed > end {
            return Err(Error::Identity);
        }
        let start = match mode {
            RepairMode::Recursive => self.recursive_start(serial)?,
            RepairMode::Fallback => confirmed,
            RepairMode::Dense | RepairMode::Accumulator => {
                if serial.is_multiple_of(16) {
                    confirmed
                } else {
                    let window = match self {
                        Self::Accumulator { window, .. } => u32::from(window),
                        Self::Recursive { .. } => 128,
                    };
                    confirmed.max(end.saturating_sub(window))
                }
            }
        };
        if start >= end {
            return Err(Error::Identity);
        }
        if u64::from(end - start) > MAX_WINDOW as u64 {
            return Err(Error::Capacity);
        }
        Ok(Support {
            start,
            end,
            seed: serial.wrapping_mul(SERIAL_MULTIPLIER),
            tail: false,
        })
    }

    /// Earliest source needed by this and future scheduled repairs.
    ///
    /// Pass the next repair serial. All modes retain the unconfirmed prefix;
    /// recursive modes additionally retain acknowledged originals whose tap
    /// expansion is still live. Fallback slots cannot move this floor forward.
    pub fn retention_floor(self, serial: u32, end: u32, confirmed: u32) -> Result<u32, Error> {
        self.mode(serial)?;
        if confirmed > end {
            return Err(Error::Identity);
        }
        match self {
            Self::Recursive { taps, .. } if taps != 0 => {
                Ok(confirmed.min(self.recursive_start(serial)?).min(end))
            }
            _ => Ok(confirmed),
        }
    }

    /// Exact one-source coefficient, with no allocation or GF primitive duplication.
    ///
    /// One evaluation is a bounded metadata operation: at most sixteen hashes,
    /// each over a single SHA256 block, or one existing compact counter mix.
    /// Hashes select coding taps; they do not authenticate packets or derive keys.
    pub fn coefficient(self, serial: u32, source: u32) -> Result<u8, Error> {
        match self.mode(serial)? {
            RepairMode::Recursive => {
                let Self::Recursive {
                    taps, width, reset, ..
                } = self
                else {
                    return Err(Error::Configuration);
                };
                let first = epoch_start(serial, reset);
                let mut value = 0;
                for edge in 0..taps {
                    let (check, weight) = source_tap(source, edge, width);
                    if u64::from(first) <= check && check <= u64::from(serial) {
                        value ^= weight;
                    }
                }
                Ok(value)
            }
            RepairMode::Accumulator => {
                let Self::Accumulator { lanes, .. } = self else {
                    return Err(Error::Configuration);
                };
                let seed = 0xa5b3_0000 + serial % u32::from(lanes);
                Ok(compact_coefficient(seed, source))
            }
            RepairMode::Dense | RepairMode::Fallback => Ok(compact_coefficient(
                serial.wrapping_mul(SERIAL_MULTIPLIER),
                source,
            )),
        }
    }

    fn recursive_start(self, serial: u32) -> Result<u32, Error> {
        let Self::Recursive {
            taps, width, reset, ..
        } = self
        else {
            return Err(Error::Configuration);
        };
        let first = u64::from(epoch_start(serial, reset));
        let age = u64::from(taps) * u64::from(width);
        // Python's max(0, (earliest-1)*125//26) is exactly this saturating form.
        let source = first.saturating_sub(age + 1) * u64::from(REPAIR_DENOMINATOR)
            / u64::from(REPAIR_NUMERATOR);
        u32::try_from(source).map_err(|_| Error::Exhausted)
    }
}

fn epoch_start(serial: u32, reset: u16) -> u32 {
    ((serial - 1) / u32::from(reset)) * u32::from(reset) + 1
}

fn source_tap(source: u32, edge: u8, width: u16) -> (u64, u8) {
    let mut hash = Sha256::new();
    hash.update(b"recursive-parity-v1/");
    hash_decimal(&mut hash, source);
    hash.update(b"/");
    hash_decimal(&mut hash, u32::from(edge));
    let digest = hash.finalize();
    let offset =
        u32::from_be_bytes([digest[0], digest[1], digest[2], digest[3]]) % u32::from(width);
    let weight = 1 + u32::from_be_bytes([digest[4], digest[5], digest[6], digest[7]]) % 255;
    let first = u64::from(REPAIR_NUMERATOR) * u64::from(source) / u64::from(REPAIR_DENOMINATOR) + 1;
    (
        first + u64::from(edge) * u64::from(width) + u64::from(offset),
        weight as u8,
    )
}

fn hash_decimal(hash: &mut Sha256, mut value: u32) {
    let mut digits = [0; 10];
    let mut start = digits.len();
    loop {
        start -= 1;
        digits[start] = b'0' + (value % 10) as u8;
        value /= 10;
        if value == 0 {
            break;
        }
    }
    hash.update(&digits[start..]);
}

#[cfg(test)]
mod tests;
