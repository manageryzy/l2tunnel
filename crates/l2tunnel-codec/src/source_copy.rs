//! Explicit copy selection over exact meaningful aligned units, before packing.
//! This supplies no authentication, recovery identity or physical-send authority.

use crate::packed;
use std::fmt;

/// Which short units can request additional physical copies.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Scope {
    /// Every valid unit within the threshold, including a record fragment.
    AllShort,
    /// Only complete explicit context and self-contained raw record units.
    ContextAndIndependent,
}

/// Immutable explicit sender selection; never inferred from TCP flags or probes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Policy {
    /// Maximum meaningful aligned-unit bytes, including channel/serial/header.
    /// Zero disables extra copies; L2PK metadata and outer bytes are excluded.
    pub max_unit_bytes: usize,
    /// Complete physical copies for selected units, in the supported range1..4.
    pub copies: u8,
    /// Generic short-size or exact context/independent record selection.
    pub scope: Scope,
}
impl Policy {
    /// Existing one-copy behavior, without short-unit selection.
    pub const ONE: Self = Self {
        max_unit_bytes: 0,
        copies: 1,
        scope: Scope::AllShort,
    };

    /// Validate all local bounds before allocation or sender ownership changes.
    pub fn validate(self, symbol_bytes: usize) -> Result<(), Error> {
        packed::Config {
            symbol_bytes,
            hold_micros: 1,
        }
        .memory_bound_bytes()
        .map_err(|_| Error::Configuration)?;
        if self.max_unit_bytes > symbol_bytes || !(1..=4).contains(&self.copies) {
            return Err(Error::Configuration);
        }
        Ok(())
    }

    /// Classify one canonical meaningful unit without changing any sender state.
    /// The threshold applies before packing, generated padding or outer framing.
    pub fn copies_for_unit(self, unit: &[u8], symbol_bytes: usize) -> Result<u8, Error> {
        self.validate(symbol_bytes)?;
        packed::validate_unit(unit, symbol_bytes).map_err(Error::Unit)?;
        if unit.len() > self.max_unit_bytes {
            return Ok(1);
        }
        if self.scope == Scope::AllShort {
            return Ok(self.copies);
        }
        if unit.len() < 6 {
            return Ok(1);
        }
        let kind = unit[3];
        let length = usize::from(u16::from_be_bytes([unit[4], unit[5]]));
        Ok(
            if unit.len() == 6 + length && (kind == 2 || kind == 0 && length == 66) {
                self.copies
            } else {
                1
            },
        )
    }
}
impl Default for Policy {
    fn default() -> Self {
        Self::ONE
    }
}

/// Explicit unsupported-policy or malformed-unit refusal, without clamping.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// Invalid geometry, threshold or supported physical-copy count.
    Configuration,
    /// The maintained packed-unit parser rejected the exact meaningful bytes.
    Unit(packed::Error),
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "source copy policy: {self:?}")
    }
}
impl std::error::Error for Error {}

#[cfg(test)]
#[path = "source_copy_tests.rs"]
mod tests;
