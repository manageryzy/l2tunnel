//! Bounded fixed-window equations over real bytes, separate from sealed block FEC.
//!
//! Authenticate and replay-check enclosing records before admission. This module
//! has no wire transport, clock or native-delivery proof. The additive pure
//! scheduler owns causal repair/feedback timing at explicit caller handoffs.
use std::fmt;

mod decoder;
mod encoder;
pub mod scheduler;
pub mod storage;
pub mod wire;
pub use decoder::{Begin, DecodeStep, Decoder, DecoderStatus};
pub use encoder::{Encoder, EncoderStatus};

/// Maximum fixed support; this does not change the sealed-block source limit.
pub const MAX_WINDOW: usize = 8192;
/// Maximum original payload, excluding the coded two-byte length.
pub const MAX_PAYLOAD: usize = 4096;
/// Hard reservation ceiling, excluding the caller's buffers.
pub const MAX_MEMORY: usize = 512 * 1024 * 1024;
/// Maximum units in each work-budget component for one service call.
pub const MAX_STEP_WORK: usize = 65_536;

/// Authenticated outer domain, not an authenticator itself.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Scope {
    /// Full authenticated session identity.
    pub session: [u8; 16],
    /// Negotiated epoch.
    pub epoch: u64,
    /// Logical coding stream.
    pub stream: u32,
    /// Global direction, encoded by the caller's negotiated profile.
    pub direction: u8,
}
/// Absolute nonwrapping source ID; renew before allocating u32::MAX.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct SourceId(pub u32);
/// Independent nonwrapping repair identity, starting at one.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct RepairId(pub u64);
/// Caller-injected monotonic ticks; their unit is fixed by the embedding profile.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct Tick(pub u64);

/// Finite fixed-window policy and storage/deadline limits.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Config {
    /// Maximum fixed support, in 1..=8192.
    pub window: usize,
    /// Regular local support, in 1..=window.
    pub local_window: usize,
    /// Every Gth transmitted 15-bit serial selects global support, in 1..=32768.
    pub global_every: u16,
    /// Maximum original bytes, in 1..=4096.
    pub max_payload: usize,
    /// Maximum simultaneous independent rows, in 1..=window.
    pub max_rows: usize,
    /// Bounded exact repair-copy history, in 1..=16384.
    pub repair_history: usize,
    /// Maximum published but not handed-off contiguous sources, in 1..=window.
    pub handoff_sources: usize,
    /// Original age limit for a staged job.
    pub job_ticks: u64,
    /// Original unresolved-debt age until all observed/admitted sources confirm.
    pub debt_ticks: u64,
    /// Original age for pending upper-layer handoff.
    pub handoff_ticks: u64,
    /// Maximum conservative reservation for each constructed owner.
    pub memory_bytes: usize,
}
impl Config {
    /// Validate scalar limits without allocating.
    pub fn validate(self) -> Result<(), Error> {
        if !(1..=MAX_WINDOW).contains(&self.window)
            || !(1..=self.window).contains(&self.local_window)
            || !(1..=32768).contains(&self.global_every)
            || !(1..=MAX_PAYLOAD).contains(&self.max_payload)
            || !(1..=self.window).contains(&self.max_rows)
            || !(1..=16384).contains(&self.repair_history)
            || !(1..=self.window).contains(&self.handoff_sources)
            || self.job_ticks == 0
            || self.debt_ticks == 0
            || self.handoff_ticks == 0
            || self.job_ticks > self.debt_ticks
            || !(1..=MAX_MEMORY).contains(&self.memory_bytes)
        {
            return Err(Error::Configuration);
        }
        Ok(())
    }
    /// Fixed coded width, including exact original length.
    pub fn width(self) -> Result<usize, Error> {
        self.validate()?;
        Ok(self.max_payload + 2)
    }
    /// Derive canonical fixed support and seed from the complete repair identity.
    pub fn support(self, end: u32, id: RepairId, tail: bool) -> Result<Support, Error> {
        self.validate()?;
        if end == 0 || id.0 == 0 {
            return Err(Error::Identity);
        }
        let serial = (id.0 & 0x7fff) as u16;
        let global = tail || serial.is_multiple_of(self.global_every);
        let count = if global {
            self.window
        } else {
            self.local_window
        } as u32;
        let seed_serial = if tail { id.0 as u32 } else { u32::from(serial) };
        Ok(Support {
            start: end.saturating_sub(count),
            end,
            seed: seed_serial.wrapping_mul(2_654_435_761),
            tail,
        })
    }
}
/// Canonical immutable support; the decoder derives and checks every field.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Support {
    /// Inclusive original source ID.
    pub start: u32,
    /// Exclusive original source ID.
    pub end: u32,
    /// Deterministic coding seed, not a cryptographic secret.
    pub seed: u32,
    /// Tail repairs always use global support.
    pub tail: bool,
}
/// Borrowed complete encoded equation; authentication is supplied by the caller.
#[derive(Clone, Copy, Debug)]
pub struct Repair<'a> {
    /// Authenticated enclosing domain.
    pub scope: Scope,
    /// Full nonwrapping replay identity.
    pub id: RepairId,
    /// Exact checked support and seed.
    pub support: Support,
    /// Complete fixed-width coded bytes; trimming is not implemented.
    pub bytes: &'a [u8],
}
/// Independent per-call work caps; all-zero is a no-op.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct WorkBudget {
    /// GF byte multiplication/XOR or normalization operations.
    pub field: usize,
    /// Bytes copied, compared or cleared.
    pub copies: usize,
    /// Bounded metadata/phase visits, including coefficient generation.
    pub metadata: usize,
}
impl WorkBudget {
    fn validate(self) -> Result<(), Error> {
        if [self.field, self.copies, self.metadata]
            .into_iter()
            .any(|v| v > MAX_STEP_WORK)
        {
            return Err(Error::WorkLimit);
        }
        Ok(())
    }
}
/// Work actually consumed by a call, never exceeding its budget.
pub type WorkUsed = WorkBudget;

/// Explicit parser, resource, time and equation errors.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// Configuration or reservation is invalid.
    Configuration,
    /// Checked arithmetic or identity space is exhausted.
    Exhausted,
    /// Fixed storage cannot admit this operation.
    Capacity,
    /// Another owned operation/output is pending.
    Busy,
    /// Context differs from the configured authenticated domain.
    Scope,
    /// Source/repair identity or derived support is invalid.
    Identity,
    /// Original or coded length/padding is malformed.
    Length,
    /// Rolling wire magic, version, kind, flags or reserved fields are invalid.
    Format,
    /// An exact retained identity arrived with different bytes.
    Conflict,
    /// Received equations are algebraically inconsistent.
    Inconsistent,
    /// Time regressed.
    TimeRegression,
    /// An original deadline expired.
    Expired,
    /// A caller work budget exceeds a hard bound.
    WorkLimit,
    /// Output storage is too small; pending bytes are unchanged.
    OutputTooSmall,
    /// Owner previously failed terminally.
    Terminal,
    /// Fallible allocation failed.
    Allocation,
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "rolling recovery: {self:?}")
    }
}
impl std::error::Error for Error {}

fn bytes(count: usize) -> Result<Vec<u8>, Error> {
    let mut value = Vec::new();
    value
        .try_reserve_exact(count)
        .map_err(|_| Error::Allocation)?;
    value.resize(count, 0);
    Ok(value)
}
fn slots<T: Clone>(count: usize, initial: T) -> Result<Vec<T>, Error> {
    let mut value = Vec::new();
    value
        .try_reserve_exact(count)
        .map_err(|_| Error::Allocation)?;
    value.resize(count, initial);
    Ok(value)
}
fn add(left: usize, right: usize) -> Result<usize, Error> {
    left.checked_add(right).ok_or(Error::Exhausted)
}
fn mul(left: usize, right: usize) -> Result<usize, Error> {
    left.checked_mul(right).ok_or(Error::Exhausted)
}
fn deadline(now: Tick, ticks: u64) -> Result<Tick, Error> {
    now.0.checked_add(ticks).map(Tick).ok_or(Error::Exhausted)
}
fn check_time(last: Tick, now: Tick, deadlines: &[Option<Tick>]) -> Result<(), Error> {
    if now < last {
        return Err(Error::TimeRegression);
    }
    if deadlines.iter().flatten().any(|end| now >= *end) {
        return Err(Error::Expired);
    }
    Ok(())
}
fn spend(value: &mut usize) -> bool {
    if *value == 0 {
        false
    } else {
        *value -= 1;
        true
    }
}
fn used(before: WorkBudget, after: WorkBudget) -> WorkUsed {
    WorkUsed {
        field: before.field - after.field,
        copies: before.copies - after.copies,
        metadata: before.metadata - after.metadata,
    }
}

#[cfg(test)]
mod tests;
