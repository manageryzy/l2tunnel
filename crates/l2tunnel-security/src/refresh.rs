//! Explicit common-v2 key refresh. Authority and key owners have no public
//! metadata-only constructor; low-level split import is a trusted adapter seam.

mod authority;
mod owners;
mod selection;

use crate::Error as ProtectionError;
pub use authority::{
    Admission, Context, Initial, Joining, Material, Request, prologue_hash, psk_commitment,
};
pub use owners::{
    Activation, ActivationOutcome, Class, Opened, Owners, Prepared, RequestOutcome, Sealed, Started,
};
pub use selection::{Selection, SelectionSpec};
use std::fmt;

/// Caller-injected monotonic microseconds, never a wall clock.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct Tick(pub u64);
/// Nonwrapping fresh-DH selector, independent of data epoch and ratchet generation.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct KeyEpoch(pub u64);
/// Exact common-v2 prefix; authentication tags are unchanged.
pub const PREFIX_BYTES: usize = 26;
/// Fixed request and refresh-flight context header size.
pub const REQUEST_BYTES: usize = 72;

/// Bounded failure without keys, packet bodies or provider strings.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// Invalid immutable selection.
    Configuration,
    /// Binding, target or credential context does not match.
    Context,
    /// The entry point does not match the selected protocol.
    Mode,
    /// Initial domain ownership cannot be transferred safely.
    Domains,
    /// Operation does not fit the current phase.
    State,
    /// Another live target or key slot is retained.
    Busy,
    /// Different bytes reuse an admitted operation.
    Conflict,
    /// Target was already allocated and retired/canceled.
    Retired,
    /// Caller moved the monotonic clock backward.
    TimeRegression,
    /// Original session or operation deadline was reached.
    Deadline,
    /// Original key age expired.
    KeyExpired,
    /// Old receive-key overlap is still required.
    OverlapActive,
    /// No further unique epoch can be allocated.
    EpochExhausted,
    /// Bounded flight-copy allowance is exhausted.
    CopiesExhausted,
    /// A bounded fallible backing reservation failed.
    Allocation,
    /// Existing maintained packet protection rejected the operation.
    Protection(ProtectionError),
}
impl From<ProtectionError> for Error {
    fn from(value: ProtectionError) -> Self {
        Self::Protection(value)
    }
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "session refresh: {self:?}")
    }
}
impl std::error::Error for Error {}

pub(super) fn add(at: Tick, micros: u64) -> Result<Tick, Error> {
    at.0.checked_add(micros)
        .map(Tick)
        .ok_or(Error::Configuration)
}
