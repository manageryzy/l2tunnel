//! Charged recursive parity, fresh-prefix fallback and rolling-accumulator protocols.
//!
//! These pure owners encode and recover real payloads using the existing rolling
//! GF engine. Authenticate/replay-check enclosing records and bind the complete
//! configuration before admission. Completion here means buffer custody or
//! recovery handoff, never native delivery. No runtime mode is enabled by this module.
use crate::rolling;
pub use rolling::scheduler::FeedbackId;
pub use rolling::{
    Begin, DecodeStep, Error, RepairId, Scope, SourceId, Tick, WorkBudget, WorkUsed,
};

pub mod policy;
mod receiver;
mod sender;
pub mod storage;
pub mod wire;
pub use policy::{Profile, RepairMode};
pub use receiver::{Receiver, ReceiverStatus, ReceiverStep};
pub use sender::{FeedbackDisposition, Output, OutputId, Sender, SenderStatus};

/// Complete immutable local resource and negotiated algorithm configuration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Config {
    /// Existing rolling payload, history, rank, deadline and memory bounds.
    /// Its local/global selection fields are unused by these explicitly selected profiles.
    pub recovery: rolling::Config,
    /// Exact Python coefficient/support policy, bound to the authenticated epoch.
    pub profile: Profile,
    /// Minimum interval between packet-triggered feedback snapshots, in caller ticks.
    /// Set to five milliseconds in the caller's tick unit for the Python study policy.
    pub feedback_ticks: u64,
    /// Complete conservative owner bound including its inline wrapper.
    pub memory_bytes: usize,
}
impl Config {
    /// Validate all scalar limits and the conservative recursive retention span.
    pub fn validate(self) -> Result<(), Error> {
        self.recovery.validate()?;
        self.profile.validate()?;
        if self.recovery.window < self.profile.minimum_window()?
            || self.feedback_ticks == 0
            || self.feedback_ticks >= self.recovery.debt_ticks
            || self.memory_bytes == 0
            || self.memory_bytes > rolling::MAX_MEMORY
        {
            return Err(Error::Configuration);
        }
        Ok(())
    }
}

/// An immutable expanded equation plus the sender's actual frozen receipt prefix.
#[derive(Clone, Copy, Debug)]
pub struct Repair<'a> {
    /// Real coded length and effective payload prefix under a canonical support.
    pub equation: rolling::Repair<'a>,
    /// Cumulative prefix known to the sender when this equation was scheduled.
    pub confirmed: u32,
}
impl Repair<'_> {
    /// Validate the fixed charged schedule and exact support without allocating.
    pub fn validate(self, config: Config) -> Result<(), Error> {
        config.validate()?;
        let serial = u32::try_from(self.equation.id.0).map_err(|_| Error::Identity)?;
        if serial == 0 {
            return Err(Error::Length);
        }
        self.equation.validate_extent(config.recovery.width()?)?;
        let expected_end = (u64::from(serial) * 125).div_ceil(26);
        if expected_end != u64::from(self.equation.support.end)
            || config
                .profile
                .support(self.equation.support.end, self.confirmed, serial)?
                != self.equation.support
            || self.equation.support.end - self.equation.support.start
                > config.recovery.window as u32
        {
            return Err(Error::Identity);
        }
        Ok(())
    }
}

/// Cumulative recovery receipt; no receiver-rank or hidden loss oracle is used.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Feedback {
    /// Authenticated forward stream being acknowledged.
    pub scope: Scope,
    /// Nonwrapping receipt identity, beginning at one.
    pub id: FeedbackId,
    /// Committed contiguous recovered prefix; separate from upper handoff.
    pub prefix: u32,
    /// Highest committed observed source end.
    pub observed_end: u32,
}
impl Feedback {
    /// Validate structure; authentication and causal sender bounds are separate.
    pub fn validate(self, config: Config) -> Result<(), Error> {
        config.validate()?;
        let extent = self
            .observed_end
            .checked_sub(self.prefix)
            .ok_or(Error::Identity)?;
        if self.id.0 == 0 || self.id.0 == u64::MAX || extent > config.recovery.window as u32 {
            return Err(Error::Identity);
        }
        Ok(())
    }
    /// Exact protocol bytes plus caller-supplied actual reverse encapsulation cost.
    pub fn charge(self, overhead: usize) -> Result<usize, Error> {
        add(wire::HEADER_BYTES, overhead)
    }
}

pub(super) fn add(a: usize, b: usize) -> Result<usize, Error> {
    a.checked_add(b).ok_or(Error::Exhausted)
}
pub(super) fn deadline(now: Tick, ticks: u64) -> Result<Tick, Error> {
    now.0.checked_add(ticks).map(Tick).ok_or(Error::Exhausted)
}
pub(super) fn check_time(last: Tick, now: Tick, deadlines: &[Option<Tick>]) -> Result<(), Error> {
    if now < last {
        return Err(Error::TimeRegression);
    }
    if deadlines.iter().flatten().any(|end| now >= *end) {
        return Err(Error::Expired);
    }
    Ok(())
}

#[cfg(test)]
mod tests;
