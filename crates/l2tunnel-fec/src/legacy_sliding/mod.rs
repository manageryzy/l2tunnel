//! Real-byte legacy sliding/hybrid RLNC with causal repair and residual ARQ.
//!
//! Authenticate records, replay-check their enclosing transport and bind this
//! entire configuration to the epoch before admission. Caller-injected time and
//! physical output confirmations drive scheduling; no runtime mode is enabled.
use crate::rolling;
pub use rolling::explicit::Term;
pub use rolling::scheduler::FeedbackId;
pub use rolling::{
    Begin, DecodeStep, Error, RepairId, Scope, SourceId, Tick, WorkBudget, WorkUsed,
};

pub mod batch;
pub mod batch_wire;
mod receiver;
mod sender;
pub mod storage;
pub mod wire;
pub use receiver::{Receiver, ReceiverStatus, ReceiverStep};
pub use sender::{FeedbackDisposition, Output, OutputId, Sender, SenderStatus};

/// Python legacy support selection, independently selected from Research modes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Mode {
    /// Every periodic equation covers the last long-window sources.
    Sliding,
    /// Every `long_every`th periodic equation is long; others are short.
    Hybrid,
}

/// Negotiated immutable policy and explicit local resource limits.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Config {
    /// Existing real GF decoder, storage, history and original age limits.
    /// Local/global seed-policy fields are unused. The forward window is at most
    /// 255; committed known sources awaiting handoff can span twice that window.
    pub recovery: rolling::Config,
    /// Periodic support selection.
    pub mode: Mode,
    /// Maximum recent admitted sources in a periodic equation, in 1..=255.
    pub long_window: u16,
    /// Hybrid short support, in 1..=long_window.
    pub short_window: u16,
    /// Every Nth periodic hybrid equation uses long support, in 1..=255.
    pub long_every: u16,
    /// Integer credit denominator and noninterleaved source-group size.
    pub repair_every: u16,
    /// Integer credit numerator and full-group repair count.
    pub repairs_per_group: u16,
    /// Use integer credit; timer flush still emits at least one repair.
    pub interleave_repairs: bool,
    /// Enable causal sparse early repair after selective feedback exposes a gap.
    pub feedback_repair: bool,
    /// Include an exclusive contiguous recovered prefix in feedback.
    pub cumulative_feedback: bool,
    /// Maximum IDs triggering one feedback snapshot, in 1..=255.
    pub feedback_batch: u16,
    /// First-admission timer for a partial FEC group; zero is immediate.
    pub fec_wait_ticks: u64,
    /// Periodic equation spacing; feedback repairs have no spacing delay.
    pub repair_spacing_ticks: u64,
    /// First-new-receipt batching timer; zero is immediate.
    pub feedback_wait_ticks: u64,
    /// Positive minimum residual ARQ delay.
    pub rto_min_ticks: u64,
    /// Rational path-RTT multiplier, rounded up to caller ticks.
    pub rto_factor_numerator: u32,
    /// Positive rational denominator; factor must be at least one.
    pub rto_factor_denominator: u32,
    /// Frozen equation queue slots, at most 1024.
    pub repair_queue: usize,
    /// Finite source-attempt cap, including the first transmission.
    pub max_attempts: u32,
    /// Python analytical payload budget (MTU minus 88), used by sparse selection
    /// and feedback batching. Actual records have a separate byte ceiling.
    pub feedback_payload_budget: usize,
    /// Complete v1 record ceiling, excluding actual outer authentication/carrier.
    pub max_record_bytes: usize,
    /// Conservative complete owner reservation, excluding caller buffers.
    pub memory_bytes: usize,
}
impl Config {
    /// Check all knobs and require room for a full explicitly described equation.
    pub fn validate(self) -> Result<(), Error> {
        self.recovery.validate()?;
        let knobs = [
            self.long_window,
            self.short_window,
            self.long_every,
            self.repair_every,
            self.repairs_per_group,
            self.feedback_batch,
        ];
        let max_repair =
            wire::HEADER_BYTES + 5 * usize::from(self.long_window) + self.recovery.width()?;
        let max_feedback = wire::HEADER_BYTES + 4 * usize::from(self.feedback_batch);
        if knobs.iter().any(|v| !(1..=255).contains(v))
            || self.short_window > self.long_window
            || self.recovery.window < usize::from(self.long_window)
            || self.recovery.window > 255
            || self.repair_queue < usize::from(self.long_window.max(self.repairs_per_group))
            || self.repair_queue > 1024
            || self.max_attempts == 0
            || self.rto_min_ticks == 0
            || self.rto_factor_denominator == 0
            || self.rto_factor_numerator < self.rto_factor_denominator
            || self.feedback_payload_budget < 4 * (1 + usize::from(self.cumulative_feedback))
            || self.feedback_payload_budget > 65_535
            || self.max_record_bytes < max_repair.max(max_feedback)
            || self.max_record_bytes > 65_535
            || self.memory_bytes == 0
            || self.memory_bytes > rolling::MAX_MEMORY
        {
            return Err(Error::Configuration);
        }
        Ok(())
    }
    /// Python MTU-aware number of receipt IDs per snapshot, including prefix cost.
    pub fn feedback_limit(self) -> Result<usize, Error> {
        self.validate()?;
        Ok(usize::from(self.feedback_batch)
            .min(self.feedback_payload_budget / 4 - usize::from(self.cumulative_feedback)))
    }
}

/// Inject independent nonzero GF coefficients, or exact captured Python vectors.
/// This crate does not prescribe a PRNG or claim Python MT19937 seed equivalence.
pub trait CoefficientSource {
    /// Fill every element with 1..=255. No references are retained after return.
    fn fill(&mut self, coefficients: &mut [u8]) -> Result<(), Error>;
}

/// Immutable explicit sparse equation; bytes encode length and padded payload.
#[derive(Clone, Copy, Debug)]
pub struct Repair<'a> {
    /// Existing engine's scope, unique repair ID, support and actual coded bytes.
    pub equation: rolling::Repair<'a>,
    /// Sorted distinct absolute source IDs and independently selected coefficients.
    pub terms: &'a [Term],
    /// Feedback-triggered repairs use sparse pending IDs and no periodic ordinal.
    pub feedback_triggered: bool,
}
impl Repair<'_> {
    /// Validate the complete coefficient identity before any decoding mutation.
    pub fn validate(self, config: Config) -> Result<(), Error> {
        config.validate()?;
        if self.equation.id.0 == 0
            || self.equation.id.0 == u64::MAX
            || self.terms.len() > usize::from(config.long_window)
            || self.equation.bytes.len() != config.recovery.width()?
        {
            return Err(Error::Length);
        }
        let expected = rolling::explicit::support(
            self.terms,
            self.feedback_triggered,
            config.recovery.window,
        )?;
        if self.equation.support != expected {
            return Err(Error::Identity);
        }
        if !self.feedback_triggered
            && self
                .terms
                .windows(2)
                .any(|pair| pair[0].source.0.checked_add(1) != Some(pair[1].source.0))
        {
            return Err(Error::Identity);
        }
        Ok(())
    }
    /// Complete record plus actual caller-supplied outer framing cost.
    pub fn charge(self, overhead: usize) -> Result<usize, Error> {
        add(
            add(wire::HEADER_BYTES, 5 * self.terms.len())?,
            add(self.equation.bytes.len(), overhead)?,
        )
    }
}

/// Selective recovery receipt plus optional exclusive cumulative prefix.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Feedback<'a> {
    /// Forward stream being acknowledged, authenticated by the reverse carrier.
    pub scope: Scope,
    /// Monotonic nonwrapping receipt snapshot identity.
    pub id: FeedbackId,
    /// Exclusive prefix; Some(0) maps to Python's inclusive prefix -1.
    pub prefix: Option<u32>,
    /// Sorted unique recovered source IDs, strictly beyond a supplied prefix.
    pub ids: &'a [SourceId],
}
impl Feedback<'_> {
    /// Check structure; the sender separately checks causal physical-send bounds.
    pub fn validate(self, config: Config) -> Result<(), Error> {
        config.validate()?;
        if self.id.0 == 0
            || self.id.0 == u64::MAX
            || self.prefix.is_some() != config.cumulative_feedback
            || self.ids.len() > config.feedback_limit()?
            || self.ids.is_empty() && self.prefix.is_none()
            || self
                .ids
                .iter()
                .any(|id| id.0 == u32::MAX || self.prefix.is_some_and(|prefix| id.0 < prefix))
            || self.ids.windows(2).any(|pair| pair[0] >= pair[1])
        {
            return Err(Error::Identity);
        }
        Ok(())
    }
    /// Complete feedback record plus actual reverse encapsulation cost.
    pub fn charge(self, overhead: usize) -> Result<usize, Error> {
        add(add(wire::HEADER_BYTES, 4 * self.ids.len())?, overhead)
    }
}

pub(super) fn add(a: usize, b: usize) -> Result<usize, Error> {
    a.checked_add(b).ok_or(Error::Exhausted)
}
pub(super) fn deadline(now: Tick, ticks: u64) -> Result<Tick, Error> {
    now.0.checked_add(ticks).map(Tick).ok_or(Error::Exhausted)
}
pub(super) fn check_time(last: Tick, now: Tick, ends: &[Option<Tick>]) -> Result<(), Error> {
    if now < last {
        return Err(Error::TimeRegression);
    }
    if ends.iter().flatten().any(|end| now >= *end) {
        return Err(Error::Expired);
    }
    Ok(())
}
pub(super) fn slots<T: Clone>(count: usize, initial: T) -> Result<Vec<T>, Error> {
    let mut value = Vec::new();
    value
        .try_reserve_exact(count)
        .map_err(|_| Error::Allocation)?;
    value.resize(count, initial);
    Ok(value)
}

#[cfg(test)]
mod tests;
