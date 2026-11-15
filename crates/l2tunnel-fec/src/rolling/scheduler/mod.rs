//! Causal bounded rolling recovery scheduling; callers supply time and authenticated I/O.
//!
//! Output confirmation is the caller's complete carrier-ownership boundary, not
//! native delivery. Neither data nor feedback codecs authenticate their bytes.
use super::*;

mod feedback;
mod receiver;
mod sender;
pub use feedback::{FEEDBACK_BYTES, Feedback, FeedbackId, decode_feedback, encode_feedback};
pub use receiver::{Receiver, ReceiverStatus, ReceiverStep};
pub use sender::{FeedbackDisposition, Output, OutputId, Sender, SenderStatus, SourceCopy};

/// Explicit scheduling and total owner reservation, with no inferred link properties.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Policy {
    /// Unchanged fixed-window byte-recovery policy.
    pub recovery: Config,
    /// Repair credit earned per successfully handed-off source, in 0..=denominator.
    pub repair_numerator: u32,
    /// Exact integer repair-ratio denominator, in 1..=65536.
    pub repair_denominator: u32,
    /// Idle delay after actual source or completed tail-burst handoff.
    pub tail_ticks: u64,
    /// Maximum wait after the first unreported committed receive event.
    pub feedback_ticks: u64,
    /// Receive events triggering feedback without waiting, in 1..=65536.
    pub feedback_packets: u32,
    /// Conservative total reservation for each constructed scheduler owner.
    pub memory_bytes: usize,
    /// Explicit systematic-source record format; both peers must select the same.
    pub source_wire: wire::SourceWire,
}
impl Policy {
    /// Validate scalar limits before constructing owners or allocating payloads.
    pub fn validate(self) -> Result<(), Error> {
        self.recovery.validate()?;
        if !(1..=65_536).contains(&self.repair_denominator)
            || self.repair_numerator > self.repair_denominator
            || self.tail_ticks == 0
            || self.tail_ticks >= self.recovery.debt_ticks
            || self.feedback_ticks == 0
            || self.feedback_ticks >= self.recovery.debt_ticks
            || !(1..=65_536).contains(&self.feedback_packets)
            || !(1..=MAX_MEMORY).contains(&self.memory_bytes)
        {
            return Err(Error::Configuration);
        }
        Ok(())
    }
}

fn remaining(before: WorkBudget, consumed: WorkUsed) -> WorkBudget {
    WorkBudget {
        field: before.field - consumed.field,
        copies: before.copies - consumed.copies,
        metadata: before.metadata - consumed.metadata,
    }
}
