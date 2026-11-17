//! Metadata-only original lifetime facts. No timer, I/O or authentication authority.
use super::{Error, RepairId, Scope, Tick};

/// The actual owner/check retaining an unchanged original deadline.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Kind {
    /// Encoder cohort remains unresolved until all admitted sources confirm.
    EncoderDebt,
    /// Original resumable encoding job, including its immutable result.
    EncoderJob,
    /// Decoder observed cohort remains unresolved.
    DecoderDebt,
    /// Original resumable decoding candidate.
    DecoderJob,
    /// Published decoded sources await upper-owner handoff.
    DecoderHandoff,
    /// Immutable systematic or repair output awaits carrier handoff.
    DataOutput,
    /// Immutable cumulative receipt awaits reverse carrier handoff.
    FeedbackOutput,
    /// Research sender's original-created cohort lifetime.
    ResearchDebt,
    /// Research feedback event awaits its output slot.
    FeedbackEvent,
    /// Research receiver retains a finite external cap.
    RetainedInput,
    /// Incoming work is already beyond its original external caller cap.
    IncomingCap,
}
/// Existing scalar identity; source ranges are current outstanding extents,
/// never an assertion about which already-completed source opened a cohort.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Identity {
    /// Half-open source extent, including a single systematic source.
    Sources {
        /// Inclusive first source.
        first: u32,
        /// Exclusive source end.
        end: u32,
    },
    /// One actual repair and its support when that support is retained.
    Repair {
        /// Exact independent repair ID.
        id: RepairId,
        /// Optional half-open support.
        support: Option<(u32, u32)>,
    },
    /// Exact feedback identity, including a building immutable snapshot.
    Feedback(u64),
}
/// One original deadline and its retained or attempted input identity.
/// An identity here does not prove that input admission succeeded.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Deadline {
    /// Actual owner/check category.
    pub kind: Kind,
    /// Original absolute caller-injected expiry tick.
    pub at: Tick,
    /// Existing identity if available; absence is not a zero identifier.
    pub identity: Option<Identity>,
}
impl Deadline {
    pub(crate) const fn new(kind: Kind, at: Tick, identity: Option<Identity>) -> Self {
        Self { kind, at, identity }
    }
}
/// Latched at the first actual expired check, before later terminal handling.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Failure {
    /// Injected tick used by that failed check.
    pub observed: Tick,
    /// First expired check in the unchanged original check order.
    pub selected: Deadline,
}
/// Allocation-free snapshot of one actual encoder/decoder and its scheduler.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Snapshot {
    /// Actual authenticated embedding identity; this grants no authority.
    pub scope: Scope,
    /// Last successful check for the outermost included owner.
    pub last_successful: Tick,
    /// Actual retained terminal error, if any.
    pub terminal: Option<Error>,
    /// Exact first failed expiry check, distinct from current candidates below.
    pub failure: Option<Failure>,
    /// Bounded current retained candidates, including nonexpired deadlines.
    pub candidates: [Option<Deadline>; 6],
}
impl Snapshot {
    pub(crate) fn first_expired(&self, now: Tick, order: &[usize]) -> Option<Failure> {
        order
            .iter()
            .filter_map(|index| self.candidates.get(*index).copied().flatten())
            .find(|deadline| now >= deadline.at)
            .map(|selected| Failure {
                observed: now,
                selected,
            })
    }
}
