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
/// Exact current decoder phase and positional cursors, without field values,
/// payload bytes, accumulation state or parsed original lengths.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DecoderPhase {
    /// Copy one row between its transactional versions.
    CopyRow {
        /// Actual row slot.
        row: usize,
        /// Committed source bank.
        from: usize,
        /// Prepared destination bank.
        to: usize,
        /// Next row byte.
        index: usize,
    },
    /// Next candidate byte to clear.
    Clear(usize),
    /// Next received coded-vector byte to load.
    Load(usize),
    /// Next source in the input equation support.
    Support(u32),
    /// Subtract an already known source.
    Known {
        /// Exact known source ID.
        source: u32,
        /// Next coded-vector byte.
        column: usize,
    },
    /// Next absolute source whose pivot is considered.
    Reduce(u32),
    /// Subtract one selected pivot row.
    Eliminate {
        /// Actual row slot.
        row: usize,
        /// Next row byte, including coefficient bytes.
        index: usize,
        /// Next absolute source for pivot reduction.
        next: u32,
    },
    /// Next absolute source considered as the candidate pivot.
    Pivot(u32),
    /// Current inverse exponentiation position; field values are omitted.
    Invert {
        /// Absolute candidate pivot source.
        pivot: u32,
        /// Remaining public exponent, not an accumulated field value.
        exponent: u8,
    },
    /// Current inverse squaring position; field values are omitted.
    Square {
        /// Absolute candidate pivot source.
        pivot: u32,
        /// Remaining public exponent.
        exponent: u8,
    },
    /// Next coded-vector byte checked for consistency.
    Zero(usize),
    /// Normalize one candidate row.
    Normalize {
        /// Absolute pivot source.
        pivot: u32,
        /// Next row byte, including coefficient bytes.
        index: usize,
    },
    /// Next retained row considered for elimination.
    Others {
        /// Absolute candidate pivot source.
        pivot: u32,
        /// Next retained row slot.
        row: usize,
    },
    /// Subtract the candidate from one prepared retained row.
    OtherEliminate {
        /// Absolute candidate pivot source.
        pivot: u32,
        /// Actual retained row slot.
        row: usize,
        /// Next row byte, including coefficient bytes.
        index: usize,
    },
    /// Next candidate coefficient position to inspect.
    CandidateCount {
        /// Absolute candidate pivot source.
        pivot: u32,
        /// Next coefficient byte.
        index: usize,
    },
    /// Next retained coefficient position to inspect.
    Scan {
        /// Actual retained row slot.
        row: usize,
        /// Next coefficient byte.
        index: usize,
    },
    /// Next row slot considered for a new pivot.
    FindSlot {
        /// Absolute candidate pivot source.
        pivot: u32,
        /// Next row slot.
        row: usize,
    },
    /// Copy a candidate into its prepared retained row.
    Insert {
        /// Absolute candidate pivot source.
        pivot: u32,
        /// Actual destination row slot.
        row: usize,
        /// Next row byte.
        index: usize,
    },
    /// Validate an original reconstructed from a row, candidate or input.
    Validate {
        /// Actual retained row when selected; None denotes candidate/input.
        row: Option<usize>,
        /// Exact reconstructed source ID.
        source: u32,
        /// Next coded-vector byte.
        index: usize,
    },
    /// Store an original under the active transaction.
    Store {
        /// Actual retained row when selected; None denotes candidate/input.
        row: Option<usize>,
        /// Exact reconstructed source ID.
        source: u32,
        /// Next coded-vector byte.
        index: usize,
    },
    /// Consider contiguous source-prefix progress.
    Advance,
    /// Next absolute source considered for history eviction.
    Evict(u32),
    /// Next immutable repair-history byte.
    History(usize),
    /// Publish the already prepared transaction.
    Commit,
}
/// Current retained decoder job, not proof that this job selected the failure.
/// All times use the caller's injected tick domain, never an internal clock.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DecoderJob {
    /// Actual source or repair identity already retained by the decoder.
    pub identity: Identity,
    /// Original authenticated arrival, preserved through earlier queue residence.
    pub received: Tick,
    /// Injected observation tick of successful decoder admission.
    /// This is not a separately sampled wall-clock instant within that call.
    pub admitted: Tick,
    /// Original min(input-age limit, caller cap); never renewed by observation.
    pub deadline: Tick,
    /// Exact current phase and positional cursors, excluding payload values.
    pub phase: DecoderPhase,
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
    /// Current retained decoder job when present. Encoder snapshots and refused
    /// inputs with no admitted job return None. Compare identity and original
    /// deadline with `failure` before attributing that selected failure to it.
    /// A latched decoder expiry retains this phase unchanged on later calls.
    pub decoder_job: Option<DecoderJob>,
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
