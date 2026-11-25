//! Shared current client policy request result, independent of any carrier emitter.
/// Why a locally requested policy change did not report completion. A refusal
/// preserves the current policy; an ended session can have a partial or unknown
/// peer outcome and never implies rollback.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SwitchError {
    /// Another change is in progress.
    Busy,
    /// Only the initiating endpoint of a session proposes changes.
    NotCoordinator,
    /// The peer refused the proposal.
    Rejected,
    /// The policy is invalid for this session.
    Invalid,
    /// The session ended before the change completed; whether the peer
    /// applied it is unknown and irrelevant, since the session is gone.
    Closed,
    /// The local device MTU could not be lowered for a smaller target
    /// (live tuning); the current setting stays.
    DeviceMtu,
}
