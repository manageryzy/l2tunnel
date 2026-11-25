//! Server sessions (DGUI-11; owner decision 2026-11-23: map to the existing
//! point-to-point model). A server generation admits one pinned member, so
//! the list holds at most the one live session. Kicking ends it and listens
//! again with the same plan; revoking replaces the profile's trusted member
//! key and replaces the session (frontends compose `profile` and
//! `profile_connect`).
use serde::{Deserialize, Serialize};

/// The live server session.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionState {
    /// Service generation (operation that made it ready).
    pub generation: u64,
    /// Configured peer address.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub peer: Option<String>,
    /// Milliseconds since the session became ready.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub connected_ms: Option<u64>,
    /// Trusted member public key (hex), when the plan came from a stored profile.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub member: Option<String>,
    /// Stored profile the plan came from.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile: Option<String>,
    /// Authenticated bytes sent and accepted, when the runtime reports them.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sent_bytes: Option<u64>,
    /// See `sent_bytes`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub received_bytes: Option<u64>,
}
