//! Failure-only scalar evidence. This module does not grant transition authority.
use super::*;

/// Exact existing Hello proof check that rejected a packet.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SetupProofBoundary {
    /// Authenticated packet admission after the local TCP owner was detached.
    AuthenticatedHello,
    /// Whole peer Hello validation, including Hello quarantined before detach.
    PeerHello,
}

/// Complementary-proof comparisons at the original refusal boundary.
///
/// Booleans report equality, not authentication permission. Session, transcript,
/// key material and complete TCP sequence numbers are deliberately absent.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SetupHelloProof {
    /// Existing refusing check, without changing its order or result.
    pub boundary: SetupProofBoundary,
    /// Local physical lane within the original Full/Half owner.
    pub lane: u8,
    /// Lane, bulk role, opposite endpoint role and session all matched.
    pub identity_matches: bool,
    /// Opposite written/read byte totals matched.
    pub stream_bytes_match: bool,
    /// Opposite next/receive sequence frontiers matched.
    pub sequence_matches: bool,
    /// Local frozen peer observation matched the peer's actual advertised window.
    pub local_peer_window_matches: bool,
    /// Peer frozen peer observation matched the local actual advertised window.
    pub peer_peer_window_matches: bool,
    /// TCP option capability matched.
    pub options_match: bool,
    /// Both negotiated window scales matched their opposite observations.
    pub scales_match: bool,
    /// Local last physically advertised, unscaled TCP window.
    pub local_window: u16,
    /// Negotiated local window shift.
    pub local_scale: u8,
    /// Local last physically advertised window after applying the shift.
    pub local_scaled_window: u32,
    /// Local frozen observation of the peer's scaled window.
    pub local_peer_window: u32,
    /// Peer authenticated unscaled TCP window.
    pub peer_window: u16,
    /// Peer authenticated negotiated window shift.
    pub peer_scale: u8,
    /// Peer authenticated window after applying the shift.
    pub peer_scaled_window: u32,
    /// Peer authenticated frozen observation of the local scaled window.
    pub peer_peer_window: u32,
}

/// Existing outer-header and range checks when releasing an authenticated early Hello.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SetupEarlyProof {
    /// Actual TCP sequence matched the frozen peer frontier plus this offset.
    pub sequence_matches: bool,
    /// Actual TCP ACK matched the frozen local frontier.
    pub acknowledgment_matches: bool,
    /// Actual TCP window matched the frozen peer horizon and scale.
    pub window_matches: bool,
    /// Authenticated right edge matched the frozen peer horizon.
    pub right_edge_matches: bool,
    /// This already authenticated extent fitted the existing local horizon.
    pub within_local_horizon: bool,
    /// This extent fitted the original remaining sequence space.
    pub within_sequence_space: bool,
    /// Unscaled window required by the existing fence.
    pub expected_window: u64,
    /// Unscaled window in the actual authenticated early packet.
    pub observed_window: u16,
    /// Existing frozen peer horizon; no enlarged or inferred capacity.
    pub expected_right_edge: u64,
    /// Authenticated right edge carried by the early packet.
    pub observed_right_edge: u64,
    /// Checked end of this early extent, relative to the frozen frontier.
    pub end: u64,
    /// Existing local horizon used by the refusing check.
    pub local_horizon: u64,
}

/// First identified setup proof refusal retained in the existing bounded snapshot.
/// Absence means this diagnostic did not identify a refusal, not proof success.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SetupProofFailure {
    /// All scalar comparisons from the existing complementary Hello check.
    Hello(SetupHelloProof),
    /// All scalar comparisons from the existing early Hello release check.
    EarlyHelloRelease(SetupEarlyProof),
}

impl SetupProofFailure {
    pub(super) fn hello(
        boundary: SetupProofBoundary,
        local: wire::LaneProof,
        peer: wire::LaneProof,
    ) -> Self {
        // Both proofs have already passed the existing parser's shift <= 14 check.
        let local_scaled_window = u32::from(local.window) << local.scale;
        let peer_scaled_window = u32::from(peer.window) << peer.scale;
        Self::Hello(SetupHelloProof {
            boundary,
            lane: local.lane,
            identity_matches: local.lane == peer.lane
                && local.bulk == peer.bulk
                && local.role != peer.role
                && local.session == peer.session,
            stream_bytes_match: local.written == peer.read && local.read == peer.written,
            sequence_matches: local.next == peer.receive && local.receive == peer.next,
            local_peer_window_matches: local.peer_window == peer_scaled_window,
            peer_peer_window_matches: peer.peer_window == local_scaled_window,
            options_match: local.options == peer.options,
            scales_match: local.scale
                == if peer.peer_scale == 255 {
                    0
                } else {
                    peer.peer_scale
                }
                && peer.scale
                    == if local.peer_scale == 255 {
                        0
                    } else {
                        local.peer_scale
                    },
            local_window: local.window,
            local_scale: local.scale,
            local_scaled_window,
            local_peer_window: local.peer_window,
            peer_window: peer.window,
            peer_scale: peer.scale,
            peer_scaled_window,
            peer_peer_window: peer.peer_window,
        })
    }
}
