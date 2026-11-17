//! Bounded, allocation-free stream-buffer snapshots without clocks or history.

/// Actual per-channel sender buffers; occupancy alone does not establish blockage.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SenderBuffers {
    /// Native codec bytes plus stream prefixes waiting to become sources.
    pub packing_bytes: usize,
    /// Local packing bound; the enclosing Engine also enforces one shared bound.
    pub packing_capacity_bytes: usize,
    /// Unconfirmed retained original source payloads.
    pub source_records: usize,
    /// Maximum unconfirmed sources permitted by the actual policy.
    pub source_capacity_records: usize,
    /// Exact retained original source payload bytes.
    pub source_bytes: usize,
    /// Maximum source payload bytes permitted by the source count and width.
    pub source_capacity_bytes: usize,
    /// Explicit retry entries, not additional payload copies.
    pub retry_entries: usize,
    /// Maximum explicit retry entries.
    pub retry_capacity_entries: usize,
    /// Earned repair work, not allocated queued repair payloads.
    pub repairs_due: u32,
}

/// Actual retained receive state; gaps and GF work are separate from native output.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReceiverBuffers {
    /// Source positions in the history/reorder ring, including missing positions.
    pub source_positions: usize,
    /// Maximum retained source positions.
    pub source_capacity_positions: usize,
    /// Actual known source payloads within those positions.
    pub known_sources: usize,
    /// Exact retained source payload bytes, including repair history.
    pub source_bytes: usize,
    /// Maximum retained source payload bytes for the configured ring.
    pub source_capacity_bytes: usize,
    /// Independent retained equations, excluding reusable vacant scratch.
    pub rows: usize,
    /// Configured maximum retained equations.
    pub row_capacity: usize,
    /// Exact equation payload bytes, excluding coefficient metadata.
    pub row_bytes: usize,
    /// Configured maximum equation payload bytes.
    pub row_capacity_bytes: usize,
    /// Ordered recovered stream bytes not yet extracted as native packets.
    pub stream_bytes: usize,
    /// Actual receive-stream safety bound, independent of sender packing bounds.
    pub stream_capacity_bytes: usize,
}

/// One indexed channel; asymmetric absent directions remain None.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ChannelBuffers {
    /// Actual sending buffers if this channel exists in the send direction.
    pub send: Option<SenderBuffers>,
    /// Actual receiving buffers if this channel exists in the receive direction.
    pub receive: Option<ReceiverBuffers>,
}
