//! Allocation-free observations of actual codec custody, never clock or delivery authority.
//!
//! Occupancy is not backpressure. Callers time actual refusal outcomes separately.
//! These snapshots retain no history; peaks and observation times belong to the caller.

/// Actual meaningful retained bytes and entries against operational limits.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Retention {
    /// Occupied logical entries.
    pub items: usize,
    /// Maximum logical entries permitted by this owner.
    pub item_capacity: usize,
    /// Meaningful retained payload or body bytes, excluding metadata.
    pub bytes: usize,
    /// Operational byte bound, not total allocated memory.
    pub byte_capacity: usize,
}

/// One native frame stage; consumed prefixes remain in its slab until release.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StageBuffers {
    /// The one frame stage and its meaningful bodies.
    pub stage: Retention,
    /// Meaningful body/context bytes not yet handed to recovery or packing.
    pub remaining_bytes: usize,
    /// Fixed reusable unit scratch, not a second pending-output queue.
    pub unit_scratch_capacity: usize,
}

/// One assembling or sealed packing source.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PackingBuffers {
    /// The one assembled source and its exact container bytes.
    pub source: Retention,
    /// Complete units retained in the source.
    pub units: usize,
    /// Effective configured maximum units per source.
    pub unit_capacity: usize,
    /// The actual first sealing event; a timer hold is not capacity pressure.
    pub sealed: Option<crate::packed::SealReason>,
}

/// The two distinct owners in the bounded packed sender.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PackedBuffers {
    /// Original frame fragments still awaiting packing.
    pub stage: StageBuffers,
    /// Assembled units awaiting recovery admission.
    pub packing: PackingBuffers,
}

/// Actual configured sender, with no fabricated absent packing queue.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SendBuffers {
    /// Direct aligned source staging.
    Aligned(StageBuffers),
    /// Aligned staging followed by the actual bounded packer.
    Packed(PackedBuffers),
}

/// Receiver head reserves remain separate from shared future-record quotas.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReceiverBuffers {
    /// Physically delivered records retained in compact replay slots.
    pub compacted_records: usize,
    /// Maximum number of compact replay slots, independent of native lookahead.
    pub compacted_record_capacity: usize,
    /// Exact source bytes retained above an unresolved contiguous floor.
    pub source_proofs: Retention,
    /// Current channel-head records with independent reserves.
    pub heads: Retention,
    /// Shared future-record resources, excluding channel heads.
    pub lookahead: Retention,
    /// Retained fragment bitmap entries for channel heads.
    pub head_fragments: usize,
    /// Sum of the independent channel-head fragment reserves.
    pub head_fragment_capacity: usize,
    /// Retained future-record fragment bitmap entries.
    pub lookahead_fragments: usize,
    /// Shared future-record fragment bound.
    pub lookahead_fragment_capacity: usize,
    /// A prepared immutable native frame; None is distinct from zero bytes.
    pub pending_native_bytes: Option<usize>,
    /// Fixed decoded-native output capacity.
    pub native_capacity_bytes: usize,
}

/// The actual selected codec owners inside an endpoint; recovery is separate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DuplexBuffers {
    /// Actual sending codec owner.
    pub send: SendBuffers,
    /// Actual receiving codec owner.
    pub receive: ReceiverBuffers,
}

/// Cause carried by a real rejected stage operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StageBlock {
    /// An earlier native frame still owns the only staging slot.
    RetainedFrame,
}

/// Cause carried by the actual packer result, not predicted from occupancy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PackingBlock {
    /// The sealed source must be released before accepting another unit.
    SealedSource,
    /// Read the accompanying packing snapshot for its exact sealing reason.
    FlushRequired,
}

/// Existing receive refusals; these do not promise that retry is appropriate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReceiveBlock {
    /// The peer record lies outside the permitted forward window.
    RecordWindow,
    /// Admitting the source would evict an unresolved lower source.
    SourceWindow,
    /// The existing error combines record slots, future byte/fragment quotas,
    /// and the per-record fragment bound; it does not identify which limit fired.
    ReceiverResources,
    /// Complete bytes cannot yet be interpreted in their ordered context.
    MissingContext,
}

/// Exact current unit in the single native stage, without preparing or consuming it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StageIdentity {
    /// Actual ordered codec channel.
    pub channel: u8,
    /// Full context/body record currently supplying the next unit.
    pub record: u64,
    /// Final body record returned at original successful native admission.
    pub native_record: u64,
    /// Cursor into the current body/context, before the next unit is committed.
    pub offset: usize,
    /// This unit belongs to the context preceding the final native body.
    pub context: bool,
}
