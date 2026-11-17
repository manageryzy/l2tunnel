//! Bounded TAP/TUN frame records, fragmentation and Python TCP header codecs.
//!
//! Authentication must precede decoding/reassembly. FrameCodec and fragmentation
//! retain independent draft formats. The tcp_header module separately implements
//! the Python timestamp/delta inner record bytes, with ordered context requirements.

/// Python-compatible bounded timestamp/delta TCP header record primitive.
pub mod tcp_header;

/// Python-compatible aligned record body transforms, without channel delivery.
pub mod aligned_body;

/// Fallible backing plans for the actual aligned and packed codec owners.
pub mod aligned_storage;

/// Allocation-free codec retention snapshots and typed actual refusal categories.
pub mod diagnostics;

mod fragment;
mod frame;

pub use fragment::storage as fragment_storage;
pub use fragment::{
    CausalTime, FRAGMENT_HEADER_BYTES, FragmentBatch, FragmentBatchView, FragmentConfig,
    FragmentContext, FragmentError, FragmentGeometry, FragmentLayout, Fragmenter, MessageId,
    Reassembler, ReassemblyConfig, ReassemblyStatus, ReassemblyTiming, SessionId,
    TimedReassemblyStatus, inspect_fragment_context,
};
pub use frame::{
    CodecConfig, CodecError, Compression, FRAME_HEADER_BYTES, FrameCodec, FrameLayer,
    MAX_FRAME_BYTES, MAX_RECORD_BYTES,
};

/// Incremental codec with caller-owned output buffers and explicit byte bounds.
pub trait RecordCodec {
    /// Malformation, context loss, unsupported profile, or output capacity error.
    type Error;
    /// Encode a complete frame into bounded caller storage and return bytes written.
    fn encode(&mut self, frame: &[u8], output: &mut [u8]) -> Result<usize, Self::Error>;
    /// Decode a record into bounded caller storage; reject expansion beyond capacity.
    fn decode(&mut self, record: &[u8], output: &mut [u8]) -> Result<usize, Self::Error>;
    /// Discard contexts at a negotiated epoch boundary, after draining old records.
    fn reset(&mut self);
}

/// Bounded aligned channel admission and explicit native delivery ownership.
pub mod aligned_receiver;

mod source_identity;

/// Absolute identity envelope requiring enclosing carrier integrity.
pub mod aligned_envelope;

/// Transactional Python aligned symbol sender with external recovery source IDs.
pub mod aligned_sender;

/// Python-compatible bounded source containers and caller-clocked packing.
pub mod packed;

/// Full absolute identities around unchanged Python packed-source bytes.
pub mod packed_envelope;

/// Bounded timed aligned-unit packing with externally owned recovery source IDs.
pub mod packed_sender;

/// Explicit generic-short/context copy selection over canonical aligned units.
pub mod source_copy;
