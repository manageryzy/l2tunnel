//! Compatibility-only pre-RRS inline shape for an existing scalar codec gate.
//!
//! These headers allocate nothing and are never protocol owners or actual memory
//! observations. BTreeMap's inline header is independent of its node payload;
//! unit values preserve that old header without copying an old decoder algorithm.
use super::{Outgoing, ReliableConfig, Restored};
use l2tunnel_fec as fec;
use l2tunnel_recovery::{RecoveryContext, RecoveryError, SelectiveRepeat};
use std::{
    collections::{BTreeMap, VecDeque},
    time::Duration,
};

#[allow(dead_code)]
struct DecoderHeader {
    context: fec::FecContext,
    config: fec::DecoderConfig,
    generations: BTreeMap<fec::GenerationId, ()>,
    terminal: BTreeMap<fec::GenerationId, ()>,
    highest: Option<fec::GenerationId>,
    reserved: usize,
    last_now: u64,
}
#[allow(dead_code)]
enum FecError {
    InvalidConfig,
    InvalidDimensions,
    InvalidCoefficients,
    PacketTooLarge,
    Malformed,
    ContextMismatch,
    Conflict,
    InvalidSource,
    WorkLimit,
    Capacity,
    TimeBackwards,
    DeadlineOverflow,
    Expired,
    AlreadyCompleted,
    CompletePending,
    StaleGeneration,
    WindowBlocked,
    UnknownGeneration,
    InsufficientRank,
    SymbolExhausted,
    Arithmetic,
}
#[allow(dead_code)]
enum ReliableError {
    InvalidConfig,
    Malformed,
    RestoredCapacity,
    SourceConflict,
    OutputTooSmall { required: usize },
    NonMonotonicTime,
    TimeOverflow,
    Exhausted,
    Arq(RecoveryError),
    Fec(FecError),
}
#[allow(dead_code)]
struct ReliableHeader {
    config: ReliableConfig,
    receive_config: ReliableConfig,
    context: RecoveryContext,
    arq: SelectiveRepeat,
    decoder: DecoderHeader,
    send_fec: fec::FecContext,
    receive_fec: fec::FecContext,
    building: Vec<Vec<u8>>,
    building_deadline: Option<Duration>,
    next_fresh_source: u64,
    next_generation: Option<fec::GenerationId>,
    outgoing: VecDeque<Outgoing>,
    restored: BTreeMap<u64, Restored>,
    restored_bytes: usize,
    fec_deadlines: BTreeMap<fec::GenerationId, u64>,
    scratch: Vec<u8>,
    maximum_packet: usize,
    receive_maximum_packet: usize,
    prefer_feedback: bool,
    now: Duration,
    failure: Option<ReliableError>,
    // Preserve the ten original u64 counters even when live telemetry grows.
    statistics: [u64; 10],
}
pub(super) const fn reliable_bytes() -> usize {
    std::mem::size_of::<ReliableHeader>()
}
