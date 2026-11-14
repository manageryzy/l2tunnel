//! Lean packed-stream tunnel codec with systematic sliding-window coding.
//!
//! This is the pure protocol engine of the `swift` profile. It follows the
//! design that performed best in the Python simulator: native packets are
//! packed back to back into fixed-capacity source symbols, every source is
//! sent once as-is, and whatever is lost is requested again explicitly, which
//! costs exactly one extra datagram per loss. An optional proportion of random
//! linear repairs over the most recent window can recover losses without a
//! round trip at a higher byte cost; the same repairs probe an idle tail.
//!
//! The engine has no sockets, clocks, keys or devices. The caller supplies
//! monotonic microseconds, a unique per-datagram number (used as the repair
//! coefficient seed) and authenticated datagram bodies. Every buffer is bounded
//! by [`Config`]. A peer that sends inconsistent data produces an [`Error`];
//! nothing here panics on received bytes.
//!
//! One [`Sender`] and one [`Receiver`] serve each direction. Delivery to the
//! native side is one ordered byte stream per direction, so a packet is never
//! duplicated or reordered relative to others in the same direction.

mod byte_queue;
pub mod control;
pub mod flow;
pub mod gf;
pub mod header;
pub mod policy;
mod receiver;
pub mod records;
mod sender;
pub mod storage;

pub use receiver::Receiver;
pub use sender::Sender;

/// Datagram kind byte of an original source symbol.
pub const KIND_SOURCE: u8 = 0;
/// Datagram kind byte of a repair equation.
pub const KIND_REPAIR: u8 = 1;
/// Datagram kind byte of receiver feedback.
pub const KIND_FEEDBACK: u8 = 2;
/// Source header: kind and the low 32 bits of the sequence number.
pub const SOURCE_HEADER: usize = 5;
/// Repair header: kind, low 32 bits of the end sequence and 8-bit covered count.
pub const REPAIR_HEADER: usize = 6;
/// Feedback header before the explicit request list.
pub const FEEDBACK_HEADER: usize = 12;
/// Largest explicit retransmission request list in one feedback datagram.
pub const MAX_REQUESTS: usize = 64;
/// Later sources that must arrive before a gap is requested when no
/// proportional repairs are configured; tolerates slight path reordering.
pub const REORDER_SOURCES: u32 = 3;
/// Length prefix of one packed native packet.
pub const FRAME_PREFIX: usize = 2;
/// Bits of the leading datagram byte that carry the kind; a frontend that
/// multiplexes several engines may use the bits above them for a channel.
pub const KIND_MASK: u8 = 0x03;
/// Largest number of channels the bits above [`KIND_MASK`] can name.
pub const MAX_CHANNELS: usize = 64;

/// Fixed protocol policy both peers must share exactly.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Config {
    /// Largest body of one datagram this engine may emit, in `64..=65000`.
    /// Source symbols carry at most `datagram_bytes - REPAIR_HEADER - 2` bytes
    /// so a repair over full symbols still fits.
    pub datagram_bytes: usize,
    /// Sources covered by one repair, in `1..=255`.
    pub window: usize,
    /// Repairs earned per source sent, as `numerator / denominator`.
    pub repair_numerator: u32,
    /// Denominator of the repair proportion, in `1..=65536`.
    pub repair_denominator: u32,
    /// Largest number of sent but unconfirmed sources, in `window..=65535`.
    pub flow_sources: usize,
    /// Bound on native bytes queued for packing, at least one maximum packet.
    pub queue_bytes: usize,
    /// Largest native packet accepted or delivered, in `1..=65535`.
    pub max_packet: usize,
    /// Longest time a partly filled source symbol waits for more native
    /// bytes before it is sent short; zero sends it at once. At most 1 s.
    pub flush_micros: u64,
    /// Minimum spacing of receiver feedback.
    pub feedback_micros: u64,
    /// Idle time after the last new source before a tail repair is sent.
    pub tail_micros: u64,
    /// Lower bound of the retransmission interval.
    pub min_rto_micros: u64,
    /// Upper bound of the retransmission and idle-probe interval.
    pub max_rto_micros: u64,
}

impl Config {
    /// Validate every scalar bound without allocating.
    pub fn validate(self) -> Result<(), Error> {
        let valid = (64..=65_000).contains(&self.datagram_bytes)
            && (1..=255).contains(&self.window)
            && (1..=65_536).contains(&self.repair_denominator)
            && self.repair_numerator <= self.repair_denominator
            && (self.window..=65_535).contains(&self.flow_sources)
            && (1..=65_535).contains(&self.max_packet)
            && self.queue_bytes >= self.max_packet + FRAME_PREFIX
            && self.queue_bytes <= 1 << 30
            && self.flush_micros <= 1_000_000
            && self.feedback_micros > 0
            && self.tail_micros > 0
            && self.min_rto_micros > 0
            && self.min_rto_micros <= self.max_rto_micros
            && self.max_rto_micros <= 60_000_000;
        if valid {
            Ok(())
        } else {
            Err(Error::Configuration)
        }
    }
    /// Largest payload of one source symbol.
    pub fn symbol_bytes(self) -> usize {
        self.datagram_bytes - REPAIR_HEADER - 2
    }
}

/// Failures of the pure engine.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// A [`Config`] value is outside its documented range.
    Configuration,
    /// An authenticated datagram or the recovered stream is structurally invalid.
    Malformed,
    /// The 64-bit source sequence space is exhausted; unreachable in practice.
    Exhausted,
    /// A native packet is empty or larger than the configured maximum.
    PacketSize,
    /// Checked storage layout, capacity or reserved-pool invariant failure.
    Storage,
    /// A fallible backing allocation was refused by the allocator.
    Allocation,
}

impl std::fmt::Display for Error {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Configuration => "invalid swift configuration",
            Self::Malformed => "malformed authenticated swift data",
            Self::Exhausted => "swift sequence space exhausted",
            Self::PacketSize => "native packet size outside the configured bound",
            Self::Storage => "swift reserved storage capacity violated",
            Self::Allocation => "swift backing allocation failed",
        })
    }
}
impl std::error::Error for Error {}

/// Counters a frontend may report; none is a performance guarantee.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SenderStats {
    /// Original source symbols sent.
    pub sources: u64,
    /// Proportional repairs sent.
    pub repairs: u64,
    /// Idle tail repairs sent.
    pub tail_repairs: u64,
    /// Explicitly requested sources sent again.
    pub retransmits: u64,
    /// Native bytes packed into sources, including length prefixes.
    pub packed_bytes: u64,
    /// Native packets accepted for packing.
    pub packets: u64,
    /// Latest smoothed round-trip estimate, zero before the first sample.
    pub smoothed_rtt_micros: u64,
}

/// Counters a frontend may report; none is a performance guarantee.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ReceiverStats {
    /// Sources that arrived directly and were new.
    pub sources: u64,
    /// Sources reconstructed from repair equations.
    pub recovered: u64,
    /// Repairs that added an independent equation.
    pub useful_repairs: u64,
    /// Repairs that carried nothing new.
    pub useless_repairs: u64,
    /// Sources or repairs that were duplicates or too old.
    pub duplicates: u64,
    /// Native packets handed to the caller.
    pub packets: u64,
    /// Feedback datagrams produced.
    pub feedback: u64,
}

impl SenderStats {
    /// Add another engine's counters; the round-trip estimate keeps the larger.
    pub fn add(&mut self, other: &Self) {
        self.sources += other.sources;
        self.repairs += other.repairs;
        self.tail_repairs += other.tail_repairs;
        self.retransmits += other.retransmits;
        self.packed_bytes += other.packed_bytes;
        self.packets += other.packets;
        self.smoothed_rtt_micros = self.smoothed_rtt_micros.max(other.smoothed_rtt_micros);
    }
}
impl ReceiverStats {
    /// Add another engine's counters.
    pub fn add(&mut self, other: &Self) {
        self.sources += other.sources;
        self.recovered += other.recovered;
        self.useful_repairs += other.useful_repairs;
        self.useless_repairs += other.useless_repairs;
        self.duplicates += other.duplicates;
        self.packets += other.packets;
        self.feedback += other.feedback;
    }
}

/// The 64-bit sequence nearest `reference` whose low 32 bits are `wire`.
/// Sequences are 64-bit inside the engine and never wrap in practice; the
/// wire carries their low half, which is unambiguous because every value a
/// peer may name lies within one flow window of the local reference.
fn expand(reference: u64, wire: u32) -> Option<u64> {
    let delta = wire.wrapping_sub(reference as u32) as i32;
    reference.checked_add_signed(i64::from(delta))
}
fn read_u32(bytes: &[u8]) -> Option<u32> {
    Some(u32::from_be_bytes(bytes.get(..4)?.try_into().ok()?))
}
fn read_u16(bytes: &[u8]) -> Option<u16> {
    Some(u16::from_be_bytes(bytes.get(..2)?.try_into().ok()?))
}

#[cfg(test)]
mod tests;
