//! Complete Swift packing and ordered channels over authenticated numbered bodies.
//!
//! Callers own authentication, replay, packet numbers, pacing, I/O and negotiated
//! control. Numbered bodies preserve the legacy channel tags and repair seeds.

use crate::{Receiver, ReceiverStats, Sender, SenderStats, flow, header};

/// Read-only sender occupancy, recovery estimate and current-engine counters.
pub use crate::sender::Observation as SenderObservation;

/// Native packet grammar, independent of a platform device handle.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Layer {
    /// Complete Ethernet frames.
    Ethernet,
    /// Complete raw IPv4/IPv6 packets.
    Ip,
}

/// One direction's packing/recovery policy and fixed native format.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Config {
    /// Existing bounded single-channel recovery configuration.
    pub codec: crate::Config,
    /// Number of connection-affinity ordering channels, in 1..=64.
    pub channels: usize,
    /// Fixed native packet grammar.
    pub layer: Layer,
    /// Largest complete native packet, before the header record tag.
    pub max_native: usize,
}
impl Config {
    /// Check all scalar bounds before allocating channel state.
    pub fn validate(self) -> Result<(), Error> {
        self.codec.validate().map_err(Error::Codec)?;
        if !(1..=crate::MAX_CHANNELS).contains(&self.channels)
            || self.max_native.checked_add(header::MAX_EXPANSION) != Some(self.codec.max_packet)
        {
            return Err(Error::Configuration);
        }
        Ok(())
    }
}

/// Full authenticated security-record number, also the GF repair seed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecordNumber(pub u64);

/// Local engine half; not an authenticated endpoint direction or epoch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Direction {
    /// Locally admitted outgoing native records.
    Send,
    /// Locally extracted incoming native records, before device completion.
    Receive,
}

/// Checked Swift channel index, independent of an installed direction's width.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ChannelId(u8);
impl ChannelId {
    /// Construct an index in 0..64; an installed direction may have fewer channels.
    pub fn new(index: usize) -> Option<Self> {
        if index >= crate::MAX_CHANNELS {
            return None;
        }
        u8::try_from(index).ok().map(Self)
    }
    /// Exact zero-based channel index.
    pub fn index(self) -> usize {
        usize::from(self.0)
    }
}

/// Zero-based native identity within one channel of one direction's epoch.
/// This is not a source, repair, security or cover packet number.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativeRecordId(pub u64);

/// Exclusive native-record count; u64::MAX is the last representable boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativeCount(pub u64);

/// Original channel and native record, without session or epoch authority.
/// The runtime must retain the actual origin scope and global direction with it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativeIdentity {
    /// Channel selected by the original admission or ordered receive owner.
    pub channel: ChannelId,
    /// Native record identity; the last emittable identity is u64::MAX - 1.
    pub record: NativeRecordId,
}

/// One exact native packet and its receive identity, before physical handoff.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativePacket<'a> {
    /// Identity allocated only after complete extraction and decompression.
    pub identity: NativeIdentity,
    /// Borrowed bytes, valid until the next mutable engine call.
    pub bytes: &'a [u8],
}

/// One current-direction exclusive count, never proof of native device delivery.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ChannelBoundary {
    /// Local engine half whose count is observed.
    pub direction: Direction,
    /// Channel inside that installed direction.
    pub channel: ChannelId,
    /// Accepted send records or successfully extracted receive records.
    pub count: NativeCount,
}

/// Identified admission, with no identity allocated by a refused packet.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IdentifiedAdmission {
    /// Exact retained native packet and its original admission identity.
    Accepted(NativeIdentity),
    /// The common packing-byte budget cannot admit another maximum record.
    Full,
    /// Empty or larger than the fixed native packet bound.
    PacketSize,
}

/// Native admission result, decided before changing header contexts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Admission {
    /// The packet was retained exactly once.
    Accepted,
    /// The common packing-byte budget cannot admit another maximum record.
    Full,
    /// Empty or larger than the fixed native packet bound.
    PacketSize,
}

/// Actual algorithm branch that produced a numbered body; not authentication authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EmissionKind {
    /// Original or explicitly retransmitted source bytes.
    Source,
    /// A proportional or tail repair equation.
    Repair,
    /// Receiver feedback, possibly containing several channel blocks.
    Feedback,
}

/// Exact borrowed engine output and its actual producing branch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Emission<'a> {
    kind: EmissionKind,
    body: &'a [u8],
}
impl<'a> Emission<'a> {
    /// Actual source, repair or feedback classification.
    pub const fn kind(self) -> EmissionKind {
        self.kind
    }
    /// Unchanged wire body, valid until the next mutable engine operation.
    pub const fn body(self) -> &'a [u8] {
        self.body
    }
}

/// Explicit configuration, protocol, drain or invariant failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// Invalid channels, native bound or changed physical packet format.
    Configuration,
    /// A native identity/count or admission/packet statistic cannot advance.
    /// Refusal occurs before the new packet changes contexts or consumes bytes.
    CounterExhausted,
    /// Existing Swift grammar or recovery failure.
    Codec(crate::Error),
    /// Directional replacement requires completed delivery/confirmation.
    NotDrained,
    /// A packing queue rejected a pre-admitted compressed record.
    Admission,
}
impl std::fmt::Display for Error {
    fn fmt(&self, output: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Configuration => output.write_str("invalid Swift record configuration"),
            Self::CounterExhausted => output.write_str("Swift native record counter exhausted"),
            Self::Codec(error) => std::fmt::Display::fmt(error, output),
            Self::NotDrained => output.write_str("Swift record direction has not drained"),
            Self::Admission => output.write_str("Swift packing queue refused an admitted record"),
        }
    }
}
impl std::error::Error for Error {}
impl From<crate::Error> for Error {
    fn from(error: crate::Error) -> Self {
        Self::Codec(error)
    }
}

/// Cumulative algorithm observations, including retired directional engines.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Stats {
    /// All current and retired sending engines.
    pub sender: SenderStats,
    /// All current and retired receiving engines.
    pub receiver: ReceiverStats,
    /// Native packets accepted for packing.
    pub native_read: u64,
    /// Native packets refused for size or common queue pressure.
    pub native_dropped: u64,
    /// Native bytes removed by exact header records, net of record tags.
    pub header_bytes_saved: u64,
}

/// One indexed channel's current directional observations, without retired totals.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ChannelStats {
    /// Absent when this index is outside the current sending channel count.
    pub send: Option<SenderObservation>,
    /// Absent when this index is outside the current receiving channel count.
    pub receive: Option<ReceiverStats>,
    /// Known sources awaiting ordered delivery; zero without a receive channel.
    pub receive_pending: u32,
}

/// Bounded pure data path; never a connection, crypto or management owner.
pub struct Engine {
    send: Config,
    receive: Config,
    limit: usize,
    source_floor: RecordNumber,
    feedback_floor: RecordNumber,
    admitted: [u64; crate::MAX_CHANNELS],
    extracted: [u64; crate::MAX_CHANNELS],
    senders: Vec<Sender>,
    receivers: Vec<Receiver>,
    compressors: Vec<header::Compressor>,
    decompressors: Vec<header::Decompressor>,
    turn: usize,
    receive_turn: usize,
    feedback_at: u64,
    feedback_turn: usize,
    ready: u64,
    body: Vec<u8>,
    block: Vec<u8>,
    native: Vec<u8>,
    record: Vec<u8>,
    base: Stats,
}

struct InitialStorage {
    senders: Vec<Sender>,
    receivers: Vec<Receiver>,
    compressors: Vec<header::Compressor>,
    decompressors: Vec<header::Decompressor>,
    body: Vec<u8>,
    block: Vec<u8>,
    native: Vec<u8>,
    record: Vec<u8>,
}

fn tagged(kind: u8, channel: usize) -> u8 {
    kind | ((channel as u8) << 2)
}

impl Engine {
    /// Construct identical initial directional policies without keys or clocks.
    pub fn new(config: Config) -> Result<Self, Error> {
        config.validate()?;
        let mut senders = Vec::with_capacity(config.channels);
        let mut receivers = Vec::with_capacity(config.channels);
        let ethernet = config.layer == Layer::Ethernet;
        let mut compressors = Vec::with_capacity(config.channels);
        let mut decompressors = Vec::with_capacity(config.channels);
        for _ in 0..config.channels {
            senders.push(Sender::new(config.codec)?);
            receivers.push(Receiver::new(config.codec)?);
            compressors.push(header::Compressor::new(ethernet));
            decompressors.push(header::Decompressor::new(ethernet));
        }
        Ok(Self::from_storage(
            config,
            config,
            InitialStorage {
                senders,
                receivers,
                compressors,
                decompressors,
                body: Vec::with_capacity(config.codec.datagram_bytes),
                block: Vec::with_capacity(crate::FEEDBACK_HEADER + 2 * crate::MAX_REQUESTS),
                native: Vec::with_capacity(config.codec.max_packet),
                record: Vec::with_capacity(config.codec.max_packet),
            },
        ))
    }

    fn validate_directions(send: Config, receive: Config) -> Result<(), Error> {
        send.validate()?;
        receive.validate()?;
        if send.layer != receive.layer || send.max_native != receive.max_native {
            return Err(Error::Configuration);
        }
        Ok(())
    }

    pub(crate) fn reserved_heap_bytes(send: Config, receive: Config) -> Result<usize, Error> {
        Self::validate_directions(send, receive)?;
        let send_heap = Sender::reserved_bytes(send.codec)?
            .checked_add(header::Compressor::reserved_bytes(send.max_native)?)
            .and_then(|bytes| bytes.checked_mul(send.channels))
            .ok_or(crate::Error::Storage)?;
        let receive_heap = Receiver::reserved_bytes(receive.codec)?
            .checked_add(header::Decompressor::reserved_bytes()?)
            .and_then(|bytes| bytes.checked_mul(receive.channels))
            .ok_or(crate::Error::Storage)?;
        let mut total = 0usize;
        for bytes in [
            crate::storage::array_bytes::<Sender>(send.channels)?,
            crate::storage::array_bytes::<Receiver>(receive.channels)?,
            crate::storage::array_bytes::<header::Compressor>(send.channels)?,
            crate::storage::array_bytes::<header::Decompressor>(receive.channels)?,
            send_heap,
            receive_heap,
            crate::storage::array_bytes::<u8>(
                send.codec.datagram_bytes.max(receive.codec.datagram_bytes),
            )?,
            crate::storage::array_bytes::<u8>(crate::FEEDBACK_HEADER + 2 * crate::MAX_REQUESTS)?,
            crate::storage::array_bytes::<u8>(receive.max_native)?,
            crate::storage::array_bytes::<u8>(send.codec.max_packet.max(receive.codec.max_packet))?,
        ] {
            total = total.checked_add(bytes).ok_or(crate::Error::Storage)?;
        }
        Ok(total)
    }

    pub(crate) fn new_reserved(
        send: Config,
        receive: Config,
        allocation: &mut crate::storage::Allocation,
    ) -> Result<Self, Error> {
        Self::validate_directions(send, receive)?;
        let mut senders = allocation.vec(send.channels)?;
        let mut receivers = allocation.vec(receive.channels)?;
        let mut compressors = allocation.vec(send.channels)?;
        let mut decompressors = allocation.vec(receive.channels)?;
        for _ in 0..send.channels {
            senders.push(Sender::new_reserved(send.codec, allocation)?);
            compressors.push(header::Compressor::new_reserved(
                send.layer == Layer::Ethernet,
                send.max_native,
                allocation,
            )?);
        }
        for _ in 0..receive.channels {
            receivers.push(Receiver::new_reserved(receive.codec, allocation)?);
            decompressors.push(header::Decompressor::new_reserved(
                receive.layer == Layer::Ethernet,
                allocation,
            )?);
        }
        Ok(Self::from_storage(
            send,
            receive,
            InitialStorage {
                senders,
                receivers,
                compressors,
                decompressors,
                body: allocation
                    .vec(send.codec.datagram_bytes.max(receive.codec.datagram_bytes))?,
                block: allocation.vec(crate::FEEDBACK_HEADER + 2 * crate::MAX_REQUESTS)?,
                native: allocation.vec(receive.max_native)?,
                record: allocation.vec(send.codec.max_packet.max(receive.codec.max_packet))?,
            },
        ))
    }

    fn from_storage(send: Config, receive: Config, storage: InitialStorage) -> Self {
        Self {
            send,
            receive,
            limit: send.codec.datagram_bytes.max(receive.codec.datagram_bytes),
            source_floor: RecordNumber(0),
            feedback_floor: RecordNumber(0),
            admitted: [0; crate::MAX_CHANNELS],
            extracted: [0; crate::MAX_CHANNELS],
            senders: storage.senders,
            receivers: storage.receivers,
            compressors: storage.compressors,
            decompressors: storage.decompressors,
            turn: 0,
            receive_turn: 0,
            feedback_at: 0,
            feedback_turn: 0,
            ready: 0,
            body: storage.body,
            block: storage.block,
            native: storage.native,
            record: storage.record,
            base: Stats::default(),
        }
    }

    /// Current sending policy.
    pub fn send_config(&self) -> Config {
        self.send
    }
    /// Current receiving policy.
    pub fn receive_config(&self) -> Config {
        self.receive
    }
    /// Observe one current native boundary without polling or granting delivery.
    /// A channel absent in the selected asymmetric direction returns None.
    pub fn boundary(&self, direction: Direction, channel: ChannelId) -> Option<ChannelBoundary> {
        let index = channel.index();
        let count = match direction {
            Direction::Send if index < self.send.channels => self.admitted[index],
            Direction::Receive if index < self.receive.channels => self.extracted[index],
            _ => return None,
        };
        Some(ChannelBoundary {
            direction,
            channel,
            count: NativeCount(count),
        })
    }
    /// Observe one channel without polling, allocating or changing protocol state.
    /// Indices beyond both current directions return None; at most 64 exist.
    pub fn channel_stats(&self, index: usize) -> Option<ChannelStats> {
        let send = self.senders.get(index).map(Sender::observation);
        let receive = self.receivers.get(index);
        if send.is_none() && receive.is_none() {
            return None;
        }
        Some(ChannelStats {
            send,
            receive: receive.map(Receiver::stats),
            receive_pending: receive.map_or(0, Receiver::pending),
        })
    }
    /// Largest body permitted by any installed directional policy.
    pub fn body_limit(&self) -> usize {
        self.limit
    }
    /// Whether the shared packing queue can admit a maximum native record.
    pub fn has_room(&self) -> bool {
        let queued: usize = self.senders.iter().map(Sender::queued).sum();
        queued + self.send.codec.max_packet + crate::FRAME_PREFIX <= self.send.codec.queue_bytes
    }
    /// Admit through the identified path while preserving the legacy result.
    pub fn offer(&mut self, now: u64, packet: &[u8]) -> Result<Admission, Error> {
        Ok(match self.offer_identified(now, packet)? {
            IdentifiedAdmission::Accepted(_) => Admission::Accepted,
            IdentifiedAdmission::Full => Admission::Full,
            IdentifiedAdmission::PacketSize => Admission::PacketSize,
        })
    }
    /// Admit before compression and allocate one checked original native identity.
    /// Size, queue or exhausted-counter refusal burns no identity or header state.
    pub fn offer_identified(
        &mut self,
        now: u64,
        packet: &[u8],
    ) -> Result<IdentifiedAdmission, Error> {
        if let Some(rejected) = self.admission_refusal(packet)? {
            return Ok(rejected);
        }
        let channel = match self.send.layer {
            Layer::Ethernet => flow::classify_ethernet(packet, self.send.channels),
            Layer::Ip => flow::classify_ip(packet, self.send.channels),
        };
        self.retain_identified(now, channel, packet)
    }

    /// Admit onto the caller's selected channel through the same shared budget.
    /// An absent send channel changes no statistics, identity, context or queue.
    pub fn offer_on_channel_identified(
        &mut self,
        now: u64,
        channel: ChannelId,
        packet: &[u8],
    ) -> Result<IdentifiedAdmission, Error> {
        if channel.index() >= self.send.channels {
            return Err(Error::Configuration);
        }
        if let Some(rejected) = self.admission_refusal(packet)? {
            return Ok(rejected);
        }
        self.retain_identified(now, channel.index(), packet)
    }

    fn admission_refusal(&mut self, packet: &[u8]) -> Result<Option<IdentifiedAdmission>, Error> {
        let rejected = if packet.is_empty() || packet.len() > self.send.max_native {
            Some(IdentifiedAdmission::PacketSize)
        } else if !self.has_room() {
            Some(IdentifiedAdmission::Full)
        } else {
            None
        };
        if let Some(rejected) = rejected {
            self.base.native_dropped = self
                .base
                .native_dropped
                .checked_add(1)
                .ok_or(Error::CounterExhausted)?;
            return Ok(Some(rejected));
        }
        Ok(None)
    }

    fn retain_identified(
        &mut self,
        now: u64,
        channel: usize,
        packet: &[u8],
    ) -> Result<IdentifiedAdmission, Error> {
        let native_read = self
            .base
            .native_read
            .checked_add(1)
            .ok_or(Error::CounterExhausted)?;
        let admitted = self.admitted[channel]
            .checked_add(1)
            .ok_or(Error::CounterExhausted)?;
        self.senders[channel]
            .stats()
            .packets
            .checked_add(1)
            .ok_or(Error::CounterExhausted)?;
        let identity = NativeIdentity {
            channel: ChannelId::new(channel).ok_or(Error::Configuration)?,
            record: NativeRecordId(self.admitted[channel]),
        };
        self.compressors[channel].compress_checked(packet, &mut self.record)?;
        if !self.senders[channel].push_packet(now, &self.record)? {
            return Err(Error::Admission);
        }
        self.admitted[channel] = admitted;
        self.base.native_read = native_read;
        Ok(IdentifiedAdmission::Accepted(identity))
    }

    fn feedback(&mut self, now: u64) -> bool {
        if now < self.feedback_at {
            return false;
        }
        self.body.clear();
        let block = crate::FEEDBACK_HEADER + 2 * crate::MAX_REQUESTS;
        let mut deferred = false;
        for step in 0..self.receive.channels {
            let channel = (self.feedback_turn + step) % self.receive.channels;
            if self.body.len() + block > self.send.codec.datagram_bytes {
                deferred = self.receivers[channel].deadline().is_some();
                if deferred {
                    self.feedback_turn = channel;
                    break;
                }
                continue;
            }
            if self.receivers[channel].feedback(now, &mut self.block) {
                self.block[0] = tagged(crate::KIND_FEEDBACK, channel);
                self.body.extend_from_slice(&self.block);
            }
        }
        if !deferred {
            self.feedback_at = now.saturating_add(self.send.codec.feedback_micros);
        }
        !self.body.is_empty()
    }

    fn feedback_bounded(&mut self, now: u64, limit: usize) -> bool {
        if now < self.feedback_at || limit < crate::FEEDBACK_HEADER {
            return false;
        }
        self.body.clear();
        let first = self.feedback_turn;
        let mut deferred = None;
        for step in 0..self.receive.channels {
            let channel = (first + step) % self.receive.channels;
            if !self.receivers[channel].preview_feedback(now, &mut self.block) {
                continue;
            }
            if self.body.len() + self.block.len() > limit {
                if deferred.is_none() {
                    deferred = Some(channel);
                }
                continue;
            }
            self.block[0] = tagged(crate::KIND_FEEDBACK, channel);
            self.body.extend_from_slice(&self.block);
            self.receivers[channel].commit_feedback(now);
        }
        if self.body.is_empty() {
            return false;
        }
        if let Some(channel) = deferred {
            self.feedback_turn = channel;
        } else {
            self.feedback_at = now.saturating_add(self.send.codec.feedback_micros);
        }
        true
    }

    fn data(&mut self, now: u64, number: RecordNumber) -> Result<Option<EmissionKind>, Error> {
        let channels = self.send.channels;
        let urgent = (0..channels)
            .map(|step| (self.turn + step) % channels)
            .find(|channel| self.senders[*channel].urgent());
        let order = urgent
            .into_iter()
            .chain((0..channels).map(|step| (self.turn + step) % channels));
        for channel in order {
            if let Some(kind) = self.senders[channel].poll_kind(now, number.0, &mut self.body)? {
                self.body[0] = tagged(self.body[0], channel);
                if urgent != Some(channel) {
                    self.turn = (channel + 1) % channels;
                }
                return Ok(Some(match kind {
                    crate::sender::DataKind::Source => EmissionKind::Source,
                    crate::sender::DataKind::Repair => EmissionKind::Repair,
                }));
            }
        }
        Ok(None)
    }

    /// Produce the exact next body for the caller's unchanged security number.
    /// Feedback bypasses `allow_data`, but the caller must charge its wire cost.
    pub fn poll(
        &mut self,
        now: u64,
        number: RecordNumber,
        allow_data: bool,
    ) -> Result<Option<&[u8]>, Error> {
        Ok(self
            .poll_emission(now, number, allow_data)?
            .map(Emission::body))
    }

    /// Produce the exact next body with metadata from its actual algorithm branch.
    /// Feedback retains priority and is available even when data is disabled.
    pub fn poll_emission(
        &mut self,
        now: u64,
        number: RecordNumber,
        allow_data: bool,
    ) -> Result<Option<Emission<'_>>, Error> {
        let kind = if self.feedback(now) {
            Some(EmissionKind::Feedback)
        } else if allow_data {
            self.data(now, number)?
        } else {
            None
        };
        Ok(kind.map(|kind| Emission {
            kind,
            body: &self.body,
        }))
    }

    /// Emit under an explicit body allowance without changing the legacy poll.
    /// Feedback consists of complete unchanged per-channel blocks. A block that
    /// does not fit retains its debt, timers and repeats. Data is polled only
    /// when its full configured maximum fits; no source identity is consumed on
    /// a credit refusal. The caller still owns the full security number.
    pub fn poll_emission_bounded(
        &mut self,
        now: u64,
        number: RecordNumber,
        allow_data: bool,
        body_limit: usize,
    ) -> Result<Option<Emission<'_>>, Error> {
        self.poll_emission_with_limits(now, number, allow_data, body_limit, body_limit)
    }

    /// Poll the same feedback/data transitions with exact per-kind body credit.
    /// This supports a stronger outer check for debt-retiring feedback without
    /// reserving that overhead for ordinary data or consuming uncharged debt.
    pub fn poll_emission_with_limits(
        &mut self,
        now: u64,
        number: RecordNumber,
        allow_data: bool,
        data_body_limit: usize,
        feedback_body_limit: usize,
    ) -> Result<Option<Emission<'_>>, Error> {
        let maximum = self.send.codec.datagram_bytes;
        let feedback_limit = feedback_body_limit.min(maximum);
        let kind = if self.feedback_bounded(now, feedback_limit) {
            Some(EmissionKind::Feedback)
        } else if allow_data && data_body_limit >= maximum {
            self.data(now, number)?
        } else {
            None
        };
        Ok(kind.map(|kind| Emission {
            kind,
            body: &self.body,
        }))
    }

    /// Earliest actual feedback time and one complete block's byte requirement.
    /// This observation never consumes receiver state or changes channel service.
    pub fn feedback_opportunity(&self) -> Option<(u64, usize)> {
        self.receivers
            .iter()
            .filter_map(Receiver::feedback_opportunity)
            .map(|(at, bytes)| (at.max(self.feedback_at), bytes))
            .min()
    }

    /// Apply an already authenticated, replay-checked User record in workspace.
    /// A malformed authenticated body is terminal; partial updates do not roll back.
    pub fn accept(&mut self, now: u64, number: RecordNumber, body: &mut [u8]) -> Result<(), Error> {
        if body.is_empty() || body.len() > self.limit {
            return Err(crate::Error::Malformed.into());
        }
        let lead = body[0];
        let channel = usize::from(lead >> 2);
        if lead & crate::KIND_MASK != crate::KIND_FEEDBACK {
            if number.0 < self.source_floor.0 {
                self.base.receiver.duplicates += 1;
                return Ok(());
            }
            if channel >= self.receive.channels {
                return Err(crate::Error::Malformed.into());
            }
            body[0] = lead & crate::KIND_MASK;
            self.ready |= 1 << channel;
            return self.receivers[channel]
                .on_datagram(number.0, body)
                .map_err(Error::Codec);
        }
        if number.0 < self.feedback_floor.0 {
            return Ok(());
        }
        let mut rest = body;
        while !rest.is_empty() {
            let lead = rest[0];
            let channel = usize::from(lead >> 2);
            let requests = usize::from(
                *rest
                    .get(crate::FEEDBACK_HEADER - 1)
                    .ok_or(crate::Error::Malformed)?,
            );
            let length = crate::FEEDBACK_HEADER + 2 * requests;
            if lead & crate::KIND_MASK != crate::KIND_FEEDBACK
                || channel >= self.send.channels
                || rest.len() < length
            {
                return Err(crate::Error::Malformed.into());
            }
            let (block, tail) = rest.split_at_mut(length);
            block[0] = crate::KIND_FEEDBACK;
            self.senders[channel].on_feedback(now, block)?;
            rest = tail;
        }
        Ok(())
    }

    /// Whether a source, repair or retransmission is ready for the outer pacer.
    pub fn data_ready(&self, now: u64) -> bool {
        self.senders.iter().any(|sender| sender.ready(now))
    }
    /// Earliest sender deadline, without pacing or transaction deadlines.
    pub fn data_deadline(&self) -> Option<u64> {
        self.senders.iter().filter_map(Sender::deadline).min()
    }
    /// Whether due feedback can actually fit under the legacy packing rule.
    /// This observation changes no receiver counters, timers or output bytes.
    pub fn feedback_ready(&self, now: u64) -> bool {
        now >= self.feedback_at
            && self.send.codec.datagram_bytes >= crate::FEEDBACK_HEADER + 2 * crate::MAX_REQUESTS
            && self
                .receivers
                .iter()
                .any(|receiver| receiver.deadline().is_some_and(|at| at <= now))
    }
    /// Earliest channel-feedback scheduling turn under the legacy packing rule.
    pub fn feedback_deadline(&self) -> Option<u64> {
        self.receivers
            .iter()
            .any(|receiver| receiver.deadline().is_some())
            .then_some(self.feedback_at)
    }
    /// Whether native delivery may return another complete packet.
    pub fn deliverable(&self) -> bool {
        self.ready != 0
    }
    /// Return bytes through the same identified bounded receive-channel rotation.
    pub fn pop(&mut self) -> Result<Option<&[u8]>, Error> {
        Ok(self.pop_identified()?.map(|packet| packet.bytes))
    }
    /// Extract one complete native packet with its original ordered channel identity.
    /// Partial records consume no identity. This is not physical device completion.
    pub fn pop_identified(&mut self) -> Result<Option<NativePacket<'_>>, Error> {
        if self.ready == 0 {
            return Ok(None);
        }
        let channels = self.receive.channels;
        for step in 0..channels {
            let channel = (self.receive_turn + step) % channels;
            if self.ready & (1_u64 << channel) == 0 {
                continue;
            }
            if self.receivers[channel].next_packet_len()?.is_none() {
                self.record.clear();
                self.ready &= !(1_u64 << channel);
                continue;
            }
            let extracted = self.extracted[channel]
                .checked_add(1)
                .ok_or(Error::CounterExhausted)?;
            self.receivers[channel]
                .stats()
                .packets
                .checked_add(1)
                .ok_or(Error::CounterExhausted)?;
            let identity = NativeIdentity {
                channel: ChannelId::new(channel).ok_or(Error::Configuration)?,
                record: NativeRecordId(self.extracted[channel]),
            };
            if !self.receivers[channel].pop_packet(&mut self.record)? {
                return Err(crate::Error::Malformed.into());
            }
            self.decompressors[channel].decompress(
                &self.record,
                self.send.max_native,
                &mut self.native,
            )?;
            self.extracted[channel] = extracted;
            self.receive_turn = (channel + 1) % channels;
            return Ok(Some(NativePacket {
                identity,
                bytes: &self.native,
            }));
        }
        Ok(None)
    }
    /// Total retained sources across all sending channels.
    pub fn unconfirmed(&self) -> usize {
        self.senders.iter().map(Sender::unconfirmed).sum()
    }
    /// All queued bytes sent and every retained source confirmed.
    pub fn send_drained(&self) -> bool {
        self.senders
            .iter()
            .all(|sender| sender.unconfirmed() == 0 && sender.queued() == 0)
    }
    /// No deliverable or pending receive state remains before a reset.
    pub fn receive_drained(&self) -> bool {
        self.ready == 0 && self.receivers.iter().all(Receiver::drained)
    }
    /// First source/repair number allowed in the current receive epoch.
    pub fn source_floor(&self) -> RecordNumber {
        self.source_floor
    }
    /// First feedback number allowed to affect the current sending epoch.
    pub fn feedback_floor(&self) -> RecordNumber {
        self.feedback_floor
    }
    fn check_format(&self, config: Config) -> Result<(), Error> {
        config.validate()?;
        if config.layer != self.send.layer || config.max_native != self.send.max_native {
            return Err(Error::Configuration);
        }
        Ok(())
    }
    /// Replace a confirmed send direction after caller-authenticated barriers.
    pub fn replace_send(
        &mut self,
        config: Config,
        feedback_from: RecordNumber,
    ) -> Result<(), Error> {
        self.check_format(config)?;
        if !self.send_drained() {
            return Err(Error::NotDrained);
        }
        for sender in &self.senders {
            self.base.sender.add(&sender.stats());
        }
        self.base.header_bytes_saved += self
            .compressors
            .iter()
            .map(header::Compressor::saved)
            .sum::<u64>();
        self.senders.clear();
        self.compressors.clear();
        for _ in 0..config.channels {
            self.senders.push(Sender::new(config.codec)?);
            self.compressors
                .push(header::Compressor::new(config.layer == Layer::Ethernet));
        }
        self.limit = self.limit.max(config.codec.datagram_bytes);
        self.turn = 0;
        self.admitted = [0; crate::MAX_CHANNELS];
        self.send = config;
        self.feedback_floor = feedback_from;
        Ok(())
    }
    /// Replace a delivered receive direction after caller-authenticated barriers.
    pub fn replace_receive(
        &mut self,
        config: Config,
        source_from: RecordNumber,
    ) -> Result<(), Error> {
        self.check_format(config)?;
        if !self.receive_drained() {
            return Err(Error::NotDrained);
        }
        for receiver in &self.receivers {
            self.base.receiver.add(&receiver.stats());
        }
        self.receivers.clear();
        self.decompressors.clear();
        for _ in 0..config.channels {
            self.receivers.push(Receiver::new(config.codec)?);
            self.decompressors
                .push(header::Decompressor::new(config.layer == Layer::Ethernet));
        }
        self.limit = self.limit.max(config.codec.datagram_bytes);
        self.receive_turn = 0;
        self.feedback_turn = 0;
        self.ready = 0;
        self.extracted = [0; crate::MAX_CHANNELS];
        self.receive = config;
        self.source_floor = source_from;
        Ok(())
    }
    /// Cumulative retired plus current algorithm statistics.
    pub fn stats(&self) -> Stats {
        let mut stats = self.base;
        for sender in &self.senders {
            stats.sender.add(&sender.stats());
        }
        for receiver in &self.receivers {
            stats.receiver.add(&receiver.stats());
        }
        stats.header_bytes_saved += self
            .compressors
            .iter()
            .map(header::Compressor::saved)
            .sum::<u64>();
        stats
    }
}

#[cfg(test)]
mod storage_tests;
#[cfg(test)]
mod tests;

#[cfg(test)]
#[path = "records/bounded_feedback_tests.rs"]
mod bounded_feedback_tests;
