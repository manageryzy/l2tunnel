//! Packing, systematic source emission, repair scheduling and retransmission.
use super::{
    Config, Error, FEEDBACK_HEADER, FRAME_PREFIX, KIND_FEEDBACK, KIND_REPAIR, KIND_SOURCE,
    MAX_REQUESTS, SenderStats, expand, gf, read_u16, read_u32,
};
use std::collections::VecDeque;

/// Kind selected at the actual sender emission branch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DataKind {
    Source,
    Repair,
}

/// Exact branch retained until the enclosing record receives carrier custody.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PreparedData {
    Source { sequence: u64, first: bool },
    Repair { tail_interval: Option<u64> },
}
impl PreparedData {
    pub(crate) const fn kind(self) -> DataKind {
        match self {
            Self::Source { .. } => DataKind::Source,
            Self::Repair { .. } => DataKind::Repair,
        }
    }
}

struct Source {
    payload: Vec<u8>,
    first_sent: u64,
    accepted: bool,
    last_sent: u64,
    retransmitted: bool,
    queued: bool,
}

/// Read-only current sender occupancy and recovery observations.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Observation {
    /// Counters for this current directional engine only.
    pub stats: SenderStats,
    /// Packed native bytes, including prefixes, not yet cut into sources.
    pub queued_bytes: usize,
    /// Retained sources not yet confirmed by the peer.
    pub unconfirmed: usize,
    /// Current retransmission estimate, without changing any timer.
    pub rto_micros: u64,
    /// Explicit retransmission queue entries awaiting polling.
    pub retransmit_pending: usize,
    /// Proportional repairs earned but not yet polled.
    pub repairs_due: u32,
}

/// One direction's sending engine.
pub struct Sender {
    config: Config,
    reserved: bool,
    /// Packed native bytes not yet cut into a source symbol.
    queue: VecDeque<u8>,
    /// When the oldest byte of the current partial symbol was queued.
    queue_since: u64,
    /// Sent sources with sequence numbers `acked..next`.
    sources: VecDeque<Source>,
    acked: u64,
    next: u64,
    credit: u32,
    repairs_due: u32,
    retransmit: VecDeque<u64>,
    smoothed_rtt: u64,
    /// Highest `end` any feedback has reported.
    sampled_end: u64,
    /// Next idle probe time while unconfirmed sources remain.
    probe_at: Option<u64>,
    last_probe_feedback: Option<u64>,
    probe_interval: u64,
    probe_burst: u32,
    peer_missing: u32,
    spare: Vec<Vec<u8>>,
    stats: SenderStats,
}

impl Sender {
    /// Allocate bounded state; no packet is produced until a native packet is queued.
    pub fn new(config: Config) -> Result<Self, Error> {
        config.validate()?;
        Ok(Self::from_storage(
            config,
            false,
            VecDeque::with_capacity(config.queue_bytes.min(1 << 16)),
            VecDeque::new(),
            VecDeque::new(),
            Vec::new(),
        ))
    }

    /// Heap layouts only; the enclosing owner accounts for the Sender header.
    pub(crate) fn reserved_bytes(config: Config) -> Result<usize, Error> {
        config.validate()?;
        let payloads = crate::storage::array_bytes::<u8>(config.symbol_bytes())?
            .checked_mul(config.flow_sources)
            .ok_or(Error::Storage)?;
        [
            crate::storage::array_bytes::<u8>(config.queue_bytes)?,
            crate::storage::array_bytes::<Source>(config.flow_sources)?,
            crate::storage::array_bytes::<u64>(config.flow_sources)?,
            crate::storage::array_bytes::<Vec<u8>>(config.flow_sources)?,
            payloads,
        ]
        .into_iter()
        .try_fold(0usize, |sum, bytes| {
            sum.checked_add(bytes).ok_or(Error::Storage)
        })
    }

    /// Construct the existing algorithm with every retained allocation reserved.
    pub(crate) fn new_reserved(
        config: Config,
        allocation: &mut crate::storage::Allocation,
    ) -> Result<Self, Error> {
        Self::reserved_bytes(config)?;
        let queue = allocation.deque(config.queue_bytes)?;
        let sources = allocation.deque(config.flow_sources)?;
        let retransmit = allocation.deque(config.flow_sources)?;
        let mut spare = allocation.vec(config.flow_sources)?;
        for _ in 0..config.flow_sources {
            spare.push(allocation.vec(config.symbol_bytes())?);
        }
        Ok(Self::from_storage(
            config, true, queue, sources, retransmit, spare,
        ))
    }

    fn from_storage(
        config: Config,
        reserved: bool,
        queue: VecDeque<u8>,
        sources: VecDeque<Source>,
        retransmit: VecDeque<u64>,
        spare: Vec<Vec<u8>>,
    ) -> Self {
        Self {
            config,
            reserved,
            queue,
            queue_since: 0,
            sources,
            acked: 0,
            next: 0,
            credit: 0,
            repairs_due: 0,
            retransmit,
            smoothed_rtt: 0,
            sampled_end: 0,
            probe_at: None,
            last_probe_feedback: None,
            probe_interval: config.tail_micros,
            probe_burst: 0,
            peer_missing: 0,
            spare,
            stats: SenderStats::default(),
        }
    }

    /// Constant-time metadata checks; payload geometry is checked before reuse.
    fn check_storage(&self) -> Result<(), Error> {
        if self.reserved
            && (self.queue.capacity() != self.config.queue_bytes
                || self.sources.capacity() != self.config.flow_sources
                || self.retransmit.capacity() != self.config.flow_sources
                || self.spare.capacity() != self.config.flow_sources
                || self.queue.len() > self.config.queue_bytes
                || self.retransmit.len() > self.config.flow_sources
                || self.sources.len().checked_add(self.spare.len())
                    != Some(self.config.flow_sources))
        {
            return Err(Error::Storage);
        }
        Ok(())
    }
    /// Begin at an arbitrary sequence, as a long-lived session would be.
    #[cfg(test)]
    pub(crate) fn start_at(&mut self, sequence: u64) {
        (self.acked, self.next, self.sampled_end) = (sequence, sequence, sequence);
    }
    #[cfg(test)]
    pub(crate) fn debug_state(&self) -> String {
        format!(
            "acked {} next {} sources {} queue {} retransmit {:?} due {} probe_at {:?} interval {} burst {} missing {} rto {}",
            self.acked,
            self.next,
            self.sources.len(),
            self.queue.len(),
            self.retransmit,
            self.repairs_due,
            self.probe_at,
            self.probe_interval,
            self.probe_burst,
            self.peer_missing,
            self.rto()
        )
    }
    /// Current counters.
    pub fn stats(&self) -> SenderStats {
        self.stats
    }
    /// Observe current occupancy without polling, allocating or advancing time.
    pub fn observation(&self) -> Observation {
        Observation {
            stats: self.stats,
            queued_bytes: self.queue.len(),
            unconfirmed: self.sources.len(),
            rto_micros: self.rto(),
            retransmit_pending: self.retransmit.len(),
            repairs_due: self.repairs_due,
        }
    }
    /// Read actual queue/window occupancy without polling or updating any timer.
    pub fn buffer_snapshot(&self) -> crate::diagnostics::SenderBuffers {
        crate::diagnostics::SenderBuffers {
            packing_bytes: self.queue.len(),
            packing_capacity_bytes: self.config.queue_bytes,
            source_records: self.sources.len(),
            source_capacity_records: self.config.flow_sources,
            source_bytes: self.sources.iter().map(|source| source.payload.len()).sum(),
            source_capacity_bytes: self.config.flow_sources * self.config.symbol_bytes(),
            retry_entries: self.retransmit.len(),
            retry_capacity_entries: self.config.flow_sources,
            repairs_due: self.repairs_due,
        }
    }
    /// Whether one more maximum-size native packet fits in the packing queue.
    pub fn has_room(&self) -> bool {
        self.queue
            .len()
            .checked_add(self.config.max_packet)
            .and_then(|bytes| bytes.checked_add(FRAME_PREFIX))
            .is_some_and(|bytes| bytes <= self.config.queue_bytes)
    }
    /// Sources sent and not yet confirmed by the peer.
    pub fn unconfirmed(&self) -> usize {
        self.sources.len()
    }
    /// Queue one native packet for packing. Returns `false`, leaving the queue
    /// unchanged, when the bounded queue is full; the caller then drops or
    /// retains the packet.
    pub fn push_packet(&mut self, now: u64, packet: &[u8]) -> Result<bool, Error> {
        if packet.is_empty() || packet.len() > self.config.max_packet {
            return Err(Error::PacketSize);
        }
        let queued = self
            .queue
            .len()
            .checked_add(packet.len())
            .and_then(|bytes| bytes.checked_add(FRAME_PREFIX))
            .ok_or(Error::Storage)?;
        if queued > self.config.queue_bytes {
            return Ok(false);
        }
        self.check_storage()?;
        if self.reserved && queued > self.queue.capacity() {
            return Err(Error::Storage);
        }
        let length = u16::try_from(packet.len()).map_err(|_| Error::PacketSize)?;
        let packets = self.stats.packets.checked_add(1).ok_or(Error::Exhausted)?;
        if self.queue.is_empty() {
            self.queue_since = now;
        }
        self.queue.extend(length.to_be_bytes());
        self.queue.extend(packet);
        self.stats.packets = packets;
        Ok(true)
    }
    fn rto(&self) -> u64 {
        self.rto_with(self.smoothed_rtt)
    }
    fn rto_with(&self, smoothed_rtt: u64) -> u64 {
        let estimate = if smoothed_rtt == 0 {
            self.config.max_rto_micros.min(200_000)
        } else {
            smoothed_rtt
                .saturating_add(smoothed_rtt / 4)
                .saturating_add(10_000)
        };
        estimate.clamp(self.config.min_rto_micros, self.config.max_rto_micros)
    }
    /// Schedule the idle probe one quiet period from now. Before the path is
    /// measured that is the configured tail time; afterwards it is at least a
    /// retransmission interval, so a probe never races feedback in flight.
    fn rearm_probe(&mut self, now: u64) {
        self.probe_interval = if self.smoothed_rtt == 0 {
            self.config.tail_micros
        } else {
            self.config.tail_micros.max(self.rto())
        };
        self.probe_at = Some(now.saturating_add(self.probe_interval));
    }
    fn source(&mut self, sequence: u64) -> Option<&mut Source> {
        let index = usize::try_from(sequence.checked_sub(self.acked)?).ok()?;
        self.sources.get_mut(index)
    }
    /// Earliest time at which [`Sender::poll`] may have something new to send
    /// without further input.
    pub fn deadline(&self) -> Option<u64> {
        let probe = if self.sources.is_empty() {
            None
        } else {
            self.probe_at
        };
        let flush = (!self.queue.is_empty() && self.sources.len() < self.config.flow_sources)
            .then(|| self.queue_since.saturating_add(self.config.flush_micros));
        match (probe, flush) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        }
    }
    /// Native bytes, including length prefixes, waiting to be cut into sources.
    pub fn queued(&self) -> usize {
        self.queue.len()
    }
    /// Whether a requested retransmission is waiting; these go before
    /// anything else a frontend multiplexes onto the same budget.
    pub fn urgent(&self) -> bool {
        !self.retransmit.is_empty()
    }
    /// Whether a datagram is ready right now, ignoring pacing.
    pub fn ready(&self, now: u64) -> bool {
        !self.retransmit.is_empty()
            || (self.repairs_due > 0 && !self.sources.is_empty())
            || self.can_send_source(now)
            || self.probe_burst > 0
            || (!self.sources.is_empty() && self.probe_at.is_some_and(|at| now >= at))
    }
    /// A full symbol is ready, or a partial one has waited long enough.
    fn can_send_source(&self, now: u64) -> bool {
        self.sources.len() < self.config.flow_sources
            && (self.queue.len() >= self.config.symbol_bytes()
                || (!self.queue.is_empty()
                    && now >= self.queue_since.saturating_add(self.config.flush_micros)))
    }
    /// Synchronous handoff at `now`; asynchronous callers use record preparation.
    /// Write the next datagram body into `output` (cleared first). `seed` must
    /// be unique per datagram and is supplied again to the peer's receiver; the
    /// carrier's packet number serves. Returns `false` when nothing is due.
    ///
    /// Order: explicitly requested retransmissions, repairs already earned,
    /// new sources, then idle tail repairs.
    pub fn poll(&mut self, now: u64, seed: u64, output: &mut Vec<u8>) -> Result<bool, Error> {
        Ok(self.poll_kind(now, seed, output)?.is_some())
    }

    /// Preserve the selected emission branch without inspecting its encoded body.
    pub(crate) fn poll_kind(
        &mut self,
        now: u64,
        seed: u64,
        output: &mut Vec<u8>,
    ) -> Result<Option<DataKind>, Error> {
        let prepared = self.prepare_kind(now, seed, output)?;
        if let Some(prepared) = prepared {
            self.confirm_prepared(now, prepared);
        }
        Ok(prepared.map(PreparedData::kind))
    }

    pub(crate) fn prepare_kind(
        &mut self,
        now: u64,
        seed: u64,
        output: &mut Vec<u8>,
    ) -> Result<Option<PreparedData>, Error> {
        self.check_storage()?;
        if self.reserved && output.capacity() < self.config.datagram_bytes {
            return Err(Error::Storage);
        }
        output.clear();
        while let Some(sequence) = self.retransmit.front().copied() {
            let source_index = sequence
                .checked_sub(self.acked)
                .and_then(|value| usize::try_from(value).ok());
            if source_index.is_none_or(|index| index >= self.sources.len()) {
                let _ = self.retransmit.pop_front();
                continue;
            }
            let retransmits = self
                .stats
                .retransmits
                .checked_add(1)
                .ok_or(Error::Exhausted)?;
            let _ = self.retransmit.pop_front();
            let source = self.source(sequence).ok_or(Error::Storage)?;
            // Keep the requested attempt guarded until actual carrier custody.
            source.queued = true;
            output.push(KIND_SOURCE);
            output.extend_from_slice(&(sequence as u32).to_be_bytes());
            output.extend_from_slice(&source.payload);
            self.stats.retransmits = retransmits;
            return Ok(Some(PreparedData::Source {
                sequence,
                first: false,
            }));
        }
        if self.repairs_due > 0 {
            let repairs = if self.sources.is_empty() {
                self.stats.repairs
            } else {
                self.stats.repairs.checked_add(1).ok_or(Error::Exhausted)?
            };
            self.repairs_due -= 1;
            if self.repair(seed, output) {
                self.stats.repairs = repairs;
                return Ok(Some(PreparedData::Repair {
                    tail_interval: None,
                }));
            }
        }
        if self.can_send_source(now) {
            let sequence = self.next;
            let next = self.next.checked_add(1).ok_or(Error::Exhausted)?;
            let length = self.queue.len().min(self.config.symbol_bytes());
            let credit = self
                .credit
                .checked_add(self.config.repair_numerator)
                .ok_or(Error::Exhausted)?;
            let repairs_due = self
                .repairs_due
                .checked_add(credit / self.config.repair_denominator)
                .ok_or(Error::Exhausted)?;
            let sources = self.stats.sources.checked_add(1).ok_or(Error::Exhausted)?;
            let packed_bytes = self
                .stats
                .packed_bytes
                .checked_add(length as u64)
                .ok_or(Error::Exhausted)?;
            if self.reserved
                && (self.sources.len() >= self.sources.capacity()
                    || self
                        .spare
                        .last()
                        .is_none_or(|payload| payload.capacity() != self.config.symbol_bytes()))
            {
                return Err(Error::Storage);
            }
            let mut payload = if self.reserved {
                self.spare.pop().ok_or(Error::Storage)?
            } else {
                self.spare.pop().unwrap_or_default()
            };
            payload.clear();
            // The reserved payload is empty with capacity S, and length <= S;
            // append_prefix's existing reserve therefore cannot allocate.
            crate::byte_queue::append_prefix(&mut self.queue, length, &mut payload)?;
            self.next = next;
            // Whatever is left starts a new partial symbol.
            self.queue_since = now;
            output.push(KIND_SOURCE);
            output.extend_from_slice(&(sequence as u32).to_be_bytes());
            output.extend_from_slice(&payload);
            self.sources.push_back(Source {
                payload,
                first_sent: 0,
                accepted: false,
                last_sent: 0,
                retransmitted: false,
                queued: true,
            });
            self.stats.sources = sources;
            self.stats.packed_bytes = packed_bytes;
            self.repairs_due = repairs_due;
            self.credit = credit % self.config.repair_denominator;
            self.probe_burst = 0;
            return Ok(Some(PreparedData::Source {
                sequence,
                first: true,
            }));
        }
        if self.sources.is_empty() {
            self.probe_at = None;
            self.probe_burst = 0;
            return Ok(None);
        }
        let tail_repairs = if self.probe_burst > 0 || self.probe_at.is_some_and(|at| now >= at) {
            self.stats
                .tail_repairs
                .checked_add(1)
                .ok_or(Error::Exhausted)?
        } else {
            self.stats.tail_repairs
        };
        let mut tail_interval = None;
        if self.probe_burst == 0 && self.probe_at.is_some_and(|at| now >= at) {
            // With proportional repairs, enough independent equations for
            // everything the peer still reports missing inside the window.
            // Otherwise one equation: it reveals the newest sequence and the
            // peer then asks for exactly what it lacks.
            self.probe_burst = if self.config.repair_numerator == 0 {
                1
            } else {
                self.peer_missing.clamp(1, self.config.window as u32)
            };
            tail_interval = Some(
                self.probe_interval
                    .saturating_mul(2)
                    .clamp(self.rto(), self.config.max_rto_micros),
            );
        }
        if self.probe_burst > 0 {
            self.probe_burst -= 1;
            if self.repair(seed, output) {
                self.stats.tail_repairs = tail_repairs;
                return Ok(Some(PreparedData::Repair { tail_interval }));
            }
        }
        Ok(None)
    }
    /// Consume actual acceptance without resurrecting sources already ACKed by
    /// an older copy. Newer feedback, including equal-tick observations, wins.
    pub(crate) fn confirm_prepared(&mut self, accepted: u64, prepared: PreparedData) {
        let mut first_retained = false;
        if let PreparedData::Source { sequence, first } = prepared
            && let Some(source) = self.source(sequence)
        {
            if first {
                source.first_sent = accepted;
                source.accepted = true;
                first_retained = true;
            } else {
                source.retransmitted = true;
            }
            source.last_sent = accepted;
            source.queued = false;
        }
        if self.sources.is_empty() || self.last_probe_feedback.is_some_and(|at| at >= accepted) {
            return;
        }
        if first_retained {
            self.rearm_probe(accepted);
        } else if let PreparedData::Repair {
            tail_interval: Some(interval),
        } = prepared
        {
            self.probe_interval = interval;
            self.probe_at = Some(accepted.saturating_add(interval));
        }
    }
    /// One equation over the newest unconfirmed sources, at most one window.
    fn repair(&mut self, seed: u64, output: &mut Vec<u8>) -> bool {
        let count = self.sources.len().min(self.config.window);
        if count == 0 {
            return false;
        }
        let first = self.sources.len() - count;
        let widest = self
            .sources
            .range(first..)
            .map(|source| source.payload.len())
            .max()
            .unwrap_or(0);
        output.clear();
        output.push(KIND_REPAIR);
        output.extend_from_slice(&(self.next as u32).to_be_bytes());
        output.push(count as u8);
        let body = output.len();
        output.resize(body + 2 + widest, 0);
        let start = self.next - count as u64;
        for (offset, source) in self.sources.range(first..).enumerate() {
            let factor = gf::coefficient(seed, (start + offset as u64) as u32);
            let length = (source.payload.len() as u16).to_be_bytes();
            gf::mul_add(&mut output[body..body + 2], &length, factor);
            gf::mul_add(&mut output[body + 2..], &source.payload, factor);
        }
        true
    }
    /// Apply one authenticated feedback datagram body.
    pub fn on_feedback(&mut self, now: u64, body: &[u8]) -> Result<(), Error> {
        if body.first() != Some(&KIND_FEEDBACK) || body.len() < FEEDBACK_HEADER {
            return Err(Error::Malformed);
        }
        // The wire carries the low 32 bits; both lie within one flow window
        // of what this sender has confirmed.
        let base = read_u32(&body[1..])
            .and_then(|wire| expand(self.acked, wire))
            .ok_or(Error::Malformed)?;
        let end = read_u32(&body[5..])
            .and_then(|wire| expand(self.acked, wire))
            .ok_or(Error::Malformed)?;
        let missing = read_u16(&body[9..]).ok_or(Error::Malformed)?;
        let requests = usize::from(body[11]);
        if base > end
            || end > self.next
            || requests > MAX_REQUESTS
            || body.len() != FEEDBACK_HEADER + 2 * requests
        {
            return Err(Error::Malformed);
        }
        // Delayed feedback may be older than what is already confirmed.
        if base < self.acked {
            return Ok(());
        }
        self.check_storage()?;
        // Validate the complete request list before ACK, RTT or probe changes.
        // At most 64 stack entries are needed; duplicate requests retain order.
        let mut sequences = [0; MAX_REQUESTS];
        for (index, sequence) in sequences[..requests].iter_mut().enumerate() {
            let offset = read_u16(&body[FEEDBACK_HEADER + 2 * index..]).ok_or(Error::Malformed)?;
            *sequence = base
                .checked_add(u64::from(offset))
                .ok_or(Error::Malformed)?;
            if *sequence >= end {
                return Err(Error::Malformed);
            }
        }
        let acknowledged = usize::try_from(base - self.acked).map_err(|_| Error::Malformed)?;
        if acknowledged > self.sources.len() {
            return Err(Error::Malformed);
        }
        // Sample the newest source the peer has seen, if it was sent once and
        // this is the first feedback to report it; later reports of the same
        // source measure how long the flow has been stalled, not the path.
        let fresh = end > self.sampled_end;
        let sample_source = end
            .checked_sub(1)
            .and_then(|sequence| sequence.checked_sub(self.acked))
            .and_then(|index| usize::try_from(index).ok())
            .and_then(|index| self.sources.get(index));
        let sampled = if fresh
            && let Some(source) = sample_source
            && source.accepted
            && !source.retransmitted
        {
            let sample = now.saturating_sub(source.first_sent).max(1);
            // Track the path's floor: fall at once, rise slowly. Lost or
            // delayed feedback only ever inflates a sample.
            Some(if self.smoothed_rtt == 0 || sample < self.smoothed_rtt {
                sample
            } else {
                self.smoothed_rtt + (sample - self.smoothed_rtt) / 16
            })
        } else {
            None
        };
        let rto = self.rto_with(sampled.unwrap_or(self.smoothed_rtt));
        let mut enqueue = [0; MAX_REQUESTS];
        let mut enqueue_count = 0;
        for sequence in sequences[..requests].iter().copied() {
            let source = usize::try_from(sequence - self.acked)
                .ok()
                .and_then(|index| self.sources.get(index));
            if source.is_some_and(|source| {
                !source.queued
                    && (!source.retransmitted || now.saturating_sub(source.last_sent) >= rto)
            }) && !enqueue[..enqueue_count].contains(&sequence)
            {
                enqueue[enqueue_count] = sequence;
                enqueue_count += 1;
            }
        }
        let pending = self
            .retransmit
            .len()
            .checked_add(enqueue_count)
            .ok_or(Error::Storage)?;
        if pending > self.config.flow_sources
            || self.reserved
                && (pending > self.retransmit.capacity()
                    || self
                        .spare
                        .len()
                        .checked_add(acknowledged)
                        .is_none_or(|count| count > self.spare.capacity())
                    || self
                        .sources
                        .iter()
                        .take(acknowledged)
                        .any(|source| source.payload.capacity() != self.config.symbol_bytes()))
        {
            return Err(Error::Storage);
        }
        self.sampled_end = self.sampled_end.max(end);
        if let Some(sample) = sampled {
            self.smoothed_rtt = sample;
            self.stats.smoothed_rtt_micros = sample;
        }
        if base > self.acked || fresh {
            // The peer is hearing us: no probe is needed until it goes quiet
            // again, and the next one starts from the short interval.
            self.last_probe_feedback = Some(now);
            self.rearm_probe(now);
        }
        let spare_limit = if self.reserved {
            self.config.flow_sources
        } else {
            64
        };
        while self.acked < base {
            if let Some(mut source) = self.sources.pop_front()
                && self.spare.len() < spare_limit
            {
                source.payload.clear();
                self.spare.push(source.payload);
            }
            self.acked += 1;
        }
        self.peer_missing = u32::from(missing);
        if self.sources.is_empty() {
            self.probe_at = None;
            self.probe_burst = 0;
            self.repairs_due = 0;
        }
        for sequence in enqueue[..enqueue_count].iter().copied() {
            // First requests are immediate; repeats use the prospective RTT
            // above, exactly as the original post-sample scheduling did.
            self.source(sequence).ok_or(Error::Storage)?.queued = true;
            self.retransmit.push_back(sequence);
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "sender_byte_queue_tests.rs"]
mod byte_queue_tests;

#[cfg(test)]
#[path = "sender_storage_tests.rs"]
mod storage_tests;
