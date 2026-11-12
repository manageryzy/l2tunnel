//! Packing, systematic source emission, repair scheduling and retransmission.
use super::{
    Config, Error, FEEDBACK_HEADER, FRAME_PREFIX, KIND_FEEDBACK, KIND_REPAIR, KIND_SOURCE,
    MAX_REQUESTS, SenderStats, gf, read_u16, read_u32,
};
use std::collections::VecDeque;

struct Source {
    payload: Vec<u8>,
    first_sent: u64,
    last_sent: u64,
    retransmitted: bool,
    queued: bool,
}

/// One direction's sending engine.
pub struct Sender {
    config: Config,
    /// Packed native bytes not yet cut into a source symbol.
    queue: VecDeque<u8>,
    /// When the oldest byte of the current partial symbol was queued.
    queue_since: u64,
    /// Sent sources with sequence numbers `acked..next`.
    sources: VecDeque<Source>,
    acked: u32,
    next: u32,
    credit: u32,
    repairs_due: u32,
    retransmit: VecDeque<u32>,
    smoothed_rtt: u64,
    /// Highest `end` any feedback has reported.
    sampled_end: u32,
    /// Next idle probe time while unconfirmed sources remain.
    probe_at: Option<u64>,
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
        Ok(Self {
            config,
            queue: VecDeque::with_capacity(config.queue_bytes.min(1 << 16)),
            queue_since: 0,
            sources: VecDeque::new(),
            acked: 0,
            next: 0,
            credit: 0,
            repairs_due: 0,
            retransmit: VecDeque::new(),
            smoothed_rtt: 0,
            sampled_end: 0,
            probe_at: None,
            probe_interval: config.tail_micros,
            probe_burst: 0,
            peer_missing: 0,
            spare: Vec::new(),
            stats: SenderStats::default(),
        })
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
    /// Whether one more maximum-size native packet fits in the packing queue.
    pub fn has_room(&self) -> bool {
        self.queue.len() + self.config.max_packet + FRAME_PREFIX <= self.config.queue_bytes
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
        if self.queue.len() + packet.len() + FRAME_PREFIX > self.config.queue_bytes {
            return Ok(false);
        }
        let length = u16::try_from(packet.len()).map_err(|_| Error::PacketSize)?;
        if self.queue.is_empty() {
            self.queue_since = now;
        }
        self.queue.extend(length.to_be_bytes());
        self.queue.extend(packet);
        self.stats.packets += 1;
        Ok(true)
    }
    fn rto(&self) -> u64 {
        let estimate = if self.smoothed_rtt == 0 {
            self.config.max_rto_micros.min(200_000)
        } else {
            self.smoothed_rtt + self.smoothed_rtt / 4 + 10_000
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
    fn source(&mut self, sequence: u32) -> Option<&mut Source> {
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
    /// Write the next datagram body into `output` (cleared first). `seed` must
    /// be unique per datagram and is supplied again to the peer's receiver; the
    /// carrier's packet number serves. Returns `false` when nothing is due.
    ///
    /// Order: explicitly requested retransmissions, repairs already earned,
    /// new sources, then idle tail repairs.
    pub fn poll(&mut self, now: u64, seed: u64, output: &mut Vec<u8>) -> Result<bool, Error> {
        output.clear();
        while let Some(sequence) = self.retransmit.pop_front() {
            let Some(source) = self.source(sequence) else {
                continue;
            };
            source.queued = false;
            source.last_sent = now;
            source.retransmitted = true;
            output.push(KIND_SOURCE);
            output.extend_from_slice(&sequence.to_be_bytes());
            output.extend_from_slice(&source.payload);
            self.stats.retransmits += 1;
            return Ok(true);
        }
        if self.repairs_due > 0 {
            self.repairs_due -= 1;
            if self.repair(seed, output) {
                self.stats.repairs += 1;
                return Ok(true);
            }
        }
        if self.can_send_source(now) {
            let sequence = self.next;
            self.next = self.next.checked_add(1).ok_or(Error::Exhausted)?;
            let length = self.queue.len().min(self.config.symbol_bytes());
            let mut payload = self.spare.pop().unwrap_or_default();
            payload.clear();
            payload.extend(self.queue.drain(..length));
            // Whatever is left starts a new partial symbol.
            self.queue_since = now;
            output.push(KIND_SOURCE);
            output.extend_from_slice(&sequence.to_be_bytes());
            output.extend_from_slice(&payload);
            self.sources.push_back(Source {
                payload,
                first_sent: now,
                last_sent: now,
                retransmitted: false,
                queued: false,
            });
            self.stats.sources += 1;
            self.stats.packed_bytes += length as u64;
            self.credit += self.config.repair_numerator;
            self.repairs_due += self.credit / self.config.repair_denominator;
            self.credit %= self.config.repair_denominator;
            self.rearm_probe(now);
            self.probe_burst = 0;
            return Ok(true);
        }
        if self.sources.is_empty() {
            self.probe_at = None;
            self.probe_burst = 0;
            return Ok(false);
        }
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
            self.probe_interval =
                (self.probe_interval * 2).clamp(self.rto(), self.config.max_rto_micros);
            self.probe_at = Some(now.saturating_add(self.probe_interval));
        }
        if self.probe_burst > 0 {
            self.probe_burst -= 1;
            if self.repair(seed, output) {
                self.stats.tail_repairs += 1;
                return Ok(true);
            }
        }
        Ok(false)
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
        output.extend_from_slice(&self.next.to_be_bytes());
        output.push(count as u8);
        let body = output.len();
        output.resize(body + 2 + widest, 0);
        let start = self.next - count as u32;
        for (offset, source) in self.sources.range(first..).enumerate() {
            let factor = gf::coefficient(seed, start + offset as u32);
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
        let base = read_u32(&body[1..]).ok_or(Error::Malformed)?;
        let end = read_u32(&body[5..]).ok_or(Error::Malformed)?;
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
        // Sample the newest source the peer has seen, if it was sent once and
        // this is the first feedback to report it; later reports of the same
        // source measure how long the flow has been stalled, not the path.
        let fresh = end > self.sampled_end;
        self.sampled_end = self.sampled_end.max(end);
        if fresh
            && end > self.acked
            && let Some(source) = self.source(end - 1)
            && !source.retransmitted
        {
            let sample = now.saturating_sub(source.first_sent).max(1);
            // Track the path's floor: fall at once, rise slowly. Lost or
            // delayed feedback only ever inflates a sample.
            self.smoothed_rtt = if self.smoothed_rtt == 0 || sample < self.smoothed_rtt {
                sample
            } else {
                self.smoothed_rtt + (sample - self.smoothed_rtt) / 16
            };
            self.stats.smoothed_rtt_micros = self.smoothed_rtt;
        }
        if base > self.acked || fresh {
            // The peer is hearing us: no probe is needed until it goes quiet
            // again, and the next one starts from the short interval.
            self.rearm_probe(now);
        }
        while self.acked < base {
            if let Some(mut source) = self.sources.pop_front()
                && self.spare.len() < 64
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
        let rto = self.rto();
        for index in 0..requests {
            let offset = read_u16(&body[FEEDBACK_HEADER + 2 * index..]).ok_or(Error::Malformed)?;
            let Some(sequence) = base.checked_add(u32::from(offset)) else {
                return Err(Error::Malformed);
            };
            if sequence >= end {
                return Err(Error::Malformed);
            }
            if let Some(source) = self.source(sequence)
                && !source.queued
                // The first request is honoured at once: the peer only asks
                // for what coding can no longer cover. A repeat must wait
                // for the previous copy to have had time to arrive.
                && (!source.retransmitted || now.saturating_sub(source.last_sent) >= rto)
            {
                source.queued = true;
                self.retransmit.push_back(sequence);
            }
        }
        Ok(())
    }
}
