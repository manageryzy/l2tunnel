//! Adaptive resend and O(1) amortized scheduling for wide send directions
//! (more than 64 records). Windows of at most 64 never construct this state and
//! keep the classic fixed timer and storage scans unchanged.
use super::{ArqConfig, Engine, Flight, Profile, RecoveryError, SourceId};
use std::{
    cmp::Reverse,
    collections::{BinaryHeap, VecDeque},
    time::Duration,
};

/// Lowest adaptive RTO, unless the configured initial RTO is already lower.
pub const ADAPTIVE_RTO_FLOOR: Duration = Duration::from_millis(20);
/// A copy is presumed lost once the peer acknowledges a copy transmitted at
/// least this many transmissions after it. Ordering by transmission, not by
/// wall time, keeps queue-inflated RTTs from re-sending copies still in flight.
pub const FAST_RESEND_THRESHOLD: u64 = 3;

/// One armed retry timer; valid only while it matches the live flight.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) struct Deadline {
    at: Duration,
    source: u64,
    attempts: u32,
}
/// Reserved heap element; storage plans charge `2 * send_records` of these.
pub(crate) type DeadlineEntry = Reverse<Deadline>;

/// One transmitted copy in transmission order; valid only while its serial is
/// still the flight's latest. Storage plans charge `2 * send_records` of these.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct SentEntry {
    serial: u64,
    source: u64,
}

#[derive(Debug)]
pub(super) struct WideTiming {
    deadlines: BinaryHeap<DeadlineEntry>,
    capacity: usize,
    /// Transmitted copies in transmission order (lazy deletion).
    order: VecDeque<SentEntry>,
    /// Serial of the latest transmitted copy.
    serial: u64,
    /// Highest serial among copies the peer has acknowledged.
    acknowledged_serial: u64,
    /// No retained source is below this (tightened after every mutation).
    oldest: u64,
    /// No unsent source is below this (tightened after every mutation).
    unsent: u64,
    srtt: Option<Duration>,
    rttvar: Duration,
}

impl WideTiming {
    /// Both storages must have capacity for twice the send window.
    pub(super) fn new(
        config: ArqConfig,
        storage: Vec<DeadlineEntry>,
        order: Vec<SentEntry>,
    ) -> Self {
        let capacity = 2 * config.send_records;
        debug_assert!(storage.capacity() >= capacity && order.capacity() >= capacity);
        Self {
            deadlines: BinaryHeap::from(storage),
            capacity,
            order: VecDeque::from(order),
            serial: 0,
            acknowledged_serial: 0,
            oldest: 0,
            unsent: 0,
            srtt: None,
            rttvar: Duration::ZERO,
        }
    }
    /// Allocate unreserved backing for the dynamic (legacy) constructor.
    pub(super) fn dynamic(config: ArqConfig) -> Self {
        Self::new(
            config,
            Vec::with_capacity(2 * config.send_records),
            Vec::with_capacity(2 * config.send_records),
        )
    }
    /// RTO for a newly armed (first or fast) send.
    pub(super) fn rto(&self, config: ArqConfig) -> Duration {
        let floor = ADAPTIVE_RTO_FLOOR.min(config.initial_rto);
        match self.srtt {
            None => config.initial_rto,
            Some(srtt) => srtt
                .saturating_add(self.rttvar.saturating_mul(4))
                .saturating_add(config.ack_delay)
                .clamp(floor, config.maximum_rto),
        }
    }
    /// RFC 6298 smoothing of one authenticated sample.
    fn sample(&mut self, rtt: Duration) {
        match self.srtt {
            None => {
                self.srtt = Some(rtt);
                self.rttvar = rtt / 2;
            }
            Some(srtt) => {
                let error = srtt.abs_diff(rtt);
                self.rttvar = (self.rttvar.saturating_mul(3) + error) / 4;
                self.srtt = Some((srtt.saturating_mul(7) + rtt) / 8);
            }
        }
    }
}

/// Send instant of a flight's armed timer (`retry_at - rto`).
pub(super) fn armed_at(flight: &Flight) -> Option<Duration> {
    flight
        .retry_at
        .map(|deadline| deadline.saturating_sub(flight.rto))
}

impl Engine {
    pub(super) fn wide_active(&self) -> bool {
        self.wide.is_some() && self.profile == Profile::Selective
    }

    /// Record a newly armed timer for `source`; rebuilds when the heap is full.
    pub(super) fn wide_arm(&mut self, source: SourceId) {
        let Some(flight) = self.sent.get(&source) else {
            return;
        };
        let Some(at) = flight.retry_at else {
            return;
        };
        let entry = Reverse(Deadline {
            at,
            source: source.0,
            attempts: flight.attempts,
        });
        let Some(wide) = self.wide.as_mut() else {
            return;
        };
        if wide.deadlines.len() >= wide.capacity {
            // At most `send_records` live timers exist, so a rebuild frees at
            // least half the reservation: amortized O(log window) per arm.
            wide.deadlines.clear();
            for (source, flight) in self.sent.iter() {
                if let Some(at) = flight.retry_at {
                    wide.deadlines.push(Reverse(Deadline {
                        at,
                        source: source.0,
                        attempts: flight.attempts,
                    }));
                }
            }
            if wide.deadlines.len() >= wide.capacity {
                return;
            }
        }
        wide.deadlines.push(entry);
    }

    /// Drop stale heap tops and tighten both pointers (amortized O(1)).
    pub(super) fn wide_tidy(&mut self) {
        let Some(wide) = self.wide.as_mut() else {
            return;
        };
        while let Some(Reverse(top)) = wide.deadlines.peek() {
            let valid = self.sent.get(&SourceId(top.source)).is_some_and(|flight| {
                flight.retry_at == Some(top.at) && flight.attempts == top.attempts
            });
            if valid {
                break;
            }
            wide.deadlines.pop();
        }
        while wide.oldest < self.next_source && self.sent.get(&SourceId(wide.oldest)).is_none() {
            wide.oldest += 1;
        }
        wide.unsent = wide.unsent.max(wide.oldest);
        while wide.unsent < self.next_source
            && self
                .sent
                .get(&SourceId(wide.unsent))
                .is_none_or(|flight| flight.attempts > 0)
        {
            wide.unsent += 1;
        }
    }

    /// Earliest due retry and lowest unsent source, in O(1).
    pub(super) fn wide_ready(&self, now: Duration) -> (Option<SourceId>, Option<SourceId>) {
        let Some(wide) = self.wide.as_ref() else {
            return (None, None);
        };
        let retry = wide
            .deadlines
            .peek()
            .filter(|Reverse(top)| top.at <= now)
            .map(|Reverse(top)| SourceId(top.source));
        (retry, self.wide_unsent())
    }

    fn wide_unsent(&self) -> Option<SourceId> {
        let wide = self.wide.as_ref()?;
        (wide.unsent < self.next_source
            && self
                .sent
                .get(&SourceId(wide.unsent))
                .is_some_and(|flight| flight.attempts == 0))
        .then_some(SourceId(wide.unsent))
    }

    /// Earliest retry deadline, or now when a first send is waiting.
    pub(super) fn wide_source_deadline(&self) -> Option<Duration> {
        let wide = self.wide.as_ref()?;
        let retry = wide.deadlines.peek().map(|Reverse(top)| top.at);
        let unsent = self.wide_unsent().map(|_| self.last_now);
        retry.into_iter().chain(unsent).min()
    }

    /// Lowest retained source, in O(1).
    pub(super) fn wide_oldest(&self) -> Option<SourceId> {
        let wide = self.wide.as_ref()?;
        (wide.oldest < self.next_source && !self.sent.is_empty()).then_some(SourceId(wide.oldest))
    }

    /// Timer for the attempt being prepared now: adaptive for first and fast
    /// sends, doubled (capped) for timeout retries.
    pub(super) fn wide_attempt_rto(&self, flight: &Flight) -> Option<Duration> {
        let wide = self.wide.as_ref()?;
        Some(if flight.attempts == 0 || flight.fast_resend {
            wide.rto(self.config)
        } else {
            flight
                .rto
                .checked_mul(2)
                .unwrap_or(self.config.maximum_rto)
                .min(self.config.maximum_rto)
        })
    }

    /// One RTT sample per ACK from the latest single-attempt flight it released.
    pub(super) fn wide_sample(&mut self, now: Duration, latest_armed: Option<Duration>) {
        if let (Some(wide), Some(armed)) = (self.wide.as_mut(), latest_armed)
            && now >= armed
        {
            wide.sample(now - armed);
        }
    }

    /// Assign the next transmission serial to the copy of `source` being
    /// prepared now and queue it in transmission order.
    pub(super) fn wide_transmit(&mut self, source: SourceId) {
        let Some(wide) = self.wide.as_mut() else {
            return;
        };
        wide.serial += 1;
        let serial = wide.serial;
        if let Some(flight) = self.sent.get_mut(&source) {
            flight.serial = serial;
        }
        if wide.order.len() >= wide.capacity {
            // At most `send_records` copies are current, so dropping superseded
            // and released entries frees at least half: amortized O(1).
            let sent = &self.sent;
            wide.order.retain(|entry| {
                sent.get(&SourceId(entry.source))
                    .is_some_and(|flight| flight.serial == entry.serial)
            });
            if wide.order.len() >= wide.capacity {
                return;
            }
        }
        wide.order.push_back(SentEntry {
            serial,
            source: source.0,
        });
    }

    /// Raise the acknowledged transmission serial from one ACK.
    pub(super) fn wide_acknowledged(&mut self, serial: u64) {
        if let Some(wide) = self.wide.as_mut() {
            wide.acknowledged_serial = wide.acknowledged_serial.max(serial);
        }
    }

    /// Make due now every confirmed, unacknowledged copy that a copy sent at
    /// least `FAST_RESEND_THRESHOLD` transmissions later has overtaken.
    /// Each queued copy is examined once: amortized O(1) per transmission.
    pub(super) fn wide_fast_resend(&mut self, now: Duration) -> Result<(), RecoveryError> {
        loop {
            let Some(wide) = self.wide.as_mut() else {
                return Ok(());
            };
            let Some(entry) = wide.order.front().copied() else {
                return Ok(());
            };
            if entry
                .serial
                .checked_add(FAST_RESEND_THRESHOLD)
                .is_none_or(|limit| limit > wide.acknowledged_serial)
            {
                return Ok(());
            }
            wide.order.pop_front();
            let id = SourceId(entry.source);
            if let Some(flight) = self.sent.get_mut(&id)
                && flight.serial == entry.serial
                && !flight.acknowledged
                && flight.attempts > 0
                && let Some(deadline) = flight.retry_at
                && deadline > now
            {
                flight.retry_at = Some(now);
                flight.fast_resend = true;
                self.statistics.fast_retransmissions =
                    self.statistics.fast_retransmissions.saturating_add(1);
                self.wide_arm(id);
            }
        }
    }
}
