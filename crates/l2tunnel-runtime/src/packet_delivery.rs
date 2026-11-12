//! Original native-byte flight, independent of local queues and recovery windows.
use crate::{RuntimeConfig, invalid, managed::DeliveryConfig};
use l2tunnel_flow_control::{delivery_window, target::Micros};
use std::{io, mem::size_of, time::Duration};
use tokio::{sync::mpsc, time::Instant};

#[derive(Clone, Copy)]
struct Native {
    ordinal: u64,
    admitted: Micros,
    message: u64,
    first_source: Option<u64>,
    submitted: usize,
    parts: usize,
    sent: usize,
    latest: Micros,
}

/// One original source, resolved from locally generated authenticated geometry.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Witness {
    ordinal: u64,
    index: usize,
}

pub(crate) struct Packet {
    pub bytes: Vec<u8>,
    pub length: usize,
    pub witness: Option<Witness>,
}
pub(crate) struct Sent {
    pub lane: usize,
    pub witness: Witness,
    pub at: Instant,
}

fn micros(now: Duration) -> io::Result<Micros> {
    Ok(Micros(
        u64::try_from(now.as_micros()).map_err(io::Error::other)?,
    ))
}
pub(crate) fn since(origin: Instant, at: Instant) -> io::Result<Duration> {
    at.checked_duration_since(origin)
        .ok_or_else(|| invalid("packet delivery event precedes actor"))
}
fn metadata(policy: delivery_window::Config, parts: usize) -> io::Result<usize> {
    if parts == 0 {
        return Err(invalid("packet delivery has no fragments"));
    }
    policy
        .metadata_bytes()
        .map_err(io::Error::other)?
        .checked_add(
            policy
                .max_records
                .checked_mul(
                    size_of::<Option<Native>>()
                        .checked_add(
                            parts
                                .div_ceil(64)
                                .checked_mul(8)
                                .ok_or_else(|| invalid("packet fragment metadata overflow"))?,
                        )
                        .ok_or_else(|| invalid("packet native metadata overflow"))?,
                )
                .ok_or_else(|| invalid("packet flight metadata overflow"))?,
        )
        .ok_or_else(|| invalid("packet metadata overflow"))
}
pub(crate) fn validate(
    runtime: RuntimeConfig,
    delivery: DeliveryConfig,
    source_bytes: usize,
) -> io::Result<usize> {
    delivery.validate(runtime)?;
    let chunk = source_bytes
        .checked_sub(l2tunnel_codec::FRAGMENT_HEADER_BYTES)
        .filter(|n| *n != 0)
        .ok_or_else(|| invalid("packet fragment payload bound"))?;
    let parts = runtime.codec()?.max_encoded_len().div_ceil(chunk);
    if parts > usize::from(u16::MAX) {
        return Err(invalid("packet fragment count ceiling"));
    }
    validate_parts(runtime, delivery, parts)?;
    Ok(parts)
}

/// Preflight a caller's exact wrapper/fragment geometry without allocating.
pub(crate) fn validate_parts(
    runtime: RuntimeConfig,
    delivery: DeliveryConfig,
    parts: usize,
) -> io::Result<()> {
    delivery.validate(runtime)?;
    if parts == 0 || parts > usize::from(u16::MAX) {
        return Err(invalid("packet fragment count ceiling"));
    }
    for policy in [delivery.forward, delivery.reverse] {
        if metadata(policy, parts)? > policy.metadata_limit_bytes {
            return Err(invalid(
                "delivery metadata excludes original fragment ownership",
            ));
        }
    }
    Ok(())
}

/// A complete bounded ordinal span retains early-ACK/unobserved-send ownership.
pub(crate) struct Flight {
    pub controller: delivery_window::Controller,
    entries: Vec<Option<Native>>,
    bits: Vec<u64>,
    words: usize,
    parts: usize,
    retired_source: Option<u64>,
    retired_ordinal: u64,
    admitted_ordinal: u64,
    #[cfg(test)]
    lookup_steps: std::cell::Cell<usize>,
    #[cfg(test)]
    retire_steps: usize,
}
impl Flight {
    pub fn new(policy: delivery_window::Config, parts: usize) -> io::Result<Self> {
        policy.validate().map_err(io::Error::other)?;
        if parts == 0 || parts > usize::from(u16::MAX) {
            return Err(invalid("packet fragment count ceiling"));
        }
        if metadata(policy, parts)? > policy.metadata_limit_bytes {
            return Err(invalid("packet original fragment metadata capacity"));
        }
        let words = parts.div_ceil(64);
        let mut entries = Vec::new();
        entries
            .try_reserve_exact(policy.max_records)
            .map_err(io::Error::other)?;
        entries.resize(policy.max_records, None);
        let count = words
            .checked_mul(policy.max_records)
            .ok_or_else(|| invalid("packet fragment bitmap capacity"))?;
        let mut bits = Vec::new();
        bits.try_reserve_exact(count).map_err(io::Error::other)?;
        bits.resize(count, 0);
        Ok(Self {
            controller: delivery_window::Controller::new(policy, Micros(0))
                .map_err(io::Error::other)?,
            entries,
            bits,
            words,
            parts,
            retired_source: None,
            retired_ordinal: 0,
            admitted_ordinal: 0,
            #[cfg(test)]
            lookup_steps: std::cell::Cell::new(0),
            #[cfg(test)]
            retire_steps: 0,
        })
    }
    pub fn preview(&mut self, bytes: usize, now: Duration) -> io::Result<bool> {
        match self.controller.preview_admit(bytes as u64, micros(now)?) {
            Ok(()) => Ok(true),
            Err(delivery_window::Error::Blocked) => Ok(false),
            Err(error) => Err(io::Error::other(error)),
        }
    }
    pub fn admit(
        &mut self,
        message: u64,
        bytes: usize,
        parts: usize,
        now: Duration,
    ) -> io::Result<()> {
        if parts == 0 || parts > self.parts {
            return Err(invalid("packet admission fragment geometry"));
        }
        let before = self
            .controller
            .status(micros(now)?)
            .map_err(io::Error::other)?;
        if message != before.admitted.records {
            return Err(invalid("packet admission identity order"));
        }
        let slot = (message % self.entries.len() as u64) as usize;
        if self.entries[slot].is_some() {
            return Err(invalid("packet admission metadata span"));
        }
        let end = self
            .controller
            .admit(bytes as u64, micros(now)?)
            .map_err(io::Error::other)?;
        self.bits[slot * self.words..(slot + 1) * self.words].fill(0);
        self.admitted_ordinal = end.records;
        self.entries[slot] = Some(Native {
            ordinal: end.records,
            admitted: micros(now)?,
            message,
            first_source: None,
            submitted: 0,
            parts,
            sent: 0,
            latest: Micros(0),
        });
        Ok(())
    }
    pub fn submitted(&mut self, message: u64, source: u64) -> io::Result<()> {
        let slot = (message % self.entries.len() as u64) as usize;
        let entry = self.entries[slot]
            .as_mut()
            .filter(|e| e.message == message)
            .ok_or_else(|| invalid("packet source admission"))?;
        if entry.submitted >= entry.parts {
            return Err(invalid("packet submitted too many originals"));
        }
        if let Some(first) = entry.first_source {
            if first.checked_add(entry.submitted as u64) != Some(source) {
                return Err(invalid("packet original source range"));
            }
        } else {
            entry.first_source = Some(source);
        }
        entry.submitted += 1;
        Ok(())
    }
    pub fn witness(&self, source: u64) -> io::Result<Option<Witness>> {
        if self.retired_source.is_some_and(|end| source < end) {
            return Ok(None);
        }
        // Active ordinals occupy a contiguous ring span. Their source ranges
        // are monotonically assigned; only the final entry may be unsubmitted.
        let mut low = self
            .retired_ordinal
            .checked_add(1)
            .ok_or_else(|| invalid("packet source lookup ordinal exhausted"))?;
        let mut high = self.admitted_ordinal;
        while low <= high {
            #[cfg(test)]
            self.lookup_steps.set(self.lookup_steps.get() + 1);
            let ordinal = low + (high - low) / 2;
            let slot = ((ordinal - 1) % self.entries.len() as u64) as usize;
            let entry = self.entries[slot]
                .filter(|e| e.ordinal == ordinal)
                .ok_or_else(|| invalid("packet source lookup lost active span"))?;
            match entry.first_source {
                None => high = ordinal - 1,
                Some(first) if source < first => high = ordinal - 1,
                Some(first) => {
                    let index = source - first;
                    if index < entry.submitted as u64 {
                        return Ok(Some(Witness {
                            ordinal,
                            index: index as usize,
                        }));
                    }
                    low = ordinal
                        .checked_add(1)
                        .ok_or_else(|| invalid("packet source lookup exhausted"))?;
                }
            }
        }
        Err(invalid("packet emitted source lacks original admission"))
    }
    pub fn sent(
        &mut self,
        witness: Witness,
        actual: Duration,
        observed: Duration,
    ) -> io::Result<()> {
        self.controller
            .tick(micros(observed)?)
            .map_err(io::Error::other)?;
        let slot = ((witness
            .ordinal
            .checked_sub(1)
            .ok_or_else(|| invalid("zero packet send ordinal"))?)
            % self.entries.len() as u64) as usize;
        let Some(mut entry) = self.entries[slot].filter(|e| e.ordinal == witness.ordinal) else {
            // A queued duplicate callback may follow a fully retired original.
            let status = self
                .controller
                .status(micros(observed)?)
                .map_err(io::Error::other)?;
            if witness.ordinal <= status.admitted.records - status.retained_records as u64 {
                return Ok(());
            }
            return Err(invalid("packet send ordinal lacks ownership"));
        };
        if witness.index >= entry.submitted || actual > observed || micros(actual)? < entry.admitted
        {
            return Err(invalid("packet actual-send fragment or clock"));
        }
        let bit = slot * self.words + witness.index / 64;
        let mask = 1u64 << (witness.index % 64);
        if self.bits[bit] & mask != 0 {
            return Ok(());
        }
        entry.sent += 1;
        entry.latest = Micros(entry.latest.0.max(micros(actual)?.0));
        if entry.sent == entry.parts {
            self.controller
                .confirm_record_flushed_at(entry.ordinal, entry.latest, micros(observed)?)
                .map_err(io::Error::other)?;
        }
        self.bits[bit] |= mask;
        self.entries[slot] = Some(entry);
        self.retire(observed)
    }
    pub fn feedback(
        &mut self,
        ordinal: u64,
        actual: Duration,
        observed: Duration,
    ) -> io::Result<()> {
        let end = self
            .controller
            .credit_at_record(ordinal)
            .map_err(io::Error::other)?;
        self.controller
            .delivered_at(end, micros(actual)?, micros(observed)?)
            .map_err(io::Error::other)?;
        self.retire(observed)
    }
    fn retire(&mut self, now: Duration) -> io::Result<()> {
        let status = self
            .controller
            .status(micros(now)?)
            .map_err(io::Error::other)?;
        let prefix = status.admitted.records - status.retained_records as u64;
        while self.retired_ordinal < prefix {
            #[cfg(test)]
            {
                self.retire_steps += 1;
            }
            let ordinal = self.retired_ordinal + 1;
            let slot = ((ordinal - 1) % self.entries.len() as u64) as usize;
            let entry = self.entries[slot]
                .filter(|e| e.ordinal == ordinal)
                .ok_or_else(|| invalid("packet retirement lost active span"))?;
            let end = entry
                .first_source
                .and_then(|first| first.checked_add(entry.parts as u64))
                .ok_or_else(|| invalid("retired packet source range"))?;
            self.retired_source = Some(end);
            self.entries[slot] = None;
            self.retired_ordinal = ordinal;
        }
        Ok(())
    }
    pub fn status(&self, now: Duration) -> io::Result<delivery_window::Status> {
        self.controller
            .status(micros(now)?)
            .map_err(io::Error::other)
    }
    pub fn tick(&mut self, now: Duration) -> io::Result<()> {
        self.controller.tick(micros(now)?).map_err(io::Error::other)
    }
}

/// Capacity is reserved before I/O; only a successful physical send publishes.
pub(crate) async fn write(
    mut sender: impl crate::udp::DatagramSend,
    mut packets: mpsc::Receiver<Packet>,
    events: mpsc::Sender<Sent>,
    lane: usize,
    returned: mpsc::Sender<(usize, Vec<u8>)>,
) -> io::Result<()> {
    while let Some(packet) = packets.recv().await {
        let permit = if packet.witness.is_some() {
            Some(
                events
                    .reserve()
                    .await
                    .map_err(|_| invalid("packet send observer closed"))?,
            )
        } else {
            None
        };
        let bytes = packet
            .bytes
            .get(..packet.length)
            .ok_or_else(|| invalid("packet writer length exceeds owned buffer"))?;
        sender.send(bytes).await?;
        let at = Instant::now();
        if let Some(witness) = packet.witness {
            permit
                .ok_or_else(|| invalid("packet send event not reserved"))?
                .send(Sent { lane, witness, at });
        }
        // Returning ownership is not another send or a renewed completion time.
        returned
            .send((lane, packet.bytes))
            .await
            .map_err(|_| invalid("packet buffer owner closed"))?;
    }
    Err(invalid("packet producer closed"))
}

/// One finite observation of three independent queue/flight domains.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LaneStatus {
    /// Original native bytes/records and genuine first-send/delivery observations.
    pub delivery: delivery_window::Status,
    /// Actual retained recovery originals, not native delivery debt.
    pub recovery: l2tunnel_recovery::Retained,
    /// Authenticated recovery byte/record/timeout limits; span stays at most64.
    pub recovery_limits: l2tunnel_recovery::ArqConfig,
    /// Configured local device queue packets, independent of both flight budgets.
    pub local_queue_limit: usize,
    /// Native packets in that local device queue.
    pub local_queued: usize,
    /// Additional native packets in the separately bounded delivery bank.
    pub bank_records: usize,
    /// Actual pending native bytes across local queue and delivery bank.
    pub native_pending_bytes: u64,
    /// Original ingress bytes staged exactly once while admission is blocked.
    pub staged_bytes: usize,
    /// Original-fragment submission met recovery count/byte/span pressure this turn.
    pub recovery_blocked: bool,
    /// Native admission met its independent byte/record/metadata limit this turn.
    pub delivery_blocked: bool,
    /// A real packet-device transmit returned WouldBlock this turn.
    pub device_blocked: bool,
}
/// At most two authenticated physical lanes; no per-packet log or queue.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Snapshot {
    /// Full mode uses the first entry; half uses both fixed directional lanes.
    pub lanes: [Option<LaneStatus>; 2],
}
/// Cloneable read-only latest snapshot handle.
#[derive(Clone)]
pub struct Observer(tokio::sync::watch::Receiver<Snapshot>);
/// Single latest-state publication owner; lag does not accumulate snapshots.
pub struct Reporter(tokio::sync::watch::Sender<Snapshot>);
/// Create bounded optional status publication without spawning a task.
pub fn observations() -> (Observer, Reporter) {
    let (tx, rx) = tokio::sync::watch::channel(Snapshot::default());
    (Observer(rx), Reporter(tx))
}
impl Observer {
    /// Read the last actual snapshot without refreshing timers or controller state.
    pub fn status(&self) -> Snapshot {
        *self.0.borrow()
    }
    /// Subscribe to coalesced latest status.
    pub fn subscribe(&self) -> tokio::sync::watch::Receiver<Snapshot> {
        self.0.clone()
    }
}
impl Reporter {
    pub(crate) fn publish(&self, snapshot: Snapshot) {
        self.0.send_replace(snapshot);
    }
}

#[cfg(test)]
#[path = "packet_delivery_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "packet_delivery_actor_tests.rs"]
mod actor_tests;
#[cfg(test)]
pub(crate) use actor_tests::actual_native_flight;
