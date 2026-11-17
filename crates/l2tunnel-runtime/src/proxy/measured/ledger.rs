//! Local bookkeeping only. C owns expiry and the caller owns actual I/O evidence.
use super::invalid;
use crate::proxy::transport::{PHYSICAL_SLOTS, PhysicalWrite};
use l2tunnel_tcp_proxy::measurement::{self, Micros, OutputId, Pending};
use std::{io, mem::size_of, sync::Arc};
use tokio::time::Instant;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::proxy) struct Id(u64);
pub(in crate::proxy) struct Admission {
    owner: Arc<()>,
    revision: u64,
    slot: usize,
    id: Id,
    entry: Entry,
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn all_user_ordinals_are_bounded_monotonic_and_failure_atomic() -> io::Result<()> {
        let mut ledger = Ledger::new(3)?;
        let stale = ledger
            .prepare_send(None, Micros(1))?
            .ok_or_else(|| invalid("slot"))?;
        let first = ledger
            .prepare_send(None, Micros(1))?
            .ok_or_else(|| invalid("slot"))?;
        assert_eq!(ledger.sent(first)?, 1);
        assert!(ledger.sent(stale).is_err());
        let second = ledger
            .prepare_send(None, Micros(2))?
            .ok_or_else(|| invalid("slot"))?;
        assert_eq!(ledger.sent(second)?, 2);
        assert!(ledger.prepare_send(None, Micros(3))?.is_none());
        assert!(ledger.observe_flushed(3).is_err());
        assert_eq!(ledger.writer_age(Micros(9))?, 8);
        ledger.observe_flushed(1)?;
        assert!(ledger.observe_flushed(0).is_err());
        assert_eq!(ledger.writer_age(Micros(9))?, 7);
        ledger.observe_flushed(2)?;
        assert_eq!(ledger.writer_age(Micros(9))?, 0);
        ledger.sent = u64::MAX;
        assert!(ledger.prepare_send(None, Micros(10)).is_err());
        assert_eq!(ledger.flushed, 2);
        assert_eq!(ledger.flights.len(), 2);
        ledger.sent = 2;
        ledger.revision = u64::MAX;
        assert!(ledger.prepare_send(None, Micros(10)).is_err());
        assert_eq!(ledger.sent, 2);
        Ok(())
    }
}
impl Admission {
    pub fn id(&self) -> Id {
        self.id
    }
    pub fn token(&self) -> OutputId {
        self.entry.token.clone()
    }
}
pub(in crate::proxy) struct Send {
    owner: Arc<()>,
    revision: u64,
    id: Option<Id>,
    ordinal: u64,
    at: Micros,
}
struct Entry {
    token: OutputId,
    id: Id,
    flow: u64,
    channel: u16,
    len: usize,
    bytes: [u8; measurement::wire::MAX_RECORD_BYTES],
    admitted: Micros,
    ordinal: Option<u64>,
    physical: Option<PhysicalWrite>,
}
#[derive(Clone, Copy)]
struct Flight {
    ordinal: u64,
    at: Micros,
}
pub(in crate::proxy) struct Ledger {
    identity: Arc<()>,
    revision: u64,
    next: u64,
    sent: u64,
    flushed: u64,
    physical_selected: bool,
    physical_observed: u64,
    physical_generation: u64,
    entries: Box<[Option<Entry>]>,
    flights: [Option<Flight>; 2],
}
pub(in crate::proxy) struct Completion {
    pub id: Id,
    pub token: OutputId,
    pub flow: u64,
    pub channel: u16,
    pub admitted: Micros,
    pub ordinal: u64,
    pub physical: Option<PhysicalWrite>,
}
impl Ledger {
    pub fn bytes(slots: usize) -> io::Result<usize> {
        slots
            .checked_mul(size_of::<Option<Entry>>())
            .and_then(|n| n.checked_add(size_of::<Self>()))
            .ok_or_else(|| invalid("measured ledger storage overflow"))
    }
    pub fn new(slots: usize) -> io::Result<Self> {
        if !(3..=129).contains(&slots) || slots % 2 != 1 {
            return Err(invalid("measured ledger lifetime geometry"));
        }
        Ok(Self {
            identity: Arc::new(()),
            revision: 0,
            next: 1,
            sent: 0,
            flushed: 0,
            physical_selected: false,
            physical_observed: 0,
            physical_generation: 0,
            entries: (0..slots).map(|_| None).collect(),
            flights: [None; 2],
        })
    }
    pub fn prepare_admission(
        &self,
        pending: &Pending<'_>,
        channel: u16,
        now: Micros,
    ) -> io::Result<Option<Admission>> {
        let Some(slot) = self.entries.iter().position(Option::is_none) else {
            return Ok(None);
        };
        self.revision
            .checked_add(1)
            .ok_or_else(|| invalid("measured ledger revision exhausted"))?;
        self.next
            .checked_add(1)
            .ok_or_else(|| invalid("measured ledger ID exhausted"))?;
        let decoded = measurement::wire::decode(pending.bytes).map_err(io::Error::other)?;
        if decoded.header.scope.flow != pending.flow || channel >= 256 {
            return Err(invalid("measured admitted metadata"));
        }
        let mut bytes = [0; measurement::wire::MAX_RECORD_BYTES];
        bytes[..pending.bytes.len()].copy_from_slice(pending.bytes);
        let id = Id(self.next);
        Ok(Some(Admission {
            owner: self.identity.clone(),
            revision: self.revision,
            slot,
            id,
            entry: Entry {
                token: pending.id.clone(),
                id,
                flow: pending.flow,
                channel,
                len: pending.bytes.len(),
                bytes,
                admitted: now,
                ordinal: None,
                physical: None,
            },
        }))
    }
    // Caller has just copied into the common MUX and confirmed B admission.
    pub fn admit(&mut self, ready: Admission) -> io::Result<()> {
        if !Arc::ptr_eq(&ready.owner, &self.identity)
            || ready.revision != self.revision
            || ready.id != Id(self.next)
            || self.entries[ready.slot].is_some()
        {
            return Err(invalid("stale measured admission transaction"));
        }
        let revision = self
            .revision
            .checked_add(1)
            .ok_or_else(|| invalid("measured ledger revision exhausted"))?;
        let next = self
            .next
            .checked_add(1)
            .ok_or_else(|| invalid("measured ledger ID exhausted"))?;
        self.entries[ready.slot] = Some(ready.entry);
        self.revision = revision;
        self.next = next;
        Ok(())
    }
    pub fn check_selected(&self, id: Id, flow: u64, channel: u16, bytes: &[u8]) -> io::Result<()> {
        let value = self.entry(id)?;
        if value.ordinal.is_some()
            || value.flow != flow
            || value.channel != channel
            || &value.bytes[..value.len] != bytes
        {
            return Err(invalid("measured immutable selection changed"));
        }
        Ok(())
    }
    pub fn prepare_send(&self, id: Option<Id>, now: Micros) -> io::Result<Option<Send>> {
        if self.flights.iter().all(Option::is_some) {
            return Ok(None);
        }
        if let Some(id) = id {
            let entry = self.entry(id)?;
            if entry.ordinal.is_some() || now < entry.admitted {
                return Err(invalid("measured writer ownership/time"));
            }
        }
        self.revision
            .checked_add(1)
            .ok_or_else(|| invalid("measured ledger revision exhausted"))?;
        let ordinal = self
            .sent
            .checked_add(1)
            .ok_or_else(|| invalid("measured user ordinal exhausted"))?;
        Ok(Some(Send {
            owner: self.identity.clone(),
            revision: self.revision,
            id,
            ordinal,
            at: now,
        }))
    }
    // Caller has just transferred exact bytes into an actual reserved writer slot.
    pub fn sent(&mut self, ready: Send) -> io::Result<u64> {
        if !Arc::ptr_eq(&ready.owner, &self.identity)
            || ready.revision != self.revision
            || self.sent.checked_add(1) != Some(ready.ordinal)
        {
            return Err(invalid("stale measured writer transaction"));
        }
        let slot = self
            .flights
            .iter()
            .position(Option::is_none)
            .ok_or_else(|| invalid("measured writer reservation missing"))?;
        let revision = self
            .revision
            .checked_add(1)
            .ok_or_else(|| invalid("measured ledger revision exhausted"))?;
        if let Some(id) = ready.id {
            self.entry_mut(id)?.ordinal = Some(ready.ordinal);
        }
        self.flights[slot] = Some(Flight {
            ordinal: ready.ordinal,
            at: ready.at,
        });
        self.sent = ready.ordinal;
        self.revision = revision;
        Ok(self.sent)
    }
    pub fn enable_physical_receipts(&mut self) -> io::Result<()> {
        if self.sent != 0 || self.flushed != 0 {
            return Err(invalid("late measured physical selection"));
        }
        self.physical_selected = true;
        Ok(())
    }
    /// Import exact local facts before expiry processing, without releasing any
    /// Flight/token or advancing semantic flush. Includes every Data ordinal.
    pub fn observe_physical(
        &mut self,
        count: u64,
        receipts: [Option<PhysicalWrite>; PHYSICAL_SLOTS],
        origin: Instant,
        observed: Instant,
    ) -> io::Result<()> {
        if !self.physical_selected
            || count < self.physical_observed
            || count > self.sent
            || count
                .checked_sub(self.physical_observed)
                .is_none_or(|n| n > PHYSICAL_SLOTS as u64)
        {
            return Err(invalid("measured physical ordinal outside handed range"));
        }
        if count == self.physical_observed {
            return Ok(());
        }
        let first = self
            .physical_observed
            .checked_add(1)
            .ok_or_else(|| invalid("physical ordinal exhausted"))?;
        let mut generation = self.physical_generation;
        // Complete preflight before retaining even the first fact.
        for ordinal in first..=count {
            let index = ((ordinal - 1) % PHYSICAL_SLOTS as u64) as usize;
            let receipt =
                receipts[index].ok_or_else(|| invalid("missing coalesced physical receipt"))?;
            let flight = self
                .flights
                .iter()
                .flatten()
                .find(|f| f.ordinal == ordinal)
                .ok_or_else(|| invalid("physical receipt lacks actual all-user handoff"))?;
            let handed = origin
                .checked_add(std::time::Duration::from_micros(flight.at.0))
                .ok_or_else(|| invalid("physical handoff time overflow"))?;
            if receipt.ordinal != Some(ordinal)
                || receipt.generation <= generation
                || receipt.accepted_at < handed
                || receipt.observed_at < receipt.accepted_at
                || observed < receipt.observed_at
            {
                return Err(invalid("measured physical token/time provenance"));
            }
            for entry in self
                .entries
                .iter()
                .flatten()
                .filter(|entry| entry.ordinal == Some(ordinal))
            {
                if entry.physical.is_some_and(|old| old != receipt) {
                    return Err(invalid("measured immutable physical receipt changed"));
                }
            }
            generation = receipt.generation;
        }
        for ordinal in first..=count {
            let receipt = receipts[((ordinal - 1) % PHYSICAL_SLOTS as u64) as usize]
                .ok_or_else(|| invalid("physical preflight changed"))?;
            for entry in self
                .entries
                .iter_mut()
                .flatten()
                .filter(|entry| entry.ordinal == Some(ordinal))
            {
                entry.physical = Some(receipt);
            }
        }
        self.physical_generation = generation;
        self.physical_observed = count;
        Ok(())
    }
    pub fn observe_flushed(&mut self, count: u64) -> io::Result<()> {
        if count < self.flushed
            || count > self.sent
            || (self.physical_selected && count > self.physical_observed)
        {
            return Err(invalid("measured flushed ordinal outside handed range"));
        }
        if count == self.flushed {
            return Ok(());
        }
        let revision = self
            .revision
            .checked_add(1)
            .ok_or_else(|| invalid("measured ledger revision exhausted"))?;
        for flight in &mut self.flights {
            if flight.is_some_and(|f| f.ordinal <= count) {
                *flight = None;
            }
        }
        self.flushed = count;
        self.revision = revision;
        Ok(())
    }
    pub fn next_completed(&self) -> Option<Completion> {
        let e = self
            .entries
            .iter()
            .flatten()
            .filter(|e| e.ordinal.is_some_and(|n| n <= self.flushed))
            .min_by_key(|e| e.ordinal)?;
        Some(Completion {
            id: e.id,
            token: e.token.clone(),
            flow: e.flow,
            channel: e.channel,
            admitted: e.admitted,
            ordinal: e.ordinal?,
            physical: e.physical,
        })
    }
    // Call only after the actual C confirm_written returned success.
    pub fn confirmed(&mut self, id: Id) -> io::Result<()> {
        let index = self
            .entries
            .iter()
            .position(|e| e.as_ref().is_some_and(|e| e.id == id))
            .ok_or_else(|| invalid("unknown measured callback"))?;
        if self.entries[index]
            .as_ref()
            .is_none_or(|e| e.ordinal.is_none_or(|n| n > self.flushed))
        {
            return Err(invalid("measured callback before full flush"));
        }
        let revision = self
            .revision
            .checked_add(1)
            .ok_or_else(|| invalid("measured ledger revision exhausted"))?;
        self.entries[index] = None;
        self.revision = revision;
        Ok(())
    }
    pub fn counts(&self) -> (usize, usize) {
        self.entries.iter().flatten().fold((0, 0), |(q, w), e| {
            if e.ordinal.is_none() {
                (q + 1, w)
            } else {
                (q, w + 1)
            }
        })
    }
    pub fn writer_age(&self, now: Micros) -> io::Result<u64> {
        self.flights
            .iter()
            .flatten()
            .map(|f| {
                now.0
                    .checked_sub(f.at.0)
                    .ok_or_else(|| invalid("measured writer clock regressed"))
            })
            .try_fold(0, |a, b| Ok(a.max(b?)))
    }
    #[cfg(debug_assertions)]
    pub(in crate::proxy) fn trace_failure(&self, now: Micros) {
        eprintln!(
            "MEASURED_LEDGER_FAILURE now={} sent={} flushed={} physical_observed={} physical_generation={} counts={:?}",
            now.0,
            self.sent,
            self.flushed,
            self.physical_observed,
            self.physical_generation,
            self.counts(),
        );
        for flight in self.flights.iter().flatten() {
            eprintln!(
                "MEASURED_FLIGHT ordinal={} handed={} age={:?}",
                flight.ordinal,
                flight.at.0,
                now.0.checked_sub(flight.at.0),
            );
        }
        for entry in self.entries.iter().flatten().take(8) {
            eprintln!(
                "MEASURED_ENTRY flow={} channel={} admitted={} age={:?} ordinal={:?} physical={:?}",
                entry.flow,
                entry.channel,
                entry.admitted.0,
                now.0.checked_sub(entry.admitted.0),
                entry.ordinal,
                entry.physical,
            );
        }
    }
    #[cfg(test)]
    pub(in crate::proxy) fn retained_physical(&self, id: Id) -> io::Result<Option<PhysicalWrite>> {
        Ok(self.entry(id)?.physical)
    }
    fn entry(&self, id: Id) -> io::Result<&Entry> {
        self.entries
            .iter()
            .flatten()
            .find(|e| e.id == id)
            .ok_or_else(|| invalid("unknown measured handoff"))
    }
    fn entry_mut(&mut self, id: Id) -> io::Result<&mut Entry> {
        self.entries
            .iter_mut()
            .flatten()
            .find(|e| e.id == id)
            .ok_or_else(|| invalid("unknown measured handoff"))
    }
}
