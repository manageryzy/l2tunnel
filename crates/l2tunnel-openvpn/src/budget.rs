use crate::runtime::{Shared, increment};
use crate::{Error, WireBudget};
use std::{
    sync::{Arc, Mutex},
    time::Duration,
};

/// Aggregate admission counters for both lanes; socket acceptance is separate.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct WireStatus {
    /// Gate, TLS, data and feedback datagrams admitted, including retries.
    pub admitted_datagrams: u64,
    /// Exact configured IP bytes admitted across both lanes.
    pub admitted_ip_bytes: u64,
}
#[derive(Clone, Copy, Default)]
struct Counts {
    packets: u64,
    bytes: u64,
    gate_sent: u64,
}
struct Ledger {
    config: WireBudget,
    until: Duration,
    last: Duration,
    packets: usize,
    bytes: usize,
    reserved_packets: usize,
    reserved_bytes: usize,
    controls: usize,
    counts: [Counts; 2],
}
#[derive(Clone)]
pub(crate) struct Budget {
    ledger: Arc<Mutex<Ledger>>,
    lane: usize,
    started: tokio::time::Instant,
}
pub(crate) struct Allowance<'a> {
    ledger: &'a mut Ledger,
    lane: usize,
}
impl Budget {
    pub fn new(config: WireBudget, started: tokio::time::Instant) -> Self {
        Self {
            ledger: Arc::new(Mutex::new(Ledger {
                config,
                until: Duration::ZERO,
                last: Duration::ZERO,
                packets: 0,
                bytes: 0,
                reserved_packets: 0,
                reserved_bytes: 0,
                controls: 0,
                counts: [Counts::default(); 2],
            })),
            lane: 0,
            started,
        }
    }
    pub fn second(&self) -> Self {
        Self {
            ledger: self.ledger.clone(),
            lane: 1,
            started: self.started,
        }
    }
    // A synchronous transaction owns reserve -> recovery poll -> charge. It cannot
    // await socket IO or leak a lock into another actor's future.
    pub fn transaction<T>(
        &self,
        operation: impl FnOnce(&mut Allowance<'_>) -> Result<T, Error>,
    ) -> Result<T, Error> {
        let mut ledger = self.ledger.lock().map_err(|_| Error::Closed)?;
        let now = self.started.elapsed();
        if now < ledger.last {
            return Err(Error::Configuration("wire clock regressed"));
        }
        ledger.last = now;
        if now >= ledger.until {
            ledger.until = now
                .checked_add(ledger.config.interval)
                .ok_or(Error::Configuration("budget deadline"))?;
            ledger.packets = ledger.config.packets;
            ledger.bytes = ledger.config.ip_bytes;
            ledger.reserved_packets = ledger.config.reserved_control_packets;
            ledger.reserved_bytes = ledger.config.reserved_control_bytes;
            ledger.controls = 0;
        }
        operation(&mut Allowance {
            ledger: &mut ledger,
            lane: self.lane,
        })
    }
    pub fn report(&self, shared: &Shared) -> Result<(), Error> {
        let ledger = self.ledger.lock().map_err(|_| Error::Closed)?;
        let counts = ledger.counts[self.lane];
        shared.modify(|s| {
            s.status.admitted_datagrams = counts.packets;
            s.status.admitted_ip_bytes = counts.bytes;
            s.status.transmitted_datagrams = counts.gate_sent;
            Ok(())
        })
    }
    pub fn gate_sent(&self) -> Result<(), Error> {
        let mut ledger = self.ledger.lock().map_err(|_| Error::Closed)?;
        increment(&mut ledger.counts[self.lane].gate_sent)
    }
    pub fn status(&self) -> Result<WireStatus, Error> {
        let ledger = self.ledger.lock().map_err(|_| Error::Closed)?;
        let mut status = WireStatus::default();
        for counts in ledger.counts {
            status.admitted_datagrams = status
                .admitted_datagrams
                .checked_add(counts.packets)
                .ok_or(Error::Configuration("pair count"))?;
            status.admitted_ip_bytes = status
                .admitted_ip_bytes
                .checked_add(counts.bytes)
                .ok_or(Error::Configuration("pair bytes"))?;
        }
        Ok(status)
    }
}
impl Allowance<'_> {
    pub fn permits(&self, control: bool, maximum: usize) -> bool {
        let l = &self.ledger;
        if control {
            l.packets != 0 && l.bytes >= maximum && l.controls < l.config.maximum_control_packets
        } else {
            l.packets > l.reserved_packets
                && l.bytes
                    .checked_sub(l.reserved_bytes)
                    .is_some_and(|bytes| bytes >= maximum)
        }
    }
    pub fn charge(
        &mut self,
        control: bool,
        cost: usize,
        shared: Option<&Shared>,
    ) -> Result<(), Error> {
        if !self.permits(control, cost) {
            return Err(Error::Configuration("unreserved wire emission"));
        }
        let l = &mut self.ledger;
        let next_packets = l.counts[self.lane]
            .packets
            .checked_add(1)
            .ok_or(Error::Configuration("wire count"))?;
        let next_bytes = l.counts[self.lane]
            .bytes
            .checked_add(cost as u64)
            .ok_or(Error::Configuration("wire bytes"))?;
        l.packets -= 1;
        l.bytes -= cost;
        if control {
            l.controls += 1;
            l.reserved_packets = l.reserved_packets.saturating_sub(1);
            l.reserved_bytes = l.reserved_bytes.saturating_sub(cost);
        }
        l.counts[self.lane].packets = next_packets;
        l.counts[self.lane].bytes = next_bytes;
        if let Some(shared) = shared {
            shared.modify(|s| {
                s.status.admitted_datagrams = next_packets;
                s.status.admitted_ip_bytes = next_bytes;
                Ok(())
            })?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn both_lanes_share_gate_data_and_mandatory_control_allowance() -> Result<(), Error> {
        let budget = Budget::new(
            WireBudget {
                interval: Duration::from_secs(1),
                packets: 4,
                ip_bytes: 4800,
                reserved_control_packets: 2,
                reserved_control_bytes: 2400,
                maximum_control_packets: 3,
            },
            tokio::time::Instant::now(),
        );
        let reverse = budget.second();
        budget.transaction(|q| {
            assert!(q.permits(true, 1200));
            q.charge(true, 172, None)
        })?;
        reverse.transaction(|q| {
            assert!(q.permits(false, 1200));
            q.charge(false, 1000, None)
        })?;
        budget.transaction(|q| {
            assert!(q.permits(false, 1200));
            q.charge(false, 1000, None)
        })?;
        reverse.transaction(|q| {
            assert!(!q.permits(false, 1));
            assert!(q.permits(true, 1200));
            q.charge(true, 100, None)
        })?;
        for lane in [&budget, &reverse] {
            lane.transaction(|q| {
                assert!(!q.permits(true, 1));
                assert!(!q.permits(false, 1));
                Ok(())
            })?;
        }
        assert_eq!(
            budget.status()?,
            WireStatus {
                admitted_datagrams: 4,
                admitted_ip_bytes: 2272
            }
        );
        assert_eq!(budget.status()?, reverse.status()?);
        Ok(())
    }
}
