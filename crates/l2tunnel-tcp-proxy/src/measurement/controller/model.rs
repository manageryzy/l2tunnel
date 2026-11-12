use super::{AckRate, ControllerError as Error, ObservationConfig, ServiceLatency, owner};
use crate::{Window, adaptive::Micros, session};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct Report {
    pub value: super::wire::Demand,
    pub at: Micros,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct Flow {
    pub baseline: Option<Window>,
    pub report: Option<Report>,
    pub weight: Option<u16>,
    empty_since: Option<Micros>,
    demanding: bool,
}
impl Default for Flow {
    fn default() -> Self {
        Self {
            baseline: None,
            report: None,
            weight: None,
            empty_since: None,
            demanding: true,
        }
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct Bin {
    pub at: Micros,
    pub elapsed: u64,
    pub bytes: u128,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct Model {
    pub flows: Box<[Flow]>,
    bins: Box<[Option<Bin>]>,
    cursor: usize,
    start: Micros,
    pub(super) accumulated: u128,
    pub latest_bin: Option<Micros>,
    completed: Option<ServiceLatency>,
}
pub(super) struct View {
    pub active: usize,
    pub unknown: usize,
    pub exhausted: bool,
    pub in_flight: Window,
    pub demanding: [u64; 64],
    pub demand_count: usize,
    pub rate: Option<AckRate>,
}
impl Model {
    pub fn new(n: usize, bins: usize, now: Micros) -> Self {
        Self {
            flows: vec![Flow::default(); n].into_boxed_slice(),
            bins: vec![None; bins].into_boxed_slice(),
            cursor: 0,
            start: now,
            accumulated: 0,
            latest_bin: None,
            completed: None,
        }
    }
    pub fn copy_from(&mut self, other: &Self) {
        self.flows.copy_from_slice(&other.flows);
        self.bins.copy_from_slice(&other.bins);
        self.cursor = other.cursor;
        self.start = other.start;
        self.accumulated = other.accumulated;
        self.latest_bin = other.latest_bin;
        self.completed = other.completed;
    }
    pub fn observe(
        &mut self,
        table: &session::Table,
        config: ObservationConfig,
        now: Micros,
    ) -> Result<(), Error> {
        let elapsed = now.0.checked_sub(self.start.0).ok_or(Error::Time)?;
        let mut delta = 0u128;
        if table.status().flows > self.flows.len() {
            return Err(Error::Accounting);
        }
        for (index, row) in self.flows.iter_mut().take(table.status().flows).enumerate() {
            let current = credit(table, index as u64 + 1)?;
            if let Some(current) = current {
                if let Some(previous) = row.baseline {
                    if !current.acknowledged.contains(previous) {
                        return Err(Error::Accounting);
                    }
                    delta = delta
                        .checked_add(u128::from(current.acknowledged.bytes - previous.bytes))
                        .ok_or(Error::Accounting)?;
                }
                row.baseline = Some(current.acknowledged);
            } else if row.baseline.is_some() {
                return Err(Error::Accounting);
            }
        }
        if elapsed > 2 * config.rate_interval_micros {
            self.bins.fill(None);
            self.cursor = 0;
            self.accumulated = 0;
            self.start = now;
        } else {
            self.accumulated = self
                .accumulated
                .checked_add(delta)
                .ok_or(Error::Accounting)?;
            if elapsed >= config.rate_interval_micros {
                self.bins[self.cursor] = Some(Bin {
                    at: now,
                    elapsed,
                    bytes: self.accumulated,
                });
                self.cursor = (self.cursor + 1) % self.bins.len();
                self.latest_bin = Some(now);
                self.start = now;
                self.accumulated = 0;
            }
        }
        self.rate(config, now)?;
        Ok(())
    }
    pub fn refresh(
        &mut self,
        table: &session::Table,
        config: ObservationConfig,
        now: Micros,
    ) -> Result<(), Error> {
        if table.status().flows > self.flows.len() {
            return Err(Error::Accounting);
        }
        for (index, row) in self.flows.iter_mut().take(table.status().flows).enumerate() {
            let id = index as u64 + 1;
            if table.flow_status(id).ok_or(Error::Accounting)?.phase != session::FlowPhase::Active {
                continue;
            }
            let current = credit(table, id)?.ok_or(Error::Accounting)?;
            let Some(report) = row
                .report
                .filter(|report| fresh(report.at, now, config.sample_ttl_micros))
            else {
                continue;
            };
            if positive(report, current) {
                row.demanding = true;
                row.empty_since = None;
            } else {
                let since = row.empty_since.get_or_insert(now);
                row.demanding = now.0 - since.0 < config.demand_idle_micros;
            }
        }
        Ok(())
    }
    pub fn view(
        &self,
        table: &session::Table,
        config: ObservationConfig,
        now: Micros,
    ) -> Result<View, Error> {
        let mut value = View {
            active: 0,
            unknown: 0,
            exhausted: false,
            in_flight: Window::default(),
            demanding: [0; 64],
            demand_count: 0,
            rate: self.rate(config, now)?,
        };
        if table.status().flows > self.flows.len() {
            return Err(Error::Accounting);
        }
        for (index, row) in self.flows.iter().take(table.status().flows).enumerate() {
            let id = index as u64 + 1;
            if table.flow_status(id).ok_or(Error::Accounting)?.phase != session::FlowPhase::Active {
                continue;
            }
            let current = credit(table, id)?.ok_or(Error::Accounting)?;
            value.active += 1;
            value.in_flight.bytes = value
                .in_flight
                .bytes
                .checked_add(current.received.bytes - current.acknowledged.bytes)
                .ok_or(Error::Accounting)?;
            value.in_flight.records = value
                .in_flight
                .records
                .checked_add(current.received.records - current.acknowledged.records)
                .ok_or(Error::Accounting)?;
            if row.demanding {
                value.demanding[value.demand_count] = id;
                value.demand_count += 1;
            }
            if let Some(report) = row
                .report
                .filter(|r| fresh(r.at, now, config.sample_ttl_micros))
            {
                let d = report.value;
                value.exhausted |= d.native_unread_bytes > 0
                    && ((d.byte_blocked && d.observed_grant.bytes == current.granted.bytes)
                        || (d.record_blocked
                            && d.observed_grant.records == current.granted.records));
            } else {
                value.unknown += 1;
            }
        }
        Ok(value)
    }
    fn rate(&self, config: ObservationConfig, now: Micros) -> Result<Option<AckRate>, Error> {
        let mut bytes = 0u128;
        let mut elapsed = 0u64;
        let mut count = 0u8;
        let mut latest = None;
        for bin in self
            .bins
            .iter()
            .flatten()
            .filter(|bin| fresh(bin.at, now, config.sample_ttl_micros))
        {
            bytes = bytes.checked_add(bin.bytes).ok_or(Error::Accounting)?;
            elapsed = elapsed.checked_add(bin.elapsed).ok_or(Error::Accounting)?;
            count += 1;
            latest = Some(latest.map_or(bin.at, |prior: Micros| prior.max(bin.at)));
        }
        let Some(latest_at) = latest else {
            return Ok(None);
        };
        let rate = bytes
            .checked_mul(1_000_000)
            .and_then(|n| n.checked_div(u128::from(elapsed)))
            .and_then(|n| u64::try_from(n).ok())
            .ok_or(Error::Accounting)?;
        Ok(Some(AckRate {
            bytes,
            elapsed_micros: elapsed,
            bytes_per_second: rate,
            bins: count,
            latest_at,
        }))
    }
    pub fn complete(&mut self, event: owner::Completion, config: ObservationConfig, now: Micros) {
        if !fresh(event.reply_at, now, config.sample_ttl_micros)
            || event.reply_at <= event.admitted_at
        {
            return;
        }
        let sample = event.reply_at.0 - event.admitted_at.0;
        let old = self
            .completed
            .filter(|old| fresh(old.reply_at, now, config.sample_ttl_micros));
        let smoothed = old.map_or(sample, |old| {
            ((7 * u128::from(old.smoothed_micros) + u128::from(sample)) / 8) as u64
        });
        self.completed = Some(ServiceLatency {
            smoothed_micros: smoothed,
            flow: event.flow,
            generation: event.generation,
            admitted_at: event.admitted_at,
            reply_at: event.reply_at,
            fresh: true,
        });
    }
    pub fn service(&self, now: Micros, config: ObservationConfig) -> Option<ServiceLatency> {
        self.completed.map(|mut value| {
            value.fresh = fresh(value.reply_at, now, config.sample_ttl_micros);
            value
        })
    }
    pub fn next_deadline(&self, config: ObservationConfig, now: Micros) -> Option<Micros> {
        let add =
            |at: Micros, delta: u64| at.0.checked_add(delta).map(Micros).filter(|end| *end > now);
        let bins = self
            .bins
            .iter()
            .flatten()
            .filter_map(|bin| add(bin.at, config.sample_ttl_micros));
        let flows = self
            .flows
            .iter()
            .flat_map(|row| {
                [
                    row.report.and_then(|r| add(r.at, config.sample_ttl_micros)),
                    row.empty_since
                        .and_then(|at| add(at, config.demand_idle_micros)),
                ]
            })
            .flatten();
        bins.chain(flows)
            .chain(add(self.start, config.rate_interval_micros))
            .chain(
                self.completed
                    .and_then(|s| add(s.reply_at, config.sample_ttl_micros)),
            )
            .min()
    }
}
fn positive(report: Report, current: session::CreditSnapshot) -> bool {
    let d = report.value;
    d.native_unread_bytes > 0
        || d.pending_data_bytes > 0
        || !current.acknowledged.contains(d.produced)
}
fn fresh(at: Micros, now: Micros, ttl: u64) -> bool {
    now >= at && now.0 - at.0 < ttl
}
fn credit(table: &session::Table, id: u64) -> Result<Option<session::CreditSnapshot>, Error> {
    let value = table.credit_status(id);
    if let Some(c) = value
        && (!c.received.contains(c.acknowledged)
            || !c.granted.contains(c.received)
            || !table.policy().maximum.contains(c.target))
    {
        return Err(Error::Accounting);
    }
    Ok(value)
}
