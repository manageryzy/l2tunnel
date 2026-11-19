//! Negotiated forward equations over eight consecutive physically sent originals.
use super::*;

/// Compact discriminator, accepted only by the negotiated forward profile.
pub const TAG: u8 = 6;
/// Independent one-based group identity. Group one covers source IDs zero through seven.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Id(pub u32);
impl Id {
    /// Exclusive source endpoint, checked before indexing the retained window.
    pub fn end(self) -> Result<u32, Error> {
        self.0
            .checked_mul(8)
            .filter(|end| *end != 0)
            .ok_or(Error::Identity)
    }
    pub(super) fn support(self) -> Result<Support, Error> {
        let end = self.end()?;
        Ok(Support {
            start: end - 8,
            end,
            seed: 0xb1800000 ^ self.0.wrapping_mul(2654435761),
            tail: false,
        })
    }
}
/// One complete equation including the coded two-byte original length.
#[derive(Clone, Copy, Debug)]
pub struct Row<'a> {
    /// Caller-authenticated parent scope.
    pub scope: Scope,
    /// Non-overlapping group, independent of regular repair serials.
    pub id: Id,
    /// Coded bytes through the longest original's true extent.
    pub bytes: &'a [u8],
}
fn length(id: Id, extent: usize) -> Result<usize, Error> {
    if !(3..=MAX_PAYLOAD + 2).contains(&extent) {
        return Err(Error::Length);
    }
    Ok(1 + wire::compact::len(u64::from(id.end()?)) + extent)
}
/// Exact compact body length before external carrier protection.
pub fn wire_len(row: Row<'_>) -> Result<usize, Error> {
    length(row.id, row.bytes.len())
}
/// Emit a canonical compact row into the caller's reserved buffer.
pub fn encode(row: Row<'_>, output: &mut [u8]) -> Result<usize, Error> {
    let size = wire_len(row)?;
    if output.len() < size {
        return Err(Error::OutputTooSmall);
    }
    output[0] = TAG;
    let mut at = 1;
    wire::compact::write(u64::from(row.id.end()?), output, &mut at);
    output[at..size].copy_from_slice(row.bytes);
    Ok(size)
}
/// Parse a canonical near row under a separately authenticated negotiated profile.
pub fn inspect(config: Config, scope: Scope, bytes: &[u8]) -> Result<Row<'_>, Error> {
    let width = config.width()?;
    if scope.direction != 0 {
        return Err(Error::Scope);
    }
    if bytes.first() != Some(&TAG) {
        return Err(Error::Format);
    }
    let mut at = 1;
    let end = u32::try_from(wire::compact::read(bytes, &mut at)?).map_err(|_| Error::Identity)?;
    if end == 0 || end % 8 != 0 {
        return Err(Error::Identity);
    }
    let data = &bytes[at..];
    if !(3..=width).contains(&data.len()) {
        return Err(Error::Length);
    }
    Ok(Row {
        scope,
        id: Id(end / 8),
        bytes: data,
    })
}

/// Local capacity decisions at bucket boundaries and at first-copy group completion.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct GateCounts {
    /// Intervals that could not be evaluated, including skipped intervals.
    pub partial_buckets: u64,
    /// Complete observed intervals with no physically accepted bytes.
    pub empty_buckets: u64,
    /// Complete nonempty intervals at or below 75 percent of the pacing budget.
    pub light_buckets: u64,
    /// Complete intervals above 75 and below 90 percent of the pacing budget.
    pub middle_buckets: u64,
    /// Complete intervals at or above 90 percent of the pacing budget.
    pub busy_buckets: u64,
    /// Complete intervals over the aggregate ordinary backlog threshold, across utilization bands.
    pub backlogged_buckets: u64,
    /// Boundary decisions that left the gate open for the following interval.
    pub open_buckets: u64,
    /// Gated groups lacking a capacity sample for the current interval.
    pub stale_groups: u64,
    /// Gated groups observed while the sustained gate was closed.
    pub closed_groups: u64,
    /// Gated groups above the instantaneous aggregate threshold, including when closed.
    pub backlogged_groups: u64,
}

/// Local capacity gate and actual extra transmission accounting.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Status {
    /// True only after four consecutive nonempty low-utilization intervals.
    pub spare: bool,
    /// Observed reasons for capacity decisions.
    pub gate: GateCounts,
    /// Eligible disjoint complete groups observed at their final first-copy receipt.
    pub opportunities: u64,
    /// Group opportunities skipped by the sustained local capacity gate.
    pub gated: u64,
    /// Group opportunities with insufficient original-byte credit.
    pub unfunded: u64,
    /// Group opportunities exceeding the configured path budget.
    pub oversized: u64,
    /// Unexposed attempts abandoned on newer traffic, custody loss, expiry or pressure.
    pub abandoned: u64,
    /// Confirmed physical row count in this sending direction.
    pub sent_rows: u64,
    /// Exact external IP bytes charged on successful row receipts.
    pub sent_ip_bytes: u64,
    /// Residual original-byte budget expressed in eighths of one IP byte.
    pub credit_eighths: u64,
}
#[derive(Clone, Copy)]
struct Gate {
    rate: u64,
    interval: u64,
    total: Option<u64>,
    bytes: u64,
    ordinary: usize,
    streak: u8,
    full_period: bool,
}
impl Gate {
    fn observe(
        &mut self,
        now: Tick,
        total: u64,
        ordinary: usize,
        mtu: usize,
        status: &mut Status,
    ) -> Result<(), Error> {
        let interval = now.0 / 100_000;
        let Some(previous) = self.total else {
            self.total = Some(total);
            self.full_period = now.0.is_multiple_of(100_000);
            self.interval = interval;
            self.ordinary = ordinary;
            return Ok(());
        };
        let delta = total.checked_sub(previous).ok_or(Error::Identity)?;
        if interval < self.interval {
            return Err(Error::TimeRegression);
        }
        if interval != self.interval {
            let consecutive = self.full_period && interval == self.interval + 1;
            let paid = u128::from(self.bytes) * 1000;
            let rate = u128::from(self.rate);
            let queued = ordinary > 8 * mtu;
            let counts = &mut status.gate;
            if !consecutive {
                counts.partial_buckets = counts
                    .partial_buckets
                    .saturating_add(interval - self.interval);
            } else {
                let band = if self.bytes == 0 {
                    &mut counts.empty_buckets
                } else if paid <= 75 * rate {
                    &mut counts.light_buckets
                } else if paid >= 90 * rate {
                    &mut counts.busy_buckets
                } else {
                    &mut counts.middle_buckets
                };
                *band = band.saturating_add(1);
                counts.backlogged_buckets =
                    counts.backlogged_buckets.saturating_add(u64::from(queued));
            }
            if !consecutive || self.bytes == 0 || paid >= 90 * rate || queued {
                self.streak = 0;
                status.spare = false;
            } else if paid <= 75 * rate {
                self.streak = self.streak.saturating_add(1).min(4);
                if self.streak == 4 {
                    status.spare = true;
                }
            } else {
                self.streak = 0;
            }
            counts.open_buckets = counts.open_buckets.saturating_add(u64::from(status.spare));
            self.interval = interval;
            self.full_period = true;
            self.bytes = 0;
        }
        self.total = Some(total);
        self.bytes = self.bytes.saturating_add(delta);
        self.ordinary = ordinary;
        Ok(())
    }
    fn eligible(self, now: Tick, mtu: usize, spare: bool) -> bool {
        spare && self.interval == now.0 / 100_000 && self.ordinary <= 8 * mtu
    }
}
#[derive(Clone, Copy)]
struct Job {
    id: Id,
    cap: Tick,
    extent: usize,
    cleared: usize,
    source: u32,
    column: usize,
    price: usize,
}
pub(super) struct State {
    pub(super) status: Status,
    output: Vec<u8>,
    gate: Option<Gate>,
    mtu: usize,
    overhead: usize,
    extent: usize,
    group_cap: Tick,
    job: Option<Job>,
}
impl State {
    pub(super) fn new(width: usize) -> Result<Self, Error> {
        Ok(Self {
            status: Status::default(),
            output: bytes(width)?,
            gate: None,
            mtu: 0,
            overhead: 0,
            extent: 0,
            group_cap: Tick(u64::MAX),
            job: None,
        })
    }
    pub(super) fn usage(&self) -> Result<storage::Usage, storage::Error> {
        storage::Usage::vector(&self.output)
    }
    pub(super) fn configured(&self) -> bool {
        self.gate.is_some()
    }
    pub(super) fn configure(
        &mut self,
        mtu: usize,
        overhead: usize,
        rate: u64,
        now: Tick,
    ) -> Result<(), Error> {
        if self.gate.is_some()
            || mtu > u16::MAX as usize
            || overhead.checked_add(5).is_none_or(|v| v > mtu)
            || rate == 0
        {
            return Err(Error::Configuration);
        }
        self.mtu = mtu;
        self.overhead = overhead;
        self.gate = Some(Gate {
            rate,
            interval: now.0 / 100_000,
            total: None,
            bytes: 0,
            ordinary: 0,
            streak: 0,
            full_period: false,
        });
        Ok(())
    }
    pub(super) fn observe(
        &mut self,
        now: Tick,
        total: u64,
        ordinary: usize,
        serial: usize,
    ) -> Result<(), Error> {
        self.gate.as_mut().ok_or(Error::Configuration)?.observe(
            now,
            total,
            ordinary.saturating_add(serial),
            self.mtu,
            &mut self.status,
        )
    }
    fn spare(&self, now: Tick) -> bool {
        self.gate
            .is_some_and(|g| g.eligible(now, self.mtu, self.status.spare))
    }
    pub(super) fn discard(&mut self) {
        if self.job.take().is_some() {
            self.status.abandoned = self.status.abandoned.saturating_add(1);
        }
    }
    pub(super) fn first(
        &mut self,
        id: SourceId,
        source_len: usize,
        price: usize,
        accepted: Tick,
        cap: Tick,
    ) -> Result<(), Error> {
        if self.gate.is_none() {
            return Err(Error::Configuration);
        }
        let end = id.0.checked_add(1).ok_or(Error::Identity)?;
        self.status.credit_eighths = self
            .status
            .credit_eighths
            .saturating_add(price as u64)
            .min(8 * self.mtu as u64);
        self.extent = self.extent.max(2 + source_len);
        self.group_cap = self.group_cap.min(cap);
        if end % 8 != 0 {
            return Ok(());
        }
        self.status.opportunities = self.status.opportunities.saturating_add(1);
        self.discard();
        let extent = std::mem::take(&mut self.extent);
        let cap = std::mem::replace(&mut self.group_cap, Tick(u64::MAX));
        let id = Id(end / 8);
        let price = add(length(id, extent)?, self.overhead)?;
        if accepted >= cap {
            self.status.abandoned = self.status.abandoned.saturating_add(1);
        } else if price > self.mtu {
            self.status.oversized = self.status.oversized.saturating_add(1);
        } else if !self.spare(accepted) {
            self.status.gated = self.status.gated.saturating_add(1);
            let gate = self.gate.ok_or(Error::Configuration)?;
            let counts = &mut self.status.gate;
            counts.stale_groups = counts.stale_groups.saturating_add(u64::from(
                gate.interval != accepted.0 / 100_000 || gate.total.is_none(),
            ));
            counts.closed_groups = counts
                .closed_groups
                .saturating_add(u64::from(!self.status.spare));
            counts.backlogged_groups = counts
                .backlogged_groups
                .saturating_add(u64::from(gate.ordinary > 8 * self.mtu));
        } else if self.status.credit_eighths < 8 * price as u64 {
            self.status.unfunded = self.status.unfunded.saturating_add(1);
        } else {
            self.job = Some(Job {
                id,
                cap,
                extent,
                price,
                source: end - 8,
                column: 0,
                cleared: 0,
            });
        }
        Ok(())
    }
    pub(super) fn pending(&self, scope: Scope) -> Option<Row<'_>> {
        let j = self.job?;
        (j.source == j.id.end().ok()?).then_some(Row {
            scope,
            id: j.id,
            bytes: &self.output[..j.extent],
        })
    }
    pub(super) fn has_job(&self) -> bool {
        self.job.is_some()
    }
    pub(super) fn service(
        &mut self,
        encoder: &Encoder,
        now: Tick,
        w: &mut WorkBudget,
    ) -> Result<Option<(Id, Tick)>, Error> {
        let Some(mut j) = self.job else {
            return Ok(None);
        };
        let end = j.id.end()?;
        if now >= j.cap || !self.spare(now) || encoder.status().confirmed_prefix >= end {
            self.discard();
            return Ok(None);
        }
        let n = (j.extent - j.cleared).min(w.copies).min(w.metadata);
        self.output[j.cleared..j.cleared + n].fill(0);
        j.cleared += n;
        w.copies -= n;
        w.metadata -= n;
        while j.cleared == j.extent && j.source < end && w.field > 0 && w.metadata > 0 {
            let Some(original) = encoder.source(SourceId(j.source)) else {
                self.discard();
                return Ok(None);
            };
            let len = original.len() + 2;
            let n = (len - j.column).min(w.metadata).min(w.field);
            let factor = crate::field::compact_coefficient(j.id.support()?.seed, j.source);
            if factor == 0 {
                w.metadata -= 1;
                j.source += 1;
                j.column = 0;
                continue;
            }
            let hi = (j.column + n).min(2);
            if j.column < hi {
                let header = (original.len() as u16).to_be_bytes();
                gf_batch::xor_scaled::<false>(
                    &mut self.output[j.column..hi],
                    &header[j.column..hi],
                    factor,
                );
            }
            let at = j.column.max(2);
            if at < j.column + n {
                gf_batch::xor_scaled::<false>(
                    &mut self.output[at..j.column + n],
                    &original[at - 2..j.column + n - 2],
                    factor,
                );
            }
            j.column += n;
            w.field -= n;
            w.metadata -= n;
            if j.column == len {
                j.source += 1;
                j.column = 0;
            }
        }
        self.job = Some(j);
        Ok((j.source == end).then_some((j.id, j.cap)))
    }
    pub(super) fn confirm(&mut self, id: Id, ip: usize) -> Result<(), Error> {
        let j = self.job.ok_or(Error::Busy)?;
        if j.id != id || j.source != id.end()? || j.price != ip {
            return Err(Error::Identity);
        }
        self.status.credit_eighths = self
            .status
            .credit_eighths
            .checked_sub(8 * ip as u64)
            .ok_or(Error::Identity)?;
        self.status.sent_rows = self.status.sent_rows.saturating_add(1);
        self.status.sent_ip_bytes = self.status.sent_ip_bytes.saturating_add(ip as u64);
        self.job = None;
        Ok(())
    }
}

#[cfg(test)]
mod tests;
