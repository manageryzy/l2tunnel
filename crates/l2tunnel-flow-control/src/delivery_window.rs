//! Bounded original-byte delivery window, separate from local queues and TCP cwnd.
use crate::{Credit, target::Micros};
use std::{fmt, mem::size_of};

/// Immutable per-direction policy, authenticated by the integrating session.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Config {
    /// Configured original-native-byte service rate in bits per second.
    pub target_bandwidth_bps: u64,
    /// Initial and stale-history fallback service RTT.
    pub bootstrap_rtt_micros: u64,
    /// Hard lower bound on a qualifying sample.
    pub min_rtt_micros: u64,
    /// Hard upper bound on a qualifying sample; at most120 seconds.
    pub max_rtt_micros: u64,
    /// Percentage of bandwidth-delay product, within 100..=400.
    pub headroom_percent: u16,
    /// Smallest future byte target, at least one maximum packet.
    pub minimum_bytes: u64,
    /// Hard outstanding byte capacity, at most64MiB.
    pub max_inflight_bytes: u64,
    /// Independent metadata/record cap, at most8192.
    pub max_records: usize,
    /// Maximum actual native packet length.
    pub max_packet_bytes: u64,
    /// Explicit local metadata allocation budget.
    pub metadata_limit_bytes: usize,
    /// Original feedback freshness lifetime.
    pub sample_ttl_micros: u64,
    /// Absolute admission-to-full-flush deadline policy.
    pub flush_timeout_micros: u64,
}
/// Explicit local/peer rejection; no peer input panics.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// Unsupported or inconsistent bounded policy.
    Configuration,
    /// Preallocation failed without constructing an owner.
    Memory,
    /// Backward time or unrepresentable original deadline.
    Time,
    /// Checked cumulative arithmetic exhausted.
    Exhausted,
    /// Zero-sized or oversized native input.
    Packet,
    /// Byte target or bounded metadata capacity prevents admission.
    Blocked,
    /// Future or non-boundary cumulative feedback.
    Feedback,
    /// Regressing cumulative prefix.
    Stale,
    /// Full-flush confirmation exceeds original admission.
    Flush,
    /// Original full-flush deadline expired; session terminal.
    FlushExpired,
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "delivery window: {self:?}")
    }
}
impl std::error::Error for Error {}
/// Duplicate cumulative notifications consume no additional authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Update {
    /// A validated original prefix advanced.
    Advanced,
    /// Exact retry; no new timestamp or authority.
    Duplicate,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Entry {
    end: Credit,
    flushed_at: Option<Micros>,
    delivered: bool,
    flush_deadline: Micros,
}
/// Causally completed local-clock flush-to-feedback service observation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Sample {
    /// Actual full-flush callback time known before feedback receipt.
    pub flushed_at: Micros,
    /// Original authenticated delivery-feedback receipt time.
    pub feedback_at: Micros,
    /// Observed positive flush-to-feedback elapsed time before clamps.
    pub raw_micros: u64,
    /// Bounded EWMA used for the future target.
    pub smoothed_micros: u64,
}
/// Copied accounting; target bytes are not a native advertised TCP window.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Status {
    /// Monotonic actual-byte and record admission prefix.
    pub admitted: Credit,
    /// Monotonic authenticated remote-device delivery prefix.
    pub delivered: Credit,
    /// Admitted minus delivered original bytes and records.
    pub outstanding: Credit,
    /// Future byte target, retaining all prior outstanding debt.
    pub target_bytes: u64,
    /// Metadata slots still waiting for delivery or full flush.
    pub retained_records: usize,
    /// Latest causally qualified original-clock observation.
    pub sample: Option<Sample>,
    /// True only while the original feedback remains within TTL.
    pub sample_fresh: bool,
    /// Earliest original deadline among unconfirmed flushes.
    pub next_flush_deadline: Option<Micros>,
    /// Sticky flush expiry observed by an authoritative operation.
    pub failed: bool,
}
/// Preallocated bounded record ledger; caller owns authenticated I/O and payloads.
#[derive(Debug)]
pub struct Controller {
    config: Config,
    entries: Vec<Option<Entry>>,
    head: usize,
    len: usize,
    admitted: Credit,
    delivered: Credit,
    flushed_records: u64,
    last_flush_at: Option<Micros>,
    last_feedback_at: Option<Micros>,
    sample: Option<Sample>,
    at: Micros,
    failed: bool,
}
impl Config {
    /// Exact Rust entry-bank size, checked before allocation.
    pub fn metadata_bytes(self) -> Result<usize, Error> {
        self.max_records
            .checked_mul(size_of::<Option<Entry>>())
            .ok_or(Error::Configuration)
    }
    /// Validate finite policy and metadata bounds without allocating or reading time.
    pub fn validate(self) -> Result<(), Error> {
        if self.target_bandwidth_bps == 0
            || self.min_rtt_micros == 0
            || self.min_rtt_micros > self.bootstrap_rtt_micros
            || self.bootstrap_rtt_micros > self.max_rtt_micros
            || self.max_rtt_micros > 120_000_000
            || !(100..=400).contains(&self.headroom_percent)
            || self.max_packet_bytes == 0
            || self.minimum_bytes < self.max_packet_bytes
            || self.minimum_bytes > self.max_inflight_bytes
            || self.max_inflight_bytes > 64 * 1024 * 1024
            || self.max_records == 0
            || self.max_records > 8192
            || self.metadata_bytes()? > self.metadata_limit_bytes
            || !(1..=120_000_000).contains(&self.sample_ttl_micros)
            || !(1..=120_000_000).contains(&self.flush_timeout_micros)
        {
            return Err(Error::Configuration);
        }
        self.target(self.max_rtt_micros)?;
        Ok(())
    }
    fn target(self, rtt: u64) -> Result<u64, Error> {
        let numerator = u128::from(self.target_bandwidth_bps)
            .checked_mul(u128::from(rtt))
            .and_then(|v| v.checked_mul(u128::from(self.headroom_percent)))
            .ok_or(Error::Exhausted)?;
        let value = numerator.div_ceil(800_000_000);
        Ok(value
            .min(u128::from(self.max_inflight_bytes))
            .max(u128::from(self.minimum_bytes)) as u64)
    }
}
impl Controller {
    /// Validate and allocate the complete bounded metadata bank before I/O.
    pub fn new(config: Config, now: Micros) -> Result<Self, Error> {
        config.validate()?;
        now.0
            .checked_add(config.flush_timeout_micros)
            .ok_or(Error::Time)?;
        let mut entries = Vec::new();
        entries
            .try_reserve_exact(config.max_records)
            .map_err(|_| Error::Memory)?;
        entries.resize(config.max_records, None);
        Ok(Self {
            config,
            entries,
            head: 0,
            len: 0,
            admitted: Credit::default(),
            delivered: Credit::default(),
            flushed_records: 0,
            last_flush_at: None,
            last_feedback_at: None,
            sample: None,
            at: now,
            failed: false,
        })
    }
    fn fresh(&self, now: Micros) -> bool {
        self.sample.is_some_and(|s| {
            now >= s.feedback_at && now.0 - s.feedback_at.0 < self.config.sample_ttl_micros
        })
    }
    fn target(&self, now: Micros) -> Result<u64, Error> {
        self.config.target(
            self.sample
                .filter(|_| self.fresh(now))
                .map_or(self.config.bootstrap_rtt_micros, |s| s.smoothed_micros),
        )
    }
    fn index(&self, record: u64) -> Option<usize> {
        let first = self.admitted.records - self.len as u64;
        if record <= first || record > self.admitted.records {
            return None;
        }
        Some((self.head + usize::try_from(record - first - 1).ok()?) % self.entries.len())
    }
    fn deadline(&self) -> Option<Micros> {
        let next = self.flushed_records.checked_add(1)?;
        self.entries
            .get(self.index(next)?)
            .copied()
            .flatten()
            .map(|e| e.flush_deadline)
    }
    /// Resolve an authenticated ordinal to the original actual-byte boundary.
    /// This lookup creates no peer authority and never estimates bytes by MTU.
    pub fn credit_at_record(&self, record: u64) -> Result<Credit, Error> {
        if record == self.delivered.records {
            return Ok(self.delivered);
        }
        if record < self.delivered.records {
            return Err(Error::Stale);
        }
        self.index(record)
            .and_then(|i| self.entries[i])
            .map(|e| e.end)
            .ok_or(Error::Feedback)
    }
    fn check(&mut self, now: Micros) -> Result<(), Error> {
        if now < self.at {
            return Err(Error::Time);
        }
        if self.failed {
            return Err(Error::FlushExpired);
        }
        if self.deadline().is_some_and(|d| now >= d) {
            self.failed = true;
            return Err(Error::FlushExpired);
        }
        Ok(())
    }
    /// Observe time-indexed facts without renewing timestamps or deadlines.
    pub fn status(&self, now: Micros) -> Result<Status, Error> {
        if now < self.at {
            return Err(Error::Time);
        }
        Ok(Status {
            admitted: self.admitted,
            delivered: self.delivered,
            outstanding: Credit {
                bytes: self.admitted.bytes - self.delivered.bytes,
                records: self.admitted.records - self.delivered.records,
            },
            target_bytes: self.target(now)?,
            retained_records: self.len,
            sample: self.sample,
            sample_fresh: self.fresh(now),
            next_flush_deadline: self.deadline(),
            failed: self.failed,
        })
    }
    /// Validate before consuming native input; this does not reserve any bytes.
    pub fn preview_admit(&mut self, bytes: u64, now: Micros) -> Result<(), Error> {
        self.check(now)?;
        if bytes == 0 || bytes > self.config.max_packet_bytes {
            return Err(Error::Packet);
        }
        let outstanding = self.admitted.bytes - self.delivered.bytes;
        let next = outstanding.checked_add(bytes).ok_or(Error::Exhausted)?;
        if next > self.target(now)?
            || next > self.config.max_inflight_bytes
            || self.len == self.config.max_records
        {
            return Err(Error::Blocked);
        }
        self.admitted
            .bytes
            .checked_add(bytes)
            .ok_or(Error::Exhausted)?;
        self.admitted
            .records
            .checked_add(1)
            .ok_or(Error::Exhausted)?;
        now.0
            .checked_add(self.config.flush_timeout_micros)
            .ok_or(Error::Time)?;
        Ok(())
    }
    /// Commit one actual native packet, charging its actual byte length once.
    pub fn admit(&mut self, bytes: u64, now: Micros) -> Result<Credit, Error> {
        self.preview_admit(bytes, now)?;
        let end = Credit {
            bytes: self.admitted.bytes + bytes,
            records: self.admitted.records + 1,
        };
        let index = (self.head + self.len) % self.entries.len();
        self.entries[index] = Some(Entry {
            end,
            flushed_at: None,
            delivered: false,
            flush_deadline: Micros(now.0 + self.config.flush_timeout_micros),
        });
        self.len += 1;
        self.admitted = end;
        self.at = now;
        Ok(end)
    }
    /// Confirm an ordered prefix when actual flush and observation share a timestamp.
    pub fn confirm_flushed(&mut self, records: u64, now: Micros) -> Result<Update, Error> {
        self.confirm_flushed_at(records, now, now)
    }
    /// Apply the writer's original full-flush timestamp at a later actor observation.
    /// Observation time governs health and the unchanged admission-time deadline;
    /// actual time must follow every covered admission and cannot be in the future.
    pub fn confirm_flushed_at(
        &mut self,
        records: u64,
        actual_flush_at: Micros,
        observed_at: Micros,
    ) -> Result<Update, Error> {
        self.check(observed_at)?;
        if actual_flush_at > observed_at {
            return Err(Error::Time);
        }
        if records < self.flushed_records {
            return Err(Error::Stale);
        }
        if records > self.admitted.records {
            return Err(Error::Flush);
        }
        if records == self.flushed_records {
            self.at = observed_at;
            return Ok(Update::Duplicate);
        }
        if self.last_flush_at.is_some_and(|t| actual_flush_at < t) {
            return Err(Error::Time);
        }
        // Preflight every original boundary before changing any timestamp.
        for record in self.flushed_records + 1..=records {
            let e = self
                .index(record)
                .and_then(|i| self.entries[i])
                .ok_or(Error::Flush)?;
            let admitted_at = e.flush_deadline.0 - self.config.flush_timeout_micros;
            if actual_flush_at.0 < admitted_at || actual_flush_at >= e.flush_deadline {
                return Err(Error::Time);
            }
        }
        for record in self.flushed_records + 1..=records {
            let i = self.index(record).ok_or(Error::Flush)?;
            if let Some(e) = &mut self.entries[i] {
                e.flushed_at = Some(actual_flush_at);
            }
        }
        self.flushed_records = records;
        self.last_flush_at = Some(actual_flush_at);
        self.at = observed_at;
        self.prune();
        Ok(Update::Advanced)
    }
    /// Apply an authenticated boundary when original receipt is observed immediately.
    pub fn delivered(&mut self, end: Credit, now: Micros) -> Result<Update, Error> {
        self.delivered_at(end, now, now)
    }
    /// Apply an original authenticated feedback receipt at a later actor observation.
    /// Only the original receipt determines service elapsed time and sample age.
    /// A later flush callback never retroactively samples an already delivered record.
    pub fn delivered_at(
        &mut self,
        end: Credit,
        feedback_at: Micros,
        observed_at: Micros,
    ) -> Result<Update, Error> {
        self.check(observed_at)?;
        if feedback_at > observed_at {
            return Err(Error::Time);
        }
        if end.records < self.delivered.records {
            return Err(Error::Stale);
        }
        if end == self.delivered {
            self.at = observed_at;
            return Ok(Update::Duplicate);
        }
        if end.records <= self.delivered.records
            || end.records > self.admitted.records
            || self.credit_at_record(end.records)? != end
        {
            return Err(Error::Feedback);
        }
        let last = self
            .index(end.records)
            .and_then(|i| self.entries[i])
            .ok_or(Error::Feedback)?;
        if feedback_at.0 < last.flush_deadline.0 - self.config.flush_timeout_micros
            || self.last_feedback_at.is_some_and(|t| feedback_at < t)
        {
            return Err(Error::Time);
        }
        let latest = (self.delivered.records + 1..=end.records)
            .rev()
            .filter_map(|record| {
                self.index(record)
                    .and_then(|i| self.entries[i])
                    .and_then(|e| {
                        e.flushed_at
                            .filter(|t| feedback_at > *t)
                            .map(|t| (record, t))
                    })
            })
            .next();
        if let Some((_, flushed)) = latest {
            let raw = feedback_at.0 - flushed.0;
            let bounded = raw.clamp(self.config.min_rtt_micros, self.config.max_rtt_micros);
            let smooth = self
                .sample
                .filter(|_| self.fresh(observed_at))
                .map_or(bounded, |s| {
                    ((7 * u128::from(s.smoothed_micros) + u128::from(bounded)) / 8) as u64
                });
            self.sample = Some(Sample {
                flushed_at: flushed,
                feedback_at,
                raw_micros: raw,
                smoothed_micros: smooth,
            });
        }
        for record in self.delivered.records + 1..=end.records {
            let i = self.index(record).ok_or(Error::Feedback)?;
            if let Some(e) = &mut self.entries[i] {
                e.delivered = true;
            }
        }
        self.delivered = end;
        self.last_feedback_at = Some(feedback_at);
        self.at = observed_at;
        self.prune();
        Ok(Update::Advanced)
    }
    fn prune(&mut self) {
        while self.len > 0
            && self.entries[self.head].is_some_and(|e| e.delivered && e.flushed_at.is_some())
        {
            self.entries[self.head] = None;
            self.head = (self.head + 1) % self.entries.len();
            self.len -= 1;
        }
    }
    /// Service the original admission-time flush deadline; retries never renew it.
    pub fn tick(&mut self, now: Micros) -> Result<(), Error> {
        self.check(now)?;
        self.at = now;
        Ok(())
    }
}

#[cfg(test)]
mod tests;
