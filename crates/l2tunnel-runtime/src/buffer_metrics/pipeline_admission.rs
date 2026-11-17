//! Exact observed FIFO-head admission waits, separate from occupancy and DRR hold.
use super::protocol_buffers::Identity;
use l2tunnel::{pipeline, record_engine::AdmissionBlock, record_engine::AdmissionRefusal};
use std::io::{self, Write};

const MAX_FLOWS: usize = 256;
const REASONS: [&str; 5] = [
    "native_delivery_window",
    "swift_packing_queue",
    "codec_stage",
    "connection_retirement",
    "connection_unreliable_slot",
];

fn reason(value: AdmissionBlock) -> usize {
    match value {
        AdmissionBlock::NativeDeliveryWindow => 0,
        AdmissionBlock::SwiftPackingQueue => 1,
        AdmissionBlock::CodecStage => 2,
        AdmissionBlock::ConnectionRetirement => 3,
        AdmissionBlock::ConnectionUnreliableSlot => 4,
    }
}
fn add(value: &mut u64, amount: u64, invalid: &mut bool) {
    match value.checked_add(amount) {
        Some(next) => *value = next,
        None => {
            *value = u64::MAX;
            *invalid = true;
        }
    }
}

#[derive(Clone, Copy, Default)]
struct Totals {
    episodes: u64,
    completed_episodes: u64,
    completed_us: u64,
    censored_episodes: u64,
    censored_us: u64,
    maximum_us: u64,
}
impl Totals {
    fn start(&mut self, invalid: &mut bool) {
        add(&mut self.episodes, 1, invalid);
    }
    fn stop(&mut self, elapsed: u64, complete: bool, invalid: &mut bool) {
        let (count, total) = if complete {
            (&mut self.completed_episodes, &mut self.completed_us)
        } else {
            (&mut self.censored_episodes, &mut self.censored_us)
        };
        add(count, 1, invalid);
        add(total, elapsed, invalid);
        self.maximum_us = self.maximum_us.max(elapsed);
    }
    fn write(&self, out: &mut impl Write, open_us: Option<u64>) -> io::Result<()> {
        write!(
            out,
            "{{\"episodes\":{},\"completed_episodes\":{},\"completed_us\":{},\"censored_episodes\":{},\"censored_us\":{},\"maximum_us\":{},\"open_us\":",
            self.episodes,
            self.completed_episodes,
            self.completed_us,
            self.censored_episodes,
            self.censored_us,
            self.maximum_us.max(open_us.unwrap_or(0)),
        )?;
        optional(out, open_us)?;
        write!(out, "}}")
    }
}

#[derive(Clone, Copy, Eq, PartialEq, Ord, PartialOrd)]
struct Key {
    epoch: u64,
    configuration: [u8; 32],
    flow: u64,
    channel: u16,
}
impl Key {
    fn new(identity: Identity, binding: pipeline::Binding) -> Self {
        Self {
            epoch: identity.epoch,
            configuration: identity.configuration,
            flow: binding.id.0,
            channel: binding.channel,
        }
    }
    fn identity(self) -> Identity {
        Identity {
            epoch: self.epoch,
            configuration: self.configuration,
        }
    }
}

#[derive(Clone, Copy)]
struct Head {
    timing: pipeline::PacketTiming,
    bytes: usize,
    first: u64,
    reason_since: u64,
    reason: usize,
}
struct Row {
    key: Key,
    first: u64,
    last: u64,
    retired_at: Option<u64>,
    pending: Option<Head>,
    refusals: [u64; REASONS.len()],
    union: Totals,
    causes: [Totals; REASONS.len()],
}
impl Row {
    fn new(key: Key, now: u64) -> Self {
        Self {
            key,
            first: now,
            last: now,
            retired_at: None,
            pending: None,
            refusals: [0; REASONS.len()],
            union: Totals::default(),
            causes: [Totals::default(); REASONS.len()],
        }
    }
    fn stop(&mut self, now: u64, complete: bool, overflow: &mut bool) {
        if let Some(head) = self.pending.take() {
            self.union.stop(now - head.first, complete, overflow);
            self.causes[head.reason].stop(now - head.reason_since, complete, overflow);
        }
        self.last = now;
    }
}

/// First-refusing flow identities are retained up to the explicitly reported cap.
/// No active wait is evicted and no per-event allocation occurs. Scope includes
/// epoch/configuration because a new Pipeline may begin with the same local ID.
pub(crate) struct PipelineAdmission {
    rows: Vec<Row>,
    limit: usize,
    last: Option<u64>,
    terminal: Option<u64>,
    omitted_refusals: u64,
    unavailable_terminal: u64,
    identity_errors: u64,
    clock_regressions: u64,
    after_terminal: u64,
    overflow: bool,
}
impl PipelineAdmission {
    pub(crate) fn new(maximum_live_flows_per_epoch: usize) -> io::Result<Self> {
        if maximum_live_flows_per_epoch == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "pipeline flow observer bound",
            ));
        }
        // The Bank has at most two live generations. Lifetime churn beyond this
        // diagnostic bound is explicitly omitted, never silently relabeled.
        let limit = maximum_live_flows_per_epoch
            .saturating_mul(2)
            .min(MAX_FLOWS);
        let mut rows = Vec::new();
        rows.try_reserve_exact(limit).map_err(io::Error::other)?;
        Ok(Self {
            rows,
            limit,
            last: None,
            terminal: None,
            omitted_refusals: 0,
            unavailable_terminal: 0,
            identity_errors: 0,
            clock_regressions: 0,
            after_terminal: 0,
            overflow: false,
        })
    }
    pub(crate) fn heap_bytes(&self) -> usize {
        self.rows.capacity() * std::mem::size_of::<Row>()
    }
    fn time(&mut self, now: u64) -> bool {
        if self.terminal.is_some() {
            add(&mut self.after_terminal, 1, &mut self.overflow);
            return false;
        }
        if self.last.is_some_and(|last| now < last) {
            add(&mut self.clock_regressions, 1, &mut self.overflow);
            return false;
        }
        self.last = Some(now);
        true
    }
    pub(crate) fn refused(&mut self, identity: Identity, now: u64, value: AdmissionRefusal) {
        if !self.time(now) {
            return;
        }
        let key = Key::new(
            identity,
            pipeline::Binding {
                id: value.flow,
                channel: value.channel,
            },
        );
        let index = match self.rows.binary_search_by_key(&key, |row| row.key) {
            Ok(index) => index,
            Err(index) if self.rows.len() < self.limit => {
                self.rows.insert(index, Row::new(key, now));
                index
            }
            Err(_) => {
                add(&mut self.omitted_refusals, 1, &mut self.overflow);
                return;
            }
        };
        let row = &mut self.rows[index];
        if row.retired_at.is_some() {
            add(&mut self.identity_errors, 1, &mut self.overflow);
            return;
        }
        let cause = reason(value.reason);
        add(&mut row.refusals[cause], 1, &mut self.overflow);
        if let Some(head) = &mut row.pending {
            // Timestamp/length is only a consistency check, not a unique packet
            // ID: exact identity comes from the retained same-flow FIFO head.
            if head.timing != value.timing || head.bytes != value.bytes {
                add(&mut self.identity_errors, 1, &mut self.overflow);
                row.stop(row.last, false, &mut self.overflow);
                row.retired_at = Some(row.last);
                return;
            }
            if head.reason != cause {
                row.causes[head.reason].stop(now - head.reason_since, true, &mut self.overflow);
                row.causes[cause].start(&mut self.overflow);
                head.reason_since = now;
                head.reason = cause;
            }
        } else {
            row.union.start(&mut self.overflow);
            row.causes[cause].start(&mut self.overflow);
            row.pending = Some(Head {
                timing: value.timing,
                bytes: value.bytes,
                first: now,
                reason_since: now,
                reason: cause,
            });
        }
        row.last = now;
    }
    pub(crate) fn admitted(
        &mut self,
        identity: Identity,
        now: u64,
        metadata: pipeline::PacketMetadata,
    ) {
        if !self.time(now) {
            return;
        }
        let key = Key::new(identity, metadata.binding);
        let Ok(index) = self.rows.binary_search_by_key(&key, |row| row.key) else {
            return;
        };
        let row = &mut self.rows[index];
        if row.retired_at.is_some() {
            add(&mut self.identity_errors, 1, &mut self.overflow);
            return;
        }
        if let Some(head) = row.pending {
            if head.timing != metadata.timing
                || head.bytes != metadata.classification.observed_bytes
            {
                add(&mut self.identity_errors, 1, &mut self.overflow);
                row.stop(row.last, false, &mut self.overflow);
                row.retired_at = Some(row.last);
                return;
            }
            row.stop(now, true, &mut self.overflow);
        }
    }
    /// Actual fresh live-generation identities; retirement censors rather than
    /// completing a queued head, and never transfers its wait to a new epoch.
    pub(crate) fn reconcile(&mut self, now: u64, live: [Option<Identity>; 2]) {
        if !self.time(now) {
            return;
        }
        for row in &mut self.rows {
            if row.retired_at.is_none() && !live.contains(&Some(row.key.identity())) {
                row.stop(now, false, &mut self.overflow);
                row.retired_at = Some(now);
            }
        }
    }
    pub(crate) fn finish(&mut self, now: u64, source_available: bool) {
        if self.terminal.is_some() {
            return;
        }
        let stopped = if source_available {
            now
        } else {
            self.last.unwrap_or(now)
        };
        if !source_available {
            add(&mut self.unavailable_terminal, 1, &mut self.overflow);
        }
        if !self.time(stopped) {
            return;
        }
        for row in &mut self.rows {
            if row.retired_at.is_none() {
                row.stop(stopped, false, &mut self.overflow);
            }
        }
        self.terminal = Some(stopped);
    }
    pub(crate) fn write(&self, out: &mut impl Write) -> io::Result<()> {
        write!(
            out,
            "{{\"definition\":\"actual selected FIFO-head refusal through same-flow head admission; includes scheduling delay; head timestamps are consistency checks, not unique identities; reason changes close only the previously observed first-refusal cause; different rows and generic collector waits overlap and must not be summed\",\"coverage\":\"first refusing flow identities only; ingress capacity, flow-table admission, per-flow occupancy, MUX internals and deliberate DRR/packing holds remain unavailable\",\"flow_limit\":{},\"retained_flows\":{},\"omitted_refusals\":{},\"unavailable_terminal\":{},\"identity_errors\":{},\"clock_regressions\":{},\"after_terminal\":{},\"counter_overflow\":{},\"terminal_at_us\":",
            self.limit,
            self.rows.len(),
            self.omitted_refusals,
            self.unavailable_terminal,
            self.identity_errors,
            self.clock_regressions,
            self.after_terminal,
            self.overflow
        )?;
        optional(out, self.terminal)?;
        write!(out, ",\"flows\":[")?;
        let now = self.last.unwrap_or(0);
        for (index, row) in self.rows.iter().enumerate() {
            if index != 0 {
                write!(out, ",")?;
            }
            write!(
                out,
                "{{\"epoch\":{},\"configuration_digest_hex\":\"",
                row.key.epoch
            )?;
            for byte in row.key.configuration {
                write!(out, "{byte:02x}")?;
            }
            write!(
                out,
                "\",\"flow_id\":{},\"channel\":{},\"first_refusal_us\":{},\"last_event_us\":{},\"retired_at_us\":",
                row.key.flow, row.key.channel, row.first, row.last
            )?;
            optional(out, row.retired_at)?;
            write!(out, ",\"blocked_heads\":")?;
            row.union
                .write(out, row.pending.map(|head| now - head.first))?;
            write!(out, ",\"reasons\":[")?;
            for (i, name) in REASONS.iter().enumerate() {
                if i != 0 {
                    write!(out, ",")?;
                }
                write!(
                    out,
                    "{{\"reason\":\"{name}\",\"refusals\":{},\"blocked\":",
                    row.refusals[i]
                )?;
                row.causes[i].write(
                    out,
                    row.pending
                        .filter(|head| head.reason == i)
                        .map(|head| now - head.reason_since),
                )?;
                write!(out, "}}")?;
            }
            write!(out, "]}}")?;
        }
        write!(out, "]}}")
    }
}
fn optional(out: &mut impl Write, value: Option<u64>) -> io::Result<()> {
    match value {
        Some(value) => write!(out, "{value}"),
        None => write!(out, "null"),
    }
}

#[cfg(test)]
#[path = "pipeline_admission_tests.rs"]
mod tests;
