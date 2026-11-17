//! Bounded management observations; none grant dispatch, ACK or storage authority.
use super::*;
use std::io::Write;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Refusal {
    WrapperEntries,
    MessageCapacity,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum WaitOutcome {
    Admitted,
    Cancelled,
    OwnerFailure,
    MetricStop,
}
#[derive(Clone, Copy, Debug)]
pub(crate) struct Identity {
    submission: u64,
    origin: sc::Scope,
    bytes: usize,
    deadline: Duration,
}
impl From<leased::Reservation> for Identity {
    fn from(value: leased::Reservation) -> Self {
        Self {
            submission: value.submission_id(),
            origin: value.origin_scope(),
            bytes: value.length(),
            deadline: value.deadline(),
        }
    }
}
#[derive(Clone, Copy)]
struct Pending {
    reservation: leased::Reservation,
    since: Duration,
    last: Duration,
}
#[derive(Clone, Copy, Debug)]
pub(crate) struct Resolved {
    identity: Identity,
    since: Duration,
    at: Duration,
    outcome: WaitOutcome,
    message: Option<u64>,
}
#[derive(Clone, Copy, Default)]
pub(crate) struct Timing {
    now: Duration,
    terminal: Option<(Duration, WaitOutcome)>,
    refusals: [u64; 2],
    ordinary_refusals: [u64; 4],
    completed: u64,
    completed_time: Duration,
    censored: u64,
    censored_time: Duration,
    maximum: Duration,
    pending: Option<Pending>,
    last_resolved: Option<Resolved>,
    clock_regression: bool,
    identity_mismatch: bool,
    overflow: bool,
}
impl Timing {
    fn observe(&mut self, now: Duration) -> bool {
        if self.terminal.is_some() {
            return false;
        }
        if now < self.now {
            self.clock_regression = true;
            return false;
        }
        self.now = now;
        true
    }
    pub(super) fn ordinary_refused(&mut self, index: usize) {
        if self.terminal.is_some() {
            return;
        }
        if let Some(count) = self.ordinary_refusals.get_mut(index) {
            add(count, 1, &mut self.overflow);
        } else {
            self.identity_mismatch = true;
        }
    }
    pub(super) fn refused(
        &mut self,
        reservation: leased::Reservation,
        now: Duration,
        reason: Refusal,
    ) {
        if !self.observe(now) {
            return;
        }
        add(
            &mut self.refusals[match reason {
                Refusal::WrapperEntries => 0,
                Refusal::MessageCapacity => 1,
            }],
            1,
            &mut self.overflow,
        );
        let pending = self.pending.get_or_insert(Pending {
            reservation,
            since: now,
            last: now,
        });
        if pending.reservation != reservation {
            self.identity_mismatch = true;
            return;
        }
        pending.last = now;
    }
    pub(super) fn resolved(
        &mut self,
        reservation: leased::Reservation,
        now: Duration,
        outcome: WaitOutcome,
        message: Option<u64>,
    ) {
        if !self.observe(now) {
            return;
        }
        let Some(pending) = self.pending else {
            return;
        };
        if pending.reservation != reservation {
            self.identity_mismatch = true;
            return;
        }
        self.close(now, outcome, message);
    }
    fn close(&mut self, now: Duration, outcome: WaitOutcome, message: Option<u64>) {
        let Some(pending) = self.pending.take() else {
            return;
        };
        let Some(elapsed) = now.checked_sub(pending.since) else {
            self.clock_regression = true;
            self.pending = Some(pending);
            return;
        };
        let (count, total) = if outcome == WaitOutcome::Admitted {
            (&mut self.completed, &mut self.completed_time)
        } else {
            (&mut self.censored, &mut self.censored_time)
        };
        add(count, 1, &mut self.overflow);
        match total.checked_add(elapsed) {
            Some(value) => *total = value,
            None => self.overflow = true,
        }
        self.maximum = self.maximum.max(elapsed);
        self.last_resolved = Some(Resolved {
            identity: pending.reservation.into(),
            since: pending.since,
            at: now,
            outcome,
            message,
        });
    }
    pub(super) fn stop(&mut self, now: Duration, outcome: WaitOutcome) {
        if self.observe(now) {
            self.close(now, outcome, None);
            self.terminal = Some((now, outcome));
        }
    }
}
fn add(value: &mut u64, count: u64, overflow: &mut bool) {
    match value.checked_add(count) {
        Some(next) => *value = next,
        None => *overflow = true,
    }
}

impl Owner {
    /// Enable only fixed scalar observations on the already charged Streamed cell.
    pub(crate) fn enable_buffer_metrics(&mut self) {
        if let Backend::Streamed(streamed) = &mut self.backend
            && streamed.buffer_timing.is_none()
        {
            streamed.buffer_timing = Some(Timing::default());
        }
    }
    pub(crate) fn finish_buffer_metrics(&mut self, now: Duration) {
        if let Backend::Streamed(streamed) = &mut self.backend
            && let Some(timing) = &mut streamed.buffer_timing
        {
            timing.stop(now, WaitOutcome::MetricStop);
        }
    }
    pub(super) fn buffer_failure(&mut self, now: Duration) {
        if let Backend::Streamed(streamed) = &mut self.backend
            && let Some(timing) = &mut streamed.buffer_timing
        {
            timing.stop(now, WaitOutcome::OwnerFailure);
        }
    }
}

const FIELD_COUNT: usize = 20;
#[derive(Clone, Copy)]
struct Row {
    stream: streams::Stream,
    snapshot: messages::BufferSnapshot,
    outgoing: usize,
    confirmed: usize,
    held: Option<Held>,
    samples: u64,
    high: [usize; FIELD_COUNT],
}
impl Row {
    fn fields(&self) -> [(&'static str, usize, Option<usize>); FIELD_COUNT] {
        let value = self.snapshot;
        let r = value.retained;
        let s = value.settings;
        let arq = s.delivery.recovery;
        [
            (
                "outbound_messages",
                r.outbound_messages,
                Some(s.max_outbound_messages),
            ),
            ("outbound_payload_bytes", r.outbound_bytes, None),
            ("outbound_fragment_bytes", r.outbound_fragment_bytes, None),
            (
                "outbound_combined_bytes",
                r.outbound_bytes.saturating_add(r.outbound_fragment_bytes),
                Some(s.max_outbound_bytes),
            ),
            (
                "confirmed_retry_metadata",
                value.confirmed_metadata,
                Some(s.max_outbound_messages),
            ),
            (
                "awaiting_semantic_accepted",
                value.awaiting_accepted,
                Some(s.max_outbound_messages),
            ),
            (
                "source_confirmation_custody",
                value.source_confirmation_custody,
                None,
            ),
            (
                "unsubmitted_fragments",
                value.remaining_fragments,
                s.max_outbound_messages
                    .checked_mul(usize::from(s.max_fragments)),
            ),
            (
                "incomplete_messages",
                r.incomplete_messages,
                Some(s.max_incomplete_messages),
            ),
            (
                "reassembly_reserved_bytes",
                r.reassembly_bytes,
                Some(s.max_reassembly_bytes),
            ),
            (
                "held_complete_bytes",
                r.held_bytes,
                Some(s.max_message_bytes),
            ),
            (
                "recovery_send_records",
                r.recovery.send_records,
                Some(arq.send_records),
            ),
            (
                "recovery_send_payload_bytes",
                r.recovery.send_bytes,
                Some(arq.send_bytes),
            ),
            (
                "recovery_receive_records",
                r.recovery.receive_records,
                Some(arq.receive_records),
            ),
            (
                "recovery_receive_payload_bytes",
                r.recovery.receive_bytes,
                Some(arq.receive_bytes),
            ),
            (
                "wrapper_outgoing",
                self.outgoing,
                Some(s.max_outbound_messages),
            ),
            (
                "wrapper_confirmed",
                self.confirmed,
                Some(s.max_outbound_messages),
            ),
            ("wrapper_held", usize::from(self.held.is_some()), Some(1)),
            (
                "wrapper_dispatched",
                usize::from(self.held.is_some_and(|held| held.dispatched)),
                Some(1),
            ),
            (
                "wrapper_leased",
                usize::from(self.held.is_some_and(|held| held.leased)),
                Some(1),
            ),
        ]
    }
}

/// Opt-in bounded export storage; fixed control identity is separate from data epochs.
pub(crate) struct Report {
    rows: Vec<Row>,
    binding: Option<delivery::Binding>,
    version: u8,
    first: Option<u64>,
    last: Option<u64>,
    samples: u64,
    omitted_owners: u64,
    unavailable: u64,
    overflow: bool,
    clock_regression: bool,
    invalid_occupancy: bool,
    timing: Option<Timing>,
    reservation: Option<Identity>,
    quota: Option<(u32, usize, u32, usize, Duration)>,
}
impl Report {
    pub(crate) fn new() -> io::Result<Self> {
        let mut rows = Vec::new();
        rows.try_reserve_exact(4).map_err(io::Error::other)?;
        Ok(Self {
            rows,
            binding: None,
            version: 0,
            first: None,
            last: None,
            samples: 0,
            omitted_owners: 0,
            unavailable: 0,
            overflow: false,
            clock_regression: false,
            invalid_occupancy: false,
            timing: None,
            reservation: None,
            quota: None,
        })
    }
    pub(crate) fn heap_bytes(&self) -> usize {
        self.rows.capacity() * std::mem::size_of::<Row>()
    }
    pub(crate) fn due(&self, now: u64, force: bool) -> bool {
        force
            || self
                .last
                .is_none_or(|last| now < last || now.saturating_sub(last) >= 100_000)
    }
    pub(crate) fn sample(&mut self, owner: &Owner, now: u64) {
        if self.last.is_some_and(|last| now < last) {
            self.clock_regression = true;
            return;
        }
        let Backend::Streamed(streamed) = &owner.backend else {
            add(&mut self.unavailable, 1, &mut self.overflow);
            self.last = Some(now);
            return;
        };
        if self.binding.is_some_and(|binding| binding != owner.binding)
            || (self.version != 0 && self.version != streamed.version())
        {
            add(
                &mut self.omitted_owners,
                self.rows.len() as u64,
                &mut self.overflow,
            );
            self.rows.clear();
            self.first = None;
            self.samples = 0;
        }
        self.binding = Some(owner.binding);
        self.version = streamed.version();
        self.first.get_or_insert(now);
        self.last = Some(now);
        add(&mut self.samples, 1, &mut self.overflow);
        self.timing = streamed.buffer_timing;
        self.reservation = streamed.reservation.map(Identity::from);
        self.quota = Some((
            streamed.packets_left,
            streamed.bytes_left,
            streamed.quota.packets_per_interval,
            streamed.quota.bytes_per_interval,
            streamed.refill,
        ));
        for (index, message) in streamed.owners.iter().enumerate() {
            let Ok(stream) = streamed.stream(index) else {
                add(&mut self.unavailable, 1, &mut self.overflow);
                continue;
            };
            let mut row = Row {
                stream,
                snapshot: message.buffer_snapshot(),
                outgoing: streamed.outgoing[index].len(),
                confirmed: streamed.outgoing[index]
                    .iter()
                    .filter(|entry| entry.confirmed)
                    .count(),
                held: streamed.held[index],
                samples: 0,
                high: [0; FIELD_COUNT],
            };
            if let Some(prior) = self.rows.get(index) {
                if prior.stream == stream {
                    row.samples = prior.samples;
                    row.high = prior.high;
                } else {
                    add(&mut self.omitted_owners, 1, &mut self.overflow);
                }
            }
            add(&mut row.samples, 1, &mut self.overflow);
            self.overflow |= row.snapshot.counter_overflow;
            for (index, (_, used, capacity)) in row.fields().into_iter().enumerate() {
                self.invalid_occupancy |= capacity.is_some_and(|limit| used > limit);
                row.high[index] = row.high[index].max(used);
            }
            if let Some(slot) = self.rows.get_mut(index) {
                *slot = row;
            } else if self.rows.len() < 4 {
                self.rows.push(row);
            } else {
                add(&mut self.unavailable, 1, &mut self.overflow);
            }
        }
    }
    pub(crate) fn write(&self, out: &mut impl Write) -> io::Result<()> {
        write!(
            out,
            "{{\"definition\":\"sampled management storage; fixed control owner distinct from data epochs; queued source confirmation custody is not missing ACK count; reassembly bytes include reserved completion capacity; frozen submit timing is independent of carrier waits and is not added to the generic union\",\"coverage\":\"partial: only immutable frozen Transaction submission is timed; ordinary reused-ID submits are count-only; fragment admission, receipt acceptance, dispatch and dependencies remain untimed; retired unsampled tails unavailable; lifecycle callback failures are only observed at the next owner check or metric stop\",\"version\":{},\"sample_interval_us\":100000,\"samples\":{},\"retired_owners_omitted\":{},\"unavailable_samples\":{},\"counter_overflow\":{},\"clock_regression\":{},\"invalid_occupancy\":{},\"first_sample_us\":",
            self.version,
            self.samples,
            self.omitted_owners,
            self.unavailable,
            self.overflow,
            self.clock_regression,
            self.invalid_occupancy
        )?;
        optional(out, self.first)?;
        write!(out, ",\"last_sample_us\":")?;
        optional(out, self.last)?;
        write!(out, ",\"binding\":")?;
        if let Some(binding) = self.binding {
            write!(out, "{{\"session_hex\":\"")?;
            for byte in binding.session.0 {
                write!(out, "{byte:02x}")?;
            }
            write!(
                out,
                "\",\"lane\":{},\"role\":\"{:?}\",\"control_epoch\":{}}}",
                binding.lane.0, binding.local_role, binding.control_epoch
            )?;
        } else {
            write!(out, "null")?;
        }
        write!(out, ",\"shared_quota\":")?;
        if let Some((packets, bytes, packet_cap, byte_cap, refill)) = self.quota {
            write!(
                out,
                "{{\"packets_left\":{packets},\"bytes_left\":{bytes},\"packets_per_interval\":{packet_cap},\"bytes_per_interval\":{byte_cap},\"refill_at_us\":{},\"definition\":\"one shared policy allowance, not buffered payload occupancy or blocked time\"}}",
                refill.as_micros()
            )?;
        } else {
            write!(out, "null")?;
        }
        write!(out, ",\"reservation\":")?;
        identity(out, self.reservation)?;
        write!(out, ",\"streams\":[")?;
        for (index, row) in self.rows.iter().enumerate() {
            if index != 0 {
                write!(out, ",")?;
            }
            write!(
                out,
                "{{\"stream\":\"{:?}\",\"stream_control_epoch\":{},\"samples\":{},\"last_successful_owner_us\":{},\"owner_failed\":{},\"held_message\":",
                row.stream,
                row.snapshot.binding.control_epoch,
                row.samples,
                row.snapshot.last_successful_at.as_micros(),
                row.snapshot.owner_error.is_some()
            )?;
            optional(out, row.snapshot.held_message)?;
            write!(out, ",\"held_original_deadline_us\":")?;
            time(out, row.snapshot.held_deadline)?;
            write!(
                out,
                ",\"source_scratch_capacity_bytes\":{},\"ordinary_submit_refusals\":",
                row.snapshot.retained.source_scratch_bytes
            )?;
            optional(
                out,
                self.timing.map(|timing| timing.ordinary_refusals[index]),
            )?;
            write!(out, ",\"ordinary_submit_duration_us\":null,\"gauges\":[")?;
            for (i, (name, used, cap)) in row.fields().into_iter().enumerate() {
                if i != 0 {
                    write!(out, ",")?;
                }
                let unit = if name.ends_with("_bytes") {
                    "bytes"
                } else {
                    "items"
                };
                write!(
                    out,
                    "{{\"name\":\"{name}\",\"unit\":\"{unit}\",\"used\":{used},\"capacity\":"
                )?;
                optional(out, cap.map(|v| v as u64))?;
                write!(out, ",\"high_water\":{}}}", row.high[i])?;
            }
            write!(out, "]}}")?;
        }
        write!(out, "],\"frozen_submission_wait\":")?;
        match self.timing {
            Some(timing) => timing.write(out, self.last.map(Duration::from_micros))?,
            None => write!(out, "null")?,
        }
        write!(out, "}}")
    }
}
fn optional(out: &mut impl Write, value: Option<u64>) -> io::Result<()> {
    match value {
        Some(value) => write!(out, "{value}"),
        None => write!(out, "null"),
    }
}
fn time(out: &mut impl Write, value: Option<Duration>) -> io::Result<()> {
    match value {
        Some(value) => write!(out, "{}", value.as_micros()),
        None => write!(out, "null"),
    }
}
fn identity(out: &mut impl Write, value: Option<Identity>) -> io::Result<()> {
    let Some(value) = value else {
        return write!(out, "null");
    };
    write!(
        out,
        "{{\"submission\":{},\"origin_epoch\":{},\"origin_digest_hex\":\"",
        value.submission, value.origin.epoch.0
    )?;
    for byte in value.origin.digest.0 {
        write!(out, "{byte:02x}")?;
    }
    write!(
        out,
        "\",\"bytes\":{},\"original_deadline_us\":{}}}",
        value.bytes,
        value.deadline.as_micros()
    )
}
impl Timing {
    fn write(self, out: &mut impl Write, observed: Option<Duration>) -> io::Result<()> {
        let at = self.terminal.map(|(at, _)| at).or(observed);
        let open = self
            .pending
            .and_then(|pending| at?.checked_sub(pending.since));
        write!(
            out,
            "{{\"definition\":\"same immutable frozen reservation refused through actual message ticket admission; repeated refusal never renews start; cancel/error/pre-settlement metric stop are censored; reasons overlap and only their joint interval is timed; includes scheduling delay\",\"stream\":\"Transaction\",\"wrapper_entry_refusals\":{},\"message_capacity_refusals\":{},\"completed_episodes\":{},\"completed_us\":{},\"censored_episodes\":{},\"censored_us\":{},\"maximum_us\":{},\"clock_regression\":{},\"identity_mismatch\":{},\"counter_overflow\":{},\"observed_at_us\":",
            self.refusals[0],
            self.refusals[1],
            self.completed,
            self.completed_time.as_micros(),
            self.censored,
            self.censored_time.as_micros(),
            self.maximum.max(open.unwrap_or_default()).as_micros(),
            self.clock_regression || at.is_some_and(|at| at < self.now),
            self.identity_mismatch,
            self.overflow
        )?;
        time(out, at)?;
        write!(out, ",\"open_us\":")?;
        time(out, open)?;
        write!(out, ",\"terminal_at_us\":")?;
        time(out, self.terminal.map(|(at, _)| at))?;
        write!(out, ",\"terminal_kind\":")?;
        if let Some((_, kind)) = self.terminal {
            write!(out, "\"{kind:?}\"")?;
        } else {
            write!(out, "null")?;
        }
        write!(out, ",\"pending\":")?;
        identity(out, self.pending.map(|pending| pending.reservation.into()))?;
        write!(out, ",\"first_refusal_us\":")?;
        time(out, self.pending.map(|pending| pending.since))?;
        write!(out, ",\"last_refusal_us\":")?;
        time(out, self.pending.map(|pending| pending.last))?;
        write!(out, ",\"last_resolved\":")?;
        if let Some(last) = self.last_resolved {
            write!(out, "{{\"identity\":")?;
            identity(out, Some(last.identity))?;
            write!(
                out,
                ",\"first_refusal_us\":{},\"resolved_at_us\":{},\"outcome\":\"{:?}\",\"wire_message\":",
                last.since.as_micros(),
                last.at.as_micros(),
                last.outcome
            )?;
            optional(out, last.message)?;
            write!(out, "}}")?;
        } else {
            write!(out, "null")?;
        }
        write!(out, "}}")
    }
}
