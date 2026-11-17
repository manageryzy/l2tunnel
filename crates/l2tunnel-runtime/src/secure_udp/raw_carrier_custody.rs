//! Optional exact raw-token custody latency, not socket blocking or peer delivery.
//!
//! Only final User and Control records are measured. Four fixed lane/class rows
//! aggregate successful stage durations separately from unresolved terminal ages.
//! No identities, payloads or keys are exported. Stage totals overlap across
//! records and must not be added to infer an owner blocked interval.
use super::{AcceptedReceipt, Pending, lane_number, raw};
use std::{
    fs::OpenOptions,
    io::{self, BufWriter, Write},
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};
use tokio::time::Instant;

static NEXT_OWNER: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Copy, Debug)]
pub(super) enum Class {
    User,
    Control,
}
impl Class {
    fn index(self) -> usize {
        match self {
            Self::User => 0,
            Self::Control => 1,
        }
    }
}
#[derive(Clone, Copy, Default)]
struct Total {
    samples: u64,
    sum_us: u64,
    max_us: u64,
}
impl Total {
    fn sample(&mut self, start: Instant, end: Instant, overflow: &mut bool) -> bool {
        let Some(us) = end
            .checked_duration_since(start)
            .and_then(|d| u64::try_from(d.as_micros()).ok())
        else {
            return false;
        };
        add(&mut self.samples, 1, overflow);
        add(&mut self.sum_us, us, overflow);
        self.max_us = self.max_us.max(us);
        true
    }
    fn write(self, out: &mut impl Write) -> io::Result<()> {
        write!(
            out,
            "{{\"samples\":{},\"sum_us\":{},\"max_us\":{}}}",
            self.samples, self.sum_us, self.max_us
        )
    }
}
#[derive(Clone, Copy, Default)]
struct Row {
    committed: u64,
    physical_observed: u64,
    upper_taken: u64,
    late_physical: u64,
    commit_to_physical: Total,
    physical_to_observe: Total,
    observe_to_take: Total,
    censored_before_physical_observation: Total,
    censored_after_physical_observation: Total,
}
#[derive(Clone, Copy)]
struct Identity<T> {
    token: T,
    lane: u8,
    bytes: usize,
    cost: usize,
    deadline: Instant,
}
#[derive(Clone, Copy)]
struct Flight<T> {
    identity: Identity<T>,
    committed_at: Instant,
    observed: Option<(AcceptedReceipt, Instant)>,
}
struct Tracker<T> {
    origin: Instant,
    last: Instant,
    finished: Option<Instant>,
    rows: [Row; 4],
    flight: [Option<Flight<T>>; 2],
    invalid_clock: bool,
    identity_mismatches: u64,
    duplicate_observations: u64,
    counter_overflow: bool,
}
impl<T: Copy + Eq> Tracker<T> {
    fn new(now: Instant) -> Self {
        Self {
            origin: now,
            last: now,
            finished: None,
            rows: [Row::default(); 4],
            flight: [None, None],
            invalid_clock: false,
            identity_mismatches: 0,
            duplicate_observations: 0,
            counter_overflow: false,
        }
    }
    fn at(&mut self, now: Instant) -> bool {
        if self.finished.is_some() || now < self.last {
            self.invalid_clock = true;
            return false;
        }
        self.last = now;
        true
    }
    fn mismatch(&mut self) {
        add(&mut self.identity_mismatches, 1, &mut self.counter_overflow);
    }
    fn commit(&mut self, class: Class, identity: Identity<T>, now: Instant) {
        if !self.at(now) {
            return;
        }
        let index = class.index();
        if identity.lane > 1 || self.flight[index].is_some() {
            self.mismatch();
            return;
        }
        self.flight[index] = Some(Flight {
            identity,
            committed_at: now,
            observed: None,
        });
        add(
            &mut self.rows[usize::from(identity.lane) * 2 + index].committed,
            1,
            &mut self.counter_overflow,
        );
    }
    fn observe(
        &mut self,
        class: Class,
        lane: u8,
        token: T,
        receipt: AcceptedReceipt,
        now: Instant,
    ) {
        if !self.at(now) {
            return;
        }
        let index = class.index();
        let Some(flight) = self.flight[index] else {
            self.mismatch();
            return;
        };
        let identity = flight.identity;
        if token != identity.token
            || lane != identity.lane
            || receipt.record_bytes != identity.bytes
            || receipt.charged_bytes != identity.cost
            || receipt.deadline != identity.deadline
        {
            self.mismatch();
            return;
        }
        if let Some((old, _)) = flight.observed {
            if old == receipt {
                add(
                    &mut self.duplicate_observations,
                    1,
                    &mut self.counter_overflow,
                );
            } else {
                self.mismatch();
            }
            return;
        }
        if receipt.accepted_at < flight.committed_at || receipt.accepted_at > now {
            self.invalid_clock = true;
            return;
        }
        let row = &mut self.rows[usize::from(lane) * 2 + index];
        if !row.commit_to_physical.sample(
            flight.committed_at,
            receipt.accepted_at,
            &mut self.counter_overflow,
        ) || !row.physical_to_observe.sample(
            receipt.accepted_at,
            now,
            &mut self.counter_overflow,
        ) {
            self.invalid_clock = true;
            return;
        }
        add(&mut row.physical_observed, 1, &mut self.counter_overflow);
        if receipt.accepted_at >= receipt.deadline {
            add(&mut row.late_physical, 1, &mut self.counter_overflow);
        }
        self.flight[index] = Some(Flight {
            observed: Some((receipt, now)),
            ..flight
        });
    }
    fn take(&mut self, class: Class, lane: u8, receipt: AcceptedReceipt, now: Instant) {
        if !self.at(now) {
            return;
        }
        let index = class.index();
        let Some(flight) = self.flight[index] else {
            self.mismatch();
            return;
        };
        let Some((old, observed_at)) = flight.observed else {
            self.mismatch();
            return;
        };
        if flight.identity.lane != lane || old != receipt {
            self.mismatch();
            return;
        }
        let row = &mut self.rows[usize::from(lane) * 2 + index];
        if !row
            .observe_to_take
            .sample(observed_at, now, &mut self.counter_overflow)
        {
            self.invalid_clock = true;
            return;
        }
        add(&mut row.upper_taken, 1, &mut self.counter_overflow);
        self.flight[index] = None;
    }
    fn finish(&mut self, now: Instant) {
        if self.finished.is_some() {
            return;
        }
        if !self.at(now) {
            self.finished = Some(self.last);
            return;
        }
        for (class, flight) in self.flight.iter_mut().enumerate() {
            if let Some(flight) = flight.take() {
                let row = &mut self.rows[usize::from(flight.identity.lane) * 2 + class];
                let valid = if let Some((_, at)) = flight.observed {
                    row.censored_after_physical_observation.sample(
                        at,
                        now,
                        &mut self.counter_overflow,
                    )
                } else {
                    // The physical boundary is unobserved, not proven absent.
                    // This is censored commit age, not a successful stage duration.
                    row.censored_before_physical_observation.sample(
                        flight.committed_at,
                        now,
                        &mut self.counter_overflow,
                    )
                };
                self.invalid_clock |= !valid;
            }
        }
        self.finished = Some(now);
    }
    fn write(&self, out: &mut impl Write, heap_bytes: usize) -> io::Result<()> {
        let elapsed = self
            .last
            .checked_duration_since(self.origin)
            .and_then(|d| u64::try_from(d.as_micros()).ok());
        write!(
            out,
            "{{\"schema\":1,\"owner\":\"raw_custody\",\"pid\":{},\"definition\":\"Exact final raw User/Control token custody stage latency; not socket blocking or peer delivery. Never add overlapping stage totals or owners.\",\"coverage\":\"Final records only; bootstrap, preparation, candidate residence and peer-credit demand intervals are unmeasured.\",\"diagnostic_heap_bytes\":{heap_bytes},\"inline_bytes\":{},\"blocked_union\":null,\"sites\":[],\"raw_custody\":{{\"schema\":1,\"observed_us\":",
            std::process::id(),
            std::mem::size_of::<Observer>()
        )?;
        optional(out, elapsed)?;
        write!(
            out,
            ",\"finished\":{},\"invalid_clock\":{},\"identity_mismatches\":{},\"duplicate_observations\":{},\"counter_overflow\":{},\"identity_definition\":\"Existing RecordToken plus class/lane is correlated before physical receipt state clears; upper take must match the exact retained AcceptedReceipt. No identities exported.\",\"censor_definition\":\"Terminal unresolved ages are separate populations. Before physical observation the send may have happened but is not known here. After observation only upper-take age is censored. No censored age is counted as successful delivery.\",\"rows\":[",
            self.finished.is_some(),
            self.invalid_clock,
            self.identity_mismatches,
            self.duplicate_observations,
            self.counter_overflow
        )?;
        for (index, row) in self.rows.iter().enumerate() {
            if index != 0 {
                write!(out, ",")?;
            }
            write!(
                out,
                "{{\"lane\":{},\"class\":\"{}\",\"committed\":{},\"physical_observed\":{},\"upper_taken\":{},\"late_physical\":{}",
                index / 2,
                if index % 2 == 0 { "User" } else { "Control" },
                row.committed,
                row.physical_observed,
                row.upper_taken,
                row.late_physical
            )?;
            for (name, total) in [
                ("commit_to_physical", row.commit_to_physical),
                ("physical_to_observe", row.physical_to_observe),
                ("observe_to_take", row.observe_to_take),
                (
                    "censored_before_physical_observation",
                    row.censored_before_physical_observation,
                ),
                (
                    "censored_after_physical_observation",
                    row.censored_after_physical_observation,
                ),
            ] {
                write!(out, ",\"{name}\":")?;
                total.write(out)?;
            }
            write!(out, "}}")?;
        }
        writeln!(out, "]}}}}")
    }
}
fn add(value: &mut u64, amount: u64, overflow: &mut bool) {
    if let Some(next) = value.checked_add(amount) {
        *value = next;
    } else {
        *value = u64::MAX;
        *overflow = true;
    }
}
fn optional(out: &mut impl Write, value: Option<u64>) -> io::Result<()> {
    match value {
        Some(v) => write!(out, "{v}"),
        None => write!(out, "null"),
    }
}
struct State {
    tracker: Tracker<raw::RecordToken>,
    path: PathBuf,
    temporary: PathBuf,
}
/// No heap when disabled. Enabling reserves one bounded cell before adapter I/O.
pub(super) struct Observer {
    state: Vec<State>,
}
impl Observer {
    pub(super) fn from_environment() -> io::Result<Self> {
        let Some(mut prefix) = std::env::var_os("L2TUNNEL_BUFFER_METRICS")
            .or_else(|| std::env::var_os("L2TUNNEL_WIRE_METRICS"))
        else {
            return Ok(Self { state: Vec::new() });
        };
        if prefix.is_empty() || prefix.as_encoded_bytes().len() > 4096 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "raw custody metrics path",
            ));
        }
        let id = NEXT_OWNER
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |id| id.checked_add(1))
            .map_err(|_| io::Error::other("raw custody metrics owner exhausted"))?;
        prefix.push(format!(
            ".buffers.raw_custody.{}.{id}.bmetrics",
            std::process::id()
        ));
        Self::at_path(PathBuf::from(prefix), Instant::now())
    }
    fn at_path(path: PathBuf, now: Instant) -> io::Result<Self> {
        let mut name = path.as_os_str().to_owned();
        name.push(".tmp");
        let mut state = Vec::new();
        state.try_reserve_exact(1).map_err(io::Error::other)?;
        if state.capacity() != 1 {
            return Err(io::Error::other("raw custody diagnostic capacity"));
        }
        state.push(State {
            tracker: Tracker::new(now),
            path,
            temporary: PathBuf::from(name),
        });
        Ok(Self { state })
    }
    pub(super) fn commit(&mut self, class: Class, pending: &Pending) {
        if let Some(state) = self.state.first_mut() {
            if pending.bootstrap {
                return;
            }
            if let Some(token) = pending.token {
                state.tracker.commit(
                    class,
                    Identity {
                        token,
                        lane: lane_number(pending.lane),
                        bytes: pending.bytes,
                        cost: pending.cost,
                        deadline: pending.deadline,
                    },
                    Instant::now(),
                );
            } else {
                state.tracker.mismatch();
            }
        }
    }
    pub(super) fn observe(
        &mut self,
        class: Class,
        lane: u8,
        token: raw::RecordToken,
        receipt: AcceptedReceipt,
    ) {
        if let Some(state) = self.state.first_mut() {
            state
                .tracker
                .observe(class, lane, token, receipt, Instant::now());
        }
    }
    pub(super) fn take(&mut self, class: Class, lane: u8, receipt: AcceptedReceipt) {
        if let Some(state) = self.state.first_mut() {
            state.tracker.take(class, lane, receipt, Instant::now());
        }
    }
    pub(super) fn finish(&mut self, now: Instant) {
        if let Some(state) = self.state.first_mut() {
            state.tracker.finish(now);
        }
    }
    #[cfg(test)]
    pub(super) fn for_test(path: PathBuf, now: Instant) -> io::Result<Self> {
        Self::at_path(path, now)
    }
}
impl Drop for Observer {
    fn drop(&mut self) {
        self.finish(Instant::now());
        let Some(state) = self.state.first() else {
            return;
        };
        let heap = self.state.capacity() * std::mem::size_of::<State>()
            + state.path.capacity()
            + state.temporary.capacity();
        let result = (|| {
            let file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&state.temporary)?;
            let mut writer = BufWriter::new(file);
            state.tracker.write(&mut writer, heap)?;
            writer.flush()?;
            writer.get_ref().sync_all()?;
            std::fs::rename(&state.temporary, &state.path)
        })();
        if let Err(error) = result {
            let _ = std::fs::remove_file(&state.temporary);
            eprintln!(
                "buffer metrics report failed: owner=raw_custody kind={:?}",
                error.kind()
            );
        }
    }
}

#[cfg(test)]
#[path = "raw_carrier_custody_tests.rs"]
mod tests;
