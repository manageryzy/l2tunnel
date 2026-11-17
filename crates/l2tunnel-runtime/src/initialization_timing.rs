//! Opt-in bounded initialization, local-API and execution wall timing.
//! This observation never becomes deadline or scheduling authority.
//!
//! Samples use the caller's Tokio clock. A stage duration includes descheduling;
//! it is not CPU time. Idle accept waiting is deliberately not timed as backlog.
//! Counts identify unobserved stages; zero samples never mean a zero-cost stage.

use std::{
    io::{self, Write},
    sync::atomic::{AtomicU64, Ordering},
};
use tokio::time::Instant;

/// Diagnostic owner; no peer/session identity or request contents are logged.
#[derive(Clone, Copy, Debug)]
pub enum Owner {
    /// Actual post-authentication Common construction, shared by all carriers.
    CommonConstruction,
    /// Actual local API listener lifetime, including failed requests.
    LocalApi,
    /// Existing service readiness future, after actual construction returned.
    CommonReadiness,
    /// Actual Common runtime work; gaps also include intentional waits.
    CommonExecution,
    /// Foreground CLI projection, serialization and flush work.
    CliOutput,
    /// Actual independent regular-file writer, when that adapter is selected.
    CliWriter,
}

/// Original operation boundaries. Initialization's entered stages are disjoint;
/// explicitly measured execution spans may overlap (for example flush and write).
/// Never add these populations to infer CPU time or buffer-pressure duration.
#[derive(Clone, Copy, Debug)]
#[repr(usize)]
pub enum Stage {
    /// Contract and Records construction before bounded control planning.
    ContractAndRecords,
    /// Control and external-buffer plans, without their backing allocation.
    ControlAndExternalPlanning,
    /// Explicit Engine and Bank storage preflight before allocation.
    EngineAndBankPlanning,
    /// Optional diagnostic observers and auxiliary runtime buffers.
    AuxiliaryConstruction,
    /// Actual Bank constructor, including its repeated validation and allocation.
    BankConstruction,
    /// Current wire activation in the constructed Bank.
    BankActivation,
    /// Transaction state and its charged retained cell construction.
    TransactionConstruction,
    /// Final Driver/cell assembly, including the original finish callback.
    DriverAssembly,
    /// Accepted local socket: credential check and complete bounded request read.
    ApiRead,
    /// Actual request handler; includes scheduling while its future is pending.
    ApiHandler,
    /// Complete bounded response write and flush.
    ApiReply,
    /// Existing first-running poll future; includes all its pending intervals.
    FirstRunning,
    /// Consecutive turn-start spacing: includes idle I/O, scheduling and other owners.
    CommonTurnSpacing,
    /// Existing retained receipt processing and cooperative carrier progress.
    CommonReceiptProgress,
    /// Actual FIFO admission to current record owners.
    CommonAdmission,
    /// Ingress, native extraction, protocol progress and Rolling service work.
    CommonProtocolProgress,
    /// Actual management service and submission.
    CommonManagement,
    /// Actual selected send preparation and submission.
    CommonSend,
    /// Authenticated input processing after the original receive operation.
    CommonReceive,
    /// Actual one-shot carrier read/promotion, before authenticated processing.
    CommonCarrierReceive,
    /// Existing expiry/deadline servicing, with unchanged protocol ticks.
    CommonDeadlineService,
    /// Actual shared observation projection/publication callback.
    CommonSnapshot,
    /// Actual bounded native write service, including any scheduling.
    CommonNativeWrite,
    /// Actual bounded native read service.
    CommonNativeRead,
    /// Actual bounded diagnostic buffer sample collection.
    CommonBufferSampling,
    /// Current Common status to bounded JSON value projection.
    CliProjection,
    /// Current JSON value serialization, excluding its queue residence.
    CliEncoding,
    /// One original bounded foreground flush invocation.
    CliFlush,
    /// One actual file.write invocation, including successful writes.
    CliFileWrite,
}

const STAGES: [Stage; 29] = [
    Stage::ContractAndRecords,
    Stage::ControlAndExternalPlanning,
    Stage::EngineAndBankPlanning,
    Stage::AuxiliaryConstruction,
    Stage::BankConstruction,
    Stage::BankActivation,
    Stage::TransactionConstruction,
    Stage::DriverAssembly,
    Stage::ApiRead,
    Stage::ApiHandler,
    Stage::ApiReply,
    Stage::FirstRunning,
    Stage::CommonTurnSpacing,
    Stage::CommonReceiptProgress,
    Stage::CommonAdmission,
    Stage::CommonProtocolProgress,
    Stage::CommonManagement,
    Stage::CommonSend,
    Stage::CommonReceive,
    Stage::CommonCarrierReceive,
    Stage::CommonDeadlineService,
    Stage::CommonSnapshot,
    Stage::CommonNativeWrite,
    Stage::CommonNativeRead,
    Stage::CommonBufferSampling,
    Stage::CliProjection,
    Stage::CliEncoding,
    Stage::CliFlush,
    Stage::CliFileWrite,
];
const MAX_OWNERS: u64 = 32;
const MAX_REPORTS: u64 = 34;
static NEXT_OWNER: AtomicU64 = AtomicU64::new(1);

/// Known completion of the actual operation, without reclassifying its error.
#[derive(Clone, Copy, Debug)]
pub enum Outcome {
    /// The actual operation returned success.
    Complete,
    /// The actual operation returned a failure, including its existing timeout.
    Failed,
    /// Scope ended while an operation was active; cause is deliberately unknown.
    Censored,
}

/// Bounded scalar observation; no packet identity, contents or queue are retained.
#[derive(Clone, Copy, Debug, Default)]
pub struct Summary {
    /// Actual completed or terminal-censored measurement intervals.
    pub samples: u64,
    /// Sum within this population; overlapping populations must not be added.
    pub sum_us: u64,
    /// Largest observed interval, including scheduling delay.
    pub max_us: u64,
    /// Operations which returned an error, including an I/O WouldBlock result.
    pub failed: u64,
    /// Operations still active when this diagnostic scope ended.
    pub censored: u64,
    /// Start of the first maximum interval, relative to this owner's origin.
    pub maximum_start_us: Option<u64>,
    /// End of that same maximum interval; never subtract across owners.
    pub maximum_end_us: Option<u64>,
}
type Aggregate = Summary;

/// Opt-in, fallibly allocated diagnostics. Disabled state is three machine words
/// and has no heap allocation; aggregate arrays never live in an async future.
/// Diagnostic memory is separate from protocol quotas and is reported explicitly.
pub struct Timing {
    state: Vec<State>,
}

struct State {
    id: u64,
    owner: Owner,
    origin: Instant,
    active: Option<(Stage, Instant)>,
    previous_turn: Option<Instant>,
    report_on_drop: bool,
    stages: [Aggregate; STAGES.len()],
    accepted: u64,
    replied: u64,
    request: Option<Instant>,
    request_duration: Aggregate,
    reports: u64,
    invalid: bool,
}

impl Timing {
    /// Disabled observation with no allocation, environment access or output I/O.
    pub fn disabled() -> Self {
        Self { state: Vec::new() }
    }

    /// Initialization opts in with L2TUNNEL_INITIALIZATION_TIMING=1. Execution
    /// opts in with L2TUNNEL_EXECUTION_TIMING=1 or either existing buffer/wire
    /// diagnostic prefix. Automatic execution reports are terminal-only; the
    /// foreground CLI publishes snapshots through its existing queue, while
    /// CommonExecution transfers its frozen report to the buffer observer.
    /// At most 32 owners
    /// per process report. Allocation failure disables observation and never
    /// changes the original operation's result, deadline or protocol resources.
    pub fn from_environment(owner: Owner, origin: Instant) -> Self {
        if !environment_enabled(owner) {
            return Self { state: Vec::new() };
        }
        let id = NEXT_OWNER
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                (value <= MAX_OWNERS).then(|| value + 1)
            })
            .unwrap_or(0);
        if id == 0 {
            return Self { state: Vec::new() };
        }
        // Keep the enabled construction scratch out of the caller's future.
        let state = allocate_state(id, owner, origin);
        if state.is_empty() {
            let _written = writeln!(
                io::stderr().lock(),
                "{{\"event\":\"initialization_timing_unavailable\",\"schema\":1,\"owner\":\"{owner:?}\",\"id\":{id},\"pid\":{},\"reason\":\"diagnostic_allocation\"}}",
                std::process::id()
            );
        }
        Self { state }
    }

    /// Apply environment opt-in without writing allocation or owner-limit errors
    /// to any output stream. The caller retains diagnostic unavailability through
    /// its existing bounded health/output mechanism; forwarding is unchanged.
    pub fn try_from_environment(owner: Owner, origin: Instant) -> io::Result<Self> {
        if environment_enabled(owner) {
            Self::try_new(owner, origin)
        } else {
            Ok(Self { state: Vec::new() })
        }
    }

    /// Explicit opt-in for an embedding runtime or an actual-owner fixture.
    /// Allocation and owner-limit failures are diagnostic errors only.
    pub fn try_new(owner: Owner, origin: Instant) -> io::Result<Self> {
        let id = NEXT_OWNER
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                (value <= MAX_OWNERS).then(|| value + 1)
            })
            .map_err(|_| io::Error::other("timing owner bound"))?;
        let state = allocate_state(id, owner, origin);
        if state.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::OutOfMemory,
                "timing allocation",
            ));
        }
        Ok(Self { state })
    }

    /// Disabled observation never reads the clock on a work or packet path.
    pub fn start(&self) -> Option<Instant> {
        (!self.state.is_empty()).then(Instant::now)
    }

    /// Snapshot without extrapolating an open operation or reading a clock.
    pub fn snapshot(&self, stage: Stage) -> Option<Summary> {
        self.state.first().map(|state| state.stages[stage as usize])
    }

    /// Record an already finished actual interval using this owner's clock.
    /// This can overlap other named spans; it is never a blocked-time union.
    pub fn record_span_at(&mut self, stage: Stage, start: Instant, end: Instant, outcome: Outcome) {
        if let Some(state) = self.state.first_mut() {
            state.record_span_at(stage, start, end, outcome);
        }
    }

    /// Complete a conditional start token. A disabled token never reads a clock.
    pub fn record_since(&mut self, stage: Stage, start: Option<Instant>, outcome: Outcome) {
        if let Some(start) = start {
            self.record_span_at(stage, start, Instant::now(), outcome);
        }
    }

    /// Observe a synchronous operation without changing its return value.
    pub fn measure_result<T, E>(
        &mut self,
        stage: Stage,
        operation: impl FnOnce() -> Result<T, E>,
    ) -> Result<T, E> {
        let start = self.start();
        let result = operation();
        self.record_since(
            stage,
            start,
            if result.is_ok() {
                Outcome::Complete
            } else {
                Outcome::Failed
            },
        );
        result
    }

    /// Observe an existing bounded future. Pending time includes descheduling,
    /// not necessarily backpressure. Drop censors the active entered interval.
    pub async fn measure_future<T, E>(
        &mut self,
        stage: Stage,
        operation: impl std::future::Future<Output = Result<T, E>>,
    ) -> Result<T, E> {
        if let Some(start) = self.start() {
            self.enter_at(stage, start);
        }
        let result = operation.await;
        if let Some(end) = self.start() {
            self.end_at(
                end,
                if result.is_ok() {
                    Outcome::Complete
                } else {
                    Outcome::Failed
                },
            );
        }
        result
    }

    /// Consecutive actual turn starts. An idle sleep, carrier wait or delayed
    /// polling by another parent branch is included; none is inferred as CPU.
    pub fn turn(&mut self) {
        let Some(now) = self.start() else {
            return;
        };
        if let Some(state) = self.state.first_mut()
            && let Some(previous) = state.previous_turn.replace(now)
        {
            state.record_span_at(Stage::CommonTurnSpacing, previous, now, Outcome::Complete);
        }
    }

    /// Serialize bounded current scalars into caller-owned output only. No file,
    /// lock, socket, allocation, active-span extrapolation or clock read occurs.
    /// Repeated renderings are snapshots, not independent work samples.
    pub fn write_snapshot_at(&mut self, now: Instant, output: &mut impl Write) -> io::Result<bool> {
        let Some(state) = self.state.first_mut() else {
            return Ok(false);
        };
        state.write_report_at("snapshot", now, output)?;
        Ok(true)
    }

    /// Finish/censor diagnostics and render into the caller's existing bounded
    /// output custody. Drop will not attempt another report. Output failure never
    /// changes the original owner; the caller records any omitted final report.
    pub fn write_terminal_at(&mut self, now: Instant, output: &mut impl Write) -> io::Result<bool> {
        let Some(state) = self.state.first_mut() else {
            return Ok(false);
        };
        state.report_on_drop = false;
        state.end_request_at(now, Outcome::Censored);
        state.write_report_at("scope_end", now, output)?;
        Ok(true)
    }

    /// Move the prepaid owner into terminal export custody without output I/O.
    /// The injected stop excludes settlement, rendering and persistence time.
    pub(crate) fn freeze_at(mut self, now: Instant) -> FrozenTiming {
        if let Some(state) = self.state.first_mut() {
            state.report_on_drop = false;
            state.end_request_at(now, Outcome::Censored);
        }
        FrozenTiming {
            timing: self,
            at: now,
        }
    }

    /// Finish the preceding successful stage and begin the next at this instant.
    pub fn enter_at(&mut self, stage: Stage, now: Instant) {
        if let Some(state) = self.state.first_mut() {
            state.enter_at(stage, now);
        }
    }

    /// Close an active stage using the actual result and existing clock.
    pub fn end_at(&mut self, now: Instant, outcome: Outcome) {
        if let Some(state) = self.state.first_mut() {
            state.end_at(now, outcome);
        }
    }

    /// Mark actual listener acceptance, excluding earlier Unix backlog time.
    pub fn accepted_at(&mut self, now: Instant) {
        if let Some(state) = self.state.first_mut() {
            state.accepted_at(now);
        }
    }

    /// Count only a response whose original write/flush future succeeded.
    pub fn replied_at(&mut self, now: Instant, success: bool) {
        if let Some(state) = self.state.first_mut() {
            state.replied_at(now, success);
        }
    }

    /// Close the complete accepted request without adding a time limit.
    pub fn end_request_at(&mut self, now: Instant, outcome: Outcome) {
        if let Some(state) = self.state.first_mut() {
            state.end_request_at(now, outcome);
        }
    }
}

/// A moved diagnostic owner with an immutable measurement cutoff. No new
/// allocation, packet state or protocol authority is introduced by this owner.
pub(crate) struct FrozenTiming {
    timing: Timing,
    at: Instant,
}
impl FrozenTiming {
    pub(crate) fn enabled(&self) -> bool {
        !self.timing.state.is_empty()
    }
    pub(crate) fn heap_bytes(&self) -> usize {
        self.timing.state.capacity() * std::mem::size_of::<State>()
    }
    pub(crate) fn write(&self, output: &mut impl Write) -> io::Result<()> {
        if let Some(state) = self.timing.state.first() {
            state.write_report_ref_at("loop_stop", self.at, output)
        } else {
            write!(output, "null")
        }
    }
}

#[inline(never)]
fn allocate_state(id: u64, owner: Owner, origin: Instant) -> Vec<State> {
    let mut state = Vec::new();
    if state.try_reserve_exact(1).is_err() || state.capacity() != 1 {
        return Vec::new();
    }
    state.push(State {
        id,
        owner,
        origin,
        active: None,
        previous_turn: None,
        report_on_drop: !matches!(owner, Owner::CliOutput | Owner::CommonExecution),
        stages: [Aggregate::default(); STAGES.len()],
        accepted: 0,
        replied: 0,
        request: None,
        request_duration: Aggregate::default(),
        reports: 0,
        invalid: false,
    });
    state
}

impl State {
    /// Finish the preceding successful stage and begin the next at this instant.
    pub fn enter_at(&mut self, stage: Stage, now: Instant) {
        self.end_at(now, Outcome::Complete);
        self.active = Some((stage, now));
    }

    /// Close an active stage with the actual result; no new time bound is created.
    pub fn end_at(&mut self, now: Instant, outcome: Outcome) {
        let Some((stage, start)) = self.active.take() else {
            return;
        };
        self.record_span_at(stage, start, now, outcome);
    }

    fn record_span_at(&mut self, stage: Stage, start: Instant, end: Instant, outcome: Outcome) {
        let times = start
            .checked_duration_since(self.origin)
            .zip(end.checked_duration_since(self.origin))
            .and_then(|(start, end)| {
                Some((
                    u64::try_from(start.as_micros()).ok()?,
                    u64::try_from(end.as_micros()).ok()?,
                ))
            });
        let Some((start_us, end_us)) = times else {
            self.invalid = true;
            return;
        };
        let Some(us) = end
            .checked_duration_since(start)
            .and_then(|value| u64::try_from(value.as_micros()).ok())
        else {
            self.invalid = true;
            return;
        };
        let aggregate = &mut self.stages[stage as usize];
        if aggregate.samples == 0 || us > aggregate.max_us {
            aggregate.max_us = us;
            aggregate.maximum_start_us = Some(start_us);
            aggregate.maximum_end_us = Some(end_us);
        }
        self.invalid |= add(&mut aggregate.samples, 1);
        self.invalid |= add(&mut aggregate.sum_us, us);
        match outcome {
            Outcome::Complete => {}
            Outcome::Failed => self.invalid |= add(&mut aggregate.failed, 1),
            Outcome::Censored => self.invalid |= add(&mut aggregate.censored, 1),
        }
    }

    /// Mark an actual accepted local socket. This is not its peer's send time.
    pub fn accepted_at(&mut self, now: Instant) {
        self.invalid |= add(&mut self.accepted, 1);
        self.request = Some(now);
        self.enter_at(Stage::ApiRead, now);
        if checkpoint(self.accepted) {
            self.report_at("accepted", now);
        }
    }

    /// Count only a response whose original write/flush future succeeded.
    pub fn replied_at(&mut self, now: Instant, success: bool) {
        self.end_request_at(
            now,
            if success {
                Outcome::Complete
            } else {
                Outcome::Failed
            },
        );
        if success {
            self.invalid |= add(&mut self.replied, 1);
        }
        if checkpoint(self.accepted) {
            self.report_at("reply", now);
        }
    }

    /// Complete or censor the original accepted-to-completion interval. This
    /// overlaps its read/handler/reply stages and must not be added to their sum.
    pub fn end_request_at(&mut self, now: Instant, outcome: Outcome) {
        self.end_at(now, outcome);
        let Some(start) = self.request.take() else {
            return;
        };
        let Some(elapsed) = now
            .checked_duration_since(start)
            .and_then(|value| u64::try_from(value.as_micros()).ok())
        else {
            self.invalid = true;
            return;
        };
        self.invalid |= add(&mut self.request_duration.samples, 1);
        self.invalid |= add(&mut self.request_duration.sum_us, elapsed);
        self.request_duration.max_us = self.request_duration.max_us.max(elapsed);
        match outcome {
            Outcome::Complete => {}
            Outcome::Failed => self.invalid |= add(&mut self.request_duration.failed, 1),
            Outcome::Censored => self.invalid |= add(&mut self.request_duration.censored, 1),
        }
        // A killed CLI can leave a failed request outside a sparse checkpoint.
        // Preserve that evidence within the same fixed owner report budget.
        if matches!(outcome, Outcome::Failed) && !checkpoint(self.accepted) {
            self.report_at("request_failed", now);
        }
    }

    /// One bounded cumulative report. Sparse API checkpoints stop after 32768
    /// accepts; the final report still includes subsequent aggregate counts.
    fn report_at(&mut self, event: &'static str, now: Instant) {
        if self.reports >= MAX_REPORTS {
            return;
        }
        self.reports += 1;
        let _written = self.write_report_at(event, now, &mut io::stderr().lock());
    }

    fn write_report_at(
        &mut self,
        event: &'static str,
        now: Instant,
        out: &mut impl Write,
    ) -> io::Result<()> {
        let elapsed = now
            .checked_duration_since(self.origin)
            .and_then(|value| u64::try_from(value.as_micros()).ok());
        if elapsed.is_none() {
            self.invalid = true;
        }
        self.write_report_ref_at(event, now, out)
    }

    fn write_report_ref_at(
        &self,
        event: &'static str,
        now: Instant,
        out: &mut impl Write,
    ) -> io::Result<()> {
        let elapsed = now
            .checked_duration_since(self.origin)
            .and_then(|value| u64::try_from(value.as_micros()).ok());
        write!(
            out,
            "{{\"event\":\"{}\",\"schema\":1,\"owner\":\"{:?}\",\"id\":{},\"pid\":{},\"checkpoint\":\"{}\",\"definition\":\"owner-local wall durations; includes descheduling; overlapping stages and turn spacing are not CPU or blocked time\",\"elapsed_us\":{},\"invalid\":{},\"accepted\":{},\"replied\":{},\"inline_bytes\":{},\"diagnostic_heap_bytes\":{},\"stages\":[",
            if execution_owner(self.owner) {
                "execution_timing"
            } else {
                "initialization_timing"
            },
            self.owner,
            self.id,
            std::process::id(),
            event,
            elapsed.unwrap_or(0),
            self.invalid || elapsed.is_none(),
            self.accepted,
            self.replied,
            std::mem::size_of::<Timing>(),
            std::mem::size_of::<Self>()
        )?;
        let stages = if execution_owner(self.owner) {
            &STAGES[12..]
        } else {
            &STAGES[..12]
        };
        for (index, stage) in stages.iter().enumerate() {
            if index != 0 {
                write!(out, ",")?;
            }
            let value = self.stages[*stage as usize];
            write!(
                out,
                "{{\"stage\":\"{stage:?}\",\"samples\":{},\"sum_us\":{},\"max_us\":{},\"failed\":{},\"censored\":{}",
                value.samples, value.sum_us, value.max_us, value.failed, value.censored
            )?;
            write!(out, ",\"maximum_start_us\":")?;
            optional_us(out, value.maximum_start_us)?;
            write!(out, ",\"maximum_end_us\":")?;
            optional_us(out, value.maximum_end_us)?;
            write!(out, "}}")?;
        }
        let value = self.request_duration;
        writeln!(
            out,
            "],\"accepted_to_completion\":{{\"samples\":{},\"sum_us\":{},\"max_us\":{},\"failed\":{},\"censored\":{}}}}}",
            value.samples, value.sum_us, value.max_us, value.failed, value.censored
        )
    }
}

impl Drop for State {
    fn drop(&mut self) {
        let now = Instant::now();
        self.end_request_at(now, Outcome::Censored);
        if self.report_on_drop {
            self.report_at("scope_end", now);
        }
    }
}

fn environment_enabled(owner: Owner) -> bool {
    if execution_owner(owner) {
        std::env::var_os("L2TUNNEL_EXECUTION_TIMING").is_some_and(|value| value == "1")
            || std::env::var_os("L2TUNNEL_BUFFER_METRICS").is_some()
            || std::env::var_os("L2TUNNEL_WIRE_METRICS").is_some()
    } else {
        std::env::var_os("L2TUNNEL_INITIALIZATION_TIMING").is_some_and(|value| value == "1")
    }
}

fn execution_owner(owner: Owner) -> bool {
    matches!(
        owner,
        Owner::CommonExecution | Owner::CliOutput | Owner::CliWriter
    )
}

fn optional_us(out: &mut impl Write, value: Option<u64>) -> io::Result<()> {
    match value {
        Some(value) => write!(out, "{value}"),
        None => write!(out, "null"),
    }
}

fn add(value: &mut u64, increment: u64) -> bool {
    match value.checked_add(increment) {
        Some(next) => {
            *value = next;
            false
        }
        None => {
            *value = u64::MAX;
            true
        }
    }
}
fn checkpoint(value: u64) -> bool {
    value <= 32_768 && value.is_power_of_two()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn disabled_timing_retains_no_aggregate_array_or_heap() {
        let mut value = Timing { state: Vec::new() };
        assert_eq!(
            std::mem::size_of::<Timing>(),
            3 * std::mem::size_of::<usize>()
        );
        assert_eq!(value.state.capacity(), 0);
        assert!(value.start().is_none());
        assert!(value.snapshot(Stage::CommonSend).is_none());
        value.turn();
        assert_eq!(
            value.measure_result(Stage::CommonSend, || Ok::<_, ()>(7)),
            Ok(7)
        );
        let now = Instant::now();
        value.accepted_at(now);
        value.enter_at(Stage::ApiHandler, now);
        value.replied_at(now, true);
        assert!(value.state.is_empty());
        assert_eq!(value.state.capacity(), 0);
    }

    #[test]
    fn stages_are_disjoint_and_failed_or_censored_work_is_not_success() {
        let origin = Instant::now();
        let mut value = State {
            id: 1,
            owner: Owner::LocalApi,
            origin,
            active: None,
            previous_turn: None,
            report_on_drop: false,
            stages: [Aggregate::default(); STAGES.len()],
            accepted: 0,
            replied: 0,
            request: None,
            request_duration: Aggregate::default(),
            reports: MAX_REPORTS,
            invalid: false,
        };
        value.enter_at(Stage::ApiRead, origin);
        value.enter_at(Stage::ApiHandler, origin + Duration::from_micros(7));
        value.end_at(origin + Duration::from_micros(20), Outcome::Failed);
        assert_eq!(value.stages[Stage::ApiRead as usize].sum_us, 7);
        assert_eq!(value.stages[Stage::ApiHandler as usize].sum_us, 13);
        assert_eq!(value.stages[Stage::ApiHandler as usize].failed, 1);
        assert_eq!(value.stages[Stage::ApiReply as usize].samples, 0);
        value.enter_at(Stage::ApiRead, origin + Duration::from_micros(30));
        value.end_at(origin + Duration::from_micros(40), Outcome::Censored);
        assert_eq!(value.stages[Stage::ApiRead as usize].censored, 1);
        assert_eq!(value.stages[Stage::ApiRead as usize].samples, 2);
        assert_eq!(value.stages[Stage::ApiRead as usize].max_us, 10);
    }

    #[test]
    fn accepted_interval_is_counted_once_and_does_not_include_idle_listener_time() {
        let origin = Instant::now();
        let mut value = State {
            id: 1,
            owner: Owner::LocalApi,
            origin,
            active: None,
            previous_turn: None,
            report_on_drop: false,
            stages: [Aggregate::default(); STAGES.len()],
            accepted: 0,
            replied: 0,
            request: None,
            request_duration: Aggregate::default(),
            reports: MAX_REPORTS,
            invalid: false,
        };
        value.accepted_at(origin + Duration::from_secs(10));
        value.enter_at(
            Stage::ApiHandler,
            origin + Duration::from_micros(10_000_002),
        );
        value.enter_at(Stage::ApiReply, origin + Duration::from_micros(10_000_012));
        value.replied_at(origin + Duration::from_micros(10_000_015), true);
        assert_eq!(value.accepted, 1);
        assert_eq!(value.replied, 1);
        assert_eq!(value.request_duration.samples, 1);
        assert_eq!(value.request_duration.sum_us, 15);
        assert_eq!(value.request_duration.max_us, 15);
        value.end_request_at(origin + Duration::from_secs(11), Outcome::Censored);
        assert_eq!(value.request_duration.samples, 1);
        value.accepted_at(origin + Duration::from_secs(12));
        value.end_request_at(origin + Duration::from_micros(12_000_005), Outcome::Failed);
        assert_eq!(value.accepted, 2);
        assert_eq!(value.replied, 1);
        assert_eq!(value.request_duration.samples, 2);
        assert_eq!(value.request_duration.sum_us, 20);
        assert_eq!(value.request_duration.failed, 1);
    }
    #[test]
    fn execution_intervals_preserve_success_error_overlap_and_maximum_identity() -> io::Result<()> {
        let origin = Instant::now();
        let mut timing = Timing::try_new(Owner::CliOutput, origin)?;
        timing.state[0].reports = MAX_REPORTS;
        let us = |value| origin + Duration::from_micros(value);
        timing.record_span_at(Stage::CliFlush, us(10), us(90), Outcome::Complete);
        timing.record_span_at(Stage::CliFileWrite, us(20), us(70), Outcome::Complete);
        timing.record_span_at(Stage::CliFileWrite, us(75), us(80), Outcome::Failed);
        let writes = timing
            .snapshot(Stage::CliFileWrite)
            .ok_or_else(|| io::Error::other("enabled observer"))?;
        assert_eq!(
            (writes.samples, writes.sum_us, writes.max_us, writes.failed),
            (2, 55, 50, 1)
        );
        assert_eq!(
            (writes.maximum_start_us, writes.maximum_end_us),
            (Some(20), Some(70))
        );
        assert_eq!(
            timing
                .snapshot(Stage::CliFlush)
                .ok_or_else(|| io::Error::other("enabled"))?
                .sum_us,
            80
        );
        timing.record_span_at(Stage::CliFileWrite, us(100), us(99), Outcome::Complete);
        assert!(timing.state[0].invalid);
        assert_eq!(
            timing
                .snapshot(Stage::CliFileWrite)
                .ok_or_else(|| io::Error::other("enabled"))?
                .samples,
            2
        );
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn execution_cancelled_existing_future_is_censored_at_terminal_fallback() -> io::Result<()>
    {
        let origin = Instant::now();
        let mut timing = Timing::try_new(Owner::CommonExecution, origin)?;
        assert!(!timing.state[0].report_on_drop);
        timing.state[0].reports = MAX_REPORTS;
        {
            let pending = timing.measure_future(
                Stage::CommonNativeWrite,
                std::future::pending::<io::Result<()>>(),
            );
            tokio::pin!(pending);
            tokio::select! {
                biased;
                _ = &mut pending => return Err(io::Error::other("pending operation completed")),
                () = std::future::ready(()) => {},
            }
            tokio::time::advance(Duration::from_micros(11)).await;
        }
        assert_eq!(
            timing
                .snapshot(Stage::CommonNativeWrite)
                .ok_or_else(|| io::Error::other("enabled"))?
                .samples,
            0
        );
        // This is the exact fallback called by State::drop, with an injected tick.
        timing.state[0].end_request_at(Instant::now(), Outcome::Censored);
        let stopped = timing
            .snapshot(Stage::CommonNativeWrite)
            .ok_or_else(|| io::Error::other("enabled"))?;
        assert_eq!(
            (stopped.samples, stopped.censored, stopped.sum_us),
            (1, 1, 11)
        );
        timing.state[0].end_request_at(Instant::now(), Outcome::Censored);
        assert_eq!(
            timing
                .snapshot(Stage::CommonNativeWrite)
                .ok_or_else(|| io::Error::other("enabled"))?
                .samples,
            1
        );
        Ok(())
    }

    #[test]
    fn execution_terminal_render_censors_once_and_suppresses_synchronous_drop_export()
    -> io::Result<()> {
        let origin = Instant::now();
        let mut timing = Timing::try_new(Owner::CliOutput, origin)?;
        assert!(!timing.state[0].report_on_drop);
        timing.enter_at(Stage::CliEncoding, origin + Duration::from_micros(5));
        let mut output = Vec::new();
        assert!(timing.write_terminal_at(origin + Duration::from_micros(19), &mut output)?);
        let document: serde_json::Value = serde_json::from_slice(&output)?;
        assert_eq!(document["event"], "execution_timing");
        assert_eq!(document["checkpoint"], "scope_end");
        let stage = document["stages"]
            .as_array()
            .ok_or_else(|| io::Error::other("stages"))?
            .iter()
            .find(|stage| stage["stage"] == "CliEncoding")
            .ok_or_else(|| io::Error::other("encoding stage"))?;
        assert_eq!(stage["samples"], 1);
        assert_eq!(stage["censored"], 1);
        assert_eq!(stage["max_us"], 14);
        assert_eq!(stage["maximum_start_us"], 5);
        assert_eq!(stage["maximum_end_us"], 19);
        assert!(!timing.state[0].report_on_drop);
        output.clear();
        assert!(timing.write_terminal_at(origin + Duration::from_micros(20), &mut output)?);
        assert_eq!(
            timing
                .snapshot(Stage::CliEncoding)
                .ok_or_else(|| io::Error::other("enabled"))?
                .samples,
            1
        );
        Ok(())
    }
}
