//! Opt-in bounded initialization and local-API timing; never deadline authority.
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
}

/// Mutually exclusive stage of one owner, using its original operation boundaries.
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
}

const STAGES: [Stage; 12] = [
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

#[derive(Clone, Copy, Debug, Default)]
struct Aggregate {
    samples: u64,
    sum_us: u64,
    max_us: u64,
    failed: u64,
    censored: u64,
}

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
    stages: [Aggregate; STAGES.len()],
    accepted: u64,
    replied: u64,
    request: Option<Instant>,
    request_duration: Aggregate,
    reports: u64,
    invalid: bool,
}

impl Timing {
    /// Opt in only with L2TUNNEL_INITIALIZATION_TIMING=1. At most 32 owners
    /// per process report. Allocation failure disables observation and never
    /// changes the original operation's result, deadline or protocol resources.
    pub fn from_environment(owner: Owner, origin: Instant) -> Self {
        if std::env::var_os("L2TUNNEL_INITIALIZATION_TIMING").is_none_or(|value| value != "1") {
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
        let Some(elapsed) = now.checked_duration_since(start) else {
            self.invalid = true;
            return;
        };
        let Ok(us) = u64::try_from(elapsed.as_micros()) else {
            self.invalid = true;
            return;
        };
        let aggregate = &mut self.stages[stage as usize];
        self.invalid |= add(&mut aggregate.samples, 1);
        self.invalid |= add(&mut aggregate.sum_us, us);
        aggregate.max_us = aggregate.max_us.max(us);
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
        let elapsed = now
            .checked_duration_since(self.origin)
            .and_then(|value| u64::try_from(value.as_micros()).ok());
        if elapsed.is_none() {
            self.invalid = true;
        }
        // Output is bounded, static-label/scalar-only and diagnostic. Failure
        // cannot change the original setup, request, result or timeout.
        let _written = (|| -> io::Result<()> {
            let mut out = io::stderr().lock();
            write!(
                out,
                "{{\"event\":\"initialization_timing\",\"schema\":1,\"owner\":\"{:?}\",\"id\":{},\"pid\":{},\"checkpoint\":\"{}\",\"elapsed_us\":{},\"invalid\":{},\"accepted\":{},\"replied\":{},\"inline_bytes\":{},\"diagnostic_heap_bytes\":{},\"stages\":[",
                self.owner,
                self.id,
                std::process::id(),
                event,
                elapsed.unwrap_or(0),
                self.invalid,
                self.accepted,
                self.replied,
                std::mem::size_of::<Timing>(),
                std::mem::size_of::<Self>()
            )?;
            for (index, stage) in STAGES.iter().enumerate() {
                if index != 0 {
                    write!(out, ",")?;
                }
                let value = self.stages[index];
                write!(
                    out,
                    "{{\"stage\":\"{stage:?}\",\"samples\":{},\"sum_us\":{},\"max_us\":{},\"failed\":{},\"censored\":{}}}",
                    value.samples, value.sum_us, value.max_us, value.failed, value.censored
                )?;
            }
            let value = self.request_duration;
            writeln!(
                out,
                "],\"accepted_to_completion\":{{\"samples\":{},\"sum_us\":{},\"max_us\":{},\"failed\":{},\"censored\":{}}}}}",
                value.samples, value.sum_us, value.max_us, value.failed, value.censored
            )
        })();
    }
}

impl Drop for State {
    fn drop(&mut self) {
        let now = Instant::now();
        self.end_request_at(now, Outcome::Censored);
        self.report_at("scope_end", now);
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
}
