//! Pure future-target planning against authoritative, irrevocable relay grants.
//!
//! Feedback/demand are caller assertions in this first slice, not measured or
//! authenticated evidence. Plans neither grant bytes nor change native TCP rings.
//! The actual table poll and reliable/native handoffs remain separate owners.
use crate::{Window, session};
use l2tunnel_flow_control::{Credit, FlowId, target};
use std::{fmt, sync::Arc};

/// Injected monotonic time and existing bounded candidate-policy inputs.
pub use target::{Feedback, Micros, TargetConfig, TargetState};

/// Immutable allocation policy; observation transport is deliberately absent.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Config {
    /// Existing aggregate target policy and hard receiver reservation cap.
    pub target: TargetConfig,
    /// Positive active-flow floor, able to admit one complete maximum record.
    pub minimum_per_flow: Window,
}
impl Config {
    /// Check against the actual table's validated policy, before any allocation.
    pub fn validate(self, table: &session::Table) -> Result<(), Error> {
        let policy = table.policy();
        target::TargetController::new(self.target, Micros(0))?;
        let cap = window(self.target.session_cap);
        if self.target.max_flows != policy.max_flows
            || self.minimum_per_flow.bytes < policy.max_record_bytes as u64
            || self.minimum_per_flow.records == 0
            || !fits(self.minimum_per_flow, policy.initial)
            || !fits(policy.initial, window(self.target.per_flow_cap))
            || !fits(window(self.target.per_flow_cap), policy.maximum)
            || !fits(self.minimum_per_flow, window(self.target.minimum))
            || !fits(multiply(policy.initial, policy.max_flows)?, cap)
            || !fits(cap, multiply(policy.maximum, policy.max_flows)?)
        {
            return Err(Error::Configuration);
        }
        Ok(())
    }
}

/// Immutable flow weight from the embedding authenticated QoS policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FlowWeight {
    /// Table's lifetime, nonreused flow ID.
    pub flow: u64,
    /// Shared QoS multiplier, in 1..=16.
    pub weight: u16,
}
/// One active flow's desired future target and required reservation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FlowTarget {
    /// Existing active table owner.
    pub flow: u64,
    /// Future target, not a cumulative grant or native advertised window.
    pub target: Window,
    /// Componentwise max of outstanding grant debt and future target.
    pub reserved: Window,
}
/// Finite allocation result; no data or memory has been released by this value.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Applied {
    /// Applied planner revision, including immutable weight registration.
    pub revision: u64,
    /// Candidate total for demanding flows before reservations constrain it.
    pub candidate: Window,
    /// Total future/issued reservation including every lifetime slot.
    pub reserved: Window,
    /// Unallocated and Opening slots' initial reservations.
    pub opening_reserved: Window,
    /// Frozen terminal reservations, retained until session close.
    pub terminal_reserved: Window,
    /// Existing candidate policy phase, not a native TCP state.
    pub state: TargetState,
    /// Exactly one row per active flow, in ascending lifetime ID order.
    pub flows: Vec<FlowTarget>,
}
/// Read-only local history, useful for distinguishing planning from commit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PlannerStatus {
    /// Changes only after successful weight registration or complete plan apply.
    pub revision: u64,
    /// Last successfully applied logical time (or construction time).
    pub applied_at: Micros,
    /// Weighted remainder cursor; rotates at most once per caller-supplied RTT.
    pub remainder_cursor: usize,
}
/// Explicit rejected input, stale ownership, overflow or invariant failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// Policy, timing, weight or bounds are inconsistent.
    Configuration,
    /// Unknown, duplicate, nonactive or unbound demanding flow.
    Flow,
    /// A different table/planner owns this operation, even with copied scopes.
    Owner,
    /// A plan revision, relevant table snapshot or logical apply time changed.
    StalePlan,
    /// Injected time regressed or precedes actual table time.
    Time,
    /// Checked counters or products cannot be represented.
    Exhausted,
    /// Actual issued/target debt exceeds the configured hard reservation cap.
    Capacity,
    /// Authoritative cumulative offsets or allocator invariants disagree.
    Accounting,
    /// Existing candidate policy rejected an input.
    Target(target::TargetError),
    /// Actual table batch validation failed before mutation.
    Table(session::Error),
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "proxy target planner: {self:?}")
    }
}
impl std::error::Error for Error {}
impl From<target::TargetError> for Error {
    fn from(value: target::TargetError) -> Self {
        Self::Target(value)
    }
}
impl From<session::Error> for Error {
    fn from(value: session::Error) -> Self {
        Self::Table(value)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Row {
    status: session::FlowStatus,
    credit: Option<session::CreditSnapshot>,
}
#[derive(Clone, Debug, Eq, PartialEq)]
struct Snapshot {
    table_time: crate::Millis,
    rows: Vec<Row>,
}
/// Opaque bounded candidate, bound to one planner, table snapshot and logical time.
/// Preparing multiple plans retains caller-owned bounded copies; only one current
/// revision may commit. Dropping a plan changes no state.
pub struct Plan {
    owner: Arc<()>,
    revision: u64,
    at: Micros,
    snapshot: Snapshot,
    controller: target::TargetController,
    rotation_at: Micros,
    result: Applied,
    cursor: usize,
}
impl Plan {
    /// Inspect the proposal without acquiring grant or native-window authority.
    pub fn allocation(&self) -> &Applied {
        &self.result
    }
}
/// Exclusive pure policy owner for one actual table's incoming relay direction.
/// It does not collect measurements, authenticate peers or drive the table.
pub struct Planner {
    config: Config,
    policy: session::Config,
    table: Arc<()>,
    owner: Arc<()>,
    controller: target::TargetController,
    weights: Vec<Option<u16>>,
    status: PlannerStatus,
    rotation_at: Micros,
}
impl Planner {
    /// Bind immutable policy and actual table identity; include already terminal debt.
    pub fn new(config: Config, table: &session::Table, now: Micros) -> Result<Self, Error> {
        config.validate(table)?;
        let value = Self {
            config,
            policy: table.policy(),
            table: table.target_identity().clone(),
            owner: Arc::new(()),
            controller: target::TargetController::new(config.target, now)?,
            weights: vec![None; table.policy().max_flows],
            status: PlannerStatus {
                revision: 0,
                applied_at: now,
                remainder_cursor: 0,
            },
            rotation_at: now,
        };
        let snapshot = value.snapshot(table)?;
        value.check_time(&snapshot, now)?;
        let mut reserved = multiply(
            value.policy.initial,
            value.policy.max_flows - snapshot.rows.len(),
        )?;
        for row in &snapshot.rows {
            reserved = add(reserved, value.current_reservation(row)?)?;
        }
        if !fits(reserved, window(config.target.session_cap)) {
            return Err(Error::Capacity);
        }
        Ok(value)
    }
    /// Register a fixed policy weight for a lifetime slot; identical retries are no-ops.
    pub fn bind_flow(&mut self, flow: FlowWeight) -> Result<(), Error> {
        let index = flow
            .flow
            .checked_sub(1)
            .and_then(|n| usize::try_from(n).ok())
            .filter(|i| *i < self.weights.len())
            .ok_or(Error::Flow)?;
        if !(1..=16).contains(&flow.weight) {
            return Err(Error::Configuration);
        }
        if let Some(previous) = self.weights[index] {
            return if previous == flow.weight {
                Ok(())
            } else {
                Err(Error::Flow)
            };
        }
        let revision = self
            .status
            .revision
            .checked_add(1)
            .ok_or(Error::Exhausted)?;
        self.weights[index] = Some(flow.weight);
        self.status.revision = revision;
        Ok(())
    }
    /// Inspect committed history; preparing or rejecting a plan does not advance it.
    pub const fn status(&self) -> PlannerStatus {
        self.status
    }
    /// Plan using caller-supplied policy inputs, without claiming measured evidence.
    /// Demand is a distinct bounded active-ID set. All active flows need fixed weights.
    pub fn prepare(
        &self,
        table: &session::Table,
        feedback: Feedback,
        demanding: &[u64],
        now: Micros,
    ) -> Result<Plan, Error> {
        let snapshot = self.snapshot(table)?;
        self.check_time(&snapshot, now)?;
        if demanding.len() > self.policy.max_flows {
            return Err(Error::Flow);
        }
        if !fits(
            window(feedback.in_flight),
            window(self.config.target.session_cap),
        ) {
            return Err(Error::Capacity);
        }
        let mut demand = demanding.to_vec();
        demand.sort_unstable();
        if demand.windows(2).any(|v| v[0] == v[1]) {
            return Err(Error::Flow);
        }
        for id in &demand {
            if !snapshot
                .rows
                .iter()
                .any(|row| row.status.id == *id && row.status.phase == session::FlowPhase::Active)
            {
                return Err(Error::Flow);
            }
        }
        let next_revision = self
            .status
            .revision
            .checked_add(1)
            .ok_or(Error::Exhausted)?;
        let mut controller = self.controller.clone();
        let candidate = controller.update(
            now,
            feedback,
            &demand.iter().copied().map(FlowId).collect::<Vec<_>>(),
        )?;
        let mut cursor = self.status.remainder_cursor;
        let mut rotation_at = self.rotation_at;
        if feedback
            .rtt_micros
            .is_some_and(|rtt| now.0 - rotation_at.0 >= rtt)
        {
            cursor = (cursor + 1) % self.policy.max_flows;
            rotation_at = now;
        }
        let mut opening = multiply(
            self.policy.initial,
            self.policy.max_flows - snapshot.rows.len(),
        )?;
        let mut terminal = Window::default();
        let mut flows = Vec::with_capacity(snapshot.rows.len());
        let mut weights = Vec::with_capacity(snapshot.rows.len());
        for row in &snapshot.rows {
            match row.status.phase {
                session::FlowPhase::Active => {
                    let weight = self.weights[row.status.id as usize - 1].ok_or(Error::Flow)?;
                    let debt = debt(row.credit.ok_or(Error::Accounting)?, self.policy.maximum)?;
                    flows.push(FlowTarget {
                        flow: row.status.id,
                        target: self.config.minimum_per_flow,
                        reserved: maximum(debt, self.config.minimum_per_flow),
                    });
                    weights.push(if demand.binary_search(&row.status.id).is_ok() {
                        weight
                    } else {
                        0
                    });
                }
                session::FlowPhase::Opening(_) => opening = add(opening, self.policy.initial)?,
                _ => terminal = add(terminal, self.current_reservation(row)?)?,
            }
        }
        let fixed = add(opening, terminal)?;
        let cap = window(self.config.target.session_cap);
        for bytes in [true, false] {
            let floor = component(self.config.minimum_per_flow, bytes);
            let per_flow = component(window(self.config.target.per_flow_cap), bytes);
            let mut desired = vec![floor; flows.len()];
            let ceilings: Vec<_> = weights
                .iter()
                .map(|w| if *w == 0 { floor } else { per_flow })
                .collect();
            let demanding_floor = floor
                .checked_mul(demand.len() as u64)
                .ok_or(Error::Exhausted)?;
            let amount =
                component(window(candidate.total()), bytes).saturating_sub(demanding_floor);
            fill(&mut desired, &ceilings, &weights, amount, cursor)?;
            // Targets below already issued debt cost no additional reservation.
            let mut actual: Vec<_> = flows
                .iter()
                .zip(&desired)
                .map(|(f, want)| (*want).min(component(f.reserved, bytes)))
                .collect();
            let used = flows.iter().try_fold(component(fixed, bytes), |sum, f| {
                sum.checked_add(component(f.reserved, bytes))
                    .ok_or(Error::Exhausted)
            })?;
            let room = component(cap, bytes)
                .checked_sub(used)
                .ok_or(Error::Capacity)?;
            fill(&mut actual, &desired, &weights, room, cursor)?;
            for (flow, value) in flows.iter_mut().zip(actual) {
                set_component(&mut flow.target, bytes, value);
                let reservation = component(flow.reserved, bytes).max(value);
                set_component(&mut flow.reserved, bytes, reservation);
            }
        }
        let reserved = flows
            .iter()
            .try_fold(fixed, |sum, f| add(sum, f.reserved))?;
        if !fits(reserved, cap) {
            return Err(Error::Accounting);
        }
        Ok(Plan {
            owner: self.owner.clone(),
            revision: self.status.revision,
            at: now,
            snapshot,
            controller,
            rotation_at,
            cursor,
            result: Applied {
                revision: next_revision,
                candidate: window(candidate.total()),
                reserved,
                opening_reserved: opening,
                terminal_reserved: terminal,
                state: candidate.state(),
                flows,
            },
        })
    }
    /// Commit exactly one current plan at its logical preparation time.
    /// All validation precedes the table's infallible batch commit; controller
    /// history changes only after that succeeds. No poll/handoff occurs here.
    pub fn apply(
        &mut self,
        table: &mut session::Table,
        plan: Plan,
        now: Micros,
    ) -> Result<Applied, Error> {
        if !Arc::ptr_eq(&self.owner, &plan.owner) {
            return Err(Error::Owner);
        }
        if plan.revision != self.status.revision || now != plan.at {
            return Err(Error::StalePlan);
        }
        if self.snapshot(table)? != plan.snapshot {
            return Err(Error::StalePlan);
        }
        let targets: Vec<_> = plan
            .result
            .flows
            .iter()
            .map(|f| (f.flow, f.target))
            .collect();
        table.set_targets(&targets)?;
        self.controller = plan.controller;
        self.rotation_at = plan.rotation_at;
        self.status = PlannerStatus {
            revision: plan.result.revision,
            applied_at: now,
            remainder_cursor: plan.cursor,
        };
        Ok(plan.result)
    }
    fn snapshot(&self, table: &session::Table) -> Result<Snapshot, Error> {
        if !Arc::ptr_eq(&self.table, table.target_identity()) || table.policy() != self.policy {
            return Err(Error::Owner);
        }
        let count = table.status().flows;
        if count > self.policy.max_flows {
            return Err(Error::Accounting);
        }
        let rows = (1..=count as u64)
            .map(|id| {
                Ok(Row {
                    status: table.flow_status(id).ok_or(Error::Accounting)?,
                    credit: table.credit_status(id),
                })
            })
            .collect::<Result<_, Error>>()?;
        Ok(Snapshot {
            table_time: table.target_time(),
            rows,
        })
    }
    fn check_time(&self, snapshot: &Snapshot, now: Micros) -> Result<(), Error> {
        session::check_time(crate::Millis(now.0 / 1000)).map_err(|_| Error::Time)?;
        if now < self.status.applied_at
            || now.0
                < snapshot
                    .table_time
                    .0
                    .checked_mul(1000)
                    .ok_or(Error::Exhausted)?
        {
            return Err(Error::Time);
        }
        Ok(())
    }
    fn current_reservation(&self, row: &Row) -> Result<Window, Error> {
        row.credit.map_or(Ok(self.policy.initial), |credit| {
            Ok(maximum(debt(credit, self.policy.maximum)?, credit.target))
        })
    }
}

fn debt(credit: session::CreditSnapshot, cap: Window) -> Result<Window, Error> {
    if !fits(credit.acknowledged, credit.received)
        || !fits(credit.received, credit.granted)
        || !fits(credit.target, cap)
        || credit.target.bytes == 0
        || credit.target.records == 0
    {
        return Err(Error::Accounting);
    }
    let value = Window {
        bytes: credit
            .granted
            .bytes
            .checked_sub(credit.acknowledged.bytes)
            .ok_or(Error::Accounting)?,
        records: credit
            .granted
            .records
            .checked_sub(credit.acknowledged.records)
            .ok_or(Error::Accounting)?,
    };
    if !fits(value, cap) {
        return Err(Error::Accounting);
    }
    Ok(value)
}
fn window(value: Credit) -> Window {
    Window {
        bytes: value.bytes,
        records: value.records,
    }
}
fn fits(a: Window, b: Window) -> bool {
    a.bytes <= b.bytes && a.records <= b.records
}
fn maximum(a: Window, b: Window) -> Window {
    Window {
        bytes: a.bytes.max(b.bytes),
        records: a.records.max(b.records),
    }
}
fn add(a: Window, b: Window) -> Result<Window, Error> {
    Ok(Window {
        bytes: a.bytes.checked_add(b.bytes).ok_or(Error::Exhausted)?,
        records: a.records.checked_add(b.records).ok_or(Error::Exhausted)?,
    })
}
fn multiply(value: Window, count: usize) -> Result<Window, Error> {
    Ok(Window {
        bytes: value
            .bytes
            .checked_mul(count as u64)
            .ok_or(Error::Exhausted)?,
        records: value
            .records
            .checked_mul(count as u64)
            .ok_or(Error::Exhausted)?,
    })
}
fn component(value: Window, bytes: bool) -> u64 {
    if bytes { value.bytes } else { value.records }
}
fn set_component(value: &mut Window, bytes: bool, n: u64) {
    if bytes {
        value.bytes = n;
    } else {
        value.records = n;
    }
}

// Weighted integer water filling. A cap-removal round removes at least one flow;
// without a hit, the remaining rounding units are fewer than active flows.
fn fill(
    values: &mut [u64],
    caps: &[u64],
    weights: &[u16],
    mut budget: u64,
    cursor: usize,
) -> Result<(), Error> {
    if values.len() != caps.len() || values.len() != weights.len() || values.len() > 64 {
        return Err(Error::Accounting);
    }
    for _ in 0..=values.len() {
        if budget == 0 {
            return Ok(());
        }
        let total: u64 = values
            .iter()
            .zip(caps)
            .zip(weights)
            .filter(|((v, c), w)| v < c && **w != 0)
            .map(|(_, w)| u64::from(*w))
            .sum();
        if total == 0 {
            return Ok(());
        }
        let before = budget;
        let mut capped = false;
        for ((value, cap), weight) in values.iter_mut().zip(caps).zip(weights) {
            if *weight == 0 || *value >= *cap {
                continue;
            }
            let share = (u128::from(before) * u128::from(*weight) / u128::from(total)) as u64;
            let available = *cap - *value;
            capped |= share >= available;
            let amount = share.min(available);
            *value = value.checked_add(amount).ok_or(Error::Exhausted)?;
            budget = budget.checked_sub(amount).ok_or(Error::Accounting)?;
        }
        if capped {
            continue;
        }
        for offset in 0..values.len() {
            let i = (cursor + offset) % values.len();
            if budget != 0 && weights[i] != 0 && values[i] < caps[i] {
                values[i] += 1;
                budget -= 1;
            }
        }
        if budget == 0 {
            return Ok(());
        }
        return Err(Error::Accounting);
    }
    Err(Error::Accounting)
}

#[cfg(test)]
#[path = "adaptive_tests.rs"]
mod tests;
