//! Pure observations from actual table ACKs and the exclusively owned B path.
//!
//! Authenticated ingress and exact common-MUX/write callbacks remain caller
//! obligations. No target here is a native TCP advertised-window setting.
use super::{Ingress, Micros, OutputId, Owner, OwnerConfig, OwnerStatus, Pending, owner, wire};
use crate::{Window, adaptive, session};
use std::{fmt, mem::size_of, sync::Arc};

mod model;
use model::{Model, Report};

const MAX_MICROS: u64 = 120_000_000;
/// Fixed observation timers; each configured duration is 1ms..=120s.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ObservationConfig {
    /// Required future adapter report cadence; no automatic report is emitted.
    pub report_interval_micros: u64,
    /// Strict age bound for completed rate bins, demand and service observations.
    pub sample_ttl_micros: u64,
    /// Continuous fresh empty-demand interval before removing allocation demand.
    pub demand_idle_micros: u64,
    /// Minimum aggregate interval for one actual ACK-rate observation.
    pub rate_interval_micros: u64,
    /// Completed aggregate intervals retained, in 1..=16.
    pub rate_bins: u8,
}
/// Immutable measured policy for one actual table and original stream direction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MeasuredConfig {
    /// Existing debt-preserving allocation policy.
    pub allocation: adaptive::Config,
    /// Existing bounded record/replay/handoff policy.
    pub ownership: OwnerConfig,
    /// Local observation cadence, ageing and hysteresis.
    pub observation: ObservationConfig,
}
/// Caller assertions about local pressure, not authenticated measurement evidence.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct LocalPressure {
    /// Actual common queue sojourn, in 0..=120 seconds.
    pub queue_delay_micros: u64,
    /// Local receiver reservation pressure.
    pub receiver_pressure: bool,
    /// Local retained carrier/write pressure.
    pub carrier_pressure: bool,
}
/// Checked retained allocations; allocator/Arc overhead and caller plans excluded.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ObservationMemory {
    /// Lifetime baseline/demand/weight slots in each preallocated observation bank.
    pub flow_slots: usize,
    /// Completed rate slots in each bank.
    pub rate_bins: usize,
    /// Controller inline bytes, live observation bank, B buffers and planner weights.
    pub retained_bytes: usize,
    /// Preallocated shadow bank bytes; commits swap banks without allocating.
    pub scratch_bytes: usize,
    /// Size of the fixed derived view, including its 64-entry temporary demand set.
    /// This is a value-component bound, not a whole native thread-stack estimate.
    pub view_bytes: usize,
    /// Separate B accounting, included in retained_bytes, excluding common copies.
    pub record_owner: super::MemoryBound,
}
impl MeasuredConfig {
    /// Validate actual policy and concrete storage before constructing any owner.
    pub fn validate(self, table: &session::Table) -> Result<ObservationMemory, ControllerError> {
        self.allocation.validate(table)?;
        let record_owner = self.ownership.validate(table)?;
        let o = self.observation;
        if [
            o.report_interval_micros,
            o.sample_ttl_micros,
            o.demand_idle_micros,
            o.rate_interval_micros,
        ]
        .into_iter()
        .any(|n| !(1_000..=MAX_MICROS).contains(&n))
            || !(1..=16).contains(&o.rate_bins)
            || o.sample_ttl_micros < o.report_interval_micros
            || o.sample_ttl_micros < self.ownership.probe_timeout_micros
            || o.sample_ttl_micros < 2 * o.rate_interval_micros
            || o.demand_idle_micros < o.report_interval_micros
            || 2 * o.rate_interval_micros * u64::from(o.rate_bins) > MAX_MICROS
        {
            return Err(ControllerError::Configuration);
        }
        let n = table.policy().max_flows;
        let bank = n
            .checked_mul(size_of::<model::Flow>())
            .and_then(|v| v.checked_add(usize::from(o.rate_bins) * size_of::<Option<model::Bin>>()))
            .ok_or(ControllerError::Accounting)?;
        let retained_bytes = size_of::<Controller>()
            .checked_add(bank)
            .and_then(|v| v.checked_add(record_owner.buffer_bytes))
            .and_then(|v| v.checked_add(record_owner.metadata_bytes))
            .and_then(|v| v.checked_sub(size_of::<Owner>()))
            .and_then(|v| v.checked_add(n * size_of::<Option<u16>>()))
            .ok_or(ControllerError::Accounting)?;
        Ok(ObservationMemory {
            flow_slots: n,
            rate_bins: usize::from(o.rate_bins),
            retained_bytes,
            scratch_bytes: bank,
            view_bytes: size_of::<model::View>(),
            record_owner,
        })
    }
}
/// Rejected observation/planning operation; no native or issued credit is released.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ControllerError {
    /// Unsupported timer, storage or local pressure bound.
    Configuration,
    /// A different actual table/controller owns the operation or plan.
    Owner,
    /// Injected time precedes authoritative controller/table time.
    Time,
    /// Authoritative counter arithmetic or state relationships are impossible.
    Accounting,
    /// The checked observation revision exhausted; this session is terminal.
    Exhausted,
    /// Observation identity, revision or exact preparation time changed.
    StalePlan,
    /// Existing bounded owner rejected the operation; handoff expiry is terminal.
    Record(owner::Error),
    /// Existing atomic debt-preserving planner rejected the operation.
    Allocation(adaptive::Error),
}
impl fmt::Display for ControllerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "proxy measured controller: {self:?}")
    }
}
impl std::error::Error for ControllerError {}
impl From<owner::Error> for ControllerError {
    fn from(error: owner::Error) -> Self {
        Self::Record(error)
    }
}
impl From<adaptive::Error> for ControllerError {
    fn from(error: adaptive::Error) -> Self {
        Self::Allocation(error)
    }
}

/// Aggregate actual original-byte ACK observation over eligible completed bins.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AckRate {
    /// Actual acknowledged bytes, never native-write or peer-report counts.
    pub bytes: u128,
    /// Sum of actual elapsed times, once per aggregate bin, not once per flow.
    pub elapsed_micros: u64,
    /// Floor(bytes * 1e6 / elapsed); zero does not qualify growth.
    pub bytes_per_second: u64,
    /// Number of eligible completed bins.
    pub bins: u8,
    /// Latest included completion time.
    pub latest_at: Micros,
}
/// Original-clock common-path echo observation, never native TCP RTT.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ServiceLatency {
    /// Smoothed positive service latency, using 7/8 prior weight while fresh.
    pub smoothed_micros: u64,
    /// Actual source flow of the latest eligible completion.
    pub flow: u64,
    /// Immutable output generation of the latest original request.
    pub generation: u64,
    /// Original exact shared-MUX admission time.
    pub admitted_at: Micros,
    /// Original reply receipt time; late write callbacks cannot renew this.
    pub reply_at: Micros,
    /// Whether the original reply remains eligible at query time.
    pub fresh: bool,
}
/// Copied time-indexed facts; reading this never advances authority or expiry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ObservationStatus {
    /// Query time, not a new measured event.
    pub at: Micros,
    /// Last successful authoritative operation time.
    pub authoritative_at: Micros,
    /// Checked observation/lifecycle revision.
    pub revision: u64,
    /// Actual current active table entries.
    pub active_flows: usize,
    /// Active entries retained in the allocation demand set.
    pub demanding_flows: usize,
    /// Active entries with no fresh demand evidence; any disables aggregate growth.
    pub unknown_flows: usize,
    /// Fresh unread demand with a still-current exhausted corresponding grant.
    pub grant_exhausted: bool,
    /// Actual active original received-minus-ACK bytes/records.
    pub in_flight: Window,
    /// Eligible completed-bin observation; Some with zero rate remains nongrowing.
    pub ack_rate: Option<AckRate>,
    /// At least one eligible bin exists, with total actual delivered bytes zero.
    pub zero_delivery: bool,
    /// Most recent actual bin completion, even when all retained bins expired.
    pub latest_completed_bin: Option<Micros>,
    /// Latest completed echo evidence; freshness is explicit.
    pub service_latency: Option<ServiceLatency>,
    /// Existing bounded record ownership at its last actual operation.
    pub owner: OwnerStatus,
    /// Latched terminal observation/handoff failure, never synthesized by a query.
    pub failure: Option<ControllerError>,
    /// Checked construction storage and separately bounded preallocated scratch.
    pub memory: ObservationMemory,
}
/// Opaque proposal bound to the exact Controller revision, table and logical time.
pub struct MeasuredPlan {
    identity: Arc<()>,
    revision: u64,
    at: Micros,
    plan: adaptive::Plan,
}
impl MeasuredPlan {
    /// Inspect future targets and reservations; no native window or grant authority.
    pub fn allocation(&self) -> &adaptive::Applied {
        self.plan.allocation()
    }
}
/// Exclusive pure composition; no mutable owner/planner or fabricated sample API.
pub struct Controller {
    config: MeasuredConfig,
    memory: ObservationMemory,
    table: Arc<()>,
    policy: session::Config,
    identity: Arc<()>,
    owner: Owner,
    planner: adaptive::Planner,
    model: Model,
    scratch: Model,
    at: Micros,
    revision: u64,
    failure: Option<ControllerError>,
}
impl Controller {
    /// Bind actual table identity and allocate two fixed observation banks.
    pub fn new(
        config: MeasuredConfig,
        table: &session::Table,
        now: Micros,
    ) -> Result<Self, ControllerError> {
        let memory = config.validate(table)?;
        // Check every future observation/owner timer before allocating banks.
        now.0.checked_add(MAX_MICROS).ok_or(ControllerError::Time)?;
        let owner = Owner::new(config.ownership, table, now)?;
        let planner = adaptive::Planner::new(config.allocation, table, now)?;
        Ok(Self {
            config,
            memory,
            table: table.target_identity().clone(),
            policy: table.policy(),
            identity: Arc::new(()),
            owner,
            planner,
            model: Model::new(memory.flow_slots, memory.rate_bins, now),
            scratch: Model::new(memory.flow_slots, memory.rate_bins, now),
            at: now,
            revision: 0,
            failure: None,
        })
    }
    /// Bind an immutable configured QoS weight; identical retries change no state.
    pub fn bind_flow(&mut self, flow: adaptive::FlowWeight) -> Result<(), ControllerError> {
        self.health()?;
        let index = flow
            .flow
            .checked_sub(1)
            .and_then(|n| usize::try_from(n).ok())
            .filter(|i| *i < self.model.flows.len())
            .ok_or(ControllerError::Allocation(adaptive::Error::Flow))?;
        if self.model.flows[index].weight == Some(flow.weight) {
            return Ok(());
        }
        let revision = self.next_revision()?;
        self.planner.bind_flow(flow)?;
        self.model.flows[index].weight = Some(flow.weight);
        self.revision = revision;
        Ok(())
    }
    /// Observe real cumulative ACK prefixes; first/terminal observations retain baselines.
    pub fn observe_table(
        &mut self,
        table: &session::Table,
        now: Micros,
    ) -> Result<(), ControllerError> {
        let revision = self.preflight(Some(table), now)?;
        self.scratch.copy_from(&self.model);
        self.scratch.observe(table, self.config.observation, now)?;
        self.scratch.refresh(table, self.config.observation, now)?;
        self.scratch.view(table, self.config.observation, now)?;
        self.commit_shadow(revision, now);
        Ok(())
    }
    /// Stage only actual local table demand through the original bounded owner.
    pub fn stage_demand(
        &mut self,
        table: &session::Table,
        flow: u64,
        now: Micros,
    ) -> Result<(), ControllerError> {
        let revision = self.preflight(Some(table), now)?;
        self.owner.stage_demand(table, flow, now)?;
        self.commit_clock(revision, now);
        Ok(())
    }
    /// Explicitly stage one original probe; its future copy uses the common MUX.
    pub fn stage_probe(
        &mut self,
        table: &session::Table,
        flow: u64,
        now: Micros,
    ) -> Result<(), ControllerError> {
        let revision = self.preflight(Some(table), now)?;
        self.owner.stage_probe(table, flow, now)?;
        self.commit_clock(revision, now);
        Ok(())
    }
    /// Borrow one bounded user-record output; this does not count as admission.
    pub fn pending(
        &mut self,
        table: &session::Table,
        now: Micros,
    ) -> Result<Option<Pending<'_>>, ControllerError> {
        let revision = self.preflight(Some(table), now)?;
        let pending = self.owner.pending(table, now)?;
        self.at = now;
        self.revision = revision;
        Ok(pending)
    }
    /// Confirm a real common-MUX copy at the same synchronous logical timestamp.
    pub fn confirm_admission(&mut self, id: OutputId, now: Micros) -> Result<(), ControllerError> {
        let revision = self.preflight(None, now)?;
        self.owner.confirm_admission(id, now)?;
        self.commit_clock(revision, now);
        Ok(())
    }
    /// Complete exact retained write/flush with current actual-table eligibility.
    pub fn confirm_written(
        &mut self,
        table: &session::Table,
        id: OutputId,
        now: Micros,
    ) -> Result<(), ControllerError> {
        let revision = self.preflight(Some(table), now)?;
        let event = self.owner.confirm_written_measured(table, id, now)?;
        if let Some(event) = event {
            self.model.complete(event, self.config.observation, now);
        }
        self.commit_clock(revision, now);
        Ok(())
    }
    /// Consume only trusted authenticated ordered records of this negotiated type.
    /// Device magic and peer-supplied identity bytes cannot authorize this call.
    pub fn receive_authenticated(
        &mut self,
        table: &session::Table,
        bytes: &[u8],
        now: Micros,
    ) -> Result<Ingress, ControllerError> {
        let revision = self.preflight(Some(table), now)?;
        let record = wire::decode(bytes).map_err(owner::Error::Decode)?;
        let demand = if let wire::Body::Demand(value) = record.body {
            Some(value)
        } else {
            None
        };
        if let Some(value) = demand {
            self.scratch.copy_from(&self.model);
            let index = record
                .header
                .scope
                .flow
                .checked_sub(1)
                .and_then(|v| usize::try_from(v).ok())
                .filter(|i| *i < self.scratch.flows.len())
                .ok_or(ControllerError::Record(owner::Error::Flow))?;
            self.scratch.flows[index].report = Some(Report { value, at: now });
            self.scratch.refresh(table, self.config.observation, now)?;
            self.scratch.view(table, self.config.observation, now)?;
        }
        let (ingress, event) = self.owner.receive_measured(table, bytes, now)?;
        if ingress == Ingress::Accepted && demand.is_some() {
            std::mem::swap(&mut self.model, &mut self.scratch);
        }
        // Completion intervals are bounded by the already-validated <=120s owner
        // lifetime, so all subsequent arithmetic is infallible (u128 intermediate).
        if let Some(event) = event {
            self.model.complete(event, self.config.observation, now);
        }
        self.commit_clock(revision, now);
        Ok(ingress)
    }
    /// Process original B expiry/terminal work without reading or polling native I/O.
    pub fn tick(&mut self, table: &session::Table, now: Micros) -> Result<(), ControllerError> {
        let revision = self.preflight(Some(table), now)?;
        self.owner.tick(table, now)?;
        self.commit_clock(revision, now);
        Ok(())
    }
    /// Stop new measurement work; admitted proof bytes remain owned until written.
    pub fn quiesce(&mut self, now: Micros) -> Result<(), ControllerError> {
        let revision = self.preflight(None, now)?;
        self.owner.quiesce(now)?;
        self.commit_clock(revision, now);
        Ok(())
    }
    /// Derive all feedback internally and stage exactly one existing atomic plan.
    pub fn prepare(
        &mut self,
        table: &session::Table,
        pressure: LocalPressure,
        now: Micros,
    ) -> Result<MeasuredPlan, ControllerError> {
        let revision = self.preflight(Some(table), now)?;
        if self.owner.status().quiescing {
            return Err(owner::Error::Quiesced.into());
        }
        if pressure.queue_delay_micros > MAX_MICROS {
            return Err(ControllerError::Configuration);
        }
        self.scratch.copy_from(&self.model);
        self.scratch.refresh(table, self.config.observation, now)?;
        let view = self.scratch.view(table, self.config.observation, now)?;
        let rate = view
            .rate
            .filter(|r| r.bytes_per_second > 0 && view.unknown == 0)
            .map(|r| r.bytes_per_second);
        let service = self
            .scratch
            .service(now, self.config.observation)
            .filter(|s| s.fresh)
            .map(|s| s.smoothed_micros);
        let feedback = adaptive::Feedback {
            rtt_micros: service,
            delivery_bytes_per_second: rate,
            in_flight: l2tunnel_flow_control::Credit {
                bytes: view.in_flight.bytes,
                records: view.in_flight.records,
            },
            queue_delay_micros: pressure.queue_delay_micros,
            receiver_pressure: pressure.receiver_pressure,
            carrier_pressure: pressure.carrier_pressure,
            sender_credit_exhausted: view.exhausted,
            ecn: false,
            loss: false,
        };
        let plan =
            self.planner
                .prepare(table, feedback, &view.demanding[..view.demand_count], now)?;
        self.commit_shadow(revision, now);
        Ok(MeasuredPlan {
            identity: self.identity.clone(),
            revision,
            at: now,
            plan,
        })
    }
    /// Commit only the current exact measured proposal; rejected plans change no targets.
    pub fn apply(
        &mut self,
        table: &mut session::Table,
        plan: MeasuredPlan,
        now: Micros,
    ) -> Result<adaptive::Applied, ControllerError> {
        let revision = self.preflight(Some(table), now)?;
        if !Arc::ptr_eq(&plan.identity, &self.identity) {
            return Err(ControllerError::Owner);
        }
        if plan.revision != self.revision || plan.at != now {
            return Err(ControllerError::StalePlan);
        }
        let result = self.planner.apply(table, plan.plan, now)?;
        self.commit_clock(revision, now);
        Ok(result)
    }
    /// Read facts at a valid time without changing sample freshness or owner expiry.
    pub fn observations(
        &self,
        table: &session::Table,
        now: Micros,
    ) -> Result<ObservationStatus, ControllerError> {
        self.check_time(Some(table), now)?;
        let view = self.model.view(table, self.config.observation, now)?;
        let owner = self.owner.status();
        let mut service = self.model.service(now, self.config.observation);
        if (self.failure.is_some() || owner.quiescing || self.owner.handoff_expired_at(now))
            && let Some(value) = &mut service
        {
            value.fresh = false;
        }
        Ok(ObservationStatus {
            at: now,
            authoritative_at: self.at,
            revision: self.revision,
            active_flows: view.active,
            demanding_flows: view.demand_count,
            unknown_flows: view.unknown,
            grant_exhausted: view.exhausted,
            in_flight: view.in_flight,
            ack_rate: view.rate,
            zero_delivery: view.rate.is_some_and(|r| r.bytes == 0),
            latest_completed_bin: self.model.latest_bin,
            service_latency: service,
            owner,
            failure: self.failure,
            memory: self.memory,
        })
    }
    /// Earliest unprocessed observation wake plus every live B ownership deadline.
    pub fn next_deadline(&self) -> Option<Micros> {
        if self.failure.is_some() {
            return self.owner.next_deadline();
        }
        self.model
            .next_deadline(self.config.observation, self.at)
            .into_iter()
            .chain(self.owner.next_deadline())
            .min()
    }
    /// Clean measurement shutdown requires quiesce and every admitted full write.
    pub fn drained(&self) -> bool {
        self.owner.drained() && self.failure.is_none()
    }

    fn health(&self) -> Result<(), ControllerError> {
        self.failure.map_or(Ok(()), Err)
    }
    fn next_revision(&mut self) -> Result<u64, ControllerError> {
        self.revision.checked_add(1).ok_or_else(|| {
            self.failure = Some(ControllerError::Exhausted);
            ControllerError::Exhausted
        })
    }
    fn check_time(
        &self,
        table: Option<&session::Table>,
        now: Micros,
    ) -> Result<(), ControllerError> {
        if now < self.at {
            return Err(ControllerError::Time);
        }
        if let Some(table) = table {
            if !Arc::ptr_eq(&self.table, table.target_identity()) || table.policy() != self.policy {
                return Err(ControllerError::Owner);
            }
            if now.0
                < table
                    .target_time()
                    .0
                    .checked_mul(1000)
                    .ok_or(ControllerError::Time)?
            {
                return Err(ControllerError::Time);
            }
        }
        Ok(())
    }
    fn preflight(
        &mut self,
        table: Option<&session::Table>,
        now: Micros,
    ) -> Result<u64, ControllerError> {
        self.health()?;
        self.check_time(table, now)?;
        // Observation deadlines can be longer than B's emission timer.
        now.0.checked_add(MAX_MICROS).ok_or(ControllerError::Time)?;
        let revision = self.next_revision()?;
        if let Err(error) = self.owner.check(table, now) {
            if error == owner::Error::HandoffExpired {
                self.failure = Some(error.into());
            }
            return Err(error.into());
        }
        Ok(revision)
    }
    fn commit_clock(&mut self, revision: u64, now: Micros) {
        self.at = now;
        self.revision = revision;
    }
    fn commit_shadow(&mut self, revision: u64, now: Micros) {
        std::mem::swap(&mut self.model, &mut self.scratch);
        self.commit_clock(revision, now);
    }
}

#[cfg(test)]
mod tests;
