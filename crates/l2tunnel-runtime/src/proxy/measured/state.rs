use super::*;
use crate::proxy::transport::{PHYSICAL_SLOTS, PhysicalWrite};
use l2tunnel_tcp_proxy::{adaptive, measurement::Micros};
use tokio::time::Instant;

/// Actual bounded state of one lifetime proxy owner, including terminal snapshots.
#[derive(Clone, Copy, Debug)]
pub struct FlowSnapshot {
    /// Maintained ownership and queue state, not peer application consumption.
    pub flow: session::FlowStatus,
    /// Current or frozen terminal authoritative incoming credit.
    pub credit: Option<session::CreditSnapshot>,
}
/// Exact successful callback provenance; cloning the opaque token grants no I/O.
/// The retained marker has no backend, control sender or cancellation lifetime.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PhysicalCallback {
    /// Exact opaque Controller token whose single callback succeeded.
    pub token: measurement::OutputId,
    /// Actual immutable lifetime flow owner.
    pub flow: u64,
    /// Original successful MUX channel.
    pub channel: u16,
    /// Monotonic ordinal among ALL writer Data frames, including nonmeasurement.
    pub ordinal: u64,
    /// Original successful measurement MUX admission in the Controller clock.
    pub admitted_at: Micros,
    /// Actual existing Bridge write generation.
    pub common_generation: u64,
    /// Actual admitted Common record identity whose physical output completed.
    pub common_record: l2tunnel_codec::aligned_receiver::RecordIdentity,
    /// Exact whole-frame physical acceptance time, not peer/native delivery.
    pub accepted_at: Instant,
    /// Exact Common receipt observation, separate from physical acceptance.
    pub physical_observed_at: Instant,
    /// Fresh actor callback expiry watermark; never backdated to acceptance.
    pub callback_observed_at: Instant,
}
/// Copied current facts; inspecting this does not create a measurement or plan.
#[derive(Clone, Debug)]
pub struct Snapshot {
    /// Pure actual-table observations and their precise provenance/freshness.
    pub observations: measurement::ObservationStatus,
    /// Last successful atomic apply; absent before the first actual policy pass.
    pub applied: Option<adaptive::Applied>,
    /// Latest pressure derived from actual shared queues and native I/O.
    pub pressure: measurement::LocalPressure,
    /// Immutable measurement records retained in the common arbiter.
    pub queued: usize,
    /// Immutable records sent to the writer, awaiting successful C callback.
    pub awaiting_callback: usize,
    /// At most two recent successful callbacks with exact physical provenance.
    /// Retained snapshots are bounded observations, not an archival receipt log.
    pub physical_callbacks: [Option<PhysicalCallback>; PHYSICAL_SLOTS],
    /// Actual admitted Demand, EchoRequest, EchoReply counts, respectively.
    pub admitted_by_kind: [u64; 3],
    /// Actual charged measurement bytes, including user and outer framing.
    pub admitted_framed_bytes: u64,
    /// At most configured N lifetime rows, including tombstones.
    pub flows: Vec<FlowSnapshot>,
}
type CallbackDiagnostic<'a> = (Instant, &'a mut dyn FnMut(crate::proxy::timing::Event));

pub(in crate::proxy) struct State {
    pub config: Config,
    pub controller: measurement::Controller,
    pub ledger: Ledger,
    physical_callbacks: [Option<PhysicalCallback>; PHYSICAL_SLOTS],
    report_due: Box<[Micros]>,
    report_cursor: usize,
    probe_cursor: usize,
    probe_due: Micros,
    plan_due: Micros,
    pub admission_cursor: usize,
    pub wire_pressure: bool,
    pub receiver_pressure: bool,
    pressure: measurement::LocalPressure,
    applied: Option<adaptive::Applied>,
    pub admitted: [u64; 3],
    pub framed_bytes: u64,
    status_due: Micros,
    status_phase: Option<super::super::Phase>,
}
fn later(now: Micros, delta: u64) -> io::Result<Micros> {
    now.0
        .checked_add(delta)
        .map(Micros)
        .ok_or_else(|| invalid("measured timer exhausted"))
}
impl State {
    pub fn storage_bytes(n: usize) -> io::Result<usize> {
        // Cover live timers, both old/new replaceable snapshots, and simultaneous
        // previous apply/next plan/status clones. External caller clones are owned
        // by the caller, not hidden retained queues in this runtime.
        n.checked_mul(
            std::mem::size_of::<Micros>()
                + 2 * std::mem::size_of::<FlowSnapshot>()
                + 4 * std::mem::size_of::<adaptive::FlowTarget>(),
        )
        .and_then(|v| {
            v.checked_add(std::mem::size_of::<Self>() + 2 * std::mem::size_of::<Snapshot>())
        })
        .ok_or_else(|| invalid("measured service storage overflow"))
    }
    pub fn new(config: Config, table: &session::Table) -> io::Result<Self> {
        Self::new_with_clock(config, table, Micros(0))
    }
    // A focused fixture may attach a fresh Controller to an already advanced
    // actual Table; use its retained clock rather than resetting logical time.
    #[cfg(test)]
    pub(in crate::proxy) fn new_at(
        config: Config,
        table: &session::Table,
        now: Micros,
    ) -> io::Result<Self> {
        Self::new_with_clock(config, table, now)
    }
    fn new_with_clock(config: Config, table: &session::Table, now: Micros) -> io::Result<Self> {
        let bound = config.validate()?;
        Ok(Self {
            controller: measurement::Controller::new(config.measured, table, now)
                .map_err(io::Error::other)?,
            ledger: Ledger::new(bound.token_slots)?,
            physical_callbacks: std::array::from_fn(|_| None),
            report_due: vec![Micros(0); config.fixed.relay.max_flows].into_boxed_slice(),
            report_cursor: 0,
            probe_cursor: 0,
            probe_due: Micros(0),
            plan_due: Micros(0),
            admission_cursor: 0,
            wire_pressure: false,
            receiver_pressure: false,
            pressure: measurement::LocalPressure::default(),
            applied: None,
            admitted: [0; 3],
            framed_bytes: 0,
            status_due: Micros(0),
            status_phase: None,
            config,
        })
    }
    pub fn enable_physical_receipts(&mut self) -> io::Result<()> {
        self.ledger.enable_physical_receipts()
    }
    pub fn observe_physical(
        &mut self,
        count: u64,
        receipts: [Option<PhysicalWrite>; PHYSICAL_SLOTS],
        origin: Instant,
        observed: Instant,
    ) -> io::Result<()> {
        self.ledger
            .observe_physical(count, receipts, origin, observed)
    }
    pub(in crate::proxy) fn observe_physical_diagnosed(
        &mut self,
        count: u64,
        receipts: [Option<PhysicalWrite>; PHYSICAL_SLOTS],
        origin: Instant,
        observed: Instant,
        terminal: bool,
        mut observe: impl FnMut(crate::proxy::timing::Event),
    ) -> io::Result<()> {
        let before = self.ledger.physical_observed();
        self.observe_physical(count, receipts, origin, observed)?;
        let at = Instant::now();
        for receipt in receipts.into_iter().flatten() {
            if receipt.ordinal.is_some_and(|n| n > before && n <= count) {
                observe(crate::proxy::timing::Event::Imported {
                    receipt,
                    at,
                    terminal,
                });
            }
        }
        Ok(())
    }
    pub(in crate::proxy) fn callbacks_physical_diagnosed(
        &mut self,
        table: &session::Table,
        count: u64,
        origin: Instant,
        observed: Instant,
        mut observe: impl FnMut(crate::proxy::timing::Event),
    ) -> io::Result<()> {
        let elapsed = observed
            .checked_duration_since(origin)
            .ok_or_else(|| invalid("measured callback clock regressed"))?;
        let now = Micros(u64::try_from(elapsed.as_micros()).map_err(io::Error::other)?);
        self.callbacks_inner(
            table,
            count,
            now,
            Some(observed),
            Some((origin, &mut observe)),
        )
    }
    pub fn callbacks_physical(
        &mut self,
        table: &session::Table,
        count: u64,
        origin: Instant,
        observed: Instant,
    ) -> io::Result<()> {
        let elapsed = observed
            .checked_duration_since(origin)
            .ok_or_else(|| invalid("measured callback clock regressed"))?;
        let now = Micros(u64::try_from(elapsed.as_micros()).map_err(io::Error::other)?);
        self.callbacks_inner(table, count, now, Some(observed), None)
    }
    pub fn callbacks(&mut self, table: &session::Table, count: u64, now: Micros) -> io::Result<()> {
        self.callbacks_inner(table, count, now, None, None)
    }
    fn callbacks_inner(
        &mut self,
        table: &session::Table,
        count: u64,
        now: Micros,
        observed: Option<Instant>,
        mut diagnostic: Option<CallbackDiagnostic<'_>>,
    ) -> io::Result<()> {
        // Deadline validation must precede any release, even for already flushed bytes.
        if let (Some(at), Some((origin, observe))) = (observed, diagnostic.as_mut()) {
            observe(crate::proxy::timing::Event::Gate { at });
            self.ledger
                .visit_timing_pending(*origin, at, false, *observe);
        }
        let gate = self.controller.tick(table, now);
        if gate.is_err()
            && let Some((_, observe)) = diagnostic.as_mut()
        {
            observe(crate::proxy::timing::Event::GateFailed);
        }
        gate.map_err(io::Error::other)?;
        self.ledger.observe_flushed(count)?;
        for _ in 0..self.config.service.callback_work_per_turn {
            let Some(next) = self.ledger.next_completed() else {
                break;
            };
            if next
                .physical
                .is_some_and(|physical| observed.is_none_or(|now| now < physical.observed_at))
            {
                return Err(invalid("measured callback preceded physical observation"));
            }
            self.controller
                .confirm_written(table, next.token.clone(), now)
                .map_err(io::Error::other)?;
            self.ledger.confirmed(next.id)?;
            if let Some(physical) = next.physical {
                let callback =
                    observed.ok_or_else(|| invalid("physical callback watermark missing"))?;
                if let Some((_, observe)) = diagnostic.as_mut() {
                    observe(crate::proxy::timing::Event::Callback {
                        receipt: physical,
                        at: callback,
                    });
                }
                self.physical_callbacks[((next.ordinal - 1) % PHYSICAL_SLOTS as u64) as usize] =
                    Some(PhysicalCallback {
                        token: next.token,
                        flow: next.flow,
                        channel: next.channel,
                        ordinal: next.ordinal,
                        admitted_at: next.admitted,
                        common_generation: physical.generation,
                        common_record: physical.identity,
                        accepted_at: physical.accepted_at,
                        physical_observed_at: physical.observed_at,
                        callback_observed_at: callback,
                    });
            }
        }
        Ok(())
    }
    pub fn service(
        &mut self,
        table: &mut session::Table,
        mut pressure: measurement::LocalPressure,
        now: Micros,
    ) -> io::Result<()> {
        self.controller
            .observe_table(table, now)
            .map_err(io::Error::other)?;
        // Source-native unread bytes at exhausted peer relay credit are already
        // authenticated Demand, which qualifies sender growth. They are not local
        // downstream receiver pressure. Observe the opposite direction here:
        // pending maintained native sends blocked by that native peer's actual
        // scaled advertised receive window. Idle zero windows cannot reduce a
        // target; no receive-window value or target is synthesized by this actor.
        pressure.receiver_pressure |= (1..=table.status().flows as u64).any(|id| {
            table.relay_status(id).is_some_and(|relay| {
                relay.native.established
                    && relay.native.send_bytes != 0
                    && relay.native.peer_receive_window_bytes == Some(0)
            })
        });
        self.pressure = pressure;
        if self
            .controller
            .observations(table, now)
            .map_err(io::Error::other)?
            .owner
            .quiescing
        {
            return Ok(());
        }
        let n = self.report_due.len();
        for _ in 0..self.config.service.report_work_per_turn {
            let index = self.report_cursor;
            self.report_cursor = (index + 1) % n;
            let id = index as u64 + 1;
            if now >= self.report_due[index] && active(table, id) {
                self.controller
                    .stage_demand(table, id, now)
                    .map_err(io::Error::other)?;
                self.report_due[index] =
                    later(now, self.config.measured.observation.report_interval_micros)?;
            }
        }
        if now >= self.probe_due {
            for _ in 0..n {
                let id = self.probe_cursor as u64 + 1;
                self.probe_cursor = (self.probe_cursor + 1) % n;
                if active(table, id) {
                    match self.controller.stage_probe(table, id, now) {
                        Ok(())
                        | Err(measurement::ControllerError::Record(
                            measurement::Error::ProbeBusy,
                        )) => {}
                        Err(e) => return Err(io::Error::other(e)),
                    }
                    break;
                }
            }
            self.probe_due = later(now, self.config.measured.ownership.probe_interval_micros)?;
        }
        if now >= self.plan_due {
            let next = later(now, self.config.service.plan_interval_micros)?;
            let plan = self
                .controller
                .prepare(table, pressure, now)
                .map_err(io::Error::other)?;
            self.applied = Some(
                self.controller
                    .apply(table, plan, now)
                    .map_err(io::Error::other)?,
            );
            self.plan_due = next;
        }
        Ok(())
    }
    pub fn next_deadline(&self, now: Micros) -> Option<Micros> {
        // Periodic scans resume on the native tick; do not spin on past due work.
        self.controller
            .next_deadline()
            .into_iter()
            .chain(
                [self.probe_due, self.plan_due, self.status_due]
                    .into_iter()
                    .filter(|n| *n > now),
            )
            .min()
    }
    pub fn publish_due(&mut self, phase: super::super::Phase, now: Micros) -> io::Result<bool> {
        if now < self.status_due && self.status_phase == Some(phase) {
            return Ok(false);
        }
        self.status_due = later(now, self.config.service.status_interval_micros)?;
        self.status_phase = Some(phase);
        Ok(true)
    }
    pub fn snapshot(&self, table: &session::Table, now: Micros) -> io::Result<Snapshot> {
        let (queued, awaiting_callback) = self.ledger.counts();
        Ok(Snapshot {
            observations: self
                .controller
                .observations(table, now)
                .map_err(io::Error::other)?,
            applied: self.applied.clone(),
            pressure: self.pressure,
            queued,
            awaiting_callback,
            physical_callbacks: self.physical_callbacks.clone(),
            admitted_by_kind: self.admitted,
            admitted_framed_bytes: self.framed_bytes,
            flows: (1..=table.status().flows as u64)
                .map(|id| {
                    table
                        .flow_status(id)
                        .map(|flow| FlowSnapshot {
                            flow,
                            credit: table.credit_status(id),
                        })
                        .ok_or_else(|| invalid("measured lifetime owner missing"))
                })
                .collect::<io::Result<Vec<_>>>()?,
        })
    }
}
fn active(table: &session::Table, id: u64) -> bool {
    table
        .flow_status(id)
        .is_some_and(|s| s.phase == session::FlowPhase::Active)
}
