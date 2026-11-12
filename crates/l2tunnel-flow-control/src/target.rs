//! Adaptive unissued tunnel-credit windows with caller-supplied time and feedback.
//!
//! These targets do not revoke issued grants or change endpoint TCP windows.
//! Actual transmission still requires independent congestion, pacing and QoS
//! admission. Feedback estimation/authentication and demand hysteresis belong to
//! the runtime; this module consumes their explicit bounded inputs.

use crate::{Credit, FlowId};
use std::fmt;

/// Largest supported demanding-flow set; bounds allocation and sorting work.
pub const MAX_DEMANDING_FLOWS: usize = 65_536;

/// Monotonic microseconds injected by the caller, unrelated to wire sequence IDs.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct Micros(pub u64);

/// Controller parameters. Hard caps take precedence over the minimum target.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TargetConfig {
    /// Aggregate starting window before demand permits measured growth.
    pub initial: Credit,
    /// Smallest nonidle target after pressure, subject to all hard caps.
    pub minimum: Credit,
    /// Negotiated aggregate retained-memory ceiling.
    pub session_cap: Credit,
    /// Uniform retained-memory ceiling for each demanding flow.
    pub per_flow_cap: Credit,
    /// Operator's aggregate target ceiling, separate from receiver memory.
    pub policy_cap: Credit,
    /// Finite byte allowance added to measured bandwidth-delay product.
    pub queue_allowance_bytes: u64,
    /// Queue delay must exceed this threshold for an RTT before pressure.
    pub queue_delay_target_micros: u64,
    /// Aggregate additive increase per RTT when the demanding-flow set is large.
    pub many_flow_step: Credit,
    /// Maximum demanding-flow count eligible for 2x growth; must be in 1..=4.
    pub few_flow_threshold: usize,
    /// Maximum number of supplied distinct demanding flow IDs.
    pub max_flows: usize,
    /// Timing fallback for pressure/recovery when no RTT estimate is available.
    /// It never qualifies a growth step without a measured RTT.
    pub bootstrap_rtt_micros: u64,
    /// Number of quiet RTTs required after the latest pressure observation.
    pub recovery_rtts: u64,
}

impl Default for TargetConfig {
    fn default() -> Self {
        Self {
            initial: Credit {
                bytes: 16_384,
                records: 16,
            },
            minimum: Credit {
                bytes: 1_024,
                records: 1,
            },
            session_cap: Credit {
                bytes: 4_194_304,
                records: 4_096,
            },
            per_flow_cap: Credit {
                bytes: 4_194_304,
                records: 4_096,
            },
            policy_cap: Credit {
                bytes: 4_194_304,
                records: 4_096,
            },
            queue_allowance_bytes: 65_536,
            queue_delay_target_micros: 5_000,
            many_flow_step: Credit {
                bytes: 1_024,
                records: 1,
            },
            few_flow_threshold: 4,
            max_flows: 1_024,
            bootstrap_rtt_micros: 100_000,
            recovery_rtts: 2,
        }
    }
}

impl TargetConfig {
    fn validate(self) -> Result<(), TargetError> {
        if self.minimum.bytes == 0
            || self.minimum.records == 0
            || !self.minimum.fits(self.initial)
            || !self.initial.fits(self.session_cap)
            || !self.initial.fits(self.policy_cap)
            || !self.minimum.fits(self.per_flow_cap)
            || self.queue_allowance_bytes < self.minimum.bytes
            || self.queue_delay_target_micros == 0
            || self.many_flow_step == Credit::default()
            || !(1..=4).contains(&self.few_flow_threshold)
            || !(1..=MAX_DEMANDING_FLOWS).contains(&self.max_flows)
            || self.bootstrap_rtt_micros == 0
            || self.recovery_rtts == 0
        {
            return Err(TargetError::InvalidConfig);
        }
        self.bootstrap_rtt_micros
            .checked_mul(self.recovery_rtts)
            .ok_or(TargetError::Overflow)?;
        Ok(())
    }
}

/// Runtime-provided observations; `Some` RTT/rate values must be positive.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Feedback {
    /// Measured smoothed RTT, in microseconds; absent estimates cannot grow credit.
    pub rtt_micros: Option<u64>,
    /// Measured delivered logical bytes per second, not configured link capacity.
    pub delivery_bytes_per_second: Option<u64>,
    /// Unique logical bytes/records actually in flight, excluding repair copies.
    pub in_flight: Credit,
    /// Observed queue sojourn delay, in microseconds.
    pub queue_delay_micros: u64,
    /// Actual receiver reservation/memory pressure.
    pub receiver_pressure: bool,
    /// Authenticated congestion-experienced feedback.
    pub ecn: bool,
    /// Qualified loss event supplied by the recovery layer.
    pub loss: bool,
    /// Carrier congestion or send-window stall, distinct from tunnel credit.
    pub carrier_pressure: bool,
    /// Actual queued demand exhausted its effective admission grant; this may
    /// qualify measured growth even when other flow slots reserve unused capacity.
    /// Never causes reduction or bypasses measured RTT/rate, timing or pressure.
    /// The runtime must not set it merely because a flow has no queued demand.
    pub sender_credit_exhausted: bool,
}

/// Current target-policy phase, for diagnostics rather than wire behavior.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TargetState {
    /// No demanding flows; no new window is allocated.
    Idle,
    /// Waiting for measured RTT/rate or the first demand observation.
    Bootstrap,
    /// A single qualified growth step was applied on this update.
    Probing,
    /// Holding the target or constrained by a hard cap.
    Steady,
    /// Current pressure is draining/reducing future admission.
    Backpressure,
    /// Pressure cleared but the quiet recovery interval has not elapsed.
    Recovering,
}

/// Equal share of the unissued aggregate target for a demanding flow.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FlowTarget {
    /// Flow selected by the caller's demand classifier.
    pub flow: FlowId,
    /// Desired outstanding window, not an absolute cumulative grant.
    pub credit: Credit,
}

/// Immutable target allocation; issued ledger grants remain independently valid.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TargetPlan {
    total: Credit,
    flows: Vec<FlowTarget>,
    state: TargetState,
}

impl TargetPlan {
    /// Aggregate outstanding-window target; no target is allocated while idle.
    pub fn total(&self) -> Credit {
        self.total
    }

    /// Sorted equal shares, with remainder preference rotating at most once per RTT.
    pub fn flows(&self) -> &[FlowTarget] {
        &self.flows
    }

    /// Controller phase for this update.
    pub fn state(&self) -> TargetState {
        self.state
    }
}

/// Invalid local configuration or observation; failures leave controller state intact.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TargetError {
    /// Inconsistent or zero timing/cap parameters.
    InvalidConfig,
    /// A supplied RTT or delivery-rate estimate was zero.
    InvalidFeedback,
    /// Caller time moved backwards within one controller lifetime.
    NonMonotonicTime,
    /// Demand list contains the same flow more than once.
    DuplicateFlow,
    /// Demand list exceeds configured work/memory limits.
    TooManyFlows,
    /// Duration multiplication exceeded the supported counter range.
    Overflow,
}

impl fmt::Display for TargetError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for TargetError {}

/// Pure policy state for a single direction; it cannot modify a receiver ledger.
#[derive(Clone, Debug)]
pub struct TargetController {
    config: TargetConfig,
    current: Credit,
    last_update: Micros,
    last_step: Micros,
    last_rotation: Micros,
    queue_pressure_since: Option<Micros>,
    last_pressure: Option<Micros>,
    last_reduction: Option<Micros>,
    was_pressure: bool,
    had_demand: bool,
    remainder_cursor: usize,
}

impl TargetController {
    /// Initialize a bounded target; this does not allocate or advertise any grant.
    pub fn new(config: TargetConfig, now: Micros) -> Result<Self, TargetError> {
        config.validate()?;
        Ok(Self {
            config,
            current: config.initial,
            last_update: now,
            last_step: now,
            last_rotation: now,
            queue_pressure_since: None,
            last_pressure: None,
            last_reduction: None,
            was_pressure: false,
            had_demand: false,
            remainder_cursor: 0,
        })
    }

    /// Reset after explicit path/idle qualification; issued grants are unaffected.
    /// The next demand sample bootstraps instead of catching up past growth steps.
    pub fn restart(&mut self, now: Micros) -> Result<(), TargetError> {
        if now < self.last_update {
            return Err(TargetError::NonMonotonicTime);
        }
        *self = Self::new(self.config, now)?;
        Ok(())
    }

    /// Apply one observation with caller-supplied monotonic time. No catch-up loop
    /// can perform several growth steps after a long pause. Demand IDs are sorted
    /// internally and checked before state is committed.
    pub fn update(
        &mut self,
        now: Micros,
        feedback: Feedback,
        demanding_flows: &[FlowId],
    ) -> Result<TargetPlan, TargetError> {
        if now < self.last_update {
            return Err(TargetError::NonMonotonicTime);
        }
        if feedback.rtt_micros == Some(0) || feedback.delivery_bytes_per_second == Some(0) {
            return Err(TargetError::InvalidFeedback);
        }
        if demanding_flows.len() > self.config.max_flows {
            return Err(TargetError::TooManyFlows);
        }
        let mut flows = demanding_flows.to_vec();
        flows.sort_unstable();
        if flows.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(TargetError::DuplicateFlow);
        }
        let mut next = self.clone();
        let plan = next.update_validated(now, feedback, &flows)?;
        *self = next;
        Ok(plan)
    }

    fn update_validated(
        &mut self,
        now: Micros,
        feedback: Feedback,
        flows: &[FlowId],
    ) -> Result<TargetPlan, TargetError> {
        let rtt = feedback
            .rtt_micros
            .unwrap_or(self.config.bootstrap_rtt_micros);
        let recovery = rtt
            .checked_mul(self.config.recovery_rtts)
            .ok_or(TargetError::Overflow)?;
        let first_demand = !self.had_demand;
        self.last_update = now;
        if feedback.queue_delay_micros > self.config.queue_delay_target_micros {
            self.queue_pressure_since.get_or_insert(now);
        } else {
            self.queue_pressure_since = None;
        }
        let queue_pressure = self
            .queue_pressure_since
            .is_some_and(|since| now.0 - since.0 >= rtt);
        let pressure = feedback.receiver_pressure
            || feedback.ecn
            || feedback.loss
            || feedback.carrier_pressure
            || queue_pressure;
        // Ordinary sender exhaustion intentionally does not enter this condition.
        if pressure {
            self.last_pressure = Some(now);
        }
        if flows.is_empty() {
            self.current = self.config.initial;
            self.had_demand = false;
            self.last_step = now;
            self.last_rotation = now;
            self.was_pressure = pressure;
            return Ok(TargetPlan {
                total: Credit::default(),
                flows: Vec::new(),
                state: TargetState::Idle,
            });
        }
        if first_demand {
            self.current = self.config.initial;
            self.last_step = now;
            self.last_rotation = now;
        }
        self.had_demand = true;
        let cap = self.effective_cap(feedback, flows.len());
        let floor = minimum(self.config.minimum, cap);
        let capped = minimum(self.current, cap);
        if capped != self.current {
            self.last_step = now;
        }
        self.current = capped;
        let quiet = self
            .last_pressure
            .is_none_or(|last| now.0 - last.0 >= recovery);
        let measured =
            feedback.rtt_micros.is_some() && feedback.delivery_bytes_per_second.is_some();
        let utilized = feedback.in_flight.bytes >= self.current.bytes
            || feedback.in_flight.records >= self.current.records
            || feedback.sender_credit_exhausted;
        let mut grew = false;
        if pressure {
            if !self.was_pressure || self.last_reduction.is_none_or(|last| now.0 - last.0 >= rtt) {
                self.current = Credit {
                    bytes: (self.current.bytes / 2).max(floor.bytes),
                    records: (self.current.records / 2).max(floor.records),
                };
                self.last_reduction = Some(now);
                self.last_step = now;
            }
        } else if quiet && measured && utilized && now.0 - self.last_step.0 >= rtt {
            let candidate = if flows.len() <= self.config.few_flow_threshold {
                Credit {
                    bytes: clamp(u128::from(self.current.bytes) * 2, cap.bytes),
                    records: clamp(u128::from(self.current.records) * 2, cap.records),
                }
            } else {
                Credit {
                    bytes: clamp(
                        u128::from(self.current.bytes)
                            + u128::from(self.config.many_flow_step.bytes),
                        cap.bytes,
                    ),
                    records: clamp(
                        u128::from(self.current.records)
                            + u128::from(self.config.many_flow_step.records),
                        cap.records,
                    ),
                }
            };
            grew = candidate != self.current;
            self.current = candidate;
            self.last_step = now;
        }
        if now.0 - self.last_rotation.0 >= rtt {
            self.remainder_cursor = (self.remainder_cursor + 1) % flows.len();
            self.last_rotation = now;
        }
        self.was_pressure = pressure;
        let state = if pressure {
            TargetState::Backpressure
        } else if !quiet {
            TargetState::Recovering
        } else if !measured || first_demand {
            TargetState::Bootstrap
        } else if grew {
            TargetState::Probing
        } else {
            TargetState::Steady
        };
        let count = flows.len() as u64;
        let cursor = self.remainder_cursor % flows.len();
        let targets = flows
            .iter()
            .enumerate()
            .map(|(index, flow)| {
                let rank = (index + flows.len() - cursor) % flows.len();
                FlowTarget {
                    flow: *flow,
                    credit: Credit {
                        bytes: self.current.bytes / count
                            + u64::from((rank as u64) < self.current.bytes % count),
                        records: self.current.records / count
                            + u64::from((rank as u64) < self.current.records % count),
                    },
                }
            })
            .collect();
        Ok(TargetPlan {
            total: self.current,
            flows: targets,
            state,
        })
    }

    fn effective_cap(&self, feedback: Feedback, count: usize) -> Credit {
        let mut cap = minimum(self.config.session_cap, self.config.policy_cap);
        cap.bytes = clamp(
            u128::from(self.config.per_flow_cap.bytes) * count as u128,
            cap.bytes,
        );
        cap.records = clamp(
            u128::from(self.config.per_flow_cap.records) * count as u128,
            cap.records,
        );
        if let (Some(rate), Some(rtt)) = (feedback.delivery_bytes_per_second, feedback.rtt_micros) {
            let bdp = u128::from(rate) * u128::from(rtt) / 1_000_000;
            cap.bytes = clamp(
                bdp + u128::from(self.config.queue_allowance_bytes),
                cap.bytes,
            );
        }
        cap
    }
}

fn minimum(left: Credit, right: Credit) -> Credit {
    Credit {
        bytes: left.bytes.min(right.bytes),
        records: left.records.min(right.records),
    }
}

fn clamp(value: u128, maximum: u64) -> u64 {
    value.min(u128::from(maximum)) as u64
}

#[cfg(test)]
mod tests;
