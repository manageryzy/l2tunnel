use super::*;
use crate::delivery::Policy as Delivery;
use l2tunnel_fec::rolling::{self as fec, scheduler};
use serde::{Deserialize, Serialize};
/// Strict, complete versioned startup policy shared by all frontends.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Settings {
    version: u16,
    profile: String,
    pub(super) channels: u16,
    stream: u32,
    epoch: u64,
    recovery: Recovery,
    scheduling: Scheduling,
    service: Service,
    delivery: Delivery,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Recovery {
    window: usize,
    local_window: usize,
    global_every: u16,
    max_payload: usize,
    max_rows: usize,
    repair_history: usize,
    handoff_sources: usize,
    job_millis: u64,
    debt_millis: u64,
    handoff_millis: u64,
    memory_bytes: usize,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Scheduling {
    repair_numerator: u32,
    repair_denominator: u32,
    tail_millis: u64,
    feedback_millis: u64,
    feedback_packets: u32,
    memory_bytes: usize,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Service {
    field_work: usize,
    copy_work: usize,
    metadata_work: usize,
    passes_per_turn: usize,
}
impl Settings {
    /// Parse at most 64 KiB, rejecting unknown, duplicate and missing fields.
    pub fn from_json(bytes: &[u8]) -> io::Result<Self> {
        if bytes.len() > MAX_POLICY_BYTES {
            return Err(invalid("rolling policy exceeds 64 KiB"));
        }
        let value: Self = serde_json::from_slice(bytes)
            .map_err(|_| invalid("invalid strict rolling policy JSON"))?;
        value.scalars()?;
        Ok(value)
    }
    fn policy(&self) -> scheduler::Policy {
        let r = &self.recovery;
        let s = &self.scheduling;
        scheduler::Policy {
            recovery: fec::Config {
                window: r.window,
                local_window: r.local_window,
                global_every: r.global_every,
                max_payload: r.max_payload,
                max_rows: r.max_rows,
                repair_history: r.repair_history,
                handoff_sources: r.handoff_sources,
                job_ticks: r.job_millis,
                debt_ticks: r.debt_millis,
                handoff_ticks: r.handoff_millis,
                memory_bytes: r.memory_bytes,
            },
            repair_numerator: s.repair_numerator,
            repair_denominator: s.repair_denominator,
            tail_ticks: s.tail_millis,
            feedback_ticks: s.feedback_millis,
            feedback_packets: s.feedback_packets,
            memory_bytes: s.memory_bytes,
        }
    }
    fn scalars(&self) -> io::Result<()> {
        self.policy()
            .validate()
            .map_err(|_| invalid("invalid rolling recovery/scheduling policy"))?;
        self.delivery.config(1)?;
        if self.version != 2
            || self.profile != PROFILE
            || !(1..=256).contains(&self.channels)
            || self.epoch == 0
            || self.recovery.window > 128
            || [
                self.service.field_work,
                self.service.copy_work,
                self.service.metadata_work,
            ]
            .into_iter()
            .any(|x| !(1..=fec::MAX_STEP_WORK).contains(&x))
            || !(1..=64).contains(&self.service.passes_per_turn)
        {
            return Err(invalid("unsupported rolling version/profile/service bound"));
        }
        Ok(())
    }
    pub(super) fn validate(
        &self,
        connection: ConnectionConfig,
        recovery: l2tunnel_runtime::udp::RecoveryMode,
    ) -> io::Result<()> {
        self.scalars()?;
        connection.session()?;
        self.delivery(connection.max_packet)?;
        if recovery != l2tunnel_runtime::udp::RecoveryMode::SelectiveRepeat
            || (connection.duplex == l2tunnel_core::Duplex::Half && self.stream == u32::MAX)
        {
            return Err(invalid(
                "rolling requires its own recovery and nonwrapping streams",
            ));
        }
        Ok(())
    }
    pub(crate) fn delivery(
        &self,
        max_packet: usize,
    ) -> io::Result<l2tunnel_runtime::managed::DeliveryConfig> {
        self.delivery.config(max_packet)
    }
    pub(super) fn apply(&self, mut value: runtime::Config) -> runtime::Config {
        value.scheduler = self.policy();
        value.stream = self.stream;
        value.epoch = self.epoch;
        value.work = fec::WorkBudget {
            field: self.service.field_work,
            copies: self.service.copy_work,
            metadata: self.service.metadata_work,
        };
        value.passes_per_turn = self.service.passes_per_turn;
        value
    }
}
