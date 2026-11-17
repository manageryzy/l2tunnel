//! Portable explicit ACK policy and actual local ingress observations.
use super::*;
use l2tunnel::pipeline::ack_coalescing as ingress;
use std::time::Duration;

/// An explicit scope label; it grants no ownership of a host TCP endpoint.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AckSelection {
    /// Requires actual owned endpoints, unsupported by the present Common composition.
    OwnedTcp,
    /// Explicit benchmark ingress; does not generate or rewrite host ACKs.
    Benchmark,
}
/// Complete canonical microsecond policy; no implicit defaults.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AckPolicy {
    /// Explicit execution scope.
    pub selection: AckSelection,
    /// First-candidate coalescing interval; zero forwards immediately.
    pub interval_micros: u64,
    /// Original maximum held age, not renewed on replacement.
    pub max_hold_micros: u64,
    /// Exact directional history and pending slot capacity.
    pub max_flows: u64,
    /// Exact retained bytes per candidate.
    pub max_ack_bytes: u64,
}
impl AckPolicy {
    pub(crate) fn build(self) -> io::Result<ingress::Policy> {
        Ok(ingress::Policy {
            selection: match self.selection {
                AckSelection::OwnedTcp => ingress::Selection::OwnedTcp,
                AckSelection::Benchmark => ingress::Selection::Benchmark,
            },
            interval: Duration::from_micros(self.interval_micros),
            max_hold: Duration::from_micros(self.max_hold_micros),
            max_flows: usize::try_from(self.max_flows).map_err(invalid)?,
            max_ack_bytes: usize::try_from(self.max_ack_bytes).map_err(invalid)?,
        })
    }
    pub(crate) fn from_policy(value: ingress::Policy) -> io::Result<Self> {
        let micros = |value: Duration| -> io::Result<u64> {
            let result = u64::try_from(value.as_micros()).map_err(invalid)?;
            if Duration::from_micros(result) != value {
                return Err(invalid("ACK policy has submicrosecond precision"));
            }
            Ok(result)
        };
        Ok(Self {
            selection: match value.selection {
                ingress::Selection::OwnedTcp => AckSelection::OwnedTcp,
                ingress::Selection::Benchmark => AckSelection::Benchmark,
            },
            interval_micros: micros(value.interval)?,
            max_hold_micros: micros(value.max_hold)?,
            max_flows: u64::try_from(value.max_flows).map_err(invalid)?,
            max_ack_bytes: u64::try_from(value.max_ack_bytes).map_err(invalid)?,
        })
    }
}
fn nullable_policy<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<AckPolicy>, D::Error> {
    Option::<AckPolicy>::deserialize(deserializer)
}
/// Independent complete role policies. Supplied objects require both fields.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AckPolicies {
    /// Client-to-server native ingress selection.
    #[serde(deserialize_with = "nullable_policy")]
    pub initiator: Option<AckPolicy>,
    /// Server-to-client native ingress selection.
    #[serde(deserialize_with = "nullable_policy")]
    pub responder: Option<AckPolicy>,
}
impl AckPolicies {
    pub(crate) fn build(self) -> io::Result<[Option<ingress::Policy>; 2]> {
        if self.initiator.is_none() && self.responder.is_none() {
            return Err(invalid("empty ACK selection must be omitted"));
        }
        Ok([
            self.initiator.map(AckPolicy::build).transpose()?,
            self.responder.map(AckPolicy::build).transpose()?,
        ])
    }
    pub(crate) fn from_policies(value: [Option<ingress::Policy>; 2]) -> io::Result<Option<Self>> {
        if value == [None, None] {
            return Ok(None);
        }
        Ok(Some(Self {
            initiator: value[0].map(AckPolicy::from_policy).transpose()?,
            responder: value[1].map(AckPolicy::from_policy).transpose()?,
        }))
    }
}
/// Actual retained ingress layout and events, separate from physical delivery.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AckObservation {
    /// Actual Engine epoch that owns this ingress.
    pub epoch: u64,
    /// Actual two-allocation heap bytes.
    pub capacity_bytes: u64,
    /// Actual successful constructor reservations.
    pub allocations: u64,
    /// Original ACK bytes held before Pipeline admission.
    pub held_bytes: u64,
    /// Original ACK candidates held before Pipeline admission.
    pub held_packets: u64,
    /// Retained directional histories, including empty candidates.
    pub histories: u64,
    /// Actual first-observation, supersede, duplicate, flush, bypass and refusal counts.
    pub first_observation: u64,
    /// Unsent advancing originals replaced by a later equivalent original.
    pub superseded: u64,
    /// Distinct equal-number ACK events actually forwarded.
    pub duplicates: u64,
    /// Previously held originals transferred to the actual Pipeline.
    pub flushed: u64,
    /// Originals forwarded without suppressing an advancing candidate.
    pub bypassed: u64,
    /// Actual typed ingress admission refusals.
    pub refusals: u64,
    /// All successfully consumed ingress events, not emitted packet count.
    pub received: u64,
    /// Safe ACK events recognized by the bounded packet validator.
    pub eligible: u64,
    /// Original earliest held-candidate expiry.
    pub expiry_micros: Option<u64>,
}
/// One actual device read retained in the existing input slab after refusal.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AckRead {
    /// Exact current retained input length.
    pub bytes: u64,
    /// First actual device-read observation.
    pub received_micros: u64,
    /// Original nonrenewable input cap.
    pub deadline_micros: u64,
}
/// Requested policy and actual installed observations stay distinct.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AckStatus {
    /// Exact paired establishment policy retained by Profile.
    pub requested: AckPolicies,
    /// Actual local owner policy; absent before a runtime report or for an unselected role.
    pub effective: Option<AckPolicy>,
    /// Actual Engine owner observations, never inferred from requested limits.
    pub observation: Option<AckObservation>,
    /// Actual refused original still held outside Pipeline in the sole input slab.
    pub pending_read: Option<AckRead>,
    /// This establishment-bound selection cannot be changed by the existing C switch.
    pub policy_switching: bool,
}
impl AckStatus {
    pub(super) fn observe(
        requested: AckPolicies,
        snapshot: Option<&l2tunnel_runtime::secure_udp::transport::CommonSnapshot>,
    ) -> io::Result<Self> {
        let number = |value| u64::try_from(value).map_err(invalid);
        let actual = snapshot.and_then(|value| value.ack_ingress);
        let observation = actual
            .map(|value| {
                let statistics = value.statistics;
                Ok::<_, io::Error>(AckObservation {
                    epoch: snapshot
                        .ok_or_else(|| invalid("ACK observation has no runtime"))?
                        .epoch
                        .0,
                    capacity_bytes: number(value.usage.capacity_bytes)?,
                    allocations: number(value.usage.allocations)?,
                    held_bytes: number(value.usage.held.bytes)?,
                    held_packets: number(value.usage.held.packets)?,
                    histories: number(value.usage.histories)?,
                    first_observation: statistics.first_observation,
                    superseded: statistics.superseded,
                    duplicates: statistics.duplicates,
                    flushed: statistics.flushed,
                    bypassed: statistics.bypassed,
                    refusals: statistics.refusals,
                    received: statistics.received,
                    eligible: statistics.eligible,
                    expiry_micros: value.expiry.map(|tick| tick.0),
                })
            })
            .transpose()?;
        let pending_read = snapshot
            .filter(|value| value.pending_ingress_bytes.is_some())
            .map(|value| {
                Ok::<_, io::Error>(AckRead {
                    bytes: number(
                        value
                            .pending_ingress_bytes
                            .ok_or_else(|| invalid("ACK read length"))?,
                    )?,
                    received_micros: value
                        .pending_ingress_since_micros
                        .ok_or_else(|| invalid("ACK read age"))?,
                    deadline_micros: value
                        .pending_ingress_deadline_micros
                        .ok_or_else(|| invalid("ACK read cap"))?,
                })
            })
            .transpose()?;
        Ok(Self {
            requested,
            effective: actual
                .map(|value| AckPolicy::from_policy(value.policy))
                .transpose()?,
            observation,
            pending_read,
            policy_switching: false,
        })
    }
}
