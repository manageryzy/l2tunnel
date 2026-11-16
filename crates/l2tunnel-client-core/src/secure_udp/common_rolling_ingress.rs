//! Exact optional authenticated Rolling input selection and actual observations.
use super::*;
use l2tunnel::rolling_records as rolling;

/// Complete independent Queue policy; neither field is a coding-window default.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RollingIngressLimits {
    /// Actual reusable complete-wire packet slots.
    pub slots: u64,
    /// Complete selected Queue heap allowance.
    pub capacity_bytes: u64,
}
impl RollingIngressLimits {
    pub(crate) fn build(self) -> io::Result<rolling::IngressLimits> {
        if self.slots == 0 || self.capacity_bytes == 0 {
            return Err(invalid("Rolling ingress requires positive explicit limits"));
        }
        Ok(rolling::IngressLimits {
            slots: usize::try_from(self.slots).map_err(invalid)?,
            capacity_bytes: usize::try_from(self.capacity_bytes).map_err(invalid)?,
        })
    }
    pub(crate) fn from_limits(value: rolling::IngressLimits) -> io::Result<Self> {
        Ok(Self {
            slots: u64::try_from(value.slots).map_err(invalid)?,
            capacity_bytes: u64::try_from(value.capacity_bytes).map_err(invalid)?,
        })
    }
}
fn nullable_limits<'de, D: Deserializer<'de>>(
    d: D,
) -> Result<Option<RollingIngressLimits>, D::Error> {
    Option::<RollingIngressLimits>::deserialize(d)
}
/// Both explicit role fields are required; null leaves that role unselected.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RollingIngressPolicies {
    /// Actual initiator receive-wire queue policy.
    #[serde(deserialize_with = "nullable_limits")]
    pub initiator: Option<RollingIngressLimits>,
    /// Actual responder receive-wire queue policy.
    #[serde(deserialize_with = "nullable_limits")]
    pub responder: Option<RollingIngressLimits>,
}
impl RollingIngressPolicies {
    pub(crate) fn build(self) -> io::Result<[Option<rolling::IngressLimits>; 2]> {
        if self.initiator.is_none() && self.responder.is_none() {
            return Err(invalid("empty Rolling ingress selection must be omitted"));
        }
        Ok([
            self.initiator
                .map(RollingIngressLimits::build)
                .transpose()?,
            self.responder
                .map(RollingIngressLimits::build)
                .transpose()?,
        ])
    }
    pub(crate) fn from_policies(
        value: [Option<rolling::IngressLimits>; 2],
    ) -> io::Result<Option<Self>> {
        if value == [None, None] {
            return Ok(None);
        }
        Ok(Some(Self {
            initiator: value[0]
                .map(RollingIngressLimits::from_limits)
                .transpose()?,
            responder: value[1]
                .map(RollingIngressLimits::from_limits)
                .transpose()?,
        }))
    }
}
/// Exact current-generation custody, not decoded/native delivery.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RollingIngressObservation {
    /// Actual issuing Engine epoch.
    pub epoch: u64,
    /// Actual Queue-owned heap; the policy allowance may be larger.
    pub capacity_bytes: u64,
    /// Actual retained allocations.
    pub allocations: u64,
    /// Actual pending whole inputs and initialized bytes.
    pub packets: u64,
    /// Actual initialized retained plaintext bytes.
    pub bytes: u64,
    /// Original arrival and already authenticated Records number of the FIFO head.
    pub oldest_received_micros: Option<u64>,
    /// Observation metadata only; this is no second replay authority.
    pub oldest_records_number: Option<u64>,
    /// Earliest original queued job/operation/session cap.
    pub deadline_micros: Option<u64>,
}
/// Immutable requested policy and actual active queue remain separate.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RollingIngressStatus {
    /// Exact complete paired establishment selection.
    pub requested: RollingIngressPolicies,
    /// Actual local active Queue policy; absent for another active record family.
    pub effective: Option<RollingIngressLimits>,
    /// Actual current-generation Queue state, absent before a runtime report.
    pub observation: Option<RollingIngressObservation>,
    /// Existing C switches cannot hot-change this establishment policy.
    pub policy_switching: bool,
}
#[cfg(unix)]
impl RollingIngressStatus {
    pub(super) fn observe(
        requested: RollingIngressPolicies,
        snapshot: Option<&l2tunnel_runtime::secure_udp::transport::CommonSnapshot>,
    ) -> io::Result<Self> {
        let actual = snapshot.and_then(|value| value.rolling_input);
        let observation = actual
            .map(|value| {
                Ok::<_, io::Error>(RollingIngressObservation {
                    epoch: snapshot
                        .ok_or_else(|| invalid("Rolling observation has no runtime"))?
                        .epoch
                        .0,
                    capacity_bytes: u64::try_from(value.capacity_bytes).map_err(invalid)?,
                    allocations: u64::try_from(value.allocations).map_err(invalid)?,
                    packets: u64::try_from(value.packets).map_err(invalid)?,
                    bytes: u64::try_from(value.bytes).map_err(invalid)?,
                    oldest_received_micros: value.oldest_received.map(|tick| tick.0),
                    oldest_records_number: value.oldest_records_number,
                    deadline_micros: value.deadline.map(|tick| tick.0),
                })
            })
            .transpose()?;
        Ok(Self {
            requested,
            effective: actual
                .map(|value| RollingIngressLimits::from_limits(value.limits))
                .transpose()?,
            observation,
            policy_switching: false,
        })
    }
}
