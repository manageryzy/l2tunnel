//! Exact optional authenticated raw ACK input selection and actual observations.
use super::*;
#[cfg(unix)]
use l2tunnel_runtime::secure_udp::transport as connection;

/// Complete independent Queue policy; separate from each independent recovery window.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConnectionIngressLimits {
    /// Actual reusable authenticated plaintext record slots.
    pub slots: u64,
    /// Complete selected Queue heap allowance.
    pub capacity_bytes: u64,
}
impl ConnectionIngressLimits {
    #[cfg(unix)]
    pub(crate) fn build(self) -> io::Result<connection::ConnectionIngressLimits> {
        if self.slots == 0 || self.capacity_bytes == 0 {
            return Err(invalid(
                "Connection ingress requires positive explicit limits",
            ));
        }
        Ok(connection::ConnectionIngressLimits {
            slots: usize::try_from(self.slots).map_err(invalid)?,
            capacity_bytes: usize::try_from(self.capacity_bytes).map_err(invalid)?,
        })
    }
    #[cfg(unix)]
    pub(crate) fn from_limits(value: connection::ConnectionIngressLimits) -> io::Result<Self> {
        Ok(Self {
            slots: u64::try_from(value.slots).map_err(invalid)?,
            capacity_bytes: u64::try_from(value.capacity_bytes).map_err(invalid)?,
        })
    }
}
fn nullable_limits<'de, D: Deserializer<'de>>(
    d: D,
) -> Result<Option<ConnectionIngressLimits>, D::Error> {
    Option::<ConnectionIngressLimits>::deserialize(d)
}
/// Both explicit role fields are required; null leaves that role unselected.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConnectionIngressPolicies {
    /// Actual initiator deferred raw ACK queue policy.
    #[serde(deserialize_with = "nullable_limits")]
    pub initiator: Option<ConnectionIngressLimits>,
    /// Actual responder deferred raw ACK queue policy.
    #[serde(deserialize_with = "nullable_limits")]
    pub responder: Option<ConnectionIngressLimits>,
}
impl ConnectionIngressPolicies {
    #[cfg(unix)]
    pub(crate) fn build(self) -> io::Result<[Option<connection::ConnectionIngressLimits>; 2]> {
        if self.initiator.is_none() && self.responder.is_none() {
            return Err(invalid(
                "empty Connection ingress selection must be omitted",
            ));
        }
        Ok([
            self.initiator
                .map(ConnectionIngressLimits::build)
                .transpose()?,
            self.responder
                .map(ConnectionIngressLimits::build)
                .transpose()?,
        ])
    }
    #[cfg(unix)]
    pub(crate) fn from_policies(
        value: [Option<connection::ConnectionIngressLimits>; 2],
    ) -> io::Result<Option<Self>> {
        if value == [None, None] {
            return Ok(None);
        }
        Ok(Some(Self {
            initiator: value[0]
                .map(ConnectionIngressLimits::from_limits)
                .transpose()?,
            responder: value[1]
                .map(ConnectionIngressLimits::from_limits)
                .transpose()?,
        }))
    }
}
/// Actual separate authenticated raw ACK queue; loss is never reliable debt.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConnectionIngressObservation {
    /// Actual managed heap retained by the queue.
    pub capacity_bytes: u64,
    /// Actual complete queued records.
    pub packets: u64,
    /// Actual initialized queued bytes.
    pub bytes: u64,
    /// Original earliest queued cap.
    pub deadline_micros: Option<u64>,
    /// Records retained after receiver pressure.
    pub retained: u64,
    /// Attempts to admit retained authenticated plaintext.
    pub retried: u64,
    /// Retained records accepted by their original collection.
    pub admitted: u64,
    /// Unreliable records dropped when the queue was full.
    pub dropped_full: u64,
    /// Unreliable records expired at their original cap.
    pub expired: u64,
}
/// Paired request and actual local queue remain separately observable.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConnectionIngressStatus {
    /// Complete paired establishment selection.
    pub requested: ConnectionIngressPolicies,
    /// Actual local queue policy, absent before a report.
    pub effective: Option<ConnectionIngressLimits>,
    /// Actual local queue observations, absent before a report.
    pub observation: Option<ConnectionIngressObservation>,
    /// This policy remains immutable during record mode switches.
    pub policy_switching: bool,
}
/// Actual selected independent cohort and source-free ACK lifecycle counters.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConnectionRecovery {
    /// Actual independent recovery owners.
    pub owners: u16,
    /// Actual implementation capability for authenticated owner reuse.
    pub flow_reuse: bool,
    /// ACKs admitted from the shared Pipeline.
    pub admitted: u64,
    /// Source-free ACK outputs prepared with one wire debit.
    pub emitted: u64,
    /// Actual whole carrier acceptances.
    pub physical_accepted: u64,
    /// Actual carrier acceptances at or after the original cap.
    pub late_physical_accepted: u64,
    /// Queued ACKs expired before output preparation.
    pub expired_before_send: u64,
    /// Authenticated ACKs retained for native delivery.
    pub received: u64,
    /// Actual whole native writes.
    pub native_written: u64,
    /// Actual native writes at or after the original arrival cap.
    pub late_native_written: u64,
}
#[cfg(unix)]
impl ConnectionRecovery {
    pub(super) fn observe(value: l2tunnel::record_engine::ConnectionSnapshot) -> Self {
        let raw = value.unreliable;
        Self {
            owners: value.owners,
            flow_reuse: value.flow_reuse,
            admitted: raw.admitted,
            emitted: raw.emitted,
            physical_accepted: raw.physical_accepted,
            late_physical_accepted: raw.late_physical_accepted,
            expired_before_send: raw.expired_before_send,
            received: raw.received,
            native_written: raw.native_written,
            late_native_written: raw.late_native_written,
        }
    }
}
#[cfg(unix)]
impl ConnectionIngressStatus {
    pub(super) fn observe(
        requested: ConnectionIngressPolicies,
        actual: Option<connection::ConnectionIngressSnapshot>,
    ) -> io::Result<Self> {
        let observation = actual
            .map(|v| {
                Ok::<_, io::Error>(ConnectionIngressObservation {
                    capacity_bytes: u64::try_from(v.capacity_bytes).map_err(invalid)?,
                    packets: u64::try_from(v.packets).map_err(invalid)?,
                    bytes: u64::try_from(v.bytes).map_err(invalid)?,
                    deadline_micros: v.deadline_micros,
                    retained: v.retained,
                    retried: v.retried,
                    admitted: v.admitted,
                    dropped_full: v.dropped_full,
                    expired: v.expired,
                })
            })
            .transpose()?;
        Ok(Self {
            requested,
            effective: actual
                .map(|v| ConnectionIngressLimits::from_limits(v.limits))
                .transpose()?,
            observation,
            policy_switching: false,
        })
    }
}
