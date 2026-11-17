//! Selected reuse observations never infer completion or authority from a DTO.
use super::*;
use crate::local::ConnectionReuseRequest;

/// Exact actual bounded protocol phase, distinct from service Applying.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectionReusePhase {
    /// Old local admission is closed.
    Stopping,
    /// Existing old custody and crossed peer counts are still draining.
    Draining,
    /// New incarnation is installed with admission still closed.
    Installed,
    /// Genuine peer installation/final confirmation is pending.
    Activating,
    /// Actual selected runtime completed the peer exchange.
    Completed,
    /// Actual selected runtime failed; no rollback is inferred.
    Failed,
}
/// One real selected protocol operation; clocks remain the original Driver clock.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConnectionReuseOperation {
    /// Actual authenticated session/epoch/operation provenance.
    pub operation: Operation,
    /// Original exact request identities.
    pub request: ConnectionReuseRequest,
    /// Previously retained owner incarnation.
    pub old_incarnation: u64,
    /// Checked next incarnation; no new endpoint/counter reset.
    pub next_incarnation: u64,
    /// Actual current protocol phase.
    pub phase: ConnectionReusePhase,
    /// Original unrenewed cap, not a phase retry deadline.
    pub original_deadline_micros: u64,
}
/// Exact bounded runtime outcome, without peer strings or rollback claims.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectionReuseOutcome {
    /// Genuine protocol completion, with confirmation fields below.
    Confirmed,
    /// This selected composition does not install the operation.
    Unsupported,
    /// Another actual peer/control operation owns the slot.
    Busy,
    /// Bounded owner/key/preflight validation failed.
    Invalid,
    /// The original permission expired; peer rollback is not implied.
    Expired,
    /// Session/control ownership ended; peer result is unknown.
    OutcomeUnknown,
    /// Actual protocol failure; peer rollback is not implied.
    Protocol,
}
/// Genuine completed result facts copied from the runtime's return value.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConnectionReuseConfirmation {
    /// Exact retained old incarnation.
    pub old_incarnation: u64,
    /// Exact peer-confirmed activated next incarnation.
    pub next_incarnation: u64,
    /// Authenticated kind-specific peer operation attempt.
    pub attempt: u64,
    /// Actual unchanged data epoch owning this monotonic reuse.
    pub epoch: u64,
    /// Actual retained complete configuration digest.
    pub configuration: [u8; 32],
}
/// Retained shared-service completion, separate from a current runtime observation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConnectionReuseResult {
    /// Exact original request, including retained-key replays.
    pub request: ConnectionReuseRequest,
    /// Original live service generation, absent only when ownership ended before observation.
    pub generation: Option<u64>,
    /// Exact accepted service operation ordinal.
    pub operation: u64,
    /// Exact supplied idempotency key.
    pub request_key: u64,
    /// Actual bounded result; only Confirmed is success.
    pub outcome: ConnectionReuseOutcome,
    /// Present only for genuine runtime success.
    pub confirmation: Option<ConnectionReuseConfirmation>,
}
/// Optional explicit selection; omission retains existing unselected API4 bytes.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConnectionReuseStatus {
    /// Profile requested this exact negotiated protocol, not implicit reuse.
    pub requested: bool,
    /// Actual constructed controller selection; absent before a runtime report.
    pub effective: Option<bool>,
    /// Actual full capability observation; request/compiled code does not set it.
    pub capability: bool,
    /// Actual selected fixed reservation; absent before a runtime report.
    pub reserved_bytes: Option<usize>,
    /// Actual selected allocation count, separate from partial Bank totals.
    pub allocations: Option<usize>,
    /// Actual retained protocol operation; None also describes selected idle.
    pub operation: Option<ConnectionReuseOperation>,
}
impl ConnectionReuseStatus {
    pub(super) fn observe(
        profile: &crate::secure_udp::common_transaction_profile::Profile,
        info: l2tunnel_runtime::secure_udp::member::Info,
        actual: Option<&l2tunnel_runtime::secure_udp::transport::CommonSnapshot>,
    ) -> io::Result<Option<Self>> {
        use l2tunnel_runtime::secure_udp::transport as rt;
        if actual.is_some_and(|value| {
            value.connection_reuse_selected != profile.connection_reuse()
                || value.connection_reuse.is_some_and(|operation| {
                    let identity = operation.operation.identity();
                    identity.session.0 != info.binding.session.0
                        || identity.role
                            != match info.role {
                                l2tunnel_security::Role::Initiator => {
                                    l2tunnel_management::Role::Client
                                }
                                l2tunnel_security::Role::Responder => {
                                    l2tunnel_management::Role::Server
                                }
                            }
                })
        }) {
            return Err(invalid(
                "actual connection reuse selection or operation differs from authenticated session",
            ));
        }
        if !profile.connection_reuse() {
            return Ok(None);
        }
        let operation = actual
            .and_then(|value| value.connection_reuse)
            .map(|value| {
                Ok::<_, io::Error>(ConnectionReuseOperation {
                    operation: value.operation.into(),
                    request: ConnectionReuseRequest::new(
                        value.owner,
                        value.old_key,
                        value.next_key,
                    )?,
                    old_incarnation: value.old_incarnation,
                    next_incarnation: value.next_incarnation,
                    phase: match value.phase {
                        rt::ConnectionReusePhase::Stopping => ConnectionReusePhase::Stopping,
                        rt::ConnectionReusePhase::Draining => ConnectionReusePhase::Draining,
                        rt::ConnectionReusePhase::Installed => ConnectionReusePhase::Installed,
                        rt::ConnectionReusePhase::Activating => ConnectionReusePhase::Activating,
                        rt::ConnectionReusePhase::Completed => ConnectionReusePhase::Completed,
                        rt::ConnectionReusePhase::Failed => ConnectionReusePhase::Failed,
                    },
                    original_deadline_micros: value.original_deadline_micros,
                })
            })
            .transpose()?;
        Ok(Some(Self {
            requested: true,
            effective: actual.map(|value| value.connection_reuse_selected),
            capability: actual
                .and_then(|value| value.connections)
                .is_some_and(|value| value.flow_reuse),
            reserved_bytes: actual.map(|value| value.connection_reuse_reserved_bytes),
            allocations: actual.map(|value| value.connection_reuse_allocations),
            operation,
        }))
    }
}
