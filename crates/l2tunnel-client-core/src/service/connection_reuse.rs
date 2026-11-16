//! One keyed command on the retained service actor; no second runtime owner.
use super::*;
use l2tunnel::packet::FlowKey;
use l2tunnel_runtime::secure_udp::transport;

impl Handle {
    /// Submit explicit authenticated slot reuse under one unrenewed accepted cap.
    /// Exact retained keys replay before new live-state validation. Dropping a
    /// waiter never cancels the runtime protocol; cancellation is unsupported.
    pub fn reuse_connection(
        &self,
        owner: u16,
        old_key: FlowKey,
        next_key: FlowKey,
        key: RequestKey,
    ) -> Result<Accepted, SubmitError> {
        // Canonical checks allocate no history or runtime state. A valid old
        // fingerprint still replays when the selected generation later stops.
        let request = local::ConnectionReuseRequest::new(owner, old_key, next_key)
            .map_err(|_| SubmitError::InvalidConfiguration)?;
        self.submit(
            Fingerprint::ConnectionReuse(request),
            Command::ConnectionReuse(request),
            key,
        )
    }
}

pub(super) fn validate(
    state: &State,
    request: local::ConnectionReuseRequest,
) -> Result<std::time::Duration, SubmitError> {
    let Some(ObservedBackend::SecureUdpCommon(backend)) = &state.backend else {
        return Err(if state.backend.is_some() {
            SubmitError::Unsupported
        } else {
            SubmitError::State
        });
    };
    if !backend.requested.connection_reuse() {
        return Err(SubmitError::Unsupported);
    }
    let actual = backend
        .counters
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let Some(snapshot) = actual
        .as_ref()
        .filter(|value| value.running && value.connection_reuse_selected)
    else {
        return Err(SubmitError::State);
    };
    let owners = snapshot.connections.ok_or(SubmitError::Unsupported)?.owners;
    if request.owner >= owners || request.old_key == request.next_key {
        return Err(SubmitError::InvalidConfiguration);
    }
    Ok(std::time::Duration::from_millis(
        backend.requested.parameters().max_operation_ms,
    ))
}

pub(super) async fn apply(
    backend: &SecureUdpCommonBackend,
    request: local::ConnectionReuseRequest,
    deadline: Instant,
) -> Completed {
    let outcome = backend
        .switcher
        .reuse_until(
            request.owner,
            request.old_key.key(),
            request.next_key.key(),
            deadline,
        )
        .await;
    match outcome {
        Err(
            transport::ConnectionReuseError::Closed
            | transport::ConnectionReuseError::OutcomeUnknown,
        ) => Completed::OutcomeUnknown,
        outcome => Completed::ConnectionReuse {
            request,
            generation: backend.generation,
            outcome,
        },
    }
}

pub(super) fn result(
    request: local::ConnectionReuseRequest,
    accepted: Accepted,
    request_key: RequestKey,
    completed: Completed,
) -> crate::secure_udp::common_status::ConnectionReuseResult {
    use crate::secure_udp::common_status::{
        ConnectionReuseConfirmation, ConnectionReuseOutcome as Out, ConnectionReuseResult,
    };
    let generation = match &completed {
        Completed::ConnectionReuse { generation, .. } => Some(*generation),
        _ => None,
    };
    let (outcome, confirmation) = match completed {
        Completed::ConnectionReuse {
            request: actual,
            outcome,
            ..
        } if actual == request => match outcome {
            Ok(value) if value.owner == request.owner => (
                Out::Confirmed,
                Some(ConnectionReuseConfirmation {
                    old_incarnation: value.old_incarnation,
                    next_incarnation: value.next_incarnation,
                    attempt: value.attempt,
                    epoch: value.epoch.0,
                    configuration: value.configuration.0,
                }),
            ),
            Ok(_) => (Out::OutcomeUnknown, None),
            Err(error) => (
                match error {
                    transport::ConnectionReuseError::Unsupported => Out::Unsupported,
                    transport::ConnectionReuseError::Busy => Out::Busy,
                    transport::ConnectionReuseError::Invalid => Out::Invalid,
                    transport::ConnectionReuseError::Expired => Out::Expired,
                    transport::ConnectionReuseError::Protocol => Out::Protocol,
                    transport::ConnectionReuseError::Closed
                    | transport::ConnectionReuseError::OutcomeUnknown => Out::OutcomeUnknown,
                },
                None,
            ),
        },
        _ => (Out::OutcomeUnknown, None),
    };
    ConnectionReuseResult {
        request,
        generation,
        operation: accepted.operation.value(),
        request_key: request_key.value(),
        outcome,
        confirmation,
    }
}
