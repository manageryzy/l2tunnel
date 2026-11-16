//! Additive API4 adapter of the sole retained keyed service command.
use super::*;
use crate::secure_udp::common_status::ConnectionReuseOutcome;

impl Handle {
    pub(super) async fn common_reuse_request(
        &self,
        request: local::ConnectionReuseRequest,
        key: u64,
    ) -> local::Response {
        let refusal = |code| Self::common_status_from(self.snapshot(), false, code);
        let Some(key) = RequestKey::new(key) else {
            return refusal("invalid_request_key");
        };
        let accepted = match self.reuse_connection(
            request.owner,
            request.old_key.key(),
            request.next_key.key(),
            key,
        ) {
            Ok(value) => value,
            Err(error) => {
                return refusal(match error {
                    SubmitError::InvalidConfiguration => "invalid_configuration",
                    SubmitError::Unsupported => "unsupported",
                    SubmitError::Busy => "busy",
                    SubmitError::Conflict => "conflict",
                    SubmitError::FutureKey => "future_key",
                    SubmitError::Expired => "expired_key",
                    SubmitError::State => "state",
                    SubmitError::Closed => "closed",
                });
            }
        };
        let completed = self
            .wait(accepted.operation)
            .await
            .unwrap_or(Completed::OutcomeUnknown);
        let result = connection_reuse::result(request, accepted, key, completed);
        let code = match result.outcome {
            ConnectionReuseOutcome::Confirmed => "ok",
            ConnectionReuseOutcome::Unsupported => "unsupported",
            ConnectionReuseOutcome::Busy => "busy",
            ConnectionReuseOutcome::Invalid => "invalid_configuration",
            ConnectionReuseOutcome::Expired => "expired",
            ConnectionReuseOutcome::OutcomeUnknown => "outcome_unknown",
            ConnectionReuseOutcome::Protocol => "protocol",
        };
        let mut response = Self::common_status_from(
            self.snapshot(),
            result.outcome == ConnectionReuseOutcome::Confirmed,
            code,
        );
        if let Some(status) = response
            .state
            .as_mut()
            .and_then(|value| value.common.as_mut())
        {
            status.connection_reuse_result = Some(Box::new(result));
        } else {
            response.ok = false;
            response.code = "status_unavailable".into();
        }
        response
    }
}
