//! Shared version-5 client steps used by every local frontend (CLI and GUI),
//! so request-key selection and lost-reply classification exist once.
use super::{OperationAction, OperationReply, OperationRequest, ServiceStatus, request_operation};
use std::io;
use std::path::Path;

/// Whether a failed exchange certainly sent nothing (the connection itself failed).
pub fn unsent(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::NotFound
            | io::ErrorKind::ConnectionRefused
            | io::ErrorKind::PermissionDenied
    )
}

/// A submitted operation and the key it used.
#[derive(Debug)]
pub struct Submitted {
    /// Request key used; retrying with it reattaches to the same operation.
    pub key: u64,
    /// Service reply (accepted or refused).
    pub reply: OperationReply,
}

/// Why a submission produced no reply.
#[derive(Debug)]
pub enum SubmitFailure {
    /// Nothing was sent: the service could not be reached.
    Unreachable(io::Error),
    /// The status read that chooses the key was refused.
    Refused(Box<OperationReply>),
    /// The service offers no request key (it is closed).
    NoKey,
    /// The submission may have reached the service; its outcome is unknown.
    /// Retrying with `key` replays the original acceptance.
    OutcomeUnknown {
        /// Key of the possibly accepted submission.
        key: u64,
        /// Transport error after the request may have been sent.
        error: io::Error,
    },
}

/// Submit a keyed action. Without `key`, the service's advisory
/// `next_request_key` is read first (not a reservation: a concurrent client
/// may take it, which the service reports as `future_key` or `conflict`).
pub async fn submit(
    path: &Path,
    key: Option<u64>,
    action: impl FnOnce(u64) -> OperationAction,
) -> Result<Submitted, SubmitFailure> {
    let key = match key {
        Some(key) => key,
        None => {
            let reply = request_operation(path, &OperationRequest::new(OperationAction::Status {}))
                .await
                .map_err(SubmitFailure::Unreachable)?;
            match reply {
                OperationReply {
                    status:
                        Some(ServiceStatus {
                            next_request_key: Some(key),
                            ..
                        }),
                    ..
                } => key,
                reply if !reply.ok => return Err(SubmitFailure::Refused(Box::new(reply))),
                _ => return Err(SubmitFailure::NoKey),
            }
        }
    };
    let request = OperationRequest::new(action(key));
    match request_operation(path, &request).await {
        Ok(reply) => Ok(Submitted { key, reply }),
        Err(error) if unsent(&error) => Err(SubmitFailure::Unreachable(error)),
        Err(error) => Err(SubmitFailure::OutcomeUnknown { key, error }),
    }
}

/// Why a composite step stopped.
#[derive(Debug)]
pub enum StepFailure {
    /// No reply or a refused submission/query (see [`SubmitFailure`]).
    Submit(SubmitFailure),
    /// A query or wait was refused with this code.
    Refused(String),
    /// The operation was still running at the bound.
    Running(u64),
    /// A transport error after the operation was accepted.
    Lost(io::Error),
    /// The precondition does not hold (bounded reason).
    Precondition(String),
}

/// Submit one keyed action and wait up to `seconds` for its result.
pub async fn submit_and_wait(
    path: &Path,
    seconds: u64,
    action: impl FnOnce(u64) -> OperationAction,
) -> Result<super::OperationResult, StepFailure> {
    let submitted = submit(path, None, action)
        .await
        .map_err(StepFailure::Submit)?;
    if !submitted.reply.ok {
        return Err(StepFailure::Refused(submitted.reply.code));
    }
    let id = submitted
        .reply
        .operation
        .as_ref()
        .map(|state| state.id)
        .ok_or_else(|| StepFailure::Refused("accepted without an operation".into()))?;
    let service = submitted.reply.service;
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(seconds);
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return Err(StepFailure::Running(id));
        }
        let timeout_ms = u32::try_from(remaining.as_millis())
            .unwrap_or(u32::MAX)
            .clamp(1, super::WAIT_LIMIT_MS);
        let reply = request_operation(
            path,
            &OperationRequest::new(OperationAction::OperationWait {
                operation: id,
                timeout_ms,
                service,
            }),
        )
        .await
        .map_err(StepFailure::Lost)?;
        if let Some(result) = reply.operation.and_then(|state| state.result) {
            return Ok(result);
        }
        if reply.code != "running" {
            return Err(StepFailure::Refused(reply.code));
        }
    }
}

async fn query(path: &Path, action: OperationAction) -> Result<OperationReply, StepFailure> {
    let reply = request_operation(path, &OperationRequest::new(action))
        .await
        .map_err(|error| StepFailure::Submit(SubmitFailure::Unreachable(error)))?;
    if reply.ok {
        Ok(reply)
    } else {
        Err(StepFailure::Refused(reply.code))
    }
}

/// Result of a member revocation.
#[derive(Debug)]
pub struct Revoked {
    /// The running server profile that was edited.
    pub profile: String,
    /// Save result (`profile_applied` on success).
    pub saved: super::OperationResult,
    /// Session replacement result, when the save succeeded.
    pub replaced: Option<super::OperationResult>,
}

/// Revoke the trusted member of the running server profile (owner decision
/// 2026-11-23): save that profile with `allow_key` as its `--allow-key`
/// (revision-checked), then replace the session with it. Two keyed
/// operations; a failed save leaves the session untouched.
pub async fn revoke_member(
    path: &Path,
    allow_key: &Path,
    seconds: u64,
) -> Result<Revoked, StepFailure> {
    if !allow_key.is_absolute() {
        return Err(StepFailure::Precondition(
            "the new member key must be an absolute path the service can read".into(),
        ));
    }
    let sessions = query(path, OperationAction::SessionList {})
        .await?
        .sessions
        .unwrap_or_default();
    let name = sessions
        .first()
        .and_then(|session| session.profile.clone())
        .ok_or_else(|| {
            StepFailure::Precondition(
                "no live session from a stored profile; revoke edits that profile's --allow-key"
                    .into(),
            )
        })?;
    let entry = query(path, OperationAction::ProfileGet { name: name.clone() })
        .await?
        .profile
        .ok_or_else(|| StepFailure::Refused("no profile in the reply".into()))?;
    let mut document = entry.document;
    document
        .options
        .insert("--allow-key".into(), allow_key.display().to_string());
    let change = super::ProfileChange::Save {
        name: name.clone(),
        document,
        expected_revision: Some(entry.revision),
    };
    let saved = submit_and_wait(path, seconds, |request_key| OperationAction::Profile {
        request_key,
        change,
    })
    .await?;
    if !saved.succeeded() {
        return Ok(Revoked {
            profile: name,
            saved,
            replaced: None,
        });
    }
    let replaced = submit_and_wait(path, seconds, |request_key| {
        OperationAction::ProfileConnect {
            request_key,
            name: name.clone(),
            replace: true,
        }
    })
    .await?;
    Ok(Revoked {
        profile: name,
        saved,
        replaced: Some(replaced),
    })
}
