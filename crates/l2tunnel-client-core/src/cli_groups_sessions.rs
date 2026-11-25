//! `session` and `member` commands of the grouped CLI (DGUI-11; owner
//! decision 2026-11-23: map to the point-to-point model). `member revoke` is
//! two keyed operations: save the server profile with the new trusted member
//! key (revision-checked), then replace the session with that profile.
use super::{Exit, note, result_exit};
use crate::local::{OperationResult, SessionState, client};
use std::io::{self, Write};
use std::path::Path;

/// Human session listing.
pub(super) fn write_sessions(out: &mut dyn Write, sessions: &[SessionState]) -> io::Result<()> {
    if sessions.is_empty() {
        return writeln!(out, "no live session");
    }
    for session in sessions {
        writeln!(
            out,
            "generation {} · peer {} · up {} s · profile {}",
            session.generation,
            session.peer.as_deref().unwrap_or("-"),
            session.connected_ms.map_or(0, |ms| ms / 1000),
            session.profile.as_deref().unwrap_or("-"),
        )?;
        if let Some(member) = &session.member {
            writeln!(out, "  trusted member {member}")?;
        }
        if let (Some(sent), Some(received)) = (session.sent_bytes, session.received_bytes) {
            writeln!(out, "  sent {sent} B · received {received} B")?;
        }
    }
    Ok(())
}

/// Exit class of a stopped composite step.
fn step_exit(failure: client::StepFailure) -> Exit {
    match failure {
        client::StepFailure::Submit(client::SubmitFailure::Unreachable(error)) => {
            note(format!("service unavailable: {error}"));
            Exit::Unreachable
        }
        client::StepFailure::Submit(client::SubmitFailure::Refused(reply)) => {
            note(format!("refused: {}", reply.code));
            super::refusal_exit(&reply.code)
        }
        client::StepFailure::Submit(client::SubmitFailure::NoKey) => Exit::Unreachable,
        client::StepFailure::Submit(client::SubmitFailure::OutcomeUnknown { key, error }) => {
            note(format!("outcome unknown ({error}); request key {key}"));
            Exit::Unknown
        }
        client::StepFailure::Refused(code) => {
            note(format!("refused: {code}"));
            super::refusal_exit(&code)
        }
        client::StepFailure::Running(id) => {
            note(format!(
                "operation {id} still running; operation watch {id}"
            ));
            Exit::Running
        }
        client::StepFailure::Lost(error) => {
            note(format!("service lost after acceptance: {error}"));
            Exit::Unknown
        }
        client::StepFailure::Precondition(reason) => {
            note(reason);
            Exit::Failed
        }
    }
}

/// `member revoke --allow-key FILE`.
pub(super) async fn revoke(socket: &Path, allow_key: &Path, seconds: u64, json: bool) -> Exit {
    let revoked = match client::revoke_member(socket, allow_key, seconds).await {
        Ok(revoked) => revoked,
        Err(failure) => return step_exit(failure),
    };
    let print = |step: &str, result: &OperationResult, human: String| {
        let _written = if json {
            writeln!(
                io::stdout().lock(),
                "{}",
                serde_json::json!({ "step": step, "profile": revoked.profile, "result": result })
            )
        } else {
            writeln!(io::stdout().lock(), "{human}")
        };
    };
    let name = &revoked.profile;
    if !revoked.saved.succeeded() {
        print(
            "saved",
            &revoked.saved,
            format!("profile {name} not saved: {:?}", revoked.saved),
        );
        return Exit::Failed;
    }
    print(
        "saved",
        &revoked.saved,
        format!("profile {name} saved with the new trusted member key"),
    );
    match &revoked.replaced {
        Some(result) => {
            let human = if result.succeeded() {
                "session replaced; only the new member key is trusted".to_owned()
            } else {
                format!("profile saved, but replacing the session did not complete: {result:?}")
            };
            print("replaced", result, human);
            result_exit(result)
        }
        None => Exit::Failed,
    }
}
