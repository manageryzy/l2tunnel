//! `session_list` and `session_kick` for the point-to-point server.
use super::*;
use crate::local::{Role, SessionState};

impl Handle {
    /// Server role of the retained plan.
    pub(super) fn serves(&self) -> bool {
        self.0
            .lock()
            .plan
            .as_ref()
            .is_some_and(|plan| plan.role() == Role::Server)
    }
    /// The live session, if any. `Err` when this service is not a server.
    pub(super) fn sessions(&self) -> Result<Vec<SessionState>, SubmitError> {
        if !self.serves() {
            return Err(SubmitError::Unsupported);
        }
        let (snapshot, connected_at, profile) = {
            let state = self.0.lock();
            (
                Self::snapshot_locked(&state),
                state.connected_at,
                state.profile.clone(),
            )
        };
        let Some(generation) = snapshot
            .generation
            .filter(|_| snapshot.phase == Phase::Connected)
        else {
            return Ok(Vec::new());
        };
        let peer = self
            .observation(&snapshot)
            .and_then(|observation| observation.common.map(|common| common.peer));
        let member = profile.as_ref().and_then(|name| {
            let entry = self.profiles()?.get(name).ok()??;
            let path = entry.document.options.get("--allow-key")?;
            crate::local::keys::inspect("--allow-key", path)?.public
        });
        let wire = self.metrics().and_then(|metrics| metrics.wire);
        Ok(vec![SessionState {
            generation: generation.value(),
            peer,
            connected_ms: connected_at
                .map(|at| u64::try_from(at.elapsed().as_millis()).unwrap_or(u64::MAX)),
            member,
            profile,
            sent_bytes: wire.map(|wire| wire.sent_bytes),
            received_bytes: wire.map(|wire| wire.accepted_bytes),
        }])
    }
    /// End the live server session and listen again with the same plan.
    pub fn kick(&self, key: RequestKey) -> Result<Accepted, SubmitError> {
        let state = self.0.lock();
        if key.0 <= state.last_key {
            return self.submit_locked(state, Fingerprint::Kick, Command::Disconnect, key);
        }
        let plan = state.plan.clone().ok_or(SubmitError::State)?;
        if plan.role() != Role::Server {
            return Err(SubmitError::Unsupported);
        }
        if state.backend.is_none() {
            return Err(SubmitError::State);
        }
        self.submit_locked(state, Fingerprint::Kick, Command::Reconnect(plan), key)
    }
}
