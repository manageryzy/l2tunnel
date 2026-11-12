//! Local reload guard; distributed messaging, authentication and barriers are planned.
use l2tunnel_core::{ConfigDigest, Epoch};

/// Reload identity authenticated by the future control protocol.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Ticket {
    /// Strictly increasing attempt number within this authenticated session.
    pub attempt: u64,
    /// Next configuration generation.
    pub epoch: Epoch,
    /// Digest of canonical negotiated configuration.
    pub digest: ConfigDigest,
}

/// Local coordinator phase. CommitSent cannot safely be rolled back unilaterally.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Phase {
    /// No proposal pending.
    Stable,
    /// Staged and waiting for peer readiness and a bidirectional drain barrier.
    Prepared,
    /// Commit may have reached peer; retry or reconcile after timeout.
    CommitSent,
}

/// Guard for a single negotiated epoch transition.
/// Callers must supply authenticated peer events and real per-lane drain evidence.
/// This helper does not establish either fact itself.
pub struct ReloadGuard {
    active: Ticket,
    pending: Option<Ticket>,
    phase: Phase,
    peer_ready: bool,
    drained: bool,
    highest_attempt: u64,
}

impl ReloadGuard {
    /// Initialize at an already negotiated configuration in a fresh authenticated session.
    /// Preserve attempt high-water state across same-session transport reconnects.
    pub fn new(active: Ticket) -> Self {
        Self {
            active,
            pending: None,
            phase: Phase::Stable,
            peer_ready: false,
            drained: false,
            highest_attempt: active.attempt,
        }
    }
    /// Current locally confirmed ticket.
    pub fn active(&self) -> Ticket {
        self.active
    }
    /// Current local phase.
    pub fn phase(&self) -> Phase {
        self.phase
    }
    /// Stage the next generation; exact retries are idempotent.
    pub fn prepare(&mut self, ticket: Ticket) -> Result<(), &'static str> {
        if let Some(pending) = self.pending {
            return if pending == ticket {
                Ok(())
            } else {
                Err("conflicting proposal")
            };
        }
        if ticket.attempt <= self.highest_attempt {
            return Err("attempt was already used or is stale");
        }
        let next = self
            .active
            .epoch
            .0
            .checked_add(1)
            .ok_or("epoch exhausted")?;
        if ticket.epoch != Epoch(next) {
            return Err("proposal must use the next epoch");
        }
        self.highest_attempt = ticket.attempt;
        self.pending = Some(ticket);
        self.phase = Phase::Prepared;
        self.peer_ready = false;
        self.drained = false;
        Ok(())
    }
    fn check_pending(&self, ticket: Ticket) -> Result<(), &'static str> {
        if self.pending == Some(ticket) {
            Ok(())
        } else {
            Err("ticket mismatch")
        }
    }
    /// Record an authenticated READY for the exact pending digest and generation.
    pub fn peer_ready(&mut self, ticket: Ticket) -> Result<(), &'static str> {
        self.check_pending(ticket)?;
        self.peer_ready = true;
        Ok(())
    }
    /// Record that all local and remote old-epoch lane barriers have completed.
    pub fn drained(&mut self, ticket: Ticket) -> Result<(), &'static str> {
        self.check_pending(ticket)?;
        self.drained = true;
        Ok(())
    }
    /// Authorize COMMIT transmission. Duplicate attempts reuse the same ticket.
    pub fn commit(&mut self, ticket: Ticket) -> Result<(), &'static str> {
        self.check_pending(ticket)?;
        if !self.peer_ready || !self.drained {
            return Err("peer readiness and drain required");
        }
        self.phase = Phase::CommitSent;
        Ok(())
    }
    /// Accept authenticated COMMIT_ACK. Retiring old receive state is a runtime task.
    pub fn acknowledge(&mut self, ticket: Ticket) -> Result<(), &'static str> {
        if self.phase == Phase::Stable && self.active == ticket {
            return Ok(());
        }
        self.check_pending(ticket)?;
        if self.phase != Phase::CommitSent {
            return Err("commit not sent");
        }
        self.active = ticket;
        self.pending = None;
        self.phase = Phase::Stable;
        Ok(())
    }
    /// Abort before COMMIT only. After COMMIT, reconnect/reconcile the peer state.
    pub fn abort(&mut self, ticket: Ticket) -> Result<(), &'static str> {
        self.check_pending(ticket)?;
        if self.phase != Phase::Prepared {
            return Err("cannot roll back a possible remote commit");
        }
        self.pending = None;
        self.phase = Phase::Stable;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn ticket(epoch: u64, digest: u8) -> Ticket {
        Ticket {
            attempt: epoch,
            epoch: Epoch(epoch),
            digest: ConfigDigest([digest; 32]),
        }
    }
    #[test]
    fn readiness_drain_and_matching_digest_are_required() -> Result<(), &'static str> {
        let mut guard = ReloadGuard::new(ticket(0, 1));
        let next = ticket(1, 2);
        guard.prepare(next)?;
        guard.prepare(next)?;
        assert!(guard.prepare(ticket(1, 3)).is_err());
        assert!(guard.peer_ready(ticket(1, 3)).is_err());
        assert!(guard.commit(next).is_err());
        guard.peer_ready(next)?;
        assert!(guard.commit(next).is_err());
        guard.drained(next)?;
        assert!(guard.acknowledge(next).is_err());
        guard.commit(next)?;
        assert!(guard.abort(next).is_err());
        assert_eq!(guard.active(), ticket(0, 1));
        guard.commit(next)?;
        guard.acknowledge(next)?;
        guard.acknowledge(next)?;
        assert_eq!(guard.active(), next);
        assert_eq!(guard.phase(), Phase::Stable);
        assert!(guard.prepare(next).is_err());
        Ok(())
    }
    #[test]
    fn timeout_before_commit_can_abort_and_epoch_cannot_wrap() -> Result<(), &'static str> {
        let mut guard = ReloadGuard::new(ticket(4, 1));
        assert!(guard.prepare(ticket(6, 2)).is_err());
        guard.prepare(ticket(5, 2))?;
        guard.abort(ticket(5, 2))?;
        let mut retry = ticket(5, 3);
        retry.attempt = 6;
        guard.prepare(retry)?;
        let mut exhausted = ReloadGuard::new(ticket(u64::MAX, 1));
        assert!(exhausted.prepare(ticket(0, 2)).is_err());
        Ok(())
    }
    #[test]
    fn aborted_attempt_cannot_confirm_a_retry() -> Result<(), &'static str> {
        let mut guard = ReloadGuard::new(ticket(0, 1));
        let old = ticket(1, 2);
        guard.prepare(old)?;
        guard.abort(old)?;
        assert!(guard.prepare(old).is_err());
        let next = Ticket { attempt: 2, ..old };
        guard.prepare(next)?;
        assert!(guard.peer_ready(old).is_err());
        assert!(guard.drained(old).is_err());
        guard.peer_ready(next)?;
        assert!(guard.commit(next).is_err());
        Ok(())
    }
}
