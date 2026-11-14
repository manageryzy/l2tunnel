//! Read-only staging intents; actual admission and storage remain separate owners.

use super::{Configuration, Error, Identity, Peer, Phase, Tick};
use crate::{Admission, Ingress, MessageKind, session_control};
use l2tunnel_session::Ticket;

/// Validated current staging intent, without operation, epoch or resource authority.
/// Actual proposal/receive calls must revalidate after real storage preparation.
pub struct Preparation<C: Configuration> {
    identity: Identity,
    ticket: Ticket,
    origin: session_control::Scope,
    expires: Tick,
    config: C,
}

impl<C: Configuration> Preparation<C> {
    /// Actual local authenticated-session identity, including endpoints and lane.
    pub fn identity(&self) -> Identity {
        self.identity
    }
    /// Exact proposed attempt, next epoch and full canonical configuration digest.
    pub fn ticket(&self) -> Ticket {
        self.ticket
    }
    /// Immutable old data origin; this is never the target digest.
    pub fn origin(&self) -> session_control::Scope {
        self.origin
    }
    /// Original caller-supplied operation cap, unchanged by preview or retry.
    pub fn expires(&self) -> Tick {
        self.expires
    }
    /// Exact canonical target value validated against the current supported catalog.
    pub fn config(&self) -> &C {
        &self.config
    }
}

impl<C: Configuration> Peer<C> {
    /// Inspect a leased local proposal without consuming time, counters or a lease.
    pub fn preview_propose_until(
        &self,
        config: &C,
        now: Tick,
        expires: Tick,
    ) -> Result<Preparation<C>, Error> {
        self.readonly_time(now)?;
        if !self.is_leased() {
            return Err(Error::LeaseRequired);
        }
        if self.operation().is_some() || self.phase != Phase::Idle {
            return Err(Error::Busy);
        }
        self.validate_new_cap(now, expires)?;
        let ticket = self.proposal_ticket(config)?;
        Ok(Preparation {
            identity: self.identity,
            ticket,
            origin: self.current_origin(),
            expires,
            config: config.clone(),
        })
    }

    /// Inspect actual inner admission and return a target only for a fresh first PREPARE.
    /// None is not semantic acceptance. Every error leaves all Peer state unchanged.
    pub fn preview_receive_until(
        &self,
        verified: Ingress,
        bytes: &[u8],
        now: Tick,
        expires: Tick,
    ) -> Result<Option<Preparation<C>>, Error> {
        self.validate_receive_cap(now, expires)?;
        // Reuse the leased physical-lane/endpoints check before generic gate inspection.
        self.verified_frame(verified, bytes)?;
        let candidate = self
            .gate
            .candidate(verified, bytes)
            .map_err(Error::Admission)?;
        let first = self.operation_frame(candidate.frame)?;
        if candidate.admission == Admission::RepeatedRequest {
            return Ok(None);
        }
        if candidate.frame.header.kind != MessageKind::Prepare {
            return Ok(None);
        }
        // A newly numbered PREPARE during an existing operation is not another target.
        let (config, _) = match first {
            Some(first) => first,
            None => return Err(Error::Unexpected),
        };
        Ok(Some(Preparation {
            identity: self.identity,
            ticket: candidate.frame.header.ticket,
            origin: self.current_origin(),
            expires,
            config,
        }))
    }

    /// Actual stored phase cap, including overdue caps; never a retry or fresh timeout.
    /// Idle final custody still retains its separate operation/session expiry.
    pub fn phase_deadline(&self) -> Option<Tick> {
        (!matches!(self.phase, Phase::Idle | Phase::Failed)).then_some(self.deadline)
    }
}

#[cfg(test)]
mod tests;
