//! Allocation staging and atomic replacement after complete bidirectional drain.

use super::*;
use l2tunnel_flow_control::RetirementMode;

/// An opaque empty next-epoch engine, owned until commit or explicit abandonment.
/// Staging does not freeze the live engine; the authenticated transaction does.
pub struct PreparedEpoch {
    inner: Box<Staged>,
}

struct Staged {
    engine: Active,
    previous: ActiveConfig,
    prepared_at: Micros,
}

impl fmt::Debug for PreparedEpoch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PreparedEpoch")
            .field("previous_epoch", &self.inner.previous.epoch)
            .field("next_epoch", &self.inner.engine.config.epoch)
            .finish_non_exhaustive()
    }
}

/// Rejection preserves the live engine and returns the same staged allocation.
#[derive(Debug)]
pub struct EpochCommitError {
    /// The failed validation or incomplete drain proof.
    pub error: Error,
    /// Ownership for a later retry or explicit abort.
    pub prepared: PreparedEpoch,
}

impl fmt::Display for EpochCommitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.error.fmt(f)
    }
}
impl std::error::Error for EpochCommitError {}

/// Constant-size old-epoch context, with no live ledger or output capability.
///
/// Keep at most the transaction's one old reader until retirement. Accepted stale
/// controls are discarded; old user data must fail its already completed fence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RetiredEpoch {
    send_scope: Scope,
    receive_scope: Scope,
    highest_outgoing: Option<FlowId>,
    highest_incoming: Option<FlowId>,
    completed_final: Option<FinalOffset>,
    cached_final: Option<FinalOffset>,
}

impl RetiredEpoch {
    /// The old negotiated epoch, independent of outer carrier sequence numbers.
    pub fn epoch(&self) -> u64 {
        self.send_scope.epoch
    }

    /// Strictly validate an authenticated old control for discard, without effects.
    ///
    /// Unknown/future flows and conflicting latest Final/FinalAck are rejected.
    /// Older valid retired IDs require no unbounded per-flow tombstone collection.
    pub fn check_control(&self, token: &[u8]) -> Result<(), Error> {
        let message = wire::decode(token)?;
        let (scope, highest) = match message {
            Message::Open { .. } => (self.receive_scope, self.highest_incoming),
            Message::Grant(_) | Message::Release(_) => (self.send_scope, self.highest_outgoing),
            Message::Final { offset, mode } => {
                self.check_final(offset, mode, self.cached_final)?;
                (self.receive_scope, self.highest_incoming)
            }
            Message::FinalAck { offset, mode } => {
                self.check_final(offset, mode, self.completed_final)?;
                (self.send_scope, self.highest_outgoing)
            }
            Message::Record(_) => return Err(Error::WrongMessage),
        };
        if message.scope() != scope {
            return Err(Error::WrongScope);
        }
        if message.flow().0 == 0 || highest.is_none_or(|last| message.flow() > last) {
            return Err(Error::UnknownFlow);
        }
        // Exact final validation above is intentionally limited to the latest
        // serialized barrier; the immutable high-water covers all older IDs.
        Ok(())
    }

    fn check_final(
        &self,
        offset: FinalOffset,
        mode: RetirementMode,
        cached: Option<FinalOffset>,
    ) -> Result<(), Error> {
        if mode != RetirementMode::Drained {
            return Err(Error::UnsupportedRetirement);
        }
        if cached.is_some_and(|previous| previous.flow == offset.flow && previous != offset) {
            return Err(Error::FinalMismatch);
        }
        Ok(())
    }
}

impl Active {
    /// Snapshot a fully drained epoch for non-generating late-control validation.
    ///
    /// After publishing a barrier the caller must keep native admission frozen
    /// and use this reader for old controls, so retries cannot create new output.
    pub fn drained_reader(&self, external: ExternalDrain) -> Result<RetiredEpoch, Error> {
        self.check_renewal()?;
        self.check_epoch_drained(external)?;
        Ok(RetiredEpoch {
            send_scope: self.send_scope,
            receive_scope: self.receive_scope,
            highest_outgoing: self.highest_outgoing,
            highest_incoming: self.highest_incoming,
            completed_final: self.completed_final,
            cached_final: self.cached_final,
        })
    }

    /// Allocate the next epoch without changing this engine or its admission gate.
    /// Only epoch and CRC channel count may differ; the caller negotiates policy.
    pub fn prepare_epoch(&self, next: ActiveConfig, now: Micros) -> Result<PreparedEpoch, Error> {
        self.check_time(now)?;
        self.check_renewal()?;
        self.check_next_config(next)?;
        Ok(PreparedEpoch {
            inner: Box::new(Staged {
                engine: Self::new(next, self.send_scope.direction, now)?,
                previous: self.config,
                prepared_at: now,
            }),
        })
    }

    /// Atomically install a staged epoch after complete native and reliable drain.
    ///
    /// Every incoming/outgoing flow must finish its exact Final handshake, even
    /// an opened flow which never sent data. Both external counts must truthfully
    /// cover all caller-owned outputs/recovery for the old epoch. This method
    /// does not authorize a transaction or reset any outer carrier/replay counter.
    pub fn commit_epoch(
        &mut self,
        mut prepared: PreparedEpoch,
        now: Micros,
        external: ExternalDrain,
    ) -> Result<RetiredEpoch, EpochCommitError> {
        if let Err(error) = self.validate_epoch_commit(&prepared, now, external) {
            return Err(EpochCommitError { error, prepared });
        }
        let retired = match self.drained_reader(external) {
            Ok(retired) => retired,
            Err(error) => return Err(EpochCommitError { error, prepared }),
        };
        // All fallible work touches only the staged allocation. Live state is
        // replaced once, below, after both scope and ownership proofs succeeded.
        let controller = match TargetController::new(prepared.inner.engine.config.target, now) {
            Ok(controller) => controller,
            Err(error) => {
                return Err(EpochCommitError {
                    error: error.into(),
                    prepared,
                });
            }
        };
        if let Err(error) = prepared
            .inner
            .engine
            .pipeline
            .continue_ids_from(&self.pipeline)
        {
            return Err(EpochCommitError {
                error: error.into(),
                prepared,
            });
        }
        prepared.inner.engine.highest_outgoing = self.highest_outgoing;
        prepared.inner.engine.highest_incoming = self.highest_incoming;
        prepared.inner.engine.last_time = now;
        prepared.inner.engine.controller = controller;
        *self = prepared.inner.engine;
        Ok(retired)
    }

    fn check_next_config(&self, mut next: ActiveConfig) -> Result<(), Error> {
        let epoch = self
            .config
            .epoch
            .checked_add(1)
            .ok_or(Error::RenewalRequired)?;
        if next.epoch != epoch {
            return Err(Error::InvalidEpoch);
        }
        next.epoch = self.config.epoch;
        next.pipeline.flows.channels = self.config.pipeline.flows.channels;
        if next != self.config {
            return Err(Error::InvalidEpoch);
        }
        Ok(())
    }

    fn validate_epoch_commit(
        &self,
        prepared: &PreparedEpoch,
        now: Micros,
        external: ExternalDrain,
    ) -> Result<(), Error> {
        self.check_time(now)?;
        if now < prepared.inner.prepared_at {
            return Err(Error::NonMonotonicTime);
        }
        self.check_renewal()?;
        if prepared.inner.previous != self.config
            || prepared.inner.engine.send_scope.direction != self.send_scope.direction
        {
            return Err(Error::InvalidEpoch);
        }
        self.check_next_config(prepared.inner.engine.config)?;
        self.check_epoch_drained(external)?;
        if [self.highest_outgoing, self.highest_incoming]
            .into_iter()
            .flatten()
            .any(|flow| flow.0 == u64::MAX)
        {
            return Err(Error::RenewalRequired);
        }
        Ok(())
    }

    fn check_epoch_drained(&self, external: ExternalDrain) -> Result<(), Error> {
        if external.pending_outputs != 0 || external.pending_recovery_records != 0 {
            return Err(Error::ExternalPending);
        }
        let status = self.status();
        if status.queued != QueueUsage::default()
            || status.sender_retained != Credit::default()
            || status.receiver_reserved != Credit::default()
            || status.receiver_payload != Credit::default()
            || status.outgoing_flows != 0
            || status.incoming_flows != 0
            || status.pending_controls != 0
            || self.retiring.is_some()
            || !self.control_order.is_empty()
            || !self.keys.is_empty()
        {
            return Err(Error::EpochNotDrained);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
