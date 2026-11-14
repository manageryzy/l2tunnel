//! Pure admission for explicitly negotiated independent control streams.
//!
//! Authentication is supplied by the enclosing Control owner. Legacy admission
//! remains unchanged. The explicitly transaction-bound contract delegates exact
//! retired-origin retries to the leased transaction owner's current cached
//! request/reply or unaccepted terminal incoming custody. Staged readers never
//! grant originating management authority.

use std::fmt;

use super::Stream;
use crate::session_control::{
    Body, Envelope, Limits, NativeReceipt, PeerBinding, ReceiptPolicy, RecoveryTag, Scope,
};
use crate::transaction as tx;
use crate::{Ingress, PacketNumber, ReplayWindow};

/// Existing strict envelope/admission errors, without a second parser grammar.
pub use crate::session_control::Error;

/// Refusal by the stream gate or the existing transaction owner.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TransactionError {
    /// Envelope authentication, binding, grammar, origin or sequence was refused.
    Gate(Error),
    /// The transaction owner refused its lease, immutable command or semantics.
    Transaction(tx::Error),
    /// The gate and peer have not both selected the leased transaction contract.
    Contract,
}

impl fmt::Display for TransactionError {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(output, "control stream transaction error: {self:?}")
    }
}

impl std::error::Error for TransactionError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Gate(error) => Some(error),
            Self::Transaction(error) => Some(error),
            Self::Contract => None,
        }
    }
}

/// Actual data-origin policy; absence of recovery does not invent a feedback tag.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DataPolicy {
    /// Exact authenticated originating data epoch and configuration digest.
    pub scope: Scope,
    /// Actual feedback grammar and maximum payload, or no such grammar.
    pub recovery: Option<(RecoveryTag, usize)>,
    /// Actual native completion grammar, independent of recovery receipt.
    pub receipts: ReceiptPolicy,
}

/// Immutable authenticated session/control context and initial data policy.
#[derive(Clone, Copy, Debug)]
pub struct GateSettings {
    /// Full authenticated peer session, remote role and physical lane identities.
    pub binding: PeerBinding,
    /// Fixed liveness scope, never replaced by a data-origin change.
    pub control: Scope,
    /// Initially registered data-origin policy.
    pub active: DataPolicy,
    /// Complete unchanged L2SC grammar bounds.
    pub limits: Limits,
}

/// One bounded sequence owner per stream in one authenticated remote direction.
pub struct Gate {
    settings: GateSettings,
    active: DataPolicy,
    draining: Option<DataPolicy>,
    replay: [ReplayWindow; 3],
    transaction_bound: bool,
}

impl Gate {
    /// Validate all policies before creating stream-local sequence ownership.
    pub fn new(settings: GateSettings) -> Result<Self, Error> {
        settings.limits.validate()?;
        let binding = settings.binding;
        if binding.session.0 == [0; 16]
            || binding.data_lanes[0].is_none()
            || binding.data_lanes[1].is_some() && binding.data_lanes[1] == binding.data_lanes[0]
            || !binding.data_lanes.contains(&Some(binding.control_lane))
        {
            return Err(Error::Binding);
        }
        if settings.control.epoch.0 == 0 {
            return Err(Error::Limits);
        }
        validate_policy(settings.active, settings.limits)?;
        Ok(Self {
            active: settings.active,
            settings,
            draining: None,
            replay: [ReplayWindow::default(); 3],
            transaction_bound: false,
        })
    }

    /// Select management admission through the leased transaction owner only.
    /// This explicit contract does not change any legacy envelope or wire bytes.
    pub fn new_transaction_bound(settings: GateSettings) -> Result<Self, Error> {
        let mut gate = Self::new(settings)?;
        gate.transaction_bound = true;
        Ok(gate)
    }

    /// Highest admitted envelope identity in this stream only.
    pub fn highest_packet(&self, stream: Stream) -> Option<PacketNumber> {
        self.replay[stream.index()].highest
    }

    /// Register a newer data policy while retaining exactly one prior origin.
    /// The caller must first establish the actual negotiated switch authority.
    pub fn advance_scope(&mut self, next: DataPolicy) -> Result<(), Error> {
        validate_policy(next, self.settings.limits)?;
        if self.draining.is_some() {
            return Err(Error::Capacity);
        }
        if next.scope.epoch <= self.active.scope.epoch {
            return Err(Error::Scope);
        }
        self.draining = Some(self.active);
        self.active = next;
        Ok(())
    }

    /// Remove only the exact drained origin; sequences and fixed control persist.
    /// Cached transaction-reply authority must be integrated separately before
    /// using this operation for a complete runtime mode switch.
    pub fn retire_draining(&mut self, expected: Scope) -> Result<(), Error> {
        if self.draining.map(|policy| policy.scope) != Some(expected) {
            return Err(Error::Scope);
        }
        self.draining = None;
        Ok(())
    }

    /// Admit one complete unchanged L2SC envelope after Control authentication.
    /// The caller reserves bounded delivery capacity first. Every error leaves
    /// all sequence and policy state unchanged; no transaction effects occur.
    pub fn admit<'a>(
        &mut self,
        verified: Ingress,
        stream: Stream,
        input: &'a [u8],
    ) -> Result<Envelope<'a>, Error> {
        let envelope = self.authenticated_envelope(verified, input)?;
        if self.transaction_bound && matches!(envelope.body, Body::Management(_)) {
            return Err(Error::Kind);
        }
        let actual = envelope.binding;
        let binding = self.settings.binding;
        match (stream, envelope.body) {
            (Stream::Liveness, Body::Ping { .. } | Body::Pong { .. }) => {
                if actual.scope != self.settings.control {
                    return Err(Error::Scope);
                }
            }
            (Stream::Transaction, Body::Management(_) | Body::ProfileControl { .. }) => {
                self.policy(actual.scope)?;
            }
            (Stream::DataFeedback, Body::RecoveryFeedback { lane, tag, bytes }) => {
                let policy = self.policy(actual.scope)?;
                let Some((expected, maximum)) = policy.recovery else {
                    return Err(Error::FeedbackTag);
                };
                if tag != expected
                    || bytes.len() > maximum
                    || !binding.data_lanes.contains(&Some(lane))
                {
                    return Err(Error::FeedbackTag);
                }
            }
            (Stream::DataFeedback, Body::NativeReceipt { lane, receipt }) => {
                let policy = self.policy(actual.scope)?;
                if !binding.data_lanes.contains(&Some(lane)) {
                    return Err(Error::Receipt);
                }
                match (policy.receipts, receipt) {
                    (ReceiptPolicy::Cumulative, NativeReceipt::Cumulative { .. }) => {}
                    (ReceiptPolicy::Record { channels }, NativeReceipt::Record { channel, .. })
                        if channel < channels => {}
                    _ => return Err(Error::Receipt),
                }
            }
            _ => return Err(Error::Kind),
        }
        let candidate = self.sequence_candidate(stream, actual.packet)?;
        self.replay[stream.index()] = candidate;
        Ok(envelope)
    }

    /// Dispatch one authenticated Management envelope through the leased owner.
    /// The caller reserves bounded completion and outbound custody beforehand.
    /// Admission refusals leave both owners unchanged. A semantic transaction
    /// error may fail that owner; no rollback or alternative admission is allowed.
    /// Only successful dispatch commits the stream sequence. An exact cached
    /// request or retained terminal incoming reply may retry under its original
    /// expiry; neither restores a retired data policy or repeats lifecycle effects.
    pub fn receive_transaction<C: tx::Configuration>(
        &mut self,
        peer: &mut tx::Peer<C>,
        verified: Ingress,
        stream: Stream,
        input: &[u8],
        now: tx::Tick,
        expires: tx::Tick,
    ) -> Result<tx::Effects<C>, TransactionError> {
        let (command, candidate) =
            self.transaction_candidate(peer, verified, stream, input, now, expires)?;
        let effects = peer
            .receive_until(verified, command, now, expires)
            .map_err(TransactionError::Transaction)?;
        self.replay[stream.index()] = candidate;
        Ok(effects)
    }

    /// Inspect the real joint gate and Peer without committing either sequence.
    /// A returned intent requires actual target storage before effectful dispatch.
    pub fn preview_transaction<C: tx::Configuration>(
        &self,
        peer: &tx::Peer<C>,
        verified: Ingress,
        stream: Stream,
        input: &[u8],
        now: tx::Tick,
        expires: tx::Tick,
    ) -> Result<Option<tx::Preparation<C>>, TransactionError> {
        let (command, _) =
            self.transaction_candidate(peer, verified, stream, input, now, expires)?;
        peer.preview_receive_until(verified, command, now, expires)
            .map_err(TransactionError::Transaction)
    }

    fn transaction_candidate<'a, C: tx::Configuration>(
        &self,
        peer: &tx::Peer<C>,
        verified: Ingress,
        stream: Stream,
        input: &'a [u8],
        now: tx::Tick,
        expires: tx::Tick,
    ) -> Result<(&'a [u8], ReplayWindow), TransactionError> {
        if !self.transaction_bound || !peer.is_leased() {
            return Err(TransactionError::Contract);
        }
        let envelope = self
            .authenticated_envelope(verified, input)
            .map_err(TransactionError::Gate)?;
        if stream != Stream::Transaction {
            return Err(TransactionError::Gate(Error::Kind));
        }
        let Body::Management(command) = envelope.body else {
            return Err(TransactionError::Gate(Error::Kind));
        };
        let candidate = self
            .sequence_candidate(stream, envelope.binding.packet)
            .map_err(TransactionError::Gate)?;
        let retained_retry = peer
            .validate_control_origin(verified, command, envelope.binding.scope, now)
            .map_err(TransactionError::Transaction)?;
        if !retained_retry {
            self.policy(envelope.binding.scope)
                .map_err(TransactionError::Gate)?;
        }
        peer.validate_receive_until(verified, command, now, expires)
            .map_err(TransactionError::Transaction)?;
        Ok((command, candidate))
    }

    fn authenticated_envelope<'a>(
        &self,
        verified: Ingress,
        input: &'a [u8],
    ) -> Result<Envelope<'a>, Error> {
        let Ingress::AuthenticatedManagement {
            session,
            lane,
            sender,
        } = verified
        else {
            return Err(Error::Legacy(crate::Error::UntrustedOrigin));
        };
        let binding = self.settings.binding;
        if session != binding.session
            || lane != binding.control_lane
            || sender != binding.remote_role
        {
            return Err(Error::Binding);
        }
        let envelope = Envelope::decode(input, self.settings.limits)?;
        let actual = envelope.binding;
        if actual.session != session || actual.lane != lane || actual.sender != sender {
            return Err(Error::Binding);
        }
        Ok(envelope)
    }

    fn sequence_candidate(
        &self,
        stream: Stream,
        packet: PacketNumber,
    ) -> Result<ReplayWindow, Error> {
        let replay = self.replay[stream.index()];
        let expected = replay
            .highest
            .map_or(Some(1), |number| number.0.checked_add(1))
            .ok_or(Error::Exhausted)?;
        if packet.0 > expected {
            return Err(Error::Sequence);
        }
        replay.candidate(packet).map_err(Error::Legacy)
    }

    fn policy(&self, scope: Scope) -> Result<DataPolicy, Error> {
        if scope == self.active.scope {
            Ok(self.active)
        } else {
            self.draining
                .filter(|policy| policy.scope == scope)
                .ok_or(Error::Scope)
        }
    }
}

fn validate_policy(policy: DataPolicy, limits: Limits) -> Result<(), Error> {
    if policy.scope.epoch.0 == 0
        || policy
            .recovery
            .is_some_and(|(_, maximum)| maximum == 0 || maximum > limits.max_feedback_bytes)
        || matches!(policy.receipts, ReceiptPolicy::Record { channels } if !(1..=256).contains(&channels))
    {
        return Err(Error::Limits);
    }
    Ok(())
}

#[cfg(test)]
#[path = "gate_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "transaction_tests.rs"]
mod transaction_tests;
