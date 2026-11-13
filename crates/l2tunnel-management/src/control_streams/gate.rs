//! Pure admission for explicitly negotiated independent control streams.
//!
//! Authentication is supplied by the enclosing Control owner. This gate changes
//! neither legacy admission nor transaction state, and grants no retired-origin
//! or staged-origin authority.

use super::Stream;
use crate::session_control::{
    Body, Envelope, Limits, NativeReceipt, PeerBinding, ReceiptPolicy, RecoveryTag, Scope,
};
use crate::{Ingress, PacketNumber, ReplayWindow};

/// Existing strict envelope/admission errors, without a second parser grammar.
pub use crate::session_control::Error;

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
        })
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
        let replay = self.replay[stream.index()];
        let expected = replay
            .highest
            .map_or(Some(1), |number| number.0.checked_add(1))
            .ok_or(Error::Exhausted)?;
        if actual.packet.0 > expected {
            return Err(Error::Sequence);
        }
        let candidate = replay.candidate(actual.packet).map_err(Error::Legacy)?;
        self.replay[stream.index()] = candidate;
        Ok(envelope)
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
