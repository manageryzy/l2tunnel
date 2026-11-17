//! Selected final union over actual rolling/research owners and packed codec state.
use super::*;
use crate::fec::research;
use record_engine::{EmissionKind, SourceForm};
use research::wire::compact as rs;
use rolling::wire::compact as rw;

#[doc(hidden)]
#[allow(missing_docs)]
pub trait CompactRecovery<P: RecoveryPolicy> {
    fn maximum_data(policy: P) -> Result<usize, rolling::Error>;
    const MAXIMUM_FEEDBACK: usize;
    fn data_len(sender: &P::Sender) -> Result<Option<usize>, rolling::Error>;
    fn encode_data(sender: &P::Sender, output: &mut [u8]) -> Result<usize, rolling::Error>;
    fn feedback_len(receiver: &P::Receiver) -> Result<Option<usize>, rolling::Error>;
    fn encode_feedback(receiver: &P::Receiver, output: &mut [u8]) -> Result<usize, rolling::Error>;
    fn inspect(
        policy: P,
        scope: rolling::Scope,
        bytes: &[u8],
    ) -> Result<recovery::View<'_>, rolling::Error>;
    fn kind(policy: P, scope: rolling::Scope, bytes: &[u8])
    -> Result<EmissionKind, rolling::Error>;
    fn extent(
        policy: P,
        scope: rolling::Scope,
        bytes: &[u8],
    ) -> Result<l2tunnel_reliable::RecoveryExtent, rolling::Error>;
    fn receive_feedback(
        policy: P,
        sender: &mut P::Sender,
        scope: rolling::Scope,
        bytes: &[u8],
        received: rolling::Tick,
        now: rolling::Tick,
    ) -> Result<(), rolling::Error>;
    fn receive(
        policy: P,
        receiver: &mut P::Receiver,
        scope: rolling::Scope,
        bytes: &[u8],
        received: rolling::Tick,
        now: rolling::Tick,
        cap: rolling::Tick,
    ) -> Result<rolling::Begin, rolling::Error>;
}
#[doc(hidden)]
pub struct Rolling;
#[doc(hidden)]
pub struct Research;
impl CompactRecovery<scheduler::Policy> for Rolling {
    const MAXIMUM_FEEDBACK: usize = rw::MAXIMUM_FEEDBACK_BYTES;
    fn maximum_data(policy: scheduler::Policy) -> Result<usize, rolling::Error> {
        rw::maximum_data_bytes(policy.recovery)
    }
    fn data_len(sender: &scheduler::Sender) -> Result<Option<usize>, rolling::Error> {
        sender.pending_output().map(rw::data_len).transpose()
    }
    fn encode_data(sender: &scheduler::Sender, output: &mut [u8]) -> Result<usize, rolling::Error> {
        rw::encode_data(sender.pending_output().ok_or(rolling::Error::Busy)?, output)
    }
    fn feedback_len(receiver: &scheduler::Receiver) -> Result<Option<usize>, rolling::Error> {
        Ok(receiver.pending_feedback().map(rw::feedback_len))
    }
    fn encode_feedback(
        receiver: &scheduler::Receiver,
        output: &mut [u8],
    ) -> Result<usize, rolling::Error> {
        rw::encode_feedback(
            receiver.pending_feedback().ok_or(rolling::Error::Busy)?,
            output,
        )
    }
    fn inspect(
        policy: scheduler::Policy,
        scope: rolling::Scope,
        bytes: &[u8],
    ) -> Result<recovery::View<'_>, rolling::Error> {
        match rw::inspect(policy.recovery, scope, bytes)? {
            rw::View::Data(rolling::wire::View::Source {
                scope,
                id,
                original,
            }) => Ok(recovery::View::Source {
                scope,
                id,
                original,
            }),
            rw::View::Data(rolling::wire::View::Repair(value)) => {
                Ok(recovery::View::Repair { scope: value.scope })
            }
            rw::View::Feedback(_) => Err(rolling::Error::Format),
        }
    }
    fn kind(
        policy: scheduler::Policy,
        scope: rolling::Scope,
        bytes: &[u8],
    ) -> Result<EmissionKind, rolling::Error> {
        Ok(match rw::inspect(policy.recovery, scope, bytes)? {
            rw::View::Data(rolling::wire::View::Source { .. }) => {
                EmissionKind::Source(SourceForm::SystematicFec)
            }
            rw::View::Data(rolling::wire::View::Repair(_)) => EmissionKind::Repair,
            rw::View::Feedback(_) => EmissionKind::Feedback,
        })
    }
    fn extent(
        policy: scheduler::Policy,
        scope: rolling::Scope,
        bytes: &[u8],
    ) -> Result<l2tunnel_reliable::RecoveryExtent, rolling::Error> {
        use l2tunnel_reliable::RecordKind;
        let (kind, payload) = match rw::inspect(policy.recovery, scope, bytes)? {
            rw::View::Data(rolling::wire::View::Source { original, .. }) => {
                (RecordKind::Systematic, original.len())
            }
            rw::View::Data(rolling::wire::View::Repair(value)) => {
                (RecordKind::Repair, value.bytes.len())
            }
            rw::View::Feedback(_) => (RecordKind::Feedback, 0),
        };
        recovery_extent(bytes.len(), payload, kind)
    }
    fn receive_feedback(
        policy: scheduler::Policy,
        sender: &mut scheduler::Sender,
        scope: rolling::Scope,
        bytes: &[u8],
        _: rolling::Tick,
        now: rolling::Tick,
    ) -> Result<(), rolling::Error> {
        let rw::View::Feedback(value) = rw::inspect(policy.recovery, scope, bytes)? else {
            return Err(rolling::Error::Format);
        };
        sender.receive_feedback(value, now).map(|_| ())
    }
    fn receive(
        policy: scheduler::Policy,
        receiver: &mut scheduler::Receiver,
        scope: rolling::Scope,
        bytes: &[u8],
        received: rolling::Tick,
        now: rolling::Tick,
        cap: rolling::Tick,
    ) -> Result<rolling::Begin, rolling::Error> {
        let rw::View::Data(value) = rw::inspect(policy.recovery, scope, bytes)? else {
            return Err(rolling::Error::Format);
        };
        receiver.receive_view_until(value, received, now, cap)
    }
}
impl CompactRecovery<research::Config> for Research {
    const MAXIMUM_FEEDBACK: usize = rs::MAXIMUM_FEEDBACK_BYTES;
    fn extent(
        policy: research::Config,
        scope: rolling::Scope,
        bytes: &[u8],
    ) -> Result<l2tunnel_reliable::RecoveryExtent, rolling::Error> {
        use l2tunnel_reliable::RecordKind;
        let (kind, payload) = match rs::inspect(policy, scope, bytes)? {
            research::wire::View::Source { original, .. } => {
                (RecordKind::Systematic, original.len())
            }
            research::wire::View::Repair(value) => (RecordKind::Repair, value.equation.bytes.len()),
            research::wire::View::Feedback(_) => (RecordKind::Feedback, 0),
        };
        recovery_extent(bytes.len(), payload, kind)
    }
    fn maximum_data(policy: research::Config) -> Result<usize, rolling::Error> {
        rs::maximum_data_bytes(policy)
    }
    fn data_len(sender: &research::Sender) -> Result<Option<usize>, rolling::Error> {
        sender.pending_output().map(rs::data_len).transpose()
    }
    fn encode_data(sender: &research::Sender, output: &mut [u8]) -> Result<usize, rolling::Error> {
        rs::encode_data(sender.pending_output().ok_or(rolling::Error::Busy)?, output)
    }
    fn feedback_len(receiver: &research::Receiver) -> Result<Option<usize>, rolling::Error> {
        Ok(receiver.pending_feedback().map(rs::feedback_len))
    }
    fn encode_feedback(
        receiver: &research::Receiver,
        output: &mut [u8],
    ) -> Result<usize, rolling::Error> {
        rs::encode_feedback(
            receiver.pending_feedback().ok_or(rolling::Error::Busy)?,
            output,
        )
    }
    fn inspect(
        policy: research::Config,
        scope: rolling::Scope,
        bytes: &[u8],
    ) -> Result<recovery::View<'_>, rolling::Error> {
        match rs::inspect(policy, scope, bytes)? {
            research::wire::View::Source {
                scope,
                id,
                original,
            } => Ok(recovery::View::Source {
                scope,
                id,
                original,
            }),
            research::wire::View::Repair(value) => Ok(recovery::View::Repair {
                scope: value.equation.scope,
            }),
            research::wire::View::Feedback(_) => Err(rolling::Error::Format),
        }
    }
    fn kind(
        policy: research::Config,
        scope: rolling::Scope,
        bytes: &[u8],
    ) -> Result<EmissionKind, rolling::Error> {
        Ok(match rs::inspect(policy, scope, bytes)? {
            research::wire::View::Source { .. } => EmissionKind::Source(SourceForm::SystematicFec),
            research::wire::View::Repair(_) => EmissionKind::Repair,
            research::wire::View::Feedback(_) => EmissionKind::Feedback,
        })
    }
    fn receive_feedback(
        policy: research::Config,
        sender: &mut research::Sender,
        scope: rolling::Scope,
        bytes: &[u8],
        received: rolling::Tick,
        now: rolling::Tick,
    ) -> Result<(), rolling::Error> {
        let research::wire::View::Feedback(value) = rs::inspect(policy, scope, bytes)? else {
            return Err(rolling::Error::Format);
        };
        sender.receive_feedback_at(value, received, now).map(|_| ())
    }
    fn receive(
        policy: research::Config,
        receiver: &mut research::Receiver,
        scope: rolling::Scope,
        bytes: &[u8],
        received: rolling::Tick,
        now: rolling::Tick,
        cap: rolling::Tick,
    ) -> Result<rolling::Begin, rolling::Error> {
        receiver.receive_view_at(rs::inspect(policy, scope, bytes)?, received, now, cap)
    }
}

fn recovery_extent(
    bytes: usize,
    payload_bytes: usize,
    kind: l2tunnel_reliable::RecordKind,
) -> Result<l2tunnel_reliable::RecoveryExtent, rolling::Error> {
    Ok(l2tunnel_reliable::RecoveryExtent {
        kind,
        bytes,
        header_bytes: bytes
            .checked_sub(payload_bytes)
            .ok_or(rolling::Error::Length)?,
        payload_bytes,
        systematic_coded_fill_bytes: 0,
    })
}
impl<P: RecoveryPolicy> DirectionConfig<P> {
    /// Selected data body ceiling with no duplicate scope/profile or packing envelope.
    pub fn compact_wire_maximum_data_bytes(self) -> Result<usize, Error> {
        self.validate()?;
        P::Compact::maximum_data(self.scheduler).map_err(Error::Rolling)
    }
    /// Independent strongly authenticated feedback body ceiling for this direction.
    pub fn compact_wire_maximum_feedback_bytes(self) -> Result<usize, Error> {
        self.validate()?;
        Ok(P::Compact::MAXIMUM_FEEDBACK)
    }
}
impl<P: RecoveryPolicy> Endpoint<P> {
    /// Read selected outgoing recovery and packed-envelope scalars using the
    /// actual directional policies. No source, feedback or custody is consumed.
    pub fn inspect_output_extent(
        &self,
        bytes: &[u8],
    ) -> Result<l2tunnel_aligned::wire_extent::OutputExtent, Error> {
        if self.compact_feedback_overhead.is_none() {
            return Err(Error::Configuration);
        }
        let feedback = bytes.first() == Some(&3);
        let (policy, scope) = if feedback {
            (self.receive_config.scheduler, self.peer_rolling_scope())
        } else {
            (self.send_config.scheduler, self.send_rolling_scope)
        };
        let recovery = P::Compact::extent(policy, scope, bytes).map_err(Error::Rolling)?;
        let codec = if recovery.kind == l2tunnel_reliable::RecordKind::Systematic {
            let recovery::View::Source { id, original, .. } =
                self.inspect_data(bytes, true).map_err(Error::Rolling)?
            else {
                return Err(Error::Identity);
            };
            Some(
                l2tunnel_aligned::wire_extent::inspect_packed(
                    self.send_config.packing.envelope(),
                    self.send_scope,
                    receiver::SourceId(u64::from(id.0)),
                    original,
                )
                .map_err(Error::Envelope)?,
            )
        } else {
            None
        };
        Ok(l2tunnel_aligned::wire_extent::OutputExtent { recovery, codec })
    }

    /// Select compact data/feedback before traffic while keeping actual owners and config.
    pub fn enable_compact_wire(&mut self, feedback_overhead: usize) -> Result<(), Error> {
        self.enable_compact_wire_with_overheads(self.overhead, feedback_overhead)
    }
    /// Validate selection without changing any nested owner or existing packet custody.
    pub fn validate_compact_wire_selection(
        &self,
        data_overhead: usize,
        feedback_overhead: usize,
    ) -> Result<(), Error> {
        if self.compact_feedback_overhead.is_some()
            || self.statistics != Statistics::default()
            || self.prepared_output.is_some()
            || self.prepared_native.is_some()
            || !self.drained()
        {
            return Err(Error::Configuration);
        }
        for (body, overhead) in [
            (
                self.send_config.compact_wire_maximum_data_bytes()?,
                data_overhead,
            ),
            (
                self.receive_config.compact_wire_maximum_feedback_bytes()?,
                feedback_overhead,
            ),
        ] {
            if let Some(mut framing) = self.framing {
                framing.outer_overhead_bytes = overhead;
                framing.geometry(body).map_err(Error::Fragment)?;
            } else {
                body.checked_add(overhead).ok_or(Error::Arithmetic)?;
            }
        }
        Ok(())
    }
    /// Select exact independent complete data and strong-feedback external charges.
    pub fn enable_compact_wire_with_overheads(
        &mut self,
        data_overhead: usize,
        feedback_overhead: usize,
    ) -> Result<(), Error> {
        self.validate_compact_wire_selection(data_overhead, feedback_overhead)?;
        self.overhead = data_overhead;
        if let Some(framing) = &mut self.framing {
            framing.outer_overhead_bytes = data_overhead;
        }
        self.compact_feedback_overhead = Some(feedback_overhead);
        Ok(())
    }
    pub(super) fn peer_rolling_scope(&self) -> rolling::Scope {
        rolling::Scope {
            direction: self.send_rolling_scope.direction ^ 1,
            ..self.send_rolling_scope
        }
    }
    /// Inspect the selected peer union before recovery mutation; this grants no authentication.
    pub fn inspect_peer(&self, bytes: &[u8]) -> Result<EmissionKind, Error> {
        if self.compact_feedback_overhead.is_some() {
            // Retiring feedback describes our local sending policy and scope.
            if bytes.first() == Some(&3) {
                return P::Compact::kind(
                    self.send_config.scheduler,
                    self.send_rolling_scope,
                    bytes,
                )
                .map_err(Error::Rolling);
            }
            return P::Compact::kind(
                self.receive_config.scheduler,
                self.peer_rolling_scope(),
                bytes,
            )
            .map_err(Error::Rolling);
        }
        match self.receive_config.scheduler.inspect(bytes) {
            Ok(recovery::View::Source { .. }) => {
                Ok(EmissionKind::Source(SourceForm::SystematicFec))
            }
            Ok(recovery::View::Repair { .. }) => Ok(EmissionKind::Repair),
            Err(error) => Err(Error::Rolling(error)),
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) fn receive<P: RecoveryPolicy>(
    compact: bool,
    policy: P,
    scope: rolling::Scope,
    receiver: &mut P::Receiver,
    bytes: &[u8],
    received: rolling::Tick,
    now: rolling::Tick,
    cap: rolling::Tick,
) -> Result<rolling::Begin, rolling::Error> {
    if compact {
        P::Compact::receive(policy, receiver, scope, bytes, received, now, cap)
    } else {
        P::receive(receiver, bytes, received, now, cap)
    }
}
pub(super) fn receive_feedback<P: RecoveryPolicy>(
    compact: bool,
    policy: P,
    scope: rolling::Scope,
    sender: &mut P::Sender,
    bytes: &[u8],
    received: rolling::Tick,
    now: rolling::Tick,
) -> Result<(), rolling::Error> {
    if compact {
        P::Compact::receive_feedback(policy, sender, scope, bytes, received, now)
    } else {
        P::receive_feedback(sender, bytes, received, now)
    }
}
impl<P: RecoveryPolicy> Endpoint<P> {
    pub(super) fn inspect_data<'a>(
        &self,
        bytes: &'a [u8],
        outgoing: bool,
    ) -> Result<recovery::View<'a>, rolling::Error> {
        let (policy, scope) = if outgoing {
            (self.send_config.scheduler, self.send_rolling_scope)
        } else {
            (self.receive_config.scheduler, self.peer_rolling_scope())
        };
        if self.compact_feedback_overhead.is_some() {
            P::Compact::inspect(policy, scope, bytes)
        } else {
            policy.inspect(bytes)
        }
    }
}
