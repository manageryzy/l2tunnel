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
    fn data_len(policy: P, sender: &P::Sender) -> Result<Option<usize>, rolling::Error>;
    fn encode_data(
        policy: P,
        sender: &P::Sender,
        output: &mut [u8],
    ) -> Result<usize, rolling::Error>;
    fn repair_len(
        _: P,
        id: rolling::RepairId,
        support: rolling::Support,
        extent: usize,
    ) -> Result<usize, rolling::Error> {
        rw::repair_len(id, support.end, extent)
    }
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
// Tag 6 belongs only to the forward grammar bound by the negotiated descriptor.
fn near_row(
    policy: scheduler::Policy,
    scope: rolling::Scope,
    bytes: &[u8],
) -> Result<Option<rolling::near8::Row<'_>>, rolling::Error> {
    if bytes.first() != Some(&rolling::near8::TAG) {
        return Ok(None);
    }
    if !policy.source_wire.is_near8() {
        return Err(rolling::Error::Format);
    }
    rolling::near8::inspect(policy.recovery, scope, bytes).map(Some)
}

impl CompactRecovery<scheduler::Policy> for Rolling {
    const MAXIMUM_FEEDBACK: usize = rw::MAXIMUM_FEEDBACK_BYTES;
    fn maximum_data(policy: scheduler::Policy) -> Result<usize, rolling::Error> {
        rw::maximum_data_bytes_with(policy.recovery, policy.source_wire)
    }
    fn data_len(
        policy: scheduler::Policy,
        sender: &scheduler::Sender,
    ) -> Result<Option<usize>, rolling::Error> {
        sender
            .pending_output()
            .map(|v| rw::data_len_with(policy.recovery, policy.source_wire, v))
            .transpose()
    }
    fn encode_data(
        policy: scheduler::Policy,
        sender: &scheduler::Sender,
        output: &mut [u8],
    ) -> Result<usize, rolling::Error> {
        rw::encode_data_with(
            policy.recovery,
            policy.source_wire,
            sender.pending_output().ok_or(rolling::Error::Busy)?,
            output,
        )
    }
    fn repair_len(
        policy: scheduler::Policy,
        id: rolling::RepairId,
        support: rolling::Support,
        extent: usize,
    ) -> Result<usize, rolling::Error> {
        rw::repair_len_with(policy.recovery, policy.source_wire, id, support, extent)
    }
    fn feedback_len(receiver: &scheduler::Receiver) -> Result<Option<usize>, rolling::Error> {
        Ok(if let Some(r) = receiver.pending_request() {
            Some(rw::gap_len(r))
        } else {
            receiver.pending_feedback().map(rw::feedback_len)
        })
    }
    fn encode_feedback(
        receiver: &scheduler::Receiver,
        output: &mut [u8],
    ) -> Result<usize, rolling::Error> {
        if let Some(request) = receiver.pending_request() {
            return receiver.encode_compact_request(request, output);
        }
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
        if let Some(row) = near_row(policy, scope, bytes)? {
            return Ok(recovery::View::Repair {
                scope: row.scope,
                end: row.id.end()?,
            });
        }
        match rw::inspect_with(policy.recovery, policy.source_wire, scope, bytes)? {
            rw::View::Data(rolling::wire::View::Source {
                scope,
                id,
                original,
            }) => Ok(recovery::View::Source {
                scope,
                id,
                original,
            }),
            rw::View::Data(rolling::wire::View::Repair(value)) => Ok(recovery::View::Repair {
                scope: value.scope,
                end: value.support.end,
            }),
            rw::View::Feedback(_) | rw::View::Gap(_) => Err(rolling::Error::Format),
        }
    }
    fn kind(
        policy: scheduler::Policy,
        scope: rolling::Scope,
        bytes: &[u8],
    ) -> Result<EmissionKind, rolling::Error> {
        if near_row(policy, scope, bytes)?.is_some() {
            return Ok(EmissionKind::Repair);
        }
        Ok(
            match rw::inspect_with(policy.recovery, policy.source_wire, scope, bytes)? {
                rw::View::Data(rolling::wire::View::Source { .. }) => {
                    EmissionKind::Source(SourceForm::SystematicFec)
                }
                rw::View::Data(rolling::wire::View::Repair(_)) => EmissionKind::Repair,
                rw::View::Feedback(_) => EmissionKind::Feedback,
                rw::View::Gap(_) if policy.source_wire.is_targeted() => EmissionKind::Feedback,
                rw::View::Gap(_) => return Err(rolling::Error::Format),
            },
        )
    }
    fn extent(
        policy: scheduler::Policy,
        scope: rolling::Scope,
        bytes: &[u8],
    ) -> Result<l2tunnel_reliable::RecoveryExtent, rolling::Error> {
        use l2tunnel_reliable::RecordKind;
        if let Some(row) = near_row(policy, scope, bytes)? {
            return recovery_extent(bytes.len(), row.bytes.len(), RecordKind::Repair);
        }
        let (kind, payload) =
            match rw::inspect_with(policy.recovery, policy.source_wire, scope, bytes)? {
                rw::View::Data(rolling::wire::View::Source { original, .. }) => {
                    (RecordKind::Systematic, original.len())
                }
                rw::View::Data(rolling::wire::View::Repair(value)) => {
                    (RecordKind::Repair, value.bytes.len())
                }
                rw::View::Feedback(_) => (RecordKind::Feedback, 0),
                rw::View::Gap(_) if policy.source_wire.is_targeted() => (RecordKind::Feedback, 0),
                rw::View::Gap(_) => return Err(rolling::Error::Format),
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
        match rw::inspect_with(policy.recovery, policy.source_wire, scope, bytes)? {
            rw::View::Feedback(value) => sender.receive_feedback(value, now),
            rw::View::Gap(request) => sender.receive_request(request, now),
            _ => return Err(rolling::Error::Format),
        }
        .map(|_| ())
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
        if let Some(row) = near_row(policy, scope, bytes)? {
            return receiver.receive_near8_until(row, received, now, cap);
        }
        let rw::View::Data(value) =
            rw::inspect_with(policy.recovery, policy.source_wire, scope, bytes)?
        else {
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
    fn data_len(
        _: research::Config,
        sender: &research::Sender,
    ) -> Result<Option<usize>, rolling::Error> {
        sender.pending_output().map(rs::data_len).transpose()
    }
    fn encode_data(
        _: research::Config,
        sender: &research::Sender,
        output: &mut [u8],
    ) -> Result<usize, rolling::Error> {
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
                end: value.equation.support.end,
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
impl Endpoint<scheduler::Policy> {
    pub(crate) fn inspect_gap_request(
        &self,
        outgoing: bool,
        bytes: &[u8],
    ) -> Result<Option<scheduler::GapRequest>, rolling::Error> {
        if self.compact_feedback_overhead.is_none() || bytes.first() != Some(&5) {
            return Ok(None);
        }
        let (policy, scope) = if outgoing {
            (self.receive_config.scheduler, self.peer_rolling_scope())
        } else {
            (self.send_config.scheduler, self.send_rolling_scope)
        };
        if !policy.source_wire.is_targeted() {
            return Ok(None);
        }
        match rw::inspect_with(policy.recovery, policy.source_wire, scope, bytes)? {
            rw::View::Gap(request) => Ok(Some(request)),
            _ => Ok(None),
        }
    }

    pub(crate) fn prepared_repair_support(
        &self,
        id: rolling::RepairId,
    ) -> Option<rolling::Support> {
        match self.sender.pending_output()? {
            scheduler::Output::Repair(row) if row.id == id => Some(row.support),
            _ => None,
        }
    }

    pub(crate) fn configure_near8(&mut self, mtu: usize, rate: u64) -> Result<(), Error> {
        if self.sender.near8_status().is_some() {
            let (_, unit_cost) = wire_charge(self.framing, 1, self.overhead)?;
            self.sender
                .configure_near8(mtu, unit_cost - 1, rate)
                .map_err(Error::Rolling)?;
        }
        Ok(())
    }

    pub(crate) fn observe_near8_capacity(
        &mut self,
        now: Tick,
        accepted: u64,
        pipeline_bytes: usize,
        serial: usize,
        primary_in_carrier: bool,
    ) -> Result<(), Error> {
        let buffers = self.packing.buffer_snapshot();
        let ordinary = pipeline_bytes
            .saturating_add(buffers.stage.remaining_bytes)
            .saturating_add(buffers.packing.source.bytes)
            .saturating_add(self.sender.ordinary_backlog_bytes(primary_in_carrier));
        self.sender
            .observe_near8_capacity_with_mux(
                rolling_tick(now),
                accepted,
                ordinary,
                serial,
                Some(pipeline_bytes),
            )
            .map_err(Error::Rolling)
    }

    pub(crate) fn near8_status(&self) -> Option<rolling::near8::Status> {
        self.sender.near8_status()
    }
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
        let feedback = matches!(bytes.first(), Some(3 | 5));
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
            let mut extent = self.with_plain_output(id, original, |plain| {
                l2tunnel_aligned::wire_extent::inspect_packed(
                    self.send_config.packing.envelope(),
                    self.send_scope,
                    receiver::SourceId(u64::from(id.0)),
                    plain,
                )
                .map_err(Error::Envelope)
            })?;
            if original.first() == Some(&0) {
                // The marker and original length are the only visible envelope
                // fields. All unit headers and bodies share one compressed block.
                extent.bytes = original.len();
                extent.envelope_bytes = 3;
                extent.container_bytes = 0;
                extent.unit_header_bytes = 0;
                extent.body_bytes = original.len().checked_sub(3).ok_or(Error::Identity)?;
            }
            Some(extent)
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
            if matches!(bytes.first(), Some(3 | 5)) {
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
