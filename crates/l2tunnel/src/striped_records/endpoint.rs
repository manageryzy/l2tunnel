use super::{
    Direction,
    native::{NativeReceiver, NativeSender},
};
use crate::{
    codec::{aligned_receiver as records, packed_envelope},
    core::Epoch,
    fec::{
        self, GenerationId,
        mixed_datagram::GroupShape,
        striped_group::{
            ReceiveAdmission,
            feedback::Feedback,
            schedule::{DataToken, ScheduledReceiver, ScheduledSender},
        },
    },
    management::Role,
    record_engine::{
        Context, Emission, EmissionKind, Error, NativeStep, ObservedProfileIdentity,
        ProfileIdentity, SourceForm, Tick,
    },
    reliable::OutboundBudget,
    rolling_records::fin_order::Guard,
};
use l2tunnel_core::bounded_index::Index;
use std::collections::VecDeque;

mod storage;
pub(crate) use storage::StoragePlan;

#[derive(Copy, Clone)]
enum Physical {
    Data(DataToken),
    Feedback(Feedback),
}

/// The common engine supplies its one MUX, protected carrier and completion clock.
pub(crate) struct Endpoint {
    send: Direction,
    receive: Direction,
    send_scope: records::Scope,
    receive_scope: records::Scope,
    packing: NativeSender,
    records: NativeReceiver,
    sender: ScheduledSender,
    receiver: ScheduledReceiver,
    guard: Guard,
    scratch: Vec<u8>,
    split: Vec<u8>,
    waiting: VecDeque<GenerationId>,
    queued: Index<GenerationId, ()>,
    runnable: usize,
    pending: Option<(Emission, Physical)>,
    packing_blocked: bool,
    native_due: Option<Tick>,
    clock: Tick,
}

impl Endpoint {
    pub(crate) fn new(
        forward: Direction,
        reverse: Direction,
        context: Context,
        now: Tick,
    ) -> Result<Self, Error> {
        use records::Direction::{InitiatorToResponder, ResponderToInitiator};
        let (send, receive, tx, rx) = match context.role {
            Role::Client => (forward, reverse, InitiatorToResponder, ResponderToInitiator),
            Role::Server => (reverse, forward, ResponderToInitiator, InitiatorToResponder),
        };
        let scope = |direction| records::Scope {
            session: context.session.to_be_bytes(),
            epoch: Epoch(context.epoch),
            direction,
        };
        let send_scope = scope(tx);
        let receive_scope = scope(rx);
        let packing = NativeSender::new(send, send_scope).map_err(Error::StripedNative)?;
        let records = NativeReceiver::new(receive, receive_scope).map_err(Error::StripedNative)?;
        let reserve_error = storage::fec_storage_error;
        let plan = fec::striped_group::TransmitPlan::for_window(send.profile, send.source_limit)
            .map_err(reserve_error)?;
        let limits = fec::storage::Limits {
            capacity_bytes: plan.capacity_bytes(),
        };
        let sender = ScheduledSender::new_reserved_custody(
            plan,
            limits,
            send.context(send_scope),
            send.first,
            send.hold_micros,
            now.0,
            send.timing,
        )
        .map_err(reserve_error)?;
        let receiver = ScheduledReceiver::new(
            receive.profile,
            receive.context(receive_scope),
            receive.first,
            now.0,
            receive.source_limit,
            receive.expanded_limit,
            receive.timing,
        )
        .map_err(Error::Striped)?;
        let mut waiting = VecDeque::new();
        waiting
            .try_reserve_exact(receive.source_limit)
            .map_err(|_| Error::Striped(fec::Error::Capacity))?;
        if waiting.capacity() != receive.source_limit {
            return Err(Error::Invariant);
        }
        let queued =
            Index::new(receive.source_limit).map_err(|_| Error::Striped(fec::Error::Capacity))?;
        Ok(Self {
            send,
            receive,
            send_scope,
            receive_scope,
            packing,
            records,
            sender,
            receiver,
            guard: Guard::for_mixed(receive.native_policy, receive.receiver)
                .map_err(Error::Rolling)?,
            scratch: super::scratch(receive.profile.max_body_bytes)
                .map_err(Error::StripedNative)?,
            split: super::scratch(
                fec::striped_group::original_limit(send.profile).map_err(Error::Striped)?,
            )
            .map_err(Error::StripedNative)?,
            waiting,
            queued,
            runnable: 0,
            pending: None,
            packing_blocked: false,
            native_due: None,
            clock: now,
        })
    }

    pub(crate) fn enqueue_admitted_observed(
        &mut self,
        now: Tick,
        channel: u16,
        frame: &[u8],
    ) -> Result<Option<ObservedProfileIdentity>, Error> {
        let channel = records::ChannelId(u8::try_from(channel).map_err(|_| Error::Configuration)?);
        // A fragmented predecessor can still occupy the sole native staging
        // slot while its first Packed source is ready for recovery admission.
        // Advance that source before refusing a native already at the MUX head.
        if self.packing.has_staged_frame() {
            self.offer_packed_sources(now)?;
        }
        match self.packing.stage_observed(now.0, channel, frame) {
            Ok((id, encoding)) => {
                self.guard.admitted(self.send.native_policy, frame);
                Ok(Some(ObservedProfileIdentity {
                    identity: ProfileIdentity::Striped(id),
                    encoding: encoding.into(),
                }))
            }
            Err(e) if e.is_backpressure() => Ok(None),
            Err(e) => Err(Error::StripedNative(e)),
        }
    }

    fn queue(&mut self, id: GenerationId) -> Result<(), Error> {
        // Local recovery reports the group range, including already handed-off
        // systematics. Only still-unclaimed originals occupy the handoff queue.
        if self.records.admitted(id)
            || self
                .receiver
                .window()
                .pending_original(id)
                .map_err(Error::Striped)?
                .is_none()
        {
            return Ok(());
        }
        if self
            .queued
            .insert(id, ())
            .map_err(|_| Error::Striped(fec::Error::Capacity))?
            .is_none()
        {
            self.waiting.push_front(id);
            self.runnable = self.waiting.len();
        }
        Ok(())
    }

    pub(crate) fn inspect_peer(&self, body: &[u8], feedback: bool) -> Result<EmissionKind, Error> {
        if feedback {
            Feedback::decode(self.send.context(self.send_scope), body).map_err(Error::Striped)?;
            Ok(EmissionKind::Feedback)
        } else {
            self.receive.profile.inspect(body).map_err(Error::Striped)?;
            Ok(EmissionKind::Source(SourceForm::SystematicFec))
        }
    }

    pub(crate) fn accept_authenticated(
        &mut self,
        now: Tick,
        kind: EmissionKind,
        body: &[u8],
    ) -> Result<(), Error> {
        match kind {
            EmissionKind::Feedback => {
                let feedback = Feedback::decode(self.send.context(self.send_scope), body)
                    .map_err(Error::Striped)?;
                self.sender
                    .receive_feedback(now.0, feedback)
                    .map_err(Error::Striped)?;
                self.packing_blocked = false;
            }
            EmissionKind::Source(SourceForm::SystematicFec) => {
                let (shape, packet) = self.receive.profile.inspect(body).map_err(Error::Striped)?;
                let id = source_id(shape, &packet)?;
                let disposition = self
                    .receiver
                    .accept_authenticated(
                        now.0,
                        self.receive.context(self.receive_scope),
                        body,
                        &mut self.scratch,
                    )
                    .map_err(Error::Striped)?;
                if disposition == ReceiveAdmission::Accepted {
                    self.queue(id)?;
                }
            }
            _ => return Err(Error::Kind),
        }
        self.tick(now)
    }

    fn offer_packed_sources(&mut self, now: Tick) -> Result<(), Error> {
        // Offer the already available Packed sources in this turn. Restrict
        // work to one group and the codec quota so peer recovery still runs.
        // The group sender independently enforces its oldest-source deadline.
        let group = usize::from(self.send.profile.data_cells + self.send.profile.parity_cells);
        for _ in 0..self.send.packing.work_limit.min(group) {
            if self.packing_blocked {
                break;
            }
            match self.packing.pump(now.0, &mut self.sender) {
                Err(e) if e.is_backpressure() => {
                    self.packing_blocked = true;
                    break;
                }
                Err(e) => return Err(Error::StripedNative(e)),
                Ok(None) => break,
                Ok(Some(_)) => {}
            }
        }
        Ok(())
    }

    pub(crate) fn tick(&mut self, now: Tick) -> Result<(), Error> {
        if now < self.clock {
            return Err(Error::Time);
        }
        self.clock = now;
        if self.expiry_deadline().is_some_and(|due| now >= due) {
            return Err(Error::Expired);
        }
        self.offer_packed_sources(now)?;
        if let Some((base, _)) = self.receiver.poll_recovery(now.0).map_err(Error::Striped)? {
            let end = self
                .receiver
                .window()
                .group_end(base)
                .ok_or(Error::Invariant)?;
            for n in (base.0..=end.0).rev() {
                self.queue(GenerationId(n))?;
            }
        }
        for _ in 0..self.runnable.min(self.receive.packing.work_limit) {
            let id = self.waiting.pop_front().ok_or(Error::Invariant)?;
            self.runnable -= 1;
            if let Some(original) = self
                .receiver
                .window()
                .pending_original(id)
                .map_err(Error::Striped)?
            {
                match self.records.admit(now.0, id, original) {
                    Ok(()) => {}
                    Err(e) if e.is_backpressure() => {
                        self.waiting.push_back(id);
                        continue;
                    }
                    Err(e) => return Err(Error::StripedNative(e)),
                }
            }
            self.queued.remove(id);
        }
        for _ in 0..self.receive.packing.work_limit {
            let Some(id) = self.records.committable_source() else {
                break;
            };
            self.receiver
                .commit_original(now.0, id)
                .map_err(Error::Striped)?;
            self.records
                .confirm_source(id)
                .map_err(Error::StripedNative)?;
            self.runnable = self.waiting.len();
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn prepare_output(
        &mut self,
        now: Tick,
        number: u64,
        allow_data: bool,
        out: &mut [u8],
        budget: &mut OutboundBudget,
        witnesses: &mut [records::UnitWitness],
        feedback_overhead: usize,
    ) -> Result<Option<Emission>, Error> {
        if self.pending.is_some() || budget.packets == 0 {
            return Ok(None);
        }
        self.tick(now)?;
        let feedback = self
            .receiver
            .prepare_feedback(now.0)
            .map_err(Error::Striped)?;
        let (physical, kind, len, cost, count) = if let Some(message) = feedback {
            let len = message.wire_len();
            let cost = len
                .checked_add(feedback_overhead)
                .ok_or(Error::Arithmetic)?;
            if budget.wire_bytes < cost {
                return Ok(None);
            }
            message.encode(out).map_err(Error::Striped)?;
            (
                Physical::Feedback(message),
                EmissionKind::Feedback,
                len,
                cost,
                0,
            )
        } else if allow_data {
            let Some((token, body)) = self.sender.prepare_data(now.0).map_err(Error::Striped)?
            else {
                return Ok(None);
            };
            let cost = body
                .len()
                .checked_add(self.send.overhead_bytes)
                .ok_or(Error::Arithmetic)?;
            if cost > budget.wire_bytes {
                return Ok(None);
            }
            let dst = out.get_mut(..body.len()).ok_or(Error::Output {
                required: body.len(),
            })?;
            let count =
                write_witnesses(self.send, self.send_scope, body, &mut self.split, witnesses)?;
            dst.copy_from_slice(body);
            (
                Physical::Data(token),
                EmissionKind::Source(SourceForm::SystematicFec),
                body.len(),
                cost,
                count,
            )
        } else {
            return Ok(None);
        };
        let emission = Emission {
            bytes: len,
            kind,
            wire_bytes: cost,
            security_number: number,
            witnesses: count,
        };
        budget.packets -= 1;
        budget.wire_bytes -= cost;
        self.pending = Some((emission, physical));
        Ok(Some(emission))
    }

    pub(crate) fn pending_output(&self) -> Option<Emission> {
        self.pending.map(|(e, _)| e)
    }

    pub(crate) fn prepared_group_seal(&self) -> Option<fec::striped_group::GroupSeal> {
        let (_, Physical::Data(_)) = self.pending? else {
            return None;
        };
        self.sender.pending_group_seal()
    }

    pub(crate) fn prepared_data_label(
        &self,
        body: &[u8],
    ) -> Option<crate::record_engine::StripedDataLabel> {
        let (emission, Physical::Data(token)) = self.pending? else {
            return None;
        };
        if body.len() != emission.bytes {
            return None;
        }
        let (shape, packet) = self.send.profile.inspect(body).ok()?;
        let generation = packet.generation();
        let ordinal = packet.index();
        let kind = token.kind();
        use fec::striped_group::schedule::DataKind;
        match kind {
            DataKind::Fresh(member)
                if member.generation() != generation || member.ordinal() != ordinal =>
            {
                return None;
            }
            DataKind::Named(id) | DataKind::Quiet(id) if source_id(shape, &packet).ok()? != id => {
                return None;
            }
            _ => {}
        }
        Some(crate::record_engine::StripedDataLabel {
            kind,
            generation,
            ordinal,
            shape,
            threshold: packet.geometry().data_cells(),
        })
    }

    /// Exact wire credit needed for a prepared member not yet reserved for carrier output.
    pub(crate) fn ready_data_wire_bytes(&self) -> Result<Option<usize>, Error> {
        let Some(bytes) = self.sender.pending_member_bytes() else {
            return Ok(None);
        };
        if self.pending.is_some()
            || self
                .feedback_opportunity()?
                .is_some_and(|(due, _)| due <= self.clock)
        {
            return Ok(None);
        }
        bytes
            .checked_add(self.send.overhead_bytes)
            .map(Some)
            .ok_or(Error::Arithmetic)
    }

    pub(crate) fn confirm_output_at(
        &mut self,
        now: Tick,
        accepted: Tick,
        emission: Emission,
    ) -> Result<(), Error> {
        let (expected, physical) = self.pending.ok_or(Error::Token)?;
        if expected != emission {
            return Err(Error::Token);
        }
        match physical {
            Physical::Data(token) => {
                self.sender
                    .confirm_data_at(now.0, accepted.0, token, emission.wire_bytes)
            }
            Physical::Feedback(feedback) => {
                self.receiver
                    .confirm_feedback_at(now.0, accepted.0, feedback, emission.wire_bytes)
            }
        }
        .map_err(Error::Striped)?;
        self.pending = None;
        self.packing_blocked = false;
        Ok(())
    }

    pub(crate) fn prepare_native(
        &mut self,
        now: Tick,
        _channel: records::ChannelId,
        work: usize,
        deadline: Tick,
        out: &mut [u8],
    ) -> Result<NativeStep, Error> {
        self.tick(now)?;
        let policy = self.receive.native_policy;
        let guard = &self.guard;
        match self
            .records
            .prepare(
                now.0,
                work,
                |v| guard.changed(v),
                |frame, short, early| {
                    if early {
                        guard.independent_ip_decision(policy, frame, now.0, short)
                    } else {
                        records::EarlyDecision::Allow
                    }
                },
            )
            .map_err(Error::StripedNative)?
        {
            records::Prepared::Ready => {
                let pending = self.records.pending().ok_or(Error::Invariant)?;
                let len = pending.bytes.len();
                out.get_mut(..len)
                    .ok_or(Error::Output { required: len })?
                    .copy_from_slice(pending.bytes);
                let cap = self
                    .records
                    .pending_deadline()
                    .map_or(deadline, |d| Tick(d).min(deadline));
                if now >= cap {
                    return Err(Error::Expired);
                }
                self.native_due = Some(self.native_due.map_or(cap, |old| old.min(cap)));
                Ok(NativeStep::Ready {
                    identity: ProfileIdentity::Striped(records::RecordIdentity {
                        channel: pending.channel,
                        record: pending.record,
                    }),
                    bytes: len,
                    early: pending.early,
                })
            }
            records::Prepared::Idle => Ok(NativeStep::Idle),
            records::Prepared::Progress => {
                self.runnable = self.waiting.len();
                Ok(NativeStep::Progress)
            }
        }
    }

    pub(crate) fn commit_native(&mut self, now: Tick) -> Result<(), Error> {
        let delivery = self.records.pending().ok_or(Error::Token)?;
        self.guard.native_commit(
            self.receive.native_policy,
            delivery.bytes,
            delivery.early,
            now.0,
        );
        self.records
            .commit_native(now.0)
            .map_err(Error::StripedNative)?;
        self.native_due = None;
        self.runnable = self.waiting.len();
        self.tick(now)
    }

    pub(crate) fn pending_native_deadline(&self) -> Option<Tick> {
        self.native_due
    }
    pub(crate) fn expiry_deadline(&self) -> Option<Tick> {
        self.native_due
            .into_iter()
            .chain(self.packing.stage_deadline().map(Tick))
            .chain(self.records.deadline().map(Tick))
            .min()
    }
    pub(crate) fn deadline(&self) -> Option<Tick> {
        let work = self.runnable != 0 || self.records.has_custody_work();
        let packing = if self.packing_blocked {
            None
        } else {
            self.packing.next_wake().map(Tick)
        };
        self.expiry_deadline()
            .into_iter()
            .chain(packing)
            .chain(self.sender.next_wake().map(Tick))
            .chain(self.receiver.next_wake().map(Tick))
            .chain(work.then_some(self.clock))
            .min()
    }
    pub(crate) fn feedback_opportunity(&self) -> Result<Option<(Tick, usize)>, Error> {
        self.receiver
            .feedback_opportunity()
            .map(|quote| quote.map(|(at, bytes)| (Tick(at), bytes)))
            .map_err(Error::Striped)
    }
    pub(crate) fn drained(&self) -> bool {
        self.sender.retained() == 0
            && self.receiver.drained()
            && self.packing.is_idle()
            && self.records.drained()
            && self.pending.is_none()
            && self.waiting.is_empty()
    }

    pub(crate) fn source_status(&self) -> super::SourceStatus {
        let window = self.receiver.window();
        super::SourceStatus {
            send_direction: self.sender.context().direction,
            send_stream: self.send.stream,
            send_outstanding: self.sender.outstanding_sources(),
            send_retained: self.sender.retained(),
            send_formation: self.sender.group_formation(),
            send_paid: self.sender.stats(),
            feedback_paid: self.receiver.stats(),
            send_confirmed: self.sender.confirmed_through(),
            receive_stream: self.receive.stream,
            receive_confirmed: window.confirmed_through(),
            receive_frontier: window.frontier(),
            receive_sealed: window.sealed_through(),
            receive_uncommitted_in_groups: window.uncommitted_in_groups(),
            receive_uncommitted_through_sealed: window.uncommitted_through_sealed(),
        }
    }
}

fn source_id(
    shape: GroupShape,
    packet: &fec::mixed_datagram::Packet<'_>,
) -> Result<GenerationId, Error> {
    let offset = match shape {
        GroupShape::Originals(_) => u64::from(packet.index()),
        GroupShape::Split(_) => 0,
    };
    packet
        .generation()
        .0
        .checked_add(offset)
        .map(GenerationId)
        .ok_or(Error::Arithmetic)
}

fn write_witnesses(
    direction: Direction,
    scope: records::Scope,
    body: &[u8],
    scratch: &mut [u8],
    out: &mut [records::UnitWitness],
) -> Result<usize, Error> {
    let (shape, packet) = direction.profile.inspect(body).map_err(Error::Striped)?;
    let id = source_id(shape, &packet)?;
    let original = if let GroupShape::Split(n) = shape {
        let (a, b) = packet.split_original(n).map_err(Error::Striped)?;
        let dst = scratch.get_mut(..usize::from(n)).ok_or(Error::Invariant)?;
        let (first, second) = dst.split_at_mut(a.len());
        first.copy_from_slice(a);
        second.copy_from_slice(b);
        &*dst
    } else {
        packet.original()
    };
    let view = packed_envelope::decode_compact(
        direction.packing.envelope(),
        scope,
        records::SourceId(id.0),
        original,
    )
    .map_err(|_| Error::Invariant)?;
    let dest = out.get_mut(..view.len()).ok_or(Error::Output {
        required: view.len(),
    })?;
    for (slot, unit) in dest
        .iter_mut()
        .zip(view.units().map_err(|_| Error::Invariant)?)
    {
        *slot = records::unit_witness_compact(unit.identity, unit.bytes, direction.receiver)
            .map_err(|_| Error::Invariant)?;
    }
    Ok(dest.len())
}
