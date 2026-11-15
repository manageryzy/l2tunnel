use super::*;
use crate::{management::Role, pipeline};
use record_engine::{EmissionKind, SourceForm};

/// Exact actual owner output namespace; source, repair and feedback never alias.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OutputId {
    /// An actual systematic original or full-byte rolling equation.
    Data(scheduler::OutputId),
    /// A reverse cumulative receipt produced by the actual rolling receiver.
    Feedback(scheduler::FeedbackId),
}
/// One retained caller-buffer output; repeat preparation does not charge twice.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PreparedOutput {
    pub(super) instance: u64,
    pub(super) serial: u64,
    /// Exact authoritative scheduler output identity.
    pub id: OutputId,
    /// Actual protected-record kind for the carrier's authenticated metadata.
    pub kind: EmissionKind,
    /// Unchanged full-width enclosing security number.
    pub security_number: u64,
    /// Exact initialized caller-buffer length.
    pub bytes: usize,
    /// Exact complete charge including the selected overhead once.
    pub wire_bytes: usize,
    /// Original native units initialized in caller witness storage.
    pub witnesses: usize,
}
/// Constant-size actual composition counters, without delivery-rate inference.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Statistics {
    /// Original native frames accepted from the one common admission policy.
    pub admitted: u64,
    /// Complete outputs explicitly acknowledged by the caller's carrier owner.
    pub handed: u64,
    /// Whole native writes explicitly acknowledged by the caller.
    pub committed: u64,
}
/// Work consumed by the two actual independent directional scheduler owners.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Step {
    /// Actual sending GF/copy/metadata work, bounded by the supplied budget.
    pub send: rolling::WorkUsed,
    /// Actual receiving work and decode/feedback result, under its own same cap.
    pub receive: scheduler::ReceiverStep,
    /// A decoded compact source atomically entered the record receiver.
    pub source_handed: bool,
}
/// One actual directional sender, receiver, compact record stage and record ledger.
///
/// Functional construction preserves the existing conservative contracts.
/// Explicit reserved construction admits and observes the same actual nested
/// codec/scheduler/scratch backing. Runtime and full shared resources stay separate.
pub struct Endpoint {
    pub(super) instance: u64,
    pub(super) config: Config,
    pub(super) digest: crate::core::ConfigDigest,
    pub(super) stream: u32,
    pub(super) send_rolling_scope: rolling::Scope,
    pub(super) stage_deadline: Option<Tick>,
    pub(super) send_config: DirectionConfig,
    pub(super) receive_config: DirectionConfig,
    pub(super) send_scope: receiver::Scope,
    pub(super) receive_scope: receiver::Scope,
    pub(super) sender: scheduler::Sender,
    pub(super) incoming: scheduler::Receiver,
    pub(super) packing: packed_sender::Sender,
    pub(super) records: receiver::Receiver,
    pub(super) source: Vec<u8>,
    pub(super) symbols: Vec<u8>,
    pub(super) overhead: usize,
    pub(super) now: Tick,
    pub(super) failure: Option<Error>,
    pub(super) statistics: Statistics,
    pub(super) prepared_output: Option<PreparedOutput>,
    pub(super) next_output: u64,
    pub(super) prepared_native: Option<PreparedNative>,
    pub(super) next_native: u64,
    pub(super) next_channel: u16,
    pub(super) usage: Option<storage::Usage>,
}
impl Endpoint {
    /// Construct real codec and rolling owners after complete scalar validation.
    /// Every tick in this composition is one injected microsecond.
    pub fn new(config: Config, context: Context, stream: u32, now: Tick) -> Result<Self, Error> {
        Self::construct(config, context, stream, now, None)
    }
    pub(super) fn construct(
        config: Config,
        context: Context,
        stream: u32,
        now: Tick,
        reserved: Option<storage::Plan>,
    ) -> Result<Self, Error> {
        config.validate()?;
        let digest = config.binding_digest(stream)?;
        if context.session == 0 || context.epoch == 0 {
            return Err(Error::Configuration);
        }
        let (send_config, receive_config, overhead) = config.local(context.role);
        let session = context.session.to_be_bytes();
        let send_direction = match context.role {
            Role::Client => receiver::Direction::InitiatorToResponder,
            Role::Server => receiver::Direction::ResponderToInitiator,
        };
        let receive_direction = match context.role {
            Role::Client => receiver::Direction::ResponderToInitiator,
            Role::Server => receiver::Direction::InitiatorToResponder,
        };
        let scope = |direction| receiver::Scope {
            session,
            epoch: crate::core::Epoch(context.epoch),
            direction,
        };
        let send_scope = scope(send_direction);
        let receive_scope = scope(receive_direction);
        let rolling_scope = |direction| rolling::Scope {
            session,
            epoch: context.epoch,
            stream,
            direction: match direction {
                receiver::Direction::InitiatorToResponder => 0,
                receiver::Direction::ResponderToInitiator => 1,
            },
        };
        let sender_plan = codec::aligned_storage::PackedSenderPlan::for_config(send_config.packing)
            .map_err(Error::Storage)?;
        let receiver_plan =
            codec::aligned_storage::ReceiverPlan::for_limits(receive_config.receiver)
                .map_err(Error::Storage)?;
        let source_bytes = send_config
            .packing
            .envelope()
            .max_source_bytes()
            .map_err(Error::Envelope)?;
        let symbol_bytes = receive_config
            .receiver
            .body
            .symbol_bytes
            .checked_mul(usize::from(receive_config.packing.max_units))
            .ok_or(Error::Arithmetic)?;
        for direction in [send_config, receive_config] {
            let c = direction.scheduler;
            for interval in [
                direction.packing.packing.hold_micros,
                direction.receiver.lifetime_ticks,
                direction.codec_stage_micros,
                c.recovery.job_ticks,
                c.recovery.debt_ticks,
                c.recovery.handoff_ticks,
                c.tail_ticks,
                c.feedback_ticks,
                config.native_stall_micros,
            ] {
                now.0.checked_add(interval).ok_or(Error::Arithmetic)?;
            }
        }
        let source = bytes(source_bytes)?;
        let symbols = bytes(symbol_bytes)?;
        let packing = packed_sender::Sender::new_reserved(
            send_scope,
            send_config.packing,
            codec::aligned_storage::Limits {
                capacity_bytes: sender_plan.capacity_bytes(),
            },
        )
        .map_err(Error::Storage)?;
        let records = receiver::Receiver::new_reserved(
            receive_scope,
            receive_config.receiver,
            codec::aligned_storage::Limits {
                capacity_bytes: receiver_plan.capacity_bytes(),
            },
        )
        .map_err(Error::Storage)?;
        let sender = if let Some(plan) = reserved {
            scheduler::Sender::new_reserved(
                send_config.scheduler,
                rolling_scope(send_direction),
                rolling_tick(now),
                rolling::storage::Limits {
                    capacity_bytes: plan.sender.capacity_bytes(),
                },
            )
            .map_err(Error::RollingStorage)?
        } else {
            scheduler::Sender::new(
                send_config.scheduler,
                rolling_scope(send_direction),
                rolling_tick(now),
            )
            .map_err(Error::Rolling)?
        };
        let incoming = if let Some(plan) = reserved {
            scheduler::Receiver::new_reserved(
                receive_config.scheduler,
                rolling_scope(receive_direction),
                rolling_tick(now),
                rolling::storage::Limits {
                    capacity_bytes: plan.incoming.capacity_bytes(),
                },
            )
            .map_err(Error::RollingStorage)?
        } else {
            scheduler::Receiver::new(
                receive_config.scheduler,
                rolling_scope(receive_direction),
                rolling_tick(now),
            )
            .map_err(Error::Rolling)?
        };
        Ok(Self {
            instance: allocate_instance()?,
            config,
            digest,
            stream,
            send_rolling_scope: rolling_scope(send_direction),
            stage_deadline: None,
            send_config,
            receive_config,
            send_scope,
            receive_scope,
            sender,
            incoming,
            packing,
            records,
            source,
            symbols,
            overhead,
            now,
            failure: None,
            statistics: Statistics::default(),
            prepared_output: None,
            next_output: 1,
            prepared_native: None,
            next_native: 1,
            next_channel: 0,
            usage: None,
        })
    }
    pub(super) fn fail<T>(&mut self, error: Error) -> Result<T, Error> {
        let original = *self.failure.get_or_insert(error);
        Err(original)
    }
    pub(super) fn advance(&mut self, now: Tick) -> Result<(), Error> {
        if let Some(error) = self.failure {
            return Err(error);
        }
        if now < self.now {
            return self.fail(Error::Time);
        }
        if self.stage_deadline.is_some_and(|deadline| now >= deadline) {
            return self.fail(Error::Expired);
        }
        if self
            .prepared_native
            .is_some_and(|native| now >= native.deadline)
        {
            return self.fail(Error::Expired);
        }
        let result = (|| {
            self.sender
                .step(rolling_tick(now), rolling::WorkBudget::default())
                .map_err(Error::Rolling)?;
            self.incoming
                .step(rolling_tick(now), rolling::WorkBudget::default())
                .map_err(Error::Rolling)?;
            self.records
                .tick(receiver_tick(now))
                .map_err(Error::Receiver)?;
            self.packing.poll(now.0).map_err(Error::Sender)?;
            Ok(())
        })();
        if let Err(error) = result {
            return self.fail(error);
        }
        self.now = now;
        Ok(())
    }
    /// Stage actual already-admitted native bytes and return the body identity.
    /// A Busy result consumes no new frame/context/record; retain and retry input.
    pub fn enqueue_admitted_identified(
        &mut self,
        now: Tick,
        channel: u16,
        frame: &[u8],
    ) -> Result<Option<receiver::RecordIdentity>, Error> {
        if channel >= self.send_config.receiver.channels
            || frame.is_empty()
            || frame.len() > self.send_config.receiver.body.max_frame_bytes
        {
            return Err(Error::Configuration);
        }
        let next = self
            .statistics
            .admitted
            .checked_add(1)
            .ok_or(Error::Arithmetic)?;
        let stage_deadline = Tick(
            now.0
                .checked_add(self.send_config.codec_stage_micros)
                .ok_or(Error::Arithmetic)?,
        );
        self.advance(now)?;
        let channel = receiver::ChannelId(u8::try_from(channel).map_err(|_| Error::Configuration)?);
        let result = match self.send_config.native_policy {
            NativePolicy::EthernetHeaders => self.packing.stage_identified(channel, frame, now.0),
            NativePolicy::RawIp => self.packing.stage_raw_identified(channel, frame, now.0),
        };
        match result {
            Ok(identity) => {
                self.statistics.admitted = next;
                self.stage_deadline.get_or_insert(stage_deadline);
                Ok(Some(identity))
            }
            Err(packed_sender::Error::Busy) => Ok(None),
            Err(error) => self.fail(Error::Sender(error)),
        }
    }
    /// Commit the one actual Pipeline head only after actual codec admission.
    /// No second classifier/DRR/MUX, channel modulo or returned payload is created.
    pub fn admit_from_pipeline(
        &mut self,
        now: Tick,
        pipeline: &mut pipeline::Pipeline,
    ) -> Result<Option<pipeline::Admission<receiver::RecordIdentity>>, pipeline::DequeueError<Error>>
    {
        pipeline.offer_front_borrowed(|metadata, bytes| {
            self.enqueue_admitted_identified(now, metadata.binding.channel, bytes)
        })
    }
    /// Explicitly seal actual pending compact units; no empty source is generated.
    pub fn flush(&mut self, now: Tick) -> Result<(), Error> {
        self.advance(now)?;
        let result = self.packing.flush(now.0).map_err(Error::Sender);
        if let Err(error) = result {
            return self.fail(error);
        }
        self.pump_send(now)
    }
    fn pump_send(&mut self, now: Tick) -> Result<(), Error> {
        if !self.packing.status().packing.sealed {
            return Ok(());
        }
        let expected = rolling::SourceId(self.sender.status().encoder.next_source);
        let length = self
            .packing
            .write_pending(receiver::SourceId(u64::from(expected.0)), &mut self.source)
            .map_err(Error::Sender)?;
        match self
            .sender
            .admit_source(&self.source[..length], rolling_tick(now))
        {
            Ok(id) if id == expected => {
                let result = self.packing.commit_source().map_err(Error::Sender);
                if let Err(error) = result {
                    return self.fail(error);
                }
                if self.packing.is_idle() {
                    self.stage_deadline = None;
                }
                Ok(())
            }
            Ok(_) => self.fail(Error::Identity),
            Err(rolling::Error::Busy | rolling::Error::Capacity) => Ok(()),
            Err(error) => self.fail(Error::Rolling(error)),
        }
    }
    fn pump_receive(&mut self, now: Tick) -> Result<bool, Error> {
        if self.incoming.status().feedback_building {
            return Ok(false);
        }
        let Some((id, bytes)) = self.incoming.pending_source() else {
            return Ok(false);
        };
        let result = admit_packed(
            &mut self.records,
            self.receive_config,
            self.receive_scope,
            id,
            bytes,
            &mut self.symbols,
            now,
        );
        match result {
            Ok(()) => {
                let result = self
                    .incoming
                    .confirm_handoff(id, rolling_tick(now))
                    .map_err(Error::Rolling);
                if let Err(error) = result {
                    return self.fail(error);
                }
                Ok(true)
            }
            Err(error) if error.is_backpressure() => Ok(false),
            Err(error) => self.fail(error),
        }
    }
    /// Service each actual scheduler under the supplied independent work cap.
    /// One call hands at most one source to the compact record receiver.
    pub fn step(&mut self, now: Tick, work: rolling::WorkBudget) -> Result<Step, Error> {
        self.advance(now)?;
        self.pump_send(now)?;
        let send = self
            .sender
            .step(rolling_tick(now), work)
            .map_err(Error::Rolling)?;
        let receive = self
            .incoming
            .step(rolling_tick(now), work)
            .map_err(Error::Rolling)?;
        let source_handed = self.pump_receive(now)?;
        Ok(Step {
            send,
            receive,
            source_handed,
        })
    }
    /// Prepare one actual immutable output and reserve its exact wire debit once.
    /// Retain caller output/witnesses until confirm; AlreadyPending is returned as
    /// the same token without rewriting storage, changing PN or charging again.
    pub fn prepare_output(
        &mut self,
        now: Tick,
        security_number: u64,
        allow_data: bool,
        output: &mut [u8],
        budget: &mut OutboundBudget,
        witnesses: &mut [receiver::UnitWitness],
    ) -> Result<Option<PreparedOutput>, Error> {
        self.advance(now)?;
        if let Some(pending) = self.prepared_output {
            return Ok(Some(pending));
        }
        let (id, kind, length) = if let Some(feedback) = self.incoming.pending_feedback() {
            (
                OutputId::Feedback(feedback.id),
                EmissionKind::Feedback,
                scheduler::FEEDBACK_BYTES,
            )
        } else if allow_data {
            let Some(pending) = self.sender.pending_output() else {
                return Ok(None);
            };
            let kind = match pending {
                scheduler::Output::Source { .. } => EmissionKind::Source(SourceForm::SystematicFec),
                scheduler::Output::Repair(_) => EmissionKind::Repair,
            };
            let length = self
                .sender
                .pending_wire_len()
                .map_err(Error::Rolling)?
                .ok_or(Error::Identity)?;
            (OutputId::Data(pending.id()), kind, length)
        } else {
            return Ok(None);
        };
        if output.len() < length {
            return Err(Error::Output { required: length });
        }
        let required = if matches!(id, OutputId::Data(scheduler::OutputId::Source(_))) {
            usize::from(self.send_config.packing.max_units)
        } else {
            0
        };
        if witnesses.len() < required {
            return Err(Error::Witnesses { required });
        }
        let wire_bytes = length.checked_add(self.overhead).ok_or(Error::Arithmetic)?;
        if budget.packets == 0 || budget.wire_bytes < wire_bytes {
            return Ok(None);
        }
        let next = self.next_output.checked_add(1).ok_or(Error::Arithmetic)?;
        self.statistics
            .handed
            .checked_add(1)
            .ok_or(Error::Arithmetic)?;
        let count = match id {
            OutputId::Feedback(_) => {
                output[..length].copy_from_slice(
                    self.incoming
                        .pending_feedback_wire()
                        .ok_or(Error::Identity)?,
                );
                0
            }
            OutputId::Data(_) => {
                if self.sender.encode_pending(output).map_err(Error::Rolling)? != length {
                    return self.fail(Error::Identity);
                }
                self.outgoing_units(&output[..length], witnesses)?
            }
        };
        let pending = PreparedOutput {
            instance: self.instance,
            serial: self.next_output,
            id,
            kind,
            security_number,
            bytes: length,
            wire_bytes,
            witnesses: count,
        };
        self.next_output = next;
        self.prepared_output = Some(pending);
        budget.packets -= 1;
        budget.wire_bytes -= wire_bytes;
        Ok(Some(pending))
    }
    /// Observe the retained token without changing original output/timers.
    pub fn pending_output(&self) -> Option<PreparedOutput> {
        self.prepared_output
    }
    /// Record exactly one caller-observed complete carrier handoff, never enqueue.
    /// Physical observation is retained even if subsequent timing validation fails.
    pub fn confirm_output(&mut self, now: Tick, pending: PreparedOutput) -> Result<(), Error> {
        if self.prepared_output != Some(pending) {
            return Err(Error::Token);
        }
        let handed = self
            .statistics
            .handed
            .checked_add(1)
            .ok_or(Error::Arithmetic)?;
        let timing = self.advance(now);
        self.prepared_output = None;
        self.statistics.handed = handed;
        timing?;
        let result = match pending.id {
            OutputId::Data(id) => self.sender.confirm_output(id, rolling_tick(now)),
            OutputId::Feedback(id) => self.incoming.confirm_feedback(id, rolling_tick(now)),
        }
        .map_err(Error::Rolling);
        if let Err(error) = result {
            return self.fail(error);
        }
        Ok(())
    }
    /// Accept complete plaintext only after caller carrier authentication/replay.
    /// Busy owns no hidden input queue; the caller retains and retries exact bytes.
    pub fn accept_authenticated(
        &mut self,
        now: Tick,
        kind: EmissionKind,
        bytes: &[u8],
    ) -> Result<(), Error> {
        self.advance(now)?;
        match kind {
            EmissionKind::Feedback => {
                self.sender
                    .receive_feedback_wire(bytes, rolling_tick(now))
                    .map_err(Error::Rolling)?;
            }
            EmissionKind::Source(SourceForm::SystematicFec) | EmissionKind::Repair => {
                let observed = match rolling::wire::inspect_with(
                    self.receive_config.scheduler.recovery,
                    self.receive_config.scheduler.source_wire,
                    bytes,
                )
                .map_err(Error::Rolling)?
                {
                    rolling::wire::View::Source { .. } => {
                        EmissionKind::Source(SourceForm::SystematicFec)
                    }
                    rolling::wire::View::Repair(_) => EmissionKind::Repair,
                };
                if observed != kind {
                    return Err(Error::Identity);
                }
                self.incoming
                    .receive_wire(bytes, rolling_tick(now))
                    .map_err(Error::Rolling)?;
            }
            _ => return Err(Error::Identity),
        }
        Ok(())
    }
    /// Borrow actual source witnesses; repairs contain no original native unit.
    pub fn outgoing_units(
        &self,
        packet: &[u8],
        output: &mut [receiver::UnitWitness],
    ) -> Result<usize, Error> {
        let (scope, id, original) = match rolling::wire::inspect_with(
            self.send_config.scheduler.recovery,
            self.send_config.scheduler.source_wire,
            packet,
        )
        .map_err(Error::Rolling)?
        {
            rolling::wire::View::Source {
                scope,
                id,
                original,
            } => (scope, id, original),
            rolling::wire::View::Repair(repair) => {
                if repair.scope != self.send_rolling_scope {
                    return Err(Error::Identity);
                }
                return Ok(0);
            }
        };
        if scope != self.send_rolling_scope {
            return Err(Error::Identity);
        }
        let view = packed_envelope::decode(
            self.send_config.packing.envelope(),
            self.send_scope,
            original,
        )
        .map_err(Error::Envelope)?;
        if view.identity().source.0 != u64::from(id.0) {
            return Err(Error::Identity);
        }
        if output.len() < view.len() {
            return Err(Error::Witnesses {
                required: view.len(),
            });
        }
        let mut symbol = [0u8; rolling::MAX_PAYLOAD];
        let width = self.send_config.receiver.body.symbol_bytes;
        if width > symbol.len() {
            return Err(Error::Configuration);
        }
        for (index, unit) in view.units().map_err(Error::Envelope)?.enumerate() {
            symbol[..width].fill(0);
            symbol[..unit.bytes.len()].copy_from_slice(unit.bytes);
            output[index] =
                receiver::unit_witness(unit.identity, &symbol[..width], self.send_config.receiver)
                    .map_err(Error::Receiver)?;
        }
        Ok(view.len())
    }
    /// Complete policy and exact coding stream identity requiring authentication.
    pub fn binding_digest(&self) -> crate::core::ConfigDigest {
        self.digest
    }
    /// Earliest actual original deadline; soft packing/tail triggers stay separate.
    pub fn deadline(&self) -> Option<Tick> {
        self.sender
            .deadline()
            .map(|t| Tick(t.0))
            .into_iter()
            .chain(self.stage_deadline)
            .chain(self.incoming.deadline().map(|t| Tick(t.0)))
            .chain(self.records.deadline().map(|t| Tick(t.0)))
            .chain(self.prepared_native.map(|native| native.deadline))
            .min()
    }
    /// Earliest hard expiry or actual first-unit/tail/feedback service trigger.
    pub fn wake_at(&self) -> Option<Tick> {
        self.deadline()
            .into_iter()
            .chain(self.sender.wake_at().map(|t| Tick(t.0)))
            .chain(self.incoming.wake_at().map(|t| Tick(t.0)))
            .chain(self.packing.deadline_micros().map(Tick))
            .min()
    }
    /// Service original hard bounds without performing hidden GF work.
    pub fn tick(&mut self, now: Tick) -> Result<(), Error> {
        self.advance(now)
    }
    /// Genuine pending/first-event feedback service requirement, not native delivery.
    pub fn feedback_opportunity(&self) -> Option<(Tick, usize)> {
        let status = self.incoming.status();
        if status.feedback_ready || status.feedback_building {
            Some((self.now, scheduler::FEEDBACK_BYTES))
        } else {
            status
                .feedback_due
                .map(|at| (Tick(at.0), scheduler::FEEDBACK_BYTES))
        }
    }
    /// Actual retained directional scheduler state, without inferred capability.
    pub fn sender_status(&self) -> scheduler::SenderStatus {
        self.sender.status()
    }
    /// Actual decode/feedback state, without native-delivery inference.
    pub fn receiver_status(&self) -> scheduler::ReceiverStatus {
        self.incoming.status()
    }
    /// Actual compact record/context/native custody state.
    pub fn record_status(&self) -> receiver::Status {
        self.records.status()
    }
    /// Constant-size actual local counters.
    pub fn statistics(&self) -> Statistics {
        self.statistics
    }
    /// First terminal local composition failure, if any.
    pub fn failure(&self) -> Option<Error> {
        self.failure
    }
    /// Whether real local stages, confirmed debt and native custody are empty.
    pub fn drained(&self) -> bool {
        let send = self.sender.status();
        let receive = self.incoming.status();
        let records = self.records.status();
        self.failure.is_none()
            && self.packing.is_idle()
            && self.prepared_output.is_none()
            && self.prepared_native.is_none()
            && !send.output_ready
            && send.regular_due == 0
            && send.tail_remaining == 0
            && send.encoder.confirmed_prefix == send.encoder.next_source
            && !receive.decoder.pending_job
            && receive.decoder.handoff_prefix == receive.decoder.observed_end
            && !receive.feedback_building
            && !receive.feedback_ready
            && receive.feedback_events == 0
            && receive.feedback_due.is_none()
            && records.retained_records == 0
            && records.retained_sources == 0
            && records.pending_bytes.is_none()
    }
}

fn admit_packed(
    records: &mut receiver::Receiver,
    config: DirectionConfig,
    scope: receiver::Scope,
    id: rolling::SourceId,
    bytes: &[u8],
    symbols: &mut [u8],
    now: Tick,
) -> Result<(), Error> {
    let view = packed_envelope::decode(config.packing.envelope(), scope, bytes)
        .map_err(Error::Envelope)?;
    if view.identity().source.0 != u64::from(id.0)
        || Some(view.identity().first_unit) != records.status().source_floor
    {
        return Err(Error::Identity);
    }
    let mut inputs: [receiver::AuthenticatedSymbol<'_>; 255] =
        std::array::from_fn(|_| receiver::AuthenticatedSymbol {
            identity: receiver::SymbolIdentity {
                scope,
                source: receiver::SourceId(0),
                record: receiver::RecordId(0),
            },
            bytes: &[],
        });
    let mut count = 0;
    for (unit, symbol) in view
        .units()
        .map_err(Error::Envelope)?
        .zip(symbols.chunks_exact_mut(config.receiver.body.symbol_bytes))
    {
        symbol.fill(0);
        symbol[..unit.bytes.len()].copy_from_slice(unit.bytes);
        if config.native_policy == NativePolicy::RawIp {
            let raw = symbol[3] == 2;
            let fragment = symbol[3] == 4 && (symbol[6..8] != [0, 0] || symbol[8] == 2);
            if !raw && !fragment {
                return Err(Error::Policy);
            }
        }
        inputs[count] = receiver::AuthenticatedSymbol {
            identity: unit.identity,
            bytes: symbol,
        };
        count += 1;
    }
    if count != view.len() {
        return Err(Error::Identity);
    }
    let mut outcomes = [receiver::Admission::Accepted; 255];
    let admitted = records
        .admit_validated_batch_authenticated_into(
            &inputs[..count],
            receiver_tick(now),
            &mut outcomes[..count],
        )
        .map_err(Error::Receiver)?;
    if admitted != count
        || outcomes[..count]
            .iter()
            .any(|a| *a != receiver::Admission::Accepted)
    {
        return Err(Error::Identity);
    }
    Ok(())
}
