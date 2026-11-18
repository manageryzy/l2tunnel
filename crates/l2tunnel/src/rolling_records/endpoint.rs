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
    pub(super) source_copy: Option<scheduler::SourceCopy>,
    pub(super) retry_full_credit: Option<bool>,
    pub(super) prepared_at: Tick,
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
    /// Exact whole physical packet count reserved by the selected framing.
    pub packets: usize,
    /// Original native units initialized in caller witness storage.
    pub witnesses: usize,
}
impl PreparedOutput {
    /// Exact physical-copy ordinal; this local witness is not I/O evidence.
    pub const fn source_copy(self) -> Option<scheduler::SourceCopy> {
        self.source_copy
    }
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
    /// Decode/feedback plus preview lookup, eligibility and slab-copy work,
    /// under the independent receiving cap. Existing bounded packed parsing and
    /// atomic record admission remain in the fixed packing-unit work domain.
    pub receive: scheduler::ReceiverStep,
    /// A decoded compact source atomically entered the record receiver.
    pub source_handed: bool,
    /// Atomic preview admission accepted at least one independent record unit.
    /// Work alone and duplicate/stale-only admissions do not report progress.
    pub native_progress: bool,
}
#[derive(Clone, Copy)]
struct PreviewUnit {
    identity: receiver::SymbolIdentity,
    offset: usize,
    length: usize,
    cleared: usize,
    copied: usize,
}
#[derive(Clone, Copy)]
struct Preview {
    source: rolling::SourceId,
    count: usize,
    unit: usize,
    current: Option<PreviewUnit>,
    selected: [u64; 4],
}
pub(super) struct ConstructionOptions {
    pub(super) copies: CopyPolicies,
    pub(super) ingress: Option<IngressLimits>,
    pub(super) framing: Option<OutputFraming>,
}

/// One actual directional sender, receiver, compact record stage and record ledger.
///
/// Functional construction preserves the existing conservative contracts.
/// Explicit reserved construction admits and observes the same actual nested
/// codec/scheduler/scratch backing. Runtime and full shared resources stay separate.
pub struct Endpoint<P: RecoveryPolicy = scheduler::Policy> {
    pub(super) instance: u64,
    pub(super) config: Config<P>,
    pub(super) copies: CopyPolicies,
    pub(super) digest: crate::core::ConfigDigest,
    pub(super) stream: u32,
    pub(super) send_rolling_scope: rolling::Scope,
    pub(super) stage_deadline: Option<Tick>,
    pub(super) send_config: DirectionConfig<P>,
    pub(super) receive_config: DirectionConfig<P>,
    pub(super) send_scope: receiver::Scope,
    pub(super) receive_scope: receiver::Scope,
    pub(super) sender: P::Sender,
    pub(super) repair_budget: Option<repair_budget::Budget>,
    pub(super) fin_order: fin_order::Guard,
    pub(super) incoming: P::Receiver,
    pub(super) ingress: Option<ingress::Ingress>,
    pub(super) packing: packed_sender::Sender,
    pub(super) records: receiver::Receiver,
    pub(super) source: Vec<u8>,
    pub(super) symbols: Vec<u8>,
    pub(super) overhead: usize,
    pub(super) compact_feedback_overhead: Option<usize>,
    pub(super) framing: Option<codec::FragmentConfig>,
    pub(super) now: Tick,
    pub(super) failure: Option<Error>,
    pub(super) expiry_failure: Option<expiry::LocalFailure>,
    pub(super) statistics: Statistics,
    pub(super) prepared_output: Option<PreparedOutput>,
    pub(super) next_output: u64,
    pub(super) prepared_native: Option<PreparedNative>,
    pub(super) next_native: u64,
    pub(super) next_channel: u16,
    pub(super) receive_progress: bool,
    receive_unit: Option<receiver::SourceId>,
    preview_next: u32,
    preview_end: u32,
    preview: Option<Preview>,
    preview_blocked: bool,
    preview_rescan: bool,
    pub(super) usage: Option<storage::Usage>,
    pub(super) waits: Vec<waits::Snapshot>,
}
impl<P: RecoveryPolicy> Endpoint<P> {
    /// Construct real codec and rolling owners after complete scalar validation.
    /// Every tick in this composition is one injected microsecond.
    pub fn new(config: Config<P>, context: Context, stream: u32, now: Tick) -> Result<Self, Error> {
        Self::construct(
            config,
            context,
            stream,
            now,
            None,
            ConstructionOptions {
                copies: CopyPolicies::ONE,
                ingress: None,
                framing: None,
            },
        )
    }
    /// Select complete caller-authenticated directional source-copy policies.
    pub fn new_with_copies(
        config: Config<P>,
        context: Context,
        stream: u32,
        now: Tick,
        copies: CopyPolicies,
    ) -> Result<Self, Error> {
        Self::construct(
            config,
            context,
            stream,
            now,
            None,
            ConstructionOptions {
                copies,
                ingress: None,
                framing: None,
            },
        )
    }
    /// Construct the same actual owners with explicitly authenticated output framing.
    /// The caller still encodes and physically confirms every actual fragment.
    pub fn new_with_output_framing(
        config: Config<P>,
        context: Context,
        stream: u32,
        now: Tick,
        copies: CopyPolicies,
        framing: OutputFraming,
    ) -> Result<Self, Error> {
        Self::construct(
            config,
            context,
            stream,
            now,
            None,
            ConstructionOptions {
                copies,
                ingress: None,
                framing: Some(framing),
            },
        )
    }
    /// Exact local selected fragment geometry; None retains one unfragmented packet.
    pub const fn output_fragment_config(&self) -> Option<codec::FragmentConfig> {
        self.framing
    }
    /// Actual selected fragment geometry for this data or strong-feedback arm.
    pub fn output_fragment_config_for(&self, kind: EmissionKind) -> Option<codec::FragmentConfig> {
        self.framing.map(|mut framing| {
            if kind == EmissionKind::Feedback {
                framing.outer_overhead_bytes =
                    self.compact_feedback_overhead.unwrap_or(self.overhead);
            }
            framing
        })
    }
    /// Observe exact selected policies; local observation provides no peer authority.
    pub const fn source_copy_policies(&self) -> CopyPolicies {
        self.copies
    }
    pub(super) fn construct(
        config: Config<P>,
        context: Context,
        stream: u32,
        now: Tick,
        reserved: Option<storage::Plan<P>>,
        options: ConstructionOptions,
    ) -> Result<Self, Error> {
        let ConstructionOptions {
            copies,
            ingress: ingress_limits,
            framing,
        } = options;
        copies.validate(config)?;
        let digest = if let Some(framing) = framing {
            framing.binding_digest(config, copies, stream)?
        } else {
            copies.binding_digest(config, stream)?
        };
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
        let sender_plan = send_config.packing_plan()?;
        let receiver_plan = receive_config.receiver_plan()?;
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
            let recovery = c.recovery();
            let intervals = c.intervals();
            for interval in [
                direction.packing.packing.hold_micros,
                direction.receiver.lifetime_ticks,
                direction.codec_stage_micros,
                recovery.job_ticks,
                recovery.debt_ticks,
                recovery.handoff_ticks,
                intervals[0],
                intervals[1],
                config.native_stall_micros,
            ] {
                now.0.checked_add(interval).ok_or(Error::Arithmetic)?;
            }
        }
        // Every requested input layout/limit is checked before selected allocation.
        if let Some(limits) = ingress_limits {
            limits.required_capacity(receive_config.maximum_packet_bytes()?)?;
        }
        let source = bytes(source_bytes)?;
        let symbols = bytes(symbol_bytes)?;
        let packing = (if send_config.native_policy == NativePolicy::IpHeaders {
            packed_sender::Sender::new_reserved_ip_with_copies
        } else {
            packed_sender::Sender::new_reserved_with_copies
        })(
            send_scope,
            send_config.packing,
            codec::aligned_storage::Limits {
                capacity_bytes: sender_plan.capacity_bytes(),
            },
            copies.local(context.role),
        )
        .map_err(Error::Storage)?;
        let records = (if receive_config.native_policy == NativePolicy::IpHeaders {
            receiver::Receiver::new_reserved_ip
        } else {
            receiver::Receiver::new_reserved
        })(
            receive_scope,
            receive_config.receiver,
            codec::aligned_storage::Limits {
                capacity_bytes: receiver_plan.capacity_bytes(),
            },
        )
        .map_err(Error::Storage)?;
        let sender = send_config.scheduler.new_sender(
            rolling_scope(send_direction),
            rolling_tick(now),
            reserved.map(|p| p.sender.capacity_bytes),
        )?;
        let incoming = receive_config.scheduler.new_receiver(
            rolling_scope(receive_direction),
            rolling_tick(now),
            reserved.map(|p| p.incoming.capacity_bytes),
        )?;
        let ingress = ingress_limits
            .map(|limits| ingress::Ingress::new(limits, receive_config.maximum_packet_bytes()?))
            .transpose()?;
        Ok(Self {
            instance: allocate_instance()?,
            config,
            copies,
            digest,
            stream,
            send_rolling_scope: rolling_scope(send_direction),
            stage_deadline: None,
            send_config,
            receive_config,
            send_scope,
            receive_scope,
            sender,
            fin_order: fin_order::Guard::new(receive_config)?,
            repair_budget: send_config
                .scheduler
                .targeted()
                .then(|| repair_budget::Budget::new(send_config.scheduler.recovery().window))
                .transpose()?,
            incoming,
            ingress,
            packing,
            records,
            source,
            symbols,
            overhead,
            compact_feedback_overhead: None,
            framing: framing.map(|value| value.local(context.role)),
            now,
            failure: None,
            expiry_failure: None,
            statistics: Statistics::default(),
            prepared_output: None,
            next_output: 1,
            prepared_native: None,
            next_native: 1,
            next_channel: 0,
            receive_progress: false,
            receive_unit: Some(receive_config.receiver.first_source),
            preview_next: 0,
            preview_end: 0,
            preview: None,
            preview_blocked: false,
            preview_rescan: false,
            usage: None,
            waits: Vec::new(),
        })
    }
    pub(super) fn fail<T>(&mut self, error: Error) -> Result<T, Error> {
        if let Some(waits) = self.waits.first_mut() {
            waits.stop(waits.observed_at, waits::Terminal::OwnerFailure);
        }
        let original = *self.failure.get_or_insert(error);
        Err(original)
    }
    pub(super) fn advance(&mut self, now: Tick) -> Result<(), Error> {
        if let Some(waits) = self.waits.first_mut() {
            waits.observe(now);
        }
        if let Some(error) = self.failure {
            return Err(error);
        }
        if now < self.now {
            return self.fail(Error::Time);
        }
        if self
            .ingress
            .as_ref()
            .and_then(|owner| owner.deadline())
            .is_some_and(|deadline| now >= deadline)
        {
            if let Some(input) = self.earliest_input_expiry() {
                self.note_expiry(
                    expiry::LocalOwner::Ingress,
                    now,
                    input.deadline,
                    input.records_number,
                    None,
                );
            }
            return self.fail(Error::Expired);
        }
        if let Some(deadline) = self.stage_deadline.filter(|deadline| now >= *deadline) {
            self.note_expiry(expiry::LocalOwner::CodecStage, now, deadline, None, None);
            return self.fail(Error::Expired);
        }
        if let Some(native) = self.prepared_native.filter(|native| now >= native.deadline) {
            self.note_expiry(
                expiry::LocalOwner::Native,
                now,
                native.deadline,
                None,
                Some(native.identity()),
            );
            return self.fail(Error::Expired);
        }
        let result = (|| {
            P::send_step(
                &mut self.sender,
                rolling_tick(now),
                rolling::WorkBudget::default(),
            )
            .map_err(Error::Rolling)?;
            P::receive_step(
                &mut self.incoming,
                rolling_tick(now),
                rolling::WorkBudget::default(),
            )
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
        self.enqueue_admitted_observed(now, channel, frame)
            .map(|value| value.map(|(identity, _)| identity))
    }
    /// Return exact codec facts only for the actual successful native admission.
    pub fn enqueue_admitted_observed(
        &mut self,
        now: Tick,
        channel: u16,
        frame: &[u8],
    ) -> Result<
        Option<(
            receiver::RecordIdentity,
            l2tunnel_codec::aligned_body::NativeEncodingObservation,
        )>,
        Error,
    > {
        if channel >= self.send_config.receiver.channels
            || frame.is_empty()
            || frame.len() > self.send_config.receiver.body.max_frame_bytes
            || self.repair_budget.as_ref().is_some_and(|b| !b.configured())
        {
            return Err(Error::Configuration);
        }
        let next = self
            .statistics
            .admitted
            .checked_add(1)
            .ok_or(Error::Arithmetic)?;
        now.0
            .checked_add(self.send_config.codec_stage_micros)
            .ok_or(Error::Arithmetic)?;
        self.advance(now)?;
        let channel = receiver::ChannelId(u8::try_from(channel).map_err(|_| Error::Configuration)?);
        let result = match self.send_config.native_policy {
            NativePolicy::EthernetHeaders | NativePolicy::IpHeaders => {
                self.packing.stage_observed(channel, frame, now.0)
            }
            NativePolicy::RawIp | NativePolicy::RawEthernet => {
                self.packing.stage_raw_observed(channel, frame, now.0)
            }
            NativePolicy::Lz4Ethernet | NativePolicy::Lz4Ip => {
                self.packing.stage_lz4_observed(channel, frame, now.0)
            }
        };
        match result {
            Ok(identity) => {
                self.fin_order
                    .admitted(self.send_config.native_policy, frame);
                self.statistics.admitted = next;
                self.refresh_stage_deadline()?;
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
    fn refresh_stage_deadline(&mut self) -> Result<(), Error> {
        self.stage_deadline = self
            .packing
            .oldest_admission_micros()
            .map(|admitted| {
                admitted
                    .checked_add(self.send_config.codec_stage_micros)
                    .map(Tick)
                    .ok_or(Error::Arithmetic)
            })
            .transpose()?;
        Ok(())
    }
    fn pump_send(&mut self, now: Tick) -> Result<(), Error> {
        if !self.packing.status().packing.sealed {
            return Ok(());
        }
        let expected = rolling::SourceId(P::send_state(&self.sender).next_source);
        let length = if self.compact_feedback_overhead.is_some() {
            self.packing.write_pending_compact(&mut self.source)
        } else {
            self.packing
                .write_pending(receiver::SourceId(u64::from(expected.0)), &mut self.source)
        }
        .map_err(Error::Sender)?;
        let copies = self.packing.pending_copies().map_err(Error::Sender)?;
        let admitted = self
            .packing
            .pending_admission_micros()
            .map_err(Error::Sender)?;
        let source_deadline = Tick(
            admitted
                .checked_add(self.send_config.codec_stage_micros)
                .ok_or(Error::Arithmetic)?,
        );
        let operation = waits::Operation {
            id: u64::from(expected.0),
            bytes: length,
            deadline: Some(source_deadline),
            packets: 0,
            wire_bytes: 0,
            copies,
        };
        match P::admit(
            &mut self.sender,
            &self.source[..length],
            rolling::Tick(admitted),
            rolling_tick(now),
            copies,
        ) {
            Ok(id) if id == expected => {
                let result = self.packing.commit_source().map_err(Error::Sender);
                if let Err(error) = result {
                    return self.fail(error);
                }
                if let Some(waits) = self.waits.first_mut() {
                    waits.progress(waits::Site::SourceAdmission, operation, now);
                }
                self.refresh_stage_deadline()?;
                Ok(())
            }
            Ok(_) => self.fail(Error::Identity),
            Err(error @ (rolling::Error::Busy | rolling::Error::Capacity)) => {
                if let Some(waits) = self.waits.first_mut() {
                    let reason = if error == rolling::Error::Busy {
                        waits::Reason::RecoveryBusy
                    } else {
                        waits::Reason::RecoveryCapacity
                    };
                    waits.refuse(waits::Site::SourceAdmission, operation, reason, now);
                }
                Ok(())
            }
            Err(error) => self.fail(Error::Rolling(error)),
        }
    }
    fn pump_receive(&mut self, now: Tick) -> Result<bool, Error> {
        if P::receive_state(&self.incoming, rolling_tick(now)).feedback_building {
            return Ok(false);
        }
        let Some((id, bytes)) = P::source(&self.incoming) else {
            return Ok(false);
        };
        let operation = waits::Operation {
            id: u64::from(id.0),
            bytes: bytes.len(),
            deadline: P::handoff_deadline(&self.incoming).map(|value| Tick(value.0)),
            packets: 0,
            wire_bytes: 0,
            copies: 0,
        };
        // The same slab belongs to one actual ordered handoff or one bounded
        // preview preparation, never both. No preview admission is partial.
        self.preview = None;
        let result = admit_packed(
            &mut self.records,
            &mut self.receive_unit,
            self.receive_config,
            self.receive_scope,
            id,
            bytes,
            &mut self.symbols,
            now,
            self.compact_feedback_overhead.is_some(),
        );
        match result {
            Ok(()) => {
                let result =
                    P::handoff(&mut self.incoming, id, rolling_tick(now)).map_err(Error::Rolling);
                if let Err(error) = result {
                    return self.fail(error);
                }
                if let Some(waits) = self.waits.first_mut() {
                    waits.progress(waits::Site::DecodedHandoff, operation, now);
                }
                Ok(true)
            }
            Err(error) if error.is_backpressure() => {
                if let Some(reason) = waits::Reason::from_error(error)
                    && let Some(waits) = self.waits.first_mut()
                {
                    waits.refuse(waits::Site::DecodedHandoff, operation, reason, now);
                }
                Ok(false)
            }
            Err(error) => self.fail(error),
        }
    }
    fn previews_sources(&self) -> bool {
        self.receive_config.scheduler.targeted()
            || self
                .receive_config
                .receiver
                .body
                .independent_short_frame_bytes
                != 0
    }
    fn request_preview_scan(&mut self) {
        if self.previews_sources() {
            self.preview_rescan = true;
            self.preview_blocked = false;
        }
    }
    fn preview_receive(
        &mut self,
        now: Tick,
        budget: &mut rolling::WorkBudget,
    ) -> Result<bool, Error> {
        if !self.previews_sources()
            || P::receive_state(&self.incoming, rolling_tick(now)).feedback_building
            || self.preview_blocked
        {
            return Ok(false);
        }
        let config = self.receive_config;
        let width = config.receiver.body.symbol_bytes;
        let mut native_progress = false;
        let mut visits = 0;
        while visits < config.packing.work_limit && budget.metadata > 0 {
            if self.preview.is_none() {
                budget.metadata -= 1;
                visits += 1;
                let status = P::receive_state(&self.incoming, rolling_tick(now)).decoder;
                // New committed availability may precede the retained cursor.
                // Coalesce it without discarding an in-progress slab copy.
                if self.preview_rescan
                    && (!config.scheduler.targeted() || self.preview_next >= self.preview_end)
                {
                    self.preview_next = status.handoff_prefix;
                    self.preview_end = status.observed_end;
                    self.preview_rescan = false;
                }
                self.preview_next = self.preview_next.max(status.handoff_prefix);
                if self.preview_next >= status.observed_end {
                    break;
                }
                let source = rolling::SourceId(self.preview_next);
                self.preview_next = self.preview_next.checked_add(1).ok_or(Error::Arithmetic)?;
                let Some(bytes) =
                    P::decoded_source(&self.incoming, source).map_err(Error::Rolling)?
                else {
                    continue;
                };
                let view = packed_view(
                    config,
                    self.receive_scope,
                    source,
                    bytes,
                    self.compact_feedback_overhead.is_some(),
                )?;
                self.preview = Some(Preview {
                    source,
                    count: view.len(),
                    unit: 0,
                    current: None,
                    selected: [0; 4],
                });
                continue;
            }
            let mut preview = self.preview.take().ok_or(Error::Identity)?;
            if preview.unit == preview.count {
                budget.metadata -= 1;
                visits += 1;
                let bytes = P::decoded_source(&self.incoming, preview.source)
                    .map_err(Error::Rolling)?
                    .ok_or(Error::Identity)?;
                let view = packed_view(
                    config,
                    self.receive_scope,
                    preview.source,
                    bytes,
                    self.compact_feedback_overhead.is_some(),
                )?;
                let mut inputs = empty_inputs(self.receive_scope);
                let mut count = 0;
                let floor = self.records.status().source_floor;
                for (index, unit) in view.units().map_err(Error::Envelope)?.enumerate() {
                    if preview.selected[index / 64] & (1 << (index % 64)) != 0
                        && floor.is_some_and(|floor| unit.identity.source.0 > floor.0)
                    {
                        inputs[count] = receiver::AuthenticatedSymbol {
                            identity: unit.identity,
                            bytes: &self.symbols[index * width..(index + 1) * width],
                        };
                        count += 1;
                    }
                }
                if count != 0 {
                    let mut outcomes = [receiver::Admission::Accepted; 255];
                    match self.records.admit_batch_authenticated_into(
                        &inputs[..count],
                        receiver_tick(now),
                        &mut outcomes[..count],
                    ) {
                        Ok(admitted)
                            if admitted == count
                                && outcomes[..count].iter().all(|value| {
                                    matches!(
                                        value,
                                        receiver::Admission::Accepted
                                            | receiver::Admission::Duplicate
                                            | receiver::Admission::StaleSource
                                    )
                                }) =>
                        {
                            native_progress |=
                                outcomes[..count].contains(&receiver::Admission::Accepted);
                        }
                        Err(
                            receiver::Error::Capacity
                            | receiver::Error::RecordWindow
                            | receiver::Error::SourceWindow,
                        ) if config.scheduler.targeted() => {
                            // Another solved source can belong to a ready channel.
                            // Native commits and ordered handoff re-arm this scan.
                            continue;
                        }
                        Err(receiver::Error::Capacity | receiver::Error::RecordWindow) => {
                            self.preview = Some(preview);
                            self.preview_blocked = true;
                            break;
                        }
                        Ok(_) => return Err(Error::Identity),
                        Err(error) => return Err(Error::Receiver(error)),
                    }
                }
                continue;
            }
            if preview.current.is_none() {
                budget.metadata -= 1;
                visits += 1;
                let bytes = P::decoded_source(&self.incoming, preview.source)
                    .map_err(Error::Rolling)?
                    .ok_or(Error::Identity)?;
                let view = packed_view(
                    config,
                    self.receive_scope,
                    preview.source,
                    bytes,
                    self.compact_feedback_overhead.is_some(),
                )?;
                // The maintained parser owns the bounded unit grammar. Retain
                // the current exact slice coordinates so byte-budget resumes
                // never walk the preceding units again.
                let unit = view
                    .units()
                    .map_err(Error::Envelope)?
                    .nth(preview.unit)
                    .ok_or(Error::Identity)?;
                if config.scheduler.targeted()
                    && self
                        .records
                        .source_observed(self.receive_scope, unit.identity.source)
                        .map_err(Error::Receiver)?
                {
                    preview.unit += 1;
                    self.preview = Some(preview);
                    continue;
                }
                let offset = (unit.bytes.as_ptr() as usize)
                    .checked_sub(bytes.as_ptr() as usize)
                    .ok_or(Error::Identity)?;
                if offset
                    .checked_add(unit.bytes.len())
                    .is_none_or(|end| end > bytes.len())
                {
                    return Err(Error::Identity);
                }
                preview.current = Some(PreviewUnit {
                    identity: unit.identity,
                    offset,
                    length: unit.bytes.len(),
                    cleared: 0,
                    copied: 0,
                });
                self.preview = Some(preview);
                continue;
            }
            let current = preview.current.as_mut().ok_or(Error::Identity)?;
            let symbol = &mut self.symbols[preview.unit * width..(preview.unit + 1) * width];
            if current.cleared < width {
                let count = budget.copies.min(width - current.cleared);
                symbol[current.cleared..current.cleared + count].fill(0);
                current.cleared += count;
                budget.copies -= count;
                if current.cleared < width {
                    self.preview = Some(preview);
                    break;
                }
            }
            if current.copied < current.length {
                if budget.copies == 0 {
                    self.preview = Some(preview);
                    break;
                }
                budget.metadata -= 1;
                visits += 1;
                let bytes = P::decoded_source(&self.incoming, preview.source)
                    .map_err(Error::Rolling)?
                    .ok_or(Error::Identity)?;
                let count = budget.copies.min(current.length - current.copied);
                let start = current
                    .offset
                    .checked_add(current.copied)
                    .ok_or(Error::Arithmetic)?;
                let original = bytes.get(start..start + count).ok_or(Error::Identity)?;
                symbol[current.copied..current.copied + count].copy_from_slice(original);
                current.copied += count;
                budget.copies -= count;
                self.preview = Some(preview);
                continue;
            }
            budget.metadata -= 1;
            visits += 1;
            check_policy(config, symbol)?;
            if config.scheduler.targeted()
                || self
                    .records
                    .is_independent_short(current.identity, symbol)
                    .map_err(Error::Receiver)?
            {
                preview.selected[preview.unit / 64] |= 1 << (preview.unit % 64);
            }
            preview.unit += 1;
            preview.current = None;
            self.preview = Some(preview);
        }
        Ok(native_progress)
    }
    /// Service each actual scheduler under the supplied independent work cap.
    /// One call hands at most one source to the compact record receiver.
    /// Preview resumes use the existing scratch slab and remaining receive
    /// metadata/copy allowance, with unit actions capped by packing.work_limit.
    pub fn step(&mut self, now: Tick, work: rolling::WorkBudget) -> Result<Step, Error> {
        self.advance(now)?;
        self.pump_send(now)?;
        self.service_ingress(now)?;
        let send = self.step_sender(now, work)?;
        if self.receive_progress {
            self.request_preview_scan();
        }
        let mut receive =
            P::receive_step(&mut self.incoming, rolling_tick(now), work).map_err(Error::Rolling)?;
        // An unchanged busy decoder cannot admit the same FIFO head. Resume
        // that head in the completion turn, including capacity rollback.
        if !matches!(receive.decode, rolling::DecodeStep::Pending(_))
            && let Some(owner) = &mut self.ingress
            && owner.waiting_on_decoder
        {
            owner.waiting_on_decoder = false;
            self.service_ingress(now)?;
        }
        if matches!(receive.decode, rolling::DecodeStep::Accepted { .. }) {
            self.request_preview_scan();
        }
        let source_handed = self.pump_receive(now)?;
        let mut native_progress = false;
        if !source_handed {
            let mut remaining = rolling::WorkBudget {
                field: work.field - receive.work.field,
                copies: work.copies - receive.work.copies,
                metadata: work.metadata - receive.work.metadata,
            };
            let before = remaining;
            native_progress = match self.preview_receive(now, &mut remaining) {
                Ok(progress) => progress,
                Err(error) => return self.fail(error),
            };
            receive.work.copies += before.copies - remaining.copies;
            receive.work.metadata += before.metadata - remaining.metadata;
        }
        self.receive_progress = source_handed;
        Ok(Step {
            send,
            receive,
            source_handed,
            native_progress,
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
        let (id, kind, length, source_copy) = if let Some(feedback) = P::feedback(&self.incoming) {
            (
                OutputId::Feedback(feedback),
                EmissionKind::Feedback,
                if self.compact_feedback_overhead.is_some() {
                    P::Compact::feedback_len(&self.incoming)
                        .map_err(Error::Rolling)?
                        .ok_or(Error::Identity)?
                } else {
                    P::FEEDBACK_BYTES
                },
                None,
            )
        } else if allow_data {
            let Some(data) = P::pending_data(&self.sender).map_err(Error::Rolling)? else {
                return Ok(None);
            };
            let kind = match data.id {
                scheduler::OutputId::Source(_) => EmissionKind::Source(SourceForm::SystematicFec),
                scheduler::OutputId::Repair(_) => EmissionKind::Repair,
            };
            let length = if self.compact_feedback_overhead.is_some() {
                P::Compact::data_len(&self.sender)
                    .map_err(Error::Rolling)?
                    .ok_or(Error::Identity)?
            } else {
                data.bytes
            };
            (OutputId::Data(data.id), kind, length, data.source_copy)
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
        let overhead = if kind == EmissionKind::Feedback {
            self.compact_feedback_overhead.unwrap_or(self.overhead)
        } else {
            self.overhead
        };
        let (packets, wire_bytes) = wire_charge(self.framing, length, overhead)?;
        let feedback_operation = match id {
            OutputId::Feedback(id) => Some(waits::Operation {
                id: id.0,
                bytes: length,
                deadline: P::feedback_deadline(&self.incoming).map(|value| Tick(value.0)),
                packets,
                wire_bytes,
                copies: 0,
            }),
            OutputId::Data(_) => None,
        };
        if budget.packets < packets || budget.wire_bytes < wire_bytes {
            if let Some(operation) = feedback_operation
                && let Some(waits) = self.waits.first_mut()
            {
                if budget.packets < packets {
                    waits.refuse(
                        waits::Site::FeedbackBudget,
                        operation,
                        waits::Reason::PacketBudget,
                        now,
                    );
                }
                if budget.wire_bytes < wire_bytes {
                    waits.refuse(
                        waits::Site::FeedbackBudget,
                        operation,
                        waits::Reason::WireByteBudget,
                        now,
                    );
                }
            }
            return Ok(None);
        }
        let next = self.next_output.checked_add(1).ok_or(Error::Arithmetic)?;
        self.statistics
            .handed
            .checked_add(1)
            .ok_or(Error::Arithmetic)?;
        let count = match id {
            OutputId::Feedback(_) => {
                let encoded = if self.compact_feedback_overhead.is_some() {
                    P::Compact::encode_feedback(&self.incoming, output)
                } else {
                    P::encode_feedback(&self.incoming, output)
                };
                if encoded.map_err(Error::Rolling)? != length {
                    return self.fail(Error::Identity);
                }
                0
            }
            OutputId::Data(_) => {
                let encoded = if self.compact_feedback_overhead.is_some() {
                    P::Compact::encode_data(&self.sender, output)
                } else {
                    P::encode_data(&self.sender, output)
                };
                if encoded.map_err(Error::Rolling)? != length {
                    return self.fail(Error::Identity);
                }
                self.outgoing_units(&output[..length], witnesses)?
            }
        };
        let pending = PreparedOutput {
            instance: self.instance,
            serial: self.next_output,
            prepared_at: now,
            source_copy,
            retry_full_credit: if matches!(id, OutputId::Data(_)) {
                P::requested_credit(&self.sender)
            } else {
                None
            },
            id,
            kind,
            security_number,
            bytes: length,
            wire_bytes,
            packets,
            witnesses: count,
        };
        self.next_output = next;
        self.prepared_output = Some(pending);
        budget.packets -= packets;
        budget.wire_bytes -= wire_bytes;
        if let Some(operation) = feedback_operation
            && let Some(waits) = self.waits.first_mut()
        {
            waits.progress(waits::Site::FeedbackBudget, operation, now);
        }
        Ok(Some(pending))
    }
    /// Observe the retained token without changing original output/timers.
    pub fn pending_output(&self) -> Option<PreparedOutput> {
        self.prepared_output
    }
    /// Record exactly one caller-observed complete carrier handoff, never enqueue.
    /// Selected framing requires all `pending.packets` whole physical fragments;
    /// an individual fragment or partial batch does not discharge this copy token.
    /// Physical observation is retained even if subsequent timing validation fails.
    pub fn confirm_output(&mut self, now: Tick, pending: PreparedOutput) -> Result<(), Error> {
        self.confirm_output_at(now, now, pending)
    }
    /// Keep original actual acceptance distinct from delayed callback observation.
    pub fn confirm_output_at(
        &mut self,
        now: Tick,
        accepted: Tick,
        pending: PreparedOutput,
    ) -> Result<(), Error> {
        if self.prepared_output != Some(pending) {
            return Err(Error::Token);
        }
        let handed = self
            .statistics
            .handed
            .checked_add(1)
            .ok_or(Error::Arithmetic)?;
        let timing = if accepted < pending.prepared_at || accepted > now {
            self.fail(Error::Time)
        } else {
            self.advance(now)
        };
        self.prepared_output = None;
        self.statistics.handed = handed;
        timing?;
        // A queued original cannot participate in an equation. Publish its extent
        // only at first handoff so future IDs cannot replace an active window slot.
        let extent = if self.repair_budget.is_some()
            && let Some(copy) = pending.source_copy
            && copy.ordinal() == 1
        {
            match P::pending_original(&self.sender) {
                Some((id, bytes)) if id == copy.source() => Some((id, bytes)),
                _ => return self.fail(Error::Identity),
            }
        } else {
            None
        };
        let result = match pending.id {
            OutputId::Data(id) => P::confirm_data(
                &mut self.sender,
                id,
                pending.source_copy,
                rolling_tick(accepted),
                rolling_tick(now),
                pending.wire_bytes,
            ),
            OutputId::Feedback(id) if pending.source_copy.is_none() => {
                P::confirm_feedback(&mut self.incoming, id, rolling_tick(now))
            }
            _ => Err(rolling::Error::Identity),
        }
        .map_err(Error::Rolling);
        if let Err(error) = result {
            return self.fail(error);
        }
        if let Some(budget) = &mut self.repair_budget {
            if let Some((id, length)) = extent {
                budget.record_source(id, length)?;
            }
            budget.accepted(pending);
        }
        self.expire_confirmed_credit();
        Ok(())
    }
    /// Accept complete plaintext only after caller carrier authentication/replay.
    /// With no selected queue, Busy retains the original caller-owned input.
    pub fn accept_authenticated(
        &mut self,
        now: Tick,
        kind: EmissionKind,
        bytes: &[u8],
    ) -> Result<(), Error> {
        self.accept_authenticated_at(now, now, kind, bytes)
    }
    /// Preserve original input age without inferring external operation authority.
    pub fn accept_authenticated_at(
        &mut self,
        received: Tick,
        now: Tick,
        kind: EmissionKind,
        bytes: &[u8],
    ) -> Result<(), Error> {
        self.accept_authenticated_until(received, now, Tick(u64::MAX), None, kind, bytes)
    }
    /// Retain already-opened input and its actual Records number/caller deadline.
    /// A number is observation metadata only; this owner creates no replay window.
    pub fn accept_authenticated_until(
        &mut self,
        received: Tick,
        now: Tick,
        original_deadline: Tick,
        security_number: Option<u64>,
        kind: EmissionKind,
        bytes: &[u8],
    ) -> Result<(), Error> {
        if received > now {
            return Err(Error::Time);
        }
        self.advance(now)?;
        if now >= original_deadline {
            self.note_expiry(
                expiry::LocalOwner::Incoming,
                now,
                original_deadline,
                security_number,
                None,
            );
            return self.fail(Error::Expired);
        }
        match kind {
            EmissionKind::Feedback => {
                compact_wire::receive_feedback::<P>(
                    self.compact_feedback_overhead.is_some(),
                    self.send_config.scheduler,
                    self.send_rolling_scope,
                    &mut self.sender,
                    bytes,
                    rolling_tick(received),
                    rolling_tick(now),
                )
                .map_err(Error::Rolling)?;
                self.expire_confirmed_credit();
            }
            EmissionKind::Source(SourceForm::SystematicFec) | EmissionKind::Repair => {
                let (observed, scope) =
                    match self.inspect_data(bytes, false).map_err(Error::Rolling)? {
                        recovery::View::Source { scope, .. } => {
                            (EmissionKind::Source(SourceForm::SystematicFec), scope)
                        }
                        recovery::View::Repair { scope } => (EmissionKind::Repair, scope),
                    };
                let expected = rolling::Scope {
                    direction: self.send_rolling_scope.direction ^ 1,
                    ..self.send_rolling_scope
                };
                if observed != kind || scope != expected {
                    return Err(Error::Identity);
                }
                if let Some(owner) = &mut self.ingress {
                    let policy = self.receive_config.scheduler.recovery();
                    let deadline = Tick(
                        received
                            .0
                            .checked_add(policy.job_ticks)
                            .ok_or(Error::Arithmetic)?,
                    )
                    .min(original_deadline);
                    received
                        .0
                        .checked_add(policy.debt_ticks)
                        .ok_or(Error::Arithmetic)?;
                    if now >= deadline {
                        self.note_expiry(
                            expiry::LocalOwner::Incoming,
                            now,
                            deadline,
                            security_number,
                            None,
                        );
                        return self.fail(Error::Expired);
                    }
                    // Start an idle decoder in this receive call. Never pass an older
                    // retained input, even if the decoder just became available.
                    if owner.queue.front().is_none() {
                        match compact_wire::receive::<P>(
                            self.compact_feedback_overhead.is_some(),
                            self.receive_config.scheduler,
                            expected,
                            &mut self.incoming,
                            bytes,
                            rolling_tick(received),
                            rolling_tick(now),
                            rolling_tick(original_deadline),
                        ) {
                            Ok(outcome) => {
                                self.note_direct_ingress_admission(received, now, outcome);
                                self.request_preview_scan();
                                return Ok(());
                            }
                            Err(rolling::Error::Busy) => {}
                            Err(error) => return self.fail(Error::Rolling(error)),
                        }
                    }
                    owner.push(
                        ingress::Input {
                            kind,
                            number: security_number,
                            received,
                            order: None,
                            original_cap: original_deadline,
                            deadline,
                        },
                        bytes,
                    )?;
                } else {
                    compact_wire::receive::<P>(
                        self.compact_feedback_overhead.is_some(),
                        self.receive_config.scheduler,
                        rolling::Scope {
                            direction: self.send_rolling_scope.direction ^ 1,
                            ..self.send_rolling_scope
                        },
                        &mut self.incoming,
                        bytes,
                        rolling_tick(received),
                        rolling_tick(now),
                        rolling_tick(original_deadline),
                    )
                    .map_err(Error::Rolling)?;
                    self.request_preview_scan();
                }
            }
            _ => return Err(Error::Identity),
        }
        Ok(())
    }
    fn service_ingress(&mut self, now: Tick) -> Result<(), Error> {
        let Some(owner) = &mut self.ingress else {
            return Ok(());
        };
        let Some(front) = owner.queue.front() else {
            return Ok(());
        };
        let input = *front.metadata();
        if input.kind == EmissionKind::Feedback {
            // Only physical completion may order this retained feedback around
            // a pending source/repair. Other ingress keeps its bounded service.
            if self.prepared_output.is_some_and(|pending| {
                matches!(pending.kind, EmissionKind::Source(_) | EmissionKind::Repair)
            }) {
                let count = owner.queue.len();
                for _ in 0..count {
                    if owner
                        .queue
                        .front()
                        .is_some_and(|front| front.metadata().kind != EmissionKind::Feedback)
                    {
                        break;
                    }
                    owner.queue.rotate_front().map_err(Error::Ingress)?;
                }
                return Ok(());
            }
            let result = compact_wire::receive_feedback::<P>(
                self.compact_feedback_overhead.is_some(),
                self.send_config.scheduler,
                self.send_rolling_scope,
                &mut self.sender,
                front.bytes(),
                rolling_tick(input.received),
                rolling_tick(now),
            )
            .map_err(Error::Rolling);
            if let Err(error) = result {
                return self.fail(error);
            }
            owner.complete_front()?;
            self.expire_confirmed_credit();
            return Ok(());
        }
        if !matches!(
            input.kind,
            EmissionKind::Source(SourceForm::SystematicFec) | EmissionKind::Repair
        ) {
            return self.fail(Error::Identity);
        }
        if owner.waiting_on_decoder {
            return Ok(());
        }
        // The immutable data head cannot rotate while Busy. Only opt-in
        // observation reads its existing metadata; no bytes are parsed again.
        let diagnostic_input = if self
            .waits
            .first()
            .is_some_and(|waits| waits.ingress_admission.is_some())
        {
            Some(waits::ingress::Input {
                records_number: input.number,
                received: input.received,
                deadline: input.deadline,
                bytes: front.bytes().len(),
                kind: if input.kind == EmissionKind::Repair {
                    waits::ingress::Kind::Repair
                } else {
                    waits::ingress::Kind::Source
                },
            })
        } else {
            None
        };
        let result = compact_wire::receive::<P>(
            self.compact_feedback_overhead.is_some(),
            self.receive_config.scheduler,
            rolling::Scope {
                direction: self.send_rolling_scope.direction ^ 1,
                ..self.send_rolling_scope
            },
            &mut self.incoming,
            front.bytes(),
            rolling_tick(input.received),
            rolling_tick(now),
            rolling_tick(input.original_cap),
        );
        match result {
            Ok(outcome) => {
                owner.complete_front()?;
                if let Some(input) = diagnostic_input {
                    let outcome = match outcome {
                        rolling::Begin::Staged => waits::ingress::Outcome::Staged,
                        rolling::Begin::Duplicate => waits::ingress::Outcome::Duplicate,
                        rolling::Begin::Stale => waits::ingress::Outcome::Stale,
                    };
                    let admitted_job = if outcome == waits::ingress::Outcome::Staged {
                        P::receive_expiry(&self.incoming).decoder_job
                    } else {
                        None
                    };
                    if let Some(waits) = self.waits.first_mut() {
                        waits.ingress_completed(input, outcome, admitted_job, now);
                    }
                }
                self.request_preview_scan();
                Ok(())
            }
            Err(rolling::Error::Busy) => {
                owner.waiting_on_decoder = P::receive_state(&self.incoming, rolling_tick(now))
                    .decoder
                    .pending_job;
                if let Some(input) = diagnostic_input {
                    let blocker = P::receive_expiry(&self.incoming).decoder_job;
                    if let Some(waits) = self.waits.first_mut() {
                        waits.ingress_refused(input, blocker, now);
                    }
                }
                Ok(())
            }
            Err(error) => self.fail(Error::Rolling(error)),
        }
    }
    /// Actual per-generation input custody, independent of decoded/native receipt.
    pub fn ingress_status(&self) -> Option<IngressStatus> {
        self.ingress.as_ref().map(|owner| owner.status())
    }
    /// Whether this local sending direction selected request-based recovery.
    pub fn uses_targeted_sender(&self) -> bool {
        self.send_config.scheduler.targeted()
    }
    /// Borrow actual source witnesses; repairs contain no original native unit.
    pub fn outgoing_units(
        &self,
        packet: &[u8],
        output: &mut [receiver::UnitWitness],
    ) -> Result<usize, Error> {
        let (scope, id, original) = match self.inspect_data(packet, true).map_err(Error::Rolling)? {
            recovery::View::Source {
                scope,
                id,
                original,
            } => (scope, id, original),
            recovery::View::Repair { scope } => {
                if scope != self.send_rolling_scope {
                    return Err(Error::Identity);
                }
                return Ok(0);
            }
        };
        if scope != self.send_rolling_scope {
            return Err(Error::Identity);
        }
        let view = packed_view(
            self.send_config,
            self.send_scope,
            id,
            original,
            self.compact_feedback_overhead.is_some(),
        )?;
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
        P::send_deadline(&self.sender)
            .map(|t| Tick(t.0))
            .into_iter()
            .chain(self.stage_deadline)
            .chain(self.ingress.as_ref().and_then(|owner| owner.deadline()))
            .chain(P::receive_deadline(&self.incoming).map(|t| Tick(t.0)))
            .chain(self.records.deadline().map(|t| Tick(t.0)))
            .chain(self.prepared_native.map(|native| native.deadline))
            .min()
    }
    /// Earliest hard expiry or actual first-unit/tail/feedback service trigger.
    pub fn wake_at(&self) -> Option<Tick> {
        self.deadline()
            .into_iter()
            .chain(P::send_wake(&self.sender).map(|t| Tick(t.0)))
            .chain(P::receive_wake(&self.incoming, rolling_tick(self.now)).map(|t| Tick(t.0)))
            .chain(self.packing.deadline_micros().map(Tick))
            .min()
    }
    /// Actual resumable computation, excluding immutable output waiting for I/O.
    pub fn work_pending(&self) -> bool {
        let send = P::send_state(&self.sender);
        let receive = P::receive_state(&self.incoming, rolling_tick(self.now));
        self.ingress.as_ref().is_some_and(|owner| {
            owner.has_data()
                || (owner.has_feedback()
                    && !self.prepared_output.is_some_and(|pending| {
                        matches!(pending.kind, EmissionKind::Source(_) | EmissionKind::Repair)
                    }))
        }) || send.work_pending
            || receive.decoder.pending_job
            || receive.feedback_building
            || receive.work_pending
            || (self.receive_progress
                && receive.decoder.decoded_prefix > receive.decoder.handoff_prefix)
            || (self.previews_sources()
                && !self.preview_blocked
                && (self.preview.is_some()
                    || self.preview_rescan
                    || self.preview_next < receive.decoder.observed_end))
    }
    /// Service original hard bounds without performing hidden GF work.
    pub fn tick(&mut self, now: Tick) -> Result<(), Error> {
        self.advance(now)
    }
    /// Genuine pending/first-event feedback service requirement, not native delivery.
    pub fn feedback_opportunity(&self) -> Option<(Tick, usize)> {
        let status = P::receive_state(&self.incoming, rolling_tick(self.now));
        if status.feedback_ready || status.feedback_building {
            Some((self.now, P::FEEDBACK_BYTES))
        } else {
            status
                .feedback_due
                .map(|at| (Tick(at.0), P::FEEDBACK_BYTES))
        }
    }
    /// Actual retained directional scheduler state, without inferred capability.
    pub fn sender_status(&self) -> P::SenderStatus {
        P::sender_status(&self.sender)
    }
    /// Actual decode/feedback state, without native-delivery inference.
    pub fn receiver_status(&self) -> P::ReceiverStatus {
        P::receiver_status(&self.incoming)
    }
    /// Actual compact record/context/native custody state.
    pub fn record_status(&self) -> receiver::Status {
        self.records.status()
    }
    /// Read actual codec retention without stepping the independent FEC owners.
    pub fn codec_buffer_snapshot(&self) -> l2tunnel_codec::diagnostics::DuplexBuffers {
        l2tunnel_codec::diagnostics::DuplexBuffers {
            send: l2tunnel_codec::diagnostics::SendBuffers::Packed(self.packing.buffer_snapshot()),
            receive: self.records.buffer_snapshot(),
        }
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
        let send = P::send_state(&self.sender);
        let receive = P::receive_state(&self.incoming, rolling_tick(self.now));
        let records = self.records.status();
        self.failure.is_none()
            && self
                .ingress
                .as_ref()
                .is_none_or(|owner| owner.queue.is_empty())
            && self.packing.is_idle()
            && self.prepared_output.is_none()
            && self.prepared_native.is_none()
            && send.drained
            && !receive.decoder.pending_job
            && receive.decoder.handoff_prefix == receive.decoder.observed_end
            && !receive.feedback_building
            && !receive.feedback_ready
            && !receive.feedback_events
            && receive.feedback_due.is_none()
            && records.retained_records == 0
            && records.retained_sources == 0
            && records.pending_bytes.is_none()
    }
}

// The exact ordered unit cursor is separate from the previewable record ledger.
#[allow(clippy::too_many_arguments)]
fn admit_packed<P: RecoveryPolicy>(
    records: &mut receiver::Receiver,
    ordered_unit: &mut Option<receiver::SourceId>,
    config: DirectionConfig<P>,
    scope: receiver::Scope,
    id: rolling::SourceId,
    bytes: &[u8],
    symbols: &mut [u8],
    now: Tick,
    compact: bool,
) -> Result<(), Error> {
    let view = packed_view(config, scope, id, bytes, compact)?;
    if Some(view.identity().first_unit) != *ordered_unit {
        return Err(Error::Identity);
    }
    let next = view
        .identity()
        .first_unit
        .0
        .checked_add(view.len() as u64)
        .map(receiver::SourceId);
    let targeted = config.scheduler.targeted();
    let preview = targeted || config.receiver.body.independent_short_frame_bytes != 0;
    let floor = records.status().source_floor;
    let mut inputs = empty_inputs(scope);
    let mut count = 0;
    let mut units = 0;
    for (unit, symbol) in view
        .units()
        .map_err(Error::Envelope)?
        .zip(symbols.chunks_exact_mut(config.receiver.body.symbol_bytes))
    {
        symbol.fill(0);
        symbol[..unit.bytes.len()].copy_from_slice(unit.bytes);
        check_policy(config, symbol)?;
        units += 1;
        if preview && floor.is_none_or(|floor| unit.identity.source.0 < floor.0) {
            continue;
        }
        inputs[count] = receiver::AuthenticatedSymbol {
            identity: unit.identity,
            bytes: symbol,
        };
        count += 1;
    }
    if units != view.len() {
        return Err(Error::Identity);
    }
    if count == 0 {
        *ordered_unit = next;
        return Ok(());
    }
    let mut outcomes = [receiver::Admission::Accepted; 255];
    // Other channels may legitimately retain complete context-dependent records
    // behind a gap. Their semantic validation runs at their own ordered head.
    let admit = if targeted {
        receiver::Receiver::admit_batch_authenticated_into
    } else {
        receiver::Receiver::admit_validated_batch_authenticated_into
    };
    let admitted = admit(
        records,
        &inputs[..count],
        receiver_tick(now),
        &mut outcomes[..count],
    )
    .map_err(Error::Receiver)?;
    if admitted != count
        || outcomes[..count].iter().any(|a| {
            !(matches!(a, receiver::Admission::Accepted)
                || preview
                    && matches!(
                        a,
                        receiver::Admission::Duplicate | receiver::Admission::StaleSource
                    ))
        })
    {
        return Err(Error::Identity);
    }
    *ordered_unit = next;
    Ok(())
}

fn empty_inputs<'a>(scope: receiver::Scope) -> [receiver::AuthenticatedSymbol<'a>; 255] {
    std::array::from_fn(|_| receiver::AuthenticatedSymbol {
        identity: receiver::SymbolIdentity {
            scope,
            source: receiver::SourceId(0),
            record: receiver::RecordId(0),
        },
        bytes: &[],
    })
}

fn packed_view<P: RecoveryPolicy>(
    config: DirectionConfig<P>,
    scope: receiver::Scope,
    id: rolling::SourceId,
    bytes: &[u8],
    compact: bool,
) -> Result<packed_envelope::View<'_>, Error> {
    let view = if compact {
        packed_envelope::decode_compact(
            config.packing.envelope(),
            scope,
            receiver::SourceId(u64::from(id.0)),
            bytes,
        )
    } else {
        packed_envelope::decode(config.packing.envelope(), scope, bytes)
    }
    .map_err(Error::Envelope)?;
    if view.identity().source.0 != u64::from(id.0) {
        return Err(Error::Identity);
    }
    Ok(view)
}

fn check_policy<P: RecoveryPolicy>(config: DirectionConfig<P>, symbol: &[u8]) -> Result<(), Error> {
    if !config.native_policy.accepts_unit(symbol) {
        return Err(Error::Policy);
    }
    Ok(())
}
