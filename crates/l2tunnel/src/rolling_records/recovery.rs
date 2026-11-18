//! Typed dispatch to the existing actual recovery owners; no codec state is duplicated.
use super::*;
use crate::fec::research;

mod sealed {
    pub trait Sealed {}
    impl Sealed for super::scheduler::Policy {}
    impl Sealed for super::research::Config {}
}

#[doc(hidden)]
#[derive(Clone, Copy)]
pub struct OwnerPlan {
    pub capacity_bytes: usize,
    pub allocations: usize,
}
#[doc(hidden)]
#[derive(Clone, Copy)]
pub struct SendState {
    pub encoder: rolling::EncoderStatus,
    /// First unassigned source, including originals admitted ahead of carrier service.
    pub next_source: u32,
    pub queued_fresh: usize,
    pub peak_queued_fresh: usize,
    pub fresh_queue_limit: usize,
    pub output_ready: bool,
    pub work_pending: bool,
    pub drained: bool,
}
#[doc(hidden)]
#[derive(Clone, Copy)]
pub struct ReceiveState {
    pub decoder: rolling::DecoderStatus,
    pub feedback_building: bool,
    pub feedback_ready: bool,
    pub feedback_events: bool,
    pub work_pending: bool,
    pub feedback_due: Option<rolling::Tick>,
}
#[doc(hidden)]
#[derive(Clone, Copy)]
pub struct Data {
    pub id: scheduler::OutputId,
    pub bytes: usize,
    pub source_copy: Option<scheduler::SourceCopy>,
}
#[doc(hidden)]
pub enum View<'a> {
    Source {
        scope: rolling::Scope,
        id: rolling::SourceId,
        original: &'a [u8],
    },
    Repair {
        scope: rolling::Scope,
    },
}

/// Sealed actual recovery selection used by the one maintained record body.
///
/// The default is the existing rolling scheduler. The research implementation
/// owns the maintained research Sender/Receiver and returns their distinct real
/// statuses. This is structural composition, not peer authentication authority.
#[doc(hidden)]
#[allow(missing_docs)] // Internal sealed dispatch; public only for concrete typed aliases.
pub trait RecoveryPolicy: sealed::Sealed + Copy + Eq {
    type Compact: CompactRecovery<Self>;
    type Sender;
    type Receiver;
    type SenderStatus;
    type ReceiverStatus;
    const HEADER_BYTES: usize;
    const FEEDBACK_BYTES: usize;
    const COPIES: bool;
    const DOMAIN: &'static [u8];
    const STREAM_DOMAIN: &'static [u8];
    fn targeted(self) -> bool {
        false
    }
    fn validate(self) -> Result<(), rolling::Error>;
    fn recovery(self) -> rolling::Config;
    fn validate_owner_bounds(self) -> Result<(), Error>;
    fn intervals(self) -> [u64; 2];
    fn words(self) -> [u64; 18];
    fn sender_plan(self) -> Result<OwnerPlan, rolling::storage::Error>;
    fn receiver_plan(self) -> Result<OwnerPlan, rolling::storage::Error>;
    fn new_sender(
        self,
        scope: rolling::Scope,
        now: rolling::Tick,
        reserved: Option<usize>,
    ) -> Result<Self::Sender, Error>;
    fn new_receiver(
        self,
        scope: rolling::Scope,
        now: rolling::Tick,
        reserved: Option<usize>,
    ) -> Result<Self::Receiver, Error>;
    fn sender_usage(
        sender: &Self::Sender,
    ) -> Result<rolling::storage::Usage, rolling::storage::Error>;
    fn receiver_usage(
        receiver: &Self::Receiver,
    ) -> Result<rolling::storage::Usage, rolling::storage::Error>;
    fn sender_status(sender: &Self::Sender) -> Self::SenderStatus;
    fn receiver_status(receiver: &Self::Receiver) -> Self::ReceiverStatus;
    fn send_state(sender: &Self::Sender) -> SendState;
    fn receive_state(receiver: &Self::Receiver, now: rolling::Tick) -> ReceiveState;
    fn admit(
        sender: &mut Self::Sender,
        bytes: &[u8],
        created: rolling::Tick,
        now: rolling::Tick,
        copies: u8,
    ) -> Result<rolling::SourceId, rolling::Error>;
    fn send_step(
        sender: &mut Self::Sender,
        now: rolling::Tick,
        work: rolling::WorkBudget,
    ) -> Result<rolling::WorkUsed, rolling::Error>;
    fn send_step_filtered(
        sender: &mut Self::Sender,
        now: rolling::Tick,
        work: rolling::WorkBudget,
        _filter: impl FnMut(rolling::RepairId, rolling::Support) -> Result<bool, rolling::Error>,
    ) -> Result<rolling::WorkUsed, rolling::Error> {
        Self::send_step(sender, now, work)
    }
    fn requested_credit(_sender: &Self::Sender) -> Option<bool> {
        None
    }
    fn request_counts(_sender: &Self::Sender) -> scheduler::RequestCounts {
        scheduler::RequestCounts::default()
    }
    fn observe_mux_wait(_sender: &mut Self::Sender, _age: u64) {}
    fn receive_step(
        receiver: &mut Self::Receiver,
        now: rolling::Tick,
        work: rolling::WorkBudget,
    ) -> Result<scheduler::ReceiverStep, rolling::Error>;
    fn pending_data(sender: &Self::Sender) -> Result<Option<Data>, rolling::Error>;
    fn pending_original(_sender: &Self::Sender) -> Option<(rolling::SourceId, usize)> {
        None
    }
    fn encode_data(sender: &Self::Sender, out: &mut [u8]) -> Result<usize, rolling::Error>;
    fn confirm_data(
        sender: &mut Self::Sender,
        id: scheduler::OutputId,
        copy: Option<scheduler::SourceCopy>,
        accepted: rolling::Tick,
        now: rolling::Tick,
        wire_bytes: usize,
    ) -> Result<(), rolling::Error>;
    fn receive_feedback(
        sender: &mut Self::Sender,
        bytes: &[u8],
        received: rolling::Tick,
        now: rolling::Tick,
    ) -> Result<(), rolling::Error>;
    fn feedback(receiver: &Self::Receiver) -> Option<scheduler::FeedbackId>;
    fn encode_feedback(receiver: &Self::Receiver, out: &mut [u8]) -> Result<usize, rolling::Error>;
    fn confirm_feedback(
        receiver: &mut Self::Receiver,
        id: scheduler::FeedbackId,
        now: rolling::Tick,
    ) -> Result<(), rolling::Error>;
    fn source(receiver: &Self::Receiver) -> Option<(rolling::SourceId, &[u8])>;
    fn handoff_deadline(receiver: &Self::Receiver) -> Option<rolling::Tick>;
    fn feedback_deadline(receiver: &Self::Receiver) -> Option<rolling::Tick>;
    fn decoded_source(
        receiver: &Self::Receiver,
        id: rolling::SourceId,
    ) -> Result<Option<&[u8]>, rolling::Error>;
    fn handoff(
        receiver: &mut Self::Receiver,
        id: rolling::SourceId,
        now: rolling::Tick,
    ) -> Result<(), rolling::Error>;
    fn receive_committed_source(
        _receiver: &mut Self::Receiver,
        _id: rolling::SourceId,
        _original: &[u8],
        _received: rolling::Tick,
        _now: rolling::Tick,
        _cap: rolling::Tick,
    ) -> Result<Option<rolling::Begin>, rolling::Error> {
        Ok(None)
    }
    fn receive(
        receiver: &mut Self::Receiver,
        bytes: &[u8],
        received: rolling::Tick,
        now: rolling::Tick,
        cap: rolling::Tick,
    ) -> Result<rolling::Begin, rolling::Error>;
    fn inspect(self, bytes: &[u8]) -> Result<View<'_>, rolling::Error>;
    fn send_deadline(sender: &Self::Sender) -> Option<rolling::Tick>;
    fn receive_deadline(receiver: &Self::Receiver) -> Option<rolling::Tick>;
    fn send_expiry(sender: &Self::Sender) -> rolling::expiry::Snapshot;
    fn receive_expiry(receiver: &Self::Receiver) -> rolling::expiry::Snapshot;
    fn send_wake(sender: &Self::Sender) -> Option<rolling::Tick>;
    fn receive_wake(receiver: &Self::Receiver, now: rolling::Tick) -> Option<rolling::Tick>;
}

impl RecoveryPolicy for scheduler::Policy {
    fn targeted(self) -> bool {
        self.source_wire.is_targeted()
    }
    type Compact = compact_wire::Rolling;
    type Sender = scheduler::Sender;
    type Receiver = scheduler::Receiver;
    type SenderStatus = scheduler::SenderStatus;
    type ReceiverStatus = scheduler::ReceiverStatus;
    const HEADER_BYTES: usize = rolling::wire::HEADER_BYTES;
    const FEEDBACK_BYTES: usize = scheduler::FEEDBACK_BYTES;
    const COPIES: bool = true;
    const DOMAIN: &'static [u8] =
        b"l2tunnel/packed-records/local-global-rolling/v1/microsecond-ticks\0";
    const STREAM_DOMAIN: &'static [u8] =
        b"l2tunnel/packed-records/local-global-rolling/stream-binding/v1\0";
    fn validate(self) -> Result<(), rolling::Error> {
        scheduler::Policy::validate(self)
    }
    fn recovery(self) -> rolling::Config {
        self.recovery
    }
    fn validate_owner_bounds(self) -> Result<(), Error> {
        if scheduler::Sender::memory_bound(self).map_err(Error::Rolling)? > self.memory_bytes
            || scheduler::Receiver::memory_bound(self).map_err(Error::Rolling)? > self.memory_bytes
        {
            return Err(Error::Rolling(rolling::Error::Capacity));
        }
        Ok(())
    }
    fn intervals(self) -> [u64; 2] {
        [self.tail_ticks, self.feedback_ticks]
    }
    fn words(self) -> [u64; 18] {
        let f = self.recovery;
        [
            f.window as u64,
            f.local_window as u64,
            u64::from(f.global_every),
            f.max_payload as u64,
            f.max_rows as u64,
            f.repair_history as u64,
            f.handoff_sources as u64,
            f.job_ticks,
            f.debt_ticks,
            f.handoff_ticks,
            f.memory_bytes as u64,
            u64::from(self.repair_numerator),
            u64::from(self.repair_denominator),
            self.tail_ticks,
            self.feedback_ticks,
            u64::from(self.feedback_packets),
            self.memory_bytes as u64,
            u64::from(self.source_wire.version()),
        ]
    }
    fn sender_plan(self) -> Result<OwnerPlan, rolling::storage::Error> {
        let p = rolling::storage::Plan::for_sender(self)?;
        Ok(OwnerPlan {
            capacity_bytes: p.capacity_bytes(),
            allocations: p.allocations(),
        })
    }
    fn receiver_plan(self) -> Result<OwnerPlan, rolling::storage::Error> {
        let p = rolling::storage::Plan::for_receiver(self)?;
        Ok(OwnerPlan {
            capacity_bytes: p.capacity_bytes(),
            allocations: p.allocations(),
        })
    }
    fn new_sender(
        self,
        scope: rolling::Scope,
        now: rolling::Tick,
        reserved: Option<usize>,
    ) -> Result<Self::Sender, Error> {
        if let Some(capacity_bytes) = reserved {
            scheduler::Sender::new_reserved(
                self,
                scope,
                now,
                rolling::storage::Limits { capacity_bytes },
            )
            .map_err(Error::RollingStorage)
        } else {
            scheduler::Sender::new(self, scope, now).map_err(Error::Rolling)
        }
    }
    fn new_receiver(
        self,
        scope: rolling::Scope,
        now: rolling::Tick,
        reserved: Option<usize>,
    ) -> Result<Self::Receiver, Error> {
        if let Some(capacity_bytes) = reserved {
            scheduler::Receiver::new_reserved(
                self,
                scope,
                now,
                rolling::storage::Limits { capacity_bytes },
            )
            .map_err(Error::RollingStorage)
        } else {
            scheduler::Receiver::new(self, scope, now).map_err(Error::Rolling)
        }
    }
    fn sender_usage(s: &Self::Sender) -> Result<rolling::storage::Usage, rolling::storage::Error> {
        s.storage_usage()
    }
    fn receiver_usage(
        r: &Self::Receiver,
    ) -> Result<rolling::storage::Usage, rolling::storage::Error> {
        r.storage_usage()
    }
    fn sender_status(s: &Self::Sender) -> Self::SenderStatus {
        s.status()
    }
    fn receiver_status(r: &Self::Receiver) -> Self::ReceiverStatus {
        r.status()
    }
    fn send_state(s: &Self::Sender) -> SendState {
        let x = s.status();
        let computing_global = s.computing_full_global();
        SendState {
            encoder: x.encoder,
            next_source: x.next_source,
            queued_fresh: x.queued_fresh,
            peak_queued_fresh: x.peak_queued_fresh,
            fresh_queue_limit: x.fresh_queue_limit,
            output_ready: x.output_ready,
            work_pending: computing_global
                || !x.output_ready
                    && (x.queued_fresh > 0
                        || x.encoder.pending_repair
                        || x.regular_due > 0
                        || x.tail_remaining > 0
                        || s.requested_retry_waiting()),
            drained: !x.output_ready
                && !computing_global
                && x.queued_fresh == 0
                && x.regular_due == 0
                && x.tail_remaining == 0
                && x.encoder.confirmed_prefix == x.encoder.next_source,
        }
    }
    fn receive_state(r: &Self::Receiver, _: rolling::Tick) -> ReceiveState {
        let x = r.status();
        ReceiveState {
            decoder: x.decoder,
            feedback_building: x.feedback_building,
            feedback_ready: x.feedback_ready,
            work_pending: false,
            feedback_events: x.feedback_events != 0,
            feedback_due: x.feedback_due,
        }
    }
    fn admit(
        s: &mut Self::Sender,
        b: &[u8],
        created: rolling::Tick,
        n: rolling::Tick,
        c: u8,
    ) -> Result<rolling::SourceId, rolling::Error> {
        s.admit_source_with_copies_at(b, created, n, c)
    }
    fn send_step(
        s: &mut Self::Sender,
        n: rolling::Tick,
        w: rolling::WorkBudget,
    ) -> Result<rolling::WorkUsed, rolling::Error> {
        s.step(n, w)
    }
    fn send_step_filtered(
        s: &mut Self::Sender,
        n: rolling::Tick,
        w: rolling::WorkBudget,
        filter: impl FnMut(rolling::RepairId, rolling::Support) -> Result<bool, rolling::Error>,
    ) -> Result<rolling::WorkUsed, rolling::Error> {
        s.step_with_regular_filter(n, w, filter)
    }
    fn requested_credit(s: &Self::Sender) -> Option<bool> {
        s.pending_requested_credit()
    }
    fn request_counts(s: &Self::Sender) -> scheduler::RequestCounts {
        s.request_counts()
    }
    fn observe_mux_wait(s: &mut Self::Sender, age: u64) {
        s.observe_mux_wait_micros(age);
    }
    fn receive_step(
        r: &mut Self::Receiver,
        n: rolling::Tick,
        w: rolling::WorkBudget,
    ) -> Result<scheduler::ReceiverStep, rolling::Error> {
        r.step(n, w)
    }
    fn pending_data(s: &Self::Sender) -> Result<Option<Data>, rolling::Error> {
        let Some(p) = s.pending_output() else {
            return Ok(None);
        };
        Ok(Some(Data {
            id: p.id(),
            bytes: s.pending_wire_len()?.ok_or(rolling::Error::Identity)?,
            source_copy: if matches!(p, scheduler::Output::Source { .. }) {
                s.pending_source_copy()
            } else {
                None
            },
        }))
    }
    fn encode_data(s: &Self::Sender, o: &mut [u8]) -> Result<usize, rolling::Error> {
        s.encode_pending(o)
    }
    fn pending_original(s: &Self::Sender) -> Option<(rolling::SourceId, usize)> {
        match s.pending_output()? {
            scheduler::Output::Source { id, original, .. } => Some((id, original.len())),
            scheduler::Output::Repair(_) => None,
        }
    }
    fn confirm_data(
        s: &mut Self::Sender,
        id: scheduler::OutputId,
        c: Option<scheduler::SourceCopy>,
        a: rolling::Tick,
        n: rolling::Tick,
        wire_bytes: usize,
    ) -> Result<(), rolling::Error> {
        match (id, c) {
            (scheduler::OutputId::Source(id), Some(c)) if c.source() == id => {
                s.confirm_source_copy_charged(n, a, c, wire_bytes)
            }
            (scheduler::OutputId::Source(_), None) if s.pending_retry_token().is_some() => s
                .confirm_retry_charged(
                    s.pending_retry_token().ok_or(rolling::Error::Identity)?,
                    a,
                    n,
                    wire_bytes,
                ),
            (id, None) => s.confirm_output_charged(id, n, wire_bytes),
            _ => Err(rolling::Error::Identity),
        }
    }
    fn receive_feedback(
        s: &mut Self::Sender,
        b: &[u8],
        _received: rolling::Tick,
        n: rolling::Tick,
    ) -> Result<(), rolling::Error> {
        s.receive_feedback_wire(b, n).map(|_| ())
    }
    fn feedback(r: &Self::Receiver) -> Option<scheduler::FeedbackId> {
        r.pending_feedback().map(|f| f.id)
    }
    fn encode_feedback(r: &Self::Receiver, o: &mut [u8]) -> Result<usize, rolling::Error> {
        let b = r.pending_feedback_wire().ok_or(rolling::Error::Busy)?;
        if o.len() < b.len() {
            return Err(rolling::Error::OutputTooSmall);
        }
        o[..b.len()].copy_from_slice(b);
        Ok(b.len())
    }
    fn confirm_feedback(
        r: &mut Self::Receiver,
        i: scheduler::FeedbackId,
        n: rolling::Tick,
    ) -> Result<(), rolling::Error> {
        r.confirm_feedback(i, n)
    }
    fn handoff_deadline(receiver: &Self::Receiver) -> Option<rolling::Tick> {
        receiver.handoff_deadline()
    }
    fn feedback_deadline(receiver: &Self::Receiver) -> Option<rolling::Tick> {
        receiver.feedback_deadline()
    }
    fn source(r: &Self::Receiver) -> Option<(rolling::SourceId, &[u8])> {
        r.pending_source()
    }
    fn decoded_source(
        r: &Self::Receiver,
        i: rolling::SourceId,
    ) -> Result<Option<&[u8]>, rolling::Error> {
        r.decoded_source(i)
    }
    fn handoff(
        r: &mut Self::Receiver,
        i: rolling::SourceId,
        n: rolling::Tick,
    ) -> Result<(), rolling::Error> {
        r.confirm_handoff(i, n)
    }
    fn receive_committed_source(
        receiver: &mut Self::Receiver,
        id: rolling::SourceId,
        original: &[u8],
        received: rolling::Tick,
        now: rolling::Tick,
        cap: rolling::Tick,
    ) -> Result<Option<rolling::Begin>, rolling::Error> {
        receiver.receive_committed_source_until(id, original, received, now, cap)
    }
    fn receive(
        r: &mut Self::Receiver,
        b: &[u8],
        a: rolling::Tick,
        n: rolling::Tick,
        c: rolling::Tick,
    ) -> Result<rolling::Begin, rolling::Error> {
        r.receive_wire_until(b, a, n, c)
    }
    fn inspect(self, b: &[u8]) -> Result<View<'_>, rolling::Error> {
        match rolling::wire::inspect_with(self.recovery, self.source_wire, b)? {
            rolling::wire::View::Source {
                scope,
                id,
                original,
            } => Ok(View::Source {
                scope,
                id,
                original,
            }),
            rolling::wire::View::Repair(r) => Ok(View::Repair { scope: r.scope }),
        }
    }
    fn send_deadline(s: &Self::Sender) -> Option<rolling::Tick> {
        s.deadline()
    }
    fn receive_deadline(r: &Self::Receiver) -> Option<rolling::Tick> {
        r.deadline()
    }
    fn send_expiry(s: &Self::Sender) -> rolling::expiry::Snapshot {
        s.expiry_snapshot()
    }
    fn receive_expiry(r: &Self::Receiver) -> rolling::expiry::Snapshot {
        r.expiry_snapshot()
    }
    fn send_wake(s: &Self::Sender) -> Option<rolling::Tick> {
        s.wake_at()
    }
    fn receive_wake(r: &Self::Receiver, _: rolling::Tick) -> Option<rolling::Tick> {
        r.wake_at()
    }
}

impl RecoveryPolicy for research::Config {
    type Compact = compact_wire::Research;
    type Sender = research::Sender;
    type Receiver = research::Receiver;
    type SenderStatus = research::SenderStatus;
    type ReceiverStatus = research::ReceiverStatus;
    const HEADER_BYTES: usize = research::wire::HEADER_BYTES;
    const FEEDBACK_BYTES: usize = research::wire::HEADER_BYTES;
    const COPIES: bool = false;
    const DOMAIN: &'static [u8] = b"l2tunnel/packed-records/research/v1/microsecond-ticks\0";
    const STREAM_DOMAIN: &'static [u8] = b"l2tunnel/packed-records/research/stream-binding/v1\0";
    fn validate(self) -> Result<(), rolling::Error> {
        research::Config::validate(self)
    }
    fn recovery(self) -> rolling::Config {
        self.recovery
    }
    fn validate_owner_bounds(self) -> Result<(), Error> {
        research::storage::Plan::for_sender(self).map_err(Error::RollingStorage)?;
        research::storage::Plan::for_receiver(self).map_err(Error::RollingStorage)?;
        Ok(())
    }
    fn intervals(self) -> [u64; 2] {
        [self.feedback_ticks, 0]
    }
    fn words(self) -> [u64; 18] {
        let f = self.recovery;
        let mut profile = [0u8; 16];
        profile[..12].copy_from_slice(&research::wire::profile_bytes(self.profile));
        [
            f.window as u64,
            f.local_window as u64,
            u64::from(f.global_every),
            f.max_payload as u64,
            f.max_rows as u64,
            f.repair_history as u64,
            f.handoff_sources as u64,
            f.job_ticks,
            f.debt_ticks,
            f.handoff_ticks,
            f.memory_bytes as u64,
            u64::from_be_bytes([
                profile[0], profile[1], profile[2], profile[3], profile[4], profile[5], profile[6],
                profile[7],
            ]),
            u64::from_be_bytes([
                profile[8],
                profile[9],
                profile[10],
                profile[11],
                profile[12],
                profile[13],
                profile[14],
                profile[15],
            ]),
            self.feedback_ticks,
            self.memory_bytes as u64,
            0,
            0,
            0,
        ]
    }
    fn sender_plan(self) -> Result<OwnerPlan, rolling::storage::Error> {
        let p = research::storage::Plan::for_sender(self)?;
        Ok(OwnerPlan {
            capacity_bytes: p.capacity_bytes(),
            allocations: p.allocations(),
        })
    }
    fn receiver_plan(self) -> Result<OwnerPlan, rolling::storage::Error> {
        let p = research::storage::Plan::for_receiver(self)?;
        Ok(OwnerPlan {
            capacity_bytes: p.capacity_bytes(),
            allocations: p.allocations(),
        })
    }
    fn new_sender(
        self,
        s: rolling::Scope,
        n: rolling::Tick,
        r: Option<usize>,
    ) -> Result<Self::Sender, Error> {
        if let Some(capacity_bytes) = r {
            research::Sender::new_reserved(self, s, n, rolling::storage::Limits { capacity_bytes })
                .map_err(Error::RollingStorage)
        } else {
            research::Sender::new(self, s, n).map_err(Error::Rolling)
        }
    }
    fn new_receiver(
        self,
        s: rolling::Scope,
        n: rolling::Tick,
        r: Option<usize>,
    ) -> Result<Self::Receiver, Error> {
        if let Some(capacity_bytes) = r {
            research::Receiver::new_reserved(
                self,
                s,
                n,
                rolling::storage::Limits { capacity_bytes },
            )
            .map_err(Error::RollingStorage)
        } else {
            research::Receiver::new(self, s, n).map_err(Error::Rolling)
        }
    }
    fn sender_usage(s: &Self::Sender) -> Result<rolling::storage::Usage, rolling::storage::Error> {
        s.storage_usage()
    }
    fn receiver_usage(
        r: &Self::Receiver,
    ) -> Result<rolling::storage::Usage, rolling::storage::Error> {
        r.storage_usage()
    }
    fn sender_status(s: &Self::Sender) -> Self::SenderStatus {
        s.status()
    }
    fn receiver_status(r: &Self::Receiver) -> Self::ReceiverStatus {
        r.status()
    }
    fn send_state(s: &Self::Sender) -> SendState {
        let x = s.status();
        SendState {
            encoder: x.encoder,
            next_source: x.encoder.next_source,
            queued_fresh: 0,
            peak_queued_fresh: 0,
            fresh_queue_limit: 0,
            output_ready: x.output_ready,
            work_pending: x.repair_pending && !x.output_ready,
            drained: !x.output_ready
                && !x.repair_pending
                && x.encoder.confirmed_prefix == x.encoder.next_source,
        }
    }
    fn receive_state(r: &Self::Receiver, n: rolling::Tick) -> ReceiveState {
        let x = r.status();
        ReceiveState {
            decoder: x.decoder,
            feedback_building: false,
            feedback_ready: x.feedback.is_some(),
            work_pending: x.feedback.is_none() && x.feedback_event.is_some(),
            feedback_events: x.feedback_event.is_some(),
            feedback_due: x.feedback_event.map(|_| n),
        }
    }
    fn admit(
        s: &mut Self::Sender,
        b: &[u8],
        a: rolling::Tick,
        n: rolling::Tick,
        c: u8,
    ) -> Result<rolling::SourceId, rolling::Error> {
        if c != 1 {
            return Err(rolling::Error::Configuration);
        }
        s.admit_source(b, a, n)
    }
    fn send_step(
        s: &mut Self::Sender,
        n: rolling::Tick,
        w: rolling::WorkBudget,
    ) -> Result<rolling::WorkUsed, rolling::Error> {
        s.step(n, w)
    }
    fn receive_step(
        r: &mut Self::Receiver,
        n: rolling::Tick,
        w: rolling::WorkBudget,
    ) -> Result<scheduler::ReceiverStep, rolling::Error> {
        let x = r.step(n, w)?;
        Ok(scheduler::ReceiverStep {
            decode: x.decode,
            work: x.work,
            feedback_ready: x.feedback_ready,
        })
    }
    fn pending_data(s: &Self::Sender) -> Result<Option<Data>, rolling::Error> {
        Ok(s.pending_output().map(|p| Data {
            id: match p.id() {
                research::OutputId::Source(i) => scheduler::OutputId::Source(i),
                research::OutputId::Repair(i) => scheduler::OutputId::Repair(i),
            },
            bytes: p.encoded_len(),
            source_copy: None,
        }))
    }
    fn encode_data(s: &Self::Sender, o: &mut [u8]) -> Result<usize, rolling::Error> {
        s.encode_pending(o)
    }
    fn confirm_data(
        s: &mut Self::Sender,
        i: scheduler::OutputId,
        c: Option<scheduler::SourceCopy>,
        a: rolling::Tick,
        n: rolling::Tick,
        _wire_bytes: usize,
    ) -> Result<(), rolling::Error> {
        if c.is_some() || a > n {
            return Err(rolling::Error::Identity);
        }
        // Research has no retransmit clock. Its retained source/debt caps remain
        // at original creation; observed completion alone earns actual credit.
        s.confirm_output_at(
            match i {
                scheduler::OutputId::Source(i) => research::OutputId::Source(i),
                scheduler::OutputId::Repair(i) => research::OutputId::Repair(i),
            },
            a,
            n,
        )
    }
    fn receive_feedback(
        s: &mut Self::Sender,
        b: &[u8],
        received: rolling::Tick,
        n: rolling::Tick,
    ) -> Result<(), rolling::Error> {
        s.receive_feedback_wire_at(b, received, n).map(|_| ())
    }
    fn feedback(r: &Self::Receiver) -> Option<scheduler::FeedbackId> {
        r.pending_feedback().map(|f| f.id)
    }
    fn encode_feedback(r: &Self::Receiver, o: &mut [u8]) -> Result<usize, rolling::Error> {
        r.encode_feedback(o)
    }
    fn confirm_feedback(
        r: &mut Self::Receiver,
        i: scheduler::FeedbackId,
        n: rolling::Tick,
    ) -> Result<(), rolling::Error> {
        r.confirm_feedback(i, n)
    }
    fn handoff_deadline(receiver: &Self::Receiver) -> Option<rolling::Tick> {
        receiver.handoff_deadline()
    }
    fn feedback_deadline(receiver: &Self::Receiver) -> Option<rolling::Tick> {
        receiver.feedback_deadline()
    }
    fn source(r: &Self::Receiver) -> Option<(rolling::SourceId, &[u8])> {
        r.pending_source()
    }
    fn decoded_source(
        r: &Self::Receiver,
        i: rolling::SourceId,
    ) -> Result<Option<&[u8]>, rolling::Error> {
        r.decoded_source(i)
    }
    fn handoff(
        r: &mut Self::Receiver,
        i: rolling::SourceId,
        n: rolling::Tick,
    ) -> Result<(), rolling::Error> {
        r.confirm_handoff(i, n)
    }
    fn receive(
        r: &mut Self::Receiver,
        b: &[u8],
        a: rolling::Tick,
        n: rolling::Tick,
        c: rolling::Tick,
    ) -> Result<rolling::Begin, rolling::Error> {
        r.receive_wire_at(b, a, n, c)
    }
    fn inspect(self, b: &[u8]) -> Result<View<'_>, rolling::Error> {
        match research::wire::inspect(self, b)? {
            research::wire::View::Source {
                scope,
                id,
                original,
            } => Ok(View::Source {
                scope,
                id,
                original,
            }),
            research::wire::View::Repair(r) => Ok(View::Repair {
                scope: r.equation.scope,
            }),
            research::wire::View::Feedback(_) => Err(rolling::Error::Format),
        }
    }
    fn send_deadline(s: &Self::Sender) -> Option<rolling::Tick> {
        s.deadline()
    }
    fn receive_deadline(r: &Self::Receiver) -> Option<rolling::Tick> {
        r.deadline()
    }
    fn send_expiry(s: &Self::Sender) -> rolling::expiry::Snapshot {
        s.expiry_snapshot()
    }
    fn receive_expiry(r: &Self::Receiver) -> rolling::expiry::Snapshot {
        r.expiry_snapshot()
    }
    fn send_wake(s: &Self::Sender) -> Option<rolling::Tick> {
        s.deadline()
    }
    fn receive_wake(r: &Self::Receiver, n: rolling::Tick) -> Option<rolling::Tick> {
        Self::receive_state(r, n)
            .feedback_due
            .into_iter()
            .chain(r.deadline())
            .min()
    }
}
