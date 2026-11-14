//! Explicit timed packed sources using the existing aligned lifecycle and recovery.
use super::*;
use l2tunnel_codec::{packed as packing, packed_envelope, packed_sender};
use std::mem::size_of;

/// Distinct authenticated packed profile; ordinary aligned wire is unchanged.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Config {
    /// Common native, receiver, reliable and complete packet policy.
    pub base: super::Config,
    /// Original first-unit hold, in1..1000 injected microseconds.
    pub hold_micros: u64,
    /// Maximum complete units per packed recovery source, in1..255.
    pub max_units: u8,
    /// Maximum unit copy attempts per service call, in1..255.
    pub work_limit: usize,
}
#[derive(Clone, Copy)]
pub(super) struct Options {
    pub hold_micros: u64,
    pub max_units: u8,
    pub work_limit: usize,
}
impl Config {
    pub(super) fn options(self) -> Options {
        Options {
            hold_micros: self.hold_micros,
            max_units: self.max_units,
            work_limit: self.work_limit,
        }
    }
    pub(super) fn sender(self) -> packed_sender::Config {
        packed_sender::Config {
            sender: super::sender_config(self.base),
            packing: packing::Config {
                symbol_bytes: self.base.receiver.body.symbol_bytes,
                hold_micros: self.hold_micros,
            },
            max_units: self.max_units,
            first_unit: self.base.receiver.first_source,
            work_limit: self.work_limit,
        }
    }
    /// Exact packed envelope geometry, before the existing recovery wrapper.
    pub fn envelope(self) -> packed_envelope::Config {
        self.sender().envelope()
    }
    /// Historical allocating-owner scalar gate, excluding caller storage.
    /// Actual reserved capacity is reported only by storage::Plan/Usage.
    pub fn codec_memory_bound_bytes(self) -> Result<usize, Error> {
        let sender = self
            .sender()
            .memory_bound_bytes()
            .map_err(Error::PackedSender)?;
        let source = self
            .envelope()
            .max_source_bytes()
            .map_err(Error::PackedEnvelope)?;
        let units = usize::from(self.max_units);
        self.base
            .receiver
            .batch_memory_bound_bytes()
            .map_err(Error::Receiver)?
            .checked_add(sender)
            .and_then(|n| n.checked_add(2 * source))
            .and_then(|n| n.checked_add(units * self.base.receiver.body.symbol_bytes))
            .and_then(|n| n.checked_add(units * size_of::<receiver::AuthenticatedSymbol<'_>>()))
            .and_then(|n| n.checked_add(size_of::<LegacyEndpointLayout>()))
            .filter(|n| *n <= 256 * 1024 * 1024)
            .ok_or(Error::Configuration)
    }
    /// Validate geometry, empty-receiver batch progress and all finite owner limits.
    pub fn validate(self) -> Result<(), Error> {
        self.codec_memory_bound_bytes()?;
        let units = usize::from(self.max_units);
        let limits = self.base.receiver;
        let maximum_record = limits
            .max_fragments_per_record
            .checked_mul(limits.body.symbol_bytes - 8)
            .ok_or(Error::Configuration)?
            .min(65535)
            .max(limits.body.symbol_bytes - 3);
        if limits.lookahead_records < units
            || limits.lookahead_bytes < units * maximum_record
            || limits.lookahead_fragments < units * limits.max_fragments_per_record
            || usize::from(limits.record_window) < units
        {
            return Err(Error::Configuration);
        }
        // These are unit slots, not reliable/FEC source slots. Recovery delivers
        // each source in order and envelopes require the exact contiguous floor.
        self.base.validate_geometry(
            self.envelope()
                .max_source_bytes()
                .map_err(Error::PackedEnvelope)?,
            units,
        )
    }
    /// Every common and packed policy field under a distinct authenticated domain.
    pub fn digest(self) -> Result<ConfigDigest, Error> {
        self.validate()?;
        let mut bytes = Vec::with_capacity(672);
        bytes.extend_from_slice(b"l2tunnel/packed-envelope-v1/reliable-v1/config-v1\0");
        self.base.append_fields(&mut bytes);
        for value in [
            self.hold_micros,
            u64::from(self.max_units),
            self.work_limit as u64,
        ] {
            number(&mut bytes, value);
        }
        Ok(config_hash(&bytes))
    }
    /// Largest configured emission including the existing external wire charge.
    pub fn maximum_charged_bytes(self) -> Result<usize, Error> {
        self.validate()?;
        self.base
            .max_recovery_packet_bytes
            .checked_add(self.base.recovery.outer_overhead_bytes)
            .ok_or(Error::Configuration)
    }
}
// Compatibility-only pre-storage header shape. Byte arrays stand for original
// dependency inline headers; they allocate no memory and grant no reservation.
// Every actual new dependency/codec/header layout is counted by storage::Plan.
#[allow(dead_code)]
enum LegacySenderOwner {
    Aligned(Box<()>),
    Packed(Box<()>),
}
#[allow(dead_code)]
struct LegacyEndpointLayout {
    config: super::Config,
    receive_config: super::Config,
    receive_scope: receiver::Scope,
    send_scope: receiver::Scope,
    sender: LegacySenderOwner,
    packing: Option<Options>,
    receive_packing: Option<Options>,
    packed_symbols: Vec<u8>,
    recovery: [u8; l2tunnel_reliable::Reliable::legacy_inline_bytes()],
    receiver: [u8; receiver::Receiver::legacy_inline_bytes()],
    send_buffer: Vec<u8>,
    receive_buffer: Vec<u8>,
    handoff: Option<(u64, usize, Duration)>,
    now: Duration,
    failure: Option<Error>,
}
impl Options {
    pub(super) fn config(self, base: super::Config) -> Config {
        Config {
            base,
            hold_micros: self.hold_micros,
            max_units: self.max_units,
            work_limit: self.work_limit,
        }
    }
}
pub(super) fn micros(now: Duration) -> Result<u64, Error> {
    u64::try_from(now.as_micros()).map_err(|_| Error::Time)
}
pub(super) enum SenderOwner {
    Aligned(Vec<sender::Sender>),
    Packed(Vec<packed_sender::Sender>),
}
impl SenderOwner {
    pub(super) fn is_pending(&self) -> bool {
        match self {
            Self::Aligned(s) => s[0].is_pending(),
            Self::Packed(s) => !s[0].is_idle(),
        }
    }
    pub(super) fn staged_frame(&self) -> bool {
        match self {
            Self::Aligned(s) => s[0].is_pending(),
            Self::Packed(s) => s[0].status().staged_frame,
        }
    }
    pub(super) fn packing(&self) -> Option<packed_sender::Status> {
        match self {
            Self::Aligned(_) => None,
            Self::Packed(s) => Some(s[0].status()),
        }
    }
    pub(super) fn stage(
        &mut self,
        policy: NativePolicy,
        channel: ChannelId,
        frame: &[u8],
        now: Duration,
    ) -> Result<receiver::RecordIdentity, Error> {
        match self {
            Self::Aligned(s) => match policy {
                NativePolicy::EthernetHeaders => s[0].stage_identified(channel, frame),
                NativePolicy::RawIp => s[0].stage_raw_identified(channel, frame),
            }
            .map_err(|e| {
                if e == sender::Error::Busy {
                    Error::Busy
                } else {
                    Error::Sender(e)
                }
            }),
            Self::Packed(s) => match policy {
                NativePolicy::EthernetHeaders => {
                    s[0].stage_identified(channel, frame, micros(now)?)
                }
                NativePolicy::RawIp => s[0].stage_raw_identified(channel, frame, micros(now)?),
            }
            .map_err(|e| {
                if e == packed_sender::Error::Busy {
                    Error::Busy
                } else {
                    Error::PackedSender(e)
                }
            }),
        }
    }
    pub(super) fn write_pending(
        &mut self,
        source: receiver::SourceId,
        output: &mut [u8],
    ) -> Result<usize, Error> {
        match self {
            Self::Aligned(s) => s[0].write_pending(source, output).map_err(Error::Sender),
            Self::Packed(s) => s[0]
                .write_pending(source, output)
                .map_err(Error::PackedSender),
        }
    }
    pub(super) fn commit_source(&mut self) -> Result<(), Error> {
        match self {
            Self::Aligned(s) => s[0].commit_source().map_err(Error::Sender),
            Self::Packed(s) => s[0].commit_source().map_err(Error::PackedSender),
        }
    }
}

/// Explicit packed capability; no automatic detection or ordinary-wire fallback.
pub struct Endpoint(super::Endpoint);
impl Endpoint {
    /// Fallibly reserve the complete actual equal-policy Packed endpoint.
    pub fn new_reserved(
        config: Config,
        context: RecoveryContext,
        limits: storage::Limits,
    ) -> Result<Self, storage::Error> {
        Self::new_duplex_reserved(config, config, context, limits)
    }
    /// Reserve independent Packed send/receive policies without unused halves.
    pub fn new_duplex_reserved(
        send: Config,
        receive: Config,
        context: RecoveryContext,
        limits: storage::Limits,
    ) -> Result<Self, storage::Error> {
        let plan = storage::Plan::for_packed_duplex(send, receive)?;
        super::Endpoint::new_reserved_profile(plan, context, limits).map(Self)
    }
    /// Complete actual retained heap; allocating construction reports None.
    pub fn storage_usage(&self) -> Option<storage::Usage> {
        self.0.storage_usage()
    }
    /// Allocate one exclusive pair of codec/recovery owners after full validation.
    pub fn new(config: Config, context: RecoveryContext) -> Result<Self, Error> {
        super::Endpoint::new_profile(config.base, context, Some(config.options())).map(Self)
    }
    /// Construct the shared owner with complete independent packed direction policies.
    pub fn new_duplex(
        send: Config,
        receive: Config,
        context: RecoveryContext,
    ) -> Result<Self, Error> {
        super::Endpoint::new_duplex_profile(
            send.base,
            receive.base,
            context,
            Some(send.options()),
            Some(receive.options()),
        )
        .map(Self)
    }
    /// Retain one frame already selected by common MUX/QoS; no peer credit is implied.
    pub fn enqueue_admitted(
        &mut self,
        channel: ChannelId,
        frame: &[u8],
        now: Duration,
    ) -> Result<(), Error> {
        self.0.enqueue_admitted(channel, frame, now)
    }
    /// Retain one native frame and return its actual body identity, not a context.
    pub fn enqueue_identified(
        &mut self,
        channel: ChannelId,
        frame: &[u8],
        now: Duration,
    ) -> Result<receiver::RecordIdentity, Error> {
        self.0.enqueue_identified(channel, frame, now)
    }
    /// Inspect source units through the same authoritative recovery/envelope parsers.
    pub fn outgoing_units(
        &mut self,
        packet: &[u8],
        output: &mut [receiver::UnitWitness],
    ) -> Result<usize, Error> {
        self.0.outgoing_units(packet, output)
    }
    /// Explicit raw-IP staging under the authenticated native policy.
    pub fn enqueue_admitted_raw(
        &mut self,
        channel: ChannelId,
        frame: &[u8],
        now: Duration,
    ) -> Result<(), Error> {
        self.0.enqueue_admitted_raw(channel, frame, now)
    }
    /// Service one bounded packing step and seal retained units for deliberate drain.
    pub fn flush(&mut self, now: Duration) -> Result<(), Error> {
        self.0.advance(now)?;
        let result = match &mut self.0.sender {
            SenderOwner::Packed(s) => s[0].flush(micros(now)?).map_err(Error::PackedSender),
            SenderOwner::Aligned(_) => Err(Error::Configuration),
        };
        self.0.terminal_result(result)?;
        self.0.submit_packed()
    }
    /// Emit data/repair/retry under the common full-wire allowance.
    pub fn poll_data(
        &mut self,
        now: Duration,
        output: &mut [u8],
        budget: &mut OutboundBudget,
    ) -> Result<Option<usize>, Error> {
        self.0.poll_data(now, output, budget)
    }
    /// Emit authoritative feedback under that same allowance.
    pub fn poll_feedback(
        &mut self,
        now: Duration,
        output: &mut [u8],
        budget: &mut OutboundBudget,
    ) -> Result<Option<usize>, Error> {
        self.0.poll_feedback(now, output, budget)
    }
    /// Receive complete recovery bytes only after carrier authentication/replay checks.
    pub fn receive_authenticated(&mut self, packet: &[u8], now: Duration) -> Result<(), Error> {
        self.0.receive_authenticated(packet, now)
    }
    /// Prepare bounded work on the scheduler-selected ordinary channel.
    pub fn prepare(
        &mut self,
        channel: ChannelId,
        now: Duration,
        max_records: usize,
    ) -> Result<Prepared, Error> {
        self.0.prepare(channel, now, max_records)
    }
    /// Immutable native output awaiting actual complete device acceptance.
    pub fn pending(&self) -> Option<Delivery<'_>> {
        self.0.pending()
    }
    /// Original expiry of pending native custody, excluding recovery/packing work.
    pub fn pending_deadline(&self) -> Option<Duration> {
        self.0.pending_deadline()
    }
    /// Commit only actual whole-frame native acceptance, never semantic simulation.
    pub fn commit_delivery(&mut self, now: Duration) -> Result<(), Error> {
        self.0.commit_delivery(now)
    }
    /// Service injected packing, handoff and receiver lifetimes while idle.
    pub fn tick(&mut self, now: Duration) -> Result<(), Error> {
        self.0.tick(now)
    }
    /// Earliest original packing/recovery/receiver/source-handoff deadline.
    pub fn deadline(&self) -> Option<Duration> {
        self.0.deadline()
    }
    /// True only when every codec, recovery and native owner drained without failure.
    pub fn drained(&self) -> bool {
        self.0.drained()
    }
    /// Complete recovery output ceiling before carrier overhead.
    pub fn max_packet_bytes(&self) -> usize {
        self.0.max_packet_bytes()
    }
    /// Exact local recovery emission ceiling before external overhead.
    pub fn send_max_packet_bytes(&self) -> usize {
        self.0.send_max_packet_bytes()
    }
    /// Exact peer recovery packet ceiling used by authenticated ingress.
    pub fn receive_max_packet_bytes(&self) -> usize {
        self.0.receive_max_packet_bytes()
    }
    /// Authoritative classification of one authenticated peer recovery record.
    pub fn inspect_peer(&self, packet: &[u8]) -> Result<l2tunnel_reliable::RecordKind, Error> {
        self.0.inspect_peer(packet)
    }
    /// Authoritative classification of one local recovery emission.
    pub fn inspect_output(&self, packet: &[u8]) -> Result<l2tunnel_reliable::RecordKind, Error> {
        self.0.inspect_output(packet)
    }
    /// Actual FEC/ARQ statistics, never inferred from codec work.
    pub fn statistics(&self) -> l2tunnel_reliable::Statistics {
        self.0.statistics()
    }
    /// Actual source/retry receipt counters from the authoritative ARQ owner.
    pub fn arq_statistics(&self) -> l2tunnel_recovery::Statistics {
        self.0.arq_statistics()
    }
    /// Retained source/unit/native ownership without consuming or acknowledging it.
    pub fn status(&self) -> Status {
        self.0.status()
    }
}
