use super::*;
use crate::{core::ConfigDigest, management::Role};

/// Complete policy for one global direction, preserving independent maxima.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DirectionConfig {
    /// Explicit body interpretation, without inferring a native device.
    pub native_policy: NativePolicy,
    /// Actual codec, channel, replay, body, context and native lifetime limits.
    pub receiver: receiver::Limits,
    /// Actual timed compact packing and per-channel sender policy.
    pub packing: packed_sender::Config,
    /// Positive first-native-admission age for codec work not yet owned by recovery.
    pub codec_stage_micros: u64,
    /// Actual fixed-window local/global scheduling and bounded work ownership.
    pub scheduler: scheduler::Policy,
}
impl DirectionConfig {
    pub(super) fn packing_plan(self) -> Result<codec::aligned_storage::PackedSenderPlan, Error> {
        (if self.native_policy == NativePolicy::IpHeaders {
            codec::aligned_storage::PackedSenderPlan::for_ip_config
        } else {
            codec::aligned_storage::PackedSenderPlan::for_config
        })(self.packing)
        .map_err(Error::Storage)
    }
    pub(super) fn receiver_plan(self) -> Result<codec::aligned_storage::ReceiverPlan, Error> {
        (if self.native_policy == NativePolicy::IpHeaders {
            codec::aligned_storage::ReceiverPlan::for_ip_limits
        } else {
            codec::aligned_storage::ReceiverPlan::for_limits
        })(self.receiver)
        .map_err(Error::Storage)
    }
    /// Validate actual owners and every cross-owner source/record geometry.
    pub fn validate(self) -> Result<(), Error> {
        self.packing_plan()?;
        self.receiver_plan()?;
        self.receiver
            .batch_memory_bound_bytes()
            .map_err(Error::Receiver)?;
        self.scheduler.validate().map_err(Error::Rolling)?;
        let source = self
            .packing
            .envelope()
            .max_source_bytes()
            .map_err(Error::Envelope)?;
        if self.codec_stage_micros == 0
            || self.packing.sender.body != self.receiver.body
            || self.packing.sender.channels != self.receiver.channels
            || self.packing.sender.first_record != self.receiver.first_record
            || self.packing.first_unit != self.receiver.first_source
            || self.receiver.source_window < usize::from(self.packing.max_units)
            || self.receiver.max_fragments_per_record
                < (self.receiver.body.max_frame_bytes + 29)
                    .clamp(69, 65535)
                    .div_ceil(self.receiver.body.symbol_bytes - 8)
            || source > self.scheduler.recovery.max_payload
            || (self.native_policy == NativePolicy::RawIp
                && (self.receiver.body.predictive
                    || self.receiver.body.elide_payload_length
                    || self.receiver.body.timestamp_pair_dictionary))
        {
            return Err(Error::Configuration);
        }
        if scheduler::Sender::memory_bound(self.scheduler).map_err(Error::Rolling)?
            > self.scheduler.memory_bytes
            || scheduler::Receiver::memory_bound(self.scheduler).map_err(Error::Rolling)?
                > self.scheduler.memory_bytes
        {
            return Err(Error::Rolling(rolling::Error::Capacity));
        }
        Ok(())
    }
    /// Actual full inner data record ceiling, excluding carrier protection.
    pub fn maximum_packet_bytes(self) -> Result<usize, Error> {
        self.validate()?;
        rolling::wire::HEADER_BYTES
            .checked_add(self.scheduler.recovery.width().map_err(Error::Rolling)?)
            .ok_or(Error::Arithmetic)
    }
}

/// Both complete global policies; no absent fields or symmetric fallback.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Config {
    /// Client-to-server records, coding, timing and limits.
    pub forward: DirectionConfig,
    /// Server-to-client records, coding, timing and limits.
    pub reverse: DirectionConfig,
    /// Exact complete carrier/protection/underlay bytes charged once per record.
    pub geometry: Geometry,
    /// Positive original native custody cap, in injected microseconds.
    pub native_stall_micros: u64,
}
impl Config {
    /// Validate both directions before allocating any selected owner.
    pub fn validate(self) -> Result<(), Error> {
        self.forward.validate()?;
        self.reverse.validate()?;
        if self.native_stall_micros == 0 {
            return Err(Error::Configuration);
        }
        for (direction, overhead) in [
            (self.forward, self.geometry.forward_overhead_bytes),
            (self.reverse, self.geometry.reverse_overhead_bytes),
        ] {
            direction
                .maximum_packet_bytes()?
                .checked_add(overhead)
                .ok_or(Error::Arithmetic)?;
            scheduler::FEEDBACK_BYTES
                .checked_add(overhead)
                .ok_or(Error::Arithmetic)?;
            direction
                .receiver
                .body
                .symbol_bytes
                .checked_mul(usize::from(direction.packing.max_units))
                .ok_or(Error::Arithmetic)?;
        }
        Ok(())
    }
    /// Bind the exact coding stream in addition to every complete policy field.
    /// The caller authenticates this value before installing this endpoint.
    pub fn binding_digest(self, stream: u32) -> Result<ConfigDigest, Error> {
        let policy = self.digest()?;
        let mut hash = ring::digest::Context::new(&ring::digest::SHA256);
        hash.update(b"l2tunnel/packed-records/local-global-rolling/stream-binding/v1\0");
        hash.update(&policy.0);
        hash.update(&stream.to_be_bytes());
        Ok(ConfigDigest(
            hash.finish()
                .as_ref()
                .try_into()
                .map_err(|_| Error::Arithmetic)?,
        ))
    }
    pub(super) fn local(self, role: Role) -> (DirectionConfig, DirectionConfig, usize) {
        match role {
            Role::Client => (
                self.forward,
                self.reverse,
                self.geometry.forward_overhead_bytes,
            ),
            Role::Server => (
                self.reverse,
                self.forward,
                self.geometry.reverse_overhead_bytes,
            ),
        }
    }
    /// Domain-separated complete policy digest for the caller's authenticated binding.
    /// This additive identity does not change CompleteV2 or any legacy vectors.
    pub fn digest(self) -> Result<ConfigDigest, Error> {
        self.validate()?;
        let mut hash = ring::digest::Context::new(&ring::digest::SHA256);
        hash.update(b"l2tunnel/packed-records/local-global-rolling/v1/microsecond-ticks\0");
        for c in [self.forward, self.reverse] {
            let r = c.receiver;
            let b = r.body;
            let p = c.packing;
            let s = c.scheduler;
            let f = s.recovery;
            for value in [
                match c.native_policy {
                    NativePolicy::EthernetHeaders => 1,
                    NativePolicy::RawIp => 2,
                    NativePolicy::IpHeaders => 3,
                },
                b.max_frame_bytes as u64,
                b.symbol_bytes as u64,
                u64::from(b.elide_payload_length),
                u64::from(b.predictive),
                u64::from(b.timestamp_pair_dictionary),
                b.independent_short_frame_bytes as u64,
                u64::from(r.channels),
                r.first_record.0,
                r.first_source.0,
                u64::from(r.record_window),
                r.source_window as u64,
                r.lookahead_records as u64,
                r.lookahead_bytes as u64,
                r.lookahead_fragments as u64,
                r.max_fragments_per_record as u64,
                r.lifetime_ticks,
                p.packing.symbol_bytes as u64,
                p.packing.hold_micros,
                u64::from(p.max_units),
                p.first_unit.0,
                p.work_limit as u64,
                c.codec_stage_micros,
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
                u64::from(s.repair_numerator),
                u64::from(s.repair_denominator),
                s.tail_ticks,
                s.feedback_ticks,
                u64::from(s.feedback_packets),
                s.memory_bytes as u64,
                u64::from(s.source_wire.version()),
            ] {
                hash.update(&value.to_be_bytes());
            }
        }
        for value in [
            self.geometry.forward_overhead_bytes as u64,
            self.geometry.reverse_overhead_bytes as u64,
            self.native_stall_micros,
        ] {
            hash.update(&value.to_be_bytes());
        }
        let digest = hash.finish();
        Ok(ConfigDigest(
            digest.as_ref().try_into().map_err(|_| Error::Arithmetic)?,
        ))
    }
}
