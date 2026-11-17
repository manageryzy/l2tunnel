use super::*;
use crate::{core::ConfigDigest, management::Role};

/// Complete policy for one global direction, preserving independent maxima.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DirectionConfig<P: RecoveryPolicy = scheduler::Policy> {
    /// Explicit body interpretation, without inferring a native device.
    pub native_policy: NativePolicy,
    /// Actual codec, channel, replay, body, context and native lifetime limits.
    pub receiver: receiver::Limits,
    /// Actual timed compact packing and per-channel sender policy.
    pub packing: packed_sender::Config,
    /// Positive first-native-admission age for codec work not yet owned by recovery.
    pub codec_stage_micros: u64,
    /// Actual fixed-window local/global scheduling and bounded work ownership.
    pub scheduler: P,
}
impl<P: RecoveryPolicy> DirectionConfig<P> {
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
        if !self.native_policy.available() {
            return Err(Error::Configuration);
        }
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
            || source > self.scheduler.recovery().max_payload
            || (self.native_policy.is_stateless()
                && (self.receiver.body.predictive
                    || self.receiver.body.elide_payload_length
                    || self.receiver.body.timestamp_pair_dictionary))
        {
            return Err(Error::Configuration);
        }
        self.scheduler.validate_owner_bounds()?;
        Ok(())
    }
    /// Actual full inner data record ceiling, excluding carrier protection.
    pub fn maximum_packet_bytes(self) -> Result<usize, Error> {
        self.validate()?;
        P::HEADER_BYTES
            .checked_add(self.scheduler.recovery().width().map_err(Error::Rolling)?)
            .ok_or(Error::Arithmetic)
    }
}

/// Both complete global policies; no absent fields or symmetric fallback.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Config<P: RecoveryPolicy = scheduler::Policy> {
    /// Client-to-server records, coding, timing and limits.
    pub forward: DirectionConfig<P>,
    /// Server-to-client records, coding, timing and limits.
    pub reverse: DirectionConfig<P>,
    /// Exact complete carrier/protection/underlay bytes charged once per record.
    pub geometry: Geometry,
    /// Positive original native custody cap, in injected microseconds.
    pub native_stall_micros: u64,
}
impl<P: RecoveryPolicy> Config<P> {
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
            P::FEEDBACK_BYTES
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
        hash.update(P::STREAM_DOMAIN);
        hash.update(&policy.0);
        hash.update(&stream.to_be_bytes());
        Ok(ConfigDigest(
            hash.finish()
                .as_ref()
                .try_into()
                .map_err(|_| Error::Arithmetic)?,
        ))
    }
    pub(super) fn local(self, role: Role) -> (DirectionConfig<P>, DirectionConfig<P>, usize) {
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
        hash.update(P::DOMAIN);
        for c in [self.forward, self.reverse] {
            let r = c.receiver;
            let b = r.body;
            let p = c.packing;
            let s = c.scheduler;
            for value in [
                u64::from(c.native_policy.wire()),
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
            ] {
                hash.update(&value.to_be_bytes());
            }
            for value in s.words() {
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

/// Explicit global directional fragmentation, selected and authenticated by the parent.
/// None at construction preserves the original unfragmented body and binding bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OutputFraming {
    /// Client-to-server canonical fragments and exact physical overhead.
    pub forward: codec::FragmentConfig,
    /// Server-to-client canonical fragments and exact physical overhead.
    pub reverse: codec::FragmentConfig,
}
impl OutputFraming {
    /// Check every actual data and opposite-driven feedback output before allocation.
    pub fn validate<P: RecoveryPolicy>(self, config: Config<P>) -> Result<(), Error> {
        config.validate()?;
        for (direction, fragment, overhead) in [
            (
                config.forward,
                self.forward,
                config.geometry.forward_overhead_bytes,
            ),
            (
                config.reverse,
                self.reverse,
                config.geometry.reverse_overhead_bytes,
            ),
        ] {
            if fragment.outer_overhead_bytes != overhead {
                return Err(Error::Configuration);
            }
            fragment
                .geometry(direction.maximum_packet_bytes()?)
                .map_err(Error::Fragment)?;
            fragment
                .geometry(P::FEEDBACK_BYTES)
                .map_err(Error::Fragment)?;
        }
        Ok(())
    }
    pub(super) fn local(self, role: Role) -> codec::FragmentConfig {
        match role {
            Role::Client => self.forward,
            Role::Server => self.reverse,
        }
    }
    /// Complete explicit framing commitment, not proof of peer authentication.
    /// The parent binds this selection before installing a framed endpoint.
    pub fn binding_digest<P: RecoveryPolicy>(
        self,
        config: Config<P>,
        copies: CopyPolicies,
        stream: u32,
    ) -> Result<ConfigDigest, Error> {
        self.validate(config)?;
        let base = copies.binding_digest(config, stream)?;
        let mut hash = ring::digest::Context::new(&ring::digest::SHA256);
        hash.update(b"l2tunnel/packed-records/local-global-rolling/output-framing/v1\0");
        hash.update(&base.0);
        for fragment in [self.forward, self.reverse] {
            for value in [
                fragment.path_mtu,
                fragment.outer_overhead_bytes,
                fragment.max_message_bytes,
                usize::from(fragment.max_fragments),
            ] {
                hash.update(
                    &u64::try_from(value)
                        .map_err(|_| Error::Arithmetic)?
                        .to_be_bytes(),
                );
            }
        }
        Ok(ConfigDigest(
            hash.finish()
                .as_ref()
                .try_into()
                .map_err(|_| Error::Arithmetic)?,
        ))
    }
}
