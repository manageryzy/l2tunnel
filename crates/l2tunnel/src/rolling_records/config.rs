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
    /// Requested native release order at this direction's receiver.
    pub native_release: NativeRelease,
    /// Requested return-traffic guard at this direction's sender.
    pub return_guard: ReturnGuard,
}

/// Requested release order of complete native IP packets on a targeted direction.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum NativeRelease {
    /// `FlowOrdered` on a targeted IP direction without the bounded-hold selector;
    /// every other direction keeps its existing release behaviour.
    #[default]
    Default,
    /// Release complete TCP data across sequence gaps.
    Independent,
    /// Release TCP data only when it is contiguous with its own flow's edge.
    FlowOrdered,
}
impl NativeRelease {
    /// Canonical configuration value; zero is the legacy all-default encoding.
    pub const fn wire(self) -> u8 {
        match self {
            Self::Default => 0,
            Self::Independent => 1,
            Self::FlowOrdered => 2,
        }
    }
    /// Strict inverse of [`Self::wire`].
    pub const fn from_wire(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::Default),
            1 => Some(Self::Independent),
            2 => Some(Self::FlowOrdered),
            _ => None,
        }
    }
}

/// Effective native release after default resolution, for status and dispatch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EffectiveRelease {
    /// Channel record order; no per-flow tracking is configured.
    Channel,
    /// Ethernet TCP data in flow order with the existing TAP decision.
    EthernetFlowOrdered,
    /// The authenticated bounded native reordering hold.
    BoundedHold,
    /// Complete IP TCP data released across sequence gaps.
    Independent,
    /// IP TCP data released only when contiguous with its flow.
    FlowOrdered,
}

/// Requested return-traffic guard mode.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum GuardMode {
    /// On at [`ReturnGuard::DEFAULT_PER_MILLE`] for a targeted IP direction; otherwise off.
    #[default]
    Default,
    /// Measure only; never shed.
    Off,
    /// Shed sheddable extras above the configured ratio.
    On,
}

/// Local sender limit on sheddable bytes relative to delivered peer traffic.
///
/// First copies of local sources, feedback, requested retries and control are
/// never shed. This changes no packet format.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ReturnGuard {
    /// Requested mode.
    pub mode: GuardMode,
    /// Sent wire bytes per thousand delivered peer bytes; nonzero only for `On`.
    pub per_mille: u16,
}
impl ReturnGuard {
    /// Default ratio when the default mode resolves to on.
    pub const DEFAULT_PER_MILLE: u16 = 100;
    /// Default mode, resolved per direction.
    pub const DEFAULT: Self = Self {
        mode: GuardMode::Default,
        per_mille: 0,
    };
    /// Explicitly measure only.
    pub const OFF: Self = Self {
        mode: GuardMode::Off,
        per_mille: 0,
    };
    /// Explicitly shed above `per_mille`, which must be within 1..=1000.
    pub const fn on(per_mille: u16) -> Self {
        Self {
            mode: GuardMode::On,
            per_mille,
        }
    }
    /// Canonical configuration mode value; zero is the legacy all-default encoding.
    pub const fn mode_wire(self) -> u8 {
        match self.mode {
            GuardMode::Default => 0,
            GuardMode::Off => 1,
            GuardMode::On => 2,
        }
    }
    /// Strict inverse of [`Self::mode_wire`] with its ratio.
    pub const fn from_wire(mode: u8, per_mille: u16) -> Option<Self> {
        let mode = match mode {
            0 => GuardMode::Default,
            1 => GuardMode::Off,
            2 => GuardMode::On,
            _ => return None,
        };
        Some(Self { mode, per_mille })
    }
    fn valid(self) -> bool {
        match self.mode {
            GuardMode::On => (1..=1000).contains(&self.per_mille),
            GuardMode::Default | GuardMode::Off => self.per_mille == 0,
        }
    }
}

impl<P: RecoveryPolicy> DirectionConfig<P> {
    /// Whether this direction has the per-flow release choice.
    fn release_selectable(self) -> bool {
        self.scheduler.targeted()
            && self.native_policy.is_ip()
            && !self.scheduler.hold_native_reordering()
    }
    /// Whether both delivery fields are at their default values.
    pub fn delivery_default(self) -> bool {
        self.native_release == NativeRelease::Default && self.return_guard == ReturnGuard::DEFAULT
    }
    /// Effective native release after default resolution.
    pub fn effective_release(self) -> EffectiveRelease {
        let tracked = self.scheduler.targeted()
            && (self.native_policy.is_ip() || self.receiver.body.independent_short_frame_bytes > 0);
        if !tracked {
            EffectiveRelease::Channel
        } else if self.scheduler.hold_native_reordering() {
            EffectiveRelease::BoundedHold
        } else if !self.native_policy.is_ip() {
            EffectiveRelease::EthernetFlowOrdered
        } else if self.native_release == NativeRelease::Independent {
            EffectiveRelease::Independent
        } else {
            EffectiveRelease::FlowOrdered
        }
    }
    /// Effective guard ratio after default resolution; `None` means measure only.
    pub fn effective_guard_per_mille(self) -> Option<u16> {
        match self.return_guard.mode {
            GuardMode::On => Some(self.return_guard.per_mille),
            GuardMode::Off => None,
            GuardMode::Default => (self.scheduler.targeted() && self.native_policy.is_ip())
                .then_some(ReturnGuard::DEFAULT_PER_MILLE),
        }
    }
    pub(super) fn packing_plan(self) -> Result<codec::aligned_storage::PackedSenderPlan, Error> {
        (if self.native_policy.uses_ip_headers() {
            codec::aligned_storage::PackedSenderPlan::for_ip_config
        } else {
            codec::aligned_storage::PackedSenderPlan::for_config
        })(self.packing)
        .map_err(Error::Storage)
    }
    pub(super) fn uses_standard_ip_replay_plan(self) -> bool {
        // Fixed-anchor receivers provision early replay together with their anchor history.
        self.scheduler.targeted()
            && self.native_policy.is_ip()
            && self.native_policy != NativePolicy::FixedAnchorIpHeaders
    }
    pub(super) fn receiver_plan(self) -> Result<codec::aligned_storage::ReceiverPlan, Error> {
        if self.uses_standard_ip_replay_plan() {
            codec::aligned_storage::ReceiverPlan::for_ip_limits_with_early_replay(self.receiver)
        } else {
            self.native_policy.receiver_plan(self.receiver)
        }
        .map_err(Error::Storage)
    }
    /// Validate actual owners and every cross-owner source/record geometry.
    pub fn validate(self) -> Result<(), Error> {
        if !self.native_policy.available()
            || !self.return_guard.valid()
            || (self.native_release != NativeRelease::Default && !self.release_selectable())
            || (self.return_guard.mode != GuardMode::Default
                && !(self.scheduler.targeted() && self.native_policy.is_ip()))
        {
            return Err(Error::Configuration);
        }
        // A recovery owner that abandons holes loses records; only a policy
        // whose later records stay decodable may be paired with it.
        // The peer's held send stage must outlive one abandonment cap, or a
        // hole that waits for the cap expires the session first.
        if self.scheduler.abandons_holes()
            && (!self.native_policy.survives_record_loss()
                || self.scheduler.abandon_ticks() >= self.codec_stage_micros)
        {
            return Err(Error::Configuration);
        }
        if self.scheduler.compresses_packed_acks()
            && (self.native_policy != NativePolicy::IpHeaders
                || !codec::aligned_body::lz4_available()
                || self.receiver.body.independent_short_frame_bytes == 0)
        {
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
        if self.native_stall_micros == 0 || self.forward.scheduler.compresses_packed_acks() {
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
        // All-default delivery keeps the exact legacy digest.
        if !(self.forward.delivery_default() && self.reverse.delivery_default()) {
            hash.update(b"l2tunnel/rolling-records/delivery-policy/v1\0");
            for c in [self.forward, self.reverse] {
                for value in [
                    u64::from(c.native_release.wire()),
                    u64::from(c.return_guard.mode_wire()),
                    u64::from(c.return_guard.per_mille),
                ] {
                    hash.update(&value.to_be_bytes());
                }
            }
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
