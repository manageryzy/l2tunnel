//! Genuine Compact R0 policy and actual body-owner construction.
use super::*;
use l2tunnel_codec::source_copy;
use l2tunnel_recovery::{CompactArqConfig, CompactBounds, CompactRecovery, CompactTiming};
use l2tunnel_reliable::CompactReliableConfig;

/// Active canonical directional bytes, including explicit copy policy.
pub const CONFIG_BYTES: usize = 249;
/// Complete Compact R0 policy with no unused legacy/FEC parameters.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Config {
    /// Exact authenticated native interpretation.
    pub native_policy: NativePolicy,
    /// Actual ordering, body, bounded lookahead and original native lifetime.
    pub receiver: receiver::Limits,
    /// Complete actual adaptive Compact recovery direction and wire overhead.
    pub recovery: CompactReliableConfig,
    /// Explicit complete recovery-packet ceiling, excluding carrier overhead.
    pub max_recovery_packet_bytes: usize,
    /// Complete requested unit-copy policy; installation capability is separate.
    pub copies: source_copy::Policy,
}
impl Config {
    /// Validate exact ordinary geometry and the complete requested policy.
    /// Multi-copy capability is checked by construction before provisioning.
    pub fn validate(self) -> Result<(), Error> {
        self.validate_geometry(
            envelope::HEADER_BYTES
                .checked_add(self.receiver.body.symbol_bytes)
                .ok_or(Error::Configuration)?,
            self.recovery.arq().bounds().receive_records,
        )
    }
    pub(super) fn validate_geometry(
        self,
        original: usize,
        minimum_sources: usize,
    ) -> Result<(), Error> {
        self.receiver
            .memory_bound_bytes()
            .map_err(Error::Receiver)?;
        sender_config(self.body())
            .memory_bound_bytes()
            .map_err(Error::Sender)?;
        self.recovery.validate().map_err(Error::Recovery)?;
        self.copies
            .validate(self.receiver.body.symbol_bytes)
            .map_err(|_| Error::Configuration)?;
        let fragments = (self.receiver.body.max_frame_bytes + 29)
            .clamp(69, 65_535)
            .div_ceil(self.receiver.body.symbol_bytes - 8);
        if self.native_policy == NativePolicy::RawIp
            && (self.receiver.body.elide_payload_length
                || self.receiver.body.predictive
                || self.receiver.body.timestamp_pair_dictionary)
            || self.receiver.first_source.0 != 0
            || self.receiver.source_window < minimum_sources
            || self.receiver.max_fragments_per_record < fragments
            || self.recovery.arq().bounds().max_source_bytes != original
            || self.max_recovery_packet_bytes > 65_507
        {
            return Err(Error::Configuration);
        }
        let maximum = original
            .checked_add(l2tunnel_recovery::COMPACT_DATA_HEADER_BYTES)
            .and_then(|n| n.checked_add(l2tunnel_reliable::ENVELOPE_BYTES))
            .ok_or(Error::Configuration)?;
        if maximum > self.max_recovery_packet_bytes {
            return Err(Error::Configuration);
        }
        Ok(())
    }
    pub(super) fn body(self) -> BodyConfig {
        let bounds = self.recovery.arq().bounds();
        BodyConfig {
            native_policy: self.native_policy,
            receiver: self.receiver,
            send_records: bounds.send_records,
            receive_records: bounds.receive_records,
            outer_overhead_bytes: self.recovery.outer_overhead_bytes(),
            compact: true,
        }
    }
    /// Canonical complete requested policy, without selecting runtime capability.
    pub fn encode_into(self, output: &mut [u8]) -> Result<(), Error> {
        self.validate()?;
        self.encode_fields(output)
    }
    pub(super) fn encode_fields(self, output: &mut [u8]) -> Result<(), Error> {
        if output.len() != CONFIG_BYTES {
            return Err(Error::Configuration);
        }
        let mut w = Writer::new(output);
        w.byte(match self.native_policy {
            NativePolicy::EthernetHeaders => 1,
            NativePolicy::RawIp => 2,
            NativePolicy::IpHeaders => 3,
        })?;
        let r = self.receiver;
        let b = r.body;
        for n in [
            b.max_frame_bytes,
            b.symbol_bytes,
            b.independent_short_frame_bytes,
        ] {
            w.size(n)?;
        }
        for flag in [
            b.elide_payload_length,
            b.predictive,
            b.timestamp_pair_dictionary,
        ] {
            w.byte(u8::from(flag))?;
        }
        for n in [
            u64::from(r.channels),
            r.first_record.0,
            r.first_source.0,
            u64::from(r.record_window),
            u64::try_from(r.source_window).map_err(|_| Error::Configuration)?,
            u64::try_from(r.lookahead_records).map_err(|_| Error::Configuration)?,
            u64::try_from(r.lookahead_bytes).map_err(|_| Error::Configuration)?,
            u64::try_from(r.lookahead_fragments).map_err(|_| Error::Configuration)?,
            u64::try_from(r.max_fragments_per_record).map_err(|_| Error::Configuration)?,
            r.lifetime_ticks,
        ] {
            w.number(n)?;
        }
        let arq = self.recovery.arq();
        let bounds = arq.bounds();
        let timing = arq.timing();
        for n in [
            bounds.max_source_bytes,
            bounds.send_bytes,
            bounds.receive_bytes,
            bounds.send_records,
            bounds.receive_records,
        ] {
            w.size(n)?;
        }
        w.duration(timing.nominal_rtt)?;
        w.duration(timing.feedback_interval)?;
        for n in [
            timing.feedback_packets,
            arq.maximum_feedback_bytes(),
            arq.history_entries(),
        ] {
            w.size(n)?;
        }
        w.number(u64::from(arq.maximum_attempts()))?;
        let (mode, gap) = match arq.recovery() {
            CompactRecovery::Guarded => (1, Duration::ZERO),
            CompactRecovery::FirstFlight => (2, Duration::ZERO),
            CompactRecovery::BoundedGap { min_interval } => (3, min_interval),
        };
        w.byte(mode)?;
        w.duration(gap)?;
        w.size(self.recovery.outer_overhead_bytes())?;
        w.size(self.max_recovery_packet_bytes)?;
        let threshold =
            u16::try_from(self.copies.max_unit_bytes).map_err(|_| Error::Configuration)?;
        w.bytes(&threshold.to_be_bytes())?;
        w.byte(self.copies.copies)?;
        w.byte(match self.copies.scope {
            source_copy::Scope::AllShort => 1,
            source_copy::Scope::ContextAndIndependent => 2,
        })?;
        w.finish()
    }
    /// Parse canonical complete ordinary policy and reject every invalid field.
    pub fn decode(input: &[u8]) -> Result<Self, Error> {
        let value = Self::decode_fields(input)?;
        value.validate()?;
        Ok(value)
    }
    pub(super) fn decode_fields(input: &[u8]) -> Result<Self, Error> {
        if input.len() != CONFIG_BYTES {
            return Err(Error::Configuration);
        }
        let mut r = Reader::new(input);
        let native_policy = match r.byte()? {
            1 => NativePolicy::EthernetHeaders,
            2 => NativePolicy::RawIp,
            3 => NativePolicy::IpHeaders,
            _ => return Err(Error::Configuration),
        };
        let body = l2tunnel_codec::aligned_body::Config {
            max_frame_bytes: r.size()?,
            symbol_bytes: r.size()?,
            independent_short_frame_bytes: r.size()?,
            elide_payload_length: r.boolean()?,
            predictive: r.boolean()?,
            timestamp_pair_dictionary: r.boolean()?,
        };
        let receiver = receiver::Limits {
            body,
            channels: r.number()?.try_into().map_err(|_| Error::Configuration)?,
            first_record: receiver::RecordId(r.number()?),
            first_source: receiver::SourceId(r.number()?),
            record_window: r.number()?.try_into().map_err(|_| Error::Configuration)?,
            source_window: r.size()?,
            lookahead_records: r.size()?,
            lookahead_bytes: r.size()?,
            lookahead_fragments: r.size()?,
            max_fragments_per_record: r.size()?,
            lifetime_ticks: r.number()?,
        };
        let bounds = CompactBounds {
            max_source_bytes: r.size()?,
            send_bytes: r.size()?,
            receive_bytes: r.size()?,
            send_records: r.size()?,
            receive_records: r.size()?,
        };
        let timing = CompactTiming {
            nominal_rtt: r.duration()?,
            feedback_interval: r.duration()?,
            feedback_packets: r.size()?,
        };
        let maximum_feedback_bytes = r.size()?;
        let history_entries = r.size()?;
        let maximum_attempts = r.number()?.try_into().map_err(|_| Error::Configuration)?;
        let mode = r.byte()?;
        let gap = r.duration()?;
        let recovery = match mode {
            1 if gap.is_zero() => CompactRecovery::Guarded,
            2 if gap.is_zero() => CompactRecovery::FirstFlight,
            3 => CompactRecovery::BoundedGap { min_interval: gap },
            _ => return Err(Error::Configuration),
        };
        let arq = CompactArqConfig::new(
            bounds,
            timing,
            maximum_feedback_bytes,
            history_entries,
            maximum_attempts,
            recovery,
        )
        .map_err(|e| Error::Recovery(l2tunnel_reliable::Error::Arq(e)))?;
        let recovery = CompactReliableConfig::new(arq, r.size()?).map_err(Error::Recovery)?;
        let max_recovery_packet_bytes = r.size()?;
        let bytes = r.take(2)?;
        let threshold = usize::from(u16::from_be_bytes([bytes[0], bytes[1]]));
        let copies = source_copy::Policy {
            max_unit_bytes: threshold,
            copies: r.byte()?,
            scope: match r.byte()? {
                1 => source_copy::Scope::AllShort,
                2 => source_copy::Scope::ContextAndIndependent,
                _ => return Err(Error::Configuration),
            },
        };
        r.finish()?;
        Ok(Self {
            native_policy,
            receiver,
            recovery,
            max_recovery_packet_bytes,
            copies,
        })
    }
    /// Distinct complete policy digest; never the legacy FEC/ARQ domain.
    pub fn digest(self) -> Result<ConfigDigest, Error> {
        self.validate()?;
        let mut bytes = [0; CONFIG_BYTES];
        self.encode_fields(&mut bytes)?;
        Ok(hash_fields(
            b"l2tunnel/aligned-envelope-v1/compact-r0-v2/config-v1\0",
            &bytes,
        ))
    }
}

#[derive(Clone, Copy)]
pub(super) struct BodyConfig {
    pub native_policy: NativePolicy,
    pub receiver: receiver::Limits,
    pub send_records: usize,
    pub receive_records: usize,
    pub outer_overhead_bytes: usize,
    pub compact: bool,
}
impl From<super::Config> for BodyConfig {
    fn from(c: super::Config) -> Self {
        Self {
            native_policy: c.native_policy,
            receiver: c.receiver,
            send_records: c.recovery.arq.send_records,
            receive_records: c.recovery.arq.receive_records,
            outer_overhead_bytes: c.recovery.outer_overhead_bytes,
            compact: false,
        }
    }
}
pub(super) fn hash_fields(domain: &[u8], bytes: &[u8]) -> ConfigDigest {
    let mut hash = ring::digest::Context::new(&ring::digest::SHA256);
    hash.update(domain);
    hash.update(bytes);
    let mut output = [0; 32];
    output.copy_from_slice(hash.finish().as_ref());
    ConfigDigest(output)
}
impl Endpoint {
    /// Preserve original authenticated arrival through selected physical-feedback
    /// deferral. The caller retains exact input and its original cap on pressure.
    pub fn receive_authenticated_at(
        &mut self,
        packet: &[u8],
        received: Duration,
        observed: Duration,
    ) -> Result<(), Error> {
        if !self.receive_config.compact {
            if received > observed {
                return Err(Error::Time);
            }
            return self.receive_authenticated(packet, observed);
        }
        if let Some(error) = self.failure {
            return Err(error);
        }
        if received > observed || observed < self.now {
            return Err(Error::Time);
        }
        ticks(observed)?;
        if self.packing.is_some() {
            packed::micros(observed)?;
        }
        let result = self
            .recovery
            .receive_at(packet, received, observed)
            .map_err(|error| match error {
                l2tunnel_reliable::Error::Arq(
                    RecoveryError::FeedbackAwaitingPhysical
                    | RecoveryError::HistoryCapacity
                    | RecoveryError::Capacity(_)
                    | RecoveryError::SequenceWindow,
                ) => Error::RecoveryPressure(error),
                _ => Error::Recovery(error),
            });
        self.recovery_result(result)?;
        self.advance(observed)?;
        self.pump_receive()
    }
}
pub(super) struct Writer<'a> {
    output: &'a mut [u8],
    at: usize,
}
impl<'a> Writer<'a> {
    pub fn new(output: &'a mut [u8]) -> Self {
        Self { output, at: 0 }
    }
    pub fn bytes(&mut self, bytes: &[u8]) -> Result<(), Error> {
        let end = self
            .at
            .checked_add(bytes.len())
            .ok_or(Error::Configuration)?;
        self.output
            .get_mut(self.at..end)
            .ok_or(Error::Configuration)?
            .copy_from_slice(bytes);
        self.at = end;
        Ok(())
    }
    pub fn byte(&mut self, n: u8) -> Result<(), Error> {
        self.bytes(&[n])
    }
    pub fn number(&mut self, n: u64) -> Result<(), Error> {
        self.bytes(&n.to_be_bytes())
    }
    pub fn size(&mut self, n: usize) -> Result<(), Error> {
        self.number(n.try_into().map_err(|_| Error::Configuration)?)
    }
    pub fn duration(&mut self, n: Duration) -> Result<(), Error> {
        self.number(n.as_secs())?;
        self.number(u64::from(n.subsec_nanos()))
    }
    pub fn finish(self) -> Result<(), Error> {
        if self.at == self.output.len() {
            Ok(())
        } else {
            Err(Error::Configuration)
        }
    }
}
pub(super) struct Reader<'a> {
    input: &'a [u8],
    at: usize,
}
impl<'a> Reader<'a> {
    pub fn new(input: &'a [u8]) -> Self {
        Self { input, at: 0 }
    }
    pub fn take(&mut self, count: usize) -> Result<&'a [u8], Error> {
        let end = self.at.checked_add(count).ok_or(Error::Configuration)?;
        let bytes = self.input.get(self.at..end).ok_or(Error::Configuration)?;
        self.at = end;
        Ok(bytes)
    }
    pub fn byte(&mut self) -> Result<u8, Error> {
        Ok(self.take(1)?[0])
    }
    pub fn number(&mut self) -> Result<u64, Error> {
        Ok(u64::from_be_bytes(
            self.take(8)?.try_into().map_err(|_| Error::Configuration)?,
        ))
    }
    pub fn size(&mut self) -> Result<usize, Error> {
        self.number()?.try_into().map_err(|_| Error::Configuration)
    }
    pub fn duration(&mut self) -> Result<Duration, Error> {
        let seconds = self.number()?;
        let nanos = self.number()?;
        if nanos >= 1_000_000_000 {
            return Err(Error::Configuration);
        }
        Ok(Duration::new(seconds, nanos as u32))
    }
    pub fn boolean(&mut self) -> Result<bool, Error> {
        match self.byte()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(Error::Configuration),
        }
    }
    pub fn finish(self) -> Result<(), Error> {
        if self.at == self.input.len() {
            Ok(())
        } else {
            Err(Error::Configuration)
        }
    }
}
