use super::Error;
use l2tunnel_core::{
    ConfigDigest, Delivery, Duplex, HeaderProfile, Mapping, ModeConfig, PayloadCompression,
    RecordLayout, Recovery,
};

/// Exact length of the version-1 canonical mode configuration.
pub const MODE_BYTES: usize = 24;

/// Explicit local canonical-value contract; never selected by an incoming length.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConfigurationEncoding {
    /// Existing canonical values, preserving the 512-byte constructor boundary.
    LegacyV1,
    /// Complete versioned profile values with at most 4096 canonical bytes.
    CompleteV2,
}

impl ConfigurationEncoding {
    /// Hard canonical-byte limit before callbacks or allocation.
    pub const fn maximum_bytes(self) -> usize {
        match self {
            Self::LegacyV1 => 512,
            Self::CompleteV2 => 4096,
        }
    }
}

/// Fixed canonical policy contract for the existing bounded transaction engine.
/// Implementations are trusted local code; decoded peer values still validate
/// and must re-encode byte-exactly before admission.
pub trait Configuration: Clone + Eq {
    /// Explicit trusted-local encoding contract; existing implementations stay legacy.
    const ENCODING: ConfigurationEncoding = ConfigurationEncoding::LegacyV1;
    /// Exact size, validated against ENCODING before callbacks or allocation.
    const ENCODED_LEN: usize;
    /// Nonempty digest domain, bounded to 128 bytes and unique to this policy.
    const DIGEST_DOMAIN: &'static [u8];
    /// Validate every local/decoded policy value before staging.
    fn validate(&self) -> Result<(), Error>;
    /// Write exactly ENCODED_LEN canonical bytes into the supplied exact buffer.
    fn encode_into(&self, output: &mut [u8]) -> Result<(), Error>;
    /// Decode an exact bounded canonical encoding.
    fn decode(input: &[u8]) -> Result<Self, Error>;
    /// Old-policy channel count for per-channel drain fences, in 1..=256.
    fn channels(&self) -> u16;
    /// Old-policy width for an authenticated global data sender, in 1..=256.
    /// Explicit directional peers use this query; legacy peers keep `channels()`.
    /// Both widths must be derived from the policy's canonical encoded value.
    fn sender_channels(&self, _sender: crate::Role) -> u16 {
        self.channels()
    }
    /// Physical lane arrangement; transactions cannot change it.
    fn duplex(&self) -> Duplex;
}

fn validate_type<C: Configuration>() -> Result<(), Error> {
    if !(1..=C::ENCODING.maximum_bytes()).contains(&C::ENCODED_LEN)
        || !(1..=128).contains(&C::DIGEST_DOMAIN.len())
    {
        return Err(Error::Configuration("canonical policy size or domain"));
    }
    Ok(())
}

/// Exact largest PREPARE for one old global sender's fence, without allocation.
/// This checks geometry only; actual frame/message/resource admission stays external.
pub fn maximum_prepare_bytes<C: Configuration>(sender_channels: u16) -> Result<usize, Error> {
    validate_type::<C>()?;
    if !(1..=256).contains(&sender_channels) {
        return Err(Error::Configuration(
            "canonical policy sender channel count",
        ));
    }
    usize::from(sender_channels)
        .checked_mul(8)
        .and_then(|bytes| bytes.checked_add(2))
        .and_then(|bytes| bytes.checked_add(C::ENCODED_LEN))
        .and_then(|bytes| bytes.checked_add(8))
        .and_then(|bytes| bytes.checked_add(crate::HEADER_LEN))
        .ok_or(Error::Exhausted)
}

/// Exact existing or explicitly extended frame/request-gate limits for this type.
/// A runtime must admit these real bounds separately from whole-message storage.
pub fn configuration_limits<C: Configuration>() -> Result<crate::Limits, Error> {
    validate_type::<C>()?;
    let mut limits = super::limits();
    if C::ENCODING == ConfigurationEncoding::CompleteV2 {
        limits.max_frame_bytes = limits.max_frame_bytes.max(maximum_prepare_bytes::<C>(256)?);
        limits.max_retained_bytes = limits
            .max_frame_bytes
            .checked_mul(limits.max_requests)
            .ok_or(Error::Exhausted)?;
    }
    Ok(limits)
}

pub(super) fn encode_configuration<C: Configuration>(config: &C) -> Result<Vec<u8>, Error> {
    validate_type::<C>()?;
    config.validate()?;
    if !(1..=256).contains(&config.channels()) {
        return Err(Error::Configuration("canonical policy channel count"));
    }
    let mut bytes = vec![0; C::ENCODED_LEN];
    config.encode_into(&mut bytes)?;
    Ok(bytes)
}

pub(super) fn validate_sender_channels<C: Configuration>(config: &C) -> Result<(), Error> {
    for sender in [crate::Role::Client, crate::Role::Server] {
        if !(1..=256).contains(&config.sender_channels(sender)) {
            return Err(Error::Configuration(
                "canonical policy sender channel count",
            ));
        }
    }
    Ok(())
}

pub(super) fn decode_configuration<C: Configuration>(input: &[u8]) -> Result<C, Error> {
    validate_type::<C>()?;
    if input.len() != C::ENCODED_LEN {
        return Err(Error::Malformed);
    }
    let config = C::decode(input)?;
    if encode_configuration(&config)? != input {
        return Err(Error::Malformed);
    }
    Ok(config)
}

/// Domain-separated SHA-256 of validated exact canonical policy bytes.
pub fn configuration_digest<C: Configuration>(config: &C) -> Result<ConfigDigest, Error> {
    let bytes = encode_configuration(config)?;
    let mut context = ring::digest::Context::new(&ring::digest::SHA256);
    context.update(C::DIGEST_DOMAIN);
    context.update(&bytes);
    let mut digest = [0; 32];
    digest.copy_from_slice(context.finish().as_ref());
    Ok(ConfigDigest(digest))
}

impl Configuration for ModeConfig {
    const ENCODED_LEN: usize = MODE_BYTES;
    const DIGEST_DOMAIN: &'static [u8] = b"l2tunnel/mode-config/v1\0";

    fn validate(&self) -> Result<(), Error> {
        ModeConfig::validate(self).map_err(Error::Configuration)
    }
    fn encode_into(&self, output: &mut [u8]) -> Result<(), Error> {
        if output.len() != MODE_BYTES {
            return Err(Error::Malformed);
        }
        output.copy_from_slice(&encode_mode(self)?);
        Ok(())
    }
    fn decode(input: &[u8]) -> Result<Self, Error> {
        decode_mode(input)
    }
    fn channels(&self) -> u16 {
        self.channels
    }
    fn duplex(&self) -> Duplex {
        self.duplex
    }
}

/// Encode a validated mode without platform-width integers or implicit enum discriminants.
pub fn encode_mode(mode: &ModeConfig) -> Result<[u8; MODE_BYTES], Error> {
    mode.validate().map_err(Error::Configuration)?;
    let mut bytes = [0; MODE_BYTES];
    bytes[0] = 1;
    bytes[1] = match mode.duplex {
        Duplex::Half => 1,
        Duplex::Full => 2,
    };
    bytes[2] = match mode.mapping {
        Mapping::Crc32 => 1,
        Mapping::ConnectionRoundRobin => 2,
    };
    bytes[3] = match mode.recovery {
        Recovery::CarrierOnly => 1,
        Recovery::SelectiveArq => 2,
        Recovery::FirstFlightArq => 3,
        Recovery::BoundedGapArq => 4,
        Recovery::BlockFec => 5,
        Recovery::SlidingFec => 6,
        Recovery::HybridFec => 7,
        Recovery::ElasticRlnc => 8,
        Recovery::RankBlockFec => 9,
    };
    bytes[4] = match mode.records {
        RecordLayout::Frame => 1,
        RecordLayout::CrossFrame => 2,
        RecordLayout::Shared => 3,
        RecordLayout::Aligned => 4,
        RecordLayout::Packed => 5,
    };
    bytes[5] = match mode.delivery {
        Delivery::Ordered => 1,
        Delivery::IndependentShort => 2,
    };
    bytes[6] = match mode.headers {
        HeaderProfile::FullL2 => 1,
        HeaderProfile::TcpTimestamp => 2,
        HeaderProfile::TcpDelta => 3,
        HeaderProfile::PredictiveTcp => 4,
    };
    bytes[7] = match mode.compression {
        PayloadCompression::Off => 1,
        PayloadCompression::Lz4 => 2,
        PayloadCompression::Zstd => 3,
    };
    bytes[8..10].copy_from_slice(&mode.channels.to_be_bytes());
    bytes[12..20].copy_from_slice(
        &u64::try_from(mode.queue_bytes)
            .map_err(|_| Error::Configuration("queue byte count overflow"))?
            .to_be_bytes(),
    );
    bytes[20..24].copy_from_slice(
        &u32::try_from(mode.queue_frames)
            .map_err(|_| Error::Configuration("queue frame count overflow"))?
            .to_be_bytes(),
    );
    Ok(bytes)
}

/// Decode an exact canonical mode; unknown versions, enum values and reserved bits fail.
pub fn decode_mode(bytes: &[u8]) -> Result<ModeConfig, Error> {
    if bytes.len() != MODE_BYTES || bytes[0] != 1 || bytes[10..12] != [0, 0] {
        return Err(Error::Malformed);
    }
    let mode = ModeConfig {
        duplex: match bytes[1] {
            1 => Duplex::Half,
            2 => Duplex::Full,
            _ => return Err(Error::Malformed),
        },
        mapping: match bytes[2] {
            1 => Mapping::Crc32,
            2 => Mapping::ConnectionRoundRobin,
            _ => return Err(Error::Malformed),
        },
        recovery: match bytes[3] {
            1 => Recovery::CarrierOnly,
            2 => Recovery::SelectiveArq,
            3 => Recovery::FirstFlightArq,
            4 => Recovery::BoundedGapArq,
            5 => Recovery::BlockFec,
            6 => Recovery::SlidingFec,
            7 => Recovery::HybridFec,
            8 => Recovery::ElasticRlnc,
            9 => Recovery::RankBlockFec,
            _ => return Err(Error::Malformed),
        },
        records: match bytes[4] {
            1 => RecordLayout::Frame,
            2 => RecordLayout::CrossFrame,
            3 => RecordLayout::Shared,
            4 => RecordLayout::Aligned,
            5 => RecordLayout::Packed,
            _ => return Err(Error::Malformed),
        },
        delivery: match bytes[5] {
            1 => Delivery::Ordered,
            2 => Delivery::IndependentShort,
            _ => return Err(Error::Malformed),
        },
        headers: match bytes[6] {
            1 => HeaderProfile::FullL2,
            2 => HeaderProfile::TcpTimestamp,
            3 => HeaderProfile::TcpDelta,
            4 => HeaderProfile::PredictiveTcp,
            _ => return Err(Error::Malformed),
        },
        compression: match bytes[7] {
            1 => PayloadCompression::Off,
            2 => PayloadCompression::Lz4,
            3 => PayloadCompression::Zstd,
            _ => return Err(Error::Malformed),
        },
        channels: u16::from_be_bytes([bytes[8], bytes[9]]),
        queue_bytes: usize::try_from(u64::from_be_bytes(
            bytes[12..20].try_into().map_err(|_| Error::Malformed)?,
        ))
        .map_err(|_| Error::Malformed)?,
        queue_frames: usize::try_from(u32::from_be_bytes(
            bytes[20..24].try_into().map_err(|_| Error::Malformed)?,
        ))
        .map_err(|_| Error::Malformed)?,
    };
    mode.validate().map_err(Error::Configuration)?;
    Ok(mode)
}

/// Domain-separated SHA-256 of the exact canonical mode through maintained ring.
pub fn mode_digest(mode: &ModeConfig) -> Result<ConfigDigest, Error> {
    let mut context = ring::digest::Context::new(&ring::digest::SHA256);
    context.update(b"l2tunnel/mode-config/v1\0");
    context.update(&encode_mode(mode)?);
    let mut bytes = [0; 32];
    bytes.copy_from_slice(context.finish().as_ref());
    Ok(ConfigDigest(bytes))
}
