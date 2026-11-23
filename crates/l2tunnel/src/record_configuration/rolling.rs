//! Additive tag4/tag5 inside the unchanged CompleteV2 fixed directional slot.
use super::*;
use crate::record_engine::Geometry;
use crate::rolling_records::recovery::RecoveryPolicy;

pub(super) const ACTIVE_BYTES: usize = 352;

pub(super) fn encode<P: RecoveryPolicy>(
    config: rolling_records::DirectionConfig<P>,
    overhead: usize,
    stall: u64,
    stream: u32,
    output: &mut [u8],
) -> Result<(), Error> {
    config.validate().map_err(|_| Error::Profile)?;
    let mut writer = Writer::new(output.get_mut(..ACTIVE_BYTES).ok_or(Error::Length)?);
    packed_fields::encode(
        &mut writer,
        config.native_policy,
        config.receiver,
        config.packing,
    )?;
    writer.number(config.codec_stage_micros)?;
    for value in config.scheduler.words() {
        writer.number(value)?;
    }
    for value in [integer(overhead)?, stall, stream_word(config, stream)] {
        writer.number(value)?;
    }
    writer.finish()
}

/// Tags 4/5 carry only all-default delivery, so the upper half stays zero there.
/// Tags 11/12 keep `release (8) | guard mode (8) | per_mille (16)` above the `u32` stream.
fn stream_word<P: RecoveryPolicy>(config: rolling_records::DirectionConfig<P>, stream: u32) -> u64 {
    let delivery = u64::from(config.native_release.wire()) << 24
        | u64::from(config.return_guard.mode_wire()) << 16
        | u64::from(config.return_guard.per_mille);
    delivery << 32 | u64::from(stream)
}

fn decode(
    input: &[u8],
    copies: bool,
) -> Result<(rolling_records::DirectionConfig, usize, u64, u32), Error> {
    if !copies {
        padding(input.get(ACTIVE_BYTES..).ok_or(Error::Length)?)?;
    }
    let mut reader = Reader::new(input.get(..ACTIVE_BYTES).ok_or(Error::Length)?);
    let (native_policy, receiver, packing) = packed_fields::decode(&mut reader)?;
    let codec_stage_micros = reader.number()?;
    let recovery = fec::rolling::Config {
        window: reader.size()?,
        local_window: reader.size()?,
        global_every: checked(reader.number()?)?,
        max_payload: reader.size()?,
        max_rows: reader.size()?,
        repair_history: reader.size()?,
        handoff_sources: reader.size()?,
        job_ticks: reader.number()?,
        debt_ticks: reader.number()?,
        handoff_ticks: reader.number()?,
        memory_bytes: reader.size()?,
    };
    let repair_numerator = checked(reader.number()?)?;
    let repair_denominator = checked(reader.number()?)?;
    let tail_ticks = reader.number()?;
    let feedback_ticks = reader.number()?;
    let feedback_packets = checked(reader.number()?)?;
    let memory_bytes = reader.size()?;
    let source_wire = match reader.number()? {
        version if version == u64::from(fec::rolling::wire::VERSION) => {
            fec::rolling::wire::SourceWire::Padded
        }
        version if version == u64::from(fec::rolling::wire::EXACT_SOURCE_VERSION) => {
            fec::rolling::wire::SourceWire::Exact
        }
        version if version == u64::from(fec::rolling::wire::TARGETED_VERSION) => {
            fec::rolling::wire::SourceWire::TargetedExact
        }
        version if version == u64::from(fec::rolling::wire::TARGETED_NEAR8_VERSION) => {
            fec::rolling::wire::SourceWire::TargetedNear8
        }
        version if version == u64::from(fec::rolling::wire::TARGETED_NEAR8_HOLD35_POLICY) => {
            fec::rolling::wire::SourceWire::TargetedNear8Hold35
        }
        version if version == u64::from(fec::rolling::wire::TARGETED_NEAR8_CONFIRMED_POLICY) => {
            fec::rolling::wire::SourceWire::TargetedNear8ConfirmedPrefix
        }
        version if version == u64::from(fec::rolling::wire::TARGETED_EXACT_ACK_LZ4_POLICY) => {
            fec::rolling::wire::SourceWire::TargetedExactAckLz4
        }
        version if version == u64::from(fec::rolling::wire::TARGETED_NEAR8_HEADROOM_POLICY) => {
            fec::rolling::wire::SourceWire::TargetedNear8Headroom
        }
        _ => return Err(Error::Prefix),
    };
    let scheduler = fec::rolling::scheduler::Policy {
        recovery,
        repair_numerator,
        repair_denominator,
        tail_ticks,
        feedback_ticks,
        feedback_packets,
        memory_bytes,
        source_wire,
    };
    let overhead = reader.size()?;
    let stall = reader.number()?;
    let word = reader.number()?;
    let stream = (word & u64::from(u32::MAX)) as u32;
    let delivery = (word >> 32) as u32;
    let native_release =
        rolling_records::NativeRelease::from_wire((delivery >> 24) as u8).ok_or(Error::Prefix)?;
    let return_guard =
        rolling_records::ReturnGuard::from_wire((delivery >> 16) as u8, delivery as u16)
            .ok_or(Error::Prefix)?;
    reader.finish()?;
    let config = rolling_records::DirectionConfig {
        native_release,
        return_guard,
        native_policy,
        receiver,
        packing,
        codec_stage_micros,
        scheduler,
    };
    config.validate().map_err(|_| Error::Profile)?;
    Ok((config, overhead, stall, stream))
}

/// Decode tag 4 (`extended == false`) or tag 11.
pub(super) fn decode_pair(a: &[u8], b: &[u8], extended: bool) -> Result<Profile, Error> {
    pair(a, b, false, extended)
}
/// Decode tag 5 (`extended == false`) or tag 12.
pub(super) fn decode_pair_with_copies(
    a: &[u8],
    b: &[u8],
    extended: bool,
) -> Result<Profile, Error> {
    pair(a, b, true, extended)
}
/// Whether a pair requires an extended delivery tag.
pub(super) fn extended<P: RecoveryPolicy>(config: rolling_records::Config<P>) -> bool {
    !(config.forward.delivery_default() && config.reverse.delivery_default())
}
fn pair(a: &[u8], b: &[u8], copies: bool, extended_tag: bool) -> Result<Profile, Error> {
    let (forward, forward_overhead_bytes, stall, stream) = decode(a, copies)?;
    let (reverse, reverse_overhead_bytes, other_stall, other_stream) = decode(b, copies)?;
    if stall != other_stall || stream != other_stream {
        return Err(Error::Relation);
    }
    let config = rolling_records::Config {
        forward,
        reverse,
        geometry: Geometry {
            forward_overhead_bytes,
            reverse_overhead_bytes,
        },
        native_stall_micros: stall,
    };
    config.validate().map_err(|_| Error::Profile)?;
    if extended(config) != extended_tag {
        return Err(Error::Prefix);
    }
    if copies {
        let copies = rolling_records::CopyPolicies {
            forward: decode_copy(a.get(ACTIVE_BYTES..).ok_or(Error::Length)?)?,
            reverse: decode_copy(b.get(ACTIVE_BYTES..).ok_or(Error::Length)?)?,
        };
        copies.validate(config).map_err(|_| Error::Profile)?;
        Ok(Profile::RollingCopies {
            config,
            stream,
            copies,
        })
    } else {
        Ok(Profile::Rolling { config, stream })
    }
}

pub(super) fn encode_copy(
    policy: crate::codec::source_copy::Policy,
    output: &mut [u8],
) -> Result<(), Error> {
    use crate::codec::source_copy::Scope;
    let threshold = u16::try_from(policy.max_unit_bytes).map_err(|_| Error::Integer)?;
    if output.len() != 4 {
        return Err(Error::Length);
    }
    output[..2].copy_from_slice(&threshold.to_be_bytes());
    output[2] = policy.copies;
    output[3] = match policy.scope {
        Scope::AllShort => 1,
        Scope::ContextAndIndependent => 2,
    };
    Ok(())
}
fn decode_copy(input: &[u8]) -> Result<crate::codec::source_copy::Policy, Error> {
    use crate::codec::source_copy::{Policy, Scope};
    let [hi, lo, copies, scope] = *<&[u8; 4]>::try_from(input).map_err(|_| Error::Length)?;
    Ok(Policy {
        max_unit_bytes: usize::from(u16::from_be_bytes([hi, lo])),
        copies,
        scope: match scope {
            1 => Scope::AllShort,
            2 => Scope::ContextAndIndependent,
            _ => return Err(Error::Prefix),
        },
    })
}
