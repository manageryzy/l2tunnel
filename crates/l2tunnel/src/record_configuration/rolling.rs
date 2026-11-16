//! Additive tag4/tag5 inside the unchanged CompleteV2 fixed directional slot.
use super::*;
use crate::rolling_records::recovery::RecoveryPolicy;
use crate::{
    codec::{aligned_sender, packed, packed_sender},
    record_engine::Geometry,
};

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
    let r = config.receiver;
    let b = r.body;
    let p = config.packing;
    let s = config.scheduler;
    for value in [
        match config.native_policy {
            aligned::NativePolicy::EthernetHeaders => 1,
            aligned::NativePolicy::RawIp => 2,
            aligned::NativePolicy::IpHeaders => 3,
        },
        integer(b.max_frame_bytes)?,
        integer(b.symbol_bytes)?,
        u64::from(b.elide_payload_length),
        u64::from(b.predictive),
        u64::from(b.timestamp_pair_dictionary),
        integer(b.independent_short_frame_bytes)?,
        u64::from(r.channels),
        r.first_record.0,
        r.first_source.0,
        u64::from(r.record_window),
        integer(r.source_window)?,
        integer(r.lookahead_records)?,
        integer(r.lookahead_bytes)?,
        integer(r.lookahead_fragments)?,
        integer(r.max_fragments_per_record)?,
        r.lifetime_ticks,
        integer(p.packing.symbol_bytes)?,
        p.packing.hold_micros,
        u64::from(p.max_units),
        p.first_unit.0,
        integer(p.work_limit)?,
        config.codec_stage_micros,
    ] {
        writer.number(value)?;
    }
    for value in s.words() {
        writer.number(value)?;
    }
    for value in [integer(overhead)?, stall, u64::from(stream)] {
        writer.number(value)?;
    }
    writer.finish()
}

fn boolean(reader: &mut Reader<'_>) -> Result<bool, Error> {
    match reader.number()? {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(Error::Scalar),
    }
}

fn decode(
    input: &[u8],
    copies: bool,
) -> Result<(rolling_records::DirectionConfig, usize, u64, u32), Error> {
    if !copies {
        padding(input.get(ACTIVE_BYTES..).ok_or(Error::Length)?)?;
    }
    let mut reader = Reader::new(input.get(..ACTIVE_BYTES).ok_or(Error::Length)?);
    let native_policy = match reader.number()? {
        1 => aligned::NativePolicy::EthernetHeaders,
        2 => aligned::NativePolicy::RawIp,
        3 => aligned::NativePolicy::IpHeaders,
        _ => return Err(Error::Prefix),
    };
    let body = aligned_body::Config {
        max_frame_bytes: reader.size()?,
        symbol_bytes: reader.size()?,
        elide_payload_length: boolean(&mut reader)?,
        predictive: boolean(&mut reader)?,
        timestamp_pair_dictionary: boolean(&mut reader)?,
        independent_short_frame_bytes: reader.size()?,
    };
    let receiver = aligned_receiver::Limits {
        body,
        channels: checked(reader.number()?)?,
        first_record: aligned_receiver::RecordId(reader.number()?),
        first_source: aligned_receiver::SourceId(reader.number()?),
        record_window: checked(reader.number()?)?,
        source_window: reader.size()?,
        lookahead_records: reader.size()?,
        lookahead_bytes: reader.size()?,
        lookahead_fragments: reader.size()?,
        max_fragments_per_record: reader.size()?,
        lifetime_ticks: reader.number()?,
    };
    let packing = packed_sender::Config {
        sender: aligned_sender::Config {
            body,
            channels: receiver.channels,
            first_record: receiver.first_record,
        },
        packing: packed::Config {
            symbol_bytes: reader.size()?,
            hold_micros: reader.number()?,
        },
        max_units: checked(reader.number()?)?,
        first_unit: aligned_receiver::SourceId(reader.number()?),
        work_limit: reader.size()?,
    };
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
        1 => fec::rolling::wire::SourceWire::Padded,
        2 => fec::rolling::wire::SourceWire::Exact,
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
    let stream = checked(reader.number()?)?;
    reader.finish()?;
    let config = rolling_records::DirectionConfig {
        native_policy,
        receiver,
        packing,
        codec_stage_micros,
        scheduler,
    };
    config.validate().map_err(|_| Error::Profile)?;
    Ok((config, overhead, stall, stream))
}

pub(super) fn decode_pair(a: &[u8], b: &[u8]) -> Result<Profile, Error> {
    pair(a, b, false)
}
pub(super) fn decode_pair_with_copies(a: &[u8], b: &[u8]) -> Result<Profile, Error> {
    pair(a, b, true)
}
fn pair(a: &[u8], b: &[u8], copies: bool) -> Result<Profile, Error> {
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
