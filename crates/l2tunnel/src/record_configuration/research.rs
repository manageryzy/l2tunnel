//! Strict additive tag9; tags1..8 and CompleteV2 length remain unchanged.
use super::*;
use crate::codec::{aligned_sender, packed, packed_sender};
const ACTIVE_BYTES: usize = 352;
fn boolean(reader: &mut Reader<'_>) -> Result<bool, Error> {
    match reader.number()? {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(Error::Scalar),
    }
}

fn decode(
    input: &[u8],
) -> Result<(crate::research_records::DirectionConfig, usize, u64, u32), Error> {
    padding(input.get(ACTIVE_BYTES..).ok_or(Error::Length)?)?;
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
    let first = reader.number()?.to_be_bytes();
    let second = reader.number()?.to_be_bytes();
    if second[4..] != [0; 4] {
        return Err(Error::Padding);
    }
    let mut descriptor = [0; 12];
    descriptor[..8].copy_from_slice(&first);
    descriptor[8..].copy_from_slice(&second[..4]);
    let profile = match descriptor[0] {
        1 => {
            if descriptor[8..] != [0; 4] {
                return Err(Error::Padding);
            }
            fec::research::Profile::Recursive {
                taps: descriptor[1],
                width: u16::from_be_bytes([descriptor[2], descriptor[3]]),
                reset: u16::from_be_bytes([descriptor[4], descriptor[5]]),
                fresh_interval: u16::from_be_bytes([descriptor[6], descriptor[7]]),
            }
        }
        2 => {
            if descriptor[1..8] != [0; 7] {
                return Err(Error::Padding);
            }
            fec::research::Profile::Accumulator {
                lanes: u16::from_be_bytes([descriptor[8], descriptor[9]]),
                window: u16::from_be_bytes([descriptor[10], descriptor[11]]),
            }
        }
        _ => return Err(Error::Prefix),
    };
    let scheduler = fec::research::Config {
        recovery,
        profile,
        feedback_ticks: reader.number()?,
        memory_bytes: reader.size()?,
    };
    for _ in 0..3 {
        if reader.number()? != 0 {
            return Err(Error::Padding);
        }
    }
    let overhead = reader.size()?;
    let stall = reader.number()?;
    let stream = checked(reader.number()?)?;
    reader.finish()?;
    let config = crate::research_records::DirectionConfig {
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
    let (forward, forward_overhead_bytes, stall, stream) = decode(a)?;
    let (reverse, reverse_overhead_bytes, other_stall, other_stream) = decode(b)?;
    if stall != other_stall || stream != other_stream {
        return Err(Error::Relation);
    }
    let config = crate::research_records::Config {
        forward,
        reverse,
        geometry: crate::record_engine::Geometry {
            forward_overhead_bytes,
            reverse_overhead_bytes,
        },
        native_stall_micros: stall,
    };
    config.validate().map_err(|_| Error::Profile)?;
    Ok(Profile::Research { config, stream })
}
