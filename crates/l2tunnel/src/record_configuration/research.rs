//! Strict additive tag9; tags1..8 and CompleteV2 length remain unchanged.
use super::*;
const ACTIVE_BYTES: usize = 352;
fn decode(
    input: &[u8],
) -> Result<(crate::research_records::DirectionConfig, usize, u64, u32), Error> {
    padding(input.get(ACTIVE_BYTES..).ok_or(Error::Length)?)?;
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
        // Formerly reserved zero: zero keeps every earlier vector valid and
        // means abandonment is off.
        abandon_ticks: reader.number()?,
    };
    for _ in 0..2 {
        if reader.number()? != 0 {
            return Err(Error::Padding);
        }
    }
    let overhead = reader.size()?;
    let stall = reader.number()?;
    let stream = checked(reader.number()?)?;
    reader.finish()?;
    let config = crate::research_records::DirectionConfig {
        native_release: Default::default(),
        return_guard: Default::default(),
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
