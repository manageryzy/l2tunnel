//! Canonical native codec and packer fields shared by the complete directional slots.
use super::*;
use crate::codec::{aligned_sender, packed, packed_sender};

pub(super) fn encode(
    writer: &mut Writer<'_>,
    native_policy: aligned::NativePolicy,
    r: aligned_receiver::Limits,
    p: packed_sender::Config,
) -> Result<(), Error> {
    let b = r.body;
    for value in [
        u64::from(native_policy.wire()),
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
    ] {
        writer.number(value)?;
    }
    Ok(())
}

fn boolean(reader: &mut Reader<'_>) -> Result<bool, Error> {
    match reader.number()? {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(Error::Scalar),
    }
}

pub(super) fn decode(
    reader: &mut Reader<'_>,
) -> Result<
    (
        aligned::NativePolicy,
        aligned_receiver::Limits,
        packed_sender::Config,
    ),
    Error,
> {
    let native_policy =
        aligned::NativePolicy::from_wire(checked(reader.number()?)?).ok_or(Error::Prefix)?;
    let body = aligned_body::Config {
        max_frame_bytes: reader.size()?,
        symbol_bytes: reader.size()?,
        elide_payload_length: boolean(reader)?,
        predictive: boolean(reader)?,
        timestamp_pair_dictionary: boolean(reader)?,
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
    Ok((native_policy, receiver, packing))
}
