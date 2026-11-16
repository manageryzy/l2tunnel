//! Selected packed source body retaining all absolute unit and record identities.
use super::*;
use source_identity::{read_varint, varint_len, write_varint};

/// Encode selected packing metadata without repeating authenticated scope/source.
/// Full record IDs use canonical varints only when smaller than their u64 list.
/// This bounds the complete body below the legacy configured source capacity.
pub fn encode_compact(
    config: Config,
    identity: Identity,
    records: &[RecordId],
    payload: &[u8],
    output: &mut [u8],
) -> Result<usize, Error> {
    count_valid(config, identity, records.len())?;
    for (unit, record) in payload_units(payload, config, records.len())?.zip(records) {
        check_unit(unit, *record, config)?;
    }
    let variable_len: usize = records.iter().map(|record| varint_len(record.0)).sum();
    let variable = variable_len < records.len() * 8;
    let record_bytes = if variable {
        variable_len
    } else {
        records.len() * 8
    };
    let header = 2 + varint_len(identity.first_unit.0);
    let needed = header + record_bytes + payload.len();
    if output.len() < needed {
        return Err(Error::OutputTooSmall { needed });
    }
    output[0] = records.len() as u8;
    output[1] = u8::from(variable);
    write_varint(identity.first_unit.0, &mut output[2..]);
    let mut offset = header;
    for record in records {
        if variable {
            offset += write_varint(record.0, &mut output[offset..]);
        } else {
            output[offset..offset + 8].copy_from_slice(&record.0.to_be_bytes());
            offset += 8;
        }
    }
    output[offset..needed].copy_from_slice(payload);
    Ok(needed)
}

/// Parse compact packing only under its explicitly selected authenticated context.
/// The outer recovery source remains distinct from this body's aligned unit IDs.
pub fn decode_compact(
    config: Config,
    expected: Scope,
    source: SourceId,
    input: &[u8],
) -> Result<View<'_>, Error> {
    config.max_source_bytes()?;
    scope_valid(expected)?;
    let count = usize::from(*input.first().ok_or(Error::Malformed)?);
    let variable = match input.get(1) {
        Some(0) => false,
        Some(1) => true,
        _ => return Err(Error::Malformed),
    };
    let (first, first_len) =
        read_varint(input.get(2..).ok_or(Error::Malformed)?).map_err(header_error)?;
    let identity = Identity {
        scope: expected,
        source,
        first_unit: SourceId(first),
    };
    count_valid(config, identity, count)?;
    let start = 2 + first_len;
    let mut end = start;
    let mut variable_len = 0;
    for _ in 0..count {
        let record = if variable {
            let (value, length) =
                read_varint(input.get(end..).ok_or(Error::Malformed)?).map_err(header_error)?;
            end += length;
            value
        } else {
            let bytes = input.get(end..end + 8).ok_or(Error::Malformed)?;
            end += 8;
            word64(bytes, 0)
        };
        variable_len += varint_len(record);
    }
    if variable != (variable_len < count * 8) {
        return Err(Error::Malformed);
    }
    let view = View {
        identity,
        records: &input[start..end],
        payload: &input[end..],
        config,
        count: count as u8,
        variable_records: variable,
    };
    for unit in view.units()? {
        check_unit(unit.bytes, unit.identity.record, config)?;
    }
    Ok(view)
}
