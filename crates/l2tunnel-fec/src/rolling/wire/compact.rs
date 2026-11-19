//! Context-free selected rolling union; outer admission supplies the full scope.
use super::*;
use crate::rolling::scheduler::{Feedback, FeedbackId, GapRequest, Output};

/// Selected source/repair/strong-feedback body under an established context.
#[derive(Clone, Copy, Debug)]
pub enum View<'a> {
    /// Exact original source bytes and independent source identity.
    Data(super::View<'a>),
    /// Strongly authenticated retiring feedback, never a short-check data arm.
    Feedback(Feedback),
    /// Explicit named-source request under the negotiated targeted policy.
    Gap(GapRequest),
}
/// Worst-case complete selected data union, before enclosing protection.
pub fn maximum_data_bytes(config: Config) -> Result<usize, Error> {
    Ok(16 + config.width()?)
}
/// Worst-case complete selected feedback union, preserving all identities.
pub const MAXIMUM_FEEDBACK_BYTES: usize = 26;
/// Exact context-free bytes of the actual frozen owner output.
pub fn data_len(output: Output<'_>) -> Result<usize, Error> {
    match output {
        Output::Source { id, original, .. } => {
            id.0.checked_add(1).ok_or(Error::Identity)?;
            if original.is_empty() || original.len() > MAX_PAYLOAD {
                return Err(Error::Length);
            }
            Ok(1 + len(u64::from(id.0)) + original.len())
        }
        Output::Near8(row) => crate::rolling::near8::wire_len(row),
        Output::Repair(repair) => {
            repair.validate_extent(MAX_PAYLOAD + 2)?;
            if repair.id.0 == u64::MAX {
                return Err(Error::Identity);
            }
            repair_len(repair.id, repair.support.end, repair.bytes.len())
        }
    }
}
/// Exact selected regular/tail body length from the frozen support end,
/// transmitted serial and true coded extent (including the coded length word).
pub fn repair_len(id: RepairId, end: u32, extent: usize) -> Result<usize, Error> {
    if id.0 == 0 || id.0 == u64::MAX || end == 0 || !(3..=MAX_PAYLOAD + 2).contains(&extent) {
        return Err(Error::Length);
    }
    Ok(1 + len(id.0) + len(u64::from(end)) + extent)
}
/// Serialize actual fields once; exact source bytes have no zero tail or duplicate length.
pub fn encode_data(value: Output<'_>, output: &mut [u8]) -> Result<usize, Error> {
    let required = data_len(value)?;
    if output.len() < required {
        return Err(Error::OutputTooSmall);
    }
    let mut position = 1;
    let payload = match value {
        Output::Source { id, original, .. } => {
            output[0] = 1;
            write(u64::from(id.0), output, &mut position);
            original
        }
        Output::Near8(row) => return crate::rolling::near8::encode(row, output),
        Output::Repair(repair) => {
            output[0] = if repair.support.tail { 4 } else { 2 };
            write(repair.id.0, output, &mut position);
            write(u64::from(repair.support.end), output, &mut position);
            repair.bytes
        }
    };
    output[position..required].copy_from_slice(payload);
    Ok(required)
}
/// Exact selected feedback size. Validation remains the sender's authority gate.
pub fn feedback_len(feedback: Feedback) -> usize {
    1 + [
        feedback.id.0,
        u64::from(feedback.prefix),
        u64::from(feedback.observed_end),
        u64::from(feedback.deficit),
    ]
    .into_iter()
    .map(len)
    .sum::<usize>()
}
/// Serialize a previously validated frozen feedback snapshot.
pub fn encode_feedback(feedback: Feedback, output: &mut [u8]) -> Result<usize, Error> {
    let required = feedback_len(feedback);
    if output.len() < required {
        return Err(Error::OutputTooSmall);
    }
    output[0] = 3;
    let mut position = 1;
    for value in [
        feedback.id.0,
        u64::from(feedback.prefix),
        u64::from(feedback.observed_end),
        u64::from(feedback.deficit),
    ] {
        write(value, output, &mut position);
    }
    Ok(required)
}
/// Exact length of an authenticated named-source request.
pub fn gap_len(request: GapRequest) -> usize {
    5 + len(request.id.0) + len(u64::from(request.prefix)) + len(u64::from(request.start))
}
/// Encode the immutable requested span. The outer carrier authenticates the scope.
pub fn encode_gap(config: Config, request: GapRequest, output: &mut [u8]) -> Result<usize, Error> {
    request.validate(config)?;
    let size = gap_len(request);
    if output.len() < size {
        return Err(Error::OutputTooSmall);
    }
    output[0] = 5;
    let mut pos = 1;
    for v in [
        request.id.0,
        u64::from(request.prefix),
        u64::from(request.start),
    ] {
        write(v, output, &mut pos);
    }
    output[pos..size].copy_from_slice(&request.mask.to_be_bytes());
    Ok(size)
}
/// Canonical bounded union parsing with complete externally established scope.
pub fn inspect(config: Config, scope: Scope, bytes: &[u8]) -> Result<View<'_>, Error> {
    config.validate()?;
    let kind = *bytes.first().ok_or(Error::Length)?;
    let mut position = 1;
    let id = read(bytes, &mut position)?;
    match kind {
        1 => {
            let id = SourceId(u32::try_from(id).map_err(|_| Error::Identity)?);
            id.0.checked_add(1).ok_or(Error::Identity)?;
            let original = &bytes[position..];
            if original.is_empty() || original.len() > config.max_payload {
                return Err(Error::Length);
            }
            Ok(View::Data(super::View::Source {
                scope,
                id,
                original,
            }))
        }
        2 | 4 => {
            if id == u64::MAX {
                return Err(Error::Identity);
            }
            let end = u32::try_from(read(bytes, &mut position)?).map_err(|_| Error::Identity)?;
            let repair = Repair {
                scope,
                id: RepairId(id),
                support: config.support(end, RepairId(id), kind == 4)?,
                bytes: &bytes[position..],
            };
            repair_shape(config, repair, config.width()?)?;
            Ok(View::Data(super::View::Repair(repair)))
        }
        3 => {
            let feedback = Feedback {
                scope,
                id: FeedbackId(id),
                prefix: word(bytes, &mut position)?,
                observed_end: word(bytes, &mut position)?,
                deficit: word(bytes, &mut position)?,
            };
            if position != bytes.len() || feedback.id.0 == 0 || feedback.id.0 == u64::MAX {
                return Err(Error::Identity);
            }
            let extent = feedback
                .observed_end
                .checked_sub(feedback.prefix)
                .ok_or(Error::Identity)?;
            if extent as usize > config.window || feedback.deficit > extent {
                return Err(Error::Identity);
            }
            Ok(View::Feedback(feedback))
        }
        5 => {
            let prefix = word(bytes, &mut position)?;
            let start = word(bytes, &mut position)?;
            let mask = u32::from_be_bytes(bytes[position..].try_into().map_err(|_| Error::Length)?);
            let request = GapRequest {
                scope,
                id: FeedbackId(id),
                prefix,
                start,
                mask,
            };
            request.validate(config)?;
            Ok(View::Gap(request))
        }
        _ => Err(Error::Format),
    }
}
pub(crate) fn len(value: u64) -> usize {
    ((64 - value.leading_zeros()).max(1) as usize).div_ceil(7)
}
pub(crate) fn write(mut value: u64, output: &mut [u8], position: &mut usize) {
    loop {
        let low = (value & 0x7f) as u8;
        value >>= 7;
        output[*position] = low | if value == 0 { 0 } else { 0x80 };
        *position += 1;
        if value == 0 {
            break;
        }
    }
}
pub(crate) fn read(input: &[u8], position: &mut usize) -> Result<u64, Error> {
    let mut value = 0;
    for index in 0..10 {
        let byte = *input.get(*position).ok_or(Error::Length)?;
        *position += 1;
        if index == 9 && byte > 1 {
            return Err(Error::Format);
        }
        value |= u64::from(byte & 0x7f) << (index * 7);
        if byte & 0x80 == 0 {
            if index > 0 && byte == 0 {
                return Err(Error::Format);
            }
            return Ok(value);
        }
    }
    Err(Error::Format)
}
pub(crate) fn word(input: &[u8], position: &mut usize) -> Result<u32, Error> {
    u32::try_from(read(input, position)?).map_err(|_| Error::Identity)
}
