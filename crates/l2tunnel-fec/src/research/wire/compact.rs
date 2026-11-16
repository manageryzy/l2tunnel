//! Selected context-free research union using the maintained exact profile.
use super::*;
use crate::rolling::wire::compact::{len, read, word, write};

/// Worst-case selected source/repair union, before outer protection.
pub fn maximum_data_bytes(config: Config) -> Result<usize, Error> {
    config.validate()?;
    Ok(16 + config.recovery.width()?)
}
/// Worst-case selected strong feedback, preserving full receipt identity.
pub const MAXIMUM_FEEDBACK_BYTES: usize = 21;
/// Exact body size of an actual immutable research owner output.
pub fn data_len(output: Output<'_>) -> Result<usize, Error> {
    match output {
        Output::Source { id, original, .. } => {
            id.0.checked_add(1).ok_or(Error::Identity)?;
            if original.is_empty() || original.len() > rolling::MAX_PAYLOAD {
                return Err(Error::Length);
            }
            Ok(1 + len(u64::from(id.0)) + original.len())
        }
        Output::Repair(repair) => Ok(1
            + len(repair.equation.id.0)
            + len(u64::from(repair.equation.support.end))
            + len(u64::from(repair.confirmed))
            + repair.equation.bytes.len()),
    }
}
/// Serialize the original or actual equation directly without profile/scope duplication.
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
        Output::Repair(repair) => {
            output[0] = 2;
            write(repair.equation.id.0, output, &mut position);
            write(
                u64::from(repair.equation.support.end),
                output,
                &mut position,
            );
            write(u64::from(repair.confirmed), output, &mut position);
            repair.equation.bytes
        }
    };
    output[position..required].copy_from_slice(payload);
    Ok(required)
}
/// Exact selected feedback size for a frozen committed snapshot.
pub fn feedback_len(feedback: Feedback) -> usize {
    1 + [
        feedback.id.0,
        u64::from(feedback.prefix),
        u64::from(feedback.observed_end),
    ]
    .into_iter()
    .map(len)
    .sum::<usize>()
}
/// Encode a frozen cumulative receipt, retaining original identity and causal semantics.
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
    ] {
        write(value, output, &mut position);
    }
    Ok(required)
}
/// Inspect the selected union using its externally established complete scope/profile.
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
            source_len(config, original.len())?;
            Ok(View::Source {
                scope,
                id,
                original,
            })
        }
        2 => {
            let serial = u32::try_from(id).map_err(|_| Error::Identity)?;
            let end = word(bytes, &mut position)?;
            let confirmed = word(bytes, &mut position)?;
            let repair = Repair {
                equation: rolling::Repair {
                    scope,
                    id: RepairId(id),
                    support: config.profile.support(end, confirmed, serial)?,
                    bytes: &bytes[position..],
                },
                confirmed,
            };
            repair.validate(config)?;
            Ok(View::Repair(repair))
        }
        3 => {
            let feedback = Feedback {
                scope,
                id: FeedbackId(id),
                prefix: word(bytes, &mut position)?,
                observed_end: word(bytes, &mut position)?,
            };
            if position != bytes.len() {
                return Err(Error::Length);
            }
            feedback.validate(config)?;
            Ok(View::Feedback(feedback))
        }
        _ => Err(Error::Format),
    }
}
