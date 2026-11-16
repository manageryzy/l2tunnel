//! Canonical context-free algorithm bodies for an explicitly selected union.
use super::*;

/// Worst-case source/attempt metadata, retaining both complete u64 domains.
pub const COMPACT_BODY_DATA_MAX_HEADER_BYTES: usize = 20;
/// Worst-case feedback scalar metadata, before the exact bitmap.
pub const COMPACT_BODY_FEEDBACK_MAX_HEADER_BYTES: usize = 53;

impl CompactPacketView<'_> {
    /// Branch to be authenticated by the enclosing final packet encoder.
    pub const fn kind(self) -> CompactPacketKind {
        match self {
            Self::Data { .. } => CompactPacketKind::Data,
            Self::Feedback(_) => CompactPacketKind::Feedback,
        }
    }

    /// Exact selected body size, without context, kind, protection or carrier.
    /// Full identities use canonical base-128 unsigned integers, never truncation.
    pub fn compact_encoded_len(self) -> Result<usize, RecoveryError> {
        self.legacy_encoded_len()?;
        match self {
            Self::Data {
                source,
                serial,
                payload,
            } => varint_len(source.0)
                .checked_add(varint_len(serial))
                .and_then(|size| size.checked_add(payload.len()))
                .ok_or(RecoveryError::SourceTooLarge),
            Self::Feedback(feedback) => Ok(feedback_values(feedback)
                .into_iter()
                .map(varint_len)
                .sum::<usize>()
                + feedback.bitmap.len()),
        }
    }

    /// Encode only this selected arm. Invalid fields/short output leave it intact.
    /// Source payload extends to the enclosing authenticated packet's exact end.
    pub fn encode_compact_into(self, output: &mut [u8]) -> Result<usize, RecoveryError> {
        let required = self.compact_encoded_len()?;
        ensure_output(output, required)?;
        let mut position = 0;
        let body = match self {
            Self::Data {
                source,
                serial,
                payload,
            } => {
                write_varint(source.0, output, &mut position);
                write_varint(serial, output, &mut position);
                payload
            }
            Self::Feedback(feedback) => {
                for value in feedback_values(feedback) {
                    write_varint(value, output, &mut position);
                }
                feedback.bitmap
            }
        };
        output[position..required].copy_from_slice(body);
        Ok(required)
    }

    pub(super) fn validate_policy(self, policy: CompactArqConfig) -> Result<(), RecoveryError> {
        let legacy = self.legacy_encoded_len()?;
        match self {
            Self::Data { payload, .. } if payload.len() > policy.bounds.max_source_bytes => {
                Err(RecoveryError::SourceTooLarge)
            }
            // Retain the negotiated bitmap domain; the smaller representation
            // does not silently increase feedback capacity or recovery windows.
            Self::Feedback(_) if legacy > policy.maximum_feedback_bytes => {
                Err(RecoveryError::MalformedPacket)
            }
            _ => Ok(()),
        }
    }
}

/// Parse a bounded body after its enclosing context, branch, check and replay
/// policy have been verified. No packet/context authentication is performed here.
pub fn inspect_compact_body(
    kind: CompactPacketKind,
    bytes: &[u8],
    policy: CompactArqConfig,
) -> Result<CompactPacketView<'_>, RecoveryError> {
    policy.validate()?;
    let mut position = 0;
    let view = match kind {
        CompactPacketKind::Data => CompactPacketView::Data {
            source: SourceId(read_varint(bytes, &mut position)?),
            serial: read_varint(bytes, &mut position)?,
            payload: &bytes[position..],
        },
        CompactPacketKind::Feedback => {
            let prefix = read_varint(bytes, &mut position)?;
            let start = prefix
                .checked_add(read_varint(bytes, &mut position)?)
                .ok_or(RecoveryError::MalformedPacket)?;
            let count = u16::try_from(read_varint(bytes, &mut position)?)
                .map_err(|_| RecoveryError::MalformedPacket)?;
            CompactPacketView::Feedback(CompactFeedback {
                prefix,
                start,
                count,
                echo: read_varint(bytes, &mut position)?,
                receiver_delay_us: read_varint(bytes, &mut position)?,
                serial: read_varint(bytes, &mut position)?,
                bitmap: &bytes[position..],
            })
        }
    };
    view.validate_policy(policy)?;
    Ok(view)
}

fn feedback_values(feedback: CompactFeedback<'_>) -> [u64; 6] {
    [
        feedback.prefix,
        feedback.start - feedback.prefix,
        u64::from(feedback.count),
        feedback.echo,
        feedback.receiver_delay_us,
        feedback.serial,
    ]
}
pub(super) fn feedback_body_len(
    prefix: u64,
    start: u64,
    count: u16,
    echo: u64,
    delay: u64,
    serial: u64,
) -> usize {
    [
        prefix,
        start - prefix,
        u64::from(count),
        echo,
        delay,
        serial,
    ]
    .into_iter()
    .map(varint_len)
    .sum::<usize>()
        + usize::from(count).div_ceil(8)
}
fn varint_len(value: u64) -> usize {
    ((64 - value.leading_zeros()).max(1) as usize).div_ceil(7)
}
fn write_varint(mut value: u64, output: &mut [u8], position: &mut usize) {
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
fn read_varint(input: &[u8], position: &mut usize) -> Result<u64, RecoveryError> {
    let mut value = 0;
    for index in 0..10 {
        let byte = *input.get(*position).ok_or(RecoveryError::MalformedPacket)?;
        *position += 1;
        if index == 9 && byte > 1 {
            return Err(RecoveryError::MalformedPacket);
        }
        value |= u64::from(byte & 0x7f) << (index * 7);
        if byte & 0x80 == 0 {
            if index > 0 && byte == 0 {
                return Err(RecoveryError::MalformedPacket);
            }
            return Ok(value);
        }
    }
    Err(RecoveryError::MalformedPacket)
}

#[cfg(test)]
mod tests;
