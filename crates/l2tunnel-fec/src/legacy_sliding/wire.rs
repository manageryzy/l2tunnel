//! Explicit legacy-algorithm records; parsing establishes structure, never authority.
use super::*;

/// Complete fixed protocol header, excluding terms, bytes and outer framing.
pub const HEADER_BYTES: usize = 72;
/// Current effective-extent format, unrelated to Python's analytical accounting.
pub const VERSION: u8 = 2;

/// One exact authenticated-carrier record borrowed from caller buffers.
#[derive(Clone, Copy, Debug)]
pub enum View<'a> {
    /// Original source bytes, without coded length or padding.
    Source {
        /// Enclosing forward domain.
        scope: Scope,
        /// Nonwrapping source identity.
        id: SourceId,
        /// Complete nonempty original.
        original: &'a [u8],
    },
    /// Complete explicit coefficient equation.
    Repair(Repair<'a>),
    /// Reverse selective/cumulative receipt.
    Feedback(Feedback<'a>),
}
fn profile(config: Config) -> [u8; 7] {
    [
        config.long_window as u8,
        config.short_window as u8,
        config.long_every as u8,
        config.repair_every as u8,
        config.repairs_per_group as u8,
        u8::from(config.interleave_repairs)
            | (u8::from(config.feedback_repair) << 1)
            | (u8::from(config.cumulative_feedback) << 2),
        config.feedback_batch as u8,
    ]
}
fn header(config: Config, scope: Scope, kind: u8, id: u64) -> Result<[u8; HEADER_BYTES], Error> {
    config.validate()?;
    let mut out = [0; HEADER_BYTES];
    out[..4].copy_from_slice(b"L2LS");
    out[4] = VERSION;
    out[5] = kind;
    out[7] = match config.mode {
        Mode::Sliding => 1,
        Mode::Hybrid => 2,
    };
    out[8..24].copy_from_slice(&scope.session);
    out[24..32].copy_from_slice(&scope.epoch.to_be_bytes());
    out[32..36].copy_from_slice(&scope.stream.to_be_bytes());
    out[36] = scope.direction;
    out[40..48].copy_from_slice(&id.to_be_bytes());
    out[58..60].copy_from_slice(&(config.recovery.width()? as u16).to_be_bytes());
    out[60..67].copy_from_slice(&profile(config));
    Ok(out)
}
/// Complete source record size; originals retain meaningful trailing zero bytes.
pub fn source_len(config: Config, original: usize) -> Result<usize, Error> {
    config.validate()?;
    if original == 0 || original > config.recovery.max_payload {
        return Err(Error::Length);
    }
    add(HEADER_BYTES, original)
}
/// Encode atomically; failure leaves output storage unchanged.
pub fn encode_source(
    config: Config,
    scope: Scope,
    source: SourceId,
    original: &[u8],
    output: &mut [u8],
) -> Result<usize, Error> {
    let length = source_len(config, original.len())?;
    let end = source.0.checked_add(1).ok_or(Error::Identity)?;
    let mut head = header(config, scope, 1, u64::from(source.0))?;
    head[48..52].copy_from_slice(&source.0.to_be_bytes());
    head[52..56].copy_from_slice(&end.to_be_bytes());
    if output.len() < length {
        return Err(Error::OutputTooSmall);
    }
    output[..HEADER_BYTES].copy_from_slice(&head);
    output[HEADER_BYTES..length].copy_from_slice(original);
    Ok(length)
}
/// Encode the exact frozen sparse coefficients and effective coded extent.
pub fn encode_repair(
    config: Config,
    repair: Repair<'_>,
    output: &mut [u8],
) -> Result<usize, Error> {
    repair.validate(config)?;
    let length = repair.charge(0)?;
    let mut head = header(config, repair.equation.scope, 2, repair.equation.id.0)?;
    head[6] = u8::from(repair.feedback_triggered);
    head[48..52].copy_from_slice(&repair.equation.support.start.to_be_bytes());
    head[52..56].copy_from_slice(&repair.equation.support.end.to_be_bytes());
    head[56..58].copy_from_slice(&(repair.terms.len() as u16).to_be_bytes());
    if length > config.max_record_bytes {
        return Err(Error::Length);
    }
    if output.len() < length {
        return Err(Error::OutputTooSmall);
    }
    output[..HEADER_BYTES].copy_from_slice(&head);
    for (index, term) in repair.terms.iter().enumerate() {
        let at = HEADER_BYTES + 5 * index;
        output[at..at + 4].copy_from_slice(&term.source.0.to_be_bytes());
        output[at + 4] = term.coefficient;
    }
    output[HEADER_BYTES + 5 * repair.terms.len()..length].copy_from_slice(repair.equation.bytes);
    Ok(length)
}
/// Encode a reverse-budgeted receipt atomically into caller storage.
pub fn encode_feedback(
    config: Config,
    feedback: Feedback<'_>,
    output: &mut [u8],
) -> Result<usize, Error> {
    feedback.validate(config)?;
    let length = feedback.charge(0)?;
    let mut head = header(config, feedback.scope, 3, feedback.id.0)?;
    head[6] = u8::from(feedback.prefix.is_some()) << 1;
    head[48..52].copy_from_slice(&feedback.prefix.unwrap_or(0).to_be_bytes());
    head[56..58].copy_from_slice(&(feedback.ids.len() as u16).to_be_bytes());
    if output.len() < length {
        return Err(Error::OutputTooSmall);
    }
    output[..HEADER_BYTES].copy_from_slice(&head);
    for (index, id) in feedback.ids.iter().enumerate() {
        let at = HEADER_BYTES + 4 * index;
        output[at..at + 4].copy_from_slice(&id.0.to_be_bytes());
    }
    Ok(length)
}
fn array<const N: usize>(value: &[u8]) -> Result<[u8; N], Error> {
    value.try_into().map_err(|_| Error::Length)
}
/// Parse without allocation. Scratch needs at most 255 terms or 255 IDs; only
/// the matching kind's scratch is used. Errors may alter scratch, never owners.
pub fn inspect<'a>(
    config: Config,
    bytes: &'a [u8],
    terms: &'a mut [Term],
    ids: &'a mut [SourceId],
) -> Result<View<'a>, Error> {
    config.validate()?;
    if bytes.len() < HEADER_BYTES || bytes.len() > config.max_record_bytes {
        return Err(Error::Length);
    }
    let expected_mode = match config.mode {
        Mode::Sliding => 1,
        Mode::Hybrid => 2,
    };
    if &bytes[..4] != b"L2LS"
        || bytes[4] != VERSION
        || bytes[7] != expected_mode
        || bytes[37..40] != [0; 3]
        || bytes[60..67] != profile(config)
        || bytes[67..72] != [0; 5]
    {
        return Err(Error::Format);
    }
    if usize::from(u16::from_be_bytes(array(&bytes[58..60])?)) != config.recovery.width()? {
        return Err(Error::Length);
    }
    let scope = Scope {
        session: array(&bytes[8..24])?,
        epoch: u64::from_be_bytes(array(&bytes[24..32])?),
        stream: u32::from_be_bytes(array(&bytes[32..36])?),
        direction: bytes[36],
    };
    let id = u64::from_be_bytes(array(&bytes[40..48])?);
    let start = u32::from_be_bytes(array(&bytes[48..52])?);
    let end = u32::from_be_bytes(array(&bytes[52..56])?);
    let count = usize::from(u16::from_be_bytes(array(&bytes[56..58])?));
    match bytes[5] {
        1 => {
            let source = u32::try_from(id).map_err(|_| Error::Identity)?;
            if bytes[6] != 0 || source != start || source.checked_add(1) != Some(end) || count != 0
            {
                return Err(Error::Identity);
            }
            let original = &bytes[HEADER_BYTES..];
            source_len(config, original.len())?;
            Ok(View::Source {
                scope,
                id: SourceId(source),
                original,
            })
        }
        2 => {
            if bytes[6] > 1
                || count == 0
                || count > usize::from(config.long_window)
                || !(HEADER_BYTES + 5 * count + 3
                    ..=HEADER_BYTES + 5 * count + config.recovery.width()?)
                    .contains(&bytes.len())
            {
                return Err(Error::Length);
            }
            if terms.len() < count {
                return Err(Error::OutputTooSmall);
            }
            for (index, term) in terms[..count].iter_mut().enumerate() {
                let at = HEADER_BYTES + 5 * index;
                *term = Term {
                    source: SourceId(u32::from_be_bytes(array(&bytes[at..at + 4])?)),
                    coefficient: bytes[at + 4],
                };
            }
            let feedback_triggered = bytes[6] == 1;
            let repair = Repair {
                equation: rolling::Repair {
                    scope,
                    id: RepairId(id),
                    support: rolling::Support {
                        start,
                        end,
                        seed: u32::from(feedback_triggered),
                        tail: false,
                    },
                    bytes: &bytes[HEADER_BYTES + 5 * count..],
                },
                terms: &terms[..count],
                feedback_triggered,
            };
            repair.validate(config)?;
            Ok(View::Repair(repair))
        }
        3 => {
            if bytes[6] != u8::from(config.cumulative_feedback) << 1
                || end != 0
                || !config.cumulative_feedback && start != 0
                || count > config.feedback_limit()?
                || bytes.len() != HEADER_BYTES + 4 * count
            {
                return Err(Error::Length);
            }
            if ids.len() < count {
                return Err(Error::OutputTooSmall);
            }
            for (index, item) in ids[..count].iter_mut().enumerate() {
                let at = HEADER_BYTES + 4 * index;
                *item = SourceId(u32::from_be_bytes(array(&bytes[at..at + 4])?));
            }
            let feedback = Feedback {
                scope,
                id: FeedbackId(id),
                prefix: config.cumulative_feedback.then_some(start),
                ids: &ids[..count],
            };
            feedback.validate(config)?;
            Ok(View::Feedback(feedback))
        }
        _ => Err(Error::Format),
    }
}
