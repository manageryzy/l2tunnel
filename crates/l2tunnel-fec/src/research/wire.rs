//! Draft explicit research records. Parsing establishes structure, never authority.
use super::*;

/// Explicit context-free selected union; legacy formats remain unchanged.
pub mod compact;

/// Fixed complete header including the twelve-byte exact algorithm descriptor.
pub const HEADER_BYTES: usize = 80;
/// Version of this additive format, distinct from rolling record versions.
pub const VERSION: u8 = 1;

/// Borrowed validated record; no payload allocation or sender ledger is used.
#[derive(Clone, Copy, Debug)]
pub enum View<'a> {
    /// Exact original source bytes.
    Source {
        /// Authenticated enclosing scope to compare at admission.
        scope: Scope,
        /// Absolute source identity.
        id: SourceId,
        /// Nonempty original including meaningful trailing zero bytes.
        original: &'a [u8],
    },
    /// Actual expanded repair vector and frozen sender receipt prefix.
    Repair(Repair<'a>),
    /// Cumulative committed recovery receipt.
    Feedback(Feedback),
}
/// Exact maintained twelve-byte algorithm descriptor; no authority is inferred.
pub fn profile_bytes(profile: Profile) -> [u8; 12] {
    let mut bytes = [0; 12];
    match profile {
        Profile::Recursive {
            taps,
            width,
            reset,
            fresh_interval,
        } => {
            bytes[0] = 1;
            bytes[1] = taps;
            bytes[2..4].copy_from_slice(&width.to_be_bytes());
            bytes[4..6].copy_from_slice(&reset.to_be_bytes());
            bytes[6..8].copy_from_slice(&fresh_interval.to_be_bytes());
        }
        Profile::Accumulator { lanes, window } => {
            bytes[0] = 2;
            bytes[8..10].copy_from_slice(&lanes.to_be_bytes());
            bytes[10..12].copy_from_slice(&window.to_be_bytes());
        }
    }
    bytes
}
fn header(config: Config, scope: Scope, kind: u8, id: u64) -> Result<[u8; HEADER_BYTES], Error> {
    config.validate()?;
    let mut bytes = [0; HEADER_BYTES];
    bytes[..4].copy_from_slice(b"L2RS");
    bytes[4] = VERSION;
    bytes[5] = kind;
    bytes[8..24].copy_from_slice(&scope.session);
    bytes[24..32].copy_from_slice(&scope.epoch.to_be_bytes());
    bytes[32..36].copy_from_slice(&scope.stream.to_be_bytes());
    bytes[36] = scope.direction;
    bytes[40..48].copy_from_slice(&id.to_be_bytes());
    bytes[60..62].copy_from_slice(&(config.recovery.width()? as u16).to_be_bytes());
    bytes[64..76].copy_from_slice(&profile_bytes(config.profile));
    Ok(bytes)
}
/// Exact source record size; rejects empty or oversized originals.
pub fn source_len(config: Config, original: usize) -> Result<usize, Error> {
    config.validate()?;
    if original == 0 || original > config.recovery.max_payload {
        return Err(Error::Length);
    }
    add(HEADER_BYTES, original)
}
/// Encode a source atomically into caller storage. Errors leave that storage unchanged.
pub fn encode_source(
    config: Config,
    scope: Scope,
    id: SourceId,
    original: &[u8],
    output: &mut [u8],
) -> Result<usize, Error> {
    let size = source_len(config, original.len())?;
    let end = id.0.checked_add(1).ok_or(Error::Identity)?;
    let mut head = header(config, scope, 1, u64::from(id.0))?;
    head[48..52].copy_from_slice(&id.0.to_be_bytes());
    head[52..56].copy_from_slice(&end.to_be_bytes());
    if output.len() < size {
        return Err(Error::OutputTooSmall);
    }
    output[..HEADER_BYTES].copy_from_slice(&head);
    output[HEADER_BYTES..size].copy_from_slice(original);
    Ok(size)
}
/// Encode a repair atomically, retaining its identity, exact support and all coded bytes.
pub fn encode_repair(
    config: Config,
    repair: Repair<'_>,
    output: &mut [u8],
) -> Result<usize, Error> {
    repair.validate(config)?;
    let r = repair.equation;
    let size = add(HEADER_BYTES, r.bytes.len())?;
    let mut head = header(config, r.scope, 2, r.id.0)?;
    head[48..52].copy_from_slice(&r.support.start.to_be_bytes());
    head[52..56].copy_from_slice(&r.support.end.to_be_bytes());
    head[56..60].copy_from_slice(&r.support.seed.to_be_bytes());
    head[76..80].copy_from_slice(&repair.confirmed.to_be_bytes());
    if output.len() < size {
        return Err(Error::OutputTooSmall);
    }
    output[..HEADER_BYTES].copy_from_slice(&head);
    output[HEADER_BYTES..size].copy_from_slice(r.bytes);
    Ok(size)
}
/// Encode a cumulative receipt; all bytes consume the reverse path's output budget.
pub fn encode_feedback(
    config: Config,
    feedback: Feedback,
    output: &mut [u8],
) -> Result<usize, Error> {
    feedback.validate(config)?;
    let mut head = header(config, feedback.scope, 3, feedback.id.0)?;
    head[48..52].copy_from_slice(&feedback.prefix.to_be_bytes());
    head[52..56].copy_from_slice(&feedback.observed_end.to_be_bytes());
    if output.len() < HEADER_BYTES {
        return Err(Error::OutputTooSmall);
    }
    output[..HEADER_BYTES].copy_from_slice(&head);
    Ok(HEADER_BYTES)
}
fn array<const N: usize>(bytes: &[u8]) -> Result<[u8; N], Error> {
    bytes.try_into().map_err(|_| Error::Length)
}
/// Parse one exact record against the negotiated profile before admission.
pub fn inspect(config: Config, bytes: &[u8]) -> Result<View<'_>, Error> {
    config.validate()?;
    if bytes.len() < HEADER_BYTES || bytes.len() > add(HEADER_BYTES, config.recovery.width()?)? {
        return Err(Error::Length);
    }
    if &bytes[..4] != b"L2RS"
        || bytes[4] != VERSION
        || bytes[6..8] != [0; 2]
        || bytes[37..40] != [0; 3]
        || bytes[62..64] != [0; 2]
        || bytes[64..76] != profile_bytes(config.profile)
    {
        return Err(Error::Format);
    }
    if usize::from(u16::from_be_bytes(array(&bytes[60..62])?)) != config.recovery.width()? {
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
    let seed = u32::from_be_bytes(array(&bytes[56..60])?);
    let confirmed = u32::from_be_bytes(array(&bytes[76..80])?);
    match bytes[5] {
        1 => {
            let source = u32::try_from(id).map_err(|_| Error::Identity)?;
            if source != start || source.checked_add(1) != Some(end) || seed != 0 || confirmed != 0
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
            let value = Repair {
                equation: rolling::Repair {
                    scope,
                    id: RepairId(id),
                    support: rolling::Support {
                        start,
                        end,
                        seed,
                        tail: false,
                    },
                    bytes: &bytes[HEADER_BYTES..],
                },
                confirmed,
            };
            value.validate(config)?;
            Ok(View::Repair(value))
        }
        3 => {
            if bytes.len() != HEADER_BYTES || seed != 0 || confirmed != 0 {
                return Err(Error::Length);
            }
            let value = Feedback {
                scope,
                id: FeedbackId(id),
                prefix: start,
                observed_end: end,
            };
            value.validate(config)?;
            Ok(View::Feedback(value))
        }
        _ => Err(Error::Format),
    }
}
