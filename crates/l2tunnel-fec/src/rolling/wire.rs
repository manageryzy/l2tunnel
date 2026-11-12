//! Versioned bounded rolling vectors; structural parsing grants no authority.
//!
//! Authenticate and replay-check the complete enclosing record before using its
//! contents with a rolling owner. Compare the returned full scope to the actual
//! authenticated session. This codec has no keys, replay state or transport.
use super::{Config, Error, MAX_PAYLOAD, Repair, RepairId, Scope, SourceId, Support, add};

/// Complete fixed version-one header, excluding the negotiated vector.
pub const HEADER_BYTES: usize = 64;
/// Maximum full record under the rolling payload limit; block limits are separate.
pub const MAX_RECORD_BYTES: usize = HEADER_BYTES + MAX_PAYLOAD + 2;
/// Version of this enclosing length-vector format, distinct from compact wire.
pub const VERSION: u8 = 1;
const MAGIC: &[u8; 4] = b"L2RW";
const SOURCE: u8 = 1;
const REPAIR: u8 = 2;
const TAIL: u8 = 1;

/// Borrowed validated structure, never an authentication or ownership proof.
#[derive(Clone, Copy, Debug)]
pub enum View<'a> {
    /// Exact original bytes after validating the complete length/padding vector.
    Source {
        /// Full enclosing domain; compare against the authenticated session.
        scope: Scope,
        /// Nonwrapping original identity in its separate source namespace.
        id: SourceId,
        /// Exact nonempty original, including meaningful trailing zero bytes.
        original: &'a [u8],
    },
    /// Complete equation; scope/identity/replay admission remains the owner's job.
    Repair(Repair<'a>),
}

fn array<const N: usize>(bytes: &[u8]) -> Result<[u8; N], Error> {
    bytes.try_into().map_err(|_| Error::Length)
}
fn source_support(id: SourceId) -> Result<Support, Error> {
    let end = id.0.checked_add(1).ok_or(Error::Identity)?;
    Ok(Support {
        start: id.0,
        end,
        seed: 0,
        tail: false,
    })
}
fn repair_shape(config: Config, repair: Repair<'_>, width: usize) -> Result<(), Error> {
    if repair.bytes.len() != width {
        return Err(Error::Length);
    }
    if repair.id.0 == u64::MAX
        || config.support(repair.support.end, repair.id, repair.support.tail)? != repair.support
    {
        return Err(Error::Identity);
    }
    Ok(())
}

/// Inspect exactly one complete version-one record without allocation.
///
/// The vector width is fixed by the validated local configuration, never selected
/// by a received length. Arbitrary scope bytes are returned for the authenticated
/// caller to compare. Invalid input cannot mutate an encoder or decoder.
pub fn inspect(config: Config, bytes: &[u8]) -> Result<View<'_>, Error> {
    let width = config.width()?;
    if bytes.len() != add(HEADER_BYTES, width)? {
        return Err(Error::Length);
    }
    if &bytes[..4] != MAGIC
        || bytes[4] != VERSION
        || !matches!(bytes[5], SOURCE | REPAIR)
        || bytes[6] & !TAIL != 0
        || bytes[7] != 0
        || bytes[37..40] != [0; 3]
        || bytes[62..64] != [0; 2]
    {
        return Err(Error::Format);
    }
    if usize::from(u16::from_be_bytes(array(&bytes[60..62])?)) != width {
        return Err(Error::Length);
    }
    let scope = Scope {
        session: array(&bytes[8..24])?,
        epoch: u64::from_be_bytes(array(&bytes[24..32])?),
        stream: u32::from_be_bytes(array(&bytes[32..36])?),
        direction: bytes[36],
    };
    let id = u64::from_be_bytes(array(&bytes[40..48])?);
    let support = Support {
        start: u32::from_be_bytes(array(&bytes[48..52])?),
        end: u32::from_be_bytes(array(&bytes[52..56])?),
        seed: u32::from_be_bytes(array(&bytes[56..60])?),
        tail: bytes[6] == TAIL,
    };
    let vector = &bytes[HEADER_BYTES..];
    if bytes[5] == SOURCE {
        let id = SourceId(u32::try_from(id).map_err(|_| Error::Identity)?);
        if source_support(id)? != support {
            return Err(Error::Identity);
        }
        let length = usize::from(u16::from_be_bytes(array(&vector[..2])?));
        if length == 0
            || length > config.max_payload
            || vector[2 + length..].iter().any(|b| *b != 0)
        {
            return Err(Error::Length);
        }
        Ok(View::Source {
            scope,
            id,
            original: &vector[2..2 + length],
        })
    } else {
        let repair = Repair {
            scope,
            id: RepairId(id),
            support,
            bytes: vector,
        };
        repair_shape(config, repair, width)?;
        Ok(View::Repair(repair))
    }
}

fn header(output: &mut [u8], kind: u8, scope: Scope, id: u64, support: Support, width: u16) {
    output[..HEADER_BYTES].fill(0);
    output[..4].copy_from_slice(MAGIC);
    output[4] = VERSION;
    output[5] = kind;
    output[6] = u8::from(support.tail);
    output[8..24].copy_from_slice(&scope.session);
    output[24..32].copy_from_slice(&scope.epoch.to_be_bytes());
    output[32..36].copy_from_slice(&scope.stream.to_be_bytes());
    output[36] = scope.direction;
    output[40..48].copy_from_slice(&id.to_be_bytes());
    output[48..52].copy_from_slice(&support.start.to_be_bytes());
    output[52..56].copy_from_slice(&support.end.to_be_bytes());
    output[56..60].copy_from_slice(&support.seed.to_be_bytes());
    output[60..62].copy_from_slice(&width.to_be_bytes());
}

/// Encode one exact original into the fixed-width enclosing vector.
///
/// Every rejection leaves the entire caller output unchanged. Successful encoding
/// changes only the returned record prefix; authentication is a separate boundary.
pub fn encode_source(
    config: Config,
    scope: Scope,
    id: SourceId,
    original: &[u8],
    output: &mut [u8],
) -> Result<usize, Error> {
    let width = config.width()?;
    let support = source_support(id)?;
    if original.is_empty() || original.len() > config.max_payload {
        return Err(Error::Length);
    }
    let length = add(HEADER_BYTES, width)?;
    if output.len() < length {
        return Err(Error::OutputTooSmall);
    }
    let width = u16::try_from(width).map_err(|_| Error::Length)?;
    let original_len = u16::try_from(original.len()).map_err(|_| Error::Length)?;
    header(output, SOURCE, scope, u64::from(id.0), support, width);
    output[HEADER_BYTES..length].fill(0);
    output[HEADER_BYTES..HEADER_BYTES + 2].copy_from_slice(&original_len.to_be_bytes());
    output[HEADER_BYTES + 2..HEADER_BYTES + 2 + original.len()].copy_from_slice(original);
    Ok(length)
}

/// Encode a complete canonical rolling equation without trimming its vector.
///
/// The bytes may be any full-width equation; algebra and reconstructed source
/// validation belong to the decoder. Every rejected call leaves output unchanged.
pub fn encode_repair(
    config: Config,
    repair: Repair<'_>,
    output: &mut [u8],
) -> Result<usize, Error> {
    let width = config.width()?;
    repair_shape(config, repair, width)?;
    let length = add(HEADER_BYTES, width)?;
    if output.len() < length {
        return Err(Error::OutputTooSmall);
    }
    let width = u16::try_from(width).map_err(|_| Error::Length)?;
    header(
        output,
        REPAIR,
        repair.scope,
        repair.id.0,
        repair.support,
        width,
    );
    output[HEADER_BYTES..length].copy_from_slice(repair.bytes);
    Ok(length)
}

#[cfg(test)]
mod tests;
