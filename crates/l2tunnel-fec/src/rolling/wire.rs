//! Versioned bounded rolling vectors; structural parsing grants no authority.
//!
//! Authenticate and replay-check the complete enclosing record before using its
//! contents with a rolling owner. Compare the returned full scope to the actual
//! authenticated session. This codec has no keys, replay state or transport.
use super::{Config, Error, MAX_PAYLOAD, Repair, RepairId, Scope, SourceId, Support, add};

/// Explicit context-free union; the authenticated configuration binds its grammar.
pub mod compact;

/// Complete fixed version-three/four header, excluding the negotiated vector.
pub const HEADER_BYTES: usize = 64;
/// Maximum full record under the rolling payload limit; block limits are separate.
pub const MAX_RECORD_BYTES: usize = HEADER_BYTES + MAX_PAYLOAD + 2;
/// Version with padded sources and effective repair extents.
pub const VERSION: u8 = 3;
/// Version with exact sources and effective repair extents.
pub const EXACT_SOURCE_VERSION: u8 = 4;

/// Explicitly selected systematic-source encoding, bound by the authenticated policy.
///
/// Both formats share the header, identities and effective repair extents and
/// present the identical original bytes to the decoder. Each accepts only its
/// own version byte, so records of the two formats can never be mixed.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum SourceWire {
    /// Version 3: every source record carries its complete zero-padded vector.
    #[default]
    Padded,
    /// Version 4: a source record ends after its exact original bytes. The
    /// receiver's decoder reconstructs the same bounded zero-padded vector.
    Exact,
}
impl SourceWire {
    /// Wire version byte required in every record of this format.
    pub const fn version(self) -> u8 {
        match self {
            Self::Padded => VERSION,
            Self::Exact => EXACT_SOURCE_VERSION,
        }
    }
}

/// Exact complete source-record length for a validated original length.
///
/// Rejects an empty or oversized original before any allocation or output.
pub fn source_len(config: Config, format: SourceWire, original: usize) -> Result<usize, Error> {
    let width = config.width()?;
    if original == 0 || original > config.max_payload {
        return Err(Error::Length);
    }
    match format {
        SourceWire::Padded => add(HEADER_BYTES, width),
        SourceWire::Exact => add(add(HEADER_BYTES, 2)?, original),
    }
}
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
    repair.validate_extent(width)?;
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
    inspect_with(config, SourceWire::Padded, bytes)
}

/// Inspect exactly one complete record of the explicitly selected format.
///
/// The repair width and the maximum source length come from the validated local
/// configuration. An exact source record must end precisely after its declared
/// original, so truncation and trailing bytes are both rejected. A record whose
/// version byte belongs to the other format is a format error, never a fallback.
pub fn inspect_with(config: Config, format: SourceWire, bytes: &[u8]) -> Result<View<'_>, Error> {
    let width = config.width()?;
    let full = add(HEADER_BYTES, width)?;
    let variable = bytes.len() >= HEADER_BYTES
        && (bytes[5] == REPAIR || format == SourceWire::Exact && bytes[5] == SOURCE);
    if variable {
        if bytes.len() < add(HEADER_BYTES, 3)? || bytes.len() > full {
            return Err(Error::Length);
        }
    } else if bytes.len() != full {
        return Err(Error::Length);
    }
    if &bytes[..4] != MAGIC
        || bytes[4] != format.version()
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
        if length == 0 || length > config.max_payload {
            return Err(Error::Length);
        }
        let tail = vector.get(2 + length..).ok_or(Error::Length)?;
        let canonical = match format {
            SourceWire::Padded => tail.iter().all(|b| *b == 0),
            SourceWire::Exact => tail.is_empty(),
        };
        if !canonical {
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

fn header(
    output: &mut [u8],
    version: u8,
    kind: u8,
    scope: Scope,
    id: u64,
    support: Support,
    width: u16,
) {
    output[..HEADER_BYTES].fill(0);
    output[..4].copy_from_slice(MAGIC);
    output[4] = version;
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
    encode_source_with(config, SourceWire::Padded, scope, id, original, output)
}

/// Encode one exact original in the explicitly selected source format.
///
/// The exact format writes only the header, length and original bytes; nothing
/// beyond the returned length is modified. Every rejection leaves the entire
/// caller output unchanged.
pub fn encode_source_with(
    config: Config,
    format: SourceWire,
    scope: Scope,
    id: SourceId,
    original: &[u8],
    output: &mut [u8],
) -> Result<usize, Error> {
    let width = config.width()?;
    let support = source_support(id)?;
    let length = source_len(config, format, original.len())?;
    if output.len() < length {
        return Err(Error::OutputTooSmall);
    }
    let width = u16::try_from(width).map_err(|_| Error::Length)?;
    let original_len = u16::try_from(original.len()).map_err(|_| Error::Length)?;
    header(
        output,
        format.version(),
        SOURCE,
        scope,
        u64::from(id.0),
        support,
        width,
    );
    output[HEADER_BYTES..length].fill(0);
    output[HEADER_BYTES..HEADER_BYTES + 2].copy_from_slice(&original_len.to_be_bytes());
    output[HEADER_BYTES + 2..HEADER_BYTES + 2 + original.len()].copy_from_slice(original);
    Ok(length)
}

/// Encode a canonical rolling equation's complete effective prefix.
///
/// The bytes may be any bounded equation prefix; algebra and reconstructed source
/// validation belong to the decoder. Every rejected call leaves output unchanged.
pub fn encode_repair(
    config: Config,
    repair: Repair<'_>,
    output: &mut [u8],
) -> Result<usize, Error> {
    encode_repair_with(config, SourceWire::Padded, repair, output)
}

/// Encode the actual effective equation extent under the selected source format.
pub fn encode_repair_with(
    config: Config,
    format: SourceWire,
    repair: Repair<'_>,
    output: &mut [u8],
) -> Result<usize, Error> {
    let width = config.width()?;
    repair_shape(config, repair, width)?;
    let length = add(HEADER_BYTES, repair.bytes.len())?;
    if output.len() < length {
        return Err(Error::OutputTooSmall);
    }
    let width = u16::try_from(width).map_err(|_| Error::Length)?;
    header(
        output,
        format.version(),
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
