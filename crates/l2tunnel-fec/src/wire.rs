use crate::{
    BlockConfig, ChannelId, EncodedSymbol, Epoch, Error, FecContext, GenerationId, SymbolId,
};

/// Fixed FEC draft header, excluding explicit coefficients and coded bytes.
pub const HEADER_BYTES: usize = 56;

/// Canonical systematic unit row or explicitly described linear repair.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SymbolKind {
    /// Symbol ID is its source index and coefficients form that identity row.
    Systematic,
    /// Symbol ID is at least source_count, with an explicit nonzero coefficient row.
    Repair,
}

/// Borrowed, dimension-checked packet. Authentication belongs to the caller.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SymbolView<'a> {
    /// Generation in the supplied authenticated context.
    pub generation: GenerationId,
    /// Source or unique repair identity.
    pub symbol: SymbolId,
    /// Validated systematic/repair kind.
    pub kind: SymbolKind,
    /// Sealed generation source count.
    pub source_count: usize,
    /// Coded vector width, including original-length bytes.
    pub coded_bytes: usize,
    /// Exactly source_count coefficient bytes.
    pub coefficients: &'a [u8],
    /// Exactly coded_bytes payload bytes.
    pub payload: &'a [u8],
}

/// Parse without payload allocation and enforce exact authenticated-domain binding.
pub fn inspect(
    packet: &[u8],
    context: FecContext,
    config: BlockConfig,
) -> Result<SymbolView<'_>, Error> {
    config.validate()?;
    if packet.len() > config.max_packet_bytes {
        return Err(Error::PacketTooLarge);
    }
    let header = packet.get(..HEADER_BYTES).ok_or(Error::Malformed)?;
    if header[..2] != *b"FE" || header[2] != 1 || header[5] != 0 || header[52..56] != [0; 4] {
        return Err(Error::Malformed);
    }
    if header[4] != context.direction.wire()
        || header[8..24] != context.session.0
        || Epoch(u64::from_be_bytes(array(header, 24)?)) != context.epoch
        || ChannelId(u32::from_be_bytes(array(header, 32)?)) != context.channel
    {
        return Err(Error::ContextMismatch);
    }
    let source_count = usize::from(u16::from_be_bytes(array(header, 6)?));
    let coded_bytes = usize::from(u16::from_be_bytes(array(header, 48)?));
    if usize::from(u16::from_be_bytes(array(header, 50)?)) != source_count {
        return Err(Error::Malformed);
    }
    config.dimensions(source_count, coded_bytes)?;
    let boundary = HEADER_BYTES
        .checked_add(source_count)
        .ok_or(Error::Arithmetic)?;
    let expected = boundary.checked_add(coded_bytes).ok_or(Error::Arithmetic)?;
    if packet.len() != expected {
        return Err(Error::Malformed);
    }
    let coefficients = packet.get(HEADER_BYTES..boundary).ok_or(Error::Malformed)?;
    let payload = packet.get(boundary..).ok_or(Error::Malformed)?;
    if coefficients.iter().all(|&coefficient| coefficient == 0) {
        return Err(Error::InvalidCoefficients);
    }
    let symbol = SymbolId(u32::from_be_bytes(array(header, 44)?));
    let kind = match header[3] {
        0 => {
            if u64::from(symbol.0) >= source_count as u64
                || coefficients
                    .iter()
                    .enumerate()
                    .any(|(index, &value)| value != u8::from(index as u64 == u64::from(symbol.0)))
            {
                return Err(Error::InvalidCoefficients);
            }
            crate::original_length(payload)?;
            SymbolKind::Systematic
        }
        1 if u64::from(symbol.0) >= source_count as u64 => SymbolKind::Repair,
        _ => return Err(Error::Malformed),
    };
    Ok(SymbolView {
        generation: GenerationId(u64::from_be_bytes(array(header, 36)?)),
        symbol,
        kind,
        source_count,
        coded_bytes,
        coefficients,
        payload,
    })
}

pub(crate) fn encode(
    context: FecContext,
    generation: GenerationId,
    symbol: SymbolId,
    kind: SymbolKind,
    coefficients: &[u8],
    payload: &[u8],
) -> Result<EncodedSymbol, Error> {
    let count = u16::try_from(coefficients.len()).map_err(|_| Error::InvalidDimensions)?;
    let width = u16::try_from(payload.len()).map_err(|_| Error::InvalidDimensions)?;
    let size = HEADER_BYTES
        .checked_add(coefficients.len())
        .and_then(|n| n.checked_add(payload.len()))
        .ok_or(Error::Arithmetic)?;
    let mut bytes = Vec::with_capacity(size);
    bytes.extend_from_slice(b"FE");
    bytes.extend_from_slice(&[
        1,
        match kind {
            SymbolKind::Systematic => 0,
            SymbolKind::Repair => 1,
        },
        context.direction.wire(),
        0,
    ]);
    bytes.extend_from_slice(&count.to_be_bytes());
    bytes.extend_from_slice(&context.session.0);
    bytes.extend_from_slice(&context.epoch.0.to_be_bytes());
    bytes.extend_from_slice(&context.channel.0.to_be_bytes());
    bytes.extend_from_slice(&generation.0.to_be_bytes());
    bytes.extend_from_slice(&symbol.0.to_be_bytes());
    bytes.extend_from_slice(&width.to_be_bytes());
    bytes.extend_from_slice(&count.to_be_bytes());
    bytes.extend_from_slice(&[0; 4]);
    bytes.extend_from_slice(coefficients);
    bytes.extend_from_slice(payload);
    Ok(EncodedSymbol {
        generation,
        symbol,
        bytes,
    })
}

fn array<const N: usize>(bytes: &[u8], offset: usize) -> Result<[u8; N], Error> {
    bytes
        .get(offset..offset.checked_add(N).ok_or(Error::Arithmetic)?)
        .ok_or(Error::Malformed)?
        .try_into()
        .map_err(|_| Error::Malformed)
}
