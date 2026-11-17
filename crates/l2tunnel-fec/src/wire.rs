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
    /// Exactly coded_bytes payload bytes for the regular symbol API. The explicit
    /// compact-extent API permits a systematic's exact length-prefixed source.
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
    let size = HEADER_BYTES
        .checked_add(coefficients.len())
        .and_then(|n| n.checked_add(payload.len()))
        .ok_or(Error::Arithmetic)?;
    let mut bytes = vec![0; size];
    encode_into(
        context,
        generation,
        symbol,
        kind,
        coefficients,
        payload,
        &mut bytes,
    )?;
    Ok(EncodedSymbol {
        generation,
        symbol,
        bytes,
    })
}

pub(crate) fn encode_into(
    context: FecContext,
    generation: GenerationId,
    symbol: SymbolId,
    kind: SymbolKind,
    coefficients: &[u8],
    payload: &[u8],
    output: &mut [u8],
) -> Result<usize, Error> {
    let count = u16::try_from(coefficients.len()).map_err(|_| Error::InvalidDimensions)?;
    let width = u16::try_from(payload.len()).map_err(|_| Error::InvalidDimensions)?;
    let size = HEADER_BYTES
        .checked_add(coefficients.len())
        .and_then(|n| n.checked_add(payload.len()))
        .ok_or(Error::Arithmetic)?;
    if output.len() < size {
        return Err(Error::OutputTooSmall { required: size });
    }
    output[..HEADER_BYTES].fill(0);
    output[..2].copy_from_slice(b"FE");
    output[2] = 1;
    output[3] = match kind {
        SymbolKind::Systematic => 0,
        SymbolKind::Repair => 1,
    };
    output[4] = context.direction.wire();
    output[6..8].copy_from_slice(&count.to_be_bytes());
    output[8..24].copy_from_slice(&context.session.0);
    output[24..32].copy_from_slice(&context.epoch.0.to_be_bytes());
    output[32..36].copy_from_slice(&context.channel.0.to_be_bytes());
    output[36..44].copy_from_slice(&generation.0.to_be_bytes());
    output[44..48].copy_from_slice(&symbol.0.to_be_bytes());
    output[48..50].copy_from_slice(&width.to_be_bytes());
    output[50..52].copy_from_slice(&count.to_be_bytes());
    output[HEADER_BYTES..HEADER_BYTES + coefficients.len()].copy_from_slice(coefficients);
    output[HEADER_BYTES + coefficients.len()..size].copy_from_slice(payload);
    Ok(size)
}

fn array<const N: usize>(bytes: &[u8], offset: usize) -> Result<[u8; N], Error> {
    bytes
        .get(offset..offset.checked_add(N).ok_or(Error::Arithmetic)?)
        .ok_or(Error::Malformed)?
        .try_into()
        .map_err(|_| Error::Malformed)
}

impl<'a> SymbolView<'a> {
    /// Borrow the exact original systematic bytes through the same canonical
    /// length/tail validator used by decoding. Repair equations have no source.
    pub fn original_source(self) -> Result<&'a [u8], Error> {
        if self.kind != SymbolKind::Systematic {
            return Err(Error::Malformed);
        }
        let length = crate::original_length(self.payload)?;
        let end = length.checked_add(2).ok_or(Error::Arithmetic)?;
        self.payload.get(2..end).ok_or(Error::InvalidSource)
    }

    /// Validate typed input independently of its enclosing authenticated wire context.
    pub fn validate(self, config: BlockConfig) -> Result<(), Error> {
        self.validate_extent(config, false)
    }

    /// Validate an explicitly selected exact-systematic wire extent. Systematic
    /// bytes end at their original-length prefix; only their absent algebraic
    /// tail is zero. Repairs still carry every byte of the declared coded width.
    /// This never accepts truncated source content or a padded systematic alias.
    pub fn validate_compact_extent(self, config: BlockConfig) -> Result<(), Error> {
        self.validate_extent(config, true)
    }

    fn validate_extent(self, config: BlockConfig, compact: bool) -> Result<(), Error> {
        config.validate()?;
        config.dimensions(self.source_count, self.coded_bytes)?;
        let exact_systematic = compact && self.kind == SymbolKind::Systematic;
        if self.coefficients.len() != self.source_count
            || if exact_systematic {
                self.payload.len() > self.coded_bytes
            } else {
                self.payload.len() != self.coded_bytes
            }
        {
            return Err(Error::Malformed);
        }
        if self
            .coefficients
            .iter()
            .all(|&coefficient| coefficient == 0)
        {
            return Err(Error::InvalidCoefficients);
        }
        match self.kind {
            SymbolKind::Systematic => {
                if u64::from(self.symbol.0) >= self.source_count as u64
                    || self.coefficients.iter().enumerate().any(|(index, &value)| {
                        value != u8::from(index as u64 == u64::from(self.symbol.0))
                    })
                {
                    return Err(Error::InvalidCoefficients);
                }
                let length = crate::original_length(self.payload)?;
                if exact_systematic
                    && length.checked_add(2).ok_or(Error::Arithmetic)? != self.payload.len()
                {
                    return Err(Error::InvalidSource);
                }
            }
            SymbolKind::Repair if u64::from(self.symbol.0) < self.source_count as u64 => {
                return Err(Error::Malformed);
            }
            SymbolKind::Repair => {}
        }
        Ok(())
    }
}
