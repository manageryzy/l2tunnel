//! Selected source body with trusted outer scope and recovery source identity.
use super::*;
use crate::aligned_receiver::SourceId;
use source_identity::{read_varint, varint_len, write_varint};

/// Encode the full record identity and exact meaningful unit without duplicate scope.
/// The authenticated outer context and recovery branch carry scope and source.
/// Failure never mutates caller output or advances source ownership.
pub fn encode_compact(
    identity: SymbolIdentity,
    symbol_bytes: usize,
    symbol: &[u8],
    output: &mut [u8],
) -> Result<usize, Error> {
    if identity.scope.session == [0; 16] || !(9..=65535).contains(&symbol_bytes) {
        return Err(Error::Configuration);
    }
    validate_unit(symbol, symbol_bytes)?;
    if u16::from_be_bytes([symbol[1], symbol[2]]) != identity.record.0 as u16 {
        return Err(Error::Malformed);
    }
    let header = varint_len(identity.record.0);
    let needed = header + symbol.len();
    if output.len() < needed {
        return Err(Error::OutputTooSmall { needed });
    }
    write_varint(identity.record.0, output);
    output[header..needed].copy_from_slice(symbol);
    Ok(needed)
}

/// Validate a selected source body using the already authenticated outer context.
/// No trial parsing or legacy-format fallback is performed.
pub fn decode_compact(
    expected: Scope,
    source: SourceId,
    symbol_bytes: usize,
    channels: u16,
    input: &[u8],
) -> Result<View<'_>, Error> {
    if expected.session == [0; 16]
        || !(9..=65535).contains(&symbol_bytes)
        || !(1..=256).contains(&channels)
    {
        return Err(Error::Configuration);
    }
    let (record, header) = read_varint(input).map_err(header_error)?;
    let symbol = input.get(header..).ok_or(Error::Malformed)?;
    validate_unit(symbol, symbol_bytes)?;
    if u16::from(symbol[0]) >= channels
        || u16::from_be_bytes([symbol[1], symbol[2]]) != record as u16
    {
        return Err(Error::Malformed);
    }
    Ok(View {
        identity: SymbolIdentity {
            scope: expected,
            source,
            record: RecordId(record),
        },
        symbol,
    })
}

// Context-dependent payload lengths are checked later by the receiver's exact
// body decoder. Never zero-extend this slice before that semantic check.
pub(crate) fn validate_unit(symbol: &[u8], symbol_bytes: usize) -> Result<(), Error> {
    crate::packed::validate_aligned_unit(symbol, symbol_bytes).map_err(|_| Error::Malformed)?;
    if symbol[3] == 4 && usize::from(u16::from_be_bytes([symbol[4], symbol[5]])) <= symbol_bytes - 3
    {
        return Err(Error::Malformed);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::aligned_receiver::Direction;
    use l2tunnel_core::Epoch;

    fn scope() -> Scope {
        Scope {
            session: [5; 16],
            epoch: Epoch(9),
            direction: Direction::InitiatorToResponder,
        }
    }
    fn identity(record: u64) -> SymbolIdentity {
        SymbolIdentity {
            scope: scope(),
            source: SourceId(u64::MAX),
            record: RecordId(record),
        }
    }
    #[test]
    fn compact_exact_units_preserve_ids_zero_tails_and_canonical_bounds()
    -> Result<(), Box<dyn std::error::Error>> {
        for record in [0, 127, 128, 65536, u64::MAX] {
            let identity = identity(record);
            let mut unit = [0u8; 14];
            unit[0] = 1;
            unit[1..3].copy_from_slice(&(record as u16).to_be_bytes());
            unit[3] = 2;
            unit[4..6].copy_from_slice(&8u16.to_be_bytes());
            unit[6..9].copy_from_slice(&[1, 2, 3]);
            let mut output = [0xa5; 176];
            let length = encode_compact(identity, 128, &unit, &mut output)?;
            let view = decode_compact(scope(), identity.source, 128, 2, &output[..length])?;
            assert_eq!(view.identity, identity);
            assert_eq!(view.symbol, unit);
            assert_eq!(length, varint_len(record) + unit.len());
            assert!(output[length..].iter().all(|byte| *byte == 0xa5));
            for end in 0..length {
                assert!(decode_compact(scope(), identity.source, 128, 2, &output[..end]).is_err());
            }
            let mut padded = output[..length].to_vec();
            padded.push(0);
            assert_eq!(
                decode_compact(scope(), identity.source, 128, 2, &padded),
                Err(Error::Malformed)
            );
            let mut short = vec![0xa5; length - 1];
            assert_eq!(
                encode_compact(identity, 128, &unit, &mut short),
                Err(Error::OutputTooSmall { needed: length })
            );
            assert!(short.iter().all(|byte| *byte == 0xa5));
        }
        for malformed in [
            &[0x80, 0][..],
            &[0xff; 10][..],
            &[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 2][..],
        ] {
            assert!(decode_compact(scope(), SourceId(0), 128, 2, malformed).is_err());
        }
        Ok(())
    }
    #[test]
    fn compact_minimum_predictive_unit_keeps_aligned_channel_255()
    -> Result<(), Box<dyn std::error::Error>> {
        let unit = [255, 0, 0, 5];
        let mut output = [0xa5; 32];
        let length = encode_compact(identity(0), 128, &unit, &mut output)?;
        assert_eq!(length, 5);
        assert_eq!(
            decode_compact(scope(), SourceId(0), 128, 256, &output[..length])?.symbol,
            unit
        );
        assert_eq!(
            decode_compact(scope(), SourceId(0), 128, 255, &output[..length]),
            Err(Error::Malformed)
        );
        assert_eq!(
            crate::packed::validate_unit(&unit, 128),
            Err(crate::packed::Error::Malformed)
        );
        for end in 0..unit.len() {
            let original = output;
            assert!(encode_compact(identity(0), 128, &unit[..end], &mut output).is_err());
            assert_eq!(output, original);
        }
        for unit in [
            &[0, 0, 0, 6][..],
            &[0, 0, 0, 6, 1, 0x80][..],
            &[0, 0, 0, 0x87][..],
        ] {
            assert_eq!(
                encode_compact(identity(0), 128, unit, &mut output),
                Err(Error::Malformed)
            );
        }
        Ok(())
    }
    #[test]
    fn compact_fragments_require_exact_extent_and_configured_stride()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut last = [0u8; 9];
        last[3] = 4;
        last[4..6].copy_from_slice(&17u16.to_be_bytes());
        last[6..8].copy_from_slice(&16u16.to_be_bytes());
        let mut output = [0xa5; 32];
        let length = encode_compact(identity(0), 16, &last, &mut output)?;
        assert_eq!(length, 10);
        assert_eq!(
            decode_compact(scope(), SourceId(0), 16, 1, &output[..length])?.symbol,
            last
        );
        for malformed in [last[..8].to_vec(), [last.as_slice(), &[0]].concat()] {
            assert_eq!(
                encode_compact(identity(0), 16, &malformed, &mut output),
                Err(Error::Malformed)
            );
        }
        last[7] = 15;
        assert_eq!(
            encode_compact(identity(0), 16, &last, &mut output),
            Err(Error::Malformed)
        );
        last[4..6].copy_from_slice(&1u16.to_be_bytes());
        last[6..8].fill(0);
        assert_eq!(
            encode_compact(identity(0), 16, &last, &mut output),
            Err(Error::Malformed)
        );
        Ok(())
    }
}
