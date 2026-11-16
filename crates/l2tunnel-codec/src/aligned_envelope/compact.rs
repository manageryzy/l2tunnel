//! Selected source body with trusted outer scope and recovery source identity.
use super::*;
use crate::aligned_receiver::SourceId;
use source_identity::{read_varint, varint_len, write_varint};

/// Encode the full record identity and unchanged symbol without duplicate scope.
/// The authenticated outer context and recovery branch carry scope and source.
/// Failure never mutates caller output or advances source ownership.
pub fn encode_compact(
    identity: SymbolIdentity,
    symbol: &[u8],
    output: &mut [u8],
) -> Result<usize, Error> {
    if identity.scope.session == [0; 16] || !(9..=65535).contains(&symbol.len()) {
        return Err(Error::Configuration);
    }
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
    if input.len() != header + symbol_bytes {
        return Err(Error::Malformed);
    }
    let symbol = &input[header..];
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::aligned_receiver::Direction;
    use l2tunnel_core::Epoch;

    #[test]
    fn full_record_ids_canonical_bounds_and_unchanged_symbols()
    -> Result<(), Box<dyn std::error::Error>> {
        let scope = Scope {
            session: [5; 16],
            epoch: Epoch(9),
            direction: Direction::InitiatorToResponder,
        };
        for record in [0, 127, 128, 65536, u64::MAX] {
            let identity = SymbolIdentity {
                scope,
                source: SourceId(u64::MAX),
                record: RecordId(record),
            };
            let mut symbol = [0x35; 128];
            symbol[0] = 1;
            symbol[1..3].copy_from_slice(&(record as u16).to_be_bytes());
            let mut output = [0xa5; 176];
            let length = encode_compact(identity, &symbol, &mut output)?;
            let view = decode_compact(scope, identity.source, symbol.len(), 2, &output[..length])?;
            assert_eq!(view.identity, identity);
            assert_eq!(view.symbol, symbol);
            assert_eq!(length, varint_len(record) + symbol.len());
            for end in 0..length {
                assert!(
                    decode_compact(scope, identity.source, symbol.len(), 2, &output[..end])
                        .is_err()
                );
            }
            let mut short = vec![0xa5; length - 1];
            assert_eq!(
                encode_compact(identity, &symbol, &mut short),
                Err(Error::OutputTooSmall { needed: length })
            );
            assert!(short.iter().all(|byte| *byte == 0xa5));
        }
        for malformed in [
            &[0x80, 0][..],
            &[0xff; 10][..],
            &[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 2][..],
        ] {
            assert!(decode_compact(scope, SourceId(0), 128, 2, malformed).is_err());
        }
        Ok(())
    }
}
