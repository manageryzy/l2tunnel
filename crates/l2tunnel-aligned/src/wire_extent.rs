//! Structural measurements only; no decoder context, native admission or receipt.
use super::*;
use l2tunnel_codec::packed_envelope;
use l2tunnel_reliable::RecoveryExtent;

/// Exact partition of a selected codec source before body interpretation.
/// Body fields, compression gain and original native packet lengths are not
/// attributed here. Fragment bodies remain opaque, even when their prefix is seen.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CodecEnvelopeExtent {
    /// Complete source passed to recovery.
    pub bytes: usize,
    /// Absolute identity/count fields outside the original packed payload.
    pub envelope_bytes: usize,
    /// Multiunit container discriminator/count/length fields; zero for one unit.
    pub container_bytes: usize,
    /// Three channel/serial bytes per actual codec unit.
    pub unit_header_bytes: usize,
    /// Remaining codec bodies, including compression/context/fragment fields.
    pub body_bytes: usize,
    /// Actual codec unit count; not a native-packet or recovered-source count.
    pub units: usize,
    /// Units carrying fragments, whose complete body attribution is unsupported.
    pub fragmented_units: usize,
}

/// Exact selected recovery and, when present, original codec-source extents.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OutputExtent {
    /// Complete source/repair/control recovery partition.
    pub recovery: RecoveryExtent,
    /// Present only for source/systematic records, never repair or feedback.
    pub codec: Option<CodecEnvelopeExtent>,
}

/// Inspect the existing canonical compact packed envelope without an owner or
/// allocation. Externally supplied scope confers no authentication authority.
pub fn inspect_packed(
    config: packed_envelope::Config,
    scope: receiver::Scope,
    source: receiver::SourceId,
    bytes: &[u8],
) -> Result<CodecEnvelopeExtent, packed_envelope::Error> {
    let view = packed_envelope::decode_compact(config, scope, source, bytes)?;
    let mut unit_bytes = 0usize;
    let mut fragmented_units = 0usize;
    for unit in view.units()? {
        unit_bytes = unit_bytes
            .checked_add(unit.bytes.len())
            .ok_or(packed_envelope::Error::Malformed)?;
        if unit.bytes.get(3) == Some(&4) {
            fragmented_units += 1;
        }
    }
    let unit_header_bytes = view
        .len()
        .checked_mul(3)
        .ok_or(packed_envelope::Error::Malformed)?;
    Ok(CodecEnvelopeExtent {
        bytes: bytes.len(),
        envelope_bytes: bytes
            .len()
            .checked_sub(view.payload().len())
            .ok_or(packed_envelope::Error::Malformed)?,
        container_bytes: view
            .payload()
            .len()
            .checked_sub(unit_bytes)
            .ok_or(packed_envelope::Error::Malformed)?,
        unit_header_bytes,
        body_bytes: unit_bytes
            .checked_sub(unit_header_bytes)
            .ok_or(packed_envelope::Error::Malformed)?,
        units: view.len(),
        fragmented_units,
    })
}

impl Endpoint {
    /// Inspect actual outgoing selected bytes using the maintained recovery and
    /// envelope parsers. This neither consumes output nor decodes native content.
    pub fn inspect_output_extent(&self, packet: &[u8]) -> Result<OutputExtent, Error> {
        if !self.compact_wire {
            return Err(Error::Configuration);
        }
        let recovery = self
            .recovery
            .inspect_output_extent(packet)
            .map_err(Error::Recovery)?;
        let view = self
            .recovery
            .inspect_output_record(packet)
            .map_err(Error::Recovery)?;
        let codec = if let Some((source, bytes)) = view.source {
            let source = receiver::SourceId(source.0);
            Some(if let Some(options) = self.packing {
                inspect_packed(
                    options.envelope(self.config),
                    self.send_scope,
                    source,
                    bytes,
                )
                .map_err(Error::PackedEnvelope)?
            } else {
                let view = compact_wire::aligned(
                    true,
                    self.send_scope,
                    source,
                    self.config.receiver,
                    bytes,
                )
                .map_err(Error::Envelope)?;
                CodecEnvelopeExtent {
                    bytes: bytes.len(),
                    envelope_bytes: bytes
                        .len()
                        .checked_sub(view.symbol.len())
                        .ok_or(Error::Configuration)?,
                    container_bytes: 0,
                    unit_header_bytes: 3,
                    body_bytes: view
                        .symbol
                        .len()
                        .checked_sub(3)
                        .ok_or(Error::Configuration)?,
                    units: 1,
                    fragmented_units: usize::from(view.symbol.get(3) == Some(&4)),
                }
            })
        } else {
            None
        };
        Ok(OutputExtent { recovery, codec })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use l2tunnel_codec::packed::{Config, Packer};
    use l2tunnel_core::Epoch;

    #[test]
    fn packed_extent_partitions_real_units_without_counting_zero_payload_as_padding()
    -> Result<(), Box<dyn std::error::Error>> {
        let scope = receiver::Scope {
            session: [7; 16],
            epoch: Epoch(9),
            direction: receiver::Direction::InitiatorToResponder,
        };
        let config = packed_envelope::Config {
            symbol_bytes: 64,
            channels: 2,
            max_units: 4,
        };
        let identity = packed_envelope::Identity {
            scope,
            source: receiver::SourceId(0),
            first_unit: receiver::SourceId(0),
        };
        let mut packing = Packer::new(Config {
            symbol_bytes: 64,
            hold_micros: 10,
        })?;
        let units = [[0, 0, 7, 2, 0, 3, 9, 0, 0], [0, 0, 8, 2, 0, 3, 8, 0, 0]];
        for unit in &units {
            packing.push(unit, 1, 0)?;
        }
        packing.flush();
        let payload = packing.pending().ok_or("actual packed source")?.payload;
        let mut bytes = [0; 128];
        let length = packed_envelope::encode_compact(
            config,
            identity,
            &[receiver::RecordId(7), receiver::RecordId(8)],
            payload,
            &mut bytes,
        )?;
        let extent = inspect_packed(config, scope, identity.source, &bytes[..length])?;
        assert_eq!(
            (
                extent.envelope_bytes,
                extent.container_bytes,
                extent.unit_header_bytes,
                extent.body_bytes
            ),
            (5, 6, 6, 12)
        );
        assert_eq!(
            (extent.bytes, extent.units, extent.fragmented_units),
            (29, 2, 0)
        );
        for end in 0..length {
            assert!(inspect_packed(config, scope, identity.source, &bytes[..end]).is_err());
        }
        let mut fragmented = [0; 64];
        fragmented[..8].copy_from_slice(&[0, 0, 7, 4, 0, 80, 0, 0]);
        let length = packed_envelope::encode_compact(
            config,
            identity,
            &[receiver::RecordId(7)],
            &fragmented,
            &mut bytes,
        )?;
        let extent = inspect_packed(config, scope, identity.source, &bytes[..length])?;
        assert_eq!(
            (
                extent.envelope_bytes,
                extent.container_bytes,
                extent.unit_header_bytes,
                extent.body_bytes
            ),
            (4, 0, 3, 61)
        );
        assert_eq!((extent.units, extent.fragmented_units), (1, 1));
        Ok(())
    }
}
