//! Allocation-free scalar observations of locally emitted current-format bytes.
use super::*;
use aligned::wire_extent::CodecEnvelopeExtent;
use l2tunnel_reliable::{RecordKind, RecoveryExtent};

/// Explicit limits of codec attribution; none claims native compression gain.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CodecCoverage {
    /// Exact envelope/container/unit headers, with codec bodies left unattributed.
    EnvelopeOnly,
    /// Exact outer codec extents, but some units contain fragments of bodies.
    FragmentedUnits,
    /// Swift source chunks may split packed lengths and native codec bodies.
    SwiftStream,
    /// An outer fragment cannot be inspected as a whole inner recovery record.
    FragmentedRecord,
    /// Repair equations and feedback contain no attributable original codec unit.
    NotApplicable,
    /// Complete source-free native bytes, without the selected recovery/codec.
    UnencodedNative,
}

/// Scalar partition of a selected output, before Records protection and carrier.
/// Count this observation only after the caller's actual whole-send acceptance.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OutputExtent {
    /// Actual emitted algorithm bytes, including route or outer fragmentation.
    pub bytes: usize,
    /// Actual source/repair/feedback branch, not authentication authority.
    pub kind: EmissionKind,
    /// Selected independent-owner route bytes, separate from recovery framing.
    pub route_header_bytes: usize,
    /// Actual outer fragment header, when the supplied emission is fragmented.
    pub fragment_header_bytes: usize,
    /// Exact recovery fields and original source/equation/fill partition.
    /// Absent for outer fragments and source-free native bypass.
    pub recovery: Option<RecoveryExtent>,
    /// Exact source envelope/container/unit extents, excluding codec body meaning.
    pub codec: Option<CodecEnvelopeExtent>,
    /// Why complete codec/native attribution is not provided.
    pub codec_coverage: CodecCoverage,
}

impl Engine {
    /// Inspect locally emitted bytes with their retained producing metadata.
    /// `fragmented` must come from the actual fragment emission, never content
    /// sniffing. Fragment results validate only the existing structural header;
    /// no admission, scope authority or native-content claim is made. All whole
    /// records use their actual outgoing owner/parser and verify `kind`.
    pub fn inspect_output_extent(
        &self,
        bytes: &[u8],
        kind: EmissionKind,
        fragmented: bool,
    ) -> Result<OutputExtent, Error> {
        if !self.is_compact_wire() {
            return Err(Error::Configuration);
        }
        let mut value = OutputExtent {
            bytes: bytes.len(),
            kind,
            route_header_bytes: 0,
            fragment_header_bytes: 0,
            recovery: None,
            codec: None,
            codec_coverage: CodecCoverage::NotApplicable,
        };
        if fragmented {
            crate::codec::inspect_fragment_context(bytes).map_err(Error::Fragment)?;
            value.fragment_header_bytes = crate::codec::FRAGMENT_HEADER_BYTES;
            value.codec_coverage = CodecCoverage::FragmentedRecord;
            return Ok(value);
        }
        let nested = match &self.owner {
            Owner::Aligned(owner) => {
                Some(owner.inspect_output_extent(bytes).map_err(Error::Aligned)?)
            }
            Owner::Packed(owner) => {
                Some(owner.inspect_output_extent(bytes).map_err(Error::Aligned)?)
            }
            Owner::Rolling(owner) => {
                Some(owner.inspect_output_extent(bytes).map_err(Error::Rolling)?)
            }
            Owner::Research(owner) => {
                Some(owner.inspect_output_extent(bytes).map_err(Error::Rolling)?)
            }
            Owner::Connections(owner) => {
                let (route, extent) = owner
                    .collection
                    .inspect_output_extent(bytes)
                    .map_err(Error::Connections)?;
                value.route_header_bytes = route.compact_bytes();
                if extent.is_none() {
                    if kind != EmissionKind::UnreliableNative {
                        return Err(Error::Kind);
                    }
                    value.codec_coverage = CodecCoverage::UnencodedNative;
                }
                extent
            }
            Owner::Swift(_) => {
                if self.inspect_swift_direction(bytes, true)? != kind {
                    return Err(Error::Kind);
                }
                let (header_bytes, recovery_kind) = match kind {
                    EmissionKind::Source(SourceForm::Swift) => {
                        (swift::SOURCE_HEADER, RecordKind::Source)
                    }
                    EmissionKind::Repair => (swift::REPAIR_HEADER, RecordKind::Repair),
                    EmissionKind::Feedback => (bytes.len(), RecordKind::Feedback),
                    _ => return Err(Error::Kind),
                };
                value.recovery = Some(RecoveryExtent {
                    kind: recovery_kind,
                    bytes: bytes.len(),
                    header_bytes,
                    // A Swift repair includes its two coded length bytes in
                    // the equation, not as original-source/native payload.
                    payload_bytes: bytes
                        .len()
                        .checked_sub(header_bytes)
                        .ok_or(Error::Arithmetic)?,
                    systematic_coded_fill_bytes: 0,
                });
                if recovery_kind == RecordKind::Source {
                    value.codec_coverage = CodecCoverage::SwiftStream;
                }
                None
            }
        };
        if let Some(extent) = nested {
            if owner::emission_kind(extent.recovery.kind) != kind
                || extent.recovery.bytes.checked_add(value.route_header_bytes) != Some(bytes.len())
            {
                return Err(Error::Kind);
            }
            value.codec_coverage = match extent.codec {
                Some(codec) if codec.fragmented_units != 0 => CodecCoverage::FragmentedUnits,
                Some(_) => CodecCoverage::EnvelopeOnly,
                None => CodecCoverage::NotApplicable,
            };
            value.recovery = Some(extent.recovery);
            value.codec = extent.codec;
        }
        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec;

    #[test]
    fn output_extent_keeps_swift_stream_and_outer_fragment_attribution_explicit()
    -> Result<(), Box<dyn std::error::Error>> {
        let config = super::super::tests::fixture(super::super::tests::Family::Swift, true)?;
        let mut engine = Engine::new_functional(
            config,
            super::super::tests::context(Role::Client),
            super::super::tests::geometry(),
            NativeLimits { stall_micros: 1000 },
        )?;
        engine.enable_compact_wire(49)?;
        let kind = EmissionKind::Source(SourceForm::Swift);
        // Local data has three channels; the opposite direction has only two.
        let source = [8, 0, 0, 0, 0, 9, 0, 0];
        let value = engine.inspect_output_extent(&source, kind, false)?;
        let recovery = value.recovery.ok_or("exact Swift recovery extent")?;
        assert_eq!((recovery.header_bytes, recovery.payload_bytes), (5, 3));
        assert_eq!(value.codec_coverage, CodecCoverage::SwiftStream);
        assert_eq!(value.codec, None);
        assert!(
            engine
                .inspect_output_extent(&source, EmissionKind::Repair, false)
                .is_err()
        );
        assert!(engine.inspect_output_extent(&[], kind, false).is_err());
        let mut feedback = [0; swift::FEEDBACK_HEADER];
        feedback[0] = swift::KIND_FEEDBACK;
        let value = engine.inspect_output_extent(&feedback, EmissionKind::Feedback, false)?;
        let recovery = value.recovery.ok_or("exact Swift control extent")?;
        assert_eq!(
            (recovery.header_bytes, recovery.payload_bytes),
            (feedback.len(), 0)
        );
        feedback[0] |= 2 << 2;
        assert!(
            engine
                .inspect_output_extent(&feedback, EmissionKind::Feedback, false)
                .is_err()
        );
        let mut fragmenter = codec::Fragmenter::new(
            codec::FragmentContext {
                session: codec::SessionId(7),
                epoch: l2tunnel_core::Epoch(7),
            },
            codec::FragmentConfig {
                path_mtu: 100,
                outer_overhead_bytes: 17,
                max_message_bytes: 100,
                max_fragments: 4,
            },
            codec::MessageId(0),
        )?;
        let batch = fragmenter.fragment(&[0; 60])?;
        let fragment = batch.fragments.first().ok_or("actual fragment")?;
        let value = engine.inspect_output_extent(fragment, kind, true)?;
        assert_eq!(value.fragment_header_bytes, codec::FRAGMENT_HEADER_BYTES);
        assert_eq!(value.codec_coverage, CodecCoverage::FragmentedRecord);
        assert_eq!(value.recovery, None);
        assert_eq!(value.codec, None);
        assert!(
            engine
                .inspect_output_extent(&fragment[..39], kind, true)
                .is_err()
        );
        Ok(())
    }
}
