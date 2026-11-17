//! Allocation-free observations of the actual selected recovery grammar.
use super::*;

/// Exact partition of one recovery emission, excluding its enclosing carrier.
/// Observation grants no authentication, admission or physical-send authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecoveryExtent {
    /// Canonically inspected source, systematic, repair or feedback arm.
    pub kind: RecordKind,
    /// Complete recovery emission bytes.
    pub bytes: usize,
    /// Union/identity fields, coefficients, and systematic original-length and
    /// inner ARQ fields. A feedback emission consists entirely of these bytes.
    pub header_bytes: usize,
    /// Exact original codec source, or encoded equation bytes for a repair.
    /// Repair bytes are redundancy, never original native payload or padding.
    pub payload_bytes: usize,
    /// Systematic vector bytes beyond its declared original ARQ source extent.
    pub systematic_coded_fill_bytes: usize,
}

impl Reliable {
    /// Inspect current context-free output without changing recovery state.
    /// The three byte extents partition the complete packet exactly. Existing
    /// contextual formats are explicitly refused; no fallback decoder is used.
    pub fn inspect_output_extent(&self, packet: &[u8]) -> Result<RecoveryExtent, Error> {
        if self.compact_wire.is_none() {
            return Err(Error::InvalidConfig);
        }
        let view = self.selected_inspect(packet, true)?;
        let payload_bytes = match view.kind {
            RecordKind::Source | RecordKind::Systematic => {
                view.source.ok_or(Error::Malformed)?.1.len()
            }
            RecordKind::Repair => view.fec.ok_or(Error::Malformed)?.payload.len(),
            RecordKind::Feedback => 0,
        };
        let systematic_coded_fill_bytes = if view.kind == RecordKind::Systematic {
            let symbol = view.fec.ok_or(Error::Malformed)?;
            let original = selected_wire::original_source(symbol)?;
            symbol
                .payload
                .len()
                .checked_sub(2)
                .and_then(|bytes| bytes.checked_sub(original.len()))
                .ok_or(Error::Malformed)?
        } else {
            0
        };
        let header_bytes = packet
            .len()
            .checked_sub(payload_bytes)
            .and_then(|bytes| bytes.checked_sub(systematic_coded_fill_bytes))
            .ok_or(Error::Malformed)?;
        Ok(RecoveryExtent {
            kind: view.kind,
            bytes: packet.len(),
            header_bytes,
            payload_bytes,
            systematic_coded_fill_bytes,
        })
    }
}
