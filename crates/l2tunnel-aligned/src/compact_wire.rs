//! Explicit final-wire selection on the existing codec and recovery owners.
use super::*;
use l2tunnel_codec::packed_envelope;

impl Endpoint {
    /// Select compact source metadata and recovery headers before admitting data.
    /// Data uses the existing configured overhead; feedback uses the supplied
    /// full strong-authentication overhead. Existing constructors retain v1 bytes.
    pub fn enable_compact_wire(&mut self, feedback_overhead: usize) -> Result<(), Error> {
        self.enable_compact_wire_with_overheads(self.config.outer_overhead_bytes, feedback_overhead)
    }
    /// Select final data and feedback charges without rewriting the canonical
    /// policy. This supports a shorter authenticated enclosing route as well.
    pub fn enable_compact_wire_with_overheads(
        &mut self,
        data_overhead: usize,
        feedback_overhead: usize,
    ) -> Result<(), Error> {
        self.validate_compact_wire_selection(data_overhead, feedback_overhead)?;
        self.recovery
            .enable_compact_wire_with_overheads(data_overhead, feedback_overhead)
            .map_err(Error::Recovery)?;
        if self.receive_packing.is_none() {
            self.receiver
                .enable_compact_units()
                .map_err(Error::Receiver)?;
        }
        self.compact_wire = true;
        self.compact_data_overhead = data_overhead;
        Ok(())
    }
    /// Pure preflight for an enclosing collection's atomic format installation.
    pub fn validate_compact_wire_selection(
        &self,
        data_overhead: usize,
        feedback_overhead: usize,
    ) -> Result<(), Error> {
        if self.compact_wire || self.now != Duration::ZERO || !self.drained() {
            return Err(Error::Configuration);
        }
        if self.receive_packing.is_none() {
            self.receiver
                .validate_compact_units_selection()
                .map_err(Error::Receiver)?;
        }
        self.recovery
            .validate_compact_wire_selection(data_overhead, feedback_overhead)
            .map_err(Error::Recovery)
    }
}

pub(super) fn aligned(
    compact: bool,
    scope: receiver::Scope,
    source: receiver::SourceId,
    limits: receiver::Limits,
    input: &[u8],
) -> Result<envelope::View<'_>, envelope::Error> {
    if compact {
        envelope::decode_compact(
            scope,
            source,
            limits.body.symbol_bytes,
            limits.channels,
            input,
        )
    } else {
        envelope::decode(scope, limits.body.symbol_bytes, limits.channels, input)
    }
}

pub(super) fn packed(
    compact: bool,
    config: packed_envelope::Config,
    scope: receiver::Scope,
    source: receiver::SourceId,
    input: &[u8],
) -> Result<packed_envelope::View<'_>, packed_envelope::Error> {
    if compact {
        packed_envelope::decode_compact(config, scope, source, input)
    } else {
        packed_envelope::decode(config, scope, input)
    }
}
