//! Packed grammar and sender policy over the same Compact R0 endpoint.
use super::*;
use l2tunnel_codec::{packed_envelope, packed_sender};

/// Complete active canonical PackedCompact direction bytes.
pub const CONFIG_BYTES: usize = compact::CONFIG_BYTES + 24;
/// Complete Packed policy with actual R0 recovery and no dummy FEC fields.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Config {
    /// Actual native, receiver, Compact recovery, wire and copy policies.
    pub base: super::CompactConfig,
    /// Original first-unit hold in injected microseconds.
    pub hold_micros: u64,
    /// Maximum complete units per actual packed source.
    pub max_units: u8,
    /// Maximum existing packing attempts per service turn.
    pub work_limit: usize,
}
impl Config {
    pub(super) fn options(self) -> packed::Options {
        packed::Options {
            hold_micros: self.hold_micros,
            max_units: self.max_units,
            work_limit: self.work_limit,
        }
    }
    pub(super) fn sender(self) -> packed_sender::Config {
        self.options().sender(self.base.body())
    }
    /// Exact existing packed envelope; no second parser or source encoding.
    pub fn envelope(self) -> packed_envelope::Config {
        self.sender().envelope()
    }
    /// Validate complete finite packing and real Receiver progress geometry.
    pub fn validate(self) -> Result<(), Error> {
        self.sender()
            .memory_bound_bytes()
            .map_err(Error::PackedSender)?;
        let units = usize::from(self.max_units);
        let r = self.base.receiver;
        r.batch_memory_bound_bytes().map_err(Error::Receiver)?;
        let maximum_record = r
            .max_fragments_per_record
            .checked_mul(r.body.symbol_bytes - 8)
            .ok_or(Error::Configuration)?
            .min(65_535)
            .max(r.body.symbol_bytes - 3);
        if r.lookahead_records < units
            || r.lookahead_bytes
                < units
                    .checked_mul(maximum_record)
                    .ok_or(Error::Configuration)?
            || r.lookahead_fragments
                < units
                    .checked_mul(r.max_fragments_per_record)
                    .ok_or(Error::Configuration)?
            || usize::from(r.record_window) < units
        {
            return Err(Error::Configuration);
        }
        self.base.validate_geometry(
            self.envelope()
                .max_source_bytes()
                .map_err(Error::PackedEnvelope)?,
            units,
        )
    }
    /// Encode the exact273-byte active grammar after complete validation.
    pub fn encode_into(self, output: &mut [u8]) -> Result<(), Error> {
        self.validate()?;
        if output.len() != CONFIG_BYTES {
            return Err(Error::Configuration);
        }
        self.base
            .encode_fields(&mut output[..compact::CONFIG_BYTES])?;
        let mut w = compact::Writer::new(&mut output[compact::CONFIG_BYTES..]);
        w.number(self.hold_micros)?;
        w.number(u64::from(self.max_units))?;
        w.size(self.work_limit)?;
        w.finish()
    }
    /// Decode complete actual fields, rejecting noncanonical durations/bounds.
    pub fn decode(input: &[u8]) -> Result<Self, Error> {
        if input.len() != CONFIG_BYTES {
            return Err(Error::Configuration);
        }
        let base = super::CompactConfig::decode_fields(&input[..compact::CONFIG_BYTES])?;
        let mut r = compact::Reader::new(&input[compact::CONFIG_BYTES..]);
        let value = Self {
            base,
            hold_micros: r.number()?,
            max_units: r.number()?.try_into().map_err(|_| Error::Configuration)?,
            work_limit: r.size()?,
        };
        r.finish()?;
        value.validate()?;
        Ok(value)
    }
    /// Distinct complete PackedCompact policy identity.
    pub fn digest(self) -> Result<ConfigDigest, Error> {
        let mut bytes = [0; CONFIG_BYTES];
        self.encode_into(&mut bytes)?;
        Ok(compact::hash_fields(
            b"l2tunnel/packed-envelope-v1/compact-r0-v2/config-v1\0",
            &bytes,
        ))
    }
}
