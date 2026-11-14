use super::Error;
use crate::{ConfigDigest, Epoch, LaneId, Limits, Protection};
use ring::digest;

/// Untrusted construction input; a spec is not authority or a checked selection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SelectionSpec {
    /// Actual physical lane.
    pub lane: LaneId,
    /// Immutable packet/key limits.
    pub limits: Limits,
    /// Explicit protection; Swift consumers still require AEAD.
    pub protection: Protection,
    /// Fixed control metadata epoch.
    pub control_epoch: Epoch,
    /// Fixed full control digest.
    pub control_digest: ConfigDigest,
    /// Complete caller-validated carrier/resource envelope, excluding setup H0.
    pub envelope_digest: ConfigDigest,
    /// Maximum duration of one accepted exchange.
    pub exchange_micros: u64,
    /// Maximum age beginning at actual confirmed split-key import.
    pub key_micros: u64,
    /// Required receive-key overlap after local activation.
    pub overlap_micros: u64,
    /// Per logical Noise flight, first emission plus exact copies.
    pub max_flight_copies: u32,
}

/// Checked canonical immutable v2 selection; no default or fallback exists.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Selection(SelectionSpec);
impl Selection {
    /// Validate before allocation or cryptographic state creation.
    pub fn new(spec: SelectionSpec) -> Result<Self, Error> {
        spec.limits.validate()?;
        if spec
            .limits
            .max_body_bytes
            .checked_add(super::PREFIX_BYTES + spec.protection.tag_bytes())
            .is_none_or(|bytes| bytes > crate::MAX_PACKET_BYTES)
        {
            return Err(Error::Configuration);
        }
        if spec.exchange_micros == 0
            || spec.key_micros == 0
            || spec.overlap_micros == 0
            || spec.overlap_micros >= spec.exchange_micros
            || spec.overlap_micros >= spec.key_micros
            || spec.max_flight_copies == 0
            || spec.limits.max_body_bytes < 88
        {
            return Err(Error::Configuration);
        }
        Ok(Self(spec))
    }
    /// Copy only the nonsecret checked input values.
    pub const fn spec(self) -> SelectionSpec {
        self.0
    }
    /// Exact 132-byte value, with full integer widths and no rounding.
    pub fn canonical_bytes(self) -> [u8; 132] {
        let s = self.0;
        let mut b = [0; 132];
        b[..4].copy_from_slice(b"L2RS");
        b[4] = 1;
        b[5] = s.protection as u8;
        b[8..12].copy_from_slice(&s.lane.0.to_be_bytes());
        b[12..16].copy_from_slice(&(s.limits.max_body_bytes as u32).to_be_bytes());
        b[16..24].copy_from_slice(&s.limits.packets_per_key.to_be_bytes());
        b[24..32].copy_from_slice(&s.limits.max_body_bytes_per_key.to_be_bytes());
        b[32..40].copy_from_slice(&s.control_epoch.0.to_be_bytes());
        b[40..72].copy_from_slice(&s.control_digest.0);
        b[72..104].copy_from_slice(&s.envelope_digest.0);
        b[104..112].copy_from_slice(&s.exchange_micros.to_be_bytes());
        b[112..120].copy_from_slice(&s.key_micros.to_be_bytes());
        b[120..128].copy_from_slice(&s.overlap_micros.to_be_bytes());
        b[128..132].copy_from_slice(&s.max_flight_copies.to_be_bytes());
        b
    }
    /// Encode without changing a short destination.
    pub fn encode(self, out: &mut [u8]) -> Result<usize, Error> {
        out.get_mut(..132)
            .ok_or(crate::Error::OutputTooSmall)?
            .copy_from_slice(&self.canonical_bytes());
        Ok(132)
    }
    /// Parse the exact canonical value; no trailing bytes or reserved bits.
    pub fn decode(b: &[u8]) -> Result<Self, Error> {
        if b.len() != 132 || &b[..4] != b"L2RS" || b[4] != 1 || b[6..8] != [0, 0] {
            return Err(Error::Configuration);
        }
        let protection = match b[5] {
            1 => Protection::ChaCha20Poly1305,
            2 => Protection::HmacSha256,
            _ => return Err(Error::Configuration),
        };
        let u64_at = |at: usize| -> Result<u64, Error> {
            Ok(u64::from_be_bytes(
                b[at..at + 8].try_into().map_err(|_| Error::Configuration)?,
            ))
        };
        Self::new(SelectionSpec {
            lane: LaneId(u32::from_be_bytes(
                b[8..12].try_into().map_err(|_| Error::Configuration)?,
            )),
            limits: Limits {
                max_body_bytes: u32::from_be_bytes(
                    b[12..16].try_into().map_err(|_| Error::Configuration)?,
                ) as usize,
                packets_per_key: u64_at(16)?,
                max_body_bytes_per_key: u64_at(24)?,
            },
            protection,
            control_epoch: Epoch(u64_at(32)?),
            control_digest: ConfigDigest(b[40..72].try_into().map_err(|_| Error::Configuration)?),
            envelope_digest: ConfigDigest(b[72..104].try_into().map_err(|_| Error::Configuration)?),
            exchange_micros: u64_at(104)?,
            key_micros: u64_at(112)?,
            overlap_micros: u64_at(120)?,
            max_flight_copies: u32::from_be_bytes(
                b[128..132].try_into().map_err(|_| Error::Configuration)?,
            ),
        })
    }
    /// Full SHA-256 of the canonical self-identifying value.
    pub fn digest(self) -> ConfigDigest {
        let mut b = [0; 32];
        b.copy_from_slice(digest::digest(&digest::SHA256, &self.canonical_bytes()).as_ref());
        ConfigDigest(b)
    }
}
