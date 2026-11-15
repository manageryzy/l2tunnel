//! Complete directional source-copy selection; callers authenticate it before use.
use super::*;
use crate::{core::ConfigDigest, management::Role};
use codec::source_copy::{Policy, Scope};

/// Canonical bytes for both complete global source-copy policies.
pub const COPY_POLICY_BYTES: usize = 20;

/// Global directions, never a locally inferred symmetric fallback.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CopyPolicies {
    /// Initiator/client to responder/server source-copy selection.
    pub forward: Policy,
    /// Responder/server to initiator/client source-copy selection.
    pub reverse: Policy,
}
impl CopyPolicies {
    /// Exact old one-copy behavior and old stream binding.
    pub const ONE: Self = Self {
        forward: Policy::ONE,
        reverse: Policy::ONE,
    };
    /// Validate against each actual directional packer's meaningful symbol width.
    pub fn validate(self, config: Config) -> Result<(), Error> {
        config.validate()?;
        for (policy, direction) in [
            (self.forward, config.forward),
            (self.reverse, config.reverse),
        ] {
            policy
                .validate(direction.packing.packing.symbol_bytes)
                .map_err(|error| Error::Sender(packed_sender::Error::Copies(error)))?;
        }
        Ok(())
    }
    /// Exact fixed-width big-endian thresholds/counts/scope tags in global order.
    /// This is public policy data, not authentication or a selected wire version.
    pub fn canonical_bytes(self) -> Result<[u8; COPY_POLICY_BYTES], Error> {
        let mut bytes = [0; COPY_POLICY_BYTES];
        for (index, policy) in [self.forward, self.reverse].into_iter().enumerate() {
            if !(1..=4).contains(&policy.copies) {
                return Err(Error::Configuration);
            }
            let start = index * 10;
            bytes[start..start + 8].copy_from_slice(
                &u64::try_from(policy.max_unit_bytes)
                    .map_err(|_| Error::Arithmetic)?
                    .to_be_bytes(),
            );
            bytes[start + 8] = policy.copies;
            bytes[start + 9] = match policy.scope {
                Scope::AllShort => 1,
                Scope::ContextAndIndependent => 2,
            };
        }
        Ok(bytes)
    }
    /// Preserve the exact legacy binding for ONE; commit both selected policies otherwise.
    /// An enclosing authenticated configuration must also select this policy.
    pub fn binding_digest(self, config: Config, stream: u32) -> Result<ConfigDigest, Error> {
        self.validate(config)?;
        let base = config.binding_digest(stream)?;
        if self == Self::ONE {
            return Ok(base);
        }
        let mut hash = ring::digest::Context::new(&ring::digest::SHA256);
        hash.update(b"l2tunnel/rolling-records/source-copies/v1\0");
        hash.update(&base.0);
        hash.update(&self.canonical_bytes()?);
        Ok(ConfigDigest(
            hash.finish()
                .as_ref()
                .try_into()
                .map_err(|_| Error::Arithmetic)?,
        ))
    }
    pub(super) fn local(self, role: Role) -> Policy {
        match role {
            Role::Client => self.forward,
            Role::Server => self.reverse,
        }
    }
}
impl Default for CopyPolicies {
    fn default() -> Self {
        Self::ONE
    }
}
