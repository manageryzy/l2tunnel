//! Strict bounded local flow identities; parsing grants no peer authority.
use super::*;
use l2tunnel::packet::FlowKey;
use std::{fmt, io};

/// Exact maintained canonical FlowKey, encoded as at most124 lowercase hex bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CanonicalFlowKey(FlowKey);
impl CanonicalFlowKey {
    /// Check the one maintained canonical inverse, without a second classifier.
    pub fn parse(text: &str) -> io::Result<Self> {
        if text.is_empty()
            || text.len() > 124
            || !text.len().is_multiple_of(2)
            || !text
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "flow key requires bounded lowercase canonical hex",
            ));
        }
        let mut bytes = [0; 62];
        let nibble = |b: u8| if b <= b'9' { b - b'0' } else { b - b'a' + 10 };
        for (out, pair) in bytes.iter_mut().zip(text.as_bytes().chunks_exact(2)) {
            *out = (nibble(pair[0]) << 4) | nibble(pair[1]);
        }
        FlowKey::from_canonical_bytes(&bytes[..text.len() / 2])
            .map(Self)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))
    }
    /// Preserve and validate an existing typed key using its exact canonical bytes.
    pub fn from_key(key: FlowKey) -> io::Result<Self> {
        let bytes = key.canonical_bytes();
        FlowKey::from_canonical_bytes(bytes.as_slice())
            .map(Self)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))
    }
    /// Typed identity; not a claimed authenticated peer flow or control capability.
    pub const fn key(self) -> FlowKey {
        self.0
    }
}
impl fmt::Display for CanonicalFlowKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0.canonical_bytes().as_slice() {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}
impl Serialize for CanonicalFlowKey {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}
impl<'de> Deserialize<'de> for CanonicalFlowKey {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct Visitor;
        impl serde::de::Visitor<'_> for Visitor {
            type Value = CanonicalFlowKey;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("bounded lowercase canonical flow-key hex")
            }
            fn visit_str<E: serde::de::Error>(self, text: &str) -> Result<Self::Value, E> {
                CanonicalFlowKey::parse(text).map_err(E::custom)
            }
        }
        d.deserialize_str(Visitor)
    }
}
/// Complete bounded local request; authenticated runtime ingress decides authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConnectionReuseRequest {
    /// Existing independent owner; no modulo remapping.
    pub owner: u16,
    /// Exact old bidirectional flow claim.
    pub old_key: CanonicalFlowKey,
    /// Exact distinct replacement bidirectional flow claim.
    pub next_key: CanonicalFlowKey,
}
impl ConnectionReuseRequest {
    /// Validate two distinct canonical keys before accepting a service operation.
    pub fn new(owner: u16, old_key: FlowKey, next_key: FlowKey) -> io::Result<Self> {
        if old_key == next_key {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "reuse requires distinct flow keys",
            ));
        }
        Ok(Self {
            owner,
            old_key: CanonicalFlowKey::from_key(old_key)?,
            next_key: CanonicalFlowKey::from_key(next_key)?,
        })
    }
}

#[cfg(test)]
#[path = "connection_reuse_tests.rs"]
mod tests;
