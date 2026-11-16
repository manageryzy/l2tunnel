//! Explicit v3 packet owners with a four-byte low packet-number prefix.
//!
//! Full session/domain identity, negotiated limits and epoch/configuration metadata
//! remain in the protection context. Only the packet number's low 32 bits travel
//! on wire. A bounded nearest reconstruction precedes the existing replay owner.
//! AES-CCM-4 has a deliberately short authentication tag; ChaCha20/CRC32C supplies
//! encryption and an unkeyed corruption check, never authenticated feedback or
//! management authority. Both require explicit establishment-time selection.
//! No constructor changes a legacy format, root, counter or default.

mod crypto;
mod receive;
#[cfg(test)]
mod tests;

use crate::{
    Error, KeyGeneration, LaneId, Limits, MAX_METADATA_BYTES, MAX_PACKET_BYTES, Metadata,
    PacketNumber, Purpose, Sealed, SessionRoot,
    keys::{Chain, KeyMaterial, Labels},
};
use crypto::Key;
pub use receive::Receiver;
use zeroize::Zeroizing;

/// Off-wire authenticated format identity; no version byte is added to packets.
pub const VERSION: u8 = 3;
/// Exact low packet-number prefix length, independent of the selected check.
pub const PREFIX_BYTES: usize = 4;

/// Explicit negotiated compact protection, independent of legacy selections.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Protection {
    /// Maintained AES-128-CCM with a native four-byte authentication tag.
    Aes128Ccm4 = 1,
    /// Maintained ChaCha20 plus an unkeyed CRC32C; not authentication.
    ChaCha20Crc32c = 2,
    /// Maintained ChaCha20-Poly1305 with its full 16-byte tag.
    ChaCha20Poly1305 = 3,
}
impl Protection {
    /// Actual bytes appended after the encrypted body.
    pub const fn tag_bytes(self) -> usize {
        match self {
            Self::Aes128Ccm4 | Self::ChaCha20Crc32c => 4,
            Self::ChaCha20Poly1305 => 16,
        }
    }
    /// Actual packet-number prefix plus check, excluding caller-owned routing.
    pub const fn overhead_bytes(self) -> usize {
        PREFIX_BYTES + self.tag_bytes()
    }
    /// Whether this suite authenticates management or reliable-retiring feedback.
    pub const fn authenticated_control(self) -> bool {
        matches!(self, Self::ChaCha20Poly1305)
    }
}

/// Mandatory negotiated ambiguity and invalid-check limits; no default is chosen.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Selection {
    /// Largest forward packet gap, further bounded by the actual key interval.
    /// Must be positive and below the ambiguous 2^31 half range.
    pub max_forward_packets: u32,
    /// Lifetime failed cryptographic/check attempt cap for this receiving owner.
    /// Reaching it permanently refuses further opens; success never resets it.
    /// A four-byte CCM tag still has only 32-bit authentication: the negotiated
    /// trial cap bounds attempts, not a stronger tag or a universal risk guarantee.
    pub max_failed_checks: u32,
}
impl Selection {
    /// Check complete scalar bounds without reserving a domain or allocating.
    pub fn validate(self, limits: Limits) -> Result<(), Error> {
        limits.validate()?;
        if self.max_forward_packets == 0
            || self.max_forward_packets > i32::MAX as u32
            || self.max_failed_checks == 0
        {
            return Err(Error::InvalidLimits);
        }
        Ok(())
    }
}

impl SessionRoot {
    /// Reserve the one local compact sender for this exact purpose/direction/lane.
    /// The same registry excludes an existing legacy owner in that domain.
    pub fn compact_sender(
        &mut self,
        purpose: Purpose,
        lane: LaneId,
        limits: Limits,
        protection: Protection,
        selection: Selection,
    ) -> Result<Sender, Error> {
        let (root, context) = self.derive_compact(
            purpose,
            self.role().sending(),
            lane,
            limits,
            protection,
            selection,
        )?;
        Sender::new(root, context, limits, protection)
    }
    /// Reserve the one peer compact receiver and replay owner in this domain.
    /// Four-byte suites are refused outside the explicit data purpose.
    pub fn compact_receiver(
        &mut self,
        purpose: Purpose,
        lane: LaneId,
        limits: Limits,
        protection: Protection,
        selection: Selection,
    ) -> Result<Receiver, Error> {
        let (root, context) = self.derive_compact(
            purpose,
            self.role().receiving(),
            lane,
            limits,
            protection,
            selection,
        )?;
        Receiver::new(root, context, limits, protection, selection)
    }
}

const AAD_BYTES: usize = 88 + 8 + 8 + 32 + 2 + MAX_METADATA_BYTES;
struct Aad {
    bytes: [u8; AAD_BYTES],
    length: usize,
}
impl Aad {
    fn new(context: &[u8; 88], number: u64, metadata: Metadata<'_>) -> Result<Self, Error> {
        metadata.validate()?;
        let mut bytes = [0; AAD_BYTES];
        bytes[..88].copy_from_slice(context);
        bytes[88..96].copy_from_slice(&number.to_be_bytes());
        bytes[96..104].copy_from_slice(&metadata.epoch.0.to_be_bytes());
        bytes[104..136].copy_from_slice(&metadata.configuration.0);
        bytes[136..138].copy_from_slice(&(metadata.extra.len() as u16).to_be_bytes());
        bytes[138..138 + metadata.extra.len()].copy_from_slice(metadata.extra);
        Ok(Self {
            bytes,
            length: 138 + metadata.extra.len(),
        })
    }
    fn as_slice(&self) -> &[u8] {
        &self.bytes[..self.length]
    }
}

/// Unique compact sender retaining full packet/nonce and per-key byte ownership.
pub struct Sender {
    chain: Chain,
    key: Key,
    context: [u8; 88],
    limits: Limits,
    protection: Protection,
    next: u64,
    body_bytes: u64,
}
impl Sender {
    fn new(
        root: Zeroizing<[u8; 32]>,
        context: [u8; 88],
        limits: Limits,
        protection: Protection,
    ) -> Result<Self, Error> {
        let chain = Chain::new(root, Labels::CompactV3);
        Ok(Self {
            key: Key::derive(&chain, protection)?,
            chain,
            context,
            limits,
            protection,
            next: 0,
            body_bytes: 0,
        })
    }
    /// Next full nonwrapping packet number; only its low word is serialized.
    pub const fn next_number(&self) -> PacketNumber {
        PacketNumber(self.next)
    }
    /// Current actual sending key generation.
    pub fn generation(&self) -> KeyGeneration {
        self.chain.generation
    }
    /// Actual selected suite, without converting an unkeyed check into authority.
    pub const fn protection(&self) -> Protection {
        self.protection
    }
    /// Complete compact overhead, excluding the caller's route byte/header.
    pub const fn overhead(&self) -> usize {
        self.protection.overhead_bytes()
    }
    /// Protect one opaque body and authenticate/check the complete supplied context.
    /// All predictable refusal checks precede nonce reservation/output mutation.
    pub fn seal(
        &mut self,
        metadata: Metadata<'_>,
        plaintext: &[u8],
        output: &mut [u8],
    ) -> Result<Sealed, Error> {
        if plaintext.len() > self.limits.max_body_bytes {
            return Err(Error::TooLarge);
        }
        let length = plaintext
            .len()
            .checked_add(self.overhead())
            .ok_or(Error::TooLarge)?;
        if length > MAX_PACKET_BYTES {
            return Err(Error::TooLarge);
        }
        if output.len() < length {
            return Err(Error::OutputTooSmall);
        }
        let aad = Aad::new(&self.context, self.next, metadata)?;
        let number = self.next;
        let next = number.checked_add(1).ok_or(Error::CounterExhausted)?;
        let generation = KeyGeneration(number / self.limits.packets_per_key);
        let previous = if generation == self.chain.generation {
            self.body_bytes
        } else {
            0
        };
        let used = previous
            .checked_add(plaintext.len() as u64)
            .ok_or(Error::KeyUsageExhausted)?;
        if used > self.limits.max_body_bytes_per_key {
            return Err(Error::KeyUsageExhausted);
        }
        if generation != self.chain.generation {
            if self.chain.generation.0.checked_add(1) != Some(generation.0) {
                return Err(Error::Generation);
            }
            let chain = self.chain.next()?;
            let key = Key::derive(&chain, self.protection)?;
            self.chain = chain;
            self.key = key;
        }
        // A provider failure cannot cause the same key/nonce pair to be reused.
        self.next = next;
        self.body_bytes = used;
        output[..PREFIX_BYTES].copy_from_slice(&(number as u32).to_be_bytes());
        self.key.seal(
            number,
            aad.as_slice(),
            plaintext,
            &mut output[PREFIX_BYTES..length],
        )?;
        Ok(Sealed {
            number: PacketNumber(number),
            generation,
            bytes: length,
        })
    }
}
