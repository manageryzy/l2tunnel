//! Explicit compatibility owners for the existing Swift v2 protected datagram.
//!
//! These owners always use ChaCha20-Poly1305, empty AAD, the legacy HKDF labels
//! and `[packet number u64][ciphertext][tag 16]`. They do not claim the common
//! session binding or expose a MAC-only switch. Inputs must be fresh authenticated
//! directional secrets, and the generation interval must already be agreed.

use crate::record::Profile;
use crate::{Error, KeyGeneration, Limits, MAX_BODY_BYTES_PER_KEY, Opened, PacketNumber, Sealed};
use zeroize::Zeroizing;

/// Legacy per-packet number/tag overhead in bytes.
pub const OVERHEAD_BYTES: usize = 24;
/// Production Swift v2 key-generation interval, unchanged by extraction.
pub const KEY_PACKETS: u64 = 1 << 28;

fn limits(max_body_bytes: usize, packets_per_key: u64) -> Limits {
    Limits {
        max_body_bytes,
        packets_per_key,
        // The shared field remains valid, but compatibility records intentionally
        // do not apply the common format's earlier byte-use termination.
        max_body_bytes_per_key: MAX_BODY_BYTES_PER_KEY,
    }
}

/// Unique Swift v2 sender, preserving packet bytes and mandatory encryption.
pub struct Sender(crate::Sender);
impl Sender {
    /// Copy a previously authenticated directional exporter into owned zeroizing
    /// state. The caller must never recreate an active sender with the same key.
    pub fn new(
        secret: &[u8; 32],
        max_body_bytes: usize,
        packets_per_key: u64,
    ) -> Result<Self, Error> {
        crate::Sender::new(
            Zeroizing::new(*secret),
            limits(max_body_bytes, packets_per_key),
            Profile::SwiftV2,
        )
        .map(Self)
    }
    /// Next unique number, also used by the existing repair coefficient seed.
    pub fn next_number(&self) -> PacketNumber {
        self.0.next_number()
    }
    /// Current sending generation; no key bytes are exposed.
    pub fn generation(&self) -> KeyGeneration {
        self.0.generation()
    }
    /// Protect one nonempty Swift body into a caller-owned packet buffer.
    pub fn seal(&mut self, plaintext: &[u8], output: &mut [u8]) -> Result<Sealed, Error> {
        self.0.seal_inner(None, plaintext, output)
    }
}

/// Swift v2 receiving key/replay owner with the fixed 4096-packet window.
pub struct Receiver(crate::Receiver);
impl Receiver {
    /// Own the authenticated incoming direction secret and agreed interval.
    pub fn new(
        secret: &[u8; 32],
        max_body_bytes: usize,
        packets_per_key: u64,
    ) -> Result<Self, Error> {
        crate::Receiver::new(
            Zeroizing::new(*secret),
            limits(max_body_bytes, packets_per_key),
            Profile::SwiftV2,
        )
        .map(Self)
    }
    /// Current authenticated generation, unchanged by forged future claims.
    pub fn generation(&self) -> KeyGeneration {
        self.0.generation()
    }
    /// Previous generation still retained for accepted-window stragglers.
    pub fn previous_generation(&self) -> Option<KeyGeneration> {
        self.0.previous_generation()
    }
    /// Highest packet number that authenticated and committed to replay state.
    pub fn highest_number(&self) -> Option<PacketNumber> {
        self.0.highest_number()
    }
    /// Authenticate a legacy packet into body-plus-tag caller workspace.
    pub fn open(&mut self, packet: &[u8], output: &mut [u8]) -> Result<Opened, Error> {
        self.0.open_inner(None, packet, output)
    }
}
