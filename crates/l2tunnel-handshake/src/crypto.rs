//! Narrow validation around maintained X25519 and Clatter's public DH interface.
use clatter::KeyPair;
use clatter::bytearray::{ByteArray, SensitiveByteArray};
use clatter::error::{DhError, DhResult};
use clatter::rand_core::{CryptoRng, Error, RngCore};
use clatter::traits::{CryptoComponent, Dh, Rng};
use std::num::NonZeroU32;
use x25519_dalek::{PublicKey, StaticSecret};

/// Internal generation is unavailable: all ephemeral input comes from the caller.
#[derive(Clone)]
pub(super) struct CheckedX25519;

impl CryptoComponent for CheckedX25519 {
    fn name() -> &'static str {
        "25519"
    }
}

impl Dh for CheckedX25519 {
    type PrivateKey = SensitiveByteArray<[u8; 32]>;
    type PubKey = [u8; 32];
    type Output = SensitiveByteArray<[u8; 32]>;

    fn genkey_rng<R: Rng>(_: &mut R) -> DhResult<KeyPair<Self::PubKey, Self::PrivateKey>> {
        // This is the fail-closed entropy boundary, including unexpected upstream
        // requests. No RNG method is called and no key is returned.
        Err(DhError::KeyGeneration)
    }

    fn pubkey(key: &Self::PrivateKey) -> Self::PubKey {
        PublicKey::from(&StaticSecret::from(**key)).to_bytes()
    }

    fn dh(key: &Self::PrivateKey, peer: &Self::PubKey) -> DhResult<Self::Output> {
        let secret = StaticSecret::from(**key);
        let shared = secret.diffie_hellman(&PublicKey::from(*peer));
        // The maintained implementation performs this check in constant time.
        // Clatter 2.3.0's stock wrapper omits it. Normalize its only DH error
        // variant here; the public wrapper reports Authentication instead.
        if !shared.was_contributory() {
            return Err(DhError::KeyGeneration);
        }
        Ok(SensitiveByteArray::from_slice(shared.as_bytes()))
    }
}

/// Clatter requires a Default+Clone RNG type even when `e` is supplied.
/// Its infallible trait methods cannot express failure. They are never used:
/// CheckedX25519 refuses all internal generation before consulting this value.
/// Clatter's getrandom feature is disabled. This type performs no OS access and
/// consults no global or thread-local provider.
#[derive(Clone, Default)]
pub(super) struct UnavailableRandom;

impl RngCore for UnavailableRandom {
    fn next_u32(&mut self) -> u32 {
        0
    }

    fn next_u64(&mut self) -> u64 {
        0
    }

    fn fill_bytes(&mut self, destination: &mut [u8]) {
        destination.fill(0);
    }

    fn try_fill_bytes(&mut self, _: &mut [u8]) -> Result<(), Error> {
        Err(NonZeroU32::MIN.into())
    }
}

// This private marker cannot authorize key generation: the DH adapter above
// always refuses it. The wrapper never offers this type as caller entropy.
impl CryptoRng for UnavailableRandom {}
