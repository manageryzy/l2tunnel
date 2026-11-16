use crate::{Error, KeyGeneration, Protection, REPLAY_PACKETS};
use ring::{aead, hkdf, hmac};
use zeroize::Zeroizing;

struct Length32;
impl hkdf::KeyType for Length32 {
    fn len(&self) -> usize {
        32
    }
}
pub(crate) fn expand(prk: &hkdf::Prk, info: &[&[u8]]) -> Result<Zeroizing<[u8; 32]>, Error> {
    let mut output = Zeroizing::new([0; 32]);
    prk.expand(info, Length32)
        .map_err(|_| Error::Crypto)?
        .fill(&mut output[..])
        .map_err(|_| Error::Crypto)?;
    Ok(output)
}

#[derive(Clone, Copy)]
pub(crate) enum Labels {
    Common,
    SwiftV2,
    RefreshV2,
    CompactV3,
}
impl Labels {
    fn key(self, protection: Protection) -> &'static [u8] {
        match (self, protection) {
            (Self::SwiftV2, _) => b"l2tunnel swift v2 datagram key",
            (Self::Common, Protection::ChaCha20Poly1305) => b"l2tunnel packet security v1 AEAD key",
            (Self::Common, Protection::HmacSha256) => b"l2tunnel packet security v1 MAC key",
            (Self::RefreshV2, Protection::ChaCha20Poly1305) => b"l2tunnel/packet/v2/aead-key\0",
            (Self::RefreshV2, Protection::HmacSha256) => b"l2tunnel/packet/v2/mac-key\0",
            (Self::CompactV3, _) => b"l2tunnel/packet/v3/compact-key\0",
        }
    }
    fn next(self) -> &'static [u8] {
        match self {
            Self::SwiftV2 => b"l2tunnel swift v2 next secret",
            Self::Common => b"l2tunnel packet security v1 next secret",
            Self::RefreshV2 => b"l2tunnel/packet/v2/next-secret\0",
            Self::CompactV3 => b"l2tunnel/packet/v3/next-secret\0",
        }
    }
}

// Keep the maintained key objects inline: the bounded current/previous/candidate
// slots should not allocate whenever a packet advances the ratchet.
#[allow(clippy::large_enum_variant)]
pub(crate) enum Key {
    Aead(aead::LessSafeKey),
    Mac(hmac::Key),
}

pub(crate) struct Chain {
    secret: Zeroizing<[u8; 32]>,
    pub(crate) generation: KeyGeneration,
    labels: Labels,
}
impl Chain {
    pub(crate) fn new(secret: Zeroizing<[u8; 32]>, labels: Labels) -> Self {
        Self {
            secret,
            generation: KeyGeneration(0),
            labels,
        }
    }
    fn expand(&self, label: &'static [u8]) -> Result<Zeroizing<[u8; 32]>, Error> {
        expand(
            &hkdf::Prk::new_less_safe(hkdf::HKDF_SHA256, &self.secret[..]),
            &[label],
        )
    }
    pub(crate) fn key(&self, protection: Protection) -> Result<Key, Error> {
        let secret = self.expand(self.labels.key(protection))?;
        match protection {
            Protection::ChaCha20Poly1305 => {
                aead::UnboundKey::new(&aead::CHACHA20_POLY1305, &secret[..])
                    .map(aead::LessSafeKey::new)
                    .map(Key::Aead)
                    .map_err(|_| Error::Crypto)
            }
            Protection::HmacSha256 => Ok(Key::Mac(hmac::Key::new(hmac::HMAC_SHA256, &secret[..]))),
        }
    }
    pub(crate) fn compact_secret(&self) -> Result<Zeroizing<[u8; 32]>, Error> {
        self.expand(b"l2tunnel/packet/v3/compact-key\0")
    }
    pub(crate) fn next(&self) -> Result<Self, Error> {
        Ok(Self {
            secret: self.expand(self.labels.next())?,
            generation: KeyGeneration(
                self.generation
                    .0
                    .checked_add(1)
                    .ok_or(Error::CounterExhausted)?,
            ),
            labels: self.labels,
        })
    }
}

pub(crate) trait KeyMaterial: Sized {
    type Selection: Copy;
    fn derive(chain: &Chain, selection: Self::Selection) -> Result<Self, Error>;
}
impl KeyMaterial for Key {
    type Selection = Protection;
    fn derive(chain: &Chain, selection: Protection) -> Result<Self, Error> {
        chain.key(selection)
    }
}

pub(crate) struct ReceivingKey<K = Key> {
    pub(crate) generation: KeyGeneration,
    pub(crate) key: K,
    pub(crate) body_bytes: u64,
}
impl<K: KeyMaterial> ReceivingKey<K> {
    fn new(chain: &Chain, protection: K::Selection) -> Result<Self, Error> {
        Ok(Self {
            generation: chain.generation,
            key: K::derive(chain, protection)?,
            body_bytes: 0,
        })
    }
}

pub(crate) struct Opening<K: KeyMaterial = Key> {
    chain: Chain,
    current: ReceivingKey<K>,
    previous: Option<ReceivingKey<K>>,
    next: Option<(Chain, ReceivingKey<K>)>,
    protection: K::Selection,
}
impl<K: KeyMaterial> Opening<K> {
    pub(crate) fn new(chain: Chain, protection: K::Selection) -> Result<Self, Error> {
        Ok(Self {
            current: ReceivingKey::new(&chain, protection)?,
            chain,
            previous: None,
            next: None,
            protection,
        })
    }
    pub(crate) fn generation(&self) -> KeyGeneration {
        self.chain.generation
    }
    pub(crate) fn previous_generation(&self) -> Option<KeyGeneration> {
        self.previous.as_ref().map(|key| key.generation)
    }
    pub(crate) fn candidate(
        &mut self,
        generation: KeyGeneration,
    ) -> Result<&mut ReceivingKey<K>, Error> {
        let current = self.chain.generation.0;
        if generation.0 == current {
            return Ok(&mut self.current);
        }
        if generation.0.checked_add(1) == Some(current) {
            return self.previous.as_mut().ok_or(Error::Generation);
        }
        if current.checked_add(1) != Some(generation.0) {
            return Err(Error::Generation);
        }
        if self.next.is_none() {
            let chain = self.chain.next()?;
            let key = ReceivingKey::new(&chain, self.protection)?;
            self.next = Some((chain, key));
        }
        self.next.as_mut().map(|(_, key)| key).ok_or(Error::Crypto)
    }
    pub(crate) fn confirm(&mut self, generation: KeyGeneration) {
        if self.chain.generation.0.checked_add(1) == Some(generation.0)
            && let Some((chain, key)) = self.next.take()
        {
            self.previous = Some(std::mem::replace(&mut self.current, key));
            self.chain = chain;
        }
    }
    pub(crate) fn retire(&mut self, highest: u64, key_packets: u64) {
        if self.previous.is_some()
            && self
                .chain
                .generation
                .0
                .checked_mul(key_packets)
                .and_then(|start| start.checked_add(REPLAY_PACKETS))
                .is_some_and(|retire_at| highest >= retire_at)
        {
            self.previous = None;
        }
    }
}

pub(crate) fn nonce(number: u64) -> aead::Nonce {
    let mut bytes = [0; aead::NONCE_LEN];
    bytes[4..].copy_from_slice(&number.to_be_bytes());
    aead::Nonce::assume_unique_for_key(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legacy_chain_separates_datagram_keys_roots_and_neighboring_generations() -> Result<(), Error>
    {
        let chain = Chain::new(Zeroizing::new([9; 32]), Labels::SwiftV2);
        let next = chain.next()?;
        let key = chain.expand(b"l2tunnel swift v2 datagram key")?;
        assert_ne!(key[..], next.expand(b"l2tunnel swift v2 datagram key")?[..]);
        assert_ne!(key[..], chain.secret[..]);
        assert_ne!(next.secret[..], chain.secret[..]);
        assert_eq!(next.generation, KeyGeneration(1));
        Ok(())
    }
}
