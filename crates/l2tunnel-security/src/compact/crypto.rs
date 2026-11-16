use super::Protection;
use crate::{
    Error,
    keys::{Chain, KeyMaterial, nonce},
};
use ccm::{
    Ccm,
    aead::{AeadInOut, KeyInit},
    consts::{U4, U13},
};
use chacha20::cipher::{KeyIvInit, StreamCipher};
use ring::aead;
use zeroize::{Zeroize, Zeroizing};

type Ccm4 = Ccm<aes::Aes128, U4, U13>;

// Keep actual maintained keys inline; legacy Key/Opening layouts remain unchanged.
#[allow(clippy::large_enum_variant)]
pub(super) enum Key {
    Ccm(Ccm4),
    Crc(Zeroizing<[u8; 32]>),
    Strong(aead::LessSafeKey),
}
impl KeyMaterial for Key {
    type Selection = Protection;
    fn derive(chain: &Chain, protection: Protection) -> Result<Self, Error> {
        let secret = chain.compact_secret()?;
        match protection {
            Protection::Aes128Ccm4 => Ccm4::new_from_slice(&secret[..16])
                .map(Self::Ccm)
                .map_err(|_| Error::Crypto),
            Protection::ChaCha20Crc32c => Ok(Self::Crc(secret)),
            Protection::ChaCha20Poly1305 => {
                aead::UnboundKey::new(&aead::CHACHA20_POLY1305, &secret[..])
                    .map(aead::LessSafeKey::new)
                    .map(Self::Strong)
                    .map_err(|_| Error::Crypto)
            }
        }
    }
}
fn ccm_nonce(number: u64) -> ccm::Nonce<U13> {
    let mut bytes = [0; 13];
    bytes[5..].copy_from_slice(&number.to_be_bytes());
    bytes.into()
}
fn stream(key: &[u8; 32], number: u64, bytes: &mut [u8]) -> Result<(), Error> {
    let mut nonce = [0; 12];
    nonce[4..].copy_from_slice(&number.to_be_bytes());
    let mut cipher = chacha20::ChaCha20::new_from_slices(key, &nonce).map_err(|_| Error::Crypto)?;
    cipher.try_apply_keystream(bytes).map_err(|_| Error::Crypto)
}
fn check(aad: &[u8], body: &[u8]) -> u32 {
    crc32c::crc32c_append(crc32c::crc32c(aad), body)
}
impl Key {
    pub(super) fn seal(
        &self,
        number: u64,
        aad: &[u8],
        plaintext: &[u8],
        output: &mut [u8],
    ) -> Result<(), Error> {
        let (body, tag) = output.split_at_mut(plaintext.len());
        body.copy_from_slice(plaintext);
        let result = match self {
            Self::Ccm(key) => key
                .encrypt_inout_detached(&ccm_nonce(number), aad, body.into())
                .map(|value| tag.copy_from_slice(&value))
                .map_err(|_| Error::Crypto),
            Self::Strong(key) => key
                .seal_in_place_separate_tag(nonce(number), aead::Aad::from(aad), body)
                .map(|value| tag.copy_from_slice(value.as_ref()))
                .map_err(|_| Error::Crypto),
            Self::Crc(key) => {
                // Encrypt the unkeyed check too. This remains malleable and is
                // deliberately never treated as authenticated control authority.
                tag.copy_from_slice(&check(aad, plaintext).to_be_bytes());
                stream(key, number, output)
            }
        };
        if result.is_err() {
            output.zeroize();
        }
        result
    }
    pub(super) fn open(
        &self,
        number: u64,
        aad: &[u8],
        payload: &[u8],
        body_bytes: usize,
        output: &mut [u8],
    ) -> Result<(), Error> {
        let buffer = &mut output[..payload.len()];
        buffer.copy_from_slice(payload);
        let result = match self {
            Self::Ccm(key) => {
                let (body, tag) = buffer.split_at_mut(body_bytes);
                let value: [u8; 4] = tag.try_into().map_err(|_| Error::Malformed)?;
                key.decrypt_inout_detached(&ccm_nonce(number), aad, body.into(), &value.into())
                    .map_err(|_| Error::Authentication)
            }
            Self::Strong(key) => key
                .open_in_place(nonce(number), aead::Aad::from(aad), buffer)
                .map(|_| ())
                .map_err(|_| Error::Authentication),
            Self::Crc(key) => stream(key, number, buffer).and_then(|()| {
                let value: [u8; 4] = buffer[body_bytes..]
                    .try_into()
                    .map_err(|_| Error::Malformed)?;
                if check(aad, &buffer[..body_bytes]) == u32::from_be_bytes(value) {
                    Ok(())
                } else {
                    Err(Error::Authentication)
                }
            }),
        };
        if result.is_err() {
            buffer.zeroize();
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maintained_ccm_four_byte_tag_matches_nist_38c_example_one() -> Result<(), Error> {
        // NIST SP800-38C Appendix C.1, including the native 32-bit CCM tag.
        // Its seven-byte nonce tests the provider KAT, not our v3 nonce layout.
        // https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38c.pdf
        type VectorCcm = Ccm<aes::Aes128, U4, ccm::consts::U7>;
        let key = [
            0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d,
            0x4e, 0x4f,
        ];
        let nonce: ccm::Nonce<ccm::consts::U7> = [0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16].into();
        let aad = [0, 1, 2, 3, 4, 5, 6, 7];
        let cipher = VectorCcm::new_from_slice(&key).map_err(|_| Error::Crypto)?;
        let mut body = [0x20, 0x21, 0x22, 0x23];
        let tag = cipher
            .encrypt_inout_detached(&nonce, &aad, body.as_mut_slice().into())
            .map_err(|_| Error::Crypto)?;
        assert_eq!(body, [0x71, 0x62, 0x01, 0x5b]);
        assert_eq!(tag.as_slice(), &[0x4d, 0xac, 0x25, 0x5d]);
        cipher
            .decrypt_inout_detached(&nonce, &aad, body.as_mut_slice().into(), &tag)
            .map_err(|_| Error::Authentication)?;
        assert_eq!(body, [0x20, 0x21, 0x22, 0x23]);
        assert_eq!(crc32c::crc32c(b"123456789"), 0xe306_9283);
        Ok(())
    }

    #[test]
    fn every_compact_nonce_uses_the_high_full_counter_bits() -> Result<(), Error> {
        let chain = Chain::new(Zeroizing::new([3; 32]), crate::keys::Labels::CompactV3);
        for suite in [
            Protection::Aes128Ccm4,
            Protection::ChaCha20Crc32c,
            Protection::ChaCha20Poly1305,
        ] {
            let key = Key::derive(&chain, suite)?;
            let mut first = vec![0; 32 + suite.tag_bytes()];
            let mut wrapped = first.clone();
            key.seal(0, b"same AAD", &[0x55; 32], &mut first)?;
            key.seal(1 << 32, b"same AAD", &[0x55; 32], &mut wrapped)?;
            assert_ne!(
                &first[..32],
                &wrapped[..32],
                "full nonce differs even with an identical low word"
            );
        }
        Ok(())
    }
}
