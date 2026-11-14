use crate::{
    Error, KeyGeneration, Limits, MAX_METADATA_BYTES, MAX_PACKET_BYTES, Metadata, PacketNumber,
    Protection, VERSION,
    keys::{Chain, Key, Labels, Opening, nonce},
    replay::Replay,
};
use ring::{aead, hmac};
use zeroize::{Zeroize, Zeroizing};

/// The same maintained protection operation serves all explicit wire profiles.
pub(crate) fn seal_key(
    key: &Key,
    number: u64,
    aad: &[u8],
    plaintext: &[u8],
    header: usize,
    output: &mut [u8],
) -> Result<(), Error> {
    let body_end = header + plaintext.len();
    output[header..body_end].copy_from_slice(plaintext);
    match key {
        Key::Aead(key) => {
            let tag = key
                .seal_in_place_separate_tag(
                    nonce(number),
                    aead::Aad::from(aad),
                    &mut output[header..body_end],
                )
                .map_err(|_| {
                    output[header..].zeroize();
                    Error::Crypto
                })?;
            output[body_end..].copy_from_slice(tag.as_ref());
        }
        Key::Mac(key) => {
            let mut mac = hmac::Context::with_key(key);
            mac.update(aad);
            mac.update(plaintext);
            output[body_end..].copy_from_slice(mac.sign().as_ref());
        }
    }
    Ok(())
}

pub(crate) fn open_key(
    key: &Key,
    number: u64,
    aad: &[u8],
    payload: &[u8],
    body_bytes: usize,
    output: &mut [u8],
    mac_input: &mut Vec<u8>,
) -> Result<(), Error> {
    match key {
        Key::Aead(key) => {
            let buffer = &mut output[..payload.len()];
            buffer.copy_from_slice(payload);
            if key
                .open_in_place(nonce(number), aead::Aad::from(aad), buffer)
                .is_err()
            {
                buffer.zeroize();
                return Err(Error::Authentication);
            }
        }
        Key::Mac(key) => {
            mac_input.clear();
            mac_input.extend_from_slice(aad);
            mac_input.extend_from_slice(&payload[..body_bytes]);
            hmac::verify(key, mac_input, &payload[body_bytes..])
                .map_err(|_| Error::Authentication)?;
            output[..body_bytes].copy_from_slice(&payload[..body_bytes]);
        }
    }
    Ok(())
}

#[derive(Clone, Copy)]
pub(crate) enum Profile {
    Common {
        context: [u8; 56],
        protection: Protection,
    },
    SwiftV2,
}
impl Profile {
    fn protection(self) -> Protection {
        match self {
            Self::Common { protection, .. } => protection,
            Self::SwiftV2 => Protection::ChaCha20Poly1305,
        }
    }
    fn header_bytes(self) -> usize {
        match self {
            Self::Common { .. } => 10,
            Self::SwiftV2 => 8,
        }
    }
    fn labels(self) -> Labels {
        match self {
            Self::Common { .. } => Labels::Common,
            Self::SwiftV2 => Labels::SwiftV2,
        }
    }
    fn header(self, number: u64, output: &mut [u8]) {
        match self {
            Self::Common { protection, .. } => {
                output[0] = VERSION;
                output[1] = protection as u8;
                output[2..10].copy_from_slice(&number.to_be_bytes());
            }
            Self::SwiftV2 => output[..8].copy_from_slice(&number.to_be_bytes()),
        }
    }
    fn number(self, packet: &[u8]) -> Result<u64, Error> {
        let offset = match self {
            Self::Common { protection, .. } => {
                if packet[0] != VERSION || packet[1] != protection as u8 {
                    return Err(Error::ContextMismatch);
                }
                2
            }
            Self::SwiftV2 => 0,
        };
        Ok(u64::from_be_bytes(
            packet[offset..offset + 8]
                .try_into()
                .map_err(|_| Error::Malformed)?,
        ))
    }
}

const AAD_BYTES: usize = 56 + 10 + 8 + 32 + 2 + MAX_METADATA_BYTES;
struct Aad {
    bytes: [u8; AAD_BYTES],
    length: usize,
}
impl Aad {
    fn new(profile: Profile, header: &[u8], metadata: Option<Metadata<'_>>) -> Result<Self, Error> {
        let mut result = Self {
            bytes: [0; AAD_BYTES],
            length: 0,
        };
        match profile {
            Profile::SwiftV2 if metadata.is_none() => return Ok(result),
            Profile::Common { context, .. } => {
                let metadata = metadata.ok_or(Error::ContextMismatch)?;
                metadata.validate()?;
                result.bytes[..56].copy_from_slice(&context);
                result.bytes[56..66].copy_from_slice(header);
                result.bytes[66..74].copy_from_slice(&metadata.epoch.0.to_be_bytes());
                result.bytes[74..106].copy_from_slice(&metadata.configuration.0);
                result.bytes[106..108]
                    .copy_from_slice(&(metadata.extra.len() as u16).to_be_bytes());
                result.bytes[108..108 + metadata.extra.len()].copy_from_slice(metadata.extra);
                result.length = 108 + metadata.extra.len();
            }
            _ => return Err(Error::ContextMismatch),
        }
        Ok(result)
    }
    fn as_slice(&self) -> &[u8] {
        &self.bytes[..self.length]
    }
}

/// Successful protected-packet output; byte length includes header and tag.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Sealed {
    /// Unique packet number reserved by this sealing attempt.
    pub number: PacketNumber,
    /// Deterministic key generation used for protection.
    pub generation: KeyGeneration,
    /// Complete protected packet bytes written into the caller buffer.
    pub bytes: usize,
}
/// Successful authenticated output; byte length is plaintext only.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Opened {
    /// Authenticated packet identity committed to the replay window.
    pub number: PacketNumber,
    /// Authenticated receiving generation.
    pub generation: KeyGeneration,
    /// Plaintext bytes at the start of the caller output buffer.
    pub bytes: usize,
}

/// Unique sending counter/key owner; never clone or recreate it under the same root.
pub struct Sender {
    chain: Chain,
    key: Key,
    next: u64,
    body_bytes: u64,
    limits: Limits,
    profile: Profile,
}
impl Sender {
    pub(crate) fn new(
        root: Zeroizing<[u8; 32]>,
        limits: Limits,
        profile: Profile,
    ) -> Result<Self, Error> {
        limits.validate()?;
        let chain = Chain::new(root, profile.labels());
        Ok(Self {
            key: chain.key(profile.protection())?,
            chain,
            next: 0,
            body_bytes: 0,
            limits,
            profile,
        })
    }
    /// The next unique sending number; inspecting it does not reserve or reset it.
    pub fn next_number(&self) -> PacketNumber {
        PacketNumber(self.next)
    }
    /// Generation of the last key derived for this sender, initially zero.
    pub fn generation(&self) -> KeyGeneration {
        self.chain.generation
    }
    /// Exact framing/tag overhead for this previously authenticated selection.
    pub fn overhead(&self) -> usize {
        self.profile.header_bytes() + self.profile.protection().tag_bytes()
    }
    /// Protect a common-format record and canonical authenticated metadata.
    /// Validation failures reserve no packet number; cryptographic attempts do.
    pub fn seal(
        &mut self,
        metadata: Metadata<'_>,
        plaintext: &[u8],
        output: &mut [u8],
    ) -> Result<Sealed, Error> {
        self.seal_inner(Some(metadata), plaintext, output)
    }
    pub(crate) fn seal_inner(
        &mut self,
        metadata: Option<Metadata<'_>>,
        plaintext: &[u8],
        output: &mut [u8],
    ) -> Result<Sealed, Error> {
        if plaintext.len() > self.limits.max_body_bytes {
            return Err(Error::TooLarge);
        }
        if matches!(self.profile, Profile::SwiftV2) && plaintext.is_empty() {
            return Err(Error::Malformed);
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
        let mut header = [0; 10];
        let header = &mut header[..self.profile.header_bytes()];
        self.profile.header(self.next, header);
        let aad = Aad::new(self.profile, header, metadata)?;
        let number = self.next;
        let next = number.checked_add(1).ok_or(Error::CounterExhausted)?;
        let generation = KeyGeneration(number / self.limits.packets_per_key);
        let previous_bytes = if generation == self.chain.generation {
            self.body_bytes
        } else {
            0
        };
        let body_bytes = previous_bytes
            .checked_add(plaintext.len() as u64)
            .ok_or(Error::KeyUsageExhausted)?;
        if matches!(self.profile, Profile::Common { .. })
            && body_bytes > self.limits.max_body_bytes_per_key
        {
            return Err(Error::KeyUsageExhausted);
        }
        // A reserved nonce is never reused, even if a cryptographic API fails.
        self.next = next;
        if generation != self.chain.generation {
            if self.chain.generation.0.checked_add(1) != Some(generation.0) {
                return Err(Error::Generation);
            }
            let chain = self.chain.next()?;
            let key = chain.key(self.profile.protection())?;
            self.chain = chain;
            self.key = key;
        }
        self.body_bytes = body_bytes;
        output[..header.len()].copy_from_slice(header);
        seal_key(
            &self.key,
            number,
            aad.as_slice(),
            plaintext,
            header.len(),
            &mut output[..length],
        )?;
        Ok(Sealed {
            number: PacketNumber(number),
            generation,
            bytes: length,
        })
    }
}

/// One receiving domain with bounded replay and adjacent-generation state.
pub struct Receiver {
    opening: Opening,
    replay: Replay,
    limits: Limits,
    profile: Profile,
    mac_input: Vec<u8>,
}
impl Receiver {
    pub(crate) fn new(
        root: Zeroizing<[u8; 32]>,
        limits: Limits,
        profile: Profile,
    ) -> Result<Self, Error> {
        limits.validate()?;
        Ok(Self {
            opening: Opening::new(Chain::new(root, profile.labels()), profile.protection())?,
            replay: Replay::new(),
            limits,
            profile,
            mac_input: match profile.protection() {
                Protection::HmacSha256 => Vec::with_capacity(
                    limits
                        .max_body_bytes
                        .checked_add(AAD_BYTES)
                        .ok_or(Error::InvalidLimits)?,
                ),
                Protection::ChaCha20Poly1305 => Vec::new(),
            },
        })
    }
    /// Current adopted key generation; forged claims never advance it.
    pub fn generation(&self) -> KeyGeneration {
        self.opening.generation()
    }
    /// Previous receiving generation retained for bounded packet reordering.
    pub fn previous_generation(&self) -> Option<KeyGeneration> {
        self.opening.previous_generation()
    }
    /// Highest successfully authenticated packet number, absent before the first.
    pub fn highest_number(&self) -> Option<PacketNumber> {
        self.replay.highest.map(PacketNumber)
    }
    /// Authenticate/decrypt a common record into caller-owned workspace.
    /// The workspace must hold body plus tag. Only `Opened::bytes` plaintext
    /// bytes are valid; failed AEAD workspace is cleared before returning.
    pub fn open(
        &mut self,
        metadata: Metadata<'_>,
        packet: &[u8],
        output: &mut [u8],
    ) -> Result<Opened, Error> {
        self.open_inner(Some(metadata), packet, output)
    }
    pub(crate) fn open_inner(
        &mut self,
        metadata: Option<Metadata<'_>>,
        packet: &[u8],
        output: &mut [u8],
    ) -> Result<Opened, Error> {
        let header = self.profile.header_bytes();
        let tag = self.profile.protection().tag_bytes();
        let overhead = header + tag;
        if packet.len() > MAX_PACKET_BYTES {
            return Err(Error::TooLarge);
        }
        if packet.len() < overhead
            || (matches!(self.profile, Profile::SwiftV2) && packet.len() == overhead)
        {
            return Err(Error::Malformed);
        }
        let body_bytes = packet.len() - overhead;
        if body_bytes > self.limits.max_body_bytes {
            return Err(Error::TooLarge);
        }
        if output.len() < packet.len() - header {
            return Err(Error::OutputTooSmall);
        }
        let number = self.profile.number(packet)?;
        let aad = Aad::new(self.profile, &packet[..header], metadata)?;
        if !self.replay.fresh(number) {
            return Err(Error::Replay);
        }
        let generation = KeyGeneration(number / self.limits.packets_per_key);
        let key = self.opening.candidate(generation)?;
        let used = key
            .body_bytes
            .checked_add(body_bytes as u64)
            .ok_or(Error::KeyUsageExhausted)?;
        if matches!(self.profile, Profile::Common { .. })
            && used > self.limits.max_body_bytes_per_key
        {
            return Err(Error::KeyUsageExhausted);
        }
        open_key(
            &key.key,
            number,
            aad.as_slice(),
            &packet[header..],
            body_bytes,
            output,
            &mut self.mac_input,
        )?;
        key.body_bytes = used;
        self.opening.confirm(generation);
        self.replay.commit(number);
        self.opening.retire(
            self.replay.highest.unwrap_or(number),
            self.limits.packets_per_key,
        );
        Ok(Opened {
            number: PacketNumber(number),
            generation,
            bytes: body_bytes,
        })
    }
}

#[cfg(test)]
mod boundaries {
    use super::*;
    use crate::{ConfigDigest, Epoch, MAX_BODY_BYTES_PER_KEY, MAX_PACKETS_PER_KEY};

    fn limits() -> Limits {
        Limits {
            max_body_bytes: 100,
            packets_per_key: MAX_PACKETS_PER_KEY,
            max_body_bytes_per_key: MAX_BODY_BYTES_PER_KEY,
        }
    }
    fn metadata() -> Metadata<'static> {
        Metadata {
            epoch: Epoch(0),
            configuration: ConfigDigest([0; 32]),
            extra: &[],
        }
    }
    fn unhex(value: &str) -> Result<Vec<u8>, Error> {
        value
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| {
                let digits = std::str::from_utf8(pair).map_err(|_| Error::Malformed)?;
                u8::from_str_radix(digits, 16).map_err(|_| Error::Malformed)
            })
            .collect()
    }

    /// Frozen independent Python cryptography ChaCha20Poly1305/HMAC-HKDF
    /// vectors preserve the pre-extraction Swift bytes and generation boundary.
    #[test]
    fn swift_v2_frozen_vectors_match_original_labels_nonce_and_empty_aad() -> Result<(), Error> {
        let body = [0, 1, 2, 0, 255];
        for (number, expected) in [
            (
                0,
                "000000000000000059b90d916bbb11ceb20491d2bde887f1445f160c46",
            ),
            (
                1,
                "000000000000000193ad41e1dfcc6e24759614c12b35294ef53a987374",
            ),
            (
                1 << 28,
                "0000000010000000c041199d6ced30e3e1ef5e0bf37310300b2cc062ca",
            ),
        ] {
            let mut sender = Sender::new(Zeroizing::new([9; 32]), limits(), Profile::SwiftV2)?;
            sender.next = number;
            let mut output = [0; 100];
            let sealed = sender.seal_inner(None, &body, &mut output)?;
            assert_eq!(&output[..sealed.bytes], &unhex(expected)?);
            assert_eq!(sealed.bytes, body.len() + 24);
            let mut receiver = Receiver::new(Zeroizing::new([9; 32]), limits(), Profile::SwiftV2)?;
            let mut plaintext = [0; 100];
            let opened = receiver.open_inner(None, &output[..sealed.bytes], &mut plaintext)?;
            assert_eq!(&plaintext[..opened.bytes], &body);
            assert_eq!(
                sender.seal(metadata(), &body, &mut output),
                Err(Error::ContextMismatch)
            );
        }
        Ok(())
    }

    #[test]
    fn counter_exhaustion_does_not_wrap_and_compatibility_does_not_add_byte_cutoff()
    -> Result<(), Error> {
        let mut sender = Sender::new(Zeroizing::new([9; 32]), limits(), Profile::SwiftV2)?;
        let mut output = [0xAA; 100];
        sender.next = u64::MAX;
        assert_eq!(
            sender.seal_inner(None, &[7], &mut output),
            Err(Error::CounterExhausted)
        );
        assert_eq!(sender.next_number(), PacketNumber(u64::MAX));
        assert!(output.iter().all(|byte| *byte == 0xAA));
        // A body-byte cutoff did not exist in Swift v2. This private fixture
        // reaches it without allocating or transmitting a terabyte of data.
        sender.next = 0;
        sender.body_bytes = MAX_BODY_BYTES_PER_KEY;
        let sealed = sender.seal_inner(None, &[7], &mut output)?;
        assert_eq!(sealed.number, PacketNumber(0));
        assert_eq!(sender.body_bytes, MAX_BODY_BYTES_PER_KEY + 1);
        Ok(())
    }
}
