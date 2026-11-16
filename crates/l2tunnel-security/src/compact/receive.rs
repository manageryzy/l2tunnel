use super::{Aad, Key, PREFIX_BYTES, Protection, Selection};
use crate::{
    Error, KeyGeneration, Limits, MAX_PACKET_BYTES, Metadata, Opened, PacketNumber,
    keys::{Chain, Labels, Opening},
    replay::Replay,
};
use zeroize::Zeroizing;

/// Unique compact receive owner with the existing replay and adjacent-key engine.
/// CRC success is only a corruption check; this type does not grant control authority.
pub struct Receiver {
    opening: Opening<Key>,
    replay: Replay,
    context: [u8; 88],
    limits: Limits,
    protection: Protection,
    selection: Selection,
    failures: u32,
}
impl Receiver {
    pub(super) fn new(
        root: Zeroizing<[u8; 32]>,
        context: [u8; 88],
        limits: Limits,
        protection: Protection,
        selection: Selection,
    ) -> Result<Self, Error> {
        Ok(Self {
            opening: Opening::new(Chain::new(root, Labels::CompactV3), protection)?,
            replay: Replay::new(),
            context,
            limits,
            protection,
            selection,
            failures: 0,
        })
    }
    /// Current key generation, advanced only by an accepted check/authentication.
    pub fn generation(&self) -> KeyGeneration {
        self.opening.generation()
    }
    /// Retained previous generation for in-window reordered packets.
    pub fn previous_generation(&self) -> Option<KeyGeneration> {
        self.opening.previous_generation()
    }
    /// Highest accepted full packet number, never just its low wire word.
    pub fn highest_number(&self) -> Option<PacketNumber> {
        self.replay.highest.map(PacketNumber)
    }
    /// Lifetime failed cryptographic/check attempts; success never resets the count.
    pub const fn failed_checks(&self) -> u32 {
        self.failures
    }
    /// Actual selected suite; CRC does not become authentication after a valid check.
    pub const fn protection(&self) -> Protection {
        self.protection
    }
    /// Complete prefix/check overhead, excluding caller-owned route/header bytes.
    pub const fn overhead(&self) -> usize {
        self.protection.overhead_bytes()
    }
    /// Check/decrypt a packet into body-plus-check caller workspace.
    /// No replay, byte charge or generation commits until the complete check passes.
    /// The negotiated failed-check cap is permanent for this owner, not a timer.
    pub fn open(
        &mut self,
        metadata: Metadata<'_>,
        packet: &[u8],
        output: &mut [u8],
    ) -> Result<Opened, Error> {
        if self.failures >= self.selection.max_failed_checks {
            return Err(Error::KeyUsageExhausted);
        }
        if packet.len() < self.overhead() || packet.len() > MAX_PACKET_BYTES {
            return Err(Error::Malformed);
        }
        let body_bytes = packet.len() - self.overhead();
        if body_bytes > self.limits.max_body_bytes {
            return Err(Error::TooLarge);
        }
        let payload = &packet[PREFIX_BYTES..];
        if output.len() < payload.len() {
            return Err(Error::OutputTooSmall);
        }
        let low = u32::from_be_bytes(
            packet[..PREFIX_BYTES]
                .try_into()
                .map_err(|_| Error::Malformed)?,
        );
        let number = reconstruct(self.replay.highest, low)?;
        let highest = self.replay.highest.unwrap_or(0);
        let max_gap = self
            .limits
            .packets_per_key
            .min(u64::from(self.selection.max_forward_packets));
        if number > highest && number - highest > max_gap {
            return Err(Error::Generation);
        }
        if !self.replay.fresh(number) {
            return Err(Error::Replay);
        }
        let aad = Aad::new(&self.context, number, metadata)?;
        let generation = KeyGeneration(number / self.limits.packets_per_key);
        let key = self.opening.candidate(generation)?;
        let used = key
            .body_bytes
            .checked_add(body_bytes as u64)
            .ok_or(Error::KeyUsageExhausted)?;
        if used > self.limits.max_body_bytes_per_key {
            return Err(Error::KeyUsageExhausted);
        }
        if let Err(error) = key
            .key
            .open(number, aad.as_slice(), payload, body_bytes, output)
        {
            // Checked before each attempt; no wrap and no successful-open reset.
            self.failures = self
                .failures
                .checked_add(1)
                .ok_or(Error::KeyUsageExhausted)?;
            return Err(error);
        }
        key.body_bytes = used;
        self.opening.confirm(generation);
        self.replay.commit(number);
        self.opening
            .retire(number.max(highest), self.limits.packets_per_key);
        Ok(Opened {
            number: PacketNumber(number),
            generation,
            bytes: body_bytes,
        })
    }
}

// Use the nearest full candidate around highest+1. Exact half-range values are
// ambiguous and refused; the negotiated/key-interval cap is stricter still.
pub(super) fn reconstruct(highest: Option<u64>, low: u32) -> Result<u64, Error> {
    const MODULUS: u128 = 1 << 32;
    const HALF: u128 = MODULUS / 2;
    let expected = highest.map_or(0, |value| u128::from(value) + 1);
    let mut candidate = (expected & !(MODULUS - 1)) | u128::from(low);
    if candidate.abs_diff(expected) == HALF {
        return Err(Error::Generation);
    }
    if candidate + HALF < expected {
        candidate += MODULUS;
    } else if candidate > expected + HALF {
        candidate = candidate.checked_sub(MODULUS).ok_or(Error::Generation)?;
    }
    u64::try_from(candidate).map_err(|_| Error::CounterExhausted)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        Direction, LaneId, Purpose, Role,
        compact::tests::{limits, metadata, root, selection},
        keys::KeyMaterial,
    };

    #[test]
    fn real_compact_owners_cross_low_word_wrap_with_reordered_old_packets() -> Result<(), Error> {
        for suite in [
            Protection::Aes128Ccm4,
            Protection::ChaCha20Crc32c,
            Protection::ChaCha20Poly1305,
        ] {
            let configured = Limits {
                packets_per_key: crate::MAX_PACKETS_PER_KEY,
                ..limits()
            };
            let mut sending = root(Role::Initiator)?;
            let mut receiving = root(Role::Responder)?;
            let mut sender =
                sending.compact_sender(Purpose::Data, LaneId(0), configured, suite, selection())?;
            let (secret, context) = receiving.derive_compact(
                Purpose::Data,
                Direction::InitiatorToResponder,
                LaneId(0),
                configured,
                suite,
                selection(),
            )?;
            let mut receiver = Receiver::new(
                Zeroizing::new(*secret),
                context,
                configured,
                suite,
                selection(),
            )?;
            let mut incoming = Chain::new(secret, Labels::CompactV3);
            let first = (1u64 << 32) - 2;
            // Seed only the real already-derived ratchet/counter state at the
            // boundary. Production offers no import/reset API for these owners.
            for _ in 0..first / configured.packets_per_key {
                sender.chain = sender.chain.next()?;
                incoming = incoming.next()?;
            }
            sender.key = Key::derive(&sender.chain, suite)?;
            sender.next = first;
            receiver.opening = Opening::new(incoming, suite)?;
            receiver.replay.commit(first - 1);
            let mut packets = Vec::new();
            for _ in 0..4 {
                let mut bytes = [0; 64];
                let sealed = sender.seal(metadata(), b"wrap body", &mut bytes)?;
                packets.push(bytes[..sealed.bytes].to_vec());
            }
            assert_eq!(&packets[0][..4], &[0xff, 0xff, 0xff, 0xfe]);
            assert_eq!(&packets[2][..4], &[0; 4]);
            let mut output = [0; 64];
            for index in [0, 2, 1, 3] {
                let opened = receiver.open(metadata(), &packets[index], &mut output)?;
                assert_eq!(opened.number, PacketNumber(first + index as u64));
                assert_eq!(&output[..opened.bytes], b"wrap body");
            }
            assert_eq!(receiver.generation(), KeyGeneration(16));
            assert_eq!(receiver.previous_generation(), Some(KeyGeneration(15)));
            assert_eq!(
                receiver.open(metadata(), &packets[1], &mut output),
                Err(Error::Replay)
            );
        }
        assert_eq!(reconstruct(None, 1 << 31), Err(Error::Generation));
        assert_eq!(reconstruct(Some((1 << 32) - 1), 0)?, 1 << 32);
        assert_eq!(reconstruct(Some(1 << 32), u32::MAX)?, (1 << 32) - 1);
        assert_eq!(reconstruct(Some(u64::MAX), 0), Err(Error::CounterExhausted));
        Ok(())
    }
}
