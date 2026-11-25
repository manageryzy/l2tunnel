//! Test addresses agreed before each test (owner decisions 6 and 7,
//! 2026-11-24): a fresh random pair of private (RFC 1918) addresses that no
//! interface or route on either host uses. While the test runs, each side's
//! runtime takes packets for its own address before its TUN/TAP device.
use crate::Error;
use smoltcp::wire::Ipv4Address;

/// The private ranges a pair is drawn from, as (first address, size).
const RANGES: [(u32, u32); 3] = [
    (0x0A00_0000, 1 << 24), // 10.0.0.0/8
    (0xAC10_0000, 1 << 20), // 172.16.0.0/12
    (0xC0A8_0000, 1 << 16), // 192.168.0.0/16
];
/// Pairs tried before giving up on finding an unused one.
pub const DRAWS: u32 = 64;

/// The tester's and the responder's address for one test.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Addresses {
    /// Source of the tester's packets.
    pub tester: Ipv4Address,
    /// The responder's address: the blackhole the peer takes packets for.
    pub responder: Ipv4Address,
}
impl Addresses {
    /// Both addresses are private, usable host addresses, and distinct.
    pub fn validate(self) -> Result<(), Error> {
        if self.tester == self.responder || !usable(self.tester) || !usable(self.responder) {
            return Err(Error::Invalid(
                "test addresses must be two distinct private host addresses",
            ));
        }
        Ok(())
    }
    /// Draw a random pair, skipping pairs where `in_use` reports either
    /// address. `seed` comes from the runtime's random source. The pair is
    /// the first two host addresses of a random /29 in a private range.
    pub fn random(seed: u64, mut in_use: impl FnMut(Ipv4Address) -> bool) -> Result<Self, Error> {
        let mut state = seed;
        for _ in 0..DRAWS {
            let value = next(&mut state);
            let total: u32 = RANGES.iter().map(|(_, size)| size).sum();
            let mut offset = (value as u32) % total;
            let mut base = 0;
            for (first, size) in RANGES {
                if offset < size {
                    base = first + (offset & !7);
                    break;
                }
                offset -= size;
            }
            let pair = Self {
                tester: Ipv4Address::from_bits(base + 1),
                responder: Ipv4Address::from_bits(base + 2),
            };
            if pair.validate().is_ok() && !in_use(pair.tester) && !in_use(pair.responder) {
                return Ok(pair);
            }
        }
        Err(Error::Invalid(
            "no unused private test address pair was found",
        ))
    }
    /// Wire form: tester then responder, four bytes each.
    pub fn to_bytes(self) -> [u8; 8] {
        let mut bytes = [0; 8];
        bytes[..4].copy_from_slice(&self.tester.octets());
        bytes[4..].copy_from_slice(&self.responder.octets());
        bytes
    }
    /// Parse and validate the wire form.
    pub fn from_bytes(bytes: [u8; 8]) -> Result<Self, Error> {
        let pair = Self {
            tester: Ipv4Address::new(bytes[0], bytes[1], bytes[2], bytes[3]),
            responder: Ipv4Address::new(bytes[4], bytes[5], bytes[6], bytes[7]),
        };
        pair.validate()?;
        Ok(pair)
    }
}

/// A private (RFC 1918) address that is not a /29's network or broadcast.
pub fn usable(address: Ipv4Address) -> bool {
    let bits = address.to_bits();
    RANGES
        .iter()
        .any(|(first, size)| bits.wrapping_sub(*first) < *size)
        && !matches!(bits & 7, 0 | 7)
}

/// SplitMix64.
fn next(state: &mut u64) -> u64 {
    *state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
    let mut value = *state;
    value = (value ^ (value >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    value = (value ^ (value >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    value ^ (value >> 31)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn random_pairs_are_private_distinct_and_skip_used_addresses() -> Result<(), Error> {
        let mut seen = std::collections::BTreeSet::new();
        for seed in 0..200 {
            let pair = Addresses::random(seed, |_| false)?;
            pair.validate()?;
            assert_eq!(Addresses::from_bytes(pair.to_bytes())?, pair);
            seen.insert(pair.responder);
        }
        assert!(seen.len() > 190, "pairs vary with the seed");
        let first = Addresses::random(7, |_| false)?;
        let other = Addresses::random(7, |address| address == first.responder)?;
        assert_ne!(
            other.responder, first.responder,
            "a used address is skipped"
        );
        assert!(Addresses::random(7, |_| true).is_err(), "bounded retries");
        Ok(())
    }

    #[test]
    fn foreign_pairs_are_refused() {
        let public = Addresses {
            tester: Ipv4Address::new(8, 8, 8, 1),
            responder: Ipv4Address::new(8, 8, 8, 2),
        };
        assert!(public.validate().is_err());
        let same = Addresses {
            tester: Ipv4Address::new(10, 1, 2, 1),
            responder: Ipv4Address::new(10, 1, 2, 1),
        };
        assert!(same.validate().is_err());
        assert!(Addresses::from_bytes([10, 0, 0, 0, 10, 0, 0, 2]).is_err());
        assert!(Addresses::from_bytes([172, 32, 0, 1, 172, 16, 0, 2]).is_err());
        assert!(Addresses::from_bytes([192, 168, 9, 1, 192, 168, 9, 2]).is_ok());
    }
}
