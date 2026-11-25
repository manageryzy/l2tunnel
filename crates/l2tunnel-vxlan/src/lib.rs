//! Bounded base VXLAN header codec, VNI/domain admission table, and pure VTEP
//! switching/FDB/BUM/MTU policy (`docs/modules/vxlan.md`, `docs/overlay-and-carriers.md`).
//! Socket ownership and OS device setup remain external.
use std::collections::BTreeMap;

/// Pure, clock-injected multi-peer VTEP policy, FDB, BUM accounting and MTU bounds.
pub mod vtep;

/// Base VXLAN header length in bytes.
pub const HEADER_LEN: usize = 8;
/// Upper policy limit for one inner Ethernet frame.
pub const MAX_FRAME: usize = 65_535;

/// A checked 24-bit VXLAN network identifier.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct Vni(u32);
impl Vni {
    /// Validate a wire-representable VNI; deployment policy may reject zero.
    pub fn new(value: u32) -> Result<Self, Error> {
        if value > 0x00ff_ffff {
            Err(Error::Vni)
        } else {
            Ok(Self(value))
        }
    }
    /// Return the 24-bit value as a u32.
    pub fn get(self) -> u32 {
        self.0
    }
}

/// Codec/admission validation failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// VNI cannot be represented in 24 bits.
    Vni,
    /// Missing base header or minimum Ethernet bytes.
    Truncated,
    /// Unsupported VXLAN extension flags or nonzero reserved fields.
    Header,
    /// Frame exceeds the configured bound.
    FrameTooLarge,
    /// Output is too small; no bytes were modified.
    OutputTooSmall,
    /// Invalid or exhausted mapping capacity.
    Capacity,
    /// Existing VNI is assigned to a different domain.
    Conflict,
    /// VNI has no authorized local domain mapping.
    Unauthorized,
}

/// Borrowed, structurally validated packet; remote-source authorization is external.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Packet<'a> {
    /// Network identifier from the validated header.
    pub vni: Vni,
    /// Complete inner Ethernet bytes without any implicit transformation.
    pub ethernet: &'a [u8],
}

/// Encode a base VXLAN packet. Validation errors leave the output untouched.
pub fn encode(vni: Vni, ethernet: &[u8], output: &mut [u8]) -> Result<usize, Error> {
    if ethernet.len() < 14 {
        return Err(Error::Truncated);
    }
    if ethernet.len() > MAX_FRAME {
        return Err(Error::FrameTooLarge);
    }
    let needed = HEADER_LEN + ethernet.len();
    if output.len() < needed {
        return Err(Error::OutputTooSmall);
    }
    let bytes = vni.0.to_be_bytes();
    output[..HEADER_LEN].copy_from_slice(&[8, 0, 0, 0, bytes[1], bytes[2], bytes[3], 0]);
    output[HEADER_LEN..needed].copy_from_slice(ethernet);
    Ok(needed)
}

/// Decode the strict base format without allocation. Extension variants are rejected.
pub fn decode(datagram: &[u8], max_frame_bytes: usize) -> Result<Packet<'_>, Error> {
    if datagram.len() < HEADER_LEN + 14 {
        return Err(Error::Truncated);
    }
    if datagram[..4] != [8, 0, 0, 0] || datagram[7] != 0 {
        return Err(Error::Header);
    }
    let ethernet = &datagram[HEADER_LEN..];
    if ethernet.len() > max_frame_bytes.min(MAX_FRAME) {
        return Err(Error::FrameTooLarge);
    }
    let vni = Vni(u32::from_be_bytes([
        0,
        datagram[4],
        datagram[5],
        datagram[6],
    ]));
    Ok(Packet { vni, ethernet })
}

/// Bounded configuration mapping; it does not authenticate remote VXLAN peers.
pub struct DomainMap {
    domains: BTreeMap<Vni, u32>,
    maximum: usize,
}
impl DomainMap {
    /// Create a map with a finite entry limit.
    pub fn new(maximum: usize) -> Result<Self, Error> {
        if maximum == 0 || maximum > 65_536 {
            return Err(Error::Capacity);
        }
        Ok(Self {
            domains: BTreeMap::new(),
            maximum,
        })
    }
    /// Add an authorized mapping; exact duplicate configurations are idempotent.
    pub fn authorize(&mut self, vni: Vni, domain: u32) -> Result<(), Error> {
        if let Some(current) = self.domains.get(&vni) {
            return if *current == domain {
                Ok(())
            } else {
                Err(Error::Conflict)
            };
        }
        if self.domains.len() == self.maximum {
            return Err(Error::Capacity);
        }
        self.domains.insert(vni, domain);
        Ok(())
    }
    /// Resolve a configured VNI before injecting its payload into a bridge domain.
    pub fn lookup(&self, vni: Vni) -> Result<u32, Error> {
        self.domains.get(&vni).copied().ok_or(Error::Unauthorized)
    }
    /// Explicitly remove a mapping; a runtime must first drain its old traffic.
    pub fn remove(&mut self, vni: Vni) -> Option<u32> {
        self.domains.remove(&vni)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn golden_header_and_opaque_ethernet_roundtrip() -> Result<(), Error> {
        let vni = Vni::new(0x123456)?;
        let frame = [0x88; 64];
        let mut output = [0; 100];
        let size = encode(vni, &frame, &mut output)?;
        assert_eq!(&output[..8], &[8, 0, 0, 0, 0x12, 0x34, 0x56, 0]);
        assert_eq!(
            decode(&output[..size], 64)?,
            Packet {
                vni,
                ethernet: &frame
            }
        );
        assert_eq!(decode(&output[..size], 63), Err(Error::FrameTooLarge));
        assert!(Vni::new(0x1000000).is_err());
        Ok(())
    }
    #[test]
    fn rejects_short_and_nonbase_headers_without_output_changes() -> Result<(), Error> {
        let vni = Vni::new(0)?;
        let mut output = [0xaa; 22];
        assert_eq!(
            encode(vni, &[0; 15], &mut output),
            Err(Error::OutputTooSmall)
        );
        assert_eq!(output, [0xaa; 22]);
        encode(vni, &[0; 14], &mut output)?;
        for end in 0..22 {
            assert!(decode(&output[..end], MAX_FRAME).is_err());
        }
        for offset in [0, 1, 2, 3, 7] {
            let mut bad = output;
            bad[offset] = 255;
            assert_eq!(decode(&bad, MAX_FRAME), Err(Error::Header));
        }
        Ok(())
    }
    #[test]
    fn exact_frame_bound_and_mapping_isolation() -> Result<(), Error> {
        let a = Vni::new(0xffffff)?;
        let b = Vni::new(2)?;
        let frame = vec![0x42; MAX_FRAME];
        let mut output = vec![0; MAX_FRAME + HEADER_LEN];
        let size = encode(a, &frame, &mut output)?;
        assert_eq!(decode(&output[..size], MAX_FRAME)?.ethernet, frame);
        assert_eq!(
            encode(a, &vec![0; MAX_FRAME + 1], &mut output),
            Err(Error::FrameTooLarge)
        );
        let mut map = DomainMap::new(1)?;
        map.authorize(a, 100)?;
        map.authorize(a, 100)?;
        assert_eq!(map.authorize(a, 200), Err(Error::Conflict));
        assert_eq!(map.lookup(b), Err(Error::Unauthorized));
        assert_eq!(map.authorize(b, 200), Err(Error::Capacity));
        assert_eq!(map.lookup(a), Ok(100));
        assert_eq!(map.remove(a), Some(100));
        map.authorize(b, 200)?;
        assert_eq!(map.lookup(b), Ok(200));
        Ok(())
    }
}
