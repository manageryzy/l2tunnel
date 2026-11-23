//! Experimental mixed-data datagrams for an authenticated striped group.
//! The selected enclosing profile supplies the coding dimensions and scope.
//! Each body transmits its own original and all of its parity cells. The
//! systematic part's virtual zero extension remains local to the codec.
use crate::{Error, GenerationId, original_length, rolling::wire::compact, striped::Geometry};

/// Number of ordinary inputs, or the original byte length of a split singleton.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GroupShape {
    /// Actual physical group size for ordinary whole originals.
    Originals(u16),
    /// Two mixed packets encode one logical input.
    Split(u16),
}

impl GroupShape {
    /// Derive this short group's effective data and parity cell counts.
    pub fn dimensions(self, k: u16, m: u16) -> Result<(u16, u16), Error> {
        let n = k.checked_add(m).ok_or(Error::InvalidDimensions)?;
        if k == 0 || m == 0 || n > 256 {
            return Err(Error::InvalidDimensions);
        }
        match self {
            Self::Originals(q) if (2..=n).contains(&q) => {
                let parity = (u32::from(q) * u32::from(m)).div_ceil(u32::from(n)) as u16;
                let parity = parity.min(q - 1);
                Ok((q - parity, parity))
            }
            Self::Split(len) if len > 0 => Ok((1, 1)),
            _ => Err(Error::InvalidDimensions),
        }
    }

    fn prefix_len(self) -> usize {
        match self {
            Self::Originals(_) => 1,
            Self::Split(len) => 1 + compact::len(u64::from(len)),
        }
    }

    fn validate_member(self, base: GenerationId, index: u8, length: usize) -> Result<(), Error> {
        match self {
            Self::Originals(q) => {
                base.0
                    .checked_add(u64::from(q - 1))
                    .ok_or(Error::Arithmetic)?;
            }
            Self::Split(total) => {
                let expected = if index == 0 {
                    total.div_ceil(2)
                } else {
                    (total / 2).max(1)
                };
                if length != usize::from(expected) {
                    return Err(Error::InvalidSource);
                }
            }
        }
        Ok(())
    }
}

/// Authenticated nominal geometry and local limits for this selected record family.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Profile {
    /// Recovery threshold for a full group.
    pub data_cells: u16,
    /// Correctable physical erasures in a full group.
    pub parity_cells: u16,
    /// Maximum expanded canonical body retained per member.
    pub max_body_bytes: usize,
    /// Maximum complete mixed plaintext after all outer overhead is subtracted.
    pub max_wire_bytes: usize,
}

impl Profile {
    /// Maximum size of one physical member's original part at this generation.
    pub fn original_limit(self, shape: GroupShape, base: GenerationId) -> Result<usize, Error> {
        let (k, m) = shape.dimensions(self.data_cells, self.parity_cells)?;
        let limit = self
            .max_wire_bytes
            .checked_sub(shape.prefix_len())
            .ok_or(Error::PacketTooLarge)?;
        original_limit(k, m, base, self.max_body_bytes, limit)
    }

    /// Parse an authenticated record. The generation is its first absolute logical source ID.
    pub fn inspect(self, wire: &[u8]) -> Result<(GroupShape, Packet<'_>), Error> {
        if wire.len() > self.max_wire_bytes {
            return Err(Error::PacketTooLarge);
        }
        let (&tag, rest) = wire.split_first().ok_or(Error::Malformed)?;
        let mut pos = 0;
        let shape = if tag == 0 {
            let length = compact::read(rest, &mut pos).map_err(|_| Error::Malformed)?;
            GroupShape::Split(u16::try_from(length).map_err(|_| Error::InvalidSource)?)
        } else {
            GroupShape::Originals(u16::from(tag) + 1)
        };
        let (k, m) = shape.dimensions(self.data_cells, self.parity_cells)?;
        let packet = inspect(
            k,
            m,
            self.max_body_bytes,
            self.max_wire_bytes - 1 - pos,
            &rest[pos..],
        )?;
        shape.validate_member(packet.generation, packet.index, packet.original().len())?;
        Ok((shape, packet))
    }

    /// Encode one complete physical member, leaving caller output untouched on error.
    pub fn encode(
        self,
        shape: GroupShape,
        base: GenerationId,
        index: u8,
        geometry: Geometry,
        body: &[u8],
        output: &mut [u8],
    ) -> Result<usize, Error> {
        if shape.dimensions(self.data_cells, self.parity_cells)?
            != (geometry.data_cells(), geometry.parity_cells())
            || geometry.body_bytes() > self.max_body_bytes
            || body.len() != geometry.body_bytes()
        {
            return Err(Error::InvalidDimensions);
        }
        let length = body.first_chunk::<2>().ok_or(Error::InvalidSource)?;
        shape.validate_member(base, index, usize::from(u16::from_be_bytes(*length)))?;
        let prefix = shape.prefix_len();
        let limit = self
            .max_wire_bytes
            .checked_sub(prefix)
            .ok_or(Error::PacketTooLarge)?;
        let rest = output.get_mut(prefix..).unwrap_or_default();
        let used =
            encode(base, index, geometry, body, limit, rest).map_err(|error| match error {
                Error::OutputTooSmall { required } => Error::OutputTooSmall {
                    required: prefix + required,
                },
                other => other,
            })?;
        match shape {
            GroupShape::Originals(q) => output[0] = (q - 1) as u8,
            GroupShape::Split(length) => {
                output[0] = 0;
                let mut pos = 1;
                compact::write(u64::from(length), output, &mut pos);
            }
        }
        Ok(prefix + used)
    }
}

/// Largest input that fits even when all originals in the generation have this
/// size. `max_wire_bytes` is the path MTU after outer framing/authentication.
/// Reserve the longest applicable generation ID when sizing a fixed epoch.
fn original_limit(
    data_cells: u16,
    parity_cells: u16,
    generation: GenerationId,
    max_body_bytes: usize,
    max_wire_bytes: usize,
) -> Result<usize, Error> {
    let k = usize::from(data_cells);
    let m = usize::from(parity_cells);
    let n = k + m;
    if k == 0 || m == 0 || n > 256 {
        return Err(Error::InvalidDimensions);
    }
    let available = max_wire_bytes
        .checked_sub(compact::len(generation.0) + 1)
        .ok_or(Error::PacketTooLarge)?;
    // Each complete cell-width increment takes k systematic and m parity bytes.
    // A partial increment pays m parity bytes before any next systematic byte.
    let available = available.min(usize::from(u16::MAX));
    let wire_extent = available / n * k + (available % n).saturating_sub(m);
    let body_extent = max_body_bytes.min(usize::from(u16::MAX)) / n * k;
    wire_extent
        .min(body_extent)
        .checked_sub(2)
        .filter(|&v| v != 0)
        .ok_or(Error::PacketTooLarge)
}

/// A structurally valid member of a group under the caller's authenticated profile.
#[derive(Debug)]
pub struct Packet<'a> {
    generation: GenerationId,
    index: u8,
    geometry: Geometry,
    systematic: &'a [u8],
    parity: &'a [u8],
}

impl Packet<'_> {
    /// Group identity within one authenticated direction and epoch.
    pub fn generation(&self) -> GenerationId {
        self.generation
    }

    /// Physical packet position in the group.
    pub fn index(&self) -> u8 {
        self.index
    }

    /// The group's cell width is inferred from the complete parity suffix.
    pub fn geometry(&self) -> Geometry {
        self.geometry
    }

    /// Borrow the systematic original immediately, without allocating or decoding.
    pub fn original(&self) -> &[u8] {
        &self.systematic[2..]
    }

    /// Both logical halves present in a physical singleton, ordered independently
    /// of which ordinal the network delivered. Padding stays outside the slices.
    pub fn split_original(&self, total: u16) -> Result<(&[u8], &[u8]), Error> {
        if self.geometry.data_cells() != 1 || self.geometry.parity_cells() != 1 {
            return Err(Error::InvalidDimensions);
        }
        crate::striped_group::split_cells(
            total,
            self.index,
            self.geometry,
            self.systematic,
            self.parity,
        )
    }

    /// Restore the codec's fixed-width row in caller-owned storage.
    pub fn write_body(&self, output: &mut [u8]) -> Result<usize, Error> {
        let required = self.geometry.body_bytes();
        let output = output
            .get_mut(..required)
            .ok_or(Error::OutputTooSmall { required })?;
        let parity_at = required - self.parity.len();
        output[..self.systematic.len()].copy_from_slice(self.systematic);
        output[self.systematic.len()..parity_at].fill(0);
        output[parity_at..].copy_from_slice(self.parity);
        Ok(required)
    }
}

/// Parse after outer authentication, using separate wire and decoded-body limits.
/// A group owner must also match the generation and geometry of later members.
fn inspect(
    data_cells: u16,
    parity_cells: u16,
    max_body_bytes: usize,
    max_wire_bytes: usize,
    wire: &[u8],
) -> Result<Packet<'_>, Error> {
    if wire.len() > max_wire_bytes {
        return Err(Error::PacketTooLarge);
    }
    let mut pos = 0;
    let generation = GenerationId(compact::read(wire, &mut pos).map_err(|_| Error::Malformed)?);
    let (&index, body) = wire[pos..].split_first().ok_or(Error::Malformed)?;
    let len = body.first_chunk::<2>().ok_or(Error::InvalidSource)?;
    let size = usize::from(u16::from_be_bytes(*len));
    if size == 0 {
        return Err(Error::InvalidSource);
    }
    let (systematic, parity) = body.split_at_checked(2 + size).ok_or(Error::Malformed)?;
    let repairs = usize::from(parity_cells);
    if repairs == 0 || parity.is_empty() || !parity.len().is_multiple_of(repairs) {
        return Err(Error::InvalidDimensions);
    }
    let geometry = Geometry::new(
        data_cells,
        parity_cells,
        parity.len() / repairs,
        max_body_bytes,
    )?;
    if usize::from(index) >= geometry.packet_count() || size > geometry.original_capacity() {
        return Err(Error::InvalidDimensions);
    }
    Ok(Packet {
        generation,
        index,
        geometry,
        systematic,
        parity,
    })
}

/// Serialize one codec row without its systematic fill. Output is unchanged on error.
fn encode(
    generation: GenerationId,
    index: u8,
    geometry: Geometry,
    body: &[u8],
    max_wire_bytes: usize,
    output: &mut [u8],
) -> Result<usize, Error> {
    if body.len() != geometry.body_bytes() || usize::from(index) >= geometry.packet_count() {
        return Err(Error::InvalidDimensions);
    }
    let (systematic, parity) =
        body.split_at(usize::from(geometry.data_cells()) * geometry.cell_bytes());
    let extent = 2 + original_length(systematic)?;
    let required = compact::len(generation.0) + 1 + extent + parity.len();
    if required > max_wire_bytes {
        return Err(Error::PacketTooLarge);
    }
    let output = output
        .get_mut(..required)
        .ok_or(Error::OutputTooSmall { required })?;
    let mut pos = 0;
    compact::write(generation.0, output, &mut pos);
    output[pos] = index;
    pos += 1;
    output[pos..pos + extent].copy_from_slice(&systematic[..extent]);
    output[pos + extent..].copy_from_slice(parity);
    Ok(required)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::striped::Encoder;

    #[test]
    fn full_short_and_split_shapes_bind_dimensions_length_and_source_identity() -> Result<(), Error>
    {
        let profile = Profile {
            data_cells: 8,
            parity_cells: 2,
            max_body_bytes: 1451,
            max_wire_bytes: 1451,
        };
        let base = GenerationId(300);
        let normal = GroupShape::Originals(10);
        assert_eq!(profile.original_limit(normal, base)?, 1155);
        assert_eq!(GroupShape::Originals(6).dimensions(8, 2)?, (4, 2));
        assert_eq!(GroupShape::Originals(5).dimensions(8, 2)?, (4, 1));
        let geom = Geometry::for_group(1, 1, &[b"abc", b"de"], 1451)?;
        let enc = Encoder::new(geom, &[b"abc", b"de"])?;
        let mut body = [0; 10];
        let mut output = [0xff; 32];
        for i in [0, 1] {
            enc.write_packet(i, &mut body)?;
            let shape = GroupShape::Split(5);
            let size = profile.encode(shape, base, i, geom, &body, &mut output)?;
            assert_eq!(&output[..4], &[0, 5, 0xac, 2]);
            let (parsed, member) = profile.inspect(&output[..size])?;
            assert_eq!(parsed, shape);
            assert_eq!(member.index(), i);
            assert_eq!(
                member.original(),
                if i == 0 { b"abc".as_slice() } else { b"de" }
            );
            assert_eq!(
                profile.encode(shape, base, i, geom, &body, &mut []),
                Err(Error::OutputTooSmall { required: size })
            );
            output[1] = 1;
            assert!(profile.inspect(&output[..size]).is_err());
            let regular = GroupShape::Originals(2);
            let size = profile.encode(regular, base, i, geom, &body, &mut output)?;
            assert_eq!(&output[..3], &[1, 0xac, 2]);
            assert_eq!(profile.inspect(&output[..size])?.0, regular);
            assert_eq!(
                profile.encode(regular, GenerationId(u64::MAX), i, geom, &body, &mut output),
                Err(Error::Arithmetic)
            );
        }
        assert!(profile.inspect(&[0, 0x80, 0]).is_err());
        assert!(profile.inspect(&[0, 0]).is_err());
        assert!(profile.inspect(&[10]).is_err());
        Ok(())
    }

    #[test]
    fn compact_python_packets_restore_unequal_originals_and_zero_tails() -> Result<(), Error> {
        let originals: [&[u8]; 5] = [b"A", b"\0\xff\0", b"xyz", b"12345678", b"end\0"];
        let geometry = Geometry::for_group(3, 2, &originals, 20)?;
        let encoder = Encoder::new(geometry, &originals)?;
        let expected: [&[u8]; 5] = [
            b"\xac\x02\0\0\x01A\x97\x1b\xbc\xc7\x38\x36\0\xf6",
            b"\xac\x02\x01\0\x03\0\xff\0\x32\xf3\xe4\xe5\x0f\x94\xe4\x57",
            b"\xac\x02\x02\0\x03xyz\0\xf7\x23\xd1\x4d\x02\x4b\x82",
            b"\xac\x02\x03\0\x0812345678\0\xf4\x3f\0\0\x01\x5e\x95",
            b"\xac\x02\x04\0\x04end\0\x0a\x39\0\x55\0\x47\x57\0",
        ];
        for (index, wire) in expected.into_iter().enumerate() {
            let mut body = [0xa5; 20];
            let mut output = [0xff; 24];
            encoder.write_packet(index as u8, &mut body)?;
            assert_eq!(
                encode(
                    GenerationId(300),
                    index as u8,
                    geometry,
                    &body,
                    wire.len() - 1,
                    &mut output
                ),
                Err(Error::PacketTooLarge)
            );
            assert_eq!(output, [0xff; 24]);
            let size = encode(
                GenerationId(300),
                index as u8,
                geometry,
                &body,
                wire.len(),
                &mut output,
            )?;
            assert_eq!(&output[..size], wire);
            let packet = inspect(3, 2, 20, wire.len(), wire)?;
            assert_eq!(packet.original(), originals[index]);
            assert_eq!(packet.geometry(), geometry);
            assert_eq!(packet.generation(), GenerationId(300));
            assert_eq!(usize::from(packet.index()), index);
            let mut restored = [0x5a; 20];
            packet.write_body(&mut restored)?;
            assert_eq!(restored, body);
        }
        Ok(())
    }

    #[test]
    fn bounds_apply_to_the_transmitted_and_expanded_forms() {
        let short = b"\0\0\0\x01a\x11\x22";
        assert!(inspect(4, 1, 10, short.len(), short).is_ok());
        assert_eq!(
            inspect(4, 1, 9, short.len(), short).err(),
            Some(Error::PacketTooLarge)
        );
        assert_eq!(
            inspect(4, 1, 10, short.len() - 1, short).err(),
            Some(Error::PacketTooLarge)
        );
        for malformed in [
            b"\x80\0\0\0\x01a11".as_slice(), // Noncanonical generation.
            b"\0\x05\0\x01a11",              // Invalid ordinal.
            b"\0\0\0\0xx",                   // Empty original.
            b"\0\0\0\x03x",                  // Truncated original.
            b"\0\0\0\x01x",                  // Missing parity.
        ] {
            assert!(inspect(4, 1, 10, 10, malformed).is_err());
        }
        assert!(inspect(3, 2, 20, 20, b"\0\0\0\x01x123").is_err());
    }

    #[test]
    fn source_limit_matches_the_last_physically_sendable_byte() -> Result<(), Error> {
        let generation = GenerationId(300);
        assert_eq!(original_limit(8, 2, generation, 1451, 1451)?, 1156);
        for (k, m) in [(1u16, 2u16), (4, 1), (8, 2), (4, 3)] {
            for wire_limit in 3..=80usize {
                for body_limit in [13usize, 40, 91] {
                    let expected = (1..=80).rev().find(|&len: &usize| {
                        let width = (len + 2).div_ceil(usize::from(k));
                        width * usize::from(k + m) <= body_limit
                            && 3 + 2 + len + width * usize::from(m) <= wire_limit
                    });
                    assert_eq!(
                        original_limit(k, m, generation, body_limit, wire_limit).ok(),
                        expected
                    );
                }
            }
        }
        Ok(())
    }
}
