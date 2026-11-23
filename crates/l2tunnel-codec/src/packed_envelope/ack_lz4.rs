//! Optional systematic-wire representation of one complete, independently decodable Packed source.
#[cfg(feature = "lz4")]
use super::decode_compact;
use super::{Config, Error, Scope, SourceId};

const MARKER: u8 = 0;
#[cfg(feature = "lz4")]
const HEADER: usize = 3;

/// Negotiated bounds for independently compressing a source of raw IPv4 ACKs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AckLz4Config {
    /// Geometry of the ordinary compact Packed plaintext.
    pub packed: Config,
    /// Maximum original bytes allowed by the recovery source.
    pub max_source_bytes: usize,
    /// Maximum native packet to qualify as a short ACK, in 1..=128 bytes.
    pub max_ack_bytes: usize,
}

/// Reusable scratch hash table. Its contents are cleared by the provider on each call.
pub struct AckLz4Table {
    #[cfg(feature = "lz4")]
    table: lz4_flex::block::CompressTable,
}

impl AckLz4Table {
    /// Create a table once when the sender enables this negotiated representation.
    pub fn new() -> Result<Self, Error> {
        #[cfg(feature = "lz4")]
        return Ok(Self {
            table: lz4_flex::block::CompressTable::small(),
        });
        #[cfg(not(feature = "lz4"))]
        Err(Error::CompressionUnavailable)
    }

    /// Heap bytes used by the pinned provider's 4096-entry small u16 table.
    pub const fn planned_bytes() -> usize {
        if cfg!(feature = "lz4") {
            4096 * size_of::<u16>()
        } else {
            0
        }
    }
    /// Capacity on the heap, excluding this handle.
    pub const fn capacity_bytes(&self) -> usize {
        Self::planned_bytes()
    }
    /// Number of provider-owned heap allocations.
    pub const fn allocations(&self) -> usize {
        cfg!(feature = "lz4") as usize
    }
}

impl AckLz4Config {
    fn bound(self) -> Result<usize, Error> {
        let packed = self.packed.max_source_bytes()?;
        if !(1..=usize::from(u16::MAX)).contains(&self.max_source_bytes)
            || !(1..=128).contains(&self.max_ack_bytes)
        {
            return Err(Error::Configuration);
        }
        Ok(self.max_source_bytes.min(packed))
    }
    /// Worst-case encoding scratch including the marker and exact original length.
    pub fn encode_scratch_len(self) -> Result<usize, Error> {
        let bound = self.bound()?;
        #[cfg(feature = "lz4")]
        return Ok(HEADER + lz4_flex::block::get_maximum_output_size(bound));
        #[cfg(not(feature = "lz4"))]
        {
            let _ = bound;
            Err(Error::CompressionUnavailable)
        }
    }

    #[cfg(feature = "lz4")]
    fn qualifies(self, scope: Scope, source: SourceId, plain: &[u8]) -> Result<bool, Error> {
        let view = decode_compact(self.packed, scope, source, plain)?;
        Ok(view.units()?.all(|unit| {
            // Compact validation has already checked the entire tag-2 length field.
            unit.bytes.get(3) == Some(&2)
                && unit.bytes.get(6..).is_some_and(|ip| {
                    ip.len() <= self.max_ack_bytes && crate::tcp_header::pure_ipv4_ack(ip)
                })
        }))
    }

    /// Return the useful scratch prefix only if the complete wrapped block shrinks.
    /// On `None` the caller sends the original unchanged. Scratch is private workspace.
    pub fn try_encode(
        self,
        scope: Scope,
        source: SourceId,
        plain: &[u8],
        scratch: &mut [u8],
        table: &mut AckLz4Table,
    ) -> Result<Option<usize>, Error> {
        if plain.is_empty() || plain.len() > self.bound()? {
            return Err(Error::Malformed);
        }
        #[cfg(feature = "lz4")]
        {
            if !self.qualifies(scope, source, plain)? {
                return Ok(None);
            }
            let needed = HEADER + lz4_flex::block::get_maximum_output_size(plain.len());
            let work = scratch
                .get_mut(..needed)
                .ok_or(Error::OutputTooSmall { needed })?;
            // At most 255 units of at most 128 native bytes fit this profile.
            // The provider's u16 table can therefore never trigger its 64K upgrade.
            let n = lz4_flex::block::compress_into_with_table(
                plain,
                &mut work[HEADER..],
                &mut table.table,
            )
            .map_err(|_| Error::Malformed)?;
            if HEADER + n >= plain.len() {
                return Ok(None);
            }
            work[0] = MARKER;
            work[1..HEADER].copy_from_slice(&(plain.len() as u16).to_be_bytes());
            Ok(Some(HEADER + n))
        }
        #[cfg(not(feature = "lz4"))]
        {
            let _ = (scope, source, scratch, table);
            Err(Error::CompressionUnavailable)
        }
    }

    /// Open an authenticated systematic source before applying it to the FEC decoder.
    /// Ordinary nonzero-count Packed bytes return `None` for the normal decoder.
    /// Only `Some(n)` exposes valid restored plaintext in `scratch[..n]`.
    pub fn decode(
        self,
        scope: Scope,
        source: SourceId,
        wire: &[u8],
        scratch: &mut [u8],
    ) -> Result<Option<usize>, Error> {
        let bound = self.bound()?;
        if wire.is_empty() || wire.len() > bound {
            return Err(Error::Malformed);
        }
        if wire[0] != MARKER {
            return Ok(None);
        }
        #[cfg(feature = "lz4")]
        {
            if wire.len() <= HEADER {
                return Err(Error::Malformed);
            }
            let n = usize::from(u16::from_be_bytes([wire[1], wire[2]]));
            if n > bound || n <= wire.len() {
                return Err(Error::Malformed);
            }
            let plain = scratch
                .get_mut(..n)
                .ok_or(Error::OutputTooSmall { needed: n })?;
            let written = lz4_flex::block::decompress_into(&wire[HEADER..], plain)
                .map_err(|_| Error::Malformed)?;
            if written != n || !self.qualifies(scope, source, plain)? {
                return Err(Error::Malformed);
            }
            Ok(Some(n))
        }
        #[cfg(not(feature = "lz4"))]
        {
            let _ = (scope, source, scratch);
            Err(Error::CompressionUnavailable)
        }
    }
}
