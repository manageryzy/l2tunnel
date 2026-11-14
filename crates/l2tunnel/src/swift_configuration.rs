//! Complete canonical Swift values for an explicitly selected transaction adapter.
//!
//! These pure values bind complete globally ordered directions and a typed
//! immutable-envelope label. They do not authenticate that label, validate a
//! carrier's geometry, reserve prepared engines or select a runtime backend.

use l2tunnel_core::Duplex;
use l2tunnel_management::{Role, transaction};
use l2tunnel_swift::{policy, records};
use ring::digest;
use std::fmt;

/// Exact complete configuration size, inside management's existing 512-byte bound.
pub const CONFIGURATION_BYTES: usize = 304;
/// Exact anchor-free descriptor size used for canonical catalog hashing.
pub const DESCRIPTOR_BYTES: usize = 272;
/// Existing generic peer's maximum number of exact supported configurations.
pub const MAX_CATALOG_ENTRIES: usize = 64;
const PREFIX: [u8; 8] = *b"L2TC\x01\x01\x01\x00";
const DIRECTION_BYTES: usize = 128;
const CATALOG_DOMAIN: &[u8] = b"l2tunnel/swift-transaction-catalog/v1\0";

/// Exact immutable-envelope label; construction is not authentication evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EnvelopeDigest([u8; 32]);
impl EnvelopeDigest {
    /// Label the caller's exact public digest without granting trust or authority.
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
    /// Borrow the unchanged label for the actual authenticated contract builder.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Domain-separated root of a sorted, exact, anchor-free supported catalog.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CatalogDigest([u8; 32]);
impl CatalogDigest {
    /// Borrow the root bytes; the actual runtime must authenticate their binding.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Bounded canonical value or catalog refusal, without peer-provided text.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// An exact canonical input/output length is wrong.
    Length,
    /// Magic, version, algorithm, duplex or reserved bytes differ.
    Prefix,
    /// A wire integer cannot fit its target type without truncation.
    Integer,
    /// Active IP MTU is outside 256..=65535.
    PathMtu,
    /// A complete directional Swift policy fails its existing scalar validation.
    Direction,
    /// Original native layers/maxima differ or a maximum is empty.
    NativeFormat,
    /// A supported catalog is empty or contains more than 64 entries.
    CatalogSize,
    /// Two supported entries have identical complete canonical descriptor bytes.
    Duplicate,
    /// The exact initial descriptor is absent from the supported catalog.
    Unlisted,
}
impl fmt::Display for Error {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        output.write_str(match self {
            Self::Length => "incorrect Swift canonical value length",
            Self::Prefix => "unsupported Swift canonical value prefix",
            Self::Integer => "Swift canonical integer conversion refused",
            Self::PathMtu => "Swift canonical path MTU outside bounds",
            Self::Direction => "invalid complete Swift direction",
            Self::NativeFormat => "inconsistent Swift native packet format",
            Self::CatalogSize => "Swift supported catalog outside bounds",
            Self::Duplicate => "duplicate Swift supported descriptor",
            Self::Unlisted => "initial Swift descriptor is not supported",
        })
    }
}
impl std::error::Error for Error {}

/// Complete mutable Swift value in global initiator/responder direction order.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Descriptor {
    path_mtu: usize,
    forward: policy::Direction,
    reverse: policy::Direction,
}
impl Descriptor {
    /// Check exact scalars/physical format without rounding or runtime effects.
    pub fn new(
        path_mtu: usize,
        forward: policy::Direction,
        reverse: policy::Direction,
    ) -> Result<Self, Error> {
        let value = Self {
            path_mtu,
            forward,
            reverse,
        };
        value.validate()?;
        Ok(value)
    }
    /// Exact active full-IP packet ceiling; actual carrier fit remains external.
    pub const fn path_mtu(&self) -> usize {
        self.path_mtu
    }
    /// Complete initiator/coordinator-to-responder direction.
    pub const fn forward(&self) -> policy::Direction {
        self.forward
    }
    /// Complete responder-to-initiator/coordinator direction.
    pub const fn reverse(&self) -> policy::Direction {
        self.reverse
    }
    /// Select by the authenticated global sender, never the local reader's role.
    pub const fn direction(&self, sender: Role) -> policy::Direction {
        match sender {
            Role::Client => self.forward,
            Role::Server => self.reverse,
        }
    }
    fn validate(&self) -> Result<(), Error> {
        if !(256..=65_535).contains(&self.path_mtu) {
            return Err(Error::PathMtu);
        }
        self.forward.validate().map_err(|_| Error::Direction)?;
        self.reverse.validate().map_err(|_| Error::Direction)?;
        if self.forward.records.layer != self.reverse.records.layer
            || self.forward.records.max_native == 0
            || self.forward.records.max_native != self.reverse.records.max_native
        {
            return Err(Error::NativeFormat);
        }
        Ok(())
    }
    fn encode(&self) -> Result<[u8; DESCRIPTOR_BYTES], Error> {
        self.validate()?;
        let mut output = [0; DESCRIPTOR_BYTES];
        output[..8].copy_from_slice(&PREFIX);
        output[8..16].copy_from_slice(&integer(self.path_mtu)?.to_be_bytes());
        encode_direction(self.forward, &mut output[16..16 + DIRECTION_BYTES])?;
        encode_direction(self.reverse, &mut output[16 + DIRECTION_BYTES..])?;
        Ok(output)
    }
    fn decode_canonical(input: &[u8]) -> Result<Self, Error> {
        if input.len() != DESCRIPTOR_BYTES {
            return Err(Error::Length);
        }
        if input[..8] != PREFIX {
            return Err(Error::Prefix);
        }
        Self::new(
            usize::try_from(read_number(&input[8..16])?).map_err(|_| Error::Integer)?,
            decode_direction(&input[16..16 + DIRECTION_BYTES])?,
            decode_direction(&input[16 + DIRECTION_BYTES..])?,
        )
    }
}

/// Exact complete data configuration; envelope trust is an adapter obligation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Configuration {
    envelope: EnvelopeDigest,
    descriptor: Descriptor,
}
impl Configuration {
    /// Bind a checked complete value to the caller's explicit envelope label.
    pub fn new(envelope: EnvelopeDigest, descriptor: Descriptor) -> Result<Self, Error> {
        descriptor.validate()?;
        Ok(Self {
            envelope,
            descriptor,
        })
    }
    /// Immutable envelope label, without implying authentication.
    pub const fn envelope(&self) -> EnvelopeDigest {
        self.envelope
    }
    /// Complete globally ordered mutable value.
    pub const fn descriptor(&self) -> Descriptor {
        self.descriptor
    }
    fn encode(&self) -> Result<[u8; CONFIGURATION_BYTES], Error> {
        let descriptor = self.descriptor.encode()?;
        let mut output = [0; CONFIGURATION_BYTES];
        output[..8].copy_from_slice(&descriptor[..8]);
        output[8..40].copy_from_slice(self.envelope.as_bytes());
        output[40..].copy_from_slice(&descriptor[8..]);
        Ok(output)
    }
    fn decode_canonical(input: &[u8]) -> Result<Self, Error> {
        if input.len() != CONFIGURATION_BYTES {
            return Err(Error::Length);
        }
        let mut descriptor = [0; DESCRIPTOR_BYTES];
        descriptor[..8].copy_from_slice(&input[..8]);
        descriptor[8..].copy_from_slice(&input[40..]);
        let mut envelope = [0; 32];
        envelope.copy_from_slice(&input[8..40]);
        Self::new(
            EnvelopeDigest::new(envelope),
            Descriptor::decode_canonical(&descriptor)?,
        )
    }
}
impl transaction::Configuration for Configuration {
    const ENCODED_LEN: usize = CONFIGURATION_BYTES;
    const DIGEST_DOMAIN: &'static [u8] = b"l2tunnel/swift-transaction-config/v1\0";

    fn validate(&self) -> Result<(), transaction::Error> {
        self.descriptor
            .validate()
            .map_err(|_| transaction::Error::Configuration("invalid complete Swift value"))
    }
    fn encode_into(&self, output: &mut [u8]) -> Result<(), transaction::Error> {
        if output.len() != CONFIGURATION_BYTES {
            return Err(transaction::Error::Malformed);
        }
        let encoded = self
            .encode()
            .map_err(|_| transaction::Error::Configuration("invalid complete Swift value"))?;
        output.copy_from_slice(&encoded);
        Ok(())
    }
    fn decode(input: &[u8]) -> Result<Self, transaction::Error> {
        Self::decode_canonical(input).map_err(|_| transaction::Error::Malformed)
    }
    fn channels(&self) -> u16 {
        // The private checked constructor admits at most 64 channels. Actual
        // asymmetric adapters must select the explicit directional Peer API.
        self.descriptor.forward.records.channels as u16
    }
    fn sender_channels(&self, sender: Role) -> u16 {
        self.descriptor.direction(sender).records.channels as u16
    }
    fn duplex(&self) -> Duplex {
        Duplex::Full
    }
}

/// Bounded exact supported set, sorted by every anchor-free descriptor byte.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Catalog {
    initial: Descriptor,
    descriptors: Vec<Descriptor>,
    root: CatalogDigest,
}
impl Catalog {
    /// Validate and sort 1..=64 complete values; duplicates/unlisted initial fail.
    pub fn new(initial: Descriptor, supported: &[Descriptor]) -> Result<Self, Error> {
        if !(1..=MAX_CATALOG_ENTRIES).contains(&supported.len()) {
            return Err(Error::CatalogSize);
        }
        initial.validate()?;
        let mut encoded = supported
            .iter()
            .map(|value| Ok((value.encode()?, *value)))
            .collect::<Result<Vec<_>, Error>>()?;
        encoded.sort_unstable_by(|left, right| left.0.cmp(&right.0));
        if encoded.windows(2).any(|pair| pair[0].0 == pair[1].0) {
            return Err(Error::Duplicate);
        }
        if !encoded.iter().any(|(_, value)| *value == initial) {
            return Err(Error::Unlisted);
        }
        let mut context = digest::Context::new(&digest::SHA256);
        context.update(CATALOG_DOMAIN);
        context.update(
            &u16::try_from(encoded.len())
                .map_err(|_| Error::Integer)?
                .to_be_bytes(),
        );
        for (bytes, _) in &encoded {
            context.update(bytes);
        }
        let mut root = [0; 32];
        root.copy_from_slice(context.finish().as_ref());
        Ok(Self {
            initial,
            descriptors: encoded.into_iter().map(|(_, value)| value).collect(),
            root: CatalogDigest(root),
        })
    }
    /// Exact independently checked initial member, without sorting it to the front.
    pub const fn initial(&self) -> Descriptor {
        self.initial
    }
    /// Complete supported descriptors in canonical byte order.
    pub fn descriptors(&self) -> &[Descriptor] {
        &self.descriptors
    }
    /// Root of anchor-free values, avoiding anchored-configuration self-reference.
    pub const fn root(&self) -> CatalogDigest {
        self.root
    }
    /// Bind every already checked member to one exact envelope without changing K.
    pub fn configurations(&self, envelope: EnvelopeDigest) -> Vec<Configuration> {
        self.descriptors
            .iter()
            .map(|descriptor| Configuration {
                envelope,
                descriptor: *descriptor,
            })
            .collect()
    }
}

fn integer(value: usize) -> Result<u64, Error> {
    u64::try_from(value).map_err(|_| Error::Integer)
}
fn encode_direction(direction: policy::Direction, output: &mut [u8]) -> Result<(), Error> {
    if output.len() != DIRECTION_BYTES {
        return Err(Error::Length);
    }
    let records = direction.records;
    let codec = records.codec;
    let values = [
        integer(records.channels)?,
        match records.layer {
            records::Layer::Ethernet => 1,
            records::Layer::Ip => 2,
        },
        integer(records.max_native)?,
        direction.bytes_per_second,
        integer(codec.datagram_bytes)?,
        integer(codec.window)?,
        u64::from(codec.repair_numerator),
        u64::from(codec.repair_denominator),
        integer(codec.flow_sources)?,
        integer(codec.queue_bytes)?,
        integer(codec.max_packet)?,
        codec.flush_micros,
        codec.feedback_micros,
        codec.tail_micros,
        codec.min_rto_micros,
        codec.max_rto_micros,
    ];
    for (slot, value) in output.chunks_exact_mut(8).zip(values) {
        slot.copy_from_slice(&value.to_be_bytes());
    }
    Ok(())
}
fn decode_direction(input: &[u8]) -> Result<policy::Direction, Error> {
    if input.len() != DIRECTION_BYTES {
        return Err(Error::Length);
    }
    let mut values = [0; 16];
    for (value, slot) in values.iter_mut().zip(input.chunks_exact(8)) {
        *value = read_number(slot)?;
    }
    let size = |index: usize| usize::try_from(values[index]).map_err(|_| Error::Integer);
    let small = |index: usize| u32::try_from(values[index]).map_err(|_| Error::Integer);
    let direction = policy::Direction {
        records: records::Config {
            channels: size(0)?,
            layer: match values[1] {
                1 => records::Layer::Ethernet,
                2 => records::Layer::Ip,
                _ => return Err(Error::Direction),
            },
            max_native: size(2)?,
            codec: l2tunnel_swift::Config {
                datagram_bytes: size(4)?,
                window: size(5)?,
                repair_numerator: small(6)?,
                repair_denominator: small(7)?,
                flow_sources: size(8)?,
                queue_bytes: size(9)?,
                max_packet: size(10)?,
                flush_micros: values[11],
                feedback_micros: values[12],
                tail_micros: values[13],
                min_rto_micros: values[14],
                max_rto_micros: values[15],
            },
        },
        bytes_per_second: values[3],
    };
    direction.validate().map_err(|_| Error::Direction)?;
    Ok(direction)
}
fn read_number(input: &[u8]) -> Result<u64, Error> {
    Ok(u64::from_be_bytes(
        input.try_into().map_err(|_| Error::Length)?,
    ))
}

#[cfg(test)]
mod tests;
