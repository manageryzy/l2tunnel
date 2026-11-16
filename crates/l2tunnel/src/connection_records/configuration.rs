//! Explicit directional policy for the proposed CompleteV2 tag8 integration.
use super::*;

/// Active versioned directional bytes; the containing356-byte slot stays strict padded.
pub const DIRECTION_BYTES: usize = aligned::COMPACT_CONFIG_BYTES + 28;

/// Complete actual independent-owner direction, separate from runtime capability.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Direction {
    /// Complete genuine single-channel Compact codec/recovery policy.
    pub compact: aligned::CompactConfig,
    /// Actual independent owners, not a renamed codec channel count.
    pub owners: u16,
    /// Immutable positive fixed-cohort incarnation.
    pub incarnation: u64,
    /// Explicit raw ACK selection and finite original limits; None means recovered.
    pub unreliable: Option<UnreliableConfig>,
}
impl Direction {
    /// Validate representable policy without constructing owners or upgrading capability.
    pub fn validate(self) -> Result<(), Error> {
        self.compact.validate().map_err(Error::Endpoint)?;
        if !(1..=256).contains(&self.owners)
            || self.incarnation == 0
            || self.compact.receiver.channels != 1
        {
            return Err(Error::Configuration);
        }
        if let Some(policy) = self.unreliable {
            policy.validate(self.compact.receiver.body.max_frame_bytes)?;
        }
        Ok(())
    }

    /// Encode exact complete policy; it does not select or install proposed tag8.
    pub fn encode_into(self, output: &mut [u8]) -> Result<(), Error> {
        if output.len() != DIRECTION_BYTES {
            return Err(Error::Configuration);
        }
        self.validate()?;
        let mut bytes = [0; DIRECTION_BYTES];
        let base = aligned::COMPACT_CONFIG_BYTES;
        self.compact
            .encode_into(&mut bytes[..base])
            .map_err(Error::Endpoint)?;
        bytes[base] = 1;
        bytes[base + 1..base + 3].copy_from_slice(&self.owners.to_be_bytes());
        bytes[base + 3..base + 11].copy_from_slice(&self.incarnation.to_be_bytes());
        if let Some(policy) = self.unreliable {
            bytes[base + 11] = 1;
            bytes[base + 12..base + 20].copy_from_slice(
                &u64::try_from(policy.max_bytes)
                    .map_err(|_| Error::Arithmetic)?
                    .to_be_bytes(),
            );
            bytes[base + 20..base + 28].copy_from_slice(&policy.hold_micros.to_be_bytes());
        }
        output.copy_from_slice(&bytes);
        Ok(())
    }

    /// Decode exact active bytes, including inactive path limits required to be zero.
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != DIRECTION_BYTES {
            return Err(Error::Configuration);
        }
        let base = aligned::COMPACT_CONFIG_BYTES;
        if bytes[base] != 1 {
            return Err(Error::Configuration);
        }
        let mut incarnation = [0; 8];
        incarnation.copy_from_slice(&bytes[base + 3..base + 11]);
        let mut maximum = [0; 8];
        maximum.copy_from_slice(&bytes[base + 12..base + 20]);
        let mut hold = [0; 8];
        hold.copy_from_slice(&bytes[base + 20..base + 28]);
        let maximum = u64::from_be_bytes(maximum);
        let hold_micros = u64::from_be_bytes(hold);
        let unreliable = match bytes[base + 11] {
            0 if maximum == 0 && hold_micros == 0 => None,
            1 => Some(UnreliableConfig {
                max_bytes: usize::try_from(maximum).map_err(|_| Error::Arithmetic)?,
                hold_micros,
            }),
            _ => return Err(Error::Configuration),
        };
        let direction = Self {
            compact: aligned::CompactConfig::decode(&bytes[..base]).map_err(Error::Endpoint)?,
            owners: u16::from_be_bytes([bytes[base + 1], bytes[base + 2]]),
            incarnation: u64::from_be_bytes(incarnation),
            unreliable,
        };
        direction.validate()?;
        Ok(direction)
    }
}

impl Config {
    /// Bind exact directional requests to independently verified external geometry.
    /// No Compact overhead or requested byte limit is silently rebased or clamped.
    pub fn from_directions(
        send: Direction,
        receive: Direction,
        send_carrier_overhead_bytes: usize,
        receive_carrier_overhead_bytes: usize,
    ) -> Result<Self, Error> {
        send.validate()?;
        receive.validate()?;
        if send.owners != receive.owners
            || send.incarnation != receive.incarnation
            || send.unreliable.is_some() != receive.unreliable.is_some()
            || (send.compact.native_policy == aligned::NativePolicy::EthernetHeaders)
                != (receive.compact.native_policy == aligned::NativePolicy::EthernetHeaders)
        {
            return Err(Error::Configuration);
        }
        let config = Self {
            owners: send.owners,
            incarnation: send.incarnation,
            send: send.compact,
            receive: receive.compact,
            send_carrier_overhead_bytes,
            receive_carrier_overhead_bytes,
            send_unreliable: send.unreliable,
            receive_unreliable: receive.unreliable,
        };
        storage::Plan::for_collection(config)?;
        Ok(config)
    }
}
