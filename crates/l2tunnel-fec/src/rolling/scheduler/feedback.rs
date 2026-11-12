use super::*;

/// Fixed structural feedback bytes; outer authentication/framing is additional.
pub const FEEDBACK_BYTES: usize = 64;
/// Independent nonwrapping feedback identity, starting at one.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct FeedbackId(pub u64);
/// Cumulative actual receiver state; it grants no native-delivery authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Feedback {
    /// Domain of the acknowledged forward coding stream, including its direction.
    pub scope: Scope,
    /// Full feedback identity; retransmissions retain this identity and all bytes.
    pub id: FeedbackId,
    /// Actual decoder published receipt prefix, separate from native delivery.
    pub prefix: u32,
    /// Actual greatest committed source end, including equations.
    pub observed_end: u32,
    /// Unknown source count minus independent retained rank, floored at zero.
    pub deficit: u32,
}
impl Feedback {
    pub(super) fn validate(self, config: Config) -> Result<(), Error> {
        config.validate()?;
        if self.id.0 == 0 || self.id.0 == u64::MAX {
            return Err(Error::Identity);
        }
        let extent = self
            .observed_end
            .checked_sub(self.prefix)
            .ok_or(Error::Identity)?;
        if extent as usize > config.window || self.deficit > extent {
            return Err(Error::Identity);
        }
        Ok(())
    }
    pub(super) fn byte(self, at: usize) -> u8 {
        match at {
            0..=3 => b"L2RF"[at],
            4 => 1,
            5 => 3,
            8..=23 => self.scope.session[at - 8],
            24..=31 => self.scope.epoch.to_be_bytes()[at - 24],
            32..=35 => self.scope.stream.to_be_bytes()[at - 32],
            36 => self.scope.direction,
            40..=47 => self.id.0.to_be_bytes()[at - 40],
            48..=51 => self.prefix.to_be_bytes()[at - 48],
            52..=55 => self.observed_end.to_be_bytes()[at - 52],
            56..=59 => self.deficit.to_be_bytes()[at - 56],
            _ => 0,
        }
    }
}
/// Encode one structural receipt atomically; errors leave caller bytes unchanged.
pub fn encode_feedback(
    config: Config,
    feedback: Feedback,
    output: &mut [u8],
) -> Result<usize, Error> {
    feedback.validate(config)?;
    if output.len() < FEEDBACK_BYTES {
        return Err(Error::OutputTooSmall);
    }
    for (at, byte) in output.iter_mut().take(FEEDBACK_BYTES).enumerate() {
        *byte = feedback.byte(at);
    }
    Ok(FEEDBACK_BYTES)
}
fn array<const N: usize>(bytes: &[u8]) -> Result<[u8; N], Error> {
    bytes.try_into().map_err(|_| Error::Length)
}
/// Inspect exactly one bounded structural receipt; compare/authenticate its scope externally.
pub fn decode_feedback(config: Config, bytes: &[u8]) -> Result<Feedback, Error> {
    config.validate()?;
    if bytes.len() != FEEDBACK_BYTES {
        return Err(Error::Length);
    }
    if &bytes[..4] != b"L2RF"
        || bytes[4] != 1
        || bytes[5] != 3
        || bytes[6..8] != [0; 2]
        || bytes[37..40] != [0; 3]
        || bytes[60..64] != [0; 4]
    {
        return Err(Error::Format);
    }
    let value = Feedback {
        scope: Scope {
            session: array(&bytes[8..24])?,
            epoch: u64::from_be_bytes(array(&bytes[24..32])?),
            stream: u32::from_be_bytes(array(&bytes[32..36])?),
            direction: bytes[36],
        },
        id: FeedbackId(u64::from_be_bytes(array(&bytes[40..48])?)),
        prefix: u32::from_be_bytes(array(&bytes[48..52])?),
        observed_end: u32::from_be_bytes(array(&bytes[52..56])?),
        deficit: u32::from_be_bytes(array(&bytes[56..60])?),
    };
    value.validate(config)?;
    Ok(value)
}
