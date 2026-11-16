use super::*;

const CHANNELS: usize = 256;

/// Actual native event totals in this Engine's exact directional channel widths.
///
/// These observations do not prove a contiguous prefix, authentication, stopped
/// admission, protocol drain or physical/control custody outside this Engine.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativeCounts<'a> {
    /// Exact original local generation labels; no authority is created by a view.
    pub context: Context,
    /// Exact complete configuration digest of this generation.
    pub digest: ConfigDigest,
    /// Native bodies actually accepted by the local sending codec, per channel.
    pub admitted: &'a [u64],
    /// Actual Ready native bodies extracted locally, per receiving channel.
    pub prepared: &'a [u64],
    /// Whole physical writes reported with exact pending tokens, per channel.
    pub committed: &'a [u64],
}

pub(super) struct Counts {
    admitted: [u64; CHANNELS],
    prepared: [u64; CHANNELS],
    committed: [u64; CHANNELS],
}

impl Default for Counts {
    fn default() -> Self {
        Self {
            admitted: [0; CHANNELS],
            prepared: [0; CHANNELS],
            committed: [0; CHANNELS],
        }
    }
}

impl Counts {
    fn slice(values: &[u64; CHANNELS], width: u16) -> Result<&[u64], Error> {
        if width == 0 {
            return Err(Error::Invariant);
        }
        values.get(..usize::from(width)).ok_or(Error::Invariant)
    }

    fn next_admission(&self, channel: u16, width: u16) -> Result<u64, Error> {
        Self::slice(&self.admitted, width)?
            .get(usize::from(channel))
            .ok_or(Error::Configuration)?
            .checked_add(1)
            .ok_or(Error::Arithmetic)
    }

    pub(super) fn preflight_prepare(&self, width: u16) -> Result<(), Error> {
        let prepared = Self::slice(&self.prepared, width)?;
        let committed = Self::slice(&self.committed, width)?;
        for (&prepared, &committed) in prepared.iter().zip(committed) {
            if committed > prepared {
                return Err(Error::Invariant);
            }
            prepared.checked_add(1).ok_or(Error::Arithmetic)?;
            committed.checked_add(1).ok_or(Error::Arithmetic)?;
        }
        Ok(())
    }

    pub(super) fn prepare(&mut self, identity: ProfileIdentity, width: u16) -> Result<(), Error> {
        let channel = identity_channel(identity);
        Self::slice(&self.prepared, width)?
            .get(channel)
            .ok_or(Error::Invariant)?;
        let count = self.prepared.get_mut(channel).ok_or(Error::Invariant)?;
        *count = count.checked_add(1).ok_or(Error::Arithmetic)?;
        Ok(())
    }

    pub(super) fn next_commit(
        &self,
        identity: ProfileIdentity,
        width: u16,
    ) -> Result<(usize, u64), Error> {
        let channel = identity_channel(identity);
        let prepared = *Self::slice(&self.prepared, width)?
            .get(channel)
            .ok_or(Error::Invariant)?;
        let committed = *Self::slice(&self.committed, width)?
            .get(channel)
            .ok_or(Error::Invariant)?;
        if committed >= prepared {
            return Err(Error::Invariant);
        }
        Ok((channel, committed.checked_add(1).ok_or(Error::Arithmetic)?))
    }

    pub(super) fn commit(&mut self, channel: usize, next: u64) {
        // The original pending identity and exact array index were checked first.
        self.committed[channel] = next;
    }
}

pub(super) fn identity_channel(identity: ProfileIdentity) -> usize {
    match identity {
        ProfileIdentity::Swift(identity) => identity.channel.index(),
        ProfileIdentity::Aligned(identity)
        | ProfileIdentity::Packed(identity)
        | ProfileIdentity::Rolling(identity) => usize::from(identity.channel.0),
    }
}

pub(super) fn offer(
    owner: &mut Owner,
    counts: &mut Counts,
    now: Tick,
    channel: u16,
    width: u16,
    bytes: &[u8],
) -> Result<Option<ProfileIdentity>, Error> {
    let next = counts.next_admission(channel, width)?;
    let admitted = owner.offer(now, channel, bytes)?;
    if admitted.is_some() {
        counts.admitted[usize::from(channel)] = next;
    }
    Ok(admitted)
}

impl Engine {
    /// Borrow actual per-channel native facts, including irreversible late writes.
    ///
    /// A failed Engine remains observable. These totals are not clean-drain or
    /// authenticated prefix proofs; original identities and custody stay separate.
    pub fn native_counts(&self) -> Result<NativeCounts<'_>, Error> {
        let local = self.configuration.descriptor().local(self.context.role);
        Ok(NativeCounts {
            context: self.context,
            digest: self.digest,
            admitted: Counts::slice(&self.native_counts.admitted, local.send().channels())?,
            prepared: Counts::slice(&self.native_counts.prepared, self.receive_channels)?,
            committed: Counts::slice(&self.native_counts.committed, self.receive_channels)?,
        })
    }
}

#[cfg(test)]
#[path = "native_counts_tests.rs"]
mod tests;
