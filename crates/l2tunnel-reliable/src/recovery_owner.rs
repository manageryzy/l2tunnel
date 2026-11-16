//! One selected recovery owner; every branch delegates its actual state machine.
use super::*;
use l2tunnel_recovery::{CompactRepeat, SourceId};

pub(super) enum Owner {
    Legacy(SelectiveRepeat),
    Compact(CompactRepeat),
}
macro_rules! dispatch {
    ($self:expr, $owner:ident => $body:expr) => {
        match $self {
            Owner::Legacy($owner) => $body,
            Owner::Compact($owner) => $body,
        }
    };
}
impl Owner {
    pub fn compact(&self) -> Result<&CompactRepeat, RecoveryError> {
        match self {
            Self::Compact(owner) => Ok(owner),
            Self::Legacy(_) => Err(RecoveryError::InvalidConfig),
        }
    }
    pub fn compact_mut(&mut self) -> Result<&mut CompactRepeat, RecoveryError> {
        match self {
            Self::Compact(owner) => Ok(owner),
            Self::Legacy(_) => Err(RecoveryError::InvalidConfig),
        }
    }
    pub fn is_compact(&self) -> bool {
        matches!(self, Self::Compact(_))
    }
    pub fn source_confirmed(&self, source: SourceId) -> Result<bool, RecoveryError> {
        match self {
            Self::Legacy(owner) => owner.source_confirmed(source),
            Self::Compact(_) => Err(RecoveryError::InvalidConfig),
        }
    }
    pub fn next_source_id(&self) -> Result<SourceId, RecoveryError> {
        dispatch!(self, owner => owner.next_source_id())
    }
    pub fn submit(&mut self, bytes: &[u8], now: Duration) -> Result<u64, RecoveryError> {
        dispatch!(self, owner => owner.submit(bytes, now))
    }
    pub fn receive(&mut self, bytes: &[u8], now: Duration) -> Result<(), RecoveryError> {
        dispatch!(self, owner => owner.receive(bytes, now))
    }
    pub fn receive_at(
        &mut self,
        bytes: &[u8],
        received: Duration,
        observed: Duration,
    ) -> Result<(), RecoveryError> {
        match self {
            Self::Legacy(owner) => owner.receive(bytes, observed),
            Self::Compact(owner) => owner.receive_at(bytes, received, observed),
        }
    }
    pub fn enable_physical_send_confirmation(&mut self) -> Result<(), RecoveryError> {
        match self {
            Self::Legacy(owner) => owner.enable_physical_send_confirmation(),
            Self::Compact(_) => Err(RecoveryError::InvalidConfig),
        }
    }
    pub fn pending_transmission(&self, source: SourceId) -> Option<PhysicalTransmission> {
        dispatch!(self, owner => owner.pending_transmission(source))
    }
    pub fn confirm_transmission_at(
        &mut self,
        observed: Duration,
        accepted: Duration,
        token: PhysicalTransmission,
    ) -> Result<(), RecoveryError> {
        dispatch!(self, owner => owner.confirm_transmission_at(observed, accepted, token))
    }
    pub fn poll_source(
        &mut self,
        now: Duration,
        out: &mut [u8],
    ) -> Result<Option<usize>, RecoveryError> {
        dispatch!(self, owner => owner.poll_source(now, out))
    }
    pub fn poll_feedback(
        &mut self,
        now: Duration,
        out: &mut [u8],
    ) -> Result<Option<usize>, RecoveryError> {
        dispatch!(self, owner => owner.poll_feedback(now, out))
    }
    pub fn compact_packet_bytes(
        &self,
        now: Duration,
        feedback: bool,
    ) -> Result<Option<usize>, RecoveryError> {
        match self {
            Self::Compact(owner) if feedback => owner.feedback_packet_bytes(now),
            Self::Compact(owner) => owner.source_packet_bytes(now),
            Self::Legacy(_) => Err(RecoveryError::InvalidConfig),
        }
    }
    pub fn poll_delivered(
        &mut self,
        out: &mut [u8],
    ) -> Result<Option<(u64, usize)>, RecoveryError> {
        dispatch!(self, owner => owner.poll_delivered(out))
    }
    pub fn received_sources(
        &self,
    ) -> Result<impl Iterator<Item = (SourceId, &[u8])>, RecoveryError> {
        let legacy = if let Self::Legacy(owner) = self {
            Some(owner.received_sources()?)
        } else {
            None
        };
        let compact = if let Self::Compact(owner) = self {
            Some(owner.received_sources()?)
        } else {
            None
        };
        Ok(legacy
            .into_iter()
            .flatten()
            .chain(compact.into_iter().flatten()))
    }
    pub fn source_deadline(&self) -> Option<Duration> {
        dispatch!(self, owner => owner.source_deadline())
    }
    pub fn feedback_deadline(&self) -> Option<Duration> {
        dispatch!(self, owner => owner.feedback_deadline())
    }
    pub fn deadline(&self) -> Option<Duration> {
        dispatch!(self, owner => owner.deadline())
    }
    pub fn drained(&self) -> bool {
        dispatch!(self, owner => owner.drained())
    }
    pub fn statistics(&self) -> ArqStatistics {
        dispatch!(self, owner => owner.statistics())
    }
    pub fn retained(&self) -> Retained {
        dispatch!(self, owner => owner.retained())
    }
    pub fn failure(&self) -> Option<RecoveryError> {
        dispatch!(self, owner => owner.failure())
    }
    #[cfg(test)]
    pub fn storage_usage(&self) -> Option<l2tunnel_recovery::storage::Usage> {
        dispatch!(self, owner => owner.storage_usage())
    }
}
