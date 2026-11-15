//! Storage operations only; sequence, ACK and timer authority stays in Engine.

use super::{BufferSide, Flight, RecoveryError, SourceId};
use std::{collections::BTreeMap, time::Duration};

#[derive(Debug)]
pub(crate) struct SendSlot {
    pub(super) source: Option<SourceId>,
    pub(super) flight: Flight,
}
#[derive(Debug)]
pub(crate) struct ReceiveSlot {
    pub(super) source: Option<SourceId>,
    pub(super) payload: Vec<u8>,
}
#[derive(Debug)]
pub(super) enum Sent {
    Legacy(BTreeMap<SourceId, Flight>),
    Reserved(Vec<SendSlot>),
}
impl Sent {
    pub(super) fn iter(&self) -> impl Iterator<Item = (&SourceId, &Flight)> {
        let (map, slots) = match self {
            Self::Legacy(map) => (Some(map), None),
            Self::Reserved(slots) => (None, Some(slots)),
        };
        map.into_iter().flat_map(|map| map.iter()).chain(
            slots
                .into_iter()
                .flat_map(|slots| slots.iter())
                .filter_map(|slot| slot.source.as_ref().map(|source| (source, &slot.flight))),
        )
    }
    pub(super) fn values(&self) -> impl Iterator<Item = &Flight> {
        self.iter().map(|(_, flight)| flight)
    }
    pub(super) fn len(&self) -> usize {
        self.iter().count()
    }
    pub(super) fn is_empty(&self) -> bool {
        self.len() == 0
    }
    pub(super) fn contains_key(&self, source: &SourceId) -> bool {
        self.get(source).is_some()
    }
    pub(super) fn first_key_value(&self) -> Option<(&SourceId, &Flight)> {
        self.iter().min_by_key(|(source, _)| **source)
    }
    pub(super) fn get(&self, source: &SourceId) -> Option<&Flight> {
        self.iter()
            .find_map(|(id, flight)| (id == source).then_some(flight))
    }
    pub(super) fn get_mut(&mut self, source: &SourceId) -> Option<&mut Flight> {
        match self {
            Self::Legacy(map) => map.get_mut(source),
            Self::Reserved(slots) => slots
                .iter_mut()
                .find(|slot| slot.source.as_ref() == Some(source))
                .map(|slot| &mut slot.flight),
        }
    }
    pub(super) fn insert_payload(
        &mut self,
        source: SourceId,
        payload: &[u8],
        rto: Duration,
    ) -> Result<(), RecoveryError> {
        match self {
            Self::Legacy(map) => {
                map.insert(
                    source,
                    Flight {
                        payload: payload.to_vec(),
                        attempts: 0,
                        retry_at: None,
                        rto,
                    },
                );
            }
            Self::Reserved(slots) => {
                let slot = slots
                    .iter_mut()
                    .find(|slot| {
                        slot.source.is_none() && slot.flight.payload.capacity() >= payload.len()
                    })
                    .ok_or(RecoveryError::Capacity(BufferSide::Send))?;
                slot.flight.payload.clear();
                slot.flight.payload.extend_from_slice(payload);
                slot.flight.attempts = 0;
                slot.flight.retry_at = None;
                slot.flight.rto = rto;
                slot.source = Some(source);
            }
        }
        Ok(())
    }
    pub(super) fn remove(&mut self, source: &SourceId) {
        match self {
            Self::Legacy(map) => {
                map.remove(source);
            }
            Self::Reserved(slots) => {
                if let Some(slot) = slots
                    .iter_mut()
                    .find(|slot| slot.source.as_ref() == Some(source))
                {
                    slot.source = None;
                    slot.flight.payload.clear();
                    slot.flight.attempts = 0;
                    slot.flight.retry_at = None;
                }
            }
        }
    }
    pub(super) fn retain(&mut self, mut keep: impl FnMut(&SourceId, &Flight) -> bool) {
        match self {
            Self::Legacy(map) => map.retain(|source, flight| keep(source, flight)),
            Self::Reserved(slots) => {
                for slot in slots {
                    if slot
                        .source
                        .as_ref()
                        .is_some_and(|source| !keep(source, &slot.flight))
                    {
                        slot.source = None;
                        slot.flight.payload.clear();
                        slot.flight.attempts = 0;
                        slot.flight.retry_at = None;
                    }
                }
            }
        }
    }
}

#[derive(Debug)]
pub(super) enum Received {
    Legacy(BTreeMap<SourceId, Vec<u8>>),
    Reserved(Vec<ReceiveSlot>),
}
impl Received {
    pub(super) fn iter(&self) -> impl Iterator<Item = (&SourceId, &Vec<u8>)> {
        let (map, slots) = match self {
            Self::Legacy(map) => (Some(map), None),
            Self::Reserved(slots) => (None, Some(slots)),
        };
        map.into_iter().flat_map(|map| map.iter()).chain(
            slots
                .into_iter()
                .flat_map(|slots| slots.iter())
                .filter_map(|slot| slot.source.as_ref().map(|source| (source, &slot.payload))),
        )
    }
    pub(super) fn keys(&self) -> impl Iterator<Item = &SourceId> {
        self.iter().map(|(source, _)| source)
    }
    pub(super) fn len(&self) -> usize {
        self.iter().count()
    }
    pub(super) fn is_empty(&self) -> bool {
        self.len() == 0
    }
    pub(super) fn contains_key(&self, source: &SourceId) -> bool {
        self.get(source).is_some()
    }
    pub(super) fn get(&self, source: &SourceId) -> Option<&Vec<u8>> {
        self.iter()
            .find_map(|(id, payload)| (id == source).then_some(payload))
    }
    pub(super) fn insert_payload(
        &mut self,
        source: SourceId,
        payload: &[u8],
    ) -> Result<(), RecoveryError> {
        match self {
            Self::Legacy(map) => {
                map.insert(source, payload.to_vec());
            }
            Self::Reserved(slots) => {
                let slot = slots
                    .iter_mut()
                    .find(|slot| slot.source.is_none() && slot.payload.capacity() >= payload.len())
                    .ok_or(RecoveryError::Capacity(BufferSide::Receive))?;
                slot.payload.clear();
                slot.payload.extend_from_slice(payload);
                slot.source = Some(source);
            }
        }
        Ok(())
    }
    pub(super) fn remove(&mut self, source: &SourceId) {
        match self {
            Self::Legacy(map) => {
                map.remove(source);
            }
            Self::Reserved(slots) => {
                if let Some(slot) = slots
                    .iter_mut()
                    .find(|slot| slot.source.as_ref() == Some(source))
                {
                    slot.source = None;
                    slot.payload.clear();
                }
            }
        }
    }
}
