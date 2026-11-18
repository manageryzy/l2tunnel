//! Container operations only; original Reliable decisions remain in its owner.
use super::{Emission, Error, Outgoing, Restored};
use crate::storage::{self, Allocation};
use l2tunnel_fec::{ExpiredGeneration, GenerationId};
use std::collections::{BTreeMap, VecDeque};

pub(crate) struct Building {
    slots: Vec<Vec<u8>>,
    used: usize,
    reserved: bool,
}
impl Building {
    pub fn legacy(n: usize) -> Self {
        Self {
            slots: Vec::with_capacity(n),
            used: 0,
            reserved: false,
        }
    }
    pub fn reserved(n: usize, bytes: usize, a: &mut Allocation) -> Result<Self, storage::Error> {
        let mut slots = a.vec(n)?;
        for _ in 0..n {
            slots.push(a.vec(bytes)?);
        }
        Ok(Self {
            slots,
            used: 0,
            reserved: true,
        })
    }
    pub fn len(&self) -> usize {
        self.used
    }
    pub fn is_empty(&self) -> bool {
        self.used == 0
    }
    pub fn iter(&self) -> impl ExactSizeIterator<Item = &Vec<u8>> + Clone {
        self.slots.iter().take(self.used)
    }
    pub fn push(&mut self, bytes: &[u8]) -> Result<(), Error> {
        if self.reserved {
            let slot = self
                .slots
                .get_mut(self.used)
                .filter(|s| s.capacity() >= bytes.len())
                .ok_or(Error::Exhausted)?;
            slot.clear();
            slot.extend_from_slice(bytes);
        } else {
            self.slots.push(bytes.to_vec());
        }
        self.used += 1;
        Ok(())
    }
    pub fn clear(&mut self) {
        if self.reserved {
            for slot in &mut self.slots {
                slot.clear();
            }
        } else {
            self.slots.clear();
        }
        self.used = 0;
    }
}
pub(crate) enum Queue {
    Legacy(VecDeque<Outgoing>),
    Reserved {
        slots: Vec<Outgoing>,
        head: usize,
        len: usize,
    },
}
impl Queue {
    pub fn legacy(n: usize) -> Self {
        Self::Legacy(VecDeque::with_capacity(n))
    }
    pub fn reserved(n: usize, bytes: usize, a: &mut Allocation) -> Result<Self, storage::Error> {
        let mut slots = a.vec(n)?;
        for _ in 0..n {
            slots.push(Outgoing {
                bytes: a.vec(bytes)?,
                emission: Emission::Systematic,
            });
        }
        Ok(Self::Reserved {
            slots,
            head: 0,
            len: 0,
        })
    }
    pub fn len(&self) -> usize {
        match self {
            Self::Legacy(v) => v.len(),
            Self::Reserved { len, .. } => *len,
        }
    }
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
    pub fn front(&self) -> Option<&Outgoing> {
        match self {
            Self::Legacy(v) => v.front(),
            Self::Reserved { slots, head, len } => (*len != 0).then(|| &slots[*head]),
        }
    }
    pub fn bytes(&self) -> usize {
        match self {
            Self::Legacy(v) => v.iter().map(|s| s.bytes.len()).sum(),
            Self::Reserved { slots, head, len } => (0..*len)
                .map(|i| slots[(*head + i) % slots.len()].bytes.len())
                .sum(),
        }
    }
    pub fn discard_front(&mut self) -> Result<(), Error> {
        match self {
            Self::Legacy(v) => {
                v.pop_front().ok_or(Error::Exhausted)?;
            }
            Self::Reserved { slots, head, len } => {
                if *len == 0 {
                    return Err(Error::Exhausted);
                }
                slots[*head].bytes.clear();
                *head = (*head + 1) % slots.len();
                *len -= 1;
            }
        }
        Ok(())
    }
    pub fn push(
        &mut self,
        size: usize,
        emission: Emission,
        write: impl FnOnce(&mut [u8]) -> Result<usize, Error>,
    ) -> Result<(), Error> {
        match self {
            Self::Legacy(v) => {
                let mut bytes = vec![0; size];
                let length = write(&mut bytes)?;
                bytes.truncate(length);
                v.push_back(Outgoing { bytes, emission });
            }
            Self::Reserved { slots, head, len } => {
                if *len == slots.len() {
                    return Err(Error::Exhausted);
                }
                let index = (*head + *len) % slots.len();
                let target = &mut slots[index];
                if size > target.bytes.capacity() {
                    return Err(Error::Exhausted);
                }
                target.bytes.resize(size, 0);
                let length = write(&mut target.bytes)?;
                target.bytes.truncate(length);
                target.emission = emission;
                *len += 1;
            }
        }
        Ok(())
    }
}
pub(crate) struct RestoredSlot {
    id: Option<u64>,
    value: Restored,
}
pub(crate) enum RestoredMap {
    Legacy(BTreeMap<u64, Restored>),
    Reserved(Vec<RestoredSlot>),
}
impl RestoredMap {
    pub fn legacy() -> Self {
        Self::Legacy(BTreeMap::new())
    }
    pub fn reserved(n: usize, bytes: usize, a: &mut Allocation) -> Result<Self, storage::Error> {
        let mut slots = a.vec(n)?;
        for _ in 0..n {
            slots.push(RestoredSlot {
                id: None,
                value: Restored {
                    bytes: a.vec(bytes)?,
                    recovered: false,
                },
            });
        }
        Ok(Self::Reserved(slots))
    }
    pub fn len(&self) -> usize {
        match self {
            Self::Legacy(m) => m.len(),
            Self::Reserved(v) => v.iter().filter(|s| s.id.is_some()).count(),
        }
    }
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
    pub fn get(&self, id: &u64) -> Option<&Restored> {
        match self {
            Self::Legacy(m) => m.get(id),
            Self::Reserved(v) => v.iter().find(|s| s.id == Some(*id)).map(|s| &s.value),
        }
    }
    pub fn contains_key(&self, id: &u64) -> bool {
        self.get(id).is_some()
    }
    pub fn first_key_value(&self) -> Option<(Option<usize>, &u64, &Restored)> {
        match self {
            Self::Legacy(m) => m.first_key_value().map(|(id, value)| (None, id, value)),
            Self::Reserved(v) => v
                .iter()
                .enumerate()
                .filter_map(|(index, s)| s.id.as_ref().map(|id| (Some(index), id, &s.value)))
                .min_by_key(|(_, id, _)| **id),
        }
    }
    pub fn insert(&mut self, id: u64, bytes: &[u8], recovered: bool) -> Result<(), Error> {
        match self {
            Self::Legacy(m) => {
                m.insert(
                    id,
                    Restored {
                        bytes: bytes.to_vec(),
                        recovered,
                    },
                );
            }
            Self::Reserved(v) => {
                let slot = v
                    .iter_mut()
                    .find(|s| s.id.is_none() && s.value.bytes.capacity() >= bytes.len())
                    .ok_or(Error::RestoredCapacity)?;
                slot.value.bytes.clear();
                slot.value.bytes.extend_from_slice(bytes);
                slot.value.recovered = recovered;
                slot.id = Some(id);
            }
        }
        Ok(())
    }
    pub fn remove(&mut self, id: &u64) {
        match self {
            Self::Legacy(m) => {
                m.remove(id);
            }
            Self::Reserved(v) => {
                if let Some(s) = v.iter_mut().find(|s| s.id == Some(*id)) {
                    s.id = None;
                    s.value.bytes.clear();
                }
            }
        }
    }
}
pub(crate) struct DeadlineSlot {
    id: Option<GenerationId>,
    deadline: u64,
}
pub(crate) enum Deadlines {
    Legacy(BTreeMap<GenerationId, u64>),
    Reserved(Vec<DeadlineSlot>),
}
impl Deadlines {
    pub fn legacy() -> Self {
        Self::Legacy(BTreeMap::new())
    }
    pub fn reserved(n: usize, a: &mut Allocation) -> Result<Self, storage::Error> {
        let mut slots = a.vec(n)?;
        for _ in 0..n {
            slots.push(DeadlineSlot {
                id: None,
                deadline: 0,
            });
        }
        Ok(Self::Reserved(slots))
    }
    pub fn minimum(&self) -> Option<u64> {
        match self {
            Self::Legacy(m) => m.values().copied().min(),
            Self::Reserved(v) => v
                .iter()
                .filter(|s| s.id.is_some())
                .map(|s| s.deadline)
                .min(),
        }
    }
    pub fn insert(&mut self, id: GenerationId, deadline: u64) -> Result<(), Error> {
        match self {
            Self::Legacy(m) => {
                m.entry(id).or_insert(deadline);
            }
            Self::Reserved(v) => {
                if v.iter().any(|s| s.id == Some(id)) {
                    return Ok(());
                }
                let s = v
                    .iter_mut()
                    .find(|s| s.id.is_none())
                    .ok_or(Error::Exhausted)?;
                s.id = Some(id);
                s.deadline = deadline;
            }
        }
        Ok(())
    }
    pub fn remove(&mut self, id: &GenerationId) {
        match self {
            Self::Legacy(m) => {
                m.remove(id);
            }
            Self::Reserved(v) => {
                if let Some(s) = v.iter_mut().find(|s| s.id == Some(*id)) {
                    s.id = None;
                }
            }
        }
    }
}
pub(crate) fn expired(
    n: usize,
    a: &mut Allocation,
) -> Result<Vec<ExpiredGeneration>, storage::Error> {
    let mut values = a.vec(n)?;
    values.resize(
        n,
        ExpiredGeneration {
            generation: GenerationId(0),
            rank: 0,
            required_rank: 0,
        },
    );
    Ok(values)
}
