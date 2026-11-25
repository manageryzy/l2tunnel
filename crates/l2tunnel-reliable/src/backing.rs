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
    /// Next slot in the live or free list; `NONE` ends a list.
    next: usize,
}
const NONE: usize = usize::MAX;
/// Reserved staging threads every slot on exactly one of two intrusive lists
/// (live or free), so operations cost O(live entries) rather than O(capacity).
/// Slot indices are stable while live; diagnostics key waits by them.
pub(crate) enum RestoredMap {
    Legacy(BTreeMap<u64, Restored>),
    Reserved {
        slots: Vec<RestoredSlot>,
        live: usize,
        free: usize,
        occupied: usize,
    },
}
impl RestoredMap {
    pub fn legacy() -> Self {
        Self::Legacy(BTreeMap::new())
    }
    pub fn reserved(n: usize, bytes: usize, a: &mut Allocation) -> Result<Self, storage::Error> {
        let mut slots = a.vec(n)?;
        for index in 0..n {
            slots.push(RestoredSlot {
                id: None,
                value: Restored {
                    bytes: a.vec(bytes)?,
                    recovered: false,
                },
                next: if index + 1 < n { index + 1 } else { NONE },
            });
        }
        Ok(Self::Reserved {
            slots,
            live: NONE,
            free: if n == 0 { NONE } else { 0 },
            occupied: 0,
        })
    }
    pub fn len(&self) -> usize {
        match self {
            Self::Legacy(m) => m.len(),
            Self::Reserved { occupied, .. } => *occupied,
        }
    }
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
    /// Live slot holding `id`, with its live-list predecessor.
    fn find(slots: &[RestoredSlot], live: usize, id: u64) -> Option<(usize, usize)> {
        let (mut previous, mut index) = (NONE, live);
        while index != NONE {
            if slots[index].id == Some(id) {
                return Some((previous, index));
            }
            previous = index;
            index = slots[index].next;
        }
        None
    }
    pub fn get(&self, id: &u64) -> Option<&Restored> {
        match self {
            Self::Legacy(m) => m.get(id),
            Self::Reserved { slots, live, .. } => {
                Self::find(slots, *live, *id).map(|(_, index)| &slots[index].value)
            }
        }
    }
    pub fn contains_key(&self, id: &u64) -> bool {
        self.get(id).is_some()
    }
    pub fn first_key_value(&self) -> Option<(Option<usize>, &u64, &Restored)> {
        match self {
            Self::Legacy(m) => m.first_key_value().map(|(id, value)| (None, id, value)),
            Self::Reserved { slots, live, .. } => {
                let mut best: Option<(usize, &u64)> = None;
                let mut index = *live;
                while index != NONE {
                    if let Some(id) = slots[index].id.as_ref()
                        && best.is_none_or(|(_, current)| id < current)
                    {
                        best = Some((index, id));
                    }
                    index = slots[index].next;
                }
                best.map(|(index, id)| (Some(index), id, &slots[index].value))
            }
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
            Self::Reserved {
                slots,
                live,
                free,
                occupied,
            } => {
                let index = *free;
                let slot = slots
                    .get_mut(index)
                    .filter(|slot| slot.value.bytes.capacity() >= bytes.len())
                    .ok_or(Error::RestoredCapacity)?;
                *free = slot.next;
                slot.value.bytes.clear();
                slot.value.bytes.extend_from_slice(bytes);
                slot.value.recovered = recovered;
                slot.id = Some(id);
                slot.next = *live;
                *live = index;
                *occupied += 1;
            }
        }
        Ok(())
    }
    pub fn remove(&mut self, id: &u64) {
        match self {
            Self::Legacy(m) => {
                m.remove(id);
            }
            Self::Reserved {
                slots,
                live,
                free,
                occupied,
            } => {
                if let Some((previous, index)) = Self::find(slots, *live, *id) {
                    let next = slots[index].next;
                    if previous == NONE {
                        *live = next;
                    } else {
                        slots[previous].next = next;
                    }
                    let slot = &mut slots[index];
                    slot.id = None;
                    slot.value.bytes.clear();
                    slot.next = *free;
                    *free = index;
                    *occupied -= 1;
                }
            }
        }
    }
}
/// Only a successfully accepted systematic establishes this range. Full decode
/// already requires contiguous source IDs; this stores that existing constraint.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct GenerationSources {
    pub base: u64,
    pub count: usize,
    pub width: usize,
}
impl GenerationSources {
    pub fn from_systematic(
        source: u64,
        index: u32,
        count: usize,
        width: usize,
    ) -> Result<Self, Error> {
        let base = source
            .checked_sub(u64::from(index))
            .ok_or(Error::SourceConflict)?;
        let last = u64::try_from(count.checked_sub(1).ok_or(Error::SourceConflict)?)
            .map_err(|_| Error::Exhausted)?;
        base.checked_add(last).ok_or(Error::SourceConflict)?;
        Ok(Self { base, count, width })
    }
    fn contains(self, source: u64) -> bool {
        source
            .checked_sub(self.base)
            .is_some_and(|index| index < self.count as u64)
    }
}
#[derive(Clone, Copy)]
pub(crate) struct Deadline {
    at: u64,
    sources: Option<GenerationSources>,
}
pub(crate) struct DeadlineSlot {
    id: Option<GenerationId>,
    value: Deadline,
}
pub(crate) enum Deadlines {
    Legacy(BTreeMap<GenerationId, Deadline>),
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
                value: Deadline {
                    at: 0,
                    sources: None,
                },
            });
        }
        Ok(Self::Reserved(slots))
    }
    fn entries(&self) -> impl Iterator<Item = (GenerationId, Deadline)> {
        let (legacy, reserved) = match self {
            Self::Legacy(m) => (Some(m), None),
            Self::Reserved(v) => (None, Some(v)),
        };
        legacy
            .into_iter()
            .flat_map(|m| m.iter().map(|(&id, &value)| (id, value)))
            .chain(
                reserved
                    .into_iter()
                    .flat_map(|v| v.iter().filter_map(|s| s.id.map(|id| (id, s.value)))),
            )
    }
    pub fn minimum(&self) -> Option<u64> {
        self.entries().map(|(_, value)| value.at).min()
    }
    pub fn sources(&self, id: GenerationId) -> Option<GenerationSources> {
        self.entries()
            .find(|(key, _)| *key == id)
            .and_then(|(_, value)| value.sources)
    }
    pub fn retry_generation(&self, source: u64) -> Option<(GenerationId, GenerationSources)> {
        let mut candidates = self.entries().filter_map(|(id, value)| {
            value
                .sources
                .filter(|sources| sources.contains(source))
                .map(|sources| (id, sources))
        });
        let first = candidates.next()?;
        candidates.next().is_none().then_some(first)
    }
    pub fn insert(
        &mut self,
        id: GenerationId,
        deadline: u64,
        sources: Option<GenerationSources>,
    ) -> Result<(), Error> {
        let update = |value: &mut Deadline| -> Result<(), Error> {
            if let Some(sources) = sources {
                if value.sources.is_some_and(|old| old != sources) {
                    return Err(Error::SourceConflict);
                }
                value.sources = Some(sources);
            }
            // An existing generation keeps its original deadline.
            Ok(())
        };
        match self {
            Self::Legacy(m) => update(m.entry(id).or_insert(Deadline {
                at: deadline,
                sources,
            })),
            Self::Reserved(v) => {
                if let Some(s) = v.iter_mut().find(|s| s.id == Some(id)) {
                    return update(&mut s.value);
                }
                let s = v
                    .iter_mut()
                    .find(|s| s.id.is_none())
                    .ok_or(Error::Exhausted)?;
                s.id = Some(id);
                s.value = Deadline {
                    at: deadline,
                    sources,
                };
                Ok(())
            }
        }
    }
    pub fn remove(&mut self, id: &GenerationId) {
        match self {
            Self::Legacy(m) => {
                m.remove(id);
            }
            Self::Reserved(v) => {
                if let Some(s) = v.iter_mut().find(|s| s.id == Some(*id)) {
                    s.id = None;
                    s.value.sources = None;
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

#[cfg(test)]
mod restored_tests {
    use super::*;

    /// Reserved staging behaves exactly like the dynamic map under random use,
    /// including refusal when full and duplicate-free reinsertion.
    #[test]
    fn reserved_restored_map_matches_the_dynamic_map() -> Result<(), Box<dyn std::error::Error>> {
        let capacity = 37;
        let mut allocation = Allocation::new(usize::MAX);
        let mut reserved = RestoredMap::reserved(capacity, 8, &mut allocation)?;
        let mut reference = RestoredMap::legacy();
        let mut state = 0x9e37_79b9_u64;
        let mut next = || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        for _ in 0..200_000 {
            let id = next() % 64;
            match next() % 4 {
                0 | 1 => {
                    if reference.contains_key(&id) {
                        continue;
                    }
                    let bytes = id.to_be_bytes();
                    let full = reference.len() == capacity;
                    let result = reserved.insert(id, &bytes, id % 3 == 0);
                    assert_eq!(result.is_err(), full);
                    if !full {
                        reference.insert(id, &bytes, id % 3 == 0)?;
                    }
                }
                2 => {
                    reserved.remove(&id);
                    reference.remove(&id);
                }
                _ => {
                    let first = reserved
                        .first_key_value()
                        .map(|(_, id, v)| (*id, v.bytes.clone()));
                    let expected = reference
                        .first_key_value()
                        .map(|(_, id, v)| (*id, v.bytes.clone()));
                    assert_eq!(first, expected);
                }
            }
            assert_eq!(reserved.len(), reference.len());
            assert_eq!(
                reserved.get(&id).map(|v| (v.bytes.clone(), v.recovered)),
                reference.get(&id).map(|v| (v.bytes.clone(), v.recovered))
            );
        }
        Ok(())
    }
}
