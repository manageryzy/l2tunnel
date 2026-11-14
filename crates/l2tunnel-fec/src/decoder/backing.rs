//! Storage selection only; equation, window and deadline decisions stay shared.
use super::{DecoderConfig, Error, Generation, GenerationId, Row, SymbolId, Terminal};
use crate::storage::{self, Allocation};
use std::collections::BTreeMap;

pub(super) struct BasisSlot {
    pub row: Row,
    pub occupied: bool,
}
pub(super) enum Basis {
    Legacy(Vec<Option<Row>>),
    Reserved(Vec<BasisSlot>),
}
impl Basis {
    pub fn get(&self, i: usize) -> Option<&Row> {
        match self {
            Self::Legacy(v) => v.get(i).and_then(Option::as_ref),
            Self::Reserved(v) => v.get(i).filter(|s| s.occupied).map(|s| &s.row),
        }
    }
    pub fn replace(&mut self, i: usize, row: &mut Row) -> Result<(), Error> {
        match self {
            Self::Legacy(v) => {
                let slot = v.get_mut(i).ok_or(Error::Arithmetic)?;
                if let Some(old) = slot {
                    std::mem::swap(old, row);
                } else {
                    *slot = Some(std::mem::replace(row, Row::empty()));
                }
            }
            Self::Reserved(v) => {
                let slot = v.get_mut(i).ok_or(Error::Arithmetic)?;
                std::mem::swap(&mut slot.row, row);
                slot.occupied = true;
            }
        }
        Ok(())
    }
    fn clear(&mut self) {
        if let Self::Reserved(v) = self {
            for slot in v {
                slot.occupied = false;
                slot.row.clear();
            }
        }
    }
}
pub(super) struct HistorySlot {
    id: Option<SymbolId>,
    row: Row,
}
pub(super) enum History {
    Legacy(BTreeMap<SymbolId, Row>),
    Reserved(Vec<HistorySlot>),
}
impl History {
    pub fn get(&self, id: &SymbolId) -> Option<&Row> {
        match self {
            Self::Legacy(m) => m.get(id),
            Self::Reserved(v) => v.iter().find(|s| s.id == Some(*id)).map(|s| &s.row),
        }
    }
    pub fn len(&self) -> usize {
        match self {
            Self::Legacy(m) => m.len(),
            Self::Reserved(v) => v.iter().filter(|s| s.id.is_some()).count(),
        }
    }
    pub fn insert(&mut self, id: SymbolId, row: &mut Row) -> Result<(), Error> {
        match self {
            Self::Legacy(m) => {
                m.insert(id, std::mem::replace(row, Row::empty()));
            }
            Self::Reserved(v) => {
                let slot = v
                    .iter_mut()
                    .find(|s| s.id.is_none())
                    .ok_or(Error::Capacity)?;
                std::mem::swap(&mut slot.row, row);
                slot.id = Some(id);
            }
        }
        Ok(())
    }
    fn clear(&mut self) {
        if let Self::Reserved(v) = self {
            for slot in v {
                slot.id = None;
                slot.row.clear();
            }
        }
    }
}
pub(super) struct GenerationSlot {
    id: Option<GenerationId>,
    value: Generation,
}
pub(super) enum Generations {
    Legacy(BTreeMap<GenerationId, Generation>),
    Reserved(Vec<GenerationSlot>),
}
impl Generations {
    #[cfg(test)]
    pub(super) fn fingerprint(&self, output: &mut Vec<(usize, usize)>) {
        if let Self::Reserved(slots) = self {
            output.push((slots.as_ptr() as usize, slots.capacity()));
            for slot in slots {
                if let Basis::Reserved(rows) = &slot.value.basis {
                    output.push((rows.as_ptr() as usize, rows.capacity()));
                    for row in rows {
                        row_fingerprint(&row.row, output);
                    }
                }
                if let History::Reserved(rows) = &slot.value.received {
                    output.push((rows.as_ptr() as usize, rows.capacity()));
                    for row in rows {
                        row_fingerprint(&row.row, output);
                    }
                }
            }
        }
    }
    pub fn get(&self, id: &GenerationId) -> Option<&Generation> {
        self.iter()
            .find(|(key, _)| *key == id)
            .map(|(_, value)| value)
    }
    pub fn get_mut(&mut self, id: &GenerationId) -> Option<&mut Generation> {
        match self {
            Self::Legacy(m) => m.get_mut(id),
            Self::Reserved(v) => v
                .iter_mut()
                .find(|s| s.id == Some(*id))
                .map(|s| &mut s.value),
        }
    }
    pub fn vacant(&self) -> Option<&Generation> {
        match self {
            Self::Legacy(_) => None,
            Self::Reserved(v) => v.iter().find(|s| s.id.is_none()).map(|s| &s.value),
        }
    }
    pub fn publish(
        &mut self,
        id: GenerationId,
        legacy: Option<Generation>,
    ) -> Result<&mut Generation, Error> {
        match self {
            Self::Legacy(m) => {
                m.insert(id, legacy.ok_or(Error::Arithmetic)?);
                m.get_mut(&id).ok_or(Error::Arithmetic)
            }
            Self::Reserved(v) => {
                let slot = v
                    .iter_mut()
                    .find(|s| s.id.is_none())
                    .ok_or(Error::Capacity)?;
                slot.id = Some(id);
                Ok(&mut slot.value)
            }
        }
    }
    pub fn iter(&self) -> impl Iterator<Item = (&GenerationId, &Generation)> {
        let (map, slots) = match self {
            Self::Legacy(m) => (Some(m), None),
            Self::Reserved(v) => (None, Some(v)),
        };
        map.into_iter().flat_map(|m| m.iter()).chain(
            slots
                .into_iter()
                .flat_map(|v| v.iter())
                .filter_map(|s| s.id.as_ref().map(|id| (id, &s.value))),
        )
    }
    pub fn len(&self) -> usize {
        self.iter().count()
    }
    pub fn remove(&mut self, id: &GenerationId) {
        match self {
            Self::Legacy(m) => {
                m.remove(id);
            }
            Self::Reserved(v) => {
                if let Some(s) = v.iter_mut().find(|s| s.id == Some(*id)) {
                    s.id = None;
                    s.value.basis.clear();
                    s.value.received.clear();
                    s.value.rank = 0;
                    s.value.count = 0;
                }
            }
        }
    }
}
pub(super) struct TerminalSlot {
    id: Option<GenerationId>,
    terminal: Terminal,
}
pub(super) enum Terminals {
    Legacy(BTreeMap<GenerationId, Terminal>),
    Reserved(Vec<TerminalSlot>),
}
impl Terminals {
    #[cfg(test)]
    pub(super) fn fingerprint(&self, output: &mut Vec<(usize, usize)>) {
        if let Self::Reserved(v) = self {
            output.push((v.as_ptr() as usize, v.capacity()));
        }
    }
    pub fn get(&self, id: &GenerationId) -> Option<Terminal> {
        match self {
            Self::Legacy(m) => m.get(id).copied(),
            Self::Reserved(v) => v.iter().find(|s| s.id == Some(*id)).map(|s| s.terminal),
        }
    }
    pub fn insert(&mut self, id: GenerationId, terminal: Terminal) -> Result<(), Error> {
        match self {
            Self::Legacy(m) => {
                m.insert(id, terminal);
            }
            Self::Reserved(v) => {
                let s = v
                    .iter_mut()
                    .find(|s| s.id == Some(id) || s.id.is_none())
                    .ok_or(Error::Capacity)?;
                s.id = Some(id);
                s.terminal = terminal;
            }
        }
        Ok(())
    }
    pub fn retain_floor(&mut self, floor: u64) {
        match self {
            Self::Legacy(m) => m.retain(|id, _| id.0 >= floor),
            Self::Reserved(v) => {
                for s in v {
                    if s.id.is_some_and(|id| id.0 < floor) {
                        s.id = None;
                    }
                }
            }
        }
    }
    pub fn len(&self) -> usize {
        match self {
            Self::Legacy(m) => m.len(),
            Self::Reserved(v) => v.iter().filter(|s| s.id.is_some()).count(),
        }
    }
}
#[cfg(test)]
pub(super) fn row_fingerprint(row: &Row, output: &mut Vec<(usize, usize)>) {
    output.push((
        row.coefficients.as_ptr() as usize,
        row.coefficients.capacity(),
    ));
    output.push((row.payload.as_ptr() as usize, row.payload.capacity()));
}
pub(super) fn row(a: &mut Allocation, n: usize, w: usize) -> Result<Row, storage::Error> {
    Ok(Row {
        coefficients: a.vec(n)?,
        payload: a.vec(w)?,
    })
}
pub(crate) fn reserved_bytes(c: DecoderConfig) -> Result<usize, storage::Error> {
    let n = c.block.max_sources;
    let w = storage::add(c.block.max_source_bytes, 2)?;
    let g = c.max_generations;
    let h = c.max_symbols_per_generation;
    let b = storage::mul(g, n)?;
    let history = storage::mul(g, h)?;
    let work = storage::add(n, 1)?;
    let mut total = storage::array_bytes::<GenerationSlot>(g)?;
    for charge in [
        storage::array_bytes::<TerminalSlot>(c.generation_window as usize)?,
        storage::array_bytes::<BasisSlot>(b)?,
        storage::array_bytes::<HistorySlot>(history)?,
        storage::array_bytes::<super::transaction::TransactionRow>(work)?,
        storage::mul(
            storage::add(storage::add(b, history)?, work)?,
            storage::add(n, w)?,
        )?,
    ] {
        total = storage::add(total, charge)?;
    }
    Ok(total)
}
pub(super) fn reserved(
    c: DecoderConfig,
    a: &mut Allocation,
) -> Result<(Generations, Terminals, super::transaction::Work), storage::Error> {
    let n = c.block.max_sources;
    let w = storage::add(c.block.max_source_bytes, 2)?;
    let mut generations = a.vec(c.max_generations)?;
    for _ in 0..c.max_generations {
        let mut basis = a.vec(n)?;
        for _ in 0..n {
            basis.push(BasisSlot {
                row: row(a, n, w)?,
                occupied: false,
            });
        }
        let mut history = a.vec(c.max_symbols_per_generation)?;
        for _ in 0..c.max_symbols_per_generation {
            history.push(HistorySlot {
                id: None,
                row: row(a, n, w)?,
            });
        }
        generations.push(GenerationSlot {
            id: None,
            value: Generation {
                count: 0,
                width: 0,
                deadline: 0,
                reservation: 0,
                basis: Basis::Reserved(basis),
                received: History::Reserved(history),
                rank: 0,
            },
        });
    }
    let mut terminals = a.vec(c.generation_window as usize)?;
    for _ in 0..c.generation_window {
        terminals.push(TerminalSlot {
            id: None,
            terminal: Terminal::Delivered,
        });
    }
    let work = super::transaction::Work::reserved(n, w, a)?;
    Ok((
        Generations::Reserved(generations),
        Terminals::Reserved(terminals),
        work,
    ))
}
