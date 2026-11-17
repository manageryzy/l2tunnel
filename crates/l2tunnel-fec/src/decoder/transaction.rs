//! One shared equation transaction. Only changed rows receive prepared versions.
use super::{Error, Generation, Row, SymbolView, original_length};
use crate::storage::{self, Allocation};

pub(super) struct TransactionRow {
    pub row: Row,
    pivot: Option<usize>,
}
pub(super) struct Work {
    rows: Vec<TransactionRow>,
    used: usize,
    reserved: bool,
}
pub(super) struct Prepared {
    pub innovative: bool,
    pub rank: usize,
}
impl Work {
    #[cfg(test)]
    pub(super) fn rows_used(&self) -> usize {
        self.used
    }
    #[cfg(test)]
    pub(super) fn fingerprint(&self, output: &mut Vec<(usize, usize)>) {
        output.push((self.rows.as_ptr() as usize, self.rows.capacity()));
        for row in &self.rows {
            super::backing::row_fingerprint(&row.row, output);
        }
    }
    pub fn legacy() -> Self {
        Self {
            rows: Vec::new(),
            used: 0,
            reserved: false,
        }
    }
    pub fn reserved(n: usize, w: usize, a: &mut Allocation) -> Result<Self, storage::Error> {
        let mut rows = a.vec(n + 1)?;
        for _ in 0..=n {
            rows.push(TransactionRow {
                row: super::backing::row(a, n, w)?,
                pivot: None,
            });
        }
        Ok(Self {
            rows,
            used: 0,
            reserved: true,
        })
    }
    fn copy(
        &mut self,
        index: usize,
        coefficients: &[u8],
        payload: &[u8],
        width: usize,
        pivot: Option<usize>,
    ) -> Result<(), Error> {
        if payload.len() > width {
            return Err(Error::Malformed);
        }
        if index >= self.rows.len() {
            if self.reserved {
                return Err(Error::Capacity);
            }
            self.rows.push(TransactionRow {
                row: Row::empty(),
                pivot: None,
            });
        }
        let target = self.rows.get_mut(index).ok_or(Error::Arithmetic)?;
        if self.reserved
            && (target.row.coefficients.capacity() < coefficients.len()
                || target.row.payload.capacity() < width)
        {
            return Err(Error::Capacity);
        }
        target.row.coefficients.clear();
        target.row.coefficients.extend_from_slice(coefficients);
        target.row.payload.clear();
        target.row.payload.extend_from_slice(payload);
        // Only a separately validated compact systematic can be shorter. Work
        // rows already reserve the full algebraic width; no new storage owner.
        target.row.payload.resize(width, 0);
        target.pivot = pivot;
        Ok(())
    }
    pub fn prepare(
        &mut self,
        generation: &Generation,
        view: SymbolView<'_>,
    ) -> Result<Prepared, Error> {
        self.used = 2;
        self.copy(0, view.coefficients, view.payload, view.coded_bytes, None)?;
        self.copy(1, view.coefficients, view.payload, view.coded_bytes, None)?;
        for pivot in 0..view.source_count {
            if let Some(existing) = generation.basis.get(pivot) {
                let factor = self.rows[1].row.coefficients[pivot];
                if factor != 0 {
                    self.rows[1].row.eliminate(existing, factor);
                }
            }
        }
        let Some(pivot) = self.rows[1].row.coefficients.iter().position(|&c| c != 0) else {
            if self.rows[1].row.payload.iter().any(|&b| b != 0) {
                return Err(Error::Conflict);
            }
            return Ok(Prepared {
                innovative: false,
                rank: generation.rank,
            });
        };
        self.rows[1].row.normalize(pivot)?;
        self.rows[1].row.validate_identifiable()?;
        self.rows[1].pivot = Some(pivot);
        // Before this input rank <= N-1. Incoming + at most N-1 changed basis
        // rows + the exact original-history candidate therefore uses <= N+1.
        for index in 0..view.source_count {
            if let Some(existing) = generation.basis.get(index) {
                let factor = existing.coefficients[pivot];
                if factor != 0 {
                    let target = self.used;
                    self.copy(
                        target,
                        &existing.coefficients,
                        &existing.payload,
                        existing.payload.len(),
                        Some(index),
                    )?;
                    self.used += 1;
                    let (before, after) = self.rows.split_at_mut(target);
                    after[0].row.eliminate(&before[1].row, factor);
                    after[0].row.validate_identifiable()?;
                } else {
                    existing.validate_identifiable()?;
                }
            }
        }
        let rank = generation.rank.checked_add(1).ok_or(Error::Arithmetic)?;
        if rank == view.source_count {
            let mut maximum = 0;
            for index in 0..view.source_count {
                let recovered = self.rows[1..self.used]
                    .iter()
                    .find(|r| r.pivot == Some(index))
                    .map(|r| &r.row)
                    .or_else(|| generation.basis.get(index))
                    .ok_or(Error::Arithmetic)?;
                if recovered
                    .coefficients
                    .iter()
                    .enumerate()
                    .any(|(column, &c)| c != u8::from(column == index))
                {
                    return Err(Error::Arithmetic);
                }
                maximum = maximum.max(original_length(&recovered.payload)?);
            }
            if maximum.checked_add(2).ok_or(Error::Arithmetic)? != view.coded_bytes {
                return Err(Error::InvalidSource);
            }
        }
        Ok(Prepared {
            innovative: true,
            rank,
        })
    }
    pub fn commit(
        &mut self,
        generation: &mut Generation,
        symbol: super::SymbolId,
        prepared: Prepared,
    ) -> Result<(), Error> {
        if prepared.innovative {
            for row in &mut self.rows[1..self.used] {
                generation
                    .basis
                    .replace(row.pivot.ok_or(Error::Arithmetic)?, &mut row.row)?;
            }
        }
        generation.received.insert(symbol, &mut self.rows[0].row)?;
        generation.rank = prepared.rank;
        Ok(())
    }
}
