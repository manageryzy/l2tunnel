//! Link native delivery to its outer sources, keeping source and unit spaces distinct.
use super::NativeError;
use crate::fec::GenerationId;
use l2tunnel_core::bounded_index::Index;

pub(super) type Key = (u8, u64);

#[derive(Clone, Copy)]
pub(super) struct Span {
    pub first: u64,
    pub last: u64,
}

/// A run of observed consecutive outer sources and consecutive Packed unit IDs.
#[derive(Clone, Copy)]
struct Run {
    last_source: u64,
    units: Span,
}

#[derive(Clone, Copy)]
struct Pending {
    digest: [u8; 32],
    remaining: usize,
}

pub(super) struct Custody {
    floor: Option<u64>,
    first_unit: Option<u64>,
    runs: Index<u64, Run>,
    limit: usize,
    max_units: u8,
    pending: Index<GenerationId, Pending>,
    waiting: Index<(Key, GenerationId), ()>,
    completed: Index<Key, ()>,
    ready: Index<GenerationId, ()>,
}

impl Custody {
    pub fn planned_bytes(limit: usize, max_units: u8) -> Result<usize, NativeError> {
        let edges = limit
            .checked_mul(usize::from(max_units))
            .ok_or(NativeError::Capacity)?;
        [
            Index::<u64, Run>::planned_bytes(limit),
            Index::<GenerationId, Pending>::planned_bytes(limit),
            Index::<(Key, GenerationId), ()>::planned_bytes(edges),
            Index::<Key, ()>::planned_bytes(edges),
            Index::<GenerationId, ()>::planned_bytes(limit),
        ]
        .into_iter()
        .try_fold(0usize, |total, bytes| {
            total
                .checked_add(bytes.map_err(|_| NativeError::Capacity)?)
                .ok_or(NativeError::Capacity)
        })
    }

    pub fn capacity_bytes(&self) -> usize {
        self.runs.capacity_bytes()
            + self.pending.capacity_bytes()
            + self.waiting.capacity_bytes()
            + self.completed.capacity_bytes()
            + self.ready.capacity_bytes()
    }

    pub fn new(
        first: GenerationId,
        first_unit: u64,
        limit: usize,
        max_units: u8,
    ) -> Result<Self, NativeError> {
        let bytes = Self::planned_bytes(limit, max_units)?;
        let edges = limit * usize::from(max_units);
        let owner = Self {
            floor: Some(first.0),
            first_unit: Some(first_unit),
            runs: Index::new(limit).map_err(|_| NativeError::Capacity)?,
            limit,
            max_units,
            pending: Index::new(limit).map_err(|_| NativeError::Capacity)?,
            waiting: Index::new(edges).map_err(|_| NativeError::Capacity)?,
            completed: Index::new(edges).map_err(|_| NativeError::Capacity)?,
            ready: Index::new(limit).map_err(|_| NativeError::Capacity)?,
        };
        if owner.capacity_bytes() != bytes {
            return Err(NativeError::Configuration);
        }
        Ok(owner)
    }

    /// Check authenticatable absolute ranges before the codec changes any state.
    pub fn preflight(
        &self,
        id: GenerationId,
        units: Span,
        digest: [u8; 32],
    ) -> Result<bool, NativeError> {
        if let Some(previous) = self.pending.get(id) {
            return if previous.digest == digest {
                Ok(false)
            } else {
                Err(NativeError::Identity)
            };
        }
        let Some(floor) = self.floor else {
            return Ok(false);
        };
        if id.0 < floor {
            return Ok(false);
        }
        let mut base = floor;
        let mut unit = self.first_unit.ok_or(NativeError::Identity)?;
        if let Some((first, prev)) = self.runs.floor(id.0) {
            if id.0 >= first && id.0 <= prev.last_source {
                return Ok(false);
            }
            base = prev
                .last_source
                .checked_add(1)
                .ok_or(NativeError::Identity)?;
            unit = prev
                .units
                .last
                .checked_add(1)
                .ok_or(NativeError::Identity)?;
        }
        let credit_floor = self
            .pending
            .first()
            .map_or(floor, |(oldest, _)| floor.min(oldest.0));
        if id.0 - credit_floor >= self.limit as u64 || self.pending.len() >= self.limit {
            return Err(NativeError::Capacity);
        }
        let fits = |first: u64, end: u64, sources: u64| {
            end.checked_sub(first).is_some_and(|n| {
                n >= sources && n <= sources.saturating_mul(u64::from(self.max_units))
            })
        };
        if !fits(unit, units.first, id.0 - base) {
            return Err(NativeError::Identity);
        }
        if let Some((next, run)) = self.runs.ceil(id.0) {
            let end = units.last.checked_add(1).ok_or(NativeError::Identity)?;
            if !fits(end, run.units.first, next - id.0 - 1) {
                return Err(NativeError::Identity);
            }
        }
        Ok(true)
    }

    pub fn admit(
        &mut self,
        id: GenerationId,
        units: Span,
        digest: [u8; 32],
        keys: &[Key],
    ) -> Result<(), NativeError> {
        // Merge at most two adjacent runs; closing an old hole never scans the window.
        let previous = self
            .runs
            .floor(id.0)
            .and_then(|(lo, r)| (r.last_source.checked_add(1) == Some(id.0)).then_some(lo));
        let mut start = id.0;
        let mut run = Run {
            last_source: id.0,
            units,
        };
        if let Some((lo, earlier)) =
            previous.and_then(|lo| self.runs.remove(lo).map(|old| (lo, old)))
        {
            start = lo;
            run.units.first = earlier.units.first;
        }
        if let Some(next) = id.0.checked_add(1).and_then(|s| self.runs.remove(s)) {
            run.last_source = next.last_source;
            run.units.last = next.units.last;
        }
        if self.floor == Some(start) {
            self.floor = run.last_source.checked_add(1);
            self.first_unit = run.units.last.checked_add(1);
        } else {
            self.runs
                .insert(start, run)
                .map_err(|_| NativeError::Capacity)?;
        }
        self.pending
            .insert(
                id,
                Pending {
                    digest,
                    remaining: keys.len(),
                },
            )
            .map_err(|_| NativeError::Capacity)?;
        for &key in keys {
            self.waiting
                .insert((key, id), ())
                .map_err(|_| NativeError::Capacity)?;
        }
        if keys.is_empty() {
            self.ready
                .insert(id, ())
                .map_err(|_| NativeError::Capacity)?;
        }
        Ok(())
    }

    fn first_waiter(&self, record: Key) -> Option<GenerationId> {
        self.waiting
            .ceil((record, GenerationId(0)))
            .and_then(|((key, id), ())| (key == record).then_some(id))
    }

    pub fn complete(&mut self, record: Key) -> Result<(), NativeError> {
        if self.first_waiter(record).is_some() {
            self.completed
                .insert(record, ())
                .map_err(|_| NativeError::Capacity)?;
        }
        Ok(())
    }

    /// A repeated fragment can add another real dependent source. Release at most
    /// the caller's budget of such edges, even for an adversarial repeated record.
    pub fn poll(&mut self, work: usize) -> Option<GenerationId> {
        for _ in 0..work {
            if !self.ready.is_empty() {
                break;
            }
            let (key, ()) = self.completed.first()?;
            let source = self.first_waiter(key)?;
            self.waiting.remove((key, source))?;
            if self.first_waiter(key).is_none() {
                self.completed.remove(key);
            }
            let entry = self.pending.get_mut(source)?;
            entry.remaining -= 1;
            if entry.remaining == 0 {
                // At most one ready key per pending source, with equal capacity.
                self.ready.insert(source, ()).ok()?;
            }
        }
        self.ready.first().map(|(id, ())| id)
    }

    pub fn committed(&mut self, id: GenerationId) -> Result<(), NativeError> {
        if self.ready.remove(id).is_none() {
            return Err(NativeError::Identity);
        }
        self.pending.remove(id);
        Ok(())
    }

    pub fn work_pending(&self) -> bool {
        !self.completed.is_empty() || !self.ready.is_empty()
    }
    pub fn admitted(&self, id: GenerationId) -> bool {
        self.floor.is_none_or(|f| id.0 < f)
            || self
                .runs
                .floor(id.0)
                .is_some_and(|(_, run)| id.0 <= run.last_source)
    }
    pub fn retained(&self) -> usize {
        self.pending.len()
    }
    pub fn drained(&self) -> bool {
        self.pending.is_empty() && self.runs.is_empty()
    }
}
