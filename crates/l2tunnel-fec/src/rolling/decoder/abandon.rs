//! Receiver-side abandonment of an unrecoverable oldest hole (RRP-05).
//!
//! The abandoned column is marked known with a zero-length vector, which no
//! valid original can produce (every published original has length at least
//! one). Prefix, eviction and feedback arithmetic then treat it as resolved;
//! handoff, decoded-source lookup and every equation path recognize the marker.
//! The row pivoted on the column (if any) is dropped, losing at most one
//! equation; later repairs with a nonzero coefficient on it are dropped whole
//! (owner decision 2026-11-24, `docs/modules/research-recursive.md`).
use super::*;

/// Abandonment counters; none of them is a native-delivery fact.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct AbandonStatus {
    /// Sources passed over without recovery.
    pub abandoned: u64,
    /// Repairs dropped because they included an abandoned source.
    pub dropped_repairs: u64,
    /// Originals that arrived after their source was abandoned.
    pub late_originals: u64,
    /// Equations removed with an abandoned pivot.
    pub dropped_rows: u64,
}

impl Decoder {
    /// Committed vector length of a known slot; zero marks an abandoned source.
    pub(super) fn known_length(&self, slot: usize) -> usize {
        let start = slot * self.width;
        usize::from(u16::from_be_bytes([
            self.known_data[start],
            self.known_data[start + 1],
        ]))
    }

    /// True when `id` is retained and was abandoned.
    pub(crate) fn is_abandoned(&self, id: u32) -> Result<bool, Error> {
        let slot = id as usize % (2 * self.config.window);
        Ok(self.live_known(slot)? == Some(id) && self.known_length(slot) == 0)
    }

    /// Oldest missing source, if the prefix is a hole rather than held by
    /// the upper handoff bound or the end of observed input.
    pub(crate) fn hole(&self) -> Result<Option<u32>, Error> {
        let id = self.live.prefix;
        if id >= self.live.observed || ((id - self.handoff) as usize) >= self.config.handoff_sources
        {
            return Ok(None);
        }
        let slot = id as usize % (2 * self.config.window);
        Ok((self.live_known(slot)? != Some(id)).then_some(id))
    }

    /// Abandonment counters.
    pub fn abandon_status(&self) -> AbandonStatus {
        self.abandon
    }

    /// Pass over the oldest missing source without recovering it.
    ///
    /// Returns the abandoned identity, or `None` when the prefix is not a hole
    /// (already known, nothing observed beyond it, or the prefix is held by the
    /// upper handoff bound). Refuses with `Busy` while a job is staged, so the
    /// change never interleaves with GF work. Bounded by `W` metadata visits.
    pub(crate) fn abandon_prefix(&mut self, now: Tick) -> Result<Option<SourceId>, Error> {
        self.time(now)?;
        if self.job.is_some() {
            return Err(Error::Busy);
        }
        let w = self.config.window;
        let id = self.live.prefix;
        if id >= self.live.observed || ((id - self.handoff) as usize) >= self.config.handoff_sources
        {
            return Ok(None);
        }
        let slot = id as usize % (2 * w);
        if self.live_known(slot)? == Some(id) {
            return Ok(None);
        }
        // Validate's staging rule: the slot is unreachable through committed
        // metadata, so its vector may be written before the commit.
        if self
            .live_known(slot)?
            .is_some_and(|old| old >= id.saturating_sub(w as u32))
        {
            return self.fail(Error::Identity);
        }
        let ticket = match self.decisions.begin() {
            Ok(ticket) => ticket,
            Err(Error::Capacity) => return Err(Error::Busy),
            Err(error) => return self.fail(error),
        };
        self.active = Some(ticket);
        self.shadow = self.live;
        match self.abandon_staged(id, slot) {
            Ok(dropped_row) => {
                let published_at = self.publication_deadline(self.shadow.prefix, now)?;
                if let Err(error) = self.decisions.commit(ticket) {
                    return self.fail(error);
                }
                self.active = None;
                self.live = self.shadow;
                self.abandon.abandoned += 1;
                self.abandon.dropped_rows += u64::from(dropped_row);
                self.skip_abandoned_handoff()?;
                if self.sliding.is_none() && self.live.prefix == self.live.observed {
                    self.debt = None;
                }
                self.delivery = if self.live.prefix > self.handoff {
                    Some(match self.delivery {
                        Some(value) => value,
                        None => self.expires(now, self.config.handoff_ticks)?,
                    })
                } else {
                    None
                };
                self.refresh_sliding(None, published_at);
                Ok(Some(SourceId(id)))
            }
            Err(error) => self.fail(error),
        }
    }

    fn abandon_staged(&mut self, id: u32, slot: usize) -> Result<bool, Error> {
        let w = self.config.window;
        // Every retained row pivots on an unknown column at or above the
        // prefix and is reduced on every other pivot, so the oldest unknown
        // column is nonzero at most in the row pivoted on it.
        let dropped = match self.map_at(id as usize % w)? {
            Some(row) => {
                if self.pivot_at(row)? != Some(id) {
                    return Err(Error::Identity);
                }
                self.set_pivot(row, None)?;
                self.set_map(id as usize % w, None)?;
                self.shadow.rank = self.shadow.rank.checked_sub(1).ok_or(Error::Identity)?;
                if self.shadow.rank == 0 {
                    self.shadow.row_end = 0;
                }
                true
            }
            None => false,
        };
        let start = slot * self.width;
        self.known_data[start..start + self.width].fill(0);
        if self.known_at(slot)?.is_none() {
            self.shadow.known_count += 1;
        }
        self.set_known(slot, Some(id))?;
        // Advance over the abandoned source and following known ones, then
        // evict exactly as a committed job does.
        loop {
            let next = self.shadow.prefix;
            if next < self.shadow.observed
                && ((next - self.handoff) as usize) < self.config.handoff_sources
                && self.known_at(next as usize % (2 * w))? == Some(next)
            {
                self.shadow.prefix = next.checked_add(1).ok_or(Error::Exhausted)?;
            } else {
                break;
            }
        }
        let floor = self.shadow.prefix.saturating_sub(w as u32);
        for old in self.live.evicted_before..floor {
            let old_slot = old as usize % (2 * w);
            if self.known_at(old_slot)? == Some(old) {
                self.set_known(old_slot, None)?;
                self.shadow.known_count -= 1;
            }
        }
        self.shadow.evicted_before = self.shadow.evicted_before.max(floor);
        Ok(dropped)
    }

    /// Move the upper handoff over abandoned sources; nothing is handed up.
    pub(super) fn skip_abandoned_handoff(&mut self) -> Result<(), Error> {
        while self.handoff < self.live.prefix && self.is_abandoned(self.handoff)? {
            self.handoff = self.handoff.checked_add(1).ok_or(Error::Exhausted)?;
        }
        Ok(())
    }
}
