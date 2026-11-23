use super::*;

#[cfg(test)]
mod tests;

impl Decoder {
    /// A source at or beyond this exclusive end cannot occur in the pending
    /// equation or in any committed basis row. The pending job has not published
    /// a wider observation or started mutating rows or source storage.
    pub(in crate::rolling) fn independent_source_floor(&self) -> Option<u32> {
        let job = self.job.as_ref()?;
        let Input::Repair(row) = job.input else {
            return None;
        };
        (self.sliding.is_some()
            && row.near_extent == 0
            && row.profile.is_none()
            && self.explicit.is_none()
            && row.support.end <= self.live.observed
            && matches!(
                job.phase,
                Phase::Clear(_) | Phase::Load(_) | Phase::Support(_) | Phase::Known { .. }
            ))
        .then_some(self.shadow.observed)
    }

    /// Commit a disjoint, caller-authenticated original using the existing
    /// versioned store. The active repair retains its exact input, cursor and
    /// deadline. Its residual cannot use this column even if that job rolls back.
    pub(in crate::rolling) fn commit_independent_source(
        &mut self,
        id: SourceId,
        original: &[u8],
        received: Tick,
        now: Tick,
        cap: Tick,
        budget: &mut WorkBudget,
    ) -> Result<bool, Error> {
        let Some(floor) = self.independent_source_floor() else {
            return Ok(false);
        };
        // No contiguous publication, eviction, basis scan or GF work is needed.
        // Debit each encoded byte and a fixed bound for metadata and publication.
        let metadata = add(self.width, 16)?;
        if id.0 < floor
            || id.0 <= self.live.prefix
            || budget.copies < self.width
            || budget.metadata < metadata
            || id.0 == u32::MAX
            || u64::from(id.0) >= u64::from(self.live.prefix) + self.config.window as u64
        {
            return Ok(false);
        }
        if original.is_empty() || original.len() > self.config.max_payload {
            return Err(Error::Length);
        }
        self.time(now)?;
        let slot = id.0 as usize % (2 * self.config.window);
        if self.live_known(slot)? == Some(id.0) {
            // Keep the queued duplicate on its original FIFO/deadline path.
            // Compare its authenticated bytes before admitting any later source.
            budget.copies -= original.len();
            budget.metadata -= original.len() + 1;
            self.source_input(self.scope, id, original, received, now, cap, false)?;
            return Ok(false);
        }
        if self.known_at(slot)?.is_some() || self.live_known(slot)?.is_some() {
            return Ok(false);
        }
        let (_, debt) = self.input_deadlines(Input::Source(id.0), received, now, cap)?;
        let ticket = match self.decisions.begin() {
            Ok(ticket) => ticket,
            Err(Error::Capacity) => return Ok(false),
            Err(error) => return Err(error),
        };
        let data = &mut self.known_data[slot * self.width..(slot + 1) * self.width];
        data[..2].copy_from_slice(&(original.len() as u16).to_be_bytes());
        data[2..2 + original.len()].copy_from_slice(original);
        data[2 + original.len()..].fill(0);
        self.known[slot].set(&mut self.decisions, ticket, Some(id.0))?;
        self.decisions.commit(ticket)?;
        self.live.known_count += 1;
        self.shadow.known_count += 1;
        // The older repair observed no additional IDs. Only this new suffix
        // contributes an observation deadline to the sliding debt ledger.
        if id.0 >= self.live.observed {
            self.live.observed = id.0 + 1;
            self.refresh_sliding(debt, None);
        }
        budget.copies -= self.width;
        budget.metadata -= metadata;
        Ok(true)
    }
}
