//! Original lifetimes for a sliding recovery window with cumulative frontiers.
use super::*;

#[derive(Clone, Copy)]
struct Range {
    end: u32,
    at: Tick,
}

/// A later range with an earlier expiry dominates every preceding range that
/// expires later. Both fields increase along the retained ring. Binary searches
/// handle a large prefix jump or an out-of-order input cap without scanning W.
struct Earliest {
    ranges: Vec<Range>,
    first: usize,
    len: usize,
}

impl Earliest {
    fn new(limit: usize) -> Result<Self, Error> {
        Ok(Self {
            ranges: slots(
                limit,
                Range {
                    end: 0,
                    at: Tick(0),
                },
            )?,
            first: 0,
            len: 0,
        })
    }

    fn index(&self, offset: usize) -> usize {
        (self.first + offset) % self.ranges.len()
    }

    fn partition(&self, keep: impl Fn(Range) -> bool) -> usize {
        let (mut left, mut right) = (0, self.len);
        while left < right {
            let mid = left + (right - left) / 2;
            if keep(self.ranges[self.index(mid)]) {
                left = mid + 1;
            } else {
                right = mid;
            }
        }
        left
    }

    fn update(&mut self, first: u32, new_range: Option<Range>) -> Option<Tick> {
        if self.len > 0 && self.ranges[self.first].end <= first {
            let remove = self.partition(|range| range.end <= first);
            self.first = self.index(remove);
            self.len -= remove;
        }
        if let Some(range) = new_range.filter(|r| r.end > first) {
            if self.len > 0 && self.ranges[self.index(self.len - 1)].at >= range.at {
                self.len = self.partition(|r| r.at < range.at);
            }
            // Each entry covers at least one outstanding source, bounded by
            // its owner's checked window or handoff_sources limit.
            debug_assert!(self.len < self.ranges.len());
            let slot = self.index(self.len);
            self.ranges[slot] = range;
            self.len += 1;
        }
        (self.len > 0).then(|| self.ranges[self.first].at)
    }
}

pub(super) struct Sliding {
    debt: Earliest,
    handoff: Earliest,
}

impl Sliding {
    pub(super) fn new(c: Config) -> Result<Self, Error> {
        Ok(Self {
            debt: Earliest::new(c.window)?,
            handoff: Earliest::new(c.handoff_sources)?,
        })
    }

    pub(super) fn bytes(c: Config) -> Result<usize, Error> {
        mul(
            add(c.window, c.handoff_sources)?,
            std::mem::size_of::<Range>(),
        )
    }

    pub(super) fn requested(c: Config) -> Result<storage::Usage, storage::Error> {
        storage::requested::<Range>(c.window)?.join(storage::requested::<Range>(c.handoff_sources)?)
    }

    pub(super) fn usage(&self) -> Result<storage::Usage, storage::Error> {
        storage::Usage::vector(&self.debt.ranges)?
            .join(storage::Usage::vector(&self.handoff.ranges)?)
    }

    pub(super) fn refresh(
        &mut self,
        header: Header,
        handed: u32,
        observed_at: Option<Tick>,
        published_at: Option<Tick>,
    ) -> (Option<Tick>, Option<Tick>) {
        let debt = self.debt.update(
            header.prefix,
            observed_at.map(|at| Range {
                end: header.observed,
                at,
            }),
        );
        let delivery = self.handoff.update(
            handed,
            published_at.map(|at| Range {
                end: header.prefix,
                at,
            }),
        );
        (debt, delivery)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decoder() -> Result<Decoder, Error> {
        let config = Config {
            window: 8,
            local_window: 2,
            global_every: 4,
            max_payload: 8,
            max_rows: 2,
            repair_history: 4,
            handoff_sources: 3,
            job_ticks: 3,
            debt_ticks: 12,
            handoff_ticks: 10,
            memory_bytes: 1 << 20,
        };
        let scope = Scope {
            session: [0x39; 16],
            epoch: 1,
            stream: 0,
            direction: 0,
        };
        Decoder::new_sliding(config, scope, Tick(0))
    }

    fn put(d: &mut Decoder, id: u32, at: u64, cap: u64) -> Result<(), Error> {
        assert_eq!(
            d.begin_source_until(d.scope, SourceId(id), &[42], Tick(at), Tick(at), Tick(cap))?,
            Begin::Staged
        );
        let work = WorkBudget {
            copies: 4096,
            metadata: 4096,
            field: 4096,
        };
        assert!(matches!(
            d.step(Tick(at), work)?,
            DecodeStep::Accepted { .. }
        ));
        Ok(())
    }

    #[test]
    fn sliding_debt_advances_with_old_gap_while_recovery_never_empties() -> Result<(), Error> {
        let mut d = decoder()?;
        put(&mut d, 1, 0, 100)?;
        for batch in 0..12_u32 {
            let t = u64::from(batch * 5);
            put(&mut d, batch * 2 + 3, t + 2, 1000)?;
            put(&mut d, batch * 2, t + 4, 1000)?;
            assert_eq!(d.debt, Some(Tick(t + 14)));
            d.confirm_handoff(SourceId(batch * 2), Tick(t + 4))?;
            d.confirm_handoff(SourceId(batch * 2 + 1), Tick(t + 4))?;
        }
        // The remaining live gap keeps its own finite lifetime despite later input.
        put(&mut d, 27, 64, 1000)?;
        assert_eq!(d.debt, Some(Tick(69)));
        assert_eq!(d.step(Tick(69), WorkBudget::default()), Err(Error::Expired));
        assert_eq!(
            d.expiry_snapshot().failure.map(|f| f.selected.kind),
            Some(expiry::Kind::DecoderDebt)
        );
        Ok(())
    }

    #[test]
    fn sliding_debt_keeps_original_caller_cap_after_reordered_evidence() -> Result<(), Error> {
        let mut d = decoder()?;
        put(&mut d, 1, 0, 100)?;
        put(&mut d, 3, 3, 9)?;
        assert_eq!(d.debt, Some(Tick(9)));
        // More generous limits on a duplicate or on newer evidence cannot renew it.
        assert_eq!(
            d.begin_source(d.scope, SourceId(3), &[42], Tick(4))?,
            Begin::Duplicate
        );
        put(&mut d, 0, 5, 100)?;
        assert_eq!(d.debt, Some(Tick(9)));
        assert_eq!(d.step(Tick(9), WorkBudget::default()), Err(Error::Expired));
        Ok(())
    }

    #[test]
    fn sliding_handoff_preserves_each_publication_age_in_continuous_queue() -> Result<(), Error> {
        let mut d = decoder()?;
        put(&mut d, 0, 0, 1000)?;
        put(&mut d, 1, 4, 1000)?;
        for id in 0..10_u32 {
            let t = u64::from(id * 4);
            d.confirm_handoff(SourceId(id), Tick(t + 6))?;
            assert_eq!(d.handoff_deadline(), Some(Tick(t + 14)));
            put(&mut d, id + 2, t + 8, 1000)?;
        }
        assert_eq!(d.handoff_deadline(), Some(Tick(50)));
        assert_eq!(d.step(Tick(50), WorkBudget::default()), Err(Error::Expired));
        assert_eq!(
            d.expiry_snapshot().failure.map(|f| f.selected.kind),
            Some(expiry::Kind::DecoderHandoff)
        );
        Ok(())
    }
}
