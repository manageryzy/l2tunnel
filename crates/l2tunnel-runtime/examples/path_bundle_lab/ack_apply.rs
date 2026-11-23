//! Apply authenticated physical receipts and logical delivery reports.

use super::*;

struct AckLedgers<'a> {
    tx: &'a mut Transmitter,
    recovery: &'a mut recovery::Recovery,
    physical: &'a mut [PathRecovery],
    paths: &'a mut [PathStats],
    totals: &'a mut Totals,
}

impl AckLedgers<'_> {
    fn apply(&mut self, batch: &AckBatch, now: u64, observed: impl FnOnce()) -> Result<()> {
        let released = self.tx.apply_ack(batch)?;
        self.totals.session_group_releases += released as u64;
        if released != 0 {
            self.recovery.acknowledge(batch);
            self.totals.logical_ack_cleanups += 1;
        } else if batch
            .blocks()
            .last()
            .is_some_and(|b| b.path() == LOGICAL_GROUP)
        {
            self.totals.logical_ack_duplicate_cleanups_skipped += 1;
        }
        if self.physical.is_empty() {
            return Ok(());
        }
        observed();
        for block in batch.blocks() {
            if block.path() == LOGICAL_GROUP {
                if released == 0 {
                    for ledger in &mut *self.physical {
                        ledger.observe_logical_time(now)?;
                    }
                    self.totals.logical_ack_path_scans_skipped += self.physical.len() as u64;
                } else {
                    for (ledger, stats) in self.physical.iter_mut().zip(&mut *self.paths) {
                        let before = ledger.outstanding();
                        ledger.acknowledge(block, now)?;
                        stats.logically_cancelled_packets += (before - ledger.outstanding()) as u64;
                    }
                    self.totals.logical_ack_path_scans += self.physical.len() as u64;
                }
                continue;
            }
            let slot = usize::from(block.path());
            let ledger = self
                .physical
                .get_mut(slot)
                .ok_or("unknown physical ACK path")?;
            let before = ledger.outstanding();
            if self.recovery.use_physical_rank {
                ledger.acknowledge_with_members(block, now, |(g, o)| {
                    self.tx.observe_paid_member_receipt(g, o);
                })?;
            } else {
                ledger.acknowledge(block, now)?;
            }
            self.paths[slot].physically_acknowledged_packets +=
                (before - ledger.outstanding()) as u64;
        }
        Ok(())
    }
}

impl Driver {
    pub(super) fn apply_ack(&mut self, bytes: &[u8], link: Event, now: u64) -> Result<()> {
        let batch = AckBatch::decode(bytes)?;
        AckLedgers {
            tx: &mut self.tx,
            recovery: &mut self.recovery,
            physical: &mut self.physical,
            paths: &mut self.stats,
            totals: &mut self.totals,
        }
        .apply(&batch, now, || {
            self.trace.observed_blocks(self.trace.time(), link, &batch)
        })?;
        self.trace
            .logical(self.trace.time(), "logical_ack_rx", link, &batch);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use l2tunnel_pipeline::path_ack::AckBlock;

    struct State {
        config: PathConfig,
        tx: Transmitter,
        recovery: recovery::Recovery,
        physical: Vec<PathRecovery>,
        paths: Vec<PathStats>,
        totals: Totals,
        observations: usize,
    }

    impl State {
        fn new() -> Result<Self> {
            let cfg = PathConfig {
                mtu: 1500,
                outer_bytes: OUTER,
                max_hold: us(500),
                max_entries: 1,
            };
            let mut recovery = recovery::Recovery::new(3, 2, 1);
            recovery.use_physical_rank = true;
            Ok(Self {
                config: cfg,
                tx: Transmitter::new(&[cfg; 3], 2, 128, 8)?,
                recovery,
                physical: (0..3)
                    .map(|p| {
                        PathRecovery::new(p, 16, 90_000, 3)?
                            .with_rtt_tracking(90_000, 500_000, 1_000)
                    })
                    .collect::<std::result::Result<_, _>>()?,
                paths: (0..3).map(|_| PathStats::default()).collect(),
                totals: Totals::default(),
                observations: 0,
            })
        }
        fn admit(&mut self, at: u64) -> Result<u64> {
            let g = self.tx.admit(us(at), b"one source")?;
            self.recovery.retain(g, at);
            Ok(g)
        }
        fn stage(&mut self, slot: u8, at: u64) -> Result<(BatchId, Vec<Charge>)> {
            let path = PathId::new(slot)?;
            self.tx.fill_path_once(path, us(at), 8)?;
            let p = self
                .tx
                .prepare(path, us(at), None)?
                .ok_or("missing full physical batch")?;
            Ok((
                p.id,
                self.recovery
                    .charges(path, self.config.decode(path, p.bytes)?)?,
            ))
        }
        fn pay(&mut self, staged: (BatchId, Vec<Charge>), at: u64) -> Result<()> {
            let (id, charges) = staged;
            self.tx.confirm(id)?;
            self.physical[usize::from(id.path().get())].sent(
                id.sequence(),
                &self.recovery.live_paid_members(&charges),
                at,
            )?;
            self.recovery.paid(id, &charges, at);
            Ok(())
        }
        fn send(&mut self, slot: u8, at: u64) -> Result<()> {
            let staged = self.stage(slot, at)?;
            self.pay(staged, at)
        }
        fn ack(&mut self, blocks: Vec<AckBlock>, at: u64) -> Result<()> {
            AckLedgers {
                tx: &mut self.tx,
                recovery: &mut self.recovery,
                physical: &mut self.physical,
                paths: &mut self.paths,
                totals: &mut self.totals,
            }
            .apply(&AckBatch::new(blocks)?, at, || self.observations += 1)
        }
    }

    #[test]
    fn repeated_delivery_keeps_mixed_receipts_rtt_fast_loss_and_late_payment_live() -> Result<()> {
        let mut s = State::new()?;
        let oldest = s.admit(10)?;
        for slot in 0..3 {
            s.send(slot, 10)?;
        }
        let delivered = s.admit(20)?;
        s.send(0, 20)?;
        s.send(1, 20)?;
        let frozen = s.stage(2, 20)?;
        let later = AckBlock::new(
            LOGICAL_GROUP,
            0,
            0,
            std::iter::once(delivered..delivered + 1).collect(),
        )?;
        s.ack(vec![later.clone()], 30)?;
        assert!(s.recovery.retains(oldest) && !s.recovery.retains(delivered));
        assert_eq!(s.tx.oldest_unconfirmed(), Some(oldest));
        assert_eq!(s.paths[0].logically_cancelled_packets, 1);
        assert_eq!(s.paths[1].logically_cancelled_packets, 1);
        assert!(s.recovery.live_paid_members(&frozen.1).is_empty());
        s.pay(frozen, 40)?;
        assert_eq!(s.physical[2].outstanding(), 1);
        for at in [50, 60, 70] {
            s.admit(at)?;
            s.send(0, at)?;
        }
        let high = AckBlock::new(0, 0, 0, std::iter::once(2..5).collect())?;
        s.ack(
            vec![high, AckBlock::new(2, 0, 2, vec![])?, later.clone()],
            100,
        )?;
        assert_eq!(s.paths[0].physically_acknowledged_packets, 3);
        assert_eq!(s.paths[2].physically_acknowledged_packets, 1);
        assert_eq!(s.physical[2].timing().samples, 1);
        assert!(s.tx.peer_has_member(oldest, 2) && s.tx.peer_has_member(2, 0));
        let (seq, debt, reason) = s.physical[0]
            .take_due_with_reason(101)
            .ok_or("missing fast loss")?;
        assert_eq!(
            (seq, debt, reason),
            (0, vec![(oldest, 0)], Reason::SelectiveGap)
        );
        assert_eq!(s.observations, 2);
        assert_eq!(s.totals.session_group_releases, 1);
        assert_eq!(s.totals.logical_ack_cleanups, 1);
        assert_eq!(s.totals.logical_ack_duplicate_cleanups_skipped, 1);
        assert_eq!(s.totals.logical_ack_path_scans, 3);
        assert_eq!(s.totals.logical_ack_path_scans_skipped, 3);
        s.ack(vec![AckBlock::new(LOGICAL_GROUP, 0, 2, vec![])?], 110)?;
        assert_eq!(s.tx.oldest_unconfirmed(), Some(2));
        assert!(s.recovery.retains(2) && !s.recovery.retains(oldest));
        assert_eq!(s.totals.session_group_releases, 2);
        Ok(())
    }

    #[test]
    fn duplicate_logical_ack_checks_clock_and_invalid_new_receipts_still_fail() -> Result<()> {
        let mut s = State::new()?;
        s.admit(1)?;
        assert!(
            s.ack(vec![AckBlock::new(LOGICAL_GROUP, 0, 1, vec![])?], 5)
                .is_err()
        );
        assert!(
            s.ack(vec![AckBlock::new(LOGICAL_GROUP, 0, 2, vec![])?], 5)
                .is_err()
        );
        assert_eq!(s.observations, 0);
        s.ack(vec![AckBlock::new(LOGICAL_GROUP, 0, 0, vec![])?], 10)?;
        assert!(s.ack(vec![AckBlock::new(0, 0, 0, vec![])?], 9).is_err());
        assert!(
            s.ack(vec![AckBlock::new(LOGICAL_GROUP, 0, 0, vec![])?], 9)
                .is_err()
        );
        assert_eq!(s.tx.oldest_unconfirmed(), Some(0));
        assert_eq!(s.totals.session_group_releases, 0);
        Ok(())
    }
}
