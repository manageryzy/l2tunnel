use super::*;
use l2tunnel::path_bundle::ReceiptEvidence;

impl Recovery {
    pub fn trim_due(&mut self, tx: &mut Transmitter, path: PathId, now: Duration) -> Result<()> {
        let i = usize::from(path.get());
        if self.staged[i].is_empty() {
            return Ok(());
        }
        tx.retain_due(path, now, |old, new, gid, ordinal, evidence| {
            let src = (old.batch.sequence(), old.index);
            let Some(&role) = self.staged[i].get(&src) else {
                return true;
            };
            let keep = role.first()
                || evidence == ReceiptEvidence::None
                || (role == Role::Quiet && evidence != ReceiptEvidence::Native);
            if keep {
                if old != new {
                    self.staged[i].remove(&src);
                    self.staged[i].insert((new.batch.sequence(), new.index), role);
                }
                return true;
            }
            self.staged[i].remove(&src);
            match evidence {
                ReceiptEvidence::Native => self.native_trimmed += 1,
                ReceiptEvidence::Rank => self.rank_suppressed += 1,
                ReceiptEvidence::Member => self.member_suppressed += 1,
                ReceiptEvidence::None => {}
            }
            if matches!(role, Role::Named | Role::NamedCopy | Role::Quiet)
                && let Some(g) = self.groups.get_mut(&gid)
            {
                g.pending[usize::from(ordinal)] -= 1;
            }
            if role == Role::FrozenRescue
                && let Some(race) = self.first_races.get_mut(&(gid, ordinal))
            {
                race.rescues -= 1;
                if race.rescues == 0 && (!race.paid || race.initial_paid) {
                    self.first_races.remove(&(gid, ordinal));
                }
            }
            false
        })?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use l2tunnel_pipeline::path_ack::AckBlock;

    #[test]
    fn duplicate_ordinals_keep_old_holes_fresh_members_and_quiet_custody_probe() -> Result<()> {
        let cfg = PathConfig {
            mtu: 1500,
            outer_bytes: 49,
            max_hold: us(100),
            max_entries: 8,
        };
        let mut tx = Transmitter::new(&[cfg; 3], 2, 1500, 8)?;
        let mut r = Recovery::new(3, 2, 1).fair_members(true);
        r.use_physical_rank = true;
        for g in 0..2 {
            assert_eq!(tx.admit(us(0), b"record")?, g);
            r.retain(g, 0);
        }
        tx.observe_paid_member_receipt(0, 0);
        assert!(!tx.peer_has_member(0, 0));
        for p in 0..2 {
            let path = PathId::new(p)?;
            tx.fill_path(path, us(0), 2)?;
            let id = tx.prepare(path, us(100), None)?.ok_or("unpaid first")?.id;
            tx.confirm(id)?;
        }
        let path = PathId::new(0)?;
        let old = tx
            .request_batched_position(path, us(100), 0, 0)?
            .ok_or("first repair")?;
        let other = tx
            .request_batched_position(path, us(100), 1, 1)?
            .ok_or("old hole")?;
        r.staged[0].insert((old.batch.sequence(), old.index), Role::Named);
        r.staged[0].insert((other.batch.sequence(), other.index), Role::Path(0));
        r.groups.get_mut(&0).ok_or("retention")?.pending[0] = 1;
        tx.observe_paid_member_receipt(0, 0);
        tx.observe_paid_member_receipt(0, 0);
        assert!(tx.peer_has_member(0, 0));
        assert!(!tx.peer_has_rank(0));
        tx.observe_paid_member_receipt(0, 1);
        assert!(tx.peer_has_rank(0));
        r.trim_due(&mut tx, path, us(200))?;
        let p = tx.prepare(path, us(200), None)?.ok_or("remaining repair")?;
        let kept = r.charges(path, cfg.decode(path, p.bytes)?)?;
        assert_eq!(kept.len(), 1);
        assert_eq!((kept[0].id, kept[0].role), (1, Role::Path(0)));
        let batch = p.id;
        tx.confirm(batch)?;
        r.paid(batch, &kept, 200);
        assert_eq!(r.rank_suppressed, 1);
        assert_eq!(tx.oldest_unconfirmed(), Some(0));
        // Rank alone does not cancel ordinary initial members or authorize retirement.
        let final_path = PathId::new(2)?;
        tx.fill_path(final_path, us(200), 2)?;
        let p = tx
            .prepare(final_path, us(300), None)?
            .ok_or("remaining first flight")?;
        assert_eq!(cfg.decode(final_path, p.bytes)?.count, 2);
        let batch = p.id;
        tx.confirm(batch)?;
        let g = r.groups.get_mut(&0).ok_or("source still retained")?;
        g.last_paid = Some(300);
        r.arm_quiet();
        r.quiet_tick_with_rank(140_300, true);
        let probes: Vec<_> = r.queues.iter().flatten().map(|q| (q.id, q.role)).collect();
        assert_eq!(probes, [(0, Role::Quiet)]);
        let logical = AckBatch::new(vec![AckBlock::new(LOGICAL_GROUP, 0, 1, vec![])?])?;
        assert_eq!(tx.apply_ack(&logical)?, 1);
        r.acknowledge(&logical);
        tx.observe_paid_member_receipt(0, 1);
        assert!(!tx.peer_has_member(0, 1));
        assert_eq!(tx.oldest_unconfirmed(), Some(1));
        Ok(())
    }
}
