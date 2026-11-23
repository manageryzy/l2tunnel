use super::*;
use l2tunnel::path_bundle::RecoveryStage;
use l2tunnel_pipeline::path_batch::EntryPosition;

enum Step {
    Added,
    Removed,
    Idle,
    Full,
}

impl Recovery {
    fn extra_replies(&mut self, req: Repair, primary: u8) {
        if req.role != Role::Named {
            return;
        }
        for copy in 1..self.reply_copies {
            let slot = rotate(primary, copy, self.n);
            self.queues[usize::from(slot)].push_back(Repair {
                role: Role::NamedCopy,
                ..req
            });
        }
    }

    pub(super) fn wake_paid_member(&mut self, group: u64, ordinal: u8) {
        if let Some(held) = self.deferred.remove(&(group, ordinal)) {
            for (deadline, slot, req) in held {
                self.deferred_timers
                    .remove(&(deadline, group, ordinal, slot));
                self.path_queues[usize::from(slot)].push_back(req);
            }
        }
    }

    pub fn deferred_wake(&self) -> Option<u64> {
        self.deferred_timers.first().map(|key| key.0)
    }

    pub fn wake_due_members(&mut self, now: u64) {
        for _ in 0..64 {
            let Some(&(due, g, o, slot)) = self.deferred_timers.first() else {
                break;
            };
            if due > now {
                break;
            }
            self.deferred_timers.pop_first();
            if let Some(held) = self.deferred.get_mut(&(g, o)) {
                if let Some(i) = held.iter().position(|v| v.1 == slot) {
                    let (_, _, mut req) = held.swap_remove(i);
                    req.independent = true;
                    self.path_queues[usize::from(slot)].push_back(req);
                }
                if held.is_empty() {
                    self.deferred.remove(&(g, o));
                }
            }
        }
    }

    fn mark_position(&mut self, pos: EntryPosition, role: Role) {
        self.staged[usize::from(pos.batch.path().get())]
            .insert((pos.batch.sequence(), pos.index), role);
    }

    fn fair_repair(
        &mut self,
        tx: &mut Transmitter,
        path: PathId,
        now: Duration,
        ledgers: &[PathRecovery],
        physical: bool,
        cancelled: &mut u64,
    ) -> Result<Step> {
        let slot = path.get();
        let i = usize::from(slot);
        let req = if physical {
            self.path_queues[i].front()
        } else {
            self.queues[i].front()
        }
        .copied();
        let Some(req) = req else {
            return Ok(Step::Idle);
        };
        let ordinal = usize::from(req.ordinal);
        let member = (req.id, req.ordinal);
        if self.use_physical_rank
            && req.role != Role::Quiet
            && (tx.peer_has_rank(req.id) || tx.peer_has_member(req.id, req.ordinal))
        {
            if tx.peer_has_rank(req.id) {
                self.rank_suppressed += 1;
            } else {
                self.member_suppressed += 1;
            }
            if physical {
                self.path_queues[i].pop_front();
                self.path_waiting[i].remove(&member);
            } else {
                self.queues[i].pop_front();
                match req.role {
                    Role::Named | Role::NamedCopy => {
                        if let Some(g) = self.groups.get_mut(&req.id) {
                            // A primary suppressed before staging has not issued its copies.
                            let copies = if req.role == Role::Named {
                                self.reply_copies
                            } else {
                                1
                            };
                            g.pending[ordinal] -= copies;
                        }
                    }
                    Role::FrozenRescue => {
                        self.rescue_queued.remove(&member);
                    }
                    _ => {}
                }
            }
            return Ok(Step::Removed);
        }
        if req.role == Role::FrozenRescue
            && self
                .groups
                .get(&req.id)
                .is_none_or(|g| g.paid_version[ordinal] != req.version)
        {
            self.rescue_queued.remove(&member);
            self.queues[i].pop_front();
            return Ok(Step::Removed);
        }
        if physical
            && !ledgers
                .get(i)
                .ok_or("missing path ledger")?
                .needs_retry(member)
        {
            self.path_queues[i].pop_front();
            self.path_waiting[i].remove(&member);
            *cancelled += 1;
            return Ok(Step::Removed);
        }
        // The old attempt is already out of flight. Only a successful named
        // payment on a different lane can take over this member's debt.
        if physical
            && self.transfer_named_path_debt
            && !req.independent
            && let Some(latest) = self.groups.get(&req.id).map(|g| g.last_payment[ordinal])
            && latest.named
            && latest.path != slot
            && !ledgers
                .get(usize::from(latest.path))
                .ok_or("missing named path ledger")?
                .needs_retry(member)
        {
            self.path_queues[i].pop_front();
            self.path_waiting[i].remove(&member);
            self.path_debts_transferred_to_named += 1;
            return Ok(Step::Removed);
        }
        if matches!(req.role, Role::Named | Role::Quiet)
            && let Some(g) = self.groups.get_mut(&req.id)
            && g.paid_version[ordinal] != req.version
        {
            let paid_slot = g.last_payment[ordinal].path;
            g.pending[ordinal] -= 1;
            self.coalesced_names += 1;
            self.queues[i].pop_front();
            self.extra_replies(req, paid_slot);
            return Ok(Step::Removed);
        }
        // Replication is explicit. A prior blocked payment on a different
        // path may hold its independent physical debt for at most one RTO.
        let explicit = matches!(req.role, Role::NamedCopy | Role::FrozenRescue)
            || (physical && req.independent);
        let outcome = if explicit {
            tx.request_batched_position(path, now, req.id, req.ordinal)
                .map(|pos| pos.map_or(RecoveryStage::Released, RecoveryStage::Retry))
        } else {
            tx.stage_recovery_once(path, now, req.id, req.ordinal)
        };
        let outcome = match outcome {
            Ok(outcome) => outcome,
            Err(TransmitError::Path(l2tunnel_pipeline::path_batch::Error::Backpressure)) => {
                return Ok(Step::Full);
            }
            Err(err) => return Err(err.into()),
        };
        if physical {
            self.path_queues[i].pop_front();
        } else {
            self.queues[i].pop_front();
        }
        if req.role == Role::FrozenRescue {
            self.rescue_queued.remove(&member);
        }
        let result = match outcome {
            RecoveryStage::First(pos) | RecoveryStage::Retry(pos) => {
                let role = if matches!(outcome, RecoveryStage::First(_)) {
                    match req.role {
                        Role::Named => Role::PromotedNamed,
                        Role::Quiet => Role::PromotedQuiet,
                        _ => return Err("invalid promoted first flight".into()),
                    }
                } else {
                    req.role
                };
                self.mark_position(pos, role);
                if role == Role::FrozenRescue
                    && (self.first_races.contains_key(&member) || req.version == 0)
                {
                    self.first_races.entry(member).or_default().rescues += 1;
                }
                self.extra_replies(req, slot);
                self.bounded_independent_retries += u64::from(physical && req.independent);
                Step::Added
            }
            RecoveryStage::AlreadyStaged { paths } => {
                if physical && paths[i / 64] & (1u64 << (i % 64)) == 0 {
                    let due = u64::try_from(now.as_micros())?
                        .checked_add(PATH_RTO)
                        .ok_or("deferred path deadline overflow")?;
                    self.deferred_timers
                        .insert((due, req.id, req.ordinal, slot));
                    self.deferred
                        .entry(member)
                        .or_default()
                        .push((due, slot, req));
                    return Ok(Step::Removed);
                }
                if physical {
                    self.coalesced_path_debts += 1;
                } else {
                    if let Some(g) = self.groups.get_mut(&req.id) {
                        g.pending[ordinal] -= 1;
                        if req.role == Role::Named && g.paid_version[ordinal] == 0 {
                            self.first_coalesced
                                .entry(member)
                                .or_insert(u64::try_from(now.as_micros())?);
                        }
                    }
                    self.coalesced_names += 1;
                    let primary = (0..self.n)
                        .find(|&p| paths[usize::from(p / 64)] & (1u64 << (p % 64)) != 0)
                        .ok_or("empty outstanding member mask")?;
                    self.extra_replies(req, primary);
                }
                Step::Removed
            }
            RecoveryStage::Released => Step::Removed,
        };
        if physical {
            self.path_waiting[i].remove(&member);
        }
        Ok(result)
    }

    pub fn stage_fair(
        &mut self,
        tx: &mut Transmitter,
        path: PathId,
        now: Duration,
        ledgers: &[PathRecovery],
    ) -> Result<u64> {
        self.stage_fair_observed(tx, path, now, ledgers, |_, _| Ok(()))
    }

    pub fn stage_fair_observed(
        &mut self,
        tx: &mut Transmitter,
        path: PathId,
        now: Duration,
        ledgers: &[PathRecovery],
        mut observe: impl FnMut(&Transmitter, PathId) -> Result<()>,
    ) -> Result<u64> {
        let i = usize::from(path.get());
        let mut cancelled = 0;
        for _ in 0..64 {
            let mut advanced = false;
            for offset in 0..3 {
                let class = (self.turns[i] + offset) % 3;
                let step = if class == 0 {
                    if tx.fill_path_once(path, now, 32)? != 0 {
                        observe(tx, path)?;
                        Step::Added
                    } else {
                        Step::Idle
                    }
                } else {
                    self.fair_repair(tx, path, now, ledgers, class == 1, &mut cancelled)?
                };
                match step {
                    Step::Added => {
                        self.turns[i] = (class + 1) % 3;
                        advanced = true;
                        break;
                    }
                    Step::Removed => advanced = true,
                    Step::Idle => (),
                    Step::Full => return Ok(cancelled),
                }
            }
            if !advanced {
                break;
            }
        }
        Ok(cancelled)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> PathConfig {
        PathConfig {
            mtu: 1500,
            outer_bytes: OUTER,
            max_hold: us(500),
            max_entries: 16,
        }
    }
    fn pay(
        tx: &mut Transmitter,
        r: &mut Recovery,
        p: PathId,
        now: u64,
    ) -> Result<(BatchId, Vec<Charge>)> {
        let head = tx
            .prepare(p, us(now), None)?
            .ok_or("missing payable DATA")?;
        let id = head.id;
        let entries = r.charges(p, config().decode(p, head.bytes)?)?;
        tx.confirm(id)?;
        r.paid(id, &entries, now);
        Ok((id, entries))
    }
    #[test]
    fn named_first_moves_once_and_a_prepared_natural_member_coalesces() -> Result<()> {
        for frozen in [false, true] {
            let mut tx = Transmitter::new(&[config(); 2], 2, 256, 32)?;
            let mut r = Recovery::new(2, 2, 1).fair_members(true);
            let gid = tx.admit(us(0), b"old native bytes")?;
            r.retain(gid, 0);
            let p0 = PathId::new(0)?;
            let p1 = PathId::new(1)?;
            if frozen {
                tx.fill_path_once(p0, us(0), 1)?;
                assert!(tx.prepare(p0, us(500), None)?.is_some());
            }
            r.named(&ShardRequest::new(2, vec![(gid, vec![0])])?, 510);
            r.stage_fair(&mut tx, p1, us(520), &[])?;
            let (_, entries) = pay(&mut tx, &mut r, p1, 1030)?;
            let promoted: Vec<_> = entries
                .iter()
                .filter(|e| e.ordinal == 0)
                .map(|e| e.role)
                .collect();
            if frozen {
                assert!(promoted.is_empty());
                assert_eq!(r.coalesced_names, 1);
                assert_eq!(pay(&mut tx, &mut r, p0, 1050)?.1[0].role, Role::Fresh);
            } else {
                assert_eq!(promoted, [Role::PromotedNamed]);
                assert_eq!(tx.fill_path_once(p0, us(1050), 1)?, 0);
            }
            assert_eq!(r.groups[&gid].pending[0], 0);
        }
        Ok(())
    }

    #[test]
    fn blocked_unpaid_initial_needs_a_later_authenticated_name_and_its_actual_first_is_priced_once()
    -> Result<()> {
        for original_first in [false, true] {
            let mut tx = Transmitter::new(&[config(); 2], 2, 256, 32)?;
            let mut r = Recovery::new(2, 2, 1).fair_members(true);
            let (p0, p1) = (PathId::new(0)?, PathId::new(1)?);
            let gid = tx.admit(us(0), b"both ordinals required")?;
            r.retain(gid, 0);
            for p in [p0, p1] {
                tx.fill_path_once(p, us(0), 1)?;
            }
            let mut original = {
                let h = tx
                    .prepare(p0, us(500), None)?
                    .ok_or("missing natural first")?;
                (
                    h.id,
                    r.charges(p0, config().decode(p0, h.bytes)?)?,
                    h.bytes.to_vec(),
                )
            };
            pay(&mut tx, &mut r, p1, 500)?;
            let name = ShardRequest::new(2, vec![(gid, vec![0])])?;
            r.socket_blocked(0, 510, &original.1);
            r.named_fair(&tx, &name, 600)?;
            r.named_fair(&tx, &name, 600 + PATH_RTO - 1)?;
            r.wake_due_members(600 + PATH_RTO);
            assert!(r.queues.iter().all(VecDeque::is_empty));
            r.named_fair(&tx, &name, 601 + PATH_RTO)?;
            r.named_fair(&tx, &name, 602 + PATH_RTO)?;
            assert_eq!(r.queues[1].len(), 1);
            let send = 603 + PATH_RTO;
            r.stage_fair(&mut tx, p1, us(send), &[])?;
            let mut rescue = {
                let h = tx
                    .prepare(p1, us(send + 500), None)?
                    .ok_or("missing alternate first")?;
                (h.id, r.charges(p1, config().decode(p1, h.bytes)?)?)
            };
            assert_eq!(
                tx.prepare(p0, us(send + 500), None)?
                    .ok_or("frozen original disappeared")?
                    .bytes,
                original.2
            );
            assert_eq!(rescue.1[0].role, Role::FrozenRescue);
            let mut paid_at = send + 500;
            for natural in [original_first, !original_first] {
                if natural {
                    tx.confirm(original.0)?;
                    r.socket_paid(0, &original.1);
                    r.price_payments(&mut original.1);
                    r.paid(original.0, &original.1, paid_at);
                    assert_eq!(
                        original.1[0].price,
                        if original_first {
                            Role::Fresh
                        } else {
                            Role::LateFirst
                        }
                    );
                } else {
                    tx.confirm(rescue.0)?;
                    r.price_payments(&mut rescue.1);
                    r.paid(rescue.0, &rescue.1, paid_at);
                    assert_eq!(
                        rescue.1[0].price,
                        if original_first {
                            Role::FrozenRescue
                        } else {
                            Role::PromotedNamed
                        }
                    );
                    if !original_first {
                        // The paid healthy-slot rescue is erased; its original remains frozen.
                        r.named_fair(&tx, &name, paid_at + PATH_RTO - 1)?;
                        assert!(r.queues.iter().all(VecDeque::is_empty));
                        paid_at += PATH_RTO + 1;
                        r.named_fair(&tx, &name, paid_at)?;
                        r.stage_fair(&mut tx, p1, us(paid_at), &[])?;
                        paid_at += 500;
                        let h = tx
                            .prepare(p1, us(paid_at), None)?
                            .ok_or("repeated old hole stalled")?;
                        let id = h.id;
                        let mut retry = r.charges(p1, config().decode(p1, h.bytes)?)?;
                        tx.confirm(id)?;
                        r.price_payments(&mut retry);
                        r.paid(id, &retry, paid_at);
                        assert_eq!((retry[0].ordinal, retry[0].price), (0, Role::FrozenRescue));
                    }
                }
            }
            assert!(r.first_races.is_empty());
        }
        Ok(())
    }

    #[test]
    fn fresh_physical_and_logical_repairs_each_advance_with_a_backlog() -> Result<()> {
        let mut tx = Transmitter::new(&[config(); 2], 2, 256, 32)?;
        let mut r = Recovery::new(2, 2, 1).fair_members(true);
        let p = PathId::new(0)?;
        let gid = tx.admit(us(0), b"retained original")?;
        r.retain(gid, 0);
        let mut ledger = PathRecovery::new(0, 8, 1000, 3)?;
        for slot in [p, PathId::new(1)?] {
            tx.fill_path_once(slot, us(0), 1)?;
            let (id, _) = pay(&mut tx, &mut r, slot, 500)?;
            if slot == p {
                ledger.sent(id.sequence(), &[(gid, 0)], 500)?;
            }
        }
        for _ in 0..8 {
            let id = tx.admit(us(510), b"continuing new traffic")?;
            r.retain(id, 510);
        }
        let (old, debt, _) = ledger
            .take_due_with_reason(1500)
            .ok_or("missing old DATA")?;
        r.requeue_path(0, old, &debt);
        r.named(&ShardRequest::new(2, vec![(gid, vec![1])])?, 1500);
        r.stage_fair(&mut tx, p, us(1500), std::slice::from_ref(&ledger))?;
        let (_, entries) = pay(&mut tx, &mut r, p, 2010)?;
        assert_eq!(
            entries.iter().take(3).map(|c| c.role).collect::<Vec<_>>(),
            [Role::Fresh, Role::Path(0), Role::Named]
        );
        Ok(())
    }

    #[test]
    fn a_frozen_foreign_copy_releases_home_debt_on_payment_or_at_the_bound() -> Result<()> {
        for foreign_pays in [true, false] {
            let mut tx = Transmitter::new(&[config(); 2], 2, 256, 32)?;
            let mut r = Recovery::new(2, 2, 1).fair_members(true);
            r.transfer_named_path_debt = !foreign_pays;
            let gid = tx.admit(us(0), b"physical recovery identity")?;
            r.retain(gid, 0);
            let p0 = PathId::new(0)?;
            let p1 = PathId::new(1)?;
            tx.fill_path_once(p0, us(0), 1)?;
            let (first, _) = pay(&mut tx, &mut r, p0, 500)?;
            let mut ledger = PathRecovery::new(0, 8, 1000, 3)?;
            ledger.sent(first.sequence(), &[(gid, 0)], 500)?;
            r.named(&ShardRequest::new(2, vec![(gid, vec![0])])?, 600);
            r.stage_fair(&mut tx, p1, us(600), &[])?;
            let frozen = tx
                .prepare(p1, us(1100), None)?
                .ok_or("missing foreign custody")?
                .bytes
                .to_vec();
            if !foreign_pays {
                let entries = r.charges(p1, config().decode(p1, &frozen)?)?;
                r.socket_blocked(p1.get(), 1100, &entries);
                assert!(!r.groups[&gid].last_payment[0].named);
                assert_eq!(r.groups[&gid].paid_version[0], 1);
            }
            let (old, debt, _) = ledger
                .take_due_with_reason(1500)
                .ok_or("missing home debt")?;
            r.requeue_path(0, old, &debt);
            r.stage_fair(&mut tx, p0, us(1500), std::slice::from_ref(&ledger))?;
            assert_eq!(tx.next_wake(p0)?, None);
            assert_eq!(r.deferred_wake(), Some(1500 + PATH_RTO));
            let now = if foreign_pays {
                let _ = pay(&mut tx, &mut r, p1, 1600)?;
                assert_eq!(r.deferred_wake(), None);
                1600
            } else {
                r.wake_due_members(1499 + PATH_RTO);
                assert!(!r.has_queued_path_repair(0));
                r.wake_due_members(1500 + PATH_RTO);
                assert_eq!(
                    tx.prepare(p1, us(1500 + PATH_RTO), None)?
                        .ok_or("lost frozen DATA")?
                        .bytes,
                    frozen
                );
                1500 + PATH_RTO
            };
            r.stage_fair(&mut tx, p0, us(now), std::slice::from_ref(&ledger))?;
            let (retry, entries) = pay(&mut tx, &mut r, p0, now + 500)?;
            assert_eq!((retry.path(), retry.sequence()), (p0, 1));
            assert_eq!(
                entries
                    .iter()
                    .map(|c| (c.id, c.ordinal, c.role))
                    .collect::<Vec<_>>(),
                [(gid, 0, Role::Path(old))]
            );
            assert_eq!(r.bounded_independent_retries, u64::from(!foreign_pays));
            assert_eq!(r.path_debts_transferred_to_named, 0);
        }
        Ok(())
    }

    #[test]
    fn named_transfer_uses_live_paid_custody_per_member_and_keeps_a_lost_name_recoverable()
    -> Result<()> {
        use l2tunnel_pipeline::path_ack::AckBlock;

        for named_already_due in [false, true] {
            let mut tx = Transmitter::new(&[config(); 2], 2, 256, 32)?;
            let mut r = Recovery::new(2, 2, 1).fair_members(true);
            r.transfer_named_path_debt = true;
            r.use_physical_rank = true;
            let mut ledgers = [
                PathRecovery::new(0, 8, 1000, 3)?,
                PathRecovery::new(1, 8, 1000, 3)?,
            ];
            let p0 = PathId::new(0)?;
            let p1 = PathId::new(1)?;
            let gid = tx.admit(us(0), b"named member")?;
            let other = tx.admit(us(0), b"ordinary member of the same old packet")?;
            for g in [gid, other] {
                r.retain(g, 0);
            }
            for p in [p0, p1] {
                r.stage_fair(&mut tx, p, us(0), &ledgers)?;
                let (id, charges) = pay(&mut tx, &mut r, p, 500)?;
                assert_eq!(charges.len(), 2);
                ledgers[usize::from(p.get())].sent(
                    id.sequence(),
                    &r.live_paid_members(&charges),
                    500,
                )?;
            }
            ledgers[1].acknowledge(&AckBlock::new(1, 0, 1, Vec::new())?, 510)?;
            r.named(&ShardRequest::new(2, vec![(gid, vec![0])])?, 600);
            r.stage_fair(&mut tx, p1, us(600), &ledgers)?;
            let (name, charges) = pay(&mut tx, &mut r, p1, 1100)?;
            assert_eq!(charges.len(), 1);
            assert_eq!(charges[0].role, Role::Named);
            ledgers[1].sent(name.sequence(), &r.live_paid_members(&charges), 1100)?;
            let (old, members, _) = ledgers[0]
                .take_due_with_reason(1500)
                .ok_or("old packet still live")?;
            r.requeue_path(0, old, &members);
            if named_already_due {
                let (seq, owed, _) = ledgers[1]
                    .take_due_with_reason(2100)
                    .ok_or("name still live")?;
                r.requeue_path(1, seq, &owed);
            }
            let now = if named_already_due { 2100 } else { 1500 };
            r.stage_fair(&mut tx, p0, us(now), &ledgers)?;
            let (_, charges) = pay(&mut tx, &mut r, p0, now + 500)?;
            assert!(
                charges
                    .iter()
                    .any(|c| (c.id, c.ordinal, c.role) == (other, 0, Role::Path(old)))
            );
            assert_eq!(
                charges
                    .iter()
                    .any(|c| (c.id, c.ordinal, c.role) == (gid, 0, Role::Path(old))),
                named_already_due
            );
            assert_eq!(
                r.path_debts_transferred_to_named,
                u64::from(!named_already_due)
            );
            if !named_already_due {
                // A missing named packet retains its own original paid deadline.
                assert_eq!(ledgers[1].next_deadline(), Some(2100));
                let (seq, owed, _) = ledgers[1]
                    .take_due_with_reason(2100)
                    .ok_or("name lost its timer")?;
                assert_eq!(owed, [(gid, 0)]);
                r.requeue_path(1, seq, &owed);
                r.stage_fair(&mut tx, p1, us(2100), &ledgers)?;
                let (_, charges) = pay(&mut tx, &mut r, p1, 2600)?;
                assert_eq!(
                    (charges[0].id, charges[0].ordinal, charges[0].role),
                    (gid, 0, Role::Path(seq))
                );
            }
            assert!(r.retains(gid) && r.retains(other));
        }
        Ok(())
    }
}
