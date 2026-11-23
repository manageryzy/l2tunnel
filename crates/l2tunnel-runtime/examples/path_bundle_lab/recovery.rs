use super::*;
use l2tunnel_pipeline::path_ack::LOGICAL_GROUP;
#[path = "blocked.rs"]
mod blocked;
#[path = "fair.rs"]
mod fair;
#[path = "rank.rs"]
mod rank;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Role {
    Fresh,
    PromotedNamed,
    PromotedQuiet,
    FrozenRescue,
    LateFirst,
    Named,
    NamedCopy,
    Path(u64),
    Quiet,
    LowLoad,
}
impl Role {
    pub fn first(self) -> bool {
        matches!(
            self,
            Self::Fresh | Self::PromotedNamed | Self::PromotedQuiet
        )
    }
}

#[derive(Clone, Copy, Default)]
struct LastPayment {
    path: u8,
    named: bool,
}

struct Group {
    last: u64,
    round: u64,
    named: Vec<u64>,
    pending: Vec<u8>,
    last_paid: Option<u64>,
    wait_for_quiet_payment: bool,
    quiet_review: Option<u64>,
    paid_version: Vec<u64>,
    last_payment: Vec<LastPayment>,
}
#[derive(Clone, Copy)]
struct Repair {
    id: u64,
    ordinal: u8,
    role: Role,
    version: u64,
    independent: bool,
}
type DeferredPathRepairs = BTreeMap<(u64, u8), Vec<(u64, u8, Repair)>>;

pub struct Charge {
    pub id: u64,
    pub ordinal: u8,
    pub bytes: usize,
    pub entry_bytes: usize,
    pub role: Role,
    pub price: Role,
}
#[derive(Default)]
struct FirstRace {
    paid: bool,
    initial_paid: bool,
    rescues: u8,
}
pub struct Recovery {
    groups: BTreeMap<u64, Group>,
    queues: Vec<VecDeque<Repair>>,
    path_queues: Vec<VecDeque<Repair>>,
    path_waiting: Vec<BTreeSet<(u64, u8)>>,
    staged: Vec<BTreeMap<(u64, u8), Role>>,
    pub quiet: Option<u64>,
    pub suppressed: u64,
    reply_copies: u8,
    n: u8,
    k: u8,
    turns: Vec<u8>,
    fair: bool,
    pub use_physical_rank: bool,
    pub transfer_named_path_debt: bool,
    pub first_partial_extra: bool,
    pub distinct_named_blocked_assignments: u64,
    pub path_debts_transferred_to_named: u64,
    pub coalesced_names: u64,
    pub coalesced_path_debts: u64,
    pub bounded_independent_retries: u64,
    pub rank_suppressed: u64,
    pub member_suppressed: u64,
    pub native_trimmed: u64,
    deferred: DeferredPathRepairs,
    deferred_timers: BTreeSet<(u64, u64, u8, u8)>,
    blocked_slots: [u64; 4],
    blocked: BTreeMap<(u64, u8), BTreeMap<u8, u64>>,
    first_coalesced: BTreeMap<(u64, u8), u64>,
    rescue_queued: BTreeSet<(u64, u8)>,
    first_races: BTreeMap<(u64, u8), FirstRace>,
}
impl Recovery {
    pub fn new(n: u8, k: u8, reply_copies: u8) -> Self {
        Self {
            groups: BTreeMap::new(),
            queues: (0..n).map(|_| VecDeque::new()).collect(),
            path_queues: (0..n).map(|_| VecDeque::new()).collect(),
            path_waiting: (0..n).map(|_| BTreeSet::new()).collect(),
            staged: (0..n).map(|_| BTreeMap::new()).collect(),
            quiet: None,
            suppressed: 0,
            reply_copies,
            n,
            k,
            turns: vec![0; usize::from(n)],
            fair: false,
            use_physical_rank: false,
            transfer_named_path_debt: false,
            first_partial_extra: false,
            distinct_named_blocked_assignments: 0,
            path_debts_transferred_to_named: 0,
            coalesced_names: 0,
            coalesced_path_debts: 0,
            bounded_independent_retries: 0,
            rank_suppressed: 0,
            member_suppressed: 0,
            native_trimmed: 0,
            deferred: BTreeMap::new(),
            deferred_timers: BTreeSet::new(),
            blocked_slots: [0; 4],
            blocked: BTreeMap::new(),
            first_coalesced: BTreeMap::new(),
            rescue_queued: BTreeSet::new(),
            first_races: BTreeMap::new(),
        }
    }
    pub fn fair_members(mut self, enabled: bool) -> Self {
        self.fair = enabled;
        self
    }
    pub fn retain(&mut self, id: u64, now: u64) {
        self.groups.insert(
            id,
            Group {
                last: now,
                round: 0,
                named: vec![0; usize::from(self.n)],
                pending: vec![0; usize::from(self.n)],
                last_paid: None,
                wait_for_quiet_payment: false,
                quiet_review: None,
                paid_version: if self.fair {
                    vec![0; usize::from(self.n)]
                } else {
                    Vec::new()
                },
                last_payment: if self.fair {
                    vec![LastPayment::default(); usize::from(self.n)]
                } else {
                    Vec::new()
                },
            },
        );
    }
    pub fn len(&self) -> usize {
        self.groups.len()
    }
    pub fn retains(&self, id: u64) -> bool {
        self.groups.contains_key(&id)
    }
    // Frozen DATA can still pay after native delivery retired some of its members.
    pub fn live_paid_members(&self, entries: &[Charge]) -> Vec<(u64, u8)> {
        entries
            .iter()
            // Optional copies do not create new timeout debt. The ordinary
            // original retains custody and remains recoverable independently.
            .filter(|c| c.role != Role::LowLoad && self.retains(c.id))
            .map(|c| (c.id, c.ordinal))
            .collect()
    }

    pub fn acknowledge(&mut self, batch: &AckBatch) {
        let Some(b) = batch.blocks().last().filter(|b| b.path() == LOGICAL_GROUP) else {
            return;
        };
        while self
            .groups
            .first_key_value()
            .is_some_and(|(id, _)| *id < b.next())
        {
            self.groups.pop_first();
        }
        for r in b.ranges() {
            self.groups.retain(|id, _| !r.contains(id));
        }
        for lane in &mut self.queues {
            lane.retain(|r| self.groups.contains_key(&r.id));
        }
        for (queue, waiting) in self.path_queues.iter_mut().zip(&mut self.path_waiting) {
            queue.retain(|r| self.groups.contains_key(&r.id));
            waiting.retain(|(g, _)| self.groups.contains_key(g));
        }
        self.deferred
            .retain(|(g, _), _| self.groups.contains_key(g));
        self.deferred_timers
            .retain(|(_, g, _, _)| self.groups.contains_key(g));
        self.first_coalesced
            .retain(|(g, _), _| self.groups.contains_key(g));
        self.rescue_queued
            .retain(|(g, _)| self.groups.contains_key(g));
        self.arm_quiet();
    }
    pub fn named(&mut self, req: &ShardRequest, now: u64) {
        for (id, ordinals) in req.rows() {
            self.request(*id, ordinals, Role::Named, now);
        }
    }
    fn request(&mut self, id: u64, ordinals: &[u8], role: Role, now: u64) {
        let Some(g) = self.groups.get_mut(&id) else {
            return;
        };
        let mut advanced = false;
        let mut assigned = [0u64; 4];
        for &ordinal in ordinals {
            let i = usize::from(ordinal);
            if g.pending[i] != 0 || (role == Role::Named && g.named[i] > now) {
                self.suppressed += 1;
                continue;
            }
            if !advanced {
                g.round += 1;
                advanced = true;
            }
            let first = ((u64::from(ordinal) + g.round) % u64::from(self.n)) as u8;
            let first = if self.first_partial_extra && role == Role::Named {
                // A3 carries a set, so each newly queued primary in this row needs a
                // different lane. Keep a blocked assignment when healthy lanes run out.
                let bit = |p: u8| (usize::from(p / 64), 1u64 << (p % 64));
                let mut available = (0..self.n).map(|i| rotate(first, i, self.n)).filter(|&p| {
                    let (word, mask) = bit(p);
                    assigned[word] & mask == 0
                });
                let route = available
                    .clone()
                    .find(|&p| {
                        let (word, mask) = bit(p);
                        self.blocked_slots[word] & mask == 0
                    })
                    .or_else(|| available.next())
                    .unwrap_or(first);
                let (word, mask) = bit(route);
                assigned[word] |= mask;
                if self.blocked_slots[word] & mask != 0 {
                    self.distinct_named_blocked_assignments += 1;
                }
                route
            } else if self.fair {
                (0..self.n)
                    .map(|i| rotate(first, i, self.n))
                    .find(|&p| self.blocked_slots[usize::from(p / 64)] & (1u64 << (p % 64)) == 0)
                    .unwrap_or(first)
            } else {
                first
            };
            let copies = if role == Role::Named {
                self.reply_copies
            } else {
                1
            };
            g.pending[i] = copies;
            if role == Role::Named {
                g.named[i] = g.last.max(now) + 35_000;
            }
            for copy in 0..if self.fair { 1 } else { copies } {
                let path = rotate(first, copy, self.n);
                let charge = if copy == 0 { role } else { Role::NamedCopy };
                self.queues[usize::from(path)].push_back(Repair {
                    id,
                    ordinal,
                    role: charge,
                    version: g.paid_version.get(i).copied().unwrap_or(0),
                    independent: false,
                });
            }
        }
        if advanced {
            g.last = g.last.max(now);
        }
    }
    fn arm_quiet(&mut self) {
        self.quiet = self.groups.first_key_value().and_then(|(_, g)| {
            if g.wait_for_quiet_payment {
                g.quiet_review
            } else {
                g.last_paid.map(|at| at + 140_000)
            }
        });
    }
    pub fn quiet_tick_with_rank(&mut self, now: u64, oldest_has_rank: bool) {
        if self.quiet.is_none_or(|t| t > now) {
            return;
        }
        if let Some((&id, g)) = self.groups.first_key_value()
            && g.last_paid.is_some_and(|at| now >= at + 140_000)
        {
            let start = (g.round % u64::from(self.n)) as u8;
            // A quiet peer that has K still owes native custody. One new DATA prompts a
            // fresh logical receipt page, including when the previous ACK was lost.
            let probes = if oldest_has_rank { 1 } else { self.k };
            let ordinals: Vec<_> = (0..probes).map(|i| rotate(start, i, self.n)).collect();
            if let Some(oldest) = self.groups.get_mut(&id) {
                oldest.wait_for_quiet_payment = true;
                oldest.quiet_review = self.fair.then(|| now.saturating_add(140_000));
            }
            self.request(id, &ordinals, Role::Quiet, now);
        }
        self.arm_quiet();
    }
    pub fn has_queued_path_repair(&self, slot: u8) -> bool {
        !self.path_queues[usize::from(slot)].is_empty()
    }
    pub fn has_queued_repair(&self, slot: u8) -> bool {
        self.has_queued_path_repair(slot) || !self.queues[usize::from(slot)].is_empty()
    }

    pub fn requeue_path(&mut self, slot: u8, previous: u64, members: &[(u64, u8)]) {
        let idx = usize::from(slot);
        // One waiting copy per live logical group and ordinal on this physical path.
        for &(id, ordinal) in members {
            if !self.groups.contains_key(&id) || !self.path_waiting[idx].insert((id, ordinal)) {
                continue;
            }
            self.path_queues[idx].push_back(Repair {
                id,
                ordinal,
                role: Role::Path(previous),
                version: 0,
                independent: false,
            });
        }
    }
    pub fn stage(
        &mut self,
        tx: &mut Transmitter,
        path: PathId,
        now: Duration,
        ledger: Option<&PathRecovery>,
    ) -> Result<u64> {
        let idx = usize::from(path.get());
        let mut cancelled = 0;
        for _ in 0..64 {
            let physical = !self.path_queues[idx].is_empty();
            let queue = if physical {
                &mut self.path_queues[idx]
            } else {
                &mut self.queues[idx]
            };
            let Some(&r) = queue.front() else {
                break;
            };
            if physical
                && !ledger
                    .ok_or("queued path repair without physical ledger")?
                    .needs_retry((r.id, r.ordinal))
            {
                cancelled += 1;
            } else {
                match tx.request_batched_position(path, now, r.id, r.ordinal) {
                    Ok(Some(pos)) => {
                        self.staged[idx].insert((pos.batch.sequence(), pos.index), r.role);
                    }
                    Ok(None) => (),
                    Err(TransmitError::Path(
                        l2tunnel_pipeline::path_batch::Error::Backpressure,
                    )) => {
                        break;
                    }
                    Err(err) => return Err(err.into()),
                }
            }
            queue.pop_front();
            if physical {
                self.path_waiting[idx].remove(&(r.id, r.ordinal));
            }
        }
        Ok(cancelled)
    }
    pub fn charges(&self, path: PathId, packet: Decoded<'_>) -> Result<Vec<Charge>> {
        packet
            .entries()
            .enumerate()
            .map(|(index, s)| {
                let role = self.staged[usize::from(path.get())]
                    .get(&(packet.sequence, index as u8))
                    .copied()
                    .unwrap_or(Role::Fresh);
                Ok(Charge {
                    entry_bytes: l2tunnel_pipeline::path_batch::entry_len(path, s)?,
                    id: s.generation,
                    ordinal: s.ordinal,
                    bytes: s.bytes.len(),
                    role,
                    price: role,
                })
            })
            .collect()
    }
    pub fn paid(&mut self, batch: BatchId, charges: &[Charge], now: u64) {
        for (index, c) in charges.iter().enumerate() {
            if c.role == Role::LowLoad {
                // This optional copy acquires no physical debt on its payment path.
                if self.transfer_named_path_debt
                    && let Some(g) = self.groups.get_mut(&c.id)
                {
                    g.last_payment[usize::from(c.ordinal)].named = false;
                }
                continue;
            }
            if self.fair {
                let member = (c.id, c.ordinal);
                if self.blocked.contains_key(&member) {
                    if let Some(anchor) = self.first_coalesced.get_mut(&member) {
                        *anchor = now;
                    }
                } else {
                    self.first_coalesced.remove(&member);
                }
            }
            self.wake_paid_member(c.id, c.ordinal);
            if c.role != Role::Fresh {
                self.staged[usize::from(batch.path().get())]
                    .remove(&(batch.sequence(), index as u8));
            }
            if let Some(g) = self.groups.get_mut(&c.id) {
                g.last = g.last.max(now);
                g.last_paid = Some(now);
                g.wait_for_quiet_payment = false;
                g.quiet_review = None;
                if self.fair {
                    g.paid_version[usize::from(c.ordinal)] += 1;
                    g.last_payment[usize::from(c.ordinal)] = LastPayment {
                        path: batch.path().get(),
                        named: matches!(c.role, Role::Named | Role::PromotedNamed)
                            && matches!(c.price, Role::Named | Role::PromotedNamed),
                    };
                }
                if matches!(
                    c.role,
                    Role::Named
                        | Role::NamedCopy
                        | Role::Quiet
                        | Role::PromotedNamed
                        | Role::PromotedQuiet
                ) {
                    g.pending[usize::from(c.ordinal)] -= 1;
                }
            }
        }
        self.arm_quiet();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_primary_ordinals_from_one_row_keep_distinct_packets_with_blocked_routes() -> Result<()> {
        let cfg = config();
        let mut tx = Transmitter::new(&[cfg; 6], 5, 1500, 8)?;
        let mut recovery = Recovery::new(6, 5, 1).fair_members(true);
        recovery.first_partial_extra = true;
        let gid = tx.admit(us(0), b"partially received group")?;
        recovery.retain(gid, 0);
        for i in 0..6 {
            let path = PathId::new(i)?;
            tx.fill_path(path, us(0), 8)?;
            let first = tx.prepare(path, us(500), None)?.ok_or("missing original")?;
            let token = first.id;
            let charges = recovery.charges(path, cfg.decode(path, first.bytes)?)?;
            tx.confirm(token)?;
            recovery.paid(token, &charges, 500);
        }
        // Old routing redirects every item to the only healthy lane, 3.
        let request = ShardRequest::new(6, vec![(gid, vec![0, 1, 2])])?;
        let mut baseline = Recovery::new(6, 5, 1).fair_members(true);
        baseline.retain(gid, 0);
        baseline.blocked_slots[0] = 0b11_0111;
        baseline.named(&request, 1000);
        assert_eq!(baseline.queues[3].len(), 3);

        recovery.blocked_slots[0] = baseline.blocked_slots[0];
        recovery.named(&request, 1000);
        recovery.named(&request, 1001);
        assert_eq!(recovery.suppressed, 3);
        assert_eq!(recovery.distinct_named_blocked_assignments, 2);
        assert_eq!(recovery.queues[3].len(), 1);
        recovery.blocked_slots[0] = 0;
        let mut sent = BTreeSet::new();
        let mut datagrams = 0;
        for i in 0..6 {
            let path = PathId::new(i)?;
            recovery.stage_fair(&mut tx, path, us(1100), &[])?;
            if let Some(batch) = tx.prepare(path, us(2000), None)? {
                let token = batch.id;
                let charges = recovery.charges(path, cfg.decode(path, batch.bytes)?)?;
                assert_eq!(charges.len(), 1);
                assert_eq!(charges[0].role, Role::Named);
                assert!(sent.insert(charges[0].ordinal));
                datagrams += 1;
                tx.confirm(token)?;
                recovery.paid(token, &charges, 2000);
            }
        }
        assert_eq!(sent, BTreeSet::from([0, 1, 2]));
        assert_eq!(datagrams, 3);
        Ok(())
    }

    #[test]
    fn optional_copy_keeps_sequence_without_new_debt_or_postponing_old_hole() -> Result<()> {
        let cfg = config();
        let mut tx = Transmitter::new(&[cfg; 3], 2, 1500, 8)?;
        let path = PathId::new(0)?;
        let mut recovery = Recovery::new(3, 2, 1).fair_members(true);
        let mut ledger = PathRecovery::new(0, 16, 90_000, 3)?;
        let gid = tx.admit(us(0), b"retained old hole")?;
        recovery.retain(gid, 0);
        tx.fill_path(path, us(0), 8)?;
        let original = tx.prepare(path, us(500), None)?.ok_or("missing original")?;
        let token = original.id;
        let charges = recovery.charges(path, cfg.decode(path, original.bytes)?)?;
        tx.confirm(token)?;
        ledger.sent(token.sequence(), &recovery.live_paid_members(&charges), 500)?;
        recovery.paid(token, &charges, 500);
        let quiet = recovery.quiet;
        assert!(tx.request(path, us(600), gid, 0)?);
        let copy = tx.prepare(path, us(600), None)?.ok_or("missing copy")?;
        let token = copy.id;
        let mut charges = recovery.charges(path, cfg.decode(path, copy.bytes)?)?;
        charges[0].role = Role::LowLoad;
        charges[0].price = Role::LowLoad;
        tx.confirm(token)?;
        ledger.sent(token.sequence(), &recovery.live_paid_members(&charges), 600)?;
        recovery.paid(token, &charges, 600);
        assert_eq!(ledger.outstanding(), 1);
        assert_eq!(recovery.quiet, quiet);
        let (sequence, members, reason) =
            ledger.take_due_with_reason(90_500).ok_or("lost old hole")?;
        assert_eq!(
            (sequence, members, reason),
            (0, vec![(gid, 0)], Reason::Timeout)
        );
        assert_eq!(tx.oldest_unconfirmed(), Some(gid));
        Ok(())
    }

    fn config() -> PathConfig {
        PathConfig {
            mtu: 1500,
            outer_bytes: OUTER,
            max_hold: us(500),
            max_entries: 10,
        }
    }

    #[test]
    fn copied_repair_with_identical_natural_entry_has_two_independent_receipts() -> Result<()> {
        let cfg = config();
        let mut tx = Transmitter::new(&[cfg; 2], 2, 128, 8)?;
        let mut recovery = Recovery::new(2, 2, 2);
        let gid = tx.admit(us(0), b"test data")?;
        recovery.retain(gid, 0);
        let paths = [PathId::new(0)?, PathId::new(1)?];
        for p in paths {
            tx.fill_path(p, us(0), 8)?;
        }
        let req = ShardRequest::new(2, vec![(gid, vec![0])])?;
        recovery.named(&req, 1);
        recovery.named(&req, 2);
        assert_eq!(recovery.suppressed, 1);
        for p in paths {
            recovery.stage(&mut tx, p, us(2), None)?;
        }
        for (idx, p) in paths.into_iter().enumerate() {
            let ready = tx
                .prepare(p, us(501), None)?
                .ok_or("missing physical copy")?;
            let id = ready.id;
            let encoded = ready.bytes.to_vec();
            let charges = recovery.charges(p, cfg.decode(p, &encoded)?)?;
            assert_eq!(
                charges.iter().map(|c| c.role).collect::<Vec<_>>(),
                [
                    Role::Fresh,
                    if idx == 0 {
                        Role::NamedCopy
                    } else {
                        Role::Named
                    }
                ]
            );
            if idx == 0 {
                assert_eq!(charges[0].ordinal, charges[1].ordinal);
            }
            assert_eq!(
                tx.prepare(p, us(550), None)?
                    .ok_or("lost blocked copy")?
                    .bytes,
                encoded
            );
            tx.confirm(id)?;
            recovery.paid(id, &charges, 550);
            assert_eq!(recovery.groups[&gid].pending[0], 1 - idx as u8);
            if idx == 0 {
                // The guard has elapsed, but the sibling payment has not completed.
                recovery.named(&req, 40_000);
                assert_eq!(recovery.suppressed, 2);
            }
        }
        Ok(())
    }

    #[test]
    fn quiet_uses_last_physical_payment_and_moves_to_the_next_old_hole() -> Result<()> {
        let cfg = config();
        let p = PathId::new(0)?;
        let mut tx = Transmitter::new(&[cfg; 2], 2, 128, 8)?;
        let mut r = Recovery::new(2, 2, 2);
        for i in 0..2 {
            let gid = tx.admit(us(i * 900), b"tail")?;
            r.retain(gid, i * 900);
            tx.fill_path(p, us(i * 900), 1)?;
            let at = i * 900 + 500;
            let h = tx.prepare(p, us(at), None)?.ok_or("missing head")?;
            let id = h.id;
            let entries = r.charges(p, cfg.decode(p, h.bytes)?)?;
            tx.confirm(id)?;
            r.paid(id, &entries, at);
        }
        assert_eq!(r.quiet, Some(140_500));
        r.quiet_tick_with_rank(140_000, false);
        assert!(r.queues.iter().all(VecDeque::is_empty));
        r.quiet_tick_with_rank(140_500, false);
        assert_eq!(r.queues.iter().map(VecDeque::len).sum::<usize>(), 2);
        assert!(r.queues.iter().flatten().all(|v| v.role == Role::Quiet));
        assert_eq!(r.quiet, None);
        let prefix = l2tunnel_pipeline::path_ack::AckBlock::new(255, 0, 1, vec![])?;
        r.acknowledge(&AckBatch::new(vec![prefix])?);
        assert_eq!(r.quiet, Some(141_400));
        Ok(())
    }

    #[test]
    fn physical_retry_keeps_its_slot_and_a_late_original_cancels_unstaged_work() -> Result<()> {
        let cfg = config();
        let path = PathId::new(1)?;
        let mut tx = Transmitter::new(&[cfg; 2], 2, 128, 8)?;
        let mut recovery = Recovery::new(2, 2, 1);
        let mut ledger = PathRecovery::new(1, 8, 1000, 3)?;
        for i in 0..2 {
            let gid = tx.admit(us(i * 600), b"native record")?;
            recovery.retain(gid, i * 600);
            tx.fill_path(path, us(i * 600), 1)?;
            let paid = i * 600 + 500;
            let first = tx.prepare(path, us(paid), None)?.ok_or("missing source")?;
            let id = first.id;
            let entries = recovery.charges(path, cfg.decode(path, first.bytes)?)?;
            tx.confirm(id)?;
            recovery.paid(id, &entries, paid);
            ledger.sent(id.sequence(), &[(gid, 1)], paid)?;
        }
        let (previous, missing, reason) = ledger
            .take_due_with_reason(1500)
            .ok_or("missing first timeout")?;
        assert_eq!((previous, reason), (0, Reason::Timeout));
        recovery.requeue_path(1, previous, &missing);
        recovery.requeue_path(1, previous, &missing);
        assert_eq!(recovery.path_queues[1].len(), 1);
        ledger.acknowledge(
            &l2tunnel_pipeline::path_ack::AckBlock::new(1, 0, 1, vec![])?,
            1550,
        )?;
        assert_eq!(recovery.stage(&mut tx, path, us(1550), Some(&ledger))?, 1);
        assert_eq!(tx.next_wake(path)?, None);
        let (previous, missing, _) = ledger
            .take_due_with_reason(2100)
            .ok_or("missing second timeout")?;
        recovery.requeue_path(1, previous, &missing);
        assert_eq!(recovery.stage(&mut tx, path, us(2100), Some(&ledger))?, 0);
        let retry = tx.prepare(path, us(2600), None)?.ok_or("missing retry")?;
        let id = retry.id;
        let entries = recovery.charges(path, cfg.decode(path, retry.bytes)?)?;
        assert_eq!((id.path(), id.sequence(), entries.len()), (path, 2, 1));
        assert_eq!(
            (entries[0].id, entries[0].ordinal, entries[0].role),
            (1, 1, Role::Path(1))
        );
        tx.confirm(id)?;
        recovery.paid(id, &entries, 2600);
        ledger.sent(id.sequence(), &[(1, 1)], 2600)?;
        assert_eq!(ledger.next_deadline(), Some(3600));
        Ok(())
    }

    #[test]
    fn one_blocked_request_copy_does_not_block_its_distinct_sibling() {
        let mut pending = feedback::RequestCopies::new(6);
        assert_eq!(pending.schedule(5, 2, vec![0xa3, 1, 1, 1]), 1);
        let second = pending.take_ready(|p| p != 5);
        assert_eq!(second.as_ref().map(|(p, c, _)| (*p, *c)), Some((0, 1)));
        let first = pending.take_ready(|_| true);
        assert_eq!(first.as_ref().map(|(p, c, _)| (*p, *c)), Some((5, 0)));
        assert_eq!(first.map(|v| v.2), second.map(|v| v.2));
        assert!(pending.is_empty());
    }
}
