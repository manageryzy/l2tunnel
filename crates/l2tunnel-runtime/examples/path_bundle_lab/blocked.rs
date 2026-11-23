use super::*;
use l2tunnel::path_bundle::MemberState;

impl Recovery {
    pub fn socket_blocked(&mut self, slot: u8, now: u64, entries: &[Charge]) {
        if !self.fair || self.blocked_slots[usize::from(slot / 64)] & (1u64 << (slot % 64)) != 0 {
            return;
        }
        self.blocked_slots[usize::from(slot / 64)] |= 1u64 << (slot % 64);
        for entry in entries {
            self.blocked
                .entry((entry.id, entry.ordinal))
                .or_default()
                .insert(slot, now);
        }
    }
    pub fn socket_paid(&mut self, slot: u8, entries: &[Charge]) {
        if self.blocked_slots[usize::from(slot / 64)] & (1u64 << (slot % 64)) == 0 {
            return;
        }
        self.blocked_slots[usize::from(slot / 64)] &= !(1u64 << (slot % 64));
        for entry in entries {
            let member = (entry.id, entry.ordinal);
            if let Some(paths) = self.blocked.get_mut(&member) {
                paths.remove(&slot);
                if paths.is_empty() {
                    self.blocked.remove(&member);
                }
            }
        }
    }
    pub fn named_fair(&mut self, tx: &Transmitter, req: &ShardRequest, now: u64) -> Result<()> {
        if self.blocked.is_empty() {
            self.named(req, now);
            return Ok(());
        }
        for (id, ordinals) in req.rows() {
            let mut ordinary = Vec::new();
            for &ordinal in ordinals {
                let member = (*id, ordinal);
                let Some(group) = self.groups.get(id) else {
                    continue;
                };
                let Some(blocked) = self.blocked.get(&member) else {
                    ordinary.push(ordinal);
                    continue;
                };
                let MemberState::Staged { paths } = tx.member_state(*id, ordinal)? else {
                    ordinary.push(ordinal);
                    continue;
                };
                let mut actual = [0u64; 4];
                for &p in blocked.keys() {
                    actual[usize::from(p / 64)] |= 1u64 << (p % 64);
                }
                if paths != actual {
                    ordinary.push(ordinal);
                    continue;
                }
                let since = *self.first_coalesced.entry(member).or_insert(now);
                let last_blocked = blocked.values().copied().max().unwrap_or(now);
                if now.saturating_sub(last_blocked.max(since)) < PATH_RTO
                    || self.rescue_queued.contains(&member)
                {
                    self.coalesced_names += 1;
                    continue;
                }
                let first = rotate(ordinal, 1, self.n);
                let Some(slot) = (0..self.n)
                    .map(|p| rotate(first, p, self.n))
                    .find(|&p| self.blocked_slots[usize::from(p / 64)] & (1u64 << (p % 64)) == 0)
                else {
                    continue;
                };
                self.rescue_queued.insert(member);
                self.queues[usize::from(slot)].push_back(Repair {
                    id: *id,
                    ordinal,
                    role: Role::FrozenRescue,
                    version: group.paid_version[usize::from(ordinal)],
                    independent: false,
                });
            }
            self.request(*id, &ordinary, Role::Named, now);
        }
        Ok(())
    }
    // An immutable natural carrier record and its explicitly authorized rescue may
    // pay in either order, even after logical retirement. Price the first exactly once.
    pub fn price_payments(&mut self, entries: &mut [Charge]) {
        if self.first_races.is_empty() {
            return;
        }
        for c in entries {
            let member = (c.id, c.ordinal);
            if let Some(race) = self.first_races.get_mut(&member) {
                if c.role == Role::FrozenRescue {
                    race.rescues -= 1;
                    if !race.paid {
                        c.price = Role::PromotedNamed;
                    }
                } else if c.role.first() {
                    race.initial_paid = true;
                    if race.paid {
                        c.price = Role::LateFirst;
                    }
                }
                race.paid = true;
                if race.initial_paid && race.rescues == 0 {
                    self.first_races.remove(&member);
                }
            }
        }
    }
}
