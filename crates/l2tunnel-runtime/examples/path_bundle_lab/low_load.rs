//! Bounded startup eligibility for one optional round of already encoded members.
use serde::Serialize;
use std::{collections::BTreeSet, error, fmt};

pub(super) const STARTUP_GROUPS: usize = 128;
pub(super) const AGE_LIMIT_US: u64 = 35_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct Member {
    pub group: u64,
    pub ordinal: u8,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Error {
    Configuration,
    Clock,
    Ordinal,
    Payment,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "low-load forward round: {self:?}")
    }
}

impl error::Error for Error {}

type Result<T> = std::result::Result<T, Error>;

#[derive(Default, Serialize)]
pub(super) struct Stats {
    pub eligible_groups: u64,
    pub expired_groups: u64,
    pub completed_rounds: u64,
    pub members_skipped: u64,
    pub frozen_members: u64,
    pub paid_members: u64,
    pub late_paid_members: u64,
}

#[derive(Default)]
struct Group {
    first_paid_at: Option<u64>,
    originals: [u64; 4],
    original_count: u8,
    next: u8,
    copies_paid: u8,
    closed: bool,
}

impl Group {
    fn expired(&self, now: u64) -> bool {
        self.first_paid_at
            .is_some_and(|at| now - at >= AGE_LIMIT_US)
    }

    fn priority(&self, id: u64) -> (u8, u64) {
        (self.copies_paid, id)
    }

    fn member(&self, group: u64, n: u8) -> Member {
        Member {
            group,
            ordinal: ((group + u64::from(self.next)) % u64::from(n)) as u8,
        }
    }
}

pub(super) struct Policy {
    n: u8,
    groups: Box<[Group]>,
    // Fewer actual optional payments first; lowest logical id breaks ties.
    ready: BTreeSet<(u8, u64)>,
    frozen: Option<Member>,
    clock: u64,
    pub stats: Stats,
}

impl Policy {
    pub(super) fn has_candidate(&self) -> bool {
        self.frozen.is_none() && !self.ready.is_empty()
    }

    pub(super) fn new(n: u8) -> Result<Self> {
        if n == 0 {
            return Err(Error::Configuration);
        }
        Ok(Self {
            n,
            groups: (0..STARTUP_GROUPS).map(|_| Group::default()).collect(),
            ready: BTreeSet::new(),
            frozen: None,
            clock: 0,
            stats: Stats::default(),
        })
    }

    fn check_time(&self, now: u64) -> Result<()> {
        if now < self.clock {
            Err(Error::Clock)
        } else {
            Ok(())
        }
    }

    pub(super) fn original_paid(&mut self, group: u64, ordinal: u8, now: u64) -> Result<()> {
        if ordinal >= self.n {
            return Err(Error::Ordinal);
        }
        self.check_time(now)?;
        self.clock = now;
        if group >= STARTUP_GROUPS as u64 {
            return Ok(());
        }
        let lane = &mut self.groups[group as usize];
        if lane.closed {
            return Ok(());
        }
        if lane.expired(now) {
            lane.closed = true;
            self.ready.remove(&lane.priority(group));
            self.stats.expired_groups += 1;
            return Ok(());
        }
        let word = &mut lane.originals[usize::from(ordinal / 64)];
        let bit = 1u64 << (ordinal % 64);
        if *word & bit == 0 {
            *word |= bit;
            lane.first_paid_at.get_or_insert(now);
            lane.original_count += 1;
            if lane.original_count == self.n {
                self.ready.insert(lane.priority(group));
                self.stats.eligible_groups += 1;
            }
        }
        Ok(())
    }

    /// The caller checks native, control and ordinary egress demand and shared credit first.
    /// A false predicate permanently skips a retired or positively acknowledged member.
    pub(super) fn candidate(
        &mut self,
        now: u64,
        mut still_needs: impl FnMut(u64, u8) -> bool,
    ) -> Result<Option<Member>> {
        self.check_time(now)?;
        self.clock = now;
        if self.frozen.is_some() {
            return Ok(None);
        }
        while let Some(&(_, id)) = self.ready.first() {
            let group = &mut self.groups[id as usize];
            if group.expired(now) {
                self.stats.expired_groups += 1;
            } else {
                while group.next < self.n {
                    let member = group.member(id, self.n);
                    if still_needs(id, member.ordinal) {
                        return Ok(Some(member));
                    }
                    group.next += 1;
                    self.stats.members_skipped += 1;
                }
            }
            group.closed = true;
            self.ready.pop_first();
        }
        Ok(None)
    }

    /// Freeze only when the existing socket batch owns this member. Selection alone
    /// creates no payment, reservation, retry timer or independent send queue.
    pub(super) fn freeze(&mut self, member: Member, now: u64) -> Result<()> {
        self.check_time(now)?;
        if self.frozen.is_some() || self.ready.first().map(|&(_, id)| id) != Some(member.group) {
            return Err(Error::Payment);
        }
        let group = &self.groups[member.group as usize];
        if group.expired(now) || group.member(member.group, self.n) != member {
            return Err(Error::Payment);
        }
        self.clock = now;
        self.stats.frozen_members += 1;
        self.frozen = Some(member);
        Ok(())
    }

    /// A socket-blocked immutable datagram can be paid after expiry or logical
    /// delivery. Its payment is counted and never reopens the original group.
    pub(super) fn paid(&mut self, member: Member, now: u64) -> Result<()> {
        self.check_time(now)?;
        if self.frozen != Some(member) {
            return Err(Error::Payment);
        }
        self.clock = now;
        self.frozen = None;
        let group = &mut self.groups[member.group as usize];
        self.ready.remove(&group.priority(member.group));
        group.copies_paid += 1;
        group.next += 1;
        self.stats.paid_members += 1;
        if group.expired(now) {
            self.stats.late_paid_members += 1;
        }
        if group.next == self.n {
            group.closed = true;
            if group.copies_paid == self.n {
                self.stats.completed_rounds += 1;
            }
        } else if !group.closed {
            self.ready.insert(group.priority(member.group));
        }
        Ok(())
    }

    pub(super) fn release(&mut self, group: u64) {
        if group < STARTUP_GROUPS as u64 {
            let entry = &mut self.groups[group as usize];
            entry.closed = true;
            self.ready.remove(&entry.priority(group));
        }
    }
}

#[cfg(test)]
mod tests;
