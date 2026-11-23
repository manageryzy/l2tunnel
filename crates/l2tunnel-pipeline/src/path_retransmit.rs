//! Sender-side selective repeat for the DATA sequence space of one authenticated physical path.
//! A retry transfers stable coding members to the same path's batcher under a new DATA number.
use super::path_ack::{AckBlock, LOGICAL_GROUP, MAX_WINDOW};
use std::collections::{BTreeMap, BTreeSet};

mod timing;
pub use timing::Timing;
use timing::Tracker;

/// Evidence that made one physical DATA attempt eligible for repair.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reason {
    /// The deadline elapsed without a physical receipt or logical delivery.
    Timeout,
    /// Enough different later DATA numbers on this path were positively acknowledged.
    SelectiveGap,
    /// The peer no longer retains physical receipt history for this number.
    ExpiredHistory,
}

/// Invalid local configuration, payment, clock, or physical peer receipt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// Zero or excessive limits, a reserved ID, or an unrepresentable body.
    Invalid,
    /// This path's bounded DATA window has no free packet slot.
    Full,
    /// The caller did not provide the next paid DATA number, or peer evidence exceeds it.
    Sequence,
    /// The supplied monotonic time moved backwards or the deadline overflowed.
    Clock,
    /// Bounded timing history could not be allocated.
    Allocation,
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "physical DATA recovery: {self:?}")
    }
}
impl std::error::Error for Error {}

/// Stable logical group and ordinal housed in a physical DATA attempt.
pub type Member = (u64, u8);

struct Flight {
    paid: u64,
    due: u64,
    reason: Reason,
    members: Vec<Member>,
}

/// Bounded path-local packet debt. Only DATA consumes this sequence space.
pub struct PathRecovery {
    path: u8,
    limit: usize,
    rto: u64,
    later: usize,
    clock: u64,
    next: u64,
    flights: BTreeMap<u64, Flight>,
    deadlines: BTreeSet<(u64, u64)>,
    aliases: BTreeMap<u64, Vec<Member>>,
    in_flight: BTreeMap<Member, usize>,
    covered: BTreeMap<u64, [u64; 4]>,
    // The highest distinct positive physical receipts, even after logical retirement.
    highest: BTreeSet<u64>,
    timing: Option<Tracker>,
}

impl PathRecovery {
    /// Configure the packet window, paid-send timeout in microseconds and fast-retry threshold.
    pub fn new(path: u8, window: usize, rto_us: u64, later_packets: u8) -> Result<Self, Error> {
        if path == LOGICAL_GROUP
            || !(1..=MAX_WINDOW).contains(&window)
            || rto_us == 0
            || later_packets == 0
        {
            return Err(Error::Invalid);
        }
        Ok(Self {
            path,
            limit: window,
            rto: rto_us,
            later: usize::from(later_packets),
            clock: 0,
            next: 0,
            flights: BTreeMap::new(),
            deadlines: BTreeSet::new(),
            aliases: BTreeMap::new(),
            in_flight: BTreeMap::new(),
            covered: BTreeMap::new(),
            highest: BTreeSet::new(),
            timing: None,
        })
    }

    /// Enable bounded RTT learning before this path's first payment. Physical DATA
    /// numbers are never reused, so a late original ACK identifies its own payment.
    /// Native delivery, forgotten receipt history and duplicate ACKs are not samples.
    pub fn with_rtt_tracking(
        mut self,
        min_us: u64,
        max_us: u64,
        granularity_us: u64,
    ) -> Result<Self, Error> {
        if self.next != 0 || self.timing.is_some() {
            return Err(Error::Invalid);
        }
        self.timing = Some(Tracker::new(
            self.limit,
            self.rto,
            min_us,
            max_us,
            granularity_us,
        )?);
        Ok(self)
    }

    /// Actual observed receipt timing, separate from configured bounds.
    pub fn timing(&self) -> Timing {
        self.timing.as_ref().map_or(
            Timing {
                adaptive: false,
                samples: 0,
                srtt_us: None,
                rttvar_us: None,
                rto_us: self.rto,
            },
            Tracker::timing,
        )
    }

    /// New physical DATA admission. Retry transfer and control remain available on a full path.
    pub fn can_send(&self) -> bool {
        self.flights.len() < self.limit && self.next != u64::MAX
    }

    /// Number of distinct physical attempts that retain unconfirmed members.
    pub fn outstanding(&self) -> usize {
        self.flights.len()
    }

    /// Check a mutable retry before staging it. A late original receipt can cancel future
    /// work. It cannot acknowledge the new physical packet or retract a frozen ciphertext.
    pub fn needs_retry(&self, member: Member) -> bool {
        let (g, i) = member;
        !self.in_flight.contains_key(&member)
            && self
                .covered
                .get(&g)
                .is_none_or(|bits| bits[usize::from(i / 64)] & (1u64 << (i % 64)) == 0)
    }

    /// Record an actual complete carrier handoff. Members already logically delivered may be
    /// omitted. A DATA with no remaining debt still advances the physical sequence space.
    pub fn sent(&mut self, sequence: u64, members: &[Member], paid_us: u64) -> Result<(), Error> {
        if sequence != self.next || sequence == u64::MAX {
            return Err(Error::Sequence);
        }
        if members.len() > usize::from(u8::MAX)
            || members
                .iter()
                .any(|&(g, i)| g == u64::MAX || i == LOGICAL_GROUP)
        {
            return Err(Error::Invalid);
        }
        if !members.is_empty() && !self.can_send() {
            return Err(Error::Full);
        }
        let due = paid_us
            .checked_add(self.rto)
            .filter(|_| paid_us >= self.clock)
            .ok_or(Error::Clock)?;
        self.clock = paid_us;
        if let Some(tracker) = &mut self.timing {
            tracker.sent(sequence, paid_us);
        }
        self.next += 1;
        if !members.is_empty() {
            if self.flights.len() + self.aliases.len() == self.limit {
                self.aliases.pop_first();
            }
            for &m in members {
                *self.in_flight.entry(m).or_default() += 1;
            }
            self.flights.insert(
                sequence,
                Flight {
                    paid: paid_us,
                    due,
                    reason: Reason::Timeout,
                    members: members.to_vec(),
                },
            );
            self.deadlines.insert((due, sequence));
        }
        Ok(())
    }

    /// Apply an authenticated block. Physical retirement needs positive receipt. Falling below a
    /// floor expedites repair. A native delivery block can instead cancel only its own members.
    pub fn acknowledge(&mut self, block: &AckBlock, now_us: u64) -> Result<(), Error> {
        self.acknowledge_with_members(block, now_us, |_| {})
    }

    /// Advance the path clock for a validated, repeated native delivery block.
    /// The caller must know that this block retires no new groups and that no paid
    /// member of an already retired group could have entered the ledger.
    pub fn observe_logical_time(&mut self, now_us: u64) -> Result<(), Error> {
        if now_us < self.clock {
            return Err(Error::Clock);
        }
        self.clock = now_us;
        Ok(())
    }

    /// Report members of positively acknowledged paid DATA, including retained late aliases.
    /// Missing history, logical retirement and duplicate receipt of a retired attempt emit none.
    pub fn acknowledge_with_members(
        &mut self,
        block: &AckBlock,
        now_us: u64,
        mut positive: impl FnMut(Member),
    ) -> Result<(), Error> {
        if now_us < self.clock {
            return Err(Error::Clock);
        }
        if block.path() != self.path && block.path() != LOGICAL_GROUP {
            return Err(Error::Invalid);
        }
        let logical = block.path() == LOGICAL_GROUP;
        if !logical {
            if block.next() > self.next || block.ranges().last().is_some_and(|r| r.end > self.next)
            {
                return Err(Error::Sequence);
            }
            if let Some(tracker) = &mut self.timing
                && let Some(timing) = tracker.propose(block, now_us)
            {
                if timing.rto_us != self.rto {
                    for f in self
                        .flights
                        .values()
                        .filter(|f| f.reason == Reason::Timeout)
                    {
                        f.paid.checked_add(timing.rto_us).ok_or(Error::Clock)?;
                    }
                    self.rto = timing.rto_us;
                    for (&seq, f) in &mut self.flights {
                        if f.reason == Reason::Timeout {
                            self.deadlines.remove(&(f.due, seq));
                            f.due = f.paid + self.rto;
                            self.deadlines.insert((f.due, seq));
                        }
                    }
                }
                tracker.commit(block, timing);
            }
            // Only the highest threshold positive numbers from any interval can enter the set.
            for r in
                std::iter::once(block.floor()..block.next()).chain(block.ranges().iter().cloned())
            {
                for n in r.rev().take(self.later) {
                    self.highest.insert(n);
                }
            }
            while self.highest.len() > self.later {
                self.highest.pop_first();
            }
        }
        self.clock = now_us;
        let fast_before = (!logical && self.highest.len() == self.later)
            .then(|| self.highest.first().copied())
            .flatten();
        if logical {
            self.covered.retain(|&g, _| !block.acknowledges(g));
        }
        self.aliases.retain(|&seq, members| {
            if logical {
                members.retain(|&(g, _)| !block.acknowledges(g));
                return !members.is_empty();
            }
            if block.acknowledges(seq) {
                mark_covered(&mut self.covered, members, &mut positive);
                return false;
            }
            seq >= block.floor()
        });
        self.flights.retain(|&seq, f| {
            if logical {
                f.members.retain(|&m| {
                    if block.acknowledges(m.0) {
                        forget(&mut self.in_flight, m);
                        false
                    } else {
                        true
                    }
                });
            }
            if f.members.is_empty() || (!logical && block.acknowledges(seq)) {
                if !logical {
                    mark_covered(&mut self.covered, &f.members, &mut positive);
                    for &m in &f.members {
                        forget(&mut self.in_flight, m);
                    }
                }
                self.deadlines.remove(&(f.due, seq));
                return false;
            }
            let reason = if !logical && seq < block.floor() {
                Some(Reason::ExpiredHistory)
            } else if fast_before.is_some_and(|n| seq < n) {
                Some(Reason::SelectiveGap)
            } else {
                None
            };
            if let Some(reason) = reason {
                self.deadlines.remove(&(f.due, seq));
                f.due = f.due.min(now_us);
                f.reason = reason;
                self.deadlines.insert((f.due, seq));
            }
            true
        });
        Ok(())
    }

    /// Earliest paid-send timeout or currently actionable receipt gap on this path.
    pub fn next_deadline(&self) -> Option<u64> {
        self.deadlines.first().map(|v| v.0)
    }

    /// Transfer one packet's still-owed members to the retry batcher. The new attempt receives
    /// a fresh physical number and deadline only when the carrier accepts its actual bytes.
    pub fn take_due_with_reason(&mut self, now_us: u64) -> Option<(u64, Vec<Member>, Reason)> {
        let &(due, seq) = self.deadlines.first()?;
        if now_us < self.clock || due > now_us {
            return None;
        }
        self.clock = now_us;
        self.deadlines.remove(&(due, seq));
        let f = self.flights.remove(&seq)?;
        for &m in &f.members {
            forget(&mut self.in_flight, m);
        }
        let mut owed: Vec<_> = f
            .members
            .iter()
            .copied()
            .filter(|&m| self.needs_retry(m))
            .collect();
        owed.sort_unstable();
        owed.dedup();
        if f.reason != Reason::ExpiredHistory {
            self.aliases.insert(seq, f.members);
        }
        Some((seq, owed, f.reason))
    }

    /// Transfer eligible debt when the caller does not collect reason-specific telemetry.
    pub fn take_due(&mut self, now_us: u64) -> Option<(u64, Vec<Member>)> {
        self.take_due_with_reason(now_us)
            .map(|(seq, members, _)| (seq, members))
    }
}

fn forget(counts: &mut BTreeMap<Member, usize>, member: Member) {
    if let std::collections::btree_map::Entry::Occupied(mut count) = counts.entry(member) {
        if *count.get() == 1 {
            count.remove();
        } else {
            *count.get_mut() -= 1;
        }
    }
}

fn mark_covered(
    covered: &mut BTreeMap<u64, [u64; 4]>,
    members: &[Member],
    positive: &mut impl FnMut(Member),
) {
    for &(g, i) in members {
        // The facade limits the live native sequence span to MAX_WINDOW. Also bound
        // positive-receipt hints for independent callers with sparse generation IDs.
        if covered.len() == MAX_WINDOW && !covered.contains_key(&g) {
            covered.pop_first();
        }
        let word = &mut covered.entry(g).or_default()[usize::from(i / 64)];
        let bit = 1u64 << (i % 64);
        if *word & bit == 0 {
            *word |= bit;
            positive((g, i));
        }
    }
}

#[cfg(test)]
mod tests;
