//! Actual data FIFO-head refusal to removal, not arrival residence or decoder CPU time.
use super::*;

/// Canonical authenticated data arm already checked before entering the FIFO.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Kind {
    /// Systematic source input.
    Source,
    /// Repair equation input.
    Repair,
}
/// Immutable existing ingress metadata; no peer bytes are reparsed for observation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Input {
    /// Exact authenticated Records number when supplied by the caller.
    pub records_number: Option<u64>,
    /// Original authenticated arrival, not the first refusal.
    pub received: Tick,
    /// Original retained job/caller cap, never renewed.
    pub deadline: Tick,
    /// Exact initialized retained input extent.
    pub bytes: usize,
    /// Already validated input arm.
    pub kind: Kind,
}
/// Successful removal result; duplicate/stale removal is not new decoder admission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Outcome {
    /// A new actual decoder job owns this input.
    Staged,
    /// The input exactly matches an already retained original/equation.
    Duplicate,
    /// The original input is outside the useful retained horizon.
    Stale,
}
impl Outcome {
    pub(crate) const fn index(self) -> usize {
        match self {
            Self::Staged => 0,
            Self::Duplicate => 1,
            Self::Stale => 2,
        }
    }
}
/// Disjoint completion or censor population at this one FIFO-head boundary.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Population {
    /// Number of actual refused heads resolved into this population.
    pub episodes: u64,
    /// Sum of injected first-Busy-to-removal/terminal durations.
    pub elapsed_us: u64,
    /// Largest observed interval in this population.
    pub maximum_us: u64,
}
/// The current actual refused FIFO head and separate blocking decoder context.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Pending {
    /// Local data-head serial; full endpoint/configuration identity surrounds it.
    pub serial: u64,
    /// Immutable actual input metadata.
    pub input: Input,
    /// First actual Busy, excluding earlier unattempted queue residence.
    pub since: Tick,
    /// Latest actual Busy for the same head.
    pub last_refusal: Tick,
    /// Actual job preventing the first admission attempt, when available.
    pub first_blocker: Option<rolling::expiry::DecoderJob>,
    /// Actual job at the latest Busy; never relabeled as the queued input.
    pub latest_blocker: Option<rolling::expiry::DecoderJob>,
}
/// Most recently completed/censored actual refusal episode.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Resolved {
    /// Exact original head and refusal context.
    pub pending: Pending,
    /// Successful removal or fresh terminal tick.
    pub at: Tick,
    /// None means unresolved at terminal, not successful admission.
    pub outcome: Option<Outcome>,
    /// Newly admitted job only for Staged, distinct from the blocking job.
    pub admitted_job: Option<rolling::expiry::DecoderJob>,
}
/// Fixed optional summary; one active data head, no per-packet queue or event log.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Snapshot {
    /// Next local data-head serial; u64::MAX means diagnostic exhaustion.
    pub next_head: u64,
    /// Actual Busy returns including retries.
    pub refusals: u64,
    /// Actual same-head successful removals by Staged, Duplicate and Stale.
    pub completions: [u64; 3],
    /// Corresponding successful removals with no observed Busy.
    pub without_refusal: [u64; 3],
    /// Staged, Duplicate, Stale and terminal-censored duration populations.
    pub populations: [Population; 4],
    /// Current refused immutable data head.
    pub pending: Option<Pending>,
    /// Last resolved episode only; not a full history or maximum witness.
    pub last_resolved: Option<Resolved>,
    /// Fresh source-terminal boundary, if available.
    pub terminal_at: Option<Tick>,
    /// Terminal observation lacked a fresh source snapshot.
    pub terminal_unavailable: bool,
    /// Actual refusals not represented after diagnostic serial exhaustion.
    pub omitted_refusals: u64,
    /// Busy returned without an observable actual blocker.
    pub blocker_unavailable: u64,
}
impl Default for Snapshot {
    fn default() -> Self {
        Self {
            next_head: 1,
            refusals: 0,
            completions: [0; 3],
            without_refusal: [0; 3],
            populations: [Population::default(); 4],
            pending: None,
            last_resolved: None,
            terminal_at: None,
            terminal_unavailable: false,
            omitted_refusals: 0,
            blocker_unavailable: 0,
        }
    }
}
impl Snapshot {
    pub(super) fn refuse(
        &mut self,
        input: Input,
        blocker: Option<rolling::expiry::DecoderJob>,
        now: Tick,
        mismatch: &mut bool,
        overflow: &mut bool,
    ) {
        increment(&mut self.refusals, overflow);
        if blocker.is_none() {
            increment(&mut self.blocker_unavailable, overflow);
        }
        if self.next_head == u64::MAX {
            increment(&mut self.omitted_refusals, overflow);
            return;
        }
        let pending = self.pending.get_or_insert(Pending {
            serial: self.next_head,
            input,
            since: now,
            last_refusal: now,
            first_blocker: blocker,
            latest_blocker: blocker,
        });
        if pending.serial != self.next_head || pending.input != input {
            *mismatch = true;
            increment(&mut self.omitted_refusals, overflow);
            return;
        }
        pending.last_refusal = now;
        pending.latest_blocker = blocker;
    }
    pub(super) fn complete(
        &mut self,
        input: Input,
        outcome: Outcome,
        admitted_job: Option<rolling::expiry::DecoderJob>,
        now: Tick,
        mismatch: &mut bool,
        overflow: &mut bool,
    ) {
        let index = outcome.index();
        increment(&mut self.completions[index], overflow);
        if (outcome == Outcome::Staged) != admitted_job.is_some() {
            *mismatch = true;
        }
        if let Some(job) = admitted_job
            && (job.received.0 != input.received.0
                || job.admitted.0 != now.0
                || job.deadline.0 != input.deadline.0)
        {
            *mismatch = true;
        }
        if let Some(pending) = self.pending {
            if pending.serial != self.next_head || pending.input != input {
                *mismatch = true;
                return;
            }
            self.resolve(now, Some(outcome), admitted_job, overflow);
        } else {
            increment(&mut self.without_refusal[index], overflow);
        }
        increment(&mut self.next_head, overflow);
    }
    fn resolve(
        &mut self,
        now: Tick,
        outcome: Option<Outcome>,
        admitted_job: Option<rolling::expiry::DecoderJob>,
        overflow: &mut bool,
    ) {
        let Some(pending) = self.pending.take() else {
            return;
        };
        let row = &mut self.populations[outcome.map_or(3, Outcome::index)];
        let elapsed = now.0 - pending.since.0;
        increment(&mut row.episodes, overflow);
        if let Some(sum) = row.elapsed_us.checked_add(elapsed) {
            row.elapsed_us = sum;
        } else {
            *overflow = true;
        }
        row.maximum_us = row.maximum_us.max(elapsed);
        self.last_resolved = Some(Resolved {
            pending,
            at: now,
            outcome,
            admitted_job,
        });
    }
    pub(super) fn stop(&mut self, now: Tick, fresh: bool, overflow: &mut bool) {
        if !fresh {
            self.terminal_unavailable = true;
            return;
        }
        self.resolve(now, None, None, overflow);
        self.terminal_at = Some(now);
    }
}
