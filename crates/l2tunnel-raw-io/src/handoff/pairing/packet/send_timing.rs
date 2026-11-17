//! Exact local PacketIo edge timing; diagnostic state never grants authority.
use tokio::time::Instant;

/// Episodes ending at one observed boundary, not a count of polling attempts.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SendTimingTotal {
    /// Number of ended episodes.
    pub episodes: u64,
    /// Sum of observed episode microseconds, with overflow reported separately.
    pub micros: u64,
}

/// One lane's observed actual PacketIo waits. Different lanes must not be summed
/// into wall time. An enabled-while-blocked episode has an unknown earlier start;
/// its observed portion is a lower bound, explicitly indicated below.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SendTimingSnapshot {
    /// Microseconds observed since this lane's timing was enabled.
    pub observed_micros: u64,
    /// Actual inner sends returning WouldBlock after timing was enabled.
    pub would_block_observations: u64,
    /// Episodes ended by actual successful PacketIo acceptance.
    pub completed: SendTimingTotal,
    /// Episodes censored by explicit cancellation of the retained send.
    pub cancelled: SendTimingTotal,
    /// Episodes censored before terminal lane destruction.
    pub terminal: SendTimingTotal,
    /// Current observed wait duration; None means no open observed wait.
    pub open_micros: Option<u64>,
    /// Maximum observed episode, including the current open portion.
    pub maximum_micros: u64,
    /// Episodes whose real start predates instrumentation; never invented as zero.
    pub left_censored_episodes: u64,
    /// At least one duration excludes an unknown earlier blocked portion.
    pub durations_are_lower_bounds: bool,
    /// Timing froze before terminal owner release.
    pub stopped: bool,
    /// A supplied observation moved backward; chronology is not qualified.
    pub invalid_clock: bool,
    /// A diagnostic duration or count saturated instead of wrapping.
    pub counter_overflow: bool,
}

#[derive(Clone, Copy)]
enum End {
    Completed,
    Cancelled,
    Terminal,
}

/// Clock-free arithmetic. Only the surrounding raw runtime samples Instant.
struct Waits {
    value: SendTimingSnapshot,
    last: u64,
    open: Option<u64>,
    finished: Option<u64>,
}
impl Waits {
    fn new(already_blocked: bool) -> Self {
        Self {
            value: SendTimingSnapshot {
                left_censored_episodes: u64::from(already_blocked),
                durations_are_lower_bounds: already_blocked,
                ..SendTimingSnapshot::default()
            },
            last: 0,
            open: already_blocked.then_some(0),
            finished: None,
        }
    }
    fn touch(&mut self, at: u64) -> u64 {
        if at < self.last {
            self.value.invalid_clock = true;
        }
        self.last = self.last.max(at);
        self.last
    }
    fn blocked(&mut self, at: u64) {
        if self.finished.is_some() {
            return;
        }
        let at = self.touch(at);
        add(
            &mut self.value.would_block_observations,
            1,
            &mut self.value.counter_overflow,
        );
        self.open.get_or_insert(at);
    }
    fn end(&mut self, kind: End, at: u64) {
        if self.finished.is_some() {
            return;
        }
        let at = self.touch(at);
        if let Some(start) = self.open.take() {
            let micros = at - start;
            let total = match kind {
                End::Completed => &mut self.value.completed,
                End::Cancelled => &mut self.value.cancelled,
                End::Terminal => &mut self.value.terminal,
            };
            add(&mut total.episodes, 1, &mut self.value.counter_overflow);
            add(&mut total.micros, micros, &mut self.value.counter_overflow);
            self.value.maximum_micros = self.value.maximum_micros.max(micros);
        }
        if matches!(kind, End::Terminal) {
            self.finished = Some(at);
            self.value.stopped = true;
        }
    }
    fn snapshot(&self, at: u64) -> SendTimingSnapshot {
        let mut value = self.value;
        let at = self.finished.unwrap_or_else(|| {
            value.invalid_clock |= at < self.last;
            at.max(self.last)
        });
        value.observed_micros = at;
        value.open_micros = self.open.map(|start| at - start);
        value.maximum_micros = value.maximum_micros.max(value.open_micros.unwrap_or(0));
        value
    }
}
fn add(value: &mut u64, amount: u64, overflow: &mut bool) {
    *value = value.checked_add(amount).unwrap_or_else(|| {
        *overflow = true;
        u64::MAX
    });
}

/// A single optional, preallocated lane cell. It is not a second I/O owner.
pub(super) struct SendTiming {
    origin: Instant,
    waits: Waits,
}
impl SendTiming {
    pub(super) fn new(origin: Instant, already_blocked: bool) -> Self {
        Self {
            origin,
            waits: Waits::new(already_blocked),
        }
    }
    fn elapsed(&mut self, at: Instant) -> u64 {
        match at.checked_duration_since(self.origin) {
            Some(value) => u64::try_from(value.as_micros()).unwrap_or_else(|_| {
                self.waits.value.counter_overflow = true;
                u64::MAX
            }),
            None => {
                self.waits.value.invalid_clock = true;
                0
            }
        }
    }
    pub(super) fn blocked(&mut self, at: Instant) {
        if self.waits.finished.is_some() {
            return;
        }
        let at = self.elapsed(at);
        self.waits.blocked(at);
    }
    pub(super) fn accepted(&mut self, at: Instant) {
        if self.waits.finished.is_some() {
            return;
        }
        let at = self.elapsed(at);
        self.waits.end(End::Completed, at);
    }
    pub(super) fn cancelled(&mut self, at: Instant) {
        if self.waits.finished.is_some() {
            return;
        }
        let at = self.elapsed(at);
        self.waits.end(End::Cancelled, at);
    }
    pub(super) fn terminal(&mut self, at: Instant) {
        if self.waits.finished.is_some() {
            return;
        }
        let at = self.elapsed(at);
        self.waits.end(End::Terminal, at);
    }
    pub(super) fn snapshot(&self, at: Instant) -> SendTimingSnapshot {
        let elapsed = at.checked_duration_since(self.origin);
        let micros = elapsed.map_or(0, |value| value.as_micros());
        let mut result = self.waits.snapshot(micros.min(u128::from(u64::MAX)) as u64);
        if self.waits.finished.is_none() {
            result.invalid_clock |= elapsed.is_none();
            result.counter_overflow |= micros > u128::from(u64::MAX);
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn packet_io_timing_keeps_each_edge_and_censors_without_recovery() {
        let mut waits = Waits::new(false);
        waits.blocked(5);
        waits.blocked(8);
        assert_eq!(waits.snapshot(10).open_micros, Some(5));
        waits.end(End::Completed, 15);
        // A later old-ACK refusal in the same turn starts another episode.
        waits.blocked(16);
        assert_eq!(
            waits.snapshot(20).completed,
            SendTimingTotal {
                episodes: 1,
                micros: 10
            }
        );
        assert_eq!(waits.snapshot(20).open_micros, Some(4));
        waits.end(End::Cancelled, 21);
        waits.end(End::Cancelled, 22);
        waits.blocked(25);
        waits.end(End::Terminal, 30);
        let saved = waits.snapshot(30);
        waits.blocked(200);
        waits.end(End::Completed, 300);
        assert_eq!(waits.snapshot(400), saved);
        assert_eq!(saved.would_block_observations, 4);
        assert_eq!(
            saved.cancelled,
            SendTimingTotal {
                episodes: 1,
                micros: 5
            }
        );
        assert_eq!(
            saved.terminal,
            SendTimingTotal {
                episodes: 1,
                micros: 5
            }
        );
        assert_eq!(saved.open_micros, None);
        assert_eq!(saved.maximum_micros, 10);
        assert!(saved.stopped);
    }

    #[test]
    fn packet_io_timing_marks_unknown_start_bad_clock_and_overflow() {
        let mut waits = Waits::new(true);
        assert_eq!(waits.snapshot(8).would_block_observations, 0);
        assert_eq!(waits.snapshot(8).left_censored_episodes, 1);
        assert!(waits.snapshot(8).durations_are_lower_bounds);
        waits.end(End::Completed, 10);
        waits.blocked(9);
        assert!(waits.snapshot(11).invalid_clock);
        waits.value.would_block_observations = u64::MAX;
        waits.blocked(12);
        assert!(waits.snapshot(12).counter_overflow);
        assert_eq!(waits.snapshot(12).would_block_observations, u64::MAX);
        assert_eq!(waits.snapshot(12).open_micros, Some(2));
    }
}
