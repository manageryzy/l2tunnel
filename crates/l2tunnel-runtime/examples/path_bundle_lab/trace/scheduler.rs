use super::*;
use std::str::FromStr;

const GROUP_LIMIT: u64 = 128;
const ROW_LIMIT: usize = 32_768;
const HARD_US: u64 = 100_000;
const TAIL_US: u64 = 2_000;

#[derive(Debug, Clone, Copy)]
pub struct ScheduleRange {
    first: u64,
    end: u64,
}

impl FromStr for ScheduleRange {
    type Err = &'static str;
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        let (first, end) = s
            .split_once(':')
            .ok_or("scheduler range must be FIRST:END")?;
        let first = first.parse().map_err(|_| "invalid first scheduler group")?;
        let end = end
            .parse::<u64>()
            .map_err(|_| "invalid scheduler group end")?;
        if !end
            .checked_sub(first)
            .is_some_and(|n| (1..=GROUP_LIMIT).contains(&n))
        {
            return Err("scheduler range must contain 1 through 128 groups");
        }
        Ok(Self { first, end })
    }
}

pub(super) struct Window {
    range: ScheduleRange,
    first_admit: Option<u64>,
    stop: u64,
    admitted: u64,
    rows: usize,
    dropped: u64,
    truncated_polls: u64,
}

impl Window {
    pub(super) fn new(range: ScheduleRange) -> Self {
        Self {
            range,
            first_admit: None,
            stop: 0,
            admitted: 0,
            rows: 0,
            dropped: 0,
            truncated_polls: 0,
        }
    }
    fn includes(&self, gid: u64) -> bool {
        (self.range.first..self.range.end).contains(&gid)
    }
    fn active(&self, now: u64) -> bool {
        self.first_admit
            .is_some_and(|start| start <= now && now < self.stop)
    }
    fn admit(&mut self, gid: u64, now: u64) {
        if !self.includes(gid) {
            return;
        }
        if gid == self.range.first && self.first_admit.is_none() {
            self.first_admit = Some(now);
            self.stop = now.saturating_add(HARD_US);
        }
        if self.active(now) {
            self.admitted += 1;
            if gid + 1 == self.range.end {
                self.stop = self.stop.min(now.saturating_add(TAIL_US));
            }
        }
    }
    pub(super) fn status(&self) -> serde_json::Value {
        json!({"first_group":self.range.first,"end_group_exclusive":self.range.end,
            "hard_limit_us":HARD_US,"tail_us":TAIL_US,"row_limit":ROW_LIMIT,
            "first_admit_elapsed_us":self.first_admit,"cutoff_elapsed_us":self.first_admit.map(|_|self.stop),
            "selected_admits_observed":self.admitted,"all_requested_admits_observed":self.admitted==self.range.end-self.range.first,
            "rows":self.rows,"dropped":self.dropped,"poll_returns_outside_window":self.truncated_polls,
            "deadline_clock":"Microseconds since endpoint origin; event time_ns is absolute CLOCK_MONOTONIC.",
            "stage_fields":"generation=accepted group, path=natural ordinal, data_seq=current batch head wake if timed, start=service elapsed us, end=group born deadline us if still absolutely owed",
            "poll_fields":"data_seq=poll ID; enter start/end=elapsed us/selected deadline, ordinal=requested TUN flags. Return start/end=elapsed us/ready fd count, ordinal=returned TUN flags. UDP detail start/end=requested/returned flags; UDP interest defaults to IN. Signal detail reports returned flags.",
            "prepared_fields":"path and data_seq identify the prepared DATA; start/end are service elapsed us and its absolute batch deadline us. sched_due_now start/end are the decision clock and selected deadline us when the loop skips poll.",
            "flag_bits":"IN=1 OUT=2 ERR=4 HUP=8 NVAL=16 PRI=32"})
    }
}

pub struct PollSample {
    pub id: u64,
    pub enter_ns: u64,
    pub return_ns: u64,
    pub entered: u64,
    pub returned: u64,
    pub deadline: u64,
    pub ready_count: usize,
    pub tun_interest: PollFlags,
    pub udp_out: [u64; 4],
}

fn flags(raw: PollFlags) -> u8 {
    [
        PollFlags::IN,
        PollFlags::OUT,
        PollFlags::ERR,
        PollFlags::HUP,
        PollFlags::NVAL,
        PollFlags::PRI,
    ]
    .into_iter()
    .enumerate()
    .fold(0, |bits, (i, f)| bits | (u8::from(raw.intersects(f)) << i))
}

impl Trace {
    pub fn scheduler_admit(&mut self, gid: u64, now: u64) {
        if let Some(w) = &mut self.schedule {
            w.admit(gid, now);
        }
    }
    pub fn scheduler_active(&self, now: u64) -> bool {
        self.schedule.as_ref().is_some_and(|w| w.active(now))
    }
    fn scheduler_row(&mut self, row: Row) {
        if let Some(w) = &mut self.schedule {
            if w.rows == ROW_LIMIT || self.rows.len() == LIMIT {
                w.dropped += 1;
            } else {
                w.rows += 1;
                self.rows.push(row);
            }
        }
    }
    pub fn scheduler_staged(
        &mut self,
        tx: &Transmitter,
        path: PathId,
        service_us: u64,
    ) -> Result<()> {
        if !self.scheduler_active(service_us) {
            return Ok(());
        }
        let (cursor, head_due) = tx.staging_cursor_and_head_wake(path)?;
        let gid = cursor
            .checked_sub(1)
            .ok_or("successful fresh stage lacked a cursor")?;
        if self.schedule.as_ref().is_some_and(|w| w.includes(gid)) {
            let due = tx.unpaid_natural_deadline(path, gid)?;
            self.scheduler_row(Row {
                group: gid,
                link: Event::new(path.get(), head_due.map(|t| t.as_micros() as u64), NA),
                range: due.map(|t| (service_us, t.as_micros() as u64)),
                ..Row::new(self.time(), "sched_stage")
            });
        }
        Ok(())
    }
    pub fn scheduler_due_now(&mut self, now: u64, due: u64) {
        if self.scheduler_active(now) {
            self.scheduler_row(Row {
                range: Some((now, due)),
                ..Row::new(self.time(), "sched_due_now")
            });
        }
    }
    pub fn scheduler_prepared(&mut self, batch: BatchId, now: u64, deadline: u64) {
        if self.scheduler_active(now) {
            self.scheduler_row(Row {
                link: Event::new(batch.path().get(), Some(batch.sequence()), NA),
                range: Some((now, deadline)),
                ..Row::new(self.time(), "sched_prepared")
            });
        }
    }
    pub fn scheduler_poll(&mut self, sample: PollSample, fds: &[PollFd<'_>]) {
        let link = Event::new(255, Some(sample.id), NA);
        self.scheduler_row(Row {
            link,
            ordinal: flags(sample.tun_interest),
            range: Some((sample.entered, sample.deadline)),
            ..Row::new(sample.enter_ns, "sched_poll_enter")
        });
        if !self.scheduler_active(sample.returned) {
            if let Some(w) = &mut self.schedule {
                w.truncated_polls += 1;
            }
            return;
        }
        self.scheduler_row(Row {
            link,
            ordinal: flags(fds[1].revents()),
            range: Some((sample.returned, sample.ready_count as u64)),
            ..Row::new(sample.return_ns, "sched_poll_return")
        });
        if !fds[0].revents().is_empty() {
            self.scheduler_row(Row {
                link,
                ordinal: flags(fds[0].revents()),
                ..Row::new(sample.return_ns, "sched_poll_signal")
            });
        }
        for (slot, fd) in fds.iter().skip(2).enumerate() {
            let writable = sample.udp_out[slot / 64] & (1u64 << (slot % 64)) != 0;
            if writable || !fd.revents().is_empty() {
                let requested = 1 | (u64::from(writable) << 1);
                self.scheduler_row(Row {
                    link: Event::new(slot as u8, Some(sample.id), NA),
                    range: Some((requested, u64::from(flags(fd.revents())))),
                    ..Row::new(sample.return_ns, "sched_poll_udp")
                });
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn range_and_tail_are_bounded_even_when_selected_groups_stop_arriving() -> Result<()> {
        for s in ["0:0", "3:2", "0:129", "0:1:2", "a:1"] {
            assert!(s.parse::<ScheduleRange>().is_err());
        }
        let mut w = Window::new("2:4".parse()?);
        w.admit(1, 10);
        assert!(!w.active(10));
        w.admit(2, 100);
        w.admit(3, 900);
        assert!(w.active(2899));
        assert!(!w.active(2900));
        let mut slow = Window::new("0:128".parse()?);
        slow.admit(0, 1);
        slow.admit(1, 100001);
        assert!(!slow.active(100001));
        assert_eq!(slow.admitted, 1);
        Ok(())
    }
    #[test]
    fn successful_stage_identifies_the_member_and_the_older_unpaid_head() -> Result<()> {
        let path = PathId::new(0)?;
        let config = PathConfig {
            mtu: 1500,
            outer_bytes: OUTER,
            max_hold: us(500),
            max_entries: 16,
        };
        let mut tx = Transmitter::new(&[config; 2], 2, 256, 32)?;
        let old = tx.admit(us(0), b"existing member")?;
        let gid = tx.admit(us(100), b"observed member")?;
        let mut t = Trace::new(None, Some("1:2".parse()?))?;
        t.scheduler_admit(gid, 100);
        assert_eq!(tx.fill_path_once(path, us(110), 32)?, 1);
        t.scheduler_staged(&tx, path, 110)?;
        assert!(t.rows.is_empty());
        assert_eq!(tx.fill_path_once(path, us(120), 32)?, 1);
        t.scheduler_staged(&tx, path, 120)?;
        let row = t.rows.first().ok_or("missing successful stage row")?;
        assert_ne!(old, gid);
        assert_eq!(
            (row.group, row.link.path, row.link.seq, row.range),
            (gid, 0, 500, Some((120, 600)))
        );
        assert_eq!(flags(PollFlags::IN | PollFlags::OUT | PollFlags::HUP), 11);
        // Exercise the final available row followed by one explicitly counted truncation.
        t.schedule.as_mut().ok_or("missing scheduler window")?.rows = ROW_LIMIT - 1;
        t.scheduler_due_now(121, 120);
        t.scheduler_due_now(122, 120);
        let w = t.schedule.as_ref().ok_or("missing scheduler status")?;
        assert_eq!((w.rows, w.dropped), (ROW_LIMIT, 1));
        Ok(())
    }
}
