//! Exact local ticket custody latencies; none is physical IP transmission time.
use super::super::Class;
use std::io::{self, Write};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Identity {
    pub(crate) owner: u64,
    pub(crate) serial: u64,
    pub(crate) class: Class,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct User {
    pub(crate) epoch: u64,
    pub(crate) configuration: [u8; 32],
    pub(crate) number: u64,
    pub(crate) bytes: usize,
    pub(crate) deadline_us: u64,
}
#[derive(Clone, Copy, Debug)]
struct Record {
    id: Identity,
    lane: usize,
    bytes: usize,
    deadline_us: u64,
    created_us: u64,
    first_poll_us: Option<u64>,
    accepted_us: Option<u64>,
    result_us: Option<u64>,
    observed_us: Option<u64>,
    taken_us: Option<u64>,
    stopped_us: Option<u64>,
    failed: bool,
    common: bool,
    user: Option<User>,
}
#[derive(Clone, Copy, Default)]
struct Span {
    completed: u64,
    completed_us: u64,
    failed: u64,
    failed_us: u64,
    censored: u64,
    censored_us: u64,
    maximum_us: Option<u64>,
    maximum_identity: Option<Identity>,
}
#[derive(Clone, Copy)]
enum Outcome {
    Completed,
    Failed,
    Censored,
}
#[derive(Clone, Copy, Default)]
struct Row {
    created: u64,
    completed: u64,
    failed: u64,
    censored: u64,
    spans: [Span; 5],
    last: Option<Record>,
}
/// Exactly two live cells and eight fixed lane/class/consumer summaries, in prepaid storage.
#[derive(Clone, Copy, Default)]
pub(crate) struct Snapshot {
    pending: [Option<Record>; 2],
    rows: [Row; 8],
    first_us: Option<u64>,
    stopped_us: Option<u64>,
    invalid: bool,
}
const STAGES: [&str; 5] = [
    "creation_to_first_poll",
    "first_poll_to_returned_queue_acceptance",
    "queue_acceptance_to_result_latch",
    "result_latch_to_upper_observation",
    "upper_observation_to_take",
];
fn add(value: &mut u64, amount: u64, invalid: &mut bool) {
    *value = value.checked_add(amount).unwrap_or_else(|| {
        *invalid = true;
        u64::MAX
    });
}
impl Snapshot {
    fn cell(&self, id: Identity) -> Option<usize> {
        let index = usize::from(id.class == Class::Control);
        self.pending[index]
            .filter(|record| record.id == id)
            .map(|_| index)
    }
    fn span(&mut self, record: Record, stage: usize, start: u64, end: u64, outcome: Outcome) {
        let Some(elapsed) = end.checked_sub(start) else {
            self.invalid = true;
            return;
        };
        let span = &mut self.rows[row_index(record)].spans[stage];
        let (count, total) = match outcome {
            Outcome::Completed => (&mut span.completed, &mut span.completed_us),
            Outcome::Failed => (&mut span.failed, &mut span.failed_us),
            Outcome::Censored => (&mut span.censored, &mut span.censored_us),
        };
        add(count, 1, &mut self.invalid);
        add(total, elapsed, &mut self.invalid);
        if span.maximum_us.is_none_or(|old| elapsed > old) {
            span.maximum_us = Some(elapsed);
            span.maximum_identity = Some(record.id);
        }
    }
    pub(crate) fn create(
        &mut self,
        id: Identity,
        lane: usize,
        bytes: usize,
        deadline_us: u64,
        now: u64,
    ) {
        if self.stopped_us.is_some() {
            return;
        }
        let index = usize::from(id.class == Class::Control);
        if lane > 1 || self.pending[index].is_some() {
            self.invalid = true;
            return;
        }
        self.first_us.get_or_insert(now);
        self.pending[index] = Some(Record {
            id,
            lane,
            bytes,
            deadline_us,
            created_us: now,
            first_poll_us: None,
            accepted_us: None,
            result_us: None,
            observed_us: None,
            taken_us: None,
            stopped_us: None,
            failed: false,
            common: false,
            user: None,
        });
        add(
            &mut self.rows[lane * 4 + index * 2].created,
            1,
            &mut self.invalid,
        );
    }
    pub(crate) fn bind(&mut self, id: Identity, user: Option<User>) {
        if let Some(index) = self.cell(id) {
            let Some(mut record) = self.pending[index] else {
                return;
            };
            if record.first_poll_us.is_some() || record.common {
                self.invalid = true;
                return;
            }
            let old = row_index(record);
            record.common = true;
            record.user = user;
            let Some(created) = self.rows[old].created.checked_sub(1) else {
                self.invalid = true;
                return;
            };
            self.rows[old].created = created;
            add(
                &mut self.rows[row_index(record)].created,
                1,
                &mut self.invalid,
            );
            self.pending[index] = Some(record);
        }
    }
    pub(crate) fn first_poll(&mut self, id: Identity, now: u64) {
        let Some(index) = self.cell(id) else {
            return;
        };
        let Some(mut record) = self.pending[index] else {
            return;
        };
        if record.first_poll_us.is_some() {
            return;
        }
        record.first_poll_us = Some(now);
        self.pending[index] = Some(record);
        self.span(record, 0, record.created_us, now, Outcome::Completed);
    }
    pub(crate) fn result(&mut self, id: Identity, accepted: Option<u64>, failed: bool, now: u64) {
        let Some(index) = self.cell(id) else {
            return;
        };
        let Some(mut record) = self.pending[index] else {
            return;
        };
        if record.result_us.is_some() {
            return;
        }
        record.result_us = Some(now);
        record.accepted_us = accepted;
        record.failed = failed;
        self.pending[index] = Some(record);
        if let Some(start) = record.first_poll_us {
            self.span(
                record,
                1,
                start,
                accepted.unwrap_or(now),
                if accepted.is_some() {
                    Outcome::Completed
                } else {
                    Outcome::Failed
                },
            );
        } else {
            self.invalid = true;
        }
        if let Some(accepted) = accepted {
            self.span(record, 2, accepted, now, Outcome::Completed);
        }
    }
    pub(crate) fn observed(&mut self, id: Identity, now: u64) {
        let Some(index) = self.cell(id) else {
            return;
        };
        let Some(mut record) = self.pending[index] else {
            return;
        };
        if record.observed_us.is_some() {
            return;
        }
        record.observed_us = Some(now);
        self.pending[index] = Some(record);
        if let Some(start) = record.result_us {
            self.span(record, 3, start, now, Outcome::Completed);
        } else {
            self.invalid = true;
        }
    }
    pub(crate) fn direct_take(&mut self, id: Identity, now: u64) {
        if self
            .cell(id)
            .and_then(|index| self.pending[index])
            .is_some_and(|record| !record.common)
        {
            self.observed(id, now);
            self.take(id, now);
        }
    }
    pub(crate) fn take(&mut self, id: Identity, now: u64) {
        let Some(index) = self.cell(id) else {
            return;
        };
        let Some(mut record) = self.pending[index].take() else {
            return;
        };
        if let Some(start) = record.observed_us {
            self.span(record, 4, start, now, Outcome::Completed);
        } else {
            self.invalid = true;
        }
        record.taken_us = Some(now);
        record.stopped_us = Some(now);
        self.retire(
            record,
            if record.failed {
                Outcome::Failed
            } else {
                Outcome::Completed
            },
        );
    }
    fn retire(&mut self, record: Record, outcome: Outcome) {
        let row = &mut self.rows[row_index(record)];
        let count = match outcome {
            Outcome::Completed => &mut row.completed,
            Outcome::Failed => &mut row.failed,
            Outcome::Censored => &mut row.censored,
        };
        add(count, 1, &mut self.invalid);
        row.last = Some(record);
    }
    pub(crate) fn finish(&mut self, now: u64) {
        if self.stopped_us.is_some() {
            return;
        }
        self.stopped_us = Some(now);
        for index in 0..2 {
            let Some(mut record) = self.pending[index].take() else {
                continue;
            };
            let (stage, start) = if let Some(at) = record.observed_us {
                (4, at)
            } else if let Some(at) = record.result_us {
                (3, at)
            } else if let Some(at) = record.first_poll_us {
                (1, at)
            } else {
                (0, record.created_us)
            };
            self.span(record, stage, start, now, Outcome::Censored);
            record.stopped_us = Some(now);
            self.retire(
                record,
                if record.failed {
                    Outcome::Failed
                } else {
                    Outcome::Censored
                },
            );
        }
    }
    pub(crate) fn invalid_clock(&mut self) {
        self.invalid = true;
    }
    pub(crate) fn write(&self, out: &mut impl Write) -> io::Result<()> {
        write!(
            out,
            "{{\"schema\":1,\"definition\":\"local ticket custody latencies, not physical IP send or continuous blockage; stages overlap generic waits and must not join their union; failed operation can retain completed acceptance stages\",\"cutoff\":\"carrier_drop\",\"invalid\":{},\"first_us\":",
            self.invalid
        )?;
        optional(out, self.first_us)?;
        write!(out, ",\"stopped_us\":")?;
        optional(out, self.stopped_us)?;
        write!(out, ",\"live_capacity\":2,\"pending\":[")?;
        let mut first = true;
        for record in self.pending.iter().flatten() {
            if !first {
                write!(out, ",")?;
            }
            first = false;
            write_record(out, *record)?;
        }
        write!(out, "],\"rows\":[")?;
        first = true;
        for (index, row) in self
            .rows
            .iter()
            .enumerate()
            .filter(|(_, row)| row.created != 0)
        {
            if !first {
                write!(out, ",")?;
            }
            first = false;
            write!(
                out,
                "{{\"lane\":{},\"class\":\"{}\",\"consumer\":\"{}\",\"created\":{},\"completed\":{},\"failed\":{},\"censored\":{},\"last\":",
                index / 4,
                if (index / 2) % 2 == 0 {
                    "User"
                } else {
                    "Control"
                },
                if index % 2 == 0 { "Direct" } else { "Common" },
                row.created,
                row.completed,
                row.failed,
                row.censored
            )?;
            if let Some(record) = row.last {
                write_record(out, record)?;
            } else {
                write!(out, "null")?;
            }
            write!(out, ",\"stages\":[")?;
            for (index, span) in row.spans.iter().enumerate() {
                if index != 0 {
                    write!(out, ",")?;
                }
                write!(
                    out,
                    "{{\"stage\":\"{}\",\"completed\":{},\"completed_us\":{},\"failed\":{},\"failed_us\":{},\"censored\":{},\"censored_us\":{},\"maximum_us\":",
                    STAGES[index],
                    span.completed,
                    span.completed_us,
                    span.failed,
                    span.failed_us,
                    span.censored,
                    span.censored_us
                )?;
                optional(out, span.maximum_us)?;
                write!(out, ",\"maximum_identity\":")?;
                if let Some(id) = span.maximum_identity {
                    write_id(out, id)?;
                } else {
                    write!(out, "null")?;
                }
                write!(out, "}}")?;
            }
            write!(out, "]}}")?;
        }
        write!(out, "]}}")
    }
}
fn row_index(record: Record) -> usize {
    record.lane * 4
        + usize::from(record.id.class == Class::Control) * 2
        + usize::from(record.common)
}
fn optional(out: &mut impl Write, value: Option<u64>) -> io::Result<()> {
    match value {
        Some(value) => write!(out, "{value}"),
        None => write!(out, "null"),
    }
}
fn write_id(out: &mut impl Write, id: Identity) -> io::Result<()> {
    write!(
        out,
        "{{\"owner\":{},\"serial\":{},\"class\":\"{:?}\"}}",
        id.owner, id.serial, id.class
    )
}
fn write_record(out: &mut impl Write, record: Record) -> io::Result<()> {
    write!(out, "{{\"identity\":")?;
    write_id(out, record.id)?;
    write!(
        out,
        ",\"lane\":{},\"bytes\":{},\"deadline_us\":{},\"created_us\":{},\"failed\":{},\"consumer\":\"{}\",\"user\":",
        record.lane,
        record.bytes,
        record.deadline_us,
        record.created_us,
        record.failed,
        if record.common { "Common" } else { "Direct" }
    )?;
    if let Some(user) = record.user {
        write!(out, "{{\"epoch\":{},\"configuration\":\"", user.epoch)?;
        for byte in user.configuration {
            write!(out, "{byte:02x}")?;
        }
        write!(
            out,
            "\",\"packet_number\":{},\"bytes\":{},\"deadline_us\":{}}}",
            user.number, user.bytes, user.deadline_us
        )?;
    } else {
        write!(out, "null")?;
    }
    for (name, value) in [
        ("first_poll_us", record.first_poll_us),
        ("accepted_us", record.accepted_us),
        ("result_us", record.result_us),
        ("observed_us", record.observed_us),
        ("taken_us", record.taken_us),
        ("stopped_us", record.stopped_us),
    ] {
        write!(out, ",\"{name}\":")?;
        optional(out, value)?;
    }
    write!(out, "}}")
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn failed_late_acceptance_and_cancel_have_distinct_original_stages() {
        let id = Identity {
            owner: 1,
            serial: 7,
            class: Class::User,
        };
        let mut state = Snapshot::default();
        state.create(id, 1, 99, 10, 1);
        state.bind(id, None);
        state.first_poll(id, 4);
        state.first_poll(id, 5);
        state.result(id, Some(12), true, 14);
        state.observed(id, 17);
        state.take(id, 20);
        state.take(id, 30);
        let row = state.rows[5];
        assert_eq!(
            (row.created, row.completed, row.failed, row.censored),
            (1, 0, 1, 0)
        );
        assert_eq!(row.spans.map(|span| span.completed_us), [3, 8, 2, 3, 3]);
        assert_eq!(row.last.and_then(|record| record.accepted_us), Some(12));
        let next = Identity { serial: 8, ..id };
        state.create(next, 1, 99, 45, 25);
        state.bind(next, None);
        state.finish(31);
        assert_eq!(state.rows[5].spans[0].censored_us, 6);
        assert_eq!(state.rows[5].censored, 1);
        assert!(!state.invalid);
    }
    #[test]
    fn no_acceptance_is_failed_not_zero_and_foreign_take_has_no_progress() {
        let id = Identity {
            owner: 3,
            serial: 0,
            class: Class::Control,
        };
        let mut state = Snapshot::default();
        state.create(id, 0, 1, 9, 1);
        state.first_poll(id, 2);
        state.result(id, None, true, 9);
        state.take(Identity { owner: 4, ..id }, 10);
        state.observed(id, 10);
        state.take(id, 12);
        state.finish(13);
        assert_eq!(state.rows[2].spans[1].failed_us, 7);
        assert_eq!(state.rows[2].spans[2].maximum_us, None);
        assert_eq!(state.rows[2].failed, 1);
        assert!(!state.invalid);
    }
}
