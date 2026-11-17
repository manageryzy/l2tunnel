//! Two identity-joined scalar rows; missing stages remain unknown.
use super::{PhysicalWrite, add};
use l2tunnel_codec::aligned_receiver::RecordIdentity;
use std::io::{self, Write};
use tokio::time::Instant;

#[derive(Clone, Copy)]
pub(crate) enum Event {
    Handed {
        ordinal: u64,
        admitted: Option<Instant>,
        ledger_at: Instant,
        enqueue_before: Instant,
        enqueue_after: Instant,
    },
    WriterDequeued {
        ordinal: u64,
        at: Instant,
    },
    BridgeStarted {
        ordinal: u64,
        generation: u64,
        at: Instant,
    },
    CommonAdmitted {
        ordinal: u64,
        generation: u64,
        identity: RecordIdentity,
        at: Instant,
    },
    Whole(PhysicalWrite),
    Gate {
        ordinal: u64,
        admitted: Instant,
        at: Instant,
    },
}
impl Event {
    fn ordinal(self) -> Option<u64> {
        match self {
            Self::Handed { ordinal, .. }
            | Self::WriterDequeued { ordinal, .. }
            | Self::BridgeStarted { ordinal, .. }
            | Self::CommonAdmitted { ordinal, .. }
            | Self::Gate { ordinal, .. } => Some(ordinal),
            Self::Whole(receipt) => receipt.ordinal,
        }
    }
}
#[derive(Clone, Copy)]
struct Row {
    ordinal: u64,
    admitted: Option<Instant>,
    ledger_at: Option<Instant>,
    enqueue_before: Option<Instant>,
    enqueue_after: Option<Instant>,
    writer_dequeued: Option<Instant>,
    generation: Option<u64>,
    bridge_started: Option<Instant>,
    identity: Option<RecordIdentity>,
    common_admitted: Option<Instant>,
    whole: Option<PhysicalWrite>,
    gate: Option<Instant>,
}
impl Row {
    fn new(ordinal: u64) -> Self {
        Self {
            ordinal,
            admitted: None,
            ledger_at: None,
            enqueue_before: None,
            enqueue_after: None,
            writer_dequeued: None,
            generation: None,
            bridge_started: None,
            identity: None,
            common_admitted: None,
            whole: None,
            gate: None,
        }
    }
    fn apply(&mut self, event: Event) -> bool {
        let same = match event {
            Event::Handed {
                admitted,
                ledger_at,
                enqueue_before,
                enqueue_after,
                ..
            } => {
                admitted.is_none_or(|at| set(&mut self.admitted, at))
                    && set(&mut self.ledger_at, ledger_at)
                    && set(&mut self.enqueue_before, enqueue_before)
                    && set(&mut self.enqueue_after, enqueue_after)
            }
            Event::WriterDequeued { at, .. } => set(&mut self.writer_dequeued, at),
            Event::BridgeStarted { generation, at, .. } => {
                set(&mut self.generation, generation) && set(&mut self.bridge_started, at)
            }
            Event::CommonAdmitted {
                generation,
                identity,
                at,
                ..
            } => {
                set(&mut self.generation, generation)
                    && set(&mut self.identity, identity)
                    && set(&mut self.common_admitted, at)
            }
            Event::Whole(receipt) => {
                set(&mut self.generation, receipt.generation)
                    && set(&mut self.identity, receipt.identity)
                    && set(&mut self.whole, receipt)
            }
            Event::Gate { admitted, at, .. } => {
                let valid = set(&mut self.admitted, admitted)
                    && self.gate.is_none_or(|previous| previous <= at);
                if valid {
                    self.gate = Some(at);
                }
                valid
            }
        };
        same && ordered(self.admitted, self.ledger_at)
            && ordered(self.ledger_at, self.enqueue_before)
            && ordered(self.enqueue_before, self.enqueue_after)
            && ordered(self.enqueue_before, self.writer_dequeued)
            && ordered(self.writer_dequeued, self.bridge_started)
            && ordered(self.bridge_started, self.common_admitted)
            && ordered(self.common_admitted, self.whole.map(|r| r.accepted_at))
            && ordered(
                self.whole.map(|r| r.accepted_at),
                self.whole.map(|r| r.observed_at),
            )
            && ordered(self.admitted, self.gate)
        // enqueue_after may follow writer_dequeued: another thread can dequeue
        // immediately after send, before the actor records its upper bound.
    }
    fn write(&self, out: &mut impl Write, origin: Instant) -> io::Result<()> {
        write!(out, "{{\"ordinal\":{},\"generation\":", self.ordinal)?;
        scalar(out, self.generation)?;
        write!(out, ",\"common_channel\":")?;
        scalar(out, self.identity.map(|id| u64::from(id.channel.0)))?;
        write!(out, ",\"common_record\":")?;
        scalar(out, self.identity.map(|id| id.record.0))?;
        for (name, at) in [
            ("measured_admitted_at", self.admitted),
            ("ledger_handoff_at", self.ledger_at),
            ("enqueue_before", self.enqueue_before),
            ("enqueue_after", self.enqueue_after),
            ("writer_dequeued_at", self.writer_dequeued),
            ("bridge_started_at", self.bridge_started),
            ("common_admitted_at", self.common_admitted),
            ("whole_accepted_at", self.whole.map(|r| r.accepted_at)),
            ("common_observed_at", self.whole.map(|r| r.observed_at)),
            ("last_gate_at", self.gate),
        ] {
            write!(out, ",\"{name}\":")?;
            scalar(
                out,
                at.and_then(|at| at.checked_duration_since(origin))
                    .and_then(|d| u64::try_from(d.as_micros()).ok()),
            )?;
        }
        write!(out, "}}")
    }
}
#[derive(Clone, Default)]
pub(super) struct Tail {
    rows: [Option<Row>; 2],
    discarded_old_events: u64,
    invalid: bool,
}
impl Tail {
    pub(super) fn observe(&mut self, event: Event) {
        let Some(ordinal) = event.ordinal() else {
            return;
        };
        if ordinal == 0 {
            self.invalid = true;
            return;
        }
        let slot = ((ordinal - 1) % 2) as usize;
        if self.rows[slot].is_some_and(|row| row.ordinal > ordinal) {
            self.invalid |= !add(&mut self.discarded_old_events, 1);
            return;
        }
        let mut next = self.rows[slot]
            .filter(|row| row.ordinal == ordinal)
            .unwrap_or_else(|| Row::new(ordinal));
        if next.apply(event) {
            self.rows[slot] = Some(next);
        } else {
            // A mismatched generation/record or time never replaces valid facts.
            self.invalid = true;
        }
    }
    pub(super) fn write(&self, out: &mut impl Write, origin: Instant) -> io::Result<()> {
        write!(
            out,
            "{{\"capacity\":2,\"invalid\":{},\"discarded_old_events\":{},\"definition\":\"owner-relative microseconds; exact identity-joined stages; enqueue is bounded by before/after and may race writer dequeue; missing is null; rows are not blocked intervals; ledger_handoff_at precedes actual enqueue\",\"rows\":[",
            self.invalid, self.discarded_old_events
        )?;
        let mut rows = self.rows;
        if rows[0]
            .zip(rows[1])
            .is_some_and(|(a, b)| a.ordinal > b.ordinal)
        {
            rows.swap(0, 1);
        }
        for (index, row) in rows.iter().flatten().enumerate() {
            if index != 0 {
                write!(out, ",")?;
            }
            row.write(out, origin)?;
        }
        write!(out, "]}}")
    }
}
fn set<T: Copy + Eq>(slot: &mut Option<T>, value: T) -> bool {
    if slot.is_some_and(|old| old != value) {
        return false;
    }
    *slot = Some(value);
    true
}
fn ordered(first: Option<Instant>, second: Option<Instant>) -> bool {
    first
        .zip(second)
        .is_none_or(|(first, second)| first <= second)
}
fn scalar(out: &mut impl Write, value: Option<u64>) -> io::Result<()> {
    match value {
        Some(value) => write!(out, "{value}"),
        None => write!(out, "null"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use l2tunnel_codec::aligned_receiver::{ChannelId, RecordId};
    use std::time::Duration;
    fn time(origin: Instant, us: u64) -> Instant {
        origin + Duration::from_micros(us)
    }
    fn json(tail: &Tail, origin: Instant) -> io::Result<serde_json::Value> {
        let mut bytes = Vec::new();
        tail.write(&mut bytes, origin)?;
        serde_json::from_slice(&bytes).map_err(io::Error::other)
    }
    #[test]
    fn joined_tail_accepts_publication_race_and_keeps_enqueue_bounds() -> io::Result<()> {
        let origin = Instant::now();
        let mut tail = Tail::default();
        let identity = RecordIdentity {
            channel: ChannelId(0),
            record: RecordId(47),
        };
        // The writer's events can arrive before the actor publishes the bracket.
        tail.observe(Event::WriterDequeued {
            ordinal: 46,
            at: time(origin, 30),
        });
        tail.observe(Event::BridgeStarted {
            ordinal: 46,
            generation: 48,
            at: time(origin, 31),
        });
        tail.observe(Event::CommonAdmitted {
            ordinal: 46,
            generation: 48,
            identity,
            at: time(origin, 40),
        });
        tail.observe(Event::Handed {
            ordinal: 46,
            admitted: Some(origin),
            ledger_at: time(origin, 20),
            enqueue_before: time(origin, 25),
            enqueue_after: time(origin, 35),
        });
        tail.observe(Event::Whole(PhysicalWrite {
            ordinal: Some(46),
            generation: 48,
            identity,
            accepted_at: time(origin, 49),
            observed_at: time(origin, 51),
        }));
        tail.observe(Event::Gate {
            ordinal: 46,
            admitted: origin,
            at: time(origin, 54),
        });
        let value = json(&tail, origin)?;
        assert_eq!(value["invalid"], false);
        let row = &value["rows"][0];
        assert_eq!(row["ordinal"], 46);
        assert_eq!(row["enqueue_before"], 25);
        assert_eq!(row["enqueue_after"], 35);
        assert_eq!(row["writer_dequeued_at"], 30);
        assert_eq!(row["common_observed_at"], 51);
        assert_eq!(row["last_gate_at"], 54);
        Ok(())
    }
    #[test]
    fn joined_tail_rejects_wrong_identity_and_never_replaces_newer_ordinal() -> io::Result<()> {
        let origin = Instant::now();
        let mut tail = Tail::default();
        let identity = RecordIdentity {
            channel: ChannelId(0),
            record: RecordId(47),
        };
        tail.observe(Event::CommonAdmitted {
            ordinal: 46,
            generation: 48,
            identity,
            at: time(origin, 40),
        });
        tail.observe(Event::Whole(PhysicalWrite {
            ordinal: Some(46),
            generation: 48,
            identity: RecordIdentity {
                record: RecordId(48),
                ..identity
            },
            accepted_at: time(origin, 49),
            observed_at: time(origin, 51),
        }));
        let value = json(&tail, origin)?;
        assert_eq!(value["invalid"], true);
        assert_eq!(value["rows"][0]["common_record"], 47);
        assert!(value["rows"][0]["whole_accepted_at"].is_null());
        tail.observe(Event::WriterDequeued {
            ordinal: 48,
            at: time(origin, 60),
        });
        tail.observe(Event::WriterDequeued {
            ordinal: 46,
            at: time(origin, 30),
        });
        let value = json(&tail, origin)?;
        assert_eq!(value["discarded_old_events"], 1);
        assert_eq!(value["rows"][0]["ordinal"], 48);
        assert!(value["rows"][0]["measured_admitted_at"].is_null());
        assert!(value["rows"][0]["generation"].is_null());
        Ok(())
    }
}
