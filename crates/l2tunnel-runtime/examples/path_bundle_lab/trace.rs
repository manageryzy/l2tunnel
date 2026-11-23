//! Optional fixed-capacity metadata ledger. No disk writes occur between READY and shutdown.
use super::*;
use rustix::time::{ClockId, clock_gettime};
use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::Path;

mod scheduler;
pub use scheduler::{PollSample, ScheduleRange};

const LIMIT: usize = 4_194_304;
const NA: u64 = u64::MAX;

pub struct Trace {
    file: Option<File>,
    rows: Vec<Row>,
    dropped: u64,
    schedule: Option<scheduler::Window>,
}

#[derive(Clone, Copy)]
pub struct Event {
    path: u8,
    seq: u64,
    pn: u64,
}
impl Event {
    pub fn new(path: u8, seq: Option<u64>, pn: u64) -> Self {
        Self {
            path,
            seq: seq.unwrap_or(NA),
            pn,
        }
    }
}

#[derive(Clone, Copy)]
struct Row {
    at: u64,
    event: &'static str,
    group: u64,
    link: Event,
    ordinal: u8,
    seq: u32,
    end: u32,
    ack: u32,
    flags: u8,
    sport: u16,
    dport: u16,
    range: Option<(u64, u64)>,
}
impl Row {
    fn new(at: u64, event: &'static str) -> Self {
        Self {
            at,
            event,
            group: NA,
            link: Event::new(255, None, NA),
            ordinal: 255,
            seq: 0,
            end: 0,
            ack: 0,
            flags: 0,
            sport: 0,
            dport: 0,
            range: None,
        }
    }
}

impl Trace {
    pub fn new(path: Option<&Path>, range: Option<ScheduleRange>) -> Result<Self> {
        let mut rows = Vec::new();
        let file = if let Some(p) = path {
            rows.try_reserve_exact(LIMIT)?;
            Some(File::create_new(p)?)
        } else {
            None
        };
        Ok(Self {
            file,
            rows,
            dropped: 0,
            schedule: range.map(scheduler::Window::new),
        })
    }
    pub fn active(&self) -> bool {
        self.file.is_some()
    }
    pub fn time(&self) -> u64 {
        if !self.active() {
            return 0;
        }
        let t = clock_gettime(ClockId::Monotonic);
        t.tv_sec as u64 * 1_000_000_000 + t.tv_nsec as u64
    }
    fn push(&mut self, row: Row) {
        if self.rows.len() < LIMIT {
            self.rows.push(row);
        } else {
            self.dropped += 1;
        }
    }
    pub fn shard(&mut self, at: u64, event: &'static str, link: Event, gid: u64, ordinal: u8) {
        if !self.active() {
            return;
        }
        self.push(Row {
            group: gid,
            link,
            ordinal,
            ..Row::new(at, event)
        });
    }
    pub fn retry(
        &mut self,
        at: u64,
        event: &'static str,
        link: Event,
        previous: u64,
        gid: u64,
        ordinal: u8,
    ) {
        if self.active() {
            self.push(Row {
                group: gid,
                link,
                ordinal,
                range: Some((previous, previous + 1)),
                ..Row::new(at, event)
            });
        }
    }
    pub fn observed_blocks(&mut self, at: u64, link: Event, batch: &AckBatch) {
        if self.active() {
            for block in batch.blocks().iter().filter(|b| b.path() != 255) {
                self.push(Row {
                    link,
                    ordinal: block.path(),
                    range: Some((block.floor(), block.next())),
                    ..Row::new(at, "physical_ack_prefix_rx")
                });
                for r in block.ranges() {
                    self.push(Row {
                        link,
                        ordinal: block.path(),
                        range: Some((r.start, r.end)),
                        ..Row::new(at, "physical_ack_range_rx")
                    });
                }
            }
        }
    }
    pub fn native(&mut self, event: &'static str, gid: u64, packet: &[u8]) {
        if !self.active() {
            return;
        }
        let mut r = Row {
            group: gid,
            ..Row::new(self.time(), event)
        };
        if packet.len() >= 20
            && packet[0] >> 4 == 4
            && packet[9] == 6
            && u16::from_be_bytes([packet[6], packet[7]]) & 0x3fff == 0
        {
            let ip = usize::from(packet[0] & 15) * 4;
            let total = usize::from(u16::from_be_bytes([packet[2], packet[3]]));
            if ip >= 20
                && let Some(tcp) = packet.get(ip..total)
                && tcp.len() >= 20
            {
                let off = usize::from(tcp[12] >> 4) * 4;
                if (20..=tcp.len()).contains(&off) {
                    r.sport = u16::from_be_bytes([tcp[0], tcp[1]]);
                    r.dport = u16::from_be_bytes([tcp[2], tcp[3]]);
                    r.seq = u32::from_be_bytes([tcp[4], tcp[5], tcp[6], tcp[7]]);
                    r.ack = u32::from_be_bytes([tcp[8], tcp[9], tcp[10], tcp[11]]);
                    r.flags = tcp[13];
                    r.end = r.seq.wrapping_add(
                        (tcp.len() - off) as u32
                            + u32::from(r.flags & 2 != 0)
                            + u32::from(r.flags & 1 != 0),
                    );
                }
            }
        }
        self.push(r);
    }
    pub fn control(&mut self, at: u64, event: &'static str, link: Event) {
        if self.active() {
            self.push(Row {
                link,
                ..Row::new(at, event)
            });
        }
    }

    pub fn physical(&mut self, at: u64, link: Event, ip_bytes: u64) {
        if self.active() {
            self.push(Row {
                link,
                range: Some((0, ip_bytes)),
                ..Row::new(at, "socket_paid")
            });
        }
    }
    pub fn names(&mut self, at: u64, event: &'static str, link: Event, request: &ShardRequest) {
        if self.active() {
            for (gid, ords) in request.rows() {
                for &ordinal in ords {
                    self.shard(at, event, link, *gid, ordinal);
                }
            }
        }
    }
    pub fn logical(&mut self, at: u64, event: &'static str, link: Event, batch: &AckBatch) {
        if self.active()
            && let Some(block) = batch.blocks().last().filter(|b| b.path() == 255)
        {
            for span in std::iter::once(0..block.next()).chain(block.ranges().iter().cloned()) {
                self.push(Row {
                    link,
                    range: Some((span.start, span.end)),
                    ..Row::new(at, event)
                });
            }
        }
    }
    pub fn status(&self) -> serde_json::Value {
        json!({"enabled":self.active(),"rows":self.rows.len(),"dropped":self.dropped,
            "capacity":self.rows.capacity(),"reserved_bytes":self.rows.capacity()*size_of::<Row>(),
            "clock":"Linux CLOCK_MONOTONIC ns","scheduler":self.schedule.as_ref().map(scheduler::Window::status)})
    }
    pub fn finish(&mut self) -> Result<()> {
        let Some(f) = self.file.take() else {
            return Ok(());
        };
        let mut out = BufWriter::new(f);
        writeln!(
            out,
            "time_ns,event,generation,path,data_seq,auth_pn,ordinal,tcp_seq,tcp_end,tcp_ack,tcp_flags,source_port,destination_port,start,end"
        )?;
        for r in &self.rows {
            write!(out, "{},{}", r.at, r.event)?;
            let tcp = r.sport != 0 || r.dport != 0;
            let fields = [
                (r.group != NA).then_some(r.group),
                (r.link.path != 255).then_some(u64::from(r.link.path)),
                (r.link.seq != NA).then_some(r.link.seq),
                (r.link.pn != NA).then_some(r.link.pn),
                (r.ordinal != 255).then_some(u64::from(r.ordinal)),
                tcp.then_some(u64::from(r.seq)),
                tcp.then_some(u64::from(r.end)),
                tcp.then_some(u64::from(r.ack)),
                tcp.then_some(u64::from(r.flags)),
                tcp.then_some(u64::from(r.sport)),
                tcp.then_some(u64::from(r.dport)),
                r.range.map(|v| v.0),
                r.range.map(|v| v.1),
            ];
            for v in fields {
                out.write_all(b",")?;
                if let Some(v) = v {
                    write!(out, "{v}")?;
                }
            }
            writeln!(out)?;
        }
        out.flush()?;
        Ok(())
    }
}
