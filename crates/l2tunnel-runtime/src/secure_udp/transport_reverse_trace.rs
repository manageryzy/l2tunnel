//! Optional per-direction startup traces of Packed records on the original UDP socket.
use l2tunnel::record_engine::{Engine, ProfileIdentity, RollingDataLabel, StripedDataLabel};
use l2tunnel_codec::aligned_receiver::{RecordIdentity, UnitWitness};
use l2tunnel_fec::rolling::scheduler::OutputId;
use ring::digest::{SHA256, digest};
use std::{
    fs::File,
    io::{self, BufWriter, Write},
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::time::Instant;

const MAX_EVENTS: usize = 65_536;
const PACKET_LIMIT: u64 = 4_096;
const MAX_SEND_YIELDS: usize = 4_096;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Direction {
    Reverse,
    Forward,
    Both,
}

enum Event {
    Read([u8; 32]),
    Packed(RecordIdentity, l2tunnel_pipeline::PacketTiming),
    Unit(UnitWitness),
    Selected(Option<RollingDataLabel>),
    MixedMember(StripedDataLabel),
    MixedSeal(l2tunnel_fec::striped_group::GroupSeal),
    RepairSupport(l2tunnel_fec::rolling::Support),
    Accepted,
    Opened(bool),
    Admission(Admission),
    Native(RecordIdentity, [u8; 32]),
    Written(RecordIdentity),
}

fn packed_identity(id: ProfileIdentity) -> Option<RecordIdentity> {
    match id {
        ProfileIdentity::Rolling(id) | ProfileIdentity::Striped(id) => Some(id),
        _ => None,
    }
}

#[derive(Clone, Copy)]
pub(super) enum Admission {
    Accepted,
    FifoFull,
    Refused,
}

struct Ledger {
    events: Vec<(u64, u64, u64, Event)>,
    overflow: u64,
    file: File,
}

pub(super) struct Trace {
    sender: Option<Ledger>,
    receiver: Option<Ledger>,
    reads: u64,
    send_yields: Vec<(u64, usize, u64)>,
    excess_send_yields: u64,
    yield_file: File,
    anchor: (u128, u128, u128),
    origin: Instant,
}

impl Trace {
    pub(super) fn from_environment(responder: bool, origin: Instant) -> io::Result<Option<Self>> {
        let Some(dir) = std::env::var_os("L2TUNNEL_REVERSE_RECORD_TRACE_DIR") else {
            return Ok(None);
        };
        let direction = match std::env::var_os("L2TUNNEL_RECORD_TRACE_DIRECTION") {
            None => Direction::Reverse,
            Some(value) if value == "reverse" => Direction::Reverse,
            Some(value) if value == "forward" => Direction::Forward,
            Some(value) if value == "both" => Direction::Both,
            Some(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "record trace direction must be reverse, forward or both",
                ));
            }
        };
        Self::in_directory(Path::new(&dir), responder, direction, origin).map(Some)
    }

    pub(super) fn in_directory(
        dir: &Path,
        responder: bool,
        direction: Direction,
        origin: Instant,
    ) -> io::Result<Self> {
        let role = if responder { "b" } else { "a" };
        let suffix = format!("{role}-{}.tsv", std::process::id());
        let mut sender = None;
        let mut receiver = None;
        for (flow, prefix, outbound) in [
            (Direction::Forward, "forward-records", !responder),
            (Direction::Reverse, "records", responder),
        ] {
            if direction == flow || direction == Direction::Both {
                let mut events = Vec::new();
                events
                    .try_reserve_exact(MAX_EVENTS)
                    .map_err(io::Error::other)?;
                let ledger = Ledger {
                    events,
                    overflow: 0,
                    file: File::create_new(dir.join(format!("{prefix}-{suffix}")))?,
                };
                if outbound {
                    sender = Some(ledger);
                } else {
                    receiver = Some(ledger);
                }
            }
        }
        let mut send_yields = Vec::new();
        send_yields
            .try_reserve_exact(MAX_SEND_YIELDS)
            .map_err(io::Error::other)?;
        let yield_file = File::create_new(dir.join(format!("udp-send-yields-{suffix}")))?;
        let before = origin.elapsed().as_nanos();
        let wall = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(io::Error::other)?
            .as_nanos();
        let after = origin.elapsed().as_nanos();
        Ok(Self {
            sender,
            receiver,
            reads: 0,
            send_yields,
            excess_send_yields: 0,
            yield_file,
            anchor: (before, wall, after),
            origin,
        })
    }

    pub(super) fn udp_send_yield(&mut self, now: u64, emitted: usize, send_poll_us: u64) {
        if self.send_yields.len() < MAX_SEND_YIELDS {
            self.send_yields.push((now, emitted, send_poll_us));
        } else {
            self.excess_send_yields = self.excess_send_yields.saturating_add(1);
        }
    }

    pub(super) fn read(&mut self, at: u64, epoch: u64, bytes: &[u8]) {
        if let Some(ledger) = &mut self.sender
            && self.reads < PACKET_LIMIT
        {
            self.reads += 1;
            ledger.record(at, epoch, 0, Event::Read(native_hash(bytes)));
        }
    }

    pub(super) fn packed(
        &mut self,
        at: u64,
        epoch: u64,
        id: ProfileIdentity,
        timing: l2tunnel_pipeline::PacketTiming,
    ) {
        if let Some(ledger) = &mut self.sender
            && let Some(identity) = packed_identity(id)
            && identity.record.0 < PACKET_LIMIT
        {
            ledger.record(at, epoch, 0, Event::Packed(identity, timing));
        }
    }

    pub(super) fn selected<'a>(
        &mut self,
        at: u64,
        epoch: u64,
        pn: u64,
        units: &[UnitWitness],
        label: Option<RollingDataLabel>,
        output: impl FnOnce() -> Option<(&'a Engine, &'a [u8])>,
    ) {
        if let Some(ledger) = &mut self.sender
            && pn < PACKET_LIMIT
        {
            ledger.record(at, epoch, pn, Event::Selected(label));
            match label.map(|label| label.id) {
                Some(OutputId::Repair(id)) => {
                    if let Some((engine, _)) = output()
                        && let Some(row) = engine.prepared_rolling_repair_support(id)
                    {
                        ledger.record(at, epoch, pn, Event::RepairSupport(row));
                    }
                }
                None => {
                    if let Some((engine, bytes)) = output()
                        && let Some(mixed) = engine.prepared_striped_data(bytes)
                    {
                        ledger.record(at, epoch, pn, Event::MixedMember(mixed));
                        if let Some(seal) = engine.prepared_striped_group_seal() {
                            ledger.record(at, epoch, pn, Event::MixedSeal(seal));
                        }
                    }
                }
                _ => {}
            }
            for unit in units {
                ledger.record(at, epoch, pn, Event::Unit(*unit));
            }
        }
    }

    pub(super) fn accepted(&mut self, at: u64, epoch: u64, pn: u64) {
        if let Some(ledger) = &mut self.sender
            && pn < PACKET_LIMIT
        {
            ledger.record(at, epoch, pn, Event::Accepted);
        }
    }

    pub(super) fn opened(&mut self, at: u64, epoch: u64, pn: u64, authenticated: bool) {
        if let Some(ledger) = &mut self.receiver
            && pn < PACKET_LIMIT
        {
            ledger.record(at, epoch, pn, Event::Opened(authenticated));
        }
    }

    pub(super) fn admission(&mut self, at: u64, epoch: u64, pn: u64, result: Admission) {
        if let Some(ledger) = &mut self.receiver
            && pn < PACKET_LIMIT
        {
            ledger.record(at, epoch, pn, Event::Admission(result));
        }
    }

    pub(super) fn native(
        &mut self,
        epoch: u64,
        id: ProfileIdentity,
        bytes: &[u8],
    ) -> io::Result<()> {
        if let Some(ledger) = &mut self.receiver
            && let Some(identity) = packed_identity(id)
            && identity.record.0 < PACKET_LIMIT
        {
            if ledger.events.len() == MAX_EVENTS {
                ledger.overflow = ledger.overflow.saturating_add(1);
            } else {
                // Sample after prepare_native returned the complete bytes, before hashing them.
                let at = super::clock(self.origin, Instant::now())?;
                ledger.record(at, epoch, 0, Event::Native(identity, native_hash(bytes)));
            }
        }
        Ok(())
    }

    pub(super) fn written(&mut self, at: u64, epoch: u64, id: ProfileIdentity) {
        if let Some(ledger) = &mut self.receiver
            && let Some(identity) = packed_identity(id)
            && identity.record.0 < PACKET_LIMIT
        {
            ledger.record(at, epoch, 0, Event::Written(identity));
        }
    }

    fn save(&self) -> io::Result<()> {
        let (before, wall, after) = self.anchor;
        for ledger in self.sender.iter().chain(&self.receiver) {
            ledger.save(self.anchor)?;
        }
        let mut yields = BufWriter::new(&self.yield_file);
        writeln!(yields, "anchor_ns\t{before}\t{wall}\t{after}")?;
        writeln!(
            yields,
            "limits\t{MAX_SEND_YIELDS}\t{}",
            self.excess_send_yields
        )?;
        writeln!(yields, "now_us\temitted\tsince_first_send_poll_us")?;
        for (now, emitted, send_poll_us) in &self.send_yields {
            writeln!(yields, "{now}\t{emitted}\t{send_poll_us}")?;
        }
        yields.flush()
    }
}

impl Ledger {
    fn record(&mut self, at: u64, epoch: u64, number: u64, event: Event) {
        if self.events.len() < MAX_EVENTS {
            self.events.push((at, epoch, number, event));
        } else {
            self.overflow = self.overflow.saturating_add(1);
        }
    }

    fn save(&self, (before, wall, after): (u128, u128, u128)) -> io::Result<()> {
        let mut out = BufWriter::new(&self.file);
        writeln!(out, "anchor_ns\t{before}\t{wall}\t{after}")?;
        writeln!(
            out,
            "limits\t{PACKET_LIMIT}\t{MAX_EVENTS}\t{}",
            self.overflow
        )?;
        for (at, epoch, pn, event) in &self.events {
            write!(out, "{at}\t{epoch}\t{pn}\t")?;
            match event {
                Event::Read(hash) => {
                    write!(out, "read_done\t")?;
                    write_hash(&mut out, hash)?;
                }
                Event::Packed(id, timing) => writeln!(
                    out,
                    "packed\t{}\t{}\t{}\t{}",
                    id.channel.0,
                    id.record.0,
                    timing.received.as_micros(),
                    timing.admitted.as_micros()
                )?,
                Event::Unit(u) => writeln!(
                    out,
                    "unit\t{}\t{}\t{}\t{}",
                    u.identity.channel.0, u.identity.record.0, u.index, u.count
                )?,
                Event::Selected(Some(label)) => {
                    let (kind, id) = match label.id {
                        OutputId::Source(id) => ("source", u64::from(id.0)),
                        OutputId::Repair(id) => ("repair", id.0),
                        OutputId::Near8(id) => ("near8", u64::from(id.0)),
                    };
                    writeln!(
                        out,
                        "selected\t{kind}\t{id}\t{}\t{}",
                        label.copy_ordinal.unwrap_or(0),
                        label.requested
                    )?;
                }
                // The unchanged mixed_member with this epoch/PN supplies the generation,
                // shape and selected source count. Both rows share the selection clock.
                Event::MixedSeal(seal) => writeln!(
                    out,
                    "mixed_seal\t{}\t{}\t{}\t{}\t{}\t{}",
                    seal.at,
                    seal.deadline,
                    seal.batch_offset,
                    seal.remaining,
                    seal.longest,
                    seal.selected
                )?,
                Event::MixedMember(label) => {
                    use l2tunnel_fec::{
                        mixed_datagram::GroupShape, striped_group::schedule::DataKind,
                    };
                    let (shape, value) = match label.shape {
                        GroupShape::Originals(count) => ("originals", count),
                        GroupShape::Split(length) => ("split", length),
                    };
                    let attempt = match label.kind {
                        DataKind::Fresh(_) => "fresh",
                        DataKind::Named(_) => "named",
                        DataKind::Quiet(_) => "quiet",
                    };
                    writeln!(
                        out,
                        "mixed_member\t{attempt}\t{}\t{}\t{shape}\t{value}\t{}",
                        label.generation.0, label.ordinal, label.threshold
                    )?;
                }
                Event::Selected(None) => writeln!(out, "selected")?,
                Event::RepairSupport(row) => writeln!(
                    out,
                    "repair_support\t{}\t{}\t{}\t{}",
                    row.start, row.end, row.seed, row.tail
                )?,
                Event::Accepted => writeln!(out, "socket")?,
                Event::Opened(auth) => writeln!(out, "opened\t{auth}")?,
                Event::Admission(outcome) => {
                    let value = match outcome {
                        Admission::Accepted => "accepted",
                        Admission::FifoFull => "fifo_full",
                        Admission::Refused => "refused",
                    };
                    writeln!(out, "admission\t{value}")?;
                }
                Event::Native(id, hash) => {
                    write!(out, "native_ready\t{}\t{}\t", id.channel.0, id.record.0)?;
                    write_hash(&mut out, hash)?;
                }
                Event::Written(id) => writeln!(out, "tun\t{}\t{}", id.channel.0, id.record.0)?,
            }
        }
        out.flush()
    }
}

fn native_hash(bytes: &[u8]) -> [u8; 32] {
    let mut hash = [0; 32];
    hash.copy_from_slice(digest(&SHA256, bytes).as_ref());
    hash
}

fn write_hash(out: &mut impl Write, hash: &[u8; 32]) -> io::Result<()> {
    for byte in hash {
        write!(out, "{byte:02x}")?;
    }
    writeln!(out)
}

impl Drop for Trace {
    fn drop(&mut self) {
        if let Err(error) = self.save() {
            let _ = writeln!(
                io::stderr().lock(),
                "Reverse record trace write failed: {error}"
            );
        }
    }
}
