//! Bounded real source/repair packet packing over one admission-aligned sender.
use super::{
    Config, Error, Feedback, FeedbackDisposition, Output, Scope, Sender, SenderStatus, SourceId,
    Tick, WorkBudget, WorkUsed, add, batch_wire, rolling,
    sender::{Detached, PackingPosition},
    storage, wire,
};
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_INSTANCE: AtomicU64 = AtomicU64::new(1);

/// Complete class of a represented physical packet.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Kind {
    /// First systematic sources, sharing one receipt and loss event.
    Source,
    /// Frozen real equations, sharing one receipt and loss event.
    Repair,
    /// One original source retry, never delayed by a source packer.
    Retry,
}
impl Kind {
    pub(super) fn code(self) -> u8 {
        match self {
            Self::Source => 1,
            Self::Repair => 2,
            Self::Retry => 3,
        }
    }
    pub(super) fn from_code(value: u8) -> Result<Self, Error> {
        match value {
            1 => Ok(Self::Source),
            2 => Ok(Self::Repair),
            3 => Ok(Self::Retry),
            _ => Err(Error::Format),
        }
    }
}
/// Explicit packing and complete packet-custody resource policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Packing {
    /// Maximum sources per packet, matching Python source_batch, in 1..=255.
    pub source_batch: u16,
    /// Maximum equations per packet, matching Python repair_batch, in 1..=255.
    pub repair_batch: u16,
    /// Original first-item timer; later items never renew it.
    pub pack_wait_ticks: u64,
    /// Python grouping MTU, including its analytical 88-byte header.
    pub analytical_mtu: usize,
    /// Actual L2LB packet byte ceiling, before outer authentication/carrier bytes.
    pub max_packet_bytes: usize,
    /// Actual fixed packet slots, including both open packers and held output.
    pub packet_slots: usize,
    /// Complete wrapper plus nested heap allowance; excludes caller buffers/RSS.
    pub memory_bytes: usize,
}
impl Packing {
    /// Validate exact scalar policy and both analytical grouping and actual wire bounds.
    pub fn validate(self, config: Config) -> Result<(), Error> {
        config.validate()?;
        if !(1..=255).contains(&self.source_batch)
            || !(1..=255).contains(&self.repair_batch)
            || self.packet_slots == 0
            || self.memory_bytes == 0
            || self.memory_bytes > rolling::MAX_MEMORY
            || self.analytical_mtu != add(88, config.feedback_payload_budget)?
            || config.recovery.max_payload > config.feedback_payload_budget
            || self.max_packet_bytes > 65_535
            || self.max_packet_bytes < self.required_packet_bytes(config)?
        {
            return Err(Error::Configuration);
        }
        Ok(())
    }
    /// Actual largest packet over the possible count/analytical-size cohorts.
    pub fn required_packet_bytes(self, config: Config) -> Result<usize, Error> {
        let payload = self
            .analytical_mtu
            .checked_sub(88)
            .ok_or(Error::Configuration)?;
        // Every original has at least one byte; each later item adds four
        // analytical bytes. A repair's real vector still has its fixed width.
        let maximum_count = add(payload, 4)? / 5;
        let sources = usize::from(self.source_batch).min(maximum_count);
        let repairs = usize::from(self.repair_batch).min(maximum_count);
        if sources == 0 || repairs == 0 {
            return Err(Error::Configuration);
        }
        let source_payload = sources
            .checked_mul(config.recovery.max_payload)
            .ok_or(Error::Exhausted)?
            .min(payload - 4 * (sources - 1));
        let source_bytes = add(
            batch_wire::HEADER_BYTES,
            add(
                sources
                    .checked_mul(wire::HEADER_BYTES + 2)
                    .ok_or(Error::Exhausted)?,
                source_payload,
            )?,
        )?;
        let repair_bytes = add(
            wire::HEADER_BYTES + 2,
            add(
                5 * usize::from(config.long_window),
                config.recovery.width()?,
            )?,
        )?;
        Ok(source_bytes.max(add(
            batch_wire::HEADER_BYTES,
            repairs.checked_mul(repair_bytes).ok_or(Error::Exhausted)?,
        )?))
    }
    fn items(self) -> usize {
        usize::from(self.source_batch.max(self.repair_batch))
    }
    fn maximum(self, kind: Kind) -> usize {
        match kind {
            Kind::Source => usize::from(self.source_batch),
            Kind::Repair => usize::from(self.repair_batch),
            Kind::Retry => 1,
        }
    }
}
/// Checked complete nested allocation plan; inline owner is charged by memory_bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Plan {
    config: Config,
    packing: Packing,
    usage: storage::Usage,
}
impl Plan {
    /// Plan the one recovery owner, actual packet slabs and all custody metadata.
    pub fn new(config: Config, packing: Packing) -> Result<Self, storage::Error> {
        packing.validate(config)?;
        let base = storage::Plan::for_sender_admission(config)?;
        let mut usage = storage::Usage {
            capacity_bytes: base.capacity_bytes(),
            allocations: base.allocations(),
        };
        usage = storage::join(
            usage,
            storage::requested::<Option<Packet>>(packing.packet_slots)?,
        )?;
        usage = storage::join(
            usage,
            storage::requested::<Option<Detached>>(
                packing
                    .packet_slots
                    .checked_mul(packing.items())
                    .ok_or(storage::Error::Overflow)?,
            )?,
        )?;
        usage = storage::join(
            usage,
            storage::requested::<u8>(
                packing
                    .packet_slots
                    .checked_mul(packing.max_packet_bytes)
                    .ok_or(storage::Error::Overflow)?,
            )?,
        )?;
        if usage
            .capacity_bytes
            .checked_add(std::mem::size_of::<BatchSender>())
            .ok_or(storage::Error::Overflow)?
            > packing.memory_bytes
        {
            return Err(storage::Error::Capacity);
        }
        Ok(Self {
            config,
            packing,
            usage,
        })
    }
    /// Exact planned nested capacity, excluding inline owner and allocator metadata.
    pub fn capacity_bytes(self) -> usize {
        self.usage.capacity_bytes
    }
    /// Number of actual nonempty retained vector allocations.
    pub fn allocations(self) -> usize {
        self.usage.allocations
    }
}
/// Owner-bound nonwrapping identity for one immutable whole physical packet.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Id {
    instance: u64,
    serial: u64,
}
/// One actual whole-packet output; repeated borrows return identical bytes/identity.
#[derive(Clone, Copy, Debug)]
pub struct PacketOutput<'a> {
    /// Opaque physical custody identity, never an authenticated wire identity.
    pub id: Id,
    /// Source, repair or single retry packet.
    pub kind: Kind,
    /// Number of actual represented records.
    pub records: usize,
    /// Complete actual L2LB bytes.
    pub bytes: &'a [u8],
    /// Original earliest immutable item cap.
    pub deadline: Tick,
}
impl PacketOutput<'_> {
    /// Reserve every physical batch byte and the caller's outer overhead once.
    pub fn charge(self, overhead: usize) -> Result<usize, Error> {
        add(self.bytes.len(), overhead)
    }
}
/// Reported whole physical fact, retained even when observation discovers expiry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Receipt {
    /// Exact packet that physically completed.
    pub id: Id,
    /// Complete represented record count.
    pub records: usize,
    /// Actual packet bytes, excluding caller's carrier overhead.
    pub bytes: usize,
    /// Actual whole-write completion, not enqueue admission.
    pub accepted: Tick,
    /// Receipt callback observation.
    pub observed: Tick,
    /// Terminal timing/bookkeeping failure after this physical fact, if any.
    pub failure: Option<Error>,
}
#[derive(Clone, Copy)]
struct Packet {
    kind: Kind,
    length: usize,
    count: usize,
    analytical: usize,
    due: Tick,
    expires: Tick,
    prepared: Tick,
    ready: Option<Tick>,
    id: Option<Id>,
    filled: usize,
}
struct Append {
    length: usize,
    analytical: usize,
    event: Tick,
    now: Tick,
}
/// Two bounded packers and physical output custody around the same real sender.
pub struct BatchSender {
    sender: Sender,
    config: Config,
    packing: Packing,
    packets: Vec<Option<Packet>>,
    tokens: Vec<Option<Detached>>,
    bytes: Vec<u8>,
    source: Option<usize>,
    repair: Option<usize>,
    instance: u64,
    serial: u64,
    receipt: Option<Receipt>,
    terminal: Option<Error>,
    active: Option<usize>,
}
impl BatchSender {
    /// Provision exact requested and observed storage before accepting any source.
    pub fn new_reserved(
        config: Config,
        packing: Packing,
        scope: Scope,
        now: Tick,
        limits: storage::Limits,
    ) -> Result<Self, storage::Error> {
        let plan = Plan::new(config, packing)?;
        if limits.capacity_bytes < plan.capacity_bytes() {
            return Err(storage::Error::Capacity);
        }
        super::deadline(now, packing.pack_wait_ticks)?;
        let sender_plan = storage::Plan::for_sender_admission(config)?;
        let mut sender = Sender::new_reserved_admission(
            config,
            scope,
            now,
            storage::Limits {
                capacity_bytes: sender_plan.capacity_bytes(),
            },
        )?;
        sender.select_batching()?;
        let mut value = Self {
            sender,
            config,
            packing,
            packets: super::slots(packing.packet_slots, None)?,
            tokens: super::slots(
                packing
                    .packet_slots
                    .checked_mul(packing.items())
                    .ok_or(Error::Exhausted)?,
                None,
            )?,
            bytes: super::slots(
                packing
                    .packet_slots
                    .checked_mul(packing.max_packet_bytes)
                    .ok_or(Error::Exhausted)?,
                0,
            )?,
            source: None,
            repair: None,
            instance: 0,
            serial: 1,
            receipt: None,
            terminal: None,
            active: None,
        };
        if value.storage_usage()? != plan.usage {
            return Err(storage::Error::Layout);
        }
        value.instance = NEXT_INSTANCE
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |id| id.checked_add(1))
            .map_err(|_| Error::Exhausted)?;
        Ok(value)
    }
    /// Observe actual nested capacities; no packet-time backing growth occurs.
    pub fn storage_usage(&self) -> Result<storage::Usage, storage::Error> {
        let usage = storage::join(
            self.sender.storage_usage()?,
            storage::vector(&self.packets)?,
        )?;
        let usage = storage::join(usage, storage::vector(&self.tokens)?)?;
        storage::join(usage, storage::vector(&self.bytes)?)
    }
    fn healthy(&self) -> Result<(), Error> {
        if self.terminal.is_some() {
            Err(Error::Terminal)
        } else {
            Ok(())
        }
    }
    fn fail<T>(&mut self, error: Error) -> Result<T, Error> {
        self.terminal = Some(error);
        Err(error)
    }
    fn open(&self, kind: Kind) -> Option<usize> {
        match kind {
            Kind::Source => self.source,
            Kind::Repair => self.repair,
            Kind::Retry => None,
        }
    }
    fn set_open(&mut self, kind: Kind, slot: Option<usize>) {
        match kind {
            Kind::Source => self.source = slot,
            Kind::Repair => self.repair = slot,
            Kind::Retry => {}
        }
    }
    fn flush(&mut self, kind: Kind, at: Tick) -> Result<(), Error> {
        let Some(slot) = self.open(kind) else {
            return Ok(());
        };
        let mut packet = self.packets[slot].ok_or(Error::Identity)?;
        let header = batch_wire::header(kind, packet.count)?;
        let serial = self.serial.checked_add(1).ok_or(Error::Exhausted)?;
        let start = slot * self.packing.max_packet_bytes;
        self.bytes[start..start + batch_wire::HEADER_BYTES].copy_from_slice(&header);
        packet.id = Some(Id {
            instance: self.instance,
            serial: self.serial,
        });
        packet.ready = Some(at);
        self.serial = serial;
        self.packets[slot] = Some(packet);
        self.set_open(kind, None);
        self.activate_ready();
        Ok(())
    }
    fn timer(&mut self, kind: Kind, now: Tick) -> Result<(), Error> {
        if let Some(slot) = self.open(kind)
            && let Some(packet) = self.packets[slot]
            && now >= packet.due
        {
            self.flush(kind, packet.due)?;
        }
        Ok(())
    }
    fn reserve_repairs(&mut self, now: Tick) -> Result<(), Error> {
        // Every successful visit assigns a previously unassigned real job.
        // The fixed queue is at most 1024; no payload/GF work is done here.
        for _ in 0..self.config.repair_queue {
            let Some(candidate) = self.sender.repair_packing_candidate(now)? else {
                break;
            };
            let slot = match self.place(Kind::Repair, candidate.analytical, candidate.event) {
                Ok(slot) => slot,
                Err(Error::Capacity) => return Ok(()),
                Err(error) => return Err(error),
            };
            let mut packet = self.entry(slot, Kind::Repair, candidate.event, candidate.cap)?;
            if add(packet.length, add(2, candidate.length)?)? > self.packing.max_packet_bytes {
                return Err(Error::Length);
            }
            let position = PackingPosition {
                slot,
                index: packet.count,
                offset: packet.length,
                length: candidate.length,
            };
            packet.expires = packet.expires.min(candidate.cap);
            // Close/count the actual cohort at its original event even if its
            // reserved payload bytes need later incremental GF turns.
            self.appended(
                slot,
                packet,
                None,
                Append {
                    length: candidate.length,
                    analytical: candidate.analytical,
                    event: candidate.event,
                    now: candidate.event,
                },
            )?;
            self.sender.assign_repair_packet(candidate.slot, position)?;
        }
        self.timer(Kind::Repair, now)
    }
    fn place(&mut self, kind: Kind, analytical: usize, event: Tick) -> Result<usize, Error> {
        if analytical == 0 || add(88, analytical)? > self.packing.analytical_mtu {
            return Err(Error::Length);
        }
        if let Some(slot) = self.open(kind) {
            let packet = self.packets[slot].ok_or(Error::Identity)?;
            if event > packet.due {
                self.flush(kind, packet.due)?;
            } else if add(packet.analytical, add(4, analytical)?)? > self.packing.analytical_mtu {
                self.flush(kind, event)?;
            }
        }
        if self.serial == u64::MAX {
            return Err(Error::Exhausted);
        }
        if let Some(slot) = self.open(kind) {
            return Ok(slot);
        }
        super::deadline(event, self.packing.pack_wait_ticks)?;
        self.packets
            .iter()
            .position(Option::is_none)
            .ok_or(Error::Capacity)
    }
    fn entry(&self, slot: usize, kind: Kind, event: Tick, cap: Tick) -> Result<Packet, Error> {
        if let Some(packet) = self.packets[slot] {
            return Ok(packet);
        }
        Ok(Packet {
            kind,
            length: batch_wire::HEADER_BYTES,
            count: 0,
            analytical: 88,
            due: super::deadline(event, self.packing.pack_wait_ticks)?,
            expires: cap,
            prepared: event,
            ready: None,
            id: None,
            filled: 0,
        })
    }
    fn appended(
        &mut self,
        slot: usize,
        mut packet: Packet,
        token: Option<Detached>,
        item: Append,
    ) -> Result<(), Error> {
        let Append {
            length,
            analytical,
            event,
            now,
        } = item;
        let start = slot * self.packing.max_packet_bytes + packet.length;
        self.bytes[start..start + 2].copy_from_slice(&(length as u16).to_be_bytes());
        let index = slot * self.packing.items() + packet.count;
        self.tokens[index] = token;
        packet.length += 2 + length;
        packet.analytical += analytical + if packet.count == 0 { 0 } else { 4 };
        packet.count += 1;
        if let Some(token) = token {
            packet.expires = packet.expires.min(token.expires);
            packet.prepared = packet.prepared.max(token.prepared);
            packet.filled += 1;
        }
        self.packets[slot] = Some(packet);
        self.set_open(packet.kind, Some(slot));
        if packet.kind == Kind::Retry {
            let header = batch_wire::header(packet.kind, packet.count)?;
            let start = slot * self.packing.max_packet_bytes;
            self.bytes[start..start + batch_wire::HEADER_BYTES].copy_from_slice(&header);
            let next = self.serial.checked_add(1).ok_or(Error::Exhausted)?;
            packet.id = Some(Id {
                instance: self.instance,
                serial: self.serial,
            });
            packet.ready = Some(event);
            self.serial = next;
            self.packets[slot] = Some(packet);
            self.activate_ready();
        } else if packet.count == self.packing.maximum(packet.kind)
            || add(packet.analytical, 5)? > self.packing.analytical_mtu
        {
            self.flush(packet.kind, event)?;
        } else if now > packet.due {
            self.flush(packet.kind, packet.due)?;
        }
        Ok(())
    }
    /// Add to the real source packer and coding window at the original admission time.
    /// A lack of packet capacity is refused before the recovery owner admits bytes.
    pub fn admit_source<C: super::CoefficientSource + ?Sized>(
        &mut self,
        original: &[u8],
        created: Tick,
        now: Tick,
        random: &mut C,
    ) -> Result<SourceId, Error> {
        self.healthy()?;
        self.sender
            .check_batch_time(now)
            .or_else(|error| self.fail(error))?;
        self.reserve_repairs(now)
            .or_else(|error| self.fail(error))?;
        let length = wire::source_len(self.config, original.len())?;
        let slot = self.place(Kind::Source, original.len(), now)?;
        let cap = super::deadline(created, self.config.recovery.job_ticks)?;
        let packet = self.entry(slot, Kind::Source, now, cap)?;
        if add(packet.length, add(2, length)?)? > self.packing.max_packet_bytes {
            return Err(Error::Length);
        }
        let id = self
            .sender
            .admit_source_with_coefficients(original, created, now, random)?;
        let start = slot * self.packing.max_packet_bytes + packet.length + 2;
        let (token, written) = self
            .sender
            .detach_source(id, now, &mut self.bytes[start..start + length])
            .or_else(|error| self.fail(error))?;
        self.appended(
            slot,
            packet,
            Some(token),
            Append {
                length: written,
                analytical: original.len(),
                event: now,
                now,
            },
        )
        .or_else(|error| self.fail(error))?;
        // Python add_to_code flushes its source packer before publishing repairs.
        if self.sender.status().fec_count == 0 {
            self.flush(Kind::Source, now)
                .or_else(|error| self.fail(error))?;
        }
        Ok(id)
    }
    /// Advance one actual encoder turn and transfer at most one complete record.
    /// GF work is reported; bounded framing copies are separate packet serialization.
    pub fn step<C: super::CoefficientSource + ?Sized>(
        &mut self,
        now: Tick,
        budget: WorkBudget,
        random: &mut C,
    ) -> Result<WorkUsed, Error> {
        self.healthy()?;
        self.sender
            .check_batch_time(now)
            .or_else(|error| self.fail(error))?;
        self.timer(Kind::Source, now)?;
        if budget.metadata != 0 && self.sender.fec_timer().is_some_and(|due| now >= due) {
            self.flush(Kind::Source, now)?;
        }
        let used = self
            .sender
            .step(now, budget, random)
            .or_else(|error| self.fail(error))?;
        self.reserve_repairs(now)
            .or_else(|error| self.fail(error))?;
        let Some(output) = self.sender.pending_output() else {
            return Ok(used);
        };
        let length = output.encoded_len();
        if matches!(output, Output::Repair(_)) {
            let Some(position) = self.sender.pending_position() else {
                return Ok(used);
            };
            if position.length != length {
                return self.fail(Error::Identity);
            }
            let mut packet = self.packets[position.slot].ok_or(Error::Identity)?;
            let index = position.slot * self.packing.items() + position.index;
            if self.tokens[index].is_some() {
                return self.fail(Error::Identity);
            }
            let start = position.slot * self.packing.max_packet_bytes + position.offset + 2;
            let (token, written) = self
                .sender
                .detach_pending(now, &mut self.bytes[start..start + length])
                .or_else(|error| self.fail(error))?;
            if written != position.length {
                return self.fail(Error::Identity);
            }
            self.tokens[index] = Some(token);
            packet.filled += 1;
            packet.prepared = packet.prepared.max(token.prepared);
            self.packets[position.slot] = Some(packet);
            self.activate_ready();
            return Ok(used);
        }
        let analytical = match output {
            Output::Source {
                original, attempt, ..
            } if attempt > 1 => original.len(),
            _ => return self.fail(Error::Identity),
        };
        let kind = Kind::Retry;
        let (event, cap) = self.sender.pending_event().ok_or(Error::Identity)?;
        let slot = match self.place(kind, analytical, event) {
            Ok(slot) => slot,
            Err(Error::Capacity) => return Ok(used),
            Err(error) => return self.fail(error),
        };
        let packet = self.entry(slot, kind, event, cap)?;
        if add(packet.length, add(2, length)?)? > self.packing.max_packet_bytes {
            return self.fail(Error::Length);
        }
        let start = slot * self.packing.max_packet_bytes + packet.length + 2;
        let (token, written) = self
            .sender
            .detach_pending(now, &mut self.bytes[start..start + length])
            .or_else(|error| self.fail(error))?;
        self.appended(
            slot,
            packet,
            Some(token),
            Append {
                length: written,
                analytical,
                event,
                now,
            },
        )
        .or_else(|error| self.fail(error))?;
        Ok(used)
    }
    fn next_ready(&self) -> Option<(usize, Packet)> {
        self.packets
            .iter()
            .enumerate()
            .filter_map(|(slot, packet)| {
                packet
                    .filter(|packet| packet.ready.is_some() && packet.id.is_some())
                    .map(|packet| (slot, packet))
            })
            .min_by_key(|(_, packet)| (packet.ready, packet.id.map(|id| id.serial)))
            .filter(|(_, packet)| packet.filled == packet.count)
    }
    fn activate_ready(&mut self) {
        if self.active.is_none() {
            self.active = self.next_ready().map(|(slot, _)| slot);
        }
    }
    fn selected(&self) -> Option<(usize, Packet)> {
        let slot = self.active?;
        Some((slot, self.packets[slot]?))
    }
    /// Borrow the oldest complete immutable packet without consuming custody.
    pub fn pending_output(&self) -> Option<PacketOutput<'_>> {
        if self.terminal.is_some() {
            return None;
        }
        let (slot, packet) = self.selected()?;
        let start = slot * self.packing.max_packet_bytes;
        Some(PacketOutput {
            id: packet.id?,
            kind: packet.kind,
            records: packet.count,
            bytes: &self.bytes[start..start + packet.length],
            deadline: packet.expires,
        })
    }
    /// Apply one actual whole-write receipt to all represented records exactly once.
    /// The physical fact remains observable even if original timing validation fails.
    pub fn confirm_output(
        &mut self,
        id: Id,
        accepted: Tick,
        observed: Tick,
        rtt: u64,
    ) -> Result<(), Error> {
        self.healthy()?;
        let (slot, packet) = self.selected().ok_or(Error::Busy)?;
        if packet.id != Some(id) {
            return Err(Error::Identity);
        }
        self.receipt = Some(Receipt {
            id,
            records: packet.count,
            bytes: packet.length,
            accepted,
            observed,
            failure: None,
        });
        let mut failure = if accepted > observed
            || accepted < packet.prepared
            || packet.ready.is_none_or(|ready| accepted < ready)
        {
            Some(Error::TimeRegression)
        } else {
            self.sender.physical_observation_failure(observed)
        };
        for index in 0..packet.count {
            let at = slot * self.packing.items() + index;
            let result = self.tokens[at].ok_or(Error::Identity).and_then(|token| {
                self.sender
                    .consume_detached_fact(token, accepted, observed, rtt)
            });
            if let Err(error) = result {
                failure = failure.or(Some(error));
            }
            self.tokens[at] = None;
        }
        if let Err(error) = self.sender.finish_batch_observation(observed, failure) {
            failure = failure.or(Some(error));
        }
        if let Some(error) = failure {
            if let Some(receipt) = &mut self.receipt {
                receipt.failure = Some(error);
            }
            return self.fail(error);
        }
        self.packets[slot] = None;
        self.active = None;
        self.activate_ready();
        Ok(())
    }
    /// Forward authenticated recovery feedback to the same causal legacy owner.
    pub fn receive_feedback<C: super::CoefficientSource + ?Sized>(
        &mut self,
        feedback: Feedback<'_>,
        now: Tick,
        random: &mut C,
    ) -> Result<FeedbackDisposition, Error> {
        self.receive_feedback_at(feedback, now, now, random)
    }
    /// Retry held feedback with its original authenticated arrival after custody becomes visible.
    pub fn receive_feedback_at<C: super::CoefficientSource + ?Sized>(
        &mut self,
        feedback: Feedback<'_>,
        arrived: Tick,
        observed: Tick,
        random: &mut C,
    ) -> Result<FeedbackDisposition, Error> {
        self.healthy()?;
        self.sender
            .receive_feedback_at(feedback, arrived, observed, random)
    }
    /// Actual recovery/admission facts; packing is separately observed by output.
    pub fn status(&self) -> SenderStatus {
        self.sender.status()
    }
    /// Original terminal failure, including wrapper-only physical timing errors.
    pub fn terminal(&self) -> Option<Error> {
        self.terminal.or(self.sender.status().terminal)
    }
    /// Last reported whole physical completion, including terminal late facts.
    pub fn last_receipt(&self) -> Option<Receipt> {
        self.receipt
    }
    /// Original hard cap; packing and physical waits never renew it.
    pub fn deadline(&self) -> Option<Tick> {
        self.sender
            .deadline()
            .into_iter()
            .chain(self.packets.iter().flatten().map(|packet| packet.expires))
            .min()
    }
    /// Original FEC/packing/retry wake opportunities, distinct from hard expiry.
    pub fn next_wakeup(&self) -> Option<Tick> {
        self.sender
            .next_wakeup()
            .into_iter()
            .chain(
                [self.source, self.repair]
                    .into_iter()
                    .flatten()
                    .filter_map(|slot| self.packets[slot].map(|packet| packet.due)),
            )
            .min()
    }
    /// No recovery debt, packer items or actual physical packet custody remains.
    pub fn is_drained(&self) -> bool {
        self.terminal.is_none()
            && self.sender.is_drained()
            && self.packets.iter().all(Option::is_none)
    }
}

#[cfg(test)]
#[path = "batch_tests.rs"]
mod tests;
