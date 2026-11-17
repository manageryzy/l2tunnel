//! Native-byte admission and actual device delivery, independent of recovery ACKs.
use super::*;
use crate::flow_control::{delivery_window as window, target::Micros};
use std::mem::size_of;

/// Exact original native completion retained until the existing reliable control
/// owner accepts it. Copying this value does not establish peer authentication.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativeDelivery {
    identity: receiver::RecordIdentity,
    bytes: usize,
    deadline: Tick,
}
impl NativeDelivery {
    /// Actual codec identity committed after a whole native device write.
    pub const fn identity(self) -> receiver::RecordIdentity {
        self.identity
    }
    /// Original native byte count, never a recovery-source length.
    pub const fn bytes(self) -> usize {
        self.bytes
    }
    /// Original native handoff cap, never renewed by control backpressure.
    pub const fn deadline(self) -> Tick {
        self.deadline
    }
}

#[derive(Clone, Copy)]
struct Original {
    identity: receiver::RecordIdentity,
    ordinal: u64,
    admitted: Tick,
    parts: Option<usize>,
    sent: usize,
    latest: Tick,
}
#[derive(Clone, Copy)]
pub(super) struct Plan {
    send: Option<window::Config>,
    receive: bool,
    channels: usize,
    parts: usize,
    witnesses: usize,
    heap: usize,
}
fn limits(profile: configuration::DirectionProfile<'_>) -> Result<receiver::Limits, Error> {
    use configuration::DirectionProfile as P;
    match profile {
        P::Aligned(c) => Ok(c.receiver),
        P::AlignedCompact(c) => Ok(c.receiver),
        P::Packed(c) => Ok(c.base.receiver),
        P::PackedCompact(c) => Ok(c.base.receiver),
        P::Rolling { config, .. } => Ok(config.receiver),
        P::Research { config, .. } => Ok(config.receiver),
        // These owners require their own native-to-source witness composition.
        P::Swift(_) | P::PerConnectionCompact(_) => {
            Err(Error::Unsupported(Capability::NativeWindow))
        }
    }
}
pub(super) fn validate(view: configuration::DirectionView<'_>) -> Result<(), Error> {
    if let configuration::NativeWindow::Delivery(policy) = view.common().native_window() {
        policy.validate().map_err(Error::NativeWindow)?;
        let bounds = limits(view.profile())?;
        if policy.max_packet_bytes < bounds.body.max_frame_bytes as u64 {
            return Err(Error::Configuration);
        }
    }
    Ok(())
}
impl Plan {
    pub(super) fn new(
        c: &configuration::Configuration,
        role: Role,
        witnesses: usize,
    ) -> Result<Option<Self>, Error> {
        let local = c.descriptor().local(role);
        let send = match local.send().common().native_window() {
            configuration::NativeWindow::Disabled => None,
            configuration::NativeWindow::Delivery(policy) => Some(policy),
        };
        let receive = matches!(
            local.receive().common().native_window(),
            configuration::NativeWindow::Delivery(_)
        );
        if send.is_none() && !receive {
            return Ok(None);
        }
        validate(local.send())?;
        validate(local.receive())?;
        let channels = usize::from(local.send().channels());
        let parts = if send.is_some() {
            limits(local.send().profile())?.max_fragments_per_record
        } else {
            0
        };
        let mut heap = 0usize;
        if let Some(policy) = send {
            let bitmap = parts
                .div_ceil(64)
                .checked_mul(size_of::<u64>())
                .ok_or(Error::Arithmetic)?;
            heap = policy
                .metadata_bytes()
                .map_err(Error::NativeWindow)?
                .checked_add(
                    policy
                        .max_records
                        .checked_mul(size_of::<Option<Original>>() + bitmap)
                        .ok_or(Error::Arithmetic)?,
                )
                .and_then(|n| n.checked_add(channels * size_of::<Option<u64>>()))
                .and_then(|n| n.checked_add(witnesses * size_of::<receiver::UnitWitness>()))
                .ok_or(Error::Arithmetic)?;
            if heap > policy.metadata_limit_bytes {
                return Err(Error::NativeWindow(window::Error::Configuration));
            }
        }
        Ok(Some(Self {
            send,
            receive,
            channels,
            parts,
            witnesses,
            heap,
        }))
    }
    pub(super) const fn heap_bytes(self) -> usize {
        self.heap
    }
}
struct Sender {
    controller: window::Controller,
    entries: Vec<Option<Original>>,
    bits: Vec<u64>,
    retired: Vec<Option<u64>>,
    pending: Vec<receiver::UnitWitness>,
    pending_len: usize,
    words: usize,
    parts: usize,
    retired_ordinal: u64,
}
pub(super) struct State {
    sender: Option<Sender>,
    receive: bool,
    delivery: Option<NativeDelivery>,
    heap: usize,
}
fn reserved<T: Clone>(len: usize, value: T) -> Result<Vec<T>, Error> {
    let mut out = Vec::new();
    out.try_reserve_exact(len)
        .map_err(|_| Error::NativeWindow(window::Error::Memory))?;
    if out.capacity() != len {
        return Err(Error::Invariant);
    }
    out.resize(len, value);
    Ok(out)
}
fn identity(value: ProfileIdentity) -> Result<receiver::RecordIdentity, Error> {
    match value {
        ProfileIdentity::Aligned(id)
        | ProfileIdentity::Packed(id)
        | ProfileIdentity::Rolling(id)
        | ProfileIdentity::Research(id) => Ok(id),
        _ => Err(Error::Unsupported(Capability::NativeWindow)),
    }
}
impl State {
    pub(super) fn new(plan: Plan) -> Result<Self, Error> {
        let sender = plan
            .send
            .map(|policy| -> Result<_, Error> {
                let words = plan.parts.div_ceil(64);
                Ok(Sender {
                    controller: window::Controller::new(policy, Micros(0))
                        .map_err(Error::NativeWindow)?,
                    entries: reserved(policy.max_records, None)?,
                    bits: reserved(
                        policy
                            .max_records
                            .checked_mul(words)
                            .ok_or(Error::Arithmetic)?,
                        0,
                    )?,
                    retired: reserved(plan.channels, None)?,
                    pending: reserved(
                        plan.witnesses,
                        receiver::UnitWitness {
                            identity: receiver::RecordIdentity {
                                channel: receiver::ChannelId(0),
                                record: receiver::RecordId(0),
                            },
                            index: 0,
                            count: 1,
                        },
                    )?,
                    pending_len: 0,
                    words,
                    parts: plan.parts,
                    retired_ordinal: 0,
                })
            })
            .transpose()?;
        Ok(Self {
            sender,
            receive: plan.receive,
            delivery: None,
            heap: plan.heap,
        })
    }
    pub(super) fn usage(&self) -> (usize, usize) {
        (self.heap, if self.sender.is_some() { 5 } else { 0 })
    }
    pub(super) fn preview(&mut self, now: Tick, bytes: usize) -> Result<bool, Error> {
        let Some(sender) = &mut self.sender else {
            return Ok(true);
        };
        match sender.controller.preview_admit(bytes as u64, Micros(now.0)) {
            Ok(()) => Ok(true),
            Err(window::Error::Blocked) => Ok(false),
            Err(error) => Err(Error::NativeWindow(error)),
        }
    }
    pub(super) fn admitted(
        &mut self,
        now: Tick,
        id: ProfileIdentity,
        bytes: usize,
    ) -> Result<(), Error> {
        let Some(sender) = &mut self.sender else {
            return Ok(());
        };
        let id = identity(id)?;
        if usize::from(id.channel.0) >= sender.retired.len() {
            return Err(Error::Invariant);
        }
        let end = sender
            .controller
            .admit(bytes as u64, Micros(now.0))
            .map_err(Error::NativeWindow)?;
        let index = ((end.records - 1) % sender.entries.len() as u64) as usize;
        if sender.entries[index].is_some() {
            return Err(Error::Invariant);
        }
        sender.entries[index] = Some(Original {
            identity: id,
            ordinal: end.records,
            admitted: now,
            parts: None,
            sent: 0,
            latest: now,
        });
        sender.bits[index * sender.words..(index + 1) * sender.words].fill(0);
        Ok(())
    }
    pub(super) fn capture(&mut self, units: &[receiver::UnitWitness]) -> Result<(), Error> {
        let Some(sender) = &mut self.sender else {
            return Ok(());
        };
        if sender.pending_len != 0 || units.len() > sender.pending.len() {
            return Err(Error::Invariant);
        }
        for unit in units {
            if unit.count == 0 || unit.count > sender.parts || unit.index >= unit.count {
                return Err(Error::Invariant);
            }
        }
        sender.pending[..units.len()].copy_from_slice(units);
        sender.pending_len = units.len();
        Ok(())
    }
    pub(super) fn confirm(&mut self, now: Tick, actual: Tick) -> Result<(), Error> {
        let Some(sender) = &mut self.sender else {
            return Ok(());
        };
        let n = std::mem::take(&mut sender.pending_len);
        if actual > now {
            return Err(Error::Time);
        }
        for i in 0..n {
            let unit = sender.pending[i];
            // Context bodies and already retired native duplicates grant no debt.
            let Some(index) = sender
                .entries
                .iter()
                .position(|entry| entry.is_some_and(|e| e.identity == unit.identity))
            else {
                continue;
            };
            let mut entry = sender.entries[index].ok_or(Error::Invariant)?;
            if actual < entry.admitted || entry.parts.is_some_and(|parts| parts != unit.count) {
                return Err(Error::Invariant);
            }
            entry.parts = Some(unit.count);
            let bit = index * sender.words + unit.index / 64;
            let mask = 1 << (unit.index % 64);
            if sender.bits[bit] & mask != 0 {
                continue;
            }
            entry.sent = entry.sent.checked_add(1).ok_or(Error::Arithmetic)?;
            entry.latest = entry.latest.max(actual);
            sender.bits[bit] |= mask;
            sender.entries[index] = Some(entry);
            if entry.sent == unit.count {
                sender
                    .controller
                    .confirm_record_flushed_at(entry.ordinal, Micros(entry.latest.0), Micros(now.0))
                    .map_err(Error::NativeWindow)?;
            }
        }
        sender.retire(now)
    }
    pub(super) fn tick(&mut self, now: Tick) -> Result<(), Error> {
        if self.delivery.is_some_and(|d| now >= d.deadline) {
            return Err(Error::Expired);
        }
        if let Some(sender) = &mut self.sender {
            sender
                .controller
                .tick(Micros(now.0))
                .map_err(Error::NativeWindow)?;
        }
        Ok(())
    }
    pub(super) fn deadline(&self, now: Tick) -> Result<Option<Tick>, Error> {
        Ok(self
            .status(now)?
            .and_then(|s| s.next_flush_deadline)
            .map(|d| Tick(d.0))
            .into_iter()
            .chain(self.delivery.map(|d| d.deadline))
            .min())
    }
    pub(super) fn status(&self, now: Tick) -> Result<Option<window::Status>, Error> {
        self.sender
            .as_ref()
            .map(|s| {
                s.controller
                    .status(Micros(now.0))
                    .map_err(Error::NativeWindow)
            })
            .transpose()
    }
    pub(super) fn drained(&self, now: Tick) -> Result<bool, Error> {
        Ok(self.delivery.is_none() && self.status(now)?.is_none_or(|s| s.retained_records == 0))
    }
    pub(super) fn committed(&mut self, pending: PreparedNative) -> Result<(), Error> {
        if !self.receive {
            return Ok(());
        }
        if self.delivery.is_some() {
            return Err(Error::Invariant);
        }
        self.delivery = Some(NativeDelivery {
            identity: identity(pending.identity())?,
            bytes: pending.bytes(),
            deadline: pending.deadline(),
        });
        Ok(())
    }
    fn delivered(
        &mut self,
        received: Tick,
        now: Tick,
        id: receiver::RecordIdentity,
    ) -> Result<(), Error> {
        let sender = self
            .sender
            .as_mut()
            .ok_or(Error::Unsupported(Capability::NativeWindow))?;
        let prior = sender
            .retired
            .get(usize::from(id.channel.0))
            .ok_or(Error::Configuration)?;
        if prior.is_some_and(|end| id.record.0 <= end) {
            return Ok(());
        }
        let ordinal = sender
            .entries
            .iter()
            .flatten()
            .find(|e| e.identity == id)
            .map(|e| e.ordinal)
            .ok_or(Error::NativeWindow(window::Error::Feedback))?;
        sender
            .controller
            .delivered_record_at(ordinal, Micros(received.0), Micros(now.0))
            .map_err(Error::NativeWindow)?;
        sender.retire(now)
    }
}
impl Sender {
    fn retire(&mut self, now: Tick) -> Result<(), Error> {
        let status = self
            .controller
            .status(Micros(now.0))
            .map_err(Error::NativeWindow)?;
        let prefix = status
            .admitted
            .records
            .checked_sub(status.retained_records as u64)
            .ok_or(Error::Invariant)?;
        while self.retired_ordinal < prefix {
            let next = self
                .retired_ordinal
                .checked_add(1)
                .ok_or(Error::Arithmetic)?;
            let index = ((next - 1) % self.entries.len() as u64) as usize;
            let entry = self.entries[index]
                .take()
                .filter(|e| e.ordinal == next)
                .ok_or(Error::Invariant)?;
            self.retired[usize::from(entry.identity.channel.0)] = Some(entry.identity.record.0);
            self.retired_ordinal = next;
        }
        Ok(())
    }
}
impl Engine {
    /// Actual cumulative native debt and physical flush facts for this generation.
    pub fn native_window_status(&self, now: Tick) -> Result<Option<window::Status>, Error> {
        self.native_window
            .as_ref()
            .map(|state| state.status(now))
            .transpose()
            .map(Option::flatten)
    }
    /// One actual whole-device completion awaiting reliable control admission.
    pub fn pending_native_delivery(&self) -> Option<NativeDelivery> {
        self.native_window.as_ref().and_then(|state| state.delivery)
    }
    /// Consume only the exact receipt after the existing control owner accepts it.
    pub fn native_delivery_queued(&mut self, delivery: NativeDelivery) -> Result<(), Error> {
        let state = self.native_window.as_mut().ok_or(Error::Token)?;
        if state.delivery != Some(delivery) {
            return Err(Error::Token);
        }
        state.delivery = None;
        Ok(())
    }
    /// Apply caller-authenticated exact native device identity, never an ARQ ACK.
    /// Scope, direction and strong authentication remain the caller's obligation.
    pub fn accept_native_delivery(
        &mut self,
        received: Tick,
        now: Tick,
        id: receiver::RecordIdentity,
    ) -> Result<(), Error> {
        self.advance(now)?;
        if received > now {
            return Err(Error::Time);
        }
        self.native_window
            .as_mut()
            .ok_or(Error::Unsupported(Capability::NativeWindow))?
            .delivered(received, now, id)
    }
}

#[cfg(test)]
#[path = "native_window_tests.rs"]
mod tests;
