//! Finite lifetime TCP ownership, reservation and retained native/carrier handoff.
//!
//! Callers provide authenticated ordered records, route authorization, common
//! QoS/MUX scheduling and actual native I/O. This module never opens a device.
pub use super::TimeWaitResetPolicy;
use super::admission::{self, InitialSyn, Inspection, Opening, Phase};
use super::{Leg, Millis, Scope, TcpIpConfig, TcpStatus, Window};
use l2tunnel_raw_tcp::CloseReason;
use smoltcp::wire::{IpAddress, IpProtocol, Ipv4Packet, Ipv6Packet, TcpOption, TcpPacket};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::net::{IpAddr, SocketAddr};

/// Only the negotiated originator creates local proxy flows in this first profile.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Role {
    /// Intercept explicitly authorized initial SYNs; assign monotonic flow IDs.
    Originator,
    /// Reserve authorized peer Opens; all other native connections stay transparent.
    Acceptor,
}

/// Immutable finite policy; bind every field and complementary roles during auth.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Config {
    /// Nonzero authenticated session identity.
    pub session: [u8; 16],
    /// Nonzero immutable profile epoch; this table has no reload operation.
    pub epoch: u64,
    /// Local negotiated origination role.
    pub role: Role,
    /// Lifetime owner entries, including rejected/closed flows, in 1..=64.
    pub max_flows: usize,
    /// Shared tuple/address-pair policy entries, in max_flows..=4096.
    pub max_policies: usize,
    /// Native dimensions/timers/seed; local and peer addresses are replaced per flow.
    pub native: TcpIpConfig,
    /// Largest original application bytes per relay Data record.
    pub max_record_bytes: usize,
    /// Maximum retained original bytes/record boundaries per flow.
    pub maximum: Window,
    /// Initial buffer-backed target per flow.
    pub initial: Window,
    /// Fixed admission timeout in 1..=120000 ms.
    pub admission_timeout_ms: u64,
    /// Explicit native close policy, negotiated with the complete session config.
    pub time_wait_reset_policy: TimeWaitResetPolicy,
}
impl Config {
    /// Validate before creating any maintained TCP owner or payload allocation.
    pub fn validate(self) -> Result<(), Error> {
        if !(1..=64).contains(&self.max_flows)
            || !(self.max_flows..=4096).contains(&self.max_policies)
            || !(1..=120_000).contains(&self.admission_timeout_ms)
            || self.native.mtu < 1280
            || self.max_record_bytes > self.native.send_bytes
        {
            return Err(Error::Config);
        }
        self.native.validate().map_err(|_| Error::Config)?;
        self.relay(1).validate().map_err(|_| Error::Config)?;
        // Bound aggregate configured payload capacity, independent of activation.
        let per_flow = self
            .native
            .send_bytes
            .checked_add(self.native.receive_bytes)
            .and_then(|n| n.checked_add(self.maximum.bytes as usize))
            .and_then(|n| n.checked_add(self.max_record_bytes + super::HEADER))
            .and_then(|n| {
                self.native
                    .packet_slots
                    .checked_mul(2)
                    .and_then(|slots| slots.checked_add(1))
                    .and_then(|slots| slots.checked_mul(self.native.mtu))
                    .and_then(|bytes| n.checked_add(bytes))
            })
            .ok_or(Error::Config)?;
        if per_flow
            .checked_mul(self.max_flows)
            .is_none_or(|bytes| bytes > 268_435_456)
        {
            return Err(Error::Config);
        }
        Ok(())
    }
    fn scope(self, id: u64) -> Scope {
        Scope {
            session: self.session,
            epoch: self.epoch,
            flow: id,
        }
    }
    fn relay(self, id: u64) -> super::Config {
        super::Config {
            scope: self.scope(id),
            max_record_bytes: self.max_record_bytes,
            maximum: self.maximum,
            initial: self.initial,
        }
    }
    fn native_for(self, syn: &InitialSyn) -> TcpIpConfig {
        let (local, peer) = if self.role == Role::Originator {
            (syn.destination(), syn.source())
        } else {
            (syn.source(), syn.destination())
        };
        TcpIpConfig {
            local,
            peer,
            ..self.native
        }
    }
}

/// Explicit parser/configuration/session failure; no silent ownership fallback.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// Invalid or excessive aggregate dimensions.
    Config,
    /// Invalid complete native packet or canonical tunnel record.
    Malformed,
    /// Native packet checksum failed before ownership mutation.
    Checksum,
    /// Wrong authenticated scope, unknown/out-of-order ID or forbidden origination.
    Scope,
    /// Ambiguous/transparent packet collides with existing proxy ownership.
    Conflict,
    /// Unknown flow, wrong phase or absent retained output.
    State,
    /// Injected time regressed or exhausted maintained timer arithmetic.
    Time,
    /// Invalid bounded poll work allowance.
    Work,
    /// Existing admission primitive rejected a record.
    Admission(admission::Error),
    /// Existing relay rejected a record or native packet.
    Relay(super::Error),
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "TCP proxy session: {self:?}")
    }
}
impl std::error::Error for Error {}
impl From<admission::Error> for Error {
    fn from(value: admission::Error) -> Self {
        Self::Admission(value)
    }
}
impl From<super::Error> for Error {
    fn from(value: super::Error) -> Self {
        Self::Relay(value)
    }
}

/// Ownership of the original complete native packet after inspection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Disposition {
    /// Caller forwards unchanged via the common transparent QoS/MUX path.
    Transparent,
    /// Existing/new owner consumed or deliberately discarded this packet.
    Owned(u64),
    /// Bounded maintained ingress is full; caller retains and retries this packet.
    Backpressure(u64),
}

/// Canonical authenticated terminal reason, never a successful stream completion.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum StopReason {
    /// Remote authorization or existing ownership policy refused reservation.
    Rejected = 1,
    /// Caller explicitly cancelled the flow.
    Cancelled = 2,
    /// Maintained reset, timeout or relay accounting failure.
    NativeFailure = 3,
    /// An owned flow changed to an unsupported packet/option policy.
    UnsupportedPacket = 4,
    /// Fixed admission deadline elapsed.
    AdmissionExpired = 5,
}
impl StopReason {
    fn decode(value: u8) -> Result<Self, Error> {
        match value {
            1 => Ok(Self::Rejected),
            2 => Ok(Self::Cancelled),
            3 => Ok(Self::NativeFailure),
            4 => Ok(Self::UnsupportedPacket),
            5 => Ok(Self::AdmissionExpired),
            _ => Err(Error::Malformed),
        }
    }
}

/// Public lifecycle; terminal tombstones live until the authenticated session ends.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FlowPhase {
    /// Existing bounded Open/Ready/Commit transaction.
    Opening(Phase),
    /// Owns the maintained native TCP leg.
    Active,
    /// Abnormal terminal state; reset/output may still need draining.
    Stopped(StopReason),
    /// Explicitly proved clean ownership drain and released native resources.
    Retired,
}
/// Current per-flow ownership, suitable for attribution by the shared scheduler.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FlowStatus {
    /// Monotonic nonreused session flow ID.
    pub id: u64,
    /// Original untrusted SYN DSCP, interpreted by configured shared QoS policy.
    pub dscp: u8,
    /// Current lifecycle.
    pub phase: FlowPhase,
    /// Actual maintained queues if a native owner still exists.
    pub native: Option<TcpStatus>,
    /// Exact native packet retained until full device write confirmation.
    pub pending_native_bytes: usize,
    /// Exact record retained until reliable carrier ownership confirmation.
    pub pending_record_bytes: usize,
}
/// Authoritative relay credit at the current active or last terminal boundary.
/// Terminal values are captured before abort/drop, never from a reset send queue.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CreditSnapshot {
    /// Original native TCP acknowledged prefix.
    pub acknowledged: Window,
    /// Original reliable relay received prefix.
    pub received: Window,
    /// Cumulative capacity already promised, including retained unsent Credit.
    pub granted: Window,
    /// Future target at this boundary; already issued capacity is irrevocable.
    pub target: Window,
}
impl From<super::Status> for CreditSnapshot {
    fn from(value: super::Status) -> Self {
        Self {
            acknowledged: value.acknowledged,
            received: value.received,
            granted: value.granted,
            target: value.target,
        }
    }
}
/// Finite lifetime counters, with no claimed delivery or throughput semantics.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Status {
    /// Lifetime flow IDs allocated, including refusals and tombstones.
    pub flows: usize,
    /// Retained tuple/address-pair decisions.
    pub policies: usize,
    /// New native interceptions stay transparent until a new session.
    pub admission_locked: bool,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct Tuple(SocketAddr, SocketAddr);
impl Tuple {
    fn new(a: SocketAddr, b: SocketAddr) -> Self {
        if a <= b { Self(a, b) } else { Self(b, a) }
    }
    fn pair(self) -> Pair {
        Pair::new(self.0.ip(), self.1.ip())
    }
}
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct Pair(IpAddr, IpAddr);
impl Pair {
    fn new(a: IpAddr, b: IpAddr) -> Self {
        if a <= b { Self(a, b) } else { Self(b, a) }
    }
}
enum Owner {
    Opening(Box<Opening>),
    Active(Box<Leg>),
    Stopped {
        reason: StopReason,
        leg: Option<Box<Leg>>,
        output: Option<Vec<u8>>,
        polled: bool,
    },
    Retired,
}
struct Entry {
    tuple: Tuple,
    incoming_source: SocketAddr,
    syn_sequence: u32,
    dscp: u8,
    peer_knows: bool,
    owner: Owner,
    native: Option<Vec<u8>>,
    final_credit: Option<CreditSnapshot>,
}
impl Entry {
    fn pending(&self) -> Option<&[u8]> {
        match &self.owner {
            Owner::Opening(value) => value.pending_record(),
            Owner::Active(value) => value.pending_record(),
            Owner::Stopped { output, .. } => output.as_deref(),
            Owner::Retired => None,
        }
    }
    fn native_status(&self) -> Option<TcpStatus> {
        match &self.owner {
            Owner::Opening(value) => value.native_status(),
            Owner::Active(value) => Some(value.status().native),
            Owner::Stopped { leg, .. } => leg.as_ref().map(|leg| leg.status().native),
            Owner::Retired => None,
        }
    }
}

/// One finite session's retained flow owners; no idle eviction or implicit auth.
pub struct Table {
    config: Config,
    entries: Vec<Entry>,
    tuples: BTreeMap<Tuple, Option<u64>>,
    pairs: BTreeSet<Pair>,
    locked: bool,
    cursor: usize,
    last: Millis,
    target_identity: std::sync::Arc<()>,
}
impl Table {
    /// Validate all aggregate dimensions without creating TCP endpoints.
    pub fn new(config: Config, now: Millis) -> Result<Self, Error> {
        config.validate()?;
        check_time(now)?;
        Ok(Self {
            config,
            entries: Vec::new(),
            tuples: BTreeMap::new(),
            pairs: BTreeSet::new(),
            locked: false,
            cursor: 0,
            last: now,
            target_identity: std::sync::Arc::new(()),
        })
    }
    /// Actual immutable configuration validated when this table was constructed.
    pub const fn policy(&self) -> Config {
        self.config
    }
    pub(crate) fn target_identity(&self) -> &std::sync::Arc<()> {
        &self.target_identity
    }
    pub(crate) const fn target_time(&self) -> Millis {
        self.last
    }
    /// Retain a new decision or feed an existing owner; authorization is caller-owned.
    pub fn ingest_native(
        &mut self,
        bytes: &[u8],
        permit_new: bool,
        now: Millis,
    ) -> Result<Disposition, Error> {
        self.time(now)?;
        let packet = inspect_packet(bytes, self.config.native.mtu)?;
        let Packet::Tcp {
            tuple,
            source,
            supported,
        } = packet
        else {
            self.observe_packet(packet)?;
            return Ok(Disposition::Transparent);
        };
        if let Some(Some(id)) = self.tuples.get(&tuple).copied() {
            let index = self.index(id)?;
            if self.entries[index].incoming_source != source {
                return Err(Error::Conflict);
            }
            if !supported {
                self.stop(index, StopReason::UnsupportedPacket, true);
                return Ok(Disposition::Owned(id));
            }
            match &mut self.entries[index].owner {
                Owner::Opening(_) => {
                    if let Inspection::Candidate(syn) =
                        admission::inspect_syn(bytes, self.config.native.mtu)?
                        && syn.sequence() == self.entries[index].syn_sequence
                    {
                        return Ok(Disposition::Owned(id));
                    }
                    self.stop(index, StopReason::Cancelled, true);
                }
                Owner::Active(leg) => match leg.ingest_packet(bytes) {
                    Ok(()) => {}
                    Err(super::Error::Tcp(l2tunnel_raw_tcp::Error::QueueFull)) => {
                        return Ok(Disposition::Backpressure(id));
                    }
                    Err(error) => return Err(error.into()),
                },
                Owner::Stopped { .. } | Owner::Retired => {}
            }
            return Ok(Disposition::Owned(id));
        }
        let eligible = self.config.role == Role::Originator
            && permit_new
            && !self.locked
            && self.entries.len() < self.config.max_flows
            && self.has_policy_room()
            && !self.tuples.contains_key(&tuple)
            && !self.pairs.contains(&tuple.pair());
        if eligible
            && let Inspection::Candidate(syn) =
                admission::inspect_syn(bytes, self.config.native.mtu)?
        {
            let id = self.entries.len() as u64 + 1;
            let mut opening = Opening::local(
                self.config.relay(id),
                self.config.native_for(&syn),
                syn.clone(),
                now,
                self.config.admission_timeout_ms,
            )?;
            opening.set_time_wait_reset_policy(self.config.time_wait_reset_policy)?;
            self.add(syn, opening, false);
            return Ok(Disposition::Owned(id));
        }
        self.pin_tuple(tuple);
        Ok(Disposition::Transparent)
    }
    /// Pin a peer-transparent decision before its original packet is written to TUN.
    /// An owned/ambiguous collision is fatal; never write that packet transparently.
    pub fn observe_transparent(&mut self, bytes: &[u8], now: Millis) -> Result<(), Error> {
        self.time(now)?;
        self.observe_packet(inspect_packet(bytes, self.config.native.mtu)?)
    }
    fn observe_packet(&mut self, packet: Packet) -> Result<(), Error> {
        match packet {
            Packet::Tcp { tuple, .. } => {
                if self.tuples.get(&tuple).is_some_and(Option::is_some) {
                    return Err(Error::Conflict);
                }
                self.pin_tuple(tuple);
            }
            Packet::Ambiguous(pair) => {
                if self.entries.iter().any(|entry| entry.tuple.pair() == pair) {
                    return Err(Error::Conflict);
                }
                if !self.pairs.contains(&pair) {
                    if self.has_policy_room() {
                        self.pairs.insert(pair);
                    } else {
                        self.locked = true;
                    }
                }
            }
            Packet::Other => {}
        }
        Ok(())
    }
    fn pin_tuple(&mut self, tuple: Tuple) {
        if !self.tuples.contains_key(&tuple) {
            if self.has_policy_room() {
                self.tuples.insert(tuple, None);
            } else {
                self.locked = true;
            }
        }
    }
    fn has_policy_room(&self) -> bool {
        self.tuples.len() + self.pairs.len() < self.config.max_policies
    }
    fn add(&mut self, syn: InitialSyn, opening: Opening, peer_knows: bool) {
        let id = self.entries.len() as u64 + 1;
        let tuple = Tuple::new(syn.source(), syn.destination());
        self.tuples.insert(tuple, Some(id));
        self.entries.push(Entry {
            tuple,
            incoming_source: self.config.native_for(&syn).peer,
            syn_sequence: syn.sequence(),
            dscp: syn.dscp(),
            peer_knows,
            owner: Owner::Opening(Box::new(opening)),
            native: None,
            final_credit: None,
        });
    }
    /// Accept one previously authenticated, framed, reliable and ordered record.
    /// `permit_open` is required only for a new Open and comes from route policy.
    pub fn receive_authenticated(
        &mut self,
        bytes: &[u8],
        permit_open: bool,
        now: Millis,
    ) -> Result<(), Error> {
        self.time(now)?;
        let (magic, kind, id) = header(self.config, bytes)?;
        if magic == *b"LTPA" && kind == 1 {
            return self.open(bytes, id, permit_open, now);
        }
        let index = self.index(id)?;
        if !self.entries[index].peer_knows {
            return Err(Error::State);
        }
        let scope = self.config.scope(id);
        if magic == *b"LTPA" {
            admission::decode(scope, bytes)?;
        } else if magic == *b"LTPR" {
            super::decode(self.config.relay(id), bytes)?;
        } else if magic != *b"LTPX" || bytes.len() != 40 {
            return Err(Error::Malformed);
        }
        if magic == *b"LTPX" {
            let reason = StopReason::decode(kind)?;
            if reason == StopReason::Rejected
                && !matches!(
                    self.entries[index].owner,
                    Owner::Opening(_) | Owner::Stopped { .. } | Owner::Retired
                )
            {
                return Err(Error::State);
            }
            self.stop(index, reason, false);
            return Ok(());
        }
        match &mut self.entries[index].owner {
            Owner::Opening(opening) if magic == *b"LTPA" => {
                match opening.receive_authenticated(bytes, now) {
                    Ok(()) => {}
                    Err(admission::Error::Expired) => {
                        self.stop(index, StopReason::AdmissionExpired, true);
                        return Ok(());
                    }
                    Err(error) => return Err(error.into()),
                }
                self.activate(index, now)?;
            }
            Owner::Active(leg) if magic == *b"LTPR" => leg.receive_authenticated(bytes)?,
            Owner::Stopped { .. } | Owner::Retired => {}
            _ => return Err(Error::State),
        }
        Ok(())
    }
    fn open(&mut self, bytes: &[u8], id: u64, permit: bool, now: Millis) -> Result<(), Error> {
        if self.config.role != Role::Acceptor
            || id != self.entries.len() as u64 + 1
            || self.entries.len() >= self.config.max_flows
        {
            return Err(Error::Scope);
        }
        let (_, syn_bytes) = admission::decode(self.config.scope(id), bytes)?;
        let syn = match admission::inspect_syn(syn_bytes, self.config.native.mtu)? {
            Inspection::Candidate(value) => value,
            _ => return Err(Error::Malformed),
        };
        let tuple = Tuple::new(syn.source(), syn.destination());
        let refused = !permit
            || self.locked
            || !self.has_policy_room()
            || self.tuples.contains_key(&tuple)
            || self.pairs.contains(&tuple.pair());
        if refused {
            // A refusal must not overwrite the existing transparent or owned tuple.
            let mut output = stop_record(self.config.scope(id), StopReason::Rejected);
            output.shrink_to_fit();
            self.entries.push(Entry {
                tuple,
                incoming_source: syn.destination(),
                syn_sequence: syn.sequence(),
                dscp: syn.dscp(),
                peer_knows: true,
                owner: Owner::Stopped {
                    reason: StopReason::Rejected,
                    leg: None,
                    output: Some(output),
                    polled: false,
                },
                native: None,
                final_credit: None,
            });
            return Ok(());
        }
        let mut opening = Opening::remote(
            self.config.relay(id),
            self.config.native_for(&syn),
            bytes,
            now,
            self.config.admission_timeout_ms,
        )?;
        opening.set_time_wait_reset_policy(self.config.time_wait_reset_policy)?;
        self.add(syn, opening, true);
        Ok(())
    }
    /// Borrow immutable flow output until actual reliable carrier ownership.
    pub fn pending_record(&self, id: u64) -> Option<&[u8]> {
        self.index(id)
            .ok()
            .and_then(|index| self.entries[index].pending())
    }
    /// Confirm exact borrowed bytes after carrier admission, never on scheduler peek.
    pub fn confirm_record_sent(&mut self, id: u64, now: Millis) -> Result<(), Error> {
        self.time(now)?;
        let index = self.index(id)?;
        match &mut self.entries[index].owner {
            Owner::Opening(opening) => {
                if let Err(error) = opening.confirm_record_sent(now) {
                    if error == admission::Error::Expired {
                        self.entries[index].peer_knows = true;
                        self.stop(index, StopReason::AdmissionExpired, true);
                        return Ok(());
                    }
                    return Err(error.into());
                }
                self.entries[index].peer_knows = true;
                self.activate(index, now)?;
            }
            Owner::Active(leg) => leg.confirm_record_sent()?,
            Owner::Stopped { output, .. } if output.is_some() => {
                *output = None;
            }
            _ => return Err(Error::State),
        }
        Ok(())
    }
    fn activate(&mut self, index: usize, now: Millis) -> Result<(), Error> {
        if let Owner::Opening(opening) = &mut self.entries[index].owner
            && opening.phase() == Phase::Active
        {
            let leg = opening.take_leg(now)?;
            self.entries[index].owner = Owner::Active(Box::new(leg));
        }
        Ok(())
    }
    /// Borrow retained native output until a complete actual device write succeeds.
    pub fn pending_native(&self, id: u64) -> Option<&[u8]> {
        self.index(id)
            .ok()
            .and_then(|index| self.entries[index].native.as_deref())
    }
    /// Confirm a complete native write; partial writes must remain retained by caller.
    pub fn confirm_native_written(&mut self, id: u64) -> Result<(), Error> {
        let index = self.index(id)?;
        if self.entries[index].native.take().is_none() {
            return Err(Error::State);
        }
        Ok(())
    }
    /// Visit at most `flow_work` owners, each with at most `stack_work` native steps.
    pub fn poll(&mut self, now: Millis, flow_work: usize, stack_work: usize) -> Result<(), Error> {
        if !(1..=64).contains(&flow_work) || !(1..=1024).contains(&stack_work) {
            return Err(Error::Work);
        }
        self.time(now)?;
        for _ in 0..flow_work.min(self.entries.len()) {
            let index = self.cursor % self.entries.len();
            self.cursor = (index + 1) % self.entries.len();
            let failure = match &mut self.entries[index].owner {
                Owner::Opening(opening) => match opening.tick(now) {
                    Ok(()) => None,
                    Err(admission::Error::Expired) => Some(StopReason::AdmissionExpired),
                    Err(error) => return Err(error.into()),
                },
                Owner::Active(leg) => leg
                    .poll(now, stack_work)
                    .err()
                    .map(|_| StopReason::NativeFailure),
                Owner::Stopped {
                    leg: Some(leg),
                    polled,
                    ..
                } => {
                    let _ = leg.poll(now, stack_work);
                    *polled = true;
                    None
                }
                _ => None,
            };
            if let Some(reason) = failure {
                self.stop(index, reason, true);
            }
            let entry = &mut self.entries[index];
            if entry.native.is_none() {
                entry.native = match &mut entry.owner {
                    Owner::Active(leg) | Owner::Stopped { leg: Some(leg), .. } => leg.pop_packet(),
                    _ => None,
                };
            }
            if let Owner::Stopped { leg, polled, .. } = &mut entry.owner
                && *polled
                && entry.native.is_none()
                && leg.as_ref().is_some_and(|leg| {
                    let status = leg.status().native;
                    status.incoming_packets == 0 && status.outgoing_packets == 0
                })
            {
                *leg = None;
            }
        }
        Ok(())
    }
    /// Cancel an owned/reserved flow; reliable terminal output survives backpressure.
    pub fn cancel(&mut self, id: u64, now: Millis) -> Result<(), Error> {
        self.time(now)?;
        let index = self.index(id)?;
        self.stop(index, StopReason::Cancelled, true);
        Ok(())
    }
    fn stop(&mut self, index: usize, reason: StopReason, notify: bool) {
        if matches!(
            self.entries[index].owner,
            Owner::Stopped { .. } | Owner::Retired
        ) {
            return;
        }
        let owner = std::mem::replace(&mut self.entries[index].owner, Owner::Retired);
        let leg = if let Owner::Active(mut leg) = owner {
            self.entries[index].final_credit = Some(leg.status().into());
            leg.abort();
            Some(leg)
        } else {
            None
        };
        let output = (notify && self.entries[index].peer_knows)
            .then(|| stop_record(self.config.scope(index as u64 + 1), reason));
        self.entries[index].owner = Owner::Stopped {
            reason,
            leg,
            output,
            polled: false,
        };
    }
    /// Release a clean owner only after both stream ends and actual write/ACK drains.
    pub fn retire_clean(&mut self, id: u64) -> Result<(), Error> {
        let index = self.index(id)?;
        let entry = &mut self.entries[index];
        let Owner::Active(leg) = &entry.owner else {
            return Err(Error::State);
        };
        let status = leg.status();
        let native = status.native;
        if entry.native.is_some()
            || status.pending_record_bytes != 0
            || !status.local_fin
            || !status.remote_fin
            || status.received != status.acknowledged
            || status.retained_records != 0
            || native.close_reason != Some(CloseReason::Clean)
            || native.incoming_packets != 0
            || native.outgoing_packets != 0
            || native.send_bytes != 0
            || native.receive_bytes != 0
        {
            return Err(Error::State);
        }
        entry.final_credit = Some(status.into());
        entry.owner = Owner::Retired;
        Ok(())
    }
    /// Adjust existing future grants; the measured target algorithm remains external.
    pub fn set_target(&mut self, id: u64, target: Window) -> Result<(), Error> {
        self.set_targets(&[(id, target)])
    }
    /// Atomically adjust a bounded set of distinct active owners' future targets.
    /// All IDs/targets/failures are checked before any mutation. This does not poll,
    /// create a grant, send a record or alter a native TCP ring/window.
    pub fn set_targets(&mut self, targets: &[(u64, Window)]) -> Result<(), Error> {
        if targets.len() > self.config.max_flows {
            return Err(Error::Config);
        }
        for (position, &(id, target)) in targets.iter().enumerate() {
            if targets[..position].iter().any(|(old, _)| *old == id) {
                return Err(Error::Config);
            }
            let index = self.index(id)?;
            match &self.entries[index].owner {
                Owner::Active(leg) => leg.validate_target(target)?,
                _ => return Err(Error::State),
            }
        }
        // Exclusive access and no intervening callbacks preserve the preflight.
        // The commit is infallible and never calls a state-advancing method.
        for (index, entry) in self.entries.iter_mut().enumerate() {
            if let Owner::Active(leg) = &mut entry.owner
                && let Some((_, target)) = targets.iter().find(|(id, _)| *id == index as u64 + 1)
            {
                leg.target = *target;
            }
        }
        Ok(())
    }
    /// Current or frozen terminal credit, with no payload retained by the snapshot.
    /// Opening/refused-before-activation entries return None; reserve their initial
    /// policy separately. Terminal snapshots persist until this table is dropped.
    pub fn credit_status(&self, id: u64) -> Option<CreditSnapshot> {
        let entry = self.entries.get(self.index(id).ok()?)?;
        match &entry.owner {
            Owner::Active(leg) => Some(leg.status().into()),
            _ => entry.final_credit,
        }
    }
    /// Inspect original-byte accounting of an active relay without advancing it.
    pub fn relay_status(&self, id: u64) -> Option<super::Status> {
        let entry = self.entries.get(self.index(id).ok()?)?;
        match &entry.owner {
            Owner::Active(leg) => Some(leg.status()),
            _ => None,
        }
    }
    /// Snapshot one flow's actual retained boundaries.
    pub fn flow_status(&self, id: u64) -> Option<FlowStatus> {
        let entry = self.entries.get(self.index(id).ok()?)?;
        Some(FlowStatus {
            id,
            dscp: entry.dscp,
            phase: match &entry.owner {
                Owner::Opening(value) => FlowPhase::Opening(value.phase()),
                Owner::Active(_) => FlowPhase::Active,
                Owner::Stopped { reason, .. } => FlowPhase::Stopped(*reason),
                Owner::Retired => FlowPhase::Retired,
            },
            native: entry.native_status(),
            pending_native_bytes: entry.native.as_ref().map_or(0, Vec::len),
            pending_record_bytes: entry.pending().map_or(0, <[u8]>::len),
        })
    }
    /// Finite lifetime counts; no policy entry can disappear within this table.
    pub fn status(&self) -> Status {
        Status {
            flows: self.entries.len(),
            policies: self.tuples.len() + self.pairs.len(),
            admission_locked: self.locked || self.entries.len() == self.config.max_flows,
        }
    }
    fn index(&self, id: u64) -> Result<usize, Error> {
        let index =
            usize::try_from(id.checked_sub(1).ok_or(Error::Scope)?).map_err(|_| Error::Scope)?;
        if index >= self.entries.len() {
            Err(Error::Scope)
        } else {
            Ok(index)
        }
    }
    fn time(&mut self, now: Millis) -> Result<(), Error> {
        if now < self.last {
            return Err(Error::Time);
        }
        check_time(now)?;
        self.last = now;
        Ok(())
    }
}
pub(crate) fn check_time(now: Millis) -> Result<(), Error> {
    if now.0 > (i64::MAX as u64 / 1000).saturating_sub(300_000) {
        Err(Error::Time)
    } else {
        Ok(())
    }
}
fn header(config: Config, bytes: &[u8]) -> Result<([u8; 4], u8, u64), Error> {
    if bytes.len() < 40
        || bytes.len() > config.max_record_bytes.max(100) + 56
        || bytes[4] != 1
        || bytes[6..8] != [0, 0]
    {
        return Err(Error::Malformed);
    }
    if bytes[8..24] != config.session || bytes[24..32] != config.epoch.to_be_bytes() {
        return Err(Error::Scope);
    }
    let magic = bytes[..4].try_into().map_err(|_| Error::Malformed)?;
    let id = u64::from_be_bytes(bytes[32..40].try_into().map_err(|_| Error::Malformed)?);
    if id == 0 || id > config.max_flows as u64 {
        return Err(Error::Scope);
    }
    Ok((magic, bytes[5], id))
}
fn stop_record(scope: Scope, reason: StopReason) -> Vec<u8> {
    let mut bytes = vec![0; 40];
    bytes[..4].copy_from_slice(b"LTPX");
    bytes[4] = 1;
    bytes[5] = reason as u8;
    bytes[8..24].copy_from_slice(&scope.session);
    bytes[24..32].copy_from_slice(&scope.epoch.to_be_bytes());
    bytes[32..40].copy_from_slice(&scope.flow.to_be_bytes());
    bytes
}

#[derive(Clone, Copy)]
enum Packet {
    Tcp {
        tuple: Tuple,
        source: SocketAddr,
        supported: bool,
    },
    Ambiguous(Pair),
    Other,
}
fn inspect_packet(bytes: &[u8], mtu: usize) -> Result<Packet, Error> {
    if bytes.len() > mtu {
        return Err(Error::Malformed);
    }
    let (src, dst, payload, ecn) = match bytes.first().map(|value| value >> 4) {
        Some(4) => {
            let ip = Ipv4Packet::new_checked(bytes).map_err(|_| Error::Malformed)?;
            if usize::from(ip.total_len()) != bytes.len() {
                return Err(Error::Malformed);
            }
            if !ip.verify_checksum() {
                return Err(Error::Checksum);
            }
            let (src, dst) = (IpAddr::V4(ip.src_addr()), IpAddr::V4(ip.dst_addr()));
            if ip.next_header() != IpProtocol::Tcp {
                return Ok(Packet::Other);
            }
            if ip.header_len() != 20 || ip.more_frags() || ip.frag_offset() != 0 {
                return Ok(Packet::Ambiguous(Pair::new(src, dst)));
            }
            (src, dst, &bytes[20..], ip.ecn())
        }
        Some(6) => {
            let ip = Ipv6Packet::new_checked(bytes).map_err(|_| Error::Malformed)?;
            if ip.payload_len() == 0 || usize::from(ip.payload_len()) + 40 != bytes.len() {
                return Err(Error::Malformed);
            }
            let (src, dst) = (IpAddr::V6(ip.src_addr()), IpAddr::V6(ip.dst_addr()));
            if ip.next_header() != IpProtocol::Tcp {
                return if matches!(ip.next_header(), IpProtocol::Udp | IpProtocol::Icmpv6) {
                    Ok(Packet::Other)
                } else {
                    Ok(Packet::Ambiguous(Pair::new(src, dst)))
                };
            }
            (src, dst, &bytes[40..], ip.traffic_class() & 3)
        }
        _ => return Err(Error::Malformed),
    };
    let tcp = TcpPacket::new_checked(payload).map_err(|_| Error::Malformed)?;
    if !tcp.verify_checksum(&IpAddress::from(src), &IpAddress::from(dst)) {
        return Err(Error::Checksum);
    }
    let source = SocketAddr::new(src, tcp.src_port());
    let destination = SocketAddr::new(dst, tcp.dst_port());
    let mut supported = payload[12] & 15 == 0 && payload[13] & 0xe0 == 0 && ecn == 0;
    let mut options = tcp.options();
    let mut seen = 0u8;
    while !options.is_empty() {
        let (rest, option) = TcpOption::parse(options).map_err(|_| Error::Malformed)?;
        let bit = match option {
            TcpOption::EndOfList => {
                supported &= rest.iter().all(|byte| *byte == 0);
                break;
            }
            TcpOption::NoOperation => 0,
            TcpOption::MaxSegmentSize(value) if tcp.syn() && value != 0 => 1,
            TcpOption::WindowScale(value) if tcp.syn() && value <= 14 => 2,
            TcpOption::SackPermitted if tcp.syn() => 4,
            TcpOption::TimeStamp { .. } => 8,
            TcpOption::SackRange(_) if !tcp.syn() => 16,
            _ => {
                supported = false;
                0
            }
        };
        if seen & bit != 0 {
            supported = false;
        }
        seen |= bit;
        options = rest;
    }
    Ok(Packet::Tcp {
        tuple: Tuple::new(source, destination),
        source,
        supported,
    })
}

#[cfg(test)]
mod tests;
