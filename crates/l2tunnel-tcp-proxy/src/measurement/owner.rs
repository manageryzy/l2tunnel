use super::wire::{self, Body, Demand, Direction, Header, Record};
use crate::{Scope, session};
use std::{fmt, mem::size_of, sync::Arc};

/// Caller-injected monotonic microseconds; this module reads no system clock.
pub use crate::adaptive::Micros;

/// Finite record ownership policy, separate from future observation/controller policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OwnerConfig {
    /// Original lifetime of unadmitted Demand/reply records, in 1 ms..=120 s.
    pub pending_ttl_micros: u64,
    /// Minimum spacing between explicit probe creations, in 1 ms..=120 s.
    pub probe_interval_micros: u64,
    /// Probe deadline from creation, including queueing, in 1 ms..=120 s.
    pub probe_timeout_micros: u64,
    /// Terminal full-write deadline from admission, in 1 ms..=120 s.
    pub handoff_timeout_micros: u64,
    /// Local emission interval, in 1 ms..=120 s; idle intervals do not accumulate.
    pub emission_interval_micros: u64,
    /// Shared-MUX admissions permitted per interval, in 1..=256.
    pub max_records_per_interval: u16,
}
impl OwnerConfig {
    /// Validate against the actual table's immutable geometry, before allocation.
    pub fn validate(self, table: &session::Table) -> Result<MemoryBound, Error> {
        table
            .policy()
            .validate()
            .map_err(|_| Error::Configuration)?;
        if [
            self.pending_ttl_micros,
            self.probe_interval_micros,
            self.probe_timeout_micros,
            self.handoff_timeout_micros,
            self.emission_interval_micros,
        ]
        .into_iter()
        .any(|n| !(1_000..=120_000_000).contains(&n))
            || !(1..=256).contains(&self.max_records_per_interval)
        {
            return Err(Error::Configuration);
        }
        let n = table.policy().max_flows;
        let slots = n
            .checked_mul(2)
            .and_then(|n| n.checked_add(1))
            .ok_or(Error::Exhausted)?;
        let proofs = n.checked_mul(3).ok_or(Error::Exhausted)?;
        let buffers = slots
            .checked_mul(2)
            .and_then(|s| s.checked_add(proofs))
            .ok_or(Error::Exhausted)?;
        let buffer_bytes = buffers
            .checked_mul(wire::MAX_RECORD_BYTES)
            .ok_or(Error::Exhausted)?;
        let inline_and_boxed = size_of::<Owner>()
            .checked_add(
                slots
                    .checked_mul(size_of::<Slot>())
                    .ok_or(Error::Exhausted)?,
            )
            .and_then(|s| s.checked_add(n.checked_mul(size_of::<Proofs>())?))
            .ok_or(Error::Exhausted)?;
        Ok(MemoryBound {
            output_slots: slots,
            incoming_proofs: proofs,
            buffer_bytes,
            metadata_bytes: inline_and_boxed
                .checked_sub(buffer_bytes)
                .ok_or(Error::Accounting)?,
            common_copy_bytes: n
                .checked_mul(256)
                .and_then(|s| s.checked_add(104))
                .ok_or(Error::Exhausted)?,
        })
    }
}

/// Fixed retained storage; allocator/control-block overhead and runtime buffers are separate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MemoryBound {
    /// Each slot has one unadmitted and one admitted fixed record buffer.
    pub output_slots: usize,
    /// At most three immutable incoming duplicate proofs per lifetime flow.
    pub incoming_proofs: usize,
    /// All fixed 104-byte record buffers, including currently empty slots.
    pub buffer_bytes: usize,
    /// Inline and boxed state bytes other than record buffers, using `size_of`.
    pub metadata_bytes: usize,
    /// Additional common-MUX/writer copies including 48-byte outer framing.
    /// This must fit existing shared caps; it grants no extra queue capacity.
    pub common_copy_bytes: usize,
}
/// Recoverable errors leave state unchanged. Handoff expiry latches terminal failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// Invalid finite policy or actual table geometry.
    Configuration,
    /// Wrong actual table or output-token owner, even when logical scopes match.
    Owner,
    /// Unknown, Opening or otherwise ineligible flow.
    Flow,
    /// Wrong session, epoch or negotiated original-stream direction.
    Scope,
    /// Same retained serial has different canonical bytes.
    Conflict,
    /// Counter regression, impossible native demand or grant beyond actual authority.
    Counters,
    /// Reused/nonmonotonic incoming request nonce.
    Nonce,
    /// Original probe or spacing token remains reserved.
    ProbeBusy,
    /// Owner has quiesced and cannot stage new work.
    Quiesced,
    /// Output generation, slot or pending/admitted transition is stale.
    Output,
    /// The exact unadmitted generation expired before handoff.
    OutputExpired,
    /// The local emission interval has no remaining admission credit.
    EmissionLimited,
    /// A full-write deadline expired; caller must terminate the session.
    HandoffExpired,
    /// Time moved backward, precedes actual table time or exceeds maintained bounds.
    Time,
    /// Checked serial, nonce or arithmetic exhausted; no wrap/reset is allowed.
    Exhausted,
    /// Authoritative retained table output or internal geometry disagrees.
    Accounting,
    /// Canonical measurement record parser rejected the input.
    Decode(wire::DecodeError),
    /// Canonical encoding rejected a preflight value.
    Encode(wire::EncodeError),
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "proxy measurement owner: {self:?}")
    }
}
impl std::error::Error for Error {}

/// Pure authenticated-ingress disposition, with no grant or measurement authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Ingress {
    /// New record stored; an EchoRequest may stage one bounded reply.
    Accepted,
    /// Exact latest canonical serial/bytes; no refresh or new response.
    Duplicate,
    /// Older, terminal, quiesced or unmatched reply; no new response/freshness.
    Stale,
}
/// Private owner/slot/generation identity; copying a token does not copy authority.
#[derive(Clone, Debug)]
pub struct OutputId {
    owner: Arc<()>,
    slot: usize,
    generation: u64,
}
impl PartialEq for OutputId {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.owner, &other.owner)
            && self.slot == other.slot
            && self.generation == other.generation
    }
}
impl Eq for OutputId {}
/// Borrowed immutable candidate. Peek alone does not admit or start a probe clock.
pub struct Pending<'a> {
    /// Use this exact token after synchronous shared-MUX admission/full write.
    pub id: OutputId,
    /// Existing lifetime flow whose common channel and QoS weight must be used.
    pub flow: u64,
    /// Exact canonical bytes; no native payload is copied into this owner.
    pub bytes: &'a [u8],
}
/// Ownership counters only; these are not delivery-rate, RTT or growth evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OwnerStatus {
    /// Last successful operation's injected time.
    pub at: Micros,
    /// Coalescible records not yet admitted to the shared MUX.
    pub pending: usize,
    /// Immutable records awaiting full write/flush confirmation.
    pub admitted: usize,
    /// Latest incoming duplicate proofs retained across terminal flows.
    pub incoming_proofs: usize,
    /// One original probe token remains live, without any public RTT result.
    pub probe_live: bool,
    /// No new work may be staged; admitted work still owns its bytes.
    pub quiescing: bool,
    /// Sticky terminal full-write expiry; immutable admitted proofs remain retained.
    pub handoff_expired: bool,
    /// Unused local emission tokens in the last serviced interval.
    pub emission_remaining: u16,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Buffer {
    bytes: [u8; wire::MAX_RECORD_BYTES],
    len: usize,
}
impl Buffer {
    fn encode(record: Record) -> Result<Self, Error> {
        let mut value = Self {
            bytes: [0; wire::MAX_RECORD_BYTES],
            len: 0,
        };
        value.len = wire::encode(record, &mut value.bytes).map_err(Error::Encode)?;
        Ok(value)
    }
    fn slice(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
    fn record(&self) -> Result<Record, Error> {
        wire::decode(self.slice()).map_err(Error::Decode)
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
struct Output {
    buffer: Buffer,
    flow: u64,
    generation: u64,
    deadline: Micros,
}
#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct Slot {
    pending: Option<Output>,
    admitted: Option<Output>,
}
type Proofs = [Option<Buffer>; 3];
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Probe {
    flow: u64,
    nonce: u64,
    generation: u64,
    deadline: Micros,
    admitted_at: Option<Micros>,
    written: bool,
    reply_at: Option<Micros>,
}
/// Private single-operation evidence; only the exclusive measured composition
/// can consume this, and standalone B callers discard it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct Completion {
    pub flow: u64,
    pub generation: u64,
    pub admitted_at: Micros,
    pub reply_at: Micros,
}
#[derive(Clone, Debug, Eq, PartialEq)]
struct State {
    slots: Box<[Slot]>,
    proofs: Box<[Proofs]>,
    last: Micros,
    serial: u64,
    nonce: u64,
    peer_nonce: u64,
    cursor: usize,
    emission_reset: Micros,
    emitted: u16,
    next_probe: Option<Micros>,
    probe: Option<Probe>,
    quiescing: bool,
    handoff_expired: bool,
}
/// Exclusive actual-table record owner with fixed capacities and injected time.
/// It authenticates nothing, drives no TCP/socket, and exports no adaptive samples.
pub struct Owner {
    config: OwnerConfig,
    policy: session::Config,
    table: Arc<()>,
    identity: Arc<()>,
    state: State,
}
impl Owner {
    /// Bind one actual validated table, even if some lifetime entries are terminal.
    pub fn new(config: OwnerConfig, table: &session::Table, now: Micros) -> Result<Self, Error> {
        let bound = config.validate(table)?;
        let mut value = Self {
            config,
            policy: table.policy(),
            table: table.target_identity().clone(),
            identity: Arc::new(()),
            state: State {
                slots: vec![Slot::default(); bound.output_slots].into_boxed_slice(),
                proofs: vec![[None, None, None]; table.policy().max_flows].into_boxed_slice(),
                last: now,
                serial: 0,
                nonce: 0,
                peer_nonce: 0,
                cursor: 0,
                emission_reset: plus(now, config.emission_interval_micros)?,
                emitted: 0,
                next_probe: None,
                probe: None,
                quiescing: false,
                handoff_expired: false,
            },
        };
        value.check(Some(table), now)?;
        Ok(value)
    }
    /// Stage actual active table demand. No caller-supplied counters are accepted.
    /// Replacing an unadmitted generation consumes a new serial and original TTL.
    pub fn stage_demand(
        &mut self,
        table: &session::Table,
        flow: u64,
        now: Micros,
    ) -> Result<(), Error> {
        self.check(Some(table), now)?;
        self.allow_stage()?;
        let index = self.active(table, flow)?;
        let relay = table.relay_status(flow).ok_or(Error::Flow)?;
        let pending_data_bytes = if let Some(bytes) = table.pending_record(flow) {
            let record = crate::decode(
                crate::Config {
                    scope: self.scope(flow),
                    max_record_bytes: self.policy.max_record_bytes,
                    maximum: self.policy.maximum,
                    initial: self.policy.initial,
                },
                bytes,
            )
            .map_err(|_| Error::Accounting)?;
            if record.kind == 2 {
                record.payload.len() as u64
            } else {
                0
            }
        } else {
            0
        };
        let unread = relay.native.receive_bytes as u64;
        let demand = Demand {
            produced: relay.produced,
            observed_grant: relay.peer_granted,
            native_unread_bytes: unread,
            pending_data_bytes,
            byte_blocked: unread != 0 && relay.produced.bytes == relay.peer_granted.bytes,
            record_blocked: unread != 0 && relay.produced.records == relay.peer_granted.records,
        };
        let output = self.output(
            flow,
            self.outgoing(),
            Body::Demand(demand),
            now,
            self.config.pending_ttl_micros,
        )?;
        self.maintain(Some(table), now);
        self.state.serial = output.generation;
        self.state.slots[index].pending = Some(output);
        Ok(())
    }
    /// Explicitly reserve one probe for the incoming original stream. No RTT is returned.
    pub fn stage_probe(
        &mut self,
        table: &session::Table,
        flow: u64,
        now: Micros,
    ) -> Result<(), Error> {
        self.check(Some(table), now)?;
        self.allow_stage()?;
        self.active(table, flow)?;
        let slot = self.request_slot();
        if self.state.slots[slot].admitted.is_some()
            || self
                .state
                .probe
                .is_some_and(|p| self.probe_current(p, Some(table), now))
            || self.state.next_probe.is_some_and(|at| now < at)
        {
            return Err(Error::ProbeBusy);
        }
        let nonce = self.state.nonce.checked_add(1).ok_or(Error::Exhausted)?;
        let deadline = plus(now, self.config.probe_timeout_micros)?;
        let next_probe = plus(now, self.config.probe_interval_micros)?;
        let output = self.output(
            flow,
            self.incoming(),
            Body::EchoRequest { nonce },
            now,
            self.config
                .pending_ttl_micros
                .min(self.config.probe_timeout_micros),
        )?;
        let probe = Probe {
            flow,
            nonce,
            generation: output.generation,
            deadline,
            admitted_at: None,
            written: false,
            reply_at: None,
        };
        self.maintain(Some(table), now);
        self.state.serial = output.generation;
        self.state.nonce = nonce;
        self.state.next_probe = Some(next_probe);
        self.state.probe = Some(probe);
        self.state.slots[slot].pending = Some(output);
        Ok(())
    }
    /// Admit only a complete ordered record already authenticated by a trusted runtime.
    /// Caller must verify retained session/configuration and outer record type;
    /// device EtherType/magic alone can never authorize this method. Pure scope
    /// checks below do not establish cryptographic evidence or shared-MUX admission.
    pub fn receive_authenticated(
        &mut self,
        table: &session::Table,
        bytes: &[u8],
        now: Micros,
    ) -> Result<Ingress, Error> {
        self.receive_measured(table, bytes, now)
            .map(|(ingress, _)| ingress)
    }
    pub(super) fn receive_measured(
        &mut self,
        table: &session::Table,
        bytes: &[u8],
        now: Micros,
    ) -> Result<(Ingress, Option<Completion>), Error> {
        let record = wire::decode(bytes).map_err(Error::Decode)?;
        self.check(Some(table), now)?;
        let (flow, kind) = (record.header.scope.flow, kind(record.body));
        let direction = if kind == 1 {
            self.outgoing()
        } else {
            self.incoming()
        };
        if record.header.scope != self.scope(flow) || record.header.direction != direction {
            return Err(Error::Scope);
        }
        let index = self.index(table, flow)?;
        if let Some(old) = &self.state.proofs[index][kind] {
            let serial = old.record()?.header.serial;
            if record.header.serial == serial {
                if old.slice() != bytes {
                    return Err(Error::Conflict);
                }
                self.maintain(Some(table), now);
                return Ok((Ingress::Duplicate, None));
            }
            if record.header.serial < serial {
                self.maintain(Some(table), now);
                return Ok((Ingress::Stale, None));
            }
        }
        let phase = table.flow_status(flow).ok_or(Error::Flow)?.phase;
        if matches!(
            phase,
            session::FlowPhase::Stopped(_) | session::FlowPhase::Retired
        ) {
            self.maintain(Some(table), now);
            return Ok((Ingress::Stale, None));
        }
        if phase != session::FlowPhase::Active {
            return Err(Error::Flow);
        }
        if self.state.quiescing {
            self.maintain(Some(table), now);
            return Ok((Ingress::Stale, None));
        }
        let mut reply = None;
        match record.body {
            Body::Demand(demand) => {
                let granted = table.credit_status(flow).ok_or(Error::Accounting)?.granted;
                if !granted.contains(demand.observed_grant)
                    || demand.native_unread_bytes > self.policy.native.receive_bytes as u64
                    || demand.pending_data_bytes > self.policy.max_record_bytes as u64
                    || demand.pending_data_bytes > demand.produced.bytes
                {
                    return Err(Error::Counters);
                }
                if let Some(old) = &self.state.proofs[index][kind]
                    && let Body::Demand(previous) = old.record()?.body
                    && (!demand.produced.contains(previous.produced)
                        || !demand.observed_grant.contains(previous.observed_grant))
                {
                    return Err(Error::Counters);
                }
            }
            Body::EchoRequest { nonce } => {
                if nonce <= self.state.peer_nonce {
                    return Err(Error::Nonce);
                }
                reply = Some(self.output(
                    flow,
                    self.outgoing(),
                    Body::EchoReply { nonce },
                    now,
                    self.config.pending_ttl_micros,
                )?);
            }
            Body::EchoReply { nonce } => {
                let matching = self.state.probe.is_some_and(|p| {
                    p.flow == flow
                        && p.nonce == nonce
                        && self.probe_current(p, Some(table), now)
                        && p.admitted_at.is_some_and(|at| now > at)
                        && p.reply_at.is_none()
                });
                if !matching {
                    self.maintain(Some(table), now);
                    return Ok((Ingress::Stale, None));
                }
            }
        }
        let proof = Buffer::encode(record)?;
        self.maintain(Some(table), now);
        self.state.proofs[index][kind] = Some(proof);
        match record.body {
            Body::EchoRequest { nonce } => {
                self.state.peer_nonce = nonce;
                if let Some(output) = reply {
                    self.state.serial = output.generation;
                    self.state.slots[self.policy.max_flows + index].pending = Some(output);
                }
            }
            Body::EchoReply { .. } => {
                if let Some(probe) = &mut self.state.probe {
                    probe.reply_at = Some(now);
                }
            }
            Body::Demand(_) => {}
        }
        Ok((Ingress::Accepted, self.finish_probe()))
    }
    /// Borrow a round-robin eligible candidate without debiting emission or MUX credit.
    /// Copy into the existing common flow/channel budget and confirm synchronously,
    /// with no await or table/owner mutation between the successful copy and callback.
    pub fn pending(
        &mut self,
        table: &session::Table,
        now: Micros,
    ) -> Result<Option<Pending<'_>>, Error> {
        self.check(Some(table), now)?;
        self.maintain(Some(table), now);
        if self.state.emitted == self.config.max_records_per_interval {
            return Ok(None);
        }
        for offset in 0..self.state.slots.len() {
            let slot = (self.state.cursor + offset) % self.state.slots.len();
            let value = &self.state.slots[slot];
            if value.admitted.is_none()
                && let Some(output) = &value.pending
            {
                return Ok(Some(Pending {
                    id: OutputId {
                        owner: self.identity.clone(),
                        slot,
                        generation: output.generation,
                    },
                    flow: output.flow,
                    bytes: output.buffer.slice(),
                }));
            }
        }
        Ok(None)
    }
    /// Confirm exact shared-MUX admission, not a scheduling peek or native write.
    /// Callback must follow the successful copy in the same single-owner section.
    pub fn confirm_admission(&mut self, id: OutputId, now: Micros) -> Result<(), Error> {
        self.token(&id)?;
        self.check(None, now)?;
        let slot = &self.state.slots[id.slot];
        let output = slot
            .pending
            .as_ref()
            .filter(|p| p.generation == id.generation)
            .ok_or(Error::Output)?;
        if slot.admitted.is_some() {
            return Err(Error::Output);
        }
        if now >= output.deadline {
            return Err(Error::OutputExpired);
        }
        if now < self.state.emission_reset
            && self.state.emitted == self.config.max_records_per_interval
        {
            return Err(Error::EmissionLimited);
        }
        let deadline = plus(now, self.config.handoff_timeout_micros)?;
        if id.slot == self.request_slot()
            && !self
                .state
                .probe
                .is_some_and(|p| p.generation == id.generation && now < p.deadline)
        {
            return Err(Error::OutputExpired);
        }
        let mut admitted = output.clone();
        admitted.deadline = deadline;
        self.maintain(None, now);
        self.state.slots[id.slot].pending = None;
        self.state.slots[id.slot].admitted = Some(admitted);
        self.state.emitted += 1;
        self.state.cursor = (id.slot + 1) % self.state.slots.len();
        if id.slot == self.request_slot()
            && let Some(probe) = &mut self.state.probe
        {
            probe.admitted_at = Some(now);
        }
        Ok(())
    }
    /// Release only after the entire retained framed write and flush completed.
    /// Unknown partial writes must terminate the session; no cancellation API exists.
    pub fn confirm_written(&mut self, id: OutputId, now: Micros) -> Result<(), Error> {
        self.written(None, id, now).map(|_| ())
    }
    pub(super) fn confirm_written_measured(
        &mut self,
        table: &session::Table,
        id: OutputId,
        now: Micros,
    ) -> Result<Option<Completion>, Error> {
        self.written(Some(table), id, now)
    }
    fn written(
        &mut self,
        table: Option<&session::Table>,
        id: OutputId,
        now: Micros,
    ) -> Result<Option<Completion>, Error> {
        self.token(&id)?;
        self.check(table, now)?;
        if self.state.slots[id.slot]
            .admitted
            .as_ref()
            .is_none_or(|p| p.generation != id.generation)
        {
            return Err(Error::Output);
        }
        self.maintain(table, now);
        self.state.slots[id.slot].admitted = None;
        if let Some(probe) = &mut self.state.probe
            && probe.generation == id.generation
        {
            probe.written = true;
        }
        Ok(self.finish_probe())
    }
    /// Process bounded expiry and terminal-flow retirement without polling the table.
    pub fn tick(&mut self, table: &session::Table, now: Micros) -> Result<(), Error> {
        self.check(Some(table), now)?;
        self.maintain(Some(table), now);
        Ok(())
    }
    /// Earliest owned expiry/handoff/emission wake; no periodic automatic probes exist.
    pub fn next_deadline(&self) -> Option<Micros> {
        if self.state.handoff_expired {
            return None;
        }
        let outputs = self
            .state
            .slots
            .iter()
            .flat_map(|s| [s.pending.as_ref(), s.admitted.as_ref()])
            .flatten()
            .map(|o| o.deadline);
        let emission = (self.state.emitted == self.config.max_records_per_interval
            && self
                .state
                .slots
                .iter()
                .any(|s| s.pending.is_some() && s.admitted.is_none()))
        .then_some(self.state.emission_reset);
        outputs
            .chain(self.state.probe.map(|p| p.deadline))
            .chain(emission)
            .min()
    }
    /// Stop new work and drop only unadmitted records; retained proofs still own writes.
    /// Runtime shutdown retains its own earliest original deadline, which always wins.
    pub fn quiesce(&mut self, now: Micros) -> Result<(), Error> {
        self.check(None, now)?;
        self.maintain(None, now);
        self.state.quiescing = true;
        self.state.probe = None;
        for slot in &mut self.state.slots {
            slot.pending = None;
        }
        Ok(())
    }
    /// True only after quiesce and every immutable admitted record's full write.
    pub fn drained(&self) -> bool {
        self.state.quiescing && self.state.slots.iter().all(|s| s.admitted.is_none())
    }
    /// Inspect finite ownership counts, never derived measurement/ACK authority.
    pub fn status(&self) -> OwnerStatus {
        OwnerStatus {
            at: self.state.last,
            pending: self
                .state
                .slots
                .iter()
                .filter(|s| s.pending.is_some())
                .count(),
            admitted: self
                .state
                .slots
                .iter()
                .filter(|s| s.admitted.is_some())
                .count(),
            incoming_proofs: self
                .state
                .proofs
                .iter()
                .flatten()
                .filter(|p| p.is_some())
                .count(),
            probe_live: self.state.probe.is_some(),
            quiescing: self.state.quiescing,
            handoff_expired: self.state.handoff_expired,
            emission_remaining: self.config.max_records_per_interval - self.state.emitted,
        }
    }
    pub(super) fn handoff_expired_at(&self, now: Micros) -> bool {
        self.state.handoff_expired
            || self
                .state
                .slots
                .iter()
                .any(|s| s.admitted.as_ref().is_some_and(|p| now >= p.deadline))
    }
    pub(super) fn check(
        &mut self,
        table: Option<&session::Table>,
        now: Micros,
    ) -> Result<(), Error> {
        if let Some(table) = table
            && !Arc::ptr_eq(&self.table, table.target_identity())
        {
            return Err(Error::Owner);
        }
        if self.state.handoff_expired {
            return Err(Error::HandoffExpired);
        }
        session::check_time(crate::Millis(now.0 / 1000)).map_err(|_| Error::Time)?;
        if now < self.state.last {
            return Err(Error::Time);
        }
        if let Some(table) = table
            && now.0
                < table
                    .target_time()
                    .0
                    .checked_mul(1000)
                    .ok_or(Error::Exhausted)?
        {
            return Err(Error::Time);
        }
        if self
            .state
            .slots
            .iter()
            .any(|s| s.admitted.as_ref().is_some_and(|p| now >= p.deadline))
        {
            self.state.handoff_expired = true;
            return Err(Error::HandoffExpired);
        }
        plus(now, self.config.emission_interval_micros)?;
        Ok(())
    }
    fn maintain(&mut self, table: Option<&session::Table>, now: Micros) {
        let current = self
            .state
            .probe
            .is_some_and(|p| self.probe_current(p, table, now));
        if !current {
            self.state.probe = None;
        }
        for slot in &mut self.state.slots {
            if slot
                .pending
                .as_ref()
                .is_some_and(|p| now >= p.deadline || table.is_some_and(|t| !active(t, p.flow)))
            {
                slot.pending = None;
            }
        }
        if !current {
            let slot = self.request_slot();
            self.state.slots[slot].pending = None;
        }
        if now >= self.state.emission_reset {
            // check() preflighted this addition before any state mutation.
            self.state.emission_reset = Micros(now.0 + self.config.emission_interval_micros);
            self.state.emitted = 0;
        }
        self.state.last = now;
    }
    fn probe_current(&self, probe: Probe, table: Option<&session::Table>, now: Micros) -> bool {
        now < probe.deadline
            && table.is_none_or(|t| active(t, probe.flow))
            && !self.state.quiescing
            && (probe.admitted_at.is_some()
                || self.state.slots[self.request_slot()]
                    .pending
                    .as_ref()
                    .is_some_and(|p| p.generation == probe.generation && now < p.deadline))
    }
    fn finish_probe(&mut self) -> Option<Completion> {
        let probe = self.state.probe?;
        if !probe.written {
            return None;
        }
        let event = Completion {
            flow: probe.flow,
            generation: probe.generation,
            admitted_at: probe.admitted_at?,
            reply_at: probe.reply_at?,
        };
        self.state.probe = None;
        Some(event)
    }
    fn token(&self, id: &OutputId) -> Result<(), Error> {
        if !Arc::ptr_eq(&self.identity, &id.owner) {
            return Err(Error::Owner);
        }
        if id.slot >= self.state.slots.len() {
            return Err(Error::Output);
        }
        Ok(())
    }
    fn output(
        &self,
        flow: u64,
        direction: Direction,
        body: Body,
        now: Micros,
        ttl: u64,
    ) -> Result<Output, Error> {
        let generation = self.state.serial.checked_add(1).ok_or(Error::Exhausted)?;
        Ok(Output {
            buffer: Buffer::encode(Record {
                header: Header {
                    scope: self.scope(flow),
                    direction,
                    serial: generation,
                },
                body,
            })?,
            flow,
            generation,
            deadline: plus(now, ttl)?,
        })
    }
    fn scope(&self, flow: u64) -> Scope {
        Scope {
            session: self.policy.session,
            epoch: self.policy.epoch,
            flow,
        }
    }
    fn outgoing(&self) -> Direction {
        match self.policy.role {
            session::Role::Originator => Direction::OriginatorToAcceptor,
            session::Role::Acceptor => Direction::AcceptorToOriginator,
        }
    }
    fn incoming(&self) -> Direction {
        match self.outgoing() {
            Direction::OriginatorToAcceptor => Direction::AcceptorToOriginator,
            Direction::AcceptorToOriginator => Direction::OriginatorToAcceptor,
        }
    }
    fn index(&self, table: &session::Table, flow: u64) -> Result<usize, Error> {
        let index = flow
            .checked_sub(1)
            .and_then(|n| usize::try_from(n).ok())
            .ok_or(Error::Flow)?;
        if index >= self.state.proofs.len() || table.flow_status(flow).is_none() {
            return Err(Error::Flow);
        }
        Ok(index)
    }
    fn active(&self, table: &session::Table, flow: u64) -> Result<usize, Error> {
        let index = self.index(table, flow)?;
        if !active(table, flow) {
            return Err(Error::Flow);
        }
        Ok(index)
    }
    fn allow_stage(&self) -> Result<(), Error> {
        if self.state.quiescing {
            Err(Error::Quiesced)
        } else {
            Ok(())
        }
    }
    fn request_slot(&self) -> usize {
        self.policy.max_flows * 2
    }
}
fn active(table: &session::Table, flow: u64) -> bool {
    table
        .flow_status(flow)
        .is_some_and(|s| s.phase == session::FlowPhase::Active)
}
fn plus(now: Micros, duration: u64) -> Result<Micros, Error> {
    now.0
        .checked_add(duration)
        .map(Micros)
        .ok_or(Error::Exhausted)
}
fn kind(body: Body) -> usize {
    match body {
        Body::Demand(_) => 0,
        Body::EchoRequest { .. } => 1,
        Body::EchoReply { .. } => 2,
    }
}

#[cfg(test)]
mod tests;
