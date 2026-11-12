//! Bounded cumulative logical credit, independent of TCP, clocks and transports.
//!
//! Callers authenticate all peer inputs before applying them. This crate stores
//! record metadata, not payloads; release means the caller actually relinquished
//! the corresponding payload buffer. The [`target`] module adjusts unissued
//! tunnel-credit targets. No congestion controller, QoS scheduler, TCP window
//! manipulation or TAP policy changes are provided.
//!
//! A receiver can replenish ordinary sender credit after releasing its buffer:
//!
//! ```
//! use l2tunnel_flow_control::{
//!     Capacity, Credit, Direction, FlowId, Received, ReceiverCredits, Scope,
//!     SenderCredits,
//! };
//! # fn main() -> Result<(), l2tunnel_flow_control::CreditError> {
//! let scope = Scope { session: 1, epoch: 0, direction: Direction::Forward };
//! let capacity = Capacity {
//!     credit: Credit { bytes: 8, records: 1 },
//!     max_flows: 1,
//! };
//! let flow = FlowId(1);
//! let mut receiver = ReceiverCredits::new(scope, capacity)?;
//! let mut sender = SenderCredits::new(scope, capacity)?;
//! receiver.open_flow(flow)?;
//! sender.open_flow(flow)?;
//! sender.apply_grant(receiver.grant(flow, Credit { bytes: 8, records: 1 })?)?;
//! let record = sender.admit(flow, 8)?;
//! // The caller transfers and authenticates the record and its payload here.
//! assert_eq!(receiver.receive(record)?, Received::New);
//! // After handing the payload to its destination, free the reservation.
//! sender.apply_release(receiver.release_next(flow)?)?;
//! sender.apply_grant(receiver.grant(flow, Credit { bytes: 16, records: 2 })?)?;
//! sender.admit(flow, 8)?;
//! # Ok(())
//! # }
//! ```

use std::collections::BTreeMap;
use std::fmt;
use std::ops::Bound::{Excluded, Unbounded};

/// Injected-time adaptive transparent-TUN credit targets, separate from grants.
pub mod target;
/// Fixed-size credit tokens for an independently authenticated record layer.
pub mod wire;

/// Independent direction of a session's logical credit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Direction {
    /// Initiator-to-responder data.
    Forward,
    /// Responder-to-initiator data.
    Reverse,
}

/// Authenticated session context; counters cannot be transferred between scopes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Scope {
    /// Session identity assigned by the authenticated session layer.
    pub session: u128,
    /// Negotiated configuration generation.
    pub epoch: u64,
    /// Direction whose buffers and grants this ledger accounts for.
    pub direction: Direction,
}

/// Monotonically allocated flow identity within one scope.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct FlowId(pub u64);

/// Zero-based logical record identity within one flow.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct RecordId(pub u64);

/// Cumulative byte/count offsets, or a capacity where explicitly named as such.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Credit {
    /// Logical payload bytes, excluding retransmission and outer wire overhead.
    pub bytes: u64,
    /// Logical record count, including records with zero payload bytes.
    pub records: u64,
}

impl Credit {
    fn fits(self, other: Self) -> bool {
        self.bytes <= other.bytes && self.records <= other.records
    }

    fn max(self, other: Self) -> Self {
        Self {
            bytes: self.bytes.max(other.bytes),
            records: self.records.max(other.records),
        }
    }

    fn add(self, other: Self) -> Result<Self, CreditError> {
        Ok(Self {
            bytes: self
                .bytes
                .checked_add(other.bytes)
                .ok_or(CreditError::Overflow)?,
            records: self
                .records
                .checked_add(other.records)
                .ok_or(CreditError::Overflow)?,
        })
    }

    fn subtract(self, other: Self) -> Result<Self, CreditError> {
        Ok(Self {
            bytes: self
                .bytes
                .checked_sub(other.bytes)
                .ok_or(CreditError::InvalidOffset)?,
            records: self
                .records
                .checked_sub(other.records)
                .ok_or(CreditError::InvalidOffset)?,
        })
    }
}

/// Local retained-buffer limits; no allocation occurs merely by configuring them.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Capacity {
    /// Maximum outstanding logical byte/count reservations or sender retention.
    pub credit: Credit,
    /// Maximum simultaneously open flows, including flows without grants.
    pub max_flows: usize,
}

impl Capacity {
    fn validate(self) -> Result<(), CreditError> {
        if self.max_flows == 0 || self.credit.records == 0 {
            return Err(CreditError::InvalidCapacity);
        }
        Ok(())
    }
}

/// Absolute grant; both flow and session limits remain valid until retirement.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Grant {
    /// Session, epoch and direction binding.
    pub scope: Scope,
    /// Flow receiving this grant.
    pub flow: FlowId,
    /// Maximum cumulative logical bytes and records admitted to this flow.
    pub flow_limit: Credit,
    /// Maximum cumulative logical bytes and records admitted across the scope.
    pub session_limit: Credit,
}

/// Immutable identity/range for one logical record, not its payload authenticator.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Record {
    /// Session, epoch and direction binding.
    pub scope: Scope,
    /// Owning flow.
    pub flow: FlowId,
    /// Zero-based record sequence.
    pub id: RecordId,
    /// Absolute start of the record's logical bytes within its flow.
    pub byte_start: u64,
    /// Logical payload length, possibly zero.
    pub byte_len: u64,
}

impl Record {
    fn end(self) -> Result<Credit, CreditError> {
        Ok(Credit {
            bytes: self
                .byte_start
                .checked_add(self.byte_len)
                .ok_or(CreditError::Overflow)?,
            records: self.id.0.checked_add(1).ok_or(CreditError::Overflow)?,
        })
    }

    fn charge(self) -> Credit {
        Credit {
            bytes: self.byte_len,
            records: 1,
        }
    }
}

/// Receiver's cumulative released prefix; receipt alone is insufficient.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Release {
    /// Session, epoch and direction binding.
    pub scope: Scope,
    /// Owning flow.
    pub flow: FlowId,
    /// Exact end of a contiguous prefix whose payload buffers were released.
    pub consumed: Credit,
}

/// Final sender offset used in a separately authenticated retirement barrier.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FinalOffset {
    /// Session, epoch and direction binding.
    pub scope: Scope,
    /// Flow that can never be reopened in this scope.
    pub flow: FlowId,
    /// Exact cumulative unique bytes and records admitted by the sender.
    pub admitted: Credit,
}

/// Explicit retirement semantics; neither mode performs a network handshake.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RetirementMode {
    /// Require every admitted record to be released before reclaiming grants.
    Drained,
    /// Cancel the flow after an authenticated barrier and discard retained data.
    /// Proxy-ACKed TCP data requires the owning connection to fail/reset first.
    Abandon,
}

/// Whether receiving a logical record created new retained metadata.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Received {
    /// Newly observed record; the caller may retain its authenticated payload.
    New,
    /// Identical retained metadata; do not consume fresh credit or redeliver.
    Duplicate,
    /// Record ID is below the released prefix; never redeliver its payload.
    AlreadyReleased,
}

/// Admission domain whose advertised allowance is temporarily exhausted.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LimitDomain {
    /// This flow's absolute grant.
    Flow,
    /// The aggregate absolute grant.
    Session,
}

/// Explicit non-panicking errors; failure leaves accounting unchanged.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CreditError {
    /// At least one configured metadata capacity is zero.
    InvalidCapacity,
    /// Message belongs to a different session, epoch or direction.
    WrongScope,
    /// Flow is unknown or was retired; no tombstone is recreated.
    UnknownFlow,
    /// New flow IDs must exceed every previously opened flow ID.
    FlowIdNotIncreasing,
    /// Opening a flow would exceed the local metadata bound.
    TooManyFlows,
    /// New grants would exceed receiver byte/count reservations.
    ReceiverPressure,
    /// New logical data reaches an ordinary advertised limit, not congestion.
    SenderExhausted(LimitDomain),
    /// Sender metadata/payload retention would exceed a local bound.
    LocalRetention,
    /// A cumulative counter would overflow; rotate/drain the scope instead.
    Overflow,
    /// Offsets, record ranges, grant hierarchy or final offsets are inconsistent.
    InvalidOffset,
    /// Record lies beyond its advertised flow grant.
    GrantExceeded,
    /// A retry ID is not retained or the next record has not arrived.
    MissingRecord,
    /// Drained retirement was requested before all admitted records were released.
    OutstandingRecords,
}

impl fmt::Display for CreditError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for CreditError {}

#[derive(Debug, Default)]
struct ReceiverFlow {
    limit: Credit,
    released: Credit,
    observed: Credit,
    pending: BTreeMap<RecordId, Record>,
}

/// Receiver ledger reserving capacity for granted data before it arrives.
#[derive(Debug)]
pub struct ReceiverCredits {
    scope: Scope,
    capacity: Capacity,
    reserved: Credit,
    total_granted: Credit,
    last_flow: Option<FlowId>,
    flows: BTreeMap<FlowId, ReceiverFlow>,
}

impl ReceiverCredits {
    /// Create an empty scoped ledger; permits zero byte capacity for empty records.
    pub fn new(scope: Scope, capacity: Capacity) -> Result<Self, CreditError> {
        capacity.validate()?;
        Ok(Self {
            scope,
            capacity,
            reserved: Credit::default(),
            total_granted: Credit::default(),
            last_flow: None,
            flows: BTreeMap::new(),
        })
    }

    /// Open a strictly increasing flow ID without granting any payload capacity.
    pub fn open_flow(&mut self, flow: FlowId) -> Result<(), CreditError> {
        check_new_flow(
            flow,
            self.last_flow,
            self.flows.len(),
            self.capacity.max_flows,
        )?;
        self.flows.insert(flow, ReceiverFlow::default());
        self.last_flow = Some(flow);
        Ok(())
    }

    /// Reserve an absolute grant before advertising it; lower components are ignored.
    /// Grant exhaustion is not a receiver-pressure event: release can permit growth.
    pub fn grant(&mut self, flow: FlowId, limit: Credit) -> Result<Grant, CreditError> {
        let current = self.flows.get(&flow).ok_or(CreditError::UnknownFlow)?.limit;
        let next = current.max(limit);
        let delta = next.subtract(current)?;
        let reserved = self.reserved.add(delta)?;
        if !reserved.fits(self.capacity.credit) {
            return Err(CreditError::ReceiverPressure);
        }
        let total_granted = self.total_granted.add(delta)?;
        self.flows
            .get_mut(&flow)
            .ok_or(CreditError::UnknownFlow)?
            .limit = next;
        self.reserved = reserved;
        self.total_granted = total_granted;
        Ok(Grant {
            scope: self.scope,
            flow,
            flow_limit: next,
            session_limit: total_granted,
        })
    }

    /// Replenish toward an unissued outstanding-window target after buffer release.
    /// Existing grants never shrink. Each over-target byte/count dimension waits
    /// for its promises to drain; the other dimension may still replenish so
    /// unused record grants cannot deadlock a byte-exhausted sender, or vice versa.
    /// Call this on release/control timers independently of data arrival or growth.
    pub fn grant_to_target(
        &mut self,
        flow: FlowId,
        flow_target: Credit,
        session_target: Credit,
    ) -> Result<Grant, CreditError> {
        let state = self.flows.get(&flow).ok_or(CreditError::UnknownFlow)?;
        let current = state.limit;
        let desired = state.released.add(flow_target)?.max(current);
        let delta = desired.subtract(current)?;
        let free_target = Credit {
            bytes: session_target.bytes.saturating_sub(self.reserved.bytes),
            records: session_target.records.saturating_sub(self.reserved.records),
        };
        let free_capacity = self.capacity.credit.subtract(self.reserved)?;
        let increment = Credit {
            bytes: delta.bytes.min(free_target.bytes).min(free_capacity.bytes),
            records: delta
                .records
                .min(free_target.records)
                .min(free_capacity.records),
        };
        self.grant(flow, current.add(increment)?)
    }

    /// Validate and retain bounded metadata for an authenticated incoming record.
    /// Payload integrity and byte-buffer ownership remain the caller's responsibility.
    pub fn receive(&mut self, record: Record) -> Result<Received, CreditError> {
        check_scope(self.scope, record.scope)?;
        let end = record.end()?;
        let flow = self
            .flows
            .get_mut(&record.flow)
            .ok_or(CreditError::UnknownFlow)?;
        if !end.fits(flow.limit) {
            return Err(CreditError::GrantExceeded);
        }
        if record.id.0 < flow.released.records {
            return if end.bytes <= flow.released.bytes {
                Ok(Received::AlreadyReleased)
            } else {
                Err(CreditError::InvalidOffset)
            };
        }
        if let Some(previous) = flow.pending.get(&record.id) {
            return if *previous == record {
                Ok(Received::Duplicate)
            } else {
                Err(CreditError::InvalidOffset)
            };
        }
        if record.byte_start < flow.released.bytes
            || (record.id.0 == flow.released.records && record.byte_start != flow.released.bytes)
        {
            return Err(CreditError::InvalidOffset);
        }
        if let Some((_, previous)) = flow.pending.range(..record.id).next_back() {
            let previous_end = previous.end()?;
            if previous_end.bytes > record.byte_start
                || (previous_end.records == record.id.0 && previous_end.bytes != record.byte_start)
            {
                return Err(CreditError::InvalidOffset);
            }
        }
        if let Some((_, next)) = flow.pending.range((Excluded(record.id), Unbounded)).next()
            && (end.bytes > next.byte_start
                || (end.records == next.id.0 && end.bytes != next.byte_start))
        {
            return Err(CreditError::InvalidOffset);
        }
        flow.observed = flow.observed.max(end);
        flow.pending.insert(record.id, record);
        Ok(Received::New)
    }

    /// Release the next contiguous record only after its payload buffer is relinquished.
    /// A missing earlier record returns `MissingRecord` without freeing reservations.
    pub fn release_next(&mut self, flow: FlowId) -> Result<Release, CreditError> {
        let state = self.flows.get(&flow).ok_or(CreditError::UnknownFlow)?;
        let id = RecordId(state.released.records);
        let record = *state.pending.get(&id).ok_or(CreditError::MissingRecord)?;
        let consumed = record.end()?;
        let reserved = self.reserved.subtract(record.charge())?;
        let state = self.flows.get_mut(&flow).ok_or(CreditError::UnknownFlow)?;
        state.pending.remove(&id);
        state.released = consumed;
        self.reserved = reserved;
        Ok(Release {
            scope: self.scope,
            flow,
            consumed,
        })
    }

    /// Retire after the caller completes an authenticated final-offset barrier.
    /// Abandonment discards all remaining payloads; normal retirement proves release.
    pub fn retire(
        &mut self,
        final_offset: FinalOffset,
        mode: RetirementMode,
    ) -> Result<(), CreditError> {
        check_scope(self.scope, final_offset.scope)?;
        let state = self
            .flows
            .get(&final_offset.flow)
            .ok_or(CreditError::UnknownFlow)?;
        if !final_offset.admitted.fits(state.limit)
            || !state.observed.fits(final_offset.admitted)
            || !state.released.fits(final_offset.admitted)
            || (state.observed.records == final_offset.admitted.records
                && state.observed.bytes != final_offset.admitted.bytes)
        {
            return Err(CreditError::InvalidOffset);
        }
        if mode == RetirementMode::Drained
            && (state.released != final_offset.admitted || !state.pending.is_empty())
        {
            return Err(CreditError::OutstandingRecords);
        }
        let unused = state.limit.subtract(state.released)?;
        let reserved = self.reserved.subtract(unused)?;
        self.flows.remove(&final_offset.flow);
        self.reserved = reserved;
        Ok(())
    }

    /// All outstanding promises, including records that have never arrived.
    pub fn reserved(&self) -> Credit {
        self.reserved
    }

    /// Count of live flows; retired flows require no growing tombstone map here.
    pub fn active_flows(&self) -> usize {
        self.flows.len()
    }
}

#[derive(Debug, Default)]
struct SenderFlow {
    limit: Credit,
    used: Credit,
    released: Credit,
    pending: BTreeMap<RecordId, Record>,
}

/// Sender ledger with absolute peer credit and separately bounded local retention.
#[derive(Debug)]
pub struct SenderCredits {
    scope: Scope,
    capacity: Capacity,
    session_limit: Credit,
    total_used: Credit,
    retained: Credit,
    last_flow: Option<FlowId>,
    flows: BTreeMap<FlowId, SenderFlow>,
}

impl SenderCredits {
    /// Create an empty ledger; the peer must explicitly grant admission capacity.
    pub fn new(scope: Scope, capacity: Capacity) -> Result<Self, CreditError> {
        capacity.validate()?;
        Ok(Self {
            scope,
            capacity,
            session_limit: Credit::default(),
            total_used: Credit::default(),
            retained: Credit::default(),
            last_flow: None,
            flows: BTreeMap::new(),
        })
    }

    /// Open a strictly increasing flow ID; opening does not grant admission credit.
    pub fn open_flow(&mut self, flow: FlowId) -> Result<(), CreditError> {
        check_new_flow(
            flow,
            self.last_flow,
            self.flows.len(),
            self.capacity.max_flows,
        )?;
        self.flows.insert(flow, SenderFlow::default());
        self.last_flow = Some(flow);
        Ok(())
    }

    /// Merge authenticated absolute limits; reordered/duplicate grants cannot revoke
    /// or recreate credit already charged to unique records.
    pub fn apply_grant(&mut self, grant: Grant) -> Result<(), CreditError> {
        check_scope(self.scope, grant.scope)?;
        if !grant.flow_limit.fits(grant.session_limit) {
            return Err(CreditError::InvalidOffset);
        }
        let flow = self
            .flows
            .get_mut(&grant.flow)
            .ok_or(CreditError::UnknownFlow)?;
        flow.limit = flow.limit.max(grant.flow_limit);
        self.session_limit = self.session_limit.max(grant.session_limit);
        Ok(())
    }

    /// Preview the exact next record without changing counters or retention.
    ///
    /// Performs the same authoritative scope/flow/session/local-capacity and
    /// checked-arithmetic validation as `admit`. It reserves nothing; commit
    /// must use the same exclusively serialized ledger without intervening work.
    pub fn preview_admit(&self, flow: FlowId, bytes: u64) -> Result<Record, CreditError> {
        let state = self.flows.get(&flow).ok_or(CreditError::UnknownFlow)?;
        let charge = Credit { bytes, records: 1 };
        let next = state.used.add(charge)?;
        let total = self.total_used.add(charge)?;
        if !next.fits(state.limit) {
            return Err(CreditError::SenderExhausted(LimitDomain::Flow));
        }
        if !total.fits(self.session_limit) {
            return Err(CreditError::SenderExhausted(LimitDomain::Session));
        }
        let retained = self.retained.add(charge)?;
        if !retained.fits(self.capacity.credit) {
            return Err(CreditError::LocalRetention);
        }
        Ok(Record {
            scope: self.scope,
            flow,
            id: RecordId(state.used.records),
            byte_start: state.used.bytes,
            byte_len: bytes,
        })
    }

    /// Admit a fresh logical record once; outer retransmission/FEC bytes are not
    /// accounted here and must still consume the caller's wire and QoS budgets.
    pub fn admit(&mut self, flow: FlowId, bytes: u64) -> Result<Record, CreditError> {
        let record = self.preview_admit(flow, bytes)?;
        let next = record.end()?;
        let total = self.total_used.add(record.charge())?;
        let retained = self.retained.add(record.charge())?;
        let state = self.flows.get_mut(&flow).ok_or(CreditError::UnknownFlow)?;
        state.pending.insert(record.id, record);
        state.used = next;
        self.total_used = total;
        self.retained = retained;
        Ok(record)
    }

    /// Retrieve the unchanged token for a retry without charging logical credit.
    pub fn retry(&self, flow: FlowId, id: RecordId) -> Result<Record, CreditError> {
        self.flows
            .get(&flow)
            .ok_or(CreditError::UnknownFlow)?
            .pending
            .get(&id)
            .copied()
            .ok_or(CreditError::MissingRecord)
    }

    /// Release local retention at an exact record boundary. Old cumulative releases
    /// are ignored; inconsistent boundaries fail without modifying counters.
    pub fn apply_release(&mut self, release: Release) -> Result<(), CreditError> {
        check_scope(self.scope, release.scope)?;
        let state = self
            .flows
            .get(&release.flow)
            .ok_or(CreditError::UnknownFlow)?;
        if release.consumed.fits(state.released) {
            return Ok(());
        }
        if !state.released.fits(release.consumed)
            || !release.consumed.fits(state.used)
            || release.consumed.records == state.released.records
        {
            return Err(CreditError::InvalidOffset);
        }
        let last = RecordId(
            release
                .consumed
                .records
                .checked_sub(1)
                .ok_or(CreditError::InvalidOffset)?,
        );
        if state
            .pending
            .get(&last)
            .ok_or(CreditError::MissingRecord)?
            .end()?
            != release.consumed
        {
            return Err(CreditError::InvalidOffset);
        }
        let delta = release.consumed.subtract(state.released)?;
        let retained = self.retained.subtract(delta)?;
        let state = self
            .flows
            .get_mut(&release.flow)
            .ok_or(CreditError::UnknownFlow)?;
        while state
            .pending
            .first_key_value()
            .is_some_and(|(id, _)| id.0 < release.consumed.records)
        {
            state.pending.pop_first();
        }
        state.released = release.consumed;
        self.retained = retained;
        Ok(())
    }

    /// Produce an exact final offset and remove local state. The caller must send
    /// this final offset through authenticated reliable management before the peer
    /// may reclaim its reservation. Keep the returned value for management retries.
    pub fn retire(
        &mut self,
        flow: FlowId,
        mode: RetirementMode,
    ) -> Result<FinalOffset, CreditError> {
        let state = self.flows.get(&flow).ok_or(CreditError::UnknownFlow)?;
        if mode == RetirementMode::Drained && !state.pending.is_empty() {
            return Err(CreditError::OutstandingRecords);
        }
        let remaining = state.used.subtract(state.released)?;
        let retained = self.retained.subtract(remaining)?;
        let final_offset = FinalOffset {
            scope: self.scope,
            flow,
            admitted: state.used,
        };
        self.flows.remove(&flow);
        self.retained = retained;
        Ok(final_offset)
    }

    /// Current local logical bytes/count retained for retransmission.
    pub fn retained(&self) -> Credit {
        self.retained
    }

    /// Irreversible aggregate unique admission counters, excluding retries.
    pub fn admitted(&self) -> Credit {
        self.total_used
    }

    /// Count of currently open flows.
    pub fn active_flows(&self) -> usize {
        self.flows.len()
    }
}

fn check_scope(expected: Scope, actual: Scope) -> Result<(), CreditError> {
    if expected != actual {
        return Err(CreditError::WrongScope);
    }
    Ok(())
}

fn check_new_flow(
    flow: FlowId,
    previous: Option<FlowId>,
    count: usize,
    maximum: usize,
) -> Result<(), CreditError> {
    if previous.is_some_and(|last| flow <= last) {
        return Err(CreditError::FlowIdNotIncreasing);
    }
    if count >= maximum {
        return Err(CreditError::TooManyFlows);
    }
    Ok(())
}

#[cfg(test)]
mod tests;
