//! Source-free ACK custody; all original bytes still require the common Pipeline.
use super::*;
use crate::packet::{Classification, FlowKey};

/// Explicit finite source-free ACK limits; absence selects recovered-only behavior.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UnreliableConfig {
    /// Maximum complete native ACK bytes in an actual preallocated slot.
    pub max_bytes: usize,
    /// Maximum age, measured from original admission/arrival and never renewed.
    pub hold_micros: u64,
}
impl UnreliableConfig {
    pub(super) fn validate(self, native_maximum: usize) -> Result<(), Error> {
        if self.max_bytes == 0 || self.max_bytes > native_maximum || self.hold_micros == 0 {
            return Err(Error::Configuration);
        }
        u64::try_from(self.max_bytes).map_err(|_| Error::Arithmetic)?;
        Ok(())
    }
}

/// Unordered native event; this serial is not a recovery/native-prefix identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UnreliableIdentity {
    /// Actual fixed owner selected through the sole common Pipeline.
    pub owner: OwnerId,
    /// Original cohort incarnation.
    pub incarnation: u64,
    /// Nonwrapping sender event serial, distinct from security packet numbers.
    pub serial: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct RawSend {
    identity: UnreliableIdentity,
    bytes: usize,
    pub(super) deadline: Duration,
    prepared_at: Option<Duration>,
    wire_bytes: usize,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct RawReceive {
    identity: UnreliableIdentity,
    generation: u64,
    bytes: usize,
    pub(super) deadline: Duration,
    prepared_at: Option<Duration>,
}

/// Move-only exact source-free output awaiting a whole-carrier receipt.
#[derive(Debug, Eq, PartialEq)]
pub struct UnreliableOutput {
    instance: u64,
    inner: RawSend,
    route_bytes: usize,
}
impl UnreliableOutput {
    /// Original owner/incarnation/event, without peer-delivery authority.
    pub const fn identity(&self) -> UnreliableIdentity {
        self.inner.identity
    }
    /// Exact routed bytes retained in the caller's output buffer.
    pub fn bytes(&self) -> usize {
        self.route_bytes + self.inner.bytes
    }
    /// Exact route and actual external carrier charge, already debited once.
    pub const fn wire_bytes(&self) -> usize {
        self.inner.wire_bytes
    }
    /// Original absolute cap retained through WouldBlock and delayed observation.
    pub const fn deadline(&self) -> Duration {
        self.inner.deadline
    }
}

/// Move-only receipt witness for one actual source-free native write.
#[derive(Debug, Eq, PartialEq)]
pub struct UnreliableNativeToken {
    instance: u64,
    inner: RawReceive,
}
impl UnreliableNativeToken {
    /// Original sender event, separate from the local receiver custody generation.
    pub const fn identity(&self) -> UnreliableIdentity {
        self.inner.identity
    }
}

/// Borrowed actual immutable native custody; no recovery prefix is advanced.
pub struct PendingUnreliableNative<'a> {
    /// Original source-free identity.
    pub identity: UnreliableIdentity,
    /// Actual retained complete native bytes.
    pub bytes: &'a [u8],
    /// Original arrival/admission cap, never a newly created preparation timer.
    pub deadline: Duration,
}

/// Local physical facts only; no unreliable peer-delivery count is invented.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct UnreliableStatistics {
    /// Actual source-free ACK admissions from the common Pipeline.
    pub admitted: u64,
    /// Actual once-debited routed outputs prepared.
    pub emitted: u64,
    /// Trusted whole-carrier receipts, including late facts.
    pub physical_accepted: u64,
    /// Receipts whose actual acceptance reached/passed the original cap.
    pub late_physical_accepted: u64,
    /// Queued packets expired before a physical output was prepared.
    pub expired_before_send: u64,
    /// Authenticated complete ACKs retained locally for native delivery.
    pub received: u64,
    /// Trusted whole native writes, including irreversible late facts.
    pub native_written: u64,
    /// Actual native acceptance reached/passed the original arrival cap.
    pub late_native_written: u64,
}

fn next(value: u64) -> Result<u64, Error> {
    value.checked_add(1).ok_or(Error::Arithmetic)
}
fn cap(now: Duration, policy: UnreliableConfig, original: Duration) -> Result<Duration, Error> {
    let deadline = now
        .checked_add(Duration::from_micros(policy.hold_micros))
        .ok_or(Error::Arithmetic)?
        .min(original);
    if now >= deadline {
        return Err(Error::UnreliableExpired);
    }
    Ok(deadline)
}
fn payload_range(
    id: OwnerId,
    maximum: usize,
    length: usize,
) -> Result<std::ops::Range<usize>, Error> {
    if length > maximum {
        return Err(Error::Configuration);
    }
    let start = usize::from(id.index())
        .checked_mul(maximum)
        .ok_or(Error::Arithmetic)?;
    Ok(start..start.checked_add(length).ok_or(Error::Arithmetic)?)
}

impl Collection {
    fn check_unreliable_time(&self, id: OwnerId, now: Duration) -> Result<(), Error> {
        if self.slot(id)?.last_raw.is_some_and(|last| now < last) {
            return Err(Error::Time);
        }
        Ok(())
    }
    /// Check the immutable association to the actual Pipeline's canonical key.
    pub fn check_owner_claim(&self, id: OwnerId, key: FlowKey) -> Result<(), Error> {
        if self.slot(id)?.claim.is_some_and(|actual| actual != key) {
            return Err(Error::Binding);
        }
        // Fixed metadata-only cohort scan; there is no second flow table/map.
        if self
            .slots
            .iter()
            .enumerate()
            .any(|(index, slot)| index != usize::from(id.index()) && slot.claim == Some(key))
        {
            return Err(Error::Binding);
        }
        Ok(())
    }

    /// Bind only after the caller's actual reverse-affinity learn has succeeded.
    /// No owner can ever be rebound or recycled by this fixed-cohort API.
    pub fn bind_received_owner(&mut self, id: OwnerId, key: FlowKey) -> Result<(), Error> {
        if self
            .slot(id)?
            .retirement
            .as_ref()
            .is_some_and(retirement::State::installed)
        {
            return Err(Error::Retiring);
        }
        self.check_owner_claim(id, key)?;
        self.slot_mut(id)?.claim = Some(key);
        Ok(())
    }

    /// Offer recovered bytes with their actual Pipeline association transaction.
    pub fn offer_recovered(
        &mut self,
        id: OwnerId,
        key: FlowKey,
        now: Duration,
        bytes: &[u8],
    ) -> Result<Option<Identity>, Error> {
        self.check_owner_claim(id, key)?;
        if !self.admission_open(id)? {
            return Ok(None);
        }
        let incarnation = self.slot(id)?.incarnation;
        let admitted = self
            .slot(id)?
            .admitted_native
            .checked_add(1)
            .ok_or(Error::Arithmetic)?;
        let slot = self.slot_mut(id)?;
        if let Some(error) = slot.native_failure {
            return Err(Error::Endpoint(error));
        }
        if let Some(error) = slot.raw_failure {
            return Err(error);
        }
        let record = match slot
            .endpoint
            .enqueue_identified(aligned::ChannelId(0), bytes, now)
        {
            Ok(record) => record,
            Err(aligned::Error::Busy) => return Ok(None),
            Err(error) => return Err(Error::Endpoint(error)),
        };
        slot.claim = Some(key);
        slot.admitted_native = admitted;
        Ok(Some(Identity {
            owner: id,
            incarnation,
            record,
        }))
    }

    /// Reuse the maintained checksum/complete-ACK inspection, without state or parsing policy duplication.
    pub fn unreliable_eligible(&self, class: Classification, bytes: &[u8]) -> bool {
        self.plan.config().send_unreliable.is_some_and(|policy| {
            crate::pipeline::ack_coalescing::is_complete_pure_tcp_ack(
                bytes,
                class,
                policy.max_bytes,
            )
        })
    }

    /// Admit one exact pure ACK; None preserves the common Pipeline head on pressure.
    pub fn offer_unreliable(
        &mut self,
        id: OwnerId,
        received: Duration,
        now: Duration,
        original_deadline: Duration,
        class: Classification,
        bytes: &[u8],
    ) -> Result<Option<UnreliableIdentity>, Error> {
        let config = self.plan.config();
        let policy = config.send_unreliable.ok_or(Error::UnsupportedUnreliable)?;
        self.check_owner_claim(id, class.key)?;
        if !self.admission_open(id)? {
            return Ok(None);
        }
        self.check_unreliable_time(id, now)?;
        let slot = self.slot(id)?;
        if let Some(error) = slot.native_failure {
            return Err(Error::Endpoint(error));
        }
        if let Some(error) = slot.raw_failure {
            return Err(error);
        }
        if !self.unreliable_eligible(class, bytes) {
            return Err(Error::UnreliableEligibility);
        }
        if slot.raw_send.is_some() {
            return Ok(None);
        }
        if received > now {
            return Err(Error::Time);
        }
        let deadline = cap(received, policy, original_deadline)?;
        if now >= deadline {
            return Err(Error::UnreliableExpired);
        }
        let serial = next(slot.next_raw_send)?;
        let admitted = next(self.unreliable_statistics.admitted)?;
        let range = payload_range(id, policy.max_bytes, bytes.len())?;
        let target = self.raw_send.get_mut(range).ok_or(Error::Invariant)?;
        target.copy_from_slice(bytes);
        let identity = UnreliableIdentity {
            owner: id,
            incarnation: self.slot(id)?.incarnation,
            serial,
        };
        let slot = self.slot_mut(id)?;
        slot.raw_send = Some(RawSend {
            identity,
            bytes: bytes.len(),
            deadline,
            prepared_at: None,
            wire_bytes: 0,
        });
        slot.next_raw_send = serial;
        slot.claim = Some(class.key);
        slot.last_raw = Some(now);
        self.unreliable_statistics.admitted = admitted;
        Ok(Some(identity))
    }

    /// Observe original prepared custody without writing, allocating or debiting again.
    pub fn pending_unreliable_output(
        &self,
        id: OwnerId,
    ) -> Result<Option<UnreliableOutput>, Error> {
        Ok(self
            .slot(id)?
            .raw_send
            .filter(|p| p.prepared_at.is_some())
            .map(|inner| UnreliableOutput {
                instance: self.instance,
                inner,
                route_bytes: self.route_bytes(true),
            }))
    }

    /// Prepare one source-free output with exact route/full-carrier bytes once.
    pub fn poll_unreliable(
        &mut self,
        id: OwnerId,
        now: Duration,
        output: &mut [u8],
        budget: &mut OutboundBudget,
    ) -> Result<Option<UnreliableOutput>, Error> {
        self.tick_unreliable(id, now)?;
        let Some(mut inner) = self.slot(id)?.raw_send else {
            return Ok(None);
        };
        if inner.prepared_at.is_some() {
            return Ok(None);
        }
        let config = self.plan.config();
        let policy = config.send_unreliable.ok_or(Error::Invariant)?;
        let route_bytes = self.route_bytes(true);
        let length = inner
            .bytes
            .checked_add(route_bytes)
            .ok_or(Error::Arithmetic)?;
        if output.len() < length {
            return Err(Error::Output { required: length });
        }
        let wire = length
            .checked_add(config.send_carrier_overhead_bytes)
            .ok_or(Error::Arithmetic)?;
        if budget.packets == 0 || budget.wire_bytes < wire {
            return Ok(None);
        }
        let emitted = next(self.unreliable_statistics.emitted)?;
        let mut header = [0; route::HEADER_BYTES];
        let route = route::Header {
            owner: id,
            incarnation: inner.identity.incarnation,
            class: route::Class::UnreliableNative,
            unreliable_serial: inner.identity.serial,
        };
        self.encode_route(route, &mut header[..route_bytes])?;
        let range = payload_range(id, policy.max_bytes, inner.bytes)?;
        let source = self.raw_send.get(range).ok_or(Error::Invariant)?;
        output[..route_bytes].copy_from_slice(&header[..route_bytes]);
        output[route_bytes..length].copy_from_slice(source);
        inner.prepared_at = Some(now);
        inner.wire_bytes = wire;
        self.slot_mut(id)?.raw_send = Some(inner);
        self.unreliable_statistics.emitted = emitted;
        budget.packets -= 1;
        budget.wire_bytes -= wire;
        Ok(Some(UnreliableOutput {
            instance: self.instance,
            inner,
            route_bytes: self.route_bytes(true),
        }))
    }

    /// Retire only after true whole-carrier acceptance; late/error facts are consumed once.
    pub fn confirm_unreliable_output_at(
        &mut self,
        observed: Duration,
        accepted: Duration,
        token: UnreliableOutput,
    ) -> Result<(), Error> {
        let id = token.inner.identity.owner;
        if token.instance != self.instance
            || self.slot(id)?.raw_send != Some(token.inner)
            || token.inner.prepared_at.is_none()
        {
            return Err(Error::Token);
        }
        let physical = next(self.unreliable_statistics.physical_accepted)?;
        let late = accepted >= token.inner.deadline;
        let late_count = if late {
            next(self.unreliable_statistics.late_physical_accepted)?
        } else {
            self.unreliable_statistics.late_physical_accepted
        };
        let prior = self.slot(id)?.raw_failure;
        let timing = if accepted > observed
            || token.inner.prepared_at.is_some_and(|at| accepted < at)
            || self.slot(id)?.last_raw.is_some_and(|last| observed < last)
        {
            Some(Error::Time)
        } else if late {
            Some(Error::UnreliableExpired)
        } else {
            None
        };
        let slot = self.slot_mut(id)?;
        slot.raw_send = None;
        if let Some(error) = timing {
            slot.raw_failure = Some(error);
        }
        slot.last_raw = Some(slot.last_raw.map_or(observed, |last| last.max(observed)));
        self.unreliable_statistics.physical_accepted = physical;
        self.unreliable_statistics.late_physical_accepted = late_count;
        timing.or(prior).map_or(Ok(()), Err)
    }

    /// Apply caller-authenticated raw ACK bytes with their actual receive classifier metadata.
    /// Busy preserves caller plaintext, original arrival and original cap for retry.
    pub fn accept_classified_authenticated_at(
        &mut self,
        received: Duration,
        observed: Duration,
        original_deadline: Duration,
        packet: &[u8],
        class: Classification,
    ) -> Result<(), Error> {
        let (header, bytes) = self.decode_route(packet)?;
        if header.class != route::Class::UnreliableNative {
            return self.accept_authenticated_at(received, observed, packet);
        }
        let config = self.plan.config();
        if header.incarnation != self.slot(header.owner)?.incarnation {
            return Err(Error::Incarnation);
        }
        if self
            .slot(header.owner)?
            .retirement
            .as_ref()
            .is_some_and(retirement::State::installed)
        {
            return Err(Error::Retiring);
        }
        let policy = config
            .receive_unreliable
            .ok_or(Error::UnsupportedUnreliable)?;
        self.check_owner_claim(header.owner, class.key)?;
        self.check_unreliable_time(header.owner, observed)?;
        let slot = self.slot(header.owner)?;
        if let Some(error) = slot.native_failure {
            return Err(Error::Endpoint(error));
        }
        if let Some(error) = slot.raw_failure {
            return Err(error);
        }
        if received > observed {
            return Err(Error::Time);
        }
        let deadline = cap(received, policy, original_deadline)?;
        if observed >= deadline {
            return Err(Error::UnreliableExpired);
        }
        if !crate::pipeline::ack_coalescing::is_complete_pure_tcp_ack(
            bytes,
            class,
            policy.max_bytes,
        ) {
            return Err(Error::UnreliableEligibility);
        }
        if slot.raw_receive.is_some() {
            return Err(Error::UnreliableBusy);
        }
        let generation = next(slot.next_raw_receive)?;
        let accepted = next(self.unreliable_statistics.received)?;
        let range = payload_range(header.owner, policy.max_bytes, bytes.len())?;
        self.raw_receive
            .get_mut(range)
            .ok_or(Error::Invariant)?
            .copy_from_slice(bytes);
        let identity = UnreliableIdentity {
            owner: header.owner,
            incarnation: header.incarnation,
            serial: header.unreliable_serial,
        };
        let slot = self.slot_mut(header.owner)?;
        slot.raw_receive = Some(RawReceive {
            identity,
            generation,
            bytes: bytes.len(),
            deadline,
            prepared_at: None,
        });
        slot.next_raw_receive = generation;
        slot.claim = Some(class.key);
        slot.last_raw = Some(observed);
        self.unreliable_statistics.received = accepted;
        Ok(())
    }

    /// Prepare/observe the same immutable raw native body; no ordered/reliable prefix moves.
    pub fn prepare_unreliable_native(
        &mut self,
        id: OwnerId,
        now: Duration,
    ) -> Result<Option<UnreliableNativeToken>, Error> {
        self.tick_unreliable(id, now)?;
        let instance = self.instance;
        let slot = self.slot_mut(id)?;
        let Some(mut inner) = slot.raw_receive else {
            return Ok(None);
        };
        if inner.prepared_at.is_none() {
            inner.prepared_at = Some(now);
            slot.raw_receive = Some(inner);
        }
        Ok(Some(UnreliableNativeToken { instance, inner }))
    }

    /// Borrow actual retained native bytes; retry cannot refresh the original arrival cap.
    pub fn pending_unreliable_native(
        &self,
        id: OwnerId,
    ) -> Result<Option<PendingUnreliableNative<'_>>, Error> {
        let slot = self.slot(id)?;
        if let Some(error) = slot.native_failure {
            return Err(Error::Endpoint(error));
        }
        if let Some(error) = slot.raw_failure {
            return Err(error);
        }
        let Some(inner) = slot.raw_receive.filter(|r| r.prepared_at.is_some()) else {
            return Ok(None);
        };
        let policy = self
            .plan
            .config()
            .receive_unreliable
            .ok_or(Error::Invariant)?;
        let range = payload_range(id, policy.max_bytes, inner.bytes)?;
        Ok(Some(PendingUnreliableNative {
            identity: inner.identity,
            bytes: self.raw_receive.get(range).ok_or(Error::Invariant)?,
            deadline: inner.deadline,
        }))
    }

    /// Record a genuine complete native write once, including irreversible late/error facts.
    pub fn commit_unreliable_native_at(
        &mut self,
        observed: Duration,
        accepted: Duration,
        token: UnreliableNativeToken,
    ) -> Result<(), Error> {
        let id = token.inner.identity.owner;
        if token.instance != self.instance
            || self.slot(id)?.raw_receive != Some(token.inner)
            || token.inner.prepared_at.is_none()
        {
            return Err(Error::Token);
        }
        let written = next(self.unreliable_statistics.native_written)?;
        let late = accepted >= token.inner.deadline;
        let late_count = if late {
            next(self.unreliable_statistics.late_native_written)?
        } else {
            self.unreliable_statistics.late_native_written
        };
        let prior = self.slot(id)?.raw_failure;
        let timing = if accepted > observed
            || token.inner.prepared_at.is_some_and(|at| accepted < at)
            || self.slot(id)?.last_raw.is_some_and(|last| observed < last)
        {
            Some(Error::Time)
        } else if late {
            Some(Error::UnreliableExpired)
        } else {
            None
        };
        let slot = self.slot_mut(id)?;
        slot.raw_receive = None;
        if let Some(error) = timing {
            slot.raw_failure = Some(error);
        }
        slot.last_raw = Some(slot.last_raw.map_or(observed, |last| last.max(observed)));
        self.unreliable_statistics.native_written = written;
        self.unreliable_statistics.late_native_written = late_count;
        timing.or(prior).map_or(Ok(()), Err)
    }

    /// Expire only queued unsent raw data; prepared/native custody remains visible until cleanup.
    pub fn tick_unreliable(&mut self, id: OwnerId, now: Duration) -> Result<(), Error> {
        self.check_unreliable_time(id, now)?;
        let slot = self.slot(id)?;
        if let Some(error) = slot.native_failure {
            return Err(Error::Endpoint(error));
        }
        if let Some(error) = slot.raw_failure {
            return Err(error);
        }
        let expired_queued = slot
            .raw_send
            .is_some_and(|p| p.prepared_at.is_none() && now >= p.deadline);
        if expired_queued {
            let expired = next(self.unreliable_statistics.expired_before_send)?;
            self.slot_mut(id)?.raw_send = None;
            self.unreliable_statistics.expired_before_send = expired;
        }
        let slot = self.slot_mut(id)?;
        slot.last_raw = Some(now);
        if slot.raw_send.is_some_and(|p| now >= p.deadline)
            || slot.raw_receive.is_some_and(|p| now >= p.deadline)
        {
            slot.raw_failure = Some(Error::UnreliableExpired);
            return Err(Error::UnreliableExpired);
        }
        Ok(())
    }

    /// Distinct local raw facts; none is a recovery/native peer prefix.
    pub const fn unreliable_statistics(&self) -> UnreliableStatistics {
        self.unreliable_statistics
    }
}
