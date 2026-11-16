//! Actual independent Compact owners, before Common Engine/profile installation.
//!
//! Callers retain the sole Pipeline, authentication, carrier and immutable output
//! buffers. This fixed cohort has no flow rebinding/eviction or runtime installation.
use crate::aligned;
use l2tunnel_recovery::RecoveryContext;
use l2tunnel_reliable::{OutboundBudget, RecordKind};
use std::{
    fmt,
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};

mod configuration;
mod observers;
/// Exact versioned route grammar, without authentication authority.
pub mod route;
/// Actual fixed, vector and nested heap inventory.
pub mod storage;
mod unreliable;
pub use configuration::{DIRECTION_BYTES, Direction};
pub use unreliable::{
    PendingUnreliableNative, UnreliableConfig, UnreliableIdentity, UnreliableNativeToken,
    UnreliableOutput, UnreliableStatistics,
};

// Local custody discriminator only; never serialized, used as a nonce or trusted.
static NEXT_COLLECTION: AtomicU64 = AtomicU64::new(1);

/// Complete fixed-cohort policy; no implied connection/channel mapping.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Config {
    /// Actual independent duplex owners to reserve, in1..=256.
    pub owners: u16,
    /// Positive immutable cohort incarnation; no reuse is offered by this module.
    pub incarnation: u64,
    /// Actual single-channel local send policy, with route overhead included.
    pub send: aligned::CompactConfig,
    /// Actual single-channel peer send policy, with route overhead included.
    pub receive: aligned::CompactConfig,
    /// Exact external carrier/security/cover bytes before adding the route.
    pub send_carrier_overhead_bytes: usize,
    /// Exact opposite-direction external bytes before adding the route.
    pub receive_carrier_overhead_bytes: usize,
    /// Explicit finite raw ACK custody, or recovered-only behavior.
    pub send_unreliable: Option<UnreliableConfig>,
    /// Independently bounded original-arrival native custody for peer raw ACKs.
    pub receive_unreliable: Option<UnreliableConfig>,
}

/// Checked index, unrelated to a cryptographic lane or inner source identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OwnerId(u16);
impl OwnerId {
    /// Exact owner index; it grants no flow-registration authority.
    pub const fn index(self) -> u16 {
        self.0
    }
}

/// Actual body identity, preserving the inner codec's independent record space.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Identity {
    /// Actual collection owner.
    pub owner: OwnerId,
    /// Original fixed-cohort incarnation.
    pub incarnation: u64,
    /// Actual inner local-channel0 identity, not an admitted-native count.
    pub record: aligned::RecordIdentity,
}

/// Collection/configuration/refusal errors; nested endpoint pressure is preserved.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// Unsupported cohort, channel, copy or explicit route geometry.
    Configuration,
    /// Index is outside the actual cohort.
    Owner,
    /// Routed packet belongs to another fixed cohort.
    Incarnation,
    /// Exact strict route grammar error.
    Route(route::Error),
    /// Claimed route class differs from the maintained recovery parser.
    Class,
    /// Unreliable-native custody is not installed; no body was admitted.
    UnsupportedUnreliable,
    /// Actual normalized flow conflicts with this immutable fixed owner claim.
    Binding,
    /// Complete native bytes are not an eligible canonical pure TCP ACK.
    UnreliableEligibility,
    /// Retain exact authenticated input and original cap until raw receive custody frees.
    UnreliableBusy,
    /// The original selected raw send/arrival cap expired.
    UnreliableExpired,
    /// Injected observation/acceptance is nonmonotonic or inconsistent.
    Time,
    /// Caller output is too short; no downstream poll ran.
    Output {
        /// Complete routed output bytes required in caller storage.
        required: usize,
    },
    /// Foreign, stale, duplicate or mismatched local custody witness.
    Token,
    /// New receiver preparation requires positive caller-bounded work.
    Work,
    /// Checked arithmetic or local nonwrapping identity exhausted.
    Arithmetic,
    /// Actual nested endpoint reservation refused.
    Storage(aligned::storage::Error),
    /// Actual nested endpoint error, including unchanged retryable pressure.
    Endpoint(aligned::Error),
    /// Complete managed capacity exceeds the explicit allowance.
    Limit {
        /// Complete actual fixed, vector and nested capacity required.
        required: usize,
        /// Explicit caller-provided capacity allowance.
        limit: usize,
    },
    /// Fallible fixed owner-vector reservation failed.
    Allocation,
    /// Actual retained capacities or emitted custody disagree with the plan.
    Invariant,
}
impl Error {
    /// Caller must retain authenticated plaintext, original arrival and cap on pressure.
    pub fn is_backpressure(self) -> bool {
        matches!(self, Self::UnreliableBusy)
            || matches!(self, Self::Endpoint(error) if error.is_backpressure())
    }
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "independent Compact owners: {self:?}")
    }
}
impl std::error::Error for Error {}

/// Move-only witness of actual retained maintained recovery output.
#[derive(Debug, Eq, PartialEq)]
pub struct PreparedOutput {
    instance: u64,
    owner: OwnerId,
    incarnation: u64,
    inner: aligned::PreparedOutput,
}
impl PreparedOutput {
    /// Exact owner that must consume the physical receipt.
    pub const fn owner(&self) -> OwnerId {
        self.owner
    }
    /// Exact initialized routed bytes in the caller's retained buffer.
    pub fn bytes(&self) -> usize {
        self.inner.bytes + route::HEADER_BYTES
    }
    /// Actual endpoint debit, including configured route overhead exactly once.
    pub const fn wire_bytes(&self) -> usize {
        self.inner.wire_bytes
    }
    /// Actual maintained parser classification.
    pub const fn kind(&self) -> RecordKind {
        self.inner.kind
    }
}

/// Move-only whole-native-write witness, separate from source/physical output.
#[derive(Debug, Eq, PartialEq)]
pub struct NativeToken {
    instance: u64,
    identity: Identity,
    serial: u64,
}
impl NativeToken {
    /// Original issuing owner/incarnation and actual body record.
    pub const fn identity(&self) -> Identity {
        self.identity
    }
}

/// Bounded preparation result; a pending token is only observed, never renewed.
#[derive(Debug, Eq, PartialEq)]
pub enum NativePreparation {
    /// No eligible complete body for the selected owner.
    Idle,
    /// Existing receiver context/tombstone work made bounded progress.
    Progress,
    /// Actual immutable native body awaits whole-device acceptance.
    Ready(NativeToken),
    /// Original immutable body and original deadline remain held.
    AlreadyPending(NativeToken),
}

/// Borrowed actual native output, without copying or retiring it.
pub struct PendingNative<'a> {
    /// Original body identity.
    pub identity: Identity,
    /// Complete actual immutable bytes.
    pub bytes: &'a [u8],
    /// Actual receiver's original pending expiry, not a recovery retry timer.
    pub deadline: Duration,
    /// Whether the existing generic short-record path released before a gap.
    pub early: bool,
}

struct Slot {
    endpoint: aligned::Endpoint,
    native: Option<(Identity, u64)>,
    next_native: u64,
    native_failure: Option<aligned::Error>,
    claim: Option<crate::packet::FlowKey>,
    raw_send: Option<unreliable::RawSend>,
    raw_receive: Option<unreliable::RawReceive>,
    next_raw_send: u64,
    next_raw_receive: u64,
    last_raw: Option<Duration>,
    raw_failure: Option<Error>,
}

/// One actual fixed cohort; downstream scheduling remains the caller's owner.
pub struct Collection {
    plan: storage::Plan,
    instance: u64,
    slots: Vec<Slot>,
    usage: storage::Usage,
    raw_send: Vec<u8>,
    raw_receive: Vec<u8>,
    unreliable_statistics: UnreliableStatistics,
}
impl Collection {
    /// Obtain a checked index without claiming flow or authentication authority.
    pub fn owner(&self, index: u16) -> Result<OwnerId, Error> {
        if usize::from(index) < self.slots.len() {
            Ok(OwnerId(index))
        } else {
            Err(Error::Owner)
        }
    }

    fn slot(&self, id: OwnerId) -> Result<&Slot, Error> {
        self.slots.get(usize::from(id.0)).ok_or(Error::Owner)
    }
    fn slot_mut(&mut self, id: OwnerId) -> Result<&mut Slot, Error> {
        self.slots.get_mut(usize::from(id.0)).ok_or(Error::Owner)
    }

    /// Stage only bytes already selected by the caller's sole common Pipeline.
    pub fn enqueue(&mut self, id: OwnerId, now: Duration, bytes: &[u8]) -> Result<Identity, Error> {
        if self.slot(id)?.claim.is_some() {
            return Err(Error::Binding);
        }
        if let Some(error) = self.slot(id)?.native_failure {
            return Err(Error::Endpoint(error));
        }
        if let Some(error) = self.slot(id)?.raw_failure {
            return Err(error);
        }
        let incarnation = self.plan.config().incarnation;
        let record = self
            .slot_mut(id)?
            .endpoint
            .enqueue_identified(aligned::ChannelId(0), bytes, now)
            .map_err(Error::Endpoint)?;
        Ok(Identity {
            owner: id,
            incarnation,
            record,
        })
    }

    fn wrap(&self, id: OwnerId, inner: aligned::PreparedOutput) -> PreparedOutput {
        PreparedOutput {
            instance: self.instance,
            owner: id,
            incarnation: self.plan.config().incarnation,
            inner,
        }
    }

    /// Observe actual data custody without polling, writing or debiting again.
    pub fn pending_data_output(&self, id: OwnerId) -> Result<Option<PreparedOutput>, Error> {
        Ok(self
            .slot(id)?
            .endpoint
            .pending_data_output()
            .map(|p| self.wrap(id, p)))
    }
    /// Observe the independently retained actual feedback output.
    pub fn pending_feedback_output(&self, id: OwnerId) -> Result<Option<PreparedOutput>, Error> {
        Ok(self
            .slot(id)?
            .endpoint
            .pending_feedback_output()
            .map(|p| self.wrap(id, p)))
    }

    /// Poll one selected owner's actual source/retry; no other owner is scanned.
    pub fn poll_data(
        &mut self,
        id: OwnerId,
        now: Duration,
        output: &mut [u8],
        budget: &mut OutboundBudget,
    ) -> Result<Option<PreparedOutput>, Error> {
        self.poll_selected(id, now, output, budget, false)
    }
    /// Poll actual lossy recovery feedback even while a data output is held.
    pub fn poll_feedback(
        &mut self,
        id: OwnerId,
        now: Duration,
        output: &mut [u8],
        budget: &mut OutboundBudget,
    ) -> Result<Option<PreparedOutput>, Error> {
        self.poll_selected(id, now, output, budget, true)
    }
    fn poll_selected(
        &mut self,
        id: OwnerId,
        now: Duration,
        output: &mut [u8],
        budget: &mut OutboundBudget,
        feedback: bool,
    ) -> Result<Option<PreparedOutput>, Error> {
        let slot = self.slot(id)?;
        let required = slot
            .endpoint
            .send_max_packet_bytes()
            .checked_add(route::HEADER_BYTES)
            .ok_or(Error::Arithmetic)?;
        if output.len() < required {
            return Err(Error::Output { required });
        }
        let class = if feedback {
            route::Class::Feedback
        } else {
            route::Class::Source
        };
        let header = route::Header {
            owner: id,
            incarnation: self.plan.config().incarnation,
            class,
            unreliable_serial: 0,
        };
        let mut encoded = [0; route::HEADER_BYTES];
        header.encode(&mut encoded).map_err(Error::Route)?;
        let endpoint = &mut self.slot_mut(id)?.endpoint;
        let selected = if feedback {
            endpoint.poll_feedback_independent(now, &mut output[route::HEADER_BYTES..], budget)
        } else {
            endpoint.poll_data_independent(now, &mut output[route::HEADER_BYTES..], budget)
        }
        .map_err(Error::Endpoint)?;
        let Some(bytes) = selected else {
            return Ok(None);
        };
        let inner = if feedback {
            endpoint.pending_feedback_output()
        } else {
            endpoint.pending_data_output()
        }
        .ok_or(Error::Invariant)?;
        let expected = if feedback {
            RecordKind::Feedback
        } else {
            RecordKind::Source
        };
        let end = route::HEADER_BYTES
            .checked_add(bytes)
            .ok_or(Error::Invariant)?;
        let emitted = output
            .get(route::HEADER_BYTES..end)
            .ok_or(Error::Invariant)?;
        if inner.bytes != bytes
            || inner.kind != expected
            || endpoint.inspect_output(emitted).map_err(Error::Endpoint)? != expected
        {
            return Err(Error::Invariant);
        }
        output[..route::HEADER_BYTES].copy_from_slice(&encoded);
        Ok(Some(self.wrap(id, inner)))
    }

    /// Confirm an actual whole-carrier receipt, preserving original acceptance time.
    pub fn confirm_output_at(
        &mut self,
        observed: Duration,
        accepted: Duration,
        token: PreparedOutput,
    ) -> Result<(), Error> {
        if token.instance != self.instance || token.incarnation != self.plan.config().incarnation {
            return Err(Error::Token);
        }
        let endpoint = &mut self.slot_mut(token.owner)?.endpoint;
        if endpoint.pending_data_output() != Some(token.inner)
            && endpoint.pending_feedback_output() != Some(token.inner)
        {
            return Err(Error::Token);
        }
        endpoint
            .confirm_output_at(observed, accepted, token.inner)
            .map_err(Error::Endpoint)
    }

    /// Admit only caller-authenticated complete routed bytes with original arrival.
    pub fn accept_authenticated_at(
        &mut self,
        received: Duration,
        observed: Duration,
        packet: &[u8],
    ) -> Result<(), Error> {
        let (header, body) = route::decode(packet).map_err(Error::Route)?;
        if header.incarnation != self.plan.config().incarnation {
            return Err(Error::Incarnation);
        }
        let endpoint = &mut self.slot_mut(header.owner)?.endpoint;
        let expected = match header.class {
            route::Class::Source => RecordKind::Source,
            route::Class::Feedback => RecordKind::Feedback,
            route::Class::UnreliableNative => return Err(Error::UnsupportedUnreliable),
        };
        if endpoint.inspect_peer(body).map_err(Error::Endpoint)? != expected {
            return Err(Error::Class);
        }
        endpoint
            .receive_authenticated_at(body, received, observed)
            .map_err(Error::Endpoint)
    }

    /// Service one actual owner's bounded receiver work; no hidden cohort scan.
    pub fn prepare_native(
        &mut self,
        id: OwnerId,
        now: Duration,
        work: usize,
    ) -> Result<NativePreparation, Error> {
        let instance = self.instance;
        let incarnation = self.plan.config().incarnation;
        let slot = self.slot_mut(id)?;
        if let Some(error) = slot.raw_failure {
            return Err(error);
        }
        if let Some(error) = slot.native_failure {
            return Err(Error::Endpoint(error));
        }
        if let Some((identity, serial)) = slot.native {
            slot.endpoint.tick(now).map_err(Error::Endpoint)?;
            return Ok(NativePreparation::AlreadyPending(NativeToken {
                instance,
                identity,
                serial,
            }));
        }
        if work == 0 {
            return Err(Error::Work);
        }
        let next = slot.next_native.checked_add(1).ok_or(Error::Arithmetic)?;
        match slot
            .endpoint
            .prepare(aligned::ChannelId(0), now, work)
            .map_err(Error::Endpoint)?
        {
            aligned::Prepared::Idle => Ok(NativePreparation::Idle),
            aligned::Prepared::Progress => Ok(NativePreparation::Progress),
            aligned::Prepared::Ready => {
                let pending = slot.endpoint.pending().ok_or(Error::Invariant)?;
                let identity = Identity {
                    owner: id,
                    incarnation,
                    record: aligned::RecordIdentity {
                        channel: pending.channel,
                        record: pending.record,
                    },
                };
                slot.next_native = next;
                slot.native = Some((identity, next));
                Ok(NativePreparation::Ready(NativeToken {
                    instance,
                    identity,
                    serial: next,
                }))
            }
        }
    }

    /// Borrow the exact retained body and actual original deadline without mutation.
    pub fn pending_native(&self, id: OwnerId) -> Result<Option<PendingNative<'_>>, Error> {
        let slot = self.slot(id)?;
        if let Some(error) = slot.raw_failure {
            return Err(error);
        }
        if let Some(error) = slot.native_failure {
            return Err(Error::Endpoint(error));
        }
        let Some((identity, _)) = slot.native else {
            return Ok(None);
        };
        let body = slot.endpoint.pending().ok_or(Error::Invariant)?;
        Ok(Some(PendingNative {
            identity,
            bytes: body.bytes,
            deadline: slot.endpoint.pending_deadline().ok_or(Error::Invariant)?,
            early: body.early,
        }))
    }

    /// Consume the exact witness after a whole native write; a late failure is real.
    pub fn commit_native(&mut self, now: Duration, token: NativeToken) -> Result<(), Error> {
        if token.instance != self.instance
            || token.identity.incarnation != self.plan.config().incarnation
        {
            return Err(Error::Token);
        }
        let slot = self.slot_mut(token.identity.owner)?;
        if slot.native != Some((token.identity, token.serial)) {
            return Err(Error::Token);
        }
        slot.native = None;
        let completion = slot.endpoint.commit_delivery(now);
        if let Err(error) = completion {
            // Whole native acceptance cannot be undone. Keep this lane terminal
            // even if the nested endpoint did not latch an invalid clock.
            slot.native_failure = Some(error);
        }
        completion.map_err(Error::Endpoint)
    }

    /// Service one selected owner's original endpoint deadlines without new timers.
    pub fn tick(&mut self, id: OwnerId, now: Duration) -> Result<(), Error> {
        if self.plan.config().send_unreliable.is_some() {
            self.tick_unreliable(id, now)?;
        }
        self.slot_mut(id)?
            .endpoint
            .tick(now)
            .map_err(Error::Endpoint)
    }
    /// Finite-cohort union of actual independently actionable endpoint wakes.
    pub fn deadline(&self) -> Option<Duration> {
        self.slots
            .iter()
            .filter_map(|s| {
                s.endpoint
                    .deadline_independent()
                    .into_iter()
                    .chain(s.raw_send.map(|r| r.deadline))
                    .chain(s.raw_receive.map(|r| r.deadline))
                    .min()
            })
            .min()
    }
    /// Actual retained hard expiry only, never a retransmission or probe wake.
    pub fn expiry_deadline(&self) -> Option<Duration> {
        self.slots
            .iter()
            .filter_map(|s| {
                s.endpoint
                    .expiry_deadline()
                    .into_iter()
                    .chain(s.raw_send.map(|r| r.deadline))
                    .chain(s.raw_receive.map(|r| r.deadline))
                    .min()
            })
            .min()
    }
    /// Local owner/custody drain; not an authenticated peer fence or delivery claim.
    pub fn drained(&self) -> bool {
        self.slots.iter().all(|s| {
            s.native_failure.is_none()
                && s.raw_failure.is_none()
                && s.raw_send.is_none()
                && s.raw_receive.is_none()
                && s.native.is_none()
                && s.endpoint.drained()
        })
    }
    /// Actual fixed/vector/nested capacities observed at construction.
    pub const fn storage_usage(&self) -> storage::Usage {
        self.usage
    }
}

#[cfg(test)]
#[path = "connection_records/tests.rs"]
mod tests;
