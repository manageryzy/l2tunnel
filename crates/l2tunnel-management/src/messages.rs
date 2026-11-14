//! Bounded whole-message custody over the existing authenticated control ARQ.
//!
//! This owner does not authenticate packets or dispatch transaction semantics.
//! A caller accepts a held message only after its actual syntax, binding and
//! semantic dispatcher have accepted the exact bytes. That receipt is not an
//! assertion that a transaction has applied. Each instance is one independently
//! bound ordered stream; liveness must not share its transaction head-of-line.

use crate::{Ingress, Role, delivery};
use l2tunnel_codec::{
    FRAGMENT_HEADER_BYTES, FragmentBatch, FragmentConfig, FragmentContext, FragmentError,
    Fragmenter, MessageId, Reassembler, ReassemblyConfig, ReassemblyStatus,
};
use l2tunnel_core::Epoch;
use l2tunnel_recovery::{ACK_PACKET_BYTES, DATA_HEADER_BYTES, RecoveryError};
use ring::digest::{Context, SHA256};
use std::{
    collections::{BTreeMap, VecDeque},
    fmt,
    time::Duration,
};

/// Opaque-source discriminator for an unchanged LXv1 fragment.
pub const FRAGMENT_KIND: u8 = 1;
/// Opaque-source discriminator for a whole-message acceptance receipt.
pub const ACCEPTED_KIND: u8 = 2;
/// Kind, message ID, complete byte length and SHA-256 digest.
pub const ACCEPTED_BYTES: usize = 45;

/// Local idempotency identity, distinct from wire message and ARQ source IDs.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct SubmissionId(pub u64);

/// Immutable bounded contract for one whole-message stream.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Settings {
    /// Existing reliable control settings; overhead includes every outer wrapper.
    pub delivery: delivery::Settings,
    /// Complete IP packet ceiling, including the supplied delivery overhead.
    pub path_mtu: usize,
    /// Largest complete nonempty message, at most 65,536 bytes.
    pub max_message_bytes: usize,
    /// Retained outbound entries, including confirmed retry metadata, within 1..=64.
    pub max_outbound_messages: usize,
    /// Original plus encoded fragment payload retention, at most 16 MiB.
    pub max_outbound_bytes: usize,
    /// Largest canonical fragment count for one message.
    pub max_fragments: u16,
    /// Incomplete payload reservation plus one full-size completion buffer.
    pub max_reassembly_bytes: usize,
    /// Concurrent incomplete messages, within 1..=64.
    pub max_incomplete_messages: usize,
    /// Lifetime from first ordered fragment delivery into reassembly.
    /// Local original deadlines may be shorter and include all transport waiting.
    pub message_lifetime: Duration,
    /// Maximum source delivery, submission and confirmation actions per call.
    pub work_per_call: usize,
}

/// Exact whole-message identity; fields cannot be forged by an API caller.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Ticket {
    binding: delivery::Binding,
    submission: SubmissionId,
    message: u64,
    length: usize,
    digest: [u8; 32],
    received: bool,
}
impl Ticket {
    /// Local retry key; a received delivery uses the reserved zero marker.
    pub fn submission(self) -> SubmissionId {
        self.submission
    }
    /// Nonwrapping wire identity in this direction and fixed stream context.
    pub fn message(self) -> u64 {
        self.message
    }
    /// Exact original message length.
    pub fn length(self) -> usize {
        self.length
    }
    /// SHA-256 of the exact complete bytes, not an authentication credential.
    pub fn digest(self) -> [u8; 32] {
        self.digest
    }

    /// Actual immutable owner context, for crate-internal custody verification.
    pub(crate) fn binding(self) -> delivery::Binding {
        self.binding
    }
}

/// Borrowed evidence that the exact complete incoming message was accepted and
/// its complete-message receipt is retained by this owner. This is not Applied.
pub struct Accepted<'a> {
    ticket: Ticket,
    owner: &'a Owner,
}

impl Accepted<'_> {
    /// Exact private identity, not a caller-constructed completion assertion.
    pub(crate) fn ticket(&self) -> Ticket {
        self.ticket
    }

    /// The injected observation that created the retained acceptance receipt.
    pub(crate) fn observed_at(&self) -> Duration {
        self.owner.last_now
    }
}

/// Borrowed evidence of exact whole-message acceptance plus all source ACKs.
/// It cannot outlive, mutate or retire its actual confirmation owner.
pub struct Confirmed<'a> {
    ticket: Ticket,
    owner: &'a Owner,
}

impl Confirmed<'_> {
    /// Exact private identity, not a caller-constructed completion assertion.
    pub(crate) fn ticket(&self) -> Ticket {
        self.ticket
    }

    /// Injected observation at which whole-message confirmation was checked.
    pub(crate) fn observed_at(&self) -> Duration {
        self.owner.last_now
    }
}

/// A completed message borrowed until explicit semantic acceptance.
#[derive(Clone, Copy, Debug)]
pub struct Delivery<'a> {
    ticket: Ticket,
    bytes: &'a [u8],
    deadline: Duration,
}
impl<'a> Delivery<'a> {
    /// Opaque identity required by `Owner::accept`.
    pub fn ticket(self) -> Ticket {
        self.ticket
    }
    /// Exact complete message; never a padded or truncated prefix.
    pub fn bytes(self) -> &'a [u8] {
        self.bytes
    }
    /// Expiry from first ordered fragment delivery, unchanged by duplicates or holds.
    pub fn deadline(self) -> Duration {
        self.deadline
    }
}

/// Current payload and bounded ledger retention; no counter is authority.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Retained {
    /// Outbound entries including confirmed retry metadata.
    pub outbound_messages: usize,
    /// Retained original outbound payload bytes.
    pub outbound_bytes: usize,
    /// Retained complete LX fragment batches, excluding ARQ copies.
    pub outbound_fragment_bytes: usize,
    /// Incomplete incoming messages retained by the existing reassembler.
    pub incomplete_messages: usize,
    /// Incomplete payload reservations plus the full completion buffer.
    pub reassembly_bytes: usize,
    /// Valid complete bytes currently held for semantic dispatch.
    pub held_bytes: usize,
    /// Fixed source staging buffer, separate from original, LX and ARQ copies.
    pub source_scratch_bytes: usize,
    /// Independent existing ARQ payload retention.
    pub recovery: l2tunnel_recovery::Retained,
}

/// Explicit configuration, admission, custody or terminal lifecycle failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// Inconsistent settings or an invalid immutable binding.
    Settings,
    /// Bounded admission is full; retry without replacing the owner.
    Backpressure,
    /// New local IDs must be positive and strictly increasing; retired IDs stay retired.
    SubmissionOrder,
    /// An existing local retry key was supplied with different bytes or deadline.
    ChangedSubmission,
    /// This owner does not own the supplied ticket.
    UnknownTicket,
    /// Only an actually confirmed outbound entry may be explicitly retired.
    NotConfirmed,
    /// An original session, message or incomplete-message deadline expired.
    Expired,
    /// Injected time moved backwards.
    NonMonotonicTime,
    /// Exact relative nanoseconds or a checked deadline cannot be represented.
    TimeOverflow,
    /// Authenticated source grammar or an acceptance identity was inconsistent.
    Protocol,
    /// Existing reliable delivery rejected the operation.
    Delivery(delivery::Error),
    /// Existing fragmentation or reassembly rejected the operation.
    Fragment(FragmentError),
}
impl fmt::Display for Error {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(output, "whole-message control error: {self:?}")
    }
}
impl std::error::Error for Error {}

struct Outbound {
    ticket: Ticket,
    deadline: Duration,
    bytes: Vec<u8>,
    batch: FragmentBatch,
    next_fragment: usize,
    sources: VecDeque<u64>,
    accepted: bool,
    confirmed: bool,
}
struct Held {
    ticket: Ticket,
    deadline: Duration,
}

/// Pure bounded composition of existing fragmentation, reassembly and ARQ owners.
///
/// `receive` requires already authenticated exact management bytes. The full
/// 128-bit delivery binding remains authority; the derived LX64 context is only
/// a redundant discriminator. Poll outputs remain caller-owned until physical
/// handoff or explicit terminal failure. No emitted attempt proves acceptance.
pub struct Owner {
    settings: Settings,
    binding: delivery::Binding,
    service: delivery::Service,
    fragmenter: Fragmenter,
    reassembler: Reassembler,
    origin: Duration,
    last_now: Duration,
    expires: Duration,
    failed: Option<Error>,
    last_submission: u64,
    outbound: VecDeque<Outbound>,
    outbound_bytes: usize,
    fragment_bytes: usize,
    source_scratch: Vec<u8>,
    complete: Vec<u8>,
    held: Option<Held>,
    arrivals: BTreeMap<MessageId, Duration>,
    phase: u8,
    confirmation_cursor: usize,
    idle_actions: usize,
}

/// ARQ-only construction failure, preserving existing whole-message errors.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReservedArqError {
    /// Existing message, fragment or delivery validation failed.
    Message(Error),
    /// Actual recovery backing could not be planned or provisioned.
    Storage(l2tunnel_recovery::storage::Error),
}
impl fmt::Display for ReservedArqError {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(output, "reserved message ARQ error: {self:?}")
    }
}
impl std::error::Error for ReservedArqError {}

struct Validated {
    fragmenter: Fragmenter,
    reassembler: Reassembler,
}
impl Settings {
    /// Allocation-free validation; this does not reserve message or ARQ backing.
    pub fn validate(
        self,
        binding: delivery::Binding,
        now: Duration,
        expires: Duration,
    ) -> Result<(), Error> {
        validate_settings(self, binding, now, expires).map(|_| ())
    }
}
fn validate_settings(
    settings: Settings,
    binding: delivery::Binding,
    now: Duration,
    expires: Duration,
) -> Result<Validated, Error> {
    let maximum = settings.delivery.recovery.max_source_bytes;
    let source_charge = DATA_HEADER_BYTES
        .checked_add(maximum)
        .and_then(|size| size.checked_add(settings.delivery.wire_overhead))
        .ok_or(Error::Settings)?;
    let ack_charge = ACK_PACKET_BYTES
        .checked_add(settings.delivery.wire_overhead)
        .ok_or(Error::Settings)?;
    let incomplete_bytes = settings
        .max_reassembly_bytes
        .checked_sub(settings.max_message_bytes)
        .ok_or(Error::Settings)?;
    let lifetime =
        u64::try_from(settings.message_lifetime.as_nanos()).map_err(|_| Error::Settings)?;
    if !(1..=65_536).contains(&settings.max_message_bytes)
        || !(1..=64).contains(&settings.max_outbound_messages)
        || !(1..=64).contains(&settings.max_incomplete_messages)
        || !(1..=4096).contains(&settings.work_per_call)
        || settings.max_outbound_bytes == 0
        || settings.max_outbound_bytes > 16 * 1024 * 1024
        || settings.max_reassembly_bytes > 16 * 1024 * 1024
        || incomplete_bytes < settings.max_message_bytes
        || settings.max_fragments == 0
        || lifetime == 0
        || maximum < ACCEPTED_BYTES
        || settings.delivery.recovery.send_records < 2
        || settings.delivery.recovery.send_bytes
            < maximum.checked_add(ACCEPTED_BYTES).ok_or(Error::Settings)?
        || settings.path_mtu > 65_535
        || source_charge > settings.path_mtu
        || ack_charge > settings.path_mtu
    {
        return Err(Error::Settings);
    }
    now.checked_add(settings.message_lifetime)
        .ok_or(Error::Settings)?;
    let outer = settings
        .delivery
        .wire_overhead
        .checked_add(DATA_HEADER_BYTES)
        .and_then(|size| size.checked_add(1))
        .ok_or(Error::Settings)?;
    // The configured source cap, rather than spare path MTU, fixes chunk size.
    let fragmenter = Fragmenter::new(
        context(binding, binding.local_role),
        FragmentConfig {
            path_mtu: source_charge,
            outer_overhead_bytes: outer,
            max_message_bytes: settings.max_message_bytes,
            max_fragments: settings.max_fragments,
        },
        MessageId(1),
    )
    .map_err(Error::Fragment)?;
    let max_total_fragments = usize::from(settings.max_fragments)
        .checked_mul(settings.max_incomplete_messages)
        .ok_or(Error::Settings)?;
    let reassembler = Reassembler::new(
        context(
            binding,
            match binding.local_role {
                Role::Client => Role::Server,
                Role::Server => Role::Client,
            },
        ),
        ReassemblyConfig {
            max_message_bytes: settings.max_message_bytes,
            max_messages: settings.max_incomplete_messages,
            max_fragment_payload_bytes: u16::try_from(fragmenter.chunk_bytes())
                .map_err(|_| Error::Settings)?,
            max_fragments_per_message: settings.max_fragments,
            max_total_fragments,
            max_reserved_bytes: incomplete_bytes,
            max_lifetime_ticks: lifetime,
            replay_window: 65_536,
        },
    )
    .map_err(Error::Fragment)?;
    settings
        .delivery
        .validate(binding, now, expires)
        .map_err(Error::Delivery)?;
    Ok(Validated {
        fragmenter,
        reassembler,
    })
}

impl Owner {
    /// Validate all immutable physical, memory, window and exact time bounds.
    pub fn new(
        settings: Settings,
        binding: delivery::Binding,
        now: Duration,
        expires: Duration,
    ) -> Result<Self, Error> {
        let validated = validate_settings(settings, binding, now, expires)?;
        let service = delivery::Service::new(settings.delivery, binding, now, expires)
            .map_err(Error::Delivery)?;
        Ok(Self::from_validated(
            settings, binding, now, expires, validated, service,
        ))
    }

    /// Reserve actual ARQ backing only; message/fragment storage remains separate.
    pub fn new_reserved_arq(
        settings: Settings,
        binding: delivery::Binding,
        now: Duration,
        expires: Duration,
        limits: l2tunnel_recovery::storage::Limits,
    ) -> Result<Self, ReservedArqError> {
        let validated = validate_settings(settings, binding, now, expires)
            .map_err(ReservedArqError::Message)?;
        let service =
            delivery::Service::new_reserved_arq(settings.delivery, binding, now, expires, limits)
                .map_err(|error| match error {
                delivery::ReservedArqError::Service(error) => {
                    ReservedArqError::Message(Error::Delivery(error))
                }
                delivery::ReservedArqError::Storage(error) => ReservedArqError::Storage(error),
            })?;
        Ok(Self::from_validated(
            settings, binding, now, expires, validated, service,
        ))
    }

    /// Actual retained recovery backing; not a complete message-owner budget.
    pub fn arq_storage_usage(&self) -> Option<l2tunnel_recovery::storage::Usage> {
        self.service.arq_storage_usage()
    }

    fn from_validated(
        settings: Settings,
        binding: delivery::Binding,
        now: Duration,
        expires: Duration,
        validated: Validated,
        service: delivery::Service,
    ) -> Self {
        Self {
            settings,
            binding,
            service,
            fragmenter: validated.fragmenter,
            reassembler: validated.reassembler,
            origin: now,
            last_now: now,
            expires,
            failed: None,
            last_submission: 0,
            outbound: VecDeque::new(),
            outbound_bytes: 0,
            fragment_bytes: 0,
            source_scratch: vec![0; settings.delivery.recovery.max_source_bytes],
            complete: vec![0; settings.max_message_bytes],
            held: None,
            arrivals: BTreeMap::new(),
            phase: 0,
            confirmation_cursor: 0,
            idle_actions: 0,
        }
    }

    /// Retain exact bytes before assigning a wire ID; identical live retries reuse it.
    /// Confirmed entries remain retryable until `retire` releases their metadata.
    pub fn submit(
        &mut self,
        id: SubmissionId,
        bytes: &[u8],
        now: Duration,
        original_deadline: Duration,
    ) -> Result<Ticket, Error> {
        self.observe(now)?;
        if bytes.is_empty() {
            return Err(Error::Fragment(FragmentError::EmptyMessage));
        }
        if bytes.len() > self.settings.max_message_bytes {
            return Err(Error::Fragment(FragmentError::MessageTooLarge));
        }
        let digest = sha256(bytes);
        if let Some(entry) = self
            .outbound
            .iter()
            .find(|entry| entry.ticket.submission == id)
        {
            return if entry.deadline == original_deadline
                && entry.ticket.length == bytes.len()
                && entry.ticket.digest == digest
                && (entry.confirmed || entry.bytes == bytes)
            {
                Ok(entry.ticket)
            } else {
                Err(Error::ChangedSubmission)
            };
        }
        if id.0 == 0 || id.0 <= self.last_submission {
            return Err(Error::SubmissionOrder);
        }
        let latest = now
            .checked_add(self.settings.message_lifetime)
            .ok_or(Error::TimeOverflow)?;
        if original_deadline <= now
            || original_deadline > latest
            || original_deadline > self.expires
        {
            return Err(Error::Expired);
        }
        let count = bytes.len().div_ceil(self.fragmenter.chunk_bytes());
        if count > usize::from(self.settings.max_fragments) {
            return Err(Error::Fragment(FragmentError::TooManyFragments));
        }
        let batch_bytes = count
            .checked_mul(FRAGMENT_HEADER_BYTES)
            .and_then(|size| size.checked_add(bytes.len()))
            .ok_or(Error::TimeOverflow)?;
        let retained = self
            .outbound_bytes
            .checked_add(self.fragment_bytes)
            .and_then(|size| size.checked_add(bytes.len()))
            .and_then(|size| size.checked_add(batch_bytes))
            .ok_or(Error::Backpressure)?;
        if self.outbound.len() >= self.settings.max_outbound_messages
            || retained > self.settings.max_outbound_bytes
        {
            return Err(Error::Backpressure);
        }
        let batch = self.fragmenter.fragment(bytes).map_err(Error::Fragment)?;
        let ticket = Ticket {
            binding: self.binding,
            submission: id,
            message: batch.message.0,
            length: bytes.len(),
            digest,
            received: false,
        };
        self.outbound_bytes += bytes.len();
        self.fragment_bytes += batch_bytes;
        self.last_submission = id.0;
        self.outbound.push_back(Outbound {
            ticket,
            deadline: original_deadline,
            bytes: bytes.to_vec(),
            batch,
            next_fragment: 0,
            sources: VecDeque::new(),
            accepted: false,
            confirmed: false,
        });
        self.idle_actions = 0;
        Ok(ticket)
    }

    /// Admit an already authenticated exact ARQ packet, then perform bounded work.
    pub fn receive(
        &mut self,
        verified: Ingress,
        packet: &[u8],
        now: Duration,
    ) -> Result<(), Error> {
        self.observe(now)?;
        if let Err(error) = self.service.receive(verified, packet, now) {
            return self.delivery_error(error);
        }
        self.idle_actions = 0;
        self.work(now)
    }

    /// Emit one charged existing ARQ attempt; insufficient caller output is recoverable.
    pub fn poll(
        &mut self,
        now: Duration,
        shared_wire_allowance: usize,
        output: &mut [u8],
    ) -> Result<Option<delivery::Emission>, Error> {
        self.observe(now)?;
        if output.len() < self.max_packet_bytes() {
            return Err(Error::Delivery(delivery::Error::OutputTooSmall));
        }
        self.work(now)?;
        match self.service.poll(now, shared_wire_allowance, output) {
            Ok(result) => Ok(result),
            Err(error) => self.delivery_error(error),
        }
    }

    /// Observe original expiry and advance only the configured finite work budget.
    pub fn tick(&mut self, now: Duration) -> Result<(), Error> {
        self.observe(now)?;
        self.work(now)
    }

    /// Borrow the same complete bytes until their exact ticket is accepted.
    pub fn pending(&self) -> Option<Delivery<'_>> {
        self.held.as_ref().map(|held| Delivery {
            ticket: held.ticket,
            bytes: &self.complete[..held.ticket.length],
            deadline: held.deadline,
        })
    }

    /// Transfer semantic custody and retain its receipt in existing reliable ARQ.
    /// Backpressure preserves the held complete message without extending expiry.
    pub fn accept(&mut self, ticket: Ticket, now: Duration) -> Result<(), Error> {
        self.observe(now)?;
        if self.held.as_ref().is_none_or(|held| held.ticket != ticket) {
            return Err(Error::UnknownTicket);
        }
        let receipt = accepted(ticket)?;
        match self.service.submit(&receipt, now) {
            Ok(_) => {
                self.held = None;
                self.idle_actions = 0;
                Ok(())
            }
            Err(error) if capacity(error) => Err(Error::Backpressure),
            Err(error) => self.delivery_error(error),
        }
    }

    /// Accept exact held custody and borrow proof that its receipt is retained.
    /// Dispatch semantics before this call; on backpressure retry acceptance
    /// without dispatching again. The proof grants no transaction effects.
    pub fn accept_with_receipt(
        &mut self,
        ticket: Ticket,
        now: Duration,
    ) -> Result<Accepted<'_>, Error> {
        self.accept(ticket, now)?;
        Ok(Accepted {
            ticket,
            owner: self,
        })
    }

    /// True only after matching semantic acceptance and every fragment source ACK.
    pub fn confirmed(&mut self, ticket: Ticket, now: Duration) -> Result<bool, Error> {
        self.observe(now)?;
        self.work(now)?;
        self.outbound
            .iter()
            .find(|entry| entry.ticket == ticket)
            .map(|entry| entry.confirmed)
            .ok_or(Error::UnknownTicket)
    }

    /// Borrow actual complete-message confirmation without retiring retry state.
    /// A source ACK or a locally emitted receipt cannot create this proof.
    pub fn confirmation(
        &mut self,
        ticket: Ticket,
        now: Duration,
    ) -> Result<Option<Confirmed<'_>>, Error> {
        Ok(self.confirmed(ticket, now)?.then_some(Confirmed {
            ticket,
            owner: self,
        }))
    }

    /// Release confirmed retry metadata; a retired submission ID cannot be reused.
    pub fn retire(&mut self, ticket: Ticket, now: Duration) -> Result<(), Error> {
        self.observe(now)?;
        let index = self
            .outbound
            .iter()
            .position(|entry| entry.ticket == ticket)
            .ok_or(Error::UnknownTicket)?;
        if !self
            .outbound
            .get(index)
            .is_some_and(|entry| entry.confirmed)
        {
            return Err(Error::NotConfirmed);
        }
        self.outbound.remove(index);
        Ok(())
    }

    /// Earliest original message, reassembly, held-custody or existing ARQ wake.
    /// A changed shared allowance or newly available semantic consumer is another trigger.
    pub fn deadline(&self) -> Duration {
        if self.failed.is_some() {
            return self.last_now;
        }
        // A bounded scan finishes internal work even when work_per_call is one.
        // After a full idle rotation no immediate wake remains until new input,
        // local submission, acceptance or the existing ARQ timer changes state.
        if self.idle_actions < self.idle_limit() {
            return self.last_now;
        }
        self.expiry().min(self.service.deadline())
    }

    /// Earliest immutable session/message/assembly expiry, independent of work
    /// readiness and ARQ retries. A shared scheduler must not delay this bound
    /// merely because its emission quota cannot refill yet.
    pub fn expiry(&self) -> Duration {
        if self.failed.is_some() {
            return self.last_now;
        }
        let partial = self
            .reassembler
            .deadline()
            .and_then(|ticks| self.origin.checked_add(Duration::from_nanos(ticks)));
        self.outbound
            .iter()
            .filter(|entry| !entry.confirmed)
            .map(|entry| entry.deadline)
            .chain(self.held.iter().map(|held| held.deadline))
            .chain(partial)
            .chain([self.expires])
            .min()
            .unwrap_or(self.expires)
    }

    /// Earliest internal-work, expiry or ARQ wake fitting an unchanged outer
    /// byte allowance. Its refill is a separate trigger owned by the scheduler.
    pub fn deadline_with_allowance(&self, allowance: usize) -> Duration {
        if self.failed.is_some() || self.idle_actions < self.idle_limit() {
            return self.last_now;
        }
        self.expiry()
            .min(self.service.deadline_with_allowance(allowance))
    }

    /// Current bounded payload retention, including the reserved completion slot.
    pub fn retained(&self) -> Retained {
        Retained {
            outbound_messages: self.outbound.len(),
            outbound_bytes: self.outbound_bytes,
            outbound_fragment_bytes: self.fragment_bytes,
            incomplete_messages: self.reassembler.pending_messages(),
            reassembly_bytes: self.reassembler.reserved_bytes() + self.complete.len(),
            held_bytes: self.held.as_ref().map_or(0, |held| held.ticket.length),
            source_scratch_bytes: self.source_scratch.len(),
            recovery: self.service.retained(),
        }
    }
    /// Existing charged emission counters; these do not prove physical sends.
    pub fn statistics(&self) -> delivery::Statistics {
        self.service.statistics()
    }
    /// Required ARQ output capacity, excluding caller-owned outer wrappers.
    pub fn max_packet_bytes(&self) -> usize {
        (DATA_HEADER_BYTES + self.settings.delivery.recovery.max_source_bytes).max(ACK_PACKET_BYTES)
    }

    /// Check actual time and immutable expiry without work or state mutation.
    /// This advisory view neither accepts a message nor renews any original cap.
    pub fn check_time(&self, now: Duration) -> Result<(), Error> {
        if let Some(error) = self.failed {
            return Err(error);
        }
        if now < self.last_now {
            return Err(Error::NonMonotonicTime);
        }
        let relative = now
            .checked_sub(self.origin)
            .ok_or(Error::NonMonotonicTime)?;
        u64::try_from(relative.as_nanos()).map_err(|_| Error::TimeOverflow)?;
        if now >= self.expiry() {
            return Err(Error::Expired);
        }
        Ok(())
    }

    fn observe(&mut self, now: Duration) -> Result<(), Error> {
        if let Some(error) = self.failed {
            return Err(error);
        }
        if now < self.last_now {
            return self.fail(Error::NonMonotonicTime);
        }
        if now >= self.expires
            || self
                .outbound
                .iter()
                .any(|entry| !entry.confirmed && now >= entry.deadline)
            || self.held.as_ref().is_some_and(|held| now >= held.deadline)
        {
            return self.fail(Error::Expired);
        }
        let ticks = self.ticks(now)?;
        match self.reassembler.expire(ticks) {
            Ok(expired) if expired.is_empty() => {}
            Ok(_) => return self.fail(Error::Expired),
            Err(error) => return self.fail(Error::Fragment(error)),
        }
        self.last_now = now;
        Ok(())
    }
    fn ticks(&mut self, now: Duration) -> Result<u64, Error> {
        let Some(relative) = now.checked_sub(self.origin) else {
            return self.fail(Error::NonMonotonicTime);
        };
        match u64::try_from(relative.as_nanos()) {
            Ok(value) => Ok(value),
            Err(_) => self.fail(Error::TimeOverflow),
        }
    }
    fn work(&mut self, now: Duration) -> Result<(), Error> {
        for _ in 0..self.settings.work_per_call {
            let phase = self.phase;
            self.phase = (self.phase + 1) % 3;
            let progressed = match phase {
                0 => self.deliver_one(now)?,
                1 => self.submit_one(now)?,
                _ => self.confirm_one(now)?,
            };
            if progressed {
                self.idle_actions = 0;
            } else {
                self.idle_actions = self.idle_actions.saturating_add(1);
            }
        }
        Ok(())
    }
    fn idle_limit(&self) -> usize {
        3 * self.outbound.len().max(1)
    }
    fn deliver_one(&mut self, now: Duration) -> Result<bool, Error> {
        if self.held.is_some() {
            return Ok(false);
        }
        let length = match self.service.deliver(&mut self.source_scratch, now) {
            Ok(Some((_, length))) => length,
            Ok(None) => return Ok(false),
            Err(error) => return self.delivery_error(error),
        };
        match self
            .source_scratch
            .get(..length)
            .and_then(|source| source.first())
            .copied()
        {
            Some(FRAGMENT_KIND) => {
                let ticks = self.ticks(now)?;
                let status = self.reassembler.accept(
                    &self.source_scratch[1..length],
                    ticks,
                    &mut self.complete,
                );
                match status {
                    Ok(
                        ReassemblyStatus::Pending {
                            message: MessageId(0),
                            ..
                        }
                        | ReassemblyStatus::Complete {
                            message: MessageId(0),
                            ..
                        }
                        | ReassemblyStatus::Duplicate {
                            message: MessageId(0),
                        },
                    ) => return self.fail(Error::Protocol),
                    Ok(ReassemblyStatus::Pending { message, .. }) => {
                        if let std::collections::btree_map::Entry::Vacant(entry) =
                            self.arrivals.entry(message)
                        {
                            let Some(deadline) = now.checked_add(self.settings.message_lifetime)
                            else {
                                return self.fail(Error::TimeOverflow);
                            };
                            entry.insert(deadline);
                        }
                    }
                    Ok(ReassemblyStatus::Complete { message, length }) => {
                        let deadline = match self.arrivals.remove(&message) {
                            Some(deadline) => deadline,
                            None => match now.checked_add(self.settings.message_lifetime) {
                                Some(deadline) => deadline,
                                None => return self.fail(Error::TimeOverflow),
                            },
                        }
                        .min(self.expires);
                        let ticket = Ticket {
                            binding: self.binding,
                            submission: SubmissionId(0),
                            message: message.0,
                            length,
                            digest: sha256(&self.complete[..length]),
                            received: true,
                        };
                        self.held = Some(Held { ticket, deadline });
                    }
                    Ok(ReassemblyStatus::Duplicate { .. }) => {}
                    Err(error) => return self.fail(Error::Fragment(error)),
                }
                Ok(true)
            }
            Some(ACCEPTED_KIND) if length == ACCEPTED_BYTES => {
                let source = &self.source_scratch[..length];
                let message =
                    u64::from_be_bytes(source[1..9].try_into().map_err(|_| Error::Protocol)?);
                let length =
                    u32::from_be_bytes(source[9..13].try_into().map_err(|_| Error::Protocol)?)
                        as usize;
                let digest: [u8; 32] = source[13..45].try_into().map_err(|_| Error::Protocol)?;
                let Some(index) = self
                    .outbound
                    .iter()
                    .position(|entry| entry.ticket.message == message)
                else {
                    return self.fail(Error::Protocol);
                };
                let Some(entry) = self.outbound.get_mut(index) else {
                    return self.fail(Error::Protocol);
                };
                if entry.ticket.length != length || entry.ticket.digest != digest {
                    return self.fail(Error::Protocol);
                }
                entry.accepted = true;
                self.finish(index);
                Ok(true)
            }
            _ => self.fail(Error::Protocol),
        }
    }
    fn submit_one(&mut self, now: Duration) -> Result<bool, Error> {
        let Some(index) = self.outbound.iter().position(|entry| {
            !entry.confirmed && entry.next_fragment < entry.batch.fragments.len()
        }) else {
            return Ok(false);
        };
        let Some(entry) = self.outbound.get(index) else {
            return self.fail(Error::Protocol);
        };
        let Some(fragment) = entry.batch.fragments.get(entry.next_fragment) else {
            return self.fail(Error::Protocol);
        };
        let length = fragment.len() + 1;
        let retained = self.service.retained();
        if retained.send_records + 1 >= self.settings.delivery.recovery.send_records
            || retained
                .send_bytes
                .checked_add(length)
                .and_then(|bytes| bytes.checked_add(ACCEPTED_BYTES))
                .is_none_or(|bytes| bytes > self.settings.delivery.recovery.send_bytes)
        {
            return Ok(false);
        }
        // Reuse the source scratch only between consuming an ordered source and this submission.
        self.source_scratch[0] = FRAGMENT_KIND;
        self.source_scratch[1..length].copy_from_slice(fragment);
        let source = match self.service.submit(&self.source_scratch[..length], now) {
            Ok(source) => source,
            Err(error) if capacity(error) => return Ok(false),
            Err(error) => return self.delivery_error(error),
        };
        if let Some(entry) = self.outbound.get_mut(index) {
            entry.next_fragment += 1;
            entry.sources.push_back(source);
        }
        Ok(true)
    }
    fn confirm_one(&mut self, now: Duration) -> Result<bool, Error> {
        if self.outbound.is_empty() {
            return Ok(false);
        }
        let index = self.confirmation_cursor % self.outbound.len();
        self.confirmation_cursor = (index + 1) % self.outbound.len();
        let source = self
            .outbound
            .get(index)
            .and_then(|entry| entry.sources.front())
            .copied();
        let mut progressed = false;
        if let Some(source) = source {
            match self.service.source_confirmed(source, now) {
                Ok(true) => {
                    if let Some(entry) = self.outbound.get_mut(index) {
                        entry.sources.pop_front();
                        progressed = true;
                    }
                }
                Ok(false) => {}
                Err(error) => return self.delivery_error(error),
            }
        }
        Ok(self.finish(index) || progressed)
    }
    fn finish(&mut self, index: usize) -> bool {
        if let Some(entry) = self.outbound.get_mut(index)
            && !entry.confirmed
            && entry.accepted
            && entry.sources.is_empty()
            && entry.next_fragment == entry.batch.fragments.len()
        {
            self.outbound_bytes -= entry.bytes.len();
            self.fragment_bytes -= entry.batch.fragments.iter().map(Vec::len).sum::<usize>();
            entry.bytes.clear();
            entry.bytes.shrink_to_fit();
            entry.batch.fragments.clear();
            entry.batch.fragments.shrink_to_fit();
            entry.confirmed = true;
            return true;
        }
        false
    }
    fn fail<T>(&mut self, error: Error) -> Result<T, Error> {
        self.failed = Some(error);
        Err(error)
    }
    fn delivery_error<T>(&mut self, error: delivery::Error) -> Result<T, Error> {
        let wrapped = Error::Delivery(error);
        match error {
            delivery::Error::Expired => self.fail(Error::Expired),
            delivery::Error::NonMonotonicTime => self.fail(Error::NonMonotonicTime),
            delivery::Error::Recovery(
                RecoveryError::RetryExhausted { .. }
                | RecoveryError::TimeOverflow
                | RecoveryError::CounterExhausted,
            ) => self.fail(wrapped),
            _ => Err(wrapped),
        }
    }
}

fn capacity(error: delivery::Error) -> bool {
    matches!(
        error,
        delivery::Error::Recovery(RecoveryError::Capacity(_) | RecoveryError::SequenceWindow)
    )
}
fn sha256(bytes: &[u8]) -> [u8; 32] {
    let mut result = [0; 32];
    result.copy_from_slice(ring::digest::digest(&SHA256, bytes).as_ref());
    result
}
fn context(binding: delivery::Binding, sender: Role) -> FragmentContext {
    let mut digest = Context::new(&SHA256);
    digest.update(b"l2tunnel-management-messages/LX64/v1\0");
    digest.update(&binding.session.0);
    digest.update(&binding.lane.0.to_be_bytes());
    digest.update(&binding.control_epoch.to_be_bytes());
    digest.update(&[sender as u8]);
    let finished = digest.finish();
    let mut session = [0; 8];
    session.copy_from_slice(&finished.as_ref()[..8]);
    FragmentContext {
        session: l2tunnel_codec::SessionId(u64::from_be_bytes(session)),
        epoch: Epoch(binding.control_epoch),
    }
}
fn accepted(ticket: Ticket) -> Result<[u8; ACCEPTED_BYTES], Error> {
    let mut receipt = [0; ACCEPTED_BYTES];
    receipt[0] = ACCEPTED_KIND;
    receipt[1..9].copy_from_slice(&ticket.message.to_be_bytes());
    receipt[9..13].copy_from_slice(
        &u32::try_from(ticket.length)
            .map_err(|_| Error::Protocol)?
            .to_be_bytes(),
    );
    receipt[13..45].copy_from_slice(&ticket.digest);
    Ok(receipt)
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod reserved_arq_tests;
