use crate::RecoveryEngine;
use std::collections::BTreeMap;
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

mod backing;
mod compact;
pub(crate) use backing::{ReceiveSlot, SendSlot};
use backing::{Received, Sent};
pub use compact::{
    COMPACT_DATA_HEADER_BYTES, COMPACT_FEEDBACK_HEADER_BYTES, CompactArqConfig, CompactBounds,
    CompactFeedback, CompactPacketView, CompactRecovery, CompactRepeat, CompactTiming,
    CompactTimingSnapshot, inspect_compact_packet,
};
pub(crate) use compact::{History as CompactHistory, Meta as CompactMeta, State as CompactState};

/// Bytes preceding one source payload in the draft authenticated inner encoding.
pub const DATA_HEADER_BYTES: usize = 44;
/// Exact byte size of the bounded cumulative/bitmap ACK packet.
pub const ACK_PACKET_BYTES: usize = 48;
const COMMON_HEADER_BYTES: usize = 32;
const WINDOW_LIMIT: usize = 64;

// Local custody only; never serialized, authenticated or used as a nonce.
static NEXT_PHYSICAL_OWNER: AtomicU64 = AtomicU64::new(1);

/// Independent endpoint role; accepting reflected local packets is forbidden.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EndpointRole {
    /// Session initiator, encoded as zero.
    Initiator,
    /// Session responder, encoded as one.
    Responder,
}

impl EndpointRole {
    fn code(self) -> u8 {
        match self {
            Self::Initiator => 0,
            Self::Responder => 1,
        }
    }
}

/// Binding checked after the caller authenticates an incoming complete packet.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecoveryContext {
    /// Authenticated session identity.
    pub session: u128,
    /// Negotiated configuration epoch; old engine state must be drained separately.
    pub epoch: u64,
    /// Local role; peer packets must carry the opposite role.
    pub role: EndpointRole,
}

/// Nonwrapping source identity in one sending direction.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct SourceId(pub u64);

/// Finite source, retention and retry budgets for one bidirectional engine.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ArqConfig {
    /// Largest admitted or received source payload; at most 65,535 bytes.
    pub max_source_bytes: usize,
    /// Maximum retained send-payload bytes, independent of source count.
    pub send_bytes: usize,
    /// Maximum retained receive-payload bytes, including pending application delivery.
    pub receive_bytes: usize,
    /// Maximum unconfirmed source count and source-ID span, in 1..=64.
    pub send_records: usize,
    /// Maximum retained source count and receive-ID window, in 1..=64.
    pub receive_records: usize,
    /// Timeout from the first transmission to its first retry.
    pub initial_rto: Duration,
    /// Maximum exponentially backed-off retry timeout.
    pub maximum_rto: Duration,
    /// Maximum delay before emitting pending receipt feedback.
    pub ack_delay: Duration,
    /// Maximum retransmissions after the initial attempt; zero is permitted.
    pub max_retries: u16,
}

impl Default for ArqConfig {
    fn default() -> Self {
        Self {
            max_source_bytes: 1_200,
            send_bytes: 76_800,
            receive_bytes: 76_800,
            send_records: 64,
            receive_records: 64,
            initial_rto: Duration::from_millis(200),
            maximum_rto: Duration::from_secs(3),
            ack_delay: Duration::from_millis(5),
            max_retries: 8,
        }
    }
}

impl ArqConfig {
    /// Validate existing payload, retention, sequence-window and timing bounds.
    /// This pure check reserves no backing and grants no authentication authority.
    pub fn validate(self) -> Result<(), RecoveryError> {
        if !(1..=65_535).contains(&self.max_source_bytes)
            || self.send_bytes < self.max_source_bytes
            || self.receive_bytes < self.max_source_bytes
            || !(1..=WINDOW_LIMIT).contains(&self.send_records)
            || !(1..=WINDOW_LIMIT).contains(&self.receive_records)
            || self.initial_rto.is_zero()
            || self.maximum_rto < self.initial_rto
            || self.ack_delay > self.initial_rto
        {
            return Err(RecoveryError::InvalidConfig);
        }
        Ok(())
    }
}

/// Which owned payload buffer requires backpressure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BufferSide {
    /// Outbound sources waiting for transmission or confirmation.
    Send,
    /// Inbound sources waiting for earlier gaps or application delivery.
    Receive,
}

/// Explicit errors; retry exhaustion and invalid physical completion time are terminal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecoveryError {
    /// Invalid local timing, window or memory configuration.
    InvalidConfig,
    /// Packet is truncated, has trailing bytes or violates the draft encoding.
    MalformedPacket,
    /// Peer role, session or epoch does not match this engine.
    WrongContext,
    /// Carrier-only and selective-repeat profiles cannot be silently mixed.
    WrongProfile,
    /// Source exceeds the configured payload-size cap.
    SourceTooLarge,
    /// A byte/count payload budget is full; retry admission after draining.
    Capacity(BufferSide),
    /// Source-ID distance exceeds the bounded send/receive reorder window.
    SequenceWindow,
    /// Carrier-only received a new source out of reliable-stream order.
    UnexpectedSequence,
    /// Same retained source identity was supplied with different payload bytes.
    ConflictingDuplicate,
    /// ACK claims a source not yet submitted or transmitted.
    UnsentAcknowledgement,
    /// Caller output capacity is insufficient; queued work remains unchanged.
    OutputTooSmall {
        /// Exact required output size.
        required: usize,
    },
    /// Injected time moved backwards.
    NonMonotonicTime,
    /// Computing a future deadline exceeded Duration's representable range.
    TimeOverflow,
    /// A source ID or checked byte counter would overflow.
    CounterExhausted,
    /// Physical confirmation is foreign, repeated or does not match the held attempt.
    InvalidTransmission,
    /// Explicit selected transmission-history budget has no free unsampled slot.
    HistoryCapacity,
    /// Selected fallible backing allocation failed.
    Allocation,
    /// Preserve this exact feedback and original arrival until its local receipt is observed.
    FeedbackAwaitingPhysical,
    /// The source's finite retry budget expired without confirmation.
    RetryExhausted {
        /// Source whose final retry deadline expired.
        source: SourceId,
    },
}

impl fmt::Display for RecoveryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for RecoveryError {}

/// Saturating diagnostics only; counters never decide protocol behavior.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Statistics {
    /// Unique sources admitted locally.
    pub submitted: u64,
    /// Source packet emissions, including retries.
    pub transmissions: u64,
    /// Source retransmissions after their initial packet emission.
    pub retransmissions: u64,
    /// Recovery ACK packets emitted.
    pub feedback_sent: u64,
    /// Valid recovery ACK packets consumed, including repeated ACKs.
    pub feedback_received: u64,
    /// Unique received sources stored from packet bytes.
    pub received_unique: u64,
    /// Duplicate data packets ignored without redelivery.
    pub duplicates: u64,
    /// Sources copied to application delivery buffers.
    pub delivered: u64,
    /// Full source and feedback packet bytes emitted, before outer protection.
    pub wire_bytes_emitted: u64,
}

/// Current owned payload retention, excluding fixed-size metadata.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Retained {
    /// Unconfirmed/unhanded-off outbound source count.
    pub send_records: usize,
    /// Retained outbound payload bytes.
    pub send_bytes: usize,
    /// Undelivered inbound source count.
    pub receive_records: usize,
    /// Retained inbound payload bytes.
    pub receive_bytes: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Profile {
    Selective,
    CarrierOnly,
}

impl Profile {
    fn code(self) -> u8 {
        match self {
            Self::Selective => 1,
            Self::CarrierOnly => 2,
        }
    }
}

#[derive(Debug)]
struct Flight {
    prepared_at: Duration,
    transmission: u64,
    acknowledged: bool,
    payload: Vec<u8>,
    attempts: u32,
    retry_at: Option<Duration>,
    rto: Duration,
}

#[derive(Debug)]
struct Engine {
    config: ArqConfig,
    receive_config: ArqConfig,
    context: RecoveryContext,
    profile: Profile,
    sent: Sent,
    received: Received,
    physical_confirmation: bool,
    physical_instance: u64,
    next_transmission: u64,
    pending_transmissions: usize,
    storage_usage: Option<crate::storage::Usage>,
    compact: compact::Cell,
    next_source: u64,
    receive_prefix: u64,
    deliver_next: u64,
    send_bytes: usize,
    receive_bytes: usize,
    ack_at: Option<Duration>,
    prefer_data: bool,
    // Fair source service is separate from the existing ACK/data alternation.
    prefer_retry: bool,
    last_now: Duration,
    failure: Option<RecoveryError>,
    statistics: Statistics,
}

/// Actual-payload selective-repeat ARQ for an authenticated datagram carrier.
/// This baseline has bounded selective ACKs and timeout recovery, not Python
/// wire parity, FEC, fast retransmit, a clock or a congestion controller.
///
/// ```
/// use l2tunnel_recovery::{
///     ArqConfig, EndpointRole, RecoveryContext, RecoveryEngine, SelectiveRepeat,
/// };
/// use std::time::Duration;
/// # fn main() -> Result<(), l2tunnel_recovery::RecoveryError> {
/// let context = RecoveryContext { session: 1, epoch: 0, role: EndpointRole::Initiator };
/// let mut sender = SelectiveRepeat::new(ArqConfig::default(), context)?;
/// let mut receiver = SelectiveRepeat::new(
///     ArqConfig::default(), RecoveryContext { role: EndpointRole::Responder, ..context },
/// )?;
/// sender.submit(b"actual payload", Duration::ZERO)?;
/// let mut packet = vec![0; sender.max_packet_bytes()];
/// if let Some(size) = sender.poll(Duration::ZERO, &mut packet)? {
///     // Authenticate the transferred packet with the session layer before receive.
///     receiver.receive(&packet[..size], Duration::ZERO)?;
/// }
/// let mut delivered = [0; 128];
/// assert_eq!(receiver.poll_delivered(&mut delivered)?, Some((0, 14)));
/// assert_eq!(&delivered[..14], b"actual payload");
/// let ack_time = Duration::from_millis(5);
/// if let Some(size) = receiver.poll(ack_time, &mut packet)? {
///     sender.receive(&packet[..size], ack_time)?;
/// }
/// assert!(sender.drained());
/// # Ok(())
/// # }
/// ```
#[derive(Debug)]
pub struct SelectiveRepeat(Engine);

/// Bounded forwarding for an authenticated reliable ordered carrier, without ARQ.
/// `poll` transfers send ownership to the caller; it does not prove peer receipt.
#[derive(Debug)]
pub struct CarrierOnly(Engine);

/// Borrowed syntactically valid selective-repeat record in the supplied peer context.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PacketView<'a> {
    /// Complete original source identity and opaque source payload.
    Data {
        /// Nonwrapping source identity.
        source: SourceId,
        /// Original source payload without the recovery header.
        payload: &'a [u8],
    },
    /// Bounded receipt feedback; sender-state validity is checked by receive.
    Ack {
        /// First missing contiguous received source ID.
        prefix: u64,
        /// Selective receipt bits relative to prefix; bit zero is clear.
        bitmap: u64,
    },
}

/// Inspect a selective-repeat peer packet using the engine's authoritative parser.
///
/// This validates encoding, profile, role/session/epoch and source size, but does
/// not authenticate bytes or validate feedback against a particular send ledger.
pub fn inspect_packet(
    packet: &[u8],
    context: RecoveryContext,
    max_source_bytes: usize,
) -> Result<PacketView<'_>, RecoveryError> {
    if !(1..=65_535).contains(&max_source_bytes) {
        return Err(RecoveryError::InvalidConfig);
    }
    parse(packet, context, Profile::Selective, max_source_bytes)
}

/// Local observation of one prepared source attempt; never peer authentication.
/// Confirmation consumes the exact attempt once, including when
/// an earlier attempt was acknowledged while this retry remained caller-owned.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PhysicalTransmission {
    instance: u64,
    context: RecoveryContext,
    source: SourceId,
    serial: u64,
}

impl SelectiveRepeat {
    /// Select physical custody before use; legacy constructors remain unchanged.
    pub fn enable_physical_send_confirmation(&mut self) -> Result<(), RecoveryError> {
        self.0.enable_physical_send_confirmation()
    }
    /// Observe one actual uncompleted source attempt.
    pub fn pending_transmission(&self, source: SourceId) -> Option<PhysicalTransmission> {
        self.0.pending_transmission(source)
    }
    /// Observe one whole write at the same injected time.
    pub fn confirm_transmission(
        &mut self,
        now: Duration,
        token: PhysicalTransmission,
    ) -> Result<(), RecoveryError> {
        self.confirm_transmission_at(now, now, token)
    }
    /// Preserve the original accepted time through delayed observation.
    pub fn confirm_transmission_at(
        &mut self,
        observed: Duration,
        accepted: Duration,
        token: PhysicalTransmission,
    ) -> Result<(), RecoveryError> {
        self.0.confirm_transmission_at(observed, accepted, token)
    }

    /// Construct the same ARQ engine with every metadata/payload buffer provisioned.
    /// The heap-only limit includes idle buffers and excludes the inline engine.
    pub fn new_reserved(
        config: ArqConfig,
        context: RecoveryContext,
        limits: crate::storage::Limits,
    ) -> Result<Self, crate::storage::Error> {
        Self::new_duplex_reserved(config, config, context, limits)
    }

    /// Reserve one actual owner using complete independent data-direction policies.
    pub fn new_duplex_reserved(
        send: ArqConfig,
        receive: ArqConfig,
        context: RecoveryContext,
        limits: crate::storage::Limits,
    ) -> Result<Self, crate::storage::Error> {
        let plan = crate::storage::DuplexPlan::for_arq(send, receive)?;
        if plan.capacity_bytes() > limits.capacity_bytes {
            return Err(crate::storage::Error::Limit {
                required: plan.capacity_bytes(),
                limit: limits.capacity_bytes,
            });
        }
        let mut allocation = crate::storage::Allocation::new(limits.capacity_bytes);
        Ok(Self(Engine::new_duplex_reserved(
            send,
            receive,
            context,
            &mut allocation,
        )?))
    }

    /// Actual persistent heap capacity, or None for legacy dynamic backing.
    pub fn storage_usage(&self) -> Option<crate::storage::Usage> {
        self.0.storage_usage
    }

    /// Whether an allocated source was removed by a validated peer receipt.
    /// Unallocated and unacknowledged sources return false; polling is not receipt.
    /// A confirmed source can retain a locally held retry until physical completion.
    /// Sticky recovery failure remains an error rather than proving completion.
    pub fn source_confirmed(&self, source: SourceId) -> Result<bool, RecoveryError> {
        self.0.running()?;
        Ok(source.0 < self.0.next_source
            && self
                .0
                .sent
                .get(&source)
                .is_none_or(|flight| flight.acknowledged))
    }

    /// Earliest first-source or retry deadline, independent of pending receipts.
    /// A bounded service can preserve a source opportunity without waking for
    /// feedback that cannot fit its remaining reservation.
    pub fn source_deadline(&self) -> Option<Duration> {
        self.0.source_deadline()
    }

    /// Earliest pending receipt deadline, independent of ready source work.
    /// A bounded service can reserve feedback while deferring source admission.
    pub fn feedback_deadline(&self) -> Option<Duration> {
        self.0.ack_at
    }

    /// Borrow retained authenticated sources, including those beyond an older gap.
    ///
    /// Iteration is bounded by the receive-record limit and has no ordering
    /// promise. Observation does not consume sources, advance the ordered
    /// delivery cursor or establish application/physical completion. A consumer
    /// using these bytes early must retain its own deduplication and gap state.
    pub fn received_sources(
        &self,
    ) -> Result<impl Iterator<Item = (SourceId, &[u8])>, RecoveryError> {
        self.0.running()?;
        Ok(self
            .0
            .received
            .iter()
            .map(|(source, bytes)| (*source, bytes.as_slice())))
    }

    /// Emit due feedback only, without advancing source attempts or source timers.
    /// Caller must charge this output to the same wire budget as data/repair copies.
    pub fn poll_feedback(
        &mut self,
        now: Duration,
        output: &mut [u8],
    ) -> Result<Option<usize>, RecoveryError> {
        self.0.poll_selected(now, output, true, false)
    }

    /// Emit a ready first source or retry only; due feedback remains pending.
    /// Small output buffers leave source attempts and deadlines unchanged.
    pub fn poll_source(
        &mut self,
        now: Duration,
        output: &mut [u8],
    ) -> Result<Option<usize>, RecoveryError> {
        self.0.poll_selected(now, output, false, true)
    }
}

macro_rules! engine_api {
    ($engine:ident, $profile:expr) => {
        impl $engine {
            /// Construct an empty engine with independent bounded direction state.
            pub fn new(config: ArqConfig, context: RecoveryContext) -> Result<Self, RecoveryError> {
                Self::new_duplex(config, config, context)
            }

            /// Use complete send and receive data-direction policies in one owner.
            pub fn new_duplex(
                send: ArqConfig,
                receive: ArqConfig,
                context: RecoveryContext,
            ) -> Result<Self, RecoveryError> {
                Ok(Self(Engine::new_duplex(send, receive, context, $profile)?))
            }

            /// Snapshot of the sole source allocator, valid until the next successful submit.
            /// Exclusive ownership is required between this read and submission.
            pub fn next_source_id(&self) -> Result<SourceId, RecoveryError> {
                self.0.running()?;
                self.0
                    .next_source
                    .checked_add(1)
                    .ok_or(RecoveryError::CounterExhausted)?;
                Ok(SourceId(self.0.next_source))
            }

            /// Largest packet the caller must be able to hold for this instance.
            pub fn max_packet_bytes(&self) -> usize {
                self.send_max_packet_bytes()
                    .max(self.receive_max_packet_bytes())
            }

            /// Exact local output buffer ceiling, including fixed feedback.
            pub fn send_max_packet_bytes(&self) -> usize {
                (DATA_HEADER_BYTES + self.0.config.max_source_bytes).max(ACK_PACKET_BYTES)
            }

            /// Exact peer packet ceiling; never replaced by the send maximum.
            pub fn receive_max_packet_bytes(&self) -> usize {
                (DATA_HEADER_BYTES + self.0.receive_config.max_source_bytes).max(ACK_PACKET_BYTES)
            }

            /// Saturating diagnostic counters for emitted/received/delivered work.
            pub fn statistics(&self) -> Statistics {
                self.0.statistics
            }

            /// Current bounded owned payload retention.
            pub fn retained(&self) -> Retained {
                Retained {
                    send_records: self.0.sent.len(),
                    send_bytes: self.0.send_bytes,
                    receive_records: self.0.received.len(),
                    receive_bytes: self.0.receive_bytes,
                }
            }

            /// Sticky retry-exhaustion failure, if any. Drop/reconcile the session;
            /// constructing a replacement engine alone cannot authorize ID reuse.
            pub fn failure(&self) -> Option<RecoveryError> {
                self.0.failure
            }
        }

        impl RecoveryEngine for $engine {
            type Error = RecoveryError;
            fn submit(&mut self, source: &[u8], now: Duration) -> Result<u64, Self::Error> {
                self.0.submit(source, now)
            }
            fn receive(&mut self, packet: &[u8], now: Duration) -> Result<(), Self::Error> {
                self.0.receive(packet, now)
            }
            fn poll(
                &mut self,
                now: Duration,
                output: &mut [u8],
            ) -> Result<Option<usize>, Self::Error> {
                self.0.poll(now, output)
            }
            fn poll_delivered(
                &mut self,
                output: &mut [u8],
            ) -> Result<Option<(u64, usize)>, Self::Error> {
                self.0.poll_delivered(output)
            }
            fn deadline(&self) -> Option<Duration> {
                self.0.deadline()
            }
            fn drained(&self) -> bool {
                self.0.failure.is_none()
                    && self.0.sent.is_empty()
                    && self.0.received.is_empty()
                    && self.0.ack_at.is_none()
                    && self.0.pending_transmissions == 0
            }
        }
    };
}

engine_api!(SelectiveRepeat, Profile::Selective);
engine_api!(CarrierOnly, Profile::CarrierOnly);

// This temporary owner is never retained by Engine. Failed construction drops
// its actual buffers; successful construction transfers the same backing once.
struct Construction {
    sent: Vec<SendSlot>,
    received: Vec<ReceiveSlot>,
    #[cfg(test)]
    trace: Option<crate::storage::ConstructionTraceHandle>,
    #[cfg(test)]
    metadata: [Option<usize>; 2],
    #[cfg(test)]
    send_payloads: [Option<usize>; WINDOW_LIMIT],
    #[cfg(test)]
    receive_payloads: [Option<usize>; WINDOW_LIMIT],
}

impl Construction {
    fn new(_allocation: &crate::storage::Allocation) -> Self {
        Self {
            sent: Vec::new(),
            received: Vec::new(),
            #[cfg(test)]
            trace: _allocation.trace(),
            #[cfg(test)]
            metadata: [None; 2],
            #[cfg(test)]
            send_payloads: [None; WINDOW_LIMIT],
            #[cfg(test)]
            receive_payloads: [None; WINDOW_LIMIT],
        }
    }

    fn publish(mut self) -> (Sent, Received) {
        #[cfg(test)]
        {
            self.record_inventory(crate::storage::ConstructionEventKind::Published);
        }
        (
            Sent::Reserved(std::mem::take(&mut self.sent)),
            Received::Reserved(std::mem::take(&mut self.received)),
        )
    }

    #[cfg(test)]
    fn record<T>(
        &self,
        kind: crate::storage::ConstructionEventKind,
        reservation: Option<usize>,
        values: &Vec<T>,
    ) {
        if let (Some(trace), Some(reservation)) = (&self.trace, reservation) {
            trace.borrow_mut().record(kind, reservation, values);
        }
    }

    #[cfg(test)]
    fn record_inventory(&self, kind: crate::storage::ConstructionEventKind) {
        self.record(kind, self.metadata[0], &self.sent);
        self.record(kind, self.metadata[1], &self.received);
        for (slot, reservation) in self.sent.iter().zip(self.send_payloads) {
            self.record(kind, reservation, &slot.flight.payload);
        }
        for (slot, reservation) in self.received.iter().zip(self.receive_payloads) {
            self.record(kind, reservation, &slot.payload);
        }
    }

    fn release<T>(
        values: Vec<T>,
        #[cfg(test)] trace: &Option<crate::storage::ConstructionTraceHandle>,
        #[cfg(test)] reservation: Option<usize>,
    ) {
        #[cfg(test)]
        let event = reservation.map(|reservation| {
            crate::storage::ConstructionEvent::for_vec(
                crate::storage::ConstructionEventKind::Released,
                reservation,
                &values,
            )
        });
        drop(values);
        #[cfg(test)]
        if let (Some(trace), Some(event)) = (trace, event) {
            // This event follows the actual Vec drop; saved pointers are never
            // read as memory or used to claim allocator/page reclamation.
            trace.borrow_mut().record_value(event);
        }
    }
}

impl Drop for Construction {
    fn drop(&mut self) {
        // Successful publication has moved both arrays out. The same release
        // statements below handle every partial construction in all builds.
        if self.sent.capacity() == 0 && self.received.capacity() == 0 {
            return;
        }
        let sent = self.sent.iter_mut();
        #[cfg(test)]
        let sent = sent.zip(self.send_payloads);
        for slot in sent {
            #[cfg(test)]
            let (slot, reservation) = slot;
            Self::release(
                std::mem::take(&mut slot.flight.payload),
                #[cfg(test)]
                &self.trace,
                #[cfg(test)]
                reservation,
            );
        }
        let received = self.received.iter_mut();
        #[cfg(test)]
        let received = received.zip(self.receive_payloads);
        for slot in received {
            #[cfg(test)]
            let (slot, reservation) = slot;
            Self::release(
                std::mem::take(&mut slot.payload),
                #[cfg(test)]
                &self.trace,
                #[cfg(test)]
                reservation,
            );
        }
        Self::release(
            std::mem::take(&mut self.sent),
            #[cfg(test)]
            &self.trace,
            #[cfg(test)]
            self.metadata[0],
        );
        Self::release(
            std::mem::take(&mut self.received),
            #[cfg(test)]
            &self.trace,
            #[cfg(test)]
            self.metadata[1],
        );
    }
}

impl Engine {
    #[cfg(test)]
    fn new_reserved(
        config: ArqConfig,
        context: RecoveryContext,
        allocation: &mut crate::storage::Allocation,
    ) -> Result<Self, crate::storage::Error> {
        Self::new_duplex_reserved(config, config, context, allocation)
    }

    fn new_duplex_reserved(
        config: ArqConfig,
        receive: ArqConfig,
        context: RecoveryContext,
        allocation: &mut crate::storage::Allocation,
    ) -> Result<Self, crate::storage::Error> {
        let plan = crate::storage::DuplexPlan::for_arq(config, receive)?;
        let mut construction = Construction::new(allocation);
        construction.sent = allocation.vec::<SendSlot>(config.send_records)?;
        #[cfg(test)]
        {
            construction.metadata[0] = Some(allocation.usage().allocations);
            construction.record(
                crate::storage::ConstructionEventKind::Owned,
                construction.metadata[0],
                &construction.sent,
            );
        }
        construction.received = allocation.vec::<ReceiveSlot>(receive.receive_records)?;
        #[cfg(test)]
        {
            construction.metadata[1] = Some(allocation.usage().allocations);
            construction.record(
                crate::storage::ConstructionEventKind::Owned,
                construction.metadata[1],
                &construction.received,
            );
        }
        for _ in 0..config.send_records {
            let payload = allocation.vec::<u8>(config.max_source_bytes)?;
            construction.sent.push(SendSlot {
                source: None,
                flight: Flight {
                    prepared_at: Duration::ZERO,
                    transmission: 0,
                    acknowledged: false,
                    payload,
                    attempts: 0,
                    retry_at: None,
                    rto: config.initial_rto,
                },
            });
            #[cfg(test)]
            {
                let index = construction.sent.len() - 1;
                construction.send_payloads[index] = Some(allocation.usage().allocations);
                construction.record(
                    crate::storage::ConstructionEventKind::Owned,
                    construction.send_payloads[index],
                    &construction.sent[index].flight.payload,
                );
            }
        }
        for _ in 0..receive.receive_records {
            construction.received.push(ReceiveSlot {
                source: None,
                payload: allocation.vec::<u8>(receive.max_source_bytes)?,
            });
            #[cfg(test)]
            {
                let index = construction.received.len() - 1;
                construction.receive_payloads[index] = Some(allocation.usage().allocations);
                construction.record(
                    crate::storage::ConstructionEventKind::Owned,
                    construction.receive_payloads[index],
                    &construction.received[index].payload,
                );
            }
        }
        let usage = allocation.usage();
        if usage.capacity_bytes != plan.capacity_bytes()
            || usage.allocations != 2 + config.send_records + receive.receive_records
        {
            return Err(crate::storage::Error::Invariant);
        }
        let (sent, received) = construction.publish();
        Ok(Self::from_backing(
            (config, receive),
            context,
            Profile::Selective,
            sent,
            received,
            Some(usage),
        ))
    }

    fn new_duplex(
        config: ArqConfig,
        receive: ArqConfig,
        context: RecoveryContext,
        profile: Profile,
    ) -> Result<Self, RecoveryError> {
        config.validate()?;
        receive.validate()?;
        Ok(Self::from_backing(
            (config, receive),
            context,
            profile,
            Sent::Legacy(BTreeMap::new()),
            Received::Legacy(BTreeMap::new()),
            None,
        ))
    }

    fn from_backing(
        configs: (ArqConfig, ArqConfig),
        context: RecoveryContext,
        profile: Profile,
        sent: Sent,
        received: Received,
        storage_usage: Option<crate::storage::Usage>,
    ) -> Self {
        let (config, receive_config) = configs;
        Self {
            config,
            receive_config,
            context,
            profile,
            sent,
            received,
            physical_confirmation: false,
            physical_instance: 0,
            next_transmission: 0,
            pending_transmissions: 0,
            storage_usage,
            compact: compact::Cell::empty(),
            next_source: 0,
            receive_prefix: 0,
            deliver_next: 0,
            send_bytes: 0,
            receive_bytes: 0,
            ack_at: None,
            prefer_data: false,
            prefer_retry: true,
            last_now: Duration::ZERO,
            failure: None,
            statistics: Statistics::default(),
        }
    }

    fn running(&self) -> Result<(), RecoveryError> {
        if let Some(error) = self.failure {
            return Err(error);
        }
        Ok(())
    }

    fn check_time(&self, now: Duration) -> Result<(), RecoveryError> {
        self.running()?;
        if now < self.last_now {
            return Err(RecoveryError::NonMonotonicTime);
        }
        Ok(())
    }

    fn submit(&mut self, source: &[u8], now: Duration) -> Result<u64, RecoveryError> {
        self.check_time(now)?;
        if source.len() > self.config.max_source_bytes {
            return Err(RecoveryError::SourceTooLarge);
        }
        let bytes = self
            .send_bytes
            .checked_add(source.len())
            .ok_or(RecoveryError::CounterExhausted)?;
        if self.sent.len() >= self.config.send_records || bytes > self.config.send_bytes {
            return Err(RecoveryError::Capacity(BufferSide::Send));
        }
        if let Some(first) = self
            .compact
            .as_ref()
            .map(|state| state.base)
            .or_else(|| self.sent.first_key_value().map(|(source, _)| source.0))
            && self.next_source - first >= self.config.send_records as u64
        {
            return Err(RecoveryError::SequenceWindow);
        }
        let next = self
            .next_source
            .checked_add(1)
            .ok_or(RecoveryError::CounterExhausted)?;
        let source_id = self.next_source;
        self.sent
            .insert_payload(SourceId(source_id), source, self.config.initial_rto)?;
        self.next_source = next;
        self.send_bytes = bytes;
        self.last_now = now;
        self.statistics.submitted = self.statistics.submitted.saturating_add(1);
        Ok(source_id)
    }

    fn receive(&mut self, packet: &[u8], now: Duration) -> Result<(), RecoveryError> {
        if self.compact.is_some() {
            return self.compact_receive(packet, now, now);
        }
        self.check_time(now)?;
        let parsed = parse(
            packet,
            self.context,
            self.profile,
            self.receive_config.max_source_bytes,
        )?;
        match parsed {
            PacketView::Data { source, payload } => self.receive_source(source, payload, now)?,
            PacketView::Ack { prefix, bitmap } => self.receive_ack(prefix, bitmap)?,
        }
        self.last_now = now;
        Ok(())
    }

    fn receive_source(
        &mut self,
        source: SourceId,
        payload: &[u8],
        now: Duration,
    ) -> Result<(), RecoveryError> {
        let ack_at = if self.profile == Profile::Selective && !self.compact.is_some() {
            Some(
                now.checked_add(self.receive_config.ack_delay)
                    .ok_or(RecoveryError::TimeOverflow)?,
            )
        } else {
            None
        };
        if let Some(previous) = self.received.get(&source) {
            if previous.as_slice() != payload {
                return Err(RecoveryError::ConflictingDuplicate);
            }
            self.schedule_ack(ack_at);
            self.statistics.duplicates = self.statistics.duplicates.saturating_add(1);
            return Ok(());
        }
        if source.0 < self.receive_prefix {
            self.schedule_ack(ack_at);
            self.statistics.duplicates = self.statistics.duplicates.saturating_add(1);
            return Ok(());
        }
        if self.profile == Profile::CarrierOnly && source.0 != self.receive_prefix {
            return Err(RecoveryError::UnexpectedSequence);
        }
        if source.0 - self.deliver_next >= self.receive_config.receive_records as u64 {
            return Err(RecoveryError::SequenceWindow);
        }
        let bytes = self
            .receive_bytes
            .checked_add(payload.len())
            .ok_or(RecoveryError::CounterExhausted)?;
        if self.received.len() >= self.receive_config.receive_records
            || bytes > self.receive_config.receive_bytes
        {
            return Err(RecoveryError::Capacity(BufferSide::Receive));
        }
        self.received.insert_payload(source, payload)?;
        self.receive_bytes = bytes;
        while self.received.contains_key(&SourceId(self.receive_prefix)) {
            // Source u64::MAX is rejected by the codec, so advancing is safe.
            self.receive_prefix += 1;
        }
        self.schedule_ack(ack_at);
        self.statistics.received_unique = self.statistics.received_unique.saturating_add(1);
        Ok(())
    }

    fn schedule_ack(&mut self, deadline: Option<Duration>) {
        if let Some(deadline) = deadline {
            self.ack_at = Some(
                self.ack_at
                    .map_or(deadline, |previous| previous.min(deadline)),
            );
        }
    }

    fn receive_ack(&mut self, prefix: u64, bitmap: u64) -> Result<(), RecoveryError> {
        if prefix > self.next_source {
            return Err(RecoveryError::UnsentAcknowledgement);
        }
        if bitmap != 0 {
            let highest = 63 - u64::from(bitmap.leading_zeros());
            let last = prefix
                .checked_add(highest)
                .ok_or(RecoveryError::UnsentAcknowledgement)?;
            if last >= self.next_source {
                return Err(RecoveryError::UnsentAcknowledgement);
            }
        }
        if self.sent.iter().any(|(source, flight)| {
            acknowledged(*source, prefix, bitmap)
                && (flight.attempts == 0
                    || (self.physical_confirmation
                        && flight.attempts == 1
                        && flight.retry_at.is_none()))
        }) {
            return Err(RecoveryError::UnsentAcknowledgement);
        }
        let mut released_bytes = 0;
        self.sent.retain(|source, flight| {
            if acknowledged(*source, prefix, bitmap) {
                if self.physical_confirmation && flight.retry_at.is_none() {
                    flight.acknowledged = true;
                    return true;
                }
                released_bytes += flight.payload.len();
                false
            } else {
                true
            }
        });
        // The removed payload subset cannot exceed the previously accounted sum.
        self.send_bytes -= released_bytes;
        self.statistics.feedback_received = self.statistics.feedback_received.saturating_add(1);
        Ok(())
    }

    fn ready_source(&self, now: Duration) -> Option<SourceId> {
        let retry = self
            .sent
            .iter()
            .filter_map(|(source, flight)| {
                flight
                    .retry_at
                    .filter(|deadline| *deadline <= now)
                    .map(|deadline| (deadline, *source))
            })
            .min()
            .map(|(_, source)| source);
        let unsent = self
            .sent
            .iter()
            .filter(|(_, flight)| flight.attempts == 0)
            .map(|(source, _)| *source)
            .min();
        // A carrier can take longer than another retry interval to accept an
        // output. Strict retry priority would then indefinitely suppress fresh
        // sources even though they already own finite send-window capacity.
        match (retry, unsent) {
            (Some(retry), Some(unsent)) => Some(if self.prefer_retry { retry } else { unsent }),
            (retry, unsent) => retry.or(unsent),
        }
    }

    fn poll(&mut self, now: Duration, output: &mut [u8]) -> Result<Option<usize>, RecoveryError> {
        self.poll_selected(now, output, true, true)
    }

    fn poll_selected(
        &mut self,
        now: Duration,
        output: &mut [u8],
        allow_feedback: bool,
        allow_sources: bool,
    ) -> Result<Option<usize>, RecoveryError> {
        if self.compact.is_some() {
            return self.compact_poll(now, output, allow_feedback, allow_sources);
        }
        self.check_time(now)?;
        let ack_ready = allow_feedback && self.ack_at.is_some_and(|deadline| deadline <= now);
        let data = if allow_sources
            && (!self.physical_confirmation
                || self.pending_transmissions < self.config.send_records)
        {
            self.ready_source(now)
        } else {
            None
        };
        if ack_ready && (!self.prefer_data || data.is_none()) {
            ensure_output(output, ACK_PACKET_BYTES)?;
            let mut bitmap = 0;
            for source in self.received.keys() {
                if source.0 >= self.receive_prefix {
                    let offset = source.0 - self.receive_prefix;
                    if offset < 64 {
                        bitmap |= 1_u64 << offset;
                    }
                }
            }
            write_common(output, self.context, self.profile, 2);
            output[32..40].copy_from_slice(&self.receive_prefix.to_be_bytes());
            output[40..48].copy_from_slice(&bitmap.to_be_bytes());
            self.ack_at = None;
            self.prefer_data = true;
            self.last_now = now;
            self.statistics.feedback_sent = self.statistics.feedback_sent.saturating_add(1);
            self.statistics.wire_bytes_emitted = self
                .statistics
                .wire_bytes_emitted
                .saturating_add(ACK_PACKET_BYTES as u64);
            return Ok(Some(ACK_PACKET_BYTES));
        }
        let Some(source) = data else {
            self.last_now = now;
            return Ok(None);
        };
        let flight = self
            .sent
            .get(&source)
            .ok_or(RecoveryError::MalformedPacket)?;
        if flight.attempts > u32::from(self.config.max_retries) {
            let error = RecoveryError::RetryExhausted { source };
            self.failure = Some(error);
            self.last_now = now;
            return Err(error);
        }
        let required = DATA_HEADER_BYTES + flight.payload.len();
        ensure_output(output, required)?;
        let is_retry = flight.attempts > 0;
        let rto = if is_retry {
            flight
                .rto
                .checked_mul(2)
                .unwrap_or(self.config.maximum_rto)
                .min(self.config.maximum_rto)
        } else {
            self.config.initial_rto
        };
        let transmission = if self.physical_confirmation {
            self.next_transmission
                .checked_add(1)
                .ok_or(RecoveryError::CounterExhausted)?
        } else {
            0
        };
        let retry_at = if self.profile == Profile::Selective && !self.physical_confirmation {
            Some(now.checked_add(rto).ok_or(RecoveryError::TimeOverflow)?)
        } else {
            None
        };
        write_common(output, self.context, self.profile, 1);
        output[32..40].copy_from_slice(&source.0.to_be_bytes());
        output[40..44].copy_from_slice(&(flight.payload.len() as u32).to_be_bytes());
        output[44..required].copy_from_slice(&flight.payload);
        if self.profile == Profile::CarrierOnly {
            self.send_bytes -= flight.payload.len();
            self.sent.remove(&source);
        } else {
            let flight = self
                .sent
                .get_mut(&source)
                .ok_or(RecoveryError::MalformedPacket)?;
            flight.attempts += 1;
            flight.prepared_at = now;
            flight.transmission = transmission;
            flight.rto = rto;
            flight.retry_at = retry_at;
        }
        self.next_transmission = transmission;
        if self.physical_confirmation {
            self.pending_transmissions += 1;
        }
        self.prefer_data = false;
        self.prefer_retry = !is_retry;
        self.last_now = now;
        self.statistics.transmissions = self.statistics.transmissions.saturating_add(1);
        self.statistics.retransmissions = self
            .statistics
            .retransmissions
            .saturating_add(u64::from(is_retry));
        self.statistics.wire_bytes_emitted = self
            .statistics
            .wire_bytes_emitted
            .saturating_add(required as u64);
        Ok(Some(required))
    }

    fn poll_delivered(&mut self, output: &mut [u8]) -> Result<Option<(u64, usize)>, RecoveryError> {
        self.running()?;
        let source = SourceId(self.deliver_next);
        let Some(payload) = self.received.get(&source) else {
            return Ok(None);
        };
        let length = payload.len();
        ensure_output(output, length)?;
        let next = self
            .deliver_next
            .checked_add(1)
            .ok_or(RecoveryError::CounterExhausted)?;
        output[..length].copy_from_slice(payload);
        self.received.remove(&source);
        self.receive_bytes -= length;
        self.deliver_next = next;
        self.statistics.delivered = self.statistics.delivered.saturating_add(1);
        Ok(Some((source.0, length)))
    }

    fn source_deadline(&self) -> Option<Duration> {
        if self.failure.is_some() {
            return None;
        }
        if self.compact.is_some() {
            return self.compact_source_deadline();
        }
        self.sent
            .values()
            .filter_map(|flight| {
                flight
                    .retry_at
                    .or_else(|| (flight.attempts == 0).then_some(self.last_now))
            })
            .min()
    }

    fn deadline(&self) -> Option<Duration> {
        if self.failure.is_some() {
            return None;
        }
        self.source_deadline().into_iter().chain(self.ack_at).min()
    }
}

fn acknowledged(source: SourceId, prefix: u64, bitmap: u64) -> bool {
    if source.0 < prefix {
        return true;
    }
    let offset = source.0 - prefix;
    offset < 64 && bitmap & (1_u64 << offset) != 0
}

fn ensure_output(output: &[u8], required: usize) -> Result<(), RecoveryError> {
    if output.len() < required {
        return Err(RecoveryError::OutputTooSmall { required });
    }
    Ok(())
}

fn write_common(output: &mut [u8], context: RecoveryContext, profile: Profile, kind: u8) {
    output[..4].copy_from_slice(b"L2AR");
    output[4] = 1;
    output[5] = profile.code();
    output[6] = kind;
    output[7] = context.role.code();
    output[8..24].copy_from_slice(&context.session.to_be_bytes());
    output[24..32].copy_from_slice(&context.epoch.to_be_bytes());
}

fn field<const N: usize>(packet: &[u8], offset: usize) -> Result<[u8; N], RecoveryError> {
    packet
        .get(offset..offset + N)
        .ok_or(RecoveryError::MalformedPacket)?
        .try_into()
        .map_err(|_| RecoveryError::MalformedPacket)
}

fn parse(
    packet: &[u8],
    context: RecoveryContext,
    profile: Profile,
    max_source: usize,
) -> Result<PacketView<'_>, RecoveryError> {
    if packet.len() < COMMON_HEADER_BYTES || packet.get(..4) != Some(b"L2AR") || packet[4] != 1 {
        return Err(RecoveryError::MalformedPacket);
    }
    if packet[5] != profile.code() {
        return Err(RecoveryError::WrongProfile);
    }
    if packet[7] > 1
        || packet[7] == context.role.code()
        || u128::from_be_bytes(field(packet, 8)?) != context.session
        || u64::from_be_bytes(field(packet, 24)?) != context.epoch
    {
        return Err(RecoveryError::WrongContext);
    }
    match packet[6] {
        1 => {
            let source = u64::from_be_bytes(field(packet, 32)?);
            if source == u64::MAX {
                return Err(RecoveryError::CounterExhausted);
            }
            let length = u32::from_be_bytes(field(packet, 40)?) as usize;
            if length > max_source {
                return Err(RecoveryError::SourceTooLarge);
            }
            if packet.len() != DATA_HEADER_BYTES + length {
                return Err(RecoveryError::MalformedPacket);
            }
            Ok(PacketView::Data {
                source: SourceId(source),
                payload: &packet[DATA_HEADER_BYTES..],
            })
        }
        2 if profile == Profile::Selective => {
            if packet.len() != ACK_PACKET_BYTES {
                return Err(RecoveryError::MalformedPacket);
            }
            let prefix = u64::from_be_bytes(field(packet, 32)?);
            let bitmap = u64::from_be_bytes(field(packet, 40)?);
            if bitmap & 1 != 0 {
                return Err(RecoveryError::MalformedPacket);
            }
            Ok(PacketView::Ack { prefix, bitmap })
        }
        _ => Err(RecoveryError::MalformedPacket),
    }
}

#[cfg(test)]
mod directional_tests;
#[cfg(test)]
mod storage_tests;
#[cfg(test)]
mod tests;

#[cfg(test)]
mod physical_tests;

impl Engine {
    /// Select whole-send timer custody before any source or peer input is used.
    /// Legacy constructors keep poll-time custody unless explicitly selected.
    pub fn enable_physical_send_confirmation(&mut self) -> Result<(), RecoveryError> {
        self.running()?;
        if self.next_source != 0 || self.statistics != Statistics::default() {
            return Err(RecoveryError::InvalidConfig);
        }
        if !self.physical_confirmation {
            self.physical_instance = NEXT_PHYSICAL_OWNER
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                    current.checked_add(1)
                })
                .map_err(|_| RecoveryError::CounterExhausted)?;
        }
        self.physical_confirmation = true;
        Ok(())
    }

    /// Observe a prepared source that has not completed physical transmission.
    pub fn pending_transmission(&self, source: SourceId) -> Option<PhysicalTransmission> {
        let flight = self.sent.get(&source)?;
        (self.physical_confirmation
            && flight.retry_at.is_none()
            && flight.attempts > 0
            && flight.transmission != 0)
            .then_some(PhysicalTransmission {
                instance: self.physical_instance,
                context: self.context,
                source,
                serial: flight.transmission,
            })
    }

    /// Confirm a prepared attempt after actual whole-carrier acceptance.
    /// Invalid time after acceptance consumes that custody and fails the owner.
    ///
    /// Confirm asynchronous carrier acceptance at its original physical time.
    /// Observation time remains monotonic; acceptance must lie between actual
    /// preparation and observation. An already due retry stays due immediately.
    pub fn confirm_transmission_at(
        &mut self,
        observed: Duration,
        accepted: Duration,
        token: PhysicalTransmission,
    ) -> Result<(), RecoveryError> {
        if !self.physical_confirmation
            || token.context != self.context
            || token.instance != self.physical_instance
            || token.serial == 0
            || self.pending_transmissions == 0
            || !self.sent.get(&token.source).is_some_and(|flight| {
                flight.transmission == token.serial
                    && flight.retry_at.is_none()
                    && flight.attempts > 0
            })
        {
            return Err(RecoveryError::InvalidTransmission);
        }
        let timing = self.check_time(observed);
        let flight = self
            .sent
            .get_mut(&token.source)
            .ok_or(RecoveryError::InvalidTransmission)?;
        // Consume real physical ownership even if time validation later fails.
        flight.transmission = 0;
        self.pending_transmissions -= 1;
        let timing = timing.and(if accepted < flight.prepared_at || accepted > observed {
            Err(RecoveryError::NonMonotonicTime)
        } else {
            Ok(())
        });
        let acknowledged = flight.acknowledged;
        let deadline = if acknowledged {
            Ok(None)
        } else {
            accepted
                .checked_add(flight.rto)
                .map(Some)
                .ok_or(RecoveryError::TimeOverflow)
        };
        if acknowledged {
            self.send_bytes -= flight.payload.len();
            self.sent.remove(&token.source);
        }
        match timing.and(deadline) {
            Ok(deadline) => {
                if let Some(flight) = self.sent.get_mut(&token.source) {
                    flight.retry_at = deadline;
                }
                if let Some(state) = self.compact.as_mut() {
                    state.confirm(token.source, token.serial, accepted)?;
                }
                self.last_now = observed;
                Ok(())
            }
            Err(error) => {
                self.failure.get_or_insert(error);
                Err(error)
            }
        }
    }
}
