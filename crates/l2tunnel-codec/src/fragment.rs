use crate::MAX_RECORD_BYTES;
use l2tunnel_core::Epoch;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

mod backing;
pub mod storage;
use backing::{PendingStore, RetiredStore};

/// Fixed overhead of one draft session-scoped fragment.
pub const FRAGMENT_HEADER_BYTES: usize = 40;

/// Session identifier copied from authenticated enclosing session state.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct SessionId(pub u64);

/// Nonwrapping message identity, unique within one direction/session/epoch.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct MessageId(pub u64);

/// Authenticated identity expected by one directional fragmentation context.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FragmentContext {
    /// Session selected by the enclosing authenticated protocol.
    pub session: SessionId,
    /// Negotiated configuration generation.
    pub epoch: Epoch,
}

/// Local sender bounds and explicit complete outer-packet MTU accounting.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FragmentConfig {
    /// Complete path packet budget, including caller-supplied outer overhead.
    pub path_mtu: usize,
    /// Real IP/carrier/authentication/wrapper overhead outside this fragment.
    pub outer_overhead_bytes: usize,
    /// Maximum complete record size, bounded by `MAX_RECORD_BYTES`.
    pub max_message_bytes: usize,
    /// Maximum fragment count per record; must be nonzero.
    pub max_fragments: u16,
}

/// Explicit receiver memory, work and lifetime bounds for one context.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReassemblyConfig {
    /// Maximum complete record size, including its frame-record header.
    pub max_message_bytes: usize,
    /// Maximum simultaneously incomplete messages.
    pub max_messages: usize,
    /// Maximum chunk size declared by an incoming fragment.
    pub max_fragment_payload_bytes: u16,
    /// Maximum fragments reserved by one incomplete message.
    pub max_fragments_per_message: u16,
    /// Maximum total fragment slots reserved by incomplete messages.
    pub max_total_fragments: usize,
    /// Maximum total payload bytes reserved for incomplete messages.
    pub max_reserved_bytes: usize,
    /// Maximum first-arrival lifetime in caller-injected monotonic ticks.
    pub max_lifetime_ticks: u64,
    /// Sliding message-ID width; 1..=65536, bounding terminal tombstones.
    pub replay_window: usize,
}

/// Fragment parsing, resource, lifecycle or identifier failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FragmentError {
    /// A local limit is zero, inconsistent or above a hard ceiling.
    InvalidConfig,
    /// There is no positive payload budget after all configured overhead.
    MtuTooSmall,
    /// Empty records cannot be fragmented.
    EmptyMessage,
    /// A declared or supplied complete record exceeds its bound.
    MessageTooLarge,
    /// The fragment count exceeds the configured bound or wire field.
    TooManyFragments,
    /// Every message ID has been consumed; create a new authenticated context.
    Exhausted,
    /// Destination cannot hold a complete message; the fragment was not added.
    OutputTooSmall,
    /// The fixed fragment header is incomplete.
    Truncated,
    /// Magic, version or reserved fields are invalid.
    InvalidHeader,
    /// Fragment count/index/chunk/body dimensions are not canonical.
    InvalidGeometry,
    /// Session or epoch differs from the expected authenticated context.
    WrongContext,
    /// Checked size, offset or accounting arithmetic failed.
    Arithmetic,
    /// Supplied time moved backwards.
    TimeWentBackwards,
    /// The first-arrival deadline cannot be represented.
    DeadlineOverflow,
    /// Maximum simultaneous incomplete messages would be exceeded.
    MessageBudget,
    /// Reserving the entire declared message would exceed the byte budget.
    ByteBudget,
    /// Reserving all declared fragment slots would exceed their budget.
    FragmentBudget,
    /// Existing message geometry or same-index bytes conflict with this fragment.
    Conflict,
    /// The message ID is older than the deduplication window.
    StaleMessage,
    /// Advancing the deduplication window would evict an incomplete message.
    ReplayWindowBlocked,
}

impl fmt::Display for FragmentError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "fragment codec error: {self:?}")
    }
}

impl std::error::Error for FragmentError {}

/// A complete bounded set of fragments for one newly assigned message ID.
#[derive(Debug, Eq, PartialEq)]
pub struct FragmentBatch {
    /// ID assigned after successful input and MTU validation.
    pub message: MessageId,
    /// Canonical index-ordered fragments, each within the configured MTU budget.
    pub fragments: Vec<Vec<u8>>,
}

/// Checked canonical flat-batch geometry; not authentication or delivery authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FragmentLayout {
    message: MessageId,
    length: usize,
    count: u16,
    chunk: u16,
    encoded: usize,
}
impl FragmentLayout {
    /// Full nonwrapping identity assigned by the actual Fragmenter.
    pub fn message(&self) -> MessageId {
        self.message
    }
    /// Number of complete canonical fragments.
    pub fn fragments(&self) -> usize {
        usize::from(self.count)
    }
    /// Initialized flat-batch prefix length.
    pub fn encoded_bytes(&self) -> usize {
        self.encoded
    }
    /// Exact header-and-body range of one index, without allocating.
    pub fn fragment_range(&self, index: usize) -> Option<std::ops::Range<usize>> {
        if index >= self.fragments() {
            return None;
        }
        let chunk = usize::from(self.chunk);
        let body = self
            .length
            .checked_sub(index.checked_mul(chunk)?)?
            .min(chunk);
        let begin = index.checked_mul(FRAGMENT_HEADER_BYTES.checked_add(chunk)?)?;
        let end = begin
            .checked_add(FRAGMENT_HEADER_BYTES)?
            .checked_add(body)?;
        (end <= self.encoded).then_some(begin..end)
    }
}

/// Borrowed exact initialized batch prefix produced into caller storage.
pub struct FragmentBatchView<'out> {
    layout: FragmentLayout,
    encoded: &'out [u8],
}
impl<'out> FragmentBatchView<'out> {
    /// Full allocated message identity.
    pub fn message(&self) -> MessageId {
        self.layout.message
    }
    /// Number of initialized fragments.
    pub fn len(&self) -> usize {
        self.layout.fragments()
    }
    /// Successful batches are never empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
    /// Exact initialized bytes, excluding unused caller capacity.
    pub fn encoded(&self) -> &'out [u8] {
        self.encoded
    }
    /// Borrow one complete header/body by canonical index.
    pub fn fragment(&self, index: usize) -> Option<&'out [u8]> {
        self.encoded.get(self.layout.fragment_range(index)?)
    }
    /// Retain checked geometry after ending this temporary buffer borrow.
    pub fn layout(&self) -> FragmentLayout {
        self.layout
    }
}

/// Monotonic message-ID owner for one direction/session/epoch.
pub struct Fragmenter {
    context: FragmentContext,
    config: FragmentConfig,
    chunk_bytes: usize,
    next_message: Option<MessageId>,
}

impl Fragmenter {
    /// Validate MTU/bounds and choose the first unused ID in this context.
    ///
    /// The caller must not recreate this object with previously consumed IDs.
    pub fn new(
        context: FragmentContext,
        config: FragmentConfig,
        first_message: MessageId,
    ) -> Result<Self, FragmentError> {
        if !(1..=MAX_RECORD_BYTES).contains(&config.max_message_bytes) || config.max_fragments == 0
        {
            return Err(FragmentError::InvalidConfig);
        }
        let overhead = config
            .outer_overhead_bytes
            .checked_add(FRAGMENT_HEADER_BYTES)
            .ok_or(FragmentError::Arithmetic)?;
        let chunk_bytes = config
            .path_mtu
            .checked_sub(overhead)
            .filter(|value| *value != 0)
            .ok_or(FragmentError::MtuTooSmall)?
            .min(usize::from(u16::MAX));
        Ok(Self {
            context,
            config,
            chunk_bytes,
            next_message: Some(first_message),
        })
    }

    /// Payload bytes available in each full fragment after actual outer overhead.
    pub fn chunk_bytes(&self) -> usize {
        self.chunk_bytes
    }

    /// Fragment a bounded record; failed calls consume no message ID.
    fn prepare(&self, record: &[u8]) -> Result<FragmentLayout, FragmentError> {
        if record.is_empty() {
            return Err(FragmentError::EmptyMessage);
        }
        if record.len() > self.config.max_message_bytes {
            return Err(FragmentError::MessageTooLarge);
        }
        let count = u16::try_from(record.len().div_ceil(self.chunk_bytes))
            .map_err(|_| FragmentError::TooManyFragments)?;
        if count > self.config.max_fragments {
            return Err(FragmentError::TooManyFragments);
        }
        let message = self.next_message.ok_or(FragmentError::Exhausted)?;
        u32::try_from(record.len()).map_err(|_| FragmentError::Arithmetic)?;
        let chunk = u16::try_from(self.chunk_bytes).map_err(|_| FragmentError::Arithmetic)?;
        let encoded = usize::from(count)
            .checked_mul(FRAGMENT_HEADER_BYTES)
            .and_then(|headers| headers.checked_add(record.len()))
            .ok_or(FragmentError::Arithmetic)?;
        Ok(FragmentLayout {
            message,
            length: record.len(),
            count,
            chunk,
            encoded,
        })
    }

    /// Fragment a bounded record; failed calls consume no message ID.
    pub fn fragment(&mut self, record: &[u8]) -> Result<FragmentBatch, FragmentError> {
        let layout = self.prepare(record)?;
        let mut fragments = Vec::with_capacity(layout.fragments());
        for (index, body) in record.chunks(self.chunk_bytes).enumerate() {
            let capacity = FRAGMENT_HEADER_BYTES
                .checked_add(body.len())
                .ok_or(FragmentError::Arithmetic)?;
            let mut bytes = vec![0; capacity];
            encode_fragment(self.context, layout, index, body, &mut bytes)?;
            fragments.push(bytes);
        }
        self.next_message = layout.message.0.checked_add(1).map(MessageId);
        Ok(FragmentBatch {
            message: layout.message,
            fragments,
        })
    }

    /// Encode a complete canonical batch without allocation or a partial ID handoff.
    pub fn fragment_into<'out>(
        &mut self,
        record: &[u8],
        encoded: &'out mut [u8],
    ) -> Result<FragmentBatchView<'out>, FragmentError> {
        let layout = self.prepare(record)?;
        let output = encoded
            .get_mut(..layout.encoded)
            .ok_or(FragmentError::OutputTooSmall)?;
        for (index, body) in record.chunks(self.chunk_bytes).enumerate() {
            let range = layout
                .fragment_range(index)
                .ok_or(FragmentError::Arithmetic)?;
            encode_fragment(
                self.context,
                layout,
                index,
                body,
                output.get_mut(range).ok_or(FragmentError::Arithmetic)?,
            )?;
        }
        self.next_message = layout.message.0.checked_add(1).map(MessageId);
        Ok(FragmentBatchView {
            layout,
            encoded: output,
        })
    }
}

fn encode_fragment(
    context: FragmentContext,
    layout: FragmentLayout,
    index: usize,
    body: &[u8],
    output: &mut [u8],
) -> Result<(), FragmentError> {
    let index = u16::try_from(index).map_err(|_| FragmentError::Arithmetic)?;
    let length = u16::try_from(body.len()).map_err(|_| FragmentError::Arithmetic)?;
    let total = u32::try_from(layout.length).map_err(|_| FragmentError::Arithmetic)?;
    let needed = FRAGMENT_HEADER_BYTES
        .checked_add(body.len())
        .ok_or(FragmentError::Arithmetic)?;
    let output = output
        .get_mut(..needed)
        .ok_or(FragmentError::OutputTooSmall)?;
    output[..2].copy_from_slice(b"LX");
    output[2..4].copy_from_slice(&[1, 0]);
    output[4..12].copy_from_slice(&context.session.0.to_be_bytes());
    output[12..20].copy_from_slice(&context.epoch.0.to_be_bytes());
    output[20..28].copy_from_slice(&layout.message.0.to_be_bytes());
    output[28..32].copy_from_slice(&total.to_be_bytes());
    output[32..34].copy_from_slice(&index.to_be_bytes());
    output[34..36].copy_from_slice(&layout.count.to_be_bytes());
    output[36..38].copy_from_slice(&layout.chunk.to_be_bytes());
    output[38..40].copy_from_slice(&length.to_be_bytes());
    output[40..].copy_from_slice(body);
    Ok(())
}

/// Result of authenticated fragment admission; only completion writes output.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReassemblyStatus {
    /// A new fragment was retained but the message is incomplete.
    Pending {
        /// Message being assembled.
        message: MessageId,
        /// Number of unique fragments currently retained.
        received: u16,
        /// Canonical total fragment count.
        total: u16,
    },
    /// Identical fragment, or a completed/expired message inside the replay window.
    Duplicate {
        /// Message whose duplicate was ignored without writing output.
        message: MessageId,
    },
    /// Exactly one complete record has been copied into caller storage.
    Complete {
        /// Completed message; it cannot be delivered again in this context/window.
        message: MessageId,
        /// Number of output bytes written.
        length: usize,
    },
}

struct Pending {
    chunk: u16,
    count: u16,
    received: u16,
    present: Vec<u8>,
    buffer: Vec<u8>,
    deadline: u64,
}

struct ParsedFragment<'a> {
    message: MessageId,
    length: usize,
    index: u16,
    count: u16,
    chunk: u16,
    offset: usize,
    body: &'a [u8],
}

/// Bounded reassembly and terminal message deduplication for one direction/context.
///
/// Input must already be authenticated. IDs/session fields are not authenticators.
/// All caller output remains unchanged on errors, incomplete input and duplicates.
pub struct Reassembler {
    context: FragmentContext,
    config: ReassemblyConfig,
    pending: PendingStore,
    retired: RetiredStore,
    highest: Option<MessageId>,
    last_time: Option<u64>,
    reserved_bytes: usize,
    reserved_fragments: usize,
    storage_usage: Option<storage::Usage>,
    expired_scratch: Vec<MessageId>,
}

fn validate_reassembly(config: ReassemblyConfig) -> Result<(), FragmentError> {
    if !(1..=MAX_RECORD_BYTES).contains(&config.max_message_bytes)
        || config.max_messages == 0
        || config.max_fragment_payload_bytes == 0
        || config.max_fragments_per_message == 0
        || config.max_total_fragments < usize::from(config.max_fragments_per_message)
        || config.max_reserved_bytes < config.max_message_bytes
        || config.max_lifetime_ticks == 0
        || !(1..=65_536).contains(&config.replay_window)
        || config.max_messages > config.replay_window
    {
        return Err(FragmentError::InvalidConfig);
    }
    Ok(())
}

impl Reassembler {
    /// Validate receiver limits without allocating peer-selected message storage.
    pub fn new(context: FragmentContext, config: ReassemblyConfig) -> Result<Self, FragmentError> {
        validate_reassembly(config)?;
        Ok(Self {
            context,
            config,
            pending: PendingStore::Legacy(BTreeMap::new()),
            retired: RetiredStore::Legacy(BTreeSet::new()),
            highest: None,
            last_time: None,
            reserved_bytes: 0,
            reserved_fragments: 0,
            storage_usage: None,
            expired_scratch: Vec::new(),
        })
    }

    /// Provision every pending/replay/scratch buffer before publication.
    pub fn new_reserved(
        context: FragmentContext,
        config: ReassemblyConfig,
        limits: storage::Limits,
    ) -> Result<Self, storage::Error> {
        let plan = storage::Plan::for_reassembly(config)?;
        if plan.capacity_bytes() > limits.capacity_bytes {
            return Err(storage::Error::Limit {
                required: plan.capacity_bytes(),
                limit: limits.capacity_bytes,
            });
        }
        Self::build_reserved(
            context,
            config,
            &mut storage::Allocation::new(limits.capacity_bytes),
        )
    }
    fn build_reserved(
        context: FragmentContext,
        config: ReassemblyConfig,
        allocation: &mut storage::Allocation,
    ) -> Result<Self, storage::Error> {
        let plan = storage::Plan::for_reassembly(config)?;
        let (pending, retired, expired_scratch) = backing::reserved(config, allocation)?;
        let usage = allocation.usage();
        if usage.capacity_bytes != plan.capacity_bytes()
            || usage.allocations != 3 + 2 * config.max_messages
        {
            return Err(storage::Error::Invariant);
        }
        Ok(Self {
            context,
            config,
            pending,
            retired,
            highest: None,
            last_time: None,
            reserved_bytes: 0,
            reserved_fragments: 0,
            storage_usage: Some(usage),
            expired_scratch,
        })
    }
    /// Actual retained heap including every idle buffer; None for legacy storage.
    pub fn storage_usage(&self) -> Option<storage::Usage> {
        self.storage_usage
    }

    /// Accept one authenticated fragment using injected monotonic ticks.
    ///
    /// Validated input triggers deadline cleanup before admission, even if the
    /// fragment is then rejected. Duplicate/conflicting fragments never extend
    /// lifetime. A too-small completion buffer does not retain the new fragment.
    /// Call `expire(now_ticks)` first if reliable recovery needs the expired IDs;
    /// this method's defensive cleanup returns only the current fragment status.
    pub fn accept(
        &mut self,
        fragment: &[u8],
        now_ticks: u64,
        output: &mut [u8],
    ) -> Result<ReassemblyStatus, FragmentError> {
        let parsed = self.parse(fragment)?;
        self.expire_count(now_ticks)?;
        let high = self
            .highest
            .map_or(parsed.message, |current| current.max(parsed.message));
        let floor = self.window_floor(high);
        if parsed.message < MessageId(floor) {
            return Err(FragmentError::StaleMessage);
        }
        if self.retired.contains(&parsed.message) {
            return Ok(ReassemblyStatus::Duplicate {
                message: parsed.message,
            });
        }
        if self.pending.contains_key(&parsed.message) {
            return self.accept_existing(parsed, output);
        }
        if self.pending.keys().any(|message| message.0 < floor) {
            return Err(FragmentError::ReplayWindowBlocked);
        }
        let deadline = now_ticks
            .checked_add(self.config.max_lifetime_ticks)
            .ok_or(FragmentError::DeadlineOverflow)?;
        if self.pending.len() >= self.config.max_messages {
            return Err(FragmentError::MessageBudget);
        }
        let reserved_bytes = self
            .reserved_bytes
            .checked_add(parsed.length)
            .filter(|total| *total <= self.config.max_reserved_bytes)
            .ok_or(FragmentError::ByteBudget)?;
        let reserved_fragments = self
            .reserved_fragments
            .checked_add(usize::from(parsed.count))
            .filter(|total| *total <= self.config.max_total_fragments)
            .ok_or(FragmentError::FragmentBudget)?;
        if parsed.count == 1 {
            let destination = output
                .get_mut(..parsed.length)
                .ok_or(FragmentError::OutputTooSmall)?;
            self.advance_window(high);
            self.retired.insert(parsed.message)?;
            destination.copy_from_slice(parsed.body);
            return Ok(ReassemblyStatus::Complete {
                message: parsed.message,
                length: parsed.length,
            });
        }
        self.pending.insert(&parsed, deadline)?;
        self.advance_window(high);
        self.reserved_bytes = reserved_bytes;
        self.reserved_fragments = reserved_fragments;
        Ok(ReassemblyStatus::Pending {
            message: parsed.message,
            received: 1,
            total: parsed.count,
        })
    }

    /// Retire all incomplete messages at/after their first-arrival deadlines.
    ///
    /// Returned IDs require external logical-record recovery/failure handling.
    /// Expired IDs are tombstoned rather than becoming eligible for reassembly.
    pub fn expire(&mut self, now_ticks: u64) -> Result<Vec<MessageId>, FragmentError> {
        if self.last_time.is_some_and(|previous| now_ticks < previous) {
            return Err(FragmentError::TimeWentBackwards);
        }
        let mut expired: Vec<_> = self
            .pending
            .iter()
            .filter_map(|(message, entry)| (now_ticks >= entry.deadline).then_some(*message))
            .collect();
        expired.sort_unstable();
        for message in &expired {
            self.release_pending(*message, None)?;
            self.retired.insert(*message)?;
        }
        self.last_time = Some(now_ticks);
        Ok(expired)
    }

    /// Apply original expiry without allocating an owned ID result.
    pub fn expire_count(&mut self, now_ticks: u64) -> Result<usize, FragmentError> {
        if self.storage_usage.is_none() {
            return self.expire(now_ticks).map(|ids| ids.len());
        }
        self.collect_expired(now_ticks)?;
        let count = self.expired_scratch.len();
        for index in 0..count {
            let message = self.expired_scratch[index];
            self.release_pending(message, None)?;
            self.retired.insert(message)?;
        }
        self.expired_scratch.clear();
        self.last_time = Some(now_ticks);
        Ok(count)
    }

    /// Emit ascending expired IDs into bounded caller storage; short output is atomic.
    pub fn expire_into(
        &mut self,
        now_ticks: u64,
        expired: &mut [MessageId],
    ) -> Result<usize, FragmentError> {
        if self.last_time.is_some_and(|last| now_ticks < last) {
            return Err(FragmentError::TimeWentBackwards);
        }
        let count = self
            .pending
            .values()
            .filter(|entry| now_ticks >= entry.deadline)
            .count();
        if expired.len() < count {
            return Err(FragmentError::OutputTooSmall);
        }
        if self.storage_usage.is_none() {
            let values = self.expire(now_ticks)?;
            expired[..count].copy_from_slice(&values);
            return Ok(count);
        }
        self.collect_expired(now_ticks)?;
        expired[..count].copy_from_slice(&self.expired_scratch);
        self.expire_count(now_ticks)
    }
    fn collect_expired(&mut self, now_ticks: u64) -> Result<(), FragmentError> {
        if self.last_time.is_some_and(|last| now_ticks < last) {
            return Err(FragmentError::TimeWentBackwards);
        }
        let count = self
            .pending
            .values()
            .filter(|entry| now_ticks >= entry.deadline)
            .count();
        if count > self.expired_scratch.capacity() {
            return Err(FragmentError::Arithmetic);
        }
        self.expired_scratch.clear();
        self.expired_scratch.extend(
            self.pending
                .iter()
                .filter_map(|(id, entry)| (now_ticks >= entry.deadline).then_some(*id)),
        );
        self.expired_scratch.sort_unstable();
        Ok(())
    }

    /// Earliest original incomplete-message expiry, without advancing time or state.
    pub fn deadline(&self) -> Option<u64> {
        self.pending.values().map(|entry| entry.deadline).min()
    }

    /// Bytes reserved for entire incomplete records, including missing fragments.
    pub fn reserved_bytes(&self) -> usize {
        self.reserved_bytes
    }

    /// Fragment slots reserved for incomplete records, including missing fragments.
    pub fn reserved_fragments(&self) -> usize {
        self.reserved_fragments
    }

    /// Number of incomplete messages currently retained.
    pub fn pending_messages(&self) -> usize {
        self.pending.len()
    }

    /// Number of bounded completion/expiry tombstones currently retained.
    pub fn retired_messages(&self) -> usize {
        self.retired.len()
    }

    fn accept_existing(
        &mut self,
        parsed: ParsedFragment<'_>,
        output: &mut [u8],
    ) -> Result<ReassemblyStatus, FragmentError> {
        let pending = self
            .pending
            .get_mut(&parsed.message)
            .ok_or(FragmentError::Arithmetic)?;
        if pending.buffer.len() != parsed.length
            || pending.count != parsed.count
            || pending.chunk != parsed.chunk
        {
            return Err(FragmentError::Conflict);
        }
        let end = parsed
            .offset
            .checked_add(parsed.body.len())
            .ok_or(FragmentError::Arithmetic)?;
        if *pending
            .present
            .get(usize::from(parsed.index))
            .ok_or(FragmentError::InvalidGeometry)?
            != 0
        {
            if pending.buffer.get(parsed.offset..end) != Some(parsed.body) {
                return Err(FragmentError::Conflict);
            }
            return Ok(ReassemblyStatus::Duplicate {
                message: parsed.message,
            });
        }
        let received = pending
            .received
            .checked_add(1)
            .ok_or(FragmentError::Arithmetic)?;
        let complete = received == pending.count;
        if complete && output.len() < parsed.length {
            return Err(FragmentError::OutputTooSmall);
        }
        write_fragment(pending, &parsed)?;
        pending.received = received;
        if !complete {
            return Ok(ReassemblyStatus::Pending {
                message: parsed.message,
                received,
                total: parsed.count,
            });
        }
        let destination = output
            .get_mut(..parsed.length)
            .ok_or(FragmentError::OutputTooSmall)?;
        self.release_pending(parsed.message, Some(destination))?;
        self.retired.insert(parsed.message)?;
        Ok(ReassemblyStatus::Complete {
            message: parsed.message,
            length: parsed.length,
        })
    }

    fn release_pending(
        &mut self,
        message: MessageId,
        output: Option<&mut [u8]>,
    ) -> Result<(), FragmentError> {
        let pending = self
            .pending
            .get(&message)
            .ok_or(FragmentError::Arithmetic)?;
        let reserved_bytes = self
            .reserved_bytes
            .checked_sub(pending.buffer.len())
            .ok_or(FragmentError::Arithmetic)?;
        let reserved_fragments = self
            .reserved_fragments
            .checked_sub(usize::from(pending.count))
            .ok_or(FragmentError::Arithmetic)?;
        self.pending.release(message, output)?;
        self.reserved_bytes = reserved_bytes;
        self.reserved_fragments = reserved_fragments;
        Ok(())
    }

    fn window_floor(&self, highest: MessageId) -> u64 {
        // Constructor bounds the width to 1..=65536, representable on all targets.
        highest
            .0
            .saturating_sub((self.config.replay_window - 1) as u64)
    }

    fn advance_window(&mut self, high: MessageId) {
        let floor = self.window_floor(high);
        self.retired.retain_floor(floor);
        self.highest = Some(high);
    }

    fn parse<'a>(&self, fragment: &'a [u8]) -> Result<ParsedFragment<'a>, FragmentError> {
        let header = fragment
            .get(..FRAGMENT_HEADER_BYTES)
            .ok_or(FragmentError::Truncated)?;
        if header.get(..2) != Some(b"LX") || header[2] != 1 || header[3] != 0 {
            return Err(FragmentError::InvalidHeader);
        }
        if read_u64(header, 4)? != self.context.session.0
            || read_u64(header, 12)? != self.context.epoch.0
        {
            return Err(FragmentError::WrongContext);
        }
        let message = MessageId(read_u64(header, 20)?);
        let length = usize::try_from(u32::from_be_bytes(read_array(header, 28)?))
            .map_err(|_| FragmentError::Arithmetic)?;
        let index = read_u16(header, 32)?;
        let count = read_u16(header, 34)?;
        let chunk = read_u16(header, 36)?;
        let payload_length = usize::from(read_u16(header, 38)?);
        if length == 0 || length > self.config.max_message_bytes {
            return Err(FragmentError::MessageTooLarge);
        }
        if count > self.config.max_fragments_per_message {
            return Err(FragmentError::TooManyFragments);
        }
        if count == 0
            || chunk == 0
            || chunk > self.config.max_fragment_payload_bytes
            || index >= count
            || length.div_ceil(usize::from(chunk)) != usize::from(count)
        {
            return Err(FragmentError::InvalidGeometry);
        }
        let offset = usize::from(index)
            .checked_mul(usize::from(chunk))
            .ok_or(FragmentError::Arithmetic)?;
        let remaining = length
            .checked_sub(offset)
            .ok_or(FragmentError::InvalidGeometry)?;
        let body = fragment
            .get(FRAGMENT_HEADER_BYTES..)
            .ok_or(FragmentError::Truncated)?;
        if payload_length != remaining.min(usize::from(chunk)) || body.len() != payload_length {
            return Err(FragmentError::InvalidGeometry);
        }
        Ok(ParsedFragment {
            message,
            length,
            index,
            count,
            chunk,
            offset,
            body,
        })
    }
}

fn write_fragment(pending: &mut Pending, parsed: &ParsedFragment<'_>) -> Result<(), FragmentError> {
    let end = parsed
        .offset
        .checked_add(parsed.body.len())
        .ok_or(FragmentError::Arithmetic)?;
    let destination = pending
        .buffer
        .get_mut(parsed.offset..end)
        .ok_or(FragmentError::InvalidGeometry)?;
    let present = pending
        .present
        .get_mut(usize::from(parsed.index))
        .ok_or(FragmentError::InvalidGeometry)?;
    destination.copy_from_slice(parsed.body);
    *present = 1;
    Ok(())
}

fn read_array<const N: usize>(bytes: &[u8], offset: usize) -> Result<[u8; N], FragmentError> {
    let end = offset.checked_add(N).ok_or(FragmentError::Arithmetic)?;
    bytes
        .get(offset..end)
        .ok_or(FragmentError::Truncated)?
        .try_into()
        .map_err(|_| FragmentError::Truncated)
}

fn read_u64(bytes: &[u8], offset: usize) -> Result<u64, FragmentError> {
    Ok(u64::from_be_bytes(read_array(bytes, offset)?))
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, FragmentError> {
    Ok(u16::from_be_bytes(read_array(bytes, offset)?))
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod storage_tests;
