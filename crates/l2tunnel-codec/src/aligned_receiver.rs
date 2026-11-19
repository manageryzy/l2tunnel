//! Bounded channel/fragment ordering for authenticated aligned symbols.
//!
//! Authentication is a caller precondition. The enclosing protocol must cover the
//! complete symbol and its absolute identity, including its inner channel byte.
//! No runtime, coding engine, device, clock or local epoch reset is provided.

use crate::aligned_body::{self, Decoder, Padding};
use l2tunnel_core::Epoch;
use std::{fmt, mem::size_of};

#[path = "aligned_receiver/cache.rs"]
mod cache;
use cache::{DeadlineCache, Retention};
mod preview;
use preview::Preview;

/// Absolute nonwrapping source identity, retained through retransmission/recovery.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SourceId(pub u64);
/// Absolute nonwrapping record identity; inner serial is only its low 16 bits.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct RecordId(pub u64);
/// Common MUX channel, never a privileged probe/control path.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ChannelId(pub u8);
/// Absolute identity of one channel record; native bodies exclude context records.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecordIdentity {
    /// Common MUX channel assigned by the original sender.
    pub channel: ChannelId,
    /// Nonwrapping channel record allocated by the original sender.
    pub record: RecordId,
}
/// One structurally validated original coding unit, not a send confirmation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UnitWitness {
    /// Context or native body identity; the admission owner distinguishes them.
    pub identity: RecordIdentity,
    /// Zero-based original fragment index; unfragmented bodies use zero.
    pub index: usize,
    /// Complete original fragment count; unfragmented bodies use one.
    pub count: usize,
}
/// Caller-injected monotonic time unit.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct Tick(pub u64);
/// Authenticated endpoint direction, independent of physical carrier lanes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Direction {
    /// Initiating peer to responding peer.
    InitiatorToResponder,
    /// Responding peer to initiating peer.
    ResponderToInitiator,
}
/// Immutable identity of one isolated decoding context pool.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Scope {
    /// Nonzero authenticated session.
    pub session: [u8; 16],
    /// Negotiated configuration generation; no local implicit reset is allowed.
    pub epoch: Epoch,
    /// Authenticated data direction.
    pub direction: Direction,
}
/// Metadata that the enclosing authenticator must bind to the complete symbol.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SymbolIdentity {
    /// Expected session, epoch and direction.
    pub scope: Scope,
    /// Stable absolute source identity.
    pub source: SourceId,
    /// Absolute record identity shared by all record fragments.
    pub record: RecordId,
}
/// Finite shared lookahead plus a reserved progress slot for every channel head.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Limits {
    /// Body format, including native and symbol bounds and generic short threshold.
    pub body: aligned_body::Config,
    /// Configured common channel count, in 1..=256.
    pub channels: u16,
    /// Initial absolute record number for each channel, negotiated before data.
    pub first_record: RecordId,
    /// Initial absolute source identity for this scope.
    pub first_source: SourceId,
    /// Maximum forward distance from each expected record, in 1..=32767.
    pub record_window: u16,
    /// Source slots ahead of the contiguous admitted floor, in 1..=65536.
    pub source_window: usize,
    /// Complete/incomplete future records, excluding reserved channel-head slots.
    pub lookahead_records: usize,
    /// Full body bytes reserved for future records, including retained tombstones.
    pub lookahead_bytes: usize,
    /// Fragment bitmap slots reserved for future fragmented records.
    pub lookahead_fragments: usize,
    /// Maximum fragments reserved by any one record, in 1..=65535.
    pub max_fragments_per_record: usize,
    /// First-arrival lifetime for records/source-hole proofs; duplicates cannot renew it.
    pub lifetime_ticks: u64,
}
impl Limits {
    /// Historical allocating-owner scalar bound, excluding allocator overhead.
    /// The separate complete ReceiverPlan counts actual reserved versions and journals.
    pub fn memory_bound_bytes(self) -> Result<usize, Error> {
        self.body.body_capacity().map_err(Error::Body)?;
        if !(1..=256).contains(&self.channels)
            || !(1..=32767).contains(&self.record_window)
            || !(1..=65536).contains(&self.source_window)
            || self.lookahead_records > 4096
            || self.lookahead_bytes > 128 * 1024 * 1024
            || self.lookahead_fragments > 1_048_576
            || !(1..=65535).contains(&self.max_fragments_per_record)
            || self.lifetime_ticks == 0
        {
            return Err(Error::Configuration);
        }
        let channels = usize::from(self.channels);
        let products = [
            (
                channels,
                65535 + self.max_fragments_per_record + size_of::<LegacyChannel>(),
            ),
            (
                self.source_window,
                self.body.symbol_bytes + size_of::<Option<Proof>>(),
            ),
            (
                channels + self.lookahead_records,
                size_of::<Option<Record>>(),
            ),
            (channels + 1, 2 * self.body.max_frame_bytes + 44),
        ];
        let mut total = self
            .lookahead_bytes
            .checked_add(self.lookahead_fragments)
            .and_then(|n| n.checked_add(self.body.max_frame_bytes))
            .and_then(|n| n.checked_add(65_535))
            .and_then(|n| n.checked_add(size_of::<LegacyLayout>()))
            .ok_or(Error::Configuration)?;
        for (count, width) in products {
            total = count
                .checked_mul(width)
                .and_then(|n| total.checked_add(n))
                .ok_or(Error::Configuration)?;
        }
        if total > 256 * 1024 * 1024 {
            return Err(Error::Configuration);
        }
        Ok(total)
    }

    /// Conservative reservation for optional atomic admission of up to 255 symbols.
    /// Includes one bounded ledger backup, but excludes allocator/caller input storage.
    /// Ordinary receiver configurations may exceed this optional 256 MiB ceiling.
    pub fn batch_memory_bound_bytes(self) -> Result<usize, Error> {
        self.memory_bound_bytes()?
            .checked_mul(2)
            .and_then(|bytes| bytes.checked_add(255 * size_of::<Admission>()))
            .filter(|bytes| *bytes <= 256 * 1024 * 1024)
            .ok_or(Error::Configuration)
    }
}
/// Admission, ordering, capacity and fail-closed lifecycle error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// Invalid local bounds or zero session identity.
    Configuration,
    /// Wrong authenticated session, epoch or direction.
    Scope,
    /// Invalid channel, serial identity, geometry, padding or record syntax.
    Malformed,
    /// Changed bytes/identity for an existing source, record or fragment.
    Conflict,
    /// Forward record window exceeded; no state changed.
    RecordWindow,
    /// Source window would evict an unresolved lower source; no state changed.
    SourceWindow,
    /// Bounded future record/byte/fragment admission is full; heads retain a reserve.
    Capacity,
    /// Absolute source or record space has ended; it cannot wrap.
    Exhausted,
    /// Time moved backward or a first-arrival deadline cannot be represented.
    Time,
    /// An unresolved source hole/record/native delivery expired; the scope is terminal.
    Expired,
    /// Body semantics failed when ordered context became available; scope is terminal.
    Body(aligned_body::Error),
    /// No prepared native frame is waiting for actual device acceptance.
    NoPending,
    /// Optional semantic preflight found a complete record behind a missing context/head.
    UnresolvedContext,
    /// Caller batch outcome storage cannot hold every unit.
    OutputTooSmall,
    /// A caller-owned returned outcome allocation failed.
    Allocation,
    /// Reserved backing contradicted its checked capacity or ownership inventory.
    Storage,
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "aligned receiver: {self:?}")
    }
}
impl std::error::Error for Error {}
impl Error {
    /// Classify an actual receive refusal without changing its retry/failure semantics.
    pub const fn buffer_refusal(self) -> Option<crate::diagnostics::ReceiveBlock> {
        use crate::diagnostics::ReceiveBlock;
        match self {
            Self::RecordWindow => Some(ReceiveBlock::RecordWindow),
            Self::SourceWindow => Some(ReceiveBlock::SourceWindow),
            Self::Capacity => Some(ReceiveBlock::ReceiverResources),
            Self::UnresolvedContext => Some(ReceiveBlock::MissingContext),
            _ => None,
        }
    }
}
/// Distinct outcomes that never imply native device acceptance.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Admission {
    /// New source contribution retained (possibly a completed record).
    Accepted,
    /// Identical retained source or record contribution.
    Duplicate,
    /// Source predates the nonwrapping contiguous receipt floor.
    StaleSource,
    /// Absolute record already retired; a fresh source cannot redeliver it.
    StaleRecord,
}
/// Result of bounded per-channel preparation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Prepared {
    /// No complete eligible frame is currently available.
    Idle,
    /// Preparation consumed its allowance on contexts, tombstones or early eligibility checks.
    Progress,
    /// The immutable frame exposed by `pending` awaits device acceptance.
    Ready,
}
/// Borrowed immutable native output; release only after whole-frame device acceptance.
#[derive(Debug)]
pub struct Delivery<'a> {
    /// Original channel whose ordinary FIFO is retained.
    pub channel: ChannelId,
    /// Absolute record identity.
    pub record: RecordId,
    /// True only for an explicitly allowed generic short frame ahead of a gap.
    pub early: bool,
    /// Complete reconstructed native bytes.
    pub bytes: &'a [u8],
}
/// Finite retention accounting; excludes allocator bookkeeping.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Status {
    /// First unadmitted absolute source, or None after u64 exhaustion.
    pub source_floor: Option<SourceId>,
    /// Exact symbol proofs still needed above source holes.
    pub retained_sources: usize,
    /// All complete/incomplete records including early-delivery tombstones.
    pub retained_records: usize,
    /// Allocated record body bytes, including full fragment reservations.
    pub record_bytes: usize,
    /// Allocated received-fragment bitmap entries.
    pub fragment_slots: usize,
    /// Retained early-delivery markers awaiting contiguous retirement.
    pub early_tombstones: usize,
    /// Delivered records moved into compact replay storage (included in tombstones).
    pub compacted_records: usize,
    /// Reserved compact replay entries; data admission retains its original limit.
    pub compacted_record_capacity: usize,
    /// Retained not-yet-delivered native records; unknown fragment headers count conservatively.
    pub native_records: usize,
    /// One immutable prepared native frame length, if any.
    pub pending_bytes: Option<usize>,
    /// Sticky terminal expiry/semantic error.
    pub failure: Option<Error>,
}
/// One externally authenticated symbol borrowed for atomic ledger admission.
/// The selected exact-unit or padded geometry and existing identity rules apply.
pub struct AuthenticatedSymbol<'a> {
    /// Authenticated absolute symbol and record identity.
    pub identity: SymbolIdentity,
    /// Complete aligned symbol; the caller retains its storage.
    pub bytes: &'a [u8],
}

#[derive(Clone)]
struct Proof {
    source: SourceId,
    record: RecordId,
    bytes: Vec<u8>,
    deadline: Tick,
}
#[derive(Clone)]
struct Record {
    channel: ChannelId,
    id: RecordId,
    bytes: Vec<u8>,
    pieces: Vec<u8>,
    count: usize,
    fragment_capacity: usize,
    padding: Padding,
    deadline: Tick,
    early_delivered: bool,
    compacted: bool,
    // Immutable classification of the original unfragmented body. Lookahead
    // can skip ordinary records without following each body slab pointer.
    independent_short: bool,
    // Filtered delivery rejected this complete short frame until its ordinary turn.
    // Zero is eligible, MAX waits for channel order, other values are owner recheck tokens.
    defer_early: u64,
}
impl Record {
    fn complete(&self) -> bool {
        self.count == self.pieces.len()
    }
    fn native_pending(&self) -> bool {
        !self.early_delivered
            && (!matches!(self.bytes.first(), Some(0 | 8))
                || (!self.pieces.is_empty() && self.pieces.first().copied().unwrap_or(0) == 0))
    }
}
#[allow(dead_code)]
struct LegacyChannel {
    expected: Option<RecordId>,
    decoder: [u8; Decoder::legacy_inline_bytes()],
}
struct Channel {
    expected: Option<RecordId>,
    decoder: Decoder,
    preview: Option<Preview>,
}
#[derive(Clone, Copy)]
struct Pending {
    slot: usize,
    written: usize,
    early: bool,
    compact_after_write: bool,
}
enum EarlySelection<'a> {
    Any,
    Ordered,
    Filtered(&'a mut dyn FnMut(&[u8]) -> bool),
    Reevaluated {
        changed: &'a dyn Fn(u64) -> bool,
        decide: &'a dyn Fn(&[u8], bool) -> EarlyDecision,
        complete_packets: bool,
    },
}
/// Local eligibility of an independently decoded complete native frame.
pub enum EarlyDecision {
    /// Expose this frame now.
    Allow,
    /// Retain this record until channel order catches up.
    Ordered,
    /// Reconsider after an owner's dependency changes. Zero and MAX are reserved.
    Wait(u64),
}
struct Parsed<'a> {
    channel: ChannelId,
    body: &'a [u8],
    total: usize,
    offset: usize,
    fragments: usize,
    capacity: usize,
    padding: Padding,
}
impl Parsed<'_> {
    fn independent_short(&self, limit: usize) -> bool {
        limit > 0
            && self.fragments == 0
            && independent_length(self.body).is_some_and(|length| length <= limit)
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum ReceiverMode {
    Ethernet,
    Ip,
    IpEarlyReplay,
}

/// Finite receiver state with separate admission, preparation and actual delivery commit.
pub struct Receiver {
    scope: Scope,
    limits: Limits,
    compact_units: bool,
    compacted_slots: usize,
    mode: ReceiverMode,
    channels: Vec<Channel>,
    records: Vec<Option<Record>>,
    // Only occupied slots, in (channel, absolute record) order. Valid limits
    // allow at most 8,448 slots including compacted records. Payload owners
    // never move with this index.
    ordered_slots: Vec<u16>,
    proofs: Vec<Option<Proof>>,
    retention: Retention,
    deadlines: DeadlineCache,
    floor: Option<SourceId>,
    staged: Decoder,
    native: Vec<u8>,
    pending: Option<Pending>,
    last_time: Option<Tick>,
    failure: Option<Error>,
    reserved: Option<storage::Reserved>,
}
// Compatibility-only original field types; never used as reservation authority.
#[allow(dead_code)]
struct LegacyLayout {
    scope: Scope,
    limits: Limits,
    channels: Vec<Channel>,
    records: Vec<Option<Record>>,
    proofs: Vec<Option<Proof>>,
    floor: Option<SourceId>,
    staged: [u8; Decoder::legacy_inline_bytes()],
    native: Vec<u8>,
    pending: Option<Pending>,
    last_time: Option<Tick>,
    failure: Option<Error>,
}
impl Receiver {
    /// Compatibility-only original inline size for historical outer scalar guards.
    /// This is not actual owner capacity, a storage Plan, or an observed Usage.
    pub const fn legacy_inline_bytes() -> usize {
        size_of::<LegacyLayout>()
    }
    /// Validate all fixed allocation products and reserve progress independently of lookahead.
    pub fn new(scope: Scope, limits: Limits) -> Result<Self, Error> {
        Self::new_mode(scope, limits, ReceiverMode::Ethernet)
    }
    /// Native-IP contexts/deltas use the same channel/record/native ownership FSM.
    pub fn new_ip(scope: Scope, limits: Limits) -> Result<Self, Error> {
        Self::new_mode(scope, limits, ReceiverMode::Ip)
    }
    /// Native IP with bounded compact replay slots for early physical delivery.
    pub fn new_ip_with_early_replay(scope: Scope, limits: Limits) -> Result<Self, Error> {
        Self::new_mode(scope, limits, ReceiverMode::IpEarlyReplay)
    }
    // Public scalar limits remain stable for historical configurations and
    // digests. An allocating owner also reserves today's inline header state,
    // occupied-slot index and compact replay metadata. Its retained bodies
    // still share the original aggregate bytes/fragment allowance.
    fn owned_memory_bound(
        limits: Limits,
        reserve_replay: bool,
        batch: bool,
    ) -> Result<usize, Error> {
        let historical = limits.memory_bound_bytes()?;
        let channels = usize::from(limits.channels);
        let compacted = Self::compacted_capacity(limits, reserve_replay);
        let indexed = channels + limits.lookahead_records + compacted;
        // The validated limits admit at most 256 channels + 2 * 4096 records.
        u16::try_from(indexed).map_err(|_| Error::Configuration)?;
        let extra = size_of::<Self>().saturating_sub(size_of::<LegacyLayout>())
            + channels * size_of::<Channel>().saturating_sub(size_of::<LegacyChannel>())
            + compacted * size_of::<Option<Record>>()
            + indexed * size_of::<u16>();
        let single = historical.checked_add(extra).ok_or(Error::Configuration)?;
        let bound = if batch {
            single
                .checked_mul(2)
                .and_then(|n| n.checked_add(255 * size_of::<Admission>()))
                .ok_or(Error::Configuration)?
        } else {
            single
        };
        if bound > 256 * 1024 * 1024 {
            return Err(Error::Configuration);
        }
        Ok(bound)
    }
    fn new_mode(scope: Scope, limits: Limits, mode: ReceiverMode) -> Result<Self, Error> {
        let ip = mode != ReceiverMode::Ethernet;
        let reserve_replay = mode == ReceiverMode::IpEarlyReplay;
        Self::owned_memory_bound(limits, reserve_replay, false)?;
        if scope.session == [0; 16] {
            return Err(Error::Configuration);
        }
        let mut channels = Vec::with_capacity(usize::from(limits.channels));
        for _ in 0..limits.channels {
            channels.push(Channel {
                expected: Some(limits.first_record),
                preview: None,
                decoder: if ip {
                    Decoder::new_ip(limits.body)
                } else {
                    Decoder::new(limits.body)
                }
                .map_err(Error::Body)?,
            });
        }
        let compacted_slots = Self::compacted_capacity(limits, reserve_replay);
        let slots = usize::from(limits.channels) + limits.lookahead_records + compacted_slots;
        let mut records = Vec::with_capacity(slots);
        records.resize_with(slots, || None);
        let mut proofs = Vec::with_capacity(limits.source_window);
        proofs.resize_with(limits.source_window, || None);
        Ok(Self {
            scope,
            limits,
            compact_units: false,
            compacted_slots,
            mode,
            channels,
            ordered_slots: Vec::with_capacity(records.len()),
            records,
            proofs,
            retention: Retention::default(),
            deadlines: DeadlineCache::default(),
            floor: Some(limits.first_source),
            staged: if ip {
                Decoder::new_ip(limits.body)
            } else {
                Decoder::new(limits.body)
            }
            .map_err(Error::Body)?,
            native: vec![0; limits.body.max_frame_bytes],
            pending: None,
            last_time: None,
            failure: None,
            reserved: None,
        })
    }
    /// Preflight exact-unit parsing before this receiver has accepted time or input.
    /// The enclosing authenticated configuration selects the wire grammar.
    pub fn validate_compact_units_selection(&self) -> Result<(), Error> {
        if self.last_time.is_some()
            || self.pending.is_some()
            || self.failure.is_some()
            || self.floor != Some(self.limits.first_source)
            || self.records.iter().any(Option::is_some)
            || self.proofs.iter().any(Option::is_some)
            || self.channels.iter().any(|channel| {
                channel.expected != Some(self.limits.first_record) || channel.decoder.has_context()
            })
        {
            return Err(Error::Configuration);
        }
        Ok(())
    }
    /// Select exact meaningful units without allocating or changing retained limits.
    /// Implicit bodies retain their real length for later context-aware decoding.
    /// Repeating selection is idempotent only before any time or input is accepted.
    pub fn enable_compact_units(&mut self) -> Result<(), Error> {
        self.validate_compact_units_selection()?;
        self.compact_units = true;
        Ok(())
    }
    fn parse_unit<'a>(&self, symbol: &'a [u8], record: RecordId) -> Result<Parsed<'a>, Error> {
        if self.compact_units {
            parse_compact(symbol, record, self.limits)
        } else {
            parse(symbol, record, self.limits)
        }
    }
    /// Expected absolute record; None means this channel consumed its last u64 ID.
    pub fn expected(&self, channel: ChannelId) -> Result<Option<RecordId>, Error> {
        self.channels
            .get(usize::from(channel.0))
            .map(|c| c.expected)
            .ok_or(Error::Malformed)
    }
    /// Admit 1..=255 authenticated symbols as one bounded ledger transaction.
    ///
    /// Any unit failure restores all record/source admission and accepted time.
    /// Preexisting expiry remains terminal. Decoder contexts and prepared native
    /// ownership are unchanged; context-dependent body decoding still occurs in
    /// `prepare`, and native acceptance still requires `commit_delivery`.
    pub fn admit_batch_authenticated(
        &mut self,
        symbols: &[AuthenticatedSymbol<'_>],
        now: Tick,
    ) -> Result<Vec<Admission>, Error> {
        if self.reserved.is_some() {
            return self.reserved_owned_batch(symbols, now, false);
        }
        if !(1..=255).contains(&symbols.len()) {
            return Err(Error::Configuration);
        }
        Self::owned_memory_bound(self.limits, self.mode == ReceiverMode::IpEarlyReplay, true)?;
        self.check_time(now)?;
        let records = self.records.clone();
        let ordered_slots = self.ordered_slots.clone();
        let proofs = self.proofs.clone();
        let floor = self.floor;
        let last_time = self.last_time;
        let retention = self.retention;
        let deadlines = self.deadlines.checkpoint();
        let mut outcomes = Vec::with_capacity(symbols.len());
        for symbol in symbols {
            match self.admit_authenticated(symbol.identity, symbol.bytes, now) {
                Ok(outcome) => outcomes.push(outcome),
                Err(error) => {
                    self.records = records;
                    self.ordered_slots.clone_from(&ordered_slots);
                    self.proofs = proofs;
                    self.floor = floor;
                    self.last_time = last_time;
                    self.retention = retention;
                    self.deadlines.restore(deadlines);
                    return Err(error);
                }
            }
        }
        Ok(outcomes)
    }
    /// Preflight every complete retained body before atomically admitting a batch.
    ///
    /// All decoding and simulated native commits occur in one private bounded
    /// shadow. Semantic errors leave live contexts, ledgers and pending native
    /// bytes unchanged. A complete body behind an unresolved record/context gap
    /// is rejected; incomplete fragment tails may remain reserved. This does not
    /// make later native device writes atomic or grant any delivery credit.
    pub fn admit_validated_batch_authenticated(
        &mut self,
        symbols: &[AuthenticatedSymbol<'_>],
        now: Tick,
    ) -> Result<Vec<Admission>, Error> {
        if self.reserved.is_some() {
            return self.reserved_owned_batch(symbols, now, true);
        }
        if !(1..=255).contains(&symbols.len()) {
            return Err(Error::Configuration);
        }
        Self::owned_memory_bound(self.limits, self.mode == ReceiverMode::IpEarlyReplay, true)?;
        self.check_time(now)?;
        let mut shadow = self.validation_shadow()?;
        for symbol in symbols {
            shadow.admit_authenticated(symbol.identity, symbol.bytes, now)?;
        }
        if shadow.pending.is_some() {
            shadow.commit_delivery(now)?;
        }
        let mut work = shadow.records.len() + shadow.channels.len();
        for channel in 0..shadow.limits.channels {
            loop {
                if work == 0 {
                    return Err(Error::UnresolvedContext);
                }
                work -= 1;
                match shadow.prepare(ChannelId(channel as u8), now, 1)? {
                    Prepared::Idle => break,
                    Prepared::Progress => {}
                    Prepared::Ready => shadow.commit_delivery(now)?,
                }
            }
        }
        if shadow
            .records
            .iter()
            .flatten()
            .any(|record| record.complete() && !record.early_delivered)
        {
            return Err(Error::UnresolvedContext);
        }
        // Do not overlap this full shadow with the existing ledger rollback copy.
        drop(shadow);
        self.admit_batch_authenticated(symbols, now)
    }
    fn validation_shadow(&self) -> Result<Self, Error> {
        let mut shadow = Self::new_mode(self.scope, self.limits, self.mode)?;
        shadow.compact_units = self.compact_units;
        for (target, source) in shadow.channels.iter_mut().zip(&self.channels) {
            target.expected = source.expected;
            target.preview.clone_from(&source.preview);
            target.decoder.copy_context_from(&source.decoder);
        }
        shadow.records.clone_from(&self.records);
        shadow.ordered_slots.extend_from_slice(&self.ordered_slots);
        shadow.proofs.clone_from(&self.proofs);
        shadow.floor = self.floor;
        shadow.staged.copy_context_from(&self.staged);
        shadow.native.copy_from_slice(&self.native);
        shadow.pending = self.pending;
        shadow.last_time = self.last_time;
        shadow.failure = self.failure;
        shadow.retention = self.retention;
        shadow.deadlines.restore(self.deadlines.checkpoint());
        Ok(shadow)
    }
    /// Classify a complete symbol using this receiver's actual scope and parser.
    /// Only an unfragmented self-contained raw/LZ4 frame within the explicitly
    /// configured generic size limit qualifies. This grants no authentication,
    /// admission or native credit and changes no receiver state.
    pub fn is_independent_short(
        &self,
        identity: SymbolIdentity,
        symbol: &[u8],
    ) -> Result<bool, Error> {
        if identity.scope != self.scope {
            return Err(Error::Scope);
        }
        let parsed = self.parse_unit(symbol, identity.record)?;
        Ok(parsed.independent_short(self.limits.body.independent_short_frame_bytes))
    }
    /// Inspect this scope's source ledger in constant time without admitting bytes.
    ///
    /// True means the source is below the contiguous admission floor or has a
    /// retained proof with that complete source identity. This grants no payload
    /// authentication or native delivery authority. A caller may skip repeated
    /// admission only when it already owns the identical immutable payload and
    /// independently services the receiver's original deadlines.
    pub fn source_observed(&self, scope: Scope, source: SourceId) -> Result<bool, Error> {
        if scope != self.scope {
            return Err(Error::Scope);
        }
        if let Some(error) = self.failure {
            return Err(error);
        }
        let floor = self.floor.ok_or(Error::Exhausted)?;
        if source.0 < floor.0 {
            return Ok(true);
        }
        let slot = (source.0 % self.limits.source_window as u64) as usize;
        Ok(self.proofs[slot]
            .as_ref()
            .is_some_and(|proof| proof.source == source))
    }
    /// Validate an authenticated preview unit and identify a missing current channel head.
    /// A retained proof must match exactly, even for units outside the selected heads.
    pub fn needs_channel_head(
        &self,
        identity: SymbolIdentity,
        symbol: &[u8],
    ) -> Result<bool, Error> {
        if identity.scope != self.scope {
            return Err(Error::Scope);
        }
        if let Some(error) = self.failure {
            return Err(error);
        }
        let parsed = self.parse_unit(symbol, identity.record)?;
        let floor = self.floor.ok_or(Error::Exhausted)?;
        if identity.source.0 < floor.0 {
            return Ok(false);
        }
        if identity.source.0 - floor.0 >= self.limits.source_window as u64 {
            // The floor can move after earlier units in the retained source drain.
            return Ok(false);
        }
        let slot = (identity.source.0 % self.limits.source_window as u64) as usize;
        if let Some(proof) = &self.proofs[slot] {
            if proof.source != identity.source
                || proof.record != identity.record
                || proof.bytes != symbol
            {
                return Err(Error::Conflict);
            }
            return Ok(false);
        }
        Ok(self.expected(parsed.channel)? == Some(identity.record))
    }
    /// Admit one authenticated complete protected symbol; errors consume no source ID.
    pub fn admit_authenticated(
        &mut self,
        identity: SymbolIdentity,
        symbol: &[u8],
        now: Tick,
    ) -> Result<Admission, Error> {
        if identity.scope != self.scope {
            return Err(Error::Scope);
        }
        self.check_time(now)?;
        let floor = self.floor.ok_or(Error::Exhausted)?;
        if identity.source.0 < floor.0 {
            self.last_time = Some(now);
            return Ok(Admission::StaleSource);
        }
        if identity.source.0 - floor.0 >= self.limits.source_window as u64 {
            return Err(Error::SourceWindow);
        }
        let proof_slot = (identity.source.0 % self.limits.source_window as u64) as usize;
        if let Some(proof) = &self.proofs[proof_slot] {
            if proof.source == identity.source
                && proof.record == identity.record
                && proof.bytes == symbol
            {
                self.last_time = Some(now);
                return Ok(Admission::Duplicate);
            }
            return Err(Error::Conflict);
        }
        let parsed = self.parse_unit(symbol, identity.record)?;
        let expected = self.expected(parsed.channel)?.ok_or(Error::Exhausted)?;
        let deadline = Tick(
            now.0
                .checked_add(self.limits.lifetime_ticks)
                .ok_or(Error::Time)?,
        );
        let outcome = if identity.record < expected {
            Admission::StaleRecord
        } else {
            if identity.record.0 - expected.0 > u64::from(self.limits.record_window) {
                return Err(Error::RecordWindow);
            }
            match self.record_position(parsed.channel, identity.record) {
                Ok(position) => {
                    let slot = usize::from(self.ordered_slots[position]);
                    let existing = self.records[slot].as_ref().ok_or(Error::Malformed)?;
                    if existing.bytes.len() != parsed.total
                        || existing.fragment_capacity != parsed.capacity
                        || existing.padding != parsed.padding
                    {
                        return Err(Error::Conflict);
                    }
                    if parsed.fragments == 0 {
                        if existing.bytes != parsed.body {
                            return Err(Error::Conflict);
                        }
                        Admission::Duplicate
                    } else {
                        let index = parsed.offset / parsed.capacity;
                        let end = parsed.offset + parsed.body.len();
                        if existing.pieces[index] != 0 {
                            if existing.bytes[parsed.offset..end] != *parsed.body {
                                return Err(Error::Conflict);
                            }
                            Admission::Duplicate
                        } else {
                            // The final fragment is validated in a bounded temporary copy
                            // before changing the admitted record or replay ledger.
                            if existing.count + 1 == parsed.fragments {
                                self.validate_completion(slot, parsed.offset, parsed.body)?;
                            }
                            self.touch_record(slot, true)?;
                            let entry = self.records[slot].as_mut().ok_or(Error::Malformed)?;
                            let was_native = entry.native_pending();
                            entry.bytes[parsed.offset..end].copy_from_slice(parsed.body);
                            entry.pieces[index] = 1;
                            entry.count += 1;
                            self.retention.native_records -= usize::from(was_native);
                            self.retention.native_records += usize::from(entry.native_pending());
                            Admission::Accepted
                        }
                    }
                }
                Err(position) => {
                    self.reserve(
                        parsed.channel,
                        identity.record,
                        parsed.total,
                        parsed.fragments,
                    )?;
                    let slot = self
                        .records
                        .iter()
                        .position(Option::is_none)
                        .ok_or(Error::Capacity)?;
                    self.touch_record(slot, false)?;
                    let (mut bytes, mut pieces) =
                        self.record_buffers(parsed.total, parsed.fragments)?;
                    bytes[parsed.offset..parsed.offset + parsed.body.len()]
                        .copy_from_slice(parsed.body);
                    if parsed.fragments != 0 {
                        pieces[parsed.offset / parsed.capacity] = 1;
                    }
                    let record = Record {
                        channel: parsed.channel,
                        id: identity.record,
                        bytes,
                        pieces,
                        count: usize::from(parsed.fragments != 0),
                        fragment_capacity: parsed.capacity,
                        padding: parsed.padding,
                        deadline,
                        early_delivered: false,
                        compacted: false,
                        independent_short: parsed
                            .independent_short(self.limits.body.independent_short_frame_bytes),
                        defer_early: 0,
                    };
                    self.retention.add_record(&record);
                    self.deadlines.insert(record.deadline);
                    self.records[slot] = Some(record);
                    self.ordered_slots.insert(position, slot as u16);
                    Admission::Accepted
                }
            }
        };
        self.touch_proof(proof_slot)?;
        let bytes = self.proof_buffer(symbol)?;
        let proof = Proof {
            source: identity.source,
            record: identity.record,
            bytes,
            deadline,
        };
        self.retention.add_proof(&proof);
        self.proofs[proof_slot] = Some(proof);
        self.deadlines.insert(deadline);
        self.advance_sources()?;
        self.last_time = Some(now);
        Ok(outcome)
    }
    /// Process at most `max_records` context/tombstone/frame records on one channel.
    /// Existing pending bytes always remain immutable under consumer backpressure.
    pub fn prepare(
        &mut self,
        channel: ChannelId,
        now: Tick,
        max_records: usize,
    ) -> Result<Prepared, Error> {
        self.prepare_selected(channel, now, max_records, EarlySelection::Any)
    }
    /// Select independent short frames using their exact reconstructed native bytes.
    /// Rejected records wait for their channel head on subsequent filtered calls.
    /// Examining one candidate consumes one record visit. Other records on the
    /// channel can still be considered within the allowance or on a later call.
    /// The ordered head and an already prepared immutable delivery bypass the filter.
    pub fn prepare_with_early_filter(
        &mut self,
        channel: ChannelId,
        now: Tick,
        max_records: usize,
        mut allow: impl FnMut(&[u8]) -> bool,
    ) -> Result<Prepared, Error> {
        self.prepare_selected(
            channel,
            now,
            max_records,
            EarlySelection::Filtered(&mut allow),
        )
    }
    /// Reconsider deferred complete records when their local dependency changes.
    /// A negative decision keeps the retained bytes and original deadline.
    pub fn prepare_with_early_dependencies(
        &mut self,
        channel: ChannelId,
        now: Tick,
        max_records: usize,
        changed: impl Fn(u64) -> bool,
        decide: impl Fn(&[u8]) -> EarlyDecision,
    ) -> Result<Prepared, Error> {
        self.prepare_selected(
            channel,
            now,
            max_records,
            EarlySelection::Reevaluated {
                changed: &changed,
                decide: &|frame, _| decide(frame),
                complete_packets: false,
            },
        )
    }
    /// Consider complete raw or stateless LZ4 bodies, including reassembled
    /// fragments, and deltas with a complete contiguous chain from an explicit
    /// native IP context. The predicate also receives the original independent-
    /// short classification. The ordered codec frontier advances separately.
    pub fn prepare_with_independent_packets(
        &mut self,
        channel: ChannelId,
        now: Tick,
        max_records: usize,
        changed: impl Fn(u64) -> bool,
        decide: impl Fn(&[u8], bool) -> EarlyDecision,
    ) -> Result<Prepared, Error> {
        self.prepare_selected(
            channel,
            now,
            max_records,
            EarlySelection::Reevaluated {
                changed: &changed,
                decide: &decide,
                complete_packets: true,
            },
        )
    }
    /// Preserve channel FIFO even when independent short bodies are enabled.
    /// Already exposed native bytes retain custody until their original commit.
    pub fn prepare_ordered(
        &mut self,
        channel: ChannelId,
        now: Tick,
        max_records: usize,
    ) -> Result<Prepared, Error> {
        self.prepare_selected(channel, now, max_records, EarlySelection::Ordered)
    }
    fn prepare_selected(
        &mut self,
        channel: ChannelId,
        now: Tick,
        max_records: usize,
        mut selection: EarlySelection<'_>,
    ) -> Result<Prepared, Error> {
        self.check_time(now)?;
        self.expected(channel)?;
        self.last_time = Some(now);
        if self.pending.is_some() {
            return Ok(Prepared::Ready);
        }
        let mut remaining = max_records;
        while remaining > 0 {
            if self.retention.records == 0 {
                return Ok(Prepared::Idle);
            }
            let expected = match self.expected(channel)? {
                Some(id) => id,
                None => return Ok(Prepared::Idle),
            };
            let Some((position, anchor)) = self.select_record(channel, expected, &selection)?
            else {
                return Ok(Prepared::Idle);
            };
            let slot = usize::from(self.ordered_slots[position]);
            let index = usize::from(channel.0);
            if let Some(anchor) = anchor {
                if !self.stage_prefix(index, anchor, position, &mut remaining)? {
                    return Ok(Prepared::Progress);
                }
            } else {
                self.staged.copy_context_from(&self.channels[index].decoder);
            }
            remaining -= 1;
            let entry = self.records[slot].as_ref().ok_or(Error::Malformed)?;
            let early = entry.id != expected;
            let independent_short = entry.independent_short;
            let delivered = entry.early_delivered;
            if delivered && independent_length(&entry.bytes).is_some() {
                self.retire(slot)?;
                continue;
            }
            let decoded = self.decode_slot(slot)?;
            if let Some(anchor) = anchor {
                self.cache_preview(index, anchor, position)?;
            }
            if delivered {
                // Linux already accepted this frame. Its ordered header transition
                // must still reach the canonical decoder for the next delta.
                self.touch_channel(index)?;
                self.channels[index].decoder.copy_context_from(&self.staged);
                self.retire(slot)?;
                continue;
            }
            match decoded {
                aligned_body::Decoded::Context { .. } => {
                    self.touch_channel(usize::from(channel.0))?;
                    self.channels[usize::from(channel.0)]
                        .decoder
                        .copy_context_from(&self.staged);
                    self.retire(slot)?;
                }
                aligned_body::Decoded::Frame { written, .. } => {
                    let hold = if early {
                        match &mut selection {
                            EarlySelection::Filtered(allow) => {
                                if allow(&self.native[..written]) {
                                    0
                                } else {
                                    u64::MAX
                                }
                            }
                            EarlySelection::Reevaluated { decide, .. } => {
                                match decide(&self.native[..written], independent_short) {
                                    EarlyDecision::Allow => 0,
                                    EarlyDecision::Ordered => u64::MAX,
                                    EarlyDecision::Wait(token) => {
                                        if token == 0 {
                                            u64::MAX
                                        } else {
                                            token
                                        }
                                    }
                                }
                            }
                            _ => 0,
                        }
                    } else {
                        0
                    };
                    if hold != 0 {
                        self.touch_record(slot, true)?;
                        self.records[slot]
                            .as_mut()
                            .ok_or(Error::Malformed)?
                            .defer_early = hold;
                        continue;
                    }
                    self.pending = Some(Pending {
                        slot,
                        written,
                        early,
                        compact_after_write: early
                            && matches!(
                                selection,
                                EarlySelection::Reevaluated {
                                    complete_packets: true,
                                    ..
                                }
                            ),
                    });
                    return Ok(Prepared::Ready);
                }
            }
        }
        Ok(Prepared::Progress)
    }
    /// Borrow the same complete native frame until actual device acceptance commits it.
    pub fn pending(&self) -> Option<Delivery<'_>> {
        if self.failure.is_some() {
            return None;
        }
        let pending = self.pending?;
        let record = self.records[pending.slot].as_ref()?;
        Some(Delivery {
            channel: record.channel,
            record: record.id,
            early: pending.early,
            bytes: &self.native[..pending.written],
        })
    }
    /// Original expiry of the actual pending native record, excluding other work.
    pub fn pending_deadline(&self) -> Option<Tick> {
        if self.failure.is_some() {
            return None;
        }
        let pending = self.pending?;
        Some(self.records.get(pending.slot)?.as_ref()?.deadline)
    }
    /// Commit only after complete native-device acceptance; WouldBlock must not call this.
    pub fn commit_delivery(&mut self, now: Tick) -> Result<(), Error> {
        self.check_time(now)?;
        let pending = self.pending.ok_or(Error::NoPending)?;
        if pending.early {
            self.touch_record(pending.slot, true)?;
            let record = self.records[pending.slot]
                .as_mut()
                .ok_or(Error::Malformed)?;
            self.retention.native_records -= usize::from(record.native_pending());
            self.retention.tombstones += usize::from(!record.early_delivered);
            record.early_delivered = true;
            if pending.compact_after_write {
                self.compact_delivered(pending.slot)?;
            }
        } else {
            let channel = usize::from(
                self.records[pending.slot]
                    .as_ref()
                    .ok_or(Error::Malformed)?
                    .channel
                    .0,
            );
            self.touch_channel(channel)?;
            self.channels[channel]
                .decoder
                .copy_context_from(&self.staged);
            self.retire(pending.slot)?;
        }
        self.pending = None;
        self.last_time = Some(now);
        Ok(())
    }
    /// Check monotonic deadlines without silently discarding gaps or old context.
    pub fn tick(&mut self, now: Tick) -> Result<(), Error> {
        self.check_time(now)?;
        self.last_time = Some(now);
        Ok(())
    }
    /// Earliest retained record or source-hole deadline; native pending ownership is included.
    pub fn deadline(&self) -> Option<Tick> {
        if self.failure.is_some() {
            return None;
        }
        self.deadlines.get(
            self.records
                .iter()
                .flatten()
                .map(|record| record.deadline)
                .chain(self.proofs.iter().flatten().map(|proof| proof.deadline)),
        )
    }
    /// Inspect payload/count retention without advancing receipt or native delivery.
    pub fn status(&self) -> Status {
        Status {
            source_floor: self.floor,
            retained_sources: self.retention.sources,
            retained_records: self.retention.records,
            native_records: self.retention.native_records,
            record_bytes: self.retention.record_bytes,
            fragment_slots: self.retention.fragment_slots,
            early_tombstones: self.retention.tombstones,
            compacted_records: self.retention.compacted,
            compacted_record_capacity: self.compacted_slots,
            pending_bytes: self.pending.map(|p| p.written),
            failure: self.failure,
        }
    }
    /// Exact retained proofs and records, with one indexed head lookup per channel.
    pub fn buffer_snapshot(&self) -> crate::diagnostics::ReceiverBuffers {
        use crate::diagnostics::{ReceiverBuffers, Retention};
        let channels = usize::from(self.limits.channels);
        let mut result = ReceiverBuffers {
            source_proofs: Retention {
                items: self.retention.sources,
                bytes: self.retention.proof_bytes,
                item_capacity: self.limits.source_window,
                byte_capacity: self.limits.source_window * self.limits.body.symbol_bytes,
            },
            heads: Retention {
                item_capacity: channels,
                byte_capacity: channels * 65_535,
                ..Retention::default()
            },
            lookahead: Retention {
                item_capacity: self.limits.lookahead_records,
                byte_capacity: self.limits.lookahead_bytes,
                ..Retention::default()
            },
            compacted_records: self.retention.compacted,
            compacted_record_capacity: self.compacted_slots,
            head_fragments: 0,
            head_fragment_capacity: channels * self.limits.max_fragments_per_record,
            lookahead_fragments: 0,
            lookahead_fragment_capacity: self.limits.lookahead_fragments,
            pending_native_bytes: self.pending.map(|value| value.written),
            native_capacity_bytes: self.native.len(),
        };
        // The established retention bounds cover every head and lookahead row.
        // Only the record at each channel's current frontier belongs to its head reserve.
        if self.retention.records != 0 {
            for (index, channel) in self.channels.iter().enumerate() {
                if let Some(id) = channel.expected
                    && let Ok(position) = self.record_position(ChannelId(index as u8), id)
                    && let Some(record) = &self.records[usize::from(self.ordered_slots[position])]
                {
                    result.heads.items += usize::from(!record.compacted);
                    result.heads.bytes += record.bytes.len();
                    result.head_fragments += record.pieces.len();
                }
            }
        }
        result.lookahead.items =
            self.retention.records - self.retention.compacted - result.heads.items;
        result.lookahead.bytes = self.retention.record_bytes - result.heads.bytes;
        result.lookahead_fragments = self.retention.fragment_slots - result.head_fragments;
        result
    }
    /// First channel with retained records in round-robin order from `start`.
    /// Incomplete records, contexts and early-delivery tombstones all participate.
    pub fn next_retained_channel(&self, start: ChannelId) -> Option<ChannelId> {
        let position = match self.record_position(start, RecordId(0)) {
            Ok(index) | Err(index) => index,
        };
        let slot = self
            .ordered_slots
            .get(position)
            .or_else(|| self.ordered_slots.first())?;
        self.records[usize::from(*slot)].as_ref().map(|r| r.channel)
    }

    fn record_position(&self, channel: ChannelId, record: RecordId) -> Result<usize, usize> {
        self.ordered_slots
            .binary_search_by_key(&Some((channel.0, record)), |slot| {
                self.records[usize::from(*slot)]
                    .as_ref()
                    .map(|r| (r.channel.0, r.id))
            })
    }
    #[cfg(test)]
    fn find(&self, channel: ChannelId, record: RecordId) -> Option<usize> {
        self.record_position(channel, record)
            .ok()
            .map(|i| usize::from(self.ordered_slots[i]))
    }
    fn check_time(&mut self, now: Tick) -> Result<(), Error> {
        if let Some(error) = self.failure {
            return Err(error);
        }
        if self.last_time.is_some_and(|last| now < last) {
            return Err(Error::Time);
        }
        // An accepted tick already checked every retained deadline. Insertions
        // use this tick plus a strictly positive lifetime; removals cannot add
        // earlier deadlines. Batch rollback restores time with the old ledger.
        // Keep sticky failure and regression checks ahead of this fast path.
        if self.last_time == Some(now) {
            return Ok(());
        }
        if self.deadline().is_some_and(|deadline| now >= deadline) {
            self.failure = Some(Error::Expired);
            return Err(Error::Expired);
        }
        Ok(())
    }
    fn reserve(
        &self,
        channel: ChannelId,
        id: RecordId,
        bytes: usize,
        fragments: usize,
    ) -> Result<(), Error> {
        if Some(id) == self.expected(channel)? {
            return Ok(());
        }
        // Totals include all reserved channel heads. When even that upper
        // bound fits, excluding the heads cannot change the decision.
        if self.retention.records - self.retention.compacted < self.limits.lookahead_records
            && self
                .retention
                .record_bytes
                .checked_add(bytes)
                .is_some_and(|used| used <= self.limits.lookahead_bytes)
            && self
                .retention
                .fragment_slots
                .checked_add(fragments)
                .is_some_and(|used| used <= self.limits.lookahead_fragments)
        {
            return Ok(());
        }
        // At saturation the same source may be retried for every receive turn.
        // The indexed head reservations are also the ones excluded by the
        // public occupancy counters. Never walk every retained payload here.
        let snapshot = self.buffer_snapshot();
        if snapshot.lookahead.items >= self.limits.lookahead_records
            || bytes > self.limits.lookahead_bytes - snapshot.lookahead.bytes
            || fragments > self.limits.lookahead_fragments - snapshot.lookahead_fragments
        {
            Err(Error::Capacity)
        } else {
            Ok(())
        }
    }
    fn retire(&mut self, slot: usize) -> Result<(), Error> {
        let entry = self.records[slot].as_ref().ok_or(Error::Malformed)?;
        let index = usize::from(entry.channel.0);
        let id = entry.id;
        if self.channels[index].expected != Some(id) {
            return Err(Error::Malformed);
        }
        let position = self
            .record_position(entry.channel, id)
            .map_err(|_| Error::Malformed)?;
        self.touch_channel(index)?;
        self.touch_record(slot, false)?;
        self.ordered_slots.remove(position);
        self.channels[index].expected = id.0.checked_add(1).map(RecordId);
        if let Some(record) = self.records[slot].take() {
            self.retention.remove_record(&record);
            self.deadlines
                .remove(record.deadline, self.retention.is_empty());
            self.recycle_record(record)?;
        }
        Ok(())
    }
    fn advance_sources(&mut self) -> Result<(), Error> {
        while let Some(floor) = self.floor {
            let index = (floor.0 % self.limits.source_window as u64) as usize;
            if !self.proofs[index]
                .as_ref()
                .is_some_and(|p| p.source == floor)
            {
                break;
            }
            self.touch_proof(index)?;
            if let Some(proof) = self.proofs[index].take() {
                self.retention.remove_proof(&proof);
                self.deadlines
                    .remove(proof.deadline, self.retention.is_empty());
                self.recycle_proof(proof)?;
            }
            self.floor = floor.0.checked_add(1).map(SourceId);
        }
        Ok(())
    }
}

#[path = "aligned_receiver/storage.rs"]
mod storage;
/// Inspect a complete original symbol using the same bounded receiver parser.
/// This authenticates nothing and creates no peer byte or delivery authority.
pub fn unit_witness(
    identity: SymbolIdentity,
    symbol: &[u8],
    limits: Limits,
) -> Result<UnitWitness, Error> {
    limits.memory_bound_bytes()?;
    let parsed = parse(symbol, identity.record, limits)?;
    Ok(witness(identity, parsed))
}
/// Inspect one exact current unit with the same parser used by compact admission.
/// Context-dependent payload validation remains the receiver decoder's duty.
pub fn unit_witness_compact(
    identity: SymbolIdentity,
    symbol: &[u8],
    limits: Limits,
) -> Result<UnitWitness, Error> {
    limits.memory_bound_bytes()?;
    let parsed = parse_compact(symbol, identity.record, limits)?;
    Ok(witness(identity, parsed))
}
fn witness(identity: SymbolIdentity, parsed: Parsed<'_>) -> UnitWitness {
    UnitWitness {
        identity: RecordIdentity {
            channel: parsed.channel,
            record: identity.record,
        },
        index: if parsed.fragments == 0 {
            0
        } else {
            parsed.offset / parsed.capacity
        },
        count: parsed.fragments.max(1),
    }
}
fn parse_compact(symbol: &[u8], record: RecordId, limits: Limits) -> Result<Parsed<'_>, Error> {
    crate::aligned_envelope::validate_compact_unit(symbol, limits.body.symbol_bytes)
        .map_err(|_| Error::Malformed)?;
    if usize::from(symbol[0]) >= usize::from(limits.channels)
        || u16::from_be_bytes([symbol[1], symbol[2]]) != record.0 as u16
    {
        return Err(Error::Malformed);
    }
    let channel = ChannelId(symbol[0]);
    let body = &symbol[3..];
    if body[0] == 4 {
        let total = usize::from(u16::from_be_bytes([body[1], body[2]]));
        let offset = usize::from(u16::from_be_bytes([body[3], body[4]]));
        let capacity = limits.body.symbol_bytes - 8;
        let fragments = total.div_ceil(capacity);
        if fragments > limits.max_fragments_per_record {
            return Err(Error::Capacity);
        }
        Ok(Parsed {
            channel,
            body: &body[5..],
            total,
            offset,
            fragments,
            capacity,
            padding: Padding::Exact,
        })
    } else {
        Ok(Parsed {
            channel,
            body,
            total: body.len(),
            offset: 0,
            fragments: 0,
            capacity: 0,
            padding: Padding::Exact,
        })
    }
}
fn parse(symbol: &[u8], record: RecordId, limits: Limits) -> Result<Parsed<'_>, Error> {
    if symbol.len() != limits.body.symbol_bytes
        || usize::from(symbol[0]) >= usize::from(limits.channels)
        || u16::from_be_bytes([symbol[1], symbol[2]]) != record.0 as u16
    {
        return Err(Error::Malformed);
    }
    let channel = ChannelId(symbol[0]);
    let body = &symbol[3..];
    if body[0] == 4 {
        let total = usize::from(u16::from_be_bytes([body[1], body[2]]));
        let offset = usize::from(u16::from_be_bytes([body[3], body[4]]));
        let capacity = body.len() - 5;
        if total <= body.len() || offset >= total || !offset.is_multiple_of(capacity) {
            return Err(Error::Malformed);
        }
        let fragments = total.div_ceil(capacity);
        if fragments > limits.max_fragments_per_record {
            return Err(Error::Capacity);
        }
        let size = capacity.min(total - offset);
        if body[5 + size..].iter().any(|b| *b != 0) {
            return Err(Error::Malformed);
        }
        Ok(Parsed {
            channel,
            body: &body[5..5 + size],
            total,
            offset,
            fragments,
            capacity,
            padding: Padding::Exact,
        })
    } else if body[0] == 6 || body[0] & 7 == 5 || body[0] & 7 == 7 {
        Ok(Parsed {
            channel,
            body,
            total: body.len(),
            offset: 0,
            fragments: 0,
            capacity: 0,
            padding: Padding::ZeroExtended,
        })
    } else {
        let length = explicit_length(body)?;
        if body[length..].iter().any(|b| *b != 0) {
            return Err(Error::Malformed);
        }
        Ok(Parsed {
            channel,
            body: &body[..length],
            total: length,
            offset: 0,
            fragments: 0,
            capacity: 0,
            padding: Padding::Exact,
        })
    }
}
fn independent_length(body: &[u8]) -> Option<usize> {
    let offset = match *body.first()? {
        2 => 1,
        crate::aligned_body::LZ4_TAG => 3,
        _ => return None,
    };
    let length = body.get(offset..offset + 2)?;
    Some(usize::from(u16::from_be_bytes([length[0], length[1]])))
}

pub(crate) fn explicit_length(body: &[u8]) -> Result<usize, Error> {
    if body.len() < 3 {
        return Err(Error::Malformed);
    }
    let size = usize::from(u16::from_be_bytes([body[1], body[2]]));
    let mut cursor = 3usize;
    match body[0] {
        0 if size == 66 => {}
        8 if (40..=crate::tcp_header::MAX_IP_HEADER_BYTES).contains(&size) => {}
        1 => cursor += 23,
        2 => {}
        crate::aligned_body::LZ4_TAG => {
            let original = body.get(3..5).ok_or(Error::Malformed)?;
            let original = usize::from(u16::from_be_bytes([original[0], original[1]]));
            if size == 0 || size + 2 >= original {
                return Err(Error::Malformed);
            }
            cursor += 2;
        }
        3 | 9 => {
            let mask = *body.get(cursor).ok_or(Error::Malformed)?;
            cursor += 1;
            for bit in 0..8 {
                if mask & (1 << bit) != 0 {
                    let mut finished = false;
                    for _ in 0..5 {
                        let byte = *body.get(cursor).ok_or(Error::Malformed)?;
                        cursor += 1;
                        if byte < 128 {
                            finished = true;
                            break;
                        }
                    }
                    if !finished {
                        return Err(Error::Malformed);
                    }
                }
            }
        }
        _ => return Err(Error::Malformed),
    }
    cursor
        .checked_add(size)
        .filter(|end| *end <= body.len())
        .ok_or(Error::Malformed)
}

#[cfg(test)]
#[path = "aligned_receiver_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "aligned_batch_tests.rs"]
mod batch_tests;

#[cfg(test)]
#[path = "aligned_short_preview_tests.rs"]
mod short_preview_tests;

#[cfg(test)]
#[path = "aligned_receiver_compact_tests.rs"]
mod compact_tests;

#[cfg(test)]
#[path = "aligned_receiver/cache_tests.rs"]
mod cache_tests;
