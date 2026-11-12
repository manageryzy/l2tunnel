//! Bounded channel/fragment ordering for authenticated aligned symbols.
//!
//! Authentication is a caller precondition. The enclosing protocol must cover the
//! complete symbol and its absolute identity, including its inner channel byte.
//! No runtime, coding engine, device, clock or local epoch reset is provided.

use crate::aligned_body::{self, Decoder, Padding};
use l2tunnel_core::Epoch;
use std::{fmt, mem::size_of};

/// Absolute nonwrapping source identity, retained through retransmission/recovery.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SourceId(pub u64);
/// Absolute nonwrapping record identity; inner serial is only its low 16 bits.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct RecordId(pub u64);
/// Common MUX channel, never a privileged probe/control path.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ChannelId(pub u8);
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
    /// Conservative bound on explicit payload and fixed-slot metadata storage.
    /// Allocator bookkeeping is platform-specific and is not included.
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
                65535 + self.max_fragments_per_record + size_of::<Channel>(),
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
            .and_then(|n| n.checked_add(size_of::<Receiver>()))
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
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "aligned receiver: {self:?}")
    }
}
impl std::error::Error for Error {}
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
    /// Context/tombstone work consumed the supplied work allowance.
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
    /// Retained not-yet-delivered native records; unknown fragment headers count conservatively.
    pub native_records: usize,
    /// One immutable prepared native frame length, if any.
    pub pending_bytes: Option<usize>,
    /// Sticky terminal expiry/semantic error.
    pub failure: Option<Error>,
}
/// One externally authenticated symbol borrowed for atomic ledger admission.
/// The full configured padded geometry and existing identity rules still apply.
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
    pieces: Vec<bool>,
    count: usize,
    fragment_capacity: usize,
    padding: Padding,
    deadline: Tick,
    early_delivered: bool,
}
impl Record {
    fn complete(&self) -> bool {
        self.count == self.pieces.len()
    }
}
struct Channel {
    expected: Option<RecordId>,
    decoder: Decoder,
}
#[derive(Clone, Copy)]
struct Pending {
    slot: usize,
    written: usize,
    early: bool,
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

/// Finite receiver state with separate admission, preparation and actual delivery commit.
pub struct Receiver {
    scope: Scope,
    limits: Limits,
    channels: Vec<Channel>,
    records: Vec<Option<Record>>,
    proofs: Vec<Option<Proof>>,
    floor: Option<SourceId>,
    staged: Decoder,
    native: Vec<u8>,
    pending: Option<Pending>,
    last_time: Option<Tick>,
    failure: Option<Error>,
}
impl Receiver {
    /// Validate all fixed allocation products and reserve progress independently of lookahead.
    pub fn new(scope: Scope, limits: Limits) -> Result<Self, Error> {
        limits.memory_bound_bytes()?;
        if scope.session == [0; 16] {
            return Err(Error::Configuration);
        }
        let mut channels = Vec::with_capacity(usize::from(limits.channels));
        for _ in 0..limits.channels {
            channels.push(Channel {
                expected: Some(limits.first_record),
                decoder: Decoder::new(limits.body).map_err(Error::Body)?,
            });
        }
        let mut records =
            Vec::with_capacity(usize::from(limits.channels) + limits.lookahead_records);
        records.resize_with(
            usize::from(limits.channels) + limits.lookahead_records,
            || None,
        );
        let mut proofs = Vec::with_capacity(limits.source_window);
        proofs.resize_with(limits.source_window, || None);
        Ok(Self {
            scope,
            limits,
            channels,
            records,
            proofs,
            floor: Some(limits.first_source),
            staged: Decoder::new(limits.body).map_err(Error::Body)?,
            native: vec![0; limits.body.max_frame_bytes],
            pending: None,
            last_time: None,
            failure: None,
        })
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
        if !(1..=255).contains(&symbols.len()) {
            return Err(Error::Configuration);
        }
        self.limits.batch_memory_bound_bytes()?;
        self.check_time(now)?;
        let records = self.records.clone();
        let proofs = self.proofs.clone();
        let floor = self.floor;
        let last_time = self.last_time;
        let mut outcomes = Vec::with_capacity(symbols.len());
        for symbol in symbols {
            match self.admit_authenticated(symbol.identity, symbol.bytes, now) {
                Ok(outcome) => outcomes.push(outcome),
                Err(error) => {
                    self.records = records;
                    self.proofs = proofs;
                    self.floor = floor;
                    self.last_time = last_time;
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
        if !(1..=255).contains(&symbols.len()) {
            return Err(Error::Configuration);
        }
        self.limits.batch_memory_bound_bytes()?;
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
        let mut shadow = Self::new(self.scope, self.limits)?;
        for (target, source) in shadow.channels.iter_mut().zip(&self.channels) {
            target.expected = source.expected;
            target.decoder.copy_context_from(&source.decoder);
        }
        shadow.records.clone_from(&self.records);
        shadow.proofs.clone_from(&self.proofs);
        shadow.floor = self.floor;
        shadow.staged.copy_context_from(&self.staged);
        shadow.native.copy_from_slice(&self.native);
        shadow.pending = self.pending;
        shadow.last_time = self.last_time;
        shadow.failure = self.failure;
        Ok(shadow)
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
        let parsed = parse(symbol, identity.record, self.limits)?;
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
            if let Some(slot) = self.find(parsed.channel, identity.record) {
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
                    if existing.pieces[index] {
                        if existing.bytes[parsed.offset..end] != *parsed.body {
                            return Err(Error::Conflict);
                        }
                        Admission::Duplicate
                    } else {
                        // The final fragment is validated in a bounded temporary copy
                        // before changing the admitted record or replay ledger.
                        if existing.count + 1 == parsed.fragments {
                            let mut complete = existing.bytes.clone();
                            complete[parsed.offset..end].copy_from_slice(parsed.body);
                            if explicit_length(&complete)? != complete.len() {
                                return Err(Error::Malformed);
                            }
                        }
                        let entry = self.records[slot].as_mut().ok_or(Error::Malformed)?;
                        entry.bytes[parsed.offset..end].copy_from_slice(parsed.body);
                        entry.pieces[index] = true;
                        entry.count += 1;
                        Admission::Accepted
                    }
                }
            } else {
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
                let mut bytes = vec![0; parsed.total];
                bytes[parsed.offset..parsed.offset + parsed.body.len()]
                    .copy_from_slice(parsed.body);
                let mut pieces = vec![false; parsed.fragments];
                if parsed.fragments != 0 {
                    pieces[parsed.offset / parsed.capacity] = true;
                }
                self.records[slot] = Some(Record {
                    channel: parsed.channel,
                    id: identity.record,
                    bytes,
                    pieces,
                    count: usize::from(parsed.fragments != 0),
                    fragment_capacity: parsed.capacity,
                    padding: parsed.padding,
                    deadline,
                    early_delivered: false,
                });
                Admission::Accepted
            }
        };
        self.proofs[proof_slot] = Some(Proof {
            source: identity.source,
            record: identity.record,
            bytes: symbol.to_vec(),
            deadline,
        });
        self.advance_sources();
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
        self.check_time(now)?;
        self.expected(channel)?;
        self.last_time = Some(now);
        if self.pending.is_some() {
            return Ok(Prepared::Ready);
        }
        for _ in 0..max_records {
            let expected = match self.expected(channel)? {
                Some(id) => id,
                None => return Ok(Prepared::Idle),
            };
            let head = self
                .find(channel, expected)
                .filter(|slot| self.records[*slot].as_ref().is_some_and(Record::complete));
            let slot = head.or_else(|| {
                self.records
                    .iter()
                    .enumerate()
                    .filter_map(|(i, entry)| {
                        let entry = entry.as_ref()?;
                        (entry.channel == channel
                            && entry.id > expected
                            && entry.complete()
                            && entry.pieces.is_empty()
                            && !entry.early_delivered
                            && entry.bytes.first() == Some(&2)
                            && self.limits.body.independent_short_frame_bytes != 0
                            && entry.bytes.len() - 3
                                <= self.limits.body.independent_short_frame_bytes)
                            .then_some((entry.id, i))
                    })
                    .min_by_key(|(id, _)| *id)
                    .map(|(_, i)| i)
            });
            let Some(slot) = slot else {
                return Ok(Prepared::Idle);
            };
            let entry = self.records[slot].as_ref().ok_or(Error::Malformed)?;
            if entry.early_delivered {
                self.retire(slot)?;
                continue;
            }
            let early = entry.id != expected;
            self.staged
                .copy_context_from(&self.channels[usize::from(channel.0)].decoder);
            let decoded =
                match self
                    .staged
                    .decode_body(&entry.bytes, entry.padding, &mut self.native)
                {
                    Ok(decoded) => decoded,
                    Err(error) => {
                        self.failure = Some(Error::Body(error));
                        return Err(Error::Body(error));
                    }
                };
            match decoded {
                aligned_body::Decoded::Context { .. } => {
                    self.channels[usize::from(channel.0)]
                        .decoder
                        .copy_context_from(&self.staged);
                    self.retire(slot)?;
                }
                aligned_body::Decoded::Frame { written, .. } => {
                    self.pending = Some(Pending {
                        slot,
                        written,
                        early,
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
    /// Commit only after complete native-device acceptance; WouldBlock must not call this.
    pub fn commit_delivery(&mut self, now: Tick) -> Result<(), Error> {
        self.check_time(now)?;
        let pending = self.pending.ok_or(Error::NoPending)?;
        let entry = self.records[pending.slot]
            .as_mut()
            .ok_or(Error::Malformed)?;
        if pending.early {
            entry.early_delivered = true;
        } else {
            self.channels[usize::from(entry.channel.0)]
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
        self.records
            .iter()
            .flatten()
            .map(|record| record.deadline)
            .chain(self.proofs.iter().flatten().map(|proof| proof.deadline))
            .min()
    }
    /// Inspect payload/count retention without advancing receipt or native delivery.
    pub fn status(&self) -> Status {
        let mut status = Status {
            source_floor: self.floor,
            retained_sources: self.proofs.iter().flatten().count(),
            retained_records: 0,
            native_records: 0,
            record_bytes: 0,
            fragment_slots: 0,
            early_tombstones: 0,
            pending_bytes: self.pending.map(|p| p.written),
            failure: self.failure,
        };
        for entry in self.records.iter().flatten() {
            status.retained_records += 1;
            if !entry.early_delivered
                && (entry.bytes.first() != Some(&0)
                    || (!entry.pieces.is_empty()
                        && !entry.pieces.first().copied().unwrap_or(false)))
            {
                status.native_records += 1;
            }
            status.record_bytes += entry.bytes.len();
            status.fragment_slots += entry.pieces.len();
            status.early_tombstones += usize::from(entry.early_delivered);
        }
        status
    }
    fn find(&self, channel: ChannelId, record: RecordId) -> Option<usize> {
        self.records.iter().position(|entry| {
            entry
                .as_ref()
                .is_some_and(|e| e.channel == channel && e.id == record)
        })
    }
    fn check_time(&mut self, now: Tick) -> Result<(), Error> {
        if let Some(error) = self.failure {
            return Err(error);
        }
        if self.last_time.is_some_and(|last| now < last) {
            return Err(Error::Time);
        }
        if self.records.iter().flatten().any(|e| now >= e.deadline)
            || self.proofs.iter().flatten().any(|p| now >= p.deadline)
        {
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
        let (mut count, mut total, mut slots) = (1usize, bytes, fragments);
        for entry in self.records.iter().flatten() {
            if Some(entry.id) != self.channels[usize::from(entry.channel.0)].expected {
                count += 1;
                total += entry.bytes.len();
                slots += entry.pieces.len();
            }
        }
        if count > self.limits.lookahead_records
            || total > self.limits.lookahead_bytes
            || slots > self.limits.lookahead_fragments
        {
            Err(Error::Capacity)
        } else {
            Ok(())
        }
    }
    fn retire(&mut self, slot: usize) -> Result<(), Error> {
        let entry = self.records[slot].as_ref().ok_or(Error::Malformed)?;
        let channel = &mut self.channels[usize::from(entry.channel.0)];
        if channel.expected != Some(entry.id) {
            return Err(Error::Malformed);
        }
        channel.expected = entry.id.0.checked_add(1).map(RecordId);
        self.records[slot] = None;
        Ok(())
    }
    fn advance_sources(&mut self) {
        while let Some(floor) = self.floor {
            let index = (floor.0 % self.limits.source_window as u64) as usize;
            if !self.proofs[index]
                .as_ref()
                .is_some_and(|p| p.source == floor)
            {
                break;
            }
            self.proofs[index] = None;
            self.floor = floor.0.checked_add(1).map(SourceId);
        }
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
pub(crate) fn explicit_length(body: &[u8]) -> Result<usize, Error> {
    if body.len() < 3 {
        return Err(Error::Malformed);
    }
    let size = usize::from(u16::from_be_bytes([body[1], body[2]]));
    let mut cursor = 3usize;
    match body[0] {
        0 if size == 66 => {}
        1 => cursor += 23,
        2 => {}
        3 => {
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
