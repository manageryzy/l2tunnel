//! Clock-injected recovery for one authenticated data direction. Each peer owns
//! a sender for its outgoing direction and a receiver for its incoming direction.
//! The carrier authenticates and pays for both data and reverse feedback.

use l2tunnel_core::bounded_index::Index;

use super::feedback::{Feedback, FeedbackId, Missing, ReplayWindow};
use super::{FreshMember, GroupShape, Profile, ReceiveAdmission, ReceiveWindow, TransmitWindow};
use crate::{Error, FecContext, GenerationId};
mod names;
use names::NamedTimers;

/// Local durations in the caller's monotonic tick units.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecoveryTiming {
    /// Delay before first requesting a newly observed hole.
    pub gap_delay: u64,
    /// Interval before rechecking an already scanned range.
    pub gap_repeat: u64,
    /// Maximum coalescing delay after contiguous native delivery.
    pub ack_delay: u64,
    /// Idle interval before probing the oldest unconfirmed physical source.
    pub quiet: u64,
}

impl RecoveryTiming {
    /// Reject a zero interval before binding these timers to a negotiated epoch.
    pub fn validate(self) -> Result<Self, Error> {
        if [self.gap_delay, self.gap_repeat, self.ack_delay, self.quiet].contains(&0) {
            return Err(Error::InvalidConfig);
        }
        Ok(self)
    }
}

fn observe(previous: &mut u64, now: u64) -> Result<(), Error> {
    if now < *previous {
        return Err(Error::TimeBackwards);
    }
    *previous = now;
    Ok(())
}

/// What the immutable prepared data datagram actually carries.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DataKind {
    /// First physical send of this group member.
    Fresh(FreshMember),
    /// Repeat a paid original in response to received feedback.
    Named(GenerationId),
    /// Repeat an oldest paid original after a quiet interval.
    Quiet(GenerationId),
}

/// Completion identity. The caller retains its sealed packet until the whole
/// carrier datagram is accepted, then commits this token exactly once.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DataToken {
    context: FecContext,
    serial: u64,
    kind: DataKind,
}

impl DataToken {
    /// Transmission class and corresponding member identity.
    pub const fn kind(self) -> DataKind {
        self.kind
    }
}

/// Physical accounting after complete carrier acceptance only.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Paid {
    /// Completed physical datagrams.
    pub packets: u64,
    /// Full physical IP bytes supplied by the runtime, including AEAD and carrier.
    pub ip_bytes: u64,
}

impl Paid {
    fn add(&mut self, bytes: usize) {
        self.packets = self.packets.saturating_add(1);
        self.ip_bytes = self.ip_bytes.saturating_add(bytes as u64);
    }
}

/// Per-class physical sender accounting.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SendStats {
    /// Fresh physical members, including both halves of a split singleton.
    pub fresh: Paid,
    /// Original member retries explicitly requested by the receiving peer.
    pub named: Paid,
    /// Timeout probes, using the ordinary original's complete mixed layout.
    pub quiet: Paid,
}

/// Sender custody, physical completion and bounded named/quiet scheduling.
pub struct ScheduledSender {
    window: TransmitWindow,
    profile: Profile,
    context: FecContext,
    first: GenerationId,
    timing: RecoveryTiming,
    now: u64,
    next_serial: Option<u64>,
    pending: Option<(DataToken, usize)>,
    wire: Vec<u8>,
    replay: ReplayWindow,
    requested: Index<GenerationId, ()>,
    last_named: Option<GenerationId>,
    last_retry_was_quiet: bool,
    paid_through: Option<GenerationId>,
    sealed_through: Option<GenerationId>,
    confirmed: Option<GenerationId>,
    quiet_due: Option<u64>,
    prefer_fresh: bool,
    stats: SendStats,
}

impl ScheduledSender {
    /// Open a fresh non-wrapping source and feedback domain.
    pub fn new(
        profile: Profile,
        context: FecContext,
        first: GenerationId,
        hold: u64,
        now: u64,
        source_limit: usize,
        timing: RecoveryTiming,
    ) -> Result<Self, Error> {
        let timing = timing.validate()?;
        let window = TransmitWindow::new(profile, context, first, hold, now, source_limit)?;
        Self::with_window(profile, context, first, now, timing, window)
    }

    /// Use the ordinary physical-send scheduler with preallocated source/packet
    /// custody. The limit covers the transmit window only; it excludes this
    /// scheduler's output buffer and named-feedback index.
    pub fn new_reserved_custody(
        plan: super::TransmitPlan,
        limits: crate::storage::Limits,
        context: FecContext,
        first: GenerationId,
        hold: u64,
        now: u64,
        timing: RecoveryTiming,
    ) -> Result<Self, crate::storage::Error> {
        let timing = timing.validate().map_err(crate::storage::Error::Fec)?;
        let window = TransmitWindow::new_reserved(plan, limits, context, first, hold, now)?;
        Self::with_window(plan.profile, context, first, now, timing, window)
            .map_err(crate::storage::Error::Fec)
    }

    /// Actual reserved transmit-window backing when selected at construction.
    pub fn custody_storage_usage(&self) -> Option<crate::storage::Usage> {
        self.window.storage_usage()
    }

    /// Heap needed for the paid-datagram buffer and the named-retry index.
    pub fn auxiliary_planned_bytes(profile: Profile, sources: usize) -> Result<usize, Error> {
        Index::<GenerationId, ()>::planned_bytes(sources)
            .map_err(|_| Error::Arithmetic)?
            .checked_add(Self::wire_capacity(profile))
            .ok_or(Error::Arithmetic)
    }
    /// Retained scheduler storage in addition to the transmit window.
    pub fn auxiliary_capacity_bytes(&self) -> usize {
        self.wire.capacity() + self.requested.capacity_bytes()
    }
    fn wire_capacity(profile: Profile) -> usize {
        profile.max_wire_bytes.min(usize::from(u16::MAX) + 15)
    }

    fn with_window(
        profile: Profile,
        context: FecContext,
        first: GenerationId,
        now: u64,
        timing: RecoveryTiming,
        window: TransmitWindow,
    ) -> Result<Self, Error> {
        // Canonical bodies fit u16. Compact framing adds at most shape, split
        // length (3), base (10) and ordinal (1) to a complete canonical body.
        let capacity = Self::wire_capacity(profile);
        let expected = Self::auxiliary_planned_bytes(profile, window.limit)?;
        let requested = Index::new(window.limit).map_err(|_| Error::Capacity)?;
        let mut wire = Vec::new();
        wire.try_reserve_exact(capacity)
            .map_err(|_| Error::Capacity)?;
        wire.resize(capacity, 0);
        let owner = Self {
            window,
            profile,
            context,
            first,
            timing,
            now,
            next_serial: Some(1),
            pending: None,
            wire,
            replay: ReplayWindow::new(context),
            requested,
            last_named: None,
            last_retry_was_quiet: false,
            paid_through: None,
            sealed_through: None,
            confirmed: None,
            quiet_due: None,
            prefer_fresh: false,
            stats: SendStats::default(),
        };
        if owner.auxiliary_capacity_bytes() != expected {
            return Err(Error::Capacity);
        }
        Ok(owner)
    }

    /// Admit native bytes under the original transmit window's source credit.
    pub fn submit(&mut self, now: u64, bytes: &[u8]) -> Result<GenerationId, Error> {
        observe(&mut self.now, now)?;
        self.window.submit(now, bytes)
    }

    /// Source IDs still held under the transmit window's configured limit.
    pub fn retained(&self) -> usize {
        self.window.retained()
    }

    /// Exact logical producer debt after applying authenticated peer receipts.
    pub fn outstanding_sources(&self) -> usize {
        self.window.outstanding_sources()
    }

    /// Count successful seals independently of fresh and repeated physical sends.
    pub fn group_formation(&self) -> super::GroupFormation {
        self.window.group_formation()
    }

    /// Local seal decision for the pending group's first fresh physical member.
    pub fn pending_group_seal(&self) -> Option<super::GroupSeal> {
        match self.pending?.0.kind {
            DataKind::Fresh(member) => self.window.first_member_seal(member),
            _ => None,
        }
    }

    /// Authenticated direction and epoch in which this owner may send originals.
    pub const fn context(&self) -> FecContext {
        self.context
    }

    /// Last inclusive authenticated contiguous receipt.
    pub const fn confirmed_through(&self) -> Option<GenerationId> {
        self.confirmed
    }

    /// Completed carrier bytes by class.
    pub const fn stats(&self) -> SendStats {
        self.stats
    }

    /// Exact plaintext length of the immutable physical member awaiting payment.
    pub fn pending_member_bytes(&self) -> Option<usize> {
        self.pending.map(|(_, length)| length)
    }

    fn oldest_paid(&self) -> Option<GenerationId> {
        let first = match self.confirmed {
            Some(id) => GenerationId(id.0.checked_add(1)?),
            None => self.first,
        };
        self.paid_through
            .filter(|&last| first <= last)
            .map(|_| first)
    }

    /// Validate and apply authenticated feedback. Delayed distinct feedback may
    /// still request an old hole. No request can create new source custody.
    pub fn receive_feedback(&mut self, now: u64, feedback: Feedback) -> Result<bool, Error> {
        observe(&mut self.now, now)?;
        let mut replay = self.replay;
        if !replay.accept(feedback)? {
            return Ok(false);
        }
        if let Some(named) = feedback.missing() {
            for id in named.ids() {
                if id < self.first || self.sealed_through.is_none_or(|end| id > end) {
                    return Err(Error::UnknownGeneration);
                }
            }
        }
        if let Some(last) = feedback.confirmed_through()
            && self.window.confirm_through(self.context, last)?
        {
            self.confirmed = Some(last);
            while let Some((id, ())) = self.requested.first().filter(|(id, _)| *id <= last) {
                self.requested.remove(id);
            }
            if self.oldest_paid().is_none() {
                self.quiet_due = None;
            }
        }
        if let Some(named) = feedback.missing() {
            for id in named.ids() {
                // A member covered by the first received seal but not physically
                // sent yet already has a guaranteed fresh turn.
                if self.confirmed.is_none_or(|last| id > last)
                    && self.paid_through.is_some_and(|last| id <= last)
                {
                    self.requested.insert(id, ()).map_err(|_| Error::Capacity)?;
                }
            }
        }
        self.replay = replay;
        Ok(true)
    }

    fn retry_kind(&self, now: u64) -> Option<DataKind> {
        let quiet = self
            .quiet_due
            .filter(|&due| now >= due)
            .and_then(|_| self.oldest_paid())
            .map(DataKind::Quiet);
        let next = self
            .last_named
            .and_then(|id| id.0.checked_add(1))
            .and_then(|start| self.requested.ceil(GenerationId(start)))
            .or_else(|| self.requested.first());
        let named = next.map(|(id, ())| DataKind::Named(id));
        if self.last_retry_was_quiet {
            named.or(quiet)
        } else {
            quiet.or(named)
        }
    }

    /// Prepare one payable physical datagram. Repeat calls return the same
    /// bytes and token through carrier backpressure or incoming confirmations.
    pub fn prepare_data(&mut self, now: u64) -> Result<Option<(DataToken, &[u8])>, Error> {
        observe(&mut self.now, now)?;
        if self.pending.is_none() {
            let serial = self.next_serial.ok_or(Error::SymbolExhausted)?;
            let retry = self.retry_kind(now);
            let fresh = if retry.is_none() || self.prefer_fresh {
                self.window.prepare_fresh(now, &mut self.wire)?
            } else {
                None
            };
            let (kind, length) = if let Some((member, len)) = fresh {
                (DataKind::Fresh(member), len)
            } else if let Some(kind @ (DataKind::Named(id) | DataKind::Quiet(id))) = retry {
                (
                    kind,
                    self.window.write_named(self.context, id, &mut self.wire)?,
                )
            } else {
                return Ok(None);
            };
            self.pending = Some((
                DataToken {
                    context: self.context,
                    serial,
                    kind,
                },
                length,
            ));
        }
        Ok(self.pending.map(|(token, len)| (token, &self.wire[..len])))
    }

    /// Commit the successful carrier send, charging its actual IP bytes. The
    /// next idle interval starts at physical acceptance, never at preparation.
    pub fn confirm_data(
        &mut self,
        now: u64,
        token: DataToken,
        physical_ip_bytes: usize,
    ) -> Result<(), Error> {
        self.confirm_data_at(now, now, token, physical_ip_bytes)
    }

    /// Preserve the physical completion time when the caller observes it later.
    pub fn confirm_data_at(
        &mut self,
        now: u64,
        accepted: u64,
        token: DataToken,
        physical_ip_bytes: usize,
    ) -> Result<(), Error> {
        if accepted > now {
            return Err(Error::TimeBackwards);
        }
        observe(&mut self.now, now)?;
        let (expected, len) = self.pending.ok_or(Error::Unsealed)?;
        if expected != token || physical_ip_bytes < len {
            return Err(Error::Conflict);
        }
        let due = accepted
            .checked_add(self.timing.quiet)
            .ok_or(Error::DeadlineOverflow)?;
        match token.kind {
            DataKind::Fresh(member) => {
                let (shape, packet) = self.profile.inspect(&self.wire[..len])?;
                let base = packet.generation();
                let (ordinal, members) = match shape {
                    GroupShape::Originals(q) => (u64::from(packet.index()), u64::from(q)),
                    GroupShape::Split(_) => (0, 1),
                };
                let paid = GenerationId(base.0.checked_add(ordinal).ok_or(Error::Arithmetic)?);
                let sealed =
                    GenerationId(base.0.checked_add(members - 1).ok_or(Error::Arithmetic)?);
                self.window.confirm_fresh(member)?;
                self.paid_through = Some(paid);
                self.sealed_through = Some(sealed);
                self.quiet_due = self.oldest_paid().map(|_| due);
                self.stats.fresh.add(physical_ip_bytes);
            }
            DataKind::Named(id) => {
                self.requested.remove(id);
                self.last_named = Some(id);
                self.last_retry_was_quiet = false;
                self.stats.named.add(physical_ip_bytes);
            }
            DataKind::Quiet(id) => {
                self.requested.remove(id);
                self.last_retry_was_quiet = true;
                self.quiet_due = self.oldest_paid().map(|_| due);
                self.stats.quiet.add(physical_ip_bytes);
            }
        }
        self.prefer_fresh = !matches!(token.kind, DataKind::Fresh(_));
        self.pending = None;
        self.next_serial = token.serial.checked_add(1);
        Ok(())
    }

    /// Earliest timer or queued work. With a prepared datagram, wait for
    /// carrier writability and explicitly retry the retained output.
    pub fn next_wake(&self) -> Option<u64> {
        if self.pending.is_some() {
            return None;
        }
        [
            self.window.next_wake(),
            self.quiet_due,
            (!self.requested.is_empty()).then_some(self.now),
        ]
        .into_iter()
        .flatten()
        .min()
    }
}

/// Cursor over source IDs whose first gap delay has not yet been serviced.
#[derive(Clone, Copy)]
struct GapScan {
    due: Option<u64>,
    next: Option<GenerationId>,
}

/// Read-only service decision. An empty page still advances bounded local work.
#[derive(Clone, Copy)]
struct GapPage {
    discovery: GapScan,
    examined_retries: Option<Missing>,
    missing: Option<Missing>,
}

/// Receiver custody and reverse-path scheduling. Independently decodable
/// originals remain ready for the native endpoint even while older ones need
/// a named retry. A receipt means successful native handoff.
pub struct ScheduledReceiver {
    window: ReceiveWindow,
    profile: Profile,
    context: FecContext,
    timing: RecoveryTiming,
    now: u64,
    ack_due: Option<u64>,
    repeat_ack: bool,
    gaps: GapScan,
    named: NamedTimers,
    next_serial: Option<u64>,
    pending: Option<Feedback>,
    // Only groups presently missing a locally solvable original have a timer.
    recovery: Index<GenerationId, (u64, GenerationId)>,
    deadlines: Index<(u64, GenerationId), ()>,
    stats: Paid,
}

impl ScheduledReceiver {
    /// Start one authenticated data direction, independently of the reverse data owner.
    pub fn new(
        profile: Profile,
        context: FecContext,
        first: GenerationId,
        now: u64,
        source_limit: usize,
        expanded_limit: usize,
        timing: RecoveryTiming,
    ) -> Result<Self, Error> {
        let timing = timing.validate()?;
        let window = ReceiveWindow::new(profile, context, first, source_limit, expanded_limit)?;
        Ok(Self {
            window,
            profile,
            context,
            timing,
            now,
            ack_due: None,
            repeat_ack: false,
            gaps: GapScan {
                due: None,
                next: Some(first),
            },
            named: NamedTimers::new(source_limit)?,
            next_serial: Some(1),
            pending: None,
            recovery: Index::new(source_limit).map_err(|_| Error::Capacity)?,
            deadlines: Index::new(source_limit).map_err(|_| Error::Capacity)?,
            stats: Paid::default(),
        })
    }

    /// Borrow contiguous progress, independent ready originals and custody metrics.
    pub const fn window(&self) -> &ReceiveWindow {
        &self.window
    }

    /// Heap needed to price and withdraw local recovery deadlines.
    pub fn auxiliary_planned_bytes(sources: usize) -> Result<usize, Error> {
        let recovery = Index::<GenerationId, (u64, GenerationId)>::planned_bytes(sources)
            .map_err(|_| Error::Arithmetic)?;
        let deadlines = Index::<(u64, GenerationId), ()>::planned_bytes(sources)
            .map_err(|_| Error::Arithmetic)?;
        NamedTimers::planned_bytes(sources)?
            .checked_add(recovery)
            .and_then(|sum| sum.checked_add(deadlines))
            .ok_or(Error::Arithmetic)
    }
    /// Retained timer indexes in addition to the physical receive window.
    pub fn auxiliary_capacity_bytes(&self) -> usize {
        self.recovery.capacity_bytes()
            + self.deadlines.capacity_bytes()
            + self.named.capacity_bytes()
    }

    /// Reverse feedback IP datagrams and bytes physically accepted.
    pub const fn stats(&self) -> Paid {
        self.stats
    }

    fn arm_ack(&mut self, due: u64) {
        self.ack_due = Some(self.ack_due.map_or(due, |old| old.min(due)));
        self.repeat_ack = true;
    }

    fn cancel_recovery(&mut self, base: GenerationId) {
        if let Some((when, _)) = self.recovery.remove(base) {
            self.deadlines.remove((when, base));
        }
    }

    fn local_work(
        &mut self,
        base: GenerationId,
        count: u16,
        now: u64,
        later: u64,
    ) -> Result<(), Error> {
        if !self.window.can_recover(base) {
            return Ok(());
        }
        let mut first = [GenerationId(0)];
        if self
            .window
            .missing_ids(base, usize::from(count), &mut first)?
            == 0
        {
            self.cancel_recovery(base);
            return Ok(());
        }
        let last = GenerationId(
            base.0
                .checked_add(u64::from(count - 1))
                .ok_or(Error::Arithmetic)?,
        );
        let ahead = self
            .window
            .observed_through()
            .is_some_and(|id| id > first[0]);
        let mut due = if ahead { now } else { later };
        if let Some((old, _)) = self.recovery.get(base) {
            due = due.min(old);
            if old == due {
                return Ok(());
            }
            self.deadlines.remove((old, base));
        }
        self.recovery
            .insert(base, (due, last))
            .map_err(|_| Error::Capacity)?;
        self.deadlines
            .insert((due, base), ())
            .map_err(|_| Error::Capacity)?;
        Ok(())
    }

    /// Accept real authenticated data; duplicates of delivered traffic trigger
    /// another cumulative receipt, so even a completely lost final ACK recovers.
    pub fn accept_authenticated(
        &mut self,
        now: u64,
        context: FecContext,
        wire: &[u8],
        scratch: &mut [u8],
    ) -> Result<ReceiveAdmission, Error> {
        observe(&mut self.now, now)?;
        let due = now
            .checked_add(self.timing.gap_delay)
            .ok_or(Error::DeadlineOverflow)?;
        let ack = now
            .checked_add(self.timing.ack_delay)
            .ok_or(Error::DeadlineOverflow)?;
        let admission = self.window.accept_authenticated(context, wire, scratch)?;
        if admission == ReceiveAdmission::Accepted {
            let (shape, packet) = self.profile.inspect(wire)?;
            if let GroupShape::Originals(count) = shape {
                self.local_work(packet.generation(), count, now, due)?;
            }
            if self
                .gaps
                .next
                .zip(self.window.sealed_through())
                .is_some_and(|(first, end)| first <= end)
            {
                self.gaps.due.get_or_insert(due);
            }
        } else if self.window.confirmed_through().is_some() {
            self.arm_ack(ack);
        }
        Ok(admission)
    }

    /// Explicitly recover this known group and withdraw its local timer.
    pub fn recover_missing(&mut self, base: GenerationId) -> Result<usize, Error> {
        let n = self.window.recover_missing(base)?;
        self.cancel_recovery(base);
        Ok(n)
    }

    /// Do at most one group of local GF work. A tail is allowed to arrive
    /// directly until the short deadline. An interior erasure can run sooner.
    pub fn poll_recovery(&mut self, now: u64) -> Result<Option<(GenerationId, usize)>, Error> {
        observe(&mut self.now, now)?;
        let Some(((due, base), ())) = self.deadlines.first() else {
            return Ok(None);
        };
        if now < due {
            return Ok(None);
        }
        Ok(Some((base, self.recover_missing(base)?)))
    }

    /// Confirm a successful native write. An out-of-order commit never claims
    /// a prefix across an older native source.
    pub fn commit_original(&mut self, now: u64, id: GenerationId) -> Result<bool, Error> {
        observe(&mut self.now, now)?;
        let ack = now
            .checked_add(self.timing.ack_delay)
            .ok_or(Error::DeadlineOverflow)?;
        let old = self.window.confirmed_through();
        let result = self.window.commit_original(id)?;
        if result {
            self.named.remove(id);
        }
        if self.window.confirmed_through() != old {
            self.arm_ack(ack);
        }
        Ok(result)
    }

    fn solvable_locally(&self, id: GenerationId) -> bool {
        self.recovery
            .floor(id)
            .is_some_and(|(_, (_, last))| id <= last)
    }

    fn needs_named_retry(&self, id: GenerationId) -> bool {
        // The independent 12/10 experiment selects only residual rank. Other
        // negotiated geometries retain their existing all-missing feedback.
        if (self.profile.data_cells, self.profile.parity_cells) == (10, 2) {
            self.window.needed_for_rank(id)
        } else {
            !self.solvable_locally(id)
        }
    }

    /// Examine only the covered IDs in one bounded mask. Available or locally
    /// solvable originals need neither a first request nor a repeated one.
    fn missing_in(
        &self,
        start: GenerationId,
        span: usize,
        mask: u64,
    ) -> Result<Option<Missing>, Error> {
        let mut ids = [GenerationId(0); 64];
        let count = self.window.missing_ids(start, span, &mut ids)?;
        let mut names = ids[..count]
            .iter()
            .copied()
            .filter(|&id| mask & (1 << (id.0 - start.0)) != 0 && self.needs_named_retry(id));
        let Some(first) = names.next() else {
            return Ok(None);
        };
        let mask = names.fold(1u64, |mask, id| mask | (1 << (id.0 - first.0)));
        Missing::new(first, mask).map(Some)
    }

    /// Discover newly exposed IDs once. Old holes have separate paid deadlines,
    /// so discovery cannot accelerate their retries or inherit their cooldown.
    fn scan(&self, now: u64) -> Result<GapPage, Error> {
        let mut page = GapPage {
            discovery: self.gaps,
            examined_retries: None,
            missing: None,
        };
        let discovery = self.gaps.due.filter(|&due| due <= now);
        if let Some((due, start)) = self.named.first()
            && due <= now
            && discovery.is_none_or(|first| due <= first)
        {
            let end = self
                .window
                .sealed_through()
                .ok_or(Error::UnknownGeneration)?;
            let span = end.0.checked_sub(start.0).ok_or(Error::Arithmetic)?.min(63) as usize + 1;
            let covered = self.named.due_mask(now, start, span)?;
            page.missing = self.missing_in(start, span, covered.mask())?;
            page.examined_retries = Some(covered);
        } else if discovery.is_some() {
            page.discovery.due = None;
            let end = self
                .window
                .sealed_through()
                .ok_or(Error::UnknownGeneration)?;
            let first = self.gaps.next.ok_or(Error::Unsealed)?;
            if let Some(start) = self
                .window
                .frontier()
                .map(|id| id.max(first))
                .filter(|&id| id <= end)
            {
                let span = (end.0 - start.0).min(63) as usize + 1;
                let last = start.0 + (span - 1) as u64;
                page.missing = self.missing_in(start, span, u64::MAX)?;
                page.discovery.next = last.checked_add(1).map(GenerationId);
                if last < end.0 {
                    let delay = if page.missing.is_some() {
                        self.timing.gap_delay
                    } else {
                        0
                    };
                    page.discovery.due =
                        Some(now.checked_add(delay).ok_or(Error::DeadlineOverflow)?);
                }
            } else {
                page.discovery.next = end.0.checked_add(1).map(GenerationId);
            }
        }
        Ok(page)
    }

    /// Prepare one retained cumulative receipt and/or named mask. Repeated
    /// calls are stable until physical confirmation, even if more data arrives.
    pub fn prepare_feedback(&mut self, now: u64) -> Result<Option<Feedback>, Error> {
        observe(&mut self.now, now)?;
        if self.pending.is_some() {
            return Ok(self.pending);
        }
        let page = self.scan(now)?;
        let message = self.selected_feedback(now, page.missing)?;
        self.gaps = page.discovery;
        if let Some(covered) = page.examined_retries {
            for id in covered.ids() {
                self.named.remove(id);
            }
        }
        self.pending = message;
        Ok(message)
    }

    fn selected_feedback(
        &self,
        now: u64,
        missing: Option<Missing>,
    ) -> Result<Option<Feedback>, Error> {
        let prefix = self.window.confirmed_through();
        if missing.is_none() && (prefix.is_none() || self.ack_due.is_none_or(|t| t > now)) {
            return Ok(None);
        }
        let id = FeedbackId(self.next_serial.ok_or(Error::SymbolExhausted)?);
        Feedback::new(self.context, id, prefix, missing).map(Some)
    }

    /// Record one actual reverse-path IP send. Repeat a cumulative receipt
    /// once after the ordinary repeat interval; later tail probes also elicit it.
    pub fn confirm_feedback(
        &mut self,
        now: u64,
        feedback: Feedback,
        physical_ip_bytes: usize,
    ) -> Result<(), Error> {
        self.confirm_feedback_at(now, now, feedback, physical_ip_bytes)
    }

    /// Preserve the physical completion time when the caller observes it later.
    pub fn confirm_feedback_at(
        &mut self,
        now: u64,
        accepted: u64,
        feedback: Feedback,
        physical_ip_bytes: usize,
    ) -> Result<(), Error> {
        if accepted > now {
            return Err(Error::TimeBackwards);
        }
        observe(&mut self.now, now)?;
        if self.pending != Some(feedback) || physical_ip_bytes < feedback.wire_len() {
            return Err(Error::Conflict);
        }
        let repeat = accepted
            .checked_add(self.timing.gap_repeat)
            .ok_or(Error::DeadlineOverflow)?;
        if let Some(names) = feedback.missing() {
            let span = (u64::BITS - names.mask().leading_zeros()) as usize;
            if let Some(still_missing) = self.missing_in(names.first(), span, names.mask())? {
                for id in still_missing.ids() {
                    self.named.arm(id, repeat)?;
                }
            }
        }
        if feedback.confirmed_through().is_some()
            && feedback.confirmed_through() == self.window.confirmed_through()
        {
            self.ack_due = self.repeat_ack.then_some(repeat);
            self.repeat_ack = false;
        }
        self.stats.add(physical_ip_bytes);
        self.pending = None;
        self.next_serial = feedback.id().0.checked_add(1);
        Ok(())
    }

    /// Earliest bounded receiver work. Local repair continues even if a
    /// prepared reverse feedback ciphertext is blocked at the carrier.
    pub fn next_wake(&self) -> Option<u64> {
        let local = self.deadlines.first().map(|((when, _), ())| when);
        if self.pending.is_some() {
            local
        } else {
            [
                self.gaps.due,
                self.named.first().map(|(time, _)| time),
                self.ack_due,
                local,
            ]
            .into_iter()
            .flatten()
            .min()
        }
    }

    /// Earliest reverse carrier service, independently of local decoder work.
    pub fn feedback_wake(&self) -> Option<u64> {
        if self.pending.is_some() {
            Some(self.now)
        } else {
            self.gaps
                .due
                .into_iter()
                .chain(self.named.first().map(|(time, _)| time))
                .chain(self.ack_due)
                .min()
        }
    }

    /// Quote the exact next feedback body under current receipts. Peeking does
    /// not consume a serial, reserve a packet, or advance the bounded scan.
    /// An empty intermediate scan remains a local wake even without a wire quote.
    pub fn feedback_opportunity(&self) -> Result<Option<(u64, usize)>, Error> {
        if let Some(message) = self.pending {
            return Ok(Some((self.now, message.wire_len())));
        }
        let Some(due) = self.feedback_wake() else {
            return Ok(None);
        };
        let at = due.max(self.now);
        let page = self.scan(at)?;
        if let Some(message) = self.selected_feedback(at, page.missing)? {
            return Ok(Some((at, message.wire_len())));
        }
        // An empty scan may precede a known cumulative ACK. Its exact body is
        // knowable only when no intervening scan could add a named request.
        if let Some(ack) = self.ack_due
            && ack > at
            && page.discovery.due.is_none_or(|next| next > ack)
            && self.named.first().is_none_or(|(due, _)| due > ack)
        {
            return Ok(self
                .selected_feedback(ack, None)?
                .map(|message| (ack, message.wire_len())));
        }
        Ok(None)
    }

    /// Whether there is no retained source, recovery job or unpaid feedback.
    pub fn drained(&self) -> bool {
        self.window.group_count() == 0 && self.next_wake().is_none() && self.pending.is_none()
    }
}

#[cfg(test)]
mod tests;
