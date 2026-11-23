//! Compact native record ownership for the striped physical scheduler.
use super::Direction;
use crate::{
    aligned::NativePolicy,
    codec::{
        aligned_body::NativeEncodingObservation, aligned_receiver as r, aligned_storage,
        packed_envelope, packed_sender,
    },
    fec::{self, GenerationId, striped_group::schedule::ScheduledSender},
};
use arrayvec::ArrayVec;
use ring::digest;
use std::fmt;

#[path = "custody.rs"]
mod custody;
use custody::{Custody, Key, Span};

/// Failure at one specific native, Packed, storage or striped handoff boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeError {
    /// Inconsistent negotiated native configuration.
    Configuration,
    /// A source, byte identity or ordered unit range contradicts an earlier admission.
    Identity,
    /// The finite bridge custody window has no space.
    Capacity,
    /// A staged native or prepared device delivery reached its original deadline.
    Expired,
    /// Monotonic time regressed or exceeded the representable deadline.
    Clock,
    /// Packed record staging or source serialization.
    Sender(packed_sender::Error),
    /// Compact authenticated source interpretation.
    Envelope(packed_envelope::Error),
    /// Aligned record admission, decoding or native commitment.
    Receiver(r::Error),
    /// Resource reservation for the atomic receive ledger.
    Storage(aligned_storage::Error),
    /// The striped scheduler retained or rejected the sealed Packed source.
    Fec(fec::Error),
}
impl fmt::Display for NativeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "striped native: {self:?}")
    }
}
impl std::error::Error for NativeError {}
impl NativeError {
    /// A retry after downstream progress may admit this exact, unchanged input.
    pub const fn is_backpressure(self) -> bool {
        match self {
            Self::Capacity | Self::Fec(fec::Error::Capacity) => true,
            Self::Sender(e) => e.buffer_refusal().is_some(),
            Self::Receiver(e) => e.buffer_refusal().is_some(),
            _ => false,
        }
    }
}

/// Retains one native stage and one timed Packed group across recovery backpressure.
pub struct NativeSender {
    config: Direction,
    context: fec::FecContext,
    packing: packed_sender::Sender,
    scratch: Vec<u8>,
    waiting_bytes: Option<usize>,
    now: u64,
}
impl NativeSender {
    /// Open the native record encoder selected by the authenticated direction.
    pub fn new(config: Direction, scope: r::Scope) -> Result<Self, NativeError> {
        config.validate().map_err(|_| NativeError::Configuration)?;
        let capacity = aligned_storage::Limits {
            capacity_bytes: config
                .packing_plan()
                .map_err(NativeError::Storage)?
                .capacity_bytes(),
        };
        let mut packing = if config.native_policy.uses_ip_headers() {
            packed_sender::Sender::new_reserved_ip(scope, config.packing, capacity)
        } else {
            packed_sender::Sender::new_reserved(scope, config.packing, capacity)
        }
        .map_err(NativeError::Storage)?;
        packing
            .enable_fragment_tail_packing()
            .map_err(NativeError::Sender)?;
        let max = config
            .packing
            .envelope()
            .max_source_bytes()
            .map_err(NativeError::Envelope)?;
        Ok(Self {
            config,
            context: config.context(scope),
            packing,
            scratch: super::scratch(max)?,
            waiting_bytes: None,
            now: 0,
        })
    }
    fn observe(&mut self, now: u64) -> Result<(), NativeError> {
        if now < self.now {
            return Err(NativeError::Clock);
        }
        if self
            .packing
            .oldest_admission_micros()
            .is_some_and(|t| now - t >= self.config.codec_stage_micros)
        {
            return Err(NativeError::Expired);
        }
        self.now = now;
        Ok(())
    }
    /// Stage one complete original and return its absolute native record identity.
    pub fn stage(
        &mut self,
        now: u64,
        channel: r::ChannelId,
        frame: &[u8],
    ) -> Result<r::RecordIdentity, NativeError> {
        self.stage_observed(now, channel, frame).map(|(id, _)| id)
    }
    /// Return the actual encoder's observation after staging the whole native packet.
    pub fn stage_observed(
        &mut self,
        now: u64,
        channel: r::ChannelId,
        frame: &[u8],
    ) -> Result<(r::RecordIdentity, NativeEncodingObservation), NativeError> {
        self.observe(now)?;
        now.checked_add(self.config.codec_stage_micros)
            .ok_or(NativeError::Clock)?;
        let result = match self.config.native_policy {
            NativePolicy::FixedAnchorIpHeaders => self
                .packing
                .stage_fixed_anchor_headers_observed(channel, frame, now),
            NativePolicy::IpHeaders => self
                .packing
                .stage_refreshed_headers_observed(channel, frame, now),
            NativePolicy::EthernetHeaders => self.packing.stage_observed(channel, frame, now),
            NativePolicy::RawEthernet | NativePolicy::RawIp => {
                self.packing.stage_raw_observed(channel, frame, now)
            }
            NativePolicy::Lz4Ethernet | NativePolicy::Lz4Ip => {
                self.packing.stage_lz4_observed(channel, frame, now)
            }
        };
        result.map_err(NativeError::Sender)
    }
    /// Offer at most one immutable compact source. Only successful striped admission
    /// consumes it; the physical charge is made later by the carrier at actual send.
    pub fn pump(
        &mut self,
        now: u64,
        sender: &mut ScheduledSender,
    ) -> Result<Option<GenerationId>, NativeError> {
        if sender.context() != self.context {
            return Err(NativeError::Fec(fec::Error::ContextMismatch));
        }
        self.observe(now)?;
        let n = if let Some(n) = self.waiting_bytes {
            n
        } else {
            self.packing.poll(now).map_err(NativeError::Sender)?;
            if !self.packing.has_pending_source() {
                return Ok(None);
            }
            let n = self
                .packing
                .write_pending_compact(&mut self.scratch)
                .map_err(NativeError::Sender)?;
            self.waiting_bytes = Some(n);
            n
        };
        let id = sender
            .submit(now, &self.scratch[..n])
            .map_err(NativeError::Fec)?;
        self.packing.commit_source().map_err(NativeError::Sender)?;
        self.waiting_bytes = None;
        Ok(Some(id))
    }
    /// Earliest local packing work or original expiry. A pending source also needs
    /// downstream credit; do not spin on this time after an explicit FEC refusal.
    pub fn next_wake(&self) -> Option<u64> {
        let expiry = self.stage_deadline();
        // A sealed source refused by FEC has no work until its scheduler seals a
        // group or accepts peer credit. Those events have their own wake paths.
        if self.waiting_bytes.is_some() {
            return expiry;
        }
        let codec = if self.packing.has_pending_source() || self.packing.status().staged_frame {
            Some(self.now)
        } else {
            self.packing.deadline_micros()
        };
        expiry.into_iter().chain(codec).min()
    }
    pub(super) fn has_staged_frame(&self) -> bool {
        self.packing.status().staged_frame
    }
    /// No staged or waiting native/packed data.
    pub fn is_idle(&self) -> bool {
        self.packing.is_idle()
    }
    pub(super) fn heap_usage(&self) -> Option<(usize, usize)> {
        let u = self.packing.storage_usage()?;
        Some((
            u.capacity_bytes + self.scratch.capacity(),
            u.allocations + 1,
        ))
    }
    /// Absolute expiry of the oldest retained native, including its packed fragments.
    pub fn stage_deadline(&self) -> Option<u64> {
        self.packing
            .oldest_admission_micros()
            .and_then(|t| t.checked_add(self.config.codec_stage_micros))
    }
}

/// Atomically admits Packed sources, owns native bytes until the device commits,
/// and reports which source custody entries can subsequently receive FEC credit.
pub struct NativeReceiver {
    config: Direction,
    scope: r::Scope,
    records: r::Receiver,
    custody: Custody,
    channel: r::ChannelId,
    native_due: Option<u64>,
}
impl NativeReceiver {
    /// Reserve the selected decoder, including its atomic batch scratch and early proofs.
    pub fn new(config: Direction, scope: r::Scope) -> Result<Self, NativeError> {
        config.validate().map_err(|_| NativeError::Configuration)?;
        let limits = config.receiver;
        let capacity = aligned_storage::Limits {
            capacity_bytes: config
                .receiver_plan()
                .map_err(NativeError::Storage)?
                .capacity_bytes(),
        };
        let mut records = if config.native_policy.is_ip()
            && config.native_policy != NativePolicy::FixedAnchorIpHeaders
        {
            r::Receiver::new_reserved_ip_with_early_replay(scope, limits, capacity)
        } else {
            config
                .native_policy
                .reserved_receiver(scope, limits, capacity)
        }
        .map_err(NativeError::Storage)?;
        records
            .enable_compact_units()
            .map_err(NativeError::Receiver)?;
        let custody = Custody::new(
            config.first,
            config.packing.first_unit.0,
            config.source_limit,
            config.packing.max_units,
        )?;
        Ok(Self {
            config,
            scope,
            records,
            custody,
            channel: r::ChannelId(0),
            native_due: None,
        })
    }
    fn tick(&mut self, now: u64) -> Result<(), NativeError> {
        if self.native_due.is_some_and(|t| now >= t) {
            return Err(NativeError::Expired);
        }
        self.records
            .tick(r::Tick(now))
            .map_err(NativeError::Receiver)
    }
    /// Admit the exact recovery-owned source. An error admits no part of its unit batch.
    pub fn admit(
        &mut self,
        now: u64,
        source: GenerationId,
        original: &[u8],
    ) -> Result<(), NativeError> {
        if self.native_due.is_some_and(|t| now >= t) {
            return Err(NativeError::Expired);
        }
        if self.records.deadline().is_some_and(|t| now >= t.0) {
            self.tick(now)?;
        }
        let view = packed_envelope::decode_compact(
            self.config.packing.envelope(),
            self.scope,
            r::SourceId(source.0),
            original,
        )
        .map_err(NativeError::Envelope)?;
        let first = view.identity().first_unit.0;
        let span = Span {
            first,
            last: first
                .checked_add((view.len() - 1) as u64)
                .ok_or(NativeError::Identity)?,
        };
        let hash = digest::digest(&digest::SHA256, original);
        let hash: [u8; 32] = hash
            .as_ref()
            .try_into()
            .map_err(|_| NativeError::Identity)?;
        if !self.custody.preflight(source, span, hash)? {
            return self.tick(now);
        }
        let mut inputs = ArrayVec::<_, 255>::new();
        let mut keys = ArrayVec::<Key, 255>::new();
        for unit in view.units().map_err(NativeError::Envelope)? {
            if !self.config.native_policy.accepts_unit(unit.bytes) {
                return Err(NativeError::Identity);
            }
            let id = r::RecordIdentity {
                channel: r::ChannelId(unit.bytes[0]),
                record: unit.identity.record,
            };
            if !self
                .records
                .record_consumed(id)
                .map_err(NativeError::Receiver)?
            {
                keys.try_push((id.channel.0, id.record.0))
                    .map_err(|_| NativeError::Identity)?;
            }
            inputs
                .try_push(r::AuthenticatedSymbol {
                    identity: unit.identity,
                    bytes: unit.bytes,
                })
                .map_err(|_| NativeError::Identity)?;
        }
        keys.sort_unstable();
        let mut previous = None;
        keys.retain(|key| previous.replace(*key) != Some(*key));
        let mut outcomes = [r::Admission::Accepted; 255];
        self.records
            .admit_batch_authenticated_into(&inputs, r::Tick(now), &mut outcomes[..inputs.len()])
            .map_err(NativeError::Receiver)?;
        self.custody.admit(source, span, hash, &keys)
    }
    /// Prepare a native packet using the caller's actual early TCP and control
    /// ordering guard. For non-IP access retain per-channel FIFO.
    pub fn prepare(
        &mut self,
        now: u64,
        work: usize,
        changed: impl Fn(u64) -> bool,
        decide: impl Fn(&[u8], bool, bool) -> r::EarlyDecision,
    ) -> Result<r::Prepared, NativeError> {
        self.tick(now)?;
        if work == 0 {
            return Err(NativeError::Configuration);
        }
        if self.records.pending().is_some() {
            return Ok(r::Prepared::Ready);
        }
        let due = now
            .checked_add(self.config.native_stall_micros)
            .ok_or(NativeError::Clock)?;
        let ch = self
            .records
            .next_retained_channel(self.channel)
            .unwrap_or(self.channel);
        let before = self.records.expected(ch).map_err(NativeError::Receiver)?;
        let work = work.min(self.config.packing.work_limit);
        let prepared = if self.config.native_policy.is_ip() {
            self.records
                .prepare_with_native_ordering(ch, r::Tick(now), work, changed, decide)
        } else {
            self.records.prepare_ordered(ch, r::Tick(now), work)
        }
        .map_err(NativeError::Receiver)?;
        self.channel = r::ChannelId(((u16::from(ch.0) + 1) % self.config.receiver.channels) as u8);
        let after = self.records.expected(ch).map_err(NativeError::Receiver)?;
        let mut cursor = before;
        while cursor != after {
            let id = cursor.ok_or(NativeError::Identity)?;
            self.custody.complete((ch.0, id.0))?;
            cursor = id.0.checked_add(1).map(r::RecordId);
        }
        if prepared == r::Prepared::Ready {
            self.native_due = Some(due);
        }
        Ok(prepared)
    }
    /// Repeated borrows return the same whole packet after device backpressure.
    pub fn pending(&self) -> Option<r::Delivery<'_>> {
        self.records.pending()
    }
    /// Commit one complete physical device handoff. A successful prepare grants no credit.
    pub fn commit_native(&mut self, now: u64) -> Result<(), NativeError> {
        self.tick(now)?;
        let delivery = self.records.pending().ok_or(NativeError::Identity)?;
        let key = (delivery.channel.0, delivery.record.0);
        self.records
            .commit_delivery(r::Tick(now))
            .map_err(NativeError::Receiver)?;
        self.native_due = None;
        self.custody.complete(key)
    }
    /// Do bounded dependency work and peek one source ready for FEC commit.
    pub fn committable_source(&mut self) -> Option<GenerationId> {
        self.custody.poll(self.config.packing.work_limit)
    }
    /// Release this bridge receipt only after the receive scheduler accepts the completion.
    pub fn confirm_source(&mut self, id: GenerationId) -> Result<(), NativeError> {
        self.custody.committed(id)
    }
    /// More ready sources or bounded dependency work can be serviced immediately.
    pub fn has_custody_work(&self) -> bool {
        self.custody.work_pending()
    }
    /// Number of outer sources waiting on native records or FEC handoff.
    pub fn retained_sources(&self) -> usize {
        self.custody.retained()
    }
    /// Five reserved ordered indexes for source runs, pending sources, dependencies and receipts.
    pub fn custody_capacity_bytes(&self) -> usize {
        self.custody.capacity_bytes()
    }
    /// Exact index storage needed even if all native records depend on distinct source units.
    pub fn custody_planned_bytes(direction: Direction) -> Result<usize, NativeError> {
        Custody::planned_bytes(direction.source_limit, direction.packing.max_units)
    }
    pub(super) fn heap_usage(&self) -> Option<(usize, usize)> {
        let u = self.records.storage_usage()?;
        Some((
            u.capacity_bytes + self.custody.capacity_bytes(),
            u.allocations + 5,
        ))
    }
    pub(super) fn admitted(&self, id: GenerationId) -> bool {
        self.custody.admitted(id)
    }
    /// All native records, old holes, source dependencies and device writes retired.
    pub fn drained(&self) -> bool {
        let status = self.records.status();
        status.failure.is_none()
            && status.retained_sources == 0
            && status.retained_records == 0
            && self.custody.drained()
    }
    /// Earliest of the original record expiry and the pending device-write cap.
    pub fn pending_deadline(&self) -> Option<u64> {
        self.native_due
            .into_iter()
            .chain(self.records.pending_deadline().map(|t| t.0))
            .min()
    }
    /// Earliest native stall or retained codec deadline.
    pub fn deadline(&self) -> Option<u64> {
        self.native_due
            .into_iter()
            .chain(self.records.deadline().map(|t| t.0))
            .min()
    }
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
