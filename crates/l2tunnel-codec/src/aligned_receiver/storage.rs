//! Reserved versions share the real Receiver transitions. Only first-touched
//! payloads are copied; proof/history owners otherwise move without snapshots.
use super::*;
use crate::{aligned_body::DecoderState, aligned_storage as heap};

struct RecordBuffer {
    bytes: Vec<u8>,
    pieces: Vec<u8>,
}
enum Undo<T> {
    Untouched,
    Empty,
    Value(T),
}
struct ChannelCheckpoint {
    expected: Option<RecordId>,
    header: DecoderState,
    preview: Option<Preview>,
}
struct Globals {
    floor: Option<SourceId>,
    pending: Option<Pending>,
    last_time: Option<Tick>,
    failure: Option<Error>,
    staged: DecoderState,
    retention: Retention,
    deadlines: cache::Checkpoint,
}

#[cfg(test)]
#[path = "storage_tests.rs"]
mod tests;
struct Journal {
    records: Vec<Undo<Record>>,
    proofs: Vec<Undo<Proof>>,
    channels: Vec<Option<ChannelCheckpoint>>,
    record_order: Vec<u16>,
    proof_order: Vec<usize>,
    channel_order: Vec<usize>,
    globals: Option<Globals>,
}
impl Journal {
    fn bytes(r: usize, s: usize, c: usize) -> Result<usize, heap::Error> {
        heap::sum(&[
            heap::array_bytes::<Undo<Record>>(r)?,
            heap::array_bytes::<Undo<Proof>>(s)?,
            heap::array_bytes::<Option<ChannelCheckpoint>>(c)?,
            heap::array_bytes::<u16>(r)?,
            heap::array_bytes::<usize>(s)?,
            heap::array_bytes::<usize>(c)?,
        ])
    }
    fn new(r: usize, s: usize, c: usize, a: &mut heap::Allocation) -> Result<Self, heap::Error> {
        let mut records = a.vec(r)?;
        records.resize_with(r, || Undo::Untouched);
        let mut proofs = a.vec(s)?;
        proofs.resize_with(s, || Undo::Untouched);
        let mut channels = a.vec(c)?;
        channels.resize_with(c, || None);
        Ok(Self {
            records,
            proofs,
            channels,
            record_order: a.vec(r)?,
            proof_order: a.vec(s)?,
            channel_order: a.vec(c)?,
            globals: None,
        })
    }
}
pub(super) struct Reserved {
    records: Vec<RecordBuffer>,
    compacted: Vec<RecordBuffer>,
    proofs: Vec<Vec<u8>>,
    journals: [Journal; 2],
    active: Option<usize>,
    complete: Vec<u8>,
    native: Vec<u8>,
    usage: Option<heap::Usage>,
}

impl Receiver {
    pub(super) fn compacted_capacity(l: Limits, reserve_replay: bool) -> usize {
        if reserve_replay {
            l.lookahead_records.min(usize::from(l.record_window))
        } else {
            0
        }
    }

    fn compacted_width(l: Limits) -> usize {
        // The ordinary pool also accepts longer encodings; those retain their
        // original slot if they cannot fit this smaller replay representation.
        (l.body.max_frame_bytes + 3).min(65_535)
    }

    pub(crate) fn reserved_bytes(l: Limits, reserve_replay: bool) -> Result<usize, heap::Error> {
        let c = usize::from(l.channels);
        let r = c
            .checked_add(l.lookahead_records)
            .ok_or(heap::Error::Layout)?;
        let s = l.source_window;
        let compacted = Self::compacted_capacity(l, reserve_replay);
        let indexed = r + compacted;
        let small = heap::product(compacted, 3)?;
        let rr = heap::product(r, 3)?;
        let ss = heap::product(s, 3)?;
        heap::sum(&[
            heap::array_bytes::<Channel>(c)?,
            heap::array_bytes::<Option<Record>>(indexed)?,
            heap::array_bytes::<u16>(indexed)?,
            heap::array_bytes::<Option<Proof>>(s)?,
            heap::product(c + 1, Decoder::reserved_bytes(l.body)?)?,
            heap::array_bytes::<u8>(l.body.max_frame_bytes)?,
            heap::array_bytes::<RecordBuffer>(rr)?,
            heap::array_bytes::<RecordBuffer>(small)?,
            heap::product(
                small,
                heap::sum(&[
                    heap::array_bytes::<u8>(Self::compacted_width(l))?,
                    heap::array_bytes::<u8>(l.max_fragments_per_record)?,
                ])?,
            )?,
            heap::array_bytes::<Vec<u8>>(ss)?,
            heap::product(
                rr,
                heap::sum(&[
                    heap::array_bytes::<u8>(65_535)?,
                    heap::array_bytes::<u8>(l.max_fragments_per_record)?,
                ])?,
            )?,
            heap::product(ss, heap::array_bytes::<u8>(l.body.symbol_bytes)?)?,
            heap::product(2, Journal::bytes(indexed, s, c)?)?,
            heap::array_bytes::<u8>(65_535)?,
            heap::array_bytes::<u8>(l.body.max_frame_bytes)?,
        ])
    }
    /// Provision all actual payload/version/channel/work buffers fallibly.
    pub fn new_reserved(
        scope: Scope,
        limits: Limits,
        budget: heap::Limits,
    ) -> Result<Self, heap::Error> {
        Self::new_reserved_mode(scope, limits, budget, ReceiverMode::Ethernet)
    }
    /// Fallibly reserve the actual selected IP context and transaction journals.
    pub fn new_reserved_ip(
        scope: Scope,
        limits: Limits,
        budget: heap::Limits,
    ) -> Result<Self, heap::Error> {
        Self::new_reserved_mode(scope, limits, budget, ReceiverMode::Ip)
    }
    /// Reserve the selected native IP codec with early-write replay storage.
    pub fn new_reserved_ip_with_early_replay(
        scope: Scope,
        limits: Limits,
        budget: heap::Limits,
    ) -> Result<Self, heap::Error> {
        Self::new_reserved_mode(scope, limits, budget, ReceiverMode::IpEarlyReplay)
    }
    /// Prepay all live fixed-anchor history and both channel rollback versions.
    pub fn new_reserved_ip_with_fixed_anchors(
        scope: Scope,
        limits: Limits,
        budget: heap::Limits,
    ) -> Result<Self, heap::Error> {
        Self::new_reserved_mode(scope, limits, budget, ReceiverMode::FixedIpAnchors)
    }
    pub(crate) fn fixed_anchor_history_bytes(limits: Limits) -> Result<usize, heap::Error> {
        heap::array_bytes::<AnchorHistory>(3 * usize::from(limits.channels))
    }
    fn new_reserved_mode(
        scope: Scope,
        limits: Limits,
        budget: heap::Limits,
        mode: ReceiverMode,
    ) -> Result<Self, heap::Error> {
        let plan = match mode {
            ReceiverMode::Ethernet => heap::ReceiverPlan::for_limits(limits)?,
            ReceiverMode::Ip => heap::ReceiverPlan::for_ip_limits(limits)?,
            ReceiverMode::FixedIpAnchors => heap::ReceiverPlan::for_fixed_anchor_ip_limits(limits)?,
            ReceiverMode::IpEarlyReplay => {
                heap::ReceiverPlan::for_ip_limits_with_early_replay(limits)?
            }
        };
        if scope.session == [0; 16] {
            return Err(heap::Error::Receiver(Error::Configuration));
        }
        let mut allocation = heap::Allocation::new(plan.capacity_bytes(), budget)?;
        let mut result = Self::new_in_mode(scope, limits, &mut allocation, mode)?;
        result
            .reserved
            .as_mut()
            .ok_or(heap::Error::Invariant)?
            .usage = Some(allocation.finish(plan.capacity_bytes())?);
        Ok(result)
    }
    /// Complete actual retained heap, never a logical-byte or RSS observation.
    pub fn storage_usage(&self) -> Option<heap::Usage> {
        self.reserved.as_ref().and_then(|r| r.usage)
    }
    #[cfg(test)]
    pub(crate) fn new_in(
        scope: Scope,
        l: Limits,
        a: &mut heap::Allocation,
    ) -> Result<Self, heap::Error> {
        Self::new_in_mode(scope, l, a, ReceiverMode::Ethernet)
    }
    fn new_in_mode(
        scope: Scope,
        l: Limits,
        a: &mut heap::Allocation,
        mode: ReceiverMode,
    ) -> Result<Self, heap::Error> {
        let ip = mode != ReceiverMode::Ethernet;
        let c = usize::from(l.channels);
        let r = c + l.lookahead_records;
        let compacted_slots = Self::compacted_capacity(l, mode.compact_replay());
        let indexed = r + compacted_slots;
        let s = l.source_window;
        let mut anchors = Vec::new();
        if mode == ReceiverMode::FixedIpAnchors {
            anchors = a.vec(3 * c)?;
            anchors.resize_with(3 * c, AnchorHistory::default);
        }
        let mut channels = a.vec(c)?;
        for _ in 0..c {
            channels.push(Channel {
                expected: Some(l.first_record),
                preview: None,
                decoder: Decoder::new_in_mode(l.body, a, ip)?,
            });
        }
        let mut records = a.vec(indexed)?;
        records.resize_with(indexed, || None);
        let mut proofs = a.vec(s)?;
        proofs.resize_with(s, || None);
        let staged = Decoder::new_in_mode(l.body, a, ip)?;
        let native = a.bytes(l.body.max_frame_bytes)?;
        let mut free_records = a.vec(3 * r)?;
        for _ in 0..3 * r {
            // Pool capacity is prepaid, but no payload is live yet. Acquisition
            // initializes the exact record/piece extent before any read.
            free_records.push(RecordBuffer {
                bytes: a.vec(65_535)?,
                pieces: a.vec(l.max_fragments_per_record)?,
            });
        }
        let mut compacted = a.vec(3 * compacted_slots)?;
        for _ in 0..3 * compacted_slots {
            compacted.push(RecordBuffer {
                bytes: a.vec(Self::compacted_width(l))?,
                pieces: a.vec(l.max_fragments_per_record)?,
            });
        }
        let mut free_proofs = a.vec(3 * s)?;
        for _ in 0..3 * s {
            // proof_buffer and transaction copies initialize the whole live
            // extent with extend_from_slice; unused capacity is never read.
            free_proofs.push(a.vec(l.body.symbol_bytes)?);
        }
        let journals = [
            Journal::new(indexed, s, c, a)?,
            Journal::new(indexed, s, c, a)?,
        ];
        Ok(Self {
            scope,
            limits: l,
            compact_units: false,
            compacted_slots,
            mode,
            channels,
            anchors,
            records,
            ordered_slots: a.vec(indexed)?,
            proofs,
            retention: Retention::default(),
            deadlines: DeadlineCache::default(),
            floor: Some(l.first_source),
            staged,
            native,
            pending: None,
            last_time: None,
            failure: None,
            reserved: Some(Reserved {
                records: free_records,
                compacted,
                proofs: free_proofs,
                journals,
                active: None,
                complete: a.bytes(65_535)?,
                native: a.bytes(l.body.max_frame_bytes)?,
                usage: None,
            }),
        })
    }
    pub(super) fn record_buffers(
        &mut self,
        bytes: usize,
        pieces: usize,
    ) -> Result<(Vec<u8>, Vec<u8>), Error> {
        let Some(r) = &mut self.reserved else {
            return Ok((vec![0; bytes], vec![0; pieces]));
        };
        let next = r.records.last().ok_or(Error::Storage)?;
        if next.bytes.capacity() < bytes || next.pieces.capacity() < pieces {
            return Err(Error::Storage);
        }
        let mut b = r.records.pop().ok_or(Error::Storage)?;
        b.bytes.resize(bytes, 0);
        b.bytes.fill(0);
        b.pieces.resize(pieces, 0);
        b.pieces.fill(0);
        Ok((b.bytes, b.pieces))
    }
    // The caller has journaled the original row and physically committed its
    // packet. Retain the exact encoded bytes, bitmap, deadline and identity in
    // the same indexed row, returning its full record slab to live admission.
    pub(super) fn compact_delivered(&mut self, slot: usize) -> Result<(), Error> {
        if self.retention.compacted >= self.compacted_slots {
            return Ok(());
        }
        let row = self.records[slot].as_mut().ok_or(Error::Malformed)?;
        if row.bytes.len() > Self::compacted_width(self.limits) {
            return Ok(());
        }
        if let Some(reserved) = &mut self.reserved {
            let mut spare = reserved.compacted.pop().ok_or(Error::Storage)?;
            spare.bytes.clear();
            spare.pieces.clear();
            spare.bytes.extend_from_slice(&row.bytes);
            spare.pieces.extend_from_slice(&row.pieces);
            std::mem::swap(&mut row.bytes, &mut spare.bytes);
            std::mem::swap(&mut row.pieces, &mut spare.pieces);
            spare.bytes.clear();
            spare.pieces.clear();
            reserved.records.push(spare);
        }
        row.compacted = true;
        self.retention.compacted += 1;
        Ok(())
    }
    pub(super) fn proof_buffer(&mut self, symbol: &[u8]) -> Result<Vec<u8>, Error> {
        let Some(r) = &mut self.reserved else {
            return Ok(symbol.to_vec());
        };
        if r.proofs.last().is_none_or(|b| b.capacity() < symbol.len()) {
            return Err(Error::Storage);
        }
        let mut b = r.proofs.pop().ok_or(Error::Storage)?;
        b.clear();
        b.extend_from_slice(symbol);
        Ok(b)
    }
    pub(super) fn recycle_record(&mut self, record: Record) -> Result<(), Error> {
        if let Some(r) = &mut self.reserved {
            let pool = if record.compacted {
                &mut r.compacted
            } else {
                &mut r.records
            };
            if pool.len() == pool.capacity() {
                return Err(Error::Storage);
            }
            let mut b = RecordBuffer {
                bytes: record.bytes,
                pieces: record.pieces,
            };
            b.bytes.clear();
            b.pieces.clear();
            pool.push(b);
        }
        Ok(())
    }
    pub(super) fn recycle_proof(&mut self, mut proof: Proof) -> Result<(), Error> {
        if let Some(r) = &mut self.reserved {
            if r.proofs.len() == r.proofs.capacity() {
                return Err(Error::Storage);
            }
            proof.bytes.clear();
            r.proofs.push(proof.bytes);
        }
        Ok(())
    }
    pub(super) fn validate_completion(
        &mut self,
        slot: usize,
        offset: usize,
        body: &[u8],
    ) -> Result<(), Error> {
        let record = self.records[slot].as_ref().ok_or(Error::Malformed)?;
        let validate = |bytes: &[u8]| {
            fixed_anchor::validate_tag(self.mode, record.id, bytes, true)?;
            if bytes.first() == Some(&aligned_body::FIXED_ANCHOR_TAG) {
                let (_, inner) =
                    aligned_body::fixed_anchor_parts(bytes).map_err(|_| Error::Malformed)?;
                if implicit_body(inner[0]) {
                    // The exact reconstructed fragment length is outer-authenticated.
                    // Its context-dependent payload extent is checked at decode.
                    return Ok(());
                }
            }
            if explicit_length(bytes)? != bytes.len() {
                return Err(Error::Malformed);
            }
            Ok(())
        };
        if let Some(r) = &mut self.reserved {
            let n = record.bytes.len();
            if n > r.complete.len() {
                return Err(Error::Storage);
            }
            r.complete[..n].copy_from_slice(&record.bytes);
            r.complete[offset..offset + body.len()].copy_from_slice(body);
            validate(&r.complete[..n])?;
        } else {
            let mut complete = record.bytes.clone();
            complete[offset..offset + body.len()].copy_from_slice(body);
            validate(&complete)?;
        }
        Ok(())
    }
    pub(super) fn touch_record(&mut self, slot: usize, copy: bool) -> Result<(), Error> {
        let Some(active) = self.reserved.as_ref().and_then(|r| r.active) else {
            return Ok(());
        };
        let r = self.reserved.as_mut().ok_or(Error::Storage)?;
        if !matches!(r.journals[active].records[slot], Undo::Untouched) {
            return Ok(());
        }
        if r.journals[active].record_order.len() == r.journals[active].record_order.capacity() {
            return Err(Error::Storage);
        }
        let replacement = if copy && let Some(old) = &self.records[slot] {
            let pool = if old.compacted {
                &mut r.compacted
            } else {
                &mut r.records
            };
            let b = pool.last().ok_or(Error::Storage)?;
            if b.bytes.capacity() < old.bytes.len() || b.pieces.capacity() < old.pieces.len() {
                return Err(Error::Storage);
            }
            let mut b = pool.pop().ok_or(Error::Storage)?;
            b.bytes.clear();
            b.bytes.extend_from_slice(&old.bytes);
            b.pieces.clear();
            b.pieces.extend_from_slice(&old.pieces);
            Some(Record {
                channel: old.channel,
                id: old.id,
                bytes: b.bytes,
                pieces: b.pieces,
                count: old.count,
                fragment_capacity: old.fragment_capacity,
                padding: old.padding,
                deadline: old.deadline,
                early_delivered: old.early_delivered,
                compacted: old.compacted,
                independent_short: old.independent_short,
                defer_early: old.defer_early,
                defer_head: old.defer_head,
            })
        } else {
            None
        };
        let old = self.records[slot].take();
        if replacement.is_none()
            && let Some(record) = &old
        {
            self.retention.remove_record(record);
            self.deadlines
                .remove(record.deadline, self.retention.is_empty());
        }
        r.journals[active].records[slot] = old.map_or(Undo::Empty, Undo::Value);
        r.journals[active].record_order.push(slot as u16);
        self.records[slot] = replacement;
        Ok(())
    }
    pub(super) fn touch_proof(&mut self, slot: usize) -> Result<(), Error> {
        let Some(r) = &mut self.reserved else {
            return Ok(());
        };
        let Some(active) = r.active else {
            return Ok(());
        };
        let j = &mut r.journals[active];
        if !matches!(j.proofs[slot], Undo::Untouched) {
            return Ok(());
        }
        if j.proof_order.len() == j.proof_order.capacity() {
            return Err(Error::Storage);
        }
        let old = self.proofs[slot].take();
        if let Some(proof) = &old {
            self.retention.remove_proof(proof);
            self.deadlines
                .remove(proof.deadline, self.retention.is_empty());
        }
        j.proofs[slot] = old.map_or(Undo::Empty, Undo::Value);
        j.proof_order.push(slot);
        Ok(())
    }
    pub(super) fn touch_channel(&mut self, channel: usize) -> Result<(), Error> {
        let Some(r) = &mut self.reserved else {
            return Ok(());
        };
        let Some(active) = r.active else {
            return Ok(());
        };
        let j = &mut r.journals[active];
        if j.channels[channel].is_some() {
            return Ok(());
        }
        if j.channel_order.len() == j.channel_order.capacity() {
            return Err(Error::Storage);
        }
        if self.mode == ReceiverMode::FixedIpAnchors {
            let backup = (active + 1) * self.channels.len() + channel;
            self.anchors[backup] = self.anchors[channel].clone();
        }
        j.channels[channel] = Some(ChannelCheckpoint {
            expected: self.channels[channel].expected,
            header: self.channels[channel].decoder.checkpoint(),
            preview: self.channels[channel].preview.clone(),
        });
        j.channel_order.push(channel);
        Ok(())
    }
    fn begin_journal(&mut self, index: usize) -> Result<(), Error> {
        let globals = Globals {
            floor: self.floor,
            pending: self.pending,
            last_time: self.last_time,
            failure: self.failure,
            staged: self.staged.checkpoint(),
            retention: self.retention,
            deadlines: self.deadlines.checkpoint(),
        };
        let r = self.reserved.as_mut().ok_or(Error::Storage)?;
        if r.active != (index == 1).then_some(0) || r.journals[index].globals.is_some() {
            return Err(Error::Storage);
        }
        if index == 1 {
            r.native.copy_from_slice(&self.native);
        }
        r.journals[index].globals = Some(globals);
        r.active = Some(index);
        Ok(())
    }
    fn end_journal(&mut self, index: usize, commit: bool) -> Result<(), Error> {
        if self.reserved.as_ref().and_then(|r| r.active) != Some(index) {
            return Err(Error::Storage);
        }
        loop {
            let next = self.reserved.as_mut().ok_or(Error::Storage)?.journals[index]
                .record_order
                .pop()
                .map(usize::from);
            let Some(slot) = next else {
                break;
            };
            let old = std::mem::replace(
                &mut self.reserved.as_mut().ok_or(Error::Storage)?.journals[index].records[slot],
                Undo::Untouched,
            );
            if commit {
                if let Undo::Value(record) = old {
                    self.recycle_record(record)?;
                }
            } else {
                if let Some(record) = self.records[slot].as_ref() {
                    let position = self
                        .record_position(record.channel, record.id)
                        .map_err(|_| Error::Storage)?;
                    self.ordered_slots.remove(position);
                }
                if let Some(record) = self.records[slot].take() {
                    self.retention.remove_record(&record);
                    self.deadlines
                        .remove(record.deadline, self.retention.is_empty());
                    self.recycle_record(record)?;
                }
                let restored = match old {
                    Undo::Empty => None,
                    Undo::Value(record) => Some(record),
                    Undo::Untouched => return Err(Error::Storage),
                };
                if let Some(record) = &restored {
                    let position = self
                        .record_position(record.channel, record.id)
                        .err()
                        .ok_or(Error::Storage)?;
                    self.ordered_slots.insert(position, slot as u16);
                    self.retention.add_record(record);
                    self.deadlines.insert(record.deadline);
                }
                self.records[slot] = restored;
            }
        }
        loop {
            let next = self.reserved.as_mut().ok_or(Error::Storage)?.journals[index]
                .proof_order
                .pop();
            let Some(slot) = next else {
                break;
            };
            let old = std::mem::replace(
                &mut self.reserved.as_mut().ok_or(Error::Storage)?.journals[index].proofs[slot],
                Undo::Untouched,
            );
            if commit {
                if let Undo::Value(proof) = old {
                    self.recycle_proof(proof)?;
                }
            } else {
                if let Some(proof) = self.proofs[slot].take() {
                    self.retention.remove_proof(&proof);
                    self.deadlines
                        .remove(proof.deadline, self.retention.is_empty());
                    self.recycle_proof(proof)?;
                }
                let restored = match old {
                    Undo::Empty => None,
                    Undo::Value(proof) => Some(proof),
                    Undo::Untouched => return Err(Error::Storage),
                };
                if let Some(proof) = &restored {
                    self.retention.add_proof(proof);
                    self.deadlines.insert(proof.deadline);
                }
                self.proofs[slot] = restored;
            }
        }
        loop {
            let next = self.reserved.as_mut().ok_or(Error::Storage)?.journals[index]
                .channel_order
                .pop();
            let Some(channel) = next else {
                break;
            };
            let old = self.reserved.as_mut().ok_or(Error::Storage)?.journals[index].channels
                [channel]
                .take()
                .ok_or(Error::Storage)?;
            if !commit {
                self.channels[channel].expected = old.expected;
                self.channels[channel].decoder.restore(old.header);
                self.channels[channel].preview = old.preview;
                if self.mode == ReceiverMode::FixedIpAnchors {
                    let backup = (index + 1) * self.channels.len() + channel;
                    self.anchors[channel] = self.anchors[backup].clone();
                }
            }
        }
        let r = self.reserved.as_mut().ok_or(Error::Storage)?;
        let globals = r.journals[index].globals.take().ok_or(Error::Storage)?;
        if !commit {
            self.floor = globals.floor;
            self.pending = globals.pending;
            self.last_time = globals.last_time;
            self.failure = globals.failure;
            self.retention = globals.retention;
            self.deadlines.restore(globals.deadlines);
            self.staged.restore(globals.staged);
            if index == 1 {
                self.native.copy_from_slice(&r.native);
            }
        }
        r.active = (index == 1).then_some(0);
        Ok(())
    }
    pub(super) fn reserved_owned_batch(
        &mut self,
        symbols: &[AuthenticatedSymbol<'_>],
        now: Tick,
        policy: Option<BatchValidation>,
    ) -> Result<Vec<Admission>, Error> {
        if !(1..=255).contains(&symbols.len()) {
            return Err(Error::Configuration);
        }
        self.limits.batch_memory_bound_bytes()?;
        self.check_time(now)?;
        let mut result = Vec::new();
        result
            .try_reserve_exact(symbols.len())
            .map_err(|_| Error::Allocation)?;
        result.resize(symbols.len(), Admission::Accepted);
        self.reserved_batch_into(symbols, now, &mut result, policy)?;
        Ok(result)
    }
    /// Atomic batch admission with caller-owned outcomes; selected endpoint uses
    /// this path without allocating a returned Vec for each protected source.
    pub fn admit_batch_authenticated_into(
        &mut self,
        symbols: &[AuthenticatedSymbol<'_>],
        now: Tick,
        output: &mut [Admission],
    ) -> Result<usize, Error> {
        if self.reserved.is_some() {
            return self.reserved_batch_into(symbols, now, output, None);
        }
        if output.len() < symbols.len() {
            return Err(Error::OutputTooSmall);
        }
        let results = self.admit_batch_authenticated(symbols, now)?;
        output[..results.len()].copy_from_slice(&results);
        Ok(results.len())
    }
    /// Same semantic transaction as the owned-output API, with bounded output.
    pub fn admit_validated_batch_authenticated_into(
        &mut self,
        symbols: &[AuthenticatedSymbol<'_>],
        now: Tick,
        output: &mut [Admission],
    ) -> Result<usize, Error> {
        self.validated_batch_into(symbols, now, output, BatchValidation::Ordered)
    }

    /// Validate every complete retained body using the independent-packet delivery policy.
    /// The enclosing owner must enforce its negotiated native encoding on all incoming units.
    /// The validation journal rehearses real decoding and leaves live native custody intact.
    pub fn admit_independent_validated_batch_authenticated_into(
        &mut self,
        symbols: &[AuthenticatedSymbol<'_>],
        now: Tick,
        output: &mut [Admission],
    ) -> Result<usize, Error> {
        self.validated_batch_into(symbols, now, output, BatchValidation::IndependentPackets)
    }

    fn validated_batch_into(
        &mut self,
        symbols: &[AuthenticatedSymbol<'_>],
        now: Tick,
        output: &mut [Admission],
        policy: BatchValidation,
    ) -> Result<usize, Error> {
        if self.reserved.is_some() {
            return self.reserved_batch_into(symbols, now, output, Some(policy));
        }
        if output.len() < symbols.len() {
            return Err(Error::OutputTooSmall);
        }
        let results = self.validated_batch(symbols, now, policy)?;
        output[..results.len()].copy_from_slice(&results);
        Ok(results.len())
    }
    fn reserved_batch_into(
        &mut self,
        symbols: &[AuthenticatedSymbol<'_>],
        now: Tick,
        output: &mut [Admission],
        policy: Option<BatchValidation>,
    ) -> Result<usize, Error> {
        if !(1..=255).contains(&symbols.len()) {
            return Err(Error::Configuration);
        }
        self.limits.batch_memory_bound_bytes()?;
        self.check_time(now)?;
        if output.len() < symbols.len() {
            return Err(Error::OutputTooSmall);
        }
        self.begin_journal(0)?;
        let mut outcomes = [Admission::Accepted; 255];
        let admission = (|| {
            for (input, outcome) in symbols.iter().zip(&mut outcomes) {
                *outcome = self.admit_authenticated(input.identity, input.bytes, now)?;
            }
            Ok(())
        })();
        if let Err(error) = admission {
            self.end_journal(0, false)?;
            return Err(error);
        }
        if let Some(policy) = policy {
            self.begin_journal(1)?;
            let validation = self.validate_pending_batch(now, policy);
            self.end_journal(1, false)?;
            if let Err(error) = validation {
                self.end_journal(0, false)?;
                return Err(error);
            }
        }
        self.end_journal(0, true)?;
        output[..symbols.len()].copy_from_slice(&outcomes[..symbols.len()]);
        Ok(symbols.len())
    }
    pub(super) fn validate_pending_batch(
        &mut self,
        now: Tick,
        policy: BatchValidation,
    ) -> Result<(), Error> {
        if self.pending.is_some() {
            self.commit_delivery(now)?;
        }
        let mut work = self.records.len() + self.channels.len();
        for channel in 0..self.limits.channels {
            loop {
                if work == 0 {
                    return Err(Error::UnresolvedContext);
                }
                work -= 1;
                let channel = ChannelId(channel as u8);
                let prepared = match policy {
                    BatchValidation::Ordered => self.prepare(channel, now, 1)?,
                    BatchValidation::IndependentPackets => self.prepare_with_independent_packets(
                        channel,
                        now,
                        1,
                        |_| true,
                        |_, _| EarlyDecision::Allow,
                    )?,
                };
                match prepared {
                    Prepared::Idle => break,
                    Prepared::Progress => {}
                    Prepared::Ready => self.commit_delivery(now)?,
                }
            }
        }
        if self
            .records
            .iter()
            .flatten()
            .any(|r| r.complete() && !r.early_delivered)
        {
            return Err(Error::UnresolvedContext);
        }
        Ok(())
    }
}
