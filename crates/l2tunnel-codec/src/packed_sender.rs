//! One bounded aligned stage and timed packed source with external recovery IDs.
use crate::{
    aligned_receiver::{ChannelId, RecordId, RecordIdentity, Scope, SourceId},
    aligned_sender as aligned, packed, packed_envelope as envelope,
};
use std::{fmt, mem::size_of};

/// Fixed per-session packetization and distinct absolute unit sequence policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Config {
    /// Existing per-channel codec and one-frame bound.
    pub sender: aligned::Config,
    /// Exact Python packing geometry and maximum first-unit hold time.
    pub packing: packed::Config,
    /// Negotiated count ceiling, independently bounded to1..255.
    pub max_units: u8,
    /// Initial aligned-unit ID, distinct from externally owned recovery IDs.
    pub first_unit: SourceId,
    /// Maximum unit handoff attempts per call, in1..255.
    pub work_limit: usize,
}
impl Config {
    /// Canonical envelope geometry; every metadata byte belongs to the source.
    pub fn envelope(self) -> envelope::Config {
        envelope::Config {
            symbol_bytes: self.packing.symbol_bytes,
            channels: self.sender.channels,
            max_units: self.max_units,
        }
    }
    /// Historical allocating-owner scalar guard, not reserved backing capacity.
    pub fn memory_bound_bytes(self) -> Result<usize, Error> {
        if self.sender.body.symbol_bytes != self.packing.symbol_bytes
            || !(1..=255).contains(&self.work_limit)
        {
            return Err(Error::Configuration);
        }
        self.envelope()
            .max_source_bytes()
            .map_err(Error::Envelope)?;
        let total = self.sender.memory_bound_bytes().map_err(Error::Aligned)?
            + self.packing.memory_bound_bytes().map_err(Error::Packing)?
            + usize::from(self.max_units) * size_of::<RecordId>()
            + size_of::<LegacyLayout>();
        if total > 64 * 1024 * 1024 {
            return Err(Error::Configuration);
        }
        Ok(total)
    }
}
/// Explicit configuration, ownership or bounded input failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// Inconsistent or excessive local policy.
    Configuration,
    /// One earlier native frame still owns the bounded stage.
    Busy,
    /// No sealed complete source is ready for recovery ownership.
    NoPending,
    /// The absolute unit space cannot represent remaining work; no wrap occurs.
    Exhausted,
    /// Existing aligned sender rejected input or state.
    Aligned(aligned::Error),
    /// Existing packer rejected input or injected time.
    Packing(packed::Error),
    /// Complete authenticated-identity envelope cannot be encoded.
    Envelope(envelope::Error),
    /// Internal source metadata disagrees with its exact packed contents.
    Ownership,
    /// Explicit source-copy policy or canonical unit classification failed.
    Copies(crate::source_copy::Error),
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "packed sender: {self:?}")
    }
}
impl std::error::Error for Error {}
impl Error {
    /// Map only actual stage refusal; clock, ownership and format errors stay errors.
    pub const fn buffer_refusal(self) -> Option<crate::diagnostics::StageBlock> {
        match self {
            Self::Busy => Some(crate::diagnostics::StageBlock::RetainedFrame),
            Self::Aligned(error) => error.buffer_refusal(),
            _ => None,
        }
    }
}
/// Current local ownership; no field is a peer acknowledgment.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Status {
    /// An original frame still has units outside the packed source.
    pub staged_frame: bool,
    /// Exact packing storage and original deadline.
    pub packing: packed::Status,
    /// Next unused absolute unit; None denotes exhaustion.
    pub next_unit: Option<SourceId>,
    /// First unit of the next source to hand off, if any.
    pub first_unit: Option<SourceId>,
    /// Sticky ownership/exhaustion failure, requiring session termination.
    pub failure: Option<Error>,
}
/// Exclusive finite sender; complete-source recovery ownership stays external.
pub struct Sender {
    scope: Scope,
    config: Config,
    aligned: aligned::Sender,
    packing: packed::Packer,
    records: Vec<RecordId>,
    next_unit: Option<SourceId>,
    first_unit: Option<SourceId>,
    failure: Option<Error>,
    usage: Option<crate::aligned_storage::Usage>,
    copy_policy: crate::source_copy::Policy,
    // The staged frame can outlive several packed sources. Moving its units
    // never renews its original admission time.
    staged_at: Option<u64>,
    source_started_at: Option<u64>,
    // A ready full first fragment can remain in the aligned scratch while
    // same-policy short final fragments share the original packing buffer.
    group_fragment_tails: bool,
    tail_copies: Option<u8>,
    leading_fragment: Option<RecordId>,
}
#[allow(dead_code)]
pub(crate) struct LegacyLayout {
    scope: Scope,
    config: Config,
    aligned: aligned::LegacyLayout,
    packing: packed::LegacyLayout,
    records: Vec<RecordId>,
    next_unit: Option<SourceId>,
    first_unit: Option<SourceId>,
    failure: Option<Error>,
}
impl Sender {
    pub(crate) fn reserved_bytes(config: Config) -> Result<usize, crate::aligned_storage::Error> {
        use crate::aligned_storage::{array_bytes, sum};
        sum(&[
            aligned::Sender::reserved_bytes(config.sender)?,
            array_bytes::<u8>(config.packing.symbol_bytes)?,
            array_bytes::<RecordId>(usize::from(config.max_units))?,
        ])
    }
    /// Reserve the actual aligned stage, timed source and unit identities once.
    pub fn new_reserved(
        scope: Scope,
        config: Config,
        limits: crate::aligned_storage::Limits,
    ) -> Result<Self, crate::aligned_storage::Error> {
        Self::new_reserved_mode(scope, config, limits, false)
    }
    /// Select real native-IP aligned contexts inside the same packing owner.
    pub fn new_reserved_ip(
        scope: Scope,
        config: Config,
        limits: crate::aligned_storage::Limits,
    ) -> Result<Self, crate::aligned_storage::Error> {
        Self::new_reserved_mode(scope, config, limits, true)
    }
    fn new_reserved_mode(
        scope: Scope,
        config: Config,
        limits: crate::aligned_storage::Limits,
        ip: bool,
    ) -> Result<Self, crate::aligned_storage::Error> {
        let plan = if ip {
            crate::aligned_storage::PackedSenderPlan::for_ip_config(config)?
        } else {
            crate::aligned_storage::PackedSenderPlan::for_config(config)?
        };
        if scope.session == [0; 16] {
            return Err(crate::aligned_storage::Error::PackedSender(
                Error::Configuration,
            ));
        }
        let mut allocation =
            crate::aligned_storage::Allocation::new(plan.capacity_bytes(), limits)?;
        let mut result = Self::new_in_mode(scope, config, &mut allocation, ip)?;
        result.usage = Some(allocation.finish(plan.capacity_bytes())?);
        Ok(result)
    }
    /// Select an explicit immutable copy policy before any actual reservation.
    /// Existing Config/wire identities are unchanged; the enclosing authenticated
    /// profile must separately bind this selection before installing the sender.
    pub fn new_reserved_with_copies(
        scope: Scope,
        config: Config,
        limits: crate::aligned_storage::Limits,
        policy: crate::source_copy::Policy,
    ) -> Result<Self, crate::aligned_storage::Error> {
        policy
            .validate(config.packing.symbol_bytes)
            .map_err(|error| crate::aligned_storage::Error::PackedSender(Error::Copies(error)))?;
        let mut result = Self::new_reserved(scope, config, limits)?;
        result.copy_policy = policy;
        Ok(result)
    }
    /// Select both native-IP context geometry and authenticated short-copy policy.
    pub fn new_reserved_ip_with_copies(
        scope: Scope,
        config: Config,
        limits: crate::aligned_storage::Limits,
        policy: crate::source_copy::Policy,
    ) -> Result<Self, crate::aligned_storage::Error> {
        policy
            .validate(config.packing.symbol_bytes)
            .map_err(|error| crate::aligned_storage::Error::PackedSender(Error::Copies(error)))?;
        let mut result = Self::new_reserved_ip(scope, config, limits)?;
        result.copy_policy = policy;
        Ok(result)
    }
    /// Actual complete backing observation; legacy construction reports None.
    pub fn storage_usage(&self) -> Option<crate::aligned_storage::Usage> {
        self.usage
    }
    #[cfg(test)]
    pub(crate) fn new_in(
        scope: Scope,
        config: Config,
        allocation: &mut crate::aligned_storage::Allocation,
    ) -> Result<Self, crate::aligned_storage::Error> {
        Self::new_in_mode(scope, config, allocation, false)
    }
    fn new_in_mode(
        scope: Scope,
        config: Config,
        allocation: &mut crate::aligned_storage::Allocation,
        ip: bool,
    ) -> Result<Self, crate::aligned_storage::Error> {
        Ok(Self {
            scope,
            config,
            aligned: aligned::Sender::new_in_mode(scope, config.sender, allocation, ip)?,
            packing: packed::Packer::new_in(config.packing, allocation)?,
            records: allocation.vec(usize::from(config.max_units))?,
            next_unit: Some(config.first_unit),
            first_unit: None,
            failure: None,
            usage: None,
            copy_policy: crate::source_copy::Policy::ONE,
            staged_at: None,
            source_started_at: None,
            group_fragment_tails: false,
            tail_copies: None,
            leading_fragment: None,
        })
    }
    /// Validate all products before allocating packet/metadata storage.
    pub fn new(scope: Scope, config: Config) -> Result<Self, Error> {
        Self::new_mode(scope, config, false)
    }
    /// Select actual native-IP delta/prediction with exact original source identities.
    pub fn new_ip(scope: Scope, config: Config) -> Result<Self, Error> {
        Self::new_mode(scope, config, true)
    }
    fn new_mode(scope: Scope, config: Config, ip: bool) -> Result<Self, Error> {
        config.memory_bound_bytes()?;
        Ok(Self {
            scope,
            config,
            aligned: if ip {
                aligned::Sender::new_ip(scope, config.sender)
            } else {
                aligned::Sender::new(scope, config.sender)
            }
            .map_err(Error::Aligned)?,
            packing: packed::Packer::new(config.packing).map_err(Error::Packing)?,
            records: Vec::with_capacity(usize::from(config.max_units)),
            next_unit: Some(config.first_unit),
            first_unit: None,
            failure: None,
            usage: None,
            copy_policy: crate::source_copy::Policy::ONE,
            staged_at: None,
            source_started_at: None,
            group_fragment_tails: false,
            tail_copies: None,
            leading_fragment: None,
        })
    }
    /// Select an explicit immutable policy while keeping existing constructors
    /// on the exact one-copy default and retaining the same actual heap owners.
    pub fn new_with_copies(
        scope: Scope,
        config: Config,
        policy: crate::source_copy::Policy,
    ) -> Result<Self, Error> {
        policy
            .validate(config.packing.symbol_bytes)
            .map_err(Error::Copies)?;
        let mut result = Self::new(scope, config)?;
        result.copy_policy = policy;
        Ok(result)
    }
    /// Explicit native-IP functional owner with the same real copy policy.
    pub fn new_ip_with_copies(
        scope: Scope,
        config: Config,
        policy: crate::source_copy::Policy,
    ) -> Result<Self, Error> {
        policy
            .validate(config.packing.symbol_bytes)
            .map_err(Error::Copies)?;
        let mut result = Self::new_ip(scope, config)?;
        result.copy_policy = policy;
        Ok(result)
    }
    /// Exact immutable local policy; this observation authenticates nothing.
    pub fn copy_policy(&self) -> crate::source_copy::Policy {
        self.copy_policy
    }
    fn live(&self) -> Result<(), Error> {
        self.failure.map_or(Ok(()), Err)
    }
    fn fail<T>(&mut self, error: Error) -> Result<T, Error> {
        self.failure = Some(error);
        Err(error)
    }
    /// Own one already-MUX-admitted Ethernet frame and service bounded unit work.
    pub fn stage(&mut self, channel: ChannelId, frame: &[u8], now: u64) -> Result<(), Error> {
        self.stage_selected(channel, frame, now, crate::aligned_body::Encoding::Headers)
            .map(|_| ())
    }
    /// Own one explicitly negotiated raw native frame/IP packet without header context.
    pub fn stage_raw(&mut self, channel: ChannelId, frame: &[u8], now: u64) -> Result<(), Error> {
        self.stage_selected(channel, frame, now, crate::aligned_body::Encoding::Raw)
            .map(|_| ())
    }
    /// Return the native-body identity before bounded polling can consume its units.
    pub fn stage_identified(
        &mut self,
        channel: ChannelId,
        frame: &[u8],
        now: u64,
    ) -> Result<RecordIdentity, Error> {
        self.stage_selected(channel, frame, now, crate::aligned_body::Encoding::Headers)
            .map(|(identity, _)| identity)
    }
    /// Return the exact raw-native body identity before packing advances ownership.
    pub fn stage_raw_identified(
        &mut self,
        channel: ChannelId,
        frame: &[u8],
        now: u64,
    ) -> Result<RecordIdentity, Error> {
        self.stage_selected(channel, frame, now, crate::aligned_body::Encoding::Raw)
            .map(|(identity, _)| identity)
    }
    /// Stage stateless LZ4-or-raw bytes before the existing timed packer advances.
    pub fn stage_lz4_identified(
        &mut self,
        channel: ChannelId,
        frame: &[u8],
        now: u64,
    ) -> Result<RecordIdentity, Error> {
        self.stage_selected(channel, frame, now, crate::aligned_body::Encoding::Lz4)
            .map(|(identity, _)| identity)
    }
    /// Return exact native encoding facts after successful staging and bounded work.
    /// Packing-container/recovery bytes and retries are not attributed here.
    pub fn stage_observed(
        &mut self,
        channel: ChannelId,
        frame: &[u8],
        now: u64,
    ) -> Result<
        (
            RecordIdentity,
            crate::aligned_body::NativeEncodingObservation,
        ),
        Error,
    > {
        self.stage_selected(channel, frame, now, crate::aligned_body::Encoding::Headers)
    }
    /// Stage TCP header deltas with periodic full contexts for targeted TUN
    /// recovery. Each refresh is a normal, charged context record.
    pub fn stage_refreshed_headers_observed(
        &mut self,
        channel: ChannelId,
        frame: &[u8],
        now: u64,
    ) -> Result<
        (
            RecordIdentity,
            crate::aligned_body::NativeEncodingObservation,
        ),
        Error,
    > {
        self.stage_selected(
            channel,
            frame,
            now,
            crate::aligned_body::Encoding::RefreshedHeaders,
        )
    }
    /// Observe successful raw native staging without attributing packing containers.
    pub fn stage_raw_observed(
        &mut self,
        channel: ChannelId,
        frame: &[u8],
        now: u64,
    ) -> Result<
        (
            RecordIdentity,
            crate::aligned_body::NativeEncodingObservation,
        ),
        Error,
    > {
        self.stage_selected(channel, frame, now, crate::aligned_body::Encoding::Raw)
    }
    /// Observe actual LZ4-or-raw encoding after successful native staging.
    pub fn stage_lz4_observed(
        &mut self,
        channel: ChannelId,
        frame: &[u8],
        now: u64,
    ) -> Result<
        (
            RecordIdentity,
            crate::aligned_body::NativeEncodingObservation,
        ),
        Error,
    > {
        self.stage_selected(channel, frame, now, crate::aligned_body::Encoding::Lz4)
    }
    fn stage_selected(
        &mut self,
        channel: ChannelId,
        frame: &[u8],
        now: u64,
        encoding: crate::aligned_body::Encoding,
    ) -> Result<
        (
            RecordIdentity,
            crate::aligned_body::NativeEncodingObservation,
        ),
        Error,
    > {
        self.live()?;
        // A fresh frame may need a new source even while an older one is sealed.
        // Reject an impossible first-unit deadline before changing time/context.
        now.checked_add(self.config.packing.hold_micros)
            .ok_or(Error::Packing(packed::Error::ClockExhausted))?;
        self.packing.tick(now).map_err(Error::Packing)?;
        if self.aligned.is_pending() {
            return Err(Error::Busy);
        }
        if self.next_unit.is_none() {
            return Err(Error::Exhausted);
        }
        let identity = self
            .aligned
            .stage_selected(channel, frame, encoding)
            .map_err(Error::Aligned)?;
        self.staged_at = Some(now);
        self.poll(now)?;
        Ok(identity)
    }
    /// Allow full first fragments to pass a same-copy batch of short final
    /// fragments. This sender-local selection requires a fresh owner.
    pub fn enable_fragment_tail_packing(&mut self) -> Result<(), Error> {
        self.live()?;
        if !self.is_idle() || self.next_unit != Some(self.config.first_unit) {
            return Err(Error::Configuration);
        }
        self.group_fragment_tails = true;
        Ok(())
    }
    /// A complete immutable source is ready, in either existing storage owner.
    pub fn has_pending_source(&self) -> bool {
        self.leading_fragment.is_some() || self.packing.pending().is_some()
    }
    /// Attempt at most the configured unit work; sealed sources remain immutable.
    pub fn poll(&mut self, now: u64) -> Result<(), Error> {
        self.live()?;
        self.packing.tick(now).map_err(Error::Packing)?;
        for _ in 0..self.config.work_limit {
            if self.has_pending_source() || !self.aligned.is_pending() {
                break;
            }
            if self.records.len() >= usize::from(self.config.max_units) {
                self.packing.flush();
                break;
            }
            let Some(id) = self.next_unit else {
                return self.fail(Error::Exhausted);
            };
            let unit = self.aligned.pending_unit().map_err(Error::Aligned)?;
            let record = unit.record;
            let copies = self
                .copy_policy
                .copies_for_unit(unit.bytes, self.config.packing.symbol_bytes)
                .map_err(Error::Copies)?;
            let offset = unit.bytes.get(3..8).and_then(|header| {
                (header[0] == 4).then(|| u16::from_be_bytes([header[3], header[4]]))
            });
            if self.group_fragment_tails
                && self.tail_copies == Some(copies)
                && offset == Some(0)
                && unit.bytes.len() == self.config.packing.symbol_bytes
                && id.0 != u64::MAX
            {
                // Reserve one more identity. The full fragment takes the first
                // uncommitted unit ID; the held batch follows without a gap.
                self.next_unit = id.0.checked_add(1).map(SourceId);
                self.leading_fragment = Some(record);
                break;
            }
            let tail = self.group_fragment_tails
                && offset.is_some_and(|offset| offset != 0)
                && unit.completes_record;
            let pushed = match self.packing.push(unit.bytes, copies, now) {
                Err(packed::Error::ClockExhausted) => {
                    return self.fail(Error::Packing(packed::Error::ClockExhausted));
                }
                other => other.map_err(Error::Packing)?,
            };
            match pushed {
                packed::Push::Accepted => {
                    if self.records.is_empty() {
                        self.tail_copies = tail.then_some(copies);
                    } else if !tail {
                        self.tail_copies = None;
                    }
                    let admitted = self.staged_at.ok_or(Error::Ownership)?;
                    self.source_started_at = Some(
                        self.source_started_at
                            .map_or(admitted, |old| old.min(admitted)),
                    );
                    self.records.push(record);
                    self.first_unit.get_or_insert(id);
                    self.next_unit = id.0.checked_add(1).map(SourceId);
                    if self.aligned.commit_unit().is_err() {
                        return self.fail(Error::Ownership);
                    }
                    if !self.aligned.is_pending() {
                        self.staged_at = None;
                    }
                    if self.records.len() == usize::from(self.config.max_units) {
                        self.packing.flush();
                    }
                }
                packed::Push::FlushRequired | packed::Push::Backpressure => break,
            }
        }
        Ok(())
    }
    /// Service bounded work and seal retained units without inventing an empty source.
    pub fn flush(&mut self, now: u64) -> Result<(), Error> {
        self.poll(now)?;
        self.packing.flush();
        Ok(())
    }
    /// Encode complete retained source bytes using the actual recovery owner's ID.
    /// Neither successful encoding nor output pressure consumes local ownership.
    pub fn write_pending(&self, source: SourceId, output: &mut [u8]) -> Result<usize, Error> {
        self.write_pending_selected(source, output, false)
    }
    /// Write compact packing metadata directly, retaining the same pending owner.
    pub fn write_pending_compact(&self, output: &mut [u8]) -> Result<usize, Error> {
        self.write_pending_selected(SourceId(0), output, true)
    }
    fn write_pending_selected(
        &self,
        source: SourceId,
        output: &mut [u8],
        compact: bool,
    ) -> Result<usize, Error> {
        self.live()?;
        let encode = if compact {
            envelope::encode_compact
        } else {
            envelope::encode
        };
        let (records, bytes) = if let Some(record) = &self.leading_fragment {
            (std::slice::from_ref(record), self.aligned.rendered_symbol())
        } else {
            let packed = self.packing.pending().ok_or(Error::NoPending)?;
            if usize::from(packed.units) != self.records.len() || !(1..=4).contains(&packed.copies)
            {
                return Err(Error::Ownership);
            }
            (self.records.as_slice(), packed.payload)
        };
        encode(
            self.config.envelope(),
            envelope::Identity {
                scope: self.scope,
                source,
                first_unit: self.first_unit.ok_or(Error::Ownership)?,
            },
            records,
            bytes,
            output,
        )
        .map_err(Error::Envelope)
    }
    /// Physical copies requested by the retained homogeneous packed source.
    /// This neither emits copies nor acknowledges any physical/recovery handoff.
    pub fn pending_copies(&self) -> Result<u8, Error> {
        self.live()?;
        if self.leading_fragment.is_some() {
            return self.tail_copies.ok_or(Error::Ownership);
        }
        Ok(self.packing.pending().ok_or(Error::NoPending)?.copies)
    }
    /// Release only after actual recovery copied the complete envelope with the same ID.
    /// This is neither a source-prefix receipt nor native-delivery confirmation.
    pub fn commit_source(&mut self) -> Result<(), Error> {
        self.live()?;
        if self.leading_fragment.is_some() {
            let first = self.first_unit.ok_or(Error::Ownership)?;
            let next = first.0.checked_add(1).ok_or(Error::Exhausted)?;
            self.aligned.commit_unit().map_err(Error::Aligned)?;
            self.first_unit = Some(SourceId(next));
            self.leading_fragment = None;
            return Ok(());
        }
        if self.packing.pending().is_none() {
            return Err(Error::NoPending);
        }
        self.packing.commit().map_err(Error::Packing)?;
        self.records.clear();
        self.first_unit = None;
        self.source_started_at = None;
        self.tail_copies = None;
        Ok(())
    }
    /// Original native admission of the oldest bytes still owned by this codec.
    /// Includes both the packed source and any staged context/body/fragment tail.
    /// A source handoff retires only its bytes; it never renews a retained tail.
    pub fn oldest_admission_micros(&self) -> Option<u64> {
        match (self.source_started_at, self.staged_at) {
            (Some(source), Some(staged)) => Some(source.min(staged)),
            (source, staged) => source.or(staged),
        }
    }
    /// Earliest original native admission represented by the sealed source.
    /// Newer input behind that source cannot change this ownership timestamp.
    pub fn pending_admission_micros(&self) -> Result<u64, Error> {
        self.live()?;
        if self.leading_fragment.is_some() {
            return self.staged_at.ok_or(Error::Ownership);
        }
        self.packing.pending().ok_or(Error::NoPending)?;
        self.source_started_at.ok_or(Error::Ownership)
    }
    /// Original first-unit deadline, including a sealed source under recovery pressure.
    pub fn deadline_micros(&self) -> Option<u64> {
        self.packing.status().deadline_micros
    }
    /// Whether no frame/unit/source remains locally owned; this says nothing about recovery.
    pub fn is_idle(&self) -> bool {
        self.failure.is_none() && !self.aligned.is_pending() && self.records.is_empty()
    }
    /// Inspect retained ownership without modifying time or any identity.
    pub fn status(&self) -> Status {
        Status {
            staged_frame: self.aligned.is_pending(),
            packing: self.packing.status(),
            next_unit: self.next_unit,
            first_unit: self.first_unit,
            failure: self.failure,
        }
    }
    /// Observe the separate native stage and packed source without polling either.
    pub fn buffer_snapshot(&self) -> crate::diagnostics::PackedBuffers {
        let mut packing = self.packing.buffer_snapshot();
        packing.unit_capacity = usize::from(self.config.max_units);
        crate::diagnostics::PackedBuffers {
            stage: self.aligned.buffer_snapshot(),
            packing,
        }
    }
}

#[cfg(test)]
#[path = "packed_sender_tests.rs"]
mod tests;
