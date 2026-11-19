//! One bounded frame stage producing Python-compatible aligned symbols.
//! Source IDs belong to the external recovery owner; only record IDs live here.

use crate::{
    aligned_body::{self, Encoder},
    aligned_envelope,
    aligned_receiver::{ChannelId, RecordId, RecordIdentity, Scope, SourceId, SymbolIdentity},
};
use std::{fmt, mem::size_of};

/// Fixed per-channel codec and single-frame staging limits.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Config {
    /// Exact body and full padded symbol geometry.
    pub body: aligned_body::Config,
    /// Common MUX channels, in 1..=256.
    pub channels: u16,
    /// Initial absolute record ID in every channel.
    pub first_record: RecordId,
}
impl Config {
    /// Historical allocating-owner scalar guard, excluding allocator overhead.
    /// Reserved backing uses the separate complete aligned_storage::SenderPlan.
    pub fn memory_bound_bytes(self) -> Result<usize, Error> {
        self.body.body_capacity()?;
        if !(1..=256).contains(&self.channels) {
            return Err(Error::Configuration);
        }
        let count = usize::from(self.channels);
        let total = (count + 2) * (self.body.max_frame_bytes + 29)
            + (count + 1) * Encoder::legacy_inline_bytes()
            + count * size_of::<LegacyChannel>()
            + self.body.symbol_bytes
            + size_of::<LegacyLayout>();
        if total > 32 * 1024 * 1024 {
            return Err(Error::Configuration);
        }
        Ok(total)
    }
}
/// Explicit transactional sender failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// Invalid channel, scope or memory bound.
    Configuration,
    /// A previous frame still owns the stage; retry after draining it.
    Busy,
    /// No source is staged for writing/committing.
    NoPending,
    /// Absolute record identities would wrap.
    Exhausted,
    /// Body encoding failed without committing context.
    Body(aligned_body::Error),
    /// Envelope output or identity failed.
    Envelope(aligned_envelope::Error),
    /// Explicit source-copy policy or canonical unit classification failed.
    Copies(crate::source_copy::Error),
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "aligned sender: {self:?}")
    }
}
impl std::error::Error for Error {}
impl Error {
    /// Classify an actual rejected operation without inferring a wait from occupancy.
    pub const fn buffer_refusal(self) -> Option<crate::diagnostics::StageBlock> {
        match self {
            Self::Busy => Some(crate::diagnostics::StageBlock::RetainedFrame),
            _ => None,
        }
    }
}
impl From<aligned_body::Error> for Error {
    fn from(value: aligned_body::Error) -> Self {
        Self::Body(value)
    }
}
impl From<aligned_envelope::Error> for Error {
    fn from(value: aligned_envelope::Error) -> Self {
        Self::Envelope(value)
    }
}
#[allow(dead_code)]
struct LegacyChannel {
    encoder: [u8; Encoder::legacy_inline_bytes()],
    next: Option<RecordId>,
}
struct Channel {
    encoder: Encoder,
    next: Option<RecordId>,
}
#[derive(Clone, Copy)]
struct Pending {
    channel: ChannelId,
    record: RecordId,
    context_len: usize,
    body_len: usize,
    context: bool,
    offset: usize,
}
// Compatibility-only original inline shape for the historical scalar guard.
// This is never actual new reserved memory, a Plan, or an observed Usage.
#[allow(dead_code)]
pub(crate) struct LegacyLayout {
    config: Config,
    scope: Scope,
    channels: Vec<Channel>,
    staged: [u8; Encoder::legacy_inline_bytes()],
    bodies: Vec<u8>,
    symbol: Vec<u8>,
    pending: Option<Pending>,
}
/// Exact meaningful unit borrowed from the existing bounded symbol scratch.
/// No recovery source identity or native-delivery acknowledgment is assigned here.
pub struct PendingUnit<'a> {
    /// Original common MUX channel.
    pub channel: ChannelId,
    /// Absolute record identity; its low16 serial is already present in bytes.
    pub record: RecordId,
    /// Complete channel/serial/body or fragment, excluding generated padding only.
    pub bytes: &'a [u8],
    /// This unit is the final fragment, or the whole unfragmented record.
    pub completes_record: bool,
    /// This unit also completes the staged native frame, not merely its context.
    pub completes_frame: bool,
}
/// Exclusive sender with one fixed pending frame and no unbounded fragment list.
pub struct Sender {
    config: Config,
    scope: Scope,
    channels: Vec<Channel>,
    staged: Encoder,
    bodies: Vec<u8>,
    symbol: Vec<u8>,
    pending: Option<Pending>,
    usage: Option<crate::aligned_storage::Usage>,
}
impl Sender {
    pub(crate) fn reserved_bytes(config: Config) -> Result<usize, crate::aligned_storage::Error> {
        use crate::aligned_storage::{array_bytes, product, sum};
        let count = usize::from(config.channels);
        sum(&[
            array_bytes::<Channel>(count)?,
            product(count + 1, Encoder::reserved_bytes(config.body)?)?,
            array_bytes::<u8>(config.body.max_frame_bytes + 29)?,
            array_bytes::<u8>(config.body.symbol_bytes)?,
        ])
    }
    /// Reserve all actual channel/stage buffers before admitting a native frame.
    pub fn new_reserved(
        scope: Scope,
        config: Config,
        limits: crate::aligned_storage::Limits,
    ) -> Result<Self, crate::aligned_storage::Error> {
        Self::new_reserved_mode(scope, config, limits, false)
    }
    /// Reserve the actual native-IP header state and the same channel/source owners.
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
            crate::aligned_storage::SenderPlan::for_ip_config(config)?
        } else {
            crate::aligned_storage::SenderPlan::for_config(config)?
        };
        if scope.session == [0; 16] {
            return Err(crate::aligned_storage::Error::Sender(Error::Configuration));
        }
        let mut allocation =
            crate::aligned_storage::Allocation::new(plan.capacity_bytes(), limits)?;
        let mut result = Self::new_in_mode(scope, config, &mut allocation, ip)?;
        result.usage = Some(allocation.finish(plan.capacity_bytes())?);
        Ok(result)
    }
    /// Complete retained heap observation; legacy construction reports None.
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
    pub(crate) fn new_in_mode(
        scope: Scope,
        config: Config,
        allocation: &mut crate::aligned_storage::Allocation,
        ip: bool,
    ) -> Result<Self, crate::aligned_storage::Error> {
        let mut channels = allocation.vec(usize::from(config.channels))?;
        for _ in 0..config.channels {
            channels.push(Channel {
                encoder: Encoder::new_in_mode(config.body, allocation, ip)?,
                next: Some(config.first_record),
            });
        }
        Ok(Self {
            config,
            scope,
            channels,
            staged: Encoder::new_in_mode(config.body, allocation, ip)?,
            bodies: allocation.bytes(config.body.max_frame_bytes + 29)?,
            symbol: allocation.bytes(config.body.symbol_bytes)?,
            pending: None,
            usage: None,
        })
    }
    /// Validate and allocate a context per channel plus one transactional stage.
    pub fn new(scope: Scope, config: Config) -> Result<Self, Error> {
        Self::new_mode(scope, config, false)
    }
    /// Select native IPv4/IPv6 TCP compression without a synthetic Ethernet frame.
    pub fn new_ip(scope: Scope, config: Config) -> Result<Self, Error> {
        Self::new_mode(scope, config, true)
    }
    fn new_mode(scope: Scope, config: Config, ip: bool) -> Result<Self, Error> {
        config.memory_bound_bytes()?;
        if scope.session == [0; 16] {
            return Err(Error::Configuration);
        }
        let mut channels = Vec::with_capacity(usize::from(config.channels));
        for _ in 0..config.channels {
            channels.push(Channel {
                encoder: if ip {
                    Encoder::new_ip(config.body)?
                } else {
                    Encoder::new(config.body)?
                },
                next: Some(config.first_record),
            });
        }
        Ok(Self {
            config,
            scope,
            channels,
            staged: if ip {
                Encoder::new_ip(config.body)?
            } else {
                Encoder::new(config.body)?
            },
            bodies: vec![0; config.body.max_frame_bytes + 29],
            symbol: vec![0; config.body.symbol_bytes],
            pending: None,
            usage: None,
        })
    }
    /// Whether one native frame still has symbols awaiting recovery ownership.
    pub fn is_pending(&self) -> bool {
        self.pending.is_some()
    }
    /// Observe the sole stage without constructing a symbol or advancing its cursor.
    pub fn buffer_snapshot(&self) -> crate::diagnostics::StageBuffers {
        let (bytes, remaining) = self.pending.map_or((0, 0), |pending| {
            let bytes = pending.context_len + pending.body_len;
            let consumed = if pending.context {
                0
            } else {
                pending.context_len
            };
            (bytes, bytes - consumed - pending.offset)
        });
        crate::diagnostics::StageBuffers {
            stage: crate::diagnostics::Retention {
                items: usize::from(self.pending.is_some()),
                item_capacity: 1,
                bytes,
                byte_capacity: self.bodies.len(),
            },
            remaining_bytes: remaining,
            unit_scratch_capacity: self.symbol.len(),
        }
    }
    /// Next unused record identity; None means the channel is exhausted.
    pub fn next_record(&self, channel: ChannelId) -> Result<Option<RecordId>, Error> {
        self.channels
            .get(usize::from(channel.0))
            .map(|channel| channel.next)
            .ok_or(Error::Configuration)
    }
    /// Stage one already-MUX-admitted frame. Failure consumes no context or ID.
    pub fn stage(&mut self, channel: ChannelId, frame: &[u8]) -> Result<(), Error> {
        self.stage_selected(channel, frame, aligned_body::Encoding::Headers)
            .map(|_| ())
    }
    /// Stage an explicitly selected raw packet without consuming a header context.
    pub fn stage_raw(&mut self, channel: ChannelId, frame: &[u8]) -> Result<(), Error> {
        self.stage_selected(channel, frame, aligned_body::Encoding::Raw)
            .map(|_| ())
    }
    /// Stage and return the actual native-body identity, excluding any context.
    pub fn stage_identified(
        &mut self,
        channel: ChannelId,
        frame: &[u8],
    ) -> Result<RecordIdentity, Error> {
        self.stage_observed(channel, frame)
            .map(|(identity, _)| identity)
    }
    /// Stage raw native bytes and return their original channel body identity.
    pub fn stage_raw_identified(
        &mut self,
        channel: ChannelId,
        frame: &[u8],
    ) -> Result<RecordIdentity, Error> {
        self.stage_raw_observed(channel, frame)
            .map(|(identity, _)| identity)
    }
    /// Stage stateless LZ4-or-raw bytes under the actual channel identity.
    pub fn stage_lz4_identified(
        &mut self,
        channel: ChannelId,
        frame: &[u8],
    ) -> Result<RecordIdentity, Error> {
        self.stage_lz4_observed(channel, frame)
            .map(|(identity, _)| identity)
    }
    /// Return exact encoding facts once, only after native staging succeeds.
    pub fn stage_observed(
        &mut self,
        channel: ChannelId,
        frame: &[u8],
    ) -> Result<(RecordIdentity, aligned_body::NativeEncodingObservation), Error> {
        self.stage_selected(channel, frame, aligned_body::Encoding::Headers)
    }
    /// Return exact raw-body and complete generated unit framing after staging.
    pub fn stage_raw_observed(
        &mut self,
        channel: ChannelId,
        frame: &[u8],
    ) -> Result<(RecordIdentity, aligned_body::NativeEncodingObservation), Error> {
        self.stage_selected(channel, frame, aligned_body::Encoding::Raw)
    }
    /// Return actual LZ4-or-raw encoding facts after staging succeeds.
    pub fn stage_lz4_observed(
        &mut self,
        channel: ChannelId,
        frame: &[u8],
    ) -> Result<(RecordIdentity, aligned_body::NativeEncodingObservation), Error> {
        self.stage_selected(channel, frame, aligned_body::Encoding::Lz4)
    }
    pub(crate) fn stage_selected(
        &mut self,
        channel: ChannelId,
        frame: &[u8],
        encoding: aligned_body::Encoding,
    ) -> Result<(RecordIdentity, aligned_body::NativeEncodingObservation), Error> {
        if self.pending.is_some() {
            return Err(Error::Busy);
        }
        let state = self
            .channels
            .get_mut(usize::from(channel.0))
            .ok_or(Error::Configuration)?;
        let record = state.next.ok_or(Error::Exhausted)?;
        self.staged.copy_context_from(&state.encoder);
        // A full context also has its own record serial. Keeping a serial-based
        // cadence needs no timer or per-flow state and survives failed admission.
        let refresh =
            encoding == aligned_body::Encoding::RefreshedHeaders && record.0.is_multiple_of(8);
        if refresh {
            self.staged.reset();
        }
        let encoded = match encoding {
            aligned_body::Encoding::Headers | aligned_body::Encoding::RefreshedHeaders => {
                self.staged.encode(frame, &mut self.bodies)?
            }
            aligned_body::Encoding::Raw => self.staged.encode_raw(frame, &mut self.bodies)?,
            aligned_body::Encoding::Lz4 => self.staged.encode_lz4(frame, &mut self.bodies)?,
        };
        let last = if encoded.context_len != 0 {
            record.0.checked_add(1).ok_or(Error::Exhausted)?
        } else {
            record.0
        };
        let framing = |length: usize| {
            if length == 0 {
                0
            } else if length <= self.config.body.symbol_bytes - 3 {
                3
            } else {
                length.div_ceil(self.config.body.symbol_bytes - 8) * 8
            }
        };
        let mut observation = encoded.observation();
        observation.framing_bytes = framing(encoded.context_len) + framing(encoded.body_len);
        // A raw fallback at a refresh boundary carries no replacement context.
        if !refresh || encoded.context_len != 0 {
            state.encoder.copy_context_from(&self.staged);
        }
        state.next = last.checked_add(1).map(RecordId);
        self.pending = Some(Pending {
            channel,
            record,
            context_len: encoded.context_len,
            body_len: encoded.body_len,
            context: encoded.context_len != 0,
            offset: 0,
        });
        Ok((
            RecordIdentity {
                channel,
                record: RecordId(last),
            },
            observation,
        ))
    }
    /// Read the authoritative retained unit without building bytes or advancing state.
    pub fn staged_identity(&self) -> Option<crate::diagnostics::StageIdentity> {
        let pending = self.pending?;
        // stage_selected validated this successor before publishing Pending.
        let native_record = pending.record.0.checked_add(u64::from(pending.context))?;
        Some(crate::diagnostics::StageIdentity {
            channel: pending.channel.0,
            record: pending.record.0,
            native_record,
            offset: pending.offset,
            context: pending.context,
        })
    }
    /// Write immutable pending bytes using the recovery owner's source-ID snapshot.
    /// Failure or success here never consumes a pending symbol.
    pub fn write_pending(&mut self, source: SourceId, output: &mut [u8]) -> Result<usize, Error> {
        let (pending, _, _) = self.build_symbol()?;
        Ok(aligned_envelope::encode(
            SymbolIdentity {
                scope: self.scope,
                source,
                record: pending.record,
            },
            &self.symbol,
            output,
        )?)
    }
    /// Write selected record metadata and the exact meaningful unit before commit.
    /// Authenticated outer context and recovery supply scope and source identity.
    /// Generated symbol padding is omitted; original zero-valued bytes remain.
    pub fn write_pending_compact(&mut self, output: &mut [u8]) -> Result<usize, Error> {
        let (pending, length, _) = self.build_symbol()?;
        Ok(aligned_envelope::encode_compact(
            SymbolIdentity {
                scope: self.scope,
                source: SourceId(0),
                record: pending.record,
            },
            self.config.body.symbol_bytes,
            &self.symbol[..length],
            output,
        )?)
    }
    /// Borrow the exact next unit without advancing any pending ownership.
    /// Actual zero-valued body bytes are retained; generated padding is excluded.
    pub fn pending_unit(&mut self) -> Result<PendingUnit<'_>, Error> {
        let (pending, length, complete) = self.build_symbol()?;
        Ok(PendingUnit {
            channel: pending.channel,
            record: pending.record,
            bytes: &self.symbol[..length],
            completes_record: complete,
            completes_frame: complete && !pending.context,
        })
    }
    // The packed sender can retain an already rendered full-width first
    // fragment until commit. The owning frame remains staged throughout.
    pub(crate) fn rendered_symbol(&self) -> &[u8] {
        &self.symbol
    }
    /// Classify the actual next meaningful unit without advancing ownership.
    /// The caller must authenticate this explicit policy before installation;
    /// returning a count does not perform or acknowledge physical packet writes.
    pub fn pending_copies(&mut self, policy: crate::source_copy::Policy) -> Result<u8, Error> {
        policy
            .validate(self.config.body.symbol_bytes)
            .map_err(Error::Copies)?;
        let width = self.config.body.symbol_bytes;
        let unit = self.pending_unit()?;
        policy
            .copies_for_unit(unit.bytes, width)
            .map_err(Error::Copies)
    }
    fn build_symbol(&mut self) -> Result<(Pending, usize, bool), Error> {
        let pending = self.pending.ok_or(Error::NoPending)?;
        let (start, length) = if pending.context {
            (0, pending.context_len)
        } else {
            (pending.context_len, pending.body_len)
        };
        let body = &self.bodies[start..start + length];
        self.symbol.fill(0);
        self.symbol[0] = pending.channel.0;
        self.symbol[1..3].copy_from_slice(&(pending.record.0 as u16).to_be_bytes());
        let (written, complete) = if length <= self.config.body.symbol_bytes - 3 {
            self.symbol[3..3 + length].copy_from_slice(body);
            (3 + length, true)
        } else {
            let capacity = self.config.body.symbol_bytes - 8;
            let count = capacity.min(length - pending.offset);
            self.symbol[3] = 4;
            self.symbol[4..6].copy_from_slice(&(length as u16).to_be_bytes());
            self.symbol[6..8].copy_from_slice(&(pending.offset as u16).to_be_bytes());
            self.symbol[8..8 + count]
                .copy_from_slice(&body[pending.offset..pending.offset + count]);
            (8 + count, pending.offset + count == length)
        };
        Ok((pending, written, complete))
    }
    /// Transfer one symbol only after recovery has copied its complete envelope.
    pub fn commit_source(&mut self) -> Result<(), Error> {
        self.advance_pending()
    }
    /// Transfer one exact unit only after a bounded local packer copied its bytes
    /// and metadata. This is local ownership, not recovery or peer acknowledgment.
    pub fn commit_unit(&mut self) -> Result<(), Error> {
        self.advance_pending()
    }
    fn advance_pending(&mut self) -> Result<(), Error> {
        let mut pending = self.pending.ok_or(Error::NoPending)?;
        let length = if pending.context {
            pending.context_len
        } else {
            pending.body_len
        };
        let capacity = self.config.body.symbol_bytes - 8;
        if length > self.config.body.symbol_bytes - 3 && pending.offset + capacity < length {
            pending.offset += capacity;
        } else if pending.context {
            pending.context = false;
            pending.offset = 0;
            pending.record = RecordId(pending.record.0.checked_add(1).ok_or(Error::Exhausted)?);
        } else {
            self.pending = None;
            return Ok(());
        }
        self.pending = Some(pending);
        Ok(())
    }
}

#[cfg(test)]
#[path = "aligned_sender_tests.rs"]
mod tests;
