//! Additive mode-independent envelope candidate. Authentication and barriers belong
//! to the runtime; this module performs no I/O, clock reads or mode transitions.
use super::{LaneId, PacketNumber, ReplayWindow, Role, SessionId};
use l2tunnel_core::{ConfigDigest, Epoch};
use std::fmt;

/// Fixed new-envelope header; legacy L2MC bytes are unchanged.
pub const HEADER_BYTES: usize = 80;
/// Version of L2SC, independently negotiated from legacy control formats.
pub const VERSION: u8 = 1;
/// Largest supported exact framed profile-control body, excluding its tag.
pub const MAX_PROFILE_CONTROL_BYTES: usize = 43;
/// Explicit profile-specific command grammar, independent of recovery feedback.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum ProfileTag {
    /// Existing framed Swift proposal and directional-barrier grammar version 1.
    SwiftPolicyV1 = 1,
}
impl ProfileTag {
    fn decode(value: u16) -> Result<Self, Error> {
        match value {
            1 => Ok(Self::SwiftPolicyV1),
            _ => Err(Error::ProfileTag),
        }
    }
}
/// Current or explicitly draining authenticated data policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Scope {
    /// Monotonic data-policy epoch.
    pub epoch: Epoch,
    /// Full canonical origin-policy digest, not a recovery-name hash.
    pub digest: ConfigDigest,
}
/// Exact maintained feedback grammar; enum presence is not adapter qualification.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum RecoveryTag {
    /// Maintained Selective Repeat version1 feedback.
    SelectiveRepeatV1 = 1,
    /// Maintained Reliable/Cauchy L2RF version1 feedback (kind2,56 bytes).
    ReliableV1 = 2,
    /// Maintained rolling scheduler L2RF version1 feedback (kind3,64 bytes).
    RollingV1 = 3,
}
impl RecoveryTag {
    fn decode(value: u16) -> Result<Self, Error> {
        match value {
            1 => Ok(Self::SelectiveRepeatV1),
            2 => Ok(Self::ReliableV1),
            3 => Ok(Self::RollingV1),
            _ => Err(Error::FeedbackTag),
        }
    }
}
/// Native receipt grammar negotiated for one data policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReceiptPolicy {
    /// One native FIFO delivery prefix.
    Cumulative,
    /// Independent native identity; channel is below this explicit limit.
    Record {
        /// Exclusive channel bound, within1..=256.
        channels: u16,
    },
}
/// Immutable scope registration, with no algorithm-owned state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ScopePolicy {
    /// Exact admitted data policy.
    pub scope: Scope,
    /// Only this feedback grammar is permitted in this scope.
    pub recovery: RecoveryTag,
    /// Bound before allocating or dispatching feedback payload.
    pub max_feedback_bytes: usize,
    /// Native delivery semantics, distinct from recovery receipt.
    pub receipts: ReceiptPolicy,
}
/// Hard wire bounds; no owned payload allocation occurs in this module.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Limits {
    /// Complete envelope, at most65536 bytes.
    pub max_frame_bytes: usize,
    /// Exact nested legacy management frame, at least112 bytes.
    pub max_management_bytes: usize,
    /// Opaque recovery payload, excluding its eight-byte target/tag header.
    pub max_feedback_bytes: usize,
}
impl Limits {
    /// Validate all wire and body limits before reading/allocating payloads.
    pub fn validate(self) -> Result<(), Error> {
        if !(HEADER_BYTES + super::HEADER_LEN..=65_536).contains(&self.max_frame_bytes)
            || !(super::HEADER_LEN..=self.max_frame_bytes - HEADER_BYTES)
                .contains(&self.max_management_bytes)
            || self.max_feedback_bytes == 0
            || self.max_feedback_bytes > self.max_frame_bytes - HEADER_BYTES - 8
        {
            return Err(Error::Limits);
        }
        Ok(())
    }
}
/// Primary-control-stream binding; all target data lanes share this one sequence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Binding {
    /// Authenticated session, supplied by the factory.
    pub session: SessionId,
    /// Authenticated physical lane; never a user MUX channel.
    pub lane: LaneId,
    /// Authenticated remote sender role.
    pub sender: Role,
    /// Fresh transmission number, never reset by scope changes.
    pub packet: PacketNumber,
    /// Originating canonical data policy.
    pub scope: Scope,
}
/// Native device delivery, independent of ARQ/FEC source acknowledgment.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeReceipt {
    /// Successful native FIFO prefix.
    Cumulative {
        /// Successful native FIFO count.
        records: u64,
    },
    /// Successful native identity in an authenticated MUX channel.
    Record {
        /// Authenticated MUX channel identity.
        channel: u16,
        /// Original native record identity.
        record: u64,
    },
}
/// Borrowed bounded body; recovery semantics remain in the selected engine.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Body<'a> {
    /// Exact existing L2MC frame; its transaction ticket retains its old meaning.
    Management(&'a [u8]),
    /// Exact selected feedback bytes, not parsed by another mode's decoder.
    RecoveryFeedback {
        /// Authenticated target data lane, distinct from the primary control lane.
        lane: LaneId,
        /// Exact selected feedback wire grammar.
        tag: RecoveryTag,
        /// Borrowed selected feedback bytes.
        bytes: &'a [u8],
    },
    /// Typed native device completion.
    NativeReceipt {
        /// Authenticated target data lane.
        lane: LaneId,
        /// Native-device completion, not recovery source receipt.
        receipt: NativeReceipt,
    },
    /// Mode-independent liveness request.
    Ping {
        /// Opaque liveness identity.
        nonce: u64,
    },
    /// Mode-independent liveness response.
    Pong {
        /// Exact request nonce being answered.
        nonce: u64,
    },
    /// Exact selected profile command; the adapter validates its full grammar.
    ProfileControl {
        /// Explicit negotiated grammar, never authority inferred from payload.
        tag: ProfileTag,
        /// One complete bounded frame, borrowed without interpretation here.
        bytes: &'a [u8],
    },
}
/// Complete borrowed envelope after strict syntactic validation only.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Envelope<'a> {
    /// Outer authenticated-session identities.
    pub binding: Binding,
    /// Length-bounded typed body.
    pub body: Body<'a>,
}
fn read<const N: usize>(input: &[u8], at: usize) -> Result<[u8; N], Error> {
    super::array(input, at).map_err(Error::Legacy)
}
impl<'a> Envelope<'a> {
    /// Strict borrowed parse; call only after checking complete outer stream length.
    pub fn decode(input: &'a [u8], limits: Limits) -> Result<Self, Error> {
        limits.validate()?;
        if input.len() > limits.max_frame_bytes {
            return Err(Error::Length);
        }
        if input.len() < HEADER_BYTES {
            return Err(Error::Length);
        }
        if input[..4] != *b"L2SC" || input[4] != VERSION {
            return Err(Error::Version);
        }
        if input[7] != 0 {
            return Err(Error::Reserved);
        }
        if u32::from_be_bytes(read(input, 8)?) as usize != input.len() {
            return Err(Error::Length);
        }
        let binding = Binding {
            sender: Role::decode(input[6]).map_err(Error::Legacy)?,
            lane: LaneId(u32::from_be_bytes(read(input, 12)?)),
            session: SessionId(read(input, 16)?),
            packet: PacketNumber(u64::from_be_bytes(read(input, 32)?)),
            scope: Scope {
                epoch: Epoch(u64::from_be_bytes(read(input, 40)?)),
                digest: ConfigDigest(read(input, 48)?),
            },
        };
        if binding.packet.0 == 0 || binding.scope.epoch.0 == 0 {
            return Err(Error::Binding);
        }
        let bytes = &input[HEADER_BYTES..];
        let body = match input[5] {
            1 => {
                if bytes.len() > limits.max_management_bytes {
                    return Err(Error::Length);
                }
                let frame = super::Frame::decode(
                    bytes,
                    super::Limits {
                        max_frame_bytes: limits.max_management_bytes,
                        ..Default::default()
                    },
                )
                .map_err(Error::Legacy)?;
                if frame.header.session != binding.session
                    || frame.header.lane != binding.lane
                    || frame.header.sender != binding.sender
                    || frame.header.source_epoch != binding.scope.epoch
                {
                    return Err(Error::Binding);
                }
                Body::Management(bytes)
            }
            2 => {
                if bytes.len() < 9 || bytes.len() - 8 > limits.max_feedback_bytes {
                    return Err(Error::Length);
                }
                if bytes[6..8] != [0; 2] {
                    return Err(Error::Reserved);
                }
                Body::RecoveryFeedback {
                    lane: LaneId(u32::from_be_bytes(read(bytes, 0)?)),
                    tag: RecoveryTag::decode(u16::from_be_bytes(read(bytes, 4)?))?,
                    bytes: &bytes[8..],
                }
            }
            3 => {
                if bytes.len() != 16 || bytes[5] != 0 {
                    return Err(Error::Length);
                }
                let record = u64::from_be_bytes(read(bytes, 8)?);
                Body::NativeReceipt {
                    lane: LaneId(u32::from_be_bytes(read(bytes, 0)?)),
                    receipt: match bytes[4] {
                        1 if bytes[6..8] == [0; 2] => NativeReceipt::Cumulative { records: record },
                        2 => NativeReceipt::Record {
                            channel: u16::from_be_bytes(read(bytes, 6)?),
                            record,
                        },
                        _ => return Err(Error::Reserved),
                    },
                }
            }
            4 | 5 => {
                if bytes.len() != 8 {
                    return Err(Error::Length);
                }
                let nonce = u64::from_be_bytes(read(bytes, 0)?);
                if input[5] == 4 {
                    Body::Ping { nonce }
                } else {
                    Body::Pong { nonce }
                }
            }
            6 => {
                if bytes.len() <= 4 || bytes.len() > 4 + MAX_PROFILE_CONTROL_BYTES {
                    return Err(Error::Length);
                }
                if bytes[2..4] != [0; 2] {
                    return Err(Error::Reserved);
                }
                Body::ProfileControl {
                    tag: ProfileTag::decode(u16::from_be_bytes(read(bytes, 0)?))?,
                    bytes: &bytes[4..],
                }
            }
            _ => return Err(Error::Kind),
        };
        Ok(Self { binding, body })
    }
    /// Complete encoded length, checked before caller-owned output allocation.
    pub fn encoded_len(self, limits: Limits) -> Result<usize, Error> {
        limits.validate()?;
        let body = match self.body {
            Body::Management(bytes) => bytes.len(),
            Body::RecoveryFeedback { bytes, .. } => {
                bytes.len().checked_add(8).ok_or(Error::Length)?
            }
            Body::NativeReceipt { .. } => 16,
            Body::Ping { .. } | Body::Pong { .. } => 8,
            Body::ProfileControl { bytes, .. } => {
                bytes.len().checked_add(4).ok_or(Error::Length)?
            }
        };
        let length = HEADER_BYTES.checked_add(body).ok_or(Error::Length)?;
        if length > limits.max_frame_bytes {
            return Err(Error::Length);
        }
        match self.body {
            Body::Management(bytes) if bytes.len() > limits.max_management_bytes => {
                return Err(Error::Length);
            }
            Body::RecoveryFeedback { bytes, .. }
                if bytes.is_empty() || bytes.len() > limits.max_feedback_bytes =>
            {
                return Err(Error::Length);
            }
            Body::ProfileControl { bytes, .. }
                if bytes.is_empty() || bytes.len() > MAX_PROFILE_CONTROL_BYTES =>
            {
                return Err(Error::Length);
            }
            _ => {}
        }
        if self.binding.packet.0 == 0 || self.binding.scope.epoch.0 == 0 {
            return Err(Error::Binding);
        }
        if let Body::Management(bytes) = self.body {
            let frame = super::Frame::decode(
                bytes,
                super::Limits {
                    max_frame_bytes: limits.max_management_bytes,
                    ..Default::default()
                },
            )
            .map_err(Error::Legacy)?;
            if frame.header.session != self.binding.session
                || frame.header.lane != self.binding.lane
                || frame.header.sender != self.binding.sender
                || frame.header.source_epoch != self.binding.scope.epoch
            {
                return Err(Error::Binding);
            }
        }
        Ok(length)
    }
    /// Encode an exact prefix; every validation failure leaves output unchanged.
    pub fn encode(self, output: &mut [u8], limits: Limits) -> Result<usize, Error> {
        let length = self.encoded_len(limits)?;
        if output.len() < length {
            return Err(Error::Output);
        }
        let b = self.binding;
        output[..4].copy_from_slice(b"L2SC");
        output[4] = VERSION;
        output[5] = match self.body {
            Body::Management(_) => 1,
            Body::RecoveryFeedback { .. } => 2,
            Body::NativeReceipt { .. } => 3,
            Body::Ping { .. } => 4,
            Body::Pong { .. } => 5,
            Body::ProfileControl { .. } => 6,
        };
        output[6] = b.sender as u8;
        output[7] = 0;
        output[8..12].copy_from_slice(&(length as u32).to_be_bytes());
        output[12..16].copy_from_slice(&b.lane.0.to_be_bytes());
        output[16..32].copy_from_slice(&b.session.0);
        output[32..40].copy_from_slice(&b.packet.0.to_be_bytes());
        output[40..48].copy_from_slice(&b.scope.epoch.0.to_be_bytes());
        output[48..80].copy_from_slice(&b.scope.digest.0);
        let body = &mut output[HEADER_BYTES..length];
        match self.body {
            Body::Management(bytes) => body.copy_from_slice(bytes),
            Body::RecoveryFeedback { lane, tag, bytes } => {
                body[..4].copy_from_slice(&lane.0.to_be_bytes());
                body[4..6].copy_from_slice(&(tag as u16).to_be_bytes());
                body[6..8].fill(0);
                body[8..].copy_from_slice(bytes);
            }
            Body::NativeReceipt { lane, receipt } => {
                body[..4].copy_from_slice(&lane.0.to_be_bytes());
                body[4..8].fill(0);
                let record = match receipt {
                    NativeReceipt::Cumulative { records } => {
                        body[4] = 1;
                        records
                    }
                    NativeReceipt::Record { channel, record } => {
                        body[4] = 2;
                        body[6..8].copy_from_slice(&channel.to_be_bytes());
                        record
                    }
                };
                body[8..16].copy_from_slice(&record.to_be_bytes());
            }
            Body::Ping { nonce } | Body::Pong { nonce } => {
                body.copy_from_slice(&nonce.to_be_bytes())
            }
            Body::ProfileControl { tag, bytes } => {
                body[..2].copy_from_slice(&(tag as u16).to_be_bytes());
                body[2..4].fill(0);
                body[4..].copy_from_slice(bytes);
            }
        }
        Ok(length)
    }
}
/// Fixed two-lane session peer binding supplied only by authenticated setup.
#[derive(Clone, Copy, Debug)]
pub struct PeerBinding {
    /// Actual authenticated primary session.
    pub session: SessionId,
    /// Actual remote endpoint role.
    pub remote_role: Role,
    /// Immutable primary reliable control lane.
    pub control_lane: LaneId,
    /// Authenticated full/paired target data lanes, first entry mandatory.
    pub data_lanes: [Option<LaneId>; 2],
}
/// Which explicitly retained scope owns an admitted event.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ScopeSlot {
    /// Current admitted data policy.
    Active,
    /// Explicitly retained prior policy.
    Draining,
}
/// Borrowed admitted event; no payload allocation, application or request deduplication.
pub struct Admitted<'a> {
    /// Exact validated borrowed envelope.
    pub envelope: Envelope<'a>,
    /// Only the selected retained policy may consume this body.
    pub slot: ScopeSlot,
}
/// One replay owner per remote direction on its fixed primary control stream.
/// Target data lanes and data scopes never reset the counter or replace this gate.
pub struct Gate {
    binding: PeerBinding,
    limits: Limits,
    active: ScopePolicy,
    draining: Option<ScopePolicy>,
    replay: ReplayWindow,
}
impl Gate {
    /// Construct after authenticated session/lane membership is fixed.
    pub fn new(binding: PeerBinding, limits: Limits, active: ScopePolicy) -> Result<Self, Error> {
        limits.validate()?;
        validate_policy(active, limits)?;
        if binding.data_lanes[0].is_none()
            || binding.data_lanes[1].is_some() && binding.data_lanes[1] == binding.data_lanes[0]
            || !binding.data_lanes.contains(&Some(binding.control_lane))
        {
            return Err(Error::Binding);
        }
        Ok(Self {
            binding,
            limits,
            active,
            draining: None,
            replay: ReplayWindow::default(),
        })
    }
    /// Trusted caller must first prove negotiated barriers; no peer frame invokes this.
    /// Keep exactly one old scope; never evict it to make room for another switch.
    pub fn advance_scope(&mut self, next: ScopePolicy) -> Result<(), Error> {
        validate_policy(next, self.limits)?;
        if self.draining.is_some() {
            return Err(Error::Capacity);
        }
        if next.scope.epoch <= self.active.scope.epoch {
            return Err(Error::Scope);
        }
        self.draining = Some(self.active);
        self.active = next;
        Ok(())
    }
    /// Retire only after actual authenticated old-scope drain/transaction evidence.
    pub fn retire_draining(&mut self, expected: Scope) -> Result<(), Error> {
        if self.draining.map(|p| p.scope) != Some(expected) {
            return Err(Error::Scope);
        }
        self.draining = None;
        Ok(())
    }
    /// Highest admitted primary-stream transmission, never reset by target/scope changes.
    pub fn highest_packet(&self) -> Option<PacketNumber> {
        self.replay.highest
    }
    /// Admit authenticated exact bytes. All errors leave scope/replay state unchanged.
    /// Reserve caller-owned event slots/bytes before invoking this infallible-copy boundary.
    pub fn admit<'a>(
        &mut self,
        ingress: super::Ingress,
        input: &'a [u8],
    ) -> Result<Admitted<'a>, Error> {
        let super::Ingress::AuthenticatedManagement {
            session,
            lane,
            sender,
        } = ingress
        else {
            return Err(Error::Legacy(super::Error::UntrustedOrigin));
        };
        if session != self.binding.session
            || sender != self.binding.remote_role
            || lane != self.binding.control_lane
        {
            return Err(Error::Binding);
        }
        let envelope = Envelope::decode(input, self.limits)?;
        let b = envelope.binding;
        if b.session != session || b.sender != sender || b.lane != lane {
            return Err(Error::Binding);
        }
        let (policy, slot) = if b.scope == self.active.scope {
            (self.active, ScopeSlot::Active)
        } else if let Some(old) = self.draining.filter(|p| p.scope == b.scope) {
            (old, ScopeSlot::Draining)
        } else {
            return Err(Error::Scope);
        };
        match envelope.body {
            Body::RecoveryFeedback { lane, tag, bytes }
                if tag != policy.recovery
                    || bytes.len() > policy.max_feedback_bytes
                    || !self.binding.data_lanes.contains(&Some(lane)) =>
            {
                return Err(Error::FeedbackTag);
            }
            Body::NativeReceipt {
                lane,
                receipt: NativeReceipt::Cumulative { .. },
            } if policy.receipts != ReceiptPolicy::Cumulative
                || !self.binding.data_lanes.contains(&Some(lane)) =>
            {
                return Err(Error::Receipt);
            }
            Body::NativeReceipt {
                lane,
                receipt: NativeReceipt::Record { channel, .. },
            } => match policy.receipts {
                ReceiptPolicy::Record { channels }
                    if channel < channels && self.binding.data_lanes.contains(&Some(lane)) => {}
                _ => return Err(Error::Receipt),
            },
            _ => {}
        }
        let expected = self
            .replay
            .highest
            .map_or(Some(1), |p| p.0.checked_add(1))
            .ok_or(Error::Exhausted)?;
        if b.packet.0 > expected {
            return Err(Error::Sequence);
        }
        let replay = self.replay.candidate(b.packet).map_err(Error::Legacy)?;
        self.replay = replay;
        Ok(Admitted { envelope, slot })
    }
}
fn validate_policy(policy: ScopePolicy, limits: Limits) -> Result<(), Error> {
    if policy.scope.epoch.0 == 0
        || policy.max_feedback_bytes == 0
        || policy.max_feedback_bytes > limits.max_feedback_bytes
    {
        return Err(Error::Limits);
    }
    if let ReceiptPolicy::Record { channels } = policy.receipts
        && !(1..=256).contains(&channels)
    {
        return Err(Error::Limits);
    }
    Ok(())
}
/// Sole primary writer transmission counter, spanning all target lanes/scopes.
pub struct PacketNumbers {
    next: Option<u64>,
}
impl Default for PacketNumbers {
    fn default() -> Self {
        Self { next: Some(1) }
    }
}
impl PacketNumbers {
    /// Assign only after bounded output and completion capacity is reserved.
    /// Once assigned, cancellation cannot retract the write; any write/flush failure
    /// terminates the session. No live stream skips/reuses an assigned number.
    pub fn assign(&mut self) -> Result<PacketNumber, Error> {
        let next = self.next.ok_or(Error::Exhausted)?;
        self.next = next.checked_add(1);
        Ok(PacketNumber(next))
    }
}
/// Explicit bounded codec/admission failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// Existing strict management codec or replay rejection.
    Legacy(super::Error),
    /// Local bounded policy is inconsistent.
    Limits,
    /// Exact declared, fixed or configured length mismatch.
    Length,
    /// Wrong discriminator or unnegotiated envelope version.
    Version,
    /// Reserved field or native receipt discriminator is invalid.
    Reserved,
    /// Actual authenticated session/role/lane differs from the frame.
    Binding,
    /// Unknown common-control body class.
    Kind,
    /// Feedback tag, target lane or scoped payload limit mismatch.
    FeedbackTag,
    /// Unknown profile-specific command grammar.
    ProfileTag,
    /// Native receipt grammar/channel/target lane mismatch.
    Receipt,
    /// Unknown, retired or nonmonotonic data scope.
    Scope,
    /// A third scope cannot replace retained draining ownership.
    Capacity,
    /// Ordered primary stream skipped a transmission identity.
    Sequence,
    /// Caller output cannot fit the complete envelope.
    Output,
    /// Sender/receiver packet identity cannot advance without wrapping.
    Exhausted,
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "session control: {self:?}")
    }
}
impl std::error::Error for Error {}
#[cfg(test)]
mod tests;
