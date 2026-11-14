//! Internal management codec, bounded admission and coordinated configuration transactions.
//!
//! The caller must authenticate exact frame bytes and their outer management record class
//! before using [`Ingress::AuthenticatedManagement`]. The transaction module supplies
//! bounded retry/retirement semantics with injected time and explicit drain evidence.
//! Reliable control delivery is separate from transaction semantics; this crate
//! does not authenticate records, own carrier I/O or inspect device queues.

use std::fmt;

use l2tunnel_core::{ConfigDigest, Epoch};
use l2tunnel_session::Ticket;

/// Bounded coordinated configuration transactions with injected time and drain evidence.
pub mod transaction;

/// Versioned mode-independent authenticated session-control envelopes.
pub mod session_control;

/// Fixed bounded reliable control service, independent of data-profile epochs.
pub mod delivery;

/// Whole-message custody composed from existing reliable delivery and fragmentation.
pub mod messages;

/// Explicitly negotiated independent streams inside one authenticated control class.
pub mod control_streams;

/// Fixed header size of the internal draft format, excluding protection outside this crate.
pub const HEADER_LEN: usize = 112;
/// Current draft format version; not a final network interoperability commitment.
pub const VERSION: u8 = 1;
const DISCRIMINATOR: [u8; 4] = *b"L2MC";
const REPLAY_BITS: u64 = 128;

/// Identity of one authenticated session, supplied by the runtime.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SessionId(pub [u8; 16]);
/// Physical authenticated lane, distinct from a user MUX channel.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LaneId(pub u32);
/// Internal logical L2 endpoint address; not a learned device MAC address.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EndpointId(pub u32);
/// Control packet number in a session's peer direction, shared across its lanes.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct PacketNumber(pub u64);
/// Identity of an immutable logical control message, retained across retransmissions.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct RequestId(pub u64);

/// Authenticated sender role in the established session.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Role {
    /// Session initiator.
    Client = 1,
    /// Session listener.
    Server = 2,
}

impl Role {
    fn decode(value: u8) -> Result<Self, Error> {
        match value {
            1 => Ok(Self::Client),
            2 => Ok(Self::Server),
            _ => Err(Error::UnknownRole),
        }
    }
}

/// Draft message discriminator. Transaction body semantics are defined by [`transaction`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum MessageKind {
    /// Propose an authenticated target configuration.
    Prepare = 1,
    /// Report target reader readiness.
    Ready = 2,
    /// Report an old-epoch drain boundary.
    Barrier = 3,
    /// Commit a prepared configuration.
    Commit = 4,
    /// Acknowledge a commit.
    CommitAck = 5,
    /// Report retirement of old state.
    Retire = 6,
    /// Reject a logical request.
    Reject = 7,
    /// Report session status.
    Status = 8,
    /// Reconcile an uncertain transition.
    Reconcile = 9,
}

impl MessageKind {
    fn decode(value: u8) -> Result<Self, Error> {
        match value {
            1 => Ok(Self::Prepare),
            2 => Ok(Self::Ready),
            3 => Ok(Self::Barrier),
            4 => Ok(Self::Commit),
            5 => Ok(Self::CommitAck),
            6 => Ok(Self::Retire),
            7 => Ok(Self::Reject),
            8 => Ok(Self::Status),
            9 => Ok(Self::Reconcile),
            _ => Err(Error::UnknownKind),
        }
    }
}

/// Resource limits for draft parsing and immutable request retention.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Limits {
    /// Maximum complete frame size, from 112 through 65,536 bytes.
    pub max_frame_bytes: usize,
    /// Maximum retained logical requests, from 1 through 1,024.
    pub max_requests: usize,
    /// Maximum sum of retained encoded header/body lengths, at most 64 MiB.
    /// Entry metadata and allocator overhead are additionally bounded by `max_requests`.
    pub max_retained_bytes: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_frame_bytes: 16_384,
            max_requests: 64,
            max_retained_bytes: 1_048_576,
        }
    }
}

impl Limits {
    /// Reject invalid limits before allocation, encoding or parsing.
    pub fn validate(self) -> Result<(), Error> {
        if !(HEADER_LEN..=65_536).contains(&self.max_frame_bytes)
            || !(1..=1_024).contains(&self.max_requests)
            || !(HEADER_LEN..=64 * 1_024 * 1_024).contains(&self.max_retained_bytes)
        {
            return Err(Error::InvalidLimits);
        }
        Ok(())
    }
}

/// Header of the internal control draft. Every field must be protected by the caller.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Header {
    /// Logical control message type.
    pub kind: MessageKind,
    /// Session role of the sender.
    pub sender: Role,
    /// Physical authenticated lane carrying this transmission.
    pub lane: LaneId,
    /// Authenticated session identity.
    pub session: SessionId,
    /// Fresh packet number for this transmission, including retries.
    pub packet: PacketNumber,
    /// Stable identity of the logical message, including retries.
    pub request: RequestId,
    /// Data epoch from which the operation originates.
    pub source_epoch: Epoch,
    /// Proposed target epoch, unique attempt and canonical configuration digest.
    pub ticket: Ticket,
    /// Internal logical sender address.
    pub source: EndpointId,
    /// Internal logical receiver address.
    pub destination: EndpointId,
}

impl Header {
    /// Compare immutable logical identity; transmission packet and lane may differ.
    /// This does not validate the actual authenticated physical lane or body bytes.
    pub fn same_request(self, other: Self) -> bool {
        Self {
            lane: other.lane,
            packet: other.packet,
            ..self
        } == other
    }
}

/// Borrowed frame. Parsing it alone grants no authority or admission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Frame<'a> {
    /// Fixed header fields.
    pub header: Header,
    /// Opaque message body; per-kind schemas are future work.
    pub body: &'a [u8],
}

impl<'a> Frame<'a> {
    /// Parse exactly one complete bounded frame without allocating or authenticating it.
    pub fn decode(input: &'a [u8], limits: Limits) -> Result<Self, Error> {
        limits.validate()?;
        if input.len() > limits.max_frame_bytes {
            return Err(Error::FrameTooLarge);
        }
        if input.len() < HEADER_LEN {
            return Err(Error::Truncated);
        }
        if array::<4>(input, 0)? != DISCRIMINATOR {
            return Err(Error::WrongDiscriminator);
        }
        if input[4] != VERSION {
            return Err(Error::UnsupportedVersion);
        }
        if input[7] != 0 {
            return Err(Error::ReservedBits);
        }
        let declared = u32::from_be_bytes(array(input, 8)?);
        if usize::try_from(declared).map_err(|_| Error::LengthMismatch)? != input.len() {
            return Err(Error::LengthMismatch);
        }
        Ok(Self {
            header: Header {
                kind: MessageKind::decode(input[5])?,
                sender: Role::decode(input[6])?,
                lane: LaneId(u32::from_be_bytes(array(input, 12)?)),
                session: SessionId(array(input, 16)?),
                packet: PacketNumber(u64::from_be_bytes(array(input, 32)?)),
                request: RequestId(u64::from_be_bytes(array(input, 40)?)),
                source_epoch: Epoch(u64::from_be_bytes(array(input, 48)?)),
                ticket: Ticket {
                    epoch: Epoch(u64::from_be_bytes(array(input, 56)?)),
                    attempt: u64::from_be_bytes(array(input, 64)?),
                    digest: ConfigDigest(array(input, 72)?),
                },
                source: EndpointId(u32::from_be_bytes(array(input, 104)?)),
                destination: EndpointId(u32::from_be_bytes(array(input, 108)?)),
            },
            body: &input[HEADER_LEN..],
        })
    }

    /// Encode into the output prefix and return its length; errors leave output unchanged.
    pub fn encode(self, output: &mut [u8], limits: Limits) -> Result<usize, Error> {
        limits.validate()?;
        let len = HEADER_LEN
            .checked_add(self.body.len())
            .ok_or(Error::FrameTooLarge)?;
        if len > limits.max_frame_bytes {
            return Err(Error::FrameTooLarge);
        }
        if output.len() < len {
            return Err(Error::OutputTooSmall);
        }
        let encoded_len = u32::try_from(len).map_err(|_| Error::FrameTooLarge)?;
        let h = self.header;
        output[..4].copy_from_slice(&DISCRIMINATOR);
        output[4] = VERSION;
        output[5] = h.kind as u8;
        output[6] = h.sender as u8;
        output[7] = 0;
        output[8..12].copy_from_slice(&encoded_len.to_be_bytes());
        output[12..16].copy_from_slice(&h.lane.0.to_be_bytes());
        output[16..32].copy_from_slice(&h.session.0);
        output[32..40].copy_from_slice(&h.packet.0.to_be_bytes());
        output[40..48].copy_from_slice(&h.request.0.to_be_bytes());
        output[48..56].copy_from_slice(&h.source_epoch.0.to_be_bytes());
        output[56..64].copy_from_slice(&h.ticket.epoch.0.to_be_bytes());
        output[64..72].copy_from_slice(&h.ticket.attempt.to_be_bytes());
        output[72..104].copy_from_slice(&h.ticket.digest.0);
        output[104..108].copy_from_slice(&h.source.0.to_be_bytes());
        output[108..112].copy_from_slice(&h.destination.0.to_be_bytes());
        output[HEADER_LEN..len].copy_from_slice(self.body);
        Ok(len)
    }
}

fn array<const N: usize>(input: &[u8], offset: usize) -> Result<[u8; N], Error> {
    let end = offset.checked_add(N).ok_or(Error::Truncated)?;
    input
        .get(offset..end)
        .ok_or(Error::Truncated)?
        .try_into()
        .map_err(|_| Error::Truncated)
}

/// Expected identities for one peer direction, shared across authenticated lanes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SessionBinding {
    /// Session established by an external authentication implementation.
    pub session: SessionId,
    /// Expected remote sender role.
    pub remote_role: Role,
    /// Logical remote management address.
    pub remote_endpoint: EndpointId,
    /// Logical local management address.
    pub local_endpoint: EndpointId,
}

/// Origin assertion supplied by the trusted runtime, never inferred from packet bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Ingress {
    /// Device, bridge, VXLAN or authenticated user-data records have no control authority.
    UserTraffic,
    /// Authentication/record-class verification has not succeeded.
    Unauthenticated,
    /// The caller asserts the exact bytes and management class were authenticated.
    /// This crate cannot verify this assertion; no authentication adapter exists here.
    AuthenticatedManagement {
        /// Session bound by the caller's authentication check.
        session: SessionId,
        /// Authenticated physical lane on which these bytes arrived.
        lane: LaneId,
        /// Remote role verified by the caller.
        sender: Role,
    },
}

/// Result of syntactic, binding, replay and immutable-request admission only.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Admission {
    /// First accepted transmission of this logical message; semantic validation remains.
    NewRequest,
    /// Same logical message under a fresh packet number; do not reapply effects.
    RepeatedRequest,
}

/// An admitted borrowed frame and its new/repeated disposition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AdmittedFrame<'a> {
    /// Whether the logical message was previously admitted.
    pub admission: Admission,
    /// Parsed frame; authentication was asserted by the caller, not performed here.
    pub frame: Frame<'a>,
}

#[derive(Clone, Copy, Default)]
struct ReplayWindow {
    highest: Option<PacketNumber>,
    seen: u128,
}

impl ReplayWindow {
    fn candidate(self, packet: PacketNumber) -> Result<Self, Error> {
        let Some(highest) = self.highest else {
            return Ok(Self {
                highest: Some(packet),
                seen: 1,
            });
        };
        if packet > highest {
            let advance = packet.0 - highest.0;
            return Ok(Self {
                highest: Some(packet),
                seen: if advance >= REPLAY_BITS {
                    1
                } else {
                    (self.seen << advance) | 1
                },
            });
        }
        let distance = highest.0 - packet.0;
        if distance >= REPLAY_BITS {
            return Err(Error::PacketTooOld);
        }
        let bit = 1_u128 << distance;
        if self.seen & bit != 0 {
            return Err(Error::PacketReplay);
        }
        Ok(Self {
            seen: self.seen | bit,
            ..self
        })
    }
}

struct AdmissionCandidate<'a> {
    frame: Frame<'a>,
    admission: Admission,
    replay: ReplayWindow,
    retained_bytes: usize,
}

struct StoredRequest {
    header: Header,
    body: Vec<u8>,
}

/// Bounded peer-direction admission; contains no clock, crypto or reload state machine.
///
/// Requests are never evicted in this initial implementation. Full ledgers reject new
/// requests but permit exact retries. Safe retirement and session renewal are integration
/// prerequisites. Keep one gate across lane changes and data epochs within the session.
pub struct AdmissionGate {
    binding: SessionBinding,
    limits: Limits,
    replay: ReplayWindow,
    requests: Vec<StoredRequest>,
    retained_bytes: usize,
    retired_through: Option<RequestId>,
}

impl AdmissionGate {
    /// Create bounded local state for an already authenticated session peer.
    pub fn new(binding: SessionBinding, limits: Limits) -> Result<Self, Error> {
        limits.validate()?;
        let mut requests = Vec::new();
        requests
            .try_reserve_exact(limits.max_requests)
            .map_err(|_| Error::Allocation)?;
        Ok(Self {
            binding,
            limits,
            replay: ReplayWindow::default(),
            requests,
            retained_bytes: 0,
            retired_through: None,
        })
    }

    /// Number of immutable logical requests retained by this gate.
    pub fn retained_requests(&self) -> usize {
        self.requests.len()
    }

    /// Sum of retained encoded header/body lengths; excludes bounded allocator metadata.
    pub fn retained_bytes(&self) -> usize {
        self.retained_bytes
    }

    /// Highest accepted packet number, for diagnostics and exhaustion handling by the caller.
    pub fn highest_packet(&self) -> Option<PacketNumber> {
        self.replay.highest
    }

    /// Retire requests through an authenticated protocol-progress watermark.
    ///
    /// Only call after the higher-level protocol establishes that replies through this
    /// watermark were consumed, or that those commands were irrevocably superseded by an
    /// authenticated abort. The permanent floor rejects even previously unseen old IDs.
    /// It is not safe to invoke this merely because a cache entry is old or queues are full.
    pub fn retire_through(&mut self, watermark: RequestId) {
        if self.retired_through.is_some_and(|old| watermark <= old) {
            return;
        }
        self.requests
            .retain(|request| request.header.request > watermark);
        self.retained_bytes = self
            .requests
            .iter()
            .map(|request| HEADER_LEN + request.body.len())
            .sum();
        self.retired_through = Some(watermark);
    }

    /// Admit exact caller-authenticated management bytes, without applying their semantics.
    /// All errors leave replay and request state unchanged.
    pub fn admit<'a>(
        &mut self,
        ingress: Ingress,
        input: &'a [u8],
    ) -> Result<AdmittedFrame<'a>, Error> {
        let candidate = self.candidate(ingress, input)?;
        let frame = candidate.frame;
        if candidate.admission == Admission::NewRequest {
            let mut body = Vec::new();
            body.try_reserve_exact(frame.body.len())
                .map_err(|_| Error::Allocation)?;
            body.extend_from_slice(frame.body);
            self.requests.push(StoredRequest {
                header: frame.header,
                body,
            });
            self.retained_bytes = candidate.retained_bytes;
        }
        self.replay = candidate.replay;
        Ok(AdmittedFrame {
            admission: candidate.admission,
            frame,
        })
    }

    // Inspect the actual admission path without allocating custody or committing replay.
    fn candidate<'a>(
        &self,
        ingress: Ingress,
        input: &'a [u8],
    ) -> Result<AdmissionCandidate<'a>, Error> {
        let Ingress::AuthenticatedManagement {
            session,
            lane,
            sender,
        } = ingress
        else {
            return Err(Error::UntrustedOrigin);
        };
        if session != self.binding.session || sender != self.binding.remote_role {
            return Err(Error::BindingMismatch);
        }
        let frame = Frame::decode(input, self.limits)?;
        let h = frame.header;
        if h.session != session
            || h.sender != sender
            || h.lane != lane
            || h.source != self.binding.remote_endpoint
            || h.destination != self.binding.local_endpoint
        {
            return Err(Error::BindingMismatch);
        }
        if self
            .retired_through
            .is_some_and(|watermark| h.request <= watermark)
        {
            return Err(Error::RequestRetired);
        }
        let replay = self.replay.candidate(h.packet)?;
        if let Some(prior) = self.requests.iter().find(|r| r.header.request == h.request) {
            if !prior.header.same_request(h) || prior.body != frame.body {
                return Err(Error::RequestConflict);
            }
            return Ok(AdmissionCandidate {
                admission: Admission::RepeatedRequest,
                frame,
                replay,
                retained_bytes: self.retained_bytes,
            });
        }
        let retained_bytes = self
            .retained_bytes
            .checked_add(input.len())
            .ok_or(Error::Capacity)?;
        if self.requests.len() >= self.limits.max_requests
            || retained_bytes > self.limits.max_retained_bytes
        {
            return Err(Error::Capacity);
        }
        Ok(AdmissionCandidate {
            admission: Admission::NewRequest,
            frame,
            replay,
            retained_bytes,
        })
    }
}

/// Explicit draft codec/admission failures. No peer input causes a deliberate panic.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// A configured bound is outside this implementation's hard limits.
    InvalidLimits,
    /// Input does not contain a complete fixed header.
    Truncated,
    /// Input/output frame would exceed the configured maximum length.
    FrameTooLarge,
    /// Output cannot hold the complete encoded frame.
    OutputTooSmall,
    /// Internal discriminator does not match this draft format.
    WrongDiscriminator,
    /// Format version is not supported.
    UnsupportedVersion,
    /// Reserved bits must be zero for this draft.
    ReservedBits,
    /// Declared size differs from the exact provided frame size.
    LengthMismatch,
    /// Message type is not recognized in this draft.
    UnknownKind,
    /// Sender role is not recognized.
    UnknownRole,
    /// Caller did not supply verified management-origin evidence.
    UntrustedOrigin,
    /// Header or verified metadata does not match the expected peer/session/lane.
    BindingMismatch,
    /// Packet number was previously accepted within the replay window.
    PacketReplay,
    /// Packet number lies outside the retained replay window.
    PacketTooOld,
    /// A retained request ID was reused with different immutable content.
    RequestConflict,
    /// Request ID was acknowledged or superseded and permanently retired.
    RequestRetired,
    /// Retaining a new request would exceed count or encoded-byte limits.
    Capacity,
    /// A bounded allocation could not be reserved.
    Allocation,
}

impl fmt::Display for Error {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(output, "management admission error: {self:?}")
    }
}

impl std::error::Error for Error {}

#[cfg(test)]
mod tests;
