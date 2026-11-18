//! Bounded two-peer mode transactions over an externally authenticated control session.
//!
//! Client coordinates; Server responds. Runtime staging and per-channel drain facts are
//! explicitly injected. One immutable command and one reply are retained, with permanent
//! request retirement floors. No sockets, automatic device barriers or crash resume exist here.

mod config;
mod lease;
mod preparation;
pub use config::{
    Configuration, ConfigurationEncoding, MODE_BYTES, configuration_digest, configuration_limits,
    decode_mode, encode_mode, maximum_prepare_bytes, mode_digest,
};
use config::{decode_configuration, encode_configuration};
pub use lease::{CachedRetryAuthority, LeaseSettings, Operation, OperationKind, OutboundContext};
pub use preparation::Preparation;

use std::fmt;

use l2tunnel_core::{ConfigDigest, Epoch, ModeConfig};
use l2tunnel_session::{Phase as GuardPhase, ReloadGuard, Ticket};

use crate::{
    Admission, AdmissionGate, EndpointId, Frame, HEADER_LEN, Header, Ingress, LaneId, Limits,
    MessageKind, PacketNumber, RequestId, Role, SessionBinding, SessionId,
};

/// Monotonic caller-provided milliseconds; unrelated to wall time or packet numbering.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct Tick(pub u64);

/// Authenticated session identity and fixed control-lane binding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Identity {
    /// Fresh authenticated session; never reuse after process restart.
    pub session: SessionId,
    /// Client is the sole coordinator.
    pub role: Role,
    /// This endpoint's logical management address.
    pub local: EndpointId,
    /// The peer's logical management address.
    pub remote: EndpointId,
    /// Fixed authenticated control lane for this transaction engine.
    pub lane: LaneId,
}

/// Finite retry and phase deadlines in injected milliseconds.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Settings {
    /// Time between retransmissions of the same logical message.
    pub retry_ms: u64,
    /// Deadline before pre-commit coordinator abort or follower session failure.
    pub phase_timeout_ms: u64,
    /// Additional time for same-session commit/retire reconciliation before session failure.
    pub reconcile_timeout_ms: u64,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            retry_ms: 100,
            phase_timeout_ms: 5_000,
            reconcile_timeout_ms: 15_000,
        }
    }
}

impl Settings {
    /// Validate finite retry and reconciliation limits without creating peer state.
    pub fn validate(self) -> Result<(), Error> {
        if self.retry_ms == 0
            || self.retry_ms > self.phase_timeout_ms
            || self.phase_timeout_ms > self.reconcile_timeout_ms
            || self.reconcile_timeout_ms > 86_400_000
        {
            return Err(Error::Configuration(
                "invalid retry or reconciliation deadline",
            ));
        }
        Ok(())
    }
}

/// Final exclusive old-epoch admitted-record count per channel, bounded to 256 channels.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Fence(Vec<u64>);

impl Fence {
    /// Copy one count per old-epoch channel; empty and over-256 vectors are rejected.
    pub fn new(counts: &[u64]) -> Result<Self, Error> {
        if counts.is_empty() || counts.len() > 256 {
            return Err(Error::Malformed);
        }
        Ok(Self(counts.to_vec()))
    }
    /// Exact exclusive counts; a channel with no admitted records has count zero.
    pub fn counts(&self) -> &[u64] {
        &self.0
    }
    fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(2 + self.0.len() * 8);
        bytes.extend_from_slice(&(self.0.len() as u16).to_be_bytes());
        for count in &self.0 {
            bytes.extend_from_slice(&count.to_be_bytes());
        }
        bytes
    }
    fn decode(bytes: &[u8], channels: u16) -> Result<Self, Error> {
        if bytes.len() < 2 {
            return Err(Error::Malformed);
        }
        let count = usize::from(u16::from_be_bytes([bytes[0], bytes[1]]));
        if count != usize::from(channels)
            || !(1..=256).contains(&count)
            || bytes.len() != 2 + count * 8
        {
            return Err(Error::Malformed);
        }
        let values = bytes[2..]
            .chunks_exact(8)
            .map(|part| {
                part.try_into()
                    .map(u64::from_be_bytes)
                    .map_err(|_| Error::Malformed)
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self(values))
    }
}

/// Current local transaction phase, not a claim of global simultaneous state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Phase {
    /// No transaction pending; new user admission is permitted.
    Idle,
    /// Coordinator awaits actual runtime target-reader staging and admission fencing.
    Staging,
    /// Coordinator waits for follower READY.
    AwaitReady,
    /// Coordinator waits for local directional drain evidence.
    Draining,
    /// Coordinator waits for the follower's independent drain confirmation.
    AwaitBarrier,
    /// COMMIT may have reached the peer; rollback is forbidden.
    AwaitCommitAck,
    /// Both commits are known; old reader retirement is pending.
    AwaitRetireAck,
    /// Pre-commit abort awaits peer confirmation before old admission resumes.
    Aborting,
    /// Commit/retirement is uncertain; retry the same immutable command.
    Uncertain,
    /// Follower waits for actual local target-reader staging.
    FollowerStaging,
    /// Follower is staged, awaiting barrier and/or independent local drain evidence.
    FollowerReady,
    /// Follower received BARRIER but its own drain evidence is incomplete.
    FollowerDraining,
    /// Both directional drain conditions hold; follower awaits COMMIT.
    FollowerDrained,
    /// Follower committed and retained the old reader pending RETIRE.
    FollowerCommitted,
    /// Session must be torn down; no local rollback/resume is authorized.
    Failed,
}

/// Runtime work or lifecycle observation produced by a validated state transition.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Event<C: Configuration = ModeConfig> {
    /// Allocate target readers and stop old-epoch admission, then call `staged`.
    Stage {
        /// Exact proposal identity.
        ticket: Ticket,
        /// Target reader/configuration specification.
        config: C,
    },
    /// Independently confirm old local sends and peer receives against these fences.
    Drain {
        /// Final admitted local records.
        local: Fence,
        /// Final admitted peer records.
        peer: Fence,
    },
    /// Local active configuration changed; old reader remains until explicit retirement.
    Committed(Ticket),
    /// Old-epoch reader is now removed.
    Retired(Epoch),
    /// A pre-commit proposal is safely aborted and old admission may resume.
    Aborted(u64),
    /// A possible remote commit/retirement requires retry, never unilateral rollback.
    Uncertain(Ticket),
    /// A bounded deadline expired or the session cannot continue safely.
    Failed,
}

/// At most one outgoing complete control frame and one runtime event per call.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Effects<C: Configuration = ModeConfig> {
    /// Pass through the authenticated management record class and charged control budget.
    pub outbound: Option<Vec<u8>>,
    /// Runtime work/status; never interpret a Stage or Drain event as completed evidence.
    pub event: Option<Event<C>>,
}

impl<C: Configuration> Default for Effects<C> {
    fn default() -> Self {
        Self {
            outbound: None,
            event: None,
        }
    }
}

/// Meaning of an available epoch reader.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReadDisposition {
    /// Decode under the current committed configuration.
    Current,
    /// Target may be committed remotely; retain bounded records until local COMMIT_ACK.
    Staged,
    /// Old configuration only for drain/duplicate processing; never redeliver old records.
    DrainOnly,
}

/// A reader is always paired with its own epoch's configuration.
pub struct Reader<'a, C: Configuration = ModeConfig> {
    /// Exact configuration for the requested epoch, never the other epoch's profile.
    pub config: &'a C,
    /// Canonical digest and epoch of this reader, retained from validated negotiation.
    pub scope: crate::session_control::Scope,
    /// Delivery restriction for this reader.
    pub disposition: ReadDisposition,
}

#[derive(Clone)]
struct Message {
    request: RequestId,
    kind: MessageKind,
    source: Epoch,
    ticket: Ticket,
    body: Vec<u8>,
}
struct CachedReply {
    for_request: RequestId,
    message: Message,
}
#[derive(Clone, Copy)]
struct Incoming {
    request: RequestId,
    source: Epoch,
    ticket: Ticket,
}
struct Pending<C: Configuration> {
    ticket: Ticket,
    origin: crate::session_control::Scope,
    old: C,
    next: C,
    local: Option<Fence>,
    peer: Option<Fence>,
    local_drained: bool,
    peer_barrier: bool,
}

#[derive(Clone, Copy)]
enum FenceContract {
    Legacy,
    GlobalSender,
}
impl FenceContract {
    fn validate<C: Configuration>(self, config: &C) -> Result<(), Error> {
        match self {
            Self::Legacy => Ok(()),
            Self::GlobalSender => config::validate_sender_channels(config),
        }
    }
    fn channels<C: Configuration>(self, config: &C, sender: Role) -> u16 {
        match self {
            Self::Legacy => config.channels(),
            Self::GlobalSender => config.sender_channels(sender),
        }
    }
}

/// Bounded distributed transaction state for one existing authenticated peer session.
pub struct Peer<C: Configuration = ModeConfig> {
    lease: Option<lease::State>,
    fence_contract: FenceContract,
    identity: Identity,
    settings: Settings,
    supported: Vec<ConfigDigest>,
    active: C,
    guard: ReloadGuard,
    gate: AdmissionGate,
    phase: Phase,
    pending: Option<Pending<C>>,
    outstanding: Option<Message>,
    cached: Option<CachedReply>,
    incoming: Option<Incoming>,
    last_command: u64,
    last_attempt: u64,
    next_request: u64,
    next_packet: u64,
    now: Tick,
    deadline: Tick,
    next_retry: Tick,
}

impl<C: Configuration> Peer<C> {
    /// Start a fresh-session engine. Runtime support must be explicitly listed (at most 64 modes).
    /// Restoring the same session after a restart without persisted replay/attempt state is forbidden.
    pub fn new(
        identity: Identity,
        epoch: Epoch,
        initial: C,
        supported: &[C],
        settings: Settings,
        now: Tick,
    ) -> Result<Self, Error> {
        Self::new_with_contract(
            identity,
            epoch,
            initial,
            supported,
            settings,
            now,
            FenceContract::Legacy,
        )
    }

    /// Select global-sender old-policy fence widths on both endpoints explicitly.
    /// Client and Server name the same global senders at each endpoint; this is
    /// independent of local send/receive halves and preserves the existing wire.
    pub fn new_directional(
        identity: Identity,
        epoch: Epoch,
        initial: C,
        supported: &[C],
        settings: Settings,
        now: Tick,
    ) -> Result<Self, Error> {
        Self::new_with_contract(
            identity,
            epoch,
            initial,
            supported,
            settings,
            now,
            FenceContract::GlobalSender,
        )
    }

    fn new_with_contract(
        identity: Identity,
        epoch: Epoch,
        initial: C,
        supported: &[C],
        settings: Settings,
        now: Tick,
        fence_contract: FenceContract,
    ) -> Result<Self, Error> {
        settings.validate()?;
        if supported.is_empty() || supported.len() > 64 || identity.local == identity.remote {
            return Err(Error::Configuration(
                "invalid supported modes or endpoint identities",
            ));
        }
        let digest = configuration_digest(&initial)?;
        fence_contract.validate(&initial)?;
        let supported = supported
            .iter()
            .map(|config| {
                let digest = configuration_digest(config)?;
                fence_contract.validate(config)?;
                Ok(digest)
            })
            .collect::<Result<Vec<_>, Error>>()?;
        if !supported.contains(&digest) {
            return Err(Error::Unsupported);
        }
        let binding = SessionBinding {
            session: identity.session,
            remote_role: opposite(identity.role),
            remote_endpoint: identity.remote,
            local_endpoint: identity.local,
        };
        let deadline = add(now, settings.reconcile_timeout_ms)?;
        Ok(Self {
            lease: None,
            fence_contract,
            identity,
            settings,
            supported,
            active: initial,
            guard: ReloadGuard::new(Ticket {
                attempt: 0,
                epoch,
                digest,
            }),
            gate: AdmissionGate::new(binding, configuration_limits::<C>()?)
                .map_err(Error::Admission)?,
            phase: Phase::Idle,
            pending: None,
            outstanding: None,
            cached: None,
            incoming: None,
            last_command: 0,
            last_attempt: 0,
            next_request: 1,
            next_packet: 1,
            now,
            deadline,
            next_retry: now,
        })
    }

    /// Current local lifecycle phase.
    pub fn phase(&self) -> Phase {
        self.phase
    }
    /// Locally committed active mode.
    pub fn active_config(&self) -> &C {
        &self.active
    }
    /// Active old-policy width under this peer's explicitly selected contract.
    /// Legacy peers return `channels()` for either authenticated global sender.
    pub fn sender_channels(&self, sender: Role) -> u16 {
        self.sender_channels_for(&self.active, sender)
    }
    fn sender_channels_for(&self, config: &C, sender: Role) -> u16 {
        self.fence_contract.channels(config, sender)
    }
    /// Actual pending peer's exclusive old native-delivery fence, when received.
    /// This immutable observation grants no drain or physical-completion authority.
    pub fn peer_fence(&self) -> Option<&Fence> {
        self.pending.as_ref()?.peer.as_ref()
    }
    /// Locally committed data epoch.
    pub fn active_epoch(&self) -> Epoch {
        self.guard.active().epoch
    }
    /// New user admission is permitted only once a transaction/abort completes.
    pub fn can_admit_data(&self) -> bool {
        self.phase == Phase::Idle && self.operation().is_none()
    }
    /// Bounded request-ledger occupancy, independent of the number of completed transactions.
    pub fn retained_requests(&self) -> usize {
        self.gate.retained_requests()
    }
    /// Retained reply count is either zero or one.
    pub fn retained_replies(&self) -> usize {
        usize::from(self.cached.is_some())
    }

    /// Select only the requested epoch's reader, with explicit delivery restrictions.
    pub fn reader(&self, epoch: Epoch) -> Option<Reader<'_, C>> {
        if self.phase == Phase::Failed {
            return None;
        }
        if epoch == self.active_epoch() {
            return Some(Reader {
                config: &self.active,
                scope: self.current_origin(),
                disposition: if self.guard.phase() == GuardPhase::CommitSent {
                    ReadDisposition::DrainOnly
                } else {
                    ReadDisposition::Current
                },
            });
        }
        let pending = self.pending.as_ref()?;
        if epoch == pending.origin.epoch && self.active_epoch() == pending.ticket.epoch {
            Some(Reader {
                config: &pending.old,
                scope: pending.origin,
                disposition: ReadDisposition::DrainOnly,
            })
        } else if epoch == pending.ticket.epoch && self.guard.phase() == GuardPhase::CommitSent {
            Some(Reader {
                config: &pending.next,
                scope: crate::session_control::Scope {
                    epoch: pending.ticket.epoch,
                    digest: pending.ticket.digest,
                },
                disposition: ReadDisposition::Staged,
            })
        } else {
            None
        }
    }

    /// Coordinator-only proposal. Actual reader allocation/admission fencing is a later `staged` call.
    pub fn propose(&mut self, config: C, now: Tick) -> Result<Effects<C>, Error> {
        self.advance(now)?;
        if self.is_leased() {
            return Err(Error::LeaseRequired);
        }
        self.propose_inner(config)
    }

    fn proposal_ticket(&self, config: &C) -> Result<Ticket, Error> {
        if self.identity.role != Role::Client {
            return Err(Error::NotCoordinator);
        }
        if self.phase != Phase::Idle || self.operation().is_some() {
            return Err(Error::Busy);
        }
        let digest = self.validate_mode(config)?;
        let ticket = Ticket {
            attempt: self.last_attempt.checked_add(1).ok_or(Error::Exhausted)?,
            epoch: Epoch(
                self.active_epoch()
                    .0
                    .checked_add(1)
                    .ok_or(Error::Exhausted)?,
            ),
            digest,
        };
        Ok(ticket)
    }

    fn propose_inner(&mut self, config: C) -> Result<Effects<C>, Error> {
        let ticket = self.proposal_ticket(&config)?;
        self.guard.prepare(ticket).map_err(Error::Guard)?;
        self.begin_operation(ticket)?;
        self.last_attempt = ticket.attempt;
        self.pending = Some(Pending {
            ticket,
            origin: self.current_origin(),
            old: self.active.clone(),
            next: config.clone(),
            local: None,
            peer: None,
            local_drained: false,
            peer_barrier: false,
        });
        self.set_phase(Phase::Staging)?;
        Ok(Effects {
            event: Some(Event::Stage { ticket, config }),
            ..Effects::default()
        })
    }

    /// Assert target readers are staged and old admission stopped before capturing this fence.
    pub fn staged(&mut self, local: Fence, now: Tick) -> Result<Effects<C>, Error> {
        self.advance(now)?;
        if !matches!(self.phase, Phase::Staging | Phase::FollowerStaging) {
            return Err(Error::Unexpected);
        }
        if local.0.len() != usize::from(self.sender_channels(self.identity.role)) {
            return Err(Error::IncompleteDrain);
        }
        let pending = self.pending.as_mut().ok_or(Error::Unexpected)?;
        pending.local = Some(local.clone());
        let ticket = pending.ticket;
        let source = pending.origin.epoch;
        if self.identity.role == Role::Client {
            let mut body = encode_configuration(&pending.next)?;
            body.extend_from_slice(&local.encode());
            self.set_phase(Phase::AwaitReady)?;
            self.command(MessageKind::Prepare, source, ticket, &body)
        } else {
            let peer = pending.peer.clone().ok_or(Error::Unexpected)?;
            let incoming = self.incoming.ok_or(Error::Unexpected)?;
            self.set_phase(Phase::FollowerReady)?;
            let mut result = self.reply(MessageKind::Ready, incoming, &local.encode())?;
            result.event = Some(Event::Drain { local, peer });
            Ok(result)
        }
    }

    /// Assert exact local-send confirmation and peer-receive delivery vectors, independently.
    /// Incomplete/asymmetric evidence cannot authorize a barrier or commit.
    pub fn confirm_drained(
        &mut self,
        sent_confirmed: &Fence,
        received_delivered: &Fence,
        now: Tick,
    ) -> Result<Effects<C>, Error> {
        self.advance(now)?;
        if !matches!(
            self.phase,
            Phase::Draining | Phase::FollowerReady | Phase::FollowerDraining
        ) {
            return Err(Error::Unexpected);
        }
        let pending = self.pending.as_mut().ok_or(Error::Unexpected)?;
        if pending.local.as_ref() != Some(sent_confirmed)
            || pending.peer.as_ref() != Some(received_delivered)
        {
            return Err(Error::IncompleteDrain);
        }
        pending.local_drained = true;
        let ticket = pending.ticket;
        let source = pending.origin.epoch;
        if self.identity.role == Role::Client {
            self.set_phase(Phase::AwaitBarrier)?;
            self.command(MessageKind::Barrier, source, ticket, &[])
        } else if pending.peer_barrier {
            self.guard.drained(ticket).map_err(Error::Guard)?;
            self.set_phase(Phase::FollowerDrained)?;
            self.reply(
                MessageKind::Barrier,
                self.incoming.ok_or(Error::Unexpected)?,
                &[],
            )
        } else {
            Ok(Effects::default())
        }
    }

    /// Process one exact externally authenticated management frame.
    /// Replay/retired packet errors are safely discardable; other protocol errors fail this session.
    pub fn receive(
        &mut self,
        ingress: Ingress,
        bytes: &[u8],
        now: Tick,
    ) -> Result<Effects<C>, Error> {
        self.advance(now)?;
        if self.phase == Phase::Failed {
            return Err(Error::Failed);
        }
        self.leased_receive_preflight(ingress, bytes)?;
        let admitted = match self.gate.admit(ingress, bytes) {
            Ok(admitted) => admitted,
            Err(error) => {
                if !matches!(
                    error,
                    crate::Error::UntrustedOrigin
                        | crate::Error::BindingMismatch
                        | crate::Error::PacketReplay
                        | crate::Error::PacketTooOld
                        | crate::Error::RequestRetired
                ) {
                    self.phase = Phase::Failed;
                }
                return Err(Error::Admission(error));
            }
        };
        let frame = admitted.frame;
        if frame.header.lane != self.identity.lane {
            self.phase = Phase::Failed;
            return Err(Error::Unexpected);
        }
        if admitted.admission == Admission::RepeatedRequest {
            if let Some(reply) = &self.cached
                && reply.for_request == frame.header.request
            {
                let message = reply.message.clone();
                return Ok(Effects {
                    outbound: Some(self.emit(&message)?),
                    event: None,
                });
            }
            return Ok(Effects::default());
        }
        let result = if self.identity.role == Role::Client {
            self.response(frame)
        } else {
            self.request(frame)
        };
        if result.is_err() {
            self.phase = Phase::Failed;
        } else if self.identity.role == Role::Client {
            let request = if self.final_request_is_held(frame.header.request) {
                RequestId(frame.header.request.0.saturating_sub(1))
            } else {
                frame.header.request
            };
            self.gate.retire_through(request);
        } else {
            self.gate
                .retire_through(RequestId(frame.header.request.0.saturating_sub(1)));
        }
        result
    }

    /// Retry due immutable messages or enforce bounded abort/uncertain-commit deadlines.
    pub fn poll(&mut self, now: Tick) -> Result<Effects<C>, Error> {
        self.advance(now)?;
        if matches!(self.phase, Phase::Idle | Phase::Failed) {
            return Ok(Effects::default());
        }
        if now >= self.deadline {
            if self.identity.role == Role::Client
                && matches!(
                    self.phase,
                    Phase::Staging | Phase::AwaitReady | Phase::Draining | Phase::AwaitBarrier
                )
            {
                let pending = self.pending.as_ref().ok_or(Error::Unexpected)?;
                let ticket = pending.ticket;
                let source = pending.origin.epoch;
                let not_sent = self.phase == Phase::Staging;
                self.guard.abort(ticket).map_err(Error::Guard)?;
                self.outstanding = None;
                if not_sent {
                    self.pending = None;
                    self.set_phase(Phase::Idle)?;
                    self.complete_local_abort();
                    return Ok(Effects {
                        event: Some(Event::Aborted(ticket.attempt)),
                        ..Effects::default()
                    });
                }
                self.set_phase(Phase::Aborting)?;
                return self.command(MessageKind::Reject, source, ticket, &[]);
            }
            if self.identity.role == Role::Client
                && matches!(self.phase, Phase::AwaitCommitAck | Phase::AwaitRetireAck)
            {
                let message = self.outstanding.clone().ok_or(Error::Unexpected)?;
                self.phase = Phase::Uncertain;
                self.deadline = self.clamp_lease(add(now, self.settings.reconcile_timeout_ms)?);
                return Ok(Effects {
                    outbound: Some(self.emit(&message)?),
                    event: Some(Event::Uncertain(message.ticket)),
                });
            }
            self.phase = Phase::Failed;
            return Ok(Effects {
                event: Some(Event::Failed),
                ..Effects::default()
            });
        }
        if now < self.next_retry {
            return Ok(Effects::default());
        }
        let message = self
            .outstanding
            .clone()
            .or_else(|| self.cached.as_ref().map(|cached| cached.message.clone()));
        if let Some(message) = message {
            Ok(Effects {
                outbound: Some(self.emit(&message)?),
                event: None,
            })
        } else {
            Ok(Effects::default())
        }
    }

    fn advance(&mut self, now: Tick) -> Result<(), Error> {
        self.observe_lease(now)?;
        if now < self.now {
            return Err(Error::Clock);
        }
        add(now, self.settings.reconcile_timeout_ms)?;
        self.now = now;
        Ok(())
    }
    fn set_phase(&mut self, phase: Phase) -> Result<(), Error> {
        self.phase = phase;
        self.deadline = self.clamp_lease(add(self.now, self.settings.phase_timeout_ms)?);
        Ok(())
    }
    fn validate_mode(&self, mode: &C) -> Result<ConfigDigest, Error> {
        let digest = configuration_digest(mode)?;
        self.fence_contract.validate(mode)?;
        if !self.supported.contains(&digest) || mode.duplex() != self.active.duplex() {
            return Err(Error::Unsupported);
        }
        Ok(digest)
    }
    fn matches_pending(&self, header: Header) -> Result<(), Error> {
        let pending = self.pending.as_ref().ok_or(Error::Unexpected)?;
        if pending.ticket != header.ticket || pending.origin.epoch != header.source_epoch {
            return Err(Error::Unexpected);
        }
        Ok(())
    }

    // The caller preserves its existing prefix/error ordering before this shared check.
    fn first_prepare(&self, frame: Frame<'_>, truncated: Error) -> Result<(C, Fence), Error> {
        let h = frame.header;
        if self.phase != Phase::Idle
            || h.ticket.attempt <= self.last_attempt
            || h.source_epoch != self.active_epoch()
            || h.ticket.epoch.0
                != self
                    .active_epoch()
                    .0
                    .checked_add(1)
                    .ok_or(Error::Exhausted)?
        {
            return Err(Error::Unexpected);
        }
        let end = 8usize.checked_add(C::ENCODED_LEN).ok_or(Error::Malformed)?;
        let canonical = frame.body.get(8..end).ok_or(truncated)?;
        let next = decode_configuration::<C>(canonical)?;
        if self.validate_mode(&next)? != h.ticket.digest {
            return Err(Error::Unexpected);
        }
        let peer = Fence::decode(
            frame.body.get(end..).ok_or(Error::Malformed)?,
            self.sender_channels(opposite(self.identity.role)),
        )?;
        Ok((next, peer))
    }

    fn request(&mut self, frame: Frame<'_>) -> Result<Effects<C>, Error> {
        let h = frame.header;
        if frame.body.len() < 8 || reply_to(frame.body)? != 0 || h.request.0 <= self.last_command {
            return Err(Error::Unexpected);
        }
        let incoming = Incoming {
            request: h.request,
            source: h.source_epoch,
            ticket: h.ticket,
        };
        let result = match h.kind {
            MessageKind::Prepare => {
                let (next, peer) = self.first_prepare(frame, Error::Unexpected)?;
                self.guard.prepare(h.ticket).map_err(Error::Guard)?;
                self.guard.peer_ready(h.ticket).map_err(Error::Guard)?;
                self.begin_operation(h.ticket)?;
                self.last_attempt = h.ticket.attempt;
                self.pending = Some(Pending {
                    ticket: h.ticket,
                    origin: self.current_origin(),
                    old: self.active.clone(),
                    next: next.clone(),
                    local: None,
                    peer: Some(peer),
                    local_drained: false,
                    peer_barrier: false,
                });
                self.cached = None;
                self.set_phase(Phase::FollowerStaging)?;
                Effects {
                    event: Some(Event::Stage {
                        ticket: h.ticket,
                        config: next,
                    }),
                    ..Effects::default()
                }
            }
            MessageKind::Barrier => {
                self.matches_pending(h)?;
                if self.phase != Phase::FollowerReady || frame.body.len() != 8 {
                    return Err(Error::Unexpected);
                }
                let pending = self.pending.as_mut().ok_or(Error::Unexpected)?;
                pending.peer_barrier = true;
                self.cached = None;
                if pending.local_drained {
                    self.guard.drained(h.ticket).map_err(Error::Guard)?;
                    self.set_phase(Phase::FollowerDrained)?;
                    self.reply(MessageKind::Barrier, incoming, &[])?
                } else {
                    self.set_phase(Phase::FollowerDraining)?;
                    Effects::default()
                }
            }
            MessageKind::Commit => {
                self.matches_pending(h)?;
                if self.phase != Phase::FollowerDrained || frame.body.len() != 8 {
                    return Err(Error::Unexpected);
                }
                self.guard.commit(h.ticket).map_err(Error::Guard)?;
                self.guard.acknowledge(h.ticket).map_err(Error::Guard)?;
                self.active = self.pending.as_ref().ok_or(Error::Unexpected)?.next.clone();
                self.set_phase(Phase::FollowerCommitted)?;
                let mut effects = self.reply(MessageKind::CommitAck, incoming, &[])?;
                effects.event = Some(Event::Committed(h.ticket));
                effects
            }
            MessageKind::Retire => {
                self.matches_pending(h)?;
                if self.phase != Phase::FollowerCommitted || frame.body.len() != 8 {
                    return Err(Error::Unexpected);
                }
                self.pending = None;
                self.set_phase(Phase::Idle)?;
                let mut effects = self.reply(MessageKind::Retire, incoming, &[])?;
                effects.event = Some(Event::Retired(h.source_epoch));
                effects
            }
            MessageKind::Reject => {
                if frame.body.len() != 8 || h.source_epoch != self.active_epoch() {
                    return Err(Error::Unexpected);
                }
                if self.pending.is_some() {
                    self.matches_pending(h)?;
                    self.guard.abort(h.ticket).map_err(Error::Guard)?;
                } else if self.phase != Phase::Idle
                    || h.ticket.attempt <= self.last_attempt
                    || h.ticket.epoch.0
                        != self
                            .active_epoch()
                            .0
                            .checked_add(1)
                            .ok_or(Error::Exhausted)?
                {
                    return Err(Error::Unexpected);
                }
                if self.operation().is_none() {
                    self.begin_operation(h.ticket)?;
                }
                self.last_attempt = h.ticket.attempt;
                self.pending = None;
                self.set_phase(Phase::Idle)?;
                let mut effects = self.reply(MessageKind::Reject, incoming, &[])?;
                effects.event = Some(Event::Aborted(h.ticket.attempt));
                effects
            }
            _ => return Err(Error::Unexpected),
        };
        self.incoming = Some(incoming);
        self.last_command = h.request.0;
        Ok(result)
    }

    fn response(&mut self, frame: Frame<'_>) -> Result<Effects<C>, Error> {
        let outstanding = self.outstanding.clone().ok_or(Error::Unexpected)?;
        let response_to = reply_to(frame.body)?;
        if response_to < outstanding.request.0 {
            return Ok(Effects::default());
        }
        if response_to != outstanding.request.0
            || frame.header.ticket != outstanding.ticket
            || frame.header.source_epoch != outstanding.source
        {
            return Err(Error::Unexpected);
        }
        let expected = match outstanding.kind {
            MessageKind::Prepare => MessageKind::Ready,
            MessageKind::Barrier => MessageKind::Barrier,
            MessageKind::Commit => MessageKind::CommitAck,
            MessageKind::Retire => MessageKind::Retire,
            MessageKind::Reject => MessageKind::Reject,
            _ => return Err(Error::Unexpected),
        };
        if frame.header.kind != expected {
            return Err(Error::Unexpected);
        }
        if expected != MessageKind::Ready && frame.body.len() != 8 {
            return Err(Error::Malformed);
        }
        match expected {
            MessageKind::Ready => {
                if self.phase != Phase::AwaitReady {
                    return Err(Error::Unexpected);
                }
                let peer = Fence::decode(
                    &frame.body[8..],
                    self.sender_channels(opposite(self.identity.role)),
                )?;
                let pending = self.pending.as_mut().ok_or(Error::Unexpected)?;
                pending.peer = Some(peer.clone());
                let local = pending.local.clone().ok_or(Error::Unexpected)?;
                self.guard
                    .peer_ready(outstanding.ticket)
                    .map_err(Error::Guard)?;
                self.outstanding = None;
                self.set_phase(Phase::Draining)?;
                Ok(Effects {
                    event: Some(Event::Drain { local, peer }),
                    ..Effects::default()
                })
            }
            MessageKind::Barrier => {
                if self.phase != Phase::AwaitBarrier
                    || !self
                        .pending
                        .as_ref()
                        .is_some_and(|pending| pending.local_drained)
                {
                    return Err(Error::Unexpected);
                }
                self.guard
                    .drained(outstanding.ticket)
                    .map_err(Error::Guard)?;
                self.guard
                    .commit(outstanding.ticket)
                    .map_err(Error::Guard)?;
                self.set_phase(Phase::AwaitCommitAck)?;
                self.command(
                    MessageKind::Commit,
                    outstanding.source,
                    outstanding.ticket,
                    &[],
                )
            }
            MessageKind::CommitAck => {
                if !matches!(self.phase, Phase::AwaitCommitAck | Phase::Uncertain) {
                    return Err(Error::Unexpected);
                }
                self.guard
                    .acknowledge(outstanding.ticket)
                    .map_err(Error::Guard)?;
                self.active = self.pending.as_ref().ok_or(Error::Unexpected)?.next.clone();
                self.set_phase(Phase::AwaitRetireAck)?;
                let mut effects = self.command(
                    MessageKind::Retire,
                    outstanding.source,
                    outstanding.ticket,
                    &[],
                )?;
                effects.event = Some(Event::Committed(outstanding.ticket));
                Ok(effects)
            }
            MessageKind::Retire => {
                if !matches!(self.phase, Phase::AwaitRetireAck | Phase::Uncertain) {
                    return Err(Error::Unexpected);
                }
                self.capture_final_incoming(frame)?;
                self.pending = None;
                self.outstanding = None;
                self.set_phase(Phase::Idle)?;
                Ok(Effects {
                    event: Some(Event::Retired(outstanding.source)),
                    ..Effects::default()
                })
            }
            MessageKind::Reject => {
                if self.phase != Phase::Aborting {
                    return Err(Error::Unexpected);
                }
                self.capture_final_incoming(frame)?;
                self.pending = None;
                self.outstanding = None;
                self.set_phase(Phase::Idle)?;
                Ok(Effects {
                    event: Some(Event::Aborted(outstanding.ticket.attempt)),
                    ..Effects::default()
                })
            }
            _ => Err(Error::Unexpected),
        }
    }

    fn message(
        &mut self,
        kind: MessageKind,
        source: Epoch,
        ticket: Ticket,
        response_to: u64,
        fields: &[u8],
    ) -> Result<Message, Error> {
        let request = RequestId(self.next_request);
        self.next_request = self.next_request.checked_add(1).ok_or_else(|| {
            self.phase = Phase::Failed;
            Error::Exhausted
        })?;
        let mut body = Vec::with_capacity(8 + fields.len());
        body.extend_from_slice(&response_to.to_be_bytes());
        body.extend_from_slice(fields);
        Ok(Message {
            request,
            kind,
            source,
            ticket,
            body,
        })
    }
    fn command(
        &mut self,
        kind: MessageKind,
        source: Epoch,
        ticket: Ticket,
        fields: &[u8],
    ) -> Result<Effects<C>, Error> {
        let message = self.message(kind, source, ticket, 0, fields)?;
        let bytes = self.emit(&message)?;
        self.outstanding = Some(message);
        Ok(Effects {
            outbound: Some(bytes),
            event: None,
        })
    }
    fn reply(
        &mut self,
        kind: MessageKind,
        incoming: Incoming,
        fields: &[u8],
    ) -> Result<Effects<C>, Error> {
        let message = self.message(
            kind,
            incoming.source,
            incoming.ticket,
            incoming.request.0,
            fields,
        )?;
        let bytes = self.emit(&message)?;
        self.cached = Some(CachedReply {
            for_request: incoming.request,
            message,
        });
        Ok(Effects {
            outbound: Some(bytes),
            event: None,
        })
    }
    fn emit(&mut self, message: &Message) -> Result<Vec<u8>, Error> {
        self.observe_lease(self.now)?;
        let packet = PacketNumber(self.next_packet);
        self.next_packet = self.next_packet.checked_add(1).ok_or_else(|| {
            self.phase = Phase::Failed;
            Error::Exhausted
        })?;
        let header = Header {
            kind: message.kind,
            sender: self.identity.role,
            lane: self.identity.lane,
            session: self.identity.session,
            packet,
            request: message.request,
            source_epoch: message.source,
            ticket: message.ticket,
            source: self.identity.local,
            destination: self.identity.remote,
        };
        let mut bytes = vec![0; HEADER_LEN + message.body.len()];
        Frame {
            header,
            body: &message.body,
        }
        .encode(&mut bytes, configuration_limits::<C>()?)
        .map_err(Error::Admission)?;
        self.next_retry = self.clamp_lease(add(self.now, self.settings.retry_ms)?);
        Ok(bytes)
    }
}

fn limits() -> Limits {
    Limits {
        max_frame_bytes: 4_096,
        max_requests: 4,
        max_retained_bytes: 16_384,
    }
}
fn opposite(role: Role) -> Role {
    match role {
        Role::Client => Role::Server,
        Role::Server => Role::Client,
    }
}
fn add(now: Tick, delta: u64) -> Result<Tick, Error> {
    now.0.checked_add(delta).map(Tick).ok_or(Error::Clock)
}
fn reply_to(bytes: &[u8]) -> Result<u64, Error> {
    bytes
        .get(..8)
        .ok_or(Error::Malformed)?
        .try_into()
        .map(u64::from_be_bytes)
        .map_err(|_| Error::Malformed)
}

/// Explicit errors. Authenticated protocol violations fail the session without rollback.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Error {
    /// This explicitly leased contract requires an original operation deadline.
    LeaseRequired,
    /// An active operation cannot change its original deadline or identity.
    LeaseConflict,
    /// The immutable session or operation cap expired; this peer cannot resume.
    LeaseExpired,
    /// Exact final-message custody or its authenticated context was not proved.
    Custody,
    /// Invalid local mode/timing/resource contract.
    Configuration(&'static str),
    /// Caller did not list the target mode as implemented, or duplex lifecycle would change.
    Unsupported,
    /// Only the deterministic Client coordinator may propose a mode.
    NotCoordinator,
    /// Another transaction is already pending.
    Busy,
    /// State/message/ticket does not match the current transaction.
    Unexpected,
    /// Drain vectors do not exactly confirm both recorded directional fences.
    IncompleteDrain,
    /// Canonical payload length/version/enum/field is invalid.
    Malformed,
    /// Clock moved backward or a bounded deadline overflows.
    Clock,
    /// Epoch, proposal attempt, packet or request counter is exhausted.
    Exhausted,
    /// The session has failed and must not be reused.
    Failed,
    /// Existing frame origin/replay/request gate rejected the input.
    Admission(crate::Error),
    /// Existing local reload guard rejected a transition.
    Guard(&'static str),
}
impl fmt::Display for Error {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(output, "management transaction error: {self:?}")
    }
}
impl std::error::Error for Error {}

#[cfg(test)]
mod tests;
