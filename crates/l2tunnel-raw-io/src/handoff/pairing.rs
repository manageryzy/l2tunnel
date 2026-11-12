//! From-birth authenticated raw lane ownership; no Armed, Seal or handoff authority.
use super::{
    MessageError, MessageLimits, MessageStatus, Setup, SetupFailure, StartError, SwitchDriver,
    SwitchLimits, SwitchStatus, TlsMessageOwner, driver::PreparedBridge, tls_owner,
};
use crate::PacketIo;
use l2tunnel_auth::{ClientTls, MemberAllowlist, MemberKey, ServerTls, SessionConfig, SessionInfo};
use l2tunnel_core::{ConfigDigest, Duplex};
use l2tunnel_raw_tcp::{Config, Role};
use ring::rand::{SecureRandom, SystemRandom};
use std::{
    fmt,
    future::Future,
    io,
    mem::size_of,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};
use tokio::time::{Instant, Sleep};
use tokio_rustls::rustls::pki_types::ServerName;
mod keys;
mod profile;
use keys::{Keys, Roots};
use profile::{Profile, RECORD, TRANSCRIPT};

/// One original packet owner and its explicit local raw TCP policy.
pub struct RawInput<I: PacketIo> {
    /// Validated local tuple, buffers and timing policy.
    pub config: Config,
    /// Exclusive original packet I/O; the factory creates all higher owners.
    pub io: I,
}
/// Exactly one full lane or two directionally ordered half lanes.
pub enum RawInputs<I: PacketIo> {
    /// One lane carries both bulk directions.
    Full(RawInput<I>),
    /// Both lanes are locally the same TLS role; bulk directions differ.
    Half {
        /// Client-to-server bulk lane zero.
        forward: RawInput<I>,
        /// Server-to-client bulk lane one.
        reverse: RawInput<I>,
    },
}
impl<I: PacketIo> RawInputs<I> {
    fn configs(&self) -> (Config, Option<Config>) {
        match self {
            Self::Full(a) => (a.config, None),
            Self::Half { forward, reverse } => (forward.config, Some(reverse.config)),
        }
    }
}
/// Immutable authenticated bounds for the entire setup and bootstrap lifetime.
#[derive(Clone, Copy, Debug)]
pub struct PairConfig {
    /// Native layer and caller's canonical base policy.
    pub session: SessionConfig,
    /// Existing symmetric exact-message and ciphertext lifetime bounds.
    pub messages: MessageLimits,
    /// Per-lane bounded raw driver policy.
    pub driver: SwitchLimits,
    /// Single factory-to-bootstrap deadline, exactly representable in microseconds.
    pub timeout: Duration,
}
/// Canonical physical lane; Second is rejected for full mode.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PairLane {
    /// Full or client-to-server bulk lane.
    First,
    /// Server-to-client bulk lane in half mode.
    Second,
}
impl PairLane {
    fn index(self) -> usize {
        match self {
            Self::First => 0,
            Self::Second => 1,
        }
    }
}
/// Checked charges for pair-controlled storage, not allocator/backend/PacketIo RSS.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResourceCharge {
    /// Maximum retained pair-controlled payload reservation.
    pub retained_payload: u64,
    /// Peak payload reservation including derivation/token scratch.
    pub peak_payload: u64,
    /// Conservative fixed metadata/future/descriptor reservation.
    pub metadata: u64,
}
/// Explicit first failure; ordinary local Busy/Payload/NoMessage remain recoverable.
#[derive(Clone, Debug)]
pub enum PairError {
    /// Invalid canonical policy, input shape, lane or duration.
    Configuration,
    /// Checked retained/peak resources or arithmetic exhausted.
    Capacity,
    /// Original absolute deadline expired.
    Expired,
    /// No current Tokio runtime; time enablement remains a documented precondition.
    Runtime,
    /// Existing exact-owner factory rejected its inputs.
    Start(StartError),
    /// Actual retained authentication failed; no secret bytes are included.
    Setup(std::sync::Arc<SetupFailure>),
    /// Actual owner, role, profile or lane identity differs.
    Identity,
    /// Malformed, wrong-phase or mismatching authenticated pair record.
    Protocol,
    /// Maintained randomness/exporter/HKDF failed.
    Keys,
    /// Original driver failed or exited unexpectedly.
    Driver {
        /// Standard category, retained from an actual error when present.
        kind: io::ErrorKind,
        /// Original optional syscall errno.
        raw_os_error: Option<i32>,
    },
    /// Exact-message operation failed.
    Message(MessageError),
    /// A completed setup was polled again.
    Completed,
}
impl fmt::Display for PairError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "raw pair: {self:?}")
    }
}
impl std::error::Error for PairError {}
/// Rejection before irreversible group attachment, with exact original inputs.
pub struct PairStartFailure<I: PacketIo> {
    /// Unpolled original inputs; boxing bounds the error representation.
    pub inputs: Box<RawInputs<I>>,
    /// Recoverable local rejection reason.
    pub error: PairError,
}
impl<I: PacketIo> fmt::Debug for PairStartFailure<I> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PairStartFailure")
            .field("error", &self.error)
            .finish_non_exhaustive()
    }
}
impl<I: PacketIo> fmt::Display for PairStartFailure<I> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.error.fmt(f)
    }
}
impl<I: PacketIo> std::error::Error for PairStartFailure<I> {}
/// Authenticated group metadata; no exported key or state-transfer authority.
#[derive(Clone, Debug)]
pub struct PairInfo {
    /// Actual physical-lane policy.
    pub duplex: Duplex,
    /// True for the original client factory.
    pub is_client: bool,
    /// Actual ordered session identities; absent second slot for full mode.
    pub lanes: [Option<SessionInfo>; 2],
    /// Canonical common configuration digest.
    pub profile: ConfigDigest,
    /// Canonical accepted group transcript digest.
    pub transcript_digest: [u8; 32],
}
/// Copied local accounting, never a transferable freeze proof.
#[derive(Clone, Debug)]
pub struct PairStatus {
    /// Original immutable absolute deadline.
    pub deadline: Instant,
    /// Exact original lane progress, including the pairing records.
    pub messages: [Option<MessageStatus>; 2],
    /// Original bridge progress; these are diagnostic snapshots only.
    pub bridges: [Option<SwitchStatus>; 2],
    /// Configured pair-controlled resource charges.
    pub resources: ResourceCharge,
    /// First terminal failure, if any.
    pub fault: Option<PairError>,
    /// Whether local pairing completed, not all-peer Armed or simultaneous knowledge.
    pub paired: bool,
}
/// Local destruction report. This never claims maintained clean TCP close.
pub struct PairAbortReport {
    /// Last actual group metadata, if pairing succeeded.
    pub info: Option<PairInfo>,
    /// Last progress before destruction of all original owners.
    pub status: PairStatus,
}
type Driver<I> = Pin<Box<dyn Future<Output = io::Result<super::SwitchExit<I>>> + Send>>;
struct Group<I: PacketIo + Send + 'static> {
    drivers: [Option<Driver<I>>; 2],
    owners: [Option<Box<TlsMessageOwner>>; 2],
    observers: [Option<super::stream::Shared>; 2],
    roots: [Option<Roots>; 2],
    keys: Option<Keys>,
    info: Option<PairInfo>,
    profile: Profile,
    deadline: Instant,
    timer: Pin<Box<Sleep>>,
    client: bool,
    cursor: usize,
    fault: Option<PairError>,
    messages: [Option<MessageStatus>; 2],
    bridges: [Option<SwitchStatus>; 2],
}
impl<I: PacketIo + Send + 'static> Group<I> {
    fn snapshot(&self) -> PairStatus {
        let mut messages = self.messages;
        let mut bridges = self.bridges;
        for i in 0..self.profile.count {
            if let Some(observer) = &self.observers[i] {
                bridges[i] = Some(match observer.lock() {
                    Ok(gate) => gate.status,
                    Err(_) => SwitchStatus {
                        state: super::SwitchState::Failed,
                        ..SwitchStatus::default()
                    },
                });
            }
            if let Some(owner) = &self.owners[i] {
                messages[i] = Some(owner.status());
                bridges[i] = Some(owner.bridge_status());
            }
        }
        PairStatus {
            deadline: self.deadline,
            messages,
            bridges,
            resources: self.profile.resources,
            fault: self.fault.clone(),
            paired: self.info.is_some(),
        }
    }
    fn release(&mut self) {
        self.messages = self.snapshot().messages;
        // No bridge lock is held while generic I/O destructors run. Driver Drop
        // publishes progress completed after its last ordinary publish/yield.
        self.owners = [None, None];
        self.drivers = [None, None];
        self.bridges = self.snapshot().bridges;
        self.observers = [None, None];
        self.roots = [None, None];
        self.keys = None;
    }
    fn fail(&mut self, error: PairError) -> PairError {
        let cause = self.fault.get_or_insert(error).clone();
        self.release();
        cause
    }
    fn live(&mut self) -> Result<(), PairError> {
        if let Some(error) = &self.fault {
            return Err(error.clone());
        }
        if Instant::now() >= self.deadline {
            return Err(self.fail(PairError::Expired));
        }
        Ok(())
    }
    fn pending(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), PairError>> {
        self.live()?;
        if self.timer.as_mut().poll(cx).is_ready() {
            return Poll::Ready(Err(self.fail(PairError::Expired)));
        }
        Poll::Pending
    }
    fn drive(&mut self, cx: &mut Context<'_>) -> Result<bool, PairError> {
        self.live()?;
        let before = self.snapshot().bridges;
        for offset in 0..self.profile.count {
            let i = (self.cursor + offset) % self.profile.count;
            self.live()?;
            let result = self.drivers[i]
                .as_mut()
                .ok_or(PairError::Identity)?
                .as_mut()
                .poll(cx);
            self.live()?;
            if let Poll::Ready(result) = result {
                let error = match result {
                    Err(e) => PairError::Driver {
                        kind: e.kind(),
                        raw_os_error: e.raw_os_error(),
                    },
                    Ok(_) => PairError::Driver {
                        kind: io::ErrorKind::UnexpectedEof,
                        raw_os_error: None,
                    },
                };
                return Err(self.fail(error));
            }
        }
        self.cursor = (self.cursor + 1) % self.profile.count;
        let after = self.snapshot().bridges;
        Ok(before.map(without_elapsed) != after.map(without_elapsed))
    }
    fn validate_owner(&self, i: usize, owner: &TlsMessageOwner) -> Result<(), PairError> {
        let info = owner.info();
        if owner.is_client() != self.client
            || info.config != self.profile.expected[i]
            || (if self.client {
                info.peer_member.is_some()
            } else {
                info.peer_member != Some(info.member)
            })
        {
            return Err(PairError::Identity);
        }
        Ok(())
    }
    fn transcript(&self, nonce: [u8; 32]) -> Result<[u8; TRANSCRIPT], PairError> {
        let first = self.owners[0].as_ref().ok_or(PairError::Identity)?;
        let info = first.info();
        for i in 0..self.profile.count {
            let owner = self.owners[i].as_ref().ok_or(PairError::Identity)?;
            self.validate_owner(i, owner)?;
            let lane = owner.info();
            if lane.member != info.member
                || lane.server != info.server
                || (i == 1 && (lane.session_id == info.session_id || first.same_bridge(owner)))
            {
                return Err(PairError::Identity);
            }
        }
        // This pure encoder grants no authority. Only the validations above
        // select the actual original observations passed into it.
        profile::transcript_bytes(
            &self.profile,
            nonce,
            std::array::from_fn(|i| self.owners[i].as_ref().map(|owner| *owner.info())),
        )
    }
    fn proposal(
        &mut self,
        fill: impl FnOnce(&mut [u8; 32]) -> Result<(), PairError>,
    ) -> Result<[u8; TRANSCRIPT], PairError> {
        self.live()?;
        let mut nonce = [0; 32];
        fill(&mut nonce)?;
        self.live()?;
        self.transcript(nonce)
    }
    fn complete(&mut self, transcript: [u8; TRANSCRIPT]) -> Result<(), PairError> {
        self.live()?;
        let mut hash = ring::digest::Context::new(&ring::digest::SHA256);
        hash.update(b"l2tunnel/raw-owned-pair-transcript/v1\0");
        hash.update(&transcript);
        let mut digest = [0; 32];
        digest.copy_from_slice(hash.finish().as_ref());
        let keys = Keys::derive(&self.roots, self.profile.count, digest)?;
        self.live()?;
        self.keys = Some(keys);
        self.roots = [None, None];
        self.info = Some(PairInfo {
            duplex: if self.profile.count == 1 {
                Duplex::Full
            } else {
                Duplex::Half
            },
            is_client: self.client,
            lanes: std::array::from_fn(|i| self.owners[i].as_ref().map(|o| *o.info())),
            profile: self.profile.digest,
            transcript_digest: digest,
        });
        self.live()
    }
}
fn without_elapsed(status: Option<SwitchStatus>) -> Option<SwitchStatus> {
    status.map(|mut status| {
        status.elapsed = Duration::ZERO;
        status
    })
}
/// Retains all original authentication/driver futures across borrowed cancellation.
/// Owning drop is terminal and destroys every lane; no worker is detached.
pub struct PairSetup<'a, I: PacketIo + Send + 'static> {
    group: Option<Group<I>>,
    setups: [Option<Setup<'a>>; 2],
    phase: u8,
    staged: [bool; 2],
    finished: [bool; 2],
    transcript: Option<[u8; TRANSCRIPT]>,
    done: bool,
}
impl<I: PacketIo + Send + 'static> PairSetup<'_, I> {
    /// Copied setup progress while the group remains owned.
    pub fn status(&self) -> Option<PairStatus> {
        self.group.as_ref().map(Group::snapshot)
    }
    fn fail(&mut self, error: PairError) -> Poll<Result<PairedRaw<I>, PairError>> {
        self.setups = [None, None];
        self.done = true;
        let cause = self.group.as_mut().map_or(error.clone(), |g| g.fail(error));
        Poll::Ready(Err(cause))
    }
    fn phase(&mut self, cx: &mut Context<'_>) -> Result<bool, PairError> {
        let group = self.group.as_mut().ok_or(PairError::Completed)?;
        let sending = if group.client {
            self.phase == 2
        } else {
            self.phase != 2
        };
        for offset in 0..group.profile.count {
            let i = (group.cursor + offset) % group.profile.count;
            if self.finished[i] {
                continue;
            }
            group.live()?;
            let owner = group.owners[i].as_mut().ok_or(PairError::Identity)?;
            if sending {
                if !self.staged[i] {
                    let transcript = self.transcript.ok_or(PairError::Protocol)?;
                    let record = encode(self.phase, i, &transcript);
                    owner.stage_message(&record).map_err(PairError::Message)?;
                    self.staged[i] = true;
                }
                if let Poll::Ready(result) = owner.poll_send(cx) {
                    result.map_err(PairError::Message)?;
                    self.finished[i] = true;
                }
            } else if let Poll::Ready(result) = owner.poll_receive(cx) {
                result.map_err(PairError::Message)?;
                let payload = owner.message().ok_or(PairError::Protocol)?;
                let candidate = decode(payload, self.phase, i)?;
                if self.phase == 1 {
                    let mut nonce = [0; 32];
                    nonce.copy_from_slice(&candidate[36..68]);
                    if group.transcript(nonce)? != candidate {
                        return Err(PairError::Protocol);
                    }
                }
                if let Some(old) = self.transcript {
                    if candidate != old {
                        return Err(PairError::Protocol);
                    }
                } else {
                    self.transcript = Some(candidate);
                }
                group.owners[i]
                    .as_mut()
                    .ok_or(PairError::Identity)?
                    .consume_message()
                    .map_err(PairError::Message)?;
                self.finished[i] = true;
            }
            group.live()?;
        }
        Ok(self.finished[..group.profile.count].iter().all(|v| *v))
    }
}
impl<I: PacketIo + Send + 'static> Future for PairSetup<'_, I> {
    type Output = Result<PairedRaw<I>, PairError>;
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        if this.done {
            return Poll::Ready(Err(PairError::Completed));
        }
        let result = (|| {
            let group = this.group.as_mut().ok_or(PairError::Completed)?;
            group.drive(cx)?;
            if this.phase == 0 {
                for offset in 0..group.profile.count {
                    let i = (group.cursor + offset) % group.profile.count;
                    group.live()?;
                    if let Some(setup) = this.setups[i].as_mut() {
                        match Pin::new(setup).poll(cx) {
                            Poll::Pending => {}
                            Poll::Ready(Err(e)) => {
                                return Err(PairError::Setup(std::sync::Arc::new(e)));
                            }
                            Poll::Ready(Ok(mut owner)) => {
                                group.validate_owner(i, &owner)?;
                                group.roots[i] = Some(owner.take_roots().ok_or(PairError::Keys)?);
                                group.owners[i] = Some(Box::new(owner));
                                this.setups[i] = None;
                            }
                        }
                    }
                    group.live()?;
                }
                if this.setups[..group.profile.count]
                    .iter()
                    .any(Option::is_some)
                {
                    return Ok(false);
                }
                // Validate all actual lane bindings before generating any challenge.
                group.transcript([0; 32])?;
                if !group.client {
                    this.transcript = Some(group.proposal(|nonce| {
                        SystemRandom::new().fill(nonce).map_err(|_| PairError::Keys)
                    })?);
                }
                this.phase = 1;
                cx.waker().wake_by_ref();
                return Ok(false);
            }
            if this.phase(cx)? {
                if this.phase == 3 {
                    let group = this.group.as_mut().ok_or(PairError::Completed)?;
                    group.complete(this.transcript.ok_or(PairError::Protocol)?)?;
                    return Ok(true);
                }
                this.phase += 1;
                this.staged = [false; 2];
                this.finished = [false; 2];
                cx.waker().wake_by_ref();
            }
            Ok(false)
        })();
        match result {
            Err(error) => this.fail(error),
            Ok(true) => {
                let Some(mut group) = this.group.take() else {
                    return this.fail(PairError::Completed);
                };
                if let Err(e) = group.live() {
                    this.group = Some(group);
                    return this.fail(e);
                }
                let Some(info) = group.info.clone() else {
                    this.group = Some(group);
                    return this.fail(PairError::Identity);
                };
                if let Err(e) = group.live() {
                    this.group = Some(group);
                    return this.fail(e);
                }
                this.done = true;
                Poll::Ready(Ok(PairedRaw { group, info }))
            }
            Ok(false) => match this
                .group
                .as_mut()
                .ok_or(PairError::Completed)
                .and_then(|g| match g.pending(cx) {
                    Poll::Ready(Err(e)) => Err(e),
                    _ => Ok(()),
                }) {
                Ok(()) => Poll::Pending,
                Err(e) => this.fail(e),
            },
        }
    }
}
fn encode(kind: u8, lane: usize, t: &[u8; TRANSCRIPT]) -> [u8; RECORD] {
    let mut out = [0; RECORD];
    out[..4].copy_from_slice(profile::PAIR_MAGIC);
    out[4..8].copy_from_slice(&[1, kind, lane as u8, 0]);
    out[8..].copy_from_slice(t);
    out
}
fn decode(bytes: &[u8], kind: u8, lane: usize) -> Result<[u8; TRANSCRIPT], PairError> {
    if bytes.len() != RECORD
        || &bytes[..4] != profile::PAIR_MAGIC
        || bytes[4..8] != [1, kind, lane as u8, 0]
    {
        return Err(PairError::Protocol);
    }
    let mut t = [0; TRANSCRIPT];
    t.copy_from_slice(&bytes[8..]);
    Ok(t)
}
/// Whole authenticated lane group, retained original drivers and private zeroizing keys.
/// Successful pairing does not grant Armed, Seal, native or physical handoff authority.
pub struct PairedRaw<I: PacketIo + Send + 'static> {
    group: Group<I>,
    info: PairInfo,
}
impl<I: PacketIo + Send + 'static> PairedRaw<I> {
    /// Actual accepted identities and canonical transcript, never key material.
    pub fn info(&self) -> &PairInfo {
        &self.info
    }
    /// Copied progress including any terminal first cause.
    pub fn status(&self) -> PairStatus {
        self.group.snapshot()
    }
    fn lane(&mut self, lane: PairLane) -> Result<usize, PairError> {
        self.group.live()?;
        let i = lane.index();
        if i >= self.group.profile.count {
            Err(PairError::Configuration)
        } else {
            Ok(i)
        }
    }
    fn message_result(&mut self, result: Result<(), MessageError>) -> Result<(), PairError> {
        match result {
            Ok(()) => Ok(()),
            Err(e @ (MessageError::Busy | MessageError::Payload | MessageError::NoMessage)) => {
                Err(PairError::Message(e))
            }
            Err(e) => Err(self.group.fail(PairError::Message(e))),
        }
    }
    /// Copy/reserve one ordinary bounded bootstrap message; no Seal recognition.
    pub fn stage_message(&mut self, lane: PairLane, payload: &[u8]) -> Result<(), PairError> {
        let i = self.lane(lane)?;
        let result = self.group.owners[i]
            .as_mut()
            .ok_or(PairError::Identity)?
            .stage_message(payload);
        self.message_result(result)
    }
    /// Fairly service every original driver and one write/read operation per lane.
    pub fn poll_progress(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), PairError>> {
        let result = (|| {
            let mut progress = self.group.drive(cx)?;
            for offset in 0..self.group.profile.count {
                let i = (self.group.cursor + offset) % self.group.profile.count;
                self.group.live()?;
                let owner = self.group.owners[i].as_mut().ok_or(PairError::Identity)?;
                let before = owner.status();
                if before.send_pending
                    && let Poll::Ready(result) = owner.poll_send(cx)
                {
                    result.map_err(PairError::Message)?;
                }
                self.group.live()?;
                let owner = self.group.owners[i].as_mut().ok_or(PairError::Identity)?;
                if owner.message().is_none()
                    && let Poll::Ready(result) = owner.poll_receive(cx)
                {
                    result.map_err(PairError::Message)?;
                }
                progress |= owner.status() != before;
                self.group.live()?;
            }
            Ok(progress)
        })();
        match result {
            Err(e) => Poll::Ready(Err(self.group.fail(e))),
            Ok(true) => Poll::Ready(Ok(())),
            Ok(false) => self.group.pending(cx),
        }
    }
    /// Borrow only a complete live message; no read or driver poll occurs.
    pub fn message(&self, lane: PairLane) -> Option<&[u8]> {
        if self.group.fault.is_some() || Instant::now() >= self.group.deadline {
            return None;
        }
        self.group.owners.get(lane.index())?.as_ref()?.message()
    }
    /// Release the exact completed delivery slot without reading more TLS input.
    pub fn consume_message(&mut self, lane: PairLane) -> Result<(), PairError> {
        let i = self.lane(lane)?;
        let result = self.group.owners[i]
            .as_mut()
            .ok_or(PairError::Identity)?
            .consume_message();
        self.message_result(result)
    }
    /// Synchronously drop all original owners. The report is not clean TCP closure.
    pub fn abort(mut self) -> PairAbortReport {
        self.group.release();
        PairAbortReport {
            info: self.group.info.clone(),
            status: self.group.snapshot(),
        }
    }
}
#[derive(Clone, Copy)]
enum Credentials<'a> {
    Client(&'a ClientTls, &'a str, &'a MemberKey),
    Server(&'a ServerTls, &'a MemberAllowlist),
}
fn future_size<A, F: Future>(_: impl FnOnce(A) -> F) -> usize {
    size_of::<F>()
}
const AUTH_METADATA: usize = 131_072;
fn metadata<I: PacketIo + Send + 'static>(count: usize, raw: Config) -> Result<u64, PairError> {
    // Conservative coexistence subtotal: concrete inline state (some repeated),
    // fixed boxed engine/socket/gate/timers, actual driver capture, and reserved
    // per-auth future metadata. Separately charged payload arrays may be repeated
    // here as part of an inline type, which deliberately overestimates the bound.
    let driver = future_size(|d: SwitchDriver<I>| d.run_owned_pair(Instant::now()));
    let fixed = size_of::<PairSetup<'static, I>>()
        .checked_add(size_of::<Group<I>>())
        .and_then(|n| n.checked_add(size_of::<PairedRaw<I>>()))
        .ok_or(PairError::Capacity)?;
    let engine = l2tunnel_raw_tcp::handoff::TrackedEngine::fixed_metadata_bytes()
        .ok_or(PairError::Capacity)?;
    let per = size_of::<PreparedBridge>()
        .checked_add(engine)
        .and_then(|n| n.checked_add(size_of::<super::stream::Gate>()))
        .and_then(|n| n.checked_add(4 * size_of::<Sleep>()))
        .and_then(|n| n.checked_add(size_of::<TlsMessageOwner>()))
        .and_then(|n| n.checked_add(driver))
        .and_then(|n| n.checked_add(AUTH_METADATA))
        .ok_or(PairError::Capacity)?;
    // Both deque descriptors, conservative capacity and old growth allocation.
    let descriptors = raw
        .packet_slots
        .max(4)
        .checked_mul(8)
        .and_then(|n| n.checked_mul(size_of::<Vec<u8>>()))
        .ok_or(PairError::Capacity)?;
    let total = per
        .checked_add(descriptors)
        .and_then(|n| n.checked_mul(count))
        .and_then(|n| n.checked_add(fixed))
        .ok_or(PairError::Capacity)?;
    let value = u64::try_from(total).map_err(|_| PairError::Capacity)?;
    if value > profile::METADATA {
        return Err(PairError::Capacity);
    }
    Ok(value)
}
fn build<'a, I: PacketIo + Send + 'static>(
    inputs: RawInputs<I>,
    credentials: Credentials<'a>,
    config: PairConfig,
) -> Result<PairSetup<'a, I>, PairStartFailure<I>> {
    let start = Instant::now();
    let prepared = (|| {
        tokio::runtime::Handle::try_current().map_err(|_| PairError::Runtime)?;
        if let Credentials::Client(_, name, _) = credentials
            && (name.is_empty() || name.len() > 253 || ServerName::try_from(name).is_err())
        {
            return Err(PairError::Start(StartError::VerificationName));
        }
        let mut profile = profile::validate(&inputs, config)?;
        let deadline = start
            .checked_add(config.timeout)
            .ok_or(PairError::Expired)?;
        let (first, second) = inputs.configs();
        profile.resources.metadata = metadata::<I>(profile.count, first)?;
        let role = if matches!(credentials, Credentials::Client(..)) {
            Role::Client
        } else {
            Role::Server
        };
        let a = PreparedBridge::new(first, role, config.driver)
            .map_err(|_| PairError::Configuration)?;
        let b = second
            .map(|raw| PreparedBridge::new(raw, role, config.driver))
            .transpose()
            .map_err(|_| PairError::Configuration)?;
        if Instant::now() >= deadline {
            return Err(PairError::Expired);
        }
        Ok((profile, deadline, a, b))
    })();
    let (profile, deadline, a, b) = match prepared {
        Ok(v) => v,
        Err(error) => {
            return Err(PairStartFailure {
                inputs: Box::new(inputs),
                error,
            });
        }
    };
    // All fallible local preparation above retains the original inputs untouched.
    // The first attach below is irreversible even before the first outer poll.
    let attached = match (inputs, b) {
        (RawInputs::Full(input), None) => [Some(a.attach(input.io)), None],
        (RawInputs::Half { forward, reverse }, Some(b)) => {
            [Some(a.attach(forward.io)), Some(b.attach(reverse.io))]
        }
        (inputs, _) => {
            return Err(PairStartFailure {
                inputs: Box::new(inputs),
                error: PairError::Configuration,
            });
        }
    };
    let mut group = Group {
        drivers: [None, None],
        owners: [None, None],
        observers: [None, None],
        roots: [None, None],
        keys: None,
        info: None,
        profile,
        deadline,
        timer: Box::pin(tokio::time::sleep_until(deadline)),
        client: matches!(credentials, Credentials::Client(..)),
        cursor: 0,
        fault: None,
        messages: [None, None],
        bridges: [None, None],
    };
    let mut setups = [None, None];
    for (i, attached) in attached.into_iter().enumerate() {
        let Some((stream, handle, driver)) = attached else {
            continue;
        };
        // Read-only internal observer: no cloned SwitchHandle or public gate access.
        group.observers[i] = Some(handle.shared.clone());
        group.drivers[i] = Some(Box::pin(driver.run_owned_pair(deadline)));
        let result = match credentials {
            Credentials::Client(tls, name, member) => tls_owner::client_setup(
                stream,
                handle,
                tls,
                name,
                member,
                group.profile.bases[i],
                config.messages,
                config.timeout,
                start,
                Some(i as u32),
            ),
            Credentials::Server(tls, allowed) => tls_owner::server_setup(
                stream,
                handle,
                tls,
                allowed,
                group.profile.bases[i],
                config.messages,
                config.timeout,
                start,
                Some(i as u32),
            ),
        };
        match result {
            Ok(setup) => {
                if setup.metadata_bytes().is_none_or(|n| n > AUTH_METADATA) {
                    group.fault = Some(PairError::Capacity);
                }
                setups[i] = Some(setup);
            }
            Err(e) => {
                group.fault = Some(PairError::Start(e.error));
            }
        }
    }
    if let Some(error) = group.fault.clone() {
        group.fail(error);
        setups = [None, None];
    }
    Ok(PairSetup {
        group: Some(group),
        setups,
        phase: 0,
        staged: [false; 2],
        finished: [false; 2],
        transcript: None,
        done: false,
    })
}
/// Construct all original client raw bridges, actual TLS/member owners and drivers.
/// Local pre-attachment failure returns the exact inputs; all later failure is terminal.
///
/// # Panics
/// The current Tokio runtime must have its time driver enabled, as required by
/// the existing TLS authentication adapter. Peer input never selects that runtime.
pub fn begin_pair_client<'a, I: PacketIo + Send + 'static>(
    inputs: RawInputs<I>,
    tls: &'a ClientTls,
    verification_name: &'a str,
    member: &'a MemberKey,
    config: PairConfig,
) -> Result<PairSetup<'a, I>, PairStartFailure<I>> {
    build(
        inputs,
        Credentials::Client(tls, verification_name, member),
        config,
    )
}
/// Construct all original server raw bridges and bounded allowlisted TLS owners.
///
/// # Panics
/// Requires the same timer-enabled Tokio runtime as `begin_pair_client`.
pub fn begin_pair_server<'a, I: PacketIo + Send + 'static>(
    inputs: RawInputs<I>,
    tls: &'a ServerTls,
    allowed: &'a MemberAllowlist,
    config: PairConfig,
) -> Result<PairSetup<'a, I>, PairStartFailure<I>> {
    build(inputs, Credentials::Server(tls, allowed), config)
}

#[cfg(test)]
#[path = "pairing_test_support.rs"]
mod test_support;
#[cfg(test)]
#[path = "pairing_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "pairing_profile_tests.rs"]
mod profile_tests;

#[cfg(test)]
#[path = "pairing_fault_tests.rs"]
mod fault_tests;

#[cfg(test)]
#[path = "pairing_review_tests.rs"]
mod review_tests;
