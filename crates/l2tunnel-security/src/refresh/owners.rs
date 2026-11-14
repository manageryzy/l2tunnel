use super::authority::header;
use super::{
    Admission, Context, Error, Initial, KeyEpoch, Material, PREFIX_BYTES, Request, Selection, Tick,
    add,
};
use crate::{
    ConfigDigest, Direction, KeyGeneration, Metadata, PacketNumber, Protection, Role,
    keys::{self, Chain, Key, Labels, Opening},
    record,
    replay::Replay,
};
use ring::hkdf;
use zeroize::Zeroizing;

/// The two existing purposes, each with its own continuing counter and replay owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Class {
    /// Opaque user records and ordinary feedback.
    Data,
    /// Fixed authenticated management.
    Management,
}
impl Class {
    fn index(self) -> usize {
        match self {
            Self::Data => 0,
            Self::Management => 1,
        }
    }
    fn purpose(self) -> u8 {
        match self {
            Self::Data => 1,
            Self::Management => 2,
        }
    }
}
/// Successful protected output with its explicit authenticated key selector.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Sealed {
    /// Existing global packet identity and protected length.
    pub record: crate::Sealed,
    /// Actual fresh-DH selector.
    pub key_epoch: KeyEpoch,
    /// Immutable actual directional ratchet base.
    pub ratchet_base: PacketNumber,
}
/// Successful authenticated output, never an authority constructor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Opened {
    /// Existing global packet identity and plaintext length.
    pub record: crate::Opened,
    /// Actual authenticated fresh-DH selector.
    pub key_epoch: KeyEpoch,
    /// Actual authenticated directional base.
    pub ratchet_base: PacketNumber,
}
/// Unique local admission and immutable request.
pub struct Started {
    /// Actual old-authority admission.
    pub admission: Admission,
    /// Exact request to protect.
    pub request: Request,
}
/// Exact authenticated request outcome; duplicate never grants another exchange.
#[allow(clippy::large_enum_variant)] // Transfer one bounded authority without allocating after admission.
pub enum RequestOutcome {
    /// First admitted request.
    New(Admission),
    /// Exact live duplicate.
    Duplicate,
}
/// Non-cloneable permission to activate the exact already-prepared target.
pub struct Prepared {
    target: KeyEpoch,
    context: [u8; 32],
    cap: Tick,
}
/// Public activation observation; constructing a copy cannot authenticate a peer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Activation {
    /// Actual activated target.
    pub target: KeyEpoch,
    /// Actual local bases in Data/Management order.
    pub bases: [PacketNumber; 2],
    /// Original fixed overlap deadline.
    pub overlap_until: Tick,
}
/// Authenticated activation outcome.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ActivationOutcome {
    /// First actual new-key activation.
    Accepted,
    /// Exact semantic duplicate, with a fresh packet number.
    Duplicate,
}

struct Sending {
    chain: Chain,
    key: Key,
    used: u64,
    base: u64,
}
impl Sending {
    fn new(seed: Zeroizing<[u8; 32]>, protection: Protection) -> Result<Self, Error> {
        let chain = Chain::new(seed, Labels::RefreshV2);
        let key = chain.key(protection)?;
        Ok(Self {
            chain,
            key,
            used: 0,
            base: 0,
        })
    }
}
struct Receiving {
    opening: Option<Opening>,
    base: Option<u64>,
}
struct KeySet {
    epoch: KeyEpoch,
    transcript: [u8; 32],
    digest: [u8; 32],
    born: Tick,
    expires: Tick,
    send: Option<[Sending; 2]>,
    receive: [Receiving; 2],
}
impl KeySet {
    #[allow(clippy::too_many_arguments)]
    fn new(
        seed: Zeroizing<[u8; 32]>,
        context: Context,
        selection: Selection,
        role: Role,
        parent: KeyEpoch,
        epoch: KeyEpoch,
        transcript: [u8; 32],
        born: Tick,
    ) -> Result<Self, Error> {
        let s = selection.spec();
        let domain = |class: Class, direction: Direction| -> Result<Zeroizing<[u8; 32]>, Error> {
            Ok(keys::expand(
                &hkdf::Prk::new_less_safe(hkdf::HKDF_SHA256, &seed[..]),
                &[
                    b"l2tunnel/packet/v2/domain\0",
                    &[s.protection as u8, class.purpose(), direction as u8],
                    &s.lane.0.to_be_bytes(),
                ],
            )?)
        };
        let receive = |class| -> Result<Receiving, Error> {
            Ok(Receiving {
                opening: Some(Opening::new(
                    Chain::new(domain(class, role.receiving())?, Labels::RefreshV2),
                    s.protection,
                )?),
                base: (epoch.0 == 0).then_some(0),
            })
        };
        Ok(Self {
            epoch,
            transcript,
            digest: context.digest(selection, parent, epoch),
            born,
            expires: add(born, s.key_micros)?,
            send: Some([
                Sending::new(domain(Class::Data, role.sending())?, s.protection)?,
                Sending::new(domain(Class::Management, role.sending())?, s.protection)?,
            ]),
            receive: [receive(Class::Data)?, receive(Class::Management)?],
        })
    }
}
#[derive(Clone, Copy, Eq, PartialEq)]
enum Phase {
    Requested,
    Prepared,
    Activated,
}
struct Pending {
    parent: KeyEpoch,
    target: KeyEpoch,
    cap: Tick,
    request: [u8; 72],
    phase: Phase,
    overlap: Option<Tick>,
    peer: Option<[u64; 2]>,
    emitted: bool,
}

/// Actual four-purpose-direction backing, with exactly one global counter/replay
/// owner per local domain across the bounded old/new key slots.
pub struct Owners {
    context: Context,
    selection: Selection,
    role: Role,
    psk: Option<Zeroizing<[u8; 32]>>,
    prologue_hash: [u8; 32],
    current: KeySet,
    additional: Option<KeySet>,
    next: [u64; 2],
    replay: [Replay; 2],
    high: KeyEpoch,
    pending: Option<Pending>,
    now: Tick,
    expires: Tick,
    failed: bool,
    mac_input: Vec<u8>,
}

struct Aad {
    bytes: [u8; 474],
    len: usize,
}
impl Aad {
    fn new(
        context: Context,
        selection: Selection,
        role_direction: Direction,
        class: Class,
        slot: &KeySet,
        prefix: &[u8],
        metadata: Metadata<'_>,
    ) -> Result<Self, Error> {
        metadata.validate()?;
        let s = selection.spec();
        let mut result = Self {
            bytes: [0; 474],
            len: 0,
        };
        for part in [
            b"l2tunnel/packet/v2/aad\0".as_slice(),
            &context.binding.session.0,
            &context.binding.transcript,
            &slot.epoch.0.to_be_bytes(),
            &slot.transcript,
            &slot.digest,
            &[s.protection as u8, class.purpose(), role_direction as u8],
            &s.lane.0.to_be_bytes(),
            prefix,
            &metadata.epoch.0.to_be_bytes(),
            &metadata.configuration.0,
            &(metadata.extra.len() as u16).to_be_bytes(),
            metadata.extra,
        ] {
            let end = result
                .len
                .checked_add(part.len())
                .ok_or(Error::Configuration)?;
            result
                .bytes
                .get_mut(result.len..end)
                .ok_or(Error::Configuration)?
                .copy_from_slice(part);
            result.len = end;
        }
        Ok(result)
    }
    fn bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}
// Private single-use authentication result. No public metadata value can create it.
struct Authenticated {
    additional: bool,
    class: Class,
    epoch: KeyEpoch,
    number: u64,
    base: u64,
    generation: KeyGeneration,
    used: u64,
    bytes: usize,
}

impl Owners {
    pub(super) fn initial(initial: Initial, now: Tick, expires: Tick) -> Result<Self, Error> {
        if now < initial.born {
            return Err(Error::TimeRegression);
        }
        if now >= expires {
            return Err(Error::Deadline);
        }
        if now >= add(initial.born, initial.selection.spec().key_micros)? {
            return Err(Error::KeyExpired);
        }
        let current = KeySet::new(
            initial.seed,
            initial.context,
            initial.selection,
            initial.role,
            KeyEpoch(0),
            KeyEpoch(0),
            initial.context.binding.transcript,
            initial.born,
        )?;
        let capacity = initial
            .selection
            .spec()
            .limits
            .max_body_bytes
            .checked_add(474)
            .ok_or(Error::Configuration)?;
        let mut mac_input = Vec::new();
        if initial.selection.spec().protection == Protection::HmacSha256 {
            mac_input
                .try_reserve_exact(capacity)
                .map_err(|_| Error::Allocation)?;
        }
        Ok(Self {
            context: initial.context,
            selection: initial.selection,
            role: initial.role,
            psk: initial.psk,
            prologue_hash: initial.prologue_hash,
            current,
            additional: None,
            next: [0; 2],
            replay: [Replay::new(), Replay::new()],
            high: KeyEpoch(0),
            pending: None,
            now,
            expires,
            failed: false,
            mac_input,
        })
    }
    /// Immutable initial verified context, not a proof constructor.
    pub const fn context(&self) -> Context {
        self.context
    }
    /// Immutable selection.
    pub const fn selection(&self) -> Selection {
        self.selection
    }
    /// Actual local sending key epoch.
    pub const fn key_epoch(&self) -> KeyEpoch {
        self.current.epoch
    }
    /// Observe the continuing counter without reserving it.
    pub fn next_number(&self, class: Class) -> PacketNumber {
        PacketNumber(self.next[class.index()])
    }
    /// Observe the one shared highest authenticated number.
    pub fn highest_number(&self, class: Class) -> Option<PacketNumber> {
        self.replay[class.index()].highest.map(PacketNumber)
    }
    /// Old/prepared selector, if retained.
    pub fn additional_epoch(&self) -> Option<KeyEpoch> {
        self.additional.as_ref().map(|slot| slot.epoch)
    }
    /// Check/latch original expiry before outer parsing/capacity work. This grants
    /// no packet or peer authority and does not renew a deadline.
    pub fn check_time(&mut self, now: Tick) -> Result<(), Error> {
        self.check(now)
    }
    fn check(&mut self, now: Tick) -> Result<(), Error> {
        if self.failed {
            return Err(Error::State);
        }
        let error = if now < self.now {
            Some(Error::TimeRegression)
        } else if now >= self.expires || self.pending.as_ref().is_some_and(|p| now >= p.cap) {
            Some(Error::Deadline)
        } else if now >= self.current.expires {
            Some(Error::KeyExpired)
        } else {
            None
        };
        if let Some(error) = error {
            self.failed = true;
            self.current.send = None;
            for receive in &mut self.current.receive {
                receive.opening = None;
            }
            self.additional = None;
            self.psk = None;
            return Err(error);
        }
        self.now = now;
        Ok(())
    }
    fn metadata(&self, route_class: u8) -> ([u8; 9], crate::Epoch, ConfigDigest) {
        let s = self.selection.spec();
        let mut route = [0; 9];
        route[0] = route_class;
        route[1..].copy_from_slice(&s.control_epoch.0.to_be_bytes());
        (route, s.control_epoch, s.control_digest)
    }
    fn validate_metadata(&self, class: Class, meta: Metadata<'_>) -> Result<(), Error> {
        meta.validate()?;
        let s = self.selection.spec();
        if class == Class::Management
            && (meta.epoch != s.control_epoch || meta.configuration != s.control_digest)
        {
            return Err(Error::Context);
        }
        Ok(())
    }
    fn admission(&self, p: &Pending) -> Admission {
        Admission {
            context: self.context,
            selection: self.selection,
            role: self.role,
            parent: p.parent,
            target: p.target,
            deadline: p.cap,
            admitted: self.now,
            psk: self.psk.as_ref().map(|v| Zeroizing::new(**v)),
            prologue_hash: self.prologue_hash,
        }
    }
    fn cap(&self, now: Tick, original: Tick) -> Result<Tick, Error> {
        let cap = original
            .min(self.expires)
            .min(self.current.expires)
            .min(add(now, self.selection.spec().exchange_micros)?);
        if now >= cap {
            return Err(Error::Deadline);
        }
        Ok(cap)
    }
    /// Mint actual local authority only for the original global initiator.
    pub fn begin_refresh(&mut self, now: Tick, original: Tick) -> Result<Started, Error> {
        self.check(now)?;
        if self.role != Role::Initiator {
            return Err(Error::Context);
        }
        if self.pending.is_some() || self.additional.is_some() {
            return Err(Error::Busy);
        }
        let target = KeyEpoch(
            self.high
                .0
                .checked_add(1)
                .filter(|v| *v < u64::MAX)
                .ok_or(Error::EpochExhausted)?,
        );
        let parent = self.current.epoch;
        let cap = self.cap(now, original)?;
        let request = header(self.context, self.selection, parent, target, *b"L2RQ", 1);
        let pending = Pending {
            parent,
            target,
            cap,
            request,
            phase: Phase::Requested,
            overlap: None,
            peer: None,
            emitted: false,
        };
        let mut admission = self.admission(&pending);
        admission.admitted = now;
        self.high = target;
        self.pending = Some(pending);
        self.now = now;
        Ok(Started {
            admission,
            request: Request(request),
        })
    }
    /// Protect the immutable local request under the current old Management keys.
    pub fn seal_request(
        &mut self,
        request: &Request,
        now: Tick,
        out: &mut [u8],
    ) -> Result<Sealed, Error> {
        self.check(now)?;
        let p = self.pending.as_ref().ok_or(Error::State)?;
        if p.phase == Phase::Activated || p.request != request.0 || self.role != Role::Initiator {
            return Err(Error::Context);
        }
        let (route, epoch, configuration) = self.metadata(4);
        self.seal(
            now,
            Class::Management,
            Metadata {
                epoch,
                configuration,
                extra: &route,
            },
            &request.0,
            out,
        )
    }
    /// Authenticate and admit one exact request atomically before replay commit.
    pub fn open_request(
        &mut self,
        now: Tick,
        original: Tick,
        packet: &[u8],
        out: &mut [u8],
    ) -> Result<RequestOutcome, Error> {
        self.check(now)?;
        if self.role != Role::Responder {
            return Err(Error::Context);
        }
        let (route, epoch, configuration) = self.metadata(4);
        let auth = self.authenticate(
            now,
            Class::Management,
            Metadata {
                epoch,
                configuration,
                extra: &route,
            },
            packet,
            out,
        )?;
        if auth.bytes != 72 {
            return Err(Error::Context);
        }
        let target = KeyEpoch(read(&out[32..40])?);
        let parent = KeyEpoch(read(&out[24..32])?);
        let expected = header(self.context, self.selection, parent, target, *b"L2RQ", 1);
        if out[..72] != expected || auth.epoch != parent {
            return Err(Error::Context);
        }
        if let Some(p) = &self.pending {
            if p.request != expected {
                return Err(Error::Conflict);
            }
            self.commit(auth)?;
            self.now = now;
            return Ok(RequestOutcome::Duplicate);
        }
        if self.additional.is_some() {
            return Err(Error::Busy);
        }
        if parent != self.current.epoch {
            return Err(Error::Context);
        }
        if target.0 <= self.high.0 {
            return Err(Error::Retired);
        }
        if target.0 == u64::MAX {
            return Err(Error::EpochExhausted);
        }
        let pending = Pending {
            parent,
            target,
            cap: self.cap(now, original)?,
            request: expected,
            phase: Phase::Requested,
            overlap: None,
            peer: None,
            emitted: false,
        };
        let mut admission = self.admission(&pending);
        admission.admitted = now;
        self.commit(auth)?;
        self.high = target;
        self.pending = Some(pending);
        self.now = now;
        Ok(RequestOutcome::New(admission))
    }
    pub(super) fn prepare(&mut self, material: Material, now: Tick) -> Result<Prepared, Error> {
        self.check(now)?;
        let p = self.pending.as_ref().ok_or(Error::State)?;
        if p.phase != Phase::Requested || self.additional.is_some() {
            return Err(Error::Busy);
        }
        let a = &material.admission;
        if a.context != self.context
            || a.selection != self.selection
            || a.role != self.role
            || a.parent != p.parent
            || a.target != p.target
            || a.deadline != p.cap
        {
            return Err(Error::Context);
        }
        if material.born > now {
            return Err(Error::TimeRegression);
        }
        if now >= add(material.born, self.selection.spec().key_micros)? {
            return Err(Error::KeyExpired);
        }
        let slot = KeySet::new(
            material.seed,
            self.context,
            self.selection,
            self.role,
            p.parent,
            p.target,
            material.transcript,
            material.born,
        )?;
        let prepared = Prepared {
            target: p.target,
            context: slot.digest,
            cap: p.cap,
        };
        self.additional = Some(slot);
        self.pending.as_mut().ok_or(Error::State)?.phase = Phase::Prepared;
        self.now = now;
        Ok(prepared)
    }
    /// Choose actual bases at activation, never at the request snapshot.
    pub fn activate_refresh(
        &mut self,
        prepared: &Prepared,
        now: Tick,
    ) -> Result<Activation, Error> {
        self.check(now)?;
        let p = self.pending.as_ref().ok_or(Error::State)?;
        if p.target != prepared.target || p.cap != prepared.cap {
            return Err(Error::Context);
        }
        if p.phase == Phase::Activated {
            let send = self.current.send.as_ref().ok_or(Error::State)?;
            return Ok(Activation {
                target: p.target,
                bases: [PacketNumber(send[0].base), PacketNumber(send[1].base)],
                overlap_until: p.overlap.ok_or(Error::State)?,
            });
        }
        if p.phase != Phase::Prepared {
            return Err(Error::State);
        }
        let overlap = add(now, self.selection.spec().overlap_micros)?;
        if overlap >= p.cap {
            return Err(Error::Deadline);
        }
        for next in self.next {
            next.checked_add(1).ok_or(crate::Error::CounterExhausted)?;
        }
        let mut new = self.additional.take().ok_or(Error::State)?;
        if new.epoch != prepared.target || new.digest != prepared.context {
            self.additional = Some(new);
            return Err(Error::Context);
        }
        let send = new.send.as_mut().ok_or(Error::State)?;
        send[0].base = self.next[0];
        send[1].base = self.next[1];
        self.current.send = None;
        let old = std::mem::replace(&mut self.current, new);
        self.additional = Some(old);
        let p = self.pending.as_mut().ok_or(Error::State)?;
        p.phase = Phase::Activated;
        p.overlap = Some(overlap);
        self.now = now;
        Ok(Activation {
            target: p.target,
            bases: self.next.map(PacketNumber),
            overlap_until: overlap,
        })
    }
    /// Emit actual new-key activation with both continuing bases.
    pub fn seal_activation(&mut self, now: Tick, out: &mut [u8]) -> Result<Sealed, Error> {
        self.check(now)?;
        let p = self.pending.as_ref().ok_or(Error::State)?;
        if p.phase != Phase::Activated {
            return Err(Error::State);
        }
        let mut body = [0; 88];
        body[..72].copy_from_slice(&header(
            self.context,
            self.selection,
            p.parent,
            p.target,
            *b"L2RQ",
            2,
        ));
        let send = self.current.send.as_ref().ok_or(Error::State)?;
        body[72..80].copy_from_slice(&send[0].base.to_be_bytes());
        body[80..88].copy_from_slice(&send[1].base.to_be_bytes());
        let (route, epoch, configuration) = self.metadata(4);
        let result = self.seal(
            now,
            Class::Management,
            Metadata {
                epoch,
                configuration,
                extra: &route,
            },
            &body,
            out,
        )?;
        self.pending.as_mut().ok_or(Error::State)?.emitted = true;
        Ok(result)
    }
    /// Only actual new-key authentication can record peer activation.
    pub fn open_activation(
        &mut self,
        now: Tick,
        packet: &[u8],
        out: &mut [u8],
    ) -> Result<ActivationOutcome, Error> {
        self.check(now)?;
        let (route, epoch, configuration) = self.metadata(4);
        let auth = self.authenticate(
            now,
            Class::Management,
            Metadata {
                epoch,
                configuration,
                extra: &route,
            },
            packet,
            out,
        )?;
        let p = self.pending.as_ref().ok_or(Error::State)?;
        if auth.bytes != 88
            || auth.epoch != p.target
            || p.phase == Phase::Requested
            || out[..72]
                != header(
                    self.context,
                    self.selection,
                    p.parent,
                    p.target,
                    *b"L2RQ",
                    2,
                )
        {
            return Err(Error::Context);
        }
        let bases = [read(&out[72..80])?, read(&out[80..88])?];
        if bases[1] != auth.base || bases.contains(&u64::MAX) {
            return Err(Error::Context);
        }
        let duplicate = p.peer.is_some();
        if p.peer.is_some_and(|old| old != bases) {
            return Err(Error::Conflict);
        }
        let slot = if auth.additional {
            self.additional.as_ref().ok_or(Error::State)?
        } else {
            &self.current
        };
        for (i, base) in bases.into_iter().enumerate() {
            if slot.receive[i].base.is_some_and(|old| old != base)
                || (slot.receive[i].base.is_none()
                    && self.replay[i]
                        .highest
                        .is_some_and(|highest| highest >= base))
            {
                return Err(Error::Context);
            }
        }
        let additional = auth.additional;
        self.commit(auth)?;
        let slot = if additional {
            self.additional.as_mut().ok_or(Error::State)?
        } else {
            &mut self.current
        };
        for (receive, base) in slot.receive.iter_mut().zip(bases) {
            receive.base = Some(base);
        }
        self.pending.as_mut().ok_or(Error::State)?.peer = Some(bases);
        self.now = now;
        Ok(if duplicate {
            ActivationOutcome::Duplicate
        } else {
            ActivationOutcome::Accepted
        })
    }
    /// Wipe the old receive context only after actual peer activation and overlap.
    pub fn retire_refresh(&mut self, target: KeyEpoch, now: Tick) -> Result<(), Error> {
        self.check(now)?;
        let p = self.pending.as_ref().ok_or(Error::State)?;
        if target != p.target {
            return Err(Error::Context);
        }
        if p.phase != Phase::Activated || p.peer.is_none() || !p.emitted {
            return Err(Error::State);
        }
        if now < p.overlap.ok_or(Error::State)? {
            return Err(Error::OverlapActive);
        }
        self.additional = None;
        self.pending = None;
        self.now = now;
        Ok(())
    }
    /// Abort only an exact unactivated attempt. Its selector stays burned.
    pub fn abort_refresh(&mut self, target: KeyEpoch, now: Tick) -> Result<(), Error> {
        self.check(now)?;
        let p = self.pending.as_ref().ok_or(Error::State)?;
        if target != p.target {
            return Err(Error::Context);
        }
        if p.phase == Phase::Activated
            || p.peer.is_some()
            || self
                .additional
                .as_ref()
                .is_some_and(|slot| slot.receive.iter().any(|receive| receive.base.is_some()))
        {
            return Err(Error::State);
        }
        self.additional = None;
        self.pending = None;
        self.now = now;
        Ok(())
    }
    /// Seal opaque bytes with the one continuing counter of the selected domain.
    pub fn seal(
        &mut self,
        now: Tick,
        class: Class,
        meta: Metadata<'_>,
        body: &[u8],
        out: &mut [u8],
    ) -> Result<Sealed, Error> {
        self.check(now)?;
        self.validate_metadata(class, meta)?;
        let s = self.selection.spec();
        let len = body
            .len()
            .checked_add(PREFIX_BYTES + s.protection.tag_bytes())
            .ok_or(crate::Error::TooLarge)?;
        if body.len() > s.limits.max_body_bytes || len > crate::MAX_PACKET_BYTES {
            return Err(crate::Error::TooLarge.into());
        }
        if out.len() < len {
            return Err(crate::Error::OutputTooSmall.into());
        }
        let i = class.index();
        let number = self.next[i];
        let next = number
            .checked_add(1)
            .ok_or(crate::Error::CounterExhausted)?;
        let send = &self.current.send.as_ref().ok_or(Error::State)?[i];
        let generation = KeyGeneration(
            number.checked_sub(send.base).ok_or(Error::Context)? / s.limits.packets_per_key,
        );
        let used = (if generation == send.chain.generation {
            send.used
        } else {
            0
        })
        .checked_add(body.len() as u64)
        .ok_or(crate::Error::KeyUsageExhausted)?;
        if used > s.limits.max_body_bytes_per_key {
            return Err(crate::Error::KeyUsageExhausted.into());
        }
        if generation != send.chain.generation
            && send.chain.generation.0.checked_add(1) != Some(generation.0)
        {
            return Err(crate::Error::Generation.into());
        }
        let base = send.base;
        let mut prefix = [0; PREFIX_BYTES];
        prefix[0] = 2;
        prefix[1] = s.protection as u8;
        prefix[2..10].copy_from_slice(&self.current.epoch.0.to_be_bytes());
        prefix[10..18].copy_from_slice(&base.to_be_bytes());
        prefix[18..].copy_from_slice(&number.to_be_bytes());
        let aad = Aad::new(
            self.context,
            self.selection,
            self.role.sending(),
            class,
            &self.current,
            &prefix,
            meta,
        )?;
        self.next[i] = next;
        let send = &mut self.current.send.as_mut().ok_or(Error::State)?[i];
        if generation != send.chain.generation {
            let chain = send.chain.next()?;
            let key = chain.key(s.protection)?;
            send.chain = chain;
            send.key = key;
        }
        send.used = used;
        out[..PREFIX_BYTES].copy_from_slice(&prefix);
        record::seal_key(
            &send.key,
            number,
            aad.bytes(),
            body,
            PREFIX_BYTES,
            &mut out[..len],
        )?;
        self.now = now;
        Ok(Sealed {
            record: crate::Sealed {
                number: PacketNumber(number),
                generation,
                bytes: len,
            },
            key_epoch: self.current.epoch,
            ratchet_base: PacketNumber(base),
        })
    }
    /// Authenticate opaque bytes; semantic request/activation methods use the same
    /// private candidate followed by their own atomic validation and commit.
    pub fn open(
        &mut self,
        now: Tick,
        class: Class,
        meta: Metadata<'_>,
        input: &[u8],
        out: &mut [u8],
    ) -> Result<Opened, Error> {
        self.check(now)?;
        let auth = self.authenticate(now, class, meta, input, out)?;
        let result = self.commit(auth)?;
        self.now = now;
        Ok(result)
    }
    fn authenticate(
        &mut self,
        now: Tick,
        class: Class,
        meta: Metadata<'_>,
        input: &[u8],
        out: &mut [u8],
    ) -> Result<Authenticated, Error> {
        self.validate_metadata(class, meta)?;
        let s = self.selection.spec();
        let overhead = PREFIX_BYTES + s.protection.tag_bytes();
        if input.len() < overhead || input.len() > crate::MAX_PACKET_BYTES {
            return Err(crate::Error::Malformed.into());
        }
        let bytes = input.len() - overhead;
        if bytes > s.limits.max_body_bytes {
            return Err(crate::Error::TooLarge.into());
        }
        if out.len() < input.len() - PREFIX_BYTES {
            return Err(crate::Error::OutputTooSmall.into());
        }
        if input[0] != 2 || input[1] != s.protection as u8 {
            return Err(Error::Context);
        }
        let epoch = KeyEpoch(read(&input[2..10])?);
        let base = read(&input[10..18])?;
        let number = read(&input[18..26])?;
        let i = class.index();
        if !self.replay[i].fresh(number) {
            return Err(crate::Error::Replay.into());
        }
        let additional = epoch != self.current.epoch;
        let slot = if additional {
            self.additional
                .as_ref()
                .filter(|slot| slot.epoch == epoch)
                .ok_or(Error::Retired)?
        } else {
            &self.current
        };
        if now >= slot.expires {
            return Err(Error::KeyExpired);
        }
        if now < slot.born {
            return Err(Error::TimeRegression);
        }
        if slot.receive[i].base.is_some_and(|old| old != base)
            || (slot.receive[i].base.is_none()
                && self.replay[i]
                    .highest
                    .is_some_and(|highest| highest >= base))
        {
            return Err(Error::Context);
        }
        // A prepared newer reader may already authenticate peer activation while
        // this endpoint still sends with the old current slot. The old-number
        // fence therefore follows key epochs, not current/additional placement.
        let newer_base = if epoch.0 < self.current.epoch.0 {
            self.current.receive[i].base
        } else {
            self.additional
                .as_ref()
                .filter(|newer| newer.epoch.0 > epoch.0)
                .and_then(|newer| newer.receive[i].base)
        };
        if newer_base.is_some_and(|new_base| number >= new_base) {
            return Err(Error::Context);
        }
        let generation = KeyGeneration(
            number.checked_sub(base).ok_or(Error::Context)? / s.limits.packets_per_key,
        );
        let aad = Aad::new(
            self.context,
            self.selection,
            self.role.receiving(),
            class,
            slot,
            &input[..PREFIX_BYTES],
            meta,
        )?;
        let slot = if additional {
            self.additional.as_mut().ok_or(Error::State)?
        } else {
            &mut self.current
        };
        let key = slot.receive[i]
            .opening
            .as_mut()
            .ok_or(Error::State)?
            .candidate(generation)?;
        let used = key
            .body_bytes
            .checked_add(bytes as u64)
            .ok_or(crate::Error::KeyUsageExhausted)?;
        if used > s.limits.max_body_bytes_per_key {
            return Err(crate::Error::KeyUsageExhausted.into());
        }
        record::open_key(
            &key.key,
            number,
            aad.bytes(),
            &input[PREFIX_BYTES..],
            bytes,
            out,
            &mut self.mac_input,
        )?;
        Ok(Authenticated {
            additional,
            class,
            epoch,
            number,
            base,
            generation,
            used,
            bytes,
        })
    }
    fn commit(&mut self, auth: Authenticated) -> Result<Opened, Error> {
        let i = auth.class.index();
        let slot = if auth.additional {
            self.additional.as_mut().ok_or(Error::State)?
        } else {
            &mut self.current
        };
        let receive = &mut slot.receive[i];
        let opening = receive.opening.as_mut().ok_or(Error::State)?;
        opening.candidate(auth.generation)?.body_bytes = auth.used;
        opening.confirm(auth.generation);
        receive.base = Some(auth.base);
        self.replay[i].commit(auth.number);
        let highest = self.replay[i]
            .highest
            .unwrap_or(auth.number)
            .saturating_sub(auth.base);
        opening.retire(highest, self.selection.spec().limits.packets_per_key);
        Ok(Opened {
            record: crate::Opened {
                number: PacketNumber(auth.number),
                generation: auth.generation,
                bytes: auth.bytes,
            },
            key_epoch: auth.epoch,
            ratchet_base: PacketNumber(auth.base),
        })
    }
}

fn read(bytes: &[u8]) -> Result<u64, Error> {
    Ok(u64::from_be_bytes(
        bytes.try_into().map_err(|_| Error::Context)?,
    ))
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
