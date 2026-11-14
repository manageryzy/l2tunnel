//! Actual maintained-Noise fresh exchange and opaque consuming record handoff.
use super::{
    Binding, Config, Entropy, FlightKind, Handshake, LocalSecret, PeerKey, Profile, Psk,
    ReadOutcome, Role, SessionBinding, Time,
};
use l2tunnel_security::{self as security, ConfigDigest, Epoch, LaneId, Limits, Protection};
pub use sec::{KeyEpoch, Selection, SelectionSpec};
use security::refresh::{self as sec, Admission, Context, Tick};
use std::fmt;
use zeroize::Zeroizing;

pub(super) enum Construction<'a> {
    Legacy,
    Initial(Selection),
    Exchange(&'a [u8; 417]),
}
#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) enum FinishKind {
    Legacy,
    Initial,
    Exchange,
}
pub(super) struct InitialSetup {
    pub(super) selection: Selection,
    pub(super) pins: [[u8; 32]; 2],
    pub(super) psk: Option<Zeroizing<[u8; 32]>>,
    pub(super) prologue_hash: [u8; 32],
}
/// Bounded fresh-handshake failure without secret/provider strings.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// Actual supplied own/peer key or PSK does not match old authenticated trust.
    Credentials,
    /// The existing maintained handshake rejected this operation.
    Handshake(super::Error),
    /// The actual security owner rejected context, time, capacity or phase.
    Security(sec::Error),
}
impl From<super::Error> for Error {
    fn from(value: super::Error) -> Self {
        Self::Handshake(value)
    }
}
impl From<sec::Error> for Error {
    fn from(value: sec::Error) -> Self {
        Self::Security(value)
    }
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Noise refresh: {self:?}")
    }
}
impl std::error::Error for Error {}

/// Real initial Noise completion, not an established-member flag.
pub struct InitialEstablished {
    /// Opaque initial key and actual trust custody.
    pub initial: ConfirmedInitial,
    /// Exact original initial final-flight ciphertext through its original cap.
    pub confirmation: super::ConfirmationCache,
}
/// Initial actual Noise proof. No public constructor, root getter or clone.
pub struct ConfirmedInitial {
    inner: sec::Initial,
}
fn binding(context: Context) -> Binding {
    Binding {
        session: context.binding.session,
        configuration: context.configuration,
        carrier: context.carrier,
        outer: context.outer,
        member: context.member,
    }
}
impl ConfirmedInitial {
    /// Actual original session/transcript observation.
    pub fn binding(&self) -> SessionBinding {
        self.inner.context().binding
    }
    /// Actual public prologue observation; copying does not recreate this owner.
    pub fn authenticated(&self) -> Binding {
        binding(self.inner.context())
    }
    /// Actual global role.
    pub fn role(&self) -> Role {
        self.inner.role()
    }
    /// Actual pins in global order.
    pub fn pins(&self) -> (PeerKey, PeerKey) {
        let p = self.inner.context().pins;
        (PeerKey(p[0]), PeerKey(p[1]))
    }
    /// Actual checked selection.
    pub fn selection(&self) -> Selection {
        self.inner.selection()
    }
    /// Consume into the only managed initial Joining pair.
    pub fn joining(
        self,
        limits: Limits,
        now: Time,
        original_deadline: Time,
    ) -> Result<InitialJoining, Error> {
        Ok(InitialJoining {
            inner: self
                .inner
                .joining(limits, Tick(now.0), Tick(original_deadline.0))?,
        })
    }
    /// Public safe cross-crate consumption, never a raw-root/material getter.
    #[allow(clippy::too_many_arguments)]
    pub fn install(
        self,
        lane: LaneId,
        limits: Limits,
        protection: Protection,
        control_epoch: Epoch,
        control_digest: ConfigDigest,
        now: Time,
        session_expires: Time,
    ) -> Result<sec::Owners, sec::Error> {
        self.inner.install(
            lane,
            limits,
            protection,
            control_epoch,
            control_digest,
            Tick(now.0),
            Tick(session_expires.0),
        )
    }
}
/// Actual managed initial Joining owners; crypto retirement is not membership.
pub struct InitialJoining {
    inner: sec::Joining,
}
impl InitialJoining {
    /// Actual initial session/transcript.
    pub fn binding(&self) -> SessionBinding {
        self.inner.context().binding
    }
    /// Actual signed-context input, without authentication authority by itself.
    pub fn authenticated(&self) -> Binding {
        binding(self.inner.context())
    }
    /// Actual local role.
    pub fn role(&self) -> Role {
        self.inner.role()
    }
    /// Actual pinned peers in global order.
    pub fn pins(&self) -> (PeerKey, PeerKey) {
        let p = self.inner.context().pins;
        (PeerKey(p[0]), PeerKey(p[1]))
    }
    /// Checked immutable selection.
    pub fn selection(&self) -> Selection {
        self.inner.selection()
    }
    /// One initial-v1 AEAD Joining record, no cover/route wrapper included.
    pub fn seal(
        &mut self,
        now: Time,
        body: &[u8],
        out: &mut [u8],
    ) -> Result<security::Sealed, Error> {
        Ok(self.inner.seal(Tick(now.0), body, out)?)
    }
    /// Authenticate peer record number zero; signature/acceptance stays external.
    pub fn open(
        &mut self,
        now: Time,
        input: &[u8],
        out: &mut [u8],
    ) -> Result<security::Opened, Error> {
        Ok(self.inner.open(Tick(now.0), input, out)?)
    }
    /// Exact ciphertext retry without another sealing opportunity.
    pub fn retransmit(&mut self, now: Time, out: &mut [u8]) -> Result<usize, Error> {
        Ok(self.inner.retransmit(Tick(now.0), out)?)
    }
    /// Consume/drop both actual owners; tombstones remain and no member flag is minted.
    pub fn retire(self, now: Time) -> Result<ConfirmedInitial, Error> {
        Ok(ConfirmedInitial {
            inner: self.inner.retire(Tick(now.0))?,
        })
    }
}

impl Handshake {
    /// Authenticate explicit v2 selection in the actual initial Noise prologue.
    #[allow(clippy::too_many_arguments)]
    pub fn new_refreshable(
        config: Config,
        selection: Selection,
        local: LocalSecret,
        peer: PeerKey,
        psk: Option<Psk>,
        now: Time,
        entropy: &mut impl Entropy,
    ) -> Result<Self, super::Error> {
        Self::construct(
            config,
            local,
            peer,
            psk,
            now,
            entropy,
            Construction::Initial(selection),
        )
    }
    /// Consume a real selected initial proof; never release a generic root.
    pub fn finish_refreshable_with_confirmation(
        mut self,
        now: Time,
    ) -> Result<InitialEstablished, Error> {
        if self.finish_kind != FinishKind::Initial {
            return Err(super::Error::State.into());
        }
        let setup = self.refresh_setup.take().ok_or(super::Error::State)?;
        let (forward, reverse, confirmation) = self.take_finished(now)?;
        let context = Context {
            binding: SessionBinding {
                session: self.config.binding.session,
                transcript: self.transcript,
            },
            configuration: self.config.binding.configuration,
            carrier: self.config.binding.carrier,
            outer: self.config.binding.outer,
            member: self.config.binding.member,
            pins: setup.pins,
            profile: if self.config.profile == Profile::Ik {
                1
            } else {
                2
            },
        };
        let inner = sec::Initial::from_split_keys(
            forward,
            reverse,
            context,
            setup.selection,
            self.config.role,
            Tick(now.0),
            Tick(self.config.deadline.0),
            setup.psk,
            setup.prologue_hash,
        )?;
        Ok(InitialEstablished {
            initial: ConfirmedInitial { inner },
            confirmation,
        })
    }
}

/// Complete refresh header plus a fixed unchanged Noise flight.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Flight {
    /// Actual logical Noise kind.
    pub kind: FlightKind,
    /// Complete 72-byte header plus Noise length.
    pub bytes: usize,
}
fn index(kind: FlightKind) -> usize {
    match kind {
        FlightKind::Initiation => 0,
        FlightKind::Response => 1,
        FlightKind::Confirmation => 2,
    }
}
fn tag(kind: FlightKind) -> u8 {
    (index(kind) + 1) as u8
}
fn decode_kind(value: u8) -> Result<FlightKind, Error> {
    match value {
        1 => Ok(FlightKind::Initiation),
        2 => Ok(FlightKind::Response),
        3 => Ok(FlightKind::Confirmation),
        _ => Err(sec::Error::Context.into()),
    }
}

/// One admitted actual fresh Noise operation with immutable context and copy caps.
pub struct Exchange {
    inner: Handshake,
    admission: Option<Admission>,
    copies: [u32; 3],
    maximum: u32,
}
impl Exchange {
    /// Check exact old trust/PSK before consuming fresh entropy or emitting a flight.
    pub fn new(
        admission: Admission,
        local: LocalSecret,
        peer: PeerKey,
        psk: Option<Psk>,
        now: Time,
        entropy: &mut impl Entropy,
    ) -> Result<Self, Error> {
        if now.0 < admission.admitted().0 {
            return Err(sec::Error::TimeRegression.into());
        }
        if now.0 >= admission.deadline().0 {
            return Err(sec::Error::Deadline.into());
        }
        admission
            .check_credentials(local.public_key().0, peer.0, psk.as_ref().map(|p| &p.0[..]))
            .map_err(|_| Error::Credentials)?;
        let context = admission.context();
        let canonical = admission.canonical_context();
        let config = Config {
            role: admission.role(),
            profile: if context.profile == 1 {
                Profile::Ik
            } else {
                Profile::IkPsk2
            },
            binding: binding(context),
            deadline: Time(admission.deadline().0),
        };
        let maximum = admission.selection().spec().max_flight_copies;
        let inner = Handshake::construct(
            config,
            local,
            peer,
            psk,
            now,
            entropy,
            Construction::Exchange(&canonical),
        )?;
        Ok(Self {
            inner,
            admission: Some(admission),
            copies: [0; 3],
            maximum,
        })
    }
    /// Original local absolute cap.
    pub fn deadline(&self) -> Time {
        self.inner.deadline()
    }
    /// Observe completion without granting key-install authority.
    pub fn is_complete(&self) -> bool {
        self.inner.is_complete()
    }
    /// Next actual new Noise flight.
    pub fn next_flight(&self) -> Option<FlightKind> {
        self.inner.next_flight()
    }
    /// Emit one new fixed flight. All header/output checks precede encryption.
    pub fn write(&mut self, now: Time, out: &mut [u8]) -> Result<Flight, Error> {
        self.inner.check(now)?;
        let kind = self.inner.next_flight().ok_or(super::Error::State)?;
        let length = 72 + kind.size();
        if out.len() < length {
            return Err(super::Error::OutputTooSmall.into());
        }
        let i = index(kind);
        if self.copies[i] >= self.maximum {
            return Err(sec::Error::CopiesExhausted.into());
        }
        let header = self
            .admission
            .as_ref()
            .ok_or(super::Error::State)?
            .header(*b"L2RH", tag(kind));
        self.inner.write(now, &mut out[72..length])?;
        out[..72].copy_from_slice(&header);
        self.copies[i] += 1;
        Ok(Flight {
            kind,
            bytes: length,
        })
    }
    /// Strictly admit only the current exact context before maintained Noise processing.
    pub fn read(&mut self, now: Time, input: &[u8]) -> Result<ReadOutcome, Error> {
        self.inner.check(now)?;
        let prefix = input.get(..72).ok_or(super::Error::Length)?;
        let kind = decode_kind(prefix[5])?;
        let expected = self
            .admission
            .as_ref()
            .ok_or(super::Error::State)?
            .header(*b"L2RH", tag(kind));
        if prefix != expected || input.len() != 72 + kind.size() {
            return Err(sec::Error::Context.into());
        }
        Ok(self.inner.read(now, kind, &input[72..])?)
    }
    /// Copy exact saved ciphertext; retries never encrypt again or renew the cap.
    pub fn retransmit(
        &mut self,
        now: Time,
        kind: FlightKind,
        out: &mut [u8],
    ) -> Result<Flight, Error> {
        self.inner.check(now)?;
        let length = 72 + kind.size();
        if out.len() < length {
            return Err(super::Error::OutputTooSmall.into());
        }
        let i = index(kind);
        if self.copies[i] >= self.maximum {
            return Err(sec::Error::CopiesExhausted.into());
        }
        let header = self
            .admission
            .as_ref()
            .ok_or(super::Error::State)?
            .header(*b"L2RH", tag(kind));
        self.inner.retransmit(now, kind, &mut out[72..length])?;
        out[..72].copy_from_slice(&header);
        self.copies[i] += 1;
        Ok(Flight {
            kind,
            bytes: length,
        })
    }
    /// Only real mutual confirmation can produce this private-constructor proof.
    pub fn finish_with_confirmation(mut self, now: Time) -> Result<Completed, Error> {
        let admission = self.admission.take().ok_or(super::Error::State)?;
        let header = admission.header(*b"L2RH", 3);
        let (forward, reverse, inner) = self.inner.take_finished(now)?;
        let material = sec::Material::from_split_keys(
            admission,
            forward,
            reverse,
            self.inner.transcript,
            Tick(now.0),
        )?;
        Ok(Completed {
            material: AuthenticatedRefresh { inner: material },
            confirmation: ConfirmationCache {
                inner,
                header,
                copies: self.copies[2],
                maximum: self.maximum,
            },
        })
    }
}
/// Actual fresh proof plus exact final-flight custody after material handoff.
pub struct Completed {
    /// Opaque real fresh proof, never a generic zero-based root.
    pub material: AuthenticatedRefresh,
    /// Exact final ciphertext to complete an asymmetric peer.
    pub confirmation: ConfirmationCache,
}
/// Not constructible from security imports, public Info or copied metadata.
pub struct AuthenticatedRefresh {
    inner: sec::Material,
}
impl AuthenticatedRefresh {
    /// Safe public consuming bridge; actual keys stay in opaque security backing.
    pub fn prepare_into(
        self,
        owners: &mut sec::Owners,
        now: Time,
    ) -> Result<sec::Prepared, sec::Error> {
        self.inner.prepare_into(owners, Tick(now.0))
    }
}
/// Bounded exact refresh confirmation; contains no secret key or cipher owner.
pub struct ConfirmationCache {
    inner: super::ConfirmationCache,
    header: [u8; 72],
    copies: u32,
    maximum: u32,
}
impl ConfirmationCache {
    /// Original accepted cap; retry cannot change it.
    pub fn deadline(&self) -> Time {
        self.inner.deadline()
    }
    /// Copy header and original ciphertext, preserving copy usage across handoff.
    pub fn retransmit(&mut self, now: Time, out: &mut [u8]) -> Result<Flight, Error> {
        if now < self.inner.now || now >= self.inner.deadline || self.inner.retired {
            self.inner.retransmit(now, &mut [0; 73])?;
            return Err(super::Error::State.into());
        }
        if out.len() < 145 {
            return Err(super::Error::OutputTooSmall.into());
        }
        if self.copies >= self.maximum {
            return Err(sec::Error::CopiesExhausted.into());
        }
        self.inner.retransmit(now, &mut out[72..145])?;
        out[..72].copy_from_slice(&self.header);
        self.copies += 1;
        Ok(Flight {
            kind: FlightKind::Confirmation,
            bytes: 145,
        })
    }
}

#[cfg(test)]
#[path = "refresh_tests.rs"]
mod tests;
