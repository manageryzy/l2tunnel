//! Bounded fixed-pattern Noise handshake proof using public maintained APIs.
//!
//! This library owns no socket, clock, OS RNG, task, carrier or device. It is not
//! a complete WireGuard lifecycle or a replacement for existing member credentials.
//! Clatter 2.3.0 is unaudited; exact adaptations and remaining gates are recorded
//! in `docs/modules/noise-handshake.md`. Application data is never a handshake input.

mod crypto;

use clatter::bytearray::{ByteArray, SensitiveByteArray};
use clatter::crypto::cipher::ChaChaPoly;
use clatter::crypto::hash::Sha256;
use clatter::handshakepattern::{noise_ik, noise_ik_psk2};
use clatter::traits::{Dh, Handshaker};
use clatter::transportstate::TransportState;
use clatter::{KeyPair, NqHandshakeCore};
use crypto::{CheckedX25519, UnavailableRandom};
pub use l2tunnel_security::{Role, SessionId};
use l2tunnel_security::{SessionBinding, SessionRoot};
use std::fmt;
use zeroize::{Zeroize, Zeroizing};

/// Maximum opaque flight size for the fixed empty-payload handshake.
pub const MAX_FLIGHT_BYTES: usize = 96;
const INITIATION_BYTES: usize = 96;
const RESPONSE_BYTES: usize = 48;
const CONFIRM_DOMAIN: &[u8; 8] = b"L2NCONF\0";
const CONFIRM_BODY: usize = 8 + 1 + 16 + 32;
const CONFIRM_BYTES: usize = CONFIRM_BODY + 16;
const PROLOGUE_DOMAIN: &[u8] = b"l2tunnel/noise-proof/v1\0";

type Noise = NqHandshakeCore<CheckedX25519, ChaChaPoly, Sha256, UnavailableRandom>;
type Transport = TransportState<ChaChaPoly, Sha256>;

/// Caller-supplied monotonic microseconds in one unchanged clock domain.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct Time(pub u64);

/// Explicit fixed proof profile; neither profile is selected by a peer packet.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Profile {
    /// Pinned mutual static-key authentication using Noise IK.
    Ik,
    /// Noise IK with an additional independently provisioned 32-byte PSK.
    IkPsk2,
}

/// Explicitly pinned remote X25519 public key, separate from Ed25519 membership.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PeerKey(pub [u8; 32]);

/// Owned X25519 private key, with no Debug, Clone or raw-key accessor.
pub struct LocalSecret(Zeroizing<[u8; 32]>);

impl LocalSecret {
    /// Consume an explicitly provisioned X25519 key; no Ed25519 conversion occurs.
    pub fn new(bytes: Zeroizing<[u8; 32]>) -> Self {
        Self(bytes)
    }

    /// Observe only the corresponding public key.
    pub fn public_key(&self) -> PeerKey {
        let secret = SensitiveByteArray::new(*self.0);
        PeerKey(CheckedX25519::pubkey(&secret))
    }
}

/// Independently provisioned optional PSK, owned and zeroized on drop.
pub struct Psk(Zeroizing<[u8; 32]>);

impl Psk {
    /// Consume owned material without exposing a secret getter.
    pub fn new(bytes: Zeroizing<[u8; 32]>) -> Self {
        Self(bytes)
    }
}

/// Public context authenticated in the fixed prologue, in global role order.
/// Digests must come from the reviewed caller policy; they do not verify it here.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Binding {
    /// Fresh logical session identity agreed by the surrounding session protocol.
    pub session: SessionId,
    /// Complete selected configuration and capability/resource digest.
    pub configuration: [u8; 32],
    /// Selected carrier/appearance contract digest.
    pub carrier: [u8; 32],
    /// Outer handshake or packet-ownership transition binding.
    pub outer: [u8; 32],
    /// Existing-member identity/provisioning binding, verified outside this proof.
    pub member: [u8; 32],
}

/// Immutable local selection; no default timeout or cipher negotiation is implied.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Config {
    /// Fixed global endpoint role.
    pub role: Role,
    /// Locally required proof profile.
    pub profile: Profile,
    /// Authenticated shared context.
    pub binding: Binding,
    /// Original absolute deadline; duplicates and retries never renew it.
    pub deadline: Time,
}

/// Fallible caller entropy source. Runtime providers must be cryptographically secure.
pub trait Entropy {
    /// Fill exactly one fresh ephemeral secret, or fail without emitting a flight.
    fn fill(&mut self, destination: &mut [u8; 32]) -> Result<(), EntropyError>;
}

/// Caller entropy failed; no provider message or secret is retained.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EntropyError;

/// Typed logical flight. Carrier wire encoding and authentication are separate work.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FlightKind {
    /// Initiator's fixed 96-byte Noise message.
    Initiation,
    /// Responder's fixed 48-byte Noise message.
    Response,
    /// Fixed encrypted role/session/transcript confirmation.
    Confirmation,
}

impl FlightKind {
    fn size(self) -> usize {
        match self {
            Self::Initiation => INITIATION_BYTES,
            Self::Response => RESPONSE_BYTES,
            Self::Confirmation => CONFIRM_BYTES,
        }
    }
}

/// Metadata for one flight already written into the caller's output.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Flight {
    /// Logical message kind, to be carried by the enclosing protocol.
    pub kind: FlightKind,
    /// Exact initialized output prefix.
    pub bytes: usize,
}

/// Established packet protection plus custody of its final confirmation bytes.
/// Neither local completion nor this handoff proves the peer received that flight.
pub struct Established {
    /// Opaque common packet-security owner, with no original Noise transport reuse.
    pub root: SessionRoot,
    /// Exact final ciphertext retained through the original handshake deadline.
    pub confirmation: ConfirmationCache,
}

/// Bounded final-flight ciphertext custody after the handshake keys are consumed.
/// This owner has no secret key, encryption operation or automatic response policy.
pub struct ConfirmationCache {
    ciphertext: Zeroizing<[u8; CONFIRM_BYTES]>,
    deadline: Time,
    now: Time,
    retired: bool,
}

impl ConfirmationCache {
    /// Original absolute handshake deadline; retransmission never extends it.
    pub fn deadline(&self) -> Time {
        self.deadline
    }

    /// Copy the exact final ciphertext, without encryption or nonce consumption.
    /// A small output leaves the cache, supplied-time state and output unchanged.
    /// Expiry or backwards time wipes and permanently retires this cache.
    pub fn retransmit(&mut self, now: Time, output: &mut [u8]) -> Result<Flight, Error> {
        if self.retired {
            return Err(Error::State);
        }
        if now < self.now || now >= self.deadline {
            self.ciphertext.zeroize();
            self.retired = true;
            return Err(Error::Deadline);
        }
        let destination = output
            .get_mut(..CONFIRM_BYTES)
            .ok_or(Error::OutputTooSmall)?;
        destination.copy_from_slice(&self.ciphertext[..]);
        self.now = now;
        Ok(Flight {
            kind: FlightKind::Confirmation,
            bytes: CONFIRM_BYTES,
        })
    }
}

/// Successful admission; exact duplicates never execute crypto again.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReadOutcome {
    /// The expected new flight authenticated and advanced local state.
    Accepted,
    /// Exact previously admitted bytes; caller may retransmit cached output.
    Duplicate,
}

/// Bounded public failure with no peer payload, private key or library state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// Missing/unexpected PSK or reflected local/remote identity.
    Configuration,
    /// Caller entropy failed; no fallback is available.
    Entropy,
    /// Original deadline expired or caller time moved backwards.
    Deadline,
    /// Flight kind does not fit this role or phase, or state was already retired.
    State,
    /// Exact fixed flight length does not match.
    Length,
    /// Caller output cannot hold the complete flight; no crypto state changes.
    OutputTooSmall,
    /// Conflicting bytes reused a previously admitted flight kind.
    Conflict,
    /// Peer identity, authenticated context, contribution or confirmation failed.
    Authentication,
    /// A maintained API violated the fixed local construction's invariant.
    Crypto,
    /// Common packet-security construction rejected the consumed result.
    Protection,
}

impl fmt::Display for Error {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(output, "Noise handshake proof: {self:?}")
    }
}

impl std::error::Error for Error {}

struct Cached {
    kind: FlightKind,
    bytes: Vec<u8>,
}

/// One bounded handshake owner. It cannot be cloned or used to carry early data.
pub struct Handshake {
    config: Config,
    peer: PeerKey,
    now: Time,
    noise: Option<Noise>,
    transport: Option<Transport>,
    transcript: [u8; 32],
    sent_confirmation: bool,
    verified_confirmation: bool,
    retired: bool,
    received: Vec<Cached>,
    sent: Vec<Cached>,
}

impl Handshake {
    /// Construct from explicit own-peer trust and one fresh caller ephemeral.
    /// Existing membership verification/provisioning is an external prerequisite.
    pub fn new(
        config: Config,
        local: LocalSecret,
        peer: PeerKey,
        psk: Option<Psk>,
        now: Time,
        entropy: &mut impl Entropy,
    ) -> Result<Self, Error> {
        if now >= config.deadline {
            return Err(Error::Deadline);
        }
        if matches!(config.profile, Profile::IkPsk2) != psk.is_some() {
            return Err(Error::Configuration);
        }
        let local_public = local.public_key();
        if local_public == peer {
            return Err(Error::Configuration);
        }
        let static_secret = SensitiveByteArray::new(*local.0);
        CheckedX25519::dh(&static_secret, &peer.0).map_err(|_| Error::Authentication)?;
        let mut ephemeral = Zeroizing::new([0; 32]);
        entropy.fill(&mut ephemeral).map_err(|_| Error::Entropy)?;
        let ephemeral_secret = SensitiveByteArray::new(*ephemeral);
        let ephemeral_public = CheckedX25519::pubkey(&ephemeral_secret);
        let initiator = config.role == Role::Initiator;
        let (initiator_key, responder_key) = if initiator {
            (local_public.0, peer.0)
        } else {
            (peer.0, local_public.0)
        };
        let mut prologue = Vec::with_capacity(PROLOGUE_DOMAIN.len() + 1 + 16 + 6 * 32);
        prologue.extend_from_slice(PROLOGUE_DOMAIN);
        prologue.push(match config.profile {
            Profile::Ik => 1,
            Profile::IkPsk2 => 2,
        });
        prologue.extend_from_slice(&config.binding.session.0);
        for field in [
            config.binding.configuration,
            config.binding.carrier,
            config.binding.outer,
            config.binding.member,
            initiator_key,
            responder_key,
        ] {
            prologue.extend_from_slice(&field);
        }
        let pattern = match config.profile {
            Profile::Ik => noise_ik(),
            Profile::IkPsk2 => noise_ik_psk2(),
        };
        let mut noise = Noise::new(
            pattern,
            &prologue,
            initiator,
            Some(KeyPair::new(local_public.0, static_secret)),
            Some(KeyPair::new(ephemeral_public, ephemeral_secret)),
            initiator.then_some(peer.0),
            None,
        )
        .map_err(|_| Error::Crypto)?;
        if let Some(psk) = psk {
            // Exact fixed-size, one-PSK input; no peer-sized queue or pattern.
            // Upstream internal PSK-copy erasure is a documented remaining gate.
            noise.push_psk(&psk.0[..]);
        }
        Ok(Self {
            config,
            peer,
            now,
            noise: Some(noise),
            transport: None,
            transcript: [0; 32],
            sent_confirmation: false,
            verified_confirmation: false,
            retired: false,
            received: Vec::with_capacity(2),
            sent: Vec::with_capacity(2),
        })
    }

    /// Original absolute deadline; this value is never changed by an input.
    pub fn deadline(&self) -> Time {
        self.config.deadline
    }

    /// Next new flight this role may emit, without performing crypto or I/O.
    pub fn next_flight(&self) -> Option<FlightKind> {
        if self.retired {
            return None;
        }
        if let Some(noise) = &self.noise {
            return noise
                .is_write_turn()
                .then_some(if self.config.role == Role::Initiator {
                    FlightKind::Initiation
                } else {
                    FlightKind::Response
                });
        }
        (self.transport.is_some() && !self.sent_confirmation).then_some(FlightKind::Confirmation)
    }

    /// Whether local confirmation emission and peer confirmation both completed.
    /// This does not prove a carrier physically flushed the emitted bytes.
    pub fn is_complete(&self) -> bool {
        !self.retired && self.sent_confirmation && self.verified_confirmation
    }

    fn check(&mut self, now: Time) -> Result<(), Error> {
        if self.retired {
            return Err(Error::State);
        }
        if now < self.now || now >= self.config.deadline {
            return self.fail(Error::Deadline);
        }
        self.now = now;
        Ok(())
    }

    fn fail<T>(&mut self, error: Error) -> Result<T, Error> {
        self.retired = true;
        self.noise = None;
        self.transport = None;
        Err(error)
    }

    fn transition(&mut self) -> Result<(), Error> {
        if !self.noise.as_ref().is_some_and(|noise| noise.is_finished()) {
            return Ok(());
        }
        let noise = self.noise.take().ok_or(Error::State)?;
        if noise.get_remote_static() != Some(self.peer.0) {
            return self.fail(Error::Authentication);
        }
        let transport = match noise.finalize() {
            Ok(transport) => transport,
            Err(_) => return self.fail(Error::Crypto),
        };
        self.transcript
            .copy_from_slice(transport.get_handshake_hash().as_slice());
        self.transport = Some(transport);
        Ok(())
    }

    fn confirmation(&self, sender: Role) -> [u8; CONFIRM_BODY] {
        let mut body = [0; CONFIRM_BODY];
        body[..8].copy_from_slice(CONFIRM_DOMAIN);
        body[8] = if sender == Role::Initiator { 1 } else { 2 };
        body[9..25].copy_from_slice(&self.config.binding.session.0);
        body[25..].copy_from_slice(&self.transcript);
        body
    }

    /// Emit exactly one new fixed flight. A small output leaves crypto state intact.
    pub fn write(&mut self, now: Time, output: &mut [u8]) -> Result<Flight, Error> {
        self.check(now)?;
        if self.sent.len() >= 2 {
            return Err(Error::State);
        }
        let kind = self.next_flight().ok_or(Error::State)?;
        let bytes = kind.size();
        let destination = output.get_mut(..bytes).ok_or(Error::OutputTooSmall)?;
        let result = if kind == FlightKind::Confirmation {
            let body = self.confirmation(self.config.role);
            self.transport
                .as_mut()
                .ok_or(Error::State)?
                .send(&body, destination)
                .map_err(|_| Error::Crypto)
        } else {
            self.noise
                .as_mut()
                .ok_or(Error::State)?
                .write_message(&[], destination)
                .map_err(|_| Error::Crypto)
        };
        match result {
            Ok(written) if written == bytes => {}
            _ => return self.fail(Error::Crypto),
        }
        self.sent.push(Cached {
            kind,
            bytes: destination.to_vec(),
        });
        if kind == FlightKind::Confirmation {
            self.sent_confirmation = true;
        }
        self.transition()?;
        Ok(Flight { kind, bytes })
    }

    /// Copy previously emitted bytes exactly; no encryption, nonce use or deadline renewal.
    pub fn retransmit(
        &mut self,
        now: Time,
        kind: FlightKind,
        output: &mut [u8],
    ) -> Result<Flight, Error> {
        self.check(now)?;
        let saved = self
            .sent
            .iter()
            .find(|saved| saved.kind == kind)
            .ok_or(Error::State)?;
        let destination = output
            .get_mut(..saved.bytes.len())
            .ok_or(Error::OutputTooSmall)?;
        destination.copy_from_slice(&saved.bytes);
        Ok(Flight {
            kind,
            bytes: saved.bytes.len(),
        })
    }

    /// Admit a fixed opaque flight. Peer protocol/authentication failure retires state.
    pub fn read(
        &mut self,
        now: Time,
        kind: FlightKind,
        bytes: &[u8],
    ) -> Result<ReadOutcome, Error> {
        self.check(now)?;
        if bytes.len() != kind.size() {
            return self.fail(Error::Length);
        }
        if let Some(saved) = self.received.iter().find(|saved| saved.kind == kind) {
            return if saved.bytes == bytes {
                Ok(ReadOutcome::Duplicate)
            } else {
                self.fail(Error::Conflict)
            };
        }
        if self.received.len() >= 2 {
            return self.fail(Error::State);
        }
        let result = if kind == FlightKind::Confirmation {
            let mut body = [0; CONFIRM_BODY];
            let peer_role = if self.config.role == Role::Initiator {
                Role::Responder
            } else {
                Role::Initiator
            };
            let expected = self.confirmation(peer_role);
            match self.transport.as_mut() {
                Some(transport) => match transport.receive(bytes, &mut body) {
                    Ok(written) if written == body.len() && body == expected => Ok(()),
                    _ => Err(Error::Authentication),
                },
                None => Err(Error::State),
            }
        } else {
            let expected_kind = if self.config.role == Role::Initiator {
                FlightKind::Response
            } else {
                FlightKind::Initiation
            };
            match self.noise.as_mut() {
                Some(noise) if kind == expected_kind && !noise.is_write_turn() => noise
                    .read_message(bytes, &mut [])
                    .map(|_| ())
                    .map_err(|_| Error::Authentication),
                _ => Err(Error::State),
            }
        };
        if let Err(error) = result {
            return self.fail(error);
        }
        self.received.push(Cached {
            kind,
            bytes: bytes.to_vec(),
        });
        if kind == FlightKind::Confirmation {
            self.verified_confirmation = true;
        }
        self.transition()?;
        Ok(ReadOutcome::Accepted)
    }

    /// Consume a confirmed handshake, intentionally discarding its final-flight cache.
    /// Use only when the caller already retained the exact final ciphertext or has
    /// established reliable completion externally. UDP callers normally require
    /// [`Self::finish_with_confirmation`] to preserve final-flight custody.
    pub fn finish(self, now: Time) -> Result<SessionRoot, Error> {
        self.finish_with_confirmation(now)
            .map(|established| established.root)
    }

    /// Release the opaque root and retain exact final ciphertext for bounded retry.
    /// No root is released before local emission and verified peer confirmation.
    /// The runtime still owns send success, readiness and amplification policy.
    pub fn finish_with_confirmation(mut self, now: Time) -> Result<Established, Error> {
        self.check(now)?;
        if !self.is_complete() {
            return Err(Error::State);
        }
        let final_flight = self
            .sent
            .iter()
            .find(|saved| saved.kind == FlightKind::Confirmation)
            .ok_or(Error::State)?;
        let mut ciphertext = Zeroizing::new([0; CONFIRM_BYTES]);
        if final_flight.bytes.len() != ciphertext.len() {
            return Err(Error::Crypto);
        }
        ciphertext.copy_from_slice(&final_flight.bytes);
        let confirmation = ConfirmationCache {
            ciphertext,
            deadline: self.config.deadline,
            now: self.now,
            retired: false,
        };
        let states = self.transport.take().ok_or(Error::State)?.take();
        let (forward, forward_nonce) = states.initiator_to_responder.take();
        let (reverse, reverse_nonce) = states.responder_to_initiator.take();
        if forward_nonce != 1 || reverse_nonce != 1 {
            return Err(Error::Crypto);
        }
        let mut forward_owned = Zeroizing::new([0; 32]);
        let mut reverse_owned = Zeroizing::new([0; 32]);
        forward_owned.copy_from_slice(forward.as_slice());
        reverse_owned.copy_from_slice(reverse.as_slice());
        drop((forward, reverse));
        let root = SessionRoot::from_split_keys(
            forward_owned,
            reverse_owned,
            SessionBinding {
                session: self.config.binding.session,
                transcript: self.transcript,
            },
            self.config.role,
        )
        .map_err(|_| Error::Protection)?;
        Ok(Established { root, confirmation })
    }
}

impl Drop for Handshake {
    fn drop(&mut self) {
        self.noise = None;
        self.transport = None;
        for cached in self.received.iter_mut().chain(self.sent.iter_mut()) {
            cached.bytes.zeroize();
        }
    }
}

#[cfg(test)]
mod tests;
