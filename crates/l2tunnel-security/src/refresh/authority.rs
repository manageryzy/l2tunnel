use super::{Error, KeyEpoch, Owners, REQUEST_BYTES, Selection, Tick, add};
use crate::{
    ConfigDigest, Epoch, LaneId, Limits, Metadata, Protection, Receiver, Role, Sender,
    SessionBinding, SessionRoot, keys,
};
use ring::{digest, hkdf, hmac};
use zeroize::Zeroizing;

/// Public context passed at the trusted secret import boundary, not auth evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Context {
    /// Original stable logical session and actual final initial Noise hash.
    pub binding: SessionBinding,
    /// Original setup H0.
    pub configuration: [u8; 32],
    /// Original selected carrier contract.
    pub carrier: [u8; 32],
    /// Original actually derived outer binding.
    pub outer: [u8; 32],
    /// Original member-policy binding, never a claim of member proof by itself.
    pub member: [u8; 32],
    /// Pinned static keys in global role order.
    pub pins: [[u8; 32]; 2],
    /// Actual initial fixed Noise profile, IK1 or IKpsk2 2.
    pub profile: u8,
}
impl Context {
    /// Exact public refresh prologue context; no secret is returned.
    pub fn canonical_bytes(
        self,
        selection: Selection,
        parent: KeyEpoch,
        target: KeyEpoch,
    ) -> [u8; 417] {
        let mut b = [0; 417];
        let mut at = 0;
        for part in [
            b"l2tunnel/refresh-context/v1\0".as_slice(),
            &self.binding.session.0,
            &self.binding.transcript,
            &self.configuration,
            &self.carrier,
            &self.outer,
            &self.member,
            &self.pins[0],
            &self.pins[1],
            &[self.profile],
            &selection.canonical_bytes(),
            &parent.0.to_be_bytes(),
            &target.0.to_be_bytes(),
        ] {
            b[at..at + part.len()].copy_from_slice(part);
            at += part.len();
        }
        b
    }
    pub(super) fn digest(
        self,
        selection: Selection,
        parent: KeyEpoch,
        target: KeyEpoch,
    ) -> [u8; 32] {
        let mut b = [0; 32];
        b.copy_from_slice(
            digest::digest(
                &digest::SHA256,
                &self.canonical_bytes(selection, parent, target),
            )
            .as_ref(),
        );
        b
    }
}

/// Standard maintained HMAC commitment; keep its returned bytes secret.
pub fn psk_commitment(psk: &[u8], initial_prologue: &[u8]) -> Zeroizing<[u8; 32]> {
    let hash = digest::digest(&digest::SHA256, initial_prologue);
    let mut mac = hmac::Context::with_key(&hmac::Key::new(hmac::HMAC_SHA256, psk));
    mac.update(b"l2tunnel/refresh-psk-check/v1\0");
    mac.update(hash.as_ref());
    let mut b = Zeroizing::new([0; 32]);
    b.copy_from_slice(mac.sign().as_ref());
    b
}

/// Public hash of the actual prologue, not a proof or secret authentication key.
pub fn prologue_hash(prologue: &[u8]) -> [u8; 32] {
    let mut result = [0; 32];
    result.copy_from_slice(digest::digest(&digest::SHA256, prologue).as_ref());
    result
}

pub(super) fn seed(
    forward: Zeroizing<[u8; 32]>,
    reverse: Zeroizing<[u8; 32]>,
    context: Context,
    selection: Selection,
    parent: KeyEpoch,
    target: KeyEpoch,
    transcript: [u8; 32],
) -> Result<Zeroizing<[u8; 32]>, Error> {
    let mut input = Zeroizing::new([0; 64]);
    input[..32].copy_from_slice(&forward[..]);
    input[32..].copy_from_slice(&reverse[..]);
    let mut salt = [0; 120];
    salt[..16].copy_from_slice(&context.binding.session.0);
    salt[16..48].copy_from_slice(&context.binding.transcript);
    salt[48..56].copy_from_slice(&target.0.to_be_bytes());
    salt[56..88].copy_from_slice(&context.digest(selection, parent, target));
    salt[88..].copy_from_slice(&transcript);
    Ok(keys::expand(
        &hkdf::Salt::new(hkdf::HKDF_SHA256, &salt).extract(&input[..]),
        &[b"l2tunnel/packet/v2/session-root\0"],
    )?)
}

/// Trusted initial secret import, held privately by the actual handshake wrapper.
/// A value constructed directly here is not a facade Noise proof.
pub struct Initial {
    pub(super) root: SessionRoot,
    pub(super) seed: Zeroizing<[u8; 32]>,
    pub(super) context: Context,
    pub(super) selection: Selection,
    pub(super) role: Role,
    pub(super) born: Tick,
    pub(super) deadline: Tick,
    pub(super) psk: Option<Zeroizing<[u8; 32]>>,
    pub(super) prologue_hash: [u8; 32],
    retired_joining: bool,
}
impl Initial {
    /// Import supported consumed split secrets once; public context alone cannot do so.
    #[allow(clippy::too_many_arguments)]
    pub fn from_split_keys(
        forward: Zeroizing<[u8; 32]>,
        reverse: Zeroizing<[u8; 32]>,
        context: Context,
        selection: Selection,
        role: Role,
        born: Tick,
        deadline: Tick,
        psk: Option<Zeroizing<[u8; 32]>>,
        prologue_hash: [u8; 32],
    ) -> Result<Self, Error> {
        if born >= deadline
            || !(1..=2).contains(&context.profile)
            || context.pins[0] == context.pins[1]
            || (context.profile == 2) != psk.is_some()
        {
            return Err(Error::Context);
        }
        let root = SessionRoot::from_split_keys(
            Zeroizing::new(*forward),
            Zeroizing::new(*reverse),
            context.binding,
            role,
        )?;
        let seed = seed(
            forward,
            reverse,
            context,
            selection,
            KeyEpoch(0),
            KeyEpoch(0),
            context.binding.transcript,
        )?;
        add(born, selection.spec().key_micros)?;
        Ok(Self {
            root,
            seed,
            context,
            selection,
            role,
            born,
            deadline,
            psk,
            prologue_hash,
            retired_joining: false,
        })
    }
    /// Observe immutable checked context; this copy grants no owner.
    pub const fn context(&self) -> Context {
        self.context
    }
    /// Observe checked selection.
    pub const fn selection(&self) -> Selection {
        self.selection
    }
    /// Observe actual local role.
    pub const fn role(&self) -> Role {
        self.role
    }
    /// Reserve only the actual managed initial Joining pair.
    pub fn joining(
        mut self,
        limits: Limits,
        now: Tick,
        original_deadline: Tick,
    ) -> Result<Joining, Error> {
        if now < self.born {
            return Err(Error::TimeRegression);
        }
        let deadline = original_deadline
            .min(self.deadline)
            .min(add(self.born, self.selection.spec().key_micros)?);
        if now >= deadline {
            return Err(Error::Deadline);
        }
        let lane = self.selection.spec().lane;
        if self.retired_joining || !self.root.managed_registry(lane, false) {
            return Err(Error::Domains);
        }
        let sender = self.root.sender(
            crate::Purpose::Joining,
            lane,
            limits,
            Protection::ChaCha20Poly1305,
        )?;
        let receiver = self.root.receiver(
            crate::Purpose::Joining,
            lane,
            limits,
            Protection::ChaCha20Poly1305,
        )?;
        let capacity = limits
            .max_body_bytes
            .checked_add(26)
            .ok_or(Error::Configuration)?;
        let mut cache = Zeroizing::new(Vec::new());
        cache
            .try_reserve_exact(capacity)
            .map_err(|_| Error::Allocation)?;
        Ok(Joining {
            initial: self,
            sender,
            receiver,
            cache,
            sent: false,
            received: false,
            now,
            deadline,
            failed: false,
        })
    }
    /// Consume managed initial backing; no generic root or packet owner escapes.
    #[allow(clippy::too_many_arguments)]
    pub fn install(
        self,
        lane: LaneId,
        limits: Limits,
        protection: Protection,
        epoch: Epoch,
        digest: ConfigDigest,
        now: Tick,
        session_expires: Tick,
    ) -> Result<Owners, Error> {
        let s = self.selection.spec();
        if s.lane != lane
            || s.limits != limits
            || s.protection != protection
            || s.control_epoch != epoch
            || s.control_digest != digest
        {
            return Err(Error::Context);
        }
        if !self.root.managed_registry(lane, self.retired_joining) {
            return Err(Error::Domains);
        }
        Owners::initial(self, now, session_expires)
    }
}

/// Actual initial Joining crypto custody. Retirement is not membership proof.
pub struct Joining {
    initial: Initial,
    sender: Sender,
    receiver: Receiver,
    cache: Zeroizing<Vec<u8>>,
    sent: bool,
    received: bool,
    now: Tick,
    deadline: Tick,
    failed: bool,
}
impl Joining {
    /// Actual retained Joining cap, including original setup and initial key age.
    pub const fn deadline(&self) -> Tick {
        self.deadline
    }
    /// Nonsecret actual initial context.
    pub const fn context(&self) -> Context {
        self.initial.context
    }
    /// Nonsecret actual local role.
    pub const fn role(&self) -> Role {
        self.initial.role
    }
    /// Nonsecret checked selection.
    pub const fn selection(&self) -> Selection {
        self.initial.selection
    }
    fn check(&mut self, now: Tick) -> Result<(), Error> {
        if self.failed {
            return Err(Error::State);
        }
        if now < self.now {
            self.failed = true;
            return Err(Error::TimeRegression);
        }
        if now >= self.deadline {
            self.failed = true;
            return Err(Error::Deadline);
        }
        self.now = now;
        Ok(())
    }
    fn metadata(&self) -> Metadata<'static> {
        Metadata {
            epoch: Epoch(1),
            configuration: ConfigDigest(self.initial.context.configuration),
            extra: &[3],
        }
    }
    /// Seal exactly once at number zero, retaining identical ciphertext.
    pub fn seal(&mut self, now: Tick, body: &[u8], out: &mut [u8]) -> Result<crate::Sealed, Error> {
        self.check(now)?;
        if self.sent {
            return Err(Error::State);
        }
        let metadata = self.metadata();
        let result = self.sender.seal(metadata, body, out)?;
        self.cache.extend_from_slice(&out[..result.bytes]);
        self.sent = true;
        self.now = now;
        Ok(result)
    }
    /// Authenticate the peer's single number-zero packet without granting membership.
    pub fn open(
        &mut self,
        now: Tick,
        input: &[u8],
        out: &mut [u8],
    ) -> Result<crate::Opened, Error> {
        self.check(now)?;
        let metadata = self.metadata();
        let result = self.receiver.open(metadata, input, out)?;
        if result.number.0 != 0 {
            return Err(Error::Context);
        }
        self.received = true;
        self.now = now;
        Ok(result)
    }
    /// Copy the exact one-time ciphertext; no nonce or deadline changes.
    pub fn retransmit(&mut self, now: Tick, out: &mut [u8]) -> Result<usize, Error> {
        self.check(now)?;
        if !self.sent {
            return Err(Error::State);
        }
        out.get_mut(..self.cache.len())
            .ok_or(crate::Error::OutputTooSmall)?
            .copy_from_slice(&self.cache);
        self.now = now;
        Ok(self.cache.len())
    }
    /// Drop the exact managed pair, retaining registry tombstones and initial custody.
    pub fn retire(mut self, now: Tick) -> Result<Initial, Error> {
        self.check(now)?;
        if !self.sent || !self.received {
            return Err(Error::State);
        }
        let Self {
            mut initial,
            sender,
            receiver,
            ..
        } = self;
        drop((sender, receiver));
        initial.retired_joining = true;
        Ok(initial)
    }
}

/// Immutable locally minted request. Parsing bytes alone cannot mint admission.
pub struct Request(pub(super) [u8; REQUEST_BYTES]);
impl Request {
    /// Exact plaintext to protect through the existing Management owner.
    pub const fn as_bytes(&self) -> &[u8; REQUEST_BYTES] {
        &self.0
    }
}

/// Unique local/remote admission; not constructible from public observations.
pub struct Admission {
    pub(super) context: Context,
    pub(super) selection: Selection,
    pub(super) role: Role,
    pub(super) parent: KeyEpoch,
    pub(super) target: KeyEpoch,
    pub(super) deadline: Tick,
    pub(super) admitted: Tick,
    pub(super) psk: Option<Zeroizing<[u8; 32]>>,
    pub(super) prologue_hash: [u8; 32],
}
impl Admission {
    /// Actual initial context, not a secret key.
    pub const fn context(&self) -> Context {
        self.context
    }
    /// Actual local role.
    pub const fn role(&self) -> Role {
        self.role
    }
    /// Exact selected contract.
    pub const fn selection(&self) -> Selection {
        self.selection
    }
    /// Original accepted local cap.
    pub const fn deadline(&self) -> Tick {
        self.deadline
    }
    /// First actual admission time; an exchange cannot move to an earlier clock.
    pub const fn admitted(&self) -> Tick {
        self.admitted
    }
    /// Target selector.
    pub const fn target(&self) -> KeyEpoch {
        self.target
    }
    /// Exact canonical fresh Noise context.
    pub fn canonical_context(&self) -> [u8; 417] {
        self.context
            .canonical_bytes(self.selection, self.parent, self.target)
    }
    /// Immutable public refresh header with caller-selected fixed kind and magic.
    pub fn header(&self, magic: [u8; 4], kind: u8) -> [u8; 72] {
        header(
            self.context,
            self.selection,
            self.parent,
            self.target,
            magic,
            kind,
        )
    }
    /// Check actual supplied own/peer public keys and the exact old PSK commitment.
    pub fn check_credentials(
        &self,
        local: [u8; 32],
        peer: [u8; 32],
        psk: Option<&[u8]>,
    ) -> Result<(), Error> {
        let own = usize::from(self.role == Role::Responder);
        if local != self.context.pins[own] || peer != self.context.pins[1 - own] {
            return Err(Error::Context);
        }
        match (&self.psk, psk) {
            (None, None) => Ok(()),
            (Some(tag), Some(psk)) => {
                let mut message = [0; 62];
                message[..30].copy_from_slice(b"l2tunnel/refresh-psk-check/v1\0");
                message[30..].copy_from_slice(&self.prologue_hash);
                hmac::verify(&hmac::Key::new(hmac::HMAC_SHA256, psk), &message, &tag[..])
                    .map_err(|_| Error::Context)
            }
            _ => Err(Error::Context),
        }
    }
}

pub(super) fn header(
    context: Context,
    selection: Selection,
    parent: KeyEpoch,
    target: KeyEpoch,
    magic: [u8; 4],
    kind: u8,
) -> [u8; 72] {
    let mut b = [0; 72];
    b[..4].copy_from_slice(&magic);
    b[4] = 1;
    b[5] = kind;
    b[8..24].copy_from_slice(&context.binding.session.0);
    b[24..32].copy_from_slice(&parent.0.to_be_bytes());
    b[32..40].copy_from_slice(&target.0.to_be_bytes());
    b[40..].copy_from_slice(&context.digest(selection, parent, target));
    b
}

/// Trusted consumed fresh split import. Facade accepts only handshake-owned proof.
pub struct Material {
    pub(super) admission: Admission,
    pub(super) seed: Zeroizing<[u8; 32]>,
    pub(super) transcript: [u8; 32],
    pub(super) born: Tick,
}
impl Material {
    /// Import actual supported split secrets after both real Noise confirmations.
    pub fn from_split_keys(
        admission: Admission,
        forward: Zeroizing<[u8; 32]>,
        reverse: Zeroizing<[u8; 32]>,
        transcript: [u8; 32],
        born: Tick,
    ) -> Result<Self, Error> {
        if born < admission.admitted {
            return Err(Error::TimeRegression);
        }
        if born >= admission.deadline {
            return Err(Error::Deadline);
        }
        let seed = seed(
            forward,
            reverse,
            admission.context,
            admission.selection,
            admission.parent,
            admission.target,
            transcript,
        )?;
        Ok(Self {
            admission,
            seed,
            transcript,
            born,
        })
    }
    /// Consume into the exact pending actual packet owners; no raw secret is returned.
    pub fn prepare_into(self, owners: &mut Owners, now: Tick) -> Result<super::Prepared, Error> {
        owners.prepare(self, now)
    }
}
