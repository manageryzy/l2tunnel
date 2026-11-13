//! Pure maintained Ed25519 membership and explicit Noise-session possession proof.
//!
//! This crate performs no key generation, randomness, I/O, clock or carrier work.
//! Runtime compatibility wrappers retain the existing TLS proof formats. A new
//! signed context binds existing client membership to separately pinned Noise keys.

use l2tunnel_security::{Role, SessionId, SessionRoot};
use ring::signature::{ED25519, Ed25519KeyPair, KeyPair, UnparsedPublicKey};
use std::fmt;

/// Existing PKCS#8 input bound, unchanged from the retained auth adapter.
pub const MAX_PKCS8_BYTES: usize = 4096;
/// Fixed work bound for generic legacy/new signing and verification transcripts.
pub const MAX_SIGNED_BYTES: usize = 16_384;
/// Maximum public entries accepted before allowlist deduplication.
pub const MAX_MEMBERS: usize = 1024;
/// Version, initiator role, public member identity and Ed25519 signature.
pub const MEMBER_PROOF_BYTES: usize = 98;
const PROOF_PREFIX: usize = 34;
const DOMAIN: &[u8] = b"l2tunnel/member-noise-binding/v1\0";
const SIGNED_CONTEXT_BYTES: usize = DOMAIN.len() + PROOF_PREFIX + 16 + 6 * 32;

/// Raw Ed25519 member public identity; never private or an X25519 key.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct MemberPublicKey(pub [u8; 32]);

/// One maintained Ed25519 private-key owner, without Clone, Debug or raw getters.
pub struct IdentityKey(Ed25519KeyPair);
impl IdentityKey {
    /// Parse the same public/private-consistent PKCS#8 v2 format as the old API.
    /// The caller owns and must manage its borrowed encoded private-key buffer.
    pub fn from_pkcs8(encoded: &[u8]) -> Result<Self, Error> {
        if encoded.len() > MAX_PKCS8_BYTES {
            return Err(Error::InvalidKey);
        }
        Ed25519KeyPair::from_pkcs8(encoded)
            .map(Self)
            .map_err(|_| Error::InvalidKey)
    }
    /// Observe the public identity only.
    pub fn public_key(&self) -> MemberPublicKey {
        let mut public = [0; 32];
        public.copy_from_slice(self.0.public_key().as_ref());
        MemberPublicKey(public)
    }
    /// Sign exact caller transcript bytes with no extra domain or randomness.
    /// Retained adapters keep their original domain-separated wire construction.
    pub fn sign(&self, transcript: &[u8]) -> Result<[u8; 64], Error> {
        if transcript.len() > MAX_SIGNED_BYTES {
            return Err(Error::TooLarge);
        }
        self.0
            .sign(transcript)
            .as_ref()
            .try_into()
            .map_err(|_| Error::InvalidSignature)
    }
}

/// Verify exact transcript/signature bytes using maintained Ed25519 verification.
pub fn verify_signature(
    member: MemberPublicKey,
    transcript: &[u8],
    signature: &[u8],
) -> Result<(), Error> {
    if transcript.len() > MAX_SIGNED_BYTES {
        return Err(Error::TooLarge);
    }
    if signature.len() != 64 {
        return Err(Error::InvalidSignature);
    }
    UnparsedPublicKey::new(&ED25519, member.0)
        .verify(transcript, signature)
        .map_err(|_| Error::InvalidSignature)
}

/// Immutable bounded public membership policy, preserving legacy deduplication.
#[derive(Clone)]
pub struct Allowlist(Vec<MemberPublicKey>);
impl Allowlist {
    /// Copy 1..1024 configured public identities, sorting and removing duplicates.
    pub fn new(members: &[MemberPublicKey]) -> Result<Self, Error> {
        if members.is_empty() || members.len() > MAX_MEMBERS {
            return Err(Error::InvalidAllowlist);
        }
        let mut members = members.to_vec();
        members.sort_unstable();
        members.dedup();
        Ok(Self(members))
    }
    /// Test configured membership; successful signature possession is separate.
    pub fn contains(&self, member: MemberPublicKey) -> bool {
        self.0.binary_search(&member).is_ok()
    }
}

/// Public X25519 identity, explicitly distinct from Ed25519 member identities.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NoisePublicKey(pub [u8; 32]);

/// Exact locally selected context authenticated by the member signature.
/// These values must come from our configuration and completed pinned handshake.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Context {
    /// Fresh authenticated logical session identity.
    pub session: SessionId,
    /// Final authenticated Noise handshake hash, never secret MAC key material.
    pub transcript: [u8; 32],
    /// Complete selected capability/resource/packet-layer configuration digest.
    pub configuration: [u8; 32],
    /// Selected carrier/appearance digest.
    pub carrier: [u8; 32],
    /// Outer handshake or ownership transition binding.
    pub outer: [u8; 32],
    /// Configured initiator X25519 public identity, in global role order.
    pub initiator_noise: NoisePublicKey,
    /// Our trusted server's pinned X25519 identity, in global role order.
    pub responder_noise: NoisePublicKey,
}
impl Context {
    fn validate(self) -> Result<(), Error> {
        if self.initiator_noise == self.responder_noise {
            return Err(Error::BindingMismatch);
        }
        Ok(())
    }
    fn signed(self, prefix: &[u8; PROOF_PREFIX]) -> [u8; SIGNED_CONTEXT_BYTES] {
        let mut bytes = [0; SIGNED_CONTEXT_BYTES];
        let mut offset = DOMAIN.len();
        bytes[..offset].copy_from_slice(DOMAIN);
        bytes[offset..offset + PROOF_PREFIX].copy_from_slice(prefix);
        offset += PROOF_PREFIX;
        bytes[offset..offset + 16].copy_from_slice(&self.session.0);
        offset += 16;
        for field in [
            self.transcript,
            self.configuration,
            self.carrier,
            self.outer,
            self.initiator_noise.0,
            self.responder_noise.0,
        ] {
            bytes[offset..offset + 32].copy_from_slice(&field);
            offset += 32;
        }
        bytes
    }
}

/// Fixed new proof bytes containing public identity and a signature, never secrets.
pub struct MemberProof([u8; MEMBER_PROOF_BYTES]);
impl MemberProof {
    /// Prove existing client membership over the fixed new session-binding domain.
    pub fn sign(member: &IdentityKey, context: Context) -> Result<Self, Error> {
        context.validate()?;
        let mut bytes = [0; MEMBER_PROOF_BYTES];
        bytes[0] = 1;
        bytes[1] = 1;
        bytes[2..PROOF_PREFIX].copy_from_slice(&member.public_key().0);
        let prefix = bytes[..PROOF_PREFIX]
            .try_into()
            .map_err(|_| Error::InvalidProof)?;
        let signature = member.sign(&context.signed(&prefix))?;
        bytes[PROOF_PREFIX..].copy_from_slice(&signature);
        Ok(Self(bytes))
    }
    /// Admit only the exact version-one initiator/client proof structure.
    /// This parser does not itself verify membership or signature possession.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let bytes: [u8; MEMBER_PROOF_BYTES] = bytes.try_into().map_err(|_| Error::InvalidProof)?;
        if bytes[0] != 1 || bytes[1] != 1 {
            return Err(Error::InvalidProof);
        }
        Ok(Self(bytes))
    }
    /// Exact bounded public proof bytes, suitable for an authenticated Joining record.
    pub fn as_bytes(&self) -> &[u8; MEMBER_PROOF_BYTES] {
        &self.0
    }
}

/// Verify actual allowlisted member possession against the exact local context.
pub fn verify_member(
    proof: &[u8],
    context: Context,
    members: &Allowlist,
) -> Result<MemberPublicKey, Error> {
    context.validate()?;
    let proof = MemberProof::from_bytes(proof)?;
    let prefix = proof.0[..PROOF_PREFIX]
        .try_into()
        .map_err(|_| Error::InvalidProof)?;
    let member = MemberPublicKey(
        proof.0[2..PROOF_PREFIX]
            .try_into()
            .map_err(|_| Error::InvalidProof)?,
    );
    if !members.contains(member) {
        return Err(Error::MemberDenied);
    }
    verify_signature(member, &context.signed(&prefix), &proof.0[PROOF_PREFIX..])?;
    Ok(member)
}

/// Caller-supplied monotonic microseconds in the unchanged session clock domain.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct Time(pub u64);

/// Server-side root custody for one authenticated membership-admission attempt.
/// Joining owners can be reserved before construction; user domains stay private.
pub struct ServerPending {
    root: SessionRoot,
    context: Context,
    members: Allowlist,
    now: Time,
    deadline: Time,
}
impl ServerPending {
    /// Hold a completed pinned Noise root whose public binding matches this proof.
    /// The trusted server controller must supply its own responder root/context.
    pub fn new(
        root: SessionRoot,
        context: Context,
        members: Allowlist,
        now: Time,
        deadline: Time,
    ) -> Result<Self, Error> {
        context.validate()?;
        if now >= deadline {
            return Err(Error::Deadline);
        }
        let binding = root.binding();
        if root.role() != Role::Responder
            || binding.session != context.session
            || binding.transcript != context.transcript
        {
            return Err(Error::BindingMismatch);
        }
        Ok(Self {
            root,
            context,
            members,
            now,
            deadline,
        })
    }
    /// Original absolute membership deadline, never renewed by a proof.
    pub fn deadline(&self) -> Time {
        self.deadline
    }
    /// Consume one actual protected membership attempt; failure drops the held root.
    /// Reject unauthenticated carrier/Joining bytes before calling this method.
    pub fn accept(self, now: Time, proof: &[u8]) -> Result<AuthenticatedMember, Error> {
        if now < self.now || now >= self.deadline {
            return Err(Error::Deadline);
        }
        let member = verify_member(proof, self.context, &self.members)?;
        Ok(AuthenticatedMember {
            root: self.root,
            member,
        })
    }
}

/// A root released only after this server's allowlisted member proof verified.
pub struct AuthenticatedMember {
    /// Original opaque root, retaining all previously reserved ownership domains.
    pub root: SessionRoot,
    /// Verified client Ed25519 identity for non-secret session status.
    pub member: MemberPublicKey,
}

/// Bounded public rejection without private bytes or provider diagnostics.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// Invalid or oversized PKCS#8 encoding, without retaining private input.
    InvalidKey,
    /// Public allowlist input was empty or exceeded 1024 entries.
    InvalidAllowlist,
    /// A generic signing/verification transcript exceeded its work bound.
    TooLarge,
    /// Exact Ed25519 signature size or maintained verification failed.
    InvalidSignature,
    /// Fixed proof length, version or initiator role is invalid.
    InvalidProof,
    /// The proof's public member identity is outside the configured allowlist.
    MemberDenied,
    /// Reflected Noise identities or root role/session/transcript mismatch.
    BindingMismatch,
    /// Original deadline expired or supplied monotonic time moved backwards.
    Deadline,
}
impl fmt::Display for Error {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(output, "member identity error: {self:?}")
    }
}
impl std::error::Error for Error {}

#[cfg(test)]
mod tests;
