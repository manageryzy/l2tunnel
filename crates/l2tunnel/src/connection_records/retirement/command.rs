//! One bounded grammar inside the existing authenticated Transaction stream.
//! Parsing attested control proves no cryptography; the runtime must supply actual
//! Records/Control ingress. No route data, booleans or public fence fields mint proof.
use super::*;
use crate::packet::FlowKey;
use l2tunnel_management::{Ingress, session_control as sc};
use ring::digest;

/// Maximum exact command, including two complete canonical native flow keys.
pub const MAX_BYTES: usize = 288;
const HEADER: usize = 164;
/// Explicit progress grammar; all stages retain one immutable operation/cap.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Kind {
    /// Stop old local admission and announce its frozen total.
    Stop = 1,
    /// Announce the responder's stopped old-admission total.
    Stopped = 2,
    /// Transport actual locally drained crossed native counters.
    Fence = 3,
    /// Confirm actual closed installation after crossed fences.
    Installed = 4,
    /// Request activation after actual matching peer installation.
    Activate = 5,
    /// Confirm the responder's actual activation.
    Activated = 6,
    /// Confirm the coordinator's concrete activation prerequisites.
    Done = 7,
    /// Final semantic reply, independently retained by reliable Control.
    DoneAck = 8,
}
/// Opaque command admitted against the actual current session/role/lane/scope.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Command {
    operation: transaction::Operation,
    lifetime_ms: u64,
    pub(super) owner: OwnerId,
    pub(super) incarnation: u64,
    pub(super) next: u64,
    pub(super) old_key: FlowKey,
    pub(super) next_key: FlowKey,
    pub(super) admitted: u64,
    pub(super) written: u64,
    pub(super) kind: Kind,
}
#[allow(clippy::too_many_arguments)] // Keep every authenticated operation binding explicit.
fn target(
    identity: transaction::Identity,
    origin: sc::Scope,
    attempt: u64,
    lifetime_ms: u64,
    owner: OwnerId,
    incarnation: u64,
    old_key: FlowKey,
    next_key: FlowKey,
) -> ConfigDigest {
    let mut hash = digest::Context::new(&digest::SHA256);
    hash.update(b"l2tunnel/control/slot-reuse/v1\0");
    hash.update(&identity.session.0);
    hash.update(&identity.lane.0.to_be_bytes());
    let (client, server) = if identity.role == Role::Client {
        (identity.local, identity.remote)
    } else {
        (identity.remote, identity.local)
    };
    for id in [client, server] {
        hash.update(&id.0.to_be_bytes());
    }
    hash.update(&origin.epoch.0.to_be_bytes());
    hash.update(&origin.digest.0);
    hash.update(&attempt.to_be_bytes());
    hash.update(&lifetime_ms.to_be_bytes());
    hash.update(&owner.index().to_be_bytes());
    hash.update(&incarnation.to_be_bytes());
    for key in [old_key, next_key] {
        let bytes = key.canonical_bytes();
        hash.update(&[bytes.as_slice().len() as u8]);
        hash.update(bytes.as_slice());
    }
    let value = hash.finish();
    let mut bytes = [0; 32];
    bytes.copy_from_slice(value.as_ref());
    ConfigDigest(bytes)
}
impl Command {
    /// Create a local proposal from actual retained identity and original cap.
    /// This requests work; it contains neither a peer fence nor an Installed proof.
    #[allow(clippy::too_many_arguments)]
    pub fn begin(
        identity: transaction::Identity,
        origin: sc::Scope,
        attempt: u64,
        owner: u16,
        incarnation: u64,
        old_key: FlowKey,
        next_key: FlowKey,
        now: transaction::Tick,
        cap: transaction::Tick,
        session_expires: transaction::Tick,
        maximum_ms: u64,
    ) -> Result<Self, Error> {
        if identity.role != Role::Client || old_key == next_key || incarnation == 0 {
            return Err(Error::RetirementConflict);
        }
        let next = incarnation.checked_add(1).ok_or(Error::Arithmetic)?;
        let owner = OwnerId(owner);
        let lifetime_ms = cap.0.checked_sub(now.0).ok_or(Error::RetirementExpired)?;
        let operation = transaction::Operation::slot_reuse(
            identity,
            origin,
            attempt,
            target(
                identity,
                origin,
                attempt,
                lifetime_ms,
                owner,
                incarnation,
                old_key,
                next_key,
            ),
            now,
            cap,
            session_expires,
            maximum_ms,
        )
        .map_err(|_| Error::RetirementExpired)?;
        Ok(Self {
            operation,
            lifetime_ms,
            owner,
            incarnation,
            next,
            old_key,
            next_key,
            admitted: 0,
            written: 0,
            kind: Kind::Stop,
        })
    }
    /// Full immutable selected identity with the retained local clock cap.
    pub fn operation(self) -> transaction::Operation {
        self.operation
    }
    /// Bounded cache lookup only; this is neither parsing nor authority.
    pub fn attempt_hint(envelope: sc::Envelope<'_>) -> Option<u64> {
        let sc::Body::ProfileControl {
            tag: sc::ProfileTag::SlotReuseV1,
            bytes,
        } = envelope.body
        else {
            return None;
        };
        Some(u64::from_be_bytes(bytes.get(64..72)?.try_into().ok()?))
    }
    /// Actual bounded semantic phase kind.
    pub fn kind(self) -> Kind {
        self.kind
    }
    /// Independent owner index; this label grants no native claim.
    pub fn owner(self) -> u16 {
        self.owner.index()
    }
    /// Exact original flow key committed by the operation.
    pub fn old_key(self) -> FlowKey {
        self.old_key
    }
    /// Exact proposed next key committed by the operation.
    pub fn next_key(self) -> FlowKey {
        self.next_key
    }
    /// Original route incarnation, never a cryptographic epoch.
    pub fn incarnation(self) -> u64 {
        self.incarnation
    }
    /// Checked next route incarnation, not proof of installation.
    pub fn next_incarnation(self) -> u64 {
        self.next
    }
    /// Actual stopped reliable-native admission total carried by this phase.
    pub fn admitted(self) -> u64 {
        self.admitted
    }
    /// Actual successful-native total carried by the drained phase.
    pub fn written(self) -> u64 {
        self.written
    }
    pub(crate) fn phase(mut self, kind: Kind, admitted: u64, written: u64) -> Self {
        self.kind = kind;
        self.admitted = admitted;
        self.written = written;
        self
    }
    pub(crate) fn mirrored(
        self,
        now: transaction::Tick,
        session: transaction::Tick,
        maximum: u64,
    ) -> Result<Self, Error> {
        let id = self.operation.identity();
        let local = transaction::Identity {
            role: if id.role == Role::Client {
                Role::Server
            } else {
                Role::Client
            },
            local: id.remote,
            remote: id.local,
            ..id
        };
        let operation = transaction::Operation::slot_reuse(
            local,
            self.operation.origin(),
            self.operation.ticket().attempt,
            self.operation.ticket().digest,
            now,
            self.operation.expires(),
            session,
            maximum,
        )
        .map_err(|_| Error::RetirementExpired)?;
        Ok(Self { operation, ..self })
    }
    pub(crate) fn matches(self, other: Self) -> bool {
        let a = self.operation;
        let b = other.operation;
        let x = a.identity();
        let y = b.identity();
        a.kind() == b.kind()
            && a.origin() == b.origin()
            && a.ticket() == b.ticket()
            && self.lifetime_ms == other.lifetime_ms
            && x.session == y.session
            && x.lane == y.lane
            && x.role != y.role
            && x.local == y.remote
            && x.remote == y.local
            && self.owner == other.owner
            && self.incarnation == other.incarnation
            && self.next == other.next
            && self.old_key == other.old_key
            && self.next_key == other.next_key
    }
    pub(crate) fn fence(self) -> Result<Fence, Error> {
        let id = self.operation.identity();
        let role = if id.role == Role::Client {
            EndpointRole::Initiator
        } else {
            EndpointRole::Responder
        };
        let origin = self.operation.origin();
        let scope = Scope::from_operation(
            RecoveryContext {
                session: u128::from_be_bytes(id.session.0),
                epoch: origin.epoch.0,
                role,
            },
            origin.digest,
            self.operation,
        )?;
        Ok(Fence {
            scope,
            owner: self.owner,
            incarnation: self.incarnation,
            key: self.old_key,
            admitted: self.admitted,
            written: self.written,
        })
    }
    pub(crate) fn installed(self) -> Result<Installed, Error> {
        Ok(Installed {
            fence: self.fence()?,
            next_incarnation: self.next,
        })
    }
    /// Checked exact encoding; no recovery/protocol state or caller bytes on refusal.
    pub fn encode(self, output: &mut [u8]) -> Result<usize, Error> {
        let old = self.old_key.canonical_bytes();
        let next = self.next_key.canonical_bytes();
        let size = HEADER
            .checked_add(old.as_slice().len())
            .and_then(|v| v.checked_add(next.as_slice().len()))
            .ok_or(Error::Arithmetic)?;
        let output = output
            .get_mut(..size)
            .ok_or(Error::Output { required: size })?;
        output.fill(0);
        output[..4].copy_from_slice(b"L2CR");
        output[4] = 1;
        output[5] = self.kind as u8;
        output[6..8].copy_from_slice(&self.owner.index().to_be_bytes());
        let id = self.operation.identity();
        let origin = self.operation.origin();
        output[8..24].copy_from_slice(&id.session.0);
        output[24..32].copy_from_slice(&origin.epoch.0.to_be_bytes());
        output[32..64].copy_from_slice(&origin.digest.0);
        output[64..72].copy_from_slice(&self.operation.ticket().attempt.to_be_bytes());
        output[72..80].copy_from_slice(&self.lifetime_ms.to_be_bytes());
        output[80..88].copy_from_slice(&self.incarnation.to_be_bytes());
        output[88..96].copy_from_slice(&self.next.to_be_bytes());
        output[96] = u8::from(id.role == Role::Server);
        for (range, id) in [(100..104, id.local), (104..108, id.remote)] {
            output[range].copy_from_slice(&id.0.to_be_bytes());
        }
        output[108..112].copy_from_slice(&id.lane.0.to_be_bytes());
        output[112..144].copy_from_slice(&self.operation.ticket().digest.0);
        output[144] = old.as_slice().len() as u8;
        output[145] = next.as_slice().len() as u8;
        output[148..156].copy_from_slice(&self.admitted.to_be_bytes());
        output[156..164].copy_from_slice(&self.written.to_be_bytes());
        output[HEADER..HEADER + old.as_slice().len()].copy_from_slice(old.as_slice());
        output[HEADER + old.as_slice().len()..].copy_from_slice(next.as_slice());
        Ok(size)
    }
    /// Accept only exact already authenticated/replay-checked Control provenance.
    /// Caller-supplied route/session bytes alone are never sufficient authority.
    #[allow(clippy::too_many_arguments)] // Provenance and original local timing are independent inputs.
    pub fn admit(
        envelope: sc::Envelope<'_>,
        verified: Ingress,
        local: transaction::Identity,
        origin: sc::Scope,
        now: transaction::Tick,
        session_expires: transaction::Tick,
        maximum_ms: u64,
        retained_local_operation: Option<transaction::Operation>,
    ) -> Result<Self, Error> {
        let sc::Body::ProfileControl {
            tag: sc::ProfileTag::SlotReuseV1,
            bytes,
        } = envelope.body
        else {
            return Err(Error::RetirementConflict);
        };
        let remote = if local.role == Role::Client {
            Role::Server
        } else {
            Role::Client
        };
        if verified
            != (Ingress::AuthenticatedManagement {
                session: local.session,
                lane: local.lane,
                sender: remote,
            })
            || envelope.binding.session != local.session
            || envelope.binding.lane != local.lane
            || envelope.binding.sender != remote
            || envelope.binding.scope != origin
            || envelope.binding.packet.0 == 0
            || !(HEADER..=MAX_BYTES).contains(&bytes.len())
            || &bytes[..4] != b"L2CR"
            || bytes[4] != 1
            || bytes[97..100] != [0; 3]
            || bytes[146..148] != [0; 2]
        {
            return Err(Error::RetirementConflict);
        }
        let kind = match bytes[5] {
            1 => Kind::Stop,
            2 => Kind::Stopped,
            3 => Kind::Fence,
            4 => Kind::Installed,
            5 => Kind::Activate,
            6 => Kind::Activated,
            7 => Kind::Done,
            8 => Kind::DoneAck,
            _ => return Err(Error::RetirementConflict),
        };
        fn u64_at(bytes: &[u8], offset: usize) -> Result<u64, Error> {
            Ok(u64::from_be_bytes(
                bytes
                    .get(offset..offset + 8)
                    .ok_or(Error::Invariant)?
                    .try_into()
                    .map_err(|_| Error::Invariant)?,
            ))
        }
        fn u32_at(bytes: &[u8], offset: usize) -> Result<u32, Error> {
            Ok(u32::from_be_bytes(
                bytes
                    .get(offset..offset + 4)
                    .ok_or(Error::Invariant)?
                    .try_into()
                    .map_err(|_| Error::Invariant)?,
            ))
        }
        let id = transaction::Identity {
            session: l2tunnel_management::SessionId(
                bytes[8..24].try_into().map_err(|_| Error::Invariant)?,
            ),
            role: match bytes[96] {
                0 => Role::Client,
                1 => Role::Server,
                _ => return Err(Error::RetirementConflict),
            },
            local: l2tunnel_management::EndpointId(u32_at(bytes, 100)?),
            remote: l2tunnel_management::EndpointId(u32_at(bytes, 104)?),
            lane: l2tunnel_management::LaneId(u32_at(bytes, 108)?),
        };
        if id.session != local.session
            || id.role != remote
            || id.local != local.remote
            || id.remote != local.local
            || id.lane != local.lane
            || u64_at(bytes, 24)? != origin.epoch.0
            || bytes[32..64] != origin.digest.0
        {
            return Err(Error::RetirementConflict);
        }
        let owner = OwnerId(u16::from_be_bytes(
            bytes[6..8].try_into().map_err(|_| Error::Invariant)?,
        ));
        let incarnation = u64_at(bytes, 80)?;
        let next = u64_at(bytes, 88)?;
        if incarnation == 0 || incarnation.checked_add(1) != Some(next) {
            return Err(Error::RetirementConflict);
        }
        let old_len = usize::from(bytes[144]);
        let next_len = usize::from(bytes[145]);
        let middle = HEADER.checked_add(old_len).ok_or(Error::Arithmetic)?;
        if middle.checked_add(next_len) != Some(bytes.len()) {
            return Err(Error::RetirementConflict);
        }
        let old_key =
            FlowKey::from_canonical_bytes(bytes.get(HEADER..middle).ok_or(Error::Invariant)?)
                .map_err(|_| Error::RetirementConflict)?;
        let next_key = FlowKey::from_canonical_bytes(bytes.get(middle..).ok_or(Error::Invariant)?)
            .map_err(|_| Error::RetirementConflict)?;
        if old_key == next_key {
            return Err(Error::RetirementConflict);
        }
        let attempt = u64_at(bytes, 64)?;
        let lifetime_ms = u64_at(bytes, 72)?;
        if lifetime_ms == 0 || lifetime_ms > maximum_ms {
            return Err(Error::RetirementExpired);
        }
        let expires = if let Some(operation) = retained_local_operation {
            operation.expires()
        } else {
            if kind != Kind::Stop || local.role != Role::Server {
                return Err(Error::RetirementConflict);
            }
            transaction::Tick(
                now.0
                    .checked_add(lifetime_ms)
                    .ok_or(Error::Arithmetic)?
                    .min(session_expires.0),
            )
        };
        let expected = target(
            id,
            origin,
            attempt,
            lifetime_ms,
            owner,
            incarnation,
            old_key,
            next_key,
        );
        if bytes[112..144] != expected.0 {
            return Err(Error::RetirementConflict);
        }
        let operation = if let Some(retained) = retained_local_operation {
            let peer = retained
                .mirror_slot_reuse()
                .map_err(|_| Error::RetirementConflict)?;
            if peer.identity() != id
                || peer.origin() != origin
                || peer.ticket().attempt != attempt
                || peer.ticket().digest != expected
            {
                return Err(Error::RetirementConflict);
            }
            peer
        } else {
            transaction::Operation::slot_reuse(
                id,
                origin,
                attempt,
                expected,
                now,
                expires,
                session_expires,
                maximum_ms,
            )
            .map_err(|_| Error::RetirementExpired)?
        };
        Ok(Self {
            operation,
            lifetime_ms,
            owner,
            incarnation,
            next,
            old_key,
            next_key,
            admitted: u64_at(bytes, 148)?,
            written: u64_at(bytes, 156)?,
            kind,
        })
    }
}
