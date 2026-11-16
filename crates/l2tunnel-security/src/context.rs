use crate::{
    COMMON_PREFIX_BYTES, Error, MAX_BODY_BYTES, MAX_BODY_BYTES_PER_KEY, MAX_DOMAINS,
    MAX_METADATA_BYTES, MAX_PACKET_BYTES, MAX_PACKETS_PER_KEY, Receiver, Sender, VERSION, keys,
    record::Profile,
};
use ring::hkdf;
use zeroize::Zeroizing;

/// Public identity of an authenticated session, distinct from any root secret.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SessionId(pub [u8; 16]);
/// Authenticated physical lane, independent of user ordering channels.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LaneId(pub u32);
/// Data-profile epoch; changing it never resets the security packet counter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Epoch(pub u64);
/// Canonical authenticated configuration digest supplied by the session owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConfigDigest(pub [u8; 32]);

/// Local endpoint role; global directions are identical at both endpoints.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Role {
    /// Endpoint that initiated the authenticated handshake.
    Initiator,
    /// Endpoint that answered the authenticated handshake.
    Responder,
}
/// Global cryptographic packet direction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Direction {
    /// Initiator sends and responder receives.
    InitiatorToResponder = 1,
    /// Responder sends and initiator receives.
    ResponderToInitiator = 2,
}
impl Role {
    pub(crate) fn sending(self) -> Direction {
        match self {
            Self::Initiator => Direction::InitiatorToResponder,
            Self::Responder => Direction::ResponderToInitiator,
        }
    }
    pub(crate) fn receiving(self) -> Direction {
        match self {
            Self::Initiator => Direction::ResponderToInitiator,
            Self::Responder => Direction::InitiatorToResponder,
        }
    }
}
/// Independent key purpose, never selected by unauthenticated packet bits.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Purpose {
    /// Opaque user-data algorithm records and their ordinary feedback.
    Data = 1,
    /// Stable authenticated management records.
    Management = 2,
    /// Authenticated physical-lane joining.
    Joining = 3,
    /// Separately negotiated session-recovery control.
    Recovery = 4,
}
/// Previously authenticated packet protection selection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Protection {
    /// ChaCha20-Poly1305 encryption and a 16-byte tag.
    ChaCha20Poly1305 = 1,
    /// Visible payload with a full, separately keyed HMAC-SHA256 tag.
    HmacSha256 = 2,
}
impl Protection {
    /// Bytes added by the selected authentication tag.
    pub const fn tag_bytes(self) -> usize {
        match self {
            Self::ChaCha20Poly1305 => 16,
            Self::HmacSha256 => 32,
        }
    }
    /// Exact complete common prefix/tag overhead, excluding carrier framing.
    pub const fn overhead_bytes(self) -> usize {
        COMMON_PREFIX_BYTES + self.tag_bytes()
    }
}

/// Fixed authenticated record/key bounds for one directional owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Limits {
    /// Largest accepted or protected opaque body.
    pub max_body_bytes: usize,
    /// Packet interval defining a key generation, from 1 through 2^28.
    pub packets_per_key: u64,
    /// Maximum total body bytes under one key generation, at most 2^40.
    pub max_body_bytes_per_key: u64,
}
impl Limits {
    pub(crate) fn validate(self) -> Result<(), Error> {
        if !(1..=MAX_BODY_BYTES).contains(&self.max_body_bytes)
            || self
                .max_body_bytes
                .checked_add(COMMON_PREFIX_BYTES + 32)
                .is_none_or(|size| size > MAX_PACKET_BYTES)
            || !(1..=MAX_PACKETS_PER_KEY).contains(&self.packets_per_key)
            || !(1..=MAX_BODY_BYTES_PER_KEY).contains(&self.max_body_bytes_per_key)
            || self.max_body_bytes as u64 > self.max_body_bytes_per_key
        {
            return Err(Error::InvalidLimits);
        }
        Ok(())
    }
}

/// Public authenticated transcript context; it is never a secret MAC key.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SessionBinding {
    /// Fresh authenticated session identity.
    pub session: SessionId,
    /// Final authenticated handshake hash, including peer/carrier/configuration binding.
    pub transcript: [u8; 32],
}

/// Metadata authenticated with a common-format packet, supplied by its staged reader.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Metadata<'a> {
    /// Data/control epoch whose state may process the authenticated record.
    pub epoch: Epoch,
    /// Complete configuration digest selected for that epoch.
    pub configuration: ConfigDigest,
    /// Additional length-delimited authenticated carrier/header bytes, at most 256.
    pub extra: &'a [u8],
}
impl Metadata<'_> {
    pub(crate) fn validate(self) -> Result<(), Error> {
        if self.extra.len() > MAX_METADATA_BYTES {
            return Err(Error::TooLarge);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct Domain {
    purpose: Purpose,
    direction: Direction,
    lane: LaneId,
}

/// Owned, zeroizing session root with bounded unique packet-domain ownership.
///
/// No raw key getter, cloning or secret Debug formatting is provided. The caller
/// must consume the maintained handshake's split keys once and stop using that
/// original transport; recreating a root with the same keys/binding is forbidden.
pub struct SessionRoot {
    root: Zeroizing<[u8; 32]>,
    binding: SessionBinding,
    role: Role,
    owners: Vec<Domain>,
}
impl SessionRoot {
    pub(crate) fn derive_compact(
        &mut self,
        purpose: Purpose,
        direction: Direction,
        lane: LaneId,
        limits: Limits,
        protection: crate::compact::Protection,
        selection: crate::compact::Selection,
    ) -> Result<(Zeroizing<[u8; 32]>, [u8; 88]), Error> {
        selection.validate(limits)?;
        if purpose != Purpose::Data && !protection.authenticated_control() {
            return Err(Error::ContextMismatch);
        }
        let domain = Domain {
            purpose,
            direction,
            lane,
        };
        if self.owners.contains(&domain) {
            return Err(Error::DomainInUse);
        }
        if self.owners.len() == MAX_DOMAINS {
            return Err(Error::DomainCapacity);
        }
        let mut context = [0; 88];
        context[..4].copy_from_slice(&[
            crate::compact::VERSION,
            protection as u8,
            purpose as u8,
            direction as u8,
        ]);
        context[4..8].copy_from_slice(&lane.0.to_be_bytes());
        context[8..24].copy_from_slice(&self.binding.session.0);
        context[24..56].copy_from_slice(&self.binding.transcript);
        context[56..64].copy_from_slice(&(limits.max_body_bytes as u64).to_be_bytes());
        context[64..72].copy_from_slice(&limits.packets_per_key.to_be_bytes());
        context[72..80].copy_from_slice(&limits.max_body_bytes_per_key.to_be_bytes());
        context[80..84].copy_from_slice(&selection.max_forward_packets.to_be_bytes());
        context[84..88].copy_from_slice(&selection.max_failed_checks.to_be_bytes());
        let root = keys::expand(
            &hkdf::Prk::new_less_safe(hkdf::HKDF_SHA256, &self.root[..]),
            &[b"l2tunnel/packet/v3/compact-domain\0", &context],
        )?;
        self.owners.push(domain);
        Ok((root, context))
    }
    pub(crate) fn managed_registry(&self, lane: LaneId, retired_joining: bool) -> bool {
        if !retired_joining {
            return self.owners.is_empty();
        }
        self.owners.len() == 2
            && self
                .owners
                .iter()
                .all(|domain| domain.purpose == Purpose::Joining && domain.lane == lane)
            && self.owners[0].direction != self.owners[1].direction
    }
    /// Public authenticated session/transcript context, never a secret MAC key.
    /// This observation creates no owner and changes no key, replay or counter.
    pub const fn binding(&self) -> SessionBinding {
        self.binding
    }

    /// Authenticated local endpoint role, without exporting secret material.
    pub const fn role(&self) -> Role {
        self.role
    }

    /// Consume global-direction split keys and bind a standard HKDF root to
    /// the authenticated session/transcript. The inputs are zeroized on drop.
    pub fn from_split_keys(
        initiator_to_responder: Zeroizing<[u8; 32]>,
        responder_to_initiator: Zeroizing<[u8; 32]>,
        binding: SessionBinding,
        role: Role,
    ) -> Result<Self, Error> {
        let mut input = Zeroizing::new([0; 64]);
        input[..32].copy_from_slice(&initiator_to_responder[..]);
        input[32..].copy_from_slice(&responder_to_initiator[..]);
        let mut salt = [0; 48];
        salt[..16].copy_from_slice(&binding.session.0);
        salt[16..].copy_from_slice(&binding.transcript);
        let extracted = hkdf::Salt::new(hkdf::HKDF_SHA256, &salt).extract(&input[..]);
        let root = keys::expand(&extracted, &[b"l2tunnel packet security v1 session root"])?;
        Ok(Self {
            root,
            binding,
            role,
            owners: Vec::with_capacity(MAX_DOMAINS),
        })
    }
    fn derive(
        &mut self,
        purpose: Purpose,
        direction: Direction,
        lane: LaneId,
        limits: Limits,
        protection: Protection,
    ) -> Result<(Zeroizing<[u8; 32]>, Profile), Error> {
        limits.validate()?;
        let domain = Domain {
            purpose,
            direction,
            lane,
        };
        if self.owners.contains(&domain) {
            return Err(Error::DomainInUse);
        }
        if self.owners.len() == MAX_DOMAINS {
            return Err(Error::DomainCapacity);
        }
        let mut context = [0; 56];
        context[..4].copy_from_slice(&[VERSION, protection as u8, purpose as u8, direction as u8]);
        context[4..8].copy_from_slice(&lane.0.to_be_bytes());
        context[8..24].copy_from_slice(&self.binding.session.0);
        context[24..].copy_from_slice(&self.binding.transcript);
        let root = keys::expand(
            &hkdf::Prk::new_less_safe(hkdf::HKDF_SHA256, &self.root[..]),
            &[b"l2tunnel packet security v1 domain", &context],
        )?;
        self.owners.push(domain);
        Ok((
            root,
            Profile::Common {
                context,
                protection,
            },
        ))
    }
    /// Reserve the unique local sending owner for this purpose/lane.
    pub fn sender(
        &mut self,
        purpose: Purpose,
        lane: LaneId,
        limits: Limits,
        protection: Protection,
    ) -> Result<Sender, Error> {
        let (root, profile) =
            self.derive(purpose, self.role.sending(), lane, limits, protection)?;
        Sender::new(root, limits, profile)
    }
    /// Reserve the unique peer sending owner and replay window for this purpose/lane.
    pub fn receiver(
        &mut self,
        purpose: Purpose,
        lane: LaneId,
        limits: Limits,
        protection: Protection,
    ) -> Result<Receiver, Error> {
        let (root, profile) =
            self.derive(purpose, self.role.receiving(), lane, limits, protection)?;
        Receiver::new(root, limits, profile)
    }
}
