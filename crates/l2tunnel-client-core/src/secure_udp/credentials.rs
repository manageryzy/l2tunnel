//! Explicit runtime provisioning owners; no automatic key generation or TLS shim.
use l2tunnel_handshake as hs;
use l2tunnel_identity as identity;
use l2tunnel_runtime::secure_udp::establish;
use l2tunnel_security::Role;
use l2tunnel_udp_control as gate;
use std::{io, sync::Arc};
use zeroize::Zeroizing;

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

/// Reusable own static identity, with fresh consuming owners for each exchange.
/// Fresh ephemeral generation remains the handshake runtime's responsibility.
pub struct NoiseIdentity {
    private: Zeroizing<[u8; 32]>,
    public: hs::PeerKey,
    peer: hs::PeerKey,
    profile: hs::Profile,
    psk: Option<Zeroizing<[u8; 32]>>,
}
impl NoiseIdentity {
    /// Import distinct explicitly provisioned Noise material; never convert Ed25519.
    pub fn new(
        private: Zeroizing<[u8; 32]>,
        peer: hs::PeerKey,
        profile: hs::Profile,
        psk: Option<Zeroizing<[u8; 32]>>,
    ) -> io::Result<Self> {
        if *private == [0; 32]
            || peer.0 == [0; 32]
            || matches!(profile, hs::Profile::IkPsk2) != psk.is_some()
            || psk
                .as_ref()
                .is_some_and(|psk| **psk == [0; 32] || **psk == *private)
        {
            return Err(invalid("invalid or overlapping explicit Noise credentials"));
        }
        let public = hs::LocalSecret::new(Zeroizing::new(*private)).public_key();
        if public == peer {
            return Err(invalid("Noise peer must be a distinct pinned identity"));
        }
        Ok(Self {
            private,
            public,
            peer,
            profile,
            psk,
        })
    }
    /// Actual own public identity, without private material.
    pub const fn public_key(&self) -> hs::PeerKey {
        self.public
    }
    /// Explicit remote trust anchor, without certificate/name inference.
    pub const fn peer(&self) -> hs::PeerKey {
        self.peer
    }
    /// Required fixed Noise pattern; never selected by a peer packet.
    pub const fn profile(&self) -> hs::Profile {
        self.profile
    }
    /// Global ordered peer identities for canonical profile validation.
    pub fn peers(&self, role: Role) -> establish::Peers {
        let (initiator, responder) = match role {
            Role::Initiator => (self.public, self.peer),
            Role::Responder => (self.peer, self.public),
        };
        establish::Peers {
            initiator,
            responder,
        }
    }
    pub(crate) fn attempt(&self) -> establish::Identity {
        establish::Identity {
            local: hs::LocalSecret::new(Zeroizing::new(*self.private)),
            peer: self.peer,
            psk: self
                .psk
                .as_ref()
                .map(|psk| hs::Psk::new(Zeroizing::new(**psk))),
        }
    }
    fn overlaps(&self, other: &Secret32) -> bool {
        *self.private == *other.0 || self.psk.as_ref().is_some_and(|psk| **psk == *other.0)
    }
}

/// One separately provisioned unpredictable admission or server-only cookie key.
pub struct Secret32(Zeroizing<[u8; 32]>);
impl Secret32 {
    /// Import a private raw32 secret; no public digest or zero fallback is accepted.
    pub fn new(bytes: Zeroizing<[u8; 32]>) -> io::Result<Self> {
        if *bytes == [0; 32] {
            return Err(invalid("all-zero provisioning secret"));
        }
        Ok(Self(bytes))
    }
    pub(crate) fn attempt(&self) -> gate::Secret {
        gate::Secret::new(*self.0)
    }
}

/// Fixed client trust and existing member possession, with no TLS placeholder.
pub struct Client {
    noise: NoiseIdentity,
    member: Arc<identity::IdentityKey>,
    admission: Secret32,
}
impl Client {
    /// Preserve the actual existing Ed25519 identity and independent admission key.
    pub fn new(
        noise: NoiseIdentity,
        member: identity::IdentityKey,
        admission: Secret32,
    ) -> io::Result<Self> {
        if noise.overlaps(&admission) {
            return Err(invalid("admission and Noise secrets overlap"));
        }
        Ok(Self {
            noise,
            member: Arc::new(member),
            admission,
        })
    }
    /// Observe only the configured existing member identity.
    pub fn member_key(&self) -> identity::MemberPublicKey {
        self.member.public_key()
    }
    /// Public Noise identity/profile; no raw secret accessor exists.
    pub fn noise(&self) -> &NoiseIdentity {
        &self.noise
    }
    pub(crate) fn member(&self) -> &identity::IdentityKey {
        &self.member
    }
    pub(crate) fn admission(&self) -> gate::Secret {
        self.admission.attempt()
    }
}

/// Fixed server trust and independent admission/cookie inputs.
/// The service plan separately retains the initialized gate and its quarantine.
pub struct Server {
    noise: NoiseIdentity,
    admission: Secret32,
    cookie: Secret32,
}
impl Server {
    /// Explicitly preserve server-only cookie custody and purpose separation.
    pub fn new(noise: NoiseIdentity, admission: Secret32, cookie: Secret32) -> io::Result<Self> {
        if *admission.0 == *cookie.0 || noise.overlaps(&admission) || noise.overlaps(&cookie) {
            return Err(invalid("server purpose credentials must be independent"));
        }
        Ok(Self {
            noise,
            admission,
            cookie,
        })
    }
    /// Public Noise identity/profile only.
    pub fn noise(&self) -> &NoiseIdentity {
        &self.noise
    }
    pub(crate) fn admission(&self) -> gate::Secret {
        self.admission.attempt()
    }
    pub(crate) fn cookie(&self) -> gate::Secret {
        self.cookie.attempt()
    }
}

#[cfg(unix)]
fn private_permissions(owner: u32, mode: u32, effective: u32) -> bool {
    owner == effective && mode & 0o077 == 0
}

fn read_file(
    path: &std::path::Path,
    maximum: usize,
    private: bool,
) -> io::Result<Zeroizing<Vec<u8>>> {
    use std::io::Read;
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(
            (rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NONBLOCK).bits() as i32,
        );
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    let file = options.open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "credential must be a regular file",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if private
            && !private_permissions(
                metadata.uid(),
                metadata.mode(),
                rustix::process::geteuid().as_raw(),
            )
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "credential must be a private owned regular file",
            ));
        }
    }
    #[cfg(not(unix))]
    let _ = private;
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;
        if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "credential must not be a reparse point",
            ));
        }
        // The Windows access check remains the operating system's file open.
        // This reader does not claim to inspect or qualify the file's ACL.
    }
    let mut bytes = Zeroizing::new(Vec::new());
    #[cfg(windows)]
    let read_max = if private {
        maximum.saturating_mul(2).saturating_add(1024)
    } else {
        maximum
    };
    #[cfg(not(windows))]
    let read_max = maximum;
    let limit = u64::try_from(read_max)
        .ok()
        .and_then(|bound| bound.checked_add(1))
        .ok_or_else(|| invalid("credential length overflow"))?;
    file.take(limit).read_to_end(&mut bytes)?;
    if bytes.len() > read_max {
        return Err(invalid("credential file exceeds exact bound"));
    }
    #[cfg(windows)]
    if private && l2tunnel_platform_windows::dpapi::is_sealed(&bytes) {
        bytes = l2tunnel_platform_windows::dpapi::unprotect_secret(&bytes)?;
    }
    if bytes.len() > maximum {
        return Err(invalid("credential file exceeds exact bound"));
    }
    Ok(bytes)
}

/// Read an exact private raw32 input from a bounded regular file.
/// Unix checks owner/mode; Windows relies on OS access checks and rejects reparse points.
pub fn read_secret(path: &std::path::Path) -> io::Result<Zeroizing<[u8; 32]>> {
    let bytes = read_file(path, 32, true)?;
    let mut secret = Zeroizing::new([0; 32]);
    if bytes.len() != secret.len() {
        return Err(invalid(
            "private credential must contain exactly32 raw bytes",
        ));
    }
    secret.copy_from_slice(&bytes);
    Ok(secret)
}

/// Read an exact public raw32 pin/member identity.
/// Unix rejects final symlinks; Windows rejects opened reparse points.
pub fn read_public(path: &std::path::Path) -> io::Result<[u8; 32]> {
    let bytes = read_file(path, 32, false)?;
    bytes
        .as_slice()
        .try_into()
        .map_err(|_| invalid("public identity must contain exactly32 raw bytes"))
}

/// Parse the unchanged existing member PKCS#8 format from a bounded private file.
pub fn read_member(path: &std::path::Path) -> io::Result<identity::IdentityKey> {
    identity::IdentityKey::from_pkcs8(&read_member_der(path)?).map_err(io::Error::other)
}

/// Read once for the maintained inner and TLS member parsers, with identical limits.
pub(crate) fn read_member_der(path: &std::path::Path) -> io::Result<Zeroizing<Vec<u8>>> {
    read_file(path, 4096, true)
}

#[cfg(test)]
#[path = "credentials_tests.rs"]
mod tests;
