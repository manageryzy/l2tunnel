//! Fixed HTTPS request admission proof, before any tunnel-specific response.
//!
//! The HTTPS adapter owns exactly one [`Attempt`] per original verified TLS
//! connection and closes after any rejected attempt. This does not authenticate
//! arbitrary I/O or replace the later fresh member challenge exchange.
use super::*;

const DOMAIN: &[u8] = b"l2tunnel/https-h2-request/v1\0";
/// Fixed public proof size: version, member, nonce and Ed25519 signature.
pub const PROOF_BYTES: usize = 129;

/// Canonical POST target and complete HTTPS policy digest.
#[derive(Clone)]
pub struct Request {
    authority: String,
    path: String,
    profile: ConfigDigest,
}
impl Request {
    /// Require a lowercase ASCII DNS/IPv4 authority with optional decimal port,
    /// and an absolute visible ASCII path without query, fragment or escapes.
    /// The TLS verification name remains a separate, mandatory trust input.
    pub fn new(authority: &str, path: &str, profile: ConfigDigest) -> Result<Self, Error> {
        if authority.is_empty()
            || authority.len() > 255
            || !authority
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b".-:".contains(&b))
            || authority.split(':').count() > 2
            || authority.split(':').next().is_none_or(|h| {
                h.is_empty() || h.starts_with('.') || h.ends_with('.') || h.contains("..")
            })
            || authority.split_once(':').is_some_and(|(_, p)| {
                p.is_empty() || p.parse::<u16>().is_err() || p == "0" || p.starts_with('0')
            })
            || path.is_empty()
            || path.len() > 512
            || !path.starts_with('/')
            || !path
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"/-._~".contains(&b))
            || path.contains("//")
            || path.split('/').any(|p| p == "." || p == "..")
        {
            return Err(Error::Configuration(
                "invalid canonical HTTPS request target",
            ));
        }
        Ok(Self {
            authority: authority.into(),
            path: path.into(),
            profile,
        })
    }
    /// Canonical request authority; it never grants certificate trust.
    pub fn authority(&self) -> &str {
        &self.authority
    }
    /// Canonical absolute POST path.
    pub fn path(&self) -> &str {
        &self.path
    }
}

/// Public, fixed proof bytes; contains no private key or exporter.
pub struct Proof([u8; PROOF_BYTES]);
impl Proof {
    /// Exact bounded bytes for opaque Authorization encoding.
    pub fn as_bytes(&self) -> &[u8; PROOF_BYTES] {
        &self.0
    }
}

fn transcript(
    binding: &CallerVerifiedChannel,
    config: SessionConfig,
    request: &Request,
    prefix: &[u8],
) -> Zeroizing<Vec<u8>> {
    let mut value = Zeroizing::new(Vec::with_capacity(1024));
    value.extend_from_slice(DOMAIN);
    value.extend_from_slice(&binding.exporter[..]);
    value.extend_from_slice(&binding.server.0);
    value.push(layer_byte(config.layer));
    value.extend_from_slice(&config.digest.0);
    value.extend_from_slice(&request.profile.0);
    for field in [
        b"POST".as_slice(),
        request.authority.as_bytes(),
        request.path.as_bytes(),
    ] {
        value.extend_from_slice(&(field.len() as u16).to_be_bytes());
        value.extend_from_slice(field);
    }
    value.extend_from_slice(prefix);
    value
}

/// Sign with a fresh OS-random nonce on the exact verified HTTPS TLS exporter.
/// CallerVerifiedChannel's certificate/name/TLS verification preconditions apply.
pub fn sign(
    member: &MemberKey,
    binding: &CallerVerifiedChannel,
    config: SessionConfig,
    request: &Request,
) -> Result<Proof, Error> {
    if binding.transport != ChannelTransport::HttpsH2 {
        return Err(Error::Configuration("HTTPS transport required"));
    }
    let mut value = [0; PROOF_BYTES];
    value[0] = 1;
    value[1..33].copy_from_slice(&member.public_key().0);
    SystemRandom::new()
        .fill(&mut value[33..65])
        .map_err(|_| Error::Random)?;
    let signature = member
        .0
        .sign(&transcript(binding, config, request, &value[..65]));
    value[65..].copy_from_slice(signature.as_ref());
    Ok(Proof(value))
}

/// One admission attempt, including malformed or rejected requests, per TLS owner.
#[derive(Default)]
pub struct Attempt {
    used: bool,
}
impl Attempt {
    /// Consume before all validation; every rejection is the same public error.
    /// The HTTP adapter maps all errors to its identical bounded ordinary reply.
    pub fn verify_once(
        &mut self,
        proof: &[u8],
        members: &MemberAllowlist,
        binding: &CallerVerifiedChannel,
        config: SessionConfig,
        request: &Request,
    ) -> Result<MemberPublicKey, Error> {
        if std::mem::replace(&mut self.used, true)
            || binding.transport != ChannelTransport::HttpsH2
            || proof.len() != PROOF_BYTES
            || proof[0] != 1
        {
            return Err(Error::InvalidProof);
        }
        let mut public = [0; 32];
        public.copy_from_slice(&proof[1..33]);
        let public = MemberPublicKey(public);
        if !members.contains(public) {
            return Err(Error::InvalidProof);
        }
        UnparsedPublicKey::new(&ED25519, public.0)
            .verify(
                &transcript(binding, config, request, &proof[..65]),
                &proof[65..],
            )
            .map_err(|_| Error::InvalidProof)?;
        Ok(public)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn binding(transport: ChannelTransport, server: u8, exporter: u8) -> CallerVerifiedChannel {
        CallerVerifiedChannel::new_after_verification(
            transport,
            ServerIdentity([server; 32]),
            [exporter; 32],
        )
    }
    #[test]
    fn request_proof_binds_every_context_and_consumes_rejected_attempt() -> Result<(), Error> {
        let key = MemberKey::from_pkcs8(&MemberKey::generate_pkcs8()?)?;
        let members = MemberAllowlist::new(&[key.public_key()])?;
        let config = SessionConfig {
            layer: PacketLayer::Ip,
            digest: ConfigDigest([1; 32]),
        };
        let request = Request::new("lab.invalid:443", "/stream", ConfigDigest([2; 32]))?;
        let channel = binding(ChannelTransport::HttpsH2, 3, 4);
        let proof = sign(&key, &channel, config, &request)?;
        assert_eq!(
            Attempt::default().verify_once(
                proof.as_bytes(),
                &members,
                &channel,
                config,
                &request
            )?,
            key.public_key()
        );
        let second = sign(&key, &channel, config, &request)?;
        assert_ne!(proof.as_bytes(), second.as_bytes());
        for wrong in [
            binding(ChannelTransport::TcpTls, 3, 4),
            binding(ChannelTransport::QuicTls, 3, 4),
            binding(ChannelTransport::OpenVpnLikeTls, 3, 4),
            binding(ChannelTransport::HttpsH2, 9, 4),
            binding(ChannelTransport::HttpsH2, 3, 9),
        ] {
            assert!(
                Attempt::default()
                    .verify_once(proof.as_bytes(), &members, &wrong, config, &request)
                    .is_err()
            );
        }
        for wrong in [
            SessionConfig {
                layer: PacketLayer::Ethernet,
                ..config
            },
            SessionConfig {
                digest: ConfigDigest([9; 32]),
                ..config
            },
        ] {
            assert!(
                Attempt::default()
                    .verify_once(proof.as_bytes(), &members, &channel, wrong, &request)
                    .is_err()
            );
        }
        for wrong in [
            Request::new("other.invalid:443", "/stream", ConfigDigest([2; 32]))?,
            Request::new("lab.invalid:443", "/other", ConfigDigest([2; 32]))?,
            Request::new("lab.invalid:443", "/stream", ConfigDigest([9; 32]))?,
        ] {
            assert!(
                Attempt::default()
                    .verify_once(proof.as_bytes(), &members, &channel, config, &wrong)
                    .is_err()
            );
        }
        for bytes in [
            vec![],
            proof.as_bytes()[..128].to_vec(),
            vec![0; 129],
            vec![1; 130],
        ] {
            let mut attempt = Attempt::default();
            assert!(
                attempt
                    .verify_once(&bytes, &members, &channel, config, &request)
                    .is_err()
            );
            assert!(
                attempt
                    .verify_once(proof.as_bytes(), &members, &channel, config, &request)
                    .is_err()
            );
        }
        let mut once = Attempt::default();
        once.verify_once(proof.as_bytes(), &members, &channel, config, &request)?;
        assert!(
            once.verify_once(proof.as_bytes(), &members, &channel, config, &request)
                .is_err()
        );
        let other = MemberKey::from_pkcs8(&MemberKey::generate_pkcs8()?)?;
        assert!(
            Attempt::default()
                .verify_once(
                    proof.as_bytes(),
                    &MemberAllowlist::new(&[other.public_key()])?,
                    &channel,
                    config,
                    &request
                )
                .is_err()
        );
        for index in [0, 1, 32, 33, 64, 65, 128] {
            let mut bad = *proof.as_bytes();
            bad[index] ^= 1;
            assert!(
                Attempt::default()
                    .verify_once(&bad, &members, &channel, config, &request)
                    .is_err()
            );
        }
        Ok(())
    }
    #[test]
    fn canonical_request_limits_and_distinct_transport_domains() {
        for authority in [
            "",
            "Lab.invalid",
            "a@b",
            "a b",
            "a:0",
            "a:0443",
            "a:",
            "a:65536",
            ".a",
            "a..b",
        ] {
            assert!(Request::new(authority, "/stream", ConfigDigest([0; 32])).is_err());
        }
        assert!(Request::new(&"a".repeat(256), "/", ConfigDigest([0; 32])).is_err());
        assert!(
            Request::new(
                "lab.invalid",
                &format!("/{}", "a".repeat(512)),
                ConfigDigest([0; 32])
            )
            .is_err()
        );
        for path in [
            "", "stream", "/a?b", "/a#b", "/%61", "/a/../b", "//a", "/a b",
        ] {
            assert!(Request::new("lab.invalid", path, ConfigDigest([0; 32])).is_err());
        }
        for other in [
            ChannelTransport::TcpTls,
            ChannelTransport::QuicTls,
            ChannelTransport::OpenVpnLikeTls,
        ] {
            assert_ne!(
                other.exporter_label(),
                ChannelTransport::HttpsH2.exporter_label()
            );
            assert_ne!(
                other.transcript_domain(),
                ChannelTransport::HttpsH2.transcript_domain()
            );
        }
    }
}
