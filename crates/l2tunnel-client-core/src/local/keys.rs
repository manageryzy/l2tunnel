//! Key files (owner decision 2026-11-23: keys stay files the profile options
//! name). Frontends generate key files locally and unprivileged; the service
//! reports, for a stored profile, what each referenced key file is and its
//! public key or certificate fingerprint. Private material is never returned.
use serde::{Deserialize, Serialize};
use std::io::{self, Write};
use std::path::Path;

/// Most key references in one reply.
pub const KEY_REFERENCE_LIMIT: usize = 16;
/// Largest TLS certificate read for a fingerprint.
const CERTIFICATE_LIMIT: usize = 65_536;

/// What a key option holds.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyRole {
    /// This member's Ed25519 identity (PKCS#8), `--identity`.
    MemberPrivate,
    /// The client member a server trusts, `--allow-key`.
    MemberTrusted,
    /// This side's Noise X25519 private key.
    NoisePrivate,
    /// The pinned Noise public key of the peer.
    NoisePeer,
    /// A shared 32-byte secret (admission, cookie, PSK).
    Secret,
    /// TLS server certificate (DER).
    TlsCertificate,
    /// TLS server private key.
    TlsPrivate,
    /// TLS trust anchor of the own server (DER).
    TlsTrust,
}
impl KeyRole {
    /// The role of a profile option, if it names a key file.
    pub fn of(option: &str) -> Option<Self> {
        Some(match option {
            "--identity" => Self::MemberPrivate,
            "--allow-key" => Self::MemberTrusted,
            "--noise-private-key-file" => Self::NoisePrivate,
            "--noise-peer-key-file" => Self::NoisePeer,
            "--noise-psk-file" | "--session-admission-key-file" | "--session-cookie-key-file" => {
                Self::Secret
            }
            "--cert" => Self::TlsCertificate,
            "--key" => Self::TlsPrivate,
            "--ca" => Self::TlsTrust,
            _ => return None,
        })
    }
    /// Human description.
    pub fn text(self) -> &'static str {
        match self {
            Self::MemberPrivate => "member identity (private)",
            Self::MemberTrusted => "trusted member (public)",
            Self::NoisePrivate => "Noise key (private)",
            Self::NoisePeer => "trusted peer Noise key (public)",
            Self::Secret => "shared secret",
            Self::TlsCertificate => "TLS certificate",
            Self::TlsPrivate => "TLS private key",
            Self::TlsTrust => "TLS trust anchor",
        }
    }
}

/// One key file a profile references.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyReference {
    /// Option naming the file.
    pub option: String,
    /// The path as written in the profile.
    pub path: String,
    /// What the file holds.
    pub role: KeyRole,
    /// The service could read and parse it as connecting would.
    pub usable: bool,
    /// Why not.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Public key (hex), or SHA-256 of a certificate (hex). Never private material.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public: Option<String>,
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Inspect one option as the service (reads with the connect-time readers and
/// permission checks). `None` when the option names no key file.
pub fn inspect(option: &str, path: &str) -> Option<KeyReference> {
    use crate::secure_udp::credentials;
    let role = KeyRole::of(option)?;
    let file = Path::new(path);
    let public: io::Result<Option<String>> = match role {
        KeyRole::MemberPrivate => {
            credentials::read_member(file).map(|member| Some(hex(&member.public_key().0)))
        }
        KeyRole::MemberTrusted | KeyRole::NoisePeer => {
            credentials::read_public(file).map(|public| Some(hex(&public)))
        }
        KeyRole::NoisePrivate => credentials::read_secret(file).map(|secret| {
            Some(hex(&l2tunnel_handshake::LocalSecret::new(secret)
                .public_key()
                .0))
        }),
        KeyRole::Secret => credentials::read_secret(file).map(|_| None),
        KeyRole::TlsCertificate | KeyRole::TlsTrust => std::fs::read(file).and_then(|der| {
            if der.len() > CERTIFICATE_LIMIT {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "certificate is too large",
                ));
            }
            Ok(Some(hex(
                ring::digest::digest(&ring::digest::SHA256, &der).as_ref()
            )))
        }),
        KeyRole::TlsPrivate => std::fs::metadata(file).and_then(|metadata| {
            if metadata.is_file() {
                Ok(None)
            } else {
                Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "not a regular file",
                ))
            }
        }),
    };
    Some(match public {
        Ok(public) => KeyReference {
            option: option.to_owned(),
            path: path.to_owned(),
            role,
            usable: true,
            reason: None,
            public,
        },
        Err(error) => KeyReference {
            option: option.to_owned(),
            path: path.to_owned(),
            role,
            usable: false,
            reason: Some(super::bounded_text(&error.to_string())),
            public: None,
        },
    })
}

/// A key file set to generate locally.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum KeyGeneration {
    /// Member Ed25519 identity: PKCS#8 private and raw public (for `--allow-key`).
    Member {
        /// `--identity` file.
        private: std::path::PathBuf,
        /// Public file for the server's `--allow-key`.
        public: std::path::PathBuf,
    },
    /// Noise X25519 pair: raw private and raw public (the peer's `--noise-peer-key-file`).
    Noise {
        /// This side's `--noise-private-key-file`.
        private: std::path::PathBuf,
        /// Public file for the peer.
        public: std::path::PathBuf,
    },
    /// 32 random bytes (admission, cookie or PSK); copy it to both sides as needed.
    Secret {
        /// Output file.
        output: std::path::PathBuf,
    },
}

fn create(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(bytes)?;
    file.sync_all()
}
fn random() -> io::Result<zeroize::Zeroizing<[u8; 32]>> {
    use ring::rand::SecureRandom;
    let mut bytes = zeroize::Zeroizing::new([0; 32]);
    ring::rand::SystemRandom::new()
        .fill(bytes.as_mut())
        .map_err(|_| io::Error::other("system randomness unavailable"))?;
    Ok(bytes)
}

/// Generate key files that must not exist yet (mode 0600 on Unix). Returns
/// the public key in hex, when there is one. A failed second file leaves the
/// first for explicit inspection, like `keygen`.
pub fn generate(request: &KeyGeneration) -> io::Result<Option<String>> {
    match request {
        KeyGeneration::Member { private, public } | KeyGeneration::Noise { private, public }
            if private == public =>
        {
            Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "private and public paths must differ",
            ))
        }
        KeyGeneration::Member { private, public } => {
            let der = l2tunnel_auth::MemberKey::generate_pkcs8().map_err(io::Error::other)?;
            let key = l2tunnel_identity::IdentityKey::from_pkcs8(&der).map_err(io::Error::other)?;
            let public_key = key.public_key().0;
            create(private, &der)?;
            create(public, &public_key)?;
            Ok(Some(hex(&public_key)))
        }
        KeyGeneration::Noise { private, public } => {
            let secret = random()?;
            let public_key = l2tunnel_handshake::LocalSecret::new(secret.clone())
                .public_key()
                .0;
            create(private, secret.as_ref())?;
            create(public, &public_key)?;
            Ok(Some(hex(&public_key)))
        }
        KeyGeneration::Secret { output } => {
            create(output, random()?.as_ref())?;
            Ok(None)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_files_inspect_like_connect_reads_them() -> io::Result<()> {
        let directory = std::env::temp_dir().join(format!("l2t-keys-{}", std::process::id()));
        std::fs::create_dir_all(&directory)?;
        let path = |name: &str| directory.join(name);
        let text = |name: &str| path(name).display().to_string();
        let member = generate(&KeyGeneration::Member {
            private: path("member.der"),
            public: path("member.pub"),
        })?;
        let noise = generate(&KeyGeneration::Noise {
            private: path("noise.key"),
            public: path("noise.pub"),
        })?;
        assert_eq!(
            generate(&KeyGeneration::Secret {
                output: path("admission.key")
            })?,
            None
        );
        // Inspection derives the same public keys; secrets show none.
        let seen = |option, name| inspect(option, &text(name)).and_then(|key| key.public);
        assert_eq!(seen("--identity", "member.der"), member);
        assert_eq!(seen("--allow-key", "member.pub"), member);
        assert_eq!(seen("--noise-private-key-file", "noise.key"), noise);
        assert_eq!(seen("--noise-peer-key-file", "noise.pub"), noise);
        let secret = inspect("--session-admission-key-file", &text("admission.key"));
        assert!(secret.is_some_and(|key| key.usable && key.public.is_none()));
        let missing = inspect("--noise-peer-key-file", &text("absent.pub"));
        assert!(missing.is_some_and(|key| !key.usable && key.reason.is_some()));
        assert!(inspect("--carrier", "quic-like").is_none());
        // Never overwrites; private and public must differ.
        assert!(
            generate(&KeyGeneration::Secret {
                output: path("admission.key")
            })
            .is_err()
        );
        assert!(
            generate(&KeyGeneration::Noise {
                private: path("same"),
                public: path("same"),
            })
            .is_err()
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(path("noise.key"))?.permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        std::fs::remove_dir_all(&directory)?;
        Ok(())
    }
}
