//! Genuine UDP-only QUIC lifecycle shared by command-line and future GUI adapters.
use super::ConnectionConfig;
use super::udp::{Endpoints, RecoveryMode};
use l2tunnel_auth::{MemberAllowlist, MemberKey, SessionConfig};
use l2tunnel_core::Duplex;
use l2tunnel_quic::{self as carrier, ClientEndpoint, EndpointLimits, ServerEndpoint};
use l2tunnel_runtime::quic as runtime;
use std::io;

/// Explicit peer/lane policy; no custom UDP cover or optional transport encryption.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Settings {
    /// Full lane or the first client-to-server lane in paired-half mode.
    pub forward: Endpoints,
    /// Required only for paired-half mode, with distinct local/peer ports.
    pub reverse: Option<Endpoints>,
    /// Explicit opaque observable ALPN identifier; all-zero is rejected.
    pub application_id: [u8; 16],
    /// Whole underlay IP packet ceiling.
    pub path_mtu: usize,
    /// Existing bounded application recovery; outer QUIC congestion control remains active.
    pub recovery: RecoveryMode,
}
impl Settings {
    /// Reject ambiguous endpoints, non-provisioned ALPN and unsupported MTUs/duplex.
    pub fn validate(self, duplex: Duplex) -> io::Result<()> {
        self.forward.validate()?;
        let minimum = if self.forward.local.is_ipv4() {
            1228
        } else {
            1280
        };
        if self.application_id == [0; 16] || !(minimum..=65_535).contains(&self.path_mtu) {
            return Err(invalid(
                "QUIC requires explicit nonzero ALPN and a supported whole-IP MTU",
            ));
        }
        match (duplex, self.reverse) {
            (Duplex::Full, None) => Ok(()),
            (Duplex::Half, Some(reverse)) => {
                reverse.validate()?;
                if reverse.local.is_ipv4() != self.forward.local.is_ipv4()
                    || reverse.local == self.forward.local
                    || reverse.peer == self.forward.peer
                {
                    return Err(invalid(
                        "QUIC half lanes require distinct endpoints in one address family",
                    ));
                }
                Ok(())
            }
            _ => Err(invalid(
                "QUIC half requires reverse endpoints; full forbids them",
            )),
        }
    }
}
fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

/// Compute the exact canonical real-QUIC runtime profile before native I/O.
pub fn runtime_config(config: ConnectionConfig, settings: Settings) -> io::Result<runtime::Config> {
    config.session()?;
    settings.validate(config.duplex)?;
    runtime::Config::new(
        config.duplex,
        settings.application_id,
        settings.path_mtu,
        settings.forward.local.is_ipv6(),
    )?
    .with_recovery(settings.recovery)
}
fn limits(config: ConnectionConfig) -> EndpointLimits {
    EndpointLimits {
        max_connections: 1,
        pending_connections: 4,
        handshake_timeout: config.handshake_timeout,
    }
}
fn client_endpoint(
    roots: &[Vec<u8>],
    config: ConnectionConfig,
    profile: runtime::Config,
    lane: runtime::Lane,
    endpoints: Endpoints,
) -> io::Result<ClientEndpoint> {
    let tls = carrier::ClientConfig::from_der_roots(
        roots,
        runtime::carrier_profile(profile, lane)?,
        limits(config),
    )
    .map_err(io::Error::other)?;
    ClientEndpoint::bind(endpoints.local, &tls).map_err(io::Error::other)
}
fn server_endpoint(
    certs: &[Vec<u8>],
    key: &[u8],
    config: ConnectionConfig,
    profile: runtime::Config,
    lane: runtime::Lane,
    endpoints: Endpoints,
) -> io::Result<ServerEndpoint> {
    let tls = carrier::ServerConfig::from_der(
        certs,
        key,
        runtime::carrier_profile(profile, lane)?,
        limits(config),
    )
    .map_err(io::Error::other)?;
    ServerEndpoint::bind(endpoints.local, &tls).map_err(io::Error::other)
}
fn check_peer(
    connection: &carrier::AuthenticatedConnection,
    endpoints: Endpoints,
) -> io::Result<()> {
    if connection.peer_addr() != endpoints.peer
        || connection.local_addr().map_err(io::Error::other)? != endpoints.local
    {
        return Err(invalid(
            "authenticated QUIC endpoint differs from configured fixed lane",
        ));
    }
    Ok(())
}

/// Authenticated physical lanes; their record-specific constructor still validates metadata.
pub(crate) struct Lanes {
    pub(crate) first: carrier::AuthenticatedConnection,
    pub(crate) second: Option<carrier::AuthenticatedConnection>,
    pub(crate) profile: runtime::Config,
    pub(crate) pair_deadline: tokio::time::Instant,
}
/// Bind both lanes before authenticating; never open a TCP socket.
pub async fn connect(
    roots: &[Vec<u8>],
    name: &str,
    member: &MemberKey,
    config: ConnectionConfig,
    settings: Settings,
) -> io::Result<(runtime::Link, runtime::Config)> {
    let profile = runtime_config(config, settings)?;
    let base = runtime::base_session_config(config.runtime(), profile)?;
    let lanes = connect_lanes(roots, name, member, config, settings, base).await?;
    let link = match lanes.second {
        None => runtime::Link::full(lanes.first, config.runtime(), profile)?,
        Some(second) => {
            finish_pair(
                lanes.pair_deadline,
                runtime::client_pair(lanes.first, second, config.runtime(), profile),
            )
            .await?
        }
    };
    Ok((link, profile))
}
pub(crate) async fn connect_lanes(
    roots: &[Vec<u8>],
    name: &str,
    member: &MemberKey,
    config: ConnectionConfig,
    settings: Settings,
    base: SessionConfig,
) -> io::Result<Lanes> {
    let profile = runtime_config(config, settings)?;
    if base.layer != config.layer {
        return Err(invalid("QUIC bound native layer mismatch"));
    }
    let first = client_endpoint(
        roots,
        config,
        profile,
        runtime::Lane::First,
        settings.forward,
    )?;
    let second = settings
        .reverse
        .map(|endpoints| client_endpoint(roots, config, profile, runtime::Lane::Second, endpoints))
        .transpose()?;
    let first = first
        .connect(settings.forward.peer, name, member, base)
        .await
        .map_err(io::Error::other)?;
    check_peer(&first, settings.forward)?;
    let pair_deadline = tokio::time::Instant::now() + config.handshake_timeout;
    let second = match (second, settings.reverse) {
        (None, None) => None,
        (Some(second), Some(endpoints)) => Some(
            tokio::time::timeout_at(pair_deadline, async {
                let second = second
                    .connect(endpoints.peer, name, member, base)
                    .await
                    .map_err(io::Error::other)?;
                check_peer(&second, endpoints)?;
                Ok::<_, io::Error>(second)
            })
            .await
            .map_err(io::Error::other)??,
        ),
        _ => return Err(invalid("inconsistent genuine QUIC client lanes")),
    };
    Ok(Lanes {
        first,
        second,
        profile,
        pair_deadline,
    })
}

pub(crate) async fn finish_pair<T>(
    deadline: tokio::time::Instant,
    operation: impl std::future::Future<Output = io::Result<T>>,
) -> io::Result<T> {
    tokio::time::timeout_at(deadline, operation)
        .await
        .map_err(io::Error::other)?
}

/// Both fixed UDP listener lanes are bound before this object becomes ready.
pub struct Listener {
    first: ServerEndpoint,
    second: Option<ServerEndpoint>,
    config: ConnectionConfig,
    profile: runtime::Config,
    settings: Settings,
    base: SessionConfig,
}
impl Listener {
    /// Validate certificates/profile and bind all required UDP lanes atomically by ownership.
    pub fn bind(
        certs: &[Vec<u8>],
        key: &[u8],
        config: ConnectionConfig,
        settings: Settings,
    ) -> io::Result<Self> {
        let profile = runtime_config(config, settings)?;
        let base = runtime::base_session_config(config.runtime(), profile)?;
        Self::bind_base(certs, key, config, settings, base)
    }
    pub(crate) fn bind_base(
        certs: &[Vec<u8>],
        key: &[u8],
        config: ConnectionConfig,
        settings: Settings,
        base: SessionConfig,
    ) -> io::Result<Self> {
        let profile = runtime_config(config, settings)?;
        if base.layer != config.layer {
            return Err(invalid("QUIC bound native layer mismatch"));
        }
        let first = server_endpoint(
            certs,
            key,
            config,
            profile,
            runtime::Lane::First,
            settings.forward,
        )?;
        let second = settings
            .reverse
            .map(|endpoints| {
                server_endpoint(
                    certs,
                    key,
                    config,
                    profile,
                    runtime::Lane::Second,
                    endpoints,
                )
            })
            .transpose()?;
        Ok(Self {
            first,
            second,
            config,
            profile,
            settings,
            base,
        })
    }
    /// Authenticate the configured peer and pair directional lanes before device I/O.
    pub async fn accept(
        &self,
        allowlist: &MemberAllowlist,
    ) -> io::Result<(runtime::Link, runtime::Config)> {
        let lanes = self.accept_lanes(allowlist).await?;
        let link = match lanes.second {
            None => runtime::Link::full(lanes.first, self.config.runtime(), self.profile)?,
            Some(second) => {
                finish_pair(
                    lanes.pair_deadline,
                    runtime::server_pair(lanes.first, second, self.config.runtime(), self.profile),
                )
                .await?
            }
        };
        Ok((link, self.profile))
    }
    pub(crate) async fn accept_lanes(&self, allowlist: &MemberAllowlist) -> io::Result<Lanes> {
        let first = self
            .first
            .accept(allowlist, self.base)
            .await
            .map_err(io::Error::other)?;
        check_peer(&first, self.settings.forward)?;
        let pair_deadline = tokio::time::Instant::now() + self.config.handshake_timeout;
        let second = match (&self.second, self.settings.reverse) {
            (None, None) => None,
            (Some(second), Some(endpoints)) => Some(
                tokio::time::timeout_at(pair_deadline, async {
                    let second = second
                        .accept(allowlist, self.base)
                        .await
                        .map_err(io::Error::other)?;
                    check_peer(&second, endpoints)?;
                    Ok::<_, io::Error>(second)
                })
                .await
                .map_err(io::Error::other)??,
            ),
            _ => return Err(invalid("inconsistent genuine QUIC server lanes")),
        };
        Ok(Lanes {
            first,
            second,
            profile: self.profile,
            pair_deadline,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn exact_endpoint_and_duplex_policy_precedes_io() -> io::Result<()> {
        let settings = Settings {
            forward: Endpoints {
                local: "192.0.2.1:24000".parse().map_err(io::Error::other)?,
                peer: "192.0.2.2:24000".parse().map_err(io::Error::other)?,
            },
            reverse: None,
            application_id: [0x77; 16],
            path_mtu: 1228,
            recovery: RecoveryMode::SelectiveRepeat,
        };
        settings.validate(Duplex::Full)?;
        assert!(settings.validate(Duplex::Half).is_err());
        assert!(
            Settings {
                reverse: Some(settings.forward),
                ..settings
            }
            .validate(Duplex::Half)
            .is_err()
        );
        assert!(
            Settings {
                application_id: [0; 16],
                ..settings
            }
            .validate(Duplex::Full)
            .is_err()
        );
        assert!(
            Settings {
                path_mtu: 1227,
                ..settings
            }
            .validate(Duplex::Full)
            .is_err()
        );
        assert!(
            Settings {
                forward: Endpoints {
                    local: "0.0.0.0:24000".parse().map_err(io::Error::other)?,
                    ..settings.forward
                },
                ..settings
            }
            .validate(Duplex::Full)
            .is_err()
        );
        let ipv6 = Settings {
            forward: Endpoints {
                local: "[2001:db8::1]:24000".parse().map_err(io::Error::other)?,
                peer: "[2001:db8::2]:24000".parse().map_err(io::Error::other)?,
            },
            ..settings
        };
        assert!(ipv6.validate(Duplex::Full).is_err());
        Settings {
            path_mtu: 1280,
            ..ipv6
        }
        .validate(Duplex::Full)?;
        Ok(())
    }
}
