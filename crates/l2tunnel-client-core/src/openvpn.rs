//! Fixed-peer standalone OpenVPN-like UDP lifecycle, shared by CLI and future GUI.
use super::{ConnectionConfig, udp::Endpoints};
use l2tunnel_auth::{ClientTls, MemberAllowlist, MemberKey, ServerTls};
use l2tunnel_core::Duplex;
use l2tunnel_datagram::Direction;
use l2tunnel_openvpn as carrier;
use l2tunnel_runtime::openvpn as runtime;
use l2tunnel_udp_control::{Path, Secret};
use std::{io, time::Duration};
use tokio::{
    net::UdpSocket,
    time::{Instant, timeout_at},
};
use zeroize::Zeroizing;

/// Additive distributed native drain; legacy selection remains the default.
pub mod drain;
/// Restricted Linux provisioning; it is not a Windows/Android permission policy.
#[cfg(target_os = "linux")]
pub mod keys;
/// Explicit fixed peer and finite transport policy; no TCP socket is opened.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Settings {
    /// Full lane, or the logical initiator-to-server paired lane.
    pub forward: Endpoints,
    /// Required only in paired half mode, with distinct fixed endpoints.
    pub reverse: Option<Endpoints>,
    /// Data AEAD or integrity-only protection; control TLS remains mandatory.
    pub protection: carrier::Protection,
    /// Complete outer IP packet ceiling.
    pub path_mtu: usize,
    /// Absolute authenticated lifetime, at most 24 hours.
    pub authenticated_lease: Duration,
}
/// Two independent directional secrets. Full duplex reserves the unused second
/// slot; that slot does not create a second authenticated lane. No Debug/Clone.
pub struct KeyBundle(Zeroizing<[u8; 64]>);
impl KeyBundle {
    /// Import exact forward/reverse keys. The caller owns any copies it retains.
    pub fn from_bytes(bytes: [u8; 64]) -> io::Result<Self> {
        let value = Self(Zeroizing::new(bytes));
        if value.0[..32] == [0; 32] || value.0[32..] == [0; 32] || value.0[..32] == value.0[32..] {
            return Err(invalid("invalid independent directional key bundle"));
        }
        Ok(value)
    }
    fn overlaps(&self, other: &Self) -> bool {
        self.0
            .chunks_exact(32)
            .any(|a| other.0.chunks_exact(32).any(|b| a == b))
    }
    fn secrets(self) -> [Secret; 2] {
        let mut first = Zeroizing::new([0; 32]);
        let mut second = Zeroizing::new([0; 32]);
        first.copy_from_slice(&self.0[..32]);
        second.copy_from_slice(&self.0[32..]);
        [Secret::new(*first), Secret::new(*second)]
    }
}
fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}
struct Profiles {
    native: runtime::DeviceConfig,
    first: carrier::Config,
    second: Option<carrier::Config>,
}
fn profiles(config: ConnectionConfig, settings: Settings, client: bool) -> io::Result<Profiles> {
    profiles_with_base(config, settings, client, |native| {
        native.base_session_config()
    })
}
fn profiles_with_base(
    config: ConnectionConfig,
    settings: Settings,
    client: bool,
    base_for: impl FnOnce(runtime::DeviceConfig) -> io::Result<l2tunnel_auth::SessionConfig>,
) -> io::Result<Profiles> {
    config.session()?;
    settings.forward.validate()?;
    let minimum = if settings.forward.local.is_ipv4() {
        576
    } else {
        1280
    };
    if !(minimum..=65_535).contains(&settings.path_mtu)
        || settings.authenticated_lease.is_zero()
        || settings.authenticated_lease > Duration::from_secs(86_400)
    {
        return Err(invalid("standalone UDP MTU/lease bounds"));
    }
    match (config.duplex, settings.reverse) {
        (Duplex::Full, None) => {}
        (Duplex::Half, Some(reverse)) => {
            reverse.validate()?;
            if reverse.local.is_ipv4() != settings.forward.local.is_ipv4()
                || reverse.local == settings.forward.local
                || reverse.peer == settings.forward.peer
            {
                return Err(invalid(
                    "standalone half lanes require distinct fixed endpoints in one family",
                ));
            }
        }
        _ => {
            return Err(invalid(
                "standalone half requires reverse endpoints; full forbids them",
            ));
        }
    }
    let native = runtime::DeviceConfig {
        native: config.runtime(),
        duplex: config.duplex,
        reassembly_timeout: Duration::from_secs(3),
        work_limit: 32,
        task_shutdown_timeout: Duration::from_secs(1),
    };
    let base = base_for(native)?;
    let build = |endpoints: Endpoints, lane| -> io::Result<carrier::Config> {
        let path = if client {
            Path {
                client: endpoints.local,
                server: endpoints.peer,
            }
        } else {
            Path {
                client: endpoints.peer,
                server: endpoints.local,
            }
        };
        let mut value = carrier::Config::new(path, base, settings.protection)
            .map_err(io::Error::other)?
            .with_path_mtu(settings.path_mtu)
            .map_err(io::Error::other)?;
        value.bootstrap.handshake_timeout = config.handshake_timeout;
        value.bootstrap.cookie_ttl = value.bootstrap.cookie_ttl.min(config.handshake_timeout);
        value.bootstrap.maximum_rto = value.bootstrap.maximum_rto.min(config.handshake_timeout);
        value.bootstrap.initial_rto = value.bootstrap.initial_rto.min(value.bootstrap.maximum_rto);
        value.authentication_timeout = config.handshake_timeout;
        value.pairing_timeout = config.handshake_timeout;
        value.authenticated_lease = settings.authenticated_lease;
        value.inactivity_timeout = value.inactivity_timeout.min(settings.authenticated_lease);
        value.heartbeat_interval = value.heartbeat_interval.min(value.inactivity_timeout / 3);
        value.profile.lane = carrier::LaneId(lane);
        if config.duplex == Duplex::Half {
            value.profile.traffic = carrier::Traffic::HalfDuplex {
                sender: if lane == 0 {
                    Direction::ClientToServer
                } else {
                    Direction::ServerToClient
                },
            };
        }
        value.validate().map_err(io::Error::other)?;
        Ok(value)
    };
    Ok(Profiles {
        native,
        first: build(settings.forward, 0)?,
        second: settings.reverse.map(|value| build(value, 1)).transpose()?,
    })
}
/// Validate all exact native/carrier policy before credentials or native I/O.
pub fn runtime_config(
    config: ConnectionConfig,
    settings: Settings,
) -> io::Result<runtime::DeviceConfig> {
    Ok(profiles(config, settings, true)?.native)
}
fn deadline(config: ConnectionConfig) -> io::Result<Instant> {
    Instant::now()
        .checked_add(config.handshake_timeout)
        .ok_or_else(|| invalid("standalone factory deadline"))
}
/// Bind and authenticate all fixed UDP lanes within one absolute factory deadline.
pub async fn connect(
    tls: &ClientTls,
    name: &str,
    member: &MemberKey,
    admission: KeyBundle,
    config: ConnectionConfig,
    settings: Settings,
) -> io::Result<(runtime::Link, runtime::DeviceConfig)> {
    let expires = deadline(config)?;
    let profile = profiles(config, settings, true)?;
    timeout_at(expires, async {
        let first = UdpSocket::bind(settings.forward.local).await?;
        let [forward, reverse] = admission.secrets();
        let link = match (profile.second, settings.reverse) {
            (None, None) => runtime::Link::full(
                carrier::client_connect(
                    first,
                    profile.first,
                    carrier::ClientCredentials {
                        tls,
                        server_name: name,
                        member,
                        admission: forward,
                    },
                )
                .await
                .map_err(io::Error::other)?,
                profile.first,
                profile.native,
            )?,
            (Some(second), Some(endpoints)) => {
                let second_socket = UdpSocket::bind(endpoints.local).await?;
                runtime::Link::paired(
                    carrier::client_pair(
                        [first, second_socket],
                        [profile.first, second],
                        carrier::ClientPairCredentials {
                            tls,
                            server_name: name,
                            member,
                            admissions: [forward, reverse],
                        },
                    )
                    .await
                    .map_err(io::Error::other)?,
                    [profile.first, second],
                    profile.native,
                )?
            }
            _ => return Err(invalid("standalone client lane invariant")),
        };
        Ok((link, profile.native))
    })
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "standalone whole factory deadline"))?
}
/// Accept one configured peer on fixed UDP sockets, with separate cookie keys.
pub async fn accept(
    tls: &ServerTls,
    members: &MemberAllowlist,
    admission: KeyBundle,
    cookie: KeyBundle,
    config: ConnectionConfig,
    settings: Settings,
) -> io::Result<(runtime::Link, runtime::DeviceConfig)> {
    let expires = deadline(config)?;
    let profile = profiles(config, settings, false)?;
    if admission.overlaps(&cookie) {
        return Err(invalid("cookie keys must be independent of admission keys"));
    }
    timeout_at(expires, async {
        let first = UdpSocket::bind(settings.forward.local).await?;
        let [forward, reverse] = admission.secrets();
        let [forward_cookie, reverse_cookie] = cookie.secrets();
        let link = match (profile.second, settings.reverse) {
            (None, None) => runtime::Link::full(
                carrier::server_accept(
                    first,
                    profile.first,
                    carrier::ServerCredentials {
                        tls,
                        members,
                        admission: forward,
                        cookie: forward_cookie,
                    },
                )
                .await
                .map_err(io::Error::other)?,
                profile.first,
                profile.native,
            )?,
            (Some(second), Some(endpoints)) => {
                let second_socket = UdpSocket::bind(endpoints.local).await?;
                runtime::Link::paired(
                    carrier::server_pair(
                        [first, second_socket],
                        [profile.first, second],
                        carrier::ServerPairCredentials {
                            tls,
                            members,
                            admissions: [forward, reverse],
                            cookies: [forward_cookie, reverse_cookie],
                        },
                    )
                    .await
                    .map_err(io::Error::other)?,
                    [profile.first, second],
                    profile.native,
                )?
            }
            _ => return Err(invalid("standalone server lane invariant")),
        };
        Ok((link, profile.native))
    })
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "standalone whole factory deadline"))?
}

#[cfg(test)]
#[path = "openvpn/tests.rs"]
mod tests;
