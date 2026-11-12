//! Explicit UDP settings shared by command-line and future GUI adapters.
use super::{ConnectionConfig, auth_error, socket};
use l2tunnel_auth::{self as auth, ClientTls, MemberAllowlist, MemberKey, ServerTls};
use l2tunnel_core::Duplex;
pub use l2tunnel_datagram::{CoverProfile, Protection};
/// Negotiated selective-repeat or systematic Cauchy repair policy.
pub use l2tunnel_runtime::udp::RecoveryMode;
use l2tunnel_runtime::{managed::DeliveryConfig, udp as runtime};
use std::io;
use std::net::{IpAddr, SocketAddr};
use tokio::net::{TcpListener, UdpSocket};

/// Fixed trusted local/remote endpoints for one physical UDP lane.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Endpoints {
    /// Explicit local unicast socket address; port zero is not a stable peer contract.
    pub local: SocketAddr,
    /// Fixed configured remote unicast socket address.
    pub peer: SocketAddr,
}
impl Endpoints {
    pub(crate) fn validate(self) -> io::Result<()> {
        for address in [self.local, self.peer] {
            if address.port() == 0
                || address.ip().is_unspecified()
                || address.ip().is_multicast()
                || matches!(address.ip(), IpAddr::V4(ip) if ip.is_broadcast())
            {
                return Err(invalid(
                    "UDP endpoints require explicit nonzero unicast addresses",
                ));
            }
        }
        if self.local.is_ipv4() != self.peer.is_ipv4() || self.local == self.peer {
            return Err(invalid(
                "UDP lane endpoints require one family and distinct sockets",
            ));
        }
        Ok(())
    }
}

/// Complete explicit client UDP profile; no address or protection fallback is implicit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Settings {
    /// Full-duplex lane, or the initiator-to-listener lane in paired-half mode.
    pub forward: Endpoints,
    /// Listener-to-initiator lane, required only in paired-half mode.
    pub reverse: Option<Endpoints>,
    /// Custom UDP appearance, not standard protocol interoperability.
    pub cover: CoverProfile,
    /// Required data confidentiality/integrity suite.
    pub protection: Protection,
    /// Whole outer IP packet budget, including UDP and protected framing.
    pub path_mtu: usize,
    /// Optional bounded systematic repair, with selective-repeat fallback.
    pub recovery: RecoveryMode,
}
impl Settings {
    /// Reject inconsistent local settings before socket/device/credential work.
    pub fn validate(self, duplex: Duplex) -> io::Result<()> {
        self.forward.validate()?;
        let minimum = if self.forward.local.is_ipv4() {
            576
        } else {
            1280
        };
        if !(minimum..=65_535).contains(&self.path_mtu) {
            return Err(invalid("UDP path MTU outside supported IP packet bounds"));
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
                        "paired UDP lanes require distinct sockets in one address family",
                    ));
                }
                Ok(())
            }
            _ => Err(invalid(
                "half UDP needs explicit reverse endpoints; full UDP forbids them",
            )),
        }
    }
    /// Actual bare IP/UDP overhead; extra underlay encapsulation needs a smaller path MTU.
    pub fn outer_overhead(self) -> usize {
        if self.forward.local.is_ipv4() { 28 } else { 48 }
    }
}
fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

/// Validate reusable UDP transport geometry; base-native factories also require delivery policy.
pub fn runtime_config(config: ConnectionConfig, settings: Settings) -> io::Result<runtime::Config> {
    config.session()?;
    settings.validate(config.duplex)?;
    runtime::Config::new(
        config.duplex,
        settings.cover,
        settings.protection,
        settings.path_mtu,
        settings.forward.local.is_ipv6(),
    )?
    .with_recovery(settings.recovery)
}

async fn bind(settings: Settings) -> io::Result<(UdpSocket, Option<UdpSocket>)> {
    let first = UdpSocket::bind(settings.forward.local).await?;
    let second = match settings.reverse {
        Some(endpoints) => Some(UdpSocket::bind(endpoints.local).await?),
        None => None,
    };
    Ok((first, second))
}

/// Private explicit record binding; base frames carry their mandatory native delivery policy.
#[derive(Clone, Copy)]
pub(crate) enum Records<'a> {
    Frame(DeliveryConfig),
    Rolling(&'a l2tunnel_runtime::rolling::Config),
    Aligned(&'a l2tunnel_runtime::aligned::Config),
    Packed(&'a l2tunnel_runtime::packed::Config),
}
impl Records<'_> {
    fn lane(
        self,
        runtime_config: l2tunnel_runtime::RuntimeConfig,
        profile: runtime::Config,
        lane: runtime::Lane,
        peer: SocketAddr,
    ) -> io::Result<(l2tunnel_udp::Config, auth::SessionConfig)> {
        match self {
            Self::Frame(delivery) => Ok((
                runtime::carrier_config(runtime_config, profile, lane, peer, delivery)?,
                runtime::session_config(runtime_config, profile, lane, delivery)?,
            )),
            Self::Aligned(config) => Ok((
                l2tunnel_runtime::aligned::udp_carrier_config(
                    runtime_config,
                    profile,
                    *config,
                    lane,
                    peer,
                )?,
                l2tunnel_runtime::aligned::udp_session_config(
                    runtime_config,
                    profile,
                    *config,
                    lane,
                )?,
            )),
            Self::Packed(config) => Ok((
                l2tunnel_runtime::packed::udp_carrier_config(
                    runtime_config,
                    profile,
                    *config,
                    lane,
                    peer,
                )?,
                l2tunnel_runtime::packed::udp_session_config(
                    runtime_config,
                    profile,
                    *config,
                    lane,
                )?,
            )),
            Self::Rolling(config) => Ok((
                l2tunnel_runtime::rolling::udp_carrier_config(
                    runtime_config,
                    profile,
                    *config,
                    lane,
                    peer,
                )?,
                l2tunnel_runtime::rolling::udp_session_config(
                    runtime_config,
                    profile,
                    *config,
                    lane,
                )?,
            )),
        }
    }
}
/// Owned authenticated lanes before their record-specific runtime constructor.
pub(crate) struct Lanes {
    pub(crate) first: l2tunnel_udp::Carrier,
    pub(crate) second: Option<l2tunnel_udp::Carrier>,
    pub(crate) profile: runtime::Config,
}

/// Authenticate base frames with explicit delivery under one whole-attempt deadline.
pub async fn connect(
    address: SocketAddr,
    tls: &ClientTls,
    server_name: &str,
    identity: &MemberKey,
    config: ConnectionConfig,
    settings: Settings,
    delivery: DeliveryConfig,
) -> io::Result<(runtime::Link, runtime::Config)> {
    let profile = runtime_config(config, settings)?;
    Records::Frame(delivery).lane(
        config.runtime(),
        profile,
        runtime::Lane::First,
        settings.forward.peer,
    )?;
    let deadline = super::HandshakeDeadline::start(config.handshake_timeout)?;
    deadline
        .within(async {
            let lanes = connect_lanes(
                address,
                tls,
                server_name,
                identity,
                config,
                settings,
                Records::Frame(delivery),
            )
            .await?;
            let link = match lanes.second {
                None => {
                    runtime::Link::full(lanes.first, config.runtime(), lanes.profile, delivery)?
                }
                Some(second) => {
                    runtime::client_pair(
                        lanes.first,
                        second,
                        config.runtime(),
                        lanes.profile,
                        delivery,
                    )
                    .await?
                }
            };
            Ok((link, lanes.profile))
        })
        .await
}

pub(crate) async fn connect_lanes(
    address: SocketAddr,
    tls: &ClientTls,
    server_name: &str,
    identity: &MemberKey,
    config: ConnectionConfig,
    settings: Settings,
    records: Records<'_>,
) -> io::Result<Lanes> {
    let profile = runtime_config(config, settings)?;
    records.lane(
        config.runtime(),
        profile,
        runtime::Lane::First,
        settings.forward.peer,
    )?;
    let (first_socket, second_socket) = bind(settings).await?;
    let lane = ClientLane {
        address,
        tls,
        server_name,
        identity,
        config,
        profile,
        records,
    };
    let first = lane
        .establish(runtime::Lane::First, settings.forward.peer, first_socket)
        .await?;
    let second = match (settings.reverse, second_socket) {
        (None, None) => None,
        (Some(endpoints), Some(socket)) => Some(
            lane.establish(runtime::Lane::Second, endpoints.peer, socket)
                .await?,
        ),
        _ => return Err(invalid("inconsistent UDP lane assembly")),
    };
    Ok(Lanes {
        first,
        second,
        profile,
    })
}
struct ClientLane<'a> {
    address: SocketAddr,
    tls: &'a ClientTls,
    server_name: &'a str,
    identity: &'a MemberKey,
    config: ConnectionConfig,
    profile: runtime::Config,
    records: Records<'a>,
}
impl ClientLane<'_> {
    async fn establish(
        &self,
        lane: runtime::Lane,
        peer: SocketAddr,
        udp: UdpSocket,
    ) -> io::Result<l2tunnel_udp::Carrier> {
        let (carrier, session) =
            self.records
                .lane(self.config.runtime(), self.profile, lane, peer)?;
        let stream = auth::client_connect(
            socket(self.address, self.config.handshake_timeout).await?,
            self.tls,
            self.server_name,
            self.identity,
            session,
            self.config.handshake_timeout,
        )
        .await
        .map_err(auth_error)?;
        l2tunnel_udp::establish(stream, udp, carrier)
            .await
            .map_err(io::Error::other)
    }
}

/// Accept one base-frame peer/pair under one deadline, including the first idle accept.
/// No UDP packet chooses its identity; cancellation releases attempt-owned lanes.
pub async fn accept(
    listener: &TcpListener,
    tls: &ServerTls,
    allowlist: &MemberAllowlist,
    config: ConnectionConfig,
    settings: Settings,
    delivery: DeliveryConfig,
) -> io::Result<(runtime::Link, runtime::Config)> {
    let profile = runtime_config(config, settings)?;
    Records::Frame(delivery).lane(
        config.runtime(),
        profile,
        runtime::Lane::First,
        settings.forward.peer,
    )?;
    let deadline = super::HandshakeDeadline::start(config.handshake_timeout)?;
    deadline
        .within(async {
            let lanes = accept_lanes(
                listener,
                tls,
                allowlist,
                config,
                settings,
                Records::Frame(delivery),
            )
            .await?;
            let link = match lanes.second {
                None => {
                    runtime::Link::full(lanes.first, config.runtime(), lanes.profile, delivery)?
                }
                Some(second) => {
                    runtime::server_pair(
                        lanes.first,
                        second,
                        config.runtime(),
                        lanes.profile,
                        delivery,
                    )
                    .await?
                }
            };
            Ok((link, lanes.profile))
        })
        .await
}
pub(crate) async fn accept_lanes(
    listener: &TcpListener,
    tls: &ServerTls,
    allowlist: &MemberAllowlist,
    config: ConnectionConfig,
    settings: Settings,
    records: Records<'_>,
) -> io::Result<Lanes> {
    let profile = runtime_config(config, settings)?;
    records.lane(
        config.runtime(),
        profile,
        runtime::Lane::First,
        settings.forward.peer,
    )?;
    let (first_socket, second_socket) = bind(settings).await?;
    let lane = ServerLane {
        listener,
        tls,
        allowlist,
        config,
        profile,
        records,
    };
    let first = lane
        .establish(
            runtime::Lane::First,
            settings.forward.peer,
            first_socket,
            false,
        )
        .await?;
    let second = match (settings.reverse, second_socket) {
        (None, None) => None,
        (Some(endpoints), Some(socket)) => Some(
            lane.establish(runtime::Lane::Second, endpoints.peer, socket, true)
                .await?,
        ),
        _ => return Err(invalid("inconsistent UDP lane assembly")),
    };
    Ok(Lanes {
        first,
        second,
        profile,
    })
}
struct ServerLane<'a> {
    listener: &'a TcpListener,
    tls: &'a ServerTls,
    allowlist: &'a MemberAllowlist,
    config: ConnectionConfig,
    profile: runtime::Config,
    records: Records<'a>,
}
impl ServerLane<'_> {
    async fn establish(
        &self,
        lane: runtime::Lane,
        peer: SocketAddr,
        udp: UdpSocket,
        bounded_accept: bool,
    ) -> io::Result<l2tunnel_udp::Carrier> {
        let accepted = if bounded_accept {
            tokio::time::timeout(self.config.handshake_timeout, self.listener.accept())
                .await
                .map_err(|_| {
                    io::Error::new(io::ErrorKind::TimedOut, "second UDP control lane timeout")
                })??
        } else {
            self.listener.accept().await?
        };
        let (stream, _) = accepted;
        stream.set_nodelay(true)?;
        let (carrier, session) =
            self.records
                .lane(self.config.runtime(), self.profile, lane, peer)?;
        let stream = auth::server_accept(
            stream,
            self.tls,
            self.allowlist,
            session,
            self.config.handshake_timeout,
        )
        .await
        .map_err(auth_error)?;
        l2tunnel_udp::establish(stream, udp, carrier)
            .await
            .map_err(io::Error::other)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn endpoints(port: u16) -> Endpoints {
        Endpoints {
            local: SocketAddr::from(([127, 0, 0, 1], port)),
            peer: SocketAddr::from(([127, 0, 0, 2], port)),
        }
    }
    fn settings() -> Settings {
        Settings {
            forward: endpoints(20000),
            reverse: Some(endpoints(20001)),
            cover: CoverProfile::QuicLike,
            protection: Protection::ChaCha20Poly1305,
            path_mtu: 1500,
            recovery: RecoveryMode::SelectiveRepeat,
        }
    }
    #[test]
    fn explicit_duplex_and_endpoint_contract_is_strict() -> io::Result<()> {
        settings().validate(Duplex::Half)?;
        assert!(settings().validate(Duplex::Full).is_err());
        let full = Settings {
            reverse: None,
            ..settings()
        };
        full.validate(Duplex::Full)?;
        assert!(full.validate(Duplex::Half).is_err());
        assert!(
            Settings {
                reverse: Some(settings().forward),
                ..settings()
            }
            .validate(Duplex::Half)
            .is_err()
        );
        for ip in ["0.0.0.0", "224.0.0.1", "255.255.255.255", "::1"] {
            let peer = SocketAddr::new(ip.parse().map_err(io::Error::other)?, 20000);
            assert!(
                Settings {
                    forward: Endpoints {
                        peer,
                        ..full.forward
                    },
                    ..full
                }
                .validate(Duplex::Full)
                .is_err()
            );
        }
        assert!(
            Settings {
                forward: endpoints(0),
                ..full
            }
            .validate(Duplex::Full)
            .is_err()
        );
        assert!(
            Settings {
                path_mtu: 575,
                ..full
            }
            .validate(Duplex::Full)
            .is_err()
        );
        assert!(
            Settings {
                path_mtu: 65_536,
                ..full
            }
            .validate(Duplex::Full)
            .is_err()
        );
        assert_eq!(full.outer_overhead(), 28);
        Ok(())
    }
    #[test]
    fn ipv6_requires_explicit_family_and_minimum_path_mtu() -> io::Result<()> {
        let forward = Endpoints {
            local: "[::1]:20000".parse().map_err(io::Error::other)?,
            peer: "[::1]:20001".parse().map_err(io::Error::other)?,
        };
        let config = Settings {
            forward,
            reverse: None,
            path_mtu: 1280,
            ..settings()
        };
        config.validate(Duplex::Full)?;
        assert_eq!(config.outer_overhead(), 48);
        assert!(
            Settings {
                path_mtu: 1279,
                ..config
            }
            .validate(Duplex::Full)
            .is_err()
        );
        Ok(())
    }
}
