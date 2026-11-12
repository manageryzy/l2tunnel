//! Shared headless connection lifecycle for CLI and future GUI clients.
use l2tunnel_auth::{
    self as auth, ClientTls, MemberAllowlist, MemberKey, ServerTls, SessionConfig,
};
/// Stateless per-packet compression.
pub use l2tunnel_codec::Compression;
use l2tunnel_core::{Duplex, ModeConfig};
use l2tunnel_device::PacketLayer;
use l2tunnel_runtime::{Link, RuntimeConfig};
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream};
use tokio::time::{Instant, timeout_at};

/// Explicit transparent-TUN credit and QoS client profile.
pub mod active;
/// Negotiated active policy catalog and managed authentication lifecycle.
pub mod active_managed;
/// Explicit aligned record selection over authenticated UDP or genuine QUIC.
pub mod aligned;
/// Strict command-line entry adapter; connection functions remain UI independent.
pub mod cli;
/// Shared strict native delivery policy for versioned profile configuration.
pub mod delivery;
/// Versioned private local API shared by CLI and future GUI.
#[cfg(unix)]
pub mod local;
/// Standalone OpenVPN-like UDP with separately provisioned admission/cookie keys.
pub mod openvpn;
/// Explicit timed packed records over authenticated UDP or genuine QUIC.
pub mod packed;
/// Explicit fixed-credit TUN proxy with retained original TCP/TLS ownership.
pub mod proxy;
/// Explicit measured relay targets over retained native TUN proxy TCP/TLS lanes.
pub mod proxy_measured;
/// Explicit genuine QUIC endpoint/profile configuration, independent of TCP.
pub mod quic;
/// Explicit original-owner raw packet runtime; native qualification remains separate.
pub mod raw_packet;
/// Shared existing-session command dispatch for authorized local frontends.
#[cfg(unix)]
pub mod session_control;
/// Explicit authenticated UDP endpoint/profile configuration.
pub mod udp;

/// First supported persistent TCP/TLS configuration, bound into authentication.
#[derive(Clone, Copy, Debug)]
pub struct ConnectionConfig {
    /// Native Ethernet or IP packets.
    pub layer: PacketLayer,
    /// Default half duplex requires two separately authenticated carriers.
    pub duplex: Duplex,
    /// Native packet size before protocol headers.
    pub max_packet: usize,
    /// Negotiated stateless compression policy.
    pub compression: Compression,
    /// One whole-attempt deadline from validated helper entry, including the
    /// first server accept, all TCP/TLS/member setup and half-duplex pairing.
    pub handshake_timeout: Duration,
}
impl ConnectionConfig {
    /// Derive a canonical domain-separated configuration digest.
    pub fn session(self) -> io::Result<SessionConfig> {
        self.runtime().validate()?;
        if self.handshake_timeout.is_zero() || self.handshake_timeout > Duration::from_secs(120) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "handshake timeout outside 0..120 seconds",
            ));
        }
        l2tunnel_runtime::managed::session_config(self.runtime(), &self.mode()?)
    }
    /// Canonical actually supported initial managed profile.
    pub fn mode(self) -> io::Result<ModeConfig> {
        l2tunnel_runtime::managed::mode_config(self.runtime(), self.duplex)
    }
    /// Derive an explicitly selected delivery policy binding, shared by GUI and CLI.
    /// Forward/reverse policies use canonical client-to-server/server-to-client order.
    pub fn session_with_delivery(
        self,
        delivery: l2tunnel_runtime::managed::DeliveryConfig,
    ) -> io::Result<SessionConfig> {
        // Preserve the exact existing validation, including the whole-attempt limit.
        self.session()?;
        l2tunnel_runtime::managed::session_config_with_delivery(
            self.runtime(),
            &self.mode_with_delivery(delivery)?,
            delivery,
        )
    }
    /// Keep local queue geometry separate from authenticated delivery-window limits.
    pub fn mode_with_delivery(
        self,
        delivery: l2tunnel_runtime::managed::DeliveryConfig,
    ) -> io::Result<ModeConfig> {
        l2tunnel_runtime::managed::mode_config_with_delivery(self.runtime(), self.duplex, delivery)
    }
    /// Bounded runtime defaults, independent of the GUI or CLI.
    pub fn runtime(self) -> RuntimeConfig {
        RuntimeConfig {
            layer: self.layer,
            max_packet: self.max_packet,
            compression: self.compression,
            queue_packets: 64,
            poll_interval: Duration::from_millis(1),
        }
    }
}
fn auth_error(error: auth::Error) -> io::Error {
    io::Error::other(error)
}
fn base_expired() -> io::Error {
    io::Error::new(
        io::ErrorKind::TimedOut,
        "original connection setup deadline elapsed",
    )
}
#[derive(Clone, Copy)]
struct HandshakeDeadline(Instant);
impl HandshakeDeadline {
    fn start(limit: Duration) -> io::Result<Self> {
        Instant::now()
            .checked_add(limit)
            .map(Self)
            .ok_or_else(base_expired)
    }
    fn remaining(self) -> io::Result<Duration> {
        self.0
            .checked_duration_since(Instant::now())
            .filter(|d| !d.is_zero())
            .ok_or_else(base_expired)
    }
    async fn within<T>(self, future: impl Future<Output = io::Result<T>>) -> io::Result<T> {
        self.remaining()?;
        let result = timeout_at(self.0, future)
            .await
            .map_err(|_| base_expired())?;
        // A ready I/O poll can cross the deadline before Tokio checks its timer.
        // Drop even a successful retained owner instead of accepting it late.
        self.remaining()?;
        result
    }
}
fn base_auth_error(error: auth::Error) -> io::Error {
    match error {
        auth::Error::TimedOut => base_expired(),
        other => auth_error(other),
    }
}
async fn socket(address: SocketAddr, timeout: Duration) -> io::Result<TcpStream> {
    let stream = tokio::time::timeout(timeout, TcpStream::connect(address))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "TCP connect timeout"))??;
    stream.set_nodelay(true)?;
    Ok(stream)
}
async fn base_socket(address: SocketAddr, deadline: HandshakeDeadline) -> io::Result<TcpStream> {
    deadline.remaining()?;
    let stream = TcpStream::connect(address).await?;
    deadline.remaining()?;
    stream.set_nodelay(true)?;
    Ok(stream)
}
/// Authenticate and retain one full-duplex connection or a paired half-duplex set.
/// One original deadline includes all TCP connects, TLS/member setup and pairing.
pub async fn connect(
    address: SocketAddr,
    tls: &ClientTls,
    server_name: &str,
    identity: &MemberKey,
    config: ConnectionConfig,
) -> io::Result<Link> {
    connect_session(
        address,
        tls,
        server_name,
        identity,
        config,
        config.session()?,
    )
    .await
}

/// Authenticate an explicit bounded delivery profile over the original TCP/TLS lanes.
/// Uses the same single whole-attempt deadline as [`connect`]; no runtime fallback.
pub async fn connect_with_delivery(
    address: SocketAddr,
    tls: &ClientTls,
    server_name: &str,
    identity: &MemberKey,
    config: ConnectionConfig,
    delivery: l2tunnel_runtime::managed::DeliveryConfig,
) -> io::Result<Link> {
    connect_session(
        address,
        tls,
        server_name,
        identity,
        config,
        config.session_with_delivery(delivery)?,
    )
    .await
}

pub(crate) async fn connect_session(
    address: SocketAddr,
    tls: &ClientTls,
    server_name: &str,
    identity: &MemberKey,
    config: ConnectionConfig,
    session: SessionConfig,
) -> io::Result<Link> {
    config.session()?;
    if session.layer != config.layer {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "authenticated profile and native layer differ",
        ));
    }
    let deadline = HandshakeDeadline::start(config.handshake_timeout)?;
    deadline
        .within(async {
            let lane = async || {
                let stream = base_socket(address, deadline).await?;
                let connection = auth::client_connect(
                    stream,
                    tls,
                    server_name,
                    identity,
                    session,
                    deadline.remaining()?,
                )
                .await
                .map_err(base_auth_error)?;
                deadline.remaining()?;
                Ok::<_, io::Error>(connection)
            };
            let first = lane().await?;
            match config.duplex {
                Duplex::Full => Ok(Link::full(first)),
                Duplex::Half => {
                    let second = lane().await?;
                    deadline.remaining()?;
                    l2tunnel_runtime::client_pair(first, second).await
                }
            }
        })
        .await
}
/// Accept one peer/pair. A failed or mismatched handshake returns an error.
/// The deadline starts at validated helper entry and includes the first accept.
/// Timeout/cancellation closes accepted sockets and leaves the caller-owned listener
/// usable. Persistent idle waiting, multi-peer arbitration and retries are caller policy.
pub async fn accept(
    listener: &TcpListener,
    tls: &ServerTls,
    allowlist: &MemberAllowlist,
    config: ConnectionConfig,
) -> io::Result<Link> {
    accept_session(listener, tls, allowlist, config, config.session()?).await
}

/// Accept the matching explicit delivery policy using the original full/half deadline.
/// A policy mismatch fails authentication; the listener remains caller-owned.
pub async fn accept_with_delivery(
    listener: &TcpListener,
    tls: &ServerTls,
    allowlist: &MemberAllowlist,
    config: ConnectionConfig,
    delivery: l2tunnel_runtime::managed::DeliveryConfig,
) -> io::Result<Link> {
    accept_session(
        listener,
        tls,
        allowlist,
        config,
        config.session_with_delivery(delivery)?,
    )
    .await
}

pub(crate) async fn accept_session(
    listener: &TcpListener,
    tls: &ServerTls,
    allowlist: &MemberAllowlist,
    config: ConnectionConfig,
    session: SessionConfig,
) -> io::Result<Link> {
    config.session()?;
    if session.layer != config.layer {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "authenticated profile and native layer differ",
        ));
    }
    let deadline = HandshakeDeadline::start(config.handshake_timeout)?;
    deadline
        .within(async {
            let lane = async || {
                deadline.remaining()?;
                let (stream, _) = listener.accept().await?;
                deadline.remaining()?;
                stream.set_nodelay(true)?;
                let connection =
                    auth::server_accept(stream, tls, allowlist, session, deadline.remaining()?)
                        .await
                        .map_err(base_auth_error)?;
                deadline.remaining()?;
                Ok::<_, io::Error>(connection)
            };
            let first = lane().await?;
            match config.duplex {
                Duplex::Full => Ok(Link::full(first)),
                Duplex::Half => {
                    let second = lane().await?;
                    deadline.remaining()?;
                    l2tunnel_runtime::server_pair(first, second).await
                }
            }
        })
        .await
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn canonical_digest_binds_every_data_plane_option() -> io::Result<()> {
        let base = ConnectionConfig {
            layer: PacketLayer::Ethernet,
            duplex: Duplex::Half,
            max_packet: 1600,
            compression: Compression::None,
            handshake_timeout: Duration::from_secs(10),
        };
        let digest = base.session()?.digest;
        for changed in [
            ConnectionConfig {
                compression: Compression::Lz4IfSmaller,
                ..base
            },
            ConnectionConfig {
                layer: PacketLayer::Ip,
                ..base
            },
            ConnectionConfig {
                duplex: Duplex::Full,
                ..base
            },
            ConnectionConfig {
                max_packet: 1500,
                ..base
            },
        ] {
            assert_ne!(digest, changed.session()?.digest);
        }
        assert_eq!(
            digest,
            ConnectionConfig {
                handshake_timeout: Duration::from_secs(20),
                ..base
            }
            .session()?
            .digest
        );
        Ok(())
    }
}

/// Explicit startup-bound rolling source/frame client and lifecycle observation.
pub mod rolling;

#[cfg(test)]
#[path = "base_deadline_tests.rs"]
mod base_deadline_tests;

#[cfg(test)]
mod delivery_tests;

#[cfg(test)]
mod base_datagram_delivery_tests;
