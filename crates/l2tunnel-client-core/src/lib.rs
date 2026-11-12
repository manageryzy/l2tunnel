//! Shared headless connection lifecycle for CLI and future GUI clients.
use l2tunnel_auth::{
    self as auth, ClientTls, MemberAllowlist, MemberKey, ServerTls, SessionConfig,
};
/// Stateless per-packet compression.
pub use l2tunnel_codec::Compression;
use l2tunnel_core::{Duplex, ModeConfig};
use l2tunnel_device::PacketLayer;
use l2tunnel_runtime::{Link, RuntimeConfig};
use std::io;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream};

/// Explicit transparent-TUN credit and QoS client profile.
pub mod active;
/// Negotiated active policy catalog and managed authentication lifecycle.
pub mod active_managed;
/// Explicit aligned record selection over authenticated UDP or genuine QUIC.
pub mod aligned;
/// Strict command-line entry adapter; connection functions remain UI independent.
pub mod cli;
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
    /// Whole handshake/second-lane deadline.
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
async fn socket(address: SocketAddr, timeout: Duration) -> io::Result<TcpStream> {
    let stream = tokio::time::timeout(timeout, TcpStream::connect(address))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "TCP connect timeout"))??;
    stream.set_nodelay(true)?;
    Ok(stream)
}
/// Authenticate and retain one full-duplex connection or a paired half-duplex set.
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
    let first = auth::client_connect(
        socket(address, config.handshake_timeout).await?,
        tls,
        server_name,
        identity,
        session,
        config.handshake_timeout,
    )
    .await
    .map_err(auth_error)?;
    match config.duplex {
        Duplex::Full => Ok(Link::full(first)),
        Duplex::Half => {
            let second = auth::client_connect(
                socket(address, config.handshake_timeout).await?,
                tls,
                server_name,
                identity,
                session,
                config.handshake_timeout,
            )
            .await
            .map_err(auth_error)?;
            l2tunnel_runtime::client_pair(first, second).await
        }
    }
}
/// Accept one peer/pair. A failed or mismatched handshake returns an error.
/// Multi-peer arbitration and reconnect policy are higher-level future work.
pub async fn accept(
    listener: &TcpListener,
    tls: &ServerTls,
    allowlist: &MemberAllowlist,
    config: ConnectionConfig,
) -> io::Result<Link> {
    accept_session(listener, tls, allowlist, config, config.session()?).await
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
    let (first, _) = listener.accept().await?;
    first.set_nodelay(true)?;
    let first = auth::server_accept(first, tls, allowlist, session, config.handshake_timeout)
        .await
        .map_err(auth_error)?;
    match config.duplex {
        Duplex::Full => Ok(Link::full(first)),
        Duplex::Half => {
            let (second, _) = tokio::time::timeout(config.handshake_timeout, listener.accept())
                .await
                .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "second carrier timeout"))??;
            second.set_nodelay(true)?;
            let second =
                auth::server_accept(second, tls, allowlist, session, config.handshake_timeout)
                    .await
                    .map_err(auth_error)?;
            l2tunnel_runtime::server_pair(first, second).await
        }
    }
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
