//! Explicit aligned records over existing authenticated UDP and genuine QUIC lanes.
use super::{ConnectionConfig, quic, udp};
use l2tunnel_auth::{ClientTls, MemberAllowlist, MemberKey, ServerTls};
use l2tunnel_runtime::{Compression, aligned as runtime};
use std::{io, net::SocketAddr};
use tokio::net::TcpListener;

/// Fixed aligned policy shared by CLI and future GUI clients.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Settings {
    /// Common native MUX channel pool, shared by every packet and probe.
    pub channels: u16,
}
impl Settings {
    /// Validate explicit record compatibility before credentials/socket/device work.
    pub fn validate(self, config: ConnectionConfig, recovery: udp::RecoveryMode) -> io::Result<()> {
        config.session()?;
        if !(1..=256).contains(&self.channels)
            || config.compression != Compression::None
            || !matches!(recovery, udp::RecoveryMode::Cauchy { .. })
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "aligned requires channels1..256, compression off and explicit Cauchy recovery",
            ));
        }
        Ok(())
    }
}
/// Canonical transport and aligned limits; no profile fallback is performed.
pub fn udp_config(
    config: ConnectionConfig,
    transport: udp::Settings,
    settings: Settings,
) -> io::Result<(l2tunnel_runtime::udp::Config, runtime::Config)> {
    settings.validate(config, transport.recovery)?;
    let profile = udp::runtime_config(config, transport)?;
    Ok((
        profile,
        runtime::Config::for_udp(config.runtime(), profile, settings.channels)?,
    ))
}
/// Canonical genuine QUIC and aligned limits; no TCP bootstrap is added.
pub fn quic_config(
    config: ConnectionConfig,
    transport: quic::Settings,
    settings: Settings,
) -> io::Result<(l2tunnel_runtime::quic::Config, runtime::Config)> {
    settings.validate(config, transport.recovery)?;
    let profile = quic::runtime_config(config, transport)?;
    Ok((
        profile,
        runtime::Config::for_quic(config.runtime(), profile, settings.channels)?,
    ))
}
/// Authenticate explicit aligned UDP lanes and retain their TLS control streams.
pub async fn connect_udp(
    address: SocketAddr,
    tls: &ClientTls,
    name: &str,
    identity: &MemberKey,
    config: ConnectionConfig,
    transport: udp::Settings,
    settings: Settings,
) -> io::Result<(
    runtime::UdpLink,
    l2tunnel_runtime::udp::Config,
    runtime::Config,
)> {
    let (profile, aligned) = udp_config(config, transport, settings)?;
    let lanes = udp::connect_lanes(
        address,
        tls,
        name,
        identity,
        config,
        transport,
        udp::Records::Aligned(&aligned),
    )
    .await?;
    let link = match lanes.second {
        None => runtime::UdpLink::full(lanes.first, config.runtime(), profile, aligned)?,
        Some(second) => {
            runtime::udp_client_pair(lanes.first, second, config.runtime(), profile, aligned)
                .await?
        }
    };
    Ok((link, profile, aligned))
}
/// Accept one aligned UDP peer/pair before opening its native packet device.
pub async fn accept_udp(
    listener: &TcpListener,
    tls: &ServerTls,
    allowlist: &MemberAllowlist,
    config: ConnectionConfig,
    transport: udp::Settings,
    settings: Settings,
) -> io::Result<(
    runtime::UdpLink,
    l2tunnel_runtime::udp::Config,
    runtime::Config,
)> {
    let (profile, aligned) = udp_config(config, transport, settings)?;
    let lanes = udp::accept_lanes(
        listener,
        tls,
        allowlist,
        config,
        transport,
        udp::Records::Aligned(&aligned),
    )
    .await?;
    let link = match lanes.second {
        None => runtime::UdpLink::full(lanes.first, config.runtime(), profile, aligned)?,
        Some(second) => {
            runtime::udp_server_pair(lanes.first, second, config.runtime(), profile, aligned)
                .await?
        }
    };
    Ok((link, profile, aligned))
}
/// Authenticate aligned genuine QUIC lanes without creating a TCP socket.
pub async fn connect_quic(
    roots: &[Vec<u8>],
    name: &str,
    member: &MemberKey,
    config: ConnectionConfig,
    transport: quic::Settings,
    settings: Settings,
) -> io::Result<(
    runtime::QuicLink,
    l2tunnel_runtime::quic::Config,
    runtime::Config,
)> {
    let (profile, aligned) = quic_config(config, transport, settings)?;
    let base = runtime::quic_base_session_config(config.runtime(), profile, aligned)?;
    let lanes = quic::connect_lanes(roots, name, member, config, transport, base).await?;
    let link = match lanes.second {
        None => runtime::QuicLink::full(lanes.first, config.runtime(), profile, aligned)?,
        Some(second) => {
            quic::finish_pair(
                lanes.pair_deadline,
                runtime::quic_client_pair(lanes.first, second, config.runtime(), profile, aligned),
            )
            .await?
        }
    };
    Ok((link, profile, aligned))
}
/// Both genuine QUIC listener lanes bound to the explicit aligned configuration.
pub struct QuicListener {
    listener: quic::Listener,
    connection: ConnectionConfig,
    aligned: runtime::Config,
}
impl QuicListener {
    /// Validate canonical aligned policy and bind every required UDP lane.
    pub fn bind(
        certs: &[Vec<u8>],
        key: &[u8],
        connection: ConnectionConfig,
        transport: quic::Settings,
        settings: Settings,
    ) -> io::Result<Self> {
        let (profile, aligned) = quic_config(connection, transport, settings)?;
        let base = runtime::quic_base_session_config(connection.runtime(), profile, aligned)?;
        Ok(Self {
            listener: quic::Listener::bind_base(certs, key, connection, transport, base)?,
            connection,
            aligned,
        })
    }
    /// Authenticate and pair exactly the configured peer, retaining owned endpoints.
    pub async fn accept(
        &self,
        allowlist: &MemberAllowlist,
    ) -> io::Result<(
        runtime::QuicLink,
        l2tunnel_runtime::quic::Config,
        runtime::Config,
    )> {
        let lanes = self.listener.accept_lanes(allowlist).await?;
        let profile = lanes.profile;
        let link = match lanes.second {
            None => runtime::QuicLink::full(
                lanes.first,
                self.connection.runtime(),
                profile,
                self.aligned,
            )?,
            Some(second) => {
                quic::finish_pair(
                    lanes.pair_deadline,
                    runtime::quic_server_pair(
                        lanes.first,
                        second,
                        self.connection.runtime(),
                        profile,
                        self.aligned,
                    ),
                )
                .await?
            }
        };
        Ok((link, profile, self.aligned))
    }
}

#[cfg(test)]
#[path = "aligned_tests.rs"]
mod tests;
