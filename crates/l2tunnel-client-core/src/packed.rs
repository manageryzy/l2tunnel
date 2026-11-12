//! Explicit timed packed records on the existing authenticated UDP/QUIC owners.
use super::{ConnectionConfig, quic, udp};
use l2tunnel_auth::{ClientTls, MemberAllowlist, MemberKey, ServerTls};
use l2tunnel_runtime::{Compression, packed as runtime};
use std::{future::Future, io, net::SocketAddr};
use tokio::{net::TcpListener, time::Instant};

/// Fixed packed policy shared by CLI and future GUI clients.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Settings {
    /// Common native MUX channel pool; 255 is reserved by the packed wire format.
    pub channels: u16,
    /// Original hold deadline and bounded source/admission work.
    pub packing: runtime::Options,
}
impl Settings {
    /// Reject unsupported combinations before credential, socket or native I/O.
    pub fn validate(self, config: ConnectionConfig, recovery: udp::RecoveryMode) -> io::Result<()> {
        config.session()?;
        if !(1..=255).contains(&self.channels)
            || !(1..=1000).contains(&self.packing.hold_micros)
            || self.packing.max_units == 0
            || !(1..=255).contains(&self.packing.work_limit)
            || config.compression != Compression::None
            || !matches!(recovery, udp::RecoveryMode::Cauchy { .. })
        {
            return Err(invalid(
                "packed requires bounded packing, channels1..255, compression off and explicit Cauchy",
            ));
        }
        Ok(())
    }
}
/// Derive the authoritative UDP and packed source/batch geometry.
pub fn udp_config(
    config: ConnectionConfig,
    transport: udp::Settings,
    settings: Settings,
) -> io::Result<(l2tunnel_runtime::udp::Config, runtime::Config)> {
    settings.validate(config, transport.recovery)?;
    let profile = udp::runtime_config(config, transport)?;
    Ok((
        profile,
        runtime::Config::for_udp(
            config.runtime(),
            profile,
            settings.channels,
            settings.packing,
        )?,
    ))
}
/// Derive the authoritative genuine QUIC and packed source/batch geometry.
pub fn quic_config(
    config: ConnectionConfig,
    transport: quic::Settings,
    settings: Settings,
) -> io::Result<(l2tunnel_runtime::quic::Config, runtime::Config)> {
    settings.validate(config, transport.recovery)?;
    let profile = quic::runtime_config(config, transport)?;
    Ok((
        profile,
        runtime::Config::for_quic(
            config.runtime(),
            profile,
            settings.channels,
            settings.packing,
        )?,
    ))
}
/// Authenticate actual packed UDP lanes under one original setup deadline.
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
    let (profile, packed) = udp_config(config, transport, settings)?;
    let end = deadline(config)?;
    finish_before(end, async {
        let lanes = udp::connect_lanes(
            address,
            tls,
            name,
            identity,
            config,
            transport,
            udp::Records::Packed(&packed),
        )
        .await?;
        let link = match lanes.second {
            None => runtime::UdpLink::full(lanes.first, config.runtime(), profile, packed)?,
            Some(second) => {
                runtime::udp_client_pair(lanes.first, second, config.runtime(), profile, packed)
                    .await?
            }
        };
        Ok((link, profile, packed))
    })
    .await
}
/// Accept one packed UDP peer/pair; cancellation keeps the borrowed TCP listener.
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
    let (profile, packed) = udp_config(config, transport, settings)?;
    let end = deadline(config)?;
    finish_before(end, async {
        let lanes = udp::accept_lanes(
            listener,
            tls,
            allowlist,
            config,
            transport,
            udp::Records::Packed(&packed),
        )
        .await?;
        let link = match lanes.second {
            None => runtime::UdpLink::full(lanes.first, config.runtime(), profile, packed)?,
            Some(second) => {
                runtime::udp_server_pair(lanes.first, second, config.runtime(), profile, packed)
                    .await?
            }
        };
        Ok((link, profile, packed))
    })
    .await
}
/// Authenticate genuine QUIC packed lanes without opening TCP sockets.
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
    let (profile, packed) = quic_config(config, transport, settings)?;
    let base = runtime::quic_base_session_config(config.runtime(), profile, packed)?;
    let end = deadline(config)?;
    finish_before(end, async {
        let lanes = quic::connect_lanes(roots, name, member, config, transport, base).await?;
        let link = match lanes.second {
            None => runtime::QuicLink::full(lanes.first, config.runtime(), profile, packed)?,
            Some(second) => {
                finish_before(
                    end.min(lanes.pair_deadline),
                    runtime::quic_client_pair(
                        lanes.first,
                        second,
                        config.runtime(),
                        profile,
                        packed,
                    ),
                )
                .await?
            }
        };
        Ok((link, profile, packed))
    })
    .await
}
/// Reusable genuine QUIC listener; it owns its pre-existing UDP endpoints.
pub struct QuicListener {
    listener: quic::Listener,
    connection: ConnectionConfig,
    packed: runtime::Config,
}
impl QuicListener {
    /// Validate exact packed policy before binding all configured UDP endpoints.
    pub fn bind(
        certs: &[Vec<u8>],
        key: &[u8],
        connection: ConnectionConfig,
        transport: quic::Settings,
        settings: Settings,
    ) -> io::Result<Self> {
        let (profile, packed) = quic_config(connection, transport, settings)?;
        let base = runtime::quic_base_session_config(connection.runtime(), profile, packed)?;
        Ok(Self {
            listener: quic::Listener::bind_base(certs, key, connection, transport, base)?,
            connection,
            packed,
        })
    }
    /// Run one finite peer attempt; cancellation preserves the listener endpoints.
    pub async fn accept(
        &self,
        allowlist: &MemberAllowlist,
    ) -> io::Result<(
        runtime::QuicLink,
        l2tunnel_runtime::quic::Config,
        runtime::Config,
    )> {
        let end = deadline(self.connection)?;
        finish_before(end, async {
            let lanes = self.listener.accept_lanes(allowlist).await?;
            let profile = lanes.profile;
            let link = match lanes.second {
                None => runtime::QuicLink::full(
                    lanes.first,
                    self.connection.runtime(),
                    profile,
                    self.packed,
                )?,
                Some(second) => {
                    finish_before(
                        end.min(lanes.pair_deadline),
                        runtime::quic_server_pair(
                            lanes.first,
                            second,
                            self.connection.runtime(),
                            profile,
                            self.packed,
                        ),
                    )
                    .await?
                }
            };
            Ok((link, profile, self.packed))
        })
        .await
    }
}
fn deadline(config: ConnectionConfig) -> io::Result<Instant> {
    Instant::now()
        .checked_add(config.handshake_timeout)
        .ok_or_else(|| invalid("packed setup deadline overflow"))
}
async fn finish_before<T>(
    end: Instant,
    operation: impl Future<Output = io::Result<T>>,
) -> io::Result<T> {
    if Instant::now() >= end {
        return Err(expired());
    }
    let value = tokio::time::timeout_at(end, operation)
        .await
        .map_err(|_| expired())?;
    // timeout_at may poll a ready inner future first. A returned capability must
    // still belong to the same original, live setup allowance. A late inner
    // failure also loses to that deadline rather than escaping as a different
    // error merely because timeout_at polled the ready operation first.
    if Instant::now() >= end {
        return Err(expired());
    }
    value
}
fn expired() -> io::Error {
    io::Error::new(io::ErrorKind::TimedOut, "packed original setup deadline")
}
fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

#[cfg(test)]
#[path = "packed_tests.rs"]
mod tests;
