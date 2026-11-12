//! Explicit shared rolling-frame client policy and retained carrier/session ownership.
use crate::{ConnectionConfig, quic, udp};
use l2tunnel_auth::{ClientTls, MemberAllowlist, MemberKey, ServerTls};
use l2tunnel_runtime::rolling as runtime;
use std::{future::Future, io, net::SocketAddr};
use tokio::{net::TcpListener, time::Instant};
mod policy;
pub use policy::Settings;
mod status;
pub use status::{Carrier, Cover, LaneMode, Layer, Observer, Phase, PipelineProfile, Snapshot};
/// Maximum entire untrusted rolling policy document before parser allocation.
pub const MAX_POLICY_BYTES: usize = 65536;
/// Explicit authenticated profile selected only by this client surface.
pub const PROFILE: &str = "rolling-frame-v1";
fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}
fn end(config: ConnectionConfig) -> io::Result<Instant> {
    Instant::now()
        .checked_add(config.handshake_timeout)
        .ok_or_else(|| invalid("rolling original setup deadline overflow"))
}
async fn finish_before<T>(
    deadline: Instant,
    operation: impl Future<Output = io::Result<T>>,
) -> io::Result<T> {
    let expired = || io::Error::new(io::ErrorKind::TimedOut, "rolling original setup deadline");
    if Instant::now() >= deadline {
        return Err(expired());
    }
    let result = tokio::time::timeout_at(deadline, operation)
        .await
        .map_err(|_| expired())?;
    if Instant::now() >= deadline {
        return Err(expired());
    }
    result
}
/// Derive exact protected UDP and rolling policy before credentials, sockets or device I/O.
pub fn udp_config(
    config: ConnectionConfig,
    transport: udp::Settings,
    settings: &Settings,
) -> io::Result<(l2tunnel_runtime::udp::Config, runtime::Config)> {
    settings.validate(config, transport.recovery)?;
    let profile = udp::runtime_config(config, transport)?;
    let value = settings.apply(runtime::Config::for_udp(
        config.runtime(),
        profile,
        settings.channels,
    )?);
    runtime::udp_base_session_config(config.runtime(), profile, value)?;
    Ok((profile, value))
}
/// Derive exact genuine QUIC and rolling policy without adding a TCP bootstrap.
pub fn quic_config(
    config: ConnectionConfig,
    transport: quic::Settings,
    settings: &Settings,
) -> io::Result<(l2tunnel_runtime::quic::Config, runtime::Config)> {
    settings.validate(config, transport.recovery)?;
    let profile = quic::runtime_config(config, transport)?;
    let value = settings.apply(runtime::Config::for_quic(
        config.runtime(),
        profile,
        settings.channels,
    )?);
    runtime::quic_base_session_config(config.runtime(), profile, value)?;
    Ok((profile, value))
}
enum Link {
    Udp(
        runtime::UdpLink,
        l2tunnel_runtime::udp::Config,
        runtime::Config,
    ),
    Quic(
        runtime::QuicLink,
        l2tunnel_runtime::quic::Config,
        runtime::Config,
    ),
}
/// Sole actual authenticated carrier/runtime capability; dropping it is cancellation.
pub struct Session {
    link: Option<Link>,
    connection: ConnectionConfig,
    observer: Observer,
    done: bool,
}
impl Session {
    fn new(
        link: Link,
        connection: ConnectionConfig,
        rolling: runtime::Config,
        carrier: Carrier,
        cover: Cover,
        digest: l2tunnel_core::ConfigDigest,
    ) -> Self {
        Self {
            link: Some(link),
            connection,
            observer: Observer::new(connection, rolling, carrier, cover, digest),
            done: false,
        }
    }
    /// Clone a bounded non-secret observer, never another runtime or drain owner.
    pub fn observer(&self) -> Observer {
        self.observer.clone()
    }
    /// Run the sole device/carrier owner. Unsupported clean completion is never invented.
    pub async fn run<D: l2tunnel_device::PacketDevice<Error = io::Error>>(
        mut self,
        device: D,
    ) -> io::Result<()> {
        if device.layer() != self.connection.layer {
            let error = invalid("rolling device layer differs from authenticated selection");
            self.observer.failed(&error);
            self.done = true;
            return Err(error);
        }
        self.observer.phase(Phase::Forwarding);
        let result = match self
            .link
            .take()
            .ok_or_else(|| invalid("rolling session already consumed"))?
        {
            Link::Udp(link, transport, rolling) => {
                runtime::run_udp(device, link, self.connection.runtime(), transport, rolling).await
            }
            Link::Quic(link, transport, rolling) => {
                runtime::run_quic(device, link, self.connection.runtime(), transport, rolling).await
            }
        };
        let error = match result {
            Err(error) => error,
            Ok(()) => io::Error::other("rolling runtime stopped without a clean-close protocol"),
        };
        self.observer.failed(&error);
        self.done = true;
        Err(error)
    }
}
impl Drop for Session {
    fn drop(&mut self) {
        if !self.done {
            self.observer.phase(Phase::Cancelled);
        }
    }
}
/// Connect actual rolling protected-UDP lanes under one original full/pair deadline.
pub async fn connect_udp(
    address: SocketAddr,
    tls: &ClientTls,
    name: &str,
    identity: &MemberKey,
    config: ConnectionConfig,
    transport: udp::Settings,
    settings: &Settings,
) -> io::Result<Session> {
    let deadline = end(config)?;
    let (profile, rolling) = udp_config(config, transport, settings)?;
    finish_before(deadline, async {
        let lanes = udp::connect_lanes(
            address,
            tls,
            name,
            identity,
            config,
            transport,
            udp::Records::Rolling(&rolling),
        )
        .await?;
        let link = match lanes.second {
            None => runtime::UdpLink::full(lanes.first, config.runtime(), profile, rolling)?,
            Some(second) => {
                runtime::udp_client_pair(lanes.first, second, config.runtime(), profile, rolling)
                    .await?
            }
        };
        let digest = runtime::udp_base_session_config(config.runtime(), profile, rolling)?.digest;
        Ok(Session::new(
            Link::Udp(link, profile, rolling),
            config,
            rolling,
            Carrier::Udp,
            Cover::from(transport.cover),
            digest,
        ))
    })
    .await
}
/// Accept one rolling UDP peer/pair; cancellation retains the borrowed TCP listener.
pub async fn accept_udp(
    listener: &TcpListener,
    tls: &ServerTls,
    allowlist: &MemberAllowlist,
    config: ConnectionConfig,
    transport: udp::Settings,
    settings: &Settings,
) -> io::Result<Session> {
    let deadline = end(config)?;
    let (profile, rolling) = udp_config(config, transport, settings)?;
    finish_before(deadline, async {
        let lanes = udp::accept_lanes(
            listener,
            tls,
            allowlist,
            config,
            transport,
            udp::Records::Rolling(&rolling),
        )
        .await?;
        let link = match lanes.second {
            None => runtime::UdpLink::full(lanes.first, config.runtime(), profile, rolling)?,
            Some(second) => {
                runtime::udp_server_pair(lanes.first, second, config.runtime(), profile, rolling)
                    .await?
            }
        };
        let digest = runtime::udp_base_session_config(config.runtime(), profile, rolling)?.digest;
        Ok(Session::new(
            Link::Udp(link, profile, rolling),
            config,
            rolling,
            Carrier::Udp,
            Cover::from(transport.cover),
            digest,
        ))
    })
    .await
}
/// Authenticate genuine rolling QUIC under one original full/paired setup allowance.
pub async fn connect_quic(
    roots: &[Vec<u8>],
    name: &str,
    member: &MemberKey,
    config: ConnectionConfig,
    transport: quic::Settings,
    settings: &Settings,
) -> io::Result<Session> {
    let deadline = end(config)?;
    let (profile, rolling) = quic_config(config, transport, settings)?;
    let base = runtime::quic_base_session_config(config.runtime(), profile, rolling)?;
    finish_before(deadline, async {
        let lanes = quic::connect_lanes(roots, name, member, config, transport, base).await?;
        let link = match lanes.second {
            None => runtime::QuicLink::full(lanes.first, config.runtime(), profile, rolling)?,
            Some(second) => {
                finish_before(
                    deadline.min(lanes.pair_deadline),
                    runtime::quic_client_pair(
                        lanes.first,
                        second,
                        config.runtime(),
                        profile,
                        rolling,
                    ),
                )
                .await?
            }
        };
        Ok(Session::new(
            Link::Quic(link, profile, rolling),
            config,
            rolling,
            Carrier::Quic,
            Cover::NotApplicable,
            base.digest,
        ))
    })
    .await
}
/// Reusable genuine QUIC endpoint owner; each accept has its own original allowance.
pub struct QuicListener {
    listener: quic::Listener,
    connection: ConnectionConfig,
    rolling: runtime::Config,
}
impl QuicListener {
    /// Validate complete rolling policy before binding required genuine QUIC UDP endpoints.
    pub fn bind(
        certs: &[Vec<u8>],
        key: &[u8],
        connection: ConnectionConfig,
        transport: quic::Settings,
        settings: &Settings,
    ) -> io::Result<Self> {
        let (profile, rolling) = quic_config(connection, transport, settings)?;
        let base = runtime::quic_base_session_config(connection.runtime(), profile, rolling)?;
        Ok(Self {
            listener: quic::Listener::bind_base(certs, key, connection, transport, base)?,
            connection,
            rolling,
        })
    }
    /// Accept a retained full/pair; dropping this future does not replace borrowed endpoints.
    pub async fn accept(&self, allowlist: &MemberAllowlist) -> io::Result<Session> {
        let deadline = end(self.connection)?;
        finish_before(deadline, async {
            let lanes = self.listener.accept_lanes(allowlist).await?;
            let profile = lanes.profile;
            let link = match lanes.second {
                None => runtime::QuicLink::full(
                    lanes.first,
                    self.connection.runtime(),
                    profile,
                    self.rolling,
                )?,
                Some(second) => {
                    finish_before(
                        deadline.min(lanes.pair_deadline),
                        runtime::quic_server_pair(
                            lanes.first,
                            second,
                            self.connection.runtime(),
                            profile,
                            self.rolling,
                        ),
                    )
                    .await?
                }
            };
            let digest = runtime::quic_base_session_config(
                self.connection.runtime(),
                profile,
                self.rolling,
            )?
            .digest;
            Ok(Session::new(
                Link::Quic(link, profile, self.rolling),
                self.connection,
                self.rolling,
                Carrier::Quic,
                Cover::NotApplicable,
                digest,
            ))
        })
        .await
    }
}

#[cfg(test)]
mod tests;
