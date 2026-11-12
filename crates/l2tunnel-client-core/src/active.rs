//! Explicit transparent-TUN active profile through the shared authenticated lifecycle.
use super::*;
use l2tunnel_runtime::active as runtime;
/// Finite negotiated active policy; runtime validation remains authoritative.
pub use l2tunnel_runtime::active::Settings;

/// Authenticate and retain an active full or paired-half TLS link.
pub async fn connect(
    address: SocketAddr,
    tls: &ClientTls,
    server_name: &str,
    identity: &MemberKey,
    config: ConnectionConfig,
    settings: Settings,
) -> io::Result<Link> {
    if settings.duplex != config.duplex {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "active duplex mismatch",
        ));
    }
    let session = runtime::session_config(config.runtime(), settings)?;
    connect_session(address, tls, server_name, identity, config, session).await
}

/// Accept an active member using the same bounded second-lane pairing lifecycle.
pub async fn accept(
    listener: &TcpListener,
    tls: &ServerTls,
    allowlist: &MemberAllowlist,
    config: ConnectionConfig,
    settings: Settings,
) -> io::Result<Link> {
    if settings.duplex != config.duplex {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "active duplex mismatch",
        ));
    }
    let session = runtime::session_config(config.runtime(), settings)?;
    accept_session(listener, tls, allowlist, config, session).await
}
