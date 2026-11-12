//! Explicit fixed rolling-frame recovery over retained authenticated UDP/QUIC owners.
//! No existing carrier profile, runtime default or client mode is changed.
use super::{Duplex, RuntimeConfig, invalid, packet_valid, quic, udp};
use l2tunnel_auth::SessionConfig;
use l2tunnel_codec::{
    FRAGMENT_HEADER_BYTES, FragmentConfig, FragmentContext, Fragmenter, MessageId, Reassembler,
    ReassemblyConfig, ReassemblyStatus, SessionId,
};
use l2tunnel_core::{ConfigDigest, Epoch};
use l2tunnel_device::{PacketDevice, PacketLayer};
use l2tunnel_fec::rolling::{self as protocol, scheduler};
use l2tunnel_pipeline::{self as pipeline, Pipeline, PipelineConfig};
use std::{collections::VecDeque, io, net::SocketAddr, time::Duration};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    sync::{mpsc, watch},
    task::JoinSet,
    time::{Instant, MissedTickBehavior, interval},
};
use udp::{DatagramParts, DatagramPolicy, DatagramReceive, DatagramSend, Lane};
mod config;
pub use config::Config;
mod owner;
use owner::{LaneContext, State};
mod pump;
use pump::run_parts;

fn ticks(now: Duration) -> io::Result<protocol::Tick> {
    u64::try_from(now.as_millis())
        .map(protocol::Tick)
        .map_err(|_| invalid("rolling runtime clock exhausted"))
}
fn add(value: &mut u64) -> io::Result<()> {
    *value = value
        .checked_add(1)
        .ok_or_else(|| invalid("rolling frame counter exhausted"))?;
    Ok(())
}

/// Canonical rolling policy before applying the selected physical UDP lane.
pub fn udp_base_session_config(
    runtime: RuntimeConfig,
    transport: udp::Config,
    config: Config,
) -> io::Result<SessionConfig> {
    config.validate(runtime, transport.policy()?)?;
    config.bind(udp::base_session_config(runtime, transport)?)
}
/// Exact retained TLS member-authentication binding for this rolling UDP lane.
pub fn udp_session_config(
    runtime: RuntimeConfig,
    transport: udp::Config,
    config: Config,
    lane: Lane,
) -> io::Result<SessionConfig> {
    let carrier = udp_carrier_config(
        runtime,
        transport,
        config,
        lane,
        SocketAddr::from(([127, 0, 0, 1], 1)),
    )?;
    l2tunnel_udp::session_config(carrier.base, carrier.profile).map_err(io::Error::other)
}
/// Construct the actual fixed-endpoint carrier with rolling authentication binding.
pub fn udp_carrier_config(
    runtime: RuntimeConfig,
    transport: udp::Config,
    config: Config,
    lane: Lane,
    peer: SocketAddr,
) -> io::Result<l2tunnel_udp::Config> {
    let mut carrier = udp::carrier_config(runtime, transport, lane, peer)?;
    carrier.base = udp_base_session_config(runtime, transport, config)?;
    Ok(carrier)
}
/// Canonical rolling native binding passed to the genuine QUIC endpoint.
pub fn quic_base_session_config(
    runtime: RuntimeConfig,
    transport: quic::Config,
    config: Config,
) -> io::Result<SessionConfig> {
    config.validate(runtime, transport.policy()?)?;
    config.bind(quic::base_session_config(runtime, transport)?)
}
/// Exact expected member-authentication binding after QUIC profile application.
pub fn quic_session_config(
    runtime: RuntimeConfig,
    transport: quic::Config,
    config: Config,
    lane: Lane,
) -> io::Result<SessionConfig> {
    l2tunnel_quic::session_config(
        quic_base_session_config(runtime, transport, config)?,
        quic::carrier_profile(transport, lane)?,
    )
    .map_err(io::Error::other)
}
/// Actual retained full or paired-half UDP carriers bound to rolling native policy.
pub struct UdpLink(udp::Link);
impl UdpLink {
    /// Validate one full-duplex authenticated carrier before native admission.
    pub fn full(
        carrier: l2tunnel_udp::Carrier,
        runtime: RuntimeConfig,
        transport: udp::Config,
        config: Config,
    ) -> io::Result<Self> {
        Ok(Self(udp::Link::full_bound(
            carrier,
            runtime,
            transport,
            udp_base_session_config(runtime, transport, config)?,
        )?))
    }
}
/// Prove two distinct client UDP lanes with their existing retained pair protocol.
pub async fn udp_client_pair(
    first: l2tunnel_udp::Carrier,
    second: l2tunnel_udp::Carrier,
    runtime: RuntimeConfig,
    transport: udp::Config,
    config: Config,
) -> io::Result<UdpLink> {
    Ok(UdpLink(
        udp::pair_bound(
            first,
            second,
            runtime,
            transport,
            udp_base_session_config(runtime, transport, config)?,
            true,
        )
        .await?,
    ))
}
/// Verify two distinct server UDP lanes before any native device read.
pub async fn udp_server_pair(
    first: l2tunnel_udp::Carrier,
    second: l2tunnel_udp::Carrier,
    runtime: RuntimeConfig,
    transport: udp::Config,
    config: Config,
) -> io::Result<UdpLink> {
    Ok(UdpLink(
        udp::pair_bound(
            first,
            second,
            runtime,
            transport,
            udp_base_session_config(runtime, transport, config)?,
            false,
        )
        .await?,
    ))
}
/// Actual retained full or paired-half genuine QUIC connections with rolling binding.
pub struct QuicLink(quic::Link);
impl QuicLink {
    /// Validate one full-duplex genuine QUIC connection before native admission.
    pub fn full(
        connection: l2tunnel_quic::AuthenticatedConnection,
        runtime: RuntimeConfig,
        transport: quic::Config,
        config: Config,
    ) -> io::Result<Self> {
        Ok(Self(quic::Link::full_bound(
            connection,
            runtime,
            transport,
            quic_base_session_config(runtime, transport, config)?,
        )?))
    }
}
/// Prove the client's two actual independently authenticated QUIC lanes.
pub async fn quic_client_pair(
    first: l2tunnel_quic::AuthenticatedConnection,
    second: l2tunnel_quic::AuthenticatedConnection,
    runtime: RuntimeConfig,
    transport: quic::Config,
    config: Config,
) -> io::Result<QuicLink> {
    Ok(QuicLink(
        quic::pair_bound(
            first,
            second,
            runtime,
            transport,
            quic_base_session_config(runtime, transport, config)?,
            true,
        )
        .await?,
    ))
}
/// Verify the server's two actual independently authenticated QUIC lanes.
pub async fn quic_server_pair(
    first: l2tunnel_quic::AuthenticatedConnection,
    second: l2tunnel_quic::AuthenticatedConnection,
    runtime: RuntimeConfig,
    transport: quic::Config,
    config: Config,
) -> io::Result<QuicLink> {
    Ok(QuicLink(
        quic::pair_bound(
            first,
            second,
            runtime,
            transport,
            quic_base_session_config(runtime, transport, config)?,
            false,
        )
        .await?,
    ))
}
/// Run fixed rolling native forwarding on actual protected UDP, retaining TLS control.
pub async fn run_udp<D: PacketDevice<Error = io::Error>>(
    device: D,
    link: UdpLink,
    runtime: RuntimeConfig,
    transport: udp::Config,
    config: Config,
) -> io::Result<()> {
    let (parts, initiator) = link
        .0
        .into_bound_parts(udp_base_session_config(runtime, transport, config)?)?;
    run_parts(
        device,
        parts,
        initiator,
        runtime,
        transport.policy()?,
        config,
    )
    .await
}
/// Run fixed rolling native forwarding on actual standalone QUIC; no TCP socket is added.
pub async fn run_quic<D: PacketDevice<Error = io::Error>>(
    device: D,
    link: QuicLink,
    runtime: RuntimeConfig,
    transport: quic::Config,
    config: Config,
) -> io::Result<()> {
    let (parts, initiator) = link
        .0
        .into_bound_parts(quic_base_session_config(runtime, transport, config)?)?;
    run_parts(
        device,
        parts,
        initiator,
        runtime,
        transport.policy()?,
        config,
    )
    .await
}

#[cfg(test)]
mod tests;
