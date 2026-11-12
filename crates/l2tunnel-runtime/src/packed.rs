//! Timed packed native sources over the same authenticated UDP/QUIC runtime actor.
//! Packing is explicit and separately bound; it does not change ordinary aligned wire.
use crate::{RuntimeConfig, aligned, invalid, quic, udp};
use l2tunnel_aligned::packed as protocol;
use l2tunnel_auth::SessionConfig;
use l2tunnel_device::PacketDevice;
use l2tunnel_pipeline::PipelineConfig;
use std::{io, net::SocketAddr};
use udp::{DatagramPolicy, Lane};

/// Finite packing policy authenticated before native admission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Options {
    /// Original first-unit maximum hold in microseconds, in 1..=1000.
    pub hold_micros: u64,
    /// Maximum complete units in one source, in 1..=255 and limited by MTU.
    pub max_units: u8,
    /// Maximum bounded codec/admission work per service, in 1..=255.
    pub work_limit: usize,
}
/// Immutable packed interpretation and the existing common MUX/QoS policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Config {
    /// Required canonical native flight budgets, independent of local queues.
    pub delivery: crate::managed::DeliveryConfig,
    /// Exact packing, source, channel, receiver and recovery bounds.
    pub protocol: protocol::Config,
    /// Common scheduling shared by all native user packets.
    pub pipeline: PipelineConfig,
}
impl Config {
    /// Derive exact packed geometry from an explicitly Cauchy UDP policy.
    pub fn for_udp(
        runtime: RuntimeConfig,
        transport: udp::Config,
        channels: u16,
        options: Options,
        delivery: crate::managed::DeliveryConfig,
    ) -> io::Result<Self> {
        udp::base_session_config(runtime, transport)?;
        Self::from_policy(runtime, transport.policy()?, channels, options, delivery)
    }
    /// Derive exact packed geometry from an explicitly Cauchy genuine QUIC policy.
    pub fn for_quic(
        runtime: RuntimeConfig,
        transport: quic::Config,
        channels: u16,
        options: Options,
        delivery: crate::managed::DeliveryConfig,
    ) -> io::Result<Self> {
        quic::base_session_config(runtime, transport)?;
        Self::from_policy(runtime, transport.policy()?, channels, options, delivery)
    }
    fn from_policy(
        runtime: RuntimeConfig,
        policy: DatagramPolicy,
        channels: u16,
        options: Options,
        delivery: crate::managed::DeliveryConfig,
    ) -> io::Result<Self> {
        if !(1..=1000).contains(&options.hold_micros)
            || options.max_units == 0
            || !(1..=255).contains(&options.work_limit)
            || !(1..=255).contains(&channels)
        {
            return Err(invalid("packed policy limits"));
        }
        let units = usize::from(options.max_units);
        let mut base =
            aligned::Config::derive(runtime, policy, channels, 56 + 8 * units, delivery)?;
        let limits = &mut base.protocol.receiver;
        let maximum_record = limits
            .max_fragments_per_record
            .checked_mul(limits.body.symbol_bytes - 8)
            .ok_or_else(|| invalid("packed record geometry"))?
            .min(65535)
            .max(limits.body.symbol_bytes - 3);
        limits.lookahead_records = limits.lookahead_records.max(units);
        limits.lookahead_bytes = limits.lookahead_bytes.max(
            units
                .checked_mul(maximum_record)
                .ok_or_else(|| invalid("packed batch bytes"))?,
        );
        limits.lookahead_fragments = limits.lookahead_fragments.max(
            units
                .checked_mul(limits.max_fragments_per_record)
                .ok_or_else(|| invalid("packed batch fragments"))?,
        );
        limits.source_window = limits.source_window.max(units);
        let value = Self {
            delivery,
            protocol: protocol::Config {
                base: base.protocol,
                hold_micros: options.hold_micros,
                max_units: options.max_units,
                work_limit: options.work_limit,
            },
            pipeline: base.pipeline,
        };
        value.validate(runtime, policy)?;
        Ok(value)
    }
    pub(crate) fn base(self) -> aligned::Config {
        aligned::Config {
            delivery: self.delivery,
            protocol: self.protocol.base,
            pipeline: self.pipeline,
        }
    }
    pub(crate) fn validate(self, runtime: RuntimeConfig, policy: DatagramPolicy) -> io::Result<()> {
        self.protocol.validate().map_err(io::Error::other)?;
        self.base().validate_runtime(runtime, policy)
    }
}
fn bind(base: SessionConfig, config: Config) -> io::Result<SessionConfig> {
    aligned::bind_delivery(
        aligned::bind_policy(
            base,
            config.protocol.digest().map_err(io::Error::other)?,
            config.pipeline,
            b"l2tunnel/packed-runtime/v2/common-mux-crc32/native-identity-credit-v2\0",
        ),
        config.delivery,
    )
}

/// Canonical packed policy before applying the selected physical UDP lane.
pub fn udp_base_session_config(
    runtime: RuntimeConfig,
    transport: udp::Config,
    config: Config,
) -> io::Result<SessionConfig> {
    config.validate(runtime, transport.policy()?)?;
    bind(udp::base_session_config(runtime, transport)?, config)
}
/// Exact retained TLS member-authentication binding for this packed UDP lane.
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
/// Construct the actual fixed-endpoint carrier with packed authentication binding.
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
/// Canonical packed native binding passed to the genuine QUIC endpoint.
pub fn quic_base_session_config(
    runtime: RuntimeConfig,
    transport: quic::Config,
    config: Config,
) -> io::Result<SessionConfig> {
    config.validate(runtime, transport.policy()?)?;
    bind(quic::base_session_config(runtime, transport)?, config)
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
/// Actual retained full or paired-half UDP carriers bound to packed native policy.
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
/// Actual retained full or paired-half genuine QUIC connections with packed binding.
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
/// Run fixed packed native forwarding on actual protected UDP, retaining TLS control.
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
    aligned::run_parts(
        device,
        parts,
        initiator,
        runtime,
        transport.policy()?,
        aligned::Selection::Packed(config),
    )
    .await
}
/// Run fixed packed native forwarding on actual standalone QUIC; no TCP socket is added.
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
    aligned::run_parts(
        device,
        parts,
        initiator,
        runtime,
        transport.policy()?,
        aligned::Selection::Packed(config),
    )
    .await
}

#[cfg(test)]
#[path = "packed_tests.rs"]
mod tests;
