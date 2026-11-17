//! Canonical native configuration shared by current carrier and client profiles.
//! These helpers bind policy; they do not construct a data emitter.

use crate::{Compression, Duplex, RuntimeConfig, invalid};
use l2tunnel_auth::SessionConfig;
use l2tunnel_core::{ConfigDigest, ModeConfig, PayloadCompression};
use l2tunnel_device::PacketLayer;
use l2tunnel_flow_control::delivery_window;
use l2tunnel_management::transaction;
use std::io;

/// Construct the canonical native base mode used by current carrier profiles.
pub fn mode_config(runtime: RuntimeConfig, duplex: Duplex) -> io::Result<ModeConfig> {
    runtime.validate()?;
    Ok(ModeConfig {
        duplex,
        channels: 1,
        queue_frames: runtime.queue_packets,
        queue_bytes: runtime
            .max_packet
            .checked_mul(runtime.queue_packets)
            .ok_or_else(|| invalid("queue byte limit overflow"))?
            .max(65_535),
        compression: to_mode(runtime.compression),
        ..ModeConfig::default()
    })
}
/// Bind native bounds and the canonical base mode before carrier authentication.
/// Current profiles add their own domain-separated carrier and record policy bindings.
pub fn session_config(runtime: RuntimeConfig, mode: &ModeConfig) -> io::Result<SessionConfig> {
    if *mode != mode_config(runtime, mode.duplex)? {
        return Err(invalid("unsupported initial base mode or queue budget"));
    }
    let canonical = transaction::encode_mode(mode).map_err(io::Error::other)?;
    let mut hash = ring::digest::Context::new(&ring::digest::SHA256);
    hash.update(b"l2tunnel/managed-runtime/session/v1\0");
    hash.update(&[
        1,
        1,
        match runtime.layer {
            PacketLayer::Ethernet => 1,
            PacketLayer::Ip => 2,
        },
    ]);
    hash.update(
        &u64::try_from(runtime.max_packet)
            .map_err(io::Error::other)?
            .to_be_bytes(),
    );
    hash.update(&canonical);
    let digest = ConfigDigest(
        hash.finish()
            .as_ref()
            .try_into()
            .map_err(|_| invalid("digest size"))?,
    );
    Ok(SessionConfig {
        layer: runtime.layer,
        digest,
    })
}
fn to_mode(compression: Compression) -> PayloadCompression {
    match compression {
        Compression::None => PayloadCompression::Off,
        Compression::Lz4IfSmaller => PayloadCompression::Lz4,
    }
}

/// Canonical original-native-byte policies, identical on both authenticated peers.
/// Forward means originator to acceptor; reverse means acceptor to originator.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeliveryConfig {
    /// Originator-to-acceptor delivery policy.
    pub forward: delivery_window::Config,
    /// Acceptor-to-originator delivery policy.
    pub reverse: delivery_window::Config,
}
impl DeliveryConfig {
    pub(crate) fn validate(self, runtime: RuntimeConfig) -> io::Result<()> {
        for config in [self.forward, self.reverse] {
            config.validate().map_err(io::Error::other)?;
            if config.max_packet_bytes != runtime.max_packet as u64 {
                return Err(invalid("delivery maximum packet differs from native bound"));
            }
        }
        Ok(())
    }
    pub(crate) fn canonical(self) -> io::Result<Vec<u8>> {
        let mut bytes = Vec::with_capacity(192);
        for config in [self.forward, self.reverse] {
            for value in [
                config.target_bandwidth_bps,
                config.bootstrap_rtt_micros,
                config.min_rtt_micros,
                config.max_rtt_micros,
                u64::from(config.headroom_percent),
                config.minimum_bytes,
                config.max_inflight_bytes,
                u64::try_from(config.max_records).map_err(io::Error::other)?,
                config.max_packet_bytes,
                u64::try_from(config.metadata_limit_bytes).map_err(io::Error::other)?,
                config.sample_ttl_micros,
                config.flush_timeout_micros,
            ] {
                bytes.extend_from_slice(&value.to_be_bytes());
            }
        }
        Ok(bytes)
    }
}
/// Validate directional delivery limits while retaining the original local mode queues.
pub fn mode_config_with_delivery(
    runtime: RuntimeConfig,
    duplex: Duplex,
    delivery: DeliveryConfig,
) -> io::Result<ModeConfig> {
    delivery.validate(runtime)?;
    mode_config(runtime, duplex)
}
/// Authenticate both directional byte policies separately from local queue budgets.
/// The directional policy extends the base configuration digest.
pub fn session_config_with_delivery(
    runtime: RuntimeConfig,
    mode: &ModeConfig,
    delivery: DeliveryConfig,
) -> io::Result<SessionConfig> {
    delivery.validate(runtime)?;
    let base = session_config(runtime, mode)?;
    let mut hash = ring::digest::Context::new(&ring::digest::SHA256);
    hash.update(b"l2tunnel/managed-runtime/delivery-window/v1\0");
    hash.update(&base.digest.0);
    hash.update(&delivery.canonical()?);
    Ok(SessionConfig {
        layer: base.layer,
        digest: ConfigDigest(
            hash.finish()
                .as_ref()
                .try_into()
                .map_err(|_| invalid("delivery digest size"))?,
        ),
    })
}
