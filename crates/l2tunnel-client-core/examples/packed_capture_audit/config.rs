use super::Result;
use l2tunnel_client_core::{ConnectionConfig, packed, quic, udp};
use l2tunnel_core::Duplex;
use l2tunnel_device::PacketLayer;
use l2tunnel_runtime::{Compression, packed::Options};
use serde::{Deserialize, Deserializer, Serialize};
use std::{net::SocketAddr, time::Duration};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "lowercase")]
pub(super) enum Layer {
    Tap,
    Tun,
}
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "lowercase")]
pub(super) enum DuplexChoice {
    Half,
    Full,
}
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "lowercase")]
pub(super) enum Carrier {
    Udp,
    Quic,
}
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub(super) enum Cover {
    QuicLike,
    OpenvpnLike,
}
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "lowercase")]
pub(super) enum Protection {
    Integrity,
    Aead,
}

fn nullable<'de, D: Deserializer<'de>, T: Deserialize<'de>>(
    value: D,
) -> std::result::Result<Option<T>, D::Error> {
    Option::deserialize(value)
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Configuration {
    version: u8,
    pub layer: Layer,
    pub duplex: DuplexChoice,
    carrier: Carrier,
    path_mtu: usize,
    max_packet: usize,
    channels: u16,
    delivery: l2tunnel_client_core::delivery::Policy,
    hold_micros: u64,
    max_units: u8,
    work_limit: usize,
    fec_sources: usize,
    fec_repairs: usize,
    fec_flush_ms: u64,
    #[serde(deserialize_with = "nullable")]
    cover: Option<Cover>,
    #[serde(deserialize_with = "nullable")]
    protection: Option<Protection>,
}

#[derive(Debug, Serialize)]
pub(super) struct Geometry {
    underlay_ip_version: u8,
    outer_overhead_bytes: usize,
    pub udp_payload_ceiling: usize,
    pub recovery_packet_ceiling: usize,
    recovery_source_bytes: usize,
    fec_source_bytes: usize,
    fec_packet_ceiling: usize,
    packed_header_bytes: usize,
    record_id_bytes: usize,
    symbol_bytes: usize,
    channels: u16,
    max_units: u8,
    max_fragments_per_record: usize,
    native_queue_packets: usize,
    native_queue_bytes: usize,
}
pub(super) struct Derived {
    pub geometry: Geometry,
    pub packed: l2tunnel_runtime::packed::Config,
}
impl Configuration {
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > super::CONFIG_LIMIT {
            return Err("configuration byte limit exceeded".into());
        }
        Ok(serde_json::from_slice(bytes)?)
    }
    pub fn cover(&self) -> Result<udp::CoverProfile> {
        match self.cover {
            Some(Cover::QuicLike) => Ok(udp::CoverProfile::QuicLike),
            Some(Cover::OpenvpnLike) => Ok(udp::CoverProfile::OpenVpnLike),
            None => Err("UDP requires a cover".into()),
        }
    }
    pub fn audit_profile(&self) -> Result<()> {
        if self.carrier != Carrier::Udp || self.protection != Some(Protection::Integrity) {
            return Err("structural audit requires visible custom UDP integrity; AEAD and genuine QUIC are unsupported".into());
        }
        Ok(())
    }
    pub fn derive(&self) -> Result<Derived> {
        if self.version != 2 || self.max_packet != 1600 {
            return Err("requires version 2 and max_packet 1600".into());
        }
        let duplex = match self.duplex {
            DuplexChoice::Half => Duplex::Half,
            DuplexChoice::Full => Duplex::Full,
        };
        let connection = ConnectionConfig {
            layer: match self.layer {
                Layer::Tap => PacketLayer::Ethernet,
                Layer::Tun => PacketLayer::Ip,
            },
            duplex,
            max_packet: self.max_packet,
            compression: Compression::None,
            handshake_timeout: Duration::from_secs(30),
        };
        let endpoints = |port| udp::Endpoints {
            local: SocketAddr::from(([127, 0, 0, 1], port)),
            peer: SocketAddr::from(([127, 0, 0, 2], port)),
        };
        let forward = endpoints(10001);
        let reverse = (duplex == Duplex::Half).then(|| endpoints(10002));
        let recovery = udp::RecoveryMode::Cauchy {
            sources: self.fec_sources,
            repairs: self.fec_repairs,
            flush_after: Duration::from_millis(self.fec_flush_ms),
        };
        let settings = packed::Settings {
            channels: self.channels,
            delivery: self.delivery.config(self.max_packet)?,
            packing: Options {
                hold_micros: self.hold_micros,
                max_units: self.max_units,
                work_limit: self.work_limit,
            },
        };
        let packed = match self.carrier {
            Carrier::Udp => {
                let protection = match self.protection {
                    Some(Protection::Integrity) => udp::Protection::HmacSha256,
                    Some(Protection::Aead) => udp::Protection::ChaCha20Poly1305,
                    None => return Err("UDP requires protection".into()),
                };
                packed::udp_config(
                    connection,
                    udp::Settings {
                        forward,
                        reverse,
                        cover: self.cover()?,
                        protection,
                        path_mtu: self.path_mtu,
                        recovery,
                    },
                    settings,
                )?
                .1
            }
            Carrier::Quic => {
                if self.cover.is_some() || self.protection.is_some() {
                    return Err("genuine QUIC requires null cover and protection".into());
                }
                packed::quic_config(
                    connection,
                    quic::Settings {
                        forward,
                        reverse,
                        application_id: [1; 16],
                        path_mtu: self.path_mtu,
                        recovery,
                    },
                    settings,
                )?
                .1
            }
        };
        let base = packed.protocol.base;
        let geometry = Geometry {
            underlay_ip_version: 4,
            outer_overhead_bytes: 28,
            udp_payload_ceiling: self.path_mtu - 28,
            recovery_packet_ceiling: base.max_recovery_packet_bytes,
            recovery_source_bytes: base.recovery.arq.max_source_bytes,
            fec_source_bytes: base.recovery.fec.block.max_source_bytes,
            fec_packet_ceiling: base.recovery.fec.block.max_packet_bytes,
            packed_header_bytes: l2tunnel_codec::packed_envelope::HEADER_BYTES,
            record_id_bytes: 8 * usize::from(self.max_units),
            symbol_bytes: base.receiver.body.symbol_bytes,
            channels: self.channels,
            max_units: self.max_units,
            max_fragments_per_record: base.receiver.max_fragments_per_record,
            native_queue_packets: connection.runtime().queue_packets,
            native_queue_bytes: packed.pipeline.queue.bytes,
        };
        Ok(Derived { geometry, packed })
    }
}
