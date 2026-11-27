//! Strict explicit maintained policy input; validation creates no I/O capability.
use crate::secure_udp::maintained::{Settings, Transport};
use l2tunnel_runtime::{retained_tls, secure_udp::maintained::Geometry};
use serde::Deserialize;
use std::{io, net::SocketAddr, time::Duration};
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Policy {
    version: u8,
    first: Path,
    second: Option<Path>,
    geometry: Bounds,
    transport: Outer,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Path {
    client: SocketAddr,
    server: SocketAddr,
}
impl Path {
    fn build(self) -> l2tunnel_udp_control::Path {
        l2tunnel_udp_control::Path {
            client: self.client,
            server: self.server,
        }
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Bounds {
    path_mtu: usize,
    max_record_bytes: usize,
    max_bootstrap_bytes: usize,
    charged_overhead_bytes: usize,
    bootstrap_overhead_bytes: usize,
    framing_bytes: usize,
}
#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum Outer {
    Tls {
        record_timeout_micros: u64,
    },
    Quic {
        application_id: [u8; 16],
        queued_datagrams: usize,
        control_window_bytes: usize,
        idle_timeout_micros: u64,
        io_timeout_micros: u64,
    },
}
pub(crate) fn read(bytes: &[u8], connection: crate::ConnectionConfig) -> io::Result<Settings> {
    if bytes.is_empty() || bytes.len() > 16 * 1024 {
        return Err(invalid("maintained policy exceeds input bound"));
    }
    let policy: Policy =
        serde_json::from_slice(bytes).map_err(|_| invalid("invalid strict maintained policy"))?;
    if policy.version != 1 {
        return Err(invalid("unsupported maintained policy version"));
    }
    let geometry = Geometry {
        path_mtu: policy.geometry.path_mtu,
        max_record_bytes: policy.geometry.max_record_bytes,
        max_bootstrap_bytes: policy.geometry.max_bootstrap_bytes,
        charged_overhead_bytes: policy.geometry.charged_overhead_bytes,
        bootstrap_overhead_bytes: policy.geometry.bootstrap_overhead_bytes,
        framing_bytes: policy.geometry.framing_bytes,
    };
    let first = policy.first.build();
    let second = policy.second.map(Path::build);
    let transport = match policy.transport {
        Outer::Tls {
            record_timeout_micros,
        } => Transport::Tls(retained_tls::Limits {
            max_record_bytes: geometry.max_record_bytes,
            record_timeout: Duration::from_micros(record_timeout_micros),
        }),
        Outer::Quic {
            application_id,
            queued_datagrams,
            control_window_bytes,
            idle_timeout_micros,
            io_timeout_micros,
        } => {
            let ip = if first.client.is_ipv6() { 48 } else { 28 };
            let udp_payload_ceiling = u16::try_from(
                geometry
                    .path_mtu
                    .checked_sub(ip)
                    .ok_or_else(|| invalid("QUIC path MTU below IP overhead"))?,
            )
            .map_err(io::Error::other)?;
            let profile = l2tunnel_quic::Profile {
                application_id,
                traffic: if second.is_some() {
                    l2tunnel_quic::Traffic::HalfDuplex {
                        sender: l2tunnel_auth::Direction::ClientToServer,
                    }
                } else {
                    l2tunnel_quic::Traffic::FullDuplex
                },
                lane: 0,
                datagram_format: l2tunnel_quic::DatagramFormat::CommonCompact,
                max_datagram_bytes: geometry.max_record_bytes,
                queued_datagrams,
                control_window_bytes,
                udp_payload_ceiling,
                idle_timeout: Duration::from_micros(idle_timeout_micros),
                io_timeout: Duration::from_micros(io_timeout_micros),
            };
            let reverse = second.map(|_| l2tunnel_quic::Profile {
                lane: 1,
                traffic: l2tunnel_quic::Traffic::HalfDuplex {
                    sender: l2tunnel_auth::Direction::ServerToClient,
                },
                ..profile
            });
            Transport::Quic([Some(profile), reverse])
        }
    };
    let selected = Settings {
        first,
        second,
        transport,
        geometry,
    };
    selected.request(connection)?;
    Ok(selected)
}
fn invalid(value: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, value)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn connection() -> crate::ConnectionConfig {
        crate::ConnectionConfig {
            layer: l2tunnel_device::PacketLayer::Ip,
            duplex: l2tunnel_core::Duplex::Full,
            max_packet: 512,
            compression: crate::Compression::None,
            handshake_timeout: Duration::from_secs(3),
        }
    }
    fn policy() -> serde_json::Value {
        serde_json::json!({"version":1,"first":{"client":"127.0.0.1:43101","server":"127.0.0.1:43102"},"second":null,"geometry":{"path_mtu":1500,"max_record_bytes":1430,"max_bootstrap_bytes":1430,"charged_overhead_bytes":70,"bootstrap_overhead_bytes":70,"framing_bytes":5},"transport":{"kind":"tls","record_timeout_micros":1000000}})
    }
    #[test]
    fn maintained_policy_accepts_exact_tls_and_quic_and_rejects_ambiguous_geometry()
    -> io::Result<()> {
        let tls = policy();
        let selected = read(&serde_json::to_vec(&tls)?, connection())?;
        assert!(matches!(selected.transport, Transport::Tls(_)));
        let mut ipv6 = selected;
        ipv6.first.client = "[::1]:43101".parse().map_err(io::Error::other)?;
        ipv6.first.server = "[::1]:43102".parse().map_err(io::Error::other)?;
        ipv6.request(connection())?;
        for (flow, scope) in [(1, 0), (0, 1)] {
            let mut unsupported = ipv6;
            unsupported.first.client = std::net::SocketAddr::V6(std::net::SocketAddrV6::new(
                std::net::Ipv6Addr::LOCALHOST,
                43101,
                flow,
                scope,
            ));
            assert!(unsupported.request(connection()).is_err());
        }
        let mut quic = tls.clone();
        quic["transport"] = serde_json::json!({"kind":"quic","application_id":[1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16],"queued_datagrams":8,"control_window_bytes":16384,"idle_timeout_micros":30000000,"io_timeout_micros":1000000});
        quic["geometry"] = serde_json::json!({"path_mtu":1500,"max_record_bytes":1344,"max_bootstrap_bytes":1296,"charged_overhead_bytes":156,"bootstrap_overhead_bytes":204,"framing_bytes":0});
        let actual = read(&serde_json::to_vec(&quic)?, connection())?;
        assert!(matches!(actual.transport, Transport::Quic(_)));
        for mut bad in [tls.clone(), quic.clone()] {
            bad["first"]["client"] = serde_json::json!("0.0.0.0:43101");
            assert!(read(&serde_json::to_vec(&bad)?, connection()).is_err());
        }
        let mut bad = quic.clone();
        bad["geometry"]["charged_overhead_bytes"] = serde_json::json!(28);
        assert!(read(&serde_json::to_vec(&bad)?, connection()).is_err());
        let mut bad = tls.clone();
        bad["transport"]["unknown"] = serde_json::json!(true);
        assert!(read(&serde_json::to_vec(&bad)?, connection()).is_err());
        let mut half = connection();
        half.duplex = l2tunnel_core::Duplex::Half;
        assert!(read(&serde_json::to_vec(&quic)?, half).is_err());
        quic["second"] = serde_json::json!({"client":"127.0.0.1:43103","server":"127.0.0.1:43104"});
        assert!(read(&serde_json::to_vec(&quic)?, half).is_ok());
        Ok(())
    }
}
