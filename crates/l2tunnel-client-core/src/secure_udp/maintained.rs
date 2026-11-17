//! Explicit maintained transport selection for the complete Common record catalog.
use crate::ConnectionConfig;
use l2tunnel_core::Duplex;
use l2tunnel_runtime::{retained_tls, secure_udp::maintained as runtime};
use l2tunnel_udp_control::Path;
use std::io;

/// Complete maintained outer policy; mandatory transport AEAD remains additional.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Transport {
    /// Genuine original TCP/TLS streams with bounded record framing.
    Tls(retained_tls::Limits),
    /// Genuine selected Quinn profiles in global First/Second lane order.
    Quic([Option<l2tunnel_quic::Profile>; 2]),
}
/// Explicit original tuples, bounds and transport policy. No socket is opened.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Settings {
    /// Original first lane in global client/server order.
    pub first: Path,
    /// Required for Half; no duplicate physical tuple is accepted.
    pub second: Option<Path>,
    /// Actual maintained transport policy, independently of the inner data suite.
    pub transport: Transport,
    /// Explicit record capacities and conservative admission allowances.
    pub geometry: runtime::Geometry,
}
impl Settings {
    /// Validate all configured fields and derive the complete request before I/O.
    pub fn request(self, connection: ConnectionConfig) -> io::Result<runtime::Request> {
        connection.session()?;
        let paths = [Some(self.first), self.second];
        if (connection.duplex == Duplex::Half) != self.second.is_some() {
            return Err(invalid(
                "maintained topology differs from requested Full/Half",
            ));
        }
        for path in paths.into_iter().flatten() {
            if [path.client, path.server].into_iter().any(|endpoint| {
                matches!(endpoint,
                std::net::SocketAddr::V6(value) if value.scope_id() != 0 || value.flowinfo() != 0)
            }) {
                return Err(invalid(
                    "maintained IPv6 scope and flow identifiers are not yet supported",
                ));
            }
            crate::udp::Endpoints {
                local: path.client,
                peer: path.server,
            }
            .validate()?;
            if path.client.is_ipv4() != self.first.client.is_ipv4() {
                return Err(invalid("maintained lanes must share an address family"));
            }
        }
        if self.second.is_some_and(|path| {
            path.client == self.first.client || path.server == self.first.server
        }) {
            return Err(invalid(
                "maintained Half requires distinct local and peer ports",
            ));
        }
        let (kind, policy) = match self.transport {
            Transport::Tls(limits) => {
                if limits.max_record_bytes != self.geometry.max_record_bytes
                    || self.geometry.framing_bytes != retained_tls::FRAMING_BYTES
                    || self.geometry.max_bootstrap_bytes > limits.max_record_bytes
                {
                    return Err(invalid(
                        "maintained TLS framing differs from complete policy",
                    ));
                }
                (
                    runtime::Kind::TlsStream,
                    retained_tls::policy_digest(connection.duplex, limits)?,
                )
            }
            Transport::Quic(profiles) => {
                let first = profiles[0].ok_or_else(|| invalid("missing first QUIC profile"))?;
                if profiles[1].is_some() != self.second.is_some() {
                    return Err(invalid("QUIC profile/lane count differs"));
                }
                for (index, profile) in profiles
                    .into_iter()
                    .enumerate()
                    .filter_map(|(i, p)| p.map(|p| (i, p)))
                {
                    profile.validate().map_err(io::Error::other)?;
                    let traffic = match (connection.duplex, index) {
                        (Duplex::Full, 0) => l2tunnel_quic::Traffic::FullDuplex,
                        (Duplex::Half, 0) => l2tunnel_quic::Traffic::HalfDuplex {
                            sender: l2tunnel_auth::Direction::ClientToServer,
                        },
                        (Duplex::Half, 1) => l2tunnel_quic::Traffic::HalfDuplex {
                            sender: l2tunnel_auth::Direction::ServerToClient,
                        },
                        _ => return Err(invalid("unexpected QUIC lane")),
                    };
                    let physical = if self.first.client.is_ipv6() { 48 } else { 28 };
                    let geometry = runtime::Geometry {
                        path_mtu: usize::from(profile.udp_payload_ceiling) + physical,
                        max_record_bytes: profile.max_datagram_bytes,
                        max_bootstrap_bytes: profile.maximum_bootstrap_bytes(),
                        charged_overhead_bytes: physical + 128,
                        bootstrap_overhead_bytes: physical + 128 + 48,
                        framing_bytes: 0,
                    };
                    if profile.datagram_format != l2tunnel_quic::DatagramFormat::CommonCompact
                        || profile.traffic != traffic
                        || profile.lane != index as u32
                        || geometry != self.geometry
                    {
                        return Err(invalid("selected QUIC profile/geometry differs"));
                    }
                }
                let values = [first, profiles[1].unwrap_or(first)];
                let count = if self.second.is_some() { 2 } else { 1 };
                (
                    runtime::Kind::QuicDatagram,
                    l2tunnel_quic::common::policy_digest(&values[..count])
                        .map_err(io::Error::other)?,
                )
            }
        };
        let request = runtime::Request {
            kind,
            duplex: connection.duplex,
            geometry: self.geometry,
            policy,
        };
        request.validate()?;
        Ok(request)
    }
}
fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

/// Maintained client trust, independent of the inner Noise identity.
pub enum Client {
    /// Existing own-server TLS verification and independently configured SNI.
    Tls(crate::service::Client),
    /// Genuine QUIC verifies this name against these own trust roots; independent SNI is unsupported.
    Quic {
        /// Bounded DER trust anchors consumed by maintained Quinn configuration.
        roots: Vec<Vec<u8>>,
        /// Own-server certificate verification identity.
        server_name: String,
        /// Same authenticated member identity required by the inner Common profile.
        member: std::sync::Arc<l2tunnel_auth::MemberKey>,
    },
}
/// Maintained server credentials; no TLS keys are serialized in observations.
pub enum Server {
    /// Existing original TLS listener policy and member allowlist.
    Tls(crate::service::Server),
    /// Genuine Quinn certificate chain, private key and fixed member allowlist.
    Quic {
        /// Maintained DER certificate chain.
        certs: Vec<Vec<u8>>,
        /// DER PKCS8 private key.
        key: zeroize::Zeroizing<Vec<u8>>,
        /// Existing authenticated outer-member allowlist.
        members: l2tunnel_auth::MemberAllowlist,
    },
}
impl Client {
    pub(crate) fn member(&self) -> l2tunnel_auth::MemberPublicKey {
        match self {
            Self::Tls(value) => value.member.public_key(),
            Self::Quic { member, .. } => member.public_key(),
        }
    }
}
impl Server {
    pub(crate) fn members(&self) -> &l2tunnel_auth::MemberAllowlist {
        match self {
            Self::Tls(value) => &value.members,
            Self::Quic { members, .. } => members,
        }
    }
}
