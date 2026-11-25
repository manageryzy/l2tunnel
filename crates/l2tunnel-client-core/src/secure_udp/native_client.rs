//! File provisioning for native clients of the shared original-UDP service.
//! All paths are fixed children of the operator-selected profile directory.
use super::{common_cli::Plan, common_runtime_cli, credentials, datagram_profile::Common};
use crate::{Compression, ConnectionConfig, service};
use l2tunnel_core::Duplex;
use l2tunnel_device::PacketLayer;
use l2tunnel_handshake as hs;
use l2tunnel_security::Role;
use serde::Deserialize;
use std::{io, net::SocketAddr, path::Path, time::Duration};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    version: u16,
    carrier: String,
    cover: String,
    udp_bind: SocketAddr,
    udp_peer: SocketAddr,
    path_mtu: u16,
    tun_mtu: u16,
    noise_profile: String,
    handshake_seconds: u16,
}

/// One validated local profile. Credentials are read with the platform file
/// policy while preparing each new service plan. Reconnects use that same plan.
pub struct UdpClientProfile {
    common: Common,
    connection: ConnectionConfig,
    plan: Plan,
    credentials: credentials::Client,
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

impl UdpClientProfile {
    /// Read a bounded version-one manifest, exact peer catalog and provisioned
    /// identity. The loader performs no socket, route or device operations.
    pub fn load(directory: &Path) -> io::Result<Self> {
        let manifest: Manifest = serde_json::from_slice(&common_runtime_cli::read_document(
            &directory.join("client.json"),
        )?)
        .map_err(|_| invalid("invalid native client manifest"))?;
        if manifest.version != 1 || manifest.carrier != "udp" {
            return Err(invalid("native client requires version 1 and carrier udp"));
        }
        if manifest.udp_bind.is_ipv4() != manifest.udp_peer.is_ipv4()
            || manifest.udp_bind == manifest.udp_peer
            || [manifest.udp_bind, manifest.udp_peer].iter().any(|addr| {
                addr.port() == 0 || addr.ip().is_unspecified() || addr.ip().is_multicast()
            })
            || manifest.path_mtu < 1280
            || !(1280..=65519).contains(&manifest.tun_mtu)
            || !(1..=120).contains(&manifest.handshake_seconds)
        {
            return Err(invalid(
                "invalid native endpoints, MTU or handshake deadline",
            ));
        }
        let appearance = match manifest.cover.as_str() {
            "quic-like" => l2tunnel_cover::Appearance::QuicLike,
            "media-like" => l2tunnel_cover::Appearance::MediaLike,
            "tls-like" => l2tunnel_cover::Appearance::TlsLike,
            _ => return Err(invalid("unsupported UDP cover")),
        };
        let pattern = match manifest.noise_profile.as_str() {
            "ik" => hs::Profile::Ik,
            "ikpsk2" => hs::Profile::IkPsk2,
            _ => return Err(invalid("unsupported Noise profile")),
        };
        let plan = Plan::read(&directory.join("common.json"))?;
        plan.validate_carrier(false)?;
        if plan.initial().path_mtu() > usize::from(manifest.path_mtu) {
            return Err(invalid("Common descriptor exceeds configured path MTU"));
        }
        let psk = if matches!(pattern, hs::Profile::IkPsk2) {
            Some(credentials::read_secret(&directory.join("noise-psk.key"))?)
        } else {
            None
        };
        let noise = credentials::NoiseIdentity::new(
            credentials::read_secret(&directory.join("noise-private.key"))?,
            hs::PeerKey(credentials::read_public(&directory.join("noise-peer.pub"))?),
            pattern,
            psk,
        )?;
        let member = credentials::read_member(&directory.join("member.pk8"))?;
        let admission = credentials::Secret32::new(credentials::read_secret(
            &directory.join("admission.key"),
        )?)?;
        Ok(Self {
            common: Common {
                appearance,
                role: Role::Initiator,
                local: manifest.udp_bind,
                peer: manifest.udp_peer,
                maximum_mtu: usize::from(manifest.path_mtu),
                profile: pattern,
            },
            connection: ConnectionConfig {
                layer: PacketLayer::Ip,
                duplex: Duplex::Full,
                max_packet: usize::from(manifest.tun_mtu),
                compression: Compression::None,
                handshake_timeout: Duration::from_secs(u64::from(manifest.handshake_seconds)),
            },
            plan,
            credentials: credentials::Client::new(noise, member, admission)?,
        })
    }

    /// Exact requested local device MTU.
    pub fn tun_mtu(&self) -> usize {
        self.connection.max_packet
    }

    /// Original peer tuple to protect from capture by the native interface.
    pub fn peer(&self) -> SocketAddr {
        self.common.peer
    }

    /// Transfer the profile's credentials to the sole service plan owner. The
    /// resulting plan can be cloned for reconnect without reopening key files.
    pub fn prepare(self, attachment: service::Attachment) -> io::Result<service::Prepared> {
        let peers = self.credentials.noise().peers(Role::Initiator);
        let raw = self.common.raw(
            self.plan.initial().path_mtu(),
            self.connection.handshake_timeout,
            peers,
            self.credentials.member_key(),
        )?;
        let (overhead, capacity) = self.common.plan_geometry(&self.plan)?;
        let profile = self
            .plan
            .build(self.connection, raw, peers, capacity, overhead)?;
        service::Prepared::secure_udp_common_client(profile, self.credentials, attachment)
    }
}
