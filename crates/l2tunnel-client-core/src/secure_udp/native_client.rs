//! File provisioning for native clients of the shared original-UDP service.
//! All paths are fixed children of the operator-selected profile directory.
use super::{
    common_cli::Plan, common_runtime_cli, credentials, datagram_profile::Common, live_tuning,
};
use crate::{Compression, ConnectionConfig, service};
use l2tunnel_core::Duplex;
use l2tunnel_device::PacketLayer;
use l2tunnel_handshake as hs;
use l2tunnel_security::Role;
use serde::Deserialize;
use std::{collections::BTreeMap, io, net::SocketAddr, path::Path, time::Duration};

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
    /// Optional explicit layer check (`"tun"` only on standard Android/Wintun L3).
    #[serde(default)]
    layer: Option<String>,
    /// Optional live FEC repair choices proposed at connect (e.g. `"off,1/8,1/4"`).
    #[serde(default)]
    tune_repair: Option<String>,
    /// Optional live device MTU choices proposed at connect (e.g. `"1280,1400,1500"`).
    #[serde(default)]
    tune_device_mtu: Option<String>,
    /// Optional live path MTU choices proposed at connect.
    #[serde(default)]
    tune_path_mtu: Option<String>,
}

/// One validated local profile. Credentials are read with the platform file
/// policy while preparing each new service plan. Reconnects use that same plan.
pub struct UdpClientProfile {
    common: Common,
    connection: ConnectionConfig,
    plan: Plan,
    tuning: live_tuning::Policy,
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
        if let Some(layer) = manifest.layer.as_deref()
            && !layer.eq_ignore_ascii_case("tun")
        {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "native L3 client only supports layer tun (TAP/VXLAN L2 is unsupported)",
            ));
        }
        // `udp_bind` may be unspecified (`0.0.0.0:0` / `[::]:0`) for dynamic mobile
        // interfaces (e.g., Android Wi-Fi/5G); `udp_peer` must always be a concrete endpoint.
        if manifest.udp_bind.is_ipv4() != manifest.udp_peer.is_ipv4()
            || manifest.udp_bind == manifest.udp_peer
            || manifest.udp_bind.ip().is_multicast()
            || manifest.udp_peer.port() == 0
            || manifest.udp_peer.ip().is_unspecified()
            || manifest.udp_peer.ip().is_multicast()
            || manifest.path_mtu < 1280
            || !(1280..=65519).contains(&manifest.tun_mtu)
            || !(1..=120).contains(&manifest.handshake_seconds)
        {
            return Err(invalid(
                "invalid native endpoints, MTU or handshake deadline",
            ));
        }
        let mut tune_opts = BTreeMap::new();
        if let Some(repair) = manifest.tune_repair {
            tune_opts.insert("--tune-repair".to_owned(), repair);
        }
        if let Some(mtu) = manifest.tune_device_mtu {
            tune_opts.insert("--tune-device-mtu".to_owned(), mtu);
        }
        if let Some(mtu) = manifest.tune_path_mtu {
            tune_opts.insert("--tune-path-mtu".to_owned(), mtu);
        }
        let tuning = live_tuning::policy("connect", &tune_opts)?;
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
            tuning,
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
            .build(self.connection, raw, peers, capacity, overhead)?
            .with_tuning(self.tuning);
        service::Prepared::secure_udp_common_client(profile, self.credentials, attachment)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifest_accepts_ephemeral_mobile_bind_and_rejects_non_tun_layer() {
        let valid: Result<Manifest, _> = serde_json::from_str(
            r#"{
                "version": 1,
                "carrier": "udp",
                "cover": "quic-like",
                "udp_bind": "0.0.0.0:0",
                "udp_peer": "198.51.100.10:24461",
                "path_mtu": 1400,
                "tun_mtu": 1340,
                "noise_profile": "ik",
                "handshake_seconds": 10,
                "layer": "tun",
                "tune_repair": "off,1/4",
                "tune_device_mtu": "1280,1340"
            }"#,
        );
        assert!(valid.is_ok(), "expected valid mobile manifest");

        let dir = std::env::temp_dir().join(format!("l2t-native-tap-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let _ = std::fs::write(
            dir.join("client.json"),
            r#"{
                "version": 1,
                "carrier": "udp",
                "cover": "quic-like",
                "udp_bind": "0.0.0.0:0",
                "udp_peer": "198.51.100.10:24461",
                "path_mtu": 1400,
                "tun_mtu": 1340,
                "noise_profile": "ik",
                "handshake_seconds": 10,
                "layer": "tap"
            }"#,
        );
        let err = UdpClientProfile::load(&dir).err();
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(
            err.map(|e| e.kind()),
            Some(io::ErrorKind::Unsupported),
            "TAP layer must be explicitly refused on native L3 client"
        );
    }
}
