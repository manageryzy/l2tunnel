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

/// Prepare a stored Local API v5 [`crate::local::ProfileDocument`] for a native
/// L3 TUN client (e.g. Windows Wintun) across all supported cross-platform
/// Common carriers: UDP covers (`quic-like`, `media-like`, `tls-like`),
/// `openvpn-like`, maintained `tcp` (TLS 1.3), and genuine `quic` (Quinn).
///
/// Explicitly refuses `--layer tap` and `--carrier raw-packet` with
/// [`io::ErrorKind::Unsupported`]. Supports Internal MTU > Capsule MTU
/// (`--max-packet > --max-path-mtu`) and live-tuning options (`--tune-repair`,
/// `--tune-device-mtu`, `--tune-path-mtu`). Opens no socket or TUN device.
#[cfg(any(unix, windows))]
pub fn prepare_profile_document<F>(
    document: &crate::local::ProfileDocument,
    make_attachment: F,
) -> io::Result<service::Prepared>
where
    F: FnOnce(u16, SocketAddr, Option<&str>) -> io::Result<service::Attachment>,
{
    use l2tunnel_auth::{ClientSni, ClientTls, MemberKey};
    use std::io::Read;

    document.validate().map_err(|msg| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("invalid profile document: {msg}"),
        )
    })?;
    if document.role != crate::local::ProfileRole::Connect {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "native L3 client daemon only runs connect profiles",
        ));
    }
    let opts = &document.options;
    let req = |key: &str| -> io::Result<&str> {
        opts.get(key)
            .map(String::as_str)
            .filter(|s| !s.is_empty())
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, format!("missing {key}")))
    };
    if let Some(record_profile) = opts.get("--record-profile")
        && record_profile != "common"
    {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "native client requires --record-profile common",
        ));
    }
    let layer = opts.get("--layer").map(String::as_str).unwrap_or("tun");
    if !layer.eq_ignore_ascii_case("tun") {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "native L3 client only supports --layer tun (TAP/VXLAN L2 is unsupported)",
        ));
    }
    let carrier = req("--carrier")?;
    if carrier == "raw-packet" {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "raw-packet carrier requires Linux raw sockets and is unsupported on Windows",
        ));
    }
    let duplex = match opts.get("--duplex").map(String::as_str).unwrap_or("full") {
        "full" => Duplex::Full,
        "half" => Duplex::Half,
        _ => return Err(invalid("invalid --duplex (expected full or half)")),
    };
    let compression = match opts
        .get("--compression")
        .map(String::as_str)
        .unwrap_or("off")
    {
        "off" => Compression::None,
        "lz4" => Compression::Lz4IfSmaller,
        _ => return Err(invalid("invalid --compression (expected off or lz4)")),
    };
    let tun_mtu: u16 = opts
        .get("--max-packet")
        .map(String::as_str)
        .unwrap_or("1500")
        .parse()
        .map_err(|_| invalid("invalid --max-packet"))?;
    let path_mtu: u16 = opts
        .get("--max-path-mtu")
        .map(String::as_str)
        .unwrap_or("1500")
        .parse()
        .map_err(|_| invalid("invalid --max-path-mtu"))?;
    let handshake_secs: u64 = opts
        .get("--handshake-seconds")
        .map(String::as_str)
        .unwrap_or("30")
        .parse()
        .map_err(|_| invalid("invalid --handshake-seconds"))?;
    if path_mtu < 1280 || !(1280..=65519).contains(&tun_mtu) || !(1..=120).contains(&handshake_secs)
    {
        return Err(invalid("invalid MTU or handshake deadline bounds"));
    }
    let connection = ConnectionConfig {
        layer: PacketLayer::Ip,
        duplex,
        max_packet: usize::from(tun_mtu),
        compression,
        handshake_timeout: Duration::from_secs(handshake_secs),
    };
    let tuning = live_tuning::policy("connect", opts)?;

    let pattern = match req("--noise-profile")? {
        "ik" => hs::Profile::Ik,
        "ikpsk2" => hs::Profile::IkPsk2,
        _ => {
            return Err(invalid(
                "unsupported --noise-profile (expected ik or ikpsk2)",
            ));
        }
    };
    let plan = Plan::read(Path::new(req("--common-transaction-plan")?))?;
    let psk = if matches!(pattern, hs::Profile::IkPsk2) {
        Some(credentials::read_secret(Path::new(req(
            "--noise-psk-file",
        )?))?)
    } else {
        None
    };
    let noise = credentials::NoiseIdentity::new(
        credentials::read_secret(Path::new(req("--noise-private-key-file")?))?,
        hs::PeerKey(credentials::read_public(Path::new(req(
            "--noise-peer-key-file",
        )?))?),
        pattern,
        psk,
    )?;
    let member_der = credentials::read_member_der(Path::new(req("--identity")?))?;
    let member_id =
        l2tunnel_identity::IdentityKey::from_pkcs8(&member_der).map_err(io::Error::other)?;
    let admission = credentials::Secret32::new(credentials::read_secret(Path::new(req(
        "--session-admission-key-file",
    )?))?)?;
    let peers = noise.peers(Role::Initiator);
    let member_pub = member_id.public_key();
    let inner_creds = credentials::Client::new(noise, member_id, admission)?;

    let read_ca_der = |path_str: &str| -> io::Result<Vec<u8>> {
        let file = std::fs::File::open(path_str)?;
        let mut buf = Vec::new();
        file.take(65_537).read_to_end(&mut buf)?;
        if buf.is_empty() || buf.len() > 65_536 {
            return Err(invalid(
                "CA certificate file exceeds 64 KiB bound or is empty",
            ));
        }
        Ok(buf)
    };
    let parse_sni = || -> io::Result<ClientSni> {
        match opts.get("--sni").map(String::as_str) {
            None | Some("none") => Ok(ClientSni::default()),
            Some(name) => ClientSni::named(name).map_err(|_| invalid("invalid --sni")),
        }
    };
    let address_override = opts
        .get("--tun-address")
        .or_else(|| opts.get("--address"))
        .map(String::as_str);

    match carrier {
        "quic-like" | "media-like" | "tls-like" => {
            plan.validate_carrier(false)?;
            if plan.initial().path_mtu() > usize::from(path_mtu) {
                return Err(invalid(
                    "Common descriptor exceeds configured --max-path-mtu",
                ));
            }
            let appearance = match carrier {
                "quic-like" => l2tunnel_cover::Appearance::QuicLike,
                "media-like" => l2tunnel_cover::Appearance::MediaLike,
                _ => l2tunnel_cover::Appearance::TlsLike,
            };
            let local: SocketAddr = opts
                .get("--udp-bind")
                .map(String::as_str)
                .unwrap_or("0.0.0.0:0")
                .parse()
                .map_err(|_| invalid("invalid --udp-bind"))?;
            let peer: SocketAddr = req("--udp-peer")?
                .parse()
                .map_err(|_| invalid("invalid --udp-peer"))?;
            let common = Common {
                appearance,
                role: Role::Initiator,
                local,
                peer,
                maximum_mtu: usize::from(path_mtu),
                profile: pattern,
            };
            let raw = common.raw(
                plan.initial().path_mtu(),
                connection.handshake_timeout,
                peers,
                member_pub,
            )?;
            let (overhead, capacity) = common.plan_geometry(&plan)?;
            let profile = plan
                .build(connection, raw, peers, capacity, overhead)?
                .with_tuning(tuning);
            let attachment = make_attachment(tun_mtu, peer, address_override)?;
            service::Prepared::secure_udp_common_client(profile, inner_creds, attachment)
        }
        "openvpn-like" => {
            plan.validate_carrier(true)?;
            if plan.initial().path_mtu() > usize::from(path_mtu) {
                return Err(invalid(
                    "Common descriptor exceeds configured --max-path-mtu",
                ));
            }
            let local: SocketAddr = opts
                .get("--udp-bind")
                .map(String::as_str)
                .unwrap_or("0.0.0.0:0")
                .parse()
                .map_err(|_| invalid("invalid --udp-bind"))?;
            let peer: SocketAddr = req("--udp-peer")?
                .parse()
                .map_err(|_| invalid("invalid --udp-peer"))?;
            let common = Common {
                appearance: l2tunnel_cover::Appearance::QuicLike,
                role: Role::Initiator,
                local,
                peer,
                maximum_mtu: usize::from(path_mtu),
                profile: pattern,
            };
            let mut raw = common.raw(
                plan.initial().path_mtu(),
                connection.handshake_timeout,
                peers,
                member_pub,
            )?;
            let outer_cap = plan.outer_capacity()?;
            let (overhead, _) = common.carrier_geometry(&mut raw, outer_cap)?;
            let capacity = plan.protected_body_capacity(outer_cap)?;
            let profile = plan
                .build(connection, raw, peers, capacity, overhead)?
                .with_tuning(tuning);
            let outer_cfg = plan.outer_config(&profile)?;
            let ca = read_ca_der(req("--ca")?)?;
            let tls = ClientTls::from_der_roots_with_sni(&[ca], parse_sni()?)
                .map_err(io::Error::other)?;
            let member =
                std::sync::Arc::new(MemberKey::from_pkcs8(&member_der).map_err(io::Error::other)?);
            let outer_creds = service::Client {
                remote: peer,
                tls,
                server_name: req("--server-name")?.to_owned(),
                member,
            };
            let attachment = make_attachment(tun_mtu, peer, address_override)?;
            service::Prepared::secure_udp_common_carrier_client(
                profile,
                outer_cfg,
                outer_creds,
                inner_creds,
                attachment,
            )
        }
        "tcp" | "quic" => {
            let policy_bytes =
                common_runtime_cli::read_document(Path::new(req("--maintained-policy")?))?;
            let settings = super::maintained_cli::read(&policy_bytes, connection)?;
            let want_quic = carrier == "quic";
            let is_quic = matches!(settings.transport, super::maintained::Transport::Quic(_));
            if want_quic != is_quic {
                return Err(invalid(
                    "--maintained-policy transport does not match --carrier",
                ));
            }
            let common = Common {
                appearance: l2tunnel_cover::Appearance::QuicLike,
                role: Role::Initiator,
                local: settings.first.client,
                peer: settings.first.server,
                maximum_mtu: usize::from(path_mtu),
                profile: pattern,
            };
            let mut raw = common.raw(
                plan.initial().path_mtu(),
                connection.handshake_timeout,
                peers,
                member_pub,
            )?;
            common.carrier_geometry(&mut raw, settings.geometry.max_bootstrap_bytes)?;
            common.bootstrap_arq_geometry(&mut raw)?;
            raw.cover.max_packet_bytes = settings.geometry.max_record_bytes;
            let maximum_body = plan.protected_body_capacity(settings.geometry.max_record_bytes)?;
            let profile = plan
                .build_maintained(connection, raw, peers, maximum_body, settings)?
                .with_tuning(tuning);
            let ca = read_ca_der(req("--ca")?)?;
            let server_name = req("--server-name")?.to_owned();
            let member =
                std::sync::Arc::new(MemberKey::from_pkcs8(&member_der).map_err(io::Error::other)?);
            let outer = match settings.transport {
                super::maintained::Transport::Tls(_) => {
                    let tls = ClientTls::from_der_roots_with_sni(&[ca], parse_sni()?)
                        .map_err(io::Error::other)?;
                    super::maintained::Client::Tls(service::Client {
                        remote: settings.first.server,
                        tls,
                        server_name,
                        member,
                    })
                }
                super::maintained::Transport::Quic(_) => super::maintained::Client::Quic {
                    roots: vec![ca],
                    server_name,
                    member,
                },
            };
            let attachment = make_attachment(tun_mtu, settings.first.server, address_override)?;
            service::Prepared::secure_udp_common_maintained_client(
                profile,
                outer,
                inner_creds,
                attachment,
            )
        }
        _ => Err(io::Error::new(
            io::ErrorKind::Unsupported,
            format!("unsupported native carrier {carrier:?}"),
        )),
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
