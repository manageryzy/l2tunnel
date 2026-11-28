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

/// Native device attachment details resolved from a [`crate::local::ProfileDocument`]
/// when opening a platform TUN (L3) or TAP (L2) adapter.
#[cfg(any(unix, windows))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeAttachmentRequest<'a> {
    /// Selected packet layer (`PacketLayer::Ip` for TUN or `PacketLayer::Ethernet` for TAP).
    pub layer: PacketLayer,
    /// Configured inner device MTU / max packet size.
    pub mtu: u16,
    /// Outer tunnel peer socket address (used for route-loop refusal).
    pub peer: SocketAddr,
    /// Optional explicit IPv4/prefix override (`--tun-address` or `--address`).
    pub address_override: Option<&'a str>,
    /// Optional explicit adapter alias (`--device`).
    pub device_name: Option<&'a str>,
    /// Optional explicit unicast Ethernet MAC address (`--tap-mac`, TAP only).
    pub tap_mac: Option<[u8; 6]>,
}

#[cfg(any(unix, windows))]
fn parse_tap_mac(text: &str) -> io::Result<[u8; 6]> {
    let trimmed = text.trim();
    let sep = if trimmed.contains(':') { ':' } else { '-' };
    let parts: Vec<&str> = trimmed.split(sep).collect();
    if parts.len() != 6 || parts.iter().any(|p| p.len() != 2) {
        return Err(invalid(
            "invalid --tap-mac (expected 6 hex octets like 02:aa:bb:cc:dd:ee)",
        ));
    }
    let mut mac = [0_u8; 6];
    for (dst, part) in mac.iter_mut().zip(parts) {
        *dst = u8::from_str_radix(part, 16).map_err(|_| invalid("invalid --tap-mac hex digit"))?;
    }
    if mac == [0; 6] || (mac[0] & 0x01) != 0 {
        return Err(invalid(
            "--tap-mac must be a non-zero unicast Ethernet MAC address",
        ));
    }
    Ok(mac)
}

#[cfg(any(unix, windows))]
#[derive(Clone, Copy)]
struct NativeVxlan {
    bind: SocketAddr,
    peer: SocketAddr,
    vni: l2tunnel_vxlan::Vni,
    max_frame_bytes: usize,
}

#[cfg(any(unix, windows))]
fn parse_native_vxlan(
    opts: &BTreeMap<String, String>,
    layer: PacketLayer,
    max_packet: u16,
) -> io::Result<Option<NativeVxlan>> {
    let count = ["--vxlan-bind", "--vxlan-peer", "--vni"]
        .iter()
        .filter(|k| opts.get(**k).is_some_and(|v| !v.trim().is_empty()))
        .count();
    if count == 0 {
        return Ok(None);
    }
    if count != 3 {
        return Err(invalid(
            "VXLAN L2 attachment requires all of --vxlan-bind, --vxlan-peer, and --vni",
        ));
    }
    if layer != PacketLayer::Ethernet {
        return Err(invalid("VXLAN L2 attachment requires --layer tap"));
    }
    if opts.get("--tap-mac").is_some_and(|v| !v.trim().is_empty()) {
        return Err(invalid(
            "--tap-mac cannot be combined with VXLAN L2 attachment",
        ));
    }
    let bind: SocketAddr = opts
        .get("--vxlan-bind")
        .ok_or_else(|| invalid("missing --vxlan-bind"))?
        .parse()
        .map_err(|_| invalid("invalid --vxlan-bind (expected IP:PORT)"))?;
    let peer: SocketAddr = opts
        .get("--vxlan-peer")
        .ok_or_else(|| invalid("missing --vxlan-peer"))?
        .parse()
        .map_err(|_| invalid("invalid --vxlan-peer (expected IP:PORT)"))?;
    if bind.is_ipv4() != peer.is_ipv4()
        || bind == peer
        || bind.ip().is_multicast()
        || peer.port() == 0
        || peer.ip().is_unspecified()
        || peer.ip().is_multicast()
    {
        return Err(invalid("invalid --vxlan-bind/--vxlan-peer endpoint pair"));
    }
    let raw_vni: u32 = opts
        .get("--vni")
        .ok_or_else(|| invalid("missing --vni"))?
        .parse()
        .map_err(|_| invalid("invalid --vni (expected integer 0..=16777215)"))?;
    let vni = l2tunnel_vxlan::Vni::new(raw_vni)
        .map_err(|_| invalid("--vni out of 24-bit VXLAN range (0..=16777215)"))?;
    Ok(Some(NativeVxlan {
        bind,
        peer,
        vni,
        max_frame_bytes: usize::from(max_packet),
    }))
}

/// Prepare a stored Local API v5 [`crate::local::ProfileDocument`] for a native
/// client (e.g. Windows Wintun L3, Windows TAP-Windows6 L2, or driverless
/// cross-platform VXLAN L2) across all supported cross-platform Common carriers:
/// UDP covers (`quic-like`, `media-like`, `tls-like`), `openvpn-like`,
/// maintained `tcp` (TLS 1.3), and genuine `quic` (Quinn).
///
/// Explicitly refuses `--carrier raw-packet` with [`io::ErrorKind::Unsupported`].
/// Supports `--layer tun` (L3), `--layer tap` (L2 TAP or VXLAN), optional
/// `--server-pin` TLS/QUIC leaf SHA-256 verification (`CONN-02`), Internal MTU >
/// Capsule MTU (`--max-packet > --max-path-mtu`), and live-tuning options
/// (`--tune-repair`, `--tune-device-mtu`, `--tune-path-mtu`). Opens no socket
/// or device.
#[cfg(any(unix, windows))]
pub fn prepare_profile_document<F>(
    document: &crate::local::ProfileDocument,
    make_attachment: F,
) -> io::Result<service::Prepared>
where
    F: FnOnce(NativeAttachmentRequest<'_>) -> io::Result<service::Attachment>,
{
    use l2tunnel_auth::{ClientSni, ClientTls, MemberKey, ServerIdentity};
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
            "native client daemon only runs connect profiles",
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
    let layer = match opts.get("--layer").map(String::as_str).unwrap_or("tun") {
        s if s.eq_ignore_ascii_case("tun") => PacketLayer::Ip,
        s if s.eq_ignore_ascii_case("tap") => PacketLayer::Ethernet,
        _ => {
            return Err(invalid("invalid --layer (expected tun or tap)"));
        }
    };
    let tap_mac = match opts
        .get("--tap-mac")
        .map(String::as_str)
        .filter(|s| !s.is_empty())
    {
        Some(text) => {
            if layer != PacketLayer::Ethernet {
                return Err(invalid("--tap-mac is only supported with --layer tap"));
            }
            Some(parse_tap_mac(text)?)
        }
        None => None,
    };
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
    let vxlan = parse_native_vxlan(opts, layer, tun_mtu)?;
    let connection = ConnectionConfig {
        layer,
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
    let parse_server_pin = || -> io::Result<Option<ServerIdentity>> {
        match opts
            .get("--server-pin")
            .map(String::as_str)
            .filter(|s| !s.is_empty())
        {
            None => Ok(None),
            Some(hex) => ServerIdentity::from_hex(hex)
                .map(Some)
                .map_err(|_| invalid("invalid --server-pin (expected 64 hex chars)")),
        }
    };
    let address_override = opts
        .get("--tun-address")
        .or_else(|| opts.get("--address"))
        .map(String::as_str)
        .filter(|s| !s.is_empty());
    let device_name = opts
        .get("--device")
        .map(String::as_str)
        .filter(|s| !s.is_empty());
    let build_attachment = |peer: SocketAddr| -> io::Result<service::Attachment> {
        if let Some(vxlan) = vxlan {
            let open_vxlan = move || -> io::Result<crate::native::Native> {
                let device = l2tunnel_platform_vxlan::VxlanDevice::bind(
                    vxlan.bind,
                    l2tunnel_platform_vxlan::VxlanConfig {
                        peer: vxlan.peer,
                        vni: vxlan.vni,
                        max_frame_bytes: vxlan.max_frame_bytes,
                        receive_budget: 64,
                    },
                )?;
                Ok(crate::native::Native::new(device))
            };
            #[cfg(unix)]
            {
                Ok(service::Attachment::readable(
                    PacketLayer::Ethernet,
                    open_vxlan,
                ))
            }
            #[cfg(windows)]
            {
                Ok(service::Attachment::deferred_native(
                    PacketLayer::Ethernet,
                    move || async move { open_vxlan() },
                ))
            }
        } else {
            make_attachment(NativeAttachmentRequest {
                layer,
                mtu: tun_mtu,
                peer,
                address_override,
                device_name,
                tap_mac,
            })
        }
    };

    match carrier {
        "quic-like" | "media-like" | "tls-like" => {
            if opts
                .get("--server-pin")
                .is_some_and(|s| !s.trim().is_empty())
            {
                return Err(invalid(
                    "--server-pin requires an outer TLS or QUIC carrier (openvpn-like, tcp, or quic)",
                ));
            }
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
            let attachment = build_attachment(peer)?;
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
            let tls =
                ClientTls::from_der_roots_with_policy(&[ca], parse_sni()?, parse_server_pin()?)
                    .map_err(io::Error::other)?;
            let member =
                std::sync::Arc::new(MemberKey::from_pkcs8(&member_der).map_err(io::Error::other)?);
            let outer_creds = service::Client {
                remote: peer,
                tls,
                server_name: req("--server-name")?.to_owned(),
                member,
            };
            let attachment = build_attachment(peer)?;
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
            let server_pin = parse_server_pin()?;
            let member =
                std::sync::Arc::new(MemberKey::from_pkcs8(&member_der).map_err(io::Error::other)?);
            let outer = match settings.transport {
                super::maintained::Transport::Tls(_) => {
                    let tls =
                        ClientTls::from_der_roots_with_policy(&[ca], parse_sni()?, server_pin)
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
                    server_pin,
                    server_name,
                    member,
                },
            };
            let attachment = build_attachment(settings.first.server)?;
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

    #[test]
    fn native_vxlan_and_tap_mac_validation() {
        let mut opts = BTreeMap::new();
        assert!(parse_native_vxlan(&opts, PacketLayer::Ip, 1500).is_ok());

        // Partial VXLAN options fail.
        opts.insert("--vxlan-bind".into(), "127.0.0.1:4789".into());
        assert!(parse_native_vxlan(&opts, PacketLayer::Ethernet, 1500).is_err());

        opts.insert("--vxlan-peer".into(), "127.0.0.1:4790".into());
        opts.insert("--vni".into(), "42".into());
        // VXLAN on TUN layer fails.
        assert!(parse_native_vxlan(&opts, PacketLayer::Ip, 1500).is_err());
        // VXLAN on TAP layer succeeds.
        let vxlan = parse_native_vxlan(&opts, PacketLayer::Ethernet, 1500)
            .ok()
            .flatten();
        assert!(vxlan.is_some());

        // Out-of-range VNI fails.
        opts.insert("--vni".into(), "16777216".into());
        assert!(parse_native_vxlan(&opts, PacketLayer::Ethernet, 1500).is_err());

        // Valid and invalid TAP MAC addresses.
        assert_eq!(
            parse_tap_mac("02:aa:bb:cc:dd:ee").ok(),
            Some([0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0xee])
        );
        assert!(parse_tap_mac("01:00:5e:00:00:01").is_err());
        assert!(parse_tap_mac("00:00:00:00:00:00").is_err());
        assert!(parse_tap_mac("not-a-mac").is_err());
    }
}
