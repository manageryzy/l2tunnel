//! One-step setup wizard and read-only cover-domain crawler.
//!
//! Simplifies configuring a server + client pair for UDP covers (`quic-like`,
//! `tls-like`, `media-like`) and outer-TLS/QUIC carriers (`openvpn-like`, `tcp`,
//! `quic`):
//!
//! 1. Optionally probes a target public cover domain (e.g. `google.com`) over a
//!    bounded read-only TLS 1.3 + UDP/443 QUIC check to inspect its public
//!    appearance (TLS version, ALPN, cipher suite, leaf cert size, UDP/443 QUIC
//!    responsiveness) and select matching `--sni` and `--udp-cover`.
//! 2. Generates fresh own-server and client credentials (Noise X25519 pairs,
//!    Ed25519 member identity, shared admission/cookie/PSK secrets, and for
//!    outer-TLS/QUIC carriers a fresh own-server DER certificate/key with exact
//!    SHA-256 `--server-pin`). The crawled domain's certificate is never trusted
//!    for tunnel authentication.
//! 3. Writes complete `server/` and `client/` directories (profiles, keys,
//!    auto-tuned `common-plan.json`, `maintained-policy.json` when needed,
//!    `run-server.sh`, and a ready-to-paste `l2tunnel://v1/connect?...` share
//!    link).
use crate::local::share_uri::{self, ShareProfile, ShareSecrets};
use crate::local::{PROFILE_VERSION, ProfileDocument, ProfileRole, validate_profile_name};
use ring::digest::{SHA256, digest};
use ring::rand::{SecureRandom, SystemRandom};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::io::{self, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// Supported carriers for the setup wizard.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum WizardCarrier {
    /// Direct UDP with QUIC-like cover framing.
    QuicLike,
    /// Direct UDP with TLS-like cover framing.
    TlsLike,
    /// Direct UDP with minimal RTP/media-like cover framing.
    MediaLike,
    /// UDP with outer TLS 1.3 OpenVPN-like handshake + `--sni` + `--server-pin`.
    OpenVpnLike,
    /// Maintained TCP/TLS 1.3 carrier + `--sni` + `--server-pin`.
    Tcp,
    /// Genuine maintained Quinn QUIC carrier + `--server-pin`.
    Quic,
}

impl WizardCarrier {
    /// Parse a carrier name (`quic-like`, `tls-like`, `media-like`, `openvpn-like`, `tcp`, `quic`).
    pub fn parse(raw: &str) -> io::Result<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "quic-like" => Ok(Self::QuicLike),
            "tls-like" => Ok(Self::TlsLike),
            "media-like" => Ok(Self::MediaLike),
            "openvpn-like" => Ok(Self::OpenVpnLike),
            "tcp" | "tls" | "tcp-tls" => Ok(Self::Tcp),
            "quic" => Ok(Self::Quic),
            other => Err(invalid(format!(
                "unsupported wizard carrier '{other}' (expected quic-like, tls-like, media-like, openvpn-like, tcp, or quic)"
            ))),
        }
    }

    /// Canonical CLI `--carrier` option value.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::QuicLike => "quic-like",
            Self::TlsLike => "tls-like",
            Self::MediaLike => "media-like",
            Self::OpenVpnLike => "openvpn-like",
            Self::Tcp => "tcp",
            Self::Quic => "quic",
        }
    }

    /// Whether this carrier uses outer TLS certificates (`--ca`, `--cert`, `--key`, `--server-pin`).
    pub fn uses_outer_tls(self) -> bool {
        matches!(self, Self::OpenVpnLike | Self::Tcp | Self::Quic)
    }

    /// Whether this carrier supports independent ClientHello `--sni` override.
    pub fn supports_sni(self) -> bool {
        matches!(self, Self::OpenVpnLike | Self::Tcp)
    }

    /// Whether this carrier requires a `maintained-policy.json` file.
    pub fn uses_maintained_policy(self) -> bool {
        matches!(self, Self::Tcp | Self::Quic)
    }
}

/// Public TLS / QUIC appearance metadata observed from a cover target domain.
///
/// This is strictly read-only reconnaissance used to select `--sni` and cover
/// presets; the observed certificate is never used as a tunnel trust anchor.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CrawlReport {
    /// Validated DNS cover hostname (e.g. `google.com`).
    pub domain: String,
    /// Target TCP/UDP port probed (typically `443`).
    pub port: u16,
    /// Resolved remote socket address contacted.
    pub resolved_addr: String,
    /// Negotiated TLS version (e.g. `TLSv1.3`).
    pub tls_version: String,
    /// Negotiated ALPN protocol, if any (e.g. `h2`).
    pub alpn: Option<String>,
    /// Negotiated TLS cipher suite name.
    pub cipher_suite: String,
    /// Observed leaf certificate SHA-256 (informational only; never trusted for l2tunnel).
    pub observed_leaf_sha256: Option<String>,
    /// Observed leaf certificate DER size in bytes.
    pub observed_leaf_bytes: usize,
    /// Whether UDP on the target port responded to a QUIC Initial-like probe.
    pub udp_quic_observed: bool,
    /// Recommended `--sni` cover hostname for TLS carriers.
    pub recommended_sni: String,
    /// Recommended `--udp-cover` (`quic-like` if QUIC responded, else `tls-like`).
    pub recommended_cover: String,
    /// Recommended carrier string matching the probe.
    pub recommended_carrier: String,
}

/// Input parameters for [`generate_pair`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WizardRequest {
    /// Profile name (`[a-z0-9._-]`).
    pub name: String,
    /// Selected carrier.
    pub carrier: WizardCarrier,
    /// Public server endpoint (`IP:PORT`) that clients will connect to.
    pub server_endpoint: SocketAddr,
    /// Optional server listen address override (defaults to `0.0.0.0:<port>` for UDP/openvpn-like
    /// and `server_endpoint` for maintained `tcp`/`quic`).
    pub server_bind: Option<SocketAddr>,
    /// Optional local client bind address for maintained `tcp`/`quic` policies.
    pub client_bind: Option<SocketAddr>,
    /// Optional domain whose traffic appearance to imitate (e.g. `google.com`).
    pub look_like: Option<String>,
    /// Whether to perform a live read-only TLS/QUIC crawl of `look_like`.
    pub crawl: bool,
    /// Tunnel layer (`tun` or `tap`).
    pub layer: String,
    /// Noise handshake profile (`ik` or `ikpsk2`).
    pub noise: String,
    /// Inner tunnel device MTU (`1280..=65519`).
    pub device_mtu: u16,
    /// Outer network path MTU (`1280..=65535`).
    pub path_mtu: u16,
    /// Server-side TUN CIDR (informational for server setup).
    pub tun_server_cidr: String,
    /// Client-side TUN CIDR (written into Share URI `tun=` and Windows `--tun-address`).
    pub tun_client_cidr: String,
    /// Output directory where `server/` and `client/` bundles are created.
    pub output_dir: PathBuf,
}

impl WizardRequest {
    /// Create a sensible default wizard request for a given carrier, server, and output directory.
    pub fn simple(
        name: String,
        carrier: WizardCarrier,
        server_endpoint: SocketAddr,
        look_like: Option<String>,
        output_dir: PathBuf,
    ) -> Self {
        Self {
            name,
            carrier,
            server_endpoint,
            server_bind: None,
            client_bind: None,
            look_like,
            crawl: true,
            layer: "tun".to_owned(),
            noise: "ik".to_owned(),
            device_mtu: 1500,
            path_mtu: 1500,
            tun_server_cidr: "10.231.0.1/30".to_owned(),
            tun_client_cidr: "10.231.0.2/30".to_owned(),
            output_dir,
        }
    }
}

/// Output produced by [`generate_pair`].
#[derive(Clone, Debug, Serialize)]
pub struct WizardResult {
    /// Profile name.
    pub name: String,
    /// Effective `--carrier`.
    pub carrier: String,
    /// Effective UDP/bootstrap cover (`quic-like`, `tls-like`, `media-like`).
    pub cover: String,
    /// Configured cover SNI (`--sni`), when applicable.
    pub sni: Option<String>,
    /// Own-server TLS verification name (`--server-name`), when applicable.
    pub server_name: Option<String>,
    /// Pinned SHA-256 of the generated own-server leaf DER certificate (`--server-pin`), when applicable.
    pub server_pin: Option<String>,
    /// Live crawl metadata when `look_like` was probed.
    pub crawl: Option<CrawlReport>,
    /// Advisory note if live crawl was skipped or unreachable (generation still succeeds offline).
    pub crawl_note: Option<String>,
    /// Server output directory.
    pub server_dir: PathBuf,
    /// Client output directory.
    pub client_dir: PathBuf,
    /// Path to `server/profile.json`.
    pub server_profile_path: PathBuf,
    /// Path to `client/profile.json`.
    pub client_profile_path: PathBuf,
    /// Path to `client/share-uri.txt`.
    pub share_uri_path: PathBuf,
    /// Ready-to-import full provisioning `l2tunnel://v1/connect?...` share link.
    pub share_uri: String,
    /// Public-only `l2tunnel://v1/connect?...` share link (no private keys).
    pub public_share_uri: String,
    /// Ready-to-run `l2tunneld serve ...` shell command for the server.
    pub server_command: String,
    /// Server profile document.
    pub server_profile: ProfileDocument,
    /// Client profile document.
    pub client_profile: ProfileDocument,
}

fn invalid(msg: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, msg.into())
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(out, "{b:02x}");
    }
    out
}

fn random_32() -> io::Result<zeroize::Zeroizing<[u8; 32]>> {
    let mut buf = zeroize::Zeroizing::new([0_u8; 32]);
    SystemRandom::new()
        .fill(buf.as_mut())
        .map_err(|_| io::Error::other("system randomness unavailable"))?;
    Ok(buf)
}

fn write_file(path: &Path, bytes: &[u8], secret: bool) -> io::Result<()> {
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    if secret {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    #[cfg(not(unix))]
    let _ = secret;
    let mut file = opts.open(path)?;
    file.write_all(bytes)?;
    file.sync_all()
}

/// Parse `"google.com"` or `"google.com:443"` into a validated DNS name and port.
pub fn parse_cover_target(raw: &str) -> io::Result<(String, u16)> {
    let trimmed = raw
        .trim()
        .trim_start_matches("https://")
        .trim_start_matches("http://");
    let host_port = trimmed.split('/').next().unwrap_or(trimmed);
    let (domain, port) = match host_port.rsplit_once(':') {
        Some((h, p)) => {
            let port: u16 = p
                .parse()
                .ok()
                .filter(|&v| v > 0)
                .ok_or_else(|| invalid(format!("invalid cover target port in '{raw}'")))?;
            (h, port)
        }
        None => (host_port, 443),
    };
    l2tunnel_auth::ClientSni::named(domain)
        .map_err(|_| invalid(format!("invalid cover DNS domain '{domain}'")))?;
    Ok((domain.to_ascii_lowercase(), port))
}

#[derive(Debug)]
struct CrawlOnlyObserver {
    leaf_der: Arc<Mutex<Option<Vec<u8>>>>,
}

/// Read-only TLS metadata observer used SOLELY by [`crawl_cover_domain`] to
/// inspect a public cover site's ServerHello/ALPN/certificate length. Never
/// used for tunnel authentication or tunnel data transfer.
impl ServerCertVerifier for CrawlOnlyObserver {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        if let Ok(mut guard) = self.leaf_der.lock()
            && end_entity.as_ref().len() <= 65_536
        {
            *guard = Some(end_entity.as_ref().to_vec());
        }
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Probe a public cover domain (e.g. `google.com`) over a bounded read-only
/// TLS 1.3 handshake + UDP/443 QUIC check to inspect its public appearance.
pub async fn crawl_cover_domain(target: &str, timeout: Duration) -> io::Result<CrawlReport> {
    let (domain, port) = parse_cover_target(target)?;
    let bounded = timeout.clamp(Duration::from_millis(500), Duration::from_secs(15));
    let resolved = tokio::time::timeout(bounded, tokio::net::lookup_host((domain.as_str(), port)))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "DNS lookup timed out"))??
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no IP address resolved"))?;

    let leaf_slot: Arc<Mutex<Option<Vec<u8>>>> = Arc::new(Mutex::new(None));
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut cfg = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(io::Error::other)?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(CrawlOnlyObserver {
            leaf_der: leaf_slot.clone(),
        }))
        .with_no_client_auth();
    cfg.enable_sni = true;
    cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    let connector = tokio_rustls::TlsConnector::from(Arc::new(cfg));
    let server_name =
        ServerName::try_from(domain.clone()).map_err(|_| invalid("invalid DNS SNI name"))?;

    let (tls_version, alpn, cipher_suite) = tokio::time::timeout(bounded, async {
        let tcp = tokio::net::TcpStream::connect(resolved).await?;
        let tls = connector.connect(server_name, tcp).await?;
        let (_, conn) = tls.get_ref();
        let ver = conn
            .protocol_version()
            .map(|v| format!("{v:?}"))
            .unwrap_or_else(|| "unknown".to_owned());
        let alpn = conn
            .alpn_protocol()
            .map(|b| String::from_utf8_lossy(b).into_owned());
        let suite = conn
            .negotiated_cipher_suite()
            .map(|s| format!("{:?}", s.suite()))
            .unwrap_or_else(|| "unknown".to_owned());
        Ok::<_, io::Error>((ver, alpn, suite))
    })
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "TLS cover crawl timed out"))??;

    let observed_leaf = leaf_slot.lock().ok().and_then(|g| g.clone());
    let observed_leaf_bytes = observed_leaf.as_ref().map_or(0, Vec::len);
    let observed_leaf_sha256 = observed_leaf
        .as_deref()
        .map(|der| hex_encode(digest(&SHA256, der).as_ref()));

    // Bounded read-only UDP QUIC Version-Negotiation probe: send a 1200-byte
    // QUIC long header with reserved grease version 0x0a0a0a0a so any live QUIC
    // server immediately replies with a QUIC Version Negotiation packet.
    let udp_quic_observed = probe_udp_quic(resolved, Duration::from_millis(800)).await;

    let recommended_cover = if udp_quic_observed {
        "quic-like".to_owned()
    } else {
        "tls-like".to_owned()
    };
    let recommended_carrier = if tls_version.contains("1_3") {
        "tcp".to_owned()
    } else {
        recommended_cover.clone()
    };

    Ok(CrawlReport {
        domain: domain.clone(),
        port,
        resolved_addr: resolved.to_string(),
        tls_version,
        alpn,
        cipher_suite,
        observed_leaf_sha256,
        observed_leaf_bytes,
        udp_quic_observed,
        recommended_sni: domain,
        recommended_cover,
        recommended_carrier,
    })
}

async fn probe_udp_quic(addr: SocketAddr, timeout: Duration) -> bool {
    let bind_addr: SocketAddr = if addr.is_ipv6() {
        SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0)
    } else {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
    };
    let Ok(sock) = tokio::net::UdpSocket::bind(bind_addr).await else {
        return false;
    };
    if sock.connect(addr).await.is_err() {
        return false;
    }
    let mut probe = [0_u8; 1200];
    // Long header (0x80 | Fixed 0x40), greased version 0x0a0a0a0a, 8-byte DCID + 8-byte SCID.
    probe[0] = 0xc0;
    probe[1..5].copy_from_slice(&[0x0a, 0x0a, 0x0a, 0x0a]);
    probe[5] = 8;
    let _ = SystemRandom::new().fill(&mut probe[6..14]);
    probe[14] = 8;
    let _ = SystemRandom::new().fill(&mut probe[15..23]);
    if sock.send(&probe).await.is_err() {
        return false;
    }
    let mut reply = [0_u8; 1500];
    matches!(
        tokio::time::timeout(timeout, sock.recv(&mut reply)).await,
        Ok(Ok(n)) if n >= 7 && (reply[0] & 0x80) != 0
    )
}

/// Blocking wrapper for [`crawl_cover_domain`] suitable for CLI and background GUI threads.
pub fn crawl_cover_domain_blocking(target: &str, timeout: Duration) -> io::Result<CrawlReport> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    rt.block_on(crawl_cover_domain(target, timeout))
}

/// Build a canonical strict `maintained-policy.json` document accepted by
/// `secure_udp::maintained_cli::read` for `tcp` or `quic` carriers.
pub(crate) fn build_maintained_policy_json(
    carrier: &str,
    client_bind: SocketAddr,
    server_endpoint: SocketAddr,
    path_mtu: u16,
) -> Result<Vec<u8>, String> {
    let path_mtu_usize = usize::from(path_mtu);
    let ip_overhead = if server_endpoint.is_ipv6() { 48 } else { 28 };
    let policy = match carrier {
        "tcp" => {
            let max_record = path_mtu_usize.saturating_sub(70).max(1200);
            serde_json::json!({
                "version": 1,
                "first": {
                    "client": client_bind.to_string(),
                    "server": server_endpoint.to_string(),
                },
                "second": null,
                "geometry": {
                    "path_mtu": path_mtu_usize,
                    "max_record_bytes": max_record,
                    "max_bootstrap_bytes": max_record,
                    "charged_overhead_bytes": 70,
                    "bootstrap_overhead_bytes": 70,
                    "framing_bytes": 5,
                },
                "transport": {
                    "kind": "tls",
                    "record_timeout_micros": 1_000_000_u64,
                },
            })
        }
        "quic" => {
            let udp_ceiling = path_mtu_usize.saturating_sub(ip_overhead);
            let udp_ceiling_u16 = u16::try_from(udp_ceiling)
                .map_err(|_| "QUIC path MTU exceeds u16 UDP ceiling".to_owned())?;
            let max_record = udp_ceiling.saturating_sub(144).max(1152);
            let app_id = [
                0x6c, 0x32, 0x74, 0x2d, 0x71, 0x75, 0x69, 0x63, 0x2d, 0x76, 0x31, 0x00, 0x00, 0x00,
                0x00, 0x01,
            ];
            let quic_profile = l2tunnel_quic::Profile {
                application_id: app_id,
                traffic: l2tunnel_quic::Traffic::FullDuplex,
                lane: 0,
                datagram_format: l2tunnel_quic::DatagramFormat::CommonCompact,
                max_datagram_bytes: max_record,
                queued_datagrams: 64,
                control_window_bytes: 65_536,
                udp_payload_ceiling: udp_ceiling_u16,
                idle_timeout: Duration::from_secs(30),
                io_timeout: Duration::from_secs(5),
            };
            let max_bootstrap = quic_profile.maximum_bootstrap_bytes();
            serde_json::json!({
                "version": 1,
                "first": {
                    "client": client_bind.to_string(),
                    "server": server_endpoint.to_string(),
                },
                "second": null,
                "geometry": {
                    "path_mtu": path_mtu_usize,
                    "max_record_bytes": max_record,
                    "max_bootstrap_bytes": max_bootstrap,
                    "charged_overhead_bytes": ip_overhead + 128,
                    "bootstrap_overhead_bytes": ip_overhead + 128 + 48,
                    "framing_bytes": 0,
                },
                "transport": {
                    "kind": "quic",
                    "application_id": app_id,
                    "queued_datagrams": 64,
                    "control_window_bytes": 65_536,
                    "idle_timeout_micros": 30_000_000_u64,
                    "io_timeout_micros": 5_000_000_u64,
                },
            })
        }
        other => return Err(format!("carrier '{other}' does not use maintained policy")),
    };
    serde_json::to_vec_pretty(&policy).map_err(|e| format!("serialize maintained policy: {e}"))
}

/// Generate a complete, matched server + client credential set, profiles,
/// ready-to-run server command, and one-click `l2tunnel://v1/connect?...` share link.
pub fn generate_pair(req: &WizardRequest) -> io::Result<WizardResult> {
    validate_profile_name(req.name.trim()).map_err(invalid)?;
    if !matches!(req.layer.as_str(), "tun" | "tap") {
        return Err(invalid("layer must be 'tun' or 'tap'"));
    }
    if !matches!(req.noise.as_str(), "ik" | "ikpsk2") {
        return Err(invalid("noise must be 'ik' or 'ikpsk2'"));
    }
    if !(1280..=65519).contains(&req.device_mtu) || req.path_mtu < 1280 {
        return Err(invalid("invalid device_mtu / path_mtu bounds"));
    }
    if req.server_endpoint.port() == 0
        || req.server_endpoint.ip().is_unspecified()
        || req.server_endpoint.ip().is_multicast()
    {
        return Err(invalid(
            "server endpoint must be a concrete unicast IP:PORT",
        ));
    }

    // 1. Validate & optionally crawl cover domain.
    let mut crawl_report: Option<CrawlReport> = None;
    let mut crawl_note: Option<String> = None;
    let validated_domain = match req
        .look_like
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        Some(raw) => {
            let (domain, port) = parse_cover_target(raw)?;
            if req.crawl {
                let target = format!("{domain}:{port}");
                match crawl_cover_domain_blocking(&target, Duration::from_secs(5)) {
                    Ok(report) => crawl_report = Some(report),
                    Err(err) => {
                        crawl_note = Some(format!(
                            "live crawl of {target} skipped/failed ({err}); using validated DNS SNI '{domain}' offline"
                        ));
                    }
                }
            } else {
                crawl_note = Some(format!(
                    "offline mode: validated DNS cover name '{domain}' without network crawl"
                ));
            }
            Some(domain)
        }
        None => None,
    };

    // Select effective UDP/bootstrap cover.
    let cover = match req.carrier {
        WizardCarrier::QuicLike => "quic-like".to_owned(),
        WizardCarrier::TlsLike => "tls-like".to_owned(),
        WizardCarrier::MediaLike => "media-like".to_owned(),
        WizardCarrier::OpenVpnLike | WizardCarrier::Tcp | WizardCarrier::Quic => {
            if let Some(report) = &crawl_report {
                report.recommended_cover.clone()
            } else if matches!(req.carrier, WizardCarrier::Quic) {
                "quic-like".to_owned()
            } else {
                "tls-like".to_owned()
            }
        }
    };

    // 2. Create output directories.
    let server_dir = req.output_dir.join("server");
    let client_dir = req.output_dir.join("client");
    std::fs::create_dir_all(&server_dir)?;
    std::fs::create_dir_all(&client_dir)?;

    // 3. Generate fresh cryptographic credentials.
    let srv_noise_priv = random_32()?;
    let srv_noise_pub = l2tunnel_handshake::LocalSecret::new(srv_noise_priv.clone())
        .public_key()
        .0;
    let cli_noise_priv = random_32()?;
    let cli_noise_pub = l2tunnel_handshake::LocalSecret::new(cli_noise_priv.clone())
        .public_key()
        .0;
    let member_pk8 = l2tunnel_auth::MemberKey::generate_pkcs8().map_err(io::Error::other)?;
    let member_id =
        l2tunnel_identity::IdentityKey::from_pkcs8(&member_pk8).map_err(io::Error::other)?;
    let member_pub = member_id.public_key().0;
    let admission = random_32()?;
    let cookie = random_32()?;
    let psk = if req.noise == "ikpsk2" {
        Some(random_32()?)
    } else {
        None
    };

    // Write shared & directional Noise/member secrets.
    let srv_noise_priv_path = server_dir.join("noise-private.key");
    let srv_noise_peer_path = server_dir.join("noise-peer.pub");
    let srv_allow_key_path = server_dir.join("member.pub");
    let srv_adm_path = server_dir.join("admission.key");
    let srv_cookie_path = server_dir.join("cookie.key");
    write_file(&srv_noise_priv_path, srv_noise_priv.as_ref(), true)?;
    write_file(&srv_noise_peer_path, &cli_noise_pub, false)?;
    write_file(&srv_allow_key_path, &member_pub, false)?;
    write_file(&srv_adm_path, admission.as_ref(), true)?;
    write_file(&srv_cookie_path, cookie.as_ref(), true)?;

    let cli_noise_priv_path = client_dir.join("noise-private.key");
    let cli_noise_peer_path = client_dir.join("noise-peer.pub");
    let cli_member_path = client_dir.join("member.pk8");
    let cli_adm_path = client_dir.join("admission.key");
    write_file(&cli_noise_priv_path, cli_noise_priv.as_ref(), true)?;
    write_file(&cli_noise_peer_path, &srv_noise_pub, false)?;
    write_file(&cli_member_path, &member_pk8, true)?;
    write_file(&cli_adm_path, admission.as_ref(), true)?;

    let mut srv_psk_path = None;
    let mut cli_psk_path = None;
    if let Some(psk_bytes) = &psk {
        let sp = server_dir.join("noise-psk.key");
        let cp = client_dir.join("noise-psk.key");
        write_file(&sp, psk_bytes.as_ref(), true)?;
        write_file(&cp, psk_bytes.as_ref(), true)?;
        srv_psk_path = Some(sp);
        cli_psk_path = Some(cp);
    }

    // 4. For outer-TLS/QUIC carriers, generate fresh own-server DER cert + key + exact SHA-256 pin.
    let mut server_name_opt: Option<String> = None;
    let mut sni_opt: Option<String> = None;
    let mut server_pin_bytes: Option<[u8; 32]> = None;
    let mut server_pin_hex: Option<String> = None;
    let mut ca_der_bytes: Option<Vec<u8>> = None;
    let mut srv_cert_path: Option<PathBuf> = None;
    let mut srv_key_path: Option<PathBuf> = None;
    let mut cli_ca_path: Option<PathBuf> = None;

    if req.carrier.uses_outer_tls() {
        let internal_name = format!("{}.l2tunnel.internal", req.name.trim());
        let cert = rcgen::generate_simple_self_signed(vec![internal_name.clone()])
            .map_err(io::Error::other)?;
        let cert_der = cert.cert.der().to_vec();
        let key_der = cert.signing_key.serialize_der();
        let pin_digest: [u8; 32] = digest(&SHA256, &cert_der)
            .as_ref()
            .try_into()
            .map_err(io::Error::other)?;
        let sc = server_dir.join("server.der");
        let sk = server_dir.join("server.key.der");
        let cc = client_dir.join("ca.der");
        write_file(&sc, &cert_der, false)?;
        write_file(&sk, &key_der, true)?;
        write_file(&cc, &cert_der, false)?;

        server_name_opt = Some(internal_name);
        if req.carrier.supports_sni() {
            sni_opt = validated_domain.clone();
        }
        server_pin_hex = Some(hex_encode(&pin_digest));
        server_pin_bytes = Some(pin_digest);
        ca_der_bytes = Some(cert_der);
        srv_cert_path = Some(sc);
        srv_key_path = Some(sk);
        cli_ca_path = Some(cc);
    }

    // 5. Materialize matching tuned Common plan (and maintained-policy.json for tcp/quic).
    let plan_bytes = if req.device_mtu == 1500 && req.path_mtu == 1500 {
        share_uri::DEFAULT_COMMON_PLAN_JSON.as_bytes().to_vec()
    } else {
        share_uri::tune_default_plan_json(req.device_mtu, req.path_mtu)
            .map_err(|e| invalid(e.to_string()))?
    };
    let srv_plan_path = server_dir.join("common-plan.json");
    let cli_plan_path = client_dir.join("common-plan.json");
    write_file(&srv_plan_path, &plan_bytes, false)?;
    write_file(&cli_plan_path, &plan_bytes, false)?;

    let client_bind_for_maintained = if req.carrier.uses_maintained_policy() {
        let default_bind = if req.server_endpoint.is_ipv6() {
            SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 43101)
        } else {
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 43101)
        };
        Some(req.client_bind.unwrap_or(default_bind))
    } else {
        None
    };

    let mut srv_maint_path: Option<PathBuf> = None;
    let mut cli_maint_path: Option<PathBuf> = None;
    if let Some(c_bind) = client_bind_for_maintained {
        let maint_bytes = build_maintained_policy_json(
            req.carrier.as_str(),
            c_bind,
            req.server_endpoint,
            req.path_mtu,
        )
        .map_err(invalid)?;
        let sm = server_dir.join("maintained-policy.json");
        let cm = client_dir.join("maintained-policy.json");
        write_file(&sm, &maint_bytes, false)?;
        write_file(&cm, &maint_bytes, false)?;
        srv_maint_path = Some(sm);
        cli_maint_path = Some(cm);
    }

    // 6. Build server and client ProfileDocuments.
    let server_bind = req.server_bind.unwrap_or_else(|| {
        if req.carrier.uses_maintained_policy() {
            req.server_endpoint
        } else if req.server_endpoint.is_ipv6() {
            SocketAddr::new(
                IpAddr::V6(Ipv6Addr::UNSPECIFIED),
                req.server_endpoint.port(),
            )
        } else {
            SocketAddr::new(
                IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                req.server_endpoint.port(),
            )
        }
    });

    let mut srv_opts = BTreeMap::new();
    srv_opts.insert("--record-profile".into(), "common".into());
    srv_opts.insert("--carrier".into(), req.carrier.as_str().into());
    srv_opts.insert("--duplex".into(), "full".into());
    srv_opts.insert("--compression".into(), "off".into());
    srv_opts.insert("--layer".into(), req.layer.clone());
    srv_opts.insert("--device".into(), "l2t0".into());
    srv_opts.insert("--max-packet".into(), req.device_mtu.to_string());
    srv_opts.insert("--max-path-mtu".into(), req.path_mtu.to_string());
    srv_opts.insert("--noise-profile".into(), req.noise.clone());
    srv_opts.insert(
        "--common-transaction-plan".into(),
        srv_plan_path.display().to_string(),
    );
    srv_opts.insert(
        "--noise-private-key-file".into(),
        srv_noise_priv_path.display().to_string(),
    );
    srv_opts.insert(
        "--noise-peer-key-file".into(),
        srv_noise_peer_path.display().to_string(),
    );
    srv_opts.insert(
        "--allow-key".into(),
        srv_allow_key_path.display().to_string(),
    );
    srv_opts.insert(
        "--session-admission-key-file".into(),
        srv_adm_path.display().to_string(),
    );
    srv_opts.insert(
        "--session-cookie-key-file".into(),
        srv_cookie_path.display().to_string(),
    );
    if let Some(p) = &srv_psk_path {
        srv_opts.insert("--noise-psk-file".into(), p.display().to_string());
    }
    if req.carrier.uses_maintained_policy() {
        srv_opts.insert("--listen".into(), server_bind.to_string());
        srv_opts.insert("--udp-cover".into(), cover.clone());
        if let Some(m) = &srv_maint_path {
            srv_opts.insert("--maintained-policy".into(), m.display().to_string());
        }
    } else {
        srv_opts.insert("--udp-bind".into(), server_bind.to_string());
        srv_opts.insert("--udp-peer".into(), "0.0.0.0:0".into());
        if req.carrier == WizardCarrier::OpenVpnLike {
            srv_opts.insert("--udp-cover".into(), cover.clone());
        }
    }
    if let (Some(cert), Some(key)) = (&srv_cert_path, &srv_key_path) {
        srv_opts.insert("--cert".into(), cert.display().to_string());
        srv_opts.insert("--key".into(), key.display().to_string());
    }
    let server_profile = ProfileDocument {
        version: PROFILE_VERSION,
        role: ProfileRole::Serve,
        options: srv_opts.clone(),
    };

    let mut cli_opts = BTreeMap::new();
    cli_opts.insert("--record-profile".into(), "common".into());
    cli_opts.insert("--carrier".into(), req.carrier.as_str().into());
    cli_opts.insert("--duplex".into(), "full".into());
    cli_opts.insert("--compression".into(), "off".into());
    cli_opts.insert("--layer".into(), req.layer.clone());
    cli_opts.insert("--device".into(), "l2t0".into());
    cli_opts.insert("--max-packet".into(), req.device_mtu.to_string());
    cli_opts.insert("--max-path-mtu".into(), req.path_mtu.to_string());
    cli_opts.insert("--noise-profile".into(), req.noise.clone());
    cli_opts.insert(
        "--common-transaction-plan".into(),
        cli_plan_path.display().to_string(),
    );
    cli_opts.insert(
        "--noise-private-key-file".into(),
        cli_noise_priv_path.display().to_string(),
    );
    cli_opts.insert(
        "--noise-peer-key-file".into(),
        cli_noise_peer_path.display().to_string(),
    );
    cli_opts.insert("--identity".into(), cli_member_path.display().to_string());
    cli_opts.insert(
        "--session-admission-key-file".into(),
        cli_adm_path.display().to_string(),
    );
    if let Some(p) = &cli_psk_path {
        cli_opts.insert("--noise-psk-file".into(), p.display().to_string());
    }
    if req.carrier.uses_maintained_policy() {
        cli_opts.insert("--remote".into(), req.server_endpoint.to_string());
        cli_opts.insert("--udp-cover".into(), cover.clone());
        if let Some(m) = &cli_maint_path {
            cli_opts.insert("--maintained-policy".into(), m.display().to_string());
        }
    } else {
        let local_bind = if req.server_endpoint.is_ipv6() {
            "[::]:0"
        } else {
            "0.0.0.0:0"
        };
        cli_opts.insert("--udp-bind".into(), local_bind.into());
        cli_opts.insert("--udp-peer".into(), req.server_endpoint.to_string());
        if req.carrier == WizardCarrier::OpenVpnLike {
            cli_opts.insert("--udp-cover".into(), cover.clone());
        }
    }
    if let Some(ca) = &cli_ca_path {
        cli_opts.insert("--ca".into(), ca.display().to_string());
    }
    if let Some(sn) = &server_name_opt {
        cli_opts.insert("--server-name".into(), sn.clone());
    }
    if let Some(sni) = &sni_opt {
        cli_opts.insert("--sni".into(), sni.clone());
    }
    if let Some(pin) = &server_pin_hex {
        cli_opts.insert("--server-pin".into(), pin.clone());
    }
    #[cfg(windows)]
    if !req.tun_client_cidr.is_empty() && req.layer == "tun" {
        cli_opts.insert("--tun-address".into(), req.tun_client_cidr.clone());
    }
    let client_profile = ProfileDocument {
        version: PROFILE_VERSION,
        role: ProfileRole::Connect,
        options: cli_opts,
    };

    // 7. Build full-provisioning & public-only l2tunnel://v1/connect share links.
    let share_carrier = match req.carrier {
        WizardCarrier::QuicLike | WizardCarrier::TlsLike | WizardCarrier::MediaLike => None,
        WizardCarrier::OpenVpnLike => Some("openvpn-like".to_owned()),
        WizardCarrier::Tcp => Some("tcp".to_owned()),
        WizardCarrier::Quic => Some("quic".to_owned()),
    };
    let mut share_profile = ShareProfile {
        name: Some(req.name.trim().to_owned()),
        carrier: share_carrier,
        peer: req.server_endpoint.to_string(),
        cover: cover.clone(),
        noise: req.noise.clone(),
        peer_pub: Some(srv_noise_pub),
        sni: sni_opt.clone(),
        server_name: server_name_opt.clone(),
        server_pin: server_pin_bytes,
        ca_der: ca_der_bytes,
        client_bind: client_bind_for_maintained.map(|a| a.to_string()),
        tun_mtu: req.device_mtu,
        path_mtu: req.path_mtu,
        handshake_seconds: 30,
        tun: (!req.tun_client_cidr.is_empty()).then(|| req.tun_client_cidr.clone()),
        routes: Vec::new(),
        dns: Vec::new(),
        tune_repair: None,
        tune_device_mtu: None,
        tune_path_mtu: None,
        secrets: ShareSecrets::default(),
    };
    let public_share_uri = share_profile
        .encode()
        .map_err(|e| invalid(format!("cannot encode public share URI: {e}")))?;

    share_profile.secrets = ShareSecrets {
        admission: Some(*admission),
        noise_private: Some(*cli_noise_priv),
        member_pk8: Some(member_pk8),
        noise_psk: psk.as_deref().copied(),
    };
    let share_uri = share_profile
        .encode()
        .map_err(|e| invalid(format!("cannot encode full provisioning share URI: {e}")))?;

    // 8. Write profile JSONs, share-uri.txt, and server run script.
    let server_profile_path = server_dir.join("profile.json");
    let client_profile_path = client_dir.join("profile.json");
    let share_uri_path = client_dir.join("share-uri.txt");
    write_file(
        &server_profile_path,
        &serde_json::to_vec_pretty(&server_profile).map_err(io::Error::other)?,
        false,
    )?;
    write_file(
        &client_profile_path,
        &serde_json::to_vec_pretty(&client_profile).map_err(io::Error::other)?,
        false,
    )?;
    write_file(&share_uri_path, format!("{share_uri}\n").as_bytes(), true)?;

    let mut server_cmd_parts = vec!["l2tunneld".to_owned(), "serve".to_owned()];
    for (k, v) in &srv_opts {
        server_cmd_parts.push(k.clone());
        server_cmd_parts.push(v.clone());
    }
    let server_command = server_cmd_parts.join(" ");
    let run_script = format!(
        "#!/usr/bin/env bash\n# Generated by l2tunnel wizard for profile '{}'\n# Suggested TUN setup (Linux): sudo ip tuntap add dev l2t0 mode tun && sudo ip addr add {} dev l2t0 && sudo ip link set l2t0 mtu {} up\nset -euo pipefail\nexec {}\n",
        req.name.trim(),
        req.tun_server_cidr,
        req.device_mtu,
        server_command
    );
    write_file(
        &server_dir.join("run-server.sh"),
        run_script.as_bytes(),
        false,
    )?;

    Ok(WizardResult {
        name: req.name.trim().to_owned(),
        carrier: req.carrier.as_str().to_owned(),
        cover,
        sni: sni_opt,
        server_name: server_name_opt,
        server_pin: server_pin_hex,
        crawl: crawl_report,
        crawl_note,
        server_dir,
        client_dir,
        server_profile_path,
        client_profile_path,
        share_uri_path,
        share_uri,
        public_share_uri,
        server_command,
        server_profile,
        client_profile,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secure_udp::maintained_cli;

    #[test]
    fn parse_cover_target_handles_urls_ports_and_rejects_ips() -> io::Result<()> {
        assert_eq!(
            parse_cover_target("google.com")?,
            ("google.com".to_owned(), 443)
        );
        assert_eq!(
            parse_cover_target("https://www.google.com:8443/path")?,
            ("www.google.com".to_owned(), 8443)
        );
        assert!(parse_cover_target("1.1.1.1").is_err());
        assert!(parse_cover_target("google.com:0").is_err());
        assert!(parse_cover_target("").is_err());
        Ok(())
    }

    #[test]
    fn wizard_generates_working_bundles_and_importable_share_uris_for_all_carriers()
    -> io::Result<()> {
        let base = std::env::temp_dir().join(format!("l2t-wizard-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let server: SocketAddr = "203.0.113.10:443".parse().map_err(io::Error::other)?;

        for (carrier, want_sni, want_pin) in [
            (WizardCarrier::QuicLike, false, false),
            (WizardCarrier::TlsLike, false, false),
            (WizardCarrier::OpenVpnLike, true, true),
            (WizardCarrier::Tcp, true, true),
            (WizardCarrier::Quic, false, true),
        ] {
            let out = base.join(carrier.as_str());
            let mut req = WizardRequest::simple(
                format!("wiz-{}", carrier.as_str()),
                carrier,
                server,
                Some("google.com".into()),
                out.clone(),
            );
            req.crawl = false; // Deterministic offline unit test.
            let res = generate_pair(&req)?;
            assert_eq!(res.sni.as_deref(), want_sni.then_some("google.com"));
            assert_eq!(res.server_pin.is_some(), want_pin);
            assert!(res.server_profile_path.is_file());
            assert!(res.client_profile_path.is_file());
            assert!(res.share_uri_path.is_file());

            // Share URI must decode and materialize a complete ProfileDocument!
            let decoded = ShareProfile::decode(&res.share_uri).map_err(io::Error::other)?;
            let import_dir = out.join("imported-client");
            let doc = decoded
                .to_profile_document(Some(&import_dir))
                .map_err(io::Error::other)?;
            assert_eq!(
                doc.options.get("--carrier").map(String::as_str),
                Some(carrier.as_str())
            );
            if want_sni {
                assert_eq!(
                    doc.options.get("--sni").map(String::as_str),
                    Some("google.com")
                );
            }
            if want_pin {
                assert_eq!(
                    doc.options.get("--server-pin").map(String::as_str),
                    res.server_pin.as_deref()
                );
                assert!(import_dir.join("ca.der").is_file());
            }
            if carrier.uses_maintained_policy() {
                let policy_path = doc
                    .options
                    .get("--maintained-policy")
                    .ok_or_else(|| invalid("missing --maintained-policy"))?;
                let raw = std::fs::read(policy_path)?;
                let conn = crate::ConnectionConfig {
                    layer: l2tunnel_device::PacketLayer::Ip,
                    duplex: l2tunnel_core::Duplex::Full,
                    max_packet: 1500,
                    compression: crate::Compression::None,
                    handshake_timeout: Duration::from_secs(30),
                };
                maintained_cli::read(&raw, conn)?;
            }
        }
        let _ = std::fs::remove_dir_all(&base);
        Ok(())
    }
}
