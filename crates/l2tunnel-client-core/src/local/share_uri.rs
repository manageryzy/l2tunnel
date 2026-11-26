//! Versioned `l2tunnel://v1/connect?...` share URI codec for quick profile
//! exchange across CLI (`l2tunnelctl`), Desktop GUI, and Android clients.
//!
//! By default, [`ShareProfile::from_profile_document`] emits ONLY public
//! connection parameters and the peer's public Noise key (`include_secrets = false`).
//! Private credentials (`adm`, `key`, `member`, `psk`) are only embedded on
//! explicit caller opt-in and must never be written to logs or diagnostics.
use crate::local::{PROFILE_VERSION, ProfileDocument, ProfileRole, validate_profile_name};
use std::collections::BTreeMap;
use std::fmt;
use std::io::{self, Write};
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};

/// URI prefix for version-1 client connect sharing.
pub const SHARE_URI_PREFIX: &str = "l2tunnel://v1/connect";
/// Maximum accepted URI length in bytes.
pub const MAX_SHARE_URI_BYTES: usize = 16_384;
/// Maximum raw member PKCS#8 DER length accepted inside a share URI.
pub const MAX_MEMBER_DER_BYTES: usize = 256;

/// Explicit parse/encode errors for `l2tunnel://` share URIs.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ShareUriError(pub String);

impl fmt::Display for ShareUriError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}
impl std::error::Error for ShareUriError {}

fn err(msg: impl Into<String>) -> ShareUriError {
    ShareUriError(msg.into())
}

/// Optional explicit-opt-in secret material carried inside a provisioning URI.
#[derive(Clone, Eq, PartialEq, Default)]
pub struct ShareSecrets {
    /// 32-byte shared admission secret (`admission.key`).
    pub admission: Option<[u8; 32]>,
    /// 32-byte client Noise X25519 private key (`noise-private.key`).
    pub noise_private: Option<[u8; 32]>,
    /// Client Ed25519 PKCS#8 DER bytes (`member.pk8`).
    pub member_pk8: Option<Vec<u8>>,
    /// 32-byte Noise PSK (`noise-psk.key`, only for `ikpsk2`).
    pub noise_psk: Option<[u8; 32]>,
}

impl ShareSecrets {
    /// Whether any secret credential is populated.
    pub fn is_empty(&self) -> bool {
        self.admission.is_none()
            && self.noise_private.is_none()
            && self.member_pk8.is_none()
            && self.noise_psk.is_none()
    }
}

impl fmt::Debug for ShareSecrets {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ShareSecrets")
            .field("admission", &self.admission.is_some())
            .field("noise_private", &self.noise_private.is_some())
            .field("member_pk8", &self.member_pk8.is_some())
            .field("noise_psk", &self.noise_psk.is_some())
            .finish()
    }
}

/// Portable L3 TUN UDP client share payload encoded by `l2tunnel://v1/connect?...`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ShareProfile {
    /// Optional suggested profile name (`[a-z0-9._-]`).
    pub name: Option<String>,
    /// Remote `l2tunneld` UDP endpoint (`host:port`).
    pub peer: String,
    /// UDP cover (`quic-like`, `media-like`, `tls-like`).
    pub cover: String,
    /// Noise handshake profile (`ik` or `ikpsk2`).
    pub noise: String,
    /// Pinned 32-byte server Noise static public key (`noise-peer.pub`).
    pub peer_pub: Option<[u8; 32]>,
    /// TUN MTU (`1280..=65519`).
    pub tun_mtu: u16,
    /// Outer IP path MTU (`1280..=65535`).
    pub path_mtu: u16,
    /// Handshake timeout in seconds (`1..=120`).
    pub handshake_seconds: u16,
    /// Optional TUN CIDR (e.g. `10.231.0.2/30`).
    pub tun: Option<String>,
    /// Optional comma-separated CIDR routes (e.g. `0.0.0.0/0`).
    pub routes: Vec<String>,
    /// Optional DNS servers.
    pub dns: Vec<String>,
    /// Optional live-tuning FEC catalog (e.g. `off,1/8,1/4`).
    pub tune_repair: Option<String>,
    /// Optional live-tuning internal/device MTU choices (e.g. `1500,4096`).
    pub tune_device_mtu: Option<String>,
    /// Optional live-tuning outer capsule/path MTU choices (e.g. `1280,1300,1400,1500`).
    pub tune_path_mtu: Option<String>,
    /// Optional secret provisioning fields (absent in default public URIs).
    pub secrets: ShareSecrets,
}

impl ShareProfile {
    /// Validate bounds and field syntax.
    pub fn validate(&self) -> Result<(), ShareUriError> {
        if let Some(name) = &self.name {
            validate_profile_name(name).map_err(err)?;
        }
        if self.peer.trim().is_empty() || self.peer.contains(char::is_whitespace) {
            return Err(err("peer must be a non-empty host:port"));
        }
        if !self.peer.contains(':') {
            return Err(err("peer must include :port"));
        }
        if !matches!(self.cover.as_str(), "quic-like" | "media-like" | "tls-like") {
            return Err(err(format!("unsupported UDP cover: {}", self.cover)));
        }
        if !matches!(self.noise.as_str(), "ik" | "ikpsk2") {
            return Err(err(format!("unsupported Noise profile: {}", self.noise)));
        }
        if !(1280..=65519).contains(&self.tun_mtu) {
            return Err(err("mtu must be in 1280..=65519"));
        }
        if !(1280..=65535).contains(&self.path_mtu) {
            return Err(err("path_mtu must be in 1280..=65535"));
        }
        if !(1..=120).contains(&self.handshake_seconds) {
            return Err(err("hs must be in 1..=120"));
        }
        if let Some(tun) = &self.tun {
            validate_cidr(tun)?;
        }
        for route in &self.routes {
            validate_cidr(route)?;
        }
        for dns in &self.dns {
            dns.parse::<IpAddr>()
                .map_err(|_| err(format!("invalid DNS IP address: {dns}")))?;
        }
        if let Some(pk8) = &self.secrets.member_pk8
            && (pk8.len() < 32 || pk8.len() > MAX_MEMBER_DER_BYTES)
        {
            return Err(err("member PKCS#8 length out of bounds"));
        }
        if self.secrets.noise_psk.is_some() && self.noise != "ikpsk2" {
            return Err(err("psk requires noise=ikpsk2"));
        }
        Ok(())
    }

    /// Encode this profile into a canonical `l2tunnel://v1/connect?...` URI.
    pub fn encode(&self) -> Result<String, ShareUriError> {
        self.validate()?;
        let mut pairs: Vec<(&str, String)> = Vec::new();
        if let Some(name) = &self.name {
            pairs.push(("name", percent_encode(name)));
        }
        pairs.push(("peer", percent_encode(&self.peer)));
        pairs.push(("cover", self.cover.clone()));
        pairs.push(("noise", self.noise.clone()));
        if let Some(pub_key) = &self.peer_pub {
            pairs.push(("peer_pub", hex_encode(pub_key)));
        }
        if self.tun_mtu != 1500 {
            pairs.push(("mtu", self.tun_mtu.to_string()));
        }
        if self.path_mtu != 1500 {
            pairs.push(("path_mtu", self.path_mtu.to_string()));
        }
        if self.handshake_seconds != 30 {
            pairs.push(("hs", self.handshake_seconds.to_string()));
        }
        if let Some(tun) = &self.tun {
            pairs.push(("tun", percent_encode(tun)));
        }
        if !self.routes.is_empty() {
            pairs.push(("routes", percent_encode(&self.routes.join(","))));
        }
        if !self.dns.is_empty() {
            pairs.push(("dns", percent_encode(&self.dns.join(","))));
        }
        if let Some(tr) = &self.tune_repair
            && !tr.trim().is_empty()
        {
            pairs.push(("tune_repair", percent_encode(tr.trim())));
        }
        if let Some(td) = &self.tune_device_mtu
            && !td.trim().is_empty()
        {
            pairs.push(("tune_device_mtu", percent_encode(td.trim())));
        }
        if let Some(tp) = &self.tune_path_mtu
            && !tp.trim().is_empty()
        {
            pairs.push(("tune_path_mtu", percent_encode(tp.trim())));
        }
        if let Some(adm) = &self.secrets.admission {
            pairs.push(("adm", hex_encode(adm)));
        }
        if let Some(key) = &self.secrets.noise_private {
            pairs.push(("key", hex_encode(key)));
        }
        if let Some(member) = &self.secrets.member_pk8 {
            pairs.push(("member", base64url_encode(member)));
        }
        if let Some(psk) = &self.secrets.noise_psk {
            pairs.push(("psk", hex_encode(psk)));
        }
        let mut out = String::from(SHARE_URI_PREFIX);
        out.push('?');
        for (idx, (k, v)) in pairs.iter().enumerate() {
            if idx > 0 {
                out.push('&');
            }
            out.push_str(k);
            out.push('=');
            out.push_str(v);
        }
        if out.len() > MAX_SHARE_URI_BYTES {
            return Err(err("encoded share URI exceeds maximum length"));
        }
        Ok(out)
    }

    /// Parse and validate an `l2tunnel://v1/connect?...` URI.
    pub fn decode(raw: &str) -> Result<Self, ShareUriError> {
        let trimmed = raw.trim();
        if trimmed.is_empty() || trimmed.len() > MAX_SHARE_URI_BYTES {
            return Err(err("share URI is empty or exceeds size limit"));
        }
        if !trimmed.is_ascii() {
            return Err(err("share URI must be ASCII"));
        }
        let (without_frag, fragment) = match trimmed.split_once('#') {
            Some((head, frag)) => (head, Some(percent_decode(frag)?)),
            None => (trimmed, None),
        };
        let (head, query) = without_frag
            .split_once('?')
            .ok_or_else(|| err("share URI missing query parameters"))?;
        if !head.eq_ignore_ascii_case(SHARE_URI_PREFIX) {
            return Err(err(format!(
                "unsupported share URI prefix (expected {SHARE_URI_PREFIX}?...)"
            )));
        }
        let mut map = BTreeMap::<String, String>::new();
        for pair in query.split('&') {
            if pair.is_empty() {
                continue;
            }
            let (k, v) = pair
                .split_once('=')
                .ok_or_else(|| err(format!("malformed query parameter: {pair}")))?;
            let key = k.to_ascii_lowercase();
            let val = percent_decode(v)?;
            if map.insert(key.clone(), val).is_some() {
                return Err(err(format!("duplicate query parameter: {key}")));
            }
        }
        if let Some(layer) = map.get("layer")
            && !layer.eq_ignore_ascii_case("tun")
        {
            return Err(err(format!(
                "layer=\"{layer}\" is unsupported in share URIs (TUN L3 only)"
            )));
        }
        for known_only in map.keys() {
            if !matches!(
                known_only.as_str(),
                "name"
                    | "peer"
                    | "cover"
                    | "noise"
                    | "peer_pub"
                    | "mtu"
                    | "path_mtu"
                    | "hs"
                    | "tun"
                    | "routes"
                    | "dns"
                    | "tune_repair"
                    | "tune_device_mtu"
                    | "tune_path_mtu"
                    | "layer"
                    | "adm"
                    | "key"
                    | "member"
                    | "psk"
            ) {
                return Err(err(format!("unknown query parameter: {known_only}")));
            }
        }
        let peer = map
            .get("peer")
            .cloned()
            .ok_or_else(|| err("missing required peer=host:port"))?;
        let name = map
            .get("name")
            .cloned()
            .or(fragment)
            .filter(|s| !s.trim().is_empty());
        let cover = map
            .get("cover")
            .cloned()
            .unwrap_or_else(|| "quic-like".to_owned());
        let noise = map.get("noise").cloned().unwrap_or_else(|| "ik".to_owned());
        let peer_pub = map.get("peer_pub").map(|h| hex_decode_32(h)).transpose()?;
        let tun_mtu = map
            .get("mtu")
            .map(|s| s.parse::<u16>().map_err(|_| err("invalid mtu")))
            .transpose()?
            .unwrap_or(1500);
        let path_mtu = map
            .get("path_mtu")
            .map(|s| s.parse::<u16>().map_err(|_| err("invalid path_mtu")))
            .transpose()?
            .unwrap_or(1500);
        let handshake_seconds = map
            .get("hs")
            .map(|s| s.parse::<u16>().map_err(|_| err("invalid hs")))
            .transpose()?
            .unwrap_or(30);
        let tun = map.get("tun").cloned().filter(|s| !s.is_empty());
        let routes = map
            .get("routes")
            .map(|s| {
                s.split(',')
                    .map(str::trim)
                    .filter(|v| !v.is_empty())
                    .map(str::to_owned)
                    .collect()
            })
            .unwrap_or_default();
        let dns = map
            .get("dns")
            .map(|s| {
                s.split(',')
                    .map(str::trim)
                    .filter(|v| !v.is_empty())
                    .map(str::to_owned)
                    .collect()
            })
            .unwrap_or_default();
        let tune_repair = map.get("tune_repair").cloned().filter(|s| !s.is_empty());
        let tune_device_mtu = map
            .get("tune_device_mtu")
            .cloned()
            .filter(|s| !s.is_empty());
        let tune_path_mtu = map.get("tune_path_mtu").cloned().filter(|s| !s.is_empty());
        let secrets = ShareSecrets {
            admission: map.get("adm").map(|h| hex_decode_32(h)).transpose()?,
            noise_private: map.get("key").map(|h| hex_decode_32(h)).transpose()?,
            member_pk8: map.get("member").map(|b| base64url_decode(b)).transpose()?,
            noise_psk: map.get("psk").map(|h| hex_decode_32(h)).transpose()?,
        };
        let parsed = Self {
            name,
            peer,
            cover,
            noise,
            peer_pub,
            tun_mtu,
            path_mtu,
            handshake_seconds,
            tun,
            routes,
            dns,
            tune_repair,
            tune_device_mtu,
            tune_path_mtu,
            secrets,
        };
        parsed.validate()?;
        Ok(parsed)
    }

    /// Build a client-ready [`ShareProfile`] from a desktop/daemon [`ProfileDocument`].
    ///
    /// - For a `connect` profile: copies `--udp-peer`, `--carrier`, `--noise-profile`,
    ///   MTUs, `--noise-peer-key-file` (public), and — ONLY if `include_secrets` is
    ///   `true` — reads `--session-admission-key-file`, `--noise-private-key-file`,
    ///   `--identity`, and `--noise-psk-file`.
    /// - For a `serve` profile: derives a client-onboarding URI using the server's
    ///   `--udp-bind` as `peer` and the server's own derived Noise public key as
    ///   `peer_pub` (plus `admission.key` ONLY if `include_secrets` is `true`).
    pub fn from_profile_document(
        name: Option<&str>,
        doc: &ProfileDocument,
        include_secrets: bool,
    ) -> Result<Self, ShareUriError> {
        let opt = |k: &str| doc.options.get(k).map(String::as_str);
        if let Some(layer) = opt("--layer")
            && !layer.eq_ignore_ascii_case("tun")
        {
            return Err(err(format!(
                "only TUN (L3) profiles can be shared via l2tunnel:// URIs (got --layer {layer})"
            )));
        }
        let cover = opt("--carrier").unwrap_or("quic-like").to_owned();
        if !matches!(cover.as_str(), "quic-like" | "media-like" | "tls-like") {
            return Err(err(format!(
                "share URIs currently support UDP covers (quic-like/media-like/tls-like), got {cover}"
            )));
        }
        let noise = opt("--noise-profile").unwrap_or("ik").to_owned();
        let tun_mtu = opt("--max-packet")
            .and_then(|s| s.parse::<u16>().ok())
            .unwrap_or(1500);
        let path_mtu = opt("--max-path-mtu")
            .and_then(|s| s.parse::<u16>().ok())
            .unwrap_or(1500);
        let handshake_seconds = opt("--handshake-timeout")
            .and_then(|s| s.parse::<u16>().ok())
            .unwrap_or(30);
        let tune_repair = opt("--tune-repair").map(str::to_owned);
        let tune_device_mtu = opt("--tune-device-mtu").map(str::to_owned);
        let tune_path_mtu = opt("--tune-path-mtu").map(str::to_owned);

        let (peer, peer_pub) = match doc.role {
            ProfileRole::Connect => {
                let peer = opt("--udp-peer")
                    .ok_or_else(|| err("profile is missing --udp-peer"))?
                    .to_owned();
                let peer_pub = opt("--noise-peer-key-file")
                    .map(|p| read_raw_32(Path::new(p)))
                    .transpose()?;
                (peer, peer_pub)
            }
            ProfileRole::Serve => {
                let bind =
                    opt("--udp-bind").ok_or_else(|| err("server profile is missing --udp-bind"))?;
                let parsed: SocketAddr = bind
                    .parse()
                    .map_err(|_| err("server --udp-bind must be a valid ip:port"))?;
                if parsed.ip().is_unspecified() {
                    return Err(err(
                        "server --udp-bind is wildcard (0.0.0.0); specify a concrete server IP before sharing",
                    ));
                }
                let srv_pub = opt("--noise-private-key-file")
                    .map(|p| {
                        let priv_bytes = read_raw_32(Path::new(p))?;
                        let pub_key = l2tunnel_handshake::LocalSecret::new(
                            zeroize::Zeroizing::new(priv_bytes),
                        )
                        .public_key()
                        .0;
                        Ok::<[u8; 32], ShareUriError>(pub_key)
                    })
                    .transpose()?;
                (bind.to_owned(), srv_pub)
            }
        };

        let mut secrets = ShareSecrets::default();
        if include_secrets {
            if let Some(adm_path) = opt("--session-admission-key-file") {
                secrets.admission = Some(read_raw_32(Path::new(adm_path))?);
            }
            if doc.role == ProfileRole::Connect {
                if let Some(priv_path) = opt("--noise-private-key-file") {
                    secrets.noise_private = Some(read_raw_32(Path::new(priv_path))?);
                }
                if let Some(id_path) = opt("--identity") {
                    let der = std::fs::read(id_path)
                        .map_err(|e| err(format!("cannot read {id_path}: {e}")))?;
                    secrets.member_pk8 = Some(der);
                }
            }
            if noise == "ikpsk2"
                && let Some(psk_path) = opt("--noise-psk-file")
            {
                secrets.noise_psk = Some(read_raw_32(Path::new(psk_path))?);
            }
        }

        let share = Self {
            name: name.map(str::to_owned),
            peer,
            cover,
            noise,
            peer_pub,
            tun_mtu,
            path_mtu,
            handshake_seconds,
            tun: None,
            routes: Vec::new(),
            dns: Vec::new(),
            tune_repair,
            tune_device_mtu,
            tune_path_mtu,
            secrets,
        };
        share.validate()?;
        Ok(share)
    }

    /// Convert an imported [`ShareProfile`] into a desktop/daemon [`ProfileDocument`],
    /// optionally writing embedded key material into `key_dir` (mode `0600` on Unix).
    pub fn to_profile_document(
        &self,
        key_dir: Option<&Path>,
    ) -> Result<ProfileDocument, ShareUriError> {
        self.validate()?;
        let mut options = BTreeMap::new();
        options.insert("--record-profile".into(), "common".into());
        options.insert("--carrier".into(), self.cover.clone());
        options.insert("--duplex".into(), "full".into());
        options.insert("--compression".into(), "off".into());
        options.insert("--layer".into(), "tun".into());
        options.insert("--udp-bind".into(), "0.0.0.0:0".into());
        options.insert("--udp-peer".into(), self.peer.clone());
        options.insert("--noise-profile".into(), self.noise.clone());
        options.insert("--max-packet".into(), self.tun_mtu.to_string());
        options.insert("--max-path-mtu".into(), self.path_mtu.to_string());
        if let Some(tr) = &self.tune_repair {
            options.insert("--tune-repair".into(), tr.clone());
        }
        if let Some(td) = &self.tune_device_mtu {
            options.insert("--tune-device-mtu".into(), td.clone());
        }
        if let Some(tp) = &self.tune_path_mtu {
            options.insert("--tune-path-mtu".into(), tp.clone());
        }
        if let Some(dir) = key_dir {
            std::fs::create_dir_all(dir)
                .map_err(|e| err(format!("cannot create {}: {e}", dir.display())))?;
            if let Some(peer_pub) = &self.peer_pub {
                let p = write_key_file(dir, "noise-peer.pub", peer_pub)?;
                options.insert("--noise-peer-key-file".into(), p.display().to_string());
            }
            if let Some(adm) = &self.secrets.admission {
                let p = write_key_file(dir, "admission.key", adm)?;
                options.insert(
                    "--session-admission-key-file".into(),
                    p.display().to_string(),
                );
            }
            if let Some(priv_key) = &self.secrets.noise_private {
                let p = write_key_file(dir, "noise-private.key", priv_key)?;
                options.insert("--noise-private-key-file".into(), p.display().to_string());
            }
            if let Some(member) = &self.secrets.member_pk8 {
                let p = write_key_file(dir, "member.pk8", member)?;
                options.insert("--identity".into(), p.display().to_string());
            }
            if let Some(psk) = &self.secrets.noise_psk {
                let p = write_key_file(dir, "noise-psk.key", psk)?;
                options.insert("--noise-psk-file".into(), p.display().to_string());
            }
        }
        Ok(ProfileDocument {
            version: PROFILE_VERSION,
            role: ProfileRole::Connect,
            options,
        })
    }
}

fn read_raw_32(path: &Path) -> Result<[u8; 32], ShareUriError> {
    let bytes =
        std::fs::read(path).map_err(|e| err(format!("cannot read {}: {e}", path.display())))?;
    bytes
        .try_into()
        .map_err(|_| err(format!("{} must be exactly 32 bytes", path.display())))
}

fn write_key_file(dir: &Path, name: &str, bytes: &[u8]) -> Result<PathBuf, ShareUriError> {
    let path = dir.join(name);
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut file = opts
        .open(&path)
        .map_err(|e| err(format!("cannot write {}: {e}", path.display())))?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|e: io::Error| err(format!("cannot write {}: {e}", path.display())))?;
    Ok(path)
}

fn validate_cidr(raw: &str) -> Result<(), ShareUriError> {
    let (ip_str, prefix_str) = raw
        .split_once('/')
        .ok_or_else(|| err(format!("invalid CIDR: {raw}")))?;
    let ip: IpAddr = ip_str
        .parse()
        .map_err(|_| err(format!("invalid CIDR IP: {raw}")))?;
    let prefix: u8 = prefix_str
        .parse()
        .map_err(|_| err(format!("invalid CIDR prefix: {raw}")))?;
    let max_prefix = match ip {
        IpAddr::V4(_) => 32,
        IpAddr::V6(_) => 128,
    };
    if prefix > max_prefix {
        return Err(err(format!("CIDR prefix out of range: {raw}")));
    }
    Ok(())
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write as _;
        let _ = write!(&mut out, "{b:02x}");
    }
    out
}

fn hex_decode_32(raw: &str) -> Result<[u8; 32], ShareUriError> {
    if raw.len() != 64 {
        return Err(err(format!("expected 64 hex chars, got {}", raw.len())));
    }
    let mut out = [0u8; 32];
    let bytes = raw.as_bytes();
    for i in 0..32 {
        let hi = hex_nibble(bytes[i * 2])?;
        let lo = hex_nibble(bytes[i * 2 + 1])?;
        out[i] = (hi << 4) | lo;
    }
    Ok(out)
}

fn hex_nibble(b: u8) -> Result<u8, ShareUriError> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => Err(err("invalid hex character")),
    }
}

fn percent_encode(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for b in input.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            out.push(b as char);
        } else {
            use std::fmt::Write as _;
            let _ = write!(&mut out, "%{b:02X}");
        }
    }
    out
}

fn percent_decode(input: &str) -> Result<String, ShareUriError> {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' => {
                if i + 2 >= bytes.len() {
                    return Err(err("truncated percent-encoding"));
                }
                let hi = hex_nibble(bytes[i + 1])?;
                let lo = hex_nibble(bytes[i + 2])?;
                out.push((hi << 4) | lo);
                i += 3;
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8(out).map_err(|_| err("invalid UTF-8 in share URI"))
}

const B64_TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

fn base64url_encode(input: &[u8]) -> String {
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    let mut i = 0;
    while i < input.len() {
        let b0 = input[i];
        let b1 = if i + 1 < input.len() { input[i + 1] } else { 0 };
        let b2 = if i + 2 < input.len() { input[i + 2] } else { 0 };
        let n = ((b0 as u32) << 16) | ((b1 as u32) << 8) | (b2 as u32);
        out.push(B64_TABLE[((n >> 18) & 63) as usize] as char);
        out.push(B64_TABLE[((n >> 12) & 63) as usize] as char);
        if i + 1 < input.len() {
            out.push(B64_TABLE[((n >> 6) & 63) as usize] as char);
        }
        if i + 2 < input.len() {
            out.push(B64_TABLE[(n & 63) as usize] as char);
        }
        i += 3;
    }
    out
}

fn base64url_val(b: u8) -> Result<u8, ShareUriError> {
    match b {
        b'A'..=b'Z' => Ok(b - b'A'),
        b'a'..=b'z' => Ok(b - b'a' + 26),
        b'0'..=b'9' => Ok(b - b'0' + 52),
        b'-' | b'+' => Ok(62),
        b'_' | b'/' => Ok(63),
        _ => Err(err("invalid base64url character")),
    }
}

fn base64url_decode(input: &str) -> Result<Vec<u8>, ShareUriError> {
    let stripped = input.trim_end_matches('=');
    let bytes = stripped.as_bytes();
    if bytes.len() % 4 == 1 {
        return Err(err("invalid base64url length"));
    }
    let mut out = Vec::with_capacity(bytes.len() * 3 / 4);
    let mut i = 0;
    while i < bytes.len() {
        let rem = bytes.len() - i;
        let v0 = base64url_val(bytes[i])? as u32;
        let v1 = base64url_val(bytes[i + 1])? as u32;
        out.push(((v0 << 2) | (v1 >> 4)) as u8);
        if rem >= 3 {
            let v2 = base64url_val(bytes[i + 2])? as u32;
            out.push((((v1 & 0x0F) << 4) | (v2 >> 2)) as u8);
            if rem >= 4 {
                let v3 = base64url_val(bytes[i + 3])? as u32;
                out.push((((v2 & 0x03) << 6) | v3) as u8);
            }
        }
        i += 4;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_public_and_full_share_uri_round_trip() -> Result<(), ShareUriError> {
        let public = ShareProfile {
            name: Some("office".into()),
            peer: "192.168.210.108:24461".into(),
            cover: "quic-like".into(),
            noise: "ik".into(),
            peer_pub: Some([0x11; 32]),
            tun_mtu: 1500,
            path_mtu: 1500,
            handshake_seconds: 30,
            tun: Some("10.236.0.2/30".into()),
            routes: vec!["0.0.0.0/0".into()],
            dns: vec!["1.1.1.1".into()],
            tune_repair: Some("off,1/8,1/4".into()),
            tune_device_mtu: None,
            tune_path_mtu: None,
            secrets: ShareSecrets::default(),
        };
        let uri = public.encode()?;
        // Exact canonical vector shared with Kotlin Android tests.
        assert_eq!(
            uri,
            "l2tunnel://v1/connect?name=office&peer=192.168.210.108%3A24461&cover=quic-like&noise=ik&peer_pub=1111111111111111111111111111111111111111111111111111111111111111&tun=10.236.0.2%2F30&routes=0.0.0.0%2F0&dns=1.1.1.1&tune_repair=off%2C1%2F8%2C1%2F4"
        );
        assert_eq!(ShareProfile::decode(&uri)?, public);

        let mut full = public;
        full.secrets = ShareSecrets {
            admission: Some([0x22; 32]),
            noise_private: Some([0x33; 32]),
            member_pk8: Some(vec![0x44; 48]),
            noise_psk: None,
        };
        let full_uri = full.encode()?;
        assert!(full_uri.contains("&adm=2222"));
        assert!(full_uri.contains("&key=3333"));
        assert!(full_uri.contains("&member="));
        assert_eq!(ShareProfile::decode(&full_uri)?, full);
        Ok(())
    }

    #[test]
    fn refuses_tap_oversize_duplicate_and_malformed_uris() {
        assert!(
            ShareProfile::decode("l2tunnel://v1/connect?peer=192.168.1.1%3A24461&layer=tap")
                .is_err()
        );
        assert!(
            ShareProfile::decode(
                "l2tunnel://v1/connect?peer=192.168.1.1%3A24461&peer=192.168.1.2%3A24461"
            )
            .is_err()
        );
        assert!(ShareProfile::decode("https://example.com/?peer=1.2.3.4:1").is_err());
        assert!(
            ShareProfile::decode("l2tunnel://v1/connect?peer=192.168.1.1%3A24461&peer_pub=abcd")
                .is_err()
        );
        assert!(
            ShareProfile::decode(&format!(
                "l2tunnel://v1/connect?peer=1.2.3.4:1&name={}",
                "a".repeat(MAX_SHARE_URI_BYTES)
            ))
            .is_err()
        );
    }

    #[test]
    fn server_profile_derives_client_public_share_uri() -> Result<(), Box<dyn std::error::Error>> {
        let dir = std::env::temp_dir().join(format!("l2t-share-srv-{}", std::process::id()));
        std::fs::create_dir_all(&dir)?;
        let srv_priv = dir.join("noise-srv.key");
        let srv_pub = dir.join("noise-srv.pub");
        let adm = dir.join("admission.key");
        let pub_hex = crate::local::keys::generate(&crate::local::keys::KeyGeneration::Noise {
            private: srv_priv.clone(),
            public: srv_pub.clone(),
        })?
        .ok_or("missing pub")?;
        crate::local::keys::generate(&crate::local::keys::KeyGeneration::Secret {
            output: adm.clone(),
        })?;

        let mut options = BTreeMap::new();
        options.insert("--carrier".into(), "quic-like".into());
        options.insert("--layer".into(), "tun".into());
        options.insert("--udp-bind".into(), "192.168.210.108:24461".into());
        options.insert("--noise-profile".into(), "ik".into());
        options.insert(
            "--noise-private-key-file".into(),
            srv_priv.display().to_string(),
        );
        options.insert(
            "--session-admission-key-file".into(),
            adm.display().to_string(),
        );
        let doc = ProfileDocument {
            version: PROFILE_VERSION,
            role: ProfileRole::Serve,
            options,
        };
        let public_only = ShareProfile::from_profile_document(Some("srv"), &doc, false)?;
        assert!(public_only.secrets.is_empty());
        assert_eq!(public_only.peer_pub.map(|k| hex_encode(&k)), Some(pub_hex));
        let with_adm = ShareProfile::from_profile_document(Some("srv"), &doc, true)?;
        assert!(with_adm.secrets.admission.is_some());
        assert!(with_adm.secrets.noise_private.is_none());
        std::fs::remove_dir_all(&dir)?;
        Ok(())
    }
}
