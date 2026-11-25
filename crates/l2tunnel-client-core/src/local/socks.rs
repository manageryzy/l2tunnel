//! Version-5 SOCKS5 entry settings, status and active flow DTOs
//! (`docs/modules/desktop-gui.md`, `DGUI-08`).
//!
//! SOCKS5 rides the explicit TCP-proxy profile on the client service: listening
//! defaults to loopback only (`127.0.0.1:1080`), and a wider listen address
//! requires an explicit allowed-client CIDR list.
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

/// Most allowed-client CIDR entries accepted in one settings update.
pub const SOCKS_ALLOWED_LIMIT: usize = 32;
/// Most flows returned by `socks_flows`.
pub const SOCKS_FLOW_LIMIT: usize = 64;
/// Upper bound on concurrent SOCKS5 flows.
pub const SOCKS_MAX_FLOWS_LIMIT: u16 = 512;
/// Default concurrent SOCKS5 flow limit.
pub const SOCKS_DEFAULT_MAX_FLOWS: u16 = 128;
/// Default SOCKS5 listen host (loopback only).
pub const SOCKS_DEFAULT_HOST: &str = "127.0.0.1";
/// Default SOCKS5 listen port.
pub const SOCKS_DEFAULT_PORT: u16 = 1080;
/// Maximum username length (RFC 1929 allows 1..=255; kept bounded at 64).
pub const SOCKS_USERNAME_LIMIT: usize = 64;
/// Maximum password length (RFC 1929 allows 1..=255; kept bounded at 128).
pub const SOCKS_PASSWORD_LIMIT: usize = 128;

/// Client authentication method advertised by the local SOCKS5 listener.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SocksAuthMode {
    /// RFC 1928 method `0x00` (no authentication).
    #[default]
    None,
    /// RFC 1929 method `0x02` (username/password).
    UserPass,
}

/// Validated IP/prefix CIDR used to filter incoming SOCKS5 client addresses.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SocksCidr {
    /// Network address.
    pub network: IpAddr,
    /// Prefix length (`0..=32` for IPv4, `0..=128` for IPv6).
    pub prefix: u8,
}

impl SocksCidr {
    /// Parse a strict `IP/PREFIX` string (no whitespace, bounded length).
    pub fn parse(text: &str) -> Result<Self, String> {
        if text.is_empty() || text.len() > 49 || text.bytes().any(|b| b.is_ascii_whitespace()) {
            return Err(format!("invalid CIDR {text:?}"));
        }
        let Some((addr_text, bits_text)) = text.split_once('/') else {
            return Err(format!("CIDR {text:?} must be IP/PREFIX"));
        };
        if bits_text.is_empty() || !bits_text.bytes().all(|b| b.is_ascii_digit()) {
            return Err(format!("invalid CIDR prefix in {text:?}"));
        }
        let address: IpAddr = addr_text
            .parse()
            .map_err(|_| format!("invalid IP address in CIDR {text:?}"))?;
        let prefix: u8 = bits_text
            .parse()
            .map_err(|_| format!("invalid prefix length in CIDR {text:?}"))?;
        let max_bits = match address {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };
        if prefix > max_bits {
            return Err(format!("prefix /{prefix} exceeds /{max_bits} in {text:?}"));
        }
        Ok(Self {
            network: address,
            prefix,
        })
    }

    /// Whether `ip` falls within this CIDR prefix.
    pub fn contains(self, ip: IpAddr) -> bool {
        match (self.network, ip) {
            (IpAddr::V4(net), IpAddr::V4(addr)) => {
                if self.prefix == 0 {
                    true
                } else {
                    let mask = u32::MAX
                        .checked_shl(32 - u32::from(self.prefix))
                        .unwrap_or(0);
                    (u32::from(net) & mask) == (u32::from(addr) & mask)
                }
            }
            (IpAddr::V6(net), IpAddr::V6(addr)) => {
                if self.prefix == 0 {
                    true
                } else {
                    let mask = u128::MAX
                        .checked_shl(128 - u32::from(self.prefix))
                        .unwrap_or(0);
                    (u128::from(net) & mask) == (u128::from(addr) & mask)
                }
            }
            // Handle IPv4-mapped IPv6 clients cleanly when matching IPv4 CIDRs.
            (IpAddr::V4(_), IpAddr::V6(addr)) => addr
                .to_ipv4_mapped()
                .is_some_and(|v4| Self::contains(self, IpAddr::V4(v4))),
            (IpAddr::V6(_), IpAddr::V4(_)) => false,
        }
    }
}

/// Configurable settings for the service-owned SOCKS5 listener.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SocksSettings {
    /// Whether the SOCKS5 listener should run while a client TCP-proxy session is active.
    pub enabled: bool,
    /// Bind IP address (defaults to `127.0.0.1`).
    pub listen_host: String,
    /// Bind TCP port (`1..=65535`, or `0` for OS-assigned port in tests when explicitly allowed).
    pub listen_port: u16,
    /// Client authentication mode.
    #[serde(default)]
    pub auth_mode: SocksAuthMode,
    /// Username required when `auth_mode` is `user_pass`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    /// Write-only password supplied on `socks_set`; never returned by `socks_get`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    /// Read-only indicator returned by `socks_get` showing whether a password is stored.
    #[serde(default)]
    pub password_set: bool,
    /// Allowed client IP/prefix CIDRs (e.g. `127.0.0.1/32`). Required for non-loopback binds.
    #[serde(default)]
    pub allowed_clients: Vec<String>,
    /// Maximum simultaneous SOCKS5 flows (`1..=512`).
    #[serde(default = "default_max_flows")]
    pub max_flows: u16,
}

const fn default_max_flows() -> u16 {
    SOCKS_DEFAULT_MAX_FLOWS
}

impl Default for SocksSettings {
    fn default() -> Self {
        Self {
            enabled: false,
            listen_host: SOCKS_DEFAULT_HOST.into(),
            listen_port: SOCKS_DEFAULT_PORT,
            auth_mode: SocksAuthMode::None,
            username: None,
            password: None,
            password_set: false,
            allowed_clients: vec!["127.0.0.1/32".into()],
            max_flows: SOCKS_DEFAULT_MAX_FLOWS,
        }
    }
}

impl SocksSettings {
    /// Parse and validate all settings fields and security bounds.
    ///
    /// When `allow_ephemeral_port` is false (normal CLI/GUI use), port `0` is rejected.
    pub fn validate(
        &self,
        has_existing_password: bool,
        allow_ephemeral_port: bool,
    ) -> Result<(SocketAddr, Vec<SocksCidr>), String> {
        let host: IpAddr = self
            .listen_host
            .trim()
            .parse()
            .map_err(|_| "listen_host must be a literal IPv4 or IPv6 address".to_owned())?;
        if self.listen_port == 0 && !allow_ephemeral_port {
            return Err("listen_port must be 1..=65535".into());
        }
        if !(1..=SOCKS_MAX_FLOWS_LIMIT).contains(&self.max_flows) {
            return Err(format!("max_flows must be 1..={SOCKS_MAX_FLOWS_LIMIT}"));
        }
        if self.allowed_clients.len() > SOCKS_ALLOWED_LIMIT {
            return Err(format!(
                "allowed_clients exceeds limit ({SOCKS_ALLOWED_LIMIT})"
            ));
        }
        let mut cidrs = Vec::with_capacity(self.allowed_clients.len());
        for entry in &self.allowed_clients {
            cidrs.push(SocksCidr::parse(entry)?);
        }
        // Security invariant: listening outside loopback requires an explicit allowlist.
        if !host.is_loopback() && cidrs.is_empty() {
            return Err(
                "listening outside loopback requires at least one allowed_clients CIDR".into(),
            );
        }
        if cidrs.is_empty() {
            // Loopback default when list is omitted: allow the matching loopback host.
            let loopback = match host {
                IpAddr::V4(_) => SocksCidr {
                    network: IpAddr::V4(Ipv4Addr::LOCALHOST),
                    prefix: 32,
                },
                IpAddr::V6(_) => SocksCidr {
                    network: IpAddr::V6(Ipv6Addr::LOCALHOST),
                    prefix: 128,
                },
            };
            cidrs.push(loopback);
        }
        match self.auth_mode {
            SocksAuthMode::None => {}
            SocksAuthMode::UserPass => {
                let user = self.username.as_deref().unwrap_or("");
                if user.is_empty()
                    || user.len() > SOCKS_USERNAME_LIMIT
                    || user.bytes().any(|b| b.is_ascii_control())
                {
                    return Err(format!(
                        "username must be 1..={SOCKS_USERNAME_LIMIT} non-control bytes"
                    ));
                }
                match self.password.as_deref() {
                    Some(pw) if pw.is_empty() || pw.len() > SOCKS_PASSWORD_LIMIT => {
                        return Err(format!("password must be 1..={SOCKS_PASSWORD_LIMIT} bytes"));
                    }
                    Some(_) => {}
                    None if has_existing_password => {}
                    None => {
                        return Err(
                            "password is required when enabling username/password authentication"
                                .into(),
                        );
                    }
                }
            }
        }
        Ok((SocketAddr::new(host, self.listen_port), cidrs))
    }

    /// Return a copy safe to expose in `socks_get` (never includes plaintext password).
    pub fn redacted(&self, password_set: bool) -> Self {
        Self {
            password: None,
            password_set,
            ..self.clone()
        }
    }
}

/// Live SOCKS5 listener status returned by `socks_get` and `socks_set`.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SocksStatus {
    /// Whether the active session is a client TCP-proxy profile capable of SOCKS5.
    pub proxy_active: bool,
    /// Actual bound listener address while listening, absent when stopped.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub listening: Option<String>,
    /// Current settings (with `password` always omitted).
    pub settings: SocksSettings,
    /// Currently open or connecting SOCKS5 flows.
    pub active_flows: u32,
    /// Lifetime flows accepted since this service started.
    pub total_flows: u64,
    /// Connections refused because the client IP did not match `allowed_clients`.
    pub rejected_clients: u64,
    /// CONNECT requests refused or failed on the upstream path.
    pub failed_connects: u64,
    /// Last bounded bind or listener error, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
}

/// One active or recently ended SOCKS5 flow (inner flow, distinct from lanes and channels).
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SocksFlow {
    /// Service-local flow identifier.
    pub id: u64,
    /// Local SOCKS5 client endpoint (e.g. `127.0.0.1:53122`).
    pub client: String,
    /// Requested upstream target (`host:port`).
    pub target: String,
    /// Bytes forwarded from client to upstream target.
    pub sent_bytes: u64,
    /// Bytes forwarded from upstream target to client.
    pub received_bytes: u64,
    /// `connecting`, `open`, `refused`, `closed` or `failed`.
    pub state: String,
    /// Milliseconds since the flow was opened.
    pub age_ms: u64,
    /// Bounded error or refusal reason when `state` is `refused` or `failed`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Bounded flow table returned by `socks_flows`.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SocksFlows {
    /// Active flows first, followed by recently closed/refused flows (bounded).
    pub flows: Vec<SocksFlow>,
    /// Total currently active flows.
    pub total_active: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn settings_enforce_loopback_allowlist_and_auth_rules() {
        let defaults = SocksSettings::default();
        assert!(defaults.validate(false, false).is_ok());

        let wide_empty = SocksSettings {
            listen_host: "0.0.0.0".into(),
            allowed_clients: Vec::new(),
            ..SocksSettings::default()
        };
        assert!(wide_empty.validate(false, false).is_err());

        let wide_allowed = SocksSettings {
            listen_host: "0.0.0.0".into(),
            allowed_clients: vec!["192.168.1.0/24".into()],
            ..SocksSettings::default()
        };
        let (addr, cidrs) = wide_allowed
            .validate(false, false)
            .unwrap_or_else(|_| (SocketAddr::from(([0, 0, 0, 0], 1)), Vec::new()));
        assert_eq!(addr.port(), 1080);
        assert!(cidrs[0].contains(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 42))));
        assert!(!cidrs[0].contains(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));

        let userpass_no_pw = SocksSettings {
            auth_mode: SocksAuthMode::UserPass,
            username: Some("alice".into()),
            password: None,
            ..SocksSettings::default()
        };
        assert!(userpass_no_pw.validate(false, false).is_err());
        assert!(userpass_no_pw.validate(true, false).is_ok());

        let redacted = SocksSettings {
            password: Some("secret".into()),
            ..SocksSettings::default()
        }
        .redacted(true);
        assert!(redacted.password.is_none());
        assert!(redacted.password_set);
    }

    #[test]
    fn cidr_parses_ipv4_and_ipv6_and_rejects_bad_inputs() {
        let v6 = SocksCidr::parse("::1/128");
        assert!(v6.is_ok_and(|cidr| cidr.contains(IpAddr::V6(Ipv6Addr::LOCALHOST))));
        assert!(SocksCidr::parse("127.0.0.1").is_err());
        assert!(SocksCidr::parse("127.0.0.1/33").is_err());
        assert!(SocksCidr::parse("::1/129").is_err());
        assert!(SocksCidr::parse("not-an-ip/24").is_err());
    }
}
