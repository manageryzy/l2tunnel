//! Detailed IP redirect / traffic-routing policy supporting CIDR, ASN,
//! IP location (GeoIP country/region), continent, and Private/LAN rules,
//! plus offline prefix database lookup (built-in baseline, CSV/JSON prefix
//! lists, and bounded zero-unsafe MaxMind MMDB v2 decoding) and exact CIDR
//! subtraction route compilation for Linux TUN and Android VpnService.
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Policy document schema version.
pub const REDIRECT_POLICY_VERSION: u16 = 1;
/// Maximum number of ordered rules in one redirect policy.
pub const MAX_REDIRECT_RULES: usize = 256;
/// Maximum entries loaded into one in-memory GeoIP/ASN database.
pub const MAX_GEO_ASN_ENTRIES: usize = 250_000;
/// Maximum MMDB input size accepted in memory (64 MiB).
pub const MAX_MMDB_BYTES: usize = 64 * 1024 * 1024;

/// Action taken when a destination IP matches a redirect rule.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RedirectAction {
    /// Redirect matching traffic through the l2tunnel TUN/proxy interface.
    #[default]
    Tunnel,
    /// Bypass the tunnel and route directly over the physical host interface.
    Direct,
    /// Drop / refuse traffic to matching destinations.
    Reject,
}

impl fmt::Display for RedirectAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Tunnel => "tunnel",
            Self::Direct => "direct",
            Self::Reject => "reject",
        })
    }
}

/// Validated canonical IPv4 or IPv6 CIDR prefix.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct IpCidr {
    /// Canonical network address (host bits masked to zero).
    pub network: IpAddr,
    /// Prefix length (`0..=32` for IPv4, `0..=128` for IPv6).
    pub prefix: u8,
}

impl IpCidr {
    /// Parse a strict `IP/PREFIX` string and mask host bits to canonical form.
    pub fn parse(text: &str) -> Result<Self, String> {
        let trimmed = text.trim();
        let (addr_s, pref_s) = trimmed
            .split_once('/')
            .ok_or_else(|| format!("invalid CIDR {trimmed:?}: expected IP/PREFIX"))?;
        let addr: IpAddr = addr_s
            .parse()
            .map_err(|_| format!("invalid IP in CIDR {trimmed:?}"))?;
        let prefix: u8 = pref_s
            .parse()
            .map_err(|_| format!("invalid prefix length in CIDR {trimmed:?}"))?;
        Self::new(addr, prefix)
    }

    /// Construct a canonical masked CIDR prefix.
    pub fn new(addr: IpAddr, prefix: u8) -> Result<Self, String> {
        match addr {
            IpAddr::V4(v4) => {
                if prefix > 32 {
                    return Err(format!("IPv4 prefix /{prefix} exceeds /32"));
                }
                let mask = v4_mask(prefix);
                Ok(Self {
                    network: IpAddr::V4(Ipv4Addr::from(u32::from(v4) & mask)),
                    prefix,
                })
            }
            IpAddr::V6(v6) => {
                if prefix > 128 {
                    return Err(format!("IPv6 prefix /{prefix} exceeds /128"));
                }
                let mask = v6_mask(prefix);
                Ok(Self {
                    network: IpAddr::V6(Ipv6Addr::from(u128::from(v6) & mask)),
                    prefix,
                })
            }
        }
    }

    /// Single-host `/32` or `/128` prefix.
    pub fn host(addr: IpAddr) -> Self {
        match addr {
            IpAddr::V4(_) => Self {
                network: addr,
                prefix: 32,
            },
            IpAddr::V6(_) => Self {
                network: addr,
                prefix: 128,
            },
        }
    }

    /// Whether `ip` lies inside this prefix.
    pub fn contains(self, ip: IpAddr) -> bool {
        match (self.network, ip) {
            (IpAddr::V4(net), IpAddr::V4(addr)) => {
                let mask = v4_mask(self.prefix);
                (u32::from(addr) & mask) == u32::from(net)
            }
            (IpAddr::V6(net), IpAddr::V6(addr)) => {
                let mask = v6_mask(self.prefix);
                (u128::from(addr) & mask) == u128::from(net)
            }
            (IpAddr::V4(_), IpAddr::V6(addr)) => addr
                .to_ipv4_mapped()
                .is_some_and(|v4| self.contains(IpAddr::V4(v4))),
            (IpAddr::V6(_), IpAddr::V4(_)) => false,
        }
    }

    /// Inclusive IPv4 `[start, end]` range if this is an IPv4 prefix.
    pub fn v4_range(self) -> Option<(u32, u32)> {
        let IpAddr::V4(net) = self.network else {
            return None;
        };
        let start = u32::from(net);
        let mask = v4_mask(self.prefix);
        let end = start | !mask;
        Some((start, end))
    }

    /// Inclusive IPv6 `[start, end]` range if this is an IPv6 prefix.
    pub fn v6_range(self) -> Option<(u128, u128)> {
        let IpAddr::V6(net) = self.network else {
            return None;
        };
        let start = u128::from(net);
        let mask = v6_mask(self.prefix);
        let end = start | !mask;
        Some((start, end))
    }
}

impl fmt::Display for IpCidr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.network, self.prefix)
    }
}

fn v4_mask(prefix: u8) -> u32 {
    if prefix == 0 {
        0
    } else {
        u32::MAX.checked_shl(32 - u32::from(prefix)).unwrap_or(0)
    }
}

fn v6_mask(prefix: u8) -> u128 {
    if prefix == 0 {
        0
    } else {
        u128::MAX.checked_shl(128 - u32::from(prefix)).unwrap_or(0)
    }
}

/// Match criterion of one ordered redirect rule.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum RuleMatcher {
    /// Explicit IPv4 or IPv6 CIDR prefix (e.g. `10.0.0.0/8`).
    Cidr {
        /// Prefix as `IP/LENGTH`.
        cidr: String,
    },
    /// Autonomous System Number (e.g. `13335` for Cloudflare, `4134` for ChinaNet).
    Asn {
        /// 32-bit ASN value (without the `AS` prefix).
        asn: u32,
    },
    /// IP geolocation country (ISO-3166-1 alpha-2) and optional subdivision/region code.
    GeoIp {
        /// Two-letter uppercase ISO country code (e.g. `CN`, `US`, `JP`, `DE`).
        country: String,
        /// Optional region / subdivision / city tag (e.g. `CA`, `BJ`, `HK`).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        region: Option<String>,
    },
    /// IP geolocation continent code (`AF`, `AN`, `AS`, `EU`, `NA`, `OC`, `SA`).
    Continent {
        /// Two-letter continent code.
        continent: String,
    },
    /// RFC1918, RFC6598 CGNAT, loopback, link-local, ULA, and multicast ranges.
    PrivateLan,
    /// Catch-all fallback matcher.
    Default,
}

impl RuleMatcher {
    /// Validate syntax and ranges.
    pub fn validate(&self) -> Result<(), String> {
        match self {
            Self::Cidr { cidr } => {
                IpCidr::parse(cidr)?;
                Ok(())
            }
            Self::Asn { asn } => {
                if *asn == 0 {
                    return Err("ASN must be >= 1".to_owned());
                }
                Ok(())
            }
            Self::GeoIp { country, region } => {
                let cc = country.trim();
                if cc.len() != 2 || !cc.bytes().all(|b| b.is_ascii_alphabetic()) {
                    return Err(format!(
                        "GeoIP country {country:?} must be a 2-letter ISO code (e.g. CN, US, JP)"
                    ));
                }
                if let Some(reg) = region {
                    let r = reg.trim();
                    if r.is_empty()
                        || r.len() > 24
                        || !r
                            .bytes()
                            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
                    {
                        return Err(format!("invalid GeoIP region tag {reg:?}"));
                    }
                }
                Ok(())
            }
            Self::Continent { continent } => {
                let c = continent.trim().to_ascii_uppercase();
                if !matches!(c.as_str(), "AF" | "AN" | "AS" | "EU" | "NA" | "OC" | "SA") {
                    return Err(format!(
                        "unsupported continent code {continent:?} (expected AF, AN, AS, EU, NA, OC, SA)"
                    ));
                }
                Ok(())
            }
            Self::PrivateLan | Self::Default => Ok(()),
        }
    }

    /// Compact human summary (e.g. `ASN:AS13335`, `GEOIP:CN`, `GEOIP:US-CA`, `CIDR:10.0.0.0/8`).
    pub fn label(&self) -> String {
        match self {
            Self::Cidr { cidr } => format!("CIDR:{cidr}"),
            Self::Asn { asn } => format!("ASN:AS{asn}"),
            Self::GeoIp {
                country,
                region: Some(region),
            } => format!(
                "GEOIP:{}-{}",
                country.to_ascii_uppercase(),
                region.to_ascii_uppercase()
            ),
            Self::GeoIp {
                country,
                region: None,
            } => format!("GEOIP:{}", country.to_ascii_uppercase()),
            Self::Continent { continent } => {
                format!("CONTINENT:{}", continent.to_ascii_uppercase())
            }
            Self::PrivateLan => "PRIVATE/LAN".to_owned(),
            Self::Default => "DEFAULT".to_owned(),
        }
    }

    /// Parse shorthand CLI syntax (`cidr:10.0.0.0/8`, `asn:13335`, `as13335`,
    /// `geoip:CN`, `geoip:US-CA`, `continent:EU`, `lan`, `default`).
    pub fn parse_shorthand(text: &str) -> Result<Self, String> {
        let trimmed = text.trim();
        let lower = trimmed.to_ascii_lowercase();
        if matches!(lower.as_str(), "lan" | "private" | "private_lan") {
            return Ok(Self::PrivateLan);
        }
        if matches!(lower.as_str(), "default" | "any" | "*") {
            return Ok(Self::Default);
        }
        if let Some(rest) = lower.strip_prefix("cidr:") {
            let cidr = IpCidr::parse(rest)?.to_string();
            return Ok(Self::Cidr { cidr });
        }
        if let Some(rest) = lower.strip_prefix("asn:") {
            let num_s = rest.trim().trim_start_matches("as");
            let asn: u32 = num_s
                .parse()
                .map_err(|_| format!("invalid ASN in {trimmed:?}"))?;
            let m = Self::Asn { asn };
            m.validate()?;
            return Ok(m);
        }
        if let Some(rest) = lower.strip_prefix("as")
            && !rest.is_empty()
            && rest.bytes().all(|b| b.is_ascii_digit())
        {
            let asn: u32 = rest
                .parse()
                .map_err(|_| format!("invalid ASN in {trimmed:?}"))?;
            let m = Self::Asn { asn };
            m.validate()?;
            return Ok(m);
        }
        if let Some(rest) = lower
            .strip_prefix("geoip:")
            .or_else(|| lower.strip_prefix("country:"))
        {
            let upper = rest.trim().to_ascii_uppercase();
            let (country, region) = match upper.split_once('-') {
                Some((c, r)) => (c.to_owned(), Some(r.to_owned())),
                None => (upper, None),
            };
            let m = Self::GeoIp { country, region };
            m.validate()?;
            return Ok(m);
        }
        if let Some(rest) = lower.strip_prefix("continent:") {
            let m = Self::Continent {
                continent: rest.trim().to_ascii_uppercase(),
            };
            m.validate()?;
            return Ok(m);
        }
        if trimmed.contains('/') {
            let cidr = IpCidr::parse(trimmed)?.to_string();
            return Ok(Self::Cidr { cidr });
        }
        Err(format!(
            "unrecognized rule matcher {trimmed:?} (use cidr:IP/LEN, asn:N, geoip:CC[-REG], continent:CODE, lan, or default)"
        ))
    }
}

/// One ordered rule in a redirect policy (first matching enabled rule wins).
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RedirectRule {
    /// Stable rule identifier (e.g. `bypass-lan`, `asn-cloudflare`).
    pub id: String,
    /// Whether this rule participates in evaluation and route compilation.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Match condition (CIDR, ASN, GeoIP country/region, Continent, PrivateLan, Default).
    pub matcher: RuleMatcher,
    /// Action taken on match (`tunnel`, `direct`, `reject`).
    pub action: RedirectAction,
    /// Optional operator note.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
}

const fn default_true() -> bool {
    true
}

impl RedirectRule {
    /// Validate rule ID and matcher.
    pub fn validate(&self) -> Result<(), String> {
        let id = self.id.trim();
        if id.is_empty() || id.len() > 64 {
            return Err("rule id must be 1..=64 characters".to_owned());
        }
        self.matcher.validate()
    }
}

/// Complete ordered redirect / split-routing policy.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RedirectPolicy {
    /// Schema version (must be `1`).
    #[serde(default = "default_version")]
    pub version: u16,
    /// Fallback action when no enabled rule matches.
    #[serde(default)]
    pub default_action: RedirectAction,
    /// Always exclude the outer tunnel peer IP from TUN routes to prevent loops.
    #[serde(default = "default_true")]
    pub bypass_peer_endpoint: bool,
    /// Ordered rule list (first match wins).
    #[serde(default)]
    pub rules: Vec<RedirectRule>,
}

const fn default_version() -> u16 {
    REDIRECT_POLICY_VERSION
}

impl Default for RedirectPolicy {
    fn default() -> Self {
        Self::preset("global-bypass-lan").unwrap_or(Self {
            version: REDIRECT_POLICY_VERSION,
            default_action: RedirectAction::Tunnel,
            bypass_peer_endpoint: true,
            rules: Vec::new(),
        })
    }
}

/// Metadata resolved for an IP address from [`IpGeoAsnDatabase`].
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct IpGeoAsnInfo {
    /// Matched CIDR prefix in the database.
    pub matched_prefix: String,
    /// ISO-3166-1 alpha-2 country code (e.g. `CN`, `US`, `JP`) or `ZZ` for private/unknown.
    pub country: String,
    /// Optional region/subdivision code (e.g. `CA`, `BJ`, `TYO`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,
    /// Two-letter continent code (`AS`, `EU`, `NA`, `OC`, `SA`, `AF`, `ZZ`).
    pub continent: String,
    /// Autonomous System Number (`0` if unattributed/private).
    pub asn: u32,
    /// Autonomous System organization name.
    pub org: String,
}

/// Outcome of evaluating a destination IP against a [`RedirectPolicy`].
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PolicyDecision {
    /// Evaluated destination IP.
    pub ip: String,
    /// Final action (`tunnel`, `direct`, `reject`).
    pub action: RedirectAction,
    /// ID of the first matching rule, or `"default_action"` if none matched.
    pub matched_rule_id: String,
    /// Human-readable description of the matched criterion.
    pub matched_by: String,
    /// Resolved IP geolocation & ASN metadata, if found in the database.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub geo: Option<IpGeoAsnInfo>,
}

/// Exact minimal TUN routes compiled from a [`RedirectPolicy`] + [`IpGeoAsnDatabase`].
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CompiledRoutes {
    /// Minimal non-overlapping IPv4 prefixes to route into the tunnel device.
    pub include_v4: Vec<String>,
    /// IPv4 prefixes explicitly bypassed (`direct`) or excluded (including peer IP).
    pub exclude_v4: Vec<String>,
    /// Minimal non-overlapping IPv6 prefixes to route into the tunnel device.
    pub include_v6: Vec<String>,
    /// IPv6 prefixes explicitly bypassed (`direct`) or excluded (including peer IP).
    pub exclude_v6: Vec<String>,
    /// Prefixes assigned the `reject` action.
    pub reject_cidrs: Vec<String>,
    /// Number of active policy rules evaluated during compilation.
    pub active_rules: usize,
    /// Number of database prefixes expanded for ASN/GeoIP/Continent rules.
    pub expanded_prefixes: usize,
}

/// One prefix record inside [`IpGeoAsnDatabase`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GeoAsnRecord {
    /// Canonical CIDR prefix.
    pub cidr: IpCidr,
    /// Two-letter uppercase country code (`ZZ` if unknown/private).
    pub country: String,
    /// Optional subdivision/region code.
    pub region: Option<String>,
    /// Two-letter uppercase continent code (`ZZ` if unknown/private).
    pub continent: String,
    /// ASN (`0` if private/unknown).
    pub asn: u32,
    /// Organization / network description.
    pub org: String,
}

/// Offline in-memory GeoIP + ASN prefix database with longest-prefix-match lookup.
#[derive(Clone, Debug, Default)]
pub struct IpGeoAsnDatabase {
    records: Vec<GeoAsnRecord>,
}

impl IpGeoAsnDatabase {
    /// Create an empty database.
    pub fn empty() -> Self {
        Self {
            records: Vec::new(),
        }
    }

    /// Number of prefix records stored.
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// Whether the database has zero records.
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// Built-in offline baseline GeoIP + ASN database covering RFC1918/LAN and major
    /// global cloud/CDN/telecom networks (CN, US, JP, HK, TW, KR, SG, DE, GB, FR, AU, etc.).
    /// Operators may layer or replace this with full CSV or MaxMind `.mmdb` databases.
    pub fn builtin() -> Self {
        type SeedRow<'a> = (&'a str, &'a str, Option<&'a str>, &'a str, u32, &'a str);
        let mut db = Self::empty();
        // Format: (cidr, country, region, continent, asn, org)
        let seed: &[SeedRow<'_>] = &[
            // RFC1918 / RFC6598 / Local
            ("10.0.0.0/8", "ZZ", None, "ZZ", 0, "Private-LAN RFC1918"),
            ("100.64.0.0/10", "ZZ", None, "ZZ", 0, "Shared-CGNAT RFC6598"),
            ("127.0.0.0/8", "ZZ", None, "ZZ", 0, "Loopback"),
            ("169.254.0.0/16", "ZZ", None, "ZZ", 0, "Link-Local"),
            ("172.16.0.0/12", "ZZ", None, "ZZ", 0, "Private-LAN RFC1918"),
            ("192.168.0.0/16", "ZZ", None, "ZZ", 0, "Private-LAN RFC1918"),
            ("::1/128", "ZZ", None, "ZZ", 0, "IPv6 Loopback"),
            ("fc00::/7", "ZZ", None, "ZZ", 0, "IPv6 Unique Local"),
            ("fe80::/10", "ZZ", None, "ZZ", 0, "IPv6 Link-Local"),
            // Cloudflare (AS13335)
            (
                "1.1.1.0/24",
                "AU",
                Some("SYD"),
                "OC",
                13335,
                "Cloudflare Inc.",
            ),
            (
                "1.0.0.0/24",
                "AU",
                Some("SYD"),
                "OC",
                13335,
                "Cloudflare Inc.",
            ),
            (
                "104.16.0.0/13",
                "US",
                Some("CA"),
                "NA",
                13335,
                "Cloudflare Inc.",
            ),
            (
                "104.24.0.0/14",
                "US",
                Some("CA"),
                "NA",
                13335,
                "Cloudflare Inc.",
            ),
            (
                "172.64.0.0/13",
                "US",
                Some("CA"),
                "NA",
                13335,
                "Cloudflare Inc.",
            ),
            (
                "2606:4700::/32",
                "US",
                Some("CA"),
                "NA",
                13335,
                "Cloudflare Inc.",
            ),
            // Google (AS15169)
            ("8.8.8.0/24", "US", Some("CA"), "NA", 15169, "Google LLC"),
            ("8.8.4.0/24", "US", Some("CA"), "NA", 15169, "Google LLC"),
            (
                "142.250.0.0/15",
                "US",
                Some("CA"),
                "NA",
                15169,
                "Google LLC",
            ),
            (
                "172.217.0.0/16",
                "US",
                Some("CA"),
                "NA",
                15169,
                "Google LLC",
            ),
            (
                "216.58.192.0/19",
                "US",
                Some("CA"),
                "NA",
                15169,
                "Google LLC",
            ),
            (
                "2001:4860::/32",
                "US",
                Some("CA"),
                "NA",
                15169,
                "Google LLC",
            ),
            // Amazon AWS (AS16509)
            (
                "3.0.0.0/9",
                "US",
                Some("VA"),
                "NA",
                16509,
                "Amazon.com Inc.",
            ),
            (
                "13.32.0.0/15",
                "US",
                Some("WA"),
                "NA",
                16509,
                "Amazon CloudFront",
            ),
            (
                "52.0.0.0/11",
                "US",
                Some("VA"),
                "NA",
                16509,
                "Amazon.com Inc.",
            ),
            (
                "54.144.0.0/12",
                "US",
                Some("VA"),
                "NA",
                16509,
                "Amazon.com Inc.",
            ),
            // Microsoft (AS8075)
            (
                "13.64.0.0/11",
                "US",
                Some("WA"),
                "NA",
                8075,
                "Microsoft Corporation",
            ),
            (
                "20.0.0.0/11",
                "US",
                Some("WA"),
                "NA",
                8075,
                "Microsoft Azure",
            ),
            (
                "40.64.0.0/10",
                "US",
                Some("WA"),
                "NA",
                8075,
                "Microsoft Corporation",
            ),
            // Meta (AS32934)
            (
                "31.13.24.0/21",
                "US",
                Some("CA"),
                "NA",
                32934,
                "Meta Platforms Inc.",
            ),
            (
                "157.240.0.0/16",
                "US",
                Some("CA"),
                "NA",
                32934,
                "Meta Platforms Inc.",
            ),
            // Fastly (AS54113) & GitHub/Microsoft
            (
                "151.101.0.0/16",
                "US",
                Some("CA"),
                "NA",
                54113,
                "Fastly Inc.",
            ),
            (
                "140.82.112.0/20",
                "US",
                Some("CA"),
                "NA",
                36459,
                "GitHub Inc.",
            ),
            // China Telecom ChinaNet (AS4134)
            (
                "114.114.114.0/24",
                "CN",
                Some("JS"),
                "AS",
                4134,
                "ChinaNet Backbone",
            ),
            (
                "61.128.0.0/10",
                "CN",
                Some("BJ"),
                "AS",
                4134,
                "ChinaNet Backbone",
            ),
            (
                "180.76.0.0/16",
                "CN",
                Some("BJ"),
                "AS",
                4134,
                "ChinaNet / Baidu",
            ),
            (
                "183.0.0.0/10",
                "CN",
                Some("GD"),
                "AS",
                4134,
                "ChinaNet Guangdong",
            ),
            (
                "202.96.0.0/12",
                "CN",
                Some("SH"),
                "AS",
                4134,
                "ChinaNet Backbone",
            ),
            (
                "222.64.0.0/11",
                "CN",
                Some("SH"),
                "AS",
                4134,
                "ChinaNet Shanghai",
            ),
            ("240e::/18", "CN", None, "AS", 4134, "ChinaNet IPv6"),
            // China Unicom China169 (AS4837)
            (
                "111.160.0.0/11",
                "CN",
                Some("TJ"),
                "AS",
                4837,
                "China169 Backbone",
            ),
            (
                "123.125.0.0/16",
                "CN",
                Some("BJ"),
                "AS",
                4837,
                "China169 Beijing",
            ),
            (
                "218.56.0.0/13",
                "CN",
                Some("SD"),
                "AS",
                4837,
                "China169 Shandong",
            ),
            (
                "221.0.0.0/11",
                "CN",
                Some("BJ"),
                "AS",
                4837,
                "China169 Backbone",
            ),
            ("2408:8000::/20", "CN", None, "AS", 4837, "China169 IPv6"),
            // China Mobile (AS9808)
            (
                "111.0.0.0/10",
                "CN",
                Some("BJ"),
                "AS",
                9808,
                "China Mobile Communications",
            ),
            (
                "120.192.0.0/10",
                "CN",
                Some("GD"),
                "AS",
                9808,
                "China Mobile Communications",
            ),
            (
                "223.5.5.0/24",
                "CN",
                Some("ZJ"),
                "AS",
                37963,
                "Alibaba AliDNS",
            ),
            (
                "223.6.6.0/24",
                "CN",
                Some("ZJ"),
                "AS",
                37963,
                "Alibaba AliDNS",
            ),
            (
                "2409:8000::/20",
                "CN",
                None,
                "AS",
                9808,
                "China Mobile IPv6",
            ),
            // Alibaba Cloud (AS45102 / AS37963) & Tencent Cloud (AS132203 / AS45090)
            (
                "47.88.0.0/13",
                "SG",
                Some("SG"),
                "AS",
                45102,
                "Alibaba US/SG Cloud",
            ),
            (
                "106.11.0.0/16",
                "CN",
                Some("ZJ"),
                "AS",
                37963,
                "Alibaba Cloud China",
            ),
            (
                "119.29.0.0/16",
                "CN",
                Some("GD"),
                "AS",
                45090,
                "Tencent Cloud DNSPod",
            ),
            (
                "43.128.0.0/11",
                "SG",
                Some("SG"),
                "AS",
                132203,
                "Tencent Cloud Global",
            ),
            // Japan (JP)
            (
                "106.128.0.0/10",
                "JP",
                Some("TYO"),
                "AS",
                2516,
                "KDDI Corporation",
            ),
            (
                "126.0.0.0/9",
                "JP",
                Some("TYO"),
                "AS",
                17676,
                "SoftBank BB Corp.",
            ),
            (
                "129.250.0.0/16",
                "JP",
                Some("TYO"),
                "AS",
                2914,
                "NTT America/Global",
            ),
            // Hong Kong (HK), Taiwan (TW), South Korea (KR), Singapore (SG)
            (
                "203.198.0.0/15",
                "HK",
                Some("HK"),
                "AS",
                4760,
                "HKT Limited",
            ),
            (
                "168.95.0.0/16",
                "TW",
                Some("TPE"),
                "AS",
                3462,
                "Chunghwa Telecom HiNet",
            ),
            (
                "112.160.0.0/11",
                "KR",
                Some("SEL"),
                "AS",
                4766,
                "Korea Telecom",
            ),
            (
                "165.21.0.0/16",
                "SG",
                Some("SG"),
                "AS",
                7473,
                "Singapore Telecom",
            ),
            // Europe (DE, GB, FR, NL)
            (
                "80.128.0.0/11",
                "DE",
                Some("FRA"),
                "EU",
                3320,
                "Deutsche Telekom AG",
            ),
            (
                "116.202.0.0/15",
                "DE",
                Some("FSN"),
                "EU",
                24940,
                "Hetzner Online GmbH",
            ),
            (
                "81.128.0.0/10",
                "GB",
                Some("LON"),
                "EU",
                2856,
                "British Telecommunications",
            ),
            ("51.38.0.0/16", "FR", Some("PAR"), "EU", 16276, "OVH SAS"),
            (
                "185.199.108.0/22",
                "NL",
                Some("AMS"),
                "EU",
                54113,
                "Fastly / GitHub Pages EU",
            ),
            // North America ISPs & Oceania
            (
                "73.0.0.0/8",
                "US",
                Some("PA"),
                "NA",
                7922,
                "Comcast Cable Communications",
            ),
            (
                "99.0.0.0/10",
                "US",
                Some("TX"),
                "NA",
                7018,
                "AT&T Services Inc.",
            ),
            (
                "1.128.0.0/11",
                "AU",
                Some("SYD"),
                "OC",
                1221,
                "Telstra Corporation",
            ),
        ];
        for &(cidr_s, cc, reg, cont, asn, org) in seed {
            if let Ok(cidr) = IpCidr::parse(cidr_s) {
                db.records.push(GeoAsnRecord {
                    cidr,
                    country: cc.to_owned(),
                    region: reg.map(str::to_owned),
                    continent: cont.to_owned(),
                    asn,
                    org: org.to_owned(),
                });
            }
        }
        db
    }

    /// Append records from a CSV text (`cidr,country,region,continent,asn,org`).
    /// Lines starting with `#` or empty lines or header lines (`cidr,...`) are skipped.
    pub fn load_csv_str(&mut self, text: &str) -> Result<usize, String> {
        let mut added = 0usize;
        for (line_no, raw_line) in text.lines().enumerate() {
            let line = raw_line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if line.to_ascii_lowercase().starts_with("cidr,") {
                continue;
            }
            if self.records.len() >= MAX_GEO_ASN_ENTRIES {
                return Err(format!(
                    "GeoIP/ASN database exceeds {MAX_GEO_ASN_ENTRIES} record limit"
                ));
            }
            let parts: Vec<&str> = line.splitn(6, ',').map(str::trim).collect();
            if parts.len() < 2 {
                return Err(format!(
                    "line {}: expected at least cidr,country[,region,continent,asn,org]",
                    line_no + 1
                ));
            }
            let cidr = IpCidr::parse(parts[0]).map_err(|e| format!("line {}: {e}", line_no + 1))?;
            let country = parts
                .get(1)
                .map(|s| s.to_ascii_uppercase())
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| "ZZ".to_owned());
            let region = parts
                .get(2)
                .filter(|s| !s.is_empty())
                .map(|s| s.to_ascii_uppercase());
            let continent = parts
                .get(3)
                .map(|s| s.to_ascii_uppercase())
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| "ZZ".to_owned());
            let asn = match parts
                .get(4)
                .map(|s| s.trim().trim_start_matches("AS").trim_start_matches("as"))
            {
                Some(s) if !s.is_empty() => s
                    .parse::<u32>()
                    .map_err(|_| format!("line {}: invalid ASN {s:?}", line_no + 1))?,
                _ => 0,
            };
            let org = parts.get(5).copied().unwrap_or("").to_owned();
            self.records.push(GeoAsnRecord {
                cidr,
                country,
                region,
                continent,
                asn,
                org,
            });
            added += 1;
        }
        Ok(added)
    }

    /// Longest-prefix-match lookup of an IP address in this database.
    pub fn lookup(&self, ip: IpAddr) -> Option<IpGeoAsnInfo> {
        let mut best: Option<&GeoAsnRecord> = None;
        for rec in &self.records {
            if rec.cidr.contains(ip) && best.is_none_or(|prev| rec.cidr.prefix >= prev.cidr.prefix)
            {
                best = Some(rec);
            }
        }
        best.map(|rec| IpGeoAsnInfo {
            matched_prefix: rec.cidr.to_string(),
            country: rec.country.clone(),
            region: rec.region.clone(),
            continent: rec.continent.clone(),
            asn: rec.asn,
            org: rec.org.clone(),
        })
    }

    /// Return all prefixes matching a given ASN, GeoIP country/region, or continent.
    pub fn prefixes_for(&self, matcher: &RuleMatcher) -> Vec<IpCidr> {
        match matcher {
            RuleMatcher::Cidr { cidr } => IpCidr::parse(cidr).into_iter().collect(),
            RuleMatcher::Asn { asn } => self
                .records
                .iter()
                .filter(|r| r.asn == *asn)
                .map(|r| r.cidr)
                .collect(),
            RuleMatcher::GeoIp { country, region } => {
                let want_cc = country.trim().to_ascii_uppercase();
                let want_reg = region.as_deref().map(|s| s.trim().to_ascii_uppercase());
                self.records
                    .iter()
                    .filter(|r| {
                        r.country == want_cc
                            && match &want_reg {
                                Some(reg) => r.region.as_deref() == Some(reg.as_str()),
                                None => true,
                            }
                    })
                    .map(|r| r.cidr)
                    .collect()
            }
            RuleMatcher::Continent { continent } => {
                let want = continent.trim().to_ascii_uppercase();
                self.records
                    .iter()
                    .filter(|r| r.continent == want)
                    .map(|r| r.cidr)
                    .collect()
            }
            RuleMatcher::PrivateLan => private_lan_cidrs(),
            RuleMatcher::Default => vec![
                IpCidr {
                    network: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                    prefix: 0,
                },
                IpCidr {
                    network: IpAddr::V6(Ipv6Addr::UNSPECIFIED),
                    prefix: 0,
                },
            ],
        }
    }
}

/// Standard RFC1918 + RFC6598 + loopback + link-local + ULA + multicast prefixes.
pub fn private_lan_cidrs() -> Vec<IpCidr> {
    [
        "10.0.0.0/8",
        "100.64.0.0/10",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "224.0.0.0/4",
        "::1/128",
        "fc00::/7",
        "fe80::/10",
        "ff00::/8",
    ]
    .iter()
    .filter_map(|s| IpCidr::parse(s).ok())
    .collect()
}

/// Whether `ip` belongs to a private / loopback / link-local / CGNAT / multicast range.
pub fn is_private_lan(ip: IpAddr) -> bool {
    private_lan_cidrs().iter().any(|c| c.contains(ip))
}

impl RedirectPolicy {
    /// Validate policy version, rule count, and every rule matcher.
    pub fn validate(&self) -> Result<(), String> {
        if self.version != REDIRECT_POLICY_VERSION {
            return Err(format!(
                "unsupported redirect policy version {} (expected {REDIRECT_POLICY_VERSION})",
                self.version
            ));
        }
        if self.rules.len() > MAX_REDIRECT_RULES {
            return Err(format!(
                "redirect policy exceeds {MAX_REDIRECT_RULES} rules"
            ));
        }
        for rule in &self.rules {
            rule.validate()?;
        }
        Ok(())
    }

    /// Return all built-in named presets `(id, description)`.
    pub fn preset_catalog() -> &'static [(&'static str, &'static str)] {
        &[
            (
                "global-bypass-lan",
                "Tunnel all internet traffic; bypass RFC1918/LAN/local ranges",
            ),
            (
                "bypass-cn-and-lan",
                "Bypass Private/LAN + GeoIP:CN prefixes; tunnel all other destinations",
            ),
            (
                "bypass-cn-asns",
                "Bypass Private/LAN + major China carrier ASNs (AS4134, AS4837, AS9808, AS37963, AS45090); tunnel everything else",
            ),
            (
                "tunnel-us-eu-only",
                "Tunnel only GeoIP:US + Continent:EU + Cloudflare/Google ASNs; route everything else Direct",
            ),
            (
                "tunnel-cloudflare-google",
                "Tunnel only AS13335 (Cloudflare) and AS15169 (Google); route everything else Direct",
            ),
        ]
    }

    /// Construct one named built-in preset policy.
    pub fn preset(name: &str) -> Option<Self> {
        match name.trim().to_ascii_lowercase().as_str() {
            "global-bypass-lan" => Some(Self {
                version: REDIRECT_POLICY_VERSION,
                default_action: RedirectAction::Tunnel,
                bypass_peer_endpoint: true,
                rules: vec![RedirectRule {
                    id: "bypass-lan".into(),
                    enabled: true,
                    matcher: RuleMatcher::PrivateLan,
                    action: RedirectAction::Direct,
                    comment: Some("Keep local LAN and CGNAT direct".into()),
                }],
            }),
            "bypass-cn-and-lan" => Some(Self {
                version: REDIRECT_POLICY_VERSION,
                default_action: RedirectAction::Tunnel,
                bypass_peer_endpoint: true,
                rules: vec![
                    RedirectRule {
                        id: "bypass-lan".into(),
                        enabled: true,
                        matcher: RuleMatcher::PrivateLan,
                        action: RedirectAction::Direct,
                        comment: Some("Keep local LAN direct".into()),
                    },
                    RedirectRule {
                        id: "bypass-geoip-cn".into(),
                        enabled: true,
                        matcher: RuleMatcher::GeoIp {
                            country: "CN".into(),
                            region: None,
                        },
                        action: RedirectAction::Direct,
                        comment: Some("Bypass mainland China IP location prefixes".into()),
                    },
                ],
            }),
            "bypass-cn-asns" => Some(Self {
                version: REDIRECT_POLICY_VERSION,
                default_action: RedirectAction::Tunnel,
                bypass_peer_endpoint: true,
                rules: vec![
                    RedirectRule {
                        id: "bypass-lan".into(),
                        enabled: true,
                        matcher: RuleMatcher::PrivateLan,
                        action: RedirectAction::Direct,
                        comment: Some("Keep local LAN direct".into()),
                    },
                    RedirectRule {
                        id: "bypass-as4134".into(),
                        enabled: true,
                        matcher: RuleMatcher::Asn { asn: 4134 },
                        action: RedirectAction::Direct,
                        comment: Some("ChinaNet Backbone".into()),
                    },
                    RedirectRule {
                        id: "bypass-as4837".into(),
                        enabled: true,
                        matcher: RuleMatcher::Asn { asn: 4837 },
                        action: RedirectAction::Direct,
                        comment: Some("China169 Backbone".into()),
                    },
                    RedirectRule {
                        id: "bypass-as9808".into(),
                        enabled: true,
                        matcher: RuleMatcher::Asn { asn: 9808 },
                        action: RedirectAction::Direct,
                        comment: Some("China Mobile".into()),
                    },
                    RedirectRule {
                        id: "bypass-as37963".into(),
                        enabled: true,
                        matcher: RuleMatcher::Asn { asn: 37963 },
                        action: RedirectAction::Direct,
                        comment: Some("Alibaba Cloud China".into()),
                    },
                    RedirectRule {
                        id: "bypass-as45090".into(),
                        enabled: true,
                        matcher: RuleMatcher::Asn { asn: 45090 },
                        action: RedirectAction::Direct,
                        comment: Some("Tencent Cloud China".into()),
                    },
                ],
            }),
            "tunnel-us-eu-only" => Some(Self {
                version: REDIRECT_POLICY_VERSION,
                default_action: RedirectAction::Direct,
                bypass_peer_endpoint: true,
                rules: vec![
                    RedirectRule {
                        id: "bypass-lan".into(),
                        enabled: true,
                        matcher: RuleMatcher::PrivateLan,
                        action: RedirectAction::Direct,
                        comment: Some("Keep local LAN direct".into()),
                    },
                    RedirectRule {
                        id: "tunnel-as13335".into(),
                        enabled: true,
                        matcher: RuleMatcher::Asn { asn: 13335 },
                        action: RedirectAction::Tunnel,
                        comment: Some("Cloudflare ASN".into()),
                    },
                    RedirectRule {
                        id: "tunnel-as15169".into(),
                        enabled: true,
                        matcher: RuleMatcher::Asn { asn: 15169 },
                        action: RedirectAction::Tunnel,
                        comment: Some("Google ASN".into()),
                    },
                    RedirectRule {
                        id: "tunnel-geoip-us".into(),
                        enabled: true,
                        matcher: RuleMatcher::GeoIp {
                            country: "US".into(),
                            region: None,
                        },
                        action: RedirectAction::Tunnel,
                        comment: Some("United States IP location".into()),
                    },
                    RedirectRule {
                        id: "tunnel-continent-eu".into(),
                        enabled: true,
                        matcher: RuleMatcher::Continent {
                            continent: "EU".into(),
                        },
                        action: RedirectAction::Tunnel,
                        comment: Some("European IP locations".into()),
                    },
                ],
            }),
            "tunnel-cloudflare-google" => Some(Self {
                version: REDIRECT_POLICY_VERSION,
                default_action: RedirectAction::Direct,
                bypass_peer_endpoint: true,
                rules: vec![
                    RedirectRule {
                        id: "tunnel-cloudflare".into(),
                        enabled: true,
                        matcher: RuleMatcher::Asn { asn: 13335 },
                        action: RedirectAction::Tunnel,
                        comment: Some("Cloudflare".into()),
                    },
                    RedirectRule {
                        id: "tunnel-google".into(),
                        enabled: true,
                        matcher: RuleMatcher::Asn { asn: 15169 },
                        action: RedirectAction::Tunnel,
                        comment: Some("Google".into()),
                    },
                ],
            }),
            _ => None,
        }
    }

    /// Evaluate a single destination IP against ordered rules (first match wins).
    pub fn evaluate(&self, ip: IpAddr, db: &IpGeoAsnDatabase) -> PolicyDecision {
        let geo = db.lookup(ip);
        for rule in &self.rules {
            if !rule.enabled {
                continue;
            }
            let matched = match &rule.matcher {
                RuleMatcher::Cidr { cidr } => IpCidr::parse(cidr).is_ok_and(|c| c.contains(ip)),
                RuleMatcher::Asn { asn } => geo.as_ref().is_some_and(|g| g.asn == *asn),
                RuleMatcher::GeoIp { country, region } => geo.as_ref().is_some_and(|g| {
                    g.country.eq_ignore_ascii_case(country.trim())
                        && match region {
                            Some(reg) => g
                                .region
                                .as_deref()
                                .is_some_and(|gr| gr.eq_ignore_ascii_case(reg.trim())),
                            None => true,
                        }
                }),
                RuleMatcher::Continent { continent } => geo
                    .as_ref()
                    .is_some_and(|g| g.continent.eq_ignore_ascii_case(continent.trim())),
                RuleMatcher::PrivateLan => is_private_lan(ip),
                RuleMatcher::Default => true,
            };
            if matched {
                return PolicyDecision {
                    ip: ip.to_string(),
                    action: rule.action,
                    matched_rule_id: rule.id.clone(),
                    matched_by: rule.matcher.label(),
                    geo,
                };
            }
        }
        PolicyDecision {
            ip: ip.to_string(),
            action: self.default_action,
            matched_rule_id: "default_action".to_owned(),
            matched_by: format!("DEFAULT({})", self.default_action),
            geo,
        }
    }

    /// Compile exact minimal non-overlapping IPv4/IPv6 TUN routes using interval
    /// subtraction (preserving rule precedence, and always excluding `peer_ip`
    /// when `bypass_peer_endpoint` is true so tunnel outer UDP/TCP never loops).
    pub fn compile_tun_routes(
        &self,
        db: &IpGeoAsnDatabase,
        peer_ip: Option<IpAddr>,
    ) -> CompiledRoutes {
        let mut active_rules = 0usize;
        let mut expanded_prefixes = 0usize;
        let mut tunnel_v4: Vec<(u32, u32)> = Vec::new();
        let mut exclude_v4_ranges: Vec<(u32, u32)> = Vec::new();
        let mut tunnel_v6: Vec<(u128, u128)> = Vec::new();
        let mut exclude_v6_ranges: Vec<(u128, u128)> = Vec::new();
        let mut exclude_v4_cidrs: Vec<IpCidr> = Vec::new();
        let mut exclude_v6_cidrs: Vec<IpCidr> = Vec::new();
        let mut reject_cidrs: Vec<IpCidr> = Vec::new();

        // Start from default action coverage:
        if self.default_action == RedirectAction::Tunnel {
            tunnel_v4.push((0, u32::MAX));
            tunnel_v6.push((0, u128::MAX));
        }

        // Apply rules in reverse order so earlier rules take strict precedence over later ones!
        for rule in self.rules.iter().rev() {
            if !rule.enabled {
                continue;
            }
            active_rules += 1;
            let prefixes = db.prefixes_for(&rule.matcher);
            expanded_prefixes += prefixes.len();
            let v4_parts: Vec<(u32, u32)> = prefixes.iter().filter_map(|c| c.v4_range()).collect();
            let v6_parts: Vec<(u128, u128)> =
                prefixes.iter().filter_map(|c| c.v6_range()).collect();
            match rule.action {
                RedirectAction::Tunnel => {
                    tunnel_v4.extend_from_slice(&v4_parts);
                    tunnel_v4 = merge_v4(tunnel_v4);
                    tunnel_v6.extend_from_slice(&v6_parts);
                    tunnel_v6 = merge_v6(tunnel_v6);
                    exclude_v4_ranges = subtract_v4(exclude_v4_ranges, &v4_parts);
                    exclude_v6_ranges = subtract_v6(exclude_v6_ranges, &v6_parts);
                }
                RedirectAction::Direct => {
                    tunnel_v4 = subtract_v4(tunnel_v4, &v4_parts);
                    tunnel_v6 = subtract_v6(tunnel_v6, &v6_parts);
                    exclude_v4_ranges.extend_from_slice(&v4_parts);
                    exclude_v4_ranges = merge_v4(exclude_v4_ranges);
                    exclude_v6_ranges.extend_from_slice(&v6_parts);
                    exclude_v6_ranges = merge_v6(exclude_v6_ranges);
                }
                RedirectAction::Reject => {
                    tunnel_v4 = subtract_v4(tunnel_v4, &v4_parts);
                    tunnel_v6 = subtract_v6(tunnel_v6, &v6_parts);
                    reject_cidrs.extend(prefixes);
                }
            }
        }

        // Always bypass peer outer endpoint to guarantee anti-loop protection.
        if self.bypass_peer_endpoint
            && let Some(peer) = peer_ip
        {
            match peer {
                IpAddr::V4(v4) => {
                    let v = u32::from(v4);
                    tunnel_v4 = subtract_v4(tunnel_v4, &[(v, v)]);
                    exclude_v4_ranges.push((v, v));
                    exclude_v4_ranges = merge_v4(exclude_v4_ranges);
                }
                IpAddr::V6(v6) => {
                    let v = u128::from(v6);
                    tunnel_v6 = subtract_v6(tunnel_v6, &[(v, v)]);
                    exclude_v6_ranges.push((v, v));
                    exclude_v6_ranges = merge_v6(exclude_v6_ranges);
                }
            }
        }

        let include_v4 = ranges_to_v4_cidrs(&tunnel_v4)
            .into_iter()
            .map(|c| c.to_string())
            .collect();
        exclude_v4_cidrs.extend(ranges_to_v4_cidrs(&exclude_v4_ranges));
        let exclude_v4 = exclude_v4_cidrs
            .into_iter()
            .map(|c| c.to_string())
            .collect();

        let include_v6 = ranges_to_v6_cidrs(&tunnel_v6)
            .into_iter()
            .map(|c| c.to_string())
            .collect();
        exclude_v6_cidrs.extend(ranges_to_v6_cidrs(&exclude_v6_ranges));
        let exclude_v6 = exclude_v6_cidrs
            .into_iter()
            .map(|c| c.to_string())
            .collect();

        reject_cidrs.sort();
        reject_cidrs.dedup();
        let reject_cidrs = reject_cidrs.into_iter().map(|c| c.to_string()).collect();

        CompiledRoutes {
            include_v4,
            exclude_v4,
            include_v6,
            exclude_v6,
            reject_cidrs,
            active_rules,
            expanded_prefixes,
        }
    }
}

fn merge_v4(mut ranges: Vec<(u32, u32)>) -> Vec<(u32, u32)> {
    if ranges.is_empty() {
        return ranges;
    }
    ranges.sort_unstable();
    let mut out: Vec<(u32, u32)> = Vec::with_capacity(ranges.len());
    for (s, e) in ranges {
        if let Some(last) = out.last_mut()
            && s <= last.1.saturating_add(1)
        {
            last.1 = last.1.max(e);
            continue;
        }
        out.push((s, e));
    }
    out
}

fn subtract_v4(base: Vec<(u32, u32)>, remove: &[(u32, u32)]) -> Vec<(u32, u32)> {
    if base.is_empty() || remove.is_empty() {
        return base;
    }
    let rem = merge_v4(remove.to_vec());
    let mut current = merge_v4(base);
    for (rs, re) in rem {
        let mut next = Vec::with_capacity(current.len() + 1);
        for (s, e) in current {
            if re < s || rs > e {
                next.push((s, e));
            } else {
                if rs > s {
                    next.push((s, rs - 1));
                }
                if re < e {
                    next.push((re + 1, e));
                }
            }
        }
        current = next;
    }
    current
}

fn ranges_to_v4_cidrs(ranges: &[(u32, u32)]) -> Vec<IpCidr> {
    let mut out = Vec::new();
    for &(start, end) in ranges {
        let mut cur = u64::from(start);
        let end64 = u64::from(end);
        while cur <= end64 {
            let max_align = if cur == 0 {
                32u32
            } else {
                (cur as u32).trailing_zeros()
            };
            let remaining = end64 - cur + 1;
            let mut bits = max_align;
            while bits > 0 && (1u64 << bits) > remaining {
                bits -= 1;
            }
            let prefix = (32 - bits) as u8;
            out.push(IpCidr {
                network: IpAddr::V4(Ipv4Addr::from(cur as u32)),
                prefix,
            });
            cur += 1u64 << bits;
        }
    }
    out
}

fn merge_v6(mut ranges: Vec<(u128, u128)>) -> Vec<(u128, u128)> {
    if ranges.is_empty() {
        return ranges;
    }
    ranges.sort_unstable();
    let mut out: Vec<(u128, u128)> = Vec::with_capacity(ranges.len());
    for (s, e) in ranges {
        if let Some(last) = out.last_mut()
            && s <= last.1.saturating_add(1)
        {
            last.1 = last.1.max(e);
            continue;
        }
        out.push((s, e));
    }
    out
}

fn subtract_v6(base: Vec<(u128, u128)>, remove: &[(u128, u128)]) -> Vec<(u128, u128)> {
    if base.is_empty() || remove.is_empty() {
        return base;
    }
    let rem = merge_v6(remove.to_vec());
    let mut current = merge_v6(base);
    for (rs, re) in rem {
        let mut next = Vec::with_capacity(current.len() + 1);
        for (s, e) in current {
            if re < s || rs > e {
                next.push((s, e));
            } else {
                if rs > s {
                    next.push((s, rs - 1));
                }
                if re < e {
                    next.push((re + 1, e));
                }
            }
        }
        current = next;
    }
    current
}

fn ranges_to_v6_cidrs(ranges: &[(u128, u128)]) -> Vec<IpCidr> {
    let mut out = Vec::new();
    for &(start, end) in ranges {
        if start == 0 && end == u128::MAX {
            out.push(IpCidr {
                network: IpAddr::V6(Ipv6Addr::UNSPECIFIED),
                prefix: 0,
            });
            continue;
        }
        let mut cur = start;
        loop {
            let max_align = if cur == 0 {
                127u32
            } else {
                cur.trailing_zeros().min(127)
            };
            let remaining_minus_one = end - cur;
            let mut bits = max_align;
            while bits > 0 && ((1u128 << bits) - 1) > remaining_minus_one {
                bits -= 1;
            }
            let prefix = (128 - bits) as u8;
            out.push(IpCidr {
                network: IpAddr::V6(Ipv6Addr::from(cur)),
                prefix,
            });
            let step = 1u128 << bits;
            match cur.checked_add(step) {
                Some(next) if next <= end => cur = next,
                _ => break,
            }
        }
    }
    out
}

/// Bounded zero-unsafe MaxMind DB (MMDB v2) reader for offline GeoLite2-Country /
/// GeoLite2-ASN / GeoLite2-City databases.
#[derive(Clone, Debug)]
pub struct MmdbReader {
    data: Vec<u8>,
    node_count: u32,
    record_size: u16,
    ip_version: u16,
    tree_size: usize,
    data_section_start: usize,
}

const MMDB_METADATA_MARKER: &[u8] = b"\xab\xcd\xefMaxMind.com";

#[derive(Clone, Debug)]
enum MmdbValue {
    String(String),
    Uint(u64),
    Map(BTreeMap<String, MmdbValue>),
    Other,
}

impl MmdbReader {
    /// Parse and validate a bounded MMDB binary file in memory.
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self, String> {
        if bytes.is_empty() || bytes.len() > MAX_MMDB_BYTES {
            return Err(format!(
                "MMDB file size out of bounds (1..={MAX_MMDB_BYTES})"
            ));
        }
        let marker_pos = bytes
            .windows(MMDB_METADATA_MARKER.len())
            .rposition(|w| w == MMDB_METADATA_MARKER)
            .ok_or_else(|| "missing MaxMind MMDB metadata marker".to_owned())?;
        let meta_start = marker_pos + MMDB_METADATA_MARKER.len();
        let (meta_val, _) = decode_mmdb_value(&bytes, meta_start, meta_start, 0)?;
        let MmdbValue::Map(meta) = meta_val else {
            return Err("MMDB metadata root is not a map".to_owned());
        };
        let node_count = match meta.get("node_count") {
            Some(MmdbValue::Uint(v)) => u32::try_from(*v).map_err(|_| "node_count overflow")?,
            _ => return Err("MMDB metadata missing node_count".to_owned()),
        };
        let record_size = match meta.get("record_size") {
            Some(MmdbValue::Uint(v)) if matches!(*v, 24 | 28 | 32) => *v as u16,
            _ => {
                return Err(
                    "MMDB metadata has unsupported record_size (expected 24, 28, or 32)".to_owned(),
                );
            }
        };
        let ip_version = match meta.get("ip_version") {
            Some(MmdbValue::Uint(v)) if matches!(*v, 4 | 6) => *v as u16,
            _ => return Err("MMDB metadata has unsupported ip_version".to_owned()),
        };
        let node_bytes = (usize::from(record_size) * 2) / 8;
        let tree_size = usize::try_from(node_count)
            .ok()
            .and_then(|n| n.checked_mul(node_bytes))
            .ok_or_else(|| "MMDB search tree size overflow".to_owned())?;
        let data_section_start = tree_size
            .checked_add(16)
            .filter(|&s| s <= marker_pos)
            .ok_or_else(|| "MMDB search tree exceeds file size".to_owned())?;
        Ok(Self {
            data: bytes,
            node_count,
            record_size,
            ip_version,
            tree_size,
            data_section_start,
        })
    }

    /// Look up GeoIP/ASN metadata for `ip` inside this MMDB file.
    pub fn lookup(&self, ip: IpAddr) -> Result<Option<IpGeoAsnInfo>, String> {
        let bits: Vec<u8> = match (self.ip_version, ip) {
            (4, IpAddr::V4(v4)) => v4.octets().to_vec(),
            (4, IpAddr::V6(_)) => return Ok(None),
            (6, IpAddr::V4(v4)) => {
                let mut out = vec![0u8; 16];
                out[12..16].copy_from_slice(&v4.octets());
                out
            }
            (6, IpAddr::V6(v6)) => v6.octets().to_vec(),
            _ => return Ok(None),
        };
        let mut node: u32 = 0;
        let mut prefix_len: u8 = 0;
        for (byte_idx, byte) in bits.iter().enumerate() {
            for bit_in_byte in (0..8).rev() {
                if node >= self.node_count {
                    break;
                }
                let bit = (byte >> bit_in_byte) & 1;
                node = self.read_record(node, bit == 1)?;
                prefix_len = (byte_idx * 8 + (7 - bit_in_byte) + 1) as u8;
                if node >= self.node_count {
                    break;
                }
            }
            if node >= self.node_count {
                break;
            }
        }
        if node == self.node_count {
            return Ok(None);
        }
        let offset = (node - self.node_count) as usize;
        let pos = self
            .tree_size
            .checked_add(offset)
            .ok_or_else(|| "MMDB data offset overflow".to_owned())?;
        let (val, _) = decode_mmdb_value(&self.data, self.data_section_start, pos, 0)?;
        let MmdbValue::Map(map) = val else {
            return Ok(None);
        };
        let country = match map.get("country") {
            Some(MmdbValue::Map(cm)) => match cm.get("iso_code") {
                Some(MmdbValue::String(s)) => s.to_ascii_uppercase(),
                _ => "ZZ".to_owned(),
            },
            _ => "ZZ".to_owned(),
        };
        let continent = match map.get("continent") {
            Some(MmdbValue::Map(cm)) => match cm.get("code") {
                Some(MmdbValue::String(s)) => s.to_ascii_uppercase(),
                _ => "ZZ".to_owned(),
            },
            _ => "ZZ".to_owned(),
        };
        let asn = match map.get("autonomous_system_number") {
            Some(MmdbValue::Uint(v)) => u32::try_from(*v).unwrap_or(0),
            _ => 0,
        };
        let org = match map.get("autonomous_system_organization") {
            Some(MmdbValue::String(s)) => s.clone(),
            _ => String::new(),
        };
        let cidr_prefix = match (self.ip_version, ip) {
            (6, IpAddr::V4(_)) => prefix_len.saturating_sub(96),
            _ => prefix_len,
        };
        let matched_prefix = IpCidr::new(ip, cidr_prefix)
            .map(|c| c.to_string())
            .unwrap_or_else(|_| ip.to_string());
        Ok(Some(IpGeoAsnInfo {
            matched_prefix,
            country,
            region: None,
            continent,
            asn,
            org,
        }))
    }

    fn read_record(&self, node: u32, right: bool) -> Result<u32, String> {
        let node_bytes = (usize::from(self.record_size) * 2) / 8;
        let base = (node as usize)
            .checked_mul(node_bytes)
            .ok_or_else(|| "MMDB node offset overflow".to_owned())?;
        let slice = self
            .data
            .get(base..base + node_bytes)
            .ok_or_else(|| "MMDB node out of bounds".to_owned())?;
        Ok(match self.record_size {
            24 => {
                let off = if right { 3 } else { 0 };
                u32::from_be_bytes([0, slice[off], slice[off + 1], slice[off + 2]])
            }
            28 => {
                let mid = slice[3];
                if right {
                    u32::from_be_bytes([mid & 0x0f, slice[4], slice[5], slice[6]])
                } else {
                    u32::from_be_bytes([mid >> 4, slice[0], slice[1], slice[2]])
                }
            }
            32 => {
                let off = if right { 4 } else { 0 };
                u32::from_be_bytes([slice[off], slice[off + 1], slice[off + 2], slice[off + 3]])
            }
            _ => return Err("unsupported MMDB record_size".to_owned()),
        })
    }
}

fn decode_mmdb_value(
    buf: &[u8],
    data_start: usize,
    pos: usize,
    depth: usize,
) -> Result<(MmdbValue, usize), String> {
    if depth > 16 {
        return Err("MMDB nesting depth exceeded".to_owned());
    }
    let ctrl = *buf
        .get(pos)
        .ok_or_else(|| "MMDB unexpected EOF".to_owned())?;
    let mut cur = pos + 1;
    let mut ty = ctrl >> 5;
    if ty == 1 {
        // Pointer
        let ptr_size = ((ctrl >> 3) & 0x03) as usize;
        let low3 = usize::from(ctrl & 0x07);
        let ptr = match ptr_size {
            0 => {
                let b1 = usize::from(*buf.get(cur).ok_or("MMDB EOF in pointer")?);
                cur += 1;
                (low3 << 8) | b1
            }
            1 => {
                let b1 = usize::from(*buf.get(cur).ok_or("MMDB EOF in pointer")?);
                let b2 = usize::from(*buf.get(cur + 1).ok_or("MMDB EOF in pointer")?);
                cur += 2;
                ((low3 << 16) | (b1 << 8) | b2) + 2048
            }
            2 => {
                let b1 = usize::from(*buf.get(cur).ok_or("MMDB EOF in pointer")?);
                let b2 = usize::from(*buf.get(cur + 1).ok_or("MMDB EOF in pointer")?);
                let b3 = usize::from(*buf.get(cur + 2).ok_or("MMDB EOF in pointer")?);
                cur += 3;
                ((low3 << 24) | (b1 << 16) | (b2 << 8) | b3) + 526_336
            }
            _ => {
                let bytes = buf.get(cur..cur + 4).ok_or("MMDB EOF in pointer")?;
                cur += 4;
                u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize
            }
        };
        let target = data_start.checked_add(ptr).ok_or("MMDB pointer overflow")?;
        let (val, _) = decode_mmdb_value(buf, data_start, target, depth + 1)?;
        return Ok((val, cur));
    }
    if ty == 0 {
        let ext = *buf.get(cur).ok_or("MMDB EOF in extended type")?;
        cur += 1;
        ty = ext + 7;
    }
    let size_bits = usize::from(ctrl & 0x1f);
    let size = match size_bits {
        0..=28 => size_bits,
        29 => {
            let b = usize::from(*buf.get(cur).ok_or("MMDB EOF in size")?);
            cur += 1;
            29 + b
        }
        30 => {
            let b = buf.get(cur..cur + 2).ok_or("MMDB EOF in size")?;
            cur += 2;
            285 + usize::from(u16::from_be_bytes([b[0], b[1]]))
        }
        _ => {
            let b = buf.get(cur..cur + 3).ok_or("MMDB EOF in size")?;
            cur += 3;
            65_821 + ((usize::from(b[0]) << 16) | (usize::from(b[1]) << 8) | usize::from(b[2]))
        }
    };
    match ty {
        2 => {
            // UTF-8 string
            let s_bytes = buf.get(cur..cur + size).ok_or("MMDB EOF in string")?;
            let s = std::str::from_utf8(s_bytes)
                .map_err(|_| "MMDB invalid UTF-8 string")?
                .to_owned();
            Ok((MmdbValue::String(s), cur + size))
        }
        5 | 6 | 9 => {
            // uint16 / uint32 / uint64
            if size > 8 {
                return Err("MMDB uint size > 8".to_owned());
            }
            let bytes = buf.get(cur..cur + size).ok_or("MMDB EOF in uint")?;
            let mut acc = 0u64;
            for &b in bytes {
                acc = (acc << 8) | u64::from(b);
            }
            Ok((MmdbValue::Uint(acc), cur + size))
        }
        7 => {
            // Map
            if size > 256 {
                return Err("MMDB map exceeds 256 entries".to_owned());
            }
            let mut map = BTreeMap::new();
            for _ in 0..size {
                let (k, next_cur) = decode_mmdb_value(buf, data_start, cur, depth + 1)?;
                let MmdbValue::String(key) = k else {
                    return Err("MMDB map key is not UTF-8 string".to_owned());
                };
                let (v, next_cur2) = decode_mmdb_value(buf, data_start, next_cur, depth + 1)?;
                map.insert(key, v);
                cur = next_cur2;
            }
            Ok((MmdbValue::Map(map), cur))
        }
        11 => {
            // Array
            if size > 512 {
                return Err("MMDB array exceeds 512 elements".to_owned());
            }
            for _ in 0..size {
                let (_, next_cur) = decode_mmdb_value(buf, data_start, cur, depth + 1)?;
                cur = next_cur;
            }
            Ok((MmdbValue::Other, cur))
        }
        14 => {
            // Boolean (payload encoded in size_bits; 0 bytes follow)
            Ok((MmdbValue::Other, cur))
        }
        _ => {
            let end = cur.checked_add(size).ok_or("MMDB skip overflow")?;
            if end > buf.len() {
                return Err("MMDB value out of bounds".to_owned());
            }
            Ok((MmdbValue::Other, end))
        }
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn evaluate_asn_geoip_continent_and_lan_rules() {
        let db = IpGeoAsnDatabase::builtin();
        let cn_policy = RedirectPolicy::preset("bypass-cn-and-lan").expect("preset exists");
        assert_eq!(cn_policy.validate(), Ok(()));

        // RFC1918 LAN -> Direct
        let lan = cn_policy.evaluate("192.168.1.50".parse().expect("ip"), &db);
        assert_eq!(lan.action, RedirectAction::Direct);
        assert_eq!(lan.matched_rule_id, "bypass-lan");

        // ChinaNet DNS -> GeoIP:CN -> Direct
        let cn = cn_policy.evaluate("114.114.114.114".parse().expect("ip"), &db);
        assert_eq!(cn.action, RedirectAction::Direct);
        assert_eq!(cn.matched_rule_id, "bypass-geoip-cn");
        assert_eq!(cn.geo.as_ref().map(|g| g.asn), Some(4134));

        // Google DNS -> US/AS15169 -> Tunnel
        let us = cn_policy.evaluate("8.8.8.8".parse().expect("ip"), &db);
        assert_eq!(us.action, RedirectAction::Tunnel);
        assert_eq!(us.geo.as_ref().map(|g| g.country.as_str()), Some("US"));
        assert_eq!(us.geo.as_ref().map(|g| g.asn), Some(15169));

        // ASN-only preset
        let asn_policy = RedirectPolicy::preset("tunnel-cloudflare-google").expect("preset");
        assert_eq!(
            asn_policy
                .evaluate("1.1.1.1".parse().expect("ip"), &db)
                .action,
            RedirectAction::Tunnel
        );
        assert_eq!(
            asn_policy
                .evaluate("114.114.114.114".parse().expect("ip"), &db)
                .action,
            RedirectAction::Direct
        );
    }

    #[test]
    fn compile_tun_routes_subtracts_direct_and_peer_endpoint() {
        let db = IpGeoAsnDatabase::builtin();
        let policy = RedirectPolicy::preset("bypass-cn-and-lan").expect("preset");
        let peer: IpAddr = "198.51.100.10".parse().expect("peer");
        let compiled = policy.compile_tun_routes(&db, Some(peer));

        let inc: Vec<IpCidr> = compiled
            .include_v4
            .iter()
            .map(|s| IpCidr::parse(s).expect("valid compiled cidr"))
            .collect();
        // Peer IP, LAN, and CN must NOT be in include_v4
        assert!(!inc.iter().any(|c| c.contains(peer)));
        assert!(
            !inc.iter()
                .any(|c| c.contains("192.168.1.1".parse().expect("ip")))
        );
        assert!(
            !inc.iter()
                .any(|c| c.contains("114.114.114.114".parse().expect("ip")))
        );
        // US / EU / Cloudflare MUST be in include_v4
        assert!(
            inc.iter()
                .any(|c| c.contains("8.8.8.8".parse().expect("ip")))
        );
        assert!(
            inc.iter()
                .any(|c| c.contains("1.1.1.1".parse().expect("ip")))
        );
    }

    #[test]
    fn csv_loader_and_shorthand_parser_work() {
        let mut db = IpGeoAsnDatabase::empty();
        let n = db
            .load_csv_str(
                "# comment\ncidr,country,region,continent,asn,org\n203.0.113.0/24,JP,TYO,AS,64512,Example JP\n",
            )
            .expect("csv parse");
        assert_eq!(n, 1);
        let info = db.lookup("203.0.113.42".parse().expect("ip")).expect("hit");
        assert_eq!(info.country, "JP");
        assert_eq!(info.region.as_deref(), Some("TYO"));
        assert_eq!(info.asn, 64512);
        assert_eq!(
            RuleMatcher::parse_shorthand("geoip:JP-TYO").expect("geoip"),
            RuleMatcher::GeoIp {
                country: "JP".into(),
                region: Some("TYO".into()),
            }
        );
        assert_eq!(
            RuleMatcher::parse_shorthand("AS13335").expect("asn"),
            RuleMatcher::Asn { asn: 13335 }
        );
    }

    #[test]
    fn mmdb_reader_decodes_minimal_v2_database() {
        // Build a minimal 1-node IPv4 MMDB (record_size=24) where bit 0 -> no data, bit 1 -> record at offset 16.
        fn enc_str(s: &str) -> Vec<u8> {
            let mut v = vec![(2u8 << 5) | (s.len() as u8)];
            v.extend_from_slice(s.as_bytes());
            v
        }
        fn enc_u32(val: u32) -> Vec<u8> {
            let bytes = val.to_be_bytes();
            let first = bytes.iter().position(|&b| b != 0).unwrap_or(3);
            let slice = &bytes[first..];
            let mut v = vec![(6u8 << 5) | (slice.len() as u8)];
            v.extend_from_slice(slice);
            v
        }
        let mut buf = Vec::new();
        // 1 node (6 bytes for 24-bit left/right): left = 1 (not found), right = 1 + 16 = 17 (data offset 0)
        buf.extend_from_slice(&[0, 0, 1, 0, 0, 17]);
        // 16-byte zero separator
        buf.extend_from_slice(&[0u8; 16]);
        // Data record at offset 0: map with 2 keys: "country": {"iso_code": "JP"}, "autonomous_system_number": 2516
        buf.push((7u8 << 5) | 2);
        buf.extend_from_slice(&enc_str("country"));
        buf.push((7u8 << 5) | 1);
        buf.extend_from_slice(&enc_str("iso_code"));
        buf.extend_from_slice(&enc_str("JP"));
        buf.extend_from_slice(&enc_str("autonomous_system_number"));
        buf.extend_from_slice(&enc_u32(2516));
        // Metadata marker + map
        buf.extend_from_slice(MMDB_METADATA_MARKER);
        buf.push((7u8 << 5) | 3);
        buf.extend_from_slice(&enc_str("node_count"));
        buf.extend_from_slice(&enc_u32(1));
        buf.extend_from_slice(&enc_str("record_size"));
        buf.extend_from_slice(&enc_u32(24));
        buf.extend_from_slice(&enc_str("ip_version"));
        buf.extend_from_slice(&enc_u32(4));

        let reader = MmdbReader::from_bytes(buf).expect("valid mmdb");
        assert!(
            reader
                .lookup("1.2.3.4".parse().expect("ip"))
                .expect("ok")
                .is_none()
        );
        let hit = reader
            .lookup("128.0.0.1".parse().expect("ip"))
            .expect("ok")
            .expect("found");
        assert_eq!(hit.country, "JP");
        assert_eq!(hit.asn, 2516);
    }
}
