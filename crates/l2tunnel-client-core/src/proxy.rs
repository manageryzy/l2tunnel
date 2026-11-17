//! Explicit fixed-credit TUN proxy factories; original TLS lanes remain owned.
use super::ConnectionConfig;
use l2tunnel_device::PacketLayer;
use l2tunnel_runtime::{Compression, proxy as runtime};
use serde::{
    Deserialize, Deserializer,
    de::{self, SeqAccess, Visitor},
};
use std::{fmt, io, net::IpAddr, time::Duration};

/// Maintained behavior by default; the optional TIME-WAIT exception is explicit.
pub use l2tunnel_tcp_proxy::TimeWaitResetPolicy;
/// Authoritative route/prefix and finite runtime control types.
pub use runtime::{
    CloseReport, Control, DrainWaiter, Handle, IpPrefix, Phase, PortRange, RoutePolicy, RouteRule,
    Status, control_channel,
};

/// Maximum complete untrusted policy JSON, checked before parsing.
pub const MAX_POLICY_BYTES: usize = 65_536;
/// Maximum explicit original-tuple ownership rules.
pub const MAX_ROUTES: usize = 256;

/// Explicit fixed proxy policy, independent of any frontend or OS device setup.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Settings {
    /// Original source/destination ownership allowlist; empty denies new ownership.
    pub routes: RoutePolicy,
    /// Common CRC-affinity pool shared by every user/proxy record, in 1..=256.
    pub channels: u16,
    /// Native close behavior; no transparent TCP header modification is implied.
    pub time_wait_reset_policy: TimeWaitResetPolicy,
}
impl Settings {
    /// Select 16 channels and maintained TCP behavior, with no inferred route.
    pub fn new(routes: RoutePolicy) -> Self {
        Self {
            routes,
            channels: 16,
            time_wait_reset_policy: TimeWaitResetPolicy::Maintained,
        }
    }
    /// Parse required version-one fields without filesystem, DNS or network I/O.
    pub fn from_json(input: &[u8]) -> io::Result<Self> {
        if input.is_empty() || input.len() > MAX_POLICY_BYTES {
            return Err(invalid("proxy policy input exceeds bound"));
        }
        let document: Document = serde_json::from_slice(input)
            .map_err(|_| invalid("invalid strict proxy policy JSON"))?;
        Self::from_document(document)
    }
    pub(super) fn from_document(document: Document) -> io::Result<Self> {
        if document.version != 1 || !(1..=256).contains(&document.channels) {
            return Err(invalid("proxy policy version or channels"));
        }
        let routes = document
            .routes
            .into_iter()
            .map(|r| {
                Ok(RouteRule {
                    source: prefix(&r.source)?,
                    destination: prefix(&r.destination)?,
                    ports: PortRange {
                        first: r.ports.first,
                        last: r.ports.last,
                    },
                })
            })
            .collect::<io::Result<Vec<_>>>()?;
        Ok(Self {
            routes: RoutePolicy::new(routes)?,
            channels: document.channels,
            time_wait_reset_policy: match document.time_wait_reset {
                Reset::Maintained => TimeWaitResetPolicy::Maintained,
                Reset::IgnoreInTimeWait => TimeWaitResetPolicy::IgnoreInTimeWait,
            },
        })
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Document {
    version: u16,
    channels: u16,
    time_wait_reset: Reset,
    #[serde(deserialize_with = "routes")]
    routes: Vec<Route>,
}
#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum Reset {
    Maintained,
    IgnoreInTimeWait,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Route {
    source: String,
    destination: String,
    ports: Ports,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Ports {
    first: u16,
    last: u16,
}
fn routes<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<Route>, D::Error> {
    struct Bounded;
    impl<'de> Visitor<'de> for Bounded {
        type Value = Vec<Route>;
        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "at most {MAX_ROUTES} proxy routes")
        }
        fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> Result<Self::Value, A::Error> {
            if sequence.size_hint().is_some_and(|n| n > MAX_ROUTES) {
                return Err(de::Error::custom("proxy route count"));
            }
            let mut values = Vec::new();
            loop {
                if values.len() == MAX_ROUTES {
                    if sequence.next_element::<de::IgnoredAny>()?.is_some() {
                        return Err(de::Error::custom("proxy route count"));
                    }
                    return Ok(values);
                }
                let Some(value) = sequence.next_element()? else {
                    return Ok(values);
                };
                values.push(value);
            }
        }
    }
    deserializer.deserialize_seq(Bounded)
}
fn prefix(text: &str) -> io::Result<IpPrefix> {
    // Mixed IPv6/IPv4 notation can use 45 address bytes plus "/128".
    if text.len() > 49 || text.bytes().any(|b| b.is_ascii_whitespace()) {
        return Err(invalid("proxy prefix length/whitespace"));
    }
    let (address, bits) = text
        .split_once('/')
        .ok_or_else(|| invalid("proxy prefix requires literal IP/bits"))?;
    if bits.is_empty() || !bits.bytes().all(|b| b.is_ascii_digit()) {
        return Err(invalid("proxy prefix bits"));
    }
    let address: IpAddr = address
        .parse()
        .map_err(|_| invalid("proxy literal prefix address"))?;
    let bits = bits.parse().map_err(|_| invalid("proxy prefix bits"))?;
    IpPrefix::new(address, bits)
}
fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}
/// Derive and validate the exact fixed runtime policy before socket/device I/O.
pub fn runtime_config(
    connection: ConnectionConfig,
    settings: &Settings,
) -> io::Result<runtime::Config> {
    if connection.layer != PacketLayer::Ip
        || connection.compression != Compression::None
        || connection.handshake_timeout.is_zero()
        || connection.handshake_timeout > Duration::from_secs(120)
    {
        return Err(invalid(
            "proxy requires TUN, compression off and finite setup timeout",
        ));
    }
    let mut value = runtime::Config::new(
        connection.runtime(),
        connection.duplex,
        settings.routes.clone(),
    )?;
    value.mux.channels = settings.channels;
    value.native.time_wait_reset_policy = settings.time_wait_reset_policy;
    value.validate()?;
    Ok(value)
}

#[cfg(test)]
#[path = "proxy_tests.rs"]
mod tests;
