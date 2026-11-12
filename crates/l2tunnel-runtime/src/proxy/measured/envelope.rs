//! Structural version-two common-user framing; no authentication or admission.
use super::{Config, invalid};
use l2tunnel_tcp_proxy::measurement;
use std::io;
/// Explicit new-profile version, distinct from fixed proxy version one.
pub const VERSION: u8 = 2;
/// Common user header bytes; outer length/header charges are additional.
pub const HEADER_BYTES: usize = 24;
/// Closed profile classes; every class is ordinary common-MUX user work.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Kind {
    /// Complete encoded transparent native packet, with flow zero.
    Transparent = 0,
    /// Existing scoped proxy admission/relay/stop record.
    Proxy = 1,
    /// Exact canonical LTPM record for an existing nonzero flow.
    Measurement = 2,
}
/// Borrowed structural data; the caller still owes TLS/role/flow/channel validation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StructuralEnvelope<'a> {
    /// Ordinary user class, never a privileged session-control selector.
    pub kind: Kind,
    /// Claimed common MUX channel.
    pub channel: u16,
    /// Claimed lifetime flow, zero only for transparent native packets.
    pub flow: u64,
    /// Exact borrowed body; no padding or extra bytes are accepted.
    pub body: &'a [u8],
}
fn fields(config: &super::super::Config, value: StructuralEnvelope<'_>) -> io::Result<usize> {
    let maximum = config.max_user()?;
    let length = value
        .body
        .len()
        .checked_add(HEADER_BYTES)
        .filter(|n| *n <= maximum)
        .ok_or_else(|| invalid("measured user length"))?;
    if !(1..=256).contains(&config.mux.channels)
        || !(1..=64).contains(&config.relay.max_flows)
        || value.channel >= config.mux.channels
        || value.flow > config.relay.max_flows as u64
        || (value.flow == 0) != (value.kind == Kind::Transparent)
    {
        return Err(invalid("measured user flow/channel"));
    }
    if value.kind == Kind::Measurement {
        let record = measurement::wire::decode(value.body).map_err(io::Error::other)?;
        if record.header.scope.flow != value.flow {
            return Err(invalid("measured inner/outer flow"));
        }
    }
    Ok(length)
}
/// Encode exactly one bounded envelope, leaving caller output unchanged on error.
/// Canonical measurement parsing here establishes no authenticated authority.
pub fn encode(config: &Config, value: StructuralEnvelope<'_>, out: &mut [u8]) -> io::Result<usize> {
    encode_fixed(&config.fixed, value, out)
}
pub(in crate::proxy) fn encode_fixed(
    config: &super::super::Config,
    value: StructuralEnvelope<'_>,
    out: &mut [u8],
) -> io::Result<usize> {
    let length = fields(config, value)?;
    if out.len() < length {
        return Err(invalid("measured user output capacity"));
    }
    let body_len: u32 = value.body.len().try_into().map_err(io::Error::other)?;
    out[..HEADER_BYTES].fill(0);
    out[..4].copy_from_slice(b"LTPW");
    out[4] = VERSION;
    out[5] = value.kind as u8;
    out[8..10].copy_from_slice(&value.channel.to_be_bytes());
    out[12..20].copy_from_slice(&value.flow.to_be_bytes());
    out[20..24].copy_from_slice(&body_len.to_be_bytes());
    out[HEADER_BYTES..length].copy_from_slice(value.body);
    Ok(length)
}
/// Parse one exact structural envelope; never dispatch device magic to C ingress.
pub fn decode<'a>(config: &Config, bytes: &'a [u8]) -> io::Result<StructuralEnvelope<'a>> {
    decode_fixed(&config.fixed, bytes)
}
pub(in crate::proxy) fn decode_fixed<'a>(
    config: &super::super::Config,
    bytes: &'a [u8],
) -> io::Result<StructuralEnvelope<'a>> {
    if bytes.len() < HEADER_BYTES
        || bytes.len() > config.max_user()?
        || bytes[..4] != *b"LTPW"
        || bytes[4] != VERSION
        || bytes[6..8] != [0; 2]
        || bytes[10..12] != [0; 2]
        || u32::from_be_bytes(bytes[20..24].try_into().map_err(io::Error::other)?) as usize
            != bytes.len() - HEADER_BYTES
    {
        return Err(invalid("measured user envelope"));
    }
    let kind = match bytes[5] {
        0 => Kind::Transparent,
        1 => Kind::Proxy,
        2 => Kind::Measurement,
        _ => return Err(invalid("measured user class")),
    };
    let value = StructuralEnvelope {
        kind,
        channel: u16::from_be_bytes(bytes[8..10].try_into().map_err(io::Error::other)?),
        flow: u64::from_be_bytes(bytes[12..20].try_into().map_err(io::Error::other)?),
        body: &bytes[HEADER_BYTES..],
    };
    fields(config, value)?;
    Ok(value)
}
