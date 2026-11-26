//! Bounded admission and authenticated reliable bytes for TLS over standalone UDP.
//! Admission is not member authentication. No sockets, clocks or TLS are owned here.
use l2tunnel_recovery::{ArqConfig, RecoveryError};
use ring::{digest, hkdf, hmac};
use std::{fmt, net::SocketAddr, time::Duration};
use zeroize::Zeroizing;

mod control;
mod gate;
#[cfg(test)]
mod tests;
pub use control::{ControlEngine, ControlStatistics, ReceiveOutcome};
pub use gate::{ClientGate, GateEvent, GateStatistics, PathTicket, ServerGate};

/// Exact Hello, Retry and Echo byte count; each stateless response is 1:1 in bytes.
pub const GATE_BYTES: usize = 144;
/// Fixed authenticated control header plus full HMAC-SHA256 tag.
pub const CONTROL_OVERHEAD: usize = 64;
/// Complete fixed-size admission record.
pub type GateFrame = [u8; GATE_BYTES];

/// Independent admission or server-cookie key; never formats private material.
pub struct Secret(Zeroizing<[u8; 32]>);
impl Secret {
    /// Import a separately provisioned unpredictable key, never a public binding hash.
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(Zeroizing::new(bytes))
    }
}

/// Caller-configured endpoints, identical at both peers.
///
/// When `client` is the unspecified address with port `0` (`0.0.0.0:0` or `[::]:0`),
/// the server accepts the client from its observed NAT address after verifying the
/// return-path cookie bound to that observed address.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Path {
    /// Client UDP endpoint (`0.0.0.0:0` / `[::]:0` for dynamic NAT clients, or fixed nonzero).
    pub client: SocketAddr,
    /// Server UDP endpoint, with a nonzero port.
    pub server: SocketAddr,
}
impl Path {
    /// Whether the client endpoint is dynamic (ephemeral/NAT), configured as `0.0.0.0:0` or `[::]:0`.
    pub fn is_dynamic_client(self) -> bool {
        self.client.ip().is_unspecified() && self.client.port() == 0
    }
}

/// All bounds are included in the computed gate profile digest.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Config {
    /// Configured global endpoint order.
    pub path: Path,
    /// Upper-layer canonical profile, later included in actual TLS member binding.
    pub base_profile: [u8; 32],
    /// Public provisioned admission-key identifier, not final member identity.
    pub key_id: u32,
    /// Server-local cookie validity; at most the total handshake deadline.
    pub cookie_ttl: Duration,
    /// Absolute bootstrap lifetime, positive and at most 120 seconds.
    pub handshake_timeout: Duration,
    /// Combined live pending and finished-cookie quarantine count, 1..=1024.
    pub pending_sessions: usize,
    /// Gate/client retry and control-budget refill interval.
    pub interval: Duration,
    /// Stateless Retry response count permitted per interval.
    pub gate_responses: u32,
    /// Initial Hello/Echo retry interval.
    pub initial_rto: Duration,
    /// Largest Hello/Echo retry interval.
    pub maximum_rto: Duration,
    /// Total Hello/Echo transmissions within the original deadline.
    pub gate_attempts: u32,
    /// Physical IP packet ceiling, 256..=65535 bytes.
    pub path_mtu: usize,
    /// Exact configured IP/UDP and further encapsulation overhead.
    pub outer_overhead: usize,
    /// Authenticated ordered control stream retention and recovery policy.
    pub arq: ArqConfig,
    /// Total control datagrams admitted per interval, including retries/ACKs.
    pub control_packets: u32,
    /// Total complete IP bytes admitted per interval, including retries/ACKs.
    pub control_bytes: usize,
}

impl Config {
    /// Checked defaults for one configured fixed endpoint pair.
    pub fn new(path: Path, base_profile: [u8; 32], key_id: u32) -> Result<Self, Error> {
        let outer_overhead = if path.client.is_ipv4() { 28 } else { 48 };
        let max_source_bytes = 1200 - outer_overhead - CONTROL_OVERHEAD - 44;
        let value = Self {
            path,
            base_profile,
            key_id,
            cookie_ttl: Duration::from_secs(3),
            handshake_timeout: Duration::from_secs(30),
            pending_sessions: 16,
            interval: Duration::from_millis(10),
            gate_responses: 8,
            initial_rto: Duration::from_millis(100),
            maximum_rto: Duration::from_secs(2),
            gate_attempts: 12,
            path_mtu: 1200,
            outer_overhead,
            arq: ArqConfig {
                max_source_bytes,
                send_bytes: max_source_bytes * 32,
                receive_bytes: max_source_bytes * 32,
                send_records: 32,
                receive_records: 32,
                ..ArqConfig::default()
            },
            control_packets: 8,
            control_bytes: 8 * 1200,
        };
        value.validate()?;
        Ok(value)
    }

    /// Digest all configured resource/transport bounds, not secret key material.
    pub fn profile_digest(self) -> Result<[u8; 32], Error> {
        self.validate()?;
        let mut context = digest::Context::new(&digest::SHA256);
        context.update(b"l2tunnel/openvpn-like/control-profile/v1\0");
        context.update(&self.base_profile);
        context.update(&path_bytes(self.path));
        for value in [
            u64::from(self.key_id),
            micros(self.cookie_ttl)?,
            micros(self.handshake_timeout)?,
            self.pending_sessions as u64,
            micros(self.interval)?,
            u64::from(self.gate_responses),
            micros(self.initial_rto)?,
            micros(self.maximum_rto)?,
            u64::from(self.gate_attempts),
            self.path_mtu as u64,
            self.outer_overhead as u64,
            self.arq.max_source_bytes as u64,
            self.arq.send_bytes as u64,
            self.arq.receive_bytes as u64,
            self.arq.send_records as u64,
            self.arq.receive_records as u64,
            micros(self.arq.initial_rto)?,
            micros(self.arq.maximum_rto)?,
            micros(self.arq.ack_delay)?,
            u64::from(self.arq.max_retries),
            u64::from(self.control_packets),
            self.control_bytes as u64,
        ] {
            context.update(&value.to_be_bytes());
        }
        Ok(hash_array(context.finish()))
    }

    fn validate(self) -> Result<(), Error> {
        // Control keeps the fixed 48-byte ACK its charges and parser assume.
        if self.arq.wide_feedback() {
            return Err(Error::Configuration);
        }
        let bad_v6 = |addr: SocketAddr| matches!(addr, SocketAddr::V6(value) if value.scope_id() != 0 || value.flowinfo() != 0);
        if self.path.server.port() == 0
            || self.path.server.ip().is_unspecified()
            || self.path.server.ip().is_multicast()
            || bad_v6(self.path.server)
        {
            return Err(Error::Configuration);
        }
        if !self.path.is_dynamic_client()
            && (self.path.client.port() == 0
                || self.path.client.ip().is_unspecified()
                || self.path.client.ip().is_multicast()
                || bad_v6(self.path.client))
        {
            return Err(Error::Configuration);
        }
        if bad_v6(self.path.client) {
            return Err(Error::Configuration);
        }
        if self.path.client == self.path.server
            || self.path.client.is_ipv4() != self.path.server.is_ipv4()
            || self.key_id == 0
            || self.cookie_ttl.is_zero()
            || self.cookie_ttl > self.handshake_timeout
            || self.handshake_timeout > Duration::from_secs(120)
            || !(1..=1024).contains(&self.pending_sessions)
            || self.interval.is_zero()
            || self.interval > Duration::from_secs(1)
            || !(1..=4096).contains(&self.gate_responses)
            || self.initial_rto.is_zero()
            || self.maximum_rto < self.initial_rto
            || self.maximum_rto > self.handshake_timeout
            || !(1..=1024).contains(&self.gate_attempts)
            || !(256..=65535).contains(&self.path_mtu)
            || self.outer_overhead < if self.path.client.is_ipv4() { 28 } else { 48 }
            || self.outer_overhead >= self.path_mtu
            || self.control_packets < 2
            || self.control_packets > 4096
            || self.control_bytes < self.path_mtu + self.ack_charge()
            || self.control_bytes > 16 * 1024 * 1024
            || self.arq.send_bytes > 4 * 1024 * 1024
            || self.arq.receive_bytes > 4 * 1024 * 1024
            || self.arq.max_retries > 1024
            || self
                .path_mtu
                .checked_sub(self.outer_overhead + CONTROL_OVERHEAD + 44)
                .is_none_or(|maximum| self.arq.max_source_bytes > maximum)
        {
            return Err(Error::Configuration);
        }
        for value in [
            self.cookie_ttl,
            self.handshake_timeout,
            self.interval,
            self.initial_rto,
            self.maximum_rto,
            self.arq.initial_rto,
            self.arq.maximum_rto,
            self.arq.ack_delay,
        ] {
            if !value.subsec_nanos().is_multiple_of(1000) {
                return Err(Error::Configuration);
            }
            micros(value)?;
        }
        l2tunnel_recovery::SelectiveRepeat::new(
            self.arq,
            l2tunnel_recovery::RecoveryContext {
                session: 1,
                epoch: 1,
                role: l2tunnel_recovery::EndpointRole::Initiator,
            },
        )
        .map_err(Error::Recovery)?;
        Ok(())
    }
    fn ack_charge(self) -> usize {
        self.outer_overhead + CONTROL_OVERHEAD + 48
    }
    fn max_datagram(self) -> usize {
        self.path_mtu - self.outer_overhead
    }
}

/// Operational or trusted-configuration failure; contains no secrets or peer payloads.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// Invalid finite policy, endpoint or profile.
    Configuration,
    /// Nonce must be fresh unpredictable nonzero bytes supplied by the caller.
    Nonce,
    /// Injected time regressed.
    TimeRegression,
    /// Deadline calculation exceeded supported integer time.
    TimeOverflow,
    /// Original absolute bootstrap deadline expired.
    Expired,
    /// Finite retry count exhausted.
    RetryExhausted,
    /// Pending or byte retention capacity is full.
    Capacity,
    /// A ticket was already produced by this client gate.
    AlreadyAccepted,
    /// The trusted owner already promoted this control engine once.
    AlreadyPromoted,
    /// The framed control packet failed a strict encoding or context check.
    Malformed,
    /// Packet MAC failed before recovery mutation.
    Authentication,
    /// Counter/key-use space exhausted; create a new session.
    CounterExhausted,
    /// Caller output is smaller than the configured complete datagram ceiling.
    OutputTooSmall,
    /// Maintained HKDF rejected the requested key size.
    Crypto,
    /// Inner bounded recovery rejected the authenticated record.
    Recovery(RecoveryError),
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "UDP control error: {self:?}")
    }
}
impl std::error::Error for Error {}
impl From<RecoveryError> for Error {
    fn from(value: RecoveryError) -> Self {
        Self::Recovery(value)
    }
}

fn micros(time: Duration) -> Result<u64, Error> {
    u64::try_from(time.as_micros()).map_err(|_| Error::TimeOverflow)
}
fn now_check(now: Duration, previous: Duration, deadline: Duration) -> Result<(), Error> {
    if now < previous {
        return Err(Error::TimeRegression);
    }
    if now >= deadline {
        return Err(Error::Expired);
    }
    micros(now)?;
    Ok(())
}
fn add(time: Duration, delay: Duration) -> Result<Duration, Error> {
    let end = time.checked_add(delay).ok_or(Error::TimeOverflow)?;
    micros(end)?;
    Ok(end)
}
fn path_bytes(path: Path) -> [u8; 38] {
    let mut output = [0; 38];
    for (address, output) in [path.client, path.server]
        .into_iter()
        .zip(output.chunks_mut(19))
    {
        match address.ip() {
            std::net::IpAddr::V4(ip) => {
                output[0] = 4;
                output[13..17].copy_from_slice(&ip.octets());
            }
            std::net::IpAddr::V6(ip) => {
                output[0] = 6;
                output[1..17].copy_from_slice(&ip.octets());
            }
        }
        output[17..19].copy_from_slice(&address.port().to_be_bytes());
    }
    output
}
fn hash_array(value: digest::Digest) -> [u8; 32] {
    let mut bytes = [0; 32];
    bytes.copy_from_slice(value.as_ref());
    bytes
}
fn mac(key: &Secret, domain: &[u8], frame: &[u8], path: Path) -> [u8; 32] {
    let key = hmac::Key::new(hmac::HMAC_SHA256, &key.0[..]);
    let mut context = hmac::Context::with_key(&key);
    context.update(domain);
    context.update(frame);
    context.update(&path_bytes(path));
    let mut bytes = [0; 32];
    bytes.copy_from_slice(context.sign().as_ref());
    bytes
}
fn verify_mac(key: &Secret, domain: &[u8], frame: &[u8], path: Path, tag: &[u8]) -> bool {
    // ring performs constant-time tag comparison; callers first bound frame length.
    let mut input = Vec::with_capacity(domain.len() + frame.len() + 38);
    input.extend_from_slice(domain);
    input.extend_from_slice(frame);
    input.extend_from_slice(&path_bytes(path));
    hmac::verify(&hmac::Key::new(hmac::HMAC_SHA256, &key.0[..]), &input, tag).is_ok()
}
struct KeySize;
impl hkdf::KeyType for KeySize {
    fn len(&self) -> usize {
        32
    }
}
fn derive(key: &Secret, context: &[u8], role: u8) -> Result<Secret, Error> {
    let salt = hkdf::Salt::new(
        hkdf::HKDF_SHA256,
        b"l2tunnel/openvpn-like/control-extract/v1\0",
    );
    let prk = salt.extract(&key.0[..]);
    let direction = [role];
    let info = [
        b"l2tunnel/openvpn-like/control-key/v1\0".as_slice(),
        context,
        &direction,
    ];
    let okm = prk.expand(&info, KeySize).map_err(|_| Error::Crypto)?;
    let mut output = Secret::new([0; 32]);
    okm.fill(&mut output.0[..]).map_err(|_| Error::Crypto)?;
    Ok(output)
}
