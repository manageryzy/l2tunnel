use std::sync::Arc;
use std::time::Duration;

use l2tunnel_auth::{Direction, ServerIdentity, SessionConfig};
use l2tunnel_core::ConfigDigest;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};

use super::{Error, HEADER, hash};

/// Permitted application DATAGRAM direction; control always remains bidirectional.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Traffic {
    /// Both roles may send native data.
    FullDuplex,
    /// Only the specified global role sends native data on this physical connection.
    HalfDuplex {
        /// Global sender, independent of local endpoint perspective.
        sender: Direction,
    },
}
impl Traffic {
    pub(super) fn allows(self, direction: Direction) -> bool {
        match self {
            Self::FullDuplex => true,
            Self::HalfDuplex { sender } => sender == direction,
        }
    }
}
/// Explicit framing selection, authenticated before carrier member acceptance.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DatagramFormat {
    /// Existing private envelope and carrier-owned replay window.
    Legacy,
    /// Explicit Common bootstrap followed by externally protected compact records.
    CommonCompact,
}
/// Canonical peer-agreed profile, included in the member authentication digest.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Profile {
    /// Required opaque configured ALPN identifier. Observable on the wire; no zero/default name.
    pub application_id: [u8; 16],
    /// Native DATAGRAM direction; control always works both ways.
    pub traffic: Traffic,
    /// Physical lane identity included in the authenticated profile.
    pub lane: u32,
    /// Explicit authenticated framing; legacy callers retain their original bytes.
    pub datagram_format: DatagramFormat,
    /// Maximum application payload for Legacy, or complete final Common record.
    pub max_datagram_bytes: usize,
    /// Queue byte allowance in maximum-sized record units, including metadata headroom.
    /// Smaller records may occupy more entries. Receive metadata is charged by
    /// Quinn; send entry count uses the selected minimum complete DATAGRAM size.
    pub queued_datagrams: usize,
    /// Per-connection reliable control send/receive window in bytes.
    pub control_window_bytes: usize,
    /// Fixed UDP payload ceiling (not IP MTU), at least QUIC's 1200-byte minimum.
    pub udp_payload_ceiling: u16,
    /// QUIC idle timeout; data can keep this alive even when Control is not polled.
    pub idle_timeout: Duration,
    /// Finite individual DATAGRAM send/receive deadline.
    pub io_timeout: Duration,
}
impl Profile {
    /// Conservative profile with full data direction; callers choose half lanes explicitly.
    pub fn new(application_id: [u8; 16]) -> Self {
        Self {
            application_id,
            traffic: Traffic::FullDuplex,
            lane: 0,
            datagram_format: DatagramFormat::Legacy,
            max_datagram_bytes: 1024,
            queued_datagrams: 32,
            control_window_bytes: 65536,
            udp_payload_ceiling: 1200,
            idle_timeout: Duration::from_secs(30),
            io_timeout: Duration::from_secs(10),
        }
    }
    /// Validate finite bytes/count/time bounds and conservative QUIC packet headroom.
    pub fn validate(self) -> Result<(), Error> {
        if self.application_id == [0; 16] {
            return Err(Error::Configuration(
                "application identifier must be explicitly configured",
            ));
        }
        let envelope = match self.datagram_format {
            DatagramFormat::Legacy => HEADER,
            DatagramFormat::CommonCompact => 0,
        };
        if !(1200..=65507).contains(&self.udp_payload_ceiling)
            || self.max_datagram_bytes == 0
            || self.max_datagram_bytes
                > usize::from(self.udp_payload_ceiling).saturating_sub(128 + envelope)
            || (self.datagram_format == DatagramFormat::CommonCompact
                && self.max_datagram_bytes <= HEADER)
            || !(1..=1024).contains(&self.queued_datagrams)
            || !(1024..=1048576).contains(&self.control_window_bytes)
        {
            return Err(Error::Configuration(
                "invalid packet, queue, MTU or control bound",
            ));
        }
        valid_duration(self.idle_timeout)?;
        valid_duration(self.io_timeout)?;
        Ok(())
    }
    /// Complete maximum DATAGRAM queued in maintained QUIC, excluding QUIC framing.
    pub fn maximum_carrier_bytes(self) -> usize {
        self.max_datagram_bytes
            .saturating_add(if self.datagram_format == DatagramFormat::Legacy {
                HEADER
            } else {
                0
            })
    }
    /// Maximum payload accepted under the retained post-member bootstrap envelope.
    pub fn maximum_bootstrap_bytes(self) -> usize {
        match self.datagram_format {
            DatagramFormat::Legacy => self.max_datagram_bytes,
            DatagramFormat::CommonCompact => self.max_datagram_bytes.saturating_sub(HEADER),
        }
    }
    /// Configured maintained queue bytes; neither packet emission nor exact heap usage.
    pub fn datagram_queue_bytes(self) -> Result<usize, Error> {
        self.validate()?;
        self.maximum_carrier_bytes()
            .checked_add(64)
            .and_then(|value| value.checked_mul(self.queued_datagrams))
            .ok_or(Error::Configuration("datagram queue overflow"))
    }
    /// Conservative send-entry count from the authenticated minimum record size.
    pub fn maximum_queued_send_entries(self) -> Result<usize, Error> {
        let minimum = if self.datagram_format == DatagramFormat::Legacy {
            HEADER + 1
        } else {
            9
        };
        Ok(self.datagram_queue_bytes()?.div_ceil(minimum))
    }
}
/// Local endpoint resource ceilings, not negotiated application semantics.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EndpointLimits {
    /// Maximum simultaneous admitted preauth or authenticated sessions.
    pub max_connections: usize,
    /// Maximum buffered unaccepted incoming handshakes.
    pub pending_connections: usize,
    /// Total TLS/member/capability-exchange timeout after admission, excluding listener wait.
    pub handshake_timeout: Duration,
}
impl Default for EndpointLimits {
    fn default() -> Self {
        Self {
            max_connections: 32,
            pending_connections: 16,
            handshake_timeout: Duration::from_secs(10),
        }
    }
}
impl EndpointLimits {
    fn validate(self) -> Result<(), Error> {
        if !(1..=1024).contains(&self.max_connections)
            || !(1..=1024).contains(&self.pending_connections)
        {
            return Err(Error::Configuration("invalid connection capacity"));
        }
        valid_duration(self.handshake_timeout)
    }
}
fn valid_duration(value: Duration) -> Result<(), Error> {
    if value.is_zero() || value > Duration::from_secs(120) {
        return Err(Error::Configuration(
            "deadline must be positive and at most 120 seconds",
        ));
    }
    Ok(())
}
/// Bind the native/session digest to every exact versioned QUIC profile field.
pub fn session_config(base: SessionConfig, profile: Profile) -> Result<SessionConfig, Error> {
    profile.validate()?;
    let mut bytes = Vec::with_capacity(160);
    bytes.extend_from_slice(match profile.datagram_format {
        DatagramFormat::Legacy => b"l2tunnel/genuine-quic/profile/v1\0",
        DatagramFormat::CommonCompact => b"l2tunnel/genuine-quic/common-compact/v1\0",
    });
    bytes.push(match base.layer {
        l2tunnel_device::PacketLayer::Ethernet => 1,
        l2tunnel_device::PacketLayer::Ip => 2,
    });
    bytes.extend_from_slice(&base.digest.0);
    bytes.extend_from_slice(&profile.application_id);
    bytes.push(match profile.traffic {
        Traffic::FullDuplex => 0,
        Traffic::HalfDuplex {
            sender: Direction::ClientToServer,
        } => 1,
        Traffic::HalfDuplex {
            sender: Direction::ServerToClient,
        } => 2,
    });
    bytes.extend_from_slice(&profile.lane.to_be_bytes());
    for value in [
        profile.max_datagram_bytes,
        profile.queued_datagrams,
        profile.control_window_bytes,
    ] {
        bytes.extend_from_slice(
            &u64::try_from(value)
                .map_err(|_| Error::Configuration("profile integer overflow"))?
                .to_be_bytes(),
        );
    }
    bytes.extend_from_slice(&profile.udp_payload_ceiling.to_be_bytes());
    for value in [profile.idle_timeout, profile.io_timeout] {
        bytes.extend_from_slice(&value.as_secs().to_be_bytes());
        bytes.extend_from_slice(&value.subsec_nanos().to_be_bytes());
    }
    Ok(SessionConfig {
        layer: base.layer,
        digest: ConfigDigest(hash(&bytes)),
    })
}
/// Verified QUIC client TLS settings; no SNI, early data or resumption.
#[derive(Clone)]
pub struct ClientConfig {
    pub(super) inner: quinn::ClientConfig,
    pub(super) profile: Profile,
    pub(super) limits: EndpointLimits,
}
/// QUIC server TLS settings plus its exact certificate identity.
#[derive(Clone)]
pub struct ServerConfig {
    pub(super) inner: quinn::ServerConfig,
    pub(super) identity: ServerIdentity,
    pub(super) profile: Profile,
    pub(super) limits: EndpointLimits,
}
impl ClientConfig {
    /// Build TLS 1.3 certificate/name verification from bounded DER trust roots.
    pub fn from_der_roots(
        certificates: &[Vec<u8>],
        profile: Profile,
        limits: EndpointLimits,
    ) -> Result<Self, Error> {
        profile.validate()?;
        limits.validate()?;
        validate_certs(certificates, 64)?;
        let mut roots = rustls::RootCertStore::empty();
        for certificate in certificates {
            roots
                .add(CertificateDer::from(certificate.clone()))
                .map_err(|_| Error::Configuration("invalid root certificate"))?;
        }
        let mut tls = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|_| Error::Configuration("TLS 1.3 configuration"))?
        .with_root_certificates(roots)
        .with_no_client_auth();
        tls.enable_sni = false;
        tls.enable_early_data = false;
        tls.resumption = rustls::client::Resumption::disabled();
        tls.alpn_protocols = vec![profile.application_id.to_vec()];
        let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(tls)
            .map_err(|_| Error::Configuration("QUIC TLS provider"))?;
        let mut inner = quinn::ClientConfig::new(Arc::new(crypto));
        inner.transport_config(Arc::new(transport(profile, false)?));
        Ok(Self {
            inner,
            profile,
            limits,
        })
    }
}
impl ServerConfig {
    /// Build a TLS 1.3 server from bounded DER leaf-first certificate chain and key.
    pub fn from_der(
        certificates: &[Vec<u8>],
        key: &[u8],
        profile: Profile,
        limits: EndpointLimits,
    ) -> Result<Self, Error> {
        profile.validate()?;
        limits.validate()?;
        validate_certs(certificates, 16)?;
        if key.is_empty() || key.len() > 65536 {
            return Err(Error::Configuration("invalid key length"));
        }
        let private = PrivateKeyDer::try_from(key.to_vec())
            .map_err(|_| Error::Configuration("invalid private key"))?;
        let chain = certificates
            .iter()
            .cloned()
            .map(CertificateDer::from)
            .collect();
        let mut tls = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|_| Error::Configuration("TLS 1.3 configuration"))?
        .with_no_client_auth()
        .with_single_cert(chain, private)
        .map_err(|_| Error::Configuration("invalid TLS certificate/key"))?;
        tls.max_early_data_size = 0;
        tls.send_tls13_tickets = 0;
        tls.session_storage = Arc::new(rustls::server::NoServerSessionStorage {});
        tls.alpn_protocols = vec![profile.application_id.to_vec()];
        let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls)
            .map_err(|_| Error::Configuration("QUIC TLS provider"))?;
        let mut inner = quinn::ServerConfig::with_crypto(Arc::new(crypto));
        inner.transport_config(Arc::new(transport(profile, true)?));
        inner.migration(false);
        inner.max_incoming(limits.pending_connections);
        inner.incoming_buffer_size(65536);
        inner.incoming_buffer_size_total(
            u64::try_from(limits.pending_connections)
                .map_err(|_| Error::Configuration("pending capacity overflow"))?
                * 65536,
        );
        // Quinn Retry timestamps have whole-second precision. Keep subsecond
        // authentication deadlines independent from token rounding.
        inner.retry_token_lifetime(limits.handshake_timeout.max(Duration::from_secs(2)));
        Ok(Self {
            inner,
            identity: ServerIdentity(hash(&certificates[0])),
            profile,
            limits,
        })
    }
}
fn validate_certs(certs: &[Vec<u8>], max: usize) -> Result<(), Error> {
    if certs.is_empty()
        || certs.len() > max
        || certs.iter().any(|x| x.is_empty() || x.len() > 65536)
    {
        return Err(Error::Configuration("invalid certificate count/length"));
    }
    Ok(())
}
fn transport(profile: Profile, server: bool) -> Result<quinn::TransportConfig, Error> {
    let mut config = quinn::TransportConfig::default();
    config.max_concurrent_bidi_streams(u32::from(server).into());
    config.max_concurrent_uni_streams(0u32.into());
    let window = u32::try_from(profile.control_window_bytes)
        .map_err(|_| Error::Configuration("control window overflow"))?;
    config.stream_receive_window(window.into());
    config.receive_window(window.into());
    config.send_window(u64::from(window));
    config.max_idle_timeout(Some(
        profile
            .idle_timeout
            .try_into()
            .map_err(|_| Error::Configuration("idle timeout overflow"))?,
    ));
    config.initial_mtu(profile.udp_payload_ceiling);
    config.min_mtu(profile.udp_payload_ceiling);
    config.mtu_discovery_config(None);
    config.crypto_buffer_size(65536);
    config.allow_spin(false);
    let bytes = profile.datagram_queue_bytes()?;
    config.datagram_receive_buffer_size(Some(bytes));
    config.datagram_send_buffer_size(bytes);
    Ok(config)
}
