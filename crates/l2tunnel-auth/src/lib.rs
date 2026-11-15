//! TLS 1.3 TCP adapter with exporter-bound Ed25519 member authentication.
//!
//! This runtime adapter intentionally depends on Tokio and sockets; protocol-core crates
//! do not. No application stream is returned until the bounded authentication exchange
//! completes. The adapter does not implement traffic framing, device setup or cover protocols.

use std::fmt;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use l2tunnel_core::ConfigDigest;
use l2tunnel_device::PacketLayer;
use ring::digest::{SHA256, digest};
use ring::rand::{SecureRandom, SystemRandom};
use ring::signature::Ed25519KeyPair;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::{TlsAcceptor, TlsConnector, TlsStream};
use zeroize::Zeroizing;

pub mod https_request;

const AUTH_VERSION: u8 = 1;
const MAX_BODY: usize = 192;
const CHALLENGE: u8 = 1;
const PROOF: u8 = 2;
const ACCEPT: u8 = 3;
const FINISH: u8 = 4;
const READY: u8 = 5;
const CHALLENGE_LEN: usize = 113;
const PROOF_PREFIX_LEN: usize = 97;
const PROOF_LEN: usize = PROOF_PREFIX_LEN + 64;
const TRANSCRIPT_DOMAIN: &[u8] = b"l2tunnel/member-auth/v1\0";
const EXPORTER_LABEL: &[u8] = b"EXPORTER-l2tunnel-member-proof-v1";

/// Authenticated transport domain; QUIC proofs cannot be transplanted into TCP TLS.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ChannelTransport {
    /// Existing TLS-over-TCP v1 protocol, preserving its original transcript.
    TcpTls,
    /// Genuine QUIC TLS 1.3, with a distinct member-proof domain.
    QuicTls,
    /// TLS records over the standalone reliable OpenVPN-like UDP control profile.
    OpenVpnLikeTls,
    /// Genuine verified TLS with HTTP/2 POST streaming on the same connection.
    HttpsH2,
}

impl ChannelTransport {
    /// Exporter label the verified transport must use on its own TLS connection.
    pub fn exporter_label(self) -> &'static [u8] {
        match self {
            Self::TcpTls => EXPORTER_LABEL,
            Self::QuicTls => b"EXPORTER-l2tunnel-quic-member-proof-v1",
            Self::OpenVpnLikeTls => b"EXPORTER-l2tunnel-openvpn-like-member-proof-v1",
            Self::HttpsH2 => b"EXPORTER-l2tunnel-https-h2-member-proof-v1",
        }
    }

    fn transcript_domain(self) -> &'static [u8] {
        match self {
            Self::TcpTls => TRANSCRIPT_DOMAIN,
            Self::QuicTls => b"l2tunnel/member-auth/quic/v1\0",
            Self::OpenVpnLikeTls => b"l2tunnel/member-auth/openvpn-like/v1\0",
            Self::HttpsH2 => b"l2tunnel/member-auth/https-h2/v1\0",
        }
    }
}

/// Verified TLS-record I/O profile; genuine QUIC has its own TLS transport adapter.
/// The profile selects authentication domains, not the underlying I/O implementation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TlsIoProfile {
    /// Original TLS-record domain, including existing TCP and raw TCP adapters.
    TcpTls,
    /// Standalone reliable UDP control carrying actual TLS records.
    OpenVpnLikeTls,
}
impl TlsIoProfile {
    fn channel(self) -> ChannelTransport {
        match self {
            Self::TcpTls => ChannelTransport::TcpTls,
            Self::OpenVpnLikeTls => ChannelTransport::OpenVpnLikeTls,
        }
    }
    fn key_label(self, purpose: KeyPurpose) -> &'static [u8] {
        match (self, purpose) {
            (Self::TcpTls, KeyPurpose::LaneJoin) => b"EXPORTER-l2tunnel-lane-join-v1",
            (Self::TcpTls, KeyPurpose::Management) => b"EXPORTER-l2tunnel-management-v1",
            (Self::TcpTls, KeyPurpose::Data) => b"EXPORTER-l2tunnel-data-v1",
            (Self::OpenVpnLikeTls, KeyPurpose::LaneJoin) => {
                b"EXPORTER-l2tunnel-openvpn-like-lane-join-v1"
            }
            (Self::OpenVpnLikeTls, KeyPurpose::Management) => {
                b"EXPORTER-l2tunnel-openvpn-like-management-v1"
            }
            (Self::OpenVpnLikeTls, KeyPurpose::Data) => b"EXPORTER-l2tunnel-openvpn-like-data-v1",
        }
    }
}

/// Caller assertion of prior secure-channel verification, NOT evidence by itself.
///
/// Only transport adapters that have completed TLS 1.3 and verified the server
/// certificate/name may construct this from that connection's exporter. Never
/// populate it from peer input. This value does not verify TLS or authenticate
/// arbitrary I/O; the generic exchange below depends on the caller's precondition.
/// Secret exporter bytes are zeroized and deliberately do not implement Debug.
pub struct CallerVerifiedChannel {
    transport: ChannelTransport,
    server: ServerIdentity,
    exporter: Zeroizing<[u8; 32]>,
}

impl CallerVerifiedChannel {
    /// Assert the documented verification preconditions for this exact stream.
    /// Export with `transport.exporter_label()` and an empty/absent context.
    pub fn new_after_verification(
        transport: ChannelTransport,
        server: ServerIdentity,
        exporter: [u8; 32],
    ) -> Self {
        Self {
            transport,
            server,
            exporter: Zeroizing::new(exporter),
        }
    }
}

/// Authenticate a member over caller-verified secure duplex I/O within a deadline.
///
/// The caller MUST establish the preconditions of `CallerVerifiedChannel` on
/// this exact I/O, disable early data and close it on failure/cancellation. This
/// function alone does not authenticate a transport or release application I/O.
pub async fn client_authenticate_channel<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    member: &MemberKey,
    config: SessionConfig,
    binding: &CallerVerifiedChannel,
    deadline: Duration,
) -> Result<SessionInfo, Error> {
    validate_timeout(deadline)?;
    timeout(deadline, client_exchange(stream, member, config, binding))
        .await
        .map_err(|_| Error::TimedOut)?
}

/// Verify allowlisted membership over caller-verified secure duplex I/O.
///
/// The same verification, early-data and close-on-error/cancellation requirements
/// as `client_authenticate_channel` apply. A binding constructor is not proof of
/// those requirements; the transport adapter is responsible for satisfying them.
pub async fn server_authenticate_channel<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    members: &MemberAllowlist,
    config: SessionConfig,
    binding: &CallerVerifiedChannel,
    deadline: Duration,
) -> Result<SessionInfo, Error> {
    validate_timeout(deadline)?;
    timeout(deadline, server_exchange(stream, members, config, binding))
        .await
        .map_err(|_| Error::TimedOut)?
}

/// Shared raw Ed25519 public member identity; contains no private key material.
pub use l2tunnel_identity::MemberPublicKey;

/// SHA-256 fingerprint of the exact server leaf DER certificate verified by TLS.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ServerIdentity(pub [u8; 32]);

/// Expected native packet layer and canonical configuration digest.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SessionConfig {
    /// Ethernet frames for TAP or raw IP packets for TUN.
    pub layer: PacketLayer,
    /// Digest computed from the canonical complete negotiated configuration.
    pub digest: ConfigDigest,
}

/// Completed authentication identities and binding, safe for non-secret status reporting.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SessionInfo {
    /// Fresh server-generated session identity bound into the member proof.
    pub session_id: [u8; 16],
    /// Server-side authenticated remote member; clients authenticate the server certificate.
    pub peer_member: Option<MemberPublicKey>,
    /// Authenticated client membership identity.
    pub member: MemberPublicKey,
    /// TLS-verified server certificate identity.
    pub server: ServerIdentity,
    /// Exact native layer and configuration accepted by both peers.
    pub config: SessionConfig,
}

/// Ed25519 private membership identity; deliberately does not implement Debug.
pub struct MemberKey(l2tunnel_identity::IdentityKey);

impl MemberKey {
    /// Generate a fresh PKCS#8 Ed25519 key for provisioning; output is secret and must not be logged.
    pub fn generate_pkcs8() -> Result<Vec<u8>, Error> {
        Ed25519KeyPair::generate_pkcs8(&SystemRandom::new())
            .map(|key| key.as_ref().to_vec())
            .map_err(|_| Error::Random)
    }

    /// Load a ring-validated PKCS#8 Ed25519 private key without logging its bytes.
    pub fn from_pkcs8(encoded: &[u8]) -> Result<Self, Error> {
        l2tunnel_identity::IdentityKey::from_pkcs8(encoded)
            .map(Self)
            .map_err(|_| Error::InvalidKey)
    }

    /// Public member identity suitable for the server allowlist.
    pub fn public_key(&self) -> MemberPublicKey {
        self.0.public_key()
    }
}

/// Immutable bounded allowlist of public Ed25519 member identities.
#[derive(Clone)]
pub struct MemberAllowlist(l2tunnel_identity::Allowlist);

impl MemberAllowlist {
    /// Validate and copy between 1 and 1,024 entries; duplicates are removed.
    pub fn new(keys: &[MemberPublicKey]) -> Result<Self, Error> {
        l2tunnel_identity::Allowlist::new(keys)
            .map(Self)
            .map_err(|_| Error::Configuration("allowlist must contain 1..=1024 entries"))
    }

    /// Check configured membership before I/O; this does not authenticate a peer.
    pub fn contains(&self, key: MemberPublicKey) -> bool {
        self.0.contains(key)
    }
}

/// Private, verified TLS 1.3 client configuration with no SNI or early data.
#[derive(Clone)]
pub struct ClientTls(Arc<ClientConfig>);

impl ClientTls {
    /// Build certificate-root and name verification from DER trust anchors.
    /// SNI, resumption and early data are disabled; certificate validation remains enabled.
    pub fn from_der_roots(certificates: &[Vec<u8>]) -> Result<Self, Error> {
        validate_certificates(certificates, 64)?;
        let mut roots = RootCertStore::empty();
        for encoded in certificates {
            roots
                .add(CertificateDer::from(encoded.clone()))
                .map_err(Error::Tls)?;
        }
        let mut config =
            ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_protocol_versions(&[&rustls::version::TLS13])
                .map_err(Error::Tls)?
                .with_root_certificates(roots)
                .with_no_client_auth();
        config.enable_sni = false;
        config.enable_early_data = false;
        config.resumption = rustls::client::Resumption::disabled();
        Ok(Self(Arc::new(config)))
    }
}

/// Private TLS 1.3 server configuration and its public certificate identity.
#[derive(Clone)]
pub struct ServerTls {
    config: Arc<ServerConfig>,
    identity: ServerIdentity,
}

impl ServerTls {
    /// Build a server from its DER certificate chain and DER private key.
    /// The first certificate must be the leaf. Client membership is checked after TLS.
    pub fn from_der(certificates: &[Vec<u8>], key_der: &[u8]) -> Result<Self, Error> {
        validate_certificates(certificates, 16)?;
        if key_der.is_empty() || key_der.len() > 65_536 {
            return Err(Error::InvalidKey);
        }
        let identity = ServerIdentity(hash(&certificates[0]));
        let key = PrivateKeyDer::try_from(key_der.to_vec()).map_err(|_| Error::InvalidKey)?;
        let chain = certificates
            .iter()
            .cloned()
            .map(CertificateDer::from)
            .collect();
        let mut config =
            ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_protocol_versions(&[&rustls::version::TLS13])
                .map_err(Error::Tls)?
                .with_no_client_auth()
                .with_single_cert(chain, key)
                .map_err(Error::Tls)?;
        config.max_early_data_size = 0;
        config.send_tls13_tickets = 0;
        config.session_storage = Arc::new(rustls::server::NoServerSessionStorage {});
        Ok(Self {
            config: Arc::new(config),
            identity,
        })
    }
}

fn validate_certificates(certificates: &[Vec<u8>], max: usize) -> Result<(), Error> {
    if certificates.is_empty()
        || certificates.len() > max
        || certificates
            .iter()
            .any(|cert| cert.is_empty() || cert.len() > 65_536)
    {
        return Err(Error::Configuration(
            "invalid certificate count or DER length",
        ));
    }
    Ok(())
}

/// Intended domain for exporter-derived key material.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KeyPurpose {
    /// Authenticating an additional lane join.
    LaneJoin,
    /// Protecting an internal management record.
    Management,
    /// Protecting user data in a separately implemented packet carrier.
    Data,
}

/// Cryptographic direction; labels do not depend on the local endpoint's viewpoint.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Direction {
    /// Client sends, server receives.
    ClientToServer,
    /// Server sends, client receives.
    ServerToClient,
}

/// Exported secret with no Debug implementation. Callers own secure handling and lifecycle.
pub struct Secret(Zeroizing<[u8; 32]>);

impl Secret {
    /// Explicit access for a maintained cryptographic implementation; never log these bytes.
    pub fn expose_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// The original TLS stream over caller-owned I/O, released only after authentication.
/// This type intentionally does not implement Debug.
pub struct AuthenticatedIo<S> {
    stream: TlsStream<S>,
    info: SessionInfo,
    profile: TlsIoProfile,
}

/// Existing socket API, retaining its concrete TLS/TCP stream type.
pub type AuthenticatedConnection = AuthenticatedIo<TcpStream>;

impl<S> AuthenticatedIo<S> {
    /// Exact profile used by actual TLS/member exchange and private exporter labels.
    pub fn profile(&self) -> TlsIoProfile {
        self.profile
    }
    /// Authenticated identities and matched session configuration.
    pub fn info(&self) -> &SessionInfo {
        &self.info
    }

    /// Transfer ownership of the same authenticated stream to a framing/runtime adapter.
    pub fn into_parts(self) -> (TlsStream<S>, SessionInfo) {
        (self.stream, self.info)
    }

    /// Derive a purpose/direction/lane-separated key from the established TLS exporter.
    /// No packet protection or key rotation is implemented by this helper.
    pub fn export_key(
        &self,
        purpose: KeyPurpose,
        direction: Direction,
        lane_id: u32,
    ) -> Result<Secret, Error> {
        let label = self.profile.key_label(purpose);
        let mut context = Vec::with_capacity(118);
        context.extend_from_slice(&self.info.session_id);
        context.extend_from_slice(&self.info.member.0);
        context.extend_from_slice(&self.info.server.0);
        context.push(layer_byte(self.info.config.layer));
        context.extend_from_slice(&self.info.config.digest.0);
        context.push(match direction {
            Direction::ClientToServer => 1,
            Direction::ServerToClient => 2,
        });
        context.extend_from_slice(&lane_id.to_be_bytes());
        export(&self.stream, label, Some(&context)).map(|bytes| Secret(Zeroizing::new(bytes)))
    }
}

impl AuthenticatedIo<TcpStream> {
    /// Retained socket's local address, useful for same-connection verification.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.stream.get_ref().0.local_addr()
    }

    /// Retained socket's remote address.
    pub fn peer_addr(&self) -> io::Result<SocketAddr> {
        self.stream.get_ref().0.peer_addr()
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for AuthenticatedIo<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_read(cx, buf)
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for AuthenticatedIo<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().stream).poll_write(cx, buf)
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_shutdown(cx)
    }
}

/// Establish TLS and member authentication over exact caller-owned reliable ordered I/O.
/// The caller owns transport semantics; this performs real TLS, not a binding assertion.
/// Failure/cancellation drops the supplied I/O; its owner must close the carrier.
/// Server name verification is required even though no SNI extension is emitted.
pub async fn client_connect_io<S: AsyncRead + AsyncWrite + Unpin>(
    io: S,
    tls: &ClientTls,
    server_name: &str,
    member: &MemberKey,
    config: SessionConfig,
    deadline: Duration,
) -> Result<AuthenticatedIo<S>, Error> {
    client_connect_profile_io(
        io,
        tls,
        server_name,
        member,
        config,
        TlsIoProfile::TcpTls,
        deadline,
    )
    .await
}

/// Establish actual verified TLS 1.3 and membership in an explicit I/O domain.
/// This does not prove that caller-owned I/O uses UDP; the runtime must bind its
/// carrier and full gate policy into `config.digest`. SessionConfig is opaque and
/// has no inspectable carrier field. No QUIC profile can be selected here.
/// Failure/cancellation drops I/O; TLS certificate/name verification and no-SNI
/// policy are identical to the original factory. No early application I/O escapes.
pub async fn client_connect_profile_io<S: AsyncRead + AsyncWrite + Unpin>(
    io: S,
    tls: &ClientTls,
    server_name: &str,
    member: &MemberKey,
    config: SessionConfig,
    profile: TlsIoProfile,
    deadline: Duration,
) -> Result<AuthenticatedIo<S>, Error> {
    validate_timeout(deadline)?;
    let name = ServerName::try_from(server_name.to_owned())
        .map_err(|_| Error::Configuration("invalid server verification name"))?;
    timeout(deadline, async {
        let stream = TlsConnector::from(tls.0.clone())
            .connect(name, io)
            .await
            .map_err(Error::Io)?;
        let mut stream = TlsStream::Client(stream);
        require_tls13(&stream)?;
        let certificate = stream
            .get_ref()
            .1
            .peer_certificates()
            .and_then(|chain| chain.first())
            .ok_or(Error::Protocol("missing verified server certificate"))?;
        let server = ServerIdentity(hash(certificate.as_ref()));
        let binding = profile_binding(&stream, server, profile)?;
        let info = client_exchange(&mut stream, member, config, &binding).await?;
        Ok(AuthenticatedIo {
            stream,
            info,
            profile,
        })
    })
    .await
    .map_err(|_| Error::TimedOut)?
}

/// Accept TLS and allowlisted member authentication over reliable ordered I/O.
/// Failure/cancellation drops the supplied I/O; its owner must close the carrier.
/// The total deadline includes TLS and every application handshake read/write.
pub async fn server_accept_io<S: AsyncRead + AsyncWrite + Unpin>(
    io: S,
    tls: &ServerTls,
    members: &MemberAllowlist,
    config: SessionConfig,
    deadline: Duration,
) -> Result<AuthenticatedIo<S>, Error> {
    server_accept_profile_io(io, tls, members, config, TlsIoProfile::TcpTls, deadline).await
}

/// Accept actual TLS/member authentication with an explicit TLS-record domain.
/// The caller must bind its actual carrier and gate policy into `config.digest`;
/// this selects proof/exporter domains, not socket semantics. The immutable
/// resulting profile cannot be changed to relabel an authenticated stream.
pub async fn server_accept_profile_io<S: AsyncRead + AsyncWrite + Unpin>(
    io: S,
    tls: &ServerTls,
    members: &MemberAllowlist,
    config: SessionConfig,
    profile: TlsIoProfile,
    deadline: Duration,
) -> Result<AuthenticatedIo<S>, Error> {
    validate_timeout(deadline)?;
    timeout(deadline, async {
        let stream = TlsAcceptor::from(tls.config.clone())
            .accept(io)
            .await
            .map_err(Error::Io)?;
        let mut stream = TlsStream::Server(stream);
        require_tls13(&stream)?;
        let binding = profile_binding(&stream, tls.identity, profile)?;
        let info = server_exchange(&mut stream, members, config, &binding).await?;
        Ok(AuthenticatedIo {
            stream,
            info,
            profile,
        })
    })
    .await
    .map_err(|_| Error::TimedOut)?
}

/// Establish verified TLS/member authentication on this exact TCP socket.
pub async fn client_connect(
    tcp: TcpStream,
    tls: &ClientTls,
    server_name: &str,
    member: &MemberKey,
    config: SessionConfig,
    deadline: Duration,
) -> Result<AuthenticatedConnection, Error> {
    client_connect_io(tcp, tls, server_name, member, config, deadline).await
}

/// Accept verified TLS/member authentication on this exact TCP socket.
pub async fn server_accept(
    tcp: TcpStream,
    tls: &ServerTls,
    members: &MemberAllowlist,
    config: SessionConfig,
    deadline: Duration,
) -> Result<AuthenticatedConnection, Error> {
    server_accept_io(tcp, tls, members, config, deadline).await
}

fn validate_timeout(duration: Duration) -> Result<(), Error> {
    if duration.is_zero() || duration > Duration::from_secs(120) {
        return Err(Error::Configuration(
            "authentication timeout must be positive and at most 120 seconds",
        ));
    }
    Ok(())
}

fn require_tls13<S>(stream: &TlsStream<S>) -> Result<(), Error> {
    if stream.get_ref().1.protocol_version() != Some(rustls::ProtocolVersion::TLSv1_3) {
        return Err(Error::Protocol("TLS 1.3 required"));
    }
    Ok(())
}

#[cfg(test)]
fn tcp_binding<S>(
    stream: &TlsStream<S>,
    server: ServerIdentity,
) -> Result<CallerVerifiedChannel, Error> {
    profile_binding(stream, server, TlsIoProfile::TcpTls)
}

fn profile_binding<S>(
    stream: &TlsStream<S>,
    server: ServerIdentity,
    profile: TlsIoProfile,
) -> Result<CallerVerifiedChannel, Error> {
    let transport = profile.channel();
    Ok(CallerVerifiedChannel::new_after_verification(
        transport,
        server,
        export(stream, transport.exporter_label(), None)?,
    ))
}

async fn client_exchange<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    member: &MemberKey,
    config: SessionConfig,
    binding: &CallerVerifiedChannel,
) -> Result<SessionInfo, Error> {
    let server = binding.server;
    let challenge = read_frame::<CHALLENGE_LEN>(stream, CHALLENGE).await?;
    if challenge[48..80] != server.0 {
        return Err(Error::BindingMismatch);
    }
    check_config(&challenge[80..], config)?;
    let mut proof = [0; PROOF_LEN];
    random_fill(&mut proof[..32])?;
    proof[32..64].copy_from_slice(&member.public_key().0);
    write_config(&mut proof[64..97], config);
    let transcript = bound_transcript(binding, &challenge, &proof[..PROOF_PREFIX_LEN])?;
    let signature = member
        .0
        .sign(&transcript)
        .map_err(|_| Error::InvalidProof)?;
    proof[PROOF_PREFIX_LEN..].copy_from_slice(&signature);
    write_frame(stream, PROOF, &proof).await?;
    let accepted = read_frame::<48>(stream, ACCEPT).await?;
    let transcript_hash = hash(&transcript);
    if accepted[..16] != challenge[32..48] || accepted[16..] != transcript_hash {
        return Err(Error::BindingMismatch);
    }
    write_frame(stream, FINISH, &transcript_hash).await?;
    if read_frame::<32>(stream, READY).await? != transcript_hash {
        return Err(Error::BindingMismatch);
    }
    Ok(SessionInfo {
        session_id: copy_array(&challenge[32..48])?,
        peer_member: None,
        member: member.public_key(),
        server,
        config,
    })
}

async fn server_exchange<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    members: &MemberAllowlist,
    config: SessionConfig,
    binding: &CallerVerifiedChannel,
) -> Result<SessionInfo, Error> {
    let server = binding.server;
    let mut challenge = [0; CHALLENGE_LEN];
    random_fill(&mut challenge[..48])?;
    challenge[48..80].copy_from_slice(&server.0);
    write_config(&mut challenge[80..], config);
    write_frame(stream, CHALLENGE, &challenge).await?;
    let proof = read_frame::<PROOF_LEN>(stream, PROOF).await?;
    let member = MemberPublicKey(copy_array(&proof[32..64])?);
    check_config(&proof[64..97], config)?;
    if !members.contains(member) {
        return Err(Error::MemberDenied);
    }
    let transcript = bound_transcript(binding, &challenge, &proof[..PROOF_PREFIX_LEN])?;
    l2tunnel_identity::verify_signature(member, &transcript, &proof[PROOF_PREFIX_LEN..])
        .map_err(|_| Error::InvalidProof)?;
    let transcript_hash = hash(&transcript);
    let mut accepted = [0; 48];
    accepted[..16].copy_from_slice(&challenge[32..48]);
    accepted[16..].copy_from_slice(&transcript_hash);
    write_frame(stream, ACCEPT, &accepted).await?;
    if read_frame::<32>(stream, FINISH).await? != transcript_hash {
        return Err(Error::BindingMismatch);
    }
    write_frame(stream, READY, &transcript_hash).await?;
    Ok(SessionInfo {
        session_id: copy_array(&challenge[32..48])?,
        peer_member: Some(member),
        member,
        server,
        config,
    })
}

fn layer_byte(layer: PacketLayer) -> u8 {
    match layer {
        PacketLayer::Ethernet => 1,
        PacketLayer::Ip => 2,
    }
}

fn write_config(output: &mut [u8], config: SessionConfig) {
    output[0] = layer_byte(config.layer);
    output[1..33].copy_from_slice(&config.digest.0);
}

fn check_config(input: &[u8], config: SessionConfig) -> Result<(), Error> {
    if input.len() != 33 || input[0] != layer_byte(config.layer) || input[1..] != config.digest.0 {
        return Err(Error::BindingMismatch);
    }
    Ok(())
}

#[cfg(test)]
fn transcript(
    stream: &TlsStream<TcpStream>,
    challenge: &[u8; CHALLENGE_LEN],
    proof_prefix: &[u8],
) -> Result<Zeroizing<Vec<u8>>, Error> {
    let binding = tcp_binding(stream, ServerIdentity(copy_array(&challenge[48..80])?))?;
    bound_transcript(&binding, challenge, proof_prefix)
}

fn bound_transcript(
    binding: &CallerVerifiedChannel,
    challenge: &[u8; CHALLENGE_LEN],
    proof_prefix: &[u8],
) -> Result<Zeroizing<Vec<u8>>, Error> {
    if proof_prefix.len() != PROOF_PREFIX_LEN {
        return Err(Error::Protocol("invalid proof prefix"));
    }
    let domain = binding.transport.transcript_domain();
    let mut bytes = Zeroizing::new(Vec::with_capacity(
        domain.len() + 32 + CHALLENGE_LEN + PROOF_PREFIX_LEN,
    ));
    bytes.extend_from_slice(domain);
    bytes.extend_from_slice(&binding.exporter[..]);
    bytes.extend_from_slice(challenge);
    bytes.extend_from_slice(proof_prefix);
    Ok(bytes)
}

fn export<S>(
    stream: &TlsStream<S>,
    label: &[u8],
    context: Option<&[u8]>,
) -> Result<[u8; 32], Error> {
    match stream {
        TlsStream::Client(tls) => tls
            .get_ref()
            .1
            .export_keying_material([0; 32], label, context),
        TlsStream::Server(tls) => tls
            .get_ref()
            .1
            .export_keying_material([0; 32], label, context),
    }
    .map_err(Error::Tls)
}

fn random_fill(output: &mut [u8]) -> Result<(), Error> {
    SystemRandom::new().fill(output).map_err(|_| Error::Random)
}

fn hash(input: &[u8]) -> [u8; 32] {
    let mut bytes = [0; 32];
    bytes.copy_from_slice(digest(&SHA256, input).as_ref());
    bytes
}

fn copy_array<const N: usize>(input: &[u8]) -> Result<[u8; N], Error> {
    input
        .try_into()
        .map_err(|_| Error::Protocol("invalid fixed-size field"))
}

async fn write_frame<S: AsyncWrite + Unpin>(
    stream: &mut S,
    kind: u8,
    body: &[u8],
) -> Result<(), Error> {
    if body.len() > MAX_BODY {
        return Err(Error::Protocol("authentication body too large"));
    }
    let len =
        u16::try_from(body.len()).map_err(|_| Error::Protocol("authentication body too large"))?;
    let mut header = [0; 8];
    header[..4].copy_from_slice(b"L2AU");
    header[4] = AUTH_VERSION;
    header[5] = kind;
    header[6..].copy_from_slice(&len.to_be_bytes());
    stream.write_all(&header).await.map_err(Error::Io)?;
    stream.write_all(body).await.map_err(Error::Io)?;
    stream.flush().await.map_err(Error::Io)
}

async fn read_frame<const N: usize>(
    stream: &mut (impl AsyncRead + Unpin),
    kind: u8,
) -> Result<[u8; N], Error> {
    let mut header = [0; 8];
    stream.read_exact(&mut header).await.map_err(Error::Io)?;
    let len = usize::from(u16::from_be_bytes([header[6], header[7]]));
    if header[..4] != *b"L2AU"
        || header[4] != AUTH_VERSION
        || header[5] != kind
        || len != N
        || len > MAX_BODY
    {
        return Err(Error::Protocol("unexpected authentication frame"));
    }
    let mut body = [0; N];
    stream.read_exact(&mut body).await.map_err(Error::Io)?;
    Ok(body)
}

/// Explicit failures; no error contains private key, nonce, exporter or proof bytes.
#[derive(Debug)]
pub enum Error {
    /// Invalid local non-secret configuration.
    Configuration(&'static str),
    /// Invalid private-key encoding; key bytes are not retained in the error.
    InvalidKey,
    /// TLS configuration or exporter failure.
    Tls(rustls::Error),
    /// Socket/TLS-stream I/O or certificate handshake failure.
    Io(io::Error),
    /// Total TLS/member-handshake deadline expired.
    TimedOut,
    /// Peer sent an invalid or unexpected bounded handshake message.
    Protocol(&'static str),
    /// Session, identity, configuration or completion hash did not match.
    BindingMismatch,
    /// Public member identity is not authorized.
    MemberDenied,
    /// Ed25519 proof verification failed.
    InvalidProof,
    /// Operating-system random source failed.
    Random,
}

impl fmt::Display for Error {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Configuration(message) => {
                write!(output, "authentication configuration: {message}")
            }
            Self::InvalidKey => output.write_str("invalid private key"),
            Self::Tls(_) => output.write_str("TLS configuration or exporter failed"),
            Self::Io(_) => output.write_str("TLS/socket I/O failed"),
            Self::TimedOut => output.write_str("authentication deadline expired"),
            Self::Protocol(message) => write!(output, "authentication protocol: {message}"),
            Self::BindingMismatch => output.write_str("authentication binding mismatch"),
            Self::MemberDenied => output.write_str("member is not authorized"),
            Self::InvalidProof => output.write_str("member proof verification failed"),
            Self::Random => output.write_str("secure random source failed"),
        }
    }
}

impl std::error::Error for Error {}

#[cfg(test)]
mod tests;
