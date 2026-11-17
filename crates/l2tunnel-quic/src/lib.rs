//! Genuine UDP-only QUIC/TLS 1.3 runtime carrier with allowlisted member auth.
//!
//! This is distinct from custom QUIC-like headers. No native devices, MUX or
//! recovery engine are provided. QUIC always encrypts; configured ALPN is visible.

pub mod common;
mod config;
mod owned_endpoint;
pub use config::{
    ClientConfig, DatagramFormat, EndpointLimits, Profile, ServerConfig, Traffic, session_config,
};

use std::fmt;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll};

use bytes::Bytes;
use l2tunnel_auth::{
    self as auth, ChannelTransport, Direction, MemberAllowlist, MemberKey, SessionConfig,
    SessionInfo,
};
use ring::digest::{SHA256, digest};
use ring::rand::{SecureRandom, SystemRandom};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::time::timeout;
use zeroize::Zeroizing;

const HEADER: usize = 48;
const PRELUDE: &[u8; 8] = b"L2QC\x01\0\0\0";

/// Bounded local, transport or authentication failure without secret material.
#[derive(Debug)]
pub enum Error {
    /// Invalid local profile, endpoint or certificate input.
    Configuration(&'static str),
    /// Local concurrent-session bound exhausted.
    Capacity,
    /// Complete handshake or individual datagram operation timed out.
    TimedOut,
    /// Transport or control stream closed or failed.
    Transport,
    /// I/O error while setting up or using the bounded control stream.
    Io(io::Error),
    /// TLS identity/configuration or member proof failed.
    Authentication(auth::Error),
    /// Invalid authenticated peer protocol or negotiated capacity.
    Protocol(&'static str),
    /// This half-duplex endpoint cannot perform the requested data operation.
    Direction,
    /// Local payload/output exceeds negotiated bounds.
    Size,
    /// Carrier sequence space is exhausted; establish a fresh session.
    Exhausted,
    /// Secure random source failed.
    Random,
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Configuration(s) => write!(f, "QUIC configuration: {s}"),
            Self::Capacity => f.write_str("QUIC session capacity exhausted"),
            Self::TimedOut => f.write_str("QUIC deadline expired"),
            Self::Transport => f.write_str("QUIC transport closed or failed"),
            Self::Io(_) => f.write_str("QUIC control I/O failed"),
            Self::Authentication(_) => f.write_str("QUIC authentication failed"),
            Self::Protocol(s) => write!(f, "QUIC protocol: {s}"),
            Self::Direction => f.write_str("QUIC data direction prohibited"),
            Self::Size => f.write_str("QUIC data size exceeds bound"),
            Self::Exhausted => f.write_str("QUIC sequence exhausted"),
            Self::Random => f.write_str("secure random source failed"),
        }
    }
}
impl std::error::Error for Error {}
impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}
impl From<auth::Error> for Error {
    fn from(e: auth::Error) -> Self {
        Self::Authentication(e)
    }
}

/// Client UDP endpoint with bounded concurrent admitted sessions.
pub struct ClientEndpoint {
    endpoint: quinn::Endpoint,
    config: ClientConfig,
    permits: Arc<Semaphore>,
    owner: owned_endpoint::Owner,
}
/// Server UDP endpoint with Retry and bounded pending/admitted handshakes.
pub struct ServerEndpoint {
    endpoint: quinn::Endpoint,
    config: ServerConfig,
    permits: Arc<Semaphore>,
    owner: owned_endpoint::Owner,
}

impl ClientEndpoint {
    /// Bind a UDP socket; wildcard/ephemeral local addresses are permitted.
    pub fn bind(local: SocketAddr, config: &ClientConfig) -> Result<Self, Error> {
        let (mut endpoint, owner) = owned_endpoint::bind(local, None, config.limits)?;
        endpoint.set_default_client_config(config.inner.clone());
        Ok(Self {
            endpoint,
            config: config.clone(),
            permits: Arc::new(Semaphore::new(config.limits.max_connections)),
            owner,
        })
    }
    /// Actual local UDP endpoint, including an assigned ephemeral port.
    pub fn local_addr(&self) -> Result<SocketAddr, Error> {
        Ok(self.endpoint.local_addr()?)
    }
    /// Verify server and member on this UDP-only connection; no application handle escapes early.
    pub async fn connect(
        &self,
        peer: SocketAddr,
        name: &str,
        member: &MemberKey,
        base: SessionConfig,
    ) -> Result<AuthenticatedConnection, Error> {
        validate_peer(peer, self.local_addr()?)?;
        let permit = self
            .permits
            .clone()
            .try_acquire_owned()
            .map_err(|_| Error::Capacity)?;
        let profile = self.config.profile;
        let cfg = session_config(base, profile)?;
        timeout(self.config.limits.handshake_timeout, async {
            let connection = self
                .endpoint
                .connect(peer, name)
                .map_err(|_| Error::Configuration("invalid peer or verification name"))?
                .await
                .map_err(|_| Error::Transport)?;
            let mut guard = CloseGuard(Some(connection.clone()));
            check_alpn(&connection, profile)?;
            let identity = connection
                .peer_identity()
                .and_then(|x| {
                    x.downcast::<Vec<rustls::pki_types::CertificateDer<'static>>>()
                        .ok()
                })
                .ok_or(Error::Protocol("missing verified server certificate"))?;
            let leaf = identity
                .first()
                .ok_or(Error::Protocol("empty verified server chain"))?;
            let binding = channel_binding(&connection, auth::ServerIdentity(hash(leaf.as_ref())))?;
            let (send, recv) = connection.open_bi().await.map_err(|_| Error::Transport)?;
            let mut stream = Stream { send, recv };
            stream.write_all(PRELUDE).await?;
            let info = auth::client_authenticate_channel(
                &mut stream,
                member,
                cfg,
                &binding,
                self.config.limits.handshake_timeout,
            )
            .await?;
            let tokens = client_gate(&mut stream, info.session_id).await?;
            let result = finish_connection(
                connection,
                (self.endpoint.clone(), self.owner.clone(), permit),
                stream,
                profile,
                info,
                Direction::ClientToServer,
                tokens,
            )?;
            guard.0 = None;
            Ok(result)
        })
        .await
        .map_err(|_| Error::TimedOut)?
    }
}
impl ServerEndpoint {
    /// Bind the UDP listener, without opening a TCP socket.
    pub fn bind(local: SocketAddr, config: &ServerConfig) -> Result<Self, Error> {
        let (endpoint, owner) =
            owned_endpoint::bind(local, Some(config.inner.clone()), config.limits)?;
        Ok(Self {
            endpoint,
            config: config.clone(),
            permits: Arc::new(Semaphore::new(config.limits.max_connections)),
            owner,
        })
    }
    /// Actual local UDP listener address.
    pub fn local_addr(&self) -> Result<SocketAddr, Error> {
        Ok(self.endpoint.local_addr()?)
    }
    /// Wait for an incoming connection, then bound TLS/member authentication time.
    /// Listener waiting has no deadline; cancel this future to stop waiting.
    pub async fn accept(
        &self,
        members: &MemberAllowlist,
        base: SessionConfig,
    ) -> Result<AuthenticatedConnection, Error> {
        let profile = self.config.profile;
        let cfg = session_config(base, profile)?;
        loop {
            let incoming = self.endpoint.accept().await.ok_or(Error::Transport)?;
            if !incoming.remote_address_validated() {
                incoming.retry().map_err(|_| Error::Transport)?;
                continue;
            }
            let permit = match self.permits.clone().try_acquire_owned() {
                Ok(permit) => permit,
                Err(_) => {
                    incoming.refuse();
                    return Err(Error::Capacity);
                }
            };
            return timeout(self.config.limits.handshake_timeout, async {
                let connection = incoming.await.map_err(|_| Error::Transport)?;
                let mut guard = CloseGuard(Some(connection.clone()));
                check_alpn(&connection, profile)?;
                let binding = channel_binding(&connection, self.config.identity)?;
                let (send, recv) = connection.accept_bi().await.map_err(|_| Error::Transport)?;
                let mut stream = Stream { send, recv };
                let mut prelude = [0; 8];
                stream.read_exact(&mut prelude).await?;
                if &prelude != PRELUDE {
                    return Err(Error::Protocol("invalid control prelude"));
                }
                let info = auth::server_authenticate_channel(
                    &mut stream,
                    members,
                    cfg,
                    &binding,
                    self.config.limits.handshake_timeout,
                )
                .await?;
                let tokens = server_gate(&mut stream, info.session_id).await?;
                let result = finish_connection(
                    connection,
                    (self.endpoint.clone(), self.owner.clone(), permit),
                    stream,
                    profile,
                    info,
                    Direction::ServerToClient,
                    tokens,
                )?;
                guard.0 = None;
                Ok(result)
            })
            .await
            .map_err(|_| Error::TimedOut)?;
        }
    }
}

fn validate_peer(peer: SocketAddr, local: SocketAddr) -> Result<(), Error> {
    if peer.port() == 0
        || peer.ip().is_unspecified()
        || peer.ip().is_multicast()
        || peer.is_ipv4() != local.is_ipv4()
        || peer.ip() == std::net::IpAddr::V4(std::net::Ipv4Addr::BROADCAST)
    {
        return Err(Error::Configuration(
            "invalid peer endpoint or address family",
        ));
    }
    Ok(())
}
fn check_alpn(connection: &quinn::Connection, profile: Profile) -> Result<(), Error> {
    let data = connection
        .handshake_data()
        .and_then(|x| x.downcast::<quinn::crypto::rustls::HandshakeData>().ok())
        .ok_or(Error::Protocol("missing TLS handshake data"))?;
    if data.protocol.as_deref() != Some(profile.application_id.as_slice())
        || data.server_name.is_some()
    {
        return Err(Error::Protocol("unexpected ALPN or SNI"));
    }
    Ok(())
}
fn channel_binding(
    connection: &quinn::Connection,
    identity: auth::ServerIdentity,
) -> Result<auth::CallerVerifiedChannel, Error> {
    let mut exporter = Zeroizing::new([0; 32]);
    connection
        .export_keying_material(
            &mut exporter[..],
            ChannelTransport::QuicTls.exporter_label(),
            b"",
        )
        .map_err(|_| Error::Transport)?;
    Ok(auth::CallerVerifiedChannel::new_after_verification(
        ChannelTransport::QuicTls,
        identity,
        *exporter,
    ))
}
fn hash(bytes: &[u8]) -> [u8; 32] {
    let mut out = [0; 32];
    out.copy_from_slice(digest(&SHA256, bytes).as_ref());
    out
}
fn random<const N: usize>() -> Result<[u8; N], Error> {
    let mut out = [0; N];
    SystemRandom::new()
        .fill(&mut out)
        .map_err(|_| Error::Random)?;
    Ok(out)
}
struct CloseGuard(Option<quinn::Connection>);
impl Drop for CloseGuard {
    fn drop(&mut self) {
        if let Some(c) = &self.0 {
            c.close(1u32.into(), b"");
        }
    }
}

struct Stream {
    send: quinn::SendStream,
    recv: quinn::RecvStream,
}
impl AsyncRead for Stream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        AsyncRead::poll_read(Pin::new(&mut self.recv), cx, buf)
    }
}
impl AsyncWrite for Stream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        AsyncWrite::poll_write(Pin::new(&mut self.send), cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        AsyncWrite::poll_flush(Pin::new(&mut self.send), cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        AsyncWrite::poll_shutdown(Pin::new(&mut self.send), cx)
    }
}

struct Tokens {
    local: Zeroizing<[u8; 16]>,
    peer: Zeroizing<[u8; 16]>,
}
async fn client_gate(stream: &mut Stream, session: [u8; 16]) -> Result<Tokens, Error> {
    let local = Zeroizing::new(random()?);
    let mut hello = Zeroizing::new([0; 32]);
    hello[..16].copy_from_slice(&session);
    hello[16..].copy_from_slice(&local[..]);
    stream.write_all(&hello[..]).await?;
    let mut reply = Zeroizing::new([0; 48]);
    stream.read_exact(&mut reply[..]).await?;
    if reply[..16] != session || reply[16..32] != local[..] {
        return Err(Error::Protocol("receive capability binding"));
    }
    let mut peer = Zeroizing::new([0; 16]);
    peer.copy_from_slice(&reply[32..]);
    let confirmation = hash(&reply[..]);
    stream.write_all(&confirmation).await?;
    let mut ready = [0; 32];
    stream.read_exact(&mut ready).await?;
    if ready != confirmation {
        return Err(Error::Protocol("receive capability completion"));
    }
    Ok(Tokens { local, peer })
}
async fn server_gate(stream: &mut Stream, session: [u8; 16]) -> Result<Tokens, Error> {
    let local = Zeroizing::new(random()?);
    let mut hello = Zeroizing::new([0; 32]);
    stream.read_exact(&mut hello[..]).await?;
    if hello[..16] != session {
        return Err(Error::Protocol("receive capability session"));
    }
    let mut peer = Zeroizing::new([0; 16]);
    peer.copy_from_slice(&hello[16..]);
    let mut reply = Zeroizing::new([0; 48]);
    reply[..32].copy_from_slice(&hello[..]);
    reply[32..].copy_from_slice(&local[..]);
    stream.write_all(&reply[..]).await?;
    let mut confirmation = [0; 32];
    stream.read_exact(&mut confirmation).await?;
    if confirmation != hash(&reply[..]) {
        return Err(Error::Protocol("receive capability confirmation"));
    }
    stream.write_all(&confirmation).await?;
    Ok(Tokens { local, peer })
}

struct Session {
    connection: quinn::Connection,
    _endpoint: quinn::Endpoint,
    _owner: owned_endpoint::Owner,
    _permit: OwnedSemaphorePermit,
    open: AtomicBool,
    info: SessionInfo,
    profile: Profile,
    send_direction: Direction,
}
impl Session {
    fn close(&self) {
        self.open.store(false, Ordering::Release);
        self.connection.close(0u32.into(), b"");
    }
    fn check(&self) -> Result<(), Error> {
        if !self.open.load(Ordering::Acquire) || self.connection.close_reason().is_some() {
            Err(Error::Transport)
        } else {
            Ok(())
        }
    }
}
/// Completed membership, owning the reliable control and bounded unreliable data path.
pub struct AuthenticatedConnection {
    control: Control,
    sender: DatagramSender,
    receiver: DatagramReceiver,
}
impl AuthenticatedConnection {
    /// Public authenticated session, member and server identity/configuration.
    pub fn info(&self) -> &SessionInfo {
        &self.control.session.info
    }
    /// Actual authenticated carrier profile, before any caller-owned Common handoff.
    pub fn profile(&self) -> Profile {
        self.control.session.profile
    }
    /// Current authenticated QUIC peer endpoint, for an additional configured-address admission check.
    /// Address matching is not a substitute for certificate/member authentication.
    pub fn peer_addr(&self) -> SocketAddr {
        self.control.session.connection.remote_address()
    }
    /// Bound local UDP socket address; wildcard binds remain wildcard addresses.
    pub fn local_addr(&self) -> Result<SocketAddr, Error> {
        Ok(self.control.session._endpoint.local_addr()?)
    }
    /// Transfer exclusive traffic owners; dropping Control closes all data operations.
    pub fn into_parts(self) -> (Control, DatagramSender, DatagramReceiver) {
        (self.control, self.sender, self.receiver)
    }
}
fn finish_connection(
    connection: quinn::Connection,
    resources: (quinn::Endpoint, owned_endpoint::Owner, OwnedSemaphorePermit),
    stream: Stream,
    profile: Profile,
    info: SessionInfo,
    send_direction: Direction,
    tokens: Tokens,
) -> Result<AuthenticatedConnection, Error> {
    if connection
        .max_datagram_size()
        .is_none_or(|max| max < profile.maximum_carrier_bytes())
    {
        return Err(Error::Protocol("negotiated DATAGRAM capacity too small"));
    }
    let session = Arc::new(Session {
        connection,
        _endpoint: resources.0,
        _owner: resources.1,
        _permit: resources.2,
        open: AtomicBool::new(true),
        info,
        profile,
        send_direction,
    });
    Ok(AuthenticatedConnection {
        control: Control {
            stream,
            session: session.clone(),
        },
        sender: DatagramSender {
            session: session.clone(),
            token: tokens.peer,
            next: Some(0),
        },
        receiver: DatagramReceiver {
            session,
            token: tokens.local,
            replay: Replay::default(),
        },
    })
}

/// Reliable stream with bounded QUIC windows. Poll it continuously to observe peer FIN.
pub struct Control {
    stream: Stream,
    session: Arc<Session>,
}
impl Drop for Control {
    fn drop(&mut self) {
        self.session.close();
    }
}
impl AsyncRead for Control {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.session.check().is_err() {
            return Poll::Ready(Err(io::Error::from(io::ErrorKind::BrokenPipe)));
        }
        let before = buf.filled().len();
        let had_space = buf.remaining() > 0;
        let result = Pin::new(&mut self.stream).poll_read(cx, buf);
        if matches!(&result, Poll::Ready(Err(_)))
            || (matches!(&result, Poll::Ready(Ok(()))) && had_space && before == buf.filled().len())
        {
            self.session.close();
        }
        result
    }
}
impl AsyncWrite for Control {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.session.check().is_err() {
            return Poll::Ready(Err(io::Error::from(io::ErrorKind::BrokenPipe)));
        }
        let result = Pin::new(&mut self.stream).poll_write(cx, buf);
        if matches!(&result, Poll::Ready(Err(_))) {
            self.session.close();
        }
        result
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let result = Pin::new(&mut self.stream).poll_flush(cx);
        if matches!(&result, Poll::Ready(Err(_))) {
            self.session.close();
        }
        result
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let result = Pin::new(&mut self.stream).poll_shutdown(cx);
        if result.is_ready() {
            self.session.close();
        }
        result
    }
}
/// Exclusive bounded DATAGRAM sender; higher-layer retransmission gets a fresh sequence.
pub struct DatagramSender {
    session: Arc<Session>,
    token: Zeroizing<[u8; 16]>,
    next: Option<u64>,
}
impl DatagramSender {
    /// Queue one protected datagram under QUIC congestion control within the I/O deadline.
    /// Cancellation can consume a sequence but never reuses one.
    pub async fn send(&mut self, payload: &[u8]) -> Result<u64, Error> {
        self.session.check()?;
        if self.session.profile.datagram_format != DatagramFormat::Legacy {
            return Err(Error::Configuration(
                "selected Common requires its actual carrier owner",
            ));
        }
        if !self
            .session
            .profile
            .traffic
            .allows(self.session.send_direction)
        {
            return Err(Error::Direction);
        }
        if payload.is_empty() || payload.len() > self.session.profile.max_datagram_bytes {
            return Err(Error::Size);
        }
        let sequence = self.next.ok_or(Error::Exhausted)?;
        self.next = sequence.checked_add(1);
        let packet = encode_datagram(&self.session, &self.token, sequence, payload)?;
        timeout(
            self.session.profile.io_timeout,
            self.session
                .connection
                .send_datagram_wait(Bytes::from(packet)),
        )
        .await
        .map_err(|_| Error::TimedOut)?
        .map_err(|_| Error::Transport)?;
        Ok(sequence)
    }
}
fn direction_byte(direction: Direction) -> u8 {
    match direction {
        Direction::ClientToServer => 1,
        Direction::ServerToClient => 2,
    }
}
fn reverse(direction: Direction) -> Direction {
    match direction {
        Direction::ClientToServer => Direction::ServerToClient,
        Direction::ServerToClient => Direction::ClientToServer,
    }
}
fn encode_datagram(
    session: &Session,
    token: &[u8; 16],
    sequence: u64,
    payload: &[u8],
) -> Result<Vec<u8>, Error> {
    let len = u16::try_from(payload.len()).map_err(|_| Error::Size)?;
    let mut out = Vec::with_capacity(HEADER + payload.len());
    out.extend_from_slice(b"L2QD");
    out.push(1);
    out.push(direction_byte(session.send_direction));
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(&session.info.session_id);
    out.extend_from_slice(token);
    out.extend_from_slice(&sequence.to_be_bytes());
    out.extend_from_slice(payload);
    Ok(out)
}
/// Result of inspecting exactly one peer DATAGRAM; discarded records release no payload.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Received {
    /// Accepted payload written into the caller's buffer.
    Packet {
        /// Written payload bytes.
        len: usize,
        /// Monotonic carrier sequence, with bounded permitted reordering.
        sequence: u64,
    },
    /// Malformed, stale, duplicate or preauth/misbound DATAGRAM discarded.
    Discarded,
}
/// Exclusive receiver with a fixed 128-sequence replay bitmap.
pub struct DatagramReceiver {
    session: Arc<Session>,
    token: Zeroizing<[u8; 16]>,
    replay: Replay,
}
impl DatagramReceiver {
    /// Receive one bounded event; output must hold the configured maximum payload.
    /// A cancelled wait is safe and does not mutate the replay window.
    pub async fn receive(&mut self, output: &mut [u8]) -> Result<Received, Error> {
        self.session.check()?;
        if self.session.profile.datagram_format != DatagramFormat::Legacy {
            return Err(Error::Configuration(
                "selected Common requires its actual carrier owner",
            ));
        }
        if !self
            .session
            .profile
            .traffic
            .allows(reverse(self.session.send_direction))
        {
            return Err(Error::Direction);
        }
        if output.len() < self.session.profile.max_datagram_bytes {
            return Err(Error::Size);
        }
        let packet = timeout(
            self.session.profile.io_timeout,
            self.session.connection.read_datagram(),
        )
        .await
        .map_err(|_| Error::TimedOut)?
        .map_err(|_| Error::Transport)?;
        Ok(self.admit(&packet, output))
    }
    fn admit(&mut self, packet: &[u8], output: &mut [u8]) -> Received {
        if packet.len() < HEADER
            || &packet[..4] != b"L2QD"
            || packet[4] != 1
            || packet[5] != direction_byte(reverse(self.session.send_direction))
            || packet[8..24] != self.session.info.session_id
            || packet[24..40] != self.token[..]
        {
            return Received::Discarded;
        }
        let len = usize::from(u16::from_be_bytes([packet[6], packet[7]]));
        if len == 0
            || len > self.session.profile.maximum_bootstrap_bytes()
            || len > output.len()
            || packet.len() != HEADER + len
        {
            return Received::Discarded;
        }
        let Ok(seqbytes) = packet[40..48].try_into() else {
            return Received::Discarded;
        };
        let sequence = u64::from_be_bytes(seqbytes);
        if !self.replay.admit(sequence) {
            return Received::Discarded;
        }
        output[..len].copy_from_slice(&packet[HEADER..]);
        Received::Packet { len, sequence }
    }
}
#[derive(Default)]
struct Replay {
    highest: Option<u64>,
    seen: u128,
}
impl Replay {
    fn admit(&mut self, seq: u64) -> bool {
        match self.highest {
            None => {
                self.highest = Some(seq);
                self.seen = 1;
                true
            }
            Some(high) if seq > high => {
                let delta = seq - high;
                self.seen = if delta >= 128 {
                    1
                } else {
                    (self.seen << delta) | 1
                };
                self.highest = Some(seq);
                true
            }
            Some(high) => {
                let delta = high - seq;
                if delta >= 128 || self.seen & (1u128 << delta) != 0 {
                    false
                } else {
                    self.seen |= 1u128 << delta;
                    true
                }
            }
        }
    }
}

#[cfg(test)]
mod tests;
