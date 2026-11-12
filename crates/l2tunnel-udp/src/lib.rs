//! Actual UDP socket adapter bootstrapped by and retaining an authenticated TLS connection.
//! Custom prefixes are not standard OpenVPN/QUIC interoperability. The adapter supplies
//! no delivery recovery, standalone UDP authentication, NAT rebinding or device integration.
use l2tunnel_auth::{AuthenticatedConnection, KeyPurpose, SessionConfig, SessionInfo};
use l2tunnel_core::ConfigDigest;
use l2tunnel_datagram::{
    self as datagram, DatagramConfig, KeyContext, PacketOpener, PacketSealer, SessionId,
};
use l2tunnel_device::PacketLayer;
use std::fmt;
use std::future::Future;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::UdpSocket;
use tokio::sync::watch;
use tokio::time::{Instant, sleep_until, timeout};

/// Global cryptographic directions and supported custom datagram profiles.
pub use l2tunnel_datagram::{
    CoverProfile, Direction, KeyGeneration, LaneId, OpenedPacket, Protection, SealedPacket, Usage,
};
/// Exact fixed length of each TLS-protected bootstrap message.
pub const BOOTSTRAP_BYTES: usize = 64;
/// Canonical bytes in the UDP profile authenticated before bootstrap.
pub const PROFILE_BYTES: usize = 40;

/// Bulk-data direction policy. Reverse control always remains available on TLS.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Traffic {
    /// Both endpoints may send and receive UDP data.
    FullDuplex,
    /// Only one global direction carries UDP data on this lane.
    HalfDuplex {
        /// The only permitted global UDP bulk direction.
        sender: Direction,
    },
}
/// Exact profile bound to initial member authentication and bootstrap confirmation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Profile {
    /// Full duplex or one-direction bulk lane.
    pub traffic: Traffic,
    /// Custom prefix shape; no standard-protocol interoperability is implied.
    pub cover: CoverProfile,
    /// Required confidentiality/integrity policy, never selected from incoming bytes.
    pub protection: Protection,
    /// Authenticated physical lane identity.
    pub lane: LaneId,
    /// Non-reused key generation; no in-place rekey API is provided.
    pub generation: KeyGeneration,
    /// Complete path packet budget including IP/UDP headers.
    pub path_mtu: usize,
    /// Actual outer IP/UDP and any additional underlay encapsulation bytes.
    pub outer_overhead_bytes: usize,
    /// Nonzero plaintext record ceiling before cover/header/tag overhead.
    pub max_payload_bytes: usize,
    /// Maximum packets under each directional key.
    pub max_packets_per_key: u64,
    /// Maximum plaintext bytes under each directional key.
    pub max_payload_bytes_per_key: u64,
}
impl Profile {
    fn packet(self, session: SessionId, direction: Direction) -> DatagramConfig {
        DatagramConfig {
            context: KeyContext {
                session,
                direction,
                lane: self.lane,
                generation: self.generation,
            },
            cover: self.cover,
            protection: self.protection,
            path_mtu: self.path_mtu,
            outer_overhead_bytes: self.outer_overhead_bytes,
            max_payload_bytes: self.max_payload_bytes,
            max_packets_per_key: self.max_packets_per_key,
            max_payload_bytes_per_key: self.max_payload_bytes_per_key,
        }
    }
    /// Strict fixed-size canonical profile for auth binding and exact TLS confirmation.
    pub fn canonical(self) -> Result<[u8; PROFILE_BYTES], Error> {
        let config = self.packet(SessionId([0; 16]), Direction::ClientToServer);
        let budget = self
            .path_mtu
            .checked_sub(self.outer_overhead_bytes)
            .ok_or(Error::Configuration("outer headers exceed path MTU"))?
            .min(datagram::MAX_DATAGRAM_BYTES);
        let maximum = self
            .max_payload_bytes
            .checked_add(config.wire_overhead())
            .ok_or(Error::Configuration("datagram length overflow"))?;
        if self.outer_overhead_bytes < 28
            || self.max_payload_bytes == 0
            || self.max_payload_bytes > usize::from(u16::MAX)
            || maximum > budget
            || !(1..=datagram::MAX_PACKETS_PER_KEY).contains(&self.max_packets_per_key)
            || !(1..=datagram::MAX_PAYLOAD_BYTES_PER_KEY).contains(&self.max_payload_bytes_per_key)
            || self.max_payload_bytes as u64 > self.max_payload_bytes_per_key
        {
            return Err(Error::Configuration("invalid MTU or key-use budget"));
        }
        let mut bytes = [0; PROFILE_BYTES];
        bytes[..4].copy_from_slice(&[
            1,
            match self.traffic {
                Traffic::FullDuplex => 1,
                Traffic::HalfDuplex {
                    sender: Direction::ClientToServer,
                } => 2,
                Traffic::HalfDuplex {
                    sender: Direction::ServerToClient,
                } => 3,
            },
            match self.cover {
                CoverProfile::OpenVpnLike => 1,
                CoverProfile::QuicLike => 2,
            },
            match self.protection {
                Protection::ChaCha20Poly1305 => 1,
                Protection::HmacSha256 => 2,
            },
        ]);
        bytes[4..8].copy_from_slice(&self.lane.0.to_be_bytes());
        bytes[8..12].copy_from_slice(&self.generation.0.to_be_bytes());
        for (offset, value) in [
            (12, self.path_mtu),
            (16, self.outer_overhead_bytes),
            (20, self.max_payload_bytes),
        ] {
            bytes[offset..offset + 4].copy_from_slice(
                &u32::try_from(value)
                    .map_err(|_| Error::Configuration("profile integer exceeds wire bound"))?
                    .to_be_bytes(),
            );
        }
        bytes[24..32].copy_from_slice(&self.max_packets_per_key.to_be_bytes());
        bytes[32..40].copy_from_slice(&self.max_payload_bytes_per_key.to_be_bytes());
        Ok(bytes)
    }
    fn permits(self, direction: Direction) -> bool {
        self.traffic == Traffic::FullDuplex
            || self.traffic == Traffic::HalfDuplex { sender: direction }
    }
}
/// Local adapter inputs. Peer endpoints are trusted local configuration, never learned from UDP.
#[derive(Clone, Copy, Debug)]
pub struct Config {
    /// Upper-layer packet/configuration binding before this UDP profile is added.
    pub base: SessionConfig,
    /// Exact negotiated UDP policy.
    pub profile: Profile,
    /// Fixed remote UDP endpoint; no unauthenticated rebinding is permitted.
    pub peer: SocketAddr,
    /// Total bootstrap, individual UDP operation and authenticated-Control idle lease bound.
    /// Callers must read authenticated Control progress/heartbeats within this interval.
    pub timeout: Duration,
}
/// Bind the UDP profile to the upper-layer digest before calling the TLS auth factories.
pub fn session_config(base: SessionConfig, profile: Profile) -> Result<SessionConfig, Error> {
    let mut digest = ring::digest::Context::new(&ring::digest::SHA256);
    digest.update(b"l2tunnel/udp-carrier/session/v1\0");
    digest.update(&[match base.layer {
        PacketLayer::Ethernet => 1,
        PacketLayer::Ip => 2,
    }]);
    digest.update(&base.digest.0);
    digest.update(&profile.canonical()?);
    Ok(SessionConfig {
        layer: base.layer,
        digest: ConfigDigest(
            digest
                .finish()
                .as_ref()
                .try_into()
                .map_err(|_| Error::Configuration("digest length"))?,
        ),
    })
}
/// Explicit operational failure; no variant contains key material or plaintext.
#[derive(Debug)]
pub enum Error {
    /// Local profile, endpoint, deadline or negotiated digest is invalid.
    Configuration(&'static str),
    /// Exporter access failed after TLS authentication.
    Authentication(l2tunnel_auth::Error),
    /// Fixed TLS confirmation frame did not match its expected state/body.
    Bootstrap,
    /// A bounded bootstrap or UDP operation timed out.
    Timeout,
    /// Control was dropped, shut down or observed closed/failed.
    ControlClosed,
    /// No authenticated TLS input renewed the finite control lease in time.
    ControlExpired,
    /// This half-mode lane does not permit the requested global data direction.
    DirectionDisabled,
    /// Local protection/configuration/key-use failure requiring caller action.
    Datagram(datagram::Error),
    /// UDP/TCP I/O failed; no automatic endpoint or transport fallback occurs.
    Io(io::Error),
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "UDP carrier error: {self:?}")
    }
}
impl std::error::Error for Error {}
impl From<io::Error> for Error {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}
impl From<datagram::Error> for Error {
    fn from(value: datagram::Error) -> Self {
        Self::Datagram(value)
    }
}

#[derive(Clone, Copy)]
struct Lease {
    open: bool,
    progress: Instant,
}
fn close(liveness: &watch::Sender<Lease>) {
    liveness.send_modify(|state| state.open = false);
}
fn live(liveness: &watch::Sender<Lease>, duration: Duration) -> Result<(), Error> {
    let state = *liveness.borrow();
    if !state.open {
        return Err(Error::ControlClosed);
    }
    if state.progress.elapsed() >= duration {
        close(liveness);
        return Err(Error::ControlExpired);
    }
    Ok(())
}
async fn bounded_io<T>(
    operation: impl Future<Output = io::Result<T>>,
    liveness: &watch::Sender<Lease>,
    duration: Duration,
) -> Result<T, Error> {
    let deadline = Instant::now() + duration;
    let mut changes = liveness.subscribe();
    tokio::pin!(operation);
    loop {
        live(liveness, duration)?;
        if Instant::now() >= deadline {
            return Err(Error::Timeout);
        }
        let lease_deadline = changes.borrow_and_update().progress + duration;
        tokio::select! {
            biased;
            changed = changes.changed() => { changed.map_err(|_| Error::ControlClosed)?; }
            _ = sleep_until(lease_deadline.min(deadline)) => {
                live(liveness, duration)?;
                return Err(Error::Timeout);
            }
            result = &mut operation => {
                live(liveness, duration)?;
                return result.map_err(Error::Io);
            }
        }
    }
}

/// The original authenticated TLS stream retained for management and liveness heartbeats.
/// No raw-connection/key export is available, so this adapter's sealer cannot be reconstructed.
pub struct Control {
    connection: AuthenticatedConnection,
    liveness: watch::Sender<Lease>,
    duration: Duration,
}
impl Control {
    fn check_lease(&self) -> io::Result<()> {
        live(&self.liveness, self.duration).map_err(|error| {
            let kind = if matches!(error, Error::ControlExpired) {
                io::ErrorKind::TimedOut
            } else {
                io::ErrorKind::BrokenPipe
            };
            io::Error::new(kind, error)
        })
    }
    /// Matched identities, layer, UDP profile digest and session ID.
    pub fn info(&self) -> &SessionInfo {
        self.connection.info()
    }
    /// Original retained TCP local address.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.connection.local_addr()
    }
    /// Original retained TCP peer address.
    pub fn peer_addr(&self) -> io::Result<SocketAddr> {
        self.connection.peer_addr()
    }
}
impl Drop for Control {
    fn drop(&mut self) {
        close(&self.liveness);
    }
}
impl AsyncRead for Control {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if let Err(error) = self.check_lease() {
            return Poll::Ready(Err(error));
        }
        let before = buffer.filled().len();
        let remaining = buffer.remaining();
        let result = Pin::new(&mut self.connection).poll_read(cx, buffer);
        match &result {
            Poll::Ready(Ok(())) if buffer.filled().len() > before => self
                .liveness
                .send_modify(|state| state.progress = Instant::now()),
            Poll::Ready(Ok(())) if remaining > 0 => close(&self.liveness),
            Poll::Ready(Err(_)) => close(&self.liveness),
            _ => {}
        }
        result
    }
}
impl AsyncWrite for Control {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        if let Err(error) = self.check_lease() {
            return Poll::Ready(Err(error));
        }
        let result = Pin::new(&mut self.connection).poll_write(cx, bytes);
        if matches!(result, Poll::Ready(Err(_))) {
            close(&self.liveness);
        }
        result
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if let Err(error) = self.check_lease() {
            return Poll::Ready(Err(error));
        }
        let result = Pin::new(&mut self.connection).poll_flush(cx);
        if matches!(result, Poll::Ready(Err(_))) {
            close(&self.liveness);
        }
        result
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        close(&self.liveness);
        let result = Pin::new(&mut self.connection).poll_shutdown(cx);
        if result.is_ready() {
            close(&self.liveness);
        }
        result
    }
}
/// One unique sender key/counter and a fixed UDP destination; intentionally non-Clone.
pub struct UdpSender {
    socket: Arc<UdpSocket>,
    peer: SocketAddr,
    sealer: Option<PacketSealer>,
    buffer: Vec<u8>,
    liveness: watch::Sender<Lease>,
    duration: Duration,
}
impl UdpSender {
    /// Seal and send one payload. Socket timeout/cancellation never rewinds the used nonce.
    pub async fn send(&mut self, payload: &[u8]) -> Result<SealedPacket, Error> {
        live(&self.liveness, self.duration)?;
        let sealed = self
            .sealer
            .as_mut()
            .ok_or(Error::DirectionDisabled)?
            .seal_into(payload, &mut self.buffer)?;
        let count = bounded_io(
            self.socket
                .send_to(&self.buffer[..sealed.wire_len], self.peer),
            &self.liveness,
            self.duration,
        )
        .await?;
        if count != sealed.wire_len {
            return Err(Error::Io(io::Error::new(
                io::ErrorKind::WriteZero,
                "partial UDP send",
            )));
        }
        Ok(sealed)
    }
    /// Attempted cryptographic send usage, including subsequently failed socket sends.
    pub fn usage(&self) -> Usage {
        self.sealer
            .as_ref()
            .map(PacketSealer::usage)
            .unwrap_or_default()
    }
    /// Immutable configured destination.
    pub fn peer_addr(&self) -> SocketAddr {
        self.peer
    }
    /// Actual local UDP address.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }
}
/// A rejected UDP packet, distinct from a terminal I/O/key-lifecycle failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DiscardReason {
    /// Source endpoint differed from the trusted configured peer.
    WrongPeer,
    /// Sentinel receive detected a packet above the complete negotiated wire bound.
    Oversized,
    /// Existing datagram codec rejected syntax, context, integrity or replay.
    Protection(datagram::Error),
}
/// Exactly one received UDP packet's result; discarded packets never modify output.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReceiveEvent {
    /// Authenticated, fresh plaintext copied to caller storage.
    Packet(OpenedPacket),
    /// One packet was discarded without advancing replay or key-use state.
    Discarded(DiscardReason),
}
/// One replay-window owner and fixed peer, with a bounded maximum-plus-one receive buffer.
pub struct UdpReceiver {
    socket: Arc<UdpSocket>,
    peer: SocketAddr,
    opener: Option<PacketOpener>,
    buffer: Vec<u8>,
    maximum: usize,
    payload_maximum: usize,
    packet_limit: u64,
    byte_limit: u64,
    liveness: watch::Sender<Lease>,
    duration: Duration,
}
impl UdpReceiver {
    /// Receive at most one packet. Output must hold the negotiated maximum plaintext length.
    /// Cancellation before receive completion does not mutate replay state.
    pub async fn receive(&mut self, output: &mut [u8]) -> Result<ReceiveEvent, Error> {
        live(&self.liveness, self.duration)?;
        if self.opener.is_none() {
            return Err(Error::DirectionDisabled);
        }
        let usage = self.usage();
        if usage.packets >= self.packet_limit || usage.payload_bytes >= self.byte_limit {
            return Err(Error::Datagram(datagram::Error::KeyUsageExhausted));
        }
        if output.len() < self.payload_maximum {
            return Err(datagram::Error::OutputTooSmall.into());
        }
        let (count, source) = bounded_io(
            self.socket.recv_from(&mut self.buffer),
            &self.liveness,
            self.duration,
        )
        .await?;
        if source != self.peer {
            return Ok(ReceiveEvent::Discarded(DiscardReason::WrongPeer));
        }
        if count > self.maximum {
            return Ok(ReceiveEvent::Discarded(DiscardReason::Oversized));
        }
        match self
            .opener
            .as_mut()
            .ok_or(Error::DirectionDisabled)?
            .open(&self.buffer[..count], output)
        {
            Ok(packet) => Ok(ReceiveEvent::Packet(packet)),
            Err(
                error @ (datagram::Error::CounterExhausted
                | datagram::Error::Crypto
                | datagram::Error::Arithmetic
                | datagram::Error::InvalidConfig
                | datagram::Error::OutputTooSmall),
            ) => Err(Error::Datagram(error)),
            Err(error) => Ok(ReceiveEvent::Discarded(DiscardReason::Protection(error))),
        }
    }
    /// Successful authenticated receive use; rejected/replayed packets are not charged.
    pub fn usage(&self) -> Usage {
        self.opener
            .as_ref()
            .map(PacketOpener::usage)
            .unwrap_or_default()
    }
    /// Immutable configured source endpoint.
    pub fn peer_addr(&self) -> SocketAddr {
        self.peer
    }
    /// Actual local UDP address.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }
}
/// Established UDP data halves and their retained original authenticated TLS control stream.
pub struct Carrier {
    control: Control,
    sender: UdpSender,
    receiver: UdpReceiver,
}
impl Carrier {
    /// Transfer the same unique connection/key owners to separate runtime tasks.
    pub fn into_parts(self) -> (Control, UdpSender, UdpReceiver) {
        (self.control, self.sender, self.receiver)
    }
}
fn address_valid(address: SocketAddr) -> bool {
    address.port() != 0
        && !address.ip().is_unspecified()
        && !address.ip().is_multicast()
        && !matches!(address.ip(), IpAddr::V4(ip) if ip.is_broadcast())
}
fn auth_direction(direction: Direction) -> l2tunnel_auth::Direction {
    match direction {
        Direction::ClientToServer => l2tunnel_auth::Direction::ClientToServer,
        Direction::ServerToClient => l2tunnel_auth::Direction::ServerToClient,
    }
}
async fn write_bootstrap(
    connection: &mut AuthenticatedConnection,
    kind: u8,
    body: &[u8; 56],
) -> Result<(), Error> {
    connection
        .write_all(&[b'L', b'2', b'U', b'D', 1, kind, 0, 56])
        .await?;
    connection.write_all(body).await?;
    connection.flush().await?;
    Ok(())
}
async fn read_bootstrap(
    connection: &mut AuthenticatedConnection,
    kind: u8,
    body: &[u8; 56],
) -> Result<(), Error> {
    let mut header = [0; 8];
    connection.read_exact(&mut header).await?;
    if header != [b'L', b'2', b'U', b'D', 1, kind, 0, 56] {
        return Err(Error::Bootstrap);
    }
    let mut received = [0; 56];
    connection.read_exact(&mut received).await?;
    if received != *body {
        return Err(Error::Bootstrap);
    }
    Ok(())
}
/// Confirm a fixed UDP profile inside the existing authenticated TLS session and retain it.
/// This consumes unique key authority, starts no hidden tasks and never learns a peer from UDP.
pub async fn establish(
    mut connection: AuthenticatedConnection,
    socket: UdpSocket,
    config: Config,
) -> Result<Carrier, Error> {
    let canonical = config.profile.canonical()?;
    if connection.info().config != session_config(config.base, config.profile)? {
        return Err(Error::Configuration(
            "UDP profile was not bound by member authentication",
        ));
    }
    if config.timeout.is_zero() || config.timeout > Duration::from_secs(120) {
        return Err(Error::Configuration(
            "timeout must be positive and at most 120 seconds",
        ));
    }
    let local = socket.local_addr()?;
    if !address_valid(local)
        || !address_valid(config.peer)
        || local.is_ipv4() != config.peer.is_ipv4()
        || (local.is_ipv6() && config.profile.outer_overhead_bytes < 48)
    {
        return Err(Error::Configuration(
            "invalid or incompatible fixed UDP endpoints/overhead",
        ));
    }
    if socket.peer_addr().is_ok_and(|peer| peer != config.peer) {
        return Err(Error::Configuration(
            "UDP socket is connected to a different peer",
        ));
    }
    let server = connection.info().peer_member.is_some();
    let session = SessionId(connection.info().session_id);
    let send_direction = if server {
        Direction::ServerToClient
    } else {
        Direction::ClientToServer
    };
    let receive_direction = if server {
        Direction::ClientToServer
    } else {
        Direction::ServerToClient
    };
    let sealer = if config.profile.permits(send_direction) {
        let material = connection
            .export_key(
                KeyPurpose::Data,
                auth_direction(send_direction),
                config.profile.lane.0,
            )
            .map_err(Error::Authentication)?;
        Some(PacketSealer::new(
            config.profile.packet(session, send_direction),
            material.expose_bytes(),
        )?)
    } else {
        None
    };
    let opener = if config.profile.permits(receive_direction) {
        let material = connection
            .export_key(
                KeyPurpose::Data,
                auth_direction(receive_direction),
                config.profile.lane.0,
            )
            .map_err(Error::Authentication)?;
        Some(PacketOpener::new(
            config.profile.packet(session, receive_direction),
            material.expose_bytes(),
        )?)
    } else {
        None
    };
    let mut body = [0; 56];
    body[..16].copy_from_slice(&session.0);
    body[16..].copy_from_slice(&canonical);
    timeout(config.timeout, async {
        if server {
            read_bootstrap(&mut connection, 1, &body).await?;
            write_bootstrap(&mut connection, 2, &body).await?;
            read_bootstrap(&mut connection, 3, &body).await?;
            write_bootstrap(&mut connection, 4, &body).await?;
        } else {
            write_bootstrap(&mut connection, 1, &body).await?;
            read_bootstrap(&mut connection, 2, &body).await?;
            write_bootstrap(&mut connection, 3, &body).await?;
            read_bootstrap(&mut connection, 4, &body).await?;
        }
        Ok::<_, Error>(())
    })
    .await
    .map_err(|_| Error::Timeout)??;
    let (liveness, _) = watch::channel(Lease {
        open: true,
        progress: Instant::now(),
    });
    let maximum = config.profile.max_payload_bytes
        + config
            .profile
            .packet(session, send_direction)
            .wire_overhead();
    let socket = Arc::new(socket);
    let sender = UdpSender {
        socket: socket.clone(),
        peer: config.peer,
        sealer,
        buffer: vec![0; maximum],
        liveness: liveness.clone(),
        duration: config.timeout,
    };
    let receiver = UdpReceiver {
        socket,
        peer: config.peer,
        opener,
        buffer: vec![0; maximum + 1],
        maximum,
        payload_maximum: config.profile.max_payload_bytes,
        packet_limit: config.profile.max_packets_per_key,
        byte_limit: config.profile.max_payload_bytes_per_key,
        liveness: liveness.clone(),
        duration: config.timeout,
    };
    Ok(Carrier {
        control: Control {
            connection,
            liveness,
            duration: config.timeout,
        },
        sender,
        receiver,
    })
}

#[cfg(test)]
mod tests;
