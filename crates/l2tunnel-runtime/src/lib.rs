//! Authenticated carrier ownership and bounded Common runtime integration.
pub(crate) mod buffer_metrics;
/// Canonical native limits and configuration digests shared by current profiles.
pub mod configuration;
/// Opt-in bounded setup and local API timing; not protocol authority.
pub mod initialization_timing;
/// Explicit bounded TUN TCP ownership over the selected Common carrier.
pub mod proxy;
/// Bounded Common framing on the original authenticated retained TCP/TLS owners.
pub mod retained_tls;
/// Same-carrier authentication and current bounded Common data transport.
pub mod secure_udp;
use l2tunnel_auth::AuthenticatedIo;
/// Optional independent packet compression.
pub use l2tunnel_codec::Compression;
use l2tunnel_codec::{CodecConfig, FRAME_HEADER_BYTES, FrameCodec, FrameLayer};
use l2tunnel_device::PacketLayer;
use l2tunnel_wire as wire;
use ring::rand::{SecureRandom, SystemRandom};
use std::io;
use std::pin::Pin;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Shared bulk-direction policy; half duplex is the default.
pub use l2tunnel_core::Duplex;
/// Finite memory/work settings for one device/peer link.
#[derive(Clone, Copy, Debug)]
pub struct RuntimeConfig {
    /// Native packet layer bound by authentication.
    pub layer: PacketLayer,
    /// Native packet size ceiling, excluding tunnel headers.
    pub max_packet: usize,
    /// Stateless per-packet compression, bound by the session configuration.
    pub compression: Compression,
    /// Complete packets retained per direction before backpressure.
    pub queue_packets: usize,
    /// Portable nonblocking device polling interval.
    pub poll_interval: Duration,
}
impl RuntimeConfig {
    /// Validate before allocating or reading the device.
    pub fn validate(self) -> io::Result<()> {
        if !(40..=wire::MAX_PAYLOAD - FRAME_HEADER_BYTES).contains(&self.max_packet)
            || !(1..=1024).contains(&self.queue_packets)
            || self.poll_interval.is_zero()
            || self.poll_interval > Duration::from_secs(1)
        {
            return Err(invalid("invalid bounded runtime configuration"));
        }
        self.codec()?;
        Ok(())
    }
    fn codec(self) -> io::Result<FrameCodec> {
        FrameCodec::new(CodecConfig {
            layer: match self.layer {
                PacketLayer::Ethernet => FrameLayer::Ethernet,
                PacketLayer::Ip => FrameLayer::Ip,
            },
            max_frame_bytes: self.max_packet,
            compression: self.compression,
        })
        .map_err(io::Error::other)
    }
}
fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
fn packet_valid(layer: PacketLayer, bytes: &[u8]) -> bool {
    match layer {
        PacketLayer::Ethernet => bytes.len() >= 14,
        PacketLayer::Ip => match bytes.first().map(|byte| byte >> 4) {
            Some(4) if bytes.len() >= 20 => {
                let ihl = usize::from(bytes[0] & 15) * 4;
                ihl >= 20
                    && ihl <= bytes.len()
                    && usize::from(u16::from_be_bytes([bytes[2], bytes[3]])) == bytes.len()
            }
            Some(6) if bytes.len() >= 40 => {
                usize::from(u16::from_be_bytes([bytes[4], bytes[5]])) + 40 == bytes.len()
            }
            _ => false,
        },
    }
}

/// An authenticated data link. Constructors retain the authenticated TLS streams.
pub struct Link {
    reader: Pin<Box<dyn AsyncRead + Send>>,
    writer: Pin<Box<dyn AsyncWrite + Send>>,
    reverse_reader: Option<Pin<Box<dyn AsyncRead + Send>>>,
    reverse_writer: Option<Pin<Box<dyn AsyncWrite + Send>>>,
    layer: PacketLayer,
}
impl Link {
    /// Use one persistent authenticated connection in full duplex.
    pub fn full<S>(connection: AuthenticatedIo<S>) -> Self
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let info = connection.info();
        let layer = info.config.layer;
        let (reader, writer) = tokio::io::split(connection);
        Self {
            reader: Box::pin(reader),
            writer: Box::pin(writer),
            reverse_reader: None,
            reverse_writer: None,
            layer,
        }
    }
    fn paired<S, T>(receive: AuthenticatedIo<S>, send: AuthenticatedIo<T>) -> Self
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
        T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let layer = receive.info().config.layer;
        let (reader, reverse_writer) = tokio::io::split(receive);
        let (reverse_reader, writer) = tokio::io::split(send);
        Self {
            reader: Box::pin(reader),
            writer: Box::pin(writer),
            reverse_reader: Some(Box::pin(reverse_reader)),
            reverse_writer: Some(Box::pin(reverse_writer)),
            layer,
        }
    }
}
const PAIR_PREFIX: &[u8; 16] = b"L2T-PAIR-V1\0\0\0\0\0";
const PAIR_TIMEOUT: Duration = Duration::from_secs(10);
fn compatible<S, T>(first: &AuthenticatedIo<S>, second: &AuthenticatedIo<T>) -> io::Result<()> {
    let a = first.info();
    let b = second.info();
    if a.config != b.config
        || a.member != b.member
        || a.server != b.server
        || a.session_id == b.session_id
    {
        return Err(invalid("incompatible authenticated carrier pair"));
    }
    Ok(())
}
/// Client pairing: first carrier sends bulk, second receives bulk.
/// Both connections must already have independently completed authentication.
pub async fn client_pair<S, T>(
    mut first: AuthenticatedIo<S>,
    mut second: AuthenticatedIo<T>,
) -> io::Result<Link>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    compatible(&first, &second)?;
    tokio::time::timeout(PAIR_TIMEOUT, async {
        let mut token = [0_u8; 48];
        first.read_exact(&mut token).await?;
        if &token[..16] != PAIR_PREFIX {
            return Err(invalid("invalid pairing challenge"));
        }
        second.write_all(&token).await?;
        second.flush().await?;
        let mut ready = [0_u8; 1];
        second.read_exact(&mut ready).await?;
        if ready != [1] {
            return Err(invalid("pairing rejected"));
        }
        Ok(Link::paired(second, first))
    })
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "carrier pairing timeout"))?
}
/// Server pairing: first carrier receives bulk, second sends bulk.
/// A fresh TLS-protected token prevents accidental cross-pair lane attachment.
pub async fn server_pair<S, T>(
    mut first: AuthenticatedIo<S>,
    mut second: AuthenticatedIo<T>,
) -> io::Result<Link>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    compatible(&first, &second)?;
    tokio::time::timeout(PAIR_TIMEOUT, async {
        let mut token = [0_u8; 48];
        token[..16].copy_from_slice(PAIR_PREFIX);
        SystemRandom::new()
            .fill(&mut token[16..])
            .map_err(|_| invalid("random generator failure"))?;
        first.write_all(&token).await?;
        first.flush().await?;
        let mut echo = [0_u8; 48];
        second.read_exact(&mut echo).await?;
        if token != echo {
            return Err(invalid("carrier pairing token mismatch"));
        }
        second.write_all(&[1]).await?;
        second.flush().await?;
        Ok(Link::paired(first, second))
    })
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "carrier pairing timeout"))?
}
