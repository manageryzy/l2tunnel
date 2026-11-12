//! Bounded authenticated stream runtime; OS setup belongs to the embedding client.
/// Transparent active TUN with fixed bootstrap credit and native-release regrant.
pub mod active;
/// Canonical policy/catalog binding for planned coordinated active-TUN switching.
pub mod active_management;
/// Separate authenticated finite native/retained-TLS shutdown profile.
pub mod drained;
/// Authenticated runtime with bounded coordinated compression hot switching.
pub mod managed;
/// Native packet forwarding over standalone OpenVPN-like UDP.
pub mod openvpn;
/// Timed packed sources on the shared authenticated UDP/QUIC runtime.
pub mod packed;
/// Explicit bounded TUN TCP ownership over retained authenticated TLS.
pub mod proxy;
/// Native packet forwarding over genuine standalone QUIC.
pub mod quic;
/// Fixed-mode authenticated UDP with selective repeat and native packet framing.
pub mod udp;
#[cfg(test)]
use l2tunnel_auth::AuthenticatedConnection;
use l2tunnel_auth::AuthenticatedIo;
/// Optional independent packet compression.
pub use l2tunnel_codec::Compression;
use l2tunnel_codec::{CodecConfig, FRAME_HEADER_BYTES, FrameCodec, FrameLayer};
use l2tunnel_core::Epoch;
use l2tunnel_device::{PacketDevice, PacketLayer};
use l2tunnel_wire::{self as wire, Header, Kind};
use ring::rand::{SecureRandom, SystemRandom};
use std::io;
use std::pin::Pin;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc;

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
fn wire_error(_: wire::DecodeError) -> io::Error {
    invalid("invalid tunnel record")
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
    managed_metadata: Option<managed::LinkMetadata>,
    reader: Pin<Box<dyn AsyncRead + Send>>,
    writer: Pin<Box<dyn AsyncWrite + Send>>,
    reverse_reader: Option<Pin<Box<dyn AsyncRead + Send>>>,
    reverse_writer: Option<Pin<Box<dyn AsyncWrite + Send>>>,
    receive_session: [u8; 16],
    send_session: [u8; 16],
    layer: PacketLayer,
}
impl Link {
    /// Use one persistent authenticated connection in full duplex.
    pub fn full<S>(connection: AuthenticatedIo<S>) -> Self
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let info = connection.info();
        let managed_metadata = Some(managed::LinkMetadata::new(info, Duplex::Full));
        let receive_session = info.session_id;
        let layer = info.config.layer;
        let (reader, writer) = tokio::io::split(connection);
        Self {
            managed_metadata,
            reader: Box::pin(reader),
            writer: Box::pin(writer),
            reverse_reader: None,
            reverse_writer: None,
            receive_session,
            send_session: receive_session,
            layer,
        }
    }
    fn paired<S, T>(receive: AuthenticatedIo<S>, send: AuthenticatedIo<T>) -> Self
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
        T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let managed_metadata = Some(managed::LinkMetadata::new(receive.info(), Duplex::Half));
        let receive_session = receive.info().session_id;
        let send_session = send.info().session_id;
        let layer = receive.info().config.layer;
        let (reader, reverse_writer) = tokio::io::split(receive);
        let (reverse_reader, writer) = tokio::io::split(send);
        Self {
            managed_metadata,
            reader: Box::pin(reader),
            writer: Box::pin(writer),
            reverse_reader: Some(Box::pin(reverse_reader)),
            reverse_writer: Some(Box::pin(reverse_writer)),
            receive_session,
            send_session,
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

async fn read_packets<R: AsyncRead + Unpin>(
    mut stream: R,
    session: [u8; 16],
    config: RuntimeConfig,
    sender: mpsc::Sender<Vec<u8>>,
) -> io::Result<()> {
    let codec = config.codec()?;
    let mut expected = 0_u64;
    loop {
        let length = stream.read_u32().await? as usize;
        if length < wire::HEADER_LEN || length > wire::HEADER_LEN + codec.max_encoded_len() {
            return Err(invalid("record length outside configured bound"));
        }
        let mut record = vec![0_u8; length];
        stream.read_exact(&mut record).await?;
        let (header, payload) =
            wire::decode(&record, codec.max_encoded_len()).map_err(wire_error)?;
        if header.kind != Kind::Data
            || header.epoch != Epoch(1)
            || header.session != session
            || header.lane != 0
            || header.packet_number != expected
        {
            return Err(invalid("record context, sequence or packet layer mismatch"));
        }
        let packet = codec.decode_vec(payload).map_err(io::Error::other)?;
        if !packet_valid(config.layer, &packet) {
            return Err(invalid("decoded native layer mismatch"));
        }
        expected = expected
            .checked_add(1)
            .ok_or_else(|| invalid("packet counter exhausted"))?;
        sender
            .send(packet)
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "device consumer stopped"))?;
    }
}
async fn write_packets<W: AsyncWrite + Unpin>(
    mut stream: W,
    session: [u8; 16],
    mut receiver: mpsc::Receiver<Vec<u8>>,
    config: RuntimeConfig,
) -> io::Result<()> {
    let codec = config.codec()?;
    let mut packet_number = 0_u64;
    while let Some(packet) = receiver.recv().await {
        let packet = codec.encode_vec(&packet).map_err(io::Error::other)?;
        let record = wire::encode(
            Header {
                kind: Kind::Data,
                epoch: Epoch(1),
                packet_number,
                session,
                lane: 0,
            },
            &packet,
        )
        .map_err(wire_error)?;
        packet_number = packet_number
            .checked_add(1)
            .ok_or_else(|| invalid("packet counter exhausted"))?;
        stream
            .write_u32(u32::try_from(record.len()).map_err(|_| invalid("record too long"))?)
            .await?;
        stream.write_all(&record).await?;
        stream.flush().await?;
    }
    Err(io::Error::new(
        io::ErrorKind::BrokenPipe,
        "device producer stopped",
    ))
}
async fn drive_device<D: PacketDevice<Error = io::Error>>(
    mut device: D,
    config: RuntimeConfig,
    sender: mpsc::Sender<Vec<u8>>,
    mut receiver: mpsc::Receiver<Vec<u8>>,
) -> io::Result<()> {
    let mut buffer = vec![0_u8; wire::MAX_PAYLOAD + 1];
    let mut pending = None;
    let mut timer = tokio::time::interval(config.poll_interval);
    timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            packet = receiver.recv(), if pending.is_none() => {
                pending = Some(packet.ok_or_else(|| io::Error::new(io::ErrorKind::BrokenPipe, "carrier reader stopped"))?);
            }
            _ = timer.tick() => {}
        }
        if let Some(packet) = pending.as_ref() {
            match device.transmit(packet) {
                Ok(()) => pending = None,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                Err(error) => return Err(error),
            }
        }
        // Reserve admission before consuming a native packet; bounded work per poll.
        for _ in 0..config.queue_packets.min(32) {
            let permit = match sender.try_reserve() {
                Ok(permit) => permit,
                Err(mpsc::error::TrySendError::Full(_)) => break,
                Err(mpsc::error::TrySendError::Closed(_)) => {
                    return Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "carrier writer stopped",
                    ));
                }
            };
            match device.receive(&mut buffer)? {
                Some(size) if size <= config.max_packet && size <= buffer.len() => {
                    if !packet_valid(config.layer, &buffer[..size]) {
                        return Err(invalid("invalid native packet"));
                    }
                    permit.send(buffer[..size].to_vec());
                }
                Some(_) => return Err(invalid("native packet exceeds configured maximum")),
                None => break,
            }
        }
    }
}
/// Forward complete packets until EOF, error or caller cancellation.
/// The device must be nonblocking and must not change its packet layer.
pub async fn run<D: PacketDevice<Error = io::Error>>(
    device: D,
    link: Link,
    config: RuntimeConfig,
) -> io::Result<()> {
    config.validate()?;
    if device.layer() != config.layer || link.layer != config.layer {
        return Err(invalid("authenticated/device packet layer mismatch"));
    }
    let (out_tx, out_rx) = mpsc::channel(config.queue_packets);
    let (in_tx, in_rx) = mpsc::channel(config.queue_packets);
    // Keep reverse halves alive and poll TLS post-handshake/control records even
    // when that carrier only sends user data. Application management is separate.
    let _reverse_writer = link.reverse_writer;
    let reverse = async move {
        match link.reverse_reader {
            Some(mut stream) => {
                let _unexpected = stream.read_u8().await?;
                Err::<(), io::Error>(invalid("unexpected reverse application data"))
            }
            None => std::future::pending::<io::Result<()>>().await,
        }
    };
    tokio::try_join!(
        reverse,
        read_packets(link.reader, link.receive_session, config, in_tx),
        write_packets(link.writer, link.send_session, out_rx, config),
        drive_device(device, config, out_tx, in_rx),
    )?;
    Ok(())
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod managed_tests;

/// Fixed common-MUX aligned symbol runtime over protected UDP or genuine QUIC.
pub mod aligned;
