//! In-process speed and ping test endpoints (TT-01, owner decisions
//! 2026-11-24, `docs/modules/tunnel-tests.md`).
//!
//! Each side owns one smoltcp IP interface on the test's [`Addresses`],
//! agreed over the control channel before each test (a random private pair
//! no host uses). The runtime admits the packets these endpoints emit like
//! device packets, so every protocol carries them unchanged through MUX
//! admission, ARQ and FEC, and hands packets for its own test address to
//! [`Tester::deliver`] or [`Responder::deliver`] instead of the TUN/TAP
//! device. They never reach the host network stack.
//!
//! Pure library: no Tokio, clocks, sockets or OS handles. Time is injected
//! as the session's monotonic [`Duration`]. Every queue and buffer is
//! bounded, and peer packets never cause a panic.
use smoltcp::iface::{Config as InterfaceConfig, Interface, SocketSet};
use smoltcp::phy::{ChecksumCapabilities, Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::{icmp, tcp};
use smoltcp::time::Instant;
use smoltcp::wire::{HardwareAddress, Icmpv4Packet, Icmpv4Repr, IpAddress, IpCidr, Ipv4Address};
use std::collections::VecDeque;
use std::time::Duration;

mod addresses;
pub mod control;
mod responder;
mod tester;
#[cfg(test)]
mod tests;

pub use addresses::{Addresses, DRAWS, usable};
pub use responder::Responder;
pub use tester::Tester;

/// Responder TCP port.
pub const RESPONDER_PORT: u16 = 5201;
/// Most parallel speed-test streams (and responder sockets).
pub const MAX_STREAMS: u8 = 8;
/// Shortest speed test.
pub const MIN_DURATION: Duration = Duration::from_secs(1);
/// Longest speed test.
pub const MAX_DURATION: Duration = Duration::from_secs(30);
/// Most ping probes.
pub const MAX_PINGS: u16 = 100;
/// Shortest gap between pings.
pub const MIN_PING_INTERVAL: Duration = Duration::from_millis(100);
/// Longest gap between pings.
pub const MAX_PING_INTERVAL: Duration = Duration::from_millis(1_000);
/// Time a ping reply may take.
pub const PING_TIMEOUT: Duration = Duration::from_secs(1);
/// TCP buffer per direction and socket (4 MiB unlocks 450+ Mb/s per stream at
/// 70 ms RTT while `fill_zeros_capped` keeps slow links bounded to 64 KiB).
pub const SOCKET_BYTES: usize = 4 * 1024 * 1024;
/// Queued packets per direction and endpoint.
pub const PACKET_SLOTS: usize = 1024;
/// Static zero block for fast, allocation-free bulk sends.
pub(crate) static ZERO_CHUNK: [u8; 65_536] = [0; 65_536];
/// Smallest test MTU (IPv4 minimum datagram).
pub const MIN_MTU: usize = 576;
/// Largest test MTU.
pub const MAX_MTU: usize = 65_535;
/// Longest a responder connection lives.
pub const CONNECTION_LIFETIME: Duration = Duration::from_secs(32);
/// Time a tester stream may take to connect, and the upload count to arrive.
pub const GRACE: Duration = Duration::from_secs(5);

/// Header magic of a test connection.
const MAGIC: &[u8; 4] = b"L2TS";
/// Test wire version.
const VERSION: u8 = 1;
/// Request header length.
const HEADER_BYTES: usize = 16;

/// Endpoint failures; none is caused by a panic on peer input.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// MTU outside [`MIN_MTU`]..=[`MAX_MTU`].
    Mtu,
    /// A test parameter is out of bounds.
    Invalid(&'static str),
    /// A test is already running.
    Busy,
    /// Time went backwards or overflowed.
    Time,
    /// The stack refused a configuration step.
    Stack,
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Mtu => write!(f, "test MTU out of bounds"),
            Self::Invalid(reason) => f.write_str(reason),
            Self::Busy => write!(f, "a test is already running"),
            Self::Time => write!(f, "test time went backwards"),
            Self::Stack => write!(f, "test stack configuration failed"),
        }
    }
}
impl std::error::Error for Error {}

/// Speed-test direction, seen from the tester.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Direction {
    /// Tester sends; the responder counts what arrived.
    Upload,
    /// Responder sends; the tester counts what arrived.
    Download,
}

/// Lifecycle of a test.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Phase {
    /// Measuring.
    Running,
    /// Finished with a result.
    Completed,
    /// Ended by an error.
    Failed,
    /// Cancelled locally.
    Cancelled,
}

/// Ping progress.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PingProgress {
    /// Probes sent.
    pub sent: u16,
    /// Round trip per sent probe; `None` is lost or still pending.
    pub rtts: Vec<Option<Duration>>,
}

/// What a test measured so far.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Measurement {
    /// TCP streaming.
    Speed {
        /// Upload or download.
        direction: Direction,
        /// Streams.
        streams: u8,
        /// Requested duration.
        duration: Duration,
        /// Bytes counted: delivered and acknowledged so far, and at the end
        /// what the receiving side counted.
        bytes: u64,
        /// Bits per second in each completed second.
        samples: Vec<u64>,
    },
    /// ICMP echo.
    Ping(PingProgress),
}

/// One test's progress.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Progress {
    /// Lifecycle.
    pub phase: Phase,
    /// Time since the start (frozen at the end).
    pub elapsed: Duration,
    /// Measured values.
    pub measurement: Measurement,
    /// Why it failed.
    pub error: Option<&'static str>,
}
impl Progress {
    /// Mean rate over the elapsed time (speed tests).
    pub fn bits_per_second(&self) -> u64 {
        match &self.measurement {
            Measurement::Speed { bytes, .. } => rate(*bytes, self.elapsed),
            Measurement::Ping(_) => 0,
        }
    }
}

/// `bytes` over `elapsed` in bits per second.
pub fn rate(bytes: u64, elapsed: Duration) -> u64 {
    let micros = elapsed.as_micros();
    if micros == 0 {
        return 0;
    }
    u64::try_from(u128::from(bytes) * 8 * 1_000_000 / micros).unwrap_or(u64::MAX)
}

/// Bounded packet queues between the stack and the runtime.
pub(crate) struct Queues {
    pub(crate) incoming: VecDeque<Vec<u8>>,
    pub(crate) outgoing: VecDeque<Vec<u8>>,
    pub(crate) free: Vec<Vec<u8>>,
    pub(crate) mtu: usize,
    /// Peer packets dropped because the incoming queue was full or the
    /// packet was oversized.
    pub(crate) dropped: u64,
}
pub(crate) struct Rx(Vec<u8>);
impl RxToken for Rx {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(&self.0)
    }
}
pub(crate) struct Tx<'a> {
    outgoing: &'a mut VecDeque<Vec<u8>>,
    free: &'a mut Vec<Vec<u8>>,
}
impl TxToken for Tx<'_> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        // Reuse a pooled packet buffer when available to avoid per-packet heap churn.
        let mut packet = self.free.pop().unwrap_or_default();
        packet.resize(len, 0);
        let result = f(&mut packet);
        self.outgoing.push_back(packet);
        result
    }
}
impl Device for Queues {
    type RxToken<'a> = Rx;
    type TxToken<'a> = Tx<'a>;
    fn receive(&mut self, _: Instant) -> Option<(Rx, Tx<'_>)> {
        if self.outgoing.len() >= PACKET_SLOTS {
            return None;
        }
        let packet = self.incoming.pop_front()?;
        Some((
            Rx(packet),
            Tx {
                outgoing: &mut self.outgoing,
                free: &mut self.free,
            },
        ))
    }
    fn transmit(&mut self, _: Instant) -> Option<Tx<'_>> {
        if self.outgoing.len() >= PACKET_SLOTS {
            return None;
        }
        Some(Tx {
            outgoing: &mut self.outgoing,
            free: &mut self.free,
        })
    }
    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = self.mtu;
        caps.max_burst_size = Some(PACKET_SLOTS);
        caps
    }
}
impl Queues {
    fn new(mtu: usize) -> Result<Self, Error> {
        if !(MIN_MTU..=MAX_MTU).contains(&mtu) {
            return Err(Error::Mtu);
        }
        Ok(Self {
            incoming: VecDeque::with_capacity(PACKET_SLOTS),
            outgoing: VecDeque::with_capacity(PACKET_SLOTS),
            free: Vec::with_capacity(PACKET_SLOTS),
            mtu,
            dropped: 0,
        })
    }
    /// Queue one peer packet; oversized packets and overflow are dropped
    /// and counted, as a lossy link would.
    pub(crate) fn deliver(&mut self, packet: &[u8]) {
        if packet.is_empty() || packet.len() > self.mtu || self.incoming.len() >= PACKET_SLOTS {
            self.dropped = self.dropped.saturating_add(1);
            return;
        }
        let mut buf = self.free.pop().unwrap_or_default();
        buf.clear();
        buf.extend_from_slice(packet);
        self.incoming.push_back(buf);
    }
    /// Return a consumed buffer to the bounded pool.
    pub(crate) fn recycle(&mut self, mut buf: Vec<u8>) {
        if self.free.len() < PACKET_SLOTS * 2 && buf.capacity() <= self.mtu.saturating_mul(2) {
            buf.clear();
            self.free.push(buf);
        }
    }
}

/// The session clock as a stack instant.
pub(crate) fn instant(now: Duration) -> Result<Instant, Error> {
    i64::try_from(now.as_micros())
        .map(Instant::from_micros)
        .map_err(|_| Error::Time)
}
/// A stack instant as session time (negative clamps to zero).
pub(crate) fn duration(at: Instant) -> Duration {
    Duration::from_micros(u64::try_from(at.total_micros()).unwrap_or(0))
}

/// One interface on `address` with a default route to `peer`.
pub(crate) fn interface(
    queues: &mut Queues,
    address: Ipv4Address,
    peer: Ipv4Address,
    seed: u64,
    now: Duration,
) -> Result<Interface, Error> {
    let mut config = InterfaceConfig::new(HardwareAddress::Ip);
    config.random_seed = seed;
    let mut interface = Interface::new(config, queues, instant(now)?);
    let mut added = false;
    interface.update_ip_addrs(|addresses| {
        added = addresses
            .push(IpCidr::new(IpAddress::Ipv4(address), 32))
            .is_ok();
    });
    if !added {
        return Err(Error::Stack);
    }
    interface
        .routes_mut()
        .add_default_ipv4_route(peer)
        .map_err(|_| Error::Stack)?;
    Ok(interface)
}

/// A TCP socket with the bounded buffers and Reno congestion control (the
/// workspace never enables CUBIC: it would change the default controller of
/// the TCP-proxy engines built into the same binary).
pub(crate) fn tcp_socket() -> tcp::Socket<'static> {
    let mut socket = tcp::Socket::new(
        tcp::SocketBuffer::new(vec![0; SOCKET_BYTES]),
        tcp::SocketBuffer::new(vec![0; SOCKET_BYTES]),
    );
    socket.set_nagle_enabled(false);
    // Avoid 10 ms delayed-ACK pauses slowing Reno slow-start and throughput.
    socket.set_ack_delay(None);
    socket.set_congestion_control(tcp::CongestionControl::Reno);
    socket.set_timeout(Some(smoltcp::time::Duration::from_secs(10)));
    socket
}

/// Adaptive TCP send-queue cap (~250 ms of actual drained rate, bounded to
/// `[64 KiB, SOCKET_BYTES]`) so high-BDP gigabit links get the full 4 MiB
/// window while slow 1-5 Mbit/s links drain TCP FIN well inside `GRACE`.
pub(crate) fn adaptive_send_queue(started: Duration, now: Duration, drained: u64) -> usize {
    let elapsed_us = now.saturating_sub(started).as_micros();
    if elapsed_us >= 250_000 {
        let bytes_per_sec = u128::from(drained).saturating_mul(1_000_000) / elapsed_us;
        usize::try_from(bytes_per_sec / 4)
            .unwrap_or(SOCKET_BYTES)
            .clamp(64 * 1024, SOCKET_BYTES)
    } else {
        128 * 1024
    }
}

/// Fill a TCP socket's send buffer up to `max_queue` queued bytes so slow links
/// do not trap a large backlog behind TCP FIN when a stream ends.
pub(crate) fn fill_zeros_capped(socket: &mut tcp::Socket<'static>, max_queue: usize) -> u64 {
    let mut total = 0_u64;
    while socket.can_send() {
        let queued = socket.send_queue();
        let room = max_queue.saturating_sub(queued);
        if room == 0 {
            break;
        }
        let chunk = &ZERO_CHUNK[..room.min(ZERO_CHUNK.len())];
        let Ok(sent) = socket.send_slice(chunk) else {
            break;
        };
        if sent == 0 {
            break;
        }
        total = total.saturating_add(sent as u64);
    }
    total
}

/// The 16-byte request header.
pub(crate) fn header(direction: Direction, duration: Duration) -> [u8; HEADER_BYTES] {
    let mut header = [0; HEADER_BYTES];
    header[..4].copy_from_slice(MAGIC);
    header[4] = VERSION;
    header[5] = match direction {
        Direction::Upload => 1,
        Direction::Download => 2,
    };
    let millis = u32::try_from(duration.as_millis()).unwrap_or(u32::MAX);
    header[8..12].copy_from_slice(&millis.to_be_bytes());
    header
}
/// Parse a request header; `None` refuses it.
pub(crate) fn parse_header(header: &[u8; HEADER_BYTES]) -> Option<(Direction, Duration)> {
    if &header[..4] != MAGIC
        || header[4] != VERSION
        || header[6..8] != [0, 0]
        || header[12..] != [0; 4]
    {
        return None;
    }
    let direction = match header[5] {
        1 => Direction::Upload,
        2 => Direction::Download,
        _ => return None,
    };
    let millis = u32::from_be_bytes([header[8], header[9], header[10], header[11]]);
    let duration = Duration::from_millis(u64::from(millis));
    (MIN_DURATION..=MAX_DURATION)
        .contains(&duration)
        .then_some((direction, duration))
}

/// An ICMP socket with room for a few probes.
pub(crate) fn icmp_socket() -> icmp::Socket<'static> {
    let buffer = || icmp::PacketBuffer::new(vec![icmp::PacketMetadata::EMPTY; 8], vec![0; 1024]);
    icmp::Socket::new(buffer(), buffer())
}
/// Echo identifier of the tester's probes; the responder answers only it.
pub(crate) const PING_IDENT: u16 = 0x4c32;
/// The echo reply to an echo request for `ident`. The responder answers
/// echo itself: smoltcp's `auto-icmp-echo-reply` feature stays off, because
/// Cargo feature unification would make every smoltcp interface in the
/// binary (TCP proxy, raw TCP, pipeline) answer pings.
pub(crate) fn echo_answer(ident: u16, bytes: &[u8]) -> Option<Vec<u8>> {
    let packet = Icmpv4Packet::new_checked(bytes).ok()?;
    match Icmpv4Repr::parse(&packet, &ChecksumCapabilities::default()).ok()? {
        Icmpv4Repr::EchoRequest {
            ident: request,
            seq_no,
            data,
        } if request == ident => {
            let repr = Icmpv4Repr::EchoReply {
                ident,
                seq_no,
                data,
            };
            let mut reply = vec![0; repr.buffer_len()];
            repr.emit(
                &mut Icmpv4Packet::new_unchecked(&mut reply),
                &ChecksumCapabilities::default(),
            );
            Some(reply)
        }
        _ => None,
    }
}
/// An echo request with `sequence`.
pub(crate) fn echo_request(ident: u16, sequence: u16) -> Vec<u8> {
    let data = [0x5a; 16];
    let repr = Icmpv4Repr::EchoRequest {
        ident,
        seq_no: sequence,
        data: &data,
    };
    let mut bytes = vec![0; repr.buffer_len()];
    repr.emit(
        &mut Icmpv4Packet::new_unchecked(&mut bytes),
        &ChecksumCapabilities::default(),
    );
    bytes
}
/// The sequence number of an echo reply for `ident`.
pub(crate) fn echo_reply(ident: u16, bytes: &[u8]) -> Option<u16> {
    let packet = Icmpv4Packet::new_checked(bytes).ok()?;
    match Icmpv4Repr::parse(&packet, &ChecksumCapabilities::default()).ok()? {
        Icmpv4Repr::EchoReply {
            ident: reply,
            seq_no,
            ..
        } if reply == ident => Some(seq_no),
        _ => None,
    }
}

/// Shared stack state of both endpoints.
pub(crate) struct Stack {
    pub(crate) interface: Interface,
    pub(crate) sockets: SocketSet<'static>,
    pub(crate) queues: Queues,
    pub(crate) last: Duration,
}
impl Stack {
    pub(crate) fn new(
        address: Ipv4Address,
        peer: Ipv4Address,
        mtu: usize,
        seed: u64,
        now: Duration,
    ) -> Result<Self, Error> {
        let mut queues = Queues::new(mtu)?;
        let interface = interface(&mut queues, address, peer, seed, now)?;
        Ok(Self {
            interface,
            sockets: SocketSet::new(Vec::new()),
            queues,
            last: now,
        })
    }
    /// Advance the stack to `now`; earlier times are refused.
    pub(crate) fn advance(&mut self, now: Duration) -> Result<(), Error> {
        if now < self.last {
            return Err(Error::Time);
        }
        self.last = now;
        let at = instant(now)?;
        // Drain bounded bursts while sockets make progress; stop at once when idle.
        for _ in 0..16 {
            let result = self.interface.poll(at, &mut self.queues, &mut self.sockets);
            if matches!(result, smoltcp::iface::PollResult::None) {
                break;
            }
        }
        Ok(())
    }
    /// Next time the stack needs a poll.
    pub(crate) fn poll_at(&mut self, now: Duration) -> Option<Duration> {
        if !self.queues.incoming.is_empty() || !self.queues.outgoing.is_empty() {
            return Some(now);
        }
        let at = instant(now).ok()?;
        self.interface.poll_at(at, &self.sockets).map(duration)
    }
}
