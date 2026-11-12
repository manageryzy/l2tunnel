//! Runtime of the lean `swift` profile.
//!
//! One task owns a readiness-registered native device, one connected UDP
//! socket and the pure [`l2tunnel_swift`] engines of every ordering channel.
//! Native packets are classified by connection into channels so that a loss
//! delays only the connections sharing its channel. Every
//! datagram is `[packet number u64][ChaCha20-Poly1305 ciphertext][tag]`; the
//! packet number is the nonce, the replay identity and the repair coefficient
//! seed. Keys come from the caller, which derives them from the authenticated
//! TLS exporter. Outbound datagrams are paced by a token bucket in IP bytes so
//! the tunnel fills, and does not overrun, a configured path budget.
//!
//! This module performs no authentication, key derivation or device setup.
use l2tunnel_device::{PacketDevice, PacketLayer, READ_BUFFER_BYTES};
use l2tunnel_swift as codec;
use ring::aead;
use std::future::Future;
use std::io;
use std::os::fd::AsRawFd;
use std::time::{Duration, Instant};
use tokio::io::unix::AsyncFd;
use tokio::io::{AsyncRead, AsyncReadExt, Interest};
use tokio::net::UdpSocket;

/// Packet number and authentication tag added to every engine datagram body.
pub const PROTECTION_BYTES: usize = 24;
const NUMBER_BYTES: usize = 8;
const REPLAY_BITS: u64 = 4096;
const SCALE: u64 = 1_000_000;
/// Datagrams taken from the socket per readiness event.
const RECEIVE_BATCH: usize = 128;
/// Recovered packets written to the device between socket reads.
const DELIVERY_BATCH: usize = 32;

/// Fixed runtime policy. Both peers bind the protocol part into the
/// authenticated session digest before calling [`run`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Config {
    /// Shared engine policy of every channel. Its `queue_bytes` bounds the
    /// native bytes queued across all channels together.
    pub codec: codec::Config,
    /// Independent ordering channels, in `1..=64`.
    pub channels: usize,
    /// Native packet layer, which selects the flow classifier and the header
    /// compression profile.
    pub layer: PacketLayer,
    /// Largest native packet; the engine's record bound is one byte more.
    pub max_native: usize,
    /// Outbound budget in IP bytes per second, in `8_000..=1_250_000_000`.
    pub send_bytes_per_second: u64,
    /// IP and UDP header bytes charged per datagram (28 for IPv4, 48 for IPv6).
    pub network_overhead: usize,
    /// Interval of periodic reports; `None` reports only at termination.
    pub report_interval: Option<Duration>,
}

impl Config {
    /// Validate scalar bounds before any state is allocated.
    pub fn validate(self) -> io::Result<()> {
        self.codec.validate().map_err(invalid)?;
        if !(1..=codec::MAX_CHANNELS).contains(&self.channels)
            || self.max_native + codec::header::MAX_EXPANSION != self.codec.max_packet
            || !(8_000..=1_250_000_000).contains(&self.send_bytes_per_second)
            || !(28..=128).contains(&self.network_overhead)
            || self
                .report_interval
                .is_some_and(|value| value < Duration::from_millis(100))
        {
            return Err(invalid(
                "swift runtime channels, packet bound, rate, overhead or report interval",
            ));
        }
        Ok(())
    }
    fn datagram_cost(self, wire: usize) -> u64 {
        (wire + self.network_overhead) as u64
    }
}

/// Directional data keys from the authenticated exporter.
pub struct Keys<'a> {
    /// Key protecting datagrams this endpoint sends.
    pub send: &'a [u8; 32],
    /// Key protecting datagrams this endpoint receives.
    pub receive: &'a [u8; 32],
}

/// Non-secret counters reported to the embedding frontend.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Snapshot {
    /// Microseconds since the runtime started.
    pub elapsed_micros: u64,
    /// Sending engine counters.
    pub sender: codec::SenderStats,
    /// Receiving engine counters.
    pub receiver: codec::ReceiverStats,
    /// Protected datagrams handed to the socket.
    pub datagrams_sent: u64,
    /// IP bytes charged for those datagrams.
    pub ip_bytes_sent: u64,
    /// Protected datagrams that passed authentication and replay checks.
    pub datagrams_received: u64,
    /// Datagrams rejected by authentication, replay or length checks.
    pub datagrams_rejected: u64,
    /// Datagrams the socket refused; the engine treats them as path loss.
    pub socket_drops: u64,
    /// Native packets read from the device and accepted for packing.
    pub native_read: u64,
    /// Native packets from the device dropped as oversized.
    pub native_dropped: u64,
    /// Native packets written to the device.
    pub native_written: u64,
    /// Recovered packets the device refused.
    pub native_write_drops: u64,
    /// Native bytes removed by header compression, net of record tags.
    pub header_bytes_saved: u64,
}

fn invalid(message: impl ToString) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.to_string())
}
fn protocol(error: codec::Error) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error)
}

/// Token bucket in millionths of an IP byte.
struct Pacer {
    rate: u64,
    burst: i64,
    tokens: i64,
    last: u64,
}
impl Pacer {
    fn new(rate: u64, largest: u64, now: u64) -> Self {
        // Four milliseconds of budget absorbs timer granularity; at least two
        // datagrams so a slow link still makes progress.
        let burst = (rate / 250).max(2 * largest).saturating_mul(SCALE);
        let burst = i64::try_from(burst).unwrap_or(i64::MAX);
        Self {
            rate,
            burst,
            tokens: burst,
            last: now,
        }
    }
    fn refill(&mut self, now: u64) {
        let elapsed = now.saturating_sub(self.last);
        self.last = now;
        let added = u128::from(self.rate) * u128::from(elapsed);
        let added = i64::try_from(added).unwrap_or(i64::MAX);
        self.tokens = self.tokens.saturating_add(added).min(self.burst);
    }
    fn ready(&self) -> bool {
        self.tokens >= 0
    }
    fn charge(&mut self, bytes: u64) {
        let cost = i64::try_from(bytes.saturating_mul(SCALE)).unwrap_or(i64::MAX);
        self.tokens = self.tokens.saturating_sub(cost);
    }
    /// Time at which the bucket is non-negative again.
    fn available_at(&self) -> u64 {
        if self.tokens >= 0 {
            self.last
        } else {
            let debt = self.tokens.unsigned_abs();
            self.last.saturating_add(debt.div_ceil(self.rate))
        }
    }
}

/// Sliding anti-replay window over authenticated packet numbers.
struct Replay {
    started: bool,
    highest: u64,
    bits: Vec<u64>,
}
impl Replay {
    fn new() -> Self {
        Self {
            started: false,
            highest: 0,
            bits: vec![0; (REPLAY_BITS / 64) as usize],
        }
    }
    fn slot(number: u64) -> (usize, u64) {
        let bit = number % REPLAY_BITS;
        ((bit / 64) as usize, 1 << (bit % 64))
    }
    fn fresh(&self, number: u64) -> bool {
        if !self.started || number > self.highest {
            return true;
        }
        if self.highest - number >= REPLAY_BITS {
            return false;
        }
        let (word, mask) = Self::slot(number);
        self.bits[word] & mask == 0
    }
    /// Record a number only after its datagram authenticated.
    fn commit(&mut self, number: u64) {
        if !self.started || number > self.highest {
            let first = if self.started { self.highest + 1 } else { 0 };
            if number - first >= REPLAY_BITS {
                self.bits.fill(0);
            } else {
                for skipped in first..number {
                    let (word, mask) = Self::slot(skipped);
                    self.bits[word] &= !mask;
                }
            }
            let (word, mask) = Self::slot(number);
            self.bits[word] &= !mask;
            self.highest = number;
            self.started = true;
        }
        let (word, mask) = Self::slot(number);
        self.bits[word] |= mask;
    }
}

fn nonce(number: u64) -> aead::Nonce {
    let mut bytes = [0; aead::NONCE_LEN];
    bytes[4..].copy_from_slice(&number.to_be_bytes());
    aead::Nonce::assume_unique_for_key(bytes)
}
fn key(bytes: &[u8; 32]) -> io::Result<aead::LessSafeKey> {
    aead::UnboundKey::new(&aead::CHACHA20_POLY1305, bytes)
        .map(aead::LessSafeKey::new)
        .map_err(|_| io::Error::other("swift data key rejected"))
}

/// Socket-free protocol state of one endpoint, driven by explicit time.
///
/// Each channel is an independent ordered stream with its own engines. The
/// leading byte of a datagram body carries the kind in its low bits and the
/// channel above them; a feedback datagram concatenates one block per channel.
struct Engine {
    config: Config,
    senders: Vec<codec::Sender>,
    receivers: Vec<codec::Receiver>,
    compressors: Vec<codec::header::Compressor>,
    decompressors: Vec<codec::header::Decompressor>,
    seal: aead::LessSafeKey,
    open: aead::LessSafeKey,
    replay: Replay,
    pacer: Pacer,
    number: u64,
    /// Channel served after the last new source, for round-robin fairness.
    turn: usize,
    /// Earliest time of the next feedback datagram.
    feedback_at: u64,
    feedback_turn: usize,
    /// One bit per channel whose receiver may hold complete packets.
    ready: u64,
    body: Vec<u8>,
    block: Vec<u8>,
    wire: Vec<u8>,
    opened: Vec<u8>,
    native: Vec<u8>,
    record: Vec<u8>,
    snapshot: Snapshot,
}

fn tagged(kind: u8, channel: usize) -> u8 {
    kind | ((channel as u8) << 2)
}

impl Engine {
    fn new(config: Config, keys: &Keys<'_>, now: u64) -> io::Result<Self> {
        config.validate()?;
        let largest = config.datagram_cost(config.codec.datagram_bytes + PROTECTION_BYTES);
        let mut senders = Vec::with_capacity(config.channels);
        let mut receivers = Vec::with_capacity(config.channels);
        let ethernet = config.layer == PacketLayer::Ethernet;
        let mut compressors = Vec::with_capacity(config.channels);
        let mut decompressors = Vec::with_capacity(config.channels);
        for _ in 0..config.channels {
            senders.push(codec::Sender::new(config.codec).map_err(invalid)?);
            receivers.push(codec::Receiver::new(config.codec).map_err(invalid)?);
            compressors.push(codec::header::Compressor::new(ethernet));
            decompressors.push(codec::header::Decompressor::new(ethernet));
        }
        Ok(Self {
            config,
            senders,
            receivers,
            compressors,
            decompressors,
            seal: key(keys.send)?,
            open: key(keys.receive)?,
            replay: Replay::new(),
            pacer: Pacer::new(config.send_bytes_per_second, largest, now),
            number: 0,
            turn: 0,
            feedback_at: 0,
            feedback_turn: 0,
            ready: 0,
            body: Vec::with_capacity(config.codec.datagram_bytes),
            block: Vec::with_capacity(codec::FEEDBACK_HEADER + 2 * codec::MAX_REQUESTS),
            wire: Vec::with_capacity(config.codec.datagram_bytes + PROTECTION_BYTES),
            opened: Vec::with_capacity(config.codec.datagram_bytes + PROTECTION_BYTES),
            native: Vec::with_capacity(config.codec.max_packet),
            record: Vec::with_capacity(config.codec.max_packet),
            snapshot: Snapshot::default(),
        })
    }
    /// The packing queues share one byte budget, like one bottleneck queue.
    fn has_room(&self) -> bool {
        let queued: usize = self.senders.iter().map(codec::Sender::queued).sum();
        queued + self.config.codec.max_packet + codec::FRAME_PREFIX <= self.config.codec.queue_bytes
    }
    /// Queue one native packet read from the device.
    fn offer(&mut self, now: u64, packet: &[u8]) -> io::Result<()> {
        // Refuse before compressing: a compressed record must be delivered,
        // or the peer's header contexts would no longer match.
        if packet.is_empty() || packet.len() > self.config.max_native || !self.has_room() {
            self.snapshot.native_dropped += 1;
            return Ok(());
        }
        let channel = match self.config.layer {
            PacketLayer::Ethernet => codec::flow::classify_ethernet(packet, self.config.channels),
            PacketLayer::Ip => codec::flow::classify_ip(packet, self.config.channels),
        };
        self.compressors[channel].compress(packet, &mut self.record);
        if !self.senders[channel]
            .push_packet(now, &self.record)
            .map_err(protocol)?
        {
            return Err(io::Error::other(
                "swift packing queue refused an admitted record",
            ));
        }
        self.snapshot.native_read += 1;
        Ok(())
    }
    /// One feedback datagram body with a block for every channel that owes
    /// one, as far as they fit. Returns whether anything was written.
    fn feedback(&mut self, now: u64) -> bool {
        if now < self.feedback_at {
            return false;
        }
        self.body.clear();
        let block = codec::FEEDBACK_HEADER + 2 * codec::MAX_REQUESTS;
        let mut deferred = false;
        for step in 0..self.config.channels {
            let channel = (self.feedback_turn + step) % self.config.channels;
            if self.body.len() + block > self.config.codec.datagram_bytes {
                // Continue with this channel in the next datagram.
                deferred = self.receivers[channel].deadline().is_some();
                if deferred {
                    self.feedback_turn = channel;
                    break;
                }
                continue;
            }
            if self.receivers[channel].feedback(now, &mut self.block) {
                self.block[0] = tagged(codec::KIND_FEEDBACK, channel);
                self.body.extend_from_slice(&self.block);
            }
        }
        if !deferred {
            self.feedback_at = now.saturating_add(self.config.codec.feedback_micros);
        }
        !self.body.is_empty()
    }
    /// The next source, repair or retransmission the budget allows.
    fn data(&mut self, now: u64) -> io::Result<bool> {
        if !self.pacer.ready() {
            return Ok(false);
        }
        let channels = self.config.channels;
        // Requested retransmissions unblock delivery, so they go first.
        let urgent = (0..channels)
            .map(|step| (self.turn + step) % channels)
            .find(|channel| self.senders[*channel].urgent());
        let order = urgent
            .into_iter()
            .chain((0..channels).map(|step| (self.turn + step) % channels));
        for channel in order {
            if self.senders[channel]
                .poll(now, self.number, &mut self.body)
                .map_err(protocol)?
            {
                self.body[0] = tagged(self.body[0], channel);
                if urgent != Some(channel) {
                    self.turn = (channel + 1) % channels;
                }
                return Ok(true);
            }
        }
        Ok(false)
    }
    /// The next protected datagram due at `now`, if any. Feedback is never
    /// held back by pacing but is charged to the same budget.
    fn produce(&mut self, now: u64) -> io::Result<Option<&[u8]>> {
        self.pacer.refill(now);
        if !self.feedback(now) && !self.data(now)? {
            return Ok(None);
        }
        let number = self.number;
        self.number = number
            .checked_add(1)
            .ok_or_else(|| io::Error::other("swift packet numbers exhausted"))?;
        self.wire.clear();
        self.wire.extend_from_slice(&number.to_be_bytes());
        self.wire.extend_from_slice(&self.body);
        let tag = self
            .seal
            .seal_in_place_separate_tag(
                nonce(number),
                aead::Aad::empty(),
                &mut self.wire[NUMBER_BYTES..],
            )
            .map_err(|_| io::Error::other("swift datagram protection failed"))?;
        self.wire.extend_from_slice(tag.as_ref());
        let cost = self.config.datagram_cost(self.wire.len());
        self.pacer.charge(cost);
        self.snapshot.datagrams_sent += 1;
        self.snapshot.ip_bytes_sent += cost;
        Ok(Some(&self.wire))
    }
    /// Earliest time [`Engine::produce`] can have something new without input.
    fn wake(&self, now: u64) -> Option<u64> {
        let send = if self.senders.iter().any(|sender| sender.ready(now)) {
            Some(self.pacer.available_at())
        } else {
            self.senders
                .iter()
                .filter_map(codec::Sender::deadline)
                .min()
        };
        let feedback = self
            .receivers
            .iter()
            .any(|receiver| receiver.deadline().is_some())
            .then_some(self.feedback_at);
        match (send, feedback) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        }
    }
    /// Authenticate and apply one received datagram. Unauthenticated input is
    /// counted and ignored; inconsistent authenticated input ends the session.
    fn accept(&mut self, now: u64, datagram: &[u8]) -> io::Result<()> {
        let limit = self.config.codec.datagram_bytes + PROTECTION_BYTES;
        if datagram.len() <= PROTECTION_BYTES || datagram.len() > limit {
            self.snapshot.datagrams_rejected += 1;
            return Ok(());
        }
        let mut prefix = [0; NUMBER_BYTES];
        prefix.copy_from_slice(&datagram[..NUMBER_BYTES]);
        let number = u64::from_be_bytes(prefix);
        if !self.replay.fresh(number) {
            self.snapshot.datagrams_rejected += 1;
            return Ok(());
        }
        self.opened.clear();
        self.opened.extend_from_slice(&datagram[NUMBER_BYTES..]);
        let Ok(body) = self
            .open
            .open_in_place(nonce(number), aead::Aad::empty(), &mut self.opened)
        else {
            self.snapshot.datagrams_rejected += 1;
            return Ok(());
        };
        self.replay.commit(number);
        self.snapshot.datagrams_received += 1;
        let malformed = || protocol(codec::Error::Malformed);
        let lead = *body.first().ok_or_else(malformed)?;
        let channel = usize::from(lead >> 2);
        if channel >= self.config.channels {
            return Err(malformed());
        }
        if lead & codec::KIND_MASK != codec::KIND_FEEDBACK {
            body[0] = lead & codec::KIND_MASK;
            self.ready |= 1 << channel;
            return self.receivers[channel]
                .on_datagram(number, body)
                .map_err(protocol);
        }
        let mut rest = body;
        while !rest.is_empty() {
            let lead = rest[0];
            let channel = usize::from(lead >> 2);
            let requests =
                usize::from(*rest.get(codec::FEEDBACK_HEADER - 1).ok_or_else(malformed)?);
            let length = codec::FEEDBACK_HEADER + 2 * requests;
            if lead & codec::KIND_MASK != codec::KIND_FEEDBACK
                || channel >= self.config.channels
                || rest.len() < length
            {
                return Err(malformed());
            }
            let (block, tail) = rest.split_at_mut(length);
            block[0] = codec::KIND_FEEDBACK;
            self.senders[channel]
                .on_feedback(now, block)
                .map_err(protocol)?;
            rest = tail;
        }
        Ok(())
    }
    /// Whether [`Engine::pop`] may still return a packet.
    fn deliverable(&self) -> bool {
        self.ready != 0
    }
    /// The next recovered native packet of any channel, if one is complete.
    fn pop(&mut self) -> io::Result<Option<&[u8]>> {
        while self.ready != 0 {
            let channel = self.ready.trailing_zeros() as usize;
            if self.receivers[channel]
                .pop_packet(&mut self.record)
                .map_err(protocol)?
            {
                self.decompressors[channel]
                    .decompress(&self.record, self.config.max_native, &mut self.native)
                    .map_err(protocol)?;
                return Ok(Some(&self.native));
            }
            self.ready &= !(1 << channel);
        }
        Ok(None)
    }
    fn snapshot(&self, now: u64) -> Snapshot {
        let mut snapshot = Snapshot {
            elapsed_micros: now,
            ..self.snapshot
        };
        for sender in &self.senders {
            snapshot.sender.add(&sender.stats());
        }
        for receiver in &self.receivers {
            snapshot.receiver.add(&receiver.stats());
        }
        snapshot.header_bytes_saved = self
            .compressors
            .iter()
            .map(codec::header::Compressor::saved)
            .sum();
        snapshot
    }
}

/// Resolve when the retained authenticated control stream closes. The profile
/// sends nothing on it, so any received byte is a protocol violation.
pub async fn closed<S: AsyncRead + Unpin>(mut stream: S) -> io::Result<()> {
    let mut byte = [0];
    match stream.read(&mut byte).await? {
        0 => Ok(()),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unexpected bytes on the retained swift control stream",
        )),
    }
}

/// Datagram socket errors that describe the path or a momentary local
/// condition, not an unusable socket: a full buffer, a peer that is not bound
/// yet, a firewall or connection-tracking drop, or a missing route. The engine
/// recovers from them exactly as from a datagram lost in transit.
fn path_loss(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::WouldBlock
            | io::ErrorKind::ConnectionRefused
            | io::ErrorKind::PermissionDenied
            | io::ErrorKind::HostUnreachable
            | io::ErrorKind::NetworkUnreachable
            | io::ErrorKind::NetworkDown
    )
}

async fn tick(interval: &mut Option<tokio::time::Interval>) {
    match interval {
        Some(interval) => {
            interval.tick().await;
        }
        None => std::future::pending().await,
    }
}

fn micros(start: Instant) -> u64 {
    u64::try_from(start.elapsed().as_micros()).unwrap_or(u64::MAX)
}

/// Forward native packets until `liveness` resolves or an error occurs.
///
/// `socket` must already be connected to the single peer. `report` receives a
/// snapshot on every configured interval and once at termination.
pub async fn run<D, L>(
    device: D,
    socket: UdpSocket,
    keys: Keys<'_>,
    config: Config,
    liveness: L,
    mut report: impl FnMut(&Snapshot),
) -> io::Result<()>
where
    D: PacketDevice<Error = io::Error> + AsRawFd,
    L: Future<Output = io::Result<()>>,
{
    let start = Instant::now();
    let mut engine = Engine::new(config, &keys, 0)?;
    let mut device = AsyncFd::with_interest(device, Interest::READABLE)?;
    let mut interval = config.report_interval.map(tokio::time::interval);
    let mut read = vec![0; READ_BUFFER_BYTES];
    let mut datagram = vec![0; 65_536];
    tokio::pin!(liveness);
    let result = loop {
        let now = micros(start);
        // Everything the budget allows right now.
        loop {
            let Some(wire) = engine.produce(now)? else {
                break;
            };
            match socket.try_send(wire) {
                Ok(_) => {}
                Err(error) if path_loss(&error) => engine.snapshot.socket_drops += 1,
                Err(error) => return Err(error),
            }
        }
        // A bounded batch of recovered packets, so that a long in-order run
        // released by one retransmission cannot starve the socket.
        for _ in 0..DELIVERY_BATCH {
            let Some(packet) = engine.pop()? else {
                break;
            };
            match device.get_mut().transmit(packet) {
                Ok(()) => engine.snapshot.native_written += 1,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    engine.snapshot.native_write_drops += 1;
                }
                Err(error) => return Err(error),
            }
        }
        let wait = if engine.deliverable() {
            Duration::ZERO
        } else {
            engine.wake(now).map_or(Duration::from_secs(3600), |at| {
                Duration::from_micros(at.saturating_sub(now).max(200))
            })
        };
        tokio::select! {
            biased;
            result = &mut liveness => break result,
            result = socket.readable() => {
                result?;
                for _ in 0..RECEIVE_BATCH {
                    match socket.try_recv(&mut datagram) {
                        Ok(length) => engine.accept(micros(start), &datagram[..length])?,
                        Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                        // A queued ICMP error about an earlier datagram.
                        Err(error) if path_loss(&error) => {}
                        Err(error) => return Err(error),
                    }
                }
            }
            result = async { device.readable().await.map(drop) }, if engine.has_room() => {
                result?;
                for _ in 0..64 {
                    if !engine.has_room() {
                        break;
                    }
                    let received = device.try_io_mut(Interest::READABLE, |device| {
                        device
                            .receive(&mut read)?
                            .ok_or_else(|| io::ErrorKind::WouldBlock.into())
                    });
                    match received {
                        Ok(length) => engine.offer(micros(start), &read[..length])?,
                        Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                        Err(error) => return Err(error),
                    }
                }
            }
            _ = tokio::time::sleep(wait) => {}
            _ = tick(&mut interval) => report(&engine.snapshot(micros(start))),
        }
    };
    report(&engine.snapshot(micros(start)));
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(rate: u64, channels: usize) -> Config {
        Config {
            codec: codec::Config {
                datagram_bytes: 1448,
                window: 64,
                repair_numerator: 0,
                repair_denominator: 1000,
                flow_sources: 1024,
                queue_bytes: 64 * 1024,
                max_packet: 1601,
                flush_micros: 0,
                feedback_micros: 5_000,
                tail_micros: 10_000,
                min_rto_micros: 20_000,
                max_rto_micros: 1_000_000,
            },
            channels,
            layer: PacketLayer::Ip,
            max_native: 1600,
            send_bytes_per_second: rate,
            network_overhead: 28,
            report_interval: None,
        }
    }
    fn pair(rate: u64, channels: usize) -> io::Result<(Engine, Engine)> {
        let (a, b) = ([1; 32], [2; 32]);
        let left = Keys {
            send: &a,
            receive: &b,
        };
        let right = Keys {
            send: &b,
            receive: &a,
        };
        Ok((
            Engine::new(config(rate, channels), &left, 0)?,
            Engine::new(config(rate, channels), &right, 0)?,
        ))
    }
    /// A minimal IPv4/TCP packet of one connection carrying a counter.
    fn segment(port: u16, counter: u32, length: usize) -> Vec<u8> {
        let mut packet = vec![0u8; length.max(44)];
        packet[0] = 0x45;
        packet[9] = 6;
        packet[12..20].copy_from_slice(&[198, 18, 0, 1, 198, 18, 0, 2]);
        packet[20..22].copy_from_slice(&port.to_be_bytes());
        packet[22..24].copy_from_slice(&24_500u16.to_be_bytes());
        packet[40..44].copy_from_slice(&counter.to_be_bytes());
        packet
    }
    fn counter(packet: &[u8]) -> (u16, u32) {
        (
            u16::from_be_bytes([packet[20], packet[21]]),
            u32::from_be_bytes([packet[40], packet[41], packet[42], packet[43]]),
        )
    }

    #[test]
    fn protected_engines_deliver_in_order_and_reject_tamper_and_replay() -> io::Result<()> {
        let (mut left, mut right) = pair(12_500_000, 1)?;
        let packets: Vec<Vec<u8>> = (0..40u8)
            .map(|i| vec![i; 60 + usize::from(i) * 30])
            .collect();
        for packet in &packets {
            left.offer(0, packet)?;
        }
        let mut wires = Vec::new();
        while let Some(wire) = left.produce(0)? {
            assert!(wire.len() <= 1448 + PROTECTION_BYTES);
            wires.push(wire.to_vec());
        }
        assert!(!wires.is_empty());
        // The body is not visible on the wire.
        assert!(!wires[0].windows(32).any(|window| window == [0u8; 32]));
        let mut tampered = wires[0].clone();
        tampered[20] ^= 1;
        right.accept(1, &tampered)?;
        right.accept(1, &wires[0][..10])?;
        assert_eq!(right.snapshot(1).datagrams_rejected, 2);
        let mut delivered = Vec::new();
        for wire in &wires {
            right.accept(1, wire)?;
            while let Some(packet) = right.pop()? {
                delivered.push(packet.to_vec());
            }
        }
        assert_eq!(delivered, packets);
        let accepted = right.snapshot(1).datagrams_received;
        for wire in &wires {
            right.accept(2, wire)?;
        }
        assert_eq!(
            right.snapshot(2).datagrams_received,
            accepted,
            "replay accepted"
        );
        // A key from the wrong direction authenticates nothing.
        let (mut other, _) = pair(12_500_000, 1)?;
        other.accept(1, &wires[0])?;
        assert_eq!(other.snapshot(1).datagrams_received, 0);
        // Feedback returns and confirms everything.
        let feedback = right.produce(10_000)?.map(<[u8]>::to_vec);
        let feedback = feedback.ok_or_else(|| io::Error::other("no feedback"))?;
        left.accept(10_000, &feedback)?;
        assert_eq!(left.senders[0].unconfirmed(), 0);
        Ok(())
    }

    /// Sixteen connections over sixteen channels with every seventh datagram
    /// lost each way: every connection sees its own packets exactly once and
    /// in order, a gap in one channel does not hold back the others, and one
    /// feedback datagram serves all channels.
    #[test]
    fn channels_order_each_connection_independently_under_loss() -> io::Result<()> {
        let (mut left, mut right) = pair(12_500_000, 16)?;
        let mut next = [0u32; 64];
        let mut expected = [0u32; 64];
        let mut total = 0;
        let mut overtaken = false;
        let mut order = Vec::new();
        let (mut forward, mut backward) = (0u64, 0u64);
        let mut now = 0;
        while total < 16 * 300 {
            now += 1_000;
            assert!(now < 60_000_000, "stalled at {total}");
            for port in 0..16u16 {
                let index = usize::from(port);
                if next[index] < 300 && left.has_room() {
                    left.offer(now, &segment(port, next[index], 1400))?;
                    next[index] += 1;
                }
            }
            let mut wires = Vec::new();
            while let Some(wire) = left.produce(now)? {
                wires.push(wire.to_vec());
            }
            for wire in wires {
                forward += 1;
                if forward % 7 == 3 {
                    continue;
                }
                right.accept(now, &wire)?;
                while let Some(packet) = right.pop()? {
                    let (port, value) = counter(packet);
                    let index = usize::from(port);
                    assert_eq!(value, expected[index], "connection {port} out of order");
                    expected[index] += 1;
                    total += 1;
                    order.push(port);
                }
            }
            let mut wires = Vec::new();
            while let Some(wire) = right.produce(now)? {
                wires.push(wire.to_vec());
            }
            for wire in wires {
                backward += 1;
                if backward % 7 != 5 {
                    left.accept(now, &wire)?;
                }
            }
            // Some connection is ahead of another by more than one round.
            let (low, high) = (expected[..16].iter().min(), expected[..16].iter().max());
            overtaken |= matches!((low, high), (Some(low), Some(high)) if high - low > 2);
        }
        assert!(overtaken, "a gap in one channel held every connection back");
        assert!(expected[..16].iter().all(|count| *count == 300));
        let report = right.snapshot(now);
        assert!(report.receiver.packets == 16 * 300);
        // Far fewer feedback datagrams than per-channel feedback blocks.
        assert!(right.snapshot.datagrams_sent * 4 < report.receiver.feedback);
        let sent = left.snapshot(now).sender;
        assert!(sent.retransmits > 0 && sent.repairs == 0);
        assert!(order.windows(2).any(|pair| pair[0] != pair[1]));
        Ok(())
    }

    #[test]
    fn inconsistent_authenticated_bodies_end_the_session() -> io::Result<()> {
        let (left, mut right) = pair(12_500_000, 4)?;
        let send = |body: &[u8], number: u64| -> io::Result<Vec<u8>> {
            let mut wire = number.to_be_bytes().to_vec();
            wire.extend_from_slice(body);
            let tag = left
                .seal
                .seal_in_place_separate_tag(nonce(number), aead::Aad::empty(), &mut wire[8..])
                .map_err(|_| io::Error::other("seal"))?;
            wire.extend_from_slice(tag.as_ref());
            Ok(wire)
        };
        let bodies: [&[u8]; 5] = [
            // channel 5 of 4
            &[tagged(codec::KIND_SOURCE, 5), 0, 0, 0, 0, 1],
            // feedback block shorter than its header
            &[tagged(codec::KIND_FEEDBACK, 1), 0, 0],
            // feedback block announcing requests it does not carry
            &[
                tagged(codec::KIND_FEEDBACK, 1),
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                3,
            ],
            // a second block that is not feedback
            &[
                tagged(codec::KIND_FEEDBACK, 1),
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                1,
            ],
            // unknown kind
            &[3, 0, 0, 0, 0, 1],
        ];
        for (number, body) in bodies.iter().enumerate() {
            let wire = send(body, 100 + number as u64)?;
            let error = right.accept(1, &wire).err();
            assert_eq!(
                error.map(|error| error.kind()),
                Some(io::ErrorKind::InvalidData),
                "{body:?}"
            );
        }
        Ok(())
    }

    #[test]
    fn pacing_holds_the_long_term_rate_and_reports_the_next_send_time() -> io::Result<()> {
        // 1 Mbit/s of IP bytes.
        let (mut left, _) = pair(125_000, 2)?;
        let mut sent = 0u64;
        let mut now = 0;
        while now <= 2_000_000 {
            while left.has_room() {
                left.offer(now, &[7; 1500])?;
            }
            while let Some(wire) = left.produce(now)? {
                sent += (wire.len() + 28) as u64;
            }
            let wake = left.wake(now).ok_or_else(|| io::Error::other("no wake"))?;
            assert!(wake > now, "busy wake at {now}");
            now = wake;
        }
        // Two seconds of budget plus the initial burst allowance.
        let expected = 250_000;
        assert!(
            sent >= expected && sent <= expected + 2 * 1500 + 3000,
            "{sent}"
        );
        assert_eq!(left.snapshot(now).ip_bytes_sent, sent);
        // The shared queue budget refuses more input instead of growing.
        while left.has_room() {
            left.offer(now, &[7; 1500])?;
        }
        let before = left.snapshot(now).native_dropped;
        left.offer(now, &[7; 1500])?;
        assert_eq!(left.snapshot(now).native_dropped, before + 1);
        Ok(())
    }

    /// A datagram socket standing in for a TAP/TUN descriptor.
    struct Pipe(std::os::unix::net::UnixDatagram);
    impl AsRawFd for Pipe {
        fn as_raw_fd(&self) -> std::os::fd::RawFd {
            self.0.as_raw_fd()
        }
    }
    impl PacketDevice for Pipe {
        type Error = io::Error;
        fn layer(&self) -> PacketLayer {
            PacketLayer::Ip
        }
        fn receive(&mut self, buffer: &mut [u8]) -> io::Result<Option<usize>> {
            match self.0.recv(buffer) {
                Ok(length) => Ok(Some(length)),
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => Ok(None),
                Err(error) => Err(error),
            }
        }
        fn transmit(&mut self, packet: &[u8]) -> io::Result<()> {
            self.0.send(packet).map(drop)
        }
    }

    /// Two complete runtimes over real loopback UDP sockets and readiness-
    /// driven descriptors: every packet crosses in both directions, exactly
    /// and in per-connection order, and closing liveness ends both cleanly.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn two_runtimes_forward_both_ways_over_loopback_and_stop_on_liveness() -> io::Result<()> {
        use std::os::unix::net::UnixDatagram;
        use std::sync::{Arc, Mutex};
        let left_udp = UdpSocket::bind("127.0.0.1:0").await?;
        let right_udp = UdpSocket::bind("127.0.0.1:0").await?;
        left_udp.connect(right_udp.local_addr()?).await?;
        right_udp.connect(left_udp.local_addr()?).await?;
        let mut applications = Vec::new();
        let mut tasks = Vec::new();
        let mut stops = Vec::new();
        let mut finals = Vec::new();
        for (socket, send, receive) in [
            (left_udp, [5u8; 32], [6u8; 32]),
            (right_udp, [6; 32], [5; 32]),
        ] {
            let (device, application) = UnixDatagram::pair()?;
            device.set_nonblocking(true)?;
            application.set_nonblocking(true)?;
            applications.push(tokio::net::UnixDatagram::from_std(application)?);
            let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
            stops.push(stop);
            let last = Arc::new(Mutex::new(Snapshot::default()));
            finals.push(last.clone());
            let mut policy = config(2_500_000, 8);
            policy.codec.flush_micros = 500;
            policy.report_interval = Some(Duration::from_millis(100));
            tasks.push(tokio::spawn(async move {
                let keys = Keys {
                    send: &send,
                    receive: &receive,
                };
                let liveness = async move {
                    let _ = stopped.await;
                    Ok(())
                };
                run(Pipe(device), socket, keys, policy, liveness, |snapshot| {
                    if let Ok(mut slot) = last.lock() {
                        *slot = *snapshot;
                    }
                })
                .await
            }));
        }
        let mut buffer = vec![0u8; 2048];
        let limit = Duration::from_secs(20);
        for round in 0..150u32 {
            // Eight connections each way per round, then collect all sixteen.
            for port in 0..8u16 {
                let length = 60 + ((round as usize * 37 + usize::from(port) * 211) % 1400);
                applications[0].send(&segment(port, round, length)).await?;
                applications[1]
                    .send(&segment(100 + port, round, length))
                    .await?;
            }
            for (side, base) in [(1usize, 0u16), (0, 100)] {
                let mut seen = [false; 8];
                for _ in 0..8 {
                    let received =
                        tokio::time::timeout(limit, applications[side].recv(&mut buffer)).await;
                    let Ok(length) = received else {
                        // Surface why: a stopped runtime, or the counters of a live one.
                        let mut detail = format!("round {round} side {side}:");
                        for (task, last) in tasks.into_iter().zip(&finals) {
                            if task.is_finished() {
                                detail.push_str(&format!(" finished {:?};", task.await));
                            } else {
                                detail
                                    .push_str(&format!(" running {:?};", last.lock().map(|v| *v)));
                            }
                        }
                        return Err(io::Error::other(detail));
                    };
                    let length = length?;
                    let (port, value) = counter(&buffer[..length]);
                    let index = usize::from(port - base);
                    assert_eq!(value, round, "connection {port} out of order");
                    assert_eq!(
                        buffer[..length],
                        segment(
                            port,
                            round,
                            60 + ((round as usize * 37 + index * 211) % 1400)
                        )[..]
                    );
                    assert!(!std::mem::replace(&mut seen[index], true), "duplicate");
                }
            }
        }
        drop(stops);
        for task in tasks {
            tokio::time::timeout(limit, task)
                .await
                .map_err(|_| io::Error::other("runtime did not stop"))?
                .map_err(io::Error::other)??;
        }
        for last in finals {
            let report = *last.lock().map_err(|_| io::Error::other("poisoned"))?;
            assert_eq!(report.native_read, 1200);
            assert_eq!(report.native_written, 1200);
            assert_eq!(report.datagrams_rejected, 0);
            assert!(report.sender.sources > 0 && report.receiver.feedback > 0);
        }
        Ok(())
    }

    #[test]
    fn only_path_conditions_are_treated_as_datagram_loss() {
        for kind in [
            io::ErrorKind::WouldBlock,
            io::ErrorKind::ConnectionRefused,
            io::ErrorKind::PermissionDenied,
            io::ErrorKind::HostUnreachable,
            io::ErrorKind::NetworkUnreachable,
            io::ErrorKind::NetworkDown,
        ] {
            assert!(path_loss(&io::Error::from(kind)), "{kind:?}");
        }
        for kind in [
            io::ErrorKind::InvalidInput,
            io::ErrorKind::NotConnected,
            io::ErrorKind::BrokenPipe,
            io::ErrorKind::Other,
        ] {
            assert!(!path_loss(&io::Error::from(kind)), "{kind:?}");
        }
    }

    #[test]
    fn replay_window_tracks_reordering_and_large_jumps() {
        let mut replay = Replay::new();
        assert!(replay.fresh(5));
        replay.commit(5);
        assert!(!replay.fresh(5));
        assert!(replay.fresh(3));
        replay.commit(3);
        assert!(!replay.fresh(3));
        replay.commit(5 + REPLAY_BITS);
        assert!(!replay.fresh(5), "number left the window");
        assert!(replay.fresh(6));
        assert!(!replay.fresh(5 + REPLAY_BITS));
        replay.commit(1 << 40);
        assert!(replay.fresh((1 << 40) - 1));
        assert!(!replay.fresh((1 << 40) - REPLAY_BITS));
    }

    #[test]
    fn invalid_runtime_configuration_is_rejected() {
        let changes: [fn(&mut Config); 7] = [
            |value| value.send_bytes_per_second = 10,
            |value| value.network_overhead = 0,
            |value| value.report_interval = Some(Duration::from_millis(1)),
            |value| value.codec.window = 0,
            |value| value.channels = 0,
            |value| value.channels = 65,
            |value| value.max_native = 1601,
        ];
        for change in changes {
            let mut bad = config(1_000_000, 4);
            change(&mut bad);
            assert!(bad.validate().is_err(), "{bad:?}");
        }
        assert!(config(1_000_000, 64).validate().is_ok());
    }
}
